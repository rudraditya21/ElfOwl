package ebpf

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// ANCHOR: certCacheEntry - Feature: cert_sha256 per-SNI cache - Apr 26, 2026
// Prevents re-probing the same host on every ClientHello. TTL matches vaanvil's 10-minute default.
type certCacheEntry struct {
	sha256  string
	issuer  string
	expiry  int64
	fetchedAt time.Time
}

const certCacheTTL = 10 * time.Minute

type TLSMonitor struct {
	programSet *ProgramSet
	eventChan  chan *enrichment.EnrichedEvent
	logger     *zap.Logger
	stopChan   chan struct{}
	wg         sync.WaitGroup
	started    bool
	mu         sync.Mutex

	// ANCHOR: cert cache - Feature: cert_sha256 per-SNI cache - Apr 26, 2026
	// Async probe populates on first miss; cache hit serves all subsequent events for the same SNI.
	certCache   map[string]*certCacheEntry
	certCacheMu sync.Mutex
}

func NewTLSMonitor(programSet *ProgramSet, logger *zap.Logger) *TLSMonitor {
	return &TLSMonitor{
		programSet: programSet,
		eventChan:  make(chan *enrichment.EnrichedEvent, 100),
		logger:     logger,
		stopChan:   make(chan struct{}),
		certCache:  make(map[string]*certCacheEntry),
	}
}

func (tm *TLSMonitor) Start(ctx context.Context) error {
	tm.mu.Lock()
	if tm.started {
		tm.mu.Unlock()
		return fmt.Errorf("tls monitor already started")
	}
	tm.started = true
	tm.mu.Unlock()
	if tm.programSet == nil {
		return fmt.Errorf("program set is nil")
	}
	tm.wg.Add(1)
	go tm.eventLoop(ctx)
	return nil
}

func (tm *TLSMonitor) getCachedCert(sni string) *certCacheEntry {
	tm.certCacheMu.Lock()
	defer tm.certCacheMu.Unlock()
	e := tm.certCache[sni]
	if e == nil || time.Since(e.fetchedAt) > certCacheTTL {
		return nil
	}
	return e
}

func (tm *TLSMonitor) setCachedCert(sni string, e *certCacheEntry) {
	tm.certCacheMu.Lock()
	tm.certCache[sni] = e
	tm.certCacheMu.Unlock()
}

func (tm *TLSMonitor) eventLoop(ctx context.Context) {
	defer tm.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tm.stopChan:
			return
		default:
			if tm.programSet.Reader == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			data, err := tm.programSet.Reader.Read()
			if err != nil {
				tm.logger.Debug("tls event read error", zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if len(data) == 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			evt, err := DecodeTLSEvent(data)
			if err != nil {
				tm.logger.Warn("parse tls event failed", zap.Error(err))
				continue
			}
			tm.logger.Debug(
				"tls event read",
				zap.Uint32("pid", evt.PID),
				zap.Uint16("family", evt.Family),
				zap.Uint8("protocol", evt.Protocol),
				zap.Uint16("src_port", evt.SrcPort),
				zap.Uint16("dst_port", evt.DstPort),
				zap.Uint32("length", evt.Length),
			)
			enriched := &enrichment.EnrichedEvent{
				RawEvent:  evt,
				EventType: "tls_client_hello",
				TLS:       &enrichment.TLSContext{},
				Timestamp: time.Now(),
			}
			// ANCHOR: TLS version drop log - Bug #13: out-of-range TLS version events silently discarded - Apr 30, 2026
			// ParseJA3Metadata rejects ClientHellos with legacy_version outside 0x0301–0x0304.
			// Log at Warn so operators can distinguish parse failures from capture failures.
			// Parse in userspace to keep the BPF side small and verifier-friendly.
			meta, err := ParseJA3Metadata(evt.Metadata[:evt.Length])
			if err != nil {
				tm.logger.Warn("tls ja3 parse failed, event dropped",
					zap.Error(err),
					zap.Uint32("pid", evt.PID),
					zap.Uint16("dst_port", evt.DstPort),
				)
			}
			if err == nil {
				tm.logger.Debug(
					"tls ja3 parsed",
					zap.String("ja3_fingerprint", meta.JA3Fingerprint),
					zap.String("ja3_string", meta.JA3String),
					zap.String("tls_version", meta.TLSVersion),
					zap.String("sni", meta.SNI),
				)
				tlsCtx := &enrichment.TLSContext{
					JA3Fingerprint: meta.JA3Fingerprint,
					JA3String:      meta.JA3String,
					TLSVersion:     meta.TLSVersion,
					Ciphers:        meta.Ciphers,
					Extensions:     meta.Extensions,
					Curves:         meta.Curves,
					PointFormats:   meta.PointFormats,
					SNI:            meta.SNI,
				}
				// ANCHOR: cert probe on SNI with cache - Feature: cert_sha256 - Apr 26, 2026
				// Cache hit: populate cert fields immediately before the event is queued.
				// Cache miss: launch a background goroutine so eventLoop is not blocked by the
				// outbound TLS dial (up to 3 s timeout). The first ClientHello to a new SNI ships
				// with empty cert fields; all subsequent events within the 10-minute TTL get the
				// cached values. Acceptable trade-off: reliable event capture beats complete cert
				// data on event #1.
				if meta.SNI != "" {
					if cached := tm.getCachedCert(meta.SNI); cached != nil {
						tlsCtx.CertSHA256 = cached.sha256
						tlsCtx.CertIssuer = cached.issuer
						tlsCtx.CertExpiry = cached.expiry
					} else {
						sni := meta.SNI
						dstPort := evt.DstPort
						go func() {
							certSHA256, issuer, expiry := probeCert(sni, dstPort)
							if certSHA256 == "" {
								return
							}
							tm.setCachedCert(sni, &certCacheEntry{
								sha256:    certSHA256,
								issuer:    issuer,
								expiry:    expiry,
								fetchedAt: time.Now(),
							})
							tm.logger.Debug("tls cert probed",
								zap.String("sni", sni),
								zap.String("cert_sha256", certSHA256),
								zap.String("cert_issuer", issuer),
							)
						}()
					}
				}
				enriched.TLS = tlsCtx
			}
			select {
			case tm.eventChan <- enriched:
				tm.logger.Debug("tls event queued")
			case <-ctx.Done():
				return
			case <-tm.stopChan:
				return
			default:
				tm.logger.Warn("tls event channel full, dropping event")
			}
		}
	}
}

// ANCHOR: probeCert port parameter - Bug: hardcoded 443 missed non-standard TLS ports - Apr 30, 2026
// Previously always dialed sni:443, so services on ports like 6443, 8443, 5671 never got cert metadata.
// Now uses the destination port from the captured TLS event for correct certificate probing.
func probeCert(sni string, port uint16) (certSHA256, issuer string, expiry int64) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp", net.JoinHostPort(sni, fmt.Sprintf("%d", port)),
		&tls.Config{ServerName: sni, InsecureSkipVerify: true},
	)
	if err != nil {
		return "", "", 0
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", "", 0
	}
	leaf := certs[0]
	sum := sha256.Sum256(leaf.Raw)
	raw := hex.EncodeToString(sum[:])
	// Format as colon-separated pairs matching vaanvil: "ab:cd:ef:..."
	parts := make([]string, 32)
	for i := 0; i < 32; i++ {
		parts[i] = raw[i*2 : i*2+2]
	}
	return strings.Join(parts, ":"), leaf.Issuer.CommonName, leaf.NotAfter.Unix()
}

func (tm *TLSMonitor) EventChan() <-chan *enrichment.EnrichedEvent { return tm.eventChan }

func (tm *TLSMonitor) Stop() error {
	tm.mu.Lock()
	if !tm.started {
		tm.mu.Unlock()
		return fmt.Errorf("tls monitor not started")
	}
	tm.started = false
	tm.mu.Unlock()
	close(tm.stopChan)
	tm.wg.Wait()
	return tm.programSet.Close()
}
