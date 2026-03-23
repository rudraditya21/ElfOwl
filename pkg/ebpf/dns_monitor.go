// ANCHOR: DNS Query Monitor - Phase 2: Monitor Implementation - Dec 27, 2025
// Streams DNS query events from kernel eBPF program to enrichment pipeline

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// DNSMonitor monitors DNS queries via eBPF tracepoint
// Streams DNSQuery events from kernel to enrichment pipeline
type DNSMonitor struct {
	programSet *ProgramSet
	eventChan  chan *enrichment.EnrichedEvent
	logger     *zap.Logger
	stopChan   chan struct{}
	wg         sync.WaitGroup
	started    bool
	mu         sync.Mutex
}

// NewDNSMonitor creates a new DNS monitor
func NewDNSMonitor(programSet *ProgramSet, logger *zap.Logger) *DNSMonitor {
	return &DNSMonitor{
		programSet: programSet,
		eventChan:  make(chan *enrichment.EnrichedEvent, 100),
		logger:     logger,
		stopChan:   make(chan struct{}),
	}
}

// Start begins monitoring DNS query events
func (dm *DNSMonitor) Start(ctx context.Context) error {
	dm.mu.Lock()
	if dm.started {
		dm.mu.Unlock()
		return fmt.Errorf("dns monitor already started")
	}
	dm.started = true
	dm.mu.Unlock()

	if dm.programSet == nil {
		return fmt.Errorf("program set is nil")
	}

	dm.wg.Add(1)
	go dm.eventLoop(ctx)

	dm.logger.Info("dns monitor started")
	return nil
}

// eventLoop reads events from kernel and sends to enrichment pipeline
func (dm *DNSMonitor) eventLoop(ctx context.Context) {
	defer dm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			dm.logger.Info("dns monitor context cancelled")
			return
		case <-dm.stopChan:
			dm.logger.Info("dns monitor stop signal received")
			return
		default:
			// ANCHOR: Read DNS event from kernel - Dec 27, 2025
			// Reads raw event bytes from perf/ringbuf reader
			// Parses into DNSEvent struct using bytes.NewReader
			// Converts to enrichment.EnrichedEvent with DNSContext

			if dm.programSet.Reader == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			data, err := dm.programSet.Reader.Read()
			if err != nil {
				dm.logger.Debug("event read error",
					zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if data == nil || len(data) == 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			// Parse raw bytes to DNSEvent struct
			evt := &DNSEvent{}
			if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, evt); err != nil {
				dm.logger.Warn("parse event failed",
					zap.Error(err))
				continue
			}

			// ANCHOR: Convert to enrichment type - Dec 27, 2025
			// Maps DNSEvent to enrichment.EnrichedEvent with DNSContext
			// Maps query type number to name (RFC 1035)
			// Maps response code number to name (RFC 1035)
			// Strips null bytes from domain name
			// Adds timestamp

			queryType := dnsQueryTypeName(evt.QueryType)

			dnsCtx := &enrichment.DNSContext{
				QueryName:    strings.TrimRight(string(evt.QueryName[:]), "\x00"),
				QueryType:    queryType,
				ResponseCode: int(evt.ResponseCode),
				QueryAllowed: evt.QueryAllowed == 1,
			}

			enriched := &enrichment.EnrichedEvent{
				RawEvent:  evt,
				EventType: "dns_query",
				DNS:       dnsCtx,
				Timestamp: time.Now(),
			}

			// Send to enrichment pipeline (non-blocking)
			select {
			case dm.eventChan <- enriched:
				dm.logger.Debug("dns event sent",
					zap.Uint32("pid", evt.PID),
					zap.String("domain", dnsCtx.QueryName),
					zap.String("query_type", dnsCtx.QueryType),
					zap.Int("response_code", dnsCtx.ResponseCode),
					zap.Bool("allowed", dnsCtx.QueryAllowed))
			case <-ctx.Done():
				return
			case <-dm.stopChan:
				return
			default:
				dm.logger.Warn("event channel full, dropping event",
					zap.Uint32("pid", evt.PID))
			}
		}
	}
}

// dnsQueryTypeName maps DNS query type number to name (RFC 1035)
func dnsQueryTypeName(qtype uint16) string {
	queryNames := map[uint16]string{
		1:   "A",
		2:   "NS",
		5:   "CNAME",
		6:   "SOA",
		12:  "PTR",
		15:  "MX",
		16:  "TXT",
		28:  "AAAA",
		33:  "SRV",
		42:  "NAPTR",
		43:  "DS",
		48:  "DNSKEY",
		255: "ANY",
	}

	if name, ok := queryNames[qtype]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

// dnsResponseCodeName maps DNS response code number to name (RFC 1035)
func dnsResponseCodeName(rcode uint8) string {
	rcodeNames := map[uint8]string{
		0:  "NOERROR",
		1:  "FORMERR",
		2:  "SERVFAIL",
		3:  "NXDOMAIN",
		4:  "NOTIMP",
		5:  "REFUSED",
		6:  "YXDOMAIN",
		7:  "YXRRSET",
		8:  "NXRRSET",
		9:  "NOTAUTH",
		10: "NOTZONE",
	}

	if name, ok := rcodeNames[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}

// EventChan returns the channel for receiving events
func (dm *DNSMonitor) EventChan() <-chan *enrichment.EnrichedEvent {
	return dm.eventChan
}

// Stop stops the monitor and waits for goroutine to finish
func (dm *DNSMonitor) Stop() error {
	dm.mu.Lock()
	if !dm.started {
		dm.mu.Unlock()
		return fmt.Errorf("dns monitor not started")
	}
	dm.started = false
	dm.mu.Unlock()

	close(dm.stopChan)
	dm.wg.Wait()

	if dm.programSet != nil {
		if err := dm.programSet.Close(); err != nil {
			dm.logger.Error("close program set failed",
				zap.Error(err))
			return fmt.Errorf("close program set: %w", err)
		}
	}

	dm.logger.Info("dns monitor stopped")
	return nil
}
