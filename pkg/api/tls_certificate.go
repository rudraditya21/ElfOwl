package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// TLSCertificateMetadata captures a server certificate chain summary.
type TLSCertificateMetadata struct {
	Host            string
	LeafSubject     string
	LeafIssuer      string
	LeafSHA256      string
	IssuerSHA256    string
	PublicKeySHA256 string
	NotBefore       time.Time
	NotAfter        time.Time
	SubjectAltNames []string
	ChainLength     int
	VerifiedChains  int
}

// ProbeTLSCertificate connects to host:port, performs a TLS handshake, and returns
// certificate metadata for the peer chain.
func ProbeTLSCertificate(ctx context.Context, hostport string, timeout time.Duration) (*TLSCertificateMetadata, error) {
	if hostport == "" {
		return nil, fmt.Errorf("hostport is required")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// ANCHOR: ProbeTLSCertificate ServerName - Bug: missing SNI caused wrong cert on multi-tenant TLS - Apr 30, 2026
	// Without ServerName the TLS stack sends no SNI extension, so multi-tenant endpoints return their
	// default certificate instead of the one for the requested host, producing a wrong LeafSHA256.
	host, _, _ := net.SplitHostPort(hostport)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", hostport, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // certificate is inspected, not trusted, here
		ServerName:         host,
	})
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", hostport, err)
	}
	defer conn.Close()

	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates from %s", hostport)
	}

	leaf := state.PeerCertificates[0]
	var issuerDER []byte
	if len(state.PeerCertificates) > 1 {
		issuerDER = state.PeerCertificates[1].Raw
	}

	meta := &TLSCertificateMetadata{
		Host:            hostport,
		LeafSubject:     certName(leaf.Subject),
		LeafIssuer:      certName(leaf.Issuer),
		LeafSHA256:      hashBytes(leaf.Raw),
		IssuerSHA256:    hashBytes(issuerDER),
		PublicKeySHA256: hashBytes(leaf.RawSubjectPublicKeyInfo),
		NotBefore:       leaf.NotBefore,
		NotAfter:        leaf.NotAfter,
		SubjectAltNames: append([]string(nil), leaf.DNSNames...),
		ChainLength:     len(state.PeerCertificates),
		VerifiedChains:  len(state.VerifiedChains),
	}

	return meta, nil
}

func certName(n pkixName) string {
	if n.CommonName != "" {
		return n.CommonName
	}
	if len(n.Organization) > 0 {
		return n.Organization[0]
	}
	return ""
}

type pkixName = pkix.Name

func hashBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// CertSHA256FromX509 returns the SHA-256 hash of a parsed certificate.
func CertSHA256FromX509(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
