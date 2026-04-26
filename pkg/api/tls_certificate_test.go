package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeTLSCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	hostport := srv.Listener.Addr().String()
	meta, err := ProbeTLSCertificate(context.Background(), hostport, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeTLSCertificate error: %v", err)
	}
	if meta == nil {
		t.Fatal("expected metadata")
	}
	if meta.ChainLength == 0 {
		t.Fatal("expected peer certificate chain")
	}
	if meta.LeafSHA256 == "" {
		t.Fatal("expected leaf sha256")
	}
}

func TestCertSHA256FromX509(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("expected peer certificates")
	}
	cert := state.PeerCertificates[0]
	got := CertSHA256FromX509(cert)
	sum := sha256.Sum256(cert.Raw)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("unexpected cert hash: got %q want %q", got, want)
	}
}
