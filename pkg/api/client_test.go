package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/udyansh/elf-owl/pkg/config"
	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/evidence"
)

const (
	testSigningKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	testEncryptKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
)

func TestBuildTLSConfigBasicValidation(t *testing.T) {
	cfg, err := BuildTLSConfig(false, true, "", "", "")
	if err != nil {
		t.Fatalf("expected nil error for disabled TLS, got %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil TLS config when disabled")
	}

	if _, err := BuildTLSConfig(true, true, "/does/not/exist", "", ""); err == nil {
		t.Fatalf("expected error for missing CA cert path")
	}
}

func TestPushEncryptedPayload(t *testing.T) {
	signer, err := evidence.NewSigner(testSigningKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	cipher, err := evidence.NewCipher(testEncryptKey)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	var received PushBatch
	client, err := NewClient("http://owl.test", "cluster-1", "node-1", "test-token", signer, cipher, nil, testRetryConfig())
	if err != nil {
		t.Fatalf("failed to create api client: %v", err)
	}
	client.httpClient = resty.NewWithClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v1/evidence" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", got)
		}
		if got := r.Header.Get("X-Encrypted"); got != "true" {
			t.Errorf("expected X-Encrypted=true, got %s", got)
		}

		raw := decodeGzipBody(t, r.Body)
		var envelope EncryptedEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("failed to unmarshal envelope: %v", err)
		}
		ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
		if err != nil {
			t.Fatalf("failed to decode ciphertext: %v", err)
		}
		nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
		if err != nil {
			t.Fatalf("failed to decode nonce: %v", err)
		}
		plaintext, err := cipher.Decrypt(ciphertext, nonce)
		if err != nil {
			t.Fatalf("failed to decrypt payload: %v", err)
		}
		if err := json.Unmarshal(plaintext, &received); err != nil {
			t.Fatalf("failed to unmarshal batch: %v", err)
		}
		return httpResponse(http.StatusOK), nil
	})})

	events := []*evidence.BufferedEvent{
		{
			EnrichedEvent: &enrichment.EnrichedEvent{EventType: "process_execution"},
			Timestamp:     time.Now(),
		},
	}
	if err := client.Push(context.Background(), events); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	if received.ClusterID != "cluster-1" || received.NodeName != "node-1" {
		t.Fatalf("unexpected batch identity: %+v", received)
	}
	if len(received.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received.Events))
	}
	if received.Signature == "" {
		t.Fatalf("expected non-empty signature")
	}
}

func TestPushPlaintextPayload(t *testing.T) {
	signer, err := evidence.NewSigner(testSigningKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	var received PushBatch
	client, err := NewClient("http://owl.test", "cluster-2", "node-2", "test-token", signer, nil, nil, testRetryConfig())
	if err != nil {
		t.Fatalf("failed to create api client: %v", err)
	}
	client.httpClient = resty.NewWithClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("X-Encrypted"); got != "false" {
			t.Errorf("expected X-Encrypted=false, got %s", got)
		}
		raw := decodeGzipBody(t, r.Body)
		if err := json.Unmarshal(raw, &received); err != nil {
			t.Fatalf("failed to unmarshal plaintext batch: %v", err)
		}
		return httpResponse(http.StatusAccepted), nil
	})})

	events := []*evidence.BufferedEvent{
		{
			EnrichedEvent: &enrichment.EnrichedEvent{EventType: "dns_query"},
			Timestamp:     time.Now(),
		},
	}
	if err := client.Push(context.Background(), events); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	if received.ClusterID != "cluster-2" || received.NodeName != "node-2" {
		t.Fatalf("unexpected batch identity: %+v", received)
	}
	if len(received.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received.Events))
	}
}

func TestPushWithRetryEventuallySucceeds(t *testing.T) {
	signer, err := evidence.NewSigner(testSigningKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	var attempts int32
	client, err := NewClient("http://owl.test", "cluster-3", "node-3", "test-token", signer, nil, nil, config.RetryConfig{
		MaxRetries:        3,
		InitialBackoff:    1 * time.Millisecond,
		MaxBackoff:        5 * time.Millisecond,
		BackoffMultiplier: 2.0,
	})
	if err != nil {
		t.Fatalf("failed to create api client: %v", err)
	}
	client.httpClient = resty.NewWithClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		current := atomic.AddInt32(&attempts, 1)
		if current == 1 {
			return httpResponse(http.StatusInternalServerError), nil
		}
		return httpResponse(http.StatusOK), nil
	})})

	events := []*evidence.BufferedEvent{
		{
			EnrichedEvent: &enrichment.EnrichedEvent{EventType: "file_access"},
			Timestamp:     time.Now(),
		},
	}
	if err := client.PushWithRetry(context.Background(), events); err != nil {
		t.Fatalf("expected retry success, got error: %v", err)
	}

	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
	if got := client.SuccessCount(); got != 1 {
		t.Fatalf("expected success count 1, got %d", got)
	}
	if got := client.FailureCount(); got != 0 {
		t.Fatalf("expected failure count 0, got %d", got)
	}
}

func decodeGzipBody(t *testing.T, body io.ReadCloser) []byte {
	t.Helper()
	defer body.Close()

	compressed, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gr.Close()

	raw, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed to read gzip body: %v", err)
	}
	return raw
}

func testRetryConfig() config.RetryConfig {
	return config.RetryConfig{
		MaxRetries:        2,
		InitialBackoff:    1 * time.Millisecond,
		MaxBackoff:        5 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func httpResponse(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte("ok"))),
	}
}
