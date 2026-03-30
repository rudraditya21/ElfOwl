package evidence

import "testing"

const testHMACKeyBase64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func TestNewSignerValidation(t *testing.T) {
	if _, err := NewSigner("not-base64"); err == nil {
		t.Fatalf("expected decode error for invalid base64 key")
	}

	if _, err := NewSigner("c2hvcnQ="); err == nil {
		t.Fatalf("expected length error for short key")
	}

	signer, err := NewSigner(testHMACKeyBase64)
	if err != nil {
		t.Fatalf("unexpected error creating signer: %v", err)
	}
	if signer == nil {
		t.Fatalf("expected non-nil signer")
	}
}

func TestSignerRoundTrip(t *testing.T) {
	signer, err := NewSigner(testHMACKeyBase64)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	payload := []byte(`{"event":"test","id":"1"}`)
	signature := signer.Sign(payload)
	if signature == "" {
		t.Fatalf("expected non-empty signature")
	}

	if !signer.Verify(payload, signature) {
		t.Fatalf("expected signature verification success")
	}

	if signer.Verify([]byte(`{"event":"tampered"}`), signature) {
		t.Fatalf("expected signature verification failure for tampered payload")
	}
}
