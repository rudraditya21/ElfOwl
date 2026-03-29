package evidence

import "testing"

const testAESKeyBase64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func TestNewCipherValidation(t *testing.T) {
	if _, err := NewCipher("not-base64"); err == nil {
		t.Fatalf("expected decode error for invalid base64 key")
	}

	if _, err := NewCipher("c2hvcnQ="); err == nil {
		t.Fatalf("expected length error for short key")
	}

	cipher, err := NewCipher(testAESKeyBase64)
	if err != nil {
		t.Fatalf("unexpected error creating cipher: %v", err)
	}
	if cipher == nil {
		t.Fatalf("expected non-nil cipher")
	}
}

func TestCipherEncryptDecryptRoundTrip(t *testing.T) {
	cipher, err := NewCipher(testAESKeyBase64)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	plaintext := []byte(`{"event":"hello","count":1}`)
	ciphertext, nonce, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if len(ciphertext) == 0 || len(nonce) == 0 {
		t.Fatalf("expected ciphertext and nonce to be populated")
	}

	decrypted, err := cipher.Decrypt(ciphertext, nonce)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %q want %q", string(decrypted), string(plaintext))
	}
}

func TestCipherDecryptWrongNonceFails(t *testing.T) {
	cipher, err := NewCipher(testAESKeyBase64)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	plaintext := []byte("secret")
	ciphertext, nonce, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	nonce[0] ^= 0xFF

	if _, err := cipher.Decrypt(ciphertext, nonce); err == nil {
		t.Fatalf("expected decrypt failure with tampered nonce")
	}
}
