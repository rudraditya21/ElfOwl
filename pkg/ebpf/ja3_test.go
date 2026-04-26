package ebpf

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

func TestParseJA3MetadataRawClientHello(t *testing.T) {
	clientHello := testClientHello()

	meta, err := ParseJA3Metadata(clientHello)
	if err != nil {
		t.Fatalf("ParseJA3Metadata error: %v", err)
	}

	if meta == nil {
		t.Fatal("expected metadata")
	}

	if meta.TLSVersion != "771" {
		t.Fatalf("unexpected tls version: %s", meta.TLSVersion)
	}

	wantString := "771,4865-4866-49195,10-11,29-23,0"
	if meta.JA3String != wantString {
		t.Fatalf("unexpected ja3 string: got %q want %q", meta.JA3String, wantString)
	}

	sum := md5.Sum([]byte(wantString))
	wantHash := hex.EncodeToString(sum[:])
	if meta.JA3Fingerprint != wantHash {
		t.Fatalf("unexpected ja3 hash: got %q want %q", meta.JA3Fingerprint, wantHash)
	}
}

func TestParseJA3MetadataTLSRecordWrapped(t *testing.T) {
	record := append([]byte{0x16, 0x03, 0x03, 0x00, 0x00}, testClientHello()...)
	// Fix record length.
	recordLen := len(record) - 5
	record[3] = byte(recordLen >> 8)
	record[4] = byte(recordLen)

	meta, err := ParseJA3Metadata(record)
	if err != nil {
		t.Fatalf("ParseJA3Metadata error: %v", err)
	}
	if meta.JA3Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
}

func TestParseJA3MetadataRejectsNonClientHello(t *testing.T) {
	if _, err := ParseJA3Metadata([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("expected error")
	}
}

func testClientHello() []byte {
	// Minimal TLS ClientHello handshake body:
	// - handshake type + length
	// - version TLS 1.2 (771)
	// - random
	// - session id length 0
	// - cipher suites length 6 with 3 suites
	// - compression methods length 1 with null
	// - extensions:
	//   supported groups, ec point formats, SNI omitted
	body := []byte{
		0x01, 0x00, 0x00, 0x49,
		0x03, 0x03,
	}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x06)
	body = append(body, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2b)
	body = append(body, 0x01, 0x00)

	ext := []byte{
		0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17,
		0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
	}
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	body[1] = byte((len(body) - 4) >> 16)
	body[2] = byte((len(body) - 4) >> 8)
	body[3] = byte(len(body) - 4)
	return body
}
