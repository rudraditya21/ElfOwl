// ANCHOR: Shared JA3 parser package - Refactor: eliminate ebpf/enrichment duplication - Apr 29, 2026
// Extracted from pkg/ebpf/ja3.go; both pkg/ebpf and pkg/enrichment import this.
// Avoids circular dependency: pkg/agent → pkg/enrichment and pkg/agent → pkg/ebpf.

package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// JA3Metadata contains the parsed JA3 components and fingerprint for a TLS ClientHello.
type JA3Metadata struct {
	TLSVersion     string
	Ciphers        []uint16
	Extensions     []uint16
	Curves         []uint16
	PointFormats   []uint8
	JA3String      string
	JA3Fingerprint string
	SNI            string
}

// ParseJA3Metadata parses a TLS ClientHello and returns JA3 metadata.
// Accepts either a raw ClientHello handshake body or a full TLS record.
func ParseJA3Metadata(clientHello []byte) (*JA3Metadata, error) {
	body, err := NormalizeClientHello(clientHello)
	if err != nil {
		return nil, err
	}

	tlsVersion, ciphers, extensions, curves, pointFormats, err := ExtractTLSClientHello(body)
	if err != nil {
		return nil, err
	}

	ja3String := BuildJA3String(tlsVersion, ciphers, extensions, curves, pointFormats)
	sum := md5.Sum([]byte(ja3String))

	return &JA3Metadata{
		TLSVersion:     tlsVersion,
		Ciphers:        ciphers,
		Extensions:     extensions,
		Curves:         curves,
		PointFormats:   pointFormats,
		JA3String:      ja3String,
		JA3Fingerprint: hex.EncodeToString(sum[:]),
		SNI:            ExtractSNI(body),
	}, nil
}

// IsGREASEValue reports whether v is a TLS GREASE value (RFC 8701).
func IsGREASEValue(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

// ExtractTLSClientHello parses a ClientHello body and returns JA3 component lists.
// The input must be the ClientHello handshake message body (not a full TLS record).
func ExtractTLSClientHello(clientHelloBytes []byte) (
	tlsVersion string,
	ciphers []uint16,
	extensions []uint16,
	curves []uint16,
	pointFormats []uint8,
	err error,
) {
	if len(clientHelloBytes) < 42 {
		return "", nil, nil, nil, nil, fmt.Errorf("ClientHello too short: %d bytes", len(clientHelloBytes))
	}

	if clientHelloBytes[0] != 0x01 {
		return "", nil, nil, nil, nil, fmt.Errorf("not a ClientHello handshake message: 0x%02x", clientHelloBytes[0])
	}

	offset := 4
	if offset+2 > len(clientHelloBytes) {
		return "", nil, nil, nil, nil, fmt.Errorf("insufficient data for ClientHello version")
	}
	rawVersion := uint16(clientHelloBytes[offset])<<8 | uint16(clientHelloBytes[offset+1])
	// ANCHOR: TLS version sanity check - Fix: garbage non-ClientHello records parsed as ClientHello - Apr 26, 2026
	// Valid legacy_version in ClientHello is 0x0301 (TLS1.0) through 0x0304 (TLS1.3).
	// Reject anything outside this range to avoid treating encrypted app data as ClientHello.
	if rawVersion < 0x0301 || rawVersion > 0x0304 {
		return "", nil, nil, nil, nil, fmt.Errorf("invalid TLS version 0x%04x", rawVersion)
	}
	tlsVersion = strconv.Itoa(int(rawVersion))
	offset += 2

	if offset+32 > len(clientHelloBytes) {
		return "", nil, nil, nil, nil, fmt.Errorf("insufficient data for random")
	}
	offset += 32

	if offset >= len(clientHelloBytes) {
		return "", nil, nil, nil, nil, fmt.Errorf("insufficient data for session id length")
	}
	sessionIDLen := int(clientHelloBytes[offset])
	offset++
	if offset+sessionIDLen > len(clientHelloBytes) {
		return "", nil, nil, nil, nil, fmt.Errorf("insufficient data for session id")
	}
	offset += sessionIDLen

	if offset+2 > len(clientHelloBytes) {
		return "", nil, nil, nil, nil, fmt.Errorf("insufficient data for cipher suite length")
	}
	cipherLen := int(clientHelloBytes[offset])<<8 | int(clientHelloBytes[offset+1])
	offset += 2
	// ANCHOR: Graceful cipher truncation - Fix: non-ClientHello / short captures - Apr 26, 2026
	// Clamp to available bytes so partial captures still yield usable cipher lists.
	if available := len(clientHelloBytes) - offset; cipherLen > available {
		cipherLen = available &^ 1 // round down to even
	}
	for i := 0; i < cipherLen; i += 2 {
		c := uint16(clientHelloBytes[offset+i])<<8 | uint16(clientHelloBytes[offset+i+1])
		if !IsGREASEValue(c) {
			ciphers = append(ciphers, c)
		}
	}
	offset += cipherLen

	if offset >= len(clientHelloBytes) {
		return tlsVersion, ciphers, nil, nil, nil, nil
	}

	compLen := int(clientHelloBytes[offset])
	offset++
	if offset+compLen > len(clientHelloBytes) {
		return "", nil, nil, nil, nil, fmt.Errorf("insufficient data for compression methods")
	}
	offset += compLen

	if offset == len(clientHelloBytes) {
		return tlsVersion, ciphers, nil, nil, nil, nil
	}
	if offset+2 > len(clientHelloBytes) {
		return "", nil, nil, nil, nil, fmt.Errorf("insufficient data for extensions length")
	}
	extLen := int(clientHelloBytes[offset])<<8 | int(clientHelloBytes[offset+1])
	offset += 2
	// ANCHOR: Graceful truncation for extensions - Fix: ClientHellos > capture buffer - Apr 26, 2026
	// Matches vaanvil: clamp extLen to available bytes and parse what we have rather than failing.
	if available := len(clientHelloBytes) - offset; extLen > available {
		extLen = available
	}
	extEnd := offset + extLen
	for offset+4 <= extEnd {
		extType := uint16(clientHelloBytes[offset])<<8 | uint16(clientHelloBytes[offset+1])
		extSize := int(clientHelloBytes[offset+2])<<8 | int(clientHelloBytes[offset+3])
		offset += 4
		if offset+extSize > extEnd {
			break // truncated extension — stop but keep what we parsed
		}
		if IsGREASEValue(extType) {
			offset += extSize
			continue
		}
		extensions = append(extensions, extType)

		switch extType {
		case 0x000a: // supported_groups
			if extSize < 2 {
				break
			}
			listLen := int(clientHelloBytes[offset])<<8 | int(clientHelloBytes[offset+1])
			if 2+listLen > extSize {
				break
			}
			for i := 0; i+1 < listLen; i += 2 {
				c := uint16(clientHelloBytes[offset+2+i])<<8 | uint16(clientHelloBytes[offset+2+i+1])
				if !IsGREASEValue(c) {
					curves = append(curves, c)
				}
			}
		case 0x000b: // ec_point_formats
			if extSize < 1 {
				break
			}
			listLen := int(clientHelloBytes[offset])
			if 1+listLen > extSize {
				break
			}
			for i := 0; i < listLen; i++ {
				pointFormats = append(pointFormats, clientHelloBytes[offset+1+i])
			}
		}
		offset += extSize
	}

	return tlsVersion, ciphers, extensions, curves, pointFormats, nil
}

// ExtractSNI walks the extensions block of a normalised ClientHello body and returns the first SNI hostname.
// ANCHOR: SNI extraction from server_name extension (0x0000) - Feature: cert probing - Apr 26, 2026
func ExtractSNI(body []byte) string {
	// Skip: handshake type(1) + length(3) + version(2) + random(32) = 38 bytes, then session id
	if len(body) < 38 {
		return ""
	}
	off := 38
	if off >= len(body) {
		return ""
	}
	sidLen := int(body[off])
	off += 1 + sidLen
	if off+2 > len(body) {
		return ""
	}
	cipherLen := int(body[off])<<8 | int(body[off+1])
	off += 2 + cipherLen
	if off >= len(body) {
		return ""
	}
	compLen := int(body[off])
	off += 1 + compLen
	if off+2 > len(body) {
		return ""
	}
	extLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	if available := len(body) - off; extLen > available {
		extLen = available
	}
	extEnd := off + extLen
	for off+4 <= extEnd {
		extType := uint16(body[off])<<8 | uint16(body[off+1])
		extSize := int(body[off+2])<<8 | int(body[off+3])
		off += 4
		if off+extSize > extEnd {
			break
		}
		if extType == 0x0000 && extSize >= 5 {
			// server_name list length(2) + name type(1) + name length(2) + name
			listLen := int(body[off])<<8 | int(body[off+1])
			if listLen >= 3 && off+2+listLen <= extEnd {
				nameLen := int(body[off+3])<<8 | int(body[off+4])
				nameOff := off + 5
				if nameLen > 0 && nameOff+nameLen <= extEnd {
					return string(body[nameOff : nameOff+nameLen])
				}
			}
		}
		off += extSize
	}
	return ""
}

// NormalizeClientHello strips a TLS record header if present, returning the raw ClientHello body.
func NormalizeClientHello(b []byte) ([]byte, error) {
	if len(b) >= 5 && b[0] == 0x16 {
		if len(b) < 9 || b[5] != 0x01 {
			return nil, fmt.Errorf("TLS record does not contain ClientHello")
		}
		handshakeLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
		end := 9 + handshakeLen
		if end > len(b) {
			end = len(b)
		}
		return b[5:end], nil
	}
	if len(b) > 0 && b[0] == 0x01 {
		return b, nil
	}
	return nil, fmt.Errorf("not a TLS ClientHello")
}

// BuildJA3String formats the JA3 components as a CSV string.
func BuildJA3String(version string, ciphers, extensions []uint16, curves []uint16, pointFormats []uint8) string {
	return fmt.Sprintf("%s,%s,%s,%s,%s",
		version,
		JoinUint16s(ciphers),
		JoinUint16s(extensions),
		JoinUint16s(curves),
		JoinUint8s(pointFormats),
	)
}

// JoinUint16s joins a slice of uint16 values as a dash-separated decimal string.
func JoinUint16s(v []uint16) string {
	if len(v) == 0 {
		return ""
	}
	parts := make([]string, 0, len(v))
	for _, n := range v {
		parts = append(parts, strconv.Itoa(int(n)))
	}
	return strings.Join(parts, "-")
}

// JoinUint8s joins a slice of uint8 values as a dash-separated decimal string.
func JoinUint8s(v []uint8) string {
	if len(v) == 0 {
		return ""
	}
	parts := make([]string, 0, len(v))
	for _, n := range v {
		parts = append(parts, strconv.Itoa(int(n)))
	}
	return strings.Join(parts, "-")
}
