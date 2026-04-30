// ANCHOR: JA3 re-exports from pkg/ja3 - Refactor: eliminate ebpf/enrichment duplication - Apr 29, 2026
// Real implementation lives in pkg/ja3. This file keeps the pkg/ebpf surface stable so
// tls_monitor.go compiles without import changes.

package ebpf

import "github.com/udyansh/elf-owl/pkg/ja3"

// JA3Metadata is an alias for ja3.JA3Metadata.
type JA3Metadata = ja3.JA3Metadata

// ParseJA3Metadata parses a TLS ClientHello and returns JA3 metadata.
func ParseJA3Metadata(clientHello []byte) (*JA3Metadata, error) {
	return ja3.ParseJA3Metadata(clientHello)
}

// ExtractTLSClientHello parses a ClientHello body and returns JA3 component lists.
func ExtractTLSClientHello(b []byte) (string, []uint16, []uint16, []uint16, []uint8, error) {
	return ja3.ExtractTLSClientHello(b)
}
