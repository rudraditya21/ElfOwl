// ANCHOR: eBPF Shared Types and Constants - Dec 27, 2025
// Defines event structures and constants shared between kernel and userspace
// Used by loader.go and eBPF C programs for consistent data exchange

package ebpf

import (
	"encoding/binary"
	"fmt"
)

// ============================================================================
// Program Names - Match filenames in pkg/ebpf/programs/
// ============================================================================

const (
	ProcessProgramName    = "process"
	NetworkProgramName    = "network"
	FileProgramName       = "file"
	CapabilityProgramName = "capability"
	DNSProgramName        = "dns"
	TLSProgramName        = "tls"
)

// ============================================================================
// Map Names - Declared in eBPF programs via BPF_PERF_OUTPUT
// ============================================================================

const (
	ProcessEventsMap    = "process_events"
	NetworkEventsMap    = "network_events"
	FileEventsMap       = "file_events"
	CapabilityEventsMap = "capability_events"
	DNSEventsMap        = "dns_events"
	TLSEventsMap        = "tls_events"
)

// ============================================================================
// Process Event Structure (matches eBPF struct process_event)
// ============================================================================

type ProcessEvent struct {
	PID          uint32
	UID          uint32
	GID          uint32
	Capabilities uint64
	Filename     [256]byte
	Argv         [256]byte
	CgroupID     uint64
}

// ============================================================================
// Network Event Structure (matches eBPF struct network_event)
// ============================================================================

// ANCHOR: NetworkEvent extended layout - Feature: IPv6 + state metadata - Mar 25, 2026
// Matches the packed network_event layout in the eBPF program.
type NetworkEvent struct {
	PID       uint32
	Family    uint16 // AF_INET=2 or AF_INET6=10
	SPort     uint16 // Host byte order
	DPort     uint16 // Host byte order
	SAddr     uint32 // IPv4 only
	DAddr     uint32 // IPv4 only
	SAddrV6   [16]byte
	DAddrV6   [16]byte
	Protocol  uint8 // IPPROTO_TCP=6 or IPPROTO_UDP=17
	Direction uint8
	State     uint8
	NetNS     uint32
	CgroupID  uint64
}

// ============================================================================
// File Event Structure (matches eBPF struct file_event)
// ============================================================================

// ANCHOR: FileEvent mode + fd fields - Feature: expanded file syscall coverage - Mar 25, 2026
// Matches the packed file_event layout in the eBPF program.
type FileEvent struct {
	PID       uint32
	Flags     uint32 // Open or operation flags
	Mode      uint32 // chmod/openat mode
	FD        uint32 // write/pwrite fd or *at dir fd
	Operation uint8  // write=1, read=2, chmod=3, unlink=4
	CgroupID  uint64
	Filename  [256]byte
	FlagsStr  [32]byte
}

// ============================================================================
// Capability Event Structure (matches eBPF struct capability_event)
// ============================================================================

// ANCHOR: CapabilityEvent syscall id - Feature: syscall attribution - Mar 25, 2026
// Matches the packed capability_event layout in the eBPF program.
type CapabilityEvent struct {
	PID         uint32
	Capability  uint32 // CAP_SYS_ADMIN=21, CAP_SYS_MODULE=16, etc.
	CheckType   uint8  // check=1, use=2
	SyscallID   uint32
	CgroupID    uint64
	SyscallName [32]byte
}

// ============================================================================
// DNS Event Structure (matches eBPF struct dns_event)
// ============================================================================

// ANCHOR: DNSEvent server family - Feature: IPv6 DNS visibility - Mar 25, 2026
// Matches the packed dns_event layout in the eBPF program.
type DNSEvent struct {
	PID          uint32
	QueryType    uint16 // A=1, AAAA=28, MX=15, TXT=16, etc.
	ResponseCode uint8  // 0=NOERROR, 1=FORMERR, 2=SERVFAIL, etc.
	QueryAllowed uint8  // 1=allowed, 0=suspicious/blocked
	ServerFamily uint16 // AF_INET=2 or AF_INET6=10
	CgroupID     uint64
	QueryName    [256]byte // Domain name
	Server       [16]byte  // DNS server IP
}

// ============================================================================
// TLS Event Structure (matches eBPF struct tls_event)
// ============================================================================

// TLSClientHelloEvent carries the first bytes of an outbound TLS ClientHello.
type TLSClientHelloEvent struct {
	PID       uint32
	Family    uint16
	Protocol  uint8
	Direction uint8
	SrcPort   uint16
	DstPort   uint16
	CgroupID  uint64
	// ANCHOR: TLS buffer size increase to 2048 - Fix: TLS 1.3 key_share truncation - Apr 29, 2026
	// 2048 bytes covers PQ-hybrid key_share extensions (X25519Kyber768 ~1200 bytes) that exceeded
	// the previous 1024-byte limit and produced inconsistent JA3 fingerprints for TLS 1.3 clients.
	// Must match TLS_METADATA_MAX in pkg/ebpf/programs/tls.c for binary.Read to succeed.
	Length   uint32
	Metadata [2048]byte
}

// ANCHOR: TLSClientHelloEvent packed decode - Bug: amd64 alignment padding mismatches __attribute__((packed)) C struct - Apr 30, 2026
// The C struct uses __attribute__((packed)) so fields are contiguous with no alignment gaps.
// Go's default struct layout inserts 4 bytes of padding before CgroupID (uint64 aligned to 8),
// shifting CgroupID, Length, and Metadata to wrong offsets when using binary.Read directly.
// Offsets (packed): PID=0 Family=4 Protocol=6 Direction=7 SrcPort=8 DstPort=10 CgroupID=12 Length=20 Metadata=24
const tlsEventFixedSize = 24 // bytes before Metadata

// DecodeTLSEvent decodes a packed eBPF tls_event byte slice into TLSClientHelloEvent
// using explicit little-endian reads at known offsets, bypassing Go struct alignment.
func DecodeTLSEvent(b []byte) (*TLSClientHelloEvent, error) {
	if len(b) < tlsEventFixedSize {
		return nil, fmt.Errorf("tls event too short: %d bytes", len(b))
	}
	e := &TLSClientHelloEvent{
		PID:       binary.LittleEndian.Uint32(b[0:4]),
		Family:    binary.LittleEndian.Uint16(b[4:6]),
		Protocol:  b[6],
		Direction: b[7],
		SrcPort:   binary.LittleEndian.Uint16(b[8:10]),
		DstPort:   binary.LittleEndian.Uint16(b[10:12]),
		CgroupID:  binary.LittleEndian.Uint64(b[12:20]),
		Length:    binary.LittleEndian.Uint32(b[20:24]),
	}
	copy(e.Metadata[:], b[tlsEventFixedSize:])
	return e, nil
}

// ============================================================================
// Capability Constants (from include/uapi/linux/capability.h)
// ============================================================================

const (
	CapSysAdmin    = 21
	CapSysModule   = 16
	CapSysBoot     = 22
	CapSysPtrace   = 19
	CapNetAdmin    = 12
	CapSysRawio    = 17
	CapSysResource = 24
)

// ============================================================================
// File Operation Types
// ============================================================================

const (
	FileOpWrite = iota + 1
	FileOpRead
	FileOpChmod
	FileOpUnlink
)

// ============================================================================
// DNS Query Types (RFC 1035 section 3.2.2)
// ============================================================================

const (
	DNSTypeA     = 1
	DNSTypeAAAA  = 28
	DNSTypeMX    = 15
	DNSTypeTXT   = 16
	DNSTypeCNAME = 5
	DNSTypeSOA   = 6
	DNSTypeNS    = 2
	DNSTypeANY   = 255
)

// ============================================================================
// DNS Response Codes (RFC 1035 section 4.1.1)
// ============================================================================

const (
	DNSRCodeNoError  = 0
	DNSRCodeFormErr  = 1
	DNSRCodeServFail = 2
	DNSRCodeNameErr  = 3
	DNSRCodeNotImpl  = 4
	DNSRCodeRefused  = 5
)

// ============================================================================
// Network Constants
// ============================================================================

const (
	AF_INET  = 2
	AF_INET6 = 10

	IPPROTO_TCP = 6
	IPPROTO_UDP = 17

	AF_UNSPEC = 0
)

// ============================================================================
// File Open Flags (from include/uapi/asm-generic/fcntl.h)
// ============================================================================

const (
	O_WRONLY   = 1
	O_RDWR     = 2
	O_CREAT    = 64
	O_EXCL     = 128
	O_TRUNC    = 512
	O_APPEND   = 1024
	O_NONBLOCK = 2048
)
