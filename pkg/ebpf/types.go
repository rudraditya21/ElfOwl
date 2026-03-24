// ANCHOR: eBPF Shared Types and Constants - Dec 27, 2025
// Defines event structures and constants shared between kernel and userspace
// Used by loader.go and eBPF C programs for consistent data exchange

package ebpf

// ============================================================================
// Program Names - Match filenames in pkg/ebpf/programs/
// ============================================================================

const (
	ProcessProgramName    = "process"
	NetworkProgramName    = "network"
	FileProgramName       = "file"
	CapabilityProgramName = "capability"
	DNSProgramName        = "dns"
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
)

// ============================================================================
// Process Event Structure (matches eBPF struct process_event)
// ============================================================================
// ANCHOR: Event struct expansion - Feature: IPv6/syscalls/file mode - Mar 24, 2026
// Keeps Go layouts aligned with updated eBPF event structures.

type ProcessEvent struct {
	CgroupID     uint64
	Capabilities uint64
	PID          uint32
	UID          uint32
	GID          uint32
	Filename     [256]byte
	Argv         [256]byte
}

// ============================================================================
// Network Event Structure (matches eBPF struct network_event)
// ============================================================================

type NetworkEvent struct {
	CgroupID  uint64
	PID       uint32
	NetNS     uint32
	SAddr     uint32 // IPv4 source (host byte order)
	DAddr     uint32 // IPv4 destination (host byte order)
	Family    uint16 // AF_INET=2 or AF_INET6=10
	SPort     uint16 // Source port (host byte order)
	DPort     uint16 // Destination port (host byte order)
	Protocol  uint8  // IPPROTO_TCP=6 or IPPROTO_UDP=17
	Direction uint8  // 1=outbound, 2=inbound
	State     uint8  // TCP state transition (newstate)
	SAddrV6   [16]byte
	DAddrV6   [16]byte
}

// ============================================================================
// File Event Structure (matches eBPF struct file_event)
// ============================================================================

type FileEvent struct {
	CgroupID  uint64
	PID       uint32
	Flags     uint32 // Open flags (O_WRONLY, O_RDWR, etc.)
	Mode      uint32
	FD        uint32
	Operation uint8 // write=1, read=2, chmod=3, unlink=4
	Sensitive uint8
	Filename  [256]byte
	FlagsStr  [32]byte
}

// ============================================================================
// Capability Event Structure (matches eBPF struct capability_event)
// ============================================================================

type CapabilityEvent struct {
	CgroupID    uint64
	PID         uint32
	Capability  uint32 // CAP_SYS_ADMIN=21, CAP_SYS_MODULE=16, etc.
	SyscallID   uint32
	CheckType   uint8 // check=1, use=2
	SyscallName [32]byte
}

// ============================================================================
// DNS Event Structure (matches eBPF struct dns_event)
// ============================================================================

type DNSEvent struct {
	PID          uint32
	QueryType    uint16 // A=1, AAAA=28, MX=15, TXT=16, etc.
	ResponseCode uint8  // 0=NOERROR, 1=FORMERR, 2=SERVFAIL, etc.
	QueryAllowed uint8  // 1=allowed, 0=suspicious/blocked
	CgroupID     uint64
	QueryName    [256]byte // Domain name
	Server       [16]byte  // DNS server IP
}

// ============================================================================
// Capability Constants (from include/uapi/linux/capability.h)
// ============================================================================

const (
	CapSysAdmin    = 21
	CapSysModule   = 16
	CapSysBoot     = 23
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
