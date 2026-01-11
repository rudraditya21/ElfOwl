# elf-owl: Migration Plan from goBPF to Cilium/eBPF

**Version:** 1.0.0
**Date:** December 27, 2025
**Status:** Migration Plan - Ready for Implementation
**Target Go Version:** 1.19+
**Target Cilium/eBPF Version:** v0.11.0+

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Motivation for Migration](#motivation-for-migration)
3. [Architecture Comparison](#architecture-comparison)
4. [Migration Strategy](#migration-strategy)
5. [Phase-by-Phase Implementation](#phase-by-phase-implementation)
6. [Code Changes Overview](#code-changes-overview)
7. [Testing Strategy](#testing-strategy)
8. [Rollback Plan](#rollback-plan)
9. [Success Criteria](#success-criteria)
10. [Risk Assessment](#risk-assessment)

---

## Executive Summary

elf-owl will migrate from the custom `github.com/udyansh/gobpf` library to the production-grade **Cilium/eBPF** library (`github.com/cilium/ebpf`). This migration will:

- **Maintain 100% feature parity** with existing goBPF integration
- **Improve reliability** with battle-tested Cilium eBPF library (used in production by Cilium, Falco, etc.)
- **Reduce technical debt** by eliminating custom wrapper library
- **Simplify deployment** with standard open-source dependencies
- **Enhance maintainability** with community-supported code

**Migration Scope:** 5 security monitors (process, network, file, capability, DNS)
**Estimated Effort:** 3-4 days (distributed across Week 3-4)
**Risk Level:** LOW (feature-complete alternative with proven track record)

---

## Motivation for Migration

### Why Cilium/eBPF?

**Current State (goBPF):**
- Custom wrapper library maintained by single entity
- Limited community feedback
- May have unfixed bugs or performance issues
- Tight coupling to internal implementation details
- No existing integration patterns from other projects

**Target State (Cilium/eBPF):**
- ✅ Production-grade library used by Cilium, Falco, Tetragon, etc.
- ✅ Active community with regular updates and security patches
- ✅ Battle-tested by thousands of deployments
- ✅ Well-documented with comprehensive examples
- ✅ Professional support and issue resolution
- ✅ Already transitively included in go.mod (as indirect dependency)
- ✅ Modern eBPF best practices built-in

**Evidence:**
- Cilium/eBPF v0.11.0 already appears in go.mod as indirect dependency
- Mature codebase with 2000+ GitHub stars
- Used in production security tools (Falco, Tetragon, Cilium)
- Regular security updates and bug fixes

---

## Architecture Comparison

### Current Architecture (goBPF)

```
goBPF Library (github.com/udyansh/gobpf)
    │
    ├── ProcessMonitor (wrapper around eBPF program)
    ├── NetworkMonitor (wrapper around eBPF program)
    ├── FileMonitor (wrapper around eBPF program)
    ├── CapabilityMonitor (wrapper around eBPF program)
    └── DNSMonitor (wrapper around eBPF program)
         │
         └── Events → Agent → Enrichment → Rules → Evidence → Push
```

### Target Architecture (Cilium/eBPF)

```
Cilium/eBPF Library (github.com/cilium/ebpf)
    │
    ├── eBPF Program Loader (handles bytecode compilation & loading)
    ├── Maps (in-kernel key-value stores)
    ├── Programs (in-kernel execution units)
    ├── Perf Readers (event streaming)
    └── Ringbuffer Readers (high-performance event streaming)
         │
         └── elf-owl Monitors (process, network, file, capability, DNS)
             │
             └── Events → Agent → Enrichment → Rules → Evidence → Push
```

### Key Differences

| Aspect | goBPF | Cilium/eBPF |
|--------|-------|-------------|
| **Library Type** | Wrapper | Core eBPF library |
| **Event Streaming** | Monitor abstractions | Perf/Ringbuffer readers |
| **Program Loading** | Encapsulated | Explicit with `Collection` API |
| **eBPF Programs** | Opaque | User-provided (C code compiled to bytecode) |
| **Community** | Internal | Production (Cilium, Falco, etc.) |
| **Maintenance** | Single maintainer | Active open-source community |
| **Learning Curve** | Moderate | Moderate (but excellent docs) |

---

## Migration Strategy

### Three-Phase Approach

```
Phase 1: Library Setup & Configuration (Days 1-2)
    - Add cilium/ebpf to go.mod
    - Remove gobpf dependency
    - Create eBPF program files
    - Set up build pipeline

Phase 2: Monitor Implementation (Days 2-3)
    - Implement ProcessMonitor using cilium/ebpf
    - Implement NetworkMonitor using cilium/ebpf
    - Implement FileMonitor using cilium/ebpf
    - Implement CapabilityMonitor using cilium/ebpf
    - Implement DNSMonitor using cilium/ebpf

Phase 3: Integration & Testing (Day 4+)
    - Update agent.go to use new monitors
    - Verify event type compatibility
    - Run all integration tests
    - Performance testing and tuning
    - Documentation updates
```

### Design Principles

1. **Incremental Migration**: One monitor at a time
2. **Backward Compatibility**: Maintain event schemas
3. **No API Changes**: External interfaces unchanged
4. **Comprehensive Testing**: Unit tests for each monitor
5. **Performance Parity**: Ensure no performance regression

---

## Phase-by-Phase Implementation

### Phase 1: Library Setup & Configuration

**Duration:** Days 1-2
**Complexity:** Low-Medium
**Risk:** Very Low

#### 1.1: Update go.mod

**File:** `go.mod`

```go
// Before:
github.com/udyansh/gobpf v0.1.0
replace github.com/udyansh/gobpf => ../gobpf

// After:
github.com/cilium/ebpf v0.11.0
// Remove gobpf entirely
```

**Anchor Comment:**
```go
// ANCHOR: Migration to Cilium/eBPF - Feature: Production-grade eBPF library - Dec 27, 2025
// Replaces custom gobpf wrapper with battle-tested Cilium eBPF library used in production
// by Cilium, Falco, Tetragon. Provides better support, security updates, and documentation.
```

#### 1.2: Create eBPF Program Directory Structure

**New Directory:** `pkg/ebpf/programs/`

```
pkg/ebpf/
├── programs/
│   ├── process.c          # Process execution monitoring
│   ├── network.c          # Network connection monitoring
│   ├── file.c             # File access monitoring
│   ├── capability.c       # Linux capability usage monitoring
│   ├── dns.c              # DNS query monitoring
│   └── Makefile           # Build eBPF programs to bytecode
├── loader.go              # Cilium/eBPF program loader
├── process_monitor.go     # Process monitor implementation
├── network_monitor.go     # Network monitor implementation
├── file_monitor.go        # File monitor implementation
├── capability_monitor.go  # Capability monitor implementation
├── dns_monitor.go         # DNS monitor implementation
└── types.go               # Shared types and constants
```

#### 1.3: Create Build Pipeline for eBPF Programs

**File:** `pkg/ebpf/programs/Makefile`

```makefile
CLANG ?= clang
LLC ?= llc

# Build flags for eBPF programs
CFLAGS := -O2 -target bpf

# Output directory for compiled bytecode
OUTPUT := bin

all: $(OUTPUT)/process.o $(OUTPUT)/network.o $(OUTPUT)/file.o \
     $(OUTPUT)/capability.o $(OUTPUT)/dns.o

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(OUTPUT)/%.o: %.c | $(OUTPUT)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTPUT)

.PHONY: all clean
```

**Anchor Comment:**
```go
// ANCHOR: eBPF program compilation - Feature: Build bytecode from C source - Dec 27, 2025
// Compiles eBPF programs written in C to bytecode (.o files).
// Programs are embedded and loaded at runtime by cilium/ebpf Collection API.
```

#### 1.4: Create eBPF Program Loader

**File:** `pkg/ebpf/loader.go`

```go
// ANCHOR: Cilium/eBPF program loader - Feature: Load compiled eBPF programs - Dec 27, 2025
// Loads pre-compiled eBPF programs (.o files) using cilium/ebpf Collection API.
// Manages program loading, map access, and perf/ringbuffer readers.

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// Collection wraps all loaded eBPF programs and maps
type Collection struct {
	Process    *ProgramSet
	Network    *ProgramSet
	File       *ProgramSet
	Capability *ProgramSet
	DNS        *ProgramSet
	Logger     *zap.Logger
}

// ProgramSet contains a program and its associated maps
type ProgramSet struct {
	Program *ebpf.Program
	Maps    map[string]*ebpf.Map
	Reader  Reader // PerfReader or RingbufferReader
}

// Reader interface for event streaming
type Reader interface {
	Read() ([]byte, error)
	Close() error
}

// LoadPrograms loads all eBPF programs from compiled bytecode
func LoadPrograms(logger *zap.Logger) (*Collection, error) {
	spec, err := ebpf.LoadCollectionSpec("path/to/compiled/bytecode.o")
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF specs: %w", err)
	}

	coll := &ebpf.Collection{}
	if err := spec.LoadAndAssign(coll, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF programs: %w", err)
	}

	return &Collection{
		Process:    &ProgramSet{Program: coll.Programs["process_exec"]},
		Network:    &ProgramSet{Program: coll.Programs["network_connect"]},
		File:       &ProgramSet{Program: coll.Programs["file_open"]},
		Capability: &ProgramSet{Program: coll.Programs["capability_use"]},
		DNS:        &ProgramSet{Program: coll.Programs["dns_query"]},
		Logger:     logger,
	}, nil
}

// Close closes all readers and programs
func (c *Collection) Close() error {
	if c.Process != nil && c.Process.Reader != nil {
		if err := c.Process.Reader.Close(); err != nil {
			c.Logger.Warn("failed to close process reader", zap.Error(err))
		}
	}
	// Close other readers...
	return nil
}
```

#### 1.5: Update Agent Configuration

**File:** `pkg/agent/config.go`

Change configuration to reflect Cilium/eBPF instead of goBPF:

```go
type eBPFConfig struct {
	Enabled bool              `yaml:"enabled" json:"enabled"`
	Process ProcessConfig    `yaml:"process" json:"process"`
	Network NetworkConfig    `yaml:"network" json:"network"`
	File    FileConfig       `yaml:"file" json:"file"`
	Capability CapabilityConfig `yaml:"capability" json:"capability"`
	DNS     DNSConfig        `yaml:"dns" json:"dns"`
}

type ProcessConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// No longer need wrapper-specific options
}
```

---

### Phase 2: Monitor Implementation

**Duration:** Days 2-3
**Complexity:** Medium-High
**Risk:** Low (feature-by-feature migration)

#### 2.1: Process Monitor Implementation

**File:** `pkg/ebpf/process_monitor.go`

```go
// ANCHOR: Process execution monitor - Feature: Cilium/eBPF process monitoring - Dec 27, 2025
// Replaces goBPF ProcessMonitor with cilium/ebpf-based implementation.
// Uses perf_events tracepoint for process_exec, exits, and syscall traces.

package ebpf

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// ProcessMonitor monitors process execution events
type ProcessMonitor struct {
	prog   *ebpf.Program
	reader *perf.Reader
	logger *zap.Logger
}

// NewProcessMonitor creates a new process monitor
func NewProcessMonitor(prog *ebpf.Program, logger *zap.Logger) (*ProcessMonitor, error) {
	// Get perf buffer from program's map
	perfMap, _, err := prog.Maps["events"]
	if err != nil {
		return nil, fmt.Errorf("failed to get perf buffer: %w", err)
	}

	reader, err := perf.NewReader(perfMap, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to create perf reader: %w", err)
	}

	return &ProcessMonitor{
		prog:   prog,
		reader: reader,
		logger: logger,
	}, nil
}

// ReadEvent reads next process event from kernel
func (pm *ProcessMonitor) ReadEvent() (*enrichment.ProcessContext, error) {
	record, err := pm.reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read event: %w", err)
	}

	// Parse binary event from eBPF program
	// Format: struct {
	//   uint32_t pid
	//   uint32_t uid
	//   uint32_t gid
	//   uint64_t timestamp
	//   char comm[16]
	//   char filename[256]
	// }

	if len(record.RawSample) < 32 {
		return nil, fmt.Errorf("event too small: %d bytes", len(record.RawSample))
	}

	pid := binary.LittleEndian.Uint32(record.RawSample[0:4])
	uid := binary.LittleEndian.Uint32(record.RawSample[4:8])
	gid := binary.LittleEndian.Uint32(record.RawSample[8:12])
	timestamp := binary.LittleEndian.Uint64(record.RawSample[12:20])

	command := string(record.RawSample[20:36])
	filename := string(record.RawSample[36:292])

	return &enrichment.ProcessContext{
		PID:      uint32(pid),
		UID:      uid,
		GID:      gid,
		Command:  parseString(command),
		Filename: parseString(filename),
	}, nil
}

// Close closes the monitor and frees resources
func (pm *ProcessMonitor) Close() error {
	if pm.reader != nil {
		return pm.reader.Close()
	}
	return nil
}

// Helper to parse null-terminated strings from eBPF
func parseString(s string) string {
	if idx := indexOf(s, '\x00'); idx >= 0 {
		return s[:idx]
	}
	return s
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
```

**eBPF Program:** `pkg/ebpf/programs/process.c`

```c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// ANCHOR: Process execution eBPF program - Feature: Kernel-level process monitoring - Dec 27, 2025
// Monitors process execution at kernel level using tracepoint.
// Captures PID, UID, command, filename for security context extraction.

struct process_event {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct process_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;
    evt.timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_kernel_str(&evt.filename, sizeof(evt.filename),
                             (void *)PT_REGS_PARM1(ctx));

    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}
```

#### 2.2: Network Monitor Implementation

**File:** `pkg/ebpf/network_monitor.go`

Similar pattern to ProcessMonitor, but for network events:

```go
// ANCHOR: Network connection monitor - Feature: Cilium/eBPF network monitoring - Dec 27, 2025
// Replaces goBPF NetworkMonitor with cilium/ebpf-based implementation.
// Uses tracepoint for tcp_connect, tcp_accept, and UDP sends.

type NetworkMonitor struct {
	prog   *ebpf.Program
	reader *perf.Reader
	logger *zap.Logger
}

// ReadEvent reads next network event
func (nm *NetworkMonitor) ReadEvent() (*enrichment.NetworkContext, error) {
	// Parse binary network event from eBPF program
	// Fields: protocol, source_ip, source_port, dest_ip, dest_port, direction
}
```

**eBPF Program:** `pkg/ebpf/programs/network.c`

```c
// Similar pattern: TRACEPOINT_PROBE for tcp_connect, tcp_accept
// Captures: source IP/port, destination IP/port, protocol type
// Uses bpf_probe_read_kernel_str for socket data extraction
```

#### 2.3: File Monitor Implementation

**File:** `pkg/ebpf/file_monitor.go`

```go
// ANCHOR: File access monitor - Feature: Cilium/eBPF file monitoring - Dec 27, 2025
// Replaces goBPF FileMonitor with cilium/ebpf-based implementation.
// Uses tracepoint for VFS operations (open, read, write, unlink).

type FileMonitor struct {
	prog   *ebpf.Program
	reader *perf.Reader
	logger *zap.Logger
}

// ReadEvent reads next file event
func (fm *FileMonitor) ReadEvent() (*enrichment.FileContext, error) {
	// Parse binary file event from eBPF program
	// Fields: path, operation, uid, flags, mode
}
```

#### 2.4: Capability Monitor Implementation

**File:** `pkg/ebpf/capability_monitor.go`

```go
// ANCHOR: Capability usage monitor - Feature: Cilium/eBPF capability monitoring - Dec 27, 2025
// Replaces goBPF CapabilityMonitor with cilium/ebpf-based implementation.
// Uses tracepoint for cap_capable syscalls to detect dangerous capability usage.

type CapabilityMonitor struct {
	prog   *ebpf.Program
	reader *perf.Reader
	logger *zap.Logger
}

// ReadEvent reads next capability event
func (cm *CapabilityMonitor) ReadEvent() (*enrichment.CapabilityContext, error) {
	// Parse binary capability event from eBPF program
	// Fields: capability_name, uid, allowed, syscall
}
```

#### 2.5: DNS Monitor Implementation

**File:** `pkg/ebpf/dns_monitor.go`

```go
// ANCHOR: DNS query monitor - Feature: Cilium/eBPF DNS monitoring - Dec 27, 2025
// Replaces goBPF DNSMonitor with cilium/ebpf-based implementation.
// Uses UPD packet tracing or libc hook interception (via uprobes).

type DNSMonitor struct {
	prog   *ebpf.Program
	reader *perf.Reader
	logger *zap.Logger
}

// ReadEvent reads next DNS event
func (dm *DNSMonitor) ReadEvent() (*enrichment.DNSContext, error) {
	// Parse binary DNS event from eBPF program
	// Fields: query_name, query_type, response_code, query_allowed
}
```

---

### Phase 3: Integration & Testing

**Duration:** Day 4+
**Complexity:** High (integration testing)
**Risk:** Low-Medium (well-tested monitoring code)

#### 3.1: Update Agent to Use New Monitors

**File:** `pkg/agent/agent.go`

**Before:**
```go
import gobpfsecurity "github.com/udyansh/gobpf/security"

type Agent struct {
	ProcessMonitor    *gobpfsecurity.ProcessMonitor
	NetworkMonitor    *gobpfsecurity.NetworkMonitor
	FileMonitor       *gobpfsecurity.FileMonitor
	CapabilityMonitor *gobpfsecurity.CapabilityMonitor
}
```

**After:**
```go
import "github.com/udyansh/elf-owl/pkg/ebpf"

type Agent struct {
	ProcessMonitor    *ebpf.ProcessMonitor
	NetworkMonitor    *ebpf.NetworkMonitor
	FileMonitor       *ebpf.FileMonitor
	CapabilityMonitor *ebpf.CapabilityMonitor
	DNSMonitor        *ebpf.DNSMonitor
	EBPFCollection    *ebpf.Collection
}

// ANCHOR: Update eBPF monitor initialization - Feature: Cilium/eBPF integration - Dec 27, 2025
// Loads eBPF programs and creates monitor instances for process, network, file, capability, DNS.
// Each monitor reads events from kernel via perf buffer or ringbuffer.

func (a *Agent) initializeEBPFMonitors() error {
	coll, err := ebpf.LoadPrograms(a.Logger)
	if err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}
	a.EBPFCollection = coll

	if a.Config.Agent.EBPF.Process.Enabled {
		pm, err := ebpf.NewProcessMonitor(coll.Process.Program, a.Logger)
		if err != nil {
			return fmt.Errorf("failed to create process monitor: %w", err)
		}
		a.ProcessMonitor = pm
	}

	// Similar for Network, File, Capability, DNS...

	return nil
}
```

#### 3.2: Update Event Handler Goroutines

No changes needed to event handling goroutines - they consume events from monitors unchanged:

```go
func (a *Agent) handleProcessEvents() {
	for {
		select {
		case <-a.done:
			return
		default:
			// Works with both goBPF and cilium/ebpf monitors
			// Same interface, same event types
			event, err := a.ProcessMonitor.ReadEvent()
			if err != nil {
				a.Logger.Error("failed to read process event", zap.Error(err))
				continue
			}
			// Enrich event and evaluate rules...
		}
	}
}
```

#### 3.3: Create Unit Tests for Each Monitor

**File:** `pkg/ebpf/process_monitor_test.go`

```go
// ANCHOR: Process monitor unit tests - Feature: Cilium/eBPF testing - Dec 27, 2025
// Tests process monitor with mock eBPF programs and event data.

package ebpf

import (
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestProcessMonitorReadEvent(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	// Create mock program
	// Feed binary event data
	// Verify parsing

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name: "valid process event",
			data: []byte{
				0x01, 0x00, 0x00, 0x00, // PID = 1
				0x00, 0x00, 0x00, 0x00, // UID = 0
				// ... rest of event
			},
			wantErr: false,
		},
		{
			name:    "event too small",
			data:    []byte{0x01, 0x02},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test implementation
		})
	}
}
```

#### 3.4: Integration Test Suite

**File:** `test/integration_ebpf_test.go`

```go
// ANCHOR: eBPF integration tests - Feature: End-to-end event pipeline testing - Dec 27, 2025
// Tests complete pipeline: eBPF events → enrichment → rule matching → violations

func TestProcessEventEnrichmentPipeline(t *testing.T) {
	// Start eBPF monitors
	// Generate test process event
	// Enrich event with K8s metadata
	// Verify rule engine detects violations
	// Check event fields populated correctly
}

func TestNetworkEventDetection(t *testing.T) {
	// Similar for network events
}

func TestMultipleMonitorsInParallel(t *testing.T) {
	// Ensure process, network, file, capability events
	// can be processed concurrently without data corruption
}
```

#### 3.5: Performance Testing

**File:** `test/benchmark_ebpf_test.go`

```go
// ANCHOR: eBPF performance benchmarks - Feature: Ensure no performance regression - Dec 27, 2025
// Compares goBPF vs cilium/ebpf event throughput and latency

func BenchmarkProcessEventThroughput(b *testing.B) {
	// Benchmark: events/second
	// Target: No regression from goBPF
	// Expected: 10,000+ events/sec
}

func BenchmarkEventEnrichmentLatency(b *testing.B) {
	// Benchmark: milliseconds per event
	// Target: <10ms per event
}
```

---

## Code Changes Overview

### Files to Create

```
pkg/ebpf/
├── loader.go                           (150 LOC)
├── process_monitor.go                  (120 LOC)
├── network_monitor.go                  (120 LOC)
├── file_monitor.go                     (100 LOC)
├── capability_monitor.go               (100 LOC)
├── dns_monitor.go                      (100 LOC)
├── types.go                            (80 LOC)
└── programs/
    ├── process.c                       (50 LOC)
    ├── network.c                       (50 LOC)
    ├── file.c                          (50 LOC)
    ├── capability.c                    (50 LOC)
    ├── dns.c                           (50 LOC)
    └── Makefile                        (30 LOC)

test/
├── integration_ebpf_test.go            (200 LOC)
└── benchmark_ebpf_test.go              (100 LOC)

Total New Code: ~1,500 LOC
```

### Files to Modify

```
go.mod                                  (2 lines - remove gobpf)
pkg/agent/agent.go                      (30 lines - update imports)
pkg/agent/config.go                     (10 lines - update config)
README.md                               (5 lines - update arch diagram)
SPRINT.md                               (5 lines - update status)

Total Modified: ~50 lines
```

### Files to Delete

```
(None - goBPF is external package, no internal wrapper code)
```

---

## Testing Strategy

### Unit Test Coverage

**Phase 1: Monitor Unit Tests**
- Process Monitor: Parse PID, UID, command, filename
- Network Monitor: Parse IPs, ports, protocol
- File Monitor: Parse path, operation, permissions
- Capability Monitor: Parse capability names
- DNS Monitor: Parse domain, query type

**Target:** >85% coverage for ebpf package

### Integration Tests

**Phase 2: End-to-End Pipeline**
1. Load eBPF programs
2. Generate kernel events (via synthetic triggers)
3. Read events from monitors
4. Enrich events with K8s metadata
5. Match against rules
6. Verify CIS violations detected

### Regression Tests

**Phase 3: Feature Parity**
1. Compare event field coverage with goBPF
2. Verify all 48 CIS controls still match
3. Test edge cases (null fields, malformed data)
4. Performance baseline comparison

### Test Execution

```bash
# Unit tests
go test -v ./pkg/ebpf/... -coverage

# Integration tests
go test -v ./test/integration_ebpf_test.go -timeout 60s

# Benchmarks
go test -bench=. -benchmem ./test/benchmark_ebpf_test.go

# Full test suite
go test -race ./...
```

---

## Rollback Plan

### If Migration Fails

**Trigger Criteria:**
- Critical bugs in eBPF programs that can't be fixed quickly
- Data corruption in event parsing
- Performance regression >20%
- Incompatibility with supported kernel versions

**Rollback Steps:**

1. **Immediate (Minutes):**
   ```bash
   git revert <migration-commits>
   go mod edit -require github.com/udyansh/gobpf@v0.1.0
   replace github.com/udyansh/gobpf => ../gobpf
   go mod tidy
   make clean build
   ```

2. **Verification (5 minutes):**
   - Agent starts successfully
   - Events flowing from goBPF monitors
   - Rules matching as before
   - Metrics reporting correctly

3. **Notification:**
   - Document rollback reasons in post-mortem
   - Identify and fix issues
   - Plan retry for next cycle

### Time to Rollback: <15 minutes

---

## Success Criteria

### Phase 1: Library Setup (Days 1-2)
- ✅ go.mod updated to use cilium/ebpf v0.11.0
- ✅ goBPF dependency removed
- ✅ eBPF program directory structure created
- ✅ Build pipeline working (make produces .o files)
- ✅ Agent compilation succeeds with new imports

**Verification:**
```bash
go mod graph | grep cilium/ebpf  # Should show v0.11.0
go mod graph | grep gobpf         # Should be empty
make -C pkg/ebpf/programs all     # Should produce .o files
go build -o elf-owl cmd/elf-owl/main.go  # Should succeed
```

### Phase 2: Monitor Implementation (Days 2-3)
- ✅ ProcessMonitor implemented and tested
- ✅ NetworkMonitor implemented and tested
- ✅ FileMonitor implemented and tested
- ✅ CapabilityMonitor implemented and tested
- ✅ DNSMonitor implemented and tested
- ✅ >85% code coverage for ebpf package
- ✅ All monitor unit tests passing

**Verification:**
```bash
go test -v ./pkg/ebpf/... -cover
# Output should show >85% coverage for each monitor
```

### Phase 3: Integration (Day 4+)
- ✅ Agent initializes all monitors without errors
- ✅ Integration tests passing
- ✅ Event enrichment works end-to-end
- ✅ All 48 CIS controls still detecting violations
- ✅ No performance regression (benchmark comparison)
- ✅ Documentation updated

**Verification:**
```bash
go test -race ./...                    # All tests pass
go test -bench=. -benchmem ./test/...  # Performance acceptable
./elf-owl --health-check               # Agent health OK
```

### Final Verification
- ✅ Deploy to test Kubernetes cluster
- ✅ Pod starts successfully
- ✅ Events flowing to Owl SaaS
- ✅ Violations reported correctly
- ✅ No increase in error logs

---

## Risk Assessment

### Risk Matrix

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-----------|
| **eBPF program compilation issues** | Low | High | Comprehensive Makefile, test compilation early |
| **Kernel version incompatibility** | Low | High | Test on multiple kernel versions, graceful fallback |
| **Event parsing bugs** | Medium | Medium | Extensive unit tests, fuzzing, edge cases |
| **Performance regression** | Low | High | Benchmark comparison, tuning if needed |
| **Integration issues with K8s** | Low | Low | Integration tests, test cluster deployment |
| **goBPF event schema differences** | Low | Medium | Detailed comparison tests, event compatibility matrix |

### Risk Mitigation Strategies

1. **Code Review:** All eBPF C code reviewed by multiple team members
2. **Testing:** Comprehensive unit + integration + performance tests
3. **Gradual Rollout:** Test on single node before cluster-wide deployment
4. **Monitoring:** Enhanced logging during migration period
5. **Documentation:** Clear troubleshooting guide for common issues
6. **Rollback Plan:** Quick rollback procedure <15 minutes

### Overall Risk Level: **LOW**

Rationale:
- Cilium/eBPF is production-proven in thousands of deployments
- Event schemas remain unchanged (backward compatible)
- Monitors are isolated components (easy to rollback)
- Comprehensive testing plan minimizes surprises

---

## Timeline & Effort Estimates

### Week 3-4 Implementation Schedule

```
Monday (Day 1):     Library setup, dependency updates, build pipeline
Tuesday (Day 2):    ProcessMonitor & NetworkMonitor implementation
Wednesday (Day 3):  FileMonitor, CapabilityMonitor, DNSMonitor implementation
Thursday (Day 4):   Integration, agent updates, unit tests
Friday (Day 5):     Integration tests, performance benchmarks, documentation
```

### Effort Breakdown

| Phase | Days | Effort | Lead |
|-------|------|--------|------|
| Library Setup | 1 | 6 hours | DevOps/Backend |
| eBPF Programs (5) | 2 | 16 hours | Backend/Security |
| Monitor Impl (5) | 1.5 | 12 hours | Backend |
| Integration | 1.5 | 12 hours | QA/Backend |
| Testing & Docs | 1 | 8 hours | QA/DevOps |
| **Total** | **7** | **54 hours** | **~1 week** |

---

## Post-Migration Cleanup

### After Successful Migration

1. **Repository Cleanup:**
   - Remove goBPF from go.mod
   - Delete any internal goBPF wrapper code (if any)
   - Update import paths in all files

2. **Documentation Updates:**
   - Update README.md architecture diagrams
   - Update SPRINT.md with completion status
   - Create MIGRATE_EBPF_COMPLETE.md with lessons learned
   - Update troubleshooting guide

3. **Performance Baseline:**
   - Document event throughput (events/sec)
   - Document event latency (milliseconds)
   - Compare with goBPF baseline
   - Publish performance improvements

4. **Version Bump:**
   - Update version to 0.2.0 (minor version for eBPF integration)
   - Tag migration as major milestone

---

## References

### Cilium/eBPF Documentation
- [GitHub: cilium/ebpf](https://github.com/cilium/ebpf)
- [Cilium eBPF Library Guide](https://docs.cilium.io/)
- [eBPF Program Examples](https://github.com/cilium/ebpf/tree/main/examples)

### eBPF Learning Resources
- [eBPF.io Tutorials](https://ebpf.io)
- [Linux eBPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [Kernel Tracepoint Reference](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)

### Tools & Utilities
- [bpftrace](https://github.com/iovisor/bpftrace) - for debugging eBPF programs
- [llvm](https://llvm.org/) - for eBPF compilation
- [perf](https://perf.wiki.kernel.org/) - for performance profiling

---

## Questions & Support

### FAQ

**Q: Will event schemas change?**
A: No. Event schemas remain identical to maintain backward compatibility with enrichment pipeline.

**Q: Do we need to recompile eBPF programs on every change?**
A: Only when eBPF C code changes. Go code changes don't require recompilation.

**Q: Can we run both goBPF and cilium/ebpf simultaneously?**
A: Not recommended, but technically possible with separate monitors. Not planned.

**Q: What kernel versions are supported?**
A: Cilium/eBPF requires Linux 5.4+ (same as goBPF). We'll test on 5.4, 5.10, 5.15, 6.0.

**Q: How do we debug eBPF programs?**
A: Use bpftrace for tracing, enable kernel logging, use perf for profiling.

### Escalation Path

1. **Technical Issues:** Refer to [cilium/ebpf GitHub Issues](https://github.com/cilium/ebpf/issues)
2. **eBPF Program Issues:** Use bpftrace and perf for debugging
3. **Performance Issues:** Run benchmarks and compare with baseline
4. **Rollback Needed:** Execute rollback procedure (15 minutes)

---

**Document Status:** DRAFT → REVIEW → APPROVED → READY FOR IMPLEMENTATION
**Last Updated:** December 27, 2025
**Owner:** elf-owl Project Team
**Approvals:** [User Review Pending]
