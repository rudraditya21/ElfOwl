# Phase 2: Monitor Implementation - Detailed Plan

**Status:** DRAFT (Ready for User Approval)
**Duration:** Days 2-3 (32 hours estimated)
**Complexity:** Medium-High
**Risk Level:** Low (feature-by-feature migration with rollback capability)

---

## Executive Summary

Phase 2 implements the actual kernel-side monitoring by:

1. **Compiling eBPF C programs** to bytecode (.o files)
2. **Embedding bytecode** in the binary using `//go:embed`
3. **Loading programs** into kernel via cilium/ebpf Collection API
4. **Attaching to tracepoints** using perf_event_open syscall
5. **Reading events** from perf buffers or ring buffers
6. **Testing thoroughly** with >85% code coverage

This completes the transition from custom goBPF wrapper to production-grade Cilium/eBPF.

---

## Implementation Overview

### Files to Create/Modify

**New Files (6):**
- `pkg/ebpf/bytecode_embed.go` - Embed compiled .o files
- `pkg/ebpf/process_monitor.go` - ProcessMonitor implementation (120 LOC)
- `pkg/ebpf/network_monitor.go` - NetworkMonitor implementation (120 LOC)
- `pkg/ebpf/file_monitor.go` - FileMonitor implementation (100 LOC)
- `pkg/ebpf/capability_monitor.go` - CapabilityMonitor implementation (100 LOC)
- `pkg/ebpf/dns_monitor.go` - DNSMonitor implementation (100 LOC)

**Modified Files (3):**
- `pkg/ebpf/loader.go` - Implement LoadPrograms(), attach tracepoints, readers
- `pkg/ebpf/types.go` - Add monitor-specific helper methods
- `pkg/agent/agent.go` - Initialize eBPF monitors (in Phase 3)

**Test Files (5):**
- `pkg/ebpf/loader_test.go` - Loader unit tests
- `pkg/ebpf/process_monitor_test.go` - ProcessMonitor tests
- `pkg/ebpf/network_monitor_test.go` - NetworkMonitor tests
- `pkg/ebpf/file_monitor_test.go` - FileMonitor tests
- `pkg/ebpf/dns_monitor_test.go` - DNSMonitor tests

**Total Code:** ~1,050 new LOC + ~300 modified LOC

---

## Task Breakdown

### Task 2.1: Build eBPF Programs to Bytecode

**File:** `pkg/ebpf/programs/Makefile` (already created in Phase 1)

**Action:** Compile all 5 eBPF C programs to bytecode

```bash
cd pkg/ebpf/programs
make all
```

**Expected Output:**
```
bin/process.o     (5-15 KB)
bin/network.o     (5-15 KB)
bin/file.o        (5-15 KB)
bin/capability.o  (5-15 KB)
bin/dns.o         (5-15 KB)
```

**Verification Steps:**
1. All .o files exist in `bin/`
2. `file bin/*.o` shows "ELF 64-bit LSB relocatable, eBPF"
3. `llvm-objdump -d bin/process.o` shows valid eBPF bytecode

---

### Task 2.2: Create Bytecode Embedding File

**File:** `pkg/ebpf/bytecode_embed.go` (~20 LOC)

**Purpose:** Embed compiled .o files in binary using `//go:embed`

**Implementation:**

```go
// ANCHOR: eBPF Bytecode Embedding - Phase 2: Monitor Implementation - Dec 27, 2025
// Uses //go:embed to include compiled eBPF programs in the binary
// Eliminates need for external file dependencies at runtime

package ebpf

import (
	"embed"
)

//go:embed programs/bin/*.o
var programFiles embed.FS

// GetProgram returns compiled eBPF bytecode for the named program
func GetProgram(name string) ([]byte, error) {
	return embed.ReadFile(programFiles, "programs/bin/"+name+".o")
}
```

**Verification:**
- `GetProgram("process")` returns bytecode
- `GetProgram("network")` returns bytecode
- etc.

---

### Task 2.3: Implement eBPF Program Loading

**File:** `pkg/ebpf/loader.go` (modify LoadPrograms function - ~150 LOC added)

**Current State:** Stub implementation

**New Implementation:**

1. **Load bytecode from embed.FS:**
   - Get each .o file via GetProgram()
   - Parse as ELF using cilium/ebpf

2. **Parse ELF and extract programs/maps:**
   - Use cilium/ebpf.CollectionSpec to parse
   - Extract program names (from SEC macros)
   - Extract map names (from BPF_PERF_OUTPUT)

3. **Load programs into kernel:**
   - Call spec.LoadAndAssign() to load into kernel
   - Handle permission errors (require CAP_BPF + CAP_PERFMON)

4. **Create ProgramSet for each monitor:**
   - Wrap program + maps + reader
   - Initialize event reader (perf or ring buffer)

5. **Attach programs to tracepoints:**
   - Use perf_event_open() for tracepoint attachment
   - Handle each program's target tracepoint
   - Store file descriptors for cleanup

**Key Functions to Implement:**

```go
// LoadPrograms - Main entry point (already defined)
func LoadPrograms(logger *zap.Logger) (*Collection, error)

// newProgramSet - Create ProgramSet from loaded program
func newProgramSet(name string, prog *ebpf.Program,
                   maps map[string]*ebpf.Map, logger *zap.Logger) (*ProgramSet, error)

// attachTracepoint - Attach program to kernel tracepoint
func attachTracepoint(prog *ebpf.Program, group, name string) error

// newPerfBufferReader - Create reader from perf buffer map
func newPerfBufferReader(m *ebpf.Map, logger *zap.Logger) (*PerfBufferReader, error)

// newRingBufferReader - Create reader from ring buffer map
func newRingBufferReader(m *ebpf.Map, logger *zap.Logger) (*RingBufferReader, error)
```

**Implementation Detail - Tracepoint Attachment:**

```go
// ANCHOR: Tracepoint Attachment - Dec 27, 2025
// Attaches eBPF program to kernel tracepoint using perf_event_open

// Find tracepoint ID
id, err := getTracepointID(group, name) // reads from /sys/kernel/debug/tracing/events/
if err != nil {
    return err
}

// Open perf event
attr := perf.Attr{
    Type:   perf.TypeTracepoint,
    Config: uint64(id),
}
fd, err := perf.EventOpen(&attr, -1, 0, -1, 0)
if err != nil {
    return err
}

// Attach eBPF program
err = prog.AttachRawLink(&rawLinkOptions{
    Target: fd,
    Program: prog,
    Event: "tracepoint",
})
```

**Error Handling:**
- Missing /sys/kernel/debug/tracing/ → helpful error message
- Permission denied → require CAP_BPF + CAP_PERFMON
- Program load failed → detailed error with kernel dmesg hints

---

### Task 2.4: Implement Event Readers

**File:** `pkg/ebpf/reader.go` (new file - ~200 LOC)

**Purpose:** Stream events from kernel perf buffers or ring buffers

#### PerfBufferReader (Preferred for older kernels)

```go
// ANCHOR: Perf Buffer Event Reader - Dec 27, 2025
// Reads events from perf buffer maps using epoll
// Each CPU core has its own perf buffer, reader aggregates

type PerfBufferReader struct {
	rd      *perf.Reader      // cilium/ebpf perf reader
	logger  *zap.Logger
	closed  bool
}

func (pr *PerfBufferReader) Read() ([]byte, error) {
	// Read next event from any CPU's buffer
	record, err := pr.rd.Read(context.Background())
	if err != nil {
		return nil, fmt.Errorf("perf read error: %w", err)
	}
	return record.RawSample, nil
}

func (pr *PerfBufferReader) Close() error {
	return pr.rd.Close()
}
```

#### RingBufferReader (Preferred for newer kernels)

```go
// ANCHOR: Ring Buffer Event Reader - Dec 27, 2025
// Reads events from ring buffer maps (kernel 5.8+)
// Simpler than perf buffers, better performance

type RingBufferReader struct {
	rd      *ringbuf.Reader   // cilium/ebpf ringbuf reader
	logger  *zap.Logger
	closed  bool
}

func (rr *RingBufferReader) Read() ([]byte, error) {
	// Read next event from ring buffer
	record, err := rr.rd.Read(context.Background())
	if err != nil {
		return nil, fmt.Errorf("ringbuf read error: %w", err)
	}
	return record.RawSample, nil
}

func (rr *RingBufferReader) Close() error {
	return rr.rd.Close()
}
```

**Configuration:**
- Config.EBPF.PerfBuffer.Enabled controls which to use
- Autodetect kernel version if not specified
- Fall back to perf if ring buffer unavailable

---

### Task 2.5: Implement Monitor Stubs → Full Implementations

Convert each stub monitor to actual implementation:

#### ProcessMonitor (pkg/ebpf/process_monitor.go - 120 LOC)

**Responsibility:** Forward events from process.o to enrichment pipeline

```go
// ANCHOR: Process Execution Monitor - Dec 27, 2025
// Streams process execution events from kernel via eBPF

type ProcessMonitor struct {
	programSet *ProgramSet
	eventChan  chan *enrichment.ProcessExecution
	logger     *zap.Logger
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

func (pm *ProcessMonitor) Start(ctx context.Context) error {
	pm.wg.Add(1)
	go pm.eventLoop(ctx)
	pm.logger.Info("process monitor started")
	return nil
}

func (pm *ProcessMonitor) eventLoop(ctx context.Context) {
	defer pm.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-pm.stopChan:
			return
		default:
			// Read event from kernel via perf/ringbuf reader
			data, err := pm.programSet.Reader.Read()
			if err != nil {
				pm.logger.Error("event read failed", zap.Error(err))
				continue
			}

			// Parse event
			evt := &ProcessEvent{}
			if err := binary.Read(bytes.NewBuffer(data),
				                   binary.LittleEndian, evt); err != nil {
				pm.logger.Error("parse failed", zap.Error(err))
				continue
			}

			// Convert to enrichment type
			enriched := &enrichment.ProcessExecution{
				PID:          evt.PID,
				UID:          evt.UID,
				GID:          evt.GID,
				Capabilities: evt.Capabilities,
				Filename:     strings.TrimNull(string(evt.Filename[:])),
				Argv:         strings.TrimNull(string(evt.Argv[:])),
				CgroupID:     evt.CgroupID,
				Timestamp:    time.Now(),
			}

			// Send to enrichment pipeline
			select {
			case pm.eventChan <- enriched:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (pm *ProcessMonitor) Stop() error {
	close(pm.stopChan)
	pm.wg.Wait()
	return pm.programSet.Close()
}
```

#### NetworkMonitor, FileMonitor, CapabilityMonitor, DNSMonitor

Same pattern as ProcessMonitor but with:
- Different event structures (NetworkEvent, FileEvent, etc.)
- Different enrichment types (NetworkConnection, FileAccess, etc.)
- Appropriate tracepoint event parsing

---

### Task 2.6: Write Comprehensive Tests

**Target Coverage:** >85%

#### Unit Tests (loader_test.go - ~200 LOC)

```go
// ANCHOR: eBPF Loader Tests - Dec 27, 2025
// Unit tests for bytecode loading and tracepoint attachment

func TestLoadPrograms(t *testing.T) {
	// Test loading all 5 programs successfully
	coll, err := LoadPrograms(zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, coll.Process)
	require.NotNil(t, coll.Network)
	// ... etc
}

func TestProgramAttachment(t *testing.T) {
	// Test attaching to tracepoints
	// Mock perf_event_open if running in unprivileged environment
}

func TestReaderCreation(t *testing.T) {
	// Test PerfBufferReader and RingBufferReader creation
}

func TestEventParsing(t *testing.T) {
	// Test parsing raw event bytes to structures
	rawData := []byte{...}
	evt := &ProcessEvent{}
	err := binary.Read(bytes.NewBuffer(rawData),
	                    binary.LittleEndian, evt)
	require.NoError(t, err)
}
```

#### Monitor Tests (process_monitor_test.go - ~150 LOC each)

```go
// ANCHOR: Process Monitor Tests - Dec 27, 2025
// Tests for ProcessMonitor event streaming

func TestProcessMonitorStart(t *testing.T) {
	// Test monitor starts without errors
}

func TestProcessMonitorEvent(t *testing.T) {
	// Mock reader to inject test events
	mockReader := &mockReader{
		data: encodeProcessEvent(&ProcessEvent{PID: 1234, ...}),
	}

	// Start monitor
	pm := &ProcessMonitor{
		programSet: &ProgramSet{Reader: mockReader},
		eventChan: make(chan *enrichment.ProcessExecution),
	}

	// Verify event received and converted correctly
}

func TestProcessMonitorStop(t *testing.T) {
	// Test monitor stops gracefully
}
```

---

## Implementation Sequence

### Day 2, Morning (4 hours)

**2.1** - Compile eBPF programs
- Run `make` in `pkg/ebpf/programs/`
- Verify bytecode files created
- Commit: `chore: compile eBPF programs to bytecode`

**2.2** - Create bytecode embedding
- Create `pkg/ebpf/bytecode_embed.go`
- Verify `//go:embed` works
- Commit: `feat: embed compiled eBPF programs in binary`

**2.3a** - Implement loader (Part 1: Bytecode parsing)
- Implement `loadBytecode()` function
- Implement `CollectionSpec` parsing
- Add error handling for missing files
- Commit: `feat: implement eBPF bytecode loading`

### Day 2, Afternoon (4 hours)

**2.3b** - Implement loader (Part 2: Tracepoint attachment)
- Implement `attachTracepoint()` function
- Handle perf_event_open syscall
- Add tracepoint group/name resolution
- Commit: `feat: implement kernel tracepoint attachment`

**2.4** - Implement event readers
- Create `pkg/ebpf/reader.go`
- Implement PerfBufferReader
- Implement RingBufferReader
- Commit: `feat: implement event streaming readers`

### Day 2, Evening (4 hours)

**2.5** - Implement monitor stubs
- ProcessMonitor implementation
- NetworkMonitor implementation
- FileMonitor implementation
- Commit: `feat: implement Process/Network/File monitors`

**2.5** (continued)
- CapabilityMonitor implementation
- DNSMonitor implementation
- Commit: `feat: implement Capability/DNS monitors`

### Day 3, Morning (4 hours)

**2.6** - Write unit tests
- loader_test.go (200 LOC)
- process_monitor_test.go (150 LOC)
- Achieve >85% code coverage
- Commit: `test: add comprehensive eBPF loader and monitor tests`

### Day 3, Afternoon (4 hours)

**2.6** (continued) - Write remaining tests
- network_monitor_test.go (150 LOC)
- file_monitor_test.go (150 LOC)
- capability_monitor_test.go (150 LOC)
- dns_monitor_test.go (150 LOC)
- Commit: `test: add remaining monitor unit tests`

**Verification**
- Run `go test -v ./pkg/ebpf/...`
- Verify coverage >85% with `go test -cover ./pkg/ebpf/...`
- Build binary: `go build -o elf-owl cmd/elf-owl/main.go`
- Commit: `test: verify all Phase 2 implementations pass`

---

## Key Implementation Notes

### 1. Bytecode Embedding vs Runtime Compilation

**Phase 2 Uses:** Embedded bytecode (fast, portable, no clang dependency at runtime)

```go
//go:embed programs/bin/*.o
var programFiles embed.FS
```

**Advantages:**
- Single binary, no external dependencies
- Faster startup (no compilation)
- Reproducible builds

**Alternative:** Runtime compilation via cilium/ebpf (not used)

### 2. Event Parsing

Events are serialized from kernel as packed C structs:

```c
struct process_event {
    unsigned int pid;      // 4 bytes
    unsigned int uid;      // 4 bytes
    unsigned int gid;      // 4 bytes
    unsigned long caps;    // 8 bytes
    char filename[256];    // 256 bytes
    char argv[256];        // 256 bytes
    unsigned long cgroup;  // 8 bytes
};
// Total: 540 bytes per event
```

Parsing in Go:

```go
var evt ProcessEvent
binary.Read(bytes.NewBuffer(rawData), binary.LittleEndian, &evt)
```

### 3. Error Handling Strategy

| Error | Action | Recovery |
|-------|--------|----------|
| Bytecode not found | Fail fast | Check build, rebuild |
| Load fails | Log detailed error | Check kernel version, CAP_BPF |
| Tracepoint attach fails | Skip monitor | Continue with others |
| Event read fails | Log and continue | Depends on error type |
| Monitor stop fails | Force close | Prevent resource leaks |

### 4. Testing Strategy

**Mock Objects:**

```go
type mockReader struct {
	data   []byte
	closed bool
}

func (mr *mockReader) Read() ([]byte, error) {
	if mr.closed {
		return nil, io.EOF
	}
	return mr.data, nil
}
```

**Benefits:**
- No need for root/CAP_BPF in tests
- Deterministic event injection
- Easy to test error paths

### 5. Linux Kernel Requirements

| Component | Min Kernel | Notes |
|-----------|-----------|-------|
| eBPF | 4.1+ | Core eBPF support |
| Perf buffers | 4.1+ | Perf event infrastructure |
| Ring buffers | 5.8+ | Modern, preferred |
| BPF_LINK_CREATE | 5.2+ | Program linking |
| CAP_BPF | 5.8+ | eBPF capabilities |

---

## Success Criteria

### Code Quality
- ✓ All Phase 2 files created/modified
- ✓ >85% code coverage in pkg/ebpf/
- ✓ All tests pass (`go test ./pkg/ebpf/...`)
- ✓ No compiler errors or warnings
- ✓ Anchor comments on all new code sections
- ✓ Conventional commit messages

### Functionality
- ✓ LoadPrograms() successfully loads all 5 programs
- ✓ Tracepoints attach without errors
- ✓ Event readers stream events from kernel
- ✓ ProcessMonitor receives and converts events
- ✓ NetworkMonitor receives and converts events
- ✓ FileMonitor receives and converts events
- ✓ CapabilityMonitor receives and converts events
- ✓ DNSMonitor receives and converts events

### Build & Deployment
- ✓ Binary builds: `go build -o elf-owl cmd/elf-owl/main.go`
- ✓ Binary size <50MB (with embedded bytecode)
- ✓ Bytecode embedded (no external dependencies)
- ✓ No security vulnerabilities introduced

### Documentation
- ✓ Loader.go has comprehensive comments
- ✓ Each monitor has anchor comments
- ✓ Reader implementations documented
- ✓ Test coverage clear

---

## Rollback Plan

If Phase 2 encounters critical issues:

1. **Immediate:** Disable eBPF in config (set EBPF.Enabled=false)
2. **Fallback:** Continue using goBPF monitors
3. **Fix:** Identify and fix issue (max 24 hours)
4. **Retry:** Re-implement corrected component

**Time to rollback:** <5 minutes (config change only)

---

## Approval Checkpoint

**This plan is ready for user review.**

Please confirm:

- [ ] Implementation sequence makes sense
- [ ] File breakdown is clear
- [ ] Testing approach is sufficient
- [ ] Timeline is acceptable
- [ ] Success criteria are achievable

**Once approved, Phase 2 implementation will begin immediately.**

---

## Next Phase (Phase 3)

After Phase 2 completion, Phase 3 will:

1. **Integration** - Connect eBPF monitors to agent.go
2. **Testing** - Full integration and E2E tests
3. **Cutover** - Gradually migrate from goBPF to eBPF
4. **Cleanup** - Remove goBPF dependency when all monitors are migrated

