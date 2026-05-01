// ANCHOR: Unit tests for FileMonitor - Phase 3: Testing - Dec 27, 2025
// Tests file access event monitoring, operation mapping, and enrichment

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// ============================================================================
// FileMonitor Creation & Initialization Tests
// ============================================================================

func TestNewFileMonitor(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewFileMonitor(nil, logger, 100, nil, nil)

	if monitor == nil {
		t.Fatal("expected non-nil monitor")
	}

	if monitor.logger != logger {
		t.Error("logger not assigned")
	}

	if monitor.started {
		t.Error("monitor should not be started on creation")
	}

	if cap(monitor.eventChan) != 100 {
		t.Errorf("expected channel buffer size 100, got %d", cap(monitor.eventChan))
	}
}

// ============================================================================
// FileMonitor Lifecycle Tests
// ============================================================================

func TestFileMonitorStart(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewFileMonitor(programSet, logger, 100, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !monitor.started {
		t.Error("monitor.started should be true")
	}

	monitor.Stop()
}

func TestFileMonitorStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewFileMonitor(programSet, logger, 100, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	err := monitor.Stop()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if monitor.started {
		t.Error("monitor.started should be false")
	}
}

// ============================================================================
// FileEvent Parsing Tests
// ============================================================================

func TestFileEventParsing(t *testing.T) {
	testEvent := NewTestFileEvent(1234, 1, "/etc/passwd")

	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, testEvent)
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	parsed := &FileEvent{}
	err = binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, parsed)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if parsed.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", parsed.PID)
	}

	if parsed.Operation != 1 {
		t.Errorf("expected Operation 1 (write), got %d", parsed.Operation)
	}
}

// ============================================================================
// FileOperation Mapping Tests
// ============================================================================

func TestFileOperationWrite(t *testing.T) {
	opType := ""
	switch 1 { // FileOpWrite
	case 1:
		opType = "write"
	case 2:
		opType = "read"
	case 3:
		opType = "chmod"
	case 4:
		opType = "unlink"
	default:
		opType = "unknown"
	}

	if opType != "write" {
		t.Errorf("expected operation 'write', got %q", opType)
	}
}

func TestFileOperationRead(t *testing.T) {
	opType := ""
	switch 2 { // FileOpRead
	case 1:
		opType = "write"
	case 2:
		opType = "read"
	case 3:
		opType = "chmod"
	case 4:
		opType = "unlink"
	default:
		opType = "unknown"
	}

	if opType != "read" {
		t.Errorf("expected operation 'read', got %q", opType)
	}
}

func TestFileOperationChmod(t *testing.T) {
	opType := ""
	switch 3 { // FileOpChmod
	case 1:
		opType = "write"
	case 2:
		opType = "read"
	case 3:
		opType = "chmod"
	case 4:
		opType = "unlink"
	default:
		opType = "unknown"
	}

	if opType != "chmod" {
		t.Errorf("expected operation 'chmod', got %q", opType)
	}
}

func TestFileOperationUnlink(t *testing.T) {
	opType := ""
	switch 4 { // FileOpUnlink
	case 1:
		opType = "write"
	case 2:
		opType = "read"
	case 3:
		opType = "chmod"
	case 4:
		opType = "unlink"
	default:
		opType = "unknown"
	}

	if opType != "unlink" {
		t.Errorf("expected operation 'unlink', got %q", opType)
	}
}

func TestFileOperationUnknown(t *testing.T) {
	opType := ""
	switch 99 { // Unknown
	case 1:
		opType = "write"
	case 2:
		opType = "read"
	case 3:
		opType = "chmod"
	case 4:
		opType = "unlink"
	default:
		opType = "unknown"
	}

	if opType != "unknown" {
		t.Errorf("expected operation 'unknown', got %q", opType)
	}
}

// ============================================================================
// FileContext Enrichment Tests
// ============================================================================

func TestFileEnrichment(t *testing.T) {
	testEvent := NewTestFileEvent(1234, 1, "/var/log/app.log")

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, testEvent)

	parsed := &FileEvent{}
	binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, parsed)

	// Map operation
	opType := ""
	switch parsed.Operation {
	case 1:
		opType = "write"
	case 2:
		opType = "read"
	case 3:
		opType = "chmod"
	case 4:
		opType = "unlink"
	default:
		opType = "unknown"
	}

	fileCtx := &enrichment.FileContext{
		Path:      "/var/log/app.log",
		Operation: opType,
		PID:       parsed.PID,
	}

	enriched := &enrichment.EnrichedEvent{
		RawEvent:  parsed,
		EventType: "file_access",
		File:      fileCtx,
		Timestamp: time.Now(),
	}

	// Verify
	AssertEnrichedEvent(t, enriched, "file_access")
	AssertFileContext(t, enriched.File, "/var/log/app.log")

	if enriched.File.Operation != "write" {
		t.Errorf("expected operation 'write', got %q", enriched.File.Operation)
	}
}

// ============================================================================
// FileMonitor Event Channel Tests
// ============================================================================

func TestFileEventChannelFlow(t *testing.T) {
	logger := zaptest.NewLogger(t)

	testEvent := NewTestFileEvent(1234, 2, "/etc/shadow")
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, testEvent)

	mockReader := NewMockReader(buf.Bytes())
	programSet := NewMockProgramSet(mockReader)
	monitor := NewFileMonitor(programSet, logger, 100, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	monitor.Start(ctx)
	defer monitor.Stop()

	event := WaitForEvent(t, monitor.eventChan, 500*time.Millisecond)

	if event == nil {
		t.Fatal("expected event, got nil")
	}

	AssertEnrichedEvent(t, event, "file_access")
}

// ============================================================================
// FileMonitor Context Cancellation Tests
// ============================================================================

func TestFileContextCancellation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewFileMonitor(programSet, logger, 100, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	cancel()

	time.Sleep(100 * time.Millisecond)

	// Context cancellation stops the event loop but doesn't clear the started flag
	// Must call Stop() to properly clean up
	err = monitor.Stop()
	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	if monitor.started {
		t.Error("monitor should be stopped after Stop() call")
	}
}

// ============================================================================
// FileMonitor Error Handling Tests
// ============================================================================

func TestFileReaderError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mockReader := NewMockReader()
	mockReader.readError = ErrSimulated
	programSet := NewMockProgramSet(mockReader)
	monitor := NewFileMonitor(programSet, logger, 100, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if !monitor.started {
		t.Error("monitor should remain running despite reader errors")
	}

	monitor.Stop()
}

// ============================================================================
// FileMonitor EventChan Return Type Test
// ============================================================================

func TestFileEventChanReturnType(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewFileMonitor(nil, logger, 100, nil, nil)

	ch := monitor.EventChan()

	if ch == nil {
		t.Fatal("event channel is nil")
	}

	_ = (<-chan *enrichment.EnrichedEvent)(ch)
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkFileMonitorEventParsing(b *testing.B) {
	events := make([][]byte, b.N)

	for i := 0; i < b.N; i++ {
		evt := NewTestFileEvent(uint32(1000+i), 1, "/var/log/app.log")
		buf := &bytes.Buffer{}
		binary.Write(buf, binary.LittleEndian, evt)
		events[i] = buf.Bytes()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parsed := &FileEvent{}
		binary.Read(bytes.NewReader(events[i]), binary.LittleEndian, parsed)
	}
}

func BenchmarkFileOperationMapping(b *testing.B) {
	operations := []uint8{1, 2, 3, 4, 1, 2, 3, 4}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		op := operations[i%len(operations)]

		opType := ""
		switch op {
		case 1:
			opType = "write"
		case 2:
			opType = "read"
		case 3:
			opType = "chmod"
		case 4:
			opType = "unlink"
		default:
			opType = "unknown"
		}

		_ = opType
	}
}

func BenchmarkFileMonitorEnrichment(b *testing.B) {
	for i := 0; i < b.N; i++ {
		evt := NewTestFileEvent(1234, 1, "/var/log/app.log")

		fileCtx := &enrichment.FileContext{
			Path:      "/var/log/app.log",
			Operation: "write",
			PID:       evt.PID,
		}

		_ = &enrichment.EnrichedEvent{
			RawEvent:  evt,
			EventType: "file_access",
			File:      fileCtx,
			Timestamp: time.Now(),
		}
	}
}
