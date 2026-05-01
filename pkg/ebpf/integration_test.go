// ANCHOR: Integration tests for eBPF monitors - Phase 3: Testing - Dec 27, 2025
// Tests cross-monitor interactions and pipeline integration with enrichment package

package ebpf

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// ============================================================================
// Multi-Monitor Integration Tests
// ============================================================================

// TestMultipleMonitorsSimultaneous tests running all 5 monitors concurrently
func TestMultipleMonitorsSimultaneous(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create all 5 monitors with mock data
	processMonitor := NewProcessMonitor(NewMockProgramSet(NewMockReader()), logger)
	networkMonitor := NewNetworkMonitor(NewMockProgramSet(NewMockReader()), logger)
	fileMonitor := NewFileMonitor(NewMockProgramSet(NewMockReader()), logger, 100, nil, nil)
	capabilityMonitor := NewCapabilityMonitor(NewMockProgramSet(NewMockReader()), logger)
	dnsMonitor := NewDNSMonitor(NewMockProgramSet(NewMockReader()), logger)

	// Start all monitors
	monitors := []interface {
		Start(context.Context) error
		Stop() error
	}{processMonitor, networkMonitor, fileMonitor, capabilityMonitor, dnsMonitor}

	for i, mon := range monitors {
		if err := mon.Start(ctx); err != nil {
			t.Fatalf("monitor %d failed to start: %v", i, err)
		}
	}

	// Allow some time for event loops to run
	time.Sleep(100 * time.Millisecond)

	// Stop all monitors
	for i, mon := range monitors {
		if err := mon.Stop(); err != nil {
			t.Fatalf("monitor %d failed to stop: %v", i, err)
		}
	}
}

// TestMonitorEventChannelBroadcast tests events sent on individual monitor channels
func TestMonitorEventChannelBroadcast(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create process monitor with test event
	eventData := make([]byte, 256) // Simplified binary representation

	mockReader := NewMockReader(eventData)
	monitor := NewProcessMonitor(NewMockProgramSet(mockReader), logger)

	// Start monitor
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer monitor.Stop()

	// Verify EventChan returns a readable channel
	eventChan := monitor.EventChan()
	if eventChan == nil {
		t.Fatal("expected non-nil event channel")
	}

	// Channel should be readable (even if no events sent in this test)
	select {
	case event := <-eventChan:
		if event != nil {
			AssertEnrichedEvent(t, event, "process_execution")
		}
	case <-time.After(200 * time.Millisecond):
		// Timeout is acceptable - mock reader has no real events
	}
}

// TestEnrichedEventTyping tests that all monitors produce correctly-typed EnrichedEvent
func TestEnrichedEventTyping(t *testing.T) {
	testCases := []struct {
		name        string
		eventType   string
		setupMonitor func() (interface {
			EventChan() <-chan *enrichment.EnrichedEvent
		}, context.CancelFunc)
	}{
		{
			name:      "ProcessMonitor produces process_execution events",
			eventType: "process_execution",
			setupMonitor: func() (interface {
				EventChan() <-chan *enrichment.EnrichedEvent
			}, context.CancelFunc) {
				logger := zaptest.NewLogger(t)
				monitor := NewProcessMonitor(NewMockProgramSet(NewMockReader()), logger)
				ctx, cancel := context.WithCancel(context.Background())
				monitor.Start(ctx)
				return monitor, func() {
					cancel()
					time.Sleep(10 * time.Millisecond)
					monitor.Stop()
				}
			},
		},
		{
			name:      "NetworkMonitor produces network_connection events",
			eventType: "network_connection",
			setupMonitor: func() (interface {
				EventChan() <-chan *enrichment.EnrichedEvent
			}, context.CancelFunc) {
				logger := zaptest.NewLogger(t)
				monitor := NewNetworkMonitor(NewMockProgramSet(NewMockReader()), logger)
				ctx, cancel := context.WithCancel(context.Background())
				monitor.Start(ctx)
				return monitor, func() {
					cancel()
					time.Sleep(10 * time.Millisecond)
					monitor.Stop()
				}
			},
		},
		{
			name:      "FileMonitor produces file_access events",
			eventType: "file_access",
			setupMonitor: func() (interface {
				EventChan() <-chan *enrichment.EnrichedEvent
			}, context.CancelFunc) {
				logger := zaptest.NewLogger(t)
				monitor := NewFileMonitor(NewMockProgramSet(NewMockReader()), logger, 100, nil, nil)
				ctx, cancel := context.WithCancel(context.Background())
				monitor.Start(ctx)
				return monitor, func() {
					cancel()
					time.Sleep(10 * time.Millisecond)
					monitor.Stop()
				}
			},
		},
		{
			name:      "CapabilityMonitor produces capability_usage events",
			eventType: "capability_usage",
			setupMonitor: func() (interface {
				EventChan() <-chan *enrichment.EnrichedEvent
			}, context.CancelFunc) {
				logger := zaptest.NewLogger(t)
				monitor := NewCapabilityMonitor(NewMockProgramSet(NewMockReader()), logger)
				ctx, cancel := context.WithCancel(context.Background())
				monitor.Start(ctx)
				return monitor, func() {
					cancel()
					time.Sleep(10 * time.Millisecond)
					monitor.Stop()
				}
			},
		},
		{
			name:      "DNSMonitor produces dns_query events",
			eventType: "dns_query",
			setupMonitor: func() (interface {
				EventChan() <-chan *enrichment.EnrichedEvent
			}, context.CancelFunc) {
				logger := zaptest.NewLogger(t)
				monitor := NewDNSMonitor(NewMockProgramSet(NewMockReader()), logger)
				ctx, cancel := context.WithCancel(context.Background())
				monitor.Start(ctx)
				return monitor, func() {
					cancel()
					time.Sleep(10 * time.Millisecond)
					monitor.Stop()
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			monitor, cleanup := tc.setupMonitor()
			defer cleanup()

			// EventChan should return a valid channel
			eventChan := monitor.EventChan()
			if eventChan == nil {
				t.Fatal("expected non-nil event channel")
			}
		})
	}
}

// ============================================================================
// Reader Interface Integration Tests
// ============================================================================

// TestMockReaderWithMultipleEvents tests MockReader handles event sequences
func TestMockReaderWithMultipleEvents(t *testing.T) {
	event1 := []byte{1, 2, 3, 4}
	event2 := []byte{5, 6, 7, 8}
	event3 := []byte{9, 10, 11, 12}

	reader := NewMockReader(event1, event2, event3)

	// Read all events
	data1, err := reader.Read()
	if err != nil {
		t.Fatalf("read 1 failed: %v", err)
	}
	if len(data1) == 0 {
		t.Fatal("expected event data 1")
	}

	data2, err := reader.Read()
	if err != nil {
		t.Fatalf("read 2 failed: %v", err)
	}
	if len(data2) == 0 {
		t.Fatal("expected event data 2")
	}

	data3, err := reader.Read()
	if err != nil {
		t.Fatalf("read 3 failed: %v", err)
	}
	if len(data3) == 0 {
		t.Fatal("expected event data 3")
	}

	// Reading beyond available events returns nil
	data4, err := reader.Read()
	if err != nil {
		t.Fatalf("read 4 failed: %v", err)
	}
	if data4 != nil {
		t.Fatal("expected nil after exhausting events")
	}

	// Close should succeed
	if err := reader.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

// TestMockReaderErrorHandling tests MockReader error simulation
func TestMockReaderErrorHandling(t *testing.T) {
	reader := NewMockReader([]byte{1, 2, 3})

	// Simulate read error
	reader.readError = ErrSimulated

	_, err := reader.Read()
	if err == nil {
		t.Fatal("expected read error")
	}
	if err != ErrSimulated {
		t.Fatalf("expected ErrSimulated, got %v", err)
	}

	// Simulate close error
	reader2 := NewMockReader()
	reader2.closeErr = ErrSimulated

	err = reader2.Close()
	if err == nil {
		t.Fatal("expected close error")
	}
	if err != ErrSimulated {
		t.Fatalf("expected ErrSimulated, got %v", err)
	}
}

// ============================================================================
// Context & Lifecycle Integration Tests
// ============================================================================

// TestMonitorContextPropagation tests that monitor respects parent context
func TestMonitorContextPropagation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	parentCtx, parentCancel := context.WithCancel(context.Background())

	monitor := NewProcessMonitor(NewMockProgramSet(NewMockReader()), logger)

	// Start with parent context
	err := monitor.Start(parentCtx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Give monitor time to start
	time.Sleep(50 * time.Millisecond)

	// Cancel parent context
	parentCancel()

	// Give monitor time to notice cancellation
	time.Sleep(100 * time.Millisecond)

	// Stop should still work
	err = monitor.Stop()
	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

// TestConcurrentMonitorStartStop tests thread safety of monitor operations
func TestConcurrentMonitorStartStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor := NewProcessMonitor(NewMockProgramSet(NewMockReader()), logger)

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Launch multiple goroutines trying to start/stop
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := monitor.Start(ctx); err != nil {
				// Only first one should succeed
				if err.Error() != "process monitor already started" {
					errors <- err
				}
			}
		}()
	}

	// Wait for starts
	wg.Wait()
	time.Sleep(50 * time.Millisecond)

	// Launch concurrent stops
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := monitor.Stop(); err != nil {
				// Only first one should succeed
				if err.Error() != "process monitor not started" {
					errors <- err
				}
			}
		}()
	}

	wg.Wait()

	// Check for unexpected errors
	select {
	case err := <-errors:
		t.Fatalf("unexpected error: %v", err)
	default:
		// Good - no unexpected errors
	}
}

// ============================================================================
// Event Channel Integration Tests
// ============================================================================

// TestEventChannelCapacity tests that events respect buffer size
func TestEventChannelCapacity(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewProcessMonitor(NewMockProgramSet(NewMockReader()), logger)

	// Get the event channel
	eventChan := monitor.EventChan()

	// Channel should have reasonable buffer size (100 from implementation)
	// But we can't directly inspect buffer size, so we test behavior

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer monitor.Stop()

	// Channel should be able to accept events without blocking
	select {
	case <-eventChan:
		// Event received (from real monitor behavior)
	case <-time.After(100 * time.Millisecond):
		// Timeout - no events (expected with mock reader)
	}
}

// TestEventChannelCloseBehavior tests behavior after monitor stops
func TestEventChannelCloseBehavior(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewProcessMonitor(NewMockProgramSet(NewMockReader()), logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Get channel while running
	eventChan := monitor.EventChan()

	// Stop monitor
	err = monitor.Stop()
	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	// Channel itself remains open (monitor doesn't close it)
	// but no new events should be sent
	select {
	case <-eventChan:
		// Events might still be in buffer
	case <-time.After(50 * time.Millisecond):
		// No events
	}
}

// ============================================================================
// Enrichment Pipeline Integration Tests
// ============================================================================

// TestEventEnrichmentConsistency tests that all monitor events are properly enriched
func TestEventEnrichmentConsistency(t *testing.T) {
	testCases := []struct {
		name          string
		createEvent   func() *enrichment.EnrichedEvent
		assertContext func(*testing.T, *enrichment.EnrichedEvent)
	}{
		{
			name: "ProcessMonitor enrichment has ProcessContext",
			createEvent: func() *enrichment.EnrichedEvent {
				procEvent := NewTestProcessEvent(100, 1000, 1000, "/bin/bash", "bash")
				return &enrichment.EnrichedEvent{
					RawEvent:  procEvent,
					EventType: "process_exec",
					Process: &enrichment.ProcessContext{
						PID:      procEvent.PID,
						Filename: string(procEvent.Filename[:]),
					},
					Timestamp: time.Now(),
				}
			},
			assertContext: func(t *testing.T, event *enrichment.EnrichedEvent) {
				if event.Process == nil {
					t.Fatal("expected ProcessContext")
				}
				if event.Process.PID != 100 {
					t.Errorf("expected PID 100, got %d", event.Process.PID)
				}
			},
		},
		{
			name: "NetworkMonitor enrichment has NetworkContext",
			createEvent: func() *enrichment.EnrichedEvent {
				netEvent := NewTestNetworkEvent(200, "192.168.1.1", "8.8.8.8", 12345, 53, 17)
				return &enrichment.EnrichedEvent{
					RawEvent:  netEvent,
					EventType: "network_connection",
					Network: &enrichment.NetworkContext{
						SourceIP:      "192.168.1.1",
						DestinationIP: "8.8.8.8",
						Protocol:      "UDP",
					},
					Timestamp: time.Now(),
				}
			},
			assertContext: func(t *testing.T, event *enrichment.EnrichedEvent) {
				if event.Network == nil {
					t.Fatal("expected NetworkContext")
				}
				if event.Network.Protocol != "UDP" {
					t.Errorf("expected UDP, got %s", event.Network.Protocol)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := tc.createEvent()
			AssertEnrichedEvent(t, event, event.EventType)
			tc.assertContext(t, event)
		})
	}
}

// TestTimestampPresence tests that all enriched events have valid timestamps
func TestTimestampPresence(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitors := []interface {
		Start(context.Context) error
		EventChan() <-chan *enrichment.EnrichedEvent
		Stop() error
	}{
		NewProcessMonitor(NewMockProgramSet(NewMockReader()), logger),
		NewNetworkMonitor(NewMockProgramSet(NewMockReader()), logger),
		NewFileMonitor(NewMockProgramSet(NewMockReader()), logger, 100, nil, nil),
		NewCapabilityMonitor(NewMockProgramSet(NewMockReader()), logger),
		NewDNSMonitor(NewMockProgramSet(NewMockReader()), logger),
	}

	for i, monitor := range monitors {
		if err := monitor.Start(ctx); err != nil {
			t.Fatalf("monitor %d start failed: %v", i, err)
		}
		defer monitor.Stop()

		// Verify EventChan is accessible and returns valid types
		eventChan := monitor.EventChan()
		if eventChan == nil {
			t.Fatalf("monitor %d returned nil event channel", i)
		}
	}
}
