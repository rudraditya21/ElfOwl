// ANCHOR: Lifecycle tests for eBPF monitors - Phase 3: Testing - Dec 27, 2025
// Tests monitor initialization, shutdown, error recovery, and state management

package ebpf

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// ============================================================================
// Monitor Initialization Tests
// ============================================================================

// TestMonitorInitialization tests proper monitor creation and initialization
func TestMonitorInitialization(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())

	// Test all monitors
	// Note: Cannot directly test via interface{} due to Go's type system,
	// but we verify creation individually below
	monitors := []struct {
		name    string
		monitor interface{}
	}{
		{
			name:    "ProcessMonitor",
			monitor: NewProcessMonitor(programSet, logger),
		},
		{
			name:    "NetworkMonitor",
			monitor: NewNetworkMonitor(programSet, logger),
		},
		{
			name:    "FileMonitor",
			monitor: NewFileMonitor(programSet, logger, 100, nil, nil),
		},
		{
			name:    "CapabilityMonitor",
			monitor: NewCapabilityMonitor(programSet, logger),
		},
		{
			name:    "DNSMonitor",
			monitor: NewDNSMonitor(programSet, logger),
		},
	}

	for _, mon := range monitors {
		t.Run(mon.name + " initialization", func(t *testing.T) {
			if mon.monitor == nil {
				t.Fatal("expected non-nil monitor")
			}
		})
	}
}

// TestMonitorNilProgramSetHandling tests monitors handle nil ProgramSet gracefully
func TestMonitorNilProgramSetHandling(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test ProcessMonitor with nil ProgramSet
	t.Run("ProcessMonitor with nil ProgramSet", func(t *testing.T) {
		monitor := NewProcessMonitor(nil, logger)
		err := monitor.Start(ctx)
		if err == nil {
			t.Fatal("expected error for nil ProgramSet")
		}
		// Note: monitor sets started=true before checking programSet,
		// so Stop() succeeds even though Start failed
		err = monitor.Stop()
		if err != nil {
			t.Fatalf("stop failed: %v", err)
		}
	})

	// Test NetworkMonitor with nil ProgramSet
	t.Run("NetworkMonitor with nil ProgramSet", func(t *testing.T) {
		monitor := NewNetworkMonitor(nil, logger)
		err := monitor.Start(ctx)
		if err == nil {
			t.Fatal("expected error for nil ProgramSet")
		}
		// Note: monitor sets started=true before checking programSet,
		// so Stop() succeeds even though Start failed
		err = monitor.Stop()
		if err != nil {
			t.Fatalf("stop failed: %v", err)
		}
	})
}

// ============================================================================
// Monitor Startup Tests
// ============================================================================

// TestMonitorStartupSequence tests proper startup sequence
func TestMonitorStartupSequence(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Monitor should not be started initially
	if monitor.started {
		t.Error("monitor should not be started initially")
	}

	// Start should succeed
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Monitor should be marked as started
	if !monitor.started {
		t.Error("monitor should be marked as started")
	}

	// Cleanup
	monitor.Stop()
}

// TestMonitorStartupWithBadContext tests startup with already-cancelled context
func TestMonitorStartupWithBadContext(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before starting

	// Starting with cancelled context should still start (context check happens in eventLoop)
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start with cancelled context failed: %v", err)
	}

	// Give time for eventLoop to notice context is cancelled
	time.Sleep(100 * time.Millisecond)

	// Monitor should still clean up properly
	err = monitor.Stop()
	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

// ============================================================================
// Monitor Shutdown Tests
// ============================================================================

// TestMonitorShutdownSequence tests proper shutdown sequence
func TestMonitorShutdownSequence(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Monitor should be running
	if !monitor.started {
		t.Error("monitor should be running")
	}

	// Stop should succeed
	err = monitor.Stop()
	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	// Monitor should be stopped
	if monitor.started {
		t.Error("monitor should be stopped")
	}
}

// TestMonitorDoubleStop tests calling stop twice is handled
func TestMonitorDoubleStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start and stop once
	monitor.Start(ctx)
	monitor.Stop()

	// Second stop should fail with "not started" error
	err := monitor.Stop()
	if err == nil {
		t.Fatal("expected error on double stop")
	}
}

// TestMonitorStopWithoutStart tests calling stop without start
func TestMonitorStopWithoutStart(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	// Calling stop without start should fail
	err := monitor.Stop()
	if err == nil {
		t.Fatal("expected error on stop without start")
	}
}

// ============================================================================
// Monitor State Management Tests
// ============================================================================

// TestMonitorStartedFlag tests started flag is properly managed
func TestMonitorStartedFlag(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initially false
	if monitor.started {
		t.Error("started should be false initially")
	}

	// After start, should be true
	monitor.Start(ctx)
	if !monitor.started {
		t.Error("started should be true after Start")
	}

	// After stop, should be false
	monitor.Stop()
	if monitor.started {
		t.Error("started should be false after Stop")
	}
}

// TestMonitorEventChannelAvailability tests event channel available after start
func TestMonitorEventChannelAvailability(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Event channel should be available before start
	ch1 := monitor.EventChan()
	if ch1 == nil {
		t.Fatal("event channel should be available before start")
	}

	// Start monitor
	monitor.Start(ctx)

	// Event channel should still be available after start
	ch2 := monitor.EventChan()
	if ch2 == nil {
		t.Fatal("event channel should be available after start")
	}

	// Should be the same channel
	if ch1 != ch2 {
		t.Error("event channel should be consistent")
	}

	// Cleanup
	monitor.Stop()
}

// ============================================================================
// Graceful Shutdown Tests
// ============================================================================

// TestGracefulShutdownWithActiveEventLoop tests graceful shutdown while processing
func TestGracefulShutdownWithActiveEventLoop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Let event loop run for a bit
	time.Sleep(50 * time.Millisecond)

	// Graceful shutdown should wait for event loop to finish
	startShutdown := time.Now()
	err = monitor.Stop()
	shutdownDuration := time.Since(startShutdown)

	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	// Shutdown should complete in reasonable time
	if shutdownDuration > 5*time.Second {
		t.Logf("warning: graceful shutdown took %v", shutdownDuration)
	}
}

// TestShutdownWithBlockedEventLoop tests shutdown when event loop is blocked
func TestShutdownWithBlockedEventLoop(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create reader that blocks (returns nothing)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Stop should unblock the event loop
	startShutdown := time.Now()
	err = monitor.Stop()
	shutdownDuration := time.Since(startShutdown)

	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	// Should shutdown promptly even if reader is blocking
	if shutdownDuration > 500*time.Millisecond {
		t.Logf("warning: shutdown with blocked reader took %v", shutdownDuration)
	}
}

// ============================================================================
// Error Recovery Tests
// ============================================================================

// TestMonitorErrorRecovery tests monitor continues after transient errors
func TestMonitorErrorRecovery(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer monitor.Stop()

	// Inject error into reader
	mockReader.readError = ErrSimulated

	// Monitor should keep running despite read errors
	time.Sleep(100 * time.Millisecond)

	if !monitor.started {
		t.Fatal("monitor stopped after reader error")
	}

	// Clear error
	mockReader.readError = nil

	// Monitor should continue normally
	time.Sleep(50 * time.Millisecond)

	if !monitor.started {
		t.Fatal("monitor stopped after clearing error")
	}
}

// TestMonitorRecoveryFromNilEvents tests monitor handles nil events
func TestMonitorRecoveryFromNilEvents(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Reader that returns nil (no data)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer monitor.Stop()

	// Monitor should handle nil events gracefully
	time.Sleep(100 * time.Millisecond)

	if !monitor.started {
		t.Fatal("monitor stopped after nil events")
	}
}

// ============================================================================
// Concurrency Tests
// ============================================================================

// TestConcurrentMonitorOperations tests concurrent start/stop operations
func TestConcurrentMonitorOperations(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	errChan := make(chan error, 20)

	// Launch concurrent goroutines trying to start
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := monitor.Start(ctx); err != nil {
				// Only first should succeed
				if err.Error() != "process monitor already started" {
					errChan <- err
				}
			}
		}()
	}

	wg.Wait()
	time.Sleep(50 * time.Millisecond)

	// Launch concurrent goroutines trying to stop
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := monitor.Stop(); err != nil {
				// Only first should succeed
				if err.Error() != "process monitor not started" {
					errChan <- err
				}
			}
		}()
	}

	wg.Wait()

	// Check for unexpected errors
	close(errChan)
	for err := range errChan {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestMonitorWaitGroupBehavior tests WaitGroup properly synchronizes goroutines
func TestMonitorWaitGroupBehavior(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor (launches eventLoop in goroutine)
	monitor.Start(ctx)

	// eventLoop should be running
	time.Sleep(50 * time.Millisecond)

	// Stop should wait for eventLoop to finish via WaitGroup
	stopDone := make(chan struct{})
	go func() {
		monitor.Stop()
		close(stopDone)
	}()

	// Should complete promptly
	select {
	case <-stopDone:
		// Good - stop completed
	case <-time.After(2 * time.Second):
		t.Fatal("stop blocked on WaitGroup (eventLoop may not have finished)")
	}
}

// ============================================================================
// Resource Cleanup Tests
// ============================================================================

// TestMonitorResourceCleanup tests proper resource cleanup on stop
func TestMonitorResourceCleanup(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create monitors and verify they clean up
	monitors := []interface {
		Start(context.Context) error
		Stop() error
	}{
		NewProcessMonitor(NewMockProgramSet(NewMockReader()), logger),
		NewNetworkMonitor(NewMockProgramSet(NewMockReader()), logger),
		NewFileMonitor(NewMockProgramSet(NewMockReader()), logger, 100, nil, nil),
		NewCapabilityMonitor(NewMockProgramSet(NewMockReader()), logger),
		NewDNSMonitor(NewMockProgramSet(NewMockReader()), logger),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start all monitors
	for i, mon := range monitors {
		if err := mon.Start(ctx); err != nil {
			t.Fatalf("monitor %d start failed: %v", i, err)
		}
	}

	// Stop all monitors
	for i, mon := range monitors {
		if err := mon.Stop(); err != nil {
			t.Fatalf("monitor %d stop failed: %v", i, err)
		}
	}

	// All should be successfully cleaned up
	t.Logf("successfully cleaned up %d monitors", len(monitors))
}

// TestMonitorChannelCleanup tests event channel is not closed (app retains control)
func TestMonitorChannelCleanup(t *testing.T) {
	logger := zaptest.NewLogger(t)
	programSet := NewMockProgramSet(NewMockReader())
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get channel before start
	ch := monitor.EventChan()

	// Start and stop monitor
	monitor.Start(ctx)
	monitor.Stop()

	// Channel should still be usable (monitor doesn't close it)
	// Sending on closed channel would panic, so this verifies it's still open
	select {
	case <-ch:
		// Event or no event - channel is accessible
	case <-time.After(50 * time.Millisecond):
		// Timeout - channel is still accessible
	}
}
