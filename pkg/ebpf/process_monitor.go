// ANCHOR: Process Execution Monitor - Phase 2: Monitor Implementation - Dec 27, 2025
// Streams process execution events from kernel eBPF program to enrichment pipeline

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// ProcessMonitor monitors process execution via eBPF tracepoint
// Streams enriched events with ProcessContext to enrichment pipeline
type ProcessMonitor struct {
	programSet *ProgramSet
	eventChan  chan *enrichment.EnrichedEvent
	logger     *zap.Logger
	stopChan   chan struct{}
	wg         sync.WaitGroup
	started    bool
	mu         sync.Mutex
}

// NewProcessMonitor creates a new process monitor
func NewProcessMonitor(programSet *ProgramSet, logger *zap.Logger) *ProcessMonitor {
	return &ProcessMonitor{
		programSet: programSet,
		eventChan:  make(chan *enrichment.EnrichedEvent, 100),
		logger:     logger,
		stopChan:   make(chan struct{}),
	}
}

// Start begins monitoring process execution events
func (pm *ProcessMonitor) Start(ctx context.Context) error {
	pm.mu.Lock()
	if pm.started {
		pm.mu.Unlock()
		return fmt.Errorf("process monitor already started")
	}
	pm.started = true
	pm.mu.Unlock()

	if pm.programSet == nil {
		return fmt.Errorf("program set is nil")
	}

	pm.wg.Add(1)
	go pm.eventLoop(ctx)

	pm.logger.Info("process monitor started")
	return nil
}

// eventLoop reads events from kernel and sends to enrichment pipeline
func (pm *ProcessMonitor) eventLoop(ctx context.Context) {
	defer pm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			pm.logger.Info("process monitor context cancelled")
			return
		case <-pm.stopChan:
			pm.logger.Info("process monitor stop signal received")
			return
		default:
			// ANCHOR: Read process event from kernel - Dec 27, 2025
			// Reads raw event bytes from perf/ringbuf reader
			// Parses into ProcessEvent struct using bytes.NewReader
			// Converts to enrichment.EnrichedEvent with ProcessContext

			if pm.programSet.Reader == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			data, err := pm.programSet.Reader.Read()
			if err != nil {
				pm.logger.Debug("event read error",
					zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if data == nil || len(data) == 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			// Parse raw bytes to ProcessEvent struct
			evt := &ProcessEvent{}
			if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, evt); err != nil {
				pm.logger.Warn("parse event failed",
					zap.Error(err))
				continue
			}

			// ANCHOR: Convert to enrichment type - Dec 27, 2025
			// Maps ProcessEvent to enrichment.EnrichedEvent with ProcessContext
			// Strips null bytes from strings
			// Adds timestamp and event type

			procCtx := &enrichment.ProcessContext{
				PID:      evt.PID,
				UID:      evt.UID,
				GID:      evt.GID,
				Filename: strings.TrimRight(string(evt.Filename[:]), "\x00"),
				Command:  strings.TrimRight(string(evt.Argv[:]), "\x00"),
			}

			enriched := &enrichment.EnrichedEvent{
				RawEvent:  evt,
				EventType: "process_execution",
				Process:   procCtx,
				Timestamp: time.Now(),
			}

			// Send to enrichment pipeline (non-blocking)
			select {
			case pm.eventChan <- enriched:
				pm.logger.Debug("process event sent",
					zap.Uint32("pid", procCtx.PID),
					zap.Uint32("uid", procCtx.UID),
					zap.Uint32("gid", procCtx.GID),
					zap.String("filename", procCtx.Filename),
					zap.String("command", procCtx.Command))
			case <-ctx.Done():
				return
			case <-pm.stopChan:
				return
			default:
				pm.logger.Warn("event channel full, dropping event",
					zap.Uint32("pid", procCtx.PID))
			}
		}
	}
}

// EventChan returns the channel for receiving events
func (pm *ProcessMonitor) EventChan() <-chan *enrichment.EnrichedEvent {
	return pm.eventChan
}

// Stop stops the monitor and waits for goroutine to finish
func (pm *ProcessMonitor) Stop() error {
	pm.mu.Lock()
	if !pm.started {
		pm.mu.Unlock()
		return fmt.Errorf("process monitor not started")
	}
	pm.started = false
	pm.mu.Unlock()

	close(pm.stopChan)
	pm.wg.Wait()

	if pm.programSet != nil {
		if err := pm.programSet.Close(); err != nil {
			pm.logger.Error("close program set failed",
				zap.Error(err))
			return fmt.Errorf("close program set: %w", err)
		}
	}

	pm.logger.Info("process monitor stopped")
	return nil
}
