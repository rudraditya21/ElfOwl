// ANCHOR: Linux Capability Monitor - Phase 2: Monitor Implementation - Dec 27, 2025
// Streams capability usage events from kernel eBPF program to enrichment pipeline

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// CapabilityMonitor monitors Linux capability usage via eBPF tracepoint
// Streams CapabilityUsage events from kernel to enrichment pipeline
type CapabilityMonitor struct {
	programSet *ProgramSet
	eventChan  chan *enrichment.EnrichedEvent
	logger     *zap.Logger
	stopChan   chan struct{}
	wg         sync.WaitGroup
	started    bool
	mu         sync.Mutex
}

// NewCapabilityMonitor creates a new capability monitor
func NewCapabilityMonitor(programSet *ProgramSet, logger *zap.Logger) *CapabilityMonitor {
	return &CapabilityMonitor{
		programSet: programSet,
		eventChan:  make(chan *enrichment.EnrichedEvent, 100),
		logger:     logger,
		stopChan:   make(chan struct{}),
	}
}

// Start begins monitoring capability usage events
func (cm *CapabilityMonitor) Start(ctx context.Context) error {
	cm.mu.Lock()
	if cm.started {
		cm.mu.Unlock()
		return fmt.Errorf("capability monitor already started")
	}
	cm.started = true
	cm.mu.Unlock()

	if cm.programSet == nil {
		return fmt.Errorf("program set is nil")
	}

	cm.wg.Add(1)
	go cm.eventLoop(ctx)

	cm.logger.Info("capability monitor started")
	return nil
}

// eventLoop reads events from kernel and sends to enrichment pipeline
func (cm *CapabilityMonitor) eventLoop(ctx context.Context) {
	defer cm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			cm.logger.Info("capability monitor context cancelled")
			return
		case <-cm.stopChan:
			cm.logger.Info("capability monitor stop signal received")
			return
		default:
			// ANCHOR: Read capability event from kernel - Dec 27, 2025
			// Reads raw event bytes from perf/ringbuf reader
			// Parses into CapabilityEvent struct using bytes.NewReader
			// Converts to enrichment.EnrichedEvent with CapabilityContext

			if cm.programSet.Reader == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			data, err := cm.programSet.Reader.Read()
			if err != nil {
				cm.logger.Debug("event read error",
					zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if data == nil || len(data) == 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			// Parse raw bytes to CapabilityEvent struct
			evt := &CapabilityEvent{}
			if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, evt); err != nil {
				cm.logger.Warn("parse event failed",
					zap.Error(err))
				continue
			}

			// ANCHOR: Convert to enrichment type - Dec 27, 2025
			// Maps CapabilityEvent to enrichment.EnrichedEvent with CapabilityContext
			// Maps capability number to name
			// Converts check type to string
			// Adds timestamp

			capName := capabilityName(evt.Capability)
			allowed := evt.CheckType != 2

			capCtx := &enrichment.CapabilityContext{
				Name:    capName,
				Allowed: allowed,
				PID:     evt.PID,
			}

			enriched := &enrichment.EnrichedEvent{
				RawEvent:   evt,
				EventType:  "capability_usage",
				Capability: capCtx,
				Timestamp:  time.Now(),
			}

			// Send to enrichment pipeline (non-blocking)
			select {
			case cm.eventChan <- enriched:
				cm.logger.Debug("capability event sent",
					zap.Uint32("pid", evt.PID),
					zap.String("capability", capName),
					zap.Uint8("check_type", evt.CheckType),
					zap.String("syscall", string(bytes.TrimRight(evt.SyscallName[:], "\x00"))))
			case <-ctx.Done():
				return
			case <-cm.stopChan:
				return
			default:
				cm.logger.Warn("event channel full, dropping event",
					zap.Uint32("pid", evt.PID))
			}
		}
	}
}

// capabilityName maps capability number to name
// Based on include/uapi/linux/capability.h
func capabilityName(cap uint32) string {
	capNames := map[uint32]string{
		0:  "CAP_CHOWN",
		1:  "CAP_DAC_OVERRIDE",
		2:  "CAP_DAC_READ_SEARCH",
		3:  "CAP_FOWNER",
		4:  "CAP_FSETID",
		5:  "CAP_KILL",
		6:  "CAP_SETGID",
		7:  "CAP_SETUID",
		8:  "CAP_SETPCAP",
		9:  "CAP_LINUX_IMMUTABLE",
		10: "CAP_NET_BIND_SERVICE",
		11: "CAP_NET_BROADCAST",
		12: "CAP_NET_ADMIN",
		13: "CAP_NET_RAW",
		14: "CAP_IPC_LOCK",
		15: "CAP_IPC_OWNER",
		16: "CAP_SYS_MODULE",
		17: "CAP_SYS_RAWIO",
		18: "CAP_SYS_CHROOT",
		19: "CAP_SYS_PTRACE",
		20: "CAP_SYS_PACCT",
		21: "CAP_SYS_ADMIN",
		22: "CAP_SYS_BOOT",
		23: "CAP_SYS_NICE",
		24: "CAP_SYS_RESOURCE",
		25: "CAP_SYS_TIME",
		26: "CAP_SYS_TTY_CONFIG",
		27: "CAP_MKNOD",
		28: "CAP_LEASE",
		29: "CAP_AUDIT_WRITE",
		30: "CAP_AUDIT_CONTROL",
		31: "CAP_SETFCAP",
		32: "CAP_MAC_OVERRIDE",
		33: "CAP_MAC_ADMIN",
		34: "CAP_SYSLOG",
		35: "CAP_WAKE_ALARM",
		36: "CAP_BLOCK_SUSPEND",
		37: "CAP_AUDIT_READ",
		38: "CAP_PERFMON",
		39: "CAP_BPF",
		40: "CAP_CHECKPOINT_RESTORE",
	}

	if name, ok := capNames[cap]; ok {
		return name
	}
	return fmt.Sprintf("CAP_UNKNOWN_%d", cap)
}

// EventChan returns the channel for receiving events
func (cm *CapabilityMonitor) EventChan() <-chan *enrichment.EnrichedEvent {
	return cm.eventChan
}

// Stop stops the monitor and waits for goroutine to finish
func (cm *CapabilityMonitor) Stop() error {
	cm.mu.Lock()
	if !cm.started {
		cm.mu.Unlock()
		return fmt.Errorf("capability monitor not started")
	}
	cm.started = false
	cm.mu.Unlock()

	close(cm.stopChan)
	cm.wg.Wait()

	if cm.programSet != nil {
		if err := cm.programSet.Close(); err != nil {
			cm.logger.Error("close program set failed",
				zap.Error(err))
			return fmt.Errorf("close program set: %w", err)
		}
	}

	cm.logger.Info("capability monitor stopped")
	return nil
}
