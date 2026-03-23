// ANCHOR: Network Connection Monitor - Phase 2: Monitor Implementation - Dec 27, 2025
// Streams network connection events from kernel eBPF program to enrichment pipeline

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// NetworkMonitor monitors network connections via eBPF tracepoint
// Streams NetworkConnection events from kernel to enrichment pipeline
type NetworkMonitor struct {
	programSet *ProgramSet
	eventChan  chan *enrichment.EnrichedEvent
	logger     *zap.Logger
	stopChan   chan struct{}
	wg         sync.WaitGroup
	started    bool
	mu         sync.Mutex
}

// NewNetworkMonitor creates a new network monitor
func NewNetworkMonitor(programSet *ProgramSet, logger *zap.Logger) *NetworkMonitor {
	return &NetworkMonitor{
		programSet: programSet,
		eventChan:  make(chan *enrichment.EnrichedEvent, 100),
		logger:     logger,
		stopChan:   make(chan struct{}),
	}
}

// Start begins monitoring network connection events
func (nm *NetworkMonitor) Start(ctx context.Context) error {
	nm.mu.Lock()
	if nm.started {
		nm.mu.Unlock()
		return fmt.Errorf("network monitor already started")
	}
	nm.started = true
	nm.mu.Unlock()

	if nm.programSet == nil {
		return fmt.Errorf("program set is nil")
	}

	nm.wg.Add(1)
	go nm.eventLoop(ctx)

	nm.logger.Info("network monitor started")
	return nil
}

// eventLoop reads events from kernel and sends to enrichment pipeline
func (nm *NetworkMonitor) eventLoop(ctx context.Context) {
	defer nm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			nm.logger.Info("network monitor context cancelled")
			return
		case <-nm.stopChan:
			nm.logger.Info("network monitor stop signal received")
			return
		default:
			// ANCHOR: Read network event from kernel - Dec 27, 2025
			// Reads raw event bytes from perf/ringbuf reader
			// Parses into NetworkEvent struct using bytes.NewReader
			// Converts to enrichment.EnrichedEvent with NetworkContext

			if nm.programSet.Reader == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			data, err := nm.programSet.Reader.Read()
			if err != nil {
				nm.logger.Debug("event read error",
					zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if data == nil || len(data) == 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			// Parse raw bytes to NetworkEvent struct
			evt := &NetworkEvent{}
			if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, evt); err != nil {
				nm.logger.Warn("parse event failed",
					zap.Error(err))
				continue
			}

			// ANCHOR: Convert to enrichment type - Dec 27, 2025
			// Maps NetworkEvent to enrichment.EnrichedEvent with NetworkContext
			// Converts binary IP addresses to net.IP
			// Converts binary ports from network byte order
			// Adds timestamp

			protocol := "tcp"
			if evt.Protocol == 17 { // IPPROTO_UDP
				protocol = "udp"
			}

			netCtx := &enrichment.NetworkContext{
				SourceIP:        net.IPv4(byte(evt.SAddr), byte(evt.SAddr>>8), byte(evt.SAddr>>16), byte(evt.SAddr>>24)).String(),
				DestinationIP:   net.IPv4(byte(evt.DAddr), byte(evt.DAddr>>8), byte(evt.DAddr>>16), byte(evt.DAddr>>24)).String(),
				SourcePort:      evt.SPort,
				DestinationPort: evt.DPort,
				Protocol:        protocol,
			}

			enriched := &enrichment.EnrichedEvent{
				RawEvent:  evt,
				EventType: "network_connection",
				Network:   netCtx,
				Timestamp: time.Now(),
			}

			// Send to enrichment pipeline (non-blocking)
			select {
			case nm.eventChan <- enriched:
				nm.logger.Debug("network event sent",
					zap.Uint32("pid", evt.PID),
					zap.String("src", netCtx.SourceIP),
					zap.Uint16("src_port", netCtx.SourcePort),
					zap.String("dest", netCtx.DestinationIP),
					zap.Uint16("dest_port", netCtx.DestinationPort),
					zap.String("protocol", netCtx.Protocol))
			case <-ctx.Done():
				return
			case <-nm.stopChan:
				return
			default:
				nm.logger.Warn("event channel full, dropping event",
					zap.Uint32("pid", evt.PID))
			}
		}
	}
}

// EventChan returns the channel for receiving events
func (nm *NetworkMonitor) EventChan() <-chan *enrichment.EnrichedEvent {
	return nm.eventChan
}

// Stop stops the monitor and waits for goroutine to finish
func (nm *NetworkMonitor) Stop() error {
	nm.mu.Lock()
	if !nm.started {
		nm.mu.Unlock()
		return fmt.Errorf("network monitor not started")
	}
	nm.started = false
	nm.mu.Unlock()

	close(nm.stopChan)
	nm.wg.Wait()

	if nm.programSet != nil {
		if err := nm.programSet.Close(); err != nil {
			nm.logger.Error("close program set failed",
				zap.Error(err))
			return fmt.Errorf("close program set: %w", err)
		}
	}

	nm.logger.Info("network monitor stopped")
	return nil
}
