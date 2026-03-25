package enrichment

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

// Stub structures matching ebpf event types without importing ebpf package
// This avoids circular import: ebpf -> enrichment -> ebpf

type ProcessEventStub struct {
	PID      uint32
	UID      uint32
	GID      uint32
	Filename [256]byte
	Argv     [256]byte
	CgroupID uint64
}

type NetworkEventStub struct {
	PID      uint32
	Family   uint16
	SPort    uint16
	DPort    uint16
	SAddr    uint32
	DAddr    uint32
	SAddrV6  [16]byte
	DAddrV6  [16]byte
	Protocol uint8
	Direction uint8
	State    uint8
	NetNS    uint32
	CgroupID uint64
}

type FileEventStub struct {
	PID       uint32
	Flags     uint32
	Mode      uint32
	FD        uint32
	Operation uint8
	CgroupID  uint64
	Filename  [256]byte
	FlagsStr  [32]byte
}

type CapabilityEventStub struct {
	PID         uint32
	Capability  uint32
	CheckType   uint8
	SyscallID   uint32
	CgroupID    uint64
	SyscallName [32]byte
}

type DNSEventStub struct {
	PID       uint32
	UID       uint32
	Query     string
	QueryType uint16
	Response  uint8
	CgroupID  uint64
	Timestamp int64
}

// TestEnrichProcessEventActuallyReturnsErrNoKubernetesContextWhenNoPod validates real EnrichProcessEvent behavior
// ANCHOR: Real enrichment function integration test - Feature: validate runtime behavior - Mar 25, 2026
// Tests that EnrichProcessEvent actually returns ErrNoKubernetesContext when pod context is missing.
// This tests the real code path, not simulated behavior.
func TestEnrichProcessEventActuallyReturnsErrNoKubernetesContextWhenNoPod(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	enricher := &Enricher{
		K8sClient:              nil,
		ClusterID:              "test-cluster",
		NodeName:               "test-node",
		Logger:                 logger,
		containerToPodCache:    make(map[string]string),
		cgroupToContainerCache: make(map[uint64]string),
	}

	// Create a real ProcessEvent struct (matches eBPF kernel event)
	processEvent := ProcessEventStub{
		PID:      1234,
		UID:      0,
		GID:      0,
		CgroupID: 0,
	}
	copy(processEvent.Argv[:], "sleep")

	// Call the REAL EnrichProcessEvent function
	enriched, err := enricher.EnrichProcessEvent(context.Background(), processEvent)

	// ASSERTION 1: Must return ErrNoKubernetesContext
	if !errors.Is(err, ErrNoKubernetesContext) {
		t.Errorf("Expected ErrNoKubernetesContext, got %v", err)
	}

	// ASSERTION 2: Must return enriched event (not nil)
	if enriched == nil {
		t.Errorf("Expected enriched event to be non-nil, got nil")
	}

	// ASSERTION 3: PodUID must be empty (no K8s context)
	if enriched != nil && enriched.Kubernetes.PodUID != "" {
		t.Errorf("Expected empty PodUID, got %s", enriched.Kubernetes.PodUID)
	}

	// ASSERTION 4: Process context must be populated
	if enriched != nil && enriched.Process == nil {
		t.Errorf("Expected Process context to be populated")
	}

	// ASSERTION 5: Process PID must match
	if enriched != nil && enriched.Process.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", enriched.Process.PID)
	}
}

// TestEnrichNetworkEventActuallyReturnsErrNoKubernetesContextWhenNoPod validates real EnrichNetworkEvent behavior
func TestEnrichNetworkEventActuallyReturnsErrNoKubernetesContextWhenNoPod(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	enricher := &Enricher{
		K8sClient:              nil,
		ClusterID:              "test-cluster",
		NodeName:               "test-node",
		Logger:                 logger,
		containerToPodCache:    make(map[string]string),
		cgroupToContainerCache: make(map[uint64]string),
	}

	// Create a real NetworkEvent struct
	networkEvent := NetworkEventStub{
		PID:      5678,
		Family:   2,         // AF_INET
		SPort:    54321,
		DPort:    443,
		SAddr:    0xC0A80164, // 192.168.1.100
		DAddr:    0x0A000001, // 10.0.0.1
		Protocol: 6,          // TCP
		CgroupID: 0,
	}

	// Call the REAL EnrichNetworkEvent function
	enriched, err := enricher.EnrichNetworkEvent(context.Background(), networkEvent)

	// ASSERTION 1: Must return ErrNoKubernetesContext
	if !errors.Is(err, ErrNoKubernetesContext) {
		t.Errorf("Expected ErrNoKubernetesContext, got %v", err)
	}

	// ASSERTION 2: Must return enriched event
	if enriched == nil {
		t.Errorf("Expected enriched event to be non-nil, got nil")
	}

	// ASSERTION 3: Network context must be populated
	if enriched != nil && enriched.Network == nil {
		t.Errorf("Expected Network context to be populated")
	}

	// ASSERTION 4: Destination port must match
	if enriched != nil && enriched.Network.DestinationPort != 443 {
		t.Errorf("Expected DestinationPort 443, got %d", enriched.Network.DestinationPort)
	}
}

// TestEnrichDNSEventActuallyReturnsErrNoKubernetesContextWhenNoPod validates real EnrichDNSEvent behavior
func TestEnrichDNSEventActuallyReturnsErrNoKubernetesContextWhenNoPod(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	enricher := &Enricher{
		K8sClient:              nil,
		ClusterID:              "test-cluster",
		NodeName:               "test-node",
		Logger:                 logger,
		containerToPodCache:    make(map[string]string),
		cgroupToContainerCache: make(map[uint64]string),
	}

	// Create a real DNS event (will use reflection to extract fields)
	dnsEvent := &DNSEventStub{
		PID:       9999,
		UID:       1000,
		Query:     "example.com",
		QueryType: 1, // A record
		Response:  0,
		CgroupID:  0,
		Timestamp: 0,
	}

	// Call the REAL EnrichDNSEvent function
	enriched, err := enricher.EnrichDNSEvent(context.Background(), dnsEvent)

	// ASSERTION 1: Must return ErrNoKubernetesContext
	if !errors.Is(err, ErrNoKubernetesContext) {
		t.Errorf("Expected ErrNoKubernetesContext, got %v", err)
	}

	// ASSERTION 2: Must return enriched event
	if enriched == nil {
		t.Errorf("Expected enriched event to be non-nil, got nil")
	}

	// ASSERTION 3: DNS context must be populated
	if enriched != nil && enriched.DNS == nil {
		t.Errorf("Expected DNS context to be populated")
	}
}

// TestEnrichFileEventActuallyReturnsErrNoKubernetesContextWhenNoPod validates real EnrichFileEvent behavior
func TestEnrichFileEventActuallyReturnsErrNoKubernetesContextWhenNoPod(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	enricher := &Enricher{
		K8sClient:              nil,
		ClusterID:              "test-cluster",
		NodeName:               "test-node",
		Logger:                 logger,
		containerToPodCache:    make(map[string]string),
		cgroupToContainerCache: make(map[uint64]string),
	}

	// Create a real FileEvent struct
	fileEvent := FileEventStub{
		PID:       7777,
		Operation: 2, // read
		CgroupID:  0,
	}
	copy(fileEvent.Filename[:], "/etc/passwd")

	// Call the REAL EnrichFileEvent function
	enriched, err := enricher.EnrichFileEvent(context.Background(), fileEvent)

	// ASSERTION 1: Must return ErrNoKubernetesContext
	if !errors.Is(err, ErrNoKubernetesContext) {
		t.Errorf("Expected ErrNoKubernetesContext, got %v", err)
	}

	// ASSERTION 2: Must return enriched event
	if enriched == nil {
		t.Errorf("Expected enriched event to be non-nil, got nil")
	}

	// ASSERTION 3: File context must be populated
	if enriched != nil && enriched.File == nil {
		t.Errorf("Expected File context to be populated")
	}

	// ASSERTION 4: Path must match
	if enriched != nil && enriched.File.Path != "/etc/passwd" {
		t.Errorf("Expected path '/etc/passwd', got %s", enriched.File.Path)
	}
}

// TestEnrichCapabilityEventActuallyReturnsErrNoKubernetesContextWhenNoPod validates real EnrichCapabilityEvent behavior
func TestEnrichCapabilityEventActuallyReturnsErrNoKubernetesContextWhenNoPod(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	enricher := &Enricher{
		K8sClient:              nil,
		ClusterID:              "test-cluster",
		NodeName:               "test-node",
		Logger:                 logger,
		containerToPodCache:    make(map[string]string),
		cgroupToContainerCache: make(map[uint64]string),
	}

	// Create a real CapabilityEvent struct
	capEvent := CapabilityEventStub{
		PID:        8888,
		Capability: 0, // CAP_CHOWN
		CheckType:  1, // check
		CgroupID:   0,
	}
	copy(capEvent.SyscallName[:], "open")

	// Call the REAL EnrichCapabilityEvent function
	enriched, err := enricher.EnrichCapabilityEvent(context.Background(), capEvent)

	// ASSERTION 1: Must return ErrNoKubernetesContext
	if !errors.Is(err, ErrNoKubernetesContext) {
		t.Errorf("Expected ErrNoKubernetesContext, got %v", err)
	}

	// ASSERTION 2: Must return enriched event
	if enriched == nil {
		t.Errorf("Expected enriched event to be non-nil, got nil")
	}

	// ASSERTION 3: Capability context must be populated
	if enriched != nil && enriched.Capability == nil {
		t.Errorf("Expected Capability context to be populated")
	}

	// ASSERTION 4: Capability name must match
	if enriched != nil && enriched.Capability.Name != "CAP_CHOWN" {
		t.Errorf("Expected CAP_CHOWN, got %s", enriched.Capability.Name)
	}
}

// TestAllEnrichFunctionsActuallyReturnSentinelErrorOnPodAbsent calls all real Enrich* functions
// ANCHOR: Comprehensive real function integration tests - Feature: runtime validation - Mar 25, 2026
// Calls actual Enrich* functions with real event structs and verifies sentinel error + enrichment.
func TestAllEnrichFunctionsActuallyReturnSentinelErrorOnPodAbsent(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	enricher := &Enricher{
		K8sClient:              nil,
		ClusterID:              "test-cluster",
		NodeName:               "test-node",
		Logger:                 logger,
		containerToPodCache:    make(map[string]string),
		cgroupToContainerCache: make(map[uint64]string),
	}

	tests := []struct {
		name        string
		enrichFn    func(context.Context) (*EnrichedEvent, error)
		eventType   string
		validateFn  func(*testing.T, *EnrichedEvent)
	}{
		{
			name: "process_event",
			enrichFn: func(ctx context.Context) (*EnrichedEvent, error) {
				event := ProcessEventStub{
					PID:      1111,
					UID:      1000,
					GID:      1000,
					CgroupID: 0,
					Argv:     [256]byte{},
				}
				copy(event.Argv[:], "bash")
				return enricher.EnrichProcessEvent(ctx, event)
			},
			eventType: "process",
			validateFn: func(t *testing.T, enriched *EnrichedEvent) {
				if enriched.Process == nil {
					t.Errorf("Process context not populated")
				} else if enriched.Process.PID != 1111 {
					t.Errorf("Process PID mismatch: expected 1111, got %d", enriched.Process.PID)
				}
			},
		},
		{
			name: "network_event",
			enrichFn: func(ctx context.Context) (*EnrichedEvent, error) {
				event := NetworkEventStub{
					PID:      2222,
					Family:   2,
					SPort:    12345,
					DPort:    80,
					SAddr:    0xC0A80165,
					DAddr:    0x08080808,
					Protocol: 6,
					CgroupID: 0,
				}
				return enricher.EnrichNetworkEvent(ctx, event)
			},
			eventType: "network",
			validateFn: func(t *testing.T, enriched *EnrichedEvent) {
				if enriched.Network == nil {
					t.Errorf("Network context not populated")
				} else if enriched.Network.DestinationPort != 80 {
					t.Errorf("Network DestinationPort mismatch: expected 80, got %d", enriched.Network.DestinationPort)
				}
			},
		},
		{
			name: "file_event",
			enrichFn: func(ctx context.Context) (*EnrichedEvent, error) {
				event := FileEventStub{
					PID:       3333,
					Operation: 1, // write
					CgroupID:  0,
					Filename:  [256]byte{},
					FlagsStr:  [32]byte{},
				}
				copy(event.Filename[:], "/var/log/app.log")
				return enricher.EnrichFileEvent(ctx, event)
			},
			eventType: "file",
			validateFn: func(t *testing.T, enriched *EnrichedEvent) {
				if enriched.File == nil {
					t.Errorf("File context not populated")
				} else if enriched.File.Path != "/var/log/app.log" {
					t.Errorf("File path mismatch: expected '/var/log/app.log', got %s", enriched.File.Path)
				}
			},
		},
		{
			name: "capability_event",
			enrichFn: func(ctx context.Context) (*EnrichedEvent, error) {
				event := CapabilityEventStub{
					PID:        4444,
					Capability: 21, // CAP_SYS_NICE
					CheckType:  1,
					CgroupID:   0,
					SyscallName: [32]byte{},
				}
				copy(event.SyscallName[:], "ioctl")
				return enricher.EnrichCapabilityEvent(ctx, event)
			},
			eventType: "capability",
			validateFn: func(t *testing.T, enriched *EnrichedEvent) {
				if enriched.Capability == nil {
					t.Errorf("Capability context not populated")
				} else if enriched.Capability.Name != "CAP_SYS_NICE" {
					t.Errorf("Capability name mismatch: expected 'CAP_SYS_NICE', got %s", enriched.Capability.Name)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			enriched, err := tt.enrichFn(ctx)

			// CRITICAL ASSERTION: All must return ErrNoKubernetesContext
			if !errors.Is(err, ErrNoKubernetesContext) {
				t.Errorf("%s: expected ErrNoKubernetesContext, got %v", tt.eventType, err)
			}

			// CRITICAL ASSERTION: All must return enriched event (not nil)
			if enriched == nil {
				t.Errorf("%s: expected enriched event, got nil", tt.eventType)
			}

			// CRITICAL ASSERTION: All must have empty PodUID (no K8s context)
			if enriched != nil && enriched.Kubernetes.PodUID != "" {
				t.Errorf("%s: expected empty PodUID, got %s", tt.eventType, enriched.Kubernetes.PodUID)
			}

			// Run type-specific validation
			if enriched != nil {
				tt.validateFn(t, enriched)
			}
		})
	}
}
