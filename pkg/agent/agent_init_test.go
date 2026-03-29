package agent

import (
	"encoding/base64"
	"testing"
)

func TestNewAgentDefersMonitorCreationUntilStart(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Enrichment.KubernetesMetadata = false
	cfg.Agent.Enrichment.KubernetesOnly = false
	cfg.Agent.OWL.TLS.Enabled = false
	cfg.Agent.EBPF.Enabled = true
	cfg.Agent.EBPF.Process.Enabled = true
	cfg.Agent.EBPF.Network.Enabled = true
	cfg.Agent.EBPF.DNS.Enabled = true
	cfg.Agent.EBPF.File.Enabled = true
	cfg.Agent.EBPF.Capability.Enabled = true

	agent, err := NewAgent(cfg)
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	if agent.ProcessMonitor != nil || agent.NetworkMonitor != nil || agent.DNSMonitor != nil || agent.FileMonitor != nil || agent.CapabilityMonitor != nil {
		t.Fatalf("expected monitors to be nil before Start() loads eBPF programs")
	}
}

func TestGenerateEphemeralKey(t *testing.T) {
	key, err := generateEphemeralKey()
	if err != nil {
		t.Fatalf("generateEphemeralKey failed: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("ephemeral key should be valid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32-byte decoded key, got %d", len(decoded))
	}
}
