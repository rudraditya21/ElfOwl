// ANCHOR: Agent configuration schema - Dec 26, 2025
// Defines all configuration structures for elf-owl agent
// Loads from YAML files and environment variables with sensible defaults

package agent

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/udyansh/elf-owl/pkg/config"
)

// Config is the top-level configuration structure
type Config struct {
	Agent AgentConfig `yaml:"agent"`
}

// AgentConfig contains agent-specific settings
// ANCHOR: Migrated to cilium/ebpf only (removed goBPF) - Dec 27, 2025
type AgentConfig struct {
	ClusterID  string           `yaml:"cluster_id"`
	NodeName   string           `yaml:"node_name"`
	Logging    LoggingConfig    `yaml:"logging"`
	EBPF       EBPFConfig       `yaml:"ebpf"`
	Kubernetes KubernetesConfig `yaml:"kubernetes"`
	Rules      RulesConfig      `yaml:"rules"`
	Enrichment EnrichmentConfig `yaml:"enrichment"`
	Evidence   EvidenceConfig   `yaml:"evidence"`
	OWL        OWLConfig        `yaml:"owl_api"`
	Metrics    MetricsConfig    `yaml:"metrics"`
	Health     HealthConfig     `yaml:"health"`
}

// LoggingConfig defines logging behavior
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// ANCHOR: eBPF Configuration - Phase 3: cilium/ebpf Migration - Dec 27, 2025
// Defines Cilium/eBPF monitor settings (now the only monitor implementation)
// Fully replaces goBPF with production-grade cilium/ebpf library
type EBPFConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Process    EBPFMonitorConfig `yaml:"process"`
	Network    EBPFMonitorConfig `yaml:"network"`
	DNS        EBPFMonitorConfig `yaml:"dns"`
	File       EBPFMonitorConfig `yaml:"file"`
	Capability EBPFMonitorConfig `yaml:"capability"`
	PerfBuffer PerfBufferConfig  `yaml:"perf_buffer"`
	RingBuffer RingBufferConfig  `yaml:"ring_buffer"`
}

// EBPFMonitorConfig defines individual Cilium/eBPF monitor settings
type EBPFMonitorConfig struct {
	Enabled    bool          `yaml:"enabled"`
	BufferSize int           `yaml:"buffer_size"`
	Timeout    time.Duration `yaml:"timeout"`
}

// PerfBufferConfig defines perf buffer settings for event streaming
type PerfBufferConfig struct {
	Enabled     bool `yaml:"enabled"`
	PageCount   int  `yaml:"page_count"`
	LostHandler bool `yaml:"lost_handler"`
}

// RingBufferConfig defines ring buffer settings (preferred for newer kernels)
type RingBufferConfig struct {
	Enabled bool `yaml:"enabled"`
	Size    int  `yaml:"size"`
}

// KubernetesConfig defines Kubernetes integration settings
type KubernetesConfig struct {
	InCluster        bool          `yaml:"in_cluster"`
	MetadataCacheTTL time.Duration `yaml:"metadata_cache_ttl"`
	WatchInterval    time.Duration `yaml:"watch_interval"`
}

// RulesConfig defines rule engine settings
// ANCHOR: Rule loading configuration - Phase 3.1 Week 3
// Supports loading rules from file, ConfigMap, or hardcoded defaults
type RulesConfig struct {
	FilePath  string `yaml:"file_path"` // Path to YAML rules file (e.g., /etc/elf-owl/rules.yaml)
	ConfigMap struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"config_map"`
	EvalTimeout   time.Duration `yaml:"eval_timeout"`
	LogViolations bool          `yaml:"log_violations"`
}

// EnrichmentConfig defines event enrichment settings
type EnrichmentConfig struct {
	KubernetesMetadata bool          `yaml:"kubernetes_metadata"`
	MetadataCacheSize  int           `yaml:"metadata_cache_size"`
	MetadataCacheTTL   time.Duration `yaml:"metadata_cache_ttl"`
}

// EvidenceConfig defines evidence processing settings
type EvidenceConfig struct {
	Signing    SigningConfig    `yaml:"signing"`
	Encryption EncryptionConfig `yaml:"encryption"`
}

// SigningConfig defines HMAC signing settings
type SigningConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Algorithm string `yaml:"algorithm"`
}

// EncryptionConfig defines AES encryption settings
type EncryptionConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Algorithm string `yaml:"algorithm"`
}

// OWLConfig defines Owl SaaS API settings
type OWLConfig struct {
	Endpoint string             `yaml:"endpoint"`
	Auth     AuthConfig         `yaml:"auth"`
	Push     PushConfig         `yaml:"push"`
	Retry    config.RetryConfig `yaml:"retry"`
	TLS      TLSConfig          `yaml:"tls"`
}

// AuthConfig defines authentication settings
type AuthConfig struct {
	Method    string `yaml:"method"`
	TokenPath string `yaml:"token_path"`
}

// PushConfig defines push settings
type PushConfig struct {
	BatchSize    int           `yaml:"batch_size"`
	BatchTimeout time.Duration `yaml:"batch_timeout"`
	Enabled      bool          `yaml:"enabled"`
	DryRun       bool          `yaml:"dry_run"`
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Verify         bool   `yaml:"verify"`
	CACertPath     string `yaml:"ca_cert_path"`
	ClientCertPath string `yaml:"client_cert_path"`
	ClientKeyPath  string `yaml:"client_key_path"`
}

// MetricsConfig defines Prometheus metrics settings
type MetricsConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_address"`
	Path          string `yaml:"path"`
}

// HealthConfig defines health check settings
type HealthConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_address"`
	Path          string `yaml:"path"`
}

// LoadConfig loads configuration from YAML and environment variables
func LoadConfig() (*Config, error) {
	// Set configuration file paths
	configPaths := []string{
		"./config/elf-owl.yaml",
		"/etc/elf-owl/elf-owl.yaml",
		os.ExpandEnv("$HOME/.config/elf-owl/elf-owl.yaml"),
	}

	var config *Config
	var found bool

	// Try to find and load config file
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			configData, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
			}

			if err := yaml.Unmarshal(configData, &config); err != nil {
				return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
			}

			found = true
			break
		}
	}

	// If no config file found, use defaults
	if !found {
		config = DefaultConfig()
	}

	// Override with environment variables
	config.applyEnvironmentOverrides()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// applyEnvironmentOverrides applies environment variable overrides to config
func (c *Config) applyEnvironmentOverrides() {
	if clusterID := os.Getenv("OWL_CLUSTER_ID"); clusterID != "" {
		c.Agent.ClusterID = clusterID
	}

	if nodeName := os.Getenv("OWL_NODE_NAME"); nodeName != "" {
		c.Agent.NodeName = nodeName
	}

	if endpoint := os.Getenv("OWL_API_ENDPOINT"); endpoint != "" {
		c.Agent.OWL.Endpoint = endpoint
	}

	if logLevel := os.Getenv("OWL_LOG_LEVEL"); logLevel != "" {
		c.Agent.Logging.Level = logLevel
	}

	// ANCHOR: Kubernetes mode override via env - Feature: VM/local testing - Mar 23, 2026
	// Allows start scripts to force out-of-cluster client mode when a kubeconfig is provided.
	if inCluster := os.Getenv("OWL_K8S_IN_CLUSTER"); inCluster != "" {
		if parsed, err := strconv.ParseBool(inCluster); err == nil {
			c.Agent.Kubernetes.InCluster = parsed
		}
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Agent.ClusterID == "" {
		return fmt.Errorf("cluster_id is required")
	}

	if c.Agent.NodeName == "" {
		c.Agent.NodeName = os.Getenv("HOSTNAME")
	}

	if c.Agent.NodeName == "" {
		return fmt.Errorf("node_name is required or HOSTNAME environment variable must be set")
	}

	if c.Agent.OWL.Endpoint == "" {
		return fmt.Errorf("owl_api.endpoint is required")
	}

	if c.Agent.OWL.Auth.TokenPath == "" {
		c.Agent.OWL.Auth.TokenPath = "/var/run/secrets/owl-jwt-token"
	}

	return nil
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	hostname, _ := os.Hostname()

	return &Config{
		Agent: AgentConfig{
			ClusterID: "default",
			NodeName:  hostname,
			Logging: LoggingConfig{
				Level:  "info",
				Format: "json",
				Output: "stdout",
			},
			// ANCHOR: eBPF Configuration Defaults - Phase 3: Migration Complete - Dec 27, 2025
			// Now enabled by default with all monitors active (goBPF has been completely removed)
			EBPF: EBPFConfig{
				Enabled: true,
				Process: EBPFMonitorConfig{
					Enabled:    true,
					BufferSize: 8192,
					Timeout:    5 * time.Second,
				},
				Network: EBPFMonitorConfig{
					Enabled:    true,
					BufferSize: 8192,
					Timeout:    5 * time.Second,
				},
				DNS: EBPFMonitorConfig{
					Enabled:    true,
					BufferSize: 4096,
					Timeout:    5 * time.Second,
				},
				File: EBPFMonitorConfig{
					Enabled:    true,
					BufferSize: 8192,
					Timeout:    5 * time.Second,
				},
				Capability: EBPFMonitorConfig{
					Enabled:    true,
					BufferSize: 4096,
					Timeout:    5 * time.Second,
				},
				PerfBuffer: PerfBufferConfig{
					Enabled:     true,
					PageCount:   64,
					LostHandler: true,
				},
				RingBuffer: RingBufferConfig{
					Enabled: false,
					Size:    65536,
				},
			},
			Kubernetes: KubernetesConfig{
				InCluster:        true,
				MetadataCacheTTL: 5 * time.Minute,
				// ANCHOR: Disable informer resync by default - Perf: reduce compliance storms - Mar 22, 2026
				// Resyncs can generate full-cluster compliance event storms; keep disabled
				// unless operators explicitly configure a resync interval.
				WatchInterval: 0,
			},
			Rules: RulesConfig{
				ConfigMap: struct {
					Name      string `yaml:"name"`
					Namespace string `yaml:"namespace"`
				}{
					Name:      "elf-owl-rules",
					Namespace: "elf-owl-system",
				},
				EvalTimeout:   5 * time.Second,
				LogViolations: true,
			},
			Enrichment: EnrichmentConfig{
				KubernetesMetadata: true,
				MetadataCacheSize:  10000,
				MetadataCacheTTL:   1 * time.Minute,
			},
			Evidence: EvidenceConfig{
				Signing: SigningConfig{
					Enabled:   true,
					Algorithm: "HMAC-SHA256",
				},
				Encryption: EncryptionConfig{
					Enabled:   true,
					Algorithm: "AES-256-GCM",
				},
			},
			OWL: OWLConfig{
				Endpoint: "https://owl-saas.example.com",
				Auth: AuthConfig{
					Method:    "jwt",
					TokenPath: "/var/run/secrets/owl-jwt-token",
				},
				Push: PushConfig{
					BatchSize:    100,
					BatchTimeout: 30 * time.Second,
					Enabled:      true,
					DryRun:       false,
				},
				Retry: config.RetryConfig{
					MaxRetries:        10,
					InitialBackoff:    1 * time.Second,
					MaxBackoff:        60 * time.Second,
					BackoffMultiplier: 2.0,
				},
				TLS: TLSConfig{
					Enabled:    true,
					Verify:     true,
					CACertPath: "/etc/elf-owl/ca.crt",
				},
			},
			Metrics: MetricsConfig{
				Enabled:       true,
				ListenAddress: ":9090",
				Path:          "/metrics",
			},
			Health: HealthConfig{
				Enabled:       true,
				ListenAddress: ":9091",
				Path:          "/health",
			},
		},
	}
}
