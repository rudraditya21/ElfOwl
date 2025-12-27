// ANCHOR: Core agent orchestrator - Dec 26, 2025
// Main coordinator that directly uses goBPF security monitors
// Orchestrates event pipeline: goBPF → enrichment → rules → evidence → push

package agent

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"

	// Direct goBPF imports (no wrapper layer)
	gobpfsecurity "github.com/udyansh/gobpf/security"

	"github.com/udyansh/elf-owl/pkg/api"
	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/evidence"
	"github.com/udyansh/elf-owl/pkg/kubernetes"
	"github.com/udyansh/elf-owl/pkg/logger"
	"github.com/udyansh/elf-owl/pkg/metrics"
	"github.com/udyansh/elf-owl/pkg/rules"
)

// Agent is the main compliance observer agent
type Agent struct {
	Config *Config
	Logger *zap.Logger

	// ===== goBPF Security Monitors (Direct Import) =====
	ProcessMonitor    *gobpfsecurity.ProcessMonitor
	NetworkMonitor    *gobpfsecurity.NetworkMonitor
	// DNSMonitor - Not yet available in goBPF security package, commented for Week 2
	FileMonitor       *gobpfsecurity.FileMonitor
	CapabilityMonitor *gobpfsecurity.CapabilityMonitor

	// ===== Owl-Specific Components =====
	K8sClient   *kubernetes.Client
	RuleEngine  *rules.Engine
	Enricher    *enrichment.Enricher
	Signer      *evidence.Signer
	Cipher      *evidence.Cipher
	APIClient   *api.Client
	EventBuffer *evidence.Buffer

	// Metrics
	MetricsRegistry *metrics.Registry

	// Control channels
	done               chan struct{}
	eventsChan         chan interface{}
	startTime          time.Time

	// ANCHOR: Mutex-protected counters for goroutine safety - Dec 26, 2025
	// Multiple event handler goroutines (process, network, file, capability) access
	// eventsProcessed and violationsFound concurrently. Mutex ensures atomic increments.
	metricsMutex       sync.Mutex
	eventsProcessed    int64
	violationsFound    int64
}

// HealthStatus represents the agent's health status
type HealthStatus struct {
	AgentVersion     string            `json:"agent_version"`
	Uptime           time.Duration     `json:"uptime"`
	Monitors         map[string]bool   `json:"monitors"`
	EventsProcessed  int64             `json:"events_processed"`
	ViolationsFound  int64             `json:"violations_found"`
	LastPushTime     time.Time         `json:"last_push_time"`
	PushFailureCount int64             `json:"push_failure_count"`
	Status           string            `json:"status"`
}

// NewAgent creates a new agent instance with all components
func NewAgent(config *Config) (*Agent, error) {
	// Initialize logger
	zapLogger, err := logger.NewLogger(config.Agent.Logging.Level)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	agent := &Agent{
		Config:          config,
		Logger:          zapLogger,
		done:            make(chan struct{}),
		eventsChan:      make(chan interface{}, 1000),
		MetricsRegistry: metrics.NewRegistry(),
		startTime:       time.Now(),
	}

	// Initialize goBPF monitors if enabled
	if config.Agent.GoBPF.Process.Enabled {
		opts := gobpfsecurity.DefaultProcessMonitorOptions()
		processMonitor, err := gobpfsecurity.NewProcessMonitor(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create process monitor: %w", err)
		}
		agent.ProcessMonitor = processMonitor
		agent.Logger.Info("process monitor initialized")
	}

	if config.Agent.GoBPF.Network.Enabled {
		opts := gobpfsecurity.DefaultNetworkMonitorOptions()
		networkMonitor, err := gobpfsecurity.NewNetworkMonitor(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create network monitor: %w", err)
		}
		agent.NetworkMonitor = networkMonitor
		agent.Logger.Info("network monitor initialized")
	}

	// ANCHOR: DNS monitor initialization skipped - Dec 26, 2025
	// DNSMonitor not yet available in goBPF security package
	// Will be enabled in Week 2 when goBPF integration is complete
	/*
	if config.Agent.GoBPF.DNS.Enabled {
		opts := gobpfsecurity.DefaultDNSMonitorOptions()
		dnsMonitor, err := gobpfsecurity.NewDNSMonitor(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS monitor: %w", err)
		}
		agent.DNSMonitor = dnsMonitor
		agent.Logger.Info("DNS monitor initialized")
	}
	*/

	if config.Agent.GoBPF.File.Enabled {
		opts := gobpfsecurity.DefaultFileMonitorOptions()
		fileMonitor, err := gobpfsecurity.NewFileMonitor(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create file monitor: %w", err)
		}
		agent.FileMonitor = fileMonitor
		agent.Logger.Info("file monitor initialized")
	}

	if config.Agent.GoBPF.Capability.Enabled {
		opts := gobpfsecurity.DefaultCapabilityMonitorOptions()
		capMonitor, err := gobpfsecurity.NewCapabilityMonitor(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create capability monitor: %w", err)
		}
		agent.CapabilityMonitor = capMonitor
		agent.Logger.Info("capability monitor initialized")
	}

	// Initialize Kubernetes client
	k8sClient, err := kubernetes.NewClient(config.Agent.Kubernetes.InCluster)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	agent.K8sClient = k8sClient
	agent.Logger.Info("kubernetes client initialized")

	// Initialize rule engine with optional rule file path
	// ANCHOR: Rule engine initialization with configurable rule source - Phase 3.1 Week 3
	// Supports loading rules from YAML file, ConfigMap, or hardcoded defaults
	// Fallback chain: file (if configured) → ConfigMap (if configured) → hardcoded CISControls
	ruleEngine, err := rules.NewEngine(config.Agent.Rules.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule engine: %w", err)
	}
	agent.RuleEngine = ruleEngine
	if config.Agent.Rules.FilePath != "" {
		agent.Logger.Info("rule engine initialized with file",
			zap.String("file", config.Agent.Rules.FilePath))
	} else {
		agent.Logger.Info("rule engine initialized with default hardcoded rules")
	}

	// Initialize enricher
	enricher, err := enrichment.NewEnricher(agent.K8sClient, config.Agent.ClusterID, config.Agent.NodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to create enricher: %w", err)
	}
	agent.Enricher = enricher
	agent.Logger.Info("enricher initialized")

	// Initialize evidence signer and cipher
	signingKey := agent.getSigningKey()
	signer, err := evidence.NewSigner(signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}
	agent.Signer = signer

	encryptionKey := agent.getEncryptionKey()
	cipher, err := evidence.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	agent.Cipher = cipher
	agent.Logger.Info("evidence signer and cipher initialized")

	// Initialize event buffer
	agent.EventBuffer = evidence.NewBuffer(
		config.Agent.OWL.Push.BatchSize,
		config.Agent.OWL.Push.BatchTimeout,
	)
	agent.Logger.Info("event buffer initialized",
		zap.Int("batch_size", config.Agent.OWL.Push.BatchSize),
		zap.Duration("batch_timeout", config.Agent.OWL.Push.BatchTimeout),
	)

	// Initialize Owl API client
	apiClient, err := api.NewClient(
		config.Agent.OWL.Endpoint,
		config.Agent.ClusterID,
		config.Agent.NodeName,
		agent.getJWTToken(),
		agent.Signer,
		agent.Cipher,
		config.Agent.OWL.Retry,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}
	agent.APIClient = apiClient
	agent.Logger.Info("API client initialized",
		zap.String("endpoint", config.Agent.OWL.Endpoint),
	)

	return agent, nil
}

// Start starts the agent and all event handlers
func (a *Agent) Start(ctx context.Context) error {
	a.Logger.Info("starting agent",
		zap.String("clusterID", a.Config.Agent.ClusterID),
		zap.String("nodeName", a.Config.Agent.NodeName),
	)

	// Start all goBPF monitors
	if a.ProcessMonitor != nil {
		if err := a.ProcessMonitor.Start(); err != nil {
			return fmt.Errorf("failed to start process monitor: %w", err)
		}
		a.Logger.Info("process monitor started")
	}

	if a.NetworkMonitor != nil {
		if err := a.NetworkMonitor.Start(); err != nil {
			return fmt.Errorf("failed to start network monitor: %w", err)
		}
		a.Logger.Info("network monitor started")
	}

	// ANCHOR: DNS monitor start skipped - Dec 26, 2025
	// DNS monitor not available in goBPF security package
	/*
	if a.DNSMonitor != nil {
		if err := a.DNSMonitor.Start(); err != nil {
			return fmt.Errorf("failed to start DNS monitor: %w", err)
		}
		a.Logger.Info("DNS monitor started")
	}
	*/

	if a.FileMonitor != nil {
		if err := a.FileMonitor.Start(); err != nil {
			return fmt.Errorf("failed to start file monitor: %w", err)
		}
		a.Logger.Info("file monitor started")
	}

	if a.CapabilityMonitor != nil {
		if err := a.CapabilityMonitor.Start(); err != nil {
			return fmt.Errorf("failed to start capability monitor: %w", err)
		}
		a.Logger.Info("capability monitor started")
	}

	// Launch event handlers for each goBPF monitor
	go a.handleProcessEvents(ctx)
	go a.handleNetworkEvents(ctx)
	// go a.handleDNSEvents(ctx) // DNS monitor not available in goBPF yet
	go a.handleFileEvents(ctx)
	go a.handleCapabilityEvents(ctx)

	// Launch API push goroutine
	go a.pushEvents(ctx)

	// Launch periodic metrics collector
	go a.collectMetrics(ctx)

	a.Logger.Info("agent started successfully")
	return nil
}

// handleProcessEvents handles goBPF process monitor events
func (a *Agent) handleProcessEvents(ctx context.Context) {
	if a.ProcessMonitor == nil {
		return
	}

	for {
		select {
		case gobpfEvent := <-a.ProcessMonitor.Events():
			// Enrich with K8s metadata
			enrichedEvent, err := a.Enricher.EnrichProcessEvent(ctx, gobpfEvent)
			if err != nil {
				a.Logger.Debug("failed to enrich process event", zap.Error(err))
				continue
			}

			// Run through rule engine
			violations := a.RuleEngine.Match(enrichedEvent)
			if len(violations) > 0 {
				a.metricsMutex.Lock()
				a.violationsFound += int64(len(violations))
				a.metricsMutex.Unlock()
				for _, violation := range violations {
					a.Logger.Info("CIS violation detected",
						zap.String("control", violation.ControlID),
						zap.String("severity", violation.Severity),
						zap.String("pod", violation.Pod.PodName),
					)
				}
			}

			// Queue for evidence processing
			a.EventBuffer.Enqueue(enrichedEvent, violations)
			a.metricsMutex.Lock()
			a.eventsProcessed++
			a.metricsMutex.Unlock()

		case err := <-a.ProcessMonitor.Errors():
			a.Logger.Warn("process monitor error", zap.Error(err))

		case <-a.done:
			return
		}
	}
}

// handleNetworkEvents handles goBPF network monitor events
func (a *Agent) handleNetworkEvents(ctx context.Context) {
	if a.NetworkMonitor == nil {
		return
	}

	for {
		select {
		case gobpfEvent := <-a.NetworkMonitor.Events():
			enrichedEvent, err := a.Enricher.EnrichNetworkEvent(ctx, gobpfEvent)
			if err != nil {
				a.Logger.Debug("failed to enrich network event", zap.Error(err))
				continue
			}

			violations := a.RuleEngine.Match(enrichedEvent)
			if len(violations) > 0 {
				a.metricsMutex.Lock()
				a.violationsFound += int64(len(violations))
				a.metricsMutex.Unlock()
			}

			a.EventBuffer.Enqueue(enrichedEvent, violations)
			a.metricsMutex.Lock()
			a.eventsProcessed++
			a.metricsMutex.Unlock()

		case err := <-a.NetworkMonitor.Errors():
			a.Logger.Warn("network monitor error", zap.Error(err))

		case <-a.done:
			return
		}
	}
}

// handleDNSEvents handles goBPF DNS monitor events
// ANCHOR: DNS event handler skipped - Dec 26, 2025
// DNS monitor not available in goBPF security package
/*
func (a *Agent) handleDNSEvents(ctx context.Context) {
	if a.DNSMonitor == nil {
		return
	}

	for {
		select {
		case gobpfEvent := <-a.DNSMonitor.Events():
			enrichedEvent, err := a.Enricher.EnrichDNSEvent(ctx, gobpfEvent)
			if err != nil {
				a.Logger.Debug("failed to enrich DNS event", zap.Error(err))
				continue
			}

			violations := a.RuleEngine.Match(enrichedEvent)
			if len(violations) > 0 {
				a.violationsFound += int64(len(violations))
			}

			a.EventBuffer.Enqueue(enrichedEvent, violations)
			a.eventsProcessed++

		case err := <-a.DNSMonitor.Errors():
			a.Logger.Warn("DNS monitor error", zap.Error(err))

		case <-a.done:
			return
		}
	}
}
*/

// handleFileEvents handles goBPF file monitor events
func (a *Agent) handleFileEvents(ctx context.Context) {
	if a.FileMonitor == nil {
		return
	}

	for {
		select {
		case gobpfEvent := <-a.FileMonitor.Events():
			enrichedEvent, err := a.Enricher.EnrichFileEvent(ctx, gobpfEvent)
			if err != nil {
				a.Logger.Debug("failed to enrich file event", zap.Error(err))
				continue
			}

			violations := a.RuleEngine.Match(enrichedEvent)
			if len(violations) > 0 {
				a.metricsMutex.Lock()
				a.violationsFound += int64(len(violations))
				a.metricsMutex.Unlock()
			}

			a.EventBuffer.Enqueue(enrichedEvent, violations)
			a.metricsMutex.Lock()
			a.eventsProcessed++
			a.metricsMutex.Unlock()

		case err := <-a.FileMonitor.Errors():
			a.Logger.Warn("file monitor error", zap.Error(err))

		case <-a.done:
			return
		}
	}
}

// handleCapabilityEvents handles goBPF capability monitor events
func (a *Agent) handleCapabilityEvents(ctx context.Context) {
	if a.CapabilityMonitor == nil {
		return
	}

	for {
		select {
		case gobpfEvent := <-a.CapabilityMonitor.Events():
			enrichedEvent, err := a.Enricher.EnrichCapabilityEvent(ctx, &gobpfEvent)
			if err != nil {
				a.Logger.Debug("failed to enrich capability event", zap.Error(err))
				continue
			}

			violations := a.RuleEngine.Match(enrichedEvent)
			if len(violations) > 0 {
				a.metricsMutex.Lock()
				a.violationsFound += int64(len(violations))
				a.metricsMutex.Unlock()
			}

			a.EventBuffer.Enqueue(enrichedEvent, violations)
			a.metricsMutex.Lock()
			a.eventsProcessed++
			a.metricsMutex.Unlock()

		case err := <-a.CapabilityMonitor.Errors():
			a.Logger.Warn("capability monitor error", zap.Error(err))

		case <-a.done:
			return
		}
	}
}

// pushEvents periodically pushes buffered events to Owl SaaS
func (a *Agent) pushEvents(ctx context.Context) {
	ticker := time.NewTicker(a.Config.Agent.OWL.Push.BatchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if buffer is ready to flush
			if a.EventBuffer.IsFull() || a.EventBuffer.IsStale() {
				bufferedEvents := a.EventBuffer.Flush()
				if len(bufferedEvents) > 0 {
					if a.Config.Agent.OWL.Push.DryRun {
						a.Logger.Info("dry-run: would push events",
							zap.Int("count", len(bufferedEvents)),
						)
					} else {
						if err := a.APIClient.PushWithRetry(ctx, bufferedEvents); err != nil {
							a.Logger.Error("failed to push events", zap.Error(err))
						}
					}
				}
			}

		case <-a.done:
			// Final flush on shutdown
			bufferedEvents := a.EventBuffer.Flush()
			if len(bufferedEvents) > 0 {
				if err := a.APIClient.PushWithRetry(ctx, bufferedEvents); err != nil {
					a.Logger.Error("failed to push events on shutdown", zap.Error(err))
				}
			}
			return

		case <-ctx.Done():
			return
		}
	}
}

// collectMetrics periodically collects and logs metrics
func (a *Agent) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// ANCHOR: Mutex protection for metric reads - Dec 26, 2025
			// Lock while reading counters to prevent tearing reads from concurrent modifications
			a.metricsMutex.Lock()
			processed := a.eventsProcessed
			violations := a.violationsFound
			a.metricsMutex.Unlock()

			a.Logger.Debug("metrics",
				zap.Int64("events_processed", processed),
				zap.Int64("violations_found", violations),
			)

		case <-a.done:
			return

		case <-ctx.Done():
			return
		}
	}
}

// Stop gracefully stops the agent
func (a *Agent) Stop() error {
	a.Logger.Info("stopping agent")
	close(a.done)

	var errs []error

	// Close all goBPF monitors
	if a.ProcessMonitor != nil {
		if err := a.ProcessMonitor.Close(); err != nil {
			a.Logger.Error("failed to close process monitor", zap.Error(err))
			errs = append(errs, err)
		}
	}

	if a.NetworkMonitor != nil {
		if err := a.NetworkMonitor.Close(); err != nil {
			a.Logger.Error("failed to close network monitor", zap.Error(err))
			errs = append(errs, err)
		}
	}

	// ANCHOR: DNS monitor close skipped - Dec 26, 2025
	// DNS monitor not available in goBPF security package
	/*
	if a.DNSMonitor != nil {
		if err := a.DNSMonitor.Close(); err != nil {
			a.Logger.Error("failed to close DNS monitor", zap.Error(err))
			errs = append(errs, err)
		}
	}
	*/

	if a.FileMonitor != nil {
		if err := a.FileMonitor.Close(); err != nil {
			a.Logger.Error("failed to close file monitor", zap.Error(err))
			errs = append(errs, err)
		}
	}

	if a.CapabilityMonitor != nil {
		if err := a.CapabilityMonitor.Close(); err != nil {
			a.Logger.Error("failed to close capability monitor", zap.Error(err))
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}

	a.Logger.Info("agent stopped successfully")
	return nil
}

// Health returns the agent's current health status
func (a *Agent) Health() HealthStatus {
	// ANCHOR: Mutex protection for health status reads - Dec 26, 2025
	// Lock while reading eventsProcessed and violationsFound to ensure
	// they are not being modified by concurrent event handler goroutines
	a.metricsMutex.Lock()
	eventsProcessed := a.eventsProcessed
	violationsFound := a.violationsFound
	a.metricsMutex.Unlock()

	return HealthStatus{
		AgentVersion:     "0.1.0",
		Uptime:           time.Since(a.startTime),
		Status:           "healthy",
		EventsProcessed:  eventsProcessed,
		ViolationsFound:  violationsFound,
		LastPushTime:     a.APIClient.LastPushTime(),
		PushFailureCount: a.APIClient.FailureCount(),
		Monitors: map[string]bool{
			"process":     a.ProcessMonitor != nil,
			"network":     a.NetworkMonitor != nil,
			"dns":         false, // a.DNSMonitor != nil - DNS monitor not available in goBPF yet
			"file":        a.FileMonitor != nil,
			"capability":  a.CapabilityMonitor != nil,
		},
	}
}

// Helper methods for credential loading

func (a *Agent) getSigningKey() string {
	// Try environment variable first
	if key := os.Getenv("ELF_OWL_SIGNING_KEY"); key != "" {
		return key
	}

	// Try reading from secret file
	if data, err := os.ReadFile("/var/run/secrets/elf-owl-signing-key"); err == nil {
		return string(data)
	}

	// Return default (insecure - for development only)
	a.Logger.Warn("using default signing key - NOT SECURE")
	return "ZGVmYXVsdC1zaWduaW5nLWtleS0tLW5vdC1zZWN1cmUtZm9yLWRldmVsb3BtZW50LW9ubHk="
}

func (a *Agent) getEncryptionKey() string {
	// Try environment variable first
	if key := os.Getenv("ELF_OWL_ENCRYPTION_KEY"); key != "" {
		return key
	}

	// Try reading from secret file
	if data, err := os.ReadFile("/var/run/secrets/elf-owl-encryption-key"); err == nil {
		return string(data)
	}

	// ANCHOR: Default development encryption key - Dec 26, 2025
	// 32-byte key (256-bit) base64-encoded for AES-256-GCM
	// This decodes to exactly 32 bytes (verified: len(base64.StdEncoding.DecodeString(...)) == 32)
	// Pattern: 32 repetitions of 0x55, base64-encoded = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU="
	// This is intentionally insecure for development/testing only - NEVER use in production
	a.Logger.Warn("using default encryption key - NOT SECURE - development only")
	return "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU="
}

func (a *Agent) getJWTToken() string {
	// Try environment variable first
	if token := os.Getenv("OWL_JWT_TOKEN"); token != "" {
		return token
	}

	// Try reading from secret file (Kubernetes)
	if data, err := os.ReadFile(a.Config.Agent.OWL.Auth.TokenPath); err == nil {
		return string(data)
	}

	// No token found
	a.Logger.Warn("no JWT token found - API authentication will fail")
	return ""
}
