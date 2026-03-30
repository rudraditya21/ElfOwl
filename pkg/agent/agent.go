// ANCHOR: Core agent orchestrator - Dec 26, 2025
// Main coordinator that uses cilium/ebpf security monitors
// Migrated from goBPF to cilium/ebpf - Dec 27, 2025
// Orchestrates event pipeline: cilium/ebpf → enrichment → rules → evidence → push

package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	// ANCHOR: cilium/ebpf monitors for production-grade eBPF support - Dec 27, 2025
	// Provides better performance, maintenance, and ecosystem integration than goBPF
	"github.com/udyansh/elf-owl/pkg/ebpf"

	"github.com/udyansh/elf-owl/pkg/api"
	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/evidence"
	"github.com/udyansh/elf-owl/pkg/kubernetes"
	"github.com/udyansh/elf-owl/pkg/logger"
	"github.com/udyansh/elf-owl/pkg/metrics"
	"github.com/udyansh/elf-owl/pkg/rules"
)

// EnrichmentProvider defines the enricher methods used by agent handlers.
type EnrichmentProvider interface {
	EnrichProcessEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error)
	EnrichNetworkEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error)
	EnrichDNSEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error)
	EnrichFileEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error)
	EnrichCapabilityEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error)
}

// MetricsRecorder defines metrics methods used by the agent.
type MetricsRecorder interface {
	RecordEventProcessed()
	RecordViolationsFound(n int)
	RecordEnrichmentError()
	RecordHostEventDiscarded()
	RecordK8sLookupFailedDiscarded()
	SetEventsBuffered(count int)
}

// Agent is the main compliance observer agent
type Agent struct {
	Config *Config
	Logger *zap.Logger

	// ===== cilium/ebpf Security Monitors (Phase 3 Migration) =====
	ProcessMonitor    *ebpf.ProcessMonitor
	NetworkMonitor    *ebpf.NetworkMonitor
	DNSMonitor        *ebpf.DNSMonitor
	FileMonitor       *ebpf.FileMonitor
	CapabilityMonitor *ebpf.CapabilityMonitor

	// ===== Owl-Specific Components =====
	K8sClient   *kubernetes.Client
	RuleEngine  *rules.Engine
	Enricher    EnrichmentProvider
	Signer      *evidence.Signer
	Cipher      *evidence.Cipher
	APIClient   *api.Client
	EventBuffer *evidence.Buffer
	ruleMu      sync.RWMutex

	// Metrics
	MetricsRegistry MetricsRecorder

	// Control channels
	done       chan struct{}
	eventsChan chan interface{}
	startTime  time.Time

	// ANCHOR: Mutex-protected counters for goroutine safety - Dec 26, 2025
	// Multiple event handler goroutines (process, network, file, capability) access
	// eventsProcessed and violationsFound concurrently. Mutex ensures atomic increments.
	metricsMutex    sync.Mutex
	eventsProcessed int64
	violationsFound int64
}

// HealthStatus represents the agent's health status
type HealthStatus struct {
	AgentVersion     string          `json:"agent_version"`
	Uptime           time.Duration   `json:"uptime"`
	Monitors         map[string]bool `json:"monitors"`
	EventsProcessed  int64           `json:"events_processed"`
	ViolationsFound  int64           `json:"violations_found"`
	LastPushTime     time.Time       `json:"last_push_time"`
	PushFailureCount int64           `json:"push_failure_count"`
	Status           string          `json:"status"`
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

	// ANCHOR: Defer monitor creation to Start() - Fix: placeholder ProgramSet lifecycle fragility - Mar 29, 2026
	// Monitor instances are now created only after LoadProgramsWithOptions succeeds so
	// partially initialized placeholder monitors are not kept on the agent instance.

	// ANCHOR: Optional Kubernetes client bootstrap - Feature: monitor-only no-k8s mode - Mar 28, 2026
	// When kubernetes_metadata is disabled, skip Kubernetes client creation entirely.
	var k8sClient *kubernetes.Client
	if config.Agent.Enrichment.KubernetesMetadata {
		k8sClient, err = kubernetes.NewClient(config.Agent.Kubernetes.InCluster)
		if err != nil {
			return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		agent.K8sClient = k8sClient
		agent.Logger.Info("kubernetes client initialized")
	} else {
		agent.K8sClient = nil
		agent.Logger.Warn("kubernetes metadata enrichment disabled; running without Kubernetes client",
			zap.Bool("kubernetes_only", config.Agent.Enrichment.KubernetesOnly))
	}

	// Initialize rule engine with configurable rule source
	// ANCHOR: Rule engine initialization with file and ConfigMap support - Phase 3.2 Week 3
	// Supports loading rules from YAML file, Kubernetes ConfigMap, or hardcoded defaults
	// Fallback chain: file (if configured) → ConfigMap (if configured) → hardcoded CISControls
	engineConfig := &rules.EngineConfig{
		RuleFilePath:       config.Agent.Rules.FilePath,
		ConfigMapName:      config.Agent.Rules.ConfigMap.Name,
		ConfigMapNamespace: config.Agent.Rules.ConfigMap.Namespace,
		Ctx:                context.Background(),
	}
	if k8sClient != nil {
		// Pass K8s client for ConfigMap rule loading when available.
		engineConfig.K8sClientset = k8sClient.GetClientset()
	}
	ruleEngine, err := rules.NewEngineWithConfig(engineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule engine: %w", err)
	}
	agent.setRuleEngine(ruleEngine)

	// Log which rule source was used
	if config.Agent.Rules.FilePath != "" {
		agent.Logger.Info("rule engine initialized with file",
			zap.String("file", config.Agent.Rules.FilePath))
	} else if config.Agent.Rules.ConfigMap.Name != "" {
		agent.Logger.Info("rule engine initialized with ConfigMap",
			zap.String("configmap", config.Agent.Rules.ConfigMap.Name),
			zap.String("namespace", config.Agent.Rules.ConfigMap.Namespace))
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

	// ANCHOR: Build TLS config for Owl API client - Findings Note fix - Feb 18, 2026
	// WHY: TLSConfig fields (CACertPath, client cert/key, InsecureSkipVerify) were
	//      parsed from YAML but never applied to the HTTP client. All pushes used
	//      the default system TLS settings regardless of operator configuration.
	// WHAT: Call api.BuildTLSConfig with the operator's TLS settings to produce
	//       a *tls.Config that resty applies to every outbound request.
	// HOW: api.BuildTLSConfig reads cert files from disk and builds *tls.Config;
	//      returns nil when TLS is disabled so resty uses system defaults.
	tlsCfg, err := api.BuildTLSConfig(
		config.Agent.OWL.TLS.Enabled,
		config.Agent.OWL.TLS.Verify,
		config.Agent.OWL.TLS.CACertPath,
		config.Agent.OWL.TLS.ClientCertPath,
		config.Agent.OWL.TLS.ClientKeyPath,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	// Initialize Owl API client
	apiClient, err := api.NewClient(
		config.Agent.OWL.Endpoint,
		config.Agent.ClusterID,
		config.Agent.NodeName,
		agent.getJWTToken(),
		agent.Signer,
		agent.Cipher,
		tlsCfg,
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

	if a.Config.Agent.EBPF.Enabled {
		// ANCHOR: Load eBPF programs before starting monitors - Feature: kernel attach - Mar 23, 2026
		// Replace placeholder ProgramSets with real kernel-attached programs and readers.
		loadOpts := ebpf.LoadOptions{
			Process: ebpf.ProgramConfig{
				Enabled:    a.Config.Agent.EBPF.Process.Enabled,
				BufferSize: a.Config.Agent.EBPF.Process.BufferSize,
				Timeout:    a.Config.Agent.EBPF.Process.Timeout,
			},
			Network: ebpf.ProgramConfig{
				Enabled:    a.Config.Agent.EBPF.Network.Enabled,
				BufferSize: a.Config.Agent.EBPF.Network.BufferSize,
				Timeout:    a.Config.Agent.EBPF.Network.Timeout,
			},
			File: ebpf.ProgramConfig{
				Enabled:    a.Config.Agent.EBPF.File.Enabled,
				BufferSize: a.Config.Agent.EBPF.File.BufferSize,
				Timeout:    a.Config.Agent.EBPF.File.Timeout,
			},
			Capability: ebpf.ProgramConfig{
				Enabled:    a.Config.Agent.EBPF.Capability.Enabled,
				BufferSize: a.Config.Agent.EBPF.Capability.BufferSize,
				Timeout:    a.Config.Agent.EBPF.Capability.Timeout,
			},
			DNS: ebpf.ProgramConfig{
				Enabled:    a.Config.Agent.EBPF.DNS.Enabled,
				BufferSize: a.Config.Agent.EBPF.DNS.BufferSize,
				Timeout:    a.Config.Agent.EBPF.DNS.Timeout,
			},
			PerfBuffer: ebpf.PerfBufferOptions{
				Enabled:     a.Config.Agent.EBPF.PerfBuffer.Enabled,
				PageCount:   a.Config.Agent.EBPF.PerfBuffer.PageCount,
				LostHandler: a.Config.Agent.EBPF.PerfBuffer.LostHandler,
			},
			RingBuffer: ebpf.RingBufferOptions{
				Enabled: a.Config.Agent.EBPF.RingBuffer.Enabled,
				Size:    a.Config.Agent.EBPF.RingBuffer.Size,
			},
			KernelBTFPath: a.Config.Agent.EBPF.KernelBTFPath,
		}

		collection, err := ebpf.LoadProgramsWithOptions(a.Logger, loadOpts)
		if err != nil {
			return fmt.Errorf("failed to load eBPF programs: %w", err)
		}

		if a.Config.Agent.EBPF.Process.Enabled && collection.Process != nil {
			a.ProcessMonitor = ebpf.NewProcessMonitor(collection.Process, a.Logger)
		}
		if a.Config.Agent.EBPF.Network.Enabled && collection.Network != nil {
			a.NetworkMonitor = ebpf.NewNetworkMonitor(collection.Network, a.Logger)
		}
		if a.Config.Agent.EBPF.DNS.Enabled && collection.DNS != nil {
			a.DNSMonitor = ebpf.NewDNSMonitor(collection.DNS, a.Logger)
		}
		if a.Config.Agent.EBPF.File.Enabled && collection.File != nil {
			a.FileMonitor = ebpf.NewFileMonitor(collection.File, a.Logger)
		}
		if a.Config.Agent.EBPF.Capability.Enabled && collection.Capability != nil {
			a.CapabilityMonitor = ebpf.NewCapabilityMonitor(collection.Capability, a.Logger)
		}
	}

	// ANCHOR: Start all cilium/ebpf monitors with context - Dec 27, 2025
	// Each monitor manages its own lifecycle via context cancellation
	if a.ProcessMonitor != nil {
		if err := a.ProcessMonitor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start process monitor: %w", err)
		}
		a.Logger.Info("process monitor started")
	}

	if a.NetworkMonitor != nil {
		if err := a.NetworkMonitor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start network monitor: %w", err)
		}
		a.Logger.Info("network monitor started")
	}

	if a.DNSMonitor != nil {
		if err := a.DNSMonitor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start DNS monitor: %w", err)
		}
		a.Logger.Info("DNS monitor started")
	}

	if a.FileMonitor != nil {
		if err := a.FileMonitor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start file monitor: %w", err)
		}
		a.Logger.Info("file monitor started")
	}

	if a.CapabilityMonitor != nil {
		if err := a.CapabilityMonitor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start capability monitor: %w", err)
		}
		a.Logger.Info("capability monitor started")
	}

	// Launch event handlers for each cilium/ebpf monitor
	go a.handleProcessEvents(ctx)
	go a.handleNetworkEvents(ctx)
	go a.handleDNSEvents(ctx)
	go a.handleFileEvents(ctx)
	go a.handleCapabilityEvents(ctx)

	// ANCHOR: Start K8s compliance watchers - Feature: pod_spec_check/network_policy_check - Mar 22, 2026
	// Watches K8s API objects and emits compliance events for rules that are not
	// driven by eBPF runtime telemetry (e.g., pod_spec_check, network_policy_check).
	if a.K8sClient != nil {
		go a.startComplianceWatchers(ctx)
	}
	go a.watchRuleUpdates(ctx)

	// ANCHOR: Respect owl_api.push.enabled - Bugfix: prevent unintended push loop - Mar 22, 2026
	// Only start the push goroutine when explicitly enabled in config.
	if a.Config.Agent.OWL.Push.Enabled {
		go a.pushEvents(ctx)
	}

	// Launch periodic metrics collector
	go a.collectMetrics(ctx)

	a.Logger.Info("agent started successfully")
	return nil
}

func (a *Agent) handleRuntimeEvent(
	ctx context.Context,
	rawEnriched *enrichment.EnrichedEvent,
	enrichFn func(context.Context, interface{}) (*enrichment.EnrichedEvent, error),
	hostDiscardMsg string,
	hostProcessMsg string,
	apiDiscardMsg string,
	apiFallbackMsg string,
	logViolationDetails bool,
) {
	if rawEnriched == nil {
		return
	}

	enrichedEvent, err := enrichFn(ctx, rawEnriched.RawEvent)
	if err != nil {
		// ANCHOR: Discard host events - Filter: K8s-native compliance - Mar 24, 2026
		// ErrNoKubernetesContext = PID has no pod association.
		// Honour kubernetes_only config: discard (true) or fall through to partial (false).
		if errors.Is(err, enrichment.ErrNoKubernetesContext) {
			if a.Config.Agent.Enrichment.KubernetesOnly {
				a.Logger.Debug(hostDiscardMsg)
				a.MetricsRegistry.RecordHostEventDiscarded()
				return
			}
			// kubernetes_only=false: process host event with non-K8s enrichment
			a.Logger.Debug(hostProcessMsg)
			if enrichedEvent == nil {
				enrichedEvent = rawEnriched
			}
		} else {
			// ANCHOR: Fail-closed on K8s lookup errors - Fix PR-23 HIGH #2 - Mar 25, 2026
			// During K8s API outage/throttling/RBAC failure, pod lookup errors must not
			// bypass kubernetes_only filtering — discard to prevent false positives.
			a.MetricsRegistry.RecordEnrichmentError()
			if a.Config.Agent.Enrichment.KubernetesOnly {
				a.Logger.Debug(apiDiscardMsg, zap.Error(err))
				// ANCHOR: K8s lookup fail-closed discard metric - Fix PR-23 #7 - Mar 26, 2026
				// Record separately from host events to distinguish API failures from true host events.
				a.MetricsRegistry.RecordK8sLookupFailedDiscarded()
				return
			}
			a.Logger.Debug(apiFallbackMsg, zap.Error(err))
			// Fall back to partially-enriched event from monitor
			enrichedEvent = rawEnriched
		}
	}

	ruleEngine := a.getRuleEngine()
	if ruleEngine == nil {
		return
	}
	violations := ruleEngine.Match(enrichedEvent)
	if len(violations) > 0 {
		a.metricsMutex.Lock()
		a.violationsFound += int64(len(violations))
		a.metricsMutex.Unlock()
		// ANCHOR: Count every violation - Medium finding fix - Feb 18, 2026
		// WHY: Previously called RecordViolationFound() once per event, undercounting
		//      when multiple rules matched the same event.
		a.MetricsRegistry.RecordViolationsFound(len(violations))
		if logViolationDetails {
			for _, violation := range violations {
				a.Logger.Info("CIS violation detected",
					zap.String("control", violation.ControlID),
					zap.String("severity", violation.Severity),
					zap.String("pod", violation.Pod.PodName),
				)
			}
		}
	}

	// Queue for evidence processing
	a.EventBuffer.Enqueue(enrichedEvent, violations)
	a.metricsMutex.Lock()
	a.eventsProcessed++
	a.metricsMutex.Unlock()
	a.MetricsRegistry.RecordEventProcessed()
}

func (a *Agent) handleProcessEvent(ctx context.Context, rawEnriched *enrichment.EnrichedEvent) {
	// ANCHOR: Wire enrichment pipeline for process events - Feb 18, 2026
	// WHY: Monitors only populate event-specific context (ProcessContext).
	//      K8s metadata (pod name, namespace, SA, labels) and container
	//      context are added here by the Enricher via K8s API lookup.
	// WHAT: Call EnrichProcessEvent with the raw eBPF event to get a fully
	//       populated EnrichedEvent including K8s and container context.
	// HOW: Pass rawEvent interface{} to avoid circular imports; enricher
	//      uses reflection to extract fields from the concrete event struct.
	a.handleRuntimeEvent(
		ctx,
		rawEnriched,
		a.Enricher.EnrichProcessEvent,
		"discarded host process event: no pod context",
		"processing host process event (kubernetes_only disabled)",
		"discarded process event: K8s lookup failed and kubernetes_only=true",
		"process event enrichment failed, using partial event",
		true,
	)
}

func (a *Agent) handleNetworkEvent(ctx context.Context, rawEnriched *enrichment.EnrichedEvent) {
	// ANCHOR: Wire enrichment pipeline for network events - Feb 18, 2026
	// WHY: Network monitor only fills NetworkContext; K8s/container metadata added here.
	// WHAT: Enrich raw network event with pod metadata and network policy context.
	// HOW: EnrichNetworkEvent queries K8s API using container ID from /proc cgroup.
	a.handleRuntimeEvent(
		ctx,
		rawEnriched,
		a.Enricher.EnrichNetworkEvent,
		"discarded host network event: no pod context",
		"processing host network event (kubernetes_only disabled)",
		"discarded network event: K8s lookup failed and kubernetes_only=true",
		"network event enrichment failed, using partial event",
		false,
	)
}

func (a *Agent) handleDNSEvent(ctx context.Context, rawEnriched *enrichment.EnrichedEvent) {
	// ANCHOR: Wire enrichment pipeline for DNS events - Feb 18, 2026
	// WHY: DNS monitor only fills DNSContext; K8s/container metadata added here.
	// WHAT: Enrich raw DNS event with pod metadata for compliance correlation.
	// HOW: EnrichDNSEvent uses container ID from /proc to look up pod in K8s API.
	a.handleRuntimeEvent(
		ctx,
		rawEnriched,
		a.Enricher.EnrichDNSEvent,
		"discarded host DNS event: no pod context",
		"processing host DNS event (kubernetes_only disabled)",
		"discarded DNS event: K8s lookup failed and kubernetes_only=true",
		"DNS event enrichment failed, using partial event",
		false,
	)
}

func (a *Agent) handleFileEvent(ctx context.Context, rawEnriched *enrichment.EnrichedEvent) {
	// ANCHOR: Wire enrichment pipeline for file events - Feb 18, 2026
	// WHY: File monitor only fills FileContext; K8s/container metadata added here.
	// WHAT: Enrich raw file event with pod metadata and read-only FS check.
	// HOW: EnrichFileEvent checks container security context for ReadOnlyFilesystem.
	a.handleRuntimeEvent(
		ctx,
		rawEnriched,
		a.Enricher.EnrichFileEvent,
		"discarded host file event: no pod context",
		"processing host file event (kubernetes_only disabled)",
		"discarded file event: K8s lookup failed and kubernetes_only=true",
		"file event enrichment failed, using partial event",
		false,
	)
}

func (a *Agent) handleCapabilityEvent(ctx context.Context, rawEnriched *enrichment.EnrichedEvent) {
	// ANCHOR: Wire enrichment pipeline for capability events - Feb 18, 2026
	// WHY: Capability monitor only fills CapabilityContext; K8s context added here.
	// WHAT: Enrich raw capability event with pod metadata and privilege escalation check.
	// HOW: EnrichCapabilityEvent maps raw capability ID to Linux capability name.
	a.handleRuntimeEvent(
		ctx,
		rawEnriched,
		a.Enricher.EnrichCapabilityEvent,
		"discarded host capability event: no pod context",
		"processing host capability event (kubernetes_only disabled)",
		"discarded capability event: K8s lookup failed and kubernetes_only=true",
		"capability event enrichment failed, using partial event",
		false,
	)
}

// handleProcessEvents handles cilium/ebpf process monitor events
func (a *Agent) handleProcessEvents(ctx context.Context) {
	if a.ProcessMonitor == nil {
		return
	}

	eventChan := a.ProcessMonitor.EventChan()
	for {
		select {
		case rawEnriched := <-eventChan:
			a.handleProcessEvent(ctx, rawEnriched)

		case <-a.done:
			return

		case <-ctx.Done():
			return
		}
	}
}

// handleNetworkEvents handles cilium/ebpf network monitor events
func (a *Agent) handleNetworkEvents(ctx context.Context) {
	if a.NetworkMonitor == nil {
		return
	}

	eventChan := a.NetworkMonitor.EventChan()
	for {
		select {
		case rawEnriched := <-eventChan:
			a.handleNetworkEvent(ctx, rawEnriched)

		case <-a.done:
			return

		case <-ctx.Done():
			return
		}
	}
}

// handleDNSEvents handles cilium/ebpf DNS monitor events
// ANCHOR: DNS event handler with enrichment pipeline - Dec 27, 2025 / Feb 18, 2026
// DNS monitor fully integrated; K8s context added via enricher.
func (a *Agent) handleDNSEvents(ctx context.Context) {
	if a.DNSMonitor == nil {
		return
	}

	eventChan := a.DNSMonitor.EventChan()
	for {
		select {
		case rawEnriched := <-eventChan:
			a.handleDNSEvent(ctx, rawEnriched)

		case <-a.done:
			return

		case <-ctx.Done():
			return
		}
	}
}

// handleFileEvents handles cilium/ebpf file monitor events
func (a *Agent) handleFileEvents(ctx context.Context) {
	if a.FileMonitor == nil {
		return
	}

	eventChan := a.FileMonitor.EventChan()
	for {
		select {
		case rawEnriched := <-eventChan:
			a.handleFileEvent(ctx, rawEnriched)

		case <-a.done:
			return

		case <-ctx.Done():
			return
		}
	}
}

// handleCapabilityEvents handles cilium/ebpf capability monitor events
func (a *Agent) handleCapabilityEvents(ctx context.Context) {
	if a.CapabilityMonitor == nil {
		return
	}

	eventChan := a.CapabilityMonitor.EventChan()
	for {
		select {
		case rawEnriched := <-eventChan:
			a.handleCapabilityEvent(ctx, rawEnriched)

		case <-a.done:
			return

		case <-ctx.Done():
			return
		}
	}
}

// handleComplianceEvent processes non-eBPF compliance events (pod specs, network policies).
// ANCHOR: Shared compliance event handler - Feature: K8s API compliance signals - Mar 22, 2026
// Keeps rule evaluation and buffering consistent across eBPF and K8s API event sources.
func (a *Agent) handleComplianceEvent(ctx context.Context, event *enrichment.EnrichedEvent) {
	if event == nil {
		return
	}

	ruleEngine := a.getRuleEngine()
	if ruleEngine == nil {
		return
	}
	violations := ruleEngine.Match(event)
	if len(violations) > 0 {
		a.metricsMutex.Lock()
		a.violationsFound += int64(len(violations))
		a.metricsMutex.Unlock()
		a.MetricsRegistry.RecordViolationsFound(len(violations))
	}

	a.EventBuffer.Enqueue(event, violations)
	a.metricsMutex.Lock()
	a.eventsProcessed++
	a.metricsMutex.Unlock()
	a.MetricsRegistry.RecordEventProcessed()

	select {
	case <-ctx.Done():
		return
	default:
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

			// ANCHOR: Sync buffer gauge to Prometheus - Feb 18, 2026
			// WHY: Prometheus gauge needs periodic refresh since buffer count changes continuously.
			// WHAT: Update eventsBuffered gauge with current buffer count.
			a.MetricsRegistry.SetEventsBuffered(a.EventBuffer.Count())

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

const ruleReloadInterval = 30 * time.Second
const ruleReloadTimeout = 10 * time.Second

func (a *Agent) getRuleEngine() *rules.Engine {
	a.ruleMu.RLock()
	defer a.ruleMu.RUnlock()
	return a.RuleEngine
}

func (a *Agent) setRuleEngine(engine *rules.Engine) {
	a.ruleMu.Lock()
	defer a.ruleMu.Unlock()
	a.RuleEngine = engine
}

func ruleEngineSignature(engine *rules.Engine) string {
	if engine == nil {
		return ""
	}
	payload, err := json.Marshal(engine.Rules)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (a *Agent) ruleEngineConfig(ctx context.Context) *rules.EngineConfig {
	cfg := &rules.EngineConfig{
		RuleFilePath:       a.Config.Agent.Rules.FilePath,
		ConfigMapName:      a.Config.Agent.Rules.ConfigMap.Name,
		ConfigMapNamespace: a.Config.Agent.Rules.ConfigMap.Namespace,
		Ctx:                ctx,
	}
	if a.K8sClient != nil {
		cfg.K8sClientset = a.K8sClient.GetClientset()
	}
	return cfg
}

func (a *Agent) watchRuleUpdates(ctx context.Context) {
	if a.Config == nil {
		return
	}

	filePath := strings.TrimSpace(a.Config.Agent.Rules.FilePath)
	configMapName := strings.TrimSpace(a.Config.Agent.Rules.ConfigMap.Name)
	configMapNamespace := strings.TrimSpace(a.Config.Agent.Rules.ConfigMap.Namespace)
	if filePath == "" && (configMapName == "" || configMapNamespace == "") {
		return
	}

	ticker := time.NewTicker(ruleReloadInterval)
	defer ticker.Stop()

	currentSignature := ruleEngineSignature(a.getRuleEngine())

	for {
		select {
		case <-ticker.C:
			reloadCtx, cancel := context.WithTimeout(ctx, ruleReloadTimeout)
			engine, err := rules.NewEngineWithConfig(a.ruleEngineConfig(reloadCtx))
			cancel()
			if err != nil {
				a.Logger.Warn("rule reload failed", zap.Error(err))
				continue
			}

			nextSignature := ruleEngineSignature(engine)
			if nextSignature == "" || nextSignature == currentSignature {
				continue
			}

			a.setRuleEngine(engine)
			currentSignature = nextSignature
			a.Logger.Info("rules reloaded", zap.Int("rule_count", len(engine.Rules)))

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

	// ANCHOR: Close all cilium/ebpf monitors - Dec 27, 2025
	// Stop() method properly cleans up monitor resources
	if a.ProcessMonitor != nil {
		if err := a.ProcessMonitor.Stop(); err != nil {
			a.Logger.Error("failed to close process monitor", zap.Error(err))
			errs = append(errs, err)
		}
	}

	if a.NetworkMonitor != nil {
		if err := a.NetworkMonitor.Stop(); err != nil {
			a.Logger.Error("failed to close network monitor", zap.Error(err))
			errs = append(errs, err)
		}
	}

	if a.DNSMonitor != nil {
		if err := a.DNSMonitor.Stop(); err != nil {
			a.Logger.Error("failed to close DNS monitor", zap.Error(err))
			errs = append(errs, err)
		}
	}

	if a.FileMonitor != nil {
		if err := a.FileMonitor.Stop(); err != nil {
			a.Logger.Error("failed to close file monitor", zap.Error(err))
			errs = append(errs, err)
		}
	}

	if a.CapabilityMonitor != nil {
		if err := a.CapabilityMonitor.Stop(); err != nil {
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
			"process":    a.ProcessMonitor != nil,
			"network":    a.NetworkMonitor != nil,
			"dns":        a.DNSMonitor != nil, // DNS monitor now available via cilium/ebpf
			"file":       a.FileMonitor != nil,
			"capability": a.CapabilityMonitor != nil,
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

	// Generate an ephemeral key when no key is configured.
	key, err := generateEphemeralKey()
	if err != nil {
		a.Logger.Fatal("failed to generate ephemeral signing key", zap.Error(err))
	}
	a.Logger.Warn("using generated ephemeral signing key; configure ELF_OWL_SIGNING_KEY or /var/run/secrets/elf-owl-signing-key for stable identity")
	return key
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

	key, err := generateEphemeralKey()
	if err != nil {
		a.Logger.Fatal("failed to generate ephemeral encryption key", zap.Error(err))
	}
	a.Logger.Warn("using generated ephemeral encryption key; configure ELF_OWL_ENCRYPTION_KEY or /var/run/secrets/elf-owl-encryption-key for stable encryption")
	return key
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

func generateEphemeralKey() (string, error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(keyBytes), nil
}
