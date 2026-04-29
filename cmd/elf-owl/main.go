// ANCHOR: elf-owl agent entry point - Dec 26, 2025 / Feb 18, 2026
// Starts the compliance observer agent with cilium/ebpf integration.
// Reads configuration from YAML and environment variables.
// Initializes all components and runs the event processing pipeline.
// Serves /health (JSON health status) and /metrics (Prometheus) HTTP endpoints.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/agent"
	"github.com/udyansh/elf-owl/pkg/logger"
)

var (
	version   = "0.1.0"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	// Initialize logger first
	zapLogger, err := logger.NewLogger("info")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer zapLogger.Sync()

	zapLogger.Info("elf-owl agent starting",
		zap.String("version", version),
		zap.String("buildTime", buildTime),
		zap.String("gitCommit", gitCommit),
	)

	// Load configuration
	config, err := agent.LoadConfig()
	if err != nil {
		zapLogger.Fatal("failed to load configuration", zap.Error(err))
	}

	zapLogger.Debug("configuration loaded",
		zap.String("clusterID", config.Agent.ClusterID),
		zap.String("nodeName", config.Agent.NodeName),
	)

	// Create agent with all components
	agentInstance, err := agent.NewAgent(config)
	if err != nil {
		zapLogger.Fatal("failed to create agent", zap.Error(err))
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// Start agent
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agentInstance.Start(ctx); err != nil {
		zapLogger.Fatal("failed to start agent", zap.Error(err))
	}

	zapLogger.Info("agent started successfully",
		zap.String("endpoint", config.Agent.OWL.Endpoint),
		zap.Int("batchSize", config.Agent.OWL.Push.BatchSize),
	)

	// ANCHOR: Health HTTP server - Feb 18, 2026 / fixed Feb 18, 2026
	// WHY: HealthStatus was computed in-memory but never exposed; Kubernetes liveness
	//      and readiness probes, as well as operators, need an HTTP endpoint.
	// WHAT: Serve GET /health returning JSON-encoded agent.HealthStatus.
	// HOW: Dedicated net/http server on address and path from config (:9091/health
	//      by default via DefaultConfig()). No hardcoded fallbacks — they drifted
	//      from DefaultConfig() values (:8081/healthz vs :9091/health) and would
	//      silently override operator configuration if a field ever parsed as "".
	if config.Agent.Health.Enabled {
		healthAddr := config.Agent.Health.ListenAddress
		healthPath := config.Agent.Health.Path

		healthMux := http.NewServeMux()
		healthMux.HandleFunc(healthPath, func(w http.ResponseWriter, r *http.Request) {
			status := agentInstance.Health()
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(status); err != nil {
				http.Error(w, "encode error", http.StatusInternalServerError)
			}
		})

		go func() {
			zapLogger.Info("health server listening", zap.String("addr", healthAddr+healthPath))
			if err := http.ListenAndServe(healthAddr, healthMux); err != nil && err != http.ErrServerClosed {
				zapLogger.Error("health server error", zap.Error(err))
			}
		}()
	}

	// ANCHOR: Prometheus metrics HTTP server - Feb 18, 2026 / fixed Feb 18, 2026
	// WHY: MetricsRegistry counters were incremented but never scraped; no HTTP
	//      server was wired to expose the /metrics endpoint for Prometheus.
	// WHAT: Serve GET /metrics using the standard promhttp.Handler() which reads
	//       from the global Prometheus registry (promauto registers there by default).
	// HOW: Dedicated net/http server on address and path from config (:9090/metrics
	//      by default via DefaultConfig()). Fallbacks (:8080/metrics) removed as
	//      they differed from config defaults and masked misconfiguration.
	if config.Agent.Metrics.Enabled {
		metricsAddr := config.Agent.Metrics.ListenAddress
		metricsPath := config.Agent.Metrics.Path

		metricsMux := http.NewServeMux()
		metricsMux.Handle(metricsPath, promhttp.Handler())

		go func() {
			zapLogger.Info("metrics server listening", zap.String("addr", metricsAddr+metricsPath))
			if err := http.ListenAndServe(metricsAddr, metricsMux); err != nil && err != http.ErrServerClosed {
				zapLogger.Error("metrics server error", zap.Error(err))
			}
		}()
	}

	// Wait for shutdown signal
	sig := <-sigChan
	zapLogger.Info("shutdown signal received",
		zap.String("signal", sig.String()),
	)

	// Graceful shutdown
	if err := agentInstance.Stop(); err != nil {
		zapLogger.Error("error during shutdown", zap.Error(err))
	}

	zapLogger.Info("agent stopped successfully")
}
