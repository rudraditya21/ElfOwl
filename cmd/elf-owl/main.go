// ANCHOR: elf-owl agent entry point - Dec 26, 2025
// Starts the minimal compliance observer agent with direct goBPF integration
// Reads configuration from YAML and environment variables
// Initializes all components and runs the event processing pipeline

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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
