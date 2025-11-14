package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/api"
	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/database"
	"github.com/codeready/go-tarsy-bot/internal/hooks"
	"github.com/codeready/go-tarsy-bot/internal/monitoring"
	"github.com/codeready/go-tarsy-bot/internal/pipeline"
	"github.com/codeready/go-tarsy-bot/internal/services"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

func main() {
	var (
		help = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		fmt.Println("TARSy-bot Go Server")
		fmt.Println("==================")
		fmt.Println()
		fmt.Println("An intelligent Site Reliability Engineering (SRE) agent system")
		fmt.Println("that automatically processes alerts and uses MCP servers for")
		fmt.Println("comprehensive incident analysis.")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  go run cmd/server/main.go")
		fmt.Println()
		fmt.Println("Configuration is loaded from .env file and environment variables.")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  # Start server with default settings")
		fmt.Println("  go run cmd/server/main.go")
		fmt.Println()
		fmt.Println("  # Override with environment variables")
		fmt.Println("  PORT=9090 LOG_LEVEL=debug go run cmd/server/main.go")
		fmt.Println()
		fmt.Println("  # Use .env file for configuration")
		fmt.Println("  echo 'PORT=8085' > .env && go run cmd/server/main.go")
		return
	}

	// Load settings from .env file and environment variables
	settings := config.LoadSettings()

	// Setup logger
	logger := setupLogger(settings.LogLevel)
	defer logger.Sync()

	logger.Info("Starting TARSy-bot Go Server",
		zap.String("host", settings.Host),
		zap.Int("port", settings.Port),
		zap.String("log_level", settings.LogLevel),
		zap.String("environment", settings.Environment))

	// Create main context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Validate configuration before starting components
	logger.Info("Validating system configuration...")
	configValidator := config.NewConfigValidator(logger)
	if err := configValidator.ValidateStartupConfiguration(); err != nil {
		logger.Fatal("Configuration validation failed", zap.Error(err))
	}
	logger.Info("Configuration validation passed")

	// Setup components
	logger.Info("Initializing system components...")

	// Database initialization
	logger.Info("Initializing database connection...")
	db, err := database.NewConnectionFromEnv()
	if err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("Failed to close database connection", zap.Error(err))
		}
	}()

	// Test database connection
	if err := db.TestConnection(); err != nil {
		logger.Fatal("Database connection test failed", zap.Error(err))
	}

	// Run database migrations
	if err := db.Migrate(); err != nil {
		logger.Fatal("Database migration failed", zap.Error(err))
	}

	// Cleanup orphaned sessions from previous runs
	if orphanedCount, err := db.CleanupOrphanedSessions(); err != nil {
		logger.Warn("Failed to cleanup orphaned sessions", zap.Error(err))
	} else if orphanedCount > 0 {
		logger.Info("Cleaned up orphaned sessions", zap.Int64("count", orphanedCount))
	}

	logger.Info("Database initialized successfully")

	// MCP Registry
	mcpConfig := &mcp.ServerRegistryConfig{
		HealthCheckInterval: 30 * time.Second,
		EnableHealthChecks:  true,
		EnableAutoRestart:   true,
		StartupTimeout:      60 * time.Second, // Longer timeout for MCP server initialization
		TerminationTimeout:  10 * time.Second,
		MaxRestartAttempts:  3,
		RestartDelay:        5 * time.Second,
	}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)

	// LLM Integration Service
	logger.Info("Initializing LLM integration service...")
	llmIntegrationService := services.NewLLMIntegrationService(db, settings, logger)

	// Agent Registry with real configuration loading
	configLoader := config.NewAgentConfigLoader(logger, settings.AgentConfigPath)
	agentRegistry := agents.NewAgentRegistry(logger, configLoader, mcpRegistry)

	// Register default agents
	logger.Info("Registering built-in agents...")
	if err := registerBuiltInAgents(agentRegistry, llmIntegrationService, mcpRegistry, logger); err != nil {
		logger.Fatal("Failed to register built-in agents", zap.Error(err))
	}

	// Load configured agents and MCP servers from YAML
	logger.Info("Loading configured agents from YAML...")
	if err := agentRegistry.LoadConfiguredAgents(); err != nil {
		logger.Warn("Failed to load configured agents", zap.Error(err))
		// Not fatal - system can still work with hardcoded agents
	}

	// Load and register MCP servers from configuration
	logger.Info("Loading MCP servers from configuration...")
	if err := loadAndRegisterMCPServers(configLoader, mcpRegistry, logger); err != nil {
		logger.Warn("Failed to load MCP servers from configuration", zap.Error(err))
		// Not fatal - hardcoded MCP servers can still be used
	}


	// Health Checker
	healthConfig := &monitoring.HealthCheckConfig{
		Interval:          30 * time.Second,
		Timeout:           10 * time.Second,
		MaxRetries:        3,
		FailureThreshold:  3,
		RecoveryThreshold: 2,
		Enabled:           true,
	}
	healthChecker := monitoring.NewHealthChecker(logger, healthConfig, agentRegistry, mcpRegistry)

	// Metrics Collector
	metricsCollector := monitoring.NewMetricsCollector()

	// WebSocket Manager
	wsConfig := services.DefaultWebSocketConfig()
	wsManager := services.NewWebSocketManager(logger, wsConfig)

	// API Server
	serverConfig := &api.ServerConfig{
		Host:           settings.Host,
		Port:           settings.Port,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		RequestTimeout: 30 * time.Second,
		EnableCORS:     len(settings.CORSOrigins) > 0,
		EnableLogging:  true,
	}
	// History Service with database connection
	logger.Info("Initializing history service...")
	historyService := services.NewHistoryService(db, logger)

	// Processing Pipeline - use defaults then customize as needed
	logger.Info("Initializing processing pipeline...")
	pipelineConfig := pipeline.DefaultPipelineConfig()
	// Override specific settings for development
	pipelineConfig.MaxConcurrentJobs = 4
	pipelineConfig.JobTimeout = 30 * time.Second
	pipelineConfig.RetryDelay = 5 * time.Second
	pipelineConfig.HealthCheckInterval = 10 * time.Second
	processingPipeline := pipeline.NewProcessingPipeline(agentRegistry, mcpRegistry, historyService, wsManager, logger, pipelineConfig)

	// Runbook Service for downloading operational runbooks
	logger.Info("Initializing runbook service...")
	runbookConfig := &services.RunbookServiceConfig{
		Timeout:        settings.RunbookTimeout,
		MaxCacheSize:   100,
		CacheTTL:       1 * time.Hour,
		MaxSize:        1024 * 1024, // 1MB
		AllowedSchemes: []string{"http", "https"},
	}
	runbookService := services.NewRunbookServiceWithConfig(runbookConfig, logger)

	// Log runbook service initialization for now (TODO: integrate with agents)
	logger.Info("Runbook service initialized successfully",
		zap.String("timeout", runbookConfig.Timeout.String()),
		zap.Int("max_cache_size", runbookConfig.MaxCacheSize))

	// Temporary: suppress unused variable warning (runbook service is ready for integration)
	_ = runbookService

	// Initialize dashboard broadcaster
	logger.Info("Initializing dashboard broadcaster...")
	dashboardBroadcaster := services.NewDashboardBroadcaster(wsManager, logger)

	// Initialize typed hook system (matching Python implementation)
	logger.Info("Initializing typed hook system...")
	typedHookRegistry := hooks.GetTypedHookRegistry(logger)

	// Create main context for hook initialization
	hookCtx := context.Background()

	err = typedHookRegistry.InitializeHooks(hookCtx, historyService, dashboardBroadcaster)
	if err != nil {
		logger.Fatal("Failed to initialize typed hook system", zap.Error(err))
	}
	logger.Info("Typed hook system initialized successfully")

	apiServer := api.NewAPIServer(serverConfig, logger, agentRegistry, mcpRegistry, processingPipeline, healthChecker, metricsCollector, wsManager, historyService)

	// Start components
	logger.Info("Starting system components...")

	// Start processing pipeline
	if err := processingPipeline.Start(ctx); err != nil {
		logger.Fatal("Failed to start processing pipeline", zap.Error(err))
	}

	// Start health checker
	logger.Info("Starting health checker...")
	go func() {
		if err := healthChecker.Start(ctx); err != nil {
			logger.Error("Health checker error", zap.Error(err))
		}
	}()

	// Start API server
	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	logger.Info("Starting API server...")
	go func() {
		if err := apiServer.Start(serverCtx); err != nil {
			logger.Error("API server error", zap.Error(err))
			cancel()
		}
	}()

	// Give API server time to start
	time.Sleep(1 * time.Second)

	logger.Info("🚀 TARSy-bot Go Server started successfully!",
		zap.String("api_url", fmt.Sprintf("http://%s:%d", settings.Host, settings.Port)),
		zap.String("health_url", fmt.Sprintf("http://%s:%d/health", settings.Host, settings.Port)),
		zap.String("docs_url", fmt.Sprintf("http://%s:%d/docs", settings.Host, settings.Port)))

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	logger.Info("Shutdown signal received, stopping server...")

	// Stop components gracefully
	logger.Info("Stopping system components...")

	if err := apiServer.Stop(); err != nil {
		logger.Error("Error stopping API server", zap.Error(err))
	}

	// Shutdown dashboard broadcaster
	if err := dashboardBroadcaster.Shutdown(); err != nil {
		logger.Error("Error stopping dashboard broadcaster", zap.Error(err))
	}

	// Shutdown typed hook system
	if err := typedHookRegistry.Shutdown(); err != nil {
		logger.Error("Error stopping typed hook registry", zap.Error(err))
	}

	if err := wsManager.Shutdown(); err != nil {
		logger.Error("Error stopping WebSocket manager", zap.Error(err))
	}

	if err := healthChecker.Stop(); err != nil {
		logger.Error("Error stopping health checker", zap.Error(err))
	}

	if err := processingPipeline.Stop(); err != nil {
		logger.Error("Error stopping processing pipeline", zap.Error(err))
	}

	logger.Info("TARSy-bot Go Server stopped successfully")
}

// setupLogger creates and configures the logger
func setupLogger(level string) *zap.Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapLevel)
	config.Development = false
	config.Encoding = "console"
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	logger, err := config.Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}

	return logger
}

// registerBuiltInAgents registers the built-in agents
func registerBuiltInAgents(
	registry *agents.AgentRegistry,
	llmIntegrationService *services.LLMIntegrationService,
	mcpRegistry *mcp.MCPServerRegistry,
	logger *zap.Logger,
) error {
	logger.Info("Registering built-in agents...")

	// Create LLM service adapter for all agents
	llmAdapter := &services.LLMServiceAdapter{Service: llmIntegrationService}

	// Base agent for general alerts
	baseSettings := agents.DefaultAgentSettings()
	baseAgent := agents.NewBaseAgentWithDependencies(
		"general",
		[]string{"general", "monitoring"},
		baseSettings,
		llmAdapter,           // LLM integration
		mcpRegistry,          // MCP server registry
		logger,              // Logger
		nil, nil, nil, nil,  // Error handling components (nil for now)
		nil,                 // Dependency checker (nil for now)
	)
	if err := registry.RegisterHardcodedAgent("general", baseAgent, []string{
		"general-alert",
		"monitoring-alert",
		"system-alert",
		"application-alert",
	}); err != nil {
		return fmt.Errorf("failed to register general agent: %w", err)
	}

	// Kubernetes agent for k8s-related alerts
	k8sSettings := agents.DefaultAgentSettings()
	k8sAgent := agents.NewBaseAgentWithDependencies(
		"kubernetes",
		[]string{"kubernetes", "container", "orchestration"},
		k8sSettings,
		llmAdapter,           // LLM integration
		mcpRegistry,          // MCP server registry
		logger,              // Logger
		nil, nil, nil, nil,  // Error handling components (nil for now)
		nil,                 // Dependency checker (nil for now)
	)
	if err := registry.RegisterHardcodedAgent("kubernetes", k8sAgent, []string{
		"k8s-alert",
		"pod-failure",
		"deployment-issue",
		"node-alert",
		"pvc-alert",
		"namespace-alert",
	}); err != nil {
		return fmt.Errorf("failed to register kubernetes agent: %w", err)
	}

	// Security agent for security-related alerts
	securitySettings := agents.DefaultAgentSettings()
	securityAgent := agents.NewBaseAgentWithDependencies(
		"security",
		[]string{"security", "compliance"},
		securitySettings,
		llmAdapter,           // LLM integration
		mcpRegistry,          // MCP server registry
		logger,              // Logger
		nil, nil, nil, nil,  // Error handling components (nil for now)
		nil,                 // Dependency checker (nil for now)
	)
	if err := registry.RegisterHardcodedAgent("security", securityAgent, []string{
		"security-alert",
		"threat-detected",
		"vulnerability-alert",
		"compliance-violation",
		"intrusion-alert",
	}); err != nil {
		return fmt.Errorf("failed to register security agent: %w", err)
	}

	// Network agent for network-related alerts
	networkSettings := agents.DefaultAgentSettings()
	networkAgent := agents.NewBaseAgentWithDependencies(
		"network",
		[]string{"network", "connectivity"},
		networkSettings,
		llmAdapter,           // LLM integration
		mcpRegistry,          // MCP server registry
		logger,              // Logger
		nil, nil, nil, nil,  // Error handling components (nil for now)
		nil,                 // Dependency checker (nil for now)
	)
	if err := registry.RegisterHardcodedAgent("network", networkAgent, []string{
		"network-alert",
		"connectivity-issue",
		"latency-alert",
		"bandwidth-alert",
		"dns-alert",
	}); err != nil {
		return fmt.Errorf("failed to register network agent: %w", err)
	}

	logger.Info("Built-in agents registered successfully",
		zap.Int("total_agents", len(registry.ListAgents())))

	return nil
}

// loadAndRegisterMCPServers loads MCP servers from configuration and registers them
func loadAndRegisterMCPServers(configLoader *config.AgentConfigLoader, mcpRegistry *mcp.MCPServerRegistry, logger *zap.Logger) error {
	if configLoader == nil {
		logger.Info("No config loader provided, skipping MCP server configuration")
		return nil
	}

	// Load configuration
	agentConfig, err := configLoader.LoadConfiguration()
	if err != nil {
		return fmt.Errorf("failed to load agent configuration for MCP servers: %w", err)
	}

	// Register each configured MCP server
	registeredCount := 0
	for serverName, serverConfig := range agentConfig.MCPServers {
		if !serverConfig.Enabled {
			logger.Info("Skipping disabled MCP server", zap.String("server", serverName))
			continue
		}

		// Convert YAML config to internal format
		internalConfig := configLoader.ConvertToMCPServerConfig(serverConfig)

		// Register the server
		if err := mcpRegistry.RegisterServer(internalConfig); err != nil {
			logger.Error("Failed to register MCP server",
				zap.String("server", serverName),
				zap.Error(err))
			continue
		}

		registeredCount++
		logger.Info("Registered MCP server from configuration",
			zap.String("server", serverName),
			zap.String("command", serverConfig.Command))

		// Auto-start if configured
		if serverConfig.AutoStart {
			go func(name string) {
				// Use longer timeout for MCP server startup (30 seconds)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				
				logger.Info("Auto-starting MCP server with 30s timeout...", zap.String("server", name))
				if err := mcpRegistry.StartServer(ctx, name); err != nil {
					logger.Error("Failed to auto-start MCP server",
						zap.String("server", name),
						zap.Error(err))
				} else {
					logger.Info("✅ Auto-started MCP server successfully", zap.String("server", name))
				}
			}(serverName)
		}
	}
	
	// CRITICAL: Assign MCP servers to agents based on configuration
	// Without this, agents won't have access to any tools!
	for agentName, agentDef := range agentConfig.Agents {
		if !agentDef.Enabled {
			continue
		}
		
		for _, serverName := range agentDef.MCPServers {
			if err := mcpRegistry.AssignServerToAgent(serverName, agentDef.Type); err != nil {
				logger.Error("Failed to assign MCP server to agent",
					zap.String("server", serverName),
					zap.String("agent", agentName),
					zap.String("agent_type", agentDef.Type),
					zap.Error(err))
			} else {
				logger.Info("Assigned MCP server to agent",
					zap.String("server", serverName),
					zap.String("agent", agentName),
					zap.String("agent_type", agentDef.Type))
			}
		}
	}
	
	// ALSO assign MCP servers to built-in hardcoded agents
	// This allows hardcoded agents to use MCP tools too!
	builtInAgentMappings := map[string][]string{
		"security":   {"devsandbox-mcp"},
		"kubernetes": {"devsandbox-mcp"},
		"general":    {"devsandbox-mcp"},
		"network":    {"devsandbox-mcp"},
	}
	
	for agentType, serverNames := range builtInAgentMappings {
		for _, serverName := range serverNames {
			// Only assign if the server is actually registered
			if _, err := mcpRegistry.GetServer(serverName); err == nil {
				if err := mcpRegistry.AssignServerToAgent(serverName, agentType); err != nil {
					logger.Warn("Failed to assign MCP server to built-in agent",
						zap.String("server", serverName),
						zap.String("agent", agentType),
						zap.Error(err))
				} else {
					logger.Info("✅ Assigned MCP server to built-in agent",
						zap.String("server", serverName),
						zap.String("agent", agentType))
				}
			}
		}
	}

	logger.Info("MCP server registration complete",
		zap.Int("registered", registeredCount),
		zap.Int("total_configured", len(agentConfig.MCPServers)))

	return nil
}