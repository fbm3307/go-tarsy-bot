package mcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// MCPServerRegistry manages multiple MCP servers with lifecycle management
type MCPServerRegistry struct {
	servers   map[string]*ServerInstance
	lifecycle *LifecycleManager
	logger    *zap.Logger
	mutex     sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// ServerInstance represents a managed MCP server instance
type ServerInstance struct {
	Config      *ServerConfig     `json:"config"`
	Client      MCPClient         `json:"-"`
	Status      ServerStatus      `json:"status"`
	StartTime   time.Time         `json:"start_time"`
	LastSeen    time.Time         `json:"last_seen"`
	RestartCount int              `json:"restart_count"`
	Health      *ServerHealth     `json:"health"`
	AssignedAgents []string       `json:"assigned_agents"`
	mutex       sync.RWMutex
}

// ServerStatus represents the current status of a server
type ServerStatus string

const (
	ServerStatusStopped     ServerStatus = "stopped"
	ServerStatusStarting    ServerStatus = "starting"
	ServerStatusRunning     ServerStatus = "running"
	ServerStatusRestarting  ServerStatus = "restarting"
	ServerStatusFailed      ServerStatus = "failed"
	ServerStatusTerminating ServerStatus = "terminating"
)

// ServerHealth contains health information for a server
type ServerHealth struct {
	IsHealthy     bool                   `json:"is_healthy"`
	LastCheck     time.Time              `json:"last_check"`
	FailureCount  int                    `json:"failure_count"`
	LastError     string                 `json:"last_error,omitempty"`
	Metrics       map[string]interface{} `json:"metrics,omitempty"`
	ResponseTime  time.Duration          `json:"response_time"`
}

// ServerRegistryConfig contains configuration for the server registry
type ServerRegistryConfig struct {
	HealthCheckInterval  time.Duration `json:"health_check_interval"`
	MaxRestartAttempts   int           `json:"max_restart_attempts"`
	RestartDelay         time.Duration `json:"restart_delay"`
	StartupTimeout       time.Duration `json:"startup_timeout"`
	TerminationTimeout   time.Duration `json:"termination_timeout"`
	EnableAutoRestart    bool          `json:"enable_auto_restart"`
	EnableHealthChecks   bool          `json:"enable_health_checks"`
}

// DefaultServerRegistryConfig returns the default configuration
func DefaultServerRegistryConfig() *ServerRegistryConfig {
	return &ServerRegistryConfig{
		HealthCheckInterval:  30 * time.Second,
		MaxRestartAttempts:   3,
		RestartDelay:         5 * time.Second,
		StartupTimeout:       30 * time.Second,
		TerminationTimeout:   10 * time.Second,
		EnableAutoRestart:    true,
		EnableHealthChecks:   true,
	}
}

// NewMCPServerRegistry creates a new MCP server registry
func NewMCPServerRegistry(logger *zap.Logger, config *ServerRegistryConfig) *MCPServerRegistry {
	if config == nil {
		config = DefaultServerRegistryConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())
	registry := &MCPServerRegistry{
		servers:   make(map[string]*ServerInstance),
		lifecycle: NewLifecycleManager(logger, config),
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
	}

	// Start background processes
	if config.EnableHealthChecks {
		go registry.healthCheckLoop()
	}

	return registry
}

// RegisterServer registers a new MCP server with the registry
func (r *MCPServerRegistry) RegisterServer(config *ServerConfig) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.servers[config.Name]; exists {
		return fmt.Errorf("server %s is already registered", config.Name)
	}

	instance := &ServerInstance{
		Config:         config,
		Status:         ServerStatusStopped,
		Health:         &ServerHealth{IsHealthy: false},
		AssignedAgents: make([]string, 0),
	}

	r.servers[config.Name] = instance
	r.logger.Info("Registered MCP server", zap.String("server", config.Name))

	return nil
}

// StartServer starts a registered MCP server
func (r *MCPServerRegistry) StartServer(ctx context.Context, serverName string) error {
	r.mutex.Lock()
	instance, exists := r.servers[serverName]
	r.mutex.Unlock()

	if !exists {
		return fmt.Errorf("server %s not found", serverName)
	}

	instance.mutex.Lock()
	defer instance.mutex.Unlock()

	if instance.Status == ServerStatusRunning {
		return fmt.Errorf("server %s is already running", serverName)
	}

	r.logger.Info("Starting MCP server", zap.String("server", serverName))
	instance.Status = ServerStatusStarting
	instance.StartTime = time.Now()

	// Create new client
	client := NewMCPClient(r.logger)
	instance.Client = client

	// Start the server with timeout
	startCtx, cancel := context.WithTimeout(ctx, r.lifecycle.config.StartupTimeout)
	defer cancel()

	if err := client.Connect(startCtx, instance.Config); err != nil {
		instance.Status = ServerStatusFailed
		instance.Health.LastError = err.Error()
		return fmt.Errorf("failed to start server %s: %w", serverName, err)
	}

	instance.Status = ServerStatusRunning
	instance.LastSeen = time.Now()
	instance.Health.IsHealthy = true
	instance.Health.LastCheck = time.Now()

	r.logger.Info("MCP server started successfully",
		zap.String("server", serverName),
		zap.Duration("startup_time", time.Since(instance.StartTime)),
	)

	return nil
}

// StopServer stops a running MCP server
func (r *MCPServerRegistry) StopServer(serverName string) error {
	r.mutex.Lock()
	instance, exists := r.servers[serverName]
	r.mutex.Unlock()

	if !exists {
		return fmt.Errorf("server %s not found", serverName)
	}

	instance.mutex.Lock()
	defer instance.mutex.Unlock()

	if instance.Status == ServerStatusStopped {
		return nil // Already stopped
	}

	r.logger.Info("Stopping MCP server", zap.String("server", serverName))
	instance.Status = ServerStatusTerminating

	if instance.Client != nil {
		if err := instance.Client.Disconnect(); err != nil {
			r.logger.Warn("Error disconnecting MCP client",
				zap.String("server", serverName),
				zap.Error(err),
			)
		}
	}

	instance.Status = ServerStatusStopped
	instance.Health.IsHealthy = false
	instance.Client = nil

	r.logger.Info("MCP server stopped", zap.String("server", serverName))
	return nil
}

// RestartServer restarts a server
func (r *MCPServerRegistry) RestartServer(ctx context.Context, serverName string) error {
	r.logger.Info("Restarting MCP server", zap.String("server", serverName))

	if err := r.StopServer(serverName); err != nil {
		return fmt.Errorf("failed to stop server for restart: %w", err)
	}

	// Wait for restart delay
	time.Sleep(r.lifecycle.config.RestartDelay)

	if err := r.StartServer(ctx, serverName); err != nil {
		return fmt.Errorf("failed to start server after restart: %w", err)
	}

	r.mutex.RLock()
	instance := r.servers[serverName]
	r.mutex.RUnlock()

	instance.mutex.Lock()
	instance.RestartCount++
	instance.mutex.Unlock()

	return nil
}

// GetServer returns a server instance by name
func (r *MCPServerRegistry) GetServer(serverName string) (*ServerInstance, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	instance, exists := r.servers[serverName]
	if !exists {
		return nil, fmt.Errorf("server %s not found", serverName)
	}

	return instance, nil
}

// GetClient returns the MCP client for a server
func (r *MCPServerRegistry) GetClient(serverName string) (MCPClient, error) {
	instance, err := r.GetServer(serverName)
	if err != nil {
		return nil, err
	}

	instance.mutex.RLock()
	defer instance.mutex.RUnlock()

	if instance.Status != ServerStatusRunning {
		return nil, fmt.Errorf("server %s is not running", serverName)
	}

	if instance.Client == nil {
		return nil, fmt.Errorf("server %s has no active client", serverName)
	}

	return instance.Client, nil
}

// ListServers returns all registered servers
func (r *MCPServerRegistry) ListServers() map[string]*ServerInstance {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[string]*ServerInstance)
	for name, instance := range r.servers {
		result[name] = instance
	}
	return result
}

// GetServersByAgent returns servers assigned to a specific agent
func (r *MCPServerRegistry) GetServersByAgent(agentName string) []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var servers []string
	for name, instance := range r.servers {
		instance.mutex.RLock()
		for _, agent := range instance.AssignedAgents {
			if agent == agentName {
				servers = append(servers, name)
				break
			}
		}
		instance.mutex.RUnlock()
	}
	return servers
}

// AssignServerToAgent assigns a server to an agent for tool access control
func (r *MCPServerRegistry) AssignServerToAgent(serverName, agentName string) error {
	instance, err := r.GetServer(serverName)
	if err != nil {
		return err
	}

	instance.mutex.Lock()
	defer instance.mutex.Unlock()

	// Check if already assigned
	for _, agent := range instance.AssignedAgents {
		if agent == agentName {
			return nil // Already assigned
		}
	}

	instance.AssignedAgents = append(instance.AssignedAgents, agentName)
	r.logger.Info("Assigned server to agent",
		zap.String("server", serverName),
		zap.String("agent", agentName),
	)

	return nil
}

// ExecuteToolOnServer executes a tool on a specific server
func (r *MCPServerRegistry) ExecuteToolOnServer(ctx context.Context, serverName, toolName string, parameters map[string]interface{}) (*ToolResult, error) {
	client, err := r.GetClient(serverName)
	if err != nil {
		return &ToolResult{
			Success:   false,
			Error:     err.Error(),
			Timestamp: time.Now(),
		}, nil
	}

	return client.ExecuteTool(ctx, toolName, parameters)
}

// GetAllToolsForAgent returns all tools available to a specific agent
func (r *MCPServerRegistry) GetAllToolsForAgent(ctx context.Context, agentName string) (map[string][]Tool, error) {
	serverNames := r.GetServersByAgent(agentName)
	if len(serverNames) == 0 {
		return make(map[string][]Tool), nil
	}

	allTools := make(map[string][]Tool)
	for _, serverName := range serverNames {
		client, err := r.GetClient(serverName)
		if err != nil {
			r.logger.Warn("Failed to get client for agent tools",
				zap.String("server", serverName),
				zap.String("agent", agentName),
				zap.Error(err),
			)
			continue
		}

		tools, err := client.ListTools(ctx)
		if err != nil {
			r.logger.Warn("Failed to list tools for agent",
				zap.String("server", serverName),
				zap.String("agent", agentName),
				zap.Error(err),
			)
			continue
		}

		allTools[serverName] = tools
	}

	return allTools, nil
}

// healthCheckLoop runs periodic health checks on all servers
func (r *MCPServerRegistry) healthCheckLoop() {
	ticker := time.NewTicker(r.lifecycle.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.performHealthChecks()
		case <-r.ctx.Done():
			return
		}
	}
}

// performHealthChecks checks the health of all running servers
func (r *MCPServerRegistry) performHealthChecks() {
	r.mutex.RLock()
	servers := make(map[string]*ServerInstance)
	for name, instance := range r.servers {
		servers[name] = instance
	}
	r.mutex.RUnlock()

	for name, instance := range servers {
		instance.mutex.RLock()
		shouldCheck := instance.Status == ServerStatusRunning && instance.Client != nil
		instance.mutex.RUnlock()

		if shouldCheck {
			r.checkServerHealth(name, instance)
		}
	}
}

// checkServerHealth performs a health check on a single server
func (r *MCPServerRegistry) checkServerHealth(serverName string, instance *ServerInstance) {
	instance.mutex.Lock()
	defer instance.mutex.Unlock()

	startTime := time.Now()

	// Simple health check - try to list tools
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := instance.Client.ListTools(ctx)
	responseTime := time.Since(startTime)

	instance.Health.LastCheck = time.Now()
	instance.Health.ResponseTime = responseTime

	if err != nil {
		instance.Health.IsHealthy = false
		instance.Health.FailureCount++
		instance.Health.LastError = err.Error()

		r.logger.Warn("Server health check failed",
			zap.String("server", serverName),
			zap.Error(err),
			zap.Int("failure_count", instance.Health.FailureCount),
		)

		// Auto-restart if enabled and failure count exceeds threshold
		if r.lifecycle.config.EnableAutoRestart &&
		   instance.Health.FailureCount >= 3 &&
		   instance.RestartCount < r.lifecycle.config.MaxRestartAttempts {

			r.logger.Info("Triggering auto-restart for failed server",
				zap.String("server", serverName),
				zap.Int("restart_count", instance.RestartCount),
			)

			// Restart in background
			go func() {
				if err := r.RestartServer(context.Background(), serverName); err != nil {
					r.logger.Error("Auto-restart failed",
						zap.String("server", serverName),
						zap.Error(err),
					)
				}
			}()
		}
	} else {
		instance.Health.IsHealthy = true
		instance.Health.FailureCount = 0
		instance.Health.LastError = ""
		instance.LastSeen = time.Now()
	}
}

// Shutdown gracefully shuts down all servers
func (r *MCPServerRegistry) Shutdown() error {
	r.logger.Info("Shutting down MCP server registry")

	// Cancel background processes
	r.cancel()

	// Stop all servers
	r.mutex.RLock()
	serverNames := make([]string, 0, len(r.servers))
	for name := range r.servers {
		serverNames = append(serverNames, name)
	}
	r.mutex.RUnlock()

	for _, name := range serverNames {
		if err := r.StopServer(name); err != nil {
			r.logger.Error("Error stopping server during shutdown",
				zap.String("server", name),
				zap.Error(err),
			)
		}
	}

	r.logger.Info("MCP server registry shutdown complete")
	return nil
}

// GetServerStatus returns the current status of a server
func (r *MCPServerRegistry) GetServerStatus(serverName string) (ServerStatus, error) {
	instance, err := r.GetServer(serverName)
	if err != nil {
		return ServerStatusStopped, err
	}

	instance.mutex.RLock()
	defer instance.mutex.RUnlock()
	return instance.Status, nil
}

// GetServerHealth returns the health information for a server
func (r *MCPServerRegistry) GetServerHealth(serverName string) (*ServerHealth, error) {
	instance, err := r.GetServer(serverName)
	if err != nil {
		return nil, err
	}

	instance.mutex.RLock()
	defer instance.mutex.RUnlock()

	// Return a copy
	return &ServerHealth{
		IsHealthy:    instance.Health.IsHealthy,
		LastCheck:    instance.Health.LastCheck,
		FailureCount: instance.Health.FailureCount,
		LastError:    instance.Health.LastError,
		Metrics:      instance.Health.Metrics,
		ResponseTime: instance.Health.ResponseTime,
	}, nil
}

// GetAllTools returns all tools from all running servers
func (r *MCPServerRegistry) GetAllTools(ctx context.Context) (map[string][]Tool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	allTools := make(map[string][]Tool)

	for serverName, instance := range r.servers {
		instance.mutex.RLock()
		if instance.Status == ServerStatusRunning && instance.Client != nil {
			client := instance.Client
			instance.mutex.RUnlock()

			tools, err := client.ListTools(ctx)
			if err != nil {
				r.logger.Warn("Failed to get tools from server",
					zap.String("server", serverName),
					zap.Error(err))
				continue
			}
			allTools[serverName] = tools
		} else {
			instance.mutex.RUnlock()
		}
	}

	return allTools, nil
}

// ExecuteTool executes a tool on any server that has it
func (r *MCPServerRegistry) ExecuteTool(ctx context.Context, serverName, toolName string, parameters map[string]interface{}) (*ToolResult, error) {
	return r.ExecuteToolOnServer(ctx, serverName, toolName, parameters)
}

// FindToolServer finds which server provides a specific tool
func (r *MCPServerRegistry) FindToolServer(ctx context.Context, toolName string) (string, error) {
	allTools, err := r.GetAllTools(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get tools: %w", err)
	}

	for serverName, tools := range allTools {
		for _, tool := range tools {
			if tool.Name == toolName {
				return serverName, nil
			}
		}
	}

	return "", fmt.Errorf("tool %s not found on any server", toolName)
}

// GetRegistryMetrics returns comprehensive metrics about the registry
func (r *MCPServerRegistry) GetRegistryMetrics() map[string]interface{} {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	metrics := map[string]interface{}{
		"total_servers":   len(r.servers),
		"server_statuses": make(map[string]int),
		"health_summary":  make(map[string]interface{}),
		"tool_counts":     make(map[string]int),
		"agent_assignments": r.getAgentAssignmentStats(),
	}

	statusCounts := make(map[string]int)
	healthyCount := 0
	unhealthyCount := 0
	totalTools := 0

	for serverName, instance := range r.servers {
		instance.mutex.RLock()
		status := string(instance.Status)
		statusCounts[status]++

		if instance.Health.IsHealthy {
			healthyCount++
		} else {
			unhealthyCount++
		}

		// Get tool count if running
		if instance.Status == ServerStatusRunning && instance.Client != nil {
			client := instance.Client
			instance.mutex.RUnlock()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			tools, err := client.ListTools(ctx)
			cancel()

			if err == nil {
				toolCount := len(tools)
				metrics["tool_counts"].(map[string]int)[serverName] = toolCount
				totalTools += toolCount
			}
		} else {
			instance.mutex.RUnlock()
		}
	}

	metrics["server_statuses"] = statusCounts
	metrics["health_summary"] = map[string]interface{}{
		"healthy_servers":   healthyCount,
		"unhealthy_servers": unhealthyCount,
		"total_tools":       totalTools,
	}

	return metrics
}

// getAgentAssignmentStats returns statistics about agent assignments
func (r *MCPServerRegistry) getAgentAssignmentStats() map[string]interface{} {
	agentStats := make(map[string][]string)
	serverStats := make(map[string]int)

	for serverName, instance := range r.servers {
		instance.mutex.RLock()
		agentCount := len(instance.AssignedAgents)
		serverStats[serverName] = agentCount

		for _, agent := range instance.AssignedAgents {
			agentStats[agent] = append(agentStats[agent], serverName)
		}
		instance.mutex.RUnlock()
	}

	return map[string]interface{}{
		"agents_to_servers": agentStats,
		"servers_to_agents": serverStats,
	}
}

// ListClients returns the names of all registered servers
func (r *MCPServerRegistry) ListClients() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	clients := make([]string, 0, len(r.servers))
	for name := range r.servers {
		clients = append(clients, name)
	}
	return clients
}

// StartAllServers starts all registered servers
func (r *MCPServerRegistry) StartAllServers(ctx context.Context) error {
	r.mutex.RLock()
	serverNames := make([]string, 0, len(r.servers))
	for name := range r.servers {
		serverNames = append(serverNames, name)
	}
	r.mutex.RUnlock()

	var lastErr error
	started := 0

	for _, name := range serverNames {
		if err := r.StartServer(ctx, name); err != nil {
			r.logger.Error("Failed to start server",
				zap.String("server", name),
				zap.Error(err))
			lastErr = err
		} else {
			started++
		}
	}

	r.logger.Info("Bulk server startup completed",
		zap.Int("started", started),
		zap.Int("total", len(serverNames)))

	return lastErr
}

// StopAllServers stops all running servers
func (r *MCPServerRegistry) StopAllServers() error {
	r.mutex.RLock()
	serverNames := make([]string, 0, len(r.servers))
	for name := range r.servers {
		serverNames = append(serverNames, name)
	}
	r.mutex.RUnlock()

	var lastErr error
	stopped := 0

	for _, name := range serverNames {
		if err := r.StopServer(name); err != nil {
			r.logger.Error("Failed to stop server",
				zap.String("server", name),
				zap.Error(err))
			lastErr = err
		} else {
			stopped++
		}
	}

	r.logger.Info("Bulk server shutdown completed",
		zap.Int("stopped", stopped),
		zap.Int("total", len(serverNames)))

	return lastErr
}

// GetRunningServers returns a list of currently running servers
func (r *MCPServerRegistry) GetRunningServers() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var running []string
	for name, instance := range r.servers {
		instance.mutex.RLock()
		if instance.Status == ServerStatusRunning {
			running = append(running, name)
		}
		instance.mutex.RUnlock()
	}
	return running
}

// GetFailedServers returns a list of servers in failed state
func (r *MCPServerRegistry) GetFailedServers() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var failed []string
	for name, instance := range r.servers {
		instance.mutex.RLock()
		if instance.Status == ServerStatusFailed {
			failed = append(failed, name)
		}
		instance.mutex.RUnlock()
	}
	return failed
}

// UnregisterServer removes a server from the registry
func (r *MCPServerRegistry) UnregisterServer(serverName string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	instance, exists := r.servers[serverName]
	if !exists {
		return fmt.Errorf("server %s not found", serverName)
	}

	// Stop the server if it's running
	instance.mutex.RLock()
	shouldStop := instance.Status == ServerStatusRunning
	instance.mutex.RUnlock()

	if shouldStop {
		r.mutex.Unlock()
		if err := r.StopServer(serverName); err != nil {
			r.mutex.Lock()
			r.logger.Warn("Failed to stop server before unregistering",
				zap.String("server", serverName),
				zap.Error(err))
		} else {
			r.mutex.Lock()
		}
	}

	delete(r.servers, serverName)
	r.logger.Info("Unregistered MCP server", zap.String("server", serverName))
	return nil
}

// UpdateServerConfig updates the configuration of a registered server
func (r *MCPServerRegistry) UpdateServerConfig(serverName string, config *ServerConfig) error {
	instance, err := r.GetServer(serverName)
	if err != nil {
		return err
	}

	instance.mutex.Lock()
	defer instance.mutex.Unlock()

	// Can only update config when server is stopped
	if instance.Status != ServerStatusStopped {
		return fmt.Errorf("cannot update config of running server %s", serverName)
	}

	instance.Config = config
	r.logger.Info("Updated server configuration", zap.String("server", serverName))
	return nil
}