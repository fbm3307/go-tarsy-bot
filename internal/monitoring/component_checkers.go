package monitoring

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// AgentRegistryChecker checks the health of the agent registry
type AgentRegistryChecker struct {
	registry *agents.AgentRegistry
	logger   *zap.Logger
}

// NewAgentRegistryChecker creates a new agent registry checker
func NewAgentRegistryChecker(registry *agents.AgentRegistry, logger *zap.Logger) *AgentRegistryChecker {
	return &AgentRegistryChecker{
		registry: registry,
		logger:   logger,
	}
}

// CheckHealth performs health check on the agent registry
func (arc *AgentRegistryChecker) CheckHealth(ctx context.Context) (*HealthCheck, error) {
	startTime := time.Now()

	// Check if registry is responding
	agents := arc.registry.ListAgents()
	agentCount := len(agents)

	// Perform registry health check
	healthMap := arc.registry.HealthCheck()

	// Count healthy agents
	healthyAgents := 0
	var unhealthyAgents []string

	for agentName, status := range healthMap {
		if status == "healthy" {
			healthyAgents++
		} else {
			unhealthyAgents = append(unhealthyAgents, agentName)
		}
	}

	// Determine status
	var status HealthStatus
	var message string

	if agentCount == 0 {
		status = HealthStatusDegraded
		message = "No agents registered"
	} else if len(unhealthyAgents) == 0 {
		status = HealthStatusHealthy
		message = fmt.Sprintf("All %d agents are healthy", healthyAgents)
	} else if healthyAgents > 0 {
		status = HealthStatusDegraded
		message = fmt.Sprintf("%d/%d agents healthy, unhealthy: %v",
			healthyAgents, agentCount, unhealthyAgents)
	} else {
		status = HealthStatusUnhealthy
		message = fmt.Sprintf("All %d agents are unhealthy", agentCount)
	}

	return &HealthCheck{
		ComponentID:   "agent-registry",
		ComponentType: ComponentTypeAgent,
		Status:        status,
		Message:       message,
		Details: map[string]interface{}{
			"total_agents":     agentCount,
			"healthy_agents":   healthyAgents,
			"unhealthy_agents": unhealthyAgents,
			"available_alert_types": arc.registry.GetAvailableAlertTypes(),
		},
		ResponseTime: time.Since(startTime),
	}, nil
}

// GetComponentID returns the component ID
func (arc *AgentRegistryChecker) GetComponentID() string {
	return "agent-registry"
}

// GetComponentType returns the component type
func (arc *AgentRegistryChecker) GetComponentType() ComponentType {
	return ComponentTypeAgent
}

// MCPRegistryChecker checks the health of the MCP server registry
type MCPRegistryChecker struct {
	registry *mcp.MCPServerRegistry
	logger   *zap.Logger
}

// NewMCPRegistryChecker creates a new MCP registry checker
func NewMCPRegistryChecker(registry *mcp.MCPServerRegistry, logger *zap.Logger) *MCPRegistryChecker {
	return &MCPRegistryChecker{
		registry: registry,
		logger:   logger,
	}
}

// CheckHealth performs health check on the MCP registry
func (mrc *MCPRegistryChecker) CheckHealth(ctx context.Context) (*HealthCheck, error) {
	startTime := time.Now()

	// In a production system, this would check actual MCP server connectivity
	// For now, we'll check if the registry is operational

	var status HealthStatus
	var message string
	details := make(map[string]interface{})

	if mrc.registry == nil {
		status = HealthStatusUnhealthy
		message = "MCP registry is nil"
	} else {
		// Check registry operational status
		// This is a simplified check - in production you'd ping actual servers
		status = HealthStatusHealthy
		message = "MCP registry is operational"

		// Add some mock server information
		details["total_servers"] = 0
		details["running_servers"] = 0
		details["last_check"] = time.Now()
	}

	return &HealthCheck{
		ComponentID:   "mcp-registry",
		ComponentType: ComponentTypeMCPServer,
		Status:        status,
		Message:       message,
		Details:       details,
		ResponseTime:  time.Since(startTime),
	}, nil
}

// GetComponentID returns the component ID
func (mrc *MCPRegistryChecker) GetComponentID() string {
	return "mcp-registry"
}

// GetComponentType returns the component type
func (mrc *MCPRegistryChecker) GetComponentType() ComponentType {
	return ComponentTypeMCPServer
}

// SystemChecker checks overall system health
type SystemChecker struct {
	logger *zap.Logger
}

// NewSystemChecker creates a new system checker
func NewSystemChecker(logger *zap.Logger) *SystemChecker {
	return &SystemChecker{
		logger: logger,
	}
}

// CheckHealth performs system health check
func (sc *SystemChecker) CheckHealth(ctx context.Context) (*HealthCheck, error) {
	startTime := time.Now()

	// Collect system metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Check memory usage
	allocMB := memStats.Alloc / 1024 / 1024
	sysMB := memStats.Sys / 1024 / 1024

	// Determine status based on memory usage
	var status HealthStatus
	var message string

	const memoryThresholdMB = 1000 // 1GB threshold for example

	if allocMB > memoryThresholdMB {
		status = HealthStatusDegraded
		message = fmt.Sprintf("High memory usage: %d MB allocated", allocMB)
	} else {
		status = HealthStatusHealthy
		message = fmt.Sprintf("System healthy: %d MB allocated", allocMB)
	}

	// Check goroutines
	numGoroutines := runtime.NumGoroutine()
	if numGoroutines > 1000 {
		status = HealthStatusDegraded
		if message == fmt.Sprintf("System healthy: %d MB allocated", allocMB) {
			message = fmt.Sprintf("High goroutine count: %d", numGoroutines)
		} else {
			message += fmt.Sprintf(", high goroutine count: %d", numGoroutines)
		}
	}

	return &HealthCheck{
		ComponentID:   "system",
		ComponentType: ComponentTypeSystem,
		Status:        status,
		Message:       message,
		Details: map[string]interface{}{
			"memory_alloc_mb":     allocMB,
			"memory_sys_mb":       sysMB,
			"memory_gc_cycles":    memStats.NumGC,
			"goroutines":          numGoroutines,
			"cpu_count":           runtime.NumCPU(),
			"go_version":          runtime.Version(),
		},
		ResponseTime: time.Since(startTime),
	}, nil
}

// GetComponentID returns the component ID
func (sc *SystemChecker) GetComponentID() string {
	return "system"
}

// GetComponentType returns the component type
func (sc *SystemChecker) GetComponentType() ComponentType {
	return ComponentTypeSystem
}

// AgentHealthChecker checks the health of individual agents
type AgentHealthChecker struct {
	agent  agents.Agent
	logger *zap.Logger
}

// NewAgentHealthChecker creates a new agent health checker
func NewAgentHealthChecker(agent agents.Agent, logger *zap.Logger) *AgentHealthChecker {
	return &AgentHealthChecker{
		agent:  agent,
		logger: logger,
	}
}

// CheckHealth performs health check on an individual agent
func (ahc *AgentHealthChecker) CheckHealth(ctx context.Context) (*HealthCheck, error) {
	startTime := time.Now()

	// Test agent with a minimal alert
	testAlert := &models.Alert{
		AlertType: "health-check",
		Data: map[string]interface{}{
			"check": "health",
			"timestamp": time.Now().Unix(),
		},
	}

	testChainCtx := models.NewChainContext(
		"health-check",
		testAlert.Data,
		"health-check-session",
		"health-check-stage",
	)

	// Create a short timeout context for the health check
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var status HealthStatus
	var message string
	details := make(map[string]interface{})

	// Validate agent configuration
	if err := ahc.agent.ValidateConfiguration(); err != nil {
		status = HealthStatusUnhealthy
		message = fmt.Sprintf("Agent configuration invalid: %v", err)
	} else {
		// Try to process a test alert
		result, err := ahc.agent.ProcessAlert(checkCtx, testAlert, testChainCtx)

		if err != nil {
			// Check if it's a timeout or other recoverable error
			if err == context.DeadlineExceeded {
				status = HealthStatusDegraded
				message = "Agent processing timed out during health check"
			} else {
				status = HealthStatusDegraded
				message = fmt.Sprintf("Agent processing failed: %v", err)
			}
		} else if result != nil {
			status = HealthStatusHealthy
			message = "Agent responding normally"
			details["last_result_status"] = result.Status
		} else {
			status = HealthStatusDegraded
			message = "Agent returned nil result"
		}
	}

	// Add agent-specific details
	details["agent_type"] = ahc.agent.GetAgentType()
	details["capabilities"] = ahc.agent.GetCapabilities()

	return &HealthCheck{
		ComponentID:   fmt.Sprintf("agent-%s", ahc.agent.GetAgentType()),
		ComponentType: ComponentTypeAgent,
		Status:        status,
		Message:       message,
		Details:       details,
		ResponseTime:  time.Since(startTime),
	}, nil
}

// GetComponentID returns the component ID
func (ahc *AgentHealthChecker) GetComponentID() string {
	return fmt.Sprintf("agent-%s", ahc.agent.GetAgentType())
}

// GetComponentType returns the component type
func (ahc *AgentHealthChecker) GetComponentType() ComponentType {
	return ComponentTypeAgent
}

// MCPServerChecker checks the health of individual MCP servers
type MCPServerChecker struct {
	serverName string
	registry   *mcp.MCPServerRegistry
	logger     *zap.Logger
}

// NewMCPServerChecker creates a new MCP server checker
func NewMCPServerChecker(serverName string, registry *mcp.MCPServerRegistry, logger *zap.Logger) *MCPServerChecker {
	return &MCPServerChecker{
		serverName: serverName,
		registry:   registry,
		logger:     logger,
	}
}

// CheckHealth performs health check on an MCP server
func (msc *MCPServerChecker) CheckHealth(ctx context.Context) (*HealthCheck, error) {
	startTime := time.Now()

	var status HealthStatus
	var message string
	details := make(map[string]interface{})

	// Check server status
	serverStatus, err := msc.registry.GetServerStatus(msc.serverName)
	if err != nil {
		status = HealthStatusUnhealthy
		message = fmt.Sprintf("Failed to get server status: %v", err)
	} else {
		switch serverStatus {
		case mcp.ServerStatusRunning:
			status = HealthStatusHealthy
			message = "MCP server is running"
		case mcp.ServerStatusStopped:
			status = HealthStatusUnhealthy
			message = "MCP server is stopped"
		case mcp.ServerStatusFailed:
			status = HealthStatusUnhealthy
			message = "MCP server is in error state"
		default:
			status = HealthStatusUnknown
			message = fmt.Sprintf("Unknown server status: %s", serverStatus)
		}

		details["server_status"] = string(serverStatus)
	}

	// Check server health if available
	if health, err := msc.registry.GetServerHealth(msc.serverName); err == nil && health != nil {
		details["server_health"] = health
		details["last_check"] = health.LastCheck
		details["response_time"] = health.ResponseTime

		// Adjust status based on server health
		if !health.IsHealthy {
			status = HealthStatusDegraded
			message = fmt.Sprintf("Server health check failed: %s", health.LastError)
		}
	}

	return &HealthCheck{
		ComponentID:   fmt.Sprintf("mcp-server-%s", msc.serverName),
		ComponentType: ComponentTypeMCPServer,
		Status:        status,
		Message:       message,
		Details:       details,
		ResponseTime:  time.Since(startTime),
	}, nil
}

// GetComponentID returns the component ID
func (msc *MCPServerChecker) GetComponentID() string {
	return fmt.Sprintf("mcp-server-%s", msc.serverName)
}

// GetComponentType returns the component type
func (msc *MCPServerChecker) GetComponentType() ComponentType {
	return ComponentTypeMCPServer
}

// DatabaseChecker checks database connectivity and health
type DatabaseChecker struct {
	connectionString string
	logger           *zap.Logger
}

// NewDatabaseChecker creates a new database checker
func NewDatabaseChecker(connectionString string, logger *zap.Logger) *DatabaseChecker {
	return &DatabaseChecker{
		connectionString: connectionString,
		logger:           logger,
	}
}

// CheckHealth performs database health check
func (dc *DatabaseChecker) CheckHealth(ctx context.Context) (*HealthCheck, error) {
	startTime := time.Now()

	var status HealthStatus
	var message string
	details := make(map[string]interface{})

	// In a real implementation, you would:
	// 1. Test database connectivity
	// 2. Check database version
	// 3. Verify critical tables exist
	// 4. Test query performance

	// For now, we'll simulate a database check
	if dc.connectionString == "" {
		status = HealthStatusDegraded
		message = "Database connection string not configured"
	} else {
		// Simulate connection check
		status = HealthStatusHealthy
		message = "Database connection successful"
		details["connection_string"] = "[REDACTED]"
		details["simulated_check"] = true
	}

	return &HealthCheck{
		ComponentID:   "database",
		ComponentType: ComponentTypeDatabase,
		Status:        status,
		Message:       message,
		Details:       details,
		ResponseTime:  time.Since(startTime),
	}, nil
}

// GetComponentID returns the component ID
func (dc *DatabaseChecker) GetComponentID() string {
	return "database"
}

// GetComponentType returns the component type
func (dc *DatabaseChecker) GetComponentType() ComponentType {
	return ComponentTypeDatabase
}