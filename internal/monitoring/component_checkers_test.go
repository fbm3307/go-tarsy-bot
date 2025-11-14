package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

func TestAgentRegistryChecker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)
	mockConfigLoader := &config.AgentConfigLoader{}
	registry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	checker := NewAgentRegistryChecker(registry, logger)

	t.Run("GetComponentInfo", func(t *testing.T) {
		assert.Equal(t, "agent-registry", checker.GetComponentID())
		assert.Equal(t, ComponentTypeAgent, checker.GetComponentType())
	})

	t.Run("NoAgentsRegistered", func(t *testing.T) {
		ctx := context.Background()
		result, err := checker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "agent-registry", result.ComponentID)
		assert.Equal(t, ComponentTypeAgent, result.ComponentType)
		assert.Equal(t, HealthStatusDegraded, result.Status)
		assert.Contains(t, result.Message, "No agents registered")
	})

	t.Run("WithHealthyAgents", func(t *testing.T) {
		// Register a test agent
		settings := agents.DefaultAgentSettings()
		agent := agents.NewBaseAgent("test-agent", []string{"testing"}, settings)
		err := registry.RegisterHardcodedAgent("test", agent, []string{"test-alert"})
		require.NoError(t, err)

		ctx := context.Background()
		result, err := checker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, HealthStatusHealthy, result.Status)
		assert.Contains(t, result.Message, "agents are healthy")
		assert.Greater(t, result.Details["total_agents"], 0)
		assert.Greater(t, result.Details["healthy_agents"], 0)
	})
}

func TestMCPRegistryChecker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)

	checker := NewMCPRegistryChecker(mcpRegistry, logger)

	t.Run("GetComponentInfo", func(t *testing.T) {
		assert.Equal(t, "mcp-registry", checker.GetComponentID())
		assert.Equal(t, ComponentTypeMCPServer, checker.GetComponentType())
	})

	t.Run("HealthyRegistry", func(t *testing.T) {
		ctx := context.Background()
		result, err := checker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "mcp-registry", result.ComponentID)
		assert.Equal(t, ComponentTypeMCPServer, result.ComponentType)
		assert.Equal(t, HealthStatusHealthy, result.Status)
		assert.Contains(t, result.Message, "operational")
	})

	t.Run("NilRegistry", func(t *testing.T) {
		nilChecker := NewMCPRegistryChecker(nil, logger)
		ctx := context.Background()
		result, err := nilChecker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, HealthStatusUnhealthy, result.Status)
		assert.Contains(t, result.Message, "MCP registry is nil")
	})
}

func TestSystemChecker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	checker := NewSystemChecker(logger)

	t.Run("GetComponentInfo", func(t *testing.T) {
		assert.Equal(t, "system", checker.GetComponentID())
		assert.Equal(t, ComponentTypeSystem, checker.GetComponentType())
	})

	t.Run("HealthySystem", func(t *testing.T) {
		ctx := context.Background()
		result, err := checker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "system", result.ComponentID)
		assert.Equal(t, ComponentTypeSystem, result.ComponentType)
		assert.NotEqual(t, HealthStatusUnknown, result.Status)

		// Check details
		assert.Contains(t, result.Details, "memory_alloc_mb")
		assert.Contains(t, result.Details, "memory_sys_mb")
		assert.Contains(t, result.Details, "goroutines")
		assert.Contains(t, result.Details, "cpu_count")
		assert.Contains(t, result.Details, "go_version")

		// Verify numeric values
		assert.IsType(t, uint64(0), result.Details["memory_alloc_mb"])
		assert.IsType(t, uint64(0), result.Details["memory_sys_mb"])
		assert.IsType(t, int(0), result.Details["goroutines"])
		assert.IsType(t, int(0), result.Details["cpu_count"])
		assert.IsType(t, "", result.Details["go_version"])

		// Check response time is reasonable
		assert.Greater(t, result.ResponseTime, time.Duration(0))
		assert.Less(t, result.ResponseTime, 1*time.Second)
	})
}

func TestAgentHealthChecker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	settings := agents.DefaultAgentSettings()
	agent := agents.NewBaseAgent("test-agent", []string{"testing"}, settings)

	checker := NewAgentHealthChecker(agent, logger)

	t.Run("GetComponentInfo", func(t *testing.T) {
		assert.Equal(t, "agent-test-agent", checker.GetComponentID())
		assert.Equal(t, ComponentTypeAgent, checker.GetComponentType())
	})

	t.Run("HealthyAgent", func(t *testing.T) {
		ctx := context.Background()
		result, err := checker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "agent-test-agent", result.ComponentID)
		assert.Equal(t, ComponentTypeAgent, result.ComponentType)

		// Agent should respond normally to health check
		assert.NotEqual(t, HealthStatusUnknown, result.Status)

		// Check details
		assert.Contains(t, result.Details, "agent_type")
		assert.Contains(t, result.Details, "capabilities")
		assert.Equal(t, "test-agent", result.Details["agent_type"])

		// Check response time is reasonable
		assert.Greater(t, result.ResponseTime, time.Duration(0))
		assert.Less(t, result.ResponseTime, 10*time.Second)
	})

	t.Run("AgentWithTimeout", func(t *testing.T) {
		// Create a context with very short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Microsecond)
		defer cancel()

		// Wait for context to timeout
		time.Sleep(10 * time.Microsecond)

		result, err := checker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should handle timeout gracefully
		if result.Status == HealthStatusDegraded {
			assert.Contains(t, result.Message, "timed out")
		}
	})
}

func TestMCPServerChecker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)

	serverName := "test-server"
	checker := NewMCPServerChecker(serverName, mcpRegistry, logger)

	t.Run("GetComponentInfo", func(t *testing.T) {
		assert.Equal(t, "mcp-server-test-server", checker.GetComponentID())
		assert.Equal(t, ComponentTypeMCPServer, checker.GetComponentType())
	})

	t.Run("UnknownServer", func(t *testing.T) {
		ctx := context.Background()
		result, err := checker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "mcp-server-test-server", result.ComponentID)
		assert.Equal(t, ComponentTypeMCPServer, result.ComponentType)

		// Should handle unknown server gracefully
		assert.NotEqual(t, HealthStatusUnknown, result.Status)
	})
}

func TestDatabaseChecker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	t.Run("WithConnectionString", func(t *testing.T) {
		connectionString := "postgres://user:pass@localhost/testdb"
		checker := NewDatabaseChecker(connectionString, logger)

		assert.Equal(t, "database", checker.GetComponentID())
		assert.Equal(t, ComponentTypeDatabase, checker.GetComponentType())

		ctx := context.Background()
		result, err := checker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "database", result.ComponentID)
		assert.Equal(t, ComponentTypeDatabase, result.ComponentType)
		assert.Equal(t, HealthStatusHealthy, result.Status)
		assert.Contains(t, result.Message, "successful")

		// Check details
		assert.Contains(t, result.Details, "connection_string")
		assert.Equal(t, "[REDACTED]", result.Details["connection_string"])
		assert.Equal(t, true, result.Details["simulated_check"])
	})

	t.Run("WithoutConnectionString", func(t *testing.T) {
		checker := NewDatabaseChecker("", logger)

		ctx := context.Background()
		result, err := checker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, HealthStatusDegraded, result.Status)
		assert.Contains(t, result.Message, "not configured")
	})
}

func TestHealthCheckTiming(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	checker := NewSystemChecker(logger)

	t.Run("ResponseTimeMeasurement", func(t *testing.T) {
		ctx := context.Background()
		start := time.Now()

		result, err := checker.CheckHealth(ctx)

		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.NotNil(t, result)

		// Response time should be approximately correct
		assert.Greater(t, result.ResponseTime, time.Duration(0))
		assert.LessOrEqual(t, result.ResponseTime, elapsed)

		// Should complete quickly for system checks
		assert.Less(t, result.ResponseTime, 1*time.Second)
	})
}

func TestHealthCheckDetails(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)
	mockConfigLoader := &config.AgentConfigLoader{}
	registry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	checker := NewAgentRegistryChecker(registry, logger)

	t.Run("DetailsPopulation", func(t *testing.T) {
		ctx := context.Background()
		result, err := checker.CheckHealth(ctx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Details)

		// Should have expected detail fields
		assert.Contains(t, result.Details, "total_agents")
		assert.Contains(t, result.Details, "healthy_agents")
		assert.Contains(t, result.Details, "unhealthy_agents")
		assert.Contains(t, result.Details, "available_alert_types")

		// Types should be correct
		assert.IsType(t, int(0), result.Details["total_agents"])
		assert.IsType(t, int(0), result.Details["healthy_agents"])
		assert.IsType(t, []string{}, result.Details["unhealthy_agents"])
		assert.IsType(t, []string{}, result.Details["available_alert_types"])
	})
}