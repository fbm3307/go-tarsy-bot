package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

func TestHealthChecker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)
	mockConfigLoader := &config.AgentConfigLoader{}
	agentRegistry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	t.Run("NewHealthChecker", func(t *testing.T) {
		config := DefaultHealthCheckConfig()
		hc := NewHealthChecker(logger, config, agentRegistry, mcpRegistry)

		assert.NotNil(t, hc)
		assert.Equal(t, config, hc.config)
		assert.NotNil(t, hc.checks)
		assert.NotNil(t, hc.checkers)
	})

	t.Run("RegisterChecker", func(t *testing.T) {
		hc := NewHealthChecker(logger, nil, agentRegistry, mcpRegistry)

		mockChecker := &mockComponentChecker{
			id:   "test-component",
			cType: ComponentTypeSystem,
		}

		hc.RegisterChecker(mockChecker)

		assert.Contains(t, hc.checkers, "test-component")
		assert.Equal(t, mockChecker, hc.checkers["test-component"])
	})

	t.Run("StartAndStop", func(t *testing.T) {
		config := &HealthCheckConfig{
			Interval:          100 * time.Millisecond,
			Timeout:           5 * time.Second,
			MaxRetries:        3,
			FailureThreshold:  3,
			RecoveryThreshold: 2,
			Enabled:           true,
		}

		hc := NewHealthChecker(logger, config, agentRegistry, mcpRegistry)
		ctx := context.Background()

		// Start health checker
		err := hc.Start(ctx)
		assert.NoError(t, err)
		assert.True(t, hc.running)

		// Starting again should return error
		err = hc.Start(ctx)
		assert.Error(t, err)

		// Stop health checker
		err = hc.Stop()
		assert.NoError(t, err)
		assert.False(t, hc.running)

		// Stopping again should not error
		err = hc.Stop()
		assert.NoError(t, err)
	})

	t.Run("DisabledHealthChecker", func(t *testing.T) {
		config := &HealthCheckConfig{
			Enabled: false,
		}

		hc := NewHealthChecker(logger, config, agentRegistry, mcpRegistry)
		ctx := context.Background()

		err := hc.Start(ctx)
		assert.NoError(t, err)
		assert.False(t, hc.running)
	})

	t.Run("PerformHealthChecks", func(t *testing.T) {
		config := &HealthCheckConfig{
			Interval:          1 * time.Second,
			Timeout:           5 * time.Second,
			MaxRetries:        3,
			FailureThreshold:  3,
			RecoveryThreshold: 2,
			Enabled:           false, // Disable automatic checks
		}

		hc := NewHealthChecker(logger, config, agentRegistry, mcpRegistry)

		// Register a mock checker
		mockChecker := &mockComponentChecker{
			id:     "test-healthy",
			cType:  ComponentTypeSystem,
			status: HealthStatusHealthy,
		}
		hc.RegisterChecker(mockChecker)

		// Perform health checks manually
		ctx := context.Background()
		hc.performHealthChecks(ctx)

		// Check results
		status := hc.GetHealthStatus()
		assert.Len(t, status, 1)
		assert.Contains(t, status, "test-healthy")
		assert.Equal(t, HealthStatusHealthy, status["test-healthy"].Status)
	})

	t.Run("GetComponentHealth", func(t *testing.T) {
		hc := NewHealthChecker(logger, nil, agentRegistry, mcpRegistry)

		// Add a health check result manually
		check := &HealthCheck{
			ComponentID:      "test-component",
			ComponentType:    ComponentTypeSystem,
			Status:           HealthStatusHealthy,
			Message:          "All good",
			LastChecked:      time.Now(),
			ResponseTime:     100 * time.Millisecond,
			CheckDuration:    50 * time.Millisecond,
			ErrorCount:       0,
			SuccessCount:     1,
			ConsecutiveFails: 0,
		}

		hc.updateHealthCheck(check)

		// Get specific component health
		result, exists := hc.GetComponentHealth("test-component")
		assert.True(t, exists)
		assert.NotNil(t, result)
		assert.Equal(t, "test-component", result.ComponentID)
		assert.Equal(t, HealthStatusHealthy, result.Status)

		// Get non-existent component
		result, exists = hc.GetComponentHealth("non-existent")
		assert.False(t, exists)
		assert.Nil(t, result)
	})

	t.Run("GetOverallHealth", func(t *testing.T) {
		hc := NewHealthChecker(logger, nil, agentRegistry, mcpRegistry)

		// Add various health check results
		checks := []*HealthCheck{
			{
				ComponentID:   "healthy-1",
				ComponentType: ComponentTypeAgent,
				Status:        HealthStatusHealthy,
				Message:       "OK",
				LastChecked:   time.Now(),
			},
			{
				ComponentID:   "healthy-2",
				ComponentType: ComponentTypeSystem,
				Status:        HealthStatusHealthy,
				Message:       "OK",
				LastChecked:   time.Now(),
			},
			{
				ComponentID:   "degraded-1",
				ComponentType: ComponentTypeMCPServer,
				Status:        HealthStatusDegraded,
				Message:       "Warning",
				LastChecked:   time.Now(),
			},
			{
				ComponentID:   "unhealthy-1",
				ComponentType: ComponentTypeDatabase,
				Status:        HealthStatusUnhealthy,
				Message:       "Error",
				LastChecked:   time.Now(),
			},
		}

		for _, check := range checks {
			hc.updateHealthCheck(check)
		}

		// Get overall health
		overall := hc.GetOverallHealth()
		assert.NotNil(t, overall)
		assert.Equal(t, HealthStatusUnhealthy, overall.Status) // Should be unhealthy due to one unhealthy component

		// Check summary
		assert.Equal(t, 4, overall.Summary["total_components"])
		assert.Equal(t, 2, overall.Summary["healthy_components"])
		assert.Equal(t, 1, overall.Summary["degraded_components"])
		assert.Equal(t, 1, overall.Summary["unhealthy_components"])
		assert.Equal(t, 50.0, overall.Summary["health_percentage"])

		// Check components by type
		assert.Len(t, overall.Components[ComponentTypeAgent], 1)
		assert.Len(t, overall.Components[ComponentTypeSystem], 1)
		assert.Len(t, overall.Components[ComponentTypeMCPServer], 1)
		assert.Len(t, overall.Components[ComponentTypeDatabase], 1)
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		hc := NewHealthChecker(logger, nil, agentRegistry, mcpRegistry)

		// Register a checker that will panic
		panicChecker := &mockComponentChecker{
			id:        "panic-checker",
			cType:     ComponentTypeSystem,
			shouldPanic: true,
		}
		hc.RegisterChecker(panicChecker)

		// Register a checker that will return error
		errorChecker := &mockComponentChecker{
			id:          "error-checker",
			cType:       ComponentTypeSystem,
			shouldError: true,
		}
		hc.RegisterChecker(errorChecker)

		// Perform health checks
		ctx := context.Background()
		hc.performHealthChecks(ctx)

		// Check that both failed components are marked as unhealthy
		status := hc.GetHealthStatus()

		panicResult, exists := status["panic-checker"]
		assert.True(t, exists)
		assert.Equal(t, HealthStatusUnhealthy, panicResult.Status)
		assert.Contains(t, panicResult.Message, "panic")

		errorResult, exists := status["error-checker"]
		assert.True(t, exists)
		assert.Equal(t, HealthStatusUnhealthy, errorResult.Status)
		assert.Contains(t, errorResult.Message, "Health check error")
	})

	t.Run("BuiltInCheckers", func(t *testing.T) {
		hc := NewHealthChecker(logger, nil, agentRegistry, mcpRegistry)

		// Built-in checkers should be registered automatically
		hc.registerBuiltInCheckers()

		// Should have system, agent-registry, and mcp-registry checkers
		assert.Contains(t, hc.checkers, "system")
		assert.Contains(t, hc.checkers, "agent-registry")
		assert.Contains(t, hc.checkers, "mcp-registry")
	})
}

func TestHealthCheckConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultHealthCheckConfig()

		assert.Equal(t, 30*time.Second, config.Interval)
		assert.Equal(t, 10*time.Second, config.Timeout)
		assert.Equal(t, 3, config.MaxRetries)
		assert.Equal(t, 3, config.FailureThreshold)
		assert.Equal(t, 2, config.RecoveryThreshold)
		assert.True(t, config.Enabled)
	})
}

func TestUpdateHealthCheck(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	hc := NewHealthChecker(logger, nil, nil, nil)

	t.Run("NewComponent", func(t *testing.T) {
		check := &HealthCheck{
			ComponentID:   "new-component",
			ComponentType: ComponentTypeSystem,
			Status:        HealthStatusHealthy,
			Message:       "New component",
			LastChecked:   time.Now(),
		}

		hc.updateHealthCheck(check)

		stored := hc.checks["new-component"]
		assert.NotNil(t, stored)
		assert.Equal(t, check.ComponentID, stored.ComponentID)
		assert.Equal(t, check.Status, stored.Status)
	})

	t.Run("UpdateExistingComponent", func(t *testing.T) {
		// First add a component
		initial := &HealthCheck{
			ComponentID:      "existing-component",
			ComponentType:    ComponentTypeSystem,
			Status:           HealthStatusHealthy,
			Message:          "Initial status",
			LastChecked:      time.Now().Add(-1 * time.Hour),
			SuccessCount:     5,
			ErrorCount:       2,
			ConsecutiveFails: 0,
		}
		hc.updateHealthCheck(initial)

		// Update with success
		update := &HealthCheck{
			ComponentID:   "existing-component",
			ComponentType: ComponentTypeSystem,
			Status:        HealthStatusHealthy,
			Message:       "Updated status",
			LastChecked:   time.Now(),
		}
		hc.updateHealthCheck(update)

		stored := hc.checks["existing-component"]
		assert.Equal(t, "Updated status", stored.Message)
		assert.Equal(t, 6, stored.SuccessCount)
		assert.Equal(t, 2, stored.ErrorCount)
		assert.Equal(t, 0, stored.ConsecutiveFails)

		// Update with failure
		failure := &HealthCheck{
			ComponentID:   "existing-component",
			ComponentType: ComponentTypeSystem,
			Status:        HealthStatusUnhealthy,
			Message:       "Failed status",
			LastChecked:   time.Now(),
		}
		hc.updateHealthCheck(failure)

		stored = hc.checks["existing-component"]
		assert.Equal(t, "Failed status", stored.Message)
		assert.Equal(t, 6, stored.SuccessCount)
		assert.Equal(t, 3, stored.ErrorCount)
		assert.Equal(t, 1, stored.ConsecutiveFails)
	})
}

// Mock component checker for testing
type mockComponentChecker struct {
	id          string
	cType       ComponentType
	status      HealthStatus
	shouldPanic bool
	shouldError bool
}

func (m *mockComponentChecker) CheckHealth(ctx context.Context) (*HealthCheck, error) {
	if m.shouldPanic {
		panic("mock panic for testing")
	}

	if m.shouldError {
		return nil, assert.AnError
	}

	return &HealthCheck{
		ComponentID:   m.id,
		ComponentType: m.cType,
		Status:        m.status,
		Message:       "Mock health check",
		LastChecked:   time.Now(),
		ResponseTime:  50 * time.Millisecond,
	}, nil
}

func (m *mockComponentChecker) GetComponentID() string {
	return m.id
}

func (m *mockComponentChecker) GetComponentType() ComponentType {
	return m.cType
}