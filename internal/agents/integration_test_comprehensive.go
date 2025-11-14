package agents

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/errors"
	"github.com/codeready/go-tarsy-bot/internal/models"
)

// ComprehensiveIntegrationTest demonstrates the complete integration of Phase 3 error handling
// and resilience patterns with the existing agent architecture
func ComprehensiveIntegrationTest(t *testing.T) error {
	logger, _ := zap.NewDevelopment()
	logger.Info("Starting comprehensive integration test")

	// Phase 1: Initialize all error handling and resilience components
	errorClassifier := errors.NewErrorClassifier(logger)
	resilienceWrapper := errors.NewResilienceWrapper(logger)
	timeoutManager := errors.NewTimeoutManager(errors.DefaultTimeoutManagerConfig(), logger)
	degradationManager := errors.NewServiceDegradationManager(errors.DefaultDegradationConfig(), logger)

	// Phase 2: Create dependency health checker using interface approach
	// Note: In a real implementation, this would be injected via dependency injection
	// For this test, we'll use nil to demonstrate interface compatibility
	var dependencyChecker DependencyHealthChecker

	ctx := context.Background()

	// Phase 3: Create agents with full resilience patterns
	agents := createTestAgents(logger, errorClassifier, resilienceWrapper, timeoutManager, degradationManager, dependencyChecker)

	// Phase 4: Create enhanced agent registry with all resilience components
	registry := NewAgentRegistryWithResilience(
		logger,
		nil, // Config loader would be provided in real scenarios
		nil, // MCP registry would be provided in real scenarios
		errorClassifier,
		resilienceWrapper,
		degradationManager,
		dependencyChecker,
	)

	// Register all test agents
	for name, agent := range agents {
		alertTypes := getAlertTypesForAgent(name)
		if err := registry.RegisterHardcodedAgent(name, agent, alertTypes); err != nil {
			return fmt.Errorf("failed to register agent %s: %w", name, err)
		}
	}

	// Phase 5: Test comprehensive error handling scenarios
	testScenarios := []struct {
		name        string
		alert       *models.Alert
		expectedErr bool
		description string
	}{
		{
			name: "successful_processing",
			alert: &models.Alert{
				AlertType: "kubernetes_pod_failure",
				Data:      map[string]interface{}{"pod": "test-pod", "namespace": "default"},
			},
			expectedErr: false,
			description: "Normal processing with healthy dependencies",
		},
		{
			name: "timeout_scenario",
			alert: &models.Alert{
				AlertType: "slow_processing_alert",
				Data:      map[string]interface{}{"complexity": "high"},
			},
			expectedErr: true,
			description: "Processing that exceeds timeout limits",
		},
		{
			name: "dependency_failure",
			alert: &models.Alert{
				AlertType: "dependency_sensitive_alert",
				Data:      map[string]interface{}{"requires_external": true},
			},
			expectedErr: false, // Should handle gracefully with degradation
			description: "Processing during dependency failures",
		},
		{
			name: "circuit_breaker_test",
			alert: &models.Alert{
				AlertType: "circuit_breaker_test",
				Data:      map[string]interface{}{"force_failure": true},
			},
			expectedErr: true,
			description: "Test circuit breaker functionality",
		},
	}

	// Phase 6: Execute test scenarios and validate error handling
	for _, scenario := range testScenarios {
		logger.Info("Executing test scenario",
			zap.String("scenario", scenario.name),
			zap.String("description", scenario.description))

		// Create chain context for the test
		chainCtx := &models.ChainContext{
			SessionID:        fmt.Sprintf("test_session_%s_%d", scenario.name, time.Now().Unix()),
			CurrentStageName: "integration_test",
		}

		// Test agent lookup with resilience
		agent, err := registry.GetAgentForAlert(scenario.alert)
		if err != nil {
			if scenario.expectedErr {
				logger.Info("Expected error during agent lookup", zap.Error(err))
				continue
			}
			return fmt.Errorf("unexpected error in agent lookup for %s: %w", scenario.name, err)
		}

		// Test agent processing with full error handling
		result, err := agent.ProcessAlert(ctx, scenario.alert, chainCtx)

		if scenario.expectedErr && err == nil {
			return fmt.Errorf("expected error for scenario %s but got none", scenario.name)
		}

		if !scenario.expectedErr && err != nil {
			// Check if this is a structured error and log details
			if structuredErr, ok := err.(*errors.StructuredError); ok {
				logger.Error("Structured error details",
					zap.String("scenario", scenario.name),
					zap.String("error_code", structuredErr.Code),
					zap.String("category", string(structuredErr.Category)),
					zap.String("severity", string(structuredErr.Severity)),
					zap.Error(structuredErr))
			}
			return fmt.Errorf("unexpected error for scenario %s: %w", scenario.name, err)
		}

		// Validate result structure
		if result != nil {
			logger.Info("Agent processing result",
				zap.String("scenario", scenario.name),
				zap.String("agent_name", result.AgentName),
				zap.String("status", string(result.Status)),
				zap.Bool("has_analysis", result.FinalAnalysis != nil))
		}
	}

	// Phase 7: Test degradation scenarios
	logger.Info("Testing degradation scenarios")
	if err := testDegradationScenarios(registry, degradationManager, logger); err != nil {
		return fmt.Errorf("degradation scenarios failed: %w", err)
	}

	// Phase 8: Test health checking and metrics
	logger.Info("Testing health checking and metrics")
	if err := testHealthAndMetrics(registry, agents, logger); err != nil {
		return fmt.Errorf("health and metrics tests failed: %w", err)
	}

	// Phase 9: Test recovery scenarios
	logger.Info("Testing recovery scenarios")
	if err := testRecoveryScenarios(degradationManager, dependencyChecker, logger); err != nil {
		return fmt.Errorf("recovery scenarios failed: %w", err)
	}

	logger.Info("Comprehensive integration test completed successfully")
	return nil
}

// configureDependenciesExample demonstrates how dependencies would be configured
// In a real implementation, this would use the actual monitoring adapter
func configureDependenciesExample(logger *zap.Logger) {
	logger.Info("Dependencies would be configured here",
		zap.Strings("dependency_types", []string{
			"primary_llm_provider",
			"secondary_llm_provider",
			"mcp_kubernetes_server",
			"history_database",
			"external_monitoring_api",
		}))
}

// createTestAgents creates a variety of test agents with different configurations
func createTestAgents(
	logger *zap.Logger,
	errorClassifier *errors.ErrorClassifier,
	resilienceWrapper *errors.ResilienceWrapper,
	timeoutManager *errors.TimeoutManager,
	degradationManager *errors.ServiceDegradationManager,
	dependencyChecker DependencyHealthChecker,
) map[string]Agent {
	agents := make(map[string]Agent)

	// Standard Kubernetes agent with full resilience
	kubernetesAgent := NewBaseAgentWithDependencies(
		"kubernetes_resilient",
		[]string{"kubernetes", "pod_management", "troubleshooting", "error_recovery"},
		&AgentSettings{
			MaxIterations:     8,
			TimeoutDuration:   90 * time.Second,
			RetryAttempts:     3,
			EnableDebugMode:   true,
			LLMProvider:       "openai",
			MCPEnabled:        true,
			Temperature:       0.3,
			MaxTokens:         4096,
			IterationStrategy: "react",
			EnableToolUse:     true,
		},
		nil, // LLM integration
		nil, // MCP registry
		logger,
		errorClassifier,
		resilienceWrapper,
		timeoutManager,
		degradationManager,
		dependencyChecker,
	)

	// High-performance agent with aggressive timeouts
	performanceAgent := NewBaseAgentWithDependencies(
		"performance_optimized",
		[]string{"performance", "monitoring", "quick_analysis"},
		&AgentSettings{
			MaxIterations:     5,
			TimeoutDuration:   30 * time.Second,
			RetryAttempts:     1,
			EnableDebugMode:   false,
			LLMProvider:       "openai",
			MCPEnabled:        true,
			Temperature:       0.1,
			MaxTokens:         2048,
			IterationStrategy: "react",
			EnableToolUse:     true,
		},
		nil, // LLM integration
		nil, // MCP registry
		logger,
		errorClassifier,
		resilienceWrapper,
		timeoutManager,
		degradationManager,
		dependencyChecker,
	)

	// Fault-tolerant agent with extensive retry logic
	faultTolerantAgent := NewBaseAgentWithDependencies(
		"fault_tolerant",
		[]string{"fault_tolerance", "recovery", "resilience", "long_running"},
		&AgentSettings{
			MaxIterations:     15,
			TimeoutDuration:   5 * time.Minute,
			RetryAttempts:     5,
			EnableDebugMode:   true,
			LLMProvider:       "openai",
			MCPEnabled:        true,
			Temperature:       0.5,
			MaxTokens:         6144,
			IterationStrategy: "react",
			EnableToolUse:     true,
		},
		nil, // LLM integration
		nil, // MCP registry
		logger,
		errorClassifier,
		resilienceWrapper,
		timeoutManager,
		degradationManager,
		dependencyChecker,
	)

	agents["kubernetes"] = kubernetesAgent
	agents["performance"] = performanceAgent
	agents["fault_tolerant"] = faultTolerantAgent

	return agents
}

// getAlertTypesForAgent returns alert types handled by each test agent
func getAlertTypesForAgent(agentName string) []string {
	switch agentName {
	case "kubernetes":
		return []string{"kubernetes_pod_failure", "kubernetes_service_down", "k8s_deployment_failed"}
	case "performance":
		return []string{"performance_degradation", "slow_processing_alert", "high_latency"}
	case "fault_tolerant":
		return []string{"dependency_sensitive_alert", "circuit_breaker_test", "long_running_analysis"}
	default:
		return []string{"unknown_alert"}
	}
}

// testDegradationScenarios tests various degradation levels and their impact
func testDegradationScenarios(
	registry *AgentRegistry,
	degradationManager *errors.ServiceDegradationManager,
	logger *zap.Logger,
) error {
	// Test minor degradation
	degradationManager.DegradeToLevel(errors.DegradationLevelMinor, "Testing minor degradation impact")

	testAlert := &models.Alert{
		AlertType: "kubernetes_pod_failure",
		Data:      map[string]interface{}{"pod": "degraded-test"},
	}

	_, err := registry.GetAgentForAlert(testAlert)
	if err != nil {
		return fmt.Errorf("agent lookup failed during minor degradation: %w", err)
	}

	// Test major degradation
	degradationManager.DegradeToLevel(errors.DegradationLevelModerate, "Testing moderate degradation impact")

	_, err = registry.GetAgentForAlert(testAlert)
	if err != nil {
		return fmt.Errorf("agent lookup failed during major degradation: %w", err)
	}

	// Test recovery
	degradationManager.Recover()
	currentLevel := degradationManager.GetCurrentLevel()
	if currentLevel != errors.DegradationLevelNone {
		return fmt.Errorf("expected recovery to none level, got %s", currentLevel)
	}

	logger.Info("Degradation scenarios completed successfully")
	return nil
}

// testHealthAndMetrics validates health checking and metrics collection
func testHealthAndMetrics(
	registry *AgentRegistry,
	agents map[string]Agent,
	logger *zap.Logger,
) error {
	// Test registry health check
	registryHealth := registry.GetRegistryHealth()
	if registryHealth == nil {
		return fmt.Errorf("registry health check returned nil")
	}

	// Validate health structure
	if _, ok := registryHealth["registry_status"]; !ok {
		return fmt.Errorf("registry health missing status field")
	}

	// Test individual agent health checks
	for name, agent := range agents {
		if baseAgent, ok := agent.(*BaseAgent); ok {
			agentHealth := baseAgent.PerformHealthCheck()
			if agentHealth == nil {
				return fmt.Errorf("agent %s health check returned nil", name)
			}

			// Validate agent health structure
			if _, ok := agentHealth["agent_type"]; !ok {
				return fmt.Errorf("agent %s health missing agent_type field", name)
			}

			if _, ok := agentHealth["health_status"]; !ok {
				return fmt.Errorf("agent %s health missing health_status field", name)
			}
		}
	}

	// Test metrics collection
	registryMetrics := registry.GetAgentMetrics()
	if registryMetrics == nil {
		return fmt.Errorf("registry metrics returned nil")
	}

	logger.Info("Health and metrics tests completed successfully")
	return nil
}

// testRecoveryScenarios tests recovery from various failure states
func testRecoveryScenarios(
	degradationManager *errors.ServiceDegradationManager,
	dependencyChecker DependencyHealthChecker,
	logger *zap.Logger,
) error {
	// Test degradation recovery
	degradationManager.DegradeToLevel(errors.DegradationLevelModerate, "Testing recovery scenario")

	// Simulate recovery conditions
	time.Sleep(100 * time.Millisecond) // Brief pause to simulate time passage

	degradationManager.Recover()
	if degradationManager.GetCurrentLevel() != errors.DegradationLevelNone {
		return fmt.Errorf("failed to recover from degradation")
	}

	// Test dependency health recovery tracking if checker is available
	if dependencyChecker != nil {
		dependencyHealth := dependencyChecker.GetAllDependencyHealth()
		if dependencyHealth != nil {
			// Validate that we can track recovery metrics
			for name, health := range dependencyHealth {
				if health.Name == "" {
					return fmt.Errorf("dependency %s missing name field", name)
				}

				// Validate health structure
				if health.LastChecked.IsZero() {
					return fmt.Errorf("dependency %s has zero last checked time", name)
				}
			}
		}
	}

	logger.Info("Recovery scenarios completed successfully")
	return nil
}

// IntegrationTestErrorClassification tests the error classification system integration
func IntegrationTestErrorClassification(logger *zap.Logger) error {
	errorClassifier := errors.NewErrorClassifier(logger)

	// Test various error types
	testErrors := []struct {
		err          error
		expectedCode string
		expectedCat  errors.ErrorCategory
	}{
		{
			err:          errors.NewStructuredError("TIMEOUT", "Operation timed out", errors.ErrorCategoryTimeout, errors.ErrorSeverityMedium),
			expectedCode: "TIMEOUT",
			expectedCat:  errors.ErrorCategoryTimeout,
		},
		{
			err:          errors.NewStructuredError("NETWORK_FAILURE", "Network connection failed", errors.ErrorCategoryNetwork, errors.ErrorSeverityHigh),
			expectedCode: "NETWORK_FAILURE",
			expectedCat:  errors.ErrorCategoryNetwork,
		},
		{
			err:          fmt.Errorf("generic error message"),
			expectedCode: "UNKNOWN_ERROR",
			expectedCat:  errors.ErrorCategoryInternal,
		},
	}

	for _, test := range testErrors {
		classified := errorClassifier.ClassifyError(test.err)

		if classified.Code != test.expectedCode {
			return fmt.Errorf("expected error code %s, got %s", test.expectedCode, classified.Code)
		}

		if classified.Category != test.expectedCat {
			return fmt.Errorf("expected error category %s, got %s", test.expectedCat, classified.Category)
		}

		logger.Info("Error classification test passed",
			zap.String("original", test.err.Error()),
			zap.String("code", classified.Code),
			zap.String("category", string(classified.Category)))
	}

	return nil
}

// ExampleUsageComplete demonstrates complete usage of the integrated system
func ExampleUsageComplete() error {
	logger, _ := zap.NewDevelopment()

	logger.Info("=== Complete Integration Example ===")

	// Run comprehensive integration test
	if err := ComprehensiveIntegrationTest(&testing.T{}); err != nil {
		return fmt.Errorf("comprehensive integration test failed: %w", err)
	}

	// Run error classification test
	if err := IntegrationTestErrorClassification(logger); err != nil {
		return fmt.Errorf("error classification test failed: %w", err)
	}

	logger.Info("=== Integration Example Completed Successfully ===")
	return nil
}