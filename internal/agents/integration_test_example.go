package agents

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/errors"
	"github.com/codeready/go-tarsy-bot/internal/models"
)

// ExampleIntegrationTest demonstrates the integration of error handling and resilience
// patterns with the agent architecture
func ExampleIntegrationTest() error {
	// Create logger
	logger, _ := zap.NewDevelopment()

	// Create error handling components
	errorClassifier := errors.NewErrorClassifier(logger)
	resilienceWrapper := errors.NewResilienceWrapper(logger)
	timeoutManager := errors.NewTimeoutManager(errors.DefaultTimeoutManagerConfig(), logger)
	degradationManager := errors.NewServiceDegradationManager(errors.DefaultDegradationConfig(), logger)

	// Create dependency health checker interface (would be injected in real implementation)
	var dependencyChecker DependencyHealthChecker

	// In a real implementation, dependencies would be configured here
	ctx := context.Background()

	// Create base agent with all resilience components
	baseAgent := NewBaseAgentWithDependencies(
		"example_agent",
		[]string{"example_capability", "error_handling"},
		DefaultAgentSettings(),
		nil, // LLM integration would be provided
		nil, // MCP registry would be provided
		logger,
		errorClassifier,
		resilienceWrapper,
		timeoutManager,
		degradationManager,
		dependencyChecker,
	)

	// Create enhanced agent registry
	registry := NewAgentRegistryWithResilience(
		logger,
		nil, // Config loader would be provided
		nil, // MCP registry would be provided
		errorClassifier,
		resilienceWrapper,
		degradationManager,
		dependencyChecker,
	)

	// Register the agent
	if err := registry.RegisterHardcodedAgent("example", baseAgent, []string{"example_alert"}); err != nil {
		return err
	}

	// Perform health checks
	agentHealth := baseAgent.PerformHealthCheck()
	logger.Info("Agent health check completed", zap.Any("health", agentHealth))

	registryHealth := registry.GetRegistryHealth()
	logger.Info("Registry health check completed", zap.Any("health", registryHealth))

	// Test agent lookup with resilience
	testAlert := &models.Alert{
		AlertType: "example_alert",
		Data:      map[string]interface{}{"test": "data"},
	}

	agent, err := registry.GetAgentForAlert(testAlert)
	if err != nil {
		// This error would be classified and handled by the error system
		structuredErr := errorClassifier.ClassifyError(err)
		logger.Error("Agent lookup failed",
			zap.String("error_code", structuredErr.Code),
			zap.String("error_category", string(structuredErr.Category)),
			zap.Error(structuredErr))
		return err
	}

	logger.Info("Agent lookup successful",
		zap.String("agent_type", agent.GetAgentType()),
		zap.Strings("capabilities", agent.GetCapabilities()))

	// Test degradation scenarios
	degradationManager.DegradeToLevel(errors.DegradationLevelMinor, "Testing degradation")
	logger.Info("Service degraded",
		zap.String("level", string(degradationManager.GetCurrentLevel())))

	// Test recovery
	degradationManager.Recover()
	logger.Info("Service recovered",
		zap.String("level", string(degradationManager.GetCurrentLevel())))

	// Test circuit breaker and retry patterns
	testErr := resilienceWrapper.ExecuteForService(ctx, "test_service", func(ctx context.Context) error {
		// Simulate some operation that might fail
		logger.Info("Executing test operation with resilience patterns")
		return nil
	})

	if testErr != nil {
		logger.Error("Resilience test failed", zap.Error(testErr))
		return testErr
	}

	logger.Info("Integration test completed successfully")
	return nil
}

// TestAgentErrorHandling demonstrates how agents handle errors with the new system
func TestAgentErrorHandling() error {
	logger, _ := zap.NewDevelopment()

	// Create a simple test setup
	errorClassifier := errors.NewErrorClassifier(logger)

	// Test different error types
	testErrors := []error{
		errors.NewStructuredError("TEST_TIMEOUT", "Test timeout error", errors.ErrorCategoryTimeout, errors.ErrorSeverityMedium),
		errors.NewStructuredError("TEST_NETWORK", "Test network error", errors.ErrorCategoryNetwork, errors.ErrorSeverityHigh),
		errors.NewStructuredError("TEST_VALIDATION", "Test validation error", errors.ErrorCategoryValidation, errors.ErrorSeverityLow),
	}

	for _, err := range testErrors {
		classified := errorClassifier.ClassifyError(err)
		logger.Info("Error classified",
			zap.String("original_message", err.Error()),
			zap.String("error_code", classified.Code),
			zap.String("category", string(classified.Category)),
			zap.String("severity", string(classified.Severity)),
			zap.Bool("recoverable", classified.Recoverable))
	}

	return nil
}

// ExampleAgentWithFullResilience shows how to create an agent with complete error handling
func ExampleAgentWithFullResilience(logger *zap.Logger) (*BaseAgent, error) {
	// Create all error handling components
	errorClassifier := errors.NewErrorClassifier(logger)
	resilienceWrapper := errors.NewResilienceWrapper(logger)
	timeoutManager := errors.NewTimeoutManager(errors.DefaultTimeoutManagerConfig(), logger)
	degradationManager := errors.NewServiceDegradationManager(errors.DefaultDegradationConfig(), logger)

	// In a real implementation, dependency checker would be injected
	var dependencyChecker DependencyHealthChecker

	// Agent-specific dependencies would be configured here
	// In a real implementation:
	// - Dependencies would be registered with the dependency checker
	// - Health checks would be configured
	// - Circuit breakers and timeouts would be set up

	// Create agent with custom settings
	settings := &AgentSettings{
		MaxIterations:     10,
		TimeoutDuration:   2 * time.Minute,
		RetryAttempts:     3,
		EnableDebugMode:   true,
		LLMProvider:       "openai",
		MCPEnabled:        true,
		Temperature:       0.7,
		MaxTokens:         4096,
		IterationStrategy: "react",
		EnableToolUse:     true,
	}

	agent := NewBaseAgentWithDependencies(
		"resilient_agent",
		[]string{"advanced_processing", "error_recovery", "health_monitoring"},
		settings,
		nil, // LLM integration
		nil, // MCP registry
		logger,
		errorClassifier,
		resilienceWrapper,
		timeoutManager,
		degradationManager,
		dependencyChecker,
	)

	return agent, nil
}