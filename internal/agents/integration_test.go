package agents

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// TestAgentRegistryIntegration tests the complete agent registry integration
func TestAgentRegistryIntegration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	// Create mock MCP registry with default config
	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)

	// Create agent registry with mock config loader
	mockConfigLoader := &config.AgentConfigLoader{}
	registry := NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	t.Run("Register and Retrieve Hardcoded Agent", func(t *testing.T) {
		// Create a test agent
		settings := DefaultAgentSettings()
		testAgent := NewBaseAgent("test", []string{"testing"}, settings)

		// Register the agent
		err := registry.RegisterHardcodedAgent("test", testAgent, []string{"test-alert"})
		require.NoError(t, err)

		// Verify agent can be retrieved
		retrievedAgent, err := registry.GetAgent("test")
		require.NoError(t, err)
		assert.Equal(t, "test", retrievedAgent.GetAgentType())
		assert.Contains(t, retrievedAgent.GetCapabilities(), "testing")

		// Test alert routing
		alert := &models.Alert{
			AlertType: "test-alert",
			Data:      map[string]interface{}{"test": "data"},
		}

		routedAgent, err := registry.GetAgentForAlert(alert)
		require.NoError(t, err)
		assert.Equal(t, "test", routedAgent.GetAgentType())
	})

	t.Run("List Agents and Capabilities", func(t *testing.T) {
		agents := registry.ListAgents()
		assert.Contains(t, agents, "test (hardcoded)")

		alertTypes := registry.GetAvailableAlertTypes()
		assert.Contains(t, alertTypes, "test-alert")

		capabilities, err := registry.GetAgentCapabilities("test")
		require.NoError(t, err)
		assert.Contains(t, capabilities, "testing")
	})

	t.Run("Validate All Agents", func(t *testing.T) {
		err := registry.ValidateAllAgents()
		assert.NoError(t, err)
	})

	t.Run("Health Check", func(t *testing.T) {
		health := registry.HealthCheck()
		assert.Equal(t, "healthy", health["test"])
	})
}

// TestBaseAgentProcessing tests the base agent processing functionality
func TestBaseAgentProcessing(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	t.Run("Simple Processing Without Iteration Controller", func(t *testing.T) {
		// Create base agent without iteration controller
		settings := DefaultAgentSettings()
		agent := NewBaseAgent("test", []string{"testing"}, settings)

		// Create test context
		alert := &models.Alert{
			AlertType: "test",
			Data:      map[string]interface{}{"message": "test alert"},
		}

		chainCtx := models.NewChainContext("test", map[string]interface{}{"test": "data"}, "test-session", "test-stage")

		// Process the alert
		ctx := context.Background()
		result, err := agent.ProcessAlert(ctx, alert, chainCtx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, models.StageStatusCompleted, result.Status)
		assert.Equal(t, "test", result.AgentName)
		assert.NotNil(t, result.FinalAnalysis)
	})

	t.Run("Configuration Validation", func(t *testing.T) {
		settings := DefaultAgentSettings()
		agent := NewBaseAgent("test", []string{"testing"}, settings)

		err := agent.ValidateConfiguration()
		assert.NoError(t, err)

		// Test invalid configuration
		invalidAgent := NewBaseAgent("", []string{}, &AgentSettings{
			MaxIterations: -1,
		})

		err = invalidAgent.ValidateConfiguration()
		assert.Error(t, err)
	})
}

// TestPromptBuilderIntegration tests the prompt builder integration
func TestPromptBuilderIntegration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	t.Run("Build Standard Prompt", func(t *testing.T) {
		settings := DefaultAgentSettings()
		agent := NewBaseAgent("test", []string{"testing", "security"}, settings)

		alert := &models.Alert{
			AlertType: "security",
			Data:      map[string]interface{}{"threat": "malware"},
		}

		chainCtx := models.NewChainContext("security", map[string]interface{}{"severity": "high"}, "test-session", "analysis")

		// Build a prompt using the react_system template
		result, err := agent.BuildPrompt("react_system", alert, chainCtx)
		require.NoError(t, err)
		assert.NotEmpty(t, result.SystemPrompt)
		assert.Contains(t, result.SystemPrompt, "test")
		assert.Contains(t, result.SystemPrompt, "security")
	})

	t.Run("Build Multi-Layer Prompt", func(t *testing.T) {
		settings := DefaultAgentSettings()
		agent := NewBaseAgent("kubernetes", []string{"kubernetes", "security"}, settings)

		alert := &models.Alert{
			AlertType: "kubernetes",
			Data:      map[string]interface{}{"namespace": "production"},
		}

		chainCtx := models.NewChainContext("kubernetes", map[string]interface{}{"cluster": "main"}, "test-session", "k8s-analysis")

		// Build multi-layer prompt
		templates := []string{"kubernetes_system", "tool_instructions"}
		result, err := agent.BuildMultiLayerPrompt(templates, alert, chainCtx)
		require.NoError(t, err)
		assert.NotEmpty(t, result.SystemPrompt)
		assert.NotEmpty(t, result.Instructions)
		assert.Contains(t, result.TemplatesUsed, "kubernetes_system")
	})
}

// TestProcessingContextIntegration tests processing context functionality
func TestProcessingContextIntegration(t *testing.T) {
	t.Run("ChainContext Operations", func(t *testing.T) {
		// Create chain context
		alertData := map[string]interface{}{
			"type":      "security",
			"severity":  "high",
			"timestamp": time.Now().Unix(),
		}

		chainCtx := models.NewChainContext("security", alertData, "session-123", "initial-analysis")
		chainCtx.SetRunbookContent("Test runbook content for security incidents")

		// Validate context
		err := chainCtx.ValidateChainContext()
		assert.NoError(t, err)

		// Test stage result management
		result := &models.AgentExecutionResult{
			Status:        models.StageStatusCompleted,
			AgentName:     "security-agent",
			TimestampUs:   time.Now().UnixMicro(),
			ResultSummary: stringPtr("Security analysis completed"),
		}

		chainCtx.AddStageResult("initial-analysis", result)
		assert.Equal(t, 1, chainCtx.GetCompletedStagesCount())
		assert.False(t, chainCtx.HasFailedStages())

		// Test context cloning
		cloned := chainCtx.Clone()
		assert.Equal(t, chainCtx.SessionID, cloned.SessionID)
		assert.Equal(t, chainCtx.AlertType, cloned.AlertType)
		assert.Equal(t, chainCtx.GetRunbookContent(), cloned.GetRunbookContent())
	})

	t.Run("StageContext Operations", func(t *testing.T) {
		chainCtx := models.NewChainContext("kubernetes", map[string]interface{}{"cluster": "prod"}, "session-456", "pod-analysis")

		tools := &models.AvailableTools{
			Tools: []models.ToolWithServer{
				{
					Server: "kubernetes-server",
					Tool:   map[string]interface{}{"name": "kubectl", "description": "Kubernetes CLI tool"},
				},
			},
		}

		stageCtx := models.NewStageContext(chainCtx, tools, "kubernetes-agent", []string{"kubernetes-server"})

		// Validate stage context
		err := stageCtx.ValidateStageContext()
		assert.NoError(t, err)

		// Test utility methods
		assert.Equal(t, "kubernetes", stageCtx.GetAlertType())
		assert.Equal(t, "session-456", stageCtx.GetSessionID())
		assert.Equal(t, 1, stageCtx.GetMCPServerCount())
		assert.Equal(t, 1, stageCtx.GetToolCount())
		assert.True(t, stageCtx.HasMCPServer("kubernetes-server"))

		// Test context cloning
		cloned := stageCtx.Clone()
		assert.Equal(t, stageCtx.AgentName, cloned.AgentName)
		assert.Equal(t, stageCtx.GetToolCount(), cloned.GetToolCount())
	})
}

// TestMCPIntegration tests MCP tool integration
func TestMCPIntegration(t *testing.T) {
	t.Run("Tool Schema Validation", func(t *testing.T) {
		// Create enhanced tool with schema
		tool := &mcp.Tool{
			Name:        "kubectl",
			Description: "Execute kubectl commands",
			Server:      "kubernetes-server",
			Schema: &mcp.ToolSchema{
				Type: "object",
				Properties: map[string]*mcp.SchemaProperty{
					"command": {
						Type:        "string",
						Description: "The kubectl command to execute",
					},
					"namespace": {
						Type:        "string",
						Description: "Kubernetes namespace",
					},
				},
				Required: []string{"command"},
			},
		}

		// Validate tool schema
		err := tool.ValidateSchema()
		assert.NoError(t, err)

		// Test utility methods
		assert.True(t, tool.IsRequired("command"))
		assert.False(t, tool.IsRequired("namespace"))
		assert.Equal(t, 30*time.Second, tool.GetTimeout())

		// Test MCP format conversion
		mcpFormat := tool.ConvertToMCPFormat()
		assert.Equal(t, "kubectl", mcpFormat["name"])
		assert.NotNil(t, mcpFormat["inputSchema"])
	})

	t.Run("Tool Result Processing", func(t *testing.T) {
		// Create enhanced tool result
		result := &mcp.ToolResult{
			Success:     true,
			Content:     map[string]interface{}{"pods": []string{"pod1", "pod2"}},
			IsText:      false,
			MimeType:    "application/json",
			Duration:    100 * time.Millisecond,
			Timestamp:   time.Now(),
			ToolName:    "kubectl",
			Server:      "kubernetes-server",
			ContentType: "json",
		}

		// Test utility methods
		assert.True(t, result.IsSuccess())
		assert.False(t, result.HasError())
		assert.True(t, result.IsCompleted())

		// Test content conversion
		contentStr := result.GetContentAsString()
		assert.NotEmpty(t, contentStr)

		jsonContent, err := result.GetContentAsJSON()
		require.NoError(t, err)
		assert.Contains(t, jsonContent, "pods")

		// Test metadata operations
		result.AddMetadata("execution_context", "test")
		assert.Equal(t, "test", result.GetMetadata("execution_context"))
	})
}

// TestErrorRecoveryIntegration tests error recovery system
func TestErrorRecoveryIntegration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	t.Run("Error Recovery Strategies", func(t *testing.T) {
		handler := NewRecoveryHandler(logger)

		// Create a structured exception
		err := NewLLMError(ErrorCodeLLMRateLimited, "Rate limit exceeded", nil).
			WithAgent("test-agent").
			WithSession("session-123").
			WithStage("analysis")

		// Create recovery context
		recoveryCtx := &RecoveryContext{
			AgentType:     "test-agent",
			SessionID:     "session-123",
			Stage:         "analysis",
			AttemptNumber: 0,
		}

		// Test error recovery
		ctx := context.Background()
		result, recErr := handler.HandleError(ctx, err, recoveryCtx)

		require.NoError(t, recErr)
		assert.True(t, result.Success)
		assert.Equal(t, "retry", result.Action)
		assert.Greater(t, result.RetryAfter, time.Duration(0))
	})

	t.Run("Processing Wrapper", func(t *testing.T) {
		wrapper := NewProcessingWrapper(logger)

		callCount := 0
		processingFunc := func(ctx context.Context) error {
			callCount++
			if callCount < 3 {
				// Simulate temporary failure
				return NewTimeoutError("Simulated timeout", 30*time.Second)
			}
			return nil // Success on third attempt
		}

		ctx := context.Background()
		err := wrapper.WrapWithRecovery(ctx, "test-agent", "session-123", "test-stage", processingFunc)

		// Should succeed after retries
		assert.NoError(t, err)
		assert.Equal(t, 3, callCount) // Called 3 times before success
	})

	t.Run("Error Statistics", func(t *testing.T) {
		handler := NewRecoveryHandler(logger)

		// Generate some test errors
		err1 := NewLLMError(ErrorCodeLLMRateLimited, "Rate limit 1", nil)
		err2 := NewMCPError(ErrorCodeMCPConnectionLost, "Connection lost", nil)
		err3 := NewProcessingError(ErrorCodeMaxIterationsReached, "Max iterations", nil)

		// Log errors
		handler.errorLogger.LogError(err1)
		handler.errorLogger.LogError(err2)
		handler.errorLogger.LogError(err3)

		// Check statistics
		stats := handler.GetErrorStatistics()
		assert.Equal(t, 3, stats["total_errors"])
		assert.Equal(t, 3, stats["unresolved_errors"])

		categoryStats := stats["by_category"].(map[ErrorCategory]int)
		assert.Equal(t, 1, categoryStats[ErrorCategoryLLM])
		assert.Equal(t, 1, categoryStats[ErrorCategoryMCP])
		assert.Equal(t, 1, categoryStats[ErrorCategoryProcessing])
	})
}

// TestChainBasedProcessing tests chain-based agent processing
func TestChainBasedProcessing(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	t.Run("Chain-Based Routing", func(t *testing.T) {
		registry := NewAgentRegistry(logger, nil, nil)

		// Register a chain-based mapping
		mapping := &ChainBasedMapping{
			AlertType: "kubernetes-incident",
			ChainID:   "k8s-security-analysis",
			Stages: []ChainStageMapping{
				{
					StageID:   "initial-triage",
					StageName: "Initial Triage",
					AgentType: "kubernetes",
					Required:  true,
					Index:     0,
				},
				{
					StageID:   "security-analysis",
					StageName: "Security Analysis",
					AgentType: "security",
					Required:  true,
					Index:     1,
				},
			},
		}

		err := registry.RegisterChainBasedMapping(mapping)
		require.NoError(t, err)

		// Test chain-based routing
		alert := &models.Alert{
			AlertType: "kubernetes-incident",
			Data:      map[string]interface{}{"namespace": "production"},
		}
		_ = alert // Used for verification

		isChainBased := registry.IsChainBasedAlert("kubernetes-incident")
		assert.True(t, isChainBased)

		retrievedMapping, exists := registry.GetChainBasedMapping("kubernetes-incident")
		assert.True(t, exists)
		assert.Equal(t, "k8s-security-analysis", retrievedMapping.ChainID)
		assert.Len(t, retrievedMapping.Stages, 2)
	})
}

// TestConfigurableAgentIntegration tests the complete configurable agent system
func TestConfigurableAgentIntegration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	// Create mock LLM integration
	mockLLM := &MockLLMIntegration{}

	// Create mock MCP registry with default config
	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)

	t.Run("YAML Agent Definition Loading", func(t *testing.T) {
		yamlContent := `
name: test-yaml-agent
description: Test YAML-based agent
type: yaml-test
version: 1.0.0
capabilities:
  - yaml_processing
  - test_analysis
alert_types:
  - yaml-alert
  - test-alert
settings:
  max_iterations: 5
  timeout_duration: 300s
  temperature: 0.3
  max_tokens: 2048
instructions:
  general: |
    You are a test agent for YAML configuration validation.
    Your role is to process test alerts and provide analysis.
  mcp: |
    Use available tools to gather information about the test environment.
    Execute tools in a logical sequence for comprehensive analysis.
  custom:
    - Always validate input data before processing
    - Provide detailed explanations for all findings
    - Include recommendations for improvement
tools:
  - name: test-tool
    server: test-server
    description: Basic test tool for validation
    parameters:
      target: "default"
      format: "json"
    required:
      - target
    conditions:
      - "test"
      - "validate"
prompts:
  initial: "Analyze the test alert: ${ALERT_TYPE}"
  analysis: "Perform detailed analysis for: ${ALERT_DATA}"
variables:
  TEST_ENV: "development"
  LOG_LEVEL: "debug"
iteration_strategy:
  strategy: react
  max_steps: 5
  convergence: content
workflows:
  - name: initial-check
    type: prompt
    prompt_key: initial
    next_steps:
      - gather-info
  - name: gather-info
    type: tool
    tool_name: test-tool
    next_steps:
      - final-analysis
  - name: final-analysis
    type: analysis
`

		// Create configurable agent from YAML
		agent, err := NewConfigurableAgent([]byte(yamlContent), mockLLM, mcpRegistry, logger)
		require.NoError(t, err)
		assert.NotNil(t, agent)

		// Validate agent properties
		assert.Equal(t, "configurable-yaml-test", agent.GetAgentType())
		assert.Contains(t, agent.GetCapabilities(), "yaml_processing")
		assert.Contains(t, agent.GetCapabilities(), "test_analysis")

		// Validate configuration
		err = agent.ValidateConfiguration()
		assert.NoError(t, err)

		// Test definition access
		def := agent.GetDefinition()
		assert.Equal(t, "test-yaml-agent", def.Name)
		assert.Equal(t, "yaml-test", def.Type)
		assert.Len(t, def.Tools, 1)
		assert.Len(t, def.Workflows, 3)
	})

	t.Run("Agent Processing with ReAct Strategy", func(t *testing.T) {
		// Use minimal YAML configuration for processing test
		yamlContent := `
name: react-test-agent
type: react-test
capabilities:
  - react_processing
instructions:
  general: "Process alerts using ReAct strategy"
iteration_strategy:
  strategy: react
  max_steps: 3
`

		// Setup mock LLM responses
		mockLLM.responses = []string{
			"I need to analyze this alert. Let me start by understanding the context.",
			"Based on my analysis, this appears to be a test alert. Let me gather more information.",
			"Final analysis: This is a test alert that has been processed successfully using the ReAct strategy.",
		}

		agent, err := NewConfigurableAgent([]byte(yamlContent), mockLLM, mcpRegistry, logger)
		require.NoError(t, err)

		// Create test alert
		alert := &models.Alert{
			AlertType: "test-alert",
			Data:      map[string]interface{}{"message": "test alert for ReAct processing"},
		}

		chainCtx := models.NewChainContext("test", map[string]interface{}{"test": true}, "test-session", "react-test")

		// Process the alert
		ctx := context.Background()
		result, err := agent.ProcessAlert(ctx, alert, chainCtx)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, models.StageStatusCompleted, result.Status)
		assert.Equal(t, "react-test-agent", result.AgentName)
		assert.NotNil(t, result.FinalAnalysis)
		assert.Contains(t, *result.FinalAnalysis, "ReAct strategy")

		// Verify LLM was called
		assert.Equal(t, 3, mockLLM.callCount)
	})
}

// TestComprehensiveWorkflow tests end-to-end agent workflow
func TestComprehensiveWorkflow(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	// Create comprehensive test environment
	mockLLM := &MockLLMIntegration{}
	_ = mockLLM // Mock used for interface compatibility
	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)
	mockConfigLoader := &config.AgentConfigLoader{}
	registry := NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	t.Run("Complete Alert Processing Workflow", func(t *testing.T) {
		// Setup agents
		settings := DefaultAgentSettings()
		kubernetesAgent := NewBaseAgent("kubernetes", []string{"kubernetes", "container_management"}, settings)
		securityAgent := NewBaseAgent("security", []string{"security", "threat_analysis"}, settings)

		// Register agents
		err := registry.RegisterHardcodedAgent("kubernetes", kubernetesAgent, []string{"k8s-alert", "pod-failure"})
		require.NoError(t, err)

		err = registry.RegisterHardcodedAgent("security", securityAgent, []string{"security-alert", "threat-detected"})
		require.NoError(t, err)

		// Test Kubernetes alert routing
		k8sAlert := &models.Alert{
			AlertType: "k8s-alert",
			Data: map[string]interface{}{
				"namespace": "production",
				"pod":       "web-server-123",
				"status":    "CrashLoopBackOff",
			},
		}

		routed, err := registry.GetAgentForAlert(k8sAlert)
		require.NoError(t, err)
		assert.Equal(t, "kubernetes", routed.GetAgentType())

		// Test Security alert routing
		secAlert := &models.Alert{
			AlertType: "security-alert",
			Data: map[string]interface{}{
				"threat_type": "malware",
				"severity":    "high",
				"source_ip":   "192.168.1.100",
			},
		}

		routed, err = registry.GetAgentForAlert(secAlert)
		require.NoError(t, err)
		assert.Equal(t, "security", routed.GetAgentType())

		// Validate registry state
		agents := registry.ListAgents()
		assert.Contains(t, agents, "kubernetes (hardcoded)")
		assert.Contains(t, agents, "security (hardcoded)")

		alertTypes := registry.GetAvailableAlertTypes()
		assert.Contains(t, alertTypes, "k8s-alert")
		assert.Contains(t, alertTypes, "security-alert")

		// Test health check
		health := registry.HealthCheck()
		assert.Equal(t, "healthy", health["kubernetes"])
		assert.Equal(t, "healthy", health["security"])
	})
}

// MockLLMIntegration provides a mock implementation for testing
type MockLLMIntegration struct {
	responses []string
	callCount int
}

func (m *MockLLMIntegration) GenerateWithTracking(ctx context.Context, request *EnhancedGenerateRequest) (*LLMResponse, error) {
	if m.callCount >= len(m.responses) {
		return &LLMResponse{
			Content: "Mock response exceeded available responses",
			Model:   "mock-model",
			Cost:    0.01,
		}, nil
	}

	response := &LLMResponse{
		Content:      m.responses[m.callCount],
		Model:        "mock-model",
		TokensUsed:   150,
		FinishReason: "stop",
		Cost:         0.01,
	}

	m.callCount++
	return response, nil
}

// ValidateRequest validates the mock request
func (m *MockLLMIntegration) ValidateRequest(request *EnhancedGenerateRequest) error {
	if request == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if len(request.Messages) == 0 {
		return fmt.Errorf("messages cannot be empty")
	}
	return nil
}

// Helper function to create string pointer (removed duplicate - using the one from base_agent.go)