package benchmarks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/pipeline"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// BenchmarkBaseAgentProcessing benchmarks the basic agent processing performance
func BenchmarkBaseAgentProcessing(b *testing.B) {
	_ = zap.NewNop() // No-op logger for benchmarks

	settings := agents.DefaultAgentSettings()
	agent := agents.NewBaseAgent("benchmark-test", []string{"benchmarking"}, settings)

	alert := &models.Alert{
		AlertType: "benchmark-alert",
		Data: map[string]interface{}{
			"severity": "medium",
			"message":  "Benchmark test alert",
			"source":   "benchmark",
		},
	}

	chainCtx := models.NewChainContext("benchmark", alert.Data, "benchmark-session", "benchmark-stage")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		result, err := agent.ProcessAlert(ctx, alert, chainCtx)
		if err != nil {
			b.Fatalf("Agent processing failed: %v", err)
		}
		if result == nil {
			b.Fatal("Expected non-nil result")
		}
	}
}

// BenchmarkAgentRegistryRouting benchmarks agent routing performance
func BenchmarkAgentRegistryRouting(b *testing.B) {
	logger := zap.NewNop()

	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)
	mockConfigLoader := &config.AgentConfigLoader{}
	registry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	// Register multiple agents
	settings := agents.DefaultAgentSettings()
	agentTypes := []string{"kubernetes", "security", "monitoring", "network", "database"}
	alertMappings := map[string][]string{
		"kubernetes": {"k8s-alert", "pod-failure", "deployment-issue"},
		"security":   {"security-alert", "threat-detected", "vulnerability"},
		"monitoring": {"metric-alert", "threshold-exceeded", "anomaly"},
		"network":    {"network-alert", "connectivity-issue", "latency"},
		"database":   {"db-alert", "query-slow", "connection-pool"},
	}

	for _, agentType := range agentTypes {
		agent := agents.NewBaseAgent(agentType, []string{agentType}, settings)
		err := registry.RegisterHardcodedAgent(agentType, agent, alertMappings[agentType])
		if err != nil {
			b.Fatalf("Failed to register agent %s: %v", agentType, err)
		}
	}

	// Benchmark routing for different alert types
	testAlerts := []*models.Alert{
		{AlertType: "k8s-alert", Data: map[string]interface{}{"test": "k8s"}},
		{AlertType: "security-alert", Data: map[string]interface{}{"test": "security"}},
		{AlertType: "metric-alert", Data: map[string]interface{}{"test": "monitoring"}},
		{AlertType: "network-alert", Data: map[string]interface{}{"test": "network"}},
		{AlertType: "db-alert", Data: map[string]interface{}{"test": "database"}},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		alert := testAlerts[i%len(testAlerts)]
		agent, err := registry.GetAgentForAlert(alert)
		if err != nil {
			b.Fatalf("Failed to route alert: %v", err)
		}
		if agent == nil {
			b.Fatal("Expected non-nil agent")
		}
	}
}

// BenchmarkPromptBuilding benchmarks prompt building performance
func BenchmarkPromptBuilding(b *testing.B) {
	_ = zap.NewNop() // Unused logger

	alert := &models.Alert{
		AlertType: "benchmark-alert",
		Data: map[string]interface{}{
			"severity":    "high",
			"description": "Critical system failure requiring immediate attention",
			"component":   "web-server",
			"timestamp":   time.Now().Unix(),
		},
	}

	chainCtx := models.NewChainContext("benchmark", alert.Data, "bench-session", "bench-stage")
	chainCtx.SetRunbookContent("Benchmark runbook content for testing prompt building performance")

	settings := agents.DefaultAgentSettings()
	agent := agents.NewBaseAgent("benchmark-agent", []string{"benchmarking", "testing"}, settings)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Use the agent's BuildPrompt method instead
		result, err := agent.BuildPrompt("react_system", alert, chainCtx)
		if err != nil {
			b.Fatalf("Prompt building failed: %v", err)
		}
		if result.SystemPrompt == "" {
			b.Fatal("Expected non-empty system prompt")
		}
	}
}

// BenchmarkProcessingContextOperations benchmarks context operations
func BenchmarkProcessingContextOperations(b *testing.B) {
	baseData := map[string]interface{}{
		"environment": "production",
		"cluster":     "main",
		"severity":    "high",
		"component":   "api-gateway",
	}

	b.Run("ChainContext Creation", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sessionID := fmt.Sprintf("session-%d", i)
			stageName := fmt.Sprintf("stage-%d", i)
			chainCtx := models.NewChainContext("benchmark", baseData, sessionID, stageName)
			if chainCtx == nil {
				b.Fatal("Expected non-nil chain context")
			}
		}
	})

	b.Run("ChainContext Validation", func(b *testing.B) {
		chainCtx := models.NewChainContext("benchmark", baseData, "validation-session", "validation-stage")
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := chainCtx.ValidateChainContext()
			if err != nil {
				b.Fatalf("Validation failed: %v", err)
			}
		}
	})

	b.Run("ChainContext Cloning", func(b *testing.B) {
		chainCtx := models.NewChainContext("benchmark", baseData, "clone-session", "clone-stage")
		chainCtx.SetRunbookContent("Test runbook content for cloning benchmark")

		// Add some stage results
		for i := 0; i < 5; i++ {
			result := &models.AgentExecutionResult{
				Status:      models.StageStatusCompleted,
				AgentName:   fmt.Sprintf("agent-%d", i),
				TimestampUs: time.Now().UnixMicro(),
			}
			chainCtx.AddStageResult(fmt.Sprintf("stage-%d", i), result)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			cloned := chainCtx.Clone()
			if cloned == nil {
				b.Fatal("Expected non-nil cloned context")
			}
			if cloned.SessionID != chainCtx.SessionID {
				b.Fatal("Cloned context should have same session ID")
			}
		}
	})

	b.Run("StageContext Creation", func(b *testing.B) {
		chainCtx := models.NewChainContext("benchmark", baseData, "stage-session", "stage-stage")
		tools := &models.AvailableTools{
			Tools: []models.ToolWithServer{
				{
					Server: "benchmark-server",
					Tool:   map[string]interface{}{"name": "benchmark-tool", "description": "Benchmark tool"},
				},
			},
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			stageCtx := models.NewStageContext(chainCtx, tools, "benchmark-agent", []string{"benchmark-server"})
			if stageCtx == nil {
				b.Fatal("Expected non-nil stage context")
			}
		}
	})
}

// BenchmarkMCPOperations benchmarks MCP-related operations
func BenchmarkMCPOperations(b *testing.B) {

	b.Run("Tool Schema Validation", func(b *testing.B) {
		tool := &mcp.Tool{
			Name:        "benchmark-tool",
			Description: "Tool for benchmarking performance",
			Server:      "benchmark-server",
			Schema: &mcp.ToolSchema{
				Type: "object",
				Properties: map[string]*mcp.SchemaProperty{
					"command": {
						Type:        "string",
						Description: "Command to execute",
					},
					"timeout": {
						Type:        "integer",
						Description: "Timeout in seconds",
					},
				},
				Required: []string{"command"},
			},
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := tool.ValidateSchema()
			if err != nil {
				b.Fatalf("Schema validation failed: %v", err)
			}
		}
	})

	b.Run("Tool Result Processing", func(b *testing.B) {
		result := &mcp.ToolResult{
			Success:  true,
			Content:  map[string]interface{}{"output": "Benchmark test output", "status": "success"},
			IsText:   false,
			MimeType: "application/json",
			Duration: 100 * time.Millisecond,
			ToolName: "benchmark-tool",
			Server:   "benchmark-server",
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Test various operations
			_ = result.IsSuccess()
			_ = result.HasError()
			_ = result.IsCompleted()
			contentStr := result.GetContentAsString()
			if contentStr == "" {
				b.Fatal("Expected non-empty content string")
			}

			jsonContent, err := result.GetContentAsJSON()
			if err != nil {
				b.Fatalf("JSON content extraction failed: %v", err)
			}
			if jsonContent == nil {
				b.Fatal("Expected non-nil JSON content")
			}
		}
	})

	b.Run("MCP Server Registry Operations", func(b *testing.B) {
		logger := zap.NewNop()
		config := &mcp.ServerRegistryConfig{}
		registry := mcp.NewMCPServerRegistry(logger, config)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Simulate registry operations
			serverName := fmt.Sprintf("server-%d", i%10)
			agentName := fmt.Sprintf("agent-%d", i%5)

			servers := registry.GetServersByAgent(agentName)
			_ = servers // Use the result

			status, _ := registry.GetServerStatus(serverName)
			_ = status // Use the result
		}
	})
}

// BenchmarkPipelineOperations benchmarks pipeline processing performance
func BenchmarkPipelineOperations(b *testing.B) {

	// Setup environment
	logger := zap.NewNop()
	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)
	mockConfigLoader := &config.AgentConfigLoader{}
	agentRegistry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	// Register benchmark agent
	settings := agents.DefaultAgentSettings()
	agent := agents.NewBaseAgent("benchmark", []string{"benchmarking"}, settings)
	err := agentRegistry.RegisterHardcodedAgent("benchmark", agent, []string{"benchmark-alert"})
	if err != nil {
		b.Fatalf("Failed to register agent: %v", err)
	}

	b.Run("Job Creation", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			alert := &models.Alert{
				AlertType: "benchmark-alert",
				Data: map[string]interface{}{
					"iteration": i,
					"benchmark": "job_creation",
				},
			}

			chainCtx := models.NewChainContext(
				alert.AlertType,
				alert.Data,
				fmt.Sprintf("session-%d", i),
				"benchmark-stage",
			)

			job := &pipeline.ProcessingJob{
				Alert:    alert,
				ChainCtx: chainCtx,
				Priority: pipeline.PriorityMedium,
				Status:   pipeline.StatusPending,
			}

			if job == nil {
				b.Fatal("Expected non-nil job")
			}
		}
	})

	b.Run("Pipeline Status Checks", func(b *testing.B) {
		pipelineConfig := &pipeline.PipelineConfig{
			MaxConcurrentJobs:   4,
			JobTimeout:          30 * time.Second,
			QueueSize:           100,
			RetryAttempts:       2,
			RetryDelay:          100 * time.Millisecond,
			HealthCheckInterval: 1 * time.Second,
		}

		testPipeline := pipeline.NewProcessingPipeline(agentRegistry, mcpRegistry, logger, pipelineConfig)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			status := testPipeline.GetPipelineStatus()
			if status == nil {
				b.Fatal("Expected non-nil status")
			}

			metrics := testPipeline.GetMetrics()
			if metrics == nil {
				b.Fatal("Expected non-nil metrics")
			}
		}
	})
}

// BenchmarkErrorHandling benchmarks error handling and recovery
func BenchmarkErrorHandling(b *testing.B) {

	b.Run("Error Creation", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := agents.NewProcessingError(
				agents.ErrorCodeProcessingFailed,
				fmt.Sprintf("Benchmark error %d", i),
				nil,
			).WithAgent("benchmark-agent").
				WithSession(fmt.Sprintf("session-%d", i)).
				WithStage("benchmark-stage")

			if err == nil {
				b.Fatal("Expected non-nil error")
			}
		}
	})

	b.Run("Error Recovery Strategy Lookup", func(b *testing.B) {
		recoveryManager := agents.NewErrorRecoveryManager()

		testError := agents.NewLLMError(
			agents.ErrorCodeLLMRateLimited,
			"Rate limit exceeded",
			nil,
		)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			strategy := recoveryManager.GetRecoveryStrategy(testError)
			if strategy == nil {
				b.Fatal("Expected non-nil strategy")
			}

			canRecover := recoveryManager.CanRecover(testError)
			if !canRecover {
				b.Fatal("Expected error to be recoverable")
			}
		}
	})

	b.Run("Error Logging", func(b *testing.B) {
		errorLogger := agents.NewErrorLogger()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := agents.NewProcessingError(
				agents.ErrorCodeProcessingFailed,
				fmt.Sprintf("Log benchmark error %d", i),
				nil,
			)

			errorLogger.LogError(err)

			// Occasionally mark errors as resolved
			if i%10 == 0 {
				errorLogger.MarkResolved(err, []string{"retry_successful"})
			}
		}

		// Get stats at the end
		stats := errorLogger.GetErrorStats()
		if stats == nil {
			b.Fatal("Expected non-nil error stats")
		}
	})
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("Large Alert Processing", func(b *testing.B) {
		settings := agents.DefaultAgentSettings()
		agent := agents.NewBaseAgent("memory-test", []string{"memory"}, settings)

		// Create large alert data
		largeData := make(map[string]interface{})
		for i := 0; i < 1000; i++ {
			largeData[fmt.Sprintf("field_%d", i)] = fmt.Sprintf("large_value_%d_with_lots_of_text_content", i)
		}

		alert := &models.Alert{
			AlertType: "memory-test-alert",
			Data:      largeData,
		}

		chainCtx := models.NewChainContext("memory-test", largeData, "memory-session", "memory-stage")

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			ctx := context.Background()
			result, err := agent.ProcessAlert(ctx, alert, chainCtx)
			if err != nil {
				b.Fatalf("Processing failed: %v", err)
			}
			if result == nil {
				b.Fatal("Expected non-nil result")
			}
		}
	})

	b.Run("Context Cloning Memory", func(b *testing.B) {
		// Create base context with substantial data
		largeData := make(map[string]interface{})
		for i := 0; i < 500; i++ {
			largeData[fmt.Sprintf("key_%d", i)] = map[string]interface{}{
				"nested_field": fmt.Sprintf("nested_value_%d", i),
				"timestamp":    time.Now().Unix(),
				"counter":      i,
			}
		}

		baseCtx := models.NewChainContext("memory-test", largeData, "memory-session", "memory-stage")
		baseCtx.SetRunbookContent("Large runbook content " + fmt.Sprintf("%1000s", "x"))

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			cloned := baseCtx.Clone()
			if cloned == nil {
				b.Fatal("Expected non-nil cloned context")
			}
		}
	})
}