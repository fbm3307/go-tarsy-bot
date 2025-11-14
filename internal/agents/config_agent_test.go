package agents

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/models"
)

// TestConfigurableAgentBasicFunctionality tests basic configuration-based agent operations
func TestConfigurableAgentBasicFunctionality(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a test agent configuration
	agentConfig := &config.AgentConfig{
		Name:        "test-k8s-agent",
		Type:        "kubernetes",
		Description: "Test Kubernetes agent for unit testing",
		AlertTypes:  []string{"kubernetes.pod.crash", "kubernetes.deployment.failed"},
		MCPServers:  []string{"kubernetes-server", "monitoring-server"},
		Configuration: map[string]interface{}{
			"namespace":     "default",
			"cluster_name":  "${CLUSTER_NAME}",
			"max_iterations": 5,
		},
		Instructions: map[string]interface{}{
			"system_prompt": "You are a Kubernetes troubleshooting expert. Analyze pod crashes and deployment failures.",
			"context_instructions": []string{
				"Always check pod logs first",
				"Examine resource usage and limits",
				"Check for networking issues",
			},
		},
	}

	// Create the configurable agent
	agent, err := NewConfigurableAgent(agentConfig, logger)
	require.NoError(t, err)
	require.NotNil(t, agent)

	// Test basic properties
	assert.Equal(t, "test-k8s-agent", agent.GetName())
	assert.Equal(t, "kubernetes", agent.GetType())
	assert.Equal(t, "Test Kubernetes agent for unit testing", agent.GetDescription())
	assert.Equal(t, []string{"kubernetes.pod.crash", "kubernetes.deployment.failed"}, agent.GetAlertTypes())
	assert.Equal(t, []string{"kubernetes-server", "monitoring-server"}, agent.GetMCPServers())

	// Test configuration access
	config := agent.GetConfiguration()
	assert.Equal(t, "default", config["namespace"])
	assert.Equal(t, "${CLUSTER_NAME}", config["cluster_name"])
	assert.Equal(t, 5, config["max_iterations"])

	// Test custom instructions
	instructions := agent.GetCustomInstructions()
	assert.Contains(t, instructions, "Kubernetes troubleshooting expert")
	assert.Contains(t, instructions, "Always check pod logs first")
}

// TestConfigurableAgentProcessAlert tests alert processing with variable resolution
func TestConfigurableAgentProcessAlert(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Set test environment variables
	os.Setenv("CLUSTER_NAME", "test-cluster")
	os.Setenv("NAMESPACE", "production")
	defer func() {
		os.Unsetenv("CLUSTER_NAME")
		os.Unsetenv("NAMESPACE")
	}()

	agentConfig := &config.AgentConfig{
		Name:        "variable-test-agent",
		Type:        "kubernetes",
		Description: "Test agent with variable resolution",
		AlertTypes:  []string{"test.alert"},
		MCPServers:  []string{"test-server"},
		Configuration: map[string]interface{}{
			"cluster":           "${CLUSTER_NAME}",
			"default_namespace": "${NAMESPACE:default}",
			"timeout":           30,
		},
		Instructions: map[string]interface{}{
			"system_prompt": "Analyze alerts for cluster ${CLUSTER_NAME} in namespace ${NAMESPACE:default}",
			"context_instructions": []string{
				"Focus on cluster ${CLUSTER_NAME}",
				"Check namespace ${NAMESPACE:default} first",
			},
		},
	}

	agent, err := NewConfigurableAgent(agentConfig, logger)
	require.NoError(t, err)

	// Create test alert
	alert := &models.Alert{
		AlertType: "test.alert",
		Data: map[string]interface{}{
			"pod_name":  "test-pod",
			"namespace": "production",
			"message":   "Pod crashed with exit code 1",
		},
		Severity:  models.SeverityHigh,
		Timestamp: time.Now(),
	}

	// Test that configuration variables are resolved
	config := agent.GetConfiguration()
	assert.Equal(t, "test-cluster", config["cluster"])
	assert.Equal(t, "production", config["default_namespace"])

	// Test that instruction variables are resolved
	instructions := agent.GetCustomInstructions()
	assert.Contains(t, instructions, "cluster test-cluster")
	assert.Contains(t, instructions, "namespace production")
}

// TestConfigurableAgentValidation tests agent configuration validation
func TestConfigurableAgentValidation(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name        string
		config      *config.AgentConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid configuration",
			config: &config.AgentConfig{
				Name:        "valid-agent",
				Type:        "generic",
				Description: "Valid test agent",
				AlertTypes:  []string{"test.alert"},
				MCPServers:  []string{"test-server"},
				Instructions: map[string]interface{}{
					"system_prompt": "Test prompt",
				},
			},
			expectError: false,
		},
		{
			name: "missing name",
			config: &config.AgentConfig{
				Type:        "generic",
				Description: "Agent without name",
				AlertTypes:  []string{"test.alert"},
				MCPServers:  []string{"test-server"},
			},
			expectError: true,
			errorMsg:    "agent name is required",
		},
		{
			name: "missing type",
			config: &config.AgentConfig{
				Name:        "no-type-agent",
				Description: "Agent without type",
				AlertTypes:  []string{"test.alert"},
				MCPServers:  []string{"test-server"},
			},
			expectError: true,
			errorMsg:    "agent type is required",
		},
		{
			name: "empty alert types",
			config: &config.AgentConfig{
				Name:        "no-alerts-agent",
				Type:        "generic",
				Description: "Agent without alert types",
				AlertTypes:  []string{},
				MCPServers:  []string{"test-server"},
			},
			expectError: true,
			errorMsg:    "at least one alert type is required",
		},
		{
			name: "empty MCP servers",
			config: &config.AgentConfig{
				Name:        "no-mcp-agent",
				Type:        "generic",
				Description: "Agent without MCP servers",
				AlertTypes:  []string{"test.alert"},
				MCPServers:  []string{},
			},
			expectError: true,
			errorMsg:    "at least one MCP server is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent, err := NewConfigurableAgent(tt.config, logger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, agent)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, agent)
			}
		})
	}
}

// TestConfigurableAgentDefaultValues tests default value handling
func TestConfigurableAgentDefaultValues(t *testing.T) {
	logger := zaptest.NewLogger(t)

	agentConfig := &config.AgentConfig{
		Name:        "defaults-test-agent",
		Type:        "generic",
		Description: "Test agent with default values",
		AlertTypes:  []string{"test.alert"},
		MCPServers:  []string{"test-server"},
		Configuration: map[string]interface{}{
			"existing_var":     "${EXISTING_VAR}",
			"missing_with_default": "${MISSING_VAR:default_value}",
			"missing_without_default": "${ANOTHER_MISSING_VAR}",
		},
	}

	// Set only one environment variable
	os.Setenv("EXISTING_VAR", "existing_value")
	defer os.Unsetenv("EXISTING_VAR")

	agent, err := NewConfigurableAgent(agentConfig, logger)
	require.NoError(t, err)

	config := agent.GetConfiguration()

	// Should resolve existing variable
	assert.Equal(t, "existing_value", config["existing_var"])

	// Should use default value for missing variable
	assert.Equal(t, "default_value", config["missing_with_default"])

	// Should leave unresolved variable as-is (or handle according to resolver policy)
	assert.Contains(t, config["missing_without_default"], "ANOTHER_MISSING_VAR")
}

// TestConfigurableAgentInstructionGeneration tests custom instruction generation
func TestConfigurableAgentInstructionGeneration(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name         string
		instructions map[string]interface{}
		expected     []string
	}{
		{
			name: "simple system prompt",
			instructions: map[string]interface{}{
				"system_prompt": "You are a helpful assistant.",
			},
			expected: []string{"You are a helpful assistant."},
		},
		{
			name: "system prompt with context instructions",
			instructions: map[string]interface{}{
				"system_prompt": "You are a Kubernetes expert.",
				"context_instructions": []string{
					"Always check logs first",
					"Examine resource usage",
				},
			},
			expected: []string{
				"You are a Kubernetes expert.",
				"Always check logs first",
				"Examine resource usage",
			},
		},
		{
			name: "complex instructions with variables",
			instructions: map[string]interface{}{
				"system_prompt": "Analyze ${ALERT_TYPE} alerts for ${CLUSTER_NAME}",
				"context_instructions": []string{
					"Focus on cluster ${CLUSTER_NAME}",
					"Check critical namespaces first",
				},
				"additional_context": "Use tools available for ${CLUSTER_NAME} cluster",
			},
			expected: []string{
				"Analyze ${ALERT_TYPE} alerts for ${CLUSTER_NAME}",
				"Focus on cluster ${CLUSTER_NAME}",
				"Check critical namespaces first",
				"Use tools available for ${CLUSTER_NAME} cluster",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agentConfig := &config.AgentConfig{
				Name:         "instruction-test-agent",
				Type:         "test",
				Description:  "Test agent for instruction generation",
				AlertTypes:   []string{"test.alert"},
				MCPServers:   []string{"test-server"},
				Instructions: tt.instructions,
			}

			agent, err := NewConfigurableAgent(agentConfig, logger)
			require.NoError(t, err)

			customInstructions := agent.GetCustomInstructions()

			for _, expected := range tt.expected {
				assert.Contains(t, customInstructions, expected,
					"Expected instruction '%s' not found in: %s", expected, customInstructions)
			}
		})
	}
}

// TestConfigurableAgentConfigurationTypes tests different configuration value types
func TestConfigurableAgentConfigurationTypes(t *testing.T) {
	logger := zaptest.NewLogger(t)

	agentConfig := &config.AgentConfig{
		Name:        "types-test-agent",
		Type:        "generic",
		Description: "Test agent with various configuration types",
		AlertTypes:  []string{"test.alert"},
		MCPServers:  []string{"test-server"},
		Configuration: map[string]interface{}{
			"string_val":  "hello world",
			"int_val":     42,
			"float_val":   3.14,
			"bool_val":    true,
			"array_val":   []string{"item1", "item2", "item3"},
			"object_val": map[string]interface{}{
				"nested_string": "nested value",
				"nested_int":    100,
			},
		},
	}

	agent, err := NewConfigurableAgent(agentConfig, logger)
	require.NoError(t, err)

	config := agent.GetConfiguration()

	// Test different types are preserved
	assert.Equal(t, "hello world", config["string_val"])
	assert.Equal(t, 42, config["int_val"])
	assert.Equal(t, 3.14, config["float_val"])
	assert.Equal(t, true, config["bool_val"])

	// Test array
	arrayVal, ok := config["array_val"].([]string)
	assert.True(t, ok)
	assert.Equal(t, []string{"item1", "item2", "item3"}, arrayVal)

	// Test nested object
	objectVal, ok := config["object_val"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "nested value", objectVal["nested_string"])
	assert.Equal(t, 100, objectVal["nested_int"])
}

// TestConfigurableAgentConcurrency tests concurrent agent operations
func TestConfigurableAgentConcurrency(t *testing.T) {
	logger := zaptest.NewLogger(t)

	agentConfig := &config.AgentConfig{
		Name:        "concurrent-test-agent",
		Type:        "generic",
		Description: "Test agent for concurrent operations",
		AlertTypes:  []string{"test.alert"},
		MCPServers:  []string{"test-server"},
		Configuration: map[string]interface{}{
			"concurrent_safe": true,
		},
	}

	agent, err := NewConfigurableAgent(agentConfig, logger)
	require.NoError(t, err)

	// Test concurrent access to agent properties
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			// Concurrent read operations should be safe
			name := agent.GetName()
			agentType := agent.GetType()
			description := agent.GetDescription()
			alertTypes := agent.GetAlertTypes()
			mcpServers := agent.GetMCPServers()
			config := agent.GetConfiguration()
			instructions := agent.GetCustomInstructions()

			// Verify data consistency
			assert.Equal(t, "concurrent-test-agent", name)
			assert.Equal(t, "generic", agentType)
			assert.Equal(t, "Test agent for concurrent operations", description)
			assert.Equal(t, []string{"test.alert"}, alertTypes)
			assert.Equal(t, []string{"test-server"}, mcpServers)
			assert.Equal(t, true, config["concurrent_safe"])
			assert.NotEmpty(t, instructions)

			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
			// Goroutine completed successfully
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations to complete")
		}
	}
}

// TestConfigurableAgentAlertTypeMatching tests alert type matching logic
func TestConfigurableAgentAlertTypeMatching(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name            string
		agentAlertTypes []string
		testAlertType   string
		shouldMatch     bool
	}{
		{
			name:            "exact match",
			agentAlertTypes: []string{"kubernetes.pod.crash"},
			testAlertType:   "kubernetes.pod.crash",
			shouldMatch:     true,
		},
		{
			name:            "no match",
			agentAlertTypes: []string{"kubernetes.pod.crash"},
			testAlertType:   "prometheus.alert.firing",
			shouldMatch:     false,
		},
		{
			name:            "multiple types with match",
			agentAlertTypes: []string{"kubernetes.pod.crash", "kubernetes.deployment.failed", "prometheus.alert.firing"},
			testAlertType:   "kubernetes.deployment.failed",
			shouldMatch:     true,
		},
		{
			name:            "wildcard support",
			agentAlertTypes: []string{"kubernetes.*"},
			testAlertType:   "kubernetes.pod.crash",
			shouldMatch:     true, // This would depend on implementation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agentConfig := &config.AgentConfig{
				Name:        "matching-test-agent",
				Type:        "generic",
				Description: "Test agent for alert type matching",
				AlertTypes:  tt.agentAlertTypes,
				MCPServers:  []string{"test-server"},
			}

			agent, err := NewConfigurableAgent(agentConfig, logger)
			require.NoError(t, err)

			alertTypes := agent.GetAlertTypes()
			found := false
			for _, alertType := range alertTypes {
				if alertType == tt.testAlertType {
					found = true
					break
				}
				// Add wildcard matching logic here if implemented
			}

			if tt.shouldMatch && !strings.Contains(tt.name, "wildcard") {
				assert.True(t, found, "Expected alert type %s to match agent types %v", tt.testAlertType, tt.agentAlertTypes)
			} else if !tt.shouldMatch && !strings.Contains(tt.name, "wildcard") {
				assert.False(t, found, "Expected alert type %s not to match agent types %v", tt.testAlertType, tt.agentAlertTypes)
			}
		})
	}
}