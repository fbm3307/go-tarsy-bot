package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestAgentLoaderBasicFunctionality tests basic agent loading from YAML
func TestAgentLoaderBasicFunctionality(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a test YAML content
	yamlContent := `
agents:
  - name: "test-agent"
    type: "kubernetes"
    description: "Test Kubernetes agent"
    alert_types:
      - "kubernetes.pod.crash"
      - "kubernetes.deployment.failed"
    mcp_servers:
      - "kubernetes-server"
      - "monitoring-server"
    configuration:
      cluster_name: "test-cluster"
      namespace: "default"
      timeout: 30
    instructions:
      system_prompt: "You are a Kubernetes expert."
      context_instructions:
        - "Check pod logs first"
        - "Examine resource usage"
`

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "test-agents-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpFile.Close()

	// Test loading agents
	loader := NewAgentLoader(logger)
	agents, err := loader.LoadAgentsFromFile(tmpFile.Name())
	require.NoError(t, err)
	require.Len(t, agents, 1)

	agent := agents[0]
	assert.Equal(t, "test-agent", agent.Name)
	assert.Equal(t, "kubernetes", agent.Type)
	assert.Equal(t, "Test Kubernetes agent", agent.Description)
	assert.Equal(t, []string{"kubernetes.pod.crash", "kubernetes.deployment.failed"}, agent.AlertTypes)
	assert.Equal(t, []string{"kubernetes-server", "monitoring-server"}, agent.MCPServers)

	// Test configuration
	assert.Equal(t, "test-cluster", agent.Configuration["cluster_name"])
	assert.Equal(t, "default", agent.Configuration["namespace"])
	assert.Equal(t, 30, agent.Configuration["timeout"])

	// Test instructions
	instructions := agent.Instructions
	assert.Equal(t, "You are a Kubernetes expert.", instructions["system_prompt"])

	contextInstructions, ok := instructions["context_instructions"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, contextInstructions, 2)
	assert.Equal(t, "Check pod logs first", contextInstructions[0])
	assert.Equal(t, "Examine resource usage", contextInstructions[1])
}

// TestAgentLoaderVariableResolution tests environment variable resolution
func TestAgentLoaderVariableResolution(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Set test environment variables
	os.Setenv("TEST_CLUSTER", "production-cluster")
	os.Setenv("TEST_NAMESPACE", "production")
	os.Setenv("TEST_TIMEOUT", "60")
	defer func() {
		os.Unsetenv("TEST_CLUSTER")
		os.Unsetenv("TEST_NAMESPACE")
		os.Unsetenv("TEST_TIMEOUT")
	}()

	yamlContent := `
agents:
  - name: "variable-test-agent"
    type: "test"
    description: "Agent with variables"
    alert_types:
      - "test.alert"
    mcp_servers:
      - "test-server"
    configuration:
      cluster_name: "${TEST_CLUSTER}"
      namespace: "${TEST_NAMESPACE:default}"
      timeout: "${TEST_TIMEOUT:30}"
      missing_var: "${MISSING_VAR:fallback_value}"
      unresolved_var: "${COMPLETELY_MISSING}"
    instructions:
      system_prompt: "Working on cluster ${TEST_CLUSTER} in namespace ${TEST_NAMESPACE}"
`

	tmpFile, err := os.CreateTemp("", "test-vars-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpFile.Close()

	loader := NewAgentLoader(logger)
	agents, err := loader.LoadAgentsFromFile(tmpFile.Name())
	require.NoError(t, err)
	require.Len(t, agents, 1)

	agent := agents[0]
	config := agent.Configuration

	// Test resolved variables
	assert.Equal(t, "production-cluster", config["cluster_name"])
	assert.Equal(t, "production", config["namespace"])
	assert.Equal(t, "60", config["timeout"]) // Note: YAML parsing may preserve string type

	// Test default value
	assert.Equal(t, "fallback_value", config["missing_var"])

	// Test unresolved variable (should remain as-is or be handled by resolver policy)
	assert.Contains(t, config["unresolved_var"], "COMPLETELY_MISSING")

	// Test instructions with variables
	instructions := agent.Instructions
	systemPrompt := instructions["system_prompt"].(string)
	assert.Contains(t, systemPrompt, "production-cluster")
	assert.Contains(t, systemPrompt, "production")
}

// TestAgentLoaderMultipleAgents tests loading multiple agents from one file
func TestAgentLoaderMultipleAgents(t *testing.T) {
	logger := zaptest.NewLogger(t)

	yamlContent := `
agents:
  - name: "agent-1"
    type: "kubernetes"
    description: "First agent"
    alert_types:
      - "k8s.pod.crash"
    mcp_servers:
      - "k8s-server"
    instructions:
      system_prompt: "First agent prompt"

  - name: "agent-2"
    type: "monitoring"
    description: "Second agent"
    alert_types:
      - "prometheus.alert"
    mcp_servers:
      - "prometheus-server"
    configuration:
      url: "http://localhost:9090"
    instructions:
      system_prompt: "Second agent prompt"

  - name: "agent-3"
    type: "database"
    description: "Third agent"
    alert_types:
      - "db.connection.failed"
      - "db.query.slow"
    mcp_servers:
      - "database-server"
      - "metrics-server"
    instructions:
      system_prompt: "Third agent prompt"
`

	tmpFile, err := os.CreateTemp("", "test-multi-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpFile.Close()

	loader := NewAgentLoader(logger)
	agents, err := loader.LoadAgentsFromFile(tmpFile.Name())
	require.NoError(t, err)
	require.Len(t, agents, 3)

	// Test first agent
	assert.Equal(t, "agent-1", agents[0].Name)
	assert.Equal(t, "kubernetes", agents[0].Type)
	assert.Equal(t, []string{"k8s.pod.crash"}, agents[0].AlertTypes)
	assert.Equal(t, []string{"k8s-server"}, agents[0].MCPServers)

	// Test second agent
	assert.Equal(t, "agent-2", agents[1].Name)
	assert.Equal(t, "monitoring", agents[1].Type)
	assert.Equal(t, []string{"prometheus.alert"}, agents[1].AlertTypes)
	assert.Equal(t, "http://localhost:9090", agents[1].Configuration["url"])

	// Test third agent
	assert.Equal(t, "agent-3", agents[2].Name)
	assert.Equal(t, "database", agents[2].Type)
	assert.Equal(t, []string{"db.connection.failed", "db.query.slow"}, agents[2].AlertTypes)
	assert.Equal(t, []string{"database-server", "metrics-server"}, agents[2].MCPServers)
}

// TestAgentLoaderValidation tests agent configuration validation
func TestAgentLoaderValidation(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name        string
		yamlContent string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid agent",
			yamlContent: `
agents:
  - name: "valid-agent"
    type: "test"
    description: "Valid agent"
    alert_types:
      - "test.alert"
    mcp_servers:
      - "test-server"
`,
			expectError: false,
		},
		{
			name: "missing name",
			yamlContent: `
agents:
  - type: "test"
    description: "Agent without name"
    alert_types:
      - "test.alert"
    mcp_servers:
      - "test-server"
`,
			expectError: true,
			errorMsg:    "name",
		},
		{
			name: "missing type",
			yamlContent: `
agents:
  - name: "no-type-agent"
    description: "Agent without type"
    alert_types:
      - "test.alert"
    mcp_servers:
      - "test-server"
`,
			expectError: true,
			errorMsg:    "type",
		},
		{
			name: "empty alert types",
			yamlContent: `
agents:
  - name: "no-alerts-agent"
    type: "test"
    description: "Agent without alerts"
    alert_types: []
    mcp_servers:
      - "test-server"
`,
			expectError: true,
			errorMsg:    "alert_types",
		},
		{
			name: "missing mcp servers",
			yamlContent: `
agents:
  - name: "no-mcp-agent"
    type: "test"
    description: "Agent without MCP servers"
    alert_types:
      - "test.alert"
`,
			expectError: true,
			errorMsg:    "mcp_servers",
		},
		{
			name: "invalid yaml",
			yamlContent: `
agents:
  - name: "invalid-yaml"
    type: test
    description: "Missing quotes
    alert_types:
      - "test.alert"
`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "test-validation-*.yaml")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.yamlContent)
			require.NoError(t, err)
			tmpFile.Close()

			loader := NewAgentLoader(logger)
			agents, err := loader.LoadAgentsFromFile(tmpFile.Name())

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, agents)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, agents)
			}
		})
	}
}

// TestAgentLoaderFileHandling tests file handling edge cases
func TestAgentLoaderFileHandling(t *testing.T) {
	logger := zaptest.NewLogger(t)
	loader := NewAgentLoader(logger)

	tests := []struct {
		name        string
		setup       func() string
		expectError bool
	}{
		{
			name: "non-existent file",
			setup: func() string {
				return "/path/that/does/not/exist.yaml"
			},
			expectError: true,
		},
		{
			name: "empty file",
			setup: func() string {
				tmpFile, _ := os.CreateTemp("", "empty-*.yaml")
				tmpFile.Close()
				return tmpFile.Name()
			},
			expectError: false, // Should return empty slice
		},
		{
			name: "file with only comments",
			setup: func() string {
				tmpFile, _ := os.CreateTemp("", "comments-*.yaml")
				tmpFile.WriteString("# This is a comment\n# Another comment\n")
				tmpFile.Close()
				return tmpFile.Name()
			},
			expectError: false, // Should return empty slice
		},
		{
			name: "directory instead of file",
			setup: func() string {
				tmpDir, _ := os.MkdirTemp("", "test-dir-*")
				return tmpDir
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setup()
			defer func() {
				if info, err := os.Stat(filePath); err == nil {
					if info.IsDir() {
						os.RemoveAll(filePath)
					} else {
						os.Remove(filePath)
					}
				}
			}()

			agents, err := loader.LoadAgentsFromFile(filePath)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, agents)
			}
		})
	}
}

// TestAgentLoaderComplexConfiguration tests complex nested configuration
func TestAgentLoaderComplexConfiguration(t *testing.T) {
	logger := zaptest.NewLogger(t)

	yamlContent := `
agents:
  - name: "complex-agent"
    type: "complex"
    description: "Agent with complex nested configuration"
    alert_types:
      - "complex.alert"
    mcp_servers:
      - "complex-server"
    configuration:
      string_value: "hello world"
      int_value: 42
      float_value: 3.14159
      bool_value: true
      array_value:
        - "item1"
        - "item2"
        - "item3"
      object_value:
        nested_string: "nested value"
        nested_int: 100
        deeply_nested:
          level3_string: "deep value"
          level3_array:
            - "deep1"
            - "deep2"
      environment_vars:
        cluster: "${CLUSTER_NAME:default-cluster}"
        region: "${AWS_REGION:us-west-2}"
        debug: "${DEBUG_MODE:false}"
    instructions:
      system_prompt: |
        You are a complex agent with the following configuration:
        - Cluster: ${CLUSTER_NAME}
        - Region: ${AWS_REGION}
        - Debug mode: ${DEBUG_MODE}

        Handle complex scenarios with nested data structures.
      context_instructions:
        - "Process nested object data"
        - "Handle array configurations"
        - "Resolve environment variables"
      advanced_config:
        retry_strategy:
          max_attempts: 3
          backoff_factor: 2.0
          initial_delay: "1s"
        resource_limits:
          cpu: "500m"
          memory: "1Gi"
          storage: "10Gi"
`

	// Set some environment variables for testing
	os.Setenv("CLUSTER_NAME", "test-cluster")
	os.Setenv("DEBUG_MODE", "true")
	defer func() {
		os.Unsetenv("CLUSTER_NAME")
		os.Unsetenv("DEBUG_MODE")
	}()

	tmpFile, err := os.CreateTemp("", "test-complex-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpFile.Close()

	loader := NewAgentLoader(logger)
	agents, err := loader.LoadAgentsFromFile(tmpFile.Name())
	require.NoError(t, err)
	require.Len(t, agents, 1)

	agent := agents[0]
	config := agent.Configuration

	// Test primitive types
	assert.Equal(t, "hello world", config["string_value"])
	assert.Equal(t, 42, config["int_value"])
	assert.Equal(t, 3.14159, config["float_value"])
	assert.Equal(t, true, config["bool_value"])

	// Test array
	arrayValue, ok := config["array_value"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, arrayValue, 3)
	assert.Equal(t, "item1", arrayValue[0])

	// Test nested object
	objectValue, ok := config["object_value"].(map[interface{}]interface{})
	assert.True(t, ok)
	assert.Equal(t, "nested value", objectValue["nested_string"])
	assert.Equal(t, 100, objectValue["nested_int"])

	// Test deeply nested object
	deeplyNested, ok := objectValue["deeply_nested"].(map[interface{}]interface{})
	assert.True(t, ok)
	assert.Equal(t, "deep value", deeplyNested["level3_string"])

	// Test environment variable resolution
	envVars, ok := config["environment_vars"].(map[interface{}]interface{})
	assert.True(t, ok)
	assert.Equal(t, "test-cluster", envVars["cluster"])
	assert.Equal(t, "us-west-2", envVars["region"]) // Should use default
	assert.Equal(t, "true", envVars["debug"])

	// Test instructions with variable resolution
	instructions := agent.Instructions
	systemPrompt := instructions["system_prompt"].(string)
	assert.Contains(t, systemPrompt, "test-cluster")
	assert.Contains(t, systemPrompt, "true")
}

// TestAgentLoaderFromDirectory tests loading agents from a directory
func TestAgentLoaderFromDirectory(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create temporary directory structure
	tmpDir, err := os.MkdirTemp("", "test-agents-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create multiple YAML files
	files := map[string]string{
		"k8s-agents.yaml": `
agents:
  - name: "k8s-agent-1"
    type: "kubernetes"
    description: "First K8s agent"
    alert_types: ["k8s.pod.crash"]
    mcp_servers: ["k8s-server"]
  - name: "k8s-agent-2"
    type: "kubernetes"
    description: "Second K8s agent"
    alert_types: ["k8s.deployment.failed"]
    mcp_servers: ["k8s-server"]
`,
		"monitoring-agents.yaml": `
agents:
  - name: "prometheus-agent"
    type: "monitoring"
    description: "Prometheus agent"
    alert_types: ["prometheus.alert"]
    mcp_servers: ["prometheus-server"]
`,
		"database-agents.yaml": `
agents:
  - name: "postgres-agent"
    type: "database"
    description: "PostgreSQL agent"
    alert_types: ["postgres.connection.failed"]
    mcp_servers: ["postgres-server"]
`,
		"not-an-agent.txt": "This is not a YAML file",
		"empty.yaml":       "", // Empty YAML file
	}

	for filename, content := range files {
		filePath := filepath.Join(tmpDir, filename)
		err := os.WriteFile(filePath, []byte(content), 0644)
		require.NoError(t, err)
	}

	loader := NewAgentLoader(logger)
	agents, err := loader.LoadAgentsFromDirectory(tmpDir)
	require.NoError(t, err)

	// Should load 4 agents from 3 YAML files (ignoring .txt and empty files)
	assert.Len(t, agents, 4)

	// Verify we got all expected agents
	agentNames := make([]string, len(agents))
	for i, agent := range agents {
		agentNames[i] = agent.Name
	}

	expectedNames := []string{"k8s-agent-1", "k8s-agent-2", "prometheus-agent", "postgres-agent"}
	for _, expectedName := range expectedNames {
		assert.Contains(t, agentNames, expectedName)
	}
}

// TestAgentLoaderConcurrency tests concurrent loading operations
func TestAgentLoaderConcurrency(t *testing.T) {
	logger := zaptest.NewLogger(t)

	yamlContent := `
agents:
  - name: "concurrent-test-agent"
    type: "test"
    description: "Agent for concurrency testing"
    alert_types: ["test.concurrent"]
    mcp_servers: ["test-server"]
`

	tmpFile, err := os.CreateTemp("", "test-concurrent-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpFile.Close()

	loader := NewAgentLoader(logger)

	// Test concurrent loading
	const numGoroutines = 10
	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			agents, err := loader.LoadAgentsFromFile(tmpFile.Name())
			if err != nil {
				results <- err
				return
			}
			if len(agents) != 1 {
				results <- assert.AnError
				return
			}
			if agents[0].Name != "concurrent-test-agent" {
				results <- assert.AnError
				return
			}
			results <- nil
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		select {
		case err := <-results:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
}