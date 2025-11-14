package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestConfigValidator_ValidateSystemConfiguration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator := NewConfigValidator(logger)

	t.Run("ValidConfiguration", func(t *testing.T) {
		// Set required environment variables
		os.Setenv("OPENAI_API_KEY", "test-key")
		os.Setenv("DEFAULT_LLM_PROVIDER", "openai")
		defer func() {
			os.Unsetenv("OPENAI_API_KEY")
			os.Unsetenv("DEFAULT_LLM_PROVIDER")
		}()

		result := validator.ValidateSystemConfiguration()
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
		assert.NotNil(t, result.Summary)
	})

	t.Run("MissingRequiredEnvironmentVariables", func(t *testing.T) {
		// Ensure required env vars are not set
		os.Unsetenv("OPENAI_API_KEY")
		os.Unsetenv("DEFAULT_LLM_PROVIDER")

		result := validator.ValidateSystemConfiguration()
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
		assert.True(t, result.Summary.TotalErrors > 0)

		// Check that environment component has errors
		envComponent, exists := result.Summary.Components["environment"]
		assert.True(t, exists)
		assert.False(t, envComponent.Valid)
		assert.True(t, envComponent.Errors > 0)
	})

	t.Run("InvalidLLMProvider", func(t *testing.T) {
		os.Setenv("OPENAI_API_KEY", "test-key")
		os.Setenv("DEFAULT_LLM_PROVIDER", "invalid-provider")
		defer func() {
			os.Unsetenv("OPENAI_API_KEY")
			os.Unsetenv("DEFAULT_LLM_PROVIDER")
		}()

		result := validator.ValidateSystemConfiguration()
		assert.False(t, result.Valid)

		// Find the LLM provider error
		found := false
		for _, err := range result.Errors {
			if err.Component == "environment" && err.Field == "DEFAULT_LLM_PROVIDER" {
				found = true
				assert.Contains(t, err.Message, "Invalid LLM provider")
			}
		}
		assert.True(t, found)
	})
}

func TestConfigValidator_ValidateEnvironmentVariables(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator := NewConfigValidator(logger)

	tests := []struct {
		name     string
		envVars  map[string]string
		wantErr  bool
		errField string
	}{
		{
			name: "ValidEnvironmentVariables",
			envVars: map[string]string{
				"OPENAI_API_KEY":        "test-key",
				"DEFAULT_LLM_PROVIDER":  "openai",
				"LOG_LEVEL":             "debug",
				"PORT":                  "8080",
				"PIPELINE_MAX_WORKERS":  "4",
				"PIPELINE_TIMEOUT":      "30s",
				"HEALTH_CHECK_INTERVAL": "30s",
			},
			wantErr: false,
		},
		{
			name: "InvalidLogLevel",
			envVars: map[string]string{
				"OPENAI_API_KEY":       "test-key",
				"DEFAULT_LLM_PROVIDER": "openai",
				"LOG_LEVEL":            "invalid",
			},
			wantErr:  true,
			errField: "LOG_LEVEL",
		},
		{
			name: "InvalidPort",
			envVars: map[string]string{
				"OPENAI_API_KEY":       "test-key",
				"DEFAULT_LLM_PROVIDER": "openai",
				"PORT":                 "99999",
			},
			wantErr:  true,
			errField: "PORT",
		},
		{
			name: "InvalidTimeout",
			envVars: map[string]string{
				"OPENAI_API_KEY":       "test-key",
				"DEFAULT_LLM_PROVIDER": "openai",
				"PIPELINE_TIMEOUT":     "invalid-duration",
			},
			wantErr:  true,
			errField: "PIPELINE_TIMEOUT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			for _, key := range []string{
				"OPENAI_API_KEY", "DEFAULT_LLM_PROVIDER", "LOG_LEVEL", "PORT",
				"PIPELINE_MAX_WORKERS", "PIPELINE_TIMEOUT", "HEALTH_CHECK_INTERVAL",
			} {
				os.Unsetenv(key)
			}

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			result := &ValidationResult{
				Valid:   true,
				Summary: ValidationSummary{Components: make(map[string]ComponentValidation)},
			}

			validator.validateEnvironmentVariables(result)

			if tt.wantErr {
				// Check if errors were added for the expected field
				found := false
				for _, err := range result.Errors {
					if err.Field == tt.errField {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected error for field %s", tt.errField)

				// Check that the environment component has errors
				envComponent := result.Summary.Components["environment"]
				assert.True(t, envComponent.Errors > 0, "Environment component should have errors")
			} else {
				// For valid cases, check that no errors were added for the specific fields being tested
				for _, err := range result.Errors {
					if err.Component == "environment" {
						// Only fail if it's an error for one of the fields we're testing
						for key := range tt.envVars {
							if err.Field == key {
								t.Errorf("Unexpected error for field %s: %s", err.Field, err.Message)
							}
						}
					}
				}
			}
		})
	}
}

func TestConfigValidator_ValidateAgentConfigurations(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator := NewConfigValidator(logger)

	t.Run("NoAgentConfigFile", func(t *testing.T) {
		// Change to a temporary directory where no agents.yaml exists
		originalDir, _ := os.Getwd()
		tmpDir := t.TempDir()
		os.Chdir(tmpDir)
		defer os.Chdir(originalDir)

		result := &ValidationResult{
			Valid:   true,
			Summary: ValidationSummary{Components: make(map[string]ComponentValidation)},
		}

		validator.validateAgentConfigurations(result)

		agentComponent := result.Summary.Components["agents"]
		assert.True(t, agentComponent.Valid)
		assert.True(t, agentComponent.Warnings > 0) // Should warn about missing config
	})

	t.Run("ValidAgentConfigFile", func(t *testing.T) {
		// Create temporary directory and agent config
		tmpDir := t.TempDir()
		configDir := filepath.Join(tmpDir, "config")
		os.MkdirAll(configDir, 0755)

		agentConfig := `
agents:
  test-agent:
    alert_types:
      - test-alert
      - monitoring-alert
    mcp_servers:
      - filesystem
      - kubectl
    instructions: "Test agent instructions"
    settings:
      max_tokens: 1000
      temperature: 0.7
      max_iterations: 5
`
		configPath := filepath.Join(configDir, "agents.yaml")
		err := os.WriteFile(configPath, []byte(agentConfig), 0644)
		require.NoError(t, err)

		originalDir, _ := os.Getwd()
		os.Chdir(tmpDir)
		defer os.Chdir(originalDir)

		result := &ValidationResult{
			Valid:   true,
			Summary: ValidationSummary{Components: make(map[string]ComponentValidation)},
		}

		validator.validateAgentConfigurations(result)

		agentComponent := result.Summary.Components["agents"]
		assert.True(t, agentComponent.Valid)
		assert.Equal(t, 0, agentComponent.Errors)
	})

	t.Run("InvalidAgentConfigFile", func(t *testing.T) {
		// Create temporary directory and invalid agent config
		tmpDir := t.TempDir()
		configDir := filepath.Join(tmpDir, "config")
		os.MkdirAll(configDir, 0755)

		invalidConfig := `
agents:
  bad-agent:
    alert_types: []  # Empty alert types
    mcp_servers: []  # Empty MCP servers
    instructions: "" # Empty instructions
    settings:
      max_tokens: -1  # Invalid token count
      temperature: 5.0  # Invalid temperature
`
		configPath := filepath.Join(configDir, "agents.yaml")
		err := os.WriteFile(configPath, []byte(invalidConfig), 0644)
		require.NoError(t, err)

		originalDir, _ := os.Getwd()
		os.Chdir(tmpDir)
		defer os.Chdir(originalDir)

		result := &ValidationResult{
			Valid:   true,
			Summary: ValidationSummary{Components: make(map[string]ComponentValidation)},
		}

		validator.validateAgentConfigurations(result)

		agentComponent := result.Summary.Components["agents"]
		assert.False(t, agentComponent.Valid)
		assert.True(t, agentComponent.Errors > 0)
		assert.True(t, agentComponent.Warnings > 0)
	})

	t.Run("InvalidYAMLSyntax", func(t *testing.T) {
		// Create temporary directory and invalid YAML
		tmpDir := t.TempDir()
		configDir := filepath.Join(tmpDir, "config")
		os.MkdirAll(configDir, 0755)

		invalidYAML := `
agents:
  test-agent:
    alert_types: [
      - invalid-yaml-syntax
`
		configPath := filepath.Join(configDir, "agents.yaml")
		err := os.WriteFile(configPath, []byte(invalidYAML), 0644)
		require.NoError(t, err)

		originalDir, _ := os.Getwd()
		os.Chdir(tmpDir)
		defer os.Chdir(originalDir)

		result := &ValidationResult{
			Valid:   true,
			Summary: ValidationSummary{Components: make(map[string]ComponentValidation)},
		}

		validator.validateAgentConfigurations(result)

		agentComponent := result.Summary.Components["agents"]
		assert.False(t, agentComponent.Valid)
		assert.True(t, agentComponent.Errors > 0)
	})
}

func TestConfigValidator_ValidateAgentSettings(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator := NewConfigValidator(logger)

	tests := []struct {
		name     string
		settings map[string]interface{}
		wantErr  bool
		errMsg   string
	}{
		{
			name: "ValidSettings",
			settings: map[string]interface{}{
				"max_tokens":     1000,
				"temperature":    0.7,
				"max_iterations": 5,
			},
			wantErr: false,
		},
		{
			name: "InvalidMaxTokens",
			settings: map[string]interface{}{
				"max_tokens": -1,
			},
			wantErr: true,
			errMsg:  "max_tokens must be between 1 and 32000",
		},
		{
			name: "InvalidTemperature",
			settings: map[string]interface{}{
				"temperature": 5.0,
			},
			wantErr: true,
			errMsg:  "temperature must be between 0.0 and 2.0",
		},
		{
			name: "InvalidMaxIterations",
			settings: map[string]interface{}{
				"max_iterations": 0,
			},
			wantErr: true,
			errMsg:  "max_iterations must be between 1 and 20",
		},
		{
			name: "WrongTypeMaxTokens",
			settings: map[string]interface{}{
				"max_tokens": "invalid",
			},
			wantErr: true,
			errMsg:  "max_tokens must be an integer",
		},
		{
			name: "WrongTypeTemperature",
			settings: map[string]interface{}{
				"temperature": "invalid",
			},
			wantErr: true,
			errMsg:  "temperature must be a number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{
				Valid:   true,
				Summary: ValidationSummary{Components: make(map[string]ComponentValidation)},
			}
			validation := &ComponentValidation{Valid: true}

			err := validator.validateAgentSettings(tt.settings, "test-agent", result, validation)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidator_ValidateStartupConfiguration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator := NewConfigValidator(logger)

	t.Run("ValidStartupConfiguration", func(t *testing.T) {
		// Set required environment variables
		os.Setenv("OPENAI_API_KEY", "test-key")
		os.Setenv("DEFAULT_LLM_PROVIDER", "openai")
		defer func() {
			os.Unsetenv("OPENAI_API_KEY")
			os.Unsetenv("DEFAULT_LLM_PROVIDER")
		}()

		err := validator.ValidateStartupConfiguration()
		assert.NoError(t, err)
	})

	t.Run("InvalidStartupConfiguration", func(t *testing.T) {
		// Ensure required env vars are not set
		os.Unsetenv("OPENAI_API_KEY")
		os.Unsetenv("DEFAULT_LLM_PROVIDER")

		err := validator.ValidateStartupConfiguration()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "configuration validation failed")
	})
}

func TestConfigValidator_ValidationHelpers(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator := NewConfigValidator(logger)

	t.Run("ValidateLogLevel", func(t *testing.T) {
		validLevels := []string{"debug", "info", "warn", "error"}
		for _, level := range validLevels {
			assert.NoError(t, validator.validateLogLevel(level))
		}

		assert.Error(t, validator.validateLogLevel("invalid"))
	})

	t.Run("ValidatePort", func(t *testing.T) {
		validPorts := []string{"80", "8080", "3000", "65535"}
		for _, port := range validPorts {
			assert.NoError(t, validator.validatePort(port))
		}

		invalidPorts := []string{"0", "65536", "invalid", "-1"}
		for _, port := range invalidPorts {
			assert.Error(t, validator.validatePort(port))
		}
	})

	t.Run("ValidatePositiveInteger", func(t *testing.T) {
		validInts := []string{"1", "10", "100", "1000"}
		for _, num := range validInts {
			assert.NoError(t, validator.validatePositiveInteger(num))
		}

		invalidInts := []string{"0", "-1", "invalid", ""}
		for _, num := range invalidInts {
			assert.Error(t, validator.validatePositiveInteger(num))
		}
	})

	t.Run("ValidateDuration", func(t *testing.T) {
		validDurations := []string{"1s", "30s", "5m", "1h", "24h"}
		for _, duration := range validDurations {
			assert.NoError(t, validator.validateDuration(duration))
		}

		invalidDurations := []string{"invalid", "", "30", "1x"}
		for _, duration := range invalidDurations {
			assert.Error(t, validator.validateDuration(duration))
		}
	})
}

func TestValidationResult(t *testing.T) {
	t.Run("ValidationResultStructure", func(t *testing.T) {
		result := &ValidationResult{
			Valid: true,
			Summary: ValidationSummary{
				TotalErrors:   0,
				TotalWarnings: 1,
				Components: map[string]ComponentValidation{
					"test": {
						Valid:    true,
						Errors:   0,
						Warnings: 1,
					},
				},
			},
		}

		assert.True(t, result.Valid)
		assert.Equal(t, 0, result.Summary.TotalErrors)
		assert.Equal(t, 1, result.Summary.TotalWarnings)
		assert.Contains(t, result.Summary.Components, "test")
	})
}

func TestComponentValidation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator := NewConfigValidator(logger)

	t.Run("AddError", func(t *testing.T) {
		result := &ValidationResult{
			Valid:   true,
			Summary: ValidationSummary{Components: make(map[string]ComponentValidation)},
		}

		validator.addError(result, "test", "field", "test error")

		assert.Len(t, result.Errors, 1)
		assert.Equal(t, "test", result.Errors[0].Component)
		assert.Equal(t, "field", result.Errors[0].Field)
		assert.Equal(t, "test error", result.Errors[0].Message)
		assert.Equal(t, "error", result.Errors[0].Level)
	})

	t.Run("AddWarning", func(t *testing.T) {
		result := &ValidationResult{
			Valid:   true,
			Summary: ValidationSummary{Components: make(map[string]ComponentValidation)},
		}

		validator.addWarning(result, "test", "field", "test warning")

		assert.Len(t, result.Warnings, 1)
		assert.Equal(t, "test", result.Warnings[0].Component)
		assert.Equal(t, "field", result.Warnings[0].Field)
		assert.Equal(t, "test warning", result.Warnings[0].Message)
	})
}

// Benchmark tests
func BenchmarkValidateSystemConfiguration(b *testing.B) {
	logger := zaptest.NewLogger(b)
	validator := NewConfigValidator(logger)

	// Set required environment variables
	os.Setenv("OPENAI_API_KEY", "test-key")
	os.Setenv("DEFAULT_LLM_PROVIDER", "openai")
	defer func() {
		os.Unsetenv("OPENAI_API_KEY")
		os.Unsetenv("DEFAULT_LLM_PROVIDER")
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := validator.ValidateSystemConfiguration()
		if !result.Valid {
			b.Fatalf("Expected valid configuration")
		}
	}
}

func BenchmarkValidateEnvironmentVariables(b *testing.B) {
	logger := zaptest.NewLogger(b)
	validator := NewConfigValidator(logger)

	// Set required environment variables
	os.Setenv("OPENAI_API_KEY", "test-key")
	os.Setenv("DEFAULT_LLM_PROVIDER", "openai")
	defer func() {
		os.Unsetenv("OPENAI_API_KEY")
		os.Unsetenv("DEFAULT_LLM_PROVIDER")
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := &ValidationResult{
			Valid:   true,
			Summary: ValidationSummary{Components: make(map[string]ComponentValidation)},
		}
		validator.validateEnvironmentVariables(result)
	}
}