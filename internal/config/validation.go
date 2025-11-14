package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// ValidationResult represents the result of configuration validation
type ValidationResult struct {
	Valid    bool                       `json:"valid"`
	Errors   []ConfigValidationError    `json:"errors,omitempty"`
	Warnings []ConfigValidationWarning  `json:"warnings,omitempty"`
	Summary  ValidationSummary          `json:"summary"`
}

// ConfigValidationError represents a configuration validation error
type ConfigValidationError struct {
	Component string `json:"component"`
	Field     string `json:"field"`
	Message   string `json:"message"`
	Level     string `json:"level"` // "error", "warning"
}

// ConfigValidationWarning represents a configuration validation warning
type ConfigValidationWarning struct {
	Component string `json:"component"`
	Field     string `json:"field"`
	Message   string `json:"message"`
}

// ValidationSummary provides a summary of validation results
type ValidationSummary struct {
	TotalErrors   int `json:"total_errors"`
	TotalWarnings int `json:"total_warnings"`
	Components    map[string]ComponentValidation `json:"components"`
}

// ComponentValidation tracks validation status for each component
type ComponentValidation struct {
	Valid    bool `json:"valid"`
	Errors   int  `json:"errors"`
	Warnings int  `json:"warnings"`
}

// ConfigValidator validates system configuration
type ConfigValidator struct {
	logger *zap.Logger
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator(logger *zap.Logger) *ConfigValidator {
	return &ConfigValidator{
		logger: logger,
	}
}

// ValidateSystemConfiguration validates the entire system configuration
func (v *ConfigValidator) ValidateSystemConfiguration() *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Summary: ValidationSummary{
			Components: make(map[string]ComponentValidation),
		},
	}

	v.logger.Info("Starting system configuration validation")

	// Validate environment variables
	v.validateEnvironmentVariables(result)

	// Validate agent configurations
	v.validateAgentConfigurations(result)

	// Validate MCP server configurations
	v.validateMCPConfigurations(result)

	// Validate pipeline configuration
	v.validatePipelineConfiguration(result)

	// Validate health check configuration
	v.validateHealthCheckConfiguration(result)

	// Validate API server configuration
	v.validateAPIServerConfiguration(result)

	// Update summary
	result.Summary.TotalErrors = len(result.Errors)
	result.Summary.TotalWarnings = len(result.Warnings)

	// Mark as invalid if any errors exist
	if result.Summary.TotalErrors > 0 {
		result.Valid = false
	}

	v.logger.Info("Configuration validation completed",
		zap.Bool("valid", result.Valid),
		zap.Int("errors", result.Summary.TotalErrors),
		zap.Int("warnings", result.Summary.TotalWarnings))

	return result
}

// validateEnvironmentVariables validates required and optional environment variables
func (v *ConfigValidator) validateEnvironmentVariables(result *ValidationResult) {
	component := "environment"
	validation := ComponentValidation{Valid: true}

	// Required environment variables
	requiredVars := map[string]string{
		"OPENAI_API_KEY":     "OpenAI API key for LLM integration",
		"DEFAULT_LLM_PROVIDER": "Default LLM provider (openai, google, xai)",
	}

	// Optional environment variables with defaults
	optionalVars := map[string]struct {
		description string
		defaultVal  string
		validator   func(string) error
	}{
		"LOG_LEVEL": {
			description: "Logging level",
			defaultVal:  "info",
			validator:   v.validateLogLevel,
		},
		"PORT": {
			description: "Server port",
			defaultVal:  "8080",
			validator:   v.validatePort,
		},
		"HOST": {
			description: "Server host",
			defaultVal:  "0.0.0.0",
			validator:   nil,
		},
		"PIPELINE_MAX_WORKERS": {
			description: "Maximum pipeline workers",
			defaultVal:  "4",
			validator:   v.validatePositiveInteger,
		},
		"PIPELINE_TIMEOUT": {
			description: "Pipeline job timeout",
			defaultVal:  "30s",
			validator:   v.validateDuration,
		},
		"HEALTH_CHECK_INTERVAL": {
			description: "Health check interval",
			defaultVal:  "30s",
			validator:   v.validateDuration,
		},
	}

	// Check required variables
	for varName, description := range requiredVars {
		value := os.Getenv(varName)
		if value == "" {
			v.addError(result, component, varName, fmt.Sprintf("Required environment variable missing: %s", description))
			validation.Errors++
			validation.Valid = false
		}
	}

	// Validate LLM provider
	provider := os.Getenv("DEFAULT_LLM_PROVIDER")
	if provider != "" {
		validProviders := []string{"openai", "google", "xai"}
		if !v.contains(validProviders, provider) {
			v.addError(result, component, "DEFAULT_LLM_PROVIDER", fmt.Sprintf("Invalid LLM provider '%s'. Valid options: %s", provider, strings.Join(validProviders, ", ")))
			validation.Errors++
			validation.Valid = false
		}
	}

	// Check optional variables
	for varName, config := range optionalVars {
		value := os.Getenv(varName)
		if value == "" {
			v.addWarning(result, component, varName, fmt.Sprintf("Using default value '%s' for %s", config.defaultVal, config.description))
			validation.Warnings++
		} else if config.validator != nil {
			if err := config.validator(value); err != nil {
				v.addError(result, component, varName, fmt.Sprintf("Invalid value '%s': %s", value, err.Error()))
				validation.Errors++
				validation.Valid = false
			}
		}
	}

	result.Summary.Components[component] = validation
}

// validateAgentConfigurations validates agent configuration files
func (v *ConfigValidator) validateAgentConfigurations(result *ValidationResult) {
	component := "agents"
	validation := ComponentValidation{Valid: true}

	// Check if agents.yaml exists
	agentConfigPath := "config/agents.yaml"
	if _, err := os.Stat(agentConfigPath); os.IsNotExist(err) {
		v.addWarning(result, component, "config_file", "No agents.yaml found, using hardcoded agents only")
		validation.Warnings++
	} else {
		// Validate agent configuration file
		if err := v.validateAgentConfigFile(agentConfigPath, result, &validation); err != nil {
			v.addError(result, component, "config_file", fmt.Sprintf("Failed to validate agent configuration: %s", err.Error()))
			validation.Errors++
			validation.Valid = false
		}
	}

	result.Summary.Components[component] = validation
}

// validateAgentConfigFile validates the structure and content of agents.yaml
func (v *ConfigValidator) validateAgentConfigFile(path string, result *ValidationResult, validation *ComponentValidation) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read agent config file: %w", err)
	}

	var agentConfig struct {
		Agents map[string]struct {
			AlertTypes  []string          `yaml:"alert_types"`
			MCPServers  []string          `yaml:"mcp_servers"`
			Instructions string           `yaml:"instructions"`
			Settings    map[string]interface{} `yaml:"settings"`
		} `yaml:"agents"`
	}

	if err := yaml.Unmarshal(data, &agentConfig); err != nil {
		return fmt.Errorf("invalid YAML syntax: %w", err)
	}

	// Validate each agent configuration
	for agentName, config := range agentConfig.Agents {
		// Check alert types
		if len(config.AlertTypes) == 0 {
			v.addWarning(result, "agents", fmt.Sprintf("%s.alert_types", agentName), "No alert types defined for agent")
			validation.Warnings++
		}

		// Check MCP servers
		if len(config.MCPServers) == 0 {
			v.addWarning(result, "agents", fmt.Sprintf("%s.mcp_servers", agentName), "No MCP servers defined for agent")
			validation.Warnings++
		}

		// Check instructions
		if config.Instructions == "" {
			v.addWarning(result, "agents", fmt.Sprintf("%s.instructions", agentName), "No custom instructions defined for agent")
			validation.Warnings++
		}

		// Validate settings if present
		if config.Settings != nil {
			if err := v.validateAgentSettings(config.Settings, agentName, result, validation); err != nil {
				v.addError(result, "agents", fmt.Sprintf("%s.settings", agentName), err.Error())
				validation.Errors++
				validation.Valid = false
			}
		}
	}

	return nil
}

// validateAgentSettings validates agent-specific settings
func (v *ConfigValidator) validateAgentSettings(settings map[string]interface{}, agentName string, result *ValidationResult, validation *ComponentValidation) error {
	// Validate common settings
	if maxTokens, exists := settings["max_tokens"]; exists {
		if tokens, ok := maxTokens.(int); ok {
			if tokens <= 0 || tokens > 32000 {
				return fmt.Errorf("max_tokens must be between 1 and 32000")
			}
		} else {
			return fmt.Errorf("max_tokens must be an integer")
		}
	}

	if temperature, exists := settings["temperature"]; exists {
		if temp, ok := temperature.(float64); ok {
			if temp < 0.0 || temp > 2.0 {
				return fmt.Errorf("temperature must be between 0.0 and 2.0")
			}
		} else {
			return fmt.Errorf("temperature must be a number")
		}
	}

	if maxIterations, exists := settings["max_iterations"]; exists {
		if iterations, ok := maxIterations.(int); ok {
			if iterations <= 0 || iterations > 20 {
				return fmt.Errorf("max_iterations must be between 1 and 20")
			}
		} else {
			return fmt.Errorf("max_iterations must be an integer")
		}
	}

	return nil
}

// validateMCPConfigurations validates MCP server configurations
func (v *ConfigValidator) validateMCPConfigurations(result *ValidationResult) {
	component := "mcp_servers"
	validation := ComponentValidation{Valid: true}

	// Validate basic MCP configuration values
	healthCheckInterval := 30 * time.Second
	if healthCheckInterval <= 0 {
		v.addError(result, component, "health_check_interval", "Health check interval must be positive")
		validation.Errors++
		validation.Valid = false
	}

	if healthCheckInterval < 5*time.Second {
		v.addWarning(result, component, "health_check_interval", "Health check interval less than 5 seconds may cause performance issues")
		validation.Warnings++
	}

	// Check for MCP server environment variables
	mcpVars := []string{
		"MCP_SERVER_FILESYSTEM_PATH",
		"MCP_SERVER_KUBECTL_KUBECONFIG",
		"MCP_SERVER_GITHUB_TOKEN",
	}

	foundVars := 0
	for _, varName := range mcpVars {
		if os.Getenv(varName) != "" {
			foundVars++
		}
	}

	if foundVars == 0 {
		v.addWarning(result, component, "environment", "No MCP server environment variables found. Some agents may have limited functionality")
		validation.Warnings++
	}

	result.Summary.Components[component] = validation
}

// validatePipelineConfiguration validates processing pipeline configuration
func (v *ConfigValidator) validatePipelineConfiguration(result *ValidationResult) {
	component := "pipeline"
	validation := ComponentValidation{Valid: true}

	// Default pipeline configuration values
	maxConcurrentJobs := 4
	jobTimeout := 30 * time.Second
	queueSize := 100
	retryAttempts := 3
	retryDelay := 5 * time.Second

	// Override with environment variables if present
	if maxWorkers := os.Getenv("PIPELINE_MAX_WORKERS"); maxWorkers != "" {
		if workers, err := strconv.Atoi(maxWorkers); err == nil {
			maxConcurrentJobs = workers
		}
	}

	if timeout := os.Getenv("PIPELINE_TIMEOUT"); timeout != "" {
		if duration, err := time.ParseDuration(timeout); err == nil {
			jobTimeout = duration
		}
	}

	// Validate configuration values
	if maxConcurrentJobs <= 0 {
		v.addError(result, component, "max_concurrent_jobs", "Max concurrent jobs must be positive")
		validation.Errors++
		validation.Valid = false
	}

	if maxConcurrentJobs > 50 {
		v.addWarning(result, component, "max_concurrent_jobs", "High concurrent job count may cause resource exhaustion")
		validation.Warnings++
	}

	if jobTimeout <= 0 {
		v.addError(result, component, "job_timeout", "Job timeout must be positive")
		validation.Errors++
		validation.Valid = false
	}

	if jobTimeout < 10*time.Second {
		v.addWarning(result, component, "job_timeout", "Job timeout less than 10 seconds may cause frequent timeouts")
		validation.Warnings++
	}

	if queueSize <= 0 {
		v.addError(result, component, "queue_size", "Queue size must be positive")
		validation.Errors++
		validation.Valid = false
	}

	if retryAttempts < 0 {
		v.addError(result, component, "retry_attempts", "Retry attempts cannot be negative")
		validation.Errors++
		validation.Valid = false
	}

	if retryDelay <= 0 {
		v.addError(result, component, "retry_delay", "Retry delay must be positive")
		validation.Errors++
		validation.Valid = false
	}

	result.Summary.Components[component] = validation
}

// validateHealthCheckConfiguration validates health check configuration
func (v *ConfigValidator) validateHealthCheckConfiguration(result *ValidationResult) {
	component := "health_checks"
	validation := ComponentValidation{Valid: true}

	// Default health check configuration values
	interval := 30 * time.Second
	timeout := 10 * time.Second
	maxRetries := 3
	failureThreshold := 3
	recoveryThreshold := 2

	// Override with environment variables if present
	if intervalEnv := os.Getenv("HEALTH_CHECK_INTERVAL"); intervalEnv != "" {
		if duration, err := time.ParseDuration(intervalEnv); err == nil {
			interval = duration
		}
	}

	// Validate configuration values
	if interval <= 0 {
		v.addError(result, component, "interval", "Health check interval must be positive")
		validation.Errors++
		validation.Valid = false
	}

	if timeout <= 0 {
		v.addError(result, component, "timeout", "Health check timeout must be positive")
		validation.Errors++
		validation.Valid = false
	}

	if timeout >= interval {
		v.addWarning(result, component, "timeout", "Health check timeout should be less than interval")
		validation.Warnings++
	}

	if maxRetries < 0 {
		v.addError(result, component, "max_retries", "Max retries cannot be negative")
		validation.Errors++
		validation.Valid = false
	}

	if failureThreshold <= 0 {
		v.addError(result, component, "failure_threshold", "Failure threshold must be positive")
		validation.Errors++
		validation.Valid = false
	}

	if recoveryThreshold <= 0 {
		v.addError(result, component, "recovery_threshold", "Recovery threshold must be positive")
		validation.Errors++
		validation.Valid = false
	}

	result.Summary.Components[component] = validation
}

// validateAPIServerConfiguration validates API server configuration
func (v *ConfigValidator) validateAPIServerConfiguration(result *ValidationResult) {
	component := "api_server"
	validation := ComponentValidation{Valid: true}

	// Get configuration from environment or use defaults
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Validate host
	if host == "" {
		v.addError(result, component, "host", "Host cannot be empty")
		validation.Errors++
		validation.Valid = false
	}

	// Validate port
	if err := v.validatePort(port); err != nil {
		v.addError(result, component, "port", fmt.Sprintf("Invalid port: %s", err.Error()))
		validation.Errors++
		validation.Valid = false
	}

	// Check for reasonable timeout values
	timeouts := map[string]time.Duration{
		"read_timeout":    30 * time.Second,
		"write_timeout":   30 * time.Second,
		"idle_timeout":    120 * time.Second,
		"request_timeout": 30 * time.Second,
	}

	for timeoutName, duration := range timeouts {
		if duration <= 0 {
			v.addError(result, component, timeoutName, "Timeout must be positive")
			validation.Errors++
			validation.Valid = false
		}

		if duration < 5*time.Second {
			v.addWarning(result, component, timeoutName, "Very low timeout may cause client issues")
			validation.Warnings++
		}
	}

	result.Summary.Components[component] = validation
}

// Helper functions for validation

func (v *ConfigValidator) addError(result *ValidationResult, component, field, message string) {
	result.Errors = append(result.Errors, ConfigValidationError{
		Component: component,
		Field:     field,
		Message:   message,
		Level:     "error",
	})
}

func (v *ConfigValidator) addWarning(result *ValidationResult, component, field, message string) {
	result.Warnings = append(result.Warnings, ConfigValidationWarning{
		Component: component,
		Field:     field,
		Message:   message,
	})
}

func (v *ConfigValidator) validateLogLevel(level string) error {
	validLevels := []string{"debug", "info", "warn", "error"}
	if !v.contains(validLevels, level) {
		return fmt.Errorf("must be one of: %s", strings.Join(validLevels, ", "))
	}
	return nil
}

func (v *ConfigValidator) validatePort(port string) error {
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("must be a valid integer")
	}
	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("must be between 1 and 65535")
	}
	if portNum < 1024 {
		// Warning for privileged ports will be handled separately
	}
	return nil
}

func (v *ConfigValidator) validatePositiveInteger(value string) error {
	num, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("must be a valid integer")
	}
	if num <= 0 {
		return fmt.Errorf("must be positive")
	}
	return nil
}

func (v *ConfigValidator) validateDuration(duration string) error {
	_, err := time.ParseDuration(duration)
	if err != nil {
		return fmt.Errorf("must be a valid duration (e.g., '30s', '5m')")
	}
	return nil
}

func (v *ConfigValidator) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ValidateStartupConfiguration validates configuration before system startup
func (v *ConfigValidator) ValidateStartupConfiguration() error {
	result := v.ValidateSystemConfiguration()

	if !result.Valid {
		var errorMessages []string
		for _, err := range result.Errors {
			errorMessages = append(errorMessages, fmt.Sprintf("%s.%s: %s", err.Component, err.Field, err.Message))
		}
		return fmt.Errorf("configuration validation failed:\n%s", strings.Join(errorMessages, "\n"))
	}

	// Log warnings
	for _, warning := range result.Warnings {
		v.logger.Warn("Configuration warning",
			zap.String("component", warning.Component),
			zap.String("field", warning.Field),
			zap.String("message", warning.Message))
	}

	return nil
}