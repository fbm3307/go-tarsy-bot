package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

// TemplateResolver handles environment variable templating in configuration files
type TemplateResolver struct {
	logger       *zap.Logger
	envPrefix    string
	defaultVars  map[string]string
	requiredVars []string
	failOnMissing bool
}

// TemplateContext contains context for template resolution
type TemplateContext struct {
	Variables     map[string]string
	DefaultValues map[string]string
	EnvPrefix     string
}

// NewTemplateResolver creates a new template resolver
func NewTemplateResolver(logger *zap.Logger) *TemplateResolver {
	return &TemplateResolver{
		logger:        logger,
		envPrefix:     "",
		defaultVars:   make(map[string]string),
		requiredVars:  make([]string, 0),
		failOnMissing: false,
	}
}

// NewTemplateResolverWithConfig creates a template resolver with configuration
func NewTemplateResolverWithConfig(logger *zap.Logger, config *TemplateConfig) *TemplateResolver {
	resolver := NewTemplateResolver(logger)

	if config != nil {
		resolver.envPrefix = config.EnvPrefix
		resolver.requiredVars = config.RequiredVars
		resolver.failOnMissing = config.FailOnMissingVars

		if config.DefaultValues != nil {
			resolver.defaultVars = make(map[string]string)
			for k, v := range config.DefaultValues {
				resolver.defaultVars[k] = v
			}
		}
	}

	return resolver
}

// ResolveTemplate resolves environment variable templates in the given text
func (tr *TemplateResolver) ResolveTemplate(text string) (string, error) {
	// Pattern to match ${VAR_NAME} or ${VAR_NAME:default_value}
	pattern := `\$\{([A-Za-z_][A-Za-z0-9_]*)(:[^}]*)?\}`
	re := regexp.MustCompile(pattern)

	missingVars := make([]string, 0)
	resolvedText := text

	// Find all template variables
	matches := re.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		fullMatch := match[0]    // ${VAR_NAME} or ${VAR_NAME:default}
		varName := match[1]      // VAR_NAME
		defaultPart := match[2]  // :default_value (including colon)

		var defaultValue string
		if defaultPart != "" {
			// Remove leading colon
			defaultValue = defaultPart[1:]
		}

		// Resolve the variable
		resolvedValue, found := tr.resolveVariable(varName, defaultValue)
		if !found {
			missingVars = append(missingVars, varName)

			if tr.failOnMissing {
				return "", fmt.Errorf("required environment variable not found: %s", varName)
			}

			// Keep the original template if no value found and not failing
			continue
		}

		// Replace the template with the resolved value
		resolvedText = strings.ReplaceAll(resolvedText, fullMatch, resolvedValue)
	}

	// Check for required variables
	if len(tr.requiredVars) > 0 {
		for _, required := range tr.requiredVars {
			if !tr.isVariableResolved(required, text) {
				missingVars = append(missingVars, required)
			}
		}
	}

	// Log missing variables
	if len(missingVars) > 0 {
		tr.logger.Warn("Missing environment variables",
			zap.Strings("missing_vars", missingVars),
			zap.Bool("fail_on_missing", tr.failOnMissing),
		)

		if tr.failOnMissing {
			return "", fmt.Errorf("missing required environment variables: %s", strings.Join(missingVars, ", "))
		}
	}

	return resolvedText, nil
}

// resolveVariable resolves a single variable
func (tr *TemplateResolver) resolveVariable(varName, defaultValue string) (string, bool) {
	// Try with prefix first if specified
	if tr.envPrefix != "" {
		prefixedName := tr.envPrefix + varName
		if value := os.Getenv(prefixedName); value != "" {
			tr.logger.Debug("Resolved variable with prefix",
				zap.String("var", varName),
				zap.String("prefixed_var", prefixedName),
				zap.String("value", value),
			)
			return value, true
		}
	}

	// Try without prefix
	if value := os.Getenv(varName); value != "" {
		tr.logger.Debug("Resolved variable",
			zap.String("var", varName),
			zap.String("value", value),
		)
		return value, true
	}

	// Try default values from configuration
	if defaultVal, exists := tr.defaultVars[varName]; exists {
		tr.logger.Debug("Using configured default value",
			zap.String("var", varName),
			zap.String("value", defaultVal),
		)
		return defaultVal, true
	}

	// Try inline default value
	if defaultValue != "" {
		tr.logger.Debug("Using inline default value",
			zap.String("var", varName),
			zap.String("value", defaultValue),
		)
		return defaultValue, true
	}

	tr.logger.Debug("Variable not found",
		zap.String("var", varName),
		zap.String("env_prefix", tr.envPrefix),
	)
	return "", false
}

// isVariableResolved checks if a variable has been resolved in the text
func (tr *TemplateResolver) isVariableResolved(varName, text string) bool {
	// Check if the variable template exists in the text
	patterns := []string{
		fmt.Sprintf("${%s}", varName),
		fmt.Sprintf("${%s:", varName),
	}

	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			// Variable template exists, check if it can be resolved
			_, found := tr.resolveVariable(varName, "")
			return found
		}
	}

	// Variable not used in template, consider it resolved
	return true
}

// ResolveTemplateWithContext resolves templates with additional context
func (tr *TemplateResolver) ResolveTemplateWithContext(text string, context *TemplateContext) (string, error) {
	// Temporarily set context values
	originalPrefix := tr.envPrefix
	originalDefaults := tr.defaultVars

	if context != nil {
		if context.EnvPrefix != "" {
			tr.envPrefix = context.EnvPrefix
		}

		if context.DefaultValues != nil {
			// Merge default values
			tr.defaultVars = make(map[string]string)
			for k, v := range originalDefaults {
				tr.defaultVars[k] = v
			}
			for k, v := range context.DefaultValues {
				tr.defaultVars[k] = v
			}
		}
	}

	// Resolve template
	result, err := tr.ResolveTemplate(text)

	// Restore original values
	tr.envPrefix = originalPrefix
	tr.defaultVars = originalDefaults

	return result, err
}

// ValidateTemplate validates that all templates in text can be resolved
func (tr *TemplateResolver) ValidateTemplate(text string) error {
	pattern := `\$\{([A-Za-z_][A-Za-z0-9_]*)(:[^}]*)?\}`
	re := regexp.MustCompile(pattern)

	matches := re.FindAllStringSubmatch(text, -1)
	missingVars := make([]string, 0)

	for _, match := range matches {
		varName := match[1]
		defaultPart := match[2]

		var defaultValue string
		if defaultPart != "" {
			defaultValue = defaultPart[1:] // Remove leading colon
		}

		if _, found := tr.resolveVariable(varName, defaultValue); !found {
			missingVars = append(missingVars, varName)
		}
	}

	if len(missingVars) > 0 {
		return fmt.Errorf("template validation failed - missing variables: %s", strings.Join(missingVars, ", "))
	}

	return nil
}

// GetTemplateVariables extracts all template variables from text
func (tr *TemplateResolver) GetTemplateVariables(text string) []string {
	pattern := `\$\{([A-Za-z_][A-Za-z0-9_]*)(:[^}]*)?\}`
	re := regexp.MustCompile(pattern)

	matches := re.FindAllStringSubmatch(text, -1)
	variables := make([]string, 0)
	seen := make(map[string]bool)

	for _, match := range matches {
		varName := match[1]
		if !seen[varName] {
			variables = append(variables, varName)
			seen[varName] = true
		}
	}

	return variables
}

// SetEnvPrefix sets the environment variable prefix
func (tr *TemplateResolver) SetEnvPrefix(prefix string) {
	tr.envPrefix = prefix
}

// SetDefaultValues sets default values for variables
func (tr *TemplateResolver) SetDefaultValues(defaults map[string]string) {
	tr.defaultVars = make(map[string]string)
	for k, v := range defaults {
		tr.defaultVars[k] = v
	}
}

// SetRequiredVariables sets the list of required variables
func (tr *TemplateResolver) SetRequiredVariables(required []string) {
	tr.requiredVars = required
}

// SetFailOnMissing sets whether to fail on missing variables
func (tr *TemplateResolver) SetFailOnMissing(fail bool) {
	tr.failOnMissing = fail
}

// ResolveConfigurationTemplate resolves templates in agent configuration
func (tr *TemplateResolver) ResolveConfigurationTemplate(configText string) (string, error) {
	tr.logger.Info("Resolving configuration templates")

	// First pass: resolve templates
	resolved, err := tr.ResolveTemplate(configText)
	if err != nil {
		return "", fmt.Errorf("template resolution failed: %w", err)
	}

	// Log template resolution statistics
	originalVars := tr.GetTemplateVariables(configText)
	remainingVars := tr.GetTemplateVariables(resolved)

	tr.logger.Info("Template resolution completed",
		zap.Int("original_variables", len(originalVars)),
		zap.Int("remaining_variables", len(remainingVars)),
		zap.Strings("original", originalVars),
		zap.Strings("remaining", remainingVars),
	)

	return resolved, nil
}

// TemplateExample provides an example of template usage
func TemplateExample() string {
	return `# Template Examples:

# Basic variable substitution
database_url: "${DATABASE_URL}"

# Variable with default value
port: "${PORT:8080}"
host: "${HOST:localhost}"

# Prefixed variables (if env_prefix is set to "TARSY_")
# Will look for TARSY_API_KEY in environment
api_key: "${API_KEY}"

# Complex example with multiple variables
mcp_servers:
  kubernetes-server:
    command: "${KUBECTL_SERVER_PATH:/usr/local/bin/kubectl-server}"
    args: ["--kubeconfig", "${KUBECONFIG:~/.kube/config}"]
    env:
      KUBECONFIG: "${KUBECONFIG:~/.kube/config}"
      NAMESPACE: "${DEFAULT_NAMESPACE:default}"

agents:
  my-agent:
    settings:
      max_iterations: "${MAX_ITERATIONS:10}"
      temperature: "${TEMPERATURE:0.7}"
      llm_provider: "${LLM_PROVIDER:openai}"
    variables:
      log_level: "${LOG_LEVEL:info}"
      timeout: "${AGENT_TIMEOUT:5m}"
`
}

// ResolveFromEnvFile resolves templates using variables from an .env file
func (tr *TemplateResolver) ResolveFromEnvFile(text, envFilePath string) (string, error) {
	if envFilePath == "" {
		return tr.ResolveTemplate(text)
	}

	// Load environment variables from file
	envVars, err := tr.loadEnvFile(envFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to load env file: %w", err)
	}

	// Create context with env file variables
	context := &TemplateContext{
		Variables:     envVars,
		DefaultValues: tr.defaultVars,
		EnvPrefix:     tr.envPrefix,
	}

	return tr.ResolveTemplateWithContext(text, context)
}

// loadEnvFile loads key-value pairs from an environment file
func (tr *TemplateResolver) loadEnvFile(envFilePath string) (map[string]string, error) {
	content, err := os.ReadFile(envFilePath)
	if err != nil {
		return nil, err
	}

	envVars := make(map[string]string)
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE format
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			tr.logger.Warn("Invalid line in env file",
				zap.String("file", envFilePath),
				zap.Int("line", i+1),
				zap.String("content", line),
			)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		if len(value) >= 2 {
			if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
			   (strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
				value = value[1 : len(value)-1]
			}
		}

		envVars[key] = value
	}

	tr.logger.Debug("Loaded environment variables from file",
		zap.String("file", envFilePath),
		zap.Int("variables", len(envVars)),
	)

	return envVars, nil
}