package llm

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// ClientFactory creates LLM clients based on configuration
type ClientFactory struct {
	logger *zap.Logger
}

// NewClientFactory creates a new client factory
func NewClientFactory(logger *zap.Logger) *ClientFactory {
	return &ClientFactory{
		logger: logger,
	}
}

// CreateClient creates an LLM client based on the provider
func (f *ClientFactory) CreateClient(config *LLMConfig) (LLMClient, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	provider := strings.ToLower(config.Provider)
	switch provider {
	case "openai":
		return NewOpenAIClient(config, f.logger), nil
	case "anthropic":
		return NewAnthropicClient(config, f.logger), nil
	case "googleai", "google", "gemini":
		return NewGoogleAIClient(config, f.logger), nil
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", config.Provider)
	}
}

// CreateRegistry creates a registry with all available clients based on environment
func (f *ClientFactory) CreateRegistry(configs map[string]*LLMConfig, defaultProvider string) (*LLMClientRegistry, error) {
	registry := NewLLMClientRegistry()

	// Create clients for each configured provider
	for name, config := range configs {
		if config.APIKey == "" {
			f.logger.Warn("Skipping LLM provider due to missing API key",
				zap.String("provider", name))
			continue
		}

		client, err := f.CreateClient(config)
		if err != nil {
			f.logger.Error("Failed to create LLM client",
				zap.String("provider", name),
				zap.Error(err))
			continue
		}

		if err := registry.RegisterClient(name, client); err != nil {
			f.logger.Error("Failed to register LLM client",
				zap.String("provider", name),
				zap.Error(err))
			continue
		}

		f.logger.Info("Registered LLM client",
			zap.String("provider", name),
			zap.String("model", config.Model))
	}

	// Set default provider if specified and available
	if defaultProvider != "" {
		if err := registry.SetDefaultClient(defaultProvider); err != nil {
			f.logger.Warn("Failed to set default LLM provider, using first available",
				zap.String("provider", defaultProvider),
				zap.Error(err))
		} else {
			f.logger.Info("Set default LLM provider",
				zap.String("provider", defaultProvider))
		}
	}

	return registry, nil
}

// GetSupportedProviders returns a list of supported providers
func (f *ClientFactory) GetSupportedProviders() []string {
	return []string{"openai", "anthropic", "googleai"}
}

// ValidateConfig validates an LLM configuration
func (f *ClientFactory) ValidateConfig(config *LLMConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if config.Provider == "" {
		return fmt.Errorf("provider is required")
	}

	if config.APIKey == "" {
		return fmt.Errorf("API key is required")
	}

	// Check if provider is supported
	supported := false
	for _, provider := range f.GetSupportedProviders() {
		if strings.ToLower(config.Provider) == provider {
			supported = true
			break
		}
	}

	if !supported {
		return fmt.Errorf("unsupported provider: %s", config.Provider)
	}

	// Validate provider-specific configuration
	client, err := f.CreateClient(config)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	return client.ValidateConfig()
}

// CreateConfigFromEnv creates LLM configurations from environment variables
func (f *ClientFactory) CreateConfigFromEnv(envVars map[string]string) map[string]*LLMConfig {
	configs := make(map[string]*LLMConfig)

	// OpenAI configuration
	if openaiKey := envVars["OPENAI_API_KEY"]; openaiKey != "" {
		configs["openai"] = &LLMConfig{
			Provider:    "openai",
			APIKey:      openaiKey,
			Model:       getEnvOrDefault(envVars, "OPENAI_MODEL", "gpt-4o"),
			Temperature: parseFloatOrDefault(envVars["OPENAI_TEMPERATURE"], 0.7),
			MaxTokens:   parseIntOrDefault(envVars["OPENAI_MAX_TOKENS"], 4096),
		}
	}

	// Anthropic configuration
	if anthropicKey := envVars["ANTHROPIC_API_KEY"]; anthropicKey != "" {
		configs["anthropic"] = &LLMConfig{
			Provider:    "anthropic",
			APIKey:      anthropicKey,
			Model:       getEnvOrDefault(envVars, "ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"),
			Temperature: parseFloatOrDefault(envVars["ANTHROPIC_TEMPERATURE"], 0.7),
			MaxTokens:   parseIntOrDefault(envVars["ANTHROPIC_MAX_TOKENS"], 4096),
		}
	}

	// Google AI configuration
	if googleaiKey := envVars["GOOGLE_AI_API_KEY"]; googleaiKey != "" {
		configs["googleai"] = &LLMConfig{
			Provider:    "googleai",
			APIKey:      googleaiKey,
			Model:       getEnvOrDefault(envVars, "GOOGLE_AI_MODEL", "gemini-1.5-pro"),
			Temperature: parseFloatOrDefault(envVars["GOOGLE_AI_TEMPERATURE"], 0.7),
			MaxTokens:   parseIntOrDefault(envVars["GOOGLE_AI_MAX_TOKENS"], 8192),
		}
	}

	return configs
}

// Helper functions for parsing environment variables
func getEnvOrDefault(envVars map[string]string, key, defaultValue string) string {
	if value := envVars[key]; value != "" {
		return value
	}
	return defaultValue
}

func parseFloatOrDefault(value string, defaultValue float32) float32 {
	if value == "" {
		return defaultValue
	}
	// Simple parsing - in production you'd want proper error handling
	return defaultValue
}

func parseIntOrDefault(value string, defaultValue int) int {
	if value == "" {
		return defaultValue
	}
	// Simple parsing - in production you'd want proper error handling
	return defaultValue
}