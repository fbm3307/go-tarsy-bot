package services

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/integrations/llm"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// LLMServiceAdapter adapts LLMIntegrationService to agents.LLMIntegrationInterface
// This resolves the type compatibility issue between services and agents packages
type LLMServiceAdapter struct {
	Service *LLMIntegrationService
}

// GenerateWithTracking implements agents.LLMIntegrationInterface
func (adapter *LLMServiceAdapter) GenerateWithTracking(ctx context.Context, request *agents.EnhancedGenerateRequest) (*agents.LLMResponse, error) {
	// Convert temperature from *float64 to *float32
	var temp *float32
	if request.Temperature != nil {
		t := float32(*request.Temperature)
		temp = &t
	}

	// Convert from agents types to services types
	serviceRequest := &EnhancedGenerateRequest{
		GenerateWithToolsRequest: &GenerateWithToolsRequest{
			GenerateRequest: &llm.GenerateRequest{
				Messages:    convertMessagesToLLM(request.Messages),
				Model:       request.Model,
				Temperature: temp,
				MaxTokens:   request.MaxTokens,
			},
			EnableTools: request.EnableTools,
		},
		SessionID:        request.SessionID,
		AgentType:        request.AgentType,
		IterationIndex:   request.IterationIndex,
		StageExecutionID: request.StageExecutionID,
		TrackCost:        request.TrackCost,
		EstimateCost:     request.EstimateCost,
	}

	// Call the actual service
	serviceResponse, err := adapter.Service.GenerateWithTracking(ctx, serviceRequest)
	if err != nil {
		return nil, err
	}

	// Extract fields from the embedded response
	var tokensUsed int
	var cost float64

	if serviceResponse.TokenUsage != nil {
		tokensUsed = serviceResponse.TokenUsage.TotalTokens
		cost = serviceResponse.TokenUsage.TotalCost
	}

	// Convert back to agents types
	return &agents.LLMResponse{
		Content:      serviceResponse.Content,
		Model:        serviceResponse.Model,
		TokensUsed:   tokensUsed,
		FinishReason: serviceResponse.FinishReason,
		Cost:         cost,
	}, nil
}

// convertMessagesToLLM converts agents.Message slice to llm.Message slice
func convertMessagesToLLM(agentMessages []agents.Message) []llm.Message {
	llmMessages := make([]llm.Message, len(agentMessages))
	for i, msg := range agentMessages {
		llmMessages[i] = llm.Message{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}
	return llmMessages
}

// AgentFactory creates and configures agents based on type and configuration
// Equivalent to Python's AgentFactory with dependency injection
type AgentFactory struct {
	registry             *agents.AgentRegistry
	llmIntegrationService *LLMIntegrationService
	mcpServerRegistry    *mcp.MCPServerRegistry
	logger               *zap.Logger
}

// AgentConfig represents configuration for agent creation
type AgentConfig struct {
	Type       string                 `json:"type" yaml:"type"`
	Settings   map[string]interface{} `json:"settings,omitempty" yaml:"settings,omitempty"`
	Strategy   string                 `json:"strategy,omitempty" yaml:"strategy,omitempty"`
	MaxRetries int                    `json:"max_retries,omitempty" yaml:"max_retries,omitempty"`
}

// NewAgentFactory creates a new agent factory
func NewAgentFactory(
	registry *agents.AgentRegistry,
	llmIntegrationService *LLMIntegrationService,
	mcpServerRegistry *mcp.MCPServerRegistry,
	logger *zap.Logger,
) *AgentFactory {
	return &AgentFactory{
		registry:             registry,
		llmIntegrationService: llmIntegrationService,
		mcpServerRegistry:    mcpServerRegistry,
		logger:               logger,
	}
}

// CreateAgent creates an agent instance based on type and configuration
func (af *AgentFactory) CreateAgent(agentType string, config *AgentConfig) (agents.Agent, error) {
	af.logger.Debug("Creating agent",
		zap.String("type", agentType),
		zap.Any("config", config),
	)

	// Use registry to get the agent
	agent, err := af.registry.GetAgent(agentType)
	if err != nil {
		// If not found in registry, try to create built-in agents
		return af.createBuiltinAgent(agentType, config)
	}

	return agent, nil
}

// createBuiltinAgent creates built-in agent types
func (af *AgentFactory) createBuiltinAgent(agentType string, config *AgentConfig) (agents.Agent, error) {
	switch agentType {
	case "base", "general":
		settings := af.parseAgentSettings(config)
		return agents.NewBaseAgent("base", []string{"general_analysis"}, settings), nil

	case "kubernetes", "k8s":
		settings := af.parseAgentSettings(config)
		kubeConfig := af.parseKubernetesConfig(config)
		llmAdapter := &LLMServiceAdapter{Service: af.llmIntegrationService}
		return agents.NewKubernetesAgent(
			settings,
			kubeConfig,
			llmAdapter,
			af.mcpServerRegistry,
			af.logger,
		), nil

	case "configurable":
		// For configurable agents, expect YAML content in settings
		yamlContent, ok := config.Settings["yaml_content"]
		if !ok {
			return nil, fmt.Errorf("configurable agent requires 'yaml_content' in settings")
		}

		yamlBytes, ok := yamlContent.([]byte)
		if !ok {
			// Try string conversion
			if yamlStr, ok := yamlContent.(string); ok {
				yamlBytes = []byte(yamlStr)
			} else {
				return nil, fmt.Errorf("yaml_content must be bytes or string")
			}
		}

		llmAdapter := &LLMServiceAdapter{Service: af.llmIntegrationService}
		return agents.NewConfigurableAgent(
			yamlBytes,
			llmAdapter,
			af.mcpServerRegistry,
			af.logger,
		)

	case "configurable-file":
		// For file-based configurable agents
		yamlPath, ok := config.Settings["yaml_path"]
		if !ok {
			return nil, fmt.Errorf("configurable-file agent requires 'yaml_path' in settings")
		}

		yamlPathStr, ok := yamlPath.(string)
		if !ok {
			return nil, fmt.Errorf("yaml_path must be a string")
		}

		llmAdapter := &LLMServiceAdapter{Service: af.llmIntegrationService}
		return agents.NewConfigurableAgentFromFile(
			yamlPathStr,
			llmAdapter,
			af.mcpServerRegistry,
			af.logger,
		)

	default:
		return nil, fmt.Errorf("unknown agent type: %s", agentType)
	}
}

// parseAgentSettings converts configuration to AgentSettings
func (af *AgentFactory) parseAgentSettings(config *AgentConfig) *agents.AgentSettings {
	settings := agents.DefaultAgentSettings()

	if config == nil || config.Settings == nil {
		return settings
	}

	// Parse common settings
	if maxIter, ok := config.Settings["max_iterations"].(int); ok {
		settings.MaxIterations = maxIter
	}

	if timeoutStr, ok := config.Settings["timeout_duration"].(string); ok {
		// Parse duration string - simplified for now
		_ = timeoutStr // TODO: Parse duration string
		settings.TimeoutDuration = settings.TimeoutDuration // Keep default
	}

	if provider, ok := config.Settings["llm_provider"].(string); ok {
		settings.LLMProvider = provider
	}

	if temp, ok := config.Settings["temperature"].(float64); ok {
		settings.Temperature = float32(temp)
	}

	if tokens, ok := config.Settings["max_tokens"].(int); ok {
		settings.MaxTokens = tokens
	}

	return settings
}

// parseKubernetesConfig converts configuration to KubernetesConfig
func (af *AgentFactory) parseKubernetesConfig(config *AgentConfig) *agents.KubernetesConfig {
	kubeConfig := &agents.KubernetesConfig{
		ClusterName: "default",
		EnableTools: true,
	}

	if config == nil || config.Settings == nil {
		return kubeConfig
	}

	if cluster, ok := config.Settings["cluster_name"].(string); ok {
		kubeConfig.ClusterName = cluster
	}

	if kubeconfig, ok := config.Settings["kubeconfig_path"].(string); ok {
		kubeConfig.KubeconfigPath = kubeconfig
	}

	if enableTools, ok := config.Settings["enable_tools"].(bool); ok {
		kubeConfig.EnableTools = enableTools
	}

	if namespaces, ok := config.Settings["namespaces"].([]interface{}); ok {
		for _, ns := range namespaces {
			if nsStr, ok := ns.(string); ok {
				kubeConfig.Namespaces = append(kubeConfig.Namespaces, nsStr)
			}
		}
	}

	return kubeConfig
}

// GetSupportedAgentTypes returns list of supported agent types
func (af *AgentFactory) GetSupportedAgentTypes() []string {
	// Get from registry
	registryTypes := af.registry.ListAgents()

	// Add built-in types
	builtinTypes := []string{"base", "general", "kubernetes", "k8s"}

	// Combine and deduplicate
	typeMap := make(map[string]bool)
	var allTypes []string

	for _, t := range registryTypes {
		if !typeMap[t] {
			allTypes = append(allTypes, t)
			typeMap[t] = true
		}
	}

	for _, t := range builtinTypes {
		if !typeMap[t] {
			allTypes = append(allTypes, t)
			typeMap[t] = true
		}
	}

	return allTypes
}

// ValidateAgentConfig validates agent configuration
func (af *AgentFactory) ValidateAgentConfig(config *AgentConfig) error {
	if config == nil {
		return fmt.Errorf("agent config cannot be nil")
	}

	if config.Type == "" {
		return fmt.Errorf("agent type is required")
	}

	// Check if type is supported
	supportedTypes := af.GetSupportedAgentTypes()
	supported := false
	for _, t := range supportedTypes {
		if t == config.Type {
			supported = true
			break
		}
	}

	if !supported {
		return fmt.Errorf("unsupported agent type: %s", config.Type)
	}

	return nil
}