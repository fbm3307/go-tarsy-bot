package agents

import (
	"fmt"
	"sync"
	"time"

	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/errors"
	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
	"go.uber.org/zap"
)

// AgentRegistry manages the registration and retrieval of different agent types
// This matches the original Python agent_registry.py structure exactly
// Enhanced with chain-based routing support
type AgentRegistry struct {
	// Hardcoded agents (like KubernetesAgent)
	hardcodedAgents map[string]Agent

	// Configuration-based agents loaded from YAML
	configuredAgents map[string]Agent

	// Alert type mappings (simple direct mapping)
	alertTypeToAgent map[string]string

	// Chain-based mappings for multi-stage processing
	chainBasedMappings map[string]*ChainBasedMapping

	// Integration with chain registry for multi-stage workflows
	chainRegistry   ChainRegistryInterface

	logger          *zap.Logger
	configLoader    *config.AgentConfigLoader
	mcpRegistry     *mcp.MCPServerRegistry
	mutex           sync.RWMutex

	// Error handling and resilience components
	errorClassifier     *errors.ErrorClassifier
	resilienceWrapper   *errors.ResilienceWrapper
	degradationManager  *errors.ServiceDegradationManager
	dependencyChecker   DependencyHealthChecker

	// Registry metrics and health
	registryMetrics     *RegistryMetrics
	healthStatus        AgentHealthStatus
}

// ChainBasedMapping defines how an alert type maps to a processing chain with multiple agents
type ChainBasedMapping struct {
	AlertType   string                `json:"alert_type"`
	ChainID     string                `json:"chain_id"`
	Stages      []ChainStageMapping   `json:"stages"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ChainStageMapping defines which agent handles each stage in a chain
type ChainStageMapping struct {
	StageID     string                 `json:"stage_id"`
	StageName   string                 `json:"stage_name"`
	AgentType   string                 `json:"agent_type"`
	AgentConfig map[string]interface{} `json:"agent_config,omitempty"`
	Required    bool                   `json:"required"`
	Index       int                    `json:"index"`
}

// ChainRegistryInterface defines the interface for chain registry integration
type ChainRegistryInterface interface {
	GetChainForAlertType(alertType string) (ChainDefinition, error)
	ListChains() map[string]ChainDefinition
}

// ChainDefinition represents a processing chain definition (interface compatibility)
type ChainDefinition interface {
	GetName() string
	GetAlertType() string
	GetStages() []ChainStage
}

// ChainStage represents a processing stage (interface compatibility)
type ChainStage interface {
	GetID() string
	GetName() string
	GetAgentType() string
	GetIndex() int
	IsRequired() bool
}

// RegistryMetrics tracks agent registry performance and health metrics
type RegistryMetrics struct {
	TotalAgents          int           `json:"total_agents"`
	HealthyAgents        int           `json:"healthy_agents"`
	DegradedAgents       int           `json:"degraded_agents"`
	UnhealthyAgents      int           `json:"unhealthy_agents"`
	TotalAlertTypes      int           `json:"total_alert_types"`
	RegistrationCount    int64         `json:"registration_count"`
	UnregistrationCount  int64         `json:"unregistration_count"`
	LookupCount          int64         `json:"lookup_count"`
	FailedLookupCount    int64         `json:"failed_lookup_count"`
	LastHealthCheck      time.Time     `json:"last_health_check"`
	AverageResponseTime  time.Duration `json:"average_response_time"`
	AgentMetrics         map[string]*AgentMetrics `json:"agent_metrics"`
}

// NewAgentRegistry creates a new agent registry matching Python structure
func NewAgentRegistry(logger *zap.Logger, configLoader *config.AgentConfigLoader, mcpRegistry *mcp.MCPServerRegistry) *AgentRegistry {
	return &AgentRegistry{
		hardcodedAgents:    make(map[string]Agent),
		configuredAgents:   make(map[string]Agent),
		alertTypeToAgent:   make(map[string]string),
		chainBasedMappings: make(map[string]*ChainBasedMapping),
		logger:             logger,
		configLoader:       configLoader,
		mcpRegistry:        mcpRegistry,

		// Initialize metrics and health status
		registryMetrics: &RegistryMetrics{
			AgentMetrics: make(map[string]*AgentMetrics),
		},
		healthStatus: AgentHealthStatusHealthy,
	}
}

// NewAgentRegistryWithResilience creates an agent registry with comprehensive error handling
func NewAgentRegistryWithResilience(
	logger *zap.Logger,
	configLoader *config.AgentConfigLoader,
	mcpRegistry *mcp.MCPServerRegistry,
	errorClassifier *errors.ErrorClassifier,
	resilienceWrapper *errors.ResilienceWrapper,
	degradationManager *errors.ServiceDegradationManager,
	dependencyChecker DependencyHealthChecker,
) *AgentRegistry {
	registry := NewAgentRegistry(logger, configLoader, mcpRegistry)

	// Add resilience components
	registry.errorClassifier = errorClassifier
	registry.resilienceWrapper = resilienceWrapper
	registry.degradationManager = degradationManager
	registry.dependencyChecker = dependencyChecker

	return registry
}

// RegisterHardcodedAgent registers a hardcoded agent (like KubernetesAgent)
func (ar *AgentRegistry) RegisterHardcodedAgent(agentType string, agent Agent, alertTypes []string) error {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	if _, exists := ar.hardcodedAgents[agentType]; exists {
		return fmt.Errorf("hardcoded agent type %s is already registered", agentType)
	}

	ar.hardcodedAgents[agentType] = agent

	// Map alert types to this agent
	for _, alertType := range alertTypes {
		ar.alertTypeToAgent[alertType] = agentType
	}

	ar.logger.Info("Hardcoded agent registered",
		zap.String("type", agentType),
		zap.Strings("alert_types", alertTypes))

	return nil
}

// LoadConfiguredAgents loads agents from YAML configuration (matches Python)
func (ar *AgentRegistry) LoadConfiguredAgents() error {
	if ar.configLoader == nil {
		ar.logger.Info("No config loader provided, skipping configured agents")
		return nil
	}

	// Load configuration
	agentConfig, err := ar.configLoader.LoadConfiguration()
	if err != nil {
		return fmt.Errorf("failed to load agent configuration: %w", err)
	}

	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	// Clear existing configured agents
	ar.configuredAgents = make(map[string]Agent)

	// Load each configured agent
	for agentName, agentDef := range agentConfig.GetEnabledAgents() {
		if agentDef.Type == "configurable" {
			// Create configurable agent from definition
			configAgent, err := ar.createConfigurableAgentFromDefinition(agentDef)
			if err != nil {
				ar.logger.Error("Failed to create configurable agent",
					zap.String("name", agentName),
					zap.Error(err))
				continue
			}

			ar.configuredAgents[agentName] = configAgent

			// Map alert types to this agent
			for _, alertType := range agentDef.AlertTypes {
				ar.alertTypeToAgent[alertType] = agentName
			}

			ar.logger.Info("Configured agent loaded",
				zap.String("name", agentName),
				zap.Strings("alert_types", agentDef.AlertTypes))
		}
	}

	return nil
}

// GetAgentForAlert determines the appropriate agent for a given alert (matches Python routing)
// Enhanced with resilience patterns and error handling
func (ar *AgentRegistry) GetAgentForAlert(alert *models.Alert) (Agent, error) {
	startTime := time.Now()
	ar.registryMetrics.LookupCount++

	// Check degradation status - disable features if needed
	if ar.degradationManager != nil && ar.degradationManager.GetCurrentLevel() != errors.DegradationLevelNone {
		ar.logger.Warn("Agent lookup under degraded conditions",
			zap.String("degradation_level", string(ar.degradationManager.GetCurrentLevel())),
			zap.String("alert_type", alert.AlertType))
	}

	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	// Update response time metric
	defer func() {
		duration := time.Since(startTime)
		ar.updateLookupMetrics(duration)
	}()

	// First check exact alert type mapping
	if agentName, exists := ar.alertTypeToAgent[alert.AlertType]; exists {
		// Check configured agents first
		if agent, exists := ar.configuredAgents[agentName]; exists {
			if ar.isAgentHealthy(agent) {
				return agent, nil
			}
			ar.logger.Warn("Agent found but unhealthy",
				zap.String("agent_name", agentName),
				zap.String("alert_type", alert.AlertType))
		}

		// Then check hardcoded agents
		if agent, exists := ar.hardcodedAgents[agentName]; exists {
			if ar.isAgentHealthy(agent) {
				return agent, nil
			}
			ar.logger.Warn("Agent found but unhealthy",
				zap.String("agent_name", agentName),
				zap.String("alert_type", alert.AlertType))
		}
	}

	// Fallback to default patterns (matches Python logic)
	switch alert.AlertType {
	case "kubernetes", "k8s", "pod", "deployment", "service":
		if agent, exists := ar.hardcodedAgents["kubernetes"]; exists {
			return agent, nil
		}
	case "security", "intrusion", "malware":
		// Look for security-configured agents
		for name, agent := range ar.configuredAgents {
			if configAgent, ok := agent.(*ConfigurableAgent); ok {
				capabilities := configAgent.GetCapabilities()
				for _, cap := range capabilities {
					if cap == "security" || cap == "security_analysis" {
						ar.logger.Info("Using security-capable configured agent", zap.String("agent", name))
						return agent, nil
					}
				}
			}
		}
	}

	// Last resort: use any available agent
	if len(ar.hardcodedAgents) > 0 {
		for _, agent := range ar.hardcodedAgents {
			ar.logger.Warn("Using fallback hardcoded agent", zap.String("alert_type", alert.AlertType))
			return agent, nil
		}
	}

	if len(ar.configuredAgents) > 0 {
		for _, agent := range ar.configuredAgents {
			ar.logger.Warn("Using fallback configured agent", zap.String("alert_type", alert.AlertType))
			return agent, nil
		}
	}

	return nil, fmt.Errorf("no suitable agent found for alert type: %s", alert.AlertType)
}

// GetAgent retrieves an agent by name (supports both hardcoded and configured)
func (ar *AgentRegistry) GetAgent(agentName string) (Agent, error) {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	// Check configured agents first
	if agent, exists := ar.configuredAgents[agentName]; exists {
		return agent, nil
	}

	// Then check hardcoded agents
	if agent, exists := ar.hardcodedAgents[agentName]; exists {
		return agent, nil
	}

	return nil, fmt.Errorf("agent %s not found", agentName)
}

// ListAgents returns all available agents (matches Python interface)
func (ar *AgentRegistry) ListAgents() []string {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	agents := make([]string, 0)

	// Add hardcoded agents
	for name := range ar.hardcodedAgents {
		agents = append(agents, fmt.Sprintf("%s (hardcoded)", name))
	}

	// Add configured agents
	for name := range ar.configuredAgents {
		agents = append(agents, fmt.Sprintf("%s (configured)", name))
	}

	return agents
}

// GetAvailableAlertTypes returns all supported alert types
func (ar *AgentRegistry) GetAvailableAlertTypes() []string {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	alertTypes := make([]string, 0, len(ar.alertTypeToAgent))
	for alertType := range ar.alertTypeToAgent {
		alertTypes = append(alertTypes, alertType)
	}

	return alertTypes
}

// GetAgentCapabilities returns the capabilities of a specific agent
func (ar *AgentRegistry) GetAgentCapabilities(agentName string) ([]string, error) {
	agent, err := ar.GetAgent(agentName)
	if err != nil {
		return nil, err
	}

	return agent.GetCapabilities(), nil
}

// createConfigurableAgentFromDefinition creates a ConfigurableAgent from YAML definition
func (ar *AgentRegistry) createConfigurableAgentFromDefinition(agentDef *config.AgentDefinition) (*ConfigurableAgent, error) {
	// Convert config.AgentDefinition to agents.AgentDefinition
	definition := &AgentDefinition{
		Name:         agentDef.Name,
		Description:  agentDef.Description,
		Type:         agentDef.Type,
		Version:      agentDef.Version,
		Capabilities: agentDef.Capabilities,
		Variables:    agentDef.Variables,
	}

	// Convert instructions
	if agentDef.Instructions != nil {
		definition.Instructions = InstructionLayers{
			General: agentDef.Instructions.General,
			MCP:     agentDef.Instructions.MCP,
			Custom:  agentDef.Instructions.Custom,
		}
	}

	// Convert settings
	if agentDef.Settings != nil {
		definition.Settings = &AgentSettings{
			MaxIterations:   agentDef.Settings.MaxIterations,
			TimeoutDuration: agentDef.Settings.Timeout,
			RetryAttempts:   agentDef.Settings.RetryAttempts,
			EnableDebugMode: agentDef.Settings.EnableDebugMode,
			LLMProvider:     agentDef.Settings.LLMProvider,
			MCPEnabled:      agentDef.Settings.MCPEnabled,
			Temperature:     agentDef.Settings.Temperature,
			MaxTokens:       agentDef.Settings.MaxTokens,
		}
	}

	// Convert MCP servers to tools
	for _, serverName := range agentDef.MCPServers {
		definition.Tools = append(definition.Tools, ToolDefinition{
			Name:   fmt.Sprintf("%s-tools", serverName),
			Server: serverName,
			Description: fmt.Sprintf("Tools from %s MCP server", serverName),
		})
	}

	// Create the base agent
	settings := definition.Settings
	if settings == nil {
		settings = DefaultAgentSettings()
	}

	baseAgent := NewBaseAgent(definition.Type, definition.Capabilities, settings)

	return &ConfigurableAgent{
		BaseAgent:  baseAgent,
		definition: definition,
		logger:     ar.logger,
	}, nil
}

// ValidateAllAgents validates all registered agents
func (ar *AgentRegistry) ValidateAllAgents() error {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	// Validate hardcoded agents
	for name, agent := range ar.hardcodedAgents {
		if err := agent.ValidateConfiguration(); err != nil {
			return fmt.Errorf("hardcoded agent %s validation failed: %w", name, err)
		}
	}

	// Validate configured agents
	for name, agent := range ar.configuredAgents {
		if err := agent.ValidateConfiguration(); err != nil {
			return fmt.Errorf("configured agent %s validation failed: %w", name, err)
		}
	}

	return nil
}

// GetAgentStatus returns comprehensive status information about all agents
func (ar *AgentRegistry) GetAgentStatus() map[string]interface{} {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	status := map[string]interface{}{
		"total_agents":       len(ar.hardcodedAgents) + len(ar.configuredAgents),
		"hardcoded_agents":   len(ar.hardcodedAgents),
		"configured_agents":  len(ar.configuredAgents),
		"alert_type_mappings": len(ar.alertTypeToAgent),
		"agents": make(map[string]interface{}),
	}

	agents := status["agents"].(map[string]interface{})

	// Add hardcoded agent status
	for name, agent := range ar.hardcodedAgents {
		agents[name] = map[string]interface{}{
			"type":         "hardcoded",
			"agent_type":   agent.GetAgentType(),
			"capabilities": agent.GetCapabilities(),
			"mcp_servers":  agent.MCPServers(),
			"valid":        agent.ValidateConfiguration() == nil,
		}
	}

	// Add configured agent status
	for name, agent := range ar.configuredAgents {
		agents[name] = map[string]interface{}{
			"type":         "configured",
			"agent_type":   agent.GetAgentType(),
			"capabilities": agent.GetCapabilities(),
			"mcp_servers":  agent.MCPServers(),
			"valid":        agent.ValidateConfiguration() == nil,
		}
	}

	return status
}

// GetAgentsByCapability returns agents that have a specific capability
func (ar *AgentRegistry) GetAgentsByCapability(capability string) []string {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	var agents []string

	// Check hardcoded agents
	for name, agent := range ar.hardcodedAgents {
		for _, cap := range agent.GetCapabilities() {
			if cap == capability {
				agents = append(agents, name)
				break
			}
		}
	}

	// Check configured agents
	for name, agent := range ar.configuredAgents {
		for _, cap := range agent.GetCapabilities() {
			if cap == capability {
				agents = append(agents, name)
				break
			}
		}
	}

	return agents
}

// GetMCPServerUsage returns which agents use which MCP servers
func (ar *AgentRegistry) GetMCPServerUsage() map[string][]string {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	serverUsage := make(map[string][]string)

	// Check hardcoded agents
	for name, agent := range ar.hardcodedAgents {
		for _, server := range agent.MCPServers() {
			serverUsage[server] = append(serverUsage[server], name)
		}
	}

	// Check configured agents
	for name, agent := range ar.configuredAgents {
		for _, server := range agent.MCPServers() {
			serverUsage[server] = append(serverUsage[server], name)
		}
	}

	return serverUsage
}

// ReloadConfiguredAgents reloads all configured agents from disk
func (ar *AgentRegistry) ReloadConfiguredAgents() error {
	ar.logger.Info("Reloading configured agents")

	if err := ar.LoadConfiguredAgents(); err != nil {
		ar.logger.Error("Failed to reload configured agents", zap.Error(err))
		return fmt.Errorf("failed to reload configured agents: %w", err)
	}

	ar.logger.Info("Successfully reloaded configured agents",
		zap.Int("configured_count", len(ar.configuredAgents)))

	return nil
}

// HealthCheck performs health checks on all registered agents
func (ar *AgentRegistry) HealthCheck() map[string]string {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	health := make(map[string]string)

	// Check hardcoded agents
	for name, agent := range ar.hardcodedAgents {
		if err := agent.ValidateConfiguration(); err != nil {
			health[name] = fmt.Sprintf("unhealthy: %v", err)
		} else {
			health[name] = "healthy"
		}
	}

	// Check configured agents
	for name, agent := range ar.configuredAgents {
		if err := agent.ValidateConfiguration(); err != nil {
			health[name] = fmt.Sprintf("unhealthy: %v", err)
		} else {
			health[name] = "healthy"
		}
	}

	return health
}

// GetAgentMetrics returns usage and performance metrics for agents
func (ar *AgentRegistry) GetAgentMetrics() map[string]interface{} {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	metrics := map[string]interface{}{
		"registry_stats": map[string]interface{}{
			"total_agents":        len(ar.hardcodedAgents) + len(ar.configuredAgents),
			"hardcoded_agents":    len(ar.hardcodedAgents),
			"configured_agents":   len(ar.configuredAgents),
			"alert_type_mappings": len(ar.alertTypeToAgent),
		},
		"capability_distribution": ar.getCapabilityDistribution(),
		"mcp_server_usage":        ar.GetMCPServerUsage(),
		"alert_type_coverage":     ar.getAlertTypeCoverage(),
	}

	return metrics
}

// getCapabilityDistribution returns distribution of capabilities across agents
func (ar *AgentRegistry) getCapabilityDistribution() map[string]int {
	capabilities := make(map[string]int)

	// Count hardcoded agent capabilities
	for _, agent := range ar.hardcodedAgents {
		for _, cap := range agent.GetCapabilities() {
			capabilities[cap]++
		}
	}

	// Count configured agent capabilities
	for _, agent := range ar.configuredAgents {
		for _, cap := range agent.GetCapabilities() {
			capabilities[cap]++
		}
	}

	return capabilities
}

// getAlertTypeCoverage returns coverage information for alert types
func (ar *AgentRegistry) getAlertTypeCoverage() map[string]interface{} {
	coverage := map[string]interface{}{
		"covered_types":   len(ar.alertTypeToAgent),
		"coverage_map":    ar.alertTypeToAgent,
		"fallback_agents": []string{},
	}

	// Identify agents that can serve as fallbacks
	fallbacks := []string{}
	for name := range ar.hardcodedAgents {
		fallbacks = append(fallbacks, name+" (hardcoded)")
	}
	for name := range ar.configuredAgents {
		fallbacks = append(fallbacks, name+" (configured)")
	}
	coverage["fallback_agents"] = fallbacks

	return coverage
}

// UnregisterAgent removes an agent from the registry
func (ar *AgentRegistry) UnregisterAgent(agentName string) error {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	// Check if it's a hardcoded agent
	if _, exists := ar.hardcodedAgents[agentName]; exists {
		delete(ar.hardcodedAgents, agentName)
		ar.logger.Info("Unregistered hardcoded agent", zap.String("name", agentName))
	}

	// Check if it's a configured agent
	if _, exists := ar.configuredAgents[agentName]; exists {
		delete(ar.configuredAgents, agentName)
		ar.logger.Info("Unregistered configured agent", zap.String("name", agentName))
	}

	// Remove from alert type mappings
	for alertType, mappedAgent := range ar.alertTypeToAgent {
		if mappedAgent == agentName {
			delete(ar.alertTypeToAgent, alertType)
		}
	}

	return nil
}

// SetChainRegistry sets the chain registry for multi-stage processing
func (ar *AgentRegistry) SetChainRegistry(chainRegistry ChainRegistryInterface) {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()
	ar.chainRegistry = chainRegistry
	ar.logger.Info("Chain registry registered with agent registry")
}

// RegisterChainBasedMapping registers a chain-based mapping for multi-stage processing
func (ar *AgentRegistry) RegisterChainBasedMapping(mapping *ChainBasedMapping) error {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	if mapping == nil {
		return fmt.Errorf("chain-based mapping cannot be nil")
	}

	if mapping.AlertType == "" {
		return fmt.Errorf("alert type is required for chain-based mapping")
	}

	if mapping.ChainID == "" {
		return fmt.Errorf("chain ID is required for chain-based mapping")
	}

	ar.chainBasedMappings[mapping.AlertType] = mapping
	ar.logger.Info("Registered chain-based mapping",
		zap.String("alert_type", mapping.AlertType),
		zap.String("chain_id", mapping.ChainID),
		zap.Int("stages", len(mapping.Stages)))

	return nil
}

// GetChainBasedMapping retrieves a chain-based mapping for an alert type
func (ar *AgentRegistry) GetChainBasedMapping(alertType string) (*ChainBasedMapping, bool) {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	mapping, exists := ar.chainBasedMappings[alertType]
	return mapping, exists
}

// IsChainBasedAlert checks if an alert type has chain-based processing
func (ar *AgentRegistry) IsChainBasedAlert(alertType string) bool {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	_, exists := ar.chainBasedMappings[alertType]
	return exists
}

// GetAgentForAlertWithChain determines the appropriate agent for a given alert with chain support
func (ar *AgentRegistry) GetAgentForAlertWithChain(alert *models.Alert, stageID string) (Agent, error) {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	// First check if this is a chain-based alert
	if mapping, exists := ar.chainBasedMappings[alert.AlertType]; exists {
		// Find the appropriate stage in the chain
		for _, stage := range mapping.Stages {
			if stage.StageID == stageID {
				// Get agent for this stage
				return ar.getAgentByName(stage.AgentType)
			}
		}

		// If no specific stage found, use the first stage
		if len(mapping.Stages) > 0 {
			return ar.getAgentByName(mapping.Stages[0].AgentType)
		}
	}

	// Fall back to regular agent routing
	return ar.GetAgentForAlert(alert)
}

// getAgentByName is a helper function to get an agent by name
func (ar *AgentRegistry) getAgentByName(agentName string) (Agent, error) {
	// Check configured agents first
	if agent, exists := ar.configuredAgents[agentName]; exists {
		return agent, nil
	}

	// Then check hardcoded agents
	if agent, exists := ar.hardcodedAgents[agentName]; exists {
		return agent, nil
	}

	return nil, fmt.Errorf("agent %s not found", agentName)
}

// GetChainForAlert retrieves the complete chain definition for an alert type
func (ar *AgentRegistry) GetChainForAlert(alert *models.Alert) (ChainDefinition, error) {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	// Check if we have a chain registry
	if ar.chainRegistry == nil {
		return nil, fmt.Errorf("chain registry not available")
	}

	// Get chain definition from chain registry
	return ar.chainRegistry.GetChainForAlertType(alert.AlertType)
}

// GetAllChainBasedMappings returns all chain-based mappings
func (ar *AgentRegistry) GetAllChainBasedMappings() map[string]*ChainBasedMapping {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	result := make(map[string]*ChainBasedMapping)
	for k, v := range ar.chainBasedMappings {
		result[k] = v
	}
	return result
}

// LoadChainBasedMappingsFromChainRegistry synchronizes chain-based mappings from chain registry
func (ar *AgentRegistry) LoadChainBasedMappingsFromChainRegistry() error {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	if ar.chainRegistry == nil {
		return fmt.Errorf("chain registry not available")
	}

	chains := ar.chainRegistry.ListChains()
	for alertType, chain := range chains {
		// Convert chain definition to chain-based mapping
		mapping := &ChainBasedMapping{
			AlertType: alertType,
			ChainID:   chain.GetName(),
			Stages:    make([]ChainStageMapping, 0),
		}

		// Convert chain stages to stage mappings
		for _, stage := range chain.GetStages() {
			stageMapping := ChainStageMapping{
				StageID:   stage.GetID(),
				StageName: stage.GetName(),
				AgentType: stage.GetAgentType(),
				Required:  stage.IsRequired(),
				Index:     stage.GetIndex(),
			}
			mapping.Stages = append(mapping.Stages, stageMapping)
		}

		ar.chainBasedMappings[alertType] = mapping
	}

	ar.logger.Info("Loaded chain-based mappings from chain registry",
		zap.Int("mappings_loaded", len(chains)))

	return nil
}

// ValidateChainBasedMappings validates all chain-based mappings
func (ar *AgentRegistry) ValidateChainBasedMappings() error {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	for alertType, mapping := range ar.chainBasedMappings {
		// Validate that all agents in the chain exist
		for _, stage := range mapping.Stages {
			if _, err := ar.getAgentByName(stage.AgentType); err != nil {
				return fmt.Errorf("chain validation failed for alert type %s: stage %s references unknown agent %s",
					alertType, stage.StageID, stage.AgentType)
			}
		}
	}

	return nil
}

// isAgentHealthy checks if an agent is in a healthy state for processing
func (ar *AgentRegistry) isAgentHealthy(agent Agent) bool {
	// If agent implements health checking interface, use it
	if healthCheckAgent, ok := agent.(*BaseAgent); ok {
		status := healthCheckAgent.GetHealthStatus()
		return status == AgentHealthStatusHealthy || status == AgentHealthStatusDegraded
	}

	// For other agent types, assume healthy if no validation errors
	return agent.ValidateConfiguration() == nil
}

// updateLookupMetrics updates registry lookup performance metrics
func (ar *AgentRegistry) updateLookupMetrics(duration time.Duration) {
	if ar.registryMetrics.LookupCount == 1 {
		ar.registryMetrics.AverageResponseTime = duration
	} else {
		totalTime := int64(ar.registryMetrics.AverageResponseTime) * (ar.registryMetrics.LookupCount - 1)
		ar.registryMetrics.AverageResponseTime = time.Duration((totalTime + int64(duration)) / ar.registryMetrics.LookupCount)
	}
}

// GetRegistryHealth returns comprehensive health information about the registry
func (ar *AgentRegistry) GetRegistryHealth() map[string]interface{} {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	healthInfo := map[string]interface{}{
		"registry_status":    string(ar.healthStatus),
		"metrics":           ar.registryMetrics,
		"total_agents":      len(ar.hardcodedAgents) + len(ar.configuredAgents),
		"issues":            make([]string, 0),
	}

	issues := make([]string, 0)

	// Check dependency health
	if ar.dependencyChecker != nil {
		dependencyHealth := ar.dependencyChecker.GetAllDependencyHealth()
		healthInfo["dependencies"] = dependencyHealth

		for name, health := range dependencyHealth {
			if health.Status != DependencyStatusHealthy {
				issues = append(issues, fmt.Sprintf("Dependency %s is %s", name, health.Status))
			}
		}
	}

	// Check degradation status
	if ar.degradationManager != nil {
		degradationStatus := ar.degradationManager.GetStatus()
		healthInfo["degradation"] = degradationStatus

		if level := ar.degradationManager.GetCurrentLevel(); level != errors.DegradationLevelNone {
			issues = append(issues, fmt.Sprintf("Registry is degraded to level %s", level))
		}
	}

	healthInfo["issues"] = issues

	return healthInfo
}