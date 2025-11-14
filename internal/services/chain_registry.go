package services

import (
	"fmt"

	"go.uber.org/zap"
)

// ChainRegistry manages alert type to processing chain mappings
// Equivalent to Python's ChainRegistry for multi-stage processing workflows
type ChainRegistry struct {
	chains map[string]*ChainDefinition
	logger *zap.Logger
}

// ChainDefinition defines a multi-stage processing workflow
type ChainDefinition struct {
	Name        string       `json:"name" yaml:"name"`
	AlertType   string       `json:"alert_type" yaml:"alert_type"`
	Description string       `json:"description,omitempty" yaml:"description,omitempty"`
	Stages      []ChainStage `json:"stages" yaml:"stages"`
}

// ChainStage represents a single stage in a processing chain
type ChainStage struct {
	ID          string       `json:"id" yaml:"id"`
	Name        string       `json:"name" yaml:"name"`
	Index       int          `json:"index" yaml:"index"`
	AgentType   string       `json:"agent_type" yaml:"agent_type"`
	AgentConfig *AgentConfig `json:"agent_config,omitempty" yaml:"agent_config,omitempty"`
	Description string       `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool         `json:"required" yaml:"required"`
}

// NewChainRegistry creates a new chain registry with default chains
func NewChainRegistry(logger *zap.Logger) *ChainRegistry {
	cr := &ChainRegistry{
		chains: make(map[string]*ChainDefinition),
		logger: logger,
	}

	// Initialize with default chains
	cr.initializeDefaultChains()

	return cr
}

// RegisterChain registers a new chain definition
func (cr *ChainRegistry) RegisterChain(chain *ChainDefinition) error {
	if err := cr.validateChain(chain); err != nil {
		return fmt.Errorf("chain validation failed: %w", err)
	}

	cr.chains[chain.AlertType] = chain
	cr.logger.Info("Registered chain",
		zap.String("alert_type", chain.AlertType),
		zap.String("chain_name", chain.Name),
		zap.Int("stages", len(chain.Stages)),
	)

	return nil
}

// GetChainForAlertType retrieves the chain definition for an alert type
func (cr *ChainRegistry) GetChainForAlertType(alertType string) (*ChainDefinition, error) {
	chain, exists := cr.chains[alertType]
	if !exists {
		// Return default chain if specific chain not found
		return cr.getDefaultChain(alertType), nil
	}

	return chain, nil
}

// ListChains returns all registered chain definitions
func (cr *ChainRegistry) ListChains() map[string]*ChainDefinition {
	result := make(map[string]*ChainDefinition)
	for k, v := range cr.chains {
		result[k] = v
	}
	return result
}

// initializeDefaultChains sets up default processing chains
func (cr *ChainRegistry) initializeDefaultChains() {
	// Default Kubernetes chain
	kubernetesChain := &ChainDefinition{
		Name:        "Kubernetes Security Analysis",
		AlertType:   "kubernetes",
		Description: "Multi-stage Kubernetes security incident analysis",
		Stages: []ChainStage{
			{
				ID:          "k8s-initial-analysis",
				Name:        "Initial Kubernetes Analysis",
				Index:       0,
				AgentType:   "kubernetes",
				Description: "Initial Kubernetes security assessment",
				Required:    true,
				AgentConfig: &AgentConfig{
					Type: "kubernetes",
					Settings: map[string]interface{}{
						"enable_tools":  true,
						"cluster_name":  "default",
						"temperature":   0.3,
					},
				},
			},
			{
				ID:          "final-synthesis",
				Name:        "Final Analysis Synthesis",
				Index:       1,
				AgentType:   "base",
				Description: "Synthesize findings into final analysis",
				Required:    true,
				AgentConfig: &AgentConfig{
					Type: "base",
					Settings: map[string]interface{}{
						"temperature": 0.7,
						"max_tokens":  2048,
					},
				},
			},
		},
	}

	// Default general chain
	generalChain := &ChainDefinition{
		Name:        "General Security Analysis",
		AlertType:   "general",
		Description: "General purpose security incident analysis",
		Stages: []ChainStage{
			{
				ID:          "general-analysis",
				Name:        "Security Analysis",
				Index:       0,
				AgentType:   "base",
				Description: "General security incident analysis",
				Required:    true,
				AgentConfig: &AgentConfig{
					Type: "base",
					Settings: map[string]interface{}{
						"temperature": 0.7,
						"max_tokens":  4096,
					},
				},
			},
		},
	}

	// Container security chain
	containerChain := &ChainDefinition{
		Name:        "Container Security Analysis",
		AlertType:   "container",
		Description: "Container and pod security analysis",
		Stages: []ChainStage{
			{
				ID:          "container-analysis",
				Name:        "Container Security Assessment",
				Index:       0,
				AgentType:   "kubernetes",
				Description: "Container security and runtime analysis",
				Required:    true,
				AgentConfig: &AgentConfig{
					Type: "kubernetes",
					Settings: map[string]interface{}{
						"enable_tools": true,
						"temperature":  0.3,
					},
				},
			},
		},
	}

	// Register default chains
	cr.chains["kubernetes"] = kubernetesChain
	cr.chains["general"] = generalChain
	cr.chains["container"] = containerChain
	cr.chains["k8s"] = kubernetesChain  // Alias
	cr.chains["pod"] = containerChain   // Alias
}

// getDefaultChain returns a default chain for unknown alert types
func (cr *ChainRegistry) getDefaultChain(alertType string) *ChainDefinition {
	return &ChainDefinition{
		Name:        "Default Analysis Chain",
		AlertType:   alertType,
		Description: "Default single-stage analysis for unknown alert types",
		Stages: []ChainStage{
			{
				ID:          "default-analysis",
				Name:        "Default Analysis",
				Index:       0,
				AgentType:   "base",
				Description: "General purpose analysis",
				Required:    true,
				AgentConfig: &AgentConfig{
					Type: "base",
					Settings: map[string]interface{}{
						"temperature": 0.7,
					},
				},
			},
		},
	}
}

// validateChain validates a chain definition
func (cr *ChainRegistry) validateChain(chain *ChainDefinition) error {
	if chain == nil {
		return fmt.Errorf("chain definition cannot be nil")
	}

	if chain.Name == "" {
		return fmt.Errorf("chain name is required")
	}

	if chain.AlertType == "" {
		return fmt.Errorf("alert type is required")
	}

	if len(chain.Stages) == 0 {
		return fmt.Errorf("chain must have at least one stage")
	}

	// Validate stages
	stageIDs := make(map[string]bool)
	for i, stage := range chain.Stages {
		if stage.ID == "" {
			return fmt.Errorf("stage %d: ID is required", i)
		}

		if stage.Name == "" {
			return fmt.Errorf("stage %d: name is required", i)
		}

		if stage.AgentType == "" {
			return fmt.Errorf("stage %d: agent type is required", i)
		}

		// Check for duplicate stage IDs
		if stageIDs[stage.ID] {
			return fmt.Errorf("duplicate stage ID: %s", stage.ID)
		}
		stageIDs[stage.ID] = true

		// Validate stage index
		if stage.Index != i {
			cr.logger.Warn("Stage index mismatch",
				zap.String("stage_id", stage.ID),
				zap.Int("expected", i),
				zap.Int("actual", stage.Index),
			)
			// Auto-correct the index
			chain.Stages[i].Index = i
		}
	}

	return nil
}

// GetChainStats returns statistics about registered chains
func (cr *ChainRegistry) GetChainStats() map[string]interface{} {
	totalChains := len(cr.chains)
	totalStages := 0
	alertTypes := make([]string, 0, len(cr.chains))

	for alertType, chain := range cr.chains {
		alertTypes = append(alertTypes, alertType)
		totalStages += len(chain.Stages)
	}

	return map[string]interface{}{
		"total_chains":  totalChains,
		"total_stages":  totalStages,
		"alert_types":   alertTypes,
	}
}