package agents

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// ConfigurableAgent represents a YAML-configured agent that can be defined without code changes
// This is equivalent to Python's ConfigurableAgent for maximum flexibility
type ConfigurableAgent struct {
	*BaseAgent
	definition          *AgentDefinition
	llmIntegration      LLMIntegrationInterface
	mcpServerRegistry   *mcp.MCPServerRegistry
	logger              *zap.Logger
}

// AgentDefinition represents the complete YAML-based agent configuration
type AgentDefinition struct {
	Name           string                 `yaml:"name" json:"name"`
	Description    string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Type           string                 `yaml:"type" json:"type"`
	Version        string                 `yaml:"version,omitempty" json:"version,omitempty"`
	Capabilities   []string               `yaml:"capabilities" json:"capabilities"`
	AlertTypes     []string               `yaml:"alert_types,omitempty" json:"alert_types,omitempty"`
	Settings       *AgentSettings         `yaml:"settings,omitempty" json:"settings,omitempty"`
	Instructions   InstructionLayers      `yaml:"instructions" json:"instructions"`
	Tools          []ToolDefinition       `yaml:"tools,omitempty" json:"tools,omitempty"`
	Prompts        map[string]string      `yaml:"prompts,omitempty" json:"prompts,omitempty"`
	Variables      map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`
	IterationStrategy IterationStrategy   `yaml:"iteration_strategy,omitempty" json:"iteration_strategy,omitempty"`
	Workflows      []WorkflowStep         `yaml:"workflows,omitempty" json:"workflows,omitempty"`
}

// InstructionLayers represents the three-tier instruction system from Python TARSy
type InstructionLayers struct {
	General   string   `yaml:"general" json:"general"`
	MCP       string   `yaml:"mcp,omitempty" json:"mcp,omitempty"`
	Custom    []string `yaml:"custom,omitempty" json:"custom,omitempty"`
}

// ToolDefinition represents a tool that the agent can use
type ToolDefinition struct {
	Name        string                 `yaml:"name" json:"name"`
	Server      string                 `yaml:"server" json:"server"`
	Description string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Parameters  map[string]interface{} `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	Required    []string               `yaml:"required,omitempty" json:"required,omitempty"`
	Conditions  []string               `yaml:"conditions,omitempty" json:"conditions,omitempty"`
}

// IterationStrategy defines how the agent should iterate through analysis
type IterationStrategy struct {
	Strategy    string `yaml:"strategy" json:"strategy"`         // "react", "chain", "single"
	MaxSteps    int    `yaml:"max_steps,omitempty" json:"max_steps,omitempty"`
	Convergence string `yaml:"convergence,omitempty" json:"convergence,omitempty"` // "content", "tools", "confidence"
}

// WorkflowStep represents a step in an agent workflow
type WorkflowStep struct {
	Name        string            `yaml:"name" json:"name"`
	Type        string            `yaml:"type" json:"type"`         // "prompt", "tool", "condition", "analysis"
	Condition   string            `yaml:"condition,omitempty" json:"condition,omitempty"`
	Parameters  map[string]string `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	ToolName    string            `yaml:"tool_name,omitempty" json:"tool_name,omitempty"`
	PromptKey   string            `yaml:"prompt_key,omitempty" json:"prompt_key,omitempty"`
	NextSteps   []string          `yaml:"next_steps,omitempty" json:"next_steps,omitempty"`
}

// NewConfigurableAgent creates a new configurable agent from YAML definition
func NewConfigurableAgent(
	yamlContent []byte,
	llmIntegration LLMIntegrationInterface,
	mcpServerRegistry *mcp.MCPServerRegistry,
	logger *zap.Logger,
) (*ConfigurableAgent, error) {
	var definition AgentDefinition
	if err := yaml.Unmarshal(yamlContent, &definition); err != nil {
		return nil, fmt.Errorf("failed to parse agent YAML: %w", err)
	}

	// Resolve environment variables in the definition
	if err := resolveEnvironmentVariables(&definition); err != nil {
		return nil, fmt.Errorf("failed to resolve environment variables: %w", err)
	}

	// Validate the definition
	if err := validateAgentDefinition(&definition); err != nil {
		return nil, fmt.Errorf("invalid agent definition: %w", err)
	}

	// Create base agent with definition settings
	settings := definition.Settings
	if settings == nil {
		settings = DefaultAgentSettings()
	}

	// Apply iteration strategy settings
	if definition.IterationStrategy.MaxSteps > 0 {
		settings.MaxIterations = definition.IterationStrategy.MaxSteps
	}

	baseAgent := NewBaseAgent(definition.Type, definition.Capabilities, settings)

	return &ConfigurableAgent{
		BaseAgent:         baseAgent,
		definition:        &definition,
		llmIntegration:    llmIntegration,
		mcpServerRegistry: mcpServerRegistry,
		logger:            logger,
	}, nil
}

// NewConfigurableAgentFromFile creates a configurable agent from a YAML file
func NewConfigurableAgentFromFile(
	yamlPath string,
	llmIntegration LLMIntegrationInterface,
	mcpServerRegistry *mcp.MCPServerRegistry,
	logger *zap.Logger,
) (*ConfigurableAgent, error) {
	// Resolve path relative to current working directory
	if !filepath.IsAbs(yamlPath) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get working directory: %w", err)
		}
		yamlPath = filepath.Join(wd, yamlPath)
	}

	// Read the YAML file
	yamlContent, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read agent definition file %s: %w", yamlPath, err)
	}

	logger.Info("Loading configurable agent from file",
		zap.String("path", yamlPath),
		zap.Int("content_size", len(yamlContent)))

	// Create agent from content
	agent, err := NewConfigurableAgent(yamlContent, llmIntegration, mcpServerRegistry, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent from file %s: %w", yamlPath, err)
	}

	return agent, nil
}

// ProcessAlert implements the Agent interface with configurable behavior using ReAct pattern
func (ca *ConfigurableAgent) ProcessAlert(ctx context.Context, alert *models.Alert, chainCtx *models.ChainContext) (*models.AgentExecutionResult, error) {
	ca.logger.Info("Starting configurable agent processing",
		zap.String("agent_name", ca.definition.Name),
		zap.String("alert_type", alert.AlertType),
		zap.String("strategy", ca.definition.IterationStrategy.Strategy))

	// Create execution context with timeout from settings
	ctx, cancel := context.WithTimeout(ctx, ca.settings.TimeoutDuration)
	defer cancel()

	// Check if this agent handles this alert type
	if !ca.canHandleAlert(alert) {
		return nil, fmt.Errorf("agent %s cannot handle alert type %s", ca.definition.Name, alert.AlertType)
	}

	// Execute based on iteration strategy
	var finalAnalysis string
	var err error

	switch ca.definition.IterationStrategy.Strategy {
	case "react":
		finalAnalysis, err = ca.executeReActStrategy(ctx, alert, chainCtx)
	case "workflow":
		finalAnalysis, err = ca.executeWorkflowStrategy(ctx, alert, chainCtx)
	case "single":
		finalAnalysis, err = ca.executeSingleStrategy(ctx, alert, chainCtx)
	default:
		// Default to ReAct if no strategy specified
		finalAnalysis, err = ca.executeReActStrategy(ctx, alert, chainCtx)
	}

	if err != nil {
		return nil, fmt.Errorf("configurable agent execution failed: %w", err)
	}

	// Create execution result
	result := &models.AgentExecutionResult{
		Status:        models.StageStatusCompleted,
		AgentName:     ca.definition.Name,
		TimestampUs:   time.Now().UnixMicro(),
		ResultSummary: stringPtr(fmt.Sprintf("Analysis completed by %s using %s strategy",
			ca.definition.Name, ca.definition.IterationStrategy.Strategy)),
		FinalAnalysis: &finalAnalysis,
	}

	ca.logger.Info("Configurable agent processing completed",
		zap.String("agent_name", ca.definition.Name),
		zap.String("strategy", ca.definition.IterationStrategy.Strategy),
		zap.Int("analysis_length", len(finalAnalysis)))

	return result, nil
}

// buildInstructions creates the complete instruction set using the three-tier system
func (ca *ConfigurableAgent) buildInstructions(alert *models.Alert, chainCtx *models.ChainContext) string {
	instructions := ""

	// Layer 1: General instructions
	if ca.definition.Instructions.General != "" {
		instructions += "# General Instructions\n"
		instructions += ca.resolveVariables(ca.definition.Instructions.General, alert, chainCtx)
		instructions += "\n\n"
	}

	// Layer 2: MCP-specific instructions
	if ca.definition.Instructions.MCP != "" {
		instructions += "# Tool Usage Instructions\n"
		instructions += ca.resolveVariables(ca.definition.Instructions.MCP, alert, chainCtx)
		instructions += "\n\n"
	}

	// Layer 3: Custom instructions
	if len(ca.definition.Instructions.Custom) > 0 {
		instructions += "# Custom Instructions\n"
		for i, customInstr := range ca.definition.Instructions.Custom {
			instructions += fmt.Sprintf("%d. %s\n", i+1, ca.resolveVariables(customInstr, alert, chainCtx))
		}
		instructions += "\n"
	}

	// Add tool information if available
	if len(ca.definition.Tools) > 0 {
		instructions += "# Available Tools\n"
		for _, tool := range ca.definition.Tools {
			instructions += fmt.Sprintf("- %s: %s\n", tool.Name, tool.Description)
		}
		instructions += "\n"
	}

	return instructions
}

// resolveVariables replaces template variables in instructions
func (ca *ConfigurableAgent) resolveVariables(template string, alert *models.Alert, chainCtx *models.ChainContext) string {
	// Simple variable resolution - can be enhanced with proper template engine
	resolved := template

	// Replace common variables
	if chainCtx != nil {
		resolved = replaceVariable(resolved, "ALERT_TYPE", alert.AlertType)
		resolved = replaceVariable(resolved, "SESSION_ID", chainCtx.SessionID)
		resolved = replaceVariable(resolved, "CURRENT_STAGE", chainCtx.CurrentStageName)
	}

	// Replace custom variables from definition
	for key, value := range ca.definition.Variables {
		if strValue, ok := value.(string); ok {
			resolved = replaceVariable(resolved, key, strValue)
		}
	}

	return resolved
}

// executeReActStrategy executes the ReAct (Reasoning + Acting) pattern
func (ca *ConfigurableAgent) executeReActStrategy(ctx context.Context, alert *models.Alert, chainCtx *models.ChainContext) (string, error) {
	maxIterations := ca.settings.MaxIterations
	if ca.definition.IterationStrategy.MaxSteps > 0 {
		maxIterations = ca.definition.IterationStrategy.MaxSteps
	}

	conversationHistory := []Message{}

	// Build system prompt with configurable instructions
	systemPrompt := ca.buildSystemPrompt(alert, chainCtx)

	// Start with initial reasoning
	initialThought := ca.buildInitialThought(alert, chainCtx)
	conversationHistory = append(conversationHistory, Message{
		Role:    "user",
		Content: initialThought,
	})

	for iteration := 0; iteration < maxIterations; iteration++ {
		ca.logger.Debug("Starting configurable agent ReAct iteration",
			zap.Int("iteration", iteration),
			zap.String("agent_name", ca.definition.Name))

		// Reasoning: Ask LLM what to do next
		llmRequest := &EnhancedGenerateRequest{
			GenerateWithToolsRequest: &GenerateWithToolsRequest{
				GenerateRequest: &GenerateRequest{
					Messages:     conversationHistory,
					SystemPrompt: &systemPrompt,
					Model:        "gpt-4",
					Temperature:  float64Ptr(float64(ca.settings.Temperature)),
					MaxTokens:    &ca.settings.MaxTokens,
				},
				EnableTools: len(ca.definition.Tools) > 0,
			},
			SessionID:        chainCtx.SessionID,
			AgentType:        ca.definition.Name,
			IterationIndex:   &iteration,
			TrackCost:        true,
			EstimateCost:     true,
		}

		llmResponse, err := ca.llmIntegration.GenerateWithTracking(ctx, llmRequest)
		if err != nil {
			return "", fmt.Errorf("LLM generation failed at iteration %d: %w", iteration, err)
		}

		// Add LLM response to conversation
		conversationHistory = append(conversationHistory, Message{
			Role:    "assistant",
			Content: llmResponse.Content,
		})

		// Acting: Execute any tools the LLM requested
		if len(ca.definition.Tools) > 0 && ca.needsToolExecution(llmResponse.Content) {
			toolResults, err := ca.executeConfigurableTools(ctx, llmResponse.Content, alert, chainCtx)
			if err != nil {
				ca.logger.Warn("Tool execution failed",
					zap.Error(err),
					zap.Int("iteration", iteration))
				conversationHistory = append(conversationHistory, Message{
					Role:    "user",
					Content: fmt.Sprintf("Tool execution failed: %v. Please continue analysis without tools.", err),
				})
			} else if toolResults != "" {
				conversationHistory = append(conversationHistory, Message{
					Role:    "user",
					Content: fmt.Sprintf("Tool execution results:\n%s\n\nPlease analyze these results and continue.", toolResults),
				})
			}
		}

		// Check if we have a final conclusion
		if ca.hasReachedConclusion(llmResponse.Content) {
			ca.logger.Info("Configurable agent ReAct pattern concluded",
				zap.Int("iterations_used", iteration+1),
				zap.String("agent_name", ca.definition.Name))
			return ca.extractFinalAnalysis(conversationHistory), nil
		}
	}

	// Final summary request
	finalPrompt := "Please provide a final comprehensive analysis and recommendations based on all the information gathered above."
	conversationHistory = append(conversationHistory, Message{
		Role:    "user",
		Content: finalPrompt,
	})

	finalRequest := &EnhancedGenerateRequest{
		GenerateWithToolsRequest: &GenerateWithToolsRequest{
			GenerateRequest: &GenerateRequest{
				Messages:     conversationHistory,
				SystemPrompt: &systemPrompt,
				Model:        "gpt-4",
				Temperature:  float64Ptr(float64(ca.settings.Temperature)),
				MaxTokens:    &ca.settings.MaxTokens,
			},
			EnableTools: false,
		},
		SessionID:     chainCtx.SessionID,
		AgentType:     ca.definition.Name,
		TrackCost:     true,
		EstimateCost:  true,
	}

	finalResponse, err := ca.llmIntegration.GenerateWithTracking(ctx, finalRequest)
	if err != nil {
		return "", fmt.Errorf("final LLM generation failed: %w", err)
	}

	return finalResponse.Content, nil
}

// executeWorkflowStrategy executes a predefined workflow
func (ca *ConfigurableAgent) executeWorkflowStrategy(ctx context.Context, alert *models.Alert, chainCtx *models.ChainContext) (string, error) {
	if len(ca.definition.Workflows) == 0 {
		return "", fmt.Errorf("no workflows defined for agent %s", ca.definition.Name)
	}

	results := []string{}

	for _, step := range ca.definition.Workflows {
		ca.logger.Debug("Executing workflow step",
			zap.String("step", step.Name),
			zap.String("type", step.Type))

		// Check step condition if specified
		if step.Condition != "" && !ca.evaluateCondition(step.Condition, alert, chainCtx) {
			ca.logger.Debug("Skipping step due to condition", zap.String("step", step.Name))
			continue
		}

		var stepResult string
		var err error

		switch step.Type {
		case "prompt":
			stepResult, err = ca.executePromptStep(ctx, step, alert, chainCtx)
		case "tool":
			stepResult, err = ca.executeToolStep(ctx, step, alert, chainCtx)
		case "analysis":
			stepResult, err = ca.executeAnalysisStep(ctx, step, alert, chainCtx)
		default:
			err = fmt.Errorf("unknown workflow step type: %s", step.Type)
		}

		if err != nil {
			return "", fmt.Errorf("workflow step %s failed: %w", step.Name, err)
		}

		if stepResult != "" {
			results = append(results, fmt.Sprintf("Step %s:\n%s", step.Name, stepResult))
		}
	}

	return strings.Join(results, "\n\n"), nil
}

// executeSingleStrategy executes a single LLM call with all instructions
func (ca *ConfigurableAgent) executeSingleStrategy(ctx context.Context, alert *models.Alert, chainCtx *models.ChainContext) (string, error) {
	systemPrompt := ca.buildSystemPrompt(alert, chainCtx)
	userPrompt := ca.buildUserPrompt(alert, chainCtx)

	request := &EnhancedGenerateRequest{
		GenerateWithToolsRequest: &GenerateWithToolsRequest{
			GenerateRequest: &GenerateRequest{
				Messages: []Message{{
					Role:    "user",
					Content: userPrompt,
				}},
				SystemPrompt: &systemPrompt,
				Model:        "gpt-4",
				Temperature:  float64Ptr(float64(ca.settings.Temperature)),
				MaxTokens:    &ca.settings.MaxTokens,
			},
			EnableTools: false, // Single strategy doesn't use tools
		},
		SessionID:     chainCtx.SessionID,
		AgentType:     ca.definition.Name,
		TrackCost:     true,
		EstimateCost:  true,
	}

	response, err := ca.llmIntegration.GenerateWithTracking(ctx, request)
	if err != nil {
		return "", fmt.Errorf("single strategy LLM generation failed: %w", err)
	}

	return response.Content, nil
}

// getToolNames extracts tool names for reporting
func (ca *ConfigurableAgent) getToolNames() []string {
	names := make([]string, len(ca.definition.Tools))
	for i, tool := range ca.definition.Tools {
		names[i] = tool.Name
	}
	return names
}

// GetAgentType returns the configurable agent type
func (ca *ConfigurableAgent) GetAgentType() string {
	return fmt.Sprintf("configurable-%s", ca.definition.Type)
}

// GetDefinition returns the agent definition
func (ca *ConfigurableAgent) GetDefinition() *AgentDefinition {
	return ca.definition
}

// ValidateConfiguration validates the configurable agent configuration
func (ca *ConfigurableAgent) ValidateConfiguration() error {
	// Validate base configuration
	if err := ca.BaseAgent.ValidateConfiguration(); err != nil {
		return err
	}

	// Validate configurable-specific configuration
	return validateAgentDefinition(ca.definition)
}

// validateAgentDefinition validates the agent definition structure
func validateAgentDefinition(def *AgentDefinition) error {
	if def.Name == "" {
		return fmt.Errorf("agent name is required")
	}

	if def.Type == "" {
		return fmt.Errorf("agent type is required")
	}

	if len(def.Capabilities) == 0 {
		return fmt.Errorf("agent must have at least one capability")
	}

	if def.Instructions.General == "" {
		return fmt.Errorf("general instructions are required")
	}

	// Validate tools
	toolNames := make(map[string]bool)
	for _, tool := range def.Tools {
		if tool.Name == "" {
			return fmt.Errorf("tool name is required")
		}
		if tool.Server == "" {
			return fmt.Errorf("tool server is required for tool: %s", tool.Name)
		}
		if toolNames[tool.Name] {
			return fmt.Errorf("duplicate tool name: %s", tool.Name)
		}
		toolNames[tool.Name] = true
	}

	return nil
}


// Helper methods for the various strategies

// canHandleAlert checks if this agent can handle the given alert type
func (ca *ConfigurableAgent) canHandleAlert(alert *models.Alert) bool {
	// If no alert types specified, agent can handle any alert type
	if len(ca.definition.AlertTypes) == 0 {
		return true
	}

	// Check if alert type is in the allowed list
	for _, alertType := range ca.definition.AlertTypes {
		if alertType == alert.AlertType || alertType == "*" {
			return true
		}
	}
	return false
}

// buildSystemPrompt creates the system prompt from configurable instructions
func (ca *ConfigurableAgent) buildSystemPrompt(alert *models.Alert, chainCtx *models.ChainContext) string {
	prompt := ca.buildInstructions(alert, chainCtx)

	// Add context information
	prompt += fmt.Sprintf(`

CURRENT CONTEXT:
- Agent: %s
- Alert Type: %s
- Session ID: %s
- Available Tools: %v

ANALYSIS APPROACH:
Based on the instructions above, analyze the alert and use available tools as needed.
When you have sufficient information, provide a comprehensive final analysis.`,
		ca.definition.Name,
		alert.AlertType,
		chainCtx.SessionID,
		ca.getToolNames())

	return prompt
}

// buildInitialThought creates the initial reasoning prompt
func (ca *ConfigurableAgent) buildInitialThought(alert *models.Alert, chainCtx *models.ChainContext) string {
	prompt := fmt.Sprintf(`I need to analyze this alert using the configured instructions:

Alert Type: %s
Alert Data: %v
Session ID: %s

Based on my instructions, I should:
%s

Let me start by understanding the current situation and determining what information I need to gather.`,
		alert.AlertType,
		alert.Data,
		chainCtx.SessionID,
		ca.buildQuickInstructionSummary())

	return prompt
}

// buildUserPrompt creates the user prompt for single strategy
func (ca *ConfigurableAgent) buildUserPrompt(alert *models.Alert, chainCtx *models.ChainContext) string {
	prompt := fmt.Sprintf(`Please analyze this alert:

Alert Type: %s
Alert Data: %v
Session ID: %s

Provide a comprehensive analysis following the instructions in your system prompt.`,
		alert.AlertType,
		alert.Data,
		chainCtx.SessionID)

	return prompt
}

// buildQuickInstructionSummary creates a quick summary of key instructions
func (ca *ConfigurableAgent) buildQuickInstructionSummary() string {
	summary := []string{}

	if len(ca.definition.Instructions.Custom) > 0 {
		summary = append(summary, "- Follow custom instructions: "+strings.Join(ca.definition.Instructions.Custom, ", "))
	}

	if len(ca.definition.Tools) > 0 {
		summary = append(summary, "- Use available tools: "+strings.Join(ca.getToolNames(), ", "))
	}

	if len(summary) == 0 {
		summary = append(summary, "- Follow general analysis guidelines")
	}

	return strings.Join(summary, "\n")
}

// needsToolExecution checks if the LLM response indicates tool usage is needed
func (ca *ConfigurableAgent) needsToolExecution(content string) bool {
	toolIndicators := []string{
		"use tool", "execute", "run command", "check", "query",
		"investigate", "examine", "look up", "fetch", "get",
	}

	contentLower := strings.ToLower(content)
	for _, indicator := range toolIndicators {
		if strings.Contains(contentLower, indicator) {
			return true
		}
	}

	// Also check if any tool names are mentioned
	for _, tool := range ca.definition.Tools {
		if strings.Contains(contentLower, strings.ToLower(tool.Name)) {
			return true
		}
	}

	return false
}

// hasReachedConclusion checks if the LLM has provided a final analysis
func (ca *ConfigurableAgent) hasReachedConclusion(content string) bool {
	conclusionIndicators := []string{
		"final analysis", "conclusion", "summary", "in conclusion",
		"based on all the information", "comprehensive analysis complete",
		"final recommendations", "analysis complete",
	}

	contentLower := strings.ToLower(content)
	for _, indicator := range conclusionIndicators {
		if strings.Contains(contentLower, indicator) {
			return true
		}
	}

	return false
}

// extractFinalAnalysis extracts the final analysis from conversation history
func (ca *ConfigurableAgent) extractFinalAnalysis(conversationHistory []Message) string {
	// Look for the last assistant message with substantial content
	for i := len(conversationHistory) - 1; i >= 0; i-- {
		if conversationHistory[i].Role == "assistant" && len(conversationHistory[i].Content) > 100 {
			return conversationHistory[i].Content
		}
	}

	// Fallback: combine the last few messages
	if len(conversationHistory) >= 2 {
		lastMessages := conversationHistory[len(conversationHistory)-2:]
		combined := []string{}
		for _, msg := range lastMessages {
			if msg.Role == "assistant" {
				combined = append(combined, msg.Content)
			}
		}
		return strings.Join(combined, "\n\n")
	}

	return "Analysis completed but no detailed output available."
}

// executeConfigurableTools executes tools based on LLM requests
func (ca *ConfigurableAgent) executeConfigurableTools(ctx context.Context, llmContent string, alert *models.Alert, chainCtx *models.ChainContext) (string, error) {
	results := []string{}

	// Parse the LLM content to determine what tools to run
	toolCommands := ca.parseConfigurableToolRequests(llmContent, alert, chainCtx)

	for _, command := range toolCommands {
		ca.logger.Debug("Executing configurable tool",
			zap.String("tool", command.Tool),
			zap.String("server", command.Server))

		result, err := ca.mcpServerRegistry.ExecuteToolOnServer(ctx, command.Server, command.Tool, command.Parameters)
		if err != nil {
			ca.logger.Error("Configurable tool execution failed",
				zap.String("tool", command.Tool),
				zap.String("server", command.Server),
				zap.Error(err))
			results = append(results, fmt.Sprintf("Tool %s failed: %v", command.Tool, err))
		} else if result != nil && result.Success {
			results = append(results, fmt.Sprintf("Tool %s output:\n%s", command.Tool, result.Content))
		} else if result != nil {
			results = append(results, fmt.Sprintf("Tool %s failed: %s", command.Tool, result.Error))
		}
	}

	if len(results) == 0 {
		return "", nil
	}

	return strings.Join(results, "\n\n"), nil
}

// parseConfigurableToolRequests parses LLM content to extract tool execution requests
func (ca *ConfigurableAgent) parseConfigurableToolRequests(content string, alert *models.Alert, chainCtx *models.ChainContext) []ToolCommand {
	commands := []ToolCommand{}
	contentLower := strings.ToLower(content)

	// Check each configured tool to see if it should be executed
	for _, tool := range ca.definition.Tools {
		shouldExecute := false

		// Check if tool is mentioned by name
		if strings.Contains(contentLower, strings.ToLower(tool.Name)) {
			shouldExecute = true
		}

		// Check conditions if specified
		if len(tool.Conditions) > 0 {
			for _, condition := range tool.Conditions {
				if strings.Contains(contentLower, strings.ToLower(condition)) {
					shouldExecute = true
					break
				}
			}
		}

		if shouldExecute {
			// Build parameters with variable resolution
			parameters := make(map[string]interface{})
			for key, value := range tool.Parameters {
				if strValue, ok := value.(string); ok {
					resolved := ca.resolveVariables(strValue, alert, chainCtx)
					parameters[key] = resolved
				} else {
					parameters[key] = value
				}
			}

			commands = append(commands, ToolCommand{
				Server:     tool.Server,
				Tool:       tool.Name,
				Parameters: parameters,
			})
		}
	}

	return commands
}

// Workflow execution helper methods

// evaluateCondition evaluates a condition for workflow steps
func (ca *ConfigurableAgent) evaluateCondition(condition string, alert *models.Alert, chainCtx *models.ChainContext) bool {
	// Simple condition evaluation - can be enhanced with expression parser
	resolved := ca.resolveVariables(condition, alert, chainCtx)

	// Basic conditions
	if resolved == "true" {
		return true
	}
	if resolved == "false" {
		return false
	}

	// Check if condition contains alert type
	if strings.Contains(resolved, alert.AlertType) {
		return true
	}

	return false // Default to false for unrecognized conditions
}

// executePromptStep executes a prompt-based workflow step
func (ca *ConfigurableAgent) executePromptStep(ctx context.Context, step WorkflowStep, alert *models.Alert, chainCtx *models.ChainContext) (string, error) {
	promptKey := step.PromptKey
	if promptKey == "" {
		return "", fmt.Errorf("prompt_key required for prompt step")
	}

	promptTemplate, exists := ca.definition.Prompts[promptKey]
	if !exists {
		return "", fmt.Errorf("prompt not found: %s", promptKey)
	}

	prompt := ca.resolveVariables(promptTemplate, alert, chainCtx)

	request := &EnhancedGenerateRequest{
		GenerateWithToolsRequest: &GenerateWithToolsRequest{
			GenerateRequest: &GenerateRequest{
				Messages: []Message{{
					Role:    "user",
					Content: prompt,
				}},
				Model:       "gpt-4",
				Temperature: float64Ptr(float64(ca.settings.Temperature)),
				MaxTokens:   &ca.settings.MaxTokens,
			},
			EnableTools: false,
		},
		SessionID: chainCtx.SessionID,
		AgentType: ca.definition.Name,
	}

	response, err := ca.llmIntegration.GenerateWithTracking(ctx, request)
	if err != nil {
		return "", err
	}

	return response.Content, nil
}

// executeToolStep executes a tool-based workflow step
func (ca *ConfigurableAgent) executeToolStep(ctx context.Context, step WorkflowStep, alert *models.Alert, chainCtx *models.ChainContext) (string, error) {
	toolName := step.ToolName
	if toolName == "" {
		return "", fmt.Errorf("tool_name required for tool step")
	}

	// Find the tool definition
	var toolDef *ToolDefinition
	for _, tool := range ca.definition.Tools {
		if tool.Name == toolName {
			toolDef = &tool
			break
		}
	}

	if toolDef == nil {
		return "", fmt.Errorf("tool not found: %s", toolName)
	}

	// Build parameters from step parameters and tool defaults
	parameters := make(map[string]interface{})
	for key, value := range toolDef.Parameters {
		parameters[key] = value
	}
	for key, value := range step.Parameters {
		resolved := ca.resolveVariables(value, alert, chainCtx)
		parameters[key] = resolved
	}

	result, err := ca.mcpServerRegistry.ExecuteToolOnServer(ctx, toolDef.Server, toolDef.Name, parameters)
	if err != nil {
		return "", err
	}

	if result != nil && result.Success {
		return result.GetContentAsString(), nil
	} else if result != nil {
		return "", fmt.Errorf("tool execution failed: %s", result.Error)
	}

	return "", nil
}

// executeAnalysisStep executes an analysis workflow step
func (ca *ConfigurableAgent) executeAnalysisStep(ctx context.Context, step WorkflowStep, alert *models.Alert, chainCtx *models.ChainContext) (string, error) {
	// Analysis steps combine prompts with potential tool usage
	systemPrompt := ca.buildInstructions(alert, chainCtx)

	userPrompt := fmt.Sprintf("Perform analysis step: %s\nAlert: %s\nData: %v",
		step.Name, alert.AlertType, alert.Data)

	request := &EnhancedGenerateRequest{
		GenerateWithToolsRequest: &GenerateWithToolsRequest{
			GenerateRequest: &GenerateRequest{
				Messages: []Message{{
					Role:    "user",
					Content: userPrompt,
				}},
				SystemPrompt: &systemPrompt,
				Model:        "gpt-4",
				Temperature:  float64Ptr(float64(ca.settings.Temperature)),
				MaxTokens:    &ca.settings.MaxTokens,
			},
			EnableTools: len(ca.definition.Tools) > 0,
		},
		SessionID: chainCtx.SessionID,
		AgentType: ca.definition.Name,
	}

	response, err := ca.llmIntegration.GenerateWithTracking(ctx, request)
	if err != nil {
		return "", err
	}

	return response.Content, nil
}

// resolveEnvironmentVariables resolves environment variables in the agent definition
func resolveEnvironmentVariables(def *AgentDefinition) error {
	// Resolve variables in instructions
	def.Instructions.General = resolveEnvVars(def.Instructions.General)
	def.Instructions.MCP = resolveEnvVars(def.Instructions.MCP)

	for i, custom := range def.Instructions.Custom {
		def.Instructions.Custom[i] = resolveEnvVars(custom)
	}

	// Resolve variables in prompts
	for key, prompt := range def.Prompts {
		def.Prompts[key] = resolveEnvVars(prompt)
	}

	// Resolve variables in tool parameters
	for i, tool := range def.Tools {
		for key, value := range tool.Parameters {
			if strValue, ok := value.(string); ok {
				def.Tools[i].Parameters[key] = resolveEnvVars(strValue)
			}
		}
	}

	return nil
}

// resolveEnvVars resolves environment variables in a string
func resolveEnvVars(str string) string {
	// Simple environment variable resolution
	// Supports ${VAR} and $VAR syntax
	result := str

	// Replace ${VAR} patterns
	for {
		start := strings.Index(result, "${")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "}")
		if end == -1 {
			break
		}
		end += start

		varName := result[start+2 : end]
		envValue := os.Getenv(varName)
		result = result[:start] + envValue + result[end+1:]
	}

	return result
}

// MCPServers returns the list of MCP servers this agent uses (matches Python abstract method)
func (ca *ConfigurableAgent) MCPServers() []string {
	servers := make([]string, 0)
	serverMap := make(map[string]bool)

	// Extract unique servers from tool definitions
	for _, tool := range ca.definition.Tools {
		if tool.Server != "" && !serverMap[tool.Server] {
			servers = append(servers, tool.Server)
			serverMap[tool.Server] = true
		}
	}

	return servers
}

// CustomInstructions returns agent-specific instructions (matches Python abstract method)
func (ca *ConfigurableAgent) CustomInstructions() string {
	return ca.buildInstructions(nil, nil) // Build with no context for static instructions
}

// CreateSampleAgentDefinition creates a comprehensive sample YAML definition for demonstration
func CreateSampleAgentDefinition() *AgentDefinition {
	return &AgentDefinition{
		Name:         "advanced-kubernetes-security-analyzer",
		Description:  "Advanced configurable agent for Kubernetes security incident analysis with multiple strategies",
		Type:         "kubernetes-security",
		Version:      "2.0.0",
		Capabilities: []string{"kubernetes_analysis", "security_assessment", "pod_inspection", "compliance_checking"},
		AlertTypes:   []string{"kubernetes", "k8s", "pod-failure", "security-alert"},
		Settings: &AgentSettings{
			MaxIterations:   8,
			TimeoutDuration: 5 * time.Minute,
			Temperature:     0.2,
			MaxTokens:       4096,
			LLMProvider:     "gpt-4",
		},
		Instructions: InstructionLayers{
			General: `You are an expert Kubernetes security analyst specializing in incident response and threat detection.
Your primary responsibilities:
1. Identify security risks, misconfigurations, and potential threats
2. Analyze compliance violations with industry standards
3. Provide actionable, specific remediation recommendations
4. Use available tools to gather comprehensive situational awareness

Environment Context:
- Cluster: ${CLUSTER_NAME}
- Security Posture: ${SECURITY_LEVEL}
- Compliance Framework: ${COMPLIANCE_FRAMEWORK}`,
			MCP: `Tool Usage Strategy:
1. Start with cluster-wide context gathering using kubectl tools
2. Focus on specific resources mentioned in the alert
3. Cross-reference security policies and network configurations
4. Summarize tool outputs concisely to preserve context window
5. Use security scanning tools for vulnerability assessment

Available tool servers: kubernetes-server, security-scanner, compliance-checker`,
			Custom: []string{
				"Always verify pod security contexts and capabilities",
				"Check for privilege escalation vectors and RBAC misconfigurations",
				"Examine network policies, service meshes, and ingress configurations",
				"Identify compliance violations with PSS (Pod Security Standards)",
				"Provide specific remediation with working YAML examples",
				"Include impact assessment and risk prioritization",
				"Suggest monitoring and alerting improvements",
			},
		},
		Tools: []ToolDefinition{
			{
				Name:        "kubectl-get",
				Server:      "kubernetes-server",
				Description: "Get Kubernetes resources with detailed output",
				Parameters: map[string]interface{}{
					"resource": "pods",
					"namespace": "${NAMESPACE}",
					"output":   "yaml",
				},
				Required:   []string{"resource"},
				Conditions: []string{"get", "show", "describe", "status"},
			},
			{
				Name:        "kubectl-logs",
				Server:      "kubernetes-server",
				Description: "Retrieve pod logs for analysis",
				Parameters: map[string]interface{}{
					"pod":       "${POD_NAME}",
					"namespace": "${NAMESPACE}",
					"lines":     "100",
				},
				Required:   []string{"pod"},
				Conditions: []string{"logs", "log", "examine logs"},
			},
			{
				Name:        "security-scan",
				Server:      "security-scanner",
				Description: "Perform security vulnerability scanning",
				Parameters: map[string]interface{}{
					"target":    "${SCAN_TARGET}",
					"severity":  "medium",
					"format":    "json",
				},
				Required:   []string{"target"},
				Conditions: []string{"scan", "vulnerability", "security check"},
			},
		},
		Prompts: map[string]string{
			"initial_assessment": `Analyze this Kubernetes security incident:
Alert Type: ${ALERT_TYPE}
Alert Data: ${ALERT_DATA}
Cluster: ${CLUSTER_NAME}

Provide initial assessment and investigation plan.`,
			"security_analysis": "Perform comprehensive security analysis for: ${ALERT_TYPE} in ${NAMESPACE}",
			"remediation_plan": "Create detailed remediation plan for identified issues in: ${RESOURCE_TYPE}",
			"compliance_check": "Verify compliance with ${COMPLIANCE_FRAMEWORK} for: ${RESOURCE_TYPE}",
		},
		Variables: map[string]interface{}{
			"CLUSTER_NAME":         "${KUBE_CLUSTER_NAME}",
			"SECURITY_LEVEL":       "high",
			"COMPLIANCE_FRAMEWORK": "CIS-Kubernetes",
			"NAMESPACE":            "default",
			"SCAN_TARGET":          "cluster",
		},
		IterationStrategy: IterationStrategy{
			Strategy:    "react",
			MaxSteps:    8,
			Convergence: "content",
		},
		Workflows: []WorkflowStep{
			{
				Name: "initial-triage",
				Type: "prompt",
				PromptKey: "initial_assessment",
				NextSteps: []string{"gather-context", "security-scan"},
			},
			{
				Name: "gather-context",
				Type: "tool",
				ToolName: "kubectl-get",
				Parameters: map[string]string{
					"resource": "pods,services,networkpolicies",
					"namespace": "${NAMESPACE}",
				},
				NextSteps: []string{"analyze-security"},
			},
			{
				Name: "security-scan",
				Type: "tool",
				ToolName: "security-scan",
				Condition: "${SECURITY_LEVEL} == 'high'",
				Parameters: map[string]string{
					"target": "${NAMESPACE}",
				},
				NextSteps: []string{"compliance-check"},
			},
			{
				Name: "analyze-security",
				Type: "analysis",
				Parameters: map[string]string{
					"focus": "security-posture",
				},
				NextSteps: []string{"generate-remediation"},
			},
			{
				Name: "compliance-check",
				Type: "prompt",
				PromptKey: "compliance_check",
				NextSteps: []string{"generate-remediation"},
			},
			{
				Name: "generate-remediation",
				Type: "prompt",
				PromptKey: "remediation_plan",
			},
		},
	}
}