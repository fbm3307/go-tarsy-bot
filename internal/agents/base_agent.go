package agents

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/agents/iteration_controllers"
	"github.com/codeready/go-tarsy-bot/internal/agents/prompts"
	"github.com/codeready/go-tarsy-bot/internal/errors"
	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// Agent represents the interface that all TARSy agents must implement
// This matches the original Python BaseAgent abstract class structure
type Agent interface {
	// ProcessAlert processes an alert and returns the execution result
	ProcessAlert(ctx context.Context, alert *models.Alert, chainCtx *models.ChainContext) (*models.AgentExecutionResult, error)

	// GetAgentType returns the type identifier for this agent
	GetAgentType() string

	// GetCapabilities returns the list of capabilities this agent supports
	GetCapabilities() []string

	// ValidateConfiguration validates the agent's configuration
	ValidateConfiguration() error

	// Abstract methods that concrete agents must implement (like original Python)
	MCPServers() []string
	CustomInstructions() string
}

// DependencyHealthChecker interface to avoid import cycles with monitoring package
type DependencyHealthChecker interface {
	RegisterDependency(config *DependencyConfig) error
	GetAllDependencyHealth() map[string]*DependencyHealth
	GetOverallHealth() DependencyStatus
	StartHealthChecking(ctx context.Context) error
	StopHealthChecking()
}

// DependencyConfig represents configuration for dependency health checking
type DependencyConfig struct {
	Name              string                  `json:"name"`
	Type              DependencyType          `json:"type"`
	Endpoint          string                  `json:"endpoint,omitempty"`
	CheckInterval     time.Duration           `json:"check_interval"`
	Timeout           time.Duration           `json:"timeout"`
	RetryAttempts     int                     `json:"retry_attempts"`
	CircuitBreaker    bool                    `json:"circuit_breaker"`
	Critical          bool                    `json:"critical"`
	Required          bool                    `json:"required"`
	Tags              map[string]string       `json:"tags,omitempty"`
	ExpectedStatus    []int                   `json:"expected_status,omitempty"`
	HealthCheckFunc   func(context.Context) error `json:"-"`
}

// DependencyHealth represents health information of a dependency
type DependencyHealth struct {
	Name               string           `json:"name"`
	Type               DependencyType   `json:"type"`
	Status             DependencyStatus `json:"status"`
	Message            string           `json:"message"`
	LastChecked        time.Time        `json:"last_checked"`
	LastHealthy        time.Time        `json:"last_healthy"`
	ResponseTime       time.Duration    `json:"response_time"`
	SuccessCount       int64            `json:"success_count"`
	ErrorCount         int64            `json:"error_count"`
	ConsecutiveFails   int              `json:"consecutive_fails"`
	Uptime             float64          `json:"uptime"`
	Details            map[string]interface{} `json:"details,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
	Critical           bool             `json:"critical"`
	Required           bool             `json:"required"`
	CircuitBreakerOpen bool             `json:"circuit_breaker_open,omitempty"`
}

// DependencyType represents the type of dependency
type DependencyType string

const (
	DependencyTypeDatabase     DependencyType = "database"
	DependencyTypeLLM         DependencyType = "llm"
	DependencyTypeMCP         DependencyType = "mcp"
	DependencyTypeWebSocket   DependencyType = "websocket"
	DependencyTypeHTTP        DependencyType = "http"
	DependencyTypeAuth        DependencyType = "auth"
	DependencyTypeCache       DependencyType = "cache"
	DependencyTypeMessageQueue DependencyType = "message_queue"
	DependencyTypeFileSystem  DependencyType = "filesystem"
	DependencyTypeNetwork     DependencyType = "network"
)

// DependencyStatus represents the health status of a dependency
type DependencyStatus string

const (
	DependencyStatusHealthy     DependencyStatus = "healthy"
	DependencyStatusDegraded    DependencyStatus = "degraded"
	DependencyStatusUnhealthy   DependencyStatus = "unhealthy"
	DependencyStatusUnknown     DependencyStatus = "unknown"
	DependencyStatusMaintenance DependencyStatus = "maintenance"
)

// BaseAgent provides common functionality for all agent implementations
// This abstract base handles shared processing logic while delegating
// agent-specific behavior to concrete implementations
// Enhanced to match Python TARSy architecture with iteration controllers
// Now includes comprehensive error handling and resilience patterns
type BaseAgent struct {
	agentType           string
	capabilities        []string
	settings           *AgentSettings
	iterationController iteration_controllers.IterationController
	llmIntegration     LLMIntegrationInterface
	mcpServerRegistry  *mcp.MCPServerRegistry
	logger             *zap.Logger
	instructionBuilder *InstructionBuilder
	promptBuilder      *prompts.PromptBuilder

	// Error handling and resilience components (Phase 3 integration)
	errorClassifier     *errors.ErrorClassifier
	resilienceWrapper   *errors.ResilienceWrapper
	timeoutManager      *errors.TimeoutManager
	degradationManager  *errors.ServiceDegradationManager
	dependencyChecker   DependencyHealthChecker

	// Agent health and metrics
	healthStatus        AgentHealthStatus
	processingMetrics   *AgentMetrics
}

// AgentSettings contains configuration for agent behavior
type AgentSettings struct {
	MaxIterations      int           `json:"max_iterations"`
	TimeoutDuration    time.Duration `json:"timeout_duration"`
	RetryAttempts      int           `json:"retry_attempts"`
	EnableDebugMode    bool          `json:"enable_debug_mode"`
	LLMProvider        string        `json:"llm_provider"`
	MCPEnabled         bool          `json:"mcp_enabled"`
	Temperature        float32       `json:"temperature"`
	MaxTokens          int           `json:"max_tokens"`
	IterationStrategy  string        `json:"iteration_strategy"`  // "react", "simple", "stage"
	PromptTemplate     string        `json:"prompt_template"`     // Custom prompt template
	EnableToolUse      bool          `json:"enable_tool_use"`     // Enable MCP tool execution
}

// InstructionBuilder provides three-tier instruction composition matching Python architecture
type InstructionBuilder struct {
	generalInstructions string
	mcpInstructions     string
	customInstructions  []string
	variableResolver    *VariableResolver
}

// VariableResolver handles template variable substitution
type VariableResolver struct {
	variables map[string]string
}

// AgentHealthStatus represents the current health status of an agent
type AgentHealthStatus string

const (
	AgentHealthStatusHealthy     AgentHealthStatus = "healthy"
	AgentHealthStatusDegraded    AgentHealthStatus = "degraded"
	AgentHealthStatusUnhealthy   AgentHealthStatus = "unhealthy"
	AgentHealthStatusMaintenance AgentHealthStatus = "maintenance"
)

// AgentMetrics tracks agent processing metrics and performance
type AgentMetrics struct {
	TotalProcessed         int64         `json:"total_processed"`
	SuccessfulProcessed    int64         `json:"successful_processed"`
	FailedProcessed        int64         `json:"failed_processed"`
	AverageProcessingTime  time.Duration `json:"average_processing_time"`
	LastProcessedTime      time.Time     `json:"last_processed_time"`
	ErrorsByCategory       map[string]int64 `json:"errors_by_category"`
	TimeoutCount          int64         `json:"timeout_count"`
	CircuitBreakerTrips   int64         `json:"circuit_breaker_trips"`
	FallbackExecutions    int64         `json:"fallback_executions"`
	DegradationEvents     int64         `json:"degradation_events"`
}


// NewBaseAgent creates a new base agent with the specified configuration
// Enhanced constructor matching Python architecture
func NewBaseAgent(agentType string, capabilities []string, settings *AgentSettings) *BaseAgent {
	if settings == nil {
		settings = DefaultAgentSettings()
	}

	return &BaseAgent{
		agentType:          agentType,
		capabilities:       capabilities,
		settings:          settings,
		instructionBuilder: NewInstructionBuilder(),
		promptBuilder:      prompts.NewPromptBuilder(),
	}
}

// NewBaseAgentWithDependencies creates a base agent with full dependency injection
// Enhanced with comprehensive error handling and resilience components
func NewBaseAgentWithDependencies(
	agentType string,
	capabilities []string,
	settings *AgentSettings,
	llmIntegration LLMIntegrationInterface,
	mcpServerRegistry *mcp.MCPServerRegistry,
	logger *zap.Logger,
	errorClassifier *errors.ErrorClassifier,
	resilienceWrapper *errors.ResilienceWrapper,
	timeoutManager *errors.TimeoutManager,
	degradationManager *errors.ServiceDegradationManager,
	dependencyChecker DependencyHealthChecker,
) *BaseAgent {
	if settings == nil {
		settings = DefaultAgentSettings()
	}

	baseAgent := &BaseAgent{
		agentType:          agentType,
		capabilities:       capabilities,
		settings:          settings,
		llmIntegration:    llmIntegration,
		mcpServerRegistry: mcpServerRegistry,
		logger:            logger,
		instructionBuilder: NewInstructionBuilder(),
		promptBuilder:      prompts.NewPromptBuilder(),

		// Error handling and resilience components
		errorClassifier:    errorClassifier,
		resilienceWrapper:  resilienceWrapper,
		timeoutManager:     timeoutManager,
		degradationManager: degradationManager,
		dependencyChecker:  dependencyChecker,

		// Initialize health status and metrics
		healthStatus:       AgentHealthStatusHealthy,
		processingMetrics:  &AgentMetrics{
			ErrorsByCategory: make(map[string]int64),
		},
	}

	// Create appropriate iteration controller based on strategy
	baseAgent.iterationController = baseAgent.createIterationController()

	return baseAgent
}

// DefaultAgentSettings returns the default configuration for agents
func DefaultAgentSettings() *AgentSettings {
	return &AgentSettings{
		MaxIterations:     10,
		TimeoutDuration:   5 * time.Minute,
		RetryAttempts:     3,
		EnableDebugMode:   false,
		LLMProvider:       "openai",
		MCPEnabled:        true,
		Temperature:       0.7,
		MaxTokens:         4096,
		IterationStrategy: "react",
		PromptTemplate:    "",
		EnableToolUse:     true,
	}
}

// ProcessAlert implements the Agent interface using the iteration controller pattern
// Enhanced with comprehensive error handling, resilience patterns, and health monitoring
func (ba *BaseAgent) ProcessAlert(ctx context.Context, alert *models.Alert, chainCtx *models.ChainContext) (*models.AgentExecutionResult, error) {
	startTime := time.Now()

	if ba.logger != nil {
		ba.logger.Info("Starting base agent processing",
			zap.String("agent_type", ba.agentType),
			zap.String("alert_type", alert.AlertType),
			zap.String("session_id", chainCtx.SessionID))
	}

	// Check agent health before processing
	if ba.healthStatus == AgentHealthStatusUnhealthy || ba.healthStatus == AgentHealthStatusMaintenance {
		return ba.createErrorResult(
			errors.NewStructuredError(
				"AGENT_UNAVAILABLE",
				fmt.Sprintf("Agent %s is in %s state", ba.agentType, ba.healthStatus),
				errors.ErrorCategoryConfiguration,
				errors.ErrorSeverityHigh,
			),
			startTime,
		)
	}

	// Check degradation status - disable features if needed
	if ba.degradationManager != nil && ba.degradationManager.GetCurrentLevel() != errors.DegradationLevelNone {
		ba.logger.Warn("Processing under degraded conditions",
			zap.String("degradation_level", string(ba.degradationManager.GetCurrentLevel())))
	}

	// Use timeout manager to create execution context
	var cancel context.CancelFunc
	if ba.timeoutManager != nil {
		ctx, cancel = ba.timeoutManager.CreateContext(ctx, "agent_processing")
	} else {
		ctx, cancel = context.WithTimeout(ctx, ba.settings.TimeoutDuration)
	}
	defer cancel()

	// Execute with resilience wrapper if available
	var result *models.AgentExecutionResult
	var err error

	if ba.resilienceWrapper != nil {
		err = ba.resilienceWrapper.ExecuteForService(ctx, ba.agentType, func(resCtx context.Context) error {
			result, err = ba.performProcessing(resCtx, alert, chainCtx)
			return err
		})
	} else {
		result, err = ba.performProcessing(ctx, alert, chainCtx)
	}

	// Update metrics and health status
	ba.updateProcessingMetrics(err == nil, time.Since(startTime), err)

	// Handle errors with structured error system
	if err != nil {
		if ba.errorClassifier != nil {
			structuredErr := ba.errorClassifier.ClassifyError(err)
			ba.logger.Error("Agent processing failed",
				zap.String("error_code", structuredErr.Code),
				zap.String("error_category", string(structuredErr.Category)),
				zap.String("error_severity", string(structuredErr.Severity)),
				zap.Error(structuredErr))

			return ba.createErrorResult(structuredErr, startTime)
		}
		return ba.createErrorResult(err, startTime)
	}

	if ba.logger != nil {
		ba.logger.Info("Base agent processing completed",
			zap.String("agent_type", ba.agentType),
			zap.String("session_id", chainCtx.SessionID),
			zap.Bool("success", result != nil),
			zap.Duration("duration", time.Since(startTime)))
	}

	return result, nil
}

// performProcessing handles the actual processing logic
func (ba *BaseAgent) performProcessing(ctx context.Context, alert *models.Alert, chainCtx *models.ChainContext) (*models.AgentExecutionResult, error) {
	// If no iteration controller is set, use simple processing
	if ba.iterationController == nil {
		return ba.simpleProcessing(ctx, alert, chainCtx)
	}

	// Build instructions using three-tier composition
	instructions := ba.buildInstructions(alert, chainCtx)

	// Create iteration context matching Python architecture
	iterCtx := &iteration_controllers.IterationContext{
		Alert:            alert,
		ChainCtx:         chainCtx,
		AgentType:        ba.agentType,
		Instructions:     instructions,
		Capabilities:     ba.capabilities,
		LLMProvider:      ba.settings.LLMProvider,
		Temperature:      ba.settings.Temperature,
		MaxTokens:        ba.settings.MaxTokens,
		MCPEnabled:       ba.settings.MCPEnabled,
		MaxIterations:    ba.settings.MaxIterations,
		CurrentIteration: 0,
		Variables:        make(map[string]interface{}),
	}

	// Add available tools and MCP registry if MCP is enabled
	if ba.settings.MCPEnabled && ba.mcpServerRegistry != nil {
		iterCtx.AvailableTools = ba.getAvailableTools()
		iterCtx.MCPRegistry = ba.mcpServerRegistry
		
		// Set MCP hook callback to record tool executions (avoiding import cycle)
		iterCtx.MCPHookFunc = ba.createMCPHookCallback()
	}


	// Add session ID and stage execution ID to context for LLM adapter
	ctxWithSession := context.WithValue(ctx, "session_id", chainCtx.SessionID)

	// Extract stage execution ID from context if available
	var ctxWithStageExecution context.Context = ctxWithSession
	if stageExecutionID := ctx.Value("stage_execution_id"); stageExecutionID != nil {
		ctxWithStageExecution = context.WithValue(ctxWithSession, "stage_execution_id", stageExecutionID)

		// Debug: Log what we're passing to iteration controller
		if ba.logger != nil {
			ba.logger.Debug("Base Agent: Passing stage execution ID to iteration controller",
				zap.String("session_id", chainCtx.SessionID),
				zap.String("stage_execution_id", fmt.Sprintf("%v", stageExecutionID)))
		}
	} else {
		// Debug: Log when stage execution ID is missing
		if ba.logger != nil {
			ba.logger.Debug("Base Agent: No stage execution ID found in context",
				zap.String("session_id", chainCtx.SessionID))
		}
	}

	// Execute using iteration controller
	result, err := ba.iterationController.Execute(ctxWithStageExecution, iterCtx)
	if err != nil {
		return nil, fmt.Errorf("iteration controller execution failed: %w", err)
	}

	// Convert iteration result to agent execution result
	agentResult := &models.AgentExecutionResult{
		Status:        models.StageStatusCompleted,
		AgentName:     ba.agentType,
		TimestampUs:   time.Now().UnixMicro(),
		ResultSummary: stringPtr(fmt.Sprintf("Analysis completed using %s strategy in %d iterations",
			ba.settings.IterationStrategy, result.TotalIterations)),
		FinalAnalysis: &result.FinalAnalysis,
	}

	if !result.Success {
		agentResult.Status = models.StageStatusFailed
		if result.ErrorMessage != "" {
			agentResult.ResultSummary = stringPtr(result.ErrorMessage)
		}
	}

	if ba.logger != nil {
		ba.logger.Info("Base agent processing completed",
			zap.String("agent_type", ba.agentType),
			zap.String("session_id", chainCtx.SessionID),
			zap.Bool("success", result.Success),
			zap.Int("iterations", result.TotalIterations))
	}

	return agentResult, nil
}

// simpleProcessing provides fallback processing when no iteration controller is available
func (ba *BaseAgent) simpleProcessing(ctx context.Context, alert *models.Alert, chainCtx *models.ChainContext) (*models.AgentExecutionResult, error) {
	// Basic fallback analysis
	analysis := fmt.Sprintf(`Simple analysis from %s agent:

Alert Type: %s
Alert Data: %v
Capabilities: %v

Basic assessment completed without advanced iteration patterns.`,
		ba.agentType, alert.AlertType, alert.Data, ba.capabilities)

	result := &models.AgentExecutionResult{
		Status:        models.StageStatusCompleted,
		AgentName:     ba.agentType,
		TimestampUs:   time.Now().UnixMicro(),
		ResultSummary: stringPtr(fmt.Sprintf("Simple processing by %s agent", ba.agentType)),
		FinalAnalysis: &analysis,
	}

	return result, nil
}

// stringPtr is a helper function to convert string to *string
func stringPtr(s string) *string {
	return &s
}

// GetAgentType returns the agent type identifier
func (ba *BaseAgent) GetAgentType() string {
	return ba.agentType
}

// GetCapabilities returns the list of agent capabilities
func (ba *BaseAgent) GetCapabilities() []string {
	return ba.capabilities
}


// ValidateConfiguration validates the base agent configuration
func (ba *BaseAgent) ValidateConfiguration() error {
	if ba.agentType == "" {
		return &AgentError{Type: "configuration", Message: "agent type cannot be empty"}
	}

	if ba.settings.MaxIterations <= 0 {
		return &AgentError{Type: "configuration", Message: "max iterations must be greater than 0"}
	}

	if ba.settings.TimeoutDuration <= 0 {
		return &AgentError{Type: "configuration", Message: "timeout duration must be greater than 0"}
	}

	if ba.settings.Temperature < 0 || ba.settings.Temperature > 2 {
		return &AgentError{Type: "configuration", Message: "temperature must be between 0 and 2"}
	}

	return nil
}

// GetSettings returns the agent settings
func (ba *BaseAgent) GetSettings() *AgentSettings {
	return ba.settings
}

// AgentError represents an error that occurred during agent processing
type AgentError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Stage   string `json:"stage,omitempty"`
}

// Error implements the error interface
func (e *AgentError) Error() string {
	if e.Stage != "" {
		return fmt.Sprintf("%s error in stage %s: %s", e.Type, e.Stage, e.Message)
	}
	return fmt.Sprintf("%s error: %s", e.Type, e.Message)
}

// NewAgentError creates a new agent error
func NewAgentError(errorType, message string) *AgentError {
	return &AgentError{
		Type:    errorType,
		Message: message,
	}
}

// NewStageError creates a new agent error with stage information
func NewStageError(errorType, message, stage string) *AgentError {
	return &AgentError{
		Type:    errorType,
		Message: message,
		Stage:   stage,
	}
}

// MCPServers implements the abstract method (base agents don't use MCP servers by default)
func (ba *BaseAgent) MCPServers() []string {
	return []string{} // Base agents have no MCP servers
}

// CustomInstructions implements the abstract method
func (ba *BaseAgent) CustomInstructions() string {
	return fmt.Sprintf("General purpose agent for %s with capabilities: %v", ba.agentType, ba.capabilities)
}

// createIterationController creates the appropriate iteration controller based on strategy
func (ba *BaseAgent) createIterationController() iteration_controllers.IterationController {
	strategy := ba.settings.IterationStrategy
	if strategy == "" {
		strategy = "react"
	}

	switch strategy {
	case "react":
		var llmService iteration_controllers.LLMServiceInterface
		if ba.llmIntegration != nil {
			// Create adapter to bridge LLM integration with iteration controller
			llmService = iteration_controllers.NewLLMServiceAdapter(
				ba.llmIntegration,
				ba.agentType,
			)
		}

		return iteration_controllers.NewReActController(
			ba.settings.MaxIterations,
			ba.settings.EnableToolUse,
			llmService,
			ba.logger,
		)
	case "simple":
		// Would create SimpleController
		return nil // Placeholder for now
	case "stage":
		// Would create StageController
		return nil // Placeholder for now
	default:
		// Default to ReAct controller
		return iteration_controllers.NewReActController(
			ba.settings.MaxIterations,
			ba.settings.EnableToolUse,
			nil,
			ba.logger,
		)
	}
}

// buildInstructions creates comprehensive instructions using three-tier composition
func (ba *BaseAgent) buildInstructions(alert *models.Alert, chainCtx *models.ChainContext) string {
	if ba.instructionBuilder == nil {
		return ba.CustomInstructions()
	}

	// Build using three-tier system matching Python architecture
	instructions := ba.instructionBuilder.BuildInstructions(
		ba.CustomInstructions(),
		ba.getMCPInstructions(),
		alert,
		chainCtx,
	)

	return instructions
}

// getMCPInstructions returns MCP-specific instructions for this agent
func (ba *BaseAgent) getMCPInstructions() string {
	if !ba.settings.MCPEnabled {
		return ""
	}

	mcpServers := ba.MCPServers()
	if len(mcpServers) == 0 {
		return ""
	}

	instructions := "Tool Usage Instructions:\n"
	instructions += fmt.Sprintf("You have access to the following MCP servers: %v\n", mcpServers)
	instructions += "Use tools strategically to gather information needed for comprehensive analysis.\n"
	instructions += "Always explain your reasoning before using a tool.\n"

	return instructions
}

// getAvailableTools returns the available tools for this agent
func (ba *BaseAgent) getAvailableTools() *models.AvailableTools {
	if ba.mcpServerRegistry == nil {
		return nil
	}

	// Query MCP registry for available tools for this agent
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	toolsMap, err := ba.mcpServerRegistry.GetAllToolsForAgent(ctx, ba.agentType)
	if err != nil {
		if ba.logger != nil {
			ba.logger.Warn("Failed to get available tools from MCP registry",
				zap.String("agent_type", ba.agentType),
				zap.Error(err))
		}
		return nil
	}
	
	// Convert to AvailableTools model
	availableTools := &models.AvailableTools{
		Tools: make([]models.ToolWithServer, 0),
	}
	
	for serverName, tools := range toolsMap {
		for _, tool := range tools {
			toolWithServer := models.ToolWithServer{
				Server: serverName,
				Tool:   tool, // Store the full MCP Tool object
			}
			availableTools.Tools = append(availableTools.Tools, toolWithServer)
		}
	}
	
	if ba.logger != nil {
		ba.logger.Info("Retrieved available tools for agent",
			zap.String("agent_type", ba.agentType),
			zap.Int("tool_count", len(availableTools.Tools)))
	}
	
	return availableTools
}

// createMCPHookCallback creates a callback function for recording MCP interactions
// This avoids import cycles by returning a no-op function for now
// MCP interactions will be logged via the MCP registry's internal mechanisms
func (ba *BaseAgent) createMCPHookCallback() func(context.Context, *models.MCPInteraction) error {
	return func(ctx context.Context, interaction *models.MCPInteraction) error {
		// No-op for now - MCP interactions are logged by the registry
		// This callback is here for future enhancement
		return nil
	}
}

// NewInstructionBuilder creates a new instruction builder
func NewInstructionBuilder() *InstructionBuilder {
	return &InstructionBuilder{
		variableResolver: &VariableResolver{
			variables: make(map[string]string),
		},
	}
}

// BuildInstructions builds instructions using three-tier composition
func (ib *InstructionBuilder) BuildInstructions(
	customInstructions string,
	mcpInstructions string,
	alert *models.Alert,
	chainCtx *models.ChainContext,
) string {
	var instructions string

	// Tier 1: General instructions
	if ib.generalInstructions != "" {
		instructions += "# General Instructions\n"
		instructions += ib.resolveVariables(ib.generalInstructions, alert, chainCtx)
		instructions += "\n\n"
	}

	// Tier 2: MCP instructions
	if mcpInstructions != "" {
		instructions += "# Tool Usage Instructions\n"
		instructions += ib.resolveVariables(mcpInstructions, alert, chainCtx)
		instructions += "\n\n"
	}

	// Tier 3: Custom instructions
	if customInstructions != "" {
		instructions += "# Agent-Specific Instructions\n"
		instructions += ib.resolveVariables(customInstructions, alert, chainCtx)
		instructions += "\n\n"
	}

	// Add custom instruction layers
	if len(ib.customInstructions) > 0 {
		instructions += "# Additional Instructions\n"
		for i, custom := range ib.customInstructions {
			instructions += fmt.Sprintf("%d. %s\n", i+1, ib.resolveVariables(custom, alert, chainCtx))
		}
		instructions += "\n"
	}

	return instructions
}

// resolveVariables resolves template variables in instructions
func (ib *InstructionBuilder) resolveVariables(template string, alert *models.Alert, chainCtx *models.ChainContext) string {
	resolved := template

	// Replace common variables
	if alert != nil {
		resolved = replaceVariable(resolved, "ALERT_TYPE", alert.AlertType)
	}

	if chainCtx != nil {
		resolved = replaceVariable(resolved, "SESSION_ID", chainCtx.SessionID)
		resolved = replaceVariable(resolved, "CURRENT_STAGE", chainCtx.CurrentStageName)
	}

	// Replace custom variables from resolver
	for key, value := range ib.variableResolver.variables {
		resolved = replaceVariable(resolved, key, value)
	}

	return resolved
}

// replaceVariable replaces a variable placeholder with a value
func replaceVariable(template, key, value string) string {
	placeholder := fmt.Sprintf("${%s}", key)
	return strings.ReplaceAll(template, placeholder, value)
}

// SetGeneralInstructions sets the general instructions
func (ib *InstructionBuilder) SetGeneralInstructions(instructions string) {
	ib.generalInstructions = instructions
}

// SetMCPInstructions sets the MCP instructions
func (ib *InstructionBuilder) SetMCPInstructions(instructions string) {
	ib.mcpInstructions = instructions
}

// AddCustomInstruction adds a custom instruction
func (ib *InstructionBuilder) AddCustomInstruction(instruction string) {
	ib.customInstructions = append(ib.customInstructions, instruction)
}

// SetVariable sets a template variable
func (ib *InstructionBuilder) SetVariable(key, value string) {
	ib.variableResolver.variables[key] = value
}

// SetLLMIntegration sets the LLM integration service
func (ba *BaseAgent) SetLLMIntegration(llmIntegration LLMIntegrationInterface) {
	ba.llmIntegration = llmIntegration
	// Re-create iteration controller with LLM service if it was previously nil
	if ba.iterationController != nil {
		ba.iterationController = ba.createIterationController()
	}
}

// SetMCPServerRegistry sets the MCP server registry
func (ba *BaseAgent) SetMCPServerRegistry(registry *mcp.MCPServerRegistry) {
	ba.mcpServerRegistry = registry
}

// SetLogger sets the logger
func (ba *BaseAgent) SetLogger(logger *zap.Logger) {
	ba.logger = logger
}

// SetIterationController sets a custom iteration controller
func (ba *BaseAgent) SetIterationController(controller iteration_controllers.IterationController) {
	ba.iterationController = controller
}

// BuildPrompt builds a prompt using the template system
func (ba *BaseAgent) BuildPrompt(templateName string, alert *models.Alert, chainCtx *models.ChainContext) (*prompts.PromptResult, error) {
	if ba.promptBuilder == nil {
		return nil, fmt.Errorf("prompt builder not initialized")
	}

	// Create prompt context
	context := &prompts.PromptContext{
		Alert:             alert,
		ChainContext:      chainCtx,
		AgentType:         ba.agentType,
		AgentCapabilities: ba.capabilities,
		AvailableTools:    ba.getAvailableToolNames(),
		MCPServers:        ba.MCPServers(),
		Instructions:      ba.CustomInstructions(),
		CustomVariables:   make(map[string]interface{}),
	}

	return ba.promptBuilder.BuildPrompt(templateName, context)
}

// BuildMultiLayerPrompt builds a complex prompt from multiple templates
func (ba *BaseAgent) BuildMultiLayerPrompt(templateNames []string, alert *models.Alert, chainCtx *models.ChainContext) (*prompts.PromptResult, error) {
	if ba.promptBuilder == nil {
		return nil, fmt.Errorf("prompt builder not initialized")
	}

	// Create prompt context
	context := &prompts.PromptContext{
		Alert:             alert,
		ChainContext:      chainCtx,
		AgentType:         ba.agentType,
		AgentCapabilities: ba.capabilities,
		AvailableTools:    ba.getAvailableToolNames(),
		MCPServers:        ba.MCPServers(),
		Instructions:      ba.CustomInstructions(),
		CustomVariables:   make(map[string]interface{}),
	}

	return ba.promptBuilder.BuildMultiLayerPrompt(templateNames, context)
}

// RegisterPromptTemplate registers a custom prompt template
func (ba *BaseAgent) RegisterPromptTemplate(template *prompts.PromptTemplate) {
	if ba.promptBuilder != nil {
		ba.promptBuilder.RegisterTemplate(template)
	}
}

// SetPromptVariable sets a variable for prompt templates
func (ba *BaseAgent) SetPromptVariable(key string, value interface{}) {
	if ba.promptBuilder != nil {
		ba.promptBuilder.SetVariable(key, value)
	}
}

// getAvailableToolNames returns tool names for prompt context
func (ba *BaseAgent) getAvailableToolNames() []string {
	if ba.mcpServerRegistry == nil {
		return []string{}
	}

	// This would query the MCP registry for tool names
	// Simplified for now
	return []string{} // TODO: Implement proper tool name discovery
}

// GetPromptBuilder returns the prompt builder for advanced usage
func (ba *BaseAgent) GetPromptBuilder() *prompts.PromptBuilder {
	return ba.promptBuilder
}

// createErrorResult creates an agent execution result for error cases
func (ba *BaseAgent) createErrorResult(err error, startTime time.Time) (*models.AgentExecutionResult, error) {
	var errorMessage string

	if structuredErr, ok := err.(*errors.StructuredError); ok {
		errorMessage = structuredErr.Message
	} else {
		errorMessage = err.Error()
	}

	result := &models.AgentExecutionResult{
		Status:        models.StageStatusFailed,
		AgentName:     ba.agentType,
		TimestampUs:   time.Now().UnixMicro(),
		ResultSummary: &errorMessage,
		FinalAnalysis: &errorMessage,
	}

	return result, err
}

// updateProcessingMetrics updates agent processing metrics and health status
func (ba *BaseAgent) updateProcessingMetrics(success bool, duration time.Duration, err error) {
	if ba.processingMetrics == nil {
		return
	}

	ba.processingMetrics.TotalProcessed++
	ba.processingMetrics.LastProcessedTime = time.Now()

	if success {
		ba.processingMetrics.SuccessfulProcessed++
		ba.healthStatus = AgentHealthStatusHealthy
	} else {
		ba.processingMetrics.FailedProcessed++

		// Classify error type for metrics
		if err != nil {
			if structuredErr, ok := err.(*errors.StructuredError); ok {
				ba.processingMetrics.ErrorsByCategory[string(structuredErr.Category)]++

				// Update specific counters based on error type
				switch structuredErr.Category {
				case errors.ErrorCategoryTimeout:
					ba.processingMetrics.TimeoutCount++
				}
			}
		}

		// Update health status based on error rate
		errorRate := float64(ba.processingMetrics.FailedProcessed) / float64(ba.processingMetrics.TotalProcessed)
		if errorRate > 0.5 { // More than 50% errors
			ba.healthStatus = AgentHealthStatusUnhealthy
		} else if errorRate > 0.2 { // More than 20% errors
			ba.healthStatus = AgentHealthStatusDegraded
		}
	}

	// Update average processing time
	if ba.processingMetrics.TotalProcessed == 1 {
		ba.processingMetrics.AverageProcessingTime = duration
	} else {
		totalTime := int64(ba.processingMetrics.AverageProcessingTime) * (ba.processingMetrics.TotalProcessed - 1)
		ba.processingMetrics.AverageProcessingTime = time.Duration((totalTime + int64(duration)) / ba.processingMetrics.TotalProcessed)
	}
}

// GetHealthStatus returns the current health status of the agent
func (ba *BaseAgent) GetHealthStatus() AgentHealthStatus {
	return ba.healthStatus
}

// SetHealthStatus sets the health status of the agent
func (ba *BaseAgent) SetHealthStatus(status AgentHealthStatus) {
	ba.healthStatus = status
	if ba.logger != nil {
		ba.logger.Info("Agent health status changed",
			zap.String("agent_type", ba.agentType),
			zap.String("new_status", string(status)))
	}
}

// GetProcessingMetrics returns the current processing metrics
func (ba *BaseAgent) GetProcessingMetrics() *AgentMetrics {
	return ba.processingMetrics
}

// PerformHealthCheck performs a comprehensive health check of the agent
func (ba *BaseAgent) PerformHealthCheck() map[string]interface{} {
	healthInfo := map[string]interface{}{
		"agent_type":          ba.agentType,
		"health_status":       string(ba.healthStatus),
		"capabilities":        ba.capabilities,
		"settings":           ba.settings,
		"processing_metrics":  ba.processingMetrics,
		"dependencies":       make(map[string]interface{}),
		"issues":             make([]string, 0),
	}

	issues := make([]string, 0)

	// Check dependency health
	if ba.dependencyChecker != nil {
		dependencyHealth := ba.dependencyChecker.GetAllDependencyHealth()
		healthInfo["dependencies"] = dependencyHealth

		for name, health := range dependencyHealth {
			if health.Status != DependencyStatusHealthy {
				issues = append(issues, fmt.Sprintf("Dependency %s is %s", name, health.Status))
			}
		}
	}

	// Check MCP server availability
	if ba.mcpServerRegistry != nil {
		mcpServers := ba.MCPServers()
		mcpStatus := make(map[string]string)
		for _, serverID := range mcpServers {
			// TODO: Add actual MCP server health check
			mcpStatus[serverID] = "unknown"
		}
		healthInfo["mcp_servers"] = mcpStatus
	}

	// Check resilience components
	if ba.resilienceWrapper != nil {
		resilienceHealth := ba.resilienceWrapper.HealthCheckAll()
		healthInfo["resilience"] = resilienceHealth

		if overallStatus, ok := resilienceHealth["overall_status"].(string); ok {
			if overallStatus != "healthy" {
				issues = append(issues, fmt.Sprintf("Resilience components are %s", overallStatus))
			}
		}
	}

	// Check degradation status
	if ba.degradationManager != nil {
		degradationStatus := ba.degradationManager.GetStatus()
		healthInfo["degradation"] = degradationStatus

		if level := ba.degradationManager.GetCurrentLevel(); level != errors.DegradationLevelNone {
			issues = append(issues, fmt.Sprintf("Service is degraded to level %s", level))
		}
	}

	healthInfo["issues"] = issues

	// Determine overall health
	overallHealth := "healthy"
	if len(issues) > 0 {
		if ba.healthStatus == AgentHealthStatusUnhealthy {
			overallHealth = "unhealthy"
		} else {
			overallHealth = "degraded"
		}
	}
	healthInfo["overall_health"] = overallHealth

	return healthInfo
}

// RegisterDependency registers a dependency for health monitoring
func (ba *BaseAgent) RegisterDependency(config *DependencyConfig) error {
	if ba.dependencyChecker == nil {
		return errors.NewStructuredError(
			"DEPENDENCY_CHECKER_UNAVAILABLE",
			"Dependency checker not initialized",
			errors.ErrorCategoryConfiguration,
			errors.ErrorSeverityMedium,
		)
	}

	return ba.dependencyChecker.RegisterDependency(config)
}

// GetErrorClassifier returns the error classifier
func (ba *BaseAgent) GetErrorClassifier() *errors.ErrorClassifier {
	return ba.errorClassifier
}

// GetResilienceWrapper returns the resilience wrapper
func (ba *BaseAgent) GetResilienceWrapper() *errors.ResilienceWrapper {
	return ba.resilienceWrapper
}

// GetTimeoutManager returns the timeout manager
func (ba *BaseAgent) GetTimeoutManager() *errors.TimeoutManager {
	return ba.timeoutManager
}

// GetDegradationManager returns the degradation manager
func (ba *BaseAgent) GetDegradationManager() *errors.ServiceDegradationManager {
	return ba.degradationManager
}

// GetDependencyChecker returns the dependency health checker
func (ba *BaseAgent) GetDependencyChecker() DependencyHealthChecker {
	return ba.dependencyChecker
}