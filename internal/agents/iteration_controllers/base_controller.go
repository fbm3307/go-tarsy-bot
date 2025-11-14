package iteration_controllers

import (
	"context"
	"fmt"

	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// MCPRegistryInterface defines the interface for MCP registry operations
type MCPRegistryInterface interface {
	ExecuteToolOnServer(ctx context.Context, serverName, toolName string, parameters map[string]interface{}) (*mcp.ToolResult, error)
	GetAllToolsForAgent(ctx context.Context, agentName string) (map[string][]mcp.Tool, error)
}

// IterationController defines the interface for all iteration control strategies
// This provides the abstraction for different AI reasoning patterns (ReAct, etc.)
type IterationController interface {
	// Execute runs the iteration strategy for the given context
	Execute(ctx context.Context, iterCtx *IterationContext) (*IterationResult, error)

	// GetStrategyType returns the type of iteration strategy
	GetStrategyType() string

	// GetMaxIterations returns the maximum number of iterations allowed
	GetMaxIterations() int

	// ValidateContext validates the iteration context before execution
	ValidateContext(iterCtx *IterationContext) error
}

// IterationContext contains all the context needed for iteration execution
type IterationContext struct {
	// Core context
	Alert    *models.Alert        `json:"alert"`
	ChainCtx *models.ChainContext `json:"chain_context"`

	// Agent information
	AgentType    string                 `json:"agent_type"`
	Instructions string                 `json:"instructions"`
	Capabilities []string               `json:"capabilities"`

	// LLM configuration
	LLMProvider  string                 `json:"llm_provider"`
	Temperature  float32                `json:"temperature"`
	MaxTokens    int                    `json:"max_tokens"`

	// MCP context
	AvailableTools *models.AvailableTools `json:"available_tools,omitempty"`
	MCPEnabled     bool                   `json:"mcp_enabled"`
	MCPRegistry    MCPRegistryInterface   `json:"-"` // Don't serialize, interface for tool execution
	MCPHookFunc    func(context.Context, *models.MCPInteraction) error `json:"-"` // Callback to avoid import cycles

	// Iteration settings
	MaxIterations    int                    `json:"max_iterations"`
	CurrentIteration int                    `json:"current_iteration"`

	// State management
	ConversationHistory []ConversationEntry `json:"conversation_history"`
	ToolExecutions      []ToolExecution     `json:"tool_executions"`
	Variables           map[string]interface{} `json:"variables,omitempty"`
}

// ConversationEntry represents a single entry in the conversation history
type ConversationEntry struct {
	Role      string `json:"role"`      // "system", "user", "assistant"
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
	TokenCount int   `json:"token_count,omitempty"`
}

// ToolExecution represents the execution of a tool during iteration
type ToolExecution struct {
	ToolName    string                 `json:"tool_name"`
	Server      string                 `json:"server"`
	Parameters  map[string]interface{} `json:"parameters"`
	Result      string                 `json:"result"`
	Error       string                 `json:"error,omitempty"`
	Duration    int64                  `json:"duration_ms"`
	Timestamp   int64                  `json:"timestamp"`
	Iteration   int                    `json:"iteration"`
}

// IterationResult contains the result of an iteration execution
type IterationResult struct {
	// Execution status
	Success         bool   `json:"success"`
	FinalAnalysis   string `json:"final_analysis"`
	ErrorMessage    string `json:"error_message,omitempty"`

	// Execution metrics
	TotalIterations   int   `json:"total_iterations"`
	TotalDuration     int64 `json:"total_duration_ms"`
	TotalTokensUsed   int   `json:"total_tokens_used,omitempty"`
	ToolExecutions    int   `json:"tool_executions"`

	// Detailed results
	ConversationHistory []ConversationEntry `json:"conversation_history"`
	ToolResults         []ToolExecution     `json:"tool_results"`
	IterationTrace      []IterationStep     `json:"iteration_trace"`

	// Analysis metadata
	Confidence      float64                `json:"confidence,omitempty"`
	RecommendedActions []string           `json:"recommended_actions,omitempty"`
	Findings        map[string]interface{} `json:"findings,omitempty"`
}

// IterationStep represents a single step in the iteration process
type IterationStep struct {
	Iteration   int                    `json:"iteration"`
	StepType    string                 `json:"step_type"`    // "thought", "action", "observation"
	Content     string                 `json:"content"`
	Timestamp   int64                  `json:"timestamp"`
	TokensUsed  int                    `json:"tokens_used,omitempty"`
	Duration    int64                  `json:"duration_ms"`
	ToolUsed    string                 `json:"tool_used,omitempty"`
	Variables   map[string]interface{} `json:"variables,omitempty"`
}

// NewIterationContext creates a new iteration context
func NewIterationContext(alert *models.Alert, chainCtx *models.ChainContext, agentType string) *IterationContext {
	return &IterationContext{
		Alert:               alert,
		ChainCtx:            chainCtx,
		AgentType:           agentType,
		ConversationHistory: make([]ConversationEntry, 0),
		ToolExecutions:      make([]ToolExecution, 0),
		Variables:           make(map[string]interface{}),
		CurrentIteration:    0,
	}
}

// ValidateIterationContext validates the iteration context
func (ic *IterationContext) ValidateIterationContext() error {
	if ic.Alert == nil {
		return fmt.Errorf("alert is required")
	}
	if ic.ChainCtx == nil {
		return fmt.Errorf("chain context is required")
	}
	if ic.AgentType == "" {
		return fmt.Errorf("agent type is required")
	}
	if ic.MaxIterations <= 0 {
		return fmt.Errorf("max iterations must be greater than 0")
	}
	return nil
}

// Clone creates a copy of the IterationContext
func (ic *IterationContext) Clone() *IterationContext {
	clone := &IterationContext{
		Alert:            ic.Alert,
		ChainCtx:         ic.ChainCtx, // Reference copy - chain context should be shared
		AgentType:        ic.AgentType,
		Instructions:     ic.Instructions,
		Capabilities:     make([]string, len(ic.Capabilities)),
		LLMProvider:      ic.LLMProvider,
		Temperature:      ic.Temperature,
		MaxTokens:        ic.MaxTokens,
		MCPEnabled:       ic.MCPEnabled,
		MaxIterations:    ic.MaxIterations,
		CurrentIteration: ic.CurrentIteration,
		Variables:        make(map[string]interface{}),
	}

	// Deep copy capabilities
	copy(clone.Capabilities, ic.Capabilities)

	// Deep copy variables
	for k, v := range ic.Variables {
		clone.Variables[k] = v
	}

	// Deep copy conversation history
	clone.ConversationHistory = make([]ConversationEntry, len(ic.ConversationHistory))
	copy(clone.ConversationHistory, ic.ConversationHistory)

	// Deep copy tool executions
	clone.ToolExecutions = make([]ToolExecution, len(ic.ToolExecutions))
	copy(clone.ToolExecutions, ic.ToolExecutions)

	// Copy available tools reference
	clone.AvailableTools = ic.AvailableTools

	return clone
}

// AddConversationEntry adds an entry to the conversation history
func (ic *IterationContext) AddConversationEntry(role, content string, tokenCount int) {
	entry := ConversationEntry{
		Role:       role,
		Content:    content,
		Timestamp:  getCurrentTimestampMicros(),
		TokenCount: tokenCount,
	}
	ic.ConversationHistory = append(ic.ConversationHistory, entry)
}

// AddToolExecution adds a tool execution record
func (ic *IterationContext) AddToolExecution(toolName, server string, parameters map[string]interface{}, result, errorMsg string, duration int64) {
	execution := ToolExecution{
		ToolName:   toolName,
		Server:     server,
		Parameters: parameters,
		Result:     result,
		Error:      errorMsg,
		Duration:   duration,
		Timestamp:  getCurrentTimestampMicros(),
		Iteration:  ic.CurrentIteration,
	}
	ic.ToolExecutions = append(ic.ToolExecutions, execution)
}

// IncrementIteration increments the current iteration counter
func (ic *IterationContext) IncrementIteration() {
	ic.CurrentIteration++
}

// HasReachedMaxIterations checks if max iterations have been reached
func (ic *IterationContext) HasReachedMaxIterations() bool {
	return ic.CurrentIteration >= ic.MaxIterations
}

// GetRemainingIterations returns the number of remaining iterations
func (ic *IterationContext) GetRemainingIterations() int {
	remaining := ic.MaxIterations - ic.CurrentIteration
	if remaining < 0 {
		return 0
	}
	return remaining
}

// GetVariable gets a variable value
func (ic *IterationContext) GetVariable(key string) (interface{}, bool) {
	value, exists := ic.Variables[key]
	return value, exists
}

// SetVariable sets a variable value
func (ic *IterationContext) SetVariable(key string, value interface{}) {
	if ic.Variables == nil {
		ic.Variables = make(map[string]interface{})
	}
	ic.Variables[key] = value
}

// GetSessionID returns the session ID from chain context
func (ic *IterationContext) GetSessionID() string {
	if ic.ChainCtx != nil {
		return ic.ChainCtx.SessionID
	}
	return ""
}

// GetAlertType returns the alert type
func (ic *IterationContext) GetAlertType() string {
	if ic.Alert != nil {
		return ic.Alert.AlertType
	}
	return ""
}

// GetCurrentStageName returns the current stage name from chain context
func (ic *IterationContext) GetCurrentStageName() string {
	if ic.ChainCtx != nil {
		return ic.ChainCtx.CurrentStageName
	}
	return ""
}

// GetConversationLength returns the number of conversation entries
func (ic *IterationContext) GetConversationLength() int {
	return len(ic.ConversationHistory)
}

// GetToolExecutionCount returns the number of tool executions
func (ic *IterationContext) GetToolExecutionCount() int {
	return len(ic.ToolExecutions)
}

// GetTotalTokensUsed calculates total tokens used in conversation
func (ic *IterationContext) GetTotalTokensUsed() int {
	total := 0
	for _, entry := range ic.ConversationHistory {
		total += entry.TokenCount
	}
	return total
}

// GetLastConversationEntry returns the last conversation entry
func (ic *IterationContext) GetLastConversationEntry() *ConversationEntry {
	if len(ic.ConversationHistory) == 0 {
		return nil
	}
	return &ic.ConversationHistory[len(ic.ConversationHistory)-1]
}

// GetLastToolExecution returns the last tool execution
func (ic *IterationContext) GetLastToolExecution() *ToolExecution {
	if len(ic.ToolExecutions) == 0 {
		return nil
	}
	return &ic.ToolExecutions[len(ic.ToolExecutions)-1]
}

// GetToolExecutionsForIteration returns tool executions for a specific iteration
func (ic *IterationContext) GetToolExecutionsForIteration(iteration int) []ToolExecution {
	var executions []ToolExecution
	for _, exec := range ic.ToolExecutions {
		if exec.Iteration == iteration {
			executions = append(executions, exec)
		}
	}
	return executions
}

// HasCapability checks if the agent has a specific capability
func (ic *IterationContext) HasCapability(capability string) bool {
	for _, cap := range ic.Capabilities {
		if cap == capability {
			return true
		}
	}
	return false
}

// NewIterationResult creates a new iteration result
func NewIterationResult() *IterationResult {
	return &IterationResult{
		ConversationHistory: make([]ConversationEntry, 0),
		ToolResults:         make([]ToolExecution, 0),
		IterationTrace:      make([]IterationStep, 0),
		RecommendedActions:  make([]string, 0),
		Findings:            make(map[string]interface{}),
	}
}

// SetSuccess marks the result as successful with analysis
func (ir *IterationResult) SetSuccess(finalAnalysis string) {
	ir.Success = true
	ir.FinalAnalysis = finalAnalysis
	ir.ErrorMessage = ""
}

// SetFailure marks the result as failed with error message
func (ir *IterationResult) SetFailure(errorMessage string) {
	ir.Success = false
	ir.ErrorMessage = errorMessage
	ir.FinalAnalysis = ""
}

// AddIterationStep adds a step to the iteration trace
func (ir *IterationResult) AddIterationStep(iteration int, stepType, content string, duration int64) {
	step := IterationStep{
		Iteration: iteration,
		StepType:  stepType,
		Content:   content,
		Timestamp: getCurrentTimestampMicros(),
		Duration:  duration,
	}
	ir.IterationTrace = append(ir.IterationTrace, step)
}

// AddRecommendedAction adds a recommended action
func (ir *IterationResult) AddRecommendedAction(action string) {
	ir.RecommendedActions = append(ir.RecommendedActions, action)
}

// SetFinding sets a finding value
func (ir *IterationResult) SetFinding(key string, value interface{}) {
	if ir.Findings == nil {
		ir.Findings = make(map[string]interface{})
	}
	ir.Findings[key] = value
}

// GetFinding gets a finding value
func (ir *IterationResult) GetFinding(key string) (interface{}, bool) {
	value, exists := ir.Findings[key]
	return value, exists
}

// getCurrentTimestampMicros returns current timestamp in microseconds
func getCurrentTimestampMicros() int64 {
	return getCurrentTimestampNanos() / 1000
}

// getCurrentTimestampNanos returns current timestamp in nanoseconds
func getCurrentTimestampNanos() int64 {
	// For now return 0, this should be implemented with time.Now().UnixNano()
	// when proper timestamp handling is needed
	return 0
}

// BaseController provides common functionality for all iteration controllers
type BaseController struct {
	strategyType   string
	maxIterations  int
	enableLogging  bool
}

// NewBaseController creates a new base controller
func NewBaseController(strategyType string, maxIterations int) *BaseController {
	return &BaseController{
		strategyType:   strategyType,
		maxIterations:  maxIterations,
		enableLogging:  true,
	}
}

// GetStrategyType returns the strategy type
func (bc *BaseController) GetStrategyType() string {
	return bc.strategyType
}

// GetMaxIterations returns the maximum iterations
func (bc *BaseController) GetMaxIterations() int {
	return bc.maxIterations
}

// ValidateContext validates the iteration context
func (bc *BaseController) ValidateContext(iterCtx *IterationContext) error {
	if iterCtx == nil {
		return fmt.Errorf("iteration context cannot be nil")
	}

	if iterCtx.Alert == nil {
		return fmt.Errorf("alert is required")
	}

	if iterCtx.ChainCtx == nil {
		return fmt.Errorf("chain context is required")
	}

	if iterCtx.Instructions == "" {
		return fmt.Errorf("instructions are required")
	}

	if iterCtx.MaxIterations <= 0 {
		return fmt.Errorf("max iterations must be greater than 0")
	}

	if iterCtx.MaxIterations > 50 {
		return fmt.Errorf("max iterations cannot exceed 50")
	}

	return nil
}

// InitializeContext sets up the initial iteration context
func (bc *BaseController) InitializeContext(iterCtx *IterationContext) error {
	if err := bc.ValidateContext(iterCtx); err != nil {
		return err
	}

	// Initialize conversation history if empty
	if iterCtx.ConversationHistory == nil {
		iterCtx.ConversationHistory = make([]ConversationEntry, 0)
	}

	// Initialize tool executions if empty
	if iterCtx.ToolExecutions == nil {
		iterCtx.ToolExecutions = make([]ToolExecution, 0)
	}

	// Initialize variables if empty
	if iterCtx.Variables == nil {
		iterCtx.Variables = make(map[string]interface{})
	}

	// Reset current iteration
	iterCtx.CurrentIteration = 0

	// Add system instruction to conversation history
	bc.addSystemMessage(iterCtx, iterCtx.Instructions)

	return nil
}

// addSystemMessage adds a system message to the conversation history
func (bc *BaseController) addSystemMessage(iterCtx *IterationContext, content string) {
	entry := ConversationEntry{
		Role:      "system",
		Content:   content,
		Timestamp: getCurrentTimestamp(),
	}
	iterCtx.ConversationHistory = append(iterCtx.ConversationHistory, entry)
}

// addUserMessage adds a user message to the conversation history
func (bc *BaseController) addUserMessage(iterCtx *IterationContext, content string) {
	entry := ConversationEntry{
		Role:      "user",
		Content:   content,
		Timestamp: getCurrentTimestamp(),
	}
	iterCtx.ConversationHistory = append(iterCtx.ConversationHistory, entry)
}

// addAssistantMessage adds an assistant message to the conversation history
func (bc *BaseController) addAssistantMessage(iterCtx *IterationContext, content string) {
	entry := ConversationEntry{
		Role:      "assistant",
		Content:   content,
		Timestamp: getCurrentTimestamp(),
	}
	iterCtx.ConversationHistory = append(iterCtx.ConversationHistory, entry)
}

// recordToolExecution records a tool execution
func (bc *BaseController) recordToolExecution(iterCtx *IterationContext, execution ToolExecution) {
	execution.Iteration = iterCtx.CurrentIteration
	execution.Timestamp = getCurrentTimestamp()
	iterCtx.ToolExecutions = append(iterCtx.ToolExecutions, execution)
}

// createIterationResult creates the final iteration result
func (bc *BaseController) createIterationResult(iterCtx *IterationContext, success bool, finalAnalysis, errorMessage string) *IterationResult {
	totalDuration := int64(0)
	totalTokens := 0
	iterationTrace := make([]IterationStep, 0)

	// Calculate totals from conversation history
	for _, entry := range iterCtx.ConversationHistory {
		totalTokens += entry.TokenCount
	}

	// Calculate total duration from tool executions
	for _, execution := range iterCtx.ToolExecutions {
		totalDuration += execution.Duration
	}

	result := &IterationResult{
		Success:             success,
		FinalAnalysis:       finalAnalysis,
		ErrorMessage:        errorMessage,
		TotalIterations:     iterCtx.CurrentIteration,
		TotalDuration:       totalDuration,
		TotalTokensUsed:     totalTokens,
		ToolExecutions:      len(iterCtx.ToolExecutions),
		ConversationHistory: iterCtx.ConversationHistory,
		ToolResults:         iterCtx.ToolExecutions,
		IterationTrace:      iterationTrace,
		Findings:            make(map[string]interface{}),
	}

	return result
}

// shouldContinueIteration determines if iteration should continue
func (bc *BaseController) shouldContinueIteration(iterCtx *IterationContext, lastResponse string) bool {
	// Check iteration limit
	if iterCtx.CurrentIteration >= iterCtx.MaxIterations {
		return false
	}

	// Check for completion markers in response
	completionMarkers := []string{
		"FINAL ANSWER:",
		"CONCLUSION:",
		"ANALYSIS COMPLETE",
		"Final Analysis:",
	}

	for _, marker := range completionMarkers {
		if containsIgnoreCase(lastResponse, marker) {
			return false
		}
	}

	return true
}

// Helper functions

// getCurrentTimestamp returns the current timestamp in microseconds
func getCurrentTimestamp() int64 {
	// Would use time.Now().UnixMicro() in real implementation
	return 0 // Placeholder
}

// containsIgnoreCase checks if a string contains a substring (case insensitive)
func containsIgnoreCase(text, substr string) bool {
	// Simplified implementation
	return false // Placeholder - would use strings.Contains(strings.ToLower(text), strings.ToLower(substr))
}

// EstimateTokenCount estimates the token count for a text string
func EstimateTokenCount(text string) int {
	// Simplified token estimation - roughly 4 characters per token
	return len(text) / 4
}