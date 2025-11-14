package models

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ToolWithServer represents an official MCP Tool with server context for action naming
type ToolWithServer struct {
	Server string      `json:"server" validate:"required"`
	Tool   interface{} `json:"tool" validate:"required"` // MCP Tool object with full schema information
}

// AvailableTools represents available tools for agent processing using official MCP Tool objects
type AvailableTools struct {
	Tools []ToolWithServer `json:"tools"`
}

// ChainContext represents context for entire chain processing session
type ChainContext struct {
	// Core data - session_id is now required field
	AlertType string                 `json:"alert_type" validate:"required"`
	AlertData map[string]interface{} `json:"alert_data" validate:"required"`
	SessionID string                 `json:"session_id" validate:"required"`
	
	// Chain execution state
	CurrentStageName string                             `json:"current_stage_name" validate:"required"`
	StageOutputs     map[string]*AgentExecutionResult   `json:"stage_outputs,omitempty"`
	
	// Processing support
	RunbookContent *string `json:"runbook_content,omitempty"`
	ChainID        *string `json:"chain_id,omitempty"`
}

// NewChainContext creates a new ChainContext with required fields
func NewChainContext(alertType string, alertData map[string]interface{}, sessionID string, currentStageName string) *ChainContext {
	return &ChainContext{
		AlertType:        alertType,
		AlertData:        alertData,
		SessionID:        sessionID,
		CurrentStageName: currentStageName,
		StageOutputs:     make(map[string]*AgentExecutionResult),
	}
}

// GetOriginalAlertData returns clean original alert data without processing artifacts
func (c *ChainContext) GetOriginalAlertData() map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range c.AlertData {
		result[k] = v
	}
	return result
}

// GetRunbookContent returns downloaded runbook content
func (c *ChainContext) GetRunbookContent() string {
	if c.RunbookContent != nil {
		return *c.RunbookContent
	}
	return ""
}

// GetPreviousStagesResults returns completed stage results in execution order
func (c *ChainContext) GetPreviousStagesResults() []StageResult {
	var results []StageResult
	for stageName, result := range c.StageOutputs {
		if result != nil && result.Status == StageStatusCompleted {
			results = append(results, StageResult{
				StageName: stageName,
				Result:    result,
			})
		}
	}
	return results
}

// AddStageResult adds result from a completed stage
func (c *ChainContext) AddStageResult(stageName string, result *AgentExecutionResult) {
	if c.StageOutputs == nil {
		c.StageOutputs = make(map[string]*AgentExecutionResult)
	}
	c.StageOutputs[stageName] = result
}

// GetRunbookURL extracts runbook URL from alert data
func (c *ChainContext) GetRunbookURL() string {
	if runbook, ok := c.AlertData["runbook"].(string); ok {
		return runbook
	}
	return ""
}

// SetChainContext sets chain context information
func (c *ChainContext) SetChainContext(chainID string, stageName *string) {
	c.ChainID = &chainID
	if stageName != nil {
		c.CurrentStageName = *stageName
	}
}

// SetRunbookContent sets downloaded runbook content
func (c *ChainContext) SetRunbookContent(content string) {
	c.RunbookContent = &content
}

// StageResult represents a tuple of stage name and result
type StageResult struct {
	StageName string
	Result    *AgentExecutionResult
}

// StageContext represents context for single stage execution
type StageContext struct {
	// Core references
	ChainContext   *ChainContext
	AvailableTools *AvailableTools
	AgentName      string
	MCPServers     []string
}

// NewStageContext creates a new StageContext
func NewStageContext(chainContext *ChainContext, availableTools *AvailableTools, agentName string, mcpServers []string) *StageContext {
	return &StageContext{
		ChainContext:   chainContext,
		AvailableTools: availableTools,
		AgentName:      agentName,
		MCPServers:     mcpServers,
	}
}

// GetAlertData returns alert data from chain context
func (s *StageContext) GetAlertData() map[string]interface{} {
	return s.ChainContext.GetOriginalAlertData()
}

// GetRunbookContent returns runbook content from chain context
func (s *StageContext) GetRunbookContent() string {
	return s.ChainContext.GetRunbookContent()
}

// GetSessionID returns session ID from chain context
func (s *StageContext) GetSessionID() string {
	return s.ChainContext.SessionID
}

// GetStageName returns current stage name from chain context
func (s *StageContext) GetStageName() string {
	return s.ChainContext.CurrentStageName
}

// GetPreviousStagesResults returns previous stage results in execution order
func (s *StageContext) GetPreviousStagesResults() []StageResult {
	return s.ChainContext.GetPreviousStagesResults()
}

// HasPreviousStages checks if there are completed previous stages
func (s *StageContext) HasPreviousStages() bool {
	return len(s.GetPreviousStagesResults()) > 0
}

// FormatPreviousStagesContext formats previous stage results for prompts in execution order
func (s *StageContext) FormatPreviousStagesContext() string {
	results := s.GetPreviousStagesResults()
	if len(results) == 0 {
		return "No previous stage context available."
	}
	
	var sections []string
	for _, stageResult := range results {
		stageTitle := stageResult.StageName
		if stageResult.Result.StageDescription != nil {
			stageTitle = *stageResult.Result.StageDescription
		}
		
		sections = append(sections, fmt.Sprintf("### Results from '%s' stage:", stageTitle))
		sections = append(sections, "")
		sections = append(sections, "#### Analysis Result")
		sections = append(sections, "")
		
		// Use complete conversation history if available, otherwise fall back to result_summary
		content := ""
		if stageResult.Result.CompleteConversationHistory != nil {
			content = *stageResult.Result.CompleteConversationHistory
		} else if stageResult.Result.ResultSummary != nil {
			content = *stageResult.Result.ResultSummary
		}
		
		// Remove existing "## Analysis Result" header from content if present
		content = strings.TrimSpace(content)
		if strings.HasPrefix(content, "## Analysis Result") {
			lines := strings.Split(content, "\n")
			if len(lines) > 1 {
				lines = lines[1:] // Skip the header line
				// Skip empty line after header if present
				if len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
					lines = lines[1:]
				}
				content = strings.Join(lines, "\n")
			}
		}
		
		// Wrap the analysis result content with HTML comment boundaries
		sections = append(sections, "<!-- Analysis Result START -->")
		escapedContent := strings.ReplaceAll(content, "-->", "--&gt;")
		escapedContent = strings.ReplaceAll(escapedContent, "<!--", "&lt;!--")
		sections = append(sections, escapedContent)
		sections = append(sections, "<!-- Analysis Result END -->")
		sections = append(sections, "")
	}
	
	return strings.Join(sections, "\n")
}

// ToJSON converts the context to JSON for serialization
func (c *ChainContext) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

// FromJSON creates a ChainContext from JSON
func (c *ChainContext) FromJSON(data []byte) error {
	return json.Unmarshal(data, c)
}

// ValidateChainContext validates the chain context structure
func (c *ChainContext) ValidateChainContext() error {
	if c.AlertType == "" {
		return fmt.Errorf("alert type is required")
	}
	if c.SessionID == "" {
		return fmt.Errorf("session ID is required")
	}
	if c.CurrentStageName == "" {
		return fmt.Errorf("current stage name is required")
	}
	if c.AlertData == nil {
		return fmt.Errorf("alert data is required")
	}
	return nil
}

// Clone creates a deep copy of the ChainContext
func (c *ChainContext) Clone() *ChainContext {
	clone := &ChainContext{
		AlertType:        c.AlertType,
		SessionID:        c.SessionID,
		CurrentStageName: c.CurrentStageName,
		StageOutputs:     make(map[string]*AgentExecutionResult),
	}

	// Deep copy alert data
	clone.AlertData = make(map[string]interface{})
	for k, v := range c.AlertData {
		clone.AlertData[k] = v
	}

	// Deep copy stage outputs
	for k, v := range c.StageOutputs {
		if v != nil {
			// Create shallow copy - adjust if deep copy needed
			outputCopy := *v
			clone.StageOutputs[k] = &outputCopy
		}
	}

	// Copy optional fields
	if c.RunbookContent != nil {
		content := *c.RunbookContent
		clone.RunbookContent = &content
	}
	if c.ChainID != nil {
		chainID := *c.ChainID
		clone.ChainID = &chainID
	}

	return clone
}

// GetChainID returns the chain ID if available
func (c *ChainContext) GetChainID() string {
	if c.ChainID != nil {
		return *c.ChainID
	}
	return ""
}

// GetStageOutputByName returns stage output by stage name
func (c *ChainContext) GetStageOutputByName(stageName string) *AgentExecutionResult {
	return c.StageOutputs[stageName]
}

// GetCompletedStagesCount returns the number of completed stages
func (c *ChainContext) GetCompletedStagesCount() int {
	count := 0
	for _, result := range c.StageOutputs {
		if result != nil && result.Status == StageStatusCompleted {
			count++
		}
	}
	return count
}

// GetFailedStagesCount returns the number of failed stages
func (c *ChainContext) GetFailedStagesCount() int {
	count := 0
	for _, result := range c.StageOutputs {
		if result != nil && result.Status == StageStatusFailed {
			count++
		}
	}
	return count
}

// HasFailedStages checks if any stages have failed
func (c *ChainContext) HasFailedStages() bool {
	return c.GetFailedStagesCount() > 0
}

// GetStageNames returns all stage names that have outputs
func (c *ChainContext) GetStageNames() []string {
	names := make([]string, 0, len(c.StageOutputs))
	for name := range c.StageOutputs {
		names = append(names, name)
	}
	return names
}

// UpdateCurrentStage updates the current stage name
func (c *ChainContext) UpdateCurrentStage(stageName string) {
	c.CurrentStageName = stageName
}

// ToStageContext creates a StageContext from this ChainContext
func (c *ChainContext) ToStageContext(availableTools *AvailableTools, agentName string, mcpServers []string) *StageContext {
	return NewStageContext(c, availableTools, agentName, mcpServers)
}

// ValidateStageContext validates the stage context structure
func (s *StageContext) ValidateStageContext() error {
	if s.ChainContext == nil {
		return fmt.Errorf("chain context is required")
	}
	if err := s.ChainContext.ValidateChainContext(); err != nil {
		return fmt.Errorf("invalid chain context: %w", err)
	}
	if s.AgentName == "" {
		return fmt.Errorf("agent name is required")
	}
	return nil
}

// Clone creates a copy of the StageContext
func (s *StageContext) Clone() *StageContext {
	clone := &StageContext{
		ChainContext: s.ChainContext.Clone(),
		AgentName:    s.AgentName,
		MCPServers:   make([]string, len(s.MCPServers)),
	}

	// Copy MCP servers slice
	copy(clone.MCPServers, s.MCPServers)

	// Copy available tools if present
	if s.AvailableTools != nil {
		clone.AvailableTools = &AvailableTools{
			Tools: make([]ToolWithServer, len(s.AvailableTools.Tools)),
		}
		copy(clone.AvailableTools.Tools, s.AvailableTools.Tools)
	}

	return clone
}

// GetMCPServerCount returns the number of MCP servers available
func (s *StageContext) GetMCPServerCount() int {
	return len(s.MCPServers)
}

// GetToolCount returns the number of available tools
func (s *StageContext) GetToolCount() int {
	if s.AvailableTools == nil {
		return 0
	}
	return len(s.AvailableTools.Tools)
}

// HasMCPServer checks if a specific MCP server is available
func (s *StageContext) HasMCPServer(serverName string) bool {
	for _, server := range s.MCPServers {
		if server == serverName {
			return true
		}
	}
	return false
}

// GetToolsByServer returns tools for a specific server
func (s *StageContext) GetToolsByServer(serverName string) []ToolWithServer {
	if s.AvailableTools == nil {
		return nil
	}

	var tools []ToolWithServer
	for _, tool := range s.AvailableTools.Tools {
		if tool.Server == serverName {
			tools = append(tools, tool)
		}
	}
	return tools
}

// GetAlertType returns alert type from chain context
func (s *StageContext) GetAlertType() string {
	return s.ChainContext.AlertType
}

// GetChainID returns chain ID from chain context
func (s *StageContext) GetChainID() string {
	return s.ChainContext.GetChainID()
}

// ToJSON converts the stage context to JSON for serialization
func (s *StageContext) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// FromJSON creates a StageContext from JSON
func (s *StageContext) FromJSON(data []byte) error {
	return json.Unmarshal(data, s)
}