package models

import (
	"time"
)

// AgentExecutionResult represents the result of agent execution
type AgentExecutionResult struct {
	Status      StageStatus `json:"status"`
	AgentName   string      `json:"agent_name"`
	TimestampUs int64       `json:"timestamp_us"`
	
	// Result summary for API consumption
	ResultSummary *string `json:"result_summary,omitempty"`
	
	// Complete conversation history for audit and debugging
	CompleteConversationHistory *string `json:"complete_conversation_history,omitempty"`
	
	// Final analysis extracted from the conversation
	FinalAnalysis *string `json:"final_analysis,omitempty"`
	
	// Error information for failed executions
	ErrorMessage *string `json:"error_message,omitempty"`
	
	// Stage description for context
	StageDescription *string `json:"stage_description,omitempty"`
	
	// Duration in milliseconds
	DurationMs *int64 `json:"duration_ms,omitempty"`
	
	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// NewAgentExecutionResult creates a new AgentExecutionResult
func NewAgentExecutionResult(status StageStatus, agentName string) *AgentExecutionResult {
	return &AgentExecutionResult{
		Status:      status,
		AgentName:   agentName,
		TimestampUs: time.Now().UnixMicro(),
		Metadata:    make(map[string]interface{}),
	}
}

// SetResultSummary sets the result summary
func (r *AgentExecutionResult) SetResultSummary(summary string) {
	r.ResultSummary = &summary
}

// SetCompleteConversationHistory sets the complete conversation history
func (r *AgentExecutionResult) SetCompleteConversationHistory(history string) {
	r.CompleteConversationHistory = &history
}

// SetFinalAnalysis sets the final analysis
func (r *AgentExecutionResult) SetFinalAnalysis(analysis string) {
	r.FinalAnalysis = &analysis
}

// SetErrorMessage sets the error message
func (r *AgentExecutionResult) SetErrorMessage(errorMsg string) {
	r.ErrorMessage = &errorMsg
}

// SetStageDescription sets the stage description
func (r *AgentExecutionResult) SetStageDescription(description string) {
	r.StageDescription = &description
}

// SetDuration sets the duration in milliseconds
func (r *AgentExecutionResult) SetDuration(duration time.Duration) {
	durationMs := duration.Milliseconds()
	r.DurationMs = &durationMs
}

// AddMetadata adds metadata to the result
func (r *AgentExecutionResult) AddMetadata(key string, value interface{}) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]interface{})
	}
	r.Metadata[key] = value
}

// IsSuccessful returns true if the execution was successful
func (r *AgentExecutionResult) IsSuccessful() bool {
	return r.Status == StageStatusCompleted
}

// IsFailed returns true if the execution failed
func (r *AgentExecutionResult) IsFailed() bool {
	return r.Status == StageStatusFailed
}

// IsPartial returns true if the execution was partially successful
func (r *AgentExecutionResult) IsPartial() bool {
	return r.Status == StageStatusPartial
}

// GetResultSummary returns the result summary with fallback
func (r *AgentExecutionResult) GetResultSummary() string {
	if r.ResultSummary != nil {
		return *r.ResultSummary
	}
	return ""
}

// GetCompleteConversationHistory returns the complete conversation history with fallback
func (r *AgentExecutionResult) GetCompleteConversationHistory() string {
	if r.CompleteConversationHistory != nil {
		return *r.CompleteConversationHistory
	}
	return ""
}

// GetFinalAnalysis returns the final analysis with fallback
func (r *AgentExecutionResult) GetFinalAnalysis() string {
	if r.FinalAnalysis != nil {
		return *r.FinalAnalysis
	}
	return ""
}

// GetErrorMessage returns the error message with fallback
func (r *AgentExecutionResult) GetErrorMessage() string {
	if r.ErrorMessage != nil {
		return *r.ErrorMessage
	}
	return ""
}

// GetStageDescription returns the stage description with fallback
func (r *AgentExecutionResult) GetStageDescription() string {
	if r.StageDescription != nil {
		return *r.StageDescription
	}
	return ""
}