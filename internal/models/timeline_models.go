package models

import (
	"time"
	"gorm.io/gorm"
	"gorm.io/datatypes"
)

// TimelineInteraction represents an individual interaction within an alert processing session
// This captures all LLM requests, MCP tool calls, and other significant events for complete audit trail
// Matches the Python implementation for timeline logging and history tracking
type TimelineInteraction struct {
	// Primary key
	ID uint64 `gorm:"primaryKey;autoIncrement" json:"id"`

	// Session association
	SessionID string `gorm:"index;type:varchar(255);not null" json:"session_id"`

	// Interaction identification
	Type        string `gorm:"index;type:varchar(100);not null" json:"type"` // "llm_request", "mcp_call", "tool_response", etc.
	Source      string `gorm:"type:varchar(100)" json:"source,omitempty"`     // Agent name or service that initiated
	Target      string `gorm:"type:varchar(100)" json:"target,omitempty"`     // Target service (LLM provider, MCP server)

	// Timing information (microseconds since epoch UTC for precision)
	TimestampUs int64 `gorm:"index;not null" json:"timestamp_us"`
	DurationUs  *int64 `json:"duration_us,omitempty"` // Duration if applicable

	// Content and metadata
	Content         datatypes.JSON `gorm:"type:json" json:"content,omitempty"`          // Request/response content
	Metadata        datatypes.JSON `gorm:"type:json" json:"metadata,omitempty"`         // Additional context
	ErrorMessage    *string        `gorm:"type:text" json:"error_message,omitempty"`    // Error if failed

	// Token usage tracking (for LLM interactions)
	InputTokens  *int `json:"input_tokens,omitempty"`
	OutputTokens *int `json:"output_tokens,omitempty"`
	TotalTokens  *int `json:"total_tokens,omitempty"`

	// Cost tracking (optional)
	EstimatedCost *float64 `gorm:"type:decimal(10,6)" json:"estimated_cost,omitempty"`

	// Stage context (if part of a stage execution)
	StageExecutionID *string `gorm:"type:varchar(255);index" json:"stage_execution_id,omitempty"`
	IterationIndex   *int    `json:"iteration_index,omitempty"` // Which iteration within ReAct loop

	// Status tracking
	Status string `gorm:"type:varchar(50);not null;default:'completed'" json:"status"` // "pending", "completed", "failed"

	// GORM timestamps
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	AlertSession AlertSession `gorm:"foreignKey:SessionID" json:"-"`
}

// TableName returns the table name for TimelineInteraction
func (TimelineInteraction) TableName() string {
	return "timeline_interactions"
}

// BeforeCreate sets the timestamp if not already set
func (ti *TimelineInteraction) BeforeCreate(tx *gorm.DB) error {
	if ti.TimestampUs == 0 {
		ti.TimestampUs = time.Now().UnixMicro()
	}
	if ti.Status == "" {
		ti.Status = "pending"
	}
	return nil
}

// MarkCompleted marks the interaction as completed and calculates duration
func (ti *TimelineInteraction) MarkCompleted() {
	ti.Status = "completed"
	if ti.DurationUs == nil {
		now := time.Now().UnixMicro()
		duration := now - ti.TimestampUs
		ti.DurationUs = &duration
	}
}

// MarkFailed marks the interaction as failed with an error message
func (ti *TimelineInteraction) MarkFailed(errorMessage string) {
	ti.Status = "failed"
	ti.ErrorMessage = &errorMessage
	if ti.DurationUs == nil {
		now := time.Now().UnixMicro()
		duration := now - ti.TimestampUs
		ti.DurationUs = &duration
	}
}

// SetTokenUsage sets token usage information for LLM interactions
func (ti *TimelineInteraction) SetTokenUsage(inputTokens, outputTokens int) {
	ti.InputTokens = &inputTokens
	ti.OutputTokens = &outputTokens
	total := inputTokens + outputTokens
	ti.TotalTokens = &total
}

// SessionSummary provides aggregated statistics for a session
// Used by the frontend for displaying session overview information
// Matches the Python implementation's summary data structure
type SessionSummary struct {
	SessionID              string `json:"session_id"`
	AlertType              string `json:"alert_type"`
	AgentType              string `json:"agent_type"`
	Status                 string `json:"status"`

	// Timing information
	StartedAtUs            int64  `json:"started_at_us"`
	CompletedAtUs          *int64 `json:"completed_at_us,omitempty"`
	DurationMs             *int64 `json:"duration_ms,omitempty"`

	// Interaction counts
	LLMInteractions        int `json:"llm_interactions"`
	MCPCommunications      int `json:"mcp_communications"`
	TotalInteractions      int `json:"total_interactions"`
	FailedInteractions     int `json:"failed_interactions"`

	// Token usage aggregation
	SessionInputTokens     *int `json:"session_input_tokens,omitempty"`
	SessionOutputTokens    *int `json:"session_output_tokens,omitempty"`
	SessionTotalTokens     *int `json:"session_total_tokens,omitempty"`

	// Cost estimation
	EstimatedTotalCost     *float64 `json:"estimated_total_cost,omitempty"`

	// Chain/Stage statistics (if applicable)
	ChainStatistics        *ChainStatistics `json:"chain_statistics,omitempty"`

	// Analysis results
	HasFinalAnalysis       bool    `json:"has_final_analysis"`
	FinalAnalysisLength    *int    `json:"final_analysis_length,omitempty"`
	ErrorMessage           *string `json:"error_message,omitempty"`
}

// ChainStatistics provides chain-specific aggregated data
type ChainStatistics struct {
	ChainID           string `json:"chain_id"`
	TotalStages       int    `json:"total_stages"`
	CompletedStages   int    `json:"completed_stages"`
	FailedStages      int    `json:"failed_stages"`
	ActiveStages      int    `json:"active_stages"`
	CurrentStageIndex *int   `json:"current_stage_index,omitempty"`
	CurrentStageName  *string `json:"current_stage_name,omitempty"`
}

// TokenUsageStatistics provides detailed token usage breakdown
type TokenUsageStatistics struct {
	SessionID       string                    `json:"session_id"`
	TotalTokens     int                       `json:"total_tokens"`
	InputTokens     int                       `json:"input_tokens"`
	OutputTokens    int                       `json:"output_tokens"`
	ByProvider      map[string]TokenBreakdown `json:"by_provider"`      // e.g., "openai", "anthropic"
	ByInteraction   map[string]TokenBreakdown `json:"by_interaction"`   // e.g., "llm_request", "mcp_call"
	ByStage         map[string]TokenBreakdown `json:"by_stage"`         // Stage-wise breakdown
	EstimatedCost   float64                   `json:"estimated_cost"`
}

// TokenBreakdown provides detailed breakdown for a specific category
type TokenBreakdown struct {
	Count        int     `json:"count"`         // Number of interactions
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	TotalTokens  int     `json:"total_tokens"`
	Cost         float64 `json:"cost"`
}

// InteractionType constants for timeline interactions
const (
	InteractionTypeLLMRequest      = "llm_request"
	InteractionTypeLLMResponse     = "llm_response"
	InteractionTypeMCPCall         = "mcp_call"
	InteractionTypeMCPResponse     = "mcp_response"
	InteractionTypeToolCall        = "tool_call"
	InteractionTypeToolResponse    = "tool_response"
	InteractionTypeStageStart      = "stage_start"
	InteractionTypeStageComplete   = "stage_complete"
	InteractionTypeIteration       = "iteration"
	InteractionTypeReActThinking   = "react_thinking"
	InteractionTypeReActAction     = "react_action"
	InteractionTypeReActObservation = "react_observation"
	InteractionTypeError           = "error"
	InteractionTypeSystemEvent     = "system_event"
)

// InteractionStatus constants
const (
	InteractionStatusPending   = "pending"
	InteractionStatusCompleted = "completed"
	InteractionStatusFailed    = "failed"
)