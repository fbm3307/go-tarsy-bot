package models

import (
	"gorm.io/datatypes"
)

// WebSocket message types that match the frontend expectations exactly
// These models ensure compatibility with the existing React TypeScript frontend

// WebSocketMessage represents the base structure for all WebSocket messages
type WebSocketMessage struct {
	Type     string      `json:"type"`               // Message type identifier
	Channel  string      `json:"channel,omitempty"`  // Channel identifier for routing
	Data     interface{} `json:"data,omitempty"`     // Message payload
	Messages []WebSocketMessage `json:"messages,omitempty"` // For batched messages
	Count    int         `json:"count,omitempty"`    // Number of messages in batch
}

// SessionUpdate represents session progress updates sent via WebSocket
// Matches the frontend's SessionUpdate interface expectations
type SessionUpdate struct {
	SessionID           string              `json:"session_id"`
	AlertType           string              `json:"alert_type"`
	AgentType           string              `json:"agent_type"`
	Status              AlertSessionStatus  `json:"status"`
	Progress            *float64            `json:"progress,omitempty"`           // Percentage (0-100)
	CurrentOperation    *string             `json:"current_operation,omitempty"`  // Human-readable current step
	ErrorMessage        *string             `json:"error_message,omitempty"`
	StartedAtUs         int64               `json:"started_at_us"`
	CompletedAtUs       *int64              `json:"completed_at_us,omitempty"`
	DurationMs          *int64              `json:"duration_ms,omitempty"`

	// Chain-specific fields
	ChainID             *string             `json:"chain_id,omitempty"`
	CurrentStageIndex   *int                `json:"current_stage_index,omitempty"`
	CurrentStageName    *string             `json:"current_stage_name,omitempty"`
	TotalStages         *int                `json:"total_stages,omitempty"`
	CompletedStages     *int                `json:"completed_stages,omitempty"`

	// Interaction counts for real-time stats
	LLMInteractions     *int                `json:"llm_interactions,omitempty"`
	MCPCommunications   *int                `json:"mcp_communications,omitempty"`
	TotalInteractions   *int                `json:"total_interactions,omitempty"`

	// Token usage updates
	SessionInputTokens  *int                `json:"session_input_tokens,omitempty"`
	SessionOutputTokens *int                `json:"session_output_tokens,omitempty"`
	SessionTotalTokens  *int                `json:"session_total_tokens,omitempty"`
}

// ChainProgressUpdate represents chain execution progress updates
// Used for multi-stage alert processing workflows
type ChainProgressUpdate struct {
	SessionID         string      `json:"session_id"`
	ChainID           string      `json:"chain_id"`
	Status            ChainStatus `json:"status"`
	CurrentStageIndex int         `json:"current_stage_index"`
	CurrentStageName  string      `json:"current_stage_name"`
	TotalStages       int         `json:"total_stages"`
	CompletedStages   int         `json:"completed_stages"`
	FailedStages      int         `json:"failed_stages"`
	Progress          float64     `json:"progress"` // Overall chain progress (0-100)

	// Timing information
	StartedAtUs       int64   `json:"started_at_us"`
	EstimatedDurationMs *int64 `json:"estimated_duration_ms,omitempty"`

	// Stage breakdown
	StageStatuses     map[string]string `json:"stage_statuses,omitempty"` // stage_id -> status
}

// StageProgressUpdate represents individual stage execution progress
// Used for detailed stage-level progress tracking within chains
type StageProgressUpdate struct {
	SessionID        string      `json:"session_id"`
	StageExecutionID string      `json:"stage_execution_id"`
	StageID          string      `json:"stage_id"`
	StageIndex       int         `json:"stage_index"`
	StageName        string      `json:"stage_name"`
	AgentType        string      `json:"agent"`
	Status           StageStatus `json:"status"`
	Progress         float64     `json:"progress"` // Stage progress (0-100)

	// Timing information
	StartedAtUs     *int64 `json:"started_at_us,omitempty"`
	CompletedAtUs   *int64 `json:"completed_at_us,omitempty"`
	DurationMs      *int64 `json:"duration_ms,omitempty"`

	// Current operation within the stage
	CurrentOperation *string `json:"current_operation,omitempty"`

	// Results and errors
	ErrorMessage     *string        `json:"error_message,omitempty"`
	StageOutput      datatypes.JSON `json:"stage_output,omitempty"`

	// Iteration tracking (for ReAct loops within stages)
	CurrentIteration *int   `json:"current_iteration,omitempty"`
	MaxIterations    *int   `json:"max_iterations,omitempty"`
	IterationStep    *string `json:"iteration_step,omitempty"` // "thinking", "acting", "observing"
}

// DashboardUpdate represents general dashboard statistics updates
// Used for system-wide metrics and status information
type DashboardUpdate struct {
	Type      string      `json:"type"`      // "system_metrics", "session_count", etc.
	Timestamp int64       `json:"timestamp"` // Unix timestamp (microseconds)
	Data      interface{} `json:"data"`      // Specific update data
}

// SystemMetrics represents system health and performance metrics
type SystemMetrics struct {
	ActiveSessions    int                `json:"active_sessions"`
	CompletedSessions int                `json:"completed_sessions"`
	FailedSessions    int                `json:"failed_sessions"`
	TotalSessions     int                `json:"total_sessions"`

	// System health
	SystemStatus      SystemHealthStatus `json:"system_status"`

	// Service health
	DatabaseHealth    string             `json:"database_health"`
	LLMServiceHealth  map[string]string  `json:"llm_service_health"`  // provider -> status
	MCPServerHealth   map[string]string  `json:"mcp_server_health"`   // server -> status

	// Performance metrics
	AverageProcessingTimeMs *float64       `json:"average_processing_time_ms,omitempty"`
	ThroughputPerHour      *float64        `json:"throughput_per_hour,omitempty"`

	// Resource usage
	MemoryUsageMB     *float64            `json:"memory_usage_mb,omitempty"`
	CPUUsagePercent   *float64            `json:"cpu_usage_percent,omitempty"`

	// Token usage statistics
	TokensUsedToday   *int                `json:"tokens_used_today,omitempty"`
	EstimatedCostToday *float64           `json:"estimated_cost_today,omitempty"`
}

// SessionTimelineUpdate represents batched timeline interaction updates
// Used for efficient real-time updates of session processing history
type SessionTimelineUpdate struct {
	SessionID     string                `json:"session_id"`
	Interactions  []TimelineInteraction `json:"interactions"`
	BatchSize     int                   `json:"batch_size"`
	TotalCount    int                   `json:"total_count"`
	HasMore       bool                  `json:"has_more"`
}

// WebSocket event types that match frontend expectations
const (
	// Session-specific events
	WSEventSessionUpdate      = "session_update"
	WSEventSessionCompleted   = "session_completed"
	WSEventSessionFailed      = "session_failed"
	WSEventSessionStatusChange = "session_status_change"

	// Chain and stage events
	WSEventChainProgress      = "chain_progress"
	WSEventStageProgress      = "stage_progress"

	// Dashboard events
	WSEventDashboardUpdate    = "dashboard_update"
	WSEventSystemMetrics      = "system_metrics"

	// Timeline events
	WSEventTimelineUpdate     = "timeline_update"
	WSEventBatchedSessionUpdates = "batched_session_updates"

	// Connection management
	WSEventPing               = "ping"
	WSEventPong               = "pong"
	WSEventConnectionEstablished = "connection_established"
	WSEventSubscriptionResponse = "subscription_response"

	// Batching
	WSEventMessageBatch       = "message_batch"
)

// WebSocket channel names
const (
	// Global channels
	WSChannelDashboardUpdates = "dashboard_updates"
	WSChannelSystemMetrics    = "system_metrics"

	// Session-specific channels (format: session_{sessionId})
	WSChannelSessionPrefix    = "session_"
)

// WebSocket subscription message
type WSSubscriptionMessage struct {
	Type    string `json:"type"`    // "subscribe" or "unsubscribe"
	Channel string `json:"channel"` // Channel name to subscribe to
}

// WebSocket subscription response
type WSSubscriptionResponse struct {
	Type    string `json:"type"`    // "subscription_response"
	Channel string `json:"channel"` // Channel name
	Status  string `json:"status"`  // "subscribed", "unsubscribed", "error"
	Message string `json:"message,omitempty"` // Error message if status is "error"
}

// Helper functions for creating WebSocket messages

// NewSessionUpdateMessage creates a session update WebSocket message
func NewSessionUpdateMessage(sessionID string, update *SessionUpdate) *WebSocketMessage {
	return &WebSocketMessage{
		Type:    WSEventSessionUpdate,
		Channel: WSChannelSessionPrefix + sessionID,
		Data:    update,
	}
}

// NewChainProgressMessage creates a chain progress WebSocket message
func NewChainProgressMessage(sessionID string, progress *ChainProgressUpdate) *WebSocketMessage {
	return &WebSocketMessage{
		Type:    WSEventChainProgress,
		Channel: WSChannelSessionPrefix + sessionID,
		Data:    progress,
	}
}

// NewStageProgressMessage creates a stage progress WebSocket message
func NewStageProgressMessage(sessionID string, progress *StageProgressUpdate) *WebSocketMessage {
	return &WebSocketMessage{
		Type:    WSEventStageProgress,
		Channel: WSChannelSessionPrefix + sessionID,
		Data:    progress,
	}
}

// NewDashboardUpdateMessage creates a dashboard update WebSocket message
func NewDashboardUpdateMessage(updateType string, data interface{}) *WebSocketMessage {
	return &WebSocketMessage{
		Type:    WSEventDashboardUpdate,
		Channel: WSChannelDashboardUpdates,
		Data: &DashboardUpdate{
			Type:      updateType,
			Timestamp: GetCurrentTimestampUs(),
			Data:      data,
		},
	}
}

// NewSystemMetricsMessage creates a system metrics WebSocket message
func NewSystemMetricsMessage(metrics *SystemMetrics) *WebSocketMessage {
	return &WebSocketMessage{
		Type:    WSEventSystemMetrics,
		Channel: WSChannelSystemMetrics,
		Data:    metrics,
	}
}

// NewMessageBatch creates a batched WebSocket message
func NewMessageBatch(messages []WebSocketMessage) *WebSocketMessage {
	return &WebSocketMessage{
		Type:     WSEventMessageBatch,
		Messages: messages,
		Count:    len(messages),
	}
}