package services

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/models"
)

// DashboardWebSocketIntegration handles real-time WebSocket updates for the dashboard
// This matches the expectations of the React dashboard's WebSocket service
type DashboardWebSocketIntegration struct {
	wsManager      *WebSocketManager
	historyService *HistoryService
	logger         *zap.Logger
}

// NewDashboardWebSocketIntegration creates a new dashboard WebSocket integration
func NewDashboardWebSocketIntegration(wsManager *WebSocketManager, historyService *HistoryService, logger *zap.Logger) *DashboardWebSocketIntegration {
	return &DashboardWebSocketIntegration{
		wsManager:      wsManager,
		historyService: historyService,
		logger:         logger,
	}
}

// Dashboard WebSocket message types (matching React dashboard expectations)
const (
	MessageTypeSessionUpdate    = "session_update"
	MessageTypeSessionCompleted = "session_completed"
	MessageTypeSessionFailed    = "session_failed"
	MessageTypeChainProgress    = "chain_progress"
	MessageTypeStageProgress    = "stage_progress"
	MessageTypeDashboardUpdate  = "dashboard_update"
)

// WebSocket message structures matching dashboard expectations
type SessionUpdateMessage struct {
	Type      string                 `json:"type"`
	SessionID string                 `json:"session_id"`
	Status    string                 `json:"status"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

type ChainProgressMessage struct {
	Type        string                 `json:"type"`
	SessionID   string                 `json:"session_id"`
	ChainID     string                 `json:"chain_id"`
	StageIndex  int                    `json:"stage_index"`
	TotalStages int                    `json:"total_stages"`
	Status      string                 `json:"status"`
	StageName   string                 `json:"stage_name"`
	Data        map[string]interface{} `json:"data"`
	Timestamp   time.Time              `json:"timestamp"`
}

type StageProgressMessage struct {
	Type               string                 `json:"type"`
	SessionID          string                 `json:"session_id"`
	StageExecutionID   string                 `json:"stage_execution_id"`
	StageName          string                 `json:"stage_name"`
	Status             string                 `json:"status"`
	Progress           int                    `json:"progress"`
	TotalInteractions  int                    `json:"total_interactions"`
	CurrentInteraction *InteractionProgress   `json:"current_interaction,omitempty"`
	Data               map[string]interface{} `json:"data"`
	Timestamp          time.Time              `json:"timestamp"`
}

type InteractionProgress struct {
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Status      string                 `json:"status"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
}

type DashboardUpdateMessage struct {
	Type      string                 `json:"type"`
	UpdatedAt time.Time              `json:"updated_at"`
	Stats     map[string]interface{} `json:"stats"`
	Data      map[string]interface{} `json:"data"`
}

// Session lifecycle events

// BroadcastSessionStarted broadcasts when a new session starts
func (dwi *DashboardWebSocketIntegration) BroadcastSessionStarted(ctx context.Context, sessionID string, alertType string, agentType string) error {
	message := SessionUpdateMessage{
		Type:      MessageTypeSessionUpdate,
		SessionID: sessionID,
		Status:    "started",
		Data: map[string]interface{}{
			"alert_type": alertType,
			"agent_type": agentType,
			"event":      "session_started",
		},
		Timestamp: time.Now(),
	}

	return dwi.broadcastToDashboard(message)
}

// BroadcastSessionCompleted broadcasts when a session completes successfully
func (dwi *DashboardWebSocketIntegration) BroadcastSessionCompleted(ctx context.Context, sessionID string, finalAnalysis string) error {
	message := SessionUpdateMessage{
		Type:      MessageTypeSessionCompleted,
		SessionID: sessionID,
		Status:    "completed",
		Data: map[string]interface{}{
			"final_analysis": finalAnalysis,
			"event":          "session_completed",
		},
		Timestamp: time.Now(),
	}

	// Broadcast to both session-specific and dashboard channels
	if err := dwi.broadcastToSession(sessionID, message); err != nil {
		dwi.logger.Warn("Failed to broadcast to session channel", zap.Error(err))
	}

	return dwi.broadcastToDashboard(message)
}

// BroadcastSessionFailed broadcasts when a session fails
func (dwi *DashboardWebSocketIntegration) BroadcastSessionFailed(ctx context.Context, sessionID string, errorMessage string) error {
	message := SessionUpdateMessage{
		Type:      MessageTypeSessionFailed,
		SessionID: sessionID,
		Status:    "failed",
		Data: map[string]interface{}{
			"error_message": errorMessage,
			"event":         "session_failed",
		},
		Timestamp: time.Now(),
	}

	// Broadcast to both session-specific and dashboard channels
	if err := dwi.broadcastToSession(sessionID, message); err != nil {
		dwi.logger.Warn("Failed to broadcast to session channel", zap.Error(err))
	}

	return dwi.broadcastToDashboard(message)
}

// Chain and stage progress events

// BroadcastChainProgress broadcasts chain-level progress updates
func (dwi *DashboardWebSocketIntegration) BroadcastChainProgress(ctx context.Context, sessionID string, chainID string, stageIndex int, totalStages int, stageName string, status string) error {
	message := ChainProgressMessage{
		Type:        MessageTypeChainProgress,
		SessionID:   sessionID,
		ChainID:     chainID,
		StageIndex:  stageIndex,
		TotalStages: totalStages,
		Status:      status,
		StageName:   stageName,
		Data: map[string]interface{}{
			"chain_id":     chainID,
			"stage_index":  stageIndex,
			"total_stages": totalStages,
		},
		Timestamp: time.Now(),
	}

	// Broadcast to both session-specific and dashboard channels
	if err := dwi.broadcastToSession(sessionID, message); err != nil {
		dwi.logger.Warn("Failed to broadcast to session channel", zap.Error(err))
	}

	return dwi.broadcastToDashboard(message)
}

// BroadcastStageProgress broadcasts stage-level progress updates
func (dwi *DashboardWebSocketIntegration) BroadcastStageProgress(ctx context.Context, sessionID string, stageExecutionID string, stageName string, status string, progress int, totalInteractions int) error {
	message := StageProgressMessage{
		Type:              MessageTypeStageProgress,
		SessionID:         sessionID,
		StageExecutionID:  stageExecutionID,
		StageName:         stageName,
		Status:            status,
		Progress:          progress,
		TotalInteractions: totalInteractions,
		Data: map[string]interface{}{
			"stage_execution_id": stageExecutionID,
			"progress_percent":   (float64(progress) / float64(totalInteractions)) * 100,
		},
		Timestamp: time.Now(),
	}

	// Broadcast to both session-specific and dashboard channels
	if err := dwi.broadcastToSession(sessionID, message); err != nil {
		dwi.logger.Warn("Failed to broadcast to session channel", zap.Error(err))
	}

	return dwi.broadcastToDashboard(message)
}

// BroadcastStageProgressWithInteraction broadcasts stage progress with current interaction details
func (dwi *DashboardWebSocketIntegration) BroadcastStageProgressWithInteraction(ctx context.Context, sessionID string, stageExecutionID string, stageName string, status string, progress int, totalInteractions int, currentInteraction *InteractionProgress) error {
	message := StageProgressMessage{
		Type:               MessageTypeStageProgress,
		SessionID:          sessionID,
		StageExecutionID:   stageExecutionID,
		StageName:          stageName,
		Status:             status,
		Progress:           progress,
		TotalInteractions:  totalInteractions,
		CurrentInteraction: currentInteraction,
		Data: map[string]interface{}{
			"stage_execution_id": stageExecutionID,
			"progress_percent":   (float64(progress) / float64(totalInteractions)) * 100,
			"has_interaction":    currentInteraction != nil,
		},
		Timestamp: time.Now(),
	}

	// Broadcast to both session-specific and dashboard channels
	if err := dwi.broadcastToSession(sessionID, message); err != nil {
		dwi.logger.Warn("Failed to broadcast to session channel", zap.Error(err))
	}

	return dwi.broadcastToDashboard(message)
}

// Interaction-level progress

// BroadcastLLMInteractionStarted broadcasts when an LLM interaction starts
func (dwi *DashboardWebSocketIntegration) BroadcastLLMInteractionStarted(ctx context.Context, sessionID string, stageExecutionID string, provider string, description string) error {
	interaction := &InteractionProgress{
		Type:        "llm_request",
		Source:      "agent",
		Target:      provider,
		Status:      "started",
		Description: description,
		Data: map[string]interface{}{
			"provider": provider,
		},
	}

	return dwi.BroadcastStageProgressWithInteraction(ctx, sessionID, stageExecutionID, "", "processing", 0, 0, interaction)
}

// BroadcastLLMInteractionCompleted broadcasts when an LLM interaction completes
func (dwi *DashboardWebSocketIntegration) BroadcastLLMInteractionCompleted(ctx context.Context, sessionID string, stageExecutionID string, provider string, inputTokens int, outputTokens int) error {
	interaction := &InteractionProgress{
		Type:        "llm_request",
		Source:      "agent",
		Target:      provider,
		Status:      "completed",
		Description: fmt.Sprintf("LLM call completed (%d→%d tokens)", inputTokens, outputTokens),
		Data: map[string]interface{}{
			"provider":      provider,
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
			"total_tokens":  inputTokens + outputTokens,
		},
	}

	return dwi.BroadcastStageProgressWithInteraction(ctx, sessionID, stageExecutionID, "", "processing", 0, 0, interaction)
}

// BroadcastMCPInteractionStarted broadcasts when an MCP tool call starts
func (dwi *DashboardWebSocketIntegration) BroadcastMCPInteractionStarted(ctx context.Context, sessionID string, stageExecutionID string, server string, tool string, description string) error {
	interaction := &InteractionProgress{
		Type:        "mcp_call",
		Source:      "agent",
		Target:      server,
		Status:      "started",
		Description: description,
		Data: map[string]interface{}{
			"server": server,
			"tool":   tool,
		},
	}

	return dwi.BroadcastStageProgressWithInteraction(ctx, sessionID, stageExecutionID, "", "processing", 0, 0, interaction)
}

// BroadcastMCPInteractionCompleted broadcasts when an MCP tool call completes
func (dwi *DashboardWebSocketIntegration) BroadcastMCPInteractionCompleted(ctx context.Context, sessionID string, stageExecutionID string, server string, tool string, success bool) error {
	status := "completed"
	description := fmt.Sprintf("MCP tool call completed: %s", tool)
	if !success {
		status = "failed"
		description = fmt.Sprintf("MCP tool call failed: %s", tool)
	}

	interaction := &InteractionProgress{
		Type:        "mcp_call",
		Source:      "agent",
		Target:      server,
		Status:      status,
		Description: description,
		Data: map[string]interface{}{
			"server":  server,
			"tool":    tool,
			"success": success,
		},
	}

	return dwi.BroadcastStageProgressWithInteraction(ctx, sessionID, stageExecutionID, "", "processing", 0, 0, interaction)
}

// Dashboard-level updates

// BroadcastDashboardUpdate broadcasts general dashboard updates (stats, etc.)
func (dwi *DashboardWebSocketIntegration) BroadcastDashboardUpdate(ctx context.Context, stats map[string]interface{}) error {
	message := DashboardUpdateMessage{
		Type:      MessageTypeDashboardUpdate,
		UpdatedAt: time.Now(),
		Stats:     stats,
		Data:      make(map[string]interface{}),
	}

	return dwi.broadcastToDashboard(message)
}

// BroadcastDashboardStatsUpdate broadcasts updated dashboard statistics
func (dwi *DashboardWebSocketIntegration) BroadcastDashboardStatsUpdate(ctx context.Context) error {
	// Get current statistics from history service
	stats, err := dwi.historyService.GetHistoryStats(ctx)
	if err != nil {
		dwi.logger.Warn("Failed to get history stats for dashboard update", zap.Error(err))
		stats = map[string]interface{}{
			"total_sessions": 0,
			"error":          "Failed to fetch stats",
		}
	}

	return dwi.BroadcastDashboardUpdate(ctx, stats)
}

// Helper methods for broadcasting

// broadcastToDashboard broadcasts a message to all dashboard subscribers
func (dwi *DashboardWebSocketIntegration) broadcastToDashboard(message interface{}) error {
	// Convert to WebSocketMessage format
	wsMessage := &models.WebSocketMessage{
		Type: dwi.getMessageType(message),
		Data: message,
	}

	// For dashboard broadcasting, we need to broadcast to channels that start with "dashboard_"
	// Since the current WebSocketManager doesn't have pattern broadcasting,
	// we'll broadcast to a generic dashboard channel
	err := dwi.wsManager.BroadcastToChannel("dashboard", wsMessage)
	if err != nil {
		dwi.logger.Debug("Failed to broadcast to dashboard channel", zap.Error(err))
		// Don't return error as dashboard channel may not have subscribers
	}

	dwi.logger.Debug("Broadcasted message to dashboard",
		zap.String("message_type", dwi.getMessageType(message)))

	return nil
}

// broadcastToSession broadcasts a message to session-specific subscribers
func (dwi *DashboardWebSocketIntegration) broadcastToSession(sessionID string, message interface{}) error {
	// Convert to WebSocketMessage format
	wsMessage := &models.WebSocketMessage{
		Type: dwi.getMessageType(message),
		Data: message,
	}

	// Broadcast to session-specific channel
	channel := fmt.Sprintf("session_%s", sessionID)
	err := dwi.wsManager.BroadcastToChannel(channel, wsMessage)
	if err != nil {
		dwi.logger.Debug("Failed to broadcast to session channel (may have no subscribers)",
			zap.String("session_id", sessionID),
			zap.Error(err))
		// Don't return error as session channels may not have subscribers
	}

	dwi.logger.Debug("Broadcasted message to session channel",
		zap.String("session_id", sessionID),
		zap.String("message_type", dwi.getMessageType(message)))

	return nil
}

// getMessageType extracts the message type from a message interface
func (dwi *DashboardWebSocketIntegration) getMessageType(message interface{}) string {
	switch msg := message.(type) {
	case SessionUpdateMessage:
		return msg.Type
	case ChainProgressMessage:
		return msg.Type
	case StageProgressMessage:
		return msg.Type
	case DashboardUpdateMessage:
		return msg.Type
	default:
		return "unknown"
	}
}

// Channel management helpers

// GetDashboardChannel returns the dashboard channel name
func (dwi *DashboardWebSocketIntegration) GetDashboardChannel() string {
	return "dashboard"
}

// GetSessionChannel returns the channel name for a specific session
func (dwi *DashboardWebSocketIntegration) GetSessionChannel(sessionID string) string {
	return fmt.Sprintf("session_%s", sessionID)
}

// Integration with existing alert processing workflow

// BroadcastSessionEvent broadcasts session lifecycle events
func (dwi *DashboardWebSocketIntegration) BroadcastSessionEvent(ctx context.Context, session *models.AlertSession, eventType string) error {
	switch eventType {
	case "created", "started":
		alertType := ""
		if session.AlertType != nil {
			alertType = *session.AlertType
		}
		return dwi.BroadcastSessionStarted(ctx, session.SessionID, alertType, session.AgentType)
	case "completed":
		finalAnalysis := ""
		if session.FinalAnalysis != nil {
			finalAnalysis = *session.FinalAnalysis
		}
		return dwi.BroadcastSessionCompleted(ctx, session.SessionID, finalAnalysis)
	case "failed":
		errorMessage := ""
		if session.ErrorMessage != nil {
			errorMessage = *session.ErrorMessage
		}
		return dwi.BroadcastSessionFailed(ctx, session.SessionID, errorMessage)
	default:
		dwi.logger.Debug("Unknown session event type", zap.String("event", eventType))
		return nil
	}
}

// BroadcastStageEvent broadcasts stage lifecycle events
func (dwi *DashboardWebSocketIntegration) BroadcastStageEvent(ctx context.Context, stageExecution *models.StageExecution, eventType string) error {
	switch eventType {
	case "started":
		return dwi.BroadcastStageProgress(ctx, stageExecution.SessionID, stageExecution.ExecutionID, stageExecution.StageName, "started", 0, 1)
	case "completed":
		status := "completed"
		if stageExecution.IsFailed() {
			status = "failed"
		}
		return dwi.BroadcastStageProgress(ctx, stageExecution.SessionID, stageExecution.ExecutionID, stageExecution.StageName, status, 1, 1)
	default:
		dwi.logger.Debug("Unknown stage event type", zap.String("event", eventType))
		return nil
	}
}