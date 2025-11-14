package services

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/codeready/go-tarsy-bot/internal/database"
	"github.com/codeready/go-tarsy-bot/internal/models"
)

// HistoryService manages alert session and stage execution history
// Enhanced to match Python's HistoryService with timeline interaction support
type HistoryService struct {
	db     *database.DB
	logger *zap.Logger
}

// HistoryFilter represents filtering options for history queries
type HistoryFilter struct {
	AlertType     *string    `json:"alert_type,omitempty"`
	Status        *string    `json:"status,omitempty"`
	AgentType     *string    `json:"agent_type,omitempty"`
	StartTime     *time.Time `json:"start_time,omitempty"`
	EndTime       *time.Time `json:"end_time,omitempty"`
	Limit         int        `json:"limit,omitempty"`
	Offset        int        `json:"offset,omitempty"`
}

// SessionSummary provides aggregate information about a session
type SessionSummary struct {
	SessionID       string    `json:"session_id"`
	AlertType       string    `json:"alert_type"`
	Status          string    `json:"status"`
	TotalStages     int       `json:"total_stages"`
	CompletedStages int       `json:"completed_stages"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	DurationMs      *int64    `json:"duration_ms,omitempty"`
	ErrorMessage    *string   `json:"error_message,omitempty"`
}

// NewHistoryService creates a new history service
func NewHistoryService(db *database.DB, logger *zap.Logger) *HistoryService {
	return &HistoryService{
		db:     db,
		logger: logger,
	}
}

// CreateSession creates a new alert session record
func (hs *HistoryService) CreateSession(ctx context.Context, session *models.AlertSession) error {
	result := hs.db.WithContext(ctx).Create(session)
	if result.Error != nil {
		hs.logger.Error("Failed to create session",
			zap.Error(result.Error),
			zap.String("session_id", session.SessionID),
		)
		return fmt.Errorf("failed to create session: %w", result.Error)
	}

	hs.logger.Info("Created session",
		zap.String("session_id", session.SessionID),
		zap.String("alert_type", models.SafeStringValue(session.AlertType)),
	)

	return nil
}

// UpdateSession updates an existing alert session
func (hs *HistoryService) UpdateSession(ctx context.Context, session *models.AlertSession) error {
	// Use Select to only update non-zero fields to avoid overwriting existing data
	result := hs.db.WithContext(ctx).Model(session).Where("session_id = ?", session.SessionID).Updates(session)
	if result.Error != nil {
		hs.logger.Error("Failed to update session",
			zap.Error(result.Error),
			zap.String("session_id", session.SessionID),
		)
		return fmt.Errorf("failed to update session: %w", result.Error)
	}

	hs.logger.Debug("Updated session",
		zap.String("session_id", session.SessionID),
		zap.String("status", string(session.Status)),
		zap.Int64("rows_affected", result.RowsAffected),
	)

	return nil
}

// GetSession retrieves a session by ID
func (hs *HistoryService) GetSession(ctx context.Context, sessionID string) (*models.AlertSession, error) {
	var session models.AlertSession
	result := hs.db.WithContext(ctx).
		Preload("StageExecutions").
		Where("session_id = ?", sessionID).
		First(&session)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		return nil, fmt.Errorf("failed to get session: %w", result.Error)
	}

	return &session, nil
}

// ListSessions retrieves sessions with optional filtering and pagination
func (hs *HistoryService) ListSessions(ctx context.Context, filter *HistoryFilter) ([]*models.AlertSession, error) {
	query := hs.db.WithContext(ctx).Model(&models.AlertSession{})

	// Apply filters
	if filter != nil {
		if filter.AlertType != nil {
			query = query.Where("alert_type = ?", *filter.AlertType)
		}
		if filter.Status != nil {
			query = query.Where("status = ?", *filter.Status)
		}
		if filter.AgentType != nil {
			query = query.Where("agent_type = ?", *filter.AgentType)
		}
		if filter.StartTime != nil {
			query = query.Where("started_at_us >= ?", filter.StartTime.UnixMicro())
		}
		if filter.EndTime != nil {
			query = query.Where("started_at_us <= ?", filter.EndTime.UnixMicro())
		}

		// Apply pagination
		if filter.Limit > 0 {
			query = query.Limit(filter.Limit)
		} else {
			query = query.Limit(100) // Default limit
		}

		if filter.Offset > 0 {
			query = query.Offset(filter.Offset)
		}
	} else {
		query = query.Limit(100) // Default limit when no filter
	}

	// Order by most recent first
	query = query.Order("started_at_us DESC")

	var sessions []*models.AlertSession
	result := query.Find(&sessions)

	if result.Error != nil {
		hs.logger.Error("Failed to list sessions", zap.Error(result.Error))
		return nil, fmt.Errorf("failed to list sessions: %w", result.Error)
	}

	return sessions, nil
}

// ListActiveSessions returns all currently active sessions
func (hs *HistoryService) ListActiveSessions(ctx context.Context) ([]*models.AlertSession, error) {
	filter := &HistoryFilter{
		Limit: 100,
	}

	// Get pending and in-progress sessions
	var sessions []*models.AlertSession
	result := hs.db.WithContext(ctx).
		Where("status IN ?", []string{
			string(models.AlertSessionStatusPending),
			string(models.AlertSessionStatusInProgress),
		}).
		Order("started_at_us DESC").
		Limit(filter.Limit).
		Find(&sessions)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to list active sessions: %w", result.Error)
	}

	return sessions, nil
}

// CreateStageExecution creates a new stage execution record
func (hs *HistoryService) CreateStageExecution(ctx context.Context, execution *models.StageExecution) error {
	result := hs.db.WithContext(ctx).Create(execution)
	if result.Error != nil {
		hs.logger.Error("Failed to create stage execution",
			zap.Error(result.Error),
			zap.String("execution_id", execution.ExecutionID),
		)
		return fmt.Errorf("failed to create stage execution: %w", result.Error)
	}

	return nil
}

// UpdateStageExecution updates an existing stage execution
func (hs *HistoryService) UpdateStageExecution(ctx context.Context, execution *models.StageExecution) error {
	result := hs.db.WithContext(ctx).Save(execution)
	if result.Error != nil {
		hs.logger.Error("Failed to update stage execution",
			zap.Error(result.Error),
			zap.String("execution_id", execution.ExecutionID),
		)
		return fmt.Errorf("failed to update stage execution: %w", result.Error)
	}

	return nil
}

// GetSessionSummary returns a summary of a session
func (hs *HistoryService) GetSessionSummary(ctx context.Context, sessionID string) (*SessionSummary, error) {
	session, err := hs.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	summary := &SessionSummary{
		SessionID:       session.SessionID,
		AlertType:       models.SafeStringValue(session.AlertType),
		Status:          string(session.Status),
		TotalStages:     len(session.StageExecutions),
		CompletedStages: 0,
		StartedAt:       time.UnixMicro(session.StartedAtUs),
		ErrorMessage:    session.ErrorMessage,
	}

	// Count completed stages
	for _, stage := range session.StageExecutions {
		if stage.IsCompleted() {
			summary.CompletedStages++
		}
	}

	// Set completion time and duration
	if session.CompletedAtUs != nil {
		completedAt := time.UnixMicro(*session.CompletedAtUs)
		summary.CompletedAt = &completedAt

		duration := *session.CompletedAtUs - session.StartedAtUs
		durationMs := duration / 1000
		summary.DurationMs = &durationMs
	}

	return summary, nil
}

// GetSessionTimeline returns a chronological timeline of session events
func (hs *HistoryService) GetSessionTimeline(ctx context.Context, sessionID string) ([]TimelineEvent, error) {
	session, err := hs.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	var timeline []TimelineEvent

	// Add session start event
	timeline = append(timeline, TimelineEvent{
		Timestamp:   time.UnixMicro(session.StartedAtUs),
		EventType:   "session_started",
		Description: fmt.Sprintf("Alert processing started for type: %s", models.SafeStringValue(session.AlertType)),
		Details: map[string]interface{}{
			"session_id": session.SessionID,
			"alert_type": models.SafeStringValue(session.AlertType),
			"agent_type": session.AgentType,
		},
	})

	// Add stage execution events
	for _, stage := range session.StageExecutions {
		if stage.StartedAtUs != nil {
			timeline = append(timeline, TimelineEvent{
				Timestamp:   time.UnixMicro(*stage.StartedAtUs),
				EventType:   "stage_started",
				Description: fmt.Sprintf("Started stage: %s", stage.StageName),
				Details: map[string]interface{}{
					"stage_id":    stage.StageID,
					"stage_name":  stage.StageName,
					"agent":       stage.Agent,
					"stage_index": stage.StageIndex,
				},
			})
		}

		if stage.CompletedAtUs != nil {
			eventType := "stage_completed"
			if stage.IsFailed() {
				eventType = "stage_failed"
			}

			timeline = append(timeline, TimelineEvent{
				Timestamp:   time.UnixMicro(*stage.CompletedAtUs),
				EventType:   eventType,
				Description: fmt.Sprintf("Completed stage: %s", stage.StageName),
				Details: map[string]interface{}{
					"stage_id":      stage.StageID,
					"stage_name":    stage.StageName,
					"status":        stage.Status,
					"duration_ms":   stage.DurationMs,
					"error_message": stage.ErrorMessage,
				},
			})
		}
	}

	// Add session completion event
	if session.CompletedAtUs != nil {
		eventType := "session_completed"
		if session.Status == string(models.AlertSessionStatusFailed) {
			eventType = "session_failed"
		}

		timeline = append(timeline, TimelineEvent{
			Timestamp:   time.UnixMicro(*session.CompletedAtUs),
			EventType:   eventType,
			Description: fmt.Sprintf("Session %s", eventType),
			Details: map[string]interface{}{
				"status":        string(session.Status),
				"error_message": session.ErrorMessage,
				"final_analysis": session.FinalAnalysis,
			},
		})
	}

	return timeline, nil
}

// TimelineEvent represents a single event in the session timeline
type TimelineEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// GetHistoryStats returns statistics about the history database
func (hs *HistoryService) GetHistoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count total sessions
	var totalSessions int64
	if err := hs.db.WithContext(ctx).Model(&models.AlertSession{}).Count(&totalSessions).Error; err != nil {
		return nil, fmt.Errorf("failed to count sessions: %w", err)
	}
	stats["total_sessions"] = totalSessions

	// Count sessions by status
	var statusCounts []struct {
		Status string
		Count  int64
	}
	if err := hs.db.WithContext(ctx).
		Model(&models.AlertSession{}).
		Select("status, count(*) as count").
		Group("status").
		Scan(&statusCounts).Error; err != nil {
		return nil, fmt.Errorf("failed to count by status: %w", err)
	}

	statusMap := make(map[string]int64)
	for _, sc := range statusCounts {
		statusMap[sc.Status] = sc.Count
	}
	stats["sessions_by_status"] = statusMap

	// Count total stage executions
	var totalStages int64
	if err := hs.db.WithContext(ctx).Model(&models.StageExecution{}).Count(&totalStages).Error; err != nil {
		return nil, fmt.Errorf("failed to count stages: %w", err)
	}
	stats["total_stages"] = totalStages

	return stats, nil
}

// CleanupOldSessions removes old sessions based on retention policy
func (hs *HistoryService) CleanupOldSessions(ctx context.Context, retentionDays int) error {
	cutoffTime := time.Now().AddDate(0, 0, -retentionDays).UnixMicro()

	result := hs.db.WithContext(ctx).
		Where("started_at_us < ? AND status IN ?", cutoffTime, []string{
			string(models.AlertSessionStatusCompleted),
			string(models.AlertSessionStatusFailed),
		}).
		Delete(&models.AlertSession{})

	if result.Error != nil {
		return fmt.Errorf("failed to cleanup old sessions: %w", result.Error)
	}

	hs.logger.Info("Cleaned up old sessions",
		zap.Int64("deleted_count", result.RowsAffected),
		zap.Int("retention_days", retentionDays),
	)

	return nil
}

// Timeline Interaction Methods

// CreateTimelineInteraction creates a new timeline interaction
func (hs *HistoryService) CreateTimelineInteraction(ctx context.Context, interaction *models.TimelineInteraction) error {
	err := hs.db.CreateTimelineInteraction(interaction)
	if err != nil {
		hs.logger.Error("Failed to create timeline interaction",
			zap.Error(err),
			zap.String("session_id", interaction.SessionID),
			zap.String("type", interaction.Type),
		)
		return fmt.Errorf("failed to create timeline interaction: %w", err)
	}

	hs.logger.Debug("Created timeline interaction",
		zap.String("session_id", interaction.SessionID),
		zap.String("type", interaction.Type),
		zap.String("source", interaction.Source),
	)

	return nil
}

// CreateTimelineInteractionsBatch creates multiple timeline interactions in a batch
func (hs *HistoryService) CreateTimelineInteractionsBatch(ctx context.Context, interactions []*models.TimelineInteraction) error {
	if len(interactions) == 0 {
		return nil
	}

	err := hs.db.CreateTimelineInteractionsBatch(interactions)
	if err != nil {
		hs.logger.Error("Failed to create timeline interactions batch",
			zap.Error(err),
			zap.Int("count", len(interactions)),
		)
		return fmt.Errorf("failed to create timeline interactions batch: %w", err)
	}

	hs.logger.Debug("Created timeline interactions batch",
		zap.Int("count", len(interactions)),
	)

	return nil
}

// GetTimelineInteractions retrieves timeline interactions for a session
func (hs *HistoryService) GetTimelineInteractions(ctx context.Context, sessionID string, limit, offset int) ([]*models.TimelineInteraction, error) {
	interactions, err := hs.db.GetTimelineInteractions(sessionID, limit, offset)
	if err != nil {
		hs.logger.Error("Failed to get timeline interactions",
			zap.Error(err),
			zap.String("session_id", sessionID),
		)
		return nil, fmt.Errorf("failed to get timeline interactions: %w", err)
	}

	return interactions, nil
}

// GetTimelineInteractionsByType retrieves timeline interactions by type
func (hs *HistoryService) GetTimelineInteractionsByType(ctx context.Context, sessionID, interactionType string) ([]*models.TimelineInteraction, error) {
	interactions, err := hs.db.GetTimelineInteractionsByType(sessionID, interactionType)
	if err != nil {
		hs.logger.Error("Failed to get timeline interactions by type",
			zap.Error(err),
			zap.String("session_id", sessionID),
			zap.String("type", interactionType),
		)
		return nil, fmt.Errorf("failed to get timeline interactions by type: %w", err)
	}

	return interactions, nil
}

// GetTimelineInteractionCount returns the count of timeline interactions for a session
func (hs *HistoryService) GetTimelineInteractionCount(ctx context.Context, sessionID string) (int64, error) {
	count, err := hs.db.GetTimelineInteractionCount(sessionID)
	if err != nil {
		hs.logger.Error("Failed to get timeline interaction count",
			zap.Error(err),
			zap.String("session_id", sessionID),
		)
		return 0, fmt.Errorf("failed to get timeline interaction count: %w", err)
	}

	return count, nil
}

// Enhanced Summary Methods

// GetEnhancedSessionSummary returns detailed session summary with token usage and timeline stats
func (hs *HistoryService) GetEnhancedSessionSummary(ctx context.Context, sessionID string) (*models.SessionSummary, error) {
	summary, err := hs.db.GetSessionSummary(sessionID)
	if err != nil {
		hs.logger.Error("Failed to get enhanced session summary",
			zap.Error(err),
			zap.String("session_id", sessionID),
		)
		return nil, fmt.Errorf("failed to get enhanced session summary: %w", err)
	}

	return summary, nil
}

// GetActiveSessions returns all currently active sessions using database layer
func (hs *HistoryService) GetActiveSessionsEnhanced(ctx context.Context) ([]*models.AlertSession, error) {
	sessions, err := hs.db.GetActiveSessions()
	if err != nil {
		hs.logger.Error("Failed to get active sessions",
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}

	return sessions, nil
}

// GetSessionsEnhanced retrieves sessions with enhanced filtering using database layer
func (hs *HistoryService) GetSessionsEnhanced(ctx context.Context, limit, offset int, statuses []models.AlertSessionStatus) ([]*models.AlertSession, error) {
	sessions, err := hs.db.GetSessions(limit, offset, statuses)
	if err != nil {
		hs.logger.Error("Failed to get sessions",
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to get sessions: %w", err)
	}

	return sessions, nil
}

// GetSessionCount returns total session count with optional status filter
func (hs *HistoryService) GetSessionCount(ctx context.Context, statuses []models.AlertSessionStatus) (int64, error) {
	count, err := hs.db.GetSessionCount(statuses)
	if err != nil {
		hs.logger.Error("Failed to get session count",
			zap.Error(err),
		)
		return 0, fmt.Errorf("failed to get session count: %w", err)
	}

	return count, nil
}

// LLM and MCP Interaction Logging

// LogLLMInteraction logs an LLM request/response interaction
func (hs *HistoryService) LogLLMInteraction(ctx context.Context, sessionID, source, target string, request, response interface{}, inputTokens, outputTokens int, cost *float64) error {
	interaction := &models.TimelineInteraction{
		SessionID:    sessionID,
		Type:         models.InteractionTypeLLMRequest,
		Source:       source,
		Target:       target,
		TimestampUs:  models.GetCurrentTimestampUs(),
		Content:      models.JSONFromInterface(map[string]interface{}{
			"request":  request,
			"response": response,
		}),
		Status: models.InteractionStatusCompleted,
	}

	// Set token usage
	if inputTokens > 0 || outputTokens > 0 {
		interaction.SetTokenUsage(inputTokens, outputTokens)
	}

	// Set cost if provided
	if cost != nil {
		interaction.EstimatedCost = cost
	}

	return hs.CreateTimelineInteraction(ctx, interaction)
}

// LogMCPInteraction logs an MCP tool call interaction
func (hs *HistoryService) LogMCPInteraction(ctx context.Context, sessionID, source, target, tool string, request, response interface{}) error {
	interaction := &models.TimelineInteraction{
		SessionID:    sessionID,
		Type:         models.InteractionTypeMCPCall,
		Source:       source,
		Target:       target,
		TimestampUs:  models.GetCurrentTimestampUs(),
		Content:      models.JSONFromInterface(map[string]interface{}{
			"tool":     tool,
			"request":  request,
			"response": response,
		}),
		Status: models.InteractionStatusCompleted,
	}

	return hs.CreateTimelineInteraction(ctx, interaction)
}

// LogIterationStep logs a ReAct iteration step
func (hs *HistoryService) LogIterationStep(ctx context.Context, sessionID, agentType string, iterationIndex int, step, content string) error {
	interaction := &models.TimelineInteraction{
		SessionID:      sessionID,
		Type:           models.InteractionTypeIteration,
		Source:         agentType,
		TimestampUs:    models.GetCurrentTimestampUs(),
		Content:        models.JSONFromInterface(map[string]interface{}{
			"step":    step,
			"content": content,
		}),
		IterationIndex: &iterationIndex,
		Status:         models.InteractionStatusCompleted,
	}

	return hs.CreateTimelineInteraction(ctx, interaction)
}

// LogStageEvent logs a stage start/complete/failure event
func (hs *HistoryService) LogStageEvent(ctx context.Context, sessionID, stageExecutionID, eventType string, stageData interface{}) error {
	interactionType := models.InteractionTypeStageStart
	if eventType == "completed" {
		interactionType = models.InteractionTypeStageComplete
	}

	interaction := &models.TimelineInteraction{
		SessionID:        sessionID,
		Type:             interactionType,
		Source:           "stage_controller",
		TimestampUs:      models.GetCurrentTimestampUs(),
		Content:          models.JSONFromInterface(stageData),
		StageExecutionID: &stageExecutionID,
		Status:           models.InteractionStatusCompleted,
	}

	return hs.CreateTimelineInteraction(ctx, interaction)
}

// LogSystemEvent logs a general system event
func (hs *HistoryService) LogSystemEvent(ctx context.Context, sessionID, eventType, description string, data interface{}) error {
	interaction := &models.TimelineInteraction{
		SessionID:   sessionID,
		Type:        models.InteractionTypeSystemEvent,
		Source:      "system",
		TimestampUs: models.GetCurrentTimestampUs(),
		Content:     models.JSONFromInterface(map[string]interface{}{
			"event_type":  eventType,
			"description": description,
			"data":        data,
		}),
		Status: models.InteractionStatusCompleted,
	}

	return hs.CreateTimelineInteraction(ctx, interaction)
}

// Data Retention and Cleanup

// CleanupOldSessionsEnhanced removes old sessions using enhanced database layer
func (hs *HistoryService) CleanupOldSessionsEnhanced(ctx context.Context, retentionDays int) (int64, error) {
	deleted, err := hs.db.CleanupOldSessions(retentionDays)
	if err != nil {
		hs.logger.Error("Failed to cleanup old sessions",
			zap.Error(err),
			zap.Int("retention_days", retentionDays),
		)
		return 0, fmt.Errorf("failed to cleanup old sessions: %w", err)
	}

	hs.logger.Info("Cleaned up old sessions",
		zap.Int64("deleted_count", deleted),
		zap.Int("retention_days", retentionDays),
	)

	return deleted, nil
}

// GetTokenUsageStatistics returns detailed token usage statistics for a session
func (hs *HistoryService) GetTokenUsageStatistics(ctx context.Context, sessionID string) (*models.TokenUsageStatistics, error) {
	interactions, err := hs.GetTimelineInteractionsByType(ctx, sessionID, models.InteractionTypeLLMRequest)
	if err != nil {
		return nil, err
	}

	stats := &models.TokenUsageStatistics{
		SessionID:     sessionID,
		ByProvider:    make(map[string]models.TokenBreakdown),
		ByInteraction: make(map[string]models.TokenBreakdown),
		ByStage:       make(map[string]models.TokenBreakdown),
	}

	for _, interaction := range interactions {
		if interaction.TotalTokens != nil {
			stats.TotalTokens += *interaction.TotalTokens
		}
		if interaction.InputTokens != nil {
			stats.InputTokens += *interaction.InputTokens
		}
		if interaction.OutputTokens != nil {
			stats.OutputTokens += *interaction.OutputTokens
		}
		if interaction.EstimatedCost != nil {
			stats.EstimatedCost += *interaction.EstimatedCost
		}

		// Group by provider (target)
		if breakdown, exists := stats.ByProvider[interaction.Target]; exists {
			breakdown.Count++
			if interaction.InputTokens != nil {
				breakdown.InputTokens += *interaction.InputTokens
			}
			if interaction.OutputTokens != nil {
				breakdown.OutputTokens += *interaction.OutputTokens
			}
			if interaction.TotalTokens != nil {
				breakdown.TotalTokens += *interaction.TotalTokens
			}
			if interaction.EstimatedCost != nil {
				breakdown.Cost += *interaction.EstimatedCost
			}
			stats.ByProvider[interaction.Target] = breakdown
		} else {
			breakdown := models.TokenBreakdown{Count: 1}
			if interaction.InputTokens != nil {
				breakdown.InputTokens = *interaction.InputTokens
			}
			if interaction.OutputTokens != nil {
				breakdown.OutputTokens = *interaction.OutputTokens
			}
			if interaction.TotalTokens != nil {
				breakdown.TotalTokens = *interaction.TotalTokens
			}
			if interaction.EstimatedCost != nil {
				breakdown.Cost = *interaction.EstimatedCost
			}
			stats.ByProvider[interaction.Target] = breakdown
		}
	}

	return stats, nil
}

// ValidateSessionExists checks if a session exists before operations
func (hs *HistoryService) ValidateSessionExists(ctx context.Context, sessionID string) error {
	_, err := hs.GetSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("session validation failed: %w", err)
	}
	return nil
}