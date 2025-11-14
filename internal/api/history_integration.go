package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/services"
)

// HistoryIntegration provides methods to integrate the existing HistoryService
// with dashboard-compatible API endpoints
type HistoryIntegration struct {
	historyService *services.HistoryService
}

// NewHistoryIntegration creates a new history integration instance
func NewHistoryIntegration(historyService *services.HistoryService) *HistoryIntegration {
	return &HistoryIntegration{
		historyService: historyService,
	}
}

// GetDashboardSessions retrieves sessions in dashboard-compatible format
func (hi *HistoryIntegration) GetDashboardSessions(ctx context.Context, statuses []string, agentType, alertType, search string, startDate, endDate *time.Time, page, pageSize int) ([]DashboardSession, int, error) {
	// Convert dashboard parameters to HistoryService format
	filter := &services.HistoryFilter{
		Limit:  pageSize,
		Offset: (page - 1) * pageSize,
	}

	if agentType != "" {
		filter.AgentType = &agentType
	}
	if alertType != "" {
		filter.AlertType = &alertType
	}
	if startDate != nil {
		filter.StartTime = startDate
	}
	if endDate != nil {
		filter.EndTime = endDate
	}

	// Get sessions from HistoryService
	sessions, err := hi.historyService.ListSessions(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list sessions: %w", err)
	}

	// Convert to dashboard format
	var dashboardSessions []DashboardSession
	for _, session := range sessions {
		dashSession := hi.convertToDashboardSession(session)

		// Apply status filter
		if len(statuses) > 0 && !containsString(statuses, dashSession.Status) {
			continue
		}

		// Apply search filter
		if search != "" {
			searchLower := strings.ToLower(search)
			if !strings.Contains(strings.ToLower(dashSession.AlertType), searchLower) &&
			   !strings.Contains(strings.ToLower(dashSession.AgentType), searchLower) &&
			   (dashSession.ErrorMessage == nil || !strings.Contains(strings.ToLower(*dashSession.ErrorMessage), searchLower)) {
				continue
			}
		}

		dashboardSessions = append(dashboardSessions, dashSession)
	}

	// Get total count for pagination
	totalCount := len(dashboardSessions)

	// Sort by started_at descending (most recent first)
	sort.Slice(dashboardSessions, func(i, j int) bool {
		return dashboardSessions[i].StartedAt.After(dashboardSessions[j].StartedAt)
	})

	return dashboardSessions, totalCount, nil
}

// GetDashboardActiveSessions retrieves active sessions in dashboard format
func (hi *HistoryIntegration) GetDashboardActiveSessions(ctx context.Context) ([]DashboardSession, error) {
	sessions, err := hi.historyService.ListActiveSessions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list active sessions: %w", err)
	}

	var dashboardSessions []DashboardSession
	for _, session := range sessions {
		dashboardSessions = append(dashboardSessions, hi.convertToDashboardSession(session))
	}

	// Sort by started_at descending
	sort.Slice(dashboardSessions, func(i, j int) bool {
		return dashboardSessions[i].StartedAt.After(dashboardSessions[j].StartedAt)
	})

	return dashboardSessions, nil
}

// GetDashboardSessionDetail retrieves detailed session information
func (hi *HistoryIntegration) GetDashboardSessionDetail(ctx context.Context, sessionID string) (*DashboardDetailedSession, error) {
	session, err := hi.historyService.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Convert basic session
	dashSession := hi.convertToDashboardSession(session)

	// Convert alert data
	var alertData map[string]interface{}
	if session.AlertData != nil {
		if err := json.Unmarshal([]byte(session.AlertData), &alertData); err != nil {
			// If unmarshal fails, create a basic structure
			alertData = map[string]interface{}{
				"raw_data": string(session.AlertData),
			}
		}
	} else {
		alertData = make(map[string]interface{})
	}

	// Convert stage executions
	var stages []DashboardStage
	for _, stageExec := range session.StageExecutions {
		stage := DashboardStage{
			StageID:           stageExec.StageID,
			StageName:         stageExec.StageName,
			Status:            string(stageExec.Status),
			TotalInteractions: 0, // Default value, can be enhanced later
		}

		// Handle started timestamp
		if stageExec.StartedAtUs != nil {
			stage.StartedAt = time.UnixMicro(*stageExec.StartedAtUs)
		} else {
			// Use a default time if not set
			stage.StartedAt = time.Now()
		}

		// Handle completed timestamp
		if stageExec.CompletedAtUs != nil {
			completedAt := time.UnixMicro(*stageExec.CompletedAtUs)
			stage.CompletedAt = &completedAt
		}

		// Handle duration
		if stageExec.DurationMs != nil {
			stage.Duration = stageExec.DurationMs
		}

		stages = append(stages, stage)
	}

	detailedSession := &DashboardDetailedSession{
		DashboardSession: dashSession,
		AlertData:        alertData,
		FinalAnalysis:    session.FinalAnalysis,
		Stages:          stages,
	}

	return detailedSession, nil
}

// GetDashboardSessionSummary retrieves session summary information
func (hi *HistoryIntegration) GetDashboardSessionSummary(ctx context.Context, sessionID string) (map[string]interface{}, error) {
	session, err := hi.historyService.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	dashSession := hi.convertToDashboardSession(session)

	summary := map[string]interface{}{
		"session_id":    dashSession.SessionID,
		"alert_type":    dashSession.AlertType,
		"agent_type":    dashSession.AgentType,
		"status":        dashSession.Status,
		"started_at":    dashSession.StartedAt,
		"completed_at":  dashSession.CompletedAt,
		"duration_ms":   dashSession.DurationMs,
		"error_message": dashSession.ErrorMessage,
	}

	return summary, nil
}

// SearchDashboardSessions searches sessions by term
func (hi *HistoryIntegration) SearchDashboardSessions(ctx context.Context, searchTerm string, limit int) ([]DashboardSession, error) {
	// Use a large limit to get all sessions for searching
	filter := &services.HistoryFilter{
		Limit: 1000, // Reasonable upper limit
	}

	sessions, err := hi.historyService.ListSessions(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions for search: %w", err)
	}

	var results []DashboardSession
	searchLower := strings.ToLower(searchTerm)

	for _, session := range sessions {
		dashSession := hi.convertToDashboardSession(session)

		// Search in alert type, agent type, and error message
		if strings.Contains(strings.ToLower(dashSession.AlertType), searchLower) ||
		   strings.Contains(strings.ToLower(dashSession.AgentType), searchLower) ||
		   (dashSession.ErrorMessage != nil && strings.Contains(strings.ToLower(*dashSession.ErrorMessage), searchLower)) {
			results = append(results, dashSession)
			if len(results) >= limit {
				break
			}
		}
	}

	// Sort by started_at descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].StartedAt.After(results[j].StartedAt)
	})

	return results, nil
}

// GetAvailableAlertTypes retrieves available alert types from the database
func (hi *HistoryIntegration) GetAvailableAlertTypes(ctx context.Context) ([]string, error) {
	var alertTypes []string

	// Query distinct alert types from the database using a simple query
	// We'll need to add this method to HistoryService, but for now let's use a workaround
	sessions, err := hi.historyService.ListSessions(ctx, &services.HistoryFilter{Limit: 1000})
	if err != nil {
		return []string{
			"general-alert",
			"k8s-alert",
			"security-alert",
			"network-alert",
			"database-alert",
		}, nil
	}

	// Extract unique alert types
	alertTypeSet := make(map[string]bool)
	for _, session := range sessions {
		if session.AlertType != nil && *session.AlertType != "" {
			alertTypeSet[*session.AlertType] = true
		}
	}

	// Convert map to slice
	for alertType := range alertTypeSet {
		alertTypes = append(alertTypes, alertType)
	}

	// If no alert types found in database, return defaults
	if len(alertTypes) == 0 {
		return []string{
			"general-alert",
			"k8s-alert",
			"security-alert",
			"network-alert",
			"database-alert",
		}, nil
	}

	return alertTypes, nil
}

// convertToDashboardSession converts an AlertSession to DashboardSession format
func (hi *HistoryIntegration) convertToDashboardSession(session *models.AlertSession) DashboardSession {
	dashSession := DashboardSession{
		SessionID: session.SessionID,
		AlertType: models.SafeStringValue(session.AlertType),
		AgentType: session.AgentType,
		Status:    string(session.Status),
		StartedAt: time.UnixMicro(session.StartedAtUs),
	}

	// Convert completed timestamp
	if session.CompletedAtUs != nil {
		completedAt := time.UnixMicro(*session.CompletedAtUs)
		dashSession.CompletedAt = &completedAt

		// Calculate duration in milliseconds
		durationUs := *session.CompletedAtUs - session.StartedAtUs
		durationMs := durationUs / 1000
		dashSession.DurationMs = &durationMs
	}

	// Set error message
	dashSession.ErrorMessage = session.ErrorMessage

	return dashSession
}

// containsString checks if a slice contains a string
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}