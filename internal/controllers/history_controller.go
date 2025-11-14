package controllers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/services"
)

// HistoryController handles history and session management endpoints
// Equivalent to Python's HistoryController with session tracking
type HistoryController struct {
	historyService *services.HistoryService
	logger         *zap.Logger
}

// NewHistoryController creates a new history controller
func NewHistoryController(historyService *services.HistoryService, logger *zap.Logger) *HistoryController {
	return &HistoryController{
		historyService: historyService,
		logger:         logger,
	}
}

// ListSessions handles GET /api/v1/history/sessions
func (hc *HistoryController) ListSessions(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Parse query parameters for filtering
	filter := hc.parseFilterParams(c)

	sessions, err := hc.historyService.ListSessions(ctx, filter)
	if err != nil {
		hc.logger.Error("Failed to list sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to list sessions",
			"details": err.Error(),
		})
		return
	}

	// Convert sessions to response format
	sessionList := make([]map[string]interface{}, len(sessions))
	for i, session := range sessions {
		sessionData := map[string]interface{}{
			"session_id":          session.SessionID,
			"alert_id":            session.AlertID,
			"alert_type":          session.AlertType,
			"agent_type":          session.AgentType,
			"status":              string(session.Status),
			"started_at":          time.UnixMicro(session.StartedAtUs),
			"current_stage_index": session.CurrentStageIndex,
			"current_stage_id":    session.CurrentStageID,
			"chain_id":            session.ChainID,
		}

		if session.CompletedAtUs != nil {
			sessionData["completed_at"] = time.UnixMicro(*session.CompletedAtUs)
			sessionData["duration_ms"] = (*session.CompletedAtUs - session.StartedAtUs) / 1000
		}

		if session.ErrorMessage != nil {
			sessionData["error_message"] = *session.ErrorMessage
		}

		sessionList[i] = sessionData
	}

	response := gin.H{
		"sessions": sessionList,
		"count":    len(sessionList),
		"filter":   filter,
	}

	c.JSON(http.StatusOK, response)
}

// GetSession handles GET /api/v1/history/sessions/{session_id}
func (hc *HistoryController) GetSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Session ID is required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	session, err := hc.historyService.GetSession(ctx, sessionID)
	if err != nil {
		hc.logger.Error("Failed to get session", zap.Error(err), zap.String("session_id", sessionID))
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Session not found",
			"details": err.Error(),
		})
		return
	}

	// Convert session to detailed response format
	sessionData := map[string]interface{}{
		"session_id":           session.SessionID,
		"alert_id":             session.AlertID,
		"alert_type":           session.AlertType,
		"agent_type":           session.AgentType,
		"status":               string(session.Status),
		"started_at":           time.UnixMicro(session.StartedAtUs),
		"current_stage_index":  session.CurrentStageIndex,
		"current_stage_id":     session.CurrentStageID,
		"chain_id":             session.ChainID,
		"alert_data":           session.AlertData,
		"chain_definition":     session.ChainDefinition,
		"session_metadata":     session.SessionMetadata,
		"final_analysis":       session.FinalAnalysis,
		"error_message":        session.ErrorMessage,
	}

	if session.CompletedAtUs != nil {
		sessionData["completed_at"] = time.UnixMicro(*session.CompletedAtUs)
		sessionData["duration_ms"] = (*session.CompletedAtUs - session.StartedAtUs) / 1000
	}

	// Include stage executions
	stageExecutions := make([]map[string]interface{}, len(session.StageExecutions))
	for i, stage := range session.StageExecutions {
		stageData := map[string]interface{}{
			"execution_id": stage.ExecutionID,
			"stage_id":     stage.StageID,
			"stage_index":  stage.StageIndex,
			"stage_name":   stage.StageName,
			"agent":        stage.Agent,
			"status":       stage.Status,
			"stage_output": stage.StageOutput,
		}

		if stage.StartedAtUs != nil {
			stageData["started_at"] = time.UnixMicro(*stage.StartedAtUs)
		}

		if stage.CompletedAtUs != nil {
			stageData["completed_at"] = time.UnixMicro(*stage.CompletedAtUs)
		}

		if stage.DurationMs != nil {
			stageData["duration_ms"] = *stage.DurationMs
		}

		if stage.ErrorMessage != nil {
			stageData["error_message"] = *stage.ErrorMessage
		}

		stageExecutions[i] = stageData
	}

	sessionData["stage_executions"] = stageExecutions

	c.JSON(http.StatusOK, sessionData)
}

// GetSessionSummary handles GET /api/v1/history/sessions/{session_id}/summary
func (hc *HistoryController) GetSessionSummary(c *gin.Context) {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Session ID is required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	summary, err := hc.historyService.GetSessionSummary(ctx, sessionID)
	if err != nil {
		hc.logger.Error("Failed to get session summary", zap.Error(err), zap.String("session_id", sessionID))
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Session not found",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// GetSessionTimeline handles GET /api/v1/history/sessions/{session_id}/timeline
func (hc *HistoryController) GetSessionTimeline(c *gin.Context) {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Session ID is required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	timeline, err := hc.historyService.GetSessionTimeline(ctx, sessionID)
	if err != nil {
		hc.logger.Error("Failed to get session timeline", zap.Error(err), zap.String("session_id", sessionID))
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Session not found",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session_id": sessionID,
		"timeline":   timeline,
		"count":      len(timeline),
	})
}

// GetHistoryStats handles GET /api/v1/history/stats
func (hc *HistoryController) GetHistoryStats(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	stats, err := hc.historyService.GetHistoryStats(ctx)
	if err != nil {
		hc.logger.Error("Failed to get history stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get history statistics",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetFilterOptions handles GET /api/v1/history/filter-options
func (hc *HistoryController) GetFilterOptions(c *gin.Context) {
	// Return available filter options for the frontend
	filterOptions := gin.H{
		"alert_types": []string{"kubernetes", "container", "general"},
		"statuses": []string{
			"pending",
			"in_progress",
			"completed",
			"failed",
		},
		"agent_types": []string{"kubernetes", "base", "general"},
		"time_ranges": gin.H{
			"last_hour":   "Last Hour",
			"last_day":    "Last Day",
			"last_week":   "Last Week",
			"last_month":  "Last Month",
			"custom":      "Custom Range",
		},
	}

	c.JSON(http.StatusOK, filterOptions)
}

// CleanupHistory handles POST /api/v1/history/cleanup
func (hc *HistoryController) CleanupHistory(c *gin.Context) {
	var request struct {
		RetentionDays int `json:"retention_days" binding:"required,min=1,max=365"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request",
			"details": err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	err := hc.historyService.CleanupOldSessions(ctx, request.RetentionDays)
	if err != nil {
		hc.logger.Error("Failed to cleanup history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to cleanup history",
			"details": err.Error(),
		})
		return
	}

	hc.logger.Info("History cleanup completed", zap.Int("retention_days", request.RetentionDays))

	c.JSON(http.StatusOK, gin.H{
		"message":        "History cleanup completed",
		"retention_days": request.RetentionDays,
	})
}

// parseFilterParams parses query parameters into HistoryFilter
func (hc *HistoryController) parseFilterParams(c *gin.Context) *services.HistoryFilter {
	filter := &services.HistoryFilter{}

	// Parse alert_type
	if alertType := c.Query("alert_type"); alertType != "" {
		filter.AlertType = &alertType
	}

	// Parse status
	if status := c.Query("status"); status != "" {
		filter.Status = &status
	}

	// Parse agent_type
	if agentType := c.Query("agent_type"); agentType != "" {
		filter.AgentType = &agentType
	}

	// Parse time range
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filter.StartTime = &startTime
		}
	}

	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if endTime, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filter.EndTime = &endTime
		}
	}

	// Handle predefined time ranges
	if timeRange := c.Query("time_range"); timeRange != "" {
		now := time.Now()
		switch timeRange {
		case "last_hour":
			startTime := now.Add(-1 * time.Hour)
			filter.StartTime = &startTime
		case "last_day":
			startTime := now.Add(-24 * time.Hour)
			filter.StartTime = &startTime
		case "last_week":
			startTime := now.Add(-7 * 24 * time.Hour)
			filter.StartTime = &startTime
		case "last_month":
			startTime := now.Add(-30 * 24 * time.Hour)
			filter.StartTime = &startTime
		}
	}

	// Parse pagination
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 1000 {
			filter.Limit = limit
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	// Default limit if not specified
	if filter.Limit == 0 {
		filter.Limit = 50
	}

	return filter
}