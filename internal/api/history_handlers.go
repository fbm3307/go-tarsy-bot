package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/models"
)

// Dashboard-compatible data structures that match Python TARSy-bot exactly

// DashboardSession represents a session in the format expected by the dashboard
type DashboardSession struct {
	SessionID    string     `json:"session_id"`
	AlertType    string     `json:"alert_type"`
	AgentType    string     `json:"agent_type"`
	Status       string     `json:"status"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	DurationMs   *int64     `json:"duration_ms,omitempty"`
	ErrorMessage *string    `json:"error_message,omitempty"`
}

// DashboardDetailedSession represents detailed session data for the dashboard
type DashboardDetailedSession struct {
	DashboardSession
	AlertData     map[string]interface{} `json:"alert_data"`
	FinalAnalysis *string                `json:"final_analysis,omitempty"`
	Stages        []DashboardStage       `json:"stages"`
}

// DashboardStage represents a stage in the format expected by the dashboard
type DashboardStage struct {
	StageID           string     `json:"stage_id"`
	StageName         string     `json:"stage_name"`
	Status            string     `json:"status"`
	StartedAt         time.Time  `json:"started_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	TotalInteractions int        `json:"total_interactions"`
	Duration          *int64     `json:"duration,omitempty"`
}

// DashboardSessionsResponse matches Python backend response format exactly
type DashboardSessionsResponse struct {
	Sessions   []DashboardSession `json:"sessions"`
	TotalCount int                `json:"total_count"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	HasMore    bool               `json:"has_more"`
}

// Frontend-compatible response structures
type FrontendPagination struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalPages int `json:"total_pages"`
	TotalItems int `json:"total_items"`
}

type FrontendSessionsResponse struct {
	Sessions        []DashboardSession     `json:"sessions"`
	Pagination      FrontendPagination     `json:"pagination"`
	FiltersApplied  map[string]interface{} `json:"filters_applied"`
}

// DashboardFilterOptions matches Python backend filter options format
type DashboardFilterOptions struct {
	AgentTypes    []string `json:"agent_types"`
	AlertTypes    []string `json:"alert_types"`
	StatusOptions []string `json:"status_options"`
}

// DashboardSearchResult represents search results for sessions
type DashboardSearchResult struct {
	Sessions   []DashboardSession `json:"sessions"`
	TotalCount int                `json:"total_count"`
	SearchTerm string             `json:"search_term"`
}

// History API Handlers - Dashboard Compatible

// GetHistorySessions handles GET /api/v1/history/sessions
func (h *APIHandlers) GetHistorySessions(w http.ResponseWriter, r *http.Request) {
	_, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Parse query parameters
	query := r.URL.Query()

	// Pagination
	page, _ := strconv.Atoi(query.Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(query.Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 25
	}

	// Filtering parameters
	statuses := query["status"]
	agentType := query.Get("agent_type")
	alertType := query.Get("alert_type")
	search := query.Get("search")

	// Date range (microseconds from frontend)
	var startDate, endDate *time.Time
	if startDateUs := query.Get("start_date_us"); startDateUs != "" {
		if us, err := strconv.ParseInt(startDateUs, 10, 64); err == nil {
			t := time.UnixMicro(us)
			startDate = &t
		}
	}
	if endDateUs := query.Get("end_date_us"); endDateUs != "" {
		if us, err := strconv.ParseInt(endDateUs, 10, 64); err == nil {
			t := time.UnixMicro(us)
			endDate = &t
		}
	}

	h.logger.Debug("Getting history sessions",
		zap.Int("page", page),
		zap.Int("page_size", pageSize),
		zap.Strings("statuses", statuses),
		zap.String("agent_type", agentType),
		zap.String("alert_type", alertType),
		zap.String("search", search))

	// Use real database integration if available, otherwise fallback to mock data
	var sessions []DashboardSession
	var totalCount int
	var err error

	if h.historyIntegration != nil {
		sessions, totalCount, err = h.historyIntegration.GetDashboardSessions(r.Context(), statuses, agentType, alertType, search, startDate, endDate, page, pageSize)
		if err != nil {
			h.logger.Error("Failed to get sessions from database", zap.Error(err))
			h.sendError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to retrieve sessions", nil)
			return
		}
	} else {
		// Fallback to mock data
		allSessions := h.getMockHistorySessions(statuses, agentType, alertType, search, startDate, endDate)
		totalCount = len(allSessions)

		// Apply pagination to mock data
		start := (page - 1) * pageSize
		end := start + pageSize
		if start >= totalCount {
			sessions = []DashboardSession{}
		} else {
			if end > totalCount {
				end = totalCount
			}
			sessions = allSessions[start:end]
		}
	}

	// For database integration, pagination is already handled
	// For mock data, we need to track if we have more results
	if h.historyIntegration == nil {
		// For mock data, check if end was truncated
		allSessionsCount := totalCount
		totalCount = allSessionsCount
	}

	// Calculate total pages
	totalPages := (totalCount + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}

	// Create frontend-compatible response
	response := FrontendSessionsResponse{
		Sessions: sessions,
		Pagination: FrontendPagination{
			Page:       page,
			PageSize:   pageSize,
			TotalPages: totalPages,
			TotalItems: totalCount,
		},
		FiltersApplied: make(map[string]interface{}),
	}

	// Ensure sessions is never null
	if response.Sessions == nil {
		response.Sessions = []DashboardSession{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetHistoryActiveSessions handles GET /api/v1/history/active-sessions
func (h *APIHandlers) GetHistoryActiveSessions(w http.ResponseWriter, r *http.Request) {
	_, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	h.logger.Debug("Getting active sessions")

	// Use real database integration if available, otherwise fallback to mock data
	var activeSessions []DashboardSession
	var err error

	if h.historyIntegration != nil {
		activeSessions, err = h.historyIntegration.GetDashboardActiveSessions(r.Context())
		if err != nil {
			h.logger.Error("Failed to get active sessions from database", zap.Error(err))
			h.sendError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to retrieve active sessions", nil)
			return
		}
	} else {
		// Fallback to mock data
		activeSessions = h.getMockActiveSessions()
	}

	// Ensure we always return an array, never null
	if activeSessions == nil {
		activeSessions = []DashboardSession{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activeSessions)
}

// GetHistorySessionDetail handles GET /api/v1/history/sessions/{id}
func (h *APIHandlers) GetHistorySessionDetail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	if sessionID == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_SESSION_ID", "Session ID is required", nil)
		return
	}

	_, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	h.logger.Debug("Getting session detail", zap.String("session_id", sessionID))

	// Use real database integration if available, otherwise fallback to mock data
	var detailedSession *DashboardDetailedSession
	var err error

	if h.historyIntegration != nil {
		detailedSession, err = h.historyIntegration.GetDashboardSessionDetail(r.Context(), sessionID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				h.sendError(w, http.StatusNotFound, "SESSION_NOT_FOUND", "Session not found", nil)
			} else {
				h.logger.Error("Failed to get session detail from database", zap.Error(err))
				h.sendError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to retrieve session detail", nil)
			}
			return
		}
	} else {
		// Fallback to mock data
		detailedSession = h.getMockDetailedSession(sessionID)
		if detailedSession == nil {
			h.sendError(w, http.StatusNotFound, "SESSION_NOT_FOUND", "Session not found", nil)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(detailedSession)
}

// GetHistorySessionSummary handles GET /api/v1/history/sessions/{id}/summary
func (h *APIHandlers) GetHistorySessionSummary(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	if sessionID == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_SESSION_ID", "Session ID is required", nil)
		return
	}

	_, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	h.logger.Debug("Getting session summary", zap.String("session_id", sessionID))

	// Use real database integration if available, otherwise fallback to mock data
	var summary map[string]interface{}
	var err error

	if h.historyIntegration != nil {
		summary, err = h.historyIntegration.GetDashboardSessionSummary(r.Context(), sessionID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				h.sendError(w, http.StatusNotFound, "SESSION_NOT_FOUND", "Session not found", nil)
			} else {
				h.logger.Error("Failed to get session summary from database", zap.Error(err))
				h.sendError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to retrieve session summary", nil)
			}
			return
		}
	} else {
		// Fallback to mock data
		summary = h.getMockSessionSummary(sessionID)
		if summary == nil {
			h.sendError(w, http.StatusNotFound, "SESSION_NOT_FOUND", "Session not found", nil)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

// GetHistoryHealth handles GET /api/v1/history/health
func (h *APIHandlers) GetHistoryHealth(w http.ResponseWriter, r *http.Request) {
	_, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	health := map[string]interface{}{
		"status":    "healthy",
		"service":   "history",
		"timestamp": time.Now(),
		"version":   "go-1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// GetHistorySearch handles GET /api/v1/history/search
func (h *APIHandlers) GetHistorySearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	searchTerm := query.Get("q")
	limit, _ := strconv.Atoi(query.Get("limit"))

	if len(searchTerm) < 3 {
		h.sendError(w, http.StatusBadRequest, "SEARCH_TERM_TOO_SHORT", "Search term must be at least 3 characters", nil)
		return
	}

	if limit <= 0 || limit > 100 {
		limit = 25
	}

	_, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	h.logger.Debug("Searching sessions", zap.String("search_term", searchTerm), zap.Int("limit", limit))

	// Use real database integration if available, otherwise fallback to mock data
	var results []DashboardSession
	var err error

	if h.historyIntegration != nil {
		results, err = h.historyIntegration.SearchDashboardSessions(r.Context(), searchTerm, limit)
		if err != nil {
			h.logger.Error("Failed to search sessions in database", zap.Error(err))
			h.sendError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to search sessions", nil)
			return
		}
	} else {
		// Fallback to mock data
		results = h.getMockSearchResults(searchTerm, limit)
	}

	response := DashboardSearchResult{
		Sessions:   results,
		TotalCount: len(results),
		SearchTerm: searchTerm,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetHistorySessionInteractions handles GET /api/v1/history/sessions/{id}/interactions
func (h *APIHandlers) GetHistorySessionInteractions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	if sessionID == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_SESSION_ID", "Session ID is required", nil)
		return
	}

	_, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Parse query parameters for pagination
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50 // Default limit
	}
	offset, _ := strconv.Atoi(query.Get("offset"))
	if offset < 0 {
		offset = 0
	}

	h.logger.Debug("Getting session interactions",
		zap.String("session_id", sessionID),
		zap.Int("limit", limit),
		zap.Int("offset", offset))

	// Use real database integration - no fallback to mock data
	if h.historyService == nil {
		h.logger.Error("History service not available")
		h.sendError(w, http.StatusInternalServerError, "SERVICE_UNAVAILABLE", "History service not available", nil)
		return
	}

	// Get timeline interactions directly from history service
	timelineInteractions, err := h.historyService.GetTimelineInteractions(r.Context(), sessionID, limit, offset)
	if err != nil {
		h.logger.Error("Failed to get timeline interactions from database", zap.Error(err))
		h.sendError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to retrieve timeline interactions", nil)
		return
	}

	// Ensure we always return an array, never null
	if timelineInteractions == nil {
		timelineInteractions = []*models.TimelineInteraction{}
	}

	h.logger.Debug("Retrieved timeline interactions",
		zap.String("session_id", sessionID),
		zap.Int("count", len(timelineInteractions)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(timelineInteractions)
}

// GetHistoryFilterOptions handles GET /api/v1/history/filter-options
func (h *APIHandlers) GetHistoryFilterOptions(w http.ResponseWriter, r *http.Request) {
	_, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	h.logger.Debug("Getting filter options")

	// Get filter options (mock data for now)
	options := DashboardFilterOptions{
		AgentTypes:    []string{"general", "kubernetes", "security", "network", "database"},
		AlertTypes:    []string{"general-alert", "k8s-alert", "security-alert", "network-alert", "database-alert"},
		StatusOptions: []string{"pending", "in_progress", "completed", "failed"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// GetSessionIDForAlert handles GET /session-id/{alertId}
func (h *APIHandlers) GetSessionIDForAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["alertId"]

	if alertID == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_ALERT_ID", "Alert ID is required", nil)
		return
	}

	h.logger.Debug("Getting session ID for alert", zap.String("alert_id", alertID))

	// For now, generate a mock session ID
	// TODO: Replace with actual alert-to-session mapping
	sessionID := "session-" + alertID

	response := map[string]interface{}{
		"alert_id":   alertID,
		"session_id": sessionID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetAlertTypes handles GET /alert-types (for dropdown in dashboard)
func (h *APIHandlers) GetAlertTypes(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Getting alert types")

	// Get alert types from various sources
	var alertTypes []string
	var err error

	// Try to get from history integration first (real database data)
	if h.historyIntegration != nil {
		alertTypes, err = h.historyIntegration.GetAvailableAlertTypes(r.Context())
		if err != nil {
			h.logger.Warn("Failed to get alert types from database, trying agent registry", zap.Error(err))
		}
	}

	// Fallback to agent registry if database didn't work
	if len(alertTypes) == 0 && h.agentRegistry != nil {
		alertTypes = h.agentRegistry.GetAvailableAlertTypes()
	}

	// Final fallback to default alert types
	if len(alertTypes) == 0 {
		alertTypes = []string{
			"general-alert",
			"k8s-alert",
			"security-alert",
			"network-alert",
			"database-alert",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alertTypes)
}

// Mock data methods (replace with real database integration)

func (h *APIHandlers) getMockHistorySessions(statuses []string, agentType, alertType, search string, startDate, endDate *time.Time) []DashboardSession {
	now := time.Now()

	allSessions := []DashboardSession{
		{
			SessionID:   "session-001",
			AlertType:   "k8s-alert",
			AgentType:   "kubernetes",
			Status:      "completed",
			StartedAt:   now.Add(-2 * time.Hour),
			CompletedAt: timePtr(now.Add(-2*time.Hour + 15*time.Minute)),
			DurationMs:  int64Ptr(15 * 60 * 1000), // 15 minutes
		},
		{
			SessionID:   "session-002",
			AlertType:   "security-alert",
			AgentType:   "security",
			Status:      "failed",
			StartedAt:   now.Add(-1 * time.Hour),
			CompletedAt: timePtr(now.Add(-1*time.Hour + 5*time.Minute)),
			DurationMs:  int64Ptr(5 * 60 * 1000), // 5 minutes
			ErrorMessage: stringPtr("Authentication failed"),
		},
		{
			SessionID: "session-003",
			AlertType: "general-alert",
			AgentType: "general",
			Status:    "in_progress",
			StartedAt: now.Add(-30 * time.Minute),
		},
		{
			SessionID: "session-004",
			AlertType: "network-alert",
			AgentType: "network",
			Status:    "pending",
			StartedAt: now.Add(-10 * time.Minute),
		},
	}

	// Apply filters
	var filtered []DashboardSession
	for _, session := range allSessions {
		// Status filter
		if len(statuses) > 0 && !contains(statuses, session.Status) {
			continue
		}

		// Agent type filter
		if agentType != "" && session.AgentType != agentType {
			continue
		}

		// Alert type filter
		if alertType != "" && session.AlertType != alertType {
			continue
		}

		// Search filter
		if search != "" {
			searchLower := strings.ToLower(search)
			if !strings.Contains(strings.ToLower(session.AlertType), searchLower) &&
			   !strings.Contains(strings.ToLower(session.AgentType), searchLower) {
				continue
			}
		}

		// Date range filter
		if startDate != nil && session.StartedAt.Before(*startDate) {
			continue
		}
		if endDate != nil && session.StartedAt.After(*endDate) {
			continue
		}

		filtered = append(filtered, session)
	}

	return filtered
}

func (h *APIHandlers) getMockActiveSessions() []DashboardSession {
	now := time.Now()

	return []DashboardSession{
		{
			SessionID: "session-003",
			AlertType: "general-alert",
			AgentType: "general",
			Status:    "in_progress",
			StartedAt: now.Add(-30 * time.Minute),
		},
		{
			SessionID: "session-004",
			AlertType: "network-alert",
			AgentType: "network",
			Status:    "pending",
			StartedAt: now.Add(-10 * time.Minute),
		},
	}
}

func (h *APIHandlers) getMockDetailedSession(sessionID string) *DashboardDetailedSession {
	session := h.findMockSession(sessionID)
	if session == nil {
		return nil
	}

	return &DashboardDetailedSession{
		DashboardSession: *session,
		AlertData: map[string]interface{}{
			"pod_name":   "api-server-abc123",
			"namespace":  "production",
			"error_code": "CrashLoopBackOff",
		},
		FinalAnalysis: stringPtr("Pod is crash looping due to missing configuration. Resolution: Update ConfigMap with required environment variables."),
		Stages: []DashboardStage{
			{
				StageID:           "stage-001",
				StageName:         "Initial Analysis",
				Status:            "completed",
				StartedAt:         session.StartedAt,
				CompletedAt:       timePtr(session.StartedAt.Add(5 * time.Minute)),
				TotalInteractions: 3,
				Duration:          int64Ptr(5 * 60 * 1000),
			},
			{
				StageID:           "stage-002",
				StageName:         "Log Analysis",
				Status:            "completed",
				StartedAt:         session.StartedAt.Add(5 * time.Minute),
				CompletedAt:       timePtr(session.StartedAt.Add(10 * time.Minute)),
				TotalInteractions: 5,
				Duration:          int64Ptr(5 * 60 * 1000),
			},
		},
	}
}

func (h *APIHandlers) getMockSessionSummary(sessionID string) map[string]interface{} {
	session := h.findMockSession(sessionID)
	if session == nil {
		return nil
	}

	return map[string]interface{}{
		"session_id":    session.SessionID,
		"alert_type":    session.AlertType,
		"agent_type":    session.AgentType,
		"status":        session.Status,
		"started_at":    session.StartedAt,
		"completed_at":  session.CompletedAt,
		"duration_ms":   session.DurationMs,
		"error_message": session.ErrorMessage,
	}
}

func (h *APIHandlers) getMockSearchResults(searchTerm string, limit int) []DashboardSession {
	allSessions := h.getMockHistorySessions(nil, "", "", "", nil, nil)

	var results []DashboardSession
	searchLower := strings.ToLower(searchTerm)

	for _, session := range allSessions {
		if strings.Contains(strings.ToLower(session.AlertType), searchLower) ||
		   strings.Contains(strings.ToLower(session.AgentType), searchLower) ||
		   (session.ErrorMessage != nil && strings.Contains(strings.ToLower(*session.ErrorMessage), searchLower)) {
			results = append(results, session)
			if len(results) >= limit {
				break
			}
		}
	}

	return results
}

func (h *APIHandlers) findMockSession(sessionID string) *DashboardSession {
	sessions := h.getMockHistorySessions(nil, "", "", "", nil, nil)
	for _, session := range sessions {
		if session.SessionID == sessionID {
			return &session
		}
	}
	return nil
}

// Helper functions
func timePtr(t time.Time) *time.Time {
	return &t
}

func int64Ptr(i int64) *int64 {
	return &i
}

func stringPtr(s string) *string {
	return &s
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

