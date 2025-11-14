package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/auth"
	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/monitoring"
	"github.com/codeready/go-tarsy-bot/internal/pipeline"
	"github.com/codeready/go-tarsy-bot/internal/services"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// APIHandlers contains all HTTP handlers for the API
type APIHandlers struct {
	agentRegistry    *agents.AgentRegistry
	mcpRegistry      *mcp.MCPServerRegistry
	pipeline         *pipeline.ProcessingPipeline
	healthChecker    *monitoring.HealthChecker
	metricsCollector *monitoring.MetricsCollector
	wsManager        *services.WebSocketManager
	jwtManager       *auth.JWTManager
	inputSanitizer   *auth.InputSanitizer
	historyService   *services.HistoryService
	historyIntegration *HistoryIntegration
	logger           *zap.Logger
}

// NewAPIHandlers creates a new API handlers instance
func NewAPIHandlers(
	agentRegistry *agents.AgentRegistry,
	mcpRegistry *mcp.MCPServerRegistry,
	pipeline *pipeline.ProcessingPipeline,
	healthChecker *monitoring.HealthChecker,
	metricsCollector *monitoring.MetricsCollector,
	wsManager *services.WebSocketManager,
	jwtManager *auth.JWTManager,
	inputSanitizer *auth.InputSanitizer,
	historyService *services.HistoryService,
	logger *zap.Logger,
) *APIHandlers {
	// Create history integration if history service is provided
	var historyIntegration *HistoryIntegration
	if historyService != nil {
		historyIntegration = NewHistoryIntegration(historyService)
	}

	return &APIHandlers{
		agentRegistry:      agentRegistry,
		mcpRegistry:        mcpRegistry,
		pipeline:           pipeline,
		healthChecker:      healthChecker,
		metricsCollector:   metricsCollector,
		wsManager:          wsManager,
		jwtManager:         jwtManager,
		inputSanitizer:     inputSanitizer,
		historyService:     historyService,
		historyIntegration: historyIntegration,
		logger:             logger,
	}
}

// AlertRequest represents an incoming alert processing request (enhanced from Python TARSy)
type AlertRequest struct {
	AlertType string                 `json:"alert_type" validate:"required"`
	Data      map[string]interface{} `json:"data" validate:"required"`
	Runbook   string                 `json:"runbook,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
	Priority  string                 `json:"priority,omitempty"`   // New: high, medium, low
	Tags      []string               `json:"tags,omitempty"`       // New: for categorization
	Metadata  map[string]interface{} `json:"metadata,omitempty"`   // New: additional context
}

// AlertResponse represents the response to an alert processing request (enhanced from Python TARSy)
type AlertResponse struct {
	AlertID     string                 `json:"alert_id"`
	Status      string                 `json:"status"`
	Message     string                 `json:"message"`
	SessionID   string                 `json:"session_id"`
	Agent       string                 `json:"agent,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Priority    string                 `json:"priority,omitempty"`
	EstimatedDuration string           `json:"estimated_duration,omitempty"`
	QueuePosition int                  `json:"queue_position,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertStatusResponse represents detailed alert status information
type AlertStatusResponse struct {
	AlertID        string                 `json:"alert_id"`
	SessionID      string                 `json:"session_id"`
	Status         string                 `json:"status"`
	Agent          string                 `json:"agent,omitempty"`
	Progress       float64                `json:"progress"`       // 0.0 to 1.0
	CurrentStage   string                 `json:"current_stage,omitempty"`
	TotalStages    int                    `json:"total_stages,omitempty"`
	StartTime      *time.Time             `json:"start_time,omitempty"`
	EndTime        *time.Time             `json:"end_time,omitempty"`
	Duration       string                 `json:"duration,omitempty"`
	Result         string                 `json:"result,omitempty"`
	Error          string                 `json:"error,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	LastUpdated    time.Time              `json:"last_updated"`
}

// AlertListResponse represents a paginated list of alerts
type AlertListResponse struct {
	Alerts     []AlertStatusResponse `json:"alerts"`
	Total      int                   `json:"total"`
	Offset     int                   `json:"offset"`
	Limit      int                   `json:"limit"`
	HasMore    bool                  `json:"has_more"`
	Timestamp  time.Time             `json:"timestamp"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Code    string                 `json:"code,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status      string                 `json:"status"`
	Timestamp   time.Time              `json:"timestamp"`
	Components  map[string]interface{} `json:"components"`
	Summary     map[string]interface{} `json:"summary"`
}

// MetricsResponse represents a metrics response
type MetricsResponse struct {
	Timestamp time.Time                      `json:"timestamp"`
	System    *monitoring.SystemMetrics      `json:"system"`
	Pipeline  *pipeline.PipelineMetrics      `json:"pipeline,omitempty"`
}

// ProcessAlert handles POST /alerts with comprehensive validation
func (h *APIHandlers) ProcessAlert(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Parse request - check for sanitized data first
	var req AlertRequest
	if sanitizedData, ok := auth.GetSanitizedDataFromContext(r.Context()); ok {
		// Use pre-sanitized data if available
		if dataBytes, err := json.Marshal(sanitizedData); err == nil {
			if err := json.Unmarshal(dataBytes, &req); err != nil {
				h.sendValidationError(w, "INVALID_SANITIZED_DATA", "Failed to process sanitized request data", nil)
				h.recordEndpointMetrics("/alerts", false, time.Since(startTime))
				return
			}
		} else {
			h.sendValidationError(w, "SANITIZATION_ERROR", "Failed to process sanitized data", nil)
			h.recordEndpointMetrics("/alerts", false, time.Since(startTime))
			return
		}
	} else {
		// Parse JSON directly
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.sendValidationError(w, "INVALID_JSON", "Invalid JSON request", map[string]interface{}{
				"error": err.Error(),
				"hint":  "Ensure your request body contains valid JSON",
			})
			h.recordEndpointMetrics("/alerts", false, time.Since(startTime))
			return
		}
	}

	// Comprehensive validation
	validator := NewAlertValidator()
	if h.agentRegistry != nil {
		alertTypes := h.agentRegistry.GetAvailableAlertTypes()
		validator.SetAllowedAlertTypes(alertTypes)
	}

	validationResult := validator.ValidateAlertRequest(&req)
	if !validationResult.Valid {
		h.sendValidationErrors(w, validationResult.Errors)
		h.recordEndpointMetrics("/alerts", false, time.Since(startTime))
		return
	}

	// Parse priority
	priority := h.parsePriority(req.Priority)

	// Generate session ID if not provided
	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("session-%d-%s", time.Now().UnixNano(), req.AlertType)
	}

	// Create enhanced alert model
	alert := &models.Alert{
		AlertType: req.AlertType,
		Data:      req.Data,
		// Note: Add fields to models.Alert if needed for tags, metadata, etc.
	}

	// Check pipeline capacity
	if h.pipeline != nil {
		metrics := h.pipeline.GetMetrics()
		if metrics != nil && metrics.QueueLength >= 100 { // Configurable limit
			h.sendError(w, http.StatusServiceUnavailable, "QUEUE_FULL",
				"Alert processing queue is full. Please try again later.", map[string]interface{}{
					"queue_length":     metrics.QueueLength,
					"max_queue_length": 100,
					"retry_after":      "30s",
				})
			h.recordEndpointMetrics("/alerts", false, time.Since(startTime))
			return
		}
	}

	// Submit to pipeline
	ctx := context.Background()
	job, err := h.pipeline.ProcessAlert(ctx, alert, priority)
	if err != nil {
		h.logger.Error("Failed to submit alert to pipeline",
			zap.Error(err),
			zap.String("alert_type", req.AlertType),
			zap.String("session_id", sessionID))

		h.sendError(w, http.StatusInternalServerError, "SUBMISSION_FAILED",
			"Failed to submit alert for processing", map[string]interface{}{
				"error":      err.Error(),
				"alert_type": req.AlertType,
				"session_id": sessionID,
			})
		h.recordEndpointMetrics("/alerts", false, time.Since(startTime))
		return
	}

	// Get assigned agent info
	agent, err := h.agentRegistry.GetAgentForAlert(alert)
	var agentName string
	if err == nil && agent != nil {
		agentName = agent.GetAgentType()
	}

	// Get queue position and estimated duration
	queuePosition := 0
	estimatedDuration := "unknown"
	if metrics := h.pipeline.GetMetrics(); metrics != nil {
		queuePosition = int(metrics.QueueLength)
		if metrics.AverageProcessingTime > 0 {
			estimatedDuration = fmt.Sprintf("%.0fs", metrics.AverageProcessingTime.Seconds())
		}
	}

	// Create enhanced response
	response := AlertResponse{
		AlertID:           job.ID,
		Status:            "submitted",
		Message:           "Alert submitted for processing",
		SessionID:         sessionID,
		Agent:             agentName,
		Priority:          req.Priority,
		EstimatedDuration: estimatedDuration,
		QueuePosition:     queuePosition,
		Timestamp:         time.Now(),
		Metadata: map[string]interface{}{
			"submitted_by": h.getUserIdentifier(r),
			"request_id":   h.getRequestID(r),
		},
	}

	h.logger.Info("Alert submitted successfully",
		zap.String("job_id", job.ID),
		zap.String("session_id", sessionID),
		zap.String("alert_type", req.AlertType),
		zap.String("agent", agentName),
		zap.String("priority", req.Priority),
		zap.Int("queue_position", queuePosition))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/alerts", true, time.Since(startTime))
}

// ListAlerts handles GET /alerts - list all active alerts for dashboard
func (h *APIHandlers) ListAlerts(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// For now, return empty list since job tracking is not fully implemented
	// TODO: Implement proper active job tracking in pipeline
	alerts := make([]map[string]interface{}, 0)

	response := map[string]interface{}{
		"alerts":    alerts,
		"total":     len(alerts),
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/alerts", true, time.Since(startTime))
}

// GetAlertStatus handles GET /alerts/{alertId} with enhanced status information
func (h *APIHandlers) GetAlertStatus(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	vars := mux.Vars(r)
	alertID := vars["alertId"]

	if alertID == "" {
		h.sendValidationError(w, "MISSING_ALERT_ID", "Alert ID is required", map[string]interface{}{
			"parameter": "alertId",
			"location":  "path",
		})
		h.recordEndpointMetrics("/alerts/{alertId}", false, time.Since(startTime))
		return
	}

	// Validate alert ID format
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(alertID) {
		h.sendValidationError(w, "INVALID_ALERT_ID", "Alert ID contains invalid characters", map[string]interface{}{
			"alert_id": alertID,
			"pattern":  "^[a-zA-Z0-9_-]+$",
		})
		h.recordEndpointMetrics("/alerts/{alertId}", false, time.Since(startTime))
		return
	}

	// Get job status from pipeline
	status, err := h.pipeline.GetJobStatus(alertID)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "ALERT_NOT_FOUND", "Alert not found", map[string]interface{}{
			"alert_id": alertID,
			"error":    err.Error(),
			"hint":     "Check that the alert ID is correct and the alert exists",
		})
		h.recordEndpointMetrics("/alerts/{alertId}", false, time.Since(startTime))
		return
	}

	// Convert pipeline status to enhanced alert status
	enhancedStatus := h.convertToAlertStatusResponse(status, alertID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enhancedStatus)
	h.recordEndpointMetrics("/alerts/{alertId}", true, time.Since(startTime))
}

// convertToAlertStatusResponse converts pipeline job status to enhanced alert status
func (h *APIHandlers) convertToAlertStatusResponse(status interface{}, alertID string) *AlertStatusResponse {
	// This would need to be adapted based on the actual pipeline.JobStatus structure
	// For now, create a basic response
	response := &AlertStatusResponse{
		AlertID:     alertID,
		SessionID:   fmt.Sprintf("session-%s", alertID), // Derive or look up session ID
		Status:      "unknown",
		Progress:    0.0,
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	// Try to extract information from the status object
	if statusMap, ok := status.(map[string]interface{}); ok {
		if statusStr, exists := statusMap["status"].(string); exists {
			response.Status = statusStr
		}
		if agent, exists := statusMap["agent"].(string); exists {
			response.Agent = agent
		}
		if startTimeStr, exists := statusMap["start_time"].(string); exists {
			if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
				response.StartTime = &startTime
			}
		}
		if endTimeStr, exists := statusMap["end_time"].(string); exists {
			if endTime, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
				response.EndTime = &endTime
			}
		}
		if result, exists := statusMap["result"].(string); exists {
			response.Result = result
		}
		if errorStr, exists := statusMap["error"].(string); exists {
			response.Error = errorStr
		}

		// Calculate progress and duration
		if response.StartTime != nil {
			if response.EndTime != nil {
				// Completed job
				response.Progress = 1.0
				response.Duration = response.EndTime.Sub(*response.StartTime).String()
			} else {
				// In progress job - estimate progress
				elapsed := time.Since(*response.StartTime)
				// Simple progress estimation (could be enhanced with pipeline metrics)
				response.Progress = math.Min(0.9, elapsed.Seconds()/300.0) // Max 90% for running jobs
				response.Duration = elapsed.String()
			}
		}
	}

	return response
}

// GetHealth handles GET /health with comprehensive service status
func (h *APIHandlers) GetHealth(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Collect comprehensive health information
	healthData := h.collectHealthData()

	// Determine overall status
	overallStatus, httpStatus := h.determineOverallHealth(healthData)

	// Enhanced health response matching Python TARSy format
	response := map[string]interface{}{
		"status":     overallStatus,
		"service":    "go-tarsy-bot",
		"version":    "1.0.0", // Could be injected at build time
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"services":   healthData.Services,
		"components": healthData.Components,
		"metrics":    healthData.Metrics,
		"warnings":   healthData.Warnings,
		"warning_count": len(healthData.Warnings),
		"uptime":     time.Since(startTime).String(), // Approximate uptime
		"metadata": map[string]interface{}{
			"go_version":    "go1.21+",
			"build_time":    "unknown", // Could be injected at build time
			"commit_hash":   "unknown", // Could be injected at build time
			"environment":   "development", // Could be from config
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/health", httpStatus == http.StatusOK, time.Since(startTime))
}

// HealthData contains comprehensive health information
type HealthData struct {
	Services   map[string]interface{} `json:"services"`
	Components map[string]interface{} `json:"components"`
	Metrics    map[string]interface{} `json:"metrics"`
	Warnings   []string               `json:"warnings"`
}

// collectHealthData gathers health information from all system components
func (h *APIHandlers) collectHealthData() *HealthData {
	healthData := &HealthData{
		Services:   make(map[string]interface{}),
		Components: make(map[string]interface{}),
		Metrics:    make(map[string]interface{}),
		Warnings:   make([]string, 0),
	}

	// Check core services
	h.checkCoreServices(healthData)
	h.checkAgentRegistry(healthData)
	h.checkPipeline(healthData)
	h.checkWebSocketManager(healthData)
	h.checkMCPRegistry(healthData)
	h.checkAuthenticationServices(healthData)

	// Collect metrics
	h.collectSystemMetrics(healthData)

	return healthData
}

// checkCoreServices checks the status of core API services
func (h *APIHandlers) checkCoreServices(healthData *HealthData) {
	healthData.Services["api_server"] = map[string]interface{}{
		"status": "healthy",
		"description": "HTTP API server is running",
		"endpoints_available": true,
	}

	healthData.Services["alert_processing"] = map[string]interface{}{
		"status": "healthy",
		"description": "Alert processing system is operational",
		"accepting_requests": true,
	}
}

// checkAgentRegistry checks agent registry health
func (h *APIHandlers) checkAgentRegistry(healthData *HealthData) {
	if h.agentRegistry == nil {
		healthData.Services["agent_registry"] = map[string]interface{}{
			"status": "unavailable",
			"description": "Agent registry is not initialized",
		}
		healthData.Warnings = append(healthData.Warnings, "Agent registry is unavailable")
		return
	}

	agents := h.agentRegistry.ListAgents()
	alertTypes := h.agentRegistry.GetAvailableAlertTypes()
	registryHealth := h.agentRegistry.HealthCheck()

	healthData.Services["agent_registry"] = map[string]interface{}{
		"status": "healthy",
		"description": "Agent registry is operational",
		"total_agents": len(agents),
		"available_alert_types": len(alertTypes),
		"health_details": registryHealth,
	}

	healthData.Components["agents"] = map[string]interface{}{
		"total": len(agents),
		"types": alertTypes,
		"details": agents,
	}

	if len(agents) == 0 {
		healthData.Warnings = append(healthData.Warnings, "No agents registered")
	}
}

// checkPipeline checks processing pipeline health
func (h *APIHandlers) checkPipeline(healthData *HealthData) {
	if h.pipeline == nil {
		healthData.Services["processing_pipeline"] = map[string]interface{}{
			"status": "unavailable",
			"description": "Processing pipeline is not initialized",
		}
		healthData.Warnings = append(healthData.Warnings, "Processing pipeline is unavailable")
		return
	}

	pipelineStatus := h.pipeline.GetPipelineStatus()
	pipelineMetrics := h.pipeline.GetMetrics()

	status := "healthy"
	if pipelineStatus.Status != "running" {
		status = "degraded"
		healthData.Warnings = append(healthData.Warnings, fmt.Sprintf("Pipeline status: %s", pipelineStatus.Status))
	}

	healthData.Services["processing_pipeline"] = map[string]interface{}{
		"status": status,
		"description": "Alert processing pipeline",
		"pipeline_status": pipelineStatus.Status,
		"details": pipelineStatus,
	}

	if pipelineMetrics != nil {
		healthData.Components["pipeline_metrics"] = map[string]interface{}{
			"queue_length": pipelineMetrics.QueueLength,
			"total_jobs": pipelineMetrics.TotalJobsProcessed,
			"successful_jobs": pipelineMetrics.SuccessfulJobs,
			"failed_jobs": pipelineMetrics.FailedJobs,
			"average_processing_time": pipelineMetrics.AverageProcessingTime.String(),
		}

		// Check for warning conditions
		if pipelineMetrics.QueueLength > 50 {
			healthData.Warnings = append(healthData.Warnings,
				fmt.Sprintf("High queue length: %d jobs pending", pipelineMetrics.QueueLength))
		}

		if pipelineMetrics.FailedJobs > 0 && pipelineMetrics.TotalJobsProcessed > 0 {
			failureRate := float64(pipelineMetrics.FailedJobs) / float64(pipelineMetrics.TotalJobsProcessed)
			if failureRate > 0.1 { // 10% failure rate
				healthData.Warnings = append(healthData.Warnings,
					fmt.Sprintf("High failure rate: %.1f%%", failureRate*100))
			}
		}
	}
}

// checkWebSocketManager checks WebSocket service health
func (h *APIHandlers) checkWebSocketManager(healthData *HealthData) {
	if h.wsManager == nil {
		healthData.Services["websocket"] = map[string]interface{}{
			"status": "unavailable",
			"description": "WebSocket manager is not initialized",
		}
		healthData.Warnings = append(healthData.Warnings, "WebSocket service is unavailable")
		return
	}

	healthData.Services["websocket"] = map[string]interface{}{
		"status": "healthy",
		"description": "WebSocket service for real-time updates",
		"service_available": true,
	}
}

// checkMCPRegistry checks MCP server registry health
func (h *APIHandlers) checkMCPRegistry(healthData *HealthData) {
	if h.mcpRegistry == nil {
		healthData.Services["mcp_registry"] = map[string]interface{}{
			"status": "unavailable",
			"description": "MCP server registry is not initialized",
		}
		healthData.Warnings = append(healthData.Warnings, "MCP registry is unavailable")
		return
	}

	healthData.Services["mcp_registry"] = map[string]interface{}{
		"status": "healthy",
		"description": "MCP server registry for tool integration",
		"registry_available": true,
	}
}

// checkAuthenticationServices checks authentication component health
func (h *APIHandlers) checkAuthenticationServices(healthData *HealthData) {
	if h.jwtManager == nil {
		healthData.Services["authentication"] = map[string]interface{}{
			"status": "disabled",
			"description": "Authentication is disabled (optional)",
			"jwt_available": false,
		}
		return
	}

	// Check JWT manager health
	jwtHealth := h.jwtManager.HealthCheck()

	authStatus := "healthy"
	if jwtHealthStatus, ok := jwtHealth["status"].(string); ok && jwtHealthStatus != "healthy" {
		authStatus = "degraded"
		if errorMsg, exists := jwtHealth["message"].(string); exists {
			healthData.Warnings = append(healthData.Warnings, fmt.Sprintf("JWT: %s", errorMsg))
		}
	}

	healthData.Services["authentication"] = map[string]interface{}{
		"status": authStatus,
		"description": "JWT authentication service",
		"jwt_available": true,
		"jwt_health": jwtHealth,
	}

	if h.inputSanitizer != nil {
		healthData.Services["input_sanitization"] = map[string]interface{}{
			"status": "healthy",
			"description": "Input sanitization and validation",
			"sanitizer_available": true,
		}
	}
}

// collectSystemMetrics gathers system-level metrics
func (h *APIHandlers) collectSystemMetrics(healthData *HealthData) {
	if h.metricsCollector != nil {
		h.metricsCollector.UpdateMetrics()
		systemMetrics := h.metricsCollector.GetMetrics()

		if systemMetrics != nil {
			healthData.Metrics["system"] = map[string]interface{}{
				"memory_allocated_mb": systemMetrics.Memory.AllocatedMB,
				"memory_system_mb":    systemMetrics.Memory.SystemMB,
				"goroutines":          systemMetrics.NumGoroutine,
				"uptime":              systemMetrics.Uptime,
				"go_version":          systemMetrics.GoVersion,
				"num_cpu":             systemMetrics.NumCPU,
				"last_updated":        systemMetrics.LastUpdated,
			}

			// Check for warning conditions
			if systemMetrics.Memory != nil && systemMetrics.Memory.AllocatedMB > 1000 { // 1GB
				healthData.Warnings = append(healthData.Warnings,
					fmt.Sprintf("High memory usage: %d MB", systemMetrics.Memory.AllocatedMB))
			}

			if systemMetrics.NumGoroutine > 1000 {
				healthData.Warnings = append(healthData.Warnings,
					fmt.Sprintf("High goroutine count: %d", systemMetrics.NumGoroutine))
			}
		}
	}
}

// determineOverallHealth determines overall system health status
func (h *APIHandlers) determineOverallHealth(healthData *HealthData) (string, int) {
	// Count service statuses
	healthyCount := 0
	degradedCount := 0
	unavailableCount := 0

	for _, service := range healthData.Services {
		if serviceMap, ok := service.(map[string]interface{}); ok {
			if status, exists := serviceMap["status"].(string); exists {
				switch status {
				case "healthy":
					healthyCount++
				case "degraded":
					degradedCount++
				case "unavailable", "disabled":
					unavailableCount++
				}
			}
		}
	}

	// Determine overall status
	totalServices := healthyCount + degradedCount + unavailableCount

	if unavailableCount > 0 && unavailableCount >= totalServices/2 {
		return "unhealthy", http.StatusServiceUnavailable
	}

	if degradedCount > 0 || len(healthData.Warnings) > 0 {
		return "degraded", http.StatusOK // 200 OK but with warnings
	}

	return "healthy", http.StatusOK
}

// GetRootStatus handles GET / - simple status like Python version
func (h *APIHandlers) GetRootStatus(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "Go-TARSy-bot is running",
		"status":  "healthy",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetHealthLive handles GET /health/live - simple liveness probe
func (h *APIHandlers) GetHealthLive(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	response := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/health/live", true, time.Since(startTime))
}

// GetHealthReady handles GET /health/ready - readiness probe
func (h *APIHandlers) GetHealthReady(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Check if essential services are ready
	ready := true
	details := make(map[string]interface{})

	// Check agent registry
	if h.agentRegistry != nil {
		agents := h.agentRegistry.ListAgents()
		details["agents"] = len(agents)
		if len(agents) == 0 {
			ready = false
			details["agents_ready"] = false
		} else {
			details["agents_ready"] = true
		}
	}

	// Check pipeline
	if h.pipeline != nil {
		pipelineStatus := h.pipeline.GetPipelineStatus()
		details["pipeline_status"] = pipelineStatus.Status
		details["pipeline_ready"] = pipelineStatus.Status == "running"
		if pipelineStatus.Status != "running" {
			ready = false
		}
	}

	httpStatus := http.StatusOK
	if !ready {
		httpStatus = http.StatusServiceUnavailable
	}

	response := map[string]interface{}{
		"status":    map[string]bool{"ready": ready},
		"timestamp": time.Now(),
		"details":   details,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/health/ready", ready, time.Since(startTime))
}

// GetMetrics handles GET /metrics
func (h *APIHandlers) GetMetrics(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if h.metricsCollector == nil {
		h.sendError(w, http.StatusServiceUnavailable, "METRICS_UNAVAILABLE", "Metrics collection is not available", nil)
		h.recordEndpointMetrics("/metrics", false, time.Since(startTime))
		return
	}

	// Update metrics before returning
	h.metricsCollector.UpdateMetrics()
	systemMetrics := h.metricsCollector.GetMetrics()

	// Get pipeline metrics if available
	var pipelineMetrics *pipeline.PipelineMetrics
	if h.pipeline != nil {
		pipelineMetrics = h.pipeline.GetMetrics()
	}

	response := MetricsResponse{
		Timestamp: time.Now(),
		System:    systemMetrics,
		Pipeline:  pipelineMetrics,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/metrics", true, time.Since(startTime))
}

// ListAgents handles GET /agents
func (h *APIHandlers) ListAgents(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if h.agentRegistry == nil {
		h.sendError(w, http.StatusServiceUnavailable, "REGISTRY_UNAVAILABLE", "Agent registry is not available", nil)
		h.recordEndpointMetrics("/agents", false, time.Since(startTime))
		return
	}

	agents := h.agentRegistry.ListAgents()
	availableAlertTypes := h.agentRegistry.GetAvailableAlertTypes()
	healthCheck := h.agentRegistry.HealthCheck()

	response := map[string]interface{}{
		"agents": agents,
		"available_alert_types": availableAlertTypes,
		"health_status": healthCheck,
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/agents", true, time.Since(startTime))
}

// GetPipelineStatus handles GET /pipeline/status
func (h *APIHandlers) GetPipelineStatus(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if h.pipeline == nil {
		h.sendError(w, http.StatusServiceUnavailable, "PIPELINE_UNAVAILABLE", "Processing pipeline is not available", nil)
		h.recordEndpointMetrics("/pipeline/status", false, time.Since(startTime))
		return
	}

	status := h.pipeline.GetPipelineStatus()
	metrics := h.pipeline.GetMetrics()

	response := map[string]interface{}{
		"status":    status,
		"metrics":   metrics,
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/pipeline/status", true, time.Since(startTime))
}

// ListMCPServers handles GET /mcp/servers
func (h *APIHandlers) ListMCPServers(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if h.mcpRegistry == nil {
		h.sendError(w, http.StatusServiceUnavailable, "MCP_UNAVAILABLE", "MCP registry is not available", nil)
		h.recordEndpointMetrics("/mcp/servers", false, time.Since(startTime))
		return
	}

	// Get server list and statuses
	servers := make(map[string]interface{})

	// Note: This would require extending MCPServerRegistry with a ListServers method
	// For now, we'll return a basic response
	response := map[string]interface{}{
		"servers":   servers,
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/mcp/servers", true, time.Since(startTime))
}

// sendError sends a structured error response
func (h *APIHandlers) sendError(w http.ResponseWriter, statusCode int, code, message string, details map[string]interface{}) {
	response := ErrorResponse{
		Error:   message,
		Code:    code,
		Details: details,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)

	h.logger.Warn("API error response",
		zap.Int("status_code", statusCode),
		zap.String("error_code", code),
		zap.String("message", message))
}

// sendValidationError sends a validation error response
func (h *APIHandlers) sendValidationError(w http.ResponseWriter, code, message string, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	details["type"] = "validation_error"

	h.sendError(w, http.StatusBadRequest, code, message, details)
}

// sendValidationErrors sends multiple validation errors
func (h *APIHandlers) sendValidationErrors(w http.ResponseWriter, errors []ValidationError) {
	response := map[string]interface{}{
		"error":   "Validation failed",
		"code":    "VALIDATION_FAILED",
		"details": map[string]interface{}{
			"errors":    errors,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"type":      "validation_errors",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(response)

	h.logger.Warn("Validation errors",
		zap.Int("error_count", len(errors)),
		zap.Any("errors", errors))
}

// parsePriority converts string priority to pipeline priority
func (h *APIHandlers) parsePriority(priorityStr string) pipeline.JobPriority {
	switch strings.ToLower(priorityStr) {
	case "high":
		return pipeline.PriorityHigh
	case "critical":
		return pipeline.PriorityCritical
	case "low":
		return pipeline.PriorityLow
	case "medium", "":
		return pipeline.PriorityMedium
	default:
		h.logger.Warn("Unknown priority, using medium", zap.String("priority", priorityStr))
		return pipeline.PriorityMedium
	}
}

// getUserIdentifier gets user identifier from request context or headers
func (h *APIHandlers) getUserIdentifier(r *http.Request) string {
	// Try to get authenticated user first
	if user, ok := auth.GetUserFromContext(r.Context()); ok {
		if user.ID != "" {
			return user.ID
		}
		if user.Email != "" {
			return user.Email
		}
	}

	// Fallback to headers
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	if userEmail := r.Header.Get("X-User-Email"); userEmail != "" {
		return userEmail
	}

	// Default fallback
	return "anonymous"
}

// getRequestID gets or generates a request ID for tracing
func (h *APIHandlers) getRequestID(r *http.Request) string {
	// Check for existing request ID in headers
	if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
		return requestID
	}
	if requestID := r.Header.Get("X-Trace-ID"); requestID != "" {
		return requestID
	}

	// Generate new request ID
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

// recordEndpointMetrics records metrics for API endpoints
func (h *APIHandlers) recordEndpointMetrics(endpoint string, success bool, latency time.Duration) {
	if h.metricsCollector != nil {
		h.metricsCollector.RecordEndpointMetrics(endpoint, success, latency)
	}
}

// Middleware for logging requests
func (h *APIHandlers) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Skip logging wrapper for WebSocket endpoints to avoid hijacker issues
		if strings.HasPrefix(r.URL.Path, "/ws/") {
			next.ServeHTTP(w, r)
			h.logger.Info("WebSocket request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Duration("duration", time.Since(start)),
				zap.String("user_agent", r.UserAgent()),
				zap.String("remote_addr", r.RemoteAddr))
			return
		}

		// Wrap ResponseWriter to capture status code for non-WebSocket requests
		wrapper := &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapper, r)

		h.logger.Info("HTTP request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("query", r.URL.RawQuery),
			zap.Int("status", wrapper.statusCode),
			zap.Duration("duration", time.Since(start)),
			zap.String("user_agent", r.UserAgent()),
			zap.String("remote_addr", r.RemoteAddr))
	})
}

// CORSConfig contains CORS configuration options
type CORSConfig struct {
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAge           int      `json:"max_age"` // Preflight cache duration in seconds
}

// DefaultCORSConfig returns default CORS configuration
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins: []string{
			"http://localhost:5173",    // TARSy Dashboard
			"http://localhost:3001",    // Alert Dev UI
			"http://localhost:3000",    // Common dev server port
			"http://127.0.0.1:5173",    // Alternative localhost
			"http://127.0.0.1:3001",    // Alternative localhost
			"http://127.0.0.1:3000",    // Alternative localhost
		},
		AllowedMethods: []string{
			"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD",
		},
		AllowedHeaders: []string{
			"Accept",
			"Accept-Language",
			"Content-Type",
			"Content-Language",
			"Authorization",
			"X-Requested-With",
			"X-Request-ID",
			"X-Trace-ID",
			"X-User-ID",
			"X-User-Email",
			"Cache-Control",
		},
		ExposedHeaders: []string{
			"X-Request-ID",
			"X-Trace-ID",
			"X-Total-Count",
			"X-Page-Count",
		},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours
	}
}

// Middleware for enhanced CORS with comprehensive configuration
func (h *APIHandlers) CORSMiddleware(next http.Handler) http.Handler {
	config := DefaultCORSConfig()

	// Override with environment-specific origins if configured
	if envOrigins := os.Getenv("CORS_ALLOWED_ORIGINS"); envOrigins != "" {
		config.AllowedOrigins = strings.Split(envOrigins, ",")
		for i, origin := range config.AllowedOrigins {
			config.AllowedOrigins[i] = strings.TrimSpace(origin)
		}
	}

	// Support wildcard for development
	if os.Getenv("CORS_ALLOW_ALL_ORIGINS") == "true" {
		config.AllowedOrigins = []string{"*"}
		config.AllowCredentials = false // Can't use credentials with wildcard
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Set CORS headers
		h.setCORSHeaders(w, r, config, origin)

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			h.handlePreflightRequest(w, r, config)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// setCORSHeaders sets appropriate CORS headers based on configuration
func (h *APIHandlers) setCORSHeaders(w http.ResponseWriter, r *http.Request, config *CORSConfig, origin string) {
	// Handle origin
	if len(config.AllowedOrigins) == 1 && config.AllowedOrigins[0] == "*" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else if h.isOriginAllowed(origin, config.AllowedOrigins) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}

	// Set other CORS headers
	if len(config.AllowedMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
	}

	if len(config.AllowedHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
	}

	if len(config.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
	}

	if config.AllowCredentials && origin != "" && !strings.Contains(strings.Join(config.AllowedOrigins, ","), "*") {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

// handlePreflightRequest handles OPTIONS preflight requests
func (h *APIHandlers) handlePreflightRequest(w http.ResponseWriter, r *http.Request, config *CORSConfig) {
	// Set preflight cache duration
	if config.MaxAge > 0 {
		w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", config.MaxAge))
	}

	// Validate requested method
	requestedMethod := r.Header.Get("Access-Control-Request-Method")
	if requestedMethod != "" && !h.isMethodAllowed(requestedMethod, config.AllowedMethods) {
		h.logger.Warn("CORS preflight rejected: method not allowed",
			zap.String("method", requestedMethod),
			zap.String("origin", r.Header.Get("Origin")))
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Validate requested headers
	requestedHeaders := r.Header.Get("Access-Control-Request-Headers")
	if requestedHeaders != "" {
		headersList := strings.Split(requestedHeaders, ",")
		for _, header := range headersList {
			header = strings.TrimSpace(header)
			if !h.isHeaderAllowed(header, config.AllowedHeaders) {
				h.logger.Warn("CORS preflight rejected: header not allowed",
					zap.String("header", header),
					zap.String("origin", r.Header.Get("Origin")))
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
	}

	w.WriteHeader(http.StatusOK)

	h.logger.Debug("CORS preflight request approved",
		zap.String("origin", r.Header.Get("Origin")),
		zap.String("method", requestedMethod),
		zap.String("headers", requestedHeaders))
}

// isOriginAllowed checks if an origin is in the allowed list
func (h *APIHandlers) isOriginAllowed(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return false
	}

	for _, allowedOrigin := range allowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			return true
		}

		// Support wildcard subdomains (e.g., "*.example.com")
		if strings.Contains(allowedOrigin, "*") {
			pattern := strings.ReplaceAll(allowedOrigin, "*", ".*")
			if matched, _ := regexp.MatchString("^"+pattern+"$", origin); matched {
				return true
			}
		}
	}

	return false
}

// isMethodAllowed checks if a method is in the allowed list
func (h *APIHandlers) isMethodAllowed(method string, allowedMethods []string) bool {
	method = strings.ToUpper(method)
	for _, allowedMethod := range allowedMethods {
		if strings.ToUpper(allowedMethod) == method {
			return true
		}
	}
	return false
}

// isHeaderAllowed checks if a header is in the allowed list
func (h *APIHandlers) isHeaderAllowed(header string, allowedHeaders []string) bool {
	header = strings.ToLower(header)
	for _, allowedHeader := range allowedHeaders {
		if strings.ToLower(allowedHeader) == header {
			return true
		}
	}
	return false
}

// Middleware for request timeout
func (h *APIHandlers) TimeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip timeout for WebSocket endpoints
			if strings.HasPrefix(r.URL.Path, "/ws/") {
				next.ServeHTTP(w, r)
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// responseWrapper wraps http.ResponseWriter to capture status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Health check for individual components
func (h *APIHandlers) GetComponentHealth(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	vars := mux.Vars(r)
	componentID := vars["componentId"]

	if componentID == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_COMPONENT_ID", "Component ID is required", nil)
		h.recordEndpointMetrics("/health/components", false, time.Since(startTime))
		return
	}

	if h.healthChecker == nil {
		h.sendError(w, http.StatusServiceUnavailable, "HEALTH_UNAVAILABLE", "Health checking is not available", nil)
		h.recordEndpointMetrics("/health/components", false, time.Since(startTime))
		return
	}

	health, exists := h.healthChecker.GetComponentHealth(componentID)
	if !exists {
		h.sendError(w, http.StatusNotFound, "COMPONENT_NOT_FOUND", "Component not found", map[string]interface{}{
			"component_id": componentID,
		})
		h.recordEndpointMetrics("/health/components", false, time.Since(startTime))
		return
	}

	response := map[string]interface{}{
		"component_id":   health.ComponentID,
		"component_type": string(health.ComponentType),
		"status":         string(health.Status),
		"message":        health.Message,
		"last_checked":   health.LastChecked,
		"response_time":  health.ResponseTime.String(),
		"details":        health.Details,
		"counters": map[string]interface{}{
			"success_count":     health.SuccessCount,
			"error_count":       health.ErrorCount,
			"consecutive_fails": health.ConsecutiveFails,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/health/components", true, time.Since(startTime))
}

// Validate request parameters
func (h *APIHandlers) validatePaginationParams(r *http.Request) (offset, limit int, err error) {
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")

	offset = 0
	limit = 50 // default limit

	if offsetStr != "" {
		offset, err = strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			return 0, 0, fmt.Errorf("invalid offset parameter")
		}
	}

	if limitStr != "" {
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 || limit > 1000 {
			return 0, 0, fmt.Errorf("invalid limit parameter (must be 1-1000)")
		}
	}

	return offset, limit, nil
}

// GetAgentTypes handles GET /agent-types with enhanced information
func (h *APIHandlers) GetAgentTypes(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if h.agentRegistry == nil {
		h.sendError(w, http.StatusServiceUnavailable, "REGISTRY_UNAVAILABLE", "Agent registry is not available", nil)
		h.recordEndpointMetrics("/agent-types", false, time.Since(startTime))
		return
	}

	// Get basic alert types
	alertTypes := h.agentRegistry.GetAvailableAlertTypes()

	// Create enhanced response with alert type metadata
	enhancedTypes := make(map[string]interface{})

	for _, alertType := range alertTypes {
		typeInfo := map[string]interface{}{
			"name":        alertType,
			"supported":   true,
			"description": h.getAlertTypeDescription(alertType),
			"examples":    h.getAlertTypeExamples(alertType),
			"required_fields": h.getRequiredFields(alertType),
			"optional_fields": h.getOptionalFields(alertType),
		}

		// Get agent info for this alert type
		alert := &models.Alert{AlertType: alertType, Data: map[string]interface{}{}}
		if agent, err := h.agentRegistry.GetAgentForAlert(alert); err == nil && agent != nil {
			typeInfo["agent"] = agent.GetAgentType()
			typeInfo["agent_description"] = h.getAgentDescription(agent.GetAgentType())
		}

		enhancedTypes[alertType] = typeInfo
	}

	// Create comprehensive response
	response := map[string]interface{}{
		"alert_types": enhancedTypes,
		"count":       len(alertTypes),
		"supported_priorities": []string{"critical", "high", "medium", "low"},
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"api_version": "v1",
		"metadata": map[string]interface{}{
			"total_agents": len(h.agentRegistry.ListAgents()),
			"system_status": "healthy",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/agent-types", true, time.Since(startTime))
}

// getAlertTypeDescription returns description for alert types
func (h *APIHandlers) getAlertTypeDescription(alertType string) string {
	descriptions := map[string]string{
		"kubernetes": "Kubernetes cluster and workload alerts including pod failures, resource constraints, and deployment issues",
		"aws":        "Amazon Web Services infrastructure alerts covering EC2, RDS, Lambda, and other AWS services",
		"prometheus": "Prometheus monitoring alerts from metric-based monitoring and alerting",
		"grafana":    "Grafana dashboard and visualization alerts for observability and monitoring",
		"general":    "General purpose alerts that don't fit specific categories",
		"network":    "Network infrastructure alerts including connectivity, latency, and routing issues",
		"security":   "Security-related alerts including intrusion detection, vulnerability scans, and compliance issues",
	}

	if desc, exists := descriptions[alertType]; exists {
		return desc
	}
	return fmt.Sprintf("Alerts related to %s systems and services", alertType)
}

// getAlertTypeExamples returns example data structures for alert types
func (h *APIHandlers) getAlertTypeExamples(alertType string) map[string]interface{} {
	switch alertType {
	case "kubernetes":
		return map[string]interface{}{
			"namespace":     "default",
			"resource_name": "my-pod",
			"resource_type": "Pod",
			"cluster":       "production",
			"severity":      "critical",
		}
	case "aws":
		return map[string]interface{}{
			"region":     "us-east-1",
			"account_id": "123456789012",
			"service":    "EC2",
			"resource":   "i-1234567890abcdef0",
			"severity":   "warning",
		}
	case "prometheus":
		return map[string]interface{}{
			"alertname": "HighCPUUsage",
			"labels": map[string]interface{}{
				"instance": "server-1",
				"job":      "node-exporter",
				"severity": "critical",
			},
		}
	case "grafana":
		return map[string]interface{}{
			"title":        "High Memory Usage Alert",
			"dashboard_id": 12345,
			"panel_id":     5,
			"severity":     "warning",
		}
	default:
		return map[string]interface{}{
			"title":       "Generic Alert",
			"description": "Alert description",
			"severity":    "info",
		}
	}
}

// getRequiredFields returns required fields for alert types
func (h *APIHandlers) getRequiredFields(alertType string) []string {
	switch alertType {
	case "kubernetes":
		return []string{"namespace", "resource_name"}
	case "aws":
		return []string{"region", "service"}
	case "prometheus":
		return []string{"alertname"}
	case "grafana":
		return []string{"title"}
	default:
		return []string{"title"}
	}
}

// getOptionalFields returns optional fields for alert types
func (h *APIHandlers) getOptionalFields(alertType string) []string {
	switch alertType {
	case "kubernetes":
		return []string{"cluster", "resource_type", "severity", "labels"}
	case "aws":
		return []string{"account_id", "resource", "availability_zone", "tags"}
	case "prometheus":
		return []string{"labels", "annotations", "severity"}
	case "grafana":
		return []string{"dashboard_id", "panel_id", "threshold", "tags"}
	default:
		return []string{"description", "severity", "tags", "metadata"}
	}
}

// getAgentDescription returns description for agent types
func (h *APIHandlers) getAgentDescription(agentType string) string {
	descriptions := map[string]string{
		"KubernetesAgent": "Specialized agent for Kubernetes cluster analysis and troubleshooting",
		"GeneralAgent":    "General-purpose agent for handling various types of alerts",
		"SecurityAgent":   "Security-focused agent for handling security incidents and compliance issues",
		"NetworkAgent":    "Network infrastructure agent for connectivity and performance issues",
	}

	if desc, exists := descriptions[agentType]; exists {
		return desc
	}
	return fmt.Sprintf("Agent specialized for %s processing", agentType)
}

// GetSessions handles GET /sessions (for history service compatibility)
func (h *APIHandlers) GetSessions(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// TODO: Implement session history retrieval
	// For now, return empty sessions
	response := map[string]interface{}{
		"sessions":  []interface{}{},
		"total":     0,
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/sessions", true, time.Since(startTime))
}

// GetSession handles GET /sessions/{sessionId}
func (h *APIHandlers) GetSession(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	if sessionID == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_SESSION_ID", "Session ID is required", nil)
		h.recordEndpointMetrics("/sessions", false, time.Since(startTime))
		return
	}

	// TODO: Implement session retrieval
	h.sendError(w, http.StatusNotFound, "SESSION_NOT_FOUND", "Session not found", map[string]interface{}{
		"session_id": sessionID,
	})
	h.recordEndpointMetrics("/sessions", false, time.Since(startTime))
}

// GetSessionID handles GET /session-id/{alertId} - enhanced session tracking
func (h *APIHandlers) GetSessionID(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	vars := mux.Vars(r)
	alertID := vars["alertId"]

	if alertID == "" {
		h.sendValidationError(w, "MISSING_ALERT_ID", "Alert ID is required", map[string]interface{}{
			"parameter": "alertId",
			"location":  "path",
		})
		h.recordEndpointMetrics("/session-id/{alertId}", false, time.Since(startTime))
		return
	}

	// Validate alert ID format
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(alertID) {
		h.sendValidationError(w, "INVALID_ALERT_ID", "Alert ID contains invalid characters", map[string]interface{}{
			"alert_id": alertID,
			"pattern":  "^[a-zA-Z0-9_-]+$",
		})
		h.recordEndpointMetrics("/session-id/{alertId}", false, time.Since(startTime))
		return
	}

	// Check if alert exists
	if h.pipeline != nil {
		if _, err := h.pipeline.GetJobStatus(alertID); err != nil {
			h.sendError(w, http.StatusNotFound, "ALERT_NOT_FOUND", "Alert not found", map[string]interface{}{
				"alert_id": alertID,
				"hint":     "Ensure the alert ID is correct and the alert has been submitted",
			})
			h.recordEndpointMetrics("/session-id/{alertId}", false, time.Since(startTime))
			return
		}
	}

	// Generate session ID based on alert ID
	// In a full implementation, this would look up or create an actual session
	sessionID := fmt.Sprintf("session-%s", alertID)

	// Enhanced response with session metadata
	response := map[string]interface{}{
		"session_id": sessionID,
		"alert_id":   alertID,
		"websocket_url": fmt.Sprintf("/ws/%s", alertID),
		"dashboard_url": fmt.Sprintf("/ws/dashboard/%s", h.getUserIdentifier(r)),
		"created_at":    time.Now().UTC().Format(time.RFC3339),
		"status":        "active",
		"metadata": map[string]interface{}{
			"user":       h.getUserIdentifier(r),
			"request_id": h.getRequestID(r),
		},
	}

	h.logger.Debug("Session ID lookup",
		zap.String("alert_id", alertID),
		zap.String("session_id", sessionID),
		zap.String("user", h.getUserIdentifier(r)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/session-id/{alertId}", true, time.Since(startTime))
}

// WebSocketAlert handles WebSocket connections for alert updates
func (h *APIHandlers) WebSocketAlert(w http.ResponseWriter, r *http.Request) {
	if h.wsManager == nil {
		h.sendError(w, http.StatusServiceUnavailable, "WEBSOCKET_UNAVAILABLE", "WebSocket service is not available", nil)
		return
	}

	vars := mux.Vars(r)
	alertID := vars["alertId"]

	if alertID == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_ALERT_ID", "Alert ID is required", nil)
		return
	}

	// Use alert ID as user ID for this connection
	userID := fmt.Sprintf("alert-%s", alertID)
	channel := fmt.Sprintf("session_%s", alertID)

	err := h.wsManager.HandleWebSocket(w, r, userID, channel)
	if err != nil {
		h.logger.Error("WebSocket connection failed",
			zap.String("alert_id", alertID),
			zap.Error(err))
		h.sendError(w, http.StatusInternalServerError, "WEBSOCKET_ERROR", "Failed to establish WebSocket connection", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	h.logger.Info("WebSocket connection established for alert",
		zap.String("alert_id", alertID),
		zap.String("channel", channel))
}

// WebSocketDashboard handles WebSocket connections for dashboard updates
func (h *APIHandlers) WebSocketDashboard(w http.ResponseWriter, r *http.Request) {
	if h.wsManager == nil {
		h.sendError(w, http.StatusServiceUnavailable, "WEBSOCKET_UNAVAILABLE", "WebSocket service is not available", nil)
		return
	}

	vars := mux.Vars(r)
	userID := vars["userId"]

	if userID == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_USER_ID", "User ID is required", nil)
		return
	}

	// Use dashboard updates channel
	channel := models.WSChannelDashboardUpdates

	err := h.wsManager.HandleWebSocket(w, r, userID, channel)
	if err != nil {
		h.logger.Error("WebSocket connection failed",
			zap.String("user_id", userID),
			zap.Error(err))
		h.sendError(w, http.StatusInternalServerError, "WEBSOCKET_ERROR", "Failed to establish WebSocket connection", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Send initial dashboard metrics after connection
	h.sendInitialDashboardMetrics(userID)

	h.logger.Info("WebSocket connection established for dashboard",
		zap.String("user_id", userID),
		zap.String("channel", channel))
}

// sendInitialDashboardMetrics sends initial dashboard metrics to a new connection
func (h *APIHandlers) sendInitialDashboardMetrics(userID string) {
	// Get current system metrics
	metrics := &models.SystemMetrics{
		ActiveSessions:    0, // TODO: Get from session manager
		CompletedSessions: 0,
		FailedSessions:    0,
		TotalSessions:     0,
		SystemStatus:      models.SystemHealthStatusHealthy,
		DatabaseHealth:    "healthy",
		LLMServiceHealth:  map[string]string{"openai": "healthy", "google": "healthy"},
		MCPServerHealth:   map[string]string{"default": "healthy"},
	}

	// Get pipeline metrics if available
	if h.pipeline != nil {
		pipelineMetrics := h.pipeline.GetMetrics()
		if pipelineMetrics != nil {
			metrics.ActiveSessions = pipelineMetrics.QueueLength
			metrics.TotalSessions = int(pipelineMetrics.TotalJobsProcessed)
			metrics.CompletedSessions = int(pipelineMetrics.SuccessfulJobs)
			metrics.FailedSessions = int(pipelineMetrics.FailedJobs)
		}
	}

	// Get system resource metrics if available
	if h.metricsCollector != nil {
		h.metricsCollector.UpdateMetrics()
		systemMetrics := h.metricsCollector.GetMetrics()
		if systemMetrics != nil && systemMetrics.Memory != nil {
			memoryMB := float64(systemMetrics.Memory.AllocatedMB)
			metrics.MemoryUsageMB = &memoryMB
		}
	}

	// Send system metrics message
	message := models.NewSystemMetricsMessage(metrics)
	if err := h.wsManager.SendToUser(userID, message); err != nil {
		h.logger.Error("Failed to send initial metrics",
			zap.String("user_id", userID),
			zap.Error(err))
	}

	// Also send current dashboard stats
	dashboardUpdate := map[string]interface{}{
		"websocket_connections": h.wsManager.GetConnectionCount(),
		"dashboard_channels":    h.wsManager.GetChannelConnectionCount(models.WSChannelDashboardUpdates),
		"server_started":        true,
	}

	dashboardMessage := models.NewDashboardUpdateMessage("connection_established", dashboardUpdate)
	if err := h.wsManager.SendToUser(userID, dashboardMessage); err != nil {
		h.logger.Error("Failed to send dashboard update",
			zap.String("user_id", userID),
			zap.Error(err))
	}
}

// ValidateConfiguration handles GET /config/validate - validates system configuration
func (h *APIHandlers) ValidateConfiguration(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Create configuration validator
	validator := config.NewConfigValidator(h.logger)

	// Run validation
	result := validator.ValidateSystemConfiguration()

	// Set HTTP status based on validation result
	httpStatus := http.StatusOK
	if !result.Valid {
		httpStatus = http.StatusBadRequest
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(result)
	h.recordEndpointMetrics("/config/validate", result.Valid, time.Since(startTime))
}

// GetJWKS handles GET /.well-known/jwks.json - JWT public key endpoint
func (h *APIHandlers) GetJWKS(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if h.jwtManager == nil {
		h.sendError(w, http.StatusServiceUnavailable, "JWT_UNAVAILABLE",
			"JWT service is not available", map[string]interface{}{
				"message": "JWT authentication is not configured",
			})
		h.recordEndpointMetrics("/.well-known/jwks.json", false, time.Since(startTime))
		return
	}

	// Delegate to JWT manager
	h.jwtManager.ServeJWKS(w, r)
	h.recordEndpointMetrics("/.well-known/jwks.json", true, time.Since(startTime))
}

// GetUser handles GET /user - returns current user information
func (h *APIHandlers) GetUser(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Get user from context (set by auth middleware)
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		h.sendError(w, http.StatusUnauthorized, "UNAUTHENTICATED",
			"User authentication required", nil)
		h.recordEndpointMetrics("/user", false, time.Since(startTime))
		return
	}

	// Return user information
	response := map[string]interface{}{
		"user":      user,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	h.recordEndpointMetrics("/user", true, time.Since(startTime))
}