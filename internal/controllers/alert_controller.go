package controllers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/services"
)

// AlertController handles alert submission and processing endpoints
// Equivalent to Python's AlertController with comprehensive validation
type AlertController struct {
	alertService *services.AlertService
	logger       *zap.Logger
	config       *AlertControllerConfig
}

// AlertControllerConfig contains configuration for the alert controller
type AlertControllerConfig struct {
	MaxPayloadSize   int64         `json:"max_payload_size"`
	ValidationTimeout time.Duration `json:"validation_timeout"`
	AllowedSchemes   []string      `json:"allowed_schemes"`
	MaxAlertDataSize int           `json:"max_alert_data_size"`
}

// NewAlertController creates a new alert controller
func NewAlertController(alertService *services.AlertService, logger *zap.Logger) *AlertController {
	config := &AlertControllerConfig{
		MaxPayloadSize:   1024 * 1024, // 1MB
		ValidationTimeout: 5 * time.Second,
		AllowedSchemes:   []string{"http", "https"},
		MaxAlertDataSize: 512 * 1024, // 512KB
	}

	return &AlertController{
		alertService: alertService,
		logger:       logger,
		config:       config,
	}
}

// SubmitAlert handles POST /api/v1/alerts - main alert submission endpoint
func (ac *AlertController) SubmitAlert(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), ac.config.ValidationTimeout)
	defer cancel()

	ac.logger.Info("Received alert submission request",
		zap.String("remote_addr", c.ClientIP()),
		zap.String("user_agent", c.GetHeader("User-Agent")),
	)

	var alert models.Alert
	if err := c.ShouldBindJSON(&alert); err != nil {
		ac.logger.Warn("Invalid alert payload", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid alert payload",
			"details": err.Error(),
		})
		return
	}

	// Validate alert
	if err := ac.validateAlert(&alert); err != nil {
		ac.logger.Warn("Alert validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Alert validation failed",
			"details": err.Error(),
		})
		return
	}

	// Sanitize alert data
	ac.sanitizeAlert(&alert)

	// Set defaults
	ac.setAlertDefaults(&alert)

	// Submit alert for processing
	response, err := ac.alertService.ProcessAlert(ctx, &alert)
	if err != nil {
		ac.logger.Error("Alert processing failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Alert processing failed",
			"details": err.Error(),
		})
		return
	}

	ac.logger.Info("Alert submitted successfully",
		zap.String("alert_id", response.AlertID),
		zap.String("alert_type", alert.AlertType),
	)

	c.JSON(http.StatusOK, response)
}

// GetAlertStatus handles GET /api/v1/alerts/{alert_id}/status
func (ac *AlertController) GetAlertStatus(c *gin.Context) {
	alertID := c.Param("alert_id")
	if alertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Alert ID is required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	session, err := ac.alertService.GetSessionStatus(ctx, alertID)
	if err != nil {
		ac.logger.Error("Failed to get alert status", zap.Error(err), zap.String("alert_id", alertID))
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Alert not found",
			"details": err.Error(),
		})
		return
	}

	// Convert session to status response
	status := map[string]interface{}{
		"alert_id":            session.AlertID,
		"session_id":          session.SessionID,
		"status":              string(session.Status),
		"alert_type":          session.AlertType,
		"agent_type":          session.AgentType,
		"started_at":          time.UnixMicro(session.StartedAtUs),
		"current_stage_index": session.CurrentStageIndex,
		"current_stage_id":    session.CurrentStageID,
		"error_message":       session.ErrorMessage,
		"final_analysis":      session.FinalAnalysis,
	}

	if session.CompletedAtUs != nil {
		status["completed_at"] = time.UnixMicro(*session.CompletedAtUs)
		status["duration_ms"] = (*session.CompletedAtUs - session.StartedAtUs) / 1000
	}

	c.JSON(http.StatusOK, status)
}

// ListActiveAlerts handles GET /api/v1/alerts/active
func (ac *AlertController) ListActiveAlerts(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	sessions, err := ac.alertService.ListActiveSessions(ctx)
	if err != nil {
		ac.logger.Error("Failed to list active alerts", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to list active alerts",
			"details": err.Error(),
		})
		return
	}

	// Convert sessions to response format
	activeAlerts := make([]map[string]interface{}, len(sessions))
	for i, session := range sessions {
		alert := map[string]interface{}{
			"alert_id":            session.AlertID,
			"session_id":          session.SessionID,
			"status":              string(session.Status),
			"alert_type":          session.AlertType,
			"agent_type":          session.AgentType,
			"started_at":          time.UnixMicro(session.StartedAtUs),
			"current_stage_index": session.CurrentStageIndex,
			"current_stage_id":    session.CurrentStageID,
		}
		activeAlerts[i] = alert
	}

	c.JSON(http.StatusOK, gin.H{
		"active_alerts": activeAlerts,
		"count":         len(activeAlerts),
	})
}

// CancelAlert handles POST /api/v1/alerts/{alert_id}/cancel
func (ac *AlertController) CancelAlert(c *gin.Context) {
	alertID := c.Param("alert_id")
	if alertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Alert ID is required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	err := ac.alertService.CancelSession(ctx, alertID)
	if err != nil {
		ac.logger.Error("Failed to cancel alert", zap.Error(err), zap.String("alert_id", alertID))
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to cancel alert",
			"details": err.Error(),
		})
		return
	}

	ac.logger.Info("Alert cancelled", zap.String("alert_id", alertID))

	c.JSON(http.StatusOK, gin.H{
		"message":  "Alert cancelled successfully",
		"alert_id": alertID,
	})
}

// GetAlertTypes handles GET /api/v1/alert-types
func (ac *AlertController) GetAlertTypes(c *gin.Context) {
	// Return supported alert types and their descriptions
	alertTypes := map[string]interface{}{
		"kubernetes": map[string]interface{}{
			"description": "Kubernetes security incidents and alerts",
			"examples":    []string{"pod-security-violation", "rbac-misconfiguration", "network-policy-violation"},
		},
		"container": map[string]interface{}{
			"description": "Container and runtime security alerts",
			"examples":    []string{"malicious-process", "privilege-escalation", "suspicious-network-activity"},
		},
		"general": map[string]interface{}{
			"description": "General security incidents and alerts",
			"examples":    []string{"security-scan-findings", "compliance-violation", "anomaly-detection"},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"alert_types": alertTypes,
		"supported":   []string{"kubernetes", "container", "general"},
	})
}

// validateAlert performs comprehensive alert validation
func (ac *AlertController) validateAlert(alert *models.Alert) error {
	// Required field validation
	if alert.AlertType == "" {
		return fmt.Errorf("alert_type is required")
	}

	if alert.Type == "" {
		return fmt.Errorf("type is required")
	}

	if alert.Runbook == "" {
		return fmt.Errorf("runbook URL is required")
	}

	// Validate runbook URL
	if err := ac.validateRunbookURL(alert.Runbook); err != nil {
		return fmt.Errorf("invalid runbook URL: %w", err)
	}

	// Validate alert data size
	if alert.Data != nil {
		dataSize := ac.estimateJSONSize(alert.Data)
		if dataSize > ac.config.MaxAlertDataSize {
			return fmt.Errorf("alert data too large: %d bytes (max: %d)", dataSize, ac.config.MaxAlertDataSize)
		}
	}

	// Validate alert type format
	if len(alert.AlertType) > 100 {
		return fmt.Errorf("alert_type too long (max 100 characters)")
	}

	if len(alert.Type) > 100 {
		return fmt.Errorf("type too long (max 100 characters)")
	}

	// Check for required fields in alert data based on type
	if err := ac.validateAlertTypeSpecificData(alert); err != nil {
		return fmt.Errorf("alert type validation failed: %w", err)
	}

	return nil
}

// validateRunbookURL validates the runbook URL format and scheme
func (ac *AlertController) validateRunbookURL(runbookURL string) error {
	if len(runbookURL) > 2048 {
		return fmt.Errorf("runbook URL too long (max 2048 characters)")
	}

	// Check allowed schemes
	hasValidScheme := false
	for _, scheme := range ac.config.AllowedSchemes {
		if strings.HasPrefix(strings.ToLower(runbookURL), scheme+"://") {
			hasValidScheme = true
			break
		}
	}

	if !hasValidScheme {
		return fmt.Errorf("invalid URL scheme (allowed: %v)", ac.config.AllowedSchemes)
	}

	return nil
}

// validateAlertTypeSpecificData validates alert data based on alert type
func (ac *AlertController) validateAlertTypeSpecificData(alert *models.Alert) error {
	switch strings.ToLower(alert.AlertType) {
	case "kubernetes", "k8s":
		return ac.validateKubernetesAlert(alert)
	case "container":
		return ac.validateContainerAlert(alert)
	default:
		// General validation for unknown types
		return nil
	}
}

// validateKubernetesAlert validates Kubernetes-specific alert data
func (ac *AlertController) validateKubernetesAlert(alert *models.Alert) error {
	if alert.Data == nil {
		return fmt.Errorf("kubernetes alerts require alert data")
	}

	// Check for required Kubernetes fields
	requiredFields := []string{"namespace"}
	for _, field := range requiredFields {
		if _, exists := alert.Data[field]; !exists {
			ac.logger.Warn("Missing recommended field for Kubernetes alert",
				zap.String("field", field),
				zap.String("alert_type", alert.AlertType),
			)
		}
	}

	return nil
}

// validateContainerAlert validates container-specific alert data
func (ac *AlertController) validateContainerAlert(alert *models.Alert) error {
	if alert.Data == nil {
		return fmt.Errorf("container alerts require alert data")
	}

	// Container alerts should have either pod_name or container_id
	hasPod := false
	hasContainer := false

	if _, exists := alert.Data["pod_name"]; exists {
		hasPod = true
	}
	if _, exists := alert.Data["container_id"]; exists {
		hasContainer = true
	}

	if !hasPod && !hasContainer {
		ac.logger.Warn("Container alert missing pod_name or container_id")
	}

	return nil
}

// sanitizeAlert sanitizes alert data to prevent injection attacks
func (ac *AlertController) sanitizeAlert(alert *models.Alert) {
	// Sanitize string fields
	alert.AlertType = ac.sanitizeString(alert.AlertType)
	alert.Type = ac.sanitizeString(alert.Type)
	alert.Runbook = strings.TrimSpace(alert.Runbook)

	// Sanitize alert data
	if alert.Data != nil {
		alert.Data = ac.sanitizeMap(alert.Data)
	}
}

// sanitizeString removes potentially dangerous characters
func (ac *AlertController) sanitizeString(input string) string {
	// Remove null bytes and control characters
	cleaned := strings.ReplaceAll(input, "\x00", "")
	cleaned = strings.TrimSpace(cleaned)

	// Additional sanitization can be added here
	return cleaned
}

// sanitizeMap recursively sanitizes map values
func (ac *AlertController) sanitizeMap(data map[string]interface{}) map[string]interface{} {
	sanitized := make(map[string]interface{})

	for key, value := range data {
		cleanKey := ac.sanitizeString(key)

		switch v := value.(type) {
		case string:
			sanitized[cleanKey] = ac.sanitizeString(v)
		case map[string]interface{}:
			sanitized[cleanKey] = ac.sanitizeMap(v)
		case []interface{}:
			sanitized[cleanKey] = ac.sanitizeSlice(v)
		default:
			sanitized[cleanKey] = value
		}
	}

	return sanitized
}

// sanitizeSlice sanitizes slice values
func (ac *AlertController) sanitizeSlice(data []interface{}) []interface{} {
	sanitized := make([]interface{}, len(data))

	for i, value := range data {
		switch v := value.(type) {
		case string:
			sanitized[i] = ac.sanitizeString(v)
		case map[string]interface{}:
			sanitized[i] = ac.sanitizeMap(v)
		case []interface{}:
			sanitized[i] = ac.sanitizeSlice(v)
		default:
			sanitized[i] = value
		}
	}

	return sanitized
}

// setAlertDefaults sets default values for optional fields
func (ac *AlertController) setAlertDefaults(alert *models.Alert) {
	// Set default severity if not provided
	if alert.Severity == nil {
		defaultSeverity := "warning"
		alert.Severity = &defaultSeverity
	}

	// Set default timestamp if not provided
	if alert.Timestamp == nil {
		now := time.Now()
		alert.Timestamp = &now
	}
}

// estimateJSONSize estimates the size of JSON-serialized data
func (ac *AlertController) estimateJSONSize(data interface{}) int {
	// This is a rough estimation - in production, you might want a more accurate method
	switch v := data.(type) {
	case string:
		return len(v)
	case map[string]interface{}:
		size := 2 // {}
		for key, value := range v {
			size += len(key) + 3 // "key":
			size += ac.estimateJSONSize(value)
			size += 1 // comma
		}
		return size
	case []interface{}:
		size := 2 // []
		for _, item := range v {
			size += ac.estimateJSONSize(item)
			size += 1 // comma
		}
		return size
	default:
		return 50 // Rough estimate for other types
	}
}