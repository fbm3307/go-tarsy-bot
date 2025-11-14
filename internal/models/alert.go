package models

import (
	"time"
)

// Alert represents a flexible alert model with minimal required fields and arbitrary data payload
type Alert struct {
	// Required fields for agent selection and processing
	AlertType string `json:"alert_type" validate:"required" binding:"required"`
	Type      string `json:"type" validate:"required" binding:"required"` // Alert type for classification
	Runbook   string `json:"runbook" validate:"required,url" binding:"required"`

	// Flexible alert payload
	Data map[string]interface{} `json:"data,omitempty"`

	// Optional fields with defaults (will be applied in API layer if not provided)
	Severity  *string    `json:"severity,omitempty"`   // Defaults to 'warning'
	Timestamp *time.Time `json:"timestamp,omitempty"`  // Defaults to current time
}

// AlertResponse represents the response model for alert submission
type AlertResponse struct {
	AlertID string `json:"alert_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// AlertKey represents a unique key for duplicate detection
type AlertKey struct {
	AlertType string                 `json:"alert_type"`
	Data      map[string]interface{} `json:"data"`
}

// NewAlertKeyFromChainContext creates an AlertKey from ChainContext for duplicate detection
func NewAlertKeyFromChainContext(ctx *ChainContext) AlertKey {
	return AlertKey{
		AlertType: ctx.AlertType,
		Data:      ctx.AlertData,
	}
}

// GetSeverity returns the severity with default fallback
func (a *Alert) GetSeverity() string {
	if a.Severity != nil {
		return *a.Severity
	}
	return "warning"
}

// GetTimestamp returns the timestamp with current time fallback
func (a *Alert) GetTimestamp() time.Time {
	if a.Timestamp != nil {
		return *a.Timestamp
	}
	return time.Now()
}

// GetTimestampMicroseconds returns the timestamp in microseconds since Unix epoch
func (a *Alert) GetTimestampMicroseconds() int64 {
	return a.GetTimestamp().UnixMicro()
}

// ValidationError represents alert validation errors
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidateAlert validates the alert structure
func (a *Alert) ValidateAlert() []ValidationError {
	var errors []ValidationError

	if a.AlertType == "" {
		errors = append(errors, ValidationError{
			Field:   "alert_type",
			Message: "alert_type is required",
		})
	}

	if a.Type == "" {
		errors = append(errors, ValidationError{
			Field:   "type",
			Message: "type is required",
		})
	}

	if a.Runbook == "" {
		errors = append(errors, ValidationError{
			Field:   "runbook",
			Message: "runbook is required",
		})
	}

	return errors
}