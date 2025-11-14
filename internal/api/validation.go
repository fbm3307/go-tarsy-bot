package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// ValidationError represents a validation error with detailed information
type ValidationError struct {
	Field   string      `json:"field"`
	Value   interface{} `json:"value"`
	Tag     string      `json:"tag"`
	Message string      `json:"message"`
}

// ValidationResult contains the results of validation
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors"`
}

// AlertValidator provides comprehensive validation for alert requests
type AlertValidator struct {
	maxDataSize        int
	allowedAlertTypes  map[string]bool
	requiredFields     []string
	urlPattern         *regexp.Regexp
	sessionIDPattern   *regexp.Regexp
}

// NewAlertValidator creates a new alert validator
func NewAlertValidator() *AlertValidator {
	return &AlertValidator{
		maxDataSize:       1024 * 1024, // 1MB max for alert data
		allowedAlertTypes: make(map[string]bool),
		requiredFields:    []string{"alert_type", "data"},
		urlPattern:        regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`),
		sessionIDPattern:  regexp.MustCompile(`^[a-zA-Z0-9_-]+$`),
	}
}

// SetAllowedAlertTypes sets the allowed alert types for validation
func (v *AlertValidator) SetAllowedAlertTypes(alertTypes []string) {
	v.allowedAlertTypes = make(map[string]bool)
	for _, alertType := range alertTypes {
		v.allowedAlertTypes[alertType] = true
	}
}

// ValidateAlertRequest validates an alert request comprehensively
func (v *AlertValidator) ValidateAlertRequest(req *AlertRequest) *ValidationResult {
	result := &ValidationResult{
		Valid:  true,
		Errors: make([]ValidationError, 0),
	}

	// Validate alert type
	if err := v.validateAlertType(req.AlertType); err != nil {
		result.Errors = append(result.Errors, *err)
		result.Valid = false
	}

	// Validate data field
	if err := v.validateData(req.Data); err != nil {
		result.Errors = append(result.Errors, *err)
		result.Valid = false
	}

	// Validate runbook URL if provided
	if req.Runbook != "" {
		if err := v.validateRunbookURL(req.Runbook); err != nil {
			result.Errors = append(result.Errors, *err)
			result.Valid = false
		}
	}

	// Validate session ID if provided
	if req.SessionID != "" {
		if err := v.validateSessionID(req.SessionID); err != nil {
			result.Errors = append(result.Errors, *err)
			result.Valid = false
		}
	}

	// Validate data structure based on alert type
	if result.Valid {
		if err := v.validateDataStructure(req.AlertType, req.Data); err != nil {
			result.Errors = append(result.Errors, *err)
			result.Valid = false
		}
	}

	return result
}

// validateAlertType validates the alert type field
func (v *AlertValidator) validateAlertType(alertType string) *ValidationError {
	if alertType == "" {
		return &ValidationError{
			Field:   "alert_type",
			Value:   alertType,
			Tag:     "required",
			Message: "Alert type is required",
		}
	}

	if len(alertType) > 100 {
		return &ValidationError{
			Field:   "alert_type",
			Value:   alertType,
			Tag:     "max_length",
			Message: "Alert type must be 100 characters or less",
		}
	}

	// Check if alert type contains only valid characters
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(alertType) {
		return &ValidationError{
			Field:   "alert_type",
			Value:   alertType,
			Tag:     "format",
			Message: "Alert type can only contain letters, numbers, underscores, and hyphens",
		}
	}

	// Check against allowed alert types if configured
	if len(v.allowedAlertTypes) > 0 && !v.allowedAlertTypes[alertType] {
		return &ValidationError{
			Field:   "alert_type",
			Value:   alertType,
			Tag:     "enum",
			Message: fmt.Sprintf("Alert type '%s' is not supported", alertType),
		}
	}

	return nil
}

// validateData validates the data field
func (v *AlertValidator) validateData(data map[string]interface{}) *ValidationError {
	if data == nil {
		return &ValidationError{
			Field:   "data",
			Value:   data,
			Tag:     "required",
			Message: "Alert data is required",
		}
	}

	if len(data) == 0 {
		return &ValidationError{
			Field:   "data",
			Value:   data,
			Tag:     "min_length",
			Message: "Alert data cannot be empty",
		}
	}

	// Check data size
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return &ValidationError{
			Field:   "data",
			Value:   data,
			Tag:     "marshal",
			Message: "Alert data must be valid JSON",
		}
	}

	if len(dataBytes) > v.maxDataSize {
		return &ValidationError{
			Field:   "data",
			Value:   data,
			Tag:     "max_size",
			Message: fmt.Sprintf("Alert data exceeds maximum size of %d bytes", v.maxDataSize),
		}
	}

	return nil
}

// validateRunbookURL validates the runbook URL field
func (v *AlertValidator) validateRunbookURL(runbookURL string) *ValidationError {
	if len(runbookURL) > 2000 {
		return &ValidationError{
			Field:   "runbook",
			Value:   runbookURL,
			Tag:     "max_length",
			Message: "Runbook URL must be 2000 characters or less",
		}
	}

	// Parse URL to validate format
	parsedURL, err := url.Parse(runbookURL)
	if err != nil {
		return &ValidationError{
			Field:   "runbook",
			Value:   runbookURL,
			Tag:     "url_format",
			Message: "Runbook URL is not a valid URL",
		}
	}

	// Check scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return &ValidationError{
			Field:   "runbook",
			Value:   runbookURL,
			Tag:     "url_scheme",
			Message: "Runbook URL must use HTTP or HTTPS scheme",
		}
	}

	// Check host
	if parsedURL.Host == "" {
		return &ValidationError{
			Field:   "runbook",
			Value:   runbookURL,
			Tag:     "url_host",
			Message: "Runbook URL must have a valid host",
		}
	}

	return nil
}

// validateSessionID validates the session ID field
func (v *AlertValidator) validateSessionID(sessionID string) *ValidationError {
	if len(sessionID) > 255 {
		return &ValidationError{
			Field:   "session_id",
			Value:   sessionID,
			Tag:     "max_length",
			Message: "Session ID must be 255 characters or less",
		}
	}

	if !v.sessionIDPattern.MatchString(sessionID) {
		return &ValidationError{
			Field:   "session_id",
			Value:   sessionID,
			Tag:     "format",
			Message: "Session ID can only contain letters, numbers, underscores, and hyphens",
		}
	}

	return nil
}

// validateDataStructure validates data structure based on alert type
func (v *AlertValidator) validateDataStructure(alertType string, data map[string]interface{}) *ValidationError {
	switch alertType {
	case "kubernetes":
		return v.validateKubernetesData(data)
	case "aws":
		return v.validateAWSData(data)
	case "prometheus":
		return v.validatePrometheusData(data)
	case "grafana":
		return v.validateGrafanaData(data)
	default:
		// For unknown alert types, just validate basic structure
		return v.validateGenericData(data)
	}
}

// validateKubernetesData validates Kubernetes-specific alert data
func (v *AlertValidator) validateKubernetesData(data map[string]interface{}) *ValidationError {
	// Check for common Kubernetes fields
	if namespace, exists := data["namespace"]; exists {
		if namespaceStr, ok := namespace.(string); !ok || namespaceStr == "" {
			return &ValidationError{
				Field:   "data.namespace",
				Value:   namespace,
				Tag:     "type",
				Message: "Kubernetes namespace must be a non-empty string",
			}
		}
	}

	if resourceName, exists := data["resource_name"]; exists {
		if resourceNameStr, ok := resourceName.(string); !ok || resourceNameStr == "" {
			return &ValidationError{
				Field:   "data.resource_name",
				Value:   resourceName,
				Tag:     "type",
				Message: "Kubernetes resource name must be a non-empty string",
			}
		}
	}

	return nil
}

// validateAWSData validates AWS-specific alert data
func (v *AlertValidator) validateAWSData(data map[string]interface{}) *ValidationError {
	// Check for common AWS fields
	if region, exists := data["region"]; exists {
		if regionStr, ok := region.(string); !ok || regionStr == "" {
			return &ValidationError{
				Field:   "data.region",
				Value:   region,
				Tag:     "type",
				Message: "AWS region must be a non-empty string",
			}
		}
	}

	if accountID, exists := data["account_id"]; exists {
		switch v := accountID.(type) {
		case string:
			if v == "" {
				return &ValidationError{
					Field:   "data.account_id",
					Value:   accountID,
					Tag:     "empty",
					Message: "AWS account ID cannot be empty",
				}
			}
		case float64:
			// Numbers are valid for account IDs
		default:
			return &ValidationError{
				Field:   "data.account_id",
				Value:   accountID,
				Tag:     "type",
				Message: "AWS account ID must be a string or number",
			}
		}
	}

	return nil
}

// validatePrometheusData validates Prometheus-specific alert data
func (v *AlertValidator) validatePrometheusData(data map[string]interface{}) *ValidationError {
	// Check for common Prometheus fields
	if alertname, exists := data["alertname"]; exists {
		if alertnameStr, ok := alertname.(string); !ok || alertnameStr == "" {
			return &ValidationError{
				Field:   "data.alertname",
				Value:   alertname,
				Tag:     "type",
				Message: "Prometheus alertname must be a non-empty string",
			}
		}
	}

	if labels, exists := data["labels"]; exists {
		if _, ok := labels.(map[string]interface{}); !ok {
			return &ValidationError{
				Field:   "data.labels",
				Value:   labels,
				Tag:     "type",
				Message: "Prometheus labels must be an object",
			}
		}
	}

	return nil
}

// validateGrafanaData validates Grafana-specific alert data
func (v *AlertValidator) validateGrafanaData(data map[string]interface{}) *ValidationError {
	// Check for common Grafana fields
	if title, exists := data["title"]; exists {
		if titleStr, ok := title.(string); !ok || titleStr == "" {
			return &ValidationError{
				Field:   "data.title",
				Value:   title,
				Tag:     "type",
				Message: "Grafana title must be a non-empty string",
			}
		}
	}

	if dashboardID, exists := data["dashboard_id"]; exists {
		switch v := dashboardID.(type) {
		case string:
			if v == "" {
				return &ValidationError{
					Field:   "data.dashboard_id",
					Value:   dashboardID,
					Tag:     "empty",
					Message: "Grafana dashboard ID cannot be empty",
				}
			}
		case float64:
			// Numbers are valid for dashboard IDs
		default:
			return &ValidationError{
				Field:   "data.dashboard_id",
				Value:   dashboardID,
				Tag:     "type",
				Message: "Grafana dashboard ID must be a string or number",
			}
		}
	}

	return nil
}

// validateGenericData validates generic alert data structure
func (v *AlertValidator) validateGenericData(data map[string]interface{}) *ValidationError {
	// Validate that all values are of supported types
	return v.validateDataTypes(data, "data")
}

// validateDataTypes recursively validates data types
func (av *AlertValidator) validateDataTypes(data interface{}, path string) *ValidationError {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			if err := av.validateDataTypes(value, path+"."+key); err != nil {
				return err
			}
		}
	case []interface{}:
		for i, value := range v {
			if err := av.validateDataTypes(value, path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
	case string, float64, bool, nil:
		// These types are valid
		return nil
	default:
		return &ValidationError{
			Field:   path,
			Value:   data,
			Tag:     "type",
			Message: fmt.Sprintf("Unsupported data type: %s", reflect.TypeOf(data)),
		}
	}
	return nil
}

// PaginationParams represents pagination parameters
type PaginationParams struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
	Sort   string `json:"sort"`
	Order  string `json:"order"`
}

// ValidatePaginationParams validates pagination parameters from request
func ValidatePaginationParams(params map[string][]string) (*PaginationParams, *ValidationError) {
	result := &PaginationParams{
		Offset: 0,
		Limit:  50, // Default limit
		Sort:   "timestamp",
		Order:  "desc",
	}

	// Validate offset
	if offsetStrs, exists := params["offset"]; exists && len(offsetStrs) > 0 {
		offset, err := strconv.Atoi(offsetStrs[0])
		if err != nil || offset < 0 {
			return nil, &ValidationError{
				Field:   "offset",
				Value:   offsetStrs[0],
				Tag:     "min",
				Message: "Offset must be a non-negative integer",
			}
		}
		result.Offset = offset
	}

	// Validate limit
	if limitStrs, exists := params["limit"]; exists && len(limitStrs) > 0 {
		limit, err := strconv.Atoi(limitStrs[0])
		if err != nil || limit <= 0 || limit > 1000 {
			return nil, &ValidationError{
				Field:   "limit",
				Value:   limitStrs[0],
				Tag:     "range",
				Message: "Limit must be an integer between 1 and 1000",
			}
		}
		result.Limit = limit
	}

	// Validate sort
	if sortStrs, exists := params["sort"]; exists && len(sortStrs) > 0 {
		sort := sortStrs[0]
		validSortFields := map[string]bool{
			"timestamp": true,
			"alert_type": true,
			"status": true,
			"agent": true,
		}
		if !validSortFields[sort] {
			return nil, &ValidationError{
				Field:   "sort",
				Value:   sort,
				Tag:     "enum",
				Message: "Sort field must be one of: timestamp, alert_type, status, agent",
			}
		}
		result.Sort = sort
	}

	// Validate order
	if orderStrs, exists := params["order"]; exists && len(orderStrs) > 0 {
		order := strings.ToLower(orderStrs[0])
		if order != "asc" && order != "desc" {
			return nil, &ValidationError{
				Field:   "order",
				Value:   orderStrs[0],
				Tag:     "enum",
				Message: "Order must be 'asc' or 'desc'",
			}
		}
		result.Order = order
	}

	return result, nil
}