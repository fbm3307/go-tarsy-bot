package models

import (
	"encoding/json"
	"time"
	"gorm.io/datatypes"
)

// GetCurrentTimestampUs returns the current timestamp in microseconds since Unix epoch
func GetCurrentTimestampUs() int64 {
	return time.Now().UnixMicro()
}

// GetCurrentTimestampMs returns the current timestamp in milliseconds since Unix epoch
func GetCurrentTimestampMs() int64 {
	return time.Now().UnixMilli()
}

// JSONFromMap converts a map[string]interface{} to datatypes.JSON
func JSONFromMap(data map[string]interface{}) datatypes.JSON {
	if data == nil {
		return datatypes.JSON("{}")
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return datatypes.JSON("{}")
	}

	return datatypes.JSON(bytes)
}

// JSONFromInterface converts any interface{} to datatypes.JSON
func JSONFromInterface(data interface{}) datatypes.JSON {
	if data == nil {
		return datatypes.JSON("null")
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return datatypes.JSON("null")
	}

	return datatypes.JSON(bytes)
}

// MapFromJSON converts datatypes.JSON to map[string]interface{}
func MapFromJSON(jsonData datatypes.JSON) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(jsonData), &result)
	return result, err
}

// StringPtr returns a pointer to the given string
func StringPtr(s string) *string {
	return &s
}

// IntPtr returns a pointer to the given int
func IntPtr(i int) *int {
	return &i
}

// Int64Ptr returns a pointer to the given int64
func Int64Ptr(i int64) *int64 {
	return &i
}

// Float64Ptr returns a pointer to the given float64
func Float64Ptr(f float64) *float64 {
	return &f
}

// BoolPtr returns a pointer to the given bool
func BoolPtr(b bool) *bool {
	return &b
}

// SafeStringValue returns the string value or empty string if pointer is nil
func SafeStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// SafeIntValue returns the int value or 0 if pointer is nil
func SafeIntValue(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

// SafeInt64Value returns the int64 value or 0 if pointer is nil
func SafeInt64Value(i *int64) int64 {
	if i == nil {
		return 0
	}
	return *i
}

// SafeFloat64Value returns the float64 value or 0.0 if pointer is nil
func SafeFloat64Value(f *float64) float64 {
	if f == nil {
		return 0.0
	}
	return *f
}

// SafeBoolValue returns the bool value or false if pointer is nil
func SafeBoolValue(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// CalculateDurationMs calculates duration in milliseconds between two timestamps in microseconds
func CalculateDurationMs(startUs, endUs int64) int64 {
	return (endUs - startUs) / 1000
}

// FormatDuration formats a duration in microseconds to a human-readable string
func FormatDuration(durationUs int64) string {
	duration := time.Duration(durationUs) * time.Microsecond

	if duration < time.Millisecond {
		return duration.String()
	}

	if duration < time.Second {
		return duration.Truncate(time.Millisecond).String()
	}

	if duration < time.Minute {
		return duration.Truncate(10 * time.Millisecond).String()
	}

	return duration.Truncate(100 * time.Millisecond).String()
}

// ValidateSessionStatus validates that a session status is valid
func ValidateSessionStatus(status string) bool {
	validStatuses := []string{
		string(AlertSessionStatusPending),
		string(AlertSessionStatusInProgress),
		string(AlertSessionStatusCompleted),
		string(AlertSessionStatusFailed),
	}

	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}

	return false
}

// ValidateStageStatus validates that a stage status is valid
func ValidateStageStatus(status string) bool {
	validStatuses := []string{
		string(StageStatusPending),
		string(StageStatusActive),
		string(StageStatusCompleted),
		string(StageStatusFailed),
		string(StageStatusPartial),
	}

	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}

	return false
}

// CreateSessionUpdateFromSession creates a SessionUpdate from an AlertSession
func CreateSessionUpdateFromSession(session *AlertSession) *SessionUpdate {
	var alertType string
	if session.AlertType != nil {
		alertType = *session.AlertType
	}

	update := &SessionUpdate{
		SessionID:       session.SessionID,
		AlertType:       alertType,
		AgentType:       session.AgentType,
		Status:          AlertSessionStatus(session.Status),
		StartedAtUs:     session.StartedAtUs,
		CompletedAtUs:   session.CompletedAtUs,
		ErrorMessage:    session.ErrorMessage,
	}

	// Calculate duration if completed
	if session.CompletedAtUs != nil {
		durationMs := CalculateDurationMs(session.StartedAtUs, *session.CompletedAtUs)
		update.DurationMs = &durationMs
	}

	// Add chain information if available
	if session.ChainID != "" {
		update.ChainID = &session.ChainID
		update.CurrentStageIndex = session.CurrentStageIndex

		if session.CurrentStageID != nil {
			// This would need to be resolved from stage execution data
			// For now, we'll use the stage ID as the name
			update.CurrentStageName = session.CurrentStageID
		}
	}

	return update
}

// CreateStageProgressFromExecution creates a StageProgressUpdate from a StageExecution
func CreateStageProgressFromExecution(execution *StageExecution) *StageProgressUpdate {
	progress := &StageProgressUpdate{
		SessionID:        execution.SessionID,
		StageExecutionID: execution.ExecutionID,
		StageID:          execution.StageID,
		StageIndex:       execution.StageIndex,
		StageName:        execution.StageName,
		AgentType:        execution.Agent,
		Status:           StageStatus(execution.Status),
		StartedAtUs:      execution.StartedAtUs,
		CompletedAtUs:    execution.CompletedAtUs,
		DurationMs:       execution.DurationMs,
		ErrorMessage:     execution.ErrorMessage,
		StageOutput:      execution.StageOutput,
	}

	// Calculate progress based on status
	switch execution.Status {
	case string(StageStatusPending):
		progress.Progress = 0.0
	case string(StageStatusActive):
		progress.Progress = 50.0 // Rough estimate for active stage
	case string(StageStatusCompleted):
		progress.Progress = 100.0
	case string(StageStatusFailed):
		progress.Progress = 0.0
	case string(StageStatusPartial):
		progress.Progress = 75.0
	default:
		progress.Progress = 0.0
	}

	return progress
}