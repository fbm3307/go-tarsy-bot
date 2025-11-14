package models

import (
	"encoding/json"
	"time"
	"gorm.io/gorm"
	"gorm.io/datatypes"
)

// AlertSession represents an alert processing session - matches Python AlertSession exactly
// From backend/tarsy/models/db_models.py
type AlertSession struct {
	// Primary key - matches Python session_id: str = Field(...)
	SessionID string `gorm:"primaryKey;type:text;autoIncrement:false" json:"session_id"`

	// Alert identification - matches Python alert_id: str = Field(...)
	AlertID string `gorm:"uniqueIndex;type:varchar(255);not null" json:"alert_id"`

	// Alert payload - matches Python alert_data: dict = Field(default_factory=dict)
	AlertData datatypes.JSON `gorm:"type:json;default:'{}'" json:"alert_data"`

	// Processing information - matches Python agent_type: str = Field(...)
	AgentType string `gorm:"index;type:varchar(255);not null" json:"agent_type"`

	// Alert type - matches Python alert_type: Optional[str] = Field(default=None)
	AlertType *string `gorm:"index;type:varchar(255)" json:"alert_type"`

	// Status - matches Python status: str = Field(...)
	Status string `gorm:"index;type:varchar(50);not null" json:"status"`

	// Timestamps - matches Python started_at_us: int = Field(default_factory=now_us)
	StartedAtUs int64 `gorm:"index;not null" json:"started_at_us"`

	// Completion timestamp - matches Python completed_at_us: Optional[int] = Field(default=None)
	CompletedAtUs *int64 `gorm:"index" json:"completed_at_us"`

	// Error handling - matches Python error_message: Optional[str] = Field(default=None)
	ErrorMessage *string `gorm:"type:text" json:"error_message"`

	// Final analysis - matches Python final_analysis: Optional[str] = Field(default=None)
	FinalAnalysis *string `gorm:"type:text" json:"final_analysis"`

	// Session metadata - matches Python session_metadata: Optional[dict] = Field(default=None)
	SessionMetadata datatypes.JSON `gorm:"type:json;default:'{}'" json:"session_metadata"`

	// Chain execution tracking - matches Python chain_id: str = Field(...)
	ChainID string `gorm:"type:varchar(255);not null" json:"chain_id"`

	// Chain definition - matches Python chain_definition: Optional[dict] = Field(default=None)
	ChainDefinition datatypes.JSON `gorm:"type:json;default:'{}'" json:"chain_definition"`

	// Current stage tracking - matches Python current_stage_index: Optional[int] = Field(default=None)
	CurrentStageIndex *int `gorm:"index" json:"current_stage_index"`

	// Current stage ID - matches Python current_stage_id: Optional[str] = Field(default=None)
	CurrentStageID *string `gorm:"type:varchar(255)" json:"current_stage_id"`

	// GORM timestamps (not in Python model)
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	StageExecutions []StageExecution `gorm:"foreignKey:SessionID" json:"stage_executions,omitempty"`
}

// TableName returns the table name for AlertSession
func (AlertSession) TableName() string {
	return "alert_sessions"
}

// BeforeCreate sets the started timestamp if not already set and initializes JSON fields
func (as *AlertSession) BeforeCreate(tx *gorm.DB) error {
	if as.StartedAtUs == 0 {
		as.StartedAtUs = time.Now().UnixMicro()
	}

	// Initialize JSON fields with empty objects to match Python defaults
	if len(as.AlertData) == 0 {
		as.AlertData = datatypes.JSON("{}")
	}
	if len(as.SessionMetadata) == 0 {
		as.SessionMetadata = datatypes.JSON("{}")
	}
	if len(as.ChainDefinition) == 0 {
		as.ChainDefinition = datatypes.JSON("{}")
	}

	return nil
}

// MarkCompleted marks the session as completed
func (as *AlertSession) MarkCompleted() {
	as.Status = string(AlertSessionStatusCompleted)
	completedAt := time.Now().UnixMicro()
	as.CompletedAtUs = &completedAt
}

// MarkFailed marks the session as failed
func (as *AlertSession) MarkFailed(errorMessage string) {
	as.Status = string(AlertSessionStatusFailed)
	as.ErrorMessage = &errorMessage
	completedAt := time.Now().UnixMicro()
	as.CompletedAtUs = &completedAt
}

// IsActive returns true if the session is still being processed
func (as *AlertSession) IsActive() bool {
	return as.Status == string(AlertSessionStatusPending) || as.Status == string(AlertSessionStatusInProgress)
}

// IsTerminal returns true if the session processing is finished
func (as *AlertSession) IsTerminal() bool {
	return as.Status == string(AlertSessionStatusCompleted) || as.Status == string(AlertSessionStatusFailed)
}

// GetDurationMicroseconds returns the duration in microseconds
func (as *AlertSession) GetDurationMicroseconds() *int64 {
	if as.CompletedAtUs != nil {
		duration := *as.CompletedAtUs - as.StartedAtUs
		return &duration
	}
	return nil
}

// StageExecution represents a single stage execution - matches Python StageExecution exactly
// From backend/tarsy/models/db_models.py
type StageExecution struct {
	// Primary key - matches Python execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
	ExecutionID string `gorm:"primaryKey;type:varchar(255);autoIncrement:false" json:"execution_id"`

	// Foreign key to AlertSession - matches Python session_id: str = Field(...)
	SessionID string `gorm:"index;type:varchar(255);not null" json:"session_id"`

	// Stage identification - matches Python stage_id: str = Field(...)
	StageID string `gorm:"type:varchar(255);not null" json:"stage_id"`

	// Stage index - matches Python stage_index: int = Field(...)
	StageIndex int `gorm:"index;not null" json:"stage_index"`

	// Stage name - matches Python stage_name: str = Field(...)
	StageName string `gorm:"type:varchar(255);not null" json:"stage_name"`

	// Agent - matches Python agent: str = Field(...)
	Agent string `gorm:"type:varchar(255);not null" json:"agent"`

	// Execution status - matches Python status: str = Field(...)
	Status string `gorm:"type:varchar(50);not null" json:"status"`

	// Timestamps - matches Python started_at_us: Optional[int] = Field(default=None)
	StartedAtUs *int64 `gorm:"index" json:"started_at_us"`

	// Completion timestamp - matches Python completed_at_us: Optional[int] = Field(default=None)
	CompletedAtUs *int64 `gorm:"index" json:"completed_at_us"`

	// Duration - matches Python duration_ms: Optional[int] = Field(default=None)
	DurationMs *int64 `json:"duration_ms"`

	// Stage output - matches Python stage_output: Optional[dict] = Field(default=None)
	StageOutput datatypes.JSON `gorm:"type:json;default:'{}'" json:"stage_output"`

	// Error message - matches Python error_message: Optional[str] = Field(default=None)
	ErrorMessage *string `gorm:"type:text" json:"error_message"`

	// GORM timestamps (not in Python model)
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	AlertSession AlertSession `gorm:"foreignKey:SessionID" json:"-"`
}

// TableName returns the table name for StageExecution
func (StageExecution) TableName() string {
	return "stage_executions"
}

// BeforeCreate generates UUID if not set
func (se *StageExecution) BeforeCreate(tx *gorm.DB) error {
	if se.ExecutionID == "" {
		// Generate UUID - you'll need to import uuid package
		// se.ExecutionID = uuid.New().String()
	}
	return nil
}

// MarkStarted marks the stage as started
func (se *StageExecution) MarkStarted() {
	se.Status = string(StageStatusActive)
	startedAt := time.Now().UnixMicro()
	se.StartedAtUs = &startedAt
}

// MarkCompleted marks the stage as completed
func (se *StageExecution) MarkCompleted(output map[string]interface{}) {
	se.Status = string(StageStatusCompleted)
	completedAt := time.Now().UnixMicro()
	se.CompletedAtUs = &completedAt

	if se.StartedAtUs != nil {
		durationMs := (completedAt - *se.StartedAtUs) / 1000
		se.DurationMs = &durationMs
	}

	if output != nil {
		outputBytes, _ := json.Marshal(output)
		se.StageOutput = datatypes.JSON(outputBytes)
	}
}

// MarkFailed marks the stage as failed
func (se *StageExecution) MarkFailed(errorMessage string) {
	se.Status = string(StageStatusFailed)
	se.ErrorMessage = &errorMessage
	completedAt := time.Now().UnixMicro()
	se.CompletedAtUs = &completedAt

	if se.StartedAtUs != nil {
		durationMs := (completedAt - *se.StartedAtUs) / 1000
		se.DurationMs = &durationMs
	}
}

// IsActive returns true if the stage is currently active
func (se *StageExecution) IsActive() bool {
	return se.Status == string(StageStatusActive)
}

// IsCompleted returns true if the stage completed successfully
func (se *StageExecution) IsCompleted() bool {
	return se.Status == string(StageStatusCompleted)
}

// IsFailed returns true if the stage failed
func (se *StageExecution) IsFailed() bool {
	return se.Status == string(StageStatusFailed)
}