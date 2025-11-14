package models

import (
	"database/sql/driver"
	"fmt"
)

// AlertSessionStatus represents the status of an alert processing session
type AlertSessionStatus string

const (
	AlertSessionStatusPending    AlertSessionStatus = "pending"
	AlertSessionStatusInProgress AlertSessionStatus = "in_progress"
	AlertSessionStatusCompleted  AlertSessionStatus = "completed"
	AlertSessionStatusFailed     AlertSessionStatus = "failed"
)

// GetActiveStatuses returns statuses that indicate session is still being processed
func GetActiveAlertSessionStatuses() []AlertSessionStatus {
	return []AlertSessionStatus{
		AlertSessionStatusPending,
		AlertSessionStatusInProgress,
	}
}

// GetTerminalStatuses returns statuses that indicate session processing is finished
func GetTerminalAlertSessionStatuses() []AlertSessionStatus {
	return []AlertSessionStatus{
		AlertSessionStatusCompleted,
		AlertSessionStatusFailed,
	}
}

// Values returns all status values as strings
func (s AlertSessionStatus) Values() []string {
	return []string{
		string(AlertSessionStatusPending),
		string(AlertSessionStatusInProgress),
		string(AlertSessionStatusCompleted),
		string(AlertSessionStatusFailed),
	}
}

// Value implements the driver.Valuer interface for GORM
func (s AlertSessionStatus) Value() (driver.Value, error) {
	return string(s), nil
}

// Scan implements the sql.Scanner interface for GORM
func (s *AlertSessionStatus) Scan(value interface{}) error {
	if value == nil {
		*s = ""
		return nil
	}

	switch v := value.(type) {
	case string:
		*s = AlertSessionStatus(v)
	case []byte:
		*s = AlertSessionStatus(v)
	default:
		return fmt.Errorf("cannot scan %T into AlertSessionStatus", value)
	}

	return nil
}

// StageStatus represents the status of individual stage execution within a chain
type StageStatus string

const (
	StageStatusPending   StageStatus = "pending"
	StageStatusActive    StageStatus = "active"
	StageStatusCompleted StageStatus = "completed"
	StageStatusFailed    StageStatus = "failed"
	StageStatusPartial   StageStatus = "partial" // Some results but with warnings/issues
)

// ChainStatus represents the status of overall chain execution progress
type ChainStatus string

const (
	ChainStatusPending    ChainStatus = "pending"    // All stages pending
	ChainStatusProcessing ChainStatus = "processing" // At least one stage active
	ChainStatusCompleted  ChainStatus = "completed"  // All stages completed successfully
	ChainStatusFailed     ChainStatus = "failed"     // One or more stages failed, no active stages
	ChainStatusPartial    ChainStatus = "partial"    // Mix of completed and failed, no active stages
)

// SystemHealthStatus represents the status of system health monitoring
type SystemHealthStatus string

const (
	SystemHealthStatusHealthy   SystemHealthStatus = "healthy"
	SystemHealthStatusDegraded  SystemHealthStatus = "degraded"
	SystemHealthStatusUnhealthy SystemHealthStatus = "unhealthy"
)

// IterationStrategy represents available iteration strategies for agent processing
type IterationStrategy string

const (
	// IterationStrategyReAct - Standard ReAct pattern with Think→Action→Observation cycles for complete analysis
	IterationStrategyReAct IterationStrategy = "react"
	// IterationStrategyReActStage - ReAct pattern for stage-specific analysis within multi-stage chains
	IterationStrategyReActStage IterationStrategy = "react-stage"
	// IterationStrategyReActFinalAnalysis - ReAct final analysis only, no tools, uses all accumulated data
	IterationStrategyReActFinalAnalysis IterationStrategy = "react-final-analysis"
)

// LLM Configuration Constants
const (
	// DefaultLLMTemperature - Lower temperature (0.1) ensures more deterministic and focused responses
	DefaultLLMTemperature = 0.1
	// MaxLLMMessageContentSize - Maximum size for LLM interaction message content before hook processing
	MaxLLMMessageContentSize = 1048576 // 1MB
)