package errors

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"go.uber.org/zap"
)

// ErrorCategory represents the category of error
type ErrorCategory string

const (
	ErrorCategoryConfiguration ErrorCategory = "configuration"
	ErrorCategoryLLM           ErrorCategory = "llm"
	ErrorCategoryMCP           ErrorCategory = "mcp"
	ErrorCategoryTimeout       ErrorCategory = "timeout"
	ErrorCategoryNetwork       ErrorCategory = "network"
	ErrorCategorySecurity      ErrorCategory = "security"
	ErrorCategoryValidation    ErrorCategory = "validation"
	ErrorCategoryProcessing    ErrorCategory = "processing"
	ErrorCategoryDatabase      ErrorCategory = "database"
	ErrorCategoryAuth          ErrorCategory = "authentication"
	ErrorCategoryAgent         ErrorCategory = "agent"
	ErrorCategoryWebSocket     ErrorCategory = "websocket"
	ErrorCategoryInternal      ErrorCategory = "internal"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	ErrorSeverityLow      ErrorSeverity = "low"
	ErrorSeverityMedium   ErrorSeverity = "medium"
	ErrorSeverityHigh     ErrorSeverity = "high"
	ErrorSeverityCritical ErrorSeverity = "critical"
)

// RecoveryAction represents the action to take for error recovery
type RecoveryAction string

const (
	RecoveryActionRetry       RecoveryAction = "retry"
	RecoveryActionFallback    RecoveryAction = "fallback"
	RecoveryActionSkip        RecoveryAction = "skip"
	RecoveryActionReconfigure RecoveryAction = "reconfigure"
	RecoveryActionAbort       RecoveryAction = "abort"
)

// ErrorContext contains contextual information about where the error occurred
type ErrorContext struct {
	Component     string                 `json:"component"`
	Operation     string                 `json:"operation"`
	SessionID     string                 `json:"session_id,omitempty"`
	AgentType     string                 `json:"agent_type,omitempty"`
	Stage         string                 `json:"stage,omitempty"`
	Iteration     int                    `json:"iteration,omitempty"`
	RequestID     string                 `json:"request_id,omitempty"`
	UserID        string                 `json:"user_id,omitempty"`
	AlertID       string                 `json:"alert_id,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// StackFrame represents a single frame in the stack trace
type StackFrame struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

// StructuredError represents a comprehensive error with metadata and context
type StructuredError struct {
	// Core error information
	Code        string         `json:"code"`
	Message     string         `json:"message"`
	Category    ErrorCategory  `json:"category"`
	Severity    ErrorSeverity  `json:"severity"`
	Timestamp   time.Time      `json:"timestamp"`

	// Context and metadata
	Context     *ErrorContext  `json:"context,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`

	// Error chain and causality
	Cause       error          `json:"cause,omitempty"`
	InnerError  *StructuredError `json:"inner_error,omitempty"`

	// Stack trace and debugging
	StackTrace  []StackFrame   `json:"stack_trace,omitempty"`

	// Recovery information
	Recoverable     bool           `json:"recoverable"`
	RecoveryAction  RecoveryAction `json:"recovery_action,omitempty"`
	RetryAttempt    int            `json:"retry_attempt,omitempty"`
	MaxRetries      int            `json:"max_retries,omitempty"`

	// Tracking and resolution
	ErrorID     string         `json:"error_id"`
	Resolved    bool           `json:"resolved"`
	ResolvedAt  *time.Time     `json:"resolved_at,omitempty"`
	ResolutionNote string      `json:"resolution_note,omitempty"`
}

// Error implements the error interface
func (e *StructuredError) Error() string {
	if e.Context != nil && e.Context.Component != "" {
		return fmt.Sprintf("[%s/%s] %s: %s", e.Category, e.Context.Component, e.Code, e.Message)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Category, e.Code, e.Message)
}

// Unwrap returns the underlying cause error for error wrapping
func (e *StructuredError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches a target error
func (e *StructuredError) Is(target error) bool {
	if se, ok := target.(*StructuredError); ok {
		return e.Code == se.Code && e.Category == se.Category
	}
	return false
}

// GetZapFields returns zap fields for structured logging
func (e *StructuredError) GetZapFields() []zap.Field {
	fields := []zap.Field{
		zap.String("error_id", e.ErrorID),
		zap.String("error_code", e.Code),
		zap.String("error_category", string(e.Category)),
		zap.String("error_severity", string(e.Severity)),
		zap.Time("error_timestamp", e.Timestamp),
		zap.Bool("recoverable", e.Recoverable),
	}

	if e.Context != nil {
		if e.Context.Component != "" {
			fields = append(fields, zap.String("component", e.Context.Component))
		}
		if e.Context.Operation != "" {
			fields = append(fields, zap.String("operation", e.Context.Operation))
		}
		if e.Context.SessionID != "" {
			fields = append(fields, zap.String("session_id", e.Context.SessionID))
		}
		if e.Context.AgentType != "" {
			fields = append(fields, zap.String("agent_type", e.Context.AgentType))
		}
		if e.Context.RequestID != "" {
			fields = append(fields, zap.String("request_id", e.Context.RequestID))
		}
	}

	if e.RecoveryAction != "" {
		fields = append(fields, zap.String("recovery_action", string(e.RecoveryAction)))
	}

	if e.RetryAttempt > 0 {
		fields = append(fields, zap.Int("retry_attempt", e.RetryAttempt))
		fields = append(fields, zap.Int("max_retries", e.MaxRetries))
	}

	if e.Metadata != nil {
		fields = append(fields, zap.Any("error_metadata", e.Metadata))
	}

	return fields
}

// ToJSON serializes the error to JSON
func (e *StructuredError) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// Clone creates a deep copy of the structured error
func (e *StructuredError) Clone() *StructuredError {
	clone := &StructuredError{
		Code:           e.Code,
		Message:        e.Message,
		Category:       e.Category,
		Severity:       e.Severity,
		Timestamp:      e.Timestamp,
		Cause:          e.Cause,
		Recoverable:    e.Recoverable,
		RecoveryAction: e.RecoveryAction,
		RetryAttempt:   e.RetryAttempt,
		MaxRetries:     e.MaxRetries,
		ErrorID:        e.ErrorID,
		Resolved:       e.Resolved,
		ResolvedAt:     e.ResolvedAt,
		ResolutionNote: e.ResolutionNote,
	}

	// Deep copy context
	if e.Context != nil {
		clone.Context = &ErrorContext{
			Component: e.Context.Component,
			Operation: e.Context.Operation,
			SessionID: e.Context.SessionID,
			AgentType: e.Context.AgentType,
			Stage:     e.Context.Stage,
			Iteration: e.Context.Iteration,
			RequestID: e.Context.RequestID,
			UserID:    e.Context.UserID,
			AlertID:   e.Context.AlertID,
		}
		if e.Context.Metadata != nil {
			clone.Context.Metadata = make(map[string]interface{})
			for k, v := range e.Context.Metadata {
				clone.Context.Metadata[k] = v
			}
		}
	}

	// Deep copy metadata
	if e.Metadata != nil {
		clone.Metadata = make(map[string]interface{})
		for k, v := range e.Metadata {
			clone.Metadata[k] = v
		}
	}

	// Deep copy stack trace
	if e.StackTrace != nil {
		clone.StackTrace = make([]StackFrame, len(e.StackTrace))
		copy(clone.StackTrace, e.StackTrace)
	}

	// Deep copy inner error
	if e.InnerError != nil {
		clone.InnerError = e.InnerError.Clone()
	}

	return clone
}

// WithContext adds or updates the error context
func (e *StructuredError) WithContext(ctx *ErrorContext) *StructuredError {
	clone := e.Clone()
	clone.Context = ctx
	return clone
}

// WithMetadata adds metadata to the error
func (e *StructuredError) WithMetadata(key string, value interface{}) *StructuredError {
	clone := e.Clone()
	if clone.Metadata == nil {
		clone.Metadata = make(map[string]interface{})
	}
	clone.Metadata[key] = value
	return clone
}

// WithRetryInfo adds retry information to the error
func (e *StructuredError) WithRetryInfo(attempt, maxRetries int) *StructuredError {
	clone := e.Clone()
	clone.RetryAttempt = attempt
	clone.MaxRetries = maxRetries
	return clone
}

// MarkResolved marks the error as resolved
func (e *StructuredError) MarkResolved(note string) {
	now := time.Now()
	e.Resolved = true
	e.ResolvedAt = &now
	e.ResolutionNote = note
}

// captureStackTrace captures the current stack trace
func captureStackTrace(skip int) []StackFrame {
	var frames []StackFrame

	// Capture up to 10 stack frames
	pcs := make([]uintptr, 10)
	n := runtime.Callers(skip+2, pcs) // +2 to skip this function and the caller

	if n > 0 {
		callersFrames := runtime.CallersFrames(pcs[:n])

		for {
			frame, more := callersFrames.Next()
			frames = append(frames, StackFrame{
				Function: frame.Function,
				File:     frame.File,
				Line:     frame.Line,
			})

			if !more {
				break
			}
		}
	}

	return frames
}

// generateErrorID generates a unique error ID
func generateErrorID() string {
	return fmt.Sprintf("err_%d", time.Now().UnixNano())
}

// NewStructuredError creates a new structured error
func NewStructuredError(code, message string, category ErrorCategory, severity ErrorSeverity) *StructuredError {
	return &StructuredError{
		Code:        code,
		Message:     message,
		Category:    category,
		Severity:    severity,
		Timestamp:   time.Now(),
		ErrorID:     generateErrorID(),
		Recoverable: true, // Default to recoverable
		StackTrace:  captureStackTrace(1),
	}
}

// WrapError wraps an existing error with structured error information
func WrapError(err error, code, message string, category ErrorCategory, severity ErrorSeverity) *StructuredError {
	se := NewStructuredError(code, message, category, severity)
	se.Cause = err

	// If the cause is also a StructuredError, make it the inner error
	if innerSE, ok := err.(*StructuredError); ok {
		se.InnerError = innerSE
	}

	return se
}

// IsRetryable checks if an error is retryable based on category and metadata
func IsRetryable(err error) bool {
	if se, ok := err.(*StructuredError); ok {
		if !se.Recoverable {
			return false
		}

		// Check if max retries exceeded
		if se.MaxRetries > 0 && se.RetryAttempt >= se.MaxRetries {
			return false
		}

		// Category-based retry logic
		switch se.Category {
		case ErrorCategoryTimeout, ErrorCategoryNetwork:
			return true
		case ErrorCategorySecurity, ErrorCategoryValidation:
			return false
		case ErrorCategoryLLM, ErrorCategoryMCP:
			return se.RecoveryAction == RecoveryActionRetry
		default:
			return se.RecoveryAction == RecoveryActionRetry
		}
	}

	return false
}

// GetErrorFromContext retrieves an error from context
func GetErrorFromContext(ctx context.Context) (*StructuredError, bool) {
	if err, ok := ctx.Value("structured_error").(*StructuredError); ok {
		return err, true
	}
	return nil, false
}

// ContextWithError adds an error to context
func ContextWithError(ctx context.Context, err *StructuredError) context.Context {
	return context.WithValue(ctx, "structured_error", err)
}