package agents

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	ErrorSeverityLow      ErrorSeverity = "low"
	ErrorSeverityMedium   ErrorSeverity = "medium"
	ErrorSeverityHigh     ErrorSeverity = "high"
	ErrorSeverityCritical ErrorSeverity = "critical"
)

// ErrorCategory represents the category of error
type ErrorCategory string

const (
	ErrorCategoryConfiguration ErrorCategory = "configuration"
	ErrorCategoryLLM          ErrorCategory = "llm"
	ErrorCategoryMCP          ErrorCategory = "mcp"
	ErrorCategoryValidation   ErrorCategory = "validation"
	ErrorCategoryTimeout      ErrorCategory = "timeout"
	ErrorCategoryNetwork      ErrorCategory = "network"
	ErrorCategoryPermission   ErrorCategory = "permission"
	ErrorCategoryResource     ErrorCategory = "resource"
	ErrorCategoryIteration    ErrorCategory = "iteration"
	ErrorCategoryProcessing   ErrorCategory = "processing"
	ErrorCategoryRecoverable  ErrorCategory = "recoverable"
	ErrorCategoryFatal        ErrorCategory = "fatal"
)

// ErrorCode represents specific error codes for categorization
type ErrorCode string

const (
	// Configuration errors
	ErrorCodeInvalidConfig      ErrorCode = "INVALID_CONFIG"
	ErrorCodeMissingConfig      ErrorCode = "MISSING_CONFIG"
	ErrorCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"

	// LLM errors
	ErrorCodeLLMConnectionFailed ErrorCode = "LLM_CONNECTION_FAILED"
	ErrorCodeLLMRateLimited      ErrorCode = "LLM_RATE_LIMITED"
	ErrorCodeLLMInvalidResponse  ErrorCode = "LLM_INVALID_RESPONSE"
	ErrorCodeLLMTokenLimitExceeded ErrorCode = "LLM_TOKEN_LIMIT_EXCEEDED"

	// MCP errors
	ErrorCodeMCPServerNotFound    ErrorCode = "MCP_SERVER_NOT_FOUND"
	ErrorCodeMCPToolNotFound      ErrorCode = "MCP_TOOL_NOT_FOUND"
	ErrorCodeMCPExecutionFailed   ErrorCode = "MCP_EXECUTION_FAILED"
	ErrorCodeMCPConnectionLost    ErrorCode = "MCP_CONNECTION_LOST"

	// Processing errors
	ErrorCodeMaxIterationsReached ErrorCode = "MAX_ITERATIONS_REACHED"
	ErrorCodeTimeoutExceeded      ErrorCode = "TIMEOUT_EXCEEDED"
	ErrorCodeValidationFailed     ErrorCode = "VALIDATION_FAILED"
	ErrorCodeProcessingFailed     ErrorCode = "PROCESSING_FAILED"

	// Agent errors
	ErrorCodeAgentNotFound        ErrorCode = "AGENT_NOT_FOUND"
	ErrorCodeAgentInitFailed      ErrorCode = "AGENT_INIT_FAILED"
	ErrorCodeChainExecutionFailed ErrorCode = "CHAIN_EXECUTION_FAILED"
)

// StructuredException represents a comprehensive error with recovery information
type StructuredException struct {
	// Core error information
	Code        ErrorCode     `json:"code"`
	Category    ErrorCategory `json:"category"`
	Severity    ErrorSeverity `json:"severity"`
	Message     string        `json:"message"`
	Cause       error         `json:"cause,omitempty"`

	// Context information
	AgentType       string                 `json:"agent_type,omitempty"`
	SessionID       string                 `json:"session_id,omitempty"`
	Stage           string                 `json:"stage,omitempty"`
	Iteration       int                    `json:"iteration,omitempty"`
	Context         map[string]interface{} `json:"context,omitempty"`

	// Recovery information
	IsRecoverable   bool          `json:"is_recoverable"`
	RecoveryActions []string      `json:"recovery_actions,omitempty"`
	RetryAfter      time.Duration `json:"retry_after,omitempty"`
	MaxRetries      int           `json:"max_retries,omitempty"`

	// Metadata
	Timestamp time.Time `json:"timestamp"`
	StackTrace string   `json:"stack_trace,omitempty"`
	RequestID  string   `json:"request_id,omitempty"`
}

// Error implements the error interface
func (e *StructuredException) Error() string {
	parts := []string{
		fmt.Sprintf("[%s:%s]", e.Category, e.Code),
		e.Message,
	}

	if e.AgentType != "" {
		parts = append(parts, fmt.Sprintf("(agent: %s)", e.AgentType))
	}

	if e.Stage != "" {
		parts = append(parts, fmt.Sprintf("(stage: %s)", e.Stage))
	}

	if e.Iteration > 0 {
		parts = append(parts, fmt.Sprintf("(iteration: %d)", e.Iteration))
	}

	return strings.Join(parts, " ")
}

// Unwrap returns the underlying cause for error wrapping
func (e *StructuredException) Unwrap() error {
	return e.Cause
}

// IsType checks if the error is of a specific type
func (e *StructuredException) IsType(category ErrorCategory) bool {
	return e.Category == category
}

// IsCode checks if the error has a specific code
func (e *StructuredException) IsCode(code ErrorCode) bool {
	return e.Code == code
}

// IsSeverity checks if the error has a specific severity
func (e *StructuredException) IsSeverity(severity ErrorSeverity) bool {
	return e.Severity == severity
}

// CanRetry returns whether this error can be retried
func (e *StructuredException) CanRetry() bool {
	return e.IsRecoverable && len(e.RecoveryActions) > 0
}

// AddContext adds context information to the error
func (e *StructuredException) AddContext(key string, value interface{}) {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
}

// AddRecoveryAction adds a recovery action
func (e *StructuredException) AddRecoveryAction(action string) {
	e.RecoveryActions = append(e.RecoveryActions, action)
}

// WithAgent adds agent context to the error
func (e *StructuredException) WithAgent(agentType string) *StructuredException {
	e.AgentType = agentType
	return e
}

// WithSession adds session context to the error
func (e *StructuredException) WithSession(sessionID string) *StructuredException {
	e.SessionID = sessionID
	return e
}

// WithStage adds stage context to the error
func (e *StructuredException) WithStage(stage string) *StructuredException {
	e.Stage = stage
	return e
}

// WithIteration adds iteration context to the error
func (e *StructuredException) WithIteration(iteration int) *StructuredException {
	e.Iteration = iteration
	return e
}

// ErrorRecoveryStrategy defines how to recover from specific errors
type ErrorRecoveryStrategy struct {
	ErrorCodes      []ErrorCode           `json:"error_codes"`
	RecoveryActions []RecoveryAction      `json:"recovery_actions"`
	MaxRetries      int                   `json:"max_retries"`
	BackoffStrategy BackoffStrategy       `json:"backoff_strategy"`
	FallbackAgent   string                `json:"fallback_agent,omitempty"`
	SkipStage       bool                  `json:"skip_stage,omitempty"`
}

// RecoveryAction represents an action to take for error recovery
type RecoveryAction struct {
	Type        string                 `json:"type"`        // "retry", "fallback", "skip", "reconfigure"
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
}

// BackoffStrategy defines retry backoff behavior
type BackoffStrategy struct {
	Type         string        `json:"type"`          // "fixed", "exponential", "linear"
	InitialDelay time.Duration `json:"initial_delay"`
	MaxDelay     time.Duration `json:"max_delay"`
	Multiplier   float64       `json:"multiplier,omitempty"`
}

// ErrorRecoveryManager manages error recovery strategies
type ErrorRecoveryManager struct {
	strategies map[ErrorCode]*ErrorRecoveryStrategy
	globalStrategy *ErrorRecoveryStrategy
}

// NewErrorRecoveryManager creates a new error recovery manager
func NewErrorRecoveryManager() *ErrorRecoveryManager {
	manager := &ErrorRecoveryManager{
		strategies: make(map[ErrorCode]*ErrorRecoveryStrategy),
	}

	manager.loadDefaultStrategies()
	return manager
}

// loadDefaultStrategies loads default recovery strategies
func (erm *ErrorRecoveryManager) loadDefaultStrategies() {
	// LLM rate limiting strategy
	erm.RegisterStrategy(&ErrorRecoveryStrategy{
		ErrorCodes: []ErrorCode{ErrorCodeLLMRateLimited},
		RecoveryActions: []RecoveryAction{
			{
				Type:        "retry",
				Description: "Wait and retry with exponential backoff",
				Timeout:     5 * time.Minute,
			},
		},
		MaxRetries: 3,
		BackoffStrategy: BackoffStrategy{
			Type:         "exponential",
			InitialDelay: 30 * time.Second,
			MaxDelay:     5 * time.Minute,
			Multiplier:   2.0,
		},
	})

	// MCP connection issues
	erm.RegisterStrategy(&ErrorRecoveryStrategy{
		ErrorCodes: []ErrorCode{ErrorCodeMCPConnectionLost, ErrorCodeMCPServerNotFound},
		RecoveryActions: []RecoveryAction{
			{
				Type:        "reconfigure",
				Description: "Reconfigure MCP connection",
				Timeout:     30 * time.Second,
			},
			{
				Type:        "fallback",
				Description: "Use alternative MCP server or continue without tools",
				Timeout:     10 * time.Second,
			},
		},
		MaxRetries: 2,
		BackoffStrategy: BackoffStrategy{
			Type:         "fixed",
			InitialDelay: 10 * time.Second,
		},
	})

	// Timeout errors
	erm.RegisterStrategy(&ErrorRecoveryStrategy{
		ErrorCodes: []ErrorCode{ErrorCodeTimeoutExceeded},
		RecoveryActions: []RecoveryAction{
			{
				Type:        "retry",
				Description: "Retry with increased timeout",
				Parameters: map[string]interface{}{
					"timeout_multiplier": 2.0,
				},
				Timeout: 10 * time.Minute,
			},
		},
		MaxRetries: 2,
		BackoffStrategy: BackoffStrategy{
			Type:         "linear",
			InitialDelay: 1 * time.Minute,
			MaxDelay:     5 * time.Minute,
		},
	})

	// Max iterations reached
	erm.RegisterStrategy(&ErrorRecoveryStrategy{
		ErrorCodes: []ErrorCode{ErrorCodeMaxIterationsReached},
		RecoveryActions: []RecoveryAction{
			{
				Type:        "fallback",
				Description: "Use simpler processing strategy",
				Parameters: map[string]interface{}{
					"strategy": "simple",
				},
			},
		},
		MaxRetries: 1,
	})

	// Global fallback strategy
	erm.globalStrategy = &ErrorRecoveryStrategy{
		ErrorCodes: []ErrorCode{}, // Applies to all uncategorized errors
		RecoveryActions: []RecoveryAction{
			{
				Type:        "skip",
				Description: "Skip current operation and continue",
			},
		},
		MaxRetries: 1,
	}
}

// RegisterStrategy registers a recovery strategy for specific error codes
func (erm *ErrorRecoveryManager) RegisterStrategy(strategy *ErrorRecoveryStrategy) {
	for _, code := range strategy.ErrorCodes {
		erm.strategies[code] = strategy
	}
}

// GetRecoveryStrategy returns the recovery strategy for an error
func (erm *ErrorRecoveryManager) GetRecoveryStrategy(err *StructuredException) *ErrorRecoveryStrategy {
	if strategy, exists := erm.strategies[err.Code]; exists {
		return strategy
	}
	return erm.globalStrategy
}

// CanRecover checks if an error can be recovered from
func (erm *ErrorRecoveryManager) CanRecover(err *StructuredException) bool {
	strategy := erm.GetRecoveryStrategy(err)
	return strategy != nil && len(strategy.RecoveryActions) > 0
}

// Factory functions for creating structured exceptions

// NewConfigurationError creates a configuration error
func NewConfigurationError(code ErrorCode, message string, cause error) *StructuredException {
	return &StructuredException{
		Code:        code,
		Category:    ErrorCategoryConfiguration,
		Severity:    ErrorSeverityHigh,
		Message:     message,
		Cause:       cause,
		Timestamp:   time.Now(),
		StackTrace:  getStackTrace(),
		IsRecoverable: code != ErrorCodeInvalidCredentials,
	}
}

// NewLLMError creates an LLM-related error
func NewLLMError(code ErrorCode, message string, cause error) *StructuredException {
	severity := ErrorSeverityMedium
	recoverable := true

	switch code {
	case ErrorCodeLLMConnectionFailed:
		severity = ErrorSeverityHigh
	case ErrorCodeLLMTokenLimitExceeded:
		severity = ErrorSeverityCritical
		recoverable = false
	}

	return &StructuredException{
		Code:        code,
		Category:    ErrorCategoryLLM,
		Severity:    severity,
		Message:     message,
		Cause:       cause,
		Timestamp:   time.Now(),
		StackTrace:  getStackTrace(),
		IsRecoverable: recoverable,
	}
}

// NewMCPError creates an MCP-related error
func NewMCPError(code ErrorCode, message string, cause error) *StructuredException {
	return &StructuredException{
		Code:        code,
		Category:    ErrorCategoryMCP,
		Severity:    ErrorSeverityMedium,
		Message:     message,
		Cause:       cause,
		Timestamp:   time.Now(),
		StackTrace:  getStackTrace(),
		IsRecoverable: true,
	}
}

// NewProcessingError creates a processing-related error
func NewProcessingError(code ErrorCode, message string, cause error) *StructuredException {
	severity := ErrorSeverityMedium
	recoverable := true

	switch code {
	case ErrorCodeMaxIterationsReached:
		severity = ErrorSeverityHigh
	case ErrorCodeTimeoutExceeded:
		severity = ErrorSeverityHigh
	case ErrorCodeValidationFailed:
		severity = ErrorSeverityCritical
		recoverable = false
	}

	return &StructuredException{
		Code:        code,
		Category:    ErrorCategoryProcessing,
		Severity:    severity,
		Message:     message,
		Cause:       cause,
		Timestamp:   time.Now(),
		StackTrace:  getStackTrace(),
		IsRecoverable: recoverable,
	}
}

// NewTimeoutError creates a timeout error
func NewTimeoutError(message string, timeout time.Duration) *StructuredException {
	return &StructuredException{
		Code:        ErrorCodeTimeoutExceeded,
		Category:    ErrorCategoryTimeout,
		Severity:    ErrorSeverityHigh,
		Message:     message,
		Timestamp:   time.Now(),
		StackTrace:  getStackTrace(),
		IsRecoverable: true,
		Context: map[string]interface{}{
			"timeout_duration": timeout.String(),
		},
	}
}

// NewStructuredAgentError creates an agent-specific structured error
func NewStructuredAgentError(code ErrorCode, message string, agentType string, cause error) *StructuredException {
	return &StructuredException{
		Code:        code,
		Category:    ErrorCategoryProcessing,
		Severity:    ErrorSeverityHigh,
		Message:     message,
		Cause:       cause,
		AgentType:   agentType,
		Timestamp:   time.Now(),
		StackTrace:  getStackTrace(),
		IsRecoverable: true,
	}
}

// Wrap wraps an existing error as a structured exception
func Wrap(err error, code ErrorCode, category ErrorCategory, message string) *StructuredException {
	return &StructuredException{
		Code:        code,
		Category:    category,
		Severity:    ErrorSeverityMedium,
		Message:     message,
		Cause:       err,
		Timestamp:   time.Now(),
		StackTrace:  getStackTrace(),
		IsRecoverable: true,
	}
}

// IsStructuredException checks if an error is a structured exception
func IsStructuredException(err error) (*StructuredException, bool) {
	if structErr, ok := err.(*StructuredException); ok {
		return structErr, true
	}
	return nil, false
}

// getStackTrace captures the current stack trace
func getStackTrace() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// ErrorLogger provides structured error logging
type ErrorLogger struct {
	errors []ErrorEntry
}

// ErrorEntry represents a logged error entry
type ErrorEntry struct {
	Error     *StructuredException `json:"error"`
	Timestamp time.Time            `json:"timestamp"`
	Resolved  bool                 `json:"resolved"`
	Actions   []string             `json:"actions_taken,omitempty"`
}

// NewErrorLogger creates a new error logger
func NewErrorLogger() *ErrorLogger {
	return &ErrorLogger{
		errors: make([]ErrorEntry, 0),
	}
}

// LogError logs a structured exception
func (el *ErrorLogger) LogError(err *StructuredException) {
	entry := ErrorEntry{
		Error:     err,
		Timestamp: time.Now(),
		Resolved:  false,
	}
	el.errors = append(el.errors, entry)
}

// MarkResolved marks an error as resolved
func (el *ErrorLogger) MarkResolved(err *StructuredException, actions []string) {
	for i := range el.errors {
		if el.errors[i].Error == err {
			el.errors[i].Resolved = true
			el.errors[i].Actions = actions
			break
		}
	}
}

// GetUnresolvedErrors returns all unresolved errors
func (el *ErrorLogger) GetUnresolvedErrors() []*StructuredException {
	var unresolved []*StructuredException
	for _, entry := range el.errors {
		if !entry.Resolved {
			unresolved = append(unresolved, entry.Error)
		}
	}
	return unresolved
}

// GetErrorsByCategory returns errors by category
func (el *ErrorLogger) GetErrorsByCategory(category ErrorCategory) []*StructuredException {
	var filtered []*StructuredException
	for _, entry := range el.errors {
		if entry.Error.Category == category {
			filtered = append(filtered, entry.Error)
		}
	}
	return filtered
}

// GetErrorStats returns error statistics
func (el *ErrorLogger) GetErrorStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_errors":      len(el.errors),
		"unresolved_errors": len(el.GetUnresolvedErrors()),
		"by_category":       make(map[ErrorCategory]int),
		"by_severity":       make(map[ErrorSeverity]int),
		"by_code":           make(map[ErrorCode]int),
	}

	categoryStats := stats["by_category"].(map[ErrorCategory]int)
	severityStats := stats["by_severity"].(map[ErrorSeverity]int)
	codeStats := stats["by_code"].(map[ErrorCode]int)

	for _, entry := range el.errors {
		categoryStats[entry.Error.Category]++
		severityStats[entry.Error.Severity]++
		codeStats[entry.Error.Code]++
	}

	return stats
}