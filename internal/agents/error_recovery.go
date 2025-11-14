package agents

import (
	"context"
	"fmt"
	"math"
	"time"

	"go.uber.org/zap"
)

// RecoveryHandler handles error recovery for agent processing
type RecoveryHandler struct {
	recoveryManager *ErrorRecoveryManager
	errorLogger     *ErrorLogger
	logger          *zap.Logger
	maxRetryAttempts int
}

// NewRecoveryHandler creates a new recovery handler
func NewRecoveryHandler(logger *zap.Logger) *RecoveryHandler {
	return &RecoveryHandler{
		recoveryManager:  NewErrorRecoveryManager(),
		errorLogger:      NewErrorLogger(),
		logger:           logger,
		maxRetryAttempts: 3,
	}
}

// RecoveryContext contains context for error recovery
type RecoveryContext struct {
	AgentType       string
	SessionID       string
	Stage           string
	Iteration       int
	AttemptNumber   int
	OriginalError   *StructuredException
	PreviousActions []string
}

// RecoveryResult represents the result of error recovery
type RecoveryResult struct {
	Success        bool                 `json:"success"`
	Action         string               `json:"action"`
	NewStrategy    string               `json:"new_strategy,omitempty"`
	FallbackAgent  string               `json:"fallback_agent,omitempty"`
	SkipStage      bool                 `json:"skip_stage,omitempty"`
	RetryAfter     time.Duration        `json:"retry_after,omitempty"`
	ModifiedConfig map[string]interface{} `json:"modified_config,omitempty"`
	Message        string               `json:"message"`
}

// HandleError handles an error with recovery strategies
func (rh *RecoveryHandler) HandleError(ctx context.Context, err *StructuredException, recoveryCtx *RecoveryContext) (*RecoveryResult, error) {
	// Log the error
	rh.errorLogger.LogError(err)

	rh.logger.Error("Processing error occurred",
		zap.String("code", string(err.Code)),
		zap.String("category", string(err.Category)),
		zap.String("severity", string(err.Severity)),
		zap.String("agent_type", recoveryCtx.AgentType),
		zap.String("session_id", recoveryCtx.SessionID),
		zap.String("stage", recoveryCtx.Stage),
		zap.Int("iteration", recoveryCtx.Iteration),
		zap.Int("attempt", recoveryCtx.AttemptNumber),
		zap.Error(err),
	)

	// Check if recovery is possible
	if !rh.recoveryManager.CanRecover(err) {
		return &RecoveryResult{
			Success: false,
			Action:  "no_recovery",
			Message: fmt.Sprintf("No recovery strategy available for error: %s", err.Code),
		}, nil
	}

	// Get recovery strategy
	strategy := rh.recoveryManager.GetRecoveryStrategy(err)
	if strategy == nil {
		return &RecoveryResult{
			Success: false,
			Action:  "no_strategy",
			Message: "No recovery strategy found for error",
		}, nil
	}

	// Check if we've exceeded max retries
	if recoveryCtx.AttemptNumber >= strategy.MaxRetries {
		return &RecoveryResult{
			Success: false,
			Action:  "max_retries_exceeded",
			Message: fmt.Sprintf("Maximum retries (%d) exceeded for error recovery", strategy.MaxRetries),
		}, nil
	}

	// Execute recovery actions
	for _, action := range strategy.RecoveryActions {
		result, execErr := rh.executeRecoveryAction(ctx, action, err, recoveryCtx, strategy)
		if execErr != nil {
			rh.logger.Warn("Recovery action failed",
				zap.String("action", action.Type),
				zap.Error(execErr),
			)
			continue
		}

		if result.Success {
			// Mark error as resolved
			rh.errorLogger.MarkResolved(err, append(recoveryCtx.PreviousActions, action.Type))

			rh.logger.Info("Error recovery successful",
				zap.String("action", action.Type),
				zap.String("error_code", string(err.Code)),
				zap.String("session_id", recoveryCtx.SessionID),
			)

			return result, nil
		}
	}

	// All recovery actions failed
	return &RecoveryResult{
		Success: false,
		Action:  "all_actions_failed",
		Message: "All recovery actions failed",
	}, nil
}

// executeRecoveryAction executes a specific recovery action
func (rh *RecoveryHandler) executeRecoveryAction(
	ctx context.Context,
	action RecoveryAction,
	originalErr *StructuredException,
	recoveryCtx *RecoveryContext,
	strategy *ErrorRecoveryStrategy,
) (*RecoveryResult, error) {

	switch action.Type {
	case "retry":
		return rh.handleRetryAction(ctx, action, originalErr, recoveryCtx, strategy)

	case "fallback":
		return rh.handleFallbackAction(ctx, action, originalErr, recoveryCtx, strategy)

	case "skip":
		return rh.handleSkipAction(ctx, action, originalErr, recoveryCtx, strategy)

	case "reconfigure":
		return rh.handleReconfigureAction(ctx, action, originalErr, recoveryCtx, strategy)

	default:
		return nil, fmt.Errorf("unknown recovery action type: %s", action.Type)
	}
}

// handleRetryAction handles retry recovery action
func (rh *RecoveryHandler) handleRetryAction(
	ctx context.Context,
	action RecoveryAction,
	originalErr *StructuredException,
	recoveryCtx *RecoveryContext,
	strategy *ErrorRecoveryStrategy,
) (*RecoveryResult, error) {

	// Calculate backoff delay
	delay := rh.calculateBackoffDelay(strategy.BackoffStrategy, recoveryCtx.AttemptNumber)

	rh.logger.Info("Scheduling retry for error recovery",
		zap.String("error_code", string(originalErr.Code)),
		zap.Duration("delay", delay),
		zap.Int("attempt", recoveryCtx.AttemptNumber+1),
	)

	// Determine if we should apply configuration changes
	modifiedConfig := make(map[string]interface{})

	// Apply timeout multiplier if specified
	if multiplier, exists := action.Parameters["timeout_multiplier"]; exists {
		if mult, ok := multiplier.(float64); ok {
			modifiedConfig["timeout_multiplier"] = mult
		}
	}

	// Apply max iterations increase if needed
	if originalErr.Code == ErrorCodeMaxIterationsReached {
		modifiedConfig["max_iterations_increase"] = 5
	}

	return &RecoveryResult{
		Success:        true,
		Action:         "retry",
		RetryAfter:     delay,
		ModifiedConfig: modifiedConfig,
		Message:        fmt.Sprintf("Retry scheduled after %v (attempt %d)", delay, recoveryCtx.AttemptNumber+1),
	}, nil
}

// handleFallbackAction handles fallback recovery action
func (rh *RecoveryHandler) handleFallbackAction(
	ctx context.Context,
	action RecoveryAction,
	originalErr *StructuredException,
	recoveryCtx *RecoveryContext,
	strategy *ErrorRecoveryStrategy,
) (*RecoveryResult, error) {

	modifiedConfig := make(map[string]interface{})

	switch originalErr.Code {
	case ErrorCodeLLMConnectionFailed, ErrorCodeLLMRateLimited:
		// Fallback to simpler processing
		return &RecoveryResult{
			Success:        true,
			Action:         "fallback",
			NewStrategy:    "simple",
			ModifiedConfig: modifiedConfig,
			Message:        "Falling back to simple processing strategy due to LLM issues",
		}, nil

	case ErrorCodeMCPConnectionLost, ErrorCodeMCPServerNotFound:
		// Continue without MCP tools
		modifiedConfig["disable_mcp"] = true
		return &RecoveryResult{
			Success:        true,
			Action:         "fallback",
			ModifiedConfig: modifiedConfig,
			Message:        "Continuing without MCP tools due to connection issues",
		}, nil

	case ErrorCodeMaxIterationsReached:
		// Use fallback processing strategy
		if strategyParam, exists := action.Parameters["strategy"]; exists {
			if strategy, ok := strategyParam.(string); ok {
				return &RecoveryResult{
					Success:     true,
					Action:      "fallback",
					NewStrategy: strategy,
					Message:     fmt.Sprintf("Switching to %s strategy due to iteration limit", strategy),
				}, nil
			}
		}

	case ErrorCodeAgentNotFound, ErrorCodeAgentInitFailed:
		// Use fallback agent if specified
		if strategy.FallbackAgent != "" {
			return &RecoveryResult{
				Success:       true,
				Action:        "fallback",
				FallbackAgent: strategy.FallbackAgent,
				Message:       fmt.Sprintf("Using fallback agent: %s", strategy.FallbackAgent),
			}, nil
		}
	}

	return &RecoveryResult{
		Success: false,
		Action:  "fallback",
		Message: "No suitable fallback strategy available",
	}, nil
}

// handleSkipAction handles skip recovery action
func (rh *RecoveryHandler) handleSkipAction(
	ctx context.Context,
	action RecoveryAction,
	originalErr *StructuredException,
	recoveryCtx *RecoveryContext,
	strategy *ErrorRecoveryStrategy,
) (*RecoveryResult, error) {

	// Determine what to skip based on error context
	skipStage := false
	message := "Skipping current operation and continuing"

	if recoveryCtx.Stage != "" {
		skipStage = true
		message = fmt.Sprintf("Skipping stage '%s' due to error", recoveryCtx.Stage)
	}

	rh.logger.Warn("Skipping operation due to error",
		zap.String("error_code", string(originalErr.Code)),
		zap.String("stage", recoveryCtx.Stage),
		zap.Bool("skip_stage", skipStage),
	)

	return &RecoveryResult{
		Success:   true,
		Action:    "skip",
		SkipStage: skipStage,
		Message:   message,
	}, nil
}

// handleReconfigureAction handles reconfigure recovery action
func (rh *RecoveryHandler) handleReconfigureAction(
	ctx context.Context,
	action RecoveryAction,
	originalErr *StructuredException,
	recoveryCtx *RecoveryContext,
	strategy *ErrorRecoveryStrategy,
) (*RecoveryResult, error) {

	modifiedConfig := make(map[string]interface{})

	switch originalErr.Code {
	case ErrorCodeMCPConnectionLost:
		// Reconfigure MCP connection settings
		modifiedConfig["mcp_reconnect"] = true
		modifiedConfig["mcp_timeout"] = "60s"
		return &RecoveryResult{
			Success:        true,
			Action:         "reconfigure",
			ModifiedConfig: modifiedConfig,
			Message:        "Reconfiguring MCP connection with extended timeout",
		}, nil

	case ErrorCodeLLMConnectionFailed:
		// Reconfigure LLM connection
		modifiedConfig["llm_timeout"] = "120s"
		modifiedConfig["llm_retry_attempts"] = 5
		return &RecoveryResult{
			Success:        true,
			Action:         "reconfigure",
			ModifiedConfig: modifiedConfig,
			Message:        "Reconfiguring LLM connection with extended settings",
		}, nil

	case ErrorCodeTimeoutExceeded:
		// Increase timeout values
		if multiplier, exists := action.Parameters["timeout_multiplier"]; exists {
			modifiedConfig["timeout_multiplier"] = multiplier
		} else {
			modifiedConfig["timeout_multiplier"] = 2.0
		}
		return &RecoveryResult{
			Success:        true,
			Action:         "reconfigure",
			ModifiedConfig: modifiedConfig,
			Message:        "Reconfiguring with increased timeout values",
		}, nil
	}

	return &RecoveryResult{
		Success: false,
		Action:  "reconfigure",
		Message: "No reconfiguration strategy available for this error",
	}, nil
}

// calculateBackoffDelay calculates the delay for retry backoff
func (rh *RecoveryHandler) calculateBackoffDelay(strategy BackoffStrategy, attemptNumber int) time.Duration {
	switch strategy.Type {
	case "exponential":
		delay := time.Duration(float64(strategy.InitialDelay) * math.Pow(strategy.Multiplier, float64(attemptNumber)))
		if delay > strategy.MaxDelay {
			delay = strategy.MaxDelay
		}
		return delay

	case "linear":
		delay := strategy.InitialDelay * time.Duration(attemptNumber+1)
		if delay > strategy.MaxDelay {
			delay = strategy.MaxDelay
		}
		return delay

	case "fixed":
		return strategy.InitialDelay

	default:
		return strategy.InitialDelay
	}
}

// RegisterCustomStrategy allows registering custom recovery strategies
func (rh *RecoveryHandler) RegisterCustomStrategy(strategy *ErrorRecoveryStrategy) {
	rh.recoveryManager.RegisterStrategy(strategy)
}

// GetErrorStatistics returns error statistics from the logger
func (rh *RecoveryHandler) GetErrorStatistics() map[string]interface{} {
	return rh.errorLogger.GetErrorStats()
}

// GetUnresolvedErrors returns all unresolved errors
func (rh *RecoveryHandler) GetUnresolvedErrors() []*StructuredException {
	return rh.errorLogger.GetUnresolvedErrors()
}

// ShouldRetry determines if an operation should be retried based on error and context
func (rh *RecoveryHandler) ShouldRetry(err *StructuredException, attemptNumber int) bool {
	if !err.IsRecoverable {
		return false
	}

	strategy := rh.recoveryManager.GetRecoveryStrategy(err)
	if strategy == nil {
		return false
	}

	return attemptNumber < strategy.MaxRetries
}

// ProcessingWrapper wraps agent processing with error recovery
type ProcessingWrapper struct {
	recoveryHandler *RecoveryHandler
	logger          *zap.Logger
}

// NewProcessingWrapper creates a new processing wrapper with error recovery
func NewProcessingWrapper(logger *zap.Logger) *ProcessingWrapper {
	return &ProcessingWrapper{
		recoveryHandler: NewRecoveryHandler(logger),
		logger:          logger,
	}
}

// WrapWithRecovery wraps a processing function with error recovery logic
func (pw *ProcessingWrapper) WrapWithRecovery(
	ctx context.Context,
	agentType, sessionID, stage string,
	processingFunc func(ctx context.Context) error,
) error {

	var lastError *StructuredException
	attemptNumber := 0

	for {
		// Create recovery context
		recoveryCtx := &RecoveryContext{
			AgentType:     agentType,
			SessionID:     sessionID,
			Stage:         stage,
			AttemptNumber: attemptNumber,
		}

		// Execute the processing function
		err := processingFunc(ctx)
		if err == nil {
			// Success - clear any previous errors
			if lastError != nil {
				pw.recoveryHandler.errorLogger.MarkResolved(lastError, []string{"retry_successful"})
			}
			return nil
		}

		// Convert to structured exception if needed
		var structErr *StructuredException
		if se, ok := IsStructuredException(err); ok {
			structErr = se
		} else {
			// Wrap as generic processing error
			structErr = NewProcessingError(ErrorCodeProcessingFailed, err.Error(), err).
				WithAgent(agentType).
				WithSession(sessionID).
				WithStage(stage)
		}

		lastError = structErr

		// Check if we should attempt recovery
		if !pw.recoveryHandler.ShouldRetry(structErr, attemptNumber) {
			pw.logger.Error("Processing failed with no recovery options",
				zap.String("agent_type", agentType),
				zap.String("session_id", sessionID),
				zap.String("stage", stage),
				zap.Int("attempts", attemptNumber+1),
				zap.Error(structErr),
			)
			return structErr
		}

		// Attempt recovery
		recoveryResult, recoveryErr := pw.recoveryHandler.HandleError(ctx, structErr, recoveryCtx)
		if recoveryErr != nil {
			pw.logger.Error("Error recovery failed",
				zap.String("session_id", sessionID),
				zap.Error(recoveryErr),
			)
			return structErr
		}

		if !recoveryResult.Success {
			pw.logger.Error("Error recovery unsuccessful",
				zap.String("action", recoveryResult.Action),
				zap.String("message", recoveryResult.Message),
			)
			return structErr
		}

		// Handle recovery result
		switch recoveryResult.Action {
		case "retry":
			if recoveryResult.RetryAfter > 0 {
				pw.logger.Info("Waiting before retry",
					zap.Duration("delay", recoveryResult.RetryAfter),
				)
				select {
				case <-time.After(recoveryResult.RetryAfter):
					// Continue with retry
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			attemptNumber++
			continue

		case "skip":
			pw.logger.Info("Skipping operation due to recovery strategy",
				zap.String("message", recoveryResult.Message),
			)
			return nil // Skip is considered success

		case "fallback":
			// This would need to be handled by the caller
			// Return a special error type that indicates fallback is needed
			return &StructuredException{
				Code:     ErrorCodeProcessingFailed,
				Category: ErrorCategoryRecoverable,
				Message:  "Fallback required: " + recoveryResult.Message,
				Context: map[string]interface{}{
					"recovery_result": recoveryResult,
				},
				IsRecoverable: false, // Don't retry this
			}

		default:
			return structErr
		}
	}
}