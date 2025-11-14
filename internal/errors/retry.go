package errors

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"go.uber.org/zap"
)

// BackoffStrategy represents different backoff strategies for retries
type BackoffStrategy string

const (
	BackoffStrategyExponential BackoffStrategy = "exponential"
	BackoffStrategyLinear      BackoffStrategy = "linear"
	BackoffStrategyFixed       BackoffStrategy = "fixed"
	BackoffStrategyCustom      BackoffStrategy = "custom"
)

// RetryConfig contains configuration for retry behavior
type RetryConfig struct {
	MaxAttempts       int             `json:"max_attempts"`
	InitialDelay      time.Duration   `json:"initial_delay"`
	MaxDelay          time.Duration   `json:"max_delay"`
	Multiplier        float64         `json:"multiplier"`
	Strategy          BackoffStrategy `json:"strategy"`
	Jitter            bool            `json:"jitter"`
	JitterRange       float64         `json:"jitter_range"`        // 0.0-1.0
	RetryableErrors   []ErrorCategory `json:"retryable_errors"`
	NonRetryableErrors []ErrorCategory `json:"non_retryable_errors"`
	TimeoutMultiplier float64         `json:"timeout_multiplier"`  // Multiplier for timeout on retry

	// Custom backoff function (when Strategy is Custom)
	CustomBackoffFunc func(attempt int, baseDelay time.Duration) time.Duration `json:"-"`

	// Retry condition function - return true if error should be retried
	RetryConditionFunc func(error) bool `json:"-"`
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:       3,
		InitialDelay:      1 * time.Second,
		MaxDelay:          30 * time.Second,
		Multiplier:        2.0,
		Strategy:          BackoffStrategyExponential,
		Jitter:            true,
		JitterRange:       0.1, // 10% jitter
		TimeoutMultiplier: 1.5,
		RetryableErrors: []ErrorCategory{
			ErrorCategoryTimeout,
			ErrorCategoryNetwork,
			ErrorCategoryLLM,
			ErrorCategoryMCP,
		},
		NonRetryableErrors: []ErrorCategory{
			ErrorCategorySecurity,
			ErrorCategoryValidation,
			ErrorCategoryAuth,
		},
	}
}

// RetryMetrics contains metrics about retry operations
type RetryMetrics struct {
	TotalAttempts     int           `json:"total_attempts"`
	SuccessfulRetries int           `json:"successful_retries"`
	FailedRetries     int           `json:"failed_retries"`
	TotalDelay        time.Duration `json:"total_delay"`
	AverageDelay      time.Duration `json:"average_delay"`
	LastAttemptTime   time.Time     `json:"last_attempt_time"`
}

// RetryExecutor handles retry logic with various backoff strategies
type RetryExecutor struct {
	config  *RetryConfig
	logger  *zap.Logger
	metrics *RetryMetrics
}

// NewRetryExecutor creates a new retry executor
func NewRetryExecutor(config *RetryConfig, logger *zap.Logger) *RetryExecutor {
	if config == nil {
		config = DefaultRetryConfig()
	}

	return &RetryExecutor{
		config:  config,
		logger:  logger,
		metrics: &RetryMetrics{},
	}
}

// Execute executes a function with retry logic
func (r *RetryExecutor) Execute(ctx context.Context, fn func(context.Context) error) error {
	var lastErr error
	var totalDelay time.Duration

	for attempt := 1; attempt <= r.config.MaxAttempts; attempt++ {
		// Create context with timeout multiplier for retries
		attemptCtx := ctx
		if attempt > 1 && r.config.TimeoutMultiplier > 1.0 {
			if deadline, ok := ctx.Deadline(); ok {
				originalTimeout := time.Until(deadline)
				newTimeout := time.Duration(float64(originalTimeout) * r.config.TimeoutMultiplier)
				var cancel context.CancelFunc
				attemptCtx, cancel = context.WithTimeout(context.Background(), newTimeout)
				defer cancel()
			}
		}

		// Execute the function
		startTime := time.Now()
		err := fn(attemptCtx)
		duration := time.Since(startTime)

		r.metrics.TotalAttempts++
		r.metrics.LastAttemptTime = time.Now()

		if err == nil {
			// Success
			if attempt > 1 {
				r.metrics.SuccessfulRetries++
				r.logger.Info("Retry succeeded",
					zap.Int("attempt", attempt),
					zap.Duration("total_delay", totalDelay),
					zap.Duration("attempt_duration", duration))
			}
			return nil
		}

		// Check if we should retry this error
		if !r.shouldRetry(err, attempt) {
			r.logger.Debug("Error not retryable",
				zap.Int("attempt", attempt),
				zap.Error(err),
				zap.String("reason", "error_type_not_retryable"))
			return r.wrapFinalError(err, attempt, totalDelay)
		}

		// Check if we've exhausted all attempts
		if attempt >= r.config.MaxAttempts {
			r.metrics.FailedRetries++
			r.logger.Error("All retry attempts exhausted",
				zap.Int("max_attempts", r.config.MaxAttempts),
				zap.Duration("total_delay", totalDelay),
				zap.Error(err))
			return r.wrapFinalError(err, attempt, totalDelay)
		}

		// Calculate delay for next attempt
		delay := r.calculateDelay(attempt)
		totalDelay += delay

		r.logger.Warn("Attempt failed, retrying",
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", r.config.MaxAttempts),
			zap.Duration("delay", delay),
			zap.Duration("total_delay", totalDelay),
			zap.Error(err))

		// Wait before next attempt
		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-ctx.Done():
			return ctx.Err()
		}

		lastErr = err
	}

	return r.wrapFinalError(lastErr, r.config.MaxAttempts, totalDelay)
}

// shouldRetry determines if an error should be retried
func (r *RetryExecutor) shouldRetry(err error, attempt int) bool {
	// Check custom retry condition first
	if r.config.RetryConditionFunc != nil {
		return r.config.RetryConditionFunc(err)
	}

	// Check if it's a structured error
	if se, ok := err.(*StructuredError); ok {
		// Check if explicitly non-retryable
		for _, category := range r.config.NonRetryableErrors {
			if se.Category == category {
				return false
			}
		}

		// Check if explicitly retryable
		for _, category := range r.config.RetryableErrors {
			if se.Category == category {
				return true
			}
		}

		// Check structured error's retry information
		if se.MaxRetries > 0 && attempt >= se.MaxRetries {
			return false
		}

		return se.Recoverable && (se.RecoveryAction == RecoveryActionRetry || se.RecoveryAction == "")
	}

	// For non-structured errors, use default retryable categories
	return true // Conservative approach - retry by default
}

// calculateDelay calculates the delay for the next retry attempt
func (r *RetryExecutor) calculateDelay(attempt int) time.Duration {
	var delay time.Duration

	switch r.config.Strategy {
	case BackoffStrategyExponential:
		delay = r.calculateExponentialDelay(attempt)
	case BackoffStrategyLinear:
		delay = r.calculateLinearDelay(attempt)
	case BackoffStrategyFixed:
		delay = r.config.InitialDelay
	case BackoffStrategyCustom:
		if r.config.CustomBackoffFunc != nil {
			delay = r.config.CustomBackoffFunc(attempt, r.config.InitialDelay)
		} else {
			delay = r.calculateExponentialDelay(attempt) // Fallback
		}
	default:
		delay = r.calculateExponentialDelay(attempt) // Default to exponential
	}

	// Apply maximum delay limit
	if delay > r.config.MaxDelay {
		delay = r.config.MaxDelay
	}

	// Apply jitter if enabled
	if r.config.Jitter {
		delay = r.applyJitter(delay)
	}

	return delay
}

// calculateExponentialDelay calculates exponential backoff delay
func (r *RetryExecutor) calculateExponentialDelay(attempt int) time.Duration {
	// delay = initial_delay * (multiplier ^ (attempt - 1))
	multiplier := math.Pow(r.config.Multiplier, float64(attempt-1))
	delay := time.Duration(float64(r.config.InitialDelay) * multiplier)
	return delay
}

// calculateLinearDelay calculates linear backoff delay
func (r *RetryExecutor) calculateLinearDelay(attempt int) time.Duration {
	// delay = initial_delay * attempt
	delay := time.Duration(int64(r.config.InitialDelay) * int64(attempt))
	return delay
}

// applyJitter applies jitter to the delay to avoid thundering herd
func (r *RetryExecutor) applyJitter(delay time.Duration) time.Duration {
	if r.config.JitterRange <= 0 {
		return delay
	}

	// Calculate jitter range
	jitterAmount := float64(delay) * r.config.JitterRange

	// Apply random jitter (±jitter_range)
	jitter := (rand.Float64() - 0.5) * 2 * jitterAmount

	newDelay := time.Duration(float64(delay) + jitter)

	// Ensure delay is not negative
	if newDelay < 0 {
		newDelay = delay / 2
	}

	return newDelay
}

// wrapFinalError wraps the final error with retry context
func (r *RetryExecutor) wrapFinalError(err error, attempts int, totalDelay time.Duration) error {
	if se, ok := err.(*StructuredError); ok {
		return se.WithMetadata("retry_attempts", attempts).
			WithMetadata("total_retry_delay", totalDelay.String()).
			WithMetadata("retry_exhausted", true)
	}

	return WrapError(err,
		"RETRY_EXHAUSTED",
		fmt.Sprintf("All retry attempts (%d) exhausted", attempts),
		ErrorCategoryProcessing,
		ErrorSeverityHigh,
	).WithMetadata("retry_attempts", attempts).
		WithMetadata("total_retry_delay", totalDelay.String()).
		WithMetadata("retry_exhausted", true)
}

// GetMetrics returns the current retry metrics
func (r *RetryExecutor) GetMetrics() *RetryMetrics {
	if r.metrics.TotalAttempts > 0 {
		r.metrics.AverageDelay = r.metrics.TotalDelay / time.Duration(r.metrics.TotalAttempts)
	}

	return &RetryMetrics{
		TotalAttempts:     r.metrics.TotalAttempts,
		SuccessfulRetries: r.metrics.SuccessfulRetries,
		FailedRetries:     r.metrics.FailedRetries,
		TotalDelay:        r.metrics.TotalDelay,
		AverageDelay:      r.metrics.AverageDelay,
		LastAttemptTime:   r.metrics.LastAttemptTime,
	}
}

// RetryableFunc is a convenience function for simple retry operations
func RetryableFunc(ctx context.Context, config *RetryConfig, logger *zap.Logger, fn func(context.Context) error) error {
	executor := NewRetryExecutor(config, logger)
	return executor.Execute(ctx, fn)
}

// ExponentialBackoff is a convenience function for exponential backoff retry
func ExponentialBackoff(ctx context.Context, maxAttempts int, initialDelay time.Duration, fn func(context.Context) error) error {
	config := &RetryConfig{
		MaxAttempts:  maxAttempts,
		InitialDelay: initialDelay,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Strategy:     BackoffStrategyExponential,
		Jitter:       true,
		JitterRange:  0.1,
	}

	executor := NewRetryExecutor(config, zap.NewNop())
	return executor.Execute(ctx, fn)
}

// LinearBackoff is a convenience function for linear backoff retry
func LinearBackoff(ctx context.Context, maxAttempts int, delay time.Duration, fn func(context.Context) error) error {
	config := &RetryConfig{
		MaxAttempts:  maxAttempts,
		InitialDelay: delay,
		MaxDelay:     30 * time.Second,
		Strategy:     BackoffStrategyLinear,
		Jitter:       true,
		JitterRange:  0.1,
	}

	executor := NewRetryExecutor(config, zap.NewNop())
	return executor.Execute(ctx, fn)
}

// FixedDelay is a convenience function for fixed delay retry
func FixedDelay(ctx context.Context, maxAttempts int, delay time.Duration, fn func(context.Context) error) error {
	config := &RetryConfig{
		MaxAttempts:  maxAttempts,
		InitialDelay: delay,
		MaxDelay:     delay,
		Strategy:     BackoffStrategyFixed,
		Jitter:       false,
	}

	executor := NewRetryExecutor(config, zap.NewNop())
	return executor.Execute(ctx, fn)
}