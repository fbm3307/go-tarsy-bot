package errors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CircuitState represents the state of a circuit breaker
type CircuitState string

const (
	CircuitStateClosed   CircuitState = "closed"   // Normal operation
	CircuitStateOpen     CircuitState = "open"     // Failing, requests rejected
	CircuitStateHalfOpen CircuitState = "half_open" // Testing if service recovered
)

// CircuitBreakerConfig contains configuration for a circuit breaker
type CircuitBreakerConfig struct {
	Name                  string        `json:"name"`
	FailureThreshold      int           `json:"failure_threshold"`       // Number of failures to trigger open state
	SuccessThreshold      int           `json:"success_threshold"`       // Number of successes to close from half-open
	Timeout               time.Duration `json:"timeout"`                 // How long to wait before trying half-open
	MaxRequestsHalfOpen   int           `json:"max_requests_half_open"`  // Max requests allowed in half-open state
	ResetTimeout          time.Duration `json:"reset_timeout"`           // How long to wait before resetting counters
	FailureRateThreshold  float64       `json:"failure_rate_threshold"`  // Failure rate threshold (0.0-1.0)
	MinimumRequestVolume  int           `json:"minimum_request_volume"`  // Minimum requests before calculating failure rate
}

// DefaultCircuitBreakerConfig returns default circuit breaker configuration
func DefaultCircuitBreakerConfig(name string) *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		Name:                 name,
		FailureThreshold:     5,
		SuccessThreshold:     3,
		Timeout:              60 * time.Second,
		MaxRequestsHalfOpen:  3,
		ResetTimeout:         300 * time.Second,
		FailureRateThreshold: 0.5, // 50% failure rate
		MinimumRequestVolume: 10,
	}
}

// CircuitBreakerMetrics contains metrics for a circuit breaker
type CircuitBreakerMetrics struct {
	TotalRequests     int64     `json:"total_requests"`
	SuccessfulRequests int64    `json:"successful_requests"`
	FailedRequests    int64     `json:"failed_requests"`
	RejectedRequests  int64     `json:"rejected_requests"`
	LastSuccessTime   time.Time `json:"last_success_time"`
	LastFailureTime   time.Time `json:"last_failure_time"`
	LastStateChange   time.Time `json:"last_state_change"`
	FailureRate       float64   `json:"failure_rate"`
}

// CircuitBreaker implements the circuit breaker pattern for resilient service calls
type CircuitBreaker struct {
	config   *CircuitBreakerConfig
	state    CircuitState
	metrics  *CircuitBreakerMetrics
	logger   *zap.Logger
	mutex    sync.RWMutex

	// State management
	consecutiveFailures int
	consecutiveSuccesses int
	halfOpenRequests    int
	lastFailureTime     time.Time
	stateChangedAt      time.Time

	// Request window for rate calculation
	requestWindow      []requestRecord
	windowMutex        sync.Mutex
}

// requestRecord represents a single request record for rate calculation
type requestRecord struct {
	timestamp time.Time
	success   bool
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *CircuitBreakerConfig, logger *zap.Logger) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig("default")
	}

	return &CircuitBreaker{
		config:          config,
		state:           CircuitStateClosed,
		metrics:         &CircuitBreakerMetrics{},
		logger:          logger.With(zap.String("circuit_breaker", config.Name)),
		requestWindow:   make([]requestRecord, 0),
		stateChangedAt:  time.Now(),
	}
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	// Check if request should be allowed
	if !cb.allowRequest() {
		cb.recordRejection()
		return NewStructuredError(
			"CIRCUIT_BREAKER_OPEN",
			fmt.Sprintf("Circuit breaker '%s' is open", cb.config.Name),
			ErrorCategoryNetwork,
			ErrorSeverityMedium,
		).WithMetadata("circuit_breaker_name", cb.config.Name).
			WithMetadata("circuit_state", string(cb.state))
	}

	// Execute the function
	startTime := time.Now()
	err := fn(ctx)
	duration := time.Since(startTime)

	// Record the result
	if err != nil {
		cb.recordFailure(err, duration)
		return cb.wrapError(err)
	} else {
		cb.recordSuccess(duration)
		return nil
	}
}

// allowRequest determines if a request should be allowed through the circuit breaker
func (cb *CircuitBreaker) allowRequest() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	switch cb.state {
	case CircuitStateClosed:
		return true
	case CircuitStateOpen:
		// Check if timeout has passed and we should transition to half-open
		if time.Since(cb.stateChangedAt) >= cb.config.Timeout {
			cb.mutex.RUnlock()
			cb.mutex.Lock()
			// Double-check state in case another goroutine changed it
			if cb.state == CircuitStateOpen && time.Since(cb.stateChangedAt) >= cb.config.Timeout {
				cb.transitionToHalfOpen()
			}
			cb.mutex.Unlock()
			cb.mutex.RLock()
			return cb.state == CircuitStateHalfOpen
		}
		return false
	case CircuitStateHalfOpen:
		return cb.halfOpenRequests < cb.config.MaxRequestsHalfOpen
	default:
		return false
	}
}

// recordSuccess records a successful request
func (cb *CircuitBreaker) recordSuccess(duration time.Duration) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.metrics.TotalRequests++
	cb.metrics.SuccessfulRequests++
	cb.metrics.LastSuccessTime = time.Now()

	cb.addToWindow(true)
	cb.updateFailureRate()

	switch cb.state {
	case CircuitStateClosed:
		cb.consecutiveFailures = 0
	case CircuitStateHalfOpen:
		cb.consecutiveSuccesses++
		cb.halfOpenRequests++
		if cb.consecutiveSuccesses >= cb.config.SuccessThreshold {
			cb.transitionToClosed()
		}
	}

	cb.logger.Debug("Circuit breaker recorded success",
		zap.String("state", string(cb.state)),
		zap.Duration("duration", duration),
		zap.Int("consecutive_successes", cb.consecutiveSuccesses))
}

// recordFailure records a failed request
func (cb *CircuitBreaker) recordFailure(err error, duration time.Duration) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.metrics.TotalRequests++
	cb.metrics.FailedRequests++
	cb.metrics.LastFailureTime = time.Now()
	cb.lastFailureTime = time.Now()

	cb.addToWindow(false)
	cb.updateFailureRate()

	switch cb.state {
	case CircuitStateClosed:
		cb.consecutiveFailures++
		cb.consecutiveSuccesses = 0
		if cb.shouldTransitionToOpen() {
			cb.transitionToOpen()
		}
	case CircuitStateHalfOpen:
		cb.halfOpenRequests++
		cb.transitionToOpen()
	}

	cb.logger.Warn("Circuit breaker recorded failure",
		zap.String("state", string(cb.state)),
		zap.Duration("duration", duration),
		zap.Int("consecutive_failures", cb.consecutiveFailures),
		zap.Error(err))
}

// recordRejection records a rejected request
func (cb *CircuitBreaker) recordRejection() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.metrics.RejectedRequests++

	cb.logger.Debug("Circuit breaker rejected request",
		zap.String("state", string(cb.state)))
}

// shouldTransitionToOpen determines if the circuit should transition to open state
func (cb *CircuitBreaker) shouldTransitionToOpen() bool {
	// Check consecutive failures threshold
	if cb.consecutiveFailures >= cb.config.FailureThreshold {
		return true
	}

	// Check failure rate threshold
	if cb.metrics.TotalRequests >= int64(cb.config.MinimumRequestVolume) {
		return cb.metrics.FailureRate >= cb.config.FailureRateThreshold
	}

	return false
}

// transitionToOpen transitions the circuit breaker to open state
func (cb *CircuitBreaker) transitionToOpen() {
	cb.state = CircuitStateOpen
	cb.stateChangedAt = time.Now()
	cb.metrics.LastStateChange = cb.stateChangedAt
	cb.consecutiveSuccesses = 0
	cb.halfOpenRequests = 0

	cb.logger.Warn("Circuit breaker transitioned to OPEN state",
		zap.Int("consecutive_failures", cb.consecutiveFailures),
		zap.Float64("failure_rate", cb.metrics.FailureRate))
}

// transitionToHalfOpen transitions the circuit breaker to half-open state
func (cb *CircuitBreaker) transitionToHalfOpen() {
	cb.state = CircuitStateHalfOpen
	cb.stateChangedAt = time.Now()
	cb.metrics.LastStateChange = cb.stateChangedAt
	cb.consecutiveSuccesses = 0
	cb.halfOpenRequests = 0

	cb.logger.Info("Circuit breaker transitioned to HALF-OPEN state")
}

// transitionToClosed transitions the circuit breaker to closed state
func (cb *CircuitBreaker) transitionToClosed() {
	cb.state = CircuitStateClosed
	cb.stateChangedAt = time.Now()
	cb.metrics.LastStateChange = cb.stateChangedAt
	cb.consecutiveFailures = 0
	cb.consecutiveSuccesses = 0
	cb.halfOpenRequests = 0

	cb.logger.Info("Circuit breaker transitioned to CLOSED state")
}

// addToWindow adds a request record to the sliding window
func (cb *CircuitBreaker) addToWindow(success bool) {
	cb.windowMutex.Lock()
	defer cb.windowMutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-cb.config.ResetTimeout)

	// Remove old records
	validRecords := make([]requestRecord, 0)
	for _, record := range cb.requestWindow {
		if record.timestamp.After(cutoff) {
			validRecords = append(validRecords, record)
		}
	}

	// Add new record
	validRecords = append(validRecords, requestRecord{
		timestamp: now,
		success:   success,
	})

	cb.requestWindow = validRecords
}

// updateFailureRate calculates the current failure rate
func (cb *CircuitBreaker) updateFailureRate() {
	cb.windowMutex.Lock()
	defer cb.windowMutex.Unlock()

	if len(cb.requestWindow) == 0 {
		cb.metrics.FailureRate = 0.0
		return
	}

	failures := 0
	for _, record := range cb.requestWindow {
		if !record.success {
			failures++
		}
	}

	cb.metrics.FailureRate = float64(failures) / float64(len(cb.requestWindow))
}

// wrapError wraps an error with circuit breaker context
func (cb *CircuitBreaker) wrapError(err error) error {
	if se, ok := err.(*StructuredError); ok {
		return se.WithMetadata("circuit_breaker_name", cb.config.Name).
			WithMetadata("circuit_state", string(cb.state))
	}

	return WrapError(err,
		"CIRCUIT_BREAKER_FAILURE",
		fmt.Sprintf("Request failed through circuit breaker '%s'", cb.config.Name),
		ErrorCategoryNetwork,
		ErrorSeverityMedium,
	).WithMetadata("circuit_breaker_name", cb.config.Name).
		WithMetadata("circuit_state", string(cb.state))
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// GetMetrics returns the current metrics of the circuit breaker
func (cb *CircuitBreaker) GetMetrics() *CircuitBreakerMetrics {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	// Return a copy to avoid race conditions
	return &CircuitBreakerMetrics{
		TotalRequests:      cb.metrics.TotalRequests,
		SuccessfulRequests: cb.metrics.SuccessfulRequests,
		FailedRequests:     cb.metrics.FailedRequests,
		RejectedRequests:   cb.metrics.RejectedRequests,
		LastSuccessTime:    cb.metrics.LastSuccessTime,
		LastFailureTime:    cb.metrics.LastFailureTime,
		LastStateChange:    cb.metrics.LastStateChange,
		FailureRate:        cb.metrics.FailureRate,
	}
}

// Reset resets the circuit breaker to closed state and clears metrics
func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.state = CircuitStateClosed
	cb.stateChangedAt = time.Now()
	cb.consecutiveFailures = 0
	cb.consecutiveSuccesses = 0
	cb.halfOpenRequests = 0
	cb.metrics = &CircuitBreakerMetrics{}

	cb.windowMutex.Lock()
	cb.requestWindow = make([]requestRecord, 0)
	cb.windowMutex.Unlock()

	cb.logger.Info("Circuit breaker reset")
}

// HealthCheck returns the health status of the circuit breaker
func (cb *CircuitBreaker) HealthCheck() map[string]interface{} {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	status := "healthy"
	if cb.state == CircuitStateOpen {
		status = "unhealthy"
	} else if cb.state == CircuitStateHalfOpen {
		status = "degraded"
	}

	return map[string]interface{}{
		"name":                 cb.config.Name,
		"status":               status,
		"state":                string(cb.state),
		"consecutive_failures": cb.consecutiveFailures,
		"consecutive_successes": cb.consecutiveSuccesses,
		"failure_rate":         cb.metrics.FailureRate,
		"last_state_change":    cb.stateChangedAt,
		"metrics":              cb.GetMetrics(),
	}
}