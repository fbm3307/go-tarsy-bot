package errors

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ResilienceConfig contains configuration for resilience patterns
type ResilienceConfig struct {
	RetryConfig         *RetryConfig         `json:"retry_config"`
	CircuitBreakerConfig *CircuitBreakerConfig `json:"circuit_breaker_config"`
	TimeoutConfig       *TimeoutConfig       `json:"timeout_config"`
	FallbackEnabled     bool                 `json:"fallback_enabled"`
	FallbackTimeout     time.Duration        `json:"fallback_timeout"`
}

// TimeoutConfig contains timeout configuration
type TimeoutConfig struct {
	DefaultTimeout    time.Duration `json:"default_timeout"`
	MaxTimeout        time.Duration `json:"max_timeout"`
	TimeoutMultiplier float64       `json:"timeout_multiplier"`
}

// DefaultResilienceConfig returns default resilience configuration
func DefaultResilienceConfig(name string) *ResilienceConfig {
	return &ResilienceConfig{
		RetryConfig:         DefaultRetryConfig(),
		CircuitBreakerConfig: DefaultCircuitBreakerConfig(name),
		TimeoutConfig: &TimeoutConfig{
			DefaultTimeout:    30 * time.Second,
			MaxTimeout:        5 * time.Minute,
			TimeoutMultiplier: 1.5,
		},
		FallbackEnabled: true,
		FallbackTimeout: 5 * time.Second,
	}
}

// FallbackFunc represents a fallback function to execute when primary function fails
type FallbackFunc func(context.Context, error) error

// ResilienceManager combines circuit breaker, retry, and fallback patterns
type ResilienceManager struct {
	config         *ResilienceConfig
	circuitBreaker *CircuitBreaker
	retryExecutor  *RetryExecutor
	logger         *zap.Logger
	fallbackFunc   FallbackFunc
	mutex          sync.RWMutex

	// Metrics
	totalExecutions     int64
	successfulExecutions int64
	failedExecutions    int64
	fallbackExecutions  int64
	lastExecutionTime   time.Time
}

// NewResilienceManager creates a new resilience manager
func NewResilienceManager(config *ResilienceConfig, logger *zap.Logger) *ResilienceManager {
	if config == nil {
		config = DefaultResilienceConfig("default")
	}

	return &ResilienceManager{
		config:         config,
		circuitBreaker: NewCircuitBreaker(config.CircuitBreakerConfig, logger),
		retryExecutor:  NewRetryExecutor(config.RetryConfig, logger),
		logger:         logger.With(zap.String("component", "resilience_manager")),
	}
}

// WithFallback sets a fallback function
func (rm *ResilienceManager) WithFallback(fallbackFunc FallbackFunc) *ResilienceManager {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.fallbackFunc = fallbackFunc
	return rm
}

// Execute executes a function with full resilience patterns (circuit breaker + retry + fallback)
func (rm *ResilienceManager) Execute(ctx context.Context, fn func(context.Context) error) error {
	rm.mutex.Lock()
	rm.totalExecutions++
	rm.lastExecutionTime = time.Now()
	rm.mutex.Unlock()

	// Apply timeout if configured
	executeCtx := ctx
	if rm.config.TimeoutConfig != nil && rm.config.TimeoutConfig.DefaultTimeout > 0 {
		var cancel context.CancelFunc
		executeCtx, cancel = context.WithTimeout(ctx, rm.config.TimeoutConfig.DefaultTimeout)
		defer cancel()
	}

	// Execute with circuit breaker protection
	err := rm.circuitBreaker.Execute(executeCtx, func(cbCtx context.Context) error {
		// Execute with retry logic
		return rm.retryExecutor.Execute(cbCtx, fn)
	})

	if err != nil {
		// Try fallback if enabled and available
		if rm.config.FallbackEnabled && rm.fallbackFunc != nil {
			rm.logger.Warn("Primary execution failed, trying fallback",
				zap.Error(err))

			fallbackErr := rm.executeFallback(ctx, err)
			if fallbackErr == nil {
				rm.mutex.Lock()
				rm.fallbackExecutions++
				rm.successfulExecutions++
				rm.mutex.Unlock()
				return nil
			}

			// Wrap fallback error with original error context
			rm.mutex.Lock()
			rm.failedExecutions++
			rm.mutex.Unlock()

			return WrapError(fallbackErr,
				"FALLBACK_FAILED",
				"Both primary execution and fallback failed",
				ErrorCategoryProcessing,
				ErrorSeverityHigh,
			).WithMetadata("original_error", err.Error()).
				WithMetadata("fallback_error", fallbackErr.Error())
		}

		rm.mutex.Lock()
		rm.failedExecutions++
		rm.mutex.Unlock()
		return err
	}

	rm.mutex.Lock()
	rm.successfulExecutions++
	rm.mutex.Unlock()
	return nil
}

// executeFallback executes the fallback function with timeout
func (rm *ResilienceManager) executeFallback(ctx context.Context, originalErr error) error {
	fallbackCtx := ctx
	if rm.config.FallbackTimeout > 0 {
		var cancel context.CancelFunc
		fallbackCtx, cancel = context.WithTimeout(ctx, rm.config.FallbackTimeout)
		defer cancel()
	}

	return rm.fallbackFunc(fallbackCtx, originalErr)
}

// ExecuteWithTimeout executes a function with a specific timeout
func (rm *ResilienceManager) ExecuteWithTimeout(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return rm.Execute(timeoutCtx, fn)
}

// ExecuteWithRetryOnly executes a function with only retry logic (no circuit breaker)
func (rm *ResilienceManager) ExecuteWithRetryOnly(ctx context.Context, fn func(context.Context) error) error {
	rm.mutex.Lock()
	rm.totalExecutions++
	rm.lastExecutionTime = time.Now()
	rm.mutex.Unlock()

	err := rm.retryExecutor.Execute(ctx, fn)

	if err != nil {
		rm.mutex.Lock()
		rm.failedExecutions++
		rm.mutex.Unlock()
		return err
	}

	rm.mutex.Lock()
	rm.successfulExecutions++
	rm.mutex.Unlock()
	return nil
}

// ExecuteWithCircuitBreakerOnly executes a function with only circuit breaker logic (no retry)
func (rm *ResilienceManager) ExecuteWithCircuitBreakerOnly(ctx context.Context, fn func(context.Context) error) error {
	rm.mutex.Lock()
	rm.totalExecutions++
	rm.lastExecutionTime = time.Now()
	rm.mutex.Unlock()

	err := rm.circuitBreaker.Execute(ctx, fn)

	if err != nil {
		rm.mutex.Lock()
		rm.failedExecutions++
		rm.mutex.Unlock()
		return err
	}

	rm.mutex.Lock()
	rm.successfulExecutions++
	rm.mutex.Unlock()
	return nil
}

// GetStatus returns the current status of the resilience manager
func (rm *ResilienceManager) GetStatus() map[string]interface{} {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	successRate := float64(0)
	if rm.totalExecutions > 0 {
		successRate = float64(rm.successfulExecutions) / float64(rm.totalExecutions)
	}

	fallbackRate := float64(0)
	if rm.totalExecutions > 0 {
		fallbackRate = float64(rm.fallbackExecutions) / float64(rm.totalExecutions)
	}

	return map[string]interface{}{
		"total_executions":      rm.totalExecutions,
		"successful_executions": rm.successfulExecutions,
		"failed_executions":     rm.failedExecutions,
		"fallback_executions":   rm.fallbackExecutions,
		"success_rate":          successRate,
		"fallback_rate":         fallbackRate,
		"last_execution_time":   rm.lastExecutionTime,
		"circuit_breaker":       rm.circuitBreaker.GetMetrics(),
		"retry_executor":        rm.retryExecutor.GetMetrics(),
		"circuit_breaker_health": rm.circuitBreaker.HealthCheck(),
	}
}

// HealthCheck returns the health status of the resilience manager
func (rm *ResilienceManager) HealthCheck() map[string]interface{} {
	status := rm.GetStatus()
	cbHealth := rm.circuitBreaker.HealthCheck()

	overallStatus := "healthy"
	if cbHealth["status"] == "unhealthy" {
		overallStatus = "unhealthy"
	} else if cbHealth["status"] == "degraded" {
		overallStatus = "degraded"
	}

	// Check success rate
	if successRate, ok := status["success_rate"].(float64); ok {
		if successRate < 0.5 { // Less than 50% success rate
			overallStatus = "degraded"
		}
	}

	return map[string]interface{}{
		"status":          overallStatus,
		"circuit_breaker": cbHealth,
		"metrics":         status,
	}
}

// Reset resets all components of the resilience manager
func (rm *ResilienceManager) Reset() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	rm.circuitBreaker.Reset()
	rm.retryExecutor.metrics = &RetryMetrics{}

	rm.totalExecutions = 0
	rm.successfulExecutions = 0
	rm.failedExecutions = 0
	rm.fallbackExecutions = 0

	rm.logger.Info("Resilience manager reset")
}

// ResilienceWrapper provides a high-level wrapper for common resilience patterns
type ResilienceWrapper struct {
	managers map[string]*ResilienceManager
	logger   *zap.Logger
	mutex    sync.RWMutex
}

// NewResilienceWrapper creates a new resilience wrapper
func NewResilienceWrapper(logger *zap.Logger) *ResilienceWrapper {
	return &ResilienceWrapper{
		managers: make(map[string]*ResilienceManager),
		logger:   logger,
	}
}

// GetOrCreateManager gets or creates a resilience manager for a service
func (rw *ResilienceWrapper) GetOrCreateManager(serviceName string, config *ResilienceConfig) *ResilienceManager {
	rw.mutex.RLock()
	if manager, exists := rw.managers[serviceName]; exists {
		rw.mutex.RUnlock()
		return manager
	}
	rw.mutex.RUnlock()

	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	// Double-check after acquiring write lock
	if manager, exists := rw.managers[serviceName]; exists {
		return manager
	}

	// Create new manager
	if config == nil {
		config = DefaultResilienceConfig(serviceName)
	}

	manager := NewResilienceManager(config, rw.logger.With(zap.String("service", serviceName)))
	rw.managers[serviceName] = manager

	return manager
}

// ExecuteForService executes a function with resilience patterns for a specific service
func (rw *ResilienceWrapper) ExecuteForService(ctx context.Context, serviceName string, fn func(context.Context) error) error {
	manager := rw.GetOrCreateManager(serviceName, nil)
	return manager.Execute(ctx, fn)
}

// ExecuteForServiceWithConfig executes a function with custom resilience configuration
func (rw *ResilienceWrapper) ExecuteForServiceWithConfig(ctx context.Context, serviceName string, config *ResilienceConfig, fn func(context.Context) error) error {
	manager := rw.GetOrCreateManager(serviceName, config)
	return manager.Execute(ctx, fn)
}

// GetAllStatus returns status for all managed services
func (rw *ResilienceWrapper) GetAllStatus() map[string]interface{} {
	rw.mutex.RLock()
	defer rw.mutex.RUnlock()

	status := make(map[string]interface{})
	for serviceName, manager := range rw.managers {
		status[serviceName] = manager.GetStatus()
	}

	return status
}

// HealthCheckAll returns health status for all managed services
func (rw *ResilienceWrapper) HealthCheckAll() map[string]interface{} {
	rw.mutex.RLock()
	defer rw.mutex.RUnlock()

	health := make(map[string]interface{})
	overallStatus := "healthy"

	for serviceName, manager := range rw.managers {
		serviceHealth := manager.HealthCheck()
		health[serviceName] = serviceHealth

		if serviceHealth["status"] == "unhealthy" {
			overallStatus = "unhealthy"
		} else if serviceHealth["status"] == "degraded" && overallStatus == "healthy" {
			overallStatus = "degraded"
		}
	}

	return map[string]interface{}{
		"overall_status": overallStatus,
		"services":       health,
		"service_count":  len(rw.managers),
	}
}