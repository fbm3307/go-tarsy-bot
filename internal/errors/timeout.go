package errors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// TimeoutManager manages timeouts and context propagation across the system
type TimeoutManager struct {
	config      *TimeoutManagerConfig
	logger      *zap.Logger
	activeTimers map[string]*TimeoutTimer
	mutex       sync.RWMutex

	// Metrics
	totalTimeouts    int64
	timeoutsByType   map[string]int64
	averageTimeout   time.Duration
	lastTimeoutTime  time.Time
}

// TimeoutManagerConfig contains configuration for timeout management
type TimeoutManagerConfig struct {
	DefaultTimeout     time.Duration            `json:"default_timeout"`
	MaxTimeout         time.Duration            `json:"max_timeout"`
	MinTimeout         time.Duration            `json:"min_timeout"`
	TimeoutMultipliers map[string]float64       `json:"timeout_multipliers"` // operation -> multiplier
	OperationTimeouts  map[string]time.Duration `json:"operation_timeouts"`  // operation -> timeout
	EnableTimeoutJitter bool                    `json:"enable_timeout_jitter"`
	JitterRange        float64                  `json:"jitter_range"`        // 0.0-1.0
	TimeoutEscalation  bool                     `json:"timeout_escalation"`  // Increase timeout on retry
	EscalationFactor   float64                  `json:"escalation_factor"`
}

// DefaultTimeoutManagerConfig returns default timeout manager configuration
func DefaultTimeoutManagerConfig() *TimeoutManagerConfig {
	return &TimeoutManagerConfig{
		DefaultTimeout:     30 * time.Second,
		MaxTimeout:         5 * time.Minute,
		MinTimeout:         1 * time.Second,
		EnableTimeoutJitter: true,
		JitterRange:        0.1, // 10% jitter
		TimeoutEscalation:  true,
		EscalationFactor:   1.5,
		TimeoutMultipliers: map[string]float64{
			"llm_request":     2.0,  // LLM requests take longer
			"mcp_tool":        1.5,  // MCP tool execution
			"database":        0.5,  // Database operations should be fast
			"websocket":       0.3,  // WebSocket operations should be very fast
			"health_check":    0.2,  // Health checks should be immediate
			"file_operation":  1.0,  // Standard file operations
			"network_request": 1.2,  // Network requests slightly longer
		},
		OperationTimeouts: map[string]time.Duration{
			"alert_processing":   10 * time.Minute,
			"agent_execution":    5 * time.Minute,
			"llm_generation":     2 * time.Minute,
			"mcp_tool_execution": 1 * time.Minute,
			"database_query":     10 * time.Second,
			"websocket_send":     5 * time.Second,
			"health_check":       3 * time.Second,
			"auth_validation":    5 * time.Second,
		},
	}
}

// TimeoutTimer tracks an active timeout
type TimeoutTimer struct {
	ID          string        `json:"id"`
	Operation   string        `json:"operation"`
	StartTime   time.Time     `json:"start_time"`
	Timeout     time.Duration `json:"timeout"`
	Context     context.Context `json:"-"`
	CancelFunc  context.CancelFunc `json:"-"`
	Escalations int           `json:"escalations"`
	UserID      string        `json:"user_id,omitempty"`
	SessionID   string        `json:"session_id,omitempty"`
	Component   string        `json:"component,omitempty"`
}

// TimeoutContext contains timeout-related context information
type TimeoutContext struct {
	Operation     string        `json:"operation"`
	OriginalTimeout time.Duration `json:"original_timeout"`
	CurrentTimeout  time.Duration `json:"current_timeout"`
	StartTime     time.Time     `json:"start_time"`
	Deadline      time.Time     `json:"deadline"`
	Escalations   int           `json:"escalations"`
	Component     string        `json:"component,omitempty"`
	UserID        string        `json:"user_id,omitempty"`
	SessionID     string        `json:"session_id,omitempty"`
}

// NewTimeoutManager creates a new timeout manager
func NewTimeoutManager(config *TimeoutManagerConfig, logger *zap.Logger) *TimeoutManager {
	if config == nil {
		config = DefaultTimeoutManagerConfig()
	}

	return &TimeoutManager{
		config:         config,
		logger:         logger.With(zap.String("component", "timeout_manager")),
		activeTimers:   make(map[string]*TimeoutTimer),
		timeoutsByType: make(map[string]int64),
	}
}

// CreateContext creates a context with timeout for a specific operation
func (tm *TimeoutManager) CreateContext(parent context.Context, operation string) (context.Context, context.CancelFunc) {
	timeout := tm.calculateTimeout(operation, 0)
	return tm.CreateContextWithTimeout(parent, operation, timeout)
}

// CreateContextWithTimeout creates a context with a specific timeout
func (tm *TimeoutManager) CreateContextWithTimeout(parent context.Context, operation string, timeout time.Duration) (context.Context, context.CancelFunc) {
	// Apply jitter if enabled
	if tm.config.EnableTimeoutJitter {
		timeout = tm.applyJitter(timeout)
	}

	// Enforce min/max limits
	timeout = tm.enforceTimeoutLimits(timeout)

	ctx, cancel := context.WithTimeout(parent, timeout)

	// Create timeout timer for tracking
	timer := &TimeoutTimer{
		ID:        fmt.Sprintf("timeout_%d", time.Now().UnixNano()),
		Operation: operation,
		StartTime: time.Now(),
		Timeout:   timeout,
		Context:   ctx,
		CancelFunc: cancel,
	}

	// Extract context information if available
	if userID, ok := ctx.Value("user_id").(string); ok {
		timer.UserID = userID
	}
	if sessionID, ok := ctx.Value("session_id").(string); ok {
		timer.SessionID = sessionID
	}
	if component, ok := ctx.Value("component").(string); ok {
		timer.Component = component
	}

	// Register timer
	tm.mutex.Lock()
	tm.activeTimers[timer.ID] = timer
	tm.mutex.Unlock()

	// Create enhanced cancel function
	enhancedCancel := func() {
		tm.unregisterTimer(timer.ID)
		cancel()
	}

	// Add timeout context to the context
	timeoutCtx := &TimeoutContext{
		Operation:       operation,
		OriginalTimeout: timeout,
		CurrentTimeout:  timeout,
		StartTime:       timer.StartTime,
		Deadline:        timer.StartTime.Add(timeout),
		Component:       timer.Component,
		UserID:          timer.UserID,
		SessionID:       timer.SessionID,
	}

	enrichedCtx := context.WithValue(ctx, "timeout_context", timeoutCtx)

	tm.logger.Debug("Created timeout context",
		zap.String("operation", operation),
		zap.Duration("timeout", timeout),
		zap.String("timer_id", timer.ID))

	return enrichedCtx, enhancedCancel
}

// CreateEscalatedContext creates a context with escalated timeout for retry operations
func (tm *TimeoutManager) CreateEscalatedContext(parent context.Context, operation string, escalationLevel int) (context.Context, context.CancelFunc) {
	baseTimeout := tm.calculateTimeout(operation, 0)
	escalatedTimeout := tm.calculateTimeout(operation, escalationLevel)

	ctx, cancel := tm.CreateContextWithTimeout(parent, operation, escalatedTimeout)

	// Update timeout context with escalation info
	if timeoutCtx, ok := ctx.Value("timeout_context").(*TimeoutContext); ok {
		timeoutCtx.Escalations = escalationLevel
		timeoutCtx.CurrentTimeout = escalatedTimeout
		timeoutCtx.OriginalTimeout = baseTimeout
		ctx = context.WithValue(ctx, "timeout_context", timeoutCtx)
	}

	tm.logger.Debug("Created escalated timeout context",
		zap.String("operation", operation),
		zap.Duration("base_timeout", baseTimeout),
		zap.Duration("escalated_timeout", escalatedTimeout),
		zap.Int("escalation_level", escalationLevel))

	return ctx, cancel
}

// calculateTimeout calculates timeout for an operation with optional escalation
func (tm *TimeoutManager) calculateTimeout(operation string, escalationLevel int) time.Duration {
	var timeout time.Duration

	// Check for specific operation timeout
	if opTimeout, exists := tm.config.OperationTimeouts[operation]; exists {
		timeout = opTimeout
	} else {
		// Use default timeout with multiplier
		timeout = tm.config.DefaultTimeout
		if multiplier, exists := tm.config.TimeoutMultipliers[operation]; exists {
			timeout = time.Duration(float64(timeout) * multiplier)
		}
	}

	// Apply escalation if enabled and requested
	if tm.config.TimeoutEscalation && escalationLevel > 0 {
		for i := 0; i < escalationLevel; i++ {
			timeout = time.Duration(float64(timeout) * tm.config.EscalationFactor)
		}
	}

	return timeout
}

// applyJitter applies random jitter to timeout to avoid thundering herd
func (tm *TimeoutManager) applyJitter(timeout time.Duration) time.Duration {
	if tm.config.JitterRange <= 0 {
		return timeout
	}

	jitterAmount := float64(timeout) * tm.config.JitterRange
	// Apply ±jitter
	jitter := (2.0*(float64(time.Now().UnixNano()%1000)/1000.0) - 1.0) * jitterAmount

	newTimeout := time.Duration(float64(timeout) + jitter)

	// Ensure timeout is not negative
	if newTimeout < 0 {
		newTimeout = timeout / 2
	}

	return newTimeout
}

// enforceTimeoutLimits ensures timeout is within configured limits
func (tm *TimeoutManager) enforceTimeoutLimits(timeout time.Duration) time.Duration {
	if timeout < tm.config.MinTimeout {
		return tm.config.MinTimeout
	}
	if timeout > tm.config.MaxTimeout {
		return tm.config.MaxTimeout
	}
	return timeout
}

// unregisterTimer removes a timer from active tracking
func (tm *TimeoutManager) unregisterTimer(timerID string) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if timer, exists := tm.activeTimers[timerID]; exists {
		// Check if it timed out
		if timer.Context.Err() == context.DeadlineExceeded {
			tm.totalTimeouts++
			tm.timeoutsByType[timer.Operation]++
			tm.lastTimeoutTime = time.Now()

			tm.logger.Warn("Operation timed out",
				zap.String("operation", timer.Operation),
				zap.Duration("timeout", timer.Timeout),
				zap.Duration("elapsed", time.Since(timer.StartTime)),
				zap.String("timer_id", timerID))
		}

		delete(tm.activeTimers, timerID)
	}
}

// CheckTimeout checks if a context has timed out and returns appropriate error
func (tm *TimeoutManager) CheckTimeout(ctx context.Context) error {
	if ctx.Err() == context.DeadlineExceeded {
		var operation string = "unknown"
		var component string
		var timeout time.Duration

		if timeoutCtx, ok := ctx.Value("timeout_context").(*TimeoutContext); ok {
			operation = timeoutCtx.Operation
			component = timeoutCtx.Component
			timeout = timeoutCtx.CurrentTimeout
		}

		se := NewStructuredError(
			"OPERATION_TIMEOUT",
			fmt.Sprintf("Operation '%s' timed out", operation),
			ErrorCategoryTimeout,
			ErrorSeverityMedium,
		)

		if component != "" {
			se = se.WithContext(&ErrorContext{
				Component: component,
				Operation: operation,
			})
		}

		se = se.WithMetadata("timeout_duration", timeout.String()).
			WithMetadata("operation", operation)

		se.RecoveryAction = RecoveryActionRetry
		se.Recoverable = true

		return se
	}

	if ctx.Err() == context.Canceled {
		return NewStructuredError(
			"OPERATION_CANCELLED",
			"Operation was cancelled",
			ErrorCategoryProcessing,
			ErrorSeverityLow,
		)
	}

	return ctx.Err()
}

// GetActiveTimers returns information about all active timers
func (tm *TimeoutManager) GetActiveTimers() []TimeoutTimer {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	timers := make([]TimeoutTimer, 0, len(tm.activeTimers))
	for _, timer := range tm.activeTimers {
		// Create copy without context to avoid circular references
		timerCopy := TimeoutTimer{
			ID:          timer.ID,
			Operation:   timer.Operation,
			StartTime:   timer.StartTime,
			Timeout:     timer.Timeout,
			Escalations: timer.Escalations,
			UserID:      timer.UserID,
			SessionID:   timer.SessionID,
			Component:   timer.Component,
		}
		timers = append(timers, timerCopy)
	}

	return timers
}

// GetTimeoutStatistics returns timeout statistics
func (tm *TimeoutManager) GetTimeoutStatistics() map[string]interface{} {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_timeouts":    tm.totalTimeouts,
		"timeouts_by_type":  tm.timeoutsByType,
		"active_timers":     len(tm.activeTimers),
		"last_timeout_time": tm.lastTimeoutTime,
		"config":            tm.config,
	}

	// Calculate timeout rates
	if tm.totalTimeouts > 0 {
		timeoutRates := make(map[string]float64)
		var totalOperations int64

		for _, count := range tm.timeoutsByType {
			totalOperations += count
		}

		for operation, timeoutCount := range tm.timeoutsByType {
			if totalOperations > 0 {
				timeoutRates[operation] = float64(timeoutCount) / float64(totalOperations)
			}
		}

		stats["timeout_rates"] = timeoutRates
	}

	return stats
}

// HealthCheck returns health status of the timeout manager
func (tm *TimeoutManager) HealthCheck() map[string]interface{} {
	stats := tm.GetTimeoutStatistics()
	timers := tm.GetActiveTimers()

	status := "healthy"
	issues := make([]string, 0)

	// Check for excessive active timers
	if len(timers) > 100 {
		status = "degraded"
		issues = append(issues, "high number of active timers")
	}

	// Check for recent timeout spikes
	recentTimeouts := int64(0)
	for _, count := range tm.timeoutsByType {
		recentTimeouts += count
	}

	if recentTimeouts > 50 {
		status = "degraded"
		issues = append(issues, "high timeout rate")
	}

	// Check for stuck timers (running for too long)
	now := time.Now()
	stuckTimers := 0
	for _, timer := range timers {
		if now.Sub(timer.StartTime) > timer.Timeout*2 {
			stuckTimers++
		}
	}

	if stuckTimers > 0 {
		status = "unhealthy"
		issues = append(issues, fmt.Sprintf("%d stuck timers detected", stuckTimers))
	}

	return map[string]interface{}{
		"status":        status,
		"issues":        issues,
		"active_timers": len(timers),
		"statistics":    stats,
	}
}

// CancelAllTimers cancels all active timers (for shutdown)
func (tm *TimeoutManager) CancelAllTimers() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	for timerID, timer := range tm.activeTimers {
		timer.CancelFunc()
		delete(tm.activeTimers, timerID)
	}

	tm.logger.Info("All timeout timers cancelled")
}

// GetTimeoutContext retrieves timeout context from a context
func GetTimeoutContext(ctx context.Context) (*TimeoutContext, bool) {
	if timeoutCtx, ok := ctx.Value("timeout_context").(*TimeoutContext); ok {
		return timeoutCtx, true
	}
	return nil, false
}

// WithTimeoutContext adds timeout context to a context
func WithTimeoutContext(ctx context.Context, timeoutCtx *TimeoutContext) context.Context {
	return context.WithValue(ctx, "timeout_context", timeoutCtx)
}

// IsTimeoutError checks if an error is a timeout error
func IsTimeoutError(err error) bool {
	if err == context.DeadlineExceeded {
		return true
	}

	if se, ok := err.(*StructuredError); ok {
		return se.Category == ErrorCategoryTimeout
	}

	return false
}

// TimeoutWrapper provides convenient timeout management for functions
type TimeoutWrapper struct {
	timeoutManager *TimeoutManager
	logger         *zap.Logger
}

// NewTimeoutWrapper creates a new timeout wrapper
func NewTimeoutWrapper(timeoutManager *TimeoutManager, logger *zap.Logger) *TimeoutWrapper {
	return &TimeoutWrapper{
		timeoutManager: timeoutManager,
		logger:         logger,
	}
}

// WithTimeout executes a function with timeout
func (tw *TimeoutWrapper) WithTimeout(parent context.Context, operation string, fn func(context.Context) error) error {
	ctx, cancel := tw.timeoutManager.CreateContext(parent, operation)
	defer cancel()

	err := fn(ctx)
	if err != nil {
		return tw.timeoutManager.CheckTimeout(ctx)
	}

	return nil
}

// WithTimeoutAndEscalation executes a function with timeout and escalation support
func (tw *TimeoutWrapper) WithTimeoutAndEscalation(parent context.Context, operation string, escalationLevel int, fn func(context.Context) error) error {
	ctx, cancel := tw.timeoutManager.CreateEscalatedContext(parent, operation, escalationLevel)
	defer cancel()

	err := fn(ctx)
	if err != nil {
		timeoutErr := tw.timeoutManager.CheckTimeout(ctx)
		if timeoutErr != nil {
			return timeoutErr
		}
		return err
	}

	return nil
}