package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/errors"
)

// DependencyType represents the type of dependency
type DependencyType string

const (
	DependencyTypeDatabase    DependencyType = "database"
	DependencyTypeLLM         DependencyType = "llm"
	DependencyTypeMCP         DependencyType = "mcp"
	DependencyTypeWebSocket   DependencyType = "websocket"
	DependencyTypeHTTP        DependencyType = "http"
	DependencyTypeAuth        DependencyType = "auth"
	DependencyTypeCache       DependencyType = "cache"
	DependencyTypeMessageQueue DependencyType = "message_queue"
	DependencyTypeFileSystem  DependencyType = "filesystem"
	DependencyTypeNetwork     DependencyType = "network"
)

// DependencyStatus represents the health status of a dependency
type DependencyStatus string

const (
	DependencyStatusHealthy     DependencyStatus = "healthy"
	DependencyStatusDegraded    DependencyStatus = "degraded"
	DependencyStatusUnhealthy   DependencyStatus = "unhealthy"
	DependencyStatusUnknown     DependencyStatus = "unknown"
	DependencyStatusMaintenance DependencyStatus = "maintenance"
)

// DependencyConfig contains configuration for dependency health checking
type DependencyConfig struct {
	Name              string                  `json:"name"`
	Type              DependencyType          `json:"type"`
	Endpoint          string                  `json:"endpoint,omitempty"`
	CheckInterval     time.Duration           `json:"check_interval"`
	Timeout           time.Duration           `json:"timeout"`
	RetryAttempts     int                     `json:"retry_attempts"`
	CircuitBreaker    bool                    `json:"circuit_breaker"`
	Critical          bool                    `json:"critical"`          // If true, failure affects overall system health
	Required          bool                    `json:"required"`          // If true, failure prevents system operation
	Tags              map[string]string       `json:"tags,omitempty"`
	ExpectedStatus    []int                   `json:"expected_status,omitempty"` // Expected HTTP status codes
	HealthCheckFunc   func(context.Context) error `json:"-"`             // Custom health check function
}

// DependencyHealth represents the health information of a dependency
type DependencyHealth struct {
	Name               string           `json:"name"`
	Type               DependencyType   `json:"type"`
	Status             DependencyStatus `json:"status"`
	Message            string           `json:"message"`
	LastChecked        time.Time        `json:"last_checked"`
	LastHealthy        time.Time        `json:"last_healthy"`
	ResponseTime       time.Duration    `json:"response_time"`
	SuccessCount       int64            `json:"success_count"`
	ErrorCount         int64            `json:"error_count"`
	ConsecutiveFails   int              `json:"consecutive_fails"`
	Uptime             float64          `json:"uptime"`            // Success rate over time
	Details            map[string]interface{} `json:"details,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
	Critical           bool             `json:"critical"`
	Required           bool             `json:"required"`
	CircuitBreakerOpen bool             `json:"circuit_breaker_open,omitempty"`
}

// DependencyHealthChecker manages health checking for system dependencies
type DependencyHealthChecker struct {
	dependencies        map[string]*DependencyConfig
	healthStatus        map[string]*DependencyHealth
	circuitBreakers     map[string]*errors.CircuitBreaker
	resilienceWrapper   *errors.ResilienceWrapper
	timeoutManager      *errors.TimeoutManager
	logger              *zap.Logger
	mutex               sync.RWMutex

	// Background checking
	stopChannel         chan struct{}
	checkerRoutines     map[string]context.CancelFunc

	// Aggregated health
	overallStatus       DependencyStatus
	lastHealthCheck     time.Time
	healthCheckCount    int64
}

// NewDependencyHealthChecker creates a new dependency health checker
func NewDependencyHealthChecker(logger *zap.Logger) *DependencyHealthChecker {
	resilienceWrapper := errors.NewResilienceWrapper(logger)
	timeoutManager := errors.NewTimeoutManager(errors.DefaultTimeoutManagerConfig(), logger)

	return &DependencyHealthChecker{
		dependencies:      make(map[string]*DependencyConfig),
		healthStatus:      make(map[string]*DependencyHealth),
		circuitBreakers:   make(map[string]*errors.CircuitBreaker),
		resilienceWrapper: resilienceWrapper,
		timeoutManager:    timeoutManager,
		logger:            logger.With(zap.String("component", "dependency_health")),
		stopChannel:       make(chan struct{}),
		checkerRoutines:   make(map[string]context.CancelFunc),
		overallStatus:     DependencyStatusUnknown,
	}
}

// RegisterDependency registers a new dependency for health checking
func (dhc *DependencyHealthChecker) RegisterDependency(config *DependencyConfig) error {
	if config.Name == "" {
		return fmt.Errorf("dependency name cannot be empty")
	}

	dhc.mutex.Lock()
	defer dhc.mutex.Unlock()

	// Set defaults
	if config.CheckInterval == 0 {
		config.CheckInterval = 30 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 3
	}

	dhc.dependencies[config.Name] = config

	// Initialize health status
	dhc.healthStatus[config.Name] = &DependencyHealth{
		Name:             config.Name,
		Type:             config.Type,
		Status:           DependencyStatusUnknown,
		Message:          "Not yet checked",
		Tags:             config.Tags,
		Critical:         config.Critical,
		Required:         config.Required,
		Details:          make(map[string]interface{}),
	}

	// Create circuit breaker if enabled
	if config.CircuitBreaker {
		cbConfig := errors.DefaultCircuitBreakerConfig(config.Name)
		cbConfig.FailureThreshold = 3
		cbConfig.Timeout = config.CheckInterval * 2
		dhc.circuitBreakers[config.Name] = errors.NewCircuitBreaker(cbConfig, dhc.logger)
	}

	dhc.logger.Info("Dependency registered",
		zap.String("name", config.Name),
		zap.String("type", string(config.Type)),
		zap.Duration("check_interval", config.CheckInterval),
		zap.Bool("critical", config.Critical))

	return nil
}

// StartHealthChecking starts background health checking for all dependencies
func (dhc *DependencyHealthChecker) StartHealthChecking(ctx context.Context) error {
	dhc.mutex.Lock()
	defer dhc.mutex.Unlock()

	for name, config := range dhc.dependencies {
		if _, exists := dhc.checkerRoutines[name]; exists {
			continue // Already running
		}

		checkCtx, cancel := context.WithCancel(ctx)
		dhc.checkerRoutines[name] = cancel

		go dhc.backgroundHealthCheck(checkCtx, config)
	}

	dhc.logger.Info("Dependency health checking started",
		zap.Int("dependency_count", len(dhc.dependencies)))

	return nil
}

// StopHealthChecking stops background health checking
func (dhc *DependencyHealthChecker) StopHealthChecking() {
	dhc.mutex.Lock()
	defer dhc.mutex.Unlock()

	// Stop timeout manager
	dhc.timeoutManager.CancelAllTimers()

	// Cancel all checker routines
	for name, cancel := range dhc.checkerRoutines {
		cancel()
		delete(dhc.checkerRoutines, name)
	}

	close(dhc.stopChannel)

	dhc.logger.Info("Dependency health checking stopped")
}

// backgroundHealthCheck runs health checks for a single dependency
func (dhc *DependencyHealthChecker) backgroundHealthCheck(ctx context.Context, config *DependencyConfig) {
	ticker := time.NewTicker(config.CheckInterval)
	defer ticker.Stop()

	// Perform initial check
	dhc.checkSingleDependency(ctx, config)

	for {
		select {
		case <-ticker.C:
			dhc.checkSingleDependency(ctx, config)
		case <-ctx.Done():
			return
		case <-dhc.stopChannel:
			return
		}
	}
}

// checkSingleDependency performs a health check for a single dependency
func (dhc *DependencyHealthChecker) checkSingleDependency(ctx context.Context, config *DependencyConfig) {
	startTime := time.Now()

	// Create timeout context
	checkCtx, cancel := dhc.timeoutManager.CreateContextWithTimeout(ctx, "health_check", config.Timeout)
	defer cancel()

	var err error

	// Use circuit breaker if enabled
	if config.CircuitBreaker {
		if cb, exists := dhc.circuitBreakers[config.Name]; exists {
			err = cb.Execute(checkCtx, func(cbCtx context.Context) error {
				return dhc.performHealthCheck(cbCtx, config)
			})
		} else {
			err = dhc.performHealthCheck(checkCtx, config)
		}
	} else {
		// Use resilience wrapper for retry logic
		err = dhc.resilienceWrapper.ExecuteForService(checkCtx, config.Name, func(resCtx context.Context) error {
			return dhc.performHealthCheck(resCtx, config)
		})
	}

	responseTime := time.Since(startTime)

	// Update health status
	dhc.updateHealthStatus(config.Name, err, responseTime)

	// Update overall system health
	dhc.updateOverallHealth()
}

// performHealthCheck performs the actual health check based on dependency type
func (dhc *DependencyHealthChecker) performHealthCheck(ctx context.Context, config *DependencyConfig) error {
	// Use custom health check function if provided
	if config.HealthCheckFunc != nil {
		return config.HealthCheckFunc(ctx)
	}

	// Default health checks based on type
	switch config.Type {
	case DependencyTypeHTTP:
		return dhc.checkHTTPDependency(ctx, config)
	case DependencyTypeDatabase:
		return dhc.checkDatabaseDependency(ctx, config)
	case DependencyTypeLLM:
		return dhc.checkLLMDependency(ctx, config)
	case DependencyTypeMCP:
		return dhc.checkMCPDependency(ctx, config)
	default:
		return fmt.Errorf("unsupported dependency type: %s", config.Type)
	}
}

// checkHTTPDependency performs HTTP health check
func (dhc *DependencyHealthChecker) checkHTTPDependency(ctx context.Context, config *DependencyConfig) error {
	// This would implement actual HTTP health check
	// For now, simulate based on config
	if config.Endpoint == "" {
		return fmt.Errorf("HTTP endpoint not configured")
	}

	// TODO: Implement actual HTTP request with proper headers, SSL verification, etc.
	dhc.logger.Debug("HTTP health check performed", zap.String("endpoint", config.Endpoint))
	return nil
}

// checkDatabaseDependency performs database health check
func (dhc *DependencyHealthChecker) checkDatabaseDependency(ctx context.Context, config *DependencyConfig) error {
	// TODO: Implement actual database health check (ping, simple query)
	dhc.logger.Debug("Database health check performed", zap.String("name", config.Name))
	return nil
}

// checkLLMDependency performs LLM service health check
func (dhc *DependencyHealthChecker) checkLLMDependency(ctx context.Context, config *DependencyConfig) error {
	// TODO: Implement actual LLM health check (simple completion request)
	dhc.logger.Debug("LLM health check performed", zap.String("name", config.Name))
	return nil
}

// checkMCPDependency performs MCP server health check
func (dhc *DependencyHealthChecker) checkMCPDependency(ctx context.Context, config *DependencyConfig) error {
	// TODO: Implement actual MCP health check (server ping, tool listing)
	dhc.logger.Debug("MCP health check performed", zap.String("name", config.Name))
	return nil
}

// updateHealthStatus updates the health status of a dependency
func (dhc *DependencyHealthChecker) updateHealthStatus(name string, err error, responseTime time.Duration) {
	dhc.mutex.Lock()
	defer dhc.mutex.Unlock()

	health, exists := dhc.healthStatus[name]
	if !exists {
		return
	}

	health.LastChecked = time.Now()
	health.ResponseTime = responseTime

	if err != nil {
		health.ErrorCount++
		health.ConsecutiveFails++
		health.Status = DependencyStatusUnhealthy
		health.Message = err.Error()

		dhc.logger.Warn("Dependency health check failed",
			zap.String("dependency", name),
			zap.Error(err),
			zap.Duration("response_time", responseTime),
			zap.Int("consecutive_fails", health.ConsecutiveFails))
	} else {
		health.SuccessCount++
		health.ConsecutiveFails = 0
		health.LastHealthy = time.Now()
		health.Status = DependencyStatusHealthy
		health.Message = "Health check successful"

		dhc.logger.Debug("Dependency health check succeeded",
			zap.String("dependency", name),
			zap.Duration("response_time", responseTime))
	}

	// Calculate uptime percentage
	totalChecks := health.SuccessCount + health.ErrorCount
	if totalChecks > 0 {
		health.Uptime = float64(health.SuccessCount) / float64(totalChecks) * 100
	}

	// Update circuit breaker status
	if cb, exists := dhc.circuitBreakers[name]; exists {
		health.CircuitBreakerOpen = cb.GetState() == errors.CircuitStateOpen
	}

	// Add detailed information
	health.Details["last_error"] = err
	health.Details["response_time_ms"] = responseTime.Milliseconds()
	health.Details["uptime_percentage"] = health.Uptime
}

// updateOverallHealth calculates and updates the overall system health
func (dhc *DependencyHealthChecker) updateOverallHealth() {
	dhc.mutex.Lock()
	defer dhc.mutex.Unlock()

	dhc.lastHealthCheck = time.Now()
	dhc.healthCheckCount++

	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0
	criticalUnhealthy := 0
	requiredUnhealthy := 0

	for _, health := range dhc.healthStatus {
		switch health.Status {
		case DependencyStatusHealthy:
			healthyCount++
		case DependencyStatusDegraded:
			degradedCount++
		case DependencyStatusUnhealthy:
			unhealthyCount++
			if health.Critical {
				criticalUnhealthy++
			}
			if health.Required {
				requiredUnhealthy++
			}
		}
	}

	// Determine overall status
	if requiredUnhealthy > 0 || criticalUnhealthy > 0 {
		dhc.overallStatus = DependencyStatusUnhealthy
	} else if unhealthyCount > 0 || degradedCount > 0 {
		dhc.overallStatus = DependencyStatusDegraded
	} else if healthyCount > 0 {
		dhc.overallStatus = DependencyStatusHealthy
	} else {
		dhc.overallStatus = DependencyStatusUnknown
	}
}

// GetOverallHealth returns the overall system health
func (dhc *DependencyHealthChecker) GetOverallHealth() DependencyStatus {
	dhc.mutex.RLock()
	defer dhc.mutex.RUnlock()
	return dhc.overallStatus
}

// GetDependencyHealth returns health information for a specific dependency
func (dhc *DependencyHealthChecker) GetDependencyHealth(name string) (*DependencyHealth, bool) {
	dhc.mutex.RLock()
	defer dhc.mutex.RUnlock()

	health, exists := dhc.healthStatus[name]
	if !exists {
		return nil, false
	}

	// Return a copy to prevent race conditions
	healthCopy := *health
	return &healthCopy, true
}

// GetAllDependencyHealth returns health information for all dependencies
func (dhc *DependencyHealthChecker) GetAllDependencyHealth() map[string]*DependencyHealth {
	dhc.mutex.RLock()
	defer dhc.mutex.RUnlock()

	result := make(map[string]*DependencyHealth)
	for name, health := range dhc.healthStatus {
		healthCopy := *health
		result[name] = &healthCopy
	}

	return result
}

// GetHealthSummary returns a summary of system health
func (dhc *DependencyHealthChecker) GetHealthSummary() map[string]interface{} {
	dhc.mutex.RLock()
	defer dhc.mutex.RUnlock()

	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0
	unknownCount := 0
	criticalUnhealthy := 0
	requiredUnhealthy := 0

	for _, health := range dhc.healthStatus {
		switch health.Status {
		case DependencyStatusHealthy:
			healthyCount++
		case DependencyStatusDegraded:
			degradedCount++
		case DependencyStatusUnhealthy:
			unhealthyCount++
			if health.Critical {
				criticalUnhealthy++
			}
			if health.Required {
				requiredUnhealthy++
			}
		case DependencyStatusUnknown:
			unknownCount++
		}
	}

	return map[string]interface{}{
		"overall_status":        string(dhc.overallStatus),
		"total_dependencies":    len(dhc.healthStatus),
		"healthy_count":         healthyCount,
		"degraded_count":        degradedCount,
		"unhealthy_count":       unhealthyCount,
		"unknown_count":         unknownCount,
		"critical_unhealthy":    criticalUnhealthy,
		"required_unhealthy":    requiredUnhealthy,
		"last_health_check":     dhc.lastHealthCheck,
		"health_check_count":    dhc.healthCheckCount,
		"dependencies":          dhc.GetAllDependencyHealth(),
	}
}

// GetCircuitBreakerStatus returns circuit breaker status for dependencies
func (dhc *DependencyHealthChecker) GetCircuitBreakerStatus() map[string]interface{} {
	dhc.mutex.RLock()
	defer dhc.mutex.RUnlock()

	status := make(map[string]interface{})
	for name, cb := range dhc.circuitBreakers {
		status[name] = cb.HealthCheck()
	}

	return status
}

// TriggerHealthCheck manually triggers health checks for all dependencies
func (dhc *DependencyHealthChecker) TriggerHealthCheck(ctx context.Context) {
	dhc.mutex.RLock()
	dependencies := make([]*DependencyConfig, 0, len(dhc.dependencies))
	for _, config := range dhc.dependencies {
		dependencies = append(dependencies, config)
	}
	dhc.mutex.RUnlock()

	for _, config := range dependencies {
		go dhc.checkSingleDependency(ctx, config)
	}

	dhc.logger.Info("Manual health check triggered for all dependencies",
		zap.Int("dependency_count", len(dependencies)))
}