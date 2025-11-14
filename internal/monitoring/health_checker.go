package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// HealthStatus represents the health status of a component
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// ComponentType represents the type of component being monitored
type ComponentType string

const (
	ComponentTypeAgent      ComponentType = "agent"
	ComponentTypeMCPServer  ComponentType = "mcp_server"
	ComponentTypePipeline   ComponentType = "pipeline"
	ComponentTypeSystem     ComponentType = "system"
	ComponentTypeDatabase   ComponentType = "database"
	ComponentTypeExternal   ComponentType = "external"
)

// HealthCheck represents a health check result for a component
type HealthCheck struct {
	ComponentID     string                 `json:"component_id"`
	ComponentType   ComponentType          `json:"component_type"`
	Status          HealthStatus           `json:"status"`
	Message         string                 `json:"message"`
	Details         map[string]interface{} `json:"details,omitempty"`
	LastChecked     time.Time              `json:"last_checked"`
	ResponseTime    time.Duration          `json:"response_time"`
	CheckDuration   time.Duration          `json:"check_duration"`
	ErrorCount      int                    `json:"error_count"`
	SuccessCount    int                    `json:"success_count"`
	ConsecutiveFails int                   `json:"consecutive_fails"`
}

// HealthCheckConfig configures health check behavior
type HealthCheckConfig struct {
	Interval         time.Duration `json:"interval"`
	Timeout          time.Duration `json:"timeout"`
	MaxRetries       int           `json:"max_retries"`
	FailureThreshold int           `json:"failure_threshold"`
	RecoveryThreshold int          `json:"recovery_threshold"`
	Enabled          bool          `json:"enabled"`
}

// DefaultHealthCheckConfig returns default health check configuration
func DefaultHealthCheckConfig() *HealthCheckConfig {
	return &HealthCheckConfig{
		Interval:          30 * time.Second,
		Timeout:           10 * time.Second,
		MaxRetries:        3,
		FailureThreshold:  3,
		RecoveryThreshold: 2,
		Enabled:           true,
	}
}

// HealthChecker performs health checks on system components
type HealthChecker struct {
	mu              sync.RWMutex
	logger          *zap.Logger
	config          *HealthCheckConfig
	checks          map[string]*HealthCheck
	checkers        map[string]ComponentChecker
	agentRegistry   *agents.AgentRegistry
	mcpRegistry     *mcp.MCPServerRegistry
	stopCh          chan struct{}
	running         bool
	wg              sync.WaitGroup
}

// ComponentChecker defines the interface for component-specific health checks
type ComponentChecker interface {
	CheckHealth(ctx context.Context) (*HealthCheck, error)
	GetComponentID() string
	GetComponentType() ComponentType
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(
	logger *zap.Logger,
	config *HealthCheckConfig,
	agentRegistry *agents.AgentRegistry,
	mcpRegistry *mcp.MCPServerRegistry,
) *HealthChecker {
	if config == nil {
		config = DefaultHealthCheckConfig()
	}

	return &HealthChecker{
		logger:        logger,
		config:        config,
		checks:        make(map[string]*HealthCheck),
		checkers:      make(map[string]ComponentChecker),
		agentRegistry: agentRegistry,
		mcpRegistry:   mcpRegistry,
		stopCh:        make(chan struct{}),
	}
}

// Start begins the health checking routine
func (hc *HealthChecker) Start(ctx context.Context) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if hc.running {
		return fmt.Errorf("health checker is already running")
	}

	if !hc.config.Enabled {
		hc.logger.Info("Health checker is disabled")
		return nil
	}

	hc.running = true
	hc.logger.Info("Starting health checker",
		zap.Duration("interval", hc.config.Interval),
		zap.Duration("timeout", hc.config.Timeout))

	// Register built-in checkers
	hc.registerBuiltInCheckers()

	// Start the main health check routine
	hc.wg.Add(1)
	go hc.healthCheckRoutine(ctx)

	return nil
}

// Stop stops the health checking routine
func (hc *HealthChecker) Stop() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if !hc.running {
		return nil
	}

	hc.logger.Info("Stopping health checker")
	close(hc.stopCh)
	hc.wg.Wait()
	hc.running = false

	return nil
}

// RegisterChecker registers a custom component checker
func (hc *HealthChecker) RegisterChecker(checker ComponentChecker) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	componentID := checker.GetComponentID()
	hc.checkers[componentID] = checker
	hc.logger.Debug("Registered health checker",
		zap.String("component_id", componentID),
		zap.String("component_type", string(checker.GetComponentType())))
}

// GetHealthStatus returns the current health status of all components
func (hc *HealthChecker) GetHealthStatus() map[string]*HealthCheck {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	result := make(map[string]*HealthCheck)
	for id, check := range hc.checks {
		// Create a copy to avoid race conditions
		checkCopy := &HealthCheck{
			ComponentID:      check.ComponentID,
			ComponentType:    check.ComponentType,
			Status:           check.Status,
			Message:          check.Message,
			Details:          make(map[string]interface{}),
			LastChecked:      check.LastChecked,
			ResponseTime:     check.ResponseTime,
			CheckDuration:    check.CheckDuration,
			ErrorCount:       check.ErrorCount,
			SuccessCount:     check.SuccessCount,
			ConsecutiveFails: check.ConsecutiveFails,
		}

		// Copy details
		for k, v := range check.Details {
			checkCopy.Details[k] = v
		}

		result[id] = checkCopy
	}

	return result
}

// GetComponentHealth returns the health status of a specific component
func (hc *HealthChecker) GetComponentHealth(componentID string) (*HealthCheck, bool) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	check, exists := hc.checks[componentID]
	if !exists {
		return nil, false
	}

	// Return a copy
	return &HealthCheck{
		ComponentID:      check.ComponentID,
		ComponentType:    check.ComponentType,
		Status:           check.Status,
		Message:          check.Message,
		Details:          check.Details,
		LastChecked:      check.LastChecked,
		ResponseTime:     check.ResponseTime,
		CheckDuration:    check.CheckDuration,
		ErrorCount:       check.ErrorCount,
		SuccessCount:     check.SuccessCount,
		ConsecutiveFails: check.ConsecutiveFails,
	}, true
}

// GetOverallHealth returns the overall system health status
func (hc *HealthChecker) GetOverallHealth() *SystemHealth {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	systemHealth := &SystemHealth{
		Status:      HealthStatusHealthy,
		LastChecked: time.Now(),
		Components:  make(map[ComponentType][]ComponentHealth),
		Summary:     make(map[string]interface{}),
	}

	var healthyCount, degradedCount, unhealthyCount int
	componentsByType := make(map[ComponentType][]*HealthCheck)

	// Group components by type
	for _, check := range hc.checks {
		componentsByType[check.ComponentType] = append(componentsByType[check.ComponentType], check)

		switch check.Status {
		case HealthStatusHealthy:
			healthyCount++
		case HealthStatusDegraded:
			degradedCount++
		case HealthStatusUnhealthy:
			unhealthyCount++
		}
	}

	// Determine overall status
	if unhealthyCount > 0 {
		systemHealth.Status = HealthStatusUnhealthy
	} else if degradedCount > 0 {
		systemHealth.Status = HealthStatusDegraded
	}

	// Build component health by type
	for componentType, checks := range componentsByType {
		var componentHealthList []ComponentHealth
		for _, check := range checks {
			componentHealthList = append(componentHealthList, ComponentHealth{
				ID:           check.ComponentID,
				Status:       check.Status,
				Message:      check.Message,
				LastChecked:  check.LastChecked,
				ResponseTime: check.ResponseTime,
			})
		}
		systemHealth.Components[componentType] = componentHealthList
	}

	// Build summary
	systemHealth.Summary["total_components"] = len(hc.checks)
	systemHealth.Summary["healthy_components"] = healthyCount
	systemHealth.Summary["degraded_components"] = degradedCount
	systemHealth.Summary["unhealthy_components"] = unhealthyCount
	systemHealth.Summary["health_percentage"] = float64(healthyCount) / float64(len(hc.checks)) * 100

	return systemHealth
}

// healthCheckRoutine runs periodic health checks
func (hc *HealthChecker) healthCheckRoutine(ctx context.Context) {
	defer hc.wg.Done()

	ticker := time.NewTicker(hc.config.Interval)
	defer ticker.Stop()

	// Run initial health check
	hc.performHealthChecks(ctx)

	for {
		select {
		case <-ticker.C:
			hc.performHealthChecks(ctx)

		case <-hc.stopCh:
			hc.logger.Info("Health check routine stopping")
			return

		case <-ctx.Done():
			hc.logger.Info("Health check routine context cancelled")
			return
		}
	}
}

// performHealthChecks executes health checks for all registered components
func (hc *HealthChecker) performHealthChecks(ctx context.Context) {
	hc.logger.Debug("Performing health checks")

	// Create a context with timeout for health checks
	checkCtx, cancel := context.WithTimeout(ctx, hc.config.Timeout)
	defer cancel()

	var wg sync.WaitGroup
	resultChan := make(chan *HealthCheck, len(hc.checkers))

	// Run health checks concurrently
	for _, checker := range hc.checkers {
		wg.Add(1)
		go func(checker ComponentChecker) {
			defer wg.Done()
			hc.runSingleHealthCheck(checkCtx, checker, resultChan)
		}(checker)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		hc.updateHealthCheck(result)
	}

	hc.logger.Debug("Health checks completed",
		zap.Int("total_checks", len(hc.checkers)))
}

// runSingleHealthCheck executes a health check for a single component
func (hc *HealthChecker) runSingleHealthCheck(ctx context.Context, checker ComponentChecker, resultChan chan<- *HealthCheck) {
	startTime := time.Now()
	componentID := checker.GetComponentID()

	defer func() {
		if r := recover(); r != nil {
			hc.logger.Error("Health check panic",
				zap.String("component_id", componentID),
				zap.Any("panic", r))

			resultChan <- &HealthCheck{
				ComponentID:   componentID,
				ComponentType: checker.GetComponentType(),
				Status:        HealthStatusUnhealthy,
				Message:       fmt.Sprintf("Health check panic: %v", r),
				LastChecked:   time.Now(),
				CheckDuration: time.Since(startTime),
			}
		}
	}()

	result, err := checker.CheckHealth(ctx)
	if err != nil {
		hc.logger.Warn("Health check failed",
			zap.String("component_id", componentID),
			zap.Error(err))

		result = &HealthCheck{
			ComponentID:   componentID,
			ComponentType: checker.GetComponentType(),
			Status:        HealthStatusUnhealthy,
			Message:       fmt.Sprintf("Health check error: %v", err),
			LastChecked:   time.Now(),
			CheckDuration: time.Since(startTime),
		}
	}

	if result != nil {
		result.CheckDuration = time.Since(startTime)
		result.LastChecked = time.Now()
		resultChan <- result
	}
}

// updateHealthCheck updates the stored health check result
func (hc *HealthChecker) updateHealthCheck(newCheck *HealthCheck) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	componentID := newCheck.ComponentID
	existingCheck, exists := hc.checks[componentID]

	if !exists {
		// New component
		hc.checks[componentID] = newCheck
		return
	}

	// Update existing check
	existingCheck.Status = newCheck.Status
	existingCheck.Message = newCheck.Message
	existingCheck.Details = newCheck.Details
	existingCheck.LastChecked = newCheck.LastChecked
	existingCheck.ResponseTime = newCheck.ResponseTime
	existingCheck.CheckDuration = newCheck.CheckDuration

	// Update counters
	if newCheck.Status == HealthStatusHealthy {
		existingCheck.SuccessCount++
		existingCheck.ConsecutiveFails = 0
	} else {
		existingCheck.ErrorCount++
		existingCheck.ConsecutiveFails++
	}

	hc.checks[componentID] = existingCheck
}

// registerBuiltInCheckers registers built-in health checkers
func (hc *HealthChecker) registerBuiltInCheckers() {
	// Register agent registry checker
	if hc.agentRegistry != nil {
		agentChecker := NewAgentRegistryChecker(hc.agentRegistry, hc.logger)
		hc.RegisterChecker(agentChecker)
	}

	// Register MCP registry checker
	if hc.mcpRegistry != nil {
		mcpChecker := NewMCPRegistryChecker(hc.mcpRegistry, hc.logger)
		hc.RegisterChecker(mcpChecker)
	}

	// Register system checker
	systemChecker := NewSystemChecker(hc.logger)
	hc.RegisterChecker(systemChecker)
}

// SystemHealth represents the overall system health
type SystemHealth struct {
	Status      HealthStatus                        `json:"status"`
	LastChecked time.Time                           `json:"last_checked"`
	Components  map[ComponentType][]ComponentHealth `json:"components"`
	Summary     map[string]interface{}              `json:"summary"`
}

// ComponentHealth represents simplified component health info
type ComponentHealth struct {
	ID           string        `json:"id"`
	Status       HealthStatus  `json:"status"`
	Message      string        `json:"message"`
	LastChecked  time.Time     `json:"last_checked"`
	ResponseTime time.Duration `json:"response_time"`
}