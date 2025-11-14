package monitoring

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// AgentDependencyConfig represents configuration for dependency health checking compatible with agents
type AgentDependencyConfig struct {
	Name              string                  `json:"name"`
	Type              AgentDependencyType     `json:"type"`
	Endpoint          string                  `json:"endpoint,omitempty"`
	CheckInterval     time.Duration           `json:"check_interval"`
	Timeout           time.Duration           `json:"timeout"`
	RetryAttempts     int                     `json:"retry_attempts"`
	CircuitBreaker    bool                    `json:"circuit_breaker"`
	Critical          bool                    `json:"critical"`
	Required          bool                    `json:"required"`
	Tags              map[string]string       `json:"tags,omitempty"`
	ExpectedStatus    []int                   `json:"expected_status,omitempty"`
	HealthCheckFunc   func(context.Context) error `json:"-"`
}

// AgentDependencyHealth represents health information compatible with agents
type AgentDependencyHealth struct {
	Name               string                 `json:"name"`
	Type               AgentDependencyType    `json:"type"`
	Status             AgentDependencyStatus  `json:"status"`
	Message            string                 `json:"message"`
	LastChecked        time.Time              `json:"last_checked"`
	LastHealthy        time.Time              `json:"last_healthy"`
	ResponseTime       time.Duration          `json:"response_time"`
	SuccessCount       int64                  `json:"success_count"`
	ErrorCount         int64                  `json:"error_count"`
	ConsecutiveFails   int                    `json:"consecutive_fails"`
	Uptime             float64                `json:"uptime"`
	Details            map[string]interface{} `json:"details,omitempty"`
	Tags               map[string]string      `json:"tags,omitempty"`
	Critical           bool                   `json:"critical"`
	Required           bool                   `json:"required"`
	CircuitBreakerOpen bool                   `json:"circuit_breaker_open,omitempty"`
}

// AgentDependencyType represents the type of dependency for agents
type AgentDependencyType string

const (
	AgentDependencyTypeDatabase     AgentDependencyType = "database"
	AgentDependencyTypeLLM         AgentDependencyType = "llm"
	AgentDependencyTypeMCP         AgentDependencyType = "mcp"
	AgentDependencyTypeWebSocket   AgentDependencyType = "websocket"
	AgentDependencyTypeHTTP        AgentDependencyType = "http"
	AgentDependencyTypeAuth        AgentDependencyType = "auth"
	AgentDependencyTypeCache       AgentDependencyType = "cache"
	AgentDependencyTypeMessageQueue AgentDependencyType = "message_queue"
	AgentDependencyTypeFileSystem  AgentDependencyType = "filesystem"
	AgentDependencyTypeNetwork     AgentDependencyType = "network"
)

// AgentDependencyStatus represents the health status for agents
type AgentDependencyStatus string

const (
	AgentDependencyStatusHealthy     AgentDependencyStatus = "healthy"
	AgentDependencyStatusDegraded    AgentDependencyStatus = "degraded"
	AgentDependencyStatusUnhealthy   AgentDependencyStatus = "unhealthy"
	AgentDependencyStatusUnknown     AgentDependencyStatus = "unknown"
	AgentDependencyStatusMaintenance AgentDependencyStatus = "maintenance"
)

// AgentDependencyHealthAdapter adapts the monitoring DependencyHealthChecker for use with agents
type AgentDependencyHealthAdapter struct {
	checker *DependencyHealthChecker
	logger  *zap.Logger
}

// NewAgentDependencyHealthAdapter creates a new adapter for agent integration
func NewAgentDependencyHealthAdapter(checker *DependencyHealthChecker, logger *zap.Logger) *AgentDependencyHealthAdapter {
	return &AgentDependencyHealthAdapter{
		checker: checker,
		logger:  logger,
	}
}

// RegisterDependency registers a dependency using agent-compatible config
func (a *AgentDependencyHealthAdapter) RegisterDependency(config *AgentDependencyConfig) error {
	// Convert agent config to monitoring config
	monitoringConfig := &DependencyConfig{
		Name:              config.Name,
		Type:              DependencyType(config.Type),
		Endpoint:          config.Endpoint,
		CheckInterval:     config.CheckInterval,
		Timeout:           config.Timeout,
		RetryAttempts:     config.RetryAttempts,
		CircuitBreaker:    config.CircuitBreaker,
		Critical:          config.Critical,
		Required:          config.Required,
		Tags:              config.Tags,
		ExpectedStatus:    config.ExpectedStatus,
		HealthCheckFunc:   config.HealthCheckFunc,
	}

	return a.checker.RegisterDependency(monitoringConfig)
}

// GetAllDependencyHealth returns all dependency health using agent-compatible types
func (a *AgentDependencyHealthAdapter) GetAllDependencyHealth() map[string]*AgentDependencyHealth {
	monitoringHealth := a.checker.GetAllDependencyHealth()
	agentHealth := make(map[string]*AgentDependencyHealth)

	for name, health := range monitoringHealth {
		agentHealth[name] = &AgentDependencyHealth{
			Name:               health.Name,
			Type:               AgentDependencyType(health.Type),
			Status:             AgentDependencyStatus(health.Status),
			Message:            health.Message,
			LastChecked:        health.LastChecked,
			LastHealthy:        health.LastHealthy,
			ResponseTime:       health.ResponseTime,
			SuccessCount:       health.SuccessCount,
			ErrorCount:         health.ErrorCount,
			ConsecutiveFails:   health.ConsecutiveFails,
			Uptime:             health.Uptime,
			Details:            health.Details,
			Tags:               health.Tags,
			Critical:           health.Critical,
			Required:           health.Required,
			CircuitBreakerOpen: health.CircuitBreakerOpen,
		}
	}

	return agentHealth
}

// GetOverallHealth returns the overall health status using agent-compatible types
func (a *AgentDependencyHealthAdapter) GetOverallHealth() AgentDependencyStatus {
	status := a.checker.GetOverallHealth()
	return AgentDependencyStatus(status)
}

// StartHealthChecking starts background health checking
func (a *AgentDependencyHealthAdapter) StartHealthChecking(ctx context.Context) error {
	return a.checker.StartHealthChecking(ctx)
}

// StopHealthChecking stops background health checking
func (a *AgentDependencyHealthAdapter) StopHealthChecking() {
	a.checker.StopHealthChecking()
}

// GetDependencyHealthChecker returns the underlying dependency health checker
func (a *AgentDependencyHealthAdapter) GetDependencyHealthChecker() *DependencyHealthChecker {
	return a.checker
}

// CreateAgentCompatibleChecker creates a dependency health checker that's compatible with agents
func CreateAgentCompatibleChecker(logger *zap.Logger) (*AgentDependencyHealthAdapter, *DependencyHealthChecker) {
	checker := NewDependencyHealthChecker(logger)
	adapter := NewAgentDependencyHealthAdapter(checker, logger)
	return adapter, checker
}

// ConfigureAgentDependencies configures standard dependencies for agents
func (a *AgentDependencyHealthAdapter) ConfigureAgentDependencies() error {
	// LLM dependency
	llmConfig := &AgentDependencyConfig{
		Name:           "llm_provider",
		Type:           AgentDependencyTypeLLM,
		CheckInterval:  30 * time.Second,
		Timeout:        10 * time.Second,
		RetryAttempts:  3,
		CircuitBreaker: true,
		Critical:       true,
		Required:       true,
		Tags: map[string]string{
			"category": "ai_service",
			"provider": "openai",
		},
	}
	if err := a.RegisterDependency(llmConfig); err != nil {
		return err
	}

	// MCP dependency
	mcpConfig := &AgentDependencyConfig{
		Name:           "mcp_servers",
		Type:           AgentDependencyTypeMCP,
		CheckInterval:  15 * time.Second,
		Timeout:        5 * time.Second,
		RetryAttempts:  2,
		CircuitBreaker: false,
		Critical:       false,
		Required:       true,
		Tags: map[string]string{
			"category": "tool_integration",
		},
	}
	if err := a.RegisterDependency(mcpConfig); err != nil {
		return err
	}

	// Database dependency
	dbConfig := &AgentDependencyConfig{
		Name:           "database",
		Type:           AgentDependencyTypeDatabase,
		CheckInterval:  45 * time.Second,
		Timeout:        3 * time.Second,
		RetryAttempts:  2,
		CircuitBreaker: true,
		Critical:       false,
		Required:       false,
		Tags: map[string]string{
			"category": "persistence",
		},
	}
	if err := a.RegisterDependency(dbConfig); err != nil {
		return err
	}

	return nil
}

// HealthCheck returns comprehensive health status for agents
func (a *AgentDependencyHealthAdapter) HealthCheck() map[string]interface{} {
	health := a.checker.GetHealthSummary()

	// Convert to agent-compatible format
	agentHealth := map[string]interface{}{
		"overall_status":        string(a.GetOverallHealth()),
		"total_dependencies":    health["total_dependencies"],
		"healthy_count":         health["healthy_count"],
		"degraded_count":        health["degraded_count"],
		"unhealthy_count":       health["unhealthy_count"],
		"unknown_count":         health["unknown_count"],
		"critical_unhealthy":    health["critical_unhealthy"],
		"required_unhealthy":    health["required_unhealthy"],
		"last_health_check":     health["last_health_check"],
		"health_check_count":    health["health_check_count"],
		"dependencies":          a.GetAllDependencyHealth(),
	}

	return agentHealth
}