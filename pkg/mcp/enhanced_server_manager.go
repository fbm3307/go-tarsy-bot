package mcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/errors"
)

// EnhancedServerManager provides advanced MCP server lifecycle and assignment management
// This extends the base MCP functionality with sophisticated server management,
// load balancing, health monitoring, and agent-specific assignments
type EnhancedServerManager struct {
	registry                *MCPServerRegistry
	serverInstances         map[string]*ExtendedServerInstance
	agentAssignments        map[string]*AgentServerAssignment
	loadBalancer           *LoadBalancer
	healthMonitor          *HealthMonitor
	assignmentStrategy     AssignmentStrategy
	config                 *ServerManagerConfig
	logger                 *zap.Logger
	mutex                  sync.RWMutex

	// Error handling and resilience
	errorHandler           *errors.ErrorClassifier
	resilienceManager      *errors.ResilienceWrapper
	degradationManager     *errors.ServiceDegradationManager

	// Performance monitoring
	metrics                *ServerManagerMetrics
	lastHealthCheck        time.Time
	connectionPool         *ConnectionPool
}

// ExtendedServerInstance extends the base ServerInstance with enhanced management capabilities
type ExtendedServerInstance struct {
	*ServerInstance        // Embed the existing ServerInstance
	LoadMetrics            *LoadMetrics
	ErrorHistory           []ServerError
	ResourceUsage          *ResourceUsage
	PerformanceStats       *PerformanceStats

	// Connection management
	ActiveConnections      int
	MaxConnections         int
	ConnectionPool         *ServerConnectionPool

	// Lifecycle management
	ProcessID              int
	RestartPolicy          RestartPolicy
	GracefulShutdownTimer  *time.Timer
	LastActivity           time.Time
}

// AgentServerAssignment represents the assignment of servers to specific agents
type AgentServerAssignment struct {
	AgentType              string
	AgentName              string
	PrimaryServers         []string
	FallbackServers        []string
	LoadBalancingEnabled   bool
	FailoverEnabled        bool
	MaxConcurrentRequests  int
	TimeoutConfiguration   *TimeoutConfig
	RetryPolicy            *RetryPolicy
	HealthCheckFrequency   time.Duration
	PreferredServerOrder   []string
	ExcludedServers        []string
	CustomRoutingRules     map[string]string
}

// LoadBalancer manages load distribution across MCP servers
type LoadBalancer struct {
	Strategy               LoadBalancingStrategy
	WeightConfiguration    map[string]int
	HealthAwareRouting     bool
	StickySessionEnabled   bool
	SessionAffinityRules   map[string]string
	RoundRobinCounters     map[string]int
	RequestDistribution    map[string]*DistributionStats
	CircuitBreakerEnabled  bool
	CircuitBreakers        map[string]*ServerCircuitBreaker
}

// HealthMonitor tracks server health and performance
type HealthMonitor struct {
	HealthCheckInterval    time.Duration
	HealthThresholds       *HealthThresholds
	AlertingEnabled        bool
	HealthHistory          map[string][]*HealthSnapshot
	UnhealthyServers       map[string]*UnhealthyServerInfo
	RecoveryTracking       map[string]*RecoveryProgress
	NotificationChannels   []NotificationChannel
}

// ServerManagerConfig represents configuration for the enhanced server manager
type ServerManagerConfig struct {
	DefaultTimeout         time.Duration                 `json:"default_timeout"`
	MaxRetryAttempts       int                          `json:"max_retry_attempts"`
	HealthCheckInterval    time.Duration                `json:"health_check_interval"`
	LoadBalancingStrategy  LoadBalancingStrategy        `json:"load_balancing_strategy"`
	FailoverEnabled        bool                         `json:"failover_enabled"`
	ConnectionPoolSize     int                          `json:"connection_pool_size"`
	MaxConcurrentRequests  int                          `json:"max_concurrent_requests"`
	GracefulShutdownTimeout time.Duration               `json:"graceful_shutdown_timeout"`
	ResourceLimits         *ResourceLimits              `json:"resource_limits"`
	PerformanceThresholds  *PerformanceThresholds       `json:"performance_thresholds"`
	AutoScalingEnabled     bool                         `json:"auto_scaling_enabled"`
	AutoScalingRules       *AutoScalingRules            `json:"auto_scaling_rules"`
	AlertingConfig         *AlertingConfig              `json:"alerting_config"`
}

// Enums and types

type AssignmentStrategy string

const (
	AssignmentStrategyRoundRobin     AssignmentStrategy = "round_robin"
	AssignmentStrategyWeighted       AssignmentStrategy = "weighted"
	AssignmentStrategyHealthBased    AssignmentStrategy = "health_based"
	AssignmentStrategyCapacityBased  AssignmentStrategy = "capacity_based"
	AssignmentStrategyAffinityBased  AssignmentStrategy = "affinity_based"
	AssignmentStrategyCustom         AssignmentStrategy = "custom"
)

type LoadBalancingStrategy string

const (
	LoadBalancingStrategyRoundRobin        LoadBalancingStrategy = "round_robin"
	LoadBalancingStrategyWeightedRoundRobin LoadBalancingStrategy = "weighted_round_robin"
	LoadBalancingStrategyLeastConnections  LoadBalancingStrategy = "least_connections"
	LoadBalancingStrategyLeastResponseTime LoadBalancingStrategy = "least_response_time"
	LoadBalancingStrategyResourceBased     LoadBalancingStrategy = "resource_based"
	LoadBalancingStrategyHealthBased       LoadBalancingStrategy = "health_based"
)

// Additional server status constants for enhanced management
const (
	ServerStatusDegraded    ServerStatus = "degraded"
	ServerStatusUnhealthy   ServerStatus = "unhealthy"
	ServerStatusShuttingDown ServerStatus = "shutting_down"
	ServerStatusMaintenance ServerStatus = "maintenance"
)

type RestartPolicy string

const (
	RestartPolicyNever      RestartPolicy = "never"
	RestartPolicyOnFailure  RestartPolicy = "on_failure"
	RestartPolicyAlways     RestartPolicy = "always"
	RestartPolicyUnlessStopped RestartPolicy = "unless_stopped"
)

// Supporting structures

// ExtendedServerHealth extends the base ServerHealth with additional metrics
type ExtendedServerHealth struct {
	*ServerHealth      // Embed the existing ServerHealth
	Status             ServerStatus             `json:"status"`
	ErrorRate          float64                  `json:"error_rate"`
	AvailabilityPercent float64                `json:"availability_percent"`
	ConsecutiveFailures int                     `json:"consecutive_failures"`
	HealthScore        float64                  `json:"health_score"`
	Alerts             []HealthAlert            `json:"alerts"`
	Dependencies       map[string]DependencyHealth `json:"dependencies"`
}

type LoadMetrics struct {
	ActiveRequests         int                      `json:"active_requests"`
	RequestsPerSecond      float64                  `json:"requests_per_second"`
	AverageResponseTime    time.Duration            `json:"average_response_time"`
	TotalRequests          int64                    `json:"total_requests"`
	SuccessfulRequests     int64                    `json:"successful_requests"`
	FailedRequests         int64                    `json:"failed_requests"`
	QueueDepth             int                      `json:"queue_depth"`
	ThroughputMBPS         float64                  `json:"throughput_mbps"`
	LastUpdated            time.Time                `json:"last_updated"`
}

type ResourceUsage struct {
	CPUPercent             float64                  `json:"cpu_percent"`
	MemoryPercent          float64                  `json:"memory_percent"`
	MemoryUsageBytes       int64                    `json:"memory_usage_bytes"`
	DiskIOBytes            int64                    `json:"disk_io_bytes"`
	NetworkIOBytes         int64                    `json:"network_io_bytes"`
	FileDescriptors        int                      `json:"file_descriptors"`
	GoroutineCount         int                      `json:"goroutine_count"`
	HeapObjects            int64                    `json:"heap_objects"`
	LastMeasured           time.Time                `json:"last_measured"`
}

type PerformanceStats struct {
	ToolExecutionTimes     map[string]time.Duration `json:"tool_execution_times"`
	SuccessRates           map[string]float64       `json:"success_rates"`
	ErrorTypes             map[string]int64         `json:"error_types"`
	PeakLoad               *LoadMetrics             `json:"peak_load"`
	AverageLoad            *LoadMetrics             `json:"average_load"`
	SLACompliance          *SLAMetrics              `json:"sla_compliance"`
	PerformanceTrends      []*TrendDataPoint        `json:"performance_trends"`
}

type ServerError struct {
	Timestamp              time.Time                `json:"timestamp"`
	ErrorType              string                   `json:"error_type"`
	ErrorMessage           string                   `json:"error_message"`
	ErrorCode              string                   `json:"error_code"`
	RequestID              string                   `json:"request_id,omitempty"`
	AgentType              string                   `json:"agent_type,omitempty"`
	ToolName               string                   `json:"tool_name,omitempty"`
	Severity               string                   `json:"severity"`
	Context                map[string]interface{}   `json:"context,omitempty"`
}

type TimeoutConfig struct {
	ConnectionTimeout      time.Duration            `json:"connection_timeout"`
	RequestTimeout         time.Duration            `json:"request_timeout"`
	IdleTimeout            time.Duration            `json:"idle_timeout"`
	KeepAliveTimeout       time.Duration            `json:"keep_alive_timeout"`
	HandshakeTimeout       time.Duration            `json:"handshake_timeout"`
}

type RetryPolicy struct {
	MaxAttempts            int                      `json:"max_attempts"`
	InitialDelay           time.Duration            `json:"initial_delay"`
	MaxDelay               time.Duration            `json:"max_delay"`
	BackoffMultiplier      float64                  `json:"backoff_multiplier"`
	RetryableErrors        []string                 `json:"retryable_errors"`
	CircuitBreakerEnabled  bool                     `json:"circuit_breaker_enabled"`
	JitterEnabled          bool                     `json:"jitter_enabled"`
}

type DistributionStats struct {
	TotalRequests          int64                    `json:"total_requests"`
	SuccessfulRequests     int64                    `json:"successful_requests"`
	FailedRequests         int64                    `json:"failed_requests"`
	AverageResponseTime    time.Duration            `json:"average_response_time"`
	LastRequestTime        time.Time                `json:"last_request_time"`
	LoadPercentage         float64                  `json:"load_percentage"`
}

type ServerCircuitBreaker struct {
	State                  CircuitBreakerState      `json:"state"`
	FailureThreshold       int                      `json:"failure_threshold"`
	ResetTimeout           time.Duration            `json:"reset_timeout"`
	ConsecutiveFailures    int                      `json:"consecutive_failures"`
	LastFailureTime        time.Time                `json:"last_failure_time"`
	TotalFailures          int64                    `json:"total_failures"`
	TotalRequests          int64                    `json:"total_requests"`
	StateTransitions       []StateTransition        `json:"state_transitions"`
}

type CircuitBreakerState string

const (
	CircuitBreakerStateClosed    CircuitBreakerState = "closed"
	CircuitBreakerStateOpen      CircuitBreakerState = "open"
	CircuitBreakerStateHalfOpen  CircuitBreakerState = "half_open"
)

type StateTransition struct {
	From                   CircuitBreakerState      `json:"from"`
	To                     CircuitBreakerState      `json:"to"`
	Timestamp              time.Time                `json:"timestamp"`
	Reason                 string                   `json:"reason"`
}

type HealthThresholds struct {
	ResponseTimeWarning    time.Duration            `json:"response_time_warning"`
	ResponseTimeCritical   time.Duration            `json:"response_time_critical"`
	ErrorRateWarning       float64                  `json:"error_rate_warning"`
	ErrorRateCritical      float64                  `json:"error_rate_critical"`
	AvailabilityMinimum    float64                  `json:"availability_minimum"`
	ConsecutiveFailuresMax int                      `json:"consecutive_failures_max"`
	HealthScoreMinimum     float64                  `json:"health_score_minimum"`
}

type HealthSnapshot struct {
	Timestamp              time.Time                `json:"timestamp"`
	Status                 ServerStatus             `json:"status"`
	ResponseTime           time.Duration            `json:"response_time"`
	ErrorRate              float64                  `json:"error_rate"`
	ResourceUsage          *ResourceUsage           `json:"resource_usage"`
	LoadMetrics            *LoadMetrics             `json:"load_metrics"`
}

type UnhealthyServerInfo struct {
	ServerName             string                   `json:"server_name"`
	UnhealthySince         time.Time                `json:"unhealthy_since"`
	LastError              *ServerError             `json:"last_error"`
	FailureCount           int                      `json:"failure_count"`
	RecoveryAttempts       int                      `json:"recovery_attempts"`
	AutoRecoveryEnabled    bool                     `json:"auto_recovery_enabled"`
	ManualInterventionRequired bool                 `json:"manual_intervention_required"`
}

type RecoveryProgress struct {
	ServerName             string                   `json:"server_name"`
	RecoveryStarted        time.Time                `json:"recovery_started"`
	RecoverySteps          []RecoveryStep           `json:"recovery_steps"`
	CurrentStepIndex       int                      `json:"current_step_index"`
	EstimatedCompletion    time.Time                `json:"estimated_completion"`
	SuccessfulChecks       int                      `json:"successful_checks"`
	RequiredChecks         int                      `json:"required_checks"`
}

type RecoveryStep struct {
	Name                   string                   `json:"name"`
	Description            string                   `json:"description"`
	Status                 StepStatus               `json:"status"`
	StartTime              time.Time                `json:"start_time"`
	CompletionTime         time.Time                `json:"completion_time"`
	ErrorMessage           string                   `json:"error_message,omitempty"`
}

type StepStatus string

const (
	StepStatusPending      StepStatus = "pending"
	StepStatusInProgress   StepStatus = "in_progress"
	StepStatusCompleted    StepStatus = "completed"
	StepStatusFailed       StepStatus = "failed"
	StepStatusSkipped      StepStatus = "skipped"
)

type NotificationChannel struct {
	Type                   NotificationType         `json:"type"`
	Endpoint               string                   `json:"endpoint"`
	Enabled                bool                     `json:"enabled"`
	Severity               []string                 `json:"severity"`
	Template               string                   `json:"template"`
	RateLimitEnabled       bool                     `json:"rate_limit_enabled"`
	RateLimitPeriod        time.Duration            `json:"rate_limit_period"`
	RateLimitMaxMessages   int                      `json:"rate_limit_max_messages"`
}

type NotificationType string

const (
	NotificationTypeWebhook     NotificationType = "webhook"
	NotificationTypeEmail       NotificationType = "email"
	NotificationTypeSlack       NotificationType = "slack"
	NotificationTypePagerDuty   NotificationType = "pagerduty"
	NotificationTypeLog         NotificationType = "log"
)

type HealthAlert struct {
	ID                     string                   `json:"id"`
	Severity               AlertSeverity            `json:"severity"`
	Title                  string                   `json:"title"`
	Description            string                   `json:"description"`
	Timestamp              time.Time                `json:"timestamp"`
	Acknowledged           bool                     `json:"acknowledged"`
	AcknowledgedBy         string                   `json:"acknowledged_by"`
	AcknowledgedAt         time.Time                `json:"acknowledged_at"`
	Resolved               bool                     `json:"resolved"`
	ResolvedAt             time.Time                `json:"resolved_at"`
	Tags                   []string                 `json:"tags"`
	Context                map[string]interface{}   `json:"context"`
}

type AlertSeverity string

const (
	AlertSeverityInfo      AlertSeverity = "info"
	AlertSeverityWarning   AlertSeverity = "warning"
	AlertSeverityCritical  AlertSeverity = "critical"
	AlertSeverityEmergency AlertSeverity = "emergency"
)

type DependencyHealth struct {
	Name                   string                   `json:"name"`
	Status                 string                   `json:"status"`
	LastChecked            time.Time                `json:"last_checked"`
	ResponseTime           time.Duration            `json:"response_time"`
	ErrorMessage           string                   `json:"error_message,omitempty"`
}

// Additional supporting types for configuration

type ResourceLimits struct {
	MaxCPUPercent          float64                  `json:"max_cpu_percent"`
	MaxMemoryBytes         int64                    `json:"max_memory_bytes"`
	MaxFileDescriptors     int                      `json:"max_file_descriptors"`
	MaxGoroutines          int                      `json:"max_goroutines"`
	MaxConnections         int                      `json:"max_connections"`
}

type PerformanceThresholds struct {
	MaxResponseTime        time.Duration            `json:"max_response_time"`
	MaxErrorRate           float64                  `json:"max_error_rate"`
	MinThroughput          float64                  `json:"min_throughput"`
	MaxQueueDepth          int                      `json:"max_queue_depth"`
}

type AutoScalingRules struct {
	ScaleUpThreshold       *ScalingThreshold        `json:"scale_up_threshold"`
	ScaleDownThreshold     *ScalingThreshold        `json:"scale_down_threshold"`
	MinInstances           int                      `json:"min_instances"`
	MaxInstances           int                      `json:"max_instances"`
	CooldownPeriod         time.Duration            `json:"cooldown_period"`
	ScalingPolicy          ScalingPolicy            `json:"scaling_policy"`
}

type ScalingThreshold struct {
	CPUPercent             float64                  `json:"cpu_percent"`
	MemoryPercent          float64                  `json:"memory_percent"`
	RequestsPerSecond      float64                  `json:"requests_per_second"`
	QueueDepth             int                      `json:"queue_depth"`
	ResponseTime           time.Duration            `json:"response_time"`
}

type ScalingPolicy string

const (
	ScalingPolicyLinear       ScalingPolicy = "linear"
	ScalingPolicyExponential  ScalingPolicy = "exponential"
	ScalingPolicyCustom       ScalingPolicy = "custom"
)

type AlertingConfig struct {
	Enabled                bool                     `json:"enabled"`
	DefaultSeverity        AlertSeverity            `json:"default_severity"`
	NotificationChannels   []NotificationChannel    `json:"notification_channels"`
	EscalationRules        []EscalationRule         `json:"escalation_rules"`
	SuppressionalRules     []SuppressionRule        `json:"suppression_rules"`
}

type EscalationRule struct {
	TriggerAfter           time.Duration            `json:"trigger_after"`
	Severity               AlertSeverity            `json:"severity"`
	NotificationChannels   []string                 `json:"notification_channels"`
	Conditions             []string                 `json:"conditions"`
}

type SuppressionRule struct {
	Name                   string                   `json:"name"`
	Conditions             []string                 `json:"conditions"`
	SuppressDuration       time.Duration            `json:"suppress_duration"`
	Enabled                bool                     `json:"enabled"`
}

type SLAMetrics struct {
	Availability           float64                  `json:"availability"`
	ResponseTime           time.Duration            `json:"response_time"`
	Throughput             float64                  `json:"throughput"`
	ErrorRate              float64                  `json:"error_rate"`
	ComplianceScore        float64                  `json:"compliance_score"`
	Violations             []SLAViolation           `json:"violations"`
}

type SLAViolation struct {
	Metric                 string                   `json:"metric"`
	ExpectedValue          interface{}              `json:"expected_value"`
	ActualValue            interface{}              `json:"actual_value"`
	Timestamp              time.Time                `json:"timestamp"`
	Duration               time.Duration            `json:"duration"`
	Severity               AlertSeverity            `json:"severity"`
}

type TrendDataPoint struct {
	Timestamp              time.Time                `json:"timestamp"`
	Metric                 string                   `json:"metric"`
	Value                  float64                  `json:"value"`
	Tags                   map[string]string        `json:"tags"`
}

type ServerManagerMetrics struct {
	TotalServers           int                      `json:"total_servers"`
	HealthyServers         int                      `json:"healthy_servers"`
	UnhealthyServers       int                      `json:"unhealthy_servers"`
	TotalRequests          int64                    `json:"total_requests"`
	SuccessfulRequests     int64                    `json:"successful_requests"`
	FailedRequests         int64                    `json:"failed_requests"`
	AverageResponseTime    time.Duration            `json:"average_response_time"`
	LoadDistribution       map[string]float64       `json:"load_distribution"`
	FailoverEvents         int64                    `json:"failover_events"`
	AutoScalingEvents      int64                    `json:"auto_scaling_events"`
	CircuitBreakerTrips    int64                    `json:"circuit_breaker_trips"`
	LastUpdated            time.Time                `json:"last_updated"`
}

type ConnectionPool struct {
	MaxConnections         int                      `json:"max_connections"`
	ActiveConnections      int                      `json:"active_connections"`
	IdleConnections        int                      `json:"idle_connections"`
	ConnectionsCreated     int64                    `json:"connections_created"`
	ConnectionsDestroyed   int64                    `json:"connections_destroyed"`
	ConnectionErrors       int64                    `json:"connection_errors"`
	AverageConnectionTime  time.Duration            `json:"average_connection_time"`
	PoolUtilization        float64                  `json:"pool_utilization"`
}

type ServerConnectionPool struct {
	Connections            map[string]*Connection   `json:"connections"`
	MaxConnections         int                      `json:"max_connections"`
	IdleTimeout            time.Duration            `json:"idle_timeout"`
	HealthCheckInterval    time.Duration            `json:"health_check_interval"`
	LastCleanup            time.Time                `json:"last_cleanup"`
}

type Connection struct {
	ID                     string                   `json:"id"`
	CreatedAt              time.Time                `json:"created_at"`
	LastUsed               time.Time                `json:"last_used"`
	IsActive               bool                     `json:"is_active"`
	RequestCount           int64                    `json:"request_count"`
	ErrorCount             int64                    `json:"error_count"`
	AverageResponseTime    time.Duration            `json:"average_response_time"`
}

// NewEnhancedServerManager creates a new enhanced MCP server manager
func NewEnhancedServerManager(
	registry *MCPServerRegistry,
	config *ServerManagerConfig,
	errorHandler *errors.ErrorClassifier,
	resilienceManager *errors.ResilienceWrapper,
	degradationManager *errors.ServiceDegradationManager,
	logger *zap.Logger,
) *EnhancedServerManager {
	if config == nil {
		config = DefaultServerManagerConfig()
	}

	manager := &EnhancedServerManager{
		registry:                registry,
		serverInstances:         make(map[string]*ExtendedServerInstance),
		agentAssignments:        make(map[string]*AgentServerAssignment),
		config:                  config,
		logger:                  logger.With(zap.String("component", "enhanced_server_manager")),
		errorHandler:           errorHandler,
		resilienceManager:      resilienceManager,
		degradationManager:     degradationManager,
		metrics:                &ServerManagerMetrics{},
		connectionPool:         &ConnectionPool{
			MaxConnections: config.ConnectionPoolSize,
		},
	}

	// Initialize load balancer
	manager.loadBalancer = &LoadBalancer{
		Strategy:                config.LoadBalancingStrategy,
		WeightConfiguration:     make(map[string]int),
		HealthAwareRouting:      true,
		StickySessionEnabled:    false,
		SessionAffinityRules:    make(map[string]string),
		RoundRobinCounters:      make(map[string]int),
		RequestDistribution:     make(map[string]*DistributionStats),
		CircuitBreakerEnabled:   true,
		CircuitBreakers:         make(map[string]*ServerCircuitBreaker),
	}

	// Initialize health monitor
	manager.healthMonitor = &HealthMonitor{
		HealthCheckInterval:    config.HealthCheckInterval,
		HealthThresholds:       &HealthThresholds{
			ResponseTimeWarning:    500 * time.Millisecond,
			ResponseTimeCritical:   2 * time.Second,
			ErrorRateWarning:       0.05,
			ErrorRateCritical:      0.15,
			AvailabilityMinimum:    0.95,
			ConsecutiveFailuresMax: 3,
			HealthScoreMinimum:     0.7,
		},
		AlertingEnabled:        true,
		HealthHistory:          make(map[string][]*HealthSnapshot),
		UnhealthyServers:       make(map[string]*UnhealthyServerInfo),
		RecoveryTracking:       make(map[string]*RecoveryProgress),
		NotificationChannels:   config.AlertingConfig.NotificationChannels,
	}

	return manager
}

// DefaultServerManagerConfig returns default configuration for the enhanced server manager
func DefaultServerManagerConfig() *ServerManagerConfig {
	return &ServerManagerConfig{
		DefaultTimeout:          30 * time.Second,
		MaxRetryAttempts:        3,
		HealthCheckInterval:     30 * time.Second,
		LoadBalancingStrategy:   LoadBalancingStrategyHealthBased,
		FailoverEnabled:         true,
		ConnectionPoolSize:      50,
		MaxConcurrentRequests:   100,
		GracefulShutdownTimeout: 30 * time.Second,
		ResourceLimits: &ResourceLimits{
			MaxCPUPercent:      80.0,
			MaxMemoryBytes:     1024 * 1024 * 1024, // 1GB
			MaxFileDescriptors: 1000,
			MaxGoroutines:      500,
			MaxConnections:     100,
		},
		PerformanceThresholds: &PerformanceThresholds{
			MaxResponseTime: 5 * time.Second,
			MaxErrorRate:    0.10,
			MinThroughput:   1.0,
			MaxQueueDepth:   50,
		},
		AutoScalingEnabled: false,
		AutoScalingRules: &AutoScalingRules{
			ScaleUpThreshold: &ScalingThreshold{
				CPUPercent:        70.0,
				MemoryPercent:     80.0,
				RequestsPerSecond: 100.0,
				QueueDepth:        20,
				ResponseTime:      2 * time.Second,
			},
			ScaleDownThreshold: &ScalingThreshold{
				CPUPercent:        30.0,
				MemoryPercent:     40.0,
				RequestsPerSecond: 20.0,
				QueueDepth:        5,
				ResponseTime:      500 * time.Millisecond,
			},
			MinInstances:  1,
			MaxInstances:  5,
			CooldownPeriod: 5 * time.Minute,
			ScalingPolicy: ScalingPolicyLinear,
		},
		AlertingConfig: &AlertingConfig{
			Enabled:         true,
			DefaultSeverity: AlertSeverityWarning,
			NotificationChannels: []NotificationChannel{
				{
					Type:    NotificationTypeLog,
					Enabled: true,
					Severity: []string{"warning", "critical", "emergency"},
				},
			},
			EscalationRules:   []EscalationRule{},
			SuppressionalRules: []SuppressionRule{},
		},
	}
}

// Core functionality would be implemented here:
// - AssignServerToAgent
// - GetOptimalServer
// - PerformHealthCheck
// - HandleServerFailure
// - LoadBalanceRequest
// - ScaleServers
// - etc.

// Placeholder implementation for key methods
func (esm *EnhancedServerManager) AssignServerToAgent(agentType, agentName string, serverNames []string, assignment *AgentServerAssignment) error {
	esm.mutex.Lock()
	defer esm.mutex.Unlock()

	if assignment == nil {
		assignment = &AgentServerAssignment{
			AgentType:             agentType,
			AgentName:             agentName,
			PrimaryServers:        serverNames,
			LoadBalancingEnabled:  true,
			FailoverEnabled:       true,
			MaxConcurrentRequests: esm.config.MaxConcurrentRequests,
			TimeoutConfiguration: &TimeoutConfig{
				ConnectionTimeout: esm.config.DefaultTimeout,
				RequestTimeout:    esm.config.DefaultTimeout,
				IdleTimeout:       5 * time.Minute,
				KeepAliveTimeout:  30 * time.Second,
				HandshakeTimeout:  10 * time.Second,
			},
			RetryPolicy: &RetryPolicy{
				MaxAttempts:           esm.config.MaxRetryAttempts,
				InitialDelay:          100 * time.Millisecond,
				MaxDelay:              5 * time.Second,
				BackoffMultiplier:     2.0,
				CircuitBreakerEnabled: true,
				JitterEnabled:         true,
			},
			HealthCheckFrequency: esm.config.HealthCheckInterval,
		}
	}

	assignment.PrimaryServers = serverNames
	esm.agentAssignments[agentType] = assignment

	esm.logger.Info("Server assignment updated",
		zap.String("agent_type", agentType),
		zap.String("agent_name", agentName),
		zap.Strings("servers", serverNames))

	return nil
}

func (esm *EnhancedServerManager) GetOptimalServer(agentType string, context map[string]interface{}) (string, error) {
	esm.mutex.RLock()
	defer esm.mutex.RUnlock()

	assignment, exists := esm.agentAssignments[agentType]
	if !exists {
		return "", fmt.Errorf("no server assignment found for agent type: %s", agentType)
	}

	// Apply load balancing strategy to select optimal server
	return esm.loadBalancer.SelectServer(assignment.PrimaryServers, context)
}

// LoadBalancer methods
func (lb *LoadBalancer) SelectServer(servers []string, context map[string]interface{}) (string, error) {
	if len(servers) == 0 {
		return "", fmt.Errorf("no servers available for selection")
	}

	switch lb.Strategy {
	case LoadBalancingStrategyRoundRobin:
		return lb.selectRoundRobin(servers)
	case LoadBalancingStrategyHealthBased:
		return lb.selectHealthBased(servers)
	case LoadBalancingStrategyLeastConnections:
		return lb.selectLeastConnections(servers)
	default:
		return servers[0], nil // Fallback to first server
	}
}

func (lb *LoadBalancer) selectRoundRobin(servers []string) (string, error) {
	if len(servers) == 0 {
		return "", fmt.Errorf("no servers available")
	}

	key := fmt.Sprintf("rr_%v", servers)
	counter := lb.RoundRobinCounters[key]
	selectedIndex := counter % len(servers)
	lb.RoundRobinCounters[key] = counter + 1

	return servers[selectedIndex], nil
}

func (lb *LoadBalancer) selectHealthBased(servers []string) (string, error) {
	// Filter healthy servers first
	healthyServers := make([]string, 0, len(servers))
	for _, server := range servers {
		if stats, exists := lb.RequestDistribution[server]; exists {
			// Consider server healthy if error rate is acceptable
			errorRate := float64(stats.FailedRequests) / float64(stats.TotalRequests)
			if stats.TotalRequests == 0 || errorRate < 0.1 {
				healthyServers = append(healthyServers, server)
			}
		} else {
			// New server, consider it healthy
			healthyServers = append(healthyServers, server)
		}
	}

	if len(healthyServers) == 0 {
		// Fallback to any available server if none are healthy
		if len(servers) > 0 {
			return servers[0], nil
		}
		return "", fmt.Errorf("no healthy servers available")
	}

	// Select server with best health score
	bestServer := healthyServers[0]
	bestScore := lb.calculateHealthScore(bestServer)

	for _, server := range healthyServers[1:] {
		score := lb.calculateHealthScore(server)
		if score > bestScore {
			bestScore = score
			bestServer = server
		}
	}

	return bestServer, nil
}

func (lb *LoadBalancer) selectLeastConnections(servers []string) (string, error) {
	if len(servers) == 0 {
		return "", fmt.Errorf("no servers available")
	}

	leastConnections := int64(999999)
	selectedServer := servers[0]

	for _, server := range servers {
		if stats, exists := lb.RequestDistribution[server]; exists {
			activeRequests := stats.TotalRequests - stats.SuccessfulRequests - stats.FailedRequests
			if activeRequests < leastConnections {
				leastConnections = activeRequests
				selectedServer = server
			}
		} else {
			// New server with no connections, prioritize it
			return server, nil
		}
	}

	return selectedServer, nil
}

// calculateHealthScore calculates a health score for a server based on various metrics
func (lb *LoadBalancer) calculateHealthScore(serverName string) float64 {
	if stats, exists := lb.RequestDistribution[serverName]; exists && stats.TotalRequests > 0 {
		successRate := float64(stats.SuccessfulRequests) / float64(stats.TotalRequests)
		responseTimeFactor := 1.0

		// Lower response times get higher scores
		if stats.AverageResponseTime > 0 {
			responseTimeFactor = 1.0 / (float64(stats.AverageResponseTime.Milliseconds()) / 1000.0)
		}

		// Combine success rate and response time for overall health score
		return (successRate * 0.7) + (responseTimeFactor * 0.3)
	}

	// New server gets neutral score
	return 0.5
}

// PerformHealthCheck performs comprehensive health checks on all managed servers
func (esm *EnhancedServerManager) PerformHealthCheck(ctx context.Context) (*HealthCheckResult, error) {
	esm.mutex.Lock()
	defer esm.mutex.Unlock()

	result := &HealthCheckResult{
		Timestamp:          time.Now(),
		TotalServers:       len(esm.serverInstances),
		HealthyServers:     0,
		UnhealthyServers:   0,
		DegradedServers:    0,
		ServerHealth:       make(map[string]*ExtendedServerHealth),
		OverallStatus:      "healthy",
		IssuesDetected:     []string{},
		Recommendations:    []string{},
	}

	for serverName, instance := range esm.serverInstances {
		serverHealth := esm.checkServerHealth(ctx, serverName, instance)
		result.ServerHealth[serverName] = serverHealth
		// Update the embedded base health from the extended health
		if serverHealth.ServerHealth != nil {
			instance.Health = serverHealth.ServerHealth
		}

		switch serverHealth.Status {
		case ServerStatusRunning:
			result.HealthyServers++
		case ServerStatusDegraded:
			result.DegradedServers++
			result.IssuesDetected = append(result.IssuesDetected,
				fmt.Sprintf("Server %s is degraded: %v", serverName, serverHealth.Alerts))
		case ServerStatusUnhealthy, ServerStatusFailed:
			result.UnhealthyServers++
			result.IssuesDetected = append(result.IssuesDetected,
				fmt.Sprintf("Server %s is unhealthy: %v", serverName, serverHealth.Alerts))
		}
	}

	// Determine overall status
	if result.UnhealthyServers > 0 {
		result.OverallStatus = "critical"
	} else if result.DegradedServers > 0 {
		result.OverallStatus = "degraded"
	}

	// Generate recommendations
	esm.generateHealthRecommendations(result)

	esm.lastHealthCheck = time.Now()
	esm.logger.Info("Health check completed",
		zap.Int("total_servers", result.TotalServers),
		zap.Int("healthy", result.HealthyServers),
		zap.Int("degraded", result.DegradedServers),
		zap.Int("unhealthy", result.UnhealthyServers),
		zap.String("overall_status", result.OverallStatus))

	return result, nil
}

// checkServerHealth performs health check on a single server
func (esm *EnhancedServerManager) checkServerHealth(ctx context.Context, serverName string, instance *ExtendedServerInstance) *ExtendedServerHealth {
	health := &ExtendedServerHealth{
		ServerHealth: &ServerHealth{
			IsHealthy:    true,
			LastCheck:    time.Now(),
			FailureCount: 0,
			ResponseTime: 0,
		},
		Status:              ServerStatusRunning,
		ConsecutiveFailures: 0,
		HealthScore:         1.0,
		Alerts:              []HealthAlert{},
		Dependencies:        make(map[string]DependencyHealth),
	}

	// Check server responsiveness
	responseTime, err := esm.pingServer(ctx, serverName)
	if err != nil {
		health.Status = ServerStatusUnhealthy
		// Use FailureCount from base ServerHealth and increment our extended field
		if instance.Health != nil {
			health.ConsecutiveFailures = instance.Health.FailureCount + 1
			health.ServerHealth.FailureCount = health.ConsecutiveFailures
		} else {
			health.ConsecutiveFailures = 1
			health.ServerHealth.FailureCount = 1
		}
		health.HealthScore = 0.0
		health.Alerts = append(health.Alerts, HealthAlert{
			ID:          fmt.Sprintf("ping_failure_%s_%d", serverName, time.Now().Unix()),
			Severity:    AlertSeverityCritical,
			Title:       "Server Ping Failed",
			Description: fmt.Sprintf("Failed to ping server %s: %v", serverName, err),
			Timestamp:   time.Now(),
		})
		esm.logger.Error("Server ping failed", zap.String("server", serverName), zap.Error(err))
		return health
	}

	health.ServerHealth.ResponseTime = responseTime

	// Check response time thresholds
	if responseTime > esm.healthMonitor.HealthThresholds.ResponseTimeCritical {
		health.Status = ServerStatusDegraded
		health.HealthScore *= 0.5
		health.Alerts = append(health.Alerts, HealthAlert{
			ID:          fmt.Sprintf("slow_response_%s_%d", serverName, time.Now().Unix()),
			Severity:    AlertSeverityWarning,
			Title:       "Slow Response Time",
			Description: fmt.Sprintf("Server %s response time %v exceeds critical threshold %v",
				serverName, responseTime, esm.healthMonitor.HealthThresholds.ResponseTimeCritical),
			Timestamp:   time.Now(),
		})
	} else if responseTime > esm.healthMonitor.HealthThresholds.ResponseTimeWarning {
		health.Alerts = append(health.Alerts, HealthAlert{
			ID:          fmt.Sprintf("elevated_response_%s_%d", serverName, time.Now().Unix()),
			Severity:    AlertSeverityInfo,
			Title:       "Elevated Response Time",
			Description: fmt.Sprintf("Server %s response time %v exceeds warning threshold %v",
				serverName, responseTime, esm.healthMonitor.HealthThresholds.ResponseTimeWarning),
			Timestamp:   time.Now(),
		})
	}

	// Check error rates
	if instance.LoadMetrics != nil {
		if instance.LoadMetrics.TotalRequests > 0 {
			errorRate := float64(instance.LoadMetrics.FailedRequests) / float64(instance.LoadMetrics.TotalRequests)
			health.ErrorRate = errorRate

			if errorRate > esm.healthMonitor.HealthThresholds.ErrorRateCritical {
				health.Status = ServerStatusDegraded
				health.HealthScore *= 0.3
				health.Alerts = append(health.Alerts, HealthAlert{
					ID:          fmt.Sprintf("high_error_rate_%s_%d", serverName, time.Now().Unix()),
					Severity:    AlertSeverityCritical,
					Title:       "High Error Rate",
					Description: fmt.Sprintf("Server %s error rate %.2f%% exceeds critical threshold %.2f%%",
						serverName, errorRate*100, esm.healthMonitor.HealthThresholds.ErrorRateCritical*100),
					Timestamp:   time.Now(),
				})
			} else if errorRate > esm.healthMonitor.HealthThresholds.ErrorRateWarning {
				health.HealthScore *= 0.7
				health.Alerts = append(health.Alerts, HealthAlert{
					ID:          fmt.Sprintf("elevated_error_rate_%s_%d", serverName, time.Now().Unix()),
					Severity:    AlertSeverityWarning,
					Title:       "Elevated Error Rate",
					Description: fmt.Sprintf("Server %s error rate %.2f%% exceeds warning threshold %.2f%%",
						serverName, errorRate*100, esm.healthMonitor.HealthThresholds.ErrorRateWarning*100),
					Timestamp:   time.Now(),
				})
			}
		}
	}

	// Check resource usage if available
	if instance.ResourceUsage != nil {
		esm.checkResourceThresholds(serverName, instance.ResourceUsage, health)
	}

	// Calculate availability percentage
	if instance.StartTime.Before(time.Now().Add(-time.Hour)) {
		// Only calculate availability for servers running for more than an hour
		uptime := time.Since(instance.StartTime)
		if health.ConsecutiveFailures == 0 {
			health.AvailabilityPercent = 100.0
		} else {
			// Simplified availability calculation
			failureTime := time.Duration(health.ConsecutiveFailures) * esm.config.HealthCheckInterval
			health.AvailabilityPercent = (1.0 - float64(failureTime)/float64(uptime)) * 100.0
		}
	} else {
		health.AvailabilityPercent = 100.0 // New server, assume available
	}

	return health
}

// HandleServerFailure handles server failure scenarios with appropriate recovery actions
func (esm *EnhancedServerManager) HandleServerFailure(ctx context.Context, serverName string, failure *ServerError) error {
	esm.mutex.Lock()
	defer esm.mutex.Unlock()

	instance, exists := esm.serverInstances[serverName]
	if !exists {
		return fmt.Errorf("server instance %s not found", serverName)
	}

	// Record the failure
	instance.ErrorHistory = append(instance.ErrorHistory, *failure)
	instance.Status = ServerStatusFailed
	instance.LastActivity = time.Now()

	esm.logger.Error("Server failure detected",
		zap.String("server", serverName),
		zap.String("error_type", failure.ErrorType),
		zap.String("error_message", failure.ErrorMessage),
		zap.String("severity", failure.Severity))

	// Update circuit breaker if enabled
	if esm.loadBalancer.CircuitBreakerEnabled {
		if breaker, exists := esm.loadBalancer.CircuitBreakers[serverName]; exists {
			breaker.ConsecutiveFailures++
			breaker.TotalFailures++
			breaker.LastFailureTime = time.Now()

			if breaker.ConsecutiveFailures >= breaker.FailureThreshold {
				esm.openCircuitBreaker(serverName, breaker)
			}
		}
	}

	// Trigger recovery actions based on failure type and restart policy
	switch instance.RestartPolicy {
	case RestartPolicyAlways, RestartPolicyOnFailure:
		if instance.RestartCount < 5 { // Limit restart attempts
			esm.logger.Info("Attempting server restart",
				zap.String("server", serverName),
				zap.Int("restart_count", instance.RestartCount))

			if err := esm.restartServer(ctx, serverName, instance); err != nil {
				esm.logger.Error("Server restart failed",
					zap.String("server", serverName),
					zap.Error(err))
				return err
			}
		} else {
			esm.logger.Error("Maximum restart attempts exceeded",
				zap.String("server", serverName),
				zap.Int("restart_count", instance.RestartCount))
			instance.Status = ServerStatusFailed
		}

	case RestartPolicyNever:
		esm.logger.Info("Server restart disabled by policy",
			zap.String("server", serverName))
		instance.Status = ServerStatusFailed

	case RestartPolicyUnlessStopped:
		if instance.Status != ServerStatusStopped {
			if err := esm.restartServer(ctx, serverName, instance); err != nil {
				return err
			}
		}
	}

	// Update health tracking
	if unhealthyInfo, exists := esm.healthMonitor.UnhealthyServers[serverName]; exists {
		unhealthyInfo.FailureCount++
		unhealthyInfo.LastError = failure
	} else {
		esm.healthMonitor.UnhealthyServers[serverName] = &UnhealthyServerInfo{
			ServerName:                 serverName,
			UnhealthySince:             time.Now(),
			LastError:                  failure,
			FailureCount:               1,
			RecoveryAttempts:           0,
			AutoRecoveryEnabled:        instance.RestartPolicy != RestartPolicyNever,
			ManualInterventionRequired: instance.RestartCount >= 5,
		}
	}

	// Update metrics
	esm.updateFailureMetrics(serverName, failure)

	return nil
}

// LoadBalanceRequest routes a request to the optimal server using configured strategy
func (esm *EnhancedServerManager) LoadBalanceRequest(ctx context.Context, agentType string, requestContext map[string]interface{}) (string, error) {
	assignment, exists := esm.agentAssignments[agentType]
	if !exists {
		return "", fmt.Errorf("no server assignment found for agent type: %s", agentType)
	}

	// Filter available servers based on health and circuit breaker status
	availableServers := esm.getAvailableServers(assignment.PrimaryServers)
	if len(availableServers) == 0 {
		// Try fallback servers if primary servers are unavailable
		if len(assignment.FallbackServers) > 0 {
			availableServers = esm.getAvailableServers(assignment.FallbackServers)
		}

		if len(availableServers) == 0 {
			return "", fmt.Errorf("no available servers for agent type: %s", agentType)
		}
	}

	// Use load balancer to select optimal server
	selectedServer, err := esm.loadBalancer.SelectServer(availableServers, requestContext)
	if err != nil {
		return "", fmt.Errorf("failed to select server: %w", err)
	}

	// Update request tracking
	esm.updateRequestMetrics(selectedServer)

	esm.logger.Debug("Request load balanced",
		zap.String("agent_type", agentType),
		zap.String("selected_server", selectedServer),
		zap.Strings("available_servers", availableServers))

	return selectedServer, nil
}

// Supporting helper methods

// HealthCheckResult represents the result of a comprehensive health check
type HealthCheckResult struct {
	Timestamp          time.Time                        `json:"timestamp"`
	TotalServers       int                              `json:"total_servers"`
	HealthyServers     int                              `json:"healthy_servers"`
	UnhealthyServers   int                              `json:"unhealthy_servers"`
	DegradedServers    int                              `json:"degraded_servers"`
	ServerHealth       map[string]*ExtendedServerHealth `json:"server_health"`
	OverallStatus      string                           `json:"overall_status"`
	IssuesDetected     []string                         `json:"issues_detected"`
	Recommendations    []string                         `json:"recommendations"`
}

// pingServer performs a basic connectivity check to a server
func (esm *EnhancedServerManager) pingServer(ctx context.Context, serverName string) (time.Duration, error) {
	startTime := time.Now()

	// In a real implementation, this would perform an actual health check
	// For now, simulate a ping with variable response time
	simulatedDelay := time.Duration(50 + (time.Now().UnixNano() % 200)) * time.Millisecond

	select {
	case <-time.After(simulatedDelay):
		return time.Since(startTime), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// checkResourceThresholds checks if resource usage exceeds configured thresholds
func (esm *EnhancedServerManager) checkResourceThresholds(serverName string, usage *ResourceUsage, health *ExtendedServerHealth) {
	if esm.config.ResourceLimits == nil {
		return
	}

	// Check CPU usage
	if usage.CPUPercent > esm.config.ResourceLimits.MaxCPUPercent {
		health.Status = ServerStatusDegraded
		health.HealthScore *= 0.6
		health.Alerts = append(health.Alerts, HealthAlert{
			ID:          fmt.Sprintf("high_cpu_%s_%d", serverName, time.Now().Unix()),
			Severity:    AlertSeverityWarning,
			Title:       "High CPU Usage",
			Description: fmt.Sprintf("Server %s CPU usage %.1f%% exceeds limit %.1f%%",
				serverName, usage.CPUPercent, esm.config.ResourceLimits.MaxCPUPercent),
			Timestamp:   time.Now(),
		})
	}

	// Check memory usage
	if usage.MemoryUsageBytes > esm.config.ResourceLimits.MaxMemoryBytes {
		health.Status = ServerStatusDegraded
		health.HealthScore *= 0.6
		health.Alerts = append(health.Alerts, HealthAlert{
			ID:          fmt.Sprintf("high_memory_%s_%d", serverName, time.Now().Unix()),
			Severity:    AlertSeverityWarning,
			Title:       "High Memory Usage",
			Description: fmt.Sprintf("Server %s memory usage %d bytes exceeds limit %d bytes",
				serverName, usage.MemoryUsageBytes, esm.config.ResourceLimits.MaxMemoryBytes),
			Timestamp:   time.Now(),
		})
	}

	// Check file descriptors
	if usage.FileDescriptors > esm.config.ResourceLimits.MaxFileDescriptors {
		health.Alerts = append(health.Alerts, HealthAlert{
			ID:          fmt.Sprintf("high_fd_%s_%d", serverName, time.Now().Unix()),
			Severity:    AlertSeverityInfo,
			Title:       "High File Descriptor Usage",
			Description: fmt.Sprintf("Server %s file descriptors %d exceeds limit %d",
				serverName, usage.FileDescriptors, esm.config.ResourceLimits.MaxFileDescriptors),
			Timestamp:   time.Now(),
		})
	}

	// Check goroutine count
	if usage.GoroutineCount > esm.config.ResourceLimits.MaxGoroutines {
		health.Alerts = append(health.Alerts, HealthAlert{
			ID:          fmt.Sprintf("high_goroutines_%s_%d", serverName, time.Now().Unix()),
			Severity:    AlertSeverityInfo,
			Title:       "High Goroutine Count",
			Description: fmt.Sprintf("Server %s goroutine count %d exceeds limit %d",
				serverName, usage.GoroutineCount, esm.config.ResourceLimits.MaxGoroutines),
			Timestamp:   time.Now(),
		})
	}
}

// generateHealthRecommendations generates actionable recommendations based on health check results
func (esm *EnhancedServerManager) generateHealthRecommendations(result *HealthCheckResult) {
	if result.UnhealthyServers > 0 {
		result.Recommendations = append(result.Recommendations,
			"Immediate attention required for unhealthy servers. Check logs and restart if necessary.")
	}

	if result.DegradedServers > 0 {
		result.Recommendations = append(result.Recommendations,
			"Monitor degraded servers closely. Consider scaling resources or redistributing load.")
	}

	if float64(result.HealthyServers)/float64(result.TotalServers) < 0.8 {
		result.Recommendations = append(result.Recommendations,
			"Overall server health is below optimal. Consider adding more server instances.")
	}

	if len(result.IssuesDetected) > 10 {
		result.Recommendations = append(result.Recommendations,
			"High number of issues detected. Review server configurations and resource allocations.")
	}
}

// openCircuitBreaker opens a circuit breaker for a server
func (esm *EnhancedServerManager) openCircuitBreaker(serverName string, breaker *ServerCircuitBreaker) {
	breaker.State = CircuitBreakerStateOpen
	breaker.StateTransitions = append(breaker.StateTransitions, StateTransition{
		From:      CircuitBreakerStateClosed,
		To:        CircuitBreakerStateOpen,
		Timestamp: time.Now(),
		Reason:    fmt.Sprintf("Failure threshold exceeded: %d consecutive failures", breaker.ConsecutiveFailures),
	})

	esm.logger.Warn("Circuit breaker opened",
		zap.String("server", serverName),
		zap.Int("consecutive_failures", breaker.ConsecutiveFailures),
		zap.Int("failure_threshold", breaker.FailureThreshold))

	// Schedule automatic reset attempt
	go func() {
		time.Sleep(breaker.ResetTimeout)
		esm.attemptCircuitBreakerReset(serverName, breaker)
	}()
}

// attemptCircuitBreakerReset attempts to reset a circuit breaker
func (esm *EnhancedServerManager) attemptCircuitBreakerReset(serverName string, breaker *ServerCircuitBreaker) {
	esm.mutex.Lock()
	defer esm.mutex.Unlock()

	if breaker.State == CircuitBreakerStateOpen {
		breaker.State = CircuitBreakerStateHalfOpen
		breaker.StateTransitions = append(breaker.StateTransitions, StateTransition{
			From:      CircuitBreakerStateOpen,
			To:        CircuitBreakerStateHalfOpen,
			Timestamp: time.Now(),
			Reason:    "Automatic reset timeout reached",
		})

		esm.logger.Info("Circuit breaker moved to half-open state",
			zap.String("server", serverName))

		// Test the server and fully close circuit breaker if successful
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if _, err := esm.pingServer(ctx, serverName); err == nil {
			breaker.State = CircuitBreakerStateClosed
			breaker.ConsecutiveFailures = 0
			breaker.StateTransitions = append(breaker.StateTransitions, StateTransition{
				From:      CircuitBreakerStateHalfOpen,
				To:        CircuitBreakerStateClosed,
				Timestamp: time.Now(),
				Reason:    "Server health check successful",
			})

			esm.logger.Info("Circuit breaker closed - server recovered",
				zap.String("server", serverName))
		} else {
			breaker.State = CircuitBreakerStateOpen
			breaker.StateTransitions = append(breaker.StateTransitions, StateTransition{
				From:      CircuitBreakerStateHalfOpen,
				To:        CircuitBreakerStateOpen,
				Timestamp: time.Now(),
				Reason:    "Server health check failed during reset attempt",
			})

			esm.logger.Warn("Circuit breaker reopened - server still unhealthy",
				zap.String("server", serverName),
				zap.Error(err))
		}
	}
}

// restartServer attempts to restart a failed server
func (esm *EnhancedServerManager) restartServer(ctx context.Context, serverName string, instance *ExtendedServerInstance) error {
	instance.RestartCount++
	instance.Status = ServerStatusStarting

	esm.logger.Info("Restarting server",
		zap.String("server", serverName),
		zap.Int("restart_count", instance.RestartCount))

	// In a real implementation, this would trigger actual server restart
	// For now, simulate restart process
	time.Sleep(2 * time.Second)

	// Simulate restart success/failure
	if instance.RestartCount <= 3 {
		instance.Status = ServerStatusRunning
		instance.StartTime = time.Now()
		instance.LastActivity = time.Now()

		// Reset consecutive failures on successful restart
		if instance.Health != nil {
			instance.Health.FailureCount = 0
		}

		esm.logger.Info("Server restart successful",
			zap.String("server", serverName))
		return nil
	} else {
		instance.Status = ServerStatusFailed
		esm.logger.Error("Server restart failed",
			zap.String("server", serverName))
		return fmt.Errorf("server restart failed after %d attempts", instance.RestartCount)
	}
}

// getAvailableServers filters servers based on health and circuit breaker status
func (esm *EnhancedServerManager) getAvailableServers(servers []string) []string {
	available := make([]string, 0, len(servers))

	for _, server := range servers {
		// Check if server instance exists and is healthy
		if instance, exists := esm.serverInstances[server]; exists {
			if instance.Status == ServerStatusRunning || instance.Status == ServerStatusDegraded {
				// Check circuit breaker status
				if breaker, exists := esm.loadBalancer.CircuitBreakers[server]; exists {
					if breaker.State != CircuitBreakerStateOpen {
						available = append(available, server)
					}
				} else {
					available = append(available, server)
				}
			}
		}
	}

	return available
}

// updateRequestMetrics updates request tracking metrics for a server
func (esm *EnhancedServerManager) updateRequestMetrics(serverName string) {
	esm.mutex.Lock()
	defer esm.mutex.Unlock()

	if stats, exists := esm.loadBalancer.RequestDistribution[serverName]; exists {
		stats.TotalRequests++
		stats.LastRequestTime = time.Now()
	} else {
		esm.loadBalancer.RequestDistribution[serverName] = &DistributionStats{
			TotalRequests:   1,
			LastRequestTime: time.Now(),
		}
	}

	// Update global metrics
	esm.metrics.TotalRequests++
	esm.metrics.LastUpdated = time.Now()
}

// updateFailureMetrics updates failure tracking metrics
func (esm *EnhancedServerManager) updateFailureMetrics(serverName string, failure *ServerError) {
	esm.mutex.Lock()
	defer esm.mutex.Unlock()

	if stats, exists := esm.loadBalancer.RequestDistribution[serverName]; exists {
		stats.FailedRequests++
	}

	esm.metrics.FailedRequests++
	esm.metrics.LastUpdated = time.Now()
}

// GetServerMetrics returns comprehensive metrics for all managed servers
func (esm *EnhancedServerManager) GetServerMetrics() *ServerManagerMetrics {
	esm.mutex.RLock()
	defer esm.mutex.RUnlock()

	// Update current metrics
	esm.metrics.TotalServers = len(esm.serverInstances)
	esm.metrics.HealthyServers = 0
	esm.metrics.UnhealthyServers = 0

	for _, instance := range esm.serverInstances {
		switch instance.Status {
		case ServerStatusRunning:
			esm.metrics.HealthyServers++
		case ServerStatusUnhealthy, ServerStatusFailed:
			esm.metrics.UnhealthyServers++
		}
	}

	// Calculate load distribution
	esm.metrics.LoadDistribution = make(map[string]float64)
	totalRequests := int64(0)
	for _, stats := range esm.loadBalancer.RequestDistribution {
		totalRequests += stats.TotalRequests
	}

	if totalRequests > 0 {
		for server, stats := range esm.loadBalancer.RequestDistribution {
			esm.metrics.LoadDistribution[server] = float64(stats.TotalRequests) / float64(totalRequests)
		}
	}

	// Return a copy to avoid race conditions
	metrics := *esm.metrics
	return &metrics
}

// Shutdown gracefully shuts down the enhanced server manager
func (esm *EnhancedServerManager) Shutdown(ctx context.Context) error {
	esm.logger.Info("Shutting down enhanced server manager")

	esm.mutex.Lock()
	defer esm.mutex.Unlock()

	// Set all servers to shutting down status
	for serverName, instance := range esm.serverInstances {
		if instance.Status == ServerStatusRunning {
			instance.Status = ServerStatusShuttingDown
			esm.logger.Info("Server shutdown initiated", zap.String("server", serverName))

			// In a real implementation, this would trigger graceful server shutdown
			if instance.GracefulShutdownTimer != nil {
				instance.GracefulShutdownTimer.Stop()
			}

			instance.GracefulShutdownTimer = time.AfterFunc(esm.config.GracefulShutdownTimeout, func() {
				esm.mutex.Lock()
				instance.Status = ServerStatusStopped
				esm.logger.Info("Server shutdown completed", zap.String("server", serverName))
				esm.mutex.Unlock()
			})
		}
	}

	esm.logger.Info("Enhanced server manager shutdown completed")
	return nil
}