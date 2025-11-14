package monitoring

import (
	"runtime"
	"sync"
	"time"
)

// MetricsCollector collects and aggregates system metrics
type MetricsCollector struct {
	mu      sync.RWMutex
	metrics *SystemMetrics
	started time.Time
}

// SystemMetrics represents comprehensive system metrics
type SystemMetrics struct {
	// System information
	StartTime    time.Time `json:"start_time"`
	Uptime       string    `json:"uptime"`
	GoVersion    string    `json:"go_version"`
	NumCPU       int       `json:"num_cpu"`
	NumGoroutine int       `json:"num_goroutine"`

	// Memory metrics
	Memory *MemoryMetrics `json:"memory"`

	// Agent metrics
	Agents *AgentMetrics `json:"agents"`

	// Pipeline metrics
	Pipeline *PipelineMetrics `json:"pipeline"`

	// MCP metrics
	MCP *MCPMetrics `json:"mcp"`

	// Performance metrics
	Performance *PerformanceMetrics `json:"performance"`

	// Last updated
	LastUpdated time.Time `json:"last_updated"`
}

// MemoryMetrics represents memory usage metrics
type MemoryMetrics struct {
	AllocatedMB     uint64 `json:"allocated_mb"`
	TotalAllocMB    uint64 `json:"total_alloc_mb"`
	SystemMB        uint64 `json:"system_mb"`
	NumGC           uint32 `json:"num_gc"`
	GCCPUFraction   float64 `json:"gc_cpu_fraction"`
	HeapAllocMB     uint64 `json:"heap_alloc_mb"`
	HeapSysMB       uint64 `json:"heap_sys_mb"`
	HeapIdleMB      uint64 `json:"heap_idle_mb"`
	HeapInuseMB     uint64 `json:"heap_inuse_mb"`
	HeapReleasedMB  uint64 `json:"heap_released_mb"`
	StackInuseMB    uint64 `json:"stack_inuse_mb"`
	StackSysMB      uint64 `json:"stack_sys_mb"`
}

// AgentMetrics represents agent-related metrics
type AgentMetrics struct {
	TotalAgents          int                            `json:"total_agents"`
	HealthyAgents        int                            `json:"healthy_agents"`
	UnhealthyAgents      int                            `json:"unhealthy_agents"`
	AlertsProcessed      int64                          `json:"alerts_processed"`
	AlertsSuccessful     int64                          `json:"alerts_successful"`
	AlertsFailed         int64                          `json:"alerts_failed"`
	AverageProcessingTime time.Duration                 `json:"average_processing_time"`
	AgentPerformance     map[string]*AgentPerformance   `json:"agent_performance"`
	AlertTypeDistribution map[string]int64              `json:"alert_type_distribution"`
}

// AgentPerformance represents performance metrics for individual agents
type AgentPerformance struct {
	AlertsHandled        int64         `json:"alerts_handled"`
	SuccessRate          float64       `json:"success_rate"`
	AverageResponseTime  time.Duration `json:"average_response_time"`
	LastActivity         time.Time     `json:"last_activity"`
	ErrorCount           int64         `json:"error_count"`
	TotalProcessingTime  time.Duration `json:"total_processing_time"`
}

// PipelineMetrics represents pipeline-related metrics
type PipelineMetrics struct {
	TotalJobs            int64         `json:"total_jobs"`
	CompletedJobs        int64         `json:"completed_jobs"`
	FailedJobs           int64         `json:"failed_jobs"`
	QueueLength          int           `json:"queue_length"`
	AverageWaitTime      time.Duration `json:"average_wait_time"`
	AverageProcessingTime time.Duration `json:"average_processing_time"`
	ThroughputPerMinute  float64       `json:"throughput_per_minute"`
	WorkerUtilization    float64       `json:"worker_utilization"`
}

// MCPMetrics represents MCP-related metrics
type MCPMetrics struct {
	TotalServers         int                           `json:"total_servers"`
	ActiveServers        int                           `json:"active_servers"`
	ToolExecutions       int64                         `json:"tool_executions"`
	SuccessfulExecutions int64                         `json:"successful_executions"`
	FailedExecutions     int64                         `json:"failed_executions"`
	AverageExecutionTime time.Duration                 `json:"average_execution_time"`
	ServerHealth         map[string]*MCPServerHealth   `json:"server_health"`
	ToolUsageStats       map[string]*ToolUsageStats    `json:"tool_usage_stats"`
}

// MCPServerHealth represents health metrics for MCP servers
type MCPServerHealth struct {
	Status           string        `json:"status"`
	LastPing         time.Time     `json:"last_ping"`
	ResponseTime     time.Duration `json:"response_time"`
	ToolsAvailable   int           `json:"tools_available"`
	ExecutionCount   int64         `json:"execution_count"`
	ErrorRate        float64       `json:"error_rate"`
}

// ToolUsageStats represents usage statistics for MCP tools
type ToolUsageStats struct {
	ExecutionCount       int64         `json:"execution_count"`
	SuccessCount         int64         `json:"success_count"`
	ErrorCount           int64         `json:"error_count"`
	AverageExecutionTime time.Duration `json:"average_execution_time"`
	LastUsed             time.Time     `json:"last_used"`
}

// PerformanceMetrics represents performance-related metrics
type PerformanceMetrics struct {
	RequestsPerSecond    float64                        `json:"requests_per_second"`
	ResponseTimeP50      time.Duration                  `json:"response_time_p50"`
	ResponseTimeP95      time.Duration                  `json:"response_time_p95"`
	ResponseTimeP99      time.Duration                  `json:"response_time_p99"`
	ErrorRate            float64                        `json:"error_rate"`
	ComponentLatencies   map[string]time.Duration       `json:"component_latencies"`
	EndpointMetrics      map[string]*EndpointMetrics    `json:"endpoint_metrics"`
}

// EndpointMetrics represents metrics for specific endpoints
type EndpointMetrics struct {
	RequestCount      int64         `json:"request_count"`
	SuccessCount      int64         `json:"success_count"`
	ErrorCount        int64         `json:"error_count"`
	AverageLatency    time.Duration `json:"average_latency"`
	LastRequest       time.Time     `json:"last_request"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	now := time.Now()
	return &MetricsCollector{
		started: now,
		metrics: &SystemMetrics{
			StartTime:   now,
			GoVersion:   runtime.Version(),
			NumCPU:      runtime.NumCPU(),
			Memory:      &MemoryMetrics{},
			Agents:      &AgentMetrics{
				AgentPerformance:      make(map[string]*AgentPerformance),
				AlertTypeDistribution: make(map[string]int64),
			},
			Pipeline: &PipelineMetrics{},
			MCP: &MCPMetrics{
				ServerHealth:   make(map[string]*MCPServerHealth),
				ToolUsageStats: make(map[string]*ToolUsageStats),
			},
			Performance: &PerformanceMetrics{
				ComponentLatencies: make(map[string]time.Duration),
				EndpointMetrics:    make(map[string]*EndpointMetrics),
			},
			LastUpdated: now,
		},
	}
}

// UpdateMetrics updates all system metrics
func (mc *MetricsCollector) UpdateMetrics() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	now := time.Now()
	mc.metrics.Uptime = time.Since(mc.started).String()
	mc.metrics.NumGoroutine = runtime.NumGoroutine()
	mc.metrics.LastUpdated = now

	// Update memory metrics
	mc.updateMemoryMetrics()
}

// updateMemoryMetrics updates memory-related metrics
func (mc *MetricsCollector) updateMemoryMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	mc.metrics.Memory = &MemoryMetrics{
		AllocatedMB:    memStats.Alloc / 1024 / 1024,
		TotalAllocMB:   memStats.TotalAlloc / 1024 / 1024,
		SystemMB:       memStats.Sys / 1024 / 1024,
		NumGC:          memStats.NumGC,
		GCCPUFraction:  memStats.GCCPUFraction,
		HeapAllocMB:    memStats.HeapAlloc / 1024 / 1024,
		HeapSysMB:      memStats.HeapSys / 1024 / 1024,
		HeapIdleMB:     memStats.HeapIdle / 1024 / 1024,
		HeapInuseMB:    memStats.HeapInuse / 1024 / 1024,
		HeapReleasedMB: memStats.HeapReleased / 1024 / 1024,
		StackInuseMB:   memStats.StackInuse / 1024 / 1024,
		StackSysMB:     memStats.StackSys / 1024 / 1024,
	}
}

// GetMetrics returns current system metrics
func (mc *MetricsCollector) GetMetrics() *SystemMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// Create a deep copy to avoid race conditions
	metricsCopy := &SystemMetrics{
		StartTime:    mc.metrics.StartTime,
		Uptime:       mc.metrics.Uptime,
		GoVersion:    mc.metrics.GoVersion,
		NumCPU:       mc.metrics.NumCPU,
		NumGoroutine: mc.metrics.NumGoroutine,
		Memory:       mc.copyMemoryMetrics(mc.metrics.Memory),
		Agents:       mc.copyAgentMetrics(mc.metrics.Agents),
		Pipeline:     mc.copyPipelineMetrics(mc.metrics.Pipeline),
		MCP:          mc.copyMCPMetrics(mc.metrics.MCP),
		Performance:  mc.copyPerformanceMetrics(mc.metrics.Performance),
		LastUpdated:  mc.metrics.LastUpdated,
	}

	return metricsCopy
}

// Helper methods for deep copying metrics

func (mc *MetricsCollector) copyMemoryMetrics(mem *MemoryMetrics) *MemoryMetrics {
	return &MemoryMetrics{
		AllocatedMB:    mem.AllocatedMB,
		TotalAllocMB:   mem.TotalAllocMB,
		SystemMB:       mem.SystemMB,
		NumGC:          mem.NumGC,
		GCCPUFraction:  mem.GCCPUFraction,
		HeapAllocMB:    mem.HeapAllocMB,
		HeapSysMB:      mem.HeapSysMB,
		HeapIdleMB:     mem.HeapIdleMB,
		HeapInuseMB:    mem.HeapInuseMB,
		HeapReleasedMB: mem.HeapReleasedMB,
		StackInuseMB:   mem.StackInuseMB,
		StackSysMB:     mem.StackSysMB,
	}
}

func (mc *MetricsCollector) copyAgentMetrics(agents *AgentMetrics) *AgentMetrics {
	agentPerf := make(map[string]*AgentPerformance)
	for k, v := range agents.AgentPerformance {
		agentPerf[k] = &AgentPerformance{
			AlertsHandled:       v.AlertsHandled,
			SuccessRate:         v.SuccessRate,
			AverageResponseTime: v.AverageResponseTime,
			LastActivity:        v.LastActivity,
			ErrorCount:          v.ErrorCount,
			TotalProcessingTime: v.TotalProcessingTime,
		}
	}

	alertDist := make(map[string]int64)
	for k, v := range agents.AlertTypeDistribution {
		alertDist[k] = v
	}

	return &AgentMetrics{
		TotalAgents:           agents.TotalAgents,
		HealthyAgents:         agents.HealthyAgents,
		UnhealthyAgents:       agents.UnhealthyAgents,
		AlertsProcessed:       agents.AlertsProcessed,
		AlertsSuccessful:      agents.AlertsSuccessful,
		AlertsFailed:          agents.AlertsFailed,
		AverageProcessingTime: agents.AverageProcessingTime,
		AgentPerformance:      agentPerf,
		AlertTypeDistribution: alertDist,
	}
}

func (mc *MetricsCollector) copyPipelineMetrics(pipeline *PipelineMetrics) *PipelineMetrics {
	return &PipelineMetrics{
		TotalJobs:             pipeline.TotalJobs,
		CompletedJobs:         pipeline.CompletedJobs,
		FailedJobs:            pipeline.FailedJobs,
		QueueLength:           pipeline.QueueLength,
		AverageWaitTime:       pipeline.AverageWaitTime,
		AverageProcessingTime: pipeline.AverageProcessingTime,
		ThroughputPerMinute:   pipeline.ThroughputPerMinute,
		WorkerUtilization:     pipeline.WorkerUtilization,
	}
}

func (mc *MetricsCollector) copyMCPMetrics(mcp *MCPMetrics) *MCPMetrics {
	serverHealth := make(map[string]*MCPServerHealth)
	for k, v := range mcp.ServerHealth {
		serverHealth[k] = &MCPServerHealth{
			Status:         v.Status,
			LastPing:       v.LastPing,
			ResponseTime:   v.ResponseTime,
			ToolsAvailable: v.ToolsAvailable,
			ExecutionCount: v.ExecutionCount,
			ErrorRate:      v.ErrorRate,
		}
	}

	toolStats := make(map[string]*ToolUsageStats)
	for k, v := range mcp.ToolUsageStats {
		toolStats[k] = &ToolUsageStats{
			ExecutionCount:       v.ExecutionCount,
			SuccessCount:         v.SuccessCount,
			ErrorCount:           v.ErrorCount,
			AverageExecutionTime: v.AverageExecutionTime,
			LastUsed:             v.LastUsed,
		}
	}

	return &MCPMetrics{
		TotalServers:         mcp.TotalServers,
		ActiveServers:        mcp.ActiveServers,
		ToolExecutions:       mcp.ToolExecutions,
		SuccessfulExecutions: mcp.SuccessfulExecutions,
		FailedExecutions:     mcp.FailedExecutions,
		AverageExecutionTime: mcp.AverageExecutionTime,
		ServerHealth:         serverHealth,
		ToolUsageStats:       toolStats,
	}
}

func (mc *MetricsCollector) copyPerformanceMetrics(perf *PerformanceMetrics) *PerformanceMetrics {
	compLatencies := make(map[string]time.Duration)
	for k, v := range perf.ComponentLatencies {
		compLatencies[k] = v
	}

	endpointMetrics := make(map[string]*EndpointMetrics)
	for k, v := range perf.EndpointMetrics {
		endpointMetrics[k] = &EndpointMetrics{
			RequestCount:   v.RequestCount,
			SuccessCount:   v.SuccessCount,
			ErrorCount:     v.ErrorCount,
			AverageLatency: v.AverageLatency,
			LastRequest:    v.LastRequest,
		}
	}

	return &PerformanceMetrics{
		RequestsPerSecond:  perf.RequestsPerSecond,
		ResponseTimeP50:    perf.ResponseTimeP50,
		ResponseTimeP95:    perf.ResponseTimeP95,
		ResponseTimeP99:    perf.ResponseTimeP99,
		ErrorRate:          perf.ErrorRate,
		ComponentLatencies: compLatencies,
		EndpointMetrics:    endpointMetrics,
	}
}

// UpdateAgentMetrics updates agent-specific metrics
func (mc *MetricsCollector) UpdateAgentMetrics(agentType string, alertsHandled, successCount int64, responseTime time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.metrics.Agents.AgentPerformance == nil {
		mc.metrics.Agents.AgentPerformance = make(map[string]*AgentPerformance)
	}

	perf, exists := mc.metrics.Agents.AgentPerformance[agentType]
	if !exists {
		perf = &AgentPerformance{}
		mc.metrics.Agents.AgentPerformance[agentType] = perf
	}

	perf.AlertsHandled += alertsHandled
	perf.LastActivity = time.Now()
	perf.TotalProcessingTime += responseTime

	if alertsHandled > 0 {
		perf.SuccessRate = float64(successCount) / float64(alertsHandled)
		perf.AverageResponseTime = perf.TotalProcessingTime / time.Duration(perf.AlertsHandled)
	}

	errorCount := alertsHandled - successCount
	if errorCount > 0 {
		perf.ErrorCount += errorCount
	}
}

// UpdatePipelineMetrics updates pipeline-specific metrics
func (mc *MetricsCollector) UpdatePipelineMetrics(totalJobs, completedJobs, failedJobs int64, queueLength int, avgWaitTime, avgProcessingTime time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.metrics.Pipeline.TotalJobs = totalJobs
	mc.metrics.Pipeline.CompletedJobs = completedJobs
	mc.metrics.Pipeline.FailedJobs = failedJobs
	mc.metrics.Pipeline.QueueLength = queueLength
	mc.metrics.Pipeline.AverageWaitTime = avgWaitTime
	mc.metrics.Pipeline.AverageProcessingTime = avgProcessingTime

	// Calculate throughput (jobs per minute)
	if totalJobs > 0 {
		elapsedMinutes := time.Since(mc.started).Minutes()
		if elapsedMinutes > 0 {
			mc.metrics.Pipeline.ThroughputPerMinute = float64(totalJobs) / elapsedMinutes
		}
	}
}

// UpdateMCPMetrics updates MCP-specific metrics
func (mc *MetricsCollector) UpdateMCPMetrics(serverName string, toolExecutions, successfulExecutions, failedExecutions int64, avgExecutionTime time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.metrics.MCP.ToolExecutions += toolExecutions
	mc.metrics.MCP.SuccessfulExecutions += successfulExecutions
	mc.metrics.MCP.FailedExecutions += failedExecutions

	if mc.metrics.MCP.ServerHealth == nil {
		mc.metrics.MCP.ServerHealth = make(map[string]*MCPServerHealth)
	}

	health, exists := mc.metrics.MCP.ServerHealth[serverName]
	if !exists {
		health = &MCPServerHealth{}
		mc.metrics.MCP.ServerHealth[serverName] = health
	}

	health.ExecutionCount += toolExecutions
	if toolExecutions > 0 {
		health.ErrorRate = float64(failedExecutions) / float64(toolExecutions)
	}
	health.LastPing = time.Now()
}

// RecordEndpointMetrics records metrics for API endpoints
func (mc *MetricsCollector) RecordEndpointMetrics(endpoint string, success bool, latency time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.metrics.Performance.EndpointMetrics == nil {
		mc.metrics.Performance.EndpointMetrics = make(map[string]*EndpointMetrics)
	}

	metrics, exists := mc.metrics.Performance.EndpointMetrics[endpoint]
	if !exists {
		metrics = &EndpointMetrics{}
		mc.metrics.Performance.EndpointMetrics[endpoint] = metrics
	}

	metrics.RequestCount++
	metrics.LastRequest = time.Now()

	if success {
		metrics.SuccessCount++
	} else {
		metrics.ErrorCount++
	}

	// Update average latency (simple moving average)
	if metrics.RequestCount == 1 {
		metrics.AverageLatency = latency
	} else {
		// Weighted average
		weight := 0.1
		metrics.AverageLatency = time.Duration(
			float64(metrics.AverageLatency)*(1-weight) + float64(latency)*weight,
		)
	}
}