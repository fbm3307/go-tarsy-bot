package monitoring

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsCollector(t *testing.T) {
	t.Run("NewMetricsCollector", func(t *testing.T) {
		mc := NewMetricsCollector()

		assert.NotNil(t, mc)
		assert.NotNil(t, mc.metrics)
		assert.NotZero(t, mc.started)

		// Check initial metrics structure
		assert.NotNil(t, mc.metrics.Memory)
		assert.NotNil(t, mc.metrics.Agents)
		assert.NotNil(t, mc.metrics.Pipeline)
		assert.NotNil(t, mc.metrics.MCP)
		assert.NotNil(t, mc.metrics.Performance)

		// Check initial values
		assert.NotEmpty(t, mc.metrics.GoVersion)
		assert.Greater(t, mc.metrics.NumCPU, 0)
		assert.NotNil(t, mc.metrics.Agents.AgentPerformance)
		assert.NotNil(t, mc.metrics.Agents.AlertTypeDistribution)
		assert.NotNil(t, mc.metrics.MCP.ServerHealth)
		assert.NotNil(t, mc.metrics.MCP.ToolUsageStats)
		assert.NotNil(t, mc.metrics.Performance.ComponentLatencies)
		assert.NotNil(t, mc.metrics.Performance.EndpointMetrics)
	})

	t.Run("UpdateMetrics", func(t *testing.T) {
		mc := NewMetricsCollector()

		initialUpdate := mc.metrics.LastUpdated

		// Wait a small amount and update
		time.Sleep(10 * time.Millisecond)
		mc.UpdateMetrics()

		// Check that metrics were updated
		assert.Greater(t, mc.metrics.LastUpdated, initialUpdate)
		assert.NotEmpty(t, mc.metrics.Uptime)
		assert.Greater(t, mc.metrics.NumGoroutine, 0)

		// Check memory metrics
		assert.Greater(t, mc.metrics.Memory.AllocatedMB, uint64(0))
		assert.Greater(t, mc.metrics.Memory.SystemMB, uint64(0))
		assert.GreaterOrEqual(t, mc.metrics.Memory.NumGC, uint32(0))
	})

	t.Run("GetMetrics", func(t *testing.T) {
		mc := NewMetricsCollector()
		mc.UpdateMetrics()

		metrics := mc.GetMetrics()

		assert.NotNil(t, metrics)
		assert.NotSame(t, mc.metrics, metrics) // Should be a copy

		// Check that all fields are copied
		assert.Equal(t, mc.metrics.StartTime, metrics.StartTime)
		assert.Equal(t, mc.metrics.GoVersion, metrics.GoVersion)
		assert.Equal(t, mc.metrics.NumCPU, metrics.NumCPU)
		assert.Equal(t, mc.metrics.NumGoroutine, metrics.NumGoroutine)

		// Check nested structures are copied
		assert.NotSame(t, mc.metrics.Memory, metrics.Memory)
		assert.NotSame(t, mc.metrics.Agents, metrics.Agents)
		assert.NotSame(t, mc.metrics.Pipeline, metrics.Pipeline)
		assert.NotSame(t, mc.metrics.MCP, metrics.MCP)
		assert.NotSame(t, mc.metrics.Performance, metrics.Performance)
	})

	t.Run("MemoryMetricsCopy", func(t *testing.T) {
		mc := NewMetricsCollector()
		mc.UpdateMetrics()

		original := mc.metrics.Memory
		copied := mc.copyMemoryMetrics(original)

		assert.NotSame(t, original, copied)
		assert.Equal(t, original.AllocatedMB, copied.AllocatedMB)
		assert.Equal(t, original.TotalAllocMB, copied.TotalAllocMB)
		assert.Equal(t, original.SystemMB, copied.SystemMB)
		assert.Equal(t, original.NumGC, copied.NumGC)
		assert.Equal(t, original.GCCPUFraction, copied.GCCPUFraction)
	})
}

func TestAgentMetricsOperations(t *testing.T) {
	mc := NewMetricsCollector()

	t.Run("UpdateAgentMetrics", func(t *testing.T) {
		agentType := "test-agent"
		alertsHandled := int64(10)
		successCount := int64(8)
		responseTime := 100 * time.Millisecond

		mc.UpdateAgentMetrics(agentType, alertsHandled, successCount, responseTime)

		metrics := mc.GetMetrics()
		agentPerf := metrics.Agents.AgentPerformance[agentType]

		require.NotNil(t, agentPerf)
		assert.Equal(t, alertsHandled, agentPerf.AlertsHandled)
		assert.Equal(t, float64(successCount)/float64(alertsHandled), agentPerf.SuccessRate)
		assert.Equal(t, responseTime, agentPerf.AverageResponseTime)
		assert.Equal(t, int64(2), agentPerf.ErrorCount) // alertsHandled - successCount
		assert.NotZero(t, agentPerf.LastActivity)
	})

	t.Run("UpdateAgentMetricsMultipleTimes", func(t *testing.T) {
		agentType := "multi-update-agent"

		// First update
		mc.UpdateAgentMetrics(agentType, 5, 4, 50*time.Millisecond)

		// Second update
		mc.UpdateAgentMetrics(agentType, 3, 3, 75*time.Millisecond)

		metrics := mc.GetMetrics()
		agentPerf := metrics.Agents.AgentPerformance[agentType]

		require.NotNil(t, agentPerf)
		assert.Equal(t, int64(8), agentPerf.AlertsHandled) // 5 + 3
		assert.Equal(t, int64(1), agentPerf.ErrorCount)   // (5-4) + (3-3)
		assert.Equal(t, 125*time.Millisecond, agentPerf.TotalProcessingTime) // 50 + 75
	})

	t.Run("AgentMetricsCopy", func(t *testing.T) {
		// Setup test data
		mc.UpdateAgentMetrics("agent1", 10, 8, 100*time.Millisecond)
		mc.UpdateAgentMetrics("agent2", 5, 5, 50*time.Millisecond)

		original := mc.metrics.Agents
		copied := mc.copyAgentMetrics(original)

		assert.NotSame(t, original, copied)
		assert.NotSame(t, original.AgentPerformance, copied.AgentPerformance)
		assert.NotSame(t, original.AlertTypeDistribution, copied.AlertTypeDistribution)

		// Check deep copy of agent performance
		assert.Len(t, copied.AgentPerformance, 2)
		assert.Contains(t, copied.AgentPerformance, "agent1")
		assert.Contains(t, copied.AgentPerformance, "agent2")

		// Verify nested structures are copied
		for agentName, perf := range copied.AgentPerformance {
			originalPerf := original.AgentPerformance[agentName]
			assert.NotSame(t, originalPerf, perf)
			assert.Equal(t, originalPerf.AlertsHandled, perf.AlertsHandled)
			assert.Equal(t, originalPerf.SuccessRate, perf.SuccessRate)
		}
	})
}

func TestPipelineMetricsOperations(t *testing.T) {
	mc := NewMetricsCollector()

	t.Run("UpdatePipelineMetrics", func(t *testing.T) {
		totalJobs := int64(100)
		completedJobs := int64(85)
		failedJobs := int64(10)
		queueLength := 5
		avgWaitTime := 200 * time.Millisecond
		avgProcessingTime := 1500 * time.Millisecond

		mc.UpdatePipelineMetrics(totalJobs, completedJobs, failedJobs, queueLength, avgWaitTime, avgProcessingTime)

		metrics := mc.GetMetrics()
		pipeline := metrics.Pipeline

		assert.Equal(t, totalJobs, pipeline.TotalJobs)
		assert.Equal(t, completedJobs, pipeline.CompletedJobs)
		assert.Equal(t, failedJobs, pipeline.FailedJobs)
		assert.Equal(t, queueLength, pipeline.QueueLength)
		assert.Equal(t, avgWaitTime, pipeline.AverageWaitTime)
		assert.Equal(t, avgProcessingTime, pipeline.AverageProcessingTime)
		assert.Greater(t, pipeline.ThroughputPerMinute, 0.0)
	})

	t.Run("PipelineMetricsCopy", func(t *testing.T) {
		mc.UpdatePipelineMetrics(50, 45, 3, 2, 100*time.Millisecond, 800*time.Millisecond)

		original := mc.metrics.Pipeline
		copied := mc.copyPipelineMetrics(original)

		assert.NotSame(t, original, copied)
		assert.Equal(t, original.TotalJobs, copied.TotalJobs)
		assert.Equal(t, original.CompletedJobs, copied.CompletedJobs)
		assert.Equal(t, original.FailedJobs, copied.FailedJobs)
		assert.Equal(t, original.QueueLength, copied.QueueLength)
		assert.Equal(t, original.AverageWaitTime, copied.AverageWaitTime)
		assert.Equal(t, original.AverageProcessingTime, copied.AverageProcessingTime)
		assert.Equal(t, original.ThroughputPerMinute, copied.ThroughputPerMinute)
		assert.Equal(t, original.WorkerUtilization, copied.WorkerUtilization)
	})
}

func TestMCPMetricsOperations(t *testing.T) {
	mc := NewMetricsCollector()

	t.Run("UpdateMCPMetrics", func(t *testing.T) {
		serverName := "test-server"
		toolExecutions := int64(25)
		successfulExecutions := int64(23)
		failedExecutions := int64(2)
		avgExecutionTime := 300 * time.Millisecond

		mc.UpdateMCPMetrics(serverName, toolExecutions, successfulExecutions, failedExecutions, avgExecutionTime)

		metrics := mc.GetMetrics()
		mcp := metrics.MCP

		assert.Equal(t, toolExecutions, mcp.ToolExecutions)
		assert.Equal(t, successfulExecutions, mcp.SuccessfulExecutions)
		assert.Equal(t, failedExecutions, mcp.FailedExecutions)

		serverHealth := mcp.ServerHealth[serverName]
		require.NotNil(t, serverHealth)
		assert.Equal(t, toolExecutions, serverHealth.ExecutionCount)
		assert.Equal(t, float64(failedExecutions)/float64(toolExecutions), serverHealth.ErrorRate)
		assert.NotZero(t, serverHealth.LastPing)
	})

	t.Run("MCPMetricsCopy", func(t *testing.T) {
		mc.UpdateMCPMetrics("server1", 10, 9, 1, 100*time.Millisecond)
		mc.UpdateMCPMetrics("server2", 5, 5, 0, 50*time.Millisecond)

		original := mc.metrics.MCP
		copied := mc.copyMCPMetrics(original)

		assert.NotSame(t, original, copied)
		assert.NotSame(t, original.ServerHealth, copied.ServerHealth)
		assert.NotSame(t, original.ToolUsageStats, copied.ToolUsageStats)

		// Check deep copy of server health
		assert.Len(t, copied.ServerHealth, 2)
		for serverName, health := range copied.ServerHealth {
			originalHealth := original.ServerHealth[serverName]
			assert.NotSame(t, originalHealth, health)
			assert.Equal(t, originalHealth.ExecutionCount, health.ExecutionCount)
			assert.Equal(t, originalHealth.ErrorRate, health.ErrorRate)
		}
	})
}

func TestEndpointMetricsOperations(t *testing.T) {
	mc := NewMetricsCollector()

	t.Run("RecordEndpointMetrics", func(t *testing.T) {
		endpoint := "/api/test"
		latency := 150 * time.Millisecond

		// Record successful requests
		mc.RecordEndpointMetrics(endpoint, true, latency)
		mc.RecordEndpointMetrics(endpoint, true, 100*time.Millisecond)

		// Record failed request
		mc.RecordEndpointMetrics(endpoint, false, 200*time.Millisecond)

		metrics := mc.GetMetrics()
		endpointMetrics := metrics.Performance.EndpointMetrics[endpoint]

		require.NotNil(t, endpointMetrics)
		assert.Equal(t, int64(3), endpointMetrics.RequestCount)
		assert.Equal(t, int64(2), endpointMetrics.SuccessCount)
		assert.Equal(t, int64(1), endpointMetrics.ErrorCount)
		assert.Greater(t, endpointMetrics.AverageLatency, time.Duration(0))
		assert.NotZero(t, endpointMetrics.LastRequest)
	})

	t.Run("AverageLatencyCalculation", func(t *testing.T) {
		endpoint := "/api/latency-test"

		// First request
		mc.RecordEndpointMetrics(endpoint, true, 100*time.Millisecond)
		metrics := mc.GetMetrics()
		assert.Equal(t, 100*time.Millisecond, metrics.Performance.EndpointMetrics[endpoint].AverageLatency)

		// Second request - should use weighted average
		mc.RecordEndpointMetrics(endpoint, true, 200*time.Millisecond)
		metrics = mc.GetMetrics()
		avgLatency := metrics.Performance.EndpointMetrics[endpoint].AverageLatency

		// Should be between 100ms and 200ms (closer to 100ms due to weighted average)
		assert.Greater(t, avgLatency, 100*time.Millisecond)
		assert.Less(t, avgLatency, 200*time.Millisecond)
	})

	t.Run("PerformanceMetricsCopy", func(t *testing.T) {
		mc.RecordEndpointMetrics("/endpoint1", true, 100*time.Millisecond)
		mc.RecordEndpointMetrics("/endpoint2", false, 200*time.Millisecond)

		original := mc.metrics.Performance
		copied := mc.copyPerformanceMetrics(original)

		assert.NotSame(t, original, copied)
		assert.NotSame(t, original.ComponentLatencies, copied.ComponentLatencies)
		assert.NotSame(t, original.EndpointMetrics, copied.EndpointMetrics)

		// Check deep copy of endpoint metrics
		assert.Len(t, copied.EndpointMetrics, 2)
		for endpoint, metrics := range copied.EndpointMetrics {
			originalMetrics := original.EndpointMetrics[endpoint]
			assert.NotSame(t, originalMetrics, metrics)
			assert.Equal(t, originalMetrics.RequestCount, metrics.RequestCount)
			assert.Equal(t, originalMetrics.SuccessCount, metrics.SuccessCount)
			assert.Equal(t, originalMetrics.ErrorCount, metrics.ErrorCount)
		}
	})
}

func TestConcurrentAccess(t *testing.T) {
	mc := NewMetricsCollector()

	t.Run("ConcurrentUpdates", func(t *testing.T) {
		const numGoroutines = 10
		const numUpdates = 100

		done := make(chan bool, numGoroutines)

		// Start multiple goroutines updating metrics
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()

				for j := 0; j < numUpdates; j++ {
					mc.UpdateMetrics()
					mc.UpdateAgentMetrics("concurrent-agent", 1, 1, time.Millisecond)
					mc.RecordEndpointMetrics("/concurrent", true, time.Millisecond)
				}
			}(i)
		}

		// Start goroutines reading metrics
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer func() { done <- true }()

				for j := 0; j < numUpdates; j++ {
					_ = mc.GetMetrics()
				}
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines*2; i++ {
			<-done
		}

		// Verify final state
		metrics := mc.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Greater(t, metrics.Agents.AgentPerformance["concurrent-agent"].AlertsHandled, int64(0))
		assert.Greater(t, metrics.Performance.EndpointMetrics["/concurrent"].RequestCount, int64(0))
	})
}