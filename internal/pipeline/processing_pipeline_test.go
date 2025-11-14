package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// TestProcessingPipelineE2E tests the complete end-to-end processing pipeline
func TestProcessingPipelineE2E(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	// Create test environment
	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)
	mockConfigLoader := &config.AgentConfigLoader{}
	agentRegistry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	// Register test agents
	settings := agents.DefaultAgentSettings()
	testAgent := agents.NewBaseAgent("test", []string{"testing", "e2e"}, settings)
	err := agentRegistry.RegisterHardcodedAgent("test", testAgent, []string{"test-alert", "e2e-alert"})
	require.NoError(t, err)

	// Create pipeline factory function for fresh instances
	createPipeline := func() *ProcessingPipeline {
		pipelineConfig := &PipelineConfig{
			MaxConcurrentJobs:   2,
			JobTimeout:          30 * time.Second,
			QueueSize:           10,
			RetryAttempts:       2,
			RetryDelay:          100 * time.Millisecond, // Short delay for testing
			HealthCheckInterval: 1 * time.Second,
		}
		return NewProcessingPipeline(agentRegistry, mcpRegistry, logger, pipelineConfig)
	}

	t.Run("Pipeline Lifecycle", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		pipeline := createPipeline()

		// Start pipeline
		err := pipeline.Start(ctx)
		require.NoError(t, err)

		// Verify initial state
		status := pipeline.GetPipelineStatus()
		assert.Equal(t, "healthy", status.Status)
		assert.Equal(t, 0, status.QueueStatus.Length)
		assert.Equal(t, 10, status.QueueStatus.Capacity)

		// Stop pipeline
		err = pipeline.Stop()
		require.NoError(t, err)
	})

	t.Run("Single Alert Processing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		pipeline := createPipeline()

		// Start pipeline
		err := pipeline.Start(ctx)
		require.NoError(t, err)
		defer func() {
			if stopErr := pipeline.Stop(); stopErr != nil {
				t.Logf("Pipeline stop error: %v", stopErr)
			}
		}()

		// Create test alert
		alert := &models.Alert{
			AlertType: "test-alert",
			Data: map[string]interface{}{
				"severity": "high",
				"message":  "Test alert for E2E processing",
				"source":   "integration-test",
			},
		}

		// Submit alert for processing
		job, err := pipeline.ProcessAlert(ctx, alert, PriorityHigh)
		require.NoError(t, err)
		assert.NotNil(t, job)
		assert.Equal(t, StatusQueued, job.Status)
		assert.Equal(t, PriorityHigh, job.Priority)

		// Give the pipeline time to process the job
		// Check metrics periodically
		var metrics *PipelineMetrics
		maxWait := 10 * time.Second
		checkInterval := 500 * time.Millisecond

		for waited := time.Duration(0); waited < maxWait; waited += checkInterval {
			time.Sleep(checkInterval)
			metrics = pipeline.GetMetrics()
			if metrics.TotalJobsProcessed > 0 {
				break
			}
		}

		// Verify metrics were updated
		assert.Greater(t, metrics.TotalJobsProcessed, int64(0), "Expected at least one job to be processed")
	})

	t.Run("Multiple Alert Processing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		pipeline := createPipeline()

		// Start pipeline
		err := pipeline.Start(ctx)
		require.NoError(t, err)
		defer pipeline.Stop()

		// Submit multiple alerts
		alerts := []*models.Alert{
			{
				AlertType: "test-alert",
				Data:      map[string]interface{}{"id": 1, "type": "cpu"},
			},
			{
				AlertType: "e2e-alert",
				Data:      map[string]interface{}{"id": 2, "type": "memory"},
			},
			{
				AlertType: "test-alert",
				Data:      map[string]interface{}{"id": 3, "type": "disk"},
			},
		}

		priorities := []JobPriority{PriorityHigh, PriorityMedium, PriorityLow}

		submittedJobs := make([]*ProcessingJob, len(alerts))
		for i, alert := range alerts {
			job, err := pipeline.ProcessAlert(ctx, alert, priorities[i])
			require.NoError(t, err)
			submittedJobs[i] = job
		}

		// Wait for all jobs to be processed
		time.Sleep(5 * time.Second)

		// Verify metrics
		metrics := pipeline.GetMetrics()
		assert.Equal(t, int64(len(alerts)), metrics.TotalJobsProcessed)
		assert.Greater(t, metrics.AverageProcessingTime, time.Duration(0))
	})

	t.Run("Pipeline Status and Health", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		pipeline := createPipeline()

		// Start pipeline
		err := pipeline.Start(ctx)
		require.NoError(t, err)
		defer pipeline.Stop()

		// Get initial status
		status := pipeline.GetPipelineStatus()
		assert.Equal(t, "healthy", status.Status)
		assert.NotNil(t, status.Metrics)
		assert.NotNil(t, status.AgentHealth)
		assert.Contains(t, status.AgentHealth, "test")

		// Verify queue status
		assert.Equal(t, 0, status.QueueStatus.Length)
		assert.Equal(t, 10, status.QueueStatus.Capacity)
		assert.Equal(t, 0.0, status.QueueStatus.Usage)

		// Submit some alerts to test queue monitoring
		for i := 0; i < 3; i++ {
			alert := &models.Alert{
				AlertType: "test-alert",
				Data:      map[string]interface{}{"batch_id": i},
			}
			_, err := pipeline.ProcessAlert(ctx, alert, PriorityMedium)
			require.NoError(t, err)
		}

		// Wait a bit and check status again
		time.Sleep(1 * time.Second)
		status = pipeline.GetPipelineStatus()

		// Metrics should show processing activity
		assert.Greater(t, status.Metrics.TotalJobsProcessed, int64(0))
	})

	t.Run("Configuration and Limits", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Test with smaller queue to verify limits
		smallPipelineConfig := &PipelineConfig{
			MaxConcurrentJobs:   1,
			JobTimeout:          5 * time.Second,
			QueueSize:           2, // Very small queue
			RetryAttempts:       1,
			RetryDelay:          50 * time.Millisecond,
			HealthCheckInterval: 1 * time.Second,
		}

		smallPipeline := NewProcessingPipeline(agentRegistry, mcpRegistry, logger, smallPipelineConfig)

		err := smallPipeline.Start(ctx)
		require.NoError(t, err)
		defer smallPipeline.Stop()

		// Fill the queue
		for i := 0; i < 2; i++ {
			alert := &models.Alert{
				AlertType: "test-alert",
				Data:      map[string]interface{}{"fill_id": i},
			}
			_, err := smallPipeline.ProcessAlert(ctx, alert, PriorityLow)
			require.NoError(t, err)
		}

		// Try to submit one more - should fail due to full queue
		alert := &models.Alert{
			AlertType: "test-alert",
			Data:      map[string]interface{}{"overflow": true},
		}
		_, err = smallPipeline.ProcessAlert(ctx, alert, PriorityLow)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "queue is full")
	})
}

// TestPipelineMetrics tests the metrics collection functionality
func TestPipelineMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	// Create minimal test environment
	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)
	mockConfigLoader := &config.AgentConfigLoader{}
	agentRegistry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	// Register minimal test agent
	settings := agents.DefaultAgentSettings()
	testAgent := agents.NewBaseAgent("metrics-test", []string{"metrics"}, settings)
	err := agentRegistry.RegisterHardcodedAgent("metrics-test", testAgent, []string{"metrics-alert"})
	require.NoError(t, err)

	pipeline := NewProcessingPipeline(agentRegistry, mcpRegistry, logger, DefaultPipelineConfig())

	t.Run("Initial Metrics", func(t *testing.T) {
		metrics := pipeline.GetMetrics()
		assert.Equal(t, int64(0), metrics.TotalJobsProcessed)
		assert.Equal(t, int64(0), metrics.SuccessfulJobs)
		assert.Equal(t, int64(0), metrics.FailedJobs)
		assert.Equal(t, time.Duration(0), metrics.AverageProcessingTime)
		assert.Equal(t, 0, metrics.QueueLength)
		assert.Equal(t, 10, metrics.ActiveWorkers) // Default config has 10 workers
	})

	t.Run("Metrics Updates During Processing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		err := pipeline.Start(ctx)
		require.NoError(t, err)
		defer pipeline.Stop()

		// Process several alerts
		for i := 0; i < 3; i++ {
			alert := &models.Alert{
				AlertType: "metrics-alert",
				Data:      map[string]interface{}{"test_id": i},
			}
			_, err := pipeline.ProcessAlert(ctx, alert, PriorityMedium)
			require.NoError(t, err)
		}

		// Wait for processing
		time.Sleep(3 * time.Second)

		// Check updated metrics
		metrics := pipeline.GetMetrics()
		assert.Equal(t, int64(3), metrics.TotalJobsProcessed)
		assert.Equal(t, int64(3), metrics.SuccessfulJobs)
		assert.Equal(t, int64(0), metrics.FailedJobs)
		assert.Greater(t, metrics.AverageProcessingTime, time.Duration(0))
	})
}

// TestJobPriorities tests different job priority handling
func TestJobPriorities(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	// Create test environment
	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)
	mockConfigLoader := &config.AgentConfigLoader{}
	agentRegistry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	settings := agents.DefaultAgentSettings()
	testAgent := agents.NewBaseAgent("priority-test", []string{"priority"}, settings)
	err := agentRegistry.RegisterHardcodedAgent("priority-test", testAgent, []string{"priority-alert"})
	require.NoError(t, err)

	pipeline := NewProcessingPipeline(agentRegistry, mcpRegistry, logger, DefaultPipelineConfig())

	t.Run("Different Priority Levels", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		err := pipeline.Start(ctx)
		require.NoError(t, err)
		defer pipeline.Stop()

		priorities := []JobPriority{PriorityLow, PriorityMedium, PriorityHigh, PriorityCritical}

		for i, priority := range priorities {
			alert := &models.Alert{
				AlertType: "priority-alert",
				Data:      map[string]interface{}{"priority_test": i, "level": string(priority)},
			}

			job, err := pipeline.ProcessAlert(ctx, alert, priority)
			require.NoError(t, err)
			assert.Equal(t, priority, job.Priority)
			assert.Equal(t, StatusQueued, job.Status)
		}

		// Wait for processing
		time.Sleep(3 * time.Second)

		// Verify all jobs were processed
		metrics := pipeline.GetMetrics()
		assert.Equal(t, int64(4), metrics.TotalJobsProcessed)
	})
}

// TestPipelineRecovery tests error handling and recovery
func TestPipelineRecovery(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	// Create test environment
	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)
	mockConfigLoader := &config.AgentConfigLoader{}
	agentRegistry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	// Register agent for alerts that exist
	settings := agents.DefaultAgentSettings()
	testAgent := agents.NewBaseAgent("recovery-test", []string{"recovery"}, settings)
	err := agentRegistry.RegisterHardcodedAgent("recovery-test", testAgent, []string{"valid-alert"})
	require.NoError(t, err)

	config := &PipelineConfig{
		MaxConcurrentJobs:   2,
		JobTimeout:          5 * time.Second,
		QueueSize:           10,
		RetryAttempts:       2,
		RetryDelay:          100 * time.Millisecond,
		HealthCheckInterval: 1 * time.Second,
	}

	pipeline := NewProcessingPipeline(agentRegistry, mcpRegistry, logger, config)

	t.Run("Invalid Alert Handling", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err := pipeline.Start(ctx)
		require.NoError(t, err)
		defer pipeline.Stop()

		// Submit alert with unregistered type (should fail)
		alert := &models.Alert{
			AlertType: "unknown-alert-type",
			Data:      map[string]interface{}{"test": "failure"},
		}

		job, err := pipeline.ProcessAlert(ctx, alert, PriorityMedium)
		require.NoError(t, err)
		_ = job // Used for job submission verification

		// Wait for processing
		time.Sleep(3 * time.Second)

		// Verify failure was recorded in metrics
		metrics := pipeline.GetMetrics()
		assert.Greater(t, metrics.TotalJobsProcessed, int64(0))
		assert.Greater(t, metrics.FailedJobs, int64(0))
	})

	t.Run("Valid Alert Processing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err := pipeline.Start(ctx)
		require.NoError(t, err)
		defer pipeline.Stop()

		// Submit valid alert
		alert := &models.Alert{
			AlertType: "valid-alert",
			Data:      map[string]interface{}{"test": "success"},
		}

		job, err := pipeline.ProcessAlert(ctx, alert, PriorityMedium)
		require.NoError(t, err)
		_ = job // Used for job submission verification

		// Wait for processing
		time.Sleep(3 * time.Second)

		// Verify success
		metrics := pipeline.GetMetrics()
		assert.Greater(t, metrics.SuccessfulJobs, int64(0))
	})
}