package services

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/monitoring"
	"github.com/codeready/go-tarsy-bot/internal/pipeline"
)

// DashboardUpdateService provides real-time dashboard updates via WebSocket
type DashboardUpdateService struct {
	wsManager        *WebSocketManager
	metricsCollector *monitoring.MetricsCollector
	pipeline         *pipeline.ProcessingPipeline
	logger           *zap.Logger
	ctx              context.Context
	cancel           context.CancelFunc
	config           *DashboardUpdateConfig

	// Internal state
	lastSystemMetrics *models.SystemMetrics
	activeAlerts      sync.Map // map[string]*models.SessionUpdate
	mu                sync.RWMutex
}

// DashboardUpdateConfig contains configuration for dashboard updates
type DashboardUpdateConfig struct {
	UpdateInterval           time.Duration `json:"update_interval"`
	MetricsInterval          time.Duration `json:"metrics_interval"`
	BatchSize               int           `json:"batch_size"`
	EnableSystemMetrics     bool          `json:"enable_system_metrics"`
	EnableAlertUpdates      bool          `json:"enable_alert_updates"`
	EnablePerformanceMetrics bool          `json:"enable_performance_metrics"`
	ThrottleInterval        time.Duration `json:"throttle_interval"`
}

// DefaultDashboardUpdateConfig returns default configuration
func DefaultDashboardUpdateConfig() *DashboardUpdateConfig {
	return &DashboardUpdateConfig{
		UpdateInterval:           5 * time.Second,
		MetricsInterval:          10 * time.Second,
		BatchSize:               10,
		EnableSystemMetrics:     true,
		EnableAlertUpdates:      true,
		EnablePerformanceMetrics: true,
		ThrottleInterval:        1 * time.Second,
	}
}

// NewDashboardUpdateService creates a new dashboard update service
func NewDashboardUpdateService(
	wsManager *WebSocketManager,
	metricsCollector *monitoring.MetricsCollector,
	pipeline *pipeline.ProcessingPipeline,
	logger *zap.Logger,
	config *DashboardUpdateConfig,
) *DashboardUpdateService {
	if config == nil {
		config = DefaultDashboardUpdateConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	service := &DashboardUpdateService{
		wsManager:        wsManager,
		metricsCollector: metricsCollector,
		pipeline:         pipeline,
		logger:           logger,
		ctx:              ctx,
		cancel:           cancel,
		config:           config,
	}

	return service
}

// Start begins the dashboard update service
func (d *DashboardUpdateService) Start() error {
	d.logger.Info("Starting dashboard update service",
		zap.Duration("update_interval", d.config.UpdateInterval),
		zap.Duration("metrics_interval", d.config.MetricsInterval))

	// Start update loops
	if d.config.EnableSystemMetrics {
		go d.systemMetricsLoop()
	}

	if d.config.EnableAlertUpdates {
		go d.alertUpdatesLoop()
	}

	if d.config.EnablePerformanceMetrics {
		go d.performanceMetricsLoop()
	}

	return nil
}

// Stop stops the dashboard update service
func (d *DashboardUpdateService) Stop() error {
	d.logger.Info("Stopping dashboard update service")
	d.cancel()
	return nil
}

// systemMetricsLoop broadcasts system metrics at regular intervals
func (d *DashboardUpdateService) systemMetricsLoop() {
	ticker := time.NewTicker(d.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := d.broadcastSystemMetrics(); err != nil {
				d.logger.Error("Failed to broadcast system metrics", zap.Error(err))
			}
		case <-d.ctx.Done():
			return
		}
	}
}

// alertUpdatesLoop broadcasts alert processing updates
func (d *DashboardUpdateService) alertUpdatesLoop() {
	ticker := time.NewTicker(d.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := d.broadcastAlertUpdates(); err != nil {
				d.logger.Error("Failed to broadcast alert updates", zap.Error(err))
			}
		case <-d.ctx.Done():
			return
		}
	}
}

// performanceMetricsLoop broadcasts performance metrics
func (d *DashboardUpdateService) performanceMetricsLoop() {
	ticker := time.NewTicker(d.config.MetricsInterval * 2) // Less frequent than system metrics
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := d.broadcastPerformanceMetrics(); err != nil {
				d.logger.Error("Failed to broadcast performance metrics", zap.Error(err))
			}
		case <-d.ctx.Done():
			return
		}
	}
}

// broadcastSystemMetrics collects and broadcasts current system metrics
func (d *DashboardUpdateService) broadcastSystemMetrics() error {
	// Collect current metrics
	systemMetrics := d.collectSystemMetrics()

	// Only broadcast if metrics have changed or it's been a while
	if d.shouldBroadcastMetrics(systemMetrics) {
		message := models.NewSystemMetricsMessage(systemMetrics)

		if err := d.wsManager.BroadcastToChannel(models.WSChannelDashboardUpdates, message); err != nil {
			return err
		}

		// Also send to system metrics channel
		if err := d.wsManager.BroadcastToChannel(models.WSChannelSystemMetrics, message); err != nil {
			return err
		}

		d.mu.Lock()
		d.lastSystemMetrics = systemMetrics
		d.mu.Unlock()

		d.logger.Debug("System metrics broadcasted",
			zap.Int("active_sessions", systemMetrics.ActiveSessions),
			zap.Int("total_sessions", systemMetrics.TotalSessions),
			zap.String("system_status", string(systemMetrics.SystemStatus)))
	}

	return nil
}

// broadcastAlertUpdates broadcasts updates for active alerts
func (d *DashboardUpdateService) broadcastAlertUpdates() error {
	// Get pipeline metrics for queue information
	if d.pipeline == nil {
		return nil
	}

	pipelineMetrics := d.pipeline.GetMetrics()
	if pipelineMetrics == nil {
		return nil
	}

	// Create dashboard update with queue status
	queueUpdate := map[string]interface{}{
		"queue_length":            pipelineMetrics.QueueLength,
		"total_jobs_processed":    pipelineMetrics.TotalJobsProcessed,
		"successful_jobs":         pipelineMetrics.SuccessfulJobs,
		"failed_jobs":             pipelineMetrics.FailedJobs,
		"average_processing_time": pipelineMetrics.AverageProcessingTime.String(),
		"last_update":             pipelineMetrics.LastUpdate,
	}

	message := models.NewDashboardUpdateMessage("pipeline_status", queueUpdate)

	return d.wsManager.BroadcastToChannel(models.WSChannelDashboardUpdates, message)
}

// broadcastPerformanceMetrics broadcasts performance and resource usage metrics
func (d *DashboardUpdateService) broadcastPerformanceMetrics() error {
	if d.metricsCollector == nil {
		return nil
	}

	// Update and get current metrics
	d.metricsCollector.UpdateMetrics()
	systemMetrics := d.metricsCollector.GetMetrics()

	if systemMetrics == nil {
		return nil
	}

	// Create performance update
	performanceUpdate := map[string]interface{}{
		"memory_allocated_mb": systemMetrics.Memory.AllocatedMB,
		"memory_system_mb":    systemMetrics.Memory.SystemMB,
		"goroutines":          systemMetrics.NumGoroutine,
		"uptime":              systemMetrics.Uptime,
		"gc_stats": map[string]interface{}{
			"num_gc":          systemMetrics.Memory.NumGC,
			"gc_cpu_fraction": systemMetrics.Memory.GCCPUFraction,
		},
		"heap_stats": map[string]interface{}{
			"heap_alloc_mb":    systemMetrics.Memory.HeapAllocMB,
			"heap_sys_mb":      systemMetrics.Memory.HeapSysMB,
			"heap_idle_mb":     systemMetrics.Memory.HeapIdleMB,
			"heap_inuse_mb":    systemMetrics.Memory.HeapInuseMB,
			"heap_released_mb": systemMetrics.Memory.HeapReleasedMB,
		},
	}

	message := models.NewDashboardUpdateMessage("performance_metrics", performanceUpdate)

	return d.wsManager.BroadcastToChannel(models.WSChannelDashboardUpdates, message)
}

// collectSystemMetrics gathers current system metrics for broadcasting
func (d *DashboardUpdateService) collectSystemMetrics() *models.SystemMetrics {
	metrics := &models.SystemMetrics{
		SystemStatus:      models.SystemHealthStatusHealthy,
		DatabaseHealth:    "healthy",
		LLMServiceHealth:  make(map[string]string),
		MCPServerHealth:   make(map[string]string),
	}

	// Get pipeline metrics if available
	if d.pipeline != nil {
		pipelineMetrics := d.pipeline.GetMetrics()
		if pipelineMetrics != nil {
			metrics.ActiveSessions = pipelineMetrics.QueueLength
			metrics.TotalSessions = int(pipelineMetrics.TotalJobsProcessed)
			metrics.CompletedSessions = int(pipelineMetrics.SuccessfulJobs)
			metrics.FailedSessions = int(pipelineMetrics.FailedJobs)

			if pipelineMetrics.AverageProcessingTime > 0 {
				avgMs := float64(pipelineMetrics.AverageProcessingTime.Milliseconds())
				metrics.AverageProcessingTimeMs = &avgMs
			}
		}
	}

	// Get system resource metrics if available
	if d.metricsCollector != nil {
		d.metricsCollector.UpdateMetrics()
		systemMetrics := d.metricsCollector.GetMetrics()
		if systemMetrics != nil && systemMetrics.Memory != nil {
			memoryMB := float64(systemMetrics.Memory.AllocatedMB)
			metrics.MemoryUsageMB = &memoryMB
		}
	}

	// Set LLM service health (placeholder - would be enhanced with actual health checks)
	metrics.LLMServiceHealth["openai"] = "healthy"
	metrics.LLMServiceHealth["google"] = "healthy"

	// Set MCP server health (placeholder - would be enhanced with actual health checks)
	metrics.MCPServerHealth["default"] = "healthy"

	return metrics
}

// shouldBroadcastMetrics determines if metrics should be broadcast
func (d *DashboardUpdateService) shouldBroadcastMetrics(newMetrics *models.SystemMetrics) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Always broadcast if we don't have previous metrics
	if d.lastSystemMetrics == nil {
		return true
	}

	// Broadcast if significant changes occurred
	if d.lastSystemMetrics.ActiveSessions != newMetrics.ActiveSessions ||
		d.lastSystemMetrics.TotalSessions != newMetrics.TotalSessions ||
		d.lastSystemMetrics.SystemStatus != newMetrics.SystemStatus {
		return true
	}

	// Broadcast if memory usage changed significantly (more than 10MB)
	if d.lastSystemMetrics.MemoryUsageMB != nil && newMetrics.MemoryUsageMB != nil {
		if abs(*newMetrics.MemoryUsageMB - *d.lastSystemMetrics.MemoryUsageMB) > 10.0 {
			return true
		}
	}

	return false
}

// BroadcastSessionUpdate broadcasts a session update to relevant channels
func (d *DashboardUpdateService) BroadcastSessionUpdate(sessionID string, update *models.SessionUpdate) error {
	// Store the update for batching
	d.activeAlerts.Store(sessionID, update)

	// Broadcast session-specific update
	sessionMessage := models.NewSessionUpdateMessage(sessionID, update)
	if err := d.wsManager.BroadcastToChannel(models.WSChannelSessionPrefix+sessionID, sessionMessage); err != nil {
		d.logger.Error("Failed to broadcast session update",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return err
	}

	// Also broadcast to dashboard for general awareness
	dashboardUpdate := map[string]interface{}{
		"session_id":   sessionID,
		"alert_type":   update.AlertType,
		"status":       update.Status,
		"progress":     update.Progress,
		"agent_type":   update.AgentType,
	}

	dashboardMessage := models.NewDashboardUpdateMessage("session_update", dashboardUpdate)
	if err := d.wsManager.BroadcastToChannel(models.WSChannelDashboardUpdates, dashboardMessage); err != nil {
		d.logger.Error("Failed to broadcast dashboard session update",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return err
	}

	d.logger.Debug("Session update broadcasted",
		zap.String("session_id", sessionID),
		zap.String("status", string(update.Status)),
		zap.String("agent_type", update.AgentType))

	return nil
}

// BroadcastChainProgress broadcasts chain progress updates
func (d *DashboardUpdateService) BroadcastChainProgress(sessionID string, progress *models.ChainProgressUpdate) error {
	message := models.NewChainProgressMessage(sessionID, progress)

	// Broadcast to session-specific channel
	if err := d.wsManager.BroadcastToChannel(models.WSChannelSessionPrefix+sessionID, message); err != nil {
		return err
	}

	// Also broadcast to dashboard
	dashboardUpdate := map[string]interface{}{
		"session_id":           sessionID,
		"chain_id":             progress.ChainID,
		"status":               progress.Status,
		"progress":             progress.Progress,
		"current_stage_index":  progress.CurrentStageIndex,
		"current_stage_name":   progress.CurrentStageName,
		"total_stages":         progress.TotalStages,
		"completed_stages":     progress.CompletedStages,
	}

	dashboardMessage := models.NewDashboardUpdateMessage("chain_progress", dashboardUpdate)
	return d.wsManager.BroadcastToChannel(models.WSChannelDashboardUpdates, dashboardMessage)
}

// BroadcastStageProgress broadcasts stage progress updates
func (d *DashboardUpdateService) BroadcastStageProgress(sessionID string, progress *models.StageProgressUpdate) error {
	message := models.NewStageProgressMessage(sessionID, progress)

	// Broadcast to session-specific channel
	if err := d.wsManager.BroadcastToChannel(models.WSChannelSessionPrefix+sessionID, message); err != nil {
		return err
	}

	// Also broadcast to dashboard for detailed monitoring
	dashboardUpdate := map[string]interface{}{
		"session_id":         sessionID,
		"stage_id":           progress.StageID,
		"stage_name":         progress.StageName,
		"status":             progress.Status,
		"progress":           progress.Progress,
		"current_operation":  progress.CurrentOperation,
		"agent_type":         progress.AgentType,
	}

	dashboardMessage := models.NewDashboardUpdateMessage("stage_progress", dashboardUpdate)
	return d.wsManager.BroadcastToChannel(models.WSChannelDashboardUpdates, dashboardMessage)
}

// GetStats returns dashboard update service statistics
func (d *DashboardUpdateService) GetStats() map[string]interface{} {
	activeAlertsCount := 0
	d.activeAlerts.Range(func(key, value interface{}) bool {
		activeAlertsCount++
		return true
	})

	return map[string]interface{}{
		"active_alerts":      activeAlertsCount,
		"websocket_stats":    d.wsManager.GetStats(),
		"update_interval":    d.config.UpdateInterval.String(),
		"metrics_interval":   d.config.MetricsInterval.String(),
		"service_enabled":    true,
	}
}

// Helper function for absolute value
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}