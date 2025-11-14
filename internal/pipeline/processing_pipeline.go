package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"gorm.io/datatypes"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// HistoryService interface defines the methods needed by the pipeline for history tracking
type HistoryService interface {
	CreateSession(ctx context.Context, session *models.AlertSession) error
	UpdateSession(ctx context.Context, session *models.AlertSession) error
	CreateStageExecution(ctx context.Context, execution *models.StageExecution) error
	UpdateStageExecution(ctx context.Context, execution *models.StageExecution) error
}

// WebSocketManager defines the interface for WebSocket communication
type WebSocketManager interface {
	BroadcastToChannel(channel string, message *models.WebSocketMessage) error
	SendToUser(userID string, message *models.WebSocketMessage) error
}

// ProcessingPipeline orchestrates the complete alert processing workflow
type ProcessingPipeline struct {
	agentRegistry   *agents.AgentRegistry
	mcpRegistry     *mcp.MCPServerRegistry
	historyService  HistoryService
	wsManager       WebSocketManager
	logger          *zap.Logger
	metrics         *PipelineMetrics
	config          *PipelineConfig
	processingQueue chan *ProcessingJob
	workers         []*PipelineWorker
	stopCh          chan struct{}
	wg              sync.WaitGroup

	// Enhanced concurrency control
	alertSemaphore   chan struct{}          // Global semaphore for alert processing
	admissionControl *AdmissionController   // Admission control for load management
	priorityQueues   map[JobPriority]chan *ProcessingJob // Priority-based queues
	backpressure     *BackpressureManager   // Backpressure management
}

// PipelineConfig contains configuration for the processing pipeline
type PipelineConfig struct {
	MaxConcurrentJobs     int           `json:"max_concurrent_jobs"`
	JobTimeout            time.Duration `json:"job_timeout"`
	QueueSize             int           `json:"queue_size"`
	RetryAttempts         int           `json:"retry_attempts"`
	RetryDelay            time.Duration `json:"retry_delay"`
	HealthCheckInterval   time.Duration `json:"health_check_interval"`

	// Enhanced concurrency control
	MaxConcurrentAlerts   int           `json:"max_concurrent_alerts"`   // Global alert processing limit
	AdmissionThrottleRate float64       `json:"admission_throttle_rate"` // Rate for admission control (0-1)
	LoadThreshold         float64       `json:"load_threshold"`          // System load threshold for admission control
	MemoryThreshold       uint64        `json:"memory_threshold"`        // Memory threshold in MB
	QueuePriorityEnabled  bool          `json:"queue_priority_enabled"`  // Enable priority-based queue processing
	BackpressureEnabled   bool          `json:"backpressure_enabled"`    // Enable backpressure mechanisms
}

// DefaultPipelineConfig returns default pipeline configuration
func DefaultPipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		MaxConcurrentJobs:     10,
		JobTimeout:            10 * time.Minute,
		QueueSize:             100,
		RetryAttempts:         3,
		RetryDelay:            30 * time.Second,
		HealthCheckInterval:   30 * time.Second,

		// Enhanced concurrency control defaults
		MaxConcurrentAlerts:   50,    // Global limit across all workers
		AdmissionThrottleRate: 0.8,   // Start throttling at 80% capacity
		LoadThreshold:         0.95,  // System load threshold (increased for development)
		MemoryThreshold:       1024,  // 1GB memory threshold
		QueuePriorityEnabled:  true,  // Enable priority queuing
		BackpressureEnabled:   true,  // Enable backpressure
	}
}

// ProcessingJob represents a single alert processing job
type ProcessingJob struct {
	ID          string                 `json:"id"`
	Alert       *models.Alert          `json:"alert"`
	ChainCtx    *models.ChainContext   `json:"chain_context"`
	Priority    JobPriority            `json:"priority"`
	CreatedAt   time.Time             `json:"created_at"`
	StartedAt   *time.Time            `json:"started_at,omitempty"`
	CompletedAt *time.Time            `json:"completed_at,omitempty"`
	Status      JobStatus             `json:"status"`
	Result      *models.AgentExecutionResult `json:"result,omitempty"`
	Error       string                `json:"error,omitempty"`
	Attempts    int                   `json:"attempts"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// JobPriority represents the priority of a processing job
type JobPriority string

const (
	PriorityLow      JobPriority = "low"
	PriorityMedium   JobPriority = "medium"
	PriorityHigh     JobPriority = "high"
	PriorityCritical JobPriority = "critical"
)

// JobStatus represents the current status of a processing job
type JobStatus string

const (
	StatusPending    JobStatus = "pending"
	StatusQueued     JobStatus = "queued"
	StatusProcessing JobStatus = "processing"
	StatusCompleted  JobStatus = "completed"
	StatusFailed     JobStatus = "failed"
	StatusCancelled  JobStatus = "cancelled"
)

// PipelineWorker processes jobs from the queue
type PipelineWorker struct {
	id       int
	pipeline *ProcessingPipeline
	logger   *zap.Logger
}

// PipelineMetrics tracks pipeline performance metrics
type PipelineMetrics struct {
	mu                    sync.RWMutex
	TotalJobsProcessed    int64         `json:"total_jobs_processed"`
	SuccessfulJobs        int64         `json:"successful_jobs"`
	FailedJobs            int64         `json:"failed_jobs"`
	AverageProcessingTime time.Duration `json:"average_processing_time"`
	QueueLength           int           `json:"queue_length"`
	ActiveWorkers         int           `json:"active_workers"`
	LastUpdate            time.Time     `json:"last_update"`
}

// AdmissionController manages admission control for the pipeline
type AdmissionController struct {
	config              *PipelineConfig
	logger              *zap.Logger
	activeAlerts        int64           // Current number of active alerts
	lastLoadCheck       time.Time
	loadCheckInterval   time.Duration
	currentLoad         float64
	currentMemoryUsage  uint64
	admissionRate       float64         // Current admission rate (0-1)
	mu                  sync.RWMutex
}

// NewAdmissionController creates a new admission controller
func NewAdmissionController(config *PipelineConfig, logger *zap.Logger) *AdmissionController {
	return &AdmissionController{
		config:            config,
		logger:            logger,
		activeAlerts:      0,
		loadCheckInterval: 5 * time.Second,
		admissionRate:     1.0, // Start with full admission
	}
}

// ShouldAdmit determines if a new alert should be admitted for processing
func (ac *AdmissionController) ShouldAdmit(priority JobPriority) bool {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// For development environment, disable admission control completely
	// TODO: Make this configurable based on environment variable
	if ac.config.LoadThreshold >= 0.95 {
		// Development mode - always admit alerts
		ac.logger.Debug("Development mode: bypassing admission control",
			zap.Float64("load_threshold", ac.config.LoadThreshold))
		return true
	}

	ac.logger.Debug("Admission control check",
		zap.Float64("load_threshold", ac.config.LoadThreshold),
		zap.String("priority", string(priority)))

	// Always admit critical alerts (with some limits)
	if priority == PriorityCritical {
		return atomic.LoadInt64(&ac.activeAlerts) < int64(ac.config.MaxConcurrentAlerts*2)
	}

	// Check global alert limit
	if atomic.LoadInt64(&ac.activeAlerts) >= int64(ac.config.MaxConcurrentAlerts) {
		ac.logger.Debug("Admission rejected: maximum concurrent alerts reached",
			zap.Int64("active_alerts", atomic.LoadInt64(&ac.activeAlerts)),
			zap.Int("max_concurrent", ac.config.MaxConcurrentAlerts))
		return false
	}

	// Update system load if needed
	if time.Since(ac.lastLoadCheck) > ac.loadCheckInterval {
		ac.updateSystemLoad()
	}

	// Check system load
	if ac.currentLoad > ac.config.LoadThreshold {
		// Throttle based on system load
		throttleRate := 1.0 - ((ac.currentLoad - ac.config.LoadThreshold) / (1.0 - ac.config.LoadThreshold))
		if throttleRate < ac.config.AdmissionThrottleRate {
			ac.logger.Debug("Admission rejected: high system load",
				zap.Float64("current_load", ac.currentLoad),
				zap.Float64("threshold", ac.config.LoadThreshold),
				zap.Float64("throttle_rate", throttleRate))
			return false
		}
	}

	// Check memory usage
	if ac.currentMemoryUsage > ac.config.MemoryThreshold {
		ac.logger.Debug("Admission rejected: high memory usage",
			zap.Uint64("current_memory_mb", ac.currentMemoryUsage),
			zap.Uint64("threshold_mb", ac.config.MemoryThreshold))
		return false
	}

	return true
}

// AlertStarted notifies the admission controller that an alert started processing
func (ac *AdmissionController) AlertStarted() {
	atomic.AddInt64(&ac.activeAlerts, 1)
}

// AlertCompleted notifies the admission controller that an alert completed processing
func (ac *AdmissionController) AlertCompleted() {
	atomic.AddInt64(&ac.activeAlerts, -1)
}

// updateSystemLoad updates the current system load and memory usage
func (ac *AdmissionController) updateSystemLoad() {
	ac.lastLoadCheck = time.Now()

	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	ac.currentMemoryUsage = memStats.Alloc / 1024 / 1024 // Convert to MB

	// Calculate CPU load approximation using goroutine count
	numGoroutines := runtime.NumGoroutine()
	numCPU := runtime.NumCPU()

	// Rough approximation: normalize goroutines by CPU count
	// This is a simplified load metric - in production you'd want proper CPU metrics
	ac.currentLoad = float64(numGoroutines) / float64(numCPU*100)
	if ac.currentLoad > 1.0 {
		ac.currentLoad = 1.0
	}
}

// GetStats returns admission controller statistics
func (ac *AdmissionController) GetStats() map[string]interface{} {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	return map[string]interface{}{
		"active_alerts":      atomic.LoadInt64(&ac.activeAlerts),
		"max_concurrent":     ac.config.MaxConcurrentAlerts,
		"current_load":       ac.currentLoad,
		"load_threshold":     ac.config.LoadThreshold,
		"memory_usage_mb":    ac.currentMemoryUsage,
		"memory_threshold":   ac.config.MemoryThreshold,
		"admission_rate":     ac.admissionRate,
		"last_load_check":    ac.lastLoadCheck,
	}
}

// BackpressureManager manages backpressure mechanisms
type BackpressureManager struct {
	config         *PipelineConfig
	logger         *zap.Logger
	backpressureOn int32           // Atomic flag for backpressure state
	lastCheck      time.Time
	checkInterval  time.Duration
	mu             sync.RWMutex
}

// NewBackpressureManager creates a new backpressure manager
func NewBackpressureManager(config *PipelineConfig, logger *zap.Logger) *BackpressureManager {
	return &BackpressureManager{
		config:        config,
		logger:        logger,
		checkInterval: 10 * time.Second,
	}
}

// ShouldApplyBackpressure determines if backpressure should be applied
func (bm *BackpressureManager) ShouldApplyBackpressure(queueLength int, activeAlerts int64) bool {
	if !bm.config.BackpressureEnabled {
		return false
	}

	// Apply backpressure if queue is nearly full
	queueUtilization := float64(queueLength) / float64(bm.config.QueueSize)
	if queueUtilization > 0.8 {
		return true
	}

	// Apply backpressure if too many alerts are active
	alertUtilization := float64(activeAlerts) / float64(bm.config.MaxConcurrentAlerts)
	if alertUtilization > 0.9 {
		return true
	}

	return false
}

// SetBackpressure sets the backpressure state
func (bm *BackpressureManager) SetBackpressure(on bool) {
	current := atomic.LoadInt32(&bm.backpressureOn) == 1
	if on != current {
		if on {
			atomic.StoreInt32(&bm.backpressureOn, 1)
			bm.logger.Warn("Backpressure enabled - system under load")
		} else {
			atomic.StoreInt32(&bm.backpressureOn, 0)
			bm.logger.Info("Backpressure disabled - system load normal")
		}
	}
}

// IsBackpressureActive returns true if backpressure is currently active
func (bm *BackpressureManager) IsBackpressureActive() bool {
	return atomic.LoadInt32(&bm.backpressureOn) == 1
}

// GetBackpressureDelay returns the delay to apply when backpressure is active
func (bm *BackpressureManager) GetBackpressureDelay() time.Duration {
	if bm.IsBackpressureActive() {
		return 100 * time.Millisecond // Small delay to reduce load
	}
	return 0
}

// NewProcessingPipeline creates a new processing pipeline
func NewProcessingPipeline(
	agentRegistry *agents.AgentRegistry,
	mcpRegistry *mcp.MCPServerRegistry,
	historyService HistoryService,
	wsManager WebSocketManager,
	logger *zap.Logger,
	config *PipelineConfig,
) *ProcessingPipeline {
	if config == nil {
		config = DefaultPipelineConfig()
	}

	pipeline := &ProcessingPipeline{
		agentRegistry:   agentRegistry,
		mcpRegistry:     mcpRegistry,
		historyService:  historyService,
		wsManager:       wsManager,
		logger:          logger,
		config:          config,
		metrics:         &PipelineMetrics{LastUpdate: time.Now()},
		processingQueue: make(chan *ProcessingJob, config.QueueSize),
		stopCh:          make(chan struct{}),

		// Initialize enhanced concurrency control
		alertSemaphore:   make(chan struct{}, config.MaxConcurrentAlerts),
		admissionControl: NewAdmissionController(config, logger.With(zap.String("component", "admission"))),
		backpressure:     NewBackpressureManager(config, logger.With(zap.String("component", "backpressure"))),
	}

	// Initialize priority queues if enabled
	if config.QueuePriorityEnabled {
		pipeline.priorityQueues = make(map[JobPriority]chan *ProcessingJob)
		pipeline.priorityQueues[PriorityCritical] = make(chan *ProcessingJob, config.QueueSize/4)
		pipeline.priorityQueues[PriorityHigh] = make(chan *ProcessingJob, config.QueueSize/4)
		pipeline.priorityQueues[PriorityMedium] = make(chan *ProcessingJob, config.QueueSize/2)
		pipeline.priorityQueues[PriorityLow] = make(chan *ProcessingJob, config.QueueSize/4)
	}

	// Create workers
	for i := 0; i < config.MaxConcurrentJobs; i++ {
		worker := &PipelineWorker{
			id:       i + 1,
			pipeline: pipeline,
			logger:   logger.With(zap.Int("worker_id", i+1)),
		}
		pipeline.workers = append(pipeline.workers, worker)
	}

	return pipeline
}

// Start starts the processing pipeline
func (p *ProcessingPipeline) Start(ctx context.Context) error {
	p.logger.Info("Starting processing pipeline",
		zap.Int("max_concurrent_jobs", p.config.MaxConcurrentJobs),
		zap.Int("queue_size", p.config.QueueSize))

	// Start workers
	for _, worker := range p.workers {
		p.wg.Add(1)
		go worker.run(ctx)
	}

	// Start health check routine
	p.wg.Add(1)
	go p.healthCheckRoutine(ctx)

	// Start metrics update routine
	p.wg.Add(1)
	go p.metricsUpdateRoutine(ctx)

	p.logger.Info("Processing pipeline started successfully")
	return nil
}

// Stop stops the processing pipeline gracefully
func (p *ProcessingPipeline) Stop() error {
	p.logger.Info("Stopping processing pipeline")

	select {
	case <-p.stopCh:
		// Already stopped
		return nil
	default:
		close(p.stopCh)
	}

	p.wg.Wait()

	p.logger.Info("Processing pipeline stopped")
	return nil
}

// SubmitJob submits a new job to the processing queue
func (p *ProcessingPipeline) SubmitJob(ctx context.Context, job *ProcessingJob) error {
	if job.ID == "" {
		job.ID = generateJobID()
	}

	job.Status = StatusQueued
	job.CreatedAt = time.Now()

	select {
	case p.processingQueue <- job:
		p.logger.Debug("Job submitted to processing queue",
			zap.String("job_id", job.ID),
			zap.String("alert_type", job.Alert.AlertType),
			zap.String("priority", string(job.Priority)))

		// Send WebSocket notification for job submission
		if p.wsManager != nil {
			p.sendJobStatusUpdate(job, "queued", nil)
		}

		p.updateQueueMetrics()
		return nil

	case <-ctx.Done():
		return ctx.Err()

	default:
		return fmt.Errorf("processing queue is full")
	}
}

// ProcessAlert creates and submits a processing job for an alert with enhanced concurrency control
func (p *ProcessingPipeline) ProcessAlert(ctx context.Context, alert *models.Alert, priority JobPriority) (*ProcessingJob, error) {
	// Check admission control
	if !p.admissionControl.ShouldAdmit(priority) {
		return nil, fmt.Errorf("alert admission rejected due to system load or capacity limits")
	}

	// Check backpressure
	if p.backpressure.IsBackpressureActive() {
		delay := p.backpressure.GetBackpressureDelay()
		if delay > 0 {
			p.logger.Debug("Applying backpressure delay",
				zap.Duration("delay", delay),
				zap.String("alert_type", alert.AlertType))

			select {
			case <-time.After(delay):
				// Continue after delay
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	// Create chain context
	chainCtx := models.NewChainContext(
		alert.AlertType,
		alert.Data,
		generateSessionID(),
		"processing",
	)

	// Create processing job
	job := &ProcessingJob{
		Alert:    alert,
		ChainCtx: chainCtx,
		Priority: priority,
		Status:   StatusPending,
		Metadata: make(map[string]interface{}),
	}

	// Submit job with priority-aware queuing
	if err := p.submitJobWithPriority(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to submit processing job: %w", err)
	}

	p.logger.Debug("Alert processing job created",
		zap.String("job_id", job.ID),
		zap.String("alert_type", alert.AlertType),
		zap.String("priority", string(priority)),
		zap.String("session_id", chainCtx.SessionID))

	return job, nil
}

// submitJobWithPriority submits a job using priority queues if enabled
func (p *ProcessingPipeline) submitJobWithPriority(ctx context.Context, job *ProcessingJob) error {
	if job.ID == "" {
		job.ID = generateJobID()
	}

	job.Status = StatusQueued
	job.CreatedAt = time.Now()

	// Use priority queues if enabled
	if p.config.QueuePriorityEnabled && p.priorityQueues != nil {
		priorityQueue, exists := p.priorityQueues[job.Priority]
		if exists {
			select {
			case priorityQueue <- job:
				p.logger.Debug("Job submitted to priority queue",
					zap.String("job_id", job.ID),
					zap.String("priority", string(job.Priority)))

				// Send WebSocket notification for job submission
				if p.wsManager != nil {
					p.sendJobStatusUpdate(job, "queued", nil)
				}

				return nil
			case <-ctx.Done():
				return ctx.Err()
			default:
				// Priority queue is full, fall back to main queue
				p.logger.Warn("Priority queue full, using main queue",
					zap.String("priority", string(job.Priority)))
			}
		}
	}

	// Use main processing queue
	select {
	case p.processingQueue <- job:
		p.logger.Debug("Job submitted to main processing queue",
			zap.String("job_id", job.ID))

		// Send WebSocket notification for job submission
		if p.wsManager != nil {
			p.sendJobStatusUpdate(job, "queued", nil)
		}

		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("processing queue is full")
	}
}

// GetJobStatus returns the current status of a job
func (p *ProcessingPipeline) GetJobStatus(jobID string) (*ProcessingJob, error) {
	// In a production system, this would query a persistent store
	// For now, we'll return a not implemented error
	return nil, fmt.Errorf("job status lookup not implemented - would query persistent store")
}

// GetMetrics returns current pipeline metrics
func (p *ProcessingPipeline) GetMetrics() *PipelineMetrics {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := &PipelineMetrics{
		TotalJobsProcessed:    p.metrics.TotalJobsProcessed,
		SuccessfulJobs:        p.metrics.SuccessfulJobs,
		FailedJobs:            p.metrics.FailedJobs,
		AverageProcessingTime: p.metrics.AverageProcessingTime,
		QueueLength:           len(p.processingQueue),
		ActiveWorkers:         len(p.workers),
		LastUpdate:            p.metrics.LastUpdate,
	}

	return metrics
}

// worker.run processes jobs from the queue
func (w *PipelineWorker) run(ctx context.Context) {
	defer w.pipeline.wg.Done()

	w.logger.Info("Pipeline worker started")

	for {
		job := w.getNextJob(ctx)
		if job == nil {
			// Context cancelled or pipeline stopping
			return
		}
		w.processJob(ctx, job)
	}
}

// getNextJob retrieves the next job from queues, prioritizing higher priority queues
func (w *PipelineWorker) getNextJob(ctx context.Context) *ProcessingJob {
	// If priority queues are enabled, use them with proper blocking behavior
	if w.pipeline.config.QueuePriorityEnabled && w.pipeline.priorityQueues != nil {
		// Priority order: Critical > High > Medium > Low
		priorityOrder := []JobPriority{PriorityCritical, PriorityHigh, PriorityMedium, PriorityLow}

		// Create a select case for each priority queue plus control channels
		cases := make([]reflect.SelectCase, 0, len(priorityOrder)+3)
		queueIndexMap := make(map[int]JobPriority)

		// Add priority queue cases (higher priority first)
		for _, priority := range priorityOrder {
			if queue, exists := w.pipeline.priorityQueues[priority]; exists {
				cases = append(cases, reflect.SelectCase{
					Dir:  reflect.SelectRecv,
					Chan: reflect.ValueOf(queue),
				})
				queueIndexMap[len(cases)-1] = priority
			}
		}

		// Add main processing queue case
		mainQueueIndex := len(cases)
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(w.pipeline.processingQueue),
		})

		// Add stop channel case
		stopChIndex := len(cases)
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(w.pipeline.stopCh),
		})

		// Add context done case
		ctxDoneIndex := len(cases)
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ctx.Done()),
		})

		// Block until a job is available from any queue
		chosen, value, ok := reflect.Select(cases)
		if !ok {
			// Channel was closed
			return nil
		}

		switch chosen {
		case stopChIndex:
			w.logger.Info("Pipeline worker stopping")
			return nil
		case ctxDoneIndex:
			w.logger.Info("Pipeline worker context cancelled")
			return nil
		case mainQueueIndex:
			job := value.Interface().(*ProcessingJob)
			w.logger.Debug("Retrieved job from main queue",
				zap.String("job_id", job.ID))
			return job
		default:
			// Job from priority queue
			if priority, exists := queueIndexMap[chosen]; exists {
				job := value.Interface().(*ProcessingJob)
				w.logger.Debug("Retrieved job from priority queue",
					zap.String("priority", string(priority)),
					zap.String("job_id", job.ID))
				return job
			}
		}
	}

	// Fall back to main processing queue only (when priority queues disabled)
	select {
	case job := <-w.pipeline.processingQueue:
		w.logger.Debug("Retrieved job from main queue (priority disabled)",
			zap.String("job_id", job.ID))
		return job

	case <-w.pipeline.stopCh:
		w.logger.Info("Pipeline worker stopping")
		return nil

	case <-ctx.Done():
		w.logger.Info("Pipeline worker context cancelled")
		return nil
	}
}

// processJob processes a single job
func (w *PipelineWorker) processJob(ctx context.Context, job *ProcessingJob) {
	startTime := time.Now()
	job.Status = StatusProcessing
	job.StartedAt = &startTime
	job.Attempts++

	w.logger.Info("Processing job",
		zap.String("job_id", job.ID),
		zap.String("alert_type", job.Alert.AlertType),
		zap.Int("attempt", job.Attempts))

	// Send WebSocket notification for processing start
	if w.pipeline.wsManager != nil {
		w.pipeline.sendJobStatusUpdate(job, "processing", nil)
	}

	// Debug: Check if historyService is nil
	w.logger.Debug("History service status check",
		zap.Bool("history_service_nil", w.pipeline.historyService == nil))

	// Acquire semaphore slot for concurrent alert processing
	select {
	case w.pipeline.alertSemaphore <- struct{}{}:
		// Successfully acquired semaphore slot
		defer func() {
			<-w.pipeline.alertSemaphore // Release semaphore slot
		}()
	case <-ctx.Done():
		w.logger.Warn("Job cancelled while waiting for semaphore",
			zap.String("job_id", job.ID))
		job.Status = StatusCancelled
		return
	}

	// Select agent first to get correct agent type for session
	agent, err := w.pipeline.agentRegistry.GetAgentForAlert(job.Alert)
	if err != nil {
		w.logger.Error("Failed to get agent for alert",
			zap.String("job_id", job.ID),
			zap.Error(err))
		job.Status = StatusFailed
		job.Error = err.Error()
		return
	}

	agentType := agent.GetAgentType()
	w.logger.Debug("Selected agent for processing",
		zap.String("job_id", job.ID),
		zap.String("agent_type", agentType))

	// Create history session record with correct agent type
	alertSession := w.createAlertSession(job, startTime, agentType)
	if w.pipeline.historyService != nil {
		if err := w.pipeline.historyService.CreateSession(ctx, alertSession); err != nil {
			w.logger.Error("Failed to create alert session in history",
				zap.String("job_id", job.ID),
				zap.String("session_id", alertSession.SessionID),
				zap.Error(err))
		} else {
			w.logger.Debug("Created alert session in history",
				zap.String("job_id", job.ID),
				zap.String("session_id", alertSession.SessionID))
		}
	}

	// Notify admission controller that alert processing started
	w.pipeline.admissionControl.AlertStarted()
	defer w.pipeline.admissionControl.AlertCompleted()

	// Update backpressure state based on current load
	if w.pipeline.backpressure != nil {
		activeAlerts := atomic.LoadInt64(&w.pipeline.admissionControl.activeAlerts)
		queueLength := len(w.pipeline.processingQueue)
		shouldApplyBackpressure := w.pipeline.backpressure.ShouldApplyBackpressure(queueLength, activeAlerts)
		w.pipeline.backpressure.SetBackpressure(shouldApplyBackpressure)
	}

	// Create processing context with timeout
	processingCtx, cancel := context.WithTimeout(ctx, w.pipeline.config.JobTimeout)
	defer cancel()

	// Create stage execution record for tracking
	stageExecution := w.createStageExecution(job, agent, startTime)
	if w.pipeline.historyService != nil {
		if err := w.pipeline.historyService.CreateStageExecution(processingCtx, stageExecution); err != nil {
			w.logger.Warn("Failed to create stage execution record",
				zap.String("job_id", job.ID),
				zap.String("execution_id", stageExecution.ExecutionID),
				zap.Error(err))
		} else {
			w.logger.Debug("Created stage execution record",
				zap.String("job_id", job.ID),
				zap.String("execution_id", stageExecution.ExecutionID))
		}
	}

	// Add stage execution ID to context before calling the agent
	ctxWithStageID := context.WithValue(processingCtx, "stage_execution_id", stageExecution.ExecutionID)

	// Debug: Log what stage execution ID we're passing
	w.logger.Debug("Pipeline: Passing stage execution ID to agent",
		zap.String("job_id", job.ID),
		zap.String("stage_execution_id", stageExecution.ExecutionID),
		zap.String("session_id", job.ChainCtx.SessionID))

	// Execute the processing with the already selected agent
	result, err := w.executeProcessingWithAgent(ctxWithStageID, job, agent)

	// Update job with results
	completedAt := time.Now()
	job.CompletedAt = &completedAt
	processingDuration := completedAt.Sub(startTime)

	// Update stage execution with completion status
	if w.pipeline.historyService != nil {
		if err != nil {
			stageExecution.MarkFailed(err.Error())
		} else {
			// Extract output from result if available
			var output map[string]interface{}
			if result != nil {
				output = map[string]interface{}{
					"status":         string(result.Status),
					"agent_name":     result.AgentName,
					"result_summary": result.ResultSummary,
					"final_analysis": result.FinalAnalysis,
				}
			}
			stageExecution.MarkCompleted(output)
		}

		if updateErr := w.pipeline.historyService.UpdateStageExecution(processingCtx, stageExecution); updateErr != nil {
			w.logger.Warn("Failed to update stage execution record",
				zap.String("job_id", job.ID),
				zap.String("execution_id", stageExecution.ExecutionID),
				zap.Error(updateErr))
		}
	}

	if err != nil {
		job.Status = StatusFailed
		job.Error = err.Error()

		w.logger.Error("Job processing failed",
			zap.String("job_id", job.ID),
			zap.Error(err),
			zap.Duration("duration", processingDuration))

		// Retry logic
		if job.Attempts < w.pipeline.config.RetryAttempts {
			w.logger.Info("Retrying failed job",
				zap.String("job_id", job.ID),
				zap.Int("attempt", job.Attempts+1))

			// Reset status and requeue after delay
			job.Status = StatusQueued
			go func() {
				time.Sleep(w.pipeline.config.RetryDelay)
				select {
				case w.pipeline.processingQueue <- job:
					// Successfully requeued
				default:
					w.logger.Warn("Failed to requeue job - queue full",
						zap.String("job_id", job.ID))
				}
			}()
			return
		}

		w.pipeline.updateMetrics(processingDuration, false)

		// Send WebSocket notification for job failure
		if w.pipeline.wsManager != nil {
			w.pipeline.sendJobStatusUpdate(job, "failed", err)
		}

		// Update AlertSession status to failed
		if w.pipeline.historyService != nil {
			if err := w.updateAlertSessionStatus(job, "failed", nil); err != nil {
				w.logger.Warn("Failed to update alert session status to failed",
					zap.String("job_id", job.ID),
					zap.Error(err))
			}
		}
	} else {
		job.Status = StatusCompleted
		job.Result = result

		w.logger.Info("Job processing completed successfully",
			zap.String("job_id", job.ID),
			zap.Duration("duration", processingDuration))

		w.pipeline.updateMetrics(processingDuration, true)

		// Send WebSocket notification for job completion
		if w.pipeline.wsManager != nil {
			w.pipeline.sendJobStatusUpdate(job, "completed", nil)
		}

		// Update AlertSession status to completed
		if w.pipeline.historyService != nil {
			if err := w.updateAlertSessionStatus(job, "completed", result); err != nil {
				w.logger.Warn("Failed to update alert session status to completed",
					zap.String("job_id", job.ID),
					zap.Error(err))
			}
		}
	}
}

// executeProcessing executes the actual alert processing
func (w *PipelineWorker) executeProcessingWithAgent(ctx context.Context, job *ProcessingJob, agent agents.Agent) (*models.AgentExecutionResult, error) {
	// Step 1: Validate the alert
	if err := w.validateAlert(job.Alert); err != nil {
		return nil, fmt.Errorf("alert validation failed: %w", err)
	}

	// Step 2: Execute agent processing (agent already selected)
	result, err := agent.ProcessAlert(ctx, job.Alert, job.ChainCtx)
	if err != nil {
		return nil, fmt.Errorf("agent processing failed: %w", err)
	}

	// Step 4: Post-process results
	if err := w.postProcessResults(job, result); err != nil {
		w.logger.Warn("Post-processing failed but continuing",
			zap.String("job_id", job.ID),
			zap.Error(err))
	}

	return result, nil
}

// validateAlert validates the incoming alert
func (w *PipelineWorker) validateAlert(alert *models.Alert) error {
	if alert == nil {
		return fmt.Errorf("alert cannot be nil")
	}

	if alert.AlertType == "" {
		return fmt.Errorf("alert type is required")
	}

	if alert.Data == nil {
		return fmt.Errorf("alert data is required")
	}

	return nil
}

// postProcessResults performs post-processing on the results
func (w *PipelineWorker) postProcessResults(job *ProcessingJob, result *models.AgentExecutionResult) error {
	// Add processing metadata
	if job.Metadata == nil {
		job.Metadata = make(map[string]interface{})
	}

	job.Metadata["worker_id"] = w.id
	job.Metadata["processing_duration"] = time.Since(*job.StartedAt).String()
	job.Metadata["agent_type"] = result.AgentName
	job.Metadata["result_status"] = result.Status

	// Log processing completion
	w.logger.Info("Alert processing completed",
		zap.String("job_id", job.ID),
		zap.String("alert_type", job.Alert.AlertType),
		zap.String("agent_name", result.AgentName),
		zap.String("status", string(result.Status)))

	return nil
}

// createAlertSession creates an AlertSession from a ProcessingJob
func (w *PipelineWorker) createAlertSession(job *ProcessingJob, startTime time.Time, agentType string) *models.AlertSession {
	// Convert the alert data to match the expected format
	var alertData datatypes.JSON
	if job.Alert.Data != nil {
		alertDataBytes, err := json.Marshal(job.Alert.Data)
		if err != nil {
			w.logger.Error("Failed to marshal alert data",
				zap.Error(err),
				zap.String("job_id", job.ID))
			// Set to empty JSON object on marshal error
			alertData = datatypes.JSON("{}")
		} else {
			alertData = datatypes.JSON(alertDataBytes)
		}
	} else {
		// Set to empty JSON object if no data
		alertData = datatypes.JSON("{}")
	}

	// Generate a unique alert ID from job ID or use session ID as fallback
	alertID := job.ID
	if alertID == "" {
		alertID = job.ChainCtx.SessionID
	}

	startTimeUs := startTime.UnixMicro()

	// Convert string AlertType to *string for the database model
	var alertType *string
	if job.Alert.AlertType != "" {
		alertType = &job.Alert.AlertType
	}

	return &models.AlertSession{
		SessionID:     job.ChainCtx.SessionID,
		AlertID:       alertID,
		AlertType:     alertType,
		AlertData:     alertData,
		AgentType:     agentType,
		Status:        string(models.AlertSessionStatusInProgress),
		StartedAtUs:   startTimeUs,
		CompletedAtUs: nil,
		ErrorMessage:  nil,
		FinalAnalysis: nil,
		ChainID:       job.ChainCtx.SessionID, // Use session ID as chain ID for now
	}
}

// createStageExecution creates a StageExecution record for tracking individual processing stages
func (w *PipelineWorker) createStageExecution(job *ProcessingJob, agent agents.Agent, startTime time.Time) *models.StageExecution {
	stageID := fmt.Sprintf("stage_%d", time.Now().UnixNano())
	executionID := fmt.Sprintf("exec_%d", time.Now().UnixNano())

	return &models.StageExecution{
		ExecutionID:   executionID,
		SessionID:     job.ChainCtx.SessionID,
		StageID:       stageID,
		StageIndex:    0, // Single stage for now, can be enhanced later for multi-stage
		StageName:     fmt.Sprintf("%s Processing", agent.GetAgentType()),
		Agent:         agent.GetAgentType(),
		Status:        string(models.StageStatusActive),
		StartedAtUs:   &[]int64{startTime.UnixMicro()}[0],
		CompletedAtUs: nil,
		DurationMs:    nil,
		StageOutput:   datatypes.JSON("{}"),
		ErrorMessage:  nil,
	}
}

// updateAlertSessionStatus updates the status of an AlertSession in the database
func (w *PipelineWorker) updateAlertSessionStatus(job *ProcessingJob, status string, result *models.AgentExecutionResult) error {
	if w.pipeline.historyService == nil {
		return fmt.Errorf("history service not available")
	}

	// Calculate completion time and duration
	completedTime := time.Now()
	completedTimeUs := completedTime.UnixMicro()

	// Map status string to AlertSessionStatus constant
	var alertStatus models.AlertSessionStatus
	switch status {
	case "completed":
		alertStatus = models.AlertSessionStatusCompleted
	case "failed":
		alertStatus = models.AlertSessionStatusFailed
	case "in_progress":
		alertStatus = models.AlertSessionStatusInProgress
	case "pending":
		alertStatus = models.AlertSessionStatusPending
	default:
		alertStatus = models.AlertSessionStatusInProgress
	}

	// Create partial AlertSession with only the fields that should be updated
	session := &models.AlertSession{
		SessionID:     job.ChainCtx.SessionID,
		Status:        string(alertStatus),
		CompletedAtUs: &completedTimeUs,
	}

	// Add agent type from result if available
	if result != nil {
		session.AgentType = result.AgentName
		if result.FinalAnalysis != nil && *result.FinalAnalysis != "" {
			session.FinalAnalysis = result.FinalAnalysis
		}
	}

	// Add error message for failed jobs
	if status == "failed" && job.Error != "" {
		errorMsg := job.Error
		session.ErrorMessage = &errorMsg
	}

	// Update the session in the database
	return w.pipeline.historyService.UpdateSession(context.Background(), session)
}

// healthCheckRoutine performs periodic health checks
func (p *ProcessingPipeline) healthCheckRoutine(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.performHealthCheck()

		case <-p.stopCh:
			return

		case <-ctx.Done():
			return
		}
	}
}

// performHealthCheck performs a health check of the pipeline
func (p *ProcessingPipeline) performHealthCheck() {
	p.logger.Debug("Performing pipeline health check")

	// Check agent registry health
	agentHealth := p.agentRegistry.HealthCheck()
	healthyAgents := 0
	for _, status := range agentHealth {
		if status == "healthy" {
			healthyAgents++
		}
	}

	// Check MCP registry health
	mcpHealthy := true
	if p.mcpRegistry != nil {
		// In a production system, we would check actual MCP server health
		// For now, assume healthy if registry exists
	}

	p.logger.Debug("Health check completed",
		zap.Int("healthy_agents", healthyAgents),
		zap.Int("total_agents", len(agentHealth)),
		zap.Bool("mcp_healthy", mcpHealthy),
		zap.Int("queue_length", len(p.processingQueue)),
		zap.Int("active_workers", len(p.workers)))
}

// metricsUpdateRoutine updates pipeline metrics
func (p *ProcessingPipeline) metricsUpdateRoutine(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.updateQueueMetrics()

		case <-p.stopCh:
			return

		case <-ctx.Done():
			return
		}
	}
}

// updateQueueMetrics updates queue-related metrics
func (p *ProcessingPipeline) updateQueueMetrics() {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	p.metrics.QueueLength = len(p.processingQueue)
	p.metrics.LastUpdate = time.Now()
}

// updateMetrics updates processing metrics
func (p *ProcessingPipeline) updateMetrics(duration time.Duration, success bool) {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	p.metrics.TotalJobsProcessed++
	if success {
		p.metrics.SuccessfulJobs++
	} else {
		p.metrics.FailedJobs++
	}

	// Update average processing time (simple moving average)
	if p.metrics.TotalJobsProcessed == 1 {
		p.metrics.AverageProcessingTime = duration
	} else {
		// Weighted average with more weight on recent values
		weight := 0.1
		p.metrics.AverageProcessingTime = time.Duration(
			float64(p.metrics.AverageProcessingTime)*(1-weight) + float64(duration)*weight,
		)
	}

	p.metrics.LastUpdate = time.Now()
}

// sendJobStatusUpdate sends WebSocket notifications for job status changes
func (p *ProcessingPipeline) sendJobStatusUpdate(job *ProcessingJob, status string, err error) {
	if p.wsManager == nil {
		return
	}

	// Create status update data
	statusData := map[string]interface{}{
		"type":       "job_status_update",
		"job_id":     job.ID,
		"alert_type": job.Alert.AlertType,
		"status":     status,
		"timestamp":  time.Now().Unix(),
		"session_id": job.ChainCtx.SessionID,
		"priority":   string(job.Priority),
	}

	// Add error information if present
	if err != nil {
		statusData["error"] = err.Error()
	}

	// Add completion time and duration for completed/failed jobs
	if status == "completed" || status == "failed" {
		if job.CompletedAt != nil {
			statusData["completed_at"] = job.CompletedAt.Unix()
			if job.StartedAt != nil {
				duration := job.CompletedAt.Sub(*job.StartedAt)
				statusData["duration_ms"] = duration.Milliseconds()
			}
		}
	}

	// Add result summary for completed jobs
	if status == "completed" && job.Result != nil {
		statusData["result_summary"] = job.Result.ResultSummary
		statusData["agent_name"] = job.Result.AgentName
		statusData["final_analysis"] = job.Result.FinalAnalysis
	}

	// Create WebSocket message
	wsMessage := &models.WebSocketMessage{
		Type:    "job_status_update",
		Data:    statusData,
		Channel: "", // Will be set for each channel
	}

	// Broadcast to alert-specific channel (for direct alert monitoring)
	alertChannel := fmt.Sprintf("alert_%s", job.ID)
	wsMessage.Channel = alertChannel
	if broadcastErr := p.wsManager.BroadcastToChannel(alertChannel, wsMessage); broadcastErr != nil {
		p.logger.Debug("Failed to broadcast to alert channel",
			zap.String("channel", alertChannel),
			zap.Error(broadcastErr))
	}

	// Broadcast to dashboard channel (for general monitoring)
	dashboardChannel := "dashboard"
	wsMessage.Channel = dashboardChannel
	if broadcastErr := p.wsManager.BroadcastToChannel(dashboardChannel, wsMessage); broadcastErr != nil {
		p.logger.Debug("Failed to broadcast to dashboard channel",
			zap.String("channel", dashboardChannel),
			zap.Error(broadcastErr))
	}

	// Broadcast to session-specific channel (for session-based updates)
	sessionChannel := fmt.Sprintf("session_%s", job.ChainCtx.SessionID)
	wsMessage.Channel = sessionChannel
	if broadcastErr := p.wsManager.BroadcastToChannel(sessionChannel, wsMessage); broadcastErr != nil {
		p.logger.Debug("Failed to broadcast to session channel",
			zap.String("channel", sessionChannel),
			zap.Error(broadcastErr))
	}

	p.logger.Info("Sent WebSocket job status update",
		zap.String("job_id", job.ID),
		zap.String("status", status),
		zap.String("alert_channel", alertChannel),
		zap.String("session_channel", sessionChannel))
}

// Helper functions

func generateJobID() string {
	return fmt.Sprintf("job_%d", time.Now().UnixNano())
}

func generateSessionID() string {
	return fmt.Sprintf("session_%d", time.Now().UnixNano())
}

// PipelineStatus represents the overall status of the pipeline
type PipelineStatus struct {
	Status              string                 `json:"status"`
	Metrics             *PipelineMetrics       `json:"metrics"`
	AgentHealth         map[string]string      `json:"agent_health"`
	QueueStatus         QueueStatus            `json:"queue_status"`
	ConcurrencyControl  ConcurrencyStatus      `json:"concurrency_control"`
	PriorityQueues      map[string]QueueStatus `json:"priority_queues,omitempty"`
	LastUpdate          time.Time              `json:"last_update"`
}

// ConcurrencyStatus represents the status of concurrency control mechanisms
type ConcurrencyStatus struct {
	AdmissionControl AdmissionStatus    `json:"admission_control"`
	Backpressure     BackpressureStatus `json:"backpressure"`
	Semaphore        SemaphoreStatus    `json:"semaphore"`
}

// AdmissionStatus represents admission controller status
type AdmissionStatus struct {
	ActiveAlerts      int64                  `json:"active_alerts"`
	MaxConcurrent     int                    `json:"max_concurrent"`
	CurrentLoad       float64                `json:"current_load"`
	LoadThreshold     float64                `json:"load_threshold"`
	MemoryUsageMB     uint64                 `json:"memory_usage_mb"`
	MemoryThreshold   uint64                 `json:"memory_threshold"`
	Stats             map[string]interface{} `json:"stats"`
}

// BackpressureStatus represents backpressure manager status
type BackpressureStatus struct {
	Active  bool   `json:"active"`
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason,omitempty"`
}

// SemaphoreStatus represents semaphore usage status
type SemaphoreStatus struct {
	Capacity int `json:"capacity"`
	Used     int `json:"used"`
	Usage    float64 `json:"usage_percentage"`
}

// QueueStatus represents the status of the processing queue
type QueueStatus struct {
	Length   int     `json:"length"`
	Capacity int     `json:"capacity"`
	Usage    float64 `json:"usage_percentage"`
}

// GetPipelineStatus returns comprehensive pipeline status
func (p *ProcessingPipeline) GetPipelineStatus() *PipelineStatus {
	metrics := p.GetMetrics()
	agentHealth := p.agentRegistry.HealthCheck()

	queueUsage := float64(len(p.processingQueue)) / float64(p.config.QueueSize) * 100

	status := "healthy"
	if queueUsage > 90 {
		status = "overloaded"
	} else if queueUsage > 70 {
		status = "busy"
	}

	// Collect admission control status
	admissionStats := p.admissionControl.GetStats()
	admissionStatus := AdmissionStatus{
		ActiveAlerts:    atomic.LoadInt64(&p.admissionControl.activeAlerts),
		MaxConcurrent:   p.config.MaxConcurrentAlerts,
		CurrentLoad:     p.admissionControl.currentLoad,
		LoadThreshold:   p.config.LoadThreshold,
		MemoryUsageMB:   p.admissionControl.currentMemoryUsage,
		MemoryThreshold: p.config.MemoryThreshold,
		Stats:           admissionStats,
	}

	// Collect backpressure status
	backpressureActive := p.backpressure.IsBackpressureActive()
	backpressureStatus := BackpressureStatus{
		Active:  backpressureActive,
		Enabled: p.config.BackpressureEnabled,
	}
	if backpressureActive {
		if queueUsage > 80 {
			backpressureStatus.Reason = "high queue utilization"
		} else if admissionStatus.ActiveAlerts > int64(float64(p.config.MaxConcurrentAlerts)*0.9) {
			backpressureStatus.Reason = "high concurrent alert load"
		} else {
			backpressureStatus.Reason = "system resource pressure"
		}
	}

	// Collect semaphore status
	semaphoreUsed := len(p.alertSemaphore)
	semaphoreCapacity := cap(p.alertSemaphore)
	semaphoreUsage := float64(semaphoreUsed) / float64(semaphoreCapacity) * 100

	semaphoreStatus := SemaphoreStatus{
		Capacity: semaphoreCapacity,
		Used:     semaphoreUsed,
		Usage:    semaphoreUsage,
	}

	// Collect priority queue status if enabled
	var priorityQueues map[string]QueueStatus
	if p.config.QueuePriorityEnabled && p.priorityQueues != nil {
		priorityQueues = make(map[string]QueueStatus)
		for priority, queue := range p.priorityQueues {
			queueLen := len(queue)
			queueCap := cap(queue)
			usage := float64(queueLen) / float64(queueCap) * 100

			priorityQueues[string(priority)] = QueueStatus{
				Length:   queueLen,
				Capacity: queueCap,
				Usage:    usage,
			}
		}
	}

	return &PipelineStatus{
		Status:      status,
		Metrics:     metrics,
		AgentHealth: agentHealth,
		QueueStatus: QueueStatus{
			Length:   len(p.processingQueue),
			Capacity: p.config.QueueSize,
			Usage:    queueUsage,
		},
		ConcurrencyControl: ConcurrencyStatus{
			AdmissionControl: admissionStatus,
			Backpressure:     backpressureStatus,
			Semaphore:        semaphoreStatus,
		},
		PriorityQueues: priorityQueues,
		LastUpdate:     time.Now(),
	}
}