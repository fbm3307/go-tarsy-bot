package services

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/database"
	"github.com/codeready/go-tarsy-bot/internal/models"
)

// AlertService handles the core alert processing orchestration
// This matches the original Python AlertService exactly - direct agent routing, no chains
type AlertService struct {
	db                    *database.DB
	logger                *zap.Logger
	agentRegistry         *agents.AgentRegistry
	historyService        *HistoryService
	runbookService        *RunbookService
	llmIntegrationService *LLMIntegrationService
	httpClient            *http.Client
	config                *AlertServiceConfig
}

// AlertServiceConfig contains configuration for the alert service
type AlertServiceConfig struct {
	MaxConcurrentAlerts int           `json:"max_concurrent_alerts"`
	ProcessingTimeout   time.Duration `json:"processing_timeout"`
	RunbookTimeout      time.Duration `json:"runbook_timeout"`
}

// NewAlertService creates a new alert service instance (matches Python structure)
func NewAlertService(
	db *database.DB,
	logger *zap.Logger,
	agentRegistry *agents.AgentRegistry,
	llmIntegrationService *LLMIntegrationService,
	config *AlertServiceConfig,
) *AlertService {
	if config == nil {
		config = &AlertServiceConfig{
			MaxConcurrentAlerts: 10,
			ProcessingTimeout:   5 * time.Minute,
			RunbookTimeout:      30 * time.Second,
		}
	}

	return &AlertService{
		db:                    db,
		logger:                logger,
		agentRegistry:         agentRegistry,
		historyService:        NewHistoryService(db, logger),
		runbookService:        NewRunbookService(&http.Client{Timeout: config.RunbookTimeout}, logger),
		llmIntegrationService: llmIntegrationService,
		httpClient:            &http.Client{Timeout: config.RunbookTimeout},
		config:                config,
	}
}

// ProcessAlert processes an alert through the exact Python workflow
// Matches original Python AlertService.ProcessAlert exactly
func (as *AlertService) ProcessAlert(ctx context.Context, alert *models.Alert) (*models.AlertResponse, error) {
	as.logger.Info("Starting alert processing",
		zap.String("alert_type", alert.AlertType),
	)

	// Step 1: Generate session ID for tracking (matches Python)
	sessionID := uuid.New().String()

	// Step 2: Validation - Ensure alert has valid structure
	if alert.AlertType == "" {
		return nil, fmt.Errorf("alert type is required")
	}

	// Step 3: AgentRegistry routes to appropriate specialized agent (CORE PYTHON BEHAVIOR)
	agent, err := as.agentRegistry.GetAgentForAlert(alert)
	if err != nil {
		as.logger.Error("Failed to get agent for alert",
			zap.String("alert_type", alert.AlertType),
			zap.Error(err))
		return nil, fmt.Errorf("agent selection failed: %w", err)
	}

	as.logger.Info("Agent selected for alert processing",
		zap.String("alert_type", alert.AlertType),
		zap.String("agent_type", agent.GetAgentType()),
		zap.String("session_id", sessionID))

	// Step 4: Create history session for complete audit trail (matches Python)
	// Convert string AlertType to *string for the database model
	var alertType *string
	if alert.AlertType != "" {
		alertType = &alert.AlertType
	}

	session := &models.AlertSession{
		SessionID:   sessionID,
		AlertID:     sessionID,
		AlertType:   alertType, // Use AlertType not Type
		AlertData:   models.JSONFromMap(alert.Data),
		AgentType:   agent.GetAgentType(), // Use actual agent type
		Status:      string(models.AlertSessionStatusPending),
		StartedAtUs: time.Now().UnixMicro(),
	}

	if err := as.historyService.CreateSession(ctx, session); err != nil {
		as.logger.Error("Failed to create alert session", zap.Error(err))
		return nil, fmt.Errorf("session creation failed: %w", err)
	}

	// Step 5: Start background processing (matches Python async behavior)
	go as.processAlertWithAgent(context.Background(), alert, agent, session)

	return &models.AlertResponse{
		AlertID: sessionID,
		Status:  "queued",
		Message: "Alert submitted for processing",
	}, nil
}

// processAlertWithAgent handles the complete agent processing workflow (matches Python exactly)
func (as *AlertService) processAlertWithAgent(ctx context.Context, alert *models.Alert, agent agents.Agent, session *models.AlertSession) {
	as.logger.Info("Starting agent processing",
		zap.String("session_id", session.SessionID),
		zap.String("agent_type", agent.GetAgentType()))

	// Step 1: Update session status to in progress (matches Python)
	session.Status = string(models.AlertSessionStatusInProgress)
	if err := as.historyService.UpdateSession(ctx, session); err != nil {
		as.logger.Error("Failed to update session status", zap.Error(err))
		return
	}

	// Step 2: Download runbook content (matches Python workflow)
	var runbookContent string
	if alert.Runbook != "" {
		content, err := as.runbookService.DownloadRunbook(ctx, alert.Runbook)
		if err != nil {
			as.logger.Warn("Failed to download runbook, continuing without",
				zap.String("runbook_url", alert.Runbook),
				zap.Error(err))
			runbookContent = "Runbook download failed - proceeding with alert analysis only"
		} else {
			runbookContent = content
			as.logger.Info("Runbook downloaded successfully",
				zap.String("session_id", session.SessionID),
				zap.Int("content_length", len(content)))
		}
	}

	// Step 3: Create processing context for agent (simplified vs Python's complex ChainContext)
	processingCtx := &models.ChainContext{
		AlertType:      alert.AlertType,
		AlertData:      alert.Data,
		SessionID:      session.SessionID,
		RunbookContent: &runbookContent,
		// No stages - direct agent execution
	}

	// Step 4: Execute agent iterative analysis (CORE PYTHON BEHAVIOR)
	// This is where the agent uses LLM + MCP tools iteratively (up to 10 iterations)
	as.logger.Info("Starting agent iterative analysis",
		zap.String("session_id", session.SessionID),
		zap.String("agent_type", agent.GetAgentType()),
		zap.Strings("agent_capabilities", agent.GetCapabilities()),
		zap.Strings("mcp_servers", agent.MCPServers()))

	result, err := agent.ProcessAlert(ctx, alert, processingCtx)
	if err != nil {
		as.logger.Error("Agent processing failed",
			zap.String("session_id", session.SessionID),
			zap.String("agent_type", agent.GetAgentType()),
			zap.Error(err))
		as.markSessionFailed(ctx, session, fmt.Sprintf("Agent processing failed: %v", err))
		return
	}

	// Step 5: Store final analysis and mark session completed (matches Python)
	finalAnalysis := ""
	if result.FinalAnalysis != nil {
		finalAnalysis = *result.FinalAnalysis
	} else if result.ResultSummary != nil {
		finalAnalysis = *result.ResultSummary
	}

	session.FinalAnalysis = &finalAnalysis
	session.AgentType = agent.GetAgentType() // Ensure correct agent type is recorded

	// Step 6: Mark session as completed (matches Python)
	session.MarkCompleted()
	if err := as.historyService.UpdateSession(ctx, session); err != nil {
		as.logger.Error("Failed to mark session as completed", zap.Error(err))
	}

	as.logger.Info("Agent processing completed successfully",
		zap.String("session_id", session.SessionID),
		zap.String("agent_type", agent.GetAgentType()),
		zap.Int("analysis_length", len(finalAnalysis)))
}

// markSessionFailed marks a session as failed with an error message (matches Python)
func (as *AlertService) markSessionFailed(ctx context.Context, session *models.AlertSession, errorMessage string) {
	session.MarkFailed(errorMessage)
	if err := as.historyService.UpdateSession(ctx, session); err != nil {
		as.logger.Error("Failed to mark session as failed", zap.Error(err))
	}
}

// checkDuplicateAlert checks if an alert with the same key has been processed recently
func (as *AlertService) checkDuplicateAlert(ctx context.Context, alertKey models.AlertKey) (bool, error) {
	// Look for recent sessions with similar alert data
	var count int64
	result := as.db.WithContext(ctx).
		Model(&models.AlertSession{}).
		Where("alert_type = ? AND started_at_us > ?",
			alertKey.AlertType,
			time.Now().Add(-24*time.Hour).UnixMicro()).
		Count(&count)

	if result.Error != nil {
		return false, fmt.Errorf("duplicate check query failed: %w", result.Error)
	}

	// Simple duplicate detection - can be enhanced with better key comparison
	return count > 0, nil
}

// GetSessionStatus returns the current status of a processing session
func (as *AlertService) GetSessionStatus(ctx context.Context, sessionID string) (*models.AlertSession, error) {
	return as.historyService.GetSession(ctx, sessionID)
}

// ListActiveSessions returns all currently active processing sessions
func (as *AlertService) ListActiveSessions(ctx context.Context) ([]*models.AlertSession, error) {
	return as.historyService.ListActiveSessions(ctx)
}

// CancelSession attempts to cancel an active processing session
func (as *AlertService) CancelSession(ctx context.Context, sessionID string) error {
	session, err := as.historyService.GetSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}

	if !session.IsActive() {
		return fmt.Errorf("session is not active")
	}

	session.MarkFailed("Cancelled by user")
	return as.historyService.UpdateSession(ctx, session)
}

// GetServiceStatus returns comprehensive status information about the alert service
func (as *AlertService) GetServiceStatus(ctx context.Context) map[string]interface{} {
	activeSessions, _ := as.ListActiveSessions(ctx)

	agentStatus := as.agentRegistry.GetAgentStatus()

	return map[string]interface{}{
		"service_info": map[string]interface{}{
			"status":                "running",
			"max_concurrent_alerts": as.config.MaxConcurrentAlerts,
			"processing_timeout":    as.config.ProcessingTimeout.String(),
			"runbook_timeout":       as.config.RunbookTimeout.String(),
		},
		"active_sessions": len(activeSessions),
		"agent_registry":  agentStatus,
		"llm_integration": as.llmIntegrationService.GetProviderStatus(),
	}
}

// GetServiceMetrics returns performance and usage metrics
func (as *AlertService) GetServiceMetrics(ctx context.Context) (map[string]interface{}, error) {
	// Get history statistics
	historyStats, err := as.historyService.GetHistoryStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get history stats: %w", err)
	}

	// Get agent metrics
	agentMetrics := as.agentRegistry.GetAgentMetrics()

	// Get LLM provider status
	llmProviders := as.llmIntegrationService.GetAvailableProviders()

	metrics := map[string]interface{}{
		"alert_processing": historyStats,
		"agent_registry":   agentMetrics,
		"llm_providers":    llmProviders,
		"service_config": map[string]interface{}{
			"max_concurrent_alerts": as.config.MaxConcurrentAlerts,
			"processing_timeout":    as.config.ProcessingTimeout.String(),
			"runbook_timeout":       as.config.RunbookTimeout.String(),
		},
	}

	return metrics, nil
}

// ProcessAlertBatch processes multiple alerts concurrently
func (as *AlertService) ProcessAlertBatch(ctx context.Context, alerts []*models.Alert) ([]*models.AlertResponse, error) {
	if len(alerts) == 0 {
		return []*models.AlertResponse{}, nil
	}

	// Limit concurrent processing
	maxConcurrent := as.config.MaxConcurrentAlerts
	if len(alerts) < maxConcurrent {
		maxConcurrent = len(alerts)
	}

	as.logger.Info("Processing alert batch",
		zap.Int("total_alerts", len(alerts)),
		zap.Int("max_concurrent", maxConcurrent))

	responses := make([]*models.AlertResponse, len(alerts))
	semaphore := make(chan struct{}, maxConcurrent)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, alert := range alerts {
		wg.Add(1)
		go func(index int, alert *models.Alert) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			response, err := as.ProcessAlert(ctx, alert)

			mu.Lock()
			if err != nil {
				responses[index] = &models.AlertResponse{
					Status:  "error",
					Message: fmt.Sprintf("Failed to process alert: %v", err),
				}
			} else {
				responses[index] = response
			}
			mu.Unlock()
		}(i, alert)
	}

	wg.Wait()

	as.logger.Info("Alert batch processing completed",
		zap.Int("total_alerts", len(alerts)))

	return responses, nil
}

// ValidateAlert validates an alert structure before processing
func (as *AlertService) ValidateAlert(alert *models.Alert) error {
	if alert == nil {
		return fmt.Errorf("alert cannot be nil")
	}

	if alert.AlertType == "" {
		return fmt.Errorf("alert type is required")
	}

	if alert.Data == nil {
		return fmt.Errorf("alert data is required")
	}

	// Validate alert type is supported
	availableTypes := as.agentRegistry.GetAvailableAlertTypes()
	typeSupported := false
	for _, supportedType := range availableTypes {
		if supportedType == alert.AlertType {
			typeSupported = true
			break
		}
	}

	if !typeSupported {
		as.logger.Warn("Alert type not explicitly supported, will use fallback agent",
			zap.String("alert_type", alert.AlertType),
			zap.Strings("supported_types", availableTypes))
	}

	return nil
}

// GetSupportedAlertTypes returns all alert types that have dedicated agents
func (as *AlertService) GetSupportedAlertTypes() []string {
	return as.agentRegistry.GetAvailableAlertTypes()
}

// GetAgentForAlertType returns which agent would handle a specific alert type
func (as *AlertService) GetAgentForAlertType(alertType string) (string, error) {
	// Create a dummy alert to test agent selection
	testAlert := &models.Alert{
		AlertType: alertType,
		Data:      map[string]interface{}{"test": true},
	}

	agent, err := as.agentRegistry.GetAgentForAlert(testAlert)
	if err != nil {
		return "", err
	}

	return agent.GetAgentType(), nil
}

// CleanupOldSessions removes old completed/failed sessions
func (as *AlertService) CleanupOldSessions(ctx context.Context, retentionDays int) (int64, error) {
	as.logger.Info("Starting session cleanup",
		zap.Int("retention_days", retentionDays))

	deleted, err := as.historyService.CleanupOldSessionsEnhanced(ctx, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("cleanup failed: %w", err)
	}

	as.logger.Info("Session cleanup completed",
		zap.Int64("deleted_sessions", deleted),
		zap.Int("retention_days", retentionDays))

	return deleted, nil
}

// HealthCheck performs a comprehensive health check of the alert service
func (as *AlertService) HealthCheck(ctx context.Context) map[string]string {
	health := make(map[string]string)

	// Check database connectivity
	sqlDB, err := as.db.DB.DB()
	if err != nil {
		health["database"] = fmt.Sprintf("unhealthy: %v", err)
	} else if err := sqlDB.Ping(); err != nil {
		health["database"] = fmt.Sprintf("unhealthy: %v", err)
	} else {
		health["database"] = "healthy"
	}

	// Check agent registry
	agentHealth := as.agentRegistry.HealthCheck()
	allAgentsHealthy := true
	for _, status := range agentHealth {
		if status != "healthy" {
			allAgentsHealthy = false
			break
		}
	}
	if allAgentsHealthy {
		health["agent_registry"] = "healthy"
	} else {
		health["agent_registry"] = "degraded - some agents unhealthy"
	}

	// Check LLM integration
	llmHealth := as.llmIntegrationService.HealthCheck(ctx)
	allLLMHealthy := true
	for _, status := range llmHealth {
		if status != "healthy" {
			allLLMHealthy = false
			break
		}
	}
	if allLLMHealthy {
		health["llm_integration"] = "healthy"
	} else {
		health["llm_integration"] = "degraded - some providers unhealthy"
	}

	// Check history service
	if _, err := as.historyService.GetHistoryStats(ctx); err != nil {
		health["history_service"] = fmt.Sprintf("unhealthy: %v", err)
	} else {
		health["history_service"] = "healthy"
	}

	return health
}