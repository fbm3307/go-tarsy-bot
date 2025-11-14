package hooks

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/services"
)

// TypedLLMHistoryHook handles LLM interactions for database logging
// Receives unified LLMInteraction and stores it in the database
type TypedLLMHistoryHook struct {
	name           string
	historyService *services.HistoryService
	logger         *zap.Logger
}

// NewTypedLLMHistoryHook creates a new LLM history hook
func NewTypedLLMHistoryHook(historyService *services.HistoryService, logger *zap.Logger) BaseTypedHook[*models.LLMInteraction] {
	return &TypedLLMHistoryHook{
		name:           "typed_llm_history",
		historyService: historyService,
		logger:         logger,
	}
}

// GetName returns the hook name
func (h *TypedLLMHistoryHook) GetName() string {
	return h.name
}

// Execute stores LLM interaction in the database
func (h *TypedLLMHistoryHook) Execute(ctx context.Context, interaction *models.LLMInteraction) error {
	if interaction == nil {
		return fmt.Errorf("LLM interaction is nil")
	}

	h.logger.Debug("Executing LLM history hook",
		zap.String("interaction_id", interaction.InteractionID),
		zap.String("session_id", interaction.SessionID))

	// Set conversation content for WebSocket transmission
	interaction.SetConversationContent()

	// Create timeline interaction for database storage
	timelineInteraction := &models.TimelineInteraction{
		SessionID:        interaction.SessionID,
		Type:             models.InteractionTypeLLMRequest,
		Source:           "agent",
		Target:           interaction.ModelName,
		TimestampUs:      interaction.TimestampUs,
		Status:           models.InteractionStatusCompleted,
		StageExecutionID: interaction.StageExecutionID,
	}

	// Set content with interaction details
	content := map[string]interface{}{
		"interaction_id":       interaction.InteractionID,
		"model_name":           interaction.ModelName,
		"provider":             interaction.Provider,
		"temperature":          interaction.Temperature,
		"conversation_content": interaction.ConversationContent,
		"duration_ms":          interaction.DurationMs,
		"success":              interaction.Success,
		"error_message":        interaction.ErrorMessage,
	}

	// Add conversation object if available
	if interaction.Conversation != nil {
		content["conversation"] = interaction.Conversation
	}

	timelineInteraction.Content = models.JSONFromInterface(content)

	// Set token usage if available
	if interaction.InputTokens != nil && interaction.OutputTokens != nil {
		timelineInteraction.InputTokens = interaction.InputTokens
		timelineInteraction.OutputTokens = interaction.OutputTokens
		totalTokens := *interaction.InputTokens + *interaction.OutputTokens
		timelineInteraction.TotalTokens = &totalTokens
	}

	// Set cost if available
	if interaction.EstimatedCost != nil {
		timelineInteraction.EstimatedCost = interaction.EstimatedCost
	}

	// Update status based on success
	if !interaction.Success {
		timelineInteraction.Status = models.InteractionStatusFailed
	}

	// Store in database
	err := h.historyService.CreateTimelineInteraction(ctx, timelineInteraction)
	if err != nil {
		h.logger.Error("Failed to store LLM interaction in database",
			zap.String("interaction_id", interaction.InteractionID),
			zap.Error(err))
		return fmt.Errorf("failed to store LLM interaction: %w", err)
	}

	h.logger.Debug("Stored LLM interaction in database",
		zap.String("interaction_id", interaction.InteractionID))

	return nil
}

// TypedMCPHistoryHook handles MCP interactions for database logging
// Receives unified MCPInteraction and stores it in the database
type TypedMCPHistoryHook struct {
	name           string
	historyService *services.HistoryService
	logger         *zap.Logger
}

// NewTypedMCPHistoryHook creates a new MCP history hook
func NewTypedMCPHistoryHook(historyService *services.HistoryService, logger *zap.Logger) BaseTypedHook[*models.MCPInteraction] {
	return &TypedMCPHistoryHook{
		name:           "typed_mcp_history",
		historyService: historyService,
		logger:         logger,
	}
}

// GetName returns the hook name
func (h *TypedMCPHistoryHook) GetName() string {
	return h.name
}

// Execute stores MCP interaction in the database
func (h *TypedMCPHistoryHook) Execute(ctx context.Context, interaction *models.MCPInteraction) error {
	if interaction == nil {
		return fmt.Errorf("MCP interaction is nil")
	}

	h.logger.Debug("Executing MCP history hook",
		zap.String("communication_id", interaction.CommunicationID),
		zap.String("session_id", interaction.SessionID))

	// Create timeline interaction for database storage
	timelineInteraction := &models.TimelineInteraction{
		SessionID:        interaction.SessionID,
		Type:             models.InteractionTypeMCPCall,
		Source:           "agent",
		Target:           interaction.ServerName,
		TimestampUs:      interaction.TimestampUs,
		Status:           models.InteractionStatusCompleted,
		StageExecutionID: interaction.StageExecutionID,
	}

	// Set content with interaction details
	content := map[string]interface{}{
		"communication_id":   interaction.CommunicationID,
		"request_id":         interaction.RequestID,
		"server_name":        interaction.ServerName,
		"tool_name":          interaction.ToolName,
		"communication_type": interaction.CommunicationType,
		"step_description":   interaction.StepDescription,
		"tool_arguments":     interaction.ToolArguments,
		"tool_result":        interaction.ToolResult,
		"duration_ms":        interaction.DurationMs,
		"success":            interaction.Success,
		"error_message":      interaction.ErrorMessage,
	}

	// Add request/response for debugging if available
	if interaction.Request != nil {
		content["request"] = interaction.Request
	}
	if interaction.Response != nil {
		content["response"] = interaction.Response
	}

	timelineInteraction.Content = models.JSONFromInterface(content)

	// Update status based on success
	if !interaction.Success {
		timelineInteraction.Status = models.InteractionStatusFailed
	}

	// Store in database
	err := h.historyService.CreateTimelineInteraction(ctx, timelineInteraction)
	if err != nil {
		h.logger.Error("Failed to store MCP interaction in database",
			zap.String("communication_id", interaction.CommunicationID),
			zap.Error(err))
		return fmt.Errorf("failed to store MCP interaction: %w", err)
	}

	h.logger.Debug("Stored MCP interaction in database",
		zap.String("communication_id", interaction.CommunicationID))

	return nil
}

// TypedStageExecutionHistoryHook handles stage execution events for database logging
type TypedStageExecutionHistoryHook struct {
	name           string
	historyService *services.HistoryService
	logger         *zap.Logger
}

// NewTypedStageExecutionHistoryHook creates a new stage execution history hook
func NewTypedStageExecutionHistoryHook(historyService *services.HistoryService, logger *zap.Logger) BaseTypedHook[*models.StageExecution] {
	return &TypedStageExecutionHistoryHook{
		name:           "typed_stage_execution_history",
		historyService: historyService,
		logger:         logger,
	}
}

// GetName returns the hook name
func (h *TypedStageExecutionHistoryHook) GetName() string {
	return h.name
}

// Execute stores stage execution in the database
func (h *TypedStageExecutionHistoryHook) Execute(ctx context.Context, stageExecution *models.StageExecution) error {
	if stageExecution == nil {
		return fmt.Errorf("stage execution is nil")
	}

	h.logger.Debug("Executing stage execution history hook",
		zap.String("execution_id", stageExecution.ExecutionID),
		zap.String("session_id", stageExecution.SessionID))

	// Check if stage execution already exists
	existingStage, err := h.historyService.GetSession(ctx, stageExecution.SessionID)
	if err != nil {
		h.logger.Warn("Could not check existing stage execution", zap.Error(err))
	}

	// Store or update stage execution
	if existingStage != nil {
		// Update existing stage execution
		err = h.historyService.UpdateStageExecution(ctx, stageExecution)
	} else {
		// Create new stage execution
		err = h.historyService.CreateStageExecution(ctx, stageExecution)
	}

	if err != nil {
		h.logger.Error("Failed to store stage execution in database",
			zap.String("execution_id", stageExecution.ExecutionID),
			zap.Error(err))
		return fmt.Errorf("failed to store stage execution: %w", err)
	}

	// Create timeline interaction for stage events
	interactionType := models.InteractionTypeStageStart
	description := fmt.Sprintf("Started stage: %s", stageExecution.StageName)

	if stageExecution.IsCompleted() {
		interactionType = models.InteractionTypeStageComplete
		description = fmt.Sprintf("Completed stage: %s", stageExecution.StageName)
	} else if stageExecution.IsFailed() {
		interactionType = models.InteractionTypeStageComplete
		description = fmt.Sprintf("Failed stage: %s", stageExecution.StageName)
	}

	timelineInteraction := &models.TimelineInteraction{
		SessionID:        stageExecution.SessionID,
		Type:             interactionType,
		Source:           "stage_controller",
		TimestampUs:      models.GetCurrentTimestampUs(),
		Status:           models.InteractionStatusCompleted,
		StageExecutionID: &stageExecution.ExecutionID,
	}

	// Set content with stage execution details
	content := map[string]interface{}{
		"execution_id":   stageExecution.ExecutionID,
		"stage_id":       stageExecution.StageID,
		"stage_name":     stageExecution.StageName,
		"stage_index":    stageExecution.StageIndex,
		"agent":          stageExecution.Agent,
		"status":         string(stageExecution.Status),
		"description":    description,
		"duration_ms":    stageExecution.DurationMs,
		"error_message":  stageExecution.ErrorMessage,
	}

	timelineInteraction.Content = models.JSONFromInterface(content)

	// Store stage event in timeline
	err = h.historyService.CreateTimelineInteraction(ctx, timelineInteraction)
	if err != nil {
		h.logger.Warn("Failed to store stage timeline interaction",
			zap.String("execution_id", stageExecution.ExecutionID),
			zap.Error(err))
		// Don't return error for timeline interactions
	}

	h.logger.Debug("Stored stage execution in database",
		zap.String("execution_id", stageExecution.ExecutionID),
		zap.String("status", string(stageExecution.Status)))

	return nil
}

// Batch hook for multiple MCP interactions (matching Python implementation)

// TypedMCPListHistoryHook handles batched MCP tool list interactions for database logging
type TypedMCPListHistoryHook struct {
	name           string
	historyService *services.HistoryService
	logger         *zap.Logger
}

// NewTypedMCPListHistoryHook creates a new MCP list history hook
func NewTypedMCPListHistoryHook(historyService *services.HistoryService, logger *zap.Logger) BaseTypedHook[[]*models.MCPInteraction] {
	return &TypedMCPListHistoryHook{
		name:           "typed_mcp_list_history",
		historyService: historyService,
		logger:         logger,
	}
}

// GetName returns the hook name
func (h *TypedMCPListHistoryHook) GetName() string {
	return h.name
}

// Execute stores multiple MCP interactions in the database in a batch
func (h *TypedMCPListHistoryHook) Execute(ctx context.Context, interactions []*models.MCPInteraction) error {
	if len(interactions) == 0 {
		return nil
	}

	h.logger.Debug("Executing MCP list history hook",
		zap.Int("interaction_count", len(interactions)))

	// Convert to timeline interactions
	var timelineInteractions []*models.TimelineInteraction

	for _, interaction := range interactions {
		if interaction == nil {
			continue
		}

		// Create timeline interaction for database storage
		timelineInteraction := &models.TimelineInteraction{
			SessionID:        interaction.SessionID,
			Type:             models.InteractionTypeMCPCall,
			Source:           "agent",
			Target:           interaction.ServerName,
			TimestampUs:      interaction.TimestampUs,
			Status:           models.InteractionStatusCompleted,
			StageExecutionID: interaction.StageExecutionID,
		}

		// Set content with interaction details
		content := map[string]interface{}{
			"communication_id":   interaction.CommunicationID,
			"request_id":         interaction.RequestID,
			"server_name":        interaction.ServerName,
			"tool_name":          interaction.ToolName,
			"communication_type": interaction.CommunicationType,
			"step_description":   interaction.StepDescription,
			"success":            interaction.Success,
			"duration_ms":        interaction.DurationMs,
			"batch_type":         "mcp_list",
		}

		timelineInteraction.Content = models.JSONFromInterface(content)

		// Update status based on success
		if !interaction.Success {
			timelineInteraction.Status = models.InteractionStatusFailed
		}

		timelineInteractions = append(timelineInteractions, timelineInteraction)
	}

	// Store batch in database
	if len(timelineInteractions) > 0 {
		err := h.historyService.CreateTimelineInteractionsBatch(ctx, timelineInteractions)
		if err != nil {
			h.logger.Error("Failed to store MCP interaction batch in database",
				zap.Int("interaction_count", len(timelineInteractions)),
				zap.Error(err))
			return fmt.Errorf("failed to store MCP interaction batch: %w", err)
		}
	}

	h.logger.Debug("Stored MCP interaction batch in database",
		zap.Int("interaction_count", len(timelineInteractions)))

	return nil
}