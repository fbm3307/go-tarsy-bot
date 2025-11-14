package hooks

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/services"
)

// TypedLLMDashboardHook handles LLM interactions for dashboard broadcasting
// Receives unified LLMInteraction and broadcasts it to WebSocket clients
type TypedLLMDashboardHook struct {
	name                string
	dashboardBroadcaster *services.DashboardBroadcaster
	logger              *zap.Logger
}

// NewTypedLLMDashboardHook creates a new LLM dashboard hook
func NewTypedLLMDashboardHook(dashboardBroadcaster *services.DashboardBroadcaster, logger *zap.Logger) BaseTypedHook[*models.LLMInteraction] {
	return &TypedLLMDashboardHook{
		name:                "typed_llm_dashboard",
		dashboardBroadcaster: dashboardBroadcaster,
		logger:              logger,
	}
}

// GetName returns the hook name
func (h *TypedLLMDashboardHook) GetName() string {
	return h.name
}

// Execute broadcasts LLM interaction to dashboard with content truncation
func (h *TypedLLMDashboardHook) Execute(ctx context.Context, interaction *models.LLMInteraction) error {
	if interaction == nil {
		return fmt.Errorf("LLM interaction is nil")
	}

	h.logger.Debug("Executing LLM dashboard hook",
		zap.String("interaction_id", interaction.InteractionID),
		zap.String("session_id", interaction.SessionID))

	// Apply content truncation before WebSocket broadcast if needed
	truncatedInteraction := ApplyLLMInteractionTruncation(interaction)

	// Create dashboard update with complete conversation object
	updateData := map[string]interface{}{
		"type":                "llm_interaction",
		"session_id":          truncatedInteraction.SessionID,
		"interaction_id":      truncatedInteraction.InteractionID,
		"model_name":          truncatedInteraction.ModelName,
		"provider":            truncatedInteraction.Provider,
		"step_description":    truncatedInteraction.GetStepDescription(),
		"conversation_content": truncatedInteraction.ConversationContent,
		"success":             truncatedInteraction.Success,
		"error_message":       truncatedInteraction.ErrorMessage,
		"duration_ms":         truncatedInteraction.DurationMs,
		"timestamp_us":        truncatedInteraction.TimestampUs,
		"input_tokens":        truncatedInteraction.InputTokens,
		"output_tokens":       truncatedInteraction.OutputTokens,
		"total_tokens":        truncatedInteraction.TotalTokens,
		"estimated_cost":      truncatedInteraction.EstimatedCost,
	}

	// Add stage execution ID for enhanced dashboard visualization
	if truncatedInteraction.StageExecutionID != nil {
		updateData["stage_execution_id"] = *truncatedInteraction.StageExecutionID
	}

	// Send complete conversation object if available
	if truncatedInteraction.Conversation != nil {
		updateData["conversation"] = truncatedInteraction.Conversation
	}

	// Broadcast to dashboard
	_, err := h.dashboardBroadcaster.BroadcastInteractionUpdate(
		truncatedInteraction.SessionID,
		updateData,
		nil, // No excluded users
	)

	if err != nil {
		h.logger.Error("Failed to broadcast LLM interaction to dashboard",
			zap.String("interaction_id", interaction.InteractionID),
			zap.Error(err))
		return fmt.Errorf("failed to broadcast LLM interaction to dashboard: %w", err)
	}

	h.logger.Debug("Broadcasted LLM interaction to dashboard",
		zap.String("interaction_id", interaction.InteractionID))

	return nil
}

// TypedMCPDashboardHook handles MCP tool interactions for dashboard broadcasting
// Receives unified MCPInteraction and broadcasts it to WebSocket clients
type TypedMCPDashboardHook struct {
	name                string
	dashboardBroadcaster *services.DashboardBroadcaster
	logger              *zap.Logger
}

// NewTypedMCPDashboardHook creates a new MCP dashboard hook
func NewTypedMCPDashboardHook(dashboardBroadcaster *services.DashboardBroadcaster, logger *zap.Logger) BaseTypedHook[*models.MCPInteraction] {
	return &TypedMCPDashboardHook{
		name:                "typed_mcp_dashboard",
		dashboardBroadcaster: dashboardBroadcaster,
		logger:              logger,
	}
}

// GetName returns the hook name
func (h *TypedMCPDashboardHook) GetName() string {
	return h.name
}

// Execute broadcasts MCP interaction to dashboard
func (h *TypedMCPDashboardHook) Execute(ctx context.Context, interaction *models.MCPInteraction) error {
	if interaction == nil {
		return fmt.Errorf("MCP interaction is nil")
	}

	h.logger.Debug("Executing MCP dashboard hook",
		zap.String("communication_id", interaction.CommunicationID),
		zap.String("session_id", interaction.SessionID))

	// Create dashboard update from typed interaction
	updateData := map[string]interface{}{
		"type":                "mcp_interaction",
		"session_id":          interaction.SessionID,
		"request_id":          interaction.RequestID,
		"communication_id":    interaction.CommunicationID,
		"server_name":         interaction.ServerName,
		"tool_name":           interaction.ToolName,
		"communication_type":  interaction.CommunicationType,
		"step_description":    interaction.GetStepDescription(),
		"tool_arguments":      interaction.ToolArguments,
		"tool_result":         interaction.ToolResult,
		"success":             interaction.Success,
		"error_message":       interaction.ErrorMessage,
		"duration_ms":         interaction.DurationMs,
		"timestamp_us":        interaction.TimestampUs,
	}

	// Add stage execution ID for enhanced dashboard visualization
	if interaction.StageExecutionID != nil {
		updateData["stage_execution_id"] = *interaction.StageExecutionID
	}

	// Add request/response for debugging if available
	if interaction.Request != nil {
		updateData["request"] = interaction.Request
	}
	if interaction.Response != nil {
		updateData["response"] = interaction.Response
	}

	// Broadcast to dashboard
	_, err := h.dashboardBroadcaster.BroadcastInteractionUpdate(
		interaction.SessionID,
		updateData,
		nil, // No excluded users
	)

	if err != nil {
		h.logger.Error("Failed to broadcast MCP interaction to dashboard",
			zap.String("communication_id", interaction.CommunicationID),
			zap.Error(err))
		return fmt.Errorf("failed to broadcast MCP interaction to dashboard: %w", err)
	}

	h.logger.Debug("Broadcasted MCP interaction to dashboard",
		zap.String("communication_id", interaction.CommunicationID))

	return nil
}

// TypedStageExecutionDashboardHook handles stage execution events for dashboard broadcasting
type TypedStageExecutionDashboardHook struct {
	name                string
	dashboardBroadcaster *services.DashboardBroadcaster
	logger              *zap.Logger
}

// NewTypedStageExecutionDashboardHook creates a new stage execution dashboard hook
func NewTypedStageExecutionDashboardHook(dashboardBroadcaster *services.DashboardBroadcaster, logger *zap.Logger) BaseTypedHook[*models.StageExecution] {
	return &TypedStageExecutionDashboardHook{
		name:                "typed_stage_execution_dashboard",
		dashboardBroadcaster: dashboardBroadcaster,
		logger:              logger,
	}
}

// GetName returns the hook name
func (h *TypedStageExecutionDashboardHook) GetName() string {
	return h.name
}

// Execute broadcasts stage execution progress to dashboard
func (h *TypedStageExecutionDashboardHook) Execute(ctx context.Context, stageExecution *models.StageExecution) error {
	if stageExecution == nil {
		return fmt.Errorf("stage execution is nil")
	}

	h.logger.Debug("Executing stage execution dashboard hook",
		zap.String("execution_id", stageExecution.ExecutionID),
		zap.String("session_id", stageExecution.SessionID))

	// Determine error message
	errorMessage := ""
	if stageExecution.ErrorMessage != nil {
		errorMessage = *stageExecution.ErrorMessage
	}

	// Convert string status to StageStatus type
	status := models.StageStatus(stageExecution.Status)

	// Broadcast stage progress update
	_, err := h.dashboardBroadcaster.BroadcastStageProgressUpdate(
		stageExecution.SessionID,
		"", // ChainID - will be derived from session if needed
		stageExecution.ExecutionID,
		stageExecution.StageID,
		stageExecution.StageName,
		stageExecution.StageIndex,
		stageExecution.Agent,
		status,
		stageExecution.StartedAtUs,
		stageExecution.CompletedAtUs,
		stageExecution.DurationMs,
		errorMessage,
		nil, // No excluded users
	)

	if err != nil {
		h.logger.Error("Failed to broadcast stage execution to dashboard",
			zap.String("execution_id", stageExecution.ExecutionID),
			zap.Error(err))
		return fmt.Errorf("failed to broadcast stage execution to dashboard: %w", err)
	}

	h.logger.Debug("Broadcasted stage execution to dashboard",
		zap.String("execution_id", stageExecution.ExecutionID),
		zap.String("status", string(stageExecution.Status)))

	return nil
}

// Batch hook for multiple interactions (matching Python implementation)

// TypedMCPListDashboardHook handles batched MCP tool list interactions
type TypedMCPListDashboardHook struct {
	name                string
	dashboardBroadcaster *services.DashboardBroadcaster
	logger              *zap.Logger
}

// NewTypedMCPListDashboardHook creates a new MCP list dashboard hook
func NewTypedMCPListDashboardHook(dashboardBroadcaster *services.DashboardBroadcaster, logger *zap.Logger) BaseTypedHook[[]*models.MCPInteraction] {
	return &TypedMCPListDashboardHook{
		name:                "typed_mcp_list_dashboard",
		dashboardBroadcaster: dashboardBroadcaster,
		logger:              logger,
	}
}

// GetName returns the hook name
func (h *TypedMCPListDashboardHook) GetName() string {
	return h.name
}

// Execute broadcasts multiple MCP interactions to dashboard in a batch
func (h *TypedMCPListDashboardHook) Execute(ctx context.Context, interactions []*models.MCPInteraction) error {
	if len(interactions) == 0 {
		return nil
	}

	h.logger.Debug("Executing MCP list dashboard hook",
		zap.Int("interaction_count", len(interactions)))

	// Process each interaction
	for _, interaction := range interactions {
		if interaction == nil {
			continue
		}

		// Create dashboard update from typed interaction
		updateData := map[string]interface{}{
			"type":               "mcp_interaction_batch",
			"session_id":         interaction.SessionID,
			"request_id":         interaction.RequestID,
			"communication_id":   interaction.CommunicationID,
			"server_name":        interaction.ServerName,
			"tool_name":          interaction.ToolName,
			"communication_type": interaction.CommunicationType,
			"step_description":   interaction.GetStepDescription(),
			"success":            interaction.Success,
			"error_message":      interaction.ErrorMessage,
			"duration_ms":        interaction.DurationMs,
			"timestamp_us":       interaction.TimestampUs,
		}

		// Add stage execution ID for enhanced dashboard visualization
		if interaction.StageExecutionID != nil {
			updateData["stage_execution_id"] = *interaction.StageExecutionID
		}

		// Broadcast to dashboard (each interaction separately for now)
		_, err := h.dashboardBroadcaster.BroadcastInteractionUpdate(
			interaction.SessionID,
			updateData,
			nil, // No excluded users
		)

		if err != nil {
			h.logger.Warn("Failed to broadcast MCP interaction in batch",
				zap.String("communication_id", interaction.CommunicationID),
				zap.Error(err))
		}
	}

	h.logger.Debug("Broadcasted MCP interaction batch to dashboard",
		zap.Int("interaction_count", len(interactions)))

	return nil
}