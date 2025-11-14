package hooks

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/services"
)

// TypedHookRegistry manages initialization and registration of all typed hooks
// with their required service dependencies. This matches the Python implementation.
type TypedHookRegistry struct {
	typedHookManager *TypedHookManager
	logger           *zap.Logger
	initialized      bool
}

// NewTypedHookRegistry creates a new typed hook registry
func NewTypedHookRegistry(logger *zap.Logger) *TypedHookRegistry {
	return &TypedHookRegistry{
		typedHookManager: GetTypedHookManager(),
		logger:           logger,
		initialized:      false,
	}
}

// InitializeHooks initializes and registers all typed hooks
func (thr *TypedHookRegistry) InitializeHooks(ctx context.Context, historyService *services.HistoryService, dashboardBroadcaster *services.DashboardBroadcaster) error {
	if thr.initialized {
		thr.logger.Warn("Hook registry already initialized")
		return nil
	}

	thr.logger.Info("Initializing typed hook registry")

	// Register history hooks
	if err := thr.registerHistoryHooks(historyService); err != nil {
		return fmt.Errorf("failed to register history hooks: %w", err)
	}

	// Register dashboard hooks
	if err := thr.registerDashboardHooks(dashboardBroadcaster); err != nil {
		return fmt.Errorf("failed to register dashboard hooks: %w", err)
	}

	thr.initialized = true
	thr.logger.Info("Typed hook registry initialized successfully")

	return nil
}

// registerHistoryHooks registers all history-related hooks
func (thr *TypedHookRegistry) registerHistoryHooks(historyService *services.HistoryService) error {
	thr.logger.Debug("Registering history hooks")

	// Register LLM History Hook
	llmHistoryHook := NewTypedLLMHistoryHook(historyService, thr.logger)
	if err := thr.typedHookManager.RegisterHook("typed_llm_history", llmHistoryHook); err != nil {
		return fmt.Errorf("failed to register LLM history hook: %w", err)
	}

	// Register MCP History Hook
	mcpHistoryHook := NewTypedMCPHistoryHook(historyService, thr.logger)
	if err := thr.typedHookManager.RegisterHook("typed_mcp_history", mcpHistoryHook); err != nil {
		return fmt.Errorf("failed to register MCP history hook: %w", err)
	}

	// Register Stage Execution History Hook
	stageHistoryHook := NewTypedStageExecutionHistoryHook(historyService, thr.logger)
	if err := thr.typedHookManager.RegisterHook("typed_stage_execution_history", stageHistoryHook); err != nil {
		return fmt.Errorf("failed to register stage execution history hook: %w", err)
	}

	thr.logger.Debug("History hooks registered successfully")
	return nil
}

// registerDashboardHooks registers all dashboard-related hooks
func (thr *TypedHookRegistry) registerDashboardHooks(dashboardBroadcaster *services.DashboardBroadcaster) error {
	thr.logger.Debug("Registering dashboard hooks")

	// Register LLM Dashboard Hook
	llmDashboardHook := NewTypedLLMDashboardHook(dashboardBroadcaster, thr.logger)
	if err := thr.typedHookManager.RegisterHook("typed_llm_dashboard", llmDashboardHook); err != nil {
		return fmt.Errorf("failed to register LLM dashboard hook: %w", err)
	}

	// Register MCP Dashboard Hook
	mcpDashboardHook := NewTypedMCPDashboardHook(dashboardBroadcaster, thr.logger)
	if err := thr.typedHookManager.RegisterHook("typed_mcp_dashboard", mcpDashboardHook); err != nil {
		return fmt.Errorf("failed to register MCP dashboard hook: %w", err)
	}

	// Register Stage Execution Dashboard Hook
	stageDashboardHook := NewTypedStageExecutionDashboardHook(dashboardBroadcaster, thr.logger)
	if err := thr.typedHookManager.RegisterHook("typed_stage_execution_dashboard", stageDashboardHook); err != nil {
		return fmt.Errorf("failed to register stage execution dashboard hook: %w", err)
	}

	thr.logger.Debug("Dashboard hooks registered successfully")
	return nil
}

// IsInitialized returns whether the hook registry has been initialized
func (thr *TypedHookRegistry) IsInitialized() bool {
	return thr.initialized
}

// GetTypedHookManager returns the underlying typed hook manager
func (thr *TypedHookRegistry) GetTypedHookManager() *TypedHookManager {
	return thr.typedHookManager
}

// GetHookStats returns statistics about registered hooks
func (thr *TypedHookRegistry) GetHookStats() map[string]interface{} {
	stats := thr.typedHookManager.GetStats()
	stats["initialized"] = thr.initialized
	return stats
}

// Shutdown gracefully shuts down the hook registry
func (thr *TypedHookRegistry) Shutdown() error {
	thr.logger.Info("Shutting down typed hook registry")

	// The hook manager will handle cleanup of individual hooks
	err := thr.typedHookManager.Shutdown()
	if err != nil {
		thr.logger.Error("Error shutting down typed hook manager", zap.Error(err))
		return err
	}

	thr.initialized = false
	thr.logger.Info("Typed hook registry shutdown complete")
	return nil
}

// Global registry instance (matching Python pattern)
var globalTypedHookRegistry *TypedHookRegistry

// GetTypedHookRegistry returns the global typed hook registry instance
func GetTypedHookRegistry(logger *zap.Logger) *TypedHookRegistry {
	if globalTypedHookRegistry == nil {
		globalTypedHookRegistry = NewTypedHookRegistry(logger)
	}
	return globalTypedHookRegistry
}