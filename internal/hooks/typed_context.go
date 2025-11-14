package hooks

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/models"
)

// Content truncation constants (matching Python)
const (
	MaxLLMContentLength = 2000 // Maximum content length for LLM interactions in WebSocket broadcasts
)

// BaseTypedHook represents the base interface for all typed hooks
type BaseTypedHook[T any] interface {
	GetName() string
	Execute(ctx context.Context, data T) error
}

// TypedHook is a concrete implementation of BaseTypedHook
type TypedHook[T any] struct {
	name    string
	handler func(ctx context.Context, data T) error
	logger  *zap.Logger
}

// NewTypedHook creates a new typed hook
func NewTypedHook[T any](name string, handler func(ctx context.Context, data T) error, logger *zap.Logger) *TypedHook[T] {
	return &TypedHook[T]{
		name:    name,
		handler: handler,
		logger:  logger,
	}
}

// GetName returns the hook name
func (th *TypedHook[T]) GetName() string {
	return th.name
}

// Execute executes the hook with the provided data
func (th *TypedHook[T]) Execute(ctx context.Context, data T) error {
	th.logger.Debug("Executing typed hook", zap.String("hook_name", th.name))

	if th.handler == nil {
		return fmt.Errorf("hook handler is nil for hook: %s", th.name)
	}

	return th.handler(ctx, data)
}

// TypedHookManager manages typed hooks with generic type safety
type TypedHookManager struct {
	hooks  map[string]interface{} // map[hookName]BaseTypedHook[T]
	logger *zap.Logger
	mu     sync.RWMutex
}

// NewTypedHookManager creates a new typed hook manager
func NewTypedHookManager(logger *zap.Logger) *TypedHookManager {
	return &TypedHookManager{
		hooks:  make(map[string]interface{}),
		logger: logger,
	}
}

// RegisterHook registers a typed hook
func (thm *TypedHookManager) RegisterHook(name string, hook interface{}) error {
	thm.mu.Lock()
	defer thm.mu.Unlock()

	if _, exists := thm.hooks[name]; exists {
		return fmt.Errorf("hook with name '%s' already registered", name)
	}

	thm.hooks[name] = hook
	thm.logger.Debug("Registered typed hook", zap.String("hook_name", name))

	return nil
}

// ExecuteHook executes a typed hook with the provided data
func (thm *TypedHookManager) ExecuteHook(ctx context.Context, name string, data interface{}) error {
	thm.mu.RLock()
	hook, exists := thm.hooks[name]
	thm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("hook with name '%s' not found", name)
	}

	// Type assertion to execute the hook
	switch h := hook.(type) {
	case BaseTypedHook[*models.LLMInteraction]:
		if llmData, ok := data.(*models.LLMInteraction); ok {
			return h.Execute(ctx, llmData)
		}
	case BaseTypedHook[*models.MCPInteraction]:
		if mcpData, ok := data.(*models.MCPInteraction); ok {
			return h.Execute(ctx, mcpData)
		}
	case BaseTypedHook[*models.StageExecution]:
		if stageData, ok := data.(*models.StageExecution); ok {
			return h.Execute(ctx, stageData)
		}
	default:
		return fmt.Errorf("unsupported hook type for hook '%s'", name)
	}

	return fmt.Errorf("data type mismatch for hook '%s'", name)
}

// GetHook retrieves a hook by name
func (thm *TypedHookManager) GetHook(name string) (interface{}, bool) {
	thm.mu.RLock()
	defer thm.mu.RUnlock()

	hook, exists := thm.hooks[name]
	return hook, exists
}

// ListHooks returns a list of all registered hook names
func (thm *TypedHookManager) ListHooks() []string {
	thm.mu.RLock()
	defer thm.mu.RUnlock()

	var names []string
	for name := range thm.hooks {
		names = append(names, name)
	}
	return names
}

// GetStats returns statistics about the hook manager
func (thm *TypedHookManager) GetStats() map[string]interface{} {
	thm.mu.RLock()
	defer thm.mu.RUnlock()

	return map[string]interface{}{
		"total_hooks": len(thm.hooks),
		"hook_names":  thm.ListHooks(),
	}
}

// Shutdown gracefully shuts down the hook manager
func (thm *TypedHookManager) Shutdown() error {
	thm.mu.Lock()
	defer thm.mu.Unlock()

	thm.logger.Info("Shutting down typed hook manager", zap.Int("total_hooks", len(thm.hooks)))

	// Clear all hooks
	thm.hooks = make(map[string]interface{})

	return nil
}

// Global typed hook manager instance
var globalTypedHookManager *TypedHookManager
var globalTypedHookManagerOnce sync.Once

// GetTypedHookManager returns the global typed hook manager instance
func GetTypedHookManager() *TypedHookManager {
	globalTypedHookManagerOnce.Do(func() {
		// Create a basic logger if none provided
		logger, _ := zap.NewDevelopment()
		globalTypedHookManager = NewTypedHookManager(logger)
	})
	return globalTypedHookManager
}

// SetTypedHookManager sets the global typed hook manager (for testing)
func SetTypedHookManager(manager *TypedHookManager) {
	globalTypedHookManager = manager
}

// Content truncation helper functions (matching Python implementation)

// ApplyLLMInteractionTruncation applies content truncation before WebSocket broadcast
func ApplyLLMInteractionTruncation(interaction *models.LLMInteraction) *models.LLMInteraction {
	if interaction == nil {
		return interaction
	}

	// Create a copy to avoid modifying the original
	truncated := *interaction

	// Truncate conversation content if it's too long
	if len(interaction.ConversationContent) > MaxLLMContentLength {
		truncated.ConversationContent = truncateWithEllipsis(interaction.ConversationContent, MaxLLMContentLength)
	}

	return &truncated
}

// truncateWithEllipsis truncates content to maxLength and adds ellipsis
func truncateWithEllipsis(content string, maxLength int) string {
	if len(content) <= maxLength {
		return content
	}

	if maxLength < 3 {
		return content[:maxLength]
	}

	return content[:maxLength-3] + "..."
}

// Helper functions for hook execution

// ExecuteLLMHook executes all registered LLM hooks
func ExecuteLLMHook(ctx context.Context, interaction *models.LLMInteraction) error {
	manager := GetTypedHookManager()

	// Execute history hook
	if err := manager.ExecuteHook(ctx, "typed_llm_history", interaction); err != nil {
		manager.logger.Warn("LLM history hook failed", zap.Error(err))
	}

	// Execute dashboard hook
	if err := manager.ExecuteHook(ctx, "typed_llm_dashboard", interaction); err != nil {
		manager.logger.Warn("LLM dashboard hook failed", zap.Error(err))
	}

	return nil
}

// ExecuteMCPHook executes all registered MCP hooks
func ExecuteMCPHook(ctx context.Context, interaction *models.MCPInteraction) error {
	manager := GetTypedHookManager()

	// Execute history hook
	if err := manager.ExecuteHook(ctx, "typed_mcp_history", interaction); err != nil {
		manager.logger.Warn("MCP history hook failed", zap.Error(err))
	}

	// Execute dashboard hook
	if err := manager.ExecuteHook(ctx, "typed_mcp_dashboard", interaction); err != nil {
		manager.logger.Warn("MCP dashboard hook failed", zap.Error(err))
	}

	return nil
}

// ExecuteStageExecutionHook executes all registered stage execution hooks
func ExecuteStageExecutionHook(ctx context.Context, stageExecution *models.StageExecution) error {
	manager := GetTypedHookManager()

	// Execute history hook
	if err := manager.ExecuteHook(ctx, "typed_stage_execution_history", stageExecution); err != nil {
		manager.logger.Warn("Stage execution history hook failed", zap.Error(err))
	}

	// Execute dashboard hook
	if err := manager.ExecuteHook(ctx, "typed_stage_execution_dashboard", stageExecution); err != nil {
		manager.logger.Warn("Stage execution dashboard hook failed", zap.Error(err))
	}

	return nil
}

// Interaction type detection helpers

// IsLLMInteractionType checks if a string represents an LLM interaction type
func IsLLMInteractionType(interactionType string) bool {
	llmTypes := []string{
		models.InteractionTypeLLMRequest,
		"llm_completion",
		"llm_chat",
		"llm_analysis",
	}

	for _, t := range llmTypes {
		if strings.EqualFold(interactionType, t) {
			return true
		}
	}
	return false
}

// IsMCPInteractionType checks if a string represents an MCP interaction type
func IsMCPInteractionType(interactionType string) bool {
	mcpTypes := []string{
		models.InteractionTypeMCPCall,
		"mcp_tool_call",
		"mcp_list_tools",
		"mcp_communication",
	}

	for _, t := range mcpTypes {
		if strings.EqualFold(interactionType, t) {
			return true
		}
	}
	return false
}

// IsStageInteractionType checks if a string represents a stage interaction type
func IsStageInteractionType(interactionType string) bool {
	stageTypes := []string{
		models.InteractionTypeStageStart,
		models.InteractionTypeStageComplete,
		"stage_execution",
		"stage_progress",
	}

	for _, t := range stageTypes {
		if strings.EqualFold(interactionType, t) {
			return true
		}
	}
	return false
}