package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/codeready/go-tarsy-bot/internal/integrations/llm"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
	"go.uber.org/zap"
)

// LLMService provides a unified interface for LLM operations with MCP tool integration
type LLMService struct {
	llmRegistry *llm.LLMClientRegistry
	mcpRegistry *mcp.MCPClientRegistry
	logger      *zap.Logger
	mutex       sync.RWMutex

	// Configuration
	defaultLLMClient string
	defaultTimeout   time.Duration
	enableToolUse    bool
}

// LLMServiceConfig represents configuration for the LLM service
type LLMServiceConfig struct {
	DefaultLLMClient string        `json:"default_llm_client" yaml:"default_llm_client"`
	DefaultTimeout   time.Duration `json:"default_timeout" yaml:"default_timeout"`
	EnableToolUse    bool          `json:"enable_tool_use" yaml:"enable_tool_use"`
}

// GenerateWithToolsRequest extends the basic generate request with tool capabilities
type GenerateWithToolsRequest struct {
	*llm.GenerateRequest

	// Tool configuration
	EnableTools   bool     `json:"enable_tools,omitempty"`
	AllowedTools  []string `json:"allowed_tools,omitempty"`
	MaxToolCalls  int      `json:"max_tool_calls,omitempty"`
	ToolTimeout   time.Duration `json:"tool_timeout,omitempty"`

	// LLM selection
	PreferredLLM  string `json:"preferred_llm,omitempty"`
}

// GenerateWithToolsResponse extends the basic response with tool execution information
type GenerateWithToolsResponse struct {
	*llm.GenerateResponse

	// Tool execution details
	ToolCalls     []ToolCall `json:"tool_calls,omitempty"`
	TotalToolTime time.Duration `json:"total_tool_time,omitempty"`
	ToolErrors    []string   `json:"tool_errors,omitempty"`
}

// ToolCall represents a tool call made during generation
type ToolCall struct {
	ToolName    string                 `json:"tool_name"`
	Server      string                 `json:"server"`
	Parameters  map[string]interface{} `json:"parameters"`
	Result      *mcp.ToolResult        `json:"result"`
	Duration    time.Duration          `json:"duration"`
	Error       string                 `json:"error,omitempty"`
}

// NewLLMService creates a new LLM service
func NewLLMService(config *LLMServiceConfig, logger *zap.Logger) *LLMService {
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 30 * time.Second
	}

	return &LLMService{
		llmRegistry:      llm.NewLLMClientRegistry(),
		mcpRegistry:      mcp.NewMCPClientRegistry(logger),
		logger:           logger,
		defaultLLMClient: config.DefaultLLMClient,
		defaultTimeout:   config.DefaultTimeout,
		enableToolUse:    config.EnableToolUse,
	}
}

// RegisterLLMClient registers an LLM client
func (s *LLMService) RegisterLLMClient(name string, client llm.LLMClient) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := s.llmRegistry.RegisterClient(name, client); err != nil {
		return fmt.Errorf("failed to register LLM client %s: %w", name, err)
	}

	// Set as default if no default is set
	if s.defaultLLMClient == "" {
		s.defaultLLMClient = name
		if err := s.llmRegistry.SetDefaultClient(name); err != nil {
			s.logger.Warn("Failed to set default LLM client", zap.Error(err))
		}
	}

	s.logger.Info("Registered LLM client", zap.String("name", name), zap.String("provider", client.GetProviderName()))
	return nil
}

// RegisterMCPClient registers an MCP client
func (s *LLMService) RegisterMCPClient(name string, client mcp.MCPClient) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.mcpRegistry.RegisterClient(name, client)
	s.logger.Info("Registered MCP client", zap.String("name", name))
}

// Generate generates text using LLM with optional tool integration
func (s *LLMService) Generate(ctx context.Context, request *GenerateWithToolsRequest) (*GenerateWithToolsResponse, error) {
	startTime := time.Now()

	// Validate request
	if err := s.validateRequest(request); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Determine which LLM client to use
	clientName := request.PreferredLLM
	if clientName == "" {
		clientName = s.defaultLLMClient
	}

	// Create response
	response := &GenerateWithToolsResponse{
		ToolCalls:     make([]ToolCall, 0),
		ToolErrors:    make([]string, 0),
		TotalToolTime: 0,
	}

	// Check if tools are available and enabled
	toolsAvailable := s.enableToolUse && request.EnableTools && s.hasAvailableTools()

	if toolsAvailable {
		// Generate with tool integration
		llmResp, toolCalls, err := s.generateWithTools(ctx, clientName, request)
		if err != nil {
			return nil, fmt.Errorf("generation with tools failed: %w", err)
		}

		response.GenerateResponse = llmResp
		response.ToolCalls = toolCalls

		// Calculate total tool time
		for _, call := range toolCalls {
			response.TotalToolTime += call.Duration
			if call.Error != "" {
				response.ToolErrors = append(response.ToolErrors, call.Error)
			}
		}
	} else {
		// Generate without tools
		llmResp, err := s.llmRegistry.Generate(ctx, clientName, request.GenerateRequest)
		if err != nil {
			return nil, fmt.Errorf("LLM generation failed: %w", err)
		}
		response.GenerateResponse = llmResp
	}

	// Update response metadata
	response.Duration = time.Since(startTime)

	s.logger.Debug("LLM generation completed",
		zap.String("client", clientName),
		zap.Bool("tools_used", len(response.ToolCalls) > 0),
		zap.Int("tool_calls", len(response.ToolCalls)),
		zap.Duration("duration", response.Duration),
	)

	return response, nil
}

// generateWithTools handles generation with tool integration
func (s *LLMService) generateWithTools(ctx context.Context, clientName string, request *GenerateWithToolsRequest) (*llm.GenerateResponse, []ToolCall, error) {
	maxCalls := request.MaxToolCalls
	if maxCalls <= 0 {
		maxCalls = 5 // Default max tool calls
	}

	toolCalls := make([]ToolCall, 0)
	conversationHistory := make([]llm.Message, len(request.Messages))
	copy(conversationHistory, request.Messages)

	// Add tool information to system prompt
	if err := s.enhancePromptWithToolInfo(&conversationHistory, request.AllowedTools); err != nil {
		return nil, nil, fmt.Errorf("failed to enhance prompt with tool info: %w", err)
	}

	for i := 0; i < maxCalls; i++ {
		// Create request for this iteration
		iterRequest := &llm.GenerateRequest{
			Messages:         conversationHistory,
			Model:            request.Model,
			Temperature:      request.Temperature,
			MaxTokens:        request.MaxTokens,
			TopP:             request.TopP,
			Stop:             request.Stop,
			PresencePenalty:  request.PresencePenalty,
			FrequencyPenalty: request.FrequencyPenalty,
			SystemPrompt:     request.SystemPrompt,
			ProviderOptions:  request.ProviderOptions,
		}

		// Generate response
		response, err := s.llmRegistry.Generate(ctx, clientName, iterRequest)
		if err != nil {
			return nil, toolCalls, err
		}

		// Add assistant response to conversation
		conversationHistory = append(conversationHistory, llm.Message{
			Role:    "assistant",
			Content: response.Content,
		})

		// Check if response contains tool calls
		if calls, hasTools := s.parseToolCalls(response.Content, request.AllowedTools); hasTools {
			// Execute tool calls
			toolResults := s.executeToolCalls(ctx, calls, request.ToolTimeout)
			toolCalls = append(toolCalls, toolResults...)

			// Add tool results to conversation
			for _, result := range toolResults {
				if result.Result != nil {
					conversationHistory = append(conversationHistory, llm.Message{
						Role:    "user",
						Content: fmt.Sprintf("Tool %s result: %s", result.ToolName, result.Result.Content),
					})
				}
			}

			// Continue if we have more tool calls to make
			continue
		}

		// No more tool calls, return final response
		return response, toolCalls, nil
	}

	// If we reach here, we've hit the max tool calls limit
	// Generate one final response
	finalRequest := &llm.GenerateRequest{
		Messages:         conversationHistory,
		Model:            request.Model,
		Temperature:      request.Temperature,
		MaxTokens:        request.MaxTokens,
		TopP:             request.TopP,
		Stop:             request.Stop,
		PresencePenalty:  request.PresencePenalty,
		FrequencyPenalty: request.FrequencyPenalty,
		SystemPrompt:     request.SystemPrompt,
		ProviderOptions:  request.ProviderOptions,
	}

	response, err := s.llmRegistry.Generate(ctx, clientName, finalRequest)
	return response, toolCalls, err
}

// hasAvailableTools checks if any MCP tools are available
func (s *LLMService) hasAvailableTools() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	clients := s.mcpRegistry.ListClients()
	return len(clients) > 0
}

// enhancePromptWithToolInfo adds tool information to the conversation
func (s *LLMService) enhancePromptWithToolInfo(messages *[]llm.Message, allowedTools []string) error {
	// Get available tools
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	allTools, err := s.mcpRegistry.GetAllTools(ctx)
	if err != nil {
		return fmt.Errorf("failed to get available tools: %w", err)
	}

	if len(allTools) == 0 {
		return nil // No tools available
	}

	// Build tool description
	toolInfo := "Available tools:\n"
	for serverName, tools := range allTools {
		for _, tool := range tools {
			// Check if tool is allowed
			if len(allowedTools) > 0 && !s.isToolAllowed(tool.Name, allowedTools) {
				continue
			}

			toolInfo += fmt.Sprintf("- %s (%s): %s\n", tool.Name, serverName, tool.Description)
			if len(tool.Parameters.Required) > 0 {
				toolInfo += fmt.Sprintf("  Required parameters: %v\n", tool.Parameters.Required)
			}
		}
	}

	toolInfo += "\nTo use a tool, include a line like: TOOL_CALL: tool_name(param1=value1, param2=value2)\n"

	// Add tool info to system message or create one
	if len(*messages) > 0 && (*messages)[0].Role == "system" {
		(*messages)[0].Content += "\n\n" + toolInfo
	} else {
		*messages = append([]llm.Message{{
			Role:    "system",
			Content: toolInfo,
		}}, *messages...)
	}

	return nil
}

// isToolAllowed checks if a tool is in the allowed list
func (s *LLMService) isToolAllowed(toolName string, allowedTools []string) bool {
	for _, allowed := range allowedTools {
		if allowed == toolName {
			return true
		}
	}
	return false
}

// parseToolCalls parses tool calls from LLM response
func (s *LLMService) parseToolCalls(content string, allowedTools []string) ([]ToolCall, bool) {
	// Simple parsing for demonstration - in production, this would be more sophisticated
	// Look for patterns like: TOOL_CALL: tool_name(param1=value1, param2=value2)

	// This is a simplified implementation
	// In reality, you might use JSON-formatted tool calls or a more sophisticated parser

	return []ToolCall{}, false // Placeholder - implement actual parsing logic
}

// executeToolCalls executes a batch of tool calls
func (s *LLMService) executeToolCalls(ctx context.Context, calls []ToolCall, timeout time.Duration) []ToolCall {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	results := make([]ToolCall, len(calls))

	for i, call := range calls {
		startTime := time.Now()

		// Create context with timeout
		callCtx, cancel := context.WithTimeout(ctx, timeout)

		// Execute the tool call
		result, err := s.mcpRegistry.ExecuteTool(callCtx, call.Server, call.ToolName, call.Parameters)
		cancel()

		// Record the result
		results[i] = ToolCall{
			ToolName:   call.ToolName,
			Server:     call.Server,
			Parameters: call.Parameters,
			Result:     result,
			Duration:   time.Since(startTime),
		}

		if err != nil {
			results[i].Error = err.Error()
		}
	}

	return results
}

// validateRequest validates a generate request
func (s *LLMService) validateRequest(request *GenerateWithToolsRequest) error {
	if request.GenerateRequest == nil {
		return fmt.Errorf("base generate request is required")
	}

	if err := llm.ValidateRequest(request.GenerateRequest); err != nil {
		return err
	}

	if request.MaxToolCalls < 0 {
		return fmt.Errorf("max_tool_calls cannot be negative")
	}

	return nil
}

// GetAvailableClients returns information about available LLM and MCP clients
func (s *LLMService) GetAvailableClients() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return map[string]interface{}{
		"llm_clients": s.llmRegistry.ListClients(),
		"mcp_clients": s.mcpRegistry.ListClients(),
		"default_llm": s.defaultLLMClient,
		"tools_enabled": s.enableToolUse,
	}
}

// GetUsageStats returns aggregated usage statistics
func (s *LLMService) GetUsageStats() (map[string]*llm.UsageStats, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := make(map[string]*llm.UsageStats)

	for _, clientName := range s.llmRegistry.ListClients() {
		client, err := s.llmRegistry.GetClient(clientName)
		if err != nil {
			continue
		}
		stats[clientName] = client.GetUsage()
	}

	return stats, nil
}

// SetDefaultLLMClient sets the default LLM client
func (s *LLMService) SetDefaultLLMClient(clientName string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := s.llmRegistry.SetDefaultClient(clientName); err != nil {
		return err
	}

	s.defaultLLMClient = clientName
	s.logger.Info("Default LLM client updated", zap.String("client", clientName))
	return nil
}