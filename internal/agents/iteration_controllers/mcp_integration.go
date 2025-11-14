package iteration_controllers

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// MCPIntegratedController extends base controller with MCP tool execution capabilities
type MCPIntegratedController struct {
	*BaseController
	mcpRegistry *mcp.MCPServerRegistry
	logger      *zap.Logger
	agentName   string
}

// NewMCPIntegratedController creates a new MCP-integrated controller
func NewMCPIntegratedController(
	strategyType string,
	maxIterations int,
	mcpRegistry *mcp.MCPServerRegistry,
	logger *zap.Logger,
	agentName string,
) *MCPIntegratedController {
	return &MCPIntegratedController{
		BaseController: NewBaseController(strategyType, maxIterations),
		mcpRegistry:    mcpRegistry,
		logger:         logger,
		agentName:      agentName,
	}
}

// ExecuteToolCall executes a tool call using the MCP registry
func (mc *MCPIntegratedController) ExecuteToolCall(ctx context.Context, serverName, toolName string, parameters map[string]interface{}) (*ToolExecutionResult, error) {
	startTime := time.Now()

	mc.logger.Debug("Executing MCP tool",
		zap.String("agent", mc.agentName),
		zap.String("server", serverName),
		zap.String("tool", toolName),
		zap.Any("parameters", parameters),
	)

	// Execute tool via MCP registry
	mcpResult, err := mc.mcpRegistry.ExecuteToolOnServer(ctx, serverName, toolName, parameters)
	if err != nil {
		mc.logger.Error("MCP tool execution failed",
			zap.String("agent", mc.agentName),
			zap.String("server", serverName),
			zap.String("tool", toolName),
			zap.Error(err),
		)

		return &ToolExecutionResult{
			ToolName:   toolName,
			Server:     serverName,
			Success:    false,
			Error:      err.Error(),
			Duration:   time.Since(startTime),
			Timestamp:  time.Now(),
		}, nil
	}

	mc.logger.Debug("MCP tool execution completed",
		zap.String("agent", mc.agentName),
		zap.String("server", serverName),
		zap.String("tool", toolName),
		zap.Bool("success", mcpResult.Success),
		zap.Duration("duration", time.Since(startTime)),
	)

	// Convert content to string safely using the enhanced ToolResult method
	contentStr := mcpResult.GetContentAsString()

	return &ToolExecutionResult{
		ToolName:   toolName,
		Server:     serverName,
		Success:    mcpResult.Success,
		Content:    contentStr,
		Error:      mcpResult.Error,
		Duration:   time.Since(startTime),
		Timestamp:  time.Now(),
		Metadata:   mcpResult.Metadata,
	}, nil
}

// GetAvailableTools returns all tools available to the agent
func (mc *MCPIntegratedController) GetAvailableTools(ctx context.Context) (map[string][]mcp.Tool, error) {
	if mc.mcpRegistry == nil {
		return make(map[string][]mcp.Tool), nil
	}

	tools, err := mc.mcpRegistry.GetAllToolsForAgent(ctx, mc.agentName)
	if err != nil {
		mc.logger.Warn("Failed to get available tools for agent",
			zap.String("agent", mc.agentName),
			zap.Error(err),
		)
		return make(map[string][]mcp.Tool), err
	}

	mc.logger.Debug("Retrieved available tools for agent",
		zap.String("agent", mc.agentName),
		zap.Int("server_count", len(tools)),
	)

	return tools, nil
}

// ValidateToolAccess validates that the agent has access to a specific tool
func (mc *MCPIntegratedController) ValidateToolAccess(serverName, toolName string) error {
	if mc.mcpRegistry == nil {
		return fmt.Errorf("MCP registry not available")
	}

	// Check if server is assigned to agent
	assignedServers := mc.mcpRegistry.GetServersByAgent(mc.agentName)
	serverAllowed := false
	for _, assigned := range assignedServers {
		if assigned == serverName {
			serverAllowed = true
			break
		}
	}

	if !serverAllowed {
		return fmt.Errorf("agent %s does not have access to server %s", mc.agentName, serverName)
	}

	// Check if server is running
	status, err := mc.mcpRegistry.GetServerStatus(serverName)
	if err != nil {
		return fmt.Errorf("failed to check server status: %w", err)
	}

	if status != mcp.ServerStatusRunning {
		return fmt.Errorf("server %s is not running (status: %s)", serverName, status)
	}

	return nil
}

// ExecuteMultipleTools executes multiple tools in sequence
func (mc *MCPIntegratedController) ExecuteMultipleTools(ctx context.Context, toolCalls []ToolCallSpec) ([]ToolExecutionResult, error) {
	results := make([]ToolExecutionResult, 0, len(toolCalls))

	for i, call := range toolCalls {
		mc.logger.Debug("Executing tool call",
			zap.String("agent", mc.agentName),
			zap.Int("call_index", i+1),
			zap.Int("total_calls", len(toolCalls)),
			zap.String("tool", call.ToolName),
			zap.String("server", call.Server),
		)

		// Validate access before execution
		if err := mc.ValidateToolAccess(call.Server, call.ToolName); err != nil {
			result := ToolExecutionResult{
				ToolName:  call.ToolName,
				Server:    call.Server,
				Success:   false,
				Error:     fmt.Sprintf("access validation failed: %v", err),
				Timestamp: time.Now(),
			}
			results = append(results, result)
			continue
		}

		// Execute the tool
		result, err := mc.ExecuteToolCall(ctx, call.Server, call.ToolName, call.Parameters)
		if err != nil {
			result = &ToolExecutionResult{
				ToolName:  call.ToolName,
				Server:    call.Server,
				Success:   false,
				Error:     err.Error(),
				Timestamp: time.Now(),
			}
		}

		results = append(results, *result)

		// Stop on critical failure if specified
		if call.StopOnFailure && !result.Success {
			mc.logger.Warn("Stopping tool execution due to critical failure",
				zap.String("agent", mc.agentName),
				zap.String("tool", call.ToolName),
				zap.String("error", result.Error),
			)
			break
		}
	}

	return results, nil
}

// CreateToolExecutionContext creates tool execution context for iteration
func (mc *MCPIntegratedController) CreateToolExecutionContext(iterCtx *IterationContext) *ToolExecutionContext {
	return &ToolExecutionContext{
		AgentName:     mc.agentName,
		Iteration:     iterCtx.CurrentIteration,
		SessionID:     iterCtx.ChainCtx.SessionID,
		AlertType:     iterCtx.Alert.AlertType,
		Capabilities:  iterCtx.Capabilities,
		MCPEnabled:    iterCtx.MCPEnabled,
		Variables:     iterCtx.Variables,
	}
}

// ToolCallSpec represents a specification for a tool call
type ToolCallSpec struct {
	ToolName      string                 `json:"tool_name"`
	Server        string                 `json:"server"`
	Parameters    map[string]interface{} `json:"parameters"`
	StopOnFailure bool                   `json:"stop_on_failure"`
	Timeout       time.Duration          `json:"timeout,omitempty"`
}

// ToolExecutionResult represents the result of executing a tool
type ToolExecutionResult struct {
	ToolName   string                 `json:"tool_name"`
	Server     string                 `json:"server"`
	Success    bool                   `json:"success"`
	Content    string                 `json:"content"`
	Error      string                 `json:"error,omitempty"`
	Duration   time.Duration          `json:"duration"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ToolExecutionContext provides context for tool execution
type ToolExecutionContext struct {
	AgentName    string                 `json:"agent_name"`
	Iteration    int                    `json:"iteration"`
	SessionID    string                 `json:"session_id"`
	AlertType    string                 `json:"alert_type"`
	Capabilities []string               `json:"capabilities"`
	MCPEnabled   bool                   `json:"mcp_enabled"`
	Variables    map[string]interface{} `json:"variables,omitempty"`
}

// ConvertToToolExecution converts ToolExecutionResult to ToolExecution
func (ter *ToolExecutionResult) ConvertToToolExecution(iteration int) ToolExecution {
	return ToolExecution{
		ToolName:   ter.ToolName,
		Server:     ter.Server,
		Parameters: nil, // Parameters not stored in ToolExecution
		Result:     ter.Content,
		Error:      ter.Error,
		Duration:   ter.Duration.Milliseconds(),
		Timestamp:  ter.Timestamp.UnixMicro(),
		Iteration:  iteration,
	}
}

// ExtractToolCallsFromResponse extracts tool calls from LLM response
func (mc *MCPIntegratedController) ExtractToolCallsFromResponse(response string) ([]ToolCallSpec, error) {
	// This is a simplified parser. In production, you might want to use a more sophisticated parser
	// that can handle structured tool calls in JSON format or other structured formats

	toolCalls := make([]ToolCallSpec, 0)

	// For now, we'll implement a simple pattern matching approach
	// In practice, this would be replaced with a proper tool call parser
	// that understands the specific format your LLM uses for tool calls

	mc.logger.Debug("Extracting tool calls from response",
		zap.String("agent", mc.agentName),
		zap.Int("response_length", len(response)),
	)

	// TODO: Implement proper tool call extraction based on your LLM's format
	// This might involve parsing JSON structures, XML, or custom formats

	return toolCalls, nil
}

// FormatToolResultsForLLM formats tool execution results for LLM consumption
func (mc *MCPIntegratedController) FormatToolResultsForLLM(results []ToolExecutionResult) string {
	if len(results) == 0 {
		return ""
	}

	formatted := "Tool Execution Results:\n\n"

	for i, result := range results {
		formatted += fmt.Sprintf("=== Tool %d: %s (Server: %s) ===\n", i+1, result.ToolName, result.Server)

		if result.Success {
			formatted += fmt.Sprintf("Status: SUCCESS\nDuration: %v\n\nOutput:\n%s\n\n",
				result.Duration, result.Content)
		} else {
			formatted += fmt.Sprintf("Status: FAILED\nDuration: %v\nError: %s\n\n",
				result.Duration, result.Error)
		}

		if result.Metadata != nil && len(result.Metadata) > 0 {
			formatted += "Metadata:\n"
			for key, value := range result.Metadata {
				formatted += fmt.Sprintf("  %s: %v\n", key, value)
			}
			formatted += "\n"
		}
	}

	return formatted
}

// GetServerHealth returns health information for all servers assigned to the agent
func (mc *MCPIntegratedController) GetServerHealth() map[string]*mcp.ServerHealth {
	if mc.mcpRegistry == nil {
		return make(map[string]*mcp.ServerHealth)
	}

	assignedServers := mc.mcpRegistry.GetServersByAgent(mc.agentName)
	health := make(map[string]*mcp.ServerHealth)

	for _, serverName := range assignedServers {
		if serverHealth, err := mc.mcpRegistry.GetServerHealth(serverName); err == nil {
			health[serverName] = serverHealth
		}
	}

	return health
}

// IsToolExecutionEnabled checks if tool execution is enabled and available
func (mc *MCPIntegratedController) IsToolExecutionEnabled() bool {
	return mc.mcpRegistry != nil
}

// GetMCPRegistry returns the MCP registry (for advanced use cases)
func (mc *MCPIntegratedController) GetMCPRegistry() *mcp.MCPServerRegistry {
	return mc.mcpRegistry
}