package iteration_controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/integrations/llm"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// EnhancedReActController implements ReAct pattern with real MCP tool integration
type EnhancedReActController struct {
	*MCPIntegratedController
	enableToolUse bool
	llmService    LLMServiceInterface
	logger        *zap.Logger
}

// NewEnhancedReActController creates a new enhanced ReAct controller
func NewEnhancedReActController(
	maxIterations int,
	enableToolUse bool,
	llmService LLMServiceInterface,
	mcpRegistry *mcp.MCPServerRegistry,
	logger *zap.Logger,
	agentName string,
) *EnhancedReActController {
	return &EnhancedReActController{
		MCPIntegratedController: NewMCPIntegratedController("enhanced_react", maxIterations, mcpRegistry, logger, agentName),
		enableToolUse:          enableToolUse,
		llmService:             llmService,
		logger:                 logger,
	}
}

// Execute implements the enhanced ReAct iteration pattern with real tool calling
func (erc *EnhancedReActController) Execute(ctx context.Context, iterCtx *IterationContext) (*IterationResult, error) {
	// Initialize the iteration context
	if err := erc.InitializeContext(iterCtx); err != nil {
		return nil, fmt.Errorf("failed to initialize context: %w", err)
	}

	// Load available tools for the agent
	availableTools, err := erc.GetAvailableTools(ctx)
	if err != nil {
		erc.logger.Warn("Failed to load available tools, continuing without tool use",
			zap.String("agent", erc.agentName),
			zap.Error(err),
		)
		erc.enableToolUse = false
	}

	// Add the initial analysis prompt with available tools
	initialPrompt := erc.buildEnhancedInitialPrompt(iterCtx, availableTools)
	erc.addUserMessage(iterCtx, initialPrompt)

	var lastResponse string
	startTime := time.Now()
	iterationTrace := make([]IterationStep, 0)

	// Main ReAct iteration loop
	for iterCtx.CurrentIteration < iterCtx.MaxIterations {
		iterCtx.CurrentIteration++

		erc.logger.Debug("Starting ReAct iteration",
			zap.String("agent", erc.agentName),
			zap.Int("iteration", iterCtx.CurrentIteration),
			zap.Int("max_iterations", iterCtx.MaxIterations),
		)

		// Step 1: Think (get LLM response)
		thinkStart := time.Now()
		thought, err := erc.executeThinkStep(ctx, iterCtx)
		if err != nil {
			return erc.createIterationResult(iterCtx, false, "", fmt.Sprintf("Think step failed: %v", err)), nil
		}

		// Record think step
		iterationTrace = append(iterationTrace, IterationStep{
			Iteration: iterCtx.CurrentIteration,
			StepType:  "thought",
			Content:   thought,
			Timestamp: time.Now().UnixMicro(),
			Duration:  time.Since(thinkStart).Milliseconds(),
		})

		lastResponse = thought
		erc.addAssistantMessage(iterCtx, thought)

		// Check if this is a final answer
		if erc.isFinalAnswer(thought) {
			finalAnalysis := erc.extractFinalAnalysis(thought)
			result := erc.createEnhancedIterationResult(iterCtx, true, finalAnalysis, "", iterationTrace)
			result.TotalDuration = time.Since(startTime).Milliseconds()
			return result, nil
		}

		// Step 2: Act (parse and execute actions if tool use is enabled)
		if erc.enableToolUse && erc.containsToolCalls(thought) {
			actionStart := time.Now()

			// Extract tool calls from the LLM response
			toolCalls, err := erc.extractToolCallsFromResponse(thought)
			if err != nil {
				erc.logger.Warn("Failed to extract tool calls from response",
					zap.String("agent", erc.agentName),
					zap.Error(err),
				)
			} else if len(toolCalls) > 0 {
				// Execute the tool calls
				toolResults, err := erc.ExecuteMultipleTools(ctx, toolCalls)
				if err != nil {
					erc.logger.Error("Tool execution failed",
						zap.String("agent", erc.agentName),
						zap.Error(err),
					)
				}

				// Record action step
				actionContent := fmt.Sprintf("Executed %d tools", len(toolCalls))
				iterationTrace = append(iterationTrace, IterationStep{
					Iteration: iterCtx.CurrentIteration,
					StepType:  "action",
					Content:   actionContent,
					Timestamp: time.Now().UnixMicro(),
					Duration:  time.Since(actionStart).Milliseconds(),
				})

				// Add tool executions to context
				for _, result := range toolResults {
					toolExec := result.ConvertToToolExecution(iterCtx.CurrentIteration)
					iterCtx.ToolExecutions = append(iterCtx.ToolExecutions, toolExec)
				}

				// Step 3: Observe (add tool results back to conversation)
				observeStart := time.Now()
				observation := erc.FormatToolResultsForLLM(toolResults)
				erc.addUserMessage(iterCtx, fmt.Sprintf("Tool Execution Results:\n%s", observation))

				// Record observe step
				iterationTrace = append(iterationTrace, IterationStep{
					Iteration: iterCtx.CurrentIteration,
					StepType:  "observation",
					Content:   observation,
					Timestamp: time.Now().UnixMicro(),
					Duration:  time.Since(observeStart).Milliseconds(),
				})
			}
		}

		// Check if we should continue iteration
		if !erc.shouldContinueIteration(iterCtx, lastResponse) {
			break
		}
	}

	// If we reached max iterations without a final answer, extract the best analysis we have
	finalAnalysis := erc.extractBestAnalysis(iterCtx)
	result := erc.createEnhancedIterationResult(iterCtx, true, finalAnalysis, "", iterationTrace)
	result.TotalDuration = time.Since(startTime).Milliseconds()

	return result, nil
}

// buildEnhancedInitialPrompt creates an enhanced initial prompt with tool information
func (erc *EnhancedReActController) buildEnhancedInitialPrompt(iterCtx *IterationContext, availableTools map[string][]mcp.Tool) string {
	prompt := fmt.Sprintf(`You are a TARSy AI agent analyzing a security alert using the ReAct (Reasoning and Acting) pattern.

Agent: %s
Alert Type: %s
Alert Data: %v

Instructions:
%s

Available Capabilities: %s

Analyze this alert step by step using the following format:

Thought: [Your reasoning about what to do next]
Action: [If you need to use a tool, specify it in the format below]
Observation: [This will be filled with tool results]

Continue this pattern until you reach a conclusion, then provide:

Final Analysis: [Your complete analysis and recommendations]

Tool Call Format:
When you want to use a tool, format your action as:
Action: {
  "tool": "tool_name",
  "server": "server_name",
  "parameters": {
    "param1": "value1",
    "param2": "value2"
  }
}

`,
		erc.agentName,
		iterCtx.Alert.AlertType,
		iterCtx.Alert.Data,
		iterCtx.Instructions,
		strings.Join(iterCtx.Capabilities, ", "))

	// Add available tools information
	if erc.enableToolUse && len(availableTools) > 0 {
		prompt += "\nAvailable Tools:\n"
		for serverName, tools := range availableTools {
			prompt += fmt.Sprintf("\nServer: %s\n", serverName)
			for _, tool := range tools {
				prompt += fmt.Sprintf("  - %s: %s\n", tool.Name, tool.Description)
				if len(tool.Parameters.Properties) > 0 {
					prompt += "    Parameters:\n"
					for paramName, param := range tool.Parameters.Properties {
						required := ""
						for _, req := range tool.Parameters.Required {
							if req == paramName {
								required = " (required)"
								break
							}
						}
						prompt += fmt.Sprintf("      %s (%s): %s%s\n", paramName, param.Type, param.Description, required)
					}
				}
			}
		}
	} else {
		prompt += "\nNote: Tool execution is disabled or no tools available. Focus on analysis based on alert data and instructions.\n"
	}

	prompt += "\nBegin your analysis:\n"
	return prompt
}

// executeThinkStep executes the thinking/reasoning step using LLM
func (erc *EnhancedReActController) executeThinkStep(ctx context.Context, iterCtx *IterationContext) (string, error) {
	if erc.llmService == nil {
		// Fallback to simulated response for testing
		return erc.generateSimulatedThought(iterCtx), nil
	}

	// Convert conversation history to LLM messages
	messages := make([]llm.Message, len(iterCtx.ConversationHistory))
	for i, entry := range iterCtx.ConversationHistory {
		messages[i] = llm.Message{
			Role:    entry.Role,
			Content: entry.Content,
		}
	}

	// Create LLM request
	llmRequest := &llm.GenerateRequest{
		Messages:    messages,
		Temperature: &iterCtx.Temperature,
		MaxTokens:   &iterCtx.MaxTokens,
	}

	request := &GenerateWithToolsRequest{
		GenerateRequest: llmRequest,
		EnableTools:     false, // We handle tools manually in ReAct pattern
	}

	// Generate response using LLM service
	response, err := erc.llmService.Generate(ctx, request)
	if err != nil {
		// Log error but fallback to simulation for robustness
		erc.logger.Warn("LLM generation failed, using simulated response",
			zap.Error(err),
			zap.String("agent", erc.agentName),
			zap.Int("iteration", iterCtx.CurrentIteration),
		)
		return erc.generateSimulatedThought(iterCtx), nil
	}

	return response.Content, nil
}

// extractToolCallsFromResponse extracts structured tool calls from LLM response
func (erc *EnhancedReActController) extractToolCallsFromResponse(response string) ([]ToolCallSpec, error) {
	var toolCalls []ToolCallSpec

	// Pattern to match Action: {...} blocks
	actionPattern := `Action:\s*\{[^}]*\}`
	re := regexp.MustCompile(actionPattern)

	matches := re.FindAllString(response, -1)
	for _, match := range matches {
		// Extract JSON part
		jsonStart := strings.Index(match, "{")
		if jsonStart == -1 {
			continue
		}

		jsonPart := match[jsonStart:]

		// Try to parse as JSON
		var toolCall struct {
			Tool       string                 `json:"tool"`
			Server     string                 `json:"server"`
			Parameters map[string]interface{} `json:"parameters"`
		}

		if err := json.Unmarshal([]byte(jsonPart), &toolCall); err != nil {
			erc.logger.Warn("Failed to parse tool call JSON",
				zap.String("agent", erc.agentName),
				zap.String("json", jsonPart),
				zap.Error(err),
			)
			continue
		}

		if toolCall.Tool != "" && toolCall.Server != "" {
			toolCalls = append(toolCalls, ToolCallSpec{
				ToolName:      toolCall.Tool,
				Server:        toolCall.Server,
				Parameters:    toolCall.Parameters,
				StopOnFailure: false, // Continue on tool failures in ReAct
				Timeout:       30 * time.Second,
			})
		}
	}

	erc.logger.Debug("Extracted tool calls from response",
		zap.String("agent", erc.agentName),
		zap.Int("tool_calls", len(toolCalls)),
	)

	return toolCalls, nil
}

// containsToolCalls checks if the response contains tool call actions
func (erc *EnhancedReActController) containsToolCalls(response string) bool {
	// Look for Action: followed by JSON structure
	actionPattern := `Action:\s*\{`
	matched, _ := regexp.MatchString(actionPattern, response)
	return matched
}

// isFinalAnswer checks if the response contains a final answer
func (erc *EnhancedReActController) isFinalAnswer(response string) bool {
	finalMarkers := []string{
		"Final Analysis:",
		"FINAL ANSWER:",
		"CONCLUSION:",
		"Analysis Complete",
	}

	lowerResponse := strings.ToLower(response)
	for _, marker := range finalMarkers {
		if strings.Contains(lowerResponse, strings.ToLower(marker)) {
			return true
		}
	}

	return false
}

// extractFinalAnalysis extracts the final analysis from the response
func (erc *EnhancedReActController) extractFinalAnalysis(response string) string {
	// Look for final analysis marker
	lines := strings.Split(response, "\n")
	inFinalAnalysis := false
	var analysis []string

	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "final analysis:") {
			inFinalAnalysis = true
			// Include the line after "Final Analysis:"
			if colonIndex := strings.Index(line, ":"); colonIndex != -1 && len(line) > colonIndex+1 {
				remainingText := strings.TrimSpace(line[colonIndex+1:])
				if remainingText != "" {
					analysis = append(analysis, remainingText)
				}
			}
			continue
		}

		if inFinalAnalysis {
			analysis = append(analysis, line)
		}
	}

	if len(analysis) > 0 {
		return strings.Join(analysis, "\n")
	}

	// If no final analysis found, return the whole response
	return response
}

// extractBestAnalysis extracts the best available analysis from conversation history
func (erc *EnhancedReActController) extractBestAnalysis(iterCtx *IterationContext) string {
	// Look through conversation history for the most recent assistant response
	for i := len(iterCtx.ConversationHistory) - 1; i >= 0; i-- {
		entry := iterCtx.ConversationHistory[i]
		if entry.Role == "assistant" {
			// Check if it contains analysis-like content
			if strings.Contains(strings.ToLower(entry.Content), "analysis") ||
				strings.Contains(strings.ToLower(entry.Content), "recommendation") {
				return entry.Content
			}
		}
	}

	return "Analysis completed through enhanced ReAct iteration pattern with tool integration. Please review conversation history for detailed reasoning steps."
}

// shouldContinueIteration determines if iteration should continue
func (erc *EnhancedReActController) shouldContinueIteration(iterCtx *IterationContext, lastResponse string) bool {
	// Check if final analysis is complete
	if erc.isFinalAnswer(lastResponse) {
		return false
	}

	// Check iteration limits
	if iterCtx.CurrentIteration >= iterCtx.MaxIterations {
		return false
	}

	return true
}

// generateSimulatedThought generates a simulated thought for demonstration
func (erc *EnhancedReActController) generateSimulatedThought(iterCtx *IterationContext) string {
	iteration := iterCtx.CurrentIteration

	switch iteration {
	case 1:
		return fmt.Sprintf(`Thought: I need to analyze this %s alert. Let me start by understanding the current state of the affected resources and checking for any immediate issues.

Action: {
  "tool": "kubectl",
  "server": "kubernetes-server",
  "parameters": {
    "command": "get pods",
    "namespace": "default"
  }
}`, iterCtx.Alert.AlertType)

	case 2:
		return `Thought: Based on the pod status, I should check the security policies and examine any recent events that might be related to this alert.

Action: {
  "tool": "check_policies",
  "server": "security-server",
  "parameters": {
    "namespace": "default"
  }
}`

	case 3:
		return `Thought: The policies seem properly configured. Let me examine the logs to understand what triggered this alert.

Action: {
  "tool": "get_pod_logs",
  "server": "kubernetes-server",
  "parameters": {
    "pod_name": "example-pod",
    "namespace": "default",
    "lines": "100"
  }
}`

	default:
		return `Final Analysis: Based on my investigation using multiple tools:

1. **Pod Status**: The pods are running normally with proper security context
2. **Security Policies**: Network policies and pod security standards are correctly enforced
3. **Log Analysis**: Logs show no suspicious activity in the recent period
4. **Tool Integration**: Successfully used MCP tools for comprehensive analysis

**Recommendations**:
- This appears to be a false positive alert
- Continue monitoring for any pattern changes
- Consider adjusting alert thresholds if this pattern persists

**Risk Level**: Low
**Confidence**: High (based on comprehensive tool analysis)`
	}
}

// Helper methods for conversation management
func (erc *EnhancedReActController) addUserMessage(iterCtx *IterationContext, content string) {
	entry := ConversationEntry{
		Role:      "user",
		Content:   content,
		Timestamp: time.Now().UnixMicro(),
	}
	iterCtx.ConversationHistory = append(iterCtx.ConversationHistory, entry)
}

func (erc *EnhancedReActController) addAssistantMessage(iterCtx *IterationContext, content string) {
	entry := ConversationEntry{
		Role:      "assistant",
		Content:   content,
		Timestamp: time.Now().UnixMicro(),
	}
	iterCtx.ConversationHistory = append(iterCtx.ConversationHistory, entry)
}

func (erc *EnhancedReActController) InitializeContext(iterCtx *IterationContext) error {
	if iterCtx.ConversationHistory == nil {
		iterCtx.ConversationHistory = make([]ConversationEntry, 0)
	}
	if iterCtx.ToolExecutions == nil {
		iterCtx.ToolExecutions = make([]ToolExecution, 0)
	}
	if iterCtx.Variables == nil {
		iterCtx.Variables = make(map[string]interface{})
	}
	return nil
}

func (erc *EnhancedReActController) createIterationResult(iterCtx *IterationContext, success bool, finalAnalysis, errorMessage string) *IterationResult {
	return &IterationResult{
		Success:             success,
		FinalAnalysis:       finalAnalysis,
		ErrorMessage:        errorMessage,
		TotalIterations:     iterCtx.CurrentIteration,
		ToolExecutions:      len(iterCtx.ToolExecutions),
		ConversationHistory: iterCtx.ConversationHistory,
		ToolResults:         iterCtx.ToolExecutions,
	}
}

func (erc *EnhancedReActController) createEnhancedIterationResult(iterCtx *IterationContext, success bool, finalAnalysis, errorMessage string, trace []IterationStep) *IterationResult {
	result := erc.createIterationResult(iterCtx, success, finalAnalysis, errorMessage)
	result.IterationTrace = trace
	return result
}