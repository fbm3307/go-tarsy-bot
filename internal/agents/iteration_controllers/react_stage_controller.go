package iteration_controllers

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ReactStageController implements ReAct pattern for individual stage processing
// This is used when processing specific stages within a larger chain
type ReactStageController struct {
	*BaseController
	stageName     string
	stageGoal     string
	enableToolUse bool
}

// NewReActStageController creates a new ReAct stage controller
func NewReActStageController(stageName, stageGoal string, maxIterations int, enableToolUse bool) *ReactStageController {
	return &ReactStageController{
		BaseController: NewBaseController("react_stage", maxIterations),
		stageName:      stageName,
		stageGoal:      stageGoal,
		enableToolUse:  enableToolUse,
	}
}

// Execute implements stage-specific ReAct iteration
func (rsc *ReactStageController) Execute(ctx context.Context, iterCtx *IterationContext) (*IterationResult, error) {
	// Initialize the iteration context
	if err := rsc.InitializeContext(iterCtx); err != nil {
		return nil, fmt.Errorf("failed to initialize stage context: %w", err)
	}

	// Add stage-specific context
	rsc.addStageContext(iterCtx)

	// Build stage-specific prompt
	stagePrompt := rsc.buildStagePrompt(iterCtx)
	rsc.addUserMessage(iterCtx, stagePrompt)

	var lastResponse string
	startTime := time.Now()

	// Stage-focused ReAct loop
	for iterCtx.CurrentIteration < iterCtx.MaxIterations {
		iterCtx.CurrentIteration++

		// Think: Focus on stage-specific goals
		thought, err := rsc.executeStageThought(ctx, iterCtx)
		if err != nil {
			return rsc.createIterationResult(iterCtx, false, "", fmt.Sprintf("Stage thought failed: %v", err)), nil
		}

		lastResponse = thought
		rsc.addAssistantMessage(iterCtx, thought)

		// Check if stage goal is achieved
		if rsc.isStageComplete(thought) {
			stageResult := rsc.extractStageResult(thought)
			result := rsc.createIterationResult(iterCtx, true, stageResult, "")
			result.TotalDuration = time.Since(startTime).Milliseconds()
			return result, nil
		}

		// Act: Execute stage-specific actions
		if rsc.enableToolUse && rsc.containsStageAction(thought) {
			observation, err := rsc.executeStageAction(ctx, iterCtx, thought)
			if err != nil {
				observation = fmt.Sprintf("Stage action error: %v", err)
			}
			rsc.addUserMessage(iterCtx, fmt.Sprintf("Stage Observation: %s", observation))
		}

		// Check continuation criteria for this stage
		if !rsc.shouldContinueStage(iterCtx, lastResponse) {
			break
		}
	}

	// Extract the best stage analysis available
	stageAnalysis := rsc.extractBestStageAnalysis(iterCtx)
	result := rsc.createIterationResult(iterCtx, true, stageAnalysis, "")
	result.TotalDuration = time.Since(startTime).Milliseconds()

	return result, nil
}

// addStageContext adds stage-specific context to the iteration
func (rsc *ReactStageController) addStageContext(iterCtx *IterationContext) {
	// Add stage information to variables
	iterCtx.Variables["STAGE_NAME"] = rsc.stageName
	iterCtx.Variables["STAGE_GOAL"] = rsc.stageGoal

	// Add previous stage results if available
	if iterCtx.ChainCtx.StageOutputs != nil {
		iterCtx.Variables["PREVIOUS_STAGES"] = len(iterCtx.ChainCtx.StageOutputs)

		// Summarize previous stage findings
		var previousFindings []string
		for stageName, result := range iterCtx.ChainCtx.StageOutputs {
			if result.ResultSummary != nil {
				previousFindings = append(previousFindings, fmt.Sprintf("%s: %s", stageName, *result.ResultSummary))
			}
		}
		iterCtx.Variables["PREVIOUS_FINDINGS"] = strings.Join(previousFindings, "; ")
	}
}

// buildStagePrompt creates a stage-specific prompt
func (rsc *ReactStageController) buildStagePrompt(iterCtx *IterationContext) string {
	prompt := fmt.Sprintf(`You are working on Stage: %s

Stage Goal: %s

Alert Context:
- Type: %s
- Data: %v

Chain Context:
- Session ID: %s
- Current Stage: %s`,
		rsc.stageName,
		rsc.stageGoal,
		iterCtx.Alert.AlertType,
		iterCtx.Alert.Data,
		iterCtx.ChainCtx.SessionID,
		iterCtx.ChainCtx.CurrentStageName)

	// Add previous stage context if available
	if previousFindings, ok := iterCtx.Variables["PREVIOUS_FINDINGS"].(string); ok && previousFindings != "" {
		prompt += fmt.Sprintf("\n\nPrevious Stage Findings:\n%s", previousFindings)
	}

	prompt += fmt.Sprintf(`

Stage Instructions:
%s

Please complete this stage using the ReAct pattern:

Stage Thought: [Your reasoning focused on achieving the stage goal]
Stage Action: [Actions specific to this stage goal]
Stage Observation: [Results from stage actions]

When you have sufficient information to complete this stage, provide:

Stage Result: [Your findings and analysis for this specific stage]

Begin stage analysis:`, iterCtx.Instructions)

	return prompt
}

// executeStageThought executes thinking focused on stage goals
func (rsc *ReactStageController) executeStageThought(ctx context.Context, iterCtx *IterationContext) (string, error) {
	// Stage-specific thought simulation
	return rsc.generateStageThought(iterCtx), nil
}

// executeStageAction executes stage-specific actions
func (rsc *ReactStageController) executeStageAction(ctx context.Context, iterCtx *IterationContext, thought string) (string, error) {
	actions := rsc.parseStageActions(thought)
	if len(actions) == 0 {
		return "No stage-specific actions identified.", nil
	}

	var observations []string
	for _, action := range actions {
		result := rsc.simulateStageAction(action, iterCtx)
		observations = append(observations, result)
	}

	return strings.Join(observations, "\n"), nil
}

// parseStageActions parses stage-specific actions
func (rsc *ReactStageController) parseStageActions(thought string) []string {
	var actions []string
	lines := strings.Split(thought, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "stage action:") {
			action := strings.TrimSpace(line[13:]) // len("stage action:") = 13
			if action != "" {
				actions = append(actions, action)
			}
		}
	}

	return actions
}

// simulateStageAction simulates stage-specific action execution
func (rsc *ReactStageController) simulateStageAction(action string, iterCtx *IterationContext) string {
	switch rsc.stageName {
	case "Initial Analysis":
		return fmt.Sprintf("Initial analysis action completed: %s", action)
	case "Security Assessment":
		return fmt.Sprintf("Security assessment performed: %s", action)
	case "Risk Evaluation":
		return fmt.Sprintf("Risk evaluation completed: %s", action)
	case "Remediation Planning":
		return fmt.Sprintf("Remediation steps identified: %s", action)
	default:
		return fmt.Sprintf("Stage action completed: %s", action)
	}
}

// generateStageThought generates stage-specific thoughts
func (rsc *ReactStageController) generateStageThought(iterCtx *IterationContext) string {
	iteration := iterCtx.CurrentIteration

	switch rsc.stageName {
	case "Initial Analysis":
		if iteration == 1 {
			return `Stage Thought: I need to perform the initial analysis of this alert. Let me examine the basic characteristics and context of the incident.

Stage Action: Examine alert metadata and basic context information`
		}
		return `Stage Result: Initial analysis indicates this is a security alert requiring detailed investigation.
Alert characteristics suggest potential security concern that needs further analysis by subsequent stages.`

	case "Security Assessment":
		if iteration == 1 {
			return `Stage Thought: Based on the initial analysis, I need to perform a comprehensive security assessment to understand the threat level and potential impact.

Stage Action: Conduct security-focused analysis of the alert data`
		}
		return `Stage Result: Security assessment reveals moderate risk level.
The alert indicates potential security implications that require remediation action.
No immediate critical threats detected, but preventive measures recommended.`

	case "Remediation Planning":
		if iteration == 1 {
			return `Stage Thought: With the security assessment complete, I need to develop specific remediation steps and recommendations.

Stage Action: Develop actionable remediation plan based on assessment findings`
		}
		return `Stage Result: Remediation plan developed with specific action items:
1. Implement security policy adjustments
2. Monitor for similar patterns
3. Update detection rules as needed
4. Schedule follow-up review in 24 hours`

	default:
		return fmt.Sprintf(`Stage Thought: Processing stage "%s" with goal: %s

Stage Action: Execute stage-specific analysis

Stage Result: Stage %s completed successfully with findings relevant to the overall alert analysis.`,
			rsc.stageName, rsc.stageGoal, rsc.stageName)
	}
}

// isStageComplete checks if the stage goal has been achieved
func (rsc *ReactStageController) isStageComplete(response string) bool {
	stageMarkers := []string{
		"Stage Result:",
		"Stage Complete:",
		"Stage Analysis Complete",
		fmt.Sprintf("%s Complete", rsc.stageName),
	}

	lowerResponse := strings.ToLower(response)
	for _, marker := range stageMarkers {
		if strings.Contains(lowerResponse, strings.ToLower(marker)) {
			return true
		}
	}

	return false
}

// containsStageAction checks if the response contains stage actions
func (rsc *ReactStageController) containsStageAction(response string) bool {
	return strings.Contains(strings.ToLower(response), "stage action:")
}

// extractStageResult extracts the result for this specific stage
func (rsc *ReactStageController) extractStageResult(response string) string {
	lines := strings.Split(response, "\n")
	inStageResult := false
	var result []string

	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "stage result:") {
			inStageResult = true
			// Include the text after "Stage Result:"
			if colonIndex := strings.Index(line, ":"); colonIndex != -1 && len(line) > colonIndex+1 {
				remainingText := strings.TrimSpace(line[colonIndex+1:])
				if remainingText != "" {
					result = append(result, remainingText)
				}
			}
			continue
		}

		if inStageResult {
			result = append(result, line)
		}
	}

	if len(result) > 0 {
		return strings.Join(result, "\n")
	}

	return response
}

// extractBestStageAnalysis extracts the best available stage analysis
func (rsc *ReactStageController) extractBestStageAnalysis(iterCtx *IterationContext) string {
	// Look for the most recent stage-related content
	for i := len(iterCtx.ConversationHistory) - 1; i >= 0; i-- {
		entry := iterCtx.ConversationHistory[i]
		if entry.Role == "assistant" &&
		   (strings.Contains(strings.ToLower(entry.Content), "stage") ||
			strings.Contains(strings.ToLower(entry.Content), rsc.stageName)) {
			return entry.Content
		}
	}

	return fmt.Sprintf("Stage %s analysis completed. Goal: %s", rsc.stageName, rsc.stageGoal)
}

// shouldContinueStage determines if stage iteration should continue
func (rsc *ReactStageController) shouldContinueStage(iterCtx *IterationContext, lastResponse string) bool {
	// Check stage-specific completion criteria
	if rsc.isStageComplete(lastResponse) {
		return false
	}

	// Check iteration limits
	if iterCtx.CurrentIteration >= iterCtx.MaxIterations {
		return false
	}

	// Stage-specific logic can be added here
	return true
}

// GetStageName returns the stage name
func (rsc *ReactStageController) GetStageName() string {
	return rsc.stageName
}

// GetStageGoal returns the stage goal
func (rsc *ReactStageController) GetStageGoal() string {
	return rsc.stageGoal
}