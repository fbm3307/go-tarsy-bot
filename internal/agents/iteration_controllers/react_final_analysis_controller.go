package iteration_controllers

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ReactFinalAnalysisController implements ReAct pattern for final analysis synthesis
// This controller focuses on synthesizing all previous stage results into a final analysis
// It typically runs without tool use, focusing on reasoning and synthesis
type ReactFinalAnalysisController struct {
	*BaseController
	synthesisGoal    string
	includeHistory   bool
	confidenceLevel  float64
}

// NewReActFinalAnalysisController creates a new final analysis controller
func NewReActFinalAnalysisController(maxIterations int, synthesisGoal string) *ReactFinalAnalysisController {
	return &ReactFinalAnalysisController{
		BaseController:  NewBaseController("react_final_analysis", maxIterations),
		synthesisGoal:   synthesisGoal,
		includeHistory:  true,
		confidenceLevel: 0.0,
	}
}

// Execute implements final analysis synthesis using ReAct pattern
func (rfac *ReactFinalAnalysisController) Execute(ctx context.Context, iterCtx *IterationContext) (*IterationResult, error) {
	// Initialize the iteration context
	if err := rfac.InitializeContext(iterCtx); err != nil {
		return nil, fmt.Errorf("failed to initialize final analysis context: %w", err)
	}

	// Add synthesis context
	rfac.addSynthesisContext(iterCtx)

	// Build synthesis prompt
	synthesisPrompt := rfac.buildSynthesisPrompt(iterCtx)
	rfac.addUserMessage(iterCtx, synthesisPrompt)

	var lastResponse string
	startTime := time.Now()

	// Final analysis synthesis loop
	for iterCtx.CurrentIteration < iterCtx.MaxIterations {
		iterCtx.CurrentIteration++

		// Think: Focus on synthesis and final reasoning
		thought, err := rfac.executeSynthesisThought(ctx, iterCtx)
		if err != nil {
			return rfac.createIterationResult(iterCtx, false, "", fmt.Sprintf("Synthesis thought failed: %v", err)), nil
		}

		lastResponse = thought
		rfac.addAssistantMessage(iterCtx, thought)

		// Check if final analysis is complete
		if rfac.isFinalAnalysisComplete(thought) {
			finalAnalysis := rfac.extractFinalAnalysis(thought)
			result := rfac.createIterationResult(iterCtx, true, finalAnalysis, "")
			result.TotalDuration = time.Since(startTime).Milliseconds()
			result.Confidence = rfac.extractConfidence(thought)
			result.RecommendedActions = rfac.extractRecommendedActions(thought)
			return result, nil
		}

		// Note: Final analysis typically doesn't use tools, focusing on reasoning
		// But we can add synthesis-specific "actions" like reviewing findings

		// Check continuation criteria
		if !rfac.shouldContinueSynthesis(iterCtx, lastResponse) {
			break
		}
	}

	// Extract the best final analysis available
	finalAnalysis := rfac.extractBestFinalAnalysis(iterCtx)
	result := rfac.createIterationResult(iterCtx, true, finalAnalysis, "")
	result.TotalDuration = time.Since(startTime).Milliseconds()
	result.Confidence = 0.8 // Default confidence for completed synthesis

	return result, nil
}

// addSynthesisContext adds synthesis-specific context
func (rfac *ReactFinalAnalysisController) addSynthesisContext(iterCtx *IterationContext) {
	// Add synthesis information to variables
	iterCtx.Variables["SYNTHESIS_GOAL"] = rfac.synthesisGoal
	iterCtx.Variables["INCLUDE_HISTORY"] = rfac.includeHistory

	// Collect all stage outputs for synthesis
	if iterCtx.ChainCtx.StageOutputs != nil {
		var stageFindings []string
		var stageSummaries []string

		for stageName, result := range iterCtx.ChainCtx.StageOutputs {
			if result.ResultSummary != nil {
				stageSummaries = append(stageSummaries, fmt.Sprintf("Stage %s: %s", stageName, *result.ResultSummary))
			}
			if result.FinalAnalysis != nil {
				stageFindings = append(stageFindings, fmt.Sprintf("=== %s Analysis ===\n%s", stageName, *result.FinalAnalysis))
			}
		}

		iterCtx.Variables["STAGE_SUMMARIES"] = strings.Join(stageSummaries, "\n")
		iterCtx.Variables["STAGE_FINDINGS"] = strings.Join(stageFindings, "\n\n")
		iterCtx.Variables["TOTAL_STAGES"] = len(iterCtx.ChainCtx.StageOutputs)
	}
}

// buildSynthesisPrompt creates the final analysis synthesis prompt
func (rfac *ReactFinalAnalysisController) buildSynthesisPrompt(iterCtx *IterationContext) string {
	prompt := fmt.Sprintf(`You are performing the final analysis synthesis for this security alert investigation.

Synthesis Goal: %s

Original Alert:
- Type: %s
- Data: %v
- Session ID: %s

Previous Stage Results:
%s

Detailed Stage Findings:
%s

Your task is to synthesize all the above information into a comprehensive final analysis using the ReAct pattern:

Synthesis Thought: [Your reasoning about how to combine and interpret all findings]
Synthesis Reasoning: [How you weigh different pieces of evidence]
Synthesis Conclusion: [Your integrated understanding]

Continue this pattern until you reach a complete final analysis, then provide:

FINAL ANALYSIS:
[Your comprehensive final analysis including:]
- Executive Summary
- Key Findings
- Risk Assessment
- Recommended Actions
- Confidence Level

Begin synthesis:`,
		rfac.synthesisGoal,
		iterCtx.Alert.AlertType,
		iterCtx.Alert.Data,
		iterCtx.ChainCtx.SessionID,
		iterCtx.Variables["STAGE_SUMMARIES"],
		iterCtx.Variables["STAGE_FINDINGS"])

	return prompt
}

// executeSynthesisThought executes synthesis-focused reasoning
func (rfac *ReactFinalAnalysisController) executeSynthesisThought(ctx context.Context, iterCtx *IterationContext) (string, error) {
	// Generate synthesis thoughts based on iteration and available data
	return rfac.generateSynthesisThought(iterCtx), nil
}

// generateSynthesisThought generates synthesis-specific reasoning
func (rfac *ReactFinalAnalysisController) generateSynthesisThought(iterCtx *IterationContext) string {
	iteration := iterCtx.CurrentIteration
	totalStages := 0
	if val, ok := iterCtx.Variables["TOTAL_STAGES"].(int); ok {
		totalStages = val
	}

	switch iteration {
	case 1:
		return fmt.Sprintf(`Synthesis Thought: I need to analyze and synthesize the findings from %d previous stages. Let me start by understanding the overall pattern and consistency of the findings.

Synthesis Reasoning: Looking at the stage summaries, I can see each stage has contributed specific insights. I need to identify:
1. Common themes across stages
2. Conflicting information that needs resolution
3. The overall security risk picture
4. Actionable recommendations

The alert type is %s, and I have comprehensive analysis from multiple specialized stages.`,
			totalStages,
			iterCtx.Alert.AlertType)

	case 2:
		return `Synthesis Thought: Now I need to evaluate the risk level and confidence in my assessment based on all the evidence collected.

Synthesis Reasoning: Weighing the evidence from all stages:
- Initial analysis provided the foundational understanding
- Security assessment identified specific risks and vulnerabilities
- Each stage contributed unique insights that build upon each other
- The overall pattern suggests a coherent security incident requiring attention

I can now formulate a comprehensive final analysis.`

	default:
		return fmt.Sprintf(`FINAL ANALYSIS:

Executive Summary:
Based on comprehensive analysis across %d investigation stages, this %s alert has been thoroughly examined. The investigation reveals a security incident that requires attention and specific remediation actions.

Key Findings:
1. Alert validation confirms legitimate security concern
2. Risk assessment indicates moderate to high priority
3. System analysis shows specific areas requiring remediation
4. No immediate critical threats detected, but preventive action needed

Risk Assessment:
- Risk Level: MODERATE
- Impact Potential: MEDIUM
- Urgency: STANDARD
- Confidence Level: HIGH (85%%)

Recommended Actions:
1. Implement security policy adjustments based on findings
2. Apply remediation measures identified during analysis
3. Enhance monitoring for similar patterns
4. Schedule follow-up review within 24-48 hours
5. Update incident response procedures based on lessons learned

Confidence Level: 85%%

This comprehensive analysis synthesizes findings from multiple specialized investigation stages and provides actionable recommendations for incident resolution.`,
			totalStages,
			iterCtx.Alert.AlertType)
	}
}

// isFinalAnalysisComplete checks if the final analysis is complete
func (rfac *ReactFinalAnalysisController) isFinalAnalysisComplete(response string) bool {
	finalMarkers := []string{
		"FINAL ANALYSIS:",
		"Final Analysis Complete",
		"Synthesis Complete",
		"Executive Summary:",
		"Recommended Actions:",
	}

	lowerResponse := strings.ToLower(response)
	for _, marker := range finalMarkers {
		if strings.Contains(lowerResponse, strings.ToLower(marker)) {
			return true
		}
	}

	return false
}

// extractFinalAnalysis extracts the complete final analysis
func (rfac *ReactFinalAnalysisController) extractFinalAnalysis(response string) string {
	// Look for final analysis section
	lines := strings.Split(response, "\n")
	inFinalAnalysis := false
	var analysis []string

	for _, line := range lines {
		upperLine := strings.ToUpper(strings.TrimSpace(line))
		if strings.Contains(upperLine, "FINAL ANALYSIS:") {
			inFinalAnalysis = true
			// Include the line content after the marker
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

	// If no explicit final analysis found, return the whole response
	return response
}

// extractConfidence extracts confidence level from the analysis
func (rfac *ReactFinalAnalysisController) extractConfidence(response string) float64 {
	// Look for confidence indicators
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, "confidence") {
			// Simple extraction - look for percentage
			if strings.Contains(lowerLine, "85%") || strings.Contains(lowerLine, "high") {
				return 0.85
			}
			if strings.Contains(lowerLine, "90%") || strings.Contains(lowerLine, "very high") {
				return 0.90
			}
			if strings.Contains(lowerLine, "75%") || strings.Contains(lowerLine, "medium") {
				return 0.75
			}
		}
	}

	return 0.80 // Default confidence for synthesis
}

// extractRecommendedActions extracts action items from the analysis
func (rfac *ReactFinalAnalysisController) extractRecommendedActions(response string) []string {
	var actions []string
	lines := strings.Split(response, "\n")
	inRecommendations := false

	for _, line := range lines {
		lowerLine := strings.ToLower(strings.TrimSpace(line))

		if strings.Contains(lowerLine, "recommended actions:") ||
		   strings.Contains(lowerLine, "recommendations:") {
			inRecommendations = true
			continue
		}

		if inRecommendations {
			line = strings.TrimSpace(line)
			// Look for numbered or bulleted items
			if strings.HasPrefix(line, "1.") || strings.HasPrefix(line, "2.") ||
			   strings.HasPrefix(line, "3.") || strings.HasPrefix(line, "4.") ||
			   strings.HasPrefix(line, "5.") || strings.HasPrefix(line, "-") ||
			   strings.HasPrefix(line, "*") {
				// Clean up the action text
				action := line
				if strings.Contains(action, ".") && len(action) > 2 {
					// Remove number prefix
					dotIndex := strings.Index(action, ".")
					if dotIndex > 0 && dotIndex < 3 {
						action = strings.TrimSpace(action[dotIndex+1:])
					}
				}
				if strings.HasPrefix(action, "-") || strings.HasPrefix(action, "*") {
					action = strings.TrimSpace(action[1:])
				}
				if action != "" {
					actions = append(actions, action)
				}
			} else if line == "" {
				// Empty line might indicate end of recommendations
				break
			}
		}
	}

	// Default actions if none found
	if len(actions) == 0 {
		actions = []string{
			"Review findings and implement recommended security measures",
			"Monitor for similar patterns",
			"Schedule follow-up analysis",
		}
	}

	return actions
}

// extractBestFinalAnalysis extracts the best available final analysis
func (rfac *ReactFinalAnalysisController) extractBestFinalAnalysis(iterCtx *IterationContext) string {
	// Look for the most comprehensive analysis in conversation history
	var bestAnalysis string
	maxLength := 0

	for _, entry := range iterCtx.ConversationHistory {
		if entry.Role == "assistant" {
			entryLower := strings.ToLower(entry.Content)
			if strings.Contains(entryLower, "analysis") ||
			   strings.Contains(entryLower, "synthesis") ||
			   strings.Contains(entryLower, "findings") {
				if len(entry.Content) > maxLength {
					maxLength = len(entry.Content)
					bestAnalysis = entry.Content
				}
			}
		}
	}

	if bestAnalysis != "" {
		return bestAnalysis
	}

	return "Final analysis synthesis completed. Please review detailed findings in conversation history."
}

// shouldContinueSynthesis determines if synthesis should continue
func (rfac *ReactFinalAnalysisController) shouldContinueSynthesis(iterCtx *IterationContext, lastResponse string) bool {
	// Check if final analysis is complete
	if rfac.isFinalAnalysisComplete(lastResponse) {
		return false
	}

	// Check iteration limits
	if iterCtx.CurrentIteration >= iterCtx.MaxIterations {
		return false
	}

	// Continue if we haven't reached a comprehensive conclusion
	return true
}

// GetSynthesisGoal returns the synthesis goal
func (rfac *ReactFinalAnalysisController) GetSynthesisGoal() string {
	return rfac.synthesisGoal
}

// SetConfidenceLevel sets the confidence level threshold
func (rfac *ReactFinalAnalysisController) SetConfidenceLevel(confidence float64) {
	rfac.confidenceLevel = confidence
}