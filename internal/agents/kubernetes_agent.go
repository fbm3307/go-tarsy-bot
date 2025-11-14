package agents

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)


// KubernetesAgent specializes in processing Kubernetes-related alerts
// Extends BaseAgent with Kubernetes-specific analysis capabilities
type KubernetesAgent struct {
	*BaseAgent
	kubeConfig          *KubernetesConfig
	toolsEnabled        bool
	llmIntegration      LLMIntegrationInterface
	mcpServerRegistry   *mcp.MCPServerRegistry
	logger              *zap.Logger
}

// KubernetesConfig contains Kubernetes-specific configuration
type KubernetesConfig struct {
	KubeconfigPath string   `json:"kubeconfig_path"`
	Namespaces     []string `json:"namespaces"`
	EnableTools    bool     `json:"enable_tools"`
	ClusterName    string   `json:"cluster_name"`
}

// NewKubernetesAgent creates a new Kubernetes agent
func NewKubernetesAgent(
	settings *AgentSettings,
	kubeConfig *KubernetesConfig,
	llmIntegration LLMIntegrationInterface,
	mcpServerRegistry *mcp.MCPServerRegistry,
	logger *zap.Logger,
) *KubernetesAgent {
	capabilities := []string{
		"kubernetes_analysis",
		"pod_inspection",
		"resource_monitoring",
		"log_analysis",
		"security_assessment",
		"kubectl_execution",
		"resource_troubleshooting",
	}

	baseAgent := NewBaseAgent("kubernetes", capabilities, settings)

	return &KubernetesAgent{
		BaseAgent:         baseAgent,
		kubeConfig:        kubeConfig,
		toolsEnabled:      kubeConfig != nil && kubeConfig.EnableTools,
		llmIntegration:    llmIntegration,
		mcpServerRegistry: mcpServerRegistry,
		logger:            logger,
	}
}

// ProcessAlert overrides the base ProcessAlert with Kubernetes-specific logic using ReAct pattern
func (ka *KubernetesAgent) ProcessAlert(ctx context.Context, alert *models.Alert, chainCtx *models.ChainContext) (*models.AgentExecutionResult, error) {
	ka.logger.Info("Starting Kubernetes agent processing",
		zap.String("alert_type", alert.AlertType),
		zap.String("session_id", chainCtx.SessionID))

	// Create execution context with timeout
	ctx, cancel := context.WithTimeout(ctx, ka.settings.TimeoutDuration)
	defer cancel()

	// Extract Kubernetes-specific information from the alert
	kubeContext, err := ka.extractKubernetesContext(alert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract Kubernetes context: %w", err)
	}

	// Execute ReAct pattern: Reasoning + Acting iteratively
	finalAnalysis, err := ka.executeReActPattern(ctx, alert, kubeContext, chainCtx)
	if err != nil {
		return nil, fmt.Errorf("ReAct execution failed: %w", err)
	}

	// Create execution result
	result := &models.AgentExecutionResult{
		Status:        models.StageStatusCompleted,
		AgentName:     "kubernetes",
		TimestampUs:   time.Now().UnixMicro(),
		ResultSummary: stringPtr(fmt.Sprintf("Kubernetes analysis completed for %s in namespace %s",
			kubeContext.ResourceType, kubeContext.Namespace)),
		FinalAnalysis: &finalAnalysis,
	}

	ka.logger.Info("Kubernetes agent processing completed",
		zap.String("session_id", chainCtx.SessionID),
		zap.Int("analysis_length", len(finalAnalysis)))

	return result, nil
}

// executeReActPattern implements the ReAct (Reasoning + Acting) pattern for Kubernetes analysis
func (ka *KubernetesAgent) executeReActPattern(ctx context.Context, alert *models.Alert, kubeCtx *KubernetesContext, chainCtx *models.ChainContext) (string, error) {
	maxIterations := ka.settings.MaxIterations
	conversationHistory := []Message{}

	// Build initial system prompt
	systemPrompt := ka.buildSystemPrompt(alert, kubeCtx, chainCtx)

	// Start with initial reasoning
	initialThought := ka.buildInitialThought(alert, kubeCtx)

	conversationHistory = append(conversationHistory, Message{
		Role:    "user",
		Content: initialThought,
	})

	for iteration := 0; iteration < maxIterations; iteration++ {
		ka.logger.Debug("Starting ReAct iteration",
			zap.Int("iteration", iteration),
			zap.String("session_id", chainCtx.SessionID))

		// Reasoning: Ask LLM what to do next
		llmRequest := &EnhancedGenerateRequest{
			GenerateWithToolsRequest: &GenerateWithToolsRequest{
				GenerateRequest: &GenerateRequest{
					Messages:     conversationHistory,
					SystemPrompt: &systemPrompt,
					Model:        "gpt-4",
					Temperature:  float64Ptr(float64(ka.settings.Temperature)),
					MaxTokens:    &ka.settings.MaxTokens,
				},
				EnableTools: ka.toolsEnabled,
			},
			SessionID:        chainCtx.SessionID,
			AgentType:        "kubernetes",
			IterationIndex:   &iteration,
			TrackCost:        true,
			EstimateCost:     true,
		}

		llmResponse, err := ka.llmIntegration.GenerateWithTracking(ctx, llmRequest)
		if err != nil {
			return "", fmt.Errorf("LLM generation failed at iteration %d: %w", iteration, err)
		}

		// Add LLM response to conversation
		conversationHistory = append(conversationHistory, Message{
			Role:    "assistant",
			Content: llmResponse.Content,
		})

		// Acting: Execute any tools the LLM requested
		if ka.toolsEnabled && ka.needsToolExecution(llmResponse.Content) {
			toolResults, err := ka.executeKubernetesTools(ctx, llmResponse.Content, kubeCtx, chainCtx)
			if err != nil {
				ka.logger.Warn("Tool execution failed",
					zap.Error(err),
					zap.Int("iteration", iteration))
				// Continue with analysis even if tools fail
				conversationHistory = append(conversationHistory, Message{
					Role:    "user",
					Content: fmt.Sprintf("Tool execution failed: %v. Please continue analysis without tools.", err),
				})
			} else if toolResults != "" {
				// Add tool results to conversation
				conversationHistory = append(conversationHistory, Message{
					Role:    "user",
					Content: fmt.Sprintf("Tool execution results:\n%s\n\nPlease analyze these results and continue.", toolResults),
				})
			}
		}

		// Check if we have a final conclusion
		if ka.hasReachedConclusion(llmResponse.Content) {
			ka.logger.Info("ReAct pattern concluded",
				zap.Int("iterations_used", iteration+1),
				zap.String("session_id", chainCtx.SessionID))
			return ka.extractFinalAnalysis(conversationHistory), nil
		}
	}

	// If we've reached max iterations, ask for final summary
	finalPrompt := "Please provide a final comprehensive analysis and recommendations based on all the information gathered above."
	conversationHistory = append(conversationHistory, Message{
		Role:    "user",
		Content: finalPrompt,
	})

	finalRequest := &EnhancedGenerateRequest{
		GenerateWithToolsRequest: &GenerateWithToolsRequest{
			GenerateRequest: &GenerateRequest{
				Messages:     conversationHistory,
				SystemPrompt: &systemPrompt,
				Model:        "gpt-4",
				Temperature:  float64Ptr(float64(ka.settings.Temperature)),
				MaxTokens:    &ka.settings.MaxTokens,
			},
			EnableTools: false, // No tools for final summary
		},
		SessionID:     chainCtx.SessionID,
		AgentType:     "kubernetes",
		TrackCost:     true,
		EstimateCost:  true,
	}

	finalResponse, err := ka.llmIntegration.GenerateWithTracking(ctx, finalRequest)
	if err != nil {
		return "", fmt.Errorf("final LLM generation failed: %w", err)
	}

	ka.logger.Info("ReAct pattern completed with max iterations",
		zap.Int("max_iterations", maxIterations),
		zap.String("session_id", chainCtx.SessionID))

	return finalResponse.Content, nil
}


// KubernetesContext represents extracted Kubernetes information from alerts
type KubernetesContext struct {
	Namespace    string            `json:"namespace"`
	PodName      string            `json:"pod_name,omitempty"`
	ServiceName  string            `json:"service_name,omitempty"`
	ResourceType string            `json:"resource_type"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// extractKubernetesContext extracts Kubernetes-specific information from the alert
func (ka *KubernetesAgent) extractKubernetesContext(alert *models.Alert) (*KubernetesContext, error) {
	context := &KubernetesContext{
		ResourceType: "unknown",
		Labels:       make(map[string]string),
		Annotations:  make(map[string]string),
	}

	// Extract information from alert data based on alert type
	if alertData := alert.Data; alertData != nil {
		if namespace, exists := alertData["namespace"]; exists {
			if ns, ok := namespace.(string); ok {
				context.Namespace = ns
			}
		}

		if podName, exists := alertData["pod_name"]; exists {
			if pod, ok := podName.(string); ok {
				context.PodName = pod
				context.ResourceType = "pod"
			}
		}

		if serviceName, exists := alertData["service_name"]; exists {
			if svc, ok := serviceName.(string); ok {
				context.ServiceName = svc
				context.ResourceType = "service"
			}
		}

		// Extract labels if present
		if labels, exists := alertData["labels"]; exists {
			if labelMap, ok := labels.(map[string]any); ok {
				for k, v := range labelMap {
					if str, ok := v.(string); ok {
						context.Labels[k] = str
					}
				}
			}
		}
	}

	return context, nil
}

// analyzeKubernetesAlert performs Kubernetes-specific analysis
func (ka *KubernetesAgent) analyzeKubernetesAlert(ctx context.Context, alert *models.Alert, kubeCtx *KubernetesContext) (string, float64, error) {
	analysis := fmt.Sprintf(`Kubernetes Alert Analysis:

Alert Type: %s
Cluster: %s
Namespace: %s
Resource: %s (%s)

Security Assessment:`,
		alert.Type,
		ka.kubeConfig.ClusterName,
		kubeCtx.Namespace,
		kubeCtx.ResourceType,
		ka.getResourceIdentifier(kubeCtx))

	confidence := 0.7

	// Analyze based on resource type
	switch kubeCtx.ResourceType {
	case "pod":
		analysis += ka.analyzePodSecurity(kubeCtx)
		confidence = 0.8
	case "service":
		analysis += ka.analyzeServiceSecurity(kubeCtx)
		confidence = 0.75
	default:
		analysis += "\n- General Kubernetes resource analysis"
		confidence = 0.6
	}

	// Check for high-risk indicators
	if ka.hasHighRiskIndicators(alert, kubeCtx) {
		analysis += "\n⚠️  HIGH RISK INDICATORS DETECTED"
		confidence = 0.9
	}

	return analysis, confidence, nil
}

// analyzePodSecurity provides pod-specific security analysis
func (ka *KubernetesAgent) analyzePodSecurity(kubeCtx *KubernetesContext) string {
	analysis := "\n\nPod Security Analysis:"

	// Check for privileged containers
	if ka.hasPrivilegedLabels(kubeCtx.Labels) {
		analysis += "\n- ⚠️  Potentially privileged container detected"
	}

	// Check namespace security posture
	if kubeCtx.Namespace == "kube-system" || kubeCtx.Namespace == "kube-public" {
		analysis += "\n- ⚠️  Alert in system namespace - elevated attention required"
	}

	analysis += "\n- Evaluating container security context"
	analysis += "\n- Checking resource limits and requests"
	analysis += "\n- Analyzing network policies impact"

	return analysis
}

// analyzeServiceSecurity provides service-specific security analysis
func (ka *KubernetesAgent) analyzeServiceSecurity(kubeCtx *KubernetesContext) string {
	analysis := "\n\nService Security Analysis:"
	analysis += "\n- Checking service exposure and network policies"
	analysis += "\n- Evaluating load balancer security"
	analysis += "\n- Analyzing ingress/egress traffic patterns"

	return analysis
}

// hasHighRiskIndicators checks for high-risk security indicators
func (ka *KubernetesAgent) hasHighRiskIndicators(alert *models.Alert, kubeCtx *KubernetesContext) bool {
	// Check for system namespaces
	systemNamespaces := []string{"kube-system", "kube-public", "kube-node-lease"}
	for _, ns := range systemNamespaces {
		if kubeCtx.Namespace == ns {
			return true
		}
	}

	// Check for privileged indicators
	if ka.hasPrivilegedLabels(kubeCtx.Labels) {
		return true
	}

	// Check alert severity
	severity := alert.GetSeverity()
	if severity == "critical" || severity == "high" {
		return true
	}

	return false
}

// hasPrivilegedLabels checks for labels indicating privileged access
func (ka *KubernetesAgent) hasPrivilegedLabels(labels map[string]string) bool {
	privilegedIndicators := []string{"privileged", "root", "admin", "system"}

	for _, value := range labels {
		for _, indicator := range privilegedIndicators {
			if value == indicator {
				return true
			}
		}
	}

	return false
}

// generateKubernetesSuggestions creates actionable recommendations
func (ka *KubernetesAgent) generateKubernetesSuggestions(kubeCtx *KubernetesContext, analysis string) []string {
	suggestions := []string{}

	// Resource-specific suggestions
	switch kubeCtx.ResourceType {
	case "pod":
		suggestions = append(suggestions,
			"Review pod security context and capabilities",
			"Check for latest container image vulnerabilities",
			"Validate resource limits and requests",
		)
	case "service":
		suggestions = append(suggestions,
			"Review service network policies",
			"Validate ingress/egress rules",
			"Check load balancer security configuration",
		)
	}

	// General Kubernetes suggestions
	suggestions = append(suggestions,
		"Review RBAC permissions for affected resources",
		"Check compliance with pod security standards",
		"Validate network segmentation",
	)

	return suggestions
}

// getResourceIdentifier returns a human-readable resource identifier
func (ka *KubernetesAgent) getResourceIdentifier(kubeCtx *KubernetesContext) string {
	switch kubeCtx.ResourceType {
	case "pod":
		return kubeCtx.PodName
	case "service":
		return kubeCtx.ServiceName
	default:
		return "unknown"
	}
}

// ValidateConfiguration validates Kubernetes agent configuration
func (ka *KubernetesAgent) ValidateConfiguration() error {
	// Validate base configuration
	if err := ka.BaseAgent.ValidateConfiguration(); err != nil {
		return err
	}

	// Validate Kubernetes-specific configuration
	if ka.kubeConfig == nil {
		return NewAgentError("configuration", "Kubernetes configuration is required")
	}

	if ka.kubeConfig.ClusterName == "" {
		return NewAgentError("configuration", "cluster name is required")
	}

	return nil
}

// MCPServers returns the list of MCP servers this agent uses (matches Python abstract method)
func (ka *KubernetesAgent) MCPServers() []string {
	return []string{
		"kubernetes-server",
		"kubectl-server",
		"security-server",
	}
}

// CustomInstructions returns agent-specific instructions (matches Python abstract method)
func (ka *KubernetesAgent) CustomInstructions() string {
	return `You are a Kubernetes security expert specializing in container orchestration and incident response.

Focus on:
1. Pod security contexts and capabilities
2. Resource quotas and limits
3. Network policies and segmentation
4. RBAC and service account permissions
5. Container image security and vulnerabilities
6. Cluster security posture

Always prioritize security implications and provide actionable remediation steps.`
}

// Helper methods for ReAct pattern

// buildSystemPrompt creates the system prompt for the LLM
func (ka *KubernetesAgent) buildSystemPrompt(alert *models.Alert, kubeCtx *KubernetesContext, chainCtx *models.ChainContext) string {
	systemPrompt := ka.CustomInstructions()

	// Add context-specific information
	systemPrompt += fmt.Sprintf(`

CURRENT CONTEXT:
- Alert Type: %s
- Cluster: %s
- Namespace: %s
- Resource Type: %s
- Session ID: %s

AVAILABLE TOOLS:
You have access to kubectl and Kubernetes APIs through the following MCP servers:
- kubernetes-server: Get cluster state, resource status
- kubectl-server: Execute kubectl commands
- security-server: Security analysis and compliance checks

ANALYSIS APPROACH:
1. First, understand the alert context and severity
2. Use available tools to gather additional information
3. Analyze security implications and root causes
4. Provide specific, actionable recommendations
5. Include kubectl commands where appropriate

When you need to use tools, clearly state what you want to investigate and I will execute the appropriate commands.
If you have enough information to provide a final analysis, conclude with "FINAL ANALYSIS:" followed by your comprehensive assessment.`,
		alert.AlertType,
		ka.kubeConfig.ClusterName,
		kubeCtx.Namespace,
		kubeCtx.ResourceType,
		chainCtx.SessionID)

	if chainCtx.RunbookContent != nil && *chainCtx.RunbookContent != "" {
		systemPrompt += fmt.Sprintf(`

RUNBOOK CONTENT:
%s

Please incorporate relevant runbook guidance into your analysis.`, *chainCtx.RunbookContent)
	}

	return systemPrompt
}

// buildInitialThought creates the initial reasoning prompt
func (ka *KubernetesAgent) buildInitialThought(alert *models.Alert, kubeCtx *KubernetesContext) string {
	return fmt.Sprintf(`I need to analyze this Kubernetes alert:

Alert Type: %s
Namespace: %s
Resource: %s (%s)
Alert Data: %v

Let me start by understanding the current state of the affected resources and checking for any security implications.

What should I investigate first to understand the root cause of this alert?`,
		alert.AlertType,
		kubeCtx.Namespace,
		kubeCtx.ResourceType,
		ka.getResourceIdentifier(kubeCtx),
		alert.Data)
}

// needsToolExecution checks if the LLM response indicates tool usage is needed
func (ka *KubernetesAgent) needsToolExecution(content string) bool {
	toolIndicators := []string{
		"kubectl",
		"check the",
		"get the status",
		"investigate",
		"examine",
		"look at the",
		"need to see",
		"should check",
	}

	contentLower := strings.ToLower(content)
	for _, indicator := range toolIndicators {
		if strings.Contains(contentLower, indicator) {
			return true
		}
	}

	return false
}

// hasReachedConclusion checks if the LLM has provided a final analysis
func (ka *KubernetesAgent) hasReachedConclusion(content string) bool {
	conclusionIndicators := []string{
		"FINAL ANALYSIS:",
		"final analysis",
		"In conclusion",
		"Based on all the information",
		"comprehensive analysis complete",
		"final recommendations",
	}

	contentLower := strings.ToLower(content)
	for _, indicator := range conclusionIndicators {
		if strings.Contains(contentLower, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// executeKubernetesTools executes Kubernetes-specific tools based on LLM requests
func (ka *KubernetesAgent) executeKubernetesTools(ctx context.Context, llmContent string, kubeCtx *KubernetesContext, chainCtx *models.ChainContext) (string, error) {
	results := []string{}

	// Parse the LLM content to determine what tools to run
	toolCommands := ka.parseToolRequests(llmContent, kubeCtx)

	for _, command := range toolCommands {
		ka.logger.Debug("Executing Kubernetes tool",
			zap.String("command", command.Tool),
			zap.String("session_id", chainCtx.SessionID))

		result, err := ka.mcpServerRegistry.ExecuteToolOnServer(ctx, command.Server, command.Tool, command.Parameters)
		if err != nil {
			ka.logger.Error("Tool execution failed",
				zap.String("tool", command.Tool),
				zap.String("server", command.Server),
				zap.Error(err))
			results = append(results, fmt.Sprintf("Tool %s failed: %v", command.Tool, err))
		} else if result != nil && result.Success {
			results = append(results, fmt.Sprintf("Tool %s output:\n%s", command.Tool, result.Content))
		} else if result != nil {
			results = append(results, fmt.Sprintf("Tool %s failed: %s", command.Tool, result.Error))
		}
	}

	if len(results) == 0 {
		return "", nil
	}

	return strings.Join(results, "\n\n"), nil
}

// ToolCommand represents a tool execution request
type ToolCommand struct {
	Server     string
	Tool       string
	Parameters map[string]interface{}
}

// parseToolRequests parses the LLM content to extract tool execution requests
func (ka *KubernetesAgent) parseToolRequests(content string, kubeCtx *KubernetesContext) []ToolCommand {
	commands := []ToolCommand{}

	contentLower := strings.ToLower(content)

	// Check for kubectl commands
	if strings.Contains(contentLower, "kubectl get") || strings.Contains(contentLower, "get the status") {
		if kubeCtx.PodName != "" {
			commands = append(commands, ToolCommand{
				Server: "kubectl-server",
				Tool:   "get_pod",
				Parameters: map[string]interface{}{
					"name":      kubeCtx.PodName,
					"namespace": kubeCtx.Namespace,
				},
			})
		}
		if kubeCtx.ServiceName != "" {
			commands = append(commands, ToolCommand{
				Server: "kubectl-server",
				Tool:   "get_service",
				Parameters: map[string]interface{}{
					"name":      kubeCtx.ServiceName,
					"namespace": kubeCtx.Namespace,
				},
			})
		}
	}

	// Check for logs request
	if strings.Contains(contentLower, "logs") || strings.Contains(contentLower, "check logs") {
		if kubeCtx.PodName != "" {
			commands = append(commands, ToolCommand{
				Server: "kubectl-server",
				Tool:   "get_logs",
				Parameters: map[string]interface{}{
					"pod":       kubeCtx.PodName,
					"namespace": kubeCtx.Namespace,
					"lines":     100,
				},
			})
		}
	}

	// Check for events request
	if strings.Contains(contentLower, "events") || strings.Contains(contentLower, "what happened") {
		commands = append(commands, ToolCommand{
			Server: "kubernetes-server",
			Tool:   "get_events",
			Parameters: map[string]interface{}{
				"namespace": kubeCtx.Namespace,
			},
		})
	}

	// Check for security analysis request
	if strings.Contains(contentLower, "security") || strings.Contains(contentLower, "compliance") {
		commands = append(commands, ToolCommand{
			Server: "security-server",
			Tool:   "security_scan",
			Parameters: map[string]interface{}{
				"namespace":     kubeCtx.Namespace,
				"resource_type": kubeCtx.ResourceType,
			},
		})
	}

	return commands
}

// extractFinalAnalysis extracts the final analysis from the conversation history
func (ka *KubernetesAgent) extractFinalAnalysis(conversationHistory []Message) string {
	// Look for the last assistant message that contains substantial analysis
	for i := len(conversationHistory) - 1; i >= 0; i-- {
		if conversationHistory[i].Role == "assistant" && len(conversationHistory[i].Content) > 100 {
			return conversationHistory[i].Content
		}
	}

	// Fallback: combine the last few messages
	if len(conversationHistory) >= 2 {
		lastMessages := conversationHistory[len(conversationHistory)-2:]
		combined := []string{}
		for _, msg := range lastMessages {
			if msg.Role == "assistant" {
				combined = append(combined, msg.Content)
			}
		}
		return strings.Join(combined, "\n\n")
	}

	return "Analysis completed but no detailed output available."
}

// Helper functions

// float64Ptr returns a pointer to a float64 value
func float64Ptr(f float64) *float64 {
	return &f
}