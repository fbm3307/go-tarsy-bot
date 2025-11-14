package prompts

import (
	"fmt"
	"strings"
	"time"

	"github.com/codeready/go-tarsy-bot/internal/models"
)

// PromptComponents provides reusable prompt building components
type PromptComponents struct {
	headers    map[string]string
	footers    map[string]string
	sections   map[string]string
	formatters map[string]Formatter
}

// NewPromptComponents creates a new prompt components manager
func NewPromptComponents() *PromptComponents {
	pc := &PromptComponents{
		headers:    make(map[string]string),
		footers:    make(map[string]string),
		sections:   make(map[string]string),
		formatters: make(map[string]Formatter),
	}

	pc.loadDefaultComponents()
	pc.loadDefaultFormatters()

	return pc
}

// GetHeader returns a header component
func (pc *PromptComponents) GetHeader(name string) string {
	return pc.headers[name]
}

// GetFooter returns a footer component
func (pc *PromptComponents) GetFooter(name string) string {
	return pc.footers[name]
}

// GetSection returns a section component
func (pc *PromptComponents) GetSection(name string) string {
	return pc.sections[name]
}

// GetFormatter returns a formatter
func (pc *PromptComponents) GetFormatter(name string) Formatter {
	return pc.formatters[name]
}

// RegisterHeader registers a header component
func (pc *PromptComponents) RegisterHeader(name, content string) {
	pc.headers[name] = content
}

// RegisterFooter registers a footer component
func (pc *PromptComponents) RegisterFooter(name, content string) {
	pc.footers[name] = content
}

// RegisterSection registers a section component
func (pc *PromptComponents) RegisterSection(name, content string) {
	pc.sections[name] = content
}

// RegisterFormatter registers a formatter
func (pc *PromptComponents) RegisterFormatter(name string, formatter Formatter) {
	pc.formatters[name] = formatter
}

// loadDefaultComponents loads built-in prompt components
func (pc *PromptComponents) loadDefaultComponents() {
	// Headers
	pc.RegisterHeader("security_analyst", `You are an expert security analyst specializing in incident response and threat detection.`)

	pc.RegisterHeader("kubernetes_expert", `You are a Kubernetes security expert with deep knowledge of container orchestration and cluster security.`)

	pc.RegisterHeader("react_pattern", `Use the ReAct (Reasoning and Acting) pattern for systematic analysis:
1. Thought: Reason about what to investigate next
2. Action: Use available tools to gather information
3. Observation: Analyze the results
4. Repeat until you have sufficient information for conclusions`)

	// Footers
	pc.RegisterFooter("analysis_request", `Provide a comprehensive analysis with specific recommendations and risk assessment.`)

	pc.RegisterFooter("tool_availability", `Use available tools strategically. Explain your reasoning before taking actions.`)

	// Sections
	pc.RegisterSection("alert_context", `ALERT CONTEXT:
- Type: {{ALERT_TYPE}}
- Severity: {{ALERT_SEVERITY}}
- Timestamp: {{TIMESTAMP}}
- Session: {{SESSION_ID}}`)

	pc.RegisterSection("capabilities", `AGENT CAPABILITIES:
{{AGENT_CAPABILITIES}}`)

	pc.RegisterSection("tools", `AVAILABLE TOOLS:
{{AVAILABLE_TOOLS}}`)

	pc.RegisterSection("instructions", `SPECIFIC INSTRUCTIONS:
{{INSTRUCTIONS}}`)

	pc.RegisterSection("runbook", `RELEVANT RUNBOOK:
{{RUNBOOK_CONTENT}}`)
}

// loadDefaultFormatters loads built-in formatters
func (pc *PromptComponents) loadDefaultFormatters() {
	// Alert formatter
	pc.RegisterFormatter("alert", &AlertFormatter{})

	// Tool list formatter
	pc.RegisterFormatter("tools", &ToolListFormatter{})

	// Capability list formatter
	pc.RegisterFormatter("capabilities", &CapabilityListFormatter{})

	// Conversation history formatter
	pc.RegisterFormatter("conversation", &ConversationFormatter{})

	// JSON formatter
	pc.RegisterFormatter("json", &JSONFormatter{})

	// Kubernetes resource formatter
	pc.RegisterFormatter("kubernetes", &KubernetesFormatter{})
}

// AlertFormatter formats alert information for prompts
type AlertFormatter struct{}

func (af *AlertFormatter) Format(data interface{}) string {
	alert, ok := data.(*models.Alert)
	if !ok {
		return fmt.Sprintf("Invalid alert data: %v", data)
	}

	var parts []string
	parts = append(parts, fmt.Sprintf("Type: %s", alert.AlertType))
	parts = append(parts, fmt.Sprintf("Severity: %s", alert.GetSeverity()))

	if alert.Data != nil {
		parts = append(parts, fmt.Sprintf("Data: %v", alert.Data))
	}

	if alert.Timestamp != nil {
		parts = append(parts, fmt.Sprintf("Timestamp: %s", alert.Timestamp.Format(time.RFC3339)))
	}

	return strings.Join(parts, "\n")
}

// ToolListFormatter formats tool lists for prompts
type ToolListFormatter struct{}

func (tlf *ToolListFormatter) Format(data interface{}) string {
	tools, ok := data.([]string)
	if !ok {
		return fmt.Sprintf("Invalid tool data: %v", data)
	}

	if len(tools) == 0 {
		return "No tools available"
	}

	var formatted []string
	for i, tool := range tools {
		formatted = append(formatted, fmt.Sprintf("%d. %s", i+1, tool))
	}

	return strings.Join(formatted, "\n")
}

// CapabilityListFormatter formats capability lists for prompts
type CapabilityListFormatter struct{}

func (clf *CapabilityListFormatter) Format(data interface{}) string {
	capabilities, ok := data.([]string)
	if !ok {
		return fmt.Sprintf("Invalid capability data: %v", data)
	}

	if len(capabilities) == 0 {
		return "No specific capabilities"
	}

	var formatted []string
	for _, capability := range capabilities {
		formatted = append(formatted, fmt.Sprintf("- %s", capability))
	}

	return strings.Join(formatted, "\n")
}

// ConversationFormatter formats conversation history for prompts
type ConversationFormatter struct{}

func (cf *ConversationFormatter) Format(data interface{}) string {
	messages, ok := data.([]ConversationMessage)
	if !ok {
		return fmt.Sprintf("Invalid conversation data: %v", data)
	}

	if len(messages) == 0 {
		return "No conversation history"
	}

	var formatted []string
	for _, msg := range messages {
		timestamp := msg.Timestamp.Format("15:04:05")
		formatted = append(formatted, fmt.Sprintf("[%s] %s: %s", timestamp, msg.Role, msg.Content))
	}

	return strings.Join(formatted, "\n")
}

// JSONFormatter formats data as JSON for prompts
type JSONFormatter struct{}

func (jf *JSONFormatter) Format(data interface{}) string {
	// Simple JSON-like formatting
	switch v := data.(type) {
	case map[string]interface{}:
		var pairs []string
		for key, value := range v {
			pairs = append(pairs, fmt.Sprintf("  \"%s\": %v", key, value))
		}
		return "{\n" + strings.Join(pairs, ",\n") + "\n}"
	case []interface{}:
		var items []string
		for _, item := range v {
			items = append(items, fmt.Sprintf("  %v", item))
		}
		return "[\n" + strings.Join(items, ",\n") + "\n]"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// KubernetesFormatter formats Kubernetes-specific data for prompts
type KubernetesFormatter struct{}

func (kf *KubernetesFormatter) Format(data interface{}) string {
	kubeData, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Sprintf("Invalid Kubernetes data: %v", data)
	}

	var formatted []string

	if namespace, exists := kubeData["namespace"]; exists {
		formatted = append(formatted, fmt.Sprintf("Namespace: %v", namespace))
	}

	if resourceType, exists := kubeData["resource_type"]; exists {
		formatted = append(formatted, fmt.Sprintf("Resource Type: %v", resourceType))
	}

	if resourceName, exists := kubeData["resource_name"]; exists {
		formatted = append(formatted, fmt.Sprintf("Resource Name: %v", resourceName))
	}

	if labels, exists := kubeData["labels"]; exists {
		if labelMap, ok := labels.(map[string]interface{}); ok && len(labelMap) > 0 {
			var labelPairs []string
			for key, value := range labelMap {
				labelPairs = append(labelPairs, fmt.Sprintf("%s=%v", key, value))
			}
			formatted = append(formatted, fmt.Sprintf("Labels: %s", strings.Join(labelPairs, ", ")))
		}
	}

	if len(formatted) == 0 {
		return "No Kubernetes context available"
	}

	return strings.Join(formatted, "\n")
}

// BuildStandardPrompt builds a standard prompt using common components
func (pc *PromptComponents) BuildStandardPrompt(promptType string, context map[string]interface{}) string {
	var sections []string

	// Add appropriate header
	switch promptType {
	case "kubernetes":
		sections = append(sections, pc.GetHeader("kubernetes_expert"))
		sections = append(sections, pc.GetHeader("react_pattern"))
	case "security":
		sections = append(sections, pc.GetHeader("security_analyst"))
		sections = append(sections, pc.GetHeader("react_pattern"))
	default:
		sections = append(sections, pc.GetHeader("security_analyst"))
	}

	// Add context sections
	if alert, exists := context["alert"]; exists {
		alertFormatted := pc.GetFormatter("alert").Format(alert)
		sections = append(sections, "ALERT INFORMATION:\n"+alertFormatted)
	}

	if capabilities, exists := context["capabilities"]; exists {
		capFormatted := pc.GetFormatter("capabilities").Format(capabilities)
		sections = append(sections, "AGENT CAPABILITIES:\n"+capFormatted)
	}

	if tools, exists := context["tools"]; exists {
		toolFormatted := pc.GetFormatter("tools").Format(tools)
		sections = append(sections, "AVAILABLE TOOLS:\n"+toolFormatted)
	}

	if instructions, exists := context["instructions"]; exists {
		sections = append(sections, fmt.Sprintf("INSTRUCTIONS:\n%v", instructions))
	}

	// Add footer
	sections = append(sections, pc.GetFooter("analysis_request"))
	sections = append(sections, pc.GetFooter("tool_availability"))

	return strings.Join(sections, "\n\n")
}

// GetComponentNames returns all available component names
func (pc *PromptComponents) GetComponentNames() map[string][]string {
	headerNames := make([]string, 0, len(pc.headers))
	for name := range pc.headers {
		headerNames = append(headerNames, name)
	}

	footerNames := make([]string, 0, len(pc.footers))
	for name := range pc.footers {
		footerNames = append(footerNames, name)
	}

	sectionNames := make([]string, 0, len(pc.sections))
	for name := range pc.sections {
		sectionNames = append(sectionNames, name)
	}

	formatterNames := make([]string, 0, len(pc.formatters))
	for name := range pc.formatters {
		formatterNames = append(formatterNames, name)
	}

	return map[string][]string{
		"headers":    headerNames,
		"footers":    footerNames,
		"sections":   sectionNames,
		"formatters": formatterNames,
	}
}