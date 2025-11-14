package prompts

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/codeready/go-tarsy-bot/internal/models"
)

// PromptBuilder provides a comprehensive template-based prompt building system
// This matches the Python TARSy architecture for flexible prompt composition
type PromptBuilder struct {
	templates       map[string]*PromptTemplate
	variableResolver *TemplateVariableResolver
	components      *PromptComponents
}

// PromptTemplate represents a structured prompt template
type PromptTemplate struct {
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`         // "system", "user", "assistant", "instruction"
	Content      string                 `json:"content"`
	Variables    []string               `json:"variables"`    // List of expected variables
	Metadata     map[string]interface{} `json:"metadata"`
	Priority     int                    `json:"priority"`     // Higher priority templates override lower ones
	Conditions   []string               `json:"conditions"`   // Conditions for template activation
}

// TemplateFunction represents a function callable from templates
type TemplateFunction func(args ...interface{}) string

// Formatter formats specific data types for prompts
type Formatter interface {
	Format(data interface{}) string
}

// PromptContext contains context for prompt generation
type PromptContext struct {
	Alert              *models.Alert
	ChainContext       *models.ChainContext
	AgentType          string
	AgentCapabilities  []string
	AvailableTools     []string
	MCPServers         []string
	Instructions       string
	CustomVariables    map[string]interface{}
	IterationIndex     int
	ConversationHistory []ConversationMessage
}

// ConversationMessage represents a message in conversation history
type ConversationMessage struct {
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

// PromptResult represents the result of prompt building
type PromptResult struct {
	SystemPrompt    string                 `json:"system_prompt"`
	UserPrompt      string                 `json:"user_prompt"`
	Instructions    string                 `json:"instructions"`
	Context         map[string]interface{} `json:"context"`
	Variables       map[string]interface{} `json:"variables"`
	TemplatesUsed   []string               `json:"templates_used"`
	TokenEstimate   int                    `json:"token_estimate"`
}

// NewPromptBuilder creates a new prompt builder with default templates
func NewPromptBuilder() *PromptBuilder {
	pb := &PromptBuilder{
		templates:        make(map[string]*PromptTemplate),
		variableResolver: NewTemplateVariableResolver(),
		components:       NewPromptComponents(),
	}

	// Load default templates
	pb.loadDefaultTemplates()
	pb.loadDefaultFunctions()

	return pb
}

// BuildPrompt builds a prompt from templates and context
func (pb *PromptBuilder) BuildPrompt(templateName string, context *PromptContext) (*PromptResult, error) {
	template, exists := pb.templates[templateName]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateName)
	}

	// Prepare variables from context
	pb.prepareVariables(context)

	// Check template conditions
	if !pb.evaluateConditions(template, context) {
		return nil, fmt.Errorf("template conditions not met: %s", templateName)
	}

	// Build the prompt
	content := pb.resolveTemplate(template.Content, context)

	result := &PromptResult{
		TemplatesUsed: []string{templateName},
		Variables:     pb.variableResolver.variables,
		TokenEstimate: pb.estimateTokens(content),
	}

	// Set appropriate field based on template type
	switch template.Type {
	case "system":
		result.SystemPrompt = content
	case "user":
		result.UserPrompt = content
	case "instruction":
		result.Instructions = content
	default:
		result.UserPrompt = content
	}

	return result, nil
}

// BuildMultiLayerPrompt builds a complex prompt from multiple templates
func (pb *PromptBuilder) BuildMultiLayerPrompt(templateNames []string, context *PromptContext) (*PromptResult, error) {
	pb.prepareVariables(context)

	var systemParts []string
	var userParts []string
	var instructionParts []string
	var templatesUsed []string

	for _, templateName := range templateNames {
		template, exists := pb.templates[templateName]
		if !exists {
			continue // Skip missing templates
		}

		if !pb.evaluateConditions(template, context) {
			continue // Skip templates with unmet conditions
		}

		content := pb.resolveTemplate(template.Content, context)
		templatesUsed = append(templatesUsed, templateName)

		switch template.Type {
		case "system":
			systemParts = append(systemParts, content)
		case "user":
			userParts = append(userParts, content)
		case "instruction":
			instructionParts = append(instructionParts, content)
		}
	}

	result := &PromptResult{
		SystemPrompt:  strings.Join(systemParts, "\n\n"),
		UserPrompt:    strings.Join(userParts, "\n\n"),
		Instructions:  strings.Join(instructionParts, "\n\n"),
		Variables:     pb.variableResolver.variables,
		TemplatesUsed: templatesUsed,
	}

	result.TokenEstimate = pb.estimateTokens(result.SystemPrompt + result.UserPrompt + result.Instructions)

	return result, nil
}

// RegisterTemplate registers a new template
func (pb *PromptBuilder) RegisterTemplate(template *PromptTemplate) {
	pb.templates[template.Name] = template
}

// RegisterTemplateFromString creates and registers a template from string content
func (pb *PromptBuilder) RegisterTemplateFromString(name, templateType, content string) {
	template := &PromptTemplate{
		Name:      name,
		Type:      templateType,
		Content:   content,
		Variables: pb.extractVariables(content),
		Metadata:  make(map[string]interface{}),
		Priority:  0,
	}
	pb.RegisterTemplate(template)
}

// SetVariable sets a global variable for template resolution
func (pb *PromptBuilder) SetVariable(key string, value interface{}) {
	pb.variableResolver.SetVariable(key, value)
}

// SetVariables sets multiple variables at once
func (pb *PromptBuilder) SetVariables(variables map[string]interface{}) {
	for key, value := range variables {
		pb.variableResolver.SetVariable(key, value)
	}
}

// RegisterFunction registers a template function
func (pb *PromptBuilder) RegisterFunction(name string, fn TemplateFunction) {
	pb.variableResolver.RegisterFunction(name, fn)
}

// prepareVariables prepares variables from context for template resolution
func (pb *PromptBuilder) prepareVariables(context *PromptContext) {
	// Clear existing variables except global ones
	pb.variableResolver.ClearContextVariables()

	// Set context variables
	if context.Alert != nil {
		pb.variableResolver.SetVariable("ALERT_TYPE", context.Alert.AlertType)
		pb.variableResolver.SetVariable("ALERT_DATA", fmt.Sprintf("%v", context.Alert.Data))
		pb.variableResolver.SetVariable("ALERT_SEVERITY", context.Alert.GetSeverity())
	}

	if context.ChainContext != nil {
		pb.variableResolver.SetVariable("SESSION_ID", context.ChainContext.SessionID)
		pb.variableResolver.SetVariable("CURRENT_STAGE", context.ChainContext.CurrentStageName)
		if context.ChainContext.RunbookContent != nil {
			pb.variableResolver.SetVariable("RUNBOOK_CONTENT", *context.ChainContext.RunbookContent)
		}
	}

	pb.variableResolver.SetVariable("AGENT_TYPE", context.AgentType)
	pb.variableResolver.SetVariable("AGENT_CAPABILITIES", strings.Join(context.AgentCapabilities, ", "))
	pb.variableResolver.SetVariable("AVAILABLE_TOOLS", strings.Join(context.AvailableTools, ", "))
	pb.variableResolver.SetVariable("MCP_SERVERS", strings.Join(context.MCPServers, ", "))
	pb.variableResolver.SetVariable("INSTRUCTIONS", context.Instructions)
	pb.variableResolver.SetVariable("ITERATION_INDEX", context.IterationIndex)
	pb.variableResolver.SetVariable("TIMESTAMP", time.Now().Format(time.RFC3339))

	// Set custom variables
	for key, value := range context.CustomVariables {
		pb.variableResolver.SetVariable(key, value)
	}
}

// resolveTemplate resolves variables and functions in a template
func (pb *PromptBuilder) resolveTemplate(template string, context *PromptContext) string {
	return pb.variableResolver.Resolve(template)
}

// evaluateConditions checks if template conditions are met
func (pb *PromptBuilder) evaluateConditions(template *PromptTemplate, context *PromptContext) bool {
	if len(template.Conditions) == 0 {
		return true
	}

	for _, condition := range template.Conditions {
		if !pb.evaluateCondition(condition, context) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single condition
func (pb *PromptBuilder) evaluateCondition(condition string, context *PromptContext) bool {
	// Simple condition evaluation - can be enhanced with expression parser
	resolved := pb.variableResolver.Resolve(condition)

	// Basic boolean conditions
	if resolved == "true" {
		return true
	}
	if resolved == "false" {
		return false
	}

	// Check for non-empty strings
	return strings.TrimSpace(resolved) != ""
}

// extractVariables extracts variable names from template content
func (pb *PromptBuilder) extractVariables(content string) []string {
	re := regexp.MustCompile(`\$\{([^}]+)\}`)
	matches := re.FindAllStringSubmatch(content, -1)

	var variables []string
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) > 1 {
			varName := match[1]
			if !seen[varName] {
				variables = append(variables, varName)
				seen[varName] = true
			}
		}
	}

	return variables
}

// estimateTokens provides a rough token count estimate
func (pb *PromptBuilder) estimateTokens(content string) int {
	// Rough estimation: ~4 characters per token
	return len(content) / 4
}

// loadDefaultTemplates loads built-in templates matching Python TARSy patterns
func (pb *PromptBuilder) loadDefaultTemplates() {
	// System prompt template for ReAct pattern
	pb.RegisterTemplateFromString("react_system", "system", `You are an expert ${AGENT_TYPE} agent analyzing security alerts using the ReAct (Reasoning and Acting) pattern.

CONTEXT:
- Alert Type: ${ALERT_TYPE}
- Session ID: ${SESSION_ID}
- Agent Capabilities: ${AGENT_CAPABILITIES}
- Available Tools: ${AVAILABLE_TOOLS}

INSTRUCTIONS:
${INSTRUCTIONS}

ANALYSIS APPROACH:
Use the following ReAct pattern:
1. Thought: Reason about what you need to do next
2. Action: Specify tools to use (if needed)
3. Observation: Analyze tool results
4. Repeat until you have sufficient information

When ready, provide:
FINAL ANALYSIS: [Your comprehensive assessment and recommendations]`)

	// User prompt template for initial alert analysis
	pb.RegisterTemplateFromString("alert_analysis", "user", `Analyze this security alert:

Alert Type: ${ALERT_TYPE}
Alert Data: ${ALERT_DATA}
${if RUNBOOK_CONTENT}
Relevant Runbook:
${RUNBOOK_CONTENT}
${endif}

Begin your analysis using the ReAct pattern.`)

	// Kubernetes-specific system prompt
	pb.RegisterTemplateFromString("kubernetes_system", "system", `You are a Kubernetes security expert specializing in container orchestration and incident response.

CONTEXT:
- Alert Type: ${ALERT_TYPE}
- Cluster: ${CLUSTER_NAME}
- Namespace: ${NAMESPACE}
- Resource Type: ${RESOURCE_TYPE}

FOCUS AREAS:
1. Pod security contexts and capabilities
2. Resource quotas and limits
3. Network policies and segmentation
4. RBAC and service account permissions
5. Container image security and vulnerabilities
6. Cluster security posture

Available MCP Servers: ${MCP_SERVERS}
${INSTRUCTIONS}`)

	// Tool usage instruction template
	pb.RegisterTemplateFromString("tool_instructions", "instruction", `TOOL USAGE GUIDELINES:
- Available tools: ${AVAILABLE_TOOLS}
- Use tools strategically to gather information
- Always explain your reasoning before using a tool
- Analyze tool results thoroughly before proceeding
- If a tool fails, continue analysis with available information`)
}

// loadDefaultFunctions loads built-in template functions
func (pb *PromptBuilder) loadDefaultFunctions() {
	// Conditional formatting function
	pb.RegisterFunction("if", func(args ...interface{}) string {
		if len(args) == 0 {
			return ""
		}
		condition := fmt.Sprintf("%v", args[0])
		return condition // Simple implementation - would be enhanced with proper conditional logic
	})

	// Join function for arrays
	pb.RegisterFunction("join", func(args ...interface{}) string {
		if len(args) < 2 {
			return ""
		}
		separator := fmt.Sprintf("%v", args[0])
		var items []string
		for i := 1; i < len(args); i++ {
			items = append(items, fmt.Sprintf("%v", args[i]))
		}
		return strings.Join(items, separator)
	})

	// Uppercase function
	pb.RegisterFunction("upper", func(args ...interface{}) string {
		if len(args) == 0 {
			return ""
		}
		return strings.ToUpper(fmt.Sprintf("%v", args[0]))
	})

	// Lowercase function
	pb.RegisterFunction("lower", func(args ...interface{}) string {
		if len(args) == 0 {
			return ""
		}
		return strings.ToLower(fmt.Sprintf("%v", args[0]))
	})
}

// GetTemplateNames returns a list of all registered template names
func (pb *PromptBuilder) GetTemplateNames() []string {
	var names []string
	for name := range pb.templates {
		names = append(names, name)
	}
	return names
}

// GetTemplate returns a template by name
func (pb *PromptBuilder) GetTemplate(name string) *PromptTemplate {
	return pb.templates[name]
}

// Clone creates a copy of the prompt builder
func (pb *PromptBuilder) Clone() *PromptBuilder {
	newPB := NewPromptBuilder()

	// Copy templates
	for name, template := range pb.templates {
		newTemplate := *template
		newPB.templates[name] = &newTemplate
	}

	// Copy variables
	for key, value := range pb.variableResolver.variables {
		newPB.variableResolver.SetVariable(key, value)
	}

	return newPB
}