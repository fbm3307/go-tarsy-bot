package llm

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// MockClient is a mock LLM client for testing and development
type MockClient struct {
	ProviderName string
	DefaultModel string
	usage        *UsageStats
}

// NewMockClient creates a new mock LLM client
func NewMockClient(providerName, defaultModel string) *MockClient {
	return &MockClient{
		ProviderName: providerName,
		DefaultModel: defaultModel,
		usage: &UsageStats{
			TotalRequests:         0,
			TotalTokens:          0,
			TotalPromptTokens:    0,
			TotalCompletionTokens: 0,
			TotalDuration:        0,
			AverageLatency:       0,
			ErrorCount:           0,
		},
	}
}

// Generate generates a mock response
func (c *MockClient) Generate(ctx context.Context, request *GenerateRequest) (*GenerateResponse, error) {
	startTime := time.Now()

	// Simulate processing time
	time.Sleep(100 * time.Millisecond)

	// Generate mock content based on the request
	content := c.generateMockContent(request)

	// Calculate mock token usage
	promptTokens := c.estimateTokens(c.getPromptText(request))
	completionTokens := c.estimateTokens(content)
	totalTokens := promptTokens + completionTokens

	duration := time.Since(startTime)

	// Update usage stats
	c.usage.TotalRequests++
	c.usage.TotalTokens += int64(totalTokens)
	c.usage.TotalPromptTokens += int64(promptTokens)
	c.usage.TotalCompletionTokens += int64(completionTokens)
	c.usage.TotalDuration += duration
	c.usage.AverageLatency = c.usage.TotalDuration / time.Duration(c.usage.TotalRequests)

	response := &GenerateResponse{
		Content:      content,
		FinishReason: "stop",
		Usage: &TokenUsage{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      totalTokens,
		},
		Model:    c.getModel(request),
		Provider: c.ProviderName,
		ID:       fmt.Sprintf("mock-%d", time.Now().UnixNano()),
		Created:  startTime,
		Duration: duration,
	}

	return response, nil
}

// GetProviderName returns the mock provider name
func (c *MockClient) GetProviderName() string {
	return c.ProviderName
}

// GetModels returns available mock models
func (c *MockClient) GetModels() []string {
	return []string{c.DefaultModel, "mock-model-2", "mock-model-3"}
}

// GetDefaultModel returns the default mock model
func (c *MockClient) GetDefaultModel() string {
	return c.DefaultModel
}

// ValidateConfig validates the mock client configuration
func (c *MockClient) ValidateConfig() error {
	if c.ProviderName == "" {
		return fmt.Errorf("provider name is required")
	}
	if c.DefaultModel == "" {
		return fmt.Errorf("default model is required")
	}
	return nil
}

// GetUsage returns mock usage statistics
func (c *MockClient) GetUsage() *UsageStats {
	return c.usage
}

// generateMockContent generates mock content based on the request
func (c *MockClient) generateMockContent(request *GenerateRequest) string {
	// Generate contextual mock content based on the conversation
	lastMessage := ""
	if len(request.Messages) > 0 {
		lastMessage = request.Messages[len(request.Messages)-1].Content
	}

	// Simple mock responses based on content
	switch {
	case containsKeywords(lastMessage, []string{"alert", "incident", "problem"}):
		return c.generateAlertAnalysisResponse()
	case containsKeywords(lastMessage, []string{"kubernetes", "k8s", "pod", "deployment"}):
		return c.generateKubernetesResponse()
	case containsKeywords(lastMessage, []string{"security", "threat", "vulnerability"}):
		return c.generateSecurityResponse()
	case containsKeywords(lastMessage, []string{"tool", "execute", "command"}):
		return c.generateToolResponse()
	default:
		return c.generateGenericResponse()
	}
}

// generateAlertAnalysisResponse generates a mock alert analysis response
func (c *MockClient) generateAlertAnalysisResponse() string {
	return `Based on the alert information provided, I can see this appears to be a resource utilization issue. Let me analyze the key indicators:

**Alert Analysis:**
1. **Severity**: The alert indicates elevated resource usage
2. **Impact**: Potential service degradation if not addressed
3. **Root Cause**: Likely related to increased traffic or resource leak

**Recommended Actions:**
1. Check current resource utilization metrics
2. Review recent deployments or configuration changes
3. Scale resources if needed
4. Monitor for improvement

**Next Steps:**
I recommend gathering additional system metrics to confirm the analysis. Would you like me to help with specific diagnostic commands?`
}

// generateKubernetesResponse generates a mock Kubernetes response
func (c *MockClient) generateKubernetesResponse() string {
	return `I'll help you analyze the Kubernetes environment. Based on the context provided:

**Kubernetes Analysis:**
- **Cluster Health**: Checking pod status and resource allocation
- **Workload Status**: Reviewing deployment and service configurations
- **Resource Usage**: Examining CPU, memory, and storage utilization

**Recommendations:**
1. Verify pod readiness and health checks
2. Check for any failed deployments or rollbacks needed
3. Review resource requests and limits
4. Ensure proper service discovery and networking

Let me know if you need specific kubectl commands or further investigation.`
}

// generateSecurityResponse generates a mock security response
func (c *MockClient) generateSecurityResponse() string {
	return `Security analysis initiated. Here's my assessment:

**Security Review:**
1. **Threat Assessment**: Analyzing potential security implications
2. **Vulnerability Check**: Reviewing for known security issues
3. **Compliance**: Checking against security best practices

**Findings:**
- No immediate critical security threats detected
- Standard security controls appear to be in place
- Recommend regular security audits and updates

**Action Items:**
1. Verify access controls and authentication
2. Check for security patches and updates
3. Review logs for suspicious activity
4. Implement monitoring for security events

Would you like me to focus on any specific security aspect?`
}

// generateToolResponse generates a mock tool usage response
func (c *MockClient) generateToolResponse() string {
	return `I understand you'd like me to use tools to gather more information. Let me proceed with the appropriate tool calls:

TOOL_CALL: kubectl_get_pods(namespace=default)

Based on the tool execution, I can provide more specific analysis. The tool results will help me understand the current system state and provide targeted recommendations.

After executing the necessary tools, I'll compile a comprehensive analysis with actionable insights.`
}

// generateGenericResponse generates a generic mock response
func (c *MockClient) generateGenericResponse() string {
	return `Thank you for your message. I'm a mock LLM client simulating responses for development and testing purposes.

I can help with:
- Alert analysis and incident response
- Kubernetes troubleshooting
- Security assessments
- Tool-based investigations
- General system analysis

Please provide more specific information about what you'd like me to analyze, and I'll generate a contextual response based on your request.`
}

// Helper functions

// containsKeywords checks if the text contains any of the given keywords
func containsKeywords(text string, keywords []string) bool {
	textLower := strings.ToLower(text)
	for _, keyword := range keywords {
		if strings.Contains(textLower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// estimateTokens provides a rough token estimate (approximately 4 characters per token)
func (c *MockClient) estimateTokens(text string) int {
	return len(text) / 4
}

// getPromptText extracts the prompt text from the request
func (c *MockClient) getPromptText(request *GenerateRequest) string {
	var prompt string

	if request.SystemPrompt != nil {
		prompt += *request.SystemPrompt + " "
	}

	for _, message := range request.Messages {
		prompt += message.Content + " "
	}

	return prompt
}

// getModel returns the model to use for the request
func (c *MockClient) getModel(request *GenerateRequest) string {
	if request.Model != "" {
		return request.Model
	}
	return c.DefaultModel
}