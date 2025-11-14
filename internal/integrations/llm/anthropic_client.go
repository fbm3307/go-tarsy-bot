package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AnthropicClient implements the LLMClient interface for Anthropic Claude API
type AnthropicClient struct {
	config     *LLMConfig
	httpClient *http.Client
	logger     *zap.Logger
	usage      *UsageStats
	mutex      sync.RWMutex
}

// AnthropicRequest represents the request format for Anthropic API
type AnthropicRequest struct {
	Model         string            `json:"model"`
	MaxTokens     int               `json:"max_tokens"`
	Messages      []AnthropicMessage `json:"messages"`
	System        string            `json:"system,omitempty"`
	Temperature   *float32          `json:"temperature,omitempty"`
	TopP          *float32          `json:"top_p,omitempty"`
	StopSequences []string          `json:"stop_sequences,omitempty"`
	Stream        bool              `json:"stream"`
}

// AnthropicMessage represents a message in Anthropic format
type AnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AnthropicResponse represents the response from Anthropic API
type AnthropicResponse struct {
	ID           string           `json:"id"`
	Type         string           `json:"type"`
	Role         string           `json:"role"`
	Content      []AnthropicContent `json:"content"`
	Model        string           `json:"model"`
	StopReason   string           `json:"stop_reason"`
	StopSequence string           `json:"stop_sequence,omitempty"`
	Usage        AnthropicUsage   `json:"usage"`
	Error        *AnthropicError  `json:"error,omitempty"`
}

// AnthropicContent represents content in Anthropic response
type AnthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// AnthropicUsage represents usage information from Anthropic
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// AnthropicError represents an error from Anthropic API
type AnthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// NewAnthropicClient creates a new Anthropic client
func NewAnthropicClient(config *LLMConfig, logger *zap.Logger) *AnthropicClient {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.anthropic.com"
	}

	if config.Model == "" {
		config.Model = "claude-3-5-sonnet-20241022"
	}

	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	return &AnthropicClient{
		config:     config,
		httpClient: httpClient,
		logger:     logger,
		usage: &UsageStats{
			TotalRequests: 0,
			TotalTokens:   0,
		},
	}
}

// Generate generates a response using Anthropic API
func (c *AnthropicClient) Generate(ctx context.Context, request *GenerateRequest) (*GenerateResponse, error) {
	startTime := time.Now()

	// Validate request
	if err := ValidateRequest(request); err != nil {
		return nil, &LLMError{
			Provider:  "anthropic",
			ErrorType: "invalid_request",
			Message:   err.Error(),
		}
	}

	// Convert to Anthropic format
	anthropicReq := c.convertToAnthropicRequest(request)

	// Make API call
	anthropicResp, err := c.callAnthropicAPI(ctx, anthropicReq)
	if err != nil {
		c.updateErrorStats()
		return nil, err
	}

	// Convert response
	response := c.convertFromAnthropicResponse(anthropicResp, startTime)

	// Update usage statistics
	c.updateUsageStats(response)

	return response, nil
}

// convertToAnthropicRequest converts our request format to Anthropic format
func (c *AnthropicClient) convertToAnthropicRequest(req *GenerateRequest) *AnthropicRequest {
	anthropicReq := &AnthropicRequest{
		Model:         c.getModel(req),
		MaxTokens:     c.getMaxTokens(req),
		Messages:      make([]AnthropicMessage, 0),
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		StopSequences: req.Stop,
		Stream:        false,
	}

	// Handle system message separately in Anthropic
	var systemMessage string
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			if systemMessage != "" {
				systemMessage += "\n\n"
			}
			systemMessage += msg.Content
		} else {
			anthropicReq.Messages = append(anthropicReq.Messages, AnthropicMessage{
				Role:    msg.Role,
				Content: msg.Content,
			})
		}
	}

	if systemMessage != "" {
		anthropicReq.System = systemMessage
	}

	// Apply defaults if not specified
	if anthropicReq.Temperature == nil {
		temp := c.config.Temperature
		anthropicReq.Temperature = &temp
	}

	return anthropicReq
}

// callAnthropicAPI makes the actual API call to Anthropic
func (c *AnthropicClient) callAnthropicAPI(ctx context.Context, request *AnthropicRequest) (*AnthropicResponse, error) {
	// Serialize request
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, &LLMError{
			Provider:  "anthropic",
			ErrorType: "serialization_error",
			Message:   fmt.Sprintf("Failed to serialize request: %v", err),
		}
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/v1/messages", c.config.BaseURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, &LLMError{
			Provider:  "anthropic",
			ErrorType: "request_creation_error",
			Message:   fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("User-Agent", "TARSy-Bot/1.0")

	// Make request
	c.logger.Debug("Making Anthropic API request",
		zap.String("model", request.Model),
		zap.Int("message_count", len(request.Messages)),
	)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &LLMError{
			Provider:  "anthropic",
			ErrorType: "network_error",
			Message:   fmt.Sprintf("HTTP request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	// Read response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &LLMError{
			Provider:   "anthropic",
			ErrorType:  "response_read_error",
			Message:    fmt.Sprintf("Failed to read response: %v", err),
			StatusCode: resp.StatusCode,
		}
	}

	// Parse response
	var anthropicResp AnthropicResponse
	if err := json.Unmarshal(responseBody, &anthropicResp); err != nil {
		return nil, &LLMError{
			Provider:   "anthropic",
			ErrorType:  "response_parse_error",
			Message:    fmt.Sprintf("Failed to parse response: %v", err),
			StatusCode: resp.StatusCode,
		}
	}

	// Check for API errors
	if anthropicResp.Error != nil {
		return nil, &LLMError{
			Provider:   "anthropic",
			ErrorType:  c.mapAnthropicErrorType(anthropicResp.Error.Type),
			Message:    anthropicResp.Error.Message,
			StatusCode: resp.StatusCode,
		}
	}

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return nil, &LLMError{
			Provider:   "anthropic",
			ErrorType:  "http_error",
			Message:    fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(responseBody)),
			StatusCode: resp.StatusCode,
		}
	}

	return &anthropicResp, nil
}

// convertFromAnthropicResponse converts Anthropic response to our format
func (c *AnthropicClient) convertFromAnthropicResponse(anthropicResp *AnthropicResponse, startTime time.Time) *GenerateResponse {
	response := &GenerateResponse{
		Model:       anthropicResp.Model,
		Provider:    "anthropic",
		ID:          anthropicResp.ID,
		Created:     time.Now(), // Anthropic doesn't provide creation time
		Duration:    time.Since(startTime),
		RawResponse: anthropicResp,
	}

	// Extract content
	if len(anthropicResp.Content) > 0 {
		response.Content = anthropicResp.Content[0].Text
	}

	// Map stop reason
	response.FinishReason = c.mapStopReason(anthropicResp.StopReason)

	// Convert usage information
	response.Usage = &TokenUsage{
		PromptTokens:     anthropicResp.Usage.InputTokens,
		CompletionTokens: anthropicResp.Usage.OutputTokens,
		TotalTokens:      anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens,
	}

	return response
}

// mapAnthropicErrorType maps Anthropic error types to our error types
func (c *AnthropicClient) mapAnthropicErrorType(anthropicType string) string {
	switch anthropicType {
	case "invalid_request_error":
		return "invalid_request"
	case "authentication_error":
		return "authentication"
	case "permission_error":
		return "permission"
	case "not_found_error":
		return "not_found"
	case "rate_limit_error":
		return "rate_limit"
	case "api_error":
		return "server_error"
	case "overloaded_error":
		return "server_error"
	default:
		return "unknown"
	}
}

// mapStopReason maps Anthropic stop reasons to our format
func (c *AnthropicClient) mapStopReason(reason string) string {
	switch reason {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "stop_sequence":
		return "stop"
	default:
		return reason
	}
}

// getModel returns the model to use for the request
func (c *AnthropicClient) getModel(req *GenerateRequest) string {
	if req.Model != "" {
		return req.Model
	}
	return c.config.Model
}

// getMaxTokens returns the max tokens for the request
func (c *AnthropicClient) getMaxTokens(req *GenerateRequest) int {
	if req.MaxTokens != nil {
		return *req.MaxTokens
	}
	if c.config.MaxTokens > 0 {
		return c.config.MaxTokens
	}
	return 4096 // Default for Anthropic
}

// updateUsageStats updates the usage statistics
func (c *AnthropicClient) updateUsageStats(response *GenerateResponse) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.usage.TotalRequests++
	c.usage.TotalDuration += response.Duration

	if response.Usage != nil {
		c.usage.TotalTokens += int64(response.Usage.TotalTokens)
		c.usage.TotalPromptTokens += int64(response.Usage.PromptTokens)
		c.usage.TotalCompletionTokens += int64(response.Usage.CompletionTokens)
	}

	// Calculate average latency
	if c.usage.TotalRequests > 0 {
		c.usage.AverageLatency = c.usage.TotalDuration / time.Duration(c.usage.TotalRequests)
	}
}

// updateErrorStats updates error statistics
func (c *AnthropicClient) updateErrorStats() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.usage.ErrorCount++
}

// GetProviderName returns the provider name
func (c *AnthropicClient) GetProviderName() string {
	return "anthropic"
}

// GetModels returns available Anthropic models
func (c *AnthropicClient) GetModels() []string {
	return []string{
		"claude-3-5-sonnet-20241022",
		"claude-3-5-haiku-20241022",
		"claude-3-opus-20240229",
		"claude-3-sonnet-20240229",
		"claude-3-haiku-20240307",
	}
}

// GetDefaultModel returns the default model
func (c *AnthropicClient) GetDefaultModel() string {
	return "claude-3-5-sonnet-20241022"
}

// ValidateConfig validates the Anthropic client configuration
func (c *AnthropicClient) ValidateConfig() error {
	if c.config.APIKey == "" {
		return fmt.Errorf("Anthropic API key is required")
	}

	if c.config.Model == "" {
		return fmt.Errorf("model is required")
	}

	// Validate model availability
	availableModels := c.GetModels()
	modelValid := false
	for _, model := range availableModels {
		if model == c.config.Model {
			modelValid = true
			break
		}
	}

	if !modelValid {
		return fmt.Errorf("invalid model: %s", c.config.Model)
	}

	return nil
}

// GetUsage returns usage statistics
func (c *AnthropicClient) GetUsage() *UsageStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Return a copy to avoid race conditions
	return &UsageStats{
		TotalRequests:         c.usage.TotalRequests,
		TotalTokens:           c.usage.TotalTokens,
		TotalPromptTokens:     c.usage.TotalPromptTokens,
		TotalCompletionTokens: c.usage.TotalCompletionTokens,
		TotalDuration:         c.usage.TotalDuration,
		AverageLatency:        c.usage.AverageLatency,
		ErrorCount:            c.usage.ErrorCount,
	}
}