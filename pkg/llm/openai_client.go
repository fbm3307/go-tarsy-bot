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

// OpenAIClient implements the LLMClient interface for OpenAI API
type OpenAIClient struct {
	config     *LLMConfig
	httpClient *http.Client
	logger     *zap.Logger
	usage      *UsageStats
	mutex      sync.RWMutex
}

// OpenAIRequest represents the request format for OpenAI API
type OpenAIRequest struct {
	Model            string                `json:"model"`
	Messages         []OpenAIMessage       `json:"messages"`
	Temperature      *float32              `json:"temperature,omitempty"`
	MaxTokens        *int                  `json:"max_tokens,omitempty"`
	TopP             *float32              `json:"top_p,omitempty"`
	Stop             []string              `json:"stop,omitempty"`
	PresencePenalty  *float32              `json:"presence_penalty,omitempty"`
	FrequencyPenalty *float32              `json:"frequency_penalty,omitempty"`
	Stream           bool                  `json:"stream"`
}

// OpenAIMessage represents a message in OpenAI format
type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIResponse represents the response from OpenAI API
type OpenAIResponse struct {
	ID      string                `json:"id"`
	Object  string                `json:"object"`
	Created int64                 `json:"created"`
	Model   string                `json:"model"`
	Choices []OpenAIChoice        `json:"choices"`
	Usage   OpenAIUsage           `json:"usage"`
	Error   *OpenAIError          `json:"error,omitempty"`
}

// OpenAIChoice represents a choice in OpenAI response
type OpenAIChoice struct {
	Index        int           `json:"index"`
	Message      OpenAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

// OpenAIUsage represents usage information from OpenAI
type OpenAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// OpenAIError represents an error from OpenAI API
type OpenAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
}

// NewOpenAIClient creates a new OpenAI client
func NewOpenAIClient(config *LLMConfig, logger *zap.Logger) *OpenAIClient {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.openai.com/v1"
	}

	if config.Model == "" {
		config.Model = "gpt-4o"
	}

	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	return &OpenAIClient{
		config:     config,
		httpClient: httpClient,
		logger:     logger,
		usage: &UsageStats{
			TotalRequests: 0,
			TotalTokens:   0,
		},
	}
}

// Generate generates a response using OpenAI API
func (c *OpenAIClient) Generate(ctx context.Context, request *GenerateRequest) (*GenerateResponse, error) {
	startTime := time.Now()

	// Validate request
	if err := ValidateRequest(request); err != nil {
		return nil, &LLMError{
			Provider:  "openai",
			ErrorType: "invalid_request",
			Message:   err.Error(),
		}
	}

	// Convert to OpenAI format
	openaiReq := c.convertToOpenAIRequest(request)

	// Make API call
	openaiResp, err := c.callOpenAIAPI(ctx, openaiReq)
	if err != nil {
		c.updateErrorStats()
		return nil, err
	}

	// Convert response
	response := c.convertFromOpenAIResponse(openaiResp, startTime)

	// Update usage statistics
	c.updateUsageStats(response)

	return response, nil
}

// convertToOpenAIRequest converts our request format to OpenAI format
func (c *OpenAIClient) convertToOpenAIRequest(req *GenerateRequest) *OpenAIRequest {
	openaiReq := &OpenAIRequest{
		Model:            c.getModel(req),
		Messages:         make([]OpenAIMessage, len(req.Messages)),
		Temperature:      req.Temperature,
		MaxTokens:        req.MaxTokens,
		TopP:             req.TopP,
		Stop:             req.Stop,
		PresencePenalty:  req.PresencePenalty,
		FrequencyPenalty: req.FrequencyPenalty,
		Stream:           false,
	}

	// Convert messages
	for i, msg := range req.Messages {
		openaiReq.Messages[i] = OpenAIMessage{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	// Apply defaults if not specified
	if openaiReq.Temperature == nil {
		temp := c.config.Temperature
		openaiReq.Temperature = &temp
	}

	if openaiReq.MaxTokens == nil {
		tokens := c.config.MaxTokens
		openaiReq.MaxTokens = &tokens
	}

	return openaiReq
}

// callOpenAIAPI makes the actual API call to OpenAI
func (c *OpenAIClient) callOpenAIAPI(ctx context.Context, request *OpenAIRequest) (*OpenAIResponse, error) {
	// Serialize request
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, &LLMError{
			Provider:  "openai",
			ErrorType: "serialization_error",
			Message:   fmt.Sprintf("Failed to serialize request: %v", err),
		}
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/chat/completions", c.config.BaseURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, &LLMError{
			Provider:  "openai",
			ErrorType: "request_creation_error",
			Message:   fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.config.APIKey))
	httpReq.Header.Set("User-Agent", "TARSy-Bot/1.0")

	// Make request
	c.logger.Debug("Making OpenAI API request",
		zap.String("model", request.Model),
		zap.Int("message_count", len(request.Messages)),
	)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &LLMError{
			Provider:  "openai",
			ErrorType: "network_error",
			Message:   fmt.Sprintf("HTTP request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	// Read response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &LLMError{
			Provider:   "openai",
			ErrorType:  "response_read_error",
			Message:    fmt.Sprintf("Failed to read response: %v", err),
			StatusCode: resp.StatusCode,
		}
	}

	// Parse response
	var openaiResp OpenAIResponse
	if err := json.Unmarshal(responseBody, &openaiResp); err != nil {
		return nil, &LLMError{
			Provider:   "openai",
			ErrorType:  "response_parse_error",
			Message:    fmt.Sprintf("Failed to parse response: %v", err),
			StatusCode: resp.StatusCode,
		}
	}

	// Check for API errors
	if openaiResp.Error != nil {
		return nil, &LLMError{
			Provider:   "openai",
			ErrorType:  c.mapOpenAIErrorType(openaiResp.Error.Type),
			ErrorCode:  openaiResp.Error.Code,
			Message:    openaiResp.Error.Message,
			StatusCode: resp.StatusCode,
		}
	}

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return nil, &LLMError{
			Provider:   "openai",
			ErrorType:  "http_error",
			Message:    fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(responseBody)),
			StatusCode: resp.StatusCode,
		}
	}

	return &openaiResp, nil
}

// convertFromOpenAIResponse converts OpenAI response to our format
func (c *OpenAIClient) convertFromOpenAIResponse(openaiResp *OpenAIResponse, startTime time.Time) *GenerateResponse {
	response := &GenerateResponse{
		Model:     openaiResp.Model,
		Provider:  "openai",
		ID:        openaiResp.ID,
		Created:   time.Unix(openaiResp.Created, 0),
		Duration:  time.Since(startTime),
		RawResponse: openaiResp,
	}

	// Extract content and finish reason
	if len(openaiResp.Choices) > 0 {
		choice := openaiResp.Choices[0]
		response.Content = choice.Message.Content
		response.FinishReason = choice.FinishReason
	}

	// Convert usage information
	response.Usage = &TokenUsage{
		PromptTokens:     openaiResp.Usage.PromptTokens,
		CompletionTokens: openaiResp.Usage.CompletionTokens,
		TotalTokens:      openaiResp.Usage.TotalTokens,
	}

	return response
}

// mapOpenAIErrorType maps OpenAI error types to our error types
func (c *OpenAIClient) mapOpenAIErrorType(openaiType string) string {
	switch openaiType {
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

// getModel returns the model to use for the request
func (c *OpenAIClient) getModel(req *GenerateRequest) string {
	if req.Model != "" {
		return req.Model
	}
	return c.config.Model
}

// updateUsageStats updates the usage statistics
func (c *OpenAIClient) updateUsageStats(response *GenerateResponse) {
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
func (c *OpenAIClient) updateErrorStats() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.usage.ErrorCount++
}

// GetProviderName returns the provider name
func (c *OpenAIClient) GetProviderName() string {
	return "openai"
}

// GetModels returns available OpenAI models
func (c *OpenAIClient) GetModels() []string {
	return []string{
		"gpt-4o",
		"gpt-4o-mini",
		"gpt-4-turbo",
		"gpt-4",
		"gpt-3.5-turbo",
	}
}

// GetDefaultModel returns the default model
func (c *OpenAIClient) GetDefaultModel() string {
	return "gpt-4o"
}

// ValidateConfig validates the OpenAI client configuration
func (c *OpenAIClient) ValidateConfig() error {
	if c.config.APIKey == "" {
		return fmt.Errorf("OpenAI API key is required")
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
func (c *OpenAIClient) GetUsage() *UsageStats {
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