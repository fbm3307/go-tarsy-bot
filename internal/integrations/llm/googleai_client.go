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

// GoogleAIClient implements the LLMClient interface for Google AI (Gemini) API
type GoogleAIClient struct {
	config     *LLMConfig
	httpClient *http.Client
	logger     *zap.Logger
	usage      *UsageStats
	mutex      sync.RWMutex
}

// GoogleAIRequest represents the request format for Google AI API
type GoogleAIRequest struct {
	Contents         []GoogleAIContent         `json:"contents"`
	GenerationConfig *GoogleAIGenerationConfig `json:"generationConfig,omitempty"`
	SafetySettings   []GoogleAISafetySetting   `json:"safetySettings,omitempty"`
}

// GoogleAIContent represents content in Google AI format
type GoogleAIContent struct {
	Role  string          `json:"role,omitempty"`
	Parts []GoogleAIPart  `json:"parts"`
}

// GoogleAIPart represents a part of content
type GoogleAIPart struct {
	Text string `json:"text"`
}

// GoogleAIGenerationConfig represents generation configuration
type GoogleAIGenerationConfig struct {
	Temperature     *float32 `json:"temperature,omitempty"`
	TopP            *float32 `json:"topP,omitempty"`
	TopK            *int     `json:"topK,omitempty"`
	MaxOutputTokens *int     `json:"maxOutputTokens,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

// GoogleAISafetySetting represents safety settings
type GoogleAISafetySetting struct {
	Category  string `json:"category"`
	Threshold string `json:"threshold"`
}

// GoogleAIResponse represents the response from Google AI API
type GoogleAIResponse struct {
	Candidates     []GoogleAICandidate    `json:"candidates"`
	UsageMetadata  GoogleAIUsageMetadata  `json:"usageMetadata"`
	Error          *GoogleAIError         `json:"error,omitempty"`
}

// GoogleAICandidate represents a candidate response
type GoogleAICandidate struct {
	Content       GoogleAIContent `json:"content"`
	FinishReason  string          `json:"finishReason"`
	SafetyRatings []GoogleAISafetyRating `json:"safetyRatings,omitempty"`
}

// GoogleAISafetyRating represents safety rating
type GoogleAISafetyRating struct {
	Category    string `json:"category"`
	Probability string `json:"probability"`
}

// GoogleAIUsageMetadata represents usage information from Google AI
type GoogleAIUsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// GoogleAIError represents an error from Google AI API
type GoogleAIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// NewGoogleAIClient creates a new Google AI client
func NewGoogleAIClient(config *LLMConfig, logger *zap.Logger) *GoogleAIClient {
	if config.BaseURL == "" {
		config.BaseURL = "https://generativelanguage.googleapis.com"
	}

	if config.Model == "" {
		config.Model = "gemini-2.0-flash"
	}

	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	return &GoogleAIClient{
		config:     config,
		httpClient: httpClient,
		logger:     logger,
		usage: &UsageStats{
			TotalRequests: 0,
			TotalTokens:   0,
		},
	}
}

// Generate generates a response using Google AI API
func (c *GoogleAIClient) Generate(ctx context.Context, request *GenerateRequest) (*GenerateResponse, error) {
	startTime := time.Now()

	// Validate request
	if err := ValidateRequest(request); err != nil {
		return nil, &LLMError{
			Provider:  "googleai",
			ErrorType: "invalid_request",
			Message:   err.Error(),
		}
	}

	// Convert to Google AI format
	googleaiReq := c.convertToGoogleAIRequest(request)

	// Make API call
	googleaiResp, err := c.callGoogleAIAPI(ctx, googleaiReq)
	if err != nil {
		c.updateErrorStats()
		return nil, err
	}

	// Convert response
	response := c.convertFromGoogleAIResponse(googleaiResp, startTime)

	// Update usage statistics
	c.updateUsageStats(response)

	return response, nil
}

// convertToGoogleAIRequest converts our request format to Google AI format
func (c *GoogleAIClient) convertToGoogleAIRequest(req *GenerateRequest) *GoogleAIRequest {
	googleaiReq := &GoogleAIRequest{
		Contents: make([]GoogleAIContent, 0),
		GenerationConfig: &GoogleAIGenerationConfig{
			Temperature:     req.Temperature,
			TopP:            req.TopP,
			MaxOutputTokens: req.MaxTokens,
			StopSequences:   req.Stop,
		},
		SafetySettings: []GoogleAISafetySetting{
			{Category: "HARM_CATEGORY_HARASSMENT", Threshold: "BLOCK_MEDIUM_AND_ABOVE"},
			{Category: "HARM_CATEGORY_HATE_SPEECH", Threshold: "BLOCK_MEDIUM_AND_ABOVE"},
			{Category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", Threshold: "BLOCK_MEDIUM_AND_ABOVE"},
			{Category: "HARM_CATEGORY_DANGEROUS_CONTENT", Threshold: "BLOCK_MEDIUM_AND_ABOVE"},
		},
	}

	// Convert system messages to user messages since v1 API doesn't support systemInstruction
	for _, msg := range req.Messages {
		role := msg.Role
		content := msg.Content

		// Convert system messages to user messages for v1 API compatibility
		if role == "system" {
			role = "user"
			content = "System instructions: " + content
		} else if role == "assistant" {
			role = "model"
		}

		googleaiReq.Contents = append(googleaiReq.Contents, GoogleAIContent{
			Role:  role,
			Parts: []GoogleAIPart{{Text: content}},
		})
	}

	// Apply defaults if not specified
	if googleaiReq.GenerationConfig.Temperature == nil {
		temp := c.config.Temperature
		googleaiReq.GenerationConfig.Temperature = &temp
	}

	if googleaiReq.GenerationConfig.MaxOutputTokens == nil {
		tokens := c.config.MaxTokens
		if tokens == 0 {
			tokens = 8192 // Default for Gemini
		}
		googleaiReq.GenerationConfig.MaxOutputTokens = &tokens
	}

	return googleaiReq
}

// callGoogleAIAPI makes the actual API call to Google AI
func (c *GoogleAIClient) callGoogleAIAPI(ctx context.Context, request *GoogleAIRequest) (*GoogleAIResponse, error) {
	// Serialize request
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, &LLMError{
			Provider:  "googleai",
			ErrorType: "serialization_error",
			Message:   fmt.Sprintf("Failed to serialize request: %v", err),
		}
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/v1/models/%s:generateContent?key=%s",
		c.config.BaseURL, c.getModel(nil), c.config.APIKey)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, &LLMError{
			Provider:  "googleai",
			ErrorType: "request_creation_error",
			Message:   fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "TARSy-Bot/1.0")

	// Make request
	c.logger.Debug("Making Google AI API request",
		zap.String("model", c.getModel(nil)),
		zap.Int("content_count", len(request.Contents)),
	)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &LLMError{
			Provider:  "googleai",
			ErrorType: "network_error",
			Message:   fmt.Sprintf("HTTP request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	// Read response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &LLMError{
			Provider:   "googleai",
			ErrorType:  "response_read_error",
			Message:    fmt.Sprintf("Failed to read response: %v", err),
			StatusCode: resp.StatusCode,
		}
	}

	// Parse response
	var googleaiResp GoogleAIResponse
	if err := json.Unmarshal(responseBody, &googleaiResp); err != nil {
		return nil, &LLMError{
			Provider:   "googleai",
			ErrorType:  "response_parse_error",
			Message:    fmt.Sprintf("Failed to parse response: %v", err),
			StatusCode: resp.StatusCode,
		}
	}

	// Check for API errors
	if googleaiResp.Error != nil {
		return nil, &LLMError{
			Provider:   "googleai",
			ErrorType:  c.mapGoogleAIErrorType(googleaiResp.Error.Status),
			Message:    googleaiResp.Error.Message,
			StatusCode: googleaiResp.Error.Code,
		}
	}

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return nil, &LLMError{
			Provider:   "googleai",
			ErrorType:  "http_error",
			Message:    fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(responseBody)),
			StatusCode: resp.StatusCode,
		}
	}

	return &googleaiResp, nil
}

// convertFromGoogleAIResponse converts Google AI response to our format
func (c *GoogleAIClient) convertFromGoogleAIResponse(googleaiResp *GoogleAIResponse, startTime time.Time) *GenerateResponse {
	response := &GenerateResponse{
		Model:       c.config.Model,
		Provider:    "googleai",
		ID:          fmt.Sprintf("googleai-%d", time.Now().UnixNano()),
		Created:     time.Now(),
		Duration:    time.Since(startTime),
		RawResponse: googleaiResp,
	}

	// Extract content and finish reason
	if len(googleaiResp.Candidates) > 0 {
		candidate := googleaiResp.Candidates[0]
		if len(candidate.Content.Parts) > 0 {
			response.Content = candidate.Content.Parts[0].Text
		}
		response.FinishReason = c.mapFinishReason(candidate.FinishReason)
	}

	// Convert usage information
	response.Usage = &TokenUsage{
		PromptTokens:     googleaiResp.UsageMetadata.PromptTokenCount,
		CompletionTokens: googleaiResp.UsageMetadata.CandidatesTokenCount,
		TotalTokens:      googleaiResp.UsageMetadata.TotalTokenCount,
	}

	return response
}

// mapGoogleAIErrorType maps Google AI error types to our error types
func (c *GoogleAIClient) mapGoogleAIErrorType(status string) string {
	switch status {
	case "INVALID_ARGUMENT":
		return "invalid_request"
	case "UNAUTHENTICATED":
		return "authentication"
	case "PERMISSION_DENIED":
		return "permission"
	case "NOT_FOUND":
		return "not_found"
	case "RESOURCE_EXHAUSTED":
		return "rate_limit"
	case "INTERNAL":
		return "server_error"
	case "UNAVAILABLE":
		return "server_error"
	default:
		return "unknown"
	}
}

// mapFinishReason maps Google AI finish reasons to our format
func (c *GoogleAIClient) mapFinishReason(reason string) string {
	switch reason {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY":
		return "content_filter"
	case "RECITATION":
		return "content_filter"
	default:
		return reason
	}
}

// getModel returns the model to use for the request
func (c *GoogleAIClient) getModel(req *GenerateRequest) string {
	if req != nil && req.Model != "" {
		return req.Model
	}
	return c.config.Model
}

// updateUsageStats updates the usage statistics
func (c *GoogleAIClient) updateUsageStats(response *GenerateResponse) {
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
func (c *GoogleAIClient) updateErrorStats() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.usage.ErrorCount++
}

// GetProviderName returns the provider name
func (c *GoogleAIClient) GetProviderName() string {
	return "googleai"
}

// GetModels returns available Google AI models
func (c *GoogleAIClient) GetModels() []string {
	return []string{
		"gemini-2.0-flash",
		"gemini-2.5-flash",
		"gemini-2.5-pro",
	}
}

// GetDefaultModel returns the default model
func (c *GoogleAIClient) GetDefaultModel() string {
	return "gemini-2.0-flash"
}

// ValidateConfig validates the Google AI client configuration
func (c *GoogleAIClient) ValidateConfig() error {
	if c.config.APIKey == "" {
		return fmt.Errorf("Google AI API key is required")
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
func (c *GoogleAIClient) GetUsage() *UsageStats {
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