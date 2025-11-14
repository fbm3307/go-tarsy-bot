package llm

import (
	"context"
	"fmt"
	"time"
)

// LLMClient defines the interface for all LLM provider implementations
// This provides a unified interface for OpenAI, Anthropic, Google AI, etc.
type LLMClient interface {
	// Generate generates a response from the LLM
	Generate(ctx context.Context, request *GenerateRequest) (*GenerateResponse, error)

	// GetProviderName returns the name of the LLM provider
	GetProviderName() string

	// GetModels returns available models for this provider
	GetModels() []string

	// GetDefaultModel returns the default model for this provider
	GetDefaultModel() string

	// ValidateConfig validates the client configuration
	ValidateConfig() error

	// GetUsage returns token usage statistics
	GetUsage() *UsageStats
}

// GenerateRequest represents a request to generate text from an LLM
type GenerateRequest struct {
	// Messages for conversation-based models
	Messages []Message `json:"messages"`

	// Model configuration
	Model       string  `json:"model,omitempty"`
	Temperature *float32 `json:"temperature,omitempty"`
	MaxTokens   *int    `json:"max_tokens,omitempty"`
	TopP        *float32 `json:"top_p,omitempty"`

	// Advanced options
	Stop           []string           `json:"stop,omitempty"`
	PresencePenalty *float32          `json:"presence_penalty,omitempty"`
	FrequencyPenalty *float32         `json:"frequency_penalty,omitempty"`
	SystemPrompt    *string           `json:"system_prompt,omitempty"`

	// Provider-specific options
	ProviderOptions map[string]interface{} `json:"provider_options,omitempty"`
}

// Message represents a single message in a conversation
type Message struct {
	Role    string `json:"role"`    // "system", "user", "assistant"
	Content string `json:"content"`
}

// GenerateResponse represents the response from an LLM
type GenerateResponse struct {
	// Generated content
	Content    string `json:"content"`
	FinishReason string `json:"finish_reason"` // "stop", "length", "content_filter", etc.

	// Token usage
	Usage *TokenUsage `json:"usage,omitempty"`

	// Model information
	Model    string `json:"model"`
	Provider string `json:"provider"`

	// Metadata
	ID        string    `json:"id,omitempty"`
	Created   time.Time `json:"created"`
	Duration  time.Duration `json:"duration"`

	// Raw response for debugging
	RawResponse interface{} `json:"raw_response,omitempty"`
}

// TokenUsage represents token usage information
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// UsageStats represents cumulative usage statistics
type UsageStats struct {
	TotalRequests      int64 `json:"total_requests"`
	TotalTokens        int64 `json:"total_tokens"`
	TotalPromptTokens  int64 `json:"total_prompt_tokens"`
	TotalCompletionTokens int64 `json:"total_completion_tokens"`
	TotalDuration      time.Duration `json:"total_duration"`
	AverageLatency     time.Duration `json:"average_latency"`
	ErrorCount         int64 `json:"error_count"`
}

// LLMConfig represents configuration for LLM clients
type LLMConfig struct {
	Provider    string            `json:"provider" yaml:"provider"`
	APIKey      string            `json:"api_key" yaml:"api_key"`
	BaseURL     string            `json:"base_url,omitempty" yaml:"base_url,omitempty"`
	Model       string            `json:"model" yaml:"model"`
	Temperature float32           `json:"temperature" yaml:"temperature"`
	MaxTokens   int               `json:"max_tokens" yaml:"max_tokens"`
	Timeout     time.Duration     `json:"timeout" yaml:"timeout"`
	RetryCount  int               `json:"retry_count" yaml:"retry_count"`
	Options     map[string]interface{} `json:"options,omitempty" yaml:"options,omitempty"`
}

// LLMError represents an error from LLM operations
type LLMError struct {
	Provider     string `json:"provider"`
	ErrorType    string `json:"error_type"`
	ErrorCode    string `json:"error_code,omitempty"`
	Message      string `json:"message"`
	StatusCode   int    `json:"status_code,omitempty"`
	RetryAfter   *time.Duration `json:"retry_after,omitempty"`
}

// Error implements the error interface
func (e *LLMError) Error() string {
	return fmt.Sprintf("LLM %s error [%s]: %s", e.Provider, e.ErrorType, e.Message)
}

// IsRetryable returns true if the error is retryable
func (e *LLMError) IsRetryable() bool {
	switch e.ErrorType {
	case "rate_limit", "timeout", "server_error", "network_error":
		return true
	case "authentication", "invalid_request", "context_length_exceeded":
		return false
	default:
		return e.StatusCode >= 500
	}
}

// LLMClientRegistry manages multiple LLM client instances
type LLMClientRegistry struct {
	clients       map[string]LLMClient
	defaultClient string
}

// NewLLMClientRegistry creates a new LLM client registry
func NewLLMClientRegistry() *LLMClientRegistry {
	return &LLMClientRegistry{
		clients: make(map[string]LLMClient),
	}
}

// RegisterClient registers an LLM client
func (r *LLMClientRegistry) RegisterClient(name string, client LLMClient) error {
	if err := client.ValidateConfig(); err != nil {
		return fmt.Errorf("client validation failed: %w", err)
	}

	r.clients[name] = client

	// Set as default if it's the first client
	if r.defaultClient == "" {
		r.defaultClient = name
	}

	return nil
}

// GetClient returns a client by name
func (r *LLMClientRegistry) GetClient(name string) (LLMClient, error) {
	client, exists := r.clients[name]
	if !exists {
		return nil, fmt.Errorf("LLM client not found: %s", name)
	}
	return client, nil
}

// GetDefaultClient returns the default client
func (r *LLMClientRegistry) GetDefaultClient() (LLMClient, error) {
	if r.defaultClient == "" {
		return nil, fmt.Errorf("no default LLM client configured")
	}
	return r.GetClient(r.defaultClient)
}

// SetDefaultClient sets the default client
func (r *LLMClientRegistry) SetDefaultClient(name string) error {
	if _, exists := r.clients[name]; !exists {
		return fmt.Errorf("client not found: %s", name)
	}
	r.defaultClient = name
	return nil
}

// ListClients returns all registered client names
func (r *LLMClientRegistry) ListClients() []string {
	names := make([]string, 0, len(r.clients))
	for name := range r.clients {
		names = append(names, name)
	}
	return names
}

// Generate generates text using the specified client (or default if empty)
func (r *LLMClientRegistry) Generate(ctx context.Context, clientName string, request *GenerateRequest) (*GenerateResponse, error) {
	var client LLMClient
	var err error

	if clientName == "" {
		client, err = r.GetDefaultClient()
	} else {
		client, err = r.GetClient(clientName)
	}

	if err != nil {
		return nil, err
	}

	return client.Generate(ctx, request)
}

// ValidateRequest validates a generate request
func ValidateRequest(req *GenerateRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if len(req.Messages) == 0 {
		return fmt.Errorf("messages cannot be empty")
	}

	// Validate messages
	for i, msg := range req.Messages {
		if msg.Role == "" {
			return fmt.Errorf("message %d: role cannot be empty", i)
		}
		if msg.Content == "" {
			return fmt.Errorf("message %d: content cannot be empty", i)
		}
		if msg.Role != "system" && msg.Role != "user" && msg.Role != "assistant" {
			return fmt.Errorf("message %d: invalid role '%s'", i, msg.Role)
		}
	}

	// Validate parameters
	if req.Temperature != nil && (*req.Temperature < 0 || *req.Temperature > 2) {
		return fmt.Errorf("temperature must be between 0 and 2")
	}

	if req.MaxTokens != nil && *req.MaxTokens <= 0 {
		return fmt.Errorf("max_tokens must be greater than 0")
	}

	if req.TopP != nil && (*req.TopP < 0 || *req.TopP > 1) {
		return fmt.Errorf("top_p must be between 0 and 1")
	}

	return nil
}

// EstimateTokens provides a rough estimate of token count for text
func EstimateTokens(text string) int {
	// Rough approximation: ~4 characters per token for English text
	// This is a simplified estimate - production would use tiktoken or similar
	return len(text) / 4
}

// BuildMessages is a helper to build message arrays
func BuildMessages(systemPrompt string, userMessage string, conversationHistory ...Message) []Message {
	messages := make([]Message, 0)

	// Add system prompt if provided
	if systemPrompt != "" {
		messages = append(messages, Message{
			Role:    "system",
			Content: systemPrompt,
		})
	}

	// Add conversation history
	messages = append(messages, conversationHistory...)

	// Add user message
	if userMessage != "" {
		messages = append(messages, Message{
			Role:    "user",
			Content: userMessage,
		})
	}

	return messages
}