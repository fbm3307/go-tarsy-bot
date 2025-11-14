package shared

import (
	"context"
)

// LLMIntegrationInterface defines the interface for LLM integration service
// This breaks the circular dependency between agents and services packages
type LLMIntegrationInterface interface {
	GenerateWithTracking(ctx context.Context, request *EnhancedGenerateRequest) (*LLMResponse, error)
}

// EnhancedGenerateRequest represents an LLM generation request with tracking
type EnhancedGenerateRequest struct {
	*GenerateWithToolsRequest
	SessionID        string  `json:"session_id"`
	AgentType        string  `json:"agent_type"`
	IterationIndex   *int    `json:"iteration_index,omitempty"`
	StageExecutionID *string `json:"stage_execution_id,omitempty"`
	TrackCost        bool    `json:"track_cost"`
	EstimateCost     bool    `json:"estimate_cost"`
}

// GenerateWithToolsRequest represents a request with tool support
type GenerateWithToolsRequest struct {
	*GenerateRequest
	EnableTools bool `json:"enable_tools"`
}

// GenerateRequest represents a basic LLM generation request
type GenerateRequest struct {
	Messages     []Message `json:"messages"`
	SystemPrompt *string   `json:"system_prompt,omitempty"`
	Model        string    `json:"model"`
	Temperature  *float64  `json:"temperature,omitempty"`
	MaxTokens    *int      `json:"max_tokens,omitempty"`
}

// Message represents a conversation message for LLM
type Message struct {
	Role    string `json:"role"`    // "user", "assistant", "system"
	Content string `json:"content"` // Message content
}

// LLMResponse represents a response from an LLM provider
type LLMResponse struct {
	Content      string  `json:"content"`       // Generated text content
	Model        string  `json:"model"`         // Model used for generation
	TokensUsed   int     `json:"tokens_used"`   // Total tokens consumed
	FinishReason string  `json:"finish_reason"` // Reason for completion
	Cost         float64 `json:"cost"`          // Estimated cost
}