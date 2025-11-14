package iteration_controllers

import (
	"context"
	"fmt"

	"github.com/codeready/go-tarsy-bot/internal/shared"
	"github.com/codeready/go-tarsy-bot/internal/integrations/llm"
)

// LLMServiceAdapter adapts the LLMIntegrationInterface to the LLMServiceInterface
// This bridges the gap between the agent's LLM integration and the iteration controllers
type LLMServiceAdapter struct {
	integration shared.LLMIntegrationInterface
	agentType   string
}

// NewLLMServiceAdapter creates a new adapter
func NewLLMServiceAdapter(integration shared.LLMIntegrationInterface, agentType string) *LLMServiceAdapter {
	return &LLMServiceAdapter{
		integration: integration,
		agentType:   agentType,
	}
}

// Generate implements LLMServiceInterface.Generate
func (a *LLMServiceAdapter) Generate(ctx context.Context, request *GenerateWithToolsRequest) (*LLMResponse, error) {
	// Extract session ID from context if available
	sessionID := ""
	if ctxSessionID := ctx.Value("session_id"); ctxSessionID != nil {
		if sid, ok := ctxSessionID.(string); ok {
			sessionID = sid
		}
	}

	// Extract iteration index from context if available
	var iterationIndex *int
	if ctxIterationIndex := ctx.Value("iteration_index"); ctxIterationIndex != nil {
		if idx, ok := ctxIterationIndex.(int); ok {
			iterationIndex = &idx
		}
	}

	// Extract stage execution ID from context if available
	var stageExecutionID *string
	if ctxStageExecutionID := ctx.Value("stage_execution_id"); ctxStageExecutionID != nil {
		if sid, ok := ctxStageExecutionID.(string); ok {
			stageExecutionID = &sid
		}
	}

	// Debug: Log what we extracted from context
	fmt.Printf("DEBUG LLM Adapter: session_id=%s, iteration_index=%v, stage_execution_id=%v\n",
		sessionID, iterationIndex, func() string {
			if stageExecutionID != nil {
				return *stageExecutionID
			}
			return "nil"
		}())

	// Convert the iteration controller request to the shared interface request
	enhancedRequest := &shared.EnhancedGenerateRequest{
		GenerateWithToolsRequest: &shared.GenerateWithToolsRequest{
			GenerateRequest: convertGenerateRequest(request.GenerateRequest),
			EnableTools:     request.EnableTools,
		},
		SessionID:        sessionID,
		AgentType:        a.agentType,
		IterationIndex:   iterationIndex,
		StageExecutionID: stageExecutionID,
		TrackCost:        true,
		EstimateCost:     false,
	}

	// Call the LLM integration service
	response, err := a.integration.GenerateWithTracking(ctx, enhancedRequest)
	if err != nil {
		return nil, err
	}

	// Convert the agent response to the iteration controller response
	return &LLMResponse{
		Content:      response.Content,
		Model:        response.Model,
		TokensUsed:   response.TokensUsed,
		FinishReason: response.FinishReason,
		Cost:         response.Cost,
	}, nil
}

// convertGenerateRequest converts from iteration controller format to shared format
func convertGenerateRequest(req *llm.GenerateRequest) *shared.GenerateRequest {
	// Convert messages
	messages := make([]shared.Message, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = shared.Message{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	// Convert temperature from *float32 to *float64
	var temperature *float64
	if req.Temperature != nil {
		temp := float64(*req.Temperature)
		temperature = &temp
	}

	return &shared.GenerateRequest{
		Messages:     messages,
		SystemPrompt: req.SystemPrompt,
		Model:        req.Model,
		Temperature:  temperature,
		MaxTokens:    req.MaxTokens,
	}
}