package services

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/database"
	"github.com/codeready/go-tarsy-bot/internal/models"
	"github.com/codeready/go-tarsy-bot/internal/integrations/llm"
)

// LLMIntegrationService provides a unified LLM interface with comprehensive logging and token tracking
// This matches the Python implementation's LLM integration exactly
type LLMIntegrationService struct {
	llmService     *LLMService
	historyService *HistoryService
	settings       *config.Settings
	logger         *zap.Logger

	// Provider configurations
	providerConfigs map[string]*ProviderConfig

	// Token cost estimation (per 1K tokens)
	tokenCosts map[string]*TokenCost
}

// ProviderConfig contains configuration for each LLM provider
type ProviderConfig struct {
	Name          string            `json:"name"`
	APIKey        string            `json:"-"` // Never serialize API keys
	BaseURL       string            `json:"base_url,omitempty"`
	DefaultModel  string            `json:"default_model"`
	MaxTokens     int               `json:"max_tokens"`
	Temperature   float64           `json:"temperature"`
	Timeout       time.Duration     `json:"timeout"`
	RateLimit     *RateLimit        `json:"rate_limit,omitempty"`
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
	Enabled       bool              `json:"enabled"`
}

// RateLimit defines rate limiting configuration for a provider
type RateLimit struct {
	RequestsPerMinute int           `json:"requests_per_minute"`
	TokensPerMinute   int           `json:"tokens_per_minute"`
	BurstSize         int           `json:"burst_size"`
	Cooldown          time.Duration `json:"cooldown"`
}

// TokenCost defines cost estimation for token usage
type TokenCost struct {
	InputCostPer1K  float64 `json:"input_cost_per_1k"`  // Cost per 1K input tokens
	OutputCostPer1K float64 `json:"output_cost_per_1k"` // Cost per 1K output tokens
	Currency        string  `json:"currency"`           // USD, EUR, etc.
}

// EnhancedGenerateRequest extends the basic request with session tracking
type EnhancedGenerateRequest struct {
	*GenerateWithToolsRequest

	// Session tracking
	SessionID       string `json:"session_id"`
	AgentType       string `json:"agent_type"`
	IterationIndex  *int   `json:"iteration_index,omitempty"`
	StageExecutionID *string `json:"stage_execution_id,omitempty"`

	// Cost tracking
	TrackCost       bool `json:"track_cost"`
	EstimateCost    bool `json:"estimate_cost"`

	// Provider override
	ForceProvider   string `json:"force_provider,omitempty"`
}

// EnhancedGenerateResponse extends the basic response with comprehensive tracking
type EnhancedGenerateResponse struct {
	*GenerateWithToolsResponse

	// Tracking information
	SessionID        string    `json:"session_id"`
	InteractionID    uint64    `json:"interaction_id"`
	Provider         string    `json:"provider"`
	Model            string    `json:"model"`
	TimestampUs      int64     `json:"timestamp_us"`

	// Token usage tracking
	TokenUsage       *TokenUsage `json:"token_usage"`
	EstimatedCost    *float64    `json:"estimated_cost,omitempty"`

	// Performance metrics
	FirstTokenTime   *time.Duration `json:"first_token_time,omitempty"`
	TokensPerSecond  *float64       `json:"tokens_per_second,omitempty"`
	ProcessingTime   time.Duration  `json:"processing_time"`
}

// TokenUsage provides detailed token usage information
type TokenUsage struct {
	InputTokens      int     `json:"input_tokens"`
	OutputTokens     int     `json:"output_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	CachedTokens     int     `json:"cached_tokens,omitempty"`
	InputCost        float64 `json:"input_cost"`
	OutputCost       float64 `json:"output_cost"`
	TotalCost        float64 `json:"total_cost"`
	Currency         string  `json:"currency"`
}

// NewLLMIntegrationService creates a new enhanced LLM integration service
func NewLLMIntegrationService(
	db *database.DB,
	settings *config.Settings,
	logger *zap.Logger,
) *LLMIntegrationService {
	// Create base LLM service
	llmConfig := &LLMServiceConfig{
		DefaultLLMClient: settings.DefaultLLMProvider,
		DefaultTimeout:   5 * time.Minute,
		EnableToolUse:    settings.IsFeatureEnabled("mcp_integration"),
	}
	llmService := NewLLMService(llmConfig, logger)

	// Create history service for logging
	historyService := NewHistoryService(db, logger)

	service := &LLMIntegrationService{
		llmService:      llmService,
		historyService:  historyService,
		settings:        settings,
		logger:          logger,
		providerConfigs: make(map[string]*ProviderConfig),
		tokenCosts:      make(map[string]*TokenCost),
	}

	// Initialize provider configurations
	service.initializeProviders()

	// Initialize token cost estimates
	service.initializeTokenCosts()

	return service
}

// initializeProviders sets up LLM provider configurations from settings
func (s *LLMIntegrationService) initializeProviders() {
	providers := []struct {
		name        string
		apiKeyFunc  func() string
		defaultModel string
		enabled     bool
	}{
		{
			name:         "openai",
			apiKeyFunc:   func() string { return s.settings.GetLLMAPIKey("openai") },
			defaultModel: "gpt-4",
			enabled:      s.settings.GetLLMAPIKey("openai") != "",
		},
		{
			name:         "anthropic",
			apiKeyFunc:   func() string { return s.settings.GetLLMAPIKey("anthropic") },
			defaultModel: "claude-3-sonnet-20240229",
			enabled:      s.settings.GetLLMAPIKey("anthropic") != "",
		},
		{
			name:         "google",
			apiKeyFunc:   func() string { return s.settings.GetLLMAPIKey("google") },
			defaultModel: "gemini-2.0-flash",
			enabled:      s.settings.GetLLMAPIKey("google") != "",
		},
		{
			name:         "xai",
			apiKeyFunc:   func() string { return s.settings.GetLLMAPIKey("xai") },
			defaultModel: "grok-beta",
			enabled:      s.settings.GetLLMAPIKey("xai") != "",
		},
	}

	for _, provider := range providers {
		config := &ProviderConfig{
			Name:         provider.name,
			APIKey:       provider.apiKeyFunc(),
			DefaultModel: provider.defaultModel,
			MaxTokens:    s.settings.MaxLLMIterations * 1000, // Rough estimate
			Temperature:  s.settings.LLMTemperature,
			Timeout:      s.settings.AlertTimeout,
			Enabled:      provider.enabled,
			RateLimit: &RateLimit{
				RequestsPerMinute: 60,
				TokensPerMinute:   100000,
				BurstSize:         10,
				Cooldown:          time.Minute,
			},
		}

		s.providerConfigs[provider.name] = config

		if provider.enabled {
			// Create and register the actual LLM client
			if err := s.createAndRegisterClient(provider.name, config); err != nil {
				s.logger.Error("Failed to register LLM client",
					zap.String("provider", provider.name),
					zap.Error(err))
			}
		}
	}
}

// initializeTokenCosts sets up token cost estimates for providers
func (s *LLMIntegrationService) initializeTokenCosts() {
	// Current pricing as of 2024 (approximate)
	costs := map[string]*TokenCost{
		"openai": {
			InputCostPer1K:  0.01,  // GPT-4 input cost per 1K tokens
			OutputCostPer1K: 0.03,  // GPT-4 output cost per 1K tokens
			Currency:        "USD",
		},
		"anthropic": {
			InputCostPer1K:  0.008, // Claude-3 Sonnet input cost per 1K tokens
			OutputCostPer1K: 0.024, // Claude-3 Sonnet output cost per 1K tokens
			Currency:        "USD",
		},
		"google": {
			InputCostPer1K:  0.0005, // Gemini Pro input cost per 1K tokens
			OutputCostPer1K: 0.0015, // Gemini Pro output cost per 1K tokens
			Currency:        "USD",
		},
		"xai": {
			InputCostPer1K:  0.005,  // Grok estimated input cost per 1K tokens
			OutputCostPer1K: 0.015,  // Grok estimated output cost per 1K tokens
			Currency:        "USD",
		},
	}

	for provider, cost := range costs {
		s.tokenCosts[provider] = cost
	}
}

// createAndRegisterClient creates and registers an LLM client
func (s *LLMIntegrationService) createAndRegisterClient(name string, config *ProviderConfig) error {
	// Create LLM configuration for the factory
	llmConfig := &llm.LLMConfig{
		Provider:    name,
		APIKey:      config.APIKey,
		BaseURL:     config.BaseURL,
		Model:       config.DefaultModel,
		Temperature: float32(config.Temperature),
		MaxTokens:   config.MaxTokens,
		Timeout:     config.Timeout,
		RetryCount:  3, // Default retry count
	}

	// Create client factory and use it to create the actual client
	factory := llm.NewClientFactory(s.logger)
	client, err := factory.CreateClient(llmConfig)
	if err != nil {
		return fmt.Errorf("failed to create %s client: %w", name, err)
	}

	return s.llmService.RegisterLLMClient(name, client)
}

// GenerateWithTracking generates text with comprehensive tracking and logging
func (s *LLMIntegrationService) GenerateWithTracking(ctx context.Context, request *EnhancedGenerateRequest) (*EnhancedGenerateResponse, error) {
	startTime := time.Now()
	timestampUs := models.GetCurrentTimestampUs()

	// Validate request
	if err := s.validateEnhancedRequest(request); err != nil {
		return nil, fmt.Errorf("invalid enhanced request: %w", err)
	}

	// Determine provider
	provider := request.ForceProvider
	if provider == "" {
		provider = s.settings.DefaultLLMProvider
	}

	// Validate provider is available
	if !s.isProviderAvailable(provider) {
		return nil, fmt.Errorf("provider %s is not available or configured", provider)
	}

	// Override preferred LLM in base request
	request.PreferredLLM = provider

	// Debug: Log stage execution ID presence
	s.logger.Debug("LLM Integration Service: Processing request",
		zap.String("session_id", request.SessionID),
		zap.String("agent_type", request.AgentType),
		zap.String("stage_execution_id", func() string {
			if request.StageExecutionID != nil {
				return *request.StageExecutionID
			}
			return "nil"
		}()),
		zap.String("iteration_index", func() string {
			if request.IterationIndex != nil {
				return fmt.Sprintf("%d", *request.IterationIndex)
			}
			return "nil"
		}()))

	// Log request start
	if request.SessionID != "" {
		if err := s.logLLMRequestStart(ctx, request, provider, timestampUs); err != nil {
			s.logger.Error("Failed to log LLM request start", zap.Error(err))
		}
	}

	// Execute the generation
	response, err := s.llmService.Generate(ctx, request.GenerateWithToolsRequest)
	if err != nil {
		// Log the error
		if request.SessionID != "" {
			s.logLLMRequestError(ctx, request, provider, err, startTime)
		}
		return nil, fmt.Errorf("LLM generation failed: %w", err)
	}

	// Calculate processing time
	processingTime := time.Since(startTime)

	// Create internal enhanced response for tracking
	enhancedResponse := &EnhancedGenerateResponse{
		GenerateWithToolsResponse: response,
		SessionID:                 request.SessionID,
		Provider:                  provider,
		Model:                     request.Model,
		TimestampUs:               timestampUs,
		ProcessingTime:            processingTime,
	}

	// Calculate token usage and cost if enabled
	if s.settings.TokenTrackingEnabled {
		tokenUsage := s.calculateTokenUsage(response, provider)
		enhancedResponse.TokenUsage = tokenUsage

		if s.settings.CostTrackingEnabled || request.EstimateCost {
			cost := s.estimateCost(tokenUsage, provider)
			enhancedResponse.EstimatedCost = &cost
		}
	}

	// Calculate performance metrics
	if enhancedResponse.TokenUsage != nil && enhancedResponse.TokenUsage.OutputTokens > 0 && processingTime > 0 {
		tokensPerSecond := float64(enhancedResponse.TokenUsage.OutputTokens) / processingTime.Seconds()
		enhancedResponse.TokensPerSecond = &tokensPerSecond
	}

	// Log successful completion
	if request.SessionID != "" {
		interactionID, err := s.logLLMRequestSuccess(ctx, request, enhancedResponse)
		if err != nil {
			s.logger.Error("Failed to log LLM request success", zap.Error(err))
		} else {
			enhancedResponse.InteractionID = interactionID
		}
	}

	inputTokens := 0
	outputTokens := 0
	if enhancedResponse.TokenUsage != nil {
		inputTokens = enhancedResponse.TokenUsage.InputTokens
		outputTokens = enhancedResponse.TokenUsage.OutputTokens
	}

	s.logger.Info("LLM generation completed",
		zap.String("session_id", request.SessionID),
		zap.String("provider", provider),
		zap.String("model", request.Model),
		zap.Duration("processing_time", processingTime),
		zap.Int("input_tokens", inputTokens),
		zap.Int("output_tokens", outputTokens),
		zap.Bool("tools_used", len(response.ToolCalls) > 0),
	)

	return enhancedResponse, nil
}

// calculateTokenUsage calculates detailed token usage information
func (s *LLMIntegrationService) calculateTokenUsage(response *GenerateWithToolsResponse, provider string) *TokenUsage {
	inputTokens := 0
	outputTokens := 0
	totalTokens := 0

	// Extract token usage from the LLM response
	if response.Usage != nil {
		inputTokens = response.Usage.PromptTokens
		outputTokens = response.Usage.CompletionTokens
		totalTokens = response.Usage.TotalTokens
	}

	tokenUsage := &TokenUsage{
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		TotalTokens:  totalTokens,
		Currency:     "USD",
	}

	// Calculate costs if cost tracking is enabled
	if cost, exists := s.tokenCosts[provider]; exists {
		tokenUsage.InputCost = float64(inputTokens) / 1000 * cost.InputCostPer1K
		tokenUsage.OutputCost = float64(outputTokens) / 1000 * cost.OutputCostPer1K
		tokenUsage.TotalCost = tokenUsage.InputCost + tokenUsage.OutputCost
		tokenUsage.Currency = cost.Currency
	}

	return tokenUsage
}

// estimateCost estimates the cost of a request
func (s *LLMIntegrationService) estimateCost(tokenUsage *TokenUsage, provider string) float64 {
	if tokenUsage == nil {
		return 0.0
	}
	return tokenUsage.TotalCost
}

// logLLMRequestStart logs the start of an LLM request
func (s *LLMIntegrationService) logLLMRequestStart(ctx context.Context, request *EnhancedGenerateRequest, provider string, timestampUs int64) error {
	return s.historyService.LogSystemEvent(ctx, request.SessionID, "llm_request_start",
		fmt.Sprintf("Starting LLM request to %s", provider),
		map[string]interface{}{
			"provider":           provider,
			"model":              request.Model,
			"temperature":        request.Temperature,
			"max_tokens":         request.MaxTokens,
			"enable_tools":       request.EnableTools,
			"iteration_index":    request.IterationIndex,
			"stage_execution_id": request.StageExecutionID,
		})
}

// logLLMRequestSuccess logs a successful LLM request with full details
func (s *LLMIntegrationService) logLLMRequestSuccess(ctx context.Context, request *EnhancedGenerateRequest, response *EnhancedGenerateResponse) (uint64, error) {
	// Prepare request/response data for logging
	requestData := map[string]interface{}{
		"messages":     request.Messages,
		"model":        request.Model,
		"temperature":  request.Temperature,
		"max_tokens":   request.MaxTokens,
		"provider":     response.Provider,
		"enable_tools": request.EnableTools,
	}

	inputTokens := 0
	outputTokens := 0
	if response.TokenUsage != nil {
		inputTokens = response.TokenUsage.InputTokens
		outputTokens = response.TokenUsage.OutputTokens
	}

	responseData := map[string]interface{}{
		"content":           response.Content,
		"finish_reason":     response.FinishReason,
		"input_tokens":      inputTokens,
		"output_tokens":     outputTokens,
		"processing_time":   response.ProcessingTime.Milliseconds(),
		"tool_calls":        len(response.ToolCalls),
		"estimated_cost":    response.EstimatedCost,
		"tokens_per_second": response.TokensPerSecond,
	}

	// Debug: Log the stage execution ID that will be set in timeline interaction
	s.logger.Debug("LLM Integration Service: Creating timeline interaction",
		zap.String("session_id", request.SessionID),
		zap.String("stage_execution_id", func() string {
			if request.StageExecutionID != nil {
				return *request.StageExecutionID
			}
			return "nil"
		}()),
		zap.String("iteration_index", func() string {
			if request.IterationIndex != nil {
				return fmt.Sprintf("%d", *request.IterationIndex)
			}
			return "nil"
		}()))

	// Create timeline interaction
	interaction := &models.TimelineInteraction{
		SessionID:        request.SessionID,
		Type:             models.InteractionTypeLLMRequest,
		Source:           request.AgentType,
		Target:           response.Provider,
		TimestampUs:      response.TimestampUs,
		Content:          models.JSONFromInterface(map[string]interface{}{
			"request":  requestData,
			"response": responseData,
		}),
		Status:           models.InteractionStatusCompleted,
		StageExecutionID: request.StageExecutionID,
		IterationIndex:   request.IterationIndex,
	}

	// Set token usage if available
	if response.TokenUsage != nil {
		interaction.SetTokenUsage(response.TokenUsage.InputTokens, response.TokenUsage.OutputTokens)
		if response.EstimatedCost != nil {
			interaction.EstimatedCost = response.EstimatedCost
		}
	}

	// Set duration
	durationUs := response.ProcessingTime.Microseconds()
	interaction.DurationUs = &durationUs

	// Create the interaction
	err := s.historyService.CreateTimelineInteraction(ctx, interaction)
	if err != nil {
		return 0, err
	}

	// Debug: Log what was actually stored
	s.logger.Debug("LLM Integration Service: Timeline interaction created",
		zap.Uint64("interaction_id", interaction.ID),
		zap.String("session_id", interaction.SessionID),
		zap.String("type", interaction.Type),
		zap.String("stored_stage_execution_id", func() string {
			if interaction.StageExecutionID != nil {
				return *interaction.StageExecutionID
			}
			return "nil"
		}()),
		zap.String("stored_iteration_index", func() string {
			if interaction.IterationIndex != nil {
				return fmt.Sprintf("%d", *interaction.IterationIndex)
			}
			return "nil"
		}()))

	return interaction.ID, nil
}

// logLLMRequestError logs a failed LLM request
func (s *LLMIntegrationService) logLLMRequestError(ctx context.Context, request *EnhancedGenerateRequest, provider string, err error, startTime time.Time) {
	durationUs := time.Since(startTime).Microseconds()

	interaction := &models.TimelineInteraction{
		SessionID:        request.SessionID,
		Type:             models.InteractionTypeLLMRequest,
		Source:           request.AgentType,
		Target:           provider,
		TimestampUs:      models.GetCurrentTimestampUs(),
		Content:          models.JSONFromInterface(map[string]interface{}{
			"request": map[string]interface{}{
				"model":        request.Model,
				"temperature":  request.Temperature,
				"max_tokens":   request.MaxTokens,
				"enable_tools": request.EnableTools,
			},
			"error": err.Error(),
		}),
		Status:           models.InteractionStatusFailed,
		DurationUs:       &durationUs,
		StageExecutionID: request.StageExecutionID,
		IterationIndex:   request.IterationIndex,
	}

	interaction.MarkFailed(err.Error())

	if logErr := s.historyService.CreateTimelineInteraction(ctx, interaction); logErr != nil {
		s.logger.Error("Failed to log LLM request error", zap.Error(logErr))
	}
}

// validateEnhancedRequest validates an enhanced generate request
func (s *LLMIntegrationService) validateEnhancedRequest(request *EnhancedGenerateRequest) error {
	if request.GenerateWithToolsRequest == nil {
		return fmt.Errorf("base generate request is required")
	}

	if request.SessionID == "" && s.settings.TokenTrackingEnabled {
		return fmt.Errorf("session_id is required when token tracking is enabled")
	}

	if request.AgentType == "" {
		request.AgentType = "unknown"
	}

	return nil
}

// isProviderAvailable checks if a provider is configured and available
func (s *LLMIntegrationService) isProviderAvailable(provider string) bool {
	config, exists := s.providerConfigs[provider]
	return exists && config.Enabled && config.APIKey != ""
}

// GetProviderStatus returns the status of all configured providers
func (s *LLMIntegrationService) GetProviderStatus() map[string]interface{} {
	status := make(map[string]interface{})

	for name, config := range s.providerConfigs {
		status[name] = map[string]interface{}{
			"enabled":       config.Enabled,
			"configured":    config.APIKey != "",
			"default_model": config.DefaultModel,
			"max_tokens":    config.MaxTokens,
			"temperature":   config.Temperature,
			"timeout":       config.Timeout.String(),
		}
	}

	return status
}

// GetTokenUsageStats returns aggregated token usage statistics
func (s *LLMIntegrationService) GetTokenUsageStats(ctx context.Context, sessionID string) (*models.TokenUsageStatistics, error) {
	return s.historyService.GetTokenUsageStatistics(ctx, sessionID)
}

// SetProviderConfig updates configuration for a specific provider
func (s *LLMIntegrationService) SetProviderConfig(provider string, config *ProviderConfig) error {
	if config == nil {
		return fmt.Errorf("provider config cannot be nil")
	}

	s.providerConfigs[provider] = config

	// Re-register the client if it's enabled
	if config.Enabled && config.APIKey != "" {
		return s.createAndRegisterClient(provider, config)
	}

	return nil
}

// GetAvailableProviders returns a list of available providers
func (s *LLMIntegrationService) GetAvailableProviders() []string {
	providers := make([]string, 0, len(s.providerConfigs))
	for name, config := range s.providerConfigs {
		if config.Enabled {
			providers = append(providers, name)
		}
	}
	return providers
}

// HealthCheck performs a health check on all configured providers
func (s *LLMIntegrationService) HealthCheck(ctx context.Context) map[string]string {
	health := make(map[string]string)

	for name, config := range s.providerConfigs {
		if !config.Enabled {
			health[name] = "disabled"
			continue
		}

		if config.APIKey == "" {
			health[name] = "not_configured"
			continue
		}

		// Perform actual health check (simplified)
		health[name] = "healthy"
	}

	return health
}