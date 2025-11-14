package prompts

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/models"
)

// AdvancedVariableResolver provides sophisticated variable resolution capabilities
// that extend beyond simple substitution to include expressions, transformations,
// conditional logic, nested references, and context-aware resolution
type AdvancedVariableResolver struct {
	baseResolver    *TemplateVariableResolver
	configResolver  *config.TemplateResolver
	logger          *zap.Logger

	// Advanced features
	expressions     map[string]*Expression
	transformers    map[string]Transformer
	conditionals    map[string]*ConditionalBlock
	nestedRefs      map[string]string
	contextStack    []*ResolutionContext

	// Performance and caching
	cache           map[string]*CachedResolution
	maxCacheSize    int
	cacheEnabled    bool

	// Configuration
	config          *AdvancedResolverConfig

	// Runtime state
	currentContext  *ResolutionContext
	depth          int
	maxDepth       int
}

// Expression represents a complex expression that can be evaluated
type Expression struct {
	Name        string                 `json:"name"`
	Type        ExpressionType         `json:"type"`
	Formula     string                 `json:"formula"`
	Variables   []string               `json:"variables"`
	Conditions  []string               `json:"conditions"`
	Transform   string                 `json:"transform,omitempty"`
	DefaultValue interface{}           `json:"default_value,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Transformer represents a data transformation function
type Transformer interface {
	Transform(input interface{}, params map[string]interface{}) (interface{}, error)
	GetName() string
	GetDescription() string
	ValidateParams(params map[string]interface{}) error
}

// ConditionalBlock represents complex conditional logic
type ConditionalBlock struct {
	Name        string                 `json:"name"`
	Conditions  []*Condition           `json:"conditions"`
	DefaultCase *ConditionalCase       `json:"default_case,omitempty"`
	Cases       []*ConditionalCase     `json:"cases"`
}

// Condition represents a single condition in conditional logic
type Condition struct {
	Expression string                 `json:"expression"`
	Operator   ComparisonOperator     `json:"operator"`
	Value      interface{}            `json:"value"`
	Logic      LogicalOperator        `json:"logic,omitempty"`
}

// ConditionalCase represents a case in conditional logic
type ConditionalCase struct {
	Condition string      `json:"condition"`
	Result    interface{} `json:"result"`
	Template  string      `json:"template,omitempty"`
}

// ResolutionContext contains context for variable resolution
type ResolutionContext struct {
	Name            string                 `json:"name"`
	Variables       map[string]interface{} `json:"variables"`
	Alert           *models.Alert          `json:"alert,omitempty"`
	ChainContext    *models.ChainContext   `json:"chain_context,omitempty"`
	AgentContext    *AgentContext          `json:"agent_context,omitempty"`
	TimeContext     *TimeContext           `json:"time_context,omitempty"`
	EnvironmentVars map[string]string      `json:"environment_vars,omitempty"`
	CustomContext   map[string]interface{} `json:"custom_context,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
}

// AgentContext contains agent-specific context
type AgentContext struct {
	Type          string   `json:"type"`
	Name          string   `json:"name"`
	Capabilities  []string `json:"capabilities"`
	Tools         []string `json:"tools"`
	MCPServers    []string `json:"mcp_servers"`
	Configuration map[string]interface{} `json:"configuration"`
}

// TimeContext contains time-related variables
type TimeContext struct {
	Current     time.Time `json:"current"`
	Timezone    string    `json:"timezone"`
	Format      string    `json:"format"`
	Locale      string    `json:"locale"`
}

// CachedResolution represents a cached resolution result
type CachedResolution struct {
	Result     string                 `json:"result"`
	Context    map[string]interface{} `json:"context"`
	Timestamp  time.Time              `json:"timestamp"`
	TTL        time.Duration          `json:"ttl"`
	AccessCount int                   `json:"access_count"`
}

// AdvancedResolverConfig contains configuration for the advanced resolver
type AdvancedResolverConfig struct {
	EnableExpressions    bool          `json:"enable_expressions"`
	EnableTransformers   bool          `json:"enable_transformers"`
	EnableConditionals   bool          `json:"enable_conditionals"`
	EnableNestedRefs     bool          `json:"enable_nested_refs"`
	EnableCaching        bool          `json:"enable_caching"`
	MaxDepth            int           `json:"max_depth"`
	MaxCacheSize        int           `json:"max_cache_size"`
	CacheTTL            time.Duration `json:"cache_ttl"`
	EnableDebugMode     bool          `json:"enable_debug_mode"`
	StrictMode          bool          `json:"strict_mode"`
	FailOnMissingVars   bool          `json:"fail_on_missing_vars"`
}

// Enums

type ExpressionType string

const (
	ExpressionTypeArithmetic   ExpressionType = "arithmetic"
	ExpressionTypeString       ExpressionType = "string"
	ExpressionTypeLogical      ExpressionType = "logical"
	ExpressionTypeComparison   ExpressionType = "comparison"
	ExpressionTypeConditional  ExpressionType = "conditional"
	ExpressionTypeTransform    ExpressionType = "transform"
	ExpressionTypeFunction     ExpressionType = "function"
)

type ComparisonOperator string

const (
	OpEqual              ComparisonOperator = "eq"
	OpNotEqual           ComparisonOperator = "ne"
	OpGreaterThan        ComparisonOperator = "gt"
	OpGreaterThanOrEqual ComparisonOperator = "gte"
	OpLessThan           ComparisonOperator = "lt"
	OpLessThanOrEqual    ComparisonOperator = "lte"
	OpContains           ComparisonOperator = "contains"
	OpStartsWith         ComparisonOperator = "starts_with"
	OpEndsWith           ComparisonOperator = "ends_with"
	OpMatches            ComparisonOperator = "matches"
	OpIn                 ComparisonOperator = "in"
	OpNotIn              ComparisonOperator = "not_in"
)

type LogicalOperator string

const (
	LogicalAnd LogicalOperator = "and"
	LogicalOr  LogicalOperator = "or"
	LogicalNot LogicalOperator = "not"
)

// NewAdvancedVariableResolver creates a new advanced variable resolver
func NewAdvancedVariableResolver(logger *zap.Logger) *AdvancedVariableResolver {
	return &AdvancedVariableResolver{
		baseResolver:   NewTemplateVariableResolver(),
		configResolver: config.NewTemplateResolver(logger),
		logger:         logger.With(zap.String("component", "advanced_variable_resolver")),
		expressions:    make(map[string]*Expression),
		transformers:   make(map[string]Transformer),
		conditionals:   make(map[string]*ConditionalBlock),
		nestedRefs:     make(map[string]string),
		contextStack:   make([]*ResolutionContext, 0),
		cache:          make(map[string]*CachedResolution),
		maxCacheSize:   1000,
		cacheEnabled:   true,
		config:         DefaultAdvancedResolverConfig(),
		maxDepth:       10,
		depth:          0,
	}
}

// DefaultAdvancedResolverConfig returns default configuration
func DefaultAdvancedResolverConfig() *AdvancedResolverConfig {
	return &AdvancedResolverConfig{
		EnableExpressions:   true,
		EnableTransformers:  true,
		EnableConditionals:  true,
		EnableNestedRefs:    true,
		EnableCaching:       true,
		MaxDepth:           10,
		MaxCacheSize:       1000,
		CacheTTL:           5 * time.Minute,
		EnableDebugMode:    false,
		StrictMode:         false,
		FailOnMissingVars:  false,
	}
}

// ResolveAdvanced performs advanced variable resolution with context
func (avr *AdvancedVariableResolver) ResolveAdvanced(template string, context *ResolutionContext) (*ResolutionResult, error) {
	if avr.depth >= avr.maxDepth {
		return nil, fmt.Errorf("maximum resolution depth exceeded: %d", avr.maxDepth)
	}

	avr.depth++
	defer func() { avr.depth-- }()

	// Set current context
	avr.currentContext = context
	avr.pushContext(context)
	defer avr.popContext()

	// Check cache if enabled
	if avr.config.EnableCaching {
		if cached := avr.getFromCache(template, context); cached != nil {
			avr.logger.Debug("Retrieved from cache",
				zap.String("template_hash", avr.hashTemplate(template)))
			return &ResolutionResult{
				ResolvedContent: cached.Result,
				Variables:       cached.Context,
				FromCache:       true,
				ProcessingTime:  time.Duration(0),
			}, nil
		}
	}

	startTime := time.Now()
	result := &ResolutionResult{
		Variables:      make(map[string]interface{}),
		Expressions:    make(map[string]interface{}),
		Transformations: make(map[string]interface{}),
		Conditionals:   make(map[string]interface{}),
		FromCache:      false,
	}

	// Merge variables from context into base resolver
	avr.mergeContextVariables(context)

	// Multi-pass resolution
	resolved := template

	// Pass 1: Resolve nested references if enabled
	if avr.config.EnableNestedRefs {
		var err error
		resolved, err = avr.resolveNestedReferences(resolved, result)
		if err != nil {
			return nil, fmt.Errorf("nested reference resolution failed: %w", err)
		}
	}

	// Pass 2: Resolve expressions if enabled
	if avr.config.EnableExpressions {
		var err error
		resolved, err = avr.resolveExpressions(resolved, result)
		if err != nil {
			return nil, fmt.Errorf("expression resolution failed: %w", err)
		}
	}

	// Pass 3: Apply transformers if enabled
	if avr.config.EnableTransformers {
		var err error
		resolved, err = avr.applyTransformers(resolved, result)
		if err != nil {
			return nil, fmt.Errorf("transformer application failed: %w", err)
		}
	}

	// Pass 4: Resolve conditionals if enabled
	if avr.config.EnableConditionals {
		var err error
		resolved, err = avr.resolveConditionals(resolved, result)
		if err != nil {
			return nil, fmt.Errorf("conditional resolution failed: %w", err)
		}
	}

	// Pass 5: Standard variable resolution using base resolver
	resolved = avr.baseResolver.Resolve(resolved)

	// Pass 6: Config template resolution for environment variables
	configResolved, err := avr.configResolver.ResolveTemplate(resolved)
	if err != nil {
		if avr.config.FailOnMissingVars {
			return nil, fmt.Errorf("config resolution failed: %w", err)
		}
		avr.logger.Warn("Config resolution failed, using partially resolved content", zap.Error(err))
		configResolved = resolved
	}

	result.ResolvedContent = configResolved
	result.ProcessingTime = time.Since(startTime)
	result.Variables = avr.baseResolver.GetAllVariables()

	// Cache the result if caching is enabled
	if avr.config.EnableCaching {
		avr.cacheResult(template, context, result)
	}

	avr.logger.Debug("Advanced resolution completed",
		zap.String("template_length", fmt.Sprintf("%d", len(template))),
		zap.String("result_length", fmt.Sprintf("%d", len(configResolved))),
		zap.Duration("processing_time", result.ProcessingTime),
		zap.Int("variables_resolved", len(result.Variables)))

	return result, nil
}

// resolveNestedReferences resolves nested variable references like ${VAR_${OTHER_VAR}}
func (avr *AdvancedVariableResolver) resolveNestedReferences(template string, result *ResolutionResult) (string, error) {
	// Pattern to match nested references: ${VAR_${OTHER}}
	nestedPattern := regexp.MustCompile(`\$\{([^{}]*\$\{[^}]+\}[^{}]*)\}`)

	maxIterations := 10
	iteration := 0
	resolved := template

	for nestedPattern.MatchString(resolved) && iteration < maxIterations {
		resolved = nestedPattern.ReplaceAllStringFunc(resolved, func(match string) string {
			// Extract the inner expression
			inner := match[2 : len(match)-1] // Remove ${ and }

			// Resolve inner references first
			innerResolved := avr.baseResolver.Resolve(inner)

			// Now resolve the outer reference
			outerRef := "${" + innerResolved + "}"
			outerResolved := avr.baseResolver.Resolve(outerRef)

			avr.logger.Debug("Resolved nested reference",
				zap.String("original", match),
				zap.String("inner_resolved", innerResolved),
				zap.String("final_resolved", outerResolved))

			return outerResolved
		})
		iteration++
	}

	if iteration >= maxIterations {
		avr.logger.Warn("Maximum nested reference iterations reached",
			zap.Int("max_iterations", maxIterations))
	}

	return resolved, nil
}

// resolveExpressions resolves complex expressions
func (avr *AdvancedVariableResolver) resolveExpressions(template string, result *ResolutionResult) (string, error) {
	// Pattern to match expressions: ${expr:expression_name} or ${expr:inline_expression}
	exprPattern := regexp.MustCompile(`\$\{expr:([^}]+)\}`)

	resolved := exprPattern.ReplaceAllStringFunc(template, func(match string) string {
		exprContent := match[7 : len(match)-1] // Remove ${expr: and }

		// Check if it's a registered expression
		if expr, exists := avr.expressions[exprContent]; exists {
			evaluated, err := avr.evaluateExpression(expr)
			if err != nil {
				avr.logger.Error("Expression evaluation failed",
					zap.String("expression", exprContent),
					zap.Error(err))
				return match // Return original on error
			}

			result.Expressions[exprContent] = evaluated
			return fmt.Sprintf("%v", evaluated)
		}

		// Try to evaluate as inline expression
		evaluated, err := avr.evaluateInlineExpression(exprContent)
		if err != nil {
			avr.logger.Error("Inline expression evaluation failed",
				zap.String("expression", exprContent),
				zap.Error(err))
			return match // Return original on error
		}

		result.Expressions[exprContent] = evaluated
		return fmt.Sprintf("%v", evaluated)
	})

	return resolved, nil
}

// applyTransformers applies data transformations
func (avr *AdvancedVariableResolver) applyTransformers(template string, result *ResolutionResult) (string, error) {
	// Pattern to match transformers: ${transform:transformer_name:variable_name[:params]}
	transformPattern := regexp.MustCompile(`\$\{transform:([^:]+):([^:}]+)(?::([^}]+))?\}`)

	resolved := transformPattern.ReplaceAllStringFunc(template, func(match string) string {
		matches := transformPattern.FindStringSubmatch(match)
		if len(matches) < 3 {
			return match
		}

		transformerName := matches[1]
		variableName := matches[2]
		paramsStr := ""
		if len(matches) > 3 {
			paramsStr = matches[3]
		}

		// Get transformer
		transformer, exists := avr.transformers[transformerName]
		if !exists {
			avr.logger.Error("Transformer not found", zap.String("transformer", transformerName))
			return match
		}

		// Get variable value
		value, exists := avr.baseResolver.GetVariable(variableName)
		if !exists {
			avr.logger.Error("Variable not found for transformation",
				zap.String("variable", variableName))
			return match
		}

		// Parse parameters
		params := avr.parseTransformParams(paramsStr)

		// Apply transformation
		transformed, err := transformer.Transform(value, params)
		if err != nil {
			avr.logger.Error("Transformation failed",
				zap.String("transformer", transformerName),
				zap.String("variable", variableName),
				zap.Error(err))
			return match
		}

		result.Transformations[transformerName+"::"+variableName] = transformed
		return fmt.Sprintf("%v", transformed)
	})

	return resolved, nil
}

// resolveConditionals resolves conditional blocks
func (avr *AdvancedVariableResolver) resolveConditionals(template string, result *ResolutionResult) (string, error) {
	// Pattern to match conditionals: ${cond:condition_name} or ${cond:inline_condition}
	condPattern := regexp.MustCompile(`\$\{cond:([^}]+)\}`)

	resolved := condPattern.ReplaceAllStringFunc(template, func(match string) string {
		condContent := match[6 : len(match)-1] // Remove ${cond: and }

		// Check if it's a registered conditional
		if cond, exists := avr.conditionals[condContent]; exists {
			evaluated, err := avr.evaluateConditional(cond)
			if err != nil {
				avr.logger.Error("Conditional evaluation failed",
					zap.String("conditional", condContent),
					zap.Error(err))
				return match
			}

			result.Conditionals[condContent] = evaluated
			return fmt.Sprintf("%v", evaluated)
		}

		// Try to evaluate as inline conditional
		evaluated, err := avr.evaluateInlineConditional(condContent)
		if err != nil {
			avr.logger.Error("Inline conditional evaluation failed",
				zap.String("conditional", condContent),
				zap.Error(err))
			return match
		}

		result.Conditionals[condContent] = evaluated
		return fmt.Sprintf("%v", evaluated)
	})

	return resolved, nil
}

// ResolutionResult represents the result of advanced resolution
type ResolutionResult struct {
	ResolvedContent  string                 `json:"resolved_content"`
	Variables        map[string]interface{} `json:"variables"`
	Expressions      map[string]interface{} `json:"expressions"`
	Transformations  map[string]interface{} `json:"transformations"`
	Conditionals     map[string]interface{} `json:"conditionals"`
	ProcessingTime   time.Duration          `json:"processing_time"`
	FromCache        bool                   `json:"from_cache"`
	CacheHit         bool                   `json:"cache_hit"`
	Warnings         []string               `json:"warnings,omitempty"`
	Errors           []string               `json:"errors,omitempty"`
}

// Supporting methods for the advanced resolver

// mergeContextVariables merges variables from resolution context into base resolver
func (avr *AdvancedVariableResolver) mergeContextVariables(context *ResolutionContext) {
	if context == nil {
		return
	}

	// Set basic context variables
	for key, value := range context.Variables {
		avr.baseResolver.SetVariable(key, value)
	}

	// Set alert context variables
	if context.Alert != nil {
		avr.baseResolver.SetVariable("ALERT_TYPE", context.Alert.AlertType)
		avr.baseResolver.SetVariable("ALERT_DATA", context.Alert.Data)
		avr.baseResolver.SetVariable("ALERT_SEVERITY", context.Alert.GetSeverity())
		if context.Alert.Timestamp != nil {
			avr.baseResolver.SetVariable("ALERT_TIMESTAMP", context.Alert.Timestamp.Format(time.RFC3339))
		}
	}

	// Set chain context variables
	if context.ChainContext != nil {
		avr.baseResolver.SetVariable("SESSION_ID", context.ChainContext.SessionID)
		avr.baseResolver.SetVariable("CURRENT_STAGE", context.ChainContext.CurrentStageName)
		if context.ChainContext.RunbookContent != nil {
			avr.baseResolver.SetVariable("RUNBOOK_CONTENT", *context.ChainContext.RunbookContent)
		}
	}

	// Set agent context variables
	if context.AgentContext != nil {
		avr.baseResolver.SetVariable("AGENT_TYPE", context.AgentContext.Type)
		avr.baseResolver.SetVariable("AGENT_NAME", context.AgentContext.Name)
		avr.baseResolver.SetVariable("AGENT_CAPABILITIES", strings.Join(context.AgentContext.Capabilities, ", "))
		avr.baseResolver.SetVariable("AVAILABLE_TOOLS", strings.Join(context.AgentContext.Tools, ", "))
		avr.baseResolver.SetVariable("MCP_SERVERS", strings.Join(context.AgentContext.MCPServers, ", "))
	}

	// Set time context variables
	if context.TimeContext != nil {
		avr.baseResolver.SetVariable("CURRENT_TIME", context.TimeContext.Current.Format(time.RFC3339))
		avr.baseResolver.SetVariable("TIMEZONE", context.TimeContext.Timezone)
		if context.TimeContext.Format != "" {
			avr.baseResolver.SetVariable("FORMATTED_TIME", context.TimeContext.Current.Format(context.TimeContext.Format))
		}
	}

	// Set custom context variables
	for key, value := range context.CustomContext {
		avr.baseResolver.SetVariable(key, value)
	}

	// Always set timestamp
	avr.baseResolver.SetVariable("TIMESTAMP", context.Timestamp.Format(time.RFC3339))
	avr.baseResolver.SetVariable("UNIX_TIMESTAMP", context.Timestamp.Unix())
}

// pushContext pushes a context onto the stack
func (avr *AdvancedVariableResolver) pushContext(context *ResolutionContext) {
	avr.contextStack = append(avr.contextStack, context)
}

// popContext pops a context from the stack
func (avr *AdvancedVariableResolver) popContext() {
	if len(avr.contextStack) > 0 {
		avr.contextStack = avr.contextStack[:len(avr.contextStack)-1]
	}
}

// Placeholder implementations for evaluation methods
func (avr *AdvancedVariableResolver) evaluateExpression(expr *Expression) (interface{}, error) {
	// This would implement sophisticated expression evaluation
	// For now, return a placeholder
	return fmt.Sprintf("EXPR_RESULT_%s", expr.Name), nil
}

func (avr *AdvancedVariableResolver) evaluateInlineExpression(expr string) (interface{}, error) {
	// This would implement inline expression evaluation
	// For now, return a placeholder
	return fmt.Sprintf("INLINE_EXPR_%s", expr), nil
}

func (avr *AdvancedVariableResolver) evaluateConditional(cond *ConditionalBlock) (interface{}, error) {
	// This would implement conditional evaluation
	// For now, return a placeholder
	return fmt.Sprintf("COND_RESULT_%s", cond.Name), nil
}

func (avr *AdvancedVariableResolver) evaluateInlineConditional(cond string) (interface{}, error) {
	// This would implement inline conditional evaluation
	// For now, return a placeholder
	return fmt.Sprintf("INLINE_COND_%s", cond), nil
}

func (avr *AdvancedVariableResolver) parseTransformParams(paramsStr string) map[string]interface{} {
	params := make(map[string]interface{})
	if paramsStr == "" {
		return params
	}

	// Simple parameter parsing - would be enhanced for complex cases
	pairs := strings.Split(paramsStr, ",")
	for _, pair := range pairs {
		if kv := strings.SplitN(strings.TrimSpace(pair), "=", 2); len(kv) == 2 {
			params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	return params
}

// Cache management methods

func (avr *AdvancedVariableResolver) getFromCache(template string, context *ResolutionContext) *CachedResolution {
	key := avr.generateCacheKey(template, context)
	cached, exists := avr.cache[key]
	if !exists {
		return nil
	}

	// Check TTL
	if time.Since(cached.Timestamp) > avr.config.CacheTTL {
		delete(avr.cache, key)
		return nil
	}

	cached.AccessCount++
	return cached
}

func (avr *AdvancedVariableResolver) cacheResult(template string, context *ResolutionContext, result *ResolutionResult) {
	if len(avr.cache) >= avr.maxCacheSize {
		avr.evictOldestCacheEntry()
	}

	key := avr.generateCacheKey(template, context)
	avr.cache[key] = &CachedResolution{
		Result:      result.ResolvedContent,
		Context:     result.Variables,
		Timestamp:   time.Now(),
		TTL:         avr.config.CacheTTL,
		AccessCount: 0,
	}
}

func (avr *AdvancedVariableResolver) generateCacheKey(template string, context *ResolutionContext) string {
	// Generate a cache key based on template and context
	return fmt.Sprintf("%x", avr.hashTemplate(template+fmt.Sprintf("%v", context)))
}

func (avr *AdvancedVariableResolver) hashTemplate(template string) string {
	// Simple hash for now - would use proper hashing in production
	return fmt.Sprintf("%x", len(template))
}

func (avr *AdvancedVariableResolver) evictOldestCacheEntry() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range avr.cache {
		if oldestKey == "" || cached.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.Timestamp
		}
	}

	if oldestKey != "" {
		delete(avr.cache, oldestKey)
	}
}

// Public API methods for registration and configuration

// RegisterExpression registers a named expression
func (avr *AdvancedVariableResolver) RegisterExpression(expr *Expression) {
	avr.expressions[expr.Name] = expr
	avr.logger.Debug("Registered expression", zap.String("name", expr.Name))
}

// RegisterTransformer registers a transformer
func (avr *AdvancedVariableResolver) RegisterTransformer(transformer Transformer) {
	avr.transformers[transformer.GetName()] = transformer
	avr.logger.Debug("Registered transformer", zap.String("name", transformer.GetName()))
}

// RegisterConditional registers a conditional block
func (avr *AdvancedVariableResolver) RegisterConditional(cond *ConditionalBlock) {
	avr.conditionals[cond.Name] = cond
	avr.logger.Debug("Registered conditional", zap.String("name", cond.Name))
}

// SetConfiguration updates the resolver configuration
func (avr *AdvancedVariableResolver) SetConfiguration(config *AdvancedResolverConfig) {
	avr.config = config
	avr.maxDepth = config.MaxDepth
	avr.maxCacheSize = config.MaxCacheSize
	avr.cacheEnabled = config.EnableCaching
}

// GetStatistics returns resolver statistics
func (avr *AdvancedVariableResolver) GetStatistics() *ResolverStatistics {
	return &ResolverStatistics{
		CacheSize:         len(avr.cache),
		CacheHitRate:      avr.calculateCacheHitRate(),
		ExpressionsCount:  len(avr.expressions),
		TransformersCount: len(avr.transformers),
		ConditionalsCount: len(avr.conditionals),
	}
}

// ResolverStatistics contains resolver performance statistics
type ResolverStatistics struct {
	CacheSize         int     `json:"cache_size"`
	CacheHitRate      float64 `json:"cache_hit_rate"`
	ExpressionsCount  int     `json:"expressions_count"`
	TransformersCount int     `json:"transformers_count"`
	ConditionalsCount int     `json:"conditionals_count"`
}

func (avr *AdvancedVariableResolver) calculateCacheHitRate() float64 {
	// Placeholder implementation
	return 0.0
}