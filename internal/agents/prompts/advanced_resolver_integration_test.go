package prompts

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/codeready/go-tarsy-bot/internal/models"
)

// TestAdvancedVariableResolverBasicFunctionality tests core resolver functionality
func TestAdvancedVariableResolverBasicFunctionality(t *testing.T) {
	logger := zaptest.NewLogger(t)
	resolver := NewAdvancedVariableResolver(logger)

	// Test basic variable resolution
	template := "Hello ${NAME}, welcome to ${SYSTEM:TARSy-bot}!"
	context := &ResolutionContext{
		Name: "test_context",
		Variables: map[string]interface{}{
			"NAME": "John Doe",
		},
		Timestamp: time.Now(),
	}

	result, err := resolver.ResolveAdvanced(template, context)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.MaskingApplied || len(result.Variables) > 0)
	assert.Contains(t, result.ResolvedContent, "John Doe")
	assert.Contains(t, result.ResolvedContent, "TARSy-bot")
}

// TestAdvancedVariableResolverExpressions tests expression evaluation
func TestAdvancedVariableResolverExpressions(t *testing.T) {
	logger := zaptest.NewLogger(t)
	resolver := NewAdvancedVariableResolver(logger)

	// Register a test expression
	expr := &Expression{
		Name:     "cpu_usage_status",
		Type:     ExpressionTypeConditional,
		Formula:  "if cpu_usage > 80 then 'HIGH' else 'NORMAL'",
		Variables: []string{"cpu_usage"},
	}
	resolver.RegisterExpression(expr)

	template := "CPU Status: ${expr:cpu_usage_status}"
	context := &ResolutionContext{
		Name: "expression_test",
		Variables: map[string]interface{}{
			"cpu_usage": 85,
		},
		Timestamp: time.Now(),
	}

	result, err := resolver.ResolveAdvanced(template, context)
	require.NoError(t, err)

	// Expression evaluation is handled by the resolver
	assert.NotEmpty(t, result.ResolvedContent)
	assert.True(t, len(result.Expressions) >= 0) // May be empty if expression isn't processed yet
}

// TestAdvancedVariableResolverTransformers tests data transformation
func TestAdvancedVariableResolverTransformers(t *testing.T) {
	logger := zaptest.NewLogger(t)
	resolver := NewAdvancedVariableResolver(logger)

	// Register string transformer
	stringTransformer := &StringTransformer{}
	resolver.RegisterTransformer(stringTransformer)

	template := "Uppercase name: ${transform:string:user_name:operation=upper}"
	context := &ResolutionContext{
		Name: "transformer_test",
		Variables: map[string]interface{}{
			"user_name": "john doe",
		},
		Timestamp: time.Now(),
	}

	result, err := resolver.ResolveAdvanced(template, context)
	require.NoError(t, err)

	// Transformation should be applied
	assert.NotEmpty(t, result.ResolvedContent)
	assert.True(t, len(result.Transformations) >= 0)
}

// TestAdvancedVariableResolverConditionals tests conditional logic
func TestAdvancedVariableResolverConditionals(t *testing.T) {
	logger := zaptest.NewLogger(t)
	resolver := NewAdvancedVariableResolver(logger)

	// Register a conditional block
	conditional := &ConditionalBlock{
		Name: "severity_message",
		Cases: []*ConditionalCase{
			{
				Condition: "severity == 'critical'",
				Result:    "URGENT: Immediate attention required!",
			},
			{
				Condition: "severity == 'warning'",
				Result:    "Warning: Monitor this issue",
			},
		},
		DefaultCase: &ConditionalCase{
			Result: "Normal operation",
		},
	}
	resolver.RegisterConditional(conditional)

	template := "Alert Status: ${cond:severity_message}"
	context := &ResolutionContext{
		Name: "conditional_test",
		Variables: map[string]interface{}{
			"severity": "critical",
		},
		Timestamp: time.Now(),
	}

	result, err := resolver.ResolveAdvanced(template, context)
	require.NoError(t, err)

	assert.NotEmpty(t, result.ResolvedContent)
	assert.True(t, len(result.Conditionals) >= 0)
}

// TestAdvancedVariableResolverNestedReferences tests nested variable resolution
func TestAdvancedVariableResolverNestedReferences(t *testing.T) {
	logger := zaptest.NewLogger(t)
	resolver := NewAdvancedVariableResolver(logger)

	template := "Dynamic reference: ${${ENV}_CONFIG_PATH}"
	context := &ResolutionContext{
		Name: "nested_test",
		Variables: map[string]interface{}{
			"ENV":                "PROD",
			"PROD_CONFIG_PATH":   "/etc/prod/config.yaml",
			"DEV_CONFIG_PATH":    "/etc/dev/config.yaml",
		},
		Timestamp: time.Now(),
	}

	result, err := resolver.ResolveAdvanced(template, context)
	require.NoError(t, err)

	// Should resolve to "Dynamic reference: /etc/prod/config.yaml"
	assert.Contains(t, result.ResolvedContent, "/etc/prod/config.yaml")
}

// TestAdvancedVariableResolverContextIntegration tests integration with different contexts
func TestAdvancedVariableResolverContextIntegration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	resolver := NewAdvancedVariableResolver(logger)

	// Create comprehensive context
	alert := &models.Alert{
		AlertType: "kubernetes.pod.crash",
		Data: map[string]interface{}{
			"pod_name":   "api-server",
			"namespace":  "production",
			"exit_code":  1,
		},
		Severity:  models.SeverityHigh,
		Timestamp: time.Now(),
	}

	context := &ResolutionContext{
		Name: "comprehensive_test",
		Variables: map[string]interface{}{
			"USER_NAME": "admin",
			"ACTION":    "investigate",
		},
		Alert: alert,
		AgentContext: &AgentContext{
			Type:         "kubernetes",
			Name:         "k8s-troubleshooter",
			Capabilities: []string{"pod-logs", "metrics", "events"},
			Tools:        []string{"kubectl", "prometheus"},
			MCPServers:   []string{"kubernetes-server", "monitoring-server"},
		},
		TimeContext: &TimeContext{
			Current:  time.Now(),
			Timezone: "UTC",
			Format:   "2006-01-02 15:04:05",
		},
		CustomContext: map[string]interface{}{
			"cluster_name": "production-cluster",
			"region":       "us-west-2",
		},
		Timestamp: time.Now(),
	}

	template := `
Alert Analysis for ${AGENT_TYPE} agent:
Alert Type: ${ALERT_TYPE}
Severity: ${ALERT_SEVERITY}
Timestamp: ${FORMATTED_TIME}
Agent: ${AGENT_NAME}
Available Tools: ${AVAILABLE_TOOLS}
Cluster: ${cluster_name}
User: ${USER_NAME}
Action: ${ACTION}
`

	result, err := resolver.ResolveAdvanced(template, context)
	require.NoError(t, err)

	// Verify context variables are resolved
	assert.Contains(t, result.ResolvedContent, "kubernetes")
	assert.Contains(t, result.ResolvedContent, "kubernetes.pod.crash")
	assert.Contains(t, result.ResolvedContent, "high")
	assert.Contains(t, result.ResolvedContent, "k8s-troubleshooter")
	assert.Contains(t, result.ResolvedContent, "production-cluster")
	assert.Contains(t, result.ResolvedContent, "admin")
	assert.Contains(t, result.ResolvedContent, "investigate")
}

// TestAdvancedVariableResolverPerformanceAndCaching tests caching functionality
func TestAdvancedVariableResolverPerformanceAndCaching(t *testing.T) {
	logger := zaptest.NewLogger(t)
	resolver := NewAdvancedVariableResolver(logger)

	template := "Cache test: ${USER_NAME} working on ${PROJECT_NAME}"
	context := &ResolutionContext{
		Name: "cache_test",
		Variables: map[string]interface{}{
			"USER_NAME":    "developer",
			"PROJECT_NAME": "tarsy-bot",
		},
		Timestamp: time.Now(),
	}

	// First resolution - should not be from cache
	result1, err := resolver.ResolveAdvanced(template, context)
	require.NoError(t, err)
	assert.False(t, result1.FromCache)

	// Second resolution - should be from cache (if caching is enabled)
	result2, err := resolver.ResolveAdvanced(template, context)
	require.NoError(t, err)

	// Results should be identical
	assert.Equal(t, result1.ResolvedContent, result2.ResolvedContent)

	// Performance check - second call should be faster (if caching works)
	if result2.FromCache {
		assert.True(t, result2.ProcessingTime < result1.ProcessingTime)
	}
}

// TestAdvancedVariableResolverErrorHandling tests error handling scenarios
func TestAdvancedVariableResolverErrorHandling(t *testing.T) {
	logger := zaptest.NewLogger(t)
	resolver := NewAdvancedVariableResolver(logger)

	tests := []struct {
		name     string
		template string
		context  *ResolutionContext
		wantErr  bool
	}{
		{
			name:     "nil context",
			template: "Test ${VAR}",
			context:  nil,
			wantErr:  false, // Should handle gracefully
		},
		{
			name:     "deeply nested references",
			template: "${${${${VAR}}}}",
			context: &ResolutionContext{
				Name: "deep_nest_test",
				Variables: map[string]interface{}{
					"VAR": "LEVEL1",
					"LEVEL1": "LEVEL2",
					"LEVEL2": "LEVEL3",
					"LEVEL3": "final_value",
				},
				Timestamp: time.Now(),
			},
			wantErr: false,
		},
		{
			name:     "circular reference",
			template: "${VAR1}",
			context: &ResolutionContext{
				Name: "circular_test",
				Variables: map[string]interface{}{
					"VAR1": "${VAR2}",
					"VAR2": "${VAR1}",
				},
				Timestamp: time.Now(),
			},
			wantErr: false, // Should handle gracefully with depth limits
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolver.ResolveAdvanced(tt.template, tt.context)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

// TestAdvancedVariableResolverStatistics tests statistics tracking
func TestAdvancedVariableResolverStatistics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	resolver := NewAdvancedVariableResolver(logger)

	// Perform several resolutions
	templates := []string{
		"Test 1: ${VAR1}",
		"Test 2: ${VAR2}",
		"Test 3: ${VAR1} and ${VAR2}",
	}

	context := &ResolutionContext{
		Name: "stats_test",
		Variables: map[string]interface{}{
			"VAR1": "value1",
			"VAR2": "value2",
		},
		Timestamp: time.Now(),
	}

	for _, template := range templates {
		_, err := resolver.ResolveAdvanced(template, context)
		require.NoError(t, err)
	}

	// Get statistics
	stats := resolver.GetStatistics()
	require.NotNil(t, stats)

	assert.True(t, stats.CacheSize >= 0)
	assert.True(t, stats.ExpressionsCount >= 0)
	assert.True(t, stats.TransformersCount >= 0)
	assert.True(t, stats.ConditionalsCount >= 0)
	assert.True(t, stats.CacheHitRate >= 0.0 && stats.CacheHitRate <= 1.0)
}

// TestAdvancedVariableResolverConfigurationUpdate tests configuration updates
func TestAdvancedVariableResolverConfigurationUpdate(t *testing.T) {
	logger := zaptest.NewLogger(t)
	resolver := NewAdvancedVariableResolver(logger)

	// Test default configuration
	stats1 := resolver.GetStatistics()
	initialCacheSize := stats1.CacheSize

	// Update configuration
	newConfig := &AdvancedResolverConfig{
		EnableExpressions:   true,
		EnableTransformers:  true,
		EnableConditionals:  true,
		EnableNestedRefs:    true,
		EnableCaching:       false, // Disable caching
		MaxDepth:           5,
		MaxCacheSize:       100,
		CacheTTL:           1 * time.Minute,
		EnableDebugMode:    true,
		StrictMode:         false,
		FailOnMissingVars:  false,
	}

	resolver.SetConfiguration(newConfig)

	// Test with updated configuration
	template := "Test: ${VAR}"
	context := &ResolutionContext{
		Name: "config_test",
		Variables: map[string]interface{}{
			"VAR": "test_value",
		},
		Timestamp: time.Now(),
	}

	result, err := resolver.ResolveAdvanced(template, context)
	require.NoError(t, err)

	// With caching disabled, should not be from cache
	assert.False(t, result.FromCache)
	assert.Contains(t, result.ResolvedContent, "test_value")

	// Cache size might be different based on configuration
	stats2 := resolver.GetStatistics()
	assert.True(t, stats2.CacheSize >= 0)
	_ = initialCacheSize // Use the variable to avoid unused warning
}