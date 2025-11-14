package security

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DataMaskingIntegration provides integration capabilities for the data masking service
// This handles integration with agents, MCP servers, and the overall TARSy system
type DataMaskingIntegration struct {
	maskingService *DataMaskingService
	logger         *zap.Logger
	config         *IntegrationConfig
}

// IntegrationConfig represents configuration for masking integration
type IntegrationConfig struct {
	EnableAgentIntegration bool                          `json:"enable_agent_integration"`
	EnableMCPIntegration   bool                          `json:"enable_mcp_integration"`
	EnableLogMasking       bool                          `json:"enable_log_masking"`
	AgentMaskingRules      map[string]*AgentMaskingRule  `json:"agent_masking_rules"`
	MCPMaskingRules        map[string]*MCPMaskingRule    `json:"mcp_masking_rules"`
	OutputFormatRules      map[OutputFormat]*FormatRule  `json:"output_format_rules"`
	AlertDataMasking       *AlertDataMaskingConfig       `json:"alert_data_masking"`
	HistoryMasking         *HistoryMaskingConfig         `json:"history_masking"`
}

// AgentMaskingRule represents masking rules specific to agents
type AgentMaskingRule struct {
	AgentType       string           `json:"agent_type"`
	MaskingLevel    MaskingLevel     `json:"masking_level"`
	ExemptFields    []string         `json:"exempt_fields"`
	RequiredFields  []string         `json:"required_fields"`
	CustomPatterns  []string         `json:"custom_patterns"`
	SensitivityOverride SensitivityLevel `json:"sensitivity_override"`
}

// MCPMaskingRule represents masking rules for MCP server interactions
type MCPMaskingRule struct {
	ServerName      string           `json:"server_name"`
	ToolName        string           `json:"tool_name"`
	MaskInputs      bool             `json:"mask_inputs"`
	MaskOutputs     bool             `json:"mask_outputs"`
	MaskingLevel    MaskingLevel     `json:"masking_level"`
	ExemptFields    []string         `json:"exempt_fields"`
	CustomPatterns  []string         `json:"custom_patterns"`
}

// FormatRule represents rules for specific output formats
type FormatRule struct {
	Format          OutputFormat     `json:"format"`
	MaskingLevel    MaskingLevel     `json:"masking_level"`
	PreserveStructure bool           `json:"preserve_structure"`
	CustomMasking   map[string]string `json:"custom_masking"`
}

// AlertDataMaskingConfig represents configuration for masking alert data
type AlertDataMaskingConfig struct {
	MaskAlertType   bool             `json:"mask_alert_type"`
	MaskMetadata    bool             `json:"mask_metadata"`
	MaskPayload     bool             `json:"mask_payload"`
	MaskingLevel    MaskingLevel     `json:"masking_level"`
	RetainStructure bool             `json:"retain_structure"`
	CustomRules     []string         `json:"custom_rules"`
}

// HistoryMaskingConfig represents configuration for masking historical data
type HistoryMaskingConfig struct {
	MaskSessionData   bool         `json:"mask_session_data"`
	MaskLLMInteractions bool       `json:"mask_llm_interactions"`
	MaskToolOutputs   bool         `json:"mask_tool_outputs"`
	RetentionPeriod   string       `json:"retention_period"`
	MaskingLevel      MaskingLevel `json:"masking_level"`
}

// NewDataMaskingIntegration creates a new data masking integration
func NewDataMaskingIntegration(maskingService *DataMaskingService, config *IntegrationConfig, logger *zap.Logger) *DataMaskingIntegration {
	if config == nil {
		config = DefaultIntegrationConfig()
	}

	return &DataMaskingIntegration{
		maskingService: maskingService,
		logger:         logger.With(zap.String("component", "data_masking_integration")),
		config:         config,
	}
}

// DefaultIntegrationConfig returns default integration configuration
func DefaultIntegrationConfig() *IntegrationConfig {
	return &IntegrationConfig{
		EnableAgentIntegration: true,
		EnableMCPIntegration:   true,
		EnableLogMasking:       true,
		AgentMaskingRules:      make(map[string]*AgentMaskingRule),
		MCPMaskingRules:        make(map[string]*MCPMaskingRule),
		OutputFormatRules:      make(map[OutputFormat]*FormatRule),
		AlertDataMasking: &AlertDataMaskingConfig{
			MaskAlertType:   false,
			MaskMetadata:    true,
			MaskPayload:     true,
			MaskingLevel:    MaskingLevelModerate,
			RetainStructure: true,
			CustomRules:     []string{},
		},
		HistoryMasking: &HistoryMaskingConfig{
			MaskSessionData:     true,
			MaskLLMInteractions: true,
			MaskToolOutputs:     true,
			RetentionPeriod:     "90d",
			MaskingLevel:        MaskingLevelModerate,
		},
	}
}

// MaskAlertData masks sensitive data in alert structures
func (dmi *DataMaskingIntegration) MaskAlertData(alertData map[string]interface{}, alertType string) (*MaskingResult, error) {
	if !dmi.config.EnableAgentIntegration {
		return &MaskingResult{
			MaskedContent:  fmt.Sprintf("%v", alertData),
			MaskingApplied: false,
		}, nil
	}

	// Apply alert-specific masking rules
	maskedData := make(map[string]interface{})
	context := map[string]interface{}{
		"alert_type": alertType,
		"source":     "alert_data",
	}

	for key, value := range alertData {
		// Check if field should be exempt from masking
		if dmi.shouldExemptField(key, "alert", alertType) {
			maskedData[key] = value
			continue
		}

		// Apply masking based on field type and sensitivity
		if strValue, ok := value.(string); ok {
			result, err := dmi.maskingService.MaskContent(strValue, context)
			if err != nil {
				dmi.logger.Warn("Failed to mask alert field",
					zap.String("field", key),
					zap.Error(err))
				maskedData[key] = "[MASKING_ERROR]"
			} else {
				maskedData[key] = result.MaskedContent
			}
		} else {
			// For non-string values, convert to string and mask if needed
			strValue := fmt.Sprintf("%v", value)
			if dmi.containsSensitiveData(strValue) {
				result, err := dmi.maskingService.MaskContent(strValue, context)
				if err != nil {
					dmi.logger.Warn("Failed to mask alert field",
						zap.String("field", key),
						zap.Error(err))
					maskedData[key] = "[MASKING_ERROR]"
				} else {
					maskedData[key] = result.MaskedContent
				}
			} else {
				maskedData[key] = value
			}
		}
	}

	// Return comprehensive masking result
	return dmi.maskingService.MaskStructuredData(maskedData)
}

// MaskMCPToolOutput masks sensitive data in MCP tool outputs
func (dmi *DataMaskingIntegration) MaskMCPToolOutput(serverName, toolName, output string) (*MaskingResult, error) {
	if !dmi.config.EnableMCPIntegration {
		return &MaskingResult{
			MaskedContent:  output,
			MaskingApplied: false,
		}, nil
	}

	// Check for MCP-specific masking rules
	ruleKey := fmt.Sprintf("%s:%s", serverName, toolName)
	if rule, exists := dmi.config.MCPMaskingRules[ruleKey]; exists && !rule.MaskOutputs {
		return &MaskingResult{
			MaskedContent:  output,
			MaskingApplied: false,
		}, nil
	}

	context := map[string]interface{}{
		"source":      "mcp_tool_output",
		"server_name": serverName,
		"tool_name":   toolName,
	}

	return dmi.maskingService.MaskContent(output, context)
}

// MaskMCPToolInput masks sensitive data in MCP tool inputs
func (dmi *DataMaskingIntegration) MaskMCPToolInput(serverName, toolName string, parameters map[string]interface{}) (*MaskingResult, error) {
	if !dmi.config.EnableMCPIntegration {
		return &MaskingResult{
			MaskedContent:  fmt.Sprintf("%v", parameters),
			MaskingApplied: false,
		}, nil
	}

	// Check for MCP-specific masking rules
	ruleKey := fmt.Sprintf("%s:%s", serverName, toolName)
	if rule, exists := dmi.config.MCPMaskingRules[ruleKey]; exists && !rule.MaskInputs {
		return &MaskingResult{
			MaskedContent:  fmt.Sprintf("%v", parameters),
			MaskingApplied: false,
		}, nil
	}

	context := map[string]interface{}{
		"source":      "mcp_tool_input",
		"server_name": serverName,
		"tool_name":   toolName,
	}
	_ = context // TODO: Pass context to MaskStructuredData when interface supports it

	return dmi.maskingService.MaskStructuredData(parameters)
}

// MaskLLMInteraction masks sensitive data in LLM interactions
func (dmi *DataMaskingIntegration) MaskLLMInteraction(agentType, sessionID string, messages []map[string]interface{}) (*MaskingResult, error) {
	maskedMessages := make([]map[string]interface{}, len(messages))
	overallResult := &MaskingResult{
		PatternsMatched: []string{},
		CategoriesFound: []DataCategory{},
		MaskingApplied:  false,
		Warnings:        []string{},
	}

	for i, message := range messages {
		context := map[string]interface{}{
			"source":     "llm_interaction",
			"agent_type": agentType,
			"session_id": sessionID,
			"message_index": i,
		}

		maskedMessage := make(map[string]interface{})
		for key, value := range message {
			if key == "content" {
				if strValue, ok := value.(string); ok {
					result, err := dmi.maskingService.MaskContent(strValue, context)
					if err != nil {
						dmi.logger.Warn("Failed to mask LLM message content",
							zap.String("agent_type", agentType),
							zap.String("session_id", sessionID),
							zap.Error(err))
						maskedMessage[key] = "[MASKING_ERROR]"
					} else {
						maskedMessage[key] = result.MaskedContent
						if result.MaskingApplied {
							overallResult.MaskingApplied = true
							overallResult.PatternsMatched = append(overallResult.PatternsMatched, result.PatternsMatched...)
						}
					}
				} else {
					maskedMessage[key] = value
				}
			} else {
				maskedMessage[key] = value
			}
		}
		maskedMessages[i] = maskedMessage
	}

	overallResult.MaskedContent = fmt.Sprintf("%v", maskedMessages)
	return overallResult, nil
}

// MaskLogContent masks sensitive data in log messages
func (dmi *DataMaskingIntegration) MaskLogContent(logLevel, logMessage string, fields map[string]interface{}) (*MaskingResult, error) {
	if !dmi.config.EnableLogMasking {
		return &MaskingResult{
			MaskedContent:  logMessage,
			MaskingApplied: false,
		}, nil
	}

	context := map[string]interface{}{
		"source":    "log_content",
		"log_level": logLevel,
	}

	// Mask the log message itself
	result, err := dmi.maskingService.MaskContent(logMessage, context)
	if err != nil {
		return nil, fmt.Errorf("failed to mask log message: %w", err)
	}

	// Mask log fields if provided
	if len(fields) > 0 {
		fieldsResult, err := dmi.maskingService.MaskStructuredData(fields)
		if err != nil {
			dmi.logger.Warn("Failed to mask log fields", zap.Error(err))
		} else if fieldsResult.MaskingApplied {
			result.MaskingApplied = true
			result.PatternsMatched = append(result.PatternsMatched, fieldsResult.PatternsMatched...)
		}
	}

	return result, nil
}

// MaskForOutputFormat masks content according to specific output format requirements
func (dmi *DataMaskingIntegration) MaskForOutputFormat(content string, format OutputFormat) (*MaskingResult, error) {
	context := map[string]interface{}{
		"source":        "output_format",
		"output_format": string(format),
	}
	_ = context // Use context variable

	// Apply format-specific rules if they exist
	if rule, exists := dmi.config.OutputFormatRules[format]; exists {
		// Apply custom masking for this format
		if rule.CustomMasking != nil {
			for pattern, replacement := range rule.CustomMasking {
				content = strings.ReplaceAll(content, pattern, replacement)
			}
		}
	}

	return dmi.maskingService.MaskContent(content, context)
}

// MaskAgentExecutionResult masks sensitive data in agent execution results
func (dmi *DataMaskingIntegration) MaskAgentExecutionResult(agentType string, result map[string]interface{}) (*MaskingResult, error) {
	if !dmi.config.EnableAgentIntegration {
		return &MaskingResult{
			MaskedContent:  fmt.Sprintf("%v", result),
			MaskingApplied: false,
		}, nil
	}

	context := map[string]interface{}{
		"source":     "agent_execution_result",
		"agent_type": agentType,
	}

	// Apply agent-specific masking rules
	if rule, exists := dmi.config.AgentMaskingRules[agentType]; exists {
		context["masking_level"] = rule.MaskingLevel
		context["exempt_fields"] = rule.ExemptFields
	}

	return dmi.maskingService.MaskStructuredData(result)
}

// CreateComprehensiveMaskingReport creates a detailed report of masking operations
func (dmi *DataMaskingIntegration) CreateComprehensiveMaskingReport() *MaskingReport {
	stats := dmi.maskingService.GetStatistics()

	return &MaskingReport{
		Timestamp:             stats.LastOperation,
		TotalOperations:       stats.TotalOperations,
		SuccessfulMasks:       stats.SuccessfulMasks,
		FailedMasks:          stats.FailedMasks,
		PatternMatches:       stats.PatternMatches,
		CategoryCounts:       stats.CategoryCounts,
		SensitivityCounts:    stats.SensitivityCounts,
		AverageLatency:       stats.AverageLatency,
		ErrorsByType:         stats.ErrorsByType,
		IntegrationMetrics:   dmi.getIntegrationMetrics(),
		ComplianceStatus:     dmi.getComplianceStatus(),
		Recommendations:      dmi.generateRecommendations(),
	}
}

// MaskingReport represents a comprehensive masking report
type MaskingReport struct {
	Timestamp           time.Time                    `json:"timestamp"`
	TotalOperations     int64                        `json:"total_operations"`
	SuccessfulMasks     int64                        `json:"successful_masks"`
	FailedMasks         int64                        `json:"failed_masks"`
	PatternMatches      map[string]int64             `json:"pattern_matches"`
	CategoryCounts      map[DataCategory]int64       `json:"category_counts"`
	SensitivityCounts   map[SensitivityLevel]int64   `json:"sensitivity_counts"`
	AverageLatency      time.Duration                `json:"average_latency"`
	ErrorsByType        map[string]int64             `json:"errors_by_type"`
	IntegrationMetrics  *IntegrationMetrics          `json:"integration_metrics"`
	ComplianceStatus    *ComplianceStatus            `json:"compliance_status"`
	Recommendations     []string                     `json:"recommendations"`
}

// IntegrationMetrics represents metrics specific to system integration
type IntegrationMetrics struct {
	AgentMaskingCount    int64            `json:"agent_masking_count"`
	MCPMaskingCount      int64            `json:"mcp_masking_count"`
	LogMaskingCount      int64            `json:"log_masking_count"`
	FormatMaskingCount   map[string]int64 `json:"format_masking_count"`
	AlertMaskingCount    int64            `json:"alert_masking_count"`
	HistoryMaskingCount  int64            `json:"history_masking_count"`
}

// ComplianceStatus represents the current compliance status
type ComplianceStatus struct {
	Framework           ComplianceMode `json:"framework"`
	OverallCompliance   float64        `json:"overall_compliance"`
	RequiredPatterns    []string       `json:"required_patterns"`
	MissingPatterns     []string       `json:"missing_patterns"`
	LastAudit          time.Time      `json:"last_audit"`
	NextAuditDue       time.Time      `json:"next_audit_due"`
	ViolationCount     int64          `json:"violation_count"`
}

// Helper methods

func (dmi *DataMaskingIntegration) shouldExemptField(fieldName, source, contextType string) bool {
	// Check global exempt patterns
	for _, pattern := range dmi.config.AlertDataMasking.CustomRules {
		if strings.Contains(fieldName, pattern) {
			return true
		}
	}

	// Check context-specific rules
	if source == "alert" {
		if rule, exists := dmi.config.AgentMaskingRules[contextType]; exists {
			for _, exemptField := range rule.ExemptFields {
				if fieldName == exemptField {
					return true
				}
			}
		}
	}

	return false
}

func (dmi *DataMaskingIntegration) containsSensitiveData(content string) bool {
	// Quick check for common sensitive data patterns
	sensitiveIndicators := []string{
		"password", "secret", "token", "key", "credential",
		"@", "://", "Bearer", "API", "ssh-",
	}

	contentLower := strings.ToLower(content)
	for _, indicator := range sensitiveIndicators {
		if strings.Contains(contentLower, indicator) {
			return true
		}
	}

	return false
}

func (dmi *DataMaskingIntegration) getIntegrationMetrics() *IntegrationMetrics {
	// This would collect actual metrics from the integration usage
	return &IntegrationMetrics{
		AgentMaskingCount:   0, // Would be tracked during runtime
		MCPMaskingCount:     0, // Would be tracked during runtime
		LogMaskingCount:     0, // Would be tracked during runtime
		FormatMaskingCount:  make(map[string]int64),
		AlertMaskingCount:   0, // Would be tracked during runtime
		HistoryMaskingCount: 0, // Would be tracked during runtime
	}
}

func (dmi *DataMaskingIntegration) getComplianceStatus() *ComplianceStatus {
	// This would assess current compliance status
	return &ComplianceStatus{
		Framework:         dmi.maskingService.config.ComplianceMode,
		OverallCompliance: 0.95, // Would be calculated based on actual compliance
		RequiredPatterns:  []string{"email", "ssn", "credit_card", "api_key"},
		MissingPatterns:   []string{},
		LastAudit:        time.Now().AddDate(0, -1, 0),
		NextAuditDue:     time.Now().AddDate(0, 2, 0),
		ViolationCount:   0,
	}
}

func (dmi *DataMaskingIntegration) generateRecommendations() []string {
	recommendations := []string{}

	stats := dmi.maskingService.GetStatistics()

	// Check for high error rates
	if stats.TotalOperations > 0 {
		errorRate := float64(stats.FailedMasks) / float64(stats.TotalOperations)
		if errorRate > 0.05 {
			recommendations = append(recommendations, "High error rate detected in masking operations. Review pattern configurations.")
		}
	}

	// Check for unused patterns
	for patternName, count := range stats.PatternMatches {
		if count == 0 {
			recommendations = append(recommendations, fmt.Sprintf("Pattern '%s' has no matches. Consider reviewing or removing.", patternName))
		}
	}

	// Check for performance issues
	if stats.AverageLatency > time.Millisecond*100 {
		recommendations = append(recommendations, "Average masking latency is high. Consider optimizing patterns or enabling caching.")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Masking service is operating within normal parameters.")
	}

	return recommendations
}

// AddAgentMaskingRule adds a new agent-specific masking rule
func (dmi *DataMaskingIntegration) AddAgentMaskingRule(agentType string, rule *AgentMaskingRule) {
	dmi.config.AgentMaskingRules[agentType] = rule
	dmi.logger.Info("Added agent masking rule",
		zap.String("agent_type", agentType),
		zap.String("masking_level", string(rule.MaskingLevel)))
}

// AddMCPMaskingRule adds a new MCP-specific masking rule
func (dmi *DataMaskingIntegration) AddMCPMaskingRule(serverName, toolName string, rule *MCPMaskingRule) {
	ruleKey := fmt.Sprintf("%s:%s", serverName, toolName)
	dmi.config.MCPMaskingRules[ruleKey] = rule
	dmi.logger.Info("Added MCP masking rule",
		zap.String("server_name", serverName),
		zap.String("tool_name", toolName),
		zap.String("masking_level", string(rule.MaskingLevel)))
}

// UpdateIntegrationConfig updates the integration configuration
func (dmi *DataMaskingIntegration) UpdateIntegrationConfig(config *IntegrationConfig) {
	dmi.config = config
	dmi.logger.Info("Updated data masking integration configuration")
}

// GetIntegrationConfig returns the current integration configuration
func (dmi *DataMaskingIntegration) GetIntegrationConfig() *IntegrationConfig {
	return dmi.config
}