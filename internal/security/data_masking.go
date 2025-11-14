package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DataMaskingService provides comprehensive data masking and PII protection
// Equivalent to Python's data_masking_service.py with enhanced capabilities
type DataMaskingService struct {
	config          *MaskingConfig
	patterns        map[string]*MaskingPattern
	logger          *zap.Logger
	mutex           sync.RWMutex
	statistics      *MaskingStatistics
	tokenMap        map[string]string // For reversible masking (where permitted)
	customReplacers map[string]func(string) string
}

// MaskingConfig represents the configuration for data masking
type MaskingConfig struct {
	EnableMasking        bool                  `json:"enable_masking"`
	MaskingLevel         MaskingLevel          `json:"masking_level"`
	RetainLength         bool                  `json:"retain_length"`
	UseTokenization      bool                  `json:"use_tokenization"`
	AllowReversible      bool                  `json:"allow_reversible"`
	PreserveFormatting   bool                  `json:"preserve_formatting"`
	CustomPatterns       []*CustomPattern      `json:"custom_patterns"`
	ExemptPatterns       []string              `json:"exempt_patterns"`
	FieldLevelRules      map[string]*FieldRule `json:"field_level_rules"`
	OutputFormats        []OutputFormat        `json:"output_formats"`
	AuditingEnabled      bool                  `json:"auditing_enabled"`
	ComplianceMode       ComplianceMode        `json:"compliance_mode"`
}

// MaskingLevel represents the intensity of masking
type MaskingLevel string

const (
	MaskingLevelNone     MaskingLevel = "none"
	MaskingLevelBasic    MaskingLevel = "basic"
	MaskingLevelModerate MaskingLevel = "moderate"
	MaskingLevelHigh     MaskingLevel = "high"
	MaskingLevelComplete MaskingLevel = "complete"
)

// ComplianceMode represents compliance framework requirements
type ComplianceMode string

const (
	ComplianceModeGDPR     ComplianceMode = "gdpr"
	ComplianceModeHIPAA    ComplianceMode = "hipaa"
	ComplianceModePCIDSS   ComplianceMode = "pci_dss"
	ComplianceModeSOX      ComplianceMode = "sox"
	ComplianceModeCustom   ComplianceMode = "custom"
)

// OutputFormat represents different output format handling
type OutputFormat string

const (
	OutputFormatJSON OutputFormat = "json"
	OutputFormatXML  OutputFormat = "xml"
	OutputFormatYAML OutputFormat = "yaml"
	OutputFormatText OutputFormat = "text"
	OutputFormatLogs OutputFormat = "logs"
)

// MaskingPattern represents a pattern for data masking
type MaskingPattern struct {
	Name          string              `json:"name"`
	Pattern       *regexp.Regexp      `json:"-"`
	PatternString string              `json:"pattern"`
	MaskingType   MaskingType         `json:"masking_type"`
	Replacement   string              `json:"replacement"`
	Priority      int                 `json:"priority"`
	Enabled       bool                `json:"enabled"`
	Categories    []DataCategory      `json:"categories"`
	Sensitivity   SensitivityLevel    `json:"sensitivity"`
	Validator     func(string) bool   `json:"-"`
	Transformer   func(string) string `json:"-"`
}

// MaskingType represents different types of masking strategies
type MaskingType string

const (
	MaskingTypeRedaction     MaskingType = "redaction"
	MaskingTypeTokenization  MaskingType = "tokenization"
	MaskingTypeEncryption    MaskingType = "encryption"
	MaskingTypeHashing       MaskingType = "hashing"
	MaskingTypePartial       MaskingType = "partial"
	MaskingTypeReplacement   MaskingType = "replacement"
	MaskingTypeFormat        MaskingType = "format_preserving"
	MaskingTypeGenerative    MaskingType = "generative"
)

// DataCategory represents categories of sensitive data
type DataCategory string

const (
	DataCategoryPII           DataCategory = "pii"
	DataCategoryFinancial     DataCategory = "financial"
	DataCategoryHealth        DataCategory = "health"
	DataCategoryCredentials   DataCategory = "credentials"
	DataCategorySecrets       DataCategory = "secrets"
	DataCategoryTechnical     DataCategory = "technical"
	DataCategoryLocation      DataCategory = "location"
	DataCategoryBiometric     DataCategory = "biometric"
	DataCategoryIntellectual  DataCategory = "intellectual_property"
)

// SensitivityLevel represents the sensitivity level of data
type SensitivityLevel string

const (
	SensitivityLevelPublic       SensitivityLevel = "public"
	SensitivityLevelInternal     SensitivityLevel = "internal"
	SensitivityLevelConfidential SensitivityLevel = "confidential"
	SensitivityLevelRestricted   SensitivityLevel = "restricted"
	SensitivityLevelTopSecret    SensitivityLevel = "top_secret"
)

// CustomPattern represents user-defined masking patterns
type CustomPattern struct {
	Name            string           `json:"name"`
	Pattern         string           `json:"pattern"`
	MaskingType     MaskingType      `json:"masking_type"`
	Replacement     string           `json:"replacement"`
	Categories      []DataCategory   `json:"categories"`
	Sensitivity     SensitivityLevel `json:"sensitivity"`
	ContextRequired bool             `json:"context_required"`
	ValidateFunc    string           `json:"validate_func,omitempty"`
}

// FieldRule represents field-specific masking rules
type FieldRule struct {
	FieldName       string           `json:"field_name"`
	MaskingType     MaskingType      `json:"masking_type"`
	MaskingLevel    MaskingLevel     `json:"masking_level"`
	PreserveFormat  bool             `json:"preserve_format"`
	AllowEmpty      bool             `json:"allow_empty"`
	Transformation  string           `json:"transformation"`
	Sensitivity     SensitivityLevel `json:"sensitivity"`
}

// MaskingStatistics tracks masking operations and performance
type MaskingStatistics struct {
	TotalOperations    int64                        `json:"total_operations"`
	SuccessfulMasks    int64                        `json:"successful_masks"`
	FailedMasks        int64                        `json:"failed_masks"`
	PatternMatches     map[string]int64             `json:"pattern_matches"`
	CategoryCounts     map[DataCategory]int64       `json:"category_counts"`
	SensitivityCounts  map[SensitivityLevel]int64   `json:"sensitivity_counts"`
	ProcessingTime     time.Duration                `json:"processing_time"`
	AverageLatency     time.Duration                `json:"average_latency"`
	LastOperation      time.Time                    `json:"last_operation"`
	ErrorsByType       map[string]int64             `json:"errors_by_type"`
}

// MaskingResult represents the result of a masking operation
type MaskingResult struct {
	OriginalContent  string                     `json:"-"` // Never log original content
	MaskedContent    string                     `json:"masked_content"`
	PatternsMatched  []string                   `json:"patterns_matched"`
	CategoriesFound  []DataCategory             `json:"categories_found"`
	SensitivityLevel SensitivityLevel           `json:"sensitivity_level"`
	MaskingApplied   bool                       `json:"masking_applied"`
	ProcessingTime   time.Duration              `json:"processing_time"`
	FieldLevelMasks  map[string]FieldMaskResult `json:"field_level_masks,omitempty"`
	Tokens           map[string]string          `json:"-"` // For reversible masking
	Warnings         []string                   `json:"warnings,omitempty"`
	ComplianceInfo   *ComplianceInfo            `json:"compliance_info,omitempty"`
}

// FieldMaskResult represents masking result for a specific field
type FieldMaskResult struct {
	OriginalValue   string           `json:"-"`
	MaskedValue     string           `json:"masked_value"`
	MaskingType     MaskingType      `json:"masking_type"`
	PatternUsed     string           `json:"pattern_used"`
	Sensitivity     SensitivityLevel `json:"sensitivity"`
	Token           string           `json:"-"`
}

// ComplianceInfo represents compliance-related information
type ComplianceInfo struct {
	Framework        ComplianceMode `json:"framework"`
	RequiredMasking  []string       `json:"required_masking"`
	OptionalMasking  []string       `json:"optional_masking"`
	RetentionPeriod  time.Duration  `json:"retention_period"`
	AuditRequired    bool           `json:"audit_required"`
	ConsentRequired  bool           `json:"consent_required"`
}

// NewDataMaskingService creates a new data masking service
func NewDataMaskingService(config *MaskingConfig, logger *zap.Logger) *DataMaskingService {
	if config == nil {
		config = DefaultMaskingConfig()
	}

	service := &DataMaskingService{
		config:          config,
		patterns:        make(map[string]*MaskingPattern),
		logger:          logger.With(zap.String("component", "data_masking")),
		statistics:      &MaskingStatistics{
			PatternMatches:    make(map[string]int64),
			CategoryCounts:    make(map[DataCategory]int64),
			SensitivityCounts: make(map[SensitivityLevel]int64),
			ErrorsByType:      make(map[string]int64),
		},
		tokenMap:        make(map[string]string),
		customReplacers: make(map[string]func(string) string),
	}

	// Initialize built-in patterns
	service.initializeBuiltinPatterns()

	// Initialize custom patterns from config
	service.initializeCustomPatterns()

	// Initialize custom replacers
	service.initializeCustomReplacers()

	return service
}

// DefaultMaskingConfig returns a default masking configuration
func DefaultMaskingConfig() *MaskingConfig {
	return &MaskingConfig{
		EnableMasking:      true,
		MaskingLevel:       MaskingLevelModerate,
		RetainLength:       true,
		UseTokenization:    true,
		AllowReversible:    false,
		PreserveFormatting: true,
		CustomPatterns:     []*CustomPattern{},
		ExemptPatterns:     []string{},
		FieldLevelRules:    make(map[string]*FieldRule),
		OutputFormats:      []OutputFormat{OutputFormatJSON, OutputFormatText, OutputFormatLogs},
		AuditingEnabled:    true,
		ComplianceMode:     ComplianceModeGDPR,
	}
}

// MaskContent masks sensitive content according to configuration
func (dms *DataMaskingService) MaskContent(content string, context ...map[string]interface{}) (*MaskingResult, error) {
	if !dms.config.EnableMasking {
		return &MaskingResult{
			MaskedContent:   content,
			MaskingApplied:  false,
			ProcessingTime:  0,
		}, nil
	}

	startTime := time.Now()
	dms.mutex.Lock()
	dms.statistics.TotalOperations++
	dms.mutex.Unlock()

	result := &MaskingResult{
		MaskedContent:    content,
		PatternsMatched:  []string{},
		CategoriesFound:  []DataCategory{},
		SensitivityLevel: SensitivityLevelPublic,
		MaskingApplied:   false,
		FieldLevelMasks:  make(map[string]FieldMaskResult),
		Tokens:           make(map[string]string),
		Warnings:         []string{},
	}

	// Apply context-based masking if context is provided
	if len(context) > 0 && context[0] != nil {
		if err := dms.applyContextualMasking(result, context[0]); err != nil {
			dms.logger.Warn("Contextual masking failed", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("Contextual masking failed: %v", err))
		}
	}

	// Apply pattern-based masking
	if err := dms.applyPatternMasking(result); err != nil {
		dms.updateStatistics(false, startTime, err)
		return nil, fmt.Errorf("pattern masking failed: %w", err)
	}

	// Apply field-level masking if structured content
	if err := dms.applyFieldLevelMasking(result, context...); err != nil {
		dms.logger.Warn("Field-level masking failed", zap.Error(err))
		result.Warnings = append(result.Warnings, fmt.Sprintf("Field-level masking failed: %v", err))
	}

	// Apply compliance-specific rules
	if err := dms.applyComplianceRules(result); err != nil {
		dms.logger.Warn("Compliance rules application failed", zap.Error(err))
		result.Warnings = append(result.Warnings, fmt.Sprintf("Compliance rules failed: %v", err))
	}

	result.ProcessingTime = time.Since(startTime)
	dms.updateStatistics(true, startTime, nil)

	dms.logger.Debug("Content masking completed",
		zap.Bool("masking_applied", result.MaskingApplied),
		zap.Int("patterns_matched", len(result.PatternsMatched)),
		zap.Duration("processing_time", result.ProcessingTime))

	return result, nil
}

// MaskStructuredData masks structured data with field-specific rules
func (dms *DataMaskingService) MaskStructuredData(data map[string]interface{}) (*MaskingResult, error) {
	if !dms.config.EnableMasking {
		return &MaskingResult{
			MaskedContent:   fmt.Sprintf("%v", data),
			MaskingApplied:  false,
			ProcessingTime:  0,
		}, nil
	}

	startTime := time.Now()
	maskedData := make(map[string]interface{})
	result := &MaskingResult{
		PatternsMatched:  []string{},
		CategoriesFound:  []DataCategory{},
		SensitivityLevel: SensitivityLevelPublic,
		MaskingApplied:   false,
		FieldLevelMasks:  make(map[string]FieldMaskResult),
		Tokens:           make(map[string]string),
		Warnings:         []string{},
	}

	// Process each field according to configured rules
	for fieldName, value := range data {
		fieldResult, err := dms.maskField(fieldName, value)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Field %s masking failed: %v", fieldName, err))
			maskedData[fieldName] = value
			continue
		}

		maskedData[fieldName] = fieldResult.MaskedValue
		result.FieldLevelMasks[fieldName] = *fieldResult

		if fieldResult.MaskingType != "" {
			result.MaskingApplied = true
			result.PatternsMatched = append(result.PatternsMatched, fieldResult.PatternUsed)
		}

		// Update sensitivity level
		if fieldResult.Sensitivity > result.SensitivityLevel {
			result.SensitivityLevel = fieldResult.Sensitivity
		}
	}

	// Convert masked data back to string representation
	result.MaskedContent = fmt.Sprintf("%v", maskedData)
	result.ProcessingTime = time.Since(startTime)

	dms.updateStatistics(true, startTime, nil)

	return result, nil
}

// initializeBuiltinPatterns initializes built-in masking patterns
func (dms *DataMaskingService) initializeBuiltinPatterns() {
	patterns := []*MaskingPattern{
		// Email addresses
		{
			Name:          "email",
			PatternString: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
			MaskingType:   MaskingTypePartial,
			Replacement:   "***@***.***",
			Priority:      10,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryPII},
			Sensitivity:   SensitivityLevelConfidential,
		},
		// Social Security Numbers (US)
		{
			Name:          "ssn",
			PatternString: `\b\d{3}-?\d{2}-?\d{4}\b`,
			MaskingType:   MaskingTypeRedaction,
			Replacement:   "***-**-****",
			Priority:      15,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryPII, DataCategoryFinancial},
			Sensitivity:   SensitivityLevelRestricted,
		},
		// Credit card numbers
		{
			Name:          "credit_card",
			PatternString: `\b(?:\d{4}[\s-]?){3}\d{4}\b`,
			MaskingType:   MaskingTypePartial,
			Replacement:   "****-****-****-****",
			Priority:      15,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryFinancial},
			Sensitivity:   SensitivityLevelRestricted,
		},
		// Phone numbers
		{
			Name:          "phone",
			PatternString: `\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b`,
			MaskingType:   MaskingTypePartial,
			Replacement:   "(***) ***-****",
			Priority:      8,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryPII},
			Sensitivity:   SensitivityLevelInternal,
		},
		// IP addresses
		{
			Name:          "ip_address",
			PatternString: `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
			MaskingType:   MaskingTypePartial,
			Replacement:   "***.***.***.***",
			Priority:      5,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryTechnical},
			Sensitivity:   SensitivityLevelInternal,
		},
		// API keys and tokens
		{
			Name:          "api_key",
			PatternString: `(?i)\b(?:api_key|token|secret|password|passwd)\s*[:=]\s*[\'""]?([a-zA-Z0-9_-]{16,})[\'""]?`,
			MaskingType:   MaskingTypeRedaction,
			Replacement:   "[REDACTED]",
			Priority:      20,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryCredentials, DataCategorySecrets},
			Sensitivity:   SensitivityLevelTopSecret,
		},
		// AWS Access Keys
		{
			Name:          "aws_access_key",
			PatternString: `\b(AKIA[0-9A-Z]{16})\b`,
			MaskingType:   MaskingTypeRedaction,
			Replacement:   "AKIA[REDACTED]",
			Priority:      20,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryCredentials, DataCategorySecrets},
			Sensitivity:   SensitivityLevelTopSecret,
		},
		// Docker/Container secrets
		{
			Name:          "docker_secret",
			PatternString: `(?i)(docker_password|docker_token|registry_token)\s*[:=]\s*[\'""]?([a-zA-Z0-9_.-]{8,})[\'""]?`,
			MaskingType:   MaskingTypeRedaction,
			Replacement:   "[DOCKER_SECRET_REDACTED]",
			Priority:      18,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryCredentials, DataCategoryTechnical},
			Sensitivity:   SensitivityLevelRestricted,
		},
		// Database connection strings
		{
			Name:          "db_connection",
			PatternString: `(?i)(password|pwd)\s*=\s*['""]?([^;'"\s]+)['""]?`,
			MaskingType:   MaskingTypeRedaction,
			Replacement:   "password=[REDACTED]",
			Priority:      19,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryCredentials, DataCategoryTechnical},
			Sensitivity:   SensitivityLevelRestricted,
		},
		// Kubernetes secrets
		{
			Name:          "k8s_secret",
			PatternString: `(?i)(data|stringData):\s*\n(\s+[^:]+:\s*[a-zA-Z0-9+/=]{8,})`,
			MaskingType:   MaskingTypeRedaction,
			Replacement:   "data:\n  [REDACTED_K8S_SECRET]",
			Priority:      18,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryCredentials, DataCategoryTechnical},
			Sensitivity:   SensitivityLevelRestricted,
		},
		// Generic sensitive data patterns
		{
			Name:          "generic_secret",
			PatternString: `(?i)\b(secret|password|passwd|token|key|credential)\b.*[:=]\s*[\'""]?([a-zA-Z0-9_.-]{6,})[\'""]?`,
			MaskingType:   MaskingTypeRedaction,
			Replacement:   "[REDACTED]",
			Priority:      12,
			Enabled:       true,
			Categories:    []DataCategory{DataCategoryCredentials},
			Sensitivity:   SensitivityLevelConfidential,
		},
	}

	// Compile patterns and add to service
	for _, pattern := range patterns {
		compiledPattern, err := regexp.Compile(pattern.PatternString)
		if err != nil {
			dms.logger.Error("Failed to compile built-in pattern",
				zap.String("pattern_name", pattern.Name),
				zap.Error(err))
			continue
		}

		pattern.Pattern = compiledPattern
		dms.patterns[pattern.Name] = pattern
	}

	dms.logger.Info("Initialized built-in masking patterns",
		zap.Int("pattern_count", len(dms.patterns)))
}

// initializeCustomPatterns initializes custom patterns from configuration
func (dms *DataMaskingService) initializeCustomPatterns() {
	for _, customPattern := range dms.config.CustomPatterns {
		pattern := &MaskingPattern{
			Name:          customPattern.Name,
			PatternString: customPattern.Pattern,
			MaskingType:   customPattern.MaskingType,
			Replacement:   customPattern.Replacement,
			Priority:      25, // Custom patterns get high priority
			Enabled:       true,
			Categories:    customPattern.Categories,
			Sensitivity:   customPattern.Sensitivity,
		}

		compiledPattern, err := regexp.Compile(customPattern.Pattern)
		if err != nil {
			dms.logger.Error("Failed to compile custom pattern",
				zap.String("pattern_name", customPattern.Name),
				zap.Error(err))
			continue
		}

		pattern.Pattern = compiledPattern
		dms.patterns[pattern.Name] = pattern
	}

	dms.logger.Info("Initialized custom masking patterns",
		zap.Int("custom_pattern_count", len(dms.config.CustomPatterns)))
}

// initializeCustomReplacers initializes custom replacement functions
func (dms *DataMaskingService) initializeCustomReplacers() {
	// Format-preserving replacers
	dms.customReplacers["preserve_length"] = func(input string) string {
		return strings.Repeat("*", len(input))
	}

	dms.customReplacers["preserve_structure"] = func(input string) string {
		result := ""
		for _, char := range input {
			if char >= 'A' && char <= 'Z' {
				result += "X"
			} else if char >= 'a' && char <= 'z' {
				result += "x"
			} else if char >= '0' && char <= '9' {
				result += "0"
			} else {
				result += string(char)
			}
		}
		return result
	}

	dms.customReplacers["hash_sha256"] = func(input string) string {
		hash := sha256.Sum256([]byte(input))
		return "[HASH:" + hex.EncodeToString(hash[:])[:8] + "]"
	}

	dms.customReplacers["tokenize"] = func(input string) string {
		if !dms.config.UseTokenization {
			return "[REDACTED]"
		}
		return dms.generateToken(input)
	}
}

// applyPatternMasking applies pattern-based masking to content
func (dms *DataMaskingService) applyPatternMasking(result *MaskingResult) error {
	content := result.MaskedContent
	maxSensitivity := SensitivityLevelPublic

	// Apply patterns in priority order
	for _, pattern := range dms.getSortedPatterns() {
		if !pattern.Enabled {
			continue
		}

		matches := pattern.Pattern.FindAllStringSubmatch(content, -1)
		if len(matches) > 0 {
			result.PatternsMatched = append(result.PatternsMatched, pattern.Name)
			result.MaskingApplied = true

			// Update categories
			for _, category := range pattern.Categories {
				if !contains(result.CategoriesFound, category) {
					result.CategoriesFound = append(result.CategoriesFound, category)
				}
			}

			// Update sensitivity level
			if pattern.Sensitivity > maxSensitivity {
				maxSensitivity = pattern.Sensitivity
			}

			// Apply masking based on type and level
			maskedContent, err := dms.applyMaskingTransformation(content, pattern)
			if err != nil {
				return fmt.Errorf("failed to apply pattern %s: %w", pattern.Name, err)
			}

			content = maskedContent

			// Update statistics
			dms.mutex.Lock()
			dms.statistics.PatternMatches[pattern.Name]++
			for _, category := range pattern.Categories {
				dms.statistics.CategoryCounts[category]++
			}
			dms.statistics.SensitivityCounts[pattern.Sensitivity]++
			dms.mutex.Unlock()
		}
	}

	result.MaskedContent = content
	result.SensitivityLevel = maxSensitivity

	return nil
}

// applyMaskingTransformation applies the appropriate masking transformation
func (dms *DataMaskingService) applyMaskingTransformation(content string, pattern *MaskingPattern) (string, error) {
	switch pattern.MaskingType {
	case MaskingTypeRedaction:
		return pattern.Pattern.ReplaceAllString(content, pattern.Replacement), nil

	case MaskingTypePartial:
		return dms.applyPartialMasking(content, pattern)

	case MaskingTypeTokenization:
		return dms.applyTokenization(content, pattern)

	case MaskingTypeHashing:
		return dms.applyHashing(content, pattern)

	case MaskingTypeFormat:
		return dms.applyFormatPreservingMasking(content, pattern)

	case MaskingTypeGenerative:
		return dms.applyGenerativeMasking(content, pattern)

	default:
		return pattern.Pattern.ReplaceAllString(content, pattern.Replacement), nil
	}
}

// applyPartialMasking applies partial masking that preserves some structure
func (dms *DataMaskingService) applyPartialMasking(content string, pattern *MaskingPattern) (string, error) {
	return pattern.Pattern.ReplaceAllStringFunc(content, func(match string) string {
		if len(match) <= 4 {
			return strings.Repeat("*", len(match))
		}

		// Preserve first and last characters for readability
		if dms.config.PreserveFormatting {
			masked := string(match[0]) + strings.Repeat("*", len(match)-2) + string(match[len(match)-1])
			return masked
		}

		// Preserve length
		if dms.config.RetainLength {
			return strings.Repeat("*", len(match))
		}

		return pattern.Replacement
	}), nil
}

// applyTokenization applies tokenization-based masking
func (dms *DataMaskingService) applyTokenization(content string, pattern *MaskingPattern) (string, error) {
	if !dms.config.UseTokenization {
		return pattern.Pattern.ReplaceAllString(content, pattern.Replacement), nil
	}

	return pattern.Pattern.ReplaceAllStringFunc(content, func(match string) string {
		return dms.generateToken(match)
	}), nil
}

// applyHashing applies hash-based masking
func (dms *DataMaskingService) applyHashing(content string, pattern *MaskingPattern) (string, error) {
	return pattern.Pattern.ReplaceAllStringFunc(content, func(match string) string {
		hash := sha256.Sum256([]byte(match))
		return "[HASH:" + hex.EncodeToString(hash[:])[:8] + "]"
	}), nil
}

// applyFormatPreservingMasking applies format-preserving masking
func (dms *DataMaskingService) applyFormatPreservingMasking(content string, pattern *MaskingPattern) (string, error) {
	return pattern.Pattern.ReplaceAllStringFunc(content, func(match string) string {
		if replacer, exists := dms.customReplacers["preserve_structure"]; exists {
			return replacer(match)
		}
		return strings.Repeat("*", len(match))
	}), nil
}

// applyGenerativeMasking applies generative masking (creates realistic fake data)
func (dms *DataMaskingService) applyGenerativeMasking(content string, pattern *MaskingPattern) (string, error) {
	return pattern.Pattern.ReplaceAllStringFunc(content, func(match string) string {
		// Generate realistic fake data based on pattern
		switch pattern.Name {
		case "email":
			return dms.generateFakeEmail()
		case "phone":
			return dms.generateFakePhone()
		case "ip_address":
			return dms.generateFakeIP()
		default:
			return pattern.Replacement
		}
	}), nil
}

// generateToken generates a unique token for reversible masking
func (dms *DataMaskingService) generateToken(original string) string {
	if !dms.config.AllowReversible {
		return "[TOKEN]"
	}

	// Check if we already have a token for this value
	dms.mutex.RLock()
	if token, exists := dms.tokenMap[original]; exists {
		dms.mutex.RUnlock()
		return token
	}
	dms.mutex.RUnlock()

	// Generate new token
	tokenBytes := make([]byte, 8)
	rand.Read(tokenBytes)
	token := "TKN_" + hex.EncodeToString(tokenBytes)

	dms.mutex.Lock()
	dms.tokenMap[original] = token
	dms.mutex.Unlock()

	return token
}

// Helper functions for generating fake data
func (dms *DataMaskingService) generateFakeEmail() string {
	domains := []string{"example.com", "test.org", "demo.net"}
	users := []string{"user", "test", "demo", "sample"}

	userIdx := time.Now().UnixNano() % int64(len(users))
	domainIdx := time.Now().UnixNano() % int64(len(domains))

	return fmt.Sprintf("%s%d@%s", users[userIdx], time.Now().Unix()%1000, domains[domainIdx])
}

func (dms *DataMaskingService) generateFakePhone() string {
	// Generate a fake US phone number
	area := 200 + (time.Now().UnixNano() % 700)
	exchange := 200 + (time.Now().UnixNano() % 700)
	number := 1000 + (time.Now().UnixNano() % 9000)

	return fmt.Sprintf("(%03d) %03d-%04d", area, exchange, number)
}

func (dms *DataMaskingService) generateFakeIP() string {
	// Generate a fake private IP address
	return fmt.Sprintf("192.168.%d.%d",
		time.Now().UnixNano()%254+1,
		time.Now().UnixNano()%254+1)
}

// getSortedPatterns returns patterns sorted by priority
func (dms *DataMaskingService) getSortedPatterns() []*MaskingPattern {
	patterns := make([]*MaskingPattern, 0, len(dms.patterns))
	for _, pattern := range dms.patterns {
		patterns = append(patterns, pattern)
	}

	// Sort by priority (higher priority first)
	for i := 0; i < len(patterns); i++ {
		for j := i + 1; j < len(patterns); j++ {
			if patterns[i].Priority < patterns[j].Priority {
				patterns[i], patterns[j] = patterns[j], patterns[i]
			}
		}
	}

	return patterns
}

// Helper functions

func contains(slice []DataCategory, item DataCategory) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Additional methods would be implemented here for:
// - applyContextualMasking
// - applyFieldLevelMasking
// - applyComplianceRules
// - maskField
// - updateStatistics
// - GetStatistics
// - AddCustomPattern
// - RemovePattern
// - UpdateConfig
// - ClearTokens
// - etc.

// Placeholder implementations for the helper methods used above
func (dms *DataMaskingService) applyContextualMasking(result *MaskingResult, context map[string]interface{}) error {
	// Implementation for contextual masking based on provided context
	return nil
}

func (dms *DataMaskingService) applyFieldLevelMasking(result *MaskingResult, context ...map[string]interface{}) error {
	// Implementation for field-level masking rules
	return nil
}

func (dms *DataMaskingService) applyComplianceRules(result *MaskingResult) error {
	// Implementation for compliance-specific masking rules
	return nil
}

func (dms *DataMaskingService) maskField(fieldName string, value interface{}) (*FieldMaskResult, error) {
	// Implementation for individual field masking
	return &FieldMaskResult{
		MaskedValue: fmt.Sprintf("%v", value),
		MaskingType: MaskingTypeRedaction,
		PatternUsed: "default",
		Sensitivity: SensitivityLevelPublic,
	}, nil
}

func (dms *DataMaskingService) updateStatistics(success bool, startTime time.Time, err error) {
	dms.mutex.Lock()
	defer dms.mutex.Unlock()

	if success {
		dms.statistics.SuccessfulMasks++
	} else {
		dms.statistics.FailedMasks++
		if err != nil {
			dms.statistics.ErrorsByType[err.Error()]++
		}
	}

	duration := time.Since(startTime)
	dms.statistics.ProcessingTime += duration

	if dms.statistics.TotalOperations > 0 {
		dms.statistics.AverageLatency = dms.statistics.ProcessingTime / time.Duration(dms.statistics.TotalOperations)
	}

	dms.statistics.LastOperation = time.Now()
}

// GetStatistics returns current masking statistics
func (dms *DataMaskingService) GetStatistics() *MaskingStatistics {
	dms.mutex.RLock()
	defer dms.mutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *dms.statistics
	return &stats
}