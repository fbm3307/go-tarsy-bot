package errors

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ErrorClassifier classifies errors based on patterns and rules
type ErrorClassifier struct {
	rules       []ClassificationRule
	patterns    map[ErrorCategory][]ErrorPattern
	statistics  *ErrorStatistics
	logger      *zap.Logger
	mutex       sync.RWMutex
}

// ClassificationRule defines how to classify an error
type ClassificationRule struct {
	Name        string           `json:"name"`
	Category    ErrorCategory    `json:"category"`
	Severity    ErrorSeverity    `json:"severity"`
	Patterns    []string         `json:"patterns"`       // Regex patterns to match
	Keywords    []string         `json:"keywords"`       // Keywords to search for
	Conditions  []string         `json:"conditions"`     // Additional conditions
	Action      RecoveryAction   `json:"action"`
	Priority    int              `json:"priority"`       // Higher priority rules are checked first
	Enabled     bool             `json:"enabled"`
}

// ErrorPattern represents a pattern for error classification
type ErrorPattern struct {
	Regex      *regexp.Regexp `json:"-"`
	Pattern    string         `json:"pattern"`
	Category   ErrorCategory  `json:"category"`
	Severity   ErrorSeverity  `json:"severity"`
	Action     RecoveryAction `json:"action"`
	Confidence float64        `json:"confidence"` // 0.0-1.0
}

// ErrorStatistics tracks error classification statistics
type ErrorStatistics struct {
	mutex                 sync.RWMutex
	TotalErrors          int64                       `json:"total_errors"`
	ClassifiedErrors     int64                       `json:"classified_errors"`
	UnclassifiedErrors   int64                       `json:"unclassified_errors"`
	CategoryCounts       map[ErrorCategory]int64     `json:"category_counts"`
	SeverityCounts       map[ErrorSeverity]int64     `json:"severity_counts"`
	ActionCounts         map[RecoveryAction]int64    `json:"action_counts"`
	LastClassified       time.Time                   `json:"last_classified"`
	ClassificationRate   float64                     `json:"classification_rate"`
	TopErrors           []ErrorSummary               `json:"top_errors"`
	ErrorTrends         map[string][]ErrorDataPoint  `json:"error_trends"`
}

// ErrorSummary represents a summary of error occurrences
type ErrorSummary struct {
	ErrorCode   string        `json:"error_code"`
	Category    ErrorCategory `json:"category"`
	Count       int64         `json:"count"`
	LastSeen    time.Time     `json:"last_seen"`
	Frequency   float64       `json:"frequency"`   // Errors per hour
}

// ErrorDataPoint represents a point in error trend data
type ErrorDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int64     `json:"count"`
	Category  ErrorCategory `json:"category"`
}

// NewErrorClassifier creates a new error classifier
func NewErrorClassifier(logger *zap.Logger) *ErrorClassifier {
	classifier := &ErrorClassifier{
		rules:      make([]ClassificationRule, 0),
		patterns:   make(map[ErrorCategory][]ErrorPattern),
		statistics: &ErrorStatistics{
			CategoryCounts: make(map[ErrorCategory]int64),
			SeverityCounts: make(map[ErrorSeverity]int64),
			ActionCounts:   make(map[RecoveryAction]int64),
			TopErrors:      make([]ErrorSummary, 0),
			ErrorTrends:    make(map[string][]ErrorDataPoint),
		},
		logger: logger.With(zap.String("component", "error_classifier")),
	}

	// Load default classification rules
	classifier.loadDefaultRules()

	return classifier
}

// loadDefaultRules loads default error classification rules
func (ec *ErrorClassifier) loadDefaultRules() {
	defaultRules := []ClassificationRule{
		{
			Name:     "timeout_errors",
			Category: ErrorCategoryTimeout,
			Severity: ErrorSeverityMedium,
			Patterns: []string{
				`(?i)timeout`,
				`(?i)deadline exceeded`,
				`(?i)context deadline exceeded`,
				`(?i)request timeout`,
			},
			Action:   RecoveryActionRetry,
			Priority: 100,
			Enabled:  true,
		},
		{
			Name:     "network_errors",
			Category: ErrorCategoryNetwork,
			Severity: ErrorSeverityMedium,
			Patterns: []string{
				`(?i)connection refused`,
				`(?i)no route to host`,
				`(?i)network unreachable`,
				`(?i)connection reset`,
				`(?i)connection timeout`,
				`(?i)dns.*fail`,
			},
			Action:   RecoveryActionRetry,
			Priority: 90,
			Enabled:  true,
		},
		{
			Name:     "authentication_errors",
			Category: ErrorCategoryAuth,
			Severity: ErrorSeverityHigh,
			Patterns: []string{
				`(?i)unauthorized`,
				`(?i)authentication.*fail`,
				`(?i)invalid.*token`,
				`(?i)access.*denied`,
				`(?i)forbidden`,
			},
			Keywords: []string{"401", "403", "unauthorized", "forbidden"},
			Action:   RecoveryActionReconfigure,
			Priority: 80,
			Enabled:  true,
		},
		{
			Name:     "validation_errors",
			Category: ErrorCategoryValidation,
			Severity: ErrorSeverityMedium,
			Patterns: []string{
				`(?i)validation.*fail`,
				`(?i)invalid.*input`,
				`(?i)bad.*request`,
				`(?i)malformed`,
				`(?i)invalid.*format`,
			},
			Keywords: []string{"400", "validation", "invalid", "malformed"},
			Action:   RecoveryActionSkip,
			Priority: 70,
			Enabled:  true,
		},
		{
			Name:     "llm_errors",
			Category: ErrorCategoryLLM,
			Severity: ErrorSeverityHigh,
			Patterns: []string{
				`(?i)openai.*error`,
				`(?i)llm.*fail`,
				`(?i)model.*unavailable`,
				`(?i)api.*quota.*exceeded`,
				`(?i)rate.*limit.*exceeded`,
			},
			Keywords: []string{"openai", "llm", "model", "anthropic", "google"},
			Action:   RecoveryActionFallback,
			Priority: 85,
			Enabled:  true,
		},
		{
			Name:     "mcp_errors",
			Category: ErrorCategoryMCP,
			Severity: ErrorSeverityMedium,
			Patterns: []string{
				`(?i)mcp.*error`,
				`(?i)tool.*execution.*fail`,
				`(?i)server.*unavailable`,
				`(?i)mcp.*timeout`,
			},
			Keywords: []string{"mcp", "tool", "server"},
			Action:   RecoveryActionRetry,
			Priority: 75,
			Enabled:  true,
		},
		{
			Name:     "database_errors",
			Category: ErrorCategoryDatabase,
			Severity: ErrorSeverityHigh,
			Patterns: []string{
				`(?i)database.*error`,
				`(?i)sql.*error`,
				`(?i)connection.*pool.*exhausted`,
				`(?i)transaction.*fail`,
				`(?i)deadlock`,
			},
			Keywords: []string{"sql", "database", "postgres", "sqlite"},
			Action:   RecoveryActionRetry,
			Priority: 80,
			Enabled:  true,
		},
		{
			Name:     "security_errors",
			Category: ErrorCategorySecurity,
			Severity: ErrorSeverityCritical,
			Patterns: []string{
				`(?i)security.*violation`,
				`(?i)injection.*attempt`,
				`(?i)xss.*detected`,
				`(?i)csrf.*fail`,
				`(?i)suspicious.*activity`,
			},
			Keywords: []string{"security", "injection", "xss", "csrf", "attack"},
			Action:   RecoveryActionAbort,
			Priority: 100,
			Enabled:  true,
		},
	}

	for _, rule := range defaultRules {
		ec.AddRule(rule)
	}
}

// AddRule adds a new classification rule
func (ec *ErrorClassifier) AddRule(rule ClassificationRule) error {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	// Compile regex patterns
	patterns := make([]ErrorPattern, 0)
	for _, patternStr := range rule.Patterns {
		regex, err := regexp.Compile(patternStr)
		if err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %w", patternStr, err)
		}

		patterns = append(patterns, ErrorPattern{
			Regex:      regex,
			Pattern:    patternStr,
			Category:   rule.Category,
			Severity:   rule.Severity,
			Action:     rule.Action,
			Confidence: 1.0, // Default high confidence for exact pattern matches
		})
	}

	// Add patterns to category map
	if ec.patterns[rule.Category] == nil {
		ec.patterns[rule.Category] = make([]ErrorPattern, 0)
	}
	ec.patterns[rule.Category] = append(ec.patterns[rule.Category], patterns...)

	// Add rule to rules list (sorted by priority)
	inserted := false
	for i, existingRule := range ec.rules {
		if rule.Priority > existingRule.Priority {
			// Insert at this position
			ec.rules = append(ec.rules[:i], append([]ClassificationRule{rule}, ec.rules[i:]...)...)
			inserted = true
			break
		}
	}

	if !inserted {
		ec.rules = append(ec.rules, rule)
	}

	ec.logger.Debug("Added classification rule",
		zap.String("rule_name", rule.Name),
		zap.String("category", string(rule.Category)),
		zap.Int("priority", rule.Priority))

	return nil
}

// ClassifyError classifies an error and returns enriched structured error
func (ec *ErrorClassifier) ClassifyError(err error) *StructuredError {
	if err == nil {
		return nil
	}

	ec.mutex.Lock()
	ec.statistics.TotalErrors++
	ec.statistics.LastClassified = time.Now()
	ec.mutex.Unlock()

	// If it's already a structured error, try to enhance it
	if se, ok := err.(*StructuredError); ok {
		enhanced := ec.enhanceStructuredError(se)
		if enhanced != nil {
			ec.updateStatistics(enhanced)
			return enhanced
		}
	}

	// Classify the error
	classification := ec.classifyErrorMessage(err.Error())

	var structuredErr *StructuredError
	if classification != nil {
		// Create new structured error with classification
		structuredErr = NewStructuredError(
			classification.generateErrorCode(),
			err.Error(),
			classification.Category,
			classification.Severity,
		)
		structuredErr.RecoveryAction = classification.Action
		structuredErr.Cause = err

		ec.mutex.Lock()
		ec.statistics.ClassifiedErrors++
		ec.mutex.Unlock()
	} else {
		// Create generic structured error for unclassified errors
		structuredErr = WrapError(err,
			"UNCLASSIFIED_ERROR",
			"Error could not be automatically classified",
			ErrorCategoryInternal,
			ErrorSeverityMedium,
		)

		ec.mutex.Lock()
		ec.statistics.UnclassifiedErrors++
		ec.mutex.Unlock()
	}

	ec.updateStatistics(structuredErr)
	return structuredErr
}

// classifyErrorMessage classifies an error message and returns the best matching rule
func (ec *ErrorClassifier) classifyErrorMessage(message string) *ClassificationRule {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()

	message = strings.ToLower(message)

	// Check rules in priority order
	for _, rule := range ec.rules {
		if !rule.Enabled {
			continue
		}

		// Check regex patterns
		for _, pattern := range rule.Patterns {
			if matched, _ := regexp.MatchString(pattern, message); matched {
				ec.logger.Debug("Error classified by pattern",
					zap.String("rule", rule.Name),
					zap.String("pattern", pattern),
					zap.String("category", string(rule.Category)))
				return &rule
			}
		}

		// Check keywords
		if len(rule.Keywords) > 0 {
			keywordMatches := 0
			for _, keyword := range rule.Keywords {
				if strings.Contains(message, strings.ToLower(keyword)) {
					keywordMatches++
				}
			}

			// Require at least one keyword match
			if keywordMatches > 0 {
				ec.logger.Debug("Error classified by keywords",
					zap.String("rule", rule.Name),
					zap.Strings("keywords", rule.Keywords),
					zap.Int("matches", keywordMatches))
				return &rule
			}
		}
	}

	return nil
}

// enhanceStructuredError enhances an existing structured error with additional classification
func (ec *ErrorClassifier) enhanceStructuredError(se *StructuredError) *StructuredError {
	// Try to reclassify if category is generic
	if se.Category == ErrorCategoryInternal {
		if classification := ec.classifyErrorMessage(se.Message); classification != nil {
			enhanced := se.Clone()
			enhanced.Category = classification.Category
			enhanced.Severity = classification.Severity
			if enhanced.RecoveryAction == "" {
				enhanced.RecoveryAction = classification.Action
			}
			return enhanced
		}
	}

	return se
}

// generateErrorCode generates a specific error code for a classification
func (rule *ClassificationRule) generateErrorCode() string {
	categoryPrefix := map[ErrorCategory]string{
		ErrorCategoryTimeout:    "TMO",
		ErrorCategoryNetwork:    "NET",
		ErrorCategoryAuth:       "AUTH",
		ErrorCategoryValidation: "VAL",
		ErrorCategoryLLM:        "LLM",
		ErrorCategoryMCP:        "MCP",
		ErrorCategoryDatabase:   "DB",
		ErrorCategorySecurity:   "SEC",
		ErrorCategoryInternal:   "INT",
	}

	prefix, exists := categoryPrefix[rule.Category]
	if !exists {
		prefix = "GEN"
	}

	return fmt.Sprintf("%s_%s", prefix, strings.ToUpper(rule.Name))
}

// updateStatistics updates error classification statistics
func (ec *ErrorClassifier) updateStatistics(se *StructuredError) {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	// Update category counts
	ec.statistics.CategoryCounts[se.Category]++

	// Update severity counts
	ec.statistics.SeverityCounts[se.Severity]++

	// Update action counts
	if se.RecoveryAction != "" {
		ec.statistics.ActionCounts[se.RecoveryAction]++
	}

	// Update classification rate
	if ec.statistics.TotalErrors > 0 {
		ec.statistics.ClassificationRate = float64(ec.statistics.ClassifiedErrors) / float64(ec.statistics.TotalErrors)
	}

	// Update error trends
	now := time.Now()
	trendKey := fmt.Sprintf("%s_%s", se.Category, se.Code)
	if ec.statistics.ErrorTrends[trendKey] == nil {
		ec.statistics.ErrorTrends[trendKey] = make([]ErrorDataPoint, 0)
	}

	// Add data point (or update if within same minute)
	trends := ec.statistics.ErrorTrends[trendKey]
	if len(trends) > 0 {
		lastPoint := &trends[len(trends)-1]
		if now.Sub(lastPoint.Timestamp) < time.Minute {
			lastPoint.Count++
			return
		}
	}

	ec.statistics.ErrorTrends[trendKey] = append(trends, ErrorDataPoint{
		Timestamp: now,
		Count:     1,
		Category:  se.Category,
	})

	// Keep only last 100 data points per trend
	if len(ec.statistics.ErrorTrends[trendKey]) > 100 {
		ec.statistics.ErrorTrends[trendKey] = ec.statistics.ErrorTrends[trendKey][1:]
	}
}

// GetStatistics returns current error classification statistics
func (ec *ErrorClassifier) GetStatistics() *ErrorStatistics {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()

	// Create a deep copy
	stats := &ErrorStatistics{
		TotalErrors:        ec.statistics.TotalErrors,
		ClassifiedErrors:   ec.statistics.ClassifiedErrors,
		UnclassifiedErrors: ec.statistics.UnclassifiedErrors,
		LastClassified:     ec.statistics.LastClassified,
		ClassificationRate: ec.statistics.ClassificationRate,
		CategoryCounts:     make(map[ErrorCategory]int64),
		SeverityCounts:     make(map[ErrorSeverity]int64),
		ActionCounts:       make(map[RecoveryAction]int64),
		TopErrors:          make([]ErrorSummary, len(ec.statistics.TopErrors)),
		ErrorTrends:        make(map[string][]ErrorDataPoint),
	}

	// Copy maps
	for k, v := range ec.statistics.CategoryCounts {
		stats.CategoryCounts[k] = v
	}
	for k, v := range ec.statistics.SeverityCounts {
		stats.SeverityCounts[k] = v
	}
	for k, v := range ec.statistics.ActionCounts {
		stats.ActionCounts[k] = v
	}

	copy(stats.TopErrors, ec.statistics.TopErrors)

	for k, v := range ec.statistics.ErrorTrends {
		stats.ErrorTrends[k] = make([]ErrorDataPoint, len(v))
		copy(stats.ErrorTrends[k], v)
	}

	return stats
}

// GetRules returns all classification rules
func (ec *ErrorClassifier) GetRules() []ClassificationRule {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()

	rules := make([]ClassificationRule, len(ec.rules))
	copy(rules, ec.rules)
	return rules
}

// UpdateRule updates an existing classification rule
func (ec *ErrorClassifier) UpdateRule(ruleName string, updatedRule ClassificationRule) error {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	for i, rule := range ec.rules {
		if rule.Name == ruleName {
			ec.rules[i] = updatedRule
			ec.logger.Info("Classification rule updated",
				zap.String("rule_name", ruleName))
			return nil
		}
	}

	return fmt.Errorf("rule not found: %s", ruleName)
}

// RemoveRule removes a classification rule
func (ec *ErrorClassifier) RemoveRule(ruleName string) error {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	for i, rule := range ec.rules {
		if rule.Name == ruleName {
			ec.rules = append(ec.rules[:i], ec.rules[i+1:]...)
			ec.logger.Info("Classification rule removed",
				zap.String("rule_name", ruleName))
			return nil
		}
	}

	return fmt.Errorf("rule not found: %s", ruleName)
}

// ExportRules exports all rules to JSON
func (ec *ErrorClassifier) ExportRules() ([]byte, error) {
	rules := ec.GetRules()
	return json.MarshalIndent(rules, "", "  ")
}

// ImportRules imports rules from JSON
func (ec *ErrorClassifier) ImportRules(data []byte) error {
	var rules []ClassificationRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	for _, rule := range rules {
		if err := ec.AddRule(rule); err != nil {
			return fmt.Errorf("failed to add rule %s: %w", rule.Name, err)
		}
	}

	ec.logger.Info("Imported classification rules",
		zap.Int("rule_count", len(rules)))

	return nil
}

// Reset resets all statistics
func (ec *ErrorClassifier) Reset() {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	ec.statistics = &ErrorStatistics{
		CategoryCounts: make(map[ErrorCategory]int64),
		SeverityCounts: make(map[ErrorSeverity]int64),
		ActionCounts:   make(map[RecoveryAction]int64),
		TopErrors:      make([]ErrorSummary, 0),
		ErrorTrends:    make(map[string][]ErrorDataPoint),
	}

	ec.logger.Info("Error classification statistics reset")
}