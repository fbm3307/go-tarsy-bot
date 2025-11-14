package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"go.uber.org/zap"
)

// SanitizationConfig holds configuration for input sanitization
type SanitizationConfig struct {
	MaxPayloadSize     int64  `yaml:"max_payload_size"`     // Maximum request payload size
	MaxStringLength    int    `yaml:"max_string_length"`    // Maximum length for string fields
	MaxArraySize       int    `yaml:"max_array_size"`       // Maximum array/slice size
	EnableXSSProtection bool   `yaml:"enable_xss_protection"` // Enable XSS protection
	StrictMode         bool   `yaml:"strict_mode"`          // Enable strict validation
	AllowedPatterns    []string `yaml:"allowed_patterns"`   // Regex patterns for allowed content
	BlockedPatterns    []string `yaml:"blocked_patterns"`   // Regex patterns for blocked content
}

// DefaultSanitizationConfig returns default sanitization configuration
func DefaultSanitizationConfig() *SanitizationConfig {
	return &SanitizationConfig{
		MaxPayloadSize:      10 * 1024 * 1024, // 10MB
		MaxStringLength:     10000,             // 10KB per string
		MaxArraySize:        1000,              // Max 1000 items in arrays
		EnableXSSProtection: true,
		StrictMode:          false,
		AllowedPatterns:     []string{},
		BlockedPatterns: []string{
			`<script[^>]*>.*?</script>`,          // Script tags
			`javascript:`,                        // JavaScript URLs
			`vbscript:`,                         // VBScript URLs
			`data:text/html`,                    // Data URLs with HTML
			`on\w+\s*=`,                         // Event handlers
			`<iframe[^>]*>.*?</iframe>`,         // Iframe tags
			`<object[^>]*>.*?</object>`,         // Object tags
			`<embed[^>]*>.*?</embed>`,           // Embed tags
		},
	}
}

// InputSanitizer provides comprehensive input sanitization
type InputSanitizer struct {
	config         *SanitizationConfig
	blockedRegexes []*regexp.Regexp
	allowedRegexes []*regexp.Regexp
	logger         *zap.Logger
}

// NewInputSanitizer creates a new input sanitizer
func NewInputSanitizer(config *SanitizationConfig, logger *zap.Logger) (*InputSanitizer, error) {
	sanitizer := &InputSanitizer{
		config: config,
		logger: logger,
	}

	// Compile blocked patterns
	for _, pattern := range config.BlockedPatterns {
		regex, err := regexp.Compile(`(?i)` + pattern) // Case-insensitive
		if err != nil {
			return nil, fmt.Errorf("invalid blocked pattern '%s': %w", pattern, err)
		}
		sanitizer.blockedRegexes = append(sanitizer.blockedRegexes, regex)
	}

	// Compile allowed patterns
	for _, pattern := range config.AllowedPatterns {
		regex, err := regexp.Compile(`(?i)` + pattern) // Case-insensitive
		if err != nil {
			return nil, fmt.Errorf("invalid allowed pattern '%s': %w", pattern, err)
		}
		sanitizer.allowedRegexes = append(sanitizer.allowedRegexes, regex)
	}

	logger.Info("Input sanitizer initialized",
		zap.Int("blocked_patterns", len(sanitizer.blockedRegexes)),
		zap.Int("allowed_patterns", len(sanitizer.allowedRegexes)),
		zap.Bool("xss_protection", config.EnableXSSProtection),
		zap.Bool("strict_mode", config.StrictMode))

	return sanitizer, nil
}

// SanitizeString sanitizes a string input
func (s *InputSanitizer) SanitizeString(input string) (string, error) {
	if len(input) > s.config.MaxStringLength {
		return "", fmt.Errorf("string too long: %d > %d", len(input), s.config.MaxStringLength)
	}

	// Check for blocked patterns
	for _, regex := range s.blockedRegexes {
		if regex.MatchString(input) {
			if s.config.StrictMode {
				return "", fmt.Errorf("input contains blocked pattern")
			}
			s.logger.Warn("Blocked pattern detected in input", zap.String("pattern", regex.String()))
		}
	}

	sanitized := input

	// Remove dangerous characters for XSS protection
	if s.config.EnableXSSProtection {
		sanitized = s.removeXSSCharacters(sanitized)
	}

	// HTML escape the content
	sanitized = html.EscapeString(sanitized)

	// Remove null bytes and control characters
	sanitized = s.removeControlCharacters(sanitized)

	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)

	return sanitized, nil
}

// removeXSSCharacters removes potentially dangerous characters
func (s *InputSanitizer) removeXSSCharacters(input string) string {
	// Remove or escape dangerous characters
	dangerous := []string{
		"<", ">", "\"", "'", "&",
		"\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07",
		"\x08", "\x09", "\x0A", "\x0B", "\x0C", "\x0D", "\x0E", "\x0F",
		"\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17",
		"\x18", "\x19", "\x1A", "\x1B", "\x1C", "\x1D", "\x1E", "\x1F",
		"\x7F", "\x80", "\x81", "\x82", "\x83", "\x84", "\x85", "\x86",
		"\x87", "\x88", "\x89", "\x8A", "\x8B", "\x8C", "\x8D", "\x8E",
		"\x8F", "\x90", "\x91", "\x92", "\x93", "\x94", "\x95", "\x96",
		"\x97", "\x98", "\x99", "\x9A", "\x9B", "\x9C", "\x9D", "\x9E", "\x9F",
	}

	result := input
	for _, char := range dangerous {
		result = strings.ReplaceAll(result, char, "")
	}

	return result
}

// removeControlCharacters removes control characters except common whitespace
func (s *InputSanitizer) removeControlCharacters(input string) string {
	var result strings.Builder
	for _, r := range input {
		// Allow normal whitespace (space, tab, newline, carriage return)
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			result.WriteRune(r)
			continue
		}
		// Remove other control characters
		if unicode.IsControl(r) {
			continue
		}
		result.WriteRune(r)
	}
	return result.String()
}

// SanitizeJSON recursively sanitizes JSON data
func (s *InputSanitizer) SanitizeJSON(data interface{}) (interface{}, error) {
	return s.sanitizeJSONRecursive(data, 0)
}

// sanitizeJSONRecursive recursively processes JSON data with depth tracking
func (s *InputSanitizer) sanitizeJSONRecursive(data interface{}, depth int) (interface{}, error) {
	// Prevent infinite recursion
	if depth > 10 {
		return nil, fmt.Errorf("JSON nesting too deep")
	}

	switch v := data.(type) {
	case string:
		return s.SanitizeString(v)

	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			// Sanitize the key
			cleanKey, err := s.SanitizeString(key)
			if err != nil {
				return nil, fmt.Errorf("invalid key '%s': %w", key, err)
			}
			if cleanKey == "" {
				continue // Skip empty keys
			}

			// Recursively sanitize the value
			cleanValue, err := s.sanitizeJSONRecursive(value, depth+1)
			if err != nil {
				return nil, fmt.Errorf("invalid value for key '%s': %w", key, err)
			}

			result[cleanKey] = cleanValue
		}
		return result, nil

	case []interface{}:
		if len(v) > s.config.MaxArraySize {
			return nil, fmt.Errorf("array too large: %d > %d", len(v), s.config.MaxArraySize)
		}

		result := make([]interface{}, 0, len(v))
		for i, item := range v {
			cleanItem, err := s.sanitizeJSONRecursive(item, depth+1)
			if err != nil {
				return nil, fmt.Errorf("invalid array item at index %d: %w", i, err)
			}
			result = append(result, cleanItem)
		}
		return result, nil

	default:
		// Numbers, booleans, and nil are passed through unchanged
		return v, nil
	}
}

// PayloadSizeMiddleware creates middleware to check payload size
func (s *InputSanitizer) PayloadSizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip payload size check for GET, HEAD, OPTIONS
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Check Content-Length header
		contentLength := r.ContentLength
		if contentLength > s.config.MaxPayloadSize {
			s.sendSanitizationError(w, "payload_too_large",
				fmt.Sprintf("Request payload exceeds maximum size of %d bytes", s.config.MaxPayloadSize),
				http.StatusRequestEntityTooLarge)
			return
		}

		// Wrap the request body with a limited reader for additional protection
		r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxPayloadSize)

		next.ServeHTTP(w, r)
	})
}

// SanitizeRequestMiddleware creates middleware to sanitize request data
func (s *InputSanitizer) SanitizeRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip sanitization for GET, HEAD, OPTIONS requests
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Skip sanitization for non-JSON content
		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			next.ServeHTTP(w, r)
			return
		}

		// Create a new request with sanitized body
		sanitizedRequest, err := s.sanitizeRequest(r)
		if err != nil {
			s.logger.Warn("Request sanitization failed", zap.Error(err))
			s.sendSanitizationError(w, "sanitization_failed",
				fmt.Sprintf("Request sanitization failed: %s", err.Error()),
				http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, sanitizedRequest)
	})
}

// sanitizeRequest sanitizes the entire HTTP request
func (s *InputSanitizer) sanitizeRequest(r *http.Request) (*http.Request, error) {
	// Parse JSON body
	var data interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Sanitize the data
	sanitizedData, err := s.SanitizeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("sanitization failed: %w", err)
	}

	// Re-encode as JSON
	sanitizedJSON, err := json.Marshal(sanitizedData)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode JSON: %w", err)
	}

	// Create new request with sanitized body
	newRequest := r.Clone(r.Context())
	newRequest.Body = http.NoBody
	newRequest.GetBody = func() (io.ReadCloser, error) {
		return http.NoBody, nil
	}

	// Store sanitized data in context for handlers to use
	ctx := r.Context()
	ctx = ContextWithSanitizedData(ctx, sanitizedData)
	newRequest = newRequest.WithContext(ctx)

	// Update content length
	newRequest.ContentLength = int64(len(sanitizedJSON))
	newRequest.Header.Set("Content-Length", fmt.Sprintf("%d", len(sanitizedJSON)))

	return newRequest, nil
}

// sendSanitizationError sends a sanitization error response
func (s *InputSanitizer) sendSanitizationError(w http.ResponseWriter, code, message string, statusCode int) {
	errorResp := map[string]interface{}{
		"error": message,
		"code":  code,
		"details": map[string]interface{}{
			"max_payload_size": s.config.MaxPayloadSize,
			"max_string_length": s.config.MaxStringLength,
			"max_array_size": s.config.MaxArraySize,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResp)
}

// Context keys for sanitized data
const SanitizedDataKey ContextKey = "sanitized_data"

// ContextWithSanitizedData stores sanitized data in context
func ContextWithSanitizedData(ctx context.Context, data interface{}) context.Context {
	return context.WithValue(ctx, SanitizedDataKey, data)
}

// GetSanitizedDataFromContext retrieves sanitized data from context
func GetSanitizedDataFromContext(ctx context.Context) (interface{}, bool) {
	data, ok := ctx.Value(SanitizedDataKey).(interface{})
	return data, ok
}