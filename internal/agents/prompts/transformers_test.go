package prompts

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStringTransformer tests all string transformation operations
func TestStringTransformer(t *testing.T) {
	transformer := &StringTransformer{}

	tests := []struct {
		name      string
		input     interface{}
		params    map[string]interface{}
		expected  interface{}
		wantError bool
	}{
		// Upper case transformation
		{
			name:     "upper case",
			input:    "hello world",
			params:   map[string]interface{}{"operation": "upper"},
			expected: "HELLO WORLD",
		},
		// Lower case transformation
		{
			name:     "lower case",
			input:    "HELLO WORLD",
			params:   map[string]interface{}{"operation": "lower"},
			expected: "hello world",
		},
		// Title case transformation
		{
			name:     "title case",
			input:    "hello world",
			params:   map[string]interface{}{"operation": "title"},
			expected: "Hello World",
		},
		// Trim transformation
		{
			name:     "trim default",
			input:    "  hello world  \n\t",
			params:   map[string]interface{}{"operation": "trim"},
			expected: "hello world",
		},
		// Trim with custom cutset
		{
			name:     "trim custom cutset",
			input:    "***hello world***",
			params:   map[string]interface{}{"operation": "trim", "cutset": "*"},
			expected: "hello world",
		},
		// Trim space
		{
			name:     "trim space",
			input:    "  hello world  \n\t",
			params:   map[string]interface{}{"operation": "trim_space"},
			expected: "hello world",
		},
		// Reverse string
		{
			name:     "reverse",
			input:    "hello",
			params:   map[string]interface{}{"operation": "reverse"},
			expected: "olleh",
		},
		// String length
		{
			name:     "length",
			input:    "hello world",
			params:   map[string]interface{}{"operation": "length"},
			expected: 11,
		},
		// Substring
		{
			name:     "substring",
			input:    "hello world",
			params:   map[string]interface{}{"operation": "substring", "start": 0, "end": 5},
			expected: "hello",
		},
		// Substring with defaults
		{
			name:     "substring with defaults",
			input:    "hello world",
			params:   map[string]interface{}{"operation": "substring", "start": 6},
			expected: "world",
		},
		// Replace
		{
			name:     "replace",
			input:    "hello world world",
			params:   map[string]interface{}{"operation": "replace", "old": "world", "new": "universe"},
			expected: "hello universe universe",
		},
		// Replace with count
		{
			name:     "replace with count",
			input:    "hello world world",
			params:   map[string]interface{}{"operation": "replace", "old": "world", "new": "universe", "count": 1},
			expected: "hello universe world",
		},
		// Split
		{
			name:     "split",
			input:    "apple,banana,cherry",
			params:   map[string]interface{}{"operation": "split", "separator": ","},
			expected: []string{"apple", "banana", "cherry"},
		},
		// Join
		{
			name:     "join",
			input:    []interface{}{"apple", "banana", "cherry"},
			params:   map[string]interface{}{"operation": "join", "separator": ", "},
			expected: "apple, banana, cherry",
		},
		// Error cases
		{
			name:      "missing operation",
			input:     "test",
			params:    map[string]interface{}{},
			wantError: true,
		},
		{
			name:      "invalid operation",
			input:     "test",
			params:    map[string]interface{}{"operation": "invalid"},
			wantError: true,
		},
		{
			name:      "replace missing parameters",
			input:     "test",
			params:    map[string]interface{}{"operation": "replace", "old": "t"},
			wantError: true,
		},
		{
			name:      "split missing separator",
			input:     "test",
			params:    map[string]interface{}{"operation": "split"},
			wantError: true,
		},
		{
			name:      "join with non-array input",
			input:     "test",
			params:    map[string]interface{}{"operation": "join"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.Transform(tt.input, tt.params)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestNumberTransformer tests all number transformation operations
func TestNumberTransformer(t *testing.T) {
	transformer := &NumberTransformer{}

	tests := []struct {
		name      string
		input     interface{}
		params    map[string]interface{}
		expected  interface{}
		wantError bool
	}{
		// Round with default precision
		{
			name:     "round default precision",
			input:    3.14159,
			params:   map[string]interface{}{"operation": "round"},
			expected: "3",
		},
		// Round with custom precision
		{
			name:     "round custom precision",
			input:    3.14159,
			params:   map[string]interface{}{"operation": "round", "precision": 2},
			expected: "3.14",
		},
		// Absolute value
		{
			name:     "absolute value positive",
			input:    -42.5,
			params:   map[string]interface{}{"operation": "abs"},
			expected: 42.5,
		},
		{
			name:     "absolute value negative",
			input:    42.5,
			params:   map[string]interface{}{"operation": "abs"},
			expected: 42.5,
		},
		// Format
		{
			name:     "format default",
			input:    3.14159,
			params:   map[string]interface{}{"operation": "format"},
			expected: "3.14",
		},
		{
			name:     "format custom",
			input:    3.14159,
			params:   map[string]interface{}{"operation": "format", "format": "%.4f"},
			expected: "3.1416",
		},
		// Add
		{
			name:     "add",
			input:    10,
			params:   map[string]interface{}{"operation": "add", "value": 5},
			expected: 15.0,
		},
		// Subtract
		{
			name:     "subtract",
			input:    10,
			params:   map[string]interface{}{"operation": "subtract", "value": 3},
			expected: 7.0,
		},
		// Multiply
		{
			name:     "multiply",
			input:    10,
			params:   map[string]interface{}{"operation": "multiply", "value": 2.5},
			expected: 25.0,
		},
		// Divide
		{
			name:     "divide",
			input:    10,
			params:   map[string]interface{}{"operation": "divide", "value": 2},
			expected: 5.0,
		},
		// String input conversion
		{
			name:     "string input",
			input:    "42.5",
			params:   map[string]interface{}{"operation": "abs"},
			expected: 42.5,
		},
		// Error cases
		{
			name:      "invalid string conversion",
			input:     "not a number",
			params:    map[string]interface{}{"operation": "abs"},
			wantError: true,
		},
		{
			name:      "division by zero",
			input:     10,
			params:    map[string]interface{}{"operation": "divide", "value": 0},
			wantError: true,
		},
		{
			name:      "missing operation",
			input:     10,
			params:    map[string]interface{}{},
			wantError: true,
		},
		{
			name:      "invalid operation",
			input:     10,
			params:    map[string]interface{}{"operation": "invalid"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.Transform(tt.input, tt.params)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestDateTimeTransformer tests all datetime transformation operations
func TestDateTimeTransformer(t *testing.T) {
	transformer := &DateTimeTransformer{}

	// Test time for consistent results
	testTime := time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC)

	tests := []struct {
		name      string
		input     interface{}
		params    map[string]interface{}
		wantError bool
		validate  func(t *testing.T, result interface{})
	}{
		// Now operation
		{
			name:   "now",
			input:  nil,
			params: map[string]interface{}{"operation": "now"},
			validate: func(t *testing.T, result interface{}) {
				timeResult, ok := result.(time.Time)
				assert.True(t, ok)
				assert.True(t, time.Since(timeResult) < time.Second)
			},
		},
		// Format operation
		{
			name:   "format default",
			input:  testTime,
			params: map[string]interface{}{"operation": "format"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, testTime.Format(time.RFC3339), result)
			},
		},
		{
			name:   "format custom",
			input:  testTime,
			params: map[string]interface{}{"operation": "format", "format": "2006-01-02"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, "2023-12-25", result)
			},
		},
		// Add duration
		{
			name:   "add duration",
			input:  testTime,
			params: map[string]interface{}{"operation": "add", "duration": "1h30m"},
			validate: func(t *testing.T, result interface{}) {
				timeResult, ok := result.(time.Time)
				assert.True(t, ok)
				expected := testTime.Add(time.Hour + 30*time.Minute)
				assert.Equal(t, expected, timeResult)
			},
		},
		// Subtract duration
		{
			name:   "subtract duration",
			input:  testTime,
			params: map[string]interface{}{"operation": "subtract", "duration": "2h"},
			validate: func(t *testing.T, result interface{}) {
				timeResult, ok := result.(time.Time)
				assert.True(t, ok)
				expected := testTime.Add(-2 * time.Hour)
				assert.Equal(t, expected, timeResult)
			},
		},
		// Unix timestamp
		{
			name:   "unix timestamp",
			input:  testTime,
			params: map[string]interface{}{"operation": "unix"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, testTime.Unix(), result)
			},
		},
		// Year extraction
		{
			name:   "year",
			input:  testTime,
			params: map[string]interface{}{"operation": "year"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, 2023, result)
			},
		},
		// Month extraction
		{
			name:   "month",
			input:  testTime,
			params: map[string]interface{}{"operation": "month"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, 12, result)
			},
		},
		// Day extraction
		{
			name:   "day",
			input:  testTime,
			params: map[string]interface{}{"operation": "day"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, 25, result)
			},
		},
		// String input parsing
		{
			name:   "parse RFC3339 string",
			input:  testTime.Format(time.RFC3339),
			params: map[string]interface{}{"operation": "year"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, 2023, result)
			},
		},
		// Unix timestamp input
		{
			name:   "unix input",
			input:  testTime.Unix(),
			params: map[string]interface{}{"operation": "year"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, 2023, result)
			},
		},
		// Error cases
		{
			name:      "missing operation",
			input:     testTime,
			params:    map[string]interface{}{},
			wantError: true,
		},
		{
			name:      "invalid operation",
			input:     testTime,
			params:    map[string]interface{}{"operation": "invalid"},
			wantError: true,
		},
		{
			name:      "invalid duration",
			input:     testTime,
			params:    map[string]interface{}{"operation": "add", "duration": "invalid"},
			wantError: true,
		},
		{
			name:      "invalid time string",
			input:     "not a time",
			params:    map[string]interface{}{"operation": "year"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.Transform(tt.input, tt.params)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

// TestJSONTransformer tests all JSON transformation operations
func TestJSONTransformer(t *testing.T) {
	transformer := &JSONTransformer{}

	testObject := map[string]interface{}{
		"name":  "John Doe",
		"age":   30,
		"email": "john@example.com",
		"address": map[string]interface{}{
			"street": "123 Main St",
			"city":   "Anytown",
		},
	}

	tests := []struct {
		name      string
		input     interface{}
		params    map[string]interface{}
		wantError bool
		validate  func(t *testing.T, result interface{})
	}{
		// Parse JSON string
		{
			name:   "parse json string",
			input:  `{"name":"John","age":30}`,
			params: map[string]interface{}{"operation": "parse"},
			validate: func(t *testing.T, result interface{}) {
				parsed, ok := result.(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, "John", parsed["name"])
				assert.Equal(t, float64(30), parsed["age"]) // JSON numbers are float64
			},
		},
		// Stringify object
		{
			name:   "stringify object",
			input:  testObject,
			params: map[string]interface{}{"operation": "stringify"},
			validate: func(t *testing.T, result interface{}) {
				jsonStr, ok := result.(string)
				assert.True(t, ok)
				assert.Contains(t, jsonStr, "John Doe")
				assert.Contains(t, jsonStr, "30")
			},
		},
		// Pretty print
		{
			name:   "pretty print",
			input:  testObject,
			params: map[string]interface{}{"operation": "pretty"},
			validate: func(t *testing.T, result interface{}) {
				jsonStr, ok := result.(string)
				assert.True(t, ok)
				assert.Contains(t, jsonStr, "John Doe")
				assert.Contains(t, jsonStr, "\n") // Should contain newlines for formatting
			},
		},
		// Extract path
		{
			name:   "extract simple path",
			input:  testObject,
			params: map[string]interface{}{"operation": "extract", "path": "name"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, "John Doe", result)
			},
		},
		{
			name:   "extract nested path",
			input:  testObject,
			params: map[string]interface{}{"operation": "extract", "path": "address.city"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, "Anytown", result)
			},
		},
		// Minify
		{
			name:   "minify",
			input:  testObject,
			params: map[string]interface{}{"operation": "minify"},
			validate: func(t *testing.T, result interface{}) {
				jsonStr, ok := result.(string)
				assert.True(t, ok)
				assert.Contains(t, jsonStr, "John Doe")
				assert.NotContains(t, jsonStr, "\n") // Should not contain newlines
			},
		},
		// Error cases
		{
			name:      "parse invalid json",
			input:     `{"invalid":json}`,
			params:    map[string]interface{}{"operation": "parse"},
			wantError: true,
		},
		{
			name:      "extract missing path",
			input:     testObject,
			params:    map[string]interface{}{"operation": "extract", "path": "nonexistent"},
			wantError: true,
		},
		{
			name:      "extract without path parameter",
			input:     testObject,
			params:    map[string]interface{}{"operation": "extract"},
			wantError: true,
		},
		{
			name:      "missing operation",
			input:     testObject,
			params:    map[string]interface{}{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.Transform(tt.input, tt.params)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

// TestRegexTransformer tests all regex transformation operations
func TestRegexTransformer(t *testing.T) {
	transformer := &RegexTransformer{}

	tests := []struct {
		name      string
		input     interface{}
		params    map[string]interface{}
		wantError bool
		validate  func(t *testing.T, result interface{})
	}{
		// Match operation
		{
			name:   "match found",
			input:  "hello world 123",
			params: map[string]interface{}{"operation": "match", "pattern": "\\d+"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, true, result)
			},
		},
		{
			name:   "match not found",
			input:  "hello world",
			params: map[string]interface{}{"operation": "match", "pattern": "\\d+"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, false, result)
			},
		},
		// Replace operation
		{
			name:   "replace",
			input:  "hello world 123",
			params: map[string]interface{}{"operation": "replace", "pattern": "\\d+", "replacement": "XXX"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, "hello world XXX", result)
			},
		},
		// Extract operation
		{
			name:   "extract with capture group",
			input:  "email: john@example.com",
			params: map[string]interface{}{"operation": "extract", "pattern": "email: ([^@]+)@([^.]+)\\.(.+)"},
			validate: func(t *testing.T, result interface{}) {
				captures, ok := result.([]string)
				assert.True(t, ok)
				assert.Equal(t, []string{"john", "example", "com"}, captures)
			},
		},
		{
			name:   "extract no capture groups",
			input:  "hello world 123",
			params: map[string]interface{}{"operation": "extract", "pattern": "\\d+"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, "123", result)
			},
		},
		{
			name:   "extract no match",
			input:  "hello world",
			params: map[string]interface{}{"operation": "extract", "pattern": "\\d+"},
			validate: func(t *testing.T, result interface{}) {
				assert.Nil(t, result)
			},
		},
		// Split operation
		{
			name:   "split",
			input:  "apple,banana,cherry",
			params: map[string]interface{}{"operation": "split", "pattern": ","},
			validate: func(t *testing.T, result interface{}) {
				parts, ok := result.([]string)
				assert.True(t, ok)
				assert.Equal(t, []string{"apple", "banana", "cherry"}, parts)
			},
		},
		// Find all operation
		{
			name:   "find all",
			input:  "The numbers are 123, 456, and 789",
			params: map[string]interface{}{"operation": "find_all", "pattern": "\\d+"},
			validate: func(t *testing.T, result interface{}) {
				matches, ok := result.([]string)
				assert.True(t, ok)
				assert.Equal(t, []string{"123", "456", "789"}, matches)
			},
		},
		// Error cases
		{
			name:      "invalid regex pattern",
			input:     "test",
			params:    map[string]interface{}{"operation": "match", "pattern": "["},
			wantError: true,
		},
		{
			name:      "missing pattern",
			input:     "test",
			params:    map[string]interface{}{"operation": "match"},
			wantError: true,
		},
		{
			name:      "missing replacement for replace",
			input:     "test",
			params:    map[string]interface{}{"operation": "replace", "pattern": "t"},
			wantError: true,
		},
		{
			name:      "invalid operation",
			input:     "test",
			params:    map[string]interface{}{"operation": "invalid", "pattern": "t"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.Transform(tt.input, tt.params)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

// TestTextTransformer tests all text transformation operations
func TestTextTransformer(t *testing.T) {
	transformer := &TextTransformer{}

	tests := []struct {
		name      string
		input     interface{}
		params    map[string]interface{}
		wantError bool
		validate  func(t *testing.T, result interface{})
	}{
		// Word count
		{
			name:   "word count",
			input:  "hello world this is a test",
			params: map[string]interface{}{"operation": "word_count"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, 6, result)
			},
		},
		// Character count
		{
			name:   "char count",
			input:  "hello",
			params: map[string]interface{}{"operation": "char_count"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, 5, result)
			},
		},
		// Sanitize
		{
			name:   "sanitize",
			input:  "hello\x00world\x01test",
			params: map[string]interface{}{"operation": "sanitize"},
			validate: func(t *testing.T, result interface{}) {
				sanitized, ok := result.(string)
				assert.True(t, ok)
				assert.Equal(t, "helloworldtest", sanitized)
			},
		},
		// Truncate
		{
			name:   "truncate default",
			input:  "this is a very long string that should be truncated because it exceeds the default length limit",
			params: map[string]interface{}{"operation": "truncate", "length": 20},
			validate: func(t *testing.T, result interface{}) {
				truncated, ok := result.(string)
				assert.True(t, ok)
				assert.True(t, len(truncated) <= 20)
				assert.True(t, strings.HasSuffix(truncated, "..."))
			},
		},
		{
			name:   "truncate custom suffix",
			input:  "this is a long string",
			params: map[string]interface{}{"operation": "truncate", "length": 10, "suffix": ">>"},
			validate: func(t *testing.T, result interface{}) {
				truncated, ok := result.(string)
				assert.True(t, ok)
				assert.True(t, len(truncated) <= 10)
				assert.True(t, strings.HasSuffix(truncated, ">>"))
			},
		},
		// Wrap
		{
			name:   "wrap text",
			input:  "this is a long line of text that should be wrapped at word boundaries",
			params: map[string]interface{}{"operation": "wrap", "width": 20},
			validate: func(t *testing.T, result interface{}) {
				wrapped, ok := result.(string)
				assert.True(t, ok)
				lines := strings.Split(wrapped, "\n")
				for _, line := range lines {
					assert.True(t, len(line) <= 20 || !strings.Contains(line, " "))
				}
			},
		},
		// Indent
		{
			name:   "indent default",
			input:  "line1\nline2\nline3",
			params: map[string]interface{}{"operation": "indent"},
			validate: func(t *testing.T, result interface{}) {
				indented, ok := result.(string)
				assert.True(t, ok)
				lines := strings.Split(indented, "\n")
				for _, line := range lines {
					assert.True(t, strings.HasPrefix(line, "  "))
				}
			},
		},
		{
			name:   "indent custom",
			input:  "line1\nline2",
			params: map[string]interface{}{"operation": "indent", "indent": "    "},
			validate: func(t *testing.T, result interface{}) {
				indented, ok := result.(string)
				assert.True(t, ok)
				lines := strings.Split(indented, "\n")
				for _, line := range lines {
					assert.True(t, strings.HasPrefix(line, "    "))
				}
			},
		},
		// Slug
		{
			name:   "slug creation",
			input:  "Hello World! This is a Test.",
			params: map[string]interface{}{"operation": "slug"},
			validate: func(t *testing.T, result interface{}) {
				slug, ok := result.(string)
				assert.True(t, ok)
				assert.Equal(t, "hello-world-this-is-a-test", slug)
			},
		},
		// Capitalize
		{
			name:   "capitalize",
			input:  "hello WORLD",
			params: map[string]interface{}{"operation": "capitalize"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, "Hello world", result)
			},
		},
		{
			name:   "capitalize empty",
			input:  "",
			params: map[string]interface{}{"operation": "capitalize"},
			validate: func(t *testing.T, result interface{}) {
				assert.Equal(t, "", result)
			},
		},
		// Error cases
		{
			name:      "missing operation",
			input:     "test",
			params:    map[string]interface{}{},
			wantError: true,
		},
		{
			name:      "invalid operation",
			input:     "test",
			params:    map[string]interface{}{"operation": "invalid"},
			wantError: true,
		},
		{
			name:      "truncate invalid length",
			input:     "test",
			params:    map[string]interface{}{"operation": "truncate", "length": "invalid"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.Transform(tt.input, tt.params)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

// TestTransformerInterfaces tests that all transformers implement the required interface
func TestTransformerInterfaces(t *testing.T) {
	transformers := []Transformer{
		&StringTransformer{},
		&NumberTransformer{},
		&DateTimeTransformer{},
		&JSONTransformer{},
		&RegexTransformer{},
		&TextTransformer{},
	}

	for _, transformer := range transformers {
		t.Run(transformer.GetName(), func(t *testing.T) {
			// Test interface methods
			name := transformer.GetName()
			assert.NotEmpty(t, name)

			description := transformer.GetDescription()
			assert.NotEmpty(t, description)

			// Test parameter validation
			err := transformer.ValidateParams(map[string]interface{}{})
			assert.Error(t, err) // Should require operation parameter

			err = transformer.ValidateParams(map[string]interface{}{"operation": "invalid"})
			assert.Error(t, err) // Should reject invalid operation
		})
	}
}