package prompts

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Built-in transformers for common data transformation needs

// StringTransformer provides string manipulation transformations
type StringTransformer struct{}

func (st *StringTransformer) GetName() string {
	return "string"
}

func (st *StringTransformer) GetDescription() string {
	return "String manipulation transformations (upper, lower, title, trim, etc.)"
}

func (st *StringTransformer) ValidateParams(params map[string]interface{}) error {
	operation, exists := params["operation"]
	if !exists {
		return fmt.Errorf("operation parameter is required")
	}

	validOps := []string{"upper", "lower", "title", "trim", "trim_space", "reverse", "length", "substring", "replace", "split", "join"}
	opStr := fmt.Sprintf("%v", operation)
	for _, valid := range validOps {
		if opStr == valid {
			return nil
		}
	}

	return fmt.Errorf("invalid operation '%s', valid operations: %v", opStr, validOps)
}

func (st *StringTransformer) Transform(input interface{}, params map[string]interface{}) (interface{}, error) {
	if err := st.ValidateParams(params); err != nil {
		return nil, err
	}

	str := fmt.Sprintf("%v", input)
	operation := fmt.Sprintf("%v", params["operation"])

	switch operation {
	case "upper":
		return strings.ToUpper(str), nil
	case "lower":
		return strings.ToLower(str), nil
	case "title":
		return strings.Title(str), nil
	case "trim":
		cutset := " \t\n\r"
		if c, exists := params["cutset"]; exists {
			cutset = fmt.Sprintf("%v", c)
		}
		return strings.Trim(str, cutset), nil
	case "trim_space":
		return strings.TrimSpace(str), nil
	case "reverse":
		runes := []rune(str)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		return string(runes), nil
	case "length":
		return len(str), nil
	case "substring":
		start, startErr := getIntParam(params, "start", 0)
		if startErr != nil {
			return nil, fmt.Errorf("invalid start parameter: %w", startErr)
		}
		end, endErr := getIntParam(params, "end", len(str))
		if endErr != nil {
			return nil, fmt.Errorf("invalid end parameter: %w", endErr)
		}
		if start < 0 || start > len(str) || end < 0 || end > len(str) || start > end {
			return "", nil // Return empty string for invalid ranges
		}
		return str[start:end], nil
	case "replace":
		old, oldExists := params["old"]
		new, newExists := params["new"]
		if !oldExists || !newExists {
			return nil, fmt.Errorf("replace operation requires 'old' and 'new' parameters")
		}
		count := -1 // Replace all by default
		if _, exists := params["count"]; exists {
			if countInt, err := getIntParam(params, "count", -1); err == nil {
				count = countInt
			}
		}
		return strings.Replace(str, fmt.Sprintf("%v", old), fmt.Sprintf("%v", new), count), nil
	case "split":
		sep, exists := params["separator"]
		if !exists {
			return nil, fmt.Errorf("split operation requires 'separator' parameter")
		}
		return strings.Split(str, fmt.Sprintf("%v", sep)), nil
	case "join":
		if arr, ok := input.([]interface{}); ok {
			sep := ","
			if s, exists := params["separator"]; exists {
				sep = fmt.Sprintf("%v", s)
			}
			var strs []string
			for _, item := range arr {
				strs = append(strs, fmt.Sprintf("%v", item))
			}
			return strings.Join(strs, sep), nil
		}
		return nil, fmt.Errorf("join operation requires array input")
	default:
		return nil, fmt.Errorf("unknown string operation: %s", operation)
	}
}

// NumberTransformer provides number manipulation transformations
type NumberTransformer struct{}

func (nt *NumberTransformer) GetName() string {
	return "number"
}

func (nt *NumberTransformer) GetDescription() string {
	return "Number manipulation transformations (round, abs, format, etc.)"
}

func (nt *NumberTransformer) ValidateParams(params map[string]interface{}) error {
	operation, exists := params["operation"]
	if !exists {
		return fmt.Errorf("operation parameter is required")
	}

	validOps := []string{"round", "abs", "format", "add", "subtract", "multiply", "divide", "min", "max"}
	opStr := fmt.Sprintf("%v", operation)
	for _, valid := range validOps {
		if opStr == valid {
			return nil
		}
	}

	return fmt.Errorf("invalid operation '%s', valid operations: %v", opStr, validOps)
}

func (nt *NumberTransformer) Transform(input interface{}, params map[string]interface{}) (interface{}, error) {
	if err := nt.ValidateParams(params); err != nil {
		return nil, err
	}

	// Convert input to float64
	var num float64
	var err error

	switch v := input.(type) {
	case int:
		num = float64(v)
	case int32:
		num = float64(v)
	case int64:
		num = float64(v)
	case float32:
		num = float64(v)
	case float64:
		num = v
	case string:
		num, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("cannot convert '%s' to number: %w", v, err)
		}
	default:
		str := fmt.Sprintf("%v", input)
		num, err = strconv.ParseFloat(str, 64)
		if err != nil {
			return nil, fmt.Errorf("cannot convert '%v' to number: %w", input, err)
		}
	}

	operation := fmt.Sprintf("%v", params["operation"])

	switch operation {
	case "round":
		precision, _ := getIntParam(params, "precision", 0)
		multiplier := 1.0
		for i := 0; i < precision; i++ {
			multiplier *= 10
		}
		return fmt.Sprintf("%."+fmt.Sprintf("%d", precision)+"f", num), nil
	case "abs":
		if num < 0 {
			return -num, nil
		}
		return num, nil
	case "format":
		format := "%.2f"
		if f, exists := params["format"]; exists {
			format = fmt.Sprintf("%v", f)
		}
		return fmt.Sprintf(format, num), nil
	case "add":
		value, err := getFloatParam(params, "value", 0)
		if err != nil {
			return nil, fmt.Errorf("add operation requires valid 'value' parameter: %w", err)
		}
		return num + value, nil
	case "subtract":
		value, err := getFloatParam(params, "value", 0)
		if err != nil {
			return nil, fmt.Errorf("subtract operation requires valid 'value' parameter: %w", err)
		}
		return num - value, nil
	case "multiply":
		value, err := getFloatParam(params, "value", 1)
		if err != nil {
			return nil, fmt.Errorf("multiply operation requires valid 'value' parameter: %w", err)
		}
		return num * value, nil
	case "divide":
		value, err := getFloatParam(params, "value", 1)
		if err != nil {
			return nil, fmt.Errorf("divide operation requires valid 'value' parameter: %w", err)
		}
		if value == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return num / value, nil
	default:
		return nil, fmt.Errorf("unknown number operation: %s", operation)
	}
}

// DateTimeTransformer provides date/time manipulation transformations
type DateTimeTransformer struct{}

func (dt *DateTimeTransformer) GetName() string {
	return "datetime"
}

func (dt *DateTimeTransformer) GetDescription() string {
	return "Date/time manipulation transformations (format, add, subtract, etc.)"
}

func (dt *DateTimeTransformer) ValidateParams(params map[string]interface{}) error {
	operation, exists := params["operation"]
	if !exists {
		return fmt.Errorf("operation parameter is required")
	}

	validOps := []string{"format", "add", "subtract", "now", "parse", "unix", "year", "month", "day", "hour", "minute", "second"}
	opStr := fmt.Sprintf("%v", operation)
	for _, valid := range validOps {
		if opStr == valid {
			return nil
		}
	}

	return fmt.Errorf("invalid operation '%s', valid operations: %v", opStr, validOps)
}

func (dt *DateTimeTransformer) Transform(input interface{}, params map[string]interface{}) (interface{}, error) {
	if err := dt.ValidateParams(params); err != nil {
		return nil, err
	}

	operation := fmt.Sprintf("%v", params["operation"])

	// Handle operations that don't require input parsing
	if operation == "now" {
		return time.Now(), nil
	}

	// Parse input as time
	var t time.Time
	var err error

	switch v := input.(type) {
	case time.Time:
		t = v
	case string:
		// Try common time formats
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02 15:04:05",
			"2006-01-02",
			"15:04:05",
		}

		for _, format := range formats {
			if t, err = time.Parse(format, v); err == nil {
				break
			}
		}

		if err != nil {
			return nil, fmt.Errorf("cannot parse time '%s': %w", v, err)
		}
	case int64:
		t = time.Unix(v, 0)
	default:
		return nil, fmt.Errorf("cannot convert '%v' to time", input)
	}

	switch operation {
	case "format":
		format := time.RFC3339
		if f, exists := params["format"]; exists {
			format = fmt.Sprintf("%v", f)
		}
		return t.Format(format), nil
	case "add":
		duration, err := getDurationParam(params, "duration")
		if err != nil {
			return nil, fmt.Errorf("add operation requires valid 'duration' parameter: %w", err)
		}
		return t.Add(duration), nil
	case "subtract":
		duration, err := getDurationParam(params, "duration")
		if err != nil {
			return nil, fmt.Errorf("subtract operation requires valid 'duration' parameter: %w", err)
		}
		return t.Add(-duration), nil
	case "unix":
		return t.Unix(), nil
	case "year":
		return t.Year(), nil
	case "month":
		return int(t.Month()), nil
	case "day":
		return t.Day(), nil
	case "hour":
		return t.Hour(), nil
	case "minute":
		return t.Minute(), nil
	case "second":
		return t.Second(), nil
	default:
		return nil, fmt.Errorf("unknown datetime operation: %s", operation)
	}
}

// JSONTransformer provides JSON manipulation transformations
type JSONTransformer struct{}

func (jt *JSONTransformer) GetName() string {
	return "json"
}

func (jt *JSONTransformer) GetDescription() string {
	return "JSON manipulation transformations (parse, stringify, extract, etc.)"
}

func (jt *JSONTransformer) ValidateParams(params map[string]interface{}) error {
	operation, exists := params["operation"]
	if !exists {
		return fmt.Errorf("operation parameter is required")
	}

	validOps := []string{"parse", "stringify", "extract", "pretty", "minify"}
	opStr := fmt.Sprintf("%v", operation)
	for _, valid := range validOps {
		if opStr == valid {
			return nil
		}
	}

	return fmt.Errorf("invalid operation '%s', valid operations: %v", opStr, validOps)
}

func (jt *JSONTransformer) Transform(input interface{}, params map[string]interface{}) (interface{}, error) {
	if err := jt.ValidateParams(params); err != nil {
		return nil, err
	}

	operation := fmt.Sprintf("%v", params["operation"])

	switch operation {
	case "parse":
		str := fmt.Sprintf("%v", input)
		var result interface{}
		err := json.Unmarshal([]byte(str), &result)
		if err != nil {
			return nil, fmt.Errorf("JSON parse error: %w", err)
		}
		return result, nil
	case "stringify":
		jsonBytes, err := json.Marshal(input)
		if err != nil {
			return nil, fmt.Errorf("JSON stringify error: %w", err)
		}
		return string(jsonBytes), nil
	case "pretty":
		jsonBytes, err := json.MarshalIndent(input, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("JSON pretty print error: %w", err)
		}
		return string(jsonBytes), nil
	case "extract":
		path, exists := params["path"]
		if !exists {
			return nil, fmt.Errorf("extract operation requires 'path' parameter")
		}
		return jt.extractPath(input, fmt.Sprintf("%v", path))
	case "minify":
		jsonBytes, err := json.Marshal(input)
		if err != nil {
			return nil, fmt.Errorf("JSON minify error: %w", err)
		}
		return string(jsonBytes), nil
	default:
		return nil, fmt.Errorf("unknown json operation: %s", operation)
	}
}

func (jt *JSONTransformer) extractPath(data interface{}, path string) (interface{}, error) {
	// Simple path extraction - would be enhanced with JSONPath library
	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			if val, exists := v[part]; exists {
				current = val
			} else {
				return nil, fmt.Errorf("path '%s' not found", path)
			}
		default:
			return nil, fmt.Errorf("cannot navigate path '%s' at '%s'", path, part)
		}
	}

	return current, nil
}

// RegexTransformer provides regular expression transformations
type RegexTransformer struct{}

func (rt *RegexTransformer) GetName() string {
	return "regex"
}

func (rt *RegexTransformer) GetDescription() string {
	return "Regular expression transformations (match, replace, extract, etc.)"
}

func (rt *RegexTransformer) ValidateParams(params map[string]interface{}) error {
	operation, exists := params["operation"]
	if !exists {
		return fmt.Errorf("operation parameter is required")
	}

	validOps := []string{"match", "replace", "extract", "split", "find_all"}
	opStr := fmt.Sprintf("%v", operation)
	for _, valid := range validOps {
		if opStr == valid {
			return nil
		}
	}

	return fmt.Errorf("invalid operation '%s', valid operations: %v", opStr, validOps)
}

func (rt *RegexTransformer) Transform(input interface{}, params map[string]interface{}) (interface{}, error) {
	if err := rt.ValidateParams(params); err != nil {
		return nil, err
	}

	str := fmt.Sprintf("%v", input)
	operation := fmt.Sprintf("%v", params["operation"])

	pattern, exists := params["pattern"]
	if !exists {
		return nil, fmt.Errorf("regex operations require 'pattern' parameter")
	}

	re, err := regexp.Compile(fmt.Sprintf("%v", pattern))
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	switch operation {
	case "match":
		return re.MatchString(str), nil
	case "replace":
		replacement, exists := params["replacement"]
		if !exists {
			return nil, fmt.Errorf("replace operation requires 'replacement' parameter")
		}
		return re.ReplaceAllString(str, fmt.Sprintf("%v", replacement)), nil
	case "extract":
		matches := re.FindStringSubmatch(str)
		if len(matches) == 0 {
			return nil, nil
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		return matches[1:], nil // Return capture groups
	case "split":
		return re.Split(str, -1), nil
	case "find_all":
		return re.FindAllString(str, -1), nil
	default:
		return nil, fmt.Errorf("unknown regex operation: %s", operation)
	}
}

// Helper functions

func getIntParam(params map[string]interface{}, key string, defaultValue int) (int, error) {
	if val, exists := params[key]; exists {
		switch v := val.(type) {
		case int:
			return v, nil
		case int32:
			return int(v), nil
		case int64:
			return int(v), nil
		case float64:
			return int(v), nil
		case string:
			return strconv.Atoi(v)
		default:
			str := fmt.Sprintf("%v", val)
			return strconv.Atoi(str)
		}
	}
	return defaultValue, nil
}

func getFloatParam(params map[string]interface{}, key string, defaultValue float64) (float64, error) {
	if val, exists := params[key]; exists {
		switch v := val.(type) {
		case int:
			return float64(v), nil
		case int32:
			return float64(v), nil
		case int64:
			return float64(v), nil
		case float32:
			return float64(v), nil
		case float64:
			return v, nil
		case string:
			return strconv.ParseFloat(v, 64)
		default:
			str := fmt.Sprintf("%v", val)
			return strconv.ParseFloat(str, 64)
		}
	}
	return defaultValue, nil
}

func getDurationParam(params map[string]interface{}, key string) (time.Duration, error) {
	if val, exists := params[key]; exists {
		switch v := val.(type) {
		case time.Duration:
			return v, nil
		case string:
			return time.ParseDuration(v)
		case int64:
			return time.Duration(v), nil
		case int:
			return time.Duration(v), nil
		default:
			str := fmt.Sprintf("%v", val)
			return time.ParseDuration(str)
		}
	}
	return 0, fmt.Errorf("duration parameter '%s' is required", key)
}

// TextTransformer provides advanced text manipulation
type TextTransformer struct{}

func (tt *TextTransformer) GetName() string {
	return "text"
}

func (tt *TextTransformer) GetDescription() string {
	return "Advanced text manipulation transformations (word_count, char_count, sanitize, etc.)"
}

func (tt *TextTransformer) ValidateParams(params map[string]interface{}) error {
	operation, exists := params["operation"]
	if !exists {
		return fmt.Errorf("operation parameter is required")
	}

	validOps := []string{"word_count", "char_count", "sanitize", "truncate", "wrap", "indent", "slug", "capitalize"}
	opStr := fmt.Sprintf("%v", operation)
	for _, valid := range validOps {
		if opStr == valid {
			return nil
		}
	}

	return fmt.Errorf("invalid operation '%s', valid operations: %v", opStr, validOps)
}

func (tt *TextTransformer) Transform(input interface{}, params map[string]interface{}) (interface{}, error) {
	if err := tt.ValidateParams(params); err != nil {
		return nil, err
	}

	str := fmt.Sprintf("%v", input)
	operation := fmt.Sprintf("%v", params["operation"])

	switch operation {
	case "word_count":
		words := strings.Fields(str)
		return len(words), nil
	case "char_count":
		return len(str), nil
	case "sanitize":
		// Remove non-printable characters
		return strings.Map(func(r rune) rune {
			if unicode.IsPrint(r) {
				return r
			}
			return -1
		}, str), nil
	case "truncate":
		length, err := getIntParam(params, "length", 100)
		if err != nil {
			return nil, fmt.Errorf("truncate operation requires valid 'length' parameter: %w", err)
		}
		if len(str) <= length {
			return str, nil
		}
		suffix := "..."
		if s, exists := params["suffix"]; exists {
			suffix = fmt.Sprintf("%v", s)
		}
		if length <= len(suffix) {
			return suffix[:length], nil
		}
		return str[:length-len(suffix)] + suffix, nil
	case "wrap":
		width, err := getIntParam(params, "width", 80)
		if err != nil {
			return nil, fmt.Errorf("wrap operation requires valid 'width' parameter: %w", err)
		}
		return tt.wrapText(str, width), nil
	case "indent":
		indent := "  "
		if i, exists := params["indent"]; exists {
			indent = fmt.Sprintf("%v", i)
		}
		lines := strings.Split(str, "\n")
		for i, line := range lines {
			lines[i] = indent + line
		}
		return strings.Join(lines, "\n"), nil
	case "slug":
		return tt.createSlug(str), nil
	case "capitalize":
		if len(str) == 0 {
			return str, nil
		}
		return strings.ToUpper(str[:1]) + strings.ToLower(str[1:]), nil
	default:
		return nil, fmt.Errorf("unknown text operation: %s", operation)
	}
}

func (tt *TextTransformer) wrapText(text string, width int) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}

	var lines []string
	var currentLine []string
	currentLength := 0

	for _, word := range words {
		if currentLength+len(word)+len(currentLine) > width && len(currentLine) > 0 {
			lines = append(lines, strings.Join(currentLine, " "))
			currentLine = []string{word}
			currentLength = len(word)
		} else {
			currentLine = append(currentLine, word)
			currentLength += len(word)
		}
	}

	if len(currentLine) > 0 {
		lines = append(lines, strings.Join(currentLine, " "))
	}

	return strings.Join(lines, "\n")
}

func (tt *TextTransformer) createSlug(text string) string {
	// Convert to lowercase
	slug := strings.ToLower(text)

	// Replace non-alphanumeric characters with dashes
	re := regexp.MustCompile(`[^a-z0-9]+`)
	slug = re.ReplaceAllString(slug, "-")

	// Remove leading and trailing dashes
	slug = strings.Trim(slug, "-")

	return slug
}