package prompts

import (
	"fmt"
	"regexp"
	"strings"
)

// TemplateVariableResolver handles sophisticated variable substitution in templates
type TemplateVariableResolver struct {
	variables     map[string]interface{}
	globalVars    map[string]interface{}
	contextVars   map[string]interface{}
	functions     map[string]TemplateFunction
	functionRegex *regexp.Regexp
	variableRegex *regexp.Regexp
}

// NewTemplateVariableResolver creates a new template variable resolver
func NewTemplateVariableResolver() *TemplateVariableResolver {
	return &TemplateVariableResolver{
		variables:     make(map[string]interface{}),
		globalVars:    make(map[string]interface{}),
		contextVars:   make(map[string]interface{}),
		functions:     make(map[string]TemplateFunction),
		functionRegex: regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\((.*?)\)\}`),
		variableRegex: regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`),
	}
}

// SetVariable sets a variable value
func (tvr *TemplateVariableResolver) SetVariable(key string, value interface{}) {
	tvr.variables[key] = value
	tvr.contextVars[key] = value
}

// SetGlobalVariable sets a global variable (persists across context clears)
func (tvr *TemplateVariableResolver) SetGlobalVariable(key string, value interface{}) {
	tvr.variables[key] = value
	tvr.globalVars[key] = value
}

// GetVariable gets a variable value
func (tvr *TemplateVariableResolver) GetVariable(key string) (interface{}, bool) {
	value, exists := tvr.variables[key]
	return value, exists
}

// RegisterFunction registers a template function
func (tvr *TemplateVariableResolver) RegisterFunction(name string, fn TemplateFunction) {
	tvr.functions[name] = fn
}

// ClearContextVariables clears context variables but keeps global ones
func (tvr *TemplateVariableResolver) ClearContextVariables() {
	tvr.variables = make(map[string]interface{})
	tvr.contextVars = make(map[string]interface{})

	// Restore global variables
	for key, value := range tvr.globalVars {
		tvr.variables[key] = value
	}
}

// Resolve resolves all variables and functions in a template string
func (tvr *TemplateVariableResolver) Resolve(template string) string {
	// First pass: resolve functions
	resolved := tvr.resolveFunctions(template)

	// Second pass: resolve variables
	resolved = tvr.resolveVariables(resolved)

	// Third pass: handle conditional blocks
	resolved = tvr.resolveConditionals(resolved)

	return resolved
}

// resolveVariables resolves variable placeholders in the template
func (tvr *TemplateVariableResolver) resolveVariables(template string) string {
	return tvr.variableRegex.ReplaceAllStringFunc(template, func(match string) string {
		// Extract variable name from ${VAR_NAME}
		matches := tvr.variableRegex.FindStringSubmatch(match)
		if len(matches) < 2 {
			return match // Return original if can't parse
		}

		varName := matches[1]
		if value, exists := tvr.variables[varName]; exists {
			return tvr.formatValue(value)
		}

		// Return empty string for undefined variables
		return ""
	})
}

// resolveFunctions resolves function calls in the template
func (tvr *TemplateVariableResolver) resolveFunctions(template string) string {
	return tvr.functionRegex.ReplaceAllStringFunc(template, func(match string) string {
		// Extract function name and arguments from ${func_name(arg1, arg2)}
		matches := tvr.functionRegex.FindStringSubmatch(match)
		if len(matches) < 3 {
			return match // Return original if can't parse
		}

		funcName := matches[1]
		argsString := matches[2]

		function, exists := tvr.functions[funcName]
		if !exists {
			return match // Return original if function not found
		}

		// Parse arguments
		args := tvr.parseArguments(argsString)

		// Execute function
		return function(args...)
	})
}

// resolveConditionals handles conditional blocks like ${if VAR}content${endif}
func (tvr *TemplateVariableResolver) resolveConditionals(template string) string {
	// Simple conditional processing - handles ${if VAR}...${endif} blocks
	conditionalRegex := regexp.MustCompile(`\$\{if\s+([^}]+)\}(.*?)\$\{endif\}`)

	return conditionalRegex.ReplaceAllStringFunc(template, func(match string) string {
		matches := conditionalRegex.FindStringSubmatch(match)
		if len(matches) < 3 {
			return match
		}

		condition := strings.TrimSpace(matches[1])
		content := matches[2]

		// Evaluate condition
		if tvr.evaluateCondition(condition) {
			return content
		}

		return "" // Remove content if condition is false
	})
}

// evaluateCondition evaluates a condition expression
func (tvr *TemplateVariableResolver) evaluateCondition(condition string) bool {
	// Handle negation
	if strings.HasPrefix(condition, "!") {
		return !tvr.evaluateCondition(strings.TrimSpace(condition[1:]))
	}

	// First try to resolve as variable
	if value, exists := tvr.variables[condition]; exists {
		return tvr.isTruthy(value)
	}

	// Try to resolve the condition string itself
	resolved := tvr.resolveVariables("${" + condition + "}")

	// Check if the resolved value is truthy
	return tvr.isTruthy(resolved)
}

// isTruthy checks if a value is considered true
func (tvr *TemplateVariableResolver) isTruthy(value interface{}) bool {
	if value == nil {
		return false
	}

	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.TrimSpace(v) != ""
	case int, int32, int64:
		return v != 0
	case float32, float64:
		return v != 0.0
	case []interface{}:
		return len(v) > 0
	case map[string]interface{}:
		return len(v) > 0
	default:
		// For unknown types, check if string representation is non-empty
		str := fmt.Sprintf("%v", v)
		return strings.TrimSpace(str) != ""
	}
}

// parseArguments parses function arguments from a string
func (tvr *TemplateVariableResolver) parseArguments(argsString string) []interface{} {
	if strings.TrimSpace(argsString) == "" {
		return []interface{}{}
	}

	// Simple argument parsing - splits by comma and trims whitespace
	argStrings := strings.Split(argsString, ",")
	args := make([]interface{}, len(argStrings))

	for i, argStr := range argStrings {
		argStr = strings.TrimSpace(argStr)

		// Remove quotes if present
		if (strings.HasPrefix(argStr, "\"") && strings.HasSuffix(argStr, "\"")) ||
			(strings.HasPrefix(argStr, "'") && strings.HasSuffix(argStr, "'")) {
			argStr = argStr[1 : len(argStr)-1]
		}

		// Try to resolve as variable first
		if value, exists := tvr.variables[argStr]; exists {
			args[i] = value
		} else {
			// Use as literal string
			args[i] = argStr
		}
	}

	return args
}

// formatValue formats a value for output in templates
func (tvr *TemplateVariableResolver) formatValue(value interface{}) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case []string:
		return strings.Join(v, ", ")
	case []interface{}:
		var strs []string
		for _, item := range v {
			strs = append(strs, tvr.formatValue(item))
		}
		return strings.Join(strs, ", ")
	case map[string]interface{}:
		// Format as key: value pairs
		var pairs []string
		for key, val := range v {
			pairs = append(pairs, fmt.Sprintf("%s: %s", key, tvr.formatValue(val)))
		}
		return strings.Join(pairs, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// GetAllVariables returns all current variables
func (tvr *TemplateVariableResolver) GetAllVariables() map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range tvr.variables {
		result[key] = value
	}
	return result
}

// GetGlobalVariables returns all global variables
func (tvr *TemplateVariableResolver) GetGlobalVariables() map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range tvr.globalVars {
		result[key] = value
	}
	return result
}

// GetContextVariables returns all context variables
func (tvr *TemplateVariableResolver) GetContextVariables() map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range tvr.contextVars {
		result[key] = value
	}
	return result
}

// Clone creates a copy of the resolver
func (tvr *TemplateVariableResolver) Clone() *TemplateVariableResolver {
	newResolver := NewTemplateVariableResolver()

	// Copy global variables
	for key, value := range tvr.globalVars {
		newResolver.SetGlobalVariable(key, value)
	}

	// Copy context variables
	for key, value := range tvr.contextVars {
		newResolver.SetVariable(key, value)
	}

	// Copy functions
	for name, fn := range tvr.functions {
		newResolver.RegisterFunction(name, fn)
	}

	return newResolver
}