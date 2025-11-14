package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/codeready/go-tarsy-bot/internal/config"
)

func main() {
	var (
		jsonOutput = flag.Bool("json", false, "Output results in JSON format")
		verbose    = flag.Bool("verbose", false, "Show detailed validation results")
		logLevel   = flag.String("log-level", "warn", "Log level (debug, info, warn, error)")
		help       = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		fmt.Println("TARSy-bot Configuration Validator")
		fmt.Println("=================================")
		fmt.Println()
		fmt.Println("Validates the TARSy-bot system configuration including:")
		fmt.Println("• Environment variables")
		fmt.Println("• Agent configurations (agents.yaml)")
		fmt.Println("• MCP server configurations")
		fmt.Println("• Pipeline settings")
		fmt.Println("• Health check settings")
		fmt.Println("• API server configuration")
		fmt.Println()
		fmt.Println("Usage:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  # Basic validation")
		fmt.Println("  go run cmd/validate-config/main.go")
		fmt.Println()
		fmt.Println("  # JSON output for automation")
		fmt.Println("  go run cmd/validate-config/main.go -json")
		fmt.Println()
		fmt.Println("  # Verbose output with details")
		fmt.Println("  go run cmd/validate-config/main.go -verbose")
		fmt.Println()
		fmt.Println("Exit codes:")
		fmt.Println("  0: Configuration is valid")
		fmt.Println("  1: Configuration has errors")
		fmt.Println("  2: Internal validation error")
		return
	}

	// Setup logger
	logger := setupLogger(*logLevel)
	defer logger.Sync()

	// Create validator
	validator := config.NewConfigValidator(logger)

	// Run validation
	result := validator.ValidateSystemConfiguration()

	// Output results
	if *jsonOutput {
		outputJSON(result)
	} else {
		outputHuman(result, *verbose)
	}

	// Exit with appropriate code
	if !result.Valid {
		os.Exit(1)
	}
}

// setupLogger creates and configures the logger
func setupLogger(level string) *zap.Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.WarnLevel
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapLevel)
	config.Development = false
	config.Encoding = "console"
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	logger, err := config.Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}

	return logger
}

// outputJSON outputs the validation result in JSON format
func outputJSON(result *config.ValidationResult) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(2)
	}
}

// outputHuman outputs the validation result in human-readable format
func outputHuman(result *config.ValidationResult, verbose bool) {
	fmt.Println("TARSy-bot Configuration Validation")
	fmt.Println("==================================")
	fmt.Println()

	// Overall status
	if result.Valid {
		fmt.Printf("✅ Configuration is VALID\n")
	} else {
		fmt.Printf("❌ Configuration is INVALID\n")
	}

	fmt.Printf("📊 Summary: %d errors, %d warnings\n", result.Summary.TotalErrors, result.Summary.TotalWarnings)
	fmt.Println()

	// Component status
	if len(result.Summary.Components) > 0 {
		fmt.Println("Component Status:")
		fmt.Println("─────────────────")

		// Sort components for consistent output
		components := make([]string, 0, len(result.Summary.Components))
		for component := range result.Summary.Components {
			components = append(components, component)
		}
		sort.Strings(components)

		for _, component := range components {
			validation := result.Summary.Components[component]
			status := "✅"
			if !validation.Valid {
				status = "❌"
			} else if validation.Warnings > 0 {
				status = "⚠️"
			}

			fmt.Printf("  %s %-15s  %d errors, %d warnings\n",
				status, component, validation.Errors, validation.Warnings)
		}
		fmt.Println()
	}

	// Errors
	if len(result.Errors) > 0 {
		fmt.Println("❌ Errors:")
		fmt.Println("─────────")
		for _, err := range result.Errors {
			fmt.Printf("  • %s.%s: %s\n", err.Component, err.Field, err.Message)
		}
		fmt.Println()
	}

	// Warnings
	if len(result.Warnings) > 0 {
		fmt.Println("⚠️  Warnings:")
		fmt.Println("──────────")
		for _, warning := range result.Warnings {
			fmt.Printf("  • %s.%s: %s\n", warning.Component, warning.Field, warning.Message)
		}
		fmt.Println()
	}

	// Detailed information if verbose
	if verbose {
		outputDetailedInformation()
	}

	// Recommendations
	if !result.Valid {
		fmt.Println("🔧 Recommendations:")
		fmt.Println("───────────────────")
		outputRecommendations(result)
	}
}

// outputDetailedInformation provides detailed configuration information
func outputDetailedInformation() {
	fmt.Println("📋 Configuration Details:")
	fmt.Println("─────────────────────────")

	// Environment variables
	fmt.Println("Environment Variables:")
	envVars := []struct {
		name     string
		required bool
	}{
		{"OPENAI_API_KEY", true},
		{"DEFAULT_LLM_PROVIDER", true},
		{"GOOGLE_API_KEY", false},
		{"XAI_API_KEY", false},
		{"LOG_LEVEL", false},
		{"PORT", false},
		{"HOST", false},
		{"PIPELINE_MAX_WORKERS", false},
		{"PIPELINE_TIMEOUT", false},
		{"HEALTH_CHECK_INTERVAL", false},
		{"MCP_SERVER_FILESYSTEM_PATH", false},
		{"MCP_SERVER_KUBECTL_KUBECONFIG", false},
		{"MCP_SERVER_GITHUB_TOKEN", false},
	}

	for _, env := range envVars {
		value := os.Getenv(env.name)
		status := "✅ Set"
		if value == "" {
			if env.required {
				status = "❌ Missing (Required)"
			} else {
				status = "⚠️  Not Set (Optional)"
			}
		}

		displayValue := value
		if strings.Contains(strings.ToLower(env.name), "key") || strings.Contains(strings.ToLower(env.name), "token") {
			if len(value) > 0 {
				displayValue = "***REDACTED***"
			}
		}

		fmt.Printf("  %-30s %s", env.name, status)
		if displayValue != "" {
			fmt.Printf(" = %s", displayValue)
		}
		fmt.Println()
	}
	fmt.Println()

	// Configuration files
	fmt.Println("Configuration Files:")
	configFiles := []string{
		"config/agents.yaml",
		".env",
	}

	for _, file := range configFiles {
		if _, err := os.Stat(file); err == nil {
			fmt.Printf("  ✅ %s (exists)\n", file)
		} else {
			fmt.Printf("  ⚠️  %s (not found)\n", file)
		}
	}
	fmt.Println()
}

// outputRecommendations provides specific recommendations based on validation results
func outputRecommendations(result *config.ValidationResult) {
	recommendations := make(map[string][]string)

	for _, err := range result.Errors {
		component := err.Component
		switch component {
		case "environment":
			if strings.Contains(err.Field, "API_KEY") {
				recommendations[component] = append(recommendations[component],
					fmt.Sprintf("Set %s environment variable with a valid API key", err.Field))
			} else if err.Field == "DEFAULT_LLM_PROVIDER" {
				recommendations[component] = append(recommendations[component],
					"Set DEFAULT_LLM_PROVIDER to one of: openai, google, xai")
			} else {
				recommendations[component] = append(recommendations[component],
					fmt.Sprintf("Fix %s: %s", err.Field, err.Message))
			}

		case "agents":
			if strings.Contains(err.Message, "YAML") {
				recommendations[component] = append(recommendations[component],
					"Fix YAML syntax errors in config/agents.yaml")
			} else {
				recommendations[component] = append(recommendations[component],
					"Review agent configuration in config/agents.yaml")
			}

		case "pipeline":
			recommendations[component] = append(recommendations[component],
				"Adjust pipeline configuration environment variables")

		case "health_checks":
			recommendations[component] = append(recommendations[component],
				"Review health check configuration settings")

		case "api_server":
			recommendations[component] = append(recommendations[component],
				"Check API server configuration (HOST, PORT)")

		default:
			recommendations[component] = append(recommendations[component],
				fmt.Sprintf("Review %s configuration", component))
		}
	}

	// Add general recommendations
	if len(result.Errors) > 0 {
		recommendations["general"] = []string{
			"Review the TARSy-bot documentation for configuration requirements",
			"Check environment variable spelling and values",
			"Ensure all required services (LLM providers, MCP servers) are configured",
		}
	}

	// Output recommendations by component
	for component, recs := range recommendations {
		if len(recs) > 0 {
			fmt.Printf("  %s:\n", strings.Title(component))
			for _, rec := range recs {
				fmt.Printf("    • %s\n", rec)
			}
		}
	}
	fmt.Println()

	// Quick fix examples
	fmt.Println("💡 Quick Fix Examples:")
	fmt.Println("─────────────────────")
	fmt.Println("  # Set required environment variables:")
	fmt.Println("  export OPENAI_API_KEY=\"your-api-key-here\"")
	fmt.Println("  export DEFAULT_LLM_PROVIDER=\"openai\"")
	fmt.Println()
	fmt.Println("  # Create basic agent configuration:")
	fmt.Println("  cp config/agents.yaml.example config/agents.yaml")
	fmt.Println()
	fmt.Println("  # Check configuration before starting:")
	fmt.Println("  go run cmd/validate-config/main.go")
	fmt.Println()
}