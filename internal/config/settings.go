package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Settings holds all application configuration
type Settings struct {
	// Server configuration
	Host string
	Port int
	
	// Environment
	Environment string
	LogLevel    string
	
	// Database configuration
	HistoryEnabled      bool
	DatabaseURL         string
	DatabaseDriver      string
	RetentionDays       int
	
	// LLM configuration
	DefaultLLMProvider string
	MaxLLMIterations   int
	LLMTemperature     float64
	
	// API Keys for LLM providers
	OpenAIAPIKey     string
	GoogleAIAPIKey   string
	AnthropicAPIKey  string
	XAIAPIKey        string
	
	// Alert processing
	MaxConcurrentAlerts int
	AlertTimeout        time.Duration
	
	// CORS configuration
	CORSOrigins []string
	
	// JWT configuration
	JWTPublicKeyPath  string
	JWTPrivateKeyPath string
	
	// MCP configuration
	MCPServerTimeout time.Duration
	
	// WebSocket configuration
	WSReadTimeout  time.Duration
	WSWriteTimeout time.Duration
	WSPingPeriod   time.Duration

	// Data masking configuration (matches Python implementation)
	DataMaskingEnabled bool
	MaskingPatterns    []string

	// Agent configuration
	AgentConfigPath     string
	MCPServerConfigPath string

	// Runbook configuration
	RunbookTimeout     time.Duration
	RunbookRetryCount  int

	// Token tracking and cost estimation
	TokenTrackingEnabled bool
	CostTrackingEnabled  bool

	// Session cleanup configuration
	CleanupInterval        time.Duration
	OrphanedSessionTimeout time.Duration

	// Dashboard configuration
	DashboardUpdateInterval time.Duration
	MetricsRetentionHours   int

	// Feature flags
	EnabledFeatures map[string]bool
}

// DefaultSettings returns default configuration values
func DefaultSettings() *Settings {
	return &Settings{
		Host:        "0.0.0.0",
		Port:        8000,
		Environment: "development",
		LogLevel:    "info",
		
		HistoryEnabled: true,
		DatabaseURL:    "history.db",
		DatabaseDriver: "sqlite",
		RetentionDays:  90,
		
		DefaultLLMProvider: "openai",
		MaxLLMIterations:   10,
		LLMTemperature:     0.1,
		
		MaxConcurrentAlerts: 5,
		AlertTimeout:        10 * time.Minute,
		
		CORSOrigins: []string{"*"},
		
		JWTPublicKeyPath:  "keys/public.pem",
		JWTPrivateKeyPath: "keys/private.pem",
		
		MCPServerTimeout: 30 * time.Second,
		
		WSReadTimeout:  60 * time.Second,
		WSWriteTimeout: 10 * time.Second,
		WSPingPeriod:   54 * time.Second,

		// Data masking defaults (matches Python implementation)
		DataMaskingEnabled: false,
		MaskingPatterns:    []string{"password", "token", "key", "secret"},

		// Agent configuration defaults
		AgentConfigPath:     "config/agents.yaml",
		MCPServerConfigPath: "config/mcp_servers.yaml",

		// Runbook defaults
		RunbookTimeout:    30 * time.Second,
		RunbookRetryCount: 3,

		// Token and cost tracking defaults
		TokenTrackingEnabled: true,
		CostTrackingEnabled:  false,

		// Session cleanup defaults
		CleanupInterval:        5 * time.Minute,
		OrphanedSessionTimeout: 1 * time.Hour,

		// Dashboard defaults
		DashboardUpdateInterval: 5 * time.Second,
		MetricsRetentionHours:   24,

		EnabledFeatures: map[string]bool{
			"history_service":     true,
			"websocket_support":   true,
			"agent_registry":      true,
			"mcp_integration":     true,
			"data_masking":        false,
			"token_tracking":      true,
			"cost_tracking":       false,
			"session_cleanup":     true,
			"dashboard_updates":   true,
		},
	}
}

// LoadSettings loads configuration from environment variables and .env file
func LoadSettings() *Settings {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found or error loading: %v", err)
	}
	
	settings := DefaultSettings()
	
	// Override with environment variables
	if host := os.Getenv("HOST"); host != "" {
		settings.Host = host
	}
	
	if port := os.Getenv("PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			settings.Port = p
		}
	}
	
	if env := os.Getenv("GO_ENV"); env != "" {
		settings.Environment = env
	}
	
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		settings.LogLevel = logLevel
	}
	
	// Database configuration
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		settings.DatabaseURL = dbURL
	}
	
	if dbDriver := os.Getenv("DB_DRIVER"); dbDriver != "" {
		settings.DatabaseDriver = dbDriver
	}
	
	if historyEnabled := os.Getenv("HISTORY_ENABLED"); historyEnabled != "" {
		settings.HistoryEnabled = strings.ToLower(historyEnabled) == "true"
	}
	
	if retentionDays := os.Getenv("RETENTION_DAYS"); retentionDays != "" {
		if days, err := strconv.Atoi(retentionDays); err == nil {
			settings.RetentionDays = days
		}
	}
	
	// LLM configuration
	if provider := os.Getenv("DEFAULT_LLM_PROVIDER"); provider != "" {
		settings.DefaultLLMProvider = provider
	}
	
	if maxIterations := os.Getenv("MAX_LLM_MCP_ITERATIONS"); maxIterations != "" {
		if max, err := strconv.Atoi(maxIterations); err == nil {
			settings.MaxLLMIterations = max
		}
	}
	
	if temperature := os.Getenv("LLM_TEMPERATURE"); temperature != "" {
		if temp, err := strconv.ParseFloat(temperature, 64); err == nil {
			settings.LLMTemperature = temp
		}
	}
	
	// API Keys
	settings.OpenAIAPIKey = os.Getenv("OPENAI_API_KEY")
	settings.GoogleAIAPIKey = os.Getenv("GOOGLE_AI_API_KEY")
	settings.AnthropicAPIKey = os.Getenv("ANTHROPIC_API_KEY")
	settings.XAIAPIKey = os.Getenv("XAI_API_KEY")
	
	// Alert processing
	if maxConcurrent := os.Getenv("MAX_CONCURRENT_ALERTS"); maxConcurrent != "" {
		if max, err := strconv.Atoi(maxConcurrent); err == nil {
			settings.MaxConcurrentAlerts = max
		}
	}
	
	if timeout := os.Getenv("ALERT_TIMEOUT"); timeout != "" {
		if t, err := time.ParseDuration(timeout); err == nil {
			settings.AlertTimeout = t
		}
	}
	
	// CORS Origins
	if origins := os.Getenv("CORS_ORIGINS"); origins != "" {
		settings.CORSOrigins = strings.Split(origins, ",")
		for i, origin := range settings.CORSOrigins {
			settings.CORSOrigins[i] = strings.TrimSpace(origin)
		}
	}
	
	// JWT configuration
	if publicKeyPath := os.Getenv("JWT_PUBLIC_KEY_PATH"); publicKeyPath != "" {
		settings.JWTPublicKeyPath = publicKeyPath
	}
	
	if privateKeyPath := os.Getenv("JWT_PRIVATE_KEY_PATH"); privateKeyPath != "" {
		settings.JWTPrivateKeyPath = privateKeyPath
	}
	
	// MCP configuration
	if mcpTimeout := os.Getenv("MCP_SERVER_TIMEOUT"); mcpTimeout != "" {
		if timeout, err := time.ParseDuration(mcpTimeout); err == nil {
			settings.MCPServerTimeout = timeout
		}
	}

	// WebSocket configuration
	if wsReadTimeout := os.Getenv("WS_READ_TIMEOUT"); wsReadTimeout != "" {
		if timeout, err := time.ParseDuration(wsReadTimeout); err == nil {
			settings.WSReadTimeout = timeout
		}
	}

	if wsWriteTimeout := os.Getenv("WS_WRITE_TIMEOUT"); wsWriteTimeout != "" {
		if timeout, err := time.ParseDuration(wsWriteTimeout); err == nil {
			settings.WSWriteTimeout = timeout
		}
	}

	if wsPingPeriod := os.Getenv("WS_PING_PERIOD"); wsPingPeriod != "" {
		if period, err := time.ParseDuration(wsPingPeriod); err == nil {
			settings.WSPingPeriod = period
		}
	}

	// Data masking configuration
	if maskingEnabled := os.Getenv("DATA_MASKING_ENABLED"); maskingEnabled != "" {
		settings.DataMaskingEnabled = strings.ToLower(maskingEnabled) == "true"
	}

	if maskingPatterns := os.Getenv("MASKING_PATTERNS"); maskingPatterns != "" {
		patterns := strings.Split(maskingPatterns, ",")
		for i, pattern := range patterns {
			patterns[i] = strings.TrimSpace(pattern)
		}
		settings.MaskingPatterns = patterns
	}

	// Agent configuration paths
	if agentConfigPath := os.Getenv("AGENT_CONFIG_PATH"); agentConfigPath != "" {
		settings.AgentConfigPath = agentConfigPath
	}

	if mcpServerConfigPath := os.Getenv("MCP_SERVER_CONFIG_PATH"); mcpServerConfigPath != "" {
		settings.MCPServerConfigPath = mcpServerConfigPath
	}

	// Runbook configuration
	if runbookTimeout := os.Getenv("RUNBOOK_TIMEOUT"); runbookTimeout != "" {
		if timeout, err := time.ParseDuration(runbookTimeout); err == nil {
			settings.RunbookTimeout = timeout
		}
	}

	if runbookRetryCount := os.Getenv("RUNBOOK_RETRY_COUNT"); runbookRetryCount != "" {
		if count, err := strconv.Atoi(runbookRetryCount); err == nil {
			settings.RunbookRetryCount = count
		}
	}

	// Token and cost tracking
	if tokenTracking := os.Getenv("TOKEN_TRACKING_ENABLED"); tokenTracking != "" {
		settings.TokenTrackingEnabled = strings.ToLower(tokenTracking) == "true"
	}

	if costTracking := os.Getenv("COST_TRACKING_ENABLED"); costTracking != "" {
		settings.CostTrackingEnabled = strings.ToLower(costTracking) == "true"
	}

	// Session cleanup configuration
	if cleanupInterval := os.Getenv("CLEANUP_INTERVAL"); cleanupInterval != "" {
		if interval, err := time.ParseDuration(cleanupInterval); err == nil {
			settings.CleanupInterval = interval
		}
	}

	if orphanedTimeout := os.Getenv("ORPHANED_SESSION_TIMEOUT"); orphanedTimeout != "" {
		if timeout, err := time.ParseDuration(orphanedTimeout); err == nil {
			settings.OrphanedSessionTimeout = timeout
		}
	}

	// Dashboard configuration
	if dashboardUpdateInterval := os.Getenv("DASHBOARD_UPDATE_INTERVAL"); dashboardUpdateInterval != "" {
		if interval, err := time.ParseDuration(dashboardUpdateInterval); err == nil {
			settings.DashboardUpdateInterval = interval
		}
	}

	if metricsRetention := os.Getenv("METRICS_RETENTION_HOURS"); metricsRetention != "" {
		if hours, err := strconv.Atoi(metricsRetention); err == nil {
			settings.MetricsRetentionHours = hours
		}
	}

	// Feature flags - allow enabling/disabling individual features
	features := map[string]string{
		"FEATURE_HISTORY_SERVICE":    "history_service",
		"FEATURE_WEBSOCKET_SUPPORT":  "websocket_support",
		"FEATURE_AGENT_REGISTRY":     "agent_registry",
		"FEATURE_MCP_INTEGRATION":    "mcp_integration",
		"FEATURE_DATA_MASKING":       "data_masking",
		"FEATURE_TOKEN_TRACKING":     "token_tracking",
		"FEATURE_COST_TRACKING":      "cost_tracking",
		"FEATURE_SESSION_CLEANUP":    "session_cleanup",
		"FEATURE_DASHBOARD_UPDATES":  "dashboard_updates",
	}

	for envVar, featureKey := range features {
		if value := os.Getenv(envVar); value != "" {
			settings.EnabledFeatures[featureKey] = strings.ToLower(value) == "true"
		}
	}

	return settings
}

// IsDevelopment returns true if running in development mode
func (s *Settings) IsDevelopment() bool {
	return s.Environment == "development"
}

// IsProduction returns true if running in production mode
func (s *Settings) IsProduction() bool {
	return s.Environment == "production"
}

// IsTesting returns true if running in test mode
func (s *Settings) IsTesting() bool {
	return s.Environment == "test" || os.Getenv("TESTING") == "true"
}

// GetAddress returns the server address
func (s *Settings) GetAddress() string {
	return s.Host + ":" + strconv.Itoa(s.Port)
}

// Validate validates the configuration
func (s *Settings) Validate() error {
	// Add validation logic here
	if s.Port < 1 || s.Port > 65535 {
		return &ValidationError{Field: "Port", Message: "must be between 1 and 65535"}
	}
	
	if s.MaxLLMIterations < 1 {
		return &ValidationError{Field: "MaxLLMIterations", Message: "must be greater than 0"}
	}
	
	if s.LLMTemperature < 0 || s.LLMTemperature > 2 {
		return &ValidationError{Field: "LLMTemperature", Message: "must be between 0 and 2"}
	}
	
	return nil
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return "configuration validation error for field '" + e.Field + "': " + e.Message
}

// GetLLMAPIKey returns the API key for the specified provider
func (s *Settings) GetLLMAPIKey(provider string) string {
	switch strings.ToLower(provider) {
	case "openai":
		return s.OpenAIAPIKey
	case "google", "googleai", "google-ai":
		return s.GoogleAIAPIKey
	case "anthropic", "claude":
		return s.AnthropicAPIKey
	case "xai", "grok":
		return s.XAIAPIKey
	default:
		return ""
	}
}

// IsFeatureEnabled checks if a feature is enabled
func (s *Settings) IsFeatureEnabled(feature string) bool {
	if enabled, exists := s.EnabledFeatures[feature]; exists {
		return enabled
	}
	return false
}

// GetDatabaseDSN returns the database connection string
func (s *Settings) GetDatabaseDSN() string {
	if s.IsTesting() {
		return ":memory:"
	}
	return s.DatabaseURL
}