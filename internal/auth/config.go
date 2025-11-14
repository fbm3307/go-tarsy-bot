package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// AuthConfig holds all authentication-related configuration
type AuthConfig struct {
	JWT           *JWTConfig           `yaml:"jwt"`
	OAuth2        *OAuth2Config        `yaml:"oauth2"`
	Sanitization  *SanitizationConfig  `yaml:"sanitization"`
	Enabled       bool                 `yaml:"enabled"`
	RequiredRoles []string             `yaml:"required_roles"`
	PublicPaths   []string             `yaml:"public_paths"`
}

// DefaultAuthConfig returns default authentication configuration
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		JWT:          DefaultJWTConfig(),
		OAuth2:       DefaultOAuth2Config(),
		Sanitization: DefaultSanitizationConfig(),
		Enabled:      false, // Disabled by default for backward compatibility
		RequiredRoles: []string{},
		PublicPaths: []string{
			"/health",
			"/metrics",
			"/.well-known/jwks.json",
			"/docs",
			"/",
		},
	}
}

// LoadAuthConfig loads authentication configuration from environment and files
func LoadAuthConfig(logger *zap.Logger) (*AuthConfig, error) {
	config := DefaultAuthConfig()

	// Load from environment variables
	if err := config.loadFromEnv(); err != nil {
		return nil, fmt.Errorf("failed to load auth config from environment: %w", err)
	}

	// Load from config file if specified
	configPath := os.Getenv("AUTH_CONFIG_PATH")
	if configPath != "" {
		if err := config.loadFromFile(configPath); err != nil {
			logger.Warn("Failed to load auth config from file, using environment/defaults",
				zap.String("config_path", configPath),
				zap.Error(err))
		} else {
			logger.Info("Loaded auth config from file", zap.String("config_path", configPath))
		}
	}

	// Validate configuration
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid auth configuration: %w", err)
	}

	logger.Info("Authentication configuration loaded",
		zap.Bool("enabled", config.Enabled),
		zap.Bool("oauth2_enabled", config.OAuth2.Enabled),
		zap.Int("public_paths", len(config.PublicPaths)),
		zap.String("jwt_key_id", config.JWT.KeyID))

	return config, nil
}

// loadFromEnv loads configuration from environment variables
func (c *AuthConfig) loadFromEnv() error {
	// Authentication enabled
	if enabled := os.Getenv("AUTH_ENABLED"); enabled != "" {
		var err error
		c.Enabled, err = strconv.ParseBool(enabled)
		if err != nil {
			return fmt.Errorf("invalid AUTH_ENABLED value: %w", err)
		}
	}

	// JWT configuration
	if publicKeyPath := os.Getenv("JWT_PUBLIC_KEY_PATH"); publicKeyPath != "" {
		c.JWT.PublicKeyPath = publicKeyPath
	}
	if privateKeyPath := os.Getenv("JWT_PRIVATE_KEY_PATH"); privateKeyPath != "" {
		c.JWT.PrivateKeyPath = privateKeyPath
	}
	if keyID := os.Getenv("JWT_KEY_ID"); keyID != "" {
		c.JWT.KeyID = keyID
	}
	if algorithm := os.Getenv("JWT_ALGORITHM"); algorithm != "" {
		c.JWT.Algorithm = algorithm
	}

	// OAuth2 configuration
	if oauth2Enabled := os.Getenv("OAUTH2_ENABLED"); oauth2Enabled != "" {
		var err error
		c.OAuth2.Enabled, err = strconv.ParseBool(oauth2Enabled)
		if err != nil {
			return fmt.Errorf("invalid OAUTH2_ENABLED value: %w", err)
		}
	}
	if upstreamURL := os.Getenv("OAUTH2_UPSTREAM_URL"); upstreamURL != "" {
		c.OAuth2.UpstreamURL = upstreamURL
	}
	if clientID := os.Getenv("OAUTH2_CLIENT_ID"); clientID != "" {
		c.OAuth2.ClientID = clientID
	}
	if clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET"); clientSecret != "" {
		c.OAuth2.ClientSecret = clientSecret
	}
	if redirectURL := os.Getenv("OAUTH2_REDIRECT_URL"); redirectURL != "" {
		c.OAuth2.RedirectURL = redirectURL
	}
	if issuerURL := os.Getenv("OAUTH2_OIDC_ISSUER_URL"); issuerURL != "" {
		c.OAuth2.OIDCIssuerURL = issuerURL
	}
	if emailDomains := os.Getenv("OAUTH2_EMAIL_DOMAINS"); emailDomains != "" {
		c.OAuth2.EmailDomains = emailDomains
	}
	if cookieSecret := os.Getenv("OAUTH2_COOKIE_SECRET"); cookieSecret != "" {
		c.OAuth2.CookieSecret = cookieSecret
	}

	// Sanitization configuration
	if maxPayload := os.Getenv("SANITIZATION_MAX_PAYLOAD_SIZE"); maxPayload != "" {
		var err error
		c.Sanitization.MaxPayloadSize, err = strconv.ParseInt(maxPayload, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid SANITIZATION_MAX_PAYLOAD_SIZE value: %w", err)
		}
	}
	if maxString := os.Getenv("SANITIZATION_MAX_STRING_LENGTH"); maxString != "" {
		var err error
		c.Sanitization.MaxStringLength, err = strconv.Atoi(maxString)
		if err != nil {
			return fmt.Errorf("invalid SANITIZATION_MAX_STRING_LENGTH value: %w", err)
		}
	}
	if xssProtection := os.Getenv("SANITIZATION_XSS_PROTECTION"); xssProtection != "" {
		var err error
		c.Sanitization.EnableXSSProtection, err = strconv.ParseBool(xssProtection)
		if err != nil {
			return fmt.Errorf("invalid SANITIZATION_XSS_PROTECTION value: %w", err)
		}
	}

	// Required roles
	if roles := os.Getenv("AUTH_REQUIRED_ROLES"); roles != "" {
		c.RequiredRoles = strings.Split(roles, ",")
		for i, role := range c.RequiredRoles {
			c.RequiredRoles[i] = strings.TrimSpace(role)
		}
	}

	// Public paths
	if paths := os.Getenv("AUTH_PUBLIC_PATHS"); paths != "" {
		c.PublicPaths = strings.Split(paths, ",")
		for i, path := range c.PublicPaths {
			c.PublicPaths[i] = strings.TrimSpace(path)
		}
	}

	return nil
}

// loadFromFile loads configuration from YAML file
func (c *AuthConfig) loadFromFile(configPath string) error {
	// Handle relative paths
	if !filepath.IsAbs(configPath) {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current working directory: %w", err)
		}
		configPath = filepath.Join(cwd, configPath)
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var fileConfig AuthConfig
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Merge file config with current config (file config takes precedence)
	if fileConfig.JWT != nil {
		if fileConfig.JWT.PublicKeyPath != "" {
			c.JWT.PublicKeyPath = fileConfig.JWT.PublicKeyPath
		}
		if fileConfig.JWT.PrivateKeyPath != "" {
			c.JWT.PrivateKeyPath = fileConfig.JWT.PrivateKeyPath
		}
		if fileConfig.JWT.KeyID != "" {
			c.JWT.KeyID = fileConfig.JWT.KeyID
		}
		if fileConfig.JWT.Algorithm != "" {
			c.JWT.Algorithm = fileConfig.JWT.Algorithm
		}
	}

	if fileConfig.OAuth2 != nil {
		// Merge OAuth2 config
		if fileConfig.OAuth2.UpstreamURL != "" {
			c.OAuth2.UpstreamURL = fileConfig.OAuth2.UpstreamURL
		}
		if fileConfig.OAuth2.ClientID != "" {
			c.OAuth2.ClientID = fileConfig.OAuth2.ClientID
		}
		// ... merge other fields as needed
	}

	if fileConfig.Sanitization != nil {
		// Merge sanitization config
		if fileConfig.Sanitization.MaxPayloadSize > 0 {
			c.Sanitization.MaxPayloadSize = fileConfig.Sanitization.MaxPayloadSize
		}
		if fileConfig.Sanitization.MaxStringLength > 0 {
			c.Sanitization.MaxStringLength = fileConfig.Sanitization.MaxStringLength
		}
		// ... merge other fields as needed
	}

	if len(fileConfig.RequiredRoles) > 0 {
		c.RequiredRoles = fileConfig.RequiredRoles
	}

	if len(fileConfig.PublicPaths) > 0 {
		c.PublicPaths = fileConfig.PublicPaths
	}

	return nil
}

// validate validates the authentication configuration
func (c *AuthConfig) validate() error {
	if !c.Enabled {
		return nil // Skip validation if auth is disabled
	}

	// Validate JWT configuration
	if c.JWT.PublicKeyPath == "" {
		return fmt.Errorf("JWT public key path is required when authentication is enabled")
	}
	if c.JWT.KeyID == "" {
		return fmt.Errorf("JWT key ID is required when authentication is enabled")
	}
	if c.JWT.Algorithm == "" {
		return fmt.Errorf("JWT algorithm is required when authentication is enabled")
	}

	// Validate OAuth2 configuration if enabled
	if c.OAuth2.Enabled {
		if c.OAuth2.ClientID == "" {
			return fmt.Errorf("OAuth2 client ID is required when OAuth2 is enabled")
		}
		if c.OAuth2.ClientSecret == "" {
			return fmt.Errorf("OAuth2 client secret is required when OAuth2 is enabled")
		}
		if c.OAuth2.OIDCIssuerURL == "" {
			return fmt.Errorf("OAuth2 OIDC issuer URL is required when OAuth2 is enabled")
		}
	}

	// Validate sanitization configuration
	if c.Sanitization.MaxPayloadSize <= 0 {
		return fmt.Errorf("sanitization max payload size must be positive")
	}
	if c.Sanitization.MaxStringLength <= 0 {
		return fmt.Errorf("sanitization max string length must be positive")
	}
	if c.Sanitization.MaxArraySize <= 0 {
		return fmt.Errorf("sanitization max array size must be positive")
	}

	return nil
}

// IsPublicPath checks if a path should be publicly accessible
func (c *AuthConfig) IsPublicPath(path string) bool {
	for _, publicPath := range c.PublicPaths {
		if strings.HasPrefix(path, publicPath) {
			return true
		}
	}
	return false
}

// GetJWTManager creates a JWT manager from the configuration
func (c *AuthConfig) GetJWTManager(logger *zap.Logger) *JWTManager {
	return NewJWTManager(c.JWT, logger)
}

// GetKeyManager creates a key manager from the configuration
func (c *AuthConfig) GetKeyManager(logger *zap.Logger) *KeyManager {
	return NewKeyManager(c.JWT, logger)
}

// GetInputSanitizer creates an input sanitizer from the configuration
func (c *AuthConfig) GetInputSanitizer(logger *zap.Logger) (*InputSanitizer, error) {
	return NewInputSanitizer(c.Sanitization, logger)
}

// SaveToFile saves the configuration to a YAML file
func (c *AuthConfig) SaveToFile(configPath string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}