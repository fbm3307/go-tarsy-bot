package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// OAuth2Config holds OAuth2 proxy configuration
type OAuth2Config struct {
	Enabled           bool   `yaml:"enabled"`
	UpstreamURL       string `yaml:"upstream_url"`
	ClientID          string `yaml:"client_id"`
	ClientSecret      string `yaml:"client_secret"`
	RedirectURL       string `yaml:"redirect_url"`
	OIDCIssuerURL     string `yaml:"oidc_issuer_url"`
	EmailDomains      string `yaml:"email_domains"`
	CookieName        string `yaml:"cookie_name"`
	CookieSecret      string `yaml:"cookie_secret"`
	CookieSecure      bool   `yaml:"cookie_secure"`
	CookieHttpOnly    bool   `yaml:"cookie_httponly"`
	CookieExpire      string `yaml:"cookie_expire"`
	SkipAuthRegex     string `yaml:"skip_auth_regex"`
	SkipProviderCheck bool   `yaml:"skip_provider_check"`
}

// DefaultOAuth2Config returns default OAuth2 configuration
func DefaultOAuth2Config() *OAuth2Config {
	return &OAuth2Config{
		Enabled:           false,
		UpstreamURL:       "http://localhost:8000",
		ClientID:          "",
		ClientSecret:      "",
		RedirectURL:       "http://localhost:4180/oauth2/callback",
		OIDCIssuerURL:     "",
		EmailDomains:      "*",
		CookieName:        "_oauth2_proxy",
		CookieSecret:      "",
		CookieSecure:      false,
		CookieHttpOnly:    true,
		CookieExpire:      "1h",
		SkipAuthRegex:     `^/(health|metrics|\.well-known)`,
		SkipProviderCheck: false,
	}
}

// KeyManager handles JWT key generation for OAuth2 proxy integration
type KeyManager struct {
	config *JWTConfig
	logger *zap.Logger
}

// NewKeyManager creates a new key manager
func NewKeyManager(config *JWTConfig, logger *zap.Logger) *KeyManager {
	return &KeyManager{
		config: config,
		logger: logger,
	}
}

// GenerateJWTKeys generates RSA key pair for JWT signing
func (k *KeyManager) GenerateJWTKeys() error {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Extract public key
	publicKey := &privateKey.PublicKey

	// Create key directory if it doesn't exist
	keyDir := filepath.Dir(k.config.PrivateKeyPath)
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Save private key
	if err := k.savePrivateKey(privateKey); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save public key
	if err := k.savePublicKey(publicKey); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	k.logger.Info("JWT keys generated successfully",
		zap.String("private_key", k.config.PrivateKeyPath),
		zap.String("public_key", k.config.PublicKeyPath))

	return nil
}

// savePrivateKey saves RSA private key to PEM file
func (k *KeyManager) savePrivateKey(privateKey *rsa.PrivateKey) error {
	// Convert to PKCS#1 ASN.1 DER encoded form
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// Create PEM block
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// Write to file
	privateKeyFile, err := os.Create(k.config.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privateKeyFile.Close()

	// Set restrictive permissions on private key
	if err := privateKeyFile.Chmod(0600); err != nil {
		return fmt.Errorf("failed to set private key permissions: %w", err)
	}

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	return nil
}

// savePublicKey saves RSA public key to PEM file
func (k *KeyManager) savePublicKey(publicKey *rsa.PublicKey) error {
	// Convert to PKIX ASN.1 DER encoded form
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create PEM block
	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	// Write to file
	publicKeyFile, err := os.Create(k.config.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer publicKeyFile.Close()

	// Set readable permissions on public key
	if err := publicKeyFile.Chmod(0644); err != nil {
		return fmt.Errorf("failed to set public key permissions: %w", err)
	}

	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	return nil
}

// KeysExist checks if JWT keys already exist
func (k *KeyManager) KeysExist() bool {
	privateExists := fileExists(k.config.PrivateKeyPath)
	publicExists := fileExists(k.config.PublicKeyPath)
	return privateExists && publicExists
}

// ValidateKeys validates that existing keys are valid
func (k *KeyManager) ValidateKeys() error {
	// Check if keys exist
	if !k.KeysExist() {
		return fmt.Errorf("JWT keys do not exist")
	}

	// Try to load and validate the keys
	jwtManager := NewJWTManager(k.config, k.logger)
	if err := jwtManager.LoadPublicKey(); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Try to generate JWKS to ensure key is usable
	_, err := jwtManager.GetJWKS()
	if err != nil {
		return fmt.Errorf("failed to generate JWKS from public key: %w", err)
	}

	k.logger.Info("JWT keys validation successful")
	return nil
}

// fileExists checks if a file exists
func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return !os.IsNotExist(err)
}

// GenerateOAuth2ProxyConfig generates OAuth2 proxy configuration file
func (k *KeyManager) GenerateOAuth2ProxyConfig(oauth2Config *OAuth2Config, outputPath string) error {
	configTemplate := `
# OAuth2 Proxy Configuration for TARSy-bot
# Generated automatically - modify with caution

# Basic Configuration
http_address = "0.0.0.0:4180"
upstreams = ["` + oauth2Config.UpstreamURL + `"]

# OIDC Configuration
provider = "oidc"
client_id = "` + oauth2Config.ClientID + `"
client_secret = "` + oauth2Config.ClientSecret + `"
redirect_url = "` + oauth2Config.RedirectURL + `"
oidc_issuer_url = "` + oauth2Config.OIDCIssuerURL + `"

# Email Configuration
email_domains = ["` + oauth2Config.EmailDomains + `"]

# Cookie Configuration
cookie_name = "` + oauth2Config.CookieName + `"
cookie_secret = "` + oauth2Config.CookieSecret + `"
cookie_secure = ` + fmt.Sprintf("%t", oauth2Config.CookieSecure) + `
cookie_httponly = ` + fmt.Sprintf("%t", oauth2Config.CookieHttpOnly) + `
cookie_expire = "` + oauth2Config.CookieExpire + `"

# Skip Authentication for Public Endpoints
skip_auth_regex = ["` + oauth2Config.SkipAuthRegex + `"]

# Skip Provider Check (for testing)
skip_provider_check = ` + fmt.Sprintf("%t", oauth2Config.SkipProviderCheck) + `

# Logging
request_logging = true
standard_logging = true
auth_logging = true

# Headers
pass_basic_auth = false
pass_access_token = true
pass_user_headers = true
set_authorization_header = true
set_xauthrequest = true

# Security
ssl_insecure_skip_verify = false
`

	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write configuration file
	if err := os.WriteFile(outputPath, []byte(configTemplate), 0644); err != nil {
		return fmt.Errorf("failed to write OAuth2 proxy config: %w", err)
	}

	k.logger.Info("OAuth2 proxy configuration generated",
		zap.String("config_path", outputPath))

	return nil
}