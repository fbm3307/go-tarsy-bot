package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key type
	Use string `json:"use"` // Key usage
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm
	N   string `json:"n"`   // Modulus (for RSA)
	E   string `json:"e"`   // Exponent (for RSA)
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	PublicKeyPath  string
	PrivateKeyPath string
	KeyID          string
	Algorithm      string
}

// JWKSCache provides caching for JWKS with TTL
type JWKSCache struct {
	jwks      *JWKS
	expiresAt time.Time
	ttl       time.Duration
	mutex     sync.RWMutex
}

// JWTManager handles JWT operations
type JWTManager struct {
	config    *JWTConfig
	cache     *JWKSCache
	publicKey *rsa.PublicKey
	logger    *zap.Logger
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(config *JWTConfig, logger *zap.Logger) *JWTManager {
	return &JWTManager{
		config: config,
		cache: &JWKSCache{
			ttl: time.Hour, // 1 hour TTL for JWKS cache
		},
		logger: logger,
	}
}

// DefaultJWTConfig returns default JWT configuration
func DefaultJWTConfig() *JWTConfig {
	return &JWTConfig{
		PublicKeyPath:  "config/keys/jwt_public_key.pem",
		PrivateKeyPath: "config/keys/jwt_private_key.pem",
		KeyID:          "tarsy-api-key-1",
		Algorithm:      "RS256",
	}
}

// LoadPublicKey loads and parses the RSA public key
func (j *JWTManager) LoadPublicKey() error {
	// Handle relative paths by resolving them from the project root
	keyPath := j.config.PublicKeyPath
	if !filepath.IsAbs(keyPath) {
		// Get current working directory and resolve relative path
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current working directory: %w", err)
		}
		keyPath = filepath.Join(cwd, keyPath)
	}

	// Check if file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return fmt.Errorf("JWT public key file does not exist at %s", keyPath)
	}

	// Read the public key file
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	// Parse PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block from public key")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Ensure it's an RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not an RSA key")
	}

	j.publicKey = rsaPubKey
	j.logger.Info("Successfully loaded JWT public key", zap.String("path", keyPath))
	return nil
}

// GetJWKS returns the JSON Web Key Set (JWKS)
func (j *JWTManager) GetJWKS() (*JWKS, error) {
	j.cache.mutex.RLock()
	// Check if cached JWKS is still valid
	if j.cache.jwks != nil && time.Now().Before(j.cache.expiresAt) {
		jwks := j.cache.jwks
		j.cache.mutex.RUnlock()
		j.logger.Debug("JWKS served from cache")
		return jwks, nil
	}
	j.cache.mutex.RUnlock()

	// Need to generate/refresh JWKS
	j.cache.mutex.Lock()
	defer j.cache.mutex.Unlock()

	// Double-check after acquiring write lock
	if j.cache.jwks != nil && time.Now().Before(j.cache.expiresAt) {
		j.logger.Debug("JWKS served from cache (double-check)")
		return j.cache.jwks, nil
	}

	// Load public key if not already loaded
	if j.publicKey == nil {
		if err := j.LoadPublicKey(); err != nil {
			return nil, fmt.Errorf("failed to load public key: %w", err)
		}
	}

	// Convert RSA public key to JWKS format
	jwks, err := j.rsaPublicKeyToJWKS(j.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to JWKS: %w", err)
	}

	// Update cache
	j.cache.jwks = jwks
	j.cache.expiresAt = time.Now().Add(j.cache.ttl)

	j.logger.Debug("JWKS generated and cached successfully")
	return jwks, nil
}

// rsaPublicKeyToJWKS converts an RSA public key to JWKS format
func (j *JWTManager) rsaPublicKeyToJWKS(pubKey *rsa.PublicKey) (*JWKS, error) {
	// Convert integers to base64url encoding
	nBytes := pubKey.N.Bytes()
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()

	n := base64.RawURLEncoding.EncodeToString(nBytes)
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: j.config.KeyID,
		Alg: j.config.Algorithm,
		N:   n,
		E:   e,
	}

	return &JWKS{
		Keys: []JWK{jwk},
	}, nil
}

// ServeJWKS handles the /.well-known/jwks.json endpoint
func (j *JWTManager) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := j.GetJWKS()
	if err != nil {
		j.logger.Error("Failed to generate JWKS", zap.Error(err))

		// Return structured error response
		errorResp := map[string]interface{}{
			"error":   "JWT public key not available",
			"message": "JWT authentication is not configured. Please run 'make generate-jwt-keys' to set up JWT authentication.",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(errorResp)
		return
	}

	// Set caching headers (1 hour cache)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		j.logger.Error("Failed to encode JWKS response", zap.Error(err))
		return
	}

	j.logger.Debug("JWKS served successfully")
}

// HealthCheck returns the health status of the JWT manager
func (j *JWTManager) HealthCheck() map[string]interface{} {
	health := map[string]interface{}{
		"component": "jwt_manager",
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	// Check if public key is loaded
	if j.publicKey == nil {
		if err := j.LoadPublicKey(); err != nil {
			health["status"] = "unhealthy"
			health["error"] = "public key not available"
			health["message"] = err.Error()
			return health
		}
	}

	// Check if JWKS can be generated
	_, err := j.GetJWKS()
	if err != nil {
		health["status"] = "unhealthy"
		health["error"] = "jwks generation failed"
		health["message"] = err.Error()
		return health
	}

	health["public_key_loaded"] = true
	health["jwks_cache_valid"] = time.Now().Before(j.cache.expiresAt)

	return health
}