package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// ContextKey is a type for context keys to avoid collisions
type ContextKey string

const (
	// UserContextKey is the context key for user information
	UserContextKey ContextKey = "user"
	// ClaimsContextKey is the context key for JWT claims
	ClaimsContextKey ContextKey = "claims"
)

// User represents authenticated user information
type User struct {
	ID       string                 `json:"id"`
	Email    string                 `json:"email"`
	Name     string                 `json:"name"`
	Groups   []string               `json:"groups"`
	Claims   map[string]interface{} `json:"claims"`
	IssuedAt time.Time              `json:"issued_at"`
}

// AuthMiddleware provides JWT authentication middleware
type AuthMiddleware struct {
	jwtManager *JWTManager
	publicKey  *rsa.PublicKey
	logger     *zap.Logger
	optional   bool // If true, authentication is optional
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(jwtManager *JWTManager, logger *zap.Logger, optional bool) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager: jwtManager,
		logger:     logger,
		optional:   optional,
	}
}

// Middleware returns the HTTP middleware function
func (a *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract JWT token from Authorization header
		token := a.extractToken(r)

		if token == "" {
			if a.optional {
				// Continue without authentication
				next.ServeHTTP(w, r)
				return
			}
			a.sendAuthError(w, "missing_token", "Authorization header is required", http.StatusUnauthorized)
			return
		}

		// Validate the token
		user, err := a.validateToken(token)
		if err != nil {
			if a.optional {
				// Log the error but continue without authentication
				a.logger.Debug("JWT validation failed (optional auth)", zap.Error(err))
				next.ServeHTTP(w, r)
				return
			}
			a.logger.Warn("JWT validation failed", zap.Error(err))
			a.sendAuthError(w, "invalid_token", fmt.Sprintf("Token validation failed: %s", err.Error()), http.StatusUnauthorized)
			return
		}

		// Add user to request context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, user.Claims)

		// Continue with authenticated request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractToken extracts JWT token from Authorization header
func (a *AuthMiddleware) extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// Check for Bearer token format
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Also check for simple token format (without Bearer prefix)
	return authHeader
}

// validateToken validates a JWT token and returns user information
func (a *AuthMiddleware) validateToken(tokenString string) (*User, error) {
	// Ensure public key is loaded
	if a.publicKey == nil {
		if a.jwtManager.publicKey == nil {
			if err := a.jwtManager.LoadPublicKey(); err != nil {
				return nil, fmt.Errorf("failed to load public key: %w", err)
			}
		}
		a.publicKey = a.jwtManager.publicKey
	}

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims")
	}

	// Create user from claims
	user, err := a.createUserFromClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to create user from claims: %w", err)
	}

	return user, nil
}

// createUserFromClaims creates a User object from JWT claims
func (a *AuthMiddleware) createUserFromClaims(claims jwt.MapClaims) (*User, error) {
	user := &User{
		Claims: make(map[string]interface{}),
	}

	// Copy all claims to user.Claims
	for key, value := range claims {
		user.Claims[key] = value
	}

	// Extract standard claims
	if sub, ok := claims["sub"].(string); ok {
		user.ID = sub
	}

	if email, ok := claims["email"].(string); ok {
		user.Email = email
	}

	if name, ok := claims["name"].(string); ok {
		user.Name = name
	}

	// Extract groups (may be in different claim names)
	if groups, ok := claims["groups"].([]interface{}); ok {
		user.Groups = make([]string, 0, len(groups))
		for _, group := range groups {
			if groupStr, ok := group.(string); ok {
				user.Groups = append(user.Groups, groupStr)
			}
		}
	} else if groups, ok := claims["roles"].([]interface{}); ok {
		user.Groups = make([]string, 0, len(groups))
		for _, role := range groups {
			if roleStr, ok := role.(string); ok {
				user.Groups = append(user.Groups, roleStr)
			}
		}
	}

	// Extract issued at time
	if iat, ok := claims["iat"].(float64); ok {
		user.IssuedAt = time.Unix(int64(iat), 0)
	}

	return user, nil
}

// sendAuthError sends an authentication error response
func (a *AuthMiddleware) sendAuthError(w http.ResponseWriter, code, message string, statusCode int) {
	errorResp := map[string]interface{}{
		"error":   message,
		"code":    code,
		"details": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResp)
}

// GetUserFromContext extracts user information from request context
func GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(UserContextKey).(*User)
	return user, ok
}

// GetClaimsFromContext extracts JWT claims from request context
func GetClaimsFromContext(ctx context.Context) (map[string]interface{}, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(map[string]interface{})
	return claims, ok
}

// RequireAuth creates a middleware that requires authentication
func (a *AuthMiddleware) RequireAuth() func(http.Handler) http.Handler {
	middleware := NewAuthMiddleware(a.jwtManager, a.logger, false)
	return middleware.Middleware
}

// OptionalAuth creates a middleware that allows optional authentication
func (a *AuthMiddleware) OptionalAuth() func(http.Handler) http.Handler {
	middleware := NewAuthMiddleware(a.jwtManager, a.logger, true)
	return middleware.Middleware
}

// CheckPermissions checks if user has required permissions
func CheckPermissions(user *User, requiredGroups []string) bool {
	if len(requiredGroups) == 0 {
		return true // No specific permissions required
	}

	userGroupMap := make(map[string]bool)
	for _, group := range user.Groups {
		userGroupMap[group] = true
	}

	// Check if user has any of the required groups
	for _, requiredGroup := range requiredGroups {
		if userGroupMap[requiredGroup] {
			return true
		}
	}

	return false
}

// RequirePermissions creates a middleware that requires specific permissions
func RequirePermissions(requiredGroups []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetUserFromContext(r.Context())
			if !ok {
				sendPermissionError(w, "unauthenticated", "Authentication required")
				return
			}

			if !CheckPermissions(user, requiredGroups) {
				sendPermissionError(w, "insufficient_permissions",
					fmt.Sprintf("Requires one of: %v", requiredGroups))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// sendPermissionError sends a permission error response
func sendPermissionError(w http.ResponseWriter, code, message string) {
	errorResp := map[string]interface{}{
		"error":   message,
		"code":    code,
		"details": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(errorResp)
}