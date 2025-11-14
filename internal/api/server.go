package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/auth"
	"github.com/codeready/go-tarsy-bot/internal/monitoring"
	"github.com/codeready/go-tarsy-bot/internal/pipeline"
	"github.com/codeready/go-tarsy-bot/internal/services"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// ServerConfig contains configuration for the HTTP server
type ServerConfig struct {
	Host           string        `json:"host"`
	Port           int           `json:"port"`
	ReadTimeout    time.Duration `json:"read_timeout"`
	WriteTimeout   time.Duration `json:"write_timeout"`
	IdleTimeout    time.Duration `json:"idle_timeout"`
	RequestTimeout time.Duration `json:"request_timeout"`
	EnableCORS     bool          `json:"enable_cors"`
	EnableLogging  bool          `json:"enable_logging"`
}

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Host:           "0.0.0.0",
		Port:           8080,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		RequestTimeout: 30 * time.Second,
		EnableCORS:     true,
		EnableLogging:  true,
	}
}

// APIServer wraps the HTTP server with proper lifecycle management
type APIServer struct {
	server           *http.Server
	config           *ServerConfig
	logger           *zap.Logger
	agentRegistry    *agents.AgentRegistry
	mcpRegistry      *mcp.MCPServerRegistry
	pipeline         *pipeline.ProcessingPipeline
	healthChecker     *monitoring.HealthChecker
	metricsCollector  *monitoring.MetricsCollector
	wsManager         *services.WebSocketManager
	historyService    *services.HistoryService
	dashboardService  *services.DashboardUpdateService
}

// NewAPIServer creates a new API server instance
func NewAPIServer(
	config *ServerConfig,
	logger *zap.Logger,
	agentRegistry *agents.AgentRegistry,
	mcpRegistry *mcp.MCPServerRegistry,
	pipeline *pipeline.ProcessingPipeline,
	healthChecker *monitoring.HealthChecker,
	metricsCollector *monitoring.MetricsCollector,
	wsManager *services.WebSocketManager,
	historyService *services.HistoryService,
) *APIServer {
	if config == nil {
		config = DefaultServerConfig()
	}

	server := &APIServer{
		config:           config,
		logger:           logger,
		agentRegistry:    agentRegistry,
		mcpRegistry:      mcpRegistry,
		pipeline:         pipeline,
		healthChecker:    healthChecker,
		metricsCollector: metricsCollector,
		wsManager:        wsManager,
		historyService:   historyService,
	}

	// Create dashboard update service if WebSocket manager is available
	if wsManager != nil {
		dashboardConfig := services.DefaultDashboardUpdateConfig()
		// Override with environment-specific settings if available
		server.dashboardService = services.NewDashboardUpdateService(
			wsManager,
			metricsCollector,
			pipeline,
			logger.With(zap.String("component", "dashboard_service")),
			dashboardConfig,
		)
	}

	return server
}

// Start starts the HTTP server
func (s *APIServer) Start(ctx context.Context) error {
	// Setup router
	routerConfig := &RouterConfig{
		RequestTimeout: s.config.RequestTimeout,
		EnableCORS:     s.config.EnableCORS,
		EnableLogging:  s.config.EnableLogging,
	}

	// Initialize optional authentication components
	var jwtManager *auth.JWTManager
	var inputSanitizer *auth.InputSanitizer
	var authMiddleware *auth.AuthMiddleware

	// For now, these are optional - can be enabled via configuration later
	// jwtManager = auth.NewJWTManager(auth.DefaultJWTConfig(), s.logger)
	// inputSanitizer, _ = auth.NewInputSanitizer(auth.DefaultSanitizationConfig(), s.logger)
	// authMiddleware = auth.NewAuthMiddleware(jwtManager, s.logger, true) // Optional auth

	router := SetupRouter(
		s.agentRegistry,
		s.mcpRegistry,
		s.pipeline,
		s.healthChecker,
		s.metricsCollector,
		s.wsManager,
		jwtManager,
		inputSanitizer,
		authMiddleware,
		s.historyService,
		s.logger,
		routerConfig,
	)

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	s.logger.Info("Starting API server",
		zap.String("address", addr),
		zap.Duration("read_timeout", s.config.ReadTimeout),
		zap.Duration("write_timeout", s.config.WriteTimeout))

	// Start dashboard update service
	if s.dashboardService != nil {
		if err := s.dashboardService.Start(); err != nil {
			s.logger.Error("Failed to start dashboard service", zap.Error(err))
			// Continue anyway - dashboard service is optional
		}
	}

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("failed to start HTTP server: %w", err)
		}
	}()

	// Wait for context cancellation or startup error
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return s.Stop()
	case <-time.After(100 * time.Millisecond):
		// Give server time to start
		s.logger.Info("API server started successfully", zap.String("address", addr))
		return nil
	}
}

// Stop gracefully stops the HTTP server
func (s *APIServer) Stop() error {
	if s.server == nil {
		return nil
	}

	s.logger.Info("Stopping API server")

	// Stop dashboard service first
	if s.dashboardService != nil {
		if err := s.dashboardService.Stop(); err != nil {
			s.logger.Error("Failed to stop dashboard service", zap.Error(err))
		}
	}

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.Error("Failed to gracefully shutdown server", zap.Error(err))
		return err
	}

	s.logger.Info("API server stopped successfully")
	return nil
}

// GetAddress returns the server address
func (s *APIServer) GetAddress() string {
	if s.server != nil {
		return s.server.Addr
	}
	return fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
}

// IsRunning returns true if the server is running
func (s *APIServer) IsRunning() bool {
	return s.server != nil
}

// GetConfig returns the server configuration
func (s *APIServer) GetConfig() *ServerConfig {
	return s.config
}

// HealthCheck performs a simple health check on the server
func (s *APIServer) HealthCheck() error {
	if !s.IsRunning() {
		return fmt.Errorf("server is not running")
	}

	// Try to make a request to the health endpoint
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	url := fmt.Sprintf("http://%s/health", s.GetAddress())
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("health check returned status: %d", resp.StatusCode)
	}

	return nil
}

// GetMetrics returns server-specific metrics
func (s *APIServer) GetMetrics() map[string]interface{} {
	metrics := map[string]interface{}{
		"server_running": s.IsRunning(),
		"server_address": s.GetAddress(),
		"config":         s.config,
	}

	if s.IsRunning() {
		metrics["uptime"] = time.Since(time.Now()) // This would need to be tracked properly
	}

	return metrics
}

// Middleware for rate limiting (placeholder for future implementation)
func (s *APIServer) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement rate limiting
		// For now, just pass through
		next.ServeHTTP(w, r)
	})
}

// Middleware for authentication (placeholder for future implementation)
func (s *APIServer) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement authentication
		// For now, just pass through
		next.ServeHTTP(w, r)
	})
}

// SetupMiddleware adds additional middleware to the server
func (s *APIServer) SetupMiddleware(router http.Handler) http.Handler {
	// Chain middleware
	handler := router

	// Add rate limiting (when implemented)
	handler = s.RateLimitMiddleware(handler)

	// Add authentication (when implemented)
	handler = s.AuthMiddleware(handler)

	return handler
}