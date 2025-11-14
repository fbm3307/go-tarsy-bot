package api

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/auth"
	"github.com/codeready/go-tarsy-bot/internal/monitoring"
	"github.com/codeready/go-tarsy-bot/internal/pipeline"
	"github.com/codeready/go-tarsy-bot/internal/services"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// RouterConfig contains configuration for the API router
type RouterConfig struct {
	RequestTimeout time.Duration `json:"request_timeout"`
	EnableCORS     bool          `json:"enable_cors"`
	EnableLogging  bool          `json:"enable_logging"`
}

// DefaultRouterConfig returns default router configuration
func DefaultRouterConfig() *RouterConfig {
	return &RouterConfig{
		RequestTimeout: 30 * time.Second,
		EnableCORS:     true,
		EnableLogging:  true,
	}
}

// SetupRouter creates and configures the HTTP router with all API endpoints
func SetupRouter(
	agentRegistry *agents.AgentRegistry,
	mcpRegistry *mcp.MCPServerRegistry,
	pipeline *pipeline.ProcessingPipeline,
	healthChecker *monitoring.HealthChecker,
	metricsCollector *monitoring.MetricsCollector,
	wsManager *services.WebSocketManager,
	jwtManager *auth.JWTManager,
	inputSanitizer *auth.InputSanitizer,
	authMiddleware *auth.AuthMiddleware,
	historyService *services.HistoryService,
	logger *zap.Logger,
	config *RouterConfig,
) *mux.Router {
	if config == nil {
		config = DefaultRouterConfig()
	}

	// Create dashboard WebSocket integration
	dashboardIntegration := services.NewDashboardWebSocketIntegration(wsManager, historyService, logger)

	// Create handlers
	handlers := NewAPIHandlers(
		agentRegistry,
		mcpRegistry,
		pipeline,
		healthChecker,
		metricsCollector,
		wsManager,
		jwtManager,
		inputSanitizer,
		historyService,
		logger,
	)

	// Create WebSocket handlers
	wsHandlers := NewWebSocketHandlers(wsManager, dashboardIntegration, logger)

	// Create router
	r := mux.NewRouter()

	// Apply middleware
	if config.EnableLogging {
		r.Use(handlers.LoggingMiddleware)
	}

	if config.EnableCORS {
		r.Use(handlers.CORSMiddleware)
	}

	// Add input sanitization middleware
	if inputSanitizer != nil {
		r.Use(inputSanitizer.PayloadSizeMiddleware)
		r.Use(inputSanitizer.SanitizeRequestMiddleware)
	}

	r.Use(handlers.TimeoutMiddleware(config.RequestTimeout))

	// Public endpoints (no authentication required)
	// JWT/JWKS endpoint for OAuth2 proxy integration
	r.HandleFunc("/.well-known/jwks.json", handlers.GetJWKS).Methods("GET")

	// Health check endpoints (no prefix, matches Python)
	r.HandleFunc("/health", handlers.GetHealth).Methods("GET")

	// Root endpoint - simple status like Python version
	r.HandleFunc("/", handlers.GetRootStatus).Methods("GET")

	// API documentation endpoint
	r.HandleFunc("/docs", serveAPIDocumentation).Methods("GET")

	// API v1 endpoints (matches Python TARSy)
	api := r.PathPrefix("/api/v1").Subrouter()

	// Apply optional authentication to API routes
	if authMiddleware != nil {
		api.Use(authMiddleware.OptionalAuth())
	}

	// Alert processing endpoints
	api.HandleFunc("/alerts", handlers.ProcessAlert).Methods("POST")
	api.HandleFunc("/alerts", handlers.ListAlerts).Methods("GET")
	api.HandleFunc("/alerts/{alertId}", handlers.GetAlertStatus).Methods("GET")

	// Health endpoint under API v1 for dashboard compatibility
	api.HandleFunc("/health", handlers.GetHealth).Methods("GET")

	// Alert types endpoint (renamed from agent-types) - Dashboard compatible
	api.HandleFunc("/alert-types", handlers.GetAlertTypes).Methods("GET")

	// History Service endpoints - Dashboard compatible (/api/v1/history/*)
	historyAPI := api.PathPrefix("/history").Subrouter()
	historyAPI.HandleFunc("/sessions", handlers.GetHistorySessions).Methods("GET")
	historyAPI.HandleFunc("/sessions/{id}", handlers.GetHistorySessionDetail).Methods("GET")
	historyAPI.HandleFunc("/sessions/{id}/summary", handlers.GetHistorySessionSummary).Methods("GET")
	historyAPI.HandleFunc("/sessions/{id}/interactions", handlers.GetHistorySessionInteractions).Methods("GET")
	historyAPI.HandleFunc("/active-sessions", handlers.GetHistoryActiveSessions).Methods("GET")
	historyAPI.HandleFunc("/search", handlers.GetHistorySearch).Methods("GET")
	historyAPI.HandleFunc("/filter-options", handlers.GetHistoryFilterOptions).Methods("GET")
	historyAPI.HandleFunc("/health", handlers.GetHistoryHealth).Methods("GET")

	// Session management endpoints (for alert-to-session mapping)
	api.HandleFunc("/session-id/{alertId}", handlers.GetSessionIDForAlert).Methods("GET")

	// Agent management endpoints
	api.HandleFunc("/agents", handlers.ListAgents).Methods("GET")

	// User information endpoint (requires authentication)
	api.HandleFunc("/user", handlers.GetUser).Methods("GET")

	// WebSocket endpoints - Dashboard compatible
	r.HandleFunc("/ws/{alertId}", wsHandlers.HandleAlertWebSocket).Methods("GET")
	r.HandleFunc("/ws/dashboard/{userId}", wsHandlers.HandleDashboardWebSocket).Methods("GET")
	r.HandleFunc("/ws/session/{sessionId}", wsHandlers.HandleSessionWebSocket).Methods("GET")

	// System endpoints
	r.HandleFunc("/metrics", handlers.GetMetrics).Methods("GET")
	r.HandleFunc("/config/validate", handlers.ValidateConfiguration).Methods("GET")

	return r
}

// serveAPIDocumentation serves basic API documentation
func serveAPIDocumentation(w http.ResponseWriter, r *http.Request) {
	documentation := `
<!DOCTYPE html>
<html>
<head>
    <title>TARSy-bot Go API Documentation</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1, h2 { color: #333; }
        code { background-color: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
        .endpoint { margin: 20px 0; padding: 15px; border-left: 4px solid #007cba; background-color: #f9f9f9; }
        .method { font-weight: bold; color: #007cba; }
        .path { font-family: monospace; }
    </style>
</head>
<body>
    <h1>TARSy-bot Go API Documentation</h1>
    <p>RESTful API for the TARSy-bot agent system written in Go.</p>

    <h2>Endpoints</h2>

    <div class="endpoint">
        <h3><span class="method">POST</span> <span class="path">/alerts</span></h3>
        <p>Submit an alert for processing by the agent system.</p>
        <p><strong>Request Body:</strong></p>
        <code>
        {
            "alert_type": "string",
            "data": {},
            "runbook": "string",
            "session_id": "string"
        }
        </code>
        <p><strong>Response:</strong></p>
        <code>
        {
            "alert_id": "string",
            "status": "submitted",
            "message": "string",
            "session_id": "string",
            "agent": "string",
            "timestamp": "ISO8601"
        }
        </code>
    </div>

    <div class="endpoint">
        <h3><span class="method">GET</span> <span class="path">/alerts/{alertId}</span></h3>
        <p>Get the processing status and results of a specific alert.</p>
    </div>

    <div class="endpoint">
        <h3><span class="method">GET</span> <span class="path">/health</span></h3>
        <p>Get comprehensive health status of all system components.</p>
    </div>

    <div class="endpoint">
        <h3><span class="method">GET</span> <span class="path">/agents</span></h3>
        <p>List all registered agents and their capabilities.</p>
    </div>

    <div class="endpoint">
        <h3><span class="method">GET</span> <span class="path">/agent-types</span></h3>
        <p>Get available alert types that can be processed by the system.</p>
    </div>

    <div class="endpoint">
        <h3><span class="method">GET</span> <span class="path">/sessions</span></h3>
        <p>List processing sessions (history service).</p>
    </div>

    <div class="endpoint">
        <h3><span class="method">GET</span> <span class="path">/sessions/{sessionId}</span></h3>
        <p>Get detailed information about a specific processing session.</p>
    </div>

    <div class="endpoint">
        <h3><span class="method">GET</span> <span class="path">/metrics</span></h3>
        <p>Get system performance metrics and statistics.</p>
    </div>

    <div class="endpoint">
        <h3><span class="method">GET</span> <span class="path">/config/validate</span></h3>
        <p>Validate system configuration and return detailed validation results.</p>
    </div>

    <h2>WebSocket Endpoints</h2>

    <div class="endpoint">
        <h3><span class="method">WebSocket</span> <span class="path">/ws/{alertId}</span></h3>
        <p>Real-time updates for alert processing progress.</p>
    </div>

    <div class="endpoint">
        <h3><span class="method">WebSocket</span> <span class="path">/ws/dashboard/{userId}</span></h3>
        <p>Real-time dashboard updates for operational monitoring.</p>
    </div>

    <h2>Error Responses</h2>
    <p>All errors follow a consistent format:</p>
    <code>
    {
        "error": "Human readable error message",
        "code": "ERROR_CODE",
        "details": {}
    }
    </code>

    <h2>Status Codes</h2>
    <ul>
        <li><strong>200</strong> - Success</li>
        <li><strong>202</strong> - Accepted (for async operations)</li>
        <li><strong>206</strong> - Partial Content (degraded health)</li>
        <li><strong>400</strong> - Bad Request</li>
        <li><strong>404</strong> - Not Found</li>
        <li><strong>500</strong> - Internal Server Error</li>
        <li><strong>503</strong> - Service Unavailable</li>
    </ul>

    <h2>Authentication</h2>
    <p>Currently, no authentication is required. This may change in future versions.</p>

    <h2>Rate Limiting</h2>
    <p>No rate limiting is currently implemented.</p>

    <h2>Pagination</h2>
    <p>Some endpoints support pagination with <code>offset</code> and <code>limit</code> query parameters.</p>

    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; color: #666;">
        <p>TARSy-bot Go Implementation - Built with Go, Gorilla Mux</p>
    </footer>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(documentation))
}