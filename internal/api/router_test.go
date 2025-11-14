package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/monitoring"
	"github.com/codeready/go-tarsy-bot/internal/pipeline"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

func setupTestRouter(t *testing.T) http.Handler {
	logger := zaptest.NewLogger(t)

	// Setup dependencies
	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)

	mockConfigLoader := &config.AgentConfigLoader{}
	agentRegistry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	pipelineConfig := pipeline.DefaultPipelineConfig()
	testPipeline := pipeline.NewProcessingPipeline(agentRegistry, mcpRegistry, logger, pipelineConfig)

	healthConfig := monitoring.DefaultHealthCheckConfig()
	healthConfig.Enabled = false
	healthChecker := monitoring.NewHealthChecker(logger, healthConfig, agentRegistry, mcpRegistry)

	metricsCollector := monitoring.NewMetricsCollector()

	routerConfig := DefaultRouterConfig()
	return SetupRouter(agentRegistry, mcpRegistry, testPipeline, healthChecker, metricsCollector, logger, routerConfig)
}

func TestRouterSetup(t *testing.T) {
	router := setupTestRouter(t)
	assert.NotNil(t, router)
}

func TestAPIRoutes(t *testing.T) {
	router := setupTestRouter(t)

	testCases := []struct {
		method   string
		path     string
		expected int
	}{
		// API v1 routes
		{"GET", "/api/v1/health", http.StatusServiceUnavailable}, // Health checker disabled in test
		{"GET", "/api/v1/health/live", http.StatusOK},
		{"GET", "/api/v1/health/ready", http.StatusServiceUnavailable}, // Pipeline not started
		{"GET", "/api/v1/metrics", http.StatusOK},
		{"GET", "/api/v1/agents", http.StatusOK},
		{"GET", "/api/v1/pipeline/status", http.StatusOK},
		{"GET", "/api/v1/mcp/servers", http.StatusOK},

		// Root routes
		{"GET", "/health", http.StatusOK},
		{"GET", "/", http.StatusOK}, // API documentation

		// Non-existent routes
		{"GET", "/api/v1/nonexistent", http.StatusNotFound},
		{"GET", "/nonexistent", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.method+"_"+tc.path, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			assert.Equal(t, tc.expected, recorder.Code,
				"Expected status %d for %s %s, got %d",
				tc.expected, tc.method, tc.path, recorder.Code)
		})
	}
}

func TestAPIDocumentation(t *testing.T) {
	router := setupTestRouter(t)

	request := httptest.NewRequest("GET", "/", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "text/html; charset=utf-8", recorder.Header().Get("Content-Type"))
	assert.Contains(t, recorder.Body.String(), "TARSy-bot Go API Documentation")
	assert.Contains(t, recorder.Body.String(), "/api/v1")
}

func TestCORSHandling(t *testing.T) {
	router := setupTestRouter(t)

	t.Run("CORSHeaders", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/api/v1/health/live", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		assert.Equal(t, "*", recorder.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, PUT, DELETE, OPTIONS", recorder.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type, Authorization", recorder.Header().Get("Access-Control-Allow-Headers"))
	})

	t.Run("OptionsRequest", func(t *testing.T) {
		request := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}

func TestRouterConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultRouterConfig()
		assert.NotNil(t, config)
		assert.True(t, config.EnableCORS)
		assert.True(t, config.EnableLogging)
		assert.Greater(t, config.RequestTimeout.Seconds(), 0.0)
	})

	t.Run("CustomConfig", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		mcpConfig := &mcp.ServerRegistryConfig{}
		mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)

		mockConfigLoader := &config.AgentConfigLoader{}
		agentRegistry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

		pipelineConfig := pipeline.DefaultPipelineConfig()
		testPipeline := pipeline.NewProcessingPipeline(agentRegistry, mcpRegistry, logger, pipelineConfig)

		healthConfig := monitoring.DefaultHealthCheckConfig()
		healthConfig.Enabled = false
		healthChecker := monitoring.NewHealthChecker(logger, healthConfig, agentRegistry, mcpRegistry)

		metricsCollector := monitoring.NewMetricsCollector()

		customConfig := &RouterConfig{
			EnableCORS:    false,
			EnableLogging: false,
		}

		router := SetupRouter(agentRegistry, mcpRegistry, testPipeline, healthChecker, metricsCollector, logger, customConfig)
		assert.NotNil(t, router)

		// Test that CORS is disabled
		request := httptest.NewRequest("GET", "/api/v1/health/live", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		// With CORS disabled, these headers should not be set
		assert.Empty(t, recorder.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestParameterizedRoutes(t *testing.T) {
	router := setupTestRouter(t)

	t.Run("AlertStatus", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/api/v1/alerts/test-job-id/status", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		// Should find the route and return 404 for non-existent job
		assert.Equal(t, http.StatusNotFound, recorder.Code)
	})

	t.Run("ComponentHealth", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/api/v1/health/components/test-component", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		// Should find the route but health checker is disabled
		assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	})
}

func TestHTTPMethods(t *testing.T) {
	router := setupTestRouter(t)

	t.Run("POSTAlerts", func(t *testing.T) {
		request := httptest.NewRequest("POST", "/api/v1/alerts", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		// Should find the route (will fail due to invalid body, but route exists)
		assert.NotEqual(t, http.StatusNotFound, recorder.Code)
	})

	t.Run("InvalidMethod", func(t *testing.T) {
		request := httptest.NewRequest("DELETE", "/api/v1/alerts", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		// Method not allowed
		assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
	})
}

func TestContentTypeHeaders(t *testing.T) {
	router := setupTestRouter(t)

	endpoints := []string{
		"/api/v1/health/live",
		"/api/v1/metrics",
		"/api/v1/agents",
		"/api/v1/pipeline/status",
		"/api/v1/mcp/servers",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			request := httptest.NewRequest("GET", endpoint, nil)
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			contentType := recorder.Header().Get("Content-Type")
			assert.Equal(t, "application/json", contentType,
				"Expected JSON content type for %s", endpoint)
		})
	}
}

func TestAPIVersioning(t *testing.T) {
	router := setupTestRouter(t)

	t.Run("V1Endpoints", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/api/v1/health/live", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})

	t.Run("NoVersionEndpoints", func(t *testing.T) {
		// Root health endpoint should work without versioning
		request := httptest.NewRequest("GET", "/health", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})

	t.Run("InvalidVersion", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/api/v2/health", nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusNotFound, recorder.Code)
	})
}