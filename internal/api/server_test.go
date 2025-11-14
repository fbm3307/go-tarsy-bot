package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/monitoring"
	"github.com/codeready/go-tarsy-bot/internal/pipeline"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

func setupTestServer(t *testing.T) *APIServer {
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

	// Use a random available port for testing
	serverConfig := &ServerConfig{
		Host:           "127.0.0.1",
		Port:           0, // Let OS choose port
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    10 * time.Second,
		RequestTimeout: 5 * time.Second,
		EnableCORS:     true,
		EnableLogging:  false, // Disable logging for cleaner test output
	}

	return NewAPIServer(serverConfig, logger, agentRegistry, mcpRegistry, testPipeline, healthChecker, metricsCollector)
}

func TestServerConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultServerConfig()
		assert.NotNil(t, config)
		assert.Equal(t, "0.0.0.0", config.Host)
		assert.Equal(t, 8080, config.Port)
		assert.Greater(t, config.ReadTimeout.Seconds(), 0.0)
		assert.Greater(t, config.WriteTimeout.Seconds(), 0.0)
		assert.Greater(t, config.IdleTimeout.Seconds(), 0.0)
		assert.True(t, config.EnableCORS)
		assert.True(t, config.EnableLogging)
	})

	t.Run("CustomConfig", func(t *testing.T) {
		customConfig := &ServerConfig{
			Host:         "127.0.0.1",
			Port:         9090,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			EnableCORS:   false,
		}

		logger := zaptest.NewLogger(t)
		server := NewAPIServer(customConfig, logger, nil, nil, nil, nil, nil)

		assert.Equal(t, customConfig, server.GetConfig())
		assert.Equal(t, "127.0.0.1:9090", server.GetAddress())
	})

	t.Run("NilConfig", func(t *testing.T) {
		logger := zaptest.NewLogger(t)
		server := NewAPIServer(nil, logger, nil, nil, nil, nil, nil)

		config := server.GetConfig()
		assert.NotNil(t, config)
		assert.Equal(t, "0.0.0.0", config.Host)
		assert.Equal(t, 8080, config.Port)
	})
}

func TestServerLifecycle(t *testing.T) {
	server := setupTestServer(t)

	t.Run("InitialState", func(t *testing.T) {
		assert.False(t, server.IsRunning())
		assert.NotEmpty(t, server.GetAddress())
	})

	t.Run("StartServer", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := server.Start(ctx)
		require.NoError(t, err)

		assert.True(t, server.IsRunning())

		// Test that server is actually listening
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://%s/health", server.GetAddress()))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("StopServer", func(t *testing.T) {
		err := server.Stop()
		require.NoError(t, err)

		assert.False(t, server.IsRunning())

		// Test that server is no longer listening
		client := &http.Client{Timeout: 1 * time.Second}
		_, err = client.Get(fmt.Sprintf("http://%s/health", server.GetAddress()))
		assert.Error(t, err) // Should fail to connect
	})

	t.Run("StopAlreadyStopped", func(t *testing.T) {
		err := server.Stop()
		assert.NoError(t, err) // Should not error when stopping already stopped server
	})
}

func TestServerStartErrors(t *testing.T) {
	t.Run("ContextCancellation", func(t *testing.T) {
		server := setupTestServer(t)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := server.Start(ctx)
		assert.NoError(t, err) // Should handle cancellation gracefully
	})

	t.Run("InvalidPort", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		// Use an invalid port
		serverConfig := &ServerConfig{
			Host: "127.0.0.1",
			Port: -1,
		}

		server := NewAPIServer(serverConfig, logger, nil, nil, nil, nil, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		err := server.Start(ctx)
		assert.Error(t, err)
	})
}

func TestServerHealthCheck(t *testing.T) {
	server := setupTestServer(t)

	t.Run("ServerNotRunning", func(t *testing.T) {
		err := server.HealthCheck()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not running")
	})

	t.Run("ServerRunning", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := server.Start(ctx)
		require.NoError(t, err)
		defer server.Stop()

		err = server.HealthCheck()
		assert.NoError(t, err)
	})
}

func TestServerMetrics(t *testing.T) {
	server := setupTestServer(t)

	metrics := server.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Contains(t, metrics, "server_running")
	assert.Contains(t, metrics, "server_address")
	assert.Contains(t, metrics, "config")

	assert.False(t, metrics["server_running"].(bool))
	assert.NotEmpty(t, metrics["server_address"].(string))
}

func TestServerMiddleware(t *testing.T) {
	server := setupTestServer(t)

	t.Run("RateLimitMiddleware", func(t *testing.T) {
		// Test that middleware passes through (no rate limiting implemented yet)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := server.RateLimitMiddleware(handler)
		assert.NotNil(t, wrappedHandler)

		// Should pass through without modification
		req := &http.Request{}
		rw := &mockResponseWriter{}
		wrappedHandler.ServeHTTP(rw, req)
		assert.Equal(t, http.StatusOK, rw.statusCode)
	})

	t.Run("AuthMiddleware", func(t *testing.T) {
		// Test that middleware passes through (no auth implemented yet)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := server.AuthMiddleware(handler)
		assert.NotNil(t, wrappedHandler)

		// Should pass through without modification
		req := &http.Request{}
		rw := &mockResponseWriter{}
		wrappedHandler.ServeHTTP(rw, req)
		assert.Equal(t, http.StatusOK, rw.statusCode)
	})

	t.Run("SetupMiddleware", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := server.SetupMiddleware(handler)
		assert.NotNil(t, wrappedHandler)

		// Should wrap with middleware chain
		req := &http.Request{}
		rw := &mockResponseWriter{}
		wrappedHandler.ServeHTTP(rw, req)
		assert.Equal(t, http.StatusOK, rw.statusCode)
	})
}

func TestConcurrentServerOperations(t *testing.T) {
	server := setupTestServer(t)

	t.Run("ConcurrentStartStop", func(t *testing.T) {
		const numGoroutines = 10
		done := make(chan bool, numGoroutines*2)

		// Start multiple goroutines trying to start the server
		for i := 0; i < numGoroutines; i++ {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancel()
				server.Start(ctx)
				done <- true
			}()
		}

		// Start multiple goroutines trying to stop the server
		for i := 0; i < numGoroutines; i++ {
			go func() {
				server.Stop()
				done <- true
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines*2; i++ {
			<-done
		}

		// Server should be in a consistent state
		assert.NotPanics(t, func() {
			server.Stop() // Should not panic
		})
	})
}

func TestServerIntegration(t *testing.T) {
	server := setupTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := server.Start(ctx)
	require.NoError(t, err)
	defer server.Stop()

	baseURL := fmt.Sprintf("http://%s", server.GetAddress())
	client := &http.Client{Timeout: 2 * time.Second}

	// Test various endpoints
	endpoints := []struct {
		path           string
		expectedStatus int
	}{
		{"/health", http.StatusOK},
		{"/api/v1/health/live", http.StatusOK},
		{"/api/v1/health/ready", http.StatusServiceUnavailable},
		{"/api/v1/metrics", http.StatusOK},
		{"/api/v1/agents", http.StatusOK},
		{"/api/v1/pipeline/status", http.StatusOK},
		{"/", http.StatusOK}, // API documentation
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.path, func(t *testing.T) {
			resp, err := client.Get(baseURL + endpoint.path)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, endpoint.expectedStatus, resp.StatusCode,
				"Unexpected status for %s", endpoint.path)
		})
	}
}

// Mock ResponseWriter for testing middleware
type mockResponseWriter struct {
	statusCode int
	headers    http.Header
}

func (m *mockResponseWriter) Header() http.Header {
	if m.headers == nil {
		m.headers = make(http.Header)
	}
	return m.headers
}

func (m *mockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}