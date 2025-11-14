package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/codeready/go-tarsy-bot/internal/agents"
	"github.com/codeready/go-tarsy-bot/internal/config"
	"github.com/codeready/go-tarsy-bot/internal/monitoring"
	"github.com/codeready/go-tarsy-bot/internal/pipeline"
	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

func setupTestHandlers(t *testing.T) *APIHandlers {
	logger := zaptest.NewLogger(t)

	// Setup dependencies
	mcpConfig := &mcp.ServerRegistryConfig{}
	mcpRegistry := mcp.NewMCPServerRegistry(logger, mcpConfig)

	mockConfigLoader := &config.AgentConfigLoader{}
	agentRegistry := agents.NewAgentRegistry(logger, mockConfigLoader, mcpRegistry)

	// Register a test agent
	settings := agents.DefaultAgentSettings()
	agent := agents.NewBaseAgent("test-agent", []string{"testing"}, settings)
	agentRegistry.RegisterHardcodedAgent("test", agent, []string{"test-alert"})

	pipelineConfig := pipeline.DefaultPipelineConfig()
	testPipeline := pipeline.NewProcessingPipeline(agentRegistry, mcpRegistry, logger, pipelineConfig)

	healthConfig := monitoring.DefaultHealthCheckConfig()
	healthConfig.Enabled = false // Disable for testing
	healthChecker := monitoring.NewHealthChecker(logger, healthConfig, agentRegistry, mcpRegistry)

	metricsCollector := monitoring.NewMetricsCollector()

	return NewAPIHandlers(agentRegistry, mcpRegistry, testPipeline, healthChecker, metricsCollector, logger)
}

func TestProcessAlert(t *testing.T) {
	handlers := setupTestHandlers(t)

	t.Run("ValidAlert", func(t *testing.T) {
		req := AlertRequest{
			AlertType: "test-alert",
			Data: map[string]interface{}{
				"message":  "Test alert message",
				"severity": "medium",
			},
			Runbook: "https://github.com/example/runbook.md",
		}

		body, _ := json.Marshal(req)
		request := httptest.NewRequest("POST", "/alerts", bytes.NewBuffer(body))
		request.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		handlers.ProcessAlert(recorder, request)

		assert.Equal(t, http.StatusAccepted, recorder.Code)

		var response AlertResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "submitted", response.Status)
		assert.NotEmpty(t, response.AlertID)
		assert.NotEmpty(t, response.SessionID)
		assert.Equal(t, "test-agent", response.Agent)
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		request := httptest.NewRequest("POST", "/alerts", bytes.NewBufferString("invalid json"))
		request.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		handlers.ProcessAlert(recorder, request)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)

		var response ErrorResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "INVALID_REQUEST", response.Code)
	})

	t.Run("MissingAlertType", func(t *testing.T) {
		req := AlertRequest{
			Data: map[string]interface{}{"test": "data"},
		}

		body, _ := json.Marshal(req)
		request := httptest.NewRequest("POST", "/alerts", bytes.NewBuffer(body))
		request.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		handlers.ProcessAlert(recorder, request)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)

		var response ErrorResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "MISSING_ALERT_TYPE", response.Code)
	})

	t.Run("MissingData", func(t *testing.T) {
		req := AlertRequest{
			AlertType: "test-alert",
		}

		body, _ := json.Marshal(req)
		request := httptest.NewRequest("POST", "/alerts", bytes.NewBuffer(body))
		request.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		handlers.ProcessAlert(recorder, request)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)

		var response ErrorResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "MISSING_DATA", response.Code)
	})
}

func TestGetAlertStatus(t *testing.T) {
	handlers := setupTestHandlers(t)

	t.Run("NonExistentJob", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/alerts/non-existent/status", nil)
		request = mux.SetURLVars(request, map[string]string{"jobId": "non-existent"})

		recorder := httptest.NewRecorder()
		handlers.GetAlertStatus(recorder, request)

		assert.Equal(t, http.StatusNotFound, recorder.Code)

		var response ErrorResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "JOB_NOT_FOUND", response.Code)
	})

	t.Run("MissingJobID", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/alerts//status", nil)
		request = mux.SetURLVars(request, map[string]string{"jobId": ""})

		recorder := httptest.NewRecorder()
		handlers.GetAlertStatus(recorder, request)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)

		var response ErrorResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "MISSING_JOB_ID", response.Code)
	})
}

func TestGetHealth(t *testing.T) {
	handlers := setupTestHandlers(t)

	t.Run("HealthAvailable", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/health", nil)
		recorder := httptest.NewRecorder()

		handlers.GetHealth(recorder, request)

		assert.Equal(t, http.StatusServiceUnavailable, recorder.Code) // Health checker is nil in test setup

		var response ErrorResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "HEALTH_UNAVAILABLE", response.Code)
	})
}

func TestGetHealthLive(t *testing.T) {
	handlers := setupTestHandlers(t)

	request := httptest.NewRequest("GET", "/health/live", nil)
	recorder := httptest.NewRecorder()

	handlers.GetHealthLive(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var response map[string]interface{}
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "ok", response["status"])
	assert.NotNil(t, response["timestamp"])
}

func TestGetHealthReady(t *testing.T) {
	handlers := setupTestHandlers(t)

	request := httptest.NewRequest("GET", "/health/ready", nil)
	recorder := httptest.NewRecorder()

	handlers.GetHealthReady(recorder, request)

	// Should be unavailable because pipeline is not started
	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)

	var response map[string]interface{}
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	status := response["status"].(map[string]interface{})
	assert.False(t, status["ready"].(bool))
}

func TestGetMetrics(t *testing.T) {
	handlers := setupTestHandlers(t)

	request := httptest.NewRequest("GET", "/metrics", nil)
	recorder := httptest.NewRecorder()

	handlers.GetMetrics(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var response MetricsResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotNil(t, response.System)
	assert.NotZero(t, response.Timestamp)
}

func TestListAgents(t *testing.T) {
	handlers := setupTestHandlers(t)

	request := httptest.NewRequest("GET", "/agents", nil)
	recorder := httptest.NewRecorder()

	handlers.ListAgents(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var response map[string]interface{}
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotNil(t, response["agents"])
	assert.NotNil(t, response["available_alert_types"])
	assert.NotNil(t, response["health_status"])
}

func TestGetPipelineStatus(t *testing.T) {
	handlers := setupTestHandlers(t)

	request := httptest.NewRequest("GET", "/pipeline/status", nil)
	recorder := httptest.NewRecorder()

	handlers.GetPipelineStatus(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var response map[string]interface{}
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotNil(t, response["status"])
	assert.NotNil(t, response["metrics"])
	assert.NotNil(t, response["timestamp"])
}

func TestListMCPServers(t *testing.T) {
	handlers := setupTestHandlers(t)

	request := httptest.NewRequest("GET", "/mcp/servers", nil)
	recorder := httptest.NewRecorder()

	handlers.ListMCPServers(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)

	var response map[string]interface{}
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotNil(t, response["servers"])
	assert.NotNil(t, response["timestamp"])
}

func TestGetComponentHealth(t *testing.T) {
	handlers := setupTestHandlers(t)

	t.Run("MissingComponentID", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/health/components/", nil)
		request = mux.SetURLVars(request, map[string]string{"componentId": ""})

		recorder := httptest.NewRecorder()
		handlers.GetComponentHealth(recorder, request)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)

		var response ErrorResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "MISSING_COMPONENT_ID", response.Code)
	})

	t.Run("HealthUnavailable", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/health/components/test", nil)
		request = mux.SetURLVars(request, map[string]string{"componentId": "test"})

		recorder := httptest.NewRecorder()
		handlers.GetComponentHealth(recorder, request)

		assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)

		var response ErrorResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "HEALTH_UNAVAILABLE", response.Code)
	})
}

func TestMiddleware(t *testing.T) {
	handlers := setupTestHandlers(t)

	t.Run("CORSMiddleware", func(t *testing.T) {
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		request := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		handlers.CORSMiddleware(nextHandler).ServeHTTP(recorder, request)

		assert.Equal(t, "*", recorder.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, PUT, DELETE, OPTIONS", recorder.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type, Authorization", recorder.Header().Get("Access-Control-Allow-Headers"))
	})

	t.Run("CORSPreflight", func(t *testing.T) {
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		request := httptest.NewRequest("OPTIONS", "/test", nil)
		recorder := httptest.NewRecorder()

		handlers.CORSMiddleware(nextHandler).ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})

	t.Run("TimeoutMiddleware", func(t *testing.T) {
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check that context has timeout
			_, hasDeadline := r.Context().Deadline()
			assert.True(t, hasDeadline)
			w.WriteHeader(http.StatusOK)
		})

		request := httptest.NewRequest("GET", "/test", nil)
		recorder := httptest.NewRecorder()

		handlers.TimeoutMiddleware(1*time.Second)(nextHandler).ServeHTTP(recorder, request)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}

func TestErrorHandling(t *testing.T) {
	handlers := setupTestHandlers(t)

	recorder := httptest.NewRecorder()

	handlers.sendError(recorder, http.StatusBadRequest, "TEST_ERROR", "Test error message", map[string]interface{}{
		"test_detail": "detail_value",
	})

	assert.Equal(t, http.StatusBadRequest, recorder.Code)

	var response ErrorResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Test error message", response.Error)
	assert.Equal(t, "TEST_ERROR", response.Code)
	assert.Equal(t, "detail_value", response.Details["test_detail"])
}

func TestValidatePaginationParams(t *testing.T) {
	handlers := setupTestHandlers(t)

	t.Run("DefaultValues", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/test", nil)
		offset, limit, err := handlers.validatePaginationParams(request)

		require.NoError(t, err)
		assert.Equal(t, 0, offset)
		assert.Equal(t, 50, limit)
	})

	t.Run("ValidParams", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/test?offset=10&limit=25", nil)
		offset, limit, err := handlers.validatePaginationParams(request)

		require.NoError(t, err)
		assert.Equal(t, 10, offset)
		assert.Equal(t, 25, limit)
	})

	t.Run("InvalidOffset", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/test?offset=invalid", nil)
		_, _, err := handlers.validatePaginationParams(request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid offset")
	})

	t.Run("InvalidLimit", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/test?limit=0", nil)
		_, _, err := handlers.validatePaginationParams(request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid limit")
	})

	t.Run("LimitTooHigh", func(t *testing.T) {
		request := httptest.NewRequest("GET", "/test?limit=2000", nil)
		_, _, err := handlers.validatePaginationParams(request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid limit")
	})
}

func TestResponseWrapper(t *testing.T) {
	recorder := httptest.NewRecorder()
	wrapper := &responseWrapper{ResponseWriter: recorder, statusCode: http.StatusOK}

	wrapper.WriteHeader(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, wrapper.statusCode)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestPriorityMapping(t *testing.T) {
	handlers := setupTestHandlers(t)

	// Test basic alert submission without priority (matches Python TARSy)
	req := AlertRequest{
		AlertType: "test-alert",
		Data:      map[string]interface{}{"test": "data"},
		Runbook:   "https://github.com/example/runbook.md",
	}

	body, _ := json.Marshal(req)
	request := httptest.NewRequest("POST", "/alerts", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	handlers.ProcessAlert(recorder, request)

	// Should accept the request
	assert.Equal(t, http.StatusAccepted, recorder.Code)
}