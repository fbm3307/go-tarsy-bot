package api

import (
	"net/http"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/services"
)

// WebSocketHandlers provides WebSocket endpoint handlers for the dashboard
type WebSocketHandlers struct {
	wsManager            *services.WebSocketManager
	dashboardIntegration *services.DashboardWebSocketIntegration
	logger               *zap.Logger
}

// NewWebSocketHandlers creates new WebSocket handlers
func NewWebSocketHandlers(wsManager *services.WebSocketManager, dashboardIntegration *services.DashboardWebSocketIntegration, logger *zap.Logger) *WebSocketHandlers {
	return &WebSocketHandlers{
		wsManager:            wsManager,
		dashboardIntegration: dashboardIntegration,
		logger:               logger,
	}
}

// HandleDashboardWebSocket handles WebSocket connections for the dashboard
// Endpoint: /ws/dashboard/{userId}
func (wsh *WebSocketHandlers) HandleDashboardWebSocket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]

	if userID == "" {
		wsh.logger.Warn("Missing userId in dashboard WebSocket request")
		http.Error(w, "Missing userId", http.StatusBadRequest)
		return
	}

	wsh.logger.Info("Dashboard WebSocket connection request",
		zap.String("user_id", userID),
		zap.String("remote_addr", r.RemoteAddr))

	// Use the WebSocket manager's HandleWebSocket method
	channel := wsh.dashboardIntegration.GetDashboardChannel()
	err := wsh.wsManager.HandleWebSocket(w, r, userID, channel)
	if err != nil {
		wsh.logger.Error("Failed to handle dashboard WebSocket connection", zap.Error(err))
		return
	}

	wsh.logger.Info("Dashboard WebSocket connection established",
		zap.String("user_id", userID),
		zap.String("channel", channel))
}

// HandleSessionWebSocket handles WebSocket connections for specific sessions
// Endpoint: /ws/session/{sessionId}
func (wsh *WebSocketHandlers) HandleSessionWebSocket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	if sessionID == "" {
		wsh.logger.Warn("Missing sessionId in session WebSocket request")
		http.Error(w, "Missing sessionId", http.StatusBadRequest)
		return
	}

	wsh.logger.Info("Session WebSocket connection request",
		zap.String("session_id", sessionID),
		zap.String("remote_addr", r.RemoteAddr))

	// Use the WebSocket manager's HandleWebSocket method
	channel := wsh.dashboardIntegration.GetSessionChannel(sessionID)
	// Use sessionID as userID for session-specific connections
	err := wsh.wsManager.HandleWebSocket(w, r, sessionID, channel)
	if err != nil {
		wsh.logger.Error("Failed to handle session WebSocket connection", zap.Error(err))
		return
	}

	wsh.logger.Info("Session WebSocket connection established",
		zap.String("session_id", sessionID),
		zap.String("channel", channel))
}

// HandleAlertWebSocket handles WebSocket connections for specific alerts (legacy endpoint)
// Endpoint: /ws/{alertId}
func (wsh *WebSocketHandlers) HandleAlertWebSocket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["alertId"]

	if alertID == "" {
		wsh.logger.Warn("Missing alertId in alert WebSocket request")
		http.Error(w, "Missing alertId", http.StatusBadRequest)
		return
	}

	wsh.logger.Info("Alert WebSocket connection request",
		zap.String("alert_id", alertID),
		zap.String("remote_addr", r.RemoteAddr))

	// For backward compatibility, treat alertId as sessionId
	// Use the session channel format
	channel := wsh.dashboardIntegration.GetSessionChannel(alertID)
	err := wsh.wsManager.HandleWebSocket(w, r, alertID, channel)
	if err != nil {
		wsh.logger.Error("Failed to handle alert WebSocket connection", zap.Error(err))
		return
	}

	wsh.logger.Info("Alert WebSocket connection established",
		zap.String("alert_id", alertID),
		zap.String("channel", channel))
}