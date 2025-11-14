package services

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/models"
)

// Configuration constants for bounded session message buffer (matching Python)
const (
	MaxMessagesPerSession   = 100               // Maximum messages to buffer per session
	MessageTTLSeconds      = 300               // 5 minutes TTL for buffered messages
	CleanupIntervalSeconds = 60                // Run cleanup every minute
)

// TimestampedMessage represents a message with timestamp for TTL management
type TimestampedMessage struct {
	Message   map[string]interface{} `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
}

// DashboardBroadcaster handles message broadcasting for dashboard clients
// Includes session message buffering to prevent lost messages during the timing gap
// between alert submission (starts background processing) and UI subscription to session channels.
type DashboardBroadcaster struct {
	connectionManager *WebSocketManager
	logger           *zap.Logger

	// Throttling (no message filtering, matching Python)
	throttleLimits      map[string]map[string]interface{}
	userMessageCounts   map[string]map[string][]time.Time

	// Bounded session message buffer with TTL: solves timing race condition where background processing
	// starts immediately after alert submission but UI needs time to connect and subscribe.
	// Without this buffer, early LLM/MCP interactions are lost because no one is subscribed yet.
	sessionMessageBuffer map[string][]*TimestampedMessage // session_channel -> []*TimestampedMessage
	bufferLock          sync.RWMutex

	// Cleanup management
	cleanupCancel context.CancelFunc
	cleanupDone   chan struct{}

	mu sync.RWMutex
}

// NewDashboardBroadcaster creates a new dashboard broadcaster
func NewDashboardBroadcaster(connectionManager *WebSocketManager, logger *zap.Logger) *DashboardBroadcaster {
	db := &DashboardBroadcaster{
		connectionManager:    connectionManager,
		logger:              logger,
		throttleLimits:      make(map[string]map[string]interface{}),
		userMessageCounts:   make(map[string]map[string][]time.Time),
		sessionMessageBuffer: make(map[string][]*TimestampedMessage),
		cleanupDone:         make(chan struct{}),
	}

	db.startCleanupTask()
	return db
}

// shouldThrottleUser checks if user should be throttled for this channel
func (db *DashboardBroadcaster) shouldThrottleUser(userID, channel string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	limits, exists := db.throttleLimits[channel]
	if !exists {
		return false
	}

	maxMessages, ok1 := limits["max_messages"].(int)
	timeWindow, ok2 := limits["time_window"].(time.Duration)
	if !ok1 || !ok2 {
		return false
	}

	if db.userMessageCounts[userID] == nil {
		db.userMessageCounts[userID] = make(map[string][]time.Time)
	}

	userMessages := db.userMessageCounts[userID][channel]
	cutoffTime := time.Now().Add(-timeWindow)

	// Clean old messages outside time window
	var validMessages []time.Time
	for _, msgTime := range userMessages {
		if msgTime.After(cutoffTime) {
			validMessages = append(validMessages, msgTime)
		}
	}
	db.userMessageCounts[userID][channel] = validMessages

	return len(validMessages) >= maxMessages
}

// recordUserMessage records that a message was sent to a user
func (db *DashboardBroadcaster) recordUserMessage(userID, channel string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.userMessageCounts[userID] == nil {
		db.userMessageCounts[userID] = make(map[string][]time.Time)
	}

	db.userMessageCounts[userID][channel] = append(
		db.userMessageCounts[userID][channel],
		time.Now(),
	)
}

// isSessionChannel checks if a channel is a session-specific channel
func isSessionChannel(channel string) bool {
	return len(channel) > len(models.WSChannelSessionPrefix) &&
		   channel[:len(models.WSChannelSessionPrefix)] == models.WSChannelSessionPrefix
}

// addMessageToBuffer adds a message to the session buffer
func (db *DashboardBroadcaster) addMessageToBuffer(channel string, message map[string]interface{}) {
	db.bufferLock.Lock()
	defer db.bufferLock.Unlock()

	// Create timestamped message
	timestampedMsg := &TimestampedMessage{
		Message:   message,
		Timestamp: time.Now(),
	}

	// Add to buffer with max size limit
	buffer := db.sessionMessageBuffer[channel]
	buffer = append(buffer, timestampedMsg)

	// Enforce max buffer size
	if len(buffer) > MaxMessagesPerSession {
		buffer = buffer[len(buffer)-MaxMessagesPerSession:]
	}

	db.sessionMessageBuffer[channel] = buffer

	db.logger.Debug("Added message to session buffer",
		zap.String("channel", channel),
		zap.Int("buffer_size", len(buffer)))
}

// getAndClearBuffer retrieves and clears all buffered messages for a channel
func (db *DashboardBroadcaster) getAndClearBuffer(channel string) []*TimestampedMessage {
	db.bufferLock.Lock()
	defer db.bufferLock.Unlock()

	buffer := db.sessionMessageBuffer[channel]
	delete(db.sessionMessageBuffer, channel)

	return buffer
}

// BroadcastMessage is the core broadcast method with filtering and throttling
func (db *DashboardBroadcaster) BroadcastMessage(channel string, message *models.WebSocketMessage, excludeUsers map[string]bool) (int, error) {
	if excludeUsers == nil {
		excludeUsers = make(map[string]bool)
	}

	// Get channel subscribers
	connectionIDs := db.connectionManager.GetConnectionsByChannel(channel)

	// CRITICAL: Handle session channel buffering if no subscribers
	//
	// Problem: Alert processing starts immediately in background, but UI takes time to:
	// 1. Get alert_id from /alerts response
	// 2. Connect to WebSocket
	// 3. Fetch session_id from /session-id/{alert_id}
	// 4. Subscribe to session_{session_id} channel
	//
	// Without buffering, early LLM/MCP interactions are dropped → user sees incomplete timeline
	// Solution: Buffer session messages until first subscriber, then flush all at once
	if len(connectionIDs) == 0 && isSessionChannel(channel) {
		messageMap := map[string]interface{}{
			"type":    message.Type,
			"channel": message.Channel,
			"data":    message.Data,
		}
		db.addMessageToBuffer(channel, messageMap)
		return 0, nil
	}

	if len(connectionIDs) == 0 {
		db.logger.Debug("No subscribers for channel", zap.String("channel", channel))
		return 0, nil
	}

	// FLUSH BUFFER: If there are subscribers and this is a session channel,
	// send any buffered messages first (in chronological order)
	sentCount := 0
	if isSessionChannel(channel) {
		bufferedMessages := db.getAndClearBuffer(channel)
		if len(bufferedMessages) > 0 {
			db.logger.Debug("First subscriber detected! Flushing buffered messages",
				zap.String("channel", channel),
				zap.Int("buffered_count", len(bufferedMessages)))

			// Send buffered messages directly to avoid recursion
			for _, bufferedMsg := range bufferedMessages {
				wsMsg := &models.WebSocketMessage{
					Type:    bufferedMsg.Message["type"].(string),
					Channel: channel,
					Data:    bufferedMsg.Message["data"],
				}

				err := db.connectionManager.BroadcastToChannel(channel, wsMsg)
				if err == nil {
					sentCount++
				}
			}
		}
	}

	// Send the current message
	err := db.connectionManager.BroadcastToChannel(channel, message)
	if err != nil {
		db.logger.Error("Failed to broadcast message",
			zap.String("channel", channel),
			zap.Error(err))
		return sentCount, err
	}

	sentCount++

	db.logger.Debug("Broadcast completed",
		zap.String("channel", channel),
		zap.Int("sent_count", sentCount))

	return sentCount, nil
}

// BroadcastDashboardUpdate broadcasts dashboard update
func (db *DashboardBroadcaster) BroadcastDashboardUpdate(data map[string]interface{}, excludeUsers map[string]bool) (int, error) {
	message := models.NewDashboardUpdateMessage("dashboard_update", data)
	return db.BroadcastMessage(models.WSChannelDashboardUpdates, message, excludeUsers)
}

// BroadcastSessionUpdate broadcasts session update
func (db *DashboardBroadcaster) BroadcastSessionUpdate(sessionID string, data map[string]interface{}, excludeUsers map[string]bool) (int, error) {
	update := &models.SessionUpdate{
		SessionID: sessionID,
	}

	// Map data fields to SessionUpdate struct
	if alertType, ok := data["alert_type"].(string); ok {
		update.AlertType = alertType
	}
	if agentType, ok := data["agent_type"].(string); ok {
		update.AgentType = agentType
	}
	if status, ok := data["status"].(string); ok {
		update.Status = models.AlertSessionStatus(status)
	}

	message := models.NewSessionUpdateMessage(sessionID, update)
	return db.BroadcastMessage(models.WSChannelSessionPrefix+sessionID, message, excludeUsers)
}

// BroadcastInteractionUpdate broadcasts interaction update to both session-specific and dashboard channels
func (db *DashboardBroadcaster) BroadcastInteractionUpdate(sessionID string, updateData map[string]interface{}, excludeUsers map[string]bool) (int, error) {
	totalSent := 0

	// Send to session-specific channel for detail views
	sessionSent, err := db.BroadcastSessionUpdate(sessionID, updateData, excludeUsers)
	if err != nil {
		db.logger.Warn("Failed to broadcast to session channel", zap.Error(err))
	}
	totalSent += sessionSent

	// Also send to dashboard channel for real-time updates in main dashboard
	dashboardSent, err := db.BroadcastDashboardUpdate(updateData, excludeUsers)
	if err != nil {
		db.logger.Warn("Failed to broadcast to dashboard channel", zap.Error(err))
	}
	totalSent += dashboardSent

	db.logger.Debug("Broadcasted interaction update",
		zap.String("session_id", sessionID),
		zap.Int("session_sent", sessionSent),
		zap.Int("dashboard_sent", dashboardSent))

	return totalSent, nil
}

// BroadcastChainProgressUpdate broadcasts chain execution progress update
func (db *DashboardBroadcaster) BroadcastChainProgressUpdate(sessionID, chainID string, currentStage string, currentStageIndex, totalStages, completedStages, failedStages int, overallStatus models.ChainStatus, stageDetails map[string]interface{}, excludeUsers map[string]bool) (int, error) {
	progress := &models.ChainProgressUpdate{
		SessionID:         sessionID,
		ChainID:           chainID,
		Status:            overallStatus,
		CurrentStageIndex: currentStageIndex,
		CurrentStageName:  currentStage,
		TotalStages:       totalStages,
		CompletedStages:   completedStages,
		FailedStages:      failedStages,
		Progress:          float64(completedStages) / float64(totalStages) * 100,
		StartedAtUs:       models.GetCurrentTimestampUs(),
	}

	message := models.NewChainProgressMessage(sessionID, progress)
	return db.BroadcastMessage(models.WSChannelSessionPrefix+sessionID, message, excludeUsers)
}

// BroadcastStageProgressUpdate broadcasts individual stage execution progress update
func (db *DashboardBroadcaster) BroadcastStageProgressUpdate(sessionID, chainID, stageExecutionID, stageID, stageName string, stageIndex int, agent string, status models.StageStatus, startedAtUs, completedAtUs, durationMs *int64, errorMessage string, excludeUsers map[string]bool) (int, error) {
	progress := &models.StageProgressUpdate{
		SessionID:        sessionID,
		StageExecutionID: stageExecutionID,
		StageID:          stageID,
		StageIndex:       stageIndex,
		StageName:        stageName,
		AgentType:        agent,
		Status:           status,
		Progress:         0, // Will be calculated based on status
		StartedAtUs:      startedAtUs,
		CompletedAtUs:    completedAtUs,
		DurationMs:       durationMs,
	}

	if errorMessage != "" {
		progress.ErrorMessage = &errorMessage
	}

	// Calculate progress based on status
	switch status {
	case models.StageStatusPending:
		progress.Progress = 0
	case models.StageStatusActive:
		progress.Progress = 50
	case models.StageStatusCompleted:
		progress.Progress = 100
	case models.StageStatusFailed:
		progress.Progress = 100 // Failed is complete, just not successful
	}

	message := models.NewStageProgressMessage(sessionID, progress)
	return db.BroadcastMessage(models.WSChannelSessionPrefix+sessionID, message, excludeUsers)
}

// Cleanup management

// startCleanupTask starts the periodic cleanup task for session message buffers
func (db *DashboardBroadcaster) startCleanupTask() {
	ctx, cancel := context.WithCancel(context.Background())
	db.cleanupCancel = cancel

	go func() {
		defer close(db.cleanupDone)
		ticker := time.NewTicker(CleanupIntervalSeconds * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				db.cleanupExpiredMessages()
			case <-ctx.Done():
				db.logger.Debug("Session buffer cleanup task cancelled")
				return
			}
		}
	}()

	db.logger.Debug("Started session buffer cleanup task")
}

// stopCleanupTask stops the periodic cleanup task
func (db *DashboardBroadcaster) stopCleanupTask() {
	if db.cleanupCancel != nil {
		db.cleanupCancel()
		<-db.cleanupDone
		db.logger.Debug("Stopped session buffer cleanup task")
	}
}

// cleanupExpiredMessages periodically cleans up expired messages and empty sessions
func (db *DashboardBroadcaster) cleanupExpiredMessages() {
	db.bufferLock.Lock()
	defer db.bufferLock.Unlock()

	cutoffTime := time.Now().Add(-MessageTTLSeconds * time.Second)
	removedCount := 0

	for channel, buffer := range db.sessionMessageBuffer {
		var validMessages []*TimestampedMessage

		for _, msg := range buffer {
			if msg.Timestamp.After(cutoffTime) {
				validMessages = append(validMessages, msg)
			} else {
				removedCount++
			}
		}

		if len(validMessages) == 0 {
			delete(db.sessionMessageBuffer, channel)
		} else {
			db.sessionMessageBuffer[channel] = validMessages
		}
	}

	if removedCount > 0 {
		db.logger.Debug("Cleaned up expired session messages",
			zap.Int("removed_count", removedCount),
			zap.Int("remaining_channels", len(db.sessionMessageBuffer)))
	}
}

// Shutdown gracefully shuts down the dashboard broadcaster
func (db *DashboardBroadcaster) Shutdown() error {
	db.logger.Info("Shutting down dashboard broadcaster")
	db.stopCleanupTask()

	// Clear all buffers
	db.bufferLock.Lock()
	db.sessionMessageBuffer = make(map[string][]*TimestampedMessage)
	db.bufferLock.Unlock()

	db.logger.Info("Dashboard broadcaster shutdown complete")
	return nil
}

// GetStats returns broadcaster statistics
func (db *DashboardBroadcaster) GetStats() map[string]interface{} {
	db.bufferLock.RLock()
	defer db.bufferLock.RUnlock()

	totalBufferedMessages := 0
	for _, buffer := range db.sessionMessageBuffer {
		totalBufferedMessages += len(buffer)
	}

	return map[string]interface{}{
		"buffered_sessions":       len(db.sessionMessageBuffer),
		"total_buffered_messages": totalBufferedMessages,
		"max_messages_per_session": MaxMessagesPerSession,
		"message_ttl_seconds":     MessageTTLSeconds,
		"cleanup_interval_seconds": CleanupIntervalSeconds,
	}
}