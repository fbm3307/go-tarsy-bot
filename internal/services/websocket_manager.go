package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/models"
)

// WebSocketManager manages WebSocket connections for real-time updates
type WebSocketManager struct {
	connections      map[string]*Connection
	channels         map[string]map[string]*Connection // channel -> connection_id -> connection
	connectionsByIP  map[string][]*Connection          // ip -> connections
	upgrader         websocket.Upgrader
	logger           *zap.Logger
	mutex            sync.RWMutex
	config           *WebSocketConfig
	ctx              context.Context
	cancel           context.CancelFunc

	// Connection tracking and limits
	totalConnections int
	connectionLimits map[string]int // ip -> connection count
	rateLimiters     map[string]*ConnectionRateLimiter // connection_id -> rate limiter
}

// Connection represents a WebSocket connection
type Connection struct {
	ID           string
	UserID       string
	Channel      string
	RemoteAddr   string
	Conn         *websocket.Conn
	Send         chan []byte
	Manager      *WebSocketManager
	LastActivity time.Time
	CreatedAt    time.Time
	Subscriptions map[string]bool
	RateLimiter  *ConnectionRateLimiter
	MessageCount int64
	BytesSent    int64
	BytesReceived int64
	mutex        sync.RWMutex
}

// ConnectionRateLimiter provides rate limiting for WebSocket connections
type ConnectionRateLimiter struct {
	messages   []time.Time
	maxMessages int
	window     time.Duration
	mutex      sync.Mutex
}

// NewConnectionRateLimiter creates a new rate limiter
func NewConnectionRateLimiter(maxMessages int, window time.Duration) *ConnectionRateLimiter {
	return &ConnectionRateLimiter{
		messages:   make([]time.Time, 0),
		maxMessages: maxMessages,
		window:     window,
	}
}

// AllowMessage checks if a message is allowed under rate limiting
func (rl *ConnectionRateLimiter) AllowMessage() bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Remove old messages outside the window
	validMessages := make([]time.Time, 0)
	for _, msgTime := range rl.messages {
		if msgTime.After(cutoff) {
			validMessages = append(validMessages, msgTime)
		}
	}
	rl.messages = validMessages

	// Check if we can add a new message
	if len(rl.messages) >= rl.maxMessages {
		return false
	}

	// Add the current message
	rl.messages = append(rl.messages, now)
	return true
}

// GetCurrentRate returns the current message rate
func (rl *ConnectionRateLimiter) GetCurrentRate() int {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	count := 0
	for _, msgTime := range rl.messages {
		if msgTime.After(cutoff) {
			count++
		}
	}
	return count
}

// WebSocketConfig contains configuration for the WebSocket manager
type WebSocketConfig struct {
	ReadTimeout         time.Duration `json:"read_timeout"`
	WriteTimeout        time.Duration `json:"write_timeout"`
	PingInterval        time.Duration `json:"ping_interval"`
	MaxMessageSize      int64         `json:"max_message_size"`
	CheckOrigin         bool          `json:"check_origin"`
	AllowedOrigins      []string      `json:"allowed_origins"`
	MaxConnections      int           `json:"max_connections"`
	MaxConnectionsPerIP int           `json:"max_connections_per_ip"`
	ConnectionTimeout   time.Duration `json:"connection_timeout"`
	RateLimitMessages   int           `json:"rate_limit_messages"`  // Messages per minute per connection
	RateLimitWindow     time.Duration `json:"rate_limit_window"`
	EnableCompression   bool          `json:"enable_compression"`
	BufferSize          int           `json:"buffer_size"`
}

// DefaultWebSocketConfig returns default WebSocket configuration
func DefaultWebSocketConfig() *WebSocketConfig {
	return &WebSocketConfig{
		ReadTimeout:         60 * time.Second,
		WriteTimeout:        10 * time.Second,
		PingInterval:        54 * time.Second,
		MaxMessageSize:      8192,
		CheckOrigin:         false,
		AllowedOrigins:      []string{"*"},
		MaxConnections:      1000,
		MaxConnectionsPerIP: 10,
		ConnectionTimeout:   30 * time.Second,
		RateLimitMessages:   60, // 60 messages per minute
		RateLimitWindow:     time.Minute,
		EnableCompression:   true,
		BufferSize:          256,
	}
}

// NewWebSocketManager creates a new WebSocket manager
func NewWebSocketManager(logger *zap.Logger, config *WebSocketConfig) *WebSocketManager {
	if config == nil {
		config = DefaultWebSocketConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	upgrader := websocket.Upgrader{
		ReadBufferSize:    1024,
		WriteBufferSize:   1024,
		EnableCompression: config.EnableCompression,
		CheckOrigin: func(r *http.Request) bool {
			if !config.CheckOrigin {
				return true
			}
			origin := r.Header.Get("Origin")
			for _, allowed := range config.AllowedOrigins {
				if allowed == "*" || allowed == origin {
					return true
				}
			}
			return false
		},
	}

	manager := &WebSocketManager{
		connections:      make(map[string]*Connection),
		channels:         make(map[string]map[string]*Connection),
		connectionsByIP:  make(map[string][]*Connection),
		upgrader:         upgrader,
		logger:           logger,
		config:           config,
		ctx:              ctx,
		cancel:           cancel,
		totalConnections: 0,
		connectionLimits: make(map[string]int),
		rateLimiters:     make(map[string]*ConnectionRateLimiter),
	}

	// Start background tasks
	go manager.pingLoop()
	go manager.cleanupLoop()

	return manager
}

// HandleWebSocket upgrades HTTP connection to WebSocket
func (wm *WebSocketManager) HandleWebSocket(w http.ResponseWriter, r *http.Request, userID, channel string) error {
	// Get client IP address
	clientIP := wm.getClientIP(r)

	// Check connection limits
	if err := wm.checkConnectionLimits(clientIP); err != nil {
		wm.logger.Warn("Connection rejected due to limits",
			zap.String("client_ip", clientIP),
			zap.Error(err))
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return err
	}

	conn, err := wm.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return fmt.Errorf("websocket upgrade failed: %w", err)
	}

	// Create rate limiter for this connection
	rateLimiter := NewConnectionRateLimiter(
		wm.config.RateLimitMessages,
		wm.config.RateLimitWindow,
	)

	// Create connection
	connection := &Connection{
		ID:            generateConnectionID(),
		UserID:        userID,
		Channel:       channel,
		RemoteAddr:    clientIP,
		Conn:          conn,
		Send:          make(chan []byte, wm.config.BufferSize),
		Manager:       wm,
		LastActivity:  time.Now(),
		CreatedAt:     time.Now(),
		Subscriptions: make(map[string]bool),
		RateLimiter:   rateLimiter,
		MessageCount:  0,
		BytesSent:     0,
		BytesReceived: 0,
	}

	// Configure connection
	conn.SetReadLimit(wm.config.MaxMessageSize)
	conn.SetReadDeadline(time.Now().Add(wm.config.ReadTimeout))
	conn.SetPongHandler(func(string) error {
		connection.LastActivity = time.Now()
		conn.SetReadDeadline(time.Now().Add(wm.config.ReadTimeout))
		return nil
	})

	// Register connection
	wm.registerConnection(connection)

	// Start connection handlers
	go connection.readPump()
	go connection.writePump()

	wm.logger.Info("WebSocket connection established",
		zap.String("connection_id", connection.ID),
		zap.String("user_id", userID),
		zap.String("channel", channel),
	)

	return nil
}

// registerConnection registers a new connection
func (wm *WebSocketManager) registerConnection(conn *Connection) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	// Add to connections map
	wm.connections[conn.ID] = conn

	// Add to channel map
	if wm.channels[conn.Channel] == nil {
		wm.channels[conn.Channel] = make(map[string]*Connection)
	}
	wm.channels[conn.Channel][conn.ID] = conn

	// Add to IP tracking
	wm.connectionsByIP[conn.RemoteAddr] = append(wm.connectionsByIP[conn.RemoteAddr], conn)
	wm.connectionLimits[conn.RemoteAddr]++
	wm.totalConnections++

	// Add rate limiter
	wm.rateLimiters[conn.ID] = conn.RateLimiter

	wm.logger.Debug("Connection registered",
		zap.String("connection_id", conn.ID),
		zap.String("channel", conn.Channel),
		zap.String("remote_addr", conn.RemoteAddr),
		zap.Int("total_connections", wm.totalConnections),
		zap.Int("ip_connections", wm.connectionLimits[conn.RemoteAddr]),
	)
}

// unregisterConnection removes a connection
func (wm *WebSocketManager) unregisterConnection(conn *Connection) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	// Remove from connections map
	delete(wm.connections, conn.ID)

	// Remove from channel map
	if channelConns, exists := wm.channels[conn.Channel]; exists {
		delete(channelConns, conn.ID)
		if len(channelConns) == 0 {
			delete(wm.channels, conn.Channel)
		}
	}

	// Remove from IP tracking
	if ipConns, exists := wm.connectionsByIP[conn.RemoteAddr]; exists {
		// Find and remove this connection from the IP list
		for i, c := range ipConns {
			if c.ID == conn.ID {
				wm.connectionsByIP[conn.RemoteAddr] = append(ipConns[:i], ipConns[i+1:]...)
				break
			}
		}

		// Clean up empty IP lists and update counters
		if len(wm.connectionsByIP[conn.RemoteAddr]) == 0 {
			delete(wm.connectionsByIP, conn.RemoteAddr)
			delete(wm.connectionLimits, conn.RemoteAddr)
		} else {
			wm.connectionLimits[conn.RemoteAddr]--
		}
	}

	// Update total connection count
	wm.totalConnections--

	// Remove rate limiter
	delete(wm.rateLimiters, conn.ID)

	close(conn.Send)

	wm.logger.Debug("Connection unregistered",
		zap.String("connection_id", conn.ID),
		zap.String("channel", conn.Channel),
		zap.String("remote_addr", conn.RemoteAddr),
		zap.Int("total_connections", wm.totalConnections),
		zap.Duration("connection_duration", time.Since(conn.CreatedAt)),
		zap.Int64("messages_processed", conn.MessageCount),
		zap.Int64("bytes_sent", conn.BytesSent),
		zap.Int64("bytes_received", conn.BytesReceived),
	)
}

// BroadcastToChannel sends a message to all connections in a channel
func (wm *WebSocketManager) BroadcastToChannel(channel string, message *models.WebSocketMessage) error {
	wm.mutex.RLock()
	channelConns, exists := wm.channels[channel]
	if !exists || len(channelConns) == 0 {
		wm.mutex.RUnlock()
		wm.logger.Debug("No connections in channel", zap.String("channel", channel))
		return nil
	}

	// Create a copy to avoid holding the lock during broadcast
	connections := make([]*Connection, 0, len(channelConns))
	for _, conn := range channelConns {
		connections = append(connections, conn)
	}
	wm.mutex.RUnlock()

	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	successCount := 0
	for _, conn := range connections {
		select {
		case conn.Send <- data:
			successCount++
		default:
			// Connection buffer is full, close it
			wm.logger.Warn("Connection buffer full, closing connection",
				zap.String("connection_id", conn.ID))
			conn.close()
		}
	}

	wm.logger.Debug("Broadcast completed",
		zap.String("channel", channel),
		zap.Int("sent_to", successCount),
		zap.Int("total_in_channel", len(connections)),
	)

	return nil
}

// SendToConnection sends a message to a specific connection
func (wm *WebSocketManager) SendToConnection(connectionID string, message *models.WebSocketMessage) error {
	wm.mutex.RLock()
	conn, exists := wm.connections[connectionID]
	wm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("connection %s not found", connectionID)
	}

	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	select {
	case conn.Send <- data:
		return nil
	default:
		// Connection buffer is full, close it
		wm.logger.Warn("Connection buffer full, closing connection",
			zap.String("connection_id", connectionID))
		conn.close()
		return fmt.Errorf("connection buffer full")
	}
}

// SendToUser sends a message to all connections for a specific user
func (wm *WebSocketManager) SendToUser(userID string, message *models.WebSocketMessage) error {
	wm.mutex.RLock()
	userConnections := make([]*Connection, 0)
	for _, conn := range wm.connections {
		if conn.UserID == userID {
			userConnections = append(userConnections, conn)
		}
	}
	wm.mutex.RUnlock()

	if len(userConnections) == 0 {
		wm.logger.Debug("No connections for user", zap.String("user_id", userID))
		return nil
	}

	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	successCount := 0
	for _, conn := range userConnections {
		select {
		case conn.Send <- data:
			successCount++
		default:
			wm.logger.Warn("Connection buffer full, closing connection",
				zap.String("connection_id", conn.ID))
			conn.close()
		}
	}

	wm.logger.Debug("User message sent",
		zap.String("user_id", userID),
		zap.Int("sent_to", successCount),
		zap.Int("total_connections", len(userConnections)),
	)

	return nil
}

// GetConnectionCount returns the total number of active connections
func (wm *WebSocketManager) GetConnectionCount() int {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()
	return len(wm.connections)
}

// GetChannelConnectionCount returns the number of connections in a channel
func (wm *WebSocketManager) GetChannelConnectionCount(channel string) int {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	if channelConns, exists := wm.channels[channel]; exists {
		return len(channelConns)
	}
	return 0
}

// GetConnectionsByChannel returns connection IDs for a channel
func (wm *WebSocketManager) GetConnectionsByChannel(channel string) []string {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	channelConns, exists := wm.channels[channel]
	if !exists {
		return []string{}
	}

	connectionIDs := make([]string, 0, len(channelConns))
	for id := range channelConns {
		connectionIDs = append(connectionIDs, id)
	}
	return connectionIDs
}

// GetStats returns WebSocket manager statistics
func (wm *WebSocketManager) GetStats() map[string]interface{} {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	channelStats := make(map[string]int)
	for channel, conns := range wm.channels {
		channelStats[channel] = len(conns)
	}

	ipStats := make(map[string]int)
	for ip, count := range wm.connectionLimits {
		ipStats[ip] = count
	}

	// Calculate aggregate statistics
	var totalMessages, totalBytesSent, totalBytesReceived int64
	var avgConnectionDuration time.Duration
	var connectionCount int64

	for _, conn := range wm.connections {
		conn.mutex.RLock()
		totalMessages += conn.MessageCount
		totalBytesSent += conn.BytesSent
		totalBytesReceived += conn.BytesReceived
		avgConnectionDuration += time.Since(conn.CreatedAt)
		connectionCount++
		conn.mutex.RUnlock()
	}

	if connectionCount > 0 {
		avgConnectionDuration = avgConnectionDuration / time.Duration(connectionCount)
	}

	return map[string]interface{}{
		"total_connections":        wm.totalConnections,
		"total_channels":           len(wm.channels),
		"unique_ips":               len(wm.connectionsByIP),
		"connections_by_channel":   channelStats,
		"connections_by_ip":        ipStats,
		"total_messages_processed": totalMessages,
		"total_bytes_sent":         totalBytesSent,
		"total_bytes_received":     totalBytesReceived,
		"average_connection_duration": avgConnectionDuration.String(),
		"rate_limited_connections": len(wm.rateLimiters),
		"config": map[string]interface{}{
			"ping_interval":         wm.config.PingInterval.String(),
			"write_timeout":         wm.config.WriteTimeout.String(),
			"read_timeout":          wm.config.ReadTimeout.String(),
			"max_message_size":      wm.config.MaxMessageSize,
			"max_connections":       wm.config.MaxConnections,
			"max_connections_per_ip": wm.config.MaxConnectionsPerIP,
			"rate_limit_messages":   wm.config.RateLimitMessages,
			"rate_limit_window":     wm.config.RateLimitWindow.String(),
			"enable_compression":    wm.config.EnableCompression,
			"buffer_size":           wm.config.BufferSize,
		},
	}
}

// Shutdown gracefully shuts down the WebSocket manager
func (wm *WebSocketManager) Shutdown() error {
	wm.logger.Info("Shutting down WebSocket manager")

	// Cancel background tasks
	wm.cancel()

	// Close all connections
	wm.mutex.Lock()
	connections := make([]*Connection, 0, len(wm.connections))
	for _, conn := range wm.connections {
		connections = append(connections, conn)
	}
	wm.mutex.Unlock()

	for _, conn := range connections {
		conn.close()
	}

	wm.logger.Info("WebSocket manager shutdown complete",
		zap.Int("closed_connections", len(connections)))

	return nil
}

// pingLoop sends ping messages to all connections
func (wm *WebSocketManager) pingLoop() {
	ticker := time.NewTicker(wm.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			wm.pingAllConnections()
		case <-wm.ctx.Done():
			return
		}
	}
}

// pingAllConnections sends ping to all active connections
func (wm *WebSocketManager) pingAllConnections() {
	wm.mutex.RLock()
	connections := make([]*Connection, 0, len(wm.connections))
	for _, conn := range wm.connections {
		connections = append(connections, conn)
	}
	wm.mutex.RUnlock()

	for _, conn := range connections {
		conn.ping()
	}
}

// cleanupLoop removes stale connections
func (wm *WebSocketManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			wm.cleanupStaleConnections()
		case <-wm.ctx.Done():
			return
		}
	}
}

// cleanupStaleConnections removes connections that haven't been active
func (wm *WebSocketManager) cleanupStaleConnections() {
	cutoff := time.Now().Add(-2 * wm.config.ReadTimeout)

	wm.mutex.RLock()
	staleConnections := make([]*Connection, 0)
	for _, conn := range wm.connections {
		conn.mutex.RLock()
		if conn.LastActivity.Before(cutoff) {
			staleConnections = append(staleConnections, conn)
		}
		conn.mutex.RUnlock()
	}
	wm.mutex.RUnlock()

	for _, conn := range staleConnections {
		wm.logger.Info("Closing stale connection",
			zap.String("connection_id", conn.ID),
			zap.Duration("inactive_for", time.Since(conn.LastActivity)))
		conn.close()
	}
}

// Connection methods

// readPump handles reading from the WebSocket connection
func (c *Connection) readPump() {
	defer func() {
		c.Manager.unregisterConnection(c)
		c.Conn.Close()
	}()

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.Manager.logger.Error("WebSocket read error",
					zap.String("connection_id", c.ID),
					zap.Error(err))
			}
			break
		}

		c.mutex.Lock()
		c.LastActivity = time.Now()
		c.mutex.Unlock()

		// Handle incoming message (could implement subscription management here)
		c.handleMessage(message)
	}
}

// writePump handles writing to the WebSocket connection
func (c *Connection) writePump() {
	ticker := time.NewTicker(c.Manager.config.PingInterval)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(c.Manager.config.WriteTimeout))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				c.Manager.logger.Error("WebSocket write error",
					zap.String("connection_id", c.ID),
					zap.Error(err))
				return
			}

			// Update bytes sent counter
			c.mutex.Lock()
			c.BytesSent += int64(len(message))
			c.mutex.Unlock()

		case <-ticker.C:
			c.ping()
		}
	}
}

// ping sends a ping message to the connection
func (c *Connection) ping() {
	c.Conn.SetWriteDeadline(time.Now().Add(c.Manager.config.WriteTimeout))
	if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
		c.Manager.logger.Debug("Ping failed, closing connection",
			zap.String("connection_id", c.ID),
			zap.Error(err))
		c.close()
	}
}

// close closes the connection
func (c *Connection) close() {
	c.Manager.unregisterConnection(c)
	c.Conn.Close()
}

// handleMessage processes incoming messages from the client
func (c *Connection) handleMessage(message []byte) {
	// Check rate limiting
	if !c.RateLimiter.AllowMessage() {
		c.Manager.logger.Warn("Message rate limit exceeded",
			zap.String("connection_id", c.ID),
			zap.String("remote_addr", c.RemoteAddr),
			zap.Int("current_rate", c.RateLimiter.GetCurrentRate()))

		// Send rate limit warning to client
		warningMsg := models.WebSocketMessage{
			Type: "rate_limit_warning",
			Data: map[string]interface{}{
				"message": "Message rate limit exceeded. Please slow down.",
				"current_rate": c.RateLimiter.GetCurrentRate(),
				"max_rate": c.Manager.config.RateLimitMessages,
			},
		}

		if msgData, err := json.Marshal(warningMsg); err == nil {
			select {
			case c.Send <- msgData:
			default:
				// Buffer full, ignore
			}
		}
		return
	}

	// Update message statistics
	c.mutex.Lock()
	c.MessageCount++
	c.BytesReceived += int64(len(message))
	c.mutex.Unlock()

	// Parse the message
	var msg map[string]interface{}
	if err := json.Unmarshal(message, &msg); err != nil {
		c.Manager.logger.Error("Failed to parse WebSocket message",
			zap.String("connection_id", c.ID),
			zap.Error(err))
		return
	}

	// Handle subscription requests
	if msgType, ok := msg["type"].(string); ok {
		switch msgType {
		case "subscribe":
			if topic, ok := msg["topic"].(string); ok {
				c.subscribe(topic)
			}
		case "unsubscribe":
			if topic, ok := msg["topic"].(string); ok {
				c.unsubscribe(topic)
			}
		case "ping":
			// Respond to client ping with pong
			pongMsg := models.WebSocketMessage{
				Type: "pong",
				Data: map[string]interface{}{
					"timestamp": time.Now().Unix(),
				},
			}
			if msgData, err := json.Marshal(pongMsg); err == nil {
				select {
				case c.Send <- msgData:
				default:
					// Buffer full, ignore
				}
			}
		}
	}

	c.Manager.logger.Debug("WebSocket message processed",
		zap.String("connection_id", c.ID),
		zap.String("message_type", fmt.Sprintf("%v", msg["type"])),
		zap.Int("message_size", len(message)),
		zap.Int64("total_messages", c.MessageCount))
}

// subscribe adds a subscription to the connection
func (c *Connection) subscribe(topic string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.Subscriptions[topic] = true
	c.Manager.logger.Debug("Connection subscribed",
		zap.String("connection_id", c.ID),
		zap.String("topic", topic))
}

// unsubscribe removes a subscription from the connection
func (c *Connection) unsubscribe(topic string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.Subscriptions, topic)
	c.Manager.logger.Debug("Connection unsubscribed",
		zap.String("connection_id", c.ID),
		zap.String("topic", topic))
}

// Helper functions

// generateConnectionID generates a unique connection ID
func generateConnectionID() string {
	return fmt.Sprintf("ws_%d", time.Now().UnixNano())
}

// getClientIP extracts the client IP address from the request
func (wm *WebSocketManager) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (common behind proxies)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fallback to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// checkConnectionLimits checks if a new connection from the given IP is allowed
func (wm *WebSocketManager) checkConnectionLimits(clientIP string) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	// Check global connection limit
	if wm.config.MaxConnections > 0 && wm.totalConnections >= wm.config.MaxConnections {
		return fmt.Errorf("maximum connections limit reached (%d)", wm.config.MaxConnections)
	}

	// Check per-IP connection limit
	if wm.config.MaxConnectionsPerIP > 0 {
		currentCount := wm.connectionLimits[clientIP]
		if currentCount >= wm.config.MaxConnectionsPerIP {
			return fmt.Errorf("maximum connections per IP limit reached (%d) for IP %s",
				wm.config.MaxConnectionsPerIP, clientIP)
		}
	}

	return nil
}