package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"go.uber.org/zap"
)

// MCPClient represents a Model Context Protocol client
// This provides tool discovery and execution capabilities
type MCPClient interface {
	// Connect establishes connection to MCP server
	Connect(ctx context.Context, serverConfig *ServerConfig) error

	// Disconnect closes the connection
	Disconnect() error

	// ListTools returns available tools
	ListTools(ctx context.Context) ([]Tool, error)

	// ExecuteTool executes a tool with given parameters
	ExecuteTool(ctx context.Context, toolName string, parameters map[string]interface{}) (*ToolResult, error)

	// GetServerInfo returns server information
	GetServerInfo() *ServerInfo

	// IsConnected returns connection status
	IsConnected() bool
}

// ServerConfig represents MCP server configuration
type ServerConfig struct {
	Name        string                 `json:"name" yaml:"name"`
	Command     string                 `json:"command" yaml:"command"`
	Args        []string               `json:"args,omitempty" yaml:"args,omitempty"`
	Env         map[string]string      `json:"env,omitempty" yaml:"env,omitempty"`
	WorkingDir  string                 `json:"working_dir,omitempty" yaml:"working_dir,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty" yaml:"options,omitempty"`
}

// ServerInfo represents information about an MCP server
type ServerInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Protocol     string   `json:"protocol"`
	Capabilities []string `json:"capabilities"`
	Connected    bool     `json:"connected"`
	LastSeen     time.Time `json:"last_seen"`
}

// Tool represents an MCP tool definition following official MCP SDK pattern
type Tool struct {
	Name        string                 `json:"name" validate:"required"`
	Description string                 `json:"description,omitempty"`
	Schema      *ToolSchema            `json:"schema,omitempty"`     // JSON Schema for parameters
	Parameters  ToolParameters         `json:"parameters,omitempty"` // Legacy support
	Server      string                 `json:"server" validate:"required"`
	Version     string                 `json:"version,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	IsAsync     bool                   `json:"is_async,omitempty"`
	Timeout     int64                  `json:"timeout_ms,omitempty"`
}

// ToolSchema represents JSON Schema for tool parameters following official MCP SDK
type ToolSchema struct {
	Type                 string                      `json:"type"`
	Properties           map[string]*SchemaProperty  `json:"properties,omitempty"`
	Required             []string                    `json:"required,omitempty"`
	AdditionalProperties bool                        `json:"additionalProperties,omitempty"`
	Title                string                      `json:"title,omitempty"`
	Description          string                      `json:"description,omitempty"`
}

// SchemaProperty represents a property in the JSON Schema
type SchemaProperty struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description,omitempty"`
	Default     interface{}            `json:"default,omitempty"`
	Enum        []interface{}          `json:"enum,omitempty"`
	Pattern     string                 `json:"pattern,omitempty"`
	MinLength   int                    `json:"minLength,omitempty"`
	MaxLength   int                    `json:"maxLength,omitempty"`
	Minimum     float64                `json:"minimum,omitempty"`
	Maximum     float64                `json:"maximum,omitempty"`
	Items       *SchemaProperty        `json:"items,omitempty"`
	Properties  map[string]*SchemaProperty `json:"properties,omitempty"`
	Required    []string               `json:"required,omitempty"`
}

// ToolParameters represents tool parameter schema
type ToolParameters struct {
	Type       string                            `json:"type"`
	Properties map[string]ToolParameterProperty  `json:"properties,omitempty"`
	Required   []string                          `json:"required,omitempty"`
}

// ToolParameterProperty represents a tool parameter property
type ToolParameterProperty struct {
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
}

// ToolResult represents the result of tool execution following official MCP SDK pattern
type ToolResult struct {
	// Core result data
	Success   bool                   `json:"success"`
	Content   interface{}            `json:"content"`                    // Can be string, object, or array
	IsText    bool                   `json:"isText,omitempty"`          // Indicates if content is text
	MimeType  string                 `json:"mimeType,omitempty"`        // MIME type of content

	// Error information
	Error     string                 `json:"error,omitempty"`
	ErrorCode string                 `json:"errorCode,omitempty"`       // Error code for categorization

	// Execution metadata
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Duration  time.Duration          `json:"duration"`
	Timestamp time.Time              `json:"timestamp"`

	// Tool execution context
	ToolName  string                 `json:"toolName,omitempty"`
	Server    string                 `json:"server,omitempty"`

	// Result processing
	ContentType string               `json:"contentType,omitempty"`     // "text", "json", "binary", etc.
	Size        int64                `json:"size,omitempty"`            // Content size in bytes

	// Async support
	IsAsync     bool                 `json:"isAsync,omitempty"`
	Progress    float64              `json:"progress,omitempty"`        // 0.0 to 1.0 for async operations
	Status      string               `json:"status,omitempty"`          // "pending", "running", "completed", "failed"
}

// MCPMessage represents a JSON-RPC 2.0 message
type MCPMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Method  string      `json:"method,omitempty"`
	Params  interface{} `json:"params,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

// MCPError represents a JSON-RPC 2.0 error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCPClientImpl provides a full MCP client implementation
type MCPClientImpl struct {
	serverConfig    *ServerConfig
	serverInfo      *ServerInfo
	tools           []Tool
	connected       bool
	logger          *zap.Logger
	mutex           sync.RWMutex

	// Process management
	cmd             *exec.Cmd
	stdin           io.WriteCloser
	stdout          io.ReadCloser
	stderr          io.ReadCloser

	// Message handling
	requestID       int64
	pendingRequests map[interface{}]chan *MCPMessage
	messageBuffer   chan *MCPMessage

	// Context management
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewMCPClient creates a new MCP client
func NewMCPClient(logger *zap.Logger) *MCPClientImpl {
	ctx, cancel := context.WithCancel(context.Background())
	return &MCPClientImpl{
		logger:          logger,
		connected:       false,
		tools:           make([]Tool, 0),
		pendingRequests: make(map[interface{}]chan *MCPMessage),
		messageBuffer:   make(chan *MCPMessage, 100),
		ctx:             ctx,
		cancel:          cancel,
	}
}

// Connect establishes connection to MCP server
func (c *MCPClientImpl) Connect(ctx context.Context, serverConfig *ServerConfig) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.connected {
		return fmt.Errorf("client is already connected")
	}

	c.logger.Info("Starting MCP server process",
		zap.String("server", serverConfig.Name),
		zap.String("command", serverConfig.Command),
		zap.Strings("args", serverConfig.Args),
	)

	// Store server config
	c.serverConfig = serverConfig

	// Start the MCP server process
	if err := c.startServerProcess(ctx, serverConfig); err != nil {
		return fmt.Errorf("failed to start server process: %w", err)
	}

	// Start message processing goroutines
	go c.readMessages()
	go c.processMessages()

	// Perform MCP handshake
	if err := c.performHandshake(ctx); err != nil {
		c.cleanup()
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Discover available tools
	if err := c.discoverTools(ctx); err != nil {
		c.cleanup()
		return fmt.Errorf("tool discovery failed: %w", err)
	}

	c.connected = true
	c.logger.Info("Connected to MCP server",
		zap.String("server", serverConfig.Name),
		zap.Int("tools_discovered", len(c.tools)),
	)

	return nil
}

// startServerProcess starts the MCP server process
func (c *MCPClientImpl) startServerProcess(ctx context.Context, config *ServerConfig) error {
	args := append([]string{}, config.Args...)
	c.cmd = exec.CommandContext(ctx, config.Command, args...)

	// Set environment variables
	if config.Env != nil {
		for key, value := range config.Env {
			c.cmd.Env = append(c.cmd.Env, fmt.Sprintf("%s=%s", key, value))
		}
	}

	// Set working directory
	if config.WorkingDir != "" {
		c.cmd.Dir = config.WorkingDir
	}

	// Setup pipes
	stdin, err := c.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	c.stdin = stdin

	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	c.stdout = stdout

	stderr, err := c.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	c.stderr = stderr

	// Start the process
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}

	c.logger.Debug("MCP server process started", zap.Int("pid", c.cmd.Process.Pid))
	return nil
}

// readMessages reads messages from stdout
func (c *MCPClientImpl) readMessages() {
	scanner := bufio.NewScanner(c.stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var msg MCPMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			c.logger.Warn("Failed to parse MCP message", zap.Error(err), zap.String("line", line))
			continue
		}

		select {
		case c.messageBuffer <- &msg:
		case <-c.ctx.Done():
			return
		}
	}

	if err := scanner.Err(); err != nil {
		c.logger.Error("Error reading from stdout", zap.Error(err))
	}
}

// processMessages processes incoming messages
func (c *MCPClientImpl) processMessages() {
	for {
		select {
		case msg := <-c.messageBuffer:
			c.handleMessage(msg)
		case <-c.ctx.Done():
			return
		}
	}
}

// handleMessage handles a single MCP message
func (c *MCPClientImpl) handleMessage(msg *MCPMessage) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if this is a response to a pending request
	if msg.ID != nil {
		if ch, exists := c.pendingRequests[msg.ID]; exists {
			delete(c.pendingRequests, msg.ID)
			select {
			case ch <- msg:
			default:
				c.logger.Warn("Failed to deliver response", zap.Any("id", msg.ID))
			}
			return
		}
	}

	// Handle notifications and requests from server
	if msg.Method != "" {
		c.handleServerMessage(msg)
	}
}

// handleServerMessage handles messages from the server
func (c *MCPClientImpl) handleServerMessage(msg *MCPMessage) {
	switch msg.Method {
	case "notifications/initialized":
		c.logger.Debug("Server initialization complete")
	case "notifications/progress":
		c.logger.Debug("Progress notification", zap.Any("params", msg.Params))
	default:
		c.logger.Debug("Unhandled server message", zap.String("method", msg.Method))
	}
}

// performHandshake performs the MCP handshake
func (c *MCPClientImpl) performHandshake(ctx context.Context) error {
	// Send initialize request
	initParams := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"clientInfo": map[string]interface{}{
			"name": "TARSy-Bot",
			"version": "1.0.0",
		},
	}

	resp, err := c.sendRequest(ctx, "initialize", initParams)
	if err != nil {
		return fmt.Errorf("initialize request failed: %w", err)
	}

	if resp.Error != nil {
		return fmt.Errorf("initialize failed: %s", resp.Error.Message)
	}

	// Parse server info from response
	if err := c.parseServerInfo(resp.Result); err != nil {
		return fmt.Errorf("failed to parse server info: %w", err)
	}

	// Send initialized notification
	if err := c.sendNotification("notifications/initialized", map[string]interface{}{}); err != nil {
		return fmt.Errorf("failed to send initialized notification: %w", err)
	}

	return nil
}

// discoverTools discovers available tools from the server
func (c *MCPClientImpl) discoverTools(ctx context.Context) error {
	resp, err := c.sendRequest(ctx, "tools/list", map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("tools/list request failed: %w", err)
	}

	if resp.Error != nil {
		return fmt.Errorf("tools/list failed: %s", resp.Error.Message)
	}

	// Parse tools from response
	if err := c.parseTools(resp.Result); err != nil {
		return fmt.Errorf("failed to parse tools: %w", err)
	}

	return nil
}

// Disconnect closes the connection
func (c *MCPClientImpl) Disconnect() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.connected {
		return nil
	}

	c.logger.Info("Disconnecting from MCP server",
		zap.String("server", c.serverConfig.Name),
	)

	c.cleanup()
	c.connected = false

	return nil
}

// cleanup cleans up resources
func (c *MCPClientImpl) cleanup() {
	// Cancel context to stop goroutines
	c.cancel()

	// Close pipes
	if c.stdin != nil {
		c.stdin.Close()
	}
	if c.stdout != nil {
		c.stdout.Close()
	}
	if c.stderr != nil {
		c.stderr.Close()
	}

	// Terminate process
	if c.cmd != nil && c.cmd.Process != nil {
		c.cmd.Process.Kill()
		c.cmd.Wait()
	}
}

// ListTools returns available tools
func (c *MCPClientImpl) ListTools(ctx context.Context) ([]Tool, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected to MCP server")
	}

	return c.tools, nil
}

// ExecuteTool executes a tool with given parameters
func (c *MCPClientImpl) ExecuteTool(ctx context.Context, toolName string, parameters map[string]interface{}) (*ToolResult, error) {
	startTime := time.Now()

	c.mutex.RLock()
	connected := c.connected
	serverName := ""
	if c.serverConfig != nil {
		serverName = c.serverConfig.Name
	}
	c.mutex.RUnlock()

	if !connected {
		return &ToolResult{
			Success:   false,
			Error:     "not connected to MCP server",
			Duration:  time.Since(startTime),
			Timestamp: time.Now(),
		}, nil
	}

	c.logger.Debug("Executing MCP tool",
		zap.String("server", serverName),
		zap.String("tool", toolName),
		zap.Any("parameters", parameters),
	)

	// Find the tool
	var tool *Tool
	for _, t := range c.tools {
		if t.Name == toolName {
			tool = &t
			break
		}
	}

	if tool == nil {
		return &ToolResult{
			Success:   false,
			Error:     fmt.Sprintf("tool not found: %s", toolName),
			Duration:  time.Since(startTime),
			Timestamp: time.Now(),
		}, nil
	}

	// Execute tool via MCP protocol
	result, err := c.executeToolViaProtocol(ctx, toolName, parameters)
	if err != nil {
		return &ToolResult{
			Success:   false,
			Error:     fmt.Sprintf("tool execution failed: %v", err),
			Duration:  time.Since(startTime),
			Timestamp: time.Now(),
		}, nil
	}

	result.Duration = time.Since(startTime)
	result.Timestamp = time.Now()

	c.logger.Debug("MCP tool execution completed",
		zap.String("tool", toolName),
		zap.Bool("success", result.Success),
		zap.Duration("duration", result.Duration),
	)

	return result, nil
}

// GetServerInfo returns server information
func (c *MCPClientImpl) GetServerInfo() *ServerInfo {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.serverInfo == nil {
		return nil
	}

	// Return a copy
	return &ServerInfo{
		Name:         c.serverInfo.Name,
		Version:      c.serverInfo.Version,
		Protocol:     c.serverInfo.Protocol,
		Capabilities: c.serverInfo.Capabilities,
		Connected:    c.serverInfo.Connected,
		LastSeen:     c.serverInfo.LastSeen,
	}
}

// IsConnected returns connection status
func (c *MCPClientImpl) IsConnected() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.connected
}

// sendRequest sends a JSON-RPC request and waits for response
func (c *MCPClientImpl) sendRequest(ctx context.Context, method string, params interface{}) (*MCPMessage, error) {
	c.mutex.Lock()
	c.requestID++
	id := c.requestID
	respChan := make(chan *MCPMessage, 1)
	c.pendingRequests[id] = respChan
	c.mutex.Unlock()

	msg := &MCPMessage{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	if err := c.sendMessage(msg); err != nil {
		c.mutex.Lock()
		delete(c.pendingRequests, id)
		c.mutex.Unlock()
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-ctx.Done():
		c.mutex.Lock()
		delete(c.pendingRequests, id)
		c.mutex.Unlock()
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		c.mutex.Lock()
		delete(c.pendingRequests, id)
		c.mutex.Unlock()
		return nil, fmt.Errorf("request timeout")
	}
}

// sendNotification sends a JSON-RPC notification
func (c *MCPClientImpl) sendNotification(method string, params interface{}) error {
	msg := &MCPMessage{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}
	return c.sendMessage(msg)
}

// sendMessage sends a message to the server
func (c *MCPClientImpl) sendMessage(msg *MCPMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	data = append(data, '\n')

	if _, err := c.stdin.Write(data); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// parseServerInfo parses server information from initialize response
func (c *MCPClientImpl) parseServerInfo(result interface{}) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}

	var info struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities   struct {
			Tools   map[string]interface{} `json:"tools,omitempty"`
			Logging map[string]interface{} `json:"logging,omitempty"`
		} `json:"capabilities"`
		ServerInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}

	if err := json.Unmarshal(data, &info); err != nil {
		return err
	}

	capabilities := []string{}
	if info.Capabilities.Tools != nil {
		capabilities = append(capabilities, "tools")
	}
	if info.Capabilities.Logging != nil {
		capabilities = append(capabilities, "logging")
	}

	c.serverInfo = &ServerInfo{
		Name:         info.ServerInfo.Name,
		Version:      info.ServerInfo.Version,
		Protocol:     info.ProtocolVersion,
		Capabilities: capabilities,
		Connected:    true,
		LastSeen:     time.Now(),
	}

	return nil
}

// parseTools parses tools from tools/list response
func (c *MCPClientImpl) parseTools(result interface{}) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}

	var response struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description,omitempty"`
			InputSchema struct {
				Type       string                 `json:"type"`
				Properties map[string]interface{} `json:"properties,omitempty"`
				Required   []string               `json:"required,omitempty"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}

	if err := json.Unmarshal(data, &response); err != nil {
		return err
	}

	c.tools = make([]Tool, len(response.Tools))
	for i, tool := range response.Tools {
		properties := make(map[string]ToolParameterProperty)
		for name, prop := range tool.InputSchema.Properties {
			propData, _ := json.Marshal(prop)
			var param ToolParameterProperty
			json.Unmarshal(propData, &param)
			properties[name] = param
		}

		c.tools[i] = Tool{
			Name:        tool.Name,
			Description: tool.Description,
			Parameters: ToolParameters{
				Type:       tool.InputSchema.Type,
				Properties: properties,
				Required:   tool.InputSchema.Required,
			},
			Server: c.serverConfig.Name,
		}
	}

	return nil
}

// executeToolViaProtocol executes a tool using the MCP protocol
func (c *MCPClientImpl) executeToolViaProtocol(ctx context.Context, toolName string, parameters map[string]interface{}) (*ToolResult, error) {
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": parameters,
	}

	resp, err := c.sendRequest(ctx, "tools/call", params)
	if err != nil {
		return nil, fmt.Errorf("tools/call request failed: %w", err)
	}

	if resp.Error != nil {
		return &ToolResult{
			Success: false,
			Error:   resp.Error.Message,
		}, nil
	}

	// Parse tool result
	data, err := json.Marshal(resp.Result)
	if err != nil {
		return nil, err
	}

	var toolResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError,omitempty"`
	}

	if err := json.Unmarshal(data, &toolResp); err != nil {
		return nil, err
	}

	// Extract content
	content := ""
	for _, c := range toolResp.Content {
		if c.Type == "text" {
			content += c.Text
		}
	}

	return &ToolResult{
		Success: !toolResp.IsError,
		Content: content,
		Error:   "",
		Metadata: map[string]interface{}{
			"tool_name": toolName,
			"server":    c.serverConfig.Name,
		},
	}, nil
}

// Legacy method for backwards compatibility
func (c *MCPClientImpl) discoverToolsForServer(config *ServerConfig) []Tool {
	switch config.Name {
	case "kubernetes-server":
		return []Tool{
			{
				Name:        "kubectl",
				Description: "Execute kubectl commands to query Kubernetes cluster",
				Parameters: ToolParameters{
					Type: "object",
					Properties: map[string]ToolParameterProperty{
						"command": {
							Type:        "string",
							Description: "The kubectl command to execute",
						},
						"namespace": {
							Type:        "string",
							Description: "Kubernetes namespace (optional)",
						},
					},
					Required: []string{"command"},
				},
				Server: config.Name,
			},
			{
				Name:        "get_pod_logs",
				Description: "Get logs from a Kubernetes pod",
				Parameters: ToolParameters{
					Type: "object",
					Properties: map[string]ToolParameterProperty{
						"pod_name": {
							Type:        "string",
							Description: "Name of the pod",
						},
						"namespace": {
							Type:        "string",
							Description: "Kubernetes namespace",
						},
						"container": {
							Type:        "string",
							Description: "Container name (optional)",
						},
						"lines": {
							Type:        "string",
							Description: "Number of lines to retrieve",
							Default:     "100",
						},
					},
					Required: []string{"pod_name", "namespace"},
				},
				Server: config.Name,
			},
		}

	case "filesystem-server":
		return []Tool{
			{
				Name:        "read_file",
				Description: "Read contents of a file",
				Parameters: ToolParameters{
					Type: "object",
					Properties: map[string]ToolParameterProperty{
						"path": {
							Type:        "string",
							Description: "Path to the file to read",
						},
					},
					Required: []string{"path"},
				},
				Server: config.Name,
			},
			{
				Name:        "list_directory",
				Description: "List contents of a directory",
				Parameters: ToolParameters{
					Type: "object",
					Properties: map[string]ToolParameterProperty{
						"path": {
							Type:        "string",
							Description: "Path to the directory",
						},
					},
					Required: []string{"path"},
				},
				Server: config.Name,
			},
		}

	default:
		return []Tool{
			{
				Name:        "echo",
				Description: "Echo back the input parameters",
				Parameters: ToolParameters{
					Type: "object",
					Properties: map[string]ToolParameterProperty{
						"message": {
							Type:        "string",
							Description: "Message to echo",
						},
					},
					Required: []string{"message"},
				},
				Server: config.Name,
			},
		}
	}
}

// simulateToolExecution simulates the execution of MCP tools
func (c *MCPClientImpl) simulateToolExecution(toolName string, parameters map[string]interface{}) *ToolResult {
	switch toolName {
	case "kubectl":
		command, _ := parameters["command"].(string)
		namespace, _ := parameters["namespace"].(string)

		content := fmt.Sprintf("Executed: kubectl %s", command)
		if namespace != "" {
			content += fmt.Sprintf(" -n %s", namespace)
		}

		if command == "get pods" {
			content += "\nNAME                    READY   STATUS    RESTARTS   AGE\n"
			content += "example-pod-12345       1/1     Running   0          2d\n"
			content += "another-pod-67890       1/1     Running   1          1d"
		}

		return &ToolResult{
			Success: true,
			Content: content,
			Metadata: map[string]interface{}{
				"command":   command,
				"namespace": namespace,
			},
		}

	case "get_pod_logs":
		podName, _ := parameters["pod_name"].(string)
		namespace, _ := parameters["namespace"].(string)

		content := fmt.Sprintf("Logs for pod %s in namespace %s:\n", podName, namespace)
		content += "2024-01-15T10:00:00Z INFO Starting application\n"
		content += "2024-01-15T10:00:01Z INFO Application ready on port 8080\n"
		content += "2024-01-15T10:05:00Z WARN Connection timeout to external service"

		return &ToolResult{
			Success: true,
			Content: content,
			Metadata: map[string]interface{}{
				"pod_name":  podName,
				"namespace": namespace,
			},
		}

	case "read_file":
		path, _ := parameters["path"].(string)
		return &ToolResult{
			Success: true,
			Content: fmt.Sprintf("Contents of file %s:\nExample file content here...", path),
			Metadata: map[string]interface{}{
				"path": path,
			},
		}

	case "list_directory":
		path, _ := parameters["path"].(string)
		return &ToolResult{
			Success: true,
			Content: fmt.Sprintf("Contents of directory %s:\nfile1.txt\nfile2.txt\nsubdir/", path),
			Metadata: map[string]interface{}{
				"path": path,
			},
		}

	case "echo":
		message, _ := parameters["message"].(string)
		return &ToolResult{
			Success: true,
			Content: fmt.Sprintf("Echo: %s", message),
			Metadata: map[string]interface{}{
				"original_message": message,
			},
		}

	default:
		return &ToolResult{
			Success: false,
			Error:   fmt.Sprintf("unknown tool: %s", toolName),
		}
	}
}

// MCPClientRegistry manages multiple MCP clients
type MCPClientRegistry struct {
	clients map[string]MCPClient
	logger  *zap.Logger
	mutex   sync.RWMutex
}

// NewMCPClientRegistry creates a new MCP client registry
func NewMCPClientRegistry(logger *zap.Logger) *MCPClientRegistry {
	return &MCPClientRegistry{
		clients: make(map[string]MCPClient),
		logger:  logger,
	}
}

// RegisterClient registers an MCP client
func (r *MCPClientRegistry) RegisterClient(name string, client MCPClient) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.clients[name] = client
}

// GetClient returns a client by name
func (r *MCPClientRegistry) GetClient(name string) (MCPClient, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	client, exists := r.clients[name]
	if !exists {
		return nil, fmt.Errorf("MCP client not found: %s", name)
	}
	return client, nil
}

// ListClients returns all registered client names
func (r *MCPClientRegistry) ListClients() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	names := make([]string, 0, len(r.clients))
	for name := range r.clients {
		names = append(names, name)
	}
	return names
}

// ExecuteTool executes a tool on the appropriate client
func (r *MCPClientRegistry) ExecuteTool(ctx context.Context, serverName, toolName string, parameters map[string]interface{}) (*ToolResult, error) {
	client, err := r.GetClient(serverName)
	if err != nil {
		return &ToolResult{
			Success:   false,
			Error:     err.Error(),
			Timestamp: time.Now(),
		}, nil
	}

	return client.ExecuteTool(ctx, toolName, parameters)
}

// GetAllTools returns all tools from all connected servers
func (r *MCPClientRegistry) GetAllTools(ctx context.Context) (map[string][]Tool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	allTools := make(map[string][]Tool)

	for name, client := range r.clients {
		if client.IsConnected() {
			tools, err := client.ListTools(ctx)
			if err != nil {
				r.logger.Warn("Failed to get tools from client",
					zap.String("client", name),
					zap.Error(err),
				)
				continue
			}
			allTools[name] = tools
		}
	}

	return allTools, nil
}

// NewSimpleMCPClient creates a simplified MCP client for backwards compatibility
func NewSimpleMCPClient(logger *zap.Logger) MCPClient {
	return NewMCPClient(logger)
}

// Enhanced Tool utility methods following official MCP SDK pattern

// ValidateSchema validates the tool's parameter schema
func (t *Tool) ValidateSchema() error {
	if t.Name == "" {
		return fmt.Errorf("tool name is required")
	}
	if t.Server == "" {
		return fmt.Errorf("tool server is required")
	}
	if t.Schema != nil {
		return t.Schema.Validate()
	}
	return nil
}

// ConvertToMCPFormat converts tool to official MCP format
func (t *Tool) ConvertToMCPFormat() map[string]interface{} {
	result := map[string]interface{}{
		"name":        t.Name,
		"description": t.Description,
	}

	if t.Schema != nil {
		result["inputSchema"] = t.Schema.ToMap()
	} else if t.Parameters.Type != "" {
		// Legacy conversion
		result["inputSchema"] = map[string]interface{}{
			"type":       t.Parameters.Type,
			"properties": t.Parameters.Properties,
			"required":   t.Parameters.Required,
		}
	}

	if t.Metadata != nil {
		result["metadata"] = t.Metadata
	}

	return result
}

// GetSchemaProperty gets a property from the schema
func (t *Tool) GetSchemaProperty(propertyName string) *SchemaProperty {
	if t.Schema != nil && t.Schema.Properties != nil {
		return t.Schema.Properties[propertyName]
	}
	return nil
}

// IsRequired checks if a parameter is required
func (t *Tool) IsRequired(paramName string) bool {
	if t.Schema != nil {
		for _, req := range t.Schema.Required {
			if req == paramName {
				return true
			}
		}
	}
	return false
}

// GetTimeout returns tool timeout or default
func (t *Tool) GetTimeout() time.Duration {
	if t.Timeout > 0 {
		return time.Duration(t.Timeout) * time.Millisecond
	}
	return 30 * time.Second // Default timeout
}

// Validate validates the tool schema structure
func (ts *ToolSchema) Validate() error {
	if ts.Type == "" {
		return fmt.Errorf("schema type is required")
	}

	// Validate properties if present
	if ts.Properties != nil {
		for name, prop := range ts.Properties {
			if err := prop.validate(name); err != nil {
				return fmt.Errorf("property %s: %w", name, err)
			}
		}
	}

	return nil
}

// ToMap converts schema to map representation
func (ts *ToolSchema) ToMap() map[string]interface{} {
	result := map[string]interface{}{
		"type": ts.Type,
	}

	if ts.Properties != nil {
		props := make(map[string]interface{})
		for name, prop := range ts.Properties {
			props[name] = prop.toMap()
		}
		result["properties"] = props
	}

	if len(ts.Required) > 0 {
		result["required"] = ts.Required
	}

	if ts.Title != "" {
		result["title"] = ts.Title
	}

	if ts.Description != "" {
		result["description"] = ts.Description
	}

	result["additionalProperties"] = ts.AdditionalProperties

	return result
}

// validate validates a schema property
func (sp *SchemaProperty) validate(name string) error {
	if sp.Type == "" {
		return fmt.Errorf("type is required")
	}

	validTypes := []string{"string", "number", "integer", "boolean", "array", "object", "null"}
	isValid := false
	for _, vt := range validTypes {
		if sp.Type == vt {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid type: %s", sp.Type)
	}

	return nil
}

// toMap converts property to map representation
func (sp *SchemaProperty) toMap() map[string]interface{} {
	result := map[string]interface{}{
		"type": sp.Type,
	}

	if sp.Description != "" {
		result["description"] = sp.Description
	}

	if sp.Default != nil {
		result["default"] = sp.Default
	}

	if len(sp.Enum) > 0 {
		result["enum"] = sp.Enum
	}

	if sp.Pattern != "" {
		result["pattern"] = sp.Pattern
	}

	if sp.MinLength > 0 {
		result["minLength"] = sp.MinLength
	}

	if sp.MaxLength > 0 {
		result["maxLength"] = sp.MaxLength
	}

	if sp.Minimum != 0 {
		result["minimum"] = sp.Minimum
	}

	if sp.Maximum != 0 {
		result["maximum"] = sp.Maximum
	}

	if sp.Items != nil {
		result["items"] = sp.Items.toMap()
	}

	if sp.Properties != nil {
		props := make(map[string]interface{})
		for name, prop := range sp.Properties {
			props[name] = prop.toMap()
		}
		result["properties"] = props
	}

	if len(sp.Required) > 0 {
		result["required"] = sp.Required
	}

	return result
}

// Enhanced ToolResult utility methods

// IsSuccess returns whether the tool execution was successful
func (tr *ToolResult) IsSuccess() bool {
	return tr.Success
}

// GetContentAsString returns content as string
func (tr *ToolResult) GetContentAsString() string {
	if tr.Content == nil {
		return ""
	}

	if str, ok := tr.Content.(string); ok {
		return str
	}

	// Try to marshal to JSON if it's not a string
	if data, err := json.Marshal(tr.Content); err == nil {
		return string(data)
	}

	return fmt.Sprintf("%v", tr.Content)
}

// GetContentAsJSON returns content as JSON object
func (tr *ToolResult) GetContentAsJSON() (map[string]interface{}, error) {
	var result map[string]interface{}

	if tr.Content == nil {
		return result, fmt.Errorf("content is nil")
	}

	// If already a map
	if m, ok := tr.Content.(map[string]interface{}); ok {
		return m, nil
	}

	// Try to parse as JSON string
	if str, ok := tr.Content.(string); ok {
		if err := json.Unmarshal([]byte(str), &result); err != nil {
			return nil, fmt.Errorf("failed to parse content as JSON: %w", err)
		}
		return result, nil
	}

	// Marshal and unmarshal to convert to map
	data, err := json.Marshal(tr.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content: %w", err)
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal content: %w", err)
	}

	return result, nil
}

// HasError returns whether the result contains an error
func (tr *ToolResult) HasError() bool {
	return tr.Error != "" || !tr.Success
}

// GetFormattedError returns formatted error message
func (tr *ToolResult) GetFormattedError() string {
	if tr.Error == "" {
		return ""
	}

	if tr.ErrorCode != "" {
		return fmt.Sprintf("[%s] %s", tr.ErrorCode, tr.Error)
	}

	return tr.Error
}

// SetAsyncProgress sets progress for async operations
func (tr *ToolResult) SetAsyncProgress(progress float64, status string) {
	tr.IsAsync = true
	tr.Progress = progress
	tr.Status = status
}

// IsCompleted returns whether async operation is completed
func (tr *ToolResult) IsCompleted() bool {
	return !tr.IsAsync || tr.Status == "completed" || tr.Status == "failed"
}

// GetDurationMs returns duration in milliseconds
func (tr *ToolResult) GetDurationMs() int64 {
	return tr.Duration.Milliseconds()
}

// AddMetadata adds metadata to the result
func (tr *ToolResult) AddMetadata(key string, value interface{}) {
	if tr.Metadata == nil {
		tr.Metadata = make(map[string]interface{})
	}
	tr.Metadata[key] = value
}

// GetMetadata gets metadata value
func (tr *ToolResult) GetMetadata(key string) interface{} {
	if tr.Metadata == nil {
		return nil
	}
	return tr.Metadata[key]
}

// ToLegacyFormat converts to legacy ToolResult format for compatibility
func (tr *ToolResult) ToLegacyFormat() map[string]interface{} {
	return map[string]interface{}{
		"success":   tr.Success,
		"content":   tr.GetContentAsString(),
		"error":     tr.Error,
		"metadata":  tr.Metadata,
		"duration":  tr.Duration.Milliseconds(),
		"timestamp": tr.Timestamp.Unix(),
	}
}