package models

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/datatypes"
)

// MessageRole represents supported LLM message roles
type MessageRole string

const (
	MessageRoleSystem    MessageRole = "system"
	MessageRoleUser      MessageRole = "user"
	MessageRoleAssistant MessageRole = "assistant"
)

// LLMMessage represents an individual message in LLM conversation with role validation
type LLMMessage struct {
	Role    MessageRole `json:"role" gorm:"type:varchar(20);not null"`
	Content string      `json:"content" gorm:"type:text;not null"`
}

// Validate validates the LLM message
func (m *LLMMessage) Validate() error {
	if m.Content == "" {
		return fmt.Errorf("message content cannot be empty")
	}
	return nil
}

// LLMConversation represents a complete conversation thread with structured messages
type LLMConversation struct {
	Messages []LLMMessage `json:"messages"`
}

// Validate validates the conversation
func (c *LLMConversation) Validate() error {
	if len(c.Messages) == 0 {
		return fmt.Errorf("conversation must have at least one message")
	}
	if c.Messages[0].Role != MessageRoleSystem {
		return fmt.Errorf("conversation must start with system message")
	}
	return nil
}

// AddMessage adds a message to the conversation with validation
func (c *LLMConversation) AddMessage(message LLMMessage) error {
	if err := message.Validate(); err != nil {
		return err
	}
	c.Messages = append(c.Messages, message)
	return nil
}

// AppendAssistantMessage adds an assistant message to the conversation
func (c *LLMConversation) AppendAssistantMessage(content string) error {
	message := LLMMessage{Role: MessageRoleAssistant, Content: content}
	return c.AddMessage(message)
}

// AppendObservation adds a user observation message to the conversation
func (c *LLMConversation) AppendObservation(observation string) error {
	message := LLMMessage{Role: MessageRoleUser, Content: observation}
	return c.AddMessage(message)
}

// GetLatestAssistantMessage gets the most recent assistant message
func (c *LLMConversation) GetLatestAssistantMessage() *LLMMessage {
	for i := len(c.Messages) - 1; i >= 0; i-- {
		if c.Messages[i].Role == MessageRoleAssistant {
			return &c.Messages[i]
		}
	}
	return nil
}

// LLMInteraction represents an enhanced LLM interaction model with structured conversation storage
// This matches the Python SQLModel implementation for both runtime and database operations
type LLMInteraction struct {
	// Primary key and identifiers
	InteractionID string `json:"interaction_id" gorm:"primaryKey;type:varchar(255);not null"`
	SessionID     string `json:"session_id" gorm:"type:varchar(255);not null;index"`
	StageExecutionID *string `json:"stage_execution_id,omitempty" gorm:"type:varchar(255);index"`

	// Timing and status
	TimestampUs  int64  `json:"timestamp_us" gorm:"not null;index"`
	DurationMs   int    `json:"duration_ms" gorm:"default:0"`
	Success      bool   `json:"success" gorm:"default:true"`
	ErrorMessage *string `json:"error_message,omitempty" gorm:"type:text"`

	// LLM-specific fields
	ModelName   string   `json:"model_name" gorm:"type:varchar(255);not null"`
	Provider    *string  `json:"provider,omitempty" gorm:"type:varchar(50)"`
	Temperature *float64 `json:"temperature,omitempty"`

	// Structured conversation storage (JSONB in PostgreSQL, JSON in other DBs)
	Conversation        *LLMConversation `json:"conversation,omitempty" gorm:"type:jsonb"`
	ConversationContent string          `json:"conversation_content,omitempty" gorm:"type:text"` // Flattened for WebSocket

	// Token usage tracking fields
	InputTokens  *int `json:"input_tokens,omitempty" gorm:"check:input_tokens >= 0"`
	OutputTokens *int `json:"output_tokens,omitempty" gorm:"check:output_tokens >= 0"`
	TotalTokens  *int `json:"total_tokens,omitempty" gorm:"check:total_tokens >= 0"`

	// Cost estimation
	EstimatedCost *float64 `json:"estimated_cost,omitempty"`

	// Common GORM fields
	CreatedAt time.Time `json:"created_at,omitempty" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at,omitempty" gorm:"autoUpdateTime"`
}

// TableName returns the table name for GORM
func (LLMInteraction) TableName() string {
	return "llm_interactions"
}

// GetStepDescription generates a human-readable description of this LLM step
func (li *LLMInteraction) GetStepDescription() string {
	if li.Provider != nil {
		return fmt.Sprintf("LLM analysis using %s (%s)", li.ModelName, *li.Provider)
	}
	return fmt.Sprintf("LLM analysis using %s", li.ModelName)
}

// SetConversationContent flattens the conversation for WebSocket transmission
func (li *LLMInteraction) SetConversationContent() {
	if li.Conversation != nil {
		// Convert conversation to a flattened string format
		content := ""
		for i, msg := range li.Conversation.Messages {
			if i > 0 {
				content += "\n"
			}
			content += fmt.Sprintf("[%s] %s", msg.Role, msg.Content)
		}
		li.ConversationContent = content
	}
}

// MCPInteraction represents a unified MCP interaction model for both runtime processing and database storage
type MCPInteraction struct {
	// Primary key and identifiers
	CommunicationID string `json:"communication_id" gorm:"primaryKey;type:varchar(255);not null"`
	RequestID       string `json:"request_id" gorm:"type:varchar(255);not null"`
	SessionID       string `json:"session_id" gorm:"type:varchar(255);not null;index"`
	StageExecutionID *string `json:"stage_execution_id,omitempty" gorm:"type:varchar(255);index"`

	// Timing and status
	TimestampUs  int64   `json:"timestamp_us" gorm:"not null;index"`
	DurationMs   int     `json:"duration_ms" gorm:"default:0"`
	Success      bool    `json:"success" gorm:"default:true"`
	ErrorMessage *string `json:"error_message,omitempty" gorm:"type:text"`

	// MCP-specific fields
	ServerName        string `json:"server_name" gorm:"type:varchar(255);not null"`
	CommunicationType string `json:"communication_type" gorm:"type:varchar(50);not null"`
	ToolName          *string `json:"tool_name,omitempty" gorm:"type:varchar(255)"`

	// Step description for hooks
	StepDescription string `json:"step_description" gorm:"type:text;not null"`

	// Tool arguments and results (JSONB in PostgreSQL, JSON in other DBs)
	ToolArguments datatypes.JSON `json:"tool_arguments,omitempty" gorm:"type:jsonb"`
	ToolResult    datatypes.JSON `json:"tool_result,omitempty" gorm:"type:jsonb"`

	// Request and response for debugging
	Request  datatypes.JSON `json:"request,omitempty" gorm:"type:jsonb"`
	Response datatypes.JSON `json:"response,omitempty" gorm:"type:jsonb"`

	// Common GORM fields
	CreatedAt time.Time `json:"created_at,omitempty" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at,omitempty" gorm:"autoUpdateTime"`
}

// TableName returns the table name for GORM
func (MCPInteraction) TableName() string {
	return "mcp_communications"
}

// GetStepDescription generates a human-readable description of this MCP step
func (mi *MCPInteraction) GetStepDescription() string {
	if mi.StepDescription != "" {
		return mi.StepDescription
	}

	if mi.ToolName != nil {
		return fmt.Sprintf("MCP tool call: %s on %s", *mi.ToolName, mi.ServerName)
	}

	switch mi.CommunicationType {
	case "tool_list":
		return fmt.Sprintf("MCP list tools from %s", mi.ServerName)
	case "tool_call":
		return fmt.Sprintf("MCP tool call on %s", mi.ServerName)
	default:
		return fmt.Sprintf("MCP communication with %s", mi.ServerName)
	}
}

// Factory functions for creating interactions

// NewLLMInteraction creates a new LLM interaction with defaults
func NewLLMInteraction(sessionID, modelName string) *LLMInteraction {
	return &LLMInteraction{
		InteractionID: generateInteractionID(),
		SessionID:     sessionID,
		ModelName:     modelName,
		TimestampUs:   GetCurrentTimestampUs(),
		Success:       true,
	}
}

// NewMCPInteraction creates a new MCP interaction with defaults
func NewMCPInteraction(sessionID, requestID, serverName, communicationType string) *MCPInteraction {
	return &MCPInteraction{
		CommunicationID:   generateCommunicationID(),
		RequestID:         requestID,
		SessionID:         sessionID,
		ServerName:        serverName,
		CommunicationType: communicationType,
		TimestampUs:       GetCurrentTimestampUs(),
		Success:           true,
	}
}

// Helper functions

func generateInteractionID() string {
	return fmt.Sprintf("llm_%d_%s", time.Now().UnixNano(), generateRandomID(8))
}

func generateCommunicationID() string {
	return fmt.Sprintf("mcp_%d_%s", time.Now().UnixNano(), generateRandomID(8))
}

func generateRandomID(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

// JSON marshaling for GORM JSONB support

// Scan implements the sql.Scanner interface for LLMConversation
func (c *LLMConversation) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, c)
	case string:
		return json.Unmarshal([]byte(v), c)
	default:
		return fmt.Errorf("cannot scan %T into LLMConversation", value)
	}
}

// Value implements the driver.Valuer interface for LLMConversation
func (c LLMConversation) Value() (interface{}, error) {
	if len(c.Messages) == 0 {
		return nil, nil
	}
	return json.Marshal(c)
}