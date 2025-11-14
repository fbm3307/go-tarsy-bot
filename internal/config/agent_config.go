package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
	"go.uber.org/zap"

	"github.com/codeready/go-tarsy-bot/internal/integrations/mcp"
)

// AgentConfiguration represents the complete agent configuration from YAML
type AgentConfiguration struct {
	Agents     map[string]*AgentDefinition `yaml:"agents" json:"agents"`
	MCPServers map[string]*MCPServerConfig `yaml:"mcp_servers" json:"mcp_servers"`
	Global     *GlobalConfig               `yaml:"global,omitempty" json:"global,omitempty"`
	Metadata   *ConfigMetadata             `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// AgentDefinition represents a single agent configuration
type AgentDefinition struct {
	Name         string                 `yaml:"name" json:"name"`
	Type         string                 `yaml:"type" json:"type"` // "configurable", "kubernetes", etc.
	Description  string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Version      string                 `yaml:"version,omitempty" json:"version,omitempty"`
	Enabled      bool                   `yaml:"enabled" json:"enabled"`

	// Agent capabilities and processing
	Capabilities []string               `yaml:"capabilities" json:"capabilities"`
	AlertTypes   []string               `yaml:"alert_types" json:"alert_types"`
	MCPServers   []string               `yaml:"mcp_servers" json:"mcp_servers"`

	// Processing instructions
	Instructions *InstructionConfig     `yaml:"instructions" json:"instructions"`

	// Agent-specific settings
	Settings     *AgentSettings         `yaml:"settings,omitempty" json:"settings,omitempty"`

	// Variables and customization
	Variables    map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`

	// Advanced configuration
	Prompts      map[string]string      `yaml:"prompts,omitempty" json:"prompts,omitempty"`
	Hooks        *HookConfig            `yaml:"hooks,omitempty" json:"hooks,omitempty"`
}

// InstructionConfig represents the three-tier instruction system
type InstructionConfig struct {
	General  string   `yaml:"general" json:"general"`
	MCP      string   `yaml:"mcp,omitempty" json:"mcp,omitempty"`
	Custom   []string `yaml:"custom,omitempty" json:"custom,omitempty"`
	Template string   `yaml:"template,omitempty" json:"template,omitempty"`
}

// AgentSettings contains agent-specific configuration
type AgentSettings struct {
	MaxIterations     int           `yaml:"max_iterations" json:"max_iterations"`
	Temperature       float32       `yaml:"temperature" json:"temperature"`
	MaxTokens         int           `yaml:"max_tokens" json:"max_tokens"`
	Timeout           time.Duration `yaml:"timeout" json:"timeout"`
	RetryAttempts     int           `yaml:"retry_attempts" json:"retry_attempts"`
	EnableDebugMode   bool          `yaml:"enable_debug_mode" json:"enable_debug_mode"`
	LLMProvider       string        `yaml:"llm_provider,omitempty" json:"llm_provider,omitempty"`
	MCPEnabled        bool          `yaml:"mcp_enabled" json:"mcp_enabled"`

	// Iteration control
	IterationStrategy string        `yaml:"iteration_strategy" json:"iteration_strategy"` // "react", "stage", "final_analysis"
	EnableToolUse     bool          `yaml:"enable_tool_use" json:"enable_tool_use"`
	ToolTimeout       time.Duration `yaml:"tool_timeout" json:"tool_timeout"`
}

// MCPServerConfig represents MCP server configuration in YAML
type MCPServerConfig struct {
	Name        string                 `yaml:"name" json:"name"`
	Command     string                 `yaml:"command" json:"command"`
	Args        []string               `yaml:"args,omitempty" json:"args,omitempty"`
	Env         map[string]string      `yaml:"env,omitempty" json:"env,omitempty"`
	WorkingDir  string                 `yaml:"working_dir,omitempty" json:"working_dir,omitempty"`
	Timeout     time.Duration          `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	AutoStart   bool                   `yaml:"auto_start" json:"auto_start"`

	// Health and lifecycle
	HealthCheck *HealthCheckConfig     `yaml:"health_check,omitempty" json:"health_check,omitempty"`
	Restart     *RestartConfig         `yaml:"restart,omitempty" json:"restart,omitempty"`

	// Additional options
	Options     map[string]interface{} `yaml:"options,omitempty" json:"options,omitempty"`
}

// HealthCheckConfig represents health check configuration
type HealthCheckConfig struct {
	Enabled   bool          `yaml:"enabled" json:"enabled"`
	Interval  time.Duration `yaml:"interval" json:"interval"`
	Timeout   time.Duration `yaml:"timeout" json:"timeout"`
	Retries   int           `yaml:"retries" json:"retries"`
}

// RestartConfig represents restart policy configuration
type RestartConfig struct {
	Policy        string        `yaml:"policy" json:"policy"` // "never", "on_failure", "always"
	MaxAttempts   int           `yaml:"max_attempts" json:"max_attempts"`
	BackoffDelay  time.Duration `yaml:"backoff_delay" json:"backoff_delay"`
	RestartDelay  time.Duration `yaml:"restart_delay" json:"restart_delay"`
}

// HookConfig represents hooks configuration for agents
type HookConfig struct {
	PreProcessing  []string `yaml:"pre_processing,omitempty" json:"pre_processing,omitempty"`
	PostProcessing []string `yaml:"post_processing,omitempty" json:"post_processing,omitempty"`
	OnError        []string `yaml:"on_error,omitempty" json:"on_error,omitempty"`
	OnSuccess      []string `yaml:"on_success,omitempty" json:"on_success,omitempty"`
}

// GlobalConfig represents global configuration settings
type GlobalConfig struct {
	DefaultLLMProvider    string        `yaml:"default_llm_provider" json:"default_llm_provider"`
	DefaultMaxIterations  int           `yaml:"default_max_iterations" json:"default_max_iterations"`
	DefaultTimeout        time.Duration `yaml:"default_timeout" json:"default_timeout"`
	EnableMetrics         bool          `yaml:"enable_metrics" json:"enable_metrics"`
	EnableTracing         bool          `yaml:"enable_tracing" json:"enable_tracing"`
	LogLevel              string        `yaml:"log_level" json:"log_level"`

	// Environment variable templating
	TemplateResolver      *TemplateConfig `yaml:"template_resolver,omitempty" json:"template_resolver,omitempty"`
}

// TemplateConfig represents template resolution configuration
type TemplateConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	EnvPrefix         string   `yaml:"env_prefix,omitempty" json:"env_prefix,omitempty"`
	RequiredVars      []string `yaml:"required_vars,omitempty" json:"required_vars,omitempty"`
	DefaultValues     map[string]string `yaml:"default_values,omitempty" json:"default_values,omitempty"`
	FailOnMissingVars bool     `yaml:"fail_on_missing_vars" json:"fail_on_missing_vars"`
}

// ConfigMetadata represents metadata about the configuration
type ConfigMetadata struct {
	Version     string    `yaml:"version" json:"version"`
	CreatedAt   time.Time `yaml:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt   time.Time `yaml:"updated_at,omitempty" json:"updated_at,omitempty"`
	Description string    `yaml:"description,omitempty" json:"description,omitempty"`
	Author      string    `yaml:"author,omitempty" json:"author,omitempty"`
}

// AgentConfigLoader handles loading and managing agent configurations
type AgentConfigLoader struct {
	logger           *zap.Logger
	templateResolver *TemplateResolver
	configPath       string
	watchEnabled     bool
}

// NewAgentConfigLoader creates a new agent configuration loader
func NewAgentConfigLoader(logger *zap.Logger, configPath string) *AgentConfigLoader {
	return &AgentConfigLoader{
		logger:           logger,
		templateResolver: NewTemplateResolver(logger),
		configPath:       configPath,
		watchEnabled:     false,
	}
}

// LoadConfiguration loads agent configuration from YAML file
func (loader *AgentConfigLoader) LoadConfiguration() (*AgentConfiguration, error) {
	if loader.configPath == "" {
		return nil, fmt.Errorf("configuration path not specified")
	}

	// Check if file exists
	if _, err := os.Stat(loader.configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", loader.configPath)
	}

	loader.logger.Info("Loading agent configuration", zap.String("path", loader.configPath))

	// Read configuration file
	data, err := os.ReadFile(loader.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Resolve environment variable templates
	resolvedData, err := loader.templateResolver.ResolveTemplate(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve templates: %w", err)
	}

	// Parse YAML
	var config AgentConfiguration
	if err := yaml.Unmarshal([]byte(resolvedData), &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML configuration: %w", err)
	}

	// Set defaults and validate
	if err := loader.setDefaults(&config); err != nil {
		return nil, fmt.Errorf("failed to set defaults: %w", err)
	}

	if err := loader.validateConfiguration(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	loader.logger.Info("Agent configuration loaded successfully",
		zap.Int("agents", len(config.Agents)),
		zap.Int("mcp_servers", len(config.MCPServers)),
	)

	return &config, nil
}

// setDefaults sets default values for configuration
func (loader *AgentConfigLoader) setDefaults(config *AgentConfiguration) error {
	// Set global defaults
	if config.Global == nil {
		config.Global = &GlobalConfig{}
	}

	if config.Global.DefaultLLMProvider == "" {
		config.Global.DefaultLLMProvider = "openai"
	}

	if config.Global.DefaultMaxIterations == 0 {
		config.Global.DefaultMaxIterations = 10
	}

	if config.Global.DefaultTimeout == 0 {
		config.Global.DefaultTimeout = 5 * time.Minute
	}

	// Set agent defaults
	for name, agent := range config.Agents {
		agent.Name = name

		if agent.Settings == nil {
			agent.Settings = &AgentSettings{}
		}

		settings := agent.Settings
		if settings.MaxIterations == 0 {
			settings.MaxIterations = config.Global.DefaultMaxIterations
		}

		if settings.Temperature == 0 {
			settings.Temperature = 0.7
		}

		if settings.MaxTokens == 0 {
			settings.MaxTokens = 4096
		}

		if settings.Timeout == 0 {
			settings.Timeout = config.Global.DefaultTimeout
		}

		if settings.RetryAttempts == 0 {
			settings.RetryAttempts = 3
		}

		if settings.LLMProvider == "" {
			settings.LLMProvider = config.Global.DefaultLLMProvider
		}

		if settings.IterationStrategy == "" {
			settings.IterationStrategy = "react"
		}

		if settings.ToolTimeout == 0 {
			settings.ToolTimeout = 30 * time.Second
		}

		settings.MCPEnabled = true
		settings.EnableToolUse = true
	}

	// Set MCP server defaults
	for name, server := range config.MCPServers {
		server.Name = name

		if server.Timeout == 0 {
			server.Timeout = 30 * time.Second
		}

		if server.HealthCheck == nil {
			server.HealthCheck = &HealthCheckConfig{
				Enabled:  true,
				Interval: 30 * time.Second,
				Timeout:  10 * time.Second,
				Retries:  3,
			}
		}

		if server.Restart == nil {
			server.Restart = &RestartConfig{
				Policy:       "on_failure",
				MaxAttempts:  3,
				BackoffDelay: 5 * time.Second,
				RestartDelay: 2 * time.Second,
			}
		}
	}

	return nil
}

// validateConfiguration validates the loaded configuration
func (loader *AgentConfigLoader) validateConfiguration(config *AgentConfiguration) error {
	// Validate agents
	for name, agent := range config.Agents {
		if agent.Type == "" {
			return fmt.Errorf("agent %s: type is required", name)
		}

		if len(agent.AlertTypes) == 0 {
			return fmt.Errorf("agent %s: at least one alert type must be specified", name)
		}

		if agent.Instructions == nil || agent.Instructions.General == "" {
			return fmt.Errorf("agent %s: general instructions are required", name)
		}

		// Validate MCP server references
		for _, serverName := range agent.MCPServers {
			if _, exists := config.MCPServers[serverName]; !exists {
				return fmt.Errorf("agent %s references unknown MCP server: %s", name, serverName)
			}
		}

		// Validate settings
		if agent.Settings != nil {
			if agent.Settings.MaxIterations <= 0 {
				return fmt.Errorf("agent %s: max_iterations must be greater than 0", name)
			}

			if agent.Settings.Temperature < 0 || agent.Settings.Temperature > 2 {
				return fmt.Errorf("agent %s: temperature must be between 0 and 2", name)
			}

			if agent.Settings.MaxTokens <= 0 {
				return fmt.Errorf("agent %s: max_tokens must be greater than 0", name)
			}
		}
	}

	// Validate MCP servers
	for name, server := range config.MCPServers {
		if server.Command == "" {
			return fmt.Errorf("MCP server %s: command is required", name)
		}

		// Validate restart policy
		if server.Restart != nil {
			validPolicies := []string{"never", "on_failure", "always"}
			policyValid := false
			for _, policy := range validPolicies {
				if server.Restart.Policy == policy {
					policyValid = true
					break
				}
			}
			if !policyValid {
				return fmt.Errorf("MCP server %s: invalid restart policy '%s'", name, server.Restart.Policy)
			}
		}
	}

	return nil
}

// ConvertToMCPServerConfig converts YAML MCP config to internal format
func (loader *AgentConfigLoader) ConvertToMCPServerConfig(yamlConfig *MCPServerConfig) *mcp.ServerConfig {
	return &mcp.ServerConfig{
		Name:       yamlConfig.Name,
		Command:    yamlConfig.Command,
		Args:       yamlConfig.Args,
		Env:        yamlConfig.Env,
		WorkingDir: yamlConfig.WorkingDir,
		Timeout:    yamlConfig.Timeout,
		Options:    yamlConfig.Options,
	}
}

// GetAgentNames returns all configured agent names
func (config *AgentConfiguration) GetAgentNames() []string {
	names := make([]string, 0, len(config.Agents))
	for name := range config.Agents {
		names = append(names, name)
	}
	return names
}

// GetEnabledAgents returns only enabled agents
func (config *AgentConfiguration) GetEnabledAgents() map[string]*AgentDefinition {
	enabled := make(map[string]*AgentDefinition)
	for name, agent := range config.Agents {
		if agent.Enabled {
			enabled[name] = agent
		}
	}
	return enabled
}

// GetAgentByType returns agents of a specific type
func (config *AgentConfiguration) GetAgentByType(agentType string) []*AgentDefinition {
	var agents []*AgentDefinition
	for _, agent := range config.Agents {
		if agent.Type == agentType {
			agents = append(agents, agent)
		}
	}
	return agents
}

// GetAgentByAlertType returns agents that handle a specific alert type
func (config *AgentConfiguration) GetAgentByAlertType(alertType string) []*AgentDefinition {
	var agents []*AgentDefinition
	for _, agent := range config.Agents {
		for _, at := range agent.AlertTypes {
			if at == alertType {
				agents = append(agents, agent)
				break
			}
		}
	}
	return agents
}

// GetMCPServersForAgent returns MCP servers assigned to an agent
func (config *AgentConfiguration) GetMCPServersForAgent(agentName string) []*MCPServerConfig {
	agent, exists := config.Agents[agentName]
	if !exists {
		return nil
	}

	var servers []*MCPServerConfig
	for _, serverName := range agent.MCPServers {
		if server, exists := config.MCPServers[serverName]; exists {
			servers = append(servers, server)
		}
	}
	return servers
}

// LoadConfigurationFromPath loads configuration from a specific path
func LoadConfigurationFromPath(logger *zap.Logger, configPath string) (*AgentConfiguration, error) {
	loader := NewAgentConfigLoader(logger, configPath)
	return loader.LoadConfiguration()
}

// GetConfigurationExample returns an example YAML configuration
func GetConfigurationExample() string {
	return `# TARSy Agent Configuration
metadata:
  version: "1.0"
  description: "TARSy-bot agent configuration"
  author: "SRE Team"

global:
  default_llm_provider: "openai"
  default_max_iterations: 10
  default_timeout: "5m"
  enable_metrics: true
  enable_tracing: true
  log_level: "info"
  template_resolver:
    enabled: true
    env_prefix: "TARSY_"
    fail_on_missing_vars: false

mcp_servers:
  kubernetes-server:
    command: "kubectl-mcp-server"
    args: ["--kubeconfig", "${KUBECONFIG}"]
    env:
      KUBECONFIG: "${KUBECONFIG}"
    enabled: true
    auto_start: true
    health_check:
      enabled: true
      interval: "30s"
      timeout: "10s"
      retries: 3
    restart:
      policy: "on_failure"
      max_attempts: 3
      backoff_delay: "5s"

  security-server:
    command: "security-tools-server"
    args: ["--config", "/etc/security/config.yaml"]
    enabled: true
    auto_start: true

agents:
  kubernetes-agent:
    type: "configurable"
    description: "Kubernetes incident response agent"
    enabled: true
    capabilities: ["kubernetes", "security", "networking"]
    alert_types: ["kubernetes", "k8s", "pod-failure", "deployment-failure"]
    mcp_servers: ["kubernetes-server", "security-server"]
    instructions:
      general: "You are a Kubernetes expert specializing in incident response and troubleshooting."
      mcp: "Use kubectl and security tools to investigate cluster issues."
      custom:
        - "Always check pod status and logs first"
        - "Examine recent events and changes"
        - "Consider security implications"
    settings:
      max_iterations: 15
      temperature: 0.7
      max_tokens: 4096
      timeout: "10m"
      retry_attempts: 3
      llm_provider: "openai"
      iteration_strategy: "react"
      enable_tool_use: true
      tool_timeout: "60s"
    variables:
      default_namespace: "default"
      log_lines: 100

  security-agent:
    type: "configurable"
    description: "Security incident response agent"
    enabled: true
    capabilities: ["security", "compliance", "threat-analysis"]
    alert_types: ["security", "intrusion", "malware", "compliance"]
    mcp_servers: ["security-server"]
    instructions:
      general: "You are a cybersecurity expert focusing on threat analysis and incident response."
      mcp: "Use security tools to analyze threats and recommend remediation."
    settings:
      max_iterations: 12
      temperature: 0.5
      iteration_strategy: "react"
`
}

// SaveConfigurationExample saves an example configuration to a file
func SaveConfigurationExample(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	example := GetConfigurationExample()
	if err := os.WriteFile(path, []byte(example), 0644); err != nil {
		return fmt.Errorf("failed to write example configuration: %w", err)
	}

	return nil
}