# EP-0006: Configuration-Based Agents - Design Document

**Status:** Implemented  
**Created:** 2025-07-29
**Implemented:** 2025-07-29
**Requirements:** `docs/enhancements/implemented/EP-0006-configurable-agents-requirements.md`

---

## Design Principles

**Core Guidelines:**
- **Balanced Simplicity**: Use configuration-driven approach that's simple to deploy while maintaining BaseAgent's powerful capabilities
- **Maintainability**: Extend existing architecture without breaking changes, preserve familiar patterns
- **Reliability**: Fail-fast validation prevents configuration errors from affecting alert processing
- **Compatibility**: Full backward compatibility with existing hardcoded agents and MCP servers

---

## Implementation Strategy

### Architecture Approach
- [x] **Extension**: Extend existing components with new functionality  

**Rationale**: The current agent architecture is solid. We're adding configuration-based capabilities alongside the existing hardcoded approach, not replacing it.

### Component Changes

**Components to Replace:**
- None - Full backward compatibility preserved

**Components to Extend:** 
- `backend/tarsy/services/agent_registry.py`: Accept parsed agent configs and convert to alert type mappings
- `backend/tarsy/services/mcp_server_registry.py`: Accept parsed MCP server configs and merge with built-in servers
- `backend/tarsy/services/agent_factory.py`: Add ConfigurableAgent creation capability
- `backend/tarsy/config/settings.py`: Add agent_config_path setting

**New Components:**
- `backend/tarsy/agents/configurable_agent.py`: Configuration-driven agent implementation extending BaseAgent
- `backend/tarsy/config/agent_config.py`: Centralized configuration loading, validation, and parsing logic (ConfigurationLoader class)
- `backend/tarsy/models/agent_config.py`: Pydantic models for agent and MCP server configuration

### Compatibility Strategy
- **External API Compatibility**: Not Required - No external API changes
- **Database Compatibility**: Not Required - No database schema changes
- **Configuration Compatibility**: Full backward compatibility - existing .env settings unchanged, new AGENT_CONFIG_PATH is optional

---

## Technical Design

### Data Structures

**New Data Models:**
```python
class AgentConfigModel(BaseModel):
    """Configuration model for a single agent."""
    alert_types: List[str]               # Alert types this agent handles
    mcp_servers: List[str]               # MCP server IDs to use
    custom_instructions: str = ""        # Agent-specific instructions

class MCPServerConfigModel(BaseModel):
    """Configuration model for a single MCP server."""
    server_id: str                       # Unique server identifier
    server_type: str                     # Server type (e.g., "security", "monitoring")
    enabled: bool = True                 # Whether server is enabled
    connection_params: Dict[str, Any]    # Server connection parameters
    instructions: str = ""               # Server-specific LLM instructions

class CombinedConfigModel(BaseModel):
    """Root configuration model for the entire config file."""
    agents: Dict[str, AgentConfigModel] = {}           # Agent configurations
    mcp_servers: Dict[str, MCPServerConfigModel] = {}  # MCP server configurations
```

**Modified Data Models:**
```python
class Settings(BaseSettings):
    # Existing fields unchanged
    agent_config_path: str = Field(
        default="./config/agents.yaml",
        description="Path to agent and MCP server configuration file"
    )
    # Note: Environment variable name is AGENT_CONFIG_PATH (uppercase)
    # Pydantic automatically maps AGENT_CONFIG_PATH -> agent_config_path
```

### API Design

**No New API Endpoints**: This enhancement is internal configuration management only.

### Database Design

**No Schema Changes**: Configuration is file-based only, no database storage.

### Integration Points

**Internal Integrations:**
- **AlertService**: Continues to work unchanged, gets agents from enhanced AgentRegistry
- **AgentRegistry**: Extended to load and merge configured agents with built-in ones, automatically converts alert_types to registry mappings (REQ-4a)
- **MCPServerRegistry**: Extended to load and merge configured MCP servers with built-in ones
- **AgentFactory**: Enhanced to create both traditional BaseAgent subclasses and ConfigurableAgent instances (recognizes "ConfigurableAgent:agent-name" format)

**External Integrations:**
- **File System**: Configuration file reading with proper error handling
- **YAML Parser**: PyYAML for configuration parsing with validation

---

## Implementation Design

### Core Logic Flow
1. **System Startup**: Load AGENT_CONFIG_PATH from settings (default: `./config/agents.yaml`)
2. **Centralized Configuration Loading**: ConfigurationLoader parses YAML file if it exists, validates structure and data types using Pydantic models
3. **MCP Server Validation**: Validate that all agent-referenced MCP servers exist in unified registry (built-in + configured)
4. **Conflict Detection**: Check for both naming conflicts (configured names vs built-in names) and alert type conflicts (multiple agents handling same alert type)
5. **Component Initialization**: Distribute parsed config to registries and factory:
   - AgentRegistry gets agent configs for alert type mapping
   - MCPServerRegistry gets MCP server configs for merging with built-in
   - AgentFactory gets agent configs for ConfigurableAgent creation
6. **Registry Population**: Each registry merges configured items with built-in items
7. **Alert Processing**: AlertService uses enhanced registries transparently (no changes needed)

### Error Handling Strategy
- **Input Validation**: Pydantic models validate all configuration data with technical error messages
- **File Errors**: Missing file is graceful (use built-in only), malformed file fails startup with technical error details
- **MCP Server Validation**: All agent-referenced MCP servers validated against unified registry (built-in + configured), startup fails with technical error if not found
- **Conflict Errors**: Both naming conflicts (configured vs built-in names) and alert type conflicts (multiple agents per alert type) fail startup with technical conflict details
- **Runtime Errors**: ConfigurableAgent handles runtime errors same as BaseAgent (no special behavior needed)

### Security Design
- **Authentication**: Not applicable - configuration is local file access only
- **Authorization**: File system permissions control access to configuration file
- **Data Protection**: No arbitrary code execution - configuration contains only data (strings, lists, dicts)
- **Input Validation**: All configuration fields validated by Pydantic models, no eval/exec/import statements allowed

### Performance Considerations
- **Performance Requirements**: Configuration loaded once at startup, minimal runtime impact
- **Optimization Strategy**: Cache parsed configuration in memory, no repeated file I/O during alert processing
- **Scalability Approach**: Single file approach scales to hundreds of agents/MCP servers without performance impact

---

## File Structure

### Files to Create
```
backend/tarsy/
  agents/
    configurable_agent.py     # ConfigurableAgent class extending BaseAgent
  config/
    agent_config.py           # ConfigurationLoader class with centralized loading and validation
  models/
    agent_config.py           # Pydantic models for configuration data
config/
  agents.yaml.example         # Example configuration file template (users copy to agents.yaml)
```

### Files to Modify
- `backend/tarsy/services/agent_registry.py`: Accept parsed agent configs and convert to alert type mappings
- `backend/tarsy/services/mcp_server_registry.py`: Accept parsed MCP server configs and merge with built-in servers
- `backend/tarsy/services/agent_factory.py`: Add ConfigurableAgent creation capability
- `backend/tarsy/config/settings.py`: Add agent_config_path setting (REQ-16a)
- `backend/env.template`: Add AGENT_CONFIG_PATH example (pointing to ./config/agents.yaml, not the .example file) (REQ-16a)

### Files to Replace
- None - Full backward compatibility preserved

---

## Implementation Guidance

### Key Design Decisions
- **Primary Architecture Decision**: Extend existing registries rather than replace them - preserves all existing functionality while adding configuration capability
- **Data Structure Decision**: Single YAML file with both agents and MCP servers - simplifies deployment and shows relationships clearly
- **Integration Decision**: ConfigurableAgent extends BaseAgent - reuses all existing functionality, only overrides abstract methods with configuration data

### Implementation Priority
1. **Phase 1**: Configuration models and loading logic - core foundation for everything else
2. **Phase 2**: ConfigurableAgent implementation and registry extensions - main functionality
3. **Phase 3**: Validation, conflict detection, and error handling - robustness and safety

### Detailed Component Design

#### ConfigurationLoader Implementation
```python
import os
import yaml
from typing import Dict, Set
from pydantic import ValidationError
from ..models.agent_config import CombinedConfigModel, AgentConfigModel, MCPServerConfigModel

class ConfigurationError(Exception):
    """Raised when configuration loading or validation fails."""
    pass

class ConfigurationLoader:
    def __init__(self, config_file_path: str):
        self.config_file_path = config_file_path
        
        # Built-in constants (injected during initialization from existing registries)
        self.BUILTIN_AGENT_CLASSES = {"KubernetesAgent"}  # From AgentFactory.static_agent_classes.keys()
        self.BUILTIN_MCP_SERVERS = {"kubernetes-server"}  # From MCPServerRegistry._DEFAULT_SERVERS.keys()
        self.BUILTIN_AGENT_MAPPINGS = {  # From AgentRegistry._DEFAULT_MAPPINGS
            "kubernetes": "KubernetesAgent",
            "NamespaceTerminating": "KubernetesAgent"
        }
    
    def load_and_validate(self) -> CombinedConfigModel:
        """Load, parse and validate configuration file."""
        if not os.path.exists(self.config_file_path):
            # Return empty config - use built-in only
            return CombinedConfigModel(agents={}, mcp_servers={})
        
        try:
            with open(self.config_file_path, 'r') as f:
                raw_config = yaml.safe_load(f)
            
            # Validate with Pydantic models
            config = CombinedConfigModel(**raw_config)
            
            # Validate MCP server references
            self._validate_mcp_server_references(config)
            
            # Detect conflicts
            self._detect_conflicts(config)
            
            return config
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"YAML parsing failed: {e}")
        except ValidationError as e:
            raise ConfigurationError(f"Configuration validation failed: {e}")
    
    def _validate_mcp_server_references(self, config: CombinedConfigModel):
        """Validate all agent MCP server references exist."""
        # Get all available MCP servers (built-in + configured)
        available_servers = set(self.BUILTIN_MCP_SERVERS)
        available_servers.update(config.mcp_servers.keys())
        
        for agent_name, agent_config in config.agents.items():
            for server_id in agent_config.mcp_servers:
                if server_id not in available_servers:
                    raise ConfigurationError(
                        f"Agent '{agent_name}' references unknown MCP server '{server_id}'"
                    )
    
    def _detect_conflicts(self, config: CombinedConfigModel):
        """Detect naming and alert type conflicts."""
        # Check naming conflicts
        for agent_name in config.agents.keys():
            if agent_name in self.BUILTIN_AGENT_CLASSES:
                raise ConfigurationError(f"Agent name '{agent_name}' conflicts with built-in agent")
        
        for server_id in config.mcp_servers.keys():
            if server_id in self.BUILTIN_MCP_SERVERS:
                raise ConfigurationError(f"MCP server ID '{server_id}' conflicts with built-in server")
        
        # Check alert type conflicts
        alert_type_mappings = {}
        
        # Add built-in mappings
        for alert_type, agent_class in self.BUILTIN_AGENT_MAPPINGS.items():
            alert_type_mappings[alert_type] = f"built-in:{agent_class}"
        
        # Check configured mappings
        for agent_name, agent_config in config.agents.items():
            for alert_type in agent_config.alert_types:
                if alert_type in alert_type_mappings:
                    existing = alert_type_mappings[alert_type]
                    raise ConfigurationError(
                        f"Alert type '{alert_type}' handled by both {existing} and configured:{agent_name}"
                    )
                alert_type_mappings[alert_type] = f"configured:{agent_name}"
```

#### ConfigurableAgent Implementation
```python
class ConfigurableAgent(BaseAgent):
    def __init__(self, config: AgentConfigModel, llm_client: LLMClient, 
                 mcp_client: MCPClient, mcp_registry: MCPServerRegistry, 
                 progress_callback: Optional[Callable] = None):
        super().__init__(llm_client, mcp_client, mcp_registry, progress_callback)
        self._config = config
    
    def mcp_servers(self) -> List[str]:
        return self._config.mcp_servers
    
    def custom_instructions(self) -> str:
        return self._config.custom_instructions
```

#### Configuration File Structure
```yaml
# Example ./config/agents.yaml.example (template - users copy to ./config/agents.yaml)
mcp_servers:
  security-server:
    server_id: "security-server"
    server_type: "security"
    enabled: true
    connection_params:
      command: "/opt/security-mcp/server"
      args: ["--mode", "production"]
    instructions: |
      Security analysis instructions:
      - Always check for unauthorized access patterns
      - Prioritize data security over service availability

agents:
  security-agent:
    alert_types: ["SecurityBreach", "AccessViolation"]
    mcp_servers: ["security-server", "kubernetes-server"]  # Mixed: configured + built-in (REQ-5a)
    custom_instructions: |
      You are a security-focused SRE agent.
      Priority: Data security over service availability.
  
  performance-agent:
    alert_types: ["HighLatency", "CPUSpike"] 
    mcp_servers: ["kubernetes-server"]  # Built-in MCP server only
    custom_instructions: |
      Focus on performance bottlenecks and resource utilization.
```

#### Registry Extension Pattern
```python
# Note: This shows the enhanced signature after implementation
class AgentRegistry:
    def __init__(self, config: Optional[Dict[str, str]] = None, 
                 agent_configs: Optional[Dict[str, AgentConfigModel]] = None):
        # Load built-in mappings (alert_type -> agent_class_name)
        self.static_mappings = config or self._DEFAULT_MAPPINGS.copy()
        # Example: {"kubernetes": "KubernetesAgent", "NamespaceTerminating": "KubernetesAgent"}
        
        # Add configured agent mappings if provided
        if agent_configs:
            configured_mappings = self._create_configured_mappings(agent_configs)
            # Example: {"SecurityBreach": "ConfigurableAgent:security-agent", 
            #          "AccessViolation": "ConfigurableAgent:security-agent"}
            self.static_mappings.update(configured_mappings)
    
    def _create_configured_mappings(self, agent_configs: Dict[str, AgentConfigModel]) -> Dict[str, str]:
        """Convert agent configs to alert_type -> agent_identifier mappings."""
        mappings = {}
        
        for agent_name, agent_config in agent_configs.items():
            for alert_type in agent_config.alert_types:
                # Map alert type to configured agent identifier
                mappings[alert_type] = f"ConfigurableAgent:{agent_name}"
                
        return mappings
```

#### MCPServerRegistry Extension Pattern
```python
class MCPServerRegistry:
    def __init__(self, config: Optional[Dict[str, Dict]] = None,
                 configured_servers: Optional[Dict[str, MCPServerConfigModel]] = None):
        # Load built-in MCP server configurations
        self.static_servers = self._DEFAULT_SERVERS.copy()
        
        # Add configured MCP servers if provided
        if configured_servers:
            # Convert MCPServerConfigModel to internal format and merge
            for server_id, server_config in configured_servers.items():
                self.static_servers[server_id] = server_config.dict()
```

#### Startup Orchestration Pattern
```python
# During application startup (shows final state after implementation)
def initialize_application():
    settings = get_settings()
    
    # 1. Load and validate configuration
    config_loader = ConfigurationLoader(settings.agent_config_path)
    parsed_config = config_loader.load_and_validate()  # All validation happens here
    
    # 2. Initialize components with parsed config
    agent_registry = AgentRegistry(
        agent_configs=parsed_config.agents  # Will be added as new parameter
    )
    mcp_server_registry = MCPServerRegistry(
        configured_servers=parsed_config.mcp_servers  # Will be added as new parameter
    )
    agent_factory = AgentFactory(
        llm_client=llm_client,
        mcp_client=mcp_client,
        mcp_registry=mcp_server_registry,
        progress_callback=None,  # Or actual callback if available
        agent_configs=parsed_config.agents
    )
    
    # 3. Initialize AlertService with enhanced registries
    alert_service = AlertService(
        agent_registry=agent_registry,
        agent_factory=agent_factory,
        # ... other dependencies
    )
    
    return alert_service
```

#### AgentFactory Extension Pattern
```python
class AgentFactory:
    def __init__(self, llm_client: LLMClient, mcp_client: MCPClient, 
                 mcp_registry: MCPServerRegistry, progress_callback: Optional[Any] = None,
                 agent_configs: Optional[Dict[str, AgentConfigModel]] = None):
        self.llm_client = llm_client
        self.mcp_client = mcp_client
        self.mcp_registry = mcp_registry
        self.progress_callback = progress_callback
        self.agent_configs = agent_configs or {}  # Parsed config injected
        
        # Static registry of available agent classes - loaded once, no runtime changes
        self.static_agent_classes: Dict[str, Type[BaseAgent]] = {}
        self._register_available_agents()
    
    def create_agent(self, agent_class_name: str) -> BaseAgent:
        # Handle traditional BaseAgent subclasses
        if agent_class_name in self.static_agent_classes:
            agent_class = self.static_agent_classes[agent_class_name]
            return agent_class(
                llm_client=self.llm_client,
                mcp_client=self.mcp_client,
                mcp_registry=self.mcp_registry,
                progress_callback=self.progress_callback
            )
        
        # Handle configured agents (format: "ConfigurableAgent:agent-name")
        if agent_class_name.startswith("ConfigurableAgent:"):
            agent_name = agent_class_name.split(":", 1)[1]
            if agent_name not in self.agent_configs:
                raise ValueError(f"Unknown configured agent: {agent_name}")
                
            return ConfigurableAgent(
                config=self.agent_configs[agent_name],
                llm_client=self.llm_client,
                mcp_client=self.mcp_client,
                mcp_registry=self.mcp_registry,
                progress_callback=self.progress_callback
            )
        
        raise ValueError(f"Unknown agent: {agent_class_name}")
```

When creating the implementation plan, break this design into specific, testable phases that can be validated independently. 