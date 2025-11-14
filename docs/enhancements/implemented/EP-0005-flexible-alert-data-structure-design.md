# EP-0005: Flexible Alert Data Structure Support - Design Document

**Status:** Implemented
**Created:** 2025-07-28
**Phase:** Technical Design
**Requirements Document:** `docs/enhancements/implemented/EP-0005-flexible-alert-data-structure-requirements.md`
**Next Phase:** Implementation Plan

---

## Design Overview

### Architecture Summary
Transform the current rigid, Kubernetes-specific alert data model into a flexible, agent-agnostic system using a minimal validation approach with JSON payload storage. The design maintains only `alert_type` and `runbook` as required fields while enabling agents to autonomously process arbitrary contextual data.

**Design Freedom**: Since the system is entirely self-contained within this project (no external dependencies), we have complete freedom to redesign APIs, data structures, UI components, and database schema while preserving core Kubernetes alert processing functionality and agent-MCP architectural patterns.

### Key Design Principles
- **Minimal Validation**: Accept alerts with minimal structure validation, deferring data interpretation to agents
- **Agent Autonomy**: Agents receive complete payloads and extract relevant data based on their domain expertise
- **Static Agent Mapping**: Maintain current AgentRegistry static mapping approach (alert_type → agent class)
- **Core Functionality Preservation**: Maintain Kubernetes alert processing capabilities and agent-MCP workflows
- **JSON-First Storage**: Store alert data as flexible JSON documents with efficient querying capabilities
- **Dynamic UI Rendering**: UI components adapt to display arbitrary alert data structures

### Design Goals
- Enable support for diverse monitoring sources (databases, networks, applications, infrastructure)
- Eliminate need for core system modifications when adding new agent types
- Provide sensible defaults for common fields while allowing complete flexibility
- Maintain current performance and reliability standards
- Support seamless addition of new alert types without schema changes
- Leverage LLM intelligence for data interpretation instead of hardcoded field extraction logic

### LLM-First Data Processing Benefits
This design embraces a **"dump everything to LLM"** approach that maximizes simplicity and intelligence:

- **True Agent Autonomy**: LLM decides field relevance, not hardcoded extraction logic
- **Adaptive Intelligence**: Can use unexpected fields creatively and find correlations we didn't anticipate  
- **Zero Code Changes**: New alert types work automatically without agent modifications
- **Context Awareness**: LLM understands field relationships better than rigid extraction patterns
- **Future Proof**: Scales to any alert structure without system updates
- **Complex Data Support**: Alert data values can be nested objects, arrays, YAML strings, or any JSON structure - LLM interprets everything
- **Unix Timestamp Preservation**: Maintains current unix timestamp format (microseconds since epoch) throughout system

## System Architecture

### High-Level Architecture
The flexible alert system follows a three-layer approach:

1. **Ingestion Layer**: Minimal validation REST API accepting JSON payloads
2. **Storage Layer**: Document-based storage with efficient JSON querying
3. **Processing Layer**: Agent-driven interpretation of alert data with autonomous field extraction

### Component Architecture

#### New Components
*None - keeping it simple by enhancing existing components rather than creating new abstractions*

#### Modified Components
- **Alert Model** (`tarsy/models/alert.py`): 
  - Current state: Rigid Pydantic model with 7 required Kubernetes fields (alert_type, severity, environment, cluster, namespace, message, runbook) plus optional fields (id, pod, context, timestamp)
  - Changes: Replace with flexible model having only alert_type and runbook as required
  - New fields: `data` field for arbitrary JSON payload containing all alert information
  
- **Alert Service** (`tarsy/services/alert_service.py`):
  - Current state: Validates against rigid schema, calls `_create_history_session(alert, agent_class_name)`
  - Changes: Add simple validation (alert_type + runbook) and apply basic defaults before storage
  - Integration: Simple inline logic in existing workflow, no new methods needed

- **Base Agent** (`tarsy/agents/base_agent.py`):
  - Current state: `_prepare_alert_data()` method converts Alert to specific dict structure with fixed keys  
  - Changes: Agents receive AlertSession.alert_data directly, eliminate _prepare_alert_data() method, include all data as key-value pairs in LLM prompt
  - Strategy: Let LLM handle all data interpretation and relevance decisions

- **API Endpoints** (`tarsy/main.py`):
  - Current state: POST /alerts expects strict Alert model validation
  - Changes: Accept flexible JSON with minimal validation
  - Enhanced error handling for malformed JSON

- **Database Schema** (`tarsy/models/history.py`):
  - Current state: Already uses JSON field for alert_data (good foundation)
  - Changes: Optimize JSON indexing, add flexible querying capabilities
  - New indexes: GIN indexes on common JSON paths for performance

- **Dashboard UI Components**:
  - Current state: `OriginalAlertCard` displays fixed Kubernetes fields (cluster, namespace, pod, severity, environment)  
  - Changes: Generic key-value rendering for any fields in alert_data
  - Components affected: `OriginalAlertCard` only (other components display session metadata, not alert data)

- **Alert-dev-ui Components**:
  - Current state: `AlertForm` with hardcoded form fields (alert_type dropdown, severity select, environment select, cluster input, namespace input, pod input, message textarea, runbook input, context textarea)
  - Changes: Required fields (alert_type dropdown, runbook input) + dynamic key-value pairs for all other data
  - Components affected: `AlertForm` (simplified redesign), `ProcessingStatus` (unchanged), `ResultDisplay` (unchanged)



#### Component Interactions
```
External Alert Source → REST API (validate alert_type + runbook, apply defaults, convert timestamps) 
→ AlertService._create_history_session() → Agent.process_alert(AlertSession.alert_data) → Prompt Builder (include all data as key-value pairs)
                                        ↓                                                    ↓
Database (JSON storage via AlertSession) ← WebSocket Updates (status/progress only) ← LLM Processing (interprets all data)
                                        ↓                           
UI Components: API calls for alert data → generic key-value rendering
```

### Data Flow Design

#### Data Flow Diagrams
```
1. Alert Ingestion Flow:
   JSON Payload → Validate (alert_type, runbook) → Apply Defaults → Store → Route to Agent

2. Agent Processing Flow:
   AlertSession.alert_data → Agent Receives Complete Payload → Include All Data in LLM Prompt → Process → Return Result

3. UI Rendering Flow:
   Fetch Alert Data → Parse JSON → Generic Key-Value Rendering → Display All Available Fields
```

#### Data Processing Steps
1. **Ingestion**: REST API receives JSON payload, validates only alert_type and runbook fields
2. **Normalization**: Simple inline logic applies defaults (severity: "warning", timestamp: current unix timestamp in microseconds, environment: "production") for missing fields, converts any datetime timestamps to Unix microseconds
3. **Storage**: AlertService._create_history_session() stores alert_type in separate indexed column, runbook and all flexible data in AlertSession.alert_data JSON field
4. **Routing**: AgentRegistry.get_agent_for_alert_type() uses static mapping to select agent class
5. **Processing**: Agent.process_alert() receives AlertSession.alert_data directly → Prompt Builder includes all data as key-value pairs in LLM prompt
6. **Updates**: WebSocket broadcasts processing status updates, UI gets alert data via separate API calls when needed

## Data Design

### Data Models

#### New Data Models
```python
# Flexible Alert Model
class FlexibleAlert(BaseModel):
    """Flexible alert model with minimal required fields."""
    alert_type: str = Field(..., description="Alert type for agent selection")
    runbook: str = Field(..., description="Processing runbook URL or reference")
    data: Dict[str, Any] = Field(default_factory=dict, description="Flexible alert payload")
    
    # Optional fields with defaults
    severity: Optional[str] = Field(None, description="Alert severity (defaults to 'warning')")
    timestamp: Optional[int] = Field(None, description="Alert timestamp in unix microseconds (defaults to current time)")

# Prompt Building Pattern (Maximum Simplification)
# Service layer extracts runbook from AlertSession.alert_data and passes remaining data to agent:
# runbook_content = alert_session.alert_data.pop("runbook")  # Extract runbook
# agent.build_analysis_prompt(alert_session.alert_data, runbook_content, mcp_data)
import json

def build_analysis_prompt(self, alert_session_data, runbook_content, mcp_data):
    alert_info = []
    for key, value in alert_session_data.items():
        # Values can be strings, objects, arrays, YAML strings, etc.
        # Just serialize everything - let LLM interpret the structure
        if isinstance(value, (dict, list)):
            alert_info.append(f"{key}: {json.dumps(value, indent=2)}")
        else:
            alert_info.append(f"{key}: {value}")
    
    prompt = f"""
    Alert Information:
    {chr(10).join(alert_info)}
    
    Runbook: {runbook_content}
    Available Tools: {mcp_data}
    
    Please analyze this alert and determine appropriate actions...
    """

# Example alert data in prompt (values can be complex structures):
# Alert Information:
# runbook: https://runbooks.example.com/k8s-namespace-terminating
# cluster: prod-us-west-2
# namespace: payment-service
# severity: critical
# message: Namespace terminating unexpectedly
# environment: production
# timestamp: 1734562799999999
# custom_monitoring_tool: datadog
# incident_id: INC-12345
# metadata: {
#   "tags": ["payment", "critical-service"],
#   "thresholds": {"cpu": 80, "memory": 85},
#   "escalation_path": ["team-lead", "on-call-engineer"]
# }
# kubernetes_config: |
#   apiVersion: v1
#   kind: ConfigMap
#   metadata:
#     name: payment-config
```

#### Modified Data Models
```python
# Enhanced Alert Session (hybrid storage approach)
class AlertSession(SQLModel, table=True):
    # Existing fields remain unchanged, including:
    alert_type: Optional[str] = Field(...)  # Separate indexed column for fast routing/filtering
    alert_data: dict = Field(sa_column=Column(JSON))  # Contains runbook + all flexible data
    
    # Add JSON indexing for common query paths
    __table_args__ = (
        Index('ix_alert_data_severity', text("((alert_data->>'severity'))")),
        Index('ix_alert_data_environment', text("((alert_data->>'environment'))")),
        # GIN index for flexible JSON queries
        Index('ix_alert_data_gin', 'alert_data', postgresql_using='gin'),
    )

# Storage Structure:
# alert_type: "kubernetes" (separate column)
# alert_data: {
#   "runbook": "https://runbooks.example.com/k8s-namespace",
#   "cluster": "prod-us-west-2", 
#   "namespace": "payment-service",
#   "severity": "critical",
#   "timestamp": 1734562799999999,
#   ...all other flexible fields
# }
```

### Database Design

#### Schema Changes
- **Enhanced JSON Indexing**: Add GIN indexes for efficient flexible JSON queries on alert_data field
- **Common Field Indexes**: Create indexes on frequently queried JSON paths (severity, environment, cluster, etc.)
- **Query Optimization**: Optimize database queries for dynamic field filtering through SQLModel/SQLAlchemy
- **Complex Data Support**: alert_data JSON field stores any structure - nested objects, arrays, strings with YAML, etc.
- **Unix Timestamp Preservation**: Continue using existing unix timestamp format (microseconds since epoch)
- **No Migration Required**: Fresh database deployment eliminates migration complexity

#### Migration Strategy
Fresh database deployment approach:
- Create new optimized schema with JSON indexing
- No data migration required
- Enhanced query performance from day one
- Clean slate for JSON-optimized table structures

## API Design

### Redesigned API Endpoint

#### Primary Endpoint: POST /alerts (Redesigned)
- **Current Behavior**: Validates against rigid Alert model with all Kubernetes fields required
- **New Behavior**: Accept flexible JSON payloads with minimal validation (alert_type + runbook required)
  - **Request Format**:
    ```json
    {
      "alert_type": "kubernetes",
      "runbook": "https://runbooks.example.com/k8s-namespace-terminating",
      "data": {
        "cluster": "prod-us-west-2",
        "namespace": "payment-service", 
        "severity": "critical",
        "message": "Namespace terminating unexpectedly",
        "timestamp": 1734562799999999,
        "metadata": {
          "tags": ["payment", "critical-service"],
          "thresholds": {"cpu": 80, "memory": 85}
        },
        "kubernetes_config": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: payment-config"
      }
    }
    ```
- **Response Format**: Same as current AlertResponse
- **Default Application**: Apply defaults (severity: "warning", timestamp: current unix microseconds, environment: "production") for missing common fields
- **Storage Mapping**: `alert_type` → separate AlertSession column, `runbook` + `data` contents → AlertSession.alert_data JSON field
- **Implementation**: Simple inline validation and normalization in existing endpoint

### API Integration Points
- **WebSocket Updates**: Continue providing processing status and progress updates (no alert data needed)
- **History API**: Support filtering on arbitrary JSON fields through SQLModel/SQLAlchemy
- **Session Detail API**: Provide complete alert data when UI requests detailed view
- **Existing Endpoints**: All other endpoints (processing status, active sessions, etc.) remain unchanged

## User Interface Design

### UI Components

#### Enhanced UI Components
- **OriginalAlertCard**: 
  - Current state: Displays fixed Kubernetes fields in predetermined layout
  - Changes: Generic key-value rendering for all fields in alert_data
  - Simple approach: Display each field as "Field Name: Value" pairs

- **AlertListItem**:
  - Current state: Shows session metadata (status, alert_type, agent_type, time, duration)
  - Changes: None - displays session metadata which is unaffected by flexible alert data structure

- **ActiveAlertCard**:
  - Current state: Shows session metadata (status, alert_type, agent_type, timestamps, progress)
  - Changes: None - displays session metadata which is unaffected by flexible alert data structure

- **AlertForm** (Alert-dev-ui):
  - Current state: Hardcoded form fields (alert_type dropdown, severity select, environment select, cluster input, namespace input, pod input, message textarea, runbook input, context textarea)
  - Changes: Required fields (alert_type dropdown, runbook input) + dynamic key-value pairs for all other data
  - Implementation: Fixed UI for alert_type and runbook, then add/remove key-value input pairs for flexible data
  - Future: Default key-value pairs will be added in UI only (not backend)

### User Experience Flow

#### User Journey
1. **Alert Submission**: User fills out alert_type dropdown, runbook field, and adds key-value pairs
2. **Validation Feedback**: Simple validation ensures alert_type and runbook are provided
3. **Processing Visualization**: User sees real-time processing with generic alert context
4. **Results Display**: Alert details show all fields as simple key-value pairs
5. **Historical Browsing**: User can filter and search historical alerts using any fields

#### User Interface Mockups
- **Dashboard**: Maintains familiar layout with enhanced dynamic field display
- **Alert Detail Page**: Expandable sections for different data categories
- **Development UI**: Simple form with alert_type dropdown, runbook field, and add/remove key-value input pairs
- **Search Interface**: Dynamic filters based on available alert data fields

## Security Design

### Security Architecture
Maintain current security model while adding JSON payload sanitization and validation layers.

### Authentication & Authorization
- Preserve existing authentication mechanisms
- No changes to current authorization model
- Alert data access follows existing user permissions

### Data Protection
- **JSON Sanitization**: Strip potentially harmful content from flexible data fields
- **XSS Prevention**: Escape all dynamic content in UI rendering
- **Injection Prevention**: Use parameterized queries for JSON field filtering
- **Data Validation**: Validate JSON structure without restricting content flexibility

### Security Controls
- Input sanitization for all flexible JSON fields
- Output encoding for dynamic UI rendering

## Performance Design

### Performance Requirements
- Database operations shall perform efficiently with flexible JSON payloads

### Performance Architecture
- **JSON Indexing Strategy**: GIN indexes for flexible queries, specific indexes for common paths
- **Query Optimization**: Optimize JSON field queries through SQLModel/SQLAlchemy indexing
- **Async Processing**: Maintain current asynchronous alert processing model

### Performance Optimizations
- Optimized database indexes for common query patterns

## Error Handling & Resilience

### Error Handling Strategy
- **Graceful Degradation**: Agents handle missing expected fields without failure
- **Fallback Values**: Provide sensible defaults for common fields
- **Validation Errors**: Clear error messages for malformed alert submissions
- **Processing Errors**: Continue processing with available data when possible

### Failure Modes
- **Malformed JSON Payload**:
  - **Impact**: Alert submission rejected
  - **Detection**: JSON parsing validation at API level
  - **Recovery**: Return detailed error message with correction guidance

- **Missing Required Fields**:
  - **Impact**: Alert cannot be routed to appropriate agent
  - **Detection**: Minimal validation at ingestion
  - **Recovery**: Return specific field requirements


### Resilience Patterns
- Circuit breaker for JSON validation failures
- Fallback rendering for UI components with unknown data structures

## Configuration & Deployment

### Configuration Changes

#### New Configuration Options
- **JSON_INDEX_STRATEGY**: Enable/disable automatic JSON indexing for performance

#### Modified Configuration Options
- **DATABASE_INDEXES**: Additional JSON indexing configuration options

## Testing Strategy

### Unit Testing

#### Test Coverage Areas
- FlexibleAlert model validation with various payload structures
- Agent LLM prompt building with diverse data types
- Generic key-value UI rendering with unknown field combinations
- JSON database operations and indexing performance

### Integration Testing

#### Integration Points to Test
- API endpoint validation with flexible payloads
- Agent processing with missing expected fields
- UI rendering with diverse alert data structures
- WebSocket status updates during alert processing

## Implementation Strategy & System Redesign

### Fresh Implementation Approach
Complete system redesign with fresh database deployment:
- Deploy new optimized schema with enhanced JSON support
- No data migration required - start with clean slate
- Full freedom to redesign all components since system is self-contained but preserve what already works well

### Core Functionality Preservation
- **Kubernetes Alert Processing**: Maintain ability to process Kubernetes-style alerts effectively
- **Agent-MCP Architecture**: Preserve agent selection and MCP communication patterns
- **Processing Pipeline**: Keep core alert processing workflow and real-time updates
- **Historical Tracking**: Maintain alert session tracking and analysis capabilities

### Implementation Steps
1. **Database Setup**: Deploy fresh schema with JSON optimizations and flexible indexing
2. **API Update**: Modify existing /alerts endpoint with minimal validation and inline defaults
3. **Agent Enhancement**: Update agents to dump all alert.data directly into LLM prompts as key-value pairs
4. **UI Update**: Implement generic key-value rendering for alert data display
5. **Integration Testing**: Validate that Kubernetes alerts process correctly in new flexible system

## Implementation Considerations

### Dependencies
- PostgreSQL JSON/JSONB indexing capabilities
- React dynamic component rendering libraries

### Constraints
- Fresh database deployment only - no existing data migration
- UI changes must not break existing user workflows

## Documentation Requirements

### Code Documentation
- Comprehensive docstrings for new flexible data models
- Agent prompt building documentation with usage examples

### API Documentation
- Flexible JSON payload examples for different alert types

---

## Next Steps

After design approval:
1. Create Implementation Plan: `docs/enhancements/pending/EP-0005-flexible-alert-data-structure-implementation.md`
2. Reference this design document in the implementation phase
3. Ensure implementation plan addresses all design elements

**AI Prompt for Next Phase:**
```
Create an implementation plan using the template at docs/templates/ep-implementation-template.md for EP-0005 based on the approved design in this document and the requirements in EP-0005-flexible-alert-data-structure-requirements.md.
``` 