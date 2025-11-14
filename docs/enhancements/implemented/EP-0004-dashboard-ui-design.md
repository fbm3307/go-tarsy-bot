# EP-0004: Tarsy Dashboard UI for Alert History - Design Document

**Status:** Implemented  
**Created:** 2025-01-19  
**Phase:** Implementation Complete  
**Last Updated:** 2025-01-25 (Backend API endpoints added)
**Implemented:** 2025-07-27
**Requirements Document:** `docs/enhancements/implemented/EP-0004-dashboard-ui-requirements.md`

---

## Design Overview

This design creates a standalone React dashboard application (`dashboard/`) that provides SRE engineers with comprehensive **read-only observability** into alert processing workflows. The dashboard will be implemented as a sibling directory to the existing `alert-dev-ui/`, maintaining complete separation between the two applications. The dashboard emphasizes the distinction between **active alerts** (currently processing) and **historical alerts** (completed processing), leveraging the existing EP-0003 history service API and **integrating with the existing EP-0003 hook system** for real-time updates.

### Integrated Hook System Approach

This design leverages the existing EP-0003 hook infrastructure to provide real-time dashboard updates, creating a **shared event pipeline** that serves both history logging and dashboard broadcasting:

**Key Benefits:**
- **Single Event Source**: Both systems use the same LLM/MCP interaction events
- **Data Consistency**: Identical timestamps, session IDs, and interaction context
- **No Service Modifications**: Existing LLM/MCP clients remain unchanged
- **Reduced Complexity**: No separate event infrastructure needed
- **Concurrent Execution**: Dashboard hooks run alongside history hooks without performance impact

### Architecture Summary

The dashboard follows a modern React SPA architecture with Material-UI components, implemented as an independent application in the `dashboard/` directory (sibling to `alert-dev-ui/`). The architecture implements a layered approach:
- **Presentation Layer**: React components with Material-UI theming
- **State Management Layer**: React hooks and context for local state management  
- **Communication Layer**: Axios for REST API calls and multiplexed WebSocket for real-time updates
- **Service Layer**: Dashboard-specific API clients and WebSocket subscription managers

**Directory Structure**: `dashboard/` as independent sibling to existing `alert-dev-ui/` directory.

### Key Design Principles

- **Read-Only Observability**: Dashboard provides monitoring and analysis without control operations
- **Active/Historical Distinction**: Clear separation between currently processing and completed alerts
- **Separation of Concerns**: Dashboard operates independently from alert dev UI
- **Reusable Patterns**: Leverage proven patterns from existing alert dev UI
- **Real-time First**: WebSocket integration for live operational monitoring
- **Performance Conscious**: Efficient data loading and virtual scrolling for large datasets
- **Accessibility First**: WCAG 2.1 AA compliance built into component design

### Design Goals

- **Operational Observability**: Provide comprehensive read-only visibility into alert processing workflows
- **Real-Time Awareness**: Enable immediate visibility into active alert processing status
- **Historical Analysis**: Support efficient filtering and analysis of completed alerts
- **Performance**: Handle 1000+ sessions with responsive UI interactions
- **Scalability**: Support multiple concurrent users without performance degradation
- **Maintainability**: Clean, testable architecture following React best practices

## System Architecture

### High-Level Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                        Tarsy Dashboard                        │
├───────────────────────────────────────────────────────────────┤
│                    React SPA (dashboard/)                     │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐  │
│  │  Session List   │ │  Session Detail │ │  Real-time      │  │
│  │  Components     │ │  Components     │ │  Components     │  │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘  │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐  │
│  │  API Service    │ │  WebSocket      │ │  State          │  │
│  │  Layer          │ │  Manager        │ │  Management     │  │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘  │
├───────────────────────────────────────────────────────────────┤
│                Backend Services (Integrated Hook System)      │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐  │
│  │  History API    │ │  Shared Hook    │ │  WebSocket      │  │
│  │  (EP-0003)      │ │  System         │ │  Broadcasting   │  │
│  │                 │ │  ┌───────────┐  │ │  (NEW)          │  │
│  │                 │ │  │ History   │  │ │                 │  │
│  │                 │ │  │ Hooks     │  │ │                 │  │
│  │                 │ │  ├───────────┤  │ │                 │  │
│  │                 │ │  │Dashboard  │  │ │                 │  │
│  │                 │ │  │ Hooks     │  │ │                 │  │
│  │                 │ │  │ (NEW)     │  │ │                 │  │
│  │                 │ │  └───────────┘  │ │                 │  │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘  │
│                               ↑                               │
│  ┌─────────────────┐          │          ┌─────────────────┐  │
│  │  LLM/MCP        │ ───────────────────→│  Alert Dev UI   │  │
│  │  Interactions   │    Hook Events      │  (Unchanged)    │  │
│  └─────────────────┘                     └─────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

### Component Architecture

**📋 Detailed Component Specifications**: For comprehensive component hierarchies, Material-UI implementations, and phase-specific component details, see **`EP-0004-dashboard-ui-phases.md`**.

#### Core Application Components

**Main Layout Components:**
- **DashboardApp**: Main application with routing, theme provider, and error boundaries
- **DashboardView**: Primary dashboard layout with active/historical split
- **SessionDetailPage**: Unified detail view for both active and historical sessions

**Data Display Components:**
- **ActiveAlertsPanel**: Real-time panel for currently processing alerts
- **HistoricalSessionsList**: Paginated list with filtering for completed sessions  
- **TimelineVisualization**: Interactive session timeline with real-time updates
- **SessionHeader**: Metadata display with active/historical status indicators

**Interactive & Utility Components:**
- **FilterPanel**: Advanced filtering interface with multi-criteria support
- **InteractionDetails**: Expandable detailed view of LLM/MCP interactions
- **SessionActions**: Action buttons for copy, export, and navigation
- **RealTimeMonitor**: Live counters and status indicators

#### Phased Component Introduction

**Phase 1-2**: Core layout and basic data display components  
**Phase 3**: Navigation and detail page components  
**Phase 4**: Advanced filtering and search components  
**Phase 5-7**: Real-time features, timeline visualization, and performance components

#### New Service Components (Dashboard-Specific)

**Note**: While similar to existing alert-dev-ui components, these are entirely new implementations for the dashboard application in the `dashboard/` directory.

- **DashboardWebSocketManager**: New multiplexed WebSocket manager specifically for dashboard:
  - Single connection for all dashboard communications
  - Dynamic subscription management for sessions and dashboard updates
  - Intelligent message routing based on subscription channels
  - Connection optimization to avoid browser connection limits
  - Auto-reconnection with subscription state restoration
  - **Difference from alert-dev-ui**: Subscription-based vs. single-session WebSocket
- **DashboardAPIClient**: New API client service for dashboard endpoints:
  - History service endpoints integration
  - Pagination support for large datasets
  - Dashboard-specific error handling and retry logic
  - **Difference from alert-dev-ui**: Read-only history API vs. alert submission API
- **SharedThemeProvider**: Shared Material-UI theme configuration:
  - **Reusable**: Could potentially be shared between alert-dev-ui and dashboard
  - **Implementation**: Copy existing theme or create shared theme package

#### Component Interactions

```
DashboardApp
├── Router
    ├── DashboardView                    # Route: /dashboard
    │   ├── FilterPanel
    │   ├── ActiveAlertsPanel           # Summary cards → navigate to detail
    │   │   └── ActiveAlertCard[]
    │   ├── HistoricalSessionsList      # Summary cards → navigate to detail
    │   │   └── HistoricalSessionCard[]
    │   └── RealTimeMonitor
    │
    └── SessionDetailPage               # Route: /sessions/{id} (both active & historical)
        ├── SessionHeader               # Shows active/historical status
        ├── TimelineVisualization       # Real-time updates for active sessions
        ├── InteractionDetails          # Live interaction details
        └── SessionActions              # Copy, export, back navigation
```

### Data Flow Design

#### Data Flow Diagrams

**Session List Data Flow (Hook System Integration):**
```
User Filter Action → FilterPanel → APIClient → History API → SessionListView → SessionCard[]
                                            ↓
                  → WebSocketManager.subscribe('dashboard_updates', filters)
                                            ↓
Hook Events → Dashboard Broadcast Hooks → WebSocket Channel Router → RealTimeMonitor → Session Status Updates
```

**Session Detail Data Flow (Hook System Integration for Active & Historical):**
```
Session Card Click → Navigate to /sessions/{id} → SessionDetailPage → APIClient → History API → Timeline Data
                                                        ↓
                                                → WebSocketManager.subscribe('session_{id}')
                                                        ↓
Hook Events → Dashboard Broadcast Hooks → WebSocket Channel Router → Real-time Timeline Updates (Active Sessions)
                                                        ↓
Navigate Back/Away → WebSocketManager.unsubscribe('session_{id}')
```

**WebSocket Message Flow (Hook System Integration):**
```
Client: { type: 'subscribe', channel: 'dashboard_updates', filters: {...} }
                              ↓
Server: Hook Events → Dashboard Broadcast Hooks → Format for WebSocket → Push Updates
                              ↓
Client: { type: 'dashboard_update', channel: 'dashboard_updates', data: {...} }
```

#### Data Processing Steps

1. **Initial Load**: Fetch paginated session list with default filters
2. **Filter Application**: Apply user filters and re-fetch filtered results
3. **Hook-Based Real-time Updates**: Process WebSocket messages generated from EP-0003 hook events for live session status on dashboard
4. **Session Detail Navigation**: Navigate to dedicated page and load detailed timeline data
5. **Timeline Rendering**: Process chronological data for timeline visualization
6. **Active Session Hook Updates**: For active sessions on detail pages, continuously update timeline with new interactions from hook events
7. **Live Status Monitoring**: Update session status, progress, and completion in real-time via integrated hook system

## Backend Dependencies & Requirements

This dashboard design leverages the existing EP-0003 hook system infrastructure, significantly reducing backend implementation requirements while ensuring consistency between historical and real-time data.

### Required Backend Changes

#### New WebSocket Implementation (Priority 1)

**Multiplexed WebSocket Endpoint**: `/ws/dashboard/{user_id}`
- **Location**: New endpoint in backend FastAPI application
- **Purpose**: Single connection supporting multiple subscription channels
- **Implementation Requirements**:
  - WebSocket connection management with user identification
  - Subscription-based message routing system
  - Channel management (subscribe/unsubscribe operations)
  - Message batching and optimization for performance
  - Graceful connection cleanup and resource management

**Subscription Channel System**:
- `dashboard_updates`: Real-time session list updates with filter support
- `session_{id}`: Individual session timeline and status updates  
- `system_health`: Service status and connectivity notifications

#### Integrated Hook System Extensions (Priority 2)

**Dashboard Broadcast Hooks** (NEW - extends existing hook system):
- **Purpose**: Capture same LLM/MCP events as EP-0003 history hooks for dashboard broadcasting
- **Architecture**: Works alongside existing history hooks using shared event pipeline
- **Implementation**: Extends `BaseEventHook` class from existing hook infrastructure
- **Benefits**: 
  - Same event timing and session context as history service
  - No modifications needed to LLM/MCP clients
  - Concurrent execution with history hooks

**Dashboard Update Service**:
- **Purpose**: Format hook event data for WebSocket broadcasting to dashboard subscribers
- **Responsibilities**:
  - Transform hook event data into dashboard-friendly messages
  - Apply user filters to session data for targeted updates
  - Batch multiple session changes into single update messages
  - Optimize update frequency to prevent dashboard flooding

**Enhanced Hook Registration**:
- **Modify**: Existing hook registration system to include dashboard hooks
- **Integration**: Dashboard hooks registered alongside history hooks at application startup
- **Execution**: Both hook types execute concurrently for same LLM/MCP events

#### Simplified Integration Points (Priority 3)

**Hook System Integration**:
- **Leverage**: Existing EP-0003 hook infrastructure without modifications
- **Events Available**: All existing LLM/MCP interaction events automatically available
  - LLM interactions (prompts, responses, timing, errors)
  - MCP communications (tool calls, results, errors)
  - Session lifecycle events (creation, completion, status changes)
- **Event Format**: Uses existing hook event format with additional dashboard formatting

**Authentication Integration**:
- **Modify**: Existing authentication system to support WebSocket user identification
- **Requirements**:
  - User ID extraction from WebSocket connection
  - Session-based or token-based WebSocket authentication
  - Connection authorization for dashboard access

### Backend Implementation Priority

1. **Phase 1 - Core WebSocket** (Must complete first)
   - Implement `/ws/dashboard/{user_id}` endpoint
   - Build subscription management system
   - Create basic message routing infrastructure

2. **Phase 2 - Hook System Integration** (Required for dashboard functionality)
   - Create dashboard broadcast hooks extending existing EP-0003 hook system
   - Integrate dashboard hooks with existing hook registration
   - Implement dashboard update service for hook data formatting

3. **Phase 3 - Optimization** (Performance and reliability)
   - Add message batching and throttling
   - Implement connection recovery mechanisms
   - Add monitoring and health checks for WebSocket system

### Backend Code Architecture

The backend implementation will follow this integrated hook system architectural pattern:

```python
# Integrated Hook System Architecture
class DashboardBroadcastHooks(BaseEventHook):
    """Dashboard broadcast hooks that work alongside existing EP-0003 history hooks"""
    
    def __init__(self, dashboard_broadcaster):
        super().__init__("dashboard_broadcast_hook")
        self.broadcaster = dashboard_broadcaster
        self.update_service = DashboardUpdateService()
    
    async def execute(self, event_type: str, **kwargs):
        """Execute dashboard broadcasting for hook events"""
        session_id = kwargs.get('session_id')
        if not session_id:
            return
            
        # Format hook data for dashboard consumption
        dashboard_data = self.update_service.format_hook_event(event_type, **kwargs)
        
        # Broadcast to appropriate subscription channels
        if event_type.endswith('.post'):
            await self.broadcaster.broadcast_session_update(session_id, dashboard_data)
        elif event_type.endswith('.error'):
            await self.broadcaster.broadcast_error_update(session_id, dashboard_data)

# Integrated Hook Registration (extends existing EP-0003 system)
def register_all_hooks():
    """Register both history and dashboard hooks together"""
    hook_manager = get_hook_manager()  # Uses existing hook manager
    
    # Existing EP-0003 hooks (unchanged)
    llm_history_hooks = LLMHooks()
    mcp_history_hooks = MCPHooks()
    hook_manager.register_hook("llm.post", llm_history_hooks)
    hook_manager.register_hook("mcp.post", mcp_history_hooks)
    
    # New EP-0004 dashboard hooks (same events, different actions)
    dashboard_broadcaster = get_dashboard_broadcaster()
    llm_dashboard_hooks = DashboardBroadcastHooks(dashboard_broadcaster)
    mcp_dashboard_hooks = DashboardBroadcastHooks(dashboard_broadcaster)
    hook_manager.register_hook("llm.post", llm_dashboard_hooks)
    hook_manager.register_hook("mcp.post", mcp_dashboard_hooks)
    
    # Both hook types execute concurrently for the same events!

# WebSocket endpoint (connects to hook-based broadcasting system)
@app.websocket("/ws/dashboard/{user_id}")
async def dashboard_websocket(websocket: WebSocket, user_id: str):
    await websocket.accept()
    connection_manager = DashboardConnectionManager()
    
    try:
        await connection_manager.register_connection(user_id, websocket)
        
        while True:
            message = await websocket.receive_json()
            await handle_dashboard_message(user_id, websocket, message)
            
    except WebSocketDisconnect:
        await connection_manager.cleanup_connection(user_id, websocket)

# Service classes (simplified due to hook integration)
class DashboardConnectionManager:
    """Manages dashboard WebSocket connections and subscriptions"""
    
class DashboardBroadcaster:
    """Broadcasts dashboard updates received from hook events"""
    
class DashboardUpdateService:
    """Formats hook event data for dashboard consumption"""
```

## Data Design

### Data Models

#### New Data Models

```typescript
DashboardSession {
  - id: string (session ID)
  - alert_type: string (alert classification)
  - agent_type: string (processing agent)
  - status: SessionStatus (current status)
  - created_at: string (ISO timestamp)
  - completed_at: string | null (completion timestamp)
  - duration_ms: number | null (processing duration)
  - summary: string (brief description)
  - error_message: string | null (error details if failed)
}

SessionFilter {
  - status: SessionStatus[] (status filter)
  - agent_type: string[] (agent type filter)
  - alert_type: string[] (alert type filter)
  - start_date: string | null (start date filter)
  - end_date: string | null (end date filter)
  - search_query: string (text search)
}

TimelineItem {
  - id: string (unique identifier)
  - type: 'llm' | 'mcp' (interaction type)
  - timestamp: string (ISO timestamp with microseconds)
  - title: string (interaction summary)
  - details: LLMInteraction | MCPCommunication (detailed data)
  - duration_ms: number | null (operation duration)
}

PaginationState {
  - page: number (current page)
  - page_size: number (items per page)
  - total_count: number (total items)
  - has_next: boolean (more pages available)
}
```

#### Modified Data Models

```typescript
// Enhanced WebSocket message model with subscription management
WebSocketMessage {
  - type: 'subscribe' | 'unsubscribe' | 'session_update' | 'session_complete' | 'dashboard_update' | 'error' (message type)
  - channel: string (subscription channel identifier)
  - session_id?: string (session identifier for session-specific messages)
  - data: SubscriptionRequest | SessionUpdate | SessionComplete | DashboardUpdate | ErrorMessage (payload)
  - timestamp: string (message timestamp)
  - user_id?: string (user identifier for connection management)
}

// Client-to-server subscription management
SubscriptionRequest {
  - action: 'subscribe' | 'unsubscribe' (subscription action)
  - channel: 'dashboard_updates' | 'session_{id}' | 'system_health' (channel name)
  - filters?: SessionFilter (optional filters for dashboard updates)
  - session_id?: string (session ID for session-specific subscriptions)
}

// Server-to-client update messages
DashboardUpdate {
  - sessions: SessionSummary[] (updated session list)
  - total_count: number (total sessions matching filters)
  - active_count: number (currently processing sessions)
  - filters_applied: SessionFilter (current filters)
}

APIResponse<T> {
  - data: T (response data)
  - pagination: PaginationState | null (pagination info)
  - error: string | null (error message)
  - timestamp: string (response timestamp)
}
```

### Database Design

No database changes required - dashboard consumes existing EP-0003 history service data through REST API endpoints.

#### Schema Changes

- No schema changes needed
- Dashboard operates as read-only consumer of existing data

#### Migration Strategy

- No data migration required
- Dashboard deployment independent of backend changes

## API Design

### New API Endpoints

Dashboard requires new dashboard-specific endpoints in addition to existing EP-0003 endpoints:

#### New Dashboard Endpoints

- **GET /api/v1/history/metrics**: Dashboard overview metrics (active sessions, completion rates, error rates, interaction counts)
- **GET /api/v1/history/active-sessions**: Currently processing sessions with real-time status
- **GET /api/v1/history/filter-options**: Dynamic filter options based on actual data (agent types, alert types, status options)
- **GET /api/v1/history/sessions/{session_id}/export**: Export comprehensive session data with timeline in JSON or CSV format
- **GET /api/v1/history/search**: Search sessions by alert content, error messages, and metadata with full-text search capabilities

#### Existing Endpoints Used

- **GET /api/v1/history/sessions**: Session list with filtering and pagination
- **GET /api/v1/history/sessions/{session_id}**: Detailed session with timeline
- **GET /api/v1/history/health**: Health check endpoint

### Modified API Endpoints

**Route Conflict Resolution**: The `/api/v1/history/sessions/active` endpoint was changed to `/api/v1/history/active-sessions` to avoid FastAPI routing conflicts with the parameterized `/api/v1/history/sessions/{session_id}` endpoint.

#### Backend Implementation Details

**New Service Methods:**
- `HistoryService.get_dashboard_metrics()`: Aggregates session counts, interaction statistics, error rates, and duration metrics
- `HistoryService.get_filter_options()`: Queries database for distinct values to populate filter dropdowns dynamically
- `HistoryService.export_session_data()`: Orchestrates session data export with timeline reconstruction and format handling
- `HistoryService.search_sessions()`: Coordinates multi-field session search with error handling and result limiting

**New Repository Methods:**
- `HistoryRepository.get_dashboard_metrics()`: Executes database queries for session counts by status, interaction counts, duration calculations, and 24-hour activity metrics
- `HistoryRepository.get_filter_options()`: Performs `SELECT DISTINCT` queries for agent types, alert types, and status options with proper sorting
- `HistoryRepository.export_session_data()`: Fetches complete session data with timeline reconstruction, supporting both JSON and CSV export formats
- `HistoryRepository.search_sessions()`: Implements SQLite full-text search across multiple fields including JSON data extraction for environment, cluster, and namespace searches

**Database Query Optimizations:**
- Uses `COUNT(*)` aggregations for efficient metric calculations
- Leverages indexed fields (`status`, `agent_type`, `started_at`) for fast filtering
- Implements proper error handling with graceful fallback to default values

### API Integration Points

#### History Service Integration
- **Base URL**: Configurable backend URL (development/production)
- **Authentication**: Bearer token or session-based (if implemented)
- **Error Handling**: Graceful degradation with user-friendly error messages
- **Caching**: Client-side caching for session list and details

#### WebSocket Integration Points

**Optimized Multiplexed Architecture**
- **Single Dashboard WebSocket**: `/ws/dashboard/{user_id}` (replaces multiple endpoint approach)
- **Subscription-Based Communication**: Dynamic subscription management within single connection
- **Channel-Based Message Routing**: Messages routed by subscription channels rather than separate connections
- **Connection Limit Optimization**: Eliminates browser 6-connection limit issues

**Connection Management Features**
- **Auto-reconnection**: Exponential backoff with subscription state restoration
- **Subscription State Persistence**: Automatic re-subscription after reconnection
- **Message Buffering**: Handle temporary connection losses with message queuing
- **Graceful Cleanup**: Proper unsubscription and resource cleanup on disconnect

**Subscription Channels**
- `dashboard_updates`: Real-time session list updates with filter support
- `session_{id}`: Individual session timeline and status updates
- `system_health`: Service status and connectivity notifications

## User Interface Design

### UI Components

The dashboard UI will be implemented through a **phased approach** with incremental functionality delivery. This allows for early value delivery and iterative refinement based on user feedback.

#### Implementation Strategy

**📋 Detailed Component Specifications**: For comprehensive component layouts, Material-UI implementations, and detailed UI specifications, see **`EP-0004-dashboard-ui-phases.md`**.

#### Phased Component Development

**Phase 1 (Basic Alert List)**: 
- Simple list component with core session information
- Basic status indicators and navigation
- Material-UI Table with essential columns

**Phase 2 (Active/Historical Split)**:
- ActiveAlertsPanel for currently processing alerts
- HistoricalSessionsList for completed alerts  
- Clear visual separation and status grouping

**Phase 3-7 (Progressive Enhancement)**:
- Advanced filtering and search components
- Interactive timeline visualizations
- Real-time update mechanisms
- Performance optimizations with virtual scrolling

#### Core Component Categories

**Dashboard Layout Components:**
- **DashboardApp**: Main application with routing
- **DashboardView**: Primary dashboard layout
- **SessionDetailPage**: Unified detail view for active/historical sessions

**Data Display Components:**
- **SessionGrid**: Virtualized session list (Phase 6+)
- **ActiveAlertsPanel**: Real-time active session display
- **TimelineVisualization**: Interactive session timeline
- **StatusIndicator**: Consistent status display across phases

**Interactive Components:**
- **FilterPanel**: Advanced filtering interface
- **SearchBar**: Debounced search with suggestions  
- **CopyButton**: Reusable copy-to-clipboard functionality

#### Technology Integration

**Material-UI v5.15.0**: All components built with Material-UI for design consistency
**React 18.2.0**: Modern React patterns with hooks and concurrent features
**@mui/lab**: Timeline components for enhanced session visualization

### User Experience Flow

#### Core User Journey

The dashboard follows a **progressive enhancement approach** where functionality expands across implementation phases:

1. **Dashboard Entry**: User navigates to dashboard and sees session list (Phase 1)
2. **Active/Historical Split**: Clear separation between processing and completed alerts (Phase 2)  
3. **Session Detail Navigation**: Click any session → dedicated detail page with timeline (Phase 3)
4. **Enhanced Filtering**: Apply advanced filters and search for targeted analysis (Phase 4)
5. **Real-time Monitoring**: Live updates for active sessions with timeline visualization (Phase 5)
6. **Advanced Operations**: Pagination, export, and performance optimizations (Phase 6-7)

#### Phased User Experience Evolution

**📋 Detailed User Flows**: For comprehensive user journey mappings, interaction patterns, and UX specifications by phase, see **`EP-0004-dashboard-ui-phases.md`**.

**Progressive Enhancement Strategy:**
- **Phase 1**: Basic read-only observability  
- **Phase 2**: Operational distinction (active vs historical)
- **Phase 3**: Deep dive investigation capabilities
- **Phase 4+**: Advanced analytical and monitoring features

#### Consistent Design Principles

- **Active/Historical Distinction**: Clear visual separation maintained across all phases
- **Unified Detail View**: Same detail page pattern for both active and historical sessions
- **Real-time First**: Live updates prioritized for operational awareness
- **Material Design**: Consistent Material-UI patterns throughout all phases

#### User Interface Design

**📋 Detailed UI Mockups & Layouts**: For comprehensive visual mockups, ASCII layouts, and Material-UI component implementations, see **`EP-0004-dashboard-ui-phases.md`**.

#### Design Evolution Summary

**Phase 1: Simple List View**  
Clean Material-UI table with basic session information (status, type, agent, time, duration).

**Phase 2: Active/Historical Split**  
Distinct panels for active alerts (top) and historical sessions (bottom) with clear visual separation.

**Phase 3: Navigation & Detail Pages**  
Dedicated session detail pages with timeline visualization and navigation between list and detail views.

**Phase 4-7: Enhanced Features**  
Progressive enhancement with filtering, search, real-time updates, advanced timeline visualization, and performance optimizations.

#### Core Design Principles

- **Material Design Consistency**: All phases use Material-UI v5.15.0 components
- **Progressive Enhancement**: Each phase builds upon previous functionality
- **Active/Historical Distinction**: Clear visual and functional separation maintained throughout
- **Responsive Design**: Components adapt to different screen sizes and orientations
- **Accessibility First**: WCAG 2.1 AA compliance built into all component designs

## Security Design

### Security Architecture

Dashboard implements client-side security measures following React security best practices:
- **XSS Prevention**: Sanitized data rendering and CSP headers
- **CSRF Protection**: CSRF tokens for API requests (if required by backend)
- **Secure Communication**: HTTPS/WSS for all API and WebSocket connections

### Authentication & Authorization

- **Authentication**: Leverage existing backend authentication mechanism
- **Authorization**: Read-only access to history data (no write operations)
- **Session Management**: Standard browser session management

### Data Protection

- **Sensitive Data**: Alert data displayed securely without logging
- **Client Storage**: Minimal localStorage usage for user preferences only
- **Memory Management**: Proper cleanup of sensitive data in component unmounting

### Security Controls

- **Input Validation**: Client-side validation of all user inputs
- **Output Encoding**: Proper HTML encoding of all displayed data
- **Error Handling**: Secure error messages without sensitive information disclosure

## Performance Design

### Performance Requirements

Based on requirements document:
- **Initial Load**: Reasonable speed for dashboard productivity
- **Pagination**: Handle 1000+ sessions efficiently  
- **Filter Operations**: Interactive performance for data exploration
- **Real-time Updates**: Prompt display of current operational status

### WebSocket Optimization Strategy

**Connection Limit Solution**
The browser's 6-connection limit per domain posed a significant constraint for the original multi-WebSocket approach. The optimized multiplexed design solves this through:
- **Single Connection Architecture**: One WebSocket handles all dashboard communications
- **Dynamic Subscription Management**: Subscribe/unsubscribe to specific data channels as needed
- **Intelligent Message Routing**: Server-side routing based on subscription channels
- **Connection Pool Preservation**: Leaves connections available for API calls and other resources

**Implementation Benefits**
- **Reduced Resource Usage**: Single persistent connection vs. multiple connections
- **Better Reconnection Handling**: Centralized reconnection logic with state restoration
- **Simplified Debugging**: All WebSocket traffic flows through single connection
- **Scalability**: Supports unlimited session subscriptions without additional connections

**Performance Optimizations**
- **Message Batching**: Multiple updates can be batched in single WebSocket message
- **Selective Updates**: Only subscribed channels receive relevant updates
- **Connection Reuse**: Same connection serves session list, details, and status updates
- **Reduced Handshake Overhead**: Single WebSocket handshake vs. multiple handshakes

### Performance Architecture

#### Virtual Scrolling
- **Implementation**: React-window for large session lists
- **Benefits**: Constant memory usage regardless of dataset size
- **Configuration**: Configurable item heights and buffer sizes

#### Efficient State Management
- **Local State**: React hooks for component-level state
- **Shared State**: Context API for cross-component state
- **Caching**: Intelligent caching of API responses with TTL

#### Lazy Loading
- **Route Splitting**: Code splitting for session detail view
- **Component Lazy Loading**: On-demand component loading
- **Data Lazy Loading**: Incremental timeline data loading

### Scalability Design

#### Client-Side Scalability
- **Memory Management**: Proper component cleanup and memory leak prevention
- **Bundle Optimization**: Tree shaking and webpack optimization
- **Progressive Loading**: Incremental data loading strategies

#### API Interaction Scalability
- **Request Debouncing**: Debounced search and filter operations
- **Batch Operations**: Batched API requests where possible
- **Connection Pooling**: Efficient WebSocket connection management

### Performance Optimizations

- **Memoization**: React.memo and useMemo for expensive computations
- **Virtualization**: Virtual scrolling for large lists and timelines
- **Image Optimization**: Optimized icons and graphics
- **Bundle Splitting**: Route-based code splitting
- **Service Worker**: Optional caching for static assets

## Error Handling & Resilience

### Error Handling Strategy

#### Error Categories
- **Network Errors**: API connection failures and timeouts
- **Data Errors**: Invalid or corrupted response data
- **Application Errors**: Component rendering and state management errors
- **WebSocket Errors**: Connection drops and message parsing failures

#### Error Handling Pattern
```typescript
interface ErrorState {
  hasError: boolean;
  error: Error | null;
  errorBoundary?: string;
  retryAction?: () => void;
}
```

### Failure Modes

- **API Unavailability**
  - **Impact**: Cannot load session data or updates
  - **Detection**: HTTP error responses and timeout detection
  - **Recovery**: Retry mechanism with exponential backoff, offline message

- **WebSocket Connection Loss**
  - **Impact**: No real-time updates received
  - **Detection**: WebSocket close/error events
  - **Recovery**: Automatic reconnection with status indicator

- **Large Dataset Performance**
  - **Impact**: UI becomes unresponsive
  - **Detection**: Performance monitoring and user feedback
  - **Recovery**: Progressive loading and virtualization

### Resilience Patterns

- **Circuit Breaker**: Prevent cascade failures in API calls
- **Retry Pattern**: Exponential backoff for failed requests
- **Graceful Degradation**: Functional UI even with limited backend connectivity
- **Error Boundaries**: Component-level error isolation

## Configuration & Deployment

## Project Structure

### Directory Layout

The dashboard application will be implemented as an independent sibling directory to maintain clear separation:

```
tarsy-bot/
├── alert-dev-ui/          # Existing development/testing UI (unchanged)
│   ├── src/
│   ├── package.json
│   └── ...
├── dashboard/             # New SRE operational dashboard  
│   ├── src/
│   │   ├── components/
│   │   ├── services/
│   │   ├── hooks/
│   │   └── types/
│   ├── package.json
│   ├── tsconfig.json
│   └── ...
├── backend/               # Backend services (WebSocket additions required)
└── ...
```

### Application Independence

- **Separate Deployments**: Each application can be built and deployed independently
- **Separate Dependencies**: Each maintains its own `package.json` and dependency management
- **Shared Infrastructure**: Both connect to the same backend services
- **Independent Development**: Teams can work on each application without conflicts

### Configuration Changes

#### New Configuration Options

- **REACT_APP_API_BASE_URL**: Backend API base URL (default: http://localhost:8000)
- **REACT_APP_WS_BASE_URL**: WebSocket base URL (default: ws://localhost:8000)
- **REACT_APP_PAGE_SIZE**: Default pagination size (default: 25)
- **REACT_APP_ENABLE_MOCK_DATA**: Enable mock data mode for development (default: false)

#### Environment-Specific Configuration

- **Development**: Mock data support and debug logging
- **Production**: Optimized builds and error reporting
- **Testing**: Test-specific API endpoints and reduced animations

## Testing Strategy

### Unit Testing

#### Test Coverage Areas

- **Component Rendering**: Snapshot and rendering tests for all components
- **State Management**: Hook and context testing
- **API Integration**: Mock API response handling
- **Utility Functions**: Pure function testing with comprehensive edge cases

#### Testing Tools
- **Jest**: Test runner and assertion framework
- **React Testing Library**: Component testing utilities
- **MSW**: API mocking for testing
- **Jest-WebSocket-Mock**: WebSocket mocking

### Integration Testing

#### Integration Points to Test

- **API Service Integration**: Full API request/response cycle testing
- **WebSocket Integration**: Real-time message handling and reconnection
- **Component Integration**: Parent-child component communication
- **Router Integration**: Navigation and route parameter handling

### End-to-End Testing (Mock Services Only)

#### Test Scenarios

- **Session List Workflow**: Load dashboard, apply filters, view results
- **Session Detail Workflow**: Navigate to session detail, view timeline
- **Real-time Updates**: Simulate live session updates and verify UI updates
- **Error Scenarios**: Test error handling and recovery mechanisms

## Monitoring & Observability

### Logging Strategy

#### Client-Side Logging
- **Error Logging**: Comprehensive error logging with stack traces
- **Performance Logging**: Performance mark and measure API
- **User Action Logging**: Optional user interaction analytics
- **Debug Logging**: Development-only detailed logging

#### Log Levels
- **ERROR**: Application errors and API failures
- **WARN**: Performance issues and deprecated feature usage
- **INFO**: User actions and application state changes
- **DEBUG**: Detailed development information

## Migration & Backward Compatibility

### Migration Strategy

No migration required as this is a new standalone application.

### Backward Compatibility

- **API Compatibility**: Compatible with existing EP-0003 history service
- **Browser Compatibility**: Support for modern browsers (Chrome 90+, Firefox 88+, Safari 14+)
- **Accessibility Compatibility**: WCAG 2.1 AA compliance maintained

### Migration Steps

1. **Development Environment Setup**: Initialize React application in `dashboard/` directory
2. **Component Development**: Build components incrementally with testing
3. **API Integration**: Connect to existing history service endpoints
4. **WebSocket Integration**: Implement optimized multiplexed WebSocket system with subscription management
5. **Production Deployment**: Deploy as standalone application


## Implementation Sequence & Priorities

### Phased Development Strategy

The dashboard implementation follows a **dual-track approach**: backend infrastructure development alongside incremental frontend phases for early value delivery.

**📋 Detailed Implementation Plan**: For comprehensive phase-by-phase implementation details, component specifications, API integrations, and success criteria, see **`EP-0004-dashboard-ui-phases.md`**.

### Backend Infrastructure (Foundation)

**Priority: Critical - Must complete before frontend phases**

#### Backend Track 1: Core Infrastructure
- **WebSocket System**: Implement `/ws/dashboard/{user_id}` multiplexed endpoint
- **Subscription Management**: Channel-based message routing (`dashboard_updates`, `session_{id}`)
- **Connection Management**: Auto-reconnection, state persistence, graceful cleanup

#### Backend Track 2: Integrated Hook System  
- **Dashboard Broadcast Hooks**: Extend existing EP-0003 `BaseEventHook` system
- **Hook Registration**: Integrate dashboard hooks alongside existing history hooks
- **Event Formatting**: Transform hook events for dashboard WebSocket broadcasting

### Frontend Phases (Progressive Enhancement)

**Phase 1 (Basic Alert List)**: Simple session list with Material-UI Table  
**Phase 2 (Active/Historical Split)**: Distinct panels for operational awareness  
**Phase 3 (Navigation & Detail)**: Session detail pages with timeline visualization  
**Phase 4 (Search & Filtering)**: Enhanced data exploration capabilities  
**Phase 5 (Real-time Updates)**: Live session monitoring with WebSocket integration  
**Phase 6 (Advanced Features)**: Pagination, export, performance optimizations  
**Phase 7 (Polish & Performance)**: Virtual scrolling, caching, final optimizations

### Implementation Dependencies

```
Backend WebSocket + Hook System
    ↓
Phase 1: Basic List (Independent)
    ↓
Phase 2: Active/Historical Split
    ↓ 
Phase 3: Detail Navigation
    ↓
Phase 4: Search/Filter (Independent)
    ↓
Phase 5: Real-time (Requires WebSocket)
    ↓
Phase 6-7: Advanced Features
```

**Key Advantage**: Early phases can begin with mock data while backend infrastructure is being completed.

## Implementation Considerations

### Technical Advantages of Integrated Hook System

- **Reduced Complexity**: No need to create separate event infrastructure
- **Data Consistency**: Same event timing and context as history service
- **No Service Modifications**: Existing LLM/MCP clients remain unchanged
- **Performance**: Concurrent hook execution with existing history hooks
- **Maintainability**: Single event pipeline reduces potential inconsistencies
- **Future Extensions**: Same hook system can support additional features

### Dependencies

**📋 Complete Dependency List**: For detailed dependency specifications, installation commands, and version requirements, see **`EP-0004-dashboard-ui-phases.md`**.

#### Core Framework
- **React 18.2.0**: Latest stable with concurrent features and improved performance
- **TypeScript**: Type safety and enhanced developer experience  
- **Vite**: Fast build tool with superior development experience

#### UI & Design
- **Material-UI v5.15.0**: Complete Material Design system with 50+ components
- **@mui/icons-material**: Comprehensive icon library for consistent iconography
- **@mui/lab**: Timeline components for session visualization (Phase 5+)
- **@emotion/react**: CSS-in-JS solution bundled with Material-UI

#### Functionality
- **React-Router-Dom v6**: Client-side routing and navigation
- **Axios**: HTTP client for API communication
- **react-markdown**: Markdown rendering for AI analysis content
- **React-Window**: Virtual scrolling for performance optimization (Phase 6+)

#### Backend Integration  
- **EP-0003 Hook System**: Existing hook infrastructure (BaseEventHook, HookManager)
- **History Service API**: Existing REST endpoints for session data

### Integrated Hook System Implementation Details

**Backend Hook Implementation Pattern**
```python
class DashboardBroadcastHooks(BaseEventHook):
    """Extends existing EP-0003 hook system for dashboard broadcasting"""
    
    def __init__(self, dashboard_broadcaster):
        super().__init__("dashboard_broadcast_hook")
        self.broadcaster = dashboard_broadcaster
        self.update_service = DashboardUpdateService()
    
    async def execute(self, event_type: str, **kwargs):
        """Same signature as existing history hooks"""
        session_id = kwargs.get('session_id')
        if not session_id:
            return
            
        # Format hook data for dashboard
        dashboard_data = self.update_service.format_hook_event(event_type, **kwargs)
        
        # Broadcast via WebSocket
        if event_type.endswith('.post'):
            await self.broadcaster.broadcast_session_update(session_id, dashboard_data)

# Registration alongside existing hooks
def register_integrated_hooks():
    hook_manager = get_hook_manager()  # Uses existing EP-0003 infrastructure
    
    # Existing history hooks (unchanged)
    llm_history_hooks = LLMHooks()
    hook_manager.register_hook("llm.post", llm_history_hooks)
    
    # New dashboard hooks (same events, different actions)
    dashboard_broadcaster = get_dashboard_broadcaster()
    llm_dashboard_hooks = DashboardBroadcastHooks(dashboard_broadcaster)
    hook_manager.register_hook("llm.post", llm_dashboard_hooks)
    
    # Both execute concurrently!
```

**Frontend WebSocket Integration (Unchanged)**
```typescript
class MultiplexedWebSocketManager {
  // Same implementation as original design
  // Receives formatted messages from dashboard hooks
}
```

### Constraints

- **Browser Compatibility**: Modern browser requirement for performance features
- **Network Dependency**: Requires stable network connection for real-time features
- **Screen Size**: Optimized for desktop/tablet usage primarily
- **Hook System Dependency**: Requires existing EP-0003 hook infrastructure to be operational

## Documentation Requirements

### Code Documentation

- **Component Documentation**: JSDoc comments for all components and hooks
- **API Documentation**: Inline comments for API service methods
- **Type Documentation**: Comprehensive TypeScript interfaces and types

### API Documentation

- **Integration Guide**: How to connect dashboard to backend services
- **WebSocket Protocol**: Message format and connection handling documentation
- **Configuration Guide**: Environment variable and deployment configuration

---

## Design Review Checklist

### Architecture Review
- [x] Architecture is sound and scalable with proper separation of concerns
- [x] Components are well-defined with clear responsibilities and interfaces
- [x] Data flow is logical and efficient with proper state management
- [x] Integration points are well-defined with existing EP-0003 API
- [x] Security considerations are addressed with React best practices

### Implementation Review
- [x] Design is implementable with React 18.2.0 and Material-UI v5.15.0
- [x] Performance requirements can be met with virtual scrolling and optimization
- [x] Error handling is comprehensive with proper fallback mechanisms
- [x] Testing strategy is adequate with unit, integration, and e2e coverage
- [x] Monitoring and observability are addressed with client-side metrics

### Requirements Traceability
- [x] All functional requirements from requirements doc are addressed
- [x] All non-functional requirements (performance, security, usability) are met
- [x] Design decisions support SRE operational monitoring needs
- [x] Real-time WebSocket requirements are comprehensively designed
- [x] Success criteria can be met with this technical design

---

## Next Steps

After design approval:
1. **Begin Backend Implementation**: Start with Phase 1 backend WebSocket infrastructure
2. **Implement Integrated Hook System**: Create dashboard broadcast hooks extending existing EP-0003 hook system
3. **Create Implementation Plan**: `docs/enhancements/pending/EP-0004-dashboard-ui-implementation.md` 
4. **Backend Development**: Complete Phases 1-2 with integrated hook system before frontend work
5. **Frontend Development**: Initialize `dashboard/` directory structure after backend integration is functional

**Development Priority**: Backend WebSocket infrastructure must be completed first, followed by integrated hook system implementation as the foundation for all dashboard functionality.

**Key Integration Advantage**: The integrated hook system approach reduces backend complexity by leveraging existing EP-0003 infrastructure while ensuring data consistency between historical and real-time dashboard data.

**AI Prompt for Next Phase:**
```
Create an implementation plan using the template at docs/templates/ep-implementation-template.md for EP-0004 based on the approved integrated hook system design in this document and the requirements in EP-0004-dashboard-ui-requirements.md. Prioritize backend WebSocket implementation followed by integrated hook system as Phase 1-2 dependencies.
```

---
*Last Updated: 2025-01-25 - Added export/search endpoints, comprehensive test coverage, and backend implementation details* 