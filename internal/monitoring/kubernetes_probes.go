package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ProbeType represents the type of Kubernetes probe
type ProbeType string

const (
	ProbeTypeLiveness  ProbeType = "liveness"
	ProbeTypeReadiness ProbeType = "readiness"
	ProbeTypeStartup   ProbeType = "startup"
)

// ProbeStatus represents the status of a probe
type ProbeStatus string

const (
	ProbeStatusHealthy   ProbeStatus = "healthy"
	ProbeStatusUnhealthy ProbeStatus = "unhealthy"
	ProbeStatusStarting  ProbeStatus = "starting"
	ProbeStatusShutdown  ProbeStatus = "shutdown"
)

// ProbeConfig contains configuration for Kubernetes probes
type ProbeConfig struct {
	LivenessConfig  *ProbeEndpointConfig `json:"liveness_config"`
	ReadinessConfig *ProbeEndpointConfig `json:"readiness_config"`
	StartupConfig   *ProbeEndpointConfig `json:"startup_config"`

	// Global settings
	ShutdownGracePeriod time.Duration `json:"shutdown_grace_period"`
	StartupTimeout      time.Duration `json:"startup_timeout"`
	HealthCheckTimeout  time.Duration `json:"health_check_timeout"`
}

// ProbeEndpointConfig contains configuration for a specific probe endpoint
type ProbeEndpointConfig struct {
	Enabled          bool               `json:"enabled"`
	Path             string             `json:"path"`
	Port             int                `json:"port,omitempty"`
	InitialDelay     time.Duration      `json:"initial_delay"`
	PeriodSeconds    time.Duration      `json:"period_seconds"`
	TimeoutSeconds   time.Duration      `json:"timeout_seconds"`
	FailureThreshold int                `json:"failure_threshold"`
	SuccessThreshold int                `json:"success_threshold"`
	Checks           []ProbeCheck       `json:"checks"`
}

// ProbeCheck represents a health check for probes
type ProbeCheck struct {
	Name        string `json:"name"`
	Component   string `json:"component"`
	Critical    bool   `json:"critical"`    // If true, failure causes probe to fail
	Required    bool   `json:"required"`    // If true, must be healthy for readiness
	Timeout     time.Duration `json:"timeout"`
	CheckFunc   func(context.Context) error `json:"-"`
}

// DefaultProbeConfig returns default Kubernetes probe configuration
func DefaultProbeConfig() *ProbeConfig {
	return &ProbeConfig{
		LivenessConfig: &ProbeEndpointConfig{
			Enabled:          true,
			Path:             "/health/live",
			InitialDelay:     30 * time.Second,
			PeriodSeconds:    10 * time.Second,
			TimeoutSeconds:   5 * time.Second,
			FailureThreshold: 3,
			SuccessThreshold: 1,
			Checks: []ProbeCheck{
				{
					Name:      "api_server",
					Component: "api",
					Critical:  true,
					Timeout:   2 * time.Second,
				},
			},
		},
		ReadinessConfig: &ProbeEndpointConfig{
			Enabled:          true,
			Path:             "/health/ready",
			InitialDelay:     5 * time.Second,
			PeriodSeconds:    5 * time.Second,
			TimeoutSeconds:   3 * time.Second,
			FailureThreshold: 3,
			SuccessThreshold: 1,
			Checks: []ProbeCheck{
				{
					Name:      "dependencies",
					Component: "dependencies",
					Critical:  false,
					Required:  true,
					Timeout:   2 * time.Second,
				},
				{
					Name:      "agent_registry",
					Component: "agents",
					Critical:  false,
					Required:  true,
					Timeout:   1 * time.Second,
				},
				{
					Name:      "pipeline",
					Component: "pipeline",
					Critical:  false,
					Required:  true,
					Timeout:   1 * time.Second,
				},
			},
		},
		StartupConfig: &ProbeEndpointConfig{
			Enabled:          true,
			Path:             "/health/startup",
			InitialDelay:     0,
			PeriodSeconds:    2 * time.Second,
			TimeoutSeconds:   1 * time.Second,
			FailureThreshold: 30, // 60 seconds total
			SuccessThreshold: 1,
			Checks: []ProbeCheck{
				{
					Name:      "initialization",
					Component: "startup",
					Critical:  true,
					Required:  true,
					Timeout:   500 * time.Millisecond,
				},
			},
		},
		ShutdownGracePeriod: 30 * time.Second,
		StartupTimeout:      60 * time.Second,
		HealthCheckTimeout:  5 * time.Second,
	}
}

// KubernetesProbeManager manages Kubernetes probe endpoints
type KubernetesProbeManager struct {
	config              *ProbeConfig
	dependencyChecker   *DependencyHealthChecker
	logger              *zap.Logger
	mutex               sync.RWMutex

	// State management
	startupCompleted    bool
	shutdownInitiated   bool
	applicationReady    bool
	lastStartupCheck    time.Time

	// Probe states
	livenessStatus      ProbeStatus
	readinessStatus     ProbeStatus
	startupStatus       ProbeStatus

	// Counters
	livenessFailures    int
	readinessFailures   int
	startupFailures     int

	// Custom check functions
	customChecks        map[string]func(context.Context) error

	// Application lifecycle hooks
	startupHooks        []func() error
	shutdownHooks       []func() error
}

// NewKubernetesProbeManager creates a new Kubernetes probe manager
func NewKubernetesProbeManager(config *ProbeConfig, dependencyChecker *DependencyHealthChecker, logger *zap.Logger) *KubernetesProbeManager {
	if config == nil {
		config = DefaultProbeConfig()
	}

	return &KubernetesProbeManager{
		config:            config,
		dependencyChecker: dependencyChecker,
		logger:            logger.With(zap.String("component", "k8s_probes")),
		livenessStatus:    ProbeStatusStarting,
		readinessStatus:   ProbeStatusStarting,
		startupStatus:     ProbeStatusStarting,
		customChecks:      make(map[string]func(context.Context) error),
		startupHooks:      make([]func() error, 0),
		shutdownHooks:     make([]func() error, 0),
	}
}

// RegisterCustomCheck registers a custom health check function
func (kpm *KubernetesProbeManager) RegisterCustomCheck(name string, checkFunc func(context.Context) error) {
	kpm.mutex.Lock()
	defer kpm.mutex.Unlock()

	kpm.customChecks[name] = checkFunc
	kpm.logger.Info("Custom health check registered", zap.String("check_name", name))
}

// AddStartupHook adds a function to be called during startup
func (kpm *KubernetesProbeManager) AddStartupHook(hook func() error) {
	kpm.mutex.Lock()
	defer kpm.mutex.Unlock()

	kpm.startupHooks = append(kpm.startupHooks, hook)
}

// AddShutdownHook adds a function to be called during shutdown
func (kpm *KubernetesProbeManager) AddShutdownHook(hook func() error) {
	kpm.mutex.Lock()
	defer kpm.mutex.Unlock()

	kpm.shutdownHooks = append(kpm.shutdownHooks, hook)
}

// MarkApplicationReady marks the application as ready to serve traffic
func (kpm *KubernetesProbeManager) MarkApplicationReady() {
	kpm.mutex.Lock()
	defer kpm.mutex.Unlock()

	kpm.applicationReady = true
	kpm.readinessStatus = ProbeStatusHealthy

	kpm.logger.Info("Application marked as ready")
}

// MarkStartupCompleted marks the startup process as completed
func (kpm *KubernetesProbeManager) MarkStartupCompleted() {
	kpm.mutex.Lock()
	defer kpm.mutex.Unlock()

	kpm.startupCompleted = true
	kpm.startupStatus = ProbeStatusHealthy
	kpm.livenessStatus = ProbeStatusHealthy

	kpm.logger.Info("Startup process completed")
}

// InitiateShutdown initiates graceful shutdown
func (kpm *KubernetesProbeManager) InitiateShutdown() error {
	kpm.mutex.Lock()
	defer kpm.mutex.Unlock()

	kpm.shutdownInitiated = true
	kpm.readinessStatus = ProbeStatusShutdown

	kpm.logger.Info("Graceful shutdown initiated")

	// Execute shutdown hooks
	for i, hook := range kpm.shutdownHooks {
		if err := hook(); err != nil {
			kpm.logger.Error("Shutdown hook failed",
				zap.Int("hook_index", i),
				zap.Error(err))
			return err
		}
	}

	return nil
}

// LivenessHandler handles Kubernetes liveness probe requests
func (kpm *KubernetesProbeManager) LivenessHandler(w http.ResponseWriter, r *http.Request) {
	if !kpm.config.LivenessConfig.Enabled {
		kpm.sendProbeResponse(w, ProbeStatusHealthy, "Liveness probe disabled", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), kpm.config.LivenessConfig.TimeoutSeconds)
	defer cancel()

	status, message, details := kpm.performLivenessCheck(ctx)

	kpm.mutex.Lock()
	if status == ProbeStatusHealthy {
		kpm.livenessFailures = 0
	} else {
		kpm.livenessFailures++
	}
	kpm.livenessStatus = status
	kpm.mutex.Unlock()

	kpm.sendProbeResponse(w, status, message, details)
}

// ReadinessHandler handles Kubernetes readiness probe requests
func (kpm *KubernetesProbeManager) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	if !kpm.config.ReadinessConfig.Enabled {
		kpm.sendProbeResponse(w, ProbeStatusHealthy, "Readiness probe disabled", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), kpm.config.ReadinessConfig.TimeoutSeconds)
	defer cancel()

	status, message, details := kpm.performReadinessCheck(ctx)

	kpm.mutex.Lock()
	if status == ProbeStatusHealthy {
		kpm.readinessFailures = 0
	} else {
		kpm.readinessFailures++
	}
	kpm.readinessStatus = status
	kpm.mutex.Unlock()

	kpm.sendProbeResponse(w, status, message, details)
}

// StartupHandler handles Kubernetes startup probe requests
func (kpm *KubernetesProbeManager) StartupHandler(w http.ResponseWriter, r *http.Request) {
	if !kpm.config.StartupConfig.Enabled {
		kpm.sendProbeResponse(w, ProbeStatusHealthy, "Startup probe disabled", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), kpm.config.StartupConfig.TimeoutSeconds)
	defer cancel()

	status, message, details := kpm.performStartupCheck(ctx)

	kpm.mutex.Lock()
	if status == ProbeStatusHealthy {
		kpm.startupFailures = 0
		if !kpm.startupCompleted {
			kpm.MarkStartupCompleted()
		}
	} else {
		kpm.startupFailures++
	}
	kpm.startupStatus = status
	kpm.lastStartupCheck = time.Now()
	kpm.mutex.Unlock()

	kpm.sendProbeResponse(w, status, message, details)
}

// performLivenessCheck performs the liveness check
func (kpm *KubernetesProbeManager) performLivenessCheck(ctx context.Context) (ProbeStatus, string, map[string]interface{}) {
	kpm.mutex.RLock()
	shutdownInitiated := kpm.shutdownInitiated
	kpm.mutex.RUnlock()

	if shutdownInitiated {
		return ProbeStatusShutdown, "Application is shutting down", nil
	}

	// Basic liveness check - ensure the process is responsive
	details := make(map[string]interface{})

	// Check basic application health
	for _, check := range kpm.config.LivenessConfig.Checks {
		checkCtx, cancel := context.WithTimeout(ctx, check.Timeout)
		var err error

		if checkFunc, exists := kpm.customChecks[check.Name]; exists {
			err = checkFunc(checkCtx)
		} else {
			err = kpm.performBuiltinCheck(checkCtx, check)
		}

		cancel()

		details[check.Name] = map[string]interface{}{
			"status": err == nil,
			"error":  nil,
		}

		if err != nil {
			details[check.Name].(map[string]interface{})["error"] = err.Error()
			if check.Critical {
				return ProbeStatusUnhealthy, fmt.Sprintf("Critical check failed: %s", check.Name), details
			}
		}
	}

	return ProbeStatusHealthy, "All liveness checks passed", details
}

// performReadinessCheck performs the readiness check
func (kpm *KubernetesProbeManager) performReadinessCheck(ctx context.Context) (ProbeStatus, string, map[string]interface{}) {
	kpm.mutex.RLock()
	shutdownInitiated := kpm.shutdownInitiated
	applicationReady := kpm.applicationReady
	kpm.mutex.RUnlock()

	if shutdownInitiated {
		return ProbeStatusShutdown, "Application is shutting down", nil
	}

	if !applicationReady {
		return ProbeStatusStarting, "Application not yet ready", nil
	}

	details := make(map[string]interface{})

	// Check dependencies
	if kpm.dependencyChecker != nil {
		dependencyHealth := kpm.dependencyChecker.GetAllDependencyHealth()
		details["dependencies"] = dependencyHealth

		for name, health := range dependencyHealth {
			if health.Required && health.Status != DependencyStatusHealthy {
				return ProbeStatusUnhealthy, fmt.Sprintf("Required dependency unhealthy: %s", name), details
			}
		}
	}

	// Perform readiness checks
	for _, check := range kpm.config.ReadinessConfig.Checks {
		checkCtx, cancel := context.WithTimeout(ctx, check.Timeout)
		var err error

		if checkFunc, exists := kpm.customChecks[check.Name]; exists {
			err = checkFunc(checkCtx)
		} else {
			err = kpm.performBuiltinCheck(checkCtx, check)
		}

		cancel()

		details[check.Name] = map[string]interface{}{
			"status": err == nil,
			"error":  nil,
		}

		if err != nil {
			details[check.Name].(map[string]interface{})["error"] = err.Error()
			if check.Required {
				return ProbeStatusUnhealthy, fmt.Sprintf("Required check failed: %s", check.Name), details
			}
		}
	}

	return ProbeStatusHealthy, "Application is ready to serve traffic", details
}

// performStartupCheck performs the startup check
func (kpm *KubernetesProbeManager) performStartupCheck(ctx context.Context) (ProbeStatus, string, map[string]interface{}) {
	kpm.mutex.RLock()
	startupCompleted := kpm.startupCompleted
	kpm.mutex.RUnlock()

	if startupCompleted {
		return ProbeStatusHealthy, "Startup completed", nil
	}

	details := make(map[string]interface{})

	// Execute startup hooks if not completed
	if !startupCompleted {
		for i, hook := range kpm.startupHooks {
			if err := hook(); err != nil {
				details[fmt.Sprintf("startup_hook_%d", i)] = map[string]interface{}{
					"status": false,
					"error":  err.Error(),
				}
				return ProbeStatusStarting, "Startup hook failed", details
			}
			details[fmt.Sprintf("startup_hook_%d", i)] = map[string]interface{}{
				"status": true,
				"error":  nil,
			}
		}
	}

	// Perform startup checks
	for _, check := range kpm.config.StartupConfig.Checks {
		checkCtx, cancel := context.WithTimeout(ctx, check.Timeout)
		var err error

		if checkFunc, exists := kpm.customChecks[check.Name]; exists {
			err = checkFunc(checkCtx)
		} else {
			err = kpm.performBuiltinCheck(checkCtx, check)
		}

		cancel()

		details[check.Name] = map[string]interface{}{
			"status": err == nil,
			"error":  nil,
		}

		if err != nil {
			details[check.Name].(map[string]interface{})["error"] = err.Error()
			if check.Critical {
				return ProbeStatusStarting, fmt.Sprintf("Startup check failed: %s", check.Name), details
			}
		}
	}

	return ProbeStatusHealthy, "Startup checks passed", details
}

// performBuiltinCheck performs built-in health checks
func (kpm *KubernetesProbeManager) performBuiltinCheck(ctx context.Context, check ProbeCheck) error {
	switch check.Component {
	case "api":
		// Basic API server health check
		return nil
	case "dependencies":
		if kpm.dependencyChecker != nil {
			overallHealth := kpm.dependencyChecker.GetOverallHealth()
			if overallHealth == DependencyStatusUnhealthy {
				return fmt.Errorf("dependencies are unhealthy")
			}
		}
		return nil
	case "agents":
		// Agent registry health check
		return nil
	case "pipeline":
		// Pipeline health check
		return nil
	case "startup":
		// Basic startup check
		return nil
	default:
		return fmt.Errorf("unknown check component: %s", check.Component)
	}
}

// sendProbeResponse sends a standardized probe response
func (kpm *KubernetesProbeManager) sendProbeResponse(w http.ResponseWriter, status ProbeStatus, message string, details map[string]interface{}) {
	response := map[string]interface{}{
		"status":    string(status),
		"message":   message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	if details != nil {
		response["details"] = details
	}

	w.Header().Set("Content-Type", "application/json")

	if status == ProbeStatusHealthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(response)

	kpm.logger.Debug("Probe response sent",
		zap.String("status", string(status)),
		zap.String("message", message))
}

// GetProbeStatus returns the current status of all probes
func (kpm *KubernetesProbeManager) GetProbeStatus() map[string]interface{} {
	kpm.mutex.RLock()
	defer kpm.mutex.RUnlock()

	return map[string]interface{}{
		"liveness": map[string]interface{}{
			"status":   string(kpm.livenessStatus),
			"failures": kpm.livenessFailures,
			"enabled":  kpm.config.LivenessConfig.Enabled,
		},
		"readiness": map[string]interface{}{
			"status":           string(kpm.readinessStatus),
			"failures":         kpm.readinessFailures,
			"enabled":          kpm.config.ReadinessConfig.Enabled,
			"application_ready": kpm.applicationReady,
		},
		"startup": map[string]interface{}{
			"status":            string(kpm.startupStatus),
			"failures":          kpm.startupFailures,
			"enabled":           kpm.config.StartupConfig.Enabled,
			"startup_completed": kpm.startupCompleted,
			"last_check":        kpm.lastStartupCheck,
		},
		"application": map[string]interface{}{
			"shutdown_initiated": kpm.shutdownInitiated,
			"startup_completed":  kpm.startupCompleted,
			"application_ready":  kpm.applicationReady,
		},
	}
}