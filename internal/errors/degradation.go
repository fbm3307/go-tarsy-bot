package errors

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DegradationLevel represents the level of service degradation
type DegradationLevel string

const (
	DegradationLevelNone     DegradationLevel = "none"     // Full functionality
	DegradationLevelMinor    DegradationLevel = "minor"    // Some non-critical features disabled
	DegradationLevelModerate DegradationLevel = "moderate" // Several features disabled
	DegradationLevelSevere   DegradationLevel = "severe"   // Only core functionality
	DegradationLevelCritical DegradationLevel = "critical" // Minimal emergency functionality
)

// FeatureFlag represents a feature that can be enabled/disabled
type FeatureFlag struct {
	Name        string           `json:"name"`
	Enabled     bool             `json:"enabled"`
	Required    bool             `json:"required"`    // If true, disabling causes degradation
	Critical    bool             `json:"critical"`    // If true, failure causes severe degradation
	DependsOn   []string         `json:"depends_on"`  // Feature dependencies
	MaxLevel    DegradationLevel `json:"max_level"`   // Maximum degradation level this feature allows
	LastCheck   time.Time        `json:"last_check"`
	HealthStatus string          `json:"health_status"`
}

// DegradationConfig contains configuration for graceful degradation
type DegradationConfig struct {
	EnableGracefulDegradation bool                        `json:"enable_graceful_degradation"`
	HealthCheckInterval       time.Duration               `json:"health_check_interval"`
	RecoveryCheckInterval     time.Duration               `json:"recovery_check_interval"`
	Features                  map[string]*FeatureFlag     `json:"features"`
	DegradationRules          map[string]DegradationRule  `json:"degradation_rules"`
	AutoRecovery              bool                        `json:"auto_recovery"`
	RecoveryTimeout           time.Duration               `json:"recovery_timeout"`
}

// DegradationRule defines when and how to degrade service
type DegradationRule struct {
	Condition       string           `json:"condition"`        // e.g., "error_rate > 0.5"
	Action          DegradationAction `json:"action"`
	TargetLevel     DegradationLevel `json:"target_level"`
	DisableFeatures []string         `json:"disable_features"`
	EnableFeatures  []string         `json:"enable_features"`
	Priority        int              `json:"priority"`         // Higher priority rules are evaluated first
}

// DegradationAction represents actions to take during degradation
type DegradationAction string

const (
	DegradationActionDisableFeature   DegradationAction = "disable_feature"
	DegradationActionEnableFeature    DegradationAction = "enable_feature"
	DegradationActionSwitchMode       DegradationAction = "switch_mode"
	DegradationActionReduceCapacity   DegradationAction = "reduce_capacity"
	DegradationActionSkipNonCritical  DegradationAction = "skip_non_critical"
)

// ServiceDegradationManager manages graceful degradation of service functionality
type ServiceDegradationManager struct {
	config           *DegradationConfig
	currentLevel     DegradationLevel
	features         map[string]*FeatureFlag
	logger           *zap.Logger
	mutex            sync.RWMutex

	// Health tracking
	errorRate        float64
	lastHealthCheck  time.Time
	degradationStartTime *time.Time

	// Metrics
	degradationEvents int64
	recoveryEvents    int64
	featureToggles    int64
}

// NewServiceDegradationManager creates a new service degradation manager
func NewServiceDegradationManager(config *DegradationConfig, logger *zap.Logger) *ServiceDegradationManager {
	if config == nil {
		config = DefaultDegradationConfig()
	}

	// Initialize features map
	features := make(map[string]*FeatureFlag)
	for name, feature := range config.Features {
		features[name] = &FeatureFlag{
			Name:         name,
			Enabled:      feature.Enabled,
			Required:     feature.Required,
			Critical:     feature.Critical,
			DependsOn:    feature.DependsOn,
			MaxLevel:     feature.MaxLevel,
			LastCheck:    time.Now(),
			HealthStatus: "unknown",
		}
	}

	return &ServiceDegradationManager{
		config:       config,
		currentLevel: DegradationLevelNone,
		features:     features,
		logger:       logger.With(zap.String("component", "degradation_manager")),
	}
}

// DefaultDegradationConfig returns default degradation configuration
func DefaultDegradationConfig() *DegradationConfig {
	return &DegradationConfig{
		EnableGracefulDegradation: true,
		HealthCheckInterval:       30 * time.Second,
		RecoveryCheckInterval:     60 * time.Second,
		AutoRecovery:              true,
		RecoveryTimeout:           5 * time.Minute,
		Features: map[string]*FeatureFlag{
			"llm_integration": {
				Name:     "llm_integration",
				Enabled:  true,
				Required: true,
				Critical: true,
				MaxLevel: DegradationLevelSevere,
			},
			"mcp_integration": {
				Name:     "mcp_integration",
				Enabled:  true,
				Required: true,
				Critical: false,
				MaxLevel: DegradationLevelModerate,
			},
			"websocket_updates": {
				Name:     "websocket_updates",
				Enabled:  true,
				Required: false,
				Critical: false,
				MaxLevel: DegradationLevelMinor,
			},
			"detailed_logging": {
				Name:     "detailed_logging",
				Enabled:  true,
				Required: false,
				Critical: false,
				MaxLevel: DegradationLevelMinor,
			},
			"metrics_collection": {
				Name:     "metrics_collection",
				Enabled:  true,
				Required: false,
				Critical: false,
				MaxLevel: DegradationLevelMinor,
			},
		},
		DegradationRules: make(map[string]DegradationRule),
	}
}

// IsFeatureEnabled checks if a feature is currently enabled
func (dm *ServiceDegradationManager) IsFeatureEnabled(featureName string) bool {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	if feature, exists := dm.features[featureName]; exists {
		return feature.Enabled
	}
	return false
}

// DisableFeature disables a specific feature
func (dm *ServiceDegradationManager) DisableFeature(featureName string, reason string) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	feature, exists := dm.features[featureName]
	if !exists {
		return NewStructuredError(
			"FEATURE_NOT_FOUND",
			fmt.Sprintf("Feature '%s' not found", featureName),
			ErrorCategoryConfiguration,
			ErrorSeverityMedium,
		)
	}

	if feature.Enabled {
		feature.Enabled = false
		dm.featureToggles++

		dm.logger.Warn("Feature disabled",
			zap.String("feature", featureName),
			zap.String("reason", reason))

		// Check if this affects degradation level
		dm.evaluateDegradationLevel()
	}

	return nil
}

// EnableFeature enables a specific feature
func (dm *ServiceDegradationManager) EnableFeature(featureName string) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	feature, exists := dm.features[featureName]
	if !exists {
		return NewStructuredError(
			"FEATURE_NOT_FOUND",
			fmt.Sprintf("Feature '%s' not found", featureName),
			ErrorCategoryConfiguration,
			ErrorSeverityMedium,
		)
	}

	// Check dependencies before enabling
	if err := dm.checkFeatureDependencies(featureName); err != nil {
		return err
	}

	if !feature.Enabled {
		feature.Enabled = true
		dm.featureToggles++

		dm.logger.Info("Feature enabled",
			zap.String("feature", featureName))

		// Check if this improves degradation level
		dm.evaluateDegradationLevel()
	}

	return nil
}

// checkFeatureDependencies checks if feature dependencies are met
func (dm *ServiceDegradationManager) checkFeatureDependencies(featureName string) error {
	feature := dm.features[featureName]
	if feature == nil {
		return fmt.Errorf("feature not found: %s", featureName)
	}

	for _, dependency := range feature.DependsOn {
		depFeature, exists := dm.features[dependency]
		if !exists {
			return NewStructuredError(
				"DEPENDENCY_NOT_FOUND",
				fmt.Sprintf("Dependency '%s' not found for feature '%s'", dependency, featureName),
				ErrorCategoryConfiguration,
				ErrorSeverityMedium,
			)
		}

		if !depFeature.Enabled {
			return NewStructuredError(
				"DEPENDENCY_DISABLED",
				fmt.Sprintf("Dependency '%s' is disabled for feature '%s'", dependency, featureName),
				ErrorCategoryConfiguration,
				ErrorSeverityMedium,
			)
		}
	}

	return nil
}

// DegradeToLevel degrades service to a specific level
func (dm *ServiceDegradationManager) DegradeToLevel(level DegradationLevel, reason string) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	if level == dm.currentLevel {
		return nil // Already at this level
	}

	previousLevel := dm.currentLevel
	dm.currentLevel = level

	if dm.degradationStartTime == nil {
		now := time.Now()
		dm.degradationStartTime = &now
	}

	dm.degradationEvents++

	dm.logger.Warn("Service degraded",
		zap.String("from_level", string(previousLevel)),
		zap.String("to_level", string(level)),
		zap.String("reason", reason))

	// Apply degradation rules
	return dm.applyDegradationLevel(level)
}

// applyDegradationLevel applies the appropriate feature settings for a degradation level
func (dm *ServiceDegradationManager) applyDegradationLevel(level DegradationLevel) error {
	switch level {
	case DegradationLevelNone:
		// Enable all features that aren't explicitly disabled
		return dm.enableAllFeatures()
	case DegradationLevelMinor:
		return dm.applyMinorDegradation()
	case DegradationLevelModerate:
		return dm.applyModerateDegradation()
	case DegradationLevelSevere:
		return dm.applySevereDegradation()
	case DegradationLevelCritical:
		return dm.applyCriticalDegradation()
	default:
		return fmt.Errorf("unknown degradation level: %s", level)
	}
}

// applyMinorDegradation disables non-critical features
func (dm *ServiceDegradationManager) applyMinorDegradation() error {
	featuresToDisable := []string{"detailed_logging", "metrics_collection"}

	for _, featureName := range featuresToDisable {
		if feature, exists := dm.features[featureName]; exists && !feature.Critical {
			feature.Enabled = false
		}
	}

	return nil
}

// applyModerateDegradation disables several non-essential features
func (dm *ServiceDegradationManager) applyModerateDegradation() error {
	featuresToDisable := []string{"detailed_logging", "metrics_collection", "websocket_updates"}

	for _, featureName := range featuresToDisable {
		if feature, exists := dm.features[featureName]; exists && !feature.Required {
			feature.Enabled = false
		}
	}

	return nil
}

// applySevereDegradation keeps only critical features
func (dm *ServiceDegradationManager) applySevereDegradation() error {
	for _, feature := range dm.features {
		if !feature.Critical && !feature.Required {
			feature.Enabled = false
		}
	}

	return nil
}

// applyCriticalDegradation keeps only absolutely essential features
func (dm *ServiceDegradationManager) applyCriticalDegradation() error {
	for _, feature := range dm.features {
		if !feature.Critical {
			feature.Enabled = false
		}
	}

	return nil
}

// enableAllFeatures attempts to enable all features (respecting dependencies)
func (dm *ServiceDegradationManager) enableAllFeatures() error {
	for featureName := range dm.features {
		if err := dm.checkFeatureDependencies(featureName); err == nil {
			dm.features[featureName].Enabled = true
		}
	}
	return nil
}

// evaluateDegradationLevel evaluates and updates the current degradation level
func (dm *ServiceDegradationManager) evaluateDegradationLevel() {
	disabledCritical := 0
	disabledRequired := 0
	totalFeatures := len(dm.features)
	disabledTotal := 0

	for _, feature := range dm.features {
		if !feature.Enabled {
			disabledTotal++
			if feature.Critical {
				disabledCritical++
			}
			if feature.Required {
				disabledRequired++
			}
		}
	}

	var newLevel DegradationLevel

	if disabledCritical > 0 {
		newLevel = DegradationLevelCritical
	} else if disabledRequired > 0 {
		newLevel = DegradationLevelSevere
	} else if disabledTotal > totalFeatures/2 {
		newLevel = DegradationLevelModerate
	} else if disabledTotal > 0 {
		newLevel = DegradationLevelMinor
	} else {
		newLevel = DegradationLevelNone
	}

	if newLevel != dm.currentLevel {
		previousLevel := dm.currentLevel
		dm.currentLevel = newLevel

		if newLevel == DegradationLevelNone && dm.degradationStartTime != nil {
			dm.degradationStartTime = nil
			dm.recoveryEvents++
		}

		dm.logger.Info("Degradation level changed",
			zap.String("from", string(previousLevel)),
			zap.String("to", string(newLevel)))
	}
}

// Recover attempts to recover from degradation
func (dm *ServiceDegradationManager) Recover() error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	if dm.currentLevel == DegradationLevelNone {
		return nil // Already recovered
	}

	dm.logger.Info("Attempting service recovery",
		zap.String("current_level", string(dm.currentLevel)))

	// Attempt to enable features gradually
	err := dm.enableAllFeatures()
	if err != nil {
		return err
	}

	// Re-evaluate degradation level
	dm.evaluateDegradationLevel()

	if dm.currentLevel == DegradationLevelNone {
		dm.logger.Info("Service recovery successful")
	} else {
		dm.logger.Warn("Partial service recovery",
			zap.String("current_level", string(dm.currentLevel)))
	}

	return nil
}

// GetCurrentLevel returns the current degradation level
func (dm *ServiceDegradationManager) GetCurrentLevel() DegradationLevel {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()
	return dm.currentLevel
}

// GetFeatureStatus returns the status of all features
func (dm *ServiceDegradationManager) GetFeatureStatus() map[string]*FeatureFlag {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	status := make(map[string]*FeatureFlag)
	for name, feature := range dm.features {
		status[name] = &FeatureFlag{
			Name:         feature.Name,
			Enabled:      feature.Enabled,
			Required:     feature.Required,
			Critical:     feature.Critical,
			DependsOn:    feature.DependsOn,
			MaxLevel:     feature.MaxLevel,
			LastCheck:    feature.LastCheck,
			HealthStatus: feature.HealthStatus,
		}
	}

	return status
}

// GetStatus returns comprehensive degradation manager status
func (dm *ServiceDegradationManager) GetStatus() map[string]interface{} {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	var degradationDuration *time.Duration
	if dm.degradationStartTime != nil {
		duration := time.Since(*dm.degradationStartTime)
		degradationDuration = &duration
	}

	return map[string]interface{}{
		"current_level":        string(dm.currentLevel),
		"degradation_start_time": dm.degradationStartTime,
		"degradation_duration": degradationDuration,
		"degradation_events":   dm.degradationEvents,
		"recovery_events":      dm.recoveryEvents,
		"feature_toggles":      dm.featureToggles,
		"features":             dm.GetFeatureStatus(),
		"error_rate":           dm.errorRate,
		"last_health_check":    dm.lastHealthCheck,
	}
}

// HealthCheck returns health status of the degradation manager
func (dm *ServiceDegradationManager) HealthCheck() map[string]interface{} {
	status := dm.GetStatus()

	healthStatus := "healthy"
	if dm.currentLevel != DegradationLevelNone {
		switch dm.currentLevel {
		case DegradationLevelMinor:
			healthStatus = "degraded"
		case DegradationLevelModerate:
			healthStatus = "degraded"
		case DegradationLevelSevere:
			healthStatus = "unhealthy"
		case DegradationLevelCritical:
			healthStatus = "critical"
		}
	}

	return map[string]interface{}{
		"status":           healthStatus,
		"degradation_level": string(dm.currentLevel),
		"features_status":   status,
	}
}