package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/codeready/go-tarsy-bot/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB wraps gorm.DB with additional functionality
type DB struct {
	*gorm.DB
}

// Config holds database configuration
type Config struct {
	Driver          string
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	LogLevel        logger.LogLevel
}

// NewConnection creates a new database connection
func NewConnection(config *Config) (*DB, error) {
	var gormConfig = &gorm.Config{
		Logger: logger.Default.LogMode(config.LogLevel),
	}

	var db *gorm.DB
	var err error

	switch config.Driver {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(config.DSN), gormConfig)
	case "postgres", "postgresql":
		db, err = gorm.Open(postgres.Open(config.DSN), gormConfig)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", config.Driver)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(config.MaxOpenConns)
	sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(config.ConnMaxLifetime)

	return &DB{DB: db}, nil
}

// NewConnectionFromEnv creates a database connection from environment variables
func NewConnectionFromEnv() (*DB, error) {
	config := &Config{
		Driver:          getEnvDefault("DB_DRIVER", "sqlite"),
		DSN:             getEnvDefault("DATABASE_URL", getDefaultDSN()),
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		LogLevel:        getLogLevel(),
	}

	return NewConnection(config)
}

// getDefaultDSN returns the default DSN based on environment
func getDefaultDSN() string {
	if os.Getenv("TESTING") == "true" {
		return ":memory:"
	}
	return "history.db"
}

// getLogLevel returns the log level based on environment
func getLogLevel() logger.LogLevel {
	switch os.Getenv("DB_LOG_LEVEL") {
	case "silent":
		return logger.Silent
	case "error":
		return logger.Error
	case "warn":
		return logger.Warn
	case "info":
		return logger.Info
	default:
		if os.Getenv("GO_ENV") == "development" {
			return logger.Info
		}
		return logger.Error
	}
}

// getEnvDefault returns environment variable value or default
func getEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Migrate runs database migrations
func (db *DB) Migrate() error {
	log.Println("Running database migrations...")

	// Fix AlertSession table schema manually first
	if err := db.fixAlertSessionSchema(); err != nil {
		return fmt.Errorf("failed to fix alert session schema: %w", err)
	}

	// Migrate models except AlertSession (handled manually above)
	err := db.AutoMigrate(
		&models.StageExecution{},
		&models.TimelineInteraction{},
	)

	if err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Create indexes for performance
	if err := db.createIndexes(); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// fixAlertSessionSchema manually fixes the AlertSession table schema
func (db *DB) fixAlertSessionSchema() error {
	// Always drop table if it exists to ensure correct schema
	log.Println("Dropping alert_sessions table if exists to fix schema...")
	if err := db.Exec("DROP TABLE IF EXISTS alert_sessions").Error; err != nil {
		return err
	}

	// Create table with correct schema manually - forcing TEXT type for session_id
	createTableSQL := `
		CREATE TABLE alert_sessions (
			session_id TEXT PRIMARY KEY,
			alert_id VARCHAR(255) NOT NULL UNIQUE,
			alert_data JSON DEFAULT '{}',
			agent_type VARCHAR(255) NOT NULL,
			alert_type VARCHAR(255),
			status VARCHAR(50) NOT NULL,
			started_at_us INTEGER NOT NULL,
			completed_at_us INTEGER,
			error_message TEXT,
			final_analysis TEXT,
			session_metadata TEXT,
			chain_id VARCHAR(255) NOT NULL,
			chain_definition TEXT,
			current_stage_index INTEGER,
			current_stage_id VARCHAR(255),
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME
		)
	`

	log.Println("Creating alert_sessions table with TEXT primary key...")
	if err := db.Exec(createTableSQL).Error; err != nil {
		return err
	}

	// Verify the schema was created correctly
	var schemaCheck string
	err := db.Raw("SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_sessions'").Scan(&schemaCheck).Error
	if err != nil {
		return err
	}
	log.Printf("Alert sessions table schema: %s", schemaCheck)

	return nil
}

// createIndexes creates additional indexes for better performance
func (db *DB) createIndexes() error {
	// Timeline interactions indexes for efficient queries
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_timeline_session_timestamp ON timeline_interactions(session_id, timestamp_us)",
		"CREATE INDEX IF NOT EXISTS idx_timeline_type_timestamp ON timeline_interactions(type, timestamp_us)",
		"CREATE INDEX IF NOT EXISTS idx_timeline_stage_execution ON timeline_interactions(stage_execution_id)",
		"CREATE INDEX IF NOT EXISTS idx_timeline_status ON timeline_interactions(status)",

		// Alert sessions enhanced indexes
		"CREATE INDEX IF NOT EXISTS idx_alert_sessions_timestamp ON alert_sessions(started_at_us DESC)",
		"CREATE INDEX IF NOT EXISTS idx_alert_sessions_agent_status ON alert_sessions(agent_type, status)",

		// Stage executions indexes
		"CREATE INDEX IF NOT EXISTS idx_stage_executions_session_index ON stage_executions(session_id, stage_index)",
		"CREATE INDEX IF NOT EXISTS idx_stage_executions_status_time ON stage_executions(status, started_at_us)",
	}

	for _, indexSQL := range indexes {
		if err := db.Exec(indexSQL).Error; err != nil {
			log.Printf("Warning: Failed to create index: %s - %v", indexSQL, err)
			// Continue with other indexes even if one fails
		}
	}

	return nil
}

// TestConnection tests the database connection
func (db *DB) TestConnection() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	
	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}
	
	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	
	return sqlDB.Close()
}

// GetDatabaseInfo returns database information for health checks
func (db *DB) GetDatabaseInfo() map[string]interface{} {
	info := map[string]interface{}{
		"enabled": true,
	}
	
	// Test connection
	if err := db.TestConnection(); err != nil {
		info["connection_test"] = false
		info["error"] = err.Error()
	} else {
		info["connection_test"] = true
	}
	
	// Get database name from DSN or config
	// This would depend on how you store/parse the DSN
	info["database_name"] = "tarsy_db"
	
	// Get retention configuration (this would come from your settings)
	info["retention_days"] = 90
	
	return info
}

// IsHealthy performs a health check on the database
func (db *DB) IsHealthy() bool {
	return db.TestConnection() == nil
}

// CleanupOrphanedSessions marks orphaned sessions as failed
func (db *DB) CleanupOrphanedSessions() (int64, error) {
	// Find sessions that are still in progress but likely orphaned
	// (e.g., started more than 1 hour ago and still pending/in_progress)
	cutoffTime := time.Now().Add(-1 * time.Hour).UnixMicro()
	
	result := db.Model(&models.AlertSession{}).
		Where("status IN (?, ?) AND started_at_us < ?", 
			models.AlertSessionStatusPending, 
			models.AlertSessionStatusInProgress, 
			cutoffTime).
		Updates(map[string]interface{}{
			"status":        models.AlertSessionStatusFailed,
			"error_message": "Session orphaned - backend restarted",
			"completed_at_us": time.Now().UnixMicro(),
		})
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to cleanup orphaned sessions: %w", result.Error)
	}
	
	return result.RowsAffected, nil
}

// GetAlertSessionByID retrieves an alert session by ID
func (db *DB) GetAlertSessionByID(sessionID string) (*models.AlertSession, error) {
	var session models.AlertSession
	
	err := db.Preload("StageExecutions").First(&session, "session_id = ?", sessionID).Error
	if err != nil {
		return nil, err
	}
	
	return &session, nil
}

// GetAlertSessionByAlertID retrieves an alert session by alert ID
func (db *DB) GetAlertSessionByAlertID(alertID string) (*models.AlertSession, error) {
	var session models.AlertSession
	
	err := db.Preload("StageExecutions").First(&session, "alert_id = ?", alertID).Error
	if err != nil {
		return nil, err
	}
	
	return &session, nil
}

// CreateAlertSession creates a new alert session
func (db *DB) CreateAlertSession(session *models.AlertSession) error {
	return db.Create(session).Error
}

// UpdateAlertSession updates an existing alert session
func (db *DB) UpdateAlertSession(session *models.AlertSession) error {
	return db.Save(session).Error
}

// CreateStageExecution creates a new stage execution
func (db *DB) CreateStageExecution(execution *models.StageExecution) error {
	return db.Create(execution).Error
}

// UpdateStageExecution updates an existing stage execution
func (db *DB) UpdateStageExecution(execution *models.StageExecution) error {
	return db.Save(execution).Error
}

// Timeline Interaction Methods

// CreateTimelineInteraction creates a new timeline interaction
func (db *DB) CreateTimelineInteraction(interaction *models.TimelineInteraction) error {
	return db.Create(interaction).Error
}

// CreateTimelineInteractionsBatch creates multiple timeline interactions in a batch
func (db *DB) CreateTimelineInteractionsBatch(interactions []*models.TimelineInteraction) error {
	if len(interactions) == 0 {
		return nil
	}
	return db.CreateInBatches(interactions, 100).Error
}

// GetTimelineInteractions retrieves timeline interactions for a session
func (db *DB) GetTimelineInteractions(sessionID string, limit, offset int) ([]*models.TimelineInteraction, error) {
	var interactions []*models.TimelineInteraction

	query := db.Where("session_id = ?", sessionID).
		Order("timestamp_us ASC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Find(&interactions).Error
	return interactions, err
}

// GetTimelineInteractionsByType retrieves timeline interactions by type
func (db *DB) GetTimelineInteractionsByType(sessionID, interactionType string) ([]*models.TimelineInteraction, error) {
	var interactions []*models.TimelineInteraction

	err := db.Where("session_id = ? AND type = ?", sessionID, interactionType).
		Order("timestamp_us ASC").
		Find(&interactions).Error

	return interactions, err
}

// GetTimelineInteractionCount returns the count of timeline interactions for a session
func (db *DB) GetTimelineInteractionCount(sessionID string) (int64, error) {
	var count int64
	err := db.Model(&models.TimelineInteraction{}).
		Where("session_id = ?", sessionID).
		Count(&count).Error
	return count, err
}

// History and Summary Methods

// GetActiveSessions retrieves all active (pending/in_progress) sessions
func (db *DB) GetActiveSessions() ([]*models.AlertSession, error) {
	var sessions []*models.AlertSession

	err := db.Where("status IN (?)", []models.AlertSessionStatus{
		models.AlertSessionStatusPending,
		models.AlertSessionStatusInProgress,
	}).Order("started_at_us DESC").Find(&sessions).Error

	return sessions, err
}

// GetSessions retrieves sessions with pagination and filtering
func (db *DB) GetSessions(limit, offset int, statuses []models.AlertSessionStatus) ([]*models.AlertSession, error) {
	var sessions []*models.AlertSession

	query := db.Preload("StageExecutions")

	if len(statuses) > 0 {
		query = query.Where("status IN (?)", statuses)
	}

	err := query.Order("started_at_us DESC").
		Limit(limit).
		Offset(offset).
		Find(&sessions).Error

	return sessions, err
}

// GetSessionSummary generates summary statistics for a session
func (db *DB) GetSessionSummary(sessionID string) (*models.SessionSummary, error) {
	// Get the basic session information
	var session models.AlertSession
	err := db.First(&session, "session_id = ?", sessionID).Error
	if err != nil {
		return nil, err
	}

	var alertType string
	if session.AlertType != nil {
		alertType = *session.AlertType
	}

	summary := &models.SessionSummary{
		SessionID:         session.SessionID,
		AlertType:         alertType,
		AgentType:         session.AgentType,
		Status:            string(session.Status),
		StartedAtUs:       session.StartedAtUs,
		CompletedAtUs:     session.CompletedAtUs,
		HasFinalAnalysis:  session.FinalAnalysis != nil,
		ErrorMessage:      session.ErrorMessage,
	}

	// Calculate duration if completed
	if session.CompletedAtUs != nil {
		durationMs := models.CalculateDurationMs(session.StartedAtUs, *session.CompletedAtUs)
		summary.DurationMs = &durationMs
	}

	// Set final analysis length
	if session.FinalAnalysis != nil {
		length := len(*session.FinalAnalysis)
		summary.FinalAnalysisLength = &length
	}

	// Get timeline interaction counts
	var counts struct {
		Total      int64 `gorm:"column:total"`
		LLM        int64 `gorm:"column:llm"`
		MCP        int64 `gorm:"column:mcp"`
		Failed     int64 `gorm:"column:failed"`
		InputTokens  sql.NullInt64 `gorm:"column:input_tokens"`
		OutputTokens sql.NullInt64 `gorm:"column:output_tokens"`
		TotalTokens  sql.NullInt64 `gorm:"column:total_tokens"`
	}

	err = db.Model(&models.TimelineInteraction{}).
		Select(`
			COUNT(*) as total,
			COUNT(CASE WHEN type LIKE 'llm_%' THEN 1 END) as llm,
			COUNT(CASE WHEN type LIKE 'mcp_%' OR type LIKE 'tool_%' THEN 1 END) as mcp,
			COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
			SUM(input_tokens) as input_tokens,
			SUM(output_tokens) as output_tokens,
			SUM(total_tokens) as total_tokens
		`).
		Where("session_id = ?", sessionID).
		Scan(&counts).Error

	if err != nil {
		return nil, err
	}

	summary.TotalInteractions = int(counts.Total)
	summary.LLMInteractions = int(counts.LLM)
	summary.MCPCommunications = int(counts.MCP)
	summary.FailedInteractions = int(counts.Failed)

	// Set token usage
	if counts.InputTokens.Valid {
		inputTokens := int(counts.InputTokens.Int64)
		summary.SessionInputTokens = &inputTokens
	}
	if counts.OutputTokens.Valid {
		outputTokens := int(counts.OutputTokens.Int64)
		summary.SessionOutputTokens = &outputTokens
	}
	if counts.TotalTokens.Valid {
		totalTokens := int(counts.TotalTokens.Int64)
		summary.SessionTotalTokens = &totalTokens
	}

	// Get chain statistics if this is a chain session
	if session.ChainID != "" {
		chainStats, err := db.getChainStatistics(sessionID, session.ChainID)
		if err == nil {
			summary.ChainStatistics = chainStats
		}
	}

	return summary, nil
}

// getChainStatistics helper method for chain-specific statistics
func (db *DB) getChainStatistics(sessionID, chainID string) (*models.ChainStatistics, error) {
	var stats struct {
		Total     int64  `gorm:"column:total"`
		Completed int64  `gorm:"column:completed"`
		Failed    int64  `gorm:"column:failed"`
		Active    int64  `gorm:"column:active"`
		CurrentIndex sql.NullInt64 `gorm:"column:current_index"`
		CurrentName  sql.NullString `gorm:"column:current_name"`
	}

	err := db.Model(&models.StageExecution{}).
		Select(`
			COUNT(*) as total,
			COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
			COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
			COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
			MAX(CASE WHEN status = 'active' THEN stage_index END) as current_index,
			MAX(CASE WHEN status = 'active' THEN stage_name END) as current_name
		`).
		Where("session_id = ?", sessionID).
		Scan(&stats).Error

	if err != nil {
		return nil, err
	}

	chainStats := &models.ChainStatistics{
		ChainID:         chainID,
		TotalStages:     int(stats.Total),
		CompletedStages: int(stats.Completed),
		FailedStages:    int(stats.Failed),
		ActiveStages:    int(stats.Active),
	}

	if stats.CurrentIndex.Valid {
		currentIndex := int(stats.CurrentIndex.Int64)
		chainStats.CurrentStageIndex = &currentIndex
	}

	if stats.CurrentName.Valid {
		chainStats.CurrentStageName = &stats.CurrentName.String
	}

	return chainStats, nil
}

// GetSessionCount returns total session count with optional status filter
func (db *DB) GetSessionCount(statuses []models.AlertSessionStatus) (int64, error) {
	var count int64
	query := db.Model(&models.AlertSession{})

	if len(statuses) > 0 {
		query = query.Where("status IN (?)", statuses)
	}

	err := query.Count(&count).Error
	return count, err
}

// CleanupOldSessions removes sessions older than the specified number of days
func (db *DB) CleanupOldSessions(retentionDays int) (int64, error) {
	cutoffTime := time.Now().AddDate(0, 0, -retentionDays).UnixMicro()

	// Delete timeline interactions first (foreign key constraint)
	timelineResult := db.Where("timestamp_us < ?", cutoffTime).Delete(&models.TimelineInteraction{})
	if timelineResult.Error != nil {
		return 0, fmt.Errorf("failed to cleanup old timeline interactions: %w", timelineResult.Error)
	}

	// Delete stage executions
	stageResult := db.Where("session_id IN (SELECT session_id FROM alert_sessions WHERE started_at_us < ?)", cutoffTime).Delete(&models.StageExecution{})
	if stageResult.Error != nil {
		return 0, fmt.Errorf("failed to cleanup old stage executions: %w", stageResult.Error)
	}

	// Delete sessions
	sessionResult := db.Where("started_at_us < ?", cutoffTime).Delete(&models.AlertSession{})
	if sessionResult.Error != nil {
		return 0, fmt.Errorf("failed to cleanup old sessions: %w", sessionResult.Error)
	}

	totalDeleted := timelineResult.RowsAffected + stageResult.RowsAffected + sessionResult.RowsAffected
	return totalDeleted, nil
}