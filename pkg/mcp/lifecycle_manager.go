package mcp

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// LifecycleManager manages the lifecycle of MCP server processes
type LifecycleManager struct {
	config     *ServerRegistryConfig
	logger     *zap.Logger
	processes  map[string]*ProcessInfo
	mutex      sync.RWMutex
}

// ProcessInfo contains information about a managed process
type ProcessInfo struct {
	Cmd         *exec.Cmd     `json:"-"`
	PID         int           `json:"pid"`
	StartTime   time.Time     `json:"start_time"`
	Status      ProcessStatus `json:"status"`
	ExitCode    int           `json:"exit_code,omitempty"`
	LastError   string        `json:"last_error,omitempty"`
	mutex       sync.RWMutex
}

// ProcessStatus represents the status of a managed process
type ProcessStatus string

const (
	ProcessStatusStarting   ProcessStatus = "starting"
	ProcessStatusRunning    ProcessStatus = "running"
	ProcessStatusTerminating ProcessStatus = "terminating"
	ProcessStatusStopped    ProcessStatus = "stopped"
	ProcessStatusFailed     ProcessStatus = "failed"
)

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(logger *zap.Logger, config *ServerRegistryConfig) *LifecycleManager {
	return &LifecycleManager{
		config:    config,
		logger:    logger,
		processes: make(map[string]*ProcessInfo),
	}
}

// StartProcess starts a new process for the given server configuration
func (lm *LifecycleManager) StartProcess(ctx context.Context, serverName string, config *ServerConfig) (*ProcessInfo, error) {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()

	// Check if process already exists
	if existing, exists := lm.processes[serverName]; exists {
		existing.mutex.RLock()
		status := existing.Status
		existing.mutex.RUnlock()

		if status == ProcessStatusRunning {
			return nil, fmt.Errorf("process for server %s is already running", serverName)
		}
	}

	lm.logger.Info("Starting process for MCP server",
		zap.String("server", serverName),
		zap.String("command", config.Command),
		zap.Strings("args", config.Args),
	)

	// Create the command
	args := append([]string{}, config.Args...)
	cmd := exec.CommandContext(ctx, config.Command, args...)

	// Set environment variables
	if config.Env != nil {
		for key, value := range config.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
		}
	}

	// Set working directory
	if config.WorkingDir != "" {
		cmd.Dir = config.WorkingDir
	}

	// Create process info
	processInfo := &ProcessInfo{
		Cmd:       cmd,
		StartTime: time.Now(),
		Status:    ProcessStatusStarting,
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		processInfo.Status = ProcessStatusFailed
		processInfo.LastError = err.Error()
		return nil, fmt.Errorf("failed to start process: %w", err)
	}

	processInfo.PID = cmd.Process.Pid
	processInfo.Status = ProcessStatusRunning
	lm.processes[serverName] = processInfo

	lm.logger.Info("Process started successfully",
		zap.String("server", serverName),
		zap.Int("pid", processInfo.PID),
	)

	// Monitor the process in a goroutine
	go lm.monitorProcess(serverName, processInfo)

	return processInfo, nil
}

// StopProcess stops a running process
func (lm *LifecycleManager) StopProcess(serverName string) error {
	lm.mutex.RLock()
	processInfo, exists := lm.processes[serverName]
	lm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("no process found for server %s", serverName)
	}

	processInfo.mutex.Lock()
	defer processInfo.mutex.Unlock()

	if processInfo.Status != ProcessStatusRunning {
		return nil // Already stopped or stopping
	}

	lm.logger.Info("Stopping process for MCP server",
		zap.String("server", serverName),
		zap.Int("pid", processInfo.PID),
	)

	processInfo.Status = ProcessStatusTerminating

	// Try graceful termination first
	if err := processInfo.Cmd.Process.Signal(syscall.SIGTERM); err != nil {
		lm.logger.Warn("Failed to send SIGTERM, trying SIGKILL",
			zap.String("server", serverName),
			zap.Error(err),
		)

		// Force kill if graceful termination fails
		if err := processInfo.Cmd.Process.Kill(); err != nil {
			processInfo.LastError = err.Error()
			return fmt.Errorf("failed to kill process: %w", err)
		}
	}

	// Wait for process to exit with timeout
	done := make(chan error, 1)
	go func() {
		_, err := processInfo.Cmd.Process.Wait()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			processInfo.LastError = err.Error()
			lm.logger.Warn("Process exited with error",
				zap.String("server", serverName),
				zap.Error(err),
			)
		} else {
			lm.logger.Info("Process stopped gracefully",
				zap.String("server", serverName),
			)
		}
		processInfo.Status = ProcessStatusStopped

	case <-time.After(lm.config.TerminationTimeout):
		// Force kill if timeout exceeded
		lm.logger.Warn("Process termination timeout, force killing",
			zap.String("server", serverName),
		)

		if err := processInfo.Cmd.Process.Kill(); err != nil {
			processInfo.LastError = err.Error()
			return fmt.Errorf("failed to force kill process: %w", err)
		}
		processInfo.Status = ProcessStatusStopped
	}

	return nil
}

// GetProcessInfo returns process information for a server
func (lm *LifecycleManager) GetProcessInfo(serverName string) (*ProcessInfo, error) {
	lm.mutex.RLock()
	defer lm.mutex.RUnlock()

	processInfo, exists := lm.processes[serverName]
	if !exists {
		return nil, fmt.Errorf("no process found for server %s", serverName)
	}

	processInfo.mutex.RLock()
	defer processInfo.mutex.RUnlock()

	// Return a copy to avoid race conditions
	return &ProcessInfo{
		PID:       processInfo.PID,
		StartTime: processInfo.StartTime,
		Status:    processInfo.Status,
		ExitCode:  processInfo.ExitCode,
		LastError: processInfo.LastError,
	}, nil
}

// IsProcessRunning checks if a process is currently running
func (lm *LifecycleManager) IsProcessRunning(serverName string) bool {
	processInfo, err := lm.GetProcessInfo(serverName)
	if err != nil {
		return false
	}

	return processInfo.Status == ProcessStatusRunning
}

// ListProcesses returns information about all managed processes
func (lm *LifecycleManager) ListProcesses() map[string]*ProcessInfo {
	lm.mutex.RLock()
	defer lm.mutex.RUnlock()

	result := make(map[string]*ProcessInfo)
	for name, processInfo := range lm.processes {
		processInfo.mutex.RLock()
		result[name] = &ProcessInfo{
			PID:       processInfo.PID,
			StartTime: processInfo.StartTime,
			Status:    processInfo.Status,
			ExitCode:  processInfo.ExitCode,
			LastError: processInfo.LastError,
		}
		processInfo.mutex.RUnlock()
	}

	return result
}

// monitorProcess monitors a process and handles its lifecycle
func (lm *LifecycleManager) monitorProcess(serverName string, processInfo *ProcessInfo) {
	// Wait for the process to exit
	state, err := processInfo.Cmd.Process.Wait()

	processInfo.mutex.Lock()
	defer processInfo.mutex.Unlock()

	if err != nil {
		processInfo.Status = ProcessStatusFailed
		processInfo.LastError = err.Error()
		lm.logger.Error("Process failed",
			zap.String("server", serverName),
			zap.Int("pid", processInfo.PID),
			zap.Error(err),
		)
	} else {
		processInfo.Status = ProcessStatusStopped
		if state.Exited() {
			processInfo.ExitCode = state.ExitCode()
		}

		if state.Success() {
			lm.logger.Info("Process exited successfully",
				zap.String("server", serverName),
				zap.Int("pid", processInfo.PID),
				zap.Int("exit_code", processInfo.ExitCode),
			)
		} else {
			lm.logger.Warn("Process exited with non-zero code",
				zap.String("server", serverName),
				zap.Int("pid", processInfo.PID),
				zap.Int("exit_code", processInfo.ExitCode),
			)
		}
	}

	// Log process lifetime
	lifetime := time.Since(processInfo.StartTime)
	lm.logger.Info("Process monitoring ended",
		zap.String("server", serverName),
		zap.Duration("lifetime", lifetime),
	)
}

// CleanupProcess removes process information for a stopped process
func (lm *LifecycleManager) CleanupProcess(serverName string) error {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()

	processInfo, exists := lm.processes[serverName]
	if !exists {
		return nil // Already cleaned up
	}

	processInfo.mutex.RLock()
	status := processInfo.Status
	processInfo.mutex.RUnlock()

	if status == ProcessStatusRunning {
		return fmt.Errorf("cannot cleanup running process for server %s", serverName)
	}

	delete(lm.processes, serverName)
	lm.logger.Debug("Cleaned up process information",
		zap.String("server", serverName),
	)

	return nil
}

// StopAllProcesses stops all managed processes
func (lm *LifecycleManager) StopAllProcesses() error {
	lm.mutex.RLock()
	serverNames := make([]string, 0, len(lm.processes))
	for name := range lm.processes {
		serverNames = append(serverNames, name)
	}
	lm.mutex.RUnlock()

	var lastError error
	for _, serverName := range serverNames {
		if err := lm.StopProcess(serverName); err != nil {
			lm.logger.Error("Error stopping process during shutdown",
				zap.String("server", serverName),
				zap.Error(err),
			)
			lastError = err
		}
	}

	return lastError
}

// GetProcessCount returns the number of managed processes
func (lm *LifecycleManager) GetProcessCount() int {
	lm.mutex.RLock()
	defer lm.mutex.RUnlock()
	return len(lm.processes)
}

// GetRunningProcessCount returns the number of running processes
func (lm *LifecycleManager) GetRunningProcessCount() int {
	lm.mutex.RLock()
	defer lm.mutex.RUnlock()

	count := 0
	for _, processInfo := range lm.processes {
		processInfo.mutex.RLock()
		if processInfo.Status == ProcessStatusRunning {
			count++
		}
		processInfo.mutex.RUnlock()
	}

	return count
}

// RestartProcess restarts a process
func (lm *LifecycleManager) RestartProcess(ctx context.Context, serverName string, config *ServerConfig) (*ProcessInfo, error) {
	// Stop existing process if it exists
	if lm.IsProcessRunning(serverName) {
		if err := lm.StopProcess(serverName); err != nil {
			return nil, fmt.Errorf("failed to stop existing process: %w", err)
		}
	}

	// Clean up old process info
	lm.CleanupProcess(serverName)

	// Wait for restart delay
	time.Sleep(lm.config.RestartDelay)

	// Start new process
	return lm.StartProcess(ctx, serverName, config)
}

// WaitForProcessExit waits for a process to exit or timeout
func (lm *LifecycleManager) WaitForProcessExit(serverName string, timeout time.Duration) error {
	processInfo, err := lm.GetProcessInfo(serverName)
	if err != nil {
		return err
	}

	if processInfo.Status != ProcessStatusRunning {
		return nil // Already stopped
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		for {
			time.Sleep(100 * time.Millisecond)
			info, err := lm.GetProcessInfo(serverName)
			if err != nil || info.Status != ProcessStatusRunning {
				close(done)
				return
			}
		}
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for process %s to exit", serverName)
	}
}