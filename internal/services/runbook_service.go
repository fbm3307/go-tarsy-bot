package services

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RunbookService handles downloading and caching of runbook content
// Equivalent to Python's RunbookService with HTTP client management
type RunbookService struct {
	client *http.Client
	logger *zap.Logger
	cache  map[string]*CachedRunbook
	mutex  sync.RWMutex
	maxCacheSize int
	cacheTTL     time.Duration
}

// CachedRunbook represents a cached runbook with metadata
type CachedRunbook struct {
	Content     string    `json:"content"`
	URL         string    `json:"url"`
	CachedAt    time.Time `json:"cached_at"`
	LastAccessed time.Time `json:"last_accessed"`
	Size        int       `json:"size"`
}

// RunbookServiceConfig contains configuration for the runbook service
type RunbookServiceConfig struct {
	Timeout      time.Duration `json:"timeout"`
	MaxCacheSize int           `json:"max_cache_size"`
	CacheTTL     time.Duration `json:"cache_ttl"`
	MaxSize      int64         `json:"max_size"`
	AllowedSchemes []string    `json:"allowed_schemes"`
}

// NewRunbookService creates a new runbook service
func NewRunbookService(client *http.Client, logger *zap.Logger) *RunbookService {
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return &RunbookService{
		client:       client,
		logger:       logger,
		cache:        make(map[string]*CachedRunbook),
		maxCacheSize: 100,
		cacheTTL:     1 * time.Hour,
	}
}

// NewRunbookServiceWithConfig creates a runbook service with custom configuration
func NewRunbookServiceWithConfig(config *RunbookServiceConfig, logger *zap.Logger) *RunbookService {
	client := &http.Client{
		Timeout: config.Timeout,
	}

	return &RunbookService{
		client:       client,
		logger:       logger,
		cache:        make(map[string]*CachedRunbook),
		maxCacheSize: config.MaxCacheSize,
		cacheTTL:     config.CacheTTL,
	}
}

// DownloadRunbook downloads runbook content from a URL with caching
func (rs *RunbookService) DownloadRunbook(ctx context.Context, runbookURL string) (string, error) {
	rs.logger.Debug("Downloading runbook", zap.String("url", runbookURL))

	// Validate URL
	if err := rs.validateURL(runbookURL); err != nil {
		return "", fmt.Errorf("invalid runbook URL: %w", err)
	}

	// Check cache first
	if cached := rs.getCachedRunbook(runbookURL); cached != nil {
		rs.logger.Debug("Using cached runbook", zap.String("url", runbookURL))
		return cached.Content, nil
	}

	// Download from URL
	content, err := rs.downloadFromURL(ctx, runbookURL)
	if err != nil {
		return "", fmt.Errorf("failed to download runbook: %w", err)
	}

	// Cache the content
	rs.cacheRunbook(runbookURL, content)

	rs.logger.Info("Downloaded runbook",
		zap.String("url", runbookURL),
		zap.Int("size", len(content)),
	)

	return content, nil
}

// downloadFromURL performs the actual HTTP download
func (rs *RunbookService) downloadFromURL(ctx context.Context, runbookURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", runbookURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set reasonable headers
	req.Header.Set("User-Agent", "TARSy-Bot/1.0")
	req.Header.Set("Accept", "text/plain, text/markdown, text/html, */*")

	resp, err := rs.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	// Check content length
	if resp.ContentLength > 0 && resp.ContentLength > 1024*1024 { // 1MB limit
		return "", fmt.Errorf("runbook too large: %d bytes", resp.ContentLength)
	}

	// Read response body with size limit
	limitedReader := io.LimitReader(resp.Body, 1024*1024) // 1MB limit
	contentBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(contentBytes), nil
}

// validateURL validates the runbook URL for security
func (rs *RunbookService) validateURL(runbookURL string) error {
	if runbookURL == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	parsedURL, err := url.Parse(runbookURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Check allowed schemes
	allowedSchemes := []string{"http", "https"}
	schemeAllowed := false
	for _, scheme := range allowedSchemes {
		if parsedURL.Scheme == scheme {
			schemeAllowed = true
			break
		}
	}

	if !schemeAllowed {
		return fmt.Errorf("unsupported URL scheme: %s", parsedURL.Scheme)
	}

	// Check for suspicious patterns
	host := strings.ToLower(parsedURL.Host)
	suspiciousHosts := []string{"localhost", "127.0.0.1", "0.0.0.0", "[::]"}
	for _, suspicious := range suspiciousHosts {
		if strings.Contains(host, suspicious) {
			return fmt.Errorf("suspicious host detected: %s", host)
		}
	}

	return nil
}

// getCachedRunbook retrieves runbook from cache if available and valid
func (rs *RunbookService) getCachedRunbook(runbookURL string) *CachedRunbook {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	cached, exists := rs.cache[runbookURL]
	if !exists {
		return nil
	}

	// Check if cache entry is still valid
	if time.Since(cached.CachedAt) > rs.cacheTTL {
		// Cache entry expired, remove it
		go rs.removeCacheEntry(runbookURL)
		return nil
	}

	// Update last accessed time
	cached.LastAccessed = time.Now()
	return cached
}

// cacheRunbook stores runbook content in cache
func (rs *RunbookService) cacheRunbook(runbookURL, content string) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	// Check cache size and evict if necessary
	if len(rs.cache) >= rs.maxCacheSize {
		rs.evictOldestEntry()
	}

	rs.cache[runbookURL] = &CachedRunbook{
		Content:      content,
		URL:          runbookURL,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
		Size:         len(content),
	}
}

// removeCacheEntry removes a specific cache entry
func (rs *RunbookService) removeCacheEntry(runbookURL string) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	delete(rs.cache, runbookURL)
}

// evictOldestEntry removes the oldest cache entry
func (rs *RunbookService) evictOldestEntry() {
	if len(rs.cache) == 0 {
		return
	}

	var oldestURL string
	var oldestTime time.Time

	for url, cached := range rs.cache {
		if oldestURL == "" || cached.LastAccessed.Before(oldestTime) {
			oldestURL = url
			oldestTime = cached.LastAccessed
		}
	}

	if oldestURL != "" {
		delete(rs.cache, oldestURL)
		rs.logger.Debug("Evicted cache entry", zap.String("url", oldestURL))
	}
}

// ClearCache clears all cached runbooks
func (rs *RunbookService) ClearCache() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	rs.cache = make(map[string]*CachedRunbook)
	rs.logger.Info("Cleared runbook cache")
}

// GetCacheStats returns statistics about the cache
func (rs *RunbookService) GetCacheStats() map[string]interface{} {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	totalSize := 0
	urls := make([]string, 0, len(rs.cache))

	for url, cached := range rs.cache {
		urls = append(urls, url)
		totalSize += cached.Size
	}

	return map[string]interface{}{
		"total_entries": len(rs.cache),
		"total_size":    totalSize,
		"max_size":      rs.maxCacheSize,
		"cache_ttl":     rs.cacheTTL.String(),
		"cached_urls":   urls,
	}
}

// ValidateRunbookURL validates a runbook URL without downloading
func (rs *RunbookService) ValidateRunbookURL(runbookURL string) error {
	return rs.validateURL(runbookURL)
}

// GetRunbookMetadata returns metadata about a cached runbook
func (rs *RunbookService) GetRunbookMetadata(runbookURL string) *CachedRunbook {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	if cached, exists := rs.cache[runbookURL]; exists {
		// Return a copy to avoid concurrent access issues
		return &CachedRunbook{
			Content:      "", // Don't include content in metadata
			URL:          cached.URL,
			CachedAt:     cached.CachedAt,
			LastAccessed: cached.LastAccessed,
			Size:         cached.Size,
		}
	}

	return nil
}

// DownloadRunbookAsync downloads a runbook asynchronously and returns immediately
func (rs *RunbookService) DownloadRunbookAsync(ctx context.Context, runbookURL string, callback func(string, error)) {
	go func() {
		content, err := rs.DownloadRunbook(ctx, runbookURL)
		if callback != nil {
			callback(content, err)
		}
	}()
}

// PrewarmCache downloads and caches runbooks from a list of URLs
func (rs *RunbookService) PrewarmCache(ctx context.Context, urls []string) map[string]error {
	results := make(map[string]error)
	var mutex sync.Mutex

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent downloads

	for _, url := range urls {
		wg.Add(1)
		go func(runbookURL string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			_, err := rs.DownloadRunbook(ctx, runbookURL)

			mutex.Lock()
			results[runbookURL] = err
			mutex.Unlock()
		}(url)
	}

	wg.Wait()

	rs.logger.Info("Cache prewarming completed",
		zap.Int("total_urls", len(urls)),
		zap.Int("successful", len(urls)-countErrors(results)),
		zap.Int("failed", countErrors(results)))

	return results
}

// RefreshCache refreshes all cached runbooks
func (rs *RunbookService) RefreshCache(ctx context.Context) map[string]error {
	rs.mutex.RLock()
	urls := make([]string, 0, len(rs.cache))
	for url := range rs.cache {
		urls = append(urls, url)
	}
	rs.mutex.RUnlock()

	if len(urls) == 0 {
		return make(map[string]error)
	}

	rs.logger.Info("Refreshing cached runbooks", zap.Int("count", len(urls)))

	// Clear cache first
	rs.ClearCache()

	// Redownload all
	return rs.PrewarmCache(ctx, urls)
}

// GetExpiredEntries returns URLs of expired cache entries
func (rs *RunbookService) GetExpiredEntries() []string {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	var expired []string
	cutoff := time.Now().Add(-rs.cacheTTL)

	for url, cached := range rs.cache {
		if cached.CachedAt.Before(cutoff) {
			expired = append(expired, url)
		}
	}

	return expired
}

// CleanExpiredEntries removes all expired cache entries
func (rs *RunbookService) CleanExpiredEntries() int {
	expired := rs.GetExpiredEntries()

	rs.mutex.Lock()
	for _, url := range expired {
		delete(rs.cache, url)
	}
	rs.mutex.Unlock()

	if len(expired) > 0 {
		rs.logger.Info("Cleaned expired cache entries", zap.Int("count", len(expired)))
	}

	return len(expired)
}

// IsRunbookCached checks if a runbook is cached and valid
func (rs *RunbookService) IsRunbookCached(runbookURL string) bool {
	return rs.getCachedRunbook(runbookURL) != nil
}

// GetCachedRunbookContent returns cached content without triggering download
func (rs *RunbookService) GetCachedRunbookContent(runbookURL string) (string, bool) {
	if cached := rs.getCachedRunbook(runbookURL); cached != nil {
		return cached.Content, true
	}
	return "", false
}

// SetCacheConfig updates cache configuration
func (rs *RunbookService) SetCacheConfig(maxSize int, ttl time.Duration) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	rs.maxCacheSize = maxSize
	rs.cacheTTL = ttl

	// Evict entries if new max size is smaller
	for len(rs.cache) > maxSize {
		rs.evictOldestEntry()
	}

	rs.logger.Info("Updated cache configuration",
		zap.Int("max_size", maxSize),
		zap.Duration("ttl", ttl))
}

// HealthCheck performs a health check on the runbook service
func (rs *RunbookService) HealthCheck(ctx context.Context) map[string]string {
	health := make(map[string]string)

	// Check if we can make a simple HTTP request
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(testCtx, "GET", "https://httpbin.org/status/200", nil)
	if err == nil {
		resp, err := rs.client.Do(req)
		if err != nil {
			health["http_client"] = fmt.Sprintf("unhealthy: %v", err)
		} else {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				health["http_client"] = "healthy"
			} else {
				health["http_client"] = fmt.Sprintf("degraded: status %d", resp.StatusCode)
			}
		}
	} else {
		health["http_client"] = fmt.Sprintf("unhealthy: %v", err)
	}

	// Check cache health
	stats := rs.GetCacheStats()
	totalEntries := stats["total_entries"].(int)
	maxSize := stats["max_size"].(int)

	if totalEntries < maxSize {
		health["cache"] = "healthy"
	} else {
		health["cache"] = "at_capacity"
	}

	return health
}

// ExportCache exports cache contents for backup/analysis
func (rs *RunbookService) ExportCache() map[string]*CachedRunbook {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	exported := make(map[string]*CachedRunbook, len(rs.cache))
	for url, cached := range rs.cache {
		// Create a copy
		exported[url] = &CachedRunbook{
			Content:      cached.Content,
			URL:          cached.URL,
			CachedAt:     cached.CachedAt,
			LastAccessed: cached.LastAccessed,
			Size:         cached.Size,
		}
	}

	return exported
}

// ImportCache imports cache contents from backup
func (rs *RunbookService) ImportCache(cacheData map[string]*CachedRunbook) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	imported := 0
	for url, cached := range cacheData {
		// Validate entry
		if cached != nil && cached.Content != "" && cached.URL == url {
			rs.cache[url] = cached
			imported++
		}
	}

	rs.logger.Info("Imported cache data",
		zap.Int("imported", imported),
		zap.Int("total_entries", len(cacheData)))
}

// GetServiceMetrics returns comprehensive service metrics
func (rs *RunbookService) GetServiceMetrics() map[string]interface{} {
	cacheStats := rs.GetCacheStats()
	expired := rs.GetExpiredEntries()

	metrics := map[string]interface{}{
		"cache_stats":     cacheStats,
		"expired_entries": len(expired),
		"client_config": map[string]interface{}{
			"timeout": rs.client.Timeout.String(),
		},
		"security": map[string]interface{}{
			"allowed_schemes": []string{"http", "https"},
			"max_size_bytes":  1024 * 1024, // 1MB
		},
	}

	return metrics
}

// Helper functions

// countErrors counts the number of errors in a result map
func countErrors(results map[string]error) int {
	count := 0
	for _, err := range results {
		if err != nil {
			count++
		}
	}
	return count
}