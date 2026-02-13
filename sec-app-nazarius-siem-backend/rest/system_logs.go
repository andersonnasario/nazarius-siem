package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// SYSTEM LOGS - View application logs from frontend
// ============================================================================

// LogEntry represents a single log entry
type LogEntry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`     // INFO, WARN, ERROR, DEBUG
	Source    string                 `json:"source"`    // Component that generated the log
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// SystemStatus represents the current system status
type SystemStatus struct {
	Status      string                 `json:"status"`       // healthy, degraded, unhealthy
	Uptime      string                 `json:"uptime"`
	StartedAt   time.Time              `json:"started_at"`
	Version     string                 `json:"version"`
	Environment string                 `json:"environment"`
	Components  map[string]interface{} `json:"components"`
	Resources   map[string]interface{} `json:"resources"`
}

// Global log storage (in-memory, circular buffer)
var (
	systemLogs      []LogEntry
	systemLogsMutex sync.RWMutex
	maxLogEntries   = 1000
	appStartTime    = time.Now()
)

// AddSystemLog adds a new log entry to the system logs
func AddSystemLog(level, source, message string, details map[string]interface{}) {
	systemLogsMutex.Lock()
	defer systemLogsMutex.Unlock()

	entry := LogEntry{
		ID:        fmt.Sprintf("log-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		Level:     level,
		Source:    source,
		Message:   message,
		Details:   details,
	}

	// Add to beginning (newest first)
	systemLogs = append([]LogEntry{entry}, systemLogs...)

	// Keep only last N entries
	if len(systemLogs) > maxLogEntries {
		systemLogs = systemLogs[:maxLogEntries]
	}
}

// Initialize system logs with startup information
func initSystemLogs() {
	AddSystemLog("INFO", "system", "🚀 SIEM Platform Backend started", map[string]interface{}{
		"version":     "1.0.0",
		"go_version":  runtime.Version(),
		"environment": getEnvOrDefault("GIN_MODE", "debug"),
	})

	// Log configuration status
	AddSystemLog("INFO", "config", "📋 Configuration loaded", map[string]interface{}{
		"db_host":           getEnvOrDefault("DB_HOST", "not set"),
		"redis_host":        getEnvOrDefault("REDIS_HOST", "not set"),
		"elasticsearch_url": getEnvOrDefault("ELASTICSEARCH_URL", "not set"),
		"use_real_aws_data": getEnvOrDefault("USE_REAL_AWS_DATA", "false"),
	})

	// Log database connection
	AddSystemLog("INFO", "database", "🔌 Attempting database connection", nil)

	// Log Redis connection
	AddSystemLog("INFO", "redis", "🔌 Attempting Redis connection", nil)

	// Log OpenSearch connection
	AddSystemLog("INFO", "opensearch", "🔌 Attempting OpenSearch connection", map[string]interface{}{
		"url":     getEnvOrDefault("ELASTICSEARCH_URL", "not set"),
		"use_tls": getEnvOrDefault("ELASTICSEARCH_USE_TLS", "false"),
	})

	// Log AWS integration status
	if os.Getenv("USE_REAL_AWS_DATA") == "true" {
		AddSystemLog("INFO", "aws", "🔄 AWS Real Data mode ENABLED", map[string]interface{}{
			"region": getEnvOrDefault("AWS_REGION", "us-east-1"),
		})
	} else if IsMockDataDisabled() {
		AddSystemLog("INFO", "aws", "🚫 AWS Mock Data DISABLED - Only real data will be shown", map[string]interface{}{
			"disable_mock_data": "true",
		})
	} else {
		AddSystemLog("WARN", "aws", "🎭 AWS Mock Data mode (USE_REAL_AWS_DATA not set)", nil)
	}
}

// Handler: Get system logs
func (s *APIServer) handleGetSystemLogs(c *gin.Context) {
	systemLogsMutex.RLock()
	defer systemLogsMutex.RUnlock()

	// Parse query parameters
	level := c.Query("level")
	source := c.Query("source")
	search := c.Query("search")
	limitStr := c.DefaultQuery("limit", "100")
	limit, _ := strconv.Atoi(limitStr)

	if limit > maxLogEntries {
		limit = maxLogEntries
	}

	// Filter logs
	filteredLogs := make([]LogEntry, 0)
	for _, log := range systemLogs {
		// Filter by level
		if level != "" && log.Level != level {
			continue
		}

		// Filter by source
		if source != "" && log.Source != source {
			continue
		}

		// Filter by search term
		if search != "" && !containsIgnoreCase(log.Message, search) {
			continue
		}

		filteredLogs = append(filteredLogs, log)

		if len(filteredLogs) >= limit {
			break
		}
	}

	// Get unique sources for filter dropdown
	sourcesMap := make(map[string]bool)
	for _, log := range systemLogs {
		sourcesMap[log.Source] = true
	}
	sources := make([]string, 0, len(sourcesMap))
	for source := range sourcesMap {
		sources = append(sources, source)
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"logs":   filteredLogs,
		"total":  len(filteredLogs),
		"filters": gin.H{
			"levels":  []string{"INFO", "WARN", "ERROR", "DEBUG"},
			"sources": sources,
		},
	})
}

// Handler: Get system status
func (s *APIServer) handleGetSystemStatus(c *gin.Context) {
	// Calculate uptime
	uptime := time.Since(appStartTime)
	uptimeStr := formatSystemUptime(uptime)

	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Check component status
	components := make(map[string]interface{})

	// Database status - check if authRepo is available
	dbStatus := "healthy"
	dbMessage := "Connected"
	if s.authRepo == nil {
		dbStatus = "unhealthy"
		dbMessage = "Not connected"
	}
	components["database"] = map[string]interface{}{
		"status":  dbStatus,
		"message": dbMessage,
		"host":    getEnvOrDefault("DB_HOST", "unknown"),
	}

	// Redis status
	redisStatus := "healthy"
	redisMessage := "Connected"
	if s.redis == nil {
		redisStatus = "unhealthy"
		redisMessage = "Not connected"
	}
	components["redis"] = map[string]interface{}{
		"status":  redisStatus,
		"message": redisMessage,
		"host":    getEnvOrDefault("REDIS_HOST", "unknown"),
		"tls":     getEnvOrDefault("REDIS_USE_TLS", "false"),
	}

	// OpenSearch status
	opensearchStatus := "healthy"
	opensearchMessage := "Connected"
	if s.opensearch == nil {
		opensearchStatus = "unhealthy"
		opensearchMessage = "Not connected"
	}
	components["opensearch"] = map[string]interface{}{
		"status":  opensearchStatus,
		"message": opensearchMessage,
		"url":     getEnvOrDefault("ELASTICSEARCH_URL", "unknown"),
		"tls":     getEnvOrDefault("ELASTICSEARCH_USE_TLS", "false"),
	}

	// AWS Integration status
	awsStatus := "disabled"
	awsMessage := "Mock data mode"
	if os.Getenv("USE_REAL_AWS_DATA") == "true" {
		awsStatus = "enabled"
		awsMessage = "Real data mode"
		if cloudtrailCollector != nil {
			awsMessage = "Connected - CloudTrail active"
		}
	}
	components["aws_integration"] = map[string]interface{}{
		"status":  awsStatus,
		"message": awsMessage,
		"region":  getEnvOrDefault("AWS_REGION", "us-east-1"),
	}

	// Determine overall status
	overallStatus := "healthy"
	if s.authRepo == nil || s.opensearch == nil {
		overallStatus = "degraded"
	}
	if s.authRepo == nil && s.opensearch == nil {
		overallStatus = "unhealthy"
	}

	// Resources
	resources := map[string]interface{}{
		"memory": map[string]interface{}{
			"alloc_mb":       memStats.Alloc / 1024 / 1024,
			"total_alloc_mb": memStats.TotalAlloc / 1024 / 1024,
			"sys_mb":         memStats.Sys / 1024 / 1024,
			"gc_cycles":      memStats.NumGC,
		},
		"goroutines": runtime.NumGoroutine(),
		"cpu_cores":  runtime.NumCPU(),
	}

	status := SystemStatus{
		Status:      overallStatus,
		Uptime:      uptimeStr,
		StartedAt:   appStartTime,
		Version:     "1.0.0",
		Environment: getEnvOrDefault("GIN_MODE", "debug"),
		Components:  components,
		Resources:   resources,
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   status,
	})
}

// Handler: Get environment configuration (sanitized)
func (s *APIServer) handleGetSystemConfig(c *gin.Context) {
	// Return sanitized configuration (no secrets)
	config := map[string]interface{}{
		"database": map[string]interface{}{
			"host":     getEnvOrDefault("DB_HOST", "not set"),
			"port":     getEnvOrDefault("DB_PORT", "5432"),
			"name":     getEnvOrDefault("DB_NAME", "siem"),
			"ssl_mode": getEnvOrDefault("DB_SSLMODE", "disable"),
		},
		"redis": map[string]interface{}{
			"host":    getEnvOrDefault("REDIS_HOST", "not set"),
			"port":    getEnvOrDefault("REDIS_PORT", "6379"),
			"use_tls": getEnvOrDefault("REDIS_USE_TLS", "false"),
		},
		"opensearch": map[string]interface{}{
			"url":     getEnvOrDefault("ELASTICSEARCH_URL", "not set"),
			"index":   getEnvOrDefault("ELASTICSEARCH_INDEX", "siem-*"),
			"use_tls": getEnvOrDefault("ELASTICSEARCH_USE_TLS", "false"),
		},
		"aws": map[string]interface{}{
			"region":        getEnvOrDefault("AWS_REGION", "us-east-1"),
			"use_real_data": getEnvOrDefault("USE_REAL_AWS_DATA", "false"),
			"account_id":    maskString(getEnvOrDefault("AWS_ACCOUNT_ID", "")),
		},
		"server": map[string]interface{}{
			"port":         getEnvOrDefault("PORT", "8080"),
			"gin_mode":     getEnvOrDefault("GIN_MODE", "debug"),
			"cors_origins": getEnvOrDefault("CORS_ORIGINS", "*"),
		},
		"jwt": map[string]interface{}{
			"expiration":         getEnvOrDefault("JWT_EXPIRATION", "15m"),
			"refresh_expiration": getEnvOrDefault("JWT_REFRESH_EXPIRATION", "7d"),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"config": config,
	})
}

// Handler: Add manual log entry (for testing)
func (s *APIServer) handleAddSystemLog(c *gin.Context) {
	var req struct {
		Level   string                 `json:"level"`
		Source  string                 `json:"source"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate level
	validLevels := map[string]bool{"INFO": true, "WARN": true, "ERROR": true, "DEBUG": true}
	if !validLevels[req.Level] {
		req.Level = "INFO"
	}

	if req.Source == "" {
		req.Source = "manual"
	}

	AddSystemLog(req.Level, req.Source, req.Message, req.Details)

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Log entry added",
	})
}

// Handler: Clear system logs
func (s *APIServer) handleClearSystemLogs(c *gin.Context) {
	systemLogsMutex.Lock()
	defer systemLogsMutex.Unlock()

	systemLogs = make([]LogEntry, 0)

	AddSystemLog("INFO", "system", "🗑️ System logs cleared by admin", nil)

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Logs cleared",
	})
}

// Helper: Format duration to human readable string (renamed to avoid conflict)
func formatSystemUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// Helper: Check if string contains substring (case insensitive)
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(substr) == 0 ||
			(len(s) > 0 && containsIgnoreCaseImpl(s, substr)))
}

func containsIgnoreCaseImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalIgnoreCase(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// Helper: Mask sensitive string
func maskString(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}
