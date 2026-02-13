package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// LogLevel represents the severity of a log message
type LogLevel string

const (
	LogLevelDebug   LogLevel = "debug"
	LogLevelInfo    LogLevel = "info"
	LogLevelWarning LogLevel = "warning"
	LogLevelError   LogLevel = "error"
	LogLevelFatal   LogLevel = "fatal"
)

// StructuredLog represents a structured log entry
type StructuredLog struct {
	Timestamp string                 `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Service   string                 `json:"service"`
	Component string                 `json:"component,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	Method    string                 `json:"method,omitempty"`
	Path      string                 `json:"path,omitempty"`
	StatusCode int                   `json:"status_code,omitempty"`
	Latency   string                 `json:"latency,omitempty"`
	ClientIP  string                 `json:"client_ip,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

// Logger is a structured logger
type Logger struct {
	service string
}

// NewLogger creates a new structured logger
func NewLogger(service string) *Logger {
	return &Logger{
		service: service,
	}
}

// log writes a structured log entry
func (l *Logger) log(level LogLevel, message string, fields map[string]interface{}) {
	log := StructuredLog{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Message:   message,
		Service:   l.service,
	}

	if fields != nil {
		// Extract known fields
		if component, ok := fields["component"].(string); ok {
			log.Component = component
			delete(fields, "component")
		}
		if userID, ok := fields["user_id"].(string); ok {
			log.UserID = userID
			delete(fields, "user_id")
		}
		if requestID, ok := fields["request_id"].(string); ok {
			log.RequestID = requestID
			delete(fields, "request_id")
		}
		if method, ok := fields["method"].(string); ok {
			log.Method = method
			delete(fields, "method")
		}
		if path, ok := fields["path"].(string); ok {
			log.Path = path
			delete(fields, "path")
		}
		if statusCode, ok := fields["status_code"].(int); ok {
			log.StatusCode = statusCode
			delete(fields, "status_code")
		}
		if latency, ok := fields["latency"].(string); ok {
			log.Latency = latency
			delete(fields, "latency")
		}
		if clientIP, ok := fields["client_ip"].(string); ok {
			log.ClientIP = clientIP
			delete(fields, "client_ip")
		}
		if err, ok := fields["error"].(string); ok {
			log.Error = err
			delete(fields, "error")
		}

		// Remaining fields go to Extra
		if len(fields) > 0 {
			log.Extra = fields
		}
	}

	// Marshal to JSON
	jsonLog, err := json.Marshal(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal log: %v\n", err)
		return
	}

	// Write to stdout
	fmt.Println(string(jsonLog))
}

// Debug logs a debug message
func (l *Logger) Debug(message string, fields map[string]interface{}) {
	l.log(LogLevelDebug, message, fields)
}

// Info logs an info message
func (l *Logger) Info(message string, fields map[string]interface{}) {
	l.log(LogLevelInfo, message, fields)
}

// Warning logs a warning message
func (l *Logger) Warning(message string, fields map[string]interface{}) {
	l.log(LogLevelWarning, message, fields)
}

// Error logs an error message
func (l *Logger) Error(message string, fields map[string]interface{}) {
	l.log(LogLevelError, message, fields)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(message string, fields map[string]interface{}) {
	l.log(LogLevelFatal, message, fields)
	os.Exit(1)
}

// Global logger instance
var globalLogger = NewLogger("siem-platform")

// StructuredLoggingMiddleware creates a middleware for structured logging
func StructuredLoggingMiddleware(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()

		// Process request
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		// Add request ID to context
		requestID := generateRequestID()
		c.Set("request_id", requestID)

		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get user ID if available
		userID := ""
		if uid, exists := c.Get("user_id"); exists {
			if uidStr, ok := uid.(string); ok {
				userID = uidStr
			}
		}

		// Log fields
		fields := map[string]interface{}{
			"request_id":  requestID,
			"method":      c.Request.Method,
			"path":        path,
			"query":       query,
			"status_code": c.Writer.Status(),
			"latency":     latency.String(),
			"client_ip":   c.ClientIP(),
			"user_agent":  c.Request.UserAgent(),
		}

		if userID != "" {
			fields["user_id"] = userID
		}

		// Add error if exists
		if len(c.Errors) > 0 {
			fields["error"] = c.Errors.String()
		}

		// Determine log level based on status code
		statusCode := c.Writer.Status()
		message := "HTTP Request"

		switch {
		case statusCode >= 500:
			logger.Error(message, fields)
		case statusCode >= 400:
			logger.Warning(message, fields)
		default:
			logger.Info(message, fields)
		}
	}
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

// Helper functions for logging in handlers

// LogInfo logs an info message with context from gin.Context
func LogInfo(c *gin.Context, message string, extra map[string]interface{}) {
	fields := extractContextFields(c)
	for k, v := range extra {
		fields[k] = v
	}
	globalLogger.Info(message, fields)
}

// LogWarning logs a warning message with context from gin.Context
func LogWarning(c *gin.Context, message string, extra map[string]interface{}) {
	fields := extractContextFields(c)
	for k, v := range extra {
		fields[k] = v
	}
	globalLogger.Warning(message, fields)
}

// LogError logs an error message with context from gin.Context
func LogError(c *gin.Context, message string, err error, extra map[string]interface{}) {
	fields := extractContextFields(c)
	if err != nil {
		fields["error"] = err.Error()
	}
	for k, v := range extra {
		fields[k] = v
	}
	globalLogger.Error(message, fields)
}

// extractContextFields extracts common fields from gin.Context
func extractContextFields(c *gin.Context) map[string]interface{} {
	fields := make(map[string]interface{})

	if requestID, exists := c.Get("request_id"); exists {
		fields["request_id"] = requestID
	}

	if userID, exists := c.Get("user_id"); exists {
		fields["user_id"] = userID
	}

	fields["method"] = c.Request.Method
	fields["path"] = c.Request.URL.Path
	fields["client_ip"] = c.ClientIP()

	return fields
}

