package main

import (
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getEnvOrDefault returns the value of an environment variable or a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// sanitizeSearchQuery escapes special Lucene/OpenSearch query_string characters
// to prevent OpenSearch injection attacks. This should be used on any user input
// passed to query_string queries.
func sanitizeSearchQuery(input string) string {
	if input == "" || input == "*" {
		return input
	}
	// Escape Lucene special characters: + - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \ /
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		`+`, `\+`,
		`-`, `\-`,
		`=`, `\=`,
		`>`, `\>`,
		`<`, `\<`,
		`!`, `\!`,
		`(`, `\(`,
		`)`, `\)`,
		`{`, `\{`,
		`}`, `\}`,
		`[`, `\[`,
		`]`, `\]`,
		`^`, `\^`,
		`~`, `\~`,
		`*`, `\*`,
		`?`, `\?`,
		`:`, `\:`,
		`/`, `\/`,
	)
	return replacer.Replace(input)
}

// validSortFields contains the allowed sort fields to prevent injection via sort parameters
var validSortFields = map[string]bool{
	"timestamp": true, "@timestamp": true, "datetime": true,
	"severity": true, "severity.keyword": true,
	"source": true, "source.keyword": true,
	"type": true, "type.keyword": true,
	"status": true, "status.keyword": true,
	"created_at": true, "updated_at": true,
	"priority": true, "priority.keyword": true,
	"score": true, "risk_score": true,
	"_score": true, "_id": true,
}

// validateSortField checks if a sort field is in the allowed list
func validateSortField(field string) string {
	if validSortFields[field] {
		return field
	}
	return "timestamp" // safe default
}

// validateSortOrder ensures sort order is either "asc" or "desc"
func validateSortOrder(order string) string {
	order = strings.ToLower(order)
	if order == "asc" || order == "desc" {
		return order
	}
	return "desc" // safe default
}

// sanitizeAlphanumeric only allows alphanumeric chars, hyphens, underscores, and dots
var reAlphanumericExtended = regexp.MustCompile(`[^a-zA-Z0-9._\-]`)

func sanitizeAlphanumeric(input string) string {
	return reAlphanumericExtended.ReplaceAllString(input, "")
}

// internalError logs the full error server-side and returns a generic message to the client.
// This prevents exposing internal details (paths, DB errors, stack traces) in API responses.
func internalError(c interface{ JSON(int, interface{}) }, logger interface{ Printf(string, ...interface{}) }, statusCode int, publicMsg string, err error) {
	if err != nil && logger != nil {
		logger.Printf("[ERROR] %s: %v", publicMsg, err)
	}
	c.JSON(statusCode, map[string]interface{}{
		"error": publicMsg,
	})
}

// getUsernameFromContext extracts the authenticated username from the Gin context.
// Falls back to "system" if no user is set (e.g., unauthenticated or internal calls).
// This should be used instead of hardcoding "admin" or "current-user".
func getUsernameFromContext(c *gin.Context) string {
	if username, exists := c.Get("username"); exists {
		if u, ok := username.(string); ok && u != "" {
			return u
		}
	}
	return "system"
}

// getUserIDFromContext extracts the authenticated user ID from the Gin context.
func getUserIDFromContext(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok && id != "" {
			return id
		}
	}
	return ""
}

// validateURL checks if a string is a valid URL with an allowed scheme (http/https).
// Returns true if valid, false otherwise. Use this before passing user-supplied URLs
// to external services or rendering them in responses.
func validateURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Host == "" {
		return false
	}
	// Reject URLs longer than 2048 characters (reasonable limit)
	if len(rawURL) > 2048 {
		return false
	}
	return true
}

// getActiveAWSConnection returns the first active AWS connection from the STS Manager.
// Used by aws_credentials_provider.go and other modules that need cross-account access.
func getActiveAWSConnection() *AccountConnection {
	connectionsMutex.RLock()
	defer connectionsMutex.RUnlock()

	for _, conn := range accountConnections {
		if conn.Status == "active" {
			return conn
		}
	}
	return nil
}
