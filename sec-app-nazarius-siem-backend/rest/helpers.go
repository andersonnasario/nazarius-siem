package main

import (
	"os"
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
