package main

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Server struct {
		Address string
	}
	Elasticsearch struct {
		Hosts        []string
		IndexPattern string
		Username     string // For AWS OpenSearch
		Password     string // For AWS OpenSearch
		UseTLS       bool   // Enable TLS for AWS OpenSearch
	}
	Redis struct {
		Address  string
		Password string
		DB       int
		UseTLS   bool // Enable TLS for AWS ElastiCache in production
	}
	JWT struct {
		Secret string
	}
	CORS struct {
		AllowOrigins []string
	}
}

func loadConfig() *Config {
	config := &Config{}

	// Server
	config.Server.Address = getEnv("SERVER_ADDRESS", ":8080")

	// Elasticsearch / OpenSearch
	config.Elasticsearch.Hosts = []string{getEnv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")}
	config.Elasticsearch.IndexPattern = getEnv("ELASTICSEARCH_INDEX", "siem-*")
	config.Elasticsearch.Username = getEnv("ELASTICSEARCH_USERNAME", "")
	config.Elasticsearch.Password = getEnv("ELASTICSEARCH_PASSWORD", "")
	config.Elasticsearch.UseTLS = getBoolEnv("ELASTICSEARCH_USE_TLS", false) // Enable for AWS OpenSearch

	// Redis
	config.Redis.Address = getEnv("REDIS_ADDRESS", "redis:6379")
	config.Redis.Password = getEnv("REDIS_PASSWORD", "")
	config.Redis.DB = 0
	config.Redis.UseTLS = getBoolEnv("REDIS_USE_TLS", false) // Enable for AWS ElastiCache

	// JWT - secret is mandatory and must be at least 32 characters
	config.JWT.Secret = os.Getenv("JWT_SECRET")

	// CORS - split comma-separated origins
	corsOrigins := getEnv("CORS_ORIGINS", "")
	if corsOrigins != "" {
		origins := strings.Split(corsOrigins, ",")
		for i, o := range origins {
			origins[i] = strings.TrimSpace(o)
		}
		config.CORS.AllowOrigins = origins
	} else {
		config.CORS.AllowOrigins = []string{}
	}

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		boolValue, err := strconv.ParseBool(value)
		if err == nil {
			return boolValue
		}
	}
	return defaultValue
}
