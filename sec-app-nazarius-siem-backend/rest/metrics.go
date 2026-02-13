package main

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics
var (
	// HTTP Metrics
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "siem_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "siem_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	// Business Metrics
	eventsProcessedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "siem_events_processed_total",
			Help: "Total number of events processed",
		},
	)

	eventsProcessedPerSecond = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "siem_events_processed_per_second",
			Help: "Number of events processed per second",
		},
	)

	alertsCreatedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "siem_alerts_created_total",
			Help: "Total number of alerts created",
		},
		[]string{"severity"},
	)

	alertsActiveGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "siem_alerts_active",
			Help: "Number of active alerts",
		},
		[]string{"severity"},
	)

	casesOpenGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "siem_cases_open",
			Help: "Number of open cases",
		},
	)

	casesCreatedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "siem_cases_created_total",
			Help: "Total number of cases created",
		},
	)

	playbooksExecutedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "siem_playbooks_executed_total",
			Help: "Total number of playbooks executed",
		},
		[]string{"status"},
	)

	playbooksExecutionDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "siem_playbooks_execution_duration_seconds",
			Help:    "Playbook execution duration in seconds",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120},
		},
	)

	// Threat Intelligence Metrics
	threatIntelEnrichmentsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "siem_threat_intel_enrichments_total",
			Help: "Total number of threat intelligence enrichments",
		},
	)

	iocMatchesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "siem_ioc_matches_total",
			Help: "Total number of IOC matches",
		},
		[]string{"type"},
	)

	// UEBA Metrics
	uebaAnomaliesDetectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "siem_ueba_anomalies_detected_total",
			Help: "Total number of UEBA anomalies detected",
		},
		[]string{"severity"},
	)

	uebaUsersAnalyzedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "siem_ueba_users_analyzed_total",
			Help: "Total number of users analyzed by UEBA",
		},
	)

	// Vulnerability Management Metrics
	vulnerabilitiesDetectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "siem_vulnerabilities_detected_total",
			Help: "Total number of vulnerabilities detected",
		},
		[]string{"severity"},
	)

	vulnerabilitiesActiveGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "siem_vulnerabilities_active",
			Help: "Number of active vulnerabilities",
		},
		[]string{"severity"},
	)

	// Network Traffic Analysis Metrics
	networkFlowsAnalyzedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "siem_network_flows_analyzed_total",
			Help: "Total number of network flows analyzed",
		},
	)

	networkAnomaliesDetectedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "siem_network_anomalies_detected_total",
			Help: "Total number of network anomalies detected",
		},
	)

	// ML Analytics Metrics
	mlModelsTrainedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "siem_ml_models_trained_total",
			Help: "Total number of ML models trained",
		},
	)

	mlPredictionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "siem_ml_predictions_total",
			Help: "Total number of ML predictions made",
		},
		[]string{"model_type"},
	)

	mlModelAccuracyGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "siem_ml_model_accuracy",
			Help: "ML model accuracy score",
		},
		[]string{"model_id", "model_type"},
	)

	// Security Metrics
	securityRateLimitHitsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "siem_security_rate_limit_hits_total",
			Help: "Total number of rate limit hits",
		},
	)

	securityBruteForceAttemptsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "siem_security_brute_force_attempts_total",
			Help: "Total number of brute force attempts detected",
		},
	)

	securityBlockedIPsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "siem_security_blocked_ips",
			Help: "Number of currently blocked IPs",
		},
	)

	// System Metrics
	systemHealthStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "siem_system_health_status",
			Help: "System health status (1 = healthy, 0 = unhealthy)",
		},
		[]string{"component"},
	)

	elasticsearchConnectionStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "siem_elasticsearch_connection_status",
			Help: "Elasticsearch connection status (1 = connected, 0 = disconnected)",
		},
	)

	redisConnectionStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "siem_redis_connection_status",
			Help: "Redis connection status (1 = connected, 0 = disconnected)",
		},
	)
)

// PrometheusMiddleware records HTTP metrics
func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		// Process request
		c.Next()

		// Record metrics
		duration := time.Since(start).Seconds()
		status := c.Writer.Status()

		httpRequestsTotal.WithLabelValues(
			c.Request.Method,
			path,
			string(rune(status)),
		).Inc()

		httpRequestDuration.WithLabelValues(
			c.Request.Method,
			path,
		).Observe(duration)
	}
}

// Helper functions to record business metrics

// RecordEventProcessed records an event being processed
func RecordEventProcessed() {
	eventsProcessedTotal.Inc()
}

// RecordEventsPerSecond updates the events per second gauge
func RecordEventsPerSecond(count float64) {
	eventsProcessedPerSecond.Set(count)
}

// RecordAlertCreated records an alert creation
func RecordAlertCreated(severity string) {
	alertsCreatedTotal.WithLabelValues(severity).Inc()
}

// RecordActiveAlerts updates the active alerts gauge
func RecordActiveAlerts(severity string, count float64) {
	alertsActiveGauge.WithLabelValues(severity).Set(count)
}

// RecordOpenCases updates the open cases gauge
func RecordOpenCases(count float64) {
	casesOpenGauge.Set(count)
}

// RecordCaseCreated records a case creation
func RecordCaseCreated() {
	casesCreatedTotal.Inc()
}

// RecordPlaybookExecuted records a playbook execution
func RecordPlaybookExecuted(status string, duration float64) {
	playbooksExecutedTotal.WithLabelValues(status).Inc()
	playbooksExecutionDuration.Observe(duration)
}

// RecordThreatIntelEnrichment records a threat intel enrichment
func RecordThreatIntelEnrichment() {
	threatIntelEnrichmentsTotal.Inc()
}

// RecordIOCMatch records an IOC match
func RecordIOCMatch(iocType string) {
	iocMatchesTotal.WithLabelValues(iocType).Inc()
}

// RecordUEBAAnomaly records a UEBA anomaly detection
func RecordUEBAAnomaly(severity string) {
	uebaAnomaliesDetectedTotal.WithLabelValues(severity).Inc()
}

// RecordUEBAUserAnalyzed records a user being analyzed
func RecordUEBAUserAnalyzed() {
	uebaUsersAnalyzedTotal.Inc()
}

// RecordVulnerabilityDetected records a vulnerability detection
func RecordVulnerabilityDetected(severity string) {
	vulnerabilitiesDetectedTotal.WithLabelValues(severity).Inc()
}

// RecordActiveVulnerabilities updates the active vulnerabilities gauge
func RecordActiveVulnerabilities(severity string, count float64) {
	vulnerabilitiesActiveGauge.WithLabelValues(severity).Set(count)
}

// RecordNetworkFlowAnalyzed records a network flow analysis
func RecordNetworkFlowAnalyzed() {
	networkFlowsAnalyzedTotal.Inc()
}

// RecordNetworkAnomalyDetected records a network anomaly detection
func RecordNetworkAnomalyDetected() {
	networkAnomaliesDetectedTotal.Inc()
}

// RecordMLModelTrained records an ML model training
func RecordMLModelTrained() {
	mlModelsTrainedTotal.Inc()
}

// RecordMLPrediction records an ML prediction
func RecordMLPrediction(modelType string) {
	mlPredictionsTotal.WithLabelValues(modelType).Inc()
}

// RecordMLModelAccuracy updates the ML model accuracy gauge
func RecordMLModelAccuracy(modelID, modelType string, accuracy float64) {
	mlModelAccuracyGauge.WithLabelValues(modelID, modelType).Set(accuracy)
}

// RecordRateLimitHit records a rate limit hit
func RecordRateLimitHit() {
	securityRateLimitHitsTotal.Inc()
}

// RecordBruteForceAttempt records a brute force attempt
func RecordBruteForceAttempt() {
	securityBruteForceAttemptsTotal.Inc()
}

// RecordBlockedIPs updates the blocked IPs gauge
func RecordBlockedIPs(count float64) {
	securityBlockedIPsGauge.Set(count)
}

// RecordSystemHealth updates the system health status
func RecordSystemHealth(component string, healthy bool) {
	status := 0.0
	if healthy {
		status = 1.0
	}
	systemHealthStatus.WithLabelValues(component).Set(status)
}

// RecordElasticsearchConnection updates the Elasticsearch connection status
func RecordElasticsearchConnection(connected bool) {
	status := 0.0
	if connected {
		status = 1.0
	}
	elasticsearchConnectionStatus.Set(status)
}

// RecordRedisConnection updates the Redis connection status
func RecordRedisConnection(connected bool) {
	status := 0.0
	if connected {
		status = 1.0
	}
	redisConnectionStatus.Set(status)
}

