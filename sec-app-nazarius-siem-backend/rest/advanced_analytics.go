package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// AnomalyDetection represents an anomaly detected by ML
type AnomalyDetection struct {
	ID              string    `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	EntityType      string    `json:"entity_type"` // user, host, network, application
	EntityID        string    `json:"entity_id"`
	EntityName      string    `json:"entity_name"`
	AnomalyType     string    `json:"anomaly_type"` // behavioral, statistical, temporal, spatial
	Severity        string    `json:"severity"`
	Confidence      float64   `json:"confidence"` // 0-100
	AnomalyScore    float64   `json:"anomaly_score"` // 0-100
	Baseline        float64   `json:"baseline"`
	CurrentValue    float64   `json:"current_value"`
	Deviation       float64   `json:"deviation"` // percentage
	Description     string    `json:"description"`
	Indicators      []string  `json:"indicators"`
	RelatedEvents   int       `json:"related_events"`
	Status          string    `json:"status"` // new, investigating, resolved, false_positive
	AssignedTo      string    `json:"assigned_to"`
	CreatedAt       time.Time `json:"created_at"`
}

// BehavioralProfile represents a behavioral profile for an entity
type BehavioralProfile struct {
	EntityType      string    `json:"entity_type"`
	EntityID        string    `json:"entity_id"`
	EntityName      string    `json:"entity_name"`
	ProfileCreated  time.Time `json:"profile_created"`
	LastUpdated     time.Time `json:"last_updated"`
	TotalEvents     int       `json:"total_events"`
	RiskScore       float64   `json:"risk_score"` // 0-100
	Patterns        []string  `json:"patterns"`
	NormalBehavior  map[string]float64 `json:"normal_behavior"`
	Anomalies       int       `json:"anomalies"`
	LastAnomaly     *time.Time `json:"last_anomaly,omitempty"`
}

// ThreatPrediction represents a predicted threat
type ThreatPrediction struct {
	ID              string    `json:"id"`
	PredictionType  string    `json:"prediction_type"` // attack, breach, malware, insider
	TargetType      string    `json:"target_type"`
	TargetID        string    `json:"target_id"`
	TargetName      string    `json:"target_name"`
	Probability     float64   `json:"probability"` // 0-100
	Severity        string    `json:"severity"`
	TimeWindow      string    `json:"time_window"` // next_hour, next_day, next_week
	Indicators      []string  `json:"indicators"`
	MITRETechniques []string  `json:"mitre_techniques"`
	Recommendations []string  `json:"recommendations"`
	Confidence      float64   `json:"confidence"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// MLModel represents a machine learning model
type MLModel struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"` // anomaly_detection, classification, prediction, clustering
	Algorithm       string    `json:"algorithm"` // isolation_forest, random_forest, lstm, etc
	Status          string    `json:"status"` // training, active, inactive, failed
	Accuracy        float64   `json:"accuracy"`
	Precision       float64   `json:"precision"`
	Recall          float64   `json:"recall"`
	F1Score         float64   `json:"f1_score"`
	TrainingData    int       `json:"training_data"` // number of samples
	LastTrained     time.Time `json:"last_trained"`
	Version         string    `json:"version"`
	Features        []string  `json:"features"`
	Description     string    `json:"description"`
}

// AnalyticsMetrics represents overall analytics metrics
type AnalyticsMetrics struct {
	TotalAnomalies      int     `json:"total_anomalies"`
	NewAnomalies        int     `json:"new_anomalies"`
	ResolvedAnomalies   int     `json:"resolved_anomalies"`
	FalsePositives      int     `json:"false_positives"`
	AvgConfidence       float64 `json:"avg_confidence"`
	HighSeverity        int     `json:"high_severity"`
	ActiveModels        int     `json:"active_models"`
	ModelAccuracy       float64 `json:"model_accuracy"`
	PredictionsToday    int     `json:"predictions_today"`
	ThreatsPrevented    int     `json:"threats_prevented"`
	DetectionRate       float64 `json:"detection_rate"`
	FalsePositiveRate   float64 `json:"false_positive_rate"`
}

// RiskAssessment represents a risk assessment for an entity
type RiskAssessment struct {
	EntityType         string     `json:"entity_type"`
	EntityID           string     `json:"entity_id"`
	EntityName         string     `json:"entity_name"`
	RiskScore          float64    `json:"risk_score"` // 0-100
	RiskLevel          string     `json:"risk_level"` // low, medium, high, critical
	RiskFactors        []string   `json:"risk_factors"`
	Vulnerabilities    int        `json:"vulnerabilities"`
	Threats            int        `json:"threats"`
	Incidents          int        `json:"incidents"`
	Anomalies          int        `json:"anomalies"`
	LastIncident       *time.Time `json:"last_incident,omitempty"`
	Trend              string     `json:"trend"` // increasing, stable, decreasing
	LastAssessment     time.Time  `json:"last_assessment"`
	NextAssessment     time.Time  `json:"next_assessment"`
	MitigationActions  []string   `json:"mitigation_actions"`
	AssessedAt         time.Time  `json:"assessed_at"`
}

// Initialize advanced analytics
func initAdvancedAnalytics() {
	// Mock data will be generated on-the-fly
}

// Handler: List anomaly detections
func (s *APIServer) handleListMLAnomalies(c *gin.Context) {
	anomalies := []AnomalyDetection{
		{
			ID:            "anom-001",
			Timestamp:     time.Now().Add(-2 * time.Hour),
			EntityType:    "user",
			EntityID:      "user-123",
			EntityName:    "john.doe",
			AnomalyType:   "behavioral",
			Severity:      "high",
			Confidence:    92.5,
			AnomalyScore:  87.3,
			Baseline:      50.0,
			CurrentValue:  450.0,
			Deviation:     800.0,
			Description:   "Unusual data access pattern detected",
			Indicators:    []string{"High volume data access", "Unusual time", "Sensitive data"},
			RelatedEvents: 45,
			Status:        "investigating",
			AssignedTo:    "analyst-1",
			CreatedAt:     time.Now().Add(-2 * time.Hour),
		},
		{
			ID:            "anom-002",
			Timestamp:     time.Now().Add(-5 * time.Hour),
			EntityType:    "host",
			EntityID:      "host-456",
			EntityName:    "web-server-01",
			AnomalyType:   "statistical",
			Severity:      "medium",
			Confidence:    85.2,
			AnomalyScore:  72.1,
			Baseline:      100.0,
			CurrentValue:  350.0,
			Deviation:     250.0,
			Description:   "Abnormal network traffic volume",
			Indicators:    []string{"High bandwidth usage", "Unusual destination IPs"},
			RelatedEvents: 120,
			Status:        "new",
			AssignedTo:    "",
			CreatedAt:     time.Now().Add(-5 * time.Hour),
		},
		{
			ID:            "anom-003",
			Timestamp:     time.Now().Add(-1 * 24 * time.Hour),
			EntityType:    "application",
			EntityID:      "app-789",
			EntityName:    "payment-api",
			AnomalyType:   "temporal",
			Severity:      "critical",
			Confidence:    95.8,
			AnomalyScore:  94.5,
			Baseline:      200.0,
			CurrentValue:  2500.0,
			Deviation:     1150.0,
			Description:   "Spike in failed authentication attempts",
			Indicators:    []string{"Brute force pattern", "Multiple source IPs", "Credential stuffing"},
			RelatedEvents: 2500,
			Status:        "resolved",
			AssignedTo:    "analyst-2",
			CreatedAt:     time.Now().Add(-1 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    anomalies,
	})
}

// Handler: List behavioral profiles
func (s *APIServer) handleListBehavioralProfiles(c *gin.Context) {
	lastAnomaly := time.Now().Add(-2 * time.Hour)
	
	profiles := []BehavioralProfile{
		{
			EntityType:     "user",
			EntityID:       "user-123",
			EntityName:     "john.doe",
			ProfileCreated: time.Now().Add(-90 * 24 * time.Hour),
			LastUpdated:    time.Now().Add(-1 * time.Hour),
			TotalEvents:    15420,
			RiskScore:      75.5,
			Patterns:       []string{"Data access 9-5", "VPN usage", "Office location"},
			NormalBehavior: map[string]float64{
				"avg_daily_logins": 3.2,
				"avg_data_access":  50.0,
				"avg_session_time": 480.0,
			},
			Anomalies:   3,
			LastAnomaly: &lastAnomaly,
		},
		{
			EntityType:     "host",
			EntityID:       "host-456",
			EntityName:     "web-server-01",
			ProfileCreated: time.Now().Add(-180 * 24 * time.Hour),
			LastUpdated:    time.Now().Add(-30 * time.Minute),
			TotalEvents:    245680,
			RiskScore:      45.2,
			Patterns:       []string{"HTTP traffic", "Database connections", "API calls"},
			NormalBehavior: map[string]float64{
				"avg_requests_per_min": 100.0,
				"avg_bandwidth_mbps":   50.0,
				"avg_connections":      200.0,
			},
			Anomalies:   1,
			LastAnomaly: &lastAnomaly,
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    profiles,
	})
}

// Handler: List threat predictions
func (s *APIServer) handleListThreatPredictions(c *gin.Context) {
	predictions := []ThreatPrediction{
		{
			ID:             "pred-001",
			PredictionType: "attack",
			TargetType:     "host",
			TargetID:       "host-456",
			TargetName:     "web-server-01",
			Probability:    78.5,
			Severity:       "high",
			TimeWindow:     "next_24_hours",
			Indicators:     []string{"Port scanning detected", "Vulnerability present", "Known attacker IP"},
			MITRETechniques: []string{"T1046", "T1190"},
			Recommendations: []string{"Patch vulnerability", "Block suspicious IPs", "Enable WAF rules"},
			Confidence:     82.3,
			CreatedAt:      time.Now().Add(-1 * time.Hour),
			ExpiresAt:      time.Now().Add(23 * time.Hour),
		},
		{
			ID:             "pred-002",
			PredictionType: "insider",
			TargetType:     "user",
			TargetID:       "user-789",
			TargetName:     "alice.smith",
			Probability:    65.2,
			Severity:       "medium",
			TimeWindow:     "next_week",
			Indicators:     []string{"Unusual data access", "After-hours activity", "Resignation submitted"},
			MITRETechniques: []string{"T1530", "T1567"},
			Recommendations: []string{"Monitor data access", "Review permissions", "Enable DLP"},
			Confidence:     71.8,
			CreatedAt:      time.Now().Add(-3 * time.Hour),
			ExpiresAt:      time.Now().Add(7 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    predictions,
	})
}

// Handler: List ML models
func (s *APIServer) handleListMLModels(c *gin.Context) {
	models := []MLModel{
		{
			ID:           "model-001",
			Name:         "User Behavior Anomaly Detector",
			Type:         "anomaly_detection",
			Algorithm:    "isolation_forest",
			Status:       "active",
			Accuracy:     94.5,
			Precision:    92.3,
			Recall:       89.7,
			F1Score:      91.0,
			TrainingData: 500000,
			LastTrained:  time.Now().Add(-7 * 24 * time.Hour),
			Version:      "2.1.0",
			Features:     []string{"login_frequency", "data_access_volume", "session_duration", "location"},
			Description:  "Detects anomalous user behavior patterns",
		},
		{
			ID:           "model-002",
			Name:         "Network Traffic Classifier",
			Type:         "classification",
			Algorithm:    "random_forest",
			Status:       "active",
			Accuracy:     96.8,
			Precision:    95.2,
			Recall:       94.1,
			F1Score:      94.6,
			TrainingData: 1000000,
			LastTrained:  time.Now().Add(-14 * 24 * time.Hour),
			Version:      "3.0.1",
			Features:     []string{"packet_size", "protocol", "port", "flow_duration", "bytes_transferred"},
			Description:  "Classifies network traffic as benign or malicious",
		},
		{
			ID:           "model-003",
			Name:         "Threat Prediction Engine",
			Type:         "prediction",
			Algorithm:    "lstm",
			Status:       "active",
			Accuracy:     88.2,
			Precision:    86.5,
			Recall:       85.3,
			F1Score:      85.9,
			TrainingData: 250000,
			LastTrained:  time.Now().Add(-3 * 24 * time.Hour),
			Version:      "1.5.2",
			Features:     []string{"historical_incidents", "vulnerability_data", "threat_intel", "time_series"},
			Description:  "Predicts likelihood of future security incidents",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    models,
	})
}

// Handler: Get analytics metrics
func (s *APIServer) handleGetAnalyticsMetrics(c *gin.Context) {
	metrics := AnalyticsMetrics{
		TotalAnomalies:    127,
		NewAnomalies:      15,
		ResolvedAnomalies: 98,
		FalsePositives:    14,
		AvgConfidence:     87.3,
		HighSeverity:      8,
		ActiveModels:      3,
		ModelAccuracy:     93.2,
		PredictionsToday:  23,
		ThreatsPrevented:  12,
		DetectionRate:     94.5,
		FalsePositiveRate: 5.2,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    metrics,
	})
}

// Handler: List risk assessments
func (s *APIServer) handleListRiskAssessments(c *gin.Context) {
	lastIncident := time.Now().Add(-48 * time.Hour)
	
	assessments := []RiskAssessment{
		{
			EntityType:      "host",
			EntityID:        "host-456",
			EntityName:      "web-server-01",
			RiskScore:       78.5,
			RiskLevel:       "high",
			RiskFactors:     []string{"Unpatched vulnerabilities", "Public exposure", "Recent anomalies"},
			Vulnerabilities: 5,
			Threats:         3,
			Incidents:       2,
			Anomalies:       4,
			LastIncident:    &lastIncident,
			Trend:           "increasing",
			LastAssessment:  time.Now().Add(-24 * time.Hour),
			NextAssessment:  time.Now().Add(24 * time.Hour),
			MitigationActions: []string{"Apply security patches", "Review firewall rules", "Enable additional monitoring"},
			AssessedAt:      time.Now(),
		},
		{
			EntityType:      "user",
			EntityID:        "user-123",
			EntityName:      "john.doe",
			RiskScore:       65.2,
			RiskLevel:       "medium",
			RiskFactors:     []string{"Unusual behavior", "High privileges", "Sensitive data access"},
			Vulnerabilities: 0,
			Threats:         2,
			Incidents:       1,
			Anomalies:       3,
			LastIncident:    &lastIncident,
			Trend:           "stable",
			LastAssessment:  time.Now().Add(-12 * time.Hour),
			NextAssessment:  time.Now().Add(36 * time.Hour),
			MitigationActions: []string{"Review access permissions", "Conduct security awareness training", "Monitor user activity"},
			AssessedAt:      time.Now(),
		},
		{
			EntityType:      "application",
			EntityID:        "app-789",
			EntityName:      "payment-api",
			RiskScore:       45.8,
			RiskLevel:       "medium",
			RiskFactors:     []string{"High value target", "Internet facing"},
			Vulnerabilities: 2,
			Threats:         1,
			Incidents:       0,
			Anomalies:       1,
			Trend:           "decreasing",
			LastAssessment:  time.Now().Add(-6 * time.Hour),
			NextAssessment:  time.Now().Add(42 * time.Hour),
			MitigationActions: []string{"Update dependencies", "Implement rate limiting", "Enable WAF"},
			AssessedAt:      time.Now(),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    assessments,
	})
}

