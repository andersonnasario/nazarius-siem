package main

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ExecutiveDashboardData aggregates all MDR metrics
type ExecutiveDashboardData struct {
	SecurityPosture      SecurityPosture      `json:"security_posture"`
	MDRPerformance       MDRPerformance       `json:"mdr_performance"`
	BusinessImpact       BusinessImpact       `json:"business_impact"`
	ThreatIntelSummary   ThreatIntelSummary   `json:"threat_intel_summary"`
	ComplianceStatus     ComplianceStatus     `json:"compliance_status"`
	CriticalAlerts       []CriticalAlert      `json:"critical_alerts"`
	TrendData            []TrendDataPoint     `json:"trend_data"`
	GeneratedAt          time.Time            `json:"generated_at"`
}

type SecurityPosture struct {
	OverallScore        float64 `json:"overall_score"` // 0-100
	ThreatLevel         string  `json:"threat_level"`  // low, medium, high, critical
	ActiveIncidents     int     `json:"active_incidents"`
	ResponseEffectiveness float64 `json:"response_effectiveness"` // 0-100
	SecurityCoverage    float64 `json:"security_coverage"` // 0-100
	DetectionRate       float64 `json:"detection_rate"` // 0-100
}

type MDRPerformance struct {
	AutomatedResponses  int     `json:"automated_responses"`
	TriagedAlerts       int     `json:"triaged_alerts"`
	SLACompliance       float64 `json:"sla_compliance"` // percentage
	MTTR                float64 `json:"mttr"` // minutes
	MTTA                float64 `json:"mtta"` // minutes
	FalsePositiveRate   float64 `json:"false_positive_rate"` // percentage
	AutomationRate      float64 `json:"automation_rate"` // percentage
}

type BusinessImpact struct {
	RiskReduction       float64 `json:"risk_reduction"` // percentage
	CostSavings         float64 `json:"cost_savings"` // dollars
	PreventedIncidents  int     `json:"prevented_incidents"`
	ROI                 float64 `json:"roi"` // percentage
	AvoidedDowntime     float64 `json:"avoided_downtime"` // hours
	ProductivityGain    float64 `json:"productivity_gain"` // percentage
}

type ThreatIntelSummary struct {
	TopThreats          []ThreatItem `json:"top_threats"`
	ActiveCampaigns     int          `json:"active_campaigns"`
	NewVulnerabilities  int          `json:"new_vulnerabilities"`
	ThreatActors        int          `json:"threat_actors"`
	MalwareDetections   int          `json:"malware_detections"`
}

type ThreatItem struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type ComplianceStatus struct {
	OverallCompliance   float64            `json:"overall_compliance"` // percentage
	Frameworks          map[string]float64 `json:"frameworks"` // framework -> compliance %
	AuditReadiness      string             `json:"audit_readiness"` // ready, needs_work, not_ready
	PolicyAdherence     float64            `json:"policy_adherence"` // percentage
	LastAudit           string             `json:"last_audit"`
}

type CriticalAlert struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
	Impact      string    `json:"impact"`
	ActionTaken string    `json:"action_taken"`
}

type TrendDataPoint struct {
	Timestamp       time.Time `json:"timestamp"`
	Incidents       int       `json:"incidents"`
	Resolved        int       `json:"resolved"`
	MTTR            float64   `json:"mttr"`
	SLACompliance   float64   `json:"sla_compliance"`
	SecurityScore   float64   `json:"security_score"`
}

var execDashMutex sync.RWMutex

func (s *APIServer) handleGetMDRExecutiveDashboard(c *gin.Context) {
	execDashMutex.RLock()
	defer execDashMutex.RUnlock()

	// Aggregate data from all MDR modules
	dashboard := ExecutiveDashboardData{
		SecurityPosture: SecurityPosture{
			OverallScore:          85.5,
			ThreatLevel:           "medium",
			ActiveIncidents:       12,
			ResponseEffectiveness: 92.3,
			SecurityCoverage:      88.7,
			DetectionRate:         94.2,
		},
		MDRPerformance: MDRPerformance{
			AutomatedResponses: 150,
			TriagedAlerts:      320,
			SLACompliance:      94.5,
			MTTR:               45.2,
			MTTA:               8.5,
			FalsePositiveRate:  5.3,
			AutomationRate:     85.0,
		},
		BusinessImpact: BusinessImpact{
			RiskReduction:      65.0,
			CostSavings:        125000.0,
			PreventedIncidents: 45,
			ROI:                320.0,
			AvoidedDowntime:    48.5,
			ProductivityGain:   35.0,
		},
		ThreatIntelSummary: ThreatIntelSummary{
			TopThreats: []ThreatItem{
				{Name: "Ransomware", Severity: "critical", Count: 15},
				{Name: "Phishing", Severity: "high", Count: 32},
				{Name: "Malware", Severity: "high", Count: 28},
			},
			ActiveCampaigns:    8,
			NewVulnerabilities: 12,
			ThreatActors:       5,
			MalwareDetections:  67,
		},
		ComplianceStatus: ComplianceStatus{
			OverallCompliance: 92.5,
			Frameworks: map[string]float64{
				"ISO 27001":  95.0,
				"SOC 2":      90.0,
				"GDPR":       93.5,
				"HIPAA":      91.0,
			},
			AuditReadiness:  "ready",
			PolicyAdherence: 94.2,
			LastAudit:       "2025-10-15",
		},
		CriticalAlerts: []CriticalAlert{
			{
				ID:          "alert-001",
				Title:       "Ransomware Detected on Critical Server",
				Severity:    "critical",
				Status:      "contained",
				Timestamp:   time.Now().Add(-2 * time.Hour),
				Impact:      "High - Production server affected",
				ActionTaken: "Host isolated, malware quarantined",
			},
			{
				ID:          "alert-002",
				Title:       "Suspicious Data Exfiltration Attempt",
				Severity:    "high",
				Status:      "investigating",
				Timestamp:   time.Now().Add(-1 * time.Hour),
				Impact:      "Medium - Sensitive data at risk",
				ActionTaken: "Network traffic blocked, investigation ongoing",
			},
		},
		TrendData:   generateTrendData(),
		GeneratedAt: time.Now(),
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    dashboard,
	})
}

func (s *APIServer) handleGetMDRSecurityPosture(c *gin.Context) {
	posture := SecurityPosture{
		OverallScore:          85.5,
		ThreatLevel:           "medium",
		ActiveIncidents:       12,
		ResponseEffectiveness: 92.3,
		SecurityCoverage:      88.7,
		DetectionRate:         94.2,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    posture,
	})
}

func (s *APIServer) handleGetMDRPerformanceMetrics(c *gin.Context) {
	performance := MDRPerformance{
		AutomatedResponses: 150,
		TriagedAlerts:      320,
		SLACompliance:      94.5,
		MTTR:               45.2,
		MTTA:               8.5,
		FalsePositiveRate:  5.3,
		AutomationRate:     85.0,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    performance,
	})
}

func (s *APIServer) handleGetMDRBusinessImpact(c *gin.Context) {
	impact := BusinessImpact{
		RiskReduction:      65.0,
		CostSavings:        125000.0,
		PreventedIncidents: 45,
		ROI:                320.0,
		AvoidedDowntime:    48.5,
		ProductivityGain:   35.0,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    impact,
	})
}

func (s *APIServer) handleGetMDRThreatIntelSummary(c *gin.Context) {
	summary := ThreatIntelSummary{
		TopThreats: []ThreatItem{
			{Name: "Ransomware", Severity: "critical", Count: 15},
			{Name: "Phishing", Severity: "high", Count: 32},
			{Name: "Malware", Severity: "high", Count: 28},
		},
		ActiveCampaigns:    8,
		NewVulnerabilities: 12,
		ThreatActors:       5,
		MalwareDetections:  67,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    summary,
	})
}

func (s *APIServer) handleGetMDRComplianceStatus(c *gin.Context) {
	status := ComplianceStatus{
		OverallCompliance: 92.5,
		Frameworks: map[string]float64{
			"ISO 27001": 95.0,
			"SOC 2":     90.0,
			"GDPR":      93.5,
			"HIPAA":     91.0,
		},
		AuditReadiness:  "ready",
		PolicyAdherence: 94.2,
		LastAudit:       "2025-10-15",
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    status,
	})
}

func (s *APIServer) handleGetMDRCriticalAlerts(c *gin.Context) {
	alerts := []CriticalAlert{
		{
			ID:          "alert-001",
			Title:       "Ransomware Detected on Critical Server",
			Severity:    "critical",
			Status:      "contained",
			Timestamp:   time.Now().Add(-2 * time.Hour),
			Impact:      "High - Production server affected",
			ActionTaken: "Host isolated, malware quarantined",
		},
		{
			ID:          "alert-002",
			Title:       "Suspicious Data Exfiltration Attempt",
			Severity:    "high",
			Status:      "investigating",
			Timestamp:   time.Now().Add(-1 * time.Hour),
			Impact:      "Medium - Sensitive data at risk",
			ActionTaken: "Network traffic blocked, investigation ongoing",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    alerts,
	})
}

func generateTrendData() []TrendDataPoint {
	data := make([]TrendDataPoint, 30)
	now := time.Now()

	for i := 0; i < 30; i++ {
		data[i] = TrendDataPoint{
			Timestamp:     now.Add(-time.Duration(29-i) * 24 * time.Hour),
			Incidents:     10 + i%5,
			Resolved:      8 + i%4,
			MTTR:          40.0 + float64(i%10),
			SLACompliance: 90.0 + float64(i%8),
			SecurityScore: 80.0 + float64(i%15),
		}
	}

	return data
}
