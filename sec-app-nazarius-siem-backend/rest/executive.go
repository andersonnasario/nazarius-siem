package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ExecutiveDashboard representa o dashboard executivo completo
type ExecutiveDashboard struct {
	Period      string              `json:"period"`      // last_24h, last_7d, last_30d, last_90d
	GeneratedAt time.Time           `json:"generatedAt"`
	KPIs        ExecutiveKPIs       `json:"kpis"`
	Modules     ModulesOverview     `json:"modules"`
	Trends      TrendsData          `json:"trends"`
	TopInsights TopInsights         `json:"topInsights"`
	ROI         ROIMetrics          `json:"roi"`
	Comparison  ComparisonData      `json:"comparison"`
}

// ExecutiveKPIs métricas-chave do sistema
type ExecutiveKPIs struct {
	TotalEvents        int     `json:"totalEvents"`
	TotalAlerts        int     `json:"totalAlerts"`
	CriticalAlerts     int     `json:"criticalAlerts"`
	TotalCases         int     `json:"totalCases"`
	OpenCases          int     `json:"openCases"`
	PlaybooksExecuted  int     `json:"playbooksExecuted"`
	IOCsDetected       int     `json:"iocsDetected"`
	MITRECoverage      float64 `json:"mitreCoverage"`      // %
	AutomationRate     float64 `json:"automationRate"`     // %
	SystemUptime       float64 `json:"systemUptime"`       // %
	MTTD               int     `json:"mttd"`               // minutes
	MTTR               int     `json:"mttr"`               // minutes
	IncidentResolution float64 `json:"incidentResolution"` // %
	FalsePositiveRate  float64 `json:"falsePositiveRate"`  // %
}

// ModulesOverview visão geral de cada módulo
type ModulesOverview struct {
	SOAR              SOARMetrics              `json:"soar"`
	CaseManagement    CaseManagementMetrics    `json:"caseManagement"`
	MITREAttack       MITREMetrics             `json:"mitreAttack"`
	ThreatIntel       ThreatIntelMetrics       `json:"threatIntel"`
	Notifications     NotificationsMetrics     `json:"notifications"`
}

// SOARMetrics métricas do SOAR
type SOARMetrics struct {
	TotalPlaybooks     int                    `json:"totalPlaybooks"`
	ActivePlaybooks    int                    `json:"activePlaybooks"`
	ExecutionsTotal    int                    `json:"executionsTotal"`
	ExecutionsSuccess  int                    `json:"executionsSuccess"`
	ExecutionsFailed   int                    `json:"executionsFailed"`
	SuccessRate        float64                `json:"successRate"` // %
	AvgExecutionTime   int                    `json:"avgExecutionTime"` // seconds
	TopPlaybooks       []PlaybookExecSummary  `json:"topPlaybooks"`
	ActionsByType      map[string]int         `json:"actionsByType"`
}

// PlaybookExecSummary resumo de execução de playbook
type PlaybookExecSummary struct {
	Name       string `json:"name"`
	Executions int    `json:"executions"`
	SuccessRate float64 `json:"successRate"`
}

// CaseManagementMetrics métricas de casos
type CaseManagementMetrics struct {
	TotalCases       int            `json:"totalCases"`
	CasesByStatus    map[string]int `json:"casesByStatus"`
	CasesBySeverity  map[string]int `json:"casesBySeverity"`
	AvgResolutionTime int           `json:"avgResolutionTime"` // hours
	SLACompliance    float64        `json:"slaCompliance"` // %
	OpenCases        int            `json:"openCases"`
	ClosedCases      int            `json:"closedCases"`
}

// MITREMetrics métricas do MITRE ATT&CK
type MITREMetrics struct {
	TotalTactics       int            `json:"totalTactics"`
	TotalTechniques    int            `json:"totalTechniques"`
	CoveragePercent    float64        `json:"coveragePercent"`
	DetectedTechniques int            `json:"detectedTechniques"`
	TopTactics         []TacticCount  `json:"topTactics"`
	GapAnalysis        []string       `json:"gapAnalysis"` // técnicas sem cobertura
}

// TacticCount contagem por tática
type TacticCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// ThreatIntelMetrics métricas de threat intelligence
type ThreatIntelMetrics struct {
	TotalIOCs          int            `json:"totalIOCs"`
	ActiveIOCs         int            `json:"activeIOCs"`
	IOCsBySeverity     map[string]int `json:"iocsBySeverity"`
	TopThreats         []ThreatCount  `json:"topThreats"`
	EventsEnriched     int            `json:"eventsEnriched"`
	EnrichmentRate     float64        `json:"enrichmentRate"` // %
	MaliciousIPsBlocked int           `json:"maliciousIPsBlocked"`
}

// ThreatCount contagem de ameaças
type ThreatCount struct {
	Threat   string `json:"threat"`
	Count    int    `json:"count"`
	Severity string `json:"severity"`
}

// NotificationsMetrics métricas de notificações
type NotificationsMetrics struct {
	TotalSent         int            `json:"totalSent"`
	SuccessfulSent    int            `json:"successfulSent"`
	FailedSent        int            `json:"failedSent"`
	SuccessRate       float64        `json:"successRate"` // %
	ByChannel         map[string]int `json:"byChannel"`
	BySeverity        map[string]int `json:"bySeverity"`
	AvgDeliveryTime   int            `json:"avgDeliveryTime"` // seconds
}

// TrendsData dados de tendências temporais
type TrendsData struct {
	Events        []TimeSeriesPoint `json:"events"`
	Alerts        []TimeSeriesPoint `json:"alerts"`
	Cases         []TimeSeriesPoint `json:"cases"`
	Playbooks     []TimeSeriesPoint `json:"playbooks"`
	IOCs          []TimeSeriesPoint `json:"iocs"`
}

// TimeSeriesPoint ponto em série temporal
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     int       `json:"value"`
}

// TopInsights principais insights
type TopInsights struct {
	TopEvents      []EventInsight    `json:"topEvents"`
	TopAlerts      []AlertInsight    `json:"topAlerts"`
	TopThreats     []ThreatInsight   `json:"topThreats"`
	TopUsers       []UserInsight     `json:"topUsers"`
	TopSources     []SourceInsight   `json:"topSources"`
}

// EventInsight insight de evento
type EventInsight struct {
	Type        string `json:"type"`
	Count       int    `json:"count"`
	Severity    string `json:"severity"`
	TrendChange int    `json:"trendChange"` // % change
}

// AlertInsight insight de alerta
type AlertInsight struct {
	Name        string `json:"name"`
	Count       int    `json:"count"`
	Severity    string `json:"severity"`
	FalsePos    int    `json:"falsePositives"`
}

// ThreatInsight insight de ameaça
type ThreatInsight struct {
	Threat      string `json:"threat"`
	Count       int    `json:"count"`
	Severity    string `json:"severity"`
	Sources     int    `json:"sources"`
}

// UserInsight insight de usuário
type UserInsight struct {
	User        string `json:"user"`
	Events      int    `json:"events"`
	Alerts      int    `json:"alerts"`
	RiskScore   int    `json:"riskScore"` // 0-100
}

// SourceInsight insight de fonte
type SourceInsight struct {
	Source      string `json:"source"`
	Events      int    `json:"events"`
	TopType     string `json:"topType"`
}

// ROIMetrics métricas de ROI
type ROIMetrics struct {
	IncidentsPrevented   int     `json:"incidentsPrevented"`
	AutomatedActions     int     `json:"automatedActions"`
	TimesSaved           int     `json:"timesSaved"` // hours
	CostSavings          float64 `json:"costSavings"` // USD
	EfficiencyGain       float64 `json:"efficiencyGain"` // %
	MeanTimeToDetect     int     `json:"meanTimeToDetect"` // minutes
	MeanTimeToRespond    int     `json:"meanTimeToRespond"` // minutes
	MeanTimeToResolve    int     `json:"meanTimeToResolve"` // minutes
	AlertFatigue         float64 `json:"alertFatigue"` // %
	AnalystProductivity  float64 `json:"analystProductivity"` // events/analyst/day
}

// ComparisonData comparação com período anterior
type ComparisonData struct {
	Events            ComparisonMetric `json:"events"`
	Alerts            ComparisonMetric `json:"alerts"`
	Cases             ComparisonMetric `json:"cases"`
	Playbooks         ComparisonMetric `json:"playbooks"`
	IOCs              ComparisonMetric `json:"iocs"`
	MTTD              ComparisonMetric `json:"mttd"`
	MTTR              ComparisonMetric `json:"mttr"`
}

// ComparisonMetric métrica de comparação
type ComparisonMetric struct {
	Current    int     `json:"current"`
	Previous   int     `json:"previous"`
	Change     int     `json:"change"`
	ChangePercent float64 `json:"changePercent"`
	Trend      string  `json:"trend"` // up, down, stable
}

// ReportRequest requisição de relatório
type ReportRequest struct {
	Period     string   `json:"period"`     // last_24h, last_7d, last_30d, custom
	StartDate  string   `json:"startDate"`  // para custom
	EndDate    string   `json:"endDate"`    // para custom
	Format     string   `json:"format"`     // pdf, excel, json
	Sections   []string `json:"sections"`   // quais seções incluir
	Recipients []string `json:"recipients"` // emails para envio
}

// ReportResponse resposta de geração de relatório
type ReportResponse struct {
	ReportID    string    `json:"reportId"`
	Status      string    `json:"status"` // generating, ready, failed
	Format      string    `json:"format"`
	DownloadURL string    `json:"downloadUrl"`
	GeneratedAt time.Time `json:"generatedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// handleGetExecutiveDashboard retorna dashboard executivo completo
func (s *APIServer) handleGetExecutiveDashboard(c *gin.Context) {
	period := c.DefaultQuery("period", "last_30d")
	
	now := time.Now()
	
	// Get real data from OpenSearch
	totalEvents := 0
	totalAlerts := 0
	criticalAlerts := 0
	
	if s.opensearch != nil {
		// Count events
		countQuery := `{"query": {"match_all": {}}}`
		res, err := s.opensearch.Count(
			s.opensearch.Count.WithIndex("siem-events"),
			s.opensearch.Count.WithBody(strings.NewReader(countQuery)),
		)
		if err == nil && !res.IsError() {
			var result map[string]interface{}
			if json.NewDecoder(res.Body).Decode(&result) == nil {
				if count, ok := result["count"].(float64); ok {
					totalEvents = int(count)
				}
			}
			res.Body.Close()
		}

		// Count alerts with severity breakdown
		alertsQuery := `{
			"size": 0,
			"track_total_hits": true,
			"aggs": {
				"by_severity": {
					"terms": { "field": "severity", "size": 10 }
				}
			}
		}`
		res, err = s.opensearch.Search(
			s.opensearch.Search.WithIndex("siem-alerts"),
			s.opensearch.Search.WithBody(strings.NewReader(alertsQuery)),
		)
		if err == nil && !res.IsError() {
			var result map[string]interface{}
			if json.NewDecoder(res.Body).Decode(&result) == nil {
				if hits, ok := result["hits"].(map[string]interface{}); ok {
					if total, ok := hits["total"].(map[string]interface{}); ok {
						totalAlerts = int(total["value"].(float64))
					}
				}
				if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
					if sevAgg, ok := aggs["by_severity"].(map[string]interface{}); ok {
						if buckets, ok := sevAgg["buckets"].([]interface{}); ok {
							for _, b := range buckets {
								bucket := b.(map[string]interface{})
								key := bucket["key"].(string)
								count := int(bucket["doc_count"].(float64))
								if key == "CRITICAL" {
									criticalAlerts = count
								}
							}
						}
					}
				}
			}
			res.Body.Close()
		}
	}

	// If no real data and mock disabled, use minimal data
	if totalEvents == 0 && !IsMockDataDisabled() {
		totalEvents = 145234
	}
	if totalAlerts == 0 && !IsMockDataDisabled() {
		totalAlerts = 2847
		criticalAlerts = 124
	}

	dashboard := ExecutiveDashboard{
		Period:      period,
		GeneratedAt: now,
		KPIs: ExecutiveKPIs{
			TotalEvents:        totalEvents,
			TotalAlerts:        totalAlerts,
			CriticalAlerts:     criticalAlerts,
			TotalCases:         86,
			OpenCases:          12,
			PlaybooksExecuted:  423,
			IOCsDetected:       int(float64(totalAlerts) * 0.87), // Estimated
			MITRECoverage:      70.5,
			AutomationRate:     68.3,
			SystemUptime:       99.97,
			MTTD:               8,  // 8 minutes
			MTTR:               45, // 45 minutes
			IncidentResolution: 94.2,
			FalsePositiveRate:  4.8,
		},
		Modules: ModulesOverview{
			SOAR: SOARMetrics{
				TotalPlaybooks:    15,
				ActivePlaybooks:   12,
				ExecutionsTotal:   423,
				ExecutionsSuccess: 398,
				ExecutionsFailed:  25,
				SuccessRate:       94.1,
				AvgExecutionTime:  23,
				TopPlaybooks: []PlaybookExecSummary{
					{Name: "Block Malicious IP", Executions: 147, SuccessRate: 98.6},
					{Name: "Phishing Response", Executions: 89, SuccessRate: 94.4},
					{Name: "Malware Containment", Executions: 67, SuccessRate: 91.0},
				},
				ActionsByType: map[string]int{
					"block_ip":       147,
					"send_email":     234,
					"create_ticket":  189,
					"isolate_host":   67,
					"slack_notify":   198,
				},
			},
			CaseManagement: CaseManagementMetrics{
				TotalCases:        86,
				CasesByStatus: map[string]int{
					"open":        12,
					"investigating": 8,
					"resolved":     62,
					"closed":       4,
				},
				CasesBySeverity: map[string]int{
					"critical": 8,
					"high":     24,
					"medium":   38,
					"low":      16,
				},
				AvgResolutionTime: 18, // 18 hours
				SLACompliance:     96.5,
				OpenCases:         12,
				ClosedCases:       74,
			},
			MITREAttack: MITREMetrics{
				TotalTactics:       14,
				TotalTechniques:    180,
				CoveragePercent:    70.5,
				DetectedTechniques: 127,
				TopTactics: []TacticCount{
					{Name: "Initial Access", Count: 234},
					{Name: "Execution", Count: 189},
					{Name: "Persistence", Count: 156},
					{Name: "Command and Control", Count: 142},
					{Name: "Exfiltration", Count: 98},
				},
				GapAnalysis: []string{
					"T1055 - Process Injection",
					"T1134 - Access Token Manipulation",
					"T1207 - Rogue Domain Controller",
				},
			},
			ThreatIntel: ThreatIntelMetrics{
				TotalIOCs:      2626,
				ActiveIOCs:     2489,
				IOCsBySeverity: map[string]int{
					"critical": 247,
					"high":     834,
					"medium":   1123,
					"low":      422,
				},
				TopThreats: []ThreatCount{
					{Threat: "botnet", Count: 547, Severity: "critical"},
					{Threat: "phishing", Count: 423, Severity: "high"},
					{Threat: "malware", Count: 389, Severity: "critical"},
					{Threat: "c2", Count: 234, Severity: "critical"},
					{Threat: "scanning", Count: 189, Severity: "medium"},
				},
				EventsEnriched:      15234,
				EnrichmentRate:      84.7,
				MaliciousIPsBlocked: 342,
			},
			Notifications: NotificationsMetrics{
				TotalSent:      1847,
				SuccessfulSent: 1789,
				FailedSent:     58,
				SuccessRate:    96.9,
				ByChannel: map[string]int{
					"slack": 847,
					"email": 623,
					"teams": 289,
					"webhook": 88,
				},
				BySeverity: map[string]int{
					"critical": 234,
					"high":     589,
					"medium":   768,
					"low":      256,
				},
				AvgDeliveryTime: 3, // 3 seconds
			},
		},
		Trends: generateTrendsData(period),
		TopInsights: TopInsights{
			TopEvents: []EventInsight{
				{Type: "authentication", Count: 45234, Severity: "info", TrendChange: 12},
				{Type: "network_traffic", Count: 38921, Severity: "info", TrendChange: -5},
				{Type: "file_access", Count: 28456, Severity: "info", TrendChange: 8},
			},
			TopAlerts: []AlertInsight{
				{Name: "Brute Force Attempt", Count: 234, Severity: "high", FalsePos: 12},
				{Name: "Malware Detected", Count: 189, Severity: "critical", FalsePos: 5},
				{Name: "Data Exfiltration", Count: 87, Severity: "critical", FalsePos: 3},
			},
			TopThreats: []ThreatInsight{
				{Threat: "Mirai Botnet", Count: 147, Severity: "critical", Sources: 3},
				{Threat: "Emotet Malware", Count: 89, Severity: "critical", Sources: 2},
				{Threat: "Phishing Campaign", Count: 67, Severity: "high", Sources: 5},
			},
			TopUsers: []UserInsight{
				{User: "admin@company.com", Events: 2847, Alerts: 12, RiskScore: 45},
				{User: "john.doe@company.com", Events: 1923, Alerts: 8, RiskScore: 32},
				{User: "jane.smith@company.com", Events: 1456, Alerts: 5, RiskScore: 28},
			},
			TopSources: []SourceInsight{
				{Source: "AWS CloudTrail", Events: 52341, TopType: "api_call"},
				{Source: "VPC Flow Logs", Events: 38921, TopType: "network"},
				{Source: "GuardDuty", Events: 2847, TopType: "threat"},
			},
		},
		ROI: ROIMetrics{
			IncidentsPrevented:   147,
			AutomatedActions:     423,
			TimesSaved:           1247, // hours
			CostSavings:          187500.00,
			EfficiencyGain:       68.3,
			MeanTimeToDetect:     8,
			MeanTimeToRespond:    45,
			MeanTimeToResolve:    180,
			AlertFatigue:         12.4,
			AnalystProductivity:  156.8,
		},
		Comparison: ComparisonData{
			Events:    ComparisonMetric{Current: 145234, Previous: 129876, Change: 15358, ChangePercent: 11.8, Trend: "up"},
			Alerts:    ComparisonMetric{Current: 2847, Previous: 3124, Change: -277, ChangePercent: -8.9, Trend: "down"},
			Cases:     ComparisonMetric{Current: 86, Previous: 94, Change: -8, ChangePercent: -8.5, Trend: "down"},
			Playbooks: ComparisonMetric{Current: 423, Previous: 356, Change: 67, ChangePercent: 18.8, Trend: "up"},
			IOCs:      ComparisonMetric{Current: 2489, Previous: 2231, Change: 258, ChangePercent: 11.6, Trend: "up"},
			MTTD:      ComparisonMetric{Current: 8, Previous: 12, Change: -4, ChangePercent: -33.3, Trend: "down"},
			MTTR:      ComparisonMetric{Current: 45, Previous: 58, Change: -13, ChangePercent: -22.4, Trend: "down"},
		},
	}

	c.JSON(http.StatusOK, dashboard)
}

// handleGetKPIs retorna apenas KPIs
func (s *APIServer) handleGetKPIs(c *gin.Context) {
	kpis := ExecutiveKPIs{
		TotalEvents:        145234,
		TotalAlerts:        2847,
		CriticalAlerts:     124,
		TotalCases:         86,
		OpenCases:          12,
		PlaybooksExecuted:  423,
		IOCsDetected:       2489,
		MITRECoverage:      70.5,
		AutomationRate:     68.3,
		SystemUptime:       99.97,
		MTTD:               8,
		MTTR:               45,
		IncidentResolution: 94.2,
		FalsePositiveRate:  4.8,
	}

	c.JSON(http.StatusOK, kpis)
}

// handleGenerateReport gera relatório executivo
func (s *APIServer) handleGenerateExecutiveReport(c *gin.Context) {
	var req ReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleGenerateExecutiveReport bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Mock - em produção, gerar relatório real
	now := time.Now()
	reportID := "report-" + now.Format("20060102150405")
	
	response := ReportResponse{
		ReportID:    reportID,
		Status:      "ready",
		Format:      req.Format,
		DownloadURL: "/api/v1/executive/reports/" + reportID + "/download",
		GeneratedAt: now,
		ExpiresAt:   now.Add(7 * 24 * time.Hour),
	}

	c.JSON(http.StatusOK, response)
}

// handleGetTrends retorna apenas dados de tendências
func (s *APIServer) handleGetTrends(c *gin.Context) {
	period := c.DefaultQuery("period", "last_30d")
	trends := generateTrendsData(period)
	c.JSON(http.StatusOK, trends)
}

// generateTrendsData gera dados de tendências (mock)
func generateTrendsData(period string) TrendsData {
	now := time.Now()
	points := 30 // 30 dias
	
	if period == "last_7d" {
		points = 7
	} else if period == "last_24h" {
		points = 24
	}

	events := make([]TimeSeriesPoint, points)
	alerts := make([]TimeSeriesPoint, points)
	cases := make([]TimeSeriesPoint, points)
	playbooks := make([]TimeSeriesPoint, points)
	iocs := make([]TimeSeriesPoint, points)

	for i := 0; i < points; i++ {
		timestamp := now.Add(-time.Duration(points-i) * 24 * time.Hour)
		events[i] = TimeSeriesPoint{Timestamp: timestamp, Value: 4500 + i*50}
		alerts[i] = TimeSeriesPoint{Timestamp: timestamp, Value: 90 + i*2}
		cases[i] = TimeSeriesPoint{Timestamp: timestamp, Value: 2 + i/10}
		playbooks[i] = TimeSeriesPoint{Timestamp: timestamp, Value: 12 + i/5}
		iocs[i] = TimeSeriesPoint{Timestamp: timestamp, Value: 80 + i*3}
	}

	return TrendsData{
		Events:    events,
		Alerts:    alerts,
		Cases:     cases,
		Playbooks: playbooks,
		IOCs:      iocs,
	}
}


