package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// TriageResult represents the result of alert triage
type TriageResult struct {
	ID                string                 `json:"id"`
	AlertID           string                 `json:"alert_id"`
	Timestamp         time.Time              `json:"timestamp"`
	SeverityScore     float64                `json:"severity_score"`      // 0-100
	ConfidenceScore   float64                `json:"confidence_score"`    // 0-100
	ImpactScore       float64                `json:"impact_score"`        // 0-100
	UrgencyScore      float64                `json:"urgency_score"`       // 0-100
	PriorityScore     float64                `json:"priority_score"`      // Calculated from above
	FalsePositiveProb float64                `json:"false_positive_prob"` // 0-1
	Classification    string                 `json:"classification"`      // critical, high, medium, low, info
	AssignedTo        string                 `json:"assigned_to"`
	AssignmentReason  string                 `json:"assignment_reason"`
	Enrichment        EnrichmentData         `json:"enrichment"`
	Correlation       CorrelationData        `json:"correlation"`
	Suggestions       []ActionSuggestion     `json:"suggestions"`
	Status            string                 `json:"status"` // pending, in_progress, resolved, false_positive
	Metadata          map[string]interface{} `json:"metadata"`
}

// EnrichmentData contains contextual information about the alert
type EnrichmentData struct {
	AssetCriticality  string                 `json:"asset_criticality"` // critical, high, medium, low
	AssetOwner        string                 `json:"asset_owner"`
	AssetLocation     string                 `json:"asset_location"`
	UserRiskScore     float64                `json:"user_risk_score"`
	UserDepartment    string                 `json:"user_department"`
	UserTitle         string                 `json:"user_title"`
	ThreatIntel       ThreatIntelData        `json:"threat_intel"`
	HistoricalPattern HistoricalPatternData  `json:"historical_pattern"`
	BusinessContext   map[string]interface{} `json:"business_context"`
}

// ThreatIntelData contains threat intelligence information
type ThreatIntelData struct {
	IsMalicious     bool     `json:"is_malicious"`
	ThreatType      string   `json:"threat_type"`
	ThreatFamily    string   `json:"threat_family"`
	Reputation      int      `json:"reputation"` // 0-100
	Sources         []string `json:"sources"`
	FirstSeen       string   `json:"first_seen"`
	LastSeen        string   `json:"last_seen"`
	RelatedCampaign string   `json:"related_campaign"`
}

// HistoricalPatternData contains historical behavior information
type HistoricalPatternData struct {
	SimilarAlertsCount    int     `json:"similar_alerts_count"`
	FalsePositiveRate     float64 `json:"false_positive_rate"`
	AverageResolutionTime int     `json:"average_resolution_time"` // minutes
	CommonResolution      string  `json:"common_resolution"`
	IsRecurring           bool    `json:"is_recurring"`
	RecurrencePattern     string  `json:"recurrence_pattern"`
}

// CorrelationData contains information about related alerts
type CorrelationData struct {
	CorrelationID     string   `json:"correlation_id"`
	RelatedAlertIDs   []string `json:"related_alert_ids"`
	CorrelationType   string   `json:"correlation_type"`  // same_source, same_target, kill_chain, campaign
	CorrelationScore  float64  `json:"correlation_score"` // 0-1
	AttackPhase       string   `json:"attack_phase"`      // reconnaissance, weaponization, delivery, exploitation, installation, c2, actions
	CampaignIndicator string   `json:"campaign_indicator"`
}

// ActionSuggestion suggests next steps for the analyst
type ActionSuggestion struct {
	ID          string  `json:"id"`
	Action      string  `json:"action"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"` // 0-1
	Priority    int     `json:"priority"`
	Playbook    string  `json:"playbook"`
	Automated   bool    `json:"automated"`
}

// TriageRule defines rules for alert triage
type TriageRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Conditions  []TriageCondition      `json:"conditions"`
	Actions     []TriageAction         `json:"actions"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TriageCondition defines conditions for triage rules
type TriageCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// TriageAction defines actions to take when rule matches
type TriageAction struct {
	Type       string                 `json:"type"` // set_severity, assign, enrich, correlate, suggest
	Parameters map[string]interface{} `json:"parameters"`
}

// AnalystProfile contains analyst information for auto-assignment
type AnalystProfile struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Email           string   `json:"email"`
	Skills          []string `json:"skills"`
	Specializations []string `json:"specializations"`
	CurrentLoad     int      `json:"current_load"`
	MaxLoad         int      `json:"max_load"`
	Availability    string   `json:"availability"` // available, busy, offline
	ShiftStart      string   `json:"shift_start"`
	ShiftEnd        string   `json:"shift_end"`
}

// TriageStats provides statistics about alert triage
type TriageStats struct {
	TotalAlerts            int                    `json:"total_alerts"`
	TriagedAlerts          int                    `json:"triaged_alerts"`
	PendingAlerts          int                    `json:"pending_alerts"`
	FalsePositives         int                    `json:"false_positives"`
	AverageTriageTime      float64                `json:"average_triage_time"` // seconds
	AlertsByClassification map[string]int         `json:"alerts_by_classification"`
	AlertsByStatus         map[string]int         `json:"alerts_by_status"`
	TopCorrelations        []CorrelationSummary   `json:"top_correlations"`
	AnalystWorkload        []AnalystWorkloadStat  `json:"analyst_workload"`
	TimeSeriesData         []TriageTimeSeriesData `json:"time_series_data"`
}

// CorrelationSummary summarizes correlated alerts
type CorrelationSummary struct {
	CorrelationID   string `json:"correlation_id"`
	AlertCount      int    `json:"alert_count"`
	CorrelationType string `json:"correlation_type"`
	Severity        string `json:"severity"`
}

// AnalystWorkloadStat tracks analyst workload
type AnalystWorkloadStat struct {
	AnalystID   string  `json:"analyst_id"`
	AnalystName string  `json:"analyst_name"`
	Assigned    int     `json:"assigned"`
	InProgress  int     `json:"in_progress"`
	Resolved    int     `json:"resolved"`
	LoadPercent float64 `json:"load_percent"`
}

// TriageTimeSeriesData for charts
type TriageTimeSeriesData struct {
	Timestamp      time.Time `json:"timestamp"`
	TriagedAlerts  int       `json:"triaged_alerts"`
	FalsePositives int       `json:"false_positives"`
	AvgScore       float64   `json:"avg_score"`
}

// ============================================================================
// IN-MEMORY STORAGE
// ============================================================================

var (
	triageResults   = make(map[string]*TriageResult)
	triageRules     = make(map[string]*TriageRule)
	analystProfiles = make(map[string]*AnalystProfile)
	triageMutex     sync.RWMutex
)

// ============================================================================
// INITIALIZATION
// ============================================================================

func initAlertTriageSystem() {
	triageMutex.Lock()
	defer triageMutex.Unlock()

	// Sample analyst profiles
	analyst1 := &AnalystProfile{
		ID:              "analyst-001",
		Name:            "Alice Johnson",
		Email:           "alice@company.com",
		Skills:          []string{"malware_analysis", "network_forensics", "threat_hunting"},
		Specializations: []string{"ransomware", "apt", "phishing"},
		CurrentLoad:     5,
		MaxLoad:         10,
		Availability:    "available",
		ShiftStart:      "08:00",
		ShiftEnd:        "17:00",
	}
	analystProfiles[analyst1.ID] = analyst1

	analyst2 := &AnalystProfile{
		ID:              "analyst-002",
		Name:            "Bob Smith",
		Email:           "bob@company.com",
		Skills:          []string{"incident_response", "forensics", "malware_analysis"},
		Specializations: []string{"web_attacks", "sql_injection", "xss"},
		CurrentLoad:     3,
		MaxLoad:         10,
		Availability:    "available",
		ShiftStart:      "08:00",
		ShiftEnd:        "17:00",
	}
	analystProfiles[analyst2.ID] = analyst2

	analyst3 := &AnalystProfile{
		ID:              "analyst-003",
		Name:            "Carol Davis",
		Email:           "carol@company.com",
		Skills:          []string{"threat_intelligence", "correlation", "hunting"},
		Specializations: []string{"apt", "nation_state", "supply_chain"},
		CurrentLoad:     8,
		MaxLoad:         10,
		Availability:    "busy",
		ShiftStart:      "08:00",
		ShiftEnd:        "17:00",
	}
	analystProfiles[analyst3.ID] = analyst3

	// Sample triage rules
	rule1 := &TriageRule{
		ID:          "rule-001",
		Name:        "Critical Asset Priority",
		Description: "Prioritize alerts from critical assets",
		Enabled:     true,
		Priority:    1,
		Conditions: []TriageCondition{
			{Field: "asset_criticality", Operator: "equals", Value: "critical"},
		},
		Actions: []TriageAction{
			{Type: "set_severity", Parameters: map[string]interface{}{"severity_boost": 20}},
			{Type: "assign", Parameters: map[string]interface{}{"skill": "critical_infrastructure"}},
		},
		CreatedAt: time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-5 * 24 * time.Hour),
		Metadata:  map[string]interface{}{"version": "1.0"},
	}
	triageRules[rule1.ID] = rule1

	rule2 := &TriageRule{
		ID:          "rule-002",
		Name:        "Known False Positive Pattern",
		Description: "Auto-classify known false positive patterns",
		Enabled:     true,
		Priority:    2,
		Conditions: []TriageCondition{
			{Field: "false_positive_rate", Operator: "greater_than", Value: 0.8},
			{Field: "similar_alerts_count", Operator: "greater_than", Value: 10},
		},
		Actions: []TriageAction{
			{Type: "set_severity", Parameters: map[string]interface{}{"classification": "false_positive"}},
		},
		CreatedAt: time.Now().Add(-20 * 24 * time.Hour),
		UpdatedAt: time.Now().Add(-2 * 24 * time.Hour),
		Metadata:  map[string]interface{}{"version": "1.1"},
	}
	triageRules[rule2.ID] = rule2

	// Sample triage results
	now := time.Now()

	result1 := &TriageResult{
		ID:                "triage-001",
		AlertID:           "alert-12345",
		Timestamp:         now.Add(-10 * time.Minute),
		SeverityScore:     85.5,
		ConfidenceScore:   92.0,
		ImpactScore:       88.0,
		UrgencyScore:      90.0,
		PriorityScore:     88.9,
		FalsePositiveProb: 0.05,
		Classification:    "critical",
		AssignedTo:        "analyst-001",
		AssignmentReason:  "Matched specialization: ransomware",
		Status:            "in_progress",
		Enrichment: EnrichmentData{
			AssetCriticality: "critical",
			AssetOwner:       "IT Department",
			AssetLocation:    "Data Center 1",
			UserRiskScore:    75.0,
			UserDepartment:   "Finance",
			UserTitle:        "CFO",
			ThreatIntel: ThreatIntelData{
				IsMalicious:     true,
				ThreatType:      "ransomware",
				ThreatFamily:    "Conti",
				Reputation:      95,
				Sources:         []string{"VirusTotal", "AlienVault", "ThreatConnect"},
				FirstSeen:       "2024-01-15",
				LastSeen:        "2025-11-10",
				RelatedCampaign: "Conti-2025-Q4",
			},
			HistoricalPattern: HistoricalPatternData{
				SimilarAlertsCount:    3,
				FalsePositiveRate:     0.1,
				AverageResolutionTime: 45,
				CommonResolution:      "isolate_host",
				IsRecurring:           false,
			},
			BusinessContext: map[string]interface{}{
				"business_unit":       "Corporate",
				"data_classification": "confidential",
			},
		},
		Correlation: CorrelationData{
			CorrelationID:     "corr-001",
			RelatedAlertIDs:   []string{"alert-12346", "alert-12347"},
			CorrelationType:   "kill_chain",
			CorrelationScore:  0.85,
			AttackPhase:       "exploitation",
			CampaignIndicator: "Conti-2025-Q4",
		},
		Suggestions: []ActionSuggestion{
			{
				ID:          "sug-001",
				Action:      "isolate_host",
				Description: "Isolate the compromised host immediately",
				Confidence:  0.95,
				Priority:    1,
				Playbook:    "ransomware_response",
				Automated:   true,
			},
			{
				ID:          "sug-002",
				Action:      "collect_forensics",
				Description: "Collect memory dump and disk image",
				Confidence:  0.90,
				Priority:    2,
				Playbook:    "forensics_collection",
				Automated:   false,
			},
		},
		Metadata: map[string]interface{}{"source": "edr"},
	}
	triageResults[result1.ID] = result1

	result2 := &TriageResult{
		ID:                "triage-002",
		AlertID:           "alert-67890",
		Timestamp:         now.Add(-5 * time.Minute),
		SeverityScore:     45.0,
		ConfidenceScore:   60.0,
		ImpactScore:       40.0,
		UrgencyScore:      50.0,
		PriorityScore:     48.8,
		FalsePositiveProb: 0.75,
		Classification:    "low",
		AssignedTo:        "analyst-002",
		AssignmentReason:  "Load balancing",
		Status:            "pending",
		Enrichment: EnrichmentData{
			AssetCriticality: "low",
			AssetOwner:       "Marketing",
			AssetLocation:    "Office Floor 3",
			UserRiskScore:    25.0,
			UserDepartment:   "Marketing",
			UserTitle:        "Marketing Coordinator",
			ThreatIntel: ThreatIntelData{
				IsMalicious: false,
				Reputation:  30,
				Sources:     []string{"VirusTotal"},
			},
			HistoricalPattern: HistoricalPatternData{
				SimilarAlertsCount:    25,
				FalsePositiveRate:     0.85,
				AverageResolutionTime: 5,
				CommonResolution:      "whitelist",
				IsRecurring:           true,
				RecurrencePattern:     "daily",
			},
		},
		Correlation: CorrelationData{
			CorrelationType:  "none",
			CorrelationScore: 0.0,
		},
		Suggestions: []ActionSuggestion{
			{
				ID:          "sug-003",
				Action:      "whitelist",
				Description: "Add to whitelist - likely false positive",
				Confidence:  0.85,
				Priority:    1,
				Automated:   true,
			},
		},
		Metadata: map[string]interface{}{"source": "ids"},
	}
	triageResults[result2.ID] = result2
}

// ============================================================================
// ML SCORING ENGINE
// ============================================================================

func calculateMLScores(alert map[string]interface{}) (severity, confidence, impact, urgency float64) {
	// Simplified ML scoring (in production, use actual ML models)

	// Severity score based on alert type and indicators
	severity = 50.0
	if alertType, ok := alert["type"].(string); ok {
		switch alertType {
		case "ransomware", "data_exfiltration":
			severity = 90.0
		case "malware", "c2_communication":
			severity = 75.0
		case "suspicious_activity":
			severity = 50.0
		case "policy_violation":
			severity = 30.0
		}
	}

	// Confidence score based on detection method and correlation
	confidence = 70.0
	if detectionMethod, ok := alert["detection_method"].(string); ok {
		switch detectionMethod {
		case "signature":
			confidence = 95.0
		case "behavioral":
			confidence = 75.0
		case "anomaly":
			confidence = 60.0
		case "heuristic":
			confidence = 50.0
		}
	}

	// Impact score based on asset and data criticality
	impact = 50.0
	if assetCriticality, ok := alert["asset_criticality"].(string); ok {
		switch assetCriticality {
		case "critical":
			impact = 95.0
		case "high":
			impact = 75.0
		case "medium":
			impact = 50.0
		case "low":
			impact = 25.0
		}
	}

	// Urgency score based on active exploitation and spread
	urgency = 50.0
	if isActive, ok := alert["is_active"].(bool); ok && isActive {
		urgency += 30.0
	}
	if isSpreading, ok := alert["is_spreading"].(bool); ok && isSpreading {
		urgency += 20.0
	}

	return severity, confidence, impact, urgency
}

func calculatePriorityScore(severity, confidence, impact, urgency float64) float64 {
	// Weighted average
	return (severity*0.3 + confidence*0.2 + impact*0.3 + urgency*0.2)
}

func classifyAlert(priorityScore float64) string {
	switch {
	case priorityScore >= 80:
		return "critical"
	case priorityScore >= 60:
		return "high"
	case priorityScore >= 40:
		return "medium"
	case priorityScore >= 20:
		return "low"
	default:
		return "info"
	}
}

func calculateFalsePositiveProb(historicalFPRate float64, confidence float64) float64 {
	// Combine historical FP rate with current confidence
	return math.Max(0, math.Min(1, historicalFPRate*(1-confidence/100)))
}

// ============================================================================
// AUTO-ASSIGNMENT ENGINE
// ============================================================================

func autoAssignAlert(alert map[string]interface{}, classification string) (string, string) {
	triageMutex.RLock()
	defer triageMutex.RUnlock()

	var bestAnalyst *AnalystProfile
	var reason string
	bestScore := -1.0

	alertType := ""
	if at, ok := alert["type"].(string); ok {
		alertType = at
	}

	for _, analyst := range analystProfiles {
		if analyst.Availability != "available" {
			continue
		}

		if analyst.CurrentLoad >= analyst.MaxLoad {
			continue
		}

		score := 0.0

		// Skill matching
		for _, skill := range analyst.Skills {
			if skill == alertType {
				score += 50.0
				reason = fmt.Sprintf("Matched skill: %s", skill)
			}
		}

		// Specialization matching
		for _, spec := range analyst.Specializations {
			if spec == alertType {
				score += 30.0
				reason = fmt.Sprintf("Matched specialization: %s", spec)
			}
		}

		// Load balancing
		loadFactor := float64(analyst.MaxLoad-analyst.CurrentLoad) / float64(analyst.MaxLoad)
		score += loadFactor * 20.0

		if score > bestScore {
			bestScore = score
			bestAnalyst = analyst
		}
	}

	if bestAnalyst != nil {
		if reason == "" {
			reason = "Load balancing"
		}
		return bestAnalyst.ID, reason
	}

	return "", "No available analyst"
}

// ============================================================================
// API HANDLERS
// ============================================================================

// Triage an alert
func (s *APIServer) handleTriageAlert(c *gin.Context) {
	var req struct {
		AlertID string                 `json:"alert_id"`
		Alert   map[string]interface{} `json:"alert"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleTriageAlert bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	// Calculate ML scores
	severity, confidence, impact, urgency := calculateMLScores(req.Alert)
	priorityScore := calculatePriorityScore(severity, confidence, impact, urgency)
	classification := classifyAlert(priorityScore)

	// Calculate false positive probability
	historicalFPRate := 0.1 // Default
	if hfp, ok := req.Alert["historical_fp_rate"].(float64); ok {
		historicalFPRate = hfp
	}
	fpProb := calculateFalsePositiveProb(historicalFPRate, confidence)

	// Auto-assign
	assignedTo, assignmentReason := autoAssignAlert(req.Alert, classification)

	// Create triage result
	result := &TriageResult{
		ID:                generateID(),
		AlertID:           req.AlertID,
		Timestamp:         time.Now(),
		SeverityScore:     severity,
		ConfidenceScore:   confidence,
		ImpactScore:       impact,
		UrgencyScore:      urgency,
		PriorityScore:     priorityScore,
		FalsePositiveProb: fpProb,
		Classification:    classification,
		AssignedTo:        assignedTo,
		AssignmentReason:  assignmentReason,
		Status:            "pending",
		Enrichment:        EnrichmentData{},     // Would be populated by enrichment engine
		Correlation:       CorrelationData{},    // Would be populated by correlation engine
		Suggestions:       []ActionSuggestion{}, // Would be populated by suggestion engine
		Metadata:          req.Alert,
	}

	triageMutex.Lock()
	triageResults[result.ID] = result

	// Update analyst load
	if assignedTo != "" {
		if analyst, exists := analystProfiles[assignedTo]; exists {
			analyst.CurrentLoad++
		}
	}
	triageMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    result,
		"message": "Alert triaged successfully",
	})
}

// List triage results
func (s *APIServer) handleListTriageResults(c *gin.Context) {
	triageMutex.RLock()
	defer triageMutex.RUnlock()

	status := c.Query("status")
	classification := c.Query("classification")
	assignedTo := c.Query("assigned_to")

	results := make([]*TriageResult, 0)
	for _, result := range triageResults {
		if status != "" && result.Status != status {
			continue
		}
		if classification != "" && result.Classification != classification {
			continue
		}
		if assignedTo != "" && result.AssignedTo != assignedTo {
			continue
		}
		results = append(results, result)
	}

	// Sort by priority score (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].PriorityScore > results[j].PriorityScore
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    results,
		"total":   len(results),
	})
}

// Get triage result
func (s *APIServer) handleGetTriageResult(c *gin.Context) {
	id := c.Param("id")

	triageMutex.RLock()
	result, exists := triageResults[id]
	triageMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Triage result not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

// Update triage result
func (s *APIServer) handleUpdateTriageResult(c *gin.Context) {
	id := c.Param("id")

	triageMutex.Lock()
	defer triageMutex.Unlock()

	result, exists := triageResults[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Triage result not found",
		})
		return
	}

	var updates struct {
		Status         string `json:"status"`
		AssignedTo     string `json:"assigned_to"`
		Classification string `json:"classification"`
		FalsePositive  bool   `json:"false_positive"`
	}

	if err := c.ShouldBindJSON(&updates); err != nil {
		log.Printf("[ERROR] handleUpdateTriageResult bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	if updates.Status != "" {
		result.Status = updates.Status
	}
	if updates.AssignedTo != "" {
		// Update analyst load
		if result.AssignedTo != "" && result.AssignedTo != updates.AssignedTo {
			if oldAnalyst, exists := analystProfiles[result.AssignedTo]; exists {
				oldAnalyst.CurrentLoad--
			}
		}
		if newAnalyst, exists := analystProfiles[updates.AssignedTo]; exists {
			newAnalyst.CurrentLoad++
		}
		result.AssignedTo = updates.AssignedTo
	}
	if updates.Classification != "" {
		result.Classification = updates.Classification
	}
	if updates.FalsePositive {
		result.Status = "false_positive"
		result.FalsePositiveProb = 1.0
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
		"message": "Triage result updated successfully",
	})
}

// Get triage statistics
func (s *APIServer) handleGetTriageStats(c *gin.Context) {
	triageMutex.RLock()
	defer triageMutex.RUnlock()

	stats := TriageStats{
		TotalAlerts:            len(triageResults),
		AlertsByClassification: make(map[string]int),
		AlertsByStatus:         make(map[string]int),
		TopCorrelations:        make([]CorrelationSummary, 0),
		AnalystWorkload:        make([]AnalystWorkloadStat, 0),
		TimeSeriesData:         make([]TriageTimeSeriesData, 0),
	}

	var totalTriageTime float64
	correlations := make(map[string]*CorrelationSummary)

	for _, result := range triageResults {
		if result.Status != "pending" {
			stats.TriagedAlerts++
		} else {
			stats.PendingAlerts++
		}

		if result.Status == "false_positive" {
			stats.FalsePositives++
		}

		stats.AlertsByClassification[result.Classification]++
		stats.AlertsByStatus[result.Status]++

		totalTriageTime += float64(time.Since(result.Timestamp).Seconds())

		// Track correlations
		if result.Correlation.CorrelationID != "" {
			if corr, exists := correlations[result.Correlation.CorrelationID]; exists {
				corr.AlertCount++
			} else {
				correlations[result.Correlation.CorrelationID] = &CorrelationSummary{
					CorrelationID:   result.Correlation.CorrelationID,
					AlertCount:      1,
					CorrelationType: result.Correlation.CorrelationType,
					Severity:        result.Classification,
				}
			}
		}
	}

	if stats.TriagedAlerts > 0 {
		stats.AverageTriageTime = totalTriageTime / float64(stats.TriagedAlerts)
	}

	// Top correlations
	for _, corr := range correlations {
		stats.TopCorrelations = append(stats.TopCorrelations, *corr)
	}
	sort.Slice(stats.TopCorrelations, func(i, j int) bool {
		return stats.TopCorrelations[i].AlertCount > stats.TopCorrelations[j].AlertCount
	})
	if len(stats.TopCorrelations) > 10 {
		stats.TopCorrelations = stats.TopCorrelations[:10]
	}

	// Analyst workload
	for _, analyst := range analystProfiles {
		assigned := 0
		inProgress := 0
		resolved := 0

		for _, result := range triageResults {
			if result.AssignedTo == analyst.ID {
				assigned++
				if result.Status == "in_progress" {
					inProgress++
				} else if result.Status == "resolved" {
					resolved++
				}
			}
		}

		loadPercent := float64(analyst.CurrentLoad) / float64(analyst.MaxLoad) * 100

		stats.AnalystWorkload = append(stats.AnalystWorkload, AnalystWorkloadStat{
			AnalystID:   analyst.ID,
			AnalystName: analyst.Name,
			Assigned:    assigned,
			InProgress:  inProgress,
			Resolved:    resolved,
			LoadPercent: loadPercent,
		})
	}

	// Time series data (last 24 hours)
	now := time.Now()
	for i := 23; i >= 0; i-- {
		timestamp := now.Add(-time.Duration(i) * time.Hour)
		dataPoint := TriageTimeSeriesData{
			Timestamp: timestamp,
		}

		var totalScore float64
		count := 0

		for _, result := range triageResults {
			if result.Timestamp.After(timestamp) && result.Timestamp.Before(timestamp.Add(time.Hour)) {
				dataPoint.TriagedAlerts++
				if result.Status == "false_positive" {
					dataPoint.FalsePositives++
				}
				totalScore += result.PriorityScore
				count++
			}
		}

		if count > 0 {
			dataPoint.AvgScore = totalScore / float64(count)
		}

		stats.TimeSeriesData = append(stats.TimeSeriesData, dataPoint)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}

// List triage rules
func (s *APIServer) handleListTriageRules(c *gin.Context) {
	triageMutex.RLock()
	defer triageMutex.RUnlock()

	enabled := c.Query("enabled")

	rules := make([]*TriageRule, 0)
	for _, rule := range triageRules {
		if enabled != "" {
			if (enabled == "true" && !rule.Enabled) || (enabled == "false" && rule.Enabled) {
				continue
			}
		}
		rules = append(rules, rule)
	}

	// Sort by priority
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    rules,
		"total":   len(rules),
	})
}

// Create triage rule
func (s *APIServer) handleCreateTriageRule(c *gin.Context) {
	var rule TriageRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		log.Printf("[ERROR] handleCreateTriageRule bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	rule.ID = generateID()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	triageMutex.Lock()
	triageRules[rule.ID] = &rule
	triageMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    rule,
		"message": "Triage rule created successfully",
	})
}

// Update triage rule
func (s *APIServer) handleUpdateTriageRule(c *gin.Context) {
	id := c.Param("id")

	triageMutex.Lock()
	defer triageMutex.Unlock()

	rule, exists := triageRules[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Triage rule not found",
		})
		return
	}

	var updates TriageRule
	if err := c.ShouldBindJSON(&updates); err != nil {
		log.Printf("[ERROR] handleUpdateTriageRule bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	rule.Name = updates.Name
	rule.Description = updates.Description
	rule.Enabled = updates.Enabled
	rule.Priority = updates.Priority
	rule.Conditions = updates.Conditions
	rule.Actions = updates.Actions
	rule.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    rule,
		"message": "Triage rule updated successfully",
	})
}

// Delete triage rule
func (s *APIServer) handleDeleteTriageRule(c *gin.Context) {
	id := c.Param("id")

	triageMutex.Lock()
	defer triageMutex.Unlock()

	if _, exists := triageRules[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Triage rule not found",
		})
		return
	}

	delete(triageRules, id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Triage rule deleted successfully",
	})
}

// List analyst profiles - fetches real users from database
func (s *APIServer) handleListAnalystProfiles(c *gin.Context) {
	// Try to fetch real users from database
	if s.authRepo != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		users, err := s.authRepo.ListUsers(ctx)
		if err == nil && len(users) > 0 {
			profiles := make([]*AnalystProfile, 0)

			for _, user := range users {
				// Only include active users
				if !user.IsActive {
					continue
				}

				// Determine availability based on user status
				availability := "available"

				// Use skills from database if available, otherwise use role defaults
				skills := user.Skills
				specializations := user.Specializations
				roleName := user.RoleName

				// If no skills defined, use role-based defaults
				if len(skills) == 0 {
					switch roleName {
					case "admin":
						skills = []string{"incident_response", "threat_hunting", "forensics", "management"}
					case "analyst":
						skills = []string{"alert_analysis", "incident_response", "log_analysis"}
					case "banking":
						skills = []string{"alert_analysis", "compliance"}
					default:
						skills = []string{"alert_analysis", "monitoring"}
					}
				}

				// If no specializations defined, use role-based defaults
				if len(specializations) == 0 {
					switch roleName {
					case "admin":
						specializations = []string{"security_operations", "compliance", "audit"}
					case "analyst":
						specializations = []string{"siem", "monitoring"}
					case "banking":
						specializations = []string{"pci_dss", "financial_security"}
					default:
						specializations = []string{"general"}
					}
				}

				// Calculate current load from assigned alerts (simplified)
				currentLoad := 0
				maxLoad := 10
				if roleName == "admin" {
					maxLoad = 20
				}

				// Get full name or use username as fallback
				fullName := user.Username
				if user.FullName != nil && *user.FullName != "" {
					fullName = *user.FullName
				}

				profile := &AnalystProfile{
					ID:              fmt.Sprintf("user-%s", user.ID),
					Name:            fullName,
					Email:           user.Email,
					Skills:          skills,
					Specializations: specializations,
					CurrentLoad:     currentLoad,
					MaxLoad:         maxLoad,
					Availability:    availability,
					ShiftStart:      "08:00",
					ShiftEnd:        "18:00",
				}

				profiles = append(profiles, profile)
			}

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"data":    profiles,
				"total":   len(profiles),
			})
			return
		}
	}

	// Fallback to mock data if database is not available
	triageMutex.RLock()
	defer triageMutex.RUnlock()

	availability := c.Query("availability")

	profiles := make([]*AnalystProfile, 0)
	for _, profile := range analystProfiles {
		if availability != "" && profile.Availability != availability {
			continue
		}
		profiles = append(profiles, profile)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    profiles,
		"total":   len(profiles),
	})
}

// Update analyst profile
func (s *APIServer) handleUpdateAnalystProfile(c *gin.Context) {
	id := c.Param("id")

	triageMutex.Lock()
	defer triageMutex.Unlock()

	profile, exists := analystProfiles[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Analyst profile not found",
		})
		return
	}

	var updates AnalystProfile
	if err := c.ShouldBindJSON(&updates); err != nil {
		log.Printf("[ERROR] handleUpdateAnalystProfile bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	if updates.Availability != "" {
		profile.Availability = updates.Availability
	}
	if updates.MaxLoad > 0 {
		profile.MaxLoad = updates.MaxLoad
	}
	if len(updates.Skills) > 0 {
		profile.Skills = updates.Skills
	}
	if len(updates.Specializations) > 0 {
		profile.Specializations = updates.Specializations
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    profile,
		"message": "Analyst profile updated successfully",
	})
}

// Mark as false positive
func (s *APIServer) handleMarkFalsePositive(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Reason   string `json:"reason"`
		Feedback string `json:"feedback"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleMarkFalsePositive bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	triageMutex.Lock()
	defer triageMutex.Unlock()

	result, exists := triageResults[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Triage result not found",
		})
		return
	}

	result.Status = "false_positive"
	result.FalsePositiveProb = 1.0
	result.Metadata["fp_reason"] = req.Reason
	result.Metadata["fp_feedback"] = req.Feedback

	// In production, this would update the ML model with feedback

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
		"message": "Marked as false positive successfully",
	})
}
