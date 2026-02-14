package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// IncidentResponse represents an automated incident
type IncidentResponse struct {
	ID                string                 `json:"id"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	Severity          string                 `json:"severity"`
	Status            string                 `json:"status"`
	AlertID           string                 `json:"alert_id"`
	CaseID            string                 `json:"case_id,omitempty"`
	AutoCreated       bool                   `json:"auto_created"`
	AutoEscalated     bool                   `json:"auto_escalated"`
	AssignedTo        string                 `json:"assigned_to"`
	AssignmentMethod  string                 `json:"assignment_method"` // auto, manual
	PlaybookTriggered string                 `json:"playbook_triggered,omitempty"`
	PlaybookStatus    string                 `json:"playbook_status,omitempty"`
	MLPriority        int                    `json:"ml_priority"`
	MLConfidence      float64                `json:"ml_confidence"`
	SimilarIncidents  []string               `json:"similar_incidents,omitempty"`
	Evidence          []IREvidence           `json:"evidence,omitempty"`
	Timeline          []IRTimelineEvent      `json:"timeline"`
	SLA               SLAInfo                `json:"sla"`
	Metrics           IncidentMetrics        `json:"metrics"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	ResolvedAt        *time.Time             `json:"resolved_at,omitempty"`
}

// IREvidence represents collected evidence
type IREvidence struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // log, network, file, memory
	Source      string    `json:"source"`
	Description string    `json:"description"`
	Data        string    `json:"data"`
	CollectedAt time.Time `json:"collected_at"`
}

// IRTimelineEvent represents an event in incident timeline
type IRTimelineEvent struct {
	ID          string    `json:"id"`
	Action      string    `json:"action"`
	Actor       string    `json:"actor"` // user, system, automation
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// SLAInfo represents SLA information
type SLAInfo struct {
	ResponseTime   time.Duration `json:"response_time"`
	ResolutionTime time.Duration `json:"resolution_time"`
	ResponseDue    time.Time     `json:"response_due"`
	ResolutionDue  time.Time     `json:"resolution_due"`
	ResponseMet    bool          `json:"response_met"`
	ResolutionMet  bool          `json:"resolution_met"`
	Breached       bool          `json:"breached"`
}

// IncidentMetrics represents incident metrics
type IncidentMetrics struct {
	MTTA time.Duration `json:"mtta"` // Mean Time To Acknowledge
	MTTD time.Duration `json:"mttd"` // Mean Time To Detect
	MTTR time.Duration `json:"mttr"` // Mean Time To Respond
	MTTC time.Duration `json:"mttc"` // Mean Time To Contain
	MTTR2 time.Duration `json:"mttr2"` // Mean Time To Resolve
}

// AutomationRule represents an automation rule
type AutomationRule struct {
	ID               string            `json:"id"`
	Name             string              `json:"name"`
	Description      string              `json:"description"`
	Enabled          bool                `json:"enabled"`
	Priority         int                 `json:"priority"`
	Conditions       []IRRuleCondition   `json:"conditions"`
	Actions          []IRRuleAction      `json:"actions"`
	CreatedAt        time.Time           `json:"created_at"`
	UpdatedAt        time.Time           `json:"updated_at"`
	ExecutionCount   int                 `json:"execution_count"`
	LastExecutedAt   *time.Time          `json:"last_executed_at,omitempty"`
}

// IRRuleCondition represents a condition for automation
type IRRuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // equals, contains, greater_than, etc
	Value    interface{} `json:"value"`
}

// IRRuleAction represents an action to execute
type IRRuleAction struct {
	Type       string                 `json:"type"` // create_incident, escalate, assign, trigger_playbook, collect_evidence
	Parameters map[string]interface{} `json:"parameters"`
}

// EscalationRule represents an escalation rule
type EscalationRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Severity    string        `json:"severity"`
	Condition   string        `json:"condition"` // time_based, event_count, ml_score
	Threshold   interface{}   `json:"threshold"`
	Action      string        `json:"action"` // escalate_severity, notify_manager, trigger_playbook
	Enabled     bool          `json:"enabled"`
	CreatedAt   time.Time     `json:"created_at"`
}

// AssignmentRule represents an assignment rule
type AssignmentRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    []string `json:"severity"`
	Category    []string `json:"category"`
	Skills      []string `json:"skills_required"`
	AssignTo    string   `json:"assign_to"` // user_id or team_id
	Priority    int      `json:"priority"`
	Enabled     bool     `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// IncidentResponseDashboard represents dashboard data
type IncidentResponseDashboard struct {
	TotalIncidents      int                    `json:"total_incidents"`
	ActiveIncidents     int                    `json:"active_incidents"`
	ResolvedToday       int                    `json:"resolved_today"`
	AutoCreated         int                    `json:"auto_created"`
	AutoAssigned        int                    `json:"auto_assigned"`
	PlaybooksTriggered  int                    `json:"playbooks_triggered"`
	AverageMTTR         string                 `json:"average_mttr"`
	AverageMTTA         string                 `json:"average_mtta"`
	SLACompliance       float64                `json:"sla_compliance"`
	IncidentsBySeverity map[string]int         `json:"incidents_by_severity"`
	IncidentsByStatus   map[string]int         `json:"incidents_by_status"`
	TopAssignees        []AssigneeStats        `json:"top_assignees"`
	RecentIncidents     []IncidentResponse     `json:"recent_incidents"`
	Automation          AutomationStats        `json:"automation"`
}

// AssigneeStats represents assignee statistics
type AssigneeStats struct {
	UserID           string  `json:"user_id"`
	UserName         string  `json:"user_name"`
	AssignedCount    int     `json:"assigned_count"`
	ResolvedCount    int     `json:"resolved_count"`
	AverageMTTR      string  `json:"average_mttr"`
	SLACompliance    float64 `json:"sla_compliance"`
}

// AutomationStats represents automation statistics
type AutomationStats struct {
	TotalRules         int     `json:"total_rules"`
	ActiveRules        int     `json:"active_rules"`
	ExecutionsToday    int     `json:"executions_today"`
	SuccessRate        float64 `json:"success_rate"`
	TimesSaved         string  `json:"times_saved"`
	AutomationRate     float64 `json:"automation_rate"`
}

// handleGetIRDashboard returns incident response dashboard
func (s *APIServer) handleGetIRDashboard(c *gin.Context) {
	// Mock data - in production, query from database
	dashboard := IncidentResponseDashboard{
		TotalIncidents:     856,
		ActiveIncidents:    34,
		ResolvedToday:      12,
		AutoCreated:        745,
		AutoAssigned:       698,
		PlaybooksTriggered: 542,
		AverageMTTR:        "2h 15m",
		AverageMTTA:        "5m 30s",
		SLACompliance:      94.5,
		IncidentsBySeverity: map[string]int{
			"critical": 8,
			"high":     15,
			"medium":   45,
			"low":      788,
		},
		IncidentsByStatus: map[string]int{
			"open":        34,
			"investigating": 12,
			"contained":   8,
			"resolved":    802,
		},
		TopAssignees: []AssigneeStats{
			{UserID: "user-1", UserName: "John Doe", AssignedCount: 45, ResolvedCount: 42, AverageMTTR: "1h 45m", SLACompliance: 96.5},
			{UserID: "user-2", UserName: "Jane Smith", AssignedCount: 38, ResolvedCount: 35, AverageMTTR: "2h 10m", SLACompliance: 92.8},
			{UserID: "user-3", UserName: "Bob Johnson", AssignedCount: 32, ResolvedCount: 30, AverageMTTR: "2h 30m", SLACompliance: 89.2},
		},
		RecentIncidents: generateMockIncidents(5),
		Automation: AutomationStats{
			TotalRules:      15,
			ActiveRules:     12,
			ExecutionsToday: 45,
			SuccessRate:     97.8,
			TimesSaved:      "8h 30m",
			AutomationRate:  87.0,
		},
	}

	c.JSON(http.StatusOK, dashboard)
}

// handleGetIncidents returns list of incidents
func (s *APIServer) handleGetIncidents(c *gin.Context) {
	// Query parameters
	status := c.Query("status")
	severity := c.Query("severity")

	// Mock data
	incidents := generateMockIncidents(20)

	// Filter by status
	if status != "" {
		filtered := []IncidentResponse{}
		for _, inc := range incidents {
			if inc.Status == status {
				filtered = append(filtered, inc)
			}
		}
		incidents = filtered
	}

	// Filter by severity
	if severity != "" {
		filtered := []IncidentResponse{}
		for _, inc := range incidents {
			if inc.Severity == severity {
				filtered = append(filtered, inc)
			}
		}
		incidents = filtered
	}

	c.JSON(http.StatusOK, gin.H{
		"incidents": incidents,
		"total":     len(incidents),
	})
}

// handleGetIncident returns incident details
func (s *APIServer) handleGetIncident(c *gin.Context) {
	id := c.Param("id")

	// Mock data
	incident := generateMockIncidents(1)[0]
	incident.ID = id

	c.JSON(http.StatusOK, incident)
}

// handleCreateIncident creates a new incident
func (s *APIServer) handleCreateIncident(c *gin.Context) {
	var req struct {
		Title       string `json:"title" binding:"required"`
		Description string `json:"description" binding:"required"`
		Severity    string `json:"severity" binding:"required"`
		AlertID     string `json:"alert_id"`
		AutoTrigger bool   `json:"auto_trigger"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleCreateIncident bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Create incident
	incident := IncidentResponse{
		ID:           "inc-" + generateID(),
		Title:        req.Title,
		Description:  req.Description,
		Severity:     req.Severity,
		Status:       "open",
		AlertID:      req.AlertID,
		AutoCreated:  req.AutoTrigger,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Timeline:     []IRTimelineEvent{},
	}

	// Auto-assign if enabled
	incident = s.autoAssignIncident(incident)

	// Trigger playbook if auto-trigger enabled
	if req.AutoTrigger {
		incident = s.autoTriggerPlaybook(incident)
	}

	// Calculate ML priority
	incident.MLPriority = s.calculateMLPriority(incident)
	incident.MLConfidence = 0.85

	// Set SLA
	incident.SLA = s.calculateSLA(incident)

	c.JSON(http.StatusCreated, incident)
}

// handleUpdateIncident updates an incident
func (s *APIServer) handleUpdateIncident(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Status      string `json:"status"`
		AssignedTo  string `json:"assigned_to"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleUpdateIncident bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Mock update
	incident := generateMockIncidents(1)[0]
	incident.ID = id
	incident.UpdatedAt = time.Now()

	if req.Status != "" {
		incident.Status = req.Status
		if req.Status == "resolved" {
			now := time.Now()
			incident.ResolvedAt = &now
		}
	}

	if req.AssignedTo != "" {
		incident.AssignedTo = req.AssignedTo
	}

	c.JSON(http.StatusOK, incident)
}

// handleGetAutomationRules returns automation rules
func (s *APIServer) handleGetAutomationRules(c *gin.Context) {
	rules := []AutomationRule{
		{
			ID:          "rule-1",
			Name:        "Auto-create incident for critical alerts",
			Description: "Automatically create incident when critical alert is detected",
			Enabled:     true,
			Priority:    1,
			Conditions: []IRRuleCondition{
				{Field: "severity", Operator: "equals", Value: "critical"},
			},
			Actions: []IRRuleAction{
				{Type: "create_incident", Parameters: map[string]interface{}{"severity": "critical"}},
				{Type: "trigger_playbook", Parameters: map[string]interface{}{"playbook_id": "pb-critical"}},
			},
			CreatedAt:      time.Now().Add(-30 * 24 * time.Hour),
			UpdatedAt:      time.Now().Add(-2 * 24 * time.Hour),
			ExecutionCount: 45,
		},
		{
			ID:          "rule-2",
			Name:        "Auto-escalate stale incidents",
			Description: "Escalate incidents that haven't been updated in 4 hours",
			Enabled:     true,
			Priority:    2,
			Conditions: []IRRuleCondition{
				{Field: "age", Operator: "greater_than", Value: "4h"},
				{Field: "status", Operator: "equals", Value: "open"},
			},
			Actions: []IRRuleAction{
				{Type: "escalate", Parameters: map[string]interface{}{"notify": true}},
			},
			CreatedAt:      time.Now().Add(-25 * 24 * time.Hour),
			UpdatedAt:      time.Now().Add(-5 * 24 * time.Hour),
			ExecutionCount: 28,
		},
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

// handleCreateAutomationRule creates a new automation rule
func (s *APIServer) handleCreateAutomationRule(c *gin.Context) {
	var rule AutomationRule

	if err := c.ShouldBindJSON(&rule); err != nil {
		log.Printf("[ERROR] handleCreateAutomationRule bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	rule.ID = "rule-" + generateID()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	rule.ExecutionCount = 0

	c.JSON(http.StatusCreated, rule)
}

// handleGetEscalationRules returns escalation rules
func (s *APIServer) handleGetEscalationRules(c *gin.Context) {
	rules := []EscalationRule{
		{
			ID:        "esc-1",
			Name:      "Escalate after 2 hours",
			Severity:  "high",
			Condition: "time_based",
			Threshold: "2h",
			Action:    "escalate_severity",
			Enabled:   true,
			CreatedAt: time.Now().Add(-20 * 24 * time.Hour),
		},
		{
			ID:        "esc-2",
			Name:      "Escalate on ML high confidence",
			Severity:  "medium",
			Condition: "ml_score",
			Threshold: 0.9,
			Action:    "notify_manager",
			Enabled:   true,
			CreatedAt: time.Now().Add(-15 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

// handleGetAssignmentRules returns assignment rules
func (s *APIServer) handleGetAssignmentRules(c *gin.Context) {
	rules := []AssignmentRule{
		{
			ID:       "assign-1",
			Name:     "Critical incidents to senior team",
			Severity: []string{"critical"},
			Category: []string{"malware", "data_breach"},
			Skills:   []string{"forensics", "incident_response"},
			AssignTo: "team-senior",
			Priority: 1,
			Enabled:  true,
			CreatedAt: time.Now().Add(-30 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

// handleGetIRStats returns incident response statistics
func (s *APIServer) handleGetIRStats(c *gin.Context) {
	stats := gin.H{
		"total_incidents":        856,
		"active_incidents":       34,
		"resolved_today":         12,
		"auto_created_percent":   87.0,
		"auto_assigned_percent":  81.5,
		"average_mttr_seconds":   8100,
		"average_mtta_seconds":   330,
		"sla_compliance_percent": 94.5,
		"automation_rate":        87.0,
	}

	c.JSON(http.StatusOK, stats)
}

// Helper functions

func generateMockIncidents(count int) []IncidentResponse {
	incidents := []IncidentResponse{}
	severities := []string{"critical", "high", "medium", "low"}
	statuses := []string{"open", "investigating", "contained", "resolved"}

	for i := 0; i < count; i++ {
		incident := IncidentResponse{
			ID:                "inc-" + generateID(),
			Title:             "Security Incident " + generateID(),
			Description:       "Automated incident created from critical alert",
			Severity:          severities[i%len(severities)],
			Status:            statuses[i%len(statuses)],
			AlertID:           "alert-" + generateID(),
			AutoCreated:       true,
			AutoEscalated:     false,
			AssignedTo:        "user-" + string(rune(i%3+1)),
			AssignmentMethod:  "auto",
			PlaybookTriggered: "playbook-auto-response",
			PlaybookStatus:    "completed",
			MLPriority:        85 + (i % 15),
			MLConfidence:      0.85 + float64(i%15)/100,
			CreatedAt:         time.Now().Add(-time.Duration(i) * time.Hour),
			UpdatedAt:         time.Now().Add(-time.Duration(i/2) * time.Hour),
			Timeline:          []IRTimelineEvent{},
			Evidence:          []IREvidence{},
		}

		incident.SLA = SLAInfo{
			ResponseTime:   15 * time.Minute,
			ResolutionTime: 4 * time.Hour,
			ResponseDue:    incident.CreatedAt.Add(15 * time.Minute),
			ResolutionDue:  incident.CreatedAt.Add(4 * time.Hour),
			ResponseMet:    true,
			ResolutionMet:  false,
			Breached:       false,
		}

		incident.Metrics = IncidentMetrics{
			MTTA:  5 * time.Minute,
			MTTD:  10 * time.Minute,
			MTTR:  2 * time.Hour,
			MTTC:  1 * time.Hour,
			MTTR2: 3 * time.Hour,
		}

		incidents = append(incidents, incident)
	}

	return incidents
}

func (s *APIServer) autoAssignIncident(incident IncidentResponse) IncidentResponse {
	// Auto-assignment logic based on severity and skills
	if incident.Severity == "critical" || incident.Severity == "high" {
		incident.AssignedTo = "user-senior-1"
	} else {
		incident.AssignedTo = "user-junior-1"
	}
	incident.AssignmentMethod = "auto"
	return incident
}

func (s *APIServer) autoTriggerPlaybook(incident IncidentResponse) IncidentResponse {
	// Auto-trigger playbook based on severity
	if incident.Severity == "critical" {
		incident.PlaybookTriggered = "playbook-critical-response"
	} else if incident.Severity == "high" {
		incident.PlaybookTriggered = "playbook-high-response"
	}
	incident.PlaybookStatus = "triggered"
	return incident
}

func (s *APIServer) calculateMLPriority(incident IncidentResponse) int {
	// ML-based priority calculation
	priority := 50

	// Increase priority based on severity
	switch incident.Severity {
	case "critical":
		priority += 40
	case "high":
		priority += 30
	case "medium":
		priority += 15
	case "low":
		priority += 5
	}

	// Add randomness for demo
	priority += len(incident.Title) % 10

	if priority > 100 {
		priority = 100
	}

	return priority
}

func (s *APIServer) calculateSLA(incident IncidentResponse) SLAInfo {
	var responseTime, resolutionTime time.Duration

	// SLA times based on severity
	switch incident.Severity {
	case "critical":
		responseTime = 15 * time.Minute
		resolutionTime = 4 * time.Hour
	case "high":
		responseTime = 30 * time.Minute
		resolutionTime = 8 * time.Hour
	case "medium":
		responseTime = 2 * time.Hour
		resolutionTime = 24 * time.Hour
	case "low":
		responseTime = 4 * time.Hour
		resolutionTime = 72 * time.Hour
	}

	return SLAInfo{
		ResponseTime:   responseTime,
		ResolutionTime: resolutionTime,
		ResponseDue:    incident.CreatedAt.Add(responseTime),
		ResolutionDue:  incident.CreatedAt.Add(resolutionTime),
		ResponseMet:    false,
		ResolutionMet:  false,
		Breached:       false,
	}
}
