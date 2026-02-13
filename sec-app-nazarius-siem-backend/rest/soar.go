package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// SOARPlaybook represents an automated security playbook
type SOARPlaybook struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Category        string    `json:"category"` // incident_response, threat_hunting, compliance, remediation
	Status          string    `json:"status"` // active, draft, disabled
	TriggerType     string    `json:"trigger_type"` // manual, automatic, scheduled
	TriggerConditions []string `json:"trigger_conditions"`
	Actions         []string  `json:"actions"`
	Steps           int       `json:"steps"`
	AvgExecutionTime string   `json:"avg_execution_time"`
	SuccessRate     float64   `json:"success_rate"` // 0-100
	ExecutionCount  int       `json:"execution_count"`
	LastExecuted    *time.Time `json:"last_executed,omitempty"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Tags            []string  `json:"tags"`
}

// SOARPlaybookExecution represents a playbook execution instance
type SOARPlaybookExecution struct {
	ID              string    `json:"id"`
	PlaybookID      string    `json:"playbook_id"`
	PlaybookName    string    `json:"playbook_name"`
	Status          string    `json:"status"` // running, completed, failed, paused
	TriggerType     string    `json:"trigger_type"`
	TriggerSource   string    `json:"trigger_source"`
	StartTime       time.Time `json:"start_time"`
	EndTime         *time.Time `json:"end_time,omitempty"`
	Duration        string    `json:"duration"`
	CurrentStep     int       `json:"current_step"`
	TotalSteps      int       `json:"total_steps"`
	SuccessfulSteps int       `json:"successful_steps"`
	FailedSteps     int       `json:"failed_steps"`
	ExecutedBy      string    `json:"executed_by"`
	Results         map[string]interface{} `json:"results"`
	Logs            []string  `json:"logs"`
}

// SOARIntegration represents a SOAR integration
type SOARIntegration struct{
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"` // siem, edr, firewall, email, ticketing, threat_intel
	Status          string    `json:"status"` // connected, disconnected, error
	Vendor          string    `json:"vendor"`
	Version         string    `json:"version"`
	Capabilities    []string  `json:"capabilities"`
	ActionsAvailable int      `json:"actions_available"`
	LastSync        time.Time `json:"last_sync"`
	Health          string    `json:"health"` // healthy, degraded, unhealthy
	APIEndpoint     string    `json:"api_endpoint"`
	ConfiguredAt    time.Time `json:"configured_at"`
	UsedByPlaybooks int       `json:"used_by_playbooks"`
}

// SOARCase represents a security case
type SOARCase struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Severity        string    `json:"severity"` // critical, high, medium, low
	Status          string    `json:"status"` // open, investigating, resolved, closed
	Priority        string    `json:"priority"` // p1, p2, p3, p4
	Category        string    `json:"category"`
	AssignedTo      string    `json:"assigned_to"`
	AssignedTeam    string    `json:"assigned_team"`
	RelatedAlerts   int       `json:"related_alerts"`
	RelatedIncidents int      `json:"related_incidents"`
	PlaybooksRun    int       `json:"playbooks_run"`
	Artifacts       []string  `json:"artifacts"`
	Timeline        []string  `json:"timeline"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	SLA             string    `json:"sla"`
	SLAStatus       string    `json:"sla_status"` // on_track, at_risk, breached
}

// SOARWorkflow represents an automated workflow
type SOARWorkflow struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Type            string    `json:"type"` // enrichment, containment, notification, remediation
	Status          string    `json:"status"` // enabled, disabled
	TriggerEvent    string    `json:"trigger_event"`
	Conditions      []string  `json:"conditions"`
	Actions         []string  `json:"actions"`
	ExecutionCount  int       `json:"execution_count"`
	SuccessRate     float64   `json:"success_rate"`
	AvgDuration     string    `json:"avg_duration"`
	LastTriggered   *time.Time `json:"last_triggered,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	IntegrationsUsed []string `json:"integrations_used"`
}

// SOARDashboardMetrics represents SOAR dashboard metrics
type SOARDashboardMetrics struct {
	TotalPlaybooks      int     `json:"total_playbooks"`
	ActivePlaybooks     int     `json:"active_playbooks"`
	ExecutionsToday     int     `json:"executions_today"`
	SuccessRate         float64 `json:"success_rate"`
	AvgExecutionTime    string  `json:"avg_execution_time"`
	ActiveIntegrations  int     `json:"active_integrations"`
	OpenCases           int     `json:"open_cases"`
	AutomationRate      float64 `json:"automation_rate"`
	TimesSaved          string  `json:"times_saved"`
	MTTRReduction       float64 `json:"mttr_reduction"`
}

// Initialize SOAR
func initSOAR() {
	// Mock data will be generated on-the-fly
}

// Handler: List SOAR playbooks
func (s *APIServer) handleListSOARPlaybooks(c *gin.Context) {
	lastExec := time.Now().Add(-2 * time.Hour)
	
	playbooks := []SOARPlaybook{
		{
			ID:              "pb-001",
			Name:            "Phishing Response",
			Description:     "Automated response to phishing incidents",
			Category:        "incident_response",
			Status:          "active",
			TriggerType:     "automatic",
			TriggerConditions: []string{"alert.type == 'phishing'", "alert.severity >= 'high'"},
			Actions:         []string{"Isolate user", "Block sender", "Scan attachments", "Create ticket"},
			Steps:           8,
			AvgExecutionTime: "3m 45s",
			SuccessRate:     94.5,
			ExecutionCount:  127,
			LastExecuted:    &lastExec,
			CreatedBy:       "admin",
			CreatedAt:       time.Now().Add(-30 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-5 * 24 * time.Hour),
			Tags:            []string{"email", "phishing", "automated"},
		},
		{
			ID:              "pb-002",
			Name:            "Malware Containment",
			Description:     "Contain and remediate malware infections",
			Category:        "remediation",
			Status:          "active",
			TriggerType:     "automatic",
			TriggerConditions: []string{"alert.type == 'malware'", "edr.detection == true"},
			Actions:         []string{"Isolate host", "Kill process", "Quarantine file", "Full scan", "Notify SOC"},
			Steps:           10,
			AvgExecutionTime: "5m 12s",
			SuccessRate:     91.2,
			ExecutionCount:  89,
			LastExecuted:    &lastExec,
			CreatedBy:       "security_team",
			CreatedAt:       time.Now().Add(-45 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-10 * 24 * time.Hour),
			Tags:            []string{"malware", "edr", "containment"},
		},
		{
			ID:              "pb-003",
			Name:            "Threat Intel Enrichment",
			Description:     "Enrich alerts with threat intelligence",
			Category:        "threat_hunting",
			Status:          "active",
			TriggerType:     "automatic",
			TriggerConditions: []string{"alert.ioc_present == true"},
			Actions:         []string{"Query TI feeds", "Check reputation", "OSINT lookup", "Update context"},
			Steps:           6,
			AvgExecutionTime: "1m 30s",
			SuccessRate:     97.8,
			ExecutionCount:  342,
			LastExecuted:    &lastExec,
			CreatedBy:       "threat_intel_team",
			CreatedAt:       time.Now().Add(-60 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-2 * 24 * time.Hour),
			Tags:            []string{"threat_intel", "enrichment", "ioc"},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    playbooks,
	})
}

// Handler: List SOAR playbook executions
func (s *APIServer) handleListSOARExecutions(c *gin.Context) {
	endTime := time.Now()
	
	executions := []SOARPlaybookExecution{
		{
			ID:              "exec-001",
			PlaybookID:      "pb-001",
			PlaybookName:    "Phishing Response",
			Status:          "completed",
			TriggerType:     "automatic",
			TriggerSource:   "alert-12345",
			StartTime:       time.Now().Add(-15 * time.Minute),
			EndTime:         &endTime,
			Duration:        "3m 42s",
			CurrentStep:     8,
			TotalSteps:      8,
			SuccessfulSteps: 8,
			FailedSteps:     0,
			ExecutedBy:      "system",
			Results:         map[string]interface{}{"user_isolated": true, "sender_blocked": true, "ticket_created": "INC-9876"},
			Logs:            []string{"Started execution", "User isolated successfully", "Sender blocked", "Ticket created"},
		},
		{
			ID:              "exec-002",
			PlaybookID:      "pb-002",
			PlaybookName:    "Malware Containment",
			Status:          "running",
			TriggerType:     "manual",
			TriggerSource:   "analyst@company.com",
			StartTime:       time.Now().Add(-5 * time.Minute),
			Duration:        "5m 0s",
			CurrentStep:     6,
			TotalSteps:      10,
			SuccessfulSteps: 5,
			FailedSteps:     0,
			ExecutedBy:      "analyst@company.com",
			Results:         map[string]interface{}{"host_isolated": true, "process_killed": true},
			Logs:            []string{"Started execution", "Host isolated", "Process terminated", "Scanning in progress"},
		},
		{
			ID:              "exec-003",
			PlaybookID:      "pb-003",
			PlaybookName:    "Threat Intel Enrichment",
			Status:          "completed",
			TriggerType:     "automatic",
			TriggerSource:   "alert-12346",
			StartTime:       time.Now().Add(-10 * time.Minute),
			EndTime:         &endTime,
			Duration:        "1m 28s",
			CurrentStep:     6,
			TotalSteps:      6,
			SuccessfulSteps: 6,
			FailedSteps:     0,
			ExecutedBy:      "system",
			Results:         map[string]interface{}{"reputation": "malicious", "threat_actor": "APT28", "confidence": "high"},
			Logs:            []string{"Started execution", "Queried TI feeds", "Reputation check complete", "Context updated"},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    executions,
	})
}

// Handler: List SOAR integrations
func (s *APIServer) handleListSOARIntegrations(c *gin.Context) {
	integrations := []SOARIntegration{
		{
			ID:              "int-001",
			Name:            "CrowdStrike Falcon",
			Type:            "edr",
			Status:          "connected",
			Vendor:          "CrowdStrike",
			Version:         "6.45.0",
			Capabilities:    []string{"isolate_host", "kill_process", "get_detections", "quarantine_file"},
			ActionsAvailable: 12,
			LastSync:        time.Now().Add(-5 * time.Minute),
			Health:          "healthy",
			APIEndpoint:     "https://api.crowdstrike.com",
			ConfiguredAt:    time.Now().Add(-90 * 24 * time.Hour),
			UsedByPlaybooks: 8,
		},
		{
			ID:              "int-002",
			Name:            "Palo Alto Firewall",
			Type:            "firewall",
			Status:          "connected",
			Vendor:          "Palo Alto Networks",
			Version:         "10.2.3",
			Capabilities:    []string{"block_ip", "block_url", "create_rule", "get_logs"},
			ActionsAvailable: 8,
			LastSync:        time.Now().Add(-2 * time.Minute),
			Health:          "healthy",
			APIEndpoint:     "https://firewall.company.com",
			ConfiguredAt:    time.Now().Add(-120 * 24 * time.Hour),
			UsedByPlaybooks: 15,
		},
		{
			ID:              "int-003",
			Name:            "Microsoft Sentinel",
			Type:            "siem",
			Status:          "connected",
			Vendor:          "Microsoft",
			Version:         "2024.1",
			Capabilities:    []string{"query_logs", "create_incident", "update_incident", "get_alerts"},
			ActionsAvailable: 10,
			LastSync:        time.Now().Add(-1 * time.Minute),
			Health:          "healthy",
			APIEndpoint:     "https://sentinel.azure.com",
			ConfiguredAt:    time.Now().Add(-60 * 24 * time.Hour),
			UsedByPlaybooks: 12,
		},
		{
			ID:              "int-004",
			Name:            "ServiceNow",
			Type:            "ticketing",
			Status:          "connected",
			Vendor:          "ServiceNow",
			Version:         "Tokyo",
			Capabilities:    []string{"create_ticket", "update_ticket", "assign_ticket", "close_ticket"},
			ActionsAvailable: 6,
			LastSync:        time.Now().Add(-3 * time.Minute),
			Health:          "healthy",
			APIEndpoint:     "https://company.service-now.com",
			ConfiguredAt:    time.Now().Add(-180 * 24 * time.Hour),
			UsedByPlaybooks: 20,
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    integrations,
	})
}

// Handler: List SOAR cases
func (s *APIServer) handleListSOARCases(c *gin.Context) {
	cases := []SOARCase{
		{
			ID:              "case-001",
			Title:           "Ransomware Attack Investigation",
			Description:     "Multiple hosts infected with ransomware variant",
			Severity:        "critical",
			Status:          "investigating",
			Priority:        "p1",
			Category:        "malware",
			AssignedTo:      "john.doe@company.com",
			AssignedTeam:    "Incident Response",
			RelatedAlerts:   15,
			RelatedIncidents: 3,
			PlaybooksRun:    5,
			Artifacts:       []string{"malware.exe", "ransom_note.txt", "network_traffic.pcap"},
			Timeline:        []string{"2024-11-11 10:00 - Case created", "2024-11-11 10:15 - Playbook executed", "2024-11-11 10:30 - Hosts isolated"},
			CreatedAt:       time.Now().Add(-4 * time.Hour),
			UpdatedAt:       time.Now().Add(-30 * time.Minute),
			SLA:             "4 hours",
			SLAStatus:       "on_track",
		},
		{
			ID:              "case-002",
			Title:           "Data Exfiltration Attempt",
			Description:     "Suspicious data transfer to external IP",
			Severity:        "high",
			Status:          "open",
			Priority:        "p2",
			Category:        "data_loss",
			AssignedTo:      "jane.smith@company.com",
			AssignedTeam:    "SOC",
			RelatedAlerts:   8,
			RelatedIncidents: 1,
			PlaybooksRun:    2,
			Artifacts:       []string{"network_logs.csv", "user_activity.json"},
			Timeline:        []string{"2024-11-11 12:00 - Case created", "2024-11-11 12:10 - Initial triage"},
			CreatedAt:       time.Now().Add(-2 * time.Hour),
			UpdatedAt:       time.Now().Add(-15 * time.Minute),
			SLA:             "8 hours",
			SLAStatus:       "on_track",
		},
		{
			ID:              "case-003",
			Title:           "Phishing Campaign",
			Description:     "Widespread phishing emails targeting employees",
			Severity:        "medium",
			Status:          "resolved",
			Priority:        "p3",
			Category:        "phishing",
			AssignedTo:      "security-team@company.com",
			AssignedTeam:    "Email Security",
			RelatedAlerts:   45,
			RelatedIncidents: 0,
			PlaybooksRun:    12,
			Artifacts:       []string{"phishing_email.eml", "sender_analysis.pdf"},
			Timeline:        []string{"2024-11-10 14:00 - Case created", "2024-11-10 14:30 - Playbooks executed", "2024-11-10 16:00 - All users protected"},
			CreatedAt:       time.Now().Add(-24 * time.Hour),
			UpdatedAt:       time.Now().Add(-20 * time.Hour),
			ResolvedAt:      func() *time.Time { t := time.Now().Add(-20 * time.Hour); return &t }(),
			SLA:             "24 hours",
			SLAStatus:       "on_track",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    cases,
	})
}

// Handler: List SOAR workflows
func (s *APIServer) handleListSOARWorkflows(c *gin.Context) {
	lastTriggered := time.Now().Add(-1 * time.Hour)
	
	workflows := []SOARWorkflow{
		{
			ID:              "wf-001",
			Name:            "Auto-Enrich High Severity Alerts",
			Description:     "Automatically enrich all high severity alerts with threat intelligence",
			Type:            "enrichment",
			Status:          "enabled",
			TriggerEvent:    "alert.created",
			Conditions:      []string{"severity >= 'high'"},
			Actions:         []string{"Query threat intel", "Add context", "Update alert"},
			ExecutionCount:  1247,
			SuccessRate:     98.5,
			AvgDuration:     "45s",
			LastTriggered:   &lastTriggered,
			CreatedAt:       time.Now().Add(-60 * 24 * time.Hour),
			IntegrationsUsed: []string{"ThreatConnect", "VirusTotal"},
		},
		{
			ID:              "wf-002",
			Name:            "Auto-Isolate Malware Hosts",
			Description:     "Automatically isolate hosts with confirmed malware",
			Type:            "containment",
			Status:          "enabled",
			TriggerEvent:    "edr.malware_detected",
			Conditions:      []string{"confidence >= 90", "severity == 'critical'"},
			Actions:         []string{"Isolate host", "Create case", "Notify team"},
			ExecutionCount:  89,
			SuccessRate:     95.5,
			AvgDuration:     "2m 15s",
			LastTriggered:   &lastTriggered,
			CreatedAt:       time.Now().Add(-45 * 24 * time.Hour),
			IntegrationsUsed: []string{"CrowdStrike", "ServiceNow", "Slack"},
		},
		{
			ID:              "wf-003",
			Name:            "Notify on Critical Incidents",
			Description:     "Send notifications for all critical incidents",
			Type:            "notification",
			Status:          "enabled",
			TriggerEvent:    "incident.created",
			Conditions:      []string{"severity == 'critical'"},
			Actions:         []string{"Send email", "Send Slack message", "Create PagerDuty alert"},
			ExecutionCount:  34,
			SuccessRate:     100.0,
			AvgDuration:     "10s",
			LastTriggered:   &lastTriggered,
			CreatedAt:       time.Now().Add(-90 * 24 * time.Hour),
			IntegrationsUsed: []string{"Email", "Slack", "PagerDuty"},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    workflows,
	})
}

// Handler: Get SOAR metrics
func (s *APIServer) handleGetSOARMetrics(c *gin.Context) {
	metrics := SOARDashboardMetrics{
		TotalPlaybooks:     45,
		ActivePlaybooks:    38,
		ExecutionsToday:    127,
		SuccessRate:        94.5,
		AvgExecutionTime:   "3m 15s",
		ActiveIntegrations: 12,
		OpenCases:          23,
		AutomationRate:     78.5,
		TimesSaved:         "156 hours/month",
		MTTRReduction:      65.0,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    metrics,
	})
}

