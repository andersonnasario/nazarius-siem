package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================================
// ALERT CORRELATION ENGINE
// ============================================================================
// This engine correlates related alerts into incidents, reducing alert fatigue
// and providing better context for security analysts.
//
// Correlation strategies:
// 1. Time-based: Alerts within a time window
// 2. Entity-based: Same source IP, user, or target
// 3. Attack pattern: MITRE ATT&CK kill chain progression
// 4. Signature-based: Same vulnerability or attack type

// CorrelatedIncident represents a group of related alerts
type CorrelatedIncident struct {
	ID              string                   `json:"id"`
	Title           string                   `json:"title"`
	Description     string                   `json:"description"`
	Severity        string                   `json:"severity"` // critical, high, medium, low
	Status          string                   `json:"status"`   // open, investigating, resolved, closed
	Priority        int                      `json:"priority"` // 1-5
	AlertCount      int                      `json:"alert_count"`
	Alerts          []CorrelatedAlert        `json:"alerts"`
	Entities        IncidentEntities         `json:"entities"`
	Timeline        []IncidentTimelineEvent          `json:"timeline"`
	MITREMapping    []MITRETechniqueRef      `json:"mitre_mapping"`
	CorrelationRule string                   `json:"correlation_rule"`
	CorrelationScore float64                 `json:"correlation_score"` // 0-100
	FirstSeen       time.Time                `json:"first_seen"`
	LastSeen        time.Time                `json:"last_seen"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
	AssignedTo      string                   `json:"assigned_to,omitempty"`
	Tags            []string                 `json:"tags"`
	Recommendations []string                 `json:"recommendations"`
	RelatedCaseID   string                   `json:"related_case_id,omitempty"`
}

// CorrelatedAlert represents an alert within a correlated incident
type CorrelatedAlert struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	SourceIP    string                 `json:"source_ip,omitempty"`
	DestIP      string                 `json:"dest_ip,omitempty"`
	User        string                 `json:"user,omitempty"`
	EventType   string                 `json:"event_type"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// IncidentEntities contains all entities involved in the incident
type IncidentEntities struct {
	SourceIPs     []string `json:"source_ips"`
	DestIPs       []string `json:"dest_ips"`
	Users         []string `json:"users"`
	Hosts         []string `json:"hosts"`
	Domains       []string `json:"domains"`
	Accounts      []string `json:"accounts"`
	Resources     []string `json:"resources"`
}

// IncidentTimelineEvent represents an event in the incident timeline
type IncidentTimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Description string    `json:"description"`
	AlertID     string    `json:"alert_id,omitempty"`
	Severity    string    `json:"severity"`
}

// MITRETechniqueRef represents a MITRE technique reference
type MITRETechniqueRef struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	TacticID      string `json:"tactic_id"`
	TacticName    string `json:"tactic_name"`
	AlertCount    int    `json:"alert_count"`
}

// CorrelationRule defines how alerts should be correlated
type CorrelationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	TimeWindow  int                    `json:"time_window_minutes"`
	Conditions  []CorrelationCondition `json:"conditions"`
	MinAlerts   int                    `json:"min_alerts"`
	Tags        []string               `json:"tags"`
}

// CorrelationCondition defines a matching condition
type CorrelationCondition struct {
	Field    string `json:"field"`    // source_ip, user, event_type, etc.
	Operator string `json:"operator"` // equals, contains, in, regex
	Value    string `json:"value"`
}

// AlertCorrelationEngine is the main correlation engine
type AlertCorrelationEngine struct {
	mu              sync.RWMutex
	server          *APIServer
	rules           map[string]*CorrelationRule
	activeIncidents map[string]*CorrelatedIncident
	alertBuffer     []*CorrelatedAlert
	bufferMutex     sync.Mutex
}

var (
	correlationEngine     *AlertCorrelationEngine
	correlationEngineOnce sync.Once
)

// GetCorrelationEngine returns the singleton correlation engine
func GetCorrelationEngine(server *APIServer) *AlertCorrelationEngine {
	correlationEngineOnce.Do(func() {
		correlationEngine = &AlertCorrelationEngine{
			server:          server,
			rules:           make(map[string]*CorrelationRule),
			activeIncidents: make(map[string]*CorrelatedIncident),
			alertBuffer:     make([]*CorrelatedAlert, 0),
		}
		correlationEngine.loadDefaultRules()
	})
	return correlationEngine
}

// loadDefaultRules loads default correlation rules
func (ace *AlertCorrelationEngine) loadDefaultRules() {
	defaultRules := []*CorrelationRule{
		{
			ID:          "brute-force-attack",
			Name:        "Brute Force Attack Detection",
			Description: "Correlates multiple failed login attempts from the same source",
			Enabled:     true,
			Priority:    1,
			TimeWindow:  15,
			MinAlerts:   5,
			Conditions: []CorrelationCondition{
				{Field: "event_type", Operator: "contains", Value: "failed_login"},
				{Field: "source_ip", Operator: "equals", Value: "*SAME*"},
			},
			Tags: []string{"authentication", "brute-force"},
		},
		{
			ID:          "lateral-movement",
			Name:        "Lateral Movement Detection",
			Description: "Detects potential lateral movement across multiple hosts",
			Enabled:     true,
			Priority:    1,
			TimeWindow:  30,
			MinAlerts:   3,
			Conditions: []CorrelationCondition{
				{Field: "user", Operator: "equals", Value: "*SAME*"},
				{Field: "dest_ip", Operator: "equals", Value: "*DIFFERENT*"},
			},
			Tags: []string{"lateral-movement", "T1021"},
		},
		{
			ID:          "data-exfiltration",
			Name:        "Data Exfiltration Pattern",
			Description: "Detects potential data exfiltration patterns",
			Enabled:     true,
			Priority:    1,
			TimeWindow:  60,
			MinAlerts:   3,
			Conditions: []CorrelationCondition{
				{Field: "event_type", Operator: "in", Value: "s3:GetObject,s3:ListBucket,DynamoDB:Scan"},
				{Field: "user", Operator: "equals", Value: "*SAME*"},
			},
			Tags: []string{"data-exfiltration", "T1567"},
		},
		{
			ID:          "privilege-escalation",
			Name:        "Privilege Escalation Chain",
			Description: "Detects privilege escalation attempts",
			Enabled:     true,
			Priority:    1,
			TimeWindow:  30,
			MinAlerts:   2,
			Conditions: []CorrelationCondition{
				{Field: "event_type", Operator: "in", Value: "iam:CreateRole,iam:AttachRolePolicy,iam:PutRolePolicy,sts:AssumeRole"},
				{Field: "user", Operator: "equals", Value: "*SAME*"},
			},
			Tags: []string{"privilege-escalation", "T1078"},
		},
		{
			ID:          "kill-chain-progression",
			Name:        "Attack Kill Chain Progression",
			Description: "Detects progression through attack kill chain phases",
			Enabled:     true,
			Priority:    1,
			TimeWindow:  120,
			MinAlerts:   4,
			Conditions: []CorrelationCondition{
				{Field: "source_ip", Operator: "equals", Value: "*SAME*"},
			},
			Tags: []string{"kill-chain", "apt"},
		},
		{
			ID:          "reconnaissance-activity",
			Name:        "Reconnaissance Activity",
			Description: "Detects reconnaissance and enumeration activities",
			Enabled:     true,
			Priority:    2,
			TimeWindow:  30,
			MinAlerts:   5,
			Conditions: []CorrelationCondition{
				{Field: "event_type", Operator: "in", Value: "Describe,List,Get"},
				{Field: "user", Operator: "equals", Value: "*SAME*"},
			},
			Tags: []string{"reconnaissance", "T1087"},
		},
	}

	for _, rule := range defaultRules {
		ace.rules[rule.ID] = rule
	}

	log.Printf("✅ Loaded %d default correlation rules", len(ace.rules))
}

// ProcessAlert processes a new alert and checks for correlations
func (ace *AlertCorrelationEngine) ProcessAlert(alert *CorrelatedAlert) (*CorrelatedIncident, bool) {
	ace.mu.Lock()
	defer ace.mu.Unlock()

	// Add to buffer
	ace.bufferMutex.Lock()
	ace.alertBuffer = append(ace.alertBuffer, alert)
	// Keep only last 1000 alerts in buffer
	if len(ace.alertBuffer) > 1000 {
		ace.alertBuffer = ace.alertBuffer[len(ace.alertBuffer)-1000:]
	}
	ace.bufferMutex.Unlock()

	// Check if alert matches any existing incident
	for _, incident := range ace.activeIncidents {
		if ace.alertMatchesIncident(alert, incident) {
			ace.addAlertToIncident(alert, incident)
			return incident, true
		}
	}

	// Check if we can create a new incident based on correlation rules
	for _, rule := range ace.rules {
		if !rule.Enabled {
			continue
		}

		correlatedAlerts := ace.findCorrelatedAlerts(alert, rule)
		if len(correlatedAlerts) >= rule.MinAlerts {
			incident := ace.createIncidentFromAlerts(correlatedAlerts, rule)
			ace.activeIncidents[incident.ID] = incident
			return incident, true
		}
	}

	return nil, false
}

// findCorrelatedAlerts finds alerts that correlate with the given alert based on a rule
func (ace *AlertCorrelationEngine) findCorrelatedAlerts(alert *CorrelatedAlert, rule *CorrelationRule) []*CorrelatedAlert {
	ace.bufferMutex.Lock()
	defer ace.bufferMutex.Unlock()

	timeThreshold := time.Now().Add(-time.Duration(rule.TimeWindow) * time.Minute)
	var correlated []*CorrelatedAlert

	for _, bufferedAlert := range ace.alertBuffer {
		// Skip if too old
		if bufferedAlert.Timestamp.Before(timeThreshold) {
			continue
		}

		// Check all conditions
		if ace.matchesConditions(alert, bufferedAlert, rule.Conditions) {
			correlated = append(correlated, bufferedAlert)
		}
	}

	return correlated
}

// matchesConditions checks if two alerts match the correlation conditions
func (ace *AlertCorrelationEngine) matchesConditions(alert1, alert2 *CorrelatedAlert, conditions []CorrelationCondition) bool {
	for _, condition := range conditions {
		val1 := ace.getFieldValue(alert1, condition.Field)
		val2 := ace.getFieldValue(alert2, condition.Field)

		switch condition.Operator {
		case "equals":
			if condition.Value == "*SAME*" {
				if val1 != val2 || val1 == "" {
					return false
				}
			} else if condition.Value == "*DIFFERENT*" {
				if val1 == val2 {
					return false
				}
			} else if val1 != condition.Value && val2 != condition.Value {
				return false
			}
		case "contains":
			if !strings.Contains(val1, condition.Value) && !strings.Contains(val2, condition.Value) {
				return false
			}
		case "in":
			values := strings.Split(condition.Value, ",")
			found1, found2 := false, false
			for _, v := range values {
				v = strings.TrimSpace(v)
				if strings.Contains(val1, v) {
					found1 = true
				}
				if strings.Contains(val2, v) {
					found2 = true
				}
			}
			if !found1 && !found2 {
				return false
			}
		}
	}
	return true
}

// getFieldValue extracts a field value from an alert
func (ace *AlertCorrelationEngine) getFieldValue(alert *CorrelatedAlert, field string) string {
	switch field {
	case "source_ip":
		return alert.SourceIP
	case "dest_ip":
		return alert.DestIP
	case "user":
		return alert.User
	case "event_type":
		return alert.EventType
	case "source":
		return alert.Source
	case "severity":
		return alert.Severity
	default:
		if alert.Details != nil {
			if val, ok := alert.Details[field]; ok {
				return fmt.Sprintf("%v", val)
			}
		}
		return ""
	}
}

// alertMatchesIncident checks if an alert should be added to an existing incident
func (ace *AlertCorrelationEngine) alertMatchesIncident(alert *CorrelatedAlert, incident *CorrelatedIncident) bool {
	// Check if within time window (default 2 hours)
	if alert.Timestamp.Sub(incident.LastSeen) > 2*time.Hour {
		return false
	}

	// Check entity overlap
	if alert.SourceIP != "" && containsStr(incident.Entities.SourceIPs, alert.SourceIP) {
		return true
	}
	if alert.User != "" && containsStr(incident.Entities.Users, alert.User) {
		return true
	}
	if alert.DestIP != "" && containsStr(incident.Entities.DestIPs, alert.DestIP) {
		return true
	}

	return false
}

// addAlertToIncident adds an alert to an existing incident
func (ace *AlertCorrelationEngine) addAlertToIncident(alert *CorrelatedAlert, incident *CorrelatedIncident) {
	incident.Alerts = append(incident.Alerts, *alert)
	incident.AlertCount++
	incident.LastSeen = alert.Timestamp
	incident.UpdatedAt = time.Now()

	// Update entities
	if alert.SourceIP != "" && !containsStr(incident.Entities.SourceIPs, alert.SourceIP) {
		incident.Entities.SourceIPs = append(incident.Entities.SourceIPs, alert.SourceIP)
	}
	if alert.DestIP != "" && !containsStr(incident.Entities.DestIPs, alert.DestIP) {
		incident.Entities.DestIPs = append(incident.Entities.DestIPs, alert.DestIP)
	}
	if alert.User != "" && !containsStr(incident.Entities.Users, alert.User) {
		incident.Entities.Users = append(incident.Entities.Users, alert.User)
	}

	// Add to timeline
	incident.Timeline = append(incident.Timeline, IncidentTimelineEvent{
		Timestamp:   alert.Timestamp,
		EventType:   alert.EventType,
		Description: alert.Title,
		AlertID:     alert.ID,
		Severity:    alert.Severity,
	})

	// Update severity if needed
	incident.Severity = ace.calculateIncidentSeverity(incident.Alerts)

	// Update correlation score
	incident.CorrelationScore = ace.calculateCorrelationScore(incident)

	log.Printf("📎 [Correlation] Added alert %s to incident %s (now %d alerts)", alert.ID, incident.ID, incident.AlertCount)
}

// createIncidentFromAlerts creates a new incident from correlated alerts
func (ace *AlertCorrelationEngine) createIncidentFromAlerts(alerts []*CorrelatedAlert, rule *CorrelationRule) *CorrelatedIncident {
	now := time.Now()
	
	incident := &CorrelatedIncident{
		ID:              uuid.New().String(),
		Title:           ace.generateIncidentTitle(alerts, rule),
		Description:     ace.generateIncidentDescription(alerts, rule),
		Status:          "open",
		Priority:        rule.Priority,
		AlertCount:      len(alerts),
		Alerts:          make([]CorrelatedAlert, 0),
		CorrelationRule: rule.Name,
		CreatedAt:       now,
		UpdatedAt:       now,
		Tags:            rule.Tags,
		Entities: IncidentEntities{
			SourceIPs: []string{},
			DestIPs:   []string{},
			Users:     []string{},
			Hosts:     []string{},
			Domains:   []string{},
			Accounts:  []string{},
			Resources: []string{},
		},
		Timeline:        []IncidentTimelineEvent{},
		MITREMapping:    []MITRETechniqueRef{},
		Recommendations: []string{},
	}

	// Process each alert
	firstSeen := now
	lastSeen := time.Time{}

	for _, alert := range alerts {
		incident.Alerts = append(incident.Alerts, *alert)
		
		if alert.Timestamp.Before(firstSeen) {
			firstSeen = alert.Timestamp
		}
		if alert.Timestamp.After(lastSeen) {
			lastSeen = alert.Timestamp
		}

		// Collect entities
		if alert.SourceIP != "" && !containsStr(incident.Entities.SourceIPs, alert.SourceIP) {
			incident.Entities.SourceIPs = append(incident.Entities.SourceIPs, alert.SourceIP)
		}
		if alert.DestIP != "" && !containsStr(incident.Entities.DestIPs, alert.DestIP) {
			incident.Entities.DestIPs = append(incident.Entities.DestIPs, alert.DestIP)
		}
		if alert.User != "" && !containsStr(incident.Entities.Users, alert.User) {
			incident.Entities.Users = append(incident.Entities.Users, alert.User)
		}

		// Build timeline
		incident.Timeline = append(incident.Timeline, IncidentTimelineEvent{
			Timestamp:   alert.Timestamp,
			EventType:   alert.EventType,
			Description: alert.Title,
			AlertID:     alert.ID,
			Severity:    alert.Severity,
		})
	}

	incident.FirstSeen = firstSeen
	incident.LastSeen = lastSeen
	incident.Severity = ace.calculateIncidentSeverity(incident.Alerts)
	incident.CorrelationScore = ace.calculateCorrelationScore(incident)
	incident.Recommendations = ace.generateRecommendations(incident, rule)
	incident.MITREMapping = ace.extractMITRETechniques(incident.Alerts)

	// Sort timeline by timestamp
	sort.Slice(incident.Timeline, func(i, j int) bool {
		return incident.Timeline[i].Timestamp.Before(incident.Timeline[j].Timestamp)
	})

	log.Printf("🆕 [Correlation] Created incident %s with %d alerts (Rule: %s)", incident.ID, incident.AlertCount, rule.Name)
	return incident
}

// calculateIncidentSeverity calculates the overall severity of an incident
func (ace *AlertCorrelationEngine) calculateIncidentSeverity(alerts []CorrelatedAlert) string {
	severityScore := 0
	for _, alert := range alerts {
		switch strings.ToLower(alert.Severity) {
		case "critical":
			severityScore += 4
		case "high":
			severityScore += 3
		case "medium":
			severityScore += 2
		case "low":
			severityScore += 1
		}
	}

	avgScore := float64(severityScore) / float64(len(alerts))
	
	// Increase severity based on alert count
	if len(alerts) >= 10 {
		avgScore += 1.0
	} else if len(alerts) >= 5 {
		avgScore += 0.5
	}

	if avgScore >= 3.5 {
		return "critical"
	} else if avgScore >= 2.5 {
		return "high"
	} else if avgScore >= 1.5 {
		return "medium"
	}
	return "low"
}

// calculateCorrelationScore calculates how strongly the alerts are correlated
func (ace *AlertCorrelationEngine) calculateCorrelationScore(incident *CorrelatedIncident) float64 {
	score := 50.0 // Base score

	// More alerts = higher correlation
	if incident.AlertCount >= 10 {
		score += 20
	} else if incident.AlertCount >= 5 {
		score += 15
	} else if incident.AlertCount >= 3 {
		score += 10
	}

	// Shared entities increase score
	if len(incident.Entities.SourceIPs) == 1 {
		score += 10 // Single source IP
	}
	if len(incident.Entities.Users) == 1 {
		score += 10 // Single user
	}

	// Time proximity
	duration := incident.LastSeen.Sub(incident.FirstSeen)
	if duration < 15*time.Minute {
		score += 10
	} else if duration < 1*time.Hour {
		score += 5
	}

	// MITRE mapping
	if len(incident.MITREMapping) >= 3 {
		score += 10 // Multiple techniques = likely real attack
	}

	if score > 100 {
		score = 100
	}

	return score
}

// generateIncidentTitle generates a title for the incident
func (ace *AlertCorrelationEngine) generateIncidentTitle(alerts []*CorrelatedAlert, rule *CorrelationRule) string {
	// Use rule name as base
	title := rule.Name

	// Add entity context
	if len(alerts) > 0 {
		if alerts[0].SourceIP != "" {
			title += fmt.Sprintf(" from %s", alerts[0].SourceIP)
		}
		if alerts[0].User != "" {
			title += fmt.Sprintf(" by %s", alerts[0].User)
		}
	}

	return title
}

// generateIncidentDescription generates a description for the incident
func (ace *AlertCorrelationEngine) generateIncidentDescription(alerts []*CorrelatedAlert, rule *CorrelationRule) string {
	return fmt.Sprintf("%s. %d related alerts detected within %d minute window. %s",
		rule.Description,
		len(alerts),
		rule.TimeWindow,
		strings.Join(rule.Tags, ", "))
}

// generateRecommendations generates response recommendations
func (ace *AlertCorrelationEngine) generateRecommendations(incident *CorrelatedIncident, rule *CorrelationRule) []string {
	recommendations := []string{}

	switch rule.ID {
	case "brute-force-attack":
		recommendations = append(recommendations,
			"Block the source IP address in WAF/Firewall",
			"Review the targeted user accounts for compromise",
			"Enable MFA for affected accounts if not already enabled",
			"Check for successful logins from the same source",
		)
	case "lateral-movement":
		recommendations = append(recommendations,
			"Isolate affected hosts from the network",
			"Review user permissions and recent access",
			"Check for credential exposure",
			"Scan endpoints for malware",
		)
	case "data-exfiltration":
		recommendations = append(recommendations,
			"Block external access for the user",
			"Review S3 bucket access logs",
			"Check data classification of accessed resources",
			"Revoke access keys if suspicious",
		)
	case "privilege-escalation":
		recommendations = append(recommendations,
			"Review IAM changes made",
			"Revoke elevated permissions",
			"Reset credentials",
			"Check for persistence mechanisms",
		)
	default:
		recommendations = append(recommendations,
			"Investigate the source of the alerts",
			"Review affected resources and users",
			"Consider isolating affected systems",
			"Create a case for detailed investigation",
		)
	}

	return recommendations
}

// extractMITRETechniques extracts MITRE ATT&CK techniques from alerts
func (ace *AlertCorrelationEngine) extractMITRETechniques(alerts []CorrelatedAlert) []MITRETechniqueRef {
	techniqueMap := make(map[string]*MITRETechniqueRef)

	for _, alert := range alerts {
		// Check if alert has MITRE mapping
		mapping := mapEventTypeToMITRE(alert.EventType)
		if mapping != nil {
			key := mapping.TechniqueID
			if existing, ok := techniqueMap[key]; ok {
				existing.AlertCount++
			} else {
				techniqueMap[key] = &MITRETechniqueRef{
					TechniqueID:   mapping.TechniqueID,
					TechniqueName: mapping.TechniqueName,
					TacticID:      mapping.TacticID,
					TacticName:    mapping.TacticName,
					AlertCount:    1,
				}
			}
		}
	}

	techniques := make([]MITRETechniqueRef, 0, len(techniqueMap))
	for _, t := range techniqueMap {
		techniques = append(techniques, *t)
	}

	return techniques
}

// Helper function
func containsStr(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

// handleListCorrelatedIncidents lists all correlated incidents
func (s *APIServer) handleListCorrelatedIncidents(c *gin.Context) {
	engine := GetCorrelationEngine(s)
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	status := c.Query("status")
	severity := c.Query("severity")

	incidents := make([]*CorrelatedIncident, 0)
	for _, incident := range engine.activeIncidents {
		if status != "" && incident.Status != status {
			continue
		}
		if severity != "" && incident.Severity != severity {
			continue
		}
		incidents = append(incidents, incident)
	}

	// Sort by last seen (most recent first)
	sort.Slice(incidents, func(i, j int) bool {
		return incidents[i].LastSeen.After(incidents[j].LastSeen)
	})

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"incidents": incidents,
		"total":     len(incidents),
	})
}

// handleGetCorrelatedIncident gets a specific correlated incident
func (s *APIServer) handleGetCorrelatedIncident(c *gin.Context) {
	id := c.Param("id")
	
	engine := GetCorrelationEngine(s)
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	incident, exists := engine.activeIncidents[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Incident not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"incident": incident,
	})
}

// handleUpdateCorrelatedIncident updates an incident status
func (s *APIServer) handleUpdateCorrelatedIncident(c *gin.Context) {
	id := c.Param("id")
	
	var update struct {
		Status     string `json:"status"`
		AssignedTo string `json:"assigned_to"`
		Priority   int    `json:"priority"`
	}

	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	engine := GetCorrelationEngine(s)
	engine.mu.Lock()
	defer engine.mu.Unlock()

	incident, exists := engine.activeIncidents[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Incident not found"})
		return
	}

	if update.Status != "" {
		incident.Status = update.Status
	}
	if update.AssignedTo != "" {
		incident.AssignedTo = update.AssignedTo
	}
	if update.Priority > 0 {
		incident.Priority = update.Priority
	}
	incident.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"incident": incident,
	})
}

// handleGetCorrelationStats returns correlation statistics
func (s *APIServer) handleGetCorrelationStats(c *gin.Context) {
	engine := GetCorrelationEngine(s)
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	stats := map[string]interface{}{
		"total_incidents": len(engine.activeIncidents),
		"by_status": map[string]int{
			"open":          0,
			"investigating": 0,
			"resolved":      0,
			"closed":        0,
		},
		"by_severity": map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
		},
		"total_correlated_alerts": 0,
		"active_rules":            len(engine.rules),
	}

	for _, incident := range engine.activeIncidents {
		stats["by_status"].(map[string]int)[incident.Status]++
		stats["by_severity"].(map[string]int)[incident.Severity]++
		stats["total_correlated_alerts"] = stats["total_correlated_alerts"].(int) + incident.AlertCount
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

// handleListCorrelationRules lists all correlation rules
func (s *APIServer) handleListCorrelationRules(c *gin.Context) {
	engine := GetCorrelationEngine(s)
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	rules := make([]*CorrelationRule, 0, len(engine.rules))
	for _, rule := range engine.rules {
		rules = append(rules, rule)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"rules":   rules,
		"total":   len(rules),
	})
}

// handleCreateCaseFromIncident creates a case from a correlated incident
func (s *APIServer) handleCreateCaseFromIncident(c *gin.Context) {
	incidentID := c.Param("id")
	
	engine := GetCorrelationEngine(s)
	engine.mu.RLock()
	incident, exists := engine.activeIncidents[incidentID]
	engine.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Incident not found"})
		return
	}

	// Obter account_id do escopo do usuário
	var accountID string
	scope := getAccessScope(c)
	if len(scope.AccountIDs) > 0 {
		accountID = scope.AccountIDs[0]
	}

	// Create case from incident
	caseData := map[string]interface{}{
		"title":       incident.Title,
		"description": incident.Description,
		"severity":    incident.Severity,
		"status":      "open",
		"source":      "correlation_engine",
		"source_id":   incident.ID,
		"tags":        incident.Tags,
		"entities":    incident.Entities,
		"alert_count": incident.AlertCount,
		"account_id":  accountID,
	}

	caseJSON, _ := json.Marshal(caseData)

	// Index the case
	res, err := s.opensearch.Index(
		"siem-cases",
		strings.NewReader(string(caseJSON)),
		s.opensearch.Index.WithDocumentID(uuid.New().String()),
		s.opensearch.Index.WithRefresh("true"),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.String()})
		return
	}

	// Update incident with case reference
	engine.mu.Lock()
	incident.RelatedCaseID = uuid.New().String()
	incident.Status = "investigating"
	engine.mu.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "Case created from correlated incident",
		"case_id": incident.RelatedCaseID,
	})
}

