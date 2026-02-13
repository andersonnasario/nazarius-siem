package main

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// SLAPolicy defines SLA requirements
type SLAPolicy struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	Enabled             bool                   `json:"enabled"`
	Severity            string                 `json:"severity"` // critical, high, medium, low
	TimeToAcknowledge   int                    `json:"time_to_acknowledge"`   // minutes
	TimeToRespond       int                    `json:"time_to_respond"`       // minutes
	TimeToResolve       int                    `json:"time_to_resolve"`       // minutes
	BusinessHoursOnly   bool                   `json:"business_hours_only"`
	EscalationEnabled   bool                   `json:"escalation_enabled"`
	EscalationThreshold int                    `json:"escalation_threshold"` // minutes before breach
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// SLATracking tracks SLA compliance for an incident
type SLATracking struct {
	ID                    string    `json:"id"`
	IncidentID            string    `json:"incident_id"`
	PolicyID              string    `json:"policy_id"`
	Severity              string    `json:"severity"`
	Status                string    `json:"status"` // compliant, at_risk, breached
	DetectedAt            time.Time `json:"detected_at"`
	AcknowledgedAt        *time.Time `json:"acknowledged_at"`
	RespondedAt           *time.Time `json:"responded_at"`
	ResolvedAt            *time.Time `json:"resolved_at"`
	TimeToAcknowledge     int       `json:"time_to_acknowledge"`     // actual minutes
	TimeToRespond         int       `json:"time_to_respond"`         // actual minutes
	TimeToResolve         int       `json:"time_to_resolve"`         // actual minutes
	SLAAcknowledge        int       `json:"sla_acknowledge"`         // target minutes
	SLARespond            int       `json:"sla_respond"`             // target minutes
	SLAResolve            int       `json:"sla_resolve"`             // target minutes
	AcknowledgeCompliance bool      `json:"acknowledge_compliance"`
	RespondCompliance     bool      `json:"respond_compliance"`
	ResolveCompliance     bool      `json:"resolve_compliance"`
	BreachReason          string    `json:"breach_reason"`
	EscalatedAt           *time.Time `json:"escalated_at"`
	EscalatedTo           string    `json:"escalated_to"`
}

// SLABreach represents an SLA violation
type SLABreach struct {
	ID          string    `json:"id"`
	TrackingID  string    `json:"tracking_id"`
	IncidentID  string    `json:"incident_id"`
	PolicyID    string    `json:"policy_id"`
	BreachType  string    `json:"breach_type"` // acknowledge, respond, resolve
	BreachedAt  time.Time `json:"breached_at"`
	TargetTime  int       `json:"target_time"`
	ActualTime  int       `json:"actual_time"`
	Delay       int       `json:"delay"` // minutes over SLA
	Severity    string    `json:"severity"`
	Reason      string    `json:"reason"`
	Acknowledged bool     `json:"acknowledged"`
}

// Metrics represents calculated operational metrics
type Metrics struct {
	Period            string  `json:"period"` // daily, weekly, monthly
	StartDate         string  `json:"start_date"`
	EndDate           string  `json:"end_date"`
	TotalIncidents    int     `json:"total_incidents"`
	ResolvedIncidents int     `json:"resolved_incidents"`
	MTTR              float64 `json:"mttr"` // Mean Time To Resolve (minutes)
	MTTA              float64 `json:"mtta"` // Mean Time To Acknowledge (minutes)
	MTTD              float64 `json:"mttd"` // Mean Time To Detect (minutes)
	MTBF              float64 `json:"mtbf"` // Mean Time Between Failures (hours)
	FirstResponseTime float64 `json:"first_response_time"` // minutes
	ResolutionRate    float64 `json:"resolution_rate"` // percentage
	SLACompliance     float64 `json:"sla_compliance"` // percentage
	BreachCount       int     `json:"breach_count"`
}

// SLAStats provides SLA statistics
type SLAStats struct {
	TotalTracked       int                    `json:"total_tracked"`
	Compliant          int                    `json:"compliant"`
	AtRisk             int                    `json:"at_risk"`
	Breached           int                    `json:"breached"`
	ComplianceRate     float64                `json:"compliance_rate"`
	AverageResolution  float64                `json:"average_resolution"` // minutes
	BySeverity         map[string]SLABySeverity `json:"by_severity"`
	RecentBreaches     []SLABreach            `json:"recent_breaches"`
	TopBreachReasons   []BreachReason         `json:"top_breach_reasons"`
	TimeSeriesData     []SLATimeSeriesData    `json:"time_series_data"`
}

// SLABySeverity tracks SLA by severity
type SLABySeverity struct {
	Severity       string  `json:"severity"`
	Total          int     `json:"total"`
	Compliant      int     `json:"compliant"`
	Breached       int     `json:"breached"`
	ComplianceRate float64 `json:"compliance_rate"`
	AvgResolution  float64 `json:"avg_resolution"`
}

// BreachReason tracks common breach reasons
type BreachReason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// SLATimeSeriesData for charts
type SLATimeSeriesData struct {
	Timestamp      time.Time `json:"timestamp"`
	Compliant      int       `json:"compliant"`
	AtRisk         int       `json:"at_risk"`
	Breached       int       `json:"breached"`
	ComplianceRate float64   `json:"compliance_rate"`
}

// ============================================================================
// IN-MEMORY STORAGE
// ============================================================================

var (
	slaPolicies  = make(map[string]*SLAPolicy)
	slaTrackings = make(map[string]*SLATracking)
	slaBreaches  = make(map[string]*SLABreach)
	slaMutex     sync.RWMutex
)

// ============================================================================
// INITIALIZATION
// ============================================================================

func initSLAMetricsSystem() {
	slaMutex.Lock()
	defer slaMutex.Unlock()

	// Sample SLA policies
	policy1 := &SLAPolicy{
		ID:                  "sla-001",
		Name:                "Critical Incidents SLA",
		Description:         "SLA for critical severity incidents",
		Enabled:             true,
		Severity:            "critical",
		TimeToAcknowledge:   15,  // 15 minutes
		TimeToRespond:       30,  // 30 minutes
		TimeToResolve:       240, // 4 hours
		BusinessHoursOnly:   false,
		EscalationEnabled:   true,
		EscalationThreshold: 10,
		CreatedAt:           time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:           time.Now(),
		Metadata:            map[string]interface{}{"priority": "highest"},
	}
	slaPolicies[policy1.ID] = policy1

	policy2 := &SLAPolicy{
		ID:                  "sla-002",
		Name:                "High Priority SLA",
		Description:         "SLA for high severity incidents",
		Enabled:             true,
		Severity:            "high",
		TimeToAcknowledge:   30,   // 30 minutes
		TimeToRespond:       60,   // 1 hour
		TimeToResolve:       480,  // 8 hours
		BusinessHoursOnly:   false,
		EscalationEnabled:   true,
		EscalationThreshold: 30,
		CreatedAt:           time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:           time.Now(),
		Metadata:            map[string]interface{}{"priority": "high"},
	}
	slaPolicies[policy2.ID] = policy2

	policy3 := &SLAPolicy{
		ID:                  "sla-003",
		Name:                "Medium Priority SLA",
		Description:         "SLA for medium severity incidents",
		Enabled:             true,
		Severity:            "medium",
		TimeToAcknowledge:   60,    // 1 hour
		TimeToRespond:       120,   // 2 hours
		TimeToResolve:       1440,  // 24 hours
		BusinessHoursOnly:   true,
		EscalationEnabled:   false,
		EscalationThreshold: 0,
		CreatedAt:           time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:           time.Now(),
		Metadata:            map[string]interface{}{"priority": "medium"},
	}
	slaPolicies[policy3.ID] = policy3

	// Sample tracking data
	now := time.Now()
	ack1 := now.Add(-10 * time.Minute)
	resp1 := now.Add(-8 * time.Minute)
	resolved1 := now.Add(-5 * time.Minute)

	tracking1 := &SLATracking{
		ID:                    "track-001",
		IncidentID:            "inc-001",
		PolicyID:              "sla-001",
		Severity:              "critical",
		Status:                "compliant",
		DetectedAt:            now.Add(-15 * time.Minute),
		AcknowledgedAt:        &ack1,
		RespondedAt:           &resp1,
		ResolvedAt:            &resolved1,
		TimeToAcknowledge:     10,
		TimeToRespond:         8,
		TimeToResolve:         15,
		SLAAcknowledge:        15,
		SLARespond:            30,
		SLAResolve:            240,
		AcknowledgeCompliance: true,
		RespondCompliance:     true,
		ResolveCompliance:     true,
	}
	slaTrackings[tracking1.ID] = tracking1

	// Sample breach
	breach1 := &SLABreach{
		ID:          "breach-001",
		TrackingID:  "track-002",
		IncidentID:  "inc-002",
		PolicyID:    "sla-002",
		BreachType:  "acknowledge",
		BreachedAt:  now.Add(-2 * time.Hour),
		TargetTime:  30,
		ActualTime:  45,
		Delay:       15,
		Severity:    "high",
		Reason:      "Analyst unavailable",
		Acknowledged: true,
	}
	slaBreaches[breach1.ID] = breach1
}

// ============================================================================
// API HANDLERS
// ============================================================================

// List SLA policies
func (s *APIServer) handleListSLAPolicies(c *gin.Context) {
	slaMutex.RLock()
	defer slaMutex.RUnlock()

	severity := c.Query("severity")
	enabled := c.Query("enabled")

	policies := make([]*SLAPolicy, 0)
	for _, policy := range slaPolicies {
		if severity != "" && policy.Severity != severity {
			continue
		}
		if enabled != "" {
			if (enabled == "true" && !policy.Enabled) || (enabled == "false" && policy.Enabled) {
				continue
			}
		}
		policies = append(policies, policy)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    policies,
		"total":   len(policies),
	})
}

// Create SLA policy
func (s *APIServer) handleCreateSLAPolicy(c *gin.Context) {
	var policy SLAPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	policy.ID = generateID()
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	slaMutex.Lock()
	slaPolicies[policy.ID] = &policy
	slaMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    policy,
		"message": "SLA policy created successfully",
	})
}

// Update SLA policy
func (s *APIServer) handleUpdateSLAPolicy(c *gin.Context) {
	id := c.Param("id")

	slaMutex.Lock()
	defer slaMutex.Unlock()

	policy, exists := slaPolicies[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "SLA policy not found",
		})
		return
	}

	var updates SLAPolicy
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	policy.Name = updates.Name
	policy.Description = updates.Description
	policy.Enabled = updates.Enabled
	policy.TimeToAcknowledge = updates.TimeToAcknowledge
	policy.TimeToRespond = updates.TimeToRespond
	policy.TimeToResolve = updates.TimeToResolve
	policy.BusinessHoursOnly = updates.BusinessHoursOnly
	policy.EscalationEnabled = updates.EscalationEnabled
	policy.EscalationThreshold = updates.EscalationThreshold
	policy.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    policy,
		"message": "SLA policy updated successfully",
	})
}

// Delete SLA policy
func (s *APIServer) handleDeleteSLAPolicy(c *gin.Context) {
	id := c.Param("id")

	slaMutex.Lock()
	defer slaMutex.Unlock()

	if _, exists := slaPolicies[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "SLA policy not found",
		})
		return
	}

	delete(slaPolicies, id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "SLA policy deleted successfully",
	})
}

// List SLA trackings
func (s *APIServer) handleListSLATrackings(c *gin.Context) {
	slaMutex.RLock()
	defer slaMutex.RUnlock()

	status := c.Query("status")
	severity := c.Query("severity")

	trackings := make([]*SLATracking, 0)
	for _, tracking := range slaTrackings {
		if status != "" && tracking.Status != status {
			continue
		}
		if severity != "" && tracking.Severity != severity {
			continue
		}
		trackings = append(trackings, tracking)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    trackings,
		"total":   len(trackings),
	})
}

// Get SLA tracking
func (s *APIServer) handleGetSLATracking(c *gin.Context) {
	id := c.Param("id")

	slaMutex.RLock()
	tracking, exists := slaTrackings[id]
	slaMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "SLA tracking not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    tracking,
	})
}

// List SLA breaches
func (s *APIServer) handleListSLABreaches(c *gin.Context) {
	slaMutex.RLock()
	defer slaMutex.RUnlock()

	severity := c.Query("severity")
	breachType := c.Query("breach_type")

	breaches := make([]*SLABreach, 0)
	for _, breach := range slaBreaches {
		if severity != "" && breach.Severity != severity {
			continue
		}
		if breachType != "" && breach.BreachType != breachType {
			continue
		}
		breaches = append(breaches, breach)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    breaches,
		"total":   len(breaches),
	})
}

// Get SLA statistics
func (s *APIServer) handleGetSLAStats(c *gin.Context) {
	slaMutex.RLock()
	defer slaMutex.RUnlock()

	stats := SLAStats{
		TotalTracked:     len(slaTrackings),
		BySeverity:       make(map[string]SLABySeverity),
		RecentBreaches:   make([]SLABreach, 0),
		TopBreachReasons: make([]BreachReason, 0),
		TimeSeriesData:   make([]SLATimeSeriesData, 0),
	}

	severityStats := make(map[string]*SLABySeverity)
	breachReasons := make(map[string]int)
	var totalResolution float64

	for _, tracking := range slaTrackings {
		switch tracking.Status {
		case "compliant":
			stats.Compliant++
		case "at_risk":
			stats.AtRisk++
		case "breached":
			stats.Breached++
		}

		totalResolution += float64(tracking.TimeToResolve)

		// Track by severity
		if _, exists := severityStats[tracking.Severity]; !exists {
			severityStats[tracking.Severity] = &SLABySeverity{
				Severity: tracking.Severity,
			}
		}
		sev := severityStats[tracking.Severity]
		sev.Total++
		if tracking.ResolveCompliance {
			sev.Compliant++
		} else {
			sev.Breached++
		}
		sev.AvgResolution += float64(tracking.TimeToResolve)
	}

	// Calculate averages
	if stats.TotalTracked > 0 {
		stats.ComplianceRate = float64(stats.Compliant) / float64(stats.TotalTracked) * 100
		stats.AverageResolution = totalResolution / float64(stats.TotalTracked)
	}

	for severity, sev := range severityStats {
		if sev.Total > 0 {
			sev.ComplianceRate = float64(sev.Compliant) / float64(sev.Total) * 100
			sev.AvgResolution = sev.AvgResolution / float64(sev.Total)
		}
		stats.BySeverity[severity] = *sev
	}

	// Recent breaches
	for _, breach := range slaBreaches {
		stats.RecentBreaches = append(stats.RecentBreaches, *breach)
		breachReasons[breach.Reason]++
	}

	// Top breach reasons
	for reason, count := range breachReasons {
		stats.TopBreachReasons = append(stats.TopBreachReasons, BreachReason{
			Reason: reason,
			Count:  count,
		})
	}

	// Time series (last 24 hours)
	now := time.Now()
	for i := 23; i >= 0; i-- {
		timestamp := now.Add(-time.Duration(i) * time.Hour)
		dataPoint := SLATimeSeriesData{
			Timestamp: timestamp,
		}

		var compliant, atRisk, breached int
		for _, tracking := range slaTrackings {
			if tracking.DetectedAt.After(timestamp) && tracking.DetectedAt.Before(timestamp.Add(time.Hour)) {
				switch tracking.Status {
				case "compliant":
					compliant++
				case "at_risk":
					atRisk++
				case "breached":
					breached++
				}
			}
		}

		dataPoint.Compliant = compliant
		dataPoint.AtRisk = atRisk
		dataPoint.Breached = breached
		total := compliant + atRisk + breached
		if total > 0 {
			dataPoint.ComplianceRate = float64(compliant) / float64(total) * 100
		}

		stats.TimeSeriesData = append(stats.TimeSeriesData, dataPoint)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}

// Get metrics
func (s *APIServer) handleGetSLAMetrics(c *gin.Context) {
	period := c.DefaultQuery("period", "daily")

	slaMutex.RLock()
	defer slaMutex.RUnlock()

	metrics := Metrics{
		Period:         period,
		StartDate:      time.Now().Add(-24 * time.Hour).Format("2006-01-02"),
		EndDate:        time.Now().Format("2006-01-02"),
		TotalIncidents: len(slaTrackings),
	}

	var totalTTR, totalTTA, totalFRT float64
	resolvedCount := 0

	for _, tracking := range slaTrackings {
		if tracking.ResolvedAt != nil {
			resolvedCount++
			totalTTR += float64(tracking.TimeToResolve)
		}
		if tracking.AcknowledgedAt != nil {
			totalTTA += float64(tracking.TimeToAcknowledge)
		}
		if tracking.RespondedAt != nil {
			totalFRT += float64(tracking.TimeToRespond)
		}
	}

	metrics.ResolvedIncidents = resolvedCount

	if resolvedCount > 0 {
		metrics.MTTR = totalTTR / float64(resolvedCount)
		metrics.ResolutionRate = float64(resolvedCount) / float64(metrics.TotalIncidents) * 100
	}

	if metrics.TotalIncidents > 0 {
		metrics.MTTA = totalTTA / float64(metrics.TotalIncidents)
		metrics.FirstResponseTime = totalFRT / float64(metrics.TotalIncidents)
	}

	// Calculate compliance
	compliantCount := 0
	for _, tracking := range slaTrackings {
		if tracking.Status == "compliant" {
			compliantCount++
		}
	}
	if metrics.TotalIncidents > 0 {
		metrics.SLACompliance = float64(compliantCount) / float64(metrics.TotalIncidents) * 100
	}

	metrics.BreachCount = len(slaBreaches)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    metrics,
	})
}

