package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// DLP Policy represents a data loss prevention policy
type DLPPolicy struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Status         string    `json:"status"` // active, disabled
	Action         string    `json:"action"` // block, alert, encrypt, quarantine
	DataTypes      []string  `json:"data_types"` // pii, pci, phi, confidential
	Patterns       []string  `json:"patterns"`
	Severity       string    `json:"severity"` // critical, high, medium, low
	Scope          []string  `json:"scope"` // email, file_upload, api, web_form
	ExclusionRules []string  `json:"exclusion_rules"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	CreatedBy      string    `json:"created_by"`
	IncidentCount  int       `json:"incident_count"`
}

// DLPIncident represents a data loss prevention incident
type DLPIncident struct {
	ID             string            `json:"id"`
	PolicyID       string            `json:"policy_id"`
	PolicyName     string            `json:"policy_name"`
	Severity       string            `json:"severity"`
	Status         string            `json:"status"` // open, investigating, resolved, false_positive
	Action         string            `json:"action"` // blocked, alerted, encrypted, quarantined
	DataType       string            `json:"data_type"`
	Channel        string            `json:"channel"` // email, file_upload, api, web_form
	Source         string            `json:"source"`
	Destination    string            `json:"destination"`
	User           string            `json:"user"`
	DetectedData   []DetectedPattern `json:"detected_data"`
	ContentPreview string            `json:"content_preview"`
	RiskScore      int               `json:"risk_score"` // 0-100
	DetectedAt     time.Time         `json:"detected_at"`
	ResolvedAt     *time.Time        `json:"resolved_at,omitempty"`
	Notes          string            `json:"notes"`
	CaseID         string            `json:"case_id,omitempty"`
}

// DetectedPattern represents a detected sensitive data pattern
type DetectedPattern struct {
	Type       string `json:"type"`
	Pattern    string `json:"pattern"`
	Value      string `json:"value"` // masked value
	Count      int    `json:"count"`
	Confidence int    `json:"confidence"` // 0-100
}

// DataClassification represents classification of data
type DataClassification struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Level        string    `json:"level"` // confidential, restricted, internal, public
	Description  string    `json:"description"`
	Requirements []string  `json:"requirements"` // encryption, access_control, audit
	Color        string    `json:"color"`
	Icon         string    `json:"icon"`
	PolicyCount  int       `json:"policy_count"`
	DataCount    int64     `json:"data_count"`
	CreatedAt    time.Time `json:"created_at"`
}

// DLPPattern represents a detection pattern
type DLPPattern struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"` // regex, keyword, ml
	Pattern     string    `json:"pattern"`
	DataType    string    `json:"data_type"`
	Description string    `json:"description"`
	Examples    []string  `json:"examples"`
	IsBuiltIn   bool      `json:"is_built_in"`
	Enabled     bool      `json:"enabled"`
	MatchCount  int       `json:"match_count"`
	CreatedAt   time.Time `json:"created_at"`
}

// DLPDashboard represents DLP dashboard metrics
type DLPDashboard struct {
	Overview       DLPOverview        `json:"overview"`
	IncidentTrend  []TrendPoint       `json:"incident_trend"`
	TopPolicies    []PolicyStats      `json:"top_policies"`
	TopUsers       []UserStats        `json:"top_users"`
	DataTypeBreakdown []DataTypeStats `json:"data_type_breakdown"`
	ChannelStats   []ChannelStats     `json:"channel_stats"`
	RecentIncidents []DLPIncident     `json:"recent_incidents"`
}

// DLPOverview represents overview metrics
type DLPOverview struct {
	TotalIncidents    int     `json:"total_incidents"`
	IncidentsToday    int     `json:"incidents_today"`
	BlockedAttempts   int     `json:"blocked_attempts"`
	ActivePolicies    int     `json:"active_policies"`
	RiskScore         int     `json:"risk_score"`
	ComplianceRate    float64 `json:"compliance_rate"`
	DataProtected     string  `json:"data_protected"` // e.g., "15.2 TB"
	TrendPercentage   float64 `json:"trend_percentage"`
}

// TrendPoint represents a point in trend chart
type TrendPoint struct {
	Date      string `json:"date"`
	Incidents int    `json:"incidents"`
	Blocked   int    `json:"blocked"`
}

// PolicyStats represents policy statistics
type PolicyStats struct {
	PolicyID      string  `json:"policy_id"`
	PolicyName    string  `json:"policy_name"`
	IncidentCount int     `json:"incident_count"`
	BlockRate     float64 `json:"block_rate"`
	Severity      string  `json:"severity"`
}

// UserStats represents user statistics
type UserStats struct {
	User          string  `json:"user"`
	IncidentCount int     `json:"incident_count"`
	RiskScore     int     `json:"risk_score"`
	DataTypes     []string `json:"data_types"`
}

// DataTypeStats represents data type statistics
type DataTypeStats struct {
	DataType string `json:"data_type"`
	Count    int    `json:"count"`
	Severity string `json:"severity"`
}

// ChannelStats represents channel statistics
type ChannelStats struct {
	Channel       string  `json:"channel"`
	IncidentCount int     `json:"incident_count"`
	BlockRate     float64 `json:"block_rate"`
}

// ContentInspection represents content to be inspected
type ContentInspection struct {
	Content string   `json:"content"`
	Channel string   `json:"channel"`
	User    string   `json:"user"`
	Policies []string `json:"policies,omitempty"` // specific policies to check
}

// InspectionResult represents inspection result
type InspectionResult struct {
	IsViolation    bool              `json:"is_violation"`
	Action         string            `json:"action"`
	DetectedData   []DetectedPattern `json:"detected_data"`
	MatchedPolicies []string         `json:"matched_policies"`
	RiskScore      int               `json:"risk_score"`
	Recommendations []string         `json:"recommendations"`
}

// Built-in detection patterns
var builtInPatterns = map[string]*regexp.Regexp{
	"ssn":           regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	"credit_card":   regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
	"email":         regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
	"phone":         regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`),
	"ip_address":    regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
	"api_key":       regexp.MustCompile(`\b[A-Za-z0-9]{32,}\b`),
	"aws_key":       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"private_key":   regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----`),
	"passport":      regexp.MustCompile(`\b[A-Z]{1,2}\d{6,9}\b`),
	"drivers_license": regexp.MustCompile(`\b[A-Z]{1,2}\d{5,8}\b`),
}

// DLP Handlers

func (s *APIServer) handleGetDLPDashboard(c *gin.Context) {
	dashboard := generateMockDLPDashboard()
	c.JSON(http.StatusOK, dashboard)
}

func (s *APIServer) handleGetDLPPolicies(c *gin.Context) {
	policies := generateMockDLPPolicies()
	c.JSON(http.StatusOK, policies)
}

func (s *APIServer) handleGetDLPPolicy(c *gin.Context) {
	policyID := c.Param("id")
	policy := generateMockDLPPolicyDetail(policyID)
	c.JSON(http.StatusOK, policy)
}

func (s *APIServer) handleCreateDLPPolicy(c *gin.Context) {
	var policy DLPPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		log.Printf("[ERROR] handleCreateDLPPolicy bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	policy.ID = fmt.Sprintf("POL-%d", time.Now().Unix())
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	policy.IncidentCount = 0

	c.JSON(http.StatusCreated, policy)
}

func (s *APIServer) handleUpdateDLPPolicy(c *gin.Context) {
	policyID := c.Param("id")
	var policy DLPPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		log.Printf("[ERROR] handleUpdateDLPPolicy bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	policy.ID = policyID
	policy.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, policy)
}

func (s *APIServer) handleDeleteDLPPolicy(c *gin.Context) {
	policyID := c.Param("id")
	c.JSON(http.StatusOK, gin.H{
		"message": "Policy deleted successfully",
		"policy_id": policyID,
	})
}

func (s *APIServer) handleGetDLPIncidents(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")
	
	incidents := generateMockDLPIncidents()
	
	// Filter by status
	if status != "" {
		filtered := []DLPIncident{}
		for _, inc := range incidents {
			if inc.Status == status {
				filtered = append(filtered, inc)
			}
		}
		incidents = filtered
	}
	
	// Filter by severity
	if severity != "" {
		filtered := []DLPIncident{}
		for _, inc := range incidents {
			if inc.Severity == severity {
				filtered = append(filtered, inc)
			}
		}
		incidents = filtered
	}
	
	c.JSON(http.StatusOK, incidents)
}

func (s *APIServer) handleGetDLPIncident(c *gin.Context) {
	incidentID := c.Param("id")
	incident := generateMockDLPIncidentDetail(incidentID)
	c.JSON(http.StatusOK, incident)
}

func (s *APIServer) handleUpdateDLPIncident(c *gin.Context) {
	incidentID := c.Param("id")
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		log.Printf("[ERROR] handleUpdateDLPIncident bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	incident := generateMockDLPIncidentDetail(incidentID)
	
	if status, ok := updates["status"].(string); ok {
		incident.Status = status
		if status == "resolved" {
			now := time.Now()
			incident.ResolvedAt = &now
		}
	}
	
	if notes, ok := updates["notes"].(string); ok {
		incident.Notes = notes
	}
	
	c.JSON(http.StatusOK, incident)
}

func (s *APIServer) handleInspectContent(c *gin.Context) {
	var inspection ContentInspection
	if err := c.ShouldBindJSON(&inspection); err != nil {
		log.Printf("[ERROR] handleInspectContent bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	result := inspectContent(inspection)
	c.JSON(http.StatusOK, result)
}

func (s *APIServer) handleGetDLPPatterns(c *gin.Context) {
	patterns := generateMockDLPPatterns()
	c.JSON(http.StatusOK, patterns)
}

func (s *APIServer) handleCreateDLPPattern(c *gin.Context) {
	var pattern DLPPattern
	if err := c.ShouldBindJSON(&pattern); err != nil {
		log.Printf("[ERROR] handleCreateDLPPattern bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	pattern.ID = fmt.Sprintf("PAT-%d", time.Now().Unix())
	pattern.CreatedAt = time.Now()
	pattern.IsBuiltIn = false
	pattern.MatchCount = 0
	pattern.Enabled = true

	c.JSON(http.StatusCreated, pattern)
}

func (s *APIServer) handleGetDataClassifications(c *gin.Context) {
	classifications := generateMockDataClassifications()
	c.JSON(http.StatusOK, classifications)
}

func (s *APIServer) handleClassifyData(c *gin.Context) {
	var request struct {
		Content  string `json:"content"`
		Filename string `json:"filename,omitempty"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		log.Printf("[ERROR] handleClassifyData bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	classification := classifyData(request.Content, request.Filename)
	c.JSON(http.StatusOK, classification)
}

func (s *APIServer) handleGetDLPStats(c *gin.Context) {
	stats := gin.H{
		"total_policies": 15,
		"active_policies": 12,
		"total_incidents": 3847,
		"open_incidents": 23,
		"blocked_today": 47,
		"avg_risk_score": 67,
		"compliance_rate": 94.5,
		"data_protected_tb": 15.2,
		"top_data_type": "PII",
		"detection_accuracy": 96.8,
	}
	c.JSON(http.StatusOK, stats)
}

// Helper functions

func inspectContent(inspection ContentInspection) InspectionResult {
	result := InspectionResult{
		IsViolation:     false,
		Action:          "allow",
		DetectedData:    []DetectedPattern{},
		MatchedPolicies: []string{},
		RiskScore:       0,
		Recommendations: []string{},
	}

	content := strings.ToLower(inspection.Content)
	detectionCount := 0

	// Check for SSN
	if matches := builtInPatterns["ssn"].FindAllString(inspection.Content, -1); len(matches) > 0 {
		result.DetectedData = append(result.DetectedData, DetectedPattern{
			Type:       "SSN",
			Pattern:    "Social Security Number",
			Value:      maskValue(matches[0]),
			Count:      len(matches),
			Confidence: 95,
		})
		detectionCount += len(matches)
		result.MatchedPolicies = append(result.MatchedPolicies, "PII Protection Policy")
	}

	// Check for Credit Card
	if matches := builtInPatterns["credit_card"].FindAllString(inspection.Content, -1); len(matches) > 0 {
		result.DetectedData = append(result.DetectedData, DetectedPattern{
			Type:       "Credit Card",
			Pattern:    "Credit Card Number",
			Value:      maskValue(matches[0]),
			Count:      len(matches),
			Confidence: 90,
		})
		detectionCount += len(matches)
		result.MatchedPolicies = append(result.MatchedPolicies, "PCI-DSS Compliance Policy")
	}

	// Check for Email
	if matches := builtInPatterns["email"].FindAllString(inspection.Content, -1); len(matches) > 0 {
		result.DetectedData = append(result.DetectedData, DetectedPattern{
			Type:       "Email",
			Pattern:    "Email Address",
			Value:      maskValue(matches[0]),
			Count:      len(matches),
			Confidence: 85,
		})
		detectionCount += len(matches)
	}

	// Check for Phone Number
	if matches := builtInPatterns["phone"].FindAllString(inspection.Content, -1); len(matches) > 0 {
		result.DetectedData = append(result.DetectedData, DetectedPattern{
			Type:       "Phone",
			Pattern:    "Phone Number",
			Value:      maskValue(matches[0]),
			Count:      len(matches),
			Confidence: 80,
		})
		detectionCount += len(matches)
	}

	// Check for AWS Keys
	if matches := builtInPatterns["aws_key"].FindAllString(inspection.Content, -1); len(matches) > 0 {
		result.DetectedData = append(result.DetectedData, DetectedPattern{
			Type:       "AWS Key",
			Pattern:    "AWS Access Key",
			Value:      maskValue(matches[0]),
			Count:      len(matches),
			Confidence: 98,
		})
		detectionCount += len(matches)
		result.MatchedPolicies = append(result.MatchedPolicies, "Cloud Credentials Policy")
		result.IsViolation = true
		result.Action = "block"
	}

	// Check for Private Key
	if builtInPatterns["private_key"].MatchString(inspection.Content) {
		result.DetectedData = append(result.DetectedData, DetectedPattern{
			Type:       "Private Key",
			Pattern:    "RSA Private Key",
			Value:      "***REDACTED***",
			Count:      1,
			Confidence: 99,
		})
		detectionCount++
		result.MatchedPolicies = append(result.MatchedPolicies, "Encryption Key Protection Policy")
		result.IsViolation = true
		result.Action = "block"
	}

	// Check for confidential keywords
	confidentialKeywords := []string{"confidential", "secret", "internal only", "do not share", "restricted"}
	for _, keyword := range confidentialKeywords {
		if strings.Contains(content, keyword) {
			result.DetectedData = append(result.DetectedData, DetectedPattern{
				Type:       "Confidential Marker",
				Pattern:    "Confidential Keyword",
				Value:      keyword,
				Count:      1,
				Confidence: 70,
			})
			detectionCount++
		}
	}

	// Calculate risk score
	result.RiskScore = calculateRiskScore(detectionCount, result.DetectedData)

	// Determine if violation based on risk score
	if result.RiskScore > 70 && result.Action != "block" {
		result.IsViolation = true
		result.Action = "alert"
	}

	// Add recommendations
	if len(result.DetectedData) > 0 {
		result.Recommendations = append(result.Recommendations, "Consider encrypting sensitive data before transmission")
		result.Recommendations = append(result.Recommendations, "Review data handling procedures with user")
		if result.RiskScore > 80 {
			result.Recommendations = append(result.Recommendations, "Immediate security team notification required")
		}
	}

	return result
}

func maskValue(value string) string {
	if len(value) <= 4 {
		return "***"
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}

func calculateRiskScore(detectionCount int, patterns []DetectedPattern) int {
	if detectionCount == 0 {
		return 0
	}

	baseScore := detectionCount * 10
	if baseScore > 50 {
		baseScore = 50
	}

	confidenceBonus := 0
	for _, pattern := range patterns {
		if pattern.Type == "AWS Key" || pattern.Type == "Private Key" {
			confidenceBonus += 30
		} else if pattern.Type == "SSN" || pattern.Type == "Credit Card" {
			confidenceBonus += 20
		} else {
			confidenceBonus += 5
		}
	}

	totalScore := baseScore + confidenceBonus
	if totalScore > 100 {
		totalScore = 100
	}

	return totalScore
}

func classifyData(content, filename string) gin.H {
	content = strings.ToLower(content)
	
	// High sensitivity indicators
	highSensitivity := []string{"ssn", "credit card", "password", "private key", "confidential", "secret"}
	mediumSensitivity := []string{"email", "phone", "address", "internal", "restricted"}
	
	level := "public"
	confidence := 60
	requirements := []string{}
	
	for _, keyword := range highSensitivity {
		if strings.Contains(content, keyword) {
			level = "confidential"
			confidence = 90
			requirements = []string{"encryption", "access_control", "audit_log", "mfa_required"}
			break
		}
	}
	
	if level == "public" {
		for _, keyword := range mediumSensitivity {
			if strings.Contains(content, keyword) {
				level = "internal"
				confidence = 75
				requirements = []string{"access_control", "audit_log"}
				break
			}
		}
	}
	
	// Check patterns
	hasSSN := builtInPatterns["ssn"].MatchString(content)
	hasCreditCard := builtInPatterns["credit_card"].MatchString(content)
	hasPrivateKey := builtInPatterns["private_key"].MatchString(content)
	
	if hasSSN || hasCreditCard || hasPrivateKey {
		level = "confidential"
		confidence = 95
		requirements = []string{"encryption", "access_control", "audit_log", "mfa_required", "data_masking"}
	}
	
	return gin.H{
		"classification": level,
		"confidence": confidence,
		"requirements": requirements,
		"detected_sensitive_data": len(builtInPatterns["ssn"].FindAllString(content, -1)) > 0 ||
			len(builtInPatterns["credit_card"].FindAllString(content, -1)) > 0,
		"recommendation": getClassificationRecommendation(level),
	}
}

func getClassificationRecommendation(level string) string {
	recommendations := map[string]string{
		"confidential": "Encrypt at rest and in transit. Restrict access to authorized personnel only. Enable full audit logging.",
		"restricted":   "Limit access to need-to-know basis. Enable audit logging. Consider encryption.",
		"internal":     "Restrict to internal users only. Basic access controls recommended.",
		"public":       "No special protection required. Standard security practices apply.",
	}
	
	if rec, ok := recommendations[level]; ok {
		return rec
	}
	return recommendations["public"]
}

// Mock data generators

func generateMockDLPDashboard() DLPDashboard {
	return DLPDashboard{
		Overview: DLPOverview{
			TotalIncidents:  3847,
			IncidentsToday:  23,
			BlockedAttempts: 47,
			ActivePolicies:  12,
			RiskScore:       67,
			ComplianceRate:  94.5,
			DataProtected:   "15.2 TB",
			TrendPercentage: -12.5,
		},
		IncidentTrend: []TrendPoint{
			{Date: "2025-11-01", Incidents: 45, Blocked: 32},
			{Date: "2025-11-02", Incidents: 38, Blocked: 28},
			{Date: "2025-11-03", Incidents: 52, Blocked: 41},
			{Date: "2025-11-04", Incidents: 41, Blocked: 35},
			{Date: "2025-11-05", Incidents: 35, Blocked: 29},
			{Date: "2025-11-06", Incidents: 23, Blocked: 18},
		},
		TopPolicies: []PolicyStats{
			{PolicyID: "POL-001", PolicyName: "PII Protection Policy", IncidentCount: 1247, BlockRate: 85.3, Severity: "critical"},
			{PolicyID: "POL-002", PolicyName: "PCI-DSS Compliance", IncidentCount: 892, BlockRate: 92.1, Severity: "critical"},
			{PolicyID: "POL-003", PolicyName: "HIPAA PHI Protection", IncidentCount: 654, BlockRate: 88.7, Severity: "high"},
			{PolicyID: "POL-004", PolicyName: "Cloud Credentials", IncidentCount: 423, BlockRate: 98.2, Severity: "critical"},
			{PolicyID: "POL-005", PolicyName: "Source Code Protection", IncidentCount: 321, BlockRate: 76.4, Severity: "high"},
		},
		TopUsers: []UserStats{
			{User: "john.doe@company.com", IncidentCount: 12, RiskScore: 78, DataTypes: []string{"PII", "PCI"}},
			{User: "sarah.smith@company.com", IncidentCount: 9, RiskScore: 65, DataTypes: []string{"PHI"}},
			{User: "mike.johnson@company.com", IncidentCount: 7, RiskScore: 54, DataTypes: []string{"PII"}},
			{User: "emma.wilson@company.com", IncidentCount: 6, RiskScore: 48, DataTypes: []string{"Internal"}},
			{User: "david.brown@company.com", IncidentCount: 5, RiskScore: 42, DataTypes: []string{"PII", "Internal"}},
		},
		DataTypeBreakdown: []DataTypeStats{
			{DataType: "PII (Personal Info)", Count: 1547, Severity: "critical"},
			{DataType: "PCI (Payment Card)", Count: 892, Severity: "critical"},
			{DataType: "PHI (Health Info)", Count: 654, Severity: "high"},
			{DataType: "Cloud Credentials", Count: 423, Severity: "critical"},
			{DataType: "Source Code", Count: 331, Severity: "medium"},
		},
		ChannelStats: []ChannelStats{
			{Channel: "email", IncidentCount: 1842, BlockRate: 87.5},
			{Channel: "file_upload", IncidentCount: 1123, BlockRate: 91.2},
			{Channel: "api", IncidentCount: 567, BlockRate: 94.8},
			{Channel: "web_form", IncidentCount: 315, BlockRate: 82.3},
		},
		RecentIncidents: generateMockDLPIncidents()[:5],
	}
}

func generateMockDLPPolicies() []DLPPolicy {
	policies := []DLPPolicy{
		{
			ID:          "POL-001",
			Name:        "PII Protection Policy",
			Description: "Prevents unauthorized sharing of personally identifiable information",
			Status:      "active",
			Action:      "block",
			DataTypes:   []string{"pii"},
			Patterns:    []string{"ssn", "email", "phone", "address"},
			Severity:    "critical",
			Scope:       []string{"email", "file_upload", "api"},
			ExclusionRules: []string{"hr-department@company.com"},
			CreatedAt:   time.Now().AddDate(0, -6, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -2),
			CreatedBy:   "admin@company.com",
			IncidentCount: 1247,
		},
		{
			ID:          "POL-002",
			Name:        "PCI-DSS Compliance Policy",
			Description: "Protects payment card information in compliance with PCI-DSS",
			Status:      "active",
			Action:      "block",
			DataTypes:   []string{"pci"},
			Patterns:    []string{"credit_card", "cvv", "card_holder"},
			Severity:    "critical",
			Scope:       []string{"email", "file_upload", "api", "web_form"},
			ExclusionRules: []string{"payment-system@company.com"},
			CreatedAt:   time.Now().AddDate(0, -8, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -1),
			CreatedBy:   "security@company.com",
			IncidentCount: 892,
		},
		{
			ID:          "POL-003",
			Name:        "HIPAA PHI Protection",
			Description: "Safeguards protected health information under HIPAA regulations",
			Status:      "active",
			Action:      "encrypt",
			DataTypes:   []string{"phi"},
			Patterns:    []string{"medical_record", "patient_id", "diagnosis"},
			Severity:    "high",
			Scope:       []string{"email", "file_upload"},
			ExclusionRules: []string{"medical-staff@company.com"},
			CreatedAt:   time.Now().AddDate(0, -5, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -3),
			CreatedBy:   "compliance@company.com",
			IncidentCount: 654,
		},
		{
			ID:          "POL-004",
			Name:        "Cloud Credentials Protection",
			Description: "Prevents exposure of cloud service credentials and API keys",
			Status:      "active",
			Action:      "block",
			DataTypes:   []string{"credentials"},
			Patterns:    []string{"aws_key", "api_key", "private_key", "password"},
			Severity:    "critical",
			Scope:       []string{"email", "file_upload", "api"},
			ExclusionRules: []string{},
			CreatedAt:   time.Now().AddDate(0, -4, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -5),
			CreatedBy:   "devops@company.com",
			IncidentCount: 423,
		},
		{
			ID:          "POL-005",
			Name:        "Source Code Protection",
			Description: "Prevents unauthorized distribution of proprietary source code",
			Status:      "active",
			Action:      "alert",
			DataTypes:   []string{"confidential"},
			Patterns:    []string{"source_code", "proprietary"},
			Severity:    "high",
			Scope:       []string{"email", "file_upload"},
			ExclusionRules: []string{"engineering@company.com"},
			CreatedAt:   time.Now().AddDate(0, -3, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -7),
			CreatedBy:   "engineering@company.com",
			IncidentCount: 321,
		},
		{
			ID:          "POL-006",
			Name:        "GDPR Data Protection",
			Description: "Ensures GDPR compliance for EU citizen data",
			Status:      "active",
			Action:      "encrypt",
			DataTypes:   []string{"pii"},
			Patterns:    []string{"email", "phone", "address", "eu_citizen_id"},
			Severity:    "high",
			Scope:       []string{"email", "api", "web_form"},
			ExclusionRules: []string{"gdpr-officer@company.com"},
			CreatedAt:   time.Now().AddDate(0, -7, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -4),
			CreatedBy:   "compliance@company.com",
			IncidentCount: 278,
		},
		{
			ID:          "POL-007",
			Name:        "Financial Data Protection",
			Description: "Protects sensitive financial information and reports",
			Status:      "active",
			Action:      "quarantine",
			DataTypes:   []string{"confidential"},
			Patterns:    []string{"financial_statement", "bank_account", "routing_number"},
			Severity:    "high",
			Scope:       []string{"email", "file_upload"},
			ExclusionRules: []string{"finance@company.com"},
			CreatedAt:   time.Now().AddDate(0, -2, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -6),
			CreatedBy:   "cfo@company.com",
			IncidentCount: 189,
		},
		{
			ID:          "POL-008",
			Name:        "Intellectual Property Protection",
			Description: "Safeguards patents, trademarks, and IP documentation",
			Status:      "active",
			Action:      "alert",
			DataTypes:   []string{"confidential"},
			Patterns:    []string{"patent", "trademark", "trade_secret"},
			Severity:    "medium",
			Scope:       []string{"email", "file_upload"},
			ExclusionRules: []string{"legal@company.com"},
			CreatedAt:   time.Now().AddDate(0, -1, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -8),
			CreatedBy:   "legal@company.com",
			IncidentCount: 156,
		},
	}

	return policies
}

func generateMockDLPPolicyDetail(policyID string) DLPPolicy {
	policies := generateMockDLPPolicies()
	for _, policy := range policies {
		if policy.ID == policyID {
			return policy
		}
	}
	return policies[0]
}

func generateMockDLPIncidents() []DLPIncident {
	incidents := []DLPIncident{
		{
			ID:          "INC-DLP-001",
			PolicyID:    "POL-001",
			PolicyName:  "PII Protection Policy",
			Severity:    "critical",
			Status:      "open",
			Action:      "blocked",
			DataType:    "PII",
			Channel:     "email",
			Source:      "john.doe@company.com",
			Destination: "external@gmail.com",
			User:        "john.doe@company.com",
			DetectedData: []DetectedPattern{
				{Type: "SSN", Pattern: "Social Security Number", Value: "12*-**-****", Count: 3, Confidence: 95},
				{Type: "Phone", Pattern: "Phone Number", Value: "55*-***-****", Count: 2, Confidence: 80},
			},
			ContentPreview: "Dear Sir, Here are the employee records containing SSN: 123-45-6789...",
			RiskScore:      92,
			DetectedAt:     time.Now().Add(-2 * time.Hour),
			Notes:          "",
		},
		{
			ID:          "INC-DLP-002",
			PolicyID:    "POL-002",
			PolicyName:  "PCI-DSS Compliance Policy",
			Severity:    "critical",
			Status:      "investigating",
			Action:      "blocked",
			DataType:    "PCI",
			Channel:     "file_upload",
			Source:      "sarah.smith@company.com",
			Destination: "cloud-storage.com",
			User:        "sarah.smith@company.com",
			DetectedData: []DetectedPattern{
				{Type: "Credit Card", Pattern: "Credit Card Number", Value: "42**-****-****-5678", Count: 5, Confidence: 90},
			},
			ContentPreview: "Payment_records_Q4_2024.xlsx containing multiple credit card numbers...",
			RiskScore:      88,
			DetectedAt:     time.Now().Add(-5 * time.Hour),
			Notes:          "User contacted for verification",
		},
		{
			ID:          "INC-DLP-003",
			PolicyID:    "POL-004",
			PolicyName:  "Cloud Credentials Protection",
			Severity:    "critical",
			Status:      "resolved",
			Action:      "blocked",
			DataType:    "Credentials",
			Channel:     "api",
			Source:      "api-service",
			Destination: "public-repository",
			User:        "mike.johnson@company.com",
			DetectedData: []DetectedPattern{
				{Type: "AWS Key", Pattern: "AWS Access Key", Value: "AK**************", Count: 1, Confidence: 98},
			},
			ContentPreview: "config.json file containing AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE...",
			RiskScore:      95,
			DetectedAt:     time.Now().AddDate(0, 0, -1),
			ResolvedAt:     timePtr(time.Now().Add(-2 * time.Hour)),
			Notes:          "Key rotated and revoked. User trained on secure credential management.",
			CaseID:         "CASE-892",
		},
		{
			ID:          "INC-DLP-004",
			PolicyID:    "POL-003",
			PolicyName:  "HIPAA PHI Protection",
			Severity:    "high",
			Status:      "open",
			Action:      "encrypted",
			DataType:    "PHI",
			Channel:     "email",
			Source:      "doctor@company.com",
			Destination: "patient@email.com",
			User:        "doctor@company.com",
			DetectedData: []DetectedPattern{
				{Type: "Medical Record", Pattern: "Patient Medical Record", Value: "MR***789", Count: 1, Confidence: 85},
			},
			ContentPreview: "Patient diagnosis and treatment plan for MRN-123789...",
			RiskScore:      75,
			DetectedAt:     time.Now().Add(-3 * time.Hour),
			Notes:          "",
		},
		{
			ID:          "INC-DLP-005",
			PolicyID:    "POL-005",
			PolicyName:  "Source Code Protection",
			Severity:    "high",
			Status:      "false_positive",
			Action:      "alerted",
			DataType:    "Source Code",
			Channel:     "file_upload",
			Source:      "developer@company.com",
			Destination: "github-enterprise",
			User:        "developer@company.com",
			DetectedData: []DetectedPattern{
				{Type: "Source Code", Pattern: "Proprietary Code", Value: "main.go", Count: 1, Confidence: 70},
			},
			ContentPreview: "main.go - Company proprietary authentication module...",
			RiskScore:      62,
			DetectedAt:     time.Now().AddDate(0, 0, -2),
			ResolvedAt:     timePtr(time.Now().AddDate(0, 0, -1)),
			Notes:          "Approved upload to internal enterprise repository. False positive.",
		},
		{
			ID:          "INC-DLP-006",
			PolicyID:    "POL-001",
			PolicyName:  "PII Protection Policy",
			Severity:    "medium",
			Status:      "open",
			Action:      "alerted",
			DataType:    "PII",
			Channel:     "web_form",
			Source:      "contact-form",
			Destination: "crm-system",
			User:        "anonymous",
			DetectedData: []DetectedPattern{
				{Type: "Email", Pattern: "Email Address", Value: "us**@email.com", Count: 1, Confidence: 85},
				{Type: "Phone", Pattern: "Phone Number", Value: "55*-***-1234", Count: 1, Confidence: 80},
			},
			ContentPreview: "Contact form submission with personal information...",
			RiskScore:      45,
			DetectedAt:     time.Now().Add(-1 * time.Hour),
			Notes:          "",
		},
	}

	return incidents
}

func generateMockDLPIncidentDetail(incidentID string) DLPIncident {
	incidents := generateMockDLPIncidents()
	for _, incident := range incidents {
		if incident.ID == incidentID {
			return incident
		}
	}
	return incidents[0]
}

func generateMockDLPPatterns() []DLPPattern {
	patterns := []DLPPattern{
		{
			ID:          "PAT-001",
			Name:        "US Social Security Number",
			Type:        "regex",
			Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
			DataType:    "PII",
			Description: "Detects US Social Security Numbers in XXX-XX-XXXX format",
			Examples:    []string{"123-45-6789", "987-65-4321"},
			IsBuiltIn:   true,
			Enabled:     true,
			MatchCount:  1247,
			CreatedAt:   time.Now().AddDate(0, -6, 0),
		},
		{
			ID:          "PAT-002",
			Name:        "Credit Card Number",
			Type:        "regex",
			Pattern:     `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
			DataType:    "PCI",
			Description: "Detects credit card numbers (Visa, MasterCard, Amex, Discover)",
			Examples:    []string{"4111-1111-1111-1111", "5500 0000 0000 0004"},
			IsBuiltIn:   true,
			Enabled:     true,
			MatchCount:  892,
			CreatedAt:   time.Now().AddDate(0, -6, 0),
		},
		{
			ID:          "PAT-003",
			Name:        "Email Address",
			Type:        "regex",
			Pattern:     `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
			DataType:    "PII",
			Description: "Detects email addresses",
			Examples:    []string{"user@example.com", "john.doe@company.co.uk"},
			IsBuiltIn:   true,
			Enabled:     true,
			MatchCount:  3421,
			CreatedAt:   time.Now().AddDate(0, -6, 0),
		},
		{
			ID:          "PAT-004",
			Name:        "US Phone Number",
			Type:        "regex",
			Pattern:     `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`,
			DataType:    "PII",
			Description: "Detects US phone numbers in various formats",
			Examples:    []string{"555-123-4567", "555.123.4567", "5551234567"},
			IsBuiltIn:   true,
			Enabled:     true,
			MatchCount:  2156,
			CreatedAt:   time.Now().AddDate(0, -6, 0),
		},
		{
			ID:          "PAT-005",
			Name:        "AWS Access Key",
			Type:        "regex",
			Pattern:     `AKIA[0-9A-Z]{16}`,
			DataType:    "Credentials",
			Description: "Detects AWS access key IDs",
			Examples:    []string{"AKIAIOSFODNN7EXAMPLE"},
			IsBuiltIn:   true,
			Enabled:     true,
			MatchCount:  423,
			CreatedAt:   time.Now().AddDate(0, -6, 0),
		},
		{
			ID:          "PAT-006",
			Name:        "Private Key Header",
			Type:        "regex",
			Pattern:     `-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----`,
			DataType:    "Credentials",
			Description: "Detects RSA private key headers",
			Examples:    []string{"-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"},
			IsBuiltIn:   true,
			Enabled:     true,
			MatchCount:  87,
			CreatedAt:   time.Now().AddDate(0, -6, 0),
		},
		{
			ID:          "PAT-007",
			Name:        "IP Address",
			Type:        "regex",
			Pattern:     `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
			DataType:    "Technical",
			Description: "Detects IPv4 addresses",
			Examples:    []string{"192.168.1.1", "10.0.0.1"},
			IsBuiltIn:   true,
			Enabled:     true,
			MatchCount:  5643,
			CreatedAt:   time.Now().AddDate(0, -6, 0),
		},
		{
			ID:          "PAT-008",
			Name:        "Confidential Marker",
			Type:        "keyword",
			Pattern:     "confidential|secret|internal only|do not share|restricted",
			DataType:    "Confidential",
			Description: "Detects documents marked as confidential",
			Examples:    []string{"CONFIDENTIAL", "Internal Only - Do Not Share"},
			IsBuiltIn:   true,
			Enabled:     true,
			MatchCount:  1876,
			CreatedAt:   time.Now().AddDate(0, -6, 0),
		},
	}

	return patterns
}

func generateMockDataClassifications() []DataClassification {
	classifications := []DataClassification{
		{
			ID:          "CLASS-001",
			Name:        "Confidential",
			Level:       "confidential",
			Description: "Highly sensitive data requiring maximum protection",
			Requirements: []string{"encryption", "access_control", "audit_log", "mfa_required", "data_masking"},
			Color:       "#d32f2f",
			Icon:        "lock",
			PolicyCount: 5,
			DataCount:   125000,
			CreatedAt:   time.Now().AddDate(0, -12, 0),
		},
		{
			ID:          "CLASS-002",
			Name:        "Restricted",
			Level:       "restricted",
			Description: "Sensitive data with limited access",
			Requirements: []string{"access_control", "audit_log", "encryption"},
			Color:       "#f57c00",
			Icon:        "shield",
			PolicyCount: 3,
			DataCount:   458000,
			CreatedAt:   time.Now().AddDate(0, -12, 0),
		},
		{
			ID:          "CLASS-003",
			Name:        "Internal",
			Level:       "internal",
			Description: "Internal use only, not for external sharing",
			Requirements: []string{"access_control", "audit_log"},
			Color:       "#fbc02d",
			Icon:        "business",
			PolicyCount: 4,
			DataCount:   1250000,
			CreatedAt:   time.Now().AddDate(0, -12, 0),
		},
		{
			ID:          "CLASS-004",
			Name:        "Public",
			Level:       "public",
			Description: "Public information with no restrictions",
			Requirements: []string{},
			Color:       "#388e3c",
			Icon:        "public",
			PolicyCount: 0,
			DataCount:   3500000,
			CreatedAt:   time.Now().AddDate(0, -12, 0),
		},
	}

	return classifications
}

