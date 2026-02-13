package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// PCI-DSS Requirement
type PCIDSSRequirement struct {
	ID          string   `json:"id"`
	Number      string   `json:"number"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Priority    string   `json:"priority"`
	Status      string   `json:"status"`
	Compliance  float64  `json:"compliance"`
	Controls    []string `json:"controls"`
	Findings    int      `json:"findings"`
	Critical    int      `json:"critical"`
	High        int      `json:"high"`
	Medium      int      `json:"medium"`
	Low         int      `json:"low"`
	LastAudit   string   `json:"last_audit"`
}

// PCI-DSS Control
type PCIDSSControl struct {
	ID             string   `json:"id"`
	RequirementID  string   `json:"requirement_id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Type           string   `json:"type"`
	Status         string   `json:"status"`
	Compliance     float64  `json:"compliance"`
	AWSServices    []string `json:"aws_services"`
	ConfigRules    []string `json:"config_rules"`
	Findings       int      `json:"findings"`
	Automated      bool     `json:"automated"`
	RemediationIDs []string `json:"remediation_ids"`
	Evidence       []string `json:"evidence"`
	LastChecked    string   `json:"last_checked"`
}

// PCI-DSS Dashboard Metrics
type PCIDSSDashboard struct {
	OverallCompliance    float64                     `json:"overall_compliance"`
	TotalRequirements    int                         `json:"total_requirements"`
	CompliantReqs        int                         `json:"compliant_requirements"`
	NonCompliantReqs     int                         `json:"non_compliant_requirements"`
	PartialCompliantReqs int                         `json:"partial_compliant_requirements"`
	TotalControls        int                         `json:"total_controls"`
	ActiveControls       int                         `json:"active_controls"`
	AutomatedControls    int                         `json:"automated_controls"`
	TotalFindings        int                         `json:"total_findings"`
	CriticalFindings     int                         `json:"critical_findings"`
	HighFindings         int                         `json:"high_findings"`
	MediumFindings       int                         `json:"medium_findings"`
	LowFindings          int                         `json:"low_findings"`
	ComplianceByCategory map[string]float64          `json:"compliance_by_category"`
	ComplianceTrend      []PCIComplianceTrendPoint   `json:"compliance_trend"`
	TopIssues            []PCITopIssue               `json:"top_issues"`
	RequirementsSummary  []PCIRequirementSummary     `json:"requirements_summary"`
	AuditReadiness       PCIAuditReadiness           `json:"audit_readiness"`
	RecentChanges        []PCIComplianceChange       `json:"recent_changes"`
	LastAuditDate        string                      `json:"last_audit_date"`
	NextAuditDate        string                      `json:"next_audit_date"`
}

type PCIComplianceTrendPoint struct {
	Date       string  `json:"date"`
	Compliance float64 `json:"compliance"`
}

type PCITopIssue struct {
	Requirement string `json:"requirement"`
	Count       int    `json:"count"`
	Severity    string `json:"severity"`
	Impact      string `json:"impact"`
}

type PCIRequirementSummary struct {
	Number     string  `json:"number"`
	Title      string  `json:"title"`
	Compliance float64 `json:"compliance"`
	Status     string  `json:"status"`
}

type PCIAuditReadiness struct {
	Score            float64            `json:"score"`
	Status           string             `json:"status"`
	ReadyControls    int                `json:"ready_controls"`
	PendingControls  int                `json:"pending_controls"`
	FailedControls   int                `json:"failed_controls"`
	EvidenceComplete float64            `json:"evidence_complete"`
	Gaps             []PCIComplianceGap `json:"gaps"`
}

type PCIComplianceGap struct {
	Requirement string `json:"requirement"`
	Control     string `json:"control"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

type PCIComplianceChange struct {
	Timestamp   string  `json:"timestamp"`
	Requirement string  `json:"requirement"`
	ChangeType  string  `json:"change_type"`
	OldValue    float64 `json:"old_value"`
	NewValue    float64 `json:"new_value"`
	Impact      string  `json:"impact"`
}

// Mock data storage
var (
	pciRequirements []PCIDSSRequirement
	pciControls     []PCIDSSControl
)

// Initialize PCI-DSS data
func initPCIDSS() {
	// Initialize 12 main PCI-DSS requirements
	pciRequirements = []PCIDSSRequirement{
		{
			ID:          "pci-req-1",
			Number:      "1",
			Title:       "Install and maintain a firewall configuration",
			Description: "Firewalls are devices that control computer traffic allowed between an entity's networks and untrusted networks",
			Category:    "network_security",
			Priority:    "critical",
			Status:      "compliant",
			Compliance:  95.5,
			Controls:    []string{"pci-ctrl-1-1", "pci-ctrl-1-2", "pci-ctrl-1-3"},
			Findings:    2,
			Critical:    0,
			High:        1,
			Medium:      1,
			Low:         0,
			LastAudit:   time.Now().AddDate(0, 0, -5).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-2",
			Number:      "2",
			Title:       "Do not use vendor-supplied defaults",
			Description: "Malicious individuals use vendor default passwords and other settings to compromise systems",
			Category:    "configuration",
			Priority:    "high",
			Status:      "partial_compliant",
			Compliance:  78.3,
			Controls:    []string{"pci-ctrl-2-1", "pci-ctrl-2-2"},
			Findings:    8,
			Critical:    2,
			High:        3,
			Medium:      3,
			Low:         0,
			LastAudit:   time.Now().AddDate(0, 0, -3).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-3",
			Number:      "3",
			Title:       "Protect stored cardholder data",
			Description: "Protection methods such as encryption, truncation, masking, and hashing are critical components of cardholder data protection",
			Category:    "data_protection",
			Priority:    "critical",
			Status:      "compliant",
			Compliance:  92.1,
			Controls:    []string{"pci-ctrl-3-1", "pci-ctrl-3-2", "pci-ctrl-3-3", "pci-ctrl-3-4"},
			Findings:    3,
			Critical:    0,
			High:        2,
			Medium:      1,
			Low:         0,
			LastAudit:   time.Now().AddDate(0, 0, -2).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-4",
			Number:      "4",
			Title:       "Encrypt transmission of cardholder data",
			Description: "Encryption of cardholder data during transmission over open, public networks",
			Category:    "data_protection",
			Priority:    "critical",
			Status:      "compliant",
			Compliance:  98.7,
			Controls:    []string{"pci-ctrl-4-1", "pci-ctrl-4-2"},
			Findings:    1,
			Critical:    0,
			High:        0,
			Medium:      1,
			Low:         0,
			LastAudit:   time.Now().AddDate(0, 0, -1).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-5",
			Number:      "5",
			Title:       "Protect all systems against malware",
			Description: "Deploy anti-virus software on all systems commonly affected by malicious software",
			Category:    "malware_protection",
			Priority:    "high",
			Status:      "compliant",
			Compliance:  88.9,
			Controls:    []string{"pci-ctrl-5-1", "pci-ctrl-5-2"},
			Findings:    4,
			Critical:    0,
			High:        1,
			Medium:      2,
			Low:         1,
			LastAudit:   time.Now().AddDate(0, 0, -7).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-6",
			Number:      "6",
			Title:       "Develop and maintain secure systems",
			Description: "Unscrupulous individuals use security vulnerabilities to gain privileged access to systems",
			Category:    "vulnerability_management",
			Priority:    "critical",
			Status:      "partial_compliant",
			Compliance:  72.5,
			Controls:    []string{"pci-ctrl-6-1", "pci-ctrl-6-2", "pci-ctrl-6-3"},
			Findings:    12,
			Critical:    3,
			High:        5,
			Medium:      4,
			Low:         0,
			LastAudit:   time.Now().AddDate(0, 0, -4).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-7",
			Number:      "7",
			Title:       "Restrict access to cardholder data",
			Description: "Access to critical data must be restricted to only those with business need-to-know",
			Category:    "access_control",
			Priority:    "critical",
			Status:      "compliant",
			Compliance:  91.3,
			Controls:    []string{"pci-ctrl-7-1", "pci-ctrl-7-2"},
			Findings:    3,
			Critical:    0,
			High:        1,
			Medium:      2,
			Low:         0,
			LastAudit:   time.Now().AddDate(0, 0, -6).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-8",
			Number:      "8",
			Title:       "Identify and authenticate access",
			Description: "Assign a unique identification (ID) to each person with computer access",
			Category:    "access_control",
			Priority:    "critical",
			Status:      "partial_compliant",
			Compliance:  82.7,
			Controls:    []string{"pci-ctrl-8-1", "pci-ctrl-8-2", "pci-ctrl-8-3"},
			Findings:    6,
			Critical:    1,
			High:        2,
			Medium:      3,
			Low:         0,
			LastAudit:   time.Now().AddDate(0, 0, -8).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-9",
			Number:      "9",
			Title:       "Restrict physical access to cardholder data",
			Description: "Any physical access to data or systems that house cardholder data provides the opportunity for individuals to access and/or remove systems or hardcopies",
			Category:    "physical_security",
			Priority:    "high",
			Status:      "compliant",
			Compliance:  94.2,
			Controls:    []string{"pci-ctrl-9-1", "pci-ctrl-9-2"},
			Findings:    2,
			Critical:    0,
			High:        0,
			Medium:      2,
			Low:         0,
			LastAudit:   time.Now().AddDate(0, 0, -10).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-10",
			Number:      "10",
			Title:       "Track and monitor all access",
			Description: "Logging mechanisms and the ability to track user activities are critical in preventing, detecting, or minimizing the impact of a data compromise",
			Category:    "monitoring",
			Priority:    "critical",
			Status:      "compliant",
			Compliance:  96.8,
			Controls:    []string{"pci-ctrl-10-1", "pci-ctrl-10-2", "pci-ctrl-10-3"},
			Findings:    1,
			Critical:    0,
			High:        0,
			Medium:      1,
			Low:         0,
			LastAudit:   time.Now().AddDate(0, 0, -3).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-11",
			Number:      "11",
			Title:       "Regularly test security systems",
			Description: "Vulnerabilities are being discovered continually by malicious individuals and researchers, and being introduced by new software",
			Category:    "security_testing",
			Priority:    "critical",
			Status:      "partial_compliant",
			Compliance:  75.4,
			Controls:    []string{"pci-ctrl-11-1", "pci-ctrl-11-2"},
			Findings:    9,
			Critical:    2,
			High:        4,
			Medium:      3,
			Low:         0,
			LastAudit:   time.Now().AddDate(0, 0, -11).Format(time.RFC3339),
		},
		{
			ID:          "pci-req-12",
			Number:      "12",
			Title:       "Maintain an information security policy",
			Description: "A strong security policy sets the security tone for the whole entity and informs personnel what is expected of them",
			Category:    "policy",
			Priority:    "high",
			Status:      "compliant",
			Compliance:  89.6,
			Controls:    []string{"pci-ctrl-12-1", "pci-ctrl-12-2"},
			Findings:    4,
			Critical:    0,
			High:        1,
			Medium:      2,
			Low:         1,
			LastAudit:   time.Now().AddDate(0, 0, -5).Format(time.RFC3339),
		},
	}

	// Initialize sample controls
	pciControls = []PCIDSSControl{
		{
			ID:             "pci-ctrl-1-1",
			RequirementID:  "pci-req-1",
			Name:           "Firewall Configuration Standard",
			Description:    "Establish firewall and router configuration standards",
			Type:           "preventive",
			Status:         "active",
			Compliance:     95.0,
			AWSServices:    []string{"VPC", "Security Groups", "Network ACLs", "WAF"},
			ConfigRules:    []string{"vpc-sg-open-only-to-authorized-ports", "restricted-ssh"},
			Findings:       2,
			Automated:      true,
			RemediationIDs: []string{"rem-sg-restrict"},
			Evidence:       []string{"config-snapshot-sg-001.json", "vpc-flow-logs.csv"},
			LastChecked:    time.Now().AddDate(0, 0, -1).Format(time.RFC3339),
		},
		{
			ID:             "pci-ctrl-3-1",
			RequirementID:  "pci-req-3",
			Name:           "Data Encryption at Rest",
			Description:    "Encrypt stored cardholder data using strong cryptography",
			Type:           "detective",
			Status:         "active",
			Compliance:     92.0,
			AWSServices:    []string{"S3", "EBS", "RDS", "KMS"},
			ConfigRules:    []string{"encrypted-volumes", "s3-bucket-server-side-encryption-enabled", "rds-storage-encrypted"},
			Findings:       3,
			Automated:      true,
			RemediationIDs: []string{"rem-enable-ebs-encryption", "rem-enable-rds-encryption"},
			Evidence:       []string{"kms-key-policy.json", "s3-encryption-config.json"},
			LastChecked:    time.Now().Format(time.RFC3339),
		},
		{
			ID:             "pci-ctrl-4-1",
			RequirementID:  "pci-req-4",
			Name:           "TLS Encryption in Transit",
			Description:    "Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission",
			Type:           "preventive",
			Status:         "active",
			Compliance:     98.5,
			AWSServices:    []string{"ELB", "CloudFront", "ACM"},
			ConfigRules:    []string{"elb-tls-https-listeners-only", "cloudfront-sni-enabled"},
			Findings:       1,
			Automated:      true,
			RemediationIDs: []string{},
			Evidence:       []string{"acm-certificate.pem", "elb-listener-config.json"},
			LastChecked:    time.Now().Format(time.RFC3339),
		},
		{
			ID:             "pci-ctrl-6-1",
			RequirementID:  "pci-req-6",
			Name:           "Vulnerability Scanning",
			Description:    "Establish a process to identify security vulnerabilities",
			Type:           "detective",
			Status:         "active",
			Compliance:     72.0,
			AWSServices:    []string{"Inspector", "Systems Manager"},
			ConfigRules:    []string{"ec2-managedinstance-patch-compliance-status-check"},
			Findings:       12,
			Automated:      true,
			RemediationIDs: []string{},
			Evidence:       []string{"inspector-findings.json", "patch-compliance-report.csv"},
			LastChecked:    time.Now().AddDate(0, 0, -2).Format(time.RFC3339),
		},
		{
			ID:             "pci-ctrl-7-1",
			RequirementID:  "pci-req-7",
			Name:           "Access Control System",
			Description:    "Limit access to system components and cardholder data to only those with business need-to-know",
			Type:           "preventive",
			Status:         "active",
			Compliance:     91.0,
			AWSServices:    []string{"IAM", "Organizations", "STS"},
			ConfigRules:    []string{"iam-user-mfa-enabled", "iam-password-policy", "access-keys-rotated"},
			Findings:       3,
			Automated:      true,
			RemediationIDs: []string{"rem-enable-mfa"},
			Evidence:       []string{"iam-policy-analysis.json", "access-review-log.csv"},
			LastChecked:    time.Now().Format(time.RFC3339),
		},
		{
			ID:             "pci-ctrl-10-1",
			RequirementID:  "pci-req-10",
			Name:           "Audit Trail Logging",
			Description:    "Implement automated audit trails for all system components",
			Type:           "detective",
			Status:         "active",
			Compliance:     96.5,
			AWSServices:    []string{"CloudTrail", "CloudWatch Logs", "Config"},
			ConfigRules:    []string{"cloud-trail-enabled", "cloudwatch-alarm-action-check"},
			Findings:       1,
			Automated:      true,
			RemediationIDs: []string{"rem-enable-cloudtrail"},
			Evidence:       []string{"cloudtrail-logs/", "cloudwatch-metrics.json"},
			LastChecked:    time.Now().Format(time.RFC3339),
		},
	}
}

// Handler: Get PCI-DSS Dashboard
func (s *APIServer) handleGetPCIDSSDashboard(c *gin.Context) {
	// Calculate metrics
	totalReqs := len(pciRequirements)
	compliantReqs := 0
	nonCompliantReqs := 0
	partialCompliantReqs := 0
	totalFindings := 0
	criticalFindings := 0
	highFindings := 0
	mediumFindings := 0
	lowFindings := 0
	complianceSum := 0.0

	complianceByCategory := make(map[string]float64)
	categoryCount := make(map[string]int)

	for _, req := range pciRequirements {
		complianceSum += req.Compliance

		if req.Status == "compliant" {
			compliantReqs++
		} else if req.Status == "non_compliant" {
			nonCompliantReqs++
		} else if req.Status == "partial_compliant" {
			partialCompliantReqs++
		}

		totalFindings += req.Findings
		criticalFindings += req.Critical
		highFindings += req.High
		mediumFindings += req.Medium
		lowFindings += req.Low

		// Calculate by category
		complianceByCategory[req.Category] += req.Compliance
		categoryCount[req.Category]++
	}

	// Average compliance by category
	for category := range complianceByCategory {
		complianceByCategory[category] = complianceByCategory[category] / float64(categoryCount[category])
	}

	overallCompliance := complianceSum / float64(totalReqs)

	// Generate compliance trend (last 30 days)
	complianceTrend := []PCIComplianceTrendPoint{
		{Date: time.Now().AddDate(0, 0, -30).Format("2006-01-02"), Compliance: 82.5},
		{Date: time.Now().AddDate(0, 0, -25).Format("2006-01-02"), Compliance: 84.2},
		{Date: time.Now().AddDate(0, 0, -20).Format("2006-01-02"), Compliance: 85.8},
		{Date: time.Now().AddDate(0, 0, -15).Format("2006-01-02"), Compliance: 86.9},
		{Date: time.Now().AddDate(0, 0, -10).Format("2006-01-02"), Compliance: 87.5},
		{Date: time.Now().AddDate(0, 0, -5).Format("2006-01-02"), Compliance: 88.1},
		{Date: time.Now().Format("2006-01-02"), Compliance: overallCompliance},
	}

	// Top issues
	topIssues := []PCITopIssue{
		{Requirement: "Req 6 - Secure Systems", Count: 12, Severity: "critical", Impact: "high"},
		{Requirement: "Req 11 - Security Testing", Count: 9, Severity: "high", Impact: "medium"},
		{Requirement: "Req 2 - Default Passwords", Count: 8, Severity: "critical", Impact: "high"},
		{Requirement: "Req 8 - Authentication", Count: 6, Severity: "high", Impact: "medium"},
		{Requirement: "Req 5 - Malware Protection", Count: 4, Severity: "medium", Impact: "low"},
	}

	// Requirements summary
	requirementsSummary := []PCIRequirementSummary{}
	for _, req := range pciRequirements {
		requirementsSummary = append(requirementsSummary, PCIRequirementSummary{
			Number:     req.Number,
			Title:      req.Title,
			Compliance: req.Compliance,
			Status:     req.Status,
		})
	}

	// Audit readiness
	auditReadiness := PCIAuditReadiness{
		Score:            overallCompliance,
		Status:           "ready",
		ReadyControls:    18,
		PendingControls:  4,
		FailedControls:   2,
		EvidenceComplete: 85.5,
		Gaps: []PCIComplianceGap{
			{
				Requirement: "Req 6",
				Control:     "Vulnerability Scanning",
				Severity:    "critical",
				Description: "12 unpatched vulnerabilities detected",
				Remediation: "Apply security patches and update systems",
			},
			{
				Requirement: "Req 11",
				Control:     "Penetration Testing",
				Severity:    "high",
				Description: "Annual penetration test overdue",
				Remediation: "Schedule and complete penetration testing",
			},
			{
				Requirement: "Req 2",
				Control:     "Default Passwords",
				Severity:    "critical",
				Description: "8 systems still using default configurations",
				Remediation: "Change all default passwords and configurations",
			},
		},
	}

	if overallCompliance < 80 {
		auditReadiness.Status = "not_ready"
	} else if overallCompliance < 90 {
		auditReadiness.Status = "needs_improvement"
	}

	// Recent changes
	recentChanges := []PCIComplianceChange{
		{
			Timestamp:   time.Now().AddDate(0, 0, -1).Format(time.RFC3339),
			Requirement: "Req 3 - Data Protection",
			ChangeType:  "improvement",
			OldValue:    89.5,
			NewValue:    92.1,
			Impact:      "positive",
		},
		{
			Timestamp:   time.Now().AddDate(0, 0, -3).Format(time.RFC3339),
			Requirement: "Req 6 - Secure Systems",
			ChangeType:  "degradation",
			OldValue:    75.2,
			NewValue:    72.5,
			Impact:      "negative",
		},
		{
			Timestamp:   time.Now().AddDate(0, 0, -5).Format(time.RFC3339),
			Requirement: "Req 10 - Monitoring",
			ChangeType:  "improvement",
			OldValue:    94.1,
			NewValue:    96.8,
			Impact:      "positive",
		},
	}

	dashboard := PCIDSSDashboard{
		OverallCompliance:    overallCompliance,
		TotalRequirements:    totalReqs,
		CompliantReqs:        compliantReqs,
		NonCompliantReqs:     nonCompliantReqs,
		PartialCompliantReqs: partialCompliantReqs,
		TotalControls:        len(pciControls),
		ActiveControls:       len(pciControls),
		AutomatedControls:    len(pciControls),
		TotalFindings:        totalFindings,
		CriticalFindings:     criticalFindings,
		HighFindings:         highFindings,
		MediumFindings:       mediumFindings,
		LowFindings:          lowFindings,
		ComplianceByCategory: complianceByCategory,
		ComplianceTrend:      complianceTrend,
		TopIssues:            topIssues,
		RequirementsSummary:  requirementsSummary,
		AuditReadiness:       auditReadiness,
		RecentChanges:        recentChanges,
		LastAuditDate:        time.Now().AddDate(0, -3, 0).Format("2006-01-02"),
		NextAuditDate:        time.Now().AddDate(0, 9, 0).Format("2006-01-02"),
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "success",
		"dashboard": dashboard,
	})
}

// Handler: List PCI-DSS Requirements
func (s *APIServer) handleListPCIDSSRequirements(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"requirements": pciRequirements,
	})
}

// Handler: Get PCI-DSS Requirement
func (s *APIServer) handleGetPCIDSSRequirement(c *gin.Context) {
	id := c.Param("id")

	for _, req := range pciRequirements {
		if req.ID == id {
			// Get associated controls
			var controls []PCIDSSControl
			for _, ctrl := range pciControls {
				if ctrl.RequirementID == id {
					controls = append(controls, ctrl)
				}
			}

			c.JSON(http.StatusOK, gin.H{
				"status":      "success",
				"requirement": req,
				"controls":    controls,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"status":  "error",
		"message": "Requirement not found",
	})
}

// Handler: List PCI-DSS Controls
func (s *APIServer) handleListPCIDSSControls(c *gin.Context) {
	requirementID := c.Query("requirement_id")

	if requirementID != "" {
		var filtered []PCIDSSControl
		for _, ctrl := range pciControls {
			if ctrl.RequirementID == requirementID {
				filtered = append(filtered, ctrl)
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"status":   "success",
			"controls": filtered,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "success",
		"controls": pciControls,
	})
}

// Handler: Get PCI-DSS Control
func (s *APIServer) handleGetPCIDSSControl(c *gin.Context) {
	id := c.Param("id")

	for _, ctrl := range pciControls {
		if ctrl.ID == id {
			c.JSON(http.StatusOK, gin.H{
				"status":  "success",
				"control": ctrl,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"status":  "error",
		"message": "Control not found",
	})
}

