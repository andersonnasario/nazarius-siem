package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/opensearch-project/opensearch-go/v2/opensearchapi"
)

// ============================================================================
// PLA - PROTECTION LEVEL AGREEMENTS
// Risk Matrix with Guard Rails Assessment
// ============================================================================

// PLAAssessment represents a vulnerability risk assessment with guard rails
type PLAAssessment struct {
	ID                  string                 `json:"id"`
	VulnerabilityID     string                 `json:"vulnerability_id"`
	VulnerabilityTitle  string                 `json:"vulnerability_title"`
	CVEID               string                 `json:"cve_id"`
	CVSSScore           float64                `json:"cvss_score"`
	
	// Asset Information
	AssetID             string                 `json:"asset_id"`
	AssetName           string                 `json:"asset_name"`
	AssetType           string                 `json:"asset_type"` // ec2, ecr, lambda, rds, s3
	AssetCriticality    string                 `json:"asset_criticality"` // critical, high, medium, low
	BusinessUnit        string                 `json:"business_unit"`
	DataClassification  string                 `json:"data_classification"` // confidential, internal, public
	
	// Exposure Analysis
	ExposureLevel       string                 `json:"exposure_level"` // internet, dmz, internal, isolated
	AttackVector        string                 `json:"attack_vector"` // network, adjacent, local, physical
	ExploitAvailable    bool                   `json:"exploit_available"`
	ExploitMaturity     string                 `json:"exploit_maturity"` // weaponized, poc, theoretical, none
	
	// Risk Calculation - Inherent Risk
	InherentProbability float64                `json:"inherent_probability"` // 0-1
	InherentImpact      float64                `json:"inherent_impact"` // 0-1
	InherentRiskScore   float64                `json:"inherent_risk_score"` // 0-100
	InherentRiskLevel   string                 `json:"inherent_risk_level"` // critical, high, medium, low
	
	// Guard Rails Applied
	GuardRails          []AppliedGuardRail     `json:"guard_rails"`
	TotalMitigation     float64                `json:"total_mitigation"` // 0-1 (percentage of risk mitigated)
	
	// Risk Calculation - Residual Risk (after guard rails)
	ResidualProbability float64                `json:"residual_probability"` // 0-1
	ResidualImpact      float64                `json:"residual_impact"` // 0-1
	ResidualRiskScore   float64                `json:"residual_risk_score"` // 0-100
	ResidualRiskLevel   string                 `json:"residual_risk_level"` // critical, high, medium, low
	
	// PLA Compliance
	PLATier             string                 `json:"pla_tier"` // platinum, gold, silver, bronze
	RemediationSLA      int                    `json:"remediation_sla_days"` // SLA in days based on residual risk
	SLADeadline         time.Time              `json:"sla_deadline"`
	SLAStatus           string                 `json:"sla_status"` // on_track, at_risk, breached
	DaysRemaining       int                    `json:"days_remaining"`
	
	// Final Score and Recommendation
	FinalScore          float64                `json:"final_score"` // 0-100 (higher = more urgent)
	Priority            int                    `json:"priority"` // 1-5 (1 = most urgent)
	Recommendation      string                 `json:"recommendation"`
	AcceptedRisk        bool                   `json:"accepted_risk"`
	AcceptedBy          string                 `json:"accepted_by,omitempty"`
	AcceptedAt          *time.Time             `json:"accepted_at,omitempty"`
	AcceptanceReason    string                 `json:"acceptance_reason,omitempty"`
	
	// Metadata
	Status              string                 `json:"status"` // pending, in_progress, remediated, accepted, expired
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	CreatedBy           string                 `json:"created_by"`
	AssignedTo          string                 `json:"assigned_to,omitempty"`
	Notes               string                 `json:"notes,omitempty"`
}

// AppliedGuardRail represents a guard rail applied to mitigate a vulnerability
type AppliedGuardRail struct {
	GuardRailID         string  `json:"guard_rail_id"`
	GuardRailName       string  `json:"guard_rail_name"`
	Category            string  `json:"category"`
	EffectivenessScore  float64 `json:"effectiveness_score"` // 0-1
	Status              string  `json:"status"` // active, partial, inactive
	Evidence            string  `json:"evidence,omitempty"`
	VerifiedAt          *time.Time `json:"verified_at,omitempty"`
	VerifiedBy          string  `json:"verified_by,omitempty"`
}

// GuardRail represents a security control that can mitigate vulnerabilities
type GuardRail struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	Category            string   `json:"category"` // network, identity, detection, protection, recovery
	Type                string   `json:"type"` // preventive, detective, corrective, compensating
	Provider            string   `json:"provider"` // aws, fortinet, internal, third_party
	
	// Effectiveness by attack vector
	NetworkEffectiveness    float64 `json:"network_effectiveness"` // 0-1
	LocalEffectiveness      float64 `json:"local_effectiveness"` // 0-1
	PhysicalEffectiveness   float64 `json:"physical_effectiveness"` // 0-1
	
	// Effectiveness by vulnerability type
	VulnTypeEffectiveness   map[string]float64 `json:"vuln_type_effectiveness"`
	
	// Integration status
	IntegrationStatus   string   `json:"integration_status"` // integrated, manual, planned
	AutoDetect          bool     `json:"auto_detect"` // Can be auto-detected from AWS/Fortinet
	DataSource          string   `json:"data_source,omitempty"` // guardduty, fortinet, waf, etc.
	
	// Metadata
	Enabled             bool     `json:"enabled"`
	LastVerified        *time.Time `json:"last_verified,omitempty"`
}

// PLAConfiguration defines the PLA tiers and SLAs
type PLAConfiguration struct {
	Tiers               []PLATier              `json:"tiers"`
	RiskThresholds      RiskThresholds         `json:"risk_thresholds"`
	SLAMatrix           map[string]map[string]int `json:"sla_matrix"` // [criticality][risk_level] = days
}

// PLATier defines a protection level tier
type PLATier struct {
	Name                string  `json:"name"`
	MinScore            float64 `json:"min_score"`
	MaxScore            float64 `json:"max_score"`
	Description         string  `json:"description"`
	Color               string  `json:"color"`
}

// RiskThresholds defines the thresholds for risk levels
type RiskThresholds struct {
	Critical            float64 `json:"critical"` // >= this = critical
	High                float64 `json:"high"`
	Medium              float64 `json:"medium"`
	Low                 float64 `json:"low"` // < medium = low
}

// PLADashboard represents the PLA dashboard data
type PLADashboard struct {
	Summary             PLASummary             `json:"summary"`
	RiskMatrix          [][]int                `json:"risk_matrix"` // 5x5 matrix [probability][impact]
	ByTier              map[string]int         `json:"by_tier"`
	BySLAStatus         map[string]int         `json:"by_sla_status"`
	ByCategory          map[string]int         `json:"by_category"`
	TopRisks            []PLAAssessment        `json:"top_risks"`
	GuardRailCoverage   []GuardRailCoverage    `json:"guard_rail_coverage"`
	TrendData           []PLATrendPoint        `json:"trend_data"`
	MitigationImpact    MitigationImpact       `json:"mitigation_impact"`
}

// PLASummary contains summary statistics
type PLASummary struct {
	TotalAssessments    int     `json:"total_assessments"`
	PendingRemediation  int     `json:"pending_remediation"`
	Remediated          int     `json:"remediated"`
	AcceptedRisks       int     `json:"accepted_risks"`
	SLABreached         int     `json:"sla_breached"`
	SLAAtRisk           int     `json:"sla_at_risk"`
	AverageRiskScore    float64 `json:"average_risk_score"`
	AverageMitigation   float64 `json:"average_mitigation"`
	CriticalCount       int     `json:"critical_count"`
	HighCount           int     `json:"high_count"`
	MediumCount         int     `json:"medium_count"`
	LowCount            int     `json:"low_count"`
}

// GuardRailCoverage shows coverage of a guard rail
type GuardRailCoverage struct {
	GuardRailID         string  `json:"guard_rail_id"`
	GuardRailName       string  `json:"guard_rail_name"`
	Category            string  `json:"category"`
	CoveragePercentage  float64 `json:"coverage_percentage"`
	AssetsProtected     int     `json:"assets_protected"`
	EffectivenessAvg    float64 `json:"effectiveness_avg"`
}

// PLATrendPoint represents a point in the trend chart
type PLATrendPoint struct {
	Date                string  `json:"date"`
	TotalRisk           float64 `json:"total_risk"`
	MitigatedRisk       float64 `json:"mitigated_risk"`
	NewVulnerabilities  int     `json:"new_vulnerabilities"`
	Remediated          int     `json:"remediated"`
}

// MitigationImpact shows the impact of guard rails
type MitigationImpact struct {
	TotalInherentRisk   float64 `json:"total_inherent_risk"`
	TotalResidualRisk   float64 `json:"total_residual_risk"`
	RiskReduction       float64 `json:"risk_reduction"` // percentage
	TopMitigatingControls []struct {
		Name            string  `json:"name"`
		RiskReduced     float64 `json:"risk_reduced"`
	} `json:"top_mitigating_controls"`
}

// In-memory storage (would be in OpenSearch in production)
var (
	plaAssessments     = make(map[string]*PLAAssessment)
	guardRails         = make(map[string]*GuardRail)
	plaConfig          *PLAConfiguration
	plaMutex           sync.RWMutex
)

// OpenSearch index names
const (
	PLAAssessmentIndex = "siem-pla-assessments"
	GuardRailsIndex    = "siem-guard-rails"
)

// Initialize PLA system
func initPLASystem() {
	plaMutex.Lock()
	defer plaMutex.Unlock()

	// Initialize default PLA configuration
	plaConfig = &PLAConfiguration{
		Tiers: []PLATier{
			{Name: "platinum", MinScore: 0, MaxScore: 25, Description: "Minimal Risk - Well Protected", Color: "#4CAF50"},
			{Name: "gold", MinScore: 25, MaxScore: 50, Description: "Low Risk - Adequately Protected", Color: "#8BC34A"},
			{Name: "silver", MinScore: 50, MaxScore: 75, Description: "Moderate Risk - Needs Attention", Color: "#FFC107"},
			{Name: "bronze", MinScore: 75, MaxScore: 100, Description: "High Risk - Immediate Action Required", Color: "#F44336"},
		},
		RiskThresholds: RiskThresholds{
			Critical: 80,
			High:     60,
			Medium:   40,
			Low:      0,
		},
		// SLA in days: [asset_criticality][risk_level]
		SLAMatrix: map[string]map[string]int{
			"critical": {"critical": 1, "high": 3, "medium": 7, "low": 30},
			"high":     {"critical": 3, "high": 7, "medium": 14, "low": 60},
			"medium":   {"critical": 7, "high": 14, "medium": 30, "low": 90},
			"low":      {"critical": 14, "high": 30, "medium": 60, "low": 180},
		},
	}

	// Initialize default guard rails catalog
	initDefaultGuardRails()

	log.Println("✅ PLA Risk Matrix system initialized")
}

// Initialize default guard rails
func initDefaultGuardRails() {
	defaultGuardRails := []GuardRail{
		// Network Controls
		{
			ID: "gr-fortinet-fw", Name: "Fortinet FortiGate Firewall",
			Description: "Network firewall with IPS/IDS capabilities",
			Category: "network", Type: "preventive", Provider: "fortinet",
			NetworkEffectiveness: 0.7, LocalEffectiveness: 0.2, PhysicalEffectiveness: 0.0,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.9, "PACKAGE_VULNERABILITY": 0.3, "CODE_VULNERABILITY": 0.2,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "fortinet",
			Enabled: true,
		},
		{
			ID: "gr-aws-waf", Name: "AWS WAF",
			Description: "Web Application Firewall for HTTP/HTTPS traffic",
			Category: "network", Type: "preventive", Provider: "aws",
			NetworkEffectiveness: 0.8, LocalEffectiveness: 0.0, PhysicalEffectiveness: 0.0,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.7, "PACKAGE_VULNERABILITY": 0.4, "CODE_VULNERABILITY": 0.6,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "waf",
			Enabled: true,
		},
		{
			ID: "gr-sg", Name: "AWS Security Groups",
			Description: "Instance-level network access control",
			Category: "network", Type: "preventive", Provider: "aws",
			NetworkEffectiveness: 0.6, LocalEffectiveness: 0.1, PhysicalEffectiveness: 0.0,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.8, "PACKAGE_VULNERABILITY": 0.2, "CODE_VULNERABILITY": 0.1,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "ec2",
			Enabled: true,
		},
		{
			ID: "gr-nacl", Name: "AWS Network ACLs",
			Description: "Subnet-level network access control",
			Category: "network", Type: "preventive", Provider: "aws",
			NetworkEffectiveness: 0.5, LocalEffectiveness: 0.0, PhysicalEffectiveness: 0.0,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.7, "PACKAGE_VULNERABILITY": 0.1, "CODE_VULNERABILITY": 0.1,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "vpc",
			Enabled: true,
		},
		{
			ID: "gr-vpc-isolation", Name: "VPC Network Isolation",
			Description: "Network segmentation via VPCs and subnets",
			Category: "network", Type: "preventive", Provider: "aws",
			NetworkEffectiveness: 0.7, LocalEffectiveness: 0.0, PhysicalEffectiveness: 0.0,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.8, "PACKAGE_VULNERABILITY": 0.2, "CODE_VULNERABILITY": 0.1,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "vpc",
			Enabled: true,
		},

		// Identity Controls
		{
			ID: "gr-iam-least-priv", Name: "IAM Least Privilege",
			Description: "Restrictive IAM policies following least privilege",
			Category: "identity", Type: "preventive", Provider: "aws",
			NetworkEffectiveness: 0.3, LocalEffectiveness: 0.7, PhysicalEffectiveness: 0.3,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.3, "PACKAGE_VULNERABILITY": 0.4, "CODE_VULNERABILITY": 0.5,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "iam",
			Enabled: true,
		},
		{
			ID: "gr-mfa", Name: "Multi-Factor Authentication",
			Description: "MFA enabled for all users and roles",
			Category: "identity", Type: "preventive", Provider: "aws",
			NetworkEffectiveness: 0.4, LocalEffectiveness: 0.8, PhysicalEffectiveness: 0.6,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.4, "PACKAGE_VULNERABILITY": 0.3, "CODE_VULNERABILITY": 0.3,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "iam",
			Enabled: true,
		},
		{
			ID: "gr-sso", Name: "Single Sign-On (SSO)",
			Description: "Centralized authentication via SSO",
			Category: "identity", Type: "preventive", Provider: "aws",
			NetworkEffectiveness: 0.3, LocalEffectiveness: 0.6, PhysicalEffectiveness: 0.4,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.3, "PACKAGE_VULNERABILITY": 0.2, "CODE_VULNERABILITY": 0.2,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "identity-center",
			Enabled: true,
		},

		// Detection Controls
		{
			ID: "gr-guardduty", Name: "AWS GuardDuty",
			Description: "Threat detection service for AWS accounts",
			Category: "detection", Type: "detective", Provider: "aws",
			NetworkEffectiveness: 0.6, LocalEffectiveness: 0.5, PhysicalEffectiveness: 0.0,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.7, "PACKAGE_VULNERABILITY": 0.4, "CODE_VULNERABILITY": 0.4,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "guardduty",
			Enabled: true,
		},
		{
			ID: "gr-cloudtrail", Name: "AWS CloudTrail",
			Description: "API activity logging and monitoring",
			Category: "detection", Type: "detective", Provider: "aws",
			NetworkEffectiveness: 0.4, LocalEffectiveness: 0.6, PhysicalEffectiveness: 0.2,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.4, "PACKAGE_VULNERABILITY": 0.3, "CODE_VULNERABILITY": 0.4,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "cloudtrail",
			Enabled: true,
		},
		{
			ID: "gr-fortinet-ips", Name: "Fortinet IPS/IDS",
			Description: "Intrusion Prevention/Detection System",
			Category: "detection", Type: "detective", Provider: "fortinet",
			NetworkEffectiveness: 0.8, LocalEffectiveness: 0.2, PhysicalEffectiveness: 0.0,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.9, "PACKAGE_VULNERABILITY": 0.5, "CODE_VULNERABILITY": 0.4,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "fortinet",
			Enabled: true,
		},
		{
			ID: "gr-siem", Name: "SIEM Monitoring (Nazarius)",
			Description: "Centralized security monitoring and alerting",
			Category: "detection", Type: "detective", Provider: "internal",
			NetworkEffectiveness: 0.5, LocalEffectiveness: 0.5, PhysicalEffectiveness: 0.3,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.6, "PACKAGE_VULNERABILITY": 0.5, "CODE_VULNERABILITY": 0.5,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "siem",
			Enabled: true,
		},
		{
			ID: "gr-securityhub", Name: "AWS Security Hub",
			Description: "Centralized security findings aggregation",
			Category: "detection", Type: "detective", Provider: "aws",
			NetworkEffectiveness: 0.4, LocalEffectiveness: 0.4, PhysicalEffectiveness: 0.2,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.5, "PACKAGE_VULNERABILITY": 0.6, "CODE_VULNERABILITY": 0.5,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "securityhub",
			Enabled: true,
		},

		// Protection Controls
		{
			ID: "gr-encryption-rest", Name: "Encryption at Rest",
			Description: "Data encrypted at rest using KMS",
			Category: "protection", Type: "preventive", Provider: "aws",
			NetworkEffectiveness: 0.1, LocalEffectiveness: 0.6, PhysicalEffectiveness: 0.9,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.2, "PACKAGE_VULNERABILITY": 0.3, "CODE_VULNERABILITY": 0.3,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "kms",
			Enabled: true,
		},
		{
			ID: "gr-encryption-transit", Name: "Encryption in Transit",
			Description: "TLS/SSL for all data in transit",
			Category: "protection", Type: "preventive", Provider: "aws",
			NetworkEffectiveness: 0.7, LocalEffectiveness: 0.3, PhysicalEffectiveness: 0.1,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.6, "PACKAGE_VULNERABILITY": 0.2, "CODE_VULNERABILITY": 0.3,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "config",
			Enabled: true,
		},
		{
			ID: "gr-patching", Name: "Automated Patch Management",
			Description: "Systems Manager automated patching",
			Category: "protection", Type: "corrective", Provider: "aws",
			NetworkEffectiveness: 0.3, LocalEffectiveness: 0.8, PhysicalEffectiveness: 0.3,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.3, "PACKAGE_VULNERABILITY": 0.9, "CODE_VULNERABILITY": 0.4,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "ssm",
			Enabled: true,
		},
		{
			ID: "gr-edr", Name: "Endpoint Detection & Response",
			Description: "EDR solution on endpoints",
			Category: "protection", Type: "detective", Provider: "third_party",
			NetworkEffectiveness: 0.4, LocalEffectiveness: 0.8, PhysicalEffectiveness: 0.5,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.4, "PACKAGE_VULNERABILITY": 0.6, "CODE_VULNERABILITY": 0.7,
			},
			IntegrationStatus: "manual", AutoDetect: false,
			Enabled: true,
		},

		// Recovery Controls
		{
			ID: "gr-backup", Name: "Automated Backups",
			Description: "Regular automated backups with retention",
			Category: "recovery", Type: "corrective", Provider: "aws",
			NetworkEffectiveness: 0.1, LocalEffectiveness: 0.3, PhysicalEffectiveness: 0.8,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.2, "PACKAGE_VULNERABILITY": 0.3, "CODE_VULNERABILITY": 0.3,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "backup",
			Enabled: true,
		},
		{
			ID: "gr-dr", Name: "Disaster Recovery Plan",
			Description: "Documented and tested DR procedures",
			Category: "recovery", Type: "corrective", Provider: "internal",
			NetworkEffectiveness: 0.2, LocalEffectiveness: 0.4, PhysicalEffectiveness: 0.7,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.3, "PACKAGE_VULNERABILITY": 0.4, "CODE_VULNERABILITY": 0.4,
			},
			IntegrationStatus: "manual", AutoDetect: false,
			Enabled: true,
		},
		{
			ID: "gr-playbook", Name: "Incident Response Playbooks",
			Description: "Automated incident response via SOAR",
			Category: "recovery", Type: "corrective", Provider: "internal",
			NetworkEffectiveness: 0.4, LocalEffectiveness: 0.5, PhysicalEffectiveness: 0.4,
			VulnTypeEffectiveness: map[string]float64{
				"NETWORK_REACHABILITY": 0.5, "PACKAGE_VULNERABILITY": 0.5, "CODE_VULNERABILITY": 0.5,
			},
			IntegrationStatus: "integrated", AutoDetect: true, DataSource: "playbooks",
			Enabled: true,
		},
	}

	for _, gr := range defaultGuardRails {
		guardRails[gr.ID] = &gr
	}
}

// ============================================================================
// RISK CALCULATION ENGINE
// ============================================================================

// CalculateRisk calculates the risk score for a vulnerability assessment
func CalculateRisk(assessment *PLAAssessment) {
	// Step 1: Calculate Inherent Probability
	assessment.InherentProbability = calculateProbability(assessment)
	
	// Step 2: Calculate Inherent Impact
	assessment.InherentImpact = calculateImpact(assessment)
	
	// Step 3: Calculate Inherent Risk Score (0-100)
	assessment.InherentRiskScore = assessment.InherentProbability * assessment.InherentImpact * 100
	assessment.InherentRiskLevel = getPLARiskLevel(assessment.InherentRiskScore)
	
	// Step 4: Calculate Mitigation from Guard Rails
	assessment.TotalMitigation = calculateMitigation(assessment)
	
	// Step 5: Calculate Residual Risk
	assessment.ResidualProbability = assessment.InherentProbability * (1 - assessment.TotalMitigation*0.7) // Guard rails mainly reduce probability
	assessment.ResidualImpact = assessment.InherentImpact * (1 - assessment.TotalMitigation*0.3) // Some impact reduction
	assessment.ResidualRiskScore = assessment.ResidualProbability * assessment.ResidualImpact * 100
	assessment.ResidualRiskLevel = getPLARiskLevel(assessment.ResidualRiskScore)
	
	// Step 6: Determine PLA Tier
	assessment.PLATier = getPLATier(assessment.ResidualRiskScore)
	
	// Step 7: Calculate SLA
	assessment.RemediationSLA = calculateSLA(assessment)
	assessment.SLADeadline = assessment.CreatedAt.AddDate(0, 0, assessment.RemediationSLA)
	assessment.DaysRemaining = int(time.Until(assessment.SLADeadline).Hours() / 24)
	assessment.SLAStatus = getSLAStatus(assessment)
	
	// Step 8: Calculate Final Score and Priority
	assessment.FinalScore = calculateFinalScore(assessment)
	assessment.Priority = getPriority(assessment.FinalScore)
	
	// Step 9: Generate Recommendation
	assessment.Recommendation = generateRecommendation(assessment)
}

func calculateProbability(a *PLAAssessment) float64 {
	probability := 0.0
	
	// Base probability from CVSS (normalized to 0-1)
	probability += (a.CVSSScore / 10) * 0.3
	
	// Exposure level factor
	exposureFactors := map[string]float64{
		"internet": 1.0,
		"dmz":      0.7,
		"internal": 0.4,
		"isolated": 0.1,
	}
	probability += exposureFactors[a.ExposureLevel] * 0.25
	
	// Exploit availability factor
	if a.ExploitAvailable {
		exploitFactors := map[string]float64{
			"weaponized":   1.0,
			"poc":          0.7,
			"theoretical":  0.4,
			"none":         0.1,
		}
		probability += exploitFactors[a.ExploitMaturity] * 0.25
	}
	
	// Attack vector factor
	vectorFactors := map[string]float64{
		"network":  1.0,
		"adjacent": 0.6,
		"local":    0.3,
		"physical": 0.1,
	}
	probability += vectorFactors[a.AttackVector] * 0.2
	
	return math.Min(probability, 1.0)
}

func calculateImpact(a *PLAAssessment) float64 {
	impact := 0.0
	
	// Asset criticality factor
	criticalityFactors := map[string]float64{
		"critical": 1.0,
		"high":     0.75,
		"medium":   0.5,
		"low":      0.25,
	}
	impact += criticalityFactors[a.AssetCriticality] * 0.4
	
	// Data classification factor
	dataFactors := map[string]float64{
		"confidential": 1.0,
		"internal":     0.6,
		"public":       0.2,
	}
	impact += dataFactors[a.DataClassification] * 0.3
	
	// CVSS impact (from base score)
	impact += (a.CVSSScore / 10) * 0.3
	
	return math.Min(impact, 1.0)
}

func calculateMitigation(a *PLAAssessment) float64 {
	if len(a.GuardRails) == 0 {
		return 0.0
	}
	
	totalMitigation := 0.0
	maxMitigation := 0.0
	
	for _, gr := range a.GuardRails {
		if gr.Status != "active" {
			continue
		}
		
		// Get effectiveness based on attack vector
		effectiveness := gr.EffectivenessScore
		
		// Diminishing returns for multiple controls
		contribution := effectiveness * (1 - totalMitigation*0.3)
		totalMitigation += contribution
		
		if effectiveness > maxMitigation {
			maxMitigation = effectiveness
		}
	}
	
	// Cap at 90% mitigation (can never fully eliminate risk)
	return math.Min(totalMitigation, 0.9)
}

func getPLARiskLevel(score float64) string {
	if score >= plaConfig.RiskThresholds.Critical {
		return "critical"
	} else if score >= plaConfig.RiskThresholds.High {
		return "high"
	} else if score >= plaConfig.RiskThresholds.Medium {
		return "medium"
	}
	return "low"
}

func getPLATier(score float64) string {
	for _, tier := range plaConfig.Tiers {
		if score >= tier.MinScore && score < tier.MaxScore {
			return tier.Name
		}
	}
	return "bronze"
}

func calculateSLA(a *PLAAssessment) int {
	criticality := a.AssetCriticality
	if criticality == "" {
		criticality = "medium"
	}
	
	riskLevel := a.ResidualRiskLevel
	if riskLevel == "" {
		riskLevel = "medium"
	}
	
	if slaByRisk, ok := plaConfig.SLAMatrix[criticality]; ok {
		if sla, ok := slaByRisk[riskLevel]; ok {
			return sla
		}
	}
	
	return 30 // Default 30 days
}

func getSLAStatus(a *PLAAssessment) string {
	if a.Status == "remediated" || a.AcceptedRisk {
		return "completed"
	}
	
	daysRemaining := int(time.Until(a.SLADeadline).Hours() / 24)
	
	if daysRemaining < 0 {
		return "breached"
	} else if daysRemaining <= 3 {
		return "at_risk"
	}
	return "on_track"
}

func calculateFinalScore(a *PLAAssessment) float64 {
	// Higher score = more urgent
	score := a.ResidualRiskScore
	
	// SLA urgency factor
	if a.DaysRemaining < 0 {
		score += 20 // Breached SLA
	} else if a.DaysRemaining <= 3 {
		score += 10 // At risk
	}
	
	// Exploit availability bonus
	if a.ExploitAvailable && a.ExploitMaturity == "weaponized" {
		score += 15
	}
	
	// Internet exposure bonus
	if a.ExposureLevel == "internet" {
		score += 10
	}
	
	return math.Min(score, 100)
}

func getPriority(score float64) int {
	if score >= 90 {
		return 1
	} else if score >= 70 {
		return 2
	} else if score >= 50 {
		return 3
	} else if score >= 30 {
		return 4
	}
	return 5
}

func generateRecommendation(a *PLAAssessment) string {
	recommendations := []string{}
	
	if a.ResidualRiskLevel == "critical" || a.ResidualRiskLevel == "high" {
		recommendations = append(recommendations, "URGENT: Immediate remediation required")
	}
	
	if a.ExposureLevel == "internet" && !hasGuardRail(a, "gr-aws-waf") {
		recommendations = append(recommendations, "Enable AWS WAF for internet-facing assets")
	}
	
	if a.ExploitAvailable && a.ExploitMaturity == "weaponized" {
		recommendations = append(recommendations, "Weaponized exploit available - prioritize patching")
	}
	
	if a.TotalMitigation < 0.3 {
		recommendations = append(recommendations, "Low guard rail coverage - review security controls")
	}
	
	if a.SLAStatus == "breached" {
		recommendations = append(recommendations, "SLA breached - escalate to management")
	}
	
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue monitoring and follow standard remediation process")
	}
	
	return strings.Join(recommendations, "; ")
}

func hasGuardRail(a *PLAAssessment, grID string) bool {
	for _, gr := range a.GuardRails {
		if gr.GuardRailID == grID && gr.Status == "active" {
			return true
		}
	}
	return false
}

// ============================================================================
// API HANDLERS
// ============================================================================

// handleCreatePLAAssessment creates a new PLA assessment from a vulnerability
func (s *APIServer) handleCreatePLAAssessment(c *gin.Context) {
	var req struct {
		VulnerabilityID    string   `json:"vulnerability_id" binding:"required"`
		AssetCriticality   string   `json:"asset_criticality"`
		BusinessUnit       string   `json:"business_unit"`
		DataClassification string   `json:"data_classification"`
		ExposureLevel      string   `json:"exposure_level"`
		GuardRailIDs       []string `json:"guard_rail_ids"`
		AssignedTo         string   `json:"assigned_to"`
		Notes              string   `json:"notes"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleCreatePLAAssessment bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	
	// Fetch vulnerability details from OpenSearch
	vuln, err := s.getVulnerabilityByID(req.VulnerabilityID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Vulnerability not found"})
		return
	}
	
	// Create assessment
	assessment := &PLAAssessment{
		ID:                 uuid.New().String(),
		VulnerabilityID:    req.VulnerabilityID,
		VulnerabilityTitle: vuln.Title,
		CVEID:              vuln.CVEID,
		CVSSScore:          vuln.CVSSScore,
		AssetID:            vuln.ResourceID,
		AssetName:          vuln.ResourceID,
		AssetType:          strings.ToLower(strings.TrimPrefix(vuln.ResourceType, "AWS_")),
		AssetCriticality:   req.AssetCriticality,
		BusinessUnit:       req.BusinessUnit,
		DataClassification: req.DataClassification,
		ExposureLevel:      req.ExposureLevel,
		AttackVector:       "network", // Default, can be parsed from CVSS
		ExploitAvailable:   vuln.ExploitAvailable,
		ExploitMaturity:    getExploitMaturity(vuln.ExploitAvailable),
		Status:             "pending",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		CreatedBy:          getUsernameFromContext(c),
		AssignedTo:         req.AssignedTo,
		Notes:              req.Notes,
	}
	
	// Set defaults if not provided
	if assessment.AssetCriticality == "" {
		assessment.AssetCriticality = "medium"
	}
	if assessment.DataClassification == "" {
		assessment.DataClassification = "internal"
	}
	if assessment.ExposureLevel == "" {
		assessment.ExposureLevel = "internal"
	}
	
	// Apply guard rails
	plaMutex.RLock()
	for _, grID := range req.GuardRailIDs {
		if gr, ok := guardRails[grID]; ok && gr.Enabled {
			now := time.Now()
			assessment.GuardRails = append(assessment.GuardRails, AppliedGuardRail{
				GuardRailID:        gr.ID,
				GuardRailName:      gr.Name,
				Category:           gr.Category,
				EffectivenessScore: gr.NetworkEffectiveness, // Use based on attack vector
				Status:             "active",
				VerifiedAt:         &now,
			})
		}
	}
	plaMutex.RUnlock()
	
	// Calculate all risk scores
	CalculateRisk(assessment)
	
	// Save to storage
	plaMutex.Lock()
	plaAssessments[assessment.ID] = assessment
	plaMutex.Unlock()
	
	// Index to OpenSearch
	s.indexPLAAssessment(assessment)
	
	c.JSON(http.StatusCreated, assessment)
}

// handleListPLAAssessments lists all PLA assessments
func (s *APIServer) handleListPLAAssessments(c *gin.Context) {
	status := c.Query("status")
	riskLevel := c.Query("risk_level")
	tier := c.Query("tier")
	slaStatus := c.Query("sla_status")
	
	plaMutex.RLock()
	defer plaMutex.RUnlock()
	
	assessments := []*PLAAssessment{}
	for _, a := range plaAssessments {
		if status != "" && a.Status != status {
			continue
		}
		if riskLevel != "" && a.ResidualRiskLevel != riskLevel {
			continue
		}
		if tier != "" && a.PLATier != tier {
			continue
		}
		if slaStatus != "" && a.SLAStatus != slaStatus {
			continue
		}
		assessments = append(assessments, a)
	}
	
	c.JSON(http.StatusOK, gin.H{
		"assessments": assessments,
		"total":       len(assessments),
	})
}

// handleGetPLAAssessment returns a specific assessment
func (s *APIServer) handleGetPLAAssessment(c *gin.Context) {
	id := c.Param("id")
	
	plaMutex.RLock()
	assessment, exists := plaAssessments[id]
	plaMutex.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Assessment not found"})
		return
	}
	
	c.JSON(http.StatusOK, assessment)
}

// handleUpdatePLAAssessment updates an assessment
func (s *APIServer) handleUpdatePLAAssessment(c *gin.Context) {
	id := c.Param("id")
	
	plaMutex.Lock()
	defer plaMutex.Unlock()
	
	assessment, exists := plaAssessments[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Assessment not found"})
		return
	}
	
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		log.Printf("[ERROR] handleUpdatePLAAssessment bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	
	// Update fields
	if status, ok := updates["status"].(string); ok {
		assessment.Status = status
	}
	if assignedTo, ok := updates["assigned_to"].(string); ok {
		assessment.AssignedTo = assignedTo
	}
	if notes, ok := updates["notes"].(string); ok {
		assessment.Notes = notes
	}
	if acceptedRisk, ok := updates["accepted_risk"].(bool); ok {
		assessment.AcceptedRisk = acceptedRisk
		if acceptedRisk {
			now := time.Now()
			assessment.AcceptedAt = &now
			assessment.AcceptedBy = getUsernameFromContext(c)
			if reason, ok := updates["acceptance_reason"].(string); ok {
				assessment.AcceptanceReason = reason
			}
		}
	}
	
	assessment.UpdatedAt = time.Now()
	
	// Recalculate risk
	CalculateRisk(assessment)
	
	c.JSON(http.StatusOK, assessment)
}

// handleAddGuardRailToAssessment adds a guard rail to an assessment
func (s *APIServer) handleAddGuardRailToAssessment(c *gin.Context) {
	id := c.Param("id")
	
	var req struct {
		GuardRailID string `json:"guard_rail_id" binding:"required"`
		Status      string `json:"status"`
		Evidence    string `json:"evidence"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleAddGuardRailToAssessment bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	
	plaMutex.Lock()
	defer plaMutex.Unlock()
	
	assessment, exists := plaAssessments[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Assessment not found"})
		return
	}
	
	gr, grExists := guardRails[req.GuardRailID]
	if !grExists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Guard rail not found"})
		return
	}
	
	status := req.Status
	if status == "" {
		status = "active"
	}
	
	now := time.Now()
	assessment.GuardRails = append(assessment.GuardRails, AppliedGuardRail{
		GuardRailID:        gr.ID,
		GuardRailName:      gr.Name,
		Category:           gr.Category,
		EffectivenessScore: gr.NetworkEffectiveness,
		Status:             status,
		Evidence:           req.Evidence,
		VerifiedAt:         &now,
		VerifiedBy:         getUsernameFromContext(c),
	})
	
	// Recalculate risk
	CalculateRisk(assessment)
	assessment.UpdatedAt = time.Now()
	
	c.JSON(http.StatusOK, assessment)
}

// handleListGuardRails lists all available guard rails
func (s *APIServer) handleListGuardRails(c *gin.Context) {
	category := c.Query("category")
	
	plaMutex.RLock()
	defer plaMutex.RUnlock()
	
	result := []*GuardRail{}
	for _, gr := range guardRails {
		if category != "" && gr.Category != category {
			continue
		}
		if gr.Enabled {
			result = append(result, gr)
		}
	}
	
	c.JSON(http.StatusOK, gin.H{
		"guard_rails": result,
		"total":       len(result),
	})
}

// handleGetPLADashboard returns the PLA dashboard data
func (s *APIServer) handleGetPLADashboard(c *gin.Context) {
	plaMutex.RLock()
	defer plaMutex.RUnlock()
	
	dashboard := PLADashboard{
		Summary: PLASummary{},
		RiskMatrix: [][]int{
			{0, 0, 0, 0, 0}, // Probability: Very Low
			{0, 0, 0, 0, 0}, // Probability: Low
			{0, 0, 0, 0, 0}, // Probability: Medium
			{0, 0, 0, 0, 0}, // Probability: High
			{0, 0, 0, 0, 0}, // Probability: Very High
		},
		ByTier:      make(map[string]int),
		BySLAStatus: make(map[string]int),
		ByCategory:  make(map[string]int),
		TopRisks:    []PLAAssessment{},
		GuardRailCoverage: []GuardRailCoverage{},
	}
	
	totalRiskScore := 0.0
	totalMitigation := 0.0
	
	for _, a := range plaAssessments {
		dashboard.Summary.TotalAssessments++
		totalRiskScore += a.ResidualRiskScore
		totalMitigation += a.TotalMitigation
		
		// Status counts
		switch a.Status {
		case "pending", "in_progress":
			dashboard.Summary.PendingRemediation++
		case "remediated":
			dashboard.Summary.Remediated++
		}
		
		if a.AcceptedRisk {
			dashboard.Summary.AcceptedRisks++
		}
		
		// SLA counts
		switch a.SLAStatus {
		case "breached":
			dashboard.Summary.SLABreached++
		case "at_risk":
			dashboard.Summary.SLAAtRisk++
		}
		
		// Risk level counts
		switch a.ResidualRiskLevel {
		case "critical":
			dashboard.Summary.CriticalCount++
		case "high":
			dashboard.Summary.HighCount++
		case "medium":
			dashboard.Summary.MediumCount++
		case "low":
			dashboard.Summary.LowCount++
		}
		
		// Tier counts
		dashboard.ByTier[a.PLATier]++
		
		// SLA status counts
		dashboard.BySLAStatus[a.SLAStatus]++
		
		// Populate risk matrix
		probIndex := int(a.ResidualProbability * 4)
		impactIndex := int(a.ResidualImpact * 4)
		if probIndex > 4 { probIndex = 4 }
		if impactIndex > 4 { impactIndex = 4 }
		dashboard.RiskMatrix[probIndex][impactIndex]++
		
		// Top risks (top 10 by final score)
		if len(dashboard.TopRisks) < 10 || a.FinalScore > dashboard.TopRisks[len(dashboard.TopRisks)-1].FinalScore {
			dashboard.TopRisks = append(dashboard.TopRisks, *a)
			// Sort by final score descending (simple bubble for small list)
			for i := len(dashboard.TopRisks) - 1; i > 0; i-- {
				if dashboard.TopRisks[i].FinalScore > dashboard.TopRisks[i-1].FinalScore {
					dashboard.TopRisks[i], dashboard.TopRisks[i-1] = dashboard.TopRisks[i-1], dashboard.TopRisks[i]
				}
			}
			if len(dashboard.TopRisks) > 10 {
				dashboard.TopRisks = dashboard.TopRisks[:10]
			}
		}
	}
	
	// Calculate averages
	if dashboard.Summary.TotalAssessments > 0 {
		dashboard.Summary.AverageRiskScore = totalRiskScore / float64(dashboard.Summary.TotalAssessments)
		dashboard.Summary.AverageMitigation = totalMitigation / float64(dashboard.Summary.TotalAssessments)
	}
	
	// Guard rail coverage
	grCoverage := make(map[string]*GuardRailCoverage)
	for _, a := range plaAssessments {
		for _, gr := range a.GuardRails {
			if _, ok := grCoverage[gr.GuardRailID]; !ok {
				grCoverage[gr.GuardRailID] = &GuardRailCoverage{
					GuardRailID:   gr.GuardRailID,
					GuardRailName: gr.GuardRailName,
					Category:      gr.Category,
				}
			}
			grCoverage[gr.GuardRailID].AssetsProtected++
			grCoverage[gr.GuardRailID].EffectivenessAvg += gr.EffectivenessScore
		}
	}
	
	for _, grc := range grCoverage {
		if grc.AssetsProtected > 0 {
			grc.EffectivenessAvg /= float64(grc.AssetsProtected)
			grc.CoveragePercentage = float64(grc.AssetsProtected) / float64(dashboard.Summary.TotalAssessments) * 100
		}
		dashboard.GuardRailCoverage = append(dashboard.GuardRailCoverage, *grc)
	}
	
	c.JSON(http.StatusOK, dashboard)
}

// handleGetPLAConfig returns PLA configuration
func (s *APIServer) handleGetPLAConfig(c *gin.Context) {
	plaMutex.RLock()
	defer plaMutex.RUnlock()
	
	c.JSON(http.StatusOK, plaConfig)
}

// handleCalculateRisk calculates risk for given parameters (preview)
func (s *APIServer) handleCalculateRisk(c *gin.Context) {
	var req struct {
		CVSSScore          float64  `json:"cvss_score"`
		AssetCriticality   string   `json:"asset_criticality"`
		DataClassification string   `json:"data_classification"`
		ExposureLevel      string   `json:"exposure_level"`
		ExploitAvailable   bool     `json:"exploit_available"`
		ExploitMaturity    string   `json:"exploit_maturity"`
		AttackVector       string   `json:"attack_vector"`
		GuardRailIDs       []string `json:"guard_rail_ids"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleCalculateRisk bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	
	// Create temporary assessment for calculation
	assessment := &PLAAssessment{
		CVSSScore:          req.CVSSScore,
		AssetCriticality:   req.AssetCriticality,
		DataClassification: req.DataClassification,
		ExposureLevel:      req.ExposureLevel,
		ExploitAvailable:   req.ExploitAvailable,
		ExploitMaturity:    req.ExploitMaturity,
		AttackVector:       req.AttackVector,
		CreatedAt:          time.Now(),
	}
	
	// Apply guard rails
	plaMutex.RLock()
	for _, grID := range req.GuardRailIDs {
		if gr, ok := guardRails[grID]; ok && gr.Enabled {
			assessment.GuardRails = append(assessment.GuardRails, AppliedGuardRail{
				GuardRailID:        gr.ID,
				GuardRailName:      gr.Name,
				Category:           gr.Category,
				EffectivenessScore: gr.NetworkEffectiveness,
				Status:             "active",
			})
		}
	}
	plaMutex.RUnlock()
	
	// Calculate risk
	CalculateRisk(assessment)
	
	c.JSON(http.StatusOK, gin.H{
		"inherent_probability": assessment.InherentProbability,
		"inherent_impact":      assessment.InherentImpact,
		"inherent_risk_score":  assessment.InherentRiskScore,
		"inherent_risk_level":  assessment.InherentRiskLevel,
		"total_mitigation":     assessment.TotalMitigation,
		"residual_probability": assessment.ResidualProbability,
		"residual_impact":      assessment.ResidualImpact,
		"residual_risk_score":  assessment.ResidualRiskScore,
		"residual_risk_level":  assessment.ResidualRiskLevel,
		"pla_tier":             assessment.PLATier,
		"remediation_sla_days": assessment.RemediationSLA,
		"final_score":          assessment.FinalScore,
		"priority":             assessment.Priority,
		"recommendation":       assessment.Recommendation,
	})
}

// Helper functions

func (s *APIServer) getVulnerabilityByID(id string) (*InspectorFinding, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("OpenSearch not available")
	}
	
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"id": id,
			},
		},
		"size": 1,
	}
	
	queryJSON, _ := json.Marshal(query)
	
	req := opensearchapi.SearchRequest{
		Index: []string{"siem-vulnerabilities"},
		Body:  strings.NewReader(string(queryJSON)),
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	res, err := req.Do(ctx, s.opensearch)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	hits := result["hits"].(map[string]interface{})["hits"].([]interface{})
	if len(hits) == 0 {
		return nil, fmt.Errorf("vulnerability not found")
	}
	
	source := hits[0].(map[string]interface{})["_source"].(map[string]interface{})
	
	finding := &InspectorFinding{
		ID:               getString(source, "id"),
		Title:            getString(source, "title"),
		CVEID:            getString(source, "cve_id"),
		CVSSScore:        getFloat64(source, "cvss_score"),
		ResourceType:     getString(source, "resource_type"),
		ResourceID:       getString(source, "resource_id"),
		ExploitAvailable: getBool(source, "exploit_available"),
	}
	
	return finding, nil
}

func getFloat64(m map[string]interface{}, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getExploitMaturity(exploitAvailable bool) string {
	if exploitAvailable {
		return "poc"
	}
	return "none"
}

func (s *APIServer) indexPLAAssessment(assessment *PLAAssessment) error {
	if s.opensearch == nil {
		return nil
	}
	
	assessmentJSON, err := json.Marshal(assessment)
	if err != nil {
		return err
	}
	
	req := opensearchapi.IndexRequest{
		Index:      PLAAssessmentIndex,
		DocumentID: assessment.ID,
		Body:       strings.NewReader(string(assessmentJSON)),
		Refresh:    "true",
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	res, err := req.Do(ctx, s.opensearch)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	
	return nil
}

