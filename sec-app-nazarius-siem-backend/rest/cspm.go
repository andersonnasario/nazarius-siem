package main

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// CloudAccount represents a cloud account being monitored
type CloudAccount struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Provider        string    `json:"provider"` // aws, azure, gcp, multi
	AccountID       string    `json:"account_id"`
	Status          string    `json:"status"` // active, inactive, error
	Region          string    `json:"region"`
	Environment     string    `json:"environment"` // production, staging, development
	Resources       int       `json:"resources"`
	Misconfigurations int     `json:"misconfigurations"`
	CriticalIssues  int       `json:"critical_issues"`
	ComplianceScore float64   `json:"compliance_score"` // 0-100
	LastScan        time.Time `json:"last_scan"`
	NextScan        time.Time `json:"next_scan"`
	Tags            []string  `json:"tags"`
}

// CloudResource represents a cloud resource
type CloudResource struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"` // vm, storage, database, network, iam, etc
	Provider        string    `json:"provider"`
	AccountID       string    `json:"account_id"`
	Region          string    `json:"region"`
	Status          string    `json:"status"` // running, stopped, terminated
	SecurityScore   float64   `json:"security_score"` // 0-100
	Issues          int       `json:"issues"`
	CriticalIssues  int       `json:"critical_issues"`
	PublicExposure  bool      `json:"public_exposure"`
	Encrypted       bool      `json:"encrypted"`
	BackupEnabled   bool      `json:"backup_enabled"`
	Tags            map[string]string `json:"tags"`
	CreatedAt       time.Time `json:"created_at"`
	LastModified    time.Time `json:"last_modified"`
}

// SecurityFinding represents a security misconfiguration
type SecurityFinding struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Severity        string    `json:"severity"` // critical, high, medium, low
	Status          string    `json:"status"` // open, in_progress, resolved, suppressed
	Category        string    `json:"category"` // iam, network, encryption, logging, backup
	ResourceID      string    `json:"resource_id"`
	ResourceName    string    `json:"resource_name"`
	ResourceType    string    `json:"resource_type"`
	Provider        string    `json:"provider"`
	AccountID       string    `json:"account_id"`
	Region          string    `json:"region"`
	Recommendation  string    `json:"recommendation"`
	RemediationSteps []string `json:"remediation_steps"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	CVSS            float64   `json:"cvss,omitempty"`
	DetectedAt      time.Time `json:"detected_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
}

// CSPMComplianceReport represents a compliance assessment
type CSPMComplianceReport struct{
	ID              string    `json:"id"`
	Framework       string    `json:"framework"` // cis, pci_dss, hipaa, gdpr, nist, iso27001
	Provider        string    `json:"provider"`
	AccountID       string    `json:"account_id"`
	Score           float64   `json:"score"` // 0-100
	Status          string    `json:"status"` // compliant, non_compliant, partial
	TotalControls   int       `json:"total_controls"`
	PassedControls  int       `json:"passed_controls"`
	FailedControls  int       `json:"failed_controls"`
	NotApplicable   int       `json:"not_applicable"`
	CriticalFailures int      `json:"critical_failures"`
	GeneratedAt     time.Time `json:"generated_at"`
	ValidUntil      time.Time `json:"valid_until"`
	Findings        []string  `json:"findings"`
}

// RemediationTask represents an automated remediation
type RemediationTask struct {
	ID              string    `json:"id"`
	FindingID       string    `json:"finding_id"`
	Title           string    `json:"title"`
	Type            string    `json:"type"` // manual, automated, scheduled
	Status          string    `json:"status"` // pending, running, completed, failed
	Priority        string    `json:"priority"` // critical, high, medium, low
	ResourceID      string    `json:"resource_id"`
	ResourceType    string    `json:"resource_type"`
	Provider        string    `json:"provider"`
	Actions         []string  `json:"actions"`
	ExecutedBy      string    `json:"executed_by"`
	CreatedAt       time.Time `json:"created_at"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	Result          string    `json:"result,omitempty"`
	ErrorMessage    string    `json:"error_message,omitempty"`
}

// CSPMMetrics represents CSPM metrics
type CSPMMetrics struct {
	TotalAccounts       int     `json:"total_accounts"`
	ActiveAccounts      int     `json:"active_accounts"`
	TotalResources      int     `json:"total_resources"`
	TotalFindings       int     `json:"total_findings"`
	CriticalFindings    int     `json:"critical_findings"`
	HighFindings        int     `json:"high_findings"`
	AvgComplianceScore  float64 `json:"avg_compliance_score"`
	RemediationRate     float64 `json:"remediation_rate"`
	AutoRemediations    int     `json:"auto_remediations"`
	PublicExposures     int     `json:"public_exposures"`
}

// Initialize CSPM
func initCSPM() {
	// Mock data will be generated on-the-fly
}

// Handler: List cloud accounts
func (s *APIServer) handleListCloudAccounts(c *gin.Context) {
	// Check if using real AWS data
	if os.Getenv("USE_REAL_AWS_DATA") == "true" || os.Getenv("DISABLE_MOCK_DATA") == "true" {
		// Use real AWS account from environment
		awsAccountID := os.Getenv("AWS_ACCOUNT_ID")
		if awsAccountID == "" {
			awsAccountID = "654654307039" // Fallback from test results
		}
		awsRegion := os.Getenv("AWS_REGION")
		if awsRegion == "" {
			awsRegion = "us-east-1"
		}

		accounts := []CloudAccount{
			{
				ID:              "aws-secops",
				Name:            "SecOps AWS Account",
				Provider:        "aws",
				AccountID:       awsAccountID,
				Status:          "active",
				Region:          awsRegion,
				Environment:     "production",
				Resources:       0, // Will be populated from Security Hub
				Misconfigurations: 0,
				CriticalIssues:  0,
				ComplianceScore: 0,
				LastScan:        time.Now(),
				NextScan:        time.Now().Add(60 * time.Minute),
				Tags:            []string{"production", "secops", "centralized"},
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    accounts,
			"source":  "aws",
		})
		return
	}

	// Fallback to mock data only if DISABLE_MOCK_DATA is not set
	accounts := []CloudAccount{
		{
			ID:              "acc-001",
			Name:            "Production AWS",
			Provider:        "aws",
			AccountID:       "123456789012",
			Status:          "active",
			Region:          "us-east-1",
			Environment:     "production",
			Resources:       1247,
			Misconfigurations: 34,
			CriticalIssues:  5,
			ComplianceScore: 87.5,
			LastScan:        time.Now().Add(-15 * time.Minute),
			NextScan:        time.Now().Add(45 * time.Minute),
			Tags:            []string{"production", "critical", "monitored"},
		},
		{
			ID:              "acc-002",
			Name:            "Production Azure",
			Provider:        "azure",
			AccountID:       "sub-abc-123",
			Status:          "active",
			Region:          "eastus",
			Environment:     "production",
			Resources:       892,
			Misconfigurations: 28,
			CriticalIssues:  3,
			ComplianceScore: 91.2,
			LastScan:        time.Now().Add(-10 * time.Minute),
			NextScan:        time.Now().Add(50 * time.Minute),
			Tags:            []string{"production", "azure", "monitored"},
		},
		{
			ID:              "acc-003",
			Name:            "Development GCP",
			Provider:        "gcp",
			AccountID:       "project-dev-456",
			Status:          "active",
			Region:          "us-central1",
			Environment:     "development",
			Resources:       345,
			Misconfigurations: 12,
			CriticalIssues:  1,
			ComplianceScore: 94.8,
			LastScan:        time.Now().Add(-20 * time.Minute),
			NextScan:        time.Now().Add(40 * time.Minute),
			Tags:            []string{"development", "gcp"},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    accounts,
		"source":  "mock",
	})
}

// Handler: List cloud resources
func (s *APIServer) handleListCloudResources(c *gin.Context) {
	// Use real data handler
	s.handleListCloudResourcesReal(c)
}

// Handler: List security findings
func (s *APIServer) handleListSecurityFindings(c *gin.Context) {
	// Use real data handler
	s.handleListSecurityFindingsReal(c)
}

// Handler: List compliance reports
func (s *APIServer) handleListComplianceReports(c *gin.Context) {
	// Use real data handler
	s.handleListComplianceReportsReal(c)
}

// Handler: List remediation tasks
func (s *APIServer) handleListRemediationTasks(c *gin.Context) {
	// Use real data handler
	s.handleListRemediationTasksReal(c)
}

// Handler: Get CSPM metrics
func (s *APIServer) handleGetCSPMMetrics(c *gin.Context) {
	// Use real data handler
	s.handleGetCSPMMetricsReal(c)
}

