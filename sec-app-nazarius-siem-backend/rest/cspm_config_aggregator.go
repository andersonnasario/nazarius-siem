package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AWSAccount represents an AWS account in the aggregator
type AWSAccount struct {
	ID                string    `json:"id"`
	AccountID         string    `json:"account_id"`
	AccountName       string    `json:"account_name"`
	Email             string    `json:"email"`
	OrganizationID    string    `json:"organization_id"`
	OrganizationUnit  string    `json:"organization_unit"`
	Status            string    `json:"status"` // active, pending, suspended
	Role              string    `json:"role"`   // member, delegated_admin, management
	Regions           []string  `json:"regions"`
	ComplianceScore   float64   `json:"compliance_score"`
	TotalResources    int       `json:"total_resources"`
	TotalFindings     int       `json:"total_findings"`
	CriticalFindings  int       `json:"critical_findings"`
	LastSync          time.Time `json:"last_sync"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// ConfigAggregator represents an AWS Config Aggregator
type ConfigAggregator struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Description           string    `json:"description"`
	AggregatorARN         string    `json:"aggregator_arn"`
	OrganizationID        string    `json:"organization_id"`
	DelegatedAdminAccount string    `json:"delegated_admin_account"`
	AccountSources        []string  `json:"account_sources"` // Account IDs
	RegionSources         []string  `json:"region_sources"`
	Status                string    `json:"status"` // active, creating, deleting, failed
	TotalAccounts         int       `json:"total_accounts"`
	TotalRegions          int       `json:"total_regions"`
	LastAggregation       time.Time `json:"last_aggregation"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// AggregatedComplianceData represents aggregated compliance data
type AggregatedComplianceData struct {
	AggregatorID      string                       `json:"aggregator_id"`
	TotalAccounts     int                          `json:"total_accounts"`
	TotalRegions      int                          `json:"total_regions"`
	TotalResources    int                          `json:"total_resources"`
	TotalFindings     int                          `json:"total_findings"`
	CriticalFindings  int                          `json:"critical_findings"`
	HighFindings      int                          `json:"high_findings"`
	MediumFindings    int                          `json:"medium_findings"`
	LowFindings       int                          `json:"low_findings"`
	OverallCompliance float64                      `json:"overall_compliance"`
	ByAccount         []AccountComplianceSummary   `json:"by_account"`
	ByRegion          []RegionComplianceSummary    `json:"by_region"`
	ByFramework       []FrameworkComplianceSummary `json:"by_framework"`
	TopFindings       []AggregatedFinding          `json:"top_findings"`
	Trends            []ComplianceTrend            `json:"trends"`
	LastUpdated       time.Time                    `json:"last_updated"`
}

// AccountComplianceSummary represents compliance summary for an account
type AccountComplianceSummary struct {
	AccountID        string  `json:"account_id"`
	AccountName      string  `json:"account_name"`
	ComplianceScore  float64 `json:"compliance_score"`
	TotalResources   int     `json:"total_resources"`
	TotalFindings    int     `json:"total_findings"`
	CriticalFindings int     `json:"critical_findings"`
	Status           string  `json:"status"`
}

// RegionComplianceSummary represents compliance summary for a region
type RegionComplianceSummary struct {
	Region           string  `json:"region"`
	ComplianceScore  float64 `json:"compliance_score"`
	TotalResources   int     `json:"total_resources"`
	TotalFindings    int     `json:"total_findings"`
	CriticalFindings int     `json:"critical_findings"`
	AccountCount     int     `json:"account_count"`
}

// FrameworkComplianceSummary represents compliance summary for a framework
type FrameworkComplianceSummary struct {
	Framework       string  `json:"framework"`
	ComplianceScore float64 `json:"compliance_score"`
	TotalControls   int     `json:"total_controls"`
	PassedControls  int     `json:"passed_controls"`
	FailedControls  int     `json:"failed_controls"`
}

// AggregatedFinding represents a finding across multiple accounts
type AggregatedFinding struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	ResourceType     string   `json:"resource_type"`
	AffectedAccounts []string `json:"affected_accounts"`
	AffectedRegions  []string `json:"affected_regions"`
	TotalOccurrences int      `json:"total_occurrences"`
	Recommendation   string   `json:"recommendation"`
}

// ComplianceTrend represents compliance trend over time
type ComplianceTrend struct {
	Date            string  `json:"date"`
	ComplianceScore float64 `json:"compliance_score"`
	TotalFindings   int     `json:"total_findings"`
}

// AggregatorSyncStatus represents sync status for an aggregator
type AggregatorSyncStatus struct {
	AggregatorID    string                 `json:"aggregator_id"`
	Status          string                 `json:"status"` // syncing, completed, failed
	Progress        int                    `json:"progress"`
	TotalAccounts   int                    `json:"total_accounts"`
	SyncedAccounts  int                    `json:"synced_accounts"`
	FailedAccounts  []string               `json:"failed_accounts"`
	AccountStatuses []AccountSyncStatus    `json:"account_statuses"`
	StartedAt       time.Time              `json:"started_at"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
}

// AccountSyncStatus represents sync status for an account
type AccountSyncStatus struct {
	AccountID   string    `json:"account_id"`
	AccountName string    `json:"account_name"`
	Status      string    `json:"status"` // pending, syncing, completed, failed
	Progress    int       `json:"progress"`
	Error       string    `json:"error,omitempty"`
	LastSync    time.Time `json:"last_sync"`
}

// Global storage
var (
	aggregatorMutex       sync.RWMutex
	awsAccounts           []AWSAccount
	configAggregators     []ConfigAggregator
	aggregatedData        map[string]*AggregatedComplianceData
	aggregatorSyncStatus  map[string]*AggregatorSyncStatus
	accountCounter        int
	aggregatorCounter     int
)

// initConfigAggregator initializes mock data for AWS Config Aggregator
func initConfigAggregator() {
	aggregatorMutex.Lock()
	defer aggregatorMutex.Unlock()

	now := time.Now()
	aggregatedData = make(map[string]*AggregatedComplianceData)
	aggregatorSyncStatus = make(map[string]*AggregatorSyncStatus)

	// Mock AWS Accounts
	awsAccounts = []AWSAccount{
		{
			ID:               "acc-001",
			AccountID:        "123456789012",
			AccountName:      "Production Account",
			Email:            "prod@company.com",
			OrganizationID:   "o-abc123",
			OrganizationUnit: "Production",
			Status:           "active",
			Role:             "member",
			Regions:          []string{"us-east-1", "us-west-2", "eu-west-1"},
			ComplianceScore:  87.5,
			TotalResources:   1245,
			TotalFindings:    156,
			CriticalFindings: 12,
			LastSync:         now.Add(-15 * time.Minute),
			CreatedAt:        now.Add(-90 * 24 * time.Hour),
			UpdatedAt:        now.Add(-15 * time.Minute),
		},
		{
			ID:               "acc-002",
			AccountID:        "234567890123",
			AccountName:      "Development Account",
			Email:            "dev@company.com",
			OrganizationID:   "o-abc123",
			OrganizationUnit: "Development",
			Status:           "active",
			Role:             "member",
			Regions:          []string{"us-east-1", "us-west-2"},
			ComplianceScore:  92.3,
			TotalResources:   856,
			TotalFindings:    67,
			CriticalFindings: 5,
			LastSync:         now.Add(-10 * time.Minute),
			CreatedAt:        now.Add(-60 * 24 * time.Hour),
			UpdatedAt:        now.Add(-10 * time.Minute),
		},
		{
			ID:               "acc-003",
			AccountID:        "345678901234",
			AccountName:      "Staging Account",
			Email:            "staging@company.com",
			OrganizationID:   "o-abc123",
			OrganizationUnit: "Staging",
			Status:           "active",
			Role:             "member",
			Regions:          []string{"us-east-1"},
			ComplianceScore:  78.9,
			TotalResources:   423,
			TotalFindings:    89,
			CriticalFindings: 18,
			LastSync:         now.Add(-20 * time.Minute),
			CreatedAt:        now.Add(-45 * 24 * time.Hour),
			UpdatedAt:        now.Add(-20 * time.Minute),
		},
		{
			ID:               "acc-004",
			AccountID:        "456789012345",
			AccountName:      "Security Account",
			Email:            "security@company.com",
			OrganizationID:   "o-abc123",
			OrganizationUnit: "Security",
			Status:           "active",
			Role:             "delegated_admin",
			Regions:          []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"},
			ComplianceScore:  95.7,
			TotalResources:   234,
			TotalFindings:    10,
			CriticalFindings: 1,
			LastSync:         now.Add(-5 * time.Minute),
			CreatedAt:        now.Add(-120 * 24 * time.Hour),
			UpdatedAt:        now.Add(-5 * time.Minute),
		},
		{
			ID:               "acc-005",
			AccountID:        "567890123456",
			AccountName:      "Management Account",
			Email:            "management@company.com",
			OrganizationID:   "o-abc123",
			OrganizationUnit: "Root",
			Status:           "active",
			Role:             "management",
			Regions:          []string{"us-east-1"},
			ComplianceScore:  98.2,
			TotalResources:   145,
			TotalFindings:    3,
			CriticalFindings: 0,
			LastSync:         now.Add(-2 * time.Minute),
			CreatedAt:        now.Add(-180 * 24 * time.Hour),
			UpdatedAt:        now.Add(-2 * time.Minute),
		},
	}

	// Mock Config Aggregator
	configAggregators = []ConfigAggregator{
		{
			ID:                    "agg-001",
			Name:                  "Organization Aggregator",
			Description:           "Aggregates configuration data from all accounts in the organization",
			AggregatorARN:         "arn:aws:config:us-east-1:456789012345:configuration-aggregator/organization-aggregator",
			OrganizationID:        "o-abc123",
			DelegatedAdminAccount: "456789012345",
			AccountSources:        []string{"123456789012", "234567890123", "345678901234", "456789012345", "567890123456"},
			RegionSources:         []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"},
			Status:                "active",
			TotalAccounts:         5,
			TotalRegions:          4,
			LastAggregation:       now.Add(-5 * time.Minute),
			CreatedAt:             now.Add(-30 * 24 * time.Hour),
			UpdatedAt:             now.Add(-5 * time.Minute),
		},
	}

	// Mock Aggregated Data
	aggregatedData["agg-001"] = &AggregatedComplianceData{
		AggregatorID:      "agg-001",
		TotalAccounts:     5,
		TotalRegions:      4,
		TotalResources:    2903,
		TotalFindings:     325,
		CriticalFindings:  36,
		HighFindings:      89,
		MediumFindings:    145,
		LowFindings:       55,
		OverallCompliance: 88.8,
		ByAccount: []AccountComplianceSummary{
			{AccountID: "123456789012", AccountName: "Production Account", ComplianceScore: 87.5, TotalResources: 1245, TotalFindings: 156, CriticalFindings: 12, Status: "active"},
			{AccountID: "234567890123", AccountName: "Development Account", ComplianceScore: 92.3, TotalResources: 856, TotalFindings: 67, CriticalFindings: 5, Status: "active"},
			{AccountID: "345678901234", AccountName: "Staging Account", ComplianceScore: 78.9, TotalResources: 423, TotalFindings: 89, CriticalFindings: 18, Status: "active"},
			{AccountID: "456789012345", AccountName: "Security Account", ComplianceScore: 95.7, TotalResources: 234, TotalFindings: 10, CriticalFindings: 1, Status: "active"},
			{AccountID: "567890123456", AccountName: "Management Account", ComplianceScore: 98.2, TotalResources: 145, TotalFindings: 3, CriticalFindings: 0, Status: "active"},
		},
		ByRegion: []RegionComplianceSummary{
			{Region: "us-east-1", ComplianceScore: 89.5, TotalResources: 1456, TotalFindings: 153, CriticalFindings: 15, AccountCount: 5},
			{Region: "us-west-2", ComplianceScore: 91.2, TotalResources: 892, TotalFindings: 78, CriticalFindings: 8, AccountCount: 3},
			{Region: "eu-west-1", ComplianceScore: 85.3, TotalResources: 423, TotalFindings: 62, CriticalFindings: 10, AccountCount: 2},
			{Region: "ap-southeast-1", ComplianceScore: 94.1, TotalResources: 132, TotalFindings: 32, CriticalFindings: 3, AccountCount: 1},
		},
		ByFramework: []FrameworkComplianceSummary{
			{Framework: "PCI-DSS", ComplianceScore: 87.5, TotalControls: 320, PassedControls: 280, FailedControls: 40},
			{Framework: "HIPAA", ComplianceScore: 91.2, TotalControls: 180, PassedControls: 164, FailedControls: 16},
			{Framework: "ISO-27001", ComplianceScore: 89.8, TotalControls: 250, PassedControls: 224, FailedControls: 26},
			{Framework: "CIS AWS", ComplianceScore: 85.3, TotalControls: 420, PassedControls: 358, FailedControls: 62},
		},
		TopFindings: []AggregatedFinding{
			{
				ID:               "finding-001",
				Title:            "S3 Bucket Public Access Enabled",
				Severity:         "CRITICAL",
				ResourceType:     "AWS::S3::Bucket",
				AffectedAccounts: []string{"123456789012", "345678901234"},
				AffectedRegions:  []string{"us-east-1", "us-west-2"},
				TotalOccurrences: 8,
				Recommendation:   "Disable public access on S3 buckets containing sensitive data",
			},
			{
				ID:               "finding-002",
				Title:            "EC2 Instance Without Encryption",
				Severity:         "HIGH",
				ResourceType:     "AWS::EC2::Instance",
				AffectedAccounts: []string{"123456789012", "234567890123", "345678901234"},
				AffectedRegions:  []string{"us-east-1", "us-west-2", "eu-west-1"},
				TotalOccurrences: 15,
				Recommendation:   "Enable EBS encryption for all EC2 instances",
			},
			{
				ID:               "finding-003",
				Title:            "Security Group Allows 0.0.0.0/0 Ingress",
				Severity:         "HIGH",
				ResourceType:     "AWS::EC2::SecurityGroup",
				AffectedAccounts: []string{"123456789012", "234567890123"},
				AffectedRegions:  []string{"us-east-1", "us-west-2"},
				TotalOccurrences: 12,
				Recommendation:   "Restrict security group rules to specific IP ranges",
			},
			{
				ID:               "finding-004",
				Title:            "RDS Instance Not Multi-AZ",
				Severity:         "MEDIUM",
				ResourceType:     "AWS::RDS::DBInstance",
				AffectedAccounts: []string{"123456789012"},
				AffectedRegions:  []string{"us-east-1"},
				TotalOccurrences: 5,
				Recommendation:   "Enable Multi-AZ deployment for production databases",
			},
			{
				ID:               "finding-005",
				Title:            "IAM User Without MFA",
				Severity:         "HIGH",
				ResourceType:     "AWS::IAM::User",
				AffectedAccounts: []string{"123456789012", "234567890123", "345678901234"},
				AffectedRegions:  []string{"global"},
				TotalOccurrences: 23,
				Recommendation:   "Enable MFA for all IAM users with console access",
			},
		},
		Trends: []ComplianceTrend{
			{Date: now.Add(-6 * 24 * time.Hour).Format("2006-01-02"), ComplianceScore: 85.2, TotalFindings: 389},
			{Date: now.Add(-5 * 24 * time.Hour).Format("2006-01-02"), ComplianceScore: 86.1, TotalFindings: 367},
			{Date: now.Add(-4 * 24 * time.Hour).Format("2006-01-02"), ComplianceScore: 86.8, TotalFindings: 352},
			{Date: now.Add(-3 * 24 * time.Hour).Format("2006-01-02"), ComplianceScore: 87.5, TotalFindings: 341},
			{Date: now.Add(-2 * 24 * time.Hour).Format("2006-01-02"), ComplianceScore: 88.0, TotalFindings: 335},
			{Date: now.Add(-1 * 24 * time.Hour).Format("2006-01-02"), ComplianceScore: 88.5, TotalFindings: 330},
			{Date: now.Format("2006-01-02"), ComplianceScore: 88.8, TotalFindings: 325},
		},
		LastUpdated: now,
	}

	// Mock Sync Status
	aggregatorSyncStatus["agg-001"] = &AggregatorSyncStatus{
		AggregatorID:   "agg-001",
		Status:         "completed",
		Progress:       100,
		TotalAccounts:  5,
		SyncedAccounts: 5,
		FailedAccounts: []string{},
		AccountStatuses: []AccountSyncStatus{
			{AccountID: "123456789012", AccountName: "Production Account", Status: "completed", Progress: 100, LastSync: now.Add(-15 * time.Minute)},
			{AccountID: "234567890123", AccountName: "Development Account", Status: "completed", Progress: 100, LastSync: now.Add(-10 * time.Minute)},
			{AccountID: "345678901234", AccountName: "Staging Account", Status: "completed", Progress: 100, LastSync: now.Add(-20 * time.Minute)},
			{AccountID: "456789012345", AccountName: "Security Account", Status: "completed", Progress: 100, LastSync: now.Add(-5 * time.Minute)},
			{AccountID: "567890123456", AccountName: "Management Account", Status: "completed", Progress: 100, LastSync: now.Add(-2 * time.Minute)},
		},
		StartedAt:   now.Add(-25 * time.Minute),
		CompletedAt: &now,
	}

	accountCounter = 5
	aggregatorCounter = 1
}

// Handlers

// handleListAccounts returns list of AWS accounts
func (s *APIServer) handleListAccounts(c *gin.Context) {
	aggregatorMutex.RLock()
	defer aggregatorMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"accounts": awsAccounts,
		"total":    len(awsAccounts),
	})
}

// handleGetAccount returns a specific AWS account
func (s *APIServer) handleGetAccount(c *gin.Context) {
	accountID := c.Param("id")

	aggregatorMutex.RLock()
	defer aggregatorMutex.RUnlock()

	for _, account := range awsAccounts {
		if account.ID == accountID || account.AccountID == accountID {
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"account": account,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Account not found",
	})
}

// handleAddAccount adds a new AWS account
func (s *APIServer) handleAddAccount(c *gin.Context) {
	var account AWSAccount
	if err := c.ShouldBindJSON(&account); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	aggregatorMutex.Lock()
	defer aggregatorMutex.Unlock()

	accountCounter++
	account.ID = fmt.Sprintf("acc-%03d", accountCounter)
	account.Status = "pending"
	account.ComplianceScore = 0
	account.TotalResources = 0
	account.TotalFindings = 0
	account.CriticalFindings = 0
	account.LastSync = time.Now()
	account.CreatedAt = time.Now()
	account.UpdatedAt = time.Now()

	awsAccounts = append(awsAccounts, account)

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "Account added successfully",
		"account": account,
	})
}

// handleUpdateAccount updates an existing AWS account
func (s *APIServer) handleUpdateAccount(c *gin.Context) {
	accountID := c.Param("id")

	var updates AWSAccount
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	aggregatorMutex.Lock()
	defer aggregatorMutex.Unlock()

	for i, account := range awsAccounts {
		if account.ID == accountID || account.AccountID == accountID {
			// Update only allowed fields
			awsAccounts[i].AccountName = updates.AccountName
			awsAccounts[i].Email = updates.Email
			awsAccounts[i].OrganizationUnit = updates.OrganizationUnit
			awsAccounts[i].Role = updates.Role
			awsAccounts[i].Regions = updates.Regions
			awsAccounts[i].UpdatedAt = time.Now()

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"message": "Account updated successfully",
				"account": awsAccounts[i],
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Account not found",
	})
}

// handleDeleteAccount deletes an AWS account
func (s *APIServer) handleDeleteAccount(c *gin.Context) {
	accountID := c.Param("id")

	aggregatorMutex.Lock()
	defer aggregatorMutex.Unlock()

	for i, account := range awsAccounts {
		if account.ID == accountID || account.AccountID == accountID {
			// Remove account from slice
			awsAccounts = append(awsAccounts[:i], awsAccounts[i+1:]...)

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"message": "Account deleted successfully",
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Account not found",
	})
}

// handleListAggregators returns list of config aggregators
func (s *APIServer) handleListAggregators(c *gin.Context) {
	aggregatorMutex.RLock()
	defer aggregatorMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"aggregators": configAggregators,
		"total":       len(configAggregators),
	})
}

// handleGetAggregator returns a specific aggregator
func (s *APIServer) handleGetAggregator(c *gin.Context) {
	aggregatorID := c.Param("id")

	aggregatorMutex.RLock()
	defer aggregatorMutex.RUnlock()

	for _, agg := range configAggregators {
		if agg.ID == aggregatorID {
			c.JSON(http.StatusOK, gin.H{
				"success":    true,
				"aggregator": agg,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Aggregator not found",
	})
}

// handleGetAggregatedData returns aggregated compliance data
func (s *APIServer) handleGetAggregatedData(c *gin.Context) {
	aggregatorID := c.Param("id")

	aggregatorMutex.RLock()
	defer aggregatorMutex.RUnlock()

	if data, exists := aggregatedData[aggregatorID]; exists {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    data,
		})
		return
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Aggregated data not found",
	})
}

// handleGetSyncStatus returns sync status for an aggregator
func (s *APIServer) handleGetSyncStatus(c *gin.Context) {
	aggregatorID := c.Param("id")

	aggregatorMutex.RLock()
	defer aggregatorMutex.RUnlock()

	if status, exists := aggregatorSyncStatus[aggregatorID]; exists {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"status":  status,
		})
		return
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Sync status not found",
	})
}

// handleTriggerSync triggers a sync for an aggregator
func (s *APIServer) handleTriggerSync(c *gin.Context) {
	aggregatorID := c.Param("id")

	aggregatorMutex.Lock()
	defer aggregatorMutex.Unlock()

	// Check if aggregator exists
	found := false
	for _, agg := range configAggregators {
		if agg.ID == aggregatorID {
			found = true
			break
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Aggregator not found",
		})
		return
	}

	// Create new sync status
	now := time.Now()
	aggregatorSyncStatus[aggregatorID] = &AggregatorSyncStatus{
		AggregatorID:   aggregatorID,
		Status:         "syncing",
		Progress:       0,
		TotalAccounts:  len(awsAccounts),
		SyncedAccounts: 0,
		FailedAccounts: []string{},
		AccountStatuses: []AccountSyncStatus{},
		StartedAt:      now,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Sync triggered successfully",
		"sync_id": uuid.New().String(),
	})
}


