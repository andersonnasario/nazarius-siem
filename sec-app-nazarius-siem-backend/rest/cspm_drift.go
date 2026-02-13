package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Drift Detection - Detecta mudanças não autorizadas na configuração

// ConfigurationBaseline representa uma configuração baseline
type ConfigurationBaseline struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	ResourceType     string                 `json:"resource_type"` // ec2, s3, rds, security_group, iam_role, etc.
	Configuration    map[string]interface{} `json:"configuration"`
	Tags             map[string]string      `json:"tags"`
	CreatedAt        time.Time              `json:"created_at"`
	CreatedBy        string                 `json:"created_by"`
	LastVerified     time.Time              `json:"last_verified"`
	Status           string                 `json:"status"` // active, inactive, deprecated
	ComplianceRules  []string               `json:"compliance_rules"`
	CriticalSettings []string               `json:"critical_settings"`
}

// DriftDetection representa uma detecção de drift
type DriftDetection struct {
	ID                string                 `json:"id"`
	BaselineID        string                 `json:"baseline_id"`
	BaselineName      string                 `json:"baseline_name"`
	ResourceID        string                 `json:"resource_id"`
	ResourceType      string                 `json:"resource_type"`
	ResourceName      string                 `json:"resource_name"`
	DriftType         string                 `json:"drift_type"` // configuration_change, unauthorized_access, policy_violation, resource_deleted
	Severity          string                 `json:"severity"` // critical, high, medium, low
	Status            string                 `json:"status"` // detected, investigating, approved, rejected, remediated
	DetectedAt        time.Time              `json:"detected_at"`
	Changes           []ConfigurationChange  `json:"changes"`
	Impact            string                 `json:"impact"`
	Recommendation    string                 `json:"recommendation"`
	AssignedTo        string                 `json:"assigned_to,omitempty"`
	ResolvedAt        *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy        string                 `json:"resolved_by,omitempty"`
	ResolutionNotes   string                 `json:"resolution_notes,omitempty"`
	ComplianceImpact  []string               `json:"compliance_impact"`
	AutoRemediation   bool                   `json:"auto_remediation"`
}

// ConfigurationChange representa uma mudança específica
type ConfigurationChange struct {
	Property     string      `json:"property"`
	ExpectedValue interface{} `json:"expected_value"`
	CurrentValue  interface{} `json:"current_value"`
	ChangeType    string      `json:"change_type"` // added, removed, modified
	IsCritical    bool        `json:"is_critical"`
	ChangedAt     time.Time   `json:"changed_at"`
	ChangedBy     string      `json:"changed_by,omitempty"`
}

// DriftScanConfig representa configuração de scan de drift
type DriftScanConfig struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	ScanFrequency   string   `json:"scan_frequency"` // continuous, hourly, daily, weekly
	ResourceTypes   []string `json:"resource_types"`
	Regions         []string `json:"regions"`
	Tags            map[string]string `json:"tags"`
	AlertOnDrift    bool     `json:"alert_on_drift"`
	AutoRemediate   bool     `json:"auto_remediate"`
	NotifyChannels  []string `json:"notify_channels"`
	LastScan        time.Time `json:"last_scan"`
	NextScan        time.Time `json:"next_scan"`
}

// DriftStatistics representa estatísticas de drift
type DriftStatistics struct {
	TotalDrifts         int                `json:"total_drifts"`
	CriticalDrifts      int                `json:"critical_drifts"`
	HighDrifts          int                `json:"high_drifts"`
	MediumDrifts        int                `json:"medium_drifts"`
	LowDrifts           int                `json:"low_drifts"`
	DetectedToday       int                `json:"detected_today"`
	RemediatedToday     int                `json:"remediated_today"`
	AverageTimeToResolve string            `json:"average_time_to_resolve"`
	DriftsByType        map[string]int     `json:"drifts_by_type"`
	DriftsByResource    map[string]int     `json:"drifts_by_resource"`
	Trend               string             `json:"trend"` // increasing, decreasing, stable
	ComplianceImpact    int                `json:"compliance_impact"`
}

// Global storage
var (
	driftMutex          sync.RWMutex
	baselines           []ConfigurationBaseline
	driftDetections     []DriftDetection
	driftScanConfigs    []DriftScanConfig
)

// Initialize drift detection
func initDriftDetection() {
	driftMutex.Lock()
	defer driftMutex.Unlock()

	now := time.Now()

	// Initialize baselines
	baselines = []ConfigurationBaseline{
		{
			ID:           "baseline-001",
			Name:         "Production EC2 Security Baseline",
			Description:  "Security baseline for production EC2 instances",
			ResourceType: "ec2_instance",
			Configuration: map[string]interface{}{
				"encryption_enabled":     true,
				"public_ip_enabled":      false,
				"monitoring_enabled":     true,
				"detailed_monitoring":    true,
				"instance_metadata_v2":   true,
				"security_groups":        []string{"sg-prod-web", "sg-prod-app"},
				"iam_instance_profile":   "ec2-prod-role",
			},
			Tags: map[string]string{
				"Environment": "production",
				"Compliance":  "pci-dss",
			},
			CreatedAt:    now.AddDate(0, -3, 0),
			CreatedBy:    "admin@company.com",
			LastVerified: now.AddDate(0, 0, -1),
			Status:       "active",
			ComplianceRules: []string{"PCI-DSS 3.4", "PCI-DSS 8.2"},
			CriticalSettings: []string{"encryption_enabled", "public_ip_enabled", "security_groups"},
		},
		{
			ID:           "baseline-002",
			Name:         "S3 Bucket Security Baseline",
			Description:  "Security baseline for S3 buckets storing sensitive data",
			ResourceType: "s3_bucket",
			Configuration: map[string]interface{}{
				"public_access_blocked":  true,
				"encryption_enabled":     true,
				"encryption_type":        "AES256",
				"versioning_enabled":     true,
				"logging_enabled":        true,
				"mfa_delete_enabled":     true,
				"lifecycle_policy":       true,
			},
			Tags: map[string]string{
				"DataClassification": "confidential",
				"Compliance":         "pci-dss,hipaa",
			},
			CreatedAt:    now.AddDate(0, -2, 0),
			CreatedBy:    "security@company.com",
			LastVerified: now,
			Status:       "active",
			ComplianceRules: []string{"PCI-DSS 3.4", "HIPAA 164.312"},
			CriticalSettings: []string{"public_access_blocked", "encryption_enabled", "mfa_delete_enabled"},
		},
		{
			ID:           "baseline-003",
			Name:         "RDS Database Security Baseline",
			Description:  "Security baseline for production RDS databases",
			ResourceType: "rds_instance",
			Configuration: map[string]interface{}{
				"encryption_at_rest":     true,
				"encryption_in_transit":  true,
				"public_access":          false,
				"backup_retention_days":  30,
				"multi_az":               true,
				"auto_minor_version_upgrade": false,
				"deletion_protection":    true,
			},
			Tags: map[string]string{
				"Environment": "production",
				"Compliance":  "pci-dss",
			},
			CreatedAt:    now.AddDate(0, -1, 0),
			CreatedBy:    "dba@company.com",
			LastVerified: now.AddDate(0, 0, -2),
			Status:       "active",
			ComplianceRules: []string{"PCI-DSS 3.4", "PCI-DSS 8.2.1"},
			CriticalSettings: []string{"encryption_at_rest", "public_access", "deletion_protection"},
		},
	}

	// Initialize drift detections
	driftDetections = []DriftDetection{
		{
			ID:           "drift-001",
			BaselineID:   "baseline-001",
			BaselineName: "Production EC2 Security Baseline",
			ResourceID:   "i-0123456789abcdef0",
			ResourceType: "ec2_instance",
			ResourceName: "prod-web-server-01",
			DriftType:    "configuration_change",
			Severity:     "critical",
			Status:       "detected",
			DetectedAt:   now.Add(-2 * time.Hour),
			Changes: []ConfigurationChange{
				{
					Property:      "public_ip_enabled",
					ExpectedValue: false,
					CurrentValue:  true,
					ChangeType:    "modified",
					IsCritical:    true,
					ChangedAt:     now.Add(-2 * time.Hour),
					ChangedBy:     "john.doe@company.com",
				},
				{
					Property:      "security_groups",
					ExpectedValue: []string{"sg-prod-web", "sg-prod-app"},
					CurrentValue:  []string{"sg-prod-web", "sg-prod-app", "sg-default"},
					ChangeType:    "modified",
					IsCritical:    true,
					ChangedAt:     now.Add(-2 * time.Hour),
					ChangedBy:     "john.doe@company.com",
				},
			},
			Impact:         "Instance is now publicly accessible, violating security policy",
			Recommendation: "Remove public IP and revert security group changes immediately",
			ComplianceImpact: []string{"PCI-DSS 1.2.1", "PCI-DSS 1.3.1"},
			AutoRemediation: true,
		},
		{
			ID:           "drift-002",
			BaselineID:   "baseline-002",
			BaselineName: "S3 Bucket Security Baseline",
			ResourceID:   "arn:aws:s3:::prod-customer-data",
			ResourceType: "s3_bucket",
			ResourceName: "prod-customer-data",
			DriftType:    "policy_violation",
			Severity:     "critical",
			Status:       "investigating",
			DetectedAt:   now.Add(-5 * time.Hour),
			Changes: []ConfigurationChange{
				{
					Property:      "public_access_blocked",
					ExpectedValue: true,
					CurrentValue:  false,
					ChangeType:    "modified",
					IsCritical:    true,
					ChangedAt:     now.Add(-5 * time.Hour),
					ChangedBy:     "unknown",
				},
			},
			Impact:         "Bucket containing customer data is now publicly accessible",
			Recommendation: "Block public access immediately and investigate who made the change",
			AssignedTo:     "security-team@company.com",
			ComplianceImpact: []string{"PCI-DSS 3.4", "HIPAA 164.312(a)(1)"},
			AutoRemediation: true,
		},
		{
			ID:           "drift-003",
			BaselineID:   "baseline-003",
			BaselineName: "RDS Database Security Baseline",
			ResourceID:   "arn:aws:rds:us-east-1:123456789012:db:prod-db-01",
			ResourceType: "rds_instance",
			ResourceName: "prod-db-01",
			DriftType:    "configuration_change",
			Severity:     "high",
			Status:       "approved",
			DetectedAt:   now.Add(-24 * time.Hour),
			Changes: []ConfigurationChange{
				{
					Property:      "backup_retention_days",
					ExpectedValue: 30,
					CurrentValue:  35,
					ChangeType:    "modified",
					IsCritical:    false,
					ChangedAt:     now.Add(-24 * time.Hour),
					ChangedBy:     "dba@company.com",
				},
			},
			Impact:         "Backup retention increased, no negative impact",
			Recommendation: "Update baseline to reflect new retention policy",
			AssignedTo:     "dba@company.com",
			ResolvedAt:     &now,
			ResolvedBy:     "security@company.com",
			ResolutionNotes: "Change approved - increased backup retention is acceptable",
			ComplianceImpact: []string{},
			AutoRemediation: false,
		},
		{
			ID:           "drift-004",
			BaselineID:   "baseline-001",
			BaselineName: "Production EC2 Security Baseline",
			ResourceID:   "i-0987654321fedcba0",
			ResourceType: "ec2_instance",
			ResourceName: "prod-app-server-02",
			DriftType:    "unauthorized_access",
			Severity:     "high",
			Status:       "detected",
			DetectedAt:   now.Add(-30 * time.Minute),
			Changes: []ConfigurationChange{
				{
					Property:      "iam_instance_profile",
					ExpectedValue: "ec2-prod-role",
					CurrentValue:  "ec2-admin-role",
					ChangeType:    "modified",
					IsCritical:    true,
					ChangedAt:     now.Add(-30 * time.Minute),
					ChangedBy:     "unknown",
				},
			},
			Impact:         "Instance now has elevated privileges beyond what is required",
			Recommendation: "Revert IAM role to ec2-prod-role and investigate privilege escalation",
			ComplianceImpact: []string{"PCI-DSS 7.1", "PCI-DSS 7.2"},
			AutoRemediation: false,
		},
	}

	// Initialize scan configs
	driftScanConfigs = []DriftScanConfig{
		{
			ID:            "scan-001",
			Name:          "Production Resources Continuous Scan",
			Enabled:       true,
			ScanFrequency: "continuous",
			ResourceTypes: []string{"ec2_instance", "s3_bucket", "rds_instance", "security_group"},
			Regions:       []string{"us-east-1", "us-west-2"},
			Tags: map[string]string{
				"Environment": "production",
			},
			AlertOnDrift:   true,
			AutoRemediate:  true,
			NotifyChannels: []string{"slack", "email", "pagerduty"},
			LastScan:       now.Add(-5 * time.Minute),
			NextScan:       now.Add(5 * time.Minute),
		},
		{
			ID:            "scan-002",
			Name:          "Compliance-Critical Resources Daily Scan",
			Enabled:       true,
			ScanFrequency: "daily",
			ResourceTypes: []string{"iam_role", "kms_key", "cloudtrail"},
			Regions:       []string{"us-east-1"},
			Tags: map[string]string{
				"Compliance": "pci-dss",
			},
			AlertOnDrift:   true,
			AutoRemediate:  false,
			NotifyChannels: []string{"email"},
			LastScan:       now.AddDate(0, 0, -1),
			NextScan:       now.AddDate(0, 0, 1),
		},
	}
}

// Handlers

// handleListDriftBaselines lista todas as baselines
func (s *APIServer) handleListDriftBaselines(c *gin.Context) {
	driftMutex.RLock()
	defer driftMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"baselines": baselines,
		"total":     len(baselines),
	})
}

// handleGetDriftBaseline retorna uma baseline específica
func (s *APIServer) handleGetDriftBaseline(c *gin.Context) {
	id := c.Param("id")

	driftMutex.RLock()
	defer driftMutex.RUnlock()

	for _, baseline := range baselines {
		if baseline.ID == id {
			c.JSON(http.StatusOK, gin.H{
				"success":  true,
				"baseline": baseline,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Baseline not found",
	})
}

// handleCreateDriftBaseline cria uma nova baseline
func (s *APIServer) handleCreateDriftBaseline(c *gin.Context) {
	var baseline ConfigurationBaseline

	if err := c.ShouldBindJSON(&baseline); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	driftMutex.Lock()
	baseline.ID = fmt.Sprintf("baseline-%03d", len(baselines)+1)
	baseline.CreatedAt = time.Now()
	baseline.LastVerified = time.Now()
	baseline.Status = "active"
	baselines = append(baselines, baseline)
	driftMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"success":  true,
		"baseline": baseline,
		"message":  "Baseline created successfully",
	})
}

// handleListDrifts lista todas as detecções de drift
func (s *APIServer) handleListDrifts(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")

	driftMutex.RLock()
	defer driftMutex.RUnlock()

	filtered := []DriftDetection{}
	for _, drift := range driftDetections {
		if status != "" && drift.Status != status {
			continue
		}
		if severity != "" && drift.Severity != severity {
			continue
		}
		filtered = append(filtered, drift)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"drifts":  filtered,
		"total":   len(filtered),
	})
}

// handleGetDrift retorna um drift específico
func (s *APIServer) handleGetDrift(c *gin.Context) {
	id := c.Param("id")

	driftMutex.RLock()
	defer driftMutex.RUnlock()

	for _, drift := range driftDetections {
		if drift.ID == id {
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"drift":   drift,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Drift not found",
	})
}

// handleUpdateDriftStatus atualiza o status de um drift
func (s *APIServer) handleUpdateDriftStatus(c *gin.Context) {
	id := c.Param("id")

	var update struct {
		Status          string `json:"status"`
		AssignedTo      string `json:"assigned_to,omitempty"`
		ResolutionNotes string `json:"resolution_notes,omitempty"`
	}

	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	driftMutex.Lock()
	defer driftMutex.Unlock()

	for i := range driftDetections {
		if driftDetections[i].ID == id {
			driftDetections[i].Status = update.Status
			if update.AssignedTo != "" {
				driftDetections[i].AssignedTo = update.AssignedTo
			}
			if update.ResolutionNotes != "" {
				driftDetections[i].ResolutionNotes = update.ResolutionNotes
			}
			if update.Status == "remediated" || update.Status == "approved" {
				now := time.Now()
				driftDetections[i].ResolvedAt = &now
				driftDetections[i].ResolvedBy = "current_user@company.com"
			}

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"drift":   driftDetections[i],
				"message": "Drift status updated successfully",
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Drift not found",
	})
}

// handleGetDriftStatistics retorna estatísticas de drift
func (s *APIServer) handleGetDriftStatistics(c *gin.Context) {
	driftMutex.RLock()
	defer driftMutex.RUnlock()

	stats := DriftStatistics{
		TotalDrifts:          len(driftDetections),
		CriticalDrifts:       0,
		HighDrifts:           0,
		MediumDrifts:         0,
		LowDrifts:            0,
		DetectedToday:        0,
		RemediatedToday:      0,
		AverageTimeToResolve: "4.5 hours",
		DriftsByType:         make(map[string]int),
		DriftsByResource:     make(map[string]int),
		Trend:                "stable",
		ComplianceImpact:     0,
	}

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	for _, drift := range driftDetections {
		// Count by severity
		switch drift.Severity {
		case "critical":
			stats.CriticalDrifts++
		case "high":
			stats.HighDrifts++
		case "medium":
			stats.MediumDrifts++
		case "low":
			stats.LowDrifts++
		}

		// Count by type
		stats.DriftsByType[drift.DriftType]++

		// Count by resource
		stats.DriftsByResource[drift.ResourceType]++

		// Count detected today
		if drift.DetectedAt.After(today) {
			stats.DetectedToday++
		}

		// Count remediated today
		if drift.ResolvedAt != nil && drift.ResolvedAt.After(today) {
			stats.RemediatedToday++
		}

		// Count compliance impact
		if len(drift.ComplianceImpact) > 0 {
			stats.ComplianceImpact++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"statistics": stats,
	})
}

// handleListScanConfigs lista configurações de scan
func (s *APIServer) handleListScanConfigs(c *gin.Context) {
	driftMutex.RLock()
	defer driftMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"configs": driftScanConfigs,
		"total":   len(driftScanConfigs),
	})
}

// handleRunDriftScan executa um scan de drift
func (s *APIServer) handleRunDriftScan(c *gin.Context) {
	configID := c.Param("id")

	driftMutex.Lock()
	defer driftMutex.Unlock()

	for i := range driftScanConfigs {
		if driftScanConfigs[i].ID == configID {
			driftScanConfigs[i].LastScan = time.Now()
			driftScanConfigs[i].NextScan = time.Now().Add(5 * time.Minute)

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"message": "Drift scan started successfully",
				"config":  driftScanConfigs[i],
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Scan configuration not found",
	})
}

