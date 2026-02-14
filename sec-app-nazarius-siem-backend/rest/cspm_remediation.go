package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Auto-Remediation Types
type RemediationType string

const (
	RemediationTypeManual    RemediationType = "manual"
	RemediationTypeAutomatic RemediationType = "automatic"
	RemediationTypeScheduled RemediationType = "scheduled"
)

type RemediationStatus string

const (
	RemediationStatusPending    RemediationStatus = "pending"
	RemediationStatusApproved   RemediationStatus = "approved"
	RemediationStatusRejected   RemediationStatus = "rejected"
	RemediationStatusRunning    RemediationStatus = "running"
	RemediationStatusCompleted  RemediationStatus = "completed"
	RemediationStatusFailed     RemediationStatus = "failed"
	RemediationStatusRolledBack RemediationStatus = "rolled_back"
)

// Auto-Remediation Rule
type AutoRemediationRule struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	FindingType     string              `json:"finding_type"` // S3_PUBLIC_ACCESS, UNENCRYPTED_EBS, etc
	Severity        []string            `json:"severity"`     // critical, high, medium, low
	AutoApprove     bool                `json:"auto_approve"`
	Enabled         bool                `json:"enabled"`
	Actions         []RemediationAction `json:"actions"`
	RollbackActions []RemediationAction `json:"rollback_actions"`
	MaxRetries      int                 `json:"max_retries"`
	NotifyChannels  []string            `json:"notify_channels"` // slack, email, pagerduty
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
	CreatedBy       string              `json:"created_by"`
}

// Remediation Action
type RemediationAction struct {
	Type            string                 `json:"type"`   // aws_api, aws_lambda, aws_ssm, script
	Target          string                 `json:"target"` // API endpoint, Lambda ARN, SSM Document
	Parameters      map[string]interface{} `json:"parameters"`
	Timeout         int                    `json:"timeout"` // seconds
	SuccessCriteria string                 `json:"success_criteria"`
	Order           int                    `json:"order"` // execution order
}

// Remediation Execution
type RemediationExecution struct {
	ID                string                      `json:"id"`
	RuleID            string                      `json:"rule_id"`
	RuleName          string                      `json:"rule_name"`
	FindingID         string                      `json:"finding_id"`
	FindingTitle      string                      `json:"finding_title"`
	ResourceID        string                      `json:"resource_id"`
	ResourceType      string                      `json:"resource_type"`
	Status            RemediationStatus           `json:"status"`
	Type              RemediationType             `json:"type"`
	RequiresApproval  bool                        `json:"requires_approval"`
	ApprovalRequest   *RemediationApprovalRequest `json:"approval_request,omitempty"`
	ImpactAnalysis    ImpactAnalysis              `json:"impact_analysis"`
	Actions           []ActionExecution           `json:"actions"`
	StartedAt         *time.Time                  `json:"started_at,omitempty"`
	CompletedAt       *time.Time                  `json:"completed_at,omitempty"`
	Duration          int                         `json:"duration"` // seconds
	Result            string                      `json:"result"`
	ErrorMessage      string                      `json:"error_message,omitempty"`
	RollbackAvailable bool                        `json:"rollback_available"`
	RolledBack        bool                        `json:"rolled_back"`
	CreatedAt         time.Time                   `json:"created_at"`
	CreatedBy         string                      `json:"created_by"`
}

// Action Execution
type ActionExecution struct {
	ActionType   string                 `json:"action_type"`
	Target       string                 `json:"target"`
	Status       string                 `json:"status"` // pending, running, completed, failed
	StartedAt    *time.Time             `json:"started_at,omitempty"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Duration     int                    `json:"duration"` // seconds
	Result       string                 `json:"result"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	Output       map[string]interface{} `json:"output,omitempty"`
}

// Remediation Approval Request
type RemediationApprovalRequest struct {
	ID              string            `json:"id"`
	ExecutionID     string            `json:"execution_id"`
	RequestedBy     string            `json:"requested_by"`
	RequestedAt     time.Time         `json:"requested_at"`
	Status          string            `json:"status"`    // pending, approved, rejected, expired
	Approvers       []string          `json:"approvers"` // list of user IDs who can approve
	ApprovedBy      string            `json:"approved_by,omitempty"`
	ApprovedAt      *time.Time        `json:"approved_at,omitempty"`
	RejectedBy      string            `json:"rejected_by,omitempty"`
	RejectedAt      *time.Time        `json:"rejected_at,omitempty"`
	RejectionReason string            `json:"rejection_reason,omitempty"`
	ExpiresAt       time.Time         `json:"expires_at"`
	Comments        []ApprovalComment `json:"comments"`
}

// Approval Comment
type ApprovalComment struct {
	UserID    string    `json:"user_id"`
	UserName  string    `json:"user_name"`
	Comment   string    `json:"comment"`
	Timestamp time.Time `json:"timestamp"`
}

// Impact Analysis
type ImpactAnalysis struct {
	DowntimeExpected  bool     `json:"downtime_expected"`
	DowntimeDuration  int      `json:"downtime_duration"` // minutes
	AffectedResources []string `json:"affected_resources"`
	AffectedUsers     []string `json:"affected_users"`
	AffectedServices  []string `json:"affected_services"`
	RiskLevel         string   `json:"risk_level"` // low, medium, high, critical
	BusinessImpact    string   `json:"business_impact"`
	RollbackAvailable bool     `json:"rollback_available"`
	RollbackDuration  int      `json:"rollback_duration"` // minutes
	EstimatedCost     float64  `json:"estimated_cost"`    // USD
	ComplianceImpact  string   `json:"compliance_impact"`
}

// Remediation Statistics
type RemediationStatistics struct {
	TotalExecutions      int     `json:"total_executions"`
	SuccessfulExecutions int     `json:"successful_executions"`
	FailedExecutions     int     `json:"failed_executions"`
	PendingApprovals     int     `json:"pending_approvals"`
	AutoApproved         int     `json:"auto_approved"`
	ManualApproved       int     `json:"manual_approved"`
	Rejected             int     `json:"rejected"`
	RolledBack           int     `json:"rolled_back"`
	SuccessRate          float64 `json:"success_rate"`
	AvgExecutionTime     int     `json:"avg_execution_time"` // seconds
	TotalTimeSaved       int     `json:"total_time_saved"`   // hours
}

// Global remediation state
var (
	remediationMutex      sync.RWMutex
	remediationRules      []AutoRemediationRule
	remediationExecutions []RemediationExecution
	remediationApprovals  []RemediationApprovalRequest
)

// Initialize auto-remediation system
func initAutoRemediation() {
	// Initialize with 7 predefined remediation rules
	remediationRules = []AutoRemediationRule{
		{
			ID:          "rule-001",
			Name:        "Block S3 Bucket Public Access",
			Description: "Automatically blocks public access to S3 buckets that are detected as publicly accessible",
			FindingType: "S3_PUBLIC_ACCESS",
			Severity:    []string{"critical", "high"},
			AutoApprove: true,
			Enabled:     true,
			Actions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "s3:PutPublicAccessBlock",
					Parameters: map[string]interface{}{
						"BlockPublicAcls":       true,
						"IgnorePublicAcls":      true,
						"BlockPublicPolicy":     true,
						"RestrictPublicBuckets": true,
					},
					Timeout:         60,
					SuccessCriteria: "PublicAccessBlockConfiguration.BlockPublicAcls == true",
					Order:           1,
				},
			},
			RollbackActions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "s3:DeletePublicAccessBlock",
					Parameters: map[string]interface{}{
						"RestorePreviousPolicy": true,
					},
					Timeout: 60,
					Order:   1,
				},
			},
			MaxRetries:     3,
			NotifyChannels: []string{"slack", "email"},
			CreatedAt:      time.Now().Add(-30 * 24 * time.Hour),
			UpdatedAt:      time.Now().Add(-7 * 24 * time.Hour),
			CreatedBy:      "admin@company.com",
		},
		{
			ID:          "rule-002",
			Name:        "Enable EBS Volume Encryption",
			Description: "Creates encrypted snapshot and replaces unencrypted EBS volumes",
			FindingType: "UNENCRYPTED_EBS",
			Severity:    []string{"high", "medium"},
			AutoApprove: false, // Requires approval due to potential downtime
			Enabled:     true,
			Actions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "ec2:CreateSnapshot",
					Parameters: map[string]interface{}{
						"Description": "Snapshot for encryption remediation",
					},
					Timeout:         300,
					SuccessCriteria: "Snapshot.State == 'completed'",
					Order:           1,
				},
				{
					Type:   "aws_api",
					Target: "ec2:CopySnapshot",
					Parameters: map[string]interface{}{
						"Encrypted": true,
						"KmsKeyId":  "alias/aws/ebs",
					},
					Timeout:         300,
					SuccessCriteria: "Snapshot.Encrypted == true",
					Order:           2,
				},
				{
					Type:   "aws_api",
					Target: "ec2:CreateVolume",
					Parameters: map[string]interface{}{
						"Encrypted": true,
					},
					Timeout:         120,
					SuccessCriteria: "Volume.Encrypted == true",
					Order:           3,
				},
			},
			RollbackActions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "ec2:AttachVolume",
					Parameters: map[string]interface{}{
						"RestoreOriginalVolume": true,
					},
					Timeout: 120,
					Order:   1,
				},
			},
			MaxRetries:     2,
			NotifyChannels: []string{"slack", "email", "pagerduty"},
			CreatedAt:      time.Now().Add(-25 * 24 * time.Hour),
			UpdatedAt:      time.Now().Add(-5 * 24 * time.Hour),
			CreatedBy:      "security-team@company.com",
		},
		{
			ID:          "rule-003",
			Name:        "Restrict Security Group 0.0.0.0/0",
			Description: "Removes or restricts security group rules that allow access from 0.0.0.0/0",
			FindingType: "SECURITY_GROUP_OPEN",
			Severity:    []string{"critical", "high"},
			AutoApprove: true,
			Enabled:     true,
			Actions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "ec2:RevokeSecurityGroupIngress",
					Parameters: map[string]interface{}{
						"CidrIp": "0.0.0.0/0",
					},
					Timeout:         60,
					SuccessCriteria: "IpPermissions[].IpRanges[].CidrIp != '0.0.0.0/0'",
					Order:           1,
				},
			},
			RollbackActions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "ec2:AuthorizeSecurityGroupIngress",
					Parameters: map[string]interface{}{
						"RestorePreviousRules": true,
					},
					Timeout: 60,
					Order:   1,
				},
			},
			MaxRetries:     3,
			NotifyChannels: []string{"slack", "email"},
			CreatedAt:      time.Now().Add(-20 * 24 * time.Hour),
			UpdatedAt:      time.Now().Add(-3 * 24 * time.Hour),
			CreatedBy:      "admin@company.com",
		},
		{
			ID:          "rule-004",
			Name:        "Enable MFA for IAM User",
			Description: "Forces MFA enablement for IAM users without MFA",
			FindingType: "IAM_USER_NO_MFA",
			Severity:    []string{"high", "medium"},
			AutoApprove: true,
			Enabled:     true,
			Actions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "iam:CreateVirtualMFADevice",
					Parameters: map[string]interface{}{
						"VirtualMFADeviceName": "{{UserName}}-mfa",
					},
					Timeout:         60,
					SuccessCriteria: "VirtualMFADevice.SerialNumber != null",
					Order:           1,
				},
				{
					Type:   "aws_api",
					Target: "iam:EnableMFADevice",
					Parameters: map[string]interface{}{
						"NotifyUser": true,
					},
					Timeout:         60,
					SuccessCriteria: "User.MFADevices.length > 0",
					Order:           2,
				},
			},
			RollbackActions: []RemediationAction{},
			MaxRetries:      2,
			NotifyChannels:  []string{"email"},
			CreatedAt:       time.Now().Add(-15 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-2 * 24 * time.Hour),
			CreatedBy:       "security-team@company.com",
		},
		{
			ID:          "rule-005",
			Name:        "Enable RDS Encryption",
			Description: "Creates encrypted snapshot and restores RDS instance with encryption",
			FindingType: "UNENCRYPTED_RDS",
			Severity:    []string{"critical", "high"},
			AutoApprove: false, // Requires approval due to downtime
			Enabled:     true,
			Actions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "rds:CreateDBSnapshot",
					Parameters: map[string]interface{}{
						"DBSnapshotIdentifier": "{{DBInstanceIdentifier}}-encryption-snapshot",
					},
					Timeout:         600,
					SuccessCriteria: "DBSnapshot.Status == 'available'",
					Order:           1,
				},
				{
					Type:   "aws_api",
					Target: "rds:CopyDBSnapshot",
					Parameters: map[string]interface{}{
						"KmsKeyId": "alias/aws/rds",
					},
					Timeout:         600,
					SuccessCriteria: "DBSnapshot.Encrypted == true",
					Order:           2,
				},
				{
					Type:   "aws_api",
					Target: "rds:RestoreDBInstanceFromDBSnapshot",
					Parameters: map[string]interface{}{
						"StorageEncrypted": true,
					},
					Timeout:         900,
					SuccessCriteria: "DBInstance.StorageEncrypted == true",
					Order:           3,
				},
			},
			RollbackActions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "rds:RestoreDBInstanceFromDBSnapshot",
					Parameters: map[string]interface{}{
						"RestoreOriginalInstance": true,
					},
					Timeout: 900,
					Order:   1,
				},
			},
			MaxRetries:     1,
			NotifyChannels: []string{"slack", "email", "pagerduty"},
			CreatedAt:      time.Now().Add(-10 * 24 * time.Hour),
			UpdatedAt:      time.Now().Add(-1 * 24 * time.Hour),
			CreatedBy:      "dba-team@company.com",
		},
		{
			ID:          "rule-006",
			Name:        "Enable CloudTrail Logging",
			Description: "Automatically enables CloudTrail if it's disabled",
			FindingType: "CLOUDTRAIL_DISABLED",
			Severity:    []string{"critical"},
			AutoApprove: true,
			Enabled:     true,
			Actions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "cloudtrail:CreateTrail",
					Parameters: map[string]interface{}{
						"Name":                       "default-trail",
						"S3BucketName":               "cloudtrail-logs-{{AccountId}}",
						"IncludeGlobalServiceEvents": true,
						"IsMultiRegionTrail":         true,
						"EnableLogFileValidation":    true,
					},
					Timeout:         120,
					SuccessCriteria: "Trail.IsLogging == true",
					Order:           1,
				},
				{
					Type:   "aws_api",
					Target: "cloudtrail:StartLogging",
					Parameters: map[string]interface{}{
						"Name": "default-trail",
					},
					Timeout:         60,
					SuccessCriteria: "Trail.IsLogging == true",
					Order:           2,
				},
			},
			RollbackActions: []RemediationAction{},
			MaxRetries:      3,
			NotifyChannels:  []string{"slack", "email"},
			CreatedAt:       time.Now().Add(-5 * 24 * time.Hour),
			UpdatedAt:       time.Now(),
			CreatedBy:       "compliance-team@company.com",
		},
		{
			ID:          "rule-007",
			Name:        "Disable Root Account Access Keys",
			Description: "Automatically disables or deletes root account access keys",
			FindingType: "ROOT_ACCOUNT_ACCESS_KEY",
			Severity:    []string{"critical"},
			AutoApprove: true,
			Enabled:     true,
			Actions: []RemediationAction{
				{
					Type:   "aws_api",
					Target: "iam:UpdateAccessKey",
					Parameters: map[string]interface{}{
						"Status": "Inactive",
					},
					Timeout:         60,
					SuccessCriteria: "AccessKey.Status == 'Inactive'",
					Order:           1,
				},
				{
					Type:   "aws_api",
					Target: "iam:DeleteAccessKey",
					Parameters: map[string]interface{}{
						"CreateIncident": true,
						"NotifySecurity": true,
					},
					Timeout:         60,
					SuccessCriteria: "AccessKey == null",
					Order:           2,
				},
			},
			RollbackActions: []RemediationAction{},
			MaxRetries:      3,
			NotifyChannels:  []string{"slack", "email", "pagerduty"},
			CreatedAt:       time.Now().Add(-3 * 24 * time.Hour),
			UpdatedAt:       time.Now(),
			CreatedBy:       "security-team@company.com",
		},
	}

	// Initialize with sample executions
	now := time.Now()
	startTime1 := now.Add(-2 * time.Hour)
	completeTime1 := now.Add(-1*time.Hour - 45*time.Minute)

	remediationExecutions = []RemediationExecution{
		{
			ID:               "exec-001",
			RuleID:           "rule-001",
			RuleName:         "Block S3 Bucket Public Access",
			FindingID:        "find-001",
			FindingTitle:     "S3 Bucket Publicly Accessible",
			ResourceID:       "arn:aws:s3:::my-public-bucket",
			ResourceType:     "AWS::S3::Bucket",
			Status:           RemediationStatusCompleted,
			Type:             RemediationTypeAutomatic,
			RequiresApproval: false,
			ImpactAnalysis: ImpactAnalysis{
				DowntimeExpected:  false,
				DowntimeDuration:  0,
				AffectedResources: []string{"arn:aws:s3:::my-public-bucket"},
				AffectedUsers:     []string{},
				AffectedServices:  []string{"S3"},
				RiskLevel:         "low",
				BusinessImpact:    "No impact - security improvement",
				RollbackAvailable: true,
				RollbackDuration:  5,
				EstimatedCost:     0.0,
				ComplianceImpact:  "Improves PCI-DSS 3.4 compliance",
			},
			Actions: []ActionExecution{
				{
					ActionType:   "aws_api",
					Target:       "s3:PutPublicAccessBlock",
					Status:       "completed",
					StartedAt:    &startTime1,
					CompletedAt:  &completeTime1,
					Duration:     15,
					Result:       "Successfully blocked public access",
					ErrorMessage: "",
				},
			},
			StartedAt:         &startTime1,
			CompletedAt:       &completeTime1,
			Duration:          15,
			Result:            "Successfully remediated S3 bucket public access",
			RollbackAvailable: true,
			RolledBack:        false,
			CreatedAt:         now.Add(-2 * time.Hour),
			CreatedBy:         "system",
		},
	}

	// Initialize with sample approval requests
	remediationApprovals = []RemediationApprovalRequest{
		{
			ID:          "approval-001",
			ExecutionID: "exec-002",
			RequestedBy: "system",
			RequestedAt: now.Add(-30 * time.Minute),
			Status:      "pending",
			Approvers:   []string{"admin@company.com", "security-lead@company.com"},
			ExpiresAt:   now.Add(2 * time.Hour),
			Comments: []ApprovalComment{
				{
					UserID:    "system",
					UserName:  "Auto-Remediation System",
					Comment:   "EBS volume encryption requires instance downtime. Estimated: 15 minutes",
					Timestamp: now.Add(-30 * time.Minute),
				},
			},
		},
	}
}

// Handlers

// Handler: List remediation rules
func (s *APIServer) handleListRemediationRules(c *gin.Context) {
	remediationMutex.RLock()
	defer remediationMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"rules":   remediationRules,
		"total":   len(remediationRules),
	})
}

// Handler: Get remediation rule by ID
func (s *APIServer) handleGetRemediationRule(c *gin.Context) {
	id := c.Param("id")

	remediationMutex.RLock()
	defer remediationMutex.RUnlock()

	for _, rule := range remediationRules {
		if rule.ID == id {
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"data":    rule,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Remediation rule not found",
	})
}

// Handler: List remediation executions
func (s *APIServer) handleListRemediationExecutions(c *gin.Context) {
	remediationMutex.RLock()
	defer remediationMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"executions": remediationExecutions,
		"total":      len(remediationExecutions),
	})
}

// Handler: Get remediation execution by ID
func (s *APIServer) handleGetRemediationExecution(c *gin.Context) {
	id := c.Param("id")

	remediationMutex.RLock()
	defer remediationMutex.RUnlock()

	for _, exec := range remediationExecutions {
		if exec.ID == id {
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"data":    exec,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Remediation execution not found",
	})
}

// Handler: List approval requests
func (s *APIServer) handleListApprovalRequests(c *gin.Context) {
	remediationMutex.RLock()
	defer remediationMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"approvals": remediationApprovals,
		"total":     len(remediationApprovals),
	})
}

// Handler: Approve remediation
func (s *APIServer) handleApproveRemediation(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		ApprovedBy string `json:"approved_by"`
		Comment    string `json:"comment"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] Invalid remediation approval request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	remediationMutex.Lock()
	defer remediationMutex.Unlock()

	// Find approval request
	for i := range remediationApprovals {
		if remediationApprovals[i].ID == id {
			now := time.Now()
			remediationApprovals[i].Status = "approved"
			remediationApprovals[i].ApprovedBy = req.ApprovedBy
			remediationApprovals[i].ApprovedAt = &now

			if req.Comment != "" {
				remediationApprovals[i].Comments = append(remediationApprovals[i].Comments, ApprovalComment{
					UserID:    req.ApprovedBy,
					UserName:  req.ApprovedBy,
					Comment:   req.Comment,
					Timestamp: now,
				})
			}

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"message": "Remediation approved successfully",
				"data":    remediationApprovals[i],
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Approval request not found",
	})
}

// Handler: Reject remediation
func (s *APIServer) handleRejectRemediation(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		RejectedBy string `json:"rejected_by"`
		Reason     string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleRejectRemediation bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	remediationMutex.Lock()
	defer remediationMutex.Unlock()

	// Find approval request
	for i := range remediationApprovals {
		if remediationApprovals[i].ID == id {
			now := time.Now()
			remediationApprovals[i].Status = "rejected"
			remediationApprovals[i].RejectedBy = req.RejectedBy
			remediationApprovals[i].RejectedAt = &now
			remediationApprovals[i].RejectionReason = req.Reason

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"message": "Remediation rejected successfully",
				"data":    remediationApprovals[i],
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Approval request not found",
	})
}

// Handler: Rollback remediation
func (s *APIServer) handleRollbackRemediation(c *gin.Context) {
	id := c.Param("id")

	remediationMutex.Lock()
	defer remediationMutex.Unlock()

	// Find execution
	for i := range remediationExecutions {
		if remediationExecutions[i].ID == id {
			if !remediationExecutions[i].RollbackAvailable {
				c.JSON(http.StatusBadRequest, gin.H{
					"success": false,
					"error":   "Rollback not available for this remediation",
				})
				return
			}

			if remediationExecutions[i].RolledBack {
				c.JSON(http.StatusBadRequest, gin.H{
					"success": false,
					"error":   "Remediation already rolled back",
				})
				return
			}

			// Simulate rollback
			remediationExecutions[i].Status = RemediationStatusRolledBack
			remediationExecutions[i].RolledBack = true

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"message": "Remediation rolled back successfully",
				"data":    remediationExecutions[i],
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"error":   "Remediation execution not found",
	})
}

// Handler: Get remediation statistics
func (s *APIServer) handleGetRemediationStatistics(c *gin.Context) {
	remediationMutex.RLock()
	defer remediationMutex.RUnlock()

	stats := RemediationStatistics{
		TotalExecutions:      len(remediationExecutions),
		SuccessfulExecutions: 0,
		FailedExecutions:     0,
		PendingApprovals:     0,
		AutoApproved:         0,
		ManualApproved:       0,
		Rejected:             0,
		RolledBack:           0,
		AvgExecutionTime:     45,
		TotalTimeSaved:       120,
	}

	for _, exec := range remediationExecutions {
		switch exec.Status {
		case RemediationStatusCompleted:
			stats.SuccessfulExecutions++
			if !exec.RequiresApproval {
				stats.AutoApproved++
			} else {
				stats.ManualApproved++
			}
		case RemediationStatusFailed:
			stats.FailedExecutions++
		case RemediationStatusRolledBack:
			stats.RolledBack++
		}
	}

	for _, approval := range remediationApprovals {
		switch approval.Status {
		case "pending":
			stats.PendingApprovals++
		case "rejected":
			stats.Rejected++
		}
	}

	if stats.TotalExecutions > 0 {
		stats.SuccessRate = float64(stats.SuccessfulExecutions) / float64(stats.TotalExecutions) * 100
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}
