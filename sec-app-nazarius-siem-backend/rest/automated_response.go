package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// ResponseRule defines automated response rules
type ResponseRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Enabled     bool              `json:"enabled"`
	Priority    int               `json:"priority"`
	Conditions  []RuleConditionAR `json:"conditions"`
	Actions     []ResponseAction  `json:"actions"`
	RequireApproval bool          `json:"require_approval"`
	ApprovalTimeout int           `json:"approval_timeout"` // minutes
	AutoRollback    bool          `json:"auto_rollback"`
	RollbackAfter   int           `json:"rollback_after"` // minutes
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by"`
	Tags        []string          `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RuleConditionAR defines conditions for triggering automated response
type RuleConditionAR struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // equals, contains, greater_than, less_than, in
	Value    interface{} `json:"value"`
}

// ResponseAction defines an automated response action
type ResponseAction struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // isolate_host, block_ip, disable_user, kill_process, quarantine_file, segment_network
	Target      string                 `json:"target"`
	Parameters  map[string]interface{} `json:"parameters"`
	Timeout     int                    `json:"timeout"` // seconds
	RetryCount  int                    `json:"retry_count"`
	Description string                 `json:"description"`
}

// ResponseExecution tracks execution of automated responses
type ResponseExecution struct {
	ID              string                 `json:"id"`
	RuleID          string                 `json:"rule_id"`
	RuleName        string                 `json:"rule_name"`
	AlertID         string                 `json:"alert_id"`
	IncidentID      string                 `json:"incident_id"`
	Status          string                 `json:"status"` // pending, approved, executing, completed, failed, rolled_back, cancelled
	Actions         []ExecutedAction       `json:"actions"`
	RequireApproval bool                   `json:"require_approval"`
	ApprovedBy      string                 `json:"approved_by"`
	ApprovedAt      *time.Time             `json:"approved_at"`
	StartedAt       time.Time              `json:"started_at"`
	CompletedAt     *time.Time             `json:"completed_at"`
	Duration        int                    `json:"duration"` // seconds
	Result          string                 `json:"result"`
	ErrorMessage    string                 `json:"error_message"`
	RollbackStatus  string                 `json:"rollback_status"` // none, pending, completed, failed
	RolledBackAt    *time.Time             `json:"rolled_back_at"`
	AuditLog        []AuditEntry           `json:"audit_log"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ExecutedAction tracks individual action execution
type ExecutedAction struct {
	ActionID     string                 `json:"action_id"`
	Type         string                 `json:"type"`
	Target       string                 `json:"target"`
	Status       string                 `json:"status"` // pending, executing, completed, failed, rolled_back
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at"`
	Duration     int                    `json:"duration"` // seconds
	Result       string                 `json:"result"`
	ErrorMessage string                 `json:"error_message"`
	RollbackData map[string]interface{} `json:"rollback_data"` // Data needed for rollback
}

// AuditEntry tracks all events in the response lifecycle
type AuditEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Event     string                 `json:"event"`
	User      string                 `json:"user"`
	Details   map[string]interface{} `json:"details"`
}

// ApprovalRequest represents a pending approval
type ApprovalRequest struct {
	ID          string    `json:"id"`
	ExecutionID string    `json:"execution_id"`
	RuleName    string    `json:"rule_name"`
	Actions     []string  `json:"actions"`
	Severity    string    `json:"severity"`
	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Status      string    `json:"status"` // pending, approved, rejected, expired
}

// ResponseStats provides statistics about automated responses
type ResponseStats struct {
	TotalExecutions     int                       `json:"total_executions"`
	SuccessfulActions   int                       `json:"successful_actions"`
	FailedActions       int                       `json:"failed_actions"`
	PendingApprovals    int                       `json:"pending_approvals"`
	RolledBackActions   int                       `json:"rolled_back_actions"`
	AverageResponseTime float64                   `json:"average_response_time"` // seconds
	ActionsByType       map[string]int            `json:"actions_by_type"`
	ExecutionsByStatus  map[string]int            `json:"executions_by_status"`
	TopRules            []RuleExecutionStat       `json:"top_rules"`
	RecentExecutions    []ResponseExecution       `json:"recent_executions"`
	TimeSeriesData      []TimeSeriesDataPoint     `json:"time_series_data"`
}

// RuleExecutionStat tracks statistics per rule
type RuleExecutionStat struct {
	RuleID      string  `json:"rule_id"`
	RuleName    string  `json:"rule_name"`
	Executions  int     `json:"executions"`
	SuccessRate float64 `json:"success_rate"`
}

// TimeSeriesDataPoint for charts
type TimeSeriesDataPoint struct {
	Timestamp  time.Time `json:"timestamp"`
	Executions int       `json:"executions"`
	Successful int       `json:"successful"`
	Failed     int       `json:"failed"`
}

// ============================================================================
// IN-MEMORY STORAGE (Replace with database in production)
// ============================================================================

var (
	responseRules      = make(map[string]*ResponseRule)
	responseExecutions = make(map[string]*ResponseExecution)
	approvalRequests   = make(map[string]*ApprovalRequest)
	responseMutex      sync.RWMutex
)

// ============================================================================
// INITIALIZATION
// ============================================================================

func initAutomatedResponseSystem() {
	responseMutex.Lock()
	defer responseMutex.Unlock()

	// Sample rule 1: Auto-isolate ransomware-infected hosts
	rule1 := &ResponseRule{
		ID:          "rule-001",
		Name:        "Auto-Isolate Ransomware Hosts",
		Description: "Automatically isolate hosts when ransomware is detected",
		Enabled:     true,
		Priority:    1,
		Conditions: []RuleConditionAR{
			{Field: "alert_type", Operator: "equals", Value: "ransomware"},
			{Field: "severity", Operator: "in", Value: []string{"critical", "high"}},
		},
		Actions: []ResponseAction{
			{
				ID:          "action-001",
				Type:        "isolate_host",
				Target:      "{{alert.host}}",
				Parameters:  map[string]interface{}{"method": "edr", "allow_admin": true},
				Timeout:     30,
				RetryCount:  3,
				Description: "Isolate host from network via EDR",
			},
			{
				ID:          "action-002",
				Type:        "disable_user",
				Target:      "{{alert.user}}",
				Parameters:  map[string]interface{}{"domain": "corporate"},
				Timeout:     20,
				RetryCount:  2,
				Description: "Disable user account in Active Directory",
			},
		},
		RequireApproval: false,
		AutoRollback:    true,
		RollbackAfter:   60,
		CreatedAt:       time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:       time.Now().Add(-5 * 24 * time.Hour),
		CreatedBy:       "admin",
		Tags:            []string{"ransomware", "critical", "auto"},
		Metadata:        map[string]interface{}{"version": "1.2"},
	}
	responseRules[rule1.ID] = rule1

	// Sample rule 2: Block malicious IPs with approval
	rule2 := &ResponseRule{
		ID:          "rule-002",
		Name:        "Block Malicious IPs",
		Description: "Block IPs identified as malicious by threat intel",
		Enabled:     true,
		Priority:    2,
		Conditions: []RuleConditionAR{
			{Field: "threat_intel_score", Operator: "greater_than", Value: 80},
			{Field: "alert_type", Operator: "in", Value: []string{"c2_communication", "data_exfiltration"}},
		},
		Actions: []ResponseAction{
			{
				ID:          "action-003",
				Type:        "block_ip",
				Target:      "{{alert.source_ip}}",
				Parameters:  map[string]interface{}{"firewall": "perimeter", "duration": 86400},
				Timeout:     15,
				RetryCount:  3,
				Description: "Block IP on perimeter firewall",
			},
		},
		RequireApproval: true,
		ApprovalTimeout: 30,
		AutoRollback:    false,
		CreatedAt:       time.Now().Add(-20 * 24 * time.Hour),
		UpdatedAt:       time.Now().Add(-2 * 24 * time.Hour),
		CreatedBy:       "security_team",
		Tags:            []string{"threat_intel", "network", "approval_required"},
		Metadata:        map[string]interface{}{"version": "1.0"},
	}
	responseRules[rule2.ID] = rule2

	// Sample rule 3: Kill malicious processes
	rule3 := &ResponseRule{
		ID:          "rule-003",
		Name:        "Terminate Malicious Processes",
		Description: "Kill processes identified as malware",
		Enabled:     true,
		Priority:    1,
		Conditions: []RuleConditionAR{
			{Field: "alert_type", Operator: "equals", Value: "malware_execution"},
			{Field: "confidence", Operator: "greater_than", Value: 90},
		},
		Actions: []ResponseAction{
			{
				ID:          "action-004",
				Type:        "kill_process",
				Target:      "{{alert.process_id}}",
				Parameters:  map[string]interface{}{"force": true, "kill_tree": true},
				Timeout:     10,
				RetryCount:  2,
				Description: "Terminate malicious process and child processes",
			},
			{
				ID:          "action-005",
				Type:        "quarantine_file",
				Target:      "{{alert.file_path}}",
				Parameters:  map[string]interface{}{"quarantine_path": "/quarantine"},
				Timeout:     15,
				RetryCount:  2,
				Description: "Quarantine malicious file",
			},
		},
		RequireApproval: false,
		AutoRollback:    false,
		CreatedAt:       time.Now().Add(-15 * 24 * time.Hour),
		UpdatedAt:       time.Now().Add(-1 * 24 * time.Hour),
		CreatedBy:       "admin",
		Tags:            []string{"malware", "edr", "auto"},
		Metadata:        map[string]interface{}{"version": "1.1"},
	}
	responseRules[rule3.ID] = rule3

	// Sample executions
	now := time.Now()
	completed1 := now.Add(-5 * time.Minute)
	completed2 := now.Add(-15 * time.Minute)
	approved1 := now.Add(-25 * time.Minute)

	exec1 := &ResponseExecution{
		ID:              "exec-001",
		RuleID:          "rule-001",
		RuleName:        "Auto-Isolate Ransomware Hosts",
		AlertID:         "alert-12345",
		IncidentID:      "inc-789",
		Status:          "completed",
		RequireApproval: false,
		StartedAt:       now.Add(-10 * time.Minute),
		CompletedAt:     &completed1,
		Duration:        300,
		Result:          "All actions completed successfully",
		RollbackStatus:  "none",
		Actions: []ExecutedAction{
			{
				ActionID:    "action-001",
				Type:        "isolate_host",
				Target:      "DESKTOP-ABC123",
				Status:      "completed",
				StartedAt:   now.Add(-10 * time.Minute),
				CompletedAt: &completed1,
				Duration:    180,
				Result:      "Host isolated successfully via EDR",
			},
			{
				ActionID:    "action-002",
				Type:        "disable_user",
				Target:      "john.doe",
				Status:      "completed",
				StartedAt:   now.Add(-7 * time.Minute),
				CompletedAt: &completed1,
				Duration:    120,
				Result:      "User account disabled in AD",
			},
		},
		AuditLog: []AuditEntry{
			{Timestamp: now.Add(-10 * time.Minute), Event: "execution_started", User: "system", Details: map[string]interface{}{"trigger": "alert-12345"}},
			{Timestamp: completed1, Event: "execution_completed", User: "system", Details: map[string]interface{}{"status": "success"}},
		},
		Metadata: map[string]interface{}{"alert_severity": "critical"},
	}
	responseExecutions[exec1.ID] = exec1

	exec2 := &ResponseExecution{
		ID:              "exec-002",
		RuleID:          "rule-002",
		RuleName:        "Block Malicious IPs",
		AlertID:         "alert-67890",
		IncidentID:      "inc-456",
		Status:          "completed",
		RequireApproval: true,
		ApprovedBy:      "security_analyst",
		ApprovedAt:      &approved1,
		StartedAt:       now.Add(-20 * time.Minute),
		CompletedAt:     &completed2,
		Duration:        180,
		Result:          "IP blocked successfully",
		RollbackStatus:  "none",
		Actions: []ExecutedAction{
			{
				ActionID:    "action-003",
				Type:        "block_ip",
				Target:      "192.168.100.50",
				Status:      "completed",
				StartedAt:   now.Add(-20 * time.Minute),
				CompletedAt: &completed2,
				Duration:    180,
				Result:      "IP blocked on firewall",
			},
		},
		AuditLog: []AuditEntry{
			{Timestamp: now.Add(-30 * time.Minute), Event: "approval_requested", User: "system", Details: map[string]interface{}{"rule": "rule-002"}},
			{Timestamp: approved1, Event: "approved", User: "security_analyst", Details: map[string]interface{}{"reason": "confirmed malicious"}},
			{Timestamp: now.Add(-20 * time.Minute), Event: "execution_started", User: "system", Details: map[string]interface{}{}},
			{Timestamp: completed2, Event: "execution_completed", User: "system", Details: map[string]interface{}{"status": "success"}},
		},
		Metadata: map[string]interface{}{"threat_intel_source": "VirusTotal"},
	}
	responseExecutions[exec2.ID] = exec2

	// Sample pending approval
	approval1 := &ApprovalRequest{
		ID:          "approval-001",
		ExecutionID: "exec-003",
		RuleName:    "Block Malicious IPs",
		Actions:     []string{"block_ip: 10.0.50.100"},
		Severity:    "high",
		RequestedBy: "system",
		RequestedAt: now.Add(-5 * time.Minute),
		ExpiresAt:   now.Add(25 * time.Minute),
		Status:      "pending",
	}
	approvalRequests[approval1.ID] = approval1
}

// ============================================================================
// API HANDLERS
// ============================================================================

// List all response rules
func (s *APIServer) handleListResponseRules(c *gin.Context) {
	responseMutex.RLock()
	defer responseMutex.RUnlock()

	enabled := c.Query("enabled")
	tag := c.Query("tag")

	rules := make([]*ResponseRule, 0)
	for _, rule := range responseRules {
		if enabled != "" {
			if (enabled == "true" && !rule.Enabled) || (enabled == "false" && rule.Enabled) {
				continue
			}
		}
		if tag != "" {
			found := false
			for _, t := range rule.Tags {
				if t == tag {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		rules = append(rules, rule)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    rules,
		"total":   len(rules),
	})
}

// Get a specific response rule
func (s *APIServer) handleGetResponseRule(c *gin.Context) {
	id := c.Param("id")

	responseMutex.RLock()
	rule, exists := responseRules[id]
	responseMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    rule,
	})
}

// Create a new response rule
func (s *APIServer) handleCreateResponseRule(c *gin.Context) {
	var rule ResponseRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	rule.ID = generateID()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	responseMutex.Lock()
	responseRules[rule.ID] = &rule
	responseMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    rule,
		"message": "Response rule created successfully",
	})
}

// Update a response rule
func (s *APIServer) handleUpdateResponseRule(c *gin.Context) {
	id := c.Param("id")

	responseMutex.Lock()
	defer responseMutex.Unlock()

	rule, exists := responseRules[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Rule not found",
		})
		return
	}

	var updates ResponseRule
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// Update fields
	rule.Name = updates.Name
	rule.Description = updates.Description
	rule.Enabled = updates.Enabled
	rule.Priority = updates.Priority
	rule.Conditions = updates.Conditions
	rule.Actions = updates.Actions
	rule.RequireApproval = updates.RequireApproval
	rule.ApprovalTimeout = updates.ApprovalTimeout
	rule.AutoRollback = updates.AutoRollback
	rule.RollbackAfter = updates.RollbackAfter
	rule.Tags = updates.Tags
	rule.Metadata = updates.Metadata
	rule.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    rule,
		"message": "Response rule updated successfully",
	})
}

// Delete a response rule
func (s *APIServer) handleDeleteResponseRule(c *gin.Context) {
	id := c.Param("id")

	responseMutex.Lock()
	defer responseMutex.Unlock()

	if _, exists := responseRules[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Rule not found",
		})
		return
	}

	delete(responseRules, id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Response rule deleted successfully",
	})
}

// List all executions
func (s *APIServer) handleListResponseExecutions(c *gin.Context) {
	responseMutex.RLock()
	defer responseMutex.RUnlock()

	status := c.Query("status")
	ruleID := c.Query("rule_id")

	executions := make([]*ResponseExecution, 0)
	for _, exec := range responseExecutions {
		if status != "" && exec.Status != status {
			continue
		}
		if ruleID != "" && exec.RuleID != ruleID {
			continue
		}
		executions = append(executions, exec)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    executions,
		"total":   len(executions),
	})
}

// Get a specific execution
func (s *APIServer) handleGetResponseExecution(c *gin.Context) {
	id := c.Param("id")

	responseMutex.RLock()
	exec, exists := responseExecutions[id]
	responseMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Execution not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    exec,
	})
}

// Trigger manual execution
func (s *APIServer) handleTriggerExecution(c *gin.Context) {
	var req struct {
		RuleID     string                 `json:"rule_id"`
		AlertID    string                 `json:"alert_id"`
		IncidentID string                 `json:"incident_id"`
		Metadata   map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	responseMutex.RLock()
	rule, exists := responseRules[req.RuleID]
	responseMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Rule not found",
		})
		return
	}

	if !rule.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Rule is disabled",
		})
		return
	}

	// Create execution
	exec := &ResponseExecution{
		ID:              generateID(),
		RuleID:          rule.ID,
		RuleName:        rule.Name,
		AlertID:         req.AlertID,
		IncidentID:      req.IncidentID,
		Status:          "pending",
		RequireApproval: rule.RequireApproval,
		StartedAt:       time.Now(),
		Actions:         make([]ExecutedAction, 0),
		AuditLog: []AuditEntry{
			{
				Timestamp: time.Now(),
				Event:     "execution_triggered",
				User:      "manual",
				Details:   map[string]interface{}{"rule_id": rule.ID},
			},
		},
		Metadata: req.Metadata,
	}

	// If requires approval, create approval request
	if rule.RequireApproval {
		approval := &ApprovalRequest{
			ID:          generateID(),
			ExecutionID: exec.ID,
			RuleName:    rule.Name,
			Actions:     make([]string, len(rule.Actions)),
			Severity:    "high",
			RequestedBy: "manual",
			RequestedAt: time.Now(),
			ExpiresAt:   time.Now().Add(time.Duration(rule.ApprovalTimeout) * time.Minute),
			Status:      "pending",
		}

		for i, action := range rule.Actions {
			approval.Actions[i] = fmt.Sprintf("%s: %s", action.Type, action.Target)
		}

		responseMutex.Lock()
		approvalRequests[approval.ID] = approval
		responseMutex.Unlock()

		exec.Status = "pending_approval"
	} else {
		exec.Status = "executing"
		// In a real implementation, this would trigger async execution
		go executeActions(exec, rule.Actions)
	}

	responseMutex.Lock()
	responseExecutions[exec.ID] = exec
	responseMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    exec,
		"message": "Execution triggered successfully",
	})
}

// Cancel an execution
func (s *APIServer) handleCancelExecution(c *gin.Context) {
	id := c.Param("id")

	responseMutex.Lock()
	defer responseMutex.Unlock()

	exec, exists := responseExecutions[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Execution not found",
		})
		return
	}

	if exec.Status != "pending" && exec.Status != "pending_approval" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Cannot cancel execution in current status",
		})
		return
	}

	exec.Status = "cancelled"
	now := time.Now()
	exec.CompletedAt = &now
	exec.AuditLog = append(exec.AuditLog, AuditEntry{
		Timestamp: now,
		Event:     "execution_cancelled",
		User:      "manual",
		Details:   map[string]interface{}{},
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    exec,
		"message": "Execution cancelled successfully",
	})
}

// Rollback an execution
func (s *APIServer) handleRollbackExecution(c *gin.Context) {
	id := c.Param("id")

	responseMutex.Lock()
	defer responseMutex.Unlock()

	exec, exists := responseExecutions[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Execution not found",
		})
		return
	}

	if exec.Status != "completed" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Can only rollback completed executions",
		})
		return
	}

	// Perform rollback
	exec.RollbackStatus = "completed"
	now := time.Now()
	exec.RolledBackAt = &now
	exec.AuditLog = append(exec.AuditLog, AuditEntry{
		Timestamp: now,
		Event:     "execution_rolled_back",
		User:      "manual",
		Details:   map[string]interface{}{"reason": "manual_rollback"},
	})

	// In a real implementation, this would trigger actual rollback actions
	for i := range exec.Actions {
		exec.Actions[i].Status = "rolled_back"
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    exec,
		"message": "Execution rolled back successfully",
	})
}

// List approval requests
func (s *APIServer) handleListApprovals(c *gin.Context) {
	responseMutex.RLock()
	defer responseMutex.RUnlock()

	status := c.Query("status")

	approvals := make([]*ApprovalRequest, 0)
	for _, approval := range approvalRequests {
		if status != "" && approval.Status != status {
			continue
		}
		approvals = append(approvals, approval)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    approvals,
		"total":   len(approvals),
	})
}

// Approve an execution
func (s *APIServer) handleApproveExecution(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		ApprovedBy string `json:"approved_by"`
		Comments   string `json:"comments"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	responseMutex.Lock()
	defer responseMutex.Unlock()

	// Find approval request
	var approval *ApprovalRequest
	for _, a := range approvalRequests {
		if a.ExecutionID == id {
			approval = a
			break
		}
	}

	if approval == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Approval request not found",
		})
		return
	}

	if approval.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Approval request is not pending",
		})
		return
	}

	// Update approval
	approval.Status = "approved"

	// Update execution
	exec, exists := responseExecutions[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Execution not found",
		})
		return
	}

	now := time.Now()
	exec.ApprovedBy = req.ApprovedBy
	exec.ApprovedAt = &now
	exec.Status = "executing"
	exec.AuditLog = append(exec.AuditLog, AuditEntry{
		Timestamp: now,
		Event:     "approved",
		User:      req.ApprovedBy,
		Details:   map[string]interface{}{"comments": req.Comments},
	})

	// In a real implementation, this would trigger async execution
	rule, _ := responseRules[exec.RuleID]
	go executeActions(exec, rule.Actions)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    exec,
		"message": "Execution approved successfully",
	})
}

// Reject an execution
func (s *APIServer) handleRejectExecution(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		RejectedBy string `json:"rejected_by"`
		Reason     string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	responseMutex.Lock()
	defer responseMutex.Unlock()

	// Find approval request
	var approval *ApprovalRequest
	for _, a := range approvalRequests {
		if a.ExecutionID == id {
			approval = a
			break
		}
	}

	if approval == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Approval request not found",
		})
		return
	}

	if approval.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Approval request is not pending",
		})
		return
	}

	// Update approval
	approval.Status = "rejected"

	// Update execution
	exec, exists := responseExecutions[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Execution not found",
		})
		return
	}

	now := time.Now()
	exec.Status = "cancelled"
	exec.CompletedAt = &now
	exec.Result = "Rejected by " + req.RejectedBy
	exec.AuditLog = append(exec.AuditLog, AuditEntry{
		Timestamp: now,
		Event:     "rejected",
		User:      req.RejectedBy,
		Details:   map[string]interface{}{"reason": req.Reason},
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    exec,
		"message": "Execution rejected successfully",
	})
}

// Get response statistics
func (s *APIServer) handleGetResponseStats(c *gin.Context) {
	responseMutex.RLock()
	defer responseMutex.RUnlock()

	stats := ResponseStats{
		TotalExecutions:   len(responseExecutions),
		ActionsByType:     make(map[string]int),
		ExecutionsByStatus: make(map[string]int),
		TopRules:          make([]RuleExecutionStat, 0),
		RecentExecutions:  make([]ResponseExecution, 0),
		TimeSeriesData:    make([]TimeSeriesDataPoint, 0),
	}

	ruleStats := make(map[string]*RuleExecutionStat)
	var totalDuration int

	for _, exec := range responseExecutions {
		stats.ExecutionsByStatus[exec.Status]++
		totalDuration += exec.Duration

		if exec.Status == "completed" {
			stats.SuccessfulActions++
		} else if exec.Status == "failed" {
			stats.FailedActions++
		}

		if exec.RollbackStatus == "completed" {
			stats.RolledBackActions++
		}

		for _, action := range exec.Actions {
			stats.ActionsByType[action.Type]++
		}

		// Track rule stats
		if _, exists := ruleStats[exec.RuleID]; !exists {
			ruleStats[exec.RuleID] = &RuleExecutionStat{
				RuleID:   exec.RuleID,
				RuleName: exec.RuleName,
			}
		}
		ruleStats[exec.RuleID].Executions++
		if exec.Status == "completed" {
			ruleStats[exec.RuleID].SuccessRate++
		}

		// Add to recent executions (limit to 10)
		if len(stats.RecentExecutions) < 10 {
			stats.RecentExecutions = append(stats.RecentExecutions, *exec)
		}
	}

	// Calculate average response time
	if stats.TotalExecutions > 0 {
		stats.AverageResponseTime = float64(totalDuration) / float64(stats.TotalExecutions)
	}

	// Calculate success rates
	for _, ruleStat := range ruleStats {
		if ruleStat.Executions > 0 {
			ruleStat.SuccessRate = (ruleStat.SuccessRate / float64(ruleStat.Executions)) * 100
		}
		stats.TopRules = append(stats.TopRules, *ruleStat)
	}

	// Count pending approvals
	for _, approval := range approvalRequests {
		if approval.Status == "pending" {
			stats.PendingApprovals++
		}
	}

	// Generate time series data (last 24 hours)
	now := time.Now()
	for i := 23; i >= 0; i-- {
		timestamp := now.Add(-time.Duration(i) * time.Hour)
		dataPoint := TimeSeriesDataPoint{
			Timestamp:  timestamp,
			Executions: 0,
			Successful: 0,
			Failed:     0,
		}

		for _, exec := range responseExecutions {
			if exec.StartedAt.After(timestamp) && exec.StartedAt.Before(timestamp.Add(time.Hour)) {
				dataPoint.Executions++
				if exec.Status == "completed" {
					dataPoint.Successful++
				} else if exec.Status == "failed" {
					dataPoint.Failed++
				}
			}
		}

		stats.TimeSeriesData = append(stats.TimeSeriesData, dataPoint)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// executeActions simulates async action execution
func executeActions(exec *ResponseExecution, actions []ResponseAction) {
	time.Sleep(2 * time.Second) // Simulate execution time

	responseMutex.Lock()
	defer responseMutex.Unlock()

	for _, action := range actions {
		executedAction := ExecutedAction{
			ActionID:  action.ID,
			Type:      action.Type,
			Target:    action.Target,
			Status:    "completed",
			StartedAt: time.Now(),
			Duration:  5,
			Result:    fmt.Sprintf("Action %s executed successfully", action.Type),
		}
		now := time.Now()
		executedAction.CompletedAt = &now

		exec.Actions = append(exec.Actions, executedAction)
	}

	exec.Status = "completed"
	now := time.Now()
	exec.CompletedAt = &now
	exec.Duration = int(now.Sub(exec.StartedAt).Seconds())
	exec.Result = "All actions completed successfully"

	exec.AuditLog = append(exec.AuditLog, AuditEntry{
		Timestamp: now,
		Event:     "execution_completed",
		User:      "system",
		Details:   map[string]interface{}{"status": "success"},
	})
}
