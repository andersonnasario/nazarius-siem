package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ═══════════════════════════════════════════════════════════════════════════
// DATA RETENTION POLICIES
// ═══════════════════════════════════════════════════════════════════════════

// RetentionPolicy defines data retention rules
type RetentionPolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	DataType    string                 `json:"data_type"` // events, logs, alerts, reports, etc
	Conditions  []RetentionCondition   `json:"conditions"`
	Actions     []RetentionAction      `json:"actions"`
	Schedule    string                 `json:"schedule"` // cron expression
	Priority    int                    `json:"priority"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	LastRun     *time.Time             `json:"last_run,omitempty"`
	NextRun     *time.Time             `json:"next_run,omitempty"`
}

// RetentionCondition defines when to apply retention
type RetentionCondition struct {
	Field    string      `json:"field"`    // age, size, count, severity
	Operator string      `json:"operator"` // gt, lt, eq
	Value    interface{} `json:"value"`
}

// RetentionAction defines what to do with data
type RetentionAction struct {
	Type   string                 `json:"type"` // archive, compress, delete
	Target string                 `json:"target,omitempty"`
	Config map[string]interface{} `json:"config,omitempty"`
}

// RetentionExecution tracks policy execution
type RetentionExecution struct {
	ID            string    `json:"id"`
	PolicyID      string    `json:"policy_id"`
	PolicyName    string    `json:"policy_name"`
	Status        string    `json:"status"` // running, completed, failed
	StartTime     time.Time `json:"start_time"`
	EndTime       *time.Time `json:"end_time,omitempty"`
	ItemsProcessed int       `json:"items_processed"`
	ItemsArchived  int       `json:"items_archived"`
	ItemsDeleted   int       `json:"items_deleted"`
	BytesProcessed int64     `json:"bytes_processed"`
	BytesSaved     int64     `json:"bytes_saved"`
	ErrorMessage   string    `json:"error_message,omitempty"`
	Logs           []string  `json:"logs,omitempty"`
}

// RetentionStats provides statistics
type RetentionStats struct {
	TotalPolicies     int                `json:"total_policies"`
	ActivePolicies    int                `json:"active_policies"`
	TotalExecutions   int                `json:"total_executions"`
	LastExecution     *time.Time         `json:"last_execution,omitempty"`
	TotalItemsDeleted int                `json:"total_items_deleted"`
	TotalBytesFreed   int64              `json:"total_bytes_freed"`
	ByDataType        map[string]int     `json:"by_data_type"`
	RecentExecutions  []RetentionExecution `json:"recent_executions"`
}

// DataTypeConfig defines retention configuration per data type
type DataTypeConfig struct {
	DataType        string `json:"data_type"`
	DefaultRetention int    `json:"default_retention"` // days
	MinRetention    int    `json:"min_retention"`     // days
	MaxRetention    int    `json:"max_retention"`     // days
	CanArchive      bool   `json:"can_archive"`
	CanCompress     bool   `json:"can_compress"`
	CanDelete       bool   `json:"can_delete"`
}

// ═══════════════════════════════════════════════════════════════════════════
// IN-MEMORY STORAGE
// ═══════════════════════════════════════════════════════════════════════════

var (
	retentionPolicies   = make(map[string]*RetentionPolicy)
	retentionExecutions = make(map[string]*RetentionExecution)
	dataTypeConfigs     = make(map[string]*DataTypeConfig)
)

// ═══════════════════════════════════════════════════════════════════════════
// API HANDLERS - POLICIES
// ═══════════════════════════════════════════════════════════════════════════

// handleListRetentionPolicies returns all retention policies
func handleListRetentionPolicies(c *gin.Context) {
	dataType := c.Query("data_type")
	enabled := c.Query("enabled")

	result := []*RetentionPolicy{}
	for _, policy := range retentionPolicies {
		// Filter by data type
		if dataType != "" && policy.DataType != dataType {
			continue
		}
		// Filter by enabled status
		if enabled == "true" && !policy.Enabled {
			continue
		}
		if enabled == "false" && policy.Enabled {
			continue
		}
		result = append(result, policy)
	}

	c.JSON(http.StatusOK, gin.H{
		"policies": result,
		"total":    len(result),
	})
}

// handleGetRetentionPolicy returns a single policy
func handleGetRetentionPolicy(c *gin.Context) {
	id := c.Param("id")
	
	policy, exists := retentionPolicies[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// handleCreateRetentionPolicy creates a new policy
func handleCreateRetentionPolicy(c *gin.Context) {
	var policy RetentionPolicy
	if err := c.BindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy.ID = generateID()
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	// Calculate next run based on schedule
	if policy.Schedule != "" {
		nextRun := calculateRetentionNextRun(policy.Schedule)
		policy.NextRun = &nextRun
	}

	retentionPolicies[policy.ID] = &policy

	c.JSON(http.StatusCreated, policy)
}

// handleUpdateRetentionPolicy updates a policy
func handleUpdateRetentionPolicy(c *gin.Context) {
	id := c.Param("id")
	
	policy, exists := retentionPolicies[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	var updates RetentionPolicy
	if err := c.BindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields
	if updates.Name != "" {
		policy.Name = updates.Name
	}
	if updates.Description != "" {
		policy.Description = updates.Description
	}
	policy.Enabled = updates.Enabled
	if updates.DataType != "" {
		policy.DataType = updates.DataType
	}
	if len(updates.Conditions) > 0 {
		policy.Conditions = updates.Conditions
	}
	if len(updates.Actions) > 0 {
		policy.Actions = updates.Actions
	}
	if updates.Schedule != "" {
		policy.Schedule = updates.Schedule
		nextRun := calculateRetentionNextRun(updates.Schedule)
		policy.NextRun = &nextRun
	}
	if updates.Priority != 0 {
		policy.Priority = updates.Priority
	}
	policy.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, policy)
}

// handleDeleteRetentionPolicy deletes a policy
func handleDeleteRetentionPolicy(c *gin.Context) {
	id := c.Param("id")
	
	if _, exists := retentionPolicies[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	delete(retentionPolicies, id)
	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

// handleExecuteRetentionPolicy manually executes a policy
func handleExecuteRetentionPolicy(c *gin.Context) {
	id := c.Param("id")
	
	policy, exists := retentionPolicies[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// Execute policy asynchronously
	execution := &RetentionExecution{
		ID:         generateID(),
		PolicyID:   policy.ID,
		PolicyName: policy.Name,
		Status:     "running",
		StartTime:  time.Now(),
		Logs:       []string{},
	}
	retentionExecutions[execution.ID] = execution

	go executeRetentionPolicy(policy, execution)

	c.JSON(http.StatusAccepted, gin.H{
		"message":      "Policy execution started",
		"execution_id": execution.ID,
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// API HANDLERS - EXECUTIONS
// ═══════════════════════════════════════════════════════════════════════════

// handleListRetentionExecutions returns execution history
func handleListRetentionExecutions(c *gin.Context) {
	policyID := c.Query("policy_id")
	status := c.Query("status")

	result := []*RetentionExecution{}
	for _, exec := range retentionExecutions {
		if policyID != "" && exec.PolicyID != policyID {
			continue
		}
		if status != "" && exec.Status != status {
			continue
		}
		result = append(result, exec)
	}

	c.JSON(http.StatusOK, gin.H{
		"executions": result,
		"total":      len(result),
	})
}

// handleGetRetentionExecution returns a single execution
func handleGetRetentionExecution(c *gin.Context) {
	id := c.Param("id")
	
	execution, exists := retentionExecutions[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Execution not found"})
		return
	}

	c.JSON(http.StatusOK, execution)
}

// ═══════════════════════════════════════════════════════════════════════════
// API HANDLERS - STATISTICS & CONFIG
// ═══════════════════════════════════════════════════════════════════════════

// handleGetRetentionStats returns retention statistics
func handleGetRetentionStats(c *gin.Context) {
	stats := RetentionStats{
		ByDataType:       make(map[string]int),
		RecentExecutions: []RetentionExecution{},
	}

	// Count policies
	for _, policy := range retentionPolicies {
		stats.TotalPolicies++
		if policy.Enabled {
			stats.ActivePolicies++
		}
		stats.ByDataType[policy.DataType]++
	}

	// Aggregate execution stats
	var lastExec *time.Time
	for _, exec := range retentionExecutions {
		stats.TotalExecutions++
		stats.TotalItemsDeleted += exec.ItemsDeleted
		stats.TotalBytesFreed += exec.BytesSaved

		if lastExec == nil || exec.StartTime.After(*lastExec) {
			lastExec = &exec.StartTime
		}

		// Add to recent executions (last 10)
		if len(stats.RecentExecutions) < 10 {
			stats.RecentExecutions = append(stats.RecentExecutions, *exec)
		}
	}
	stats.LastExecution = lastExec

	c.JSON(http.StatusOK, stats)
}

// handleListDataTypeConfigs returns data type configurations
func handleListDataTypeConfigs(c *gin.Context) {
	result := []*DataTypeConfig{}
	for _, config := range dataTypeConfigs {
		result = append(result, config)
	}

	c.JSON(http.StatusOK, gin.H{
		"configs": result,
		"total":   len(result),
	})
}

// handleUpdateDataTypeConfig updates data type configuration
func handleUpdateDataTypeConfig(c *gin.Context) {
	dataType := c.Param("type")
	
	config, exists := dataTypeConfigs[dataType]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Data type config not found"})
		return
	}

	var updates DataTypeConfig
	if err := c.BindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if updates.DefaultRetention > 0 {
		config.DefaultRetention = updates.DefaultRetention
	}
	if updates.MinRetention > 0 {
		config.MinRetention = updates.MinRetention
	}
	if updates.MaxRetention > 0 {
		config.MaxRetention = updates.MaxRetention
	}

	c.JSON(http.StatusOK, config)
}

// ═══════════════════════════════════════════════════════════════════════════
// RETENTION POLICY ENGINE
// ═══════════════════════════════════════════════════════════════════════════

// executeRetentionPolicy executes a retention policy
func executeRetentionPolicy(policy *RetentionPolicy, execution *RetentionExecution) {
	execution.Logs = append(execution.Logs, fmt.Sprintf("Starting execution of policy: %s", policy.Name))

	// Simulate data processing
	// In production, this would query Elasticsearch, process data, etc.
	
	// Example: Process events older than X days
	for _, condition := range policy.Conditions {
		if condition.Field == "age" && condition.Operator == "gt" {
			days := int(condition.Value.(float64))
			execution.Logs = append(execution.Logs, fmt.Sprintf("Processing data older than %d days", days))
			
			// Simulate finding items
			itemsFound := 1000 // Mock value
			execution.ItemsProcessed = itemsFound
			
			// Execute actions
			for _, action := range policy.Actions {
				switch action.Type {
				case "archive":
					archived := archiveData(policy.DataType, itemsFound)
					execution.ItemsArchived = archived
					execution.Logs = append(execution.Logs, fmt.Sprintf("Archived %d items", archived))
					
				case "compress":
					compressed := compressData(policy.DataType, itemsFound)
					execution.BytesSaved = int64(compressed * 1024 * 1024) // Mock: 1MB per item
					execution.Logs = append(execution.Logs, fmt.Sprintf("Compressed %d items, saved %d MB", compressed, compressed))
					
				case "delete":
					deleted := deleteData(policy.DataType, itemsFound)
					execution.ItemsDeleted = deleted
					execution.BytesSaved += int64(deleted * 2 * 1024 * 1024) // Mock: 2MB per item
					execution.Logs = append(execution.Logs, fmt.Sprintf("Deleted %d items", deleted))
				}
			}
		}
	}

	// Complete execution
	now := time.Now()
	execution.EndTime = &now
	execution.Status = "completed"
	execution.Logs = append(execution.Logs, "Execution completed successfully")

	// Update policy last run
	policy.LastRun = &now
	nextRun := calculateRetentionNextRun(policy.Schedule)
	policy.NextRun = &nextRun
}

// archiveData archives data (mock implementation)
func archiveData(dataType string, count int) int {
	// In production: move data to archive storage (S3, etc.)
	return count
}

// compressData compresses data (mock implementation)
func compressData(dataType string, count int) int {
	// In production: compress data using gzip, etc.
	return count
}

// deleteData deletes data (mock implementation)
func deleteData(dataType string, count int) int {
	// In production: delete data from Elasticsearch, etc.
	return count
}

// calculateRetentionNextRun calculates next execution time based on schedule
func calculateRetentionNextRun(schedule string) time.Time {
	// Simple implementation - in production use cron parser
	// For now, assume daily execution
	return time.Now().Add(24 * time.Hour)
}

// ═══════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

func initRetentionSystem() {
	// Create default data type configs
	createDefaultDataTypeConfigs()
	
	// Create sample policies
	createSampleRetentionPolicies()
	
	// Create sample executions
	createSampleExecutions()
}

func createDefaultDataTypeConfigs() {
	configs := []DataTypeConfig{
		{
			DataType:        "events",
			DefaultRetention: 90,
			MinRetention:    7,
			MaxRetention:    365,
			CanArchive:      true,
			CanCompress:     true,
			CanDelete:       true,
		},
		{
			DataType:        "logs",
			DefaultRetention: 30,
			MinRetention:    7,
			MaxRetention:    180,
			CanArchive:      true,
			CanCompress:     true,
			CanDelete:       true,
		},
		{
			DataType:        "alerts",
			DefaultRetention: 180,
			MinRetention:    30,
			MaxRetention:    730,
			CanArchive:      true,
			CanCompress:     false,
			CanDelete:       false,
		},
		{
			DataType:        "reports",
			DefaultRetention: 365,
			MinRetention:    90,
			MaxRetention:    1825,
			CanArchive:      true,
			CanCompress:     true,
			CanDelete:       false,
		},
		{
			DataType:        "audit_logs",
			DefaultRetention: 730,
			MinRetention:    365,
			MaxRetention:    3650,
			CanArchive:      true,
			CanCompress:     true,
			CanDelete:       false,
		},
	}

	for _, config := range configs {
		dataTypeConfigs[config.DataType] = &config
	}
}

func createSampleRetentionPolicies() {
	now := time.Now()
	nextRun := now.Add(24 * time.Hour)

	policies := []RetentionPolicy{
		{
			ID:          "policy-events-90d",
			Name:        "Events - 90 Days Retention",
			Description: "Archive events older than 90 days, delete after 180 days",
			Enabled:     true,
			DataType:    "events",
			Priority:    1,
			Schedule:    "0 2 * * *", // Daily at 2 AM
			Conditions: []RetentionCondition{
				{Field: "age", Operator: "gt", Value: 90},
			},
			Actions: []RetentionAction{
				{Type: "archive", Target: "s3://archive-bucket/events"},
				{Type: "compress"},
			},
			CreatedAt: now.Add(-30 * 24 * time.Hour),
			UpdatedAt: now,
			LastRun:   &now,
			NextRun:   &nextRun,
		},
		{
			ID:          "policy-logs-30d",
			Name:        "Logs - 30 Days Retention",
			Description: "Delete logs older than 30 days",
			Enabled:     true,
			DataType:    "logs",
			Priority:    2,
			Schedule:    "0 3 * * *", // Daily at 3 AM
			Conditions: []RetentionCondition{
				{Field: "age", Operator: "gt", Value: 30},
			},
			Actions: []RetentionAction{
				{Type: "delete"},
			},
			CreatedAt: now.Add(-60 * 24 * time.Hour),
			UpdatedAt: now,
			LastRun:   &now,
			NextRun:   &nextRun,
		},
		{
			ID:          "policy-alerts-180d",
			Name:        "Alerts - 180 Days Retention",
			Description: "Archive critical alerts older than 180 days",
			Enabled:     true,
			DataType:    "alerts",
			Priority:    3,
			Schedule:    "0 4 * * 0", // Weekly on Sunday at 4 AM
			Conditions: []RetentionCondition{
				{Field: "age", Operator: "gt", Value: 180},
			},
			Actions: []RetentionAction{
				{Type: "archive", Target: "s3://archive-bucket/alerts"},
			},
			CreatedAt: now.Add(-90 * 24 * time.Hour),
			UpdatedAt: now,
			NextRun:   &nextRun,
		},
	}

	for _, policy := range policies {
		retentionPolicies[policy.ID] = &policy
	}
}

func createSampleExecutions() {
	now := time.Now()
	
	executions := []RetentionExecution{
		{
			ID:             "exec-1",
			PolicyID:       "policy-events-90d",
			PolicyName:     "Events - 90 Days Retention",
			Status:         "completed",
			StartTime:      now.Add(-2 * time.Hour),
			EndTime:        &[]time.Time{now.Add(-1 * time.Hour)}[0],
			ItemsProcessed: 15000,
			ItemsArchived:  15000,
			ItemsDeleted:   0,
			BytesProcessed: 15000 * 1024 * 1024,
			BytesSaved:     7500 * 1024 * 1024,
			Logs: []string{
				"Starting execution of policy: Events - 90 Days Retention",
				"Processing data older than 90 days",
				"Archived 15000 items",
				"Compressed 15000 items, saved 7500 MB",
				"Execution completed successfully",
			},
		},
		{
			ID:             "exec-2",
			PolicyID:       "policy-logs-30d",
			PolicyName:     "Logs - 30 Days Retention",
			Status:         "completed",
			StartTime:      now.Add(-1 * time.Hour),
			EndTime:        &[]time.Time{now.Add(-30 * time.Minute)}[0],
			ItemsProcessed: 50000,
			ItemsArchived:  0,
			ItemsDeleted:   50000,
			BytesProcessed: 50000 * 512 * 1024,
			BytesSaved:     50000 * 512 * 1024,
			Logs: []string{
				"Starting execution of policy: Logs - 30 Days Retention",
				"Processing data older than 30 days",
				"Deleted 50000 items",
				"Execution completed successfully",
			},
		},
	}

	for _, exec := range executions {
		retentionExecutions[exec.ID] = &exec
	}
}

