package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// TriageAction represents quick actions for alert triage
type TriageActionRequest struct {
	Action   string `json:"action"` // acknowledge, dismiss, escalate, assign, resolve, false_positive
	Reason   string `json:"reason"`
	AssignTo string `json:"assign_to"`
	Notes    string `json:"notes"`
	Priority string `json:"priority"`
}

// AlertForTriage represents an alert ready for triage
type AlertForTriage struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Source         string                 `json:"source"`
	Severity       string                 `json:"severity"`
	Status         string                 `json:"status"`
	Category       string                 `json:"category"`
	ResourceID     string                 `json:"resource_id"`
	ResourceType   string                 `json:"resource_type"`
	Region         string                 `json:"region"`
	AccountID      string                 `json:"account_id"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	DetectedAt     time.Time              `json:"detected_at"`
	Recommendation string                 `json:"recommendation"`
	Tags           []string               `json:"tags"`
	TriageStatus   string                 `json:"triage_status"` // pending, acknowledged, investigating, resolved, dismissed, escalated
	TriagedBy      string                 `json:"triaged_by"`
	TriagedAt      *time.Time             `json:"triaged_at"`
	Notes          string                 `json:"notes"`
	PriorityScore  float64                `json:"priority_score"`
	FalsePositive  bool                   `json:"false_positive"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// handleGetAlertsForTriage returns alerts pending triage from OpenSearch
func (s *APIServer) handleGetAlertsForTriage(c *gin.Context) {
	if s.opensearch == nil {
		// Return mock data if OpenSearch not available
		s.handleListTriageResults(c)
		return
	}

	status := c.DefaultQuery("status", "")
	severity := c.DefaultQuery("severity", "")
	source := c.DefaultQuery("source", "")
	pageSize := 50
	if ps := c.Query("page_size"); ps != "" {
		fmt.Sscanf(ps, "%d", &pageSize)
	}

	// Build query with RBAC filter
	must := []map[string]interface{}{}

	// Apply access scope filter for RBAC
	scope := getAccessScope(c)
	accessFilters := buildAlertAccessFilter(scope)
	if len(accessFilters) > 0 {
		must = append(must, accessFilters...)
	}

	if status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"status": status,
			},
		})
	}

	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"severity": strings.ToUpper(severity),
			},
		})
	}

	if source != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"source": source,
			},
		})
	}

	query := map[string]interface{}{
		"size":             pageSize,
		"track_total_hits": true,
		"sort": []map[string]interface{}{
			{"created_at": map[string]interface{}{"order": "desc"}},
		},
	}

	if len(must) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ Error searching alerts for triage: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to fetch alerts",
		})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ OpenSearch error: %s", res.String())
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "OpenSearch query failed",
		})
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	// Parse results
	alerts := []AlertForTriage{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			total = int(totalObj["value"].(float64))
		}

		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				hitMap := hit.(map[string]interface{})
				source := hitMap["_source"].(map[string]interface{})

				alert := AlertForTriage{
					ID:             getTriageString(source, "id"),
					Name:           getTriageString(source, "name"),
					Description:    getTriageString(source, "description"),
					Source:         getTriageString(source, "source"),
					Severity:       getTriageString(source, "severity"),
					Status:         getTriageString(source, "status"),
					Category:       getTriageString(source, "category"),
					ResourceID:     getTriageString(source, "resource_id"),
					ResourceType:   getTriageString(source, "resource_type"),
					Region:         getTriageString(source, "region"),
					AccountID:      getTriageString(source, "account_id"),
					Recommendation: getTriageString(source, "recommendation"),
					TriageStatus:   getTriageString(source, "triage_status"),
					TriagedBy:      getTriageString(source, "triaged_by"),
					Notes:          getTriageString(source, "notes"),
					FalsePositive:  getTriageBool(source, "false_positive"),
				}

				// Parse dates
				if createdStr := getTriageString(source, "created_at"); createdStr != "" {
					if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
						alert.CreatedAt = t
					}
				}
				if detectedStr := getTriageString(source, "detected_at"); detectedStr != "" {
					if t, err := time.Parse(time.RFC3339, detectedStr); err == nil {
						alert.DetectedAt = t
					}
				}

				// Parse tags
				if tags, ok := source["tags"].([]interface{}); ok {
					for _, tag := range tags {
						if t, ok := tag.(string); ok {
							alert.Tags = append(alert.Tags, t)
						}
					}
				}

				// Calculate priority score
				alert.PriorityScore = calculateAlertPriority(alert)

				// Default triage status
				if alert.TriageStatus == "" {
					alert.TriageStatus = "pending"
				}

				alerts = append(alerts, alert)
			}
		}
	}

	// Calculate statistics
	stats := calculateTriageStats(alerts)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    alerts,
		"total":   total,
		"stats":   stats,
	})
}

// handleTriageAlertAction performs a triage action on an alert
func (s *APIServer) handleTriageAlertAction(c *gin.Context) {
	alertID := c.Param("id")

	var req TriageActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// Get current user from context
	user := "admin" // Default
	if u, exists := c.Get("user"); exists {
		if userMap, ok := u.(map[string]interface{}); ok {
			if username, ok := userMap["username"].(string); ok {
				user = username
			}
		}
	}

	// Build update based on action
	var newStatus string
	updates := map[string]interface{}{
		"updated_at": time.Now().Format(time.RFC3339),
		"triaged_by": user,
		"triaged_at": time.Now().Format(time.RFC3339),
	}

	switch req.Action {
	case "acknowledge":
		newStatus = "acknowledged"
		updates["triage_status"] = newStatus
		updates["notes"] = req.Notes

	case "dismiss":
		newStatus = "dismissed"
		updates["triage_status"] = newStatus
		updates["status"] = "dismissed"
		updates["dismiss_reason"] = req.Reason
		updates["notes"] = req.Notes

	case "escalate":
		newStatus = "escalated"
		updates["triage_status"] = newStatus
		updates["status"] = "escalated"
		updates["escalate_reason"] = req.Reason
		updates["priority"] = req.Priority
		if req.AssignTo != "" {
			updates["assigned_to"] = req.AssignTo
		}
		updates["notes"] = req.Notes

	case "assign":
		newStatus = "investigating"
		updates["triage_status"] = newStatus
		updates["assigned_to"] = req.AssignTo
		updates["notes"] = req.Notes

	case "resolve":
		newStatus = "resolved"
		updates["triage_status"] = newStatus
		updates["status"] = "resolved"
		updates["resolution"] = req.Reason
		updates["notes"] = req.Notes

	case "false_positive":
		newStatus = "false_positive"
		updates["triage_status"] = newStatus
		updates["status"] = "false_positive"
		updates["false_positive"] = true
		updates["fp_reason"] = req.Reason
		updates["notes"] = req.Notes

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid action. Use: acknowledge, dismiss, escalate, assign, resolve, false_positive",
		})
		return
	}

	// Update in OpenSearch
	if s.opensearch != nil {
		updateDoc := map[string]interface{}{
			"doc": updates,
		}
		updateJSON, _ := json.Marshal(updateDoc)

		res, err := s.opensearch.Update(
			"siem-alerts",
			alertID,
			strings.NewReader(string(updateJSON)),
		)
		if err != nil {
			log.Printf("❌ Error updating alert %s: %v", alertID, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Failed to update alert",
			})
			return
		}
		defer res.Body.Close()

		if res.IsError() {
			log.Printf("❌ OpenSearch update error for %s: %s", alertID, res.String())
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Failed to update alert in OpenSearch",
			})
			return
		}
	}

	log.Printf("✅ Alert %s triaged: action=%s, by=%s", alertID, req.Action, user)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Alert %s successfully", req.Action),
		"data": gin.H{
			"alert_id":   alertID,
			"action":     req.Action,
			"new_status": newStatus,
			"triaged_by": user,
			"triaged_at": time.Now().Format(time.RFC3339),
		},
	})
}

// handleBulkTriageAction performs triage action on multiple alerts
func (s *APIServer) handleBulkTriageAction(c *gin.Context) {
	var req struct {
		AlertIDs []string            `json:"alert_ids"`
		Action   TriageActionRequest `json:"action"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	if len(req.AlertIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "No alert IDs provided",
		})
		return
	}

	// Get current user
	user := "admin"
	if u, exists := c.Get("user"); exists {
		if userMap, ok := u.(map[string]interface{}); ok {
			if username, ok := userMap["username"].(string); ok {
				user = username
			}
		}
	}

	successCount := 0
	failedCount := 0
	failedIDs := []string{}

	for _, alertID := range req.AlertIDs {
		// Build update based on action
		updates := map[string]interface{}{
			"updated_at":    time.Now().Format(time.RFC3339),
			"triaged_by":    user,
			"triaged_at":    time.Now().Format(time.RFC3339),
			"triage_status": req.Action.Action,
			"notes":         req.Action.Notes,
		}

		switch req.Action.Action {
		case "dismiss":
			updates["status"] = "dismissed"
			updates["dismiss_reason"] = req.Action.Reason
		case "acknowledge":
			updates["triage_status"] = "acknowledged"
		case "false_positive":
			updates["status"] = "false_positive"
			updates["false_positive"] = true
			updates["fp_reason"] = req.Action.Reason
		case "resolve":
			updates["status"] = "resolved"
			updates["resolution"] = req.Action.Reason
		}

		if s.opensearch != nil {
			updateDoc := map[string]interface{}{"doc": updates}
			updateJSON, _ := json.Marshal(updateDoc)

			res, err := s.opensearch.Update(
				"siem-alerts",
				alertID,
				strings.NewReader(string(updateJSON)),
			)
			if err != nil || res.IsError() {
				failedCount++
				failedIDs = append(failedIDs, alertID)
				if res != nil {
					res.Body.Close()
				}
				continue
			}
			res.Body.Close()
		}
		successCount++
	}

	log.Printf("✅ Bulk triage: %d success, %d failed, action=%s, by=%s",
		successCount, failedCount, req.Action.Action, user)

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"message":       fmt.Sprintf("Bulk action completed: %d success, %d failed", successCount, failedCount),
		"success_count": successCount,
		"failed_count":  failedCount,
		"failed_ids":    failedIDs,
	})
}

// handleGetTriageStatistics returns real-time triage statistics
func (s *APIServer) handleGetTriageStatistics(c *gin.Context) {
	if s.opensearch == nil {
		s.handleGetTriageStats(c)
		return
	}

	// Build query with RBAC filter
	scope := getAccessScope(c)
	accessFilters := buildAlertAccessFilter(scope)

	// Build aggregation query for triage statistics
	query := map[string]interface{}{
		"size":             0,
		"track_total_hits": true,
		"aggs": map[string]interface{}{
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{"field": "severity", "size": 10},
			},
			"by_status": map[string]interface{}{
				"terms": map[string]interface{}{"field": "status", "size": 10},
			},
			"by_triage_status": map[string]interface{}{
				"terms": map[string]interface{}{"field": "triage_status", "size": 10},
			},
			"by_source": map[string]interface{}{
				"terms": map[string]interface{}{"field": "source", "size": 10},
			},
			"pending_count": map[string]interface{}{
				"filter": map[string]interface{}{
					"bool": map[string]interface{}{
						"should": []map[string]interface{}{
							{"term": map[string]interface{}{"triage_status": "pending"}},
							{"bool": map[string]interface{}{"must_not": map[string]interface{}{"exists": map[string]interface{}{"field": "triage_status"}}}},
						},
					},
				},
			},
			"last_24h": map[string]interface{}{
				"filter": map[string]interface{}{
					"range": map[string]interface{}{"created_at": map[string]interface{}{"gte": "now-24h"}},
				},
			},
			"false_positives": map[string]interface{}{
				"filter": map[string]interface{}{
					"term": map[string]interface{}{"false_positive": true},
				},
			},
		},
	}

	// Apply access scope filter if present
	if len(accessFilters) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{
				"must": accessFilters,
			},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ Error getting triage stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to get statistics",
		})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	// Parse statistics
	stats := gin.H{
		"total_alerts":     0,
		"pending_alerts":   0,
		"triaged_alerts":   0,
		"false_positives":  0,
		"last_24h_alerts":  0,
		"by_severity":      map[string]int{},
		"by_status":        map[string]int{},
		"by_triage_status": map[string]int{},
		"by_source":        map[string]int{},
	}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			stats["total_alerts"] = int(total["value"].(float64))
		}
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		// By severity
		if sevAgg, ok := aggs["by_severity"].(map[string]interface{}); ok {
			bySev := map[string]int{}
			if buckets, ok := sevAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					bySev[bucket["key"].(string)] = int(bucket["doc_count"].(float64))
				}
			}
			stats["by_severity"] = bySev
		}

		// By status
		if statusAgg, ok := aggs["by_status"].(map[string]interface{}); ok {
			byStatus := map[string]int{}
			if buckets, ok := statusAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					byStatus[bucket["key"].(string)] = int(bucket["doc_count"].(float64))
				}
			}
			stats["by_status"] = byStatus
		}

		// By triage status
		if triageAgg, ok := aggs["by_triage_status"].(map[string]interface{}); ok {
			byTriage := map[string]int{}
			if buckets, ok := triageAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					byTriage[bucket["key"].(string)] = int(bucket["doc_count"].(float64))
				}
			}
			stats["by_triage_status"] = byTriage
		}

		// By source
		if sourceAgg, ok := aggs["by_source"].(map[string]interface{}); ok {
			bySource := map[string]int{}
			if buckets, ok := sourceAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					bySource[bucket["key"].(string)] = int(bucket["doc_count"].(float64))
				}
			}
			stats["by_source"] = bySource
		}

		// Pending count
		if pending, ok := aggs["pending_count"].(map[string]interface{}); ok {
			stats["pending_alerts"] = int(pending["doc_count"].(float64))
		}

		// Last 24h
		if last24h, ok := aggs["last_24h"].(map[string]interface{}); ok {
			stats["last_24h_alerts"] = int(last24h["doc_count"].(float64))
		}

		// False positives
		if fp, ok := aggs["false_positives"].(map[string]interface{}); ok {
			stats["false_positives"] = int(fp["doc_count"].(float64))
		}
	}

	// Calculate triaged
	totalAlerts := stats["total_alerts"].(int)
	pendingAlerts := stats["pending_alerts"].(int)
	stats["triaged_alerts"] = totalAlerts - pendingAlerts

	// Calculate false positive rate
	triaged := stats["triaged_alerts"].(int)
	fps := stats["false_positives"].(int)
	if triaged > 0 {
		stats["false_positive_rate"] = float64(fps) / float64(triaged) * 100
	} else {
		stats["false_positive_rate"] = 0.0
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}

// Helper functions

func getTriageString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getTriageBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func calculateAlertPriority(alert AlertForTriage) float64 {
	score := 50.0

	// Severity factor
	switch strings.ToUpper(alert.Severity) {
	case "CRITICAL":
		score += 40
	case "HIGH":
		score += 25
	case "MEDIUM":
		score += 10
	case "LOW":
		score += 0
	}

	// Source factor (some sources are more reliable)
	switch alert.Source {
	case "guardduty":
		score += 10
	case "inspector":
		score += 5
	case "securityhub":
		score += 5
	}

	// Recency factor
	age := time.Since(alert.CreatedAt)
	if age < 1*time.Hour {
		score += 10
	} else if age < 24*time.Hour {
		score += 5
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func calculateTriageStats(alerts []AlertForTriage) map[string]interface{} {
	stats := map[string]interface{}{
		"total":            len(alerts),
		"pending":          0,
		"acknowledged":     0,
		"investigating":    0,
		"resolved":         0,
		"dismissed":        0,
		"escalated":        0,
		"false_positives":  0,
		"critical_pending": 0,
		"high_pending":     0,
	}

	for _, alert := range alerts {
		switch alert.TriageStatus {
		case "pending", "":
			stats["pending"] = stats["pending"].(int) + 1
			if alert.Severity == "CRITICAL" {
				stats["critical_pending"] = stats["critical_pending"].(int) + 1
			} else if alert.Severity == "HIGH" {
				stats["high_pending"] = stats["high_pending"].(int) + 1
			}
		case "acknowledged":
			stats["acknowledged"] = stats["acknowledged"].(int) + 1
		case "investigating":
			stats["investigating"] = stats["investigating"].(int) + 1
		case "resolved":
			stats["resolved"] = stats["resolved"].(int) + 1
		case "dismissed":
			stats["dismissed"] = stats["dismissed"].(int) + 1
		case "escalated":
			stats["escalated"] = stats["escalated"].(int) + 1
		case "false_positive":
			stats["false_positives"] = stats["false_positives"].(int) + 1
		}
	}

	return stats
}
