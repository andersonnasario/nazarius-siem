package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const playbooksIndex = "siem-playbooks"
const executionsIndex = "siem-executions"

// PlaybookOpenSearch represents a playbook stored in OpenSearch
type PlaybookOpenSearch struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Description      string           `json:"description"`
	Category         string           `json:"category"`
	Trigger          string           `json:"trigger"`
	TriggerType      string           `json:"trigger_type"`
	TriggerConditions []string        `json:"trigger_conditions"`
	Actions          []PlaybookAction `json:"actions"`
	Status           string           `json:"status"`
	Executions       int              `json:"executions"`
	SuccessCount     int              `json:"success_count"`
	FailureCount     int              `json:"failure_count"`
	SuccessRate      float64          `json:"success_rate"`
	AvgExecutionTime int              `json:"avg_execution_time_ms"`
	LastExecution    *time.Time       `json:"last_execution,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
	CreatedBy        string           `json:"created_by"`
	Tags             []string         `json:"tags"`
	Steps            int              `json:"steps"`
}

// ExecutionOpenSearch represents a playbook execution stored in OpenSearch
type ExecutionOpenSearch struct {
	ID              string                 `json:"id"`
	PlaybookID      string                 `json:"playbook_id"`
	PlaybookName    string                 `json:"playbook_name"`
	Status          string                 `json:"status"`
	TriggerType     string                 `json:"trigger_type"`
	TriggerSource   string                 `json:"trigger_source"`
	TriggerAlertID  string                 `json:"trigger_alert_id,omitempty"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         *time.Time             `json:"end_time,omitempty"`
	Duration        int                    `json:"duration_ms"`
	CurrentStep     int                    `json:"current_step"`
	TotalSteps      int                    `json:"total_steps"`
	SuccessfulSteps int                    `json:"successful_steps"`
	FailedSteps     int                    `json:"failed_steps"`
	ExecutedBy      string                 `json:"executed_by"`
	Results         map[string]interface{} `json:"results"`
	Logs            []string               `json:"logs"`
	Error           string                 `json:"error,omitempty"`
}

// EnsurePlaybooksIndex creates the siem-playbooks index if it doesn't exist
func (s *APIServer) EnsurePlaybooksIndex() {
	if s.opensearch == nil {
		return
	}

	mapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"description": { "type": "text" },
				"category": { "type": "keyword" },
				"trigger": { "type": "keyword" },
				"trigger_type": { "type": "keyword" },
				"trigger_conditions": { "type": "keyword" },
				"status": { "type": "keyword" },
				"executions": { "type": "integer" },
				"success_count": { "type": "integer" },
				"failure_count": { "type": "integer" },
				"success_rate": { "type": "float" },
				"avg_execution_time_ms": { "type": "integer" },
				"last_execution": { "type": "date" },
				"created_at": { "type": "date" },
				"updated_at": { "type": "date" },
				"created_by": { "type": "keyword" },
				"tags": { "type": "keyword" },
				"steps": { "type": "integer" }
			}
		}
	}`

	res, err := s.opensearch.Indices.Exists([]string{playbooksIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			playbooksIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(mapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", playbooksIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", playbooksIndex)
		}
	}
}

// EnsureExecutionsIndex creates the siem-executions index if it doesn't exist
func (s *APIServer) EnsureExecutionsIndex() {
	if s.opensearch == nil {
		return
	}

	mapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"playbook_id": { "type": "keyword" },
				"playbook_name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"status": { "type": "keyword" },
				"trigger_type": { "type": "keyword" },
				"trigger_source": { "type": "keyword" },
				"trigger_alert_id": { "type": "keyword" },
				"start_time": { "type": "date" },
				"end_time": { "type": "date" },
				"duration_ms": { "type": "integer" },
				"current_step": { "type": "integer" },
				"total_steps": { "type": "integer" },
				"successful_steps": { "type": "integer" },
				"failed_steps": { "type": "integer" },
				"executed_by": { "type": "keyword" },
				"error": { "type": "text" }
			}
		}
	}`

	res, err := s.opensearch.Indices.Exists([]string{executionsIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			executionsIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(mapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", executionsIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", executionsIndex)
		}
	}
}

// handleListPlaybooksOpenSearch lists playbooks from OpenSearch
func (s *APIServer) handleListPlaybooksOpenSearch(c *gin.Context) {
	if s.opensearch == nil {
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"playbooks": []PlaybookOpenSearch{},
				"total":     0,
				"source":    "opensearch",
			})
			return
		}
		s.handleListPlaybooksMock(c)
		return
	}

	// Parse filters
	status := c.Query("status")
	category := c.Query("category")

	// Build query
	must := []map[string]interface{}{}
	if status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"status": status},
		})
	}
	if category != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"category": category},
		})
	}

	query := map[string]interface{}{
		"size":             100,
		"track_total_hits": true,
		"sort": []map[string]interface{}{
			{"updated_at": map[string]interface{}{"order": "desc"}},
		},
	}

	if len(must) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{"must": must},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(playbooksIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ Error searching playbooks: %v", err)
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"playbooks": []PlaybookOpenSearch{},
				"total":     0,
				"source":    "opensearch",
			})
			return
		}
		s.handleListPlaybooksMock(c)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ OpenSearch error: %s", res.String())
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"playbooks": []PlaybookOpenSearch{},
				"total":     0,
				"source":    "opensearch",
			})
			return
		}
		s.handleListPlaybooksMock(c)
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	playbooks := []PlaybookOpenSearch{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			total = int(totalObj["value"].(float64))
		}

		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				hitMap := hit.(map[string]interface{})
				source := hitMap["_source"].(map[string]interface{})
				pb := parsePlaybookFromSource(source)
				playbooks = append(playbooks, pb)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"playbooks": playbooks,
		"total":     total,
		"source":    "opensearch",
	})
}

// handleGetPlaybookOpenSearch gets a single playbook from OpenSearch
func (s *APIServer) handleGetPlaybookOpenSearch(c *gin.Context) {
	id := c.Param("id")

	if s.opensearch == nil {
		if IsMockDataDisabled() {
			c.JSON(http.StatusNotFound, gin.H{"error": "Playbook not found"})
			return
		}
		s.handleGetPlaybookMock(c, id)
		return
	}

	res, err := s.opensearch.Get(playbooksIndex, id)
	if err != nil {
		log.Printf("❌ Error getting playbook %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get playbook"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Playbook not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get playbook"})
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	if source, ok := result["_source"].(map[string]interface{}); ok {
		pb := parsePlaybookFromSource(source)
		c.JSON(http.StatusOK, pb)
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Playbook not found"})
}

// handleCreatePlaybookOpenSearch creates a new playbook in OpenSearch
func (s *APIServer) handleCreatePlaybookOpenSearch(c *gin.Context) {
	var pb PlaybookOpenSearch
	if err := c.ShouldBindJSON(&pb); err != nil {
		log.Printf("[ERROR] handleCreatePlaybookOpenSearch bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Set defaults
	pb.ID = uuid.New().String()
	pb.CreatedAt = time.Now()
	pb.UpdatedAt = time.Now()
	if pb.Status == "" {
		pb.Status = "draft"
	}
	pb.Executions = 0
	pb.SuccessCount = 0
	pb.FailureCount = 0
	pb.SuccessRate = 0
	pb.AvgExecutionTime = 0
	pb.Steps = len(pb.Actions)

	// Get user from context
	if user, exists := c.Get("user"); exists {
		if userMap, ok := user.(map[string]interface{}); ok {
			if username, ok := userMap["username"].(string); ok {
				pb.CreatedBy = username
			}
		}
	}
	if pb.CreatedBy == "" {
		pb.CreatedBy = getUsernameFromContext(c)
	}

	if s.opensearch == nil {
		c.JSON(http.StatusCreated, gin.H{
			"success": true,
			"data":    pb,
			"message": "Playbook created (mock mode)",
		})
		return
	}

	// Index to OpenSearch
	pbJSON, _ := json.Marshal(pb)

	res, err := s.opensearch.Index(
		playbooksIndex,
		strings.NewReader(string(pbJSON)),
		s.opensearch.Index.WithDocumentID(pb.ID),
	)
	if err != nil {
		log.Printf("❌ Error creating playbook: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create playbook"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ OpenSearch error creating playbook: %s", res.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create playbook"})
		return
	}

	log.Printf("✅ Playbook %s created: %s", pb.ID, pb.Name)

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    pb,
		"message": "Playbook created successfully",
	})
}

// handleUpdatePlaybookOpenSearch updates a playbook in OpenSearch
func (s *APIServer) handleUpdatePlaybookOpenSearch(c *gin.Context) {
	id := c.Param("id")

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		log.Printf("[ERROR] handleUpdatePlaybookOpenSearch bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	updates["updated_at"] = time.Now().Format(time.RFC3339)

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Playbook updated (mock mode)",
			"id":      id,
		})
		return
	}

	updateDoc := map[string]interface{}{"doc": updates}
	updateJSON, _ := json.Marshal(updateDoc)

	res, err := s.opensearch.Update(
		playbooksIndex,
		id,
		strings.NewReader(string(updateJSON)),
	)
	if err != nil {
		log.Printf("❌ Error updating playbook %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update playbook"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Playbook not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update playbook"})
		return
	}

	log.Printf("✅ Playbook %s updated", id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Playbook updated successfully",
		"id":      id,
	})
}

// handleDeletePlaybookOpenSearch deletes a playbook from OpenSearch
func (s *APIServer) handleDeletePlaybookOpenSearch(c *gin.Context) {
	id := c.Param("id")

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Playbook deleted (mock mode)",
			"id":      id,
		})
		return
	}

	res, err := s.opensearch.Delete(playbooksIndex, id)
	if err != nil {
		log.Printf("❌ Error deleting playbook %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete playbook"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Playbook not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete playbook"})
		return
	}

	log.Printf("✅ Playbook %s deleted", id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Playbook deleted successfully",
		"id":      id,
	})
}

// handleExecutePlaybookOpenSearch executes a playbook and logs the execution
func (s *APIServer) handleExecutePlaybookOpenSearch(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		TriggerSource  string                 `json:"trigger_source"`
		TriggerAlertID string                 `json:"trigger_alert_id"`
		Parameters     map[string]interface{} `json:"parameters"`
	}
	c.ShouldBindJSON(&req)

	// Get playbook details
	var playbookName string
	var totalSteps int

	if s.opensearch != nil {
		res, err := s.opensearch.Get(playbooksIndex, id)
		if err == nil && !res.IsError() {
			var result map[string]interface{}
			json.NewDecoder(res.Body).Decode(&result)
			res.Body.Close()

			if source, ok := result["_source"].(map[string]interface{}); ok {
				if name, ok := source["name"].(string); ok {
					playbookName = name
				}
				if steps, ok := source["steps"].(float64); ok {
					totalSteps = int(steps)
				}
			}
		}
	}

	if playbookName == "" {
		playbookName = "Unknown Playbook"
	}
	if totalSteps == 0 {
		totalSteps = 5
	}

	// Get user
	executedBy := "system"
	if user, exists := c.Get("user"); exists {
		if userMap, ok := user.(map[string]interface{}); ok {
			if username, ok := userMap["username"].(string); ok {
				executedBy = username
			}
		}
	}

	// Create execution record
	execution := ExecutionOpenSearch{
		ID:              uuid.New().String(),
		PlaybookID:      id,
		PlaybookName:    playbookName,
		Status:          "running",
		TriggerType:     "manual",
		TriggerSource:   req.TriggerSource,
		TriggerAlertID:  req.TriggerAlertID,
		StartTime:       time.Now(),
		CurrentStep:     1,
		TotalSteps:      totalSteps,
		SuccessfulSteps: 0,
		FailedSteps:     0,
		ExecutedBy:      executedBy,
		Results:         map[string]interface{}{},
		Logs:            []string{fmt.Sprintf("Execution started by %s", executedBy)},
	}

	// Save execution to OpenSearch
	if s.opensearch != nil {
		execJSON, _ := json.Marshal(execution)
		res, err := s.opensearch.Index(
			executionsIndex,
			strings.NewReader(string(execJSON)),
			s.opensearch.Index.WithDocumentID(execution.ID),
		)
		if err != nil {
			log.Printf("❌ Error creating execution: %v", err)
		} else {
			res.Body.Close()
		}

		// Update playbook execution count
		updateDoc := map[string]interface{}{
			"script": map[string]interface{}{
				"source": "ctx._source.executions += 1; ctx._source.last_execution = params.now",
				"params": map[string]interface{}{
					"now": time.Now().Format(time.RFC3339),
				},
			},
		}
		updateJSON, _ := json.Marshal(updateDoc)
		s.opensearch.Update(playbooksIndex, id, strings.NewReader(string(updateJSON)))
	}

	log.Printf("✅ Playbook %s execution started: %s", id, execution.ID)

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"execution_id": execution.ID,
		"status":       "running",
		"message":      fmt.Sprintf("Playbook '%s' execution started", playbookName),
	})
}

// handleListExecutionsOpenSearch lists playbook executions from OpenSearch
func (s *APIServer) handleListExecutionsOpenSearch(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"executions": []ExecutionOpenSearch{},
			"total":      0,
			"source":     "opensearch",
			"info":       "OpenSearch not available",
		})
		return
	}

	// Parse filters
	playbookID := c.Query("playbook_id")
	status := c.Query("status")

	// Build query
	must := []map[string]interface{}{}
	if playbookID != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"playbook_id": playbookID},
		})
	}
	if status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"status": status},
		})
	}

	query := map[string]interface{}{
		"size":             100,
		"track_total_hits": true,
		"sort": []map[string]interface{}{
			{"start_time": map[string]interface{}{"order": "desc"}},
		},
	}

	if len(must) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{"must": must},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(executionsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ Error searching executions: %v", err)
		c.JSON(http.StatusOK, gin.H{
			"executions": []ExecutionOpenSearch{},
			"total":      0,
			"source":     "opensearch",
		})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ OpenSearch error: %s", res.String())
		c.JSON(http.StatusOK, gin.H{
			"executions": []ExecutionOpenSearch{},
			"total":      0,
			"source":     "opensearch",
		})
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	executions := []ExecutionOpenSearch{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			total = int(totalObj["value"].(float64))
		}

		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				hitMap := hit.(map[string]interface{})
				source := hitMap["_source"].(map[string]interface{})
				exec := parseExecutionFromSource(source)
				executions = append(executions, exec)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"executions": executions,
		"total":      total,
		"source":     "opensearch",
	})
}

// handleGetPlaybookStatisticsOpenSearch returns real-time playbook statistics
func (s *APIServer) handleGetPlaybookStatisticsOpenSearch(c *gin.Context) {
	emptyStats := gin.H{
		"success": true,
		"data": gin.H{
			"total_playbooks":    0,
			"active_playbooks":   0,
			"executions_today":   0,
			"success_rate":       0.0,
			"avg_execution_time": "0ms",
			"by_category":        map[string]int{},
			"by_status":          map[string]int{},
		},
		"source": "opensearch",
	}

	if s.opensearch == nil {
		c.JSON(http.StatusOK, emptyStats)
		return
	}

	// Query playbooks statistics
	playbookQuery := `{
		"size": 0,
		"track_total_hits": true,
		"aggs": {
			"by_status": {
				"terms": { "field": "status", "size": 10 }
			},
			"by_category": {
				"terms": { "field": "category", "size": 20 }
			},
			"total_executions": {
				"sum": { "field": "executions" }
			},
			"total_success": {
				"sum": { "field": "success_count" }
			},
			"avg_exec_time": {
				"avg": { "field": "avg_execution_time_ms" }
			}
		}
	}`

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(playbooksIndex),
		s.opensearch.Search.WithBody(strings.NewReader(playbookQuery)),
	)
	if err != nil {
		log.Printf("❌ Error getting playbook statistics: %v", err)
		c.JSON(http.StatusOK, emptyStats)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		c.JSON(http.StatusOK, emptyStats)
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	stats := gin.H{
		"total_playbooks":    0,
		"active_playbooks":   0,
		"executions_today":   0,
		"success_rate":       0.0,
		"avg_execution_time": "0ms",
		"by_category":        map[string]int{},
		"by_status":          map[string]int{},
	}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			stats["total_playbooks"] = int(total["value"].(float64))
		}
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		// By status
		if statusAgg, ok := aggs["by_status"].(map[string]interface{}); ok {
			byStatus := map[string]int{}
			if buckets, ok := statusAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					key := bucket["key"].(string)
					count := int(bucket["doc_count"].(float64))
					byStatus[key] = count
					if key == "active" {
						stats["active_playbooks"] = count
					}
				}
			}
			stats["by_status"] = byStatus
		}

		// By category
		if catAgg, ok := aggs["by_category"].(map[string]interface{}); ok {
			byCat := map[string]int{}
			if buckets, ok := catAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					byCat[bucket["key"].(string)] = int(bucket["doc_count"].(float64))
				}
			}
			stats["by_category"] = byCat
		}

		// Calculate success rate
		totalExec := 0.0
		totalSuccess := 0.0
		if execAgg, ok := aggs["total_executions"].(map[string]interface{}); ok {
			if v, ok := execAgg["value"].(float64); ok {
				totalExec = v
			}
		}
		if successAgg, ok := aggs["total_success"].(map[string]interface{}); ok {
			if v, ok := successAgg["value"].(float64); ok {
				totalSuccess = v
			}
		}
		if totalExec > 0 {
			stats["success_rate"] = (totalSuccess / totalExec) * 100
		}

		// Avg execution time
		if avgAgg, ok := aggs["avg_exec_time"].(map[string]interface{}); ok {
			if v, ok := avgAgg["value"].(float64); ok {
				if v > 1000 {
					stats["avg_execution_time"] = fmt.Sprintf("%.1fs", v/1000)
				} else {
					stats["avg_execution_time"] = fmt.Sprintf("%.0fms", v)
				}
			}
		}
	}

	// Get today's executions
	todayQuery := fmt.Sprintf(`{
		"size": 0,
		"query": {
			"range": {
				"start_time": {
					"gte": "%s"
				}
			}
		}
	}`, time.Now().Truncate(24*time.Hour).Format(time.RFC3339))

	res2, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(executionsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(todayQuery)),
	)
	if err == nil && !res2.IsError() {
		var result2 map[string]interface{}
		json.NewDecoder(res2.Body).Decode(&result2)
		res2.Body.Close()

		if hits, ok := result2["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				stats["executions_today"] = int(total["value"].(float64))
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
		"source":  "opensearch",
	})
}

// Helper functions
func parsePlaybookFromSource(source map[string]interface{}) PlaybookOpenSearch {
	pb := PlaybookOpenSearch{
		ID:          getStrVal(source, "id"),
		Name:        getStrVal(source, "name"),
		Description: getStrVal(source, "description"),
		Category:    getStrVal(source, "category"),
		Trigger:     getStrVal(source, "trigger"),
		TriggerType: getStrVal(source, "trigger_type"),
		Status:      getStrVal(source, "status"),
		CreatedBy:   getStrVal(source, "created_by"),
	}

	if v, ok := source["executions"].(float64); ok {
		pb.Executions = int(v)
	}
	if v, ok := source["success_count"].(float64); ok {
		pb.SuccessCount = int(v)
	}
	if v, ok := source["failure_count"].(float64); ok {
		pb.FailureCount = int(v)
	}
	if v, ok := source["success_rate"].(float64); ok {
		pb.SuccessRate = v
	}
	if v, ok := source["avg_execution_time_ms"].(float64); ok {
		pb.AvgExecutionTime = int(v)
	}
	if v, ok := source["steps"].(float64); ok {
		pb.Steps = int(v)
	}

	// Parse dates
	if createdStr := getStrVal(source, "created_at"); createdStr != "" {
		if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
			pb.CreatedAt = t
		}
	}
	if updatedStr := getStrVal(source, "updated_at"); updatedStr != "" {
		if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
			pb.UpdatedAt = t
		}
	}

	// Parse arrays
	if tags, ok := source["tags"].([]interface{}); ok {
		for _, t := range tags {
			if s, ok := t.(string); ok {
				pb.Tags = append(pb.Tags, s)
			}
		}
	}
	if conditions, ok := source["trigger_conditions"].([]interface{}); ok {
		for _, c := range conditions {
			if s, ok := c.(string); ok {
				pb.TriggerConditions = append(pb.TriggerConditions, s)
			}
		}
	}

	return pb
}

func parseExecutionFromSource(source map[string]interface{}) ExecutionOpenSearch {
	exec := ExecutionOpenSearch{
		ID:             getStrVal(source, "id"),
		PlaybookID:    getStrVal(source, "playbook_id"),
		PlaybookName:  getStrVal(source, "playbook_name"),
		Status:        getStrVal(source, "status"),
		TriggerType:   getStrVal(source, "trigger_type"),
		TriggerSource: getStrVal(source, "trigger_source"),
		TriggerAlertID: getStrVal(source, "trigger_alert_id"),
		ExecutedBy:    getStrVal(source, "executed_by"),
		Error:         getStrVal(source, "error"),
	}

	if v, ok := source["duration_ms"].(float64); ok {
		exec.Duration = int(v)
	}
	if v, ok := source["current_step"].(float64); ok {
		exec.CurrentStep = int(v)
	}
	if v, ok := source["total_steps"].(float64); ok {
		exec.TotalSteps = int(v)
	}
	if v, ok := source["successful_steps"].(float64); ok {
		exec.SuccessfulSteps = int(v)
	}
	if v, ok := source["failed_steps"].(float64); ok {
		exec.FailedSteps = int(v)
	}

	// Parse dates
	if startStr := getStrVal(source, "start_time"); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			exec.StartTime = t
		}
	}

	// Parse results and logs
	if results, ok := source["results"].(map[string]interface{}); ok {
		exec.Results = results
	}
	if logs, ok := source["logs"].([]interface{}); ok {
		for _, l := range logs {
			if s, ok := l.(string); ok {
				exec.Logs = append(exec.Logs, s)
			}
		}
	}

	return exec
}

