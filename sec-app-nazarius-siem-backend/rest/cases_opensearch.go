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

const casesIndex = "siem-cases"
const casePoliciesIndex = "siem-case-policies"

// CaseOpenSearch represents a case stored in OpenSearch
type CaseOpenSearch struct {
	ID               string     `json:"id"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	Severity         string     `json:"severity"`
	Status           string     `json:"status"`
	Priority         string     `json:"priority"`
	Category         string     `json:"category"`
	AssignedTo       string     `json:"assigned_to"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	ResolvedAt       *time.Time `json:"resolved_at,omitempty"`
	ClosedAt         *time.Time `json:"closed_at,omitempty"`
	DueDate          *time.Time `json:"due_date,omitempty"`
	Tags             []string   `json:"tags"`
	RelatedAlerts    []string   `json:"related_alerts"`
	RelatedEvents    []string   `json:"related_events"`
	RelatedPlaybooks []string   `json:"related_playbooks"`
	Notes            string     `json:"notes"`
	Resolution       string     `json:"resolution"`
	Source           string     `json:"source"`
	SourceID         string     `json:"source_id"`
	AccountID        string     `json:"account_id,omitempty"` // AWS Account ID para filtro de escopo
	TimeToDetect     int        `json:"time_to_detect"`
	TimeToRespond    int        `json:"time_to_respond"`
	TimeToResolve    int        `json:"time_to_resolve"`
	SLABreach        bool       `json:"sla_breach"`
	SLADeadline      *time.Time `json:"sla_deadline,omitempty"`
	Evidence         []CaseEvidence         `json:"evidence,omitempty"`
	Timeline         []CaseTimelineEntry    `json:"timeline,omitempty"`
	Indicators       map[string]interface{} `json:"indicators,omitempty"`
	MitreTactics     []string               `json:"mitre_tactics,omitempty"`
	MitreTechniques  []string               `json:"mitre_techniques,omitempty"`
	AffectedAssets   []string               `json:"affected_assets,omitempty"`
	Checklist        []CaseChecklistItem    `json:"checklist,omitempty"`
	Recommendations  []CaseRecommendation    `json:"recommendations,omitempty"`
	Summary          *CaseSummary           `json:"summary,omitempty"`
	ResolutionTimeMinutes int               `json:"resolution_time_minutes,omitempty"`
}

// EnsureCasePoliciesIndex creates the index for case policies if it doesn't exist
func (s *APIServer) EnsureCasePoliciesIndex() {
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
				"updated_at": { "type": "date" }
			}
		}
	}`

	res, err := s.opensearch.Indices.Exists([]string{casePoliciesIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			casePoliciesIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(mapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", casePoliciesIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", casePoliciesIndex)
		}
	}
}

// EnsureCasesIndex creates the siem-cases index if it doesn't exist
func (s *APIServer) EnsureCasesIndex() {
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
				"title": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"description": { "type": "text" },
				"severity": { "type": "keyword" },
				"status": { "type": "keyword" },
				"priority": { "type": "keyword" },
				"category": { "type": "keyword" },
				"assigned_to": { "type": "keyword" },
				"created_by": { "type": "keyword" },
				"created_at": { "type": "date" },
				"updated_at": { "type": "date" },
				"resolved_at": { "type": "date" },
				"closed_at": { "type": "date" },
				"due_date": { "type": "date" },
				"tags": { "type": "keyword" },
				"related_alerts": { "type": "keyword" },
				"related_events": { "type": "keyword" },
				"related_playbooks": { "type": "keyword" },
				"notes": { "type": "text" },
				"resolution": { "type": "text" },
				"source": { "type": "keyword" },
				"source_id": { "type": "keyword" },
				"time_to_detect": { "type": "integer" },
				"time_to_respond": { "type": "integer" },
				"time_to_resolve": { "type": "integer" },
				"sla_breach": { "type": "boolean" },
				"sla_deadline": { "type": "date" },
				"evidence": { "type": "object" },
				"timeline": { "type": "object" },
				"indicators": { "type": "object" },
				"mitre_tactics": { "type": "keyword" },
				"mitre_techniques": { "type": "keyword" },
				"affected_assets": { "type": "keyword" },
				"checklist": { "type": "object" }
			}
		}
	}`

	res, err := s.opensearch.Indices.Exists([]string{casesIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			casesIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(mapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", casesIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", casesIndex)
		}
	}
}

// handleListCasesOpenSearch lists cases from OpenSearch
func (s *APIServer) handleListCasesOpenSearch(c *gin.Context) {
	if s.opensearch == nil {
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"cases":  []CaseOpenSearch{},
				"total":  0,
				"source": "opensearch",
				"info":   "OpenSearch not available, no mock data",
			})
			return
		}
		s.handleListCasesMock(c)
		return
	}

	// Parse filters
	status := c.Query("status")
	severity := c.Query("severity")
	assignedTo := c.Query("assigned_to")
	category := c.Query("category")

	// Build query
	must := []map[string]interface{}{}

	if status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"status": status},
		})
	}
	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"severity": severity},
		})
	}
	if assignedTo != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"assigned_to": assignedTo},
		})
	}
	if category != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"category": category},
		})
	}

	// Apply access scope filter (role-based access control)
	accessFilters := buildCaseAccessFilter(getAccessScope(c))
	if len(accessFilters) > 0 {
		must = append(must, accessFilters...)
	}

	query := map[string]interface{}{
		"size":             100,
		"track_total_hits": true,
		"sort": []map[string]interface{}{
			{"created_at": map[string]interface{}{"order": "desc"}},
		},
	}

	if len(must) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{"must": must},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(casesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ Error searching cases: %v", err)
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"cases":  []CaseOpenSearch{},
				"total":  0,
				"source": "opensearch",
				"error":  "OpenSearch connection error",
			})
			return
		}
		s.handleListCasesMock(c)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ OpenSearch error: %s", res.String())
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"cases":  []CaseOpenSearch{},
				"total":  0,
				"source": "opensearch",
				"error":  "OpenSearch query error",
			})
			return
		}
		s.handleListCasesMock(c)
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	cases := []CaseOpenSearch{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			total = int(totalObj["value"].(float64))
		}

		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				hitMap := hit.(map[string]interface{})
				source := hitMap["_source"].(map[string]interface{})

				caseObj := parseCaseFromSource(source)
				cases = append(cases, caseObj)
			}
		}
	}

	// Always return real data - no fallback to mock when DISABLE_MOCK_DATA is true
	// or when we successfully queried OpenSearch (even if empty)
	c.JSON(http.StatusOK, gin.H{
		"cases":  cases,
		"total":  total,
		"source": "opensearch",
	})
}

// handleGetCaseOpenSearch gets a single case from OpenSearch
func (s *APIServer) handleGetCaseOpenSearch(c *gin.Context) {
	id := c.Param("id")

	if s.opensearch == nil {
		if IsMockDataDisabled() {
			c.JSON(http.StatusNotFound, gin.H{"error": "Case not found - OpenSearch not available"})
			return
		}
		s.handleGetCaseMock(c, id)
		return
	}

	res, err := s.opensearch.Get(casesIndex, id)
	if err != nil {
		log.Printf("❌ Error getting case %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get case"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Case not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get case"})
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	if source, ok := result["_source"].(map[string]interface{}); ok {
		caseObj := parseCaseFromSource(source)
		apiCase := &Case{
			Title:            caseObj.Title,
			Severity:         caseObj.Severity,
			Status:           caseObj.Status,
			Priority:         caseObj.Priority,
			Category:         caseObj.Category,
			RelatedAlerts:    caseObj.RelatedAlerts,
			RelatedEvents:    caseObj.RelatedEvents,
			RelatedPlaybooks: []string{},
			TimeToDetect:     caseObj.TimeToDetect,
			TimeToRespond:    caseObj.TimeToRespond,
			TimeToResolve:    caseObj.TimeToResolve,
			SLABreach:        caseObj.SLABreach,
		}
		caseObj.Recommendations = buildCaseRecommendations(apiCase)
		caseObj.Summary = buildCaseSummary(apiCase)
		c.JSON(http.StatusOK, caseObj)
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Case not found"})
}

// handleCreateCaseOpenSearch creates a new case in OpenSearch
func (s *APIServer) handleCreateCaseOpenSearch(c *gin.Context) {
	var caseObj CaseOpenSearch
	if err := c.ShouldBindJSON(&caseObj); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	caseObj.ID = uuid.New().String()
	caseObj.CreatedAt = time.Now()
	caseObj.UpdatedAt = time.Now()
	if caseObj.Status == "" {
		caseObj.Status = "new"
	}
	if caseObj.Priority == "" {
		caseObj.Priority = "medium"
	}

	// Get user from context
	if user, exists := c.Get("user"); exists {
		if userMap, ok := user.(map[string]interface{}); ok {
			if username, ok := userMap["username"].(string); ok {
				caseObj.CreatedBy = username
			}
		}
	}
	if caseObj.CreatedBy == "" {
		caseObj.CreatedBy = "admin"
	}

	// Atribuir account_id do escopo do usuário (se não foi fornecido)
	if caseObj.AccountID == "" {
		scope := getAccessScope(c)
		if len(scope.AccountIDs) > 0 {
			// Usa o primeiro account_id do escopo do usuário
			caseObj.AccountID = scope.AccountIDs[0]
			log.Printf("📌 Case created with account_id from user scope: %s", caseObj.AccountID)
		}
	}

	// Apply default workflow (checklist + playbooks)
	applyDefaultCaseWorkflowOpenSearch(&caseObj)

	if s.opensearch == nil {
		c.JSON(http.StatusCreated, gin.H{
			"success": true,
			"data":    caseObj,
			"message": "Case created (mock mode)",
		})
		return
	}

	// Index to OpenSearch
	caseJSON, _ := json.Marshal(caseObj)

	res, err := s.opensearch.Index(
		casesIndex,
		strings.NewReader(string(caseJSON)),
		s.opensearch.Index.WithDocumentID(caseObj.ID),
	)
	if err != nil {
		log.Printf("❌ Error creating case: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create case"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ OpenSearch error creating case: %s", res.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create case"})
		return
	}

	log.Printf("✅ Case %s created: %s", caseObj.ID, caseObj.Title)

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    caseObj,
		"message": "Case created successfully",
	})
}

// handleUpdateCaseOpenSearch updates a case in OpenSearch
func (s *APIServer) handleUpdateCaseOpenSearch(c *gin.Context) {
	id := c.Param("id")

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates["updated_at"] = time.Now().Format(time.RFC3339)

	// Handle status changes
	if newStatus, ok := updates["status"].(string); ok {
		now := time.Now()
		switch newStatus {
		case "resolved":
			updates["resolved_at"] = now.Format(time.RFC3339)
		case "closed":
			updates["closed_at"] = now.Format(time.RFC3339)
		}
	}

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Case updated (mock mode)",
			"id":      id,
		})
		return
	}

	updateDoc := map[string]interface{}{"doc": updates}
	updateJSON, _ := json.Marshal(updateDoc)

	res, err := s.opensearch.Update(
		casesIndex,
		id,
		strings.NewReader(string(updateJSON)),
	)
	if err != nil {
		log.Printf("❌ Error updating case %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update case"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Case not found"})
			return
		}
		log.Printf("❌ OpenSearch error updating case: %s", res.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update case"})
		return
	}

	log.Printf("✅ Case %s updated", id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Case updated successfully",
		"id":      id,
		"updates": updates,
	})
}

// handleDeleteCaseOpenSearch deletes a case from OpenSearch
func (s *APIServer) handleDeleteCaseOpenSearch(c *gin.Context) {
	id := c.Param("id")

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Case deleted (mock mode)",
			"id":      id,
		})
		return
	}

	res, err := s.opensearch.Delete(casesIndex, id)
	if err != nil {
		log.Printf("❌ Error deleting case %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete case"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Case not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete case"})
		return
	}

	log.Printf("✅ Case %s deleted", id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Case deleted successfully",
		"id":      id,
	})
}

// handleGetCaseStatisticsOpenSearch returns real-time case statistics
func (s *APIServer) handleGetCaseStatisticsOpenSearch(c *gin.Context) {
	// Default empty stats for when OpenSearch is unavailable
	emptyStats := gin.H{
		"success": true,
		"data": gin.H{
			"total":               0,
			"new":                 0,
			"in_progress":         0,
			"resolved":            0,
			"closed":              0,
			"by_severity":         map[string]int{},
			"by_category":         map[string]int{},
			"by_assigned":         map[string]int{},
			"sla_breaches":        0,
			"avg_time_to_resolve": 0.0,
			"trend_data":          []map[string]interface{}{},
		},
		"source": "opensearch",
	}

	if s.opensearch == nil {
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, emptyStats)
			return
		}
		s.handleGetCaseStatisticsMock(c)
		return
	}

	// Build query with access scope filter
	queryMap := map[string]interface{}{
		"size":             0,
		"track_total_hits": true,
		"aggs": map[string]interface{}{
			"by_status": map[string]interface{}{
				"terms": map[string]interface{}{"field": "status", "size": 10},
			},
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{"field": "severity", "size": 10},
			},
			"by_category": map[string]interface{}{
				"terms": map[string]interface{}{"field": "category", "size": 20},
			},
			"by_assigned": map[string]interface{}{
				"terms": map[string]interface{}{"field": "assigned_to", "size": 20},
			},
			"sla_breaches": map[string]interface{}{
				"filter": map[string]interface{}{"term": map[string]interface{}{"sla_breach": true}},
			},
			"avg_time_to_resolve": map[string]interface{}{
				"avg": map[string]interface{}{"field": "time_to_resolve"},
			},
			"last_7_days": map[string]interface{}{
				"date_histogram": map[string]interface{}{
					"field":             "created_at",
					"calendar_interval": "day",
					"min_doc_count":     0,
				},
			},
		},
	}

	// Apply access scope filter (role-based access control)
	accessFilters := buildCaseAccessFilter(getAccessScope(c))
	if len(accessFilters) > 0 {
		queryMap["query"] = map[string]interface{}{
			"bool": map[string]interface{}{
				"must": accessFilters,
			},
		}
	}

	queryJSON, _ := json.Marshal(queryMap)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(casesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ Error getting case statistics: %v", err)
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, emptyStats)
			return
		}
		s.handleGetCaseStatisticsMock(c)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ OpenSearch error for case statistics: %s", res.String())
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, emptyStats)
			return
		}
		s.handleGetCaseStatisticsMock(c)
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	stats := gin.H{
		"total":             0,
		"new":               0,
		"in_progress":       0,
		"resolved":          0,
		"closed":            0,
		"by_severity":       map[string]int{},
		"by_category":       map[string]int{},
		"by_assigned":       map[string]int{},
		"sla_breaches":      0,
		"avg_time_to_resolve": 0.0,
		"trend_data":        []map[string]interface{}{},
	}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			stats["total"] = int(total["value"].(float64))
		}
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		// By status
		if statusAgg, ok := aggs["by_status"].(map[string]interface{}); ok {
			if buckets, ok := statusAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					key := bucket["key"].(string)
					count := int(bucket["doc_count"].(float64))
					switch key {
					case "new":
						stats["new"] = count
					case "in_progress":
						stats["in_progress"] = count
					case "resolved":
						stats["resolved"] = count
					case "closed":
						stats["closed"] = count
					}
				}
			}
		}

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

		// By assigned
		if assignedAgg, ok := aggs["by_assigned"].(map[string]interface{}); ok {
			byAssigned := map[string]int{}
			if buckets, ok := assignedAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					byAssigned[bucket["key"].(string)] = int(bucket["doc_count"].(float64))
				}
			}
			stats["by_assigned"] = byAssigned
		}

		// SLA breaches
		if slaBreach, ok := aggs["sla_breaches"].(map[string]interface{}); ok {
			stats["sla_breaches"] = int(slaBreach["doc_count"].(float64))
		}

		// Avg time to resolve
		if avgTTR, ok := aggs["avg_time_to_resolve"].(map[string]interface{}); ok {
			if value, ok := avgTTR["value"].(float64); ok {
				stats["avg_time_to_resolve"] = value
			}
		}

		// Trend data
		if trendAgg, ok := aggs["last_7_days"].(map[string]interface{}); ok {
			trendData := []map[string]interface{}{}
			if buckets, ok := trendAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					trendData = append(trendData, map[string]interface{}{
						"date":  bucket["key_as_string"],
						"count": int(bucket["doc_count"].(float64)),
					})
				}
			}
			stats["trend_data"] = trendData
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
		"source":  "opensearch",
	})
}

// handleCreateCaseFromEvent creates a case from an event
func (s *APIServer) handleCreateCaseFromEvent(c *gin.Context) {
	var req struct {
		EventID     string `json:"event_id"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Priority    string `json:"priority"`
		AssignTo    string `json:"assign_to"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get event details if available
	eventSeverity := "medium"
	eventType := "security_event"
	eventSource := "manual"
	eventDescription := req.Description

	if s.opensearch != nil && req.EventID != "" {
		res, err := s.opensearch.Get("siem-events", req.EventID)
		if err == nil && !res.IsError() {
			var eventResult map[string]interface{}
			json.NewDecoder(res.Body).Decode(&eventResult)
			res.Body.Close()

			if source, ok := eventResult["_source"].(map[string]interface{}); ok {
				if sev, ok := source["severity"].(string); ok {
					eventSeverity = strings.ToLower(sev)
				}
				if typ, ok := source["type"].(string); ok {
					eventType = typ
				}
				if src, ok := source["source"].(string); ok {
					eventSource = src
				}
				if desc, ok := source["description"].(string); ok && eventDescription == "" {
					eventDescription = desc
				}
			}
		}
	}

	// Generate title if not provided
	caseTitle := req.Title
	if caseTitle == "" {
		caseTitle = fmt.Sprintf("Investigação: %s (%s)", eventType, eventSeverity)
	}

	// Create case
	caseObj := CaseOpenSearch{
		ID:            uuid.New().String(),
		Title:         caseTitle,
		Description:   eventDescription,
		Severity:      eventSeverity,
		Status:        "new",
		Priority:      req.Priority,
		Category:      "security_event",
		AssignedTo:    req.AssignTo,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Source:        eventSource,
		SourceID:      req.EventID,
		RelatedAlerts: []string{},
		RelatedEvents: []string{req.EventID},
		Tags:          []string{"from_event", eventType},
	}

	// Default priority if not set
	if caseObj.Priority == "" {
		switch eventSeverity {
		case "critical":
			caseObj.Priority = "critical"
		case "high":
			caseObj.Priority = "high"
		default:
			caseObj.Priority = "medium"
		}
	}

	// Get user
	if user, exists := c.Get("user"); exists {
		if userMap, ok := user.(map[string]interface{}); ok {
			if username, ok := userMap["username"].(string); ok {
				caseObj.CreatedBy = username
			}
		}
	}
	if caseObj.CreatedBy == "" {
		caseObj.CreatedBy = "admin"
	}

	// Atribuir account_id do escopo do usuário
	scope := getAccessScope(c)
	if len(scope.AccountIDs) > 0 {
		caseObj.AccountID = scope.AccountIDs[0]
		log.Printf("📌 Case from event created with account_id: %s", caseObj.AccountID)
	}

	// Calculate SLA
	slaHours := 72
	switch caseObj.Severity {
	case "critical":
		slaHours = 4
	case "high":
		slaHours = 24
	case "medium":
		slaHours = 72
	case "low":
		slaHours = 168
	}
	deadline := time.Now().Add(time.Duration(slaHours) * time.Hour)
	caseObj.SLADeadline = &deadline

	// Save to OpenSearch
	if s.opensearch != nil {
		applyDefaultCaseWorkflowOpenSearch(&caseObj)
		caseJSON, _ := json.Marshal(caseObj)
		res, err := s.opensearch.Index(
			casesIndex,
			strings.NewReader(string(caseJSON)),
			s.opensearch.Index.WithDocumentID(caseObj.ID),
		)
		if err != nil {
			log.Printf("❌ Error creating case from event: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create case"})
			return
		}
		res.Body.Close()
		log.Printf("✅ Case %s created from event %s", caseObj.ID, req.EventID)
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    caseObj,
		"message": fmt.Sprintf("Case created from event %s", req.EventID),
	})
}

// Helper function to parse case from OpenSearch source
func parseCaseFromSource(source map[string]interface{}) CaseOpenSearch {
	caseObj := CaseOpenSearch{
		ID:          getStrVal(source, "id"),
		Title:       getStrVal(source, "title"),
		Description: getStrVal(source, "description"),
		Severity:    getStrVal(source, "severity"),
		Status:      getStrVal(source, "status"),
		Priority:    getStrVal(source, "priority"),
		Category:    getStrVal(source, "category"),
		AssignedTo:  getStrVal(source, "assigned_to"),
		CreatedBy:   getStrVal(source, "created_by"),
		Notes:       getStrVal(source, "notes"),
		Resolution:  getStrVal(source, "resolution"),
		Source:      getStrVal(source, "source"),
		SourceID:    getStrVal(source, "source_id"),
		AccountID:   getStrVal(source, "account_id"), // Account ID para filtro de escopo
		SLABreach:   getBoolVal(source, "sla_breach"),
	}

	// Parse dates
	if createdStr := getStrVal(source, "created_at"); createdStr != "" {
		if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
			caseObj.CreatedAt = t
		}
	}
	if updatedStr := getStrVal(source, "updated_at"); updatedStr != "" {
		if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
			caseObj.UpdatedAt = t
		}
	}

	// Parse arrays
	if tags, ok := source["tags"].([]interface{}); ok {
		for _, t := range tags {
			if s, ok := t.(string); ok {
				caseObj.Tags = append(caseObj.Tags, s)
			}
		}
	}
	if alerts, ok := source["related_alerts"].([]interface{}); ok {
		for _, a := range alerts {
			if s, ok := a.(string); ok {
				caseObj.RelatedAlerts = append(caseObj.RelatedAlerts, s)
			}
		}
	}
	if playbooks, ok := source["related_playbooks"].([]interface{}); ok {
		for _, p := range playbooks {
			if s, ok := p.(string); ok {
				caseObj.RelatedPlaybooks = append(caseObj.RelatedPlaybooks, s)
			}
		}
	}

	// Parse integers
	if ttd, ok := source["time_to_detect"].(float64); ok {
		caseObj.TimeToDetect = int(ttd)
	}
	if ttr, ok := source["time_to_respond"].(float64); ok {
		caseObj.TimeToRespond = int(ttr)
	}
	if ttres, ok := source["time_to_resolve"].(float64); ok {
		caseObj.TimeToResolve = int(ttres)
	}
	if rt, ok := source["resolution_time_minutes"].(float64); ok {
		caseObj.ResolutionTimeMinutes = int(rt)
	}

	// Parse MITRE and assets
	if tactics, ok := source["mitre_tactics"].([]interface{}); ok {
		for _, t := range tactics {
			if s, ok := t.(string); ok {
				caseObj.MitreTactics = append(caseObj.MitreTactics, s)
			}
		}
	}
	if techniques, ok := source["mitre_techniques"].([]interface{}); ok {
		for _, t := range techniques {
			if s, ok := t.(string); ok {
				caseObj.MitreTechniques = append(caseObj.MitreTechniques, s)
			}
		}
	}
	if assets, ok := source["affected_assets"].([]interface{}); ok {
		for _, a := range assets {
			if s, ok := a.(string); ok {
				caseObj.AffectedAssets = append(caseObj.AffectedAssets, s)
			}
		}
	}

	// Parse evidence
	if evidenceArr, ok := source["evidence"].([]interface{}); ok {
		for _, item := range evidenceArr {
			if m, ok := item.(map[string]interface{}); ok {
				ev := CaseEvidence{
					ID:          getStringFromMap(m, "id"),
					Type:        getStringFromMap(m, "type"),
					Description: getStringFromMap(m, "description"),
					Source:      getStringFromMap(m, "source"),
					Data:        getStringFromMap(m, "data"),
					Hash:        getStringFromMap(m, "hash"),
					Preserved:   getBoolFromMap(m, "preserved"),
				}
				if ts := getStringFromMap(m, "timestamp"); ts != "" {
					if t, err := time.Parse(time.RFC3339, ts); err == nil {
						ev.Timestamp = t
					}
				}
				if sizeVal, ok := m["size"].(float64); ok {
					ev.Size = int64(sizeVal)
				}
				caseObj.Evidence = append(caseObj.Evidence, ev)
			}
		}
	}

	// Parse timeline
	if timelineArr, ok := source["timeline"].([]interface{}); ok {
		for _, item := range timelineArr {
			if m, ok := item.(map[string]interface{}); ok {
				entry := CaseTimelineEntry{
					Event:       getStringFromMap(m, "event"),
					Description: getStringFromMap(m, "description"),
					User:        getStringFromMap(m, "user"),
					Source:      getStringFromMap(m, "source"),
				}
				if ts := getStringFromMap(m, "timestamp"); ts != "" {
					if t, err := time.Parse(time.RFC3339, ts); err == nil {
						entry.Timestamp = t
					}
				}
				if details, ok := m["details"].(map[string]interface{}); ok {
					entry.Details = details
				}
				caseObj.Timeline = append(caseObj.Timeline, entry)
			}
		}
	}

	// Parse indicators
	if indicators, ok := source["indicators"].(map[string]interface{}); ok {
		caseObj.Indicators = indicators
	}

	// Parse checklist
	if checklistArr, ok := source["checklist"].([]interface{}); ok {
		for _, item := range checklistArr {
			if m, ok := item.(map[string]interface{}); ok {
				ci := CaseChecklistItem{
					ID:     getStringFromMap(m, "id"),
					Text:   getStringFromMap(m, "text"),
					Status: getStringFromMap(m, "status"),
				}
				if ts := getStringFromMap(m, "created_at"); ts != "" {
					if t, err := time.Parse(time.RFC3339, ts); err == nil {
						ci.CreatedAt = t
					}
				}
				if ts := getStringFromMap(m, "completed_at"); ts != "" {
					if t, err := time.Parse(time.RFC3339, ts); err == nil {
						ci.CompletedAt = &t
					}
				}
				ci.CompletedBy = getStringFromMap(m, "completed_by")
				caseObj.Checklist = append(caseObj.Checklist, ci)
			}
		}
	}

	return caseObj
}

func applyDefaultCaseWorkflowOpenSearch(caseObj *CaseOpenSearch) {
	if caseObj == nil {
		return
	}

	applyCaseSLAPolicyOpenSearch(caseObj)

	// Ajustar prioridade baseada na severidade se não definida
	if caseObj.Priority == "" {
		switch strings.ToLower(caseObj.Severity) {
		case "critical":
			caseObj.Priority = "urgent"
		case "high":
			caseObj.Priority = "high"
		case "medium":
			caseObj.Priority = "medium"
		default:
			caseObj.Priority = "low"
		}
	}

	// Checklist por tipo de incidente
	if len(caseObj.Checklist) == 0 {
		caseObj.Checklist = buildChecklistByCategory(caseObj.Category, getCasePolicy())
	}

	// Playbooks sugeridos
	if len(caseObj.RelatedPlaybooks) == 0 {
		switch strings.ToLower(caseObj.Category) {
		case "malware":
			caseObj.RelatedPlaybooks = []string{"playbook-malware-removal"}
		case "phishing":
			caseObj.RelatedPlaybooks = []string{"playbook-phishing-response"}
		case "data_breach", "data_loss":
			caseObj.RelatedPlaybooks = []string{"playbook-data-breach-response"}
		case "unauthorized_access":
			caseObj.RelatedPlaybooks = []string{"playbook-privilege-escalation-response"}
		default:
			if strings.ToLower(caseObj.Severity) == "critical" || strings.ToLower(caseObj.Severity) == "high" {
				caseObj.RelatedPlaybooks = []string{"playbook-incident-containment"}
			}
		}
	}
}

func applyCaseSLAPolicyOpenSearch(caseObj *CaseOpenSearch) {
	if caseObj == nil {
		return
	}

	policy := getCasePolicy()
	sla := getSLAPolicy(policy, caseObj.Category, caseObj.Severity)
	if caseObj.SLADeadline == nil {
		deadline := time.Now().Add(time.Duration(sla.DeadlineHours) * time.Hour)
		caseObj.SLADeadline = &deadline
	}
	if caseObj.TimeToRespond == 0 {
		caseObj.TimeToRespond = sla.ResponseSeconds
	}
	if caseObj.TimeToResolve == 0 {
		caseObj.TimeToResolve = sla.ResolveSeconds
	}
	if caseObj.DueDate == nil && caseObj.SLADeadline != nil {
		caseObj.DueDate = caseObj.SLADeadline
	}
}

func (s *APIServer) getCasePolicyFromOpenSearch() (*CasePolicy, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	res, err := s.opensearch.Get(casePoliciesIndex, "default")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("policy not found")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	if source, ok := result["_source"].(map[string]interface{}); ok {
		raw, _ := json.Marshal(source)
		var policy CasePolicy
		if err := json.Unmarshal(raw, &policy); err != nil {
			return nil, err
		}
		return &policy, nil
	}

	return nil, fmt.Errorf("invalid policy format")
}

func (s *APIServer) saveCasePolicyToOpenSearch(policy *CasePolicy) error {
	if s.opensearch == nil {
		return fmt.Errorf("opensearch not available")
	}
	if policy == nil {
		return fmt.Errorf("invalid policy")
	}

	policyJSON, _ := json.Marshal(policy)
	res, err := s.opensearch.Index(
		casePoliciesIndex,
		strings.NewReader(string(policyJSON)),
		s.opensearch.Index.WithDocumentID("default"),
		s.opensearch.Index.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("failed to save policy: %s", res.String())
	}
	return nil
}

func (s *APIServer) getCaseFromOpenSearch(id string) (*CaseOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	res, err := s.opensearch.Get(casesIndex, id)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("case not found")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	if source, ok := result["_source"].(map[string]interface{}); ok {
		caseObj := parseCaseFromSource(source)
		return &caseObj, nil
	}

	return nil, fmt.Errorf("invalid case format")
}

func getStrVal(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBoolVal(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

