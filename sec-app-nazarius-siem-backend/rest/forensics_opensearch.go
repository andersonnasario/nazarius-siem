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

const forensicsIndex = "siem-forensics"
const forensicsEvidenceIndex = "siem-forensics-evidence"
const forensicsTimelineIndex = "siem-forensics-timeline"

// ForensicInvestigation represents a forensic investigation stored in OpenSearch
type ForensicInvestigation struct {
	ID             string    `json:"id"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Status         string    `json:"status"` // active, completed, pending, archived
	Severity       string    `json:"severity"`
	Priority       string    `json:"priority"`
	IncidentID     string    `json:"incident_id,omitempty"`
	CaseID         string    `json:"case_id,omitempty"`
	EvidenceCount  int       `json:"evidence_count"`
	ArtifactsCount int       `json:"artifacts_count"`
	Analyst        string    `json:"analyst"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ClosedAt       *time.Time `json:"closed_at,omitempty"`
	Tags           []string  `json:"tags"`
	Findings       []string  `json:"findings"`
	MITRETactics   []string  `json:"mitre_tactics"`
	MITRETechniques []string `json:"mitre_techniques"`
	AffectedAssets []string  `json:"affected_assets"`
	Source         string    `json:"source"` // manual, auto, alert, case
	Notes          string    `json:"notes"`
}

// ForensicEvidence represents digital evidence
type ForensicEvidence struct {
	ID              string                 `json:"id"`
	InvestigationID string                 `json:"investigation_id"`
	Type            string                 `json:"type"` // file, memory, network, registry, log, disk, process
	Name            string                 `json:"name"`
	Source          string                 `json:"source"`
	Hash            string                 `json:"hash"` // SHA-256
	Size            int64                  `json:"size"` // bytes
	CollectedAt     time.Time              `json:"collected_at"`
	CollectedBy     string                 `json:"collected_by"`
	ChainOfCustody  []ChainOfCustodyEntry  `json:"chain_of_custody"`
	Metadata        map[string]interface{} `json:"metadata"`
	Tags            []string               `json:"tags"`
	Status          string                 `json:"status"` // collected, analyzing, analyzed, archived
	Analysis        string                 `json:"analysis"`
	IsMalicious     bool                   `json:"is_malicious"`
}

// ChainOfCustodyEntry tracks evidence handling
type ChainOfCustodyEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	PerformedBy string    `json:"performed_by"`
	Notes       string    `json:"notes"`
}

// ForensicTimelineEntry represents an event in the timeline
type ForensicTimelineEntry struct {
	ID              string    `json:"id"`
	InvestigationID string    `json:"investigation_id"`
	Timestamp       time.Time `json:"timestamp"`
	Event           string    `json:"event"`
	EventType       string    `json:"event_type"` // system, network, user, file, process, registry
	Actor           string    `json:"actor"`
	Target          string    `json:"target"`
	Details         string    `json:"details"`
	Source          string    `json:"source"`
	Severity        string    `json:"severity"`
	EvidenceID      string    `json:"evidence_id,omitempty"`
}

// ForensicStats holds statistics
type ForensicStats struct {
	TotalInvestigations  int            `json:"total_investigations"`
	ActiveInvestigations int            `json:"active_investigations"`
	CompletedInvestigations int         `json:"completed_investigations"`
	PendingInvestigations int           `json:"pending_investigations"`
	TotalEvidence        int            `json:"total_evidence"`
	TotalArtifacts       int            `json:"total_artifacts"`
	BySeverity           map[string]int `json:"by_severity"`
	ByStatus             map[string]int `json:"by_status"`
	ByType               map[string]int `json:"by_type"`
	RecentActivity       int            `json:"recent_activity"` // last 24h
}

// EnsureForensicsIndex creates the forensics indices if they don't exist
func (s *APIServer) EnsureForensicsIndex() {
	if s.opensearch == nil {
		log.Println("⚠️ OpenSearch not available, forensics will use mock data")
		return
	}

	// Main forensics index
	investigationsMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"title": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"description": { "type": "text" },
				"status": { "type": "keyword" },
				"severity": { "type": "keyword" },
				"priority": { "type": "keyword" },
				"incident_id": { "type": "keyword" },
				"case_id": { "type": "keyword" },
				"evidence_count": { "type": "integer" },
				"artifacts_count": { "type": "integer" },
				"analyst": { "type": "keyword" },
				"created_at": { "type": "date" },
				"updated_at": { "type": "date" },
				"closed_at": { "type": "date" },
				"tags": { "type": "keyword" },
				"findings": { "type": "text" },
				"mitre_tactics": { "type": "keyword" },
				"mitre_techniques": { "type": "keyword" },
				"affected_assets": { "type": "keyword" },
				"source": { "type": "keyword" },
				"notes": { "type": "text" }
			}
		}
	}`

	res, err := s.opensearch.Indices.Exists([]string{forensicsIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			forensicsIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(investigationsMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", forensicsIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", forensicsIndex)
		}
	}

	// Evidence index
	evidenceMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"investigation_id": { "type": "keyword" },
				"type": { "type": "keyword" },
				"name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"source": { "type": "text" },
				"hash": { "type": "keyword" },
				"size": { "type": "long" },
				"collected_at": { "type": "date" },
				"collected_by": { "type": "keyword" },
				"chain_of_custody": { "type": "nested" },
				"metadata": { "type": "object" },
				"tags": { "type": "keyword" },
				"status": { "type": "keyword" },
				"analysis": { "type": "text" },
				"is_malicious": { "type": "boolean" }
			}
		}
	}`

	res, err = s.opensearch.Indices.Exists([]string{forensicsEvidenceIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			forensicsEvidenceIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(evidenceMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", forensicsEvidenceIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", forensicsEvidenceIndex)
		}
	}

	// Timeline index
	timelineMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"investigation_id": { "type": "keyword" },
				"timestamp": { "type": "date" },
				"event": { "type": "text" },
				"event_type": { "type": "keyword" },
				"actor": { "type": "keyword" },
				"target": { "type": "keyword" },
				"details": { "type": "text" },
				"source": { "type": "keyword" },
				"severity": { "type": "keyword" },
				"evidence_id": { "type": "keyword" }
			}
		}
	}`

	res, err = s.opensearch.Indices.Exists([]string{forensicsTimelineIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			forensicsTimelineIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(timelineMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", forensicsTimelineIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", forensicsTimelineIndex)
		}
	}

	log.Println("✅ Forensics indices initialized")
}

// handleListForensicInvestigations lists all forensic investigations
func (s *APIServer) handleListForensicInvestigations(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")
	search := c.Query("search")

	if s.opensearch == nil {
		// Return mock data if OpenSearch is not available
		investigations := generateMockForensicInvestigations()
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    investigations,
			"total":   len(investigations),
			"source":  "mock",
		})
		return
	}

	// Build query
	var mustClauses []map[string]interface{}

	if status != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{"status": status},
		})
	}

	if severity != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{"severity": severity},
		})
	}

	if search != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  search,
				"fields": []string{"title", "description", "notes", "analyst"},
			},
		})
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		},
		"sort": []map[string]interface{}{
			{"created_at": map[string]interface{}{"order": "desc"}},
		},
		"size": 100,
	}

	if len(mustClauses) == 0 {
		query["query"] = map[string]interface{}{
			"match_all": map[string]interface{}{},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(forensicsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ Error searching forensics: %v", err)
		// Fallback to mock
		investigations := generateMockForensicInvestigations()
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    investigations,
			"total":   len(investigations),
			"source":  "mock",
		})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		log.Printf("❌ Error decoding response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response"})
		return
	}

	investigations := []ForensicInvestigation{}
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitArray {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"].(map[string]interface{}); ok {
						inv := parseForensicInvestigation(source)
						investigations = append(investigations, inv)
					}
				}
			}
		}
	}

	total := 0
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalVal, ok := hits["total"].(map[string]interface{}); ok {
			if value, ok := totalVal["value"].(float64); ok {
				total = int(value)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    investigations,
		"total":   total,
		"source":  "opensearch",
	})
}

// handleCreateForensicInvestigation creates a new forensic investigation
func (s *APIServer) handleCreateForensicInvestigation(c *gin.Context) {
	var inv ForensicInvestigation
	if err := c.ShouldBindJSON(&inv); err != nil {
		log.Printf("[ERROR] handleCreateForensicInvestigation bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	// Set defaults
	inv.ID = uuid.New().String()
	inv.CreatedAt = time.Now()
	inv.UpdatedAt = time.Now()
	if inv.Status == "" {
		inv.Status = "active"
	}
	if inv.Priority == "" {
		inv.Priority = "medium"
	}
	if inv.Severity == "" {
		inv.Severity = "medium"
	}
	if inv.Source == "" {
		inv.Source = "manual"
	}

	// Get user from context
	if user, exists := c.Get("user"); exists {
		if userMap, ok := user.(map[string]interface{}); ok {
			if username, ok := userMap["username"].(string); ok {
				if inv.Analyst == "" {
					inv.Analyst = username
				}
			}
		}
	}
	if inv.Analyst == "" {
		inv.Analyst = getUsernameFromContext(c)
	}

	if s.opensearch == nil {
		c.JSON(http.StatusCreated, gin.H{
			"success": true,
			"data":    inv,
			"message": "Investigation created (mock mode)",
		})
		return
	}

	// Index to OpenSearch
	invJSON, _ := json.Marshal(inv)

	res, err := s.opensearch.Index(
		forensicsIndex,
		strings.NewReader(string(invJSON)),
		s.opensearch.Index.WithDocumentID(inv.ID),
	)
	if err != nil {
		log.Printf("❌ Error creating investigation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create investigation"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ OpenSearch error: %s", res.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create investigation"})
		return
	}

	// Add initial timeline entry
	timelineEntry := ForensicTimelineEntry{
		ID:              uuid.New().String(),
		InvestigationID: inv.ID,
		Timestamp:       time.Now(),
		Event:           "Investigation created",
		EventType:       "system",
		Actor:           inv.Analyst,
		Details:         fmt.Sprintf("Investigation '%s' created with severity %s", inv.Title, inv.Severity),
		Source:          "system",
		Severity:        "info",
	}

	s.addForensicTimelineEntry(timelineEntry)

	log.Printf("✅ Forensic investigation %s created: %s", inv.ID, inv.Title)

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    inv,
	})
}

// handleGetForensicInvestigation gets a specific investigation
func (s *APIServer) handleGetForensicInvestigation(c *gin.Context) {
	id := c.Param("id")

	if s.opensearch == nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Investigation not found"})
		return
	}

	res, err := s.opensearch.Get(forensicsIndex, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Investigation not found"})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response"})
		return
	}

	if found, ok := result["found"].(bool); !ok || !found {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Investigation not found"})
		return
	}

	if source, ok := result["_source"].(map[string]interface{}); ok {
		inv := parseForensicInvestigation(source)
		c.JSON(http.StatusOK, gin.H{"success": true, "data": inv})
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Investigation not found"})
}

// handleUpdateForensicInvestigation updates an investigation
func (s *APIServer) handleUpdateForensicInvestigation(c *gin.Context) {
	id := c.Param("id")

	var update ForensicInvestigation
	if err := c.ShouldBindJSON(&update); err != nil {
		log.Printf("[ERROR] handleUpdateForensicInvestigation bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	update.ID = id
	update.UpdatedAt = time.Now()

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    update,
			"message": "Investigation updated (mock mode)",
		})
		return
	}

	updateJSON, _ := json.Marshal(update)

	res, err := s.opensearch.Index(
		forensicsIndex,
		strings.NewReader(string(updateJSON)),
		s.opensearch.Index.WithDocumentID(id),
	)
	if err != nil {
		log.Printf("❌ Error updating investigation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update investigation"})
		return
	}
	defer res.Body.Close()

	// Add timeline entry for update
	timelineEntry := ForensicTimelineEntry{
		ID:              uuid.New().String(),
		InvestigationID: id,
		Timestamp:       time.Now(),
		Event:           "Investigation updated",
		EventType:       "system",
		Actor:           update.Analyst,
		Details:         fmt.Sprintf("Status: %s, Severity: %s", update.Status, update.Severity),
		Source:          "system",
		Severity:        "info",
	}

	s.addForensicTimelineEntry(timelineEntry)

	c.JSON(http.StatusOK, gin.H{"success": true, "data": update})
}

// handleDeleteForensicInvestigation deletes an investigation
func (s *APIServer) handleDeleteForensicInvestigation(c *gin.Context) {
	id := c.Param("id")

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Investigation deleted (mock mode)"})
		return
	}

	res, err := s.opensearch.Delete(forensicsIndex, id)
	if err != nil {
		log.Printf("❌ Error deleting investigation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete investigation"})
		return
	}
	defer res.Body.Close()

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Investigation deleted"})
}

// handleListForensicEvidence lists evidence for an investigation
func (s *APIServer) handleListForensicEvidence(c *gin.Context) {
	investigationID := c.Query("investigation_id")
	evidenceType := c.Query("type")

	if s.opensearch == nil {
		evidence := generateMockForensicEvidence()
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    evidence,
			"total":   len(evidence),
			"source":  "mock",
		})
		return
	}

	var mustClauses []map[string]interface{}

	if investigationID != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{"investigation_id": investigationID},
		})
	}

	if evidenceType != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{"type": evidenceType},
		})
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		},
		"sort": []map[string]interface{}{
			{"collected_at": map[string]interface{}{"order": "desc"}},
		},
		"size": 100,
	}

	if len(mustClauses) == 0 {
		query["query"] = map[string]interface{}{
			"match_all": map[string]interface{}{},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(forensicsEvidenceIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		evidence := generateMockForensicEvidence()
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    evidence,
			"total":   len(evidence),
			"source":  "mock",
		})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response"})
		return
	}

	evidence := []ForensicEvidence{}
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitArray {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"].(map[string]interface{}); ok {
						ev := parseForensicEvidence(source)
						evidence = append(evidence, ev)
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    evidence,
		"total":   len(evidence),
		"source":  "opensearch",
	})
}

// handleCreateForensicEvidence creates new evidence
func (s *APIServer) handleCreateForensicEvidence(c *gin.Context) {
	var ev ForensicEvidence
	if err := c.ShouldBindJSON(&ev); err != nil {
		log.Printf("[ERROR] handleCreateForensicEvidence bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	ev.ID = uuid.New().String()
	ev.CollectedAt = time.Now()
	if ev.Status == "" {
		ev.Status = "collected"
	}

	// Get user
	if user, exists := c.Get("user"); exists {
		if userMap, ok := user.(map[string]interface{}); ok {
			if username, ok := userMap["username"].(string); ok {
				if ev.CollectedBy == "" {
					ev.CollectedBy = username
				}
			}
		}
	}
	if ev.CollectedBy == "" {
		ev.CollectedBy = getUsernameFromContext(c)
	}

	// Initialize chain of custody
	ev.ChainOfCustody = []ChainOfCustodyEntry{
		{
			Timestamp:   time.Now(),
			Action:      "collected",
			PerformedBy: ev.CollectedBy,
			Notes:       fmt.Sprintf("Evidence collected from %s", ev.Source),
		},
	}

	if s.opensearch == nil {
		c.JSON(http.StatusCreated, gin.H{
			"success": true,
			"data":    ev,
			"message": "Evidence created (mock mode)",
		})
		return
	}

	evJSON, _ := json.Marshal(ev)

	res, err := s.opensearch.Index(
		forensicsEvidenceIndex,
		strings.NewReader(string(evJSON)),
		s.opensearch.Index.WithDocumentID(ev.ID),
	)
	if err != nil {
		log.Printf("❌ Error creating evidence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create evidence"})
		return
	}
	defer res.Body.Close()

	// Update investigation evidence count
	s.updateInvestigationEvidenceCount(ev.InvestigationID, 1)

	// Add timeline entry
	timelineEntry := ForensicTimelineEntry{
		ID:              uuid.New().String(),
		InvestigationID: ev.InvestigationID,
		Timestamp:       time.Now(),
		Event:           fmt.Sprintf("Evidence collected: %s", ev.Name),
		EventType:       "evidence",
		Actor:           ev.CollectedBy,
		Details:         fmt.Sprintf("Type: %s, Source: %s, Hash: %s", ev.Type, ev.Source, ev.Hash),
		Source:          "evidence_collection",
		Severity:        "info",
		EvidenceID:      ev.ID,
	}

	s.addForensicTimelineEntry(timelineEntry)

	log.Printf("✅ Evidence %s created for investigation %s", ev.ID, ev.InvestigationID)

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": ev})
}

// handleGetForensicTimeline gets the timeline for an investigation
func (s *APIServer) handleGetForensicTimeline(c *gin.Context) {
	investigationID := c.Param("id")

	if s.opensearch == nil {
		timeline := generateMockForensicTimeline(investigationID)
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    timeline,
			"source":  "mock",
		})
		return
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"investigation_id": investigationID,
			},
		},
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
		"size": 100,
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(forensicsTimelineIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		timeline := generateMockForensicTimeline(investigationID)
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    timeline,
			"source":  "mock",
		})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response"})
		return
	}

	timeline := []ForensicTimelineEntry{}
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitArray {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"].(map[string]interface{}); ok {
						entry := parseForensicTimelineEntry(source)
						timeline = append(timeline, entry)
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    timeline,
		"source":  "opensearch",
	})
}

// handleAddForensicTimelineEntry adds a timeline entry
func (s *APIServer) handleAddForensicTimelineEntry(c *gin.Context) {
	investigationID := c.Param("id")

	var entry ForensicTimelineEntry
	if err := c.ShouldBindJSON(&entry); err != nil {
		log.Printf("[ERROR] handleAddForensicTimelineEntry bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	entry.ID = uuid.New().String()
	entry.InvestigationID = investigationID
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Get user
	if user, exists := c.Get("user"); exists {
		if userMap, ok := user.(map[string]interface{}); ok {
			if username, ok := userMap["username"].(string); ok {
				if entry.Actor == "" {
					entry.Actor = username
				}
			}
		}
	}

	s.addForensicTimelineEntry(entry)

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": entry})
}

// handleGetForensicStats gets forensic statistics
func (s *APIServer) handleGetForensicStats(c *gin.Context) {
	if s.opensearch == nil {
		stats := ForensicStats{
			TotalInvestigations:  12,
			ActiveInvestigations: 3,
			CompletedInvestigations: 8,
			PendingInvestigations: 1,
			TotalEvidence:        847,
			TotalArtifacts:       1523,
			BySeverity: map[string]int{
				"critical": 2,
				"high":     4,
				"medium":   4,
				"low":      2,
			},
			ByStatus: map[string]int{
				"active":    3,
				"completed": 8,
				"pending":   1,
			},
			ByType: map[string]int{
				"memory":   150,
				"file":     320,
				"network":  180,
				"registry": 97,
				"log":      100,
			},
			RecentActivity: 15,
		}
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    stats,
			"source":  "mock",
		})
		return
	}

	// Query for statistics
	statsQuery := map[string]interface{}{
		"size": 0,
		"aggs": map[string]interface{}{
			"total": map[string]interface{}{
				"value_count": map[string]interface{}{"field": "id"},
			},
			"by_status": map[string]interface{}{
				"terms": map[string]interface{}{"field": "status"},
			},
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{"field": "severity"},
			},
		},
	}

	queryJSON, _ := json.Marshal(statsQuery)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(forensicsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ Error getting forensic stats: %v", err)
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    ForensicStats{},
			"source":  "error",
		})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response"})
		return
	}

	stats := ForensicStats{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
		ByType:     make(map[string]int),
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		// Parse total
		if total, ok := aggs["total"].(map[string]interface{}); ok {
			if value, ok := total["value"].(float64); ok {
				stats.TotalInvestigations = int(value)
			}
		}

		// Parse by status
		if byStatus, ok := aggs["by_status"].(map[string]interface{}); ok {
			if buckets, ok := byStatus["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if b, ok := bucket.(map[string]interface{}); ok {
						key := b["key"].(string)
						count := int(b["doc_count"].(float64))
						stats.ByStatus[key] = count
						switch key {
						case "active":
							stats.ActiveInvestigations = count
						case "completed":
							stats.CompletedInvestigations = count
						case "pending":
							stats.PendingInvestigations = count
						}
					}
				}
			}
		}

		// Parse by severity
		if bySeverity, ok := aggs["by_severity"].(map[string]interface{}); ok {
			if buckets, ok := bySeverity["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if b, ok := bucket.(map[string]interface{}); ok {
						key := b["key"].(string)
						count := int(b["doc_count"].(float64))
						stats.BySeverity[key] = count
					}
				}
			}
		}
	}

	// Query evidence count
	evidenceCountQuery := map[string]interface{}{
		"size": 0,
		"aggs": map[string]interface{}{
			"total": map[string]interface{}{
				"value_count": map[string]interface{}{"field": "id"},
			},
			"by_type": map[string]interface{}{
				"terms": map[string]interface{}{"field": "type"},
			},
		},
	}

	queryJSON, _ = json.Marshal(evidenceCountQuery)

	res, err = s.opensearch.Search(
		s.opensearch.Search.WithIndex(forensicsEvidenceIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err == nil {
		defer res.Body.Close()
		var evidenceResult map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&evidenceResult); err == nil {
			if aggs, ok := evidenceResult["aggregations"].(map[string]interface{}); ok {
				if total, ok := aggs["total"].(map[string]interface{}); ok {
					if value, ok := total["value"].(float64); ok {
						stats.TotalEvidence = int(value)
					}
				}
				if byType, ok := aggs["by_type"].(map[string]interface{}); ok {
					if buckets, ok := byType["buckets"].([]interface{}); ok {
						for _, bucket := range buckets {
							if b, ok := bucket.(map[string]interface{}); ok {
								key := b["key"].(string)
								count := int(b["doc_count"].(float64))
								stats.ByType[key] = count
							}
						}
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
		"source":  "opensearch",
	})
}

// Helper function to add timeline entry
func (s *APIServer) addForensicTimelineEntry(entry ForensicTimelineEntry) {
	if s.opensearch == nil {
		return
	}

	entryJSON, _ := json.Marshal(entry)

	res, err := s.opensearch.Index(
		forensicsTimelineIndex,
		strings.NewReader(string(entryJSON)),
		s.opensearch.Index.WithDocumentID(entry.ID),
	)
	if err != nil {
		log.Printf("⚠️ Error adding timeline entry: %v", err)
		return
	}
	defer res.Body.Close()
}

// Helper function to update investigation evidence count
func (s *APIServer) updateInvestigationEvidenceCount(investigationID string, delta int) {
	if s.opensearch == nil || investigationID == "" {
		return
	}

	// Get current investigation
	res, err := s.opensearch.Get(forensicsIndex, investigationID)
	if err != nil {
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return
	}

	if source, ok := result["_source"].(map[string]interface{}); ok {
		currentCount := 0
		if count, ok := source["evidence_count"].(float64); ok {
			currentCount = int(count)
		}
		source["evidence_count"] = currentCount + delta
		source["updated_at"] = time.Now()

		updateJSON, _ := json.Marshal(source)
		s.opensearch.Index(
			forensicsIndex,
			strings.NewReader(string(updateJSON)),
			s.opensearch.Index.WithDocumentID(investigationID),
		)
	}
}

// Parse helper functions
func parseForensicInvestigation(source map[string]interface{}) ForensicInvestigation {
	inv := ForensicInvestigation{}

	if v, ok := source["id"].(string); ok {
		inv.ID = v
	}
	if v, ok := source["title"].(string); ok {
		inv.Title = v
	}
	if v, ok := source["description"].(string); ok {
		inv.Description = v
	}
	if v, ok := source["status"].(string); ok {
		inv.Status = v
	}
	if v, ok := source["severity"].(string); ok {
		inv.Severity = v
	}
	if v, ok := source["priority"].(string); ok {
		inv.Priority = v
	}
	if v, ok := source["incident_id"].(string); ok {
		inv.IncidentID = v
	}
	if v, ok := source["case_id"].(string); ok {
		inv.CaseID = v
	}
	if v, ok := source["evidence_count"].(float64); ok {
		inv.EvidenceCount = int(v)
	}
	if v, ok := source["artifacts_count"].(float64); ok {
		inv.ArtifactsCount = int(v)
	}
	if v, ok := source["analyst"].(string); ok {
		inv.Analyst = v
	}
	if v, ok := source["created_at"].(string); ok {
		inv.CreatedAt, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["updated_at"].(string); ok {
		inv.UpdatedAt, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["tags"].([]interface{}); ok {
		for _, tag := range v {
			if t, ok := tag.(string); ok {
				inv.Tags = append(inv.Tags, t)
			}
		}
	}
	if v, ok := source["findings"].([]interface{}); ok {
		for _, f := range v {
			if finding, ok := f.(string); ok {
				inv.Findings = append(inv.Findings, finding)
			}
		}
	}
	if v, ok := source["notes"].(string); ok {
		inv.Notes = v
	}
	if v, ok := source["source"].(string); ok {
		inv.Source = v
	}

	return inv
}

func parseForensicEvidence(source map[string]interface{}) ForensicEvidence {
	ev := ForensicEvidence{}

	if v, ok := source["id"].(string); ok {
		ev.ID = v
	}
	if v, ok := source["investigation_id"].(string); ok {
		ev.InvestigationID = v
	}
	if v, ok := source["type"].(string); ok {
		ev.Type = v
	}
	if v, ok := source["name"].(string); ok {
		ev.Name = v
	}
	if v, ok := source["source"].(string); ok {
		ev.Source = v
	}
	if v, ok := source["hash"].(string); ok {
		ev.Hash = v
	}
	if v, ok := source["size"].(float64); ok {
		ev.Size = int64(v)
	}
	if v, ok := source["collected_at"].(string); ok {
		ev.CollectedAt, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["collected_by"].(string); ok {
		ev.CollectedBy = v
	}
	if v, ok := source["status"].(string); ok {
		ev.Status = v
	}
	if v, ok := source["analysis"].(string); ok {
		ev.Analysis = v
	}
	if v, ok := source["is_malicious"].(bool); ok {
		ev.IsMalicious = v
	}
	if v, ok := source["metadata"].(map[string]interface{}); ok {
		ev.Metadata = v
	}

	return ev
}

func parseForensicTimelineEntry(source map[string]interface{}) ForensicTimelineEntry {
	entry := ForensicTimelineEntry{}

	if v, ok := source["id"].(string); ok {
		entry.ID = v
	}
	if v, ok := source["investigation_id"].(string); ok {
		entry.InvestigationID = v
	}
	if v, ok := source["timestamp"].(string); ok {
		entry.Timestamp, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["event"].(string); ok {
		entry.Event = v
	}
	if v, ok := source["event_type"].(string); ok {
		entry.EventType = v
	}
	if v, ok := source["actor"].(string); ok {
		entry.Actor = v
	}
	if v, ok := source["target"].(string); ok {
		entry.Target = v
	}
	if v, ok := source["details"].(string); ok {
		entry.Details = v
	}
	if v, ok := source["source"].(string); ok {
		entry.Source = v
	}
	if v, ok := source["severity"].(string); ok {
		entry.Severity = v
	}
	if v, ok := source["evidence_id"].(string); ok {
		entry.EvidenceID = v
	}

	return entry
}

// Mock data generators
func generateMockForensicInvestigations() []ForensicInvestigation {
	return []ForensicInvestigation{
		{
			ID:             "inv-001",
			Title:          "Ransomware Attack Investigation",
			Description:    "Investigation of ransomware incident affecting production servers",
			Status:         "active",
			Severity:       "critical",
			Priority:       "critical",
			IncidentID:     "INC-2025-001",
			EvidenceCount:  45,
			ArtifactsCount: 123,
			Analyst:        "security.analyst@company.com",
			CreatedAt:      time.Now().Add(-24 * time.Hour),
			UpdatedAt:      time.Now().Add(-2 * time.Hour),
			Tags:           []string{"ransomware", "critical", "production"},
			Findings:       []string{"Malware entry via phishing email", "Lateral movement detected"},
			Source:         "alert",
		},
		{
			ID:             "inv-002",
			Title:          "Data Exfiltration Analysis",
			Description:    "Analysis of potential data exfiltration to external IP",
			Status:         "active",
			Severity:       "high",
			Priority:       "high",
			IncidentID:     "INC-2025-002",
			EvidenceCount:  32,
			ArtifactsCount: 87,
			Analyst:        "incident.responder@company.com",
			CreatedAt:      time.Now().Add(-48 * time.Hour),
			UpdatedAt:      time.Now().Add(-1 * time.Hour),
			Tags:           []string{"data-exfiltration", "network"},
			Source:         "manual",
		},
		{
			ID:             "inv-003",
			Title:          "Insider Threat Investigation",
			Description:    "Investigation of unusual user activity patterns",
			Status:         "pending",
			Severity:       "medium",
			Priority:       "medium",
			EvidenceCount:  28,
			ArtifactsCount: 65,
			Analyst:        "soc.lead@company.com",
			CreatedAt:      time.Now().Add(-72 * time.Hour),
			UpdatedAt:      time.Now().Add(-4 * time.Hour),
			Tags:           []string{"insider-threat", "ueba"},
			Source:         "case",
		},
	}
}

func generateMockForensicEvidence() []ForensicEvidence {
	return []ForensicEvidence{
		{
			ID:              "ev-001",
			InvestigationID: "inv-001",
			Type:            "file",
			Name:            "malware.exe",
			Source:          "C:\\Windows\\Temp\\malware.exe",
			Hash:            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Size:            1024000,
			CollectedAt:     time.Now().Add(-20 * time.Hour),
			CollectedBy:     "security.analyst@company.com",
			Status:          "analyzed",
			IsMalicious:     true,
			Metadata: map[string]interface{}{
				"pe_type":      "executable",
				"signed":       false,
				"entropy":      7.8,
				"import_hash":  "abc123",
				"compile_time": "2025-01-10T14:30:00Z",
			},
		},
		{
			ID:              "ev-002",
			InvestigationID: "inv-001",
			Type:            "memory",
			Name:            "memory_dump.dmp",
			Source:          "Process: explorer.exe (PID: 1234)",
			Hash:            "f5ca38f748a1d6eaf726b8a42fb575c3c71f1864a8143301782de13da2d9202b",
			Size:            16777216000,
			CollectedAt:     time.Now().Add(-18 * time.Hour),
			CollectedBy:     "security.analyst@company.com",
			Status:          "analyzing",
			Metadata: map[string]interface{}{
				"process_name": "explorer.exe",
				"pid":          1234,
				"dump_type":    "full",
			},
		},
		{
			ID:              "ev-003",
			InvestigationID: "inv-002",
			Type:            "network",
			Name:            "network_capture.pcap",
			Source:          "Network interface eth0",
			Hash:            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			Size:            524288000,
			CollectedAt:     time.Now().Add(-12 * time.Hour),
			CollectedBy:     "incident.responder@company.com",
			Status:          "collected",
			Metadata: map[string]interface{}{
				"duration_sec":  3600,
				"packets_count": 125000,
				"filter":        "host 192.168.1.100",
			},
		},
		{
			ID:              "ev-004",
			InvestigationID: "inv-001",
			Type:            "log",
			Name:            "security_events.evtx",
			Source:          "Windows Security Event Log",
			Hash:            "def456def456def456def456def456def456def456def456def456def456def4",
			Size:            104857600,
			CollectedAt:     time.Now().Add(-16 * time.Hour),
			CollectedBy:     "security.analyst@company.com",
			Status:          "analyzed",
			Metadata: map[string]interface{}{
				"event_count": 5432,
				"time_range":  "2025-01-05 to 2025-01-07",
				"log_type":    "Security",
			},
		},
	}
}

func generateMockForensicTimeline(investigationID string) []ForensicTimelineEntry {
	return []ForensicTimelineEntry{
		{
			ID:              "tl-001",
			InvestigationID: investigationID,
			Timestamp:       time.Now().Add(-24 * time.Hour),
			Event:           "Investigation created",
			EventType:       "system",
			Actor:           "security.analyst@company.com",
			Details:         "Investigation initiated after critical alert",
			Source:          "system",
			Severity:        "info",
		},
		{
			ID:              "tl-002",
			InvestigationID: investigationID,
			Timestamp:       time.Now().Add(-23 * time.Hour),
			Event:           "Malware sample collected",
			EventType:       "evidence",
			Actor:           "security.analyst@company.com",
			Target:          "WORKSTATION-001",
			Details:         "Collected malware.exe from C:\\Windows\\Temp",
			Source:          "evidence_collection",
			Severity:        "high",
			EvidenceID:      "ev-001",
		},
		{
			ID:              "tl-003",
			InvestigationID: investigationID,
			Timestamp:       time.Now().Add(-22 * time.Hour),
			Event:           "Memory dump captured",
			EventType:       "evidence",
			Actor:           "security.analyst@company.com",
			Target:          "WORKSTATION-001",
			Details:         "Full memory dump of compromised system",
			Source:          "evidence_collection",
			Severity:        "medium",
			EvidenceID:      "ev-002",
		},
		{
			ID:              "tl-004",
			InvestigationID: investigationID,
			Timestamp:       time.Now().Add(-20 * time.Hour),
			Event:           "Malware analysis completed",
			EventType:       "analysis",
			Actor:           "malware.analyst@company.com",
			Details:         "Identified as LockBit 3.0 ransomware variant",
			Source:          "sandbox",
			Severity:        "critical",
		},
		{
			ID:              "tl-005",
			InvestigationID: investigationID,
			Timestamp:       time.Now().Add(-18 * time.Hour),
			Event:           "Lateral movement detected",
			EventType:       "finding",
			Actor:           "security.analyst@company.com",
			Details:         "Attacker moved from WORKSTATION-001 to SERVER-001 via RDP",
			Source:          "log_analysis",
			Severity:        "critical",
		},
		{
			ID:              "tl-006",
			InvestigationID: investigationID,
			Timestamp:       time.Now().Add(-12 * time.Hour),
			Event:           "Initial access vector identified",
			EventType:       "finding",
			Actor:           "incident.responder@company.com",
			Details:         "Phishing email with malicious attachment opened by user",
			Source:          "email_analysis",
			Severity:        "high",
		},
		{
			ID:              "tl-007",
			InvestigationID: investigationID,
			Timestamp:       time.Now().Add(-6 * time.Hour),
			Event:           "MITRE ATT&CK mapping updated",
			EventType:       "system",
			Actor:           "security.analyst@company.com",
			Details:         "Added T1566.001 (Phishing: Spearphishing Attachment), T1059.001 (PowerShell)",
			Source:          "manual",
			Severity:        "info",
		},
		{
			ID:              "tl-008",
			InvestigationID: investigationID,
			Timestamp:       time.Now().Add(-2 * time.Hour),
			Event:           "Investigation status update",
			EventType:       "system",
			Actor:           "soc.lead@company.com",
			Details:         "Containment actions completed, moving to eradication phase",
			Source:          "manual",
			Severity:        "info",
		},
	}
}

