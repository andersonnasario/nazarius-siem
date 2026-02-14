package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// MDR Forensics structures
type MDRForensicCase struct {
	ID            string    `json:"id"`
	IncidentID    string    `json:"incident_id"`
	Title         string    `json:"title"`
	Status        string    `json:"status"` // active, closed, archived
	Priority      string    `json:"priority"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	EvidenceCount int       `json:"evidence_count"`
	Analyst       string    `json:"analyst"`
}

type MDRForensicEvidence struct {
	ID          string                 `json:"id"`
	CaseID      string                 `json:"case_id"`
	Type        string                 `json:"type"` // file, memory, network, registry, log
	Source      string                 `json:"source"`
	Hash        string                 `json:"hash"`
	Size        int64                  `json:"size"`
	CollectedAt time.Time              `json:"collected_at"`
	Metadata    map[string]interface{} `json:"metadata"`
	ChainHash   string                 `json:"chain_hash"` // Chain of custody hash
}

type MDRForensicTimeline struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"case_id"`
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	Actor     string    `json:"actor"`
	Details   string    `json:"details"`
}

type MDRForensicReport struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"case_id"`
	Title     string    `json:"title"`
	Summary   string    `json:"summary"`
	Findings  []string  `json:"findings"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

var (
	mdrForensicCases     = make(map[string]*MDRForensicCase)
	mdrForensicEvidence  = make(map[string]*MDRForensicEvidence)
	mdrForensicTimelines = make(map[string]*MDRForensicTimeline)
	mdrForensicReports   = make(map[string]*MDRForensicReport)
	mdrForensicMutex     sync.RWMutex
)

func initMDRForensics() {
	mdrForensicMutex.Lock()
	defer mdrForensicMutex.Unlock()

	// Sample data
	case1 := &MDRForensicCase{
		ID:            "mdr-case-001",
		IncidentID:    "inc-001",
		Title:         "Ransomware Investigation",
		Status:        "active",
		Priority:      "critical",
		CreatedAt:     time.Now().Add(-24 * time.Hour),
		UpdatedAt:     time.Now().Add(-2 * time.Hour),
		EvidenceCount: 5,
		Analyst:       "John Doe",
	}
	mdrForensicCases[case1.ID] = case1

	case2 := &MDRForensicCase{
		ID:            "mdr-case-002",
		IncidentID:    "inc-002",
		Title:         "Data Exfiltration Analysis",
		Status:        "active",
		Priority:      "high",
		CreatedAt:     time.Now().Add(-48 * time.Hour),
		UpdatedAt:     time.Now().Add(-1 * time.Hour),
		EvidenceCount: 8,
		Analyst:       "Jane Smith",
	}
	mdrForensicCases[case2.ID] = case2

	// Sample evidence
	evidence1 := &MDRForensicEvidence{
		ID:          "mdr-ev-001",
		CaseID:      "mdr-case-001",
		Type:        "file",
		Source:      "C:\\Windows\\Temp\\malware.exe",
		Hash:        "a1b2c3d4e5f6",
		Size:        1024000,
		CollectedAt: time.Now().Add(-20 * time.Hour),
		Metadata:    map[string]interface{}{"pe_type": "executable", "signed": false},
		ChainHash:   "chain-hash-001",
	}
	mdrForensicEvidence[evidence1.ID] = evidence1
}

// Handlers
func (s *APIServer) handleListMDRForensicCases(c *gin.Context) {
	mdrForensicMutex.RLock()
	defer mdrForensicMutex.RUnlock()

	cases := make([]*MDRForensicCase, 0, len(mdrForensicCases))
	for _, fc := range mdrForensicCases {
		cases = append(cases, fc)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": cases})
}

func (s *APIServer) handleCreateMDRForensicCase(c *gin.Context) {
	var fc MDRForensicCase
	if err := c.ShouldBindJSON(&fc); err != nil {
		log.Printf("[ERROR] handleCreateMDRForensicCase bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	fc.ID = generateID()
	fc.CreatedAt = time.Now()
	fc.UpdatedAt = time.Now()
	fc.Status = "active"

	mdrForensicMutex.Lock()
	mdrForensicCases[fc.ID] = &fc
	mdrForensicMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": fc})
}

func (s *APIServer) handleGetMDRForensicCase(c *gin.Context) {
	id := c.Param("id")

	mdrForensicMutex.RLock()
	fc, exists := mdrForensicCases[id]
	mdrForensicMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Case not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": fc})
}

func (s *APIServer) handleListMDRForensicEvidence(c *gin.Context) {
	caseID := c.Query("case_id")

	mdrForensicMutex.RLock()
	defer mdrForensicMutex.RUnlock()

	evidence := make([]*MDRForensicEvidence, 0)
	for _, ev := range mdrForensicEvidence {
		if caseID == "" || ev.CaseID == caseID {
			evidence = append(evidence, ev)
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": evidence})
}

func (s *APIServer) handleCreateMDRForensicEvidence(c *gin.Context) {
	var ev MDRForensicEvidence
	if err := c.ShouldBindJSON(&ev); err != nil {
		log.Printf("[ERROR] handleCreateMDRForensicEvidence bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	ev.ID = generateID()
	ev.CollectedAt = time.Now()
	ev.ChainHash = generateID() // Simple chain of custody hash

	mdrForensicMutex.Lock()
	mdrForensicEvidence[ev.ID] = &ev
	
	// Update case evidence count
	if fc, exists := mdrForensicCases[ev.CaseID]; exists {
		fc.EvidenceCount++
		fc.UpdatedAt = time.Now()
	}
	mdrForensicMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": ev})
}

func (s *APIServer) handleGetMDRForensicStats(c *gin.Context) {
	mdrForensicMutex.RLock()
	defer mdrForensicMutex.RUnlock()

	activeCases := 0
	totalEvidence := len(mdrForensicEvidence)
	
	for _, fc := range mdrForensicCases {
		if fc.Status == "active" {
			activeCases++
		}
	}

	stats := gin.H{
		"total_cases":      len(mdrForensicCases),
		"active_cases":     activeCases,
		"closed_cases":     len(mdrForensicCases) - activeCases,
		"total_evidence":   totalEvidence,
		"avg_evidence_per_case": float64(totalEvidence) / float64(len(mdrForensicCases)),
		"critical_cases":   1,
		"high_cases":       1,
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": stats})
}

func (s *APIServer) handleGetMDRForensicTimeline(c *gin.Context) {
	caseID := c.Param("id")

	mdrForensicMutex.RLock()
	defer mdrForensicMutex.RUnlock()

	timeline := make([]*MDRForensicTimeline, 0)
	for _, tl := range mdrForensicTimelines {
		if tl.CaseID == caseID {
			timeline = append(timeline, tl)
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": timeline})
}

