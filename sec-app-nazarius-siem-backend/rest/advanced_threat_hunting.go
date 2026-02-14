package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Advanced Threat Hunting structures
type AdvancedHuntingCampaign struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // active, paused, completed
	Priority    string    `json:"priority"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Queries     []string  `json:"queries"`
	Findings    int       `json:"findings"`
	Coverage    float64   `json:"coverage"` // MITRE ATT&CK coverage %
}

type AdvancedHuntingQuery struct {
	ID          string                 `json:"id"`
	CampaignID  string                 `json:"campaign_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Query       string                 `json:"query"`
	QueryType   string                 `json:"query_type"` // elasticsearch, sql, kql
	Schedule    string                 `json:"schedule"`   // cron expression
	Enabled     bool                   `json:"enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	LastRun     time.Time              `json:"last_run"`
	NextRun     time.Time              `json:"next_run"`
	Results     int                    `json:"results"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type AdvancedHuntingNotebook struct {
	ID          string                   `json:"id"`
	Title       string                   `json:"title"`
	Description string                   `json:"description"`
	Author      string                   `json:"author"`
	CreatedAt   time.Time                `json:"created_at"`
	UpdatedAt   time.Time                `json:"updated_at"`
	Cells       []AdvancedHuntingCell    `json:"cells"`
	Tags        []string                 `json:"tags"`
	Shared      bool                     `json:"shared"`
	Collaborators []string               `json:"collaborators"`
}

type AdvancedHuntingCell struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"` // code, markdown, query, visualization
	Content   string                 `json:"content"`
	Output    map[string]interface{} `json:"output"`
	Executed  bool                   `json:"executed"`
	Order     int                    `json:"order"`
}

type AdvancedHuntingWorkflow struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Trigger     string                 `json:"trigger"` // manual, scheduled, event-based
	Steps       []WorkflowStep         `json:"steps"`
	Status      string                 `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	LastRun     time.Time              `json:"last_run"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type WorkflowStep struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // query, enrichment, correlation, action
	Config      map[string]interface{} `json:"config"`
	Order       int                    `json:"order"`
	Status      string                 `json:"status"`
}

type AdvancedHuntingMetrics struct {
	TotalCampaigns    int     `json:"total_campaigns"`
	ActiveCampaigns   int     `json:"active_campaigns"`
	TotalQueries      int     `json:"total_queries"`
	QueriesExecuted   int     `json:"queries_executed"`
	TotalFindings     int     `json:"total_findings"`
	AvgCoverage       float64 `json:"avg_coverage"`
	TopTechniques     []string `json:"top_techniques"`
	HuntingEfficiency float64 `json:"hunting_efficiency"`
}

type AdvancedMITRECoverage struct {
	TacticID    string  `json:"tactic_id"`
	TacticName  string  `json:"tactic_name"`
	Techniques  int     `json:"techniques"`
	Covered     int     `json:"covered"`
	Coverage    float64 `json:"coverage"`
}

var (
	advHuntingCampaigns  = make(map[string]*AdvancedHuntingCampaign)
	advHuntingQueries    = make(map[string]*AdvancedHuntingQuery)
	advHuntingNotebooks  = make(map[string]*AdvancedHuntingNotebook)
	advHuntingWorkflows  = make(map[string]*AdvancedHuntingWorkflow)
	advHuntingMutex      sync.RWMutex
)

func initAdvancedThreatHunting() {
	advHuntingMutex.Lock()
	defer advHuntingMutex.Unlock()

	// Sample campaign
	campaign1 := &AdvancedHuntingCampaign{
		ID:          "adv-camp-001",
		Name:        "APT Detection Campaign",
		Description: "Advanced persistent threat detection across network",
		Status:      "active",
		Priority:    "high",
		CreatedBy:   "analyst@company.com",
		CreatedAt:   time.Now().Add(-7 * 24 * time.Hour),
		UpdatedAt:   time.Now().Add(-1 * time.Hour),
		Queries:     []string{"query-001", "query-002"},
		Findings:    15,
		Coverage:    75.5,
	}
	advHuntingCampaigns[campaign1.ID] = campaign1

	campaign2 := &AdvancedHuntingCampaign{
		ID:          "adv-camp-002",
		Name:        "Lateral Movement Hunt",
		Description: "Detecting lateral movement techniques",
		Status:      "active",
		Priority:    "critical",
		CreatedBy:   "soc@company.com",
		CreatedAt:   time.Now().Add(-3 * 24 * time.Hour),
		UpdatedAt:   time.Now(),
		Queries:     []string{"query-003"},
		Findings:    8,
		Coverage:    82.3,
	}
	advHuntingCampaigns[campaign2.ID] = campaign2

	// Sample query
	query1 := &AdvancedHuntingQuery{
		ID:          "query-001",
		CampaignID:  "adv-camp-001",
		Name:        "Suspicious PowerShell Execution",
		Description: "Detect encoded PowerShell commands",
		Query:       `process.name:"powershell.exe" AND process.command_line:*-enc*`,
		QueryType:   "elasticsearch",
		Schedule:    "0 */4 * * *", // Every 4 hours
		Enabled:     true,
		CreatedAt:   time.Now().Add(-7 * 24 * time.Hour),
		LastRun:     time.Now().Add(-2 * time.Hour),
		NextRun:     time.Now().Add(2 * time.Hour),
		Results:     45,
		Metadata:    map[string]interface{}{"mitre_technique": "T1059.001"},
	}
	advHuntingQueries[query1.ID] = query1

	// Sample notebook
	notebook1 := &AdvancedHuntingNotebook{
		ID:          "notebook-001",
		Title:       "APT29 Hunting Playbook",
		Description: "Comprehensive hunting for APT29 TTPs",
		Author:      "threat-hunter@company.com",
		CreatedAt:   time.Now().Add(-14 * 24 * time.Hour),
		UpdatedAt:   time.Now().Add(-1 * 24 * time.Hour),
		Cells: []AdvancedHuntingCell{
			{
				ID:       "cell-001",
				Type:     "markdown",
				Content:  "# APT29 Hunting\n\nThis notebook covers hunting for APT29 activities.",
				Order:    1,
				Executed: false,
			},
			{
				ID:       "cell-002",
				Type:     "query",
				Content:  `process.name:"rundll32.exe" AND network.direction:"outbound"`,
				Order:    2,
				Executed: true,
				Output:   map[string]interface{}{"results": 12, "time": "2.3s"},
			},
		},
		Tags:          []string{"APT29", "Cozy Bear", "Advanced"},
		Shared:        true,
		Collaborators: []string{"analyst1@company.com", "analyst2@company.com"},
	}
	advHuntingNotebooks[notebook1.ID] = notebook1
}

// Handlers
func (s *APIServer) handleListAdvHuntingCampaigns(c *gin.Context) {
	advHuntingMutex.RLock()
	defer advHuntingMutex.RUnlock()

	campaigns := make([]*AdvancedHuntingCampaign, 0, len(advHuntingCampaigns))
	for _, camp := range advHuntingCampaigns {
		campaigns = append(campaigns, camp)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": campaigns})
}

func (s *APIServer) handleCreateAdvHuntingCampaign(c *gin.Context) {
	var campaign AdvancedHuntingCampaign
	if err := c.ShouldBindJSON(&campaign); err != nil {
		log.Printf("[ERROR] handleCreateAdvHuntingCampaign bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	campaign.ID = generateID()
	campaign.CreatedAt = time.Now()
	campaign.UpdatedAt = time.Now()
	campaign.Status = "active"

	advHuntingMutex.Lock()
	advHuntingCampaigns[campaign.ID] = &campaign
	advHuntingMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": campaign})
}

func (s *APIServer) handleGetAdvHuntingCampaign(c *gin.Context) {
	id := c.Param("id")

	advHuntingMutex.RLock()
	campaign, exists := advHuntingCampaigns[id]
	advHuntingMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Campaign not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": campaign})
}

func (s *APIServer) handleListAdvHuntingQueries(c *gin.Context) {
	campaignID := c.Query("campaign_id")

	advHuntingMutex.RLock()
	defer advHuntingMutex.RUnlock()

	queries := make([]*AdvancedHuntingQuery, 0)
	for _, query := range advHuntingQueries {
		if campaignID == "" || query.CampaignID == campaignID {
			queries = append(queries, query)
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": queries})
}

func (s *APIServer) handleCreateAdvHuntingQuery(c *gin.Context) {
	var query AdvancedHuntingQuery
	if err := c.ShouldBindJSON(&query); err != nil {
		log.Printf("[ERROR] handleCreateAdvHuntingQuery bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	query.ID = generateID()
	query.CreatedAt = time.Now()
	query.Enabled = true

	advHuntingMutex.Lock()
	advHuntingQueries[query.ID] = &query
	advHuntingMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": query})
}

func (s *APIServer) handleListAdvHuntingNotebooks(c *gin.Context) {
	advHuntingMutex.RLock()
	defer advHuntingMutex.RUnlock()

	notebooks := make([]*AdvancedHuntingNotebook, 0, len(advHuntingNotebooks))
	for _, nb := range advHuntingNotebooks {
		notebooks = append(notebooks, nb)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": notebooks})
}

func (s *APIServer) handleCreateAdvHuntingNotebook(c *gin.Context) {
	var notebook AdvancedHuntingNotebook
	if err := c.ShouldBindJSON(&notebook); err != nil {
		log.Printf("[ERROR] handleCreateAdvHuntingNotebook bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	notebook.ID = generateID()
	notebook.CreatedAt = time.Now()
	notebook.UpdatedAt = time.Now()

	advHuntingMutex.Lock()
	advHuntingNotebooks[notebook.ID] = &notebook
	advHuntingMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": notebook})
}

func (s *APIServer) handleGetAdvHuntingMetrics(c *gin.Context) {
	advHuntingMutex.RLock()
	defer advHuntingMutex.RUnlock()

	activeCampaigns := 0
	totalFindings := 0
	totalCoverage := 0.0

	for _, camp := range advHuntingCampaigns {
		if camp.Status == "active" {
			activeCampaigns++
		}
		totalFindings += camp.Findings
		totalCoverage += camp.Coverage
	}

	avgCoverage := 0.0
	if len(advHuntingCampaigns) > 0 {
		avgCoverage = totalCoverage / float64(len(advHuntingCampaigns))
	}

	metrics := AdvancedHuntingMetrics{
		TotalCampaigns:    len(advHuntingCampaigns),
		ActiveCampaigns:   activeCampaigns,
		TotalQueries:      len(advHuntingQueries),
		QueriesExecuted:   45,
		TotalFindings:     totalFindings,
		AvgCoverage:       avgCoverage,
		TopTechniques:     []string{"T1059.001", "T1055", "T1003"},
		HuntingEfficiency: 87.5,
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": metrics})
}

func (s *APIServer) handleGetAdvancedMITRECoverage(c *gin.Context) {
	coverage := []AdvancedMITRECoverage{
		{TacticID: "TA0001", TacticName: "Initial Access", Techniques: 12, Covered: 9, Coverage: 75.0},
		{TacticID: "TA0002", TacticName: "Execution", Techniques: 15, Covered: 13, Coverage: 86.7},
		{TacticID: "TA0003", TacticName: "Persistence", Techniques: 20, Covered: 15, Coverage: 75.0},
		{TacticID: "TA0004", TacticName: "Privilege Escalation", Techniques: 18, Covered: 14, Coverage: 77.8},
		{TacticID: "TA0005", TacticName: "Defense Evasion", Techniques: 42, Covered: 30, Coverage: 71.4},
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": coverage})
}

