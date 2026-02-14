package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// ThreatHuntHypothesis represents a threat hunting hypothesis
type ThreatHuntHypothesis struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	MitreTactics  []string               `json:"mitre_tactics"`
	MitreTechniques []string             `json:"mitre_techniques"`
	Status        string                 `json:"status"` // draft, active, validated, invalidated
	Priority      string                 `json:"priority"` // critical, high, medium, low
	CreatedBy     string                 `json:"created_by"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	Queries       []ThreatHuntQuery         `json:"queries"`
	Findings      []ThreatHuntFinding       `json:"findings"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ThreatHuntQuery represents a query for threat hunting
type ThreatHuntQuery struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	QueryType   string    `json:"query_type"` // elasticsearch, kql, sql
	QueryBody   string    `json:"query_body"`
	SavedQuery  bool      `json:"saved_query"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	ExecutionCount int    `json:"execution_count"`
	LastExecuted *time.Time `json:"last_executed"`
}

// ThreatHuntFinding represents a finding from threat hunting
type ThreatHuntFinding struct {
	ID            string    `json:"id"`
	HypothesisID  string    `json:"hypothesis_id"`
	QueryID       string    `json:"query_id"`
	Severity      string    `json:"severity"` // critical, high, medium, low
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	Evidence      []string  `json:"evidence"`
	Indicators    []string  `json:"indicators"`
	MitreTactics  []string  `json:"mitre_tactics"`
	MitreTechniques []string `json:"mitre_techniques"`
	Status        string    `json:"status"` // new, investigating, confirmed, false_positive
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ThreatHuntNotebook represents a Jupyter-like hunting notebook
type ThreatHuntNotebook struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Cells       []NotebookCell   `json:"cells"`
	CreatedBy   string           `json:"created_by"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	Shared      bool             `json:"shared"`
}

// NotebookCell represents a cell in a hunting notebook
type NotebookCell struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // markdown, code, query
	Content   string    `json:"content"`
	Output    string    `json:"output"`
	ExecutedAt *time.Time `json:"executed_at"`
}

// ScheduledHunt represents a scheduled threat hunt
type ScheduledHunt struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	HypothesisID string    `json:"hypothesis_id"`
	QueryID      string    `json:"query_id"`
	Schedule     string    `json:"schedule"` // cron expression
	Enabled      bool      `json:"enabled"`
	LastRun      *time.Time `json:"last_run"`
	NextRun      *time.Time `json:"next_run"`
	FindingsCount int      `json:"findings_count"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

// ThreatHuntMetrics represents hunting performance metrics
type ThreatHuntMetrics struct {
	TotalHypotheses    int     `json:"total_hypotheses"`
	ActiveHypotheses   int     `json:"active_hypotheses"`
	ValidatedHypotheses int    `json:"validated_hypotheses"`
	TotalFindings      int     `json:"total_findings"`
	CriticalFindings   int     `json:"critical_findings"`
	ValidationRate     float64 `json:"validation_rate"`
	AvgTimeToDiscovery float64 `json:"avg_time_to_discovery"` // hours
	CoverageScore      float64 `json:"coverage_score"` // 0-100
	TopHunters         []HunterPerformance `json:"top_hunters"`
}

// HunterPerformance represents individual hunter metrics
type HunterPerformance struct {
	HunterID        string  `json:"hunter_id"`
	HunterName      string  `json:"hunter_name"`
	HypothesesCount int     `json:"hypotheses_count"`
	FindingsCount   int     `json:"findings_count"`
	ValidationRate  float64 `json:"validation_rate"`
}

// QueryTemplate represents a pre-built query template
type QueryTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"` // lateral_movement, privilege_escalation, etc
	QueryType   string   `json:"query_type"`
	QueryBody   string   `json:"query_body"`
	MitreTactics []string `json:"mitre_tactics"`
	MitreTechniques []string `json:"mitre_techniques"`
	Severity    string   `json:"severity"`
}

// HuntingActivity represents a hunting activity for history tracking
type HuntingActivity struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"` // hypothesis_created, hypothesis_validated, query_executed, finding_created, etc
	HunterID     string                 `json:"hunter_id"`
	HunterName   string                 `json:"hunter_name"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	EntityID     string                 `json:"entity_id"` // ID of hypothesis, query, or finding
	EntityType   string                 `json:"entity_type"` // hypothesis, query, finding
	Severity     string                 `json:"severity,omitempty"`
	Status       string                 `json:"status,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// ============================================================================
// IN-MEMORY STORAGE
// ============================================================================

var (
	huntingHypotheses = make(map[string]*ThreatHuntHypothesis)
	huntingQueries    = make(map[string]*ThreatHuntQuery)
	huntingFindings   = make(map[string]*ThreatHuntFinding)
	huntingNotebooks  = make(map[string]*ThreatHuntNotebook)
	scheduledHunts    = make(map[string]*ScheduledHunt)
	queryTemplates    = make(map[string]*QueryTemplate)
	huntingActivities = make([]*HuntingActivity, 0) // Slice for chronological order
	huntingMutex      sync.RWMutex
)

// ============================================================================
// INITIALIZATION
// ============================================================================

func initThreatHuntingPlatform() {
	huntingMutex.Lock()
	defer huntingMutex.Unlock()

	// Initialize query templates
	initQueryTemplates()
	
	// Initialize sample hypotheses (15 realistic hunting scenarios)
	now := time.Now()
	
	hypotheses := []*ThreatHuntHypothesis{
		{
			ID:          "hyp-001",
			Name:        "Lateral Movement via RDP",
			Description: "Detect potential lateral movement using RDP connections from workstations to servers",
			MitreTactics: []string{"TA0008"},
			MitreTechniques: []string{"T1021.001"},
			Status:      "active",
			Priority:    "high",
			CreatedBy:   "hunter-1",
			CreatedAt:   now.Add(-7 * 24 * time.Hour),
			UpdatedAt:   now.Add(-1 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "high", "dwell_time": "2-5 days"},
		},
		{
			ID:          "hyp-002",
			Name:        "Privilege Escalation via Token Manipulation",
			Description: "Hunt for token manipulation techniques used for privilege escalation",
			MitreTactics: []string{"TA0004"},
			MitreTechniques: []string{"T1134"},
			Status:      "validated",
			Priority:    "critical",
			CreatedBy:   "hunter-2",
			CreatedAt:   now.Add(-14 * 24 * time.Hour),
			UpdatedAt:   now.Add(-3 * 24 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "high", "true_positives": 3},
		},
		{
			ID:          "hyp-003",
			Name:        "Data Exfiltration via DNS Tunneling",
			Description: "Identify abnormal DNS queries that may indicate data exfiltration",
			MitreTactics: []string{"TA0010"},
			MitreTechniques: []string{"T1048.003"},
			Status:      "active",
			Priority:    "critical",
			CreatedBy:   "hunter-1",
			CreatedAt:   now.Add(-5 * 24 * time.Hour),
			UpdatedAt:   now.Add(-2 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "medium", "baseline_required": true},
		},
		{
			ID:          "hyp-004",
			Name:        "Living off the Land - PowerShell Abuse",
			Description: "Detect suspicious PowerShell execution patterns and encoded commands",
			MitreTactics: []string{"TA0002", "TA0005"},
			MitreTechniques: []string{"T1059.001", "T1027"},
			Status:      "active",
			Priority:    "high",
			CreatedBy:   "hunter-3",
			CreatedAt:   now.Add(-10 * 24 * time.Hour),
			UpdatedAt:   now.Add(-6 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "high", "common_in_environment": true},
		},
		{
			ID:          "hyp-005",
			Name:        "Persistence via Registry Run Keys",
			Description: "Hunt for unauthorized modifications to registry run keys",
			MitreTactics: []string{"TA0003"},
			MitreTechniques: []string{"T1547.001"},
			Status:      "validated",
			Priority:    "medium",
			CreatedBy:   "hunter-2",
			CreatedAt:   now.Add(-21 * 24 * time.Hour),
			UpdatedAt:   now.Add(-7 * 24 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "high", "true_positives": 2},
		},
		{
			ID:          "hyp-006",
			Name:        "Credential Dumping - LSASS Access",
			Description: "Detect attempts to access LSASS memory for credential dumping",
			MitreTactics: []string{"TA0006"},
			MitreTechniques: []string{"T1003.001"},
			Status:      "active",
			Priority:    "critical",
			CreatedBy:   "hunter-1",
			CreatedAt:   now.Add(-3 * 24 * time.Hour),
			UpdatedAt:   now.Add(-30 * time.Minute),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "high", "edr_required": true},
		},
		{
			ID:          "hyp-007",
			Name:        "C2 Communication via Uncommon Ports",
			Description: "Identify potential C2 traffic using non-standard ports",
			MitreTactics: []string{"TA0011"},
			MitreTechniques: []string{"T1071.001"},
			Status:      "active",
			Priority:    "high",
			CreatedBy:   "hunter-3",
			UpdatedAt:   now.Add(-4 * time.Hour),
			CreatedAt:   now.Add(-12 * 24 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "medium", "network_baseline": "required"},
		},
		{
			ID:          "hyp-008",
			Name:        "Suspicious Service Creation",
			Description: "Hunt for services created with suspicious characteristics",
			MitreTactics: []string{"TA0003", "TA0004"},
			MitreTechniques: []string{"T1543.003"},
			Status:      "validated",
			Priority:    "high",
			CreatedBy:   "hunter-2",
			CreatedAt:   now.Add(-18 * 24 * time.Hour),
			UpdatedAt:   now.Add(-5 * 24 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "high", "true_positives": 1},
		},
		{
			ID:          "hyp-009",
			Name:        "Kerberoasting Detection",
			Description: "Detect Kerberoasting attacks via TGS ticket requests",
			MitreTactics: []string{"TA0006"},
			MitreTechniques: []string{"T1558.003"},
			Status:      "active",
			Priority:    "high",
			CreatedBy:   "hunter-1",
			CreatedAt:   now.Add(-6 * 24 * time.Hour),
			UpdatedAt:   now.Add(-1 * 24 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "high", "ad_logs_required": true},
		},
		{
			ID:          "hyp-010",
			Name:        "Suspicious Scheduled Task Creation",
			Description: "Hunt for scheduled tasks created for persistence or execution",
			MitreTactics: []string{"TA0003", "TA0002"},
			MitreTechniques: []string{"T1053.005"},
			Status:      "active",
			Priority:    "medium",
			CreatedBy:   "hunter-3",
			CreatedAt:   now.Add(-9 * 24 * time.Hour),
			UpdatedAt:   now.Add(-8 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "medium"},
		},
		{
			ID:          "hyp-011",
			Name:        "Web Shell Detection",
			Description: "Identify potential web shells on web servers",
			MitreTactics: []string{"TA0003", "TA0011"},
			MitreTechniques: []string{"T1505.003"},
			Status:      "validated",
			Priority:    "critical",
			CreatedBy:   "hunter-2",
			CreatedAt:   now.Add(-25 * 24 * time.Hour),
			UpdatedAt:   now.Add(-10 * 24 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "high", "true_positives": 2},
		},
		{
			ID:          "hyp-012",
			Name:        "Pass-the-Hash Attacks",
			Description: "Detect pass-the-hash authentication attempts",
			MitreTactics: []string{"TA0008"},
			MitreTechniques: []string{"T1550.002"},
			Status:      "active",
			Priority:    "critical",
			CreatedBy:   "hunter-1",
			CreatedAt:   now.Add(-4 * 24 * time.Hour),
			UpdatedAt:   now.Add(-3 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "high", "ntlm_monitoring": true},
		},
		{
			ID:          "hyp-013",
			Name:        "Suspicious WMI Activity",
			Description: "Hunt for malicious WMI usage for persistence or lateral movement",
			MitreTactics: []string{"TA0002", "TA0003", "TA0008"},
			MitreTechniques: []string{"T1047"},
			Status:      "draft",
			Priority:    "medium",
			CreatedBy:   "hunter-3",
			CreatedAt:   now.Add(-2 * 24 * time.Hour),
			UpdatedAt:   now.Add(-2 * 24 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "medium", "status": "under_development"},
		},
		{
			ID:          "hyp-014",
			Name:        "DLL Side-Loading Detection",
			Description: "Identify DLL side-loading techniques used by attackers",
			MitreTactics: []string{"TA0005"},
			MitreTechniques: []string{"T1574.002"},
			Status:      "active",
			Priority:    "high",
			CreatedBy:   "hunter-2",
			CreatedAt:   now.Add(-8 * 24 * time.Hour),
			UpdatedAt:   now.Add(-12 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "medium", "requires_sysmon": true},
		},
		{
			ID:          "hyp-015",
			Name:        "Golden Ticket Detection",
			Description: "Hunt for forged Kerberos TGT tickets (Golden Ticket attacks)",
			MitreTactics: []string{"TA0006"},
			MitreTechniques: []string{"T1558.001"},
			Status:      "validated",
			Priority:    "critical",
			CreatedBy:   "hunter-1",
			CreatedAt:   now.Add(-30 * 24 * time.Hour),
			UpdatedAt:   now.Add(-15 * 24 * time.Hour),
			Queries:     []ThreatHuntQuery{},
			Findings:    []ThreatHuntFinding{},
			Metadata:    map[string]interface{}{"confidence": "high", "true_positives": 1, "critical_finding": true},
		},
	}
	
	for _, hyp := range hypotheses {
		huntingHypotheses[hyp.ID] = hyp
	}
	
	// Initialize sample findings
	initSampleFindings(now)
}

func initQueryTemplates() {
	templates := []QueryTemplate{
		{
			ID:          "tpl-001",
			Name:        "Lateral Movement via RDP",
			Description: "Detect RDP connections between internal hosts",
			Category:    "lateral_movement",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "network"}}, {"match": {"destination.port": 3389}}, {"range": {"@timestamp": {"gte": "now-24h"}}}]}}}`,
			MitreTactics: []string{"TA0008"},
			MitreTechniques: []string{"T1021.001"},
			Severity:    "high",
		},
		{
			ID:          "tpl-002",
			Name:        "Privilege Escalation via Token Manipulation",
			Description: "Detect token manipulation for privilege escalation",
			Category:    "privilege_escalation",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "process"}}, {"match": {"event.action": "token_manipulation"}}]}}}`,
			MitreTactics: []string{"TA0004"},
			MitreTechniques: []string{"T1134"},
			Severity:    "critical",
		},
		{
			ID:          "tpl-003",
			Name:        "DNS Tunneling Detection",
			Description: "Identify abnormal DNS query patterns",
			Category:    "exfiltration",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "dns"}}, {"range": {"dns.question.name.length": {"gte": 50}}}]}}}`,
			MitreTactics: []string{"TA0010"},
			MitreTechniques: []string{"T1048.003"},
			Severity:    "critical",
		},
		{
			ID:          "tpl-004",
			Name:        "PowerShell Encoded Commands",
			Description: "Detect encoded PowerShell commands",
			Category:    "execution",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"process.name": "powershell.exe"}}, {"wildcard": {"process.command_line": "*-enc*"}}]}}}`,
			MitreTactics: []string{"TA0002"},
			MitreTechniques: []string{"T1059.001", "T1027"},
			Severity:    "high",
		},
		{
			ID:          "tpl-005",
			Name:        "Registry Run Key Modifications",
			Description: "Detect modifications to registry run keys",
			Category:    "persistence",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "registry"}}, {"wildcard": {"registry.path": "*\\\\Run*"}}]}}}`,
			MitreTactics: []string{"TA0003"},
			MitreTechniques: []string{"T1547.001"},
			Severity:    "medium",
		},
		{
			ID:          "tpl-006",
			Name:        "LSASS Memory Access",
			Description: "Detect attempts to access LSASS process memory",
			Category:    "credential_access",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "process"}}, {"match": {"process.target.name": "lsass.exe"}}]}}}`,
			MitreTactics: []string{"TA0006"},
			MitreTechniques: []string{"T1003.001"},
			Severity:    "critical",
		},
		{
			ID:          "tpl-007",
			Name:        "Uncommon Network Ports",
			Description: "Identify traffic on non-standard ports",
			Category:    "command_and_control",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "network"}}, {"bool": {"must_not": [{"terms": {"destination.port": [80, 443, 22, 3389]}}]}}]}}}`,
			MitreTactics: []string{"TA0011"},
			MitreTechniques: []string{"T1071.001"},
			Severity:    "high",
		},
		{
			ID:          "tpl-008",
			Name:        "Suspicious Service Creation",
			Description: "Detect services with suspicious characteristics",
			Category:    "persistence",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "service"}}, {"match": {"event.action": "creation"}}]}}}`,
			MitreTactics: []string{"TA0003"},
			MitreTechniques: []string{"T1543.003"},
			Severity:    "high",
		},
		{
			ID:          "tpl-009",
			Name:        "Kerberoasting - TGS Requests",
			Description: "Detect potential Kerberoasting attacks",
			Category:    "credential_access",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "authentication"}}, {"match": {"event.action": "kerberos_tgs_request"}}, {"range": {"event.count": {"gte": 10}}}]}}}`,
			MitreTactics: []string{"TA0006"},
			MitreTechniques: []string{"T1558.003"},
			Severity:    "high",
		},
		{
			ID:          "tpl-010",
			Name:        "Scheduled Task Creation",
			Description: "Hunt for suspicious scheduled tasks",
			Category:    "persistence",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "task_scheduler"}}, {"match": {"event.action": "task_created"}}]}}}`,
			MitreTactics: []string{"TA0003"},
			MitreTechniques: []string{"T1053.005"},
			Severity:    "medium",
		},
		{
			ID:          "tpl-011",
			Name:        "Web Shell Indicators",
			Description: "Detect potential web shell activity",
			Category:    "persistence",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "web"}}, {"wildcard": {"url.path": "*.aspx*"}}, {"match": {"http.request.method": "POST"}}]}}}`,
			MitreTactics: []string{"TA0003"},
			MitreTechniques: []string{"T1505.003"},
			Severity:    "critical",
		},
		{
			ID:          "tpl-012",
			Name:        "Pass-the-Hash Detection",
			Description: "Identify pass-the-hash authentication",
			Category:    "lateral_movement",
			QueryType:   "elasticsearch",
			QueryBody:   `{"query": {"bool": {"must": [{"match": {"event.category": "authentication"}}, {"match": {"event.action": "ntlm_auth"}}, {"match": {"event.outcome": "success"}}]}}}`,
			MitreTactics: []string{"TA0008"},
			MitreTechniques: []string{"T1550.002"},
			Severity:    "critical",
		},
	}
	
	for _, tpl := range templates {
		queryTemplates[tpl.ID] = &tpl
	}
}

// initSampleFindings creates sample findings for demonstration
func initSampleFindings(now time.Time) {
	findings := []*ThreatHuntFinding{
		{
			ID:           "find-001",
			HypothesisID: "hyp-002",
			QueryID:      "query-001",
			Severity:     "critical",
			Title:        "Token Manipulation Detected on Domain Controller",
			Description:  "Detected suspicious token manipulation activity on DC01, potentially indicating privilege escalation attempt",
			Evidence:     []string{"Process: lsass.exe", "User: SYSTEM", "Action: SeDebugPrivilege enabled"},
			Indicators:   []string{"192.168.1.10", "DC01.domain.local"},
			MitreTactics: []string{"TA0004"},
			MitreTechniques: []string{"T1134"},
			Status:       "confirmed",
			CreatedBy:    "hunter-2",
			CreatedAt:    now.Add(-3 * 24 * time.Hour),
			UpdatedAt:    now.Add(-2 * 24 * time.Hour),
		},
		{
			ID:           "find-002",
			HypothesisID: "hyp-001",
			QueryID:      "query-002",
			Severity:     "high",
			Title:        "Lateral Movement via RDP from Workstation",
			Description:  "Workstation WS-1234 initiated RDP connection to multiple servers",
			Evidence:     []string{"Source: 192.168.10.50", "Destinations: 10.0.1.5, 10.0.1.8, 10.0.1.12", "Port: 3389"},
			Indicators:   []string{"192.168.10.50", "WS-1234"},
			MitreTactics: []string{"TA0008"},
			MitreTechniques: []string{"T1021.001"},
			Status:       "investigating",
			CreatedBy:    "hunter-1",
			CreatedAt:    now.Add(-1 * 24 * time.Hour),
			UpdatedAt:    now.Add(-6 * time.Hour),
		},
		{
			ID:           "find-003",
			HypothesisID: "hyp-011",
			QueryID:      "query-003",
			Severity:     "critical",
			Title:        "Web Shell Detected on IIS Server",
			Description:  "Suspicious ASPX file with web shell characteristics found on WEB-01",
			Evidence:     []string{"File: /uploads/shell.aspx", "MD5: 5d41402abc4b2a76b9719d911017c592", "POST requests: 45"},
			Indicators:   []string{"10.0.2.15", "shell.aspx", "attacker-ip: 203.0.113.45"},
			MitreTactics: []string{"TA0003", "TA0011"},
			MitreTechniques: []string{"T1505.003"},
			Status:       "confirmed",
			CreatedBy:    "hunter-2",
			CreatedAt:    now.Add(-10 * 24 * time.Hour),
			UpdatedAt:    now.Add(-9 * 24 * time.Hour),
		},
		{
			ID:           "find-004",
			HypothesisID: "hyp-015",
			QueryID:      "query-004",
			Severity:     "critical",
			Title:        "Golden Ticket Attack Detected",
			Description:  "Forged Kerberos TGT ticket detected with suspicious lifetime",
			Evidence:     []string{"Ticket lifetime: 10 years", "Encryption: RC4", "User: krbtgt"},
			Indicators:   []string{"Ticket hash: abc123...", "Source: 192.168.1.100"},
			MitreTactics: []string{"TA0006"},
			MitreTechniques: []string{"T1558.001"},
			Status:       "confirmed",
			CreatedBy:    "hunter-1",
			CreatedAt:    now.Add(-15 * 24 * time.Hour),
			UpdatedAt:    now.Add(-14 * 24 * time.Hour),
		},
	}
	
	for _, finding := range findings {
		huntingFindings[finding.ID] = finding
	}
}

// ============================================================================
// API HANDLERS
// ============================================================================

// List hypotheses
func (s *APIServer) handleListThreatHuntHypotheses(c *gin.Context) {
	huntingMutex.RLock()
	defer huntingMutex.RUnlock()

	status := c.Query("status")
	priority := c.Query("priority")

	hypotheses := make([]*ThreatHuntHypothesis, 0)
	for _, hyp := range huntingHypotheses {
		if status != "" && hyp.Status != status {
			continue
		}
		if priority != "" && hyp.Priority != priority {
			continue
		}
		hypotheses = append(hypotheses, hyp)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    hypotheses,
		"total":   len(hypotheses),
	})
}

// Create hypothesis
func (s *APIServer) handleCreateThreatHuntHypothesis(c *gin.Context) {
	var hyp ThreatHuntHypothesis
	if err := c.ShouldBindJSON(&hyp); err != nil {
		log.Printf("[ERROR] handleCreateThreatHuntHypothesis bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	hyp.ID = generateID()
	hyp.CreatedAt = time.Now()
	hyp.UpdatedAt = time.Now()
	hyp.Status = "draft"

	huntingMutex.Lock()
	huntingHypotheses[hyp.ID] = &hyp
	huntingMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    hyp,
		"message": "Hunting hypothesis created successfully",
	})
}

// Get hypothesis
func (s *APIServer) handleGetThreatHuntHypothesis(c *gin.Context) {
	id := c.Param("id")

	huntingMutex.RLock()
	hyp, exists := huntingHypotheses[id]
	huntingMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Hypothesis not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    hyp,
	})
}

// Update hypothesis
func (s *APIServer) handleUpdateThreatHuntHypothesis(c *gin.Context) {
	id := c.Param("id")

	huntingMutex.Lock()
	defer huntingMutex.Unlock()

	hyp, exists := huntingHypotheses[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Hypothesis not found",
		})
		return
	}

	var updates ThreatHuntHypothesis
	if err := c.ShouldBindJSON(&updates); err != nil {
		log.Printf("[ERROR] handleUpdateThreatHuntHypothesis bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	hyp.Name = updates.Name
	hyp.Description = updates.Description
	hyp.Status = updates.Status
	hyp.Priority = updates.Priority
	hyp.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    hyp,
		"message": "Hypothesis updated successfully",
	})
}

// Delete hypothesis
func (s *APIServer) handleDeleteThreatHuntHypothesis(c *gin.Context) {
	id := c.Param("id")

	huntingMutex.Lock()
	defer huntingMutex.Unlock()

	if _, exists := huntingHypotheses[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Hypothesis not found",
		})
		return
	}

	delete(huntingHypotheses, id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Hypothesis deleted successfully",
	})
}

// List query templates
func (s *APIServer) handleListQueryTemplates(c *gin.Context) {
	huntingMutex.RLock()
	defer huntingMutex.RUnlock()

	category := c.Query("category")

	templates := make([]*QueryTemplate, 0)
	for _, tpl := range queryTemplates {
		if category != "" && tpl.Category != category {
			continue
		}
		templates = append(templates, tpl)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    templates,
		"total":   len(templates),
	})
}

// Execute query
func (s *APIServer) handleExecuteThreatHuntQuery(c *gin.Context) {
	var query ThreatHuntQuery
	if err := c.ShouldBindJSON(&query); err != nil {
		log.Printf("[ERROR] handleExecuteThreatHuntQuery bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	// Simulate query execution
	results := map[string]interface{}{
		"hits": []map[string]interface{}{
			{
				"timestamp": time.Now().Add(-1 * time.Hour),
				"source_ip": "192.168.1.100",
				"dest_ip":   "10.0.0.50",
				"action":    "rdp_connection",
				"user":      "admin",
			},
		},
		"total": 1,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    results,
		"message": "Query executed successfully",
	})
}

// Get hunting metrics
func (s *APIServer) handleGetThreatHuntMetrics(c *gin.Context) {
	huntingMutex.RLock()
	defer huntingMutex.RUnlock()

	metrics := ThreatHuntMetrics{
		TotalHypotheses:    len(huntingHypotheses),
		ActiveHypotheses:   0,
		ValidatedHypotheses: 0,
		TotalFindings:      len(huntingFindings),
		CriticalFindings:   0,
		ValidationRate:     0,
		AvgTimeToDiscovery: 12.5,
		CoverageScore:      85.0,
		TopHunters:         []HunterPerformance{},
	}

	// Count by status
	for _, hyp := range huntingHypotheses {
		if hyp.Status == "active" {
			metrics.ActiveHypotheses++
		}
		if hyp.Status == "validated" {
			metrics.ValidatedHypotheses++
		}
	}

	// Count critical findings
	for _, finding := range huntingFindings {
		if finding.Severity == "critical" {
			metrics.CriticalFindings++
		}
	}

	// Calculate validation rate
	if metrics.TotalHypotheses > 0 {
		metrics.ValidationRate = (float64(metrics.ValidatedHypotheses) / float64(metrics.TotalHypotheses)) * 100
	}

	// Top hunters performance
	hunterStats := make(map[string]*HunterPerformance)
	for _, hyp := range huntingHypotheses {
		if _, exists := hunterStats[hyp.CreatedBy]; !exists {
			hunterStats[hyp.CreatedBy] = &HunterPerformance{
				HunterID:   hyp.CreatedBy,
				HunterName: hyp.CreatedBy,
			}
		}
		hunterStats[hyp.CreatedBy].HypothesesCount++
		if hyp.Status == "validated" {
			hunterStats[hyp.CreatedBy].FindingsCount++
		}
	}

	// Calculate validation rate per hunter
	for _, hunter := range hunterStats {
		if hunter.HypothesesCount > 0 {
			hunter.ValidationRate = (float64(hunter.FindingsCount) / float64(hunter.HypothesesCount)) * 100
		}
		metrics.TopHunters = append(metrics.TopHunters, *hunter)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    metrics,
	})
}

// List notebooks
func (s *APIServer) handleListThreatHuntNotebooks(c *gin.Context) {
	huntingMutex.RLock()
	defer huntingMutex.RUnlock()

	notebooks := make([]*ThreatHuntNotebook, 0)
	for _, nb := range huntingNotebooks {
		notebooks = append(notebooks, nb)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    notebooks,
		"total":   len(notebooks),
	})
}

// Create notebook
func (s *APIServer) handleCreateThreatHuntNotebook(c *gin.Context) {
	var nb ThreatHuntNotebook
	if err := c.ShouldBindJSON(&nb); err != nil {
		log.Printf("[ERROR] handleCreateThreatHuntNotebook bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	nb.ID = generateID()
	nb.CreatedAt = time.Now()
	nb.UpdatedAt = time.Now()

	huntingMutex.Lock()
	huntingNotebooks[nb.ID] = &nb
	huntingMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    nb,
		"message": "Notebook created successfully",
	})
}

// List scheduled hunts
func (s *APIServer) handleListThreatScheduledHunts(c *gin.Context) {
	huntingMutex.RLock()
	defer huntingMutex.RUnlock()

	hunts := make([]*ScheduledHunt, 0)
	for _, hunt := range scheduledHunts {
		hunts = append(hunts, hunt)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    hunts,
		"total":   len(hunts),
	})
}

// Create scheduled hunt
func (s *APIServer) handleCreateThreatScheduledHunt(c *gin.Context) {
	var hunt ScheduledHunt
	if err := c.ShouldBindJSON(&hunt); err != nil {
		log.Printf("[ERROR] handleCreateThreatScheduledHunt bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	hunt.ID = generateID()
	hunt.CreatedAt = time.Now()
	hunt.Enabled = true

	huntingMutex.Lock()
	scheduledHunts[hunt.ID] = &hunt
	huntingMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    hunt,
		"message": "Scheduled hunt created successfully",
	})
}

// ============================================================================
// HUNTING HISTORY / ACTIVITIES
// ============================================================================

// Initialize sample hunting activities
func initHuntingActivities() {
	now := time.Now()
	
	activities := []*HuntingActivity{
		// Recent activities (last 7 days)
		{
			ID:          "act-001",
			Type:        "finding_created",
			HunterID:    "hunter-1",
			HunterName:  "hunter-1",
			Title:       "Critical Finding: Lateral Movement Detected",
			Description: "Confirmed RDP lateral movement from workstation to production servers",
			EntityID:    "find-001",
			EntityType:  "finding",
			Severity:    "critical",
			Status:      "confirmed",
			Metadata:    map[string]interface{}{"affected_hosts": 5, "technique": "T1021.001"},
			Timestamp:   now.Add(-2 * time.Hour),
		},
		{
			ID:          "act-002",
			Type:        "query_executed",
			HunterID:    "hunter-2",
			HunterName:  "hunter-2",
			Title:       "Query Executed: Token Manipulation Detection",
			Description: "Executed query to detect token manipulation attempts",
			EntityID:    "query-002",
			EntityType:  "query",
			Metadata:    map[string]interface{}{"results_count": 15, "execution_time": "2.3s"},
			Timestamp:   now.Add(-5 * time.Hour),
		},
		{
			ID:          "act-003",
			Type:        "hypothesis_validated",
			HunterID:    "hunter-2",
			HunterName:  "hunter-2",
			Title:       "Hypothesis Validated: Token Manipulation",
			Description: "Hypothesis validated with 3 confirmed findings",
			EntityID:    "hyp-002",
			EntityType:  "hypothesis",
			Status:      "validated",
			Metadata:    map[string]interface{}{"findings_count": 3, "confidence": "high"},
			Timestamp:   now.Add(-8 * time.Hour),
		},
		{
			ID:          "act-004",
			Type:        "hypothesis_created",
			HunterID:    "hunter-3",
			HunterName:  "hunter-3",
			Title:       "New Hypothesis: PowerShell Abuse",
			Description: "Created hypothesis to detect suspicious PowerShell execution patterns",
			EntityID:    "hyp-004",
			EntityType:  "hypothesis",
			Status:      "active",
			Metadata:    map[string]interface{}{"priority": "high", "mitre_tactics": []string{"TA0002", "TA0005"}},
			Timestamp:   now.Add(-12 * time.Hour),
		},
		{
			ID:          "act-005",
			Type:        "finding_created",
			HunterID:    "hunter-2",
			HunterName:  "hunter-2",
			Title:       "High Finding: Privilege Escalation Attempt",
			Description: "Detected token manipulation on DC01",
			EntityID:    "find-002",
			EntityType:  "finding",
			Severity:    "critical",
			Status:      "investigating",
			Metadata:    map[string]interface{}{"host": "DC01", "technique": "T1134"},
			Timestamp:   now.Add(-18 * time.Hour),
		},
		{
			ID:          "act-006",
			Type:        "query_executed",
			HunterID:    "hunter-1",
			HunterName:  "hunter-1",
			Title:       "Query Executed: DNS Tunneling Detection",
			Description: "Executed query to identify abnormal DNS queries",
			EntityID:    "query-003",
			EntityType:  "query",
			Metadata:    map[string]interface{}{"results_count": 42, "execution_time": "5.1s"},
			Timestamp:   now.Add(-24 * time.Hour),
		},
		{
			ID:          "act-007",
			Type:        "hypothesis_created",
			HunterID:    "hunter-1",
			HunterName:  "hunter-1",
			Title:       "New Hypothesis: DNS Tunneling",
			Description: "Created hypothesis to detect data exfiltration via DNS",
			EntityID:    "hyp-003",
			EntityType:  "hypothesis",
			Status:      "active",
			Metadata:    map[string]interface{}{"priority": "critical", "mitre_tactics": []string{"TA0010"}},
			Timestamp:   now.Add(-30 * time.Hour),
		},
		
		// Older activities (7-30 days)
		{
			ID:          "act-008",
			Type:        "finding_created",
			HunterID:    "hunter-1",
			HunterName:  "hunter-1",
			Title:       "Critical Finding: Web Shell Detected",
			Description: "Confirmed web shell on IIS server",
			EntityID:    "find-003",
			EntityType:  "finding",
			Severity:    "critical",
			Status:      "confirmed",
			Metadata:    map[string]interface{}{"server": "WEB-01", "technique": "T1505.003"},
			Timestamp:   now.Add(-3 * 24 * time.Hour),
		},
		{
			ID:          "act-009",
			Type:        "hypothesis_validated",
			HunterID:    "hunter-2",
			HunterName:  "hunter-2",
			Title:       "Hypothesis Validated: Registry Persistence",
			Description: "Hypothesis validated with 2 confirmed findings",
			EntityID:    "hyp-005",
			EntityType:  "hypothesis",
			Status:      "validated",
			Metadata:    map[string]interface{}{"findings_count": 2, "confidence": "high"},
			Timestamp:   now.Add(-7 * 24 * time.Hour),
		},
		{
			ID:          "act-010",
			Type:        "query_executed",
			HunterID:    "hunter-3",
			HunterName:  "hunter-3",
			Title:       "Query Executed: LSASS Access Detection",
			Description: "Executed query to detect LSASS memory access attempts",
			EntityID:    "query-006",
			EntityType:  "query",
			Metadata:    map[string]interface{}{"results_count": 8, "execution_time": "1.7s"},
			Timestamp:   now.Add(-10 * 24 * time.Hour),
		},
		{
			ID:          "act-011",
			Type:        "hypothesis_created",
			HunterID:    "hunter-1",
			HunterName:  "hunter-1",
			Title:       "New Hypothesis: Lateral Movement via RDP",
			Description: "Created hypothesis to detect RDP lateral movement",
			EntityID:    "hyp-001",
			EntityType:  "hypothesis",
			Status:      "active",
			Metadata:    map[string]interface{}{"priority": "high", "mitre_tactics": []string{"TA0008"}},
			Timestamp:   now.Add(-14 * 24 * time.Hour),
		},
		{
			ID:          "act-012",
			Type:        "hypothesis_created",
			HunterID:    "hunter-2",
			HunterName:  "hunter-2",
			Title:       "New Hypothesis: Token Manipulation",
			Description: "Created hypothesis to hunt for token manipulation techniques",
			EntityID:    "hyp-002",
			EntityType:  "hypothesis",
			Status:      "active",
			Metadata:    map[string]interface{}{"priority": "critical", "mitre_tactics": []string{"TA0004"}},
			Timestamp:   now.Add(-21 * 24 * time.Hour),
		},
		{
			ID:          "act-013",
			Type:        "finding_created",
			HunterID:    "hunter-1",
			HunterName:  "hunter-1",
			Title:       "High Finding: Golden Ticket Detected",
			Description: "Detected forged Kerberos ticket usage",
			EntityID:    "find-004",
			EntityType:  "finding",
			Severity:    "high",
			Status:      "confirmed",
			Metadata:    map[string]interface{}{"domain": "CORP", "technique": "T1558.001"},
			Timestamp:   now.Add(-25 * 24 * time.Hour),
		},
		{
			ID:          "act-014",
			Type:        "query_executed",
			HunterID:    "hunter-2",
			HunterName:  "hunter-2",
			Title:       "Query Executed: Registry Run Keys",
			Description: "Executed query to detect unauthorized registry modifications",
			EntityID:    "query-005",
			EntityType:  "query",
			Metadata:    map[string]interface{}{"results_count": 23, "execution_time": "3.2s"},
			Timestamp:   now.Add(-28 * 24 * time.Hour),
		},
		{
			ID:          "act-015",
			Type:        "hypothesis_created",
			HunterID:    "hunter-2",
			HunterName:  "hunter-2",
			Title:       "New Hypothesis: Registry Persistence",
			Description: "Created hypothesis to hunt for registry run key modifications",
			EntityID:    "hyp-005",
			EntityType:  "hypothesis",
			Status:      "active",
			Metadata:    map[string]interface{}{"priority": "medium", "mitre_tactics": []string{"TA0003"}},
			Timestamp:   now.Add(-30 * 24 * time.Hour),
		},
	}
	
	huntingActivities = activities
}

// Get hunting activities with filters
func (s *APIServer) handleGetHuntingActivities(c *gin.Context) {
	huntingMutex.RLock()
	defer huntingMutex.RUnlock()

	// Query parameters
	hunterID := c.Query("hunter_id")
	activityType := c.Query("type")
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")
	limit := 100 // Default limit

	if limitParam := c.Query("limit"); limitParam != "" {
		if parsedLimit, err := time.ParseDuration(limitParam); err == nil {
			limit = int(parsedLimit)
		}
	}

	// Filter activities
	filteredActivities := make([]*HuntingActivity, 0)
	for _, activity := range huntingActivities {
		// Filter by hunter
		if hunterID != "" && activity.HunterID != hunterID {
			continue
		}

		// Filter by type
		if activityType != "" && activity.Type != activityType {
			continue
		}

		// Filter by date range
		if startDate != "" {
			if start, err := time.Parse(time.RFC3339, startDate); err == nil {
				if activity.Timestamp.Before(start) {
					continue
				}
			}
		}
		if endDate != "" {
			if end, err := time.Parse(time.RFC3339, endDate); err == nil {
				if activity.Timestamp.After(end) {
					continue
				}
			}
		}

		filteredActivities = append(filteredActivities, activity)
	}

	// Sort by timestamp (most recent first)
	// Already sorted in initialization, but ensure it
	for i := 0; i < len(filteredActivities)-1; i++ {
		for j := i + 1; j < len(filteredActivities); j++ {
			if filteredActivities[i].Timestamp.Before(filteredActivities[j].Timestamp) {
				filteredActivities[i], filteredActivities[j] = filteredActivities[j], filteredActivities[i]
			}
		}
	}

	// Apply limit
	if len(filteredActivities) > limit {
		filteredActivities = filteredActivities[:limit]
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    filteredActivities,
		"total":   len(filteredActivities),
	})
}

// Get activity statistics
func (s *APIServer) handleGetActivityStatistics(c *gin.Context) {
	huntingMutex.RLock()
	defer huntingMutex.RUnlock()

	now := time.Now()
	last24h := now.Add(-24 * time.Hour)
	last7d := now.Add(-7 * 24 * time.Hour)
	last30d := now.Add(-30 * 24 * time.Hour)

	stats := map[string]interface{}{
		"total_activities": len(huntingActivities),
		"last_24h":         0,
		"last_7d":          0,
		"last_30d":         0,
		"by_type":          make(map[string]int),
		"by_hunter":        make(map[string]int),
		"by_severity":      make(map[string]int),
	}

	byType := make(map[string]int)
	byHunter := make(map[string]int)
	bySeverity := make(map[string]int)

	for _, activity := range huntingActivities {
		// Count by time period
		if activity.Timestamp.After(last24h) {
			stats["last_24h"] = stats["last_24h"].(int) + 1
		}
		if activity.Timestamp.After(last7d) {
			stats["last_7d"] = stats["last_7d"].(int) + 1
		}
		if activity.Timestamp.After(last30d) {
			stats["last_30d"] = stats["last_30d"].(int) + 1
		}

		// Count by type
		byType[activity.Type]++

		// Count by hunter
		byHunter[activity.HunterID]++

		// Count by severity (if applicable)
		if activity.Severity != "" {
			bySeverity[activity.Severity]++
		}
	}

	stats["by_type"] = byType
	stats["by_hunter"] = byHunter
	stats["by_severity"] = bySeverity

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}
