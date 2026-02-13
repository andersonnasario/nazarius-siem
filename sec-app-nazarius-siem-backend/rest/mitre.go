package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// MITRETactic representa uma tática do MITRE ATT&CK
type MITRETactic struct {
	ID          string `json:"id"`          // TA0001
	Name        string `json:"name"`        // Initial Access
	Description string `json:"description"`
	URL         string `json:"url"`
	Order       int    `json:"order"`
}

// MITRETechnique representa uma técnica do MITRE ATT&CK
type MITRETechnique struct {
	ID           string   `json:"id"`           // T1190
	Name         string   `json:"name"`         // Exploit Public-Facing Application
	Description  string   `json:"description"`
	TacticIDs    []string `json:"tacticIds"`    // [TA0001]
	Platforms    []string `json:"platforms"`    // [Windows, Linux, macOS]
	DataSources  []string `json:"dataSources"`
	Mitigations  []string `json:"mitigations"`
	URL          string   `json:"url"`
	DetectionCoverage string `json:"detectionCoverage"` // none, low, medium, high
	EventCount   int      `json:"eventCount"`
	LastDetected *time.Time `json:"lastDetected,omitempty"`
}

// MITREDetection representa uma detecção mapeada para técnica
type MITREDetection struct {
	ID           string    `json:"id"`
	TechniqueID  string    `json:"techniqueId"`
	TechniqueName string   `json:"techniqueName"`
	EventID      string    `json:"eventId"`
	AlertID      string    `json:"alertId,omitempty"`
	CaseID       string    `json:"caseId,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	Severity     string    `json:"severity"`
	Source       string    `json:"source"`
	Description  string    `json:"description"`
	Confidence   float64   `json:"confidence"` // 0-100
}

// MITRECoverage representa análise de cobertura
type MITRECoverage struct {
	TotalTactics          int                    `json:"totalTactics"`
	CoveredTactics        int                    `json:"coveredTactics"`
	TotalTechniques       int                    `json:"totalTechniques"`
	CoveredTechniques     int                    `json:"coveredTechniques"`
	CoveragePercentage    float64                `json:"coveragePercentage"`
	TacticsCoverage       map[string]TacticCoverage `json:"tacticsCoverage"`
	CriticalGaps          []MITRETechnique       `json:"criticalGaps"`
	RecentDetections      int                    `json:"recentDetections"`
	TopTechniques         []TechniqueActivity    `json:"topTechniques"`
}

// TacticCoverage representa cobertura por tática
type TacticCoverage struct {
	TacticID           string  `json:"tacticId"`
	TacticName         string  `json:"tacticName"`
	TotalTechniques    int     `json:"totalTechniques"`
	CoveredTechniques  int     `json:"coveredTechniques"`
	CoveragePercentage float64 `json:"coveragePercentage"`
}

// TechniqueActivity representa atividade de uma técnica
type TechniqueActivity struct {
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	EventCount    int    `json:"eventCount"`
	Severity      string `json:"severity"`
	TacticID      string `json:"tacticId"`
}

// MITRETimeline representa timeline de ataque
type MITRETimelineEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	TacticID      string    `json:"tacticId"`
	TacticName    string    `json:"tacticName"`
	TechniqueID   string    `json:"techniqueId"`
	TechniqueName string    `json:"techniqueName"`
	EventCount    int       `json:"eventCount"`
	Severity      string    `json:"severity"`
}

// handleGetMITRETactics retorna todas as táticas
func (s *APIServer) handleGetMITRETactics(c *gin.Context) {
	tactics := []MITRETactic{
		{ID: "TA0043", Name: "Reconnaissance", Description: "Gathering information to plan future adversary operations", URL: "https://attack.mitre.org/tactics/TA0043", Order: 1},
		{ID: "TA0042", Name: "Resource Development", Description: "Establishing resources to support operations", URL: "https://attack.mitre.org/tactics/TA0042", Order: 2},
		{ID: "TA0001", Name: "Initial Access", Description: "Trying to get into your network", URL: "https://attack.mitre.org/tactics/TA0001", Order: 3},
		{ID: "TA0002", Name: "Execution", Description: "Trying to run malicious code", URL: "https://attack.mitre.org/tactics/TA0002", Order: 4},
		{ID: "TA0003", Name: "Persistence", Description: "Trying to maintain their foothold", URL: "https://attack.mitre.org/tactics/TA0003", Order: 5},
		{ID: "TA0004", Name: "Privilege Escalation", Description: "Trying to gain higher-level permissions", URL: "https://attack.mitre.org/tactics/TA0004", Order: 6},
		{ID: "TA0005", Name: "Defense Evasion", Description: "Trying to avoid being detected", URL: "https://attack.mitre.org/tactics/TA0005", Order: 7},
		{ID: "TA0006", Name: "Credential Access", Description: "Stealing accounts names and passwords", URL: "https://attack.mitre.org/tactics/TA0006", Order: 8},
		{ID: "TA0007", Name: "Discovery", Description: "Trying to figure out your environment", URL: "https://attack.mitre.org/tactics/TA0007", Order: 9},
		{ID: "TA0008", Name: "Lateral Movement", Description: "Moving through your environment", URL: "https://attack.mitre.org/tactics/TA0008", Order: 10},
		{ID: "TA0009", Name: "Collection", Description: "Gathering data of interest", URL: "https://attack.mitre.org/tactics/TA0009", Order: 11},
		{ID: "TA0011", Name: "Command and Control", Description: "Communicating with compromised systems", URL: "https://attack.mitre.org/tactics/TA0011", Order: 12},
		{ID: "TA0010", Name: "Exfiltration", Description: "Stealing data", URL: "https://attack.mitre.org/tactics/TA0010", Order: 13},
		{ID: "TA0040", Name: "Impact", Description: "Manipulate, interrupt, or destroy systems and data", URL: "https://attack.mitre.org/tactics/TA0040", Order: 14},
	}

	c.JSON(http.StatusOK, gin.H{
		"tactics": tactics,
		"total":   len(tactics),
	})
}

// handleGetMITRETechniques retorna técnicas (com filtros)
func (s *APIServer) handleGetMITRETechniques(c *gin.Context) {
	tacticID := c.Query("tactic_id")
	coverage := c.Query("coverage")

	// Técnicas de exemplo (subset das mais importantes)
	techniques := []MITRETechnique{
		// Initial Access
		{ID: "T1190", Name: "Exploit Public-Facing Application", Description: "Adversaries may attempt to exploit weakness in an Internet-facing host", TacticIDs: []string{"TA0001"}, Platforms: []string{"Windows", "Linux", "macOS"}, DetectionCoverage: "high", EventCount: 45, LastDetected: timePtr(time.Now().Add(-2 * time.Hour))},
		{ID: "T1133", Name: "External Remote Services", Description: "Adversaries may leverage external remote services", TacticIDs: []string{"TA0001", "TA0003"}, Platforms: []string{"Windows", "Linux"}, DetectionCoverage: "high", EventCount: 89, LastDetected: timePtr(time.Now().Add(-1 * time.Hour))},
		{ID: "T1078", Name: "Valid Accounts", Description: "Adversaries may obtain and abuse credentials", TacticIDs: []string{"TA0001", "TA0003", "TA0004", "TA0005"}, Platforms: []string{"Windows", "Linux", "macOS"}, DetectionCoverage: "high", EventCount: 347, LastDetected: timePtr(time.Now().Add(-15 * time.Minute))},
		
		// Execution
		{ID: "T1059", Name: "Command and Scripting Interpreter", Description: "Adversaries may abuse command interpreters", TacticIDs: []string{"TA0002"}, Platforms: []string{"Windows", "Linux", "macOS"}, DetectionCoverage: "high", EventCount: 189, LastDetected: timePtr(time.Now().Add(-30 * time.Minute))},
		{ID: "T1203", Name: "Exploitation for Client Execution", Description: "Adversaries may exploit software vulnerabilities", TacticIDs: []string{"TA0002"}, Platforms: []string{"Windows", "Linux", "macOS"}, DetectionCoverage: "medium", EventCount: 12, LastDetected: timePtr(time.Now().Add(-5 * time.Hour))},
		
		// Persistence
		{ID: "T1053", Name: "Scheduled Task/Job", Description: "Adversaries may abuse task scheduling", TacticIDs: []string{"TA0003", "TA0004", "TA0002"}, Platforms: []string{"Windows", "Linux", "macOS"}, DetectionCoverage: "high", EventCount: 67, LastDetected: timePtr(time.Now().Add(-3 * time.Hour))},
		{ID: "T1543", Name: "Create or Modify System Process", Description: "Adversaries may create or modify system-level processes", TacticIDs: []string{"TA0003", "TA0004"}, Platforms: []string{"Windows", "Linux"}, DetectionCoverage: "medium", EventCount: 34, LastDetected: timePtr(time.Now().Add(-6 * time.Hour))},
		
		// Privilege Escalation
		{ID: "T1068", Name: "Exploitation for Privilege Escalation", Description: "Adversaries may exploit software vulnerabilities", TacticIDs: []string{"TA0004"}, Platforms: []string{"Windows", "Linux"}, DetectionCoverage: "low", EventCount: 8, LastDetected: timePtr(time.Now().Add(-12 * time.Hour))},
		{ID: "T1055", Name: "Process Injection", Description: "Adversaries may inject code into processes", TacticIDs: []string{"TA0004", "TA0005"}, Platforms: []string{"Windows", "Linux"}, DetectionCoverage: "medium", EventCount: 23, LastDetected: timePtr(time.Now().Add(-8 * time.Hour))},
		
		// Credential Access
		{ID: "T1110", Name: "Brute Force", Description: "Adversaries may use brute force techniques", TacticIDs: []string{"TA0006"}, Platforms: []string{"Windows", "Linux", "macOS"}, DetectionCoverage: "high", EventCount: 234, LastDetected: timePtr(time.Now().Add(-10 * time.Minute))},
		{ID: "T1003", Name: "OS Credential Dumping", Description: "Adversaries may attempt to dump credentials", TacticIDs: []string{"TA0006"}, Platforms: []string{"Windows", "Linux"}, DetectionCoverage: "medium", EventCount: 15, LastDetected: timePtr(time.Now().Add(-4 * time.Hour))},
		
		// Lateral Movement
		{ID: "T1021", Name: "Remote Services", Description: "Adversaries may use valid accounts to log into a service", TacticIDs: []string{"TA0008"}, Platforms: []string{"Windows", "Linux"}, DetectionCoverage: "high", EventCount: 78, LastDetected: timePtr(time.Now().Add(-2 * time.Hour))},
		{ID: "T1210", Name: "Exploitation of Remote Services", Description: "Adversaries may exploit remote services", TacticIDs: []string{"TA0008"}, Platforms: []string{"Windows", "Linux"}, DetectionCoverage: "medium", EventCount: 5, LastDetected: timePtr(time.Now().Add(-18 * time.Hour))},
		
		// Impact
		{ID: "T1486", Name: "Data Encrypted for Impact", Description: "Adversaries may encrypt data to impact availability", TacticIDs: []string{"TA0040"}, Platforms: []string{"Windows", "Linux", "macOS"}, DetectionCoverage: "high", EventCount: 7, LastDetected: timePtr(time.Now().Add(-24 * time.Hour))},
		{ID: "T1490", Name: "Inhibit System Recovery", Description: "Adversaries may delete or remove built-in data", TacticIDs: []string{"TA0040"}, Platforms: []string{"Windows", "Linux"}, DetectionCoverage: "medium", EventCount: 3, LastDetected: timePtr(time.Now().Add(-30 * time.Hour))},
		
		// Técnicas sem detecção (gaps)
		{ID: "T1027", Name: "Obfuscated Files or Information", Description: "Adversaries may obfuscate command and control traffic", TacticIDs: []string{"TA0005"}, Platforms: []string{"Windows", "Linux", "macOS"}, DetectionCoverage: "none", EventCount: 0},
		{ID: "T1070", Name: "Indicator Removal", Description: "Adversaries may delete or modify artifacts", TacticIDs: []string{"TA0005"}, Platforms: []string{"Windows", "Linux", "macOS"}, DetectionCoverage: "none", EventCount: 0},
	}

	// Aplicar filtros
	var filteredTechniques []MITRETechnique
	for _, tech := range techniques {
		if tacticID != "" {
			found := false
			for _, tid := range tech.TacticIDs {
				if tid == tacticID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		if coverage != "" && tech.DetectionCoverage != coverage {
			continue
		}
		
		filteredTechniques = append(filteredTechniques, tech)
	}

	c.JSON(http.StatusOK, gin.H{
		"techniques": filteredTechniques,
		"total":      len(filteredTechniques),
	})
}

// handleGetMITRECoverage retorna análise de cobertura
func (s *APIServer) handleGetMITRECoverage(c *gin.Context) {
	coverage := MITRECoverage{
		TotalTactics:       14,
		CoveredTactics:     14,
		TotalTechniques:    180,
		CoveredTechniques:  127,
		CoveragePercentage: 70.5,
		TacticsCoverage: map[string]TacticCoverage{
			"TA0001": {TacticID: "TA0001", TacticName: "Initial Access", TotalTechniques: 9, CoveredTechniques: 7, CoveragePercentage: 77.8},
			"TA0002": {TacticID: "TA0002", TacticName: "Execution", TotalTechniques: 12, CoveredTechniques: 10, CoveragePercentage: 83.3},
			"TA0003": {TacticID: "TA0003", TacticName: "Persistence", TotalTechniques: 19, CoveredTechniques: 14, CoveragePercentage: 73.7},
			"TA0004": {TacticID: "TA0004", TacticName: "Privilege Escalation", TotalTechniques: 13, CoveredTechniques: 8, CoveragePercentage: 61.5},
			"TA0005": {TacticID: "TA0005", TacticName: "Defense Evasion", TotalTechniques: 42, CoveredTechniques: 25, CoveragePercentage: 59.5},
			"TA0006": {TacticID: "TA0006", TacticName: "Credential Access", TotalTechniques: 15, CoveredTechniques: 11, CoveragePercentage: 73.3},
			"TA0007": {TacticID: "TA0007", TacticName: "Discovery", TotalTechniques: 30, CoveredTechniques: 22, CoveragePercentage: 73.3},
			"TA0008": {TacticID: "TA0008", TacticName: "Lateral Movement", TotalTechniques: 9, CoveredTechniques: 7, CoveragePercentage: 77.8},
			"TA0009": {TacticID: "TA0009", TacticName: "Collection", TotalTechniques: 17, CoveredTechniques: 12, CoveragePercentage: 70.6},
			"TA0011": {TacticID: "TA0011", TacticName: "Command and Control", TotalTechniques: 16, CoveredTechniques: 11, CoveragePercentage: 68.8},
		},
		RecentDetections: 1247,
		TopTechniques: []TechniqueActivity{
			{TechniqueID: "T1078", TechniqueName: "Valid Accounts", EventCount: 347, Severity: "high", TacticID: "TA0001"},
			{TechniqueID: "T1110", TechniqueName: "Brute Force", EventCount: 234, Severity: "high", TacticID: "TA0006"},
			{TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter", EventCount: 189, Severity: "medium", TacticID: "TA0002"},
			{TechniqueID: "T1133", TechniqueName: "External Remote Services", EventCount: 89, Severity: "medium", TacticID: "TA0001"},
			{TechniqueID: "T1021", TechniqueName: "Remote Services", EventCount: 78, Severity: "medium", TacticID: "TA0008"},
		},
		CriticalGaps: []MITRETechnique{
			{ID: "T1027", Name: "Obfuscated Files or Information", TacticIDs: []string{"TA0005"}, DetectionCoverage: "none"},
			{ID: "T1070", Name: "Indicator Removal", TacticIDs: []string{"TA0005"}, DetectionCoverage: "none"},
			{ID: "T1068", Name: "Exploitation for Privilege Escalation", TacticIDs: []string{"TA0004"}, DetectionCoverage: "low"},
		},
	}

	c.JSON(http.StatusOK, coverage)
}

// handleGetMITRETimeline retorna timeline de ataques
func (s *APIServer) handleGetMITRETimeline(c *gin.Context) {
	hours := c.DefaultQuery("hours", "24")
	
	timeline := []MITRETimelineEntry{
		{Timestamp: time.Now().Add(-23 * time.Hour), TacticID: "TA0043", TacticName: "Reconnaissance", TechniqueID: "T1595", TechniqueName: "Active Scanning", EventCount: 12, Severity: "low"},
		{Timestamp: time.Now().Add(-22 * time.Hour), TacticID: "TA0001", TacticName: "Initial Access", TechniqueID: "T1190", TechniqueName: "Exploit Public-Facing Application", EventCount: 3, Severity: "high"},
		{Timestamp: time.Now().Add(-21 * time.Hour), TacticID: "TA0002", TacticName: "Execution", TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter", EventCount: 8, Severity: "high"},
		{Timestamp: time.Now().Add(-20 * time.Hour), TacticID: "TA0003", TacticName: "Persistence", TechniqueID: "T1053", TechniqueName: "Scheduled Task/Job", EventCount: 5, Severity: "medium"},
		{Timestamp: time.Now().Add(-18 * time.Hour), TacticID: "TA0004", TacticName: "Privilege Escalation", TechniqueID: "T1055", TechniqueName: "Process Injection", EventCount: 2, Severity: "high"},
		{Timestamp: time.Now().Add(-15 * time.Hour), TacticID: "TA0007", TacticName: "Discovery", TechniqueID: "T1083", TechniqueName: "File and Directory Discovery", EventCount: 45, Severity: "medium"},
		{Timestamp: time.Now().Add(-12 * time.Hour), TacticID: "TA0008", TacticName: "Lateral Movement", TechniqueID: "T1021", TechniqueName: "Remote Services", EventCount: 7, Severity: "high"},
		{Timestamp: time.Now().Add(-8 * time.Hour), TacticID: "TA0009", TacticName: "Collection", TechniqueID: "T1560", TechniqueName: "Archive Collected Data", EventCount: 3, Severity: "medium"},
		{Timestamp: time.Now().Add(-4 * time.Hour), TacticID: "TA0010", TacticName: "Exfiltration", TechniqueID: "T1041", TechniqueName: "Exfiltration Over C2 Channel", EventCount: 2, Severity: "critical"},
	}

	c.JSON(http.StatusOK, gin.H{
		"timeline": timeline,
		"total":    len(timeline),
		"hours":    hours,
	})
}

// handleGetMITREDetections retorna detecções recentes
func (s *APIServer) handleGetMITREDetections(c *gin.Context) {
	techniqueID := c.Query("technique_id")
	limit := c.DefaultQuery("limit", "50")

	detections := []MITREDetection{
		{ID: "det-001", TechniqueID: "T1078", TechniqueName: "Valid Accounts", EventID: "evt-12345", Timestamp: time.Now().Add(-15 * time.Minute), Severity: "high", Source: "Active Directory", Description: "Multiple successful logins from unusual location", Confidence: 85.5},
		{ID: "det-002", TechniqueID: "T1110", TechniqueName: "Brute Force", EventID: "evt-12346", AlertID: "alert-001", CaseID: "case-001", Timestamp: time.Now().Add(-30 * time.Minute), Severity: "high", Source: "SSH Server", Description: "247 failed login attempts detected", Confidence: 95.0},
		{ID: "det-003", TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter", EventID: "evt-12347", Timestamp: time.Now().Add(-45 * time.Minute), Severity: "medium", Source: "EDR", Description: "PowerShell execution with suspicious parameters", Confidence: 78.0},
	}

	// Filtrar por technique_id se fornecido
	if techniqueID != "" {
		var filtered []MITREDetection
		for _, det := range detections {
			if det.TechniqueID == techniqueID {
				filtered = append(filtered, det)
			}
		}
		detections = filtered
	}

	c.JSON(http.StatusOK, gin.H{
		"detections": detections,
		"total":      len(detections),
		"limit":      limit,
	})
}

