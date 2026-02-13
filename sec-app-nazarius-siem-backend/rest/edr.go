package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// EDR Agent represents an endpoint agent
type EDRAgent struct {
	ID              string    `json:"id"`
	Hostname        string    `json:"hostname"`
	IPAddress       string    `json:"ip_address"`
	OS              string    `json:"os"` // windows, linux, macos
	OSVersion       string    `json:"os_version"`
	AgentVersion    string    `json:"agent_version"`
	Status          string    `json:"status"` // online, offline, isolated, updating
	LastSeen        time.Time `json:"last_seen"`
	InstallDate     time.Time `json:"install_date"`
	CPUUsage        float64   `json:"cpu_usage"`
	MemoryUsage     float64   `json:"memory_usage"`
	DiskUsage       float64   `json:"disk_usage"`
	ThreatCount     int       `json:"threat_count"`
	QuarantineCount int       `json:"quarantine_count"`
	Tags            []string  `json:"tags"`
}

// Endpoint represents a monitored endpoint
type Endpoint struct {
	ID               string    `json:"id"`
	AgentID          string    `json:"agent_id"`
	Hostname         string    `json:"hostname"`
	IPAddress        string    `json:"ip_address"`
	MACAddress       string    `json:"mac_address"`
	OS               string    `json:"os"`
	Domain           string    `json:"domain"`
	Users            []string  `json:"users"`
	RunningProcesses int       `json:"running_processes"`
	OpenPorts        []int     `json:"open_ports"`
	InstalledSoftware int      `json:"installed_software"`
	LastScan         time.Time `json:"last_scan"`
	RiskScore        int       `json:"risk_score"` // 0-100
	Compliance       bool      `json:"compliance"`
	Isolated         bool      `json:"isolated"`
}

// EDRThreat represents a detected threat
type EDRThreat struct {
	ID               string    `json:"id"`
	AgentID          string    `json:"agent_id"`
	Hostname         string    `json:"hostname"`
	Type             string    `json:"type"` // malware, ransomware, trojan, rootkit, exploit, suspicious_behavior
	Name             string    `json:"name"`
	Severity         string    `json:"severity"` // critical, high, medium, low
	Status           string    `json:"status"` // detected, quarantined, removed, whitelisted
	FilePath         string    `json:"file_path"`
	FileHash         string    `json:"file_hash"` // SHA-256
	ProcessName      string    `json:"process_name"`
	ProcessID        int       `json:"process_id"`
	CommandLine      string    `json:"command_line"`
	ParentProcess    string    `json:"parent_process"`
	DetectionMethod  string    `json:"detection_method"` // signature, behavior, ml, heuristic
	MITRETactics     []string  `json:"mitre_tactics"`
	MITRETechniques  []string  `json:"mitre_techniques"`
	DetectedAt       time.Time `json:"detected_at"`
	QuarantinedAt    *time.Time `json:"quarantined_at,omitempty"`
	RemovedAt        *time.Time `json:"removed_at,omitempty"`
	ActionTaken      string    `json:"action_taken"` // quarantine, terminate, block, alert
	ThreatScore      int       `json:"threat_score"` // 0-100
}

// Process represents a running process
type Process struct {
	ID              string    `json:"id"`
	AgentID         string    `json:"agent_id"`
	Hostname        string    `json:"hostname"`
	Name            string    `json:"name"`
	PID             int       `json:"pid"`
	ParentPID       int       `json:"parent_pid"`
	ParentName      string    `json:"parent_name"`
	CommandLine     string    `json:"command_line"`
	Path            string    `json:"path"`
	Hash            string    `json:"hash"` // SHA-256
	User            string    `json:"user"`
	CPUUsage        float64   `json:"cpu_usage"`
	MemoryUsage     int64     `json:"memory_usage"` // bytes
	StartTime       time.Time `json:"start_time"`
	Connections     int       `json:"connections"`
	FileOperations  int       `json:"file_operations"`
	RegistryChanges int       `json:"registry_changes"`
	Suspicious      bool      `json:"suspicious"`
	ThreatScore     int       `json:"threat_score"` // 0-100
	Signature       string    `json:"signature"`
}

// MemoryScan represents a memory scan result
type MemoryScan struct {
	ID               string    `json:"id"`
	AgentID          string    `json:"agent_id"`
	Hostname         string    `json:"hostname"`
	ScanType         string    `json:"scan_type"` // full, quick, targeted
	Status           string    `json:"status"` // running, completed, failed
	StartTime        time.Time `json:"start_time"`
	EndTime          *time.Time `json:"end_time,omitempty"`
	Duration         int       `json:"duration"` // seconds
	ProcessesScanned int       `json:"processes_scanned"`
	ThreatsFound     int       `json:"threats_found"`
	SuspiciousItems  int       `json:"suspicious_items"`
	InjectedCode     int       `json:"injected_code"`
	HiddenProcesses  int       `json:"hidden_processes"`
	Findings         []string  `json:"findings"`
}

// ForensicData represents forensic collection
type ForensicData struct {
	ID           string    `json:"id"`
	AgentID      string    `json:"agent_id"`
	Hostname     string    `json:"hostname"`
	Type         string    `json:"type"` // memory_dump, disk_image, process_dump, registry_snapshot, event_logs
	Status       string    `json:"status"` // collecting, collected, uploaded, failed
	StartTime    time.Time `json:"start_time"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	Size         int64     `json:"size"` // bytes
	Location     string    `json:"location"`
	Hash         string    `json:"hash"` // SHA-256
	IncidentID   string    `json:"incident_id,omitempty"`
	CollectedBy  string    `json:"collected_by"`
	Notes        string    `json:"notes"`
}

// IsolationAction represents endpoint isolation
type IsolationAction struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname"`
	Action    string    `json:"action"` // isolate, restore
	Reason    string    `json:"reason"`
	Status    string    `json:"status"` // pending, completed, failed
	InitiatedBy string  `json:"initiated_by"`
	InitiatedAt time.Time `json:"initiated_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Notes       string    `json:"notes"`
}

// EDRDashboard represents dashboard metrics
type EDRDashboard struct {
	Overview        EDROverview        `json:"overview"`
	ThreatTrend     []ThreatTrendPoint `json:"threat_trend"`
	TopThreats      []ThreatStats      `json:"top_threats"`
	EndpointHealth  []EndpointHealth   `json:"endpoint_health"`
	OSDistribution  []OSStats          `json:"os_distribution"`
	RecentThreats   []EDRThreat        `json:"recent_threats"`
	CriticalAgents  []EDRAgent         `json:"critical_agents"`
}

// EDROverview represents overview metrics
type EDROverview struct {
	TotalAgents       int     `json:"total_agents"`
	OnlineAgents      int     `json:"online_agents"`
	IsolatedAgents    int     `json:"isolated_agents"`
	ThreatsDetected   int     `json:"threats_detected"`
	ThreatsQuarantined int    `json:"threats_quarantined"`
	ThreatsRemoved    int     `json:"threats_removed"`
	AvgResponseTime   int     `json:"avg_response_time"` // seconds
	ComplianceRate    float64 `json:"compliance_rate"`
}

// ThreatTrendPoint represents a point in threat trend
type ThreatTrendPoint struct {
	Date       string `json:"date"`
	Detected   int    `json:"detected"`
	Quarantined int   `json:"quarantined"`
	Removed    int    `json:"removed"`
}

// ThreatStats represents threat statistics
type ThreatStats struct {
	ThreatType string `json:"threat_type"`
	Count      int    `json:"count"`
	Severity   string `json:"severity"`
	Trend      string `json:"trend"` // up, down, stable
}

// EndpointHealth represents endpoint health metrics
type EndpointHealth struct {
	Status string `json:"status"` // healthy, warning, critical, offline
	Count  int    `json:"count"`
	Percentage float64 `json:"percentage"`
}

// OSStats represents OS distribution
type OSStats struct {
	OS    string `json:"os"`
	Count int    `json:"count"`
	Version string `json:"version"`
}

// AgentDeployment represents agent deployment request
type AgentDeployment struct {
	Hostname  string   `json:"hostname"`
	IPAddress string   `json:"ip_address"`
	OS        string   `json:"os"`
	Tags      []string `json:"tags"`
}

// ThreatAction represents action to take on threat
type ThreatAction struct {
	Action string `json:"action"` // quarantine, remove, whitelist, investigate
	Notes  string `json:"notes"`
}

// EDR Handlers

func (s *APIServer) handleGetEDRDashboard(c *gin.Context) {
	dashboard := generateMockEDRDashboard()
	c.JSON(http.StatusOK, dashboard)
}

func (s *APIServer) handleGetEDRAgents(c *gin.Context) {
	status := c.Query("status")
	
	agents := generateMockEDRAgents()
	
	// Filter by status
	if status != "" {
		filtered := []EDRAgent{}
		for _, agent := range agents {
			if agent.Status == status {
				filtered = append(filtered, agent)
			}
		}
		agents = filtered
	}
	
	c.JSON(http.StatusOK, agents)
}

func (s *APIServer) handleGetEDRAgent(c *gin.Context) {
	agentID := c.Param("id")
	agent := generateMockEDRAgentDetail(agentID)
	c.JSON(http.StatusOK, agent)
}

func (s *APIServer) handleDeployAgent(c *gin.Context) {
	var deployment AgentDeployment
	if err := c.ShouldBindJSON(&deployment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agent := EDRAgent{
		ID:           fmt.Sprintf("AGENT-%d", time.Now().Unix()),
		Hostname:     deployment.Hostname,
		IPAddress:    deployment.IPAddress,
		OS:           deployment.OS,
		AgentVersion: "2.5.0",
		Status:       "online",
		LastSeen:     time.Now(),
		InstallDate:  time.Now(),
		Tags:         deployment.Tags,
	}

	c.JSON(http.StatusCreated, agent)
}

func (s *APIServer) handleUninstallAgent(c *gin.Context) {
	agentID := c.Param("id")
	c.JSON(http.StatusOK, gin.H{
		"message": "Agent uninstall initiated",
		"agent_id": agentID,
		"status": "pending",
	})
}

func (s *APIServer) handleGetEndpoints(c *gin.Context) {
	endpoints := generateMockEndpoints()
	c.JSON(http.StatusOK, endpoints)
}

func (s *APIServer) handleGetEndpoint(c *gin.Context) {
	endpointID := c.Param("id")
	endpoint := generateMockEndpointDetail(endpointID)
	c.JSON(http.StatusOK, endpoint)
}

func (s *APIServer) handleIsolateEndpoint(c *gin.Context) {
	endpointID := c.Param("id")
	
	var request struct {
		Reason string `json:"reason"`
		Notes  string `json:"notes"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	action := IsolationAction{
		ID:          fmt.Sprintf("ISO-%d", time.Now().Unix()),
		AgentID:     endpointID,
		Hostname:    "endpoint-host",
		Action:      "isolate",
		Reason:      request.Reason,
		Status:      "completed",
		InitiatedBy: "admin@company.com",
		InitiatedAt: time.Now(),
		CompletedAt: timePtr(time.Now()),
		Notes:       request.Notes,
	}

	c.JSON(http.StatusOK, action)
}

func (s *APIServer) handleRestoreEndpoint(c *gin.Context) {
	endpointID := c.Param("id")
	
	action := IsolationAction{
		ID:          fmt.Sprintf("RES-%d", time.Now().Unix()),
		AgentID:     endpointID,
		Hostname:    "endpoint-host",
		Action:      "restore",
		Reason:      "Threat remediated",
		Status:      "completed",
		InitiatedBy: "admin@company.com",
		InitiatedAt: time.Now(),
		CompletedAt: timePtr(time.Now()),
	}

	c.JSON(http.StatusOK, action)
}

func (s *APIServer) handleGetEDRThreats(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")
	threatType := c.Query("type")
	
	threats := generateMockEDRThreats()
	
	// Apply filters
	if status != "" {
		filtered := []EDRThreat{}
		for _, threat := range threats {
			if threat.Status == status {
				filtered = append(filtered, threat)
			}
		}
		threats = filtered
	}
	
	if severity != "" {
		filtered := []EDRThreat{}
		for _, threat := range threats {
			if threat.Severity == severity {
				filtered = append(filtered, threat)
			}
		}
		threats = filtered
	}
	
	if threatType != "" {
		filtered := []EDRThreat{}
		for _, threat := range threats {
			if threat.Type == threatType {
				filtered = append(filtered, threat)
			}
		}
		threats = filtered
	}
	
	c.JSON(http.StatusOK, threats)
}

func (s *APIServer) handleGetEDRThreat(c *gin.Context) {
	threatID := c.Param("id")
	threat := generateMockEDRThreatDetail(threatID)
	c.JSON(http.StatusOK, threat)
}

func (s *APIServer) handleTakeActionOnThreat(c *gin.Context) {
	threatID := c.Param("id")
	
	var action ThreatAction
	if err := c.ShouldBindJSON(&action); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	threat := generateMockEDRThreatDetail(threatID)
	threat.ActionTaken = action.Action
	
	switch action.Action {
	case "quarantine":
		threat.Status = "quarantined"
		now := time.Now()
		threat.QuarantinedAt = &now
	case "remove":
		threat.Status = "removed"
		now := time.Now()
		threat.RemovedAt = &now
	case "whitelist":
		threat.Status = "whitelisted"
	}

	c.JSON(http.StatusOK, threat)
}

func (s *APIServer) handleGetProcesses(c *gin.Context) {
	agentID := c.Query("agent_id")
	suspicious := c.Query("suspicious")
	
	processes := generateMockProcesses()
	
	// Filter by agent
	if agentID != "" {
		filtered := []Process{}
		for _, proc := range processes {
			if proc.AgentID == agentID {
				filtered = append(filtered, proc)
			}
		}
		processes = filtered
	}
	
	// Filter suspicious
	if suspicious == "true" {
		filtered := []Process{}
		for _, proc := range processes {
			if proc.Suspicious {
				filtered = append(filtered, proc)
			}
		}
		processes = filtered
	}
	
	c.JSON(http.StatusOK, processes)
}

func (s *APIServer) handleTerminateProcess(c *gin.Context) {
	processID := c.Param("id")
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Process termination initiated",
		"process_id": processID,
		"status": "terminated",
	})
}

func (s *APIServer) handleGetMemoryScans(c *gin.Context) {
	scans := generateMockMemoryScans()
	c.JSON(http.StatusOK, scans)
}

func (s *APIServer) handleInitiateMemoryScan(c *gin.Context) {
	var request struct {
		AgentID  string `json:"agent_id"`
		ScanType string `json:"scan_type"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scan := MemoryScan{
		ID:               fmt.Sprintf("SCAN-%d", time.Now().Unix()),
		AgentID:          request.AgentID,
		Hostname:         "endpoint-host",
		ScanType:         request.ScanType,
		Status:           "running",
		StartTime:        time.Now(),
		ProcessesScanned: 0,
		ThreatsFound:     0,
	}

	c.JSON(http.StatusCreated, scan)
}

func (s *APIServer) handleGetForensics(c *gin.Context) {
	forensics := generateMockForensics()
	c.JSON(http.StatusOK, forensics)
}

func (s *APIServer) handleCollectForensics(c *gin.Context) {
	var request struct {
		AgentID    string `json:"agent_id"`
		Type       string `json:"type"`
		IncidentID string `json:"incident_id,omitempty"`
		Notes      string `json:"notes"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	forensic := ForensicData{
		ID:          fmt.Sprintf("FOR-%d", time.Now().Unix()),
		AgentID:     request.AgentID,
		Hostname:    "endpoint-host",
		Type:        request.Type,
		Status:      "collecting",
		StartTime:   time.Now(),
		IncidentID:  request.IncidentID,
		CollectedBy: "admin@company.com",
		Notes:       request.Notes,
	}

	c.JSON(http.StatusCreated, forensic)
}

func (s *APIServer) handleGetEDRStats(c *gin.Context) {
	stats := gin.H{
		"total_agents": 342,
		"online_agents": 318,
		"offline_agents": 24,
		"isolated_agents": 5,
		"threats_detected_today": 47,
		"threats_quarantined_today": 42,
		"threats_removed_today": 38,
		"avg_response_time": 45,
		"compliance_rate": 96.8,
		"memory_scans_today": 89,
		"forensic_collections": 12,
	}
	c.JSON(http.StatusOK, stats)
}

// Mock data generators

func generateMockEDRDashboard() EDRDashboard {
	return EDRDashboard{
		Overview: EDROverview{
			TotalAgents:       342,
			OnlineAgents:      318,
			IsolatedAgents:    5,
			ThreatsDetected:   1847,
			ThreatsQuarantined: 1523,
			ThreatsRemoved:    1289,
			AvgResponseTime:   45,
			ComplianceRate:    96.8,
		},
		ThreatTrend: []ThreatTrendPoint{
			{Date: "2025-11-01", Detected: 42, Quarantined: 38, Removed: 35},
			{Date: "2025-11-02", Detected: 38, Quarantined: 35, Removed: 32},
			{Date: "2025-11-03", Detected: 51, Quarantined: 47, Removed: 43},
			{Date: "2025-11-04", Detected: 45, Quarantined: 41, Removed: 38},
			{Date: "2025-11-05", Detected: 39, Quarantined: 36, Removed: 33},
			{Date: "2025-11-06", Detected: 47, Quarantined: 42, Removed: 38},
		},
		TopThreats: []ThreatStats{
			{ThreatType: "Ransomware", Count: 456, Severity: "critical", Trend: "down"},
			{ThreatType: "Trojan", Count: 389, Severity: "high", Trend: "stable"},
			{ThreatType: "Malware", Count: 312, Severity: "high", Trend: "up"},
			{ThreatType: "Rootkit", Count: 198, Severity: "critical", Trend: "down"},
			{ThreatType: "Exploit", Count: 165, Severity: "high", Trend: "stable"},
		},
		EndpointHealth: []EndpointHealth{
			{Status: "healthy", Count: 289, Percentage: 84.5},
			{Status: "warning", Count: 29, Percentage: 8.5},
			{Status: "critical", Count: 19, Percentage: 5.6},
			{Status: "offline", Count: 5, Percentage: 1.5},
		},
		OSDistribution: []OSStats{
			{OS: "Windows", Count: 198, Version: "10/11"},
			{OS: "Linux", Count: 89, Version: "Ubuntu/RHEL"},
			{OS: "MacOS", Count: 55, Version: "Monterey/Ventura"},
		},
		RecentThreats:  generateMockEDRThreats()[:5],
		CriticalAgents: generateMockCriticalAgents(),
	}
}

func generateMockEDRAgents() []EDRAgent {
	agents := []EDRAgent{
		{
			ID:              "AGENT-001",
			Hostname:        "DC-01.corp.local",
			IPAddress:       "192.168.1.10",
			OS:              "windows",
			OSVersion:       "Server 2019",
			AgentVersion:    "2.5.0",
			Status:          "online",
			LastSeen:        time.Now().Add(-5 * time.Minute),
			InstallDate:     time.Now().AddDate(0, -6, 0),
			CPUUsage:        45.3,
			MemoryUsage:     68.2,
			DiskUsage:       52.1,
			ThreatCount:     12,
			QuarantineCount: 5,
			Tags:            []string{"domain_controller", "critical"},
		},
		{
			ID:              "AGENT-002",
			Hostname:        "WEB-SERVER-01",
			IPAddress:       "192.168.1.20",
			OS:              "linux",
			OSVersion:       "Ubuntu 22.04",
			AgentVersion:    "2.5.0",
			Status:          "online",
			LastSeen:        time.Now().Add(-2 * time.Minute),
			InstallDate:     time.Now().AddDate(0, -4, 0),
			CPUUsage:        32.1,
			MemoryUsage:     54.7,
			DiskUsage:       61.3,
			ThreatCount:     8,
			QuarantineCount: 3,
			Tags:            []string{"web_server", "production"},
		},
		{
			ID:              "AGENT-003",
			Hostname:        "DB-SERVER-01",
			IPAddress:       "192.168.1.30",
			OS:              "windows",
			OSVersion:       "Server 2022",
			AgentVersion:    "2.5.0",
			Status:          "isolated",
			LastSeen:        time.Now().Add(-1 * time.Hour),
			InstallDate:     time.Now().AddDate(0, -8, 0),
			CPUUsage:        78.9,
			MemoryUsage:     89.4,
			DiskUsage:       73.2,
			ThreatCount:     25,
			QuarantineCount: 18,
			Tags:            []string{"database", "critical", "isolated"},
		},
		{
			ID:              "AGENT-004",
			Hostname:        "WORKSTATION-42",
			IPAddress:       "192.168.2.42",
			OS:              "windows",
			OSVersion:       "Windows 11 Pro",
			AgentVersion:    "2.5.0",
			Status:          "online",
			LastSeen:        time.Now().Add(-10 * time.Minute),
			InstallDate:     time.Now().AddDate(0, -2, 0),
			CPUUsage:        23.4,
			MemoryUsage:     41.2,
			DiskUsage:       45.8,
			ThreatCount:     3,
			QuarantineCount: 1,
			Tags:            []string{"workstation", "finance"},
		},
		{
			ID:              "AGENT-005",
			Hostname:        "MAC-LAPTOP-15",
			IPAddress:       "192.168.2.15",
			OS:              "macos",
			OSVersion:       "Ventura 13.5",
			AgentVersion:    "2.5.0",
			Status:          "online",
			LastSeen:        time.Now().Add(-3 * time.Minute),
			InstallDate:     time.Now().AddDate(0, -1, 0),
			CPUUsage:        18.7,
			MemoryUsage:     35.9,
			DiskUsage:       38.4,
			ThreatCount:     1,
			QuarantineCount: 0,
			Tags:            []string{"laptop", "marketing"},
		},
		{
			ID:              "AGENT-006",
			Hostname:        "FILE-SERVER-01",
			IPAddress:       "192.168.1.40",
			OS:              "windows",
			OSVersion:       "Server 2019",
			AgentVersion:    "2.4.5",
			Status:          "updating",
			LastSeen:        time.Now().Add(-30 * time.Minute),
			InstallDate:     time.Now().AddDate(0, -12, 0),
			CPUUsage:        56.2,
			MemoryUsage:     72.3,
			DiskUsage:       89.1,
			ThreatCount:     15,
			QuarantineCount: 8,
			Tags:            []string{"file_server", "production"},
		},
	}

	return agents
}

func generateMockEDRAgentDetail(agentID string) EDRAgent {
	agents := generateMockEDRAgents()
	for _, agent := range agents {
		if agent.ID == agentID {
			return agent
		}
	}
	return agents[0]
}

func generateMockCriticalAgents() []EDRAgent {
	allAgents := generateMockEDRAgents()
	critical := []EDRAgent{}
	for _, agent := range allAgents {
		if agent.ThreatCount > 10 || agent.Status == "isolated" {
			critical = append(critical, agent)
		}
	}
	return critical
}

func generateMockEndpoints() []Endpoint {
	endpoints := []Endpoint{
		{
			ID:               "EP-001",
			AgentID:          "AGENT-001",
			Hostname:         "DC-01.corp.local",
			IPAddress:        "192.168.1.10",
			MACAddress:       "00:1A:2B:3C:4D:5E",
			OS:               "Windows Server 2019",
			Domain:           "corp.local",
			Users:            []string{"Administrator", "BackupUser"},
			RunningProcesses: 145,
			OpenPorts:        []int{53, 88, 135, 389, 445, 3389},
			InstalledSoftware: 89,
			LastScan:         time.Now().Add(-2 * time.Hour),
			RiskScore:        78,
			Compliance:       true,
			Isolated:         false,
		},
		{
			ID:               "EP-002",
			AgentID:          "AGENT-002",
			Hostname:         "WEB-SERVER-01",
			IPAddress:        "192.168.1.20",
			MACAddress:       "00:1B:2C:3D:4E:5F",
			OS:               "Ubuntu 22.04 LTS",
			Domain:           "corp.local",
			Users:            []string{"webadmin", "www-data"},
			RunningProcesses: 98,
			OpenPorts:        []int{22, 80, 443},
			InstalledSoftware: 156,
			LastScan:         time.Now().Add(-1 * time.Hour),
			RiskScore:        45,
			Compliance:       true,
			Isolated:         false,
		},
		{
			ID:               "EP-003",
			AgentID:          "AGENT-003",
			Hostname:         "DB-SERVER-01",
			IPAddress:        "192.168.1.30",
			MACAddress:       "00:1C:2D:3E:4F:60",
			OS:               "Windows Server 2022",
			Domain:           "corp.local",
			Users:            []string{"dbadmin", "sqlservice"},
			RunningProcesses: 132,
			OpenPorts:        []int{1433, 3389},
			InstalledSoftware: 72,
			LastScan:         time.Now().Add(-3 * time.Hour),
			RiskScore:        92,
			Compliance:       false,
			Isolated:         true,
		},
	}

	return endpoints
}

func generateMockEndpointDetail(endpointID string) Endpoint {
	endpoints := generateMockEndpoints()
	for _, ep := range endpoints {
		if ep.ID == endpointID {
			return ep
		}
	}
	return endpoints[0]
}

func generateMockEDRThreats() []EDRThreat {
	threats := []EDRThreat{
		{
			ID:              "THR-001",
			AgentID:         "AGENT-003",
			Hostname:        "DB-SERVER-01",
			Type:            "ransomware",
			Name:            "WannaCry.Variant",
			Severity:        "critical",
			Status:          "quarantined",
			FilePath:        "C:\\Users\\Admin\\Downloads\\invoice.exe",
			FileHash:        "5d5b09f6dcb2d53a5fffc60c4ac0d55fabdf556069d6631545f42aa6e3500f2e",
			ProcessName:     "invoice.exe",
			ProcessID:       4892,
			CommandLine:     "C:\\Users\\Admin\\Downloads\\invoice.exe -encrypt",
			ParentProcess:   "explorer.exe",
			DetectionMethod: "signature",
			MITRETactics:    []string{"Impact", "Defense Evasion"},
			MITRETechniques: []string{"T1486", "T1027"},
			DetectedAt:      time.Now().Add(-2 * time.Hour),
			QuarantinedAt:   timePtr(time.Now().Add(-1 * time.Hour)),
			ActionTaken:     "quarantine",
			ThreatScore:     98,
		},
		{
			ID:              "THR-002",
			AgentID:         "AGENT-001",
			Hostname:        "DC-01.corp.local",
			Type:            "trojan",
			Name:            "Emotet.Downloader",
			Severity:        "high",
			Status:          "removed",
			FilePath:        "C:\\Windows\\Temp\\svchost32.exe",
			FileHash:        "8f14e45fceea167a5a36dedd4bea2543ca7d4bb3ae4c75c8d85b1c5c2c8f6f2c",
			ProcessName:     "svchost32.exe",
			ProcessID:       2341,
			CommandLine:     "C:\\Windows\\Temp\\svchost32.exe -c2 185.244.39.78",
			ParentProcess:   "winword.exe",
			DetectionMethod: "behavior",
			MITRETactics:    []string{"Command and Control", "Persistence"},
			MITRETechniques: []string{"T1071", "T1547"},
			DetectedAt:      time.Now().Add(-5 * time.Hour),
			QuarantinedAt:   timePtr(time.Now().Add(-4 * time.Hour)),
			RemovedAt:       timePtr(time.Now().Add(-3 * time.Hour)),
			ActionTaken:     "remove",
			ThreatScore:     87,
		},
		{
			ID:              "THR-003",
			AgentID:         "AGENT-002",
			Hostname:        "WEB-SERVER-01",
			Type:            "exploit",
			Name:            "Log4Shell.Exploit",
			Severity:        "critical",
			Status:          "detected",
			FilePath:        "/var/log/apache2/access.log",
			FileHash:        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
			ProcessName:     "java",
			ProcessID:       1823,
			CommandLine:     "/usr/bin/java -jar application.jar",
			ParentProcess:   "systemd",
			DetectionMethod: "heuristic",
			MITRETactics:    []string{"Initial Access", "Execution"},
			MITRETechniques: []string{"T1190", "T1059"},
			DetectedAt:      time.Now().Add(-30 * time.Minute),
			ActionTaken:     "alert",
			ThreatScore:     95,
		},
		{
			ID:              "THR-004",
			AgentID:         "AGENT-004",
			Hostname:        "WORKSTATION-42",
			Type:            "suspicious_behavior",
			Name:            "PowerShell.EncodedCommand",
			Severity:        "medium",
			Status:          "detected",
			FilePath:        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			FileHash:        "7c1c9e6f5e6f9c7f0e7f9c7f0e7f9c7f0e7f9c7f0e7f9c7f0e7f9c7f0e7f9c7f",
			ProcessName:     "powershell.exe",
			ProcessID:       7654,
			CommandLine:     "powershell.exe -encodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
			ParentProcess:   "cmd.exe",
			DetectionMethod: "behavior",
			MITRETactics:    []string{"Execution", "Defense Evasion"},
			MITRETechniques: []string{"T1059.001", "T1027"},
			DetectedAt:      time.Now().Add(-15 * time.Minute),
			ActionTaken:     "alert",
			ThreatScore:     65,
		},
		{
			ID:              "THR-005",
			AgentID:         "AGENT-003",
			Hostname:        "DB-SERVER-01",
			Type:            "rootkit",
			Name:            "ZeroAccess.Rootkit",
			Severity:        "critical",
			Status:          "quarantined",
			FilePath:        "C:\\Windows\\System32\\drivers\\null.sys",
			FileHash:        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			ProcessName:     "null.sys",
			ProcessID:       0,
			CommandLine:     "",
			ParentProcess:   "system",
			DetectionMethod: "ml",
			MITRETactics:    []string{"Defense Evasion", "Persistence"},
			MITRETechniques: []string{"T1014", "T1547.006"},
			DetectedAt:      time.Now().Add(-6 * time.Hour),
			QuarantinedAt:   timePtr(time.Now().Add(-5 * time.Hour)),
			ActionTaken:     "quarantine",
			ThreatScore:     99,
		},
	}

	return threats
}

func generateMockEDRThreatDetail(threatID string) EDRThreat {
	threats := generateMockEDRThreats()
	for _, threat := range threats {
		if threat.ID == threatID {
			return threat
		}
	}
	return threats[0]
}

func generateMockProcesses() []Process {
	processes := []Process{
		{
			ID:              "PROC-001",
			AgentID:         "AGENT-001",
			Hostname:        "DC-01.corp.local",
			Name:            "lsass.exe",
			PID:             672,
			ParentPID:       528,
			ParentName:      "wininit.exe",
			CommandLine:     "C:\\Windows\\system32\\lsass.exe",
			Path:            "C:\\Windows\\system32\\lsass.exe",
			Hash:            "d02ba951e5e0e1b43f0c1f4c2e0e1b43f0c1f4c2e0e1b43f0c1f4c2e0e1b43f0",
			User:            "SYSTEM",
			CPUUsage:        2.3,
			MemoryUsage:     45678901,
			StartTime:       time.Now().AddDate(0, 0, -7),
			Connections:     15,
			FileOperations:  234,
			RegistryChanges: 89,
			Suspicious:      false,
			ThreatScore:     10,
			Signature:       "Microsoft Corporation",
		},
		{
			ID:              "PROC-002",
			AgentID:         "AGENT-003",
			Hostname:        "DB-SERVER-01",
			Name:            "invoice.exe",
			PID:             4892,
			ParentPID:       3456,
			ParentName:      "explorer.exe",
			CommandLine:     "C:\\Users\\Admin\\Downloads\\invoice.exe -encrypt",
			Path:            "C:\\Users\\Admin\\Downloads\\invoice.exe",
			Hash:            "5d5b09f6dcb2d53a5fffc60c4ac0d55fabdf556069d6631545f42aa6e3500f2e",
			User:            "Admin",
			CPUUsage:        78.9,
			MemoryUsage:     189234567,
			StartTime:       time.Now().Add(-2 * time.Hour),
			Connections:     45,
			FileOperations:  15678,
			RegistryChanges: 234,
			Suspicious:      true,
			ThreatScore:     98,
			Signature:       "Unsigned",
		},
		{
			ID:              "PROC-003",
			AgentID:         "AGENT-004",
			Hostname:        "WORKSTATION-42",
			Name:            "powershell.exe",
			PID:             7654,
			ParentPID:       6543,
			ParentName:      "cmd.exe",
			CommandLine:     "powershell.exe -encodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
			Path:            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			Hash:            "7c1c9e6f5e6f9c7f0e7f9c7f0e7f9c7f0e7f9c7f0e7f9c7f0e7f9c7f0e7f9c7f",
			User:            "john.doe",
			CPUUsage:        15.6,
			MemoryUsage:     67890123,
			StartTime:       time.Now().Add(-15 * time.Minute),
			Connections:     8,
			FileOperations:  156,
			RegistryChanges: 23,
			Suspicious:      true,
			ThreatScore:     65,
			Signature:       "Microsoft Corporation",
		},
	}

	return processes
}

func generateMockMemoryScans() []MemoryScan {
	scans := []MemoryScan{
		{
			ID:               "SCAN-001",
			AgentID:          "AGENT-003",
			Hostname:         "DB-SERVER-01",
			ScanType:         "full",
			Status:           "completed",
			StartTime:        time.Now().Add(-2 * time.Hour),
			EndTime:          timePtr(time.Now().Add(-1 * time.Hour)),
			Duration:         3600,
			ProcessesScanned: 132,
			ThreatsFound:     3,
			SuspiciousItems:  7,
			InjectedCode:     2,
			HiddenProcesses:  1,
			Findings:         []string{"Rootkit detected", "Code injection in lsass.exe", "Hidden process found"},
		},
		{
			ID:               "SCAN-002",
			AgentID:          "AGENT-001",
			Hostname:         "DC-01.corp.local",
			ScanType:         "quick",
			Status:           "completed",
			StartTime:        time.Now().Add(-30 * time.Minute),
			EndTime:          timePtr(time.Now().Add(-25 * time.Minute)),
			Duration:         300,
			ProcessesScanned: 89,
			ThreatsFound:     0,
			SuspiciousItems:  2,
			InjectedCode:     0,
			HiddenProcesses:  0,
			Findings:         []string{"Suspicious PowerShell activity"},
		},
		{
			ID:               "SCAN-003",
			AgentID:          "AGENT-002",
			Hostname:         "WEB-SERVER-01",
			ScanType:         "targeted",
			Status:           "running",
			StartTime:        time.Now().Add(-10 * time.Minute),
			ProcessesScanned: 23,
			ThreatsFound:     0,
			SuspiciousItems:  1,
			InjectedCode:     0,
			HiddenProcesses:  0,
			Findings:         []string{},
		},
	}

	return scans
}

func generateMockForensics() []ForensicData {
	forensics := []ForensicData{
		{
			ID:          "FOR-001",
			AgentID:     "AGENT-003",
			Hostname:    "DB-SERVER-01",
			Type:        "memory_dump",
			Status:      "collected",
			StartTime:   time.Now().Add(-3 * time.Hour),
			EndTime:     timePtr(time.Now().Add(-2 * time.Hour)),
			Size:        16777216000,
			Location:    "/forensics/memory_dump_20251106_150000.dmp",
			Hash:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			IncidentID:  "INC-1234",
			CollectedBy: "security.analyst@company.com",
			Notes:       "Ransomware incident - full memory dump collected",
		},
		{
			ID:          "FOR-002",
			AgentID:     "AGENT-001",
			Hostname:    "DC-01.corp.local",
			Type:        "event_logs",
			Status:      "uploaded",
			StartTime:   time.Now().Add(-1 * time.Hour),
			EndTime:     timePtr(time.Now().Add(-45 * time.Minute)),
			Size:        524288000,
			Location:    "/forensics/event_logs_20251106_170000.evtx",
			Hash:        "f5ca38f748a1d6eaf726b8a42fb575c3c71f1864a8143301782de13da2d9202b",
			IncidentID:  "INC-1235",
			CollectedBy: "incident.responder@company.com",
			Notes:       "Suspicious authentication attempts",
		},
		{
			ID:          "FOR-003",
			AgentID:     "AGENT-002",
			Hostname:    "WEB-SERVER-01",
			Type:        "process_dump",
			Status:      "collecting",
			StartTime:   time.Now().Add(-15 * time.Minute),
			Size:        0,
			IncidentID:  "INC-1236",
			CollectedBy: "automation@company.com",
			Notes:       "Automated collection for suspicious java process",
		},
	}

	return forensics
}

