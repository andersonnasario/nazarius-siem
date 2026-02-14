package main

import (
	"crypto/md5"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// min retorna o menor valor entre dois inteiros
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MonitoredFile representa um arquivo monitorado
type MonitoredFile struct {
	ID               string    `json:"id"`
	Path             string    `json:"path"`
	Filename         string    `json:"filename"`
	Size             int64     `json:"size"`
	Permissions      string    `json:"permissions"`
	Owner            string    `json:"owner"`
	Group            string    `json:"group"`
	MD5Hash          string    `json:"md5_hash"`
	SHA256Hash       string    `json:"sha256_hash"`
	LastModified     time.Time `json:"last_modified"`
	LastChecked      time.Time `json:"last_checked"`
	Status           string    `json:"status"` // ok, changed, missing, new
	ChangeCount      int       `json:"change_count"`
	Severity         string    `json:"severity"` // critical, high, medium, low
	ComplianceFrames []string  `json:"compliance_frameworks"`
	Tags             []string  `json:"tags"`
}

// FileChange representa uma mudança detectada
type FileChange struct {
	ID             string    `json:"id"`
	FileID         string    `json:"file_id"`
	FilePath       string    `json:"file_path"`
	ChangeType     string    `json:"change_type"` // modified, deleted, created, permissions, owner
	DetectedAt     time.Time `json:"detected_at"`
	OldHash        string    `json:"old_hash,omitempty"`
	NewHash        string    `json:"new_hash,omitempty"`
	OldSize        int64     `json:"old_size,omitempty"`
	NewSize        int64     `json:"new_size,omitempty"`
	OldPermissions string    `json:"old_permissions,omitempty"`
	NewPermissions string    `json:"new_permissions,omitempty"`
	OldOwner       string    `json:"old_owner,omitempty"`
	NewOwner       string    `json:"new_owner,omitempty"`
	Severity       string    `json:"severity"`
	AlertGenerated bool      `json:"alert_generated"`
	Acknowledged   bool      `json:"acknowledged"`
	AcknowledgedBy string    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt time.Time `json:"acknowledged_at,omitempty"`
	Notes          string    `json:"notes,omitempty"`
}

// Baseline representa um baseline de arquivos
type Baseline struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	CreatedAt   time.Time           `json:"created_at"`
	CreatedBy   string              `json:"created_by"`
	FileCount   int                 `json:"file_count"`
	Status      string              `json:"status"` // active, archived
	Files       []MonitoredFile     `json:"files,omitempty"`
	Metadata    map[string]string   `json:"metadata"`
}

// FIMRule representa uma regra de monitoramento
type FIMRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Path        string   `json:"path"`
	Recursive   bool     `json:"recursive"`
	Enabled     bool     `json:"enabled"`
	AlertOn     []string `json:"alert_on"` // modified, deleted, created, permissions, owner
	Severity    string   `json:"severity"`
	Compliance  []string `json:"compliance"`
	Exclude     []string `json:"exclude"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// FIMAlert representa um alerta de FIM
type FIMAlert struct {
	ID          string    `json:"id"`
	FileID      string    `json:"file_id"`
	FilePath    string    `json:"file_path"`
	ChangeID    string    `json:"change_id"`
	ChangeType  string    `json:"change_type"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	DetectedAt  time.Time `json:"detected_at"`
	Status      string    `json:"status"` // new, investigating, resolved, false_positive
	AssignedTo  string    `json:"assigned_to,omitempty"`
	ResolvedAt  time.Time `json:"resolved_at,omitempty"`
	ResolvedBy  string    `json:"resolved_by,omitempty"`
	Resolution  string    `json:"resolution,omitempty"`
	MitreIDs    []string  `json:"mitre_ids,omitempty"`
}

// FIMDashboard representa o dashboard de FIM
type FIMDashboard struct {
	TotalFiles        int           `json:"total_files"`
	FilesOK           int           `json:"files_ok"`
	FilesChanged      int           `json:"files_changed"`
	FilesMissing      int           `json:"files_missing"`
	ChangesLast24h    int           `json:"changes_last_24h"`
	AlertsOpen        int           `json:"alerts_open"`
	ComplianceScore   float64       `json:"compliance_score"`
	RecentChanges     []FileChange  `json:"recent_changes"`
	CriticalFiles     []MonitoredFile `json:"critical_files"`
	TopChangedFiles   []MonitoredFile `json:"top_changed_files"`
	ChangesTrend      []ChangeTrend `json:"changes_trend"`
	AlertsBySeverity  map[string]int `json:"alerts_by_severity"`
}

// ChangeTrend representa tendência de mudanças
type ChangeTrend struct {
	Timestamp    time.Time `json:"timestamp"`
	ChangeCount  int       `json:"change_count"`
	FileModified int       `json:"file_modified"`
	FileDeleted  int       `json:"file_deleted"`
	FileCreated  int       `json:"file_created"`
}

// handleGetFIMDashboard retorna dashboard de FIM
func (s *APIServer) handleGetFIMDashboard(c *gin.Context) {
	monitoredFiles := generateMockMonitoredFiles()
	fileChanges := generateMockFileChanges()
	
	dashboard := FIMDashboard{
		TotalFiles:       2847,
		FilesOK:          2715,
		FilesChanged:     89,
		FilesMissing:     43,
		ChangesLast24h:   132,
		AlertsOpen:       15,
		ComplianceScore:  94.5,
		RecentChanges:    fileChanges[:min(5, len(fileChanges))],
		CriticalFiles:    monitoredFiles[:min(5, len(monitoredFiles))],
		TopChangedFiles:  generateMockTopChangedFiles(),
		ChangesTrend:     generateMockChangesTrend(),
		AlertsBySeverity: map[string]int{
			"critical": 3,
			"high":     7,
			"medium":   12,
			"low":      8,
		},
	}

	c.JSON(http.StatusOK, dashboard)
}

// handleGetMonitoredFiles lista arquivos monitorados
func (s *APIServer) handleGetMonitoredFiles(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")

	files := generateMockMonitoredFiles()

	// Filtrar por status
	if status != "" && status != "all" {
		filtered := []MonitoredFile{}
		for _, f := range files {
			if f.Status == status {
				filtered = append(filtered, f)
			}
		}
		files = filtered
	}

	// Filtrar por severity
	if severity != "" && severity != "all" {
		filtered := []MonitoredFile{}
		for _, f := range files {
			if f.Severity == severity {
				filtered = append(filtered, f)
			}
		}
		files = filtered
	}

	c.JSON(http.StatusOK, gin.H{
		"files": files,
		"total": len(files),
	})
}

// handleGetFileChanges lista mudanças de arquivos
func (s *APIServer) handleGetFileChanges(c *gin.Context) {
	changes := generateMockFileChanges()

	c.JSON(http.StatusOK, gin.H{
		"changes": changes,
		"total":   len(changes),
	})
}

// handleGetBaselines lista baselines
func (s *APIServer) handleGetBaselines(c *gin.Context) {
	baselines := generateMockBaselines()

	c.JSON(http.StatusOK, gin.H{
		"baselines": baselines,
		"total":     len(baselines),
	})
}

// handleCreateBaseline cria novo baseline
func (s *APIServer) handleCreateBaseline(c *gin.Context) {
	var baseline Baseline
	if err := c.ShouldBindJSON(&baseline); err != nil {
		log.Printf("[ERROR] handleCreateBaseline bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	baseline.ID = "baseline-" + generateID()
	baseline.CreatedAt = time.Now()
	baseline.Status = "active"

	c.JSON(http.StatusCreated, baseline)
}

// handleGetFIMRules lista regras de FIM
func (s *APIServer) handleGetFIMRules(c *gin.Context) {
	rules := generateMockFIMRules()

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"total": len(rules),
	})
}

// handleCreateFIMRule cria nova regra
func (s *APIServer) handleCreateFIMRule(c *gin.Context) {
	var rule FIMRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		log.Printf("[ERROR] handleCreateFIMRule bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	rule.ID = "rule-" + generateID()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	c.JSON(http.StatusCreated, rule)
}

// handleGetFIMAlerts lista alertas de FIM
func (s *APIServer) handleGetFIMAlerts(c *gin.Context) {
	alerts := generateMockFIMAlerts()

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"total":  len(alerts),
	})
}

// handleAcknowledgeChange marca mudança como reconhecida
func (s *APIServer) handleAcknowledgeChange(c *gin.Context) {
	changeID := c.Param("id")
	
	var req struct {
		Notes string `json:"notes"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleAcknowledgeChange bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Change acknowledged successfully",
		"change_id":      changeID,
		"acknowledged_by": "admin@company.com",
		"acknowledged_at": time.Now(),
	})
}

// handleGetFIMStats retorna estatísticas gerais
func (s *APIServer) handleGetFIMStats(c *gin.Context) {
	stats := gin.H{
		"total_monitored_files":      2847,
		"files_ok":                   2715,
		"files_changed":              89,
		"files_missing":              43,
		"total_changes_24h":          132,
		"total_changes_7d":           847,
		"total_changes_30d":          3456,
		"avg_changes_per_day":        115,
		"alerts_open":                15,
		"alerts_resolved_24h":        23,
		"compliance_score":           94.5,
		"critical_files_monitored":   234,
		"baselines_count":            12,
		"active_rules":               28,
		"last_scan_time":             time.Now().Add(-15 * time.Minute),
		"next_scan_time":             time.Now().Add(45 * time.Minute),
		"scan_frequency":             "1 hour",
		"storage_used":               "15.2 GB",
		"top_change_type":            "modified",
		"compliance_frameworks":      []string{"PCI-DSS", "HIPAA", "SOC2", "ISO27001"},
	}

	c.JSON(http.StatusOK, stats)
}

// === Mock Data Generators ===

func generateMockMonitoredFiles() []MonitoredFile {
	files := []MonitoredFile{
		{
			ID: "file-001", Path: "/etc/passwd", Filename: "passwd",
			Size: 2048, Permissions: "-rw-r--r--", Owner: "root", Group: "root",
			MD5Hash: "5d41402abc4b2a76b9719d911017c592", SHA256Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			LastModified: time.Now().Add(-2 * time.Hour), LastChecked: time.Now().Add(-5 * time.Minute),
			Status: "ok", ChangeCount: 0, Severity: "critical",
			ComplianceFrames: []string{"PCI-DSS 11.5", "HIPAA"},
			Tags: []string{"system", "authentication"},
		},
		{
			ID: "file-002", Path: "/etc/shadow", Filename: "shadow",
			Size: 1024, Permissions: "-rw-------", Owner: "root", Group: "shadow",
			MD5Hash: "098f6bcd4621d373cade4e832627b4f6", SHA256Hash: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
			LastModified: time.Now().Add(-15 * time.Minute), LastChecked: time.Now().Add(-2 * time.Minute),
			Status: "changed", ChangeCount: 1, Severity: "critical",
			ComplianceFrames: []string{"PCI-DSS 11.5", "HIPAA", "SOC2"},
			Tags: []string{"system", "authentication", "passwords"},
		},
		{
			ID: "file-003", Path: "/var/www/html/index.html", Filename: "index.html",
			Size: 4096, Permissions: "-rw-r--r--", Owner: "www-data", Group: "www-data",
			MD5Hash: "c4ca4238a0b923820dcc509a6f75849b", SHA256Hash: "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
			LastModified: time.Now().Add(-1 * time.Hour), LastChecked: time.Now().Add(-10 * time.Minute),
			Status: "ok", ChangeCount: 3, Severity: "high",
			ComplianceFrames: []string{"PCI-DSS 6.5"},
			Tags: []string{"web", "public"},
		},
		{
			ID: "file-004", Path: "/opt/app/config.json", Filename: "config.json",
			Size: 512, Permissions: "-rw-------", Owner: "appuser", Group: "appuser",
			MD5Hash: "e4da3b7fbbce2345d7772b0674a318d5", SHA256Hash: "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
			LastModified: time.Now().Add(-30 * time.Minute), LastChecked: time.Now().Add(-1 * time.Minute),
			Status: "changed", ChangeCount: 2, Severity: "high",
			ComplianceFrames: []string{"ISO27001"},
			Tags: []string{"application", "configuration"},
		},
		{
			ID: "file-005", Path: "/etc/hosts", Filename: "hosts",
			Size: 256, Permissions: "-rw-r--r--", Owner: "root", Group: "root",
			MD5Hash: "1679091c5a880faf6fb5e6087eb1b2dc", SHA256Hash: "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
			LastModified: time.Now().Add(-48 * time.Hour), LastChecked: time.Now().Add(-3 * time.Minute),
			Status: "ok", ChangeCount: 0, Severity: "medium",
			ComplianceFrames: []string{"PCI-DSS 11.5"},
			Tags: []string{"system", "network"},
		},
	}

	return files
}

func generateMockFileChanges() []FileChange {
	changes := []FileChange{
		{
			ID: "change-001", FileID: "file-002", FilePath: "/etc/shadow",
			ChangeType: "modified", DetectedAt: time.Now().Add(-15 * time.Minute),
			OldHash: "098f6bcd4621d373cade4e832627b4f6", NewHash: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
			OldSize: 1020, NewSize: 1024,
			Severity: "critical", AlertGenerated: true, Acknowledged: false,
		},
		{
			ID: "change-002", FileID: "file-004", FilePath: "/opt/app/config.json",
			ChangeType: "modified", DetectedAt: time.Now().Add(-30 * time.Minute),
			OldHash: "c4ca4238a0b923820dcc509a6f75849b", NewHash: "e4da3b7fbbce2345d7772b0674a318d5",
			OldSize: 498, NewSize: 512,
			Severity: "high", AlertGenerated: true, Acknowledged: false,
		},
		{
			ID: "change-003", FileID: "file-006", FilePath: "/var/log/auth.log",
			ChangeType: "modified", DetectedAt: time.Now().Add(-45 * time.Minute),
			OldSize: 102400, NewSize: 104448,
			Severity: "low", AlertGenerated: false, Acknowledged: true,
			AcknowledgedBy: "admin@company.com", AcknowledgedAt: time.Now().Add(-30 * time.Minute),
			Notes: "Normal log rotation",
		},
		{
			ID: "change-004", FileID: "file-007", FilePath: "/etc/ssh/sshd_config",
			ChangeType: "permissions", DetectedAt: time.Now().Add(-2 * time.Hour),
			OldPermissions: "-rw-r--r--", NewPermissions: "-rw-------",
			Severity: "high", AlertGenerated: true, Acknowledged: true,
			AcknowledgedBy: "security@company.com", AcknowledgedAt: time.Now().Add(-1 * time.Hour),
			Notes: "Security hardening - restricted permissions",
		},
		{
			ID: "change-005", FileID: "file-008", FilePath: "/usr/bin/sudo",
			ChangeType: "modified", DetectedAt: time.Now().Add(-3 * time.Hour),
			OldHash: "abc123def456", NewHash: "def789ghi012",
			Severity: "critical", AlertGenerated: true, Acknowledged: false,
		},
	}

	return changes
}

func generateMockBaselines() []Baseline {
	baselines := []Baseline{
		{
			ID: "baseline-001", Name: "Production Server Baseline",
			Description: "Baseline for production web servers",
			CreatedAt: time.Now().Add(-30 * 24 * time.Hour),
			CreatedBy: "admin@company.com", FileCount: 1234, Status: "active",
			Metadata: map[string]string{"environment": "production", "type": "web-server"},
		},
		{
			ID: "baseline-002", Name: "Database Server Baseline",
			Description: "Baseline for database servers",
			CreatedAt: time.Now().Add(-60 * 24 * time.Hour),
			CreatedBy: "dba@company.com", FileCount: 856, Status: "active",
			Metadata: map[string]string{"environment": "production", "type": "database"},
		},
		{
			ID: "baseline-003", Name: "Development Environment",
			Description: "Baseline for dev servers",
			CreatedAt: time.Now().Add(-90 * 24 * time.Hour),
			CreatedBy: "devops@company.com", FileCount: 2345, Status: "archived",
			Metadata: map[string]string{"environment": "development"},
		},
	}

	return baselines
}

func generateMockFIMRules() []FIMRule {
	rules := []FIMRule{
		{
			ID: "rule-001", Name: "System Configuration Files",
			Description: "Monitor critical system configuration files",
			Path: "/etc", Recursive: true, Enabled: true,
			AlertOn: []string{"modified", "deleted", "permissions"},
			Severity: "critical", Compliance: []string{"PCI-DSS 11.5", "HIPAA"},
			Exclude: []string{"*.log", "*.tmp"},
			CreatedAt: time.Now().Add(-90 * 24 * time.Hour),
			UpdatedAt: time.Now().Add(-10 * 24 * time.Hour),
		},
		{
			ID: "rule-002", Name: "Web Application Files",
			Description: "Monitor web application directory",
			Path: "/var/www", Recursive: true, Enabled: true,
			AlertOn: []string{"modified", "deleted", "created"},
			Severity: "high", Compliance: []string{"PCI-DSS 6.5"},
			Exclude: []string{"*.log", "cache/*"},
			CreatedAt: time.Now().Add(-60 * 24 * time.Hour),
			UpdatedAt: time.Now().Add(-5 * 24 * time.Hour),
		},
		{
			ID: "rule-003", Name: "Binary Files",
			Description: "Monitor system binaries",
			Path: "/usr/bin", Recursive: false, Enabled: true,
			AlertOn: []string{"modified", "deleted"},
			Severity: "critical", Compliance: []string{"PCI-DSS 11.5", "SOC2"},
			Exclude: []string{},
			CreatedAt: time.Now().Add(-120 * 24 * time.Hour),
			UpdatedAt: time.Now().Add(-30 * 24 * time.Hour),
		},
	}

	return rules
}

func generateMockFIMAlerts() []FIMAlert {
	alerts := []FIMAlert{
		{
			ID: "alert-001", FileID: "file-002", FilePath: "/etc/shadow",
			ChangeID: "change-001", ChangeType: "modified", Severity: "critical",
			Title: "Critical System File Modified", Description: "Password file /etc/shadow has been modified",
			DetectedAt: time.Now().Add(-15 * time.Minute), Status: "new",
			MitreIDs: []string{"T1078", "T1098"},
		},
		{
			ID: "alert-002", FileID: "file-004", FilePath: "/opt/app/config.json",
			ChangeID: "change-002", ChangeType: "modified", Severity: "high",
			Title: "Application Configuration Changed", Description: "Application config file has been modified",
			DetectedAt: time.Now().Add(-30 * time.Minute), Status: "investigating",
			AssignedTo: "devops@company.com",
			MitreIDs: []string{"T1496"},
		},
		{
			ID: "alert-003", FileID: "file-007", FilePath: "/etc/ssh/sshd_config",
			ChangeID: "change-004", ChangeType: "permissions", Severity: "high",
			Title: "SSH Configuration Permissions Changed", Description: "SSH config permissions changed to more restrictive",
			DetectedAt: time.Now().Add(-2 * time.Hour), Status: "resolved",
			AssignedTo: "security@company.com", ResolvedAt: time.Now().Add(-1 * time.Hour),
			ResolvedBy: "security@company.com", Resolution: "Authorized security hardening",
		},
	}

	return alerts
}

func generateMockTopChangedFiles() []MonitoredFile {
	files := []MonitoredFile{
		{
			ID: "file-101", Path: "/var/log/syslog", Filename: "syslog",
			Size: 1048576, Permissions: "-rw-r--r--", Owner: "syslog", Group: "adm",
			Status: "ok", ChangeCount: 2847, Severity: "low",
			Tags: []string{"logs"},
		},
		{
			ID: "file-102", Path: "/etc/hosts", Filename: "hosts",
			Size: 256, Permissions: "-rw-r--r--", Owner: "root", Group: "root",
			Status: "ok", ChangeCount: 123, Severity: "medium",
			Tags: []string{"system", "network"},
		},
		{
			ID: "file-103", Path: "/etc/resolv.conf", Filename: "resolv.conf",
			Size: 128, Permissions: "-rw-r--r--", Owner: "root", Group: "root",
			Status: "ok", ChangeCount: 87, Severity: "medium",
			Tags: []string{"system", "network"},
		},
	}

	return files
}

func generateMockChangesTrend() []ChangeTrend {
	trend := []ChangeTrend{}
	now := time.Now()
	
	for i := 23; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		trend = append(trend, ChangeTrend{
			Timestamp:    t,
			ChangeCount:  5 + (i % 12),
			FileModified: 3 + (i % 8),
			FileDeleted:  (i % 5),
			FileCreated:  (i % 6),
		})
	}
	
	return trend
}

func generateID() string {
	data := []byte(time.Now().String())
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])[:8]
}

