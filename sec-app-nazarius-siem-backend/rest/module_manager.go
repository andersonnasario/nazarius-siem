package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opensearch-project/opensearch-go/v2"
)

const moduleConfigFile = "module_config.json"

// Module represents a system module
type Module struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"` // siem, mdr, threat, analytics, protection
	Description string    `json:"description"`
	Status      string    `json:"status"` // active, standby, disabled
	Path        string    `json:"path"`
	Icon        string    `json:"icon"`
	Badge       string    `json:"badge,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"` // IDs of required modules
	RequiredFor []string  `json:"required_for,omitempty"` // IDs of modules that require this
	Tier        string    `json:"tier"` // free, basic, premium, enterprise
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ModuleConfig represents module configuration
type ModuleConfig struct {
	EnabledModules  []string          `json:"enabled_modules"`
	DisabledModules []string          `json:"disabled_modules"`
	Settings        map[string]string `json:"settings"`
	UpdatedAt       time.Time         `json:"updated_at"`
	UpdatedBy       string            `json:"updated_by"`
}

// In-memory storage
var (
	modules      = make(map[string]Module)
	moduleConfig = ModuleConfig{
		EnabledModules:  []string{},
		DisabledModules: []string{},
		Settings:        make(map[string]string),
	}
	moduleMutex      sync.RWMutex
	moduleOpenSearch *opensearch.Client
)

// OpenSearch index for module configuration
const moduleConfigIndex = "siem-module-config"

// SetModuleOpenSearch sets the OpenSearch client for module persistence
func SetModuleOpenSearch(client *opensearch.Client) {
	moduleOpenSearch = client
	if client != nil {
		log.Println("✅ Module Manager: OpenSearch client configured for persistence")
		// Create index if not exists
		createModuleConfigIndex()
	}
}

// Initialize Module Manager
func initModuleManager() {
	moduleMutex.Lock()
	defer moduleMutex.Unlock()

	// Define all available modules
	allModules := []Module{
		// SIEM Base Modules
		{
			ID:          "dashboard",
			Name:        "Dashboard Principal",
			Category:    "siem",
			Description: "Dashboard principal com visão geral do sistema",
			Status:      "active",
			Path:        "/",
			Icon:        "DashboardIcon",
			Tier:        "free",
		},
		{
			ID:          "dashboard-executive",
			Name:        "Dashboard Executivo",
			Category:    "siem",
			Description: "Dashboard executivo com métricas de alto nível",
			Status:      "disabled", // SOC Monitoring: não necessário inicialmente
			Path:        "/executive",
			Icon:        "BusinessCenterIcon",
			Tier:        "premium",
		},
		{
			ID:          "events",
			Name:        "Event Monitoring",
			Category:    "siem",
			Description: "Monitoramento de eventos em tempo real",
			Status:      "active",
			Path:        "/events",
			Icon:        "EventNoteIcon",
			Tier:        "free",
		},
		{
			ID:          "alerts",
			Name:        "Alerts",
			Category:    "siem",
			Description: "Gerenciamento de alertas de segurança",
			Status:      "active",
			Path:        "/alerts",
			Icon:        "WarningIcon",
			Tier:        "free",
		},
		{
			ID:          "threat-intelligence",
			Name:        "Threat Intelligence",
			Category:    "threat",
			Description: "Inteligência de ameaças e IOCs",
			Status:      "active",
			Path:        "/threat-intelligence",
			Icon:        "TravelExploreIcon",
			Tier:        "basic",
		},
		{
			ID:          "cve-database",
			Name:        "CVE Database",
			Category:    "threat",
			Description: "Banco de dados de vulnerabilidades CVE com sincronização NVD",
			Status:      "active",
			Path:        "/cve-database",
			Icon:        "BugReportIcon",
			Badge:       "NVD",
			Tier:        "basic",
		},
		{
			ID:          "threat-hunting",
			Name:        "Threat Hunting",
			Category:    "threat",
			Description: "Caça proativa a ameaças",
			Status:      "active",
			Path:        "/hunting",
			Icon:        "SearchIcon",
			Tier:        "basic",
		},
		{
			ID:          "threat-hunting-platform",
			Name:        "Threat Hunting Platform",
			Category:    "threat",
			Description: "Plataforma avançada de threat hunting",
			Status:      "disabled", // SOC Monitoring: módulo avançado - desabilitado
			Path:        "/threat-hunting-platform",
			Icon:        "SearchIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "threat-hunting-ranking",
			Name:        "Hunters Ranking",
			Category:    "threat",
			Description: "Ranking de performance dos threat hunters",
			Status:      "disabled", // SOC Monitoring: módulo avançado - desabilitado
			Path:        "/threat-hunting-ranking",
			Icon:        "EmojiEventsIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "threat-hunting-history",
			Name:        "Hunting History",
			Category:    "threat",
			Description: "Histórico de atividades de threat hunting",
			Status:      "disabled", // SOC Monitoring: módulo avançado - desabilitado
			Path:        "/threat-hunting-history",
			Icon:        "HistoryIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "mitre-attack",
			Name:        "MITRE ATT&CK",
			Category:    "threat",
			Description: "Framework MITRE ATT&CK",
			Status:      "active",
			Path:        "/mitre-attack",
			Icon:        "SecurityIcon",
			Tier:        "basic",
		},
		{
			ID:          "compliance",
			Name:        "Compliance",
			Category:    "siem",
			Description: "Gestão de conformidade regulatória",
			Status:      "active",
			Path:        "/compliance",
			Icon:        "GavelIcon",
			Tier:        "basic",
		},
		// Protection & Compliance Modules
		{
			ID:          "vulnerabilities",
			Name:        "Vulnerabilidades",
			Category:    "protection",
			Description: "Gestão de vulnerabilidades com AWS Inspector",
			Status:      "active",
			Path:        "/vulnerabilities",
			Icon:        "BugReportIcon",
			Tier:        "basic",
		},
		{
			ID:          "pla-risk-matrix",
			Name:        "PLA Risk Matrix",
			Category:    "protection",
			Description: "Protection Level Agreements - Matriz de Risco com Guard Rails",
			Status:      "active",
			Path:        "/pla-risk-matrix",
			Icon:        "GavelIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "vulnerability-diagnostics",
			Name:        "Diagnóstico AWS",
			Category:    "protection",
			Description: "Diagnóstico de conectividade AWS Inspector e Security Hub",
			Status:      "active",
			Path:        "/vulnerability-diagnostics",
			Icon:        "CloudIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "edr",
			Name:        "EDR (Endpoint)",
			Category:    "protection",
			Description: "Endpoint Detection & Response",
			Status:      "disabled", // SOC Monitoring: módulo de resposta - desabilitado
			Path:        "/edr",
			Icon:        "DesktopWindowsIcon",
			Tier:        "premium",
		},
		{
			ID:          "network",
			Name:        "Network Analysis",
			Category:    "protection",
			Description: "Análise de tráfego de rede e VPC Flow Logs",
			Status:      "active",
			Path:        "/network",
			Icon:        "NetworkCheckIcon",
			Tier:        "basic",
		},
		{
			ID:          "file-integrity",
			Name:        "File Integrity",
			Category:    "protection",
			Description: "Monitoramento de integridade de arquivos",
			Status:      "disabled", // SOC Monitoring: módulo FIM - desabilitado
			Path:        "/file-integrity",
			Icon:        "FolderOpenIcon",
			Tier:        "basic",
		},
		{
			ID:          "dlp",
			Name:        "Data Loss Prevention",
			Category:    "protection",
			Description: "Prevenção contra perda de dados",
			Status:      "disabled", // SOC Monitoring: módulo de proteção ativa - desabilitado
			Path:        "/dlp",
			Icon:        "ShieldIcon",
			Tier:        "premium",
		},
		{
			ID:          "forensics",
			Name:        "Forensics",
			Category:    "siem",
			Description: "Análise forense de incidentes",
			Status:      "disabled", // SOC Monitoring: módulo de resposta - desabilitado
			Path:        "/forensics",
			Icon:        "BugReportIcon",
			Tier:        "premium",
		},

		// MDR Modules - Phase 1
		{
			ID:          "mdr-executive",
			Name:        "Executive Dashboard MDR",
			Category:    "mdr",
			Description: "Dashboard executivo para gestão MDR",
			Status:      "disabled", // Desativado - será habilitado quando MDR estiver em uso
			Path:        "/mdr-dashboard",
			Icon:        "DashboardIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "automated-response",
			Name:        "Automated Response",
			Category:    "mdr",
			Description: "Resposta automatizada a incidentes",
			Status:      "disabled", // Desativado - requer configuração de playbooks
			Path:        "/automated-response",
			Icon:        "AutoFixHighIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "alert-triage",
			Name:        "Alert Triage",
			Category:    "mdr",
			Description: "Triagem inteligente de alertas",
			Status:      "active",
			Path:        "/alert-triage",
			Icon:        "PsychologyIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "sla-metrics",
			Name:        "SLA & Metrics",
			Category:    "mdr",
			Description: "Métricas e SLA de atendimento",
			Status:      "active",
			Path:        "/sla-metrics",
			Icon:        "SpeedIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},

		// MDR Modules - Phase 2
		{
			ID:          "mdr-forensics",
			Name:        "Automated Forensics",
			Category:    "mdr",
			Description: "Análise forense automatizada",
			Status:      "disabled", // Desativado - requer integração com ferramentas forenses
			Path:        "/mdr-forensics",
			Icon:        "BugReportIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "mdr-threat-intel",
			Name:        "Threat Intel Platform",
			Category:    "mdr",
			Description: "Plataforma de inteligência de ameaças",
			Status:      "disabled", // SOC Monitoring: módulo MDR avançado - desabilitado
			Path:        "/mdr-threat-intel",
			Icon:        "SecurityIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "mdr-multi-tenancy",
			Name:        "Multi-Tenancy",
			Category:    "mdr",
			Description: "Gestão multi-tenant",
			Status:      "disabled", // SOC Monitoring: módulo MDR avançado - desabilitado
			Path:        "/mdr-multi-tenancy",
			Icon:        "BusinessIcon",
			Badge:       "NEW",
			Tier:        "enterprise",
		},

		// MDR Modules - Phase 3
		{
			ID:          "advanced-hunting",
			Name:        "Advanced Hunting",
			Category:    "mdr",
			Description: "Caça avançada a ameaças",
			Status:      "disabled", // SOC Monitoring: módulo avançado de resposta - desabilitado
			Path:        "/advanced-hunting",
			Icon:        "SearchIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "deception",
			Name:        "Deception Technology",
			Category:    "mdr",
			Description: "Tecnologia de decepção e honeypots",
			Status:      "disabled", // Desativado - requer infraestrutura de honeypots
			Path:        "/deception",
			Icon:        "ShieldIcon",
			Badge:       "NEW",
			Tier:        "enterprise",
		},
		{
			ID:          "continuous-validation",
			Name:        "Continuous Validation",
			Category:    "mdr",
			Description: "Validação contínua de segurança",
			Status:      "disabled", // SOC Monitoring: módulo avançado - desabilitado
			Path:        "/continuous-validation",
			Icon:        "SecurityIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "security-awareness",
			Name:        "Security Awareness",
			Category:    "mdr",
			Description: "Conscientização e treinamento de segurança",
			Status:      "disabled", // SOC Monitoring: módulo de treinamento - desabilitado
			Path:        "/security-awareness",
			Icon:        "SchoolIcon",
			Badge:       "NEW",
			Tier:        "basic",
		},

		// MDR Modules - Phase 4
		{
			ID:          "advanced-analytics",
			Name:        "Advanced Analytics",
			Category:    "mdr",
			Description: "Analytics avançado com ML",
			Status:      "disabled", // SOC Monitoring: módulo avançado - desabilitado
			Path:        "/advanced-analytics",
			Icon:        "PsychologyIcon",
			Badge:       "NEW",
			Tier:        "enterprise",
		},
		{
			ID:          "soar",
			Name:        "SOAR",
			Category:    "mdr",
			Description: "Security Orchestration, Automation and Response",
			Status:      "disabled", // Desativado - requer playbooks e integrações configuradas
			Path:        "/soar",
			Icon:        "AccountTreeIcon",
			Badge:       "NEW",
			Tier:        "enterprise",
		},
		{
			ID:          "threat-intel-fusion",
			Name:        "Threat Intel Fusion",
			Category:    "mdr",
			Description: "Fusão de inteligência de ameaças",
			Status:      "disabled", // SOC Monitoring: módulo avançado - desabilitado
			Path:        "/threat-intel-fusion",
			Icon:        "LinkIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "cspm",
			Name:        "CSPM",
			Category:    "mdr",
			Description: "Cloud Security Posture Management",
			Status:      "disabled", // SOC Monitoring: módulo CSPM - desabilitado (habilitar quando necessário)
			Path:        "/cspm",
			Icon:        "CloudIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "cspm-aws",
			Name:        "AWS Integrations",
			Category:    "mdr",
			Description: "Integrações AWS para CSPM",
			Status:      "disabled", // SOC Monitoring: módulo CSPM - desabilitado
			Path:        "/cspm-aws",
			Icon:        "CloudIcon",
			Badge:       "AWS",
			Tier:        "premium",
		},
		{
			ID:          "cspm-remediation",
			Name:        "Auto-Remediation",
			Category:    "mdr",
			Description: "Remediação automática de findings",
			Status:      "disabled", // Desativado - requer aprovação para ações automáticas
			Path:        "/cspm-remediation",
			Icon:        "AutoFixHighIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "cspm-alerts",
			Name:        "Sistema de Alertas",
			Category:    "mdr",
			Description: "Gerenciamento de alertas inteligentes",
			Status:      "disabled", // SOC Monitoring: módulo CSPM - desabilitado
			Path:        "/cspm-alerts",
			Icon:        "NotificationsActiveIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "cspm-pci-dss",
			Name:        "PCI-DSS Dashboard",
			Category:    "mdr",
			Description: "Dashboard de compliance PCI-DSS",
			Status:      "disabled", // SOC Monitoring: módulo CSPM - desabilitado
			Path:        "/cspm-pci-dss",
			Icon:        "AssessmentIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "cspm-drift",
			Name:        "Drift Detection",
			Category:    "mdr",
			Description: "Detecção de mudanças não autorizadas",
			Status:      "disabled", // SOC Monitoring: módulo CSPM - desabilitado
			Path:        "/cspm-drift",
			Icon:        "CompareArrowsIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "cspm-config-aggregator",
			Name:        "Config Aggregator",
			Category:    "mdr",
			Description: "Agregação multi-conta AWS",
			Status:      "disabled", // SOC Monitoring: módulo CSPM - desabilitado
			Path:        "/cspm-config-aggregator",
			Icon:        "AccountBalanceIcon",
			Badge:       "NEW",
			Tier:        "enterprise",
		},
		{
			ID:          "aws-connections",
			Name:        "AWS Connections",
			Category:    "mdr",
			Description: "Gerenciamento de credenciais AWS STS",
			Status:      "disabled", // SOC Monitoring: módulo avançado - desabilitado
			Path:        "/aws-connections",
			Icon:        "VpnKeyIcon",
			Badge:       "NEW",
			Tier:        "enterprise",
		},
		{
			ID:          "zero-trust",
			Name:        "Zero Trust",
			Category:    "mdr",
			Description: "Arquitetura Zero Trust",
			Status:      "disabled", // SOC Monitoring: módulo avançado - desabilitado
			Path:        "/zero-trust",
			Icon:        "VpnLockIcon",
			Badge:       "NEW",
			Tier:        "enterprise",
		},

		// Other Modules
		{
			ID:          "playbooks",
			Name:        "Playbooks",
			Category:    "protection",
			Description: "Playbooks de resposta a incidentes",
			Status:      "disabled", // SOC Monitoring: módulo de resposta - desabilitado
			Path:        "/playbooks",
			Icon:        "AssignmentIcon",
			Tier:        "basic",
		},
		{
			ID:          "cases",
			Name:        "Cases",
			Category:    "protection",
			Description: "Gerenciamento de casos de segurança",
			Status:      "active",
			Path:        "/cases",
			Icon:        "FolderOpenIcon",
			Tier:        "basic",
		},
		{
			ID:          "ai-analysis",
			Name:        "AI Analysis",
			Category:    "analytics",
			Description: "Análise com inteligência artificial",
			Status:      "standby",
			Path:        "/ai-analysis",
			Icon:        "SmartToyIcon",
			Tier:        "enterprise",
		},
		{
			ID:          "ueba",
			Name:        "UEBA",
			Category:    "analytics",
			Description: "User and Entity Behavior Analytics - Análise comportamental de usuários e entidades com ML",
			Status:      "active",
			Path:        "/ueba",
			Icon:        "PsychologyIcon",
			Badge:       "IA",
			Tier:        "enterprise",
		},
		{
			ID:          "dashboard-customizer",
			Name:        "Dashboard Customizer",
			Category:    "siem",
			Description: "Personalização de dashboards",
			Status:      "disabled", // Desativado - recurso em desenvolvimento
			Path:        "/dashboard-customizer",
			Icon:        "SettingsIcon",
			Badge:       "NEW",
			Tier:        "basic",
		},

		// Settings & Administration
		{
			ID:          "module-manager",
			Name:        "Module Manager",
			Category:    "settings",
			Description: "Gerenciamento de módulos do sistema",
			Status:      "active",
			Path:        "/module-manager",
			Icon:        "ExtensionIcon",
			Tier:        "free",
		},
		{
			ID:          "user-management",
			Name:        "User Management",
			Category:    "settings",
			Description: "Gerenciamento de usuários e permissões",
			Status:      "active",
			Path:        "/users",
			Icon:        "PeopleIcon",
			Tier:        "free",
		},
		{
			ID:          "integrations",
			Name:        "Integrations",
			Category:    "settings",
			Description: "Integrações com sistemas externos",
			Status:      "active",
			Path:        "/integrations",
			Icon:        "IntegrationInstructionsIcon",
			Tier:        "premium",
		},
		{
			ID:          "fortinet",
			Name:        "Fortinet Integration",
			Category:    "settings",
			Description: "Integração com FortiGate via Webhook",
			Status:      "active",
			Path:        "/fortinet",
			Icon:        "ShieldIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "cloudflare",
			Name:        "Cloudflare WAF",
			Category:    "settings",
			Description: "Integração com Cloudflare Web Application Firewall",
			Status:      "active",
			Path:        "/cloudflare",
			Icon:        "CloudIcon",
			Badge:       "NEW",
			Tier:        "premium",
		},
		{
			ID:          "configuration",
			Name:        "Configuration",
			Category:    "settings",
			Description: "Configurações gerais do sistema",
			Status:      "active",
			Path:        "/settings",
			Icon:        "SettingsIcon",
			Tier:        "free",
		},
	}

	// Initialize modules with defaults
	now := time.Now()
	for _, module := range allModules {
		module.CreatedAt = now
		module.UpdatedAt = now
		modules[module.ID] = module

		// Add to enabled list if active (default state)
		if module.Status == "active" {
			moduleConfig.EnabledModules = append(moduleConfig.EnabledModules, module.ID)
		} else {
			moduleConfig.DisabledModules = append(moduleConfig.DisabledModules, module.ID)
		}
	}

	moduleConfig.UpdatedAt = now
	moduleConfig.UpdatedBy = "system"
	
	// Load saved configuration (overrides defaults)
	loadModuleConfig()
	
	// Log module count for debugging
	log.Printf("✅ Module Manager initialized with %d modules", len(modules))
	log.Printf("✅ Active modules: %d, Disabled: %d", len(moduleConfig.EnabledModules), len(moduleConfig.DisabledModules))
}

// Handler: List all modules
func (s *APIServer) handleListModules(c *gin.Context) {
	moduleMutex.RLock()
	defer moduleMutex.RUnlock()

	moduleList := make([]Module, 0, len(modules))
	for _, module := range modules {
		moduleList = append(moduleList, module)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    moduleList,
	})
}

// Handler: Get module configuration
func (s *APIServer) handleGetModuleConfig(c *gin.Context) {
	moduleMutex.RLock()
	defer moduleMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    moduleConfig,
	})
}

// Handler: Update module status
func (s *APIServer) handleUpdateModuleStatus(c *gin.Context) {
	moduleID := c.Param("id")

	var request struct {
		Status string `json:"status" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request: " + err.Error(),
		})
		return
	}

	// Validate status
	if request.Status != "active" && request.Status != "standby" && request.Status != "disabled" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid status. Must be: active, standby, or disabled",
		})
		return
	}

	moduleMutex.Lock()
	defer moduleMutex.Unlock()

	// Check if module exists
	module, exists := modules[moduleID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Module not found",
		})
		return
	}

	// Update module status
	module.Status = request.Status
	module.UpdatedAt = time.Now()
	modules[moduleID] = module

	// Update config lists
	updateModuleConfig(moduleID, request.Status)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    module,
		"message": "Module status updated successfully",
	})
}

// Handler: Bulk update module status
func (s *APIServer) handleBulkUpdateModules(c *gin.Context) {
	var request struct {
		Modules []struct {
			ID     string `json:"id" binding:"required"`
			Status string `json:"status" binding:"required"`
		} `json:"modules" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request: " + err.Error(),
		})
		return
	}

	moduleMutex.Lock()
	defer moduleMutex.Unlock()

	updated := []Module{}
	failed := []string{}

	for _, req := range request.Modules {
		module, exists := modules[req.ID]
		if !exists {
			failed = append(failed, req.ID)
			continue
		}

		module.Status = req.Status
		module.UpdatedAt = time.Now()
		modules[req.ID] = module
		updateModuleConfig(req.ID, req.Status)
		updated = append(updated, module)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"updated": updated,
			"failed":  failed,
		},
		"message": "Bulk update completed",
	})
}

// Helper function to update module config
func updateModuleConfig(moduleID, status string) {
	// Remove from all lists
	moduleConfig.EnabledModules = removeFromSlice(moduleConfig.EnabledModules, moduleID)
	moduleConfig.DisabledModules = removeFromSlice(moduleConfig.DisabledModules, moduleID)

	// Add to appropriate list
	if status == "active" {
		moduleConfig.EnabledModules = append(moduleConfig.EnabledModules, moduleID)
	} else {
		moduleConfig.DisabledModules = append(moduleConfig.DisabledModules, moduleID)
	}

	moduleConfig.UpdatedAt = time.Now()
	
	// Persistir alterações
	saveModuleConfig()
}

// Helper function to remove item from slice
func removeFromSlice(slice []string, item string) []string {
	result := []string{}
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

// ============================================================================
// PERSISTENCE FUNCTIONS
// ============================================================================

// ModuleStatusPersistence stores module status for persistence
type ModuleStatusPersistence struct {
	ModuleStatuses map[string]string `json:"module_statuses"`
	UpdatedAt      time.Time         `json:"updated_at"`
	UpdatedBy      string            `json:"updated_by"`
}

// getConfigFilePath returns the path to the config file
func getConfigFilePath() string {
	// Try data directory first, then current directory
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}
	return filepath.Join(dataDir, moduleConfigFile)
}

// createModuleConfigIndex creates the OpenSearch index for module config
func createModuleConfigIndex() {
	if moduleOpenSearch == nil {
		return
	}
	
	mapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 1
		},
		"mappings": {
			"properties": {
				"module_statuses": { "type": "object", "enabled": true },
				"updated_at": { "type": "date" },
				"updated_by": { "type": "keyword" }
			}
		}
	}`
	
	res, err := moduleOpenSearch.Indices.Create(
		moduleConfigIndex,
		moduleOpenSearch.Indices.Create.WithBody(strings.NewReader(mapping)),
		moduleOpenSearch.Indices.Create.WithContext(context.Background()),
	)
	if err != nil {
		log.Printf("⚠️ Could not create module config index: %v", err)
		return
	}
	defer res.Body.Close()
	
	if res.IsError() {
		// Index might already exist, that's OK
		if !strings.Contains(res.String(), "resource_already_exists_exception") {
			log.Printf("⚠️ Index creation response: %s", res.String())
		}
	} else {
		log.Printf("✅ Module config index created: %s", moduleConfigIndex)
	}
}

// saveModuleConfig persists module configuration to OpenSearch (primary) and file (backup)
func saveModuleConfig() {
	persistence := ModuleStatusPersistence{
		ModuleStatuses: make(map[string]string),
		UpdatedAt:      time.Now(),
		UpdatedBy:      moduleConfig.UpdatedBy,
	}
	
	// Save status of each module
	for id, module := range modules {
		persistence.ModuleStatuses[id] = module.Status
	}
	
	// Primary: Save to OpenSearch
	if moduleOpenSearch != nil {
		saveModuleConfigToOpenSearch(persistence)
	}
	
	// Backup: Also save to file (in case OpenSearch is temporarily unavailable)
	saveModuleConfigToFile(persistence)
}

// saveModuleConfigToOpenSearch saves config to OpenSearch
func saveModuleConfigToOpenSearch(persistence ModuleStatusPersistence) {
	data, err := json.Marshal(persistence)
	if err != nil {
		log.Printf("⚠️ Failed to marshal module config for OpenSearch: %v", err)
		return
	}
	
	// Use a fixed document ID so we always update the same document
	res, err := moduleOpenSearch.Index(
		moduleConfigIndex,
		strings.NewReader(string(data)),
		moduleOpenSearch.Index.WithDocumentID("module-config"),
		moduleOpenSearch.Index.WithRefresh("true"),
		moduleOpenSearch.Index.WithContext(context.Background()),
	)
	if err != nil {
		log.Printf("⚠️ Failed to save module config to OpenSearch: %v", err)
		return
	}
	defer res.Body.Close()
	
	if res.IsError() {
		log.Printf("⚠️ OpenSearch error saving module config: %s", res.String())
		return
	}
	
	log.Printf("✅ Module config saved to OpenSearch")
}

// saveModuleConfigToFile saves config to local file as backup
func saveModuleConfigToFile(persistence ModuleStatusPersistence) {
	data, err := json.MarshalIndent(persistence, "", "  ")
	if err != nil {
		log.Printf("⚠️ Failed to marshal module config: %v", err)
		return
	}
	
	filePath := getConfigFilePath()
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		log.Printf("⚠️ Failed to save module config to %s: %v", filePath, err)
		return
	}
	
	log.Printf("✅ Module config backup saved to %s", filePath)
}

// loadModuleConfig loads module configuration from OpenSearch (primary) or file (fallback)
func loadModuleConfig() {
	// Try OpenSearch first
	if moduleOpenSearch != nil {
		if loadModuleConfigFromOpenSearch() {
			return
		}
		log.Println("⚠️ OpenSearch load failed, trying file fallback...")
	}
	
	// Fallback to file
	loadModuleConfigFromFile()
}

// loadModuleConfigFromOpenSearch loads config from OpenSearch
func loadModuleConfigFromOpenSearch() bool {
	if moduleOpenSearch == nil {
		return false
	}
	
	res, err := moduleOpenSearch.Get(
		moduleConfigIndex,
		"module-config",
		moduleOpenSearch.Get.WithContext(context.Background()),
	)
	if err != nil {
		log.Printf("⚠️ Failed to get module config from OpenSearch: %v", err)
		return false
	}
	defer res.Body.Close()
	
	if res.IsError() {
		if res.StatusCode == 404 {
			log.Println("ℹ️ No module config found in OpenSearch, using defaults")
			return false
		}
		log.Printf("⚠️ OpenSearch error: %s", res.String())
		return false
	}
	
	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		log.Printf("⚠️ Failed to decode OpenSearch response: %v", err)
		return false
	}
	
	source, ok := result["_source"].(map[string]interface{})
	if !ok {
		log.Printf("⚠️ Invalid OpenSearch response structure")
		return false
	}
	
	// Parse module statuses
	if moduleStatuses, ok := source["module_statuses"].(map[string]interface{}); ok {
		applyModuleStatuses(moduleStatuses, source)
		log.Printf("✅ Module config loaded from OpenSearch")
		log.Printf("✅ Active modules: %d, Disabled: %d", len(moduleConfig.EnabledModules), len(moduleConfig.DisabledModules))
		return true
	}
	
	return false
}

// loadModuleConfigFromFile loads config from local file
func loadModuleConfigFromFile() {
	filePath := getConfigFilePath()
	
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("ℹ️ No saved module config found at %s, using defaults", filePath)
			return
		}
		log.Printf("⚠️ Failed to read module config: %v", err)
		return
	}
	
	var persistence ModuleStatusPersistence
	if err := json.Unmarshal(data, &persistence); err != nil {
		log.Printf("⚠️ Failed to parse module config: %v", err)
		return
	}
	
	// Convert to interface map for reuse
	moduleStatuses := make(map[string]interface{})
	for k, v := range persistence.ModuleStatuses {
		moduleStatuses[k] = v
	}
	
	source := map[string]interface{}{
		"updated_at": persistence.UpdatedAt.Format(time.RFC3339),
		"updated_by": persistence.UpdatedBy,
	}
	
	applyModuleStatuses(moduleStatuses, source)
	log.Printf("✅ Module config loaded from file: %s", filePath)
	log.Printf("✅ Active modules: %d, Disabled: %d", len(moduleConfig.EnabledModules), len(moduleConfig.DisabledModules))
}

// applyModuleStatuses applies loaded statuses to modules
func applyModuleStatuses(moduleStatuses map[string]interface{}, source map[string]interface{}) {
	var updatedAt time.Time
	if ua, ok := source["updated_at"].(string); ok {
		updatedAt, _ = time.Parse(time.RFC3339, ua)
	}
	
	updatedBy := "system"
	if ub, ok := source["updated_by"].(string); ok {
		updatedBy = ub
	}
	
	// Reset lists before applying
	moduleConfig.EnabledModules = []string{}
	moduleConfig.DisabledModules = []string{}
	
	// Apply saved statuses
	for id, statusInterface := range moduleStatuses {
		status, ok := statusInterface.(string)
		if !ok {
			continue
		}
		
		if module, exists := modules[id]; exists {
			module.Status = status
			module.UpdatedAt = updatedAt
			modules[id] = module
			
			// Update enabled/disabled lists
			if status == "active" {
				moduleConfig.EnabledModules = append(moduleConfig.EnabledModules, id)
			} else {
				moduleConfig.DisabledModules = append(moduleConfig.DisabledModules, id)
			}
		}
	}
	
	// Add any new modules not in saved config (default to their initial status)
	for id, module := range modules {
		if _, exists := moduleStatuses[id]; !exists {
			if module.Status == "active" {
				if !moduleSliceContains(moduleConfig.EnabledModules, id) {
					moduleConfig.EnabledModules = append(moduleConfig.EnabledModules, id)
				}
			} else {
				if !moduleSliceContains(moduleConfig.DisabledModules, id) {
					moduleConfig.DisabledModules = append(moduleConfig.DisabledModules, id)
				}
			}
		}
	}
	
	moduleConfig.UpdatedAt = updatedAt
	moduleConfig.UpdatedBy = updatedBy
}

// moduleSliceContains checks if slice contains item
func moduleSliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

