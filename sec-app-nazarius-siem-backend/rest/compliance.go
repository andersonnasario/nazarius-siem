package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Global storage for compliance reports
var (
	complianceReportsMutex sync.RWMutex
	complianceReportsStore []ComplianceReport
	reportCounter          int
)

// ComplianceFramework representa um framework de compliance
type ComplianceFramework struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Version           string                 `json:"version"`
	ComplianceScore   float64                `json:"compliance_score"` // 0-100%
	TotalControls     int                    `json:"total_controls"`
	ImplementedControls int                  `json:"implemented_controls"`
	FailedControls    int                    `json:"failed_controls"`
	NotApplicable     int                    `json:"not_applicable"`
	LastAssessment    time.Time              `json:"last_assessment"`
	NextAssessment    time.Time              `json:"next_assessment"`
	Status            string                 `json:"status"` // compliant, non_compliant, in_progress
	Categories        []ComplianceCategory   `json:"categories"`
}

// ComplianceCategory representa uma categoria de controles
type ComplianceCategory struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`
	Description     string             `json:"description"`
	ComplianceScore float64            `json:"compliance_score"`
	Controls        []ComplianceControl `json:"controls"`
}

// ComplianceControl representa um controle específico
type ComplianceControl struct {
	ID              string    `json:"id"`
	ControlID       string    `json:"control_id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Status          string    `json:"status"` // implemented, failed, not_implemented, not_applicable
	Severity        string    `json:"severity"` // low, medium, high, critical
	LastChecked     time.Time `json:"last_checked"`
	Evidence        []string  `json:"evidence,omitempty"`
	RemediationPlan string    `json:"remediation_plan,omitempty"`
	Owner           string    `json:"owner,omitempty"`
	DueDate         *time.Time `json:"due_date,omitempty"`
}

// PolicyViolation representa uma violação de política
type PolicyViolation struct {
	ID              string                 `json:"id"`
	PolicyID        string                 `json:"policy_id"`
	PolicyName      string                 `json:"policy_name"`
	Framework       string                 `json:"framework"` // PCI-DSS, HIPAA, etc
	ControlID       string                 `json:"control_id"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	DetectedAt      time.Time              `json:"detected_at"`
	Source          string                 `json:"source"` // event_id, user_id, asset_id
	Status          string                 `json:"status"` // open, investigating, resolved, false_positive
	AssignedTo      string                 `json:"assigned_to,omitempty"`
	ResolutionNotes string                 `json:"resolution_notes,omitempty"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
	RelatedCase     string                 `json:"related_case,omitempty"`
	Details         map[string]interface{} `json:"details"`
}

// AuditLog representa uma entrada no audit trail
type AuditLog struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	UserID     string                 `json:"user_id"`
	Username   string                 `json:"username"`
	Action     string                 `json:"action"` // create, update, delete, view, export
	Resource   string                 `json:"resource"` // case, playbook, user, etc
	ResourceID string                 `json:"resource_id"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Status     string                 `json:"status"` // success, failed
	Details    map[string]interface{} `json:"details,omitempty"`
}

// ComplianceReport representa um relatório de compliance
type ComplianceReport struct {
	ID              string    `json:"id"`
	Framework       string    `json:"framework"`
	ReportType      string    `json:"report_type"` // executive, detailed, gap_analysis
	GeneratedAt     time.Time `json:"generated_at"`
	GeneratedBy     string    `json:"generated_by"`
	PeriodStart     time.Time `json:"period_start"`
	PeriodEnd       time.Time `json:"period_end"`
	ComplianceScore float64   `json:"compliance_score"`
	Summary         string    `json:"summary"`
	DownloadURL     string    `json:"download_url,omitempty"`
}

// ComplianceStats representa estatísticas de compliance
type ComplianceStats struct {
	TotalFrameworks     int     `json:"total_frameworks"`
	CompliantFrameworks int     `json:"compliant_frameworks"`
	OverallScore        float64 `json:"overall_score"`
	TotalViolations     int     `json:"total_violations"`
	OpenViolations      int     `json:"open_violations"`
	CriticalViolations  int     `json:"critical_violations"`
	ResolvedLast30Days  int     `json:"resolved_last_30_days"`
	AuditLogsLast24h    int     `json:"audit_logs_last_24h"`
	TotalControls       int     `json:"total_controls"`
	ImplementedControls int     `json:"implemented_controls"`
	FailedControls      int     `json:"failed_controls"`
	ComplianceTrend     string  `json:"compliance_trend"` // improving, declining, stable
}

// GapAnalysis representa análise de gaps
type GapAnalysis struct {
	Framework     string         `json:"framework"`
	TotalGaps     int            `json:"total_gaps"`
	CriticalGaps  int            `json:"critical_gaps"`
	Gaps          []ComplianceGap `json:"gaps"`
	RemediationTime string       `json:"remediation_time"`
}

// ComplianceGap representa um gap de compliance
type ComplianceGap struct {
	ControlID       string    `json:"control_id"`
	Title           string    `json:"title"`
	Severity        string    `json:"severity"`
	CurrentStatus   string    `json:"current_status"`
	RequiredStatus  string    `json:"required_status"`
	RemediationPlan string    `json:"remediation_plan"`
	EstimatedEffort string    `json:"estimated_effort"`
	DueDate         time.Time `json:"due_date"`
}

// Handlers

// handleGetComplianceDashboard retorna o dashboard completo de compliance
func (s *APIServer) handleGetComplianceDashboard(c *gin.Context) {
	stats := generateMockComplianceStats()
	frameworks := generateMockFrameworks()
	recentViolations := generateMockViolations(5)
	
	c.JSON(http.StatusOK, gin.H{
		"stats":              stats,
		"frameworks":         frameworks,
		"recent_violations":  recentViolations,
	})
}

// handleListFrameworks retorna lista de frameworks
func (s *APIServer) handleListFrameworks(c *gin.Context) {
	frameworks := generateMockFrameworks()
	c.JSON(http.StatusOK, gin.H{
		"frameworks": frameworks,
		"total":      len(frameworks),
	})
}

// handleGetFramework retorna detalhes de um framework específico
func (s *APIServer) handleGetFramework(c *gin.Context) {
	frameworkID := c.Param("id")
	framework := generateMockFrameworkDetails(frameworkID)
	c.JSON(http.StatusOK, framework)
}

// handleRunAssessment executa avaliação de compliance
func (s *APIServer) handleRunAssessment(c *gin.Context) {
	frameworkID := c.Param("id")
	
	result := gin.H{
		"framework_id":     frameworkID,
		"assessment_id":    "assess-" + frameworkID + "-001",
		"started_at":       time.Now(),
		"status":           "running",
		"estimated_time":   "5 minutes",
		"controls_to_check": 45,
	}
	
	c.JSON(http.StatusOK, result)
}

// handleListViolations retorna lista de violações
func (s *APIServer) handleListViolations(c *gin.Context) {
	severity := c.Query("severity")
	status := c.Query("status")
	
	violations := generateMockViolations(20)
	
	// Filtrar por severidade
	if severity != "" {
		filtered := []PolicyViolation{}
		for _, v := range violations {
			if v.Severity == severity {
				filtered = append(filtered, v)
			}
		}
		violations = filtered
	}
	
	// Filtrar por status
	if status != "" {
		filtered := []PolicyViolation{}
		for _, v := range violations {
			if v.Status == status {
				filtered = append(filtered, v)
			}
		}
		violations = filtered
	}
	
	c.JSON(http.StatusOK, gin.H{
		"violations": violations,
		"total":      len(violations),
	})
}

// handleUpdateViolation atualiza status de uma violação
func (s *APIServer) handleUpdateViolation(c *gin.Context) {
	violationID := c.Param("id")
	
	var update struct {
		Status          string `json:"status"`
		AssignedTo      string `json:"assigned_to,omitempty"`
		ResolutionNotes string `json:"resolution_notes,omitempty"`
	}
	
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Mock: retornar violação atualizada
	now := time.Now()
	violation := PolicyViolation{
		ID:              violationID,
		Status:          update.Status,
		AssignedTo:      update.AssignedTo,
		ResolutionNotes: update.ResolutionNotes,
		ResolvedAt:      &now,
	}
	
	c.JSON(http.StatusOK, violation)
}

// handleGetAuditTrail retorna audit trail
func (s *APIServer) handleGetAuditTrail(c *gin.Context) {
	logs := generateMockAuditLogs(50)
	c.JSON(http.StatusOK, gin.H{
		"audit_logs": logs,
		"total":      len(logs),
	})
}

// handleListAuditLogs é um alias para handleGetAuditTrail
func (s *APIServer) handleListAuditLogs(c *gin.Context) {
	s.handleGetAuditTrail(c)
}

// handleListControls retorna lista de controles
func (s *APIServer) handleListControls(c *gin.Context) {
	frameworkID := c.Query("framework")
	controls := []ComplianceControl{}
	
	if frameworkID != "" {
		framework := generateMockFrameworkDetails(frameworkID)
		for _, cat := range framework.Categories {
			controls = append(controls, cat.Controls...)
		}
	}
	
	c.JSON(http.StatusOK, gin.H{
		"controls": controls,
		"total":    len(controls),
	})
}

// handleUpdateControl atualiza um controle
func (s *APIServer) handleUpdateControl(c *gin.Context) {
	controlID := c.Param("id")
	
	var update struct {
		Status          string    `json:"status"`
		RemediationPlan string    `json:"remediation_plan,omitempty"`
		Owner           string    `json:"owner,omitempty"`
		DueDate         *time.Time `json:"due_date,omitempty"`
	}
	
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Mock: retornar controle atualizado
	control := ComplianceControl{
		ID:              controlID,
		Status:          update.Status,
		RemediationPlan: update.RemediationPlan,
		Owner:           update.Owner,
		DueDate:         update.DueDate,
		LastChecked:     time.Now(),
	}
	
	c.JSON(http.StatusOK, control)
}

// handleGenerateReport gera relatório de compliance
func (s *APIServer) handleGenerateComplianceReport(c *gin.Context) {
	var request struct {
		Framework   string    `json:"framework"`
		ReportType  string    `json:"report_type"`
		PeriodStart time.Time `json:"period_start"`
		PeriodEnd   time.Time `json:"period_end"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Lock para escrita
	complianceReportsMutex.Lock()
	reportCounter++
	reportID := fmt.Sprintf("report-%03d", reportCounter+100)
	complianceReportsMutex.Unlock()
	
	report := ComplianceReport{
		ID:              reportID,
		Framework:       request.Framework,
		ReportType:      request.ReportType,
		GeneratedAt:     time.Now(),
		GeneratedBy:     "admin@company.com",
		PeriodStart:     request.PeriodStart,
		PeriodEnd:       request.PeriodEnd,
		ComplianceScore: 87.5,
		Summary:         "Overall compliance is good. 3 critical gaps identified.",
		DownloadURL:     "/api/v1/compliance/reports/" + reportID + "/download",
	}
	
	// Adicionar à lista de relatórios
	complianceReportsMutex.Lock()
	complianceReportsStore = append(complianceReportsStore, report)
	complianceReportsMutex.Unlock()
	
	c.JSON(http.StatusCreated, report)
}

// handleDownloadComplianceReport faz download de um relatório
func (s *APIServer) handleDownloadComplianceReport(c *gin.Context) {
	reportID := c.Param("id")
	format := c.DefaultQuery("format", "html")
	
	// Buscar relatório (mock)
	report := ComplianceReport{
		ID:              reportID,
		Framework:       "pci_dss",
		ReportType:      "full_audit",
		GeneratedAt:     time.Now(),
		GeneratedBy:     "admin@company.com",
		PeriodStart:     time.Now().AddDate(0, -3, 0),
		PeriodEnd:       time.Now(),
		ComplianceScore: 87.5,
		Summary:         "Overall compliance is good. 3 critical gaps identified.",
	}
	
	if format == "html" {
		htmlContent := generateHTMLReport(report)
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Content-Disposition", "attachment; filename="+reportID+".html")
		c.String(http.StatusOK, htmlContent)
		return
	}
	
	// Para PDF, retornar mensagem informativa
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "PDF generation requires additional libraries",
		"note":    "Download HTML version instead",
		"report":  report,
	})
}

// generateHTMLReport gera conteúdo HTML do relatório
func generateHTMLReport(report ComplianceReport) string {
	return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Compliance - ` + report.Framework + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
        }
        .header {
            border-bottom: 3px solid #1976d2;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #1976d2;
            font-size: 32px;
            margin-bottom: 10px;
        }
        .header .meta {
            color: #666;
            font-size: 14px;
        }
        .section {
            margin: 30px 0;
        }
        .section h2 {
            color: #1976d2;
            font-size: 24px;
            margin-bottom: 15px;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 10px;
        }
        .score-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            text-align: center;
            margin: 20px 0;
        }
        .score-card .score {
            font-size: 64px;
            font-weight: bold;
            margin: 10px 0;
        }
        .score-card .label {
            font-size: 18px;
            opacity: 0.9;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .info-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #1976d2;
        }
        .info-card .label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        .info-card .value {
            font-size: 18px;
            font-weight: bold;
            color: #333;
        }
        .summary-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .summary-box h3 {
            color: #856404;
            margin-bottom: 10px;
        }
        .summary-box p {
            color: #856404;
        }
        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #e0e0e0;
            text-align: center;
            color: #666;
            font-size: 12px;
        }
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Relatório de Compliance</h1>
            <div class="meta">
                <strong>Framework:</strong> ` + report.Framework + ` | 
                <strong>Gerado em:</strong> ` + report.GeneratedAt.Format("02/01/2006 15:04") + ` | 
                <strong>Por:</strong> ` + report.GeneratedBy + `
            </div>
        </div>

        <div class="score-card">
            <div class="label">Score de Compliance</div>
            <div class="score">` + formatFloat(report.ComplianceScore) + `%</div>
            <div class="label">Status: Conforme</div>
        </div>

        <div class="section">
            <h2>Informações do Relatório</h2>
            <div class="info-grid">
                <div class="info-card">
                    <div class="label">ID do Relatório</div>
                    <div class="value">` + report.ID + `</div>
                </div>
                <div class="info-card">
                    <div class="label">Tipo</div>
                    <div class="value">` + report.ReportType + `</div>
                </div>
                <div class="info-card">
                    <div class="label">Período Inicial</div>
                    <div class="value">` + report.PeriodStart.Format("02/01/2006") + `</div>
                </div>
                <div class="info-card">
                    <div class="label">Período Final</div>
                    <div class="value">` + report.PeriodEnd.Format("02/01/2006") + `</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Resumo Executivo</h2>
            <div class="summary-box">
                <h3>⚠️ Principais Descobertas</h3>
                <p>` + report.Summary + `</p>
            </div>
        </div>

        <div class="section">
            <h2>Detalhes de Compliance</h2>
            <p>Este relatório foi gerado automaticamente pelo SIEM Platform e contém uma análise detalhada do estado de compliance da organização em relação ao framework ` + report.Framework + `.</p>
            <br>
            <p><strong>Próximos Passos:</strong></p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>Revisar os 3 gaps críticos identificados</li>
                <li>Implementar planos de ação corretiva</li>
                <li>Agendar reavaliação em 30 dias</li>
                <li>Documentar evidências de remediação</li>
            </ul>
        </div>

        <div class="footer">
            <p><strong>SIEM Platform</strong> - Sistema de Gerenciamento de Segurança da Informação</p>
            <p>Este documento é confidencial e destinado exclusivamente ao uso interno.</p>
            <p>Gerado automaticamente em ` + time.Now().Format("02/01/2006 às 15:04:05") + `</p>
        </div>
    </div>
</body>
</html>`
}

// formatFloat formata float para string com 1 casa decimal
func formatFloat(f float64) string {
	return fmt.Sprintf("%.1f", f)
}

// handleListReports retorna lista de relatórios
func (s *APIServer) handleListReports(c *gin.Context) {
	complianceReportsMutex.RLock()
	reports := make([]ComplianceReport, len(complianceReportsStore))
	copy(reports, complianceReportsStore)
	complianceReportsMutex.RUnlock()
	
	c.JSON(http.StatusOK, gin.H{
		"reports": reports,
		"total":   len(reports),
	})
}

// handleGetGapAnalysis retorna análise de gaps
func (s *APIServer) handleGetGapAnalysis(c *gin.Context) {
	frameworkID := c.Param("id")
	analysis := generateMockGapAnalysis(frameworkID)
	c.JSON(http.StatusOK, analysis)
}

// handleGetComplianceStats retorna estatísticas
func (s *APIServer) handleGetComplianceStats(c *gin.Context) {
	stats := generateMockComplianceStats()
	c.JSON(http.StatusOK, stats)
}

// Mock Data Generators

func generateMockComplianceStats() ComplianceStats {
	return ComplianceStats{
		TotalFrameworks:     5,
		CompliantFrameworks: 3,
		OverallScore:        82.5,
		TotalViolations:     147,
		OpenViolations:      23,
		CriticalViolations:  5,
		ResolvedLast30Days:  34,
		AuditLogsLast24h:    1247,
		TotalControls:       234,
		ImplementedControls: 189,
		FailedControls:      23,
		ComplianceTrend:     "improving",
	}
}

func generateMockFrameworks() []ComplianceFramework {
	now := time.Now()
	return []ComplianceFramework{
		{
			ID:                  "pci-dss",
			Name:                "PCI-DSS v4.0",
			Description:         "Payment Card Industry Data Security Standard",
			Version:             "4.0",
			ComplianceScore:     87.5,
			TotalControls:       45,
			ImplementedControls: 39,
			FailedControls:      3,
			NotApplicable:       3,
			LastAssessment:      now.AddDate(0, 0, -7),
			NextAssessment:      now.AddDate(0, 0, 23),
			Status:              "compliant",
		},
		{
			ID:                  "hipaa",
			Name:                "HIPAA",
			Description:         "Health Insurance Portability and Accountability Act",
			Version:             "2023",
			ComplianceScore:     92.3,
			TotalControls:       38,
			ImplementedControls: 35,
			FailedControls:      1,
			NotApplicable:       2,
			LastAssessment:      now.AddDate(0, 0, -14),
			NextAssessment:      now.AddDate(0, 0, 16),
			Status:              "compliant",
		},
		{
			ID:                  "gdpr",
			Name:                "GDPR",
			Description:         "General Data Protection Regulation",
			Version:             "2024",
			ComplianceScore:     78.2,
			TotalControls:       52,
			ImplementedControls: 41,
			FailedControls:      7,
			NotApplicable:       4,
			LastAssessment:      now.AddDate(0, 0, -21),
			NextAssessment:      now.AddDate(0, 0, 9),
			Status:              "non_compliant",
		},
		{
			ID:                  "soc2",
			Name:                "SOC 2 Type II",
			Description:         "Service Organization Control 2",
			Version:             "2024",
			ComplianceScore:     85.7,
			TotalControls:       67,
			ImplementedControls: 57,
			FailedControls:      5,
			NotApplicable:       5,
			LastAssessment:      now.AddDate(0, 0, -10),
			NextAssessment:      now.AddDate(0, 0, 20),
			Status:              "compliant",
		},
		{
			ID:                  "iso27001",
			Name:                "ISO 27001:2022",
			Description:         "Information Security Management System",
			Version:             "2022",
			ComplianceScore:     73.5,
			TotalControls:       114,
			ImplementedControls: 84,
			FailedControls:      18,
			NotApplicable:       12,
			LastAssessment:      now.AddDate(0, 0, -30),
			NextAssessment:      now.AddDate(0, 0, 0),
			Status:              "in_progress",
		},
	}
}

func generateMockFrameworkDetails(frameworkID string) ComplianceFramework {
	now := time.Now()
	framework := ComplianceFramework{
		ID:                  frameworkID,
		Name:                "PCI-DSS v4.0",
		Description:         "Payment Card Industry Data Security Standard",
		Version:             "4.0",
		ComplianceScore:     87.5,
		TotalControls:       45,
		ImplementedControls: 39,
		FailedControls:      3,
		NotApplicable:       3,
		LastAssessment:      now.AddDate(0, 0, -7),
		NextAssessment:      now.AddDate(0, 0, 23),
		Status:              "compliant",
		Categories: []ComplianceCategory{
			{
				ID:              "cat-1",
				Name:            "Build and Maintain a Secure Network",
				Description:     "Install and maintain network security controls",
				ComplianceScore: 90.0,
				Controls: []ComplianceControl{
					{
						ID:          "ctrl-1.1",
						ControlID:   "1.1",
						Title:       "Install and maintain network security controls",
						Description: "Network security controls (NSCs) must be installed and configured",
						Status:      "implemented",
						Severity:    "high",
						LastChecked: now.AddDate(0, 0, -1),
						Evidence:    []string{"firewall-config-2024.pdf", "network-diagram.png"},
						Owner:       "security@company.com",
					},
					{
						ID:              "ctrl-1.2",
						ControlID:       "1.2",
						Title:           "Apply secure configurations",
						Description:     "Apply secure configurations to all system components",
						Status:          "failed",
						Severity:        "critical",
						LastChecked:     now.AddDate(0, 0, -1),
						RemediationPlan: "Update firewall rules by end of week",
						Owner:           "infra@company.com",
						DueDate:         timePtr(now.AddDate(0, 0, 5)),
					},
				},
			},
		},
	}
	return framework
}

func generateMockViolations(count int) []PolicyViolation {
	now := time.Now()
	violations := []PolicyViolation{
		{
			ID:          "viol-001",
			PolicyID:    "pol-pci-001",
			PolicyName:  "Encryption of cardholder data",
			Framework:   "PCI-DSS",
			ControlID:   "3.4",
			Severity:    "critical",
			Description: "Unencrypted credit card data found in database",
			DetectedAt:  now.Add(-2 * time.Hour),
			Source:      "db-prod-01",
			Status:      "open",
			Details: map[string]interface{}{
				"database":       "payments_db",
				"table":          "transactions",
				"records_found":  127,
			},
		},
		{
			ID:              "viol-002",
			PolicyID:        "pol-hipaa-002",
			PolicyName:      "Access Control",
			Framework:       "HIPAA",
			ControlID:       "164.312(a)(1)",
			Severity:        "high",
			Description:     "Unauthorized access attempt to patient records",
			DetectedAt:      now.Add(-5 * time.Hour),
			Source:          "user-12345",
			Status:          "investigating",
			AssignedTo:      "security-team@company.com",
			Details: map[string]interface{}{
				"user_id":        "user-12345",
				"records_accessed": 5,
				"ip_address":     "192.168.1.100",
			},
		},
		{
			ID:              "viol-003",
			PolicyID:        "pol-gdpr-003",
			PolicyName:      "Data Retention",
			Framework:       "GDPR",
			ControlID:       "Art. 5(1)(e)",
			Severity:        "medium",
			Description:     "Personal data retained beyond required period",
			DetectedAt:      now.Add(-24 * time.Hour),
			Source:          "crm-system",
			Status:          "resolved",
			AssignedTo:      "compliance@company.com",
			ResolutionNotes: "Data purged according to retention policy",
			ResolvedAt:      timePtr(now.Add(-12 * time.Hour)),
			Details: map[string]interface{}{
				"records_deleted": 1543,
				"retention_period": "3 years",
			},
		},
	}
	
	if count < len(violations) {
		return violations[:count]
	}
	return violations
}

func generateMockAuditLogs(count int) []AuditLog {
	now := time.Now()
	logs := []AuditLog{
		{
			ID:         "log-001",
			Timestamp:  now.Add(-5 * time.Minute),
			UserID:     "user-123",
			Username:   "admin@company.com",
			Action:     "update",
			Resource:   "case",
			ResourceID: "case-456",
			IPAddress:  "192.168.1.50",
			UserAgent:  "Mozilla/5.0",
			Status:     "success",
			Details: map[string]interface{}{
				"field_changed": "status",
				"old_value":     "open",
				"new_value":     "resolved",
			},
		},
		{
			ID:         "log-002",
			Timestamp:  now.Add(-10 * time.Minute),
			UserID:     "user-456",
			Username:   "analyst@company.com",
			Action:     "view",
			Resource:   "compliance_report",
			ResourceID: "report-pci-001",
			IPAddress:  "192.168.1.51",
			UserAgent:  "Mozilla/5.0",
			Status:     "success",
		},
		{
			ID:         "log-003",
			Timestamp:  now.Add(-15 * time.Minute),
			UserID:     "user-789",
			Username:   "security@company.com",
			Action:     "export",
			Resource:   "audit_logs",
			ResourceID: "export-2024-01",
			IPAddress:  "192.168.1.52",
			UserAgent:  "Mozilla/5.0",
			Status:     "success",
			Details: map[string]interface{}{
				"format":      "csv",
				"rows_exported": 5000,
			},
		},
	}
	
	// Gerar mais logs se necessário
	result := []AuditLog{}
	for i := 0; i < count; i++ {
		result = append(result, logs[i%len(logs)])
	}
	
	return result
}

// initComplianceReports inicializa a lista de relatórios com dados mock
func initComplianceReports() {
	complianceReportsMutex.Lock()
	defer complianceReportsMutex.Unlock()
	
	now := time.Now()
	complianceReportsStore = []ComplianceReport{
		{
			ID:              "report-001",
			Framework:       "PCI-DSS",
			ReportType:      "executive",
			GeneratedAt:     now.AddDate(0, 0, -7),
			GeneratedBy:     "admin@company.com",
			PeriodStart:     now.AddDate(0, -1, 0),
			PeriodEnd:       now,
			ComplianceScore: 87.5,
			Summary:         "Overall compliance is good. Minor gaps identified.",
			DownloadURL:     "/api/v1/compliance/reports/report-001/download",
		},
		{
			ID:              "report-002",
			Framework:       "HIPAA",
			ReportType:      "detailed",
			GeneratedAt:     now.AddDate(0, 0, -14),
			GeneratedBy:     "compliance@company.com",
			PeriodStart:     now.AddDate(0, -1, 0),
			PeriodEnd:       now,
			ComplianceScore: 92.3,
			Summary:         "Excellent compliance. No critical issues.",
			DownloadURL:     "/api/v1/compliance/reports/report-002/download",
		},
	}
	reportCounter = 2
}

func generateMockGapAnalysis(frameworkID string) GapAnalysis {
	now := time.Now()
	return GapAnalysis{
		Framework:       frameworkID,
		TotalGaps:       7,
		CriticalGaps:    2,
		RemediationTime: "45 days",
		Gaps: []ComplianceGap{
			{
				ControlID:       "3.4",
				Title:           "Encryption of cardholder data at rest",
				Severity:        "critical",
				CurrentStatus:   "not_implemented",
				RequiredStatus:  "implemented",
				RemediationPlan: "Implement TDE for all databases containing CHD",
				EstimatedEffort: "2 weeks",
				DueDate:         now.AddDate(0, 0, 14),
			},
			{
				ControlID:       "8.2",
				Title:           "Multi-factor authentication",
				Severity:        "high",
				CurrentStatus:   "partially_implemented",
				RequiredStatus:  "fully_implemented",
				RemediationPlan: "Enable MFA for all administrative access",
				EstimatedEffort: "1 week",
				DueDate:         now.AddDate(0, 0, 7),
			},
		},
	}
}
