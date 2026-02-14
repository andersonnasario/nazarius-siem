package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Report representa um relatório
type Report struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Template    string                 `json:"template"`
	Parameters  map[string]interface{} `json:"parameters"`
	Format      string                 `json:"format"` // pdf, excel, csv, json
	CreatedBy   string                 `json:"created_by"`
	CreatedAt   time.Time              `json:"created_at"`
	Status      string                 `json:"status"` // pending, generating, completed, failed
	FileURL     string                 `json:"file_url,omitempty"`
}

// ReportTemplate representa um template de relatório
type ReportTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Parameters  []TemplateParameter    `json:"parameters"`
	Sections    []ReportSection        `json:"sections"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TemplateParameter representa um parâmetro de template
type TemplateParameter struct {
	Name        string      `json:"name"`
	Label       string      `json:"label"`
	Type        string      `json:"type"` // text, date, daterange, select, multiselect
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
	Options     []string    `json:"options,omitempty"`
	Description string      `json:"description,omitempty"`
}

// ReportSection representa uma seção de relatório
type ReportSection struct {
	Title       string                 `json:"title"`
	Type        string                 `json:"type"` // summary, table, chart, metrics, text
	DataSource  string                 `json:"data_source"`
	Columns     []string               `json:"columns,omitempty"`
	ChartType   string                 `json:"chart_type,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

// ScheduledReport representa um relatório agendado
type ScheduledReport struct {
	ID         string                 `json:"id"`
	ReportID   string                 `json:"report_id"`
	Template   string                 `json:"template"`
	Parameters map[string]interface{} `json:"parameters"`
	Schedule   string                 `json:"schedule"` // cron format
	Format     string                 `json:"format"`
	Recipients []string               `json:"recipients"` // email addresses
	Enabled    bool                   `json:"enabled"`
	LastRun    *time.Time             `json:"last_run,omitempty"`
	NextRun    time.Time              `json:"next_run"`
	CreatedBy  string                 `json:"created_by"`
	CreatedAt  time.Time              `json:"created_at"`
}

// ReportData representa dados agregados para relatórios
type ReportData struct {
	Summary      map[string]interface{} `json:"summary"`
	Tables       map[string][]map[string]interface{} `json:"tables"`
	Charts       map[string]interface{} `json:"charts"`
	Metrics      []Metric               `json:"metrics"`
	GeneratedAt  time.Time              `json:"generated_at"`
}

// Metric representa uma métrica do relatório
type Metric struct {
	Name     string      `json:"name"`
	Value    interface{} `json:"value"`
	Unit     string      `json:"unit,omitempty"`
	Trend    string      `json:"trend,omitempty"` // up, down, stable
	Change   float64     `json:"change,omitempty"`
}

// Templates pré-configurados
var reportTemplates = []ReportTemplate{
	{
		ID:          "executive-summary",
		Name:        "Executive Summary Report",
		Description: "High-level security overview for executive leadership",
		Category:    "executive",
		Parameters: []TemplateParameter{
			{Name: "date_range", Label: "Date Range", Type: "daterange", Required: true},
			{Name: "include_trends", Label: "Include Trends", Type: "boolean", Default: true},
		},
		Sections: []ReportSection{
			{Title: "Security Overview", Type: "summary"},
			{Title: "Key Metrics", Type: "metrics"},
			{Title: "Top Threats", Type: "table"},
			{Title: "Trend Analysis", Type: "chart", ChartType: "line"},
		},
	},
	{
		ID:          "compliance-report",
		Name:        "Compliance Report",
		Description: "Compliance status report (PCI-DSS, HIPAA, SOC 2)",
		Category:    "compliance",
		Parameters: []TemplateParameter{
			{Name: "framework", Label: "Framework", Type: "select", Required: true, Options: []string{"PCI-DSS", "HIPAA", "SOC2", "ISO27001", "GDPR"}},
			{Name: "date_range", Label: "Date Range", Type: "daterange", Required: true},
		},
		Sections: []ReportSection{
			{Title: "Compliance Status", Type: "summary"},
			{Title: "Control Assessment", Type: "table"},
			{Title: "Findings", Type: "table"},
			{Title: "Remediation Plan", Type: "table"},
		},
	},
	{
		ID:          "incident-response",
		Name:        "Incident Response Report",
		Description: "Detailed incident investigation and response report",
		Category:    "incident",
		Parameters: []TemplateParameter{
			{Name: "incident_id", Label: "Incident ID", Type: "text", Required: false},
			{Name: "date_range", Label: "Date Range", Type: "daterange", Required: true},
			{Name: "severity", Label: "Severity", Type: "multiselect", Options: []string{"critical", "high", "medium", "low"}},
		},
		Sections: []ReportSection{
			{Title: "Incident Summary", Type: "summary"},
			{Title: "Timeline", Type: "table"},
			{Title: "Impact Analysis", Type: "metrics"},
			{Title: "Response Actions", Type: "table"},
			{Title: "Lessons Learned", Type: "text"},
		},
	},
	{
		ID:          "vulnerability-assessment",
		Name:        "Vulnerability Assessment Report",
		Description: "Comprehensive vulnerability scan and assessment results",
		Category:    "vulnerability",
		Parameters: []TemplateParameter{
			{Name: "date_range", Label: "Date Range", Type: "daterange", Required: true},
			{Name: "severity", Label: "Min Severity", Type: "select", Options: []string{"critical", "high", "medium", "low", "info"}},
		},
		Sections: []ReportSection{
			{Title: "Vulnerability Overview", Type: "summary"},
			{Title: "Severity Distribution", Type: "chart", ChartType: "pie"},
			{Title: "Critical Vulnerabilities", Type: "table"},
			{Title: "Top Affected Assets", Type: "table"},
			{Title: "Remediation Timeline", Type: "chart", ChartType: "bar"},
		},
	},
	{
		ID:          "security-metrics",
		Name:        "Security Metrics Dashboard",
		Description: "Key security metrics and KPIs for operational tracking",
		Category:    "operations",
		Parameters: []TemplateParameter{
			{Name: "date_range", Label: "Date Range", Type: "daterange", Required: true},
			{Name: "comparison_period", Label: "Compare With", Type: "select", Options: []string{"previous_period", "previous_month", "previous_quarter"}},
		},
		Sections: []ReportSection{
			{Title: "KPI Summary", Type: "metrics"},
			{Title: "Event Trends", Type: "chart", ChartType: "line"},
			{Title: "Alert Analysis", Type: "chart", ChartType: "bar"},
			{Title: "Performance Metrics", Type: "table"},
		},
	},
}

// handleListReportTemplates retorna lista de templates
func handleListReportTemplates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"templates": reportTemplates,
		"total":     len(reportTemplates),
	})
}

// handleGetReportTemplate retorna um template específico
func handleGetReportTemplate(c *gin.Context) {
	templateID := c.Param("id")

	for _, template := range reportTemplates {
		if template.ID == templateID {
			c.JSON(http.StatusOK, template)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
}

// handleGenerateReport gera um novo relatório
func handleGenerateReport(c *gin.Context) {
	var req struct {
		Template   string                 `json:"template"`
		Parameters map[string]interface{} `json:"parameters"`
		Format     string                 `json:"format"`
		Name       string                 `json:"name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleGenerateReport bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Gera ID do relatório
	reportID := "report-" + generateID()

	// Cria relatório
	report := Report{
		ID:          reportID,
		Name:        req.Name,
		Template:    req.Template,
		Parameters:  req.Parameters,
		Format:      req.Format,
		CreatedBy:   "current-user", // TODO: pegar do context
		CreatedAt:   time.Now(),
		Status:      "generating",
	}

	// Em produção, isso seria assíncrono
	// Aqui vamos simular geração rápida
	data := generateReportData(req.Template, req.Parameters)

	// Gera arquivo baseado no formato
	var fileURL string
	switch req.Format {
	case "pdf":
		fileURL = "/reports/" + reportID + ".pdf"
	case "excel":
		fileURL = "/reports/" + reportID + ".xlsx"
	case "csv":
		fileURL = "/reports/" + reportID + ".csv"
	case "json":
		fileURL = "/reports/" + reportID + ".json"
	}

	report.Status = "completed"
	report.FileURL = fileURL

	c.JSON(http.StatusOK, gin.H{
		"report": report,
		"data":   data,
	})
}

// generateReportData gera dados mockados para o relatório
func generateReportData(templateID string, params map[string]interface{}) ReportData {
	data := ReportData{
		GeneratedAt: time.Now(),
		Summary:     make(map[string]interface{}),
		Tables:      make(map[string][]map[string]interface{}),
		Charts:      make(map[string]interface{}),
		Metrics:     []Metric{},
	}

	switch templateID {
	case "executive-summary":
		data.Summary = map[string]interface{}{
			"total_events":       125430,
			"total_alerts":       2847,
			"critical_incidents": 12,
			"resolved_incidents": 105,
			"avg_response_time":  "2.3 hours",
		}
		data.Metrics = []Metric{
			{Name: "Security Score", Value: 87.5, Unit: "%", Trend: "up", Change: 2.3},
			{Name: "Mean Time to Detect", Value: 15, Unit: "min", Trend: "down", Change: -5.2},
			{Name: "Mean Time to Respond", Value: 138, Unit: "min", Trend: "down", Change: -12.5},
			{Name: "False Positive Rate", Value: 8.2, Unit: "%", Trend: "down", Change: -1.8},
		}

	case "compliance-report":
		framework := "PCI-DSS"
		if fw, ok := params["framework"].(string); ok {
			framework = fw
		}
		data.Summary = map[string]interface{}{
			"framework":          framework,
			"compliance_status":  "Compliant",
			"total_controls":     250,
			"compliant_controls": 242,
			"compliance_rate":    96.8,
			"findings":           8,
		}

	case "incident-response":
		data.Summary = map[string]interface{}{
			"total_incidents":    87,
			"critical":           5,
			"high":               18,
			"medium":             45,
			"low":                19,
			"avg_resolution_time": "4.2 hours",
		}

	case "vulnerability-assessment":
		data.Summary = map[string]interface{}{
			"total_vulnerabilities": 1247,
			"critical":              32,
			"high":                  156,
			"medium":                543,
			"low":                   516,
			"remediation_rate":      82.5,
		}

	case "security-metrics":
		data.Metrics = []Metric{
			{Name: "Events/Second", Value: 342.5, Unit: "eps", Trend: "stable", Change: 0.5},
			{Name: "Alert Volume", Value: 2847, Unit: "alerts", Trend: "down", Change: -12.3},
			{Name: "Incident Count", Value: 87, Unit: "incidents", Trend: "down", Change: -8.5},
			{Name: "MTTD", Value: 15, Unit: "min", Trend: "down", Change: -5.2},
			{Name: "MTTR", Value: 138, Unit: "min", Trend: "down", Change: -12.5},
		}
	}

	return data
}

// handleExportReportPDF exporta relatório como PDF
func handleExportReportPDF(c *gin.Context) {
	reportID := c.Param("id")

	// Em produção, isso geraria um PDF real
	// Por enquanto, retorna headers adequados
	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pdf", reportID))
	
	// Mock PDF content
	c.String(http.StatusOK, "PDF Report Content - "+reportID)
}

// handleExportReportExcel exporta relatório como Excel
func handleExportReportExcel(c *gin.Context) {
	reportID := c.Param("id")

	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.xlsx", reportID))
	
	c.String(http.StatusOK, "Excel Report Content - "+reportID)
}

// handleExportReportCSV exporta relatório como CSV
func handleExportReportCSV(c *gin.Context) {
	reportID := c.Param("id")

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", reportID))
	
	w := csv.NewWriter(c.Writer)
	defer w.Flush()

	// Mock CSV data
	w.Write([]string{"Metric", "Value", "Trend"})
	w.Write([]string{"Total Events", "125430", "up"})
	w.Write([]string{"Total Alerts", "2847", "down"})
	w.Write([]string{"Critical Incidents", "12", "stable"})
}

// handleListReports lista relatórios gerados
func handleListReports(c *gin.Context) {
	// Mock data
	reports := []Report{
		{
			ID:          "report-001",
			Name:        "Monthly Executive Summary",
			Template:    "executive-summary",
			Format:      "pdf",
			CreatedBy:   "admin",
			CreatedAt:   time.Now().Add(-24 * time.Hour),
			Status:      "completed",
			FileURL:     "/reports/report-001.pdf",
		},
		{
			ID:          "report-002",
			Name:        "Q4 Compliance Report",
			Template:    "compliance-report",
			Format:      "excel",
			CreatedBy:   "compliance-officer",
			CreatedAt:   time.Now().Add(-48 * time.Hour),
			Status:      "completed",
			FileURL:     "/reports/report-002.xlsx",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"reports": reports,
		"total":   len(reports),
	})
}

// handleCreateScheduledReport cria um relatório agendado
func handleCreateScheduledReport(c *gin.Context) {
	var req ScheduledReport

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleCreateScheduledReport bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	req.ID = "schedule-" + generateID()
	req.CreatedAt = time.Now()
	req.CreatedBy = "current-user"
	req.Enabled = true
	req.NextRun = calculateNextRun(req.Schedule)

	c.JSON(http.StatusCreated, req)
}

// handleListScheduledReports lista relatórios agendados
func handleListScheduledReports(c *gin.Context) {
	// Mock data
	schedules := []ScheduledReport{
		{
			ID:         "schedule-001",
			Template:   "executive-summary",
			Schedule:   "0 9 1 * *", // 1st day of month at 9am
			Format:     "pdf",
			Recipients: []string{"ceo@company.com", "ciso@company.com"},
			Enabled:    true,
			NextRun:    time.Now().Add(24 * time.Hour),
			CreatedBy:  "admin",
			CreatedAt:  time.Now().Add(-30 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"schedules": schedules,
		"total":     len(schedules),
	})
}

// calculateNextRun calcula próxima execução baseado no cron
func calculateNextRun(cronExpr string) time.Time {
	// Simulação simples - em produção usar biblioteca de cron
	return time.Now().Add(24 * time.Hour)
}

// handleGetReportStats retorna estatísticas de relatórios
func handleGetReportStats(c *gin.Context) {
	stats := gin.H{
		"total_reports":         147,
		"reports_this_month":    23,
		"scheduled_reports":     8,
		"most_used_template":    "executive-summary",
		"avg_generation_time":   "2.3s",
		"formats_distribution": gin.H{
			"pdf":   65,
			"excel": 45,
			"csv":   27,
			"json":  10,
		},
		"templates_usage": gin.H{
			"executive-summary":       45,
			"compliance-report":       32,
			"incident-response":       28,
			"vulnerability-assessment": 25,
			"security-metrics":        17,
		},
	}

	c.JSON(http.StatusOK, stats)
}

