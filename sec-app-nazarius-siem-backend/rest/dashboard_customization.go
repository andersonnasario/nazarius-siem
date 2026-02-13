package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Widget representa um widget no dashboard
type Widget struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"` // kpi, chart, table, feed, etc
	Title      string                 `json:"title"`
	Config     map[string]interface{} `json:"config"`
	DataSource string                 `json:"data_source"`
	Position   WidgetPosition         `json:"position"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// WidgetPosition representa a posição de um widget no grid
type WidgetPosition struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	W      int `json:"w"` // width in grid units
	H      int `json:"h"` // height in grid units
	MinW   int `json:"minW,omitempty"`
	MinH   int `json:"minH,omitempty"`
	MaxW   int `json:"maxW,omitempty"`
	MaxH   int `json:"maxH,omitempty"`
	Static bool `json:"static,omitempty"`
}

// CustomDashboard representa um dashboard personalizado
type CustomDashboard struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	UserID      string    `json:"user_id"`
	Widgets     []Widget  `json:"widgets"`
	IsDefault   bool      `json:"is_default"`
	IsPublic    bool      `json:"is_public"`
	Template    string    `json:"template,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DashboardTemplate representa um template de dashboard
type DashboardTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"` // security, executive, operations, etc
	Widgets     []Widget `json:"widgets"`
	Preview     string   `json:"preview,omitempty"`
}

// WidgetType representa um tipo de widget disponível
type WidgetType struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Icon        string                 `json:"icon"`
	Category    string                 `json:"category"`
	DefaultSize WidgetPosition         `json:"default_size"`
	ConfigSchema map[string]interface{} `json:"config_schema,omitempty"`
}

// Templates pré-configurados
var dashboardTemplates = []DashboardTemplate{
	{
		ID:          "security-overview",
		Name:        "Security Overview",
		Description: "Comprehensive security monitoring dashboard",
		Category:    "security",
		Widgets: []Widget{
			{ID: "w1", Type: "kpi", Title: "Active Alerts", Position: WidgetPosition{X: 0, Y: 0, W: 3, H: 2}},
			{ID: "w2", Type: "kpi", Title: "Events/Second", Position: WidgetPosition{X: 3, Y: 0, W: 3, H: 2}},
			{ID: "w3", Type: "kpi", Title: "Open Incidents", Position: WidgetPosition{X: 6, Y: 0, W: 3, H: 2}},
			{ID: "w4", Type: "kpi", Title: "Security Score", Position: WidgetPosition{X: 9, Y: 0, W: 3, H: 2}},
			{ID: "w5", Type: "line-chart", Title: "Event Trends", Position: WidgetPosition{X: 0, Y: 2, W: 6, H: 4}},
			{ID: "w6", Type: "pie-chart", Title: "Alerts by Severity", Position: WidgetPosition{X: 6, Y: 2, W: 6, H: 4}},
			{ID: "w7", Type: "table", Title: "Recent Alerts", Position: WidgetPosition{X: 0, Y: 6, W: 12, H: 4}},
		},
	},
	{
		ID:          "executive-summary",
		Name:        "Executive Summary",
		Description: "High-level metrics for leadership",
		Category:    "executive",
		Widgets: []Widget{
			{ID: "e1", Type: "kpi", Title: "Risk Score", Position: WidgetPosition{X: 0, Y: 0, W: 4, H: 3}},
			{ID: "e2", Type: "kpi", Title: "Compliance Rate", Position: WidgetPosition{X: 4, Y: 0, W: 4, H: 3}},
			{ID: "e3", Type: "kpi", Title: "MTTR", Position: WidgetPosition{X: 8, Y: 0, W: 4, H: 3}},
			{ID: "e4", Type: "area-chart", Title: "Security Trends", Position: WidgetPosition{X: 0, Y: 3, W: 12, H: 5}},
			{ID: "e5", Type: "bar-chart", Title: "Top Threats", Position: WidgetPosition{X: 0, Y: 8, W: 6, H: 4}},
			{ID: "e6", Type: "gauge", Title: "Overall Health", Position: WidgetPosition{X: 6, Y: 8, W: 6, H: 4}},
		},
	},
	{
		ID:          "soc-operations",
		Name:        "SOC Operations",
		Description: "Real-time SOC monitoring and operations",
		Category:    "operations",
		Widgets: []Widget{
			{ID: "s1", Type: "kpi", Title: "Queue Size", Position: WidgetPosition{X: 0, Y: 0, W: 3, H: 2}},
			{ID: "s2", Type: "kpi", Title: "Avg Response Time", Position: WidgetPosition{X: 3, Y: 0, W: 3, H: 2}},
			{ID: "s3", Type: "kpi", Title: "Analysts Online", Position: WidgetPosition{X: 6, Y: 0, W: 3, H: 2}},
			{ID: "s4", Type: "status", Title: "System Status", Position: WidgetPosition{X: 9, Y: 0, W: 3, H: 2}},
			{ID: "s5", Type: "feed", Title: "Real-time Events", Position: WidgetPosition{X: 0, Y: 2, W: 4, H: 8}},
			{ID: "s6", Type: "alert-list", Title: "Priority Alerts", Position: WidgetPosition{X: 4, Y: 2, W: 4, H: 8}},
			{ID: "s7", Type: "timeline", Title: "Activity Timeline", Position: WidgetPosition{X: 8, Y: 2, W: 4, H: 8}},
		},
	},
	{
		ID:          "threat-hunting",
		Name:        "Threat Hunting",
		Description: "Advanced threat detection and analysis",
		Category:    "threat",
		Widgets: []Widget{
			{ID: "t1", Type: "heatmap", Title: "Attack Heatmap", Position: WidgetPosition{X: 0, Y: 0, W: 6, H: 4}},
			{ID: "t2", Type: "top-n", Title: "Top Attackers", Position: WidgetPosition{X: 6, Y: 0, W: 6, H: 4}},
			{ID: "t3", Type: "geo-map", Title: "Geographic Distribution", Position: WidgetPosition{X: 0, Y: 4, W: 12, H: 6}},
			{ID: "t4", Type: "table", Title: "IOC Matches", Position: WidgetPosition{X: 0, Y: 10, W: 12, H: 4}},
		},
	},
}

// Widget types disponíveis
var widgetTypes = []WidgetType{
	{Type: "kpi", Name: "KPI Card", Description: "Display a key performance indicator", Icon: "assessment", Category: "metrics", DefaultSize: WidgetPosition{W: 3, H: 2}},
	{Type: "line-chart", Name: "Line Chart", Description: "Time series line chart", Icon: "show_chart", Category: "charts", DefaultSize: WidgetPosition{W: 6, H: 4}},
	{Type: "bar-chart", Name: "Bar Chart", Description: "Vertical bar chart", Icon: "bar_chart", Category: "charts", DefaultSize: WidgetPosition{W: 6, H: 4}},
	{Type: "pie-chart", Name: "Pie Chart", Description: "Circular pie chart", Icon: "pie_chart", Category: "charts", DefaultSize: WidgetPosition{W: 4, H: 4}},
	{Type: "area-chart", Name: "Area Chart", Description: "Filled area chart", Icon: "area_chart", Category: "charts", DefaultSize: WidgetPosition{W: 6, H: 4}},
	{Type: "radar-chart", Name: "Radar Chart", Description: "Multi-dimensional radar chart", Icon: "radar", Category: "charts", DefaultSize: WidgetPosition{W: 4, H: 4}},
	{Type: "table", Name: "Data Table", Description: "Sortable and filterable table", Icon: "table_chart", Category: "data", DefaultSize: WidgetPosition{W: 12, H: 4}},
	{Type: "feed", Name: "Event Feed", Description: "Real-time event stream", Icon: "feed", Category: "realtime", DefaultSize: WidgetPosition{W: 4, H: 6}},
	{Type: "alert-list", Name: "Alert List", Description: "List of active alerts", Icon: "notification_important", Category: "alerts", DefaultSize: WidgetPosition{W: 4, H: 6}},
	{Type: "top-n", Name: "Top N Ranking", Description: "Top items ranking", Icon: "format_list_numbered", Category: "analytics", DefaultSize: WidgetPosition{W: 6, H: 4}},
	{Type: "heatmap", Name: "Heatmap", Description: "2D data heatmap", Icon: "grid_on", Category: "analytics", DefaultSize: WidgetPosition{W: 6, H: 4}},
	{Type: "timeline", Name: "Timeline", Description: "Event timeline visualization", Icon: "timeline", Category: "analytics", DefaultSize: WidgetPosition{W: 4, H: 6}},
	{Type: "gauge", Name: "Gauge Meter", Description: "Circular gauge meter", Icon: "speed", Category: "metrics", DefaultSize: WidgetPosition{W: 4, H: 4}},
	{Type: "geo-map", Name: "Geographic Map", Description: "World map with data points", Icon: "map", Category: "geo", DefaultSize: WidgetPosition{W: 12, H: 6}},
	{Type: "status", Name: "Status Indicator", Description: "System status display", Icon: "check_circle", Category: "monitoring", DefaultSize: WidgetPosition{W: 3, H: 2}},
	{Type: "activity-log", Name: "Activity Log", Description: "Recent activity log", Icon: "history", Category: "logs", DefaultSize: WidgetPosition{W: 6, H: 4}},
}

// handleListDashboards lista dashboards do usuário
func handleListDashboards(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		userID = "current-user" // TODO: pegar do context
	}

	// Mock data
	dashboards := []CustomDashboard{
		{
			ID:          "dash-001",
			Name:        "My Security Dashboard",
			Description: "Personal security monitoring",
			UserID:      userID,
			IsDefault:   true,
			IsPublic:    false,
			CreatedAt:   time.Now().Add(-30 * 24 * time.Hour),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "dash-002",
			Name:        "Executive View",
			Description: "High-level overview",
			UserID:      userID,
			IsDefault:   false,
			IsPublic:    true,
			Template:    "executive-summary",
			CreatedAt:   time.Now().Add(-15 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-2 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"dashboards": dashboards,
		"total":      len(dashboards),
	})
}

// handleGetDashboard retorna um dashboard específico
func handleGetDashboard(c *gin.Context) {
	dashboardID := c.Param("id")

	// Mock dashboard com widgets
	dashboard := CustomDashboard{
		ID:          dashboardID,
		Name:        "My Security Dashboard",
		Description: "Personal security monitoring",
		UserID:      "current-user",
		IsDefault:   true,
		IsPublic:    false,
		Widgets: []Widget{
			{
				ID:         "w1",
				Type:       "kpi",
				Title:      "Active Alerts",
				DataSource: "alerts.active",
				Position:   WidgetPosition{X: 0, Y: 0, W: 3, H: 2},
				Config: map[string]interface{}{
					"value":  127,
					"trend":  "+12%",
					"color":  "error",
				},
				CreatedAt: time.Now().Add(-24 * time.Hour),
				UpdatedAt: time.Now(),
			},
			{
				ID:         "w2",
				Type:       "line-chart",
				Title:      "Event Trends (24h)",
				DataSource: "events.timeseries",
				Position:   WidgetPosition{X: 3, Y: 0, W: 9, H: 4},
				Config: map[string]interface{}{
					"interval": "1h",
					"metric":   "count",
				},
				CreatedAt: time.Now().Add(-24 * time.Hour),
				UpdatedAt: time.Now(),
			},
		},
		CreatedAt: time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt: time.Now(),
	}

	c.JSON(http.StatusOK, dashboard)
}

// handleCreateDashboard cria um novo dashboard
func handleCreateDashboard(c *gin.Context) {
	var req CustomDashboard

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.ID = "dash-" + generateID()
	req.UserID = "current-user" // TODO: pegar do context
	req.CreatedAt = time.Now()
	req.UpdatedAt = time.Now()

	c.JSON(http.StatusCreated, req)
}

// handleUpdateDashboard atualiza um dashboard
func handleUpdateDashboardCustom(c *gin.Context) {
	dashboardID := c.Param("id")

	var req CustomDashboard
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.ID = dashboardID
	req.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, req)
}

// handleDeleteDashboard deleta um dashboard
func handleDeleteDashboardCustom(c *gin.Context) {
	dashboardID := c.Param("id")

	c.JSON(http.StatusOK, gin.H{
		"message": "Dashboard deleted successfully",
		"id":      dashboardID,
	})
}

// handleListTemplates lista templates disponíveis
func handleListTemplates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"templates": dashboardTemplates,
		"total":     len(dashboardTemplates),
	})
}

// handleGetTemplate retorna um template específico
func handleGetTemplate(c *gin.Context) {
	templateID := c.Param("id")

	for _, template := range dashboardTemplates {
		if template.ID == templateID {
			c.JSON(http.StatusOK, template)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
}

// handleCreateFromTemplate cria dashboard a partir de template
func handleCreateFromTemplate(c *gin.Context) {
	templateID := c.Param("id")

	var template *DashboardTemplate
	for _, t := range dashboardTemplates {
		if t.ID == templateID {
			template = &t
			break
		}
	}

	if template == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
		return
	}

	dashboard := CustomDashboard{
		ID:          "dash-" + generateID(),
		Name:        template.Name + " (Copy)",
		Description: template.Description,
		UserID:      "current-user",
		Widgets:     template.Widgets,
		IsDefault:   false,
		IsPublic:    false,
		Template:    templateID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	c.JSON(http.StatusCreated, dashboard)
}

// handleListWidgetTypes lista tipos de widgets disponíveis
func handleListWidgetTypes(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"widget_types": widgetTypes,
		"total":        len(widgetTypes),
	})
}

// handleAddWidget adiciona um widget ao dashboard
func handleAddWidget(c *gin.Context) {
	dashboardID := c.Param("id")

	var widget Widget
	if err := c.ShouldBindJSON(&widget); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	widget.ID = "w-" + generateID()
	widget.CreatedAt = time.Now()
	widget.UpdatedAt = time.Now()

	c.JSON(http.StatusCreated, gin.H{
		"dashboard_id": dashboardID,
		"widget":       widget,
	})
}

// handleUpdateWidget atualiza um widget
func handleUpdateWidget(c *gin.Context) {
	dashboardID := c.Param("id")
	widgetID := c.Param("widget_id")

	var widget Widget
	if err := c.ShouldBindJSON(&widget); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	widget.ID = widgetID
	widget.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, gin.H{
		"dashboard_id": dashboardID,
		"widget":       widget,
	})
}

// handleDeleteWidget remove um widget
func handleDeleteWidget(c *gin.Context) {
	dashboardID := c.Param("id")
	widgetID := c.Param("widget_id")

	c.JSON(http.StatusOK, gin.H{
		"message":      "Widget deleted successfully",
		"dashboard_id": dashboardID,
		"widget_id":    widgetID,
	})
}

// handleGetWidgetData retorna dados para um widget
func handleGetWidgetData(c *gin.Context) {
	widgetType := c.Query("type")
	dataSource := c.Query("source")

	// Mock data baseado no tipo de widget
	var data interface{}

	switch widgetType {
	case "kpi":
		data = gin.H{
			"value":     127,
			"label":     "Active Alerts",
			"trend":     "+12%",
			"trend_dir": "up",
			"color":     "error",
		}

	case "line-chart":
		data = gin.H{
			"labels": []string{"00:00", "04:00", "08:00", "12:00", "16:00", "20:00"},
			"datasets": []gin.H{
				{
					"label": "Events",
					"data":  []int{234, 189, 267, 312, 289, 245},
					"color": "#2196f3",
				},
			},
		}

	case "pie-chart":
		data = gin.H{
			"labels": []string{"Critical", "High", "Medium", "Low"},
			"data":    []int{12, 45, 78, 32},
			"colors":  []string{"#f44336", "#ff9800", "#ffc107", "#4caf50"},
		}

	case "table":
		data = gin.H{
			"columns": []string{"Time", "Severity", "Alert", "Source", "Status"},
			"rows": [][]interface{}{
				{"14:32:15", "Critical", "Brute Force Attack", "192.168.1.100", "Active"},
				{"14:28:42", "High", "SQL Injection Attempt", "10.0.0.45", "Investigating"},
				{"14:25:11", "High", "Malware Detected", "workstation-042", "Contained"},
			},
		}

	case "top-n":
		data = gin.H{
			"items": []gin.H{
				{"label": "192.168.1.100", "value": 245, "color": "#f44336"},
				{"label": "10.0.0.45", "value": 189, "color": "#ff9800"},
				{"label": "172.16.0.12", "value": 156, "color": "#ffc107"},
				{"label": "192.168.2.33", "value": 123, "color": "#4caf50"},
				{"label": "10.1.1.88", "value": 89, "color": "#2196f3"},
			},
		}

	case "gauge":
		data = gin.H{
			"value": 87.5,
			"min":   0,
			"max":   100,
			"label": "Security Score",
			"color": "#4caf50",
		}

	default:
		data = gin.H{
			"message": fmt.Sprintf("Widget type %s data", widgetType),
			"type":    widgetType,
			"source":  dataSource,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"widget_type": widgetType,
		"data_source": dataSource,
		"data":        data,
		"timestamp":   time.Now(),
	})
}

// handleExportDashboard exporta configuração do dashboard
func handleExportDashboard(c *gin.Context) {
	dashboardID := c.Param("id")

	dashboard := CustomDashboard{
		ID:          dashboardID,
		Name:        "Exported Dashboard",
		Description: "Dashboard configuration export",
		Widgets:     []Widget{},
	}

	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=dashboard-%s.json", dashboardID))
	c.JSON(http.StatusOK, dashboard)
}

// handleImportDashboard importa configuração de dashboard
func handleImportDashboard(c *gin.Context) {
	var dashboard CustomDashboard

	if err := c.ShouldBindJSON(&dashboard); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dashboard.ID = "dash-" + generateID()
	dashboard.UserID = "current-user"
	dashboard.CreatedAt = time.Now()
	dashboard.UpdatedAt = time.Now()

	c.JSON(http.StatusCreated, dashboard)
}

// handleGetDashboardStats retorna estatísticas
func handleGetDashboardStats(c *gin.Context) {
	stats := gin.H{
		"total_dashboards":  15,
		"public_dashboards": 3,
		"total_widgets":     87,
		"most_used_widget":  "kpi",
		"widget_usage": gin.H{
			"kpi":        28,
			"line-chart": 22,
			"table":      15,
			"pie-chart":  12,
			"bar-chart":  10,
		},
		"dashboards_by_template": gin.H{
			"security-overview": 6,
			"executive-summary": 4,
			"soc-operations":    3,
			"custom":            2,
		},
	}

	c.JSON(http.StatusOK, stats)
}

