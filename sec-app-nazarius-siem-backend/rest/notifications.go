package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ═══════════════════════════════════════════════════════════════════════════
// NOTIFICATION SYSTEM
// ═══════════════════════════════════════════════════════════════════════════

// Notification represents a system notification
type Notification struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Message     string    `json:"message"`
	Type        string    `json:"type"` // info, warning, error, success
	Severity    string    `json:"severity"` // low, medium, high, critical
	Category    string    `json:"category"` // security, system, alert, report
	Read        bool      `json:"read"`
	UserID      string    `json:"user_id"`
	Source      string    `json:"source"`
	SourceID    string    `json:"source_id"`
	ActionURL   string    `json:"action_url,omitempty"`
	ActionLabel string    `json:"action_label,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ReadAt      *time.Time `json:"read_at,omitempty"`
}

// NotificationRule defines when and how to send notifications
type NotificationRule struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Enabled     bool                `json:"enabled"`
	Conditions  []RuleConditionNotif `json:"conditions"`
	Actions     []RuleActionNotif    `json:"actions"`
	Priority    int                 `json:"priority"`
	Cooldown    int                 `json:"cooldown"` // minutes
	LastTriggered *time.Time        `json:"last_triggered,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

// RuleConditionNotif defines notification trigger conditions
type RuleConditionNotif struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, gt, lt, contains, regex
	Value    interface{} `json:"value"`
}

// RuleActionNotif defines what to do when rule is triggered
type RuleActionNotif struct {
	Type       string                 `json:"type"` // notification, email, sms, webhook
	TemplateID string                 `json:"template_id,omitempty"`
	Channels   []string               `json:"channels"`
	Recipients []string               `json:"recipients,omitempty"`
	Config     map[string]interface{} `json:"config,omitempty"`
}

// NotificationTemplate for reusable notification formats
type NotificationTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        string            `json:"type"` // email, sms, push, in-app
	Subject     string            `json:"subject,omitempty"`
	Body        string            `json:"body"`
	Variables   []string          `json:"variables,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// NotificationChannel configuration
type NotificationChannel struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Type      string                 `json:"type"` // email, sms, webhook, slack, teams
	Enabled   bool                   `json:"enabled"`
	Config    map[string]interface{} `json:"config"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// NotificationStats for analytics
type NotificationStats struct {
	Total     int            `json:"total"`
	Unread    int            `json:"unread"`
	ByType    map[string]int `json:"by_type"`
	BySeverity map[string]int `json:"by_severity"`
	Recent    int            `json:"recent"` // last 24h
}

// ═══════════════════════════════════════════════════════════════════════════
// IN-MEMORY STORAGE (Replace with database in production)
// ═══════════════════════════════════════════════════════════════════════════

var (
	notifications        = make(map[string]*Notification)
	notificationRules    = make(map[string]*NotificationRule)
	notificationTemplates = make(map[string]*NotificationTemplate)
	notificationChannels  = make(map[string]*NotificationChannel)
)

// ═══════════════════════════════════════════════════════════════════════════
// API HANDLERS - NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════════════════

// handleListNotifications returns all notifications
func handleListNotifications(c *gin.Context) {
	userID := c.Query("user_id")
	unreadOnly := c.Query("unread") == "true"
	category := c.Query("category")
	limit := 50

	result := []*Notification{}
	for _, notif := range notifications {
		// Filter by user
		if userID != "" && notif.UserID != userID {
			continue
		}
		// Filter unread
		if unreadOnly && notif.Read {
			continue
		}
		// Filter category
		if category != "" && notif.Category != category {
			continue
		}
		result = append(result, notif)
	}

	// Sort by created_at desc and limit
	if len(result) > limit {
		result = result[:limit]
	}

	c.JSON(http.StatusOK, gin.H{
		"notifications": result,
		"total":         len(result),
	})
}

// handleGetNotification returns a single notification
func handleGetNotification(c *gin.Context) {
	id := c.Param("id")
	
	notif, exists := notifications[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Notification not found"})
		return
	}

	c.JSON(http.StatusOK, notif)
}

// handleCreateNotification creates a new notification
func handleCreateNotification(c *gin.Context) {
	var notif Notification
	if err := c.BindJSON(&notif); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	notif.ID = generateID()
	notif.CreatedAt = time.Now()
	notif.Read = false

	notifications[notif.ID] = &notif

	// Trigger notification delivery
	go deliverNotification(&notif)

	c.JSON(http.StatusCreated, notif)
}

// handleMarkAsRead marks notification as read
func handleMarkAsRead(c *gin.Context) {
	id := c.Param("id")
	
	notif, exists := notifications[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Notification not found"})
		return
	}

	notif.Read = true
	now := time.Now()
	notif.ReadAt = &now

	c.JSON(http.StatusOK, notif)
}

// handleMarkAllAsRead marks all user notifications as read
func handleMarkAllAsRead(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	count := 0
	for _, notif := range notifications {
		if notif.UserID == userID && !notif.Read {
			notif.Read = true
			now := time.Now()
			notif.ReadAt = &now
			count++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Notifications marked as read",
		"count":   count,
	})
}

// handleDeleteNotification deletes a notification
func handleDeleteNotification(c *gin.Context) {
	id := c.Param("id")
	
	if _, exists := notifications[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Notification not found"})
		return
	}

	delete(notifications, id)
	c.JSON(http.StatusOK, gin.H{"message": "Notification deleted"})
}

// handleGetNotificationStats returns notification statistics
func handleGetNotificationStats(c *gin.Context) {
	userID := c.Query("user_id")

	stats := NotificationStats{
		ByType:     make(map[string]int),
		BySeverity: make(map[string]int),
	}

	recent24h := time.Now().Add(-24 * time.Hour)

	for _, notif := range notifications {
		if userID != "" && notif.UserID != userID {
			continue
		}

		stats.Total++
		if !notif.Read {
			stats.Unread++
		}
		stats.ByType[notif.Type]++
		stats.BySeverity[notif.Severity]++
		
		if notif.CreatedAt.After(recent24h) {
			stats.Recent++
		}
	}

	c.JSON(http.StatusOK, stats)
}

// ═══════════════════════════════════════════════════════════════════════════
// API HANDLERS - RULES
// ═══════════════════════════════════════════════════════════════════════════

// handleListNotificationRules returns all notification rules
func handleListNotificationRules(c *gin.Context) {
	result := []*NotificationRule{}
	for _, rule := range notificationRules {
		result = append(result, rule)
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": result,
		"total": len(result),
	})
}

// handleCreateNotificationRule creates a new rule
func handleCreateNotificationRule(c *gin.Context) {
	var rule NotificationRule
	if err := c.BindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule.ID = generateID()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	notificationRules[rule.ID] = &rule

	c.JSON(http.StatusCreated, rule)
}

// handleUpdateNotificationRule updates a rule
func handleUpdateNotificationRule(c *gin.Context) {
	id := c.Param("id")
	
	rule, exists := notificationRules[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	var updates NotificationRule
	if err := c.BindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields
	if updates.Name != "" {
		rule.Name = updates.Name
	}
	if updates.Description != "" {
		rule.Description = updates.Description
	}
	rule.Enabled = updates.Enabled
	if len(updates.Conditions) > 0 {
		rule.Conditions = updates.Conditions
	}
	if len(updates.Actions) > 0 {
		rule.Actions = updates.Actions
	}
	if updates.Priority != 0 {
		rule.Priority = updates.Priority
	}
	if updates.Cooldown != 0 {
		rule.Cooldown = updates.Cooldown
	}
	rule.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, rule)
}

// handleDeleteNotificationRule deletes a rule
func handleDeleteNotificationRule(c *gin.Context) {
	id := c.Param("id")
	
	if _, exists := notificationRules[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	delete(notificationRules, id)
	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted"})
}

// ═══════════════════════════════════════════════════════════════════════════
// API HANDLERS - TEMPLATES
// ═══════════════════════════════════════════════════════════════════════════

// handleListNotificationTemplates returns all templates
func handleListNotificationTemplates(c *gin.Context) {
	result := []*NotificationTemplate{}
	for _, template := range notificationTemplates {
		result = append(result, template)
	}

	c.JSON(http.StatusOK, gin.H{
		"templates": result,
		"total":     len(result),
	})
}

// handleCreateNotificationTemplate creates a new template
func handleCreateNotificationTemplate(c *gin.Context) {
	var template NotificationTemplate
	if err := c.BindJSON(&template); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	template.ID = generateID()
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()

	notificationTemplates[template.ID] = &template

	c.JSON(http.StatusCreated, template)
}

// handleDeleteNotificationTemplate deletes a template
func handleDeleteNotificationTemplate(c *gin.Context) {
	id := c.Param("id")
	
	if _, exists := notificationTemplates[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
		return
	}

	delete(notificationTemplates, id)
	c.JSON(http.StatusOK, gin.H{"message": "Template deleted"})
}

// ═══════════════════════════════════════════════════════════════════════════
// API HANDLERS - CHANNELS
// ═══════════════════════════════════════════════════════════════════════════

// handleListNotificationChannels returns all channels
func handleListNotificationChannels(c *gin.Context) {
	result := []*NotificationChannel{}
	for _, channel := range notificationChannels {
		result = append(result, channel)
	}

	c.JSON(http.StatusOK, gin.H{
		"channels": result,
		"total":    len(result),
	})
}

// handleCreateNotificationChannel creates a new channel
func handleCreateNotificationChannel(c *gin.Context) {
	var channel NotificationChannel
	if err := c.BindJSON(&channel); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	channel.ID = generateID()
	channel.CreatedAt = time.Now()
	channel.UpdatedAt = time.Now()

	notificationChannels[channel.ID] = &channel

	c.JSON(http.StatusCreated, channel)
}

// handleUpdateNotificationChannel updates a channel
func handleUpdateNotificationChannel(c *gin.Context) {
	id := c.Param("id")
	
	channel, exists := notificationChannels[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Channel not found"})
		return
	}

	var updates NotificationChannel
	if err := c.BindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if updates.Name != "" {
		channel.Name = updates.Name
	}
	channel.Enabled = updates.Enabled
	if updates.Config != nil {
		channel.Config = updates.Config
	}
	channel.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, channel)
}

// handleDeleteNotificationChannel deletes a channel
func handleDeleteNotificationChannel(c *gin.Context) {
	id := c.Param("id")
	
	if _, exists := notificationChannels[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Channel not found"})
		return
	}

	delete(notificationChannels, id)
	c.JSON(http.StatusOK, gin.H{"message": "Channel deleted"})
}

// ═══════════════════════════════════════════════════════════════════════════
// NOTIFICATION DELIVERY SYSTEM
// ═══════════════════════════════════════════════════════════════════════════

// deliverNotification sends notification through configured channels
func deliverNotification(notif *Notification) {
	// Find applicable rules
	for _, rule := range notificationRules {
		if !rule.Enabled {
			continue
		}

		// Check cooldown
		if rule.LastTriggered != nil && rule.Cooldown > 0 {
			cooldownExpiry := rule.LastTriggered.Add(time.Duration(rule.Cooldown) * time.Minute)
			if time.Now().Before(cooldownExpiry) {
				continue
			}
		}

		// Evaluate conditions
		if evaluateRuleConditions(notif, rule.Conditions) {
			executeRuleActions(notif, rule.Actions)
			now := time.Now()
			rule.LastTriggered = &now
		}
	}
}

// evaluateRuleConditions checks if notification matches rule conditions
func evaluateRuleConditions(notif *Notification, conditions []RuleConditionNotif) bool {
	if len(conditions) == 0 {
		return true
	}

	for _, cond := range conditions {
		var fieldValue interface{}
		
		// Extract field value from notification
		switch cond.Field {
		case "type":
			fieldValue = notif.Type
		case "severity":
			fieldValue = notif.Severity
		case "category":
			fieldValue = notif.Category
		case "source":
			fieldValue = notif.Source
		default:
			// Check metadata
			if notif.Metadata != nil {
				fieldValue = notif.Metadata[cond.Field]
			}
		}

		// Evaluate operator
		if !evaluateCondition(fieldValue, cond.Operator, cond.Value) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single condition
func evaluateCondition(fieldValue interface{}, operator string, compareValue interface{}) bool {
	switch operator {
	case "eq":
		return fmt.Sprint(fieldValue) == fmt.Sprint(compareValue)
	case "ne":
		return fmt.Sprint(fieldValue) != fmt.Sprint(compareValue)
	case "contains":
		return contains(fmt.Sprint(fieldValue), fmt.Sprint(compareValue))
	default:
		return false
	}
}

// executeRuleActions performs rule actions
func executeRuleActions(notif *Notification, actions []RuleActionNotif) {
	for _, action := range actions {
		switch action.Type {
		case "email":
			sendEmail(notif, action)
		case "sms":
			sendSMS(notif, action)
		case "webhook":
			sendWebhook(notif, action)
		case "slack":
			sendSlack(notif, action)
		}
	}
}

// sendEmail sends email notification (placeholder)
func sendEmail(notif *Notification, action RuleActionNotif) {
	fmt.Printf("📧 Sending email notification: %s\n", notif.Title)
	// TODO: Implement actual email sending
}

// sendSMS sends SMS notification (placeholder)
func sendSMS(notif *Notification, action RuleActionNotif) {
	fmt.Printf("📱 Sending SMS notification: %s\n", notif.Title)
	// TODO: Implement actual SMS sending
}

// sendWebhook sends webhook notification (placeholder)
func sendWebhook(notif *Notification, action RuleActionNotif) {
	fmt.Printf("🔗 Sending webhook notification: %s\n", notif.Title)
	// TODO: Implement actual webhook sending
}

// sendSlack sends Slack notification (placeholder)
func sendSlack(notif *Notification, action RuleActionNotif) {
	fmt.Printf("💬 Sending Slack notification: %s\n", notif.Title)
	// TODO: Implement actual Slack integration
}

// ═══════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

func initNotificationSystem() {
	// Create default templates
	createDefaultTemplates()
	
	// Create default channels
	createDefaultChannels()
	
	// Create default rules
	createDefaultRules()
	
	// Create sample notifications
	createSampleNotifications()
}

func createDefaultTemplates() {
	templates := []NotificationTemplate{
		{
			ID:          "tmpl-security-alert",
			Name:        "Security Alert",
			Description: "Template for security alerts",
			Type:        "email",
			Subject:     "Security Alert: {{title}}",
			Body:        "A security alert has been triggered:\n\n{{message}}\n\nSeverity: {{severity}}\nTime: {{timestamp}}",
			Variables:   []string{"title", "message", "severity", "timestamp"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "tmpl-system-notification",
			Name:        "System Notification",
			Description: "Template for system notifications",
			Type:        "in-app",
			Body:        "{{message}}",
			Variables:   []string{"message"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, tmpl := range templates {
		notificationTemplates[tmpl.ID] = &tmpl
	}
}

func createDefaultChannels() {
	channels := []NotificationChannel{
		{
			ID:      "ch-email",
			Name:    "Email",
			Type:    "email",
			Enabled: true,
			Config: map[string]interface{}{
				"smtp_host": "smtp.example.com",
				"smtp_port": 587,
				"from":      "noreply@siem-platform.com",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:      "ch-slack",
			Name:    "Slack",
			Type:    "slack",
			Enabled: true,
			Config: map[string]interface{}{
				"webhook_url": "https://hooks.slack.com/services/...",
				"channel":     "#security-alerts",
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for _, ch := range channels {
		notificationChannels[ch.ID] = &ch
	}
}

func createDefaultRules() {
	rules := []NotificationRule{
		{
			ID:          "rule-critical-alerts",
			Name:        "Critical Security Alerts",
			Description: "Notify immediately for critical security alerts",
			Enabled:     true,
			Priority:    1,
			Cooldown:    0,
			Conditions: []RuleConditionNotif{
				{Field: "severity", Operator: "eq", Value: "critical"},
				{Field: "category", Operator: "eq", Value: "security"},
			},
			Actions: []RuleActionNotif{
				{
					Type:       "email",
					TemplateID: "tmpl-security-alert",
					Channels:   []string{"ch-email", "ch-slack"},
					Recipients: []string{"admin@example.com", "security@example.com"},
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for _, rule := range rules {
		notificationRules[rule.ID] = &rule
	}
}

func createSampleNotifications() {
	samples := []Notification{
		{
			ID:       "notif-1",
			Title:    "Critical Security Alert",
			Message:  "Suspicious login attempt detected from unknown location",
			Type:     "error",
			Severity: "critical",
			Category: "security",
			Read:     false,
			UserID:   "user-1",
			Source:   "Authentication System",
			SourceID: "auth-12345",
			ActionURL: "/security/alerts/12345",
			ActionLabel: "View Details",
			CreatedAt: time.Now().Add(-2 * time.Hour),
		},
		{
			ID:       "notif-2",
			Title:    "New Threat Detected",
			Message:  "ML model identified anomalous behavior in network traffic",
			Type:     "warning",
			Severity: "high",
			Category: "security",
			Read:     false,
			UserID:   "user-1",
			Source:   "ML Analytics",
			SourceID: "ml-67890",
			ActionURL: "/ml-analytics",
			ActionLabel: "Investigate",
			CreatedAt: time.Now().Add(-4 * time.Hour),
		},
		{
			ID:       "notif-3",
			Title:    "Report Generated Successfully",
			Message:  "Your monthly security report is ready for download",
			Type:     "success",
			Severity: "low",
			Category: "report",
			Read:     true,
			UserID:   "user-1",
			Source:   "Reporting Engine",
			SourceID: "report-111",
			ActionURL: "/reports",
			ActionLabel: "Download",
			CreatedAt: time.Now().Add(-1 * 24 * time.Hour),
		},
		{
			ID:       "notif-4",
			Title:    "System Maintenance Scheduled",
			Message:  "Scheduled maintenance window: Tomorrow 2:00 AM - 4:00 AM UTC",
			Type:     "info",
			Severity: "medium",
			Category: "system",
			Read:     false,
			UserID:   "user-1",
			Source:   "System",
			SourceID: "sys-maintenance",
			CreatedAt: time.Now().Add(-6 * time.Hour),
		},
		{
			ID:       "notif-5",
			Title:    "Incident Response Triggered",
			Message:  "Automated incident response playbook executed successfully",
			Type:     "success",
			Severity: "medium",
			Category: "security",
			Read:     false,
			UserID:   "user-1",
			Source:   "Incident Response",
			SourceID: "incident-999",
			ActionURL: "/incident-response",
			ActionLabel: "View Incident",
			CreatedAt: time.Now().Add(-30 * time.Minute),
		},
	}

	for _, notif := range samples {
		notifications[notif.ID] = &notif
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > 0 && (s[0:len(substr)] == substr || contains(s[1:], substr))))
}

// Helper function to marshal notification to JSON string (for logging)
func notificationToJSON(notif *Notification) string {
	data, _ := json.Marshal(notif)
	return string(data)
}
