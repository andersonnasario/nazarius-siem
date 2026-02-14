package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Alert Channel Types
type AlertChannelType string

const (
	ChannelSlack     AlertChannelType = "slack"
	ChannelPagerDuty AlertChannelType = "pagerduty"
	ChannelEmail     AlertChannelType = "email"
	ChannelWebhook   AlertChannelType = "webhook"
	ChannelSMS       AlertChannelType = "sms"
)

// Alert Severity
type AlertSeverity string

const (
	SeverityCritical AlertSeverity = "critical"
	SeverityHigh     AlertSeverity = "high"
	SeverityMedium   AlertSeverity = "medium"
	SeverityLow      AlertSeverity = "low"
	SeverityInfo     AlertSeverity = "info"
)

// Alert Status
type AlertStatus string

const (
	AlertPending    AlertStatus = "pending"
	AlertSent       AlertStatus = "sent"
	AlertFailed     AlertStatus = "failed"
	AlertAcknowled  AlertStatus = "acknowledged"
	AlertResolved   AlertStatus = "resolved"
	AlertSuppressed AlertStatus = "suppressed"
)

// AlertChannel represents a notification channel configuration
type AlertChannel struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Type        AlertChannelType `json:"type"`
	Enabled     bool             `json:"enabled"`
	Config      ChannelConfig    `json:"config"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	LastUsedAt  *time.Time       `json:"last_used_at,omitempty"`
	SuccessRate float64          `json:"success_rate"`
	TotalSent   int              `json:"total_sent"`
	TotalFailed int              `json:"total_failed"`
}

// ChannelConfig holds channel-specific configuration
type ChannelConfig struct {
	// Slack
	WebhookURL string `json:"webhook_url,omitempty"`
	Channel    string `json:"channel,omitempty"`
	Username   string `json:"username,omitempty"`
	IconEmoji  string `json:"icon_emoji,omitempty"`

	// PagerDuty
	IntegrationKey string `json:"integration_key,omitempty"`
	RoutingKey     string `json:"routing_key,omitempty"`

	// Email
	SMTPHost     string   `json:"smtp_host,omitempty"`
	SMTPPort     int      `json:"smtp_port,omitempty"`
	SMTPUsername string   `json:"smtp_username,omitempty"`
	SMTPPassword string   `json:"smtp_password,omitempty"`
	FromAddress  string   `json:"from_address,omitempty"`
	ToAddresses  []string `json:"to_addresses,omitempty"`

	// Webhook
	URL     string            `json:"url,omitempty"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`

	// SMS
	Provider    string `json:"provider,omitempty"`
	APIKey      string `json:"api_key,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

// AlertRule defines when and how to send alerts
type AlertRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Enabled          bool            `json:"enabled"`
	Severities       []AlertSeverity `json:"severities"`
	FindingTypes     []string        `json:"finding_types"`
	ResourceTypes    []string        `json:"resource_types"`
	Channels         []string        `json:"channels"` // Channel IDs
	EscalationPolicy string          `json:"escalation_policy,omitempty"`
	Throttle         ThrottleConfig  `json:"throttle"`
	Schedule         ScheduleConfig  `json:"schedule"`
	Conditions       []Condition     `json:"conditions"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	LastTriggeredAt  *time.Time      `json:"last_triggered_at,omitempty"`
	TriggerCount     int             `json:"trigger_count"`
}

// ThrottleConfig prevents alert flooding
type ThrottleConfig struct {
	Enabled       bool `json:"enabled"`
	MaxPerHour    int  `json:"max_per_hour"`
	MaxPerDay     int  `json:"max_per_day"`
	CooldownMinss int  `json:"cooldown_minutes"`
}

// ScheduleConfig defines when alerts should be sent
type ScheduleConfig struct {
	Enabled    bool     `json:"enabled"`
	Timezone   string   `json:"timezone"`
	DaysOfWeek []int    `json:"days_of_week"` // 0=Sunday, 6=Saturday
	StartTime  string   `json:"start_time"`   // HH:MM
	EndTime    string   `json:"end_time"`     // HH:MM
	Holidays   []string `json:"holidays"`     // Dates to skip
}

// Condition for alert matching
type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"` // eq, ne, gt, lt, contains, regex
	Value    string `json:"value"`
}

// EscalationPolicy defines escalation rules
type EscalationPolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Levels      []EscalationLevel `json:"levels"`
	RepeatCount int               `json:"repeat_count"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// EscalationLevel represents a step in escalation
type EscalationLevel struct {
	Level           int      `json:"level"`
	DelayMinutes    int      `json:"delay_minutes"`
	Channels        []string `json:"channels"`
	NotifyOnResolve bool     `json:"notify_on_resolve"`
}

// CSPMAlert represents a sent or pending alert
type CSPMAlert struct {
	ID              string        `json:"id"`
	RuleID          string        `json:"rule_id"`
	RuleName        string        `json:"rule_name"`
	FindingID       string        `json:"finding_id"`
	FindingType     string        `json:"finding_type"`
	ResourceID      string        `json:"resource_id"`
	ResourceType    string        `json:"resource_type"`
	Severity        AlertSeverity `json:"severity"`
	Title           string        `json:"title"`
	Description     string        `json:"description"`
	Status          AlertStatus   `json:"status"`
	Channels        []string      `json:"channels"`
	SentAt          *time.Time    `json:"sent_at,omitempty"`
	AcknowledgedAt  *time.Time    `json:"acknowledged_at,omitempty"`
	AcknowledgedBy  string        `json:"acknowledged_by,omitempty"`
	ResolvedAt      *time.Time    `json:"resolved_at,omitempty"`
	ResolvedBy      string        `json:"resolved_by,omitempty"`
	EscalationLevel int           `json:"escalation_level"`
	RetryCount      int           `json:"retry_count"`
	Error           string        `json:"error,omitempty"`
	Metadata        AlertMetadata `json:"metadata"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// AlertMetadata contains additional context
type AlertMetadata struct {
	Account      string            `json:"account"`
	Region       string            `json:"region"`
	Service      string            `json:"service"`
	ComplianceID string            `json:"compliance_id,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	Links        []Link            `json:"links,omitempty"`
}

// Link represents a related resource
type Link struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// AlertStatistics provides metrics
type AlertStatistics struct {
	TotalAlerts       int                      `json:"total_alerts"`
	AlertsBySeverity  map[AlertSeverity]int    `json:"alerts_by_severity"`
	AlertsByStatus    map[AlertStatus]int      `json:"alerts_by_status"`
	AlertsByChannel   map[AlertChannelType]int `json:"alerts_by_channel"`
	AvgResponseTime   int                      `json:"avg_response_time_minutes"`
	AvgResolutionTime int                      `json:"avg_resolution_time_minutes"`
	SuccessRate       float64                  `json:"success_rate"`
	TopRules          []RuleStatistic          `json:"top_rules"`
	AlertTrend        []AlertTrendPoint        `json:"alert_trend"`
}

// RuleStatistic for top triggered rules
type RuleStatistic struct {
	RuleID       string `json:"rule_id"`
	RuleName     string `json:"rule_name"`
	TriggerCount int    `json:"trigger_count"`
}

// AlertTrendPoint for time series data
type AlertTrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int       `json:"count"`
}

// Global state
var (
	alertChannels      []AlertChannel
	alertRules         []AlertRule
	escalationPolicies []EscalationPolicy
	cspmAlerts         []CSPMAlert
	alertsMutex        sync.RWMutex
)

// Initialize alert system
func initCSPMAlerts() {
	alertChannels = []AlertChannel{
		{
			ID:      "channel-001",
			Name:    "Security Team Slack",
			Type:    ChannelSlack,
			Enabled: true,
			Config: ChannelConfig{
				WebhookURL: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
				Channel:    "#security-alerts",
				Username:   "SIEM Platform",
				IconEmoji:  ":shield:",
			},
			CreatedAt:   time.Now().Add(-30 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-1 * time.Hour),
			SuccessRate: 99.5,
			TotalSent:   1234,
			TotalFailed: 6,
		},
		{
			ID:      "channel-002",
			Name:    "Critical Incidents PagerDuty",
			Type:    ChannelPagerDuty,
			Enabled: true,
			Config: ChannelConfig{
				IntegrationKey: "R0XXXXXXXXXXXXXXXXXXXX",
				RoutingKey:     "critical-security",
			},
			CreatedAt:   time.Now().Add(-25 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-2 * time.Hour),
			SuccessRate: 100.0,
			TotalSent:   87,
			TotalFailed: 0,
		},
		{
			ID:      "channel-003",
			Name:    "Security Team Email",
			Type:    ChannelEmail,
			Enabled: true,
			Config: ChannelConfig{
				SMTPHost:     "smtp.gmail.com",
				SMTPPort:     587,
				SMTPUsername: "alerts@company.com",
				FromAddress:  "SIEM Platform <alerts@company.com>",
				ToAddresses:  []string{"security-team@company.com", "soc@company.com"},
			},
			CreatedAt:   time.Now().Add(-20 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-3 * time.Hour),
			SuccessRate: 98.2,
			TotalSent:   456,
			TotalFailed: 8,
		},
		{
			ID:      "channel-004",
			Name:    "Custom Webhook",
			Type:    ChannelWebhook,
			Enabled: false,
			Config: ChannelConfig{
				URL:    "https://api.company.com/security/webhooks/alerts",
				Method: "POST",
				Headers: map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Bearer token123",
				},
			},
			CreatedAt:   time.Now().Add(-15 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-5 * 24 * time.Hour),
			SuccessRate: 95.0,
			TotalSent:   200,
			TotalFailed: 10,
		},
	}

	alertRules = []AlertRule{
		{
			ID:            "rule-001",
			Name:          "Critical Security Findings",
			Description:   "Alert on all critical security findings immediately",
			Enabled:       true,
			Severities:    []AlertSeverity{SeverityCritical},
			FindingTypes:  []string{"S3_PUBLIC_ACCESS", "ROOT_ACCOUNT_ACCESS_KEY", "SECURITY_GROUP_OPEN"},
			ResourceTypes: []string{"AWS::S3::Bucket", "AWS::IAM::User", "AWS::EC2::SecurityGroup"},
			Channels:      []string{"channel-001", "channel-002", "channel-003"},
			Throttle: ThrottleConfig{
				Enabled:       true,
				MaxPerHour:    10,
				MaxPerDay:     50,
				CooldownMinss: 15,
			},
			Schedule: ScheduleConfig{
				Enabled:    false,
				Timezone:   "America/Sao_Paulo",
				DaysOfWeek: []int{0, 1, 2, 3, 4, 5, 6},
				StartTime:  "00:00",
				EndTime:    "23:59",
			},
			CreatedAt:    time.Now().Add(-30 * 24 * time.Hour),
			UpdatedAt:    time.Now().Add(-1 * time.Hour),
			TriggerCount: 45,
		},
		{
			ID:            "rule-002",
			Name:          "High Severity Findings",
			Description:   "Alert on high severity findings during business hours",
			Enabled:       true,
			Severities:    []AlertSeverity{SeverityHigh},
			FindingTypes:  []string{"UNENCRYPTED_EBS", "UNENCRYPTED_RDS", "IAM_USER_NO_MFA"},
			ResourceTypes: []string{"AWS::EC2::Volume", "AWS::RDS::DBInstance", "AWS::IAM::User"},
			Channels:      []string{"channel-001", "channel-003"},
			Throttle: ThrottleConfig{
				Enabled:       true,
				MaxPerHour:    20,
				MaxPerDay:     100,
				CooldownMinss: 30,
			},
			Schedule: ScheduleConfig{
				Enabled:    true,
				Timezone:   "America/Sao_Paulo",
				DaysOfWeek: []int{1, 2, 3, 4, 5}, // Monday-Friday
				StartTime:  "08:00",
				EndTime:    "18:00",
			},
			CreatedAt:    time.Now().Add(-25 * 24 * time.Hour),
			UpdatedAt:    time.Now().Add(-2 * time.Hour),
			TriggerCount: 123,
		},
		{
			ID:               "rule-003",
			Name:             "Compliance Violations",
			Description:      "Alert on PCI-DSS compliance violations",
			Enabled:          true,
			Severities:       []AlertSeverity{SeverityCritical, SeverityHigh},
			FindingTypes:     []string{"CLOUDTRAIL_DISABLED", "S3_PUBLIC_ACCESS", "UNENCRYPTED_RDS"},
			ResourceTypes:    []string{"AWS::CloudTrail::Trail", "AWS::S3::Bucket", "AWS::RDS::DBInstance"},
			Channels:         []string{"channel-001", "channel-002", "channel-003"},
			EscalationPolicy: "policy-001",
			Throttle: ThrottleConfig{
				Enabled: false,
			},
			Schedule: ScheduleConfig{
				Enabled: false,
			},
			CreatedAt:    time.Now().Add(-20 * 24 * time.Hour),
			UpdatedAt:    time.Now().Add(-3 * time.Hour),
			TriggerCount: 34,
		},
	}

	escalationPolicies = []EscalationPolicy{
		{
			ID:          "policy-001",
			Name:        "Standard Escalation",
			Description: "Escalate to management if not acknowledged within 30 minutes",
			Levels: []EscalationLevel{
				{
					Level:           1,
					DelayMinutes:    0,
					Channels:        []string{"channel-001"},
					NotifyOnResolve: true,
				},
				{
					Level:           2,
					DelayMinutes:    30,
					Channels:        []string{"channel-001", "channel-002"},
					NotifyOnResolve: true,
				},
				{
					Level:           3,
					DelayMinutes:    60,
					Channels:        []string{"channel-001", "channel-002", "channel-003"},
					NotifyOnResolve: true,
				},
			},
			RepeatCount: 3,
			CreatedAt:   time.Now().Add(-30 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-1 * time.Hour),
		},
	}

	// Sample alerts
	now := time.Now()
	sentAt := now.Add(-2 * time.Hour)
	acknowledgedAt := now.Add(-1 * time.Hour)

	cspmAlerts = []CSPMAlert{
		{
			ID:              "alert-001",
			RuleID:          "rule-001",
			RuleName:        "Critical Security Findings",
			FindingID:       "finding-001",
			FindingType:     "S3_PUBLIC_ACCESS",
			ResourceID:      "arn:aws:s3:::my-public-bucket",
			ResourceType:    "AWS::S3::Bucket",
			Severity:        SeverityCritical,
			Title:           "S3 Bucket Publicly Accessible",
			Description:     "S3 bucket 'my-public-bucket' is publicly accessible, violating security policy",
			Status:          AlertAcknowled,
			Channels:        []string{"channel-001", "channel-002"},
			SentAt:          &sentAt,
			AcknowledgedAt:  &acknowledgedAt,
			AcknowledgedBy:  "admin@company.com",
			EscalationLevel: 1,
			RetryCount:      0,
			Metadata: AlertMetadata{
				Account: "123456789012",
				Region:  "us-east-1",
				Service: "S3",
				Tags: map[string]string{
					"Environment": "production",
					"Team":        "platform",
				},
				Links: []Link{
					{Title: "View in AWS Console", URL: "https://console.aws.amazon.com/s3/buckets/my-public-bucket"},
					{Title: "Remediation Playbook", URL: "https://wiki.company.com/security/s3-public-access"},
				},
			},
			CreatedAt: sentAt,
			UpdatedAt: acknowledgedAt,
		},
		{
			ID:              "alert-002",
			RuleID:          "rule-002",
			RuleName:        "High Severity Findings",
			FindingID:       "finding-002",
			FindingType:     "UNENCRYPTED_EBS",
			ResourceID:      "vol-1234567890abcdef0",
			ResourceType:    "AWS::EC2::Volume",
			Severity:        SeverityHigh,
			Title:           "Unencrypted EBS Volume",
			Description:     "EBS volume 'vol-1234567890abcdef0' is not encrypted",
			Status:          AlertSent,
			Channels:        []string{"channel-001", "channel-003"},
			SentAt:          &sentAt,
			EscalationLevel: 1,
			RetryCount:      0,
			Metadata: AlertMetadata{
				Account: "123456789012",
				Region:  "us-east-1",
				Service: "EC2",
				Tags: map[string]string{
					"Environment": "production",
				},
			},
			CreatedAt: sentAt,
			UpdatedAt: sentAt,
		},
	}
}

// Handlers

func (s *APIServer) handleListAlertChannels(c *gin.Context) {
	alertsMutex.RLock()
	defer alertsMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"channels": alertChannels,
		"total":    len(alertChannels),
	})
}

func (s *APIServer) handleGetAlertChannel(c *gin.Context) {
	id := c.Param("id")

	alertsMutex.RLock()
	defer alertsMutex.RUnlock()

	for _, channel := range alertChannels {
		if channel.ID == id {
			c.JSON(http.StatusOK, channel)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Channel not found"})
}

func (s *APIServer) handleCreateAlertChannel(c *gin.Context) {
	var channel AlertChannel
	if err := c.ShouldBindJSON(&channel); err != nil {
		log.Printf("[ERROR] handleCreateAlertChannel bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	channel.ID = fmt.Sprintf("channel-%03d", len(alertChannels)+1)
	channel.CreatedAt = time.Now()
	channel.UpdatedAt = time.Now()
	channel.SuccessRate = 100.0

	alertsMutex.Lock()
	alertChannels = append(alertChannels, channel)
	alertsMutex.Unlock()

	c.JSON(http.StatusCreated, channel)
}

func (s *APIServer) handleUpdateAlertChannel(c *gin.Context) {
	id := c.Param("id")

	var updates AlertChannel
	if err := c.ShouldBindJSON(&updates); err != nil {
		log.Printf("[ERROR] Invalid alert channel update request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	alertsMutex.Lock()
	defer alertsMutex.Unlock()

	for i, channel := range alertChannels {
		if channel.ID == id {
			updates.ID = id
			updates.CreatedAt = channel.CreatedAt
			updates.UpdatedAt = time.Now()
			alertChannels[i] = updates
			c.JSON(http.StatusOK, updates)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Channel not found"})
}

func (s *APIServer) handleDeleteAlertChannel(c *gin.Context) {
	id := c.Param("id")

	alertsMutex.Lock()
	defer alertsMutex.Unlock()

	for i, channel := range alertChannels {
		if channel.ID == id {
			alertChannels = append(alertChannels[:i], alertChannels[i+1:]...)
			c.JSON(http.StatusOK, gin.H{"message": "Channel deleted successfully"})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Channel not found"})
}

func (s *APIServer) handleTestAlertChannel(c *gin.Context) {
	id := c.Param("id")

	alertsMutex.RLock()
	var channel *AlertChannel
	for i := range alertChannels {
		if alertChannels[i].ID == id {
			channel = &alertChannels[i]
			break
		}
	}
	alertsMutex.RUnlock()

	if channel == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Channel not found"})
		return
	}

	// Simulate sending test message
	testResult := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Test alert sent successfully to %s channel '%s'", channel.Type, channel.Name),
		"sent_at": time.Now(),
	}

	c.JSON(http.StatusOK, testResult)
}

func (s *APIServer) handleListAlertRules(c *gin.Context) {
	alertsMutex.RLock()
	defer alertsMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"rules": alertRules,
		"total": len(alertRules),
	})
}

func (s *APIServer) handleGetAlertRule(c *gin.Context) {
	id := c.Param("id")

	alertsMutex.RLock()
	defer alertsMutex.RUnlock()

	for _, rule := range alertRules {
		if rule.ID == id {
			c.JSON(http.StatusOK, rule)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
}

func (s *APIServer) handleCreateAlertRule(c *gin.Context) {
	var rule AlertRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		log.Printf("[ERROR] handleCreateAlertRule bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	rule.ID = fmt.Sprintf("rule-%03d", len(alertRules)+1)
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	rule.TriggerCount = 0

	alertsMutex.Lock()
	alertRules = append(alertRules, rule)
	alertsMutex.Unlock()

	c.JSON(http.StatusCreated, rule)
}

func (s *APIServer) handleUpdateAlertRule(c *gin.Context) {
	id := c.Param("id")

	var updates AlertRule
	if err := c.ShouldBindJSON(&updates); err != nil {
		log.Printf("[ERROR] handleUpdateAlertRule bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	alertsMutex.Lock()
	defer alertsMutex.Unlock()

	for i, rule := range alertRules {
		if rule.ID == id {
			updates.ID = id
			updates.CreatedAt = rule.CreatedAt
			updates.UpdatedAt = time.Now()
			updates.TriggerCount = rule.TriggerCount
			alertRules[i] = updates
			c.JSON(http.StatusOK, updates)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
}

func (s *APIServer) handleDeleteAlertRule(c *gin.Context) {
	id := c.Param("id")

	alertsMutex.Lock()
	defer alertsMutex.Unlock()

	for i, rule := range alertRules {
		if rule.ID == id {
			alertRules = append(alertRules[:i], alertRules[i+1:]...)
			c.JSON(http.StatusOK, gin.H{"message": "Rule deleted successfully"})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
}

func (s *APIServer) handleListCSPMAlerts(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")

	alertsMutex.RLock()
	defer alertsMutex.RUnlock()

	filtered := cspmAlerts
	if status != "" {
		var temp []CSPMAlert
		for _, alert := range filtered {
			if string(alert.Status) == status {
				temp = append(temp, alert)
			}
		}
		filtered = temp
	}

	if severity != "" {
		var temp []CSPMAlert
		for _, alert := range filtered {
			if string(alert.Severity) == severity {
				temp = append(temp, alert)
			}
		}
		filtered = temp
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": filtered,
		"total":  len(filtered),
	})
}

func (s *APIServer) handleGetCSPMAlert(c *gin.Context) {
	id := c.Param("id")

	alertsMutex.RLock()
	defer alertsMutex.RUnlock()

	for _, alert := range cspmAlerts {
		if alert.ID == id {
			c.JSON(http.StatusOK, alert)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
}

func (s *APIServer) handleAcknowledgeAlert(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		AcknowledgedBy string `json:"acknowledged_by"`
		Comment        string `json:"comment"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] Invalid acknowledge alert request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	alertsMutex.Lock()
	defer alertsMutex.Unlock()

	for i, alert := range cspmAlerts {
		if alert.ID == id {
			now := time.Now()
			cspmAlerts[i].Status = AlertAcknowled
			cspmAlerts[i].AcknowledgedAt = &now
			cspmAlerts[i].AcknowledgedBy = req.AcknowledgedBy
			cspmAlerts[i].UpdatedAt = now
			c.JSON(http.StatusOK, cspmAlerts[i])
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
}

func (s *APIServer) handleResolveAlert(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		ResolvedBy string `json:"resolved_by"`
		Comment    string `json:"comment"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleResolveAlert bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	alertsMutex.Lock()
	defer alertsMutex.Unlock()

	for i, alert := range cspmAlerts {
		if alert.ID == id {
			now := time.Now()
			cspmAlerts[i].Status = AlertResolved
			cspmAlerts[i].ResolvedAt = &now
			cspmAlerts[i].ResolvedBy = req.ResolvedBy
			cspmAlerts[i].UpdatedAt = now
			c.JSON(http.StatusOK, cspmAlerts[i])
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
}

func (s *APIServer) handleGetCSPMAlertStatistics(c *gin.Context) {
	alertsMutex.RLock()
	defer alertsMutex.RUnlock()

	stats := AlertStatistics{
		TotalAlerts:       len(cspmAlerts),
		AlertsBySeverity:  make(map[AlertSeverity]int),
		AlertsByStatus:    make(map[AlertStatus]int),
		AlertsByChannel:   make(map[AlertChannelType]int),
		AvgResponseTime:   25,
		AvgResolutionTime: 120,
		SuccessRate:       98.5,
	}

	// Count by severity and status
	for _, alert := range cspmAlerts {
		stats.AlertsBySeverity[alert.Severity]++
		stats.AlertsByStatus[alert.Status]++
	}

	// Count by channel
	for _, channel := range alertChannels {
		stats.AlertsByChannel[channel.Type] = channel.TotalSent
	}

	// Top rules
	stats.TopRules = []RuleStatistic{
		{RuleID: "rule-002", RuleName: "High Severity Findings", TriggerCount: 123},
		{RuleID: "rule-001", RuleName: "Critical Security Findings", TriggerCount: 45},
		{RuleID: "rule-003", RuleName: "Compliance Violations", TriggerCount: 34},
	}

	// Alert trend (last 7 days)
	now := time.Now()
	for i := 6; i >= 0; i-- {
		stats.AlertTrend = append(stats.AlertTrend, AlertTrendPoint{
			Timestamp: now.Add(-time.Duration(i) * 24 * time.Hour),
			Count:     15 + (i * 3),
		})
	}

	c.JSON(http.StatusOK, stats)
}

func (s *APIServer) handleListEscalationPolicies(c *gin.Context) {
	alertsMutex.RLock()
	defer alertsMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"policies": escalationPolicies,
		"total":    len(escalationPolicies),
	})
}

func (s *APIServer) handleGetEscalationPolicy(c *gin.Context) {
	id := c.Param("id")

	alertsMutex.RLock()
	defer alertsMutex.RUnlock()

	for _, policy := range escalationPolicies {
		if policy.ID == id {
			c.JSON(http.StatusOK, policy)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
}

// Helper functions for sending alerts (stubs for now)

func sendSlackAlert(channel AlertChannel, alert CSPMAlert) error {
	// TODO: Implement actual Slack webhook
	return nil
}

func sendPagerDutyAlert(channel AlertChannel, alert CSPMAlert) error {
	// TODO: Implement actual PagerDuty API
	return nil
}

func sendEmailAlert(channel AlertChannel, alert CSPMAlert) error {
	// TODO: Implement actual SMTP
	return nil
}

func sendWebhookAlert(channel AlertChannel, alert CSPMAlert) error {
	// TODO: Implement actual HTTP webhook
	return nil
}

// Verify webhook signature (for incoming webhooks)
func verifyWebhookSignature(payload []byte, signature string, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// Marshal alert to JSON for sending
func marshalAlert(alert CSPMAlert) ([]byte, error) {
	return json.Marshal(alert)
}
