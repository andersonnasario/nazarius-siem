package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Integration types
const (
	IntegrationTypeFirewall  = "firewall"
	IntegrationTypeWAF       = "waf"
	IntegrationTypeEDR       = "edr"
	IntegrationTypeAntivirus = "antivirus"
	IntegrationTypeIAM       = "iam"
	IntegrationTypeSIEM      = "siem"
)

// Integration vendors
const (
	VendorFortinet  = "fortinet"
	VendorAWS       = "aws"
	VendorAcronis   = "acronis"
	VendorJumpCloud = "jumpcloud"
)

// Integration status
const (
	IntegrationStatusActive      = "active"
	IntegrationStatusInactive    = "inactive"
	IntegrationStatusError       = "error"
	IntegrationStatusConfiguring = "configuring"
	IntegrationStatusTesting     = "testing"
)

// Integration represents a third-party integration
type Integration struct {
	ID              string                  `json:"id"`
	Name            string                  `json:"name"`
	Type            string                  `json:"type"`
	Vendor          string                  `json:"vendor"`
	Description     string                  `json:"description"`
	Status          string                  `json:"status"`
	Enabled         bool                    `json:"enabled"`
	Configuration   map[string]interface{}  `json:"configuration"`
	Credentials     *IntegrationCredentials `json:"credentials,omitempty"`
	LastSync        *time.Time              `json:"last_sync,omitempty"`
	LastError       string                  `json:"last_error,omitempty"`
	EventsCollected int64                   `json:"events_collected"`
	DataCollected   int64                   `json:"data_collected"` // in bytes
	Health          *IntegrationHealth      `json:"health"`
	Capabilities    []string                `json:"capabilities"`
	CreatedAt       time.Time               `json:"created_at"`
	UpdatedAt       time.Time               `json:"updated_at"`
	CreatedBy       string                  `json:"created_by"`
}

// IntegrationCredentials stores encrypted credentials
type IntegrationCredentials struct {
	Type       string            `json:"type"` // api_key, oauth2, basic_auth, certificate
	Endpoint   string            `json:"endpoint"`
	APIKey     string            `json:"api_key,omitempty"`
	SecretKey  string            `json:"secret_key,omitempty"`
	Username   string            `json:"username,omitempty"`
	Password   string            `json:"password,omitempty"`
	Token      string            `json:"token,omitempty"`
	Region     string            `json:"region,omitempty"`
	AccountID  string            `json:"account_id,omitempty"`
	TenantID   string            `json:"tenant_id,omitempty"`
	Additional map[string]string `json:"additional,omitempty"`
}

// IntegrationHealth represents health status
type IntegrationHealth struct {
	Status       string    `json:"status"`
	ResponseTime int       `json:"response_time_ms"`
	LastCheck    time.Time `json:"last_check"`
	ErrorCount   int       `json:"error_count"`
	SuccessRate  float64   `json:"success_rate"`
	Message      string    `json:"message,omitempty"`
}

// IntegrationLog represents integration activity log
type IntegrationLog struct {
	ID            string                 `json:"id"`
	IntegrationID string                 `json:"integration_id"`
	Action        string                 `json:"action"`
	Status        string                 `json:"status"`
	Message       string                 `json:"message"`
	Details       map[string]interface{} `json:"details,omitempty"`
	Duration      int                    `json:"duration_ms"`
	Timestamp     time.Time              `json:"timestamp"`
}

// IntegrationTemplate represents a pre-configured integration template
type IntegrationTemplate struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Vendor         string                 `json:"vendor"`
	Type           string                 `json:"type"`
	Description    string                 `json:"description"`
	Icon           string                 `json:"icon"`
	Documentation  string                 `json:"documentation"`
	RequiredFields []IntegrationField     `json:"required_fields"`
	OptionalFields []IntegrationField     `json:"optional_fields"`
	Capabilities   []string               `json:"capabilities"`
	DefaultConfig  map[string]interface{} `json:"default_config"`
	SetupSteps     []string               `json:"setup_steps"`
	Permissions    []string               `json:"permissions"`
}

// IntegrationField represents a configuration field
type IntegrationField struct {
	Name        string      `json:"name"`
	Label       string      `json:"label"`
	Type        string      `json:"type"` // text, password, select, number, url
	Required    bool        `json:"required"`
	Placeholder string      `json:"placeholder,omitempty"`
	Description string      `json:"description,omitempty"`
	Options     []string    `json:"options,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Validation  string      `json:"validation,omitempty"`
}

// In-memory storage
var (
	integrations     = make(map[string]*Integration)
	integrationLogs  = []IntegrationLog{}
	integrationMutex sync.RWMutex
	encryptionKey    = func() []byte {
		key := os.Getenv("ENCRYPTION_KEY")
		if key == "" {
			log.Println("⚠️  ENCRYPTION_KEY not set, using random key (integration credentials will NOT survive restarts)")
			randKey := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, randKey); err != nil {
				log.Fatal("FATAL: Failed to generate random encryption key: " + err.Error())
			}
			return randKey
		}
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			log.Fatal("FATAL: ENCRYPTION_KEY must be a base64-encoded 32-byte key. Generate one with: openssl rand -base64 32")
		}
		return decoded
	}() // 32 bytes for AES-256
)

// Initialize integrations
func initIntegrations() {
	integrationMutex.Lock()
	defer integrationMutex.Unlock()

	now := time.Now()

	// Sample integrations for demonstration
	integrations = map[string]*Integration{
		"int-001": {
			ID:          "int-001",
			Name:        "Fortinet FortiGate - Main Firewall",
			Type:        IntegrationTypeFirewall,
			Vendor:      VendorFortinet,
			Description: "Firewall principal - Coleta de logs e eventos de segurança",
			Status:      IntegrationStatusActive,
			Enabled:     true,
			Configuration: map[string]interface{}{
				"log_level":       "high",
				"collect_traffic": true,
				"collect_utm":     true,
				"poll_interval":   60,
			},
			EventsCollected: 125430,
			DataCollected:   1024 * 1024 * 450, // 450 MB
			Health: &IntegrationHealth{
				Status:       "healthy",
				ResponseTime: 45,
				LastCheck:    now.Add(-2 * time.Minute),
				ErrorCount:   0,
				SuccessRate:  99.8,
			},
			Capabilities: []string{"logs", "events", "traffic", "utm", "ips", "av"},
			CreatedAt:    now.Add(-30 * 24 * time.Hour),
			UpdatedAt:    now.Add(-2 * time.Minute),
			CreatedBy:    "admin",
		},
	}
}

// Integration handlers
func (s *APIServer) handleListIntegrations(c *gin.Context) {
	integrationMutex.RLock()
	defer integrationMutex.RUnlock()

	typeFilter := c.Query("type")
	vendorFilter := c.Query("vendor")
	statusFilter := c.Query("status")

	result := []*Integration{}
	for _, integration := range integrations {
		if typeFilter != "" && integration.Type != typeFilter {
			continue
		}
		if vendorFilter != "" && integration.Vendor != vendorFilter {
			continue
		}
		if statusFilter != "" && integration.Status != statusFilter {
			continue
		}

		// Remove sensitive data
		integrationCopy := *integration
		integrationCopy.Credentials = nil
		result = append(result, &integrationCopy)
	}

	c.JSON(http.StatusOK, gin.H{
		"integrations": result,
		"total":        len(result),
	})
}

func (s *APIServer) handleGetIntegration(c *gin.Context) {
	id := c.Param("id")

	integrationMutex.RLock()
	integration, exists := integrations[id]
	integrationMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Integration not found"})
		return
	}

	// Remove sensitive data
	integrationCopy := *integration
	integrationCopy.Credentials = nil

	c.JSON(http.StatusOK, integrationCopy)
}

func (s *APIServer) handleCreateIntegration(c *gin.Context) {
	var req Integration
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] create integration bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	integrationMutex.Lock()
	defer integrationMutex.Unlock()

	// Generate ID
	req.ID = fmt.Sprintf("int-%03d", len(integrations)+1)
	req.Status = IntegrationStatusConfiguring
	req.CreatedAt = time.Now()
	req.UpdatedAt = time.Now()
	req.CreatedBy = "admin" // TODO: Get from JWT
	req.EventsCollected = 0
	req.DataCollected = 0

	// Encrypt credentials if provided
	if req.Credentials != nil {
		if err := encryptCredentials(req.Credentials); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt credentials"})
			return
		}
	}

	integrations[req.ID] = &req

	// Log action
	logIntegrationAction(req.ID, "create", "success", "Integration created", nil)

	c.JSON(http.StatusCreated, req)
}

func (s *APIServer) handleUpdateIntegration(c *gin.Context) {
	id := c.Param("id")

	integrationMutex.Lock()
	defer integrationMutex.Unlock()

	integration, exists := integrations[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Integration not found"})
		return
	}

	var req Integration
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] update integration bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Update fields
	integration.Name = req.Name
	integration.Description = req.Description
	integration.Configuration = req.Configuration
	integration.Enabled = req.Enabled
	integration.UpdatedAt = time.Now()

	// Update credentials if provided
	if req.Credentials != nil {
		if err := encryptCredentials(req.Credentials); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt credentials"})
			return
		}
		integration.Credentials = req.Credentials
	}

	// Log action
	logIntegrationAction(id, "update", "success", "Integration updated", nil)

	c.JSON(http.StatusOK, integration)
}

func (s *APIServer) handleDeleteIntegration(c *gin.Context) {
	id := c.Param("id")

	integrationMutex.Lock()
	defer integrationMutex.Unlock()

	if _, exists := integrations[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Integration not found"})
		return
	}

	delete(integrations, id)

	// Log action
	logIntegrationAction(id, "delete", "success", "Integration deleted", nil)

	c.JSON(http.StatusOK, gin.H{"message": "Integration deleted successfully"})
}

func (s *APIServer) handleTestIntegration(c *gin.Context) {
	id := c.Param("id")

	integrationMutex.RLock()
	integration, exists := integrations[id]
	integrationMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Integration not found"})
		return
	}

	// Simulate connection test
	start := time.Now()

	// Update status
	integrationMutex.Lock()
	integration.Status = IntegrationStatusTesting
	integrationMutex.Unlock()

	// Simulate test (in real implementation, this would test actual connection)
	time.Sleep(500 * time.Millisecond)

	duration := time.Since(start).Milliseconds()

	testResult := gin.H{
		"success":       true,
		"message":       "Connection successful",
		"response_time": duration,
		"details": gin.H{
			"endpoint":    integration.Credentials.Endpoint,
			"vendor":      integration.Vendor,
			"type":        integration.Type,
			"api_version": "v2.0",
		},
	}

	// Update health
	integrationMutex.Lock()
	integration.Status = IntegrationStatusActive
	integration.Health = &IntegrationHealth{
		Status:       "healthy",
		ResponseTime: int(duration),
		LastCheck:    time.Now(),
		ErrorCount:   0,
		SuccessRate:  100.0,
		Message:      "Connection test successful",
	}
	integrationMutex.Unlock()

	// Log action
	logIntegrationAction(id, "test", "success", "Connection test successful", testResult)

	c.JSON(http.StatusOK, testResult)
}

func (s *APIServer) handleSyncIntegration(c *gin.Context) {
	id := c.Param("id")

	integrationMutex.RLock()
	integration, exists := integrations[id]
	integrationMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Integration not found"})
		return
	}

	if !integration.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Integration is disabled"})
		return
	}

	// Simulate sync
	start := time.Now()

	// In real implementation, this would fetch data from the integration
	time.Sleep(1 * time.Second)

	eventsCollected := int64(1250)
	dataCollected := int64(1024 * 1024 * 5) // 5 MB

	integrationMutex.Lock()
	integration.EventsCollected += eventsCollected
	integration.DataCollected += dataCollected
	now := time.Now()
	integration.LastSync = &now
	integration.UpdatedAt = now
	integrationMutex.Unlock()

	duration := time.Since(start).Milliseconds()

	result := gin.H{
		"success":          true,
		"events_collected": eventsCollected,
		"data_collected":   dataCollected,
		"duration_ms":      duration,
		"timestamp":        time.Now(),
	}

	// Log action
	logIntegrationAction(id, "sync", "success", fmt.Sprintf("Collected %d events", eventsCollected), result)

	c.JSON(http.StatusOK, result)
}

func (s *APIServer) handleGetIntegrationLogs(c *gin.Context) {
	id := c.Param("id")

	integrationMutex.RLock()
	defer integrationMutex.RUnlock()

	logs := []IntegrationLog{}
	for _, log := range integrationLogs {
		if log.IntegrationID == id {
			logs = append(logs, log)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"total": len(logs),
	})
}

func (s *APIServer) handleGetIntegrationTemplates(c *gin.Context) {
	templates := getIntegrationTemplates()

	typeFilter := c.Query("type")
	vendorFilter := c.Query("vendor")

	result := []IntegrationTemplate{}
	for _, template := range templates {
		if typeFilter != "" && template.Type != typeFilter {
			continue
		}
		if vendorFilter != "" && template.Vendor != vendorFilter {
			continue
		}
		result = append(result, template)
	}

	c.JSON(http.StatusOK, gin.H{
		"templates": result,
		"total":     len(result),
	})
}

func (s *APIServer) handleGetIntegrationStats(c *gin.Context) {
	integrationMutex.RLock()
	defer integrationMutex.RUnlock()

	stats := gin.H{
		"total_integrations": len(integrations),
		"active":             0,
		"inactive":           0,
		"error":              0,
		"total_events":       int64(0),
		"total_data":         int64(0),
		"by_type":            make(map[string]int),
		"by_vendor":          make(map[string]int),
		"health_summary": gin.H{
			"healthy":   0,
			"degraded":  0,
			"unhealthy": 0,
		},
	}

	for _, integration := range integrations {
		// Count by status
		switch integration.Status {
		case IntegrationStatusActive:
			stats["active"] = stats["active"].(int) + 1
		case IntegrationStatusInactive:
			stats["inactive"] = stats["inactive"].(int) + 1
		case IntegrationStatusError:
			stats["error"] = stats["error"].(int) + 1
		}

		// Count by type
		byType := stats["by_type"].(map[string]int)
		byType[integration.Type]++

		// Count by vendor
		byVendor := stats["by_vendor"].(map[string]int)
		byVendor[integration.Vendor]++

		// Sum events and data
		stats["total_events"] = stats["total_events"].(int64) + integration.EventsCollected
		stats["total_data"] = stats["total_data"].(int64) + integration.DataCollected

		// Health summary
		if integration.Health != nil {
			healthSummary := stats["health_summary"].(gin.H)
			if integration.Health.SuccessRate >= 95.0 {
				healthSummary["healthy"] = healthSummary["healthy"].(int) + 1
			} else if integration.Health.SuccessRate >= 80.0 {
				healthSummary["degraded"] = healthSummary["degraded"].(int) + 1
			} else {
				healthSummary["unhealthy"] = healthSummary["unhealthy"].(int) + 1
			}
		}
	}

	c.JSON(http.StatusOK, stats)
}

// Helper functions

func encryptCredentials(creds *IntegrationCredentials) error {
	// Encrypt sensitive fields
	if creds.APIKey != "" {
		encrypted, err := encrypt(creds.APIKey)
		if err != nil {
			return err
		}
		creds.APIKey = encrypted
	}
	if creds.SecretKey != "" {
		encrypted, err := encrypt(creds.SecretKey)
		if err != nil {
			return err
		}
		creds.SecretKey = encrypted
	}
	if creds.Password != "" {
		encrypted, err := encrypt(creds.Password)
		if err != nil {
			return err
		}
		creds.Password = encrypted
	}
	if creds.Token != "" {
		encrypted, err := encrypt(creds.Token)
		if err != nil {
			return err
		}
		creds.Token = encrypted
	}
	return nil
}

func encrypt(text string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encrypted string) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func logIntegrationAction(integrationID, action, status, message string, details map[string]interface{}) {
	log := IntegrationLog{
		ID:            fmt.Sprintf("log-%d", len(integrationLogs)+1),
		IntegrationID: integrationID,
		Action:        action,
		Status:        status,
		Message:       message,
		Details:       details,
		Duration:      0,
		Timestamp:     time.Now(),
	}
	integrationLogs = append(integrationLogs, log)
}

func getIntegrationTemplates() []IntegrationTemplate {
	return []IntegrationTemplate{
		{
			ID:            "template-fortinet",
			Name:          "Fortinet FortiGate",
			Vendor:        VendorFortinet,
			Type:          IntegrationTypeFirewall,
			Description:   "Integração com Fortinet FortiGate Firewall para coleta de logs, eventos de segurança, tráfego e UTM",
			Icon:          "SecurityIcon",
			Documentation: "/docs/integrations/fortinet-fortigate",
			RequiredFields: []IntegrationField{
				{Name: "endpoint", Label: "FortiGate IP/Hostname", Type: "text", Required: true, Placeholder: "192.168.1.1 or fortigate.company.com"},
				{Name: "api_key", Label: "API Key", Type: "password", Required: true, Description: "API Key gerada no FortiGate"},
				{Name: "port", Label: "API Port", Type: "number", Required: true, Default: 443},
			},
			OptionalFields: []IntegrationField{
				{Name: "vdom", Label: "VDOM", Type: "text", Required: false, Placeholder: "root", Description: "Virtual Domain (padrão: root)"},
				{Name: "verify_ssl", Label: "Verify SSL", Type: "select", Options: []string{"true", "false"}, Default: "true"},
				{Name: "poll_interval", Label: "Poll Interval (seconds)", Type: "number", Default: 60},
			},
			Capabilities: []string{"logs", "events", "traffic", "utm", "ips", "av", "webfilter", "application_control"},
			DefaultConfig: map[string]interface{}{
				"log_level":       "high",
				"collect_traffic": true,
				"collect_utm":     true,
				"collect_ips":     true,
				"poll_interval":   60,
			},
			SetupSteps: []string{
				"Acesse o FortiGate via HTTPS",
				"Navegue até System > Administrators > Create New > REST API Admin",
				"Configure o nome do administrador e gere uma API Key",
				"Defina as permissões: Read para System, Log, Firewall, UTM",
				"Anote a API Key (será exibida apenas uma vez)",
				"Configure Trusted Hosts com o IP do SIEM",
				"Teste a conexão usando o botão 'Test Connection'",
			},
			Permissions: []string{
				"System: Read",
				"Log & Report: Read",
				"Firewall: Read",
				"UTM: Read",
				"VPN: Read (opcional)",
				"User & Device: Read (opcional)",
			},
		},
		{
			ID:            "template-aws-waf",
			Name:          "AWS WAF",
			Vendor:        VendorAWS,
			Type:          IntegrationTypeWAF,
			Description:   "Integração com AWS WAF para coleta de logs, métricas e eventos de segurança",
			Icon:          "CloudIcon",
			Documentation: "/docs/integrations/aws-waf",
			RequiredFields: []IntegrationField{
				{Name: "access_key_id", Label: "AWS Access Key ID", Type: "text", Required: true},
				{Name: "secret_access_key", Label: "AWS Secret Access Key", Type: "password", Required: true},
				{Name: "region", Label: "AWS Region", Type: "select", Required: true, Options: []string{"us-east-1", "us-west-2", "eu-west-1", "sa-east-1"}},
			},
			OptionalFields: []IntegrationField{
				{Name: "web_acl_id", Label: "Web ACL ID", Type: "text", Description: "ID do Web ACL específico (deixe vazio para todos)"},
				{Name: "s3_bucket", Label: "S3 Bucket for Logs", Type: "text", Description: "Bucket S3 onde os logs do WAF são armazenados"},
				{Name: "kinesis_stream", Label: "Kinesis Stream", Type: "text", Description: "Stream Kinesis para logs em tempo real"},
			},
			Capabilities: []string{"logs", "metrics", "rules", "blocked_requests", "allowed_requests", "rate_limiting"},
			DefaultConfig: map[string]interface{}{
				"collect_logs":    true,
				"collect_metrics": true,
				"poll_interval":   300,
			},
			SetupSteps: []string{
				"Acesse AWS IAM Console",
				"Crie um novo usuário IAM para o SIEM",
				"Anexe a policy 'WAFReadOnlyAccess'",
				"Anexe a policy 'CloudWatchReadOnlyAccess'",
				"Se usar S3: Anexe permissões de leitura no bucket de logs",
				"Gere Access Key e Secret Key",
				"Configure logging do WAF para S3 ou Kinesis",
				"Teste a conexão",
			},
			Permissions: []string{
				"wafv2:ListWebACLs",
				"wafv2:GetWebACL",
				"wafv2:GetLoggingConfiguration",
				"wafv2:GetSampledRequests",
				"cloudwatch:GetMetricStatistics",
				"cloudwatch:ListMetrics",
				"s3:GetObject (se usar S3)",
				"s3:ListBucket (se usar S3)",
				"kinesis:GetRecords (se usar Kinesis)",
				"kinesis:GetShardIterator (se usar Kinesis)",
			},
		},
		{
			ID:            "template-acronis-edr",
			Name:          "Acronis Cyber Protect (EDR)",
			Vendor:        VendorAcronis,
			Type:          IntegrationTypeEDR,
			Description:   "Integração com Acronis Cyber Protect para coleta de eventos de EDR, alertas e telemetria de endpoints",
			Icon:          "SecurityIcon",
			Documentation: "/docs/integrations/acronis-edr",
			RequiredFields: []IntegrationField{
				{Name: "data_center", Label: "Data Center", Type: "select", Required: true, Options: []string{"US", "EU", "AP", "CA"}},
				{Name: "client_id", Label: "Client ID", Type: "text", Required: true},
				{Name: "client_secret", Label: "Client Secret", Type: "password", Required: true},
				{Name: "tenant_id", Label: "Tenant ID", Type: "text", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "api_version", Label: "API Version", Type: "select", Options: []string{"v2", "v3"}, Default: "v2"},
				{Name: "collect_telemetry", Label: "Collect Telemetry", Type: "select", Options: []string{"true", "false"}, Default: "true"},
			},
			Capabilities: []string{"edr_events", "alerts", "threats", "endpoint_status", "telemetry", "investigations"},
			DefaultConfig: map[string]interface{}{
				"collect_alerts":    true,
				"collect_events":    true,
				"collect_telemetry": true,
				"poll_interval":     120,
			},
			SetupSteps: []string{
				"Acesse Acronis Cyber Platform",
				"Navegue até Settings > API Clients",
				"Clique em 'Create API Client'",
				"Defina um nome (ex: SIEM Integration)",
				"Selecione as permissões necessárias",
				"Anote Client ID e Client Secret",
				"Anote o Tenant ID da sua organização",
				"Teste a autenticação",
			},
			Permissions: []string{
				"alerts.read",
				"events.read",
				"devices.read",
				"threats.read",
				"telemetry.read",
				"investigations.read",
			},
		},
		{
			ID:            "template-acronis-av",
			Name:          "Acronis Cyber Protect (Antivirus)",
			Vendor:        VendorAcronis,
			Type:          IntegrationTypeAntivirus,
			Description:   "Integração com Acronis Cyber Protect para coleta de eventos de antivírus, detecções e quarentena",
			Icon:          "ShieldIcon",
			Documentation: "/docs/integrations/acronis-antivirus",
			RequiredFields: []IntegrationField{
				{Name: "data_center", Label: "Data Center", Type: "select", Required: true, Options: []string{"US", "EU", "AP", "CA"}},
				{Name: "client_id", Label: "Client ID", Type: "text", Required: true},
				{Name: "client_secret", Label: "Client Secret", Type: "password", Required: true},
				{Name: "tenant_id", Label: "Tenant ID", Type: "text", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "collect_scans", Label: "Collect Scan Results", Type: "select", Options: []string{"true", "false"}, Default: "true"},
			},
			Capabilities: []string{"av_events", "detections", "quarantine", "scans", "definitions_update"},
			DefaultConfig: map[string]interface{}{
				"collect_detections": true,
				"collect_scans":      true,
				"poll_interval":      180,
			},
			SetupSteps: []string{
				"Use as mesmas credenciais da integração EDR",
				"Ou crie um novo API Client específico para AV",
				"Garanta permissões de leitura em Antivirus",
				"Configure coleta de eventos",
			},
			Permissions: []string{
				"antivirus.read",
				"detections.read",
				"quarantine.read",
				"scans.read",
				"devices.read",
			},
		},
		{
			ID:            "template-jumpcloud",
			Name:          "JumpCloud",
			Vendor:        VendorJumpCloud,
			Type:          IntegrationTypeIAM,
			Description:   "Integração com JumpCloud para coleta de eventos de autenticação, gestão de usuários e atividades de IAM",
			Icon:          "PeopleIcon",
			Documentation: "/docs/integrations/jumpcloud",
			RequiredFields: []IntegrationField{
				{Name: "api_key", Label: "API Key", Type: "password", Required: true},
				{Name: "org_id", Label: "Organization ID", Type: "text", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "api_version", Label: "API Version", Type: "select", Options: []string{"v1", "v2"}, Default: "v2"},
				{Name: "collect_directory_insights", Label: "Collect Directory Insights", Type: "select", Options: []string{"true", "false"}, Default: "true"},
			},
			Capabilities: []string{"authentication_events", "user_management", "group_management", "mfa_events", "device_management", "directory_insights"},
			DefaultConfig: map[string]interface{}{
				"collect_auth_events":  true,
				"collect_user_changes": true,
				"collect_mfa_events":   true,
				"poll_interval":        120,
			},
			SetupSteps: []string{
				"Acesse JumpCloud Admin Console",
				"Navegue até Settings > API Keys",
				"Clique em 'Generate New API Key'",
				"Defina um nome (ex: SIEM Integration)",
				"Copie a API Key (será exibida apenas uma vez)",
				"Anote o Organization ID (visível no dashboard)",
				"Configure permissões de leitura",
				"Teste a conexão",
			},
			Permissions: []string{
				"Read Users",
				"Read Groups",
				"Read Devices",
				"Read Events",
				"Read Directory Insights",
				"Read MFA Settings",
			},
		},
		{
			ID:            "template-palo-alto",
			Name:          "Palo Alto Networks Firewall",
			Vendor:        "Palo Alto Networks",
			Type:          IntegrationTypeFirewall,
			Description:   "Integração com Palo Alto Networks para coleta de logs, threats, traffic e URL filtering",
			Icon:          "SecurityIcon",
			Documentation: "/docs/integrations/palo-alto",
			RequiredFields: []IntegrationField{
				{Name: "hostname", Label: "Firewall Hostname/IP", Type: "text", Required: true, Placeholder: "192.168.1.1 or pa-fw.company.com"},
				{Name: "api_key", Label: "API Key", Type: "password", Required: true, Description: "API Key gerada no Palo Alto"},
			},
			OptionalFields: []IntegrationField{
				{Name: "vsys", Label: "Virtual System", Type: "text", Placeholder: "vsys1", Description: "Virtual System (padrão: vsys1)"},
				{Name: "device_group", Label: "Device Group", Type: "text", Description: "Para Panorama"},
				{Name: "verify_ssl", Label: "Verify SSL", Type: "select", Options: []string{"true", "false"}, Default: "true"},
			},
			Capabilities: []string{"logs", "threats", "traffic", "url_filtering", "wildfire", "data_filtering", "hip_match"},
			DefaultConfig: map[string]interface{}{
				"collect_traffic": true,
				"collect_threats": true,
				"poll_interval":   60,
			},
			SetupSteps: []string{
				"Acesse o Palo Alto via HTTPS",
				"Navegue até Device > Setup > Management > Authentication Settings",
				"Clique em 'Generate' para criar uma API Key",
				"Configure as permissões necessárias no perfil do usuário",
				"Anote a API Key",
				"Configure log forwarding para o SIEM (opcional)",
				"Teste a conexão",
			},
			Permissions: []string{
				"XML API: Read",
				"Logs: Read",
				"Configuration: Read",
				"Operational Requests: Execute",
			},
		},
		{
			ID:            "template-microsoft-defender",
			Name:          "Microsoft Defender for Endpoint",
			Vendor:        "Microsoft",
			Type:          IntegrationTypeEDR,
			Description:   "Integração com Microsoft Defender for Endpoint para coleta de alertas, incidentes e telemetria",
			Icon:          "SecurityIcon",
			Documentation: "/docs/integrations/microsoft-defender",
			RequiredFields: []IntegrationField{
				{Name: "tenant_id", Label: "Azure Tenant ID", Type: "text", Required: true},
				{Name: "client_id", Label: "Application (Client) ID", Type: "text", Required: true},
				{Name: "client_secret", Label: "Client Secret", Type: "password", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "cloud", Label: "Cloud Environment", Type: "select", Options: []string{"Commercial", "GCC", "GCC-High", "DoD"}, Default: "Commercial"},
			},
			Capabilities: []string{"alerts", "incidents", "machines", "vulnerabilities", "software_inventory", "recommendations", "advanced_hunting"},
			DefaultConfig: map[string]interface{}{
				"collect_alerts":    true,
				"collect_incidents": true,
				"poll_interval":     120,
			},
			SetupSteps: []string{
				"Acesse Azure Portal",
				"Navegue até Azure Active Directory > App registrations",
				"Clique em 'New registration'",
				"Defina um nome (ex: SIEM-MDE-Integration)",
				"Em API permissions, adicione 'Microsoft Threat Protection' APIs",
				"Adicione permissões: Alert.Read.All, Incident.Read.All, Machine.Read.All",
				"Grant admin consent",
				"Crie um Client Secret em Certificates & secrets",
				"Anote Tenant ID, Client ID e Client Secret",
			},
			Permissions: []string{
				"Alert.Read.All",
				"Incident.Read.All",
				"Machine.Read.All",
				"Vulnerability.Read.All",
				"Software.Read.All",
				"AdvancedQuery.Read.All",
			},
		},
		{
			ID:            "template-crowdstrike",
			Name:          "CrowdStrike Falcon",
			Vendor:        "CrowdStrike",
			Type:          IntegrationTypeEDR,
			Description:   "Integração com CrowdStrike Falcon para coleta de detecções, incidents e telemetria de endpoints",
			Icon:          "SecurityIcon",
			Documentation: "/docs/integrations/crowdstrike",
			RequiredFields: []IntegrationField{
				{Name: "client_id", Label: "API Client ID", Type: "text", Required: true},
				{Name: "client_secret", Label: "API Client Secret", Type: "password", Required: true},
				{Name: "base_url", Label: "Base URL", Type: "select", Required: true, Options: []string{
					"https://api.crowdstrike.com",
					"https://api.us-2.crowdstrike.com",
					"https://api.eu-1.crowdstrike.com",
					"https://api.laggar.gcw.crowdstrike.com",
				}},
			},
			OptionalFields: []IntegrationField{
				{Name: "member_cid", Label: "Member CID", Type: "text", Description: "Para ambientes MSSP"},
			},
			Capabilities: []string{"detections", "incidents", "iocs", "hosts", "vulnerabilities", "spotlight", "real_time_response"},
			DefaultConfig: map[string]interface{}{
				"collect_detections": true,
				"collect_incidents":  true,
				"poll_interval":      90,
			},
			SetupSteps: []string{
				"Acesse Falcon Console",
				"Navegue até Support > API Clients and Keys",
				"Clique em 'Add new API client'",
				"Defina um nome (ex: SIEM Integration)",
				"Selecione as permissões necessárias",
				"Clique em 'Add' e anote Client ID e Secret",
				"Identifique sua Base URL (região)",
				"Teste a conexão",
			},
			Permissions: []string{
				"Detections: Read",
				"Incidents: Read",
				"Hosts: Read",
				"IOCs: Read",
				"Vulnerabilities: Read",
				"Spotlight: Read",
			},
		},
		{
			ID:            "template-splunk",
			Name:          "Splunk Enterprise",
			Vendor:        "Splunk",
			Type:          "siem",
			Description:   "Integração com Splunk para coleta de eventos, searches e alertas",
			Icon:          "StorageIcon",
			Documentation: "/docs/integrations/splunk",
			RequiredFields: []IntegrationField{
				{Name: "hostname", Label: "Splunk Hostname/IP", Type: "text", Required: true, Placeholder: "splunk.company.com"},
				{Name: "port", Label: "Management Port", Type: "number", Required: true, Default: 8089},
				{Name: "username", Label: "Username", Type: "text", Required: true},
				{Name: "password", Label: "Password", Type: "password", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "verify_ssl", Label: "Verify SSL", Type: "select", Options: []string{"true", "false"}, Default: "true"},
				{Name: "app_context", Label: "App Context", Type: "text", Default: "search"},
			},
			Capabilities: []string{"search", "alerts", "saved_searches", "indexes", "data_models", "kvstore"},
			DefaultConfig: map[string]interface{}{
				"collect_alerts": true,
				"poll_interval":  300,
			},
			SetupSteps: []string{
				"Acesse Splunk Web",
				"Navegue até Settings > Users and authentication",
				"Crie um novo usuário ou use existente",
				"Atribua role 'admin' ou crie role customizada",
				"Configure permissões de leitura em indexes",
				"Habilite API access",
				"Teste a conexão via REST API",
			},
			Permissions: []string{
				"search: Read",
				"indexes: Read",
				"saved_searches: Read",
				"alerts: Read",
				"data_models: Read",
			},
		},
		{
			ID:            "template-okta",
			Name:          "Okta",
			Vendor:        "Okta",
			Type:          IntegrationTypeIAM,
			Description:   "Integração com Okta para coleta de eventos de autenticação, usuários e aplicações",
			Icon:          "PeopleIcon",
			Documentation: "/docs/integrations/okta",
			RequiredFields: []IntegrationField{
				{Name: "domain", Label: "Okta Domain", Type: "text", Required: true, Placeholder: "company.okta.com"},
				{Name: "api_token", Label: "API Token", Type: "password", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "rate_limit", Label: "Rate Limit (req/min)", Type: "number", Default: 60},
			},
			Capabilities: []string{"system_log", "users", "groups", "applications", "authentication_events", "mfa_events", "policy_events"},
			DefaultConfig: map[string]interface{}{
				"collect_system_log": true,
				"collect_users":      true,
				"poll_interval":      120,
			},
			SetupSteps: []string{
				"Acesse Okta Admin Console",
				"Navegue até Security > API",
				"Clique em 'Create Token'",
				"Defina um nome (ex: SIEM Integration)",
				"Copie o token (será exibido apenas uma vez)",
				"Configure permissões de leitura",
				"Teste a conexão",
			},
			Permissions: []string{
				"okta.logs.read",
				"okta.users.read",
				"okta.groups.read",
				"okta.apps.read",
				"okta.events.read",
			},
		},
		{
			ID:            "template-cisco-firepower",
			Name:          "Cisco Firepower",
			Vendor:        "Cisco",
			Type:          IntegrationTypeFirewall,
			Description:   "Integração com Cisco Firepower para coleta de eventos, intrusions e file events",
			Icon:          "SecurityIcon",
			Documentation: "/docs/integrations/cisco-firepower",
			RequiredFields: []IntegrationField{
				{Name: "hostname", Label: "FMC Hostname/IP", Type: "text", Required: true, Placeholder: "fmc.company.com"},
				{Name: "username", Label: "Username", Type: "text", Required: true},
				{Name: "password", Label: "Password", Type: "password", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "domain_uuid", Label: "Domain UUID", Type: "text", Description: "UUID do domínio (padrão: Global)"},
				{Name: "verify_ssl", Label: "Verify SSL", Type: "select", Options: []string{"true", "false"}, Default: "true"},
			},
			Capabilities: []string{"events", "intrusions", "file_events", "malware_events", "connection_events", "security_intelligence"},
			DefaultConfig: map[string]interface{}{
				"collect_intrusions":  true,
				"collect_file_events": true,
				"poll_interval":       120,
			},
			SetupSteps: []string{
				"Acesse Firepower Management Center",
				"Navegue até System > Integration > REST API Preferences",
				"Habilite REST API",
				"Crie um usuário com permissões de leitura",
				"Configure event streaming (opcional)",
				"Teste a autenticação",
			},
			Permissions: []string{
				"Events: Read",
				"Intrusions: Read",
				"Files: Read",
				"Devices: Read",
				"Policies: Read",
			},
		},
		{
			ID:            "template-sentinelone",
			Name:          "SentinelOne",
			Vendor:        "SentinelOne",
			Type:          IntegrationTypeEDR,
			Description:   "Integração com SentinelOne para coleta de threats, agents e deep visibility events",
			Icon:          "SecurityIcon",
			Documentation: "/docs/integrations/sentinelone",
			RequiredFields: []IntegrationField{
				{Name: "console_url", Label: "Console URL", Type: "text", Required: true, Placeholder: "https://company.sentinelone.net"},
				{Name: "api_token", Label: "API Token", Type: "password", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "account_id", Label: "Account ID", Type: "text", Description: "ID da conta específica"},
				{Name: "site_id", Label: "Site ID", Type: "text", Description: "ID do site específico"},
			},
			Capabilities: []string{"threats", "agents", "activities", "deep_visibility", "firewall_control", "device_control"},
			DefaultConfig: map[string]interface{}{
				"collect_threats":    true,
				"collect_activities": true,
				"poll_interval":      90,
			},
			SetupSteps: []string{
				"Acesse SentinelOne Management Console",
				"Navegue até Settings > Users",
				"Crie um novo Service User ou use existente",
				"Clique em 'Generate' para criar API Token",
				"Atribua role 'Viewer' ou superior",
				"Copie o API Token",
				"Anote a Console URL",
				"Teste a conexão",
			},
			Permissions: []string{
				"Threats: View",
				"Agents: View",
				"Activities: View",
				"Deep Visibility: View",
				"Reports: View",
			},
		},
		{
			ID:            "template-zscaler",
			Name:          "Zscaler Internet Access",
			Vendor:        "Zscaler",
			Type:          "cloud_security",
			Description:   "Integração com Zscaler ZIA para coleta de web logs, firewall logs e DNS logs",
			Icon:          "CloudIcon",
			Documentation: "/docs/integrations/zscaler",
			RequiredFields: []IntegrationField{
				{Name: "cloud_name", Label: "Cloud Name", Type: "select", Required: true, Options: []string{"zscaler", "zscalerone", "zscalertwo", "zscalerthree", "zscloud", "zscalerbeta"}},
				{Name: "api_key", Label: "API Key", Type: "password", Required: true},
				{Name: "username", Label: "Admin Username", Type: "text", Required: true},
				{Name: "password", Label: "Admin Password", Type: "password", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "obfuscate_api_key", Label: "Obfuscate API Key", Type: "select", Options: []string{"true", "false"}, Default: "true"},
			},
			Capabilities: []string{"web_logs", "firewall_logs", "dns_logs", "tunnel_logs", "audit_logs", "sandbox_report"},
			DefaultConfig: map[string]interface{}{
				"collect_web_logs": true,
				"collect_fw_logs":  true,
				"poll_interval":    300,
			},
			SetupSteps: []string{
				"Acesse Zscaler Admin Portal",
				"Navegue até Administration > API Key Management",
				"Gere uma nova API Key",
				"Crie um usuário admin com role 'Auditor' ou 'Read-only Admin'",
				"Configure NSS (Nanolog Streaming Service) para logs",
				"Ou use Cloud NSS para streaming direto",
				"Teste a autenticação",
			},
			Permissions: []string{
				"Read-only Admin ou Auditor role",
				"API access enabled",
				"NSS configured (opcional)",
			},
		},
		{
			ID:            "template-qualys",
			Name:          "Qualys VMDR",
			Vendor:        "Qualys",
			Type:          "vulnerability_management",
			Description:   "Integração com Qualys para coleta de vulnerabilidades, assets e compliance data",
			Icon:          "BugReportIcon",
			Documentation: "/docs/integrations/qualys",
			RequiredFields: []IntegrationField{
				{Name: "platform", Label: "Platform", Type: "select", Required: true, Options: []string{
					"qualysapi.qualys.com",
					"qualysapi.qg2.apps.qualys.com",
					"qualysapi.qg3.apps.qualys.com",
					"qualysapi.qg4.apps.qualys.eu",
				}},
				{Name: "username", Label: "Username", Type: "text", Required: true},
				{Name: "password", Label: "Password", Type: "password", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "proxy", Label: "Proxy URL", Type: "text", Description: "HTTP proxy (opcional)"},
			},
			Capabilities: []string{"vulnerabilities", "assets", "scans", "compliance", "was", "policy_compliance"},
			DefaultConfig: map[string]interface{}{
				"collect_vulnerabilities": true,
				"collect_assets":          true,
				"poll_interval":           3600,
			},
			SetupSteps: []string{
				"Acesse Qualys Platform",
				"Navegue até Users > Users",
				"Crie um novo usuário ou use existente",
				"Atribua permissões de API access",
				"Configure permissões de leitura em módulos necessários",
				"Identifique sua plataforma (URL base)",
				"Teste a autenticação via API",
			},
			Permissions: []string{
				"API Access",
				"VM Module: Read",
				"Asset View: Read",
				"Scan: Read",
				"Compliance: Read (opcional)",
			},
		},
		{
			ID:            "template-tenable",
			Name:          "Tenable Nessus / Tenable.io",
			Vendor:        "Tenable",
			Type:          "vulnerability_management",
			Description:   "Integração com Tenable para coleta de vulnerabilidades, scans e assets",
			Icon:          "BugReportIcon",
			Documentation: "/docs/integrations/tenable",
			RequiredFields: []IntegrationField{
				{Name: "product", Label: "Product", Type: "select", Required: true, Options: []string{"Tenable.io", "Tenable.sc", "Nessus Professional"}},
				{Name: "access_key", Label: "Access Key", Type: "text", Required: true},
				{Name: "secret_key", Label: "Secret Key", Type: "password", Required: true},
			},
			OptionalFields: []IntegrationField{
				{Name: "hostname", Label: "Hostname", Type: "text", Description: "Para Tenable.sc ou Nessus on-premise"},
				{Name: "port", Label: "Port", Type: "number", Default: 443},
			},
			Capabilities: []string{"vulnerabilities", "assets", "scans", "exports", "plugins", "compliance"},
			DefaultConfig: map[string]interface{}{
				"collect_vulnerabilities": true,
				"collect_assets":          true,
				"poll_interval":           3600,
			},
			SetupSteps: []string{
				"Acesse Tenable.io ou Tenable.sc",
				"Navegue até Settings > My Account > API Keys",
				"Clique em 'Generate' para criar API Keys",
				"Copie Access Key e Secret Key",
				"Configure permissões adequadas",
				"Para on-premise: anote hostname e porta",
				"Teste a conexão",
			},
			Permissions: []string{
				"Can View: Vulnerabilities",
				"Can View: Assets",
				"Can View: Scans",
				"Can Use: API",
			},
		},
		{
			ID:            "template-aws-identity-center",
			Name:          "AWS Identity Center (AWS SSO)",
			Vendor:        VendorAWS,
			Type:          IntegrationTypeIAM,
			Description:   "Integração com AWS Identity Center para coleta de eventos de autenticação, usuários, grupos e atividades de SSO",
			Icon:          "PeopleIcon",
			Documentation: "/docs/integrations/aws-identity-center",
			RequiredFields: []IntegrationField{
				{Name: "access_key_id", Label: "AWS Access Key ID", Type: "text", Required: true, Description: "Access Key do usuário IAM com permissões"},
				{Name: "secret_access_key", Label: "AWS Secret Access Key", Type: "password", Required: true, Description: "Secret Key do usuário IAM"},
				{Name: "region", Label: "AWS Region", Type: "select", Required: true, Options: []string{
					"us-east-1",
					"us-east-2",
					"us-west-1",
					"us-west-2",
					"eu-west-1",
					"eu-west-2",
					"eu-central-1",
					"ap-southeast-1",
					"ap-southeast-2",
					"ap-northeast-1",
					"sa-east-1",
				}, Description: "Região onde o Identity Center está configurado"},
				{Name: "identity_store_id", Label: "Identity Store ID", Type: "text", Required: true, Placeholder: "d-1234567890", Description: "ID do Identity Store (encontrado no console)"},
			},
			OptionalFields: []IntegrationField{
				{Name: "instance_arn", Label: "SSO Instance ARN", Type: "text", Description: "ARN da instância do Identity Center"},
				{Name: "cloudtrail_enabled", Label: "Collect CloudTrail Events", Type: "select", Options: []string{"true", "false"}, Default: "true", Description: "Coletar eventos de CloudTrail para auditoria"},
				{Name: "cloudwatch_log_group", Label: "CloudWatch Log Group", Type: "text", Description: "Log group do CloudWatch para eventos SSO"},
			},
			Capabilities: []string{
				"authentication_events",
				"user_management",
				"group_management",
				"permission_sets",
				"account_assignments",
				"mfa_events",
				"audit_logs",
				"session_management",
			},
			DefaultConfig: map[string]interface{}{
				"collect_auth_events":         true,
				"collect_user_changes":        true,
				"collect_permission_sets":     true,
				"collect_account_assignments": true,
				"collect_cloudtrail":          true,
				"poll_interval":               120,
			},
			SetupSteps: []string{
				"Acesse AWS IAM Console",
				"Crie um novo usuário IAM para integração (ex: siem-identity-center-reader)",
				"Anexe as policies necessárias (veja lista de permissões)",
				"Gere Access Key e Secret Key para o usuário",
				"Acesse AWS Identity Center Console",
				"Anote o Identity Store ID (Settings > Identity source)",
				"Anote o Instance ARN (Settings > ARN)",
				"Configure CloudTrail para capturar eventos SSO (recomendado)",
				"Opcional: Configure CloudWatch Logs para eventos em tempo real",
				"Teste a conexão usando as credenciais",
			},
			Permissions: []string{
				"identitystore:DescribeUser",
				"identitystore:ListUsers",
				"identitystore:DescribeGroup",
				"identitystore:ListGroups",
				"identitystore:ListGroupMemberships",
				"sso:ListInstances",
				"sso:DescribePermissionSet",
				"sso:ListPermissionSets",
				"sso:ListAccountAssignments",
				"sso:ListAccountsForProvisionedPermissionSet",
				"sso-directory:DescribeUser",
				"sso-directory:DescribeGroup",
				"sso-directory:SearchUsers",
				"sso-directory:SearchGroups",
				"cloudtrail:LookupEvents (opcional)",
				"logs:FilterLogEvents (opcional para CloudWatch)",
			},
		},
		{
			ID:            "template-aws-config",
			Name:          "AWS Config",
			Vendor:        VendorAWS,
			Type:          "cspm",
			Description:   "Integração com AWS Config para monitoramento de configuração, compliance e postura de segurança",
			Icon:          "SettingsIcon",
			Documentation: "/docs/integrations/aws-config",
			RequiredFields: []IntegrationField{
				{Name: "access_key_id", Label: "AWS Access Key ID", Type: "text", Required: true},
				{Name: "secret_access_key", Label: "AWS Secret Access Key", Type: "password", Required: true},
				{Name: "region", Label: "Primary Region", Type: "select", Required: true, Options: []string{
					"us-east-1", "us-east-2", "us-west-1", "us-west-2",
					"eu-west-1", "eu-west-2", "eu-central-1",
					"ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
					"sa-east-1",
				}},
			},
			OptionalFields: []IntegrationField{
				{Name: "multi_region", Label: "Multi-Region Collection", Type: "select", Options: []string{"true", "false"}, Default: "true", Description: "Coletar de todas as regiões"},
				{Name: "aggregator_name", Label: "Config Aggregator Name", Type: "text", Description: "Nome do Config Aggregator (se configurado)"},
				{Name: "s3_bucket", Label: "Config S3 Bucket", Type: "text", Description: "Bucket S3 onde Config armazena snapshots"},
			},
			Capabilities: []string{
				"configuration_items",
				"compliance_status",
				"config_rules",
				"resource_inventory",
				"configuration_history",
				"compliance_timeline",
				"remediation_actions",
				"conformance_packs",
			},
			DefaultConfig: map[string]interface{}{
				"collect_compliance":     true,
				"collect_config_changes": true,
				"multi_region":           true,
				"poll_interval":          300,
			},
			SetupSteps: []string{
				"Acesse AWS IAM Console",
				"Crie usuário IAM: siem-config-reader",
				"Anexe policy: ReadOnlyAccess ou Config-specific permissions",
				"Gere Access Key e Secret Key",
				"Acesse AWS Config Console",
				"Verifique se Config está habilitado nas regiões desejadas",
				"Opcional: Configure Config Aggregator para multi-região/multi-conta",
				"Anote o nome do Aggregator (se usar)",
				"Teste a conexão",
			},
			Permissions: []string{
				"config:DescribeConfigRules",
				"config:DescribeComplianceByConfigRule",
				"config:DescribeComplianceByResource",
				"config:GetComplianceDetailsByConfigRule",
				"config:GetComplianceDetailsByResource",
				"config:DescribeConfigurationRecorders",
				"config:DescribeConfigurationRecorderStatus",
				"config:ListDiscoveredResources",
				"config:GetResourceConfigHistory",
				"config:DescribeConfigurationAggregators",
				"config:DescribeAggregateComplianceByConfigRules",
				"config:GetAggregateComplianceDetailsByConfigRule",
				"config:DescribeConformancePacks",
				"config:DescribeConformancePackCompliance",
			},
		},
		{
			ID:            "template-aws-security-hub",
			Name:          "AWS Security Hub",
			Vendor:        VendorAWS,
			Type:          "cspm",
			Description:   "Integração com AWS Security Hub para agregação de findings de segurança e compliance checks",
			Icon:          "SecurityIcon",
			Documentation: "/docs/integrations/aws-security-hub",
			RequiredFields: []IntegrationField{
				{Name: "access_key_id", Label: "AWS Access Key ID", Type: "text", Required: true},
				{Name: "secret_access_key", Label: "AWS Secret Access Key", Type: "password", Required: true},
				{Name: "region", Label: "Primary Region", Type: "select", Required: true, Options: []string{
					"us-east-1", "us-east-2", "us-west-1", "us-west-2",
					"eu-west-1", "eu-west-2", "eu-central-1",
					"ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
					"sa-east-1",
				}},
			},
			OptionalFields: []IntegrationField{
				{Name: "multi_region", Label: "Multi-Region Collection", Type: "select", Options: []string{"true", "false"}, Default: "true"},
				{Name: "severity_filter", Label: "Minimum Severity", Type: "select", Options: []string{"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, Default: "MEDIUM"},
				{Name: "standards", Label: "Collect Standards", Type: "select", Options: []string{"true", "false"}, Default: "true", Description: "CIS, PCI-DSS, AWS Foundational Security"},
			},
			Capabilities: []string{
				"security_findings",
				"compliance_standards",
				"cis_benchmark",
				"pci_dss_checks",
				"aws_foundational_security",
				"insights",
				"custom_actions",
				"finding_aggregation",
			},
			DefaultConfig: map[string]interface{}{
				"collect_findings":  true,
				"collect_standards": true,
				"multi_region":      true,
				"poll_interval":     180,
			},
			SetupSteps: []string{
				"Acesse AWS IAM Console",
				"Crie usuário IAM: siem-securityhub-reader",
				"Anexe as permissões necessárias",
				"Gere Access Key e Secret Key",
				"Acesse AWS Security Hub Console",
				"Habilite Security Hub nas regiões desejadas",
				"Habilite os standards: CIS, PCI-DSS, AWS Foundational Security",
				"Configure integrations com GuardDuty, Inspector, Macie (recomendado)",
				"Teste a conexão",
			},
			Permissions: []string{
				"securityhub:GetFindings",
				"securityhub:GetInsights",
				"securityhub:GetInsightResults",
				"securityhub:DescribeHub",
				"securityhub:DescribeStandards",
				"securityhub:DescribeStandardsControls",
				"securityhub:GetEnabledStandards",
				"securityhub:BatchImportFindings",
				"securityhub:GetMasterAccount",
				"securityhub:ListMembers",
			},
		},
		{
			ID:            "template-aws-guardduty",
			Name:          "AWS GuardDuty",
			Vendor:        VendorAWS,
			Type:          "threat_detection",
			Description:   "Integração com AWS GuardDuty para detecção de ameaças e atividades maliciosas",
			Icon:          "SecurityIcon",
			Documentation: "/docs/integrations/aws-guardduty",
			RequiredFields: []IntegrationField{
				{Name: "access_key_id", Label: "AWS Access Key ID", Type: "text", Required: true},
				{Name: "secret_access_key", Label: "AWS Secret Access Key", Type: "password", Required: true},
				{Name: "region", Label: "Primary Region", Type: "select", Required: true, Options: []string{
					"us-east-1", "us-east-2", "us-west-1", "us-west-2",
					"eu-west-1", "eu-west-2", "eu-central-1",
					"ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
					"sa-east-1",
				}},
			},
			OptionalFields: []IntegrationField{
				{Name: "multi_region", Label: "Multi-Region Collection", Type: "select", Options: []string{"true", "false"}, Default: "true"},
				{Name: "severity_filter", Label: "Minimum Severity", Type: "select", Options: []string{"0", "4", "7"}, Default: "4", Description: "0=Low, 4=Medium, 7=High"},
				{Name: "finding_types", Label: "Finding Types Filter", Type: "text", Description: "Filtro de tipos (vazio = todos)"},
			},
			Capabilities: []string{
				"threat_detection",
				"anomaly_detection",
				"malware_detection",
				"cryptocurrency_mining",
				"unauthorized_access",
				"reconnaissance",
				"instance_compromise",
				"account_compromise",
			},
			DefaultConfig: map[string]interface{}{
				"collect_findings": true,
				"multi_region":     true,
				"poll_interval":    120,
			},
			SetupSteps: []string{
				"Acesse AWS IAM Console",
				"Crie usuário IAM: siem-guardduty-reader",
				"Anexe as permissões necessárias",
				"Gere Access Key e Secret Key",
				"Acesse AWS GuardDuty Console",
				"Habilite GuardDuty nas regiões desejadas",
				"Configure S3 Protection, EKS Protection (opcional)",
				"Configure exportação para S3 (opcional)",
				"Teste a conexão",
			},
			Permissions: []string{
				"guardduty:GetDetector",
				"guardduty:ListDetectors",
				"guardduty:GetFindings",
				"guardduty:ListFindings",
				"guardduty:GetFindingsStatistics",
				"guardduty:DescribeOrganizationConfiguration",
				"guardduty:GetMasterAccount",
				"guardduty:ListMembers",
				"guardduty:GetThreatIntelSet",
				"guardduty:ListThreatIntelSets",
			},
		},
		{
			ID:            "template-aws-cloudtrail",
			Name:          "AWS CloudTrail",
			Vendor:        VendorAWS,
			Type:          "audit_logging",
			Description:   "Integração com AWS CloudTrail para coleta de audit logs e eventos de API calls",
			Icon:          "HistoryIcon",
			Documentation: "/docs/integrations/aws-cloudtrail",
			RequiredFields: []IntegrationField{
				{Name: "access_key_id", Label: "AWS Access Key ID", Type: "text", Required: true},
				{Name: "secret_access_key", Label: "AWS Secret Access Key", Type: "password", Required: true},
				{Name: "region", Label: "Primary Region", Type: "select", Required: true, Options: []string{
					"us-east-1", "us-east-2", "us-west-1", "us-west-2",
					"eu-west-1", "eu-west-2", "eu-central-1",
					"ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
					"sa-east-1",
				}},
				{Name: "s3_bucket", Label: "CloudTrail S3 Bucket", Type: "text", Required: true, Placeholder: "my-cloudtrail-bucket", Description: "Bucket onde CloudTrail armazena logs"},
			},
			OptionalFields: []IntegrationField{
				{Name: "s3_prefix", Label: "S3 Prefix", Type: "text", Description: "Prefixo dos logs no S3"},
				{Name: "multi_region", Label: "Multi-Region Trail", Type: "select", Options: []string{"true", "false"}, Default: "true"},
				{Name: "organization_trail", Label: "Organization Trail", Type: "select", Options: []string{"true", "false"}, Default: "false"},
				{Name: "event_selectors", Label: "Event Types", Type: "select", Options: []string{"all", "management", "data"}, Default: "all"},
			},
			Capabilities: []string{
				"api_calls",
				"management_events",
				"data_events",
				"insights_events",
				"user_activity",
				"resource_changes",
				"security_events",
				"compliance_audit",
			},
			DefaultConfig: map[string]interface{}{
				"collect_management_events": true,
				"collect_data_events":       false,
				"multi_region":              true,
				"poll_interval":             300,
			},
			SetupSteps: []string{
				"Acesse AWS IAM Console",
				"Crie usuário IAM: siem-cloudtrail-reader",
				"Anexe as permissões necessárias (CloudTrail + S3)",
				"Gere Access Key e Secret Key",
				"Acesse AWS CloudTrail Console",
				"Verifique se há um trail configurado",
				"Anote o nome do S3 bucket onde logs são armazenados",
				"Configure permissões de leitura no bucket S3",
				"Opcional: Habilite CloudTrail Insights",
				"Teste a conexão",
			},
			Permissions: []string{
				"cloudtrail:LookupEvents",
				"cloudtrail:DescribeTrails",
				"cloudtrail:GetTrailStatus",
				"cloudtrail:GetEventSelectors",
				"cloudtrail:GetInsightSelectors",
				"cloudtrail:ListTrails",
				"s3:GetObject",
				"s3:ListBucket",
				"s3:GetBucketLocation",
				"s3:GetBucketVersioning",
			},
		},
		{
			ID:            "template-aws-inspector",
			Name:          "AWS Inspector",
			Vendor:        VendorAWS,
			Type:          "vulnerability_assessment",
			Description:   "Integração com AWS Inspector para avaliação de vulnerabilidades em EC2 e ECR",
			Icon:          "BugReportIcon",
			Documentation: "/docs/integrations/aws-inspector",
			RequiredFields: []IntegrationField{
				{Name: "access_key_id", Label: "AWS Access Key ID", Type: "text", Required: true},
				{Name: "secret_access_key", Label: "AWS Secret Access Key", Type: "password", Required: true},
				{Name: "region", Label: "Primary Region", Type: "select", Required: true, Options: []string{
					"us-east-1", "us-east-2", "us-west-1", "us-west-2",
					"eu-west-1", "eu-west-2", "eu-central-1",
					"ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
					"sa-east-1",
				}},
			},
			OptionalFields: []IntegrationField{
				{Name: "multi_region", Label: "Multi-Region Collection", Type: "select", Options: []string{"true", "false"}, Default: "true"},
				{Name: "inspector_version", Label: "Inspector Version", Type: "select", Options: []string{"v2", "v1"}, Default: "v2", Description: "Inspector Classic (v1) ou Inspector v2"},
				{Name: "severity_filter", Label: "Minimum Severity", Type: "select", Options: []string{"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, Default: "MEDIUM"},
				{Name: "scan_ec2", Label: "Scan EC2 Instances", Type: "select", Options: []string{"true", "false"}, Default: "true"},
				{Name: "scan_ecr", Label: "Scan ECR Images", Type: "select", Options: []string{"true", "false"}, Default: "true"},
			},
			Capabilities: []string{
				"vulnerability_scanning",
				"ec2_assessment",
				"ecr_image_scanning",
				"network_reachability",
				"cve_detection",
				"package_vulnerabilities",
				"compliance_checks",
				"risk_scoring",
			},
			DefaultConfig: map[string]interface{}{
				"collect_findings": true,
				"scan_ec2":         true,
				"scan_ecr":         true,
				"multi_region":     true,
				"poll_interval":    600,
			},
			SetupSteps: []string{
				"Acesse AWS IAM Console",
				"Crie usuário IAM: siem-inspector-reader",
				"Anexe as permissões necessárias",
				"Gere Access Key e Secret Key",
				"Acesse AWS Inspector Console",
				"Habilite Inspector v2 nas regiões desejadas",
				"Ative scanning para EC2 e/ou ECR",
				"Configure auto-enable para novas instâncias (recomendado)",
				"Aguarde primeiro scan completar",
				"Teste a conexão",
			},
			Permissions: []string{
				"inspector2:ListFindings",
				"inspector2:ListFindingAggregations",
				"inspector2:GetFindingsReportStatus",
				"inspector2:DescribeOrganizationConfiguration",
				"inspector2:ListCoverage",
				"inspector2:GetMember",
				"inspector2:ListMembers",
				"inspector:DescribeFindings (v1)",
				"inspector:ListFindings (v1)",
				"inspector:DescribeAssessmentRuns (v1)",
				"ec2:DescribeInstances",
				"ecr:DescribeImages",
				"ecr:DescribeRepositories",
			},
		},
	}
}
