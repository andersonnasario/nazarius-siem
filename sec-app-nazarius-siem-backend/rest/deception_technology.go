package main

import (
	"net/http"
	"sync"
	"time"
	"github.com/gin-gonic/gin"
)

// Deception Technology structures
type Honeypot struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"` // ssh, rdp, http, smb, database
	Status      string    `json:"status"` // active, inactive, compromised
	IPAddress   string    `json:"ip_address"`
	Port        int       `json:"port"`
	Location    string    `json:"location"`
	DeployedAt  time.Time `json:"deployed_at"`
	LastActivity time.Time `json:"last_activity"`
	Interactions int      `json:"interactions"`
	Alerts      int       `json:"alerts"`
}

type Honeytoken struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // credential, file, api_key, cookie
	Value       string                 `json:"value"`
	Location    string                 `json:"location"`
	Status      string                 `json:"status"` // active, triggered, expired
	CreatedAt   time.Time              `json:"created_at"`
	TriggeredAt *time.Time             `json:"triggered_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type DecoySystem struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"` // server, workstation, iot, network_device
	OS          string    `json:"os"`
	Services    []string  `json:"services"`
	Status      string    `json:"status"`
	IPAddress   string    `json:"ip_address"`
	Hostname    string    `json:"hostname"`
	DeployedAt  time.Time `json:"deployed_at"`
	Interactions int      `json:"interactions"`
}

type AttackerActivity struct {
	ID            string    `json:"id"`
	SourceIP      string    `json:"source_ip"`
	TargetID      string    `json:"target_id"` // honeypot/honeytoken/decoy ID
	TargetType    string    `json:"target_type"`
	ActivityType  string    `json:"activity_type"` // scan, login_attempt, file_access, command_exec
	Timestamp     time.Time `json:"timestamp"`
	Details       string    `json:"details"`
	Severity      string    `json:"severity"`
	AlertGenerated bool     `json:"alert_generated"`
}

type DeceptionAlert struct {
	ID          string    `json:"id"`
	ActivityID  string    `json:"activity_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"` // new, investigating, resolved
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	AssignedTo  string    `json:"assigned_to"`
}

type DeceptionMetrics struct {
	TotalHoneypots     int     `json:"total_honeypots"`
	ActiveHoneypots    int     `json:"active_honeypots"`
	TotalHoneytokens   int     `json:"total_honeytokens"`
	TriggeredTokens    int     `json:"triggered_tokens"`
	TotalDecoys        int     `json:"total_decoys"`
	TotalInteractions  int     `json:"total_interactions"`
	AlertsGenerated    int     `json:"alerts_generated"`
	DetectionRate      float64 `json:"detection_rate"`
	AvgResponseTime    float64 `json:"avg_response_time"` // minutes
	TopAttackerIPs     []string `json:"top_attacker_ips"`
}

var (
	honeypots         = make(map[string]*Honeypot)
	honeytokens       = make(map[string]*Honeytoken)
	decoySystems      = make(map[string]*DecoySystem)
	attackerActivity  = make(map[string]*AttackerActivity)
	deceptionAlerts   = make(map[string]*DeceptionAlert)
	deceptionMutex    sync.RWMutex
)

func initDeceptionTechnology() {
	deceptionMutex.Lock()
	defer deceptionMutex.Unlock()

	// Sample honeypots
	honeypot1 := &Honeypot{
		ID:           "hp-001",
		Name:         "SSH Honeypot - DMZ",
		Type:         "ssh",
		Status:       "active",
		IPAddress:    "10.0.1.50",
		Port:         22,
		Location:     "DMZ",
		DeployedAt:   time.Now().Add(-30 * 24 * time.Hour),
		LastActivity: time.Now().Add(-2 * time.Hour),
		Interactions: 145,
		Alerts:       12,
	}
	honeypots[honeypot1.ID] = honeypot1

	honeypot2 := &Honeypot{
		ID:           "hp-002",
		Name:         "RDP Honeypot - Internal",
		Type:         "rdp",
		Status:       "active",
		IPAddress:    "192.168.1.100",
		Port:         3389,
		Location:     "Internal Network",
		DeployedAt:   time.Now().Add(-15 * 24 * time.Hour),
		LastActivity: time.Now().Add(-5 * time.Hour),
		Interactions: 78,
		Alerts:       8,
	}
	honeypots[honeypot2.ID] = honeypot2

	// Sample honeytokens
	token1 := &Honeytoken{
		ID:        "ht-001",
		Name:      "Fake Admin Credentials",
		Type:      "credential",
		Value:     "admin:P@ssw0rd123!",
		Location:  "\\\\fileserver\\shared\\passwords.txt",
		Status:    "active",
		CreatedAt: time.Now().Add(-20 * 24 * time.Hour),
		Metadata:  map[string]interface{}{"username": "admin", "service": "database"},
	}
	honeytokens[token1.ID] = token1

	triggeredTime := time.Now().Add(-3 * 24 * time.Hour)
	token2 := &Honeytoken{
		ID:          "ht-002",
		Name:        "Fake API Key",
		Type:        "api_key",
		Value:       "sk_test_fake_key_12345",
		Location:    "config.json",
		Status:      "triggered",
		CreatedAt:   time.Now().Add(-10 * 24 * time.Hour),
		TriggeredAt: &triggeredTime,
		Metadata:    map[string]interface{}{"service": "payment_api"},
	}
	honeytokens[token2.ID] = token2

	// Sample decoy
	decoy1 := &DecoySystem{
		ID:           "decoy-001",
		Name:         "Fake File Server",
		Type:         "server",
		OS:           "Windows Server 2019",
		Services:     []string{"SMB", "FTP"},
		Status:       "active",
		IPAddress:    "192.168.1.150",
		Hostname:     "FS-FINANCE-01",
		DeployedAt:   time.Now().Add(-25 * 24 * time.Hour),
		Interactions: 34,
	}
	decoySystems[decoy1.ID] = decoy1

	// Sample attacker activity
	activity1 := &AttackerActivity{
		ID:             "act-001",
		SourceIP:       "203.0.113.45",
		TargetID:       "hp-001",
		TargetType:     "honeypot",
		ActivityType:   "login_attempt",
		Timestamp:      time.Now().Add(-2 * time.Hour),
		Details:        "Failed SSH login attempt with username 'root'",
		Severity:       "medium",
		AlertGenerated: true,
	}
	attackerActivity[activity1.ID] = activity1
}

// Handlers
func (s *APIServer) handleListHoneypots(c *gin.Context) {
	deceptionMutex.RLock()
	defer deceptionMutex.RUnlock()

	hps := make([]*Honeypot, 0, len(honeypots))
	for _, hp := range honeypots {
		hps = append(hps, hp)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": hps})
}

func (s *APIServer) handleCreateHoneypot(c *gin.Context) {
	var hp Honeypot
	if err := c.ShouldBindJSON(&hp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	hp.ID = generateID()
	hp.DeployedAt = time.Now()
	hp.Status = "active"

	deceptionMutex.Lock()
	honeypots[hp.ID] = &hp
	deceptionMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": hp})
}

func (s *APIServer) handleListHoneytokens(c *gin.Context) {
	deceptionMutex.RLock()
	defer deceptionMutex.RUnlock()

	tokens := make([]*Honeytoken, 0, len(honeytokens))
	for _, token := range honeytokens {
		tokens = append(tokens, token)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": tokens})
}

func (s *APIServer) handleCreateHoneytoken(c *gin.Context) {
	var token Honeytoken
	if err := c.ShouldBindJSON(&token); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	token.ID = generateID()
	token.CreatedAt = time.Now()
	token.Status = "active"

	deceptionMutex.Lock()
	honeytokens[token.ID] = &token
	deceptionMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": token})
}

func (s *APIServer) handleListDecoySystems(c *gin.Context) {
	deceptionMutex.RLock()
	defer deceptionMutex.RUnlock()

	decoys := make([]*DecoySystem, 0, len(decoySystems))
	for _, decoy := range decoySystems {
		decoys = append(decoys, decoy)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": decoys})
}

func (s *APIServer) handleListAttackerActivity(c *gin.Context) {
	deceptionMutex.RLock()
	defer deceptionMutex.RUnlock()

	activities := make([]*AttackerActivity, 0, len(attackerActivity))
	for _, activity := range attackerActivity {
		activities = append(activities, activity)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": activities})
}

func (s *APIServer) handleGetDeceptionMetrics(c *gin.Context) {
	deceptionMutex.RLock()
	defer deceptionMutex.RUnlock()

	activeHoneypots := 0
	totalInteractions := 0
	totalAlerts := 0

	for _, hp := range honeypots {
		if hp.Status == "active" {
			activeHoneypots++
		}
		totalInteractions += hp.Interactions
		totalAlerts += hp.Alerts
	}

	triggeredTokens := 0
	for _, token := range honeytokens {
		if token.Status == "triggered" {
			triggeredTokens++
		}
	}

	metrics := DeceptionMetrics{
		TotalHoneypots:    len(honeypots),
		ActiveHoneypots:   activeHoneypots,
		TotalHoneytokens:  len(honeytokens),
		TriggeredTokens:   triggeredTokens,
		TotalDecoys:       len(decoySystems),
		TotalInteractions: totalInteractions,
		AlertsGenerated:   totalAlerts,
		DetectionRate:     94.5,
		AvgResponseTime:   3.2,
		TopAttackerIPs:    []string{"203.0.113.45", "198.51.100.23", "192.0.2.100"},
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": metrics})
}

