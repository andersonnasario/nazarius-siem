package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ZeroTrustIdentity represents an identity in Zero Trust
type ZeroTrustIdentity struct {
	ID              string    `json:"id"`
	Username        string    `json:"username"`
	Email           string    `json:"email"`
	Type            string    `json:"type"` // user, service, device
	TrustScore      float64   `json:"trust_score"` // 0-100
	RiskLevel       string    `json:"risk_level"` // low, medium, high, critical
	Status          string    `json:"status"` // active, suspended, blocked
	MFAEnabled      bool      `json:"mfa_enabled"`
	LastAuth        time.Time `json:"last_auth"`
	FailedAttempts  int       `json:"failed_attempts"`
	Devices         int       `json:"devices"`
	Locations       []string  `json:"locations"`
	Roles           []string  `json:"roles"`
	CreatedAt       time.Time `json:"created_at"`
}

// ZeroTrustDevice represents a device in Zero Trust
type ZeroTrustDevice struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"` // laptop, mobile, server, iot
	OS              string    `json:"os"`
	OSVersion       string    `json:"os_version"`
	UserID          string    `json:"user_id"`
	Username        string    `json:"username"`
	TrustScore      float64   `json:"trust_score"` // 0-100
	ComplianceScore float64   `json:"compliance_score"` // 0-100
	Status          string    `json:"status"` // compliant, non_compliant, quarantined
	Encrypted       bool      `json:"encrypted"`
	AntivirusStatus string    `json:"antivirus_status"` // active, inactive, outdated
	LastSeen        time.Time `json:"last_seen"`
	IPAddress       string    `json:"ip_address"`
	Location        string    `json:"location"`
	Vulnerabilities int       `json:"vulnerabilities"`
	RegisteredAt    time.Time `json:"registered_at"`
}

// ZeroTrustPolicy represents a Zero Trust policy
type ZeroTrustPolicy struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Type            string    `json:"type"` // access, device, network, data
	Status          string    `json:"status"` // active, inactive, testing
	Priority        int       `json:"priority"`
	Conditions      []string  `json:"conditions"`
	Actions         []string  `json:"actions"`
	AppliesTo       []string  `json:"applies_to"` // users, devices, resources
	Violations      int       `json:"violations"`
	Enforcements    int       `json:"enforcements"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	CreatedBy       string    `json:"created_by"`
}

// ZeroTrustAccess represents an access request/session
type ZeroTrustAccess struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	Username        string    `json:"username"`
	DeviceID        string    `json:"device_id"`
	DeviceName      string    `json:"device_name"`
	Resource        string    `json:"resource"`
	ResourceType    string    `json:"resource_type"` // application, data, network, system
	Action          string    `json:"action"` // read, write, execute, delete
	Decision        string    `json:"decision"` // allow, deny, challenge
	Reason          string    `json:"reason"`
	TrustScore      float64   `json:"trust_score"`
	RiskScore       float64   `json:"risk_score"`
	ContextFactors  []string  `json:"context_factors"`
	IPAddress       string    `json:"ip_address"`
	Location        string    `json:"location"`
	Timestamp       time.Time `json:"timestamp"`
	Duration        int       `json:"duration,omitempty"` // seconds
}

// ZeroTrustSegment represents a network microsegment
type ZeroTrustSegment struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Type            string    `json:"type"` // production, development, dmz, restricted
	Status          string    `json:"status"` // active, inactive
	Resources       int       `json:"resources"`
	Policies        int       `json:"policies"`
	AllowedSources  []string  `json:"allowed_sources"`
	BlockedSources  []string  `json:"blocked_sources"`
	TrafficIn       int64     `json:"traffic_in"` // bytes
	TrafficOut      int64     `json:"traffic_out"` // bytes
	Violations      int       `json:"violations"`
	LastActivity    time.Time `json:"last_activity"`
	CreatedAt       time.Time `json:"created_at"`
}

// ZeroTrustMetrics represents Zero Trust metrics
type ZeroTrustMetrics struct {
	TotalIdentities     int     `json:"total_identities"`
	ActiveIdentities    int     `json:"active_identities"`
	HighRiskIdentities  int     `json:"high_risk_identities"`
	TotalDevices        int     `json:"total_devices"`
	CompliantDevices    int     `json:"compliant_devices"`
	QuarantinedDevices  int     `json:"quarantined_devices"`
	ActivePolicies      int     `json:"active_policies"`
	PolicyViolations    int     `json:"policy_violations"`
	AccessRequests      int     `json:"access_requests"`
	DeniedAccess        int     `json:"denied_access"`
	AvgTrustScore       float64 `json:"avg_trust_score"`
	MFAAdoption         float64 `json:"mfa_adoption"` // percentage
}

// In-memory storage for policies (in production, use database)
var (
	zeroTrustPolicies = make(map[string]ZeroTrustPolicy)
	policyMutex       sync.RWMutex
)

// Initialize Zero Trust
func initZeroTrust() {
	// Initialize with default policies
	policyMutex.Lock()
	defer policyMutex.Unlock()
	
	// Add default policies
	defaultPolicies := []ZeroTrustPolicy{
		{
			ID:          "pol-001",
			Name:        "MFA Required for Admin Access",
			Description: "Enforce MFA for all administrative actions",
			Type:        "access",
			Status:      "active",
			Priority:    1,
			Conditions:  []string{"role=admin", "action=admin_*"},
			Actions:     []string{"require_mfa", "log_access"},
			AppliesTo:   []string{"users"},
			Violations:  3,
			Enforcements: 1247,
			CreatedAt:   time.Now().Add(-180 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-30 * 24 * time.Hour),
			CreatedBy:   "security-team",
		},
		{
			ID:          "pol-002",
			Name:        "Device Compliance Check",
			Description: "Block access from non-compliant devices",
			Type:        "device",
			Status:      "active",
			Priority:    2,
			Conditions:  []string{"compliance_score<70", "encryption=false"},
			Actions:     []string{"deny_access", "quarantine", "notify_admin"},
			AppliesTo:   []string{"devices"},
			Violations:  12,
			Enforcements: 45,
			CreatedAt:   time.Now().Add(-90 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-10 * 24 * time.Hour),
			CreatedBy:   "security-team",
		},
		{
			ID:          "pol-003",
			Name:        "Geo-Restriction for Sensitive Data",
			Description: "Block access to sensitive data from high-risk countries",
			Type:        "data",
			Status:      "active",
			Priority:    1,
			Conditions:  []string{"resource_type=sensitive", "location=high_risk"},
			Actions:     []string{"deny_access", "alert_soc", "log_attempt"},
			AppliesTo:   []string{"users", "devices"},
			Violations:  8,
			Enforcements: 23,
			CreatedAt:   time.Now().Add(-120 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-15 * 24 * time.Hour),
			CreatedBy:   "security-team",
		},
	}
	
	for _, policy := range defaultPolicies {
		zeroTrustPolicies[policy.ID] = policy
	}
}

// Handler: List identities
func (s *APIServer) handleListZeroTrustIdentities(c *gin.Context) {
	identities := []ZeroTrustIdentity{
		{
			ID:             "id-001",
			Username:       "john.doe",
			Email:          "john.doe@company.com",
			Type:           "user",
			TrustScore:     92.5,
			RiskLevel:      "low",
			Status:         "active",
			MFAEnabled:     true,
			LastAuth:       time.Now().Add(-15 * time.Minute),
			FailedAttempts: 0,
			Devices:        3,
			Locations:      []string{"New York, US", "London, UK"},
			Roles:          []string{"admin", "security-team"},
			CreatedAt:      time.Now().Add(-365 * 24 * time.Hour),
		},
		{
			ID:             "id-002",
			Username:       "api-service-prod",
			Email:          "api@company.com",
			Type:           "service",
			TrustScore:     98.0,
			RiskLevel:      "low",
			Status:         "active",
			MFAEnabled:     true,
			LastAuth:       time.Now().Add(-2 * time.Minute),
			FailedAttempts: 0,
			Devices:        1,
			Locations:      []string{"AWS us-east-1"},
			Roles:          []string{"api-service"},
			CreatedAt:      time.Now().Add(-180 * 24 * time.Hour),
		},
		{
			ID:             "id-003",
			Username:       "contractor.user",
			Email:          "contractor@external.com",
			Type:           "user",
			TrustScore:     65.0,
			RiskLevel:      "medium",
			Status:         "active",
			MFAEnabled:     false,
			LastAuth:       time.Now().Add(-2 * time.Hour),
			FailedAttempts: 2,
			Devices:        1,
			Locations:      []string{"Remote Location"},
			Roles:          []string{"contractor"},
			CreatedAt:      time.Now().Add(-30 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    identities,
	})
}

// Handler: List devices
func (s *APIServer) handleListZeroTrustDevices(c *gin.Context) {
	devices := []ZeroTrustDevice{
		{
			ID:              "dev-001",
			Name:            "LAPTOP-JOHN-001",
			Type:            "laptop",
			OS:              "Windows",
			OSVersion:       "11 Pro",
			UserID:          "id-001",
			Username:        "john.doe",
			TrustScore:      95.0,
			ComplianceScore: 98.0,
			Status:          "compliant",
			Encrypted:       true,
			AntivirusStatus: "active",
			LastSeen:        time.Now().Add(-5 * time.Minute),
			IPAddress:       "10.0.1.45",
			Location:        "New York, US",
			Vulnerabilities: 0,
			RegisteredAt:    time.Now().Add(-200 * 24 * time.Hour),
		},
		{
			ID:              "dev-002",
			Name:            "iPhone-John",
			Type:            "mobile",
			OS:              "iOS",
			OSVersion:       "17.2",
			UserID:          "id-001",
			Username:        "john.doe",
			TrustScore:      88.0,
			ComplianceScore: 92.0,
			Status:          "compliant",
			Encrypted:       true,
			AntivirusStatus: "active",
			LastSeen:        time.Now().Add(-30 * time.Minute),
			IPAddress:       "192.168.1.102",
			Location:        "New York, US",
			Vulnerabilities: 1,
			RegisteredAt:    time.Now().Add(-150 * 24 * time.Hour),
		},
		{
			ID:              "dev-003",
			Name:            "LAPTOP-CONTRACTOR",
			Type:            "laptop",
			OS:              "macOS",
			OSVersion:       "12.0",
			UserID:          "id-003",
			Username:        "contractor.user",
			TrustScore:      55.0,
			ComplianceScore: 60.0,
			Status:          "non_compliant",
			Encrypted:       false,
			AntivirusStatus: "outdated",
			LastSeen:        time.Now().Add(-2 * time.Hour),
			IPAddress:       "203.45.67.89",
			Location:        "Remote Location",
			Vulnerabilities: 5,
			RegisteredAt:    time.Now().Add(-30 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    devices,
	})
}

// Handler: List policies
func (s *APIServer) handleListZeroTrustPolicies(c *gin.Context) {
	policyMutex.RLock()
	defer policyMutex.RUnlock()

	policies := make([]ZeroTrustPolicy, 0, len(zeroTrustPolicies))
	for _, policy := range zeroTrustPolicies {
		policies = append(policies, policy)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    policies,
	})
}

// Handler: Create policy
func (s *APIServer) handleCreateZeroTrustPolicy(c *gin.Context) {
	var policy ZeroTrustPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request body: " + err.Error(),
		})
		return
	}

	// Validate required fields
	if policy.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Policy name is required",
		})
		return
	}

	if policy.Type == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Policy type is required",
		})
		return
	}

	policyMutex.Lock()
	defer policyMutex.Unlock()

	// Generate ID if not provided
	if policy.ID == "" {
		policy.ID = fmt.Sprintf("pol-%03d", len(zeroTrustPolicies)+1)
	}

	// Check if ID already exists
	if _, exists := zeroTrustPolicies[policy.ID]; exists {
		c.JSON(http.StatusConflict, gin.H{
			"success": false,
			"error":   "Policy with this ID already exists",
		})
		return
	}

	// Set timestamps
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	
	// Set default values
	if policy.Status == "" {
		policy.Status = "inactive"
	}
	if policy.Priority == 0 {
		policy.Priority = 10
	}
	if policy.CreatedBy == "" {
		policy.CreatedBy = "admin"
	}

	// Initialize counters
	policy.Violations = 0
	policy.Enforcements = 0

	// Store policy
	zeroTrustPolicies[policy.ID] = policy

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    policy,
		"message": "Policy created successfully",
	})
}

// Handler: Update policy
func (s *APIServer) handleUpdateZeroTrustPolicy(c *gin.Context) {
	policyID := c.Param("id")

	var updates ZeroTrustPolicy
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request body: " + err.Error(),
		})
		return
	}

	policyMutex.Lock()
	defer policyMutex.Unlock()

	// Check if policy exists
	existing, exists := zeroTrustPolicies[policyID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Policy not found",
		})
		return
	}

	// Update fields (preserve ID, CreatedAt, and counters)
	if updates.Name != "" {
		existing.Name = updates.Name
	}
	if updates.Description != "" {
		existing.Description = updates.Description
	}
	if updates.Type != "" {
		existing.Type = updates.Type
	}
	if updates.Status != "" {
		existing.Status = updates.Status
	}
	if updates.Priority != 0 {
		existing.Priority = updates.Priority
	}
	if len(updates.Conditions) > 0 {
		existing.Conditions = updates.Conditions
	}
	if len(updates.Actions) > 0 {
		existing.Actions = updates.Actions
	}
	if len(updates.AppliesTo) > 0 {
		existing.AppliesTo = updates.AppliesTo
	}

	existing.UpdatedAt = time.Now()

	// Store updated policy
	zeroTrustPolicies[policyID] = existing

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    existing,
		"message": "Policy updated successfully",
	})
}

// Handler: Delete policy
func (s *APIServer) handleDeleteZeroTrustPolicy(c *gin.Context) {
	policyID := c.Param("id")

	policyMutex.Lock()
	defer policyMutex.Unlock()

	// Check if policy exists
	policy, exists := zeroTrustPolicies[policyID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Policy not found",
		})
		return
	}

	// Delete policy
	delete(zeroTrustPolicies, policyID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Policy deleted successfully",
		"data":    policy,
	})
}

// Handler: Toggle policy status
func (s *APIServer) handleToggleZeroTrustPolicy(c *gin.Context) {
	policyID := c.Param("id")

	policyMutex.Lock()
	defer policyMutex.Unlock()

	// Check if policy exists
	policy, exists := zeroTrustPolicies[policyID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Policy not found",
		})
		return
	}

	// Toggle status
	if policy.Status == "active" {
		policy.Status = "inactive"
	} else {
		policy.Status = "active"
	}
	policy.UpdatedAt = time.Now()

	// Store updated policy
	zeroTrustPolicies[policyID] = policy

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    policy,
		"message": fmt.Sprintf("Policy %s successfully", policy.Status),
	})
}

// Handler: List access requests
func (s *APIServer) handleListZeroTrustAccess(c *gin.Context) {
	access := []ZeroTrustAccess{
		{
			ID:             "acc-001",
			UserID:         "id-001",
			Username:       "john.doe",
			DeviceID:       "dev-001",
			DeviceName:     "LAPTOP-JOHN-001",
			Resource:       "/api/admin/users",
			ResourceType:   "application",
			Action:         "read",
			Decision:       "allow",
			Reason:         "High trust score, MFA verified, compliant device",
			TrustScore:     92.5,
			RiskScore:      8.0,
			ContextFactors: []string{"mfa_verified", "known_device", "normal_location"},
			IPAddress:      "10.0.1.45",
			Location:       "New York, US",
			Timestamp:      time.Now().Add(-5 * time.Minute),
			Duration:       120,
		},
		{
			ID:             "acc-002",
			UserID:         "id-003",
			Username:       "contractor.user",
			DeviceID:       "dev-003",
			DeviceName:     "LAPTOP-CONTRACTOR",
			Resource:       "/api/sensitive/data",
			ResourceType:   "data",
			Action:         "write",
			Decision:       "deny",
			Reason:         "Non-compliant device, no MFA, medium trust score",
			TrustScore:     65.0,
			RiskScore:      78.0,
			ContextFactors: []string{"no_mfa", "non_compliant_device", "unusual_location"},
			IPAddress:      "203.45.67.89",
			Location:       "Remote Location",
			Timestamp:      time.Now().Add(-15 * time.Minute),
		},
		{
			ID:             "acc-003",
			UserID:         "id-002",
			Username:       "api-service-prod",
			DeviceID:       "dev-service-001",
			DeviceName:     "API-SERVER-PROD",
			Resource:       "/database/customer_data",
			ResourceType:   "data",
			Action:         "read",
			Decision:       "allow",
			Reason:         "Service account, high trust score, expected behavior",
			TrustScore:     98.0,
			RiskScore:      2.0,
			ContextFactors: []string{"service_account", "expected_pattern", "secure_network"},
			IPAddress:      "10.0.2.10",
			Location:       "AWS us-east-1",
			Timestamp:      time.Now().Add(-2 * time.Minute),
			Duration:       5,
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    access,
	})
}

// Handler: List network segments
func (s *APIServer) handleListZeroTrustSegments(c *gin.Context) {
	segments := []ZeroTrustSegment{
		{
			ID:             "seg-001",
			Name:           "Production Environment",
			Description:    "Production servers and databases",
			Type:           "production",
			Status:         "active",
			Resources:      145,
			Policies:       8,
			AllowedSources: []string{"10.0.0.0/16", "172.16.0.0/12"},
			BlockedSources: []string{"0.0.0.0/0"},
			TrafficIn:      1024000000,
			TrafficOut:     512000000,
			Violations:     2,
			LastActivity:   time.Now().Add(-1 * time.Minute),
			CreatedAt:      time.Now().Add(-365 * 24 * time.Hour),
		},
		{
			ID:             "seg-002",
			Name:           "DMZ",
			Description:    "Demilitarized zone for public-facing services",
			Type:           "dmz",
			Status:         "active",
			Resources:      23,
			Policies:       12,
			AllowedSources: []string{"0.0.0.0/0"},
			BlockedSources: []string{"10.0.0.0/8"},
			TrafficIn:      5120000000,
			TrafficOut:     2048000000,
			Violations:     15,
			LastActivity:   time.Now().Add(-30 * time.Second),
			CreatedAt:      time.Now().Add(-300 * 24 * time.Hour),
		},
		{
			ID:             "seg-003",
			Name:           "Restricted - Finance",
			Description:    "Highly restricted segment for financial systems",
			Type:           "restricted",
			Status:         "active",
			Resources:      12,
			Policies:       15,
			AllowedSources: []string{"10.0.100.0/24"},
			BlockedSources: []string{"0.0.0.0/0"},
			TrafficIn:      102400000,
			TrafficOut:     51200000,
			Violations:     0,
			LastActivity:   time.Now().Add(-5 * time.Minute),
			CreatedAt:      time.Now().Add(-200 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    segments,
	})
}

// Handler: Get Zero Trust metrics
func (s *APIServer) handleGetZeroTrustMetrics(c *gin.Context) {
	metrics := ZeroTrustMetrics{
		TotalIdentities:    2847,
		ActiveIdentities:   2145,
		HighRiskIdentities: 23,
		TotalDevices:       3421,
		CompliantDevices:   3156,
		QuarantinedDevices: 45,
		ActivePolicies:     67,
		PolicyViolations:   142,
		AccessRequests:     45678,
		DeniedAccess:       892,
		AvgTrustScore:      87.5,
		MFAAdoption:        94.2,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    metrics,
	})
}


