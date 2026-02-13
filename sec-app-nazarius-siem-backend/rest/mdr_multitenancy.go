package main

import (
	"net/http"
	"sync"
	"time"
	"github.com/gin-gonic/gin"
)

// MDR Multi-Tenancy structures
type MDRTenant struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Domain      string    `json:"domain"`
	Status      string    `json:"status"` // active, suspended, trial
	Plan        string    `json:"plan"`   // basic, professional, enterprise
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	UserCount   int       `json:"user_count"`
	EventCount  int64     `json:"event_count"`
	StorageUsed int64     `json:"storage_used"` // in bytes
	MaxUsers    int       `json:"max_users"`
	MaxStorage  int64     `json:"max_storage"` // in bytes
}

type MDRTenantConfig struct {
	TenantID    string                 `json:"tenant_id"`
	Settings    map[string]interface{} `json:"settings"`
	Limits      map[string]int         `json:"limits"`
	Features    []string               `json:"features"`
	Integrations []string              `json:"integrations"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type MDRTenantUser struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"` // admin, analyst, viewer
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	LastLogin time.Time `json:"last_login"`
}

type MDRTenantUsage struct {
	TenantID      string    `json:"tenant_id"`
	Date          time.Time `json:"date"`
	EventsIngested int64    `json:"events_ingested"`
	AlertsGenerated int64   `json:"alerts_generated"`
	StorageUsed   int64     `json:"storage_used"`
	APICallsMade  int64     `json:"api_calls_made"`
}

var (
	mdrTenants       = make(map[string]*MDRTenant)
	mdrTenantConfigs = make(map[string]*MDRTenantConfig)
	mdrTenantUsers   = make(map[string]*MDRTenantUser)
	mdrTenantUsage   = make(map[string]*MDRTenantUsage)
	mdrTenantMutex   sync.RWMutex
)

func initMDRMultiTenancy() {
	mdrTenantMutex.Lock()
	defer mdrTenantMutex.Unlock()

	// Sample tenants
	tenant1 := &MDRTenant{
		ID:          "mdr-tenant-001",
		Name:        "Acme Corporation",
		Domain:      "acme.com",
		Status:      "active",
		Plan:        "enterprise",
		CreatedAt:   time.Now().Add(-90 * 24 * time.Hour),
		UpdatedAt:   time.Now(),
		UserCount:   25,
		EventCount:  1500000,
		StorageUsed: 50 * 1024 * 1024 * 1024, // 50 GB
		MaxUsers:    100,
		MaxStorage:  500 * 1024 * 1024 * 1024, // 500 GB
	}
	mdrTenants[tenant1.ID] = tenant1

	tenant2 := &MDRTenant{
		ID:          "mdr-tenant-002",
		Name:        "TechStart Inc",
		Domain:      "techstart.io",
		Status:      "active",
		Plan:        "professional",
		CreatedAt:   time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:   time.Now(),
		UserCount:   10,
		EventCount:  500000,
		StorageUsed: 15 * 1024 * 1024 * 1024, // 15 GB
		MaxUsers:    50,
		MaxStorage:  200 * 1024 * 1024 * 1024, // 200 GB
	}
	mdrTenants[tenant2.ID] = tenant2

	tenant3 := &MDRTenant{
		ID:          "mdr-tenant-003",
		Name:        "Small Business LLC",
		Domain:      "smallbiz.com",
		Status:      "trial",
		Plan:        "basic",
		CreatedAt:   time.Now().Add(-7 * 24 * time.Hour),
		UpdatedAt:   time.Now(),
		UserCount:   3,
		EventCount:  50000,
		StorageUsed: 2 * 1024 * 1024 * 1024, // 2 GB
		MaxUsers:    10,
		MaxStorage:  50 * 1024 * 1024 * 1024, // 50 GB
	}
	mdrTenants[tenant3.ID] = tenant3

	// Sample config
	config1 := &MDRTenantConfig{
		TenantID: "mdr-tenant-001",
		Settings: map[string]interface{}{
			"retention_days": 365,
			"alert_threshold": "medium",
			"auto_response": true,
		},
		Limits: map[string]int{
			"max_alerts_per_day": 10000,
			"max_api_calls": 100000,
		},
		Features: []string{"advanced_analytics", "threat_hunting", "automated_response"},
		Integrations: []string{"slack", "email", "webhook"},
		UpdatedAt: time.Now(),
	}
	mdrTenantConfigs[config1.TenantID] = config1
}

// Handlers
func (s *APIServer) handleListMDRTenants(c *gin.Context) {
	mdrTenantMutex.RLock()
	defer mdrTenantMutex.RUnlock()

	tenants := make([]*MDRTenant, 0, len(mdrTenants))
	for _, t := range mdrTenants {
		tenants = append(tenants, t)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": tenants})
}

func (s *APIServer) handleCreateMDRTenant(c *gin.Context) {
	var tenant MDRTenant
	if err := c.ShouldBindJSON(&tenant); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	tenant.ID = generateID()
	tenant.CreatedAt = time.Now()
	tenant.UpdatedAt = time.Now()
	tenant.Status = "active"
	tenant.UserCount = 0
	tenant.EventCount = 0
	tenant.StorageUsed = 0

	// Set defaults based on plan
	switch tenant.Plan {
	case "enterprise":
		tenant.MaxUsers = 100
		tenant.MaxStorage = 500 * 1024 * 1024 * 1024
	case "professional":
		tenant.MaxUsers = 50
		tenant.MaxStorage = 200 * 1024 * 1024 * 1024
	default: // basic
		tenant.MaxUsers = 10
		tenant.MaxStorage = 50 * 1024 * 1024 * 1024
	}

	mdrTenantMutex.Lock()
	mdrTenants[tenant.ID] = &tenant
	mdrTenantMutex.Unlock()

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": tenant})
}

func (s *APIServer) handleGetMDRTenant(c *gin.Context) {
	id := c.Param("id")

	mdrTenantMutex.RLock()
	tenant, exists := mdrTenants[id]
	mdrTenantMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Tenant not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": tenant})
}

func (s *APIServer) handleUpdateMDRTenant(c *gin.Context) {
	id := c.Param("id")

	mdrTenantMutex.Lock()
	defer mdrTenantMutex.Unlock()

	tenant, exists := mdrTenants[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Tenant not found"})
		return
	}

	var updates MDRTenant
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	// Update fields
	if updates.Name != "" {
		tenant.Name = updates.Name
	}
	if updates.Status != "" {
		tenant.Status = updates.Status
	}
	if updates.Plan != "" {
		tenant.Plan = updates.Plan
	}
	tenant.UpdatedAt = time.Now()

	c.JSON(http.StatusOK, gin.H{"success": true, "data": tenant})
}

func (s *APIServer) handleGetMDRTenantConfig(c *gin.Context) {
	tenantID := c.Param("id")

	mdrTenantMutex.RLock()
	config, exists := mdrTenantConfigs[tenantID]
	mdrTenantMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Config not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": config})
}

func (s *APIServer) handleGetMDRTenantStats(c *gin.Context) {
	mdrTenantMutex.RLock()
	defer mdrTenantMutex.RUnlock()

	activeTenants := 0
	trialTenants := 0
	totalUsers := 0
	totalEvents := int64(0)
	totalStorage := int64(0)

	for _, t := range mdrTenants {
		if t.Status == "active" {
			activeTenants++
		} else if t.Status == "trial" {
			trialTenants++
		}
		totalUsers += t.UserCount
		totalEvents += t.EventCount
		totalStorage += t.StorageUsed
	}

	stats := gin.H{
		"total_tenants":   len(mdrTenants),
		"active_tenants":  activeTenants,
		"trial_tenants":   trialTenants,
		"total_users":     totalUsers,
		"total_events":    totalEvents,
		"total_storage_gb": totalStorage / (1024 * 1024 * 1024),
		"avg_users_per_tenant": float64(totalUsers) / float64(len(mdrTenants)),
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": stats})
}

