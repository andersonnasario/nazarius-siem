package main

// =============================================================================
// CSPM GCP - Google Cloud Platform Integration
// =============================================================================
// Provides handlers for GCP Security Command Center, Cloud Asset Inventory,
// Cloud Audit Logs, IAM analysis, and compliance checks.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	logging "cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/logging/apiv2/loggingpb"
	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/gin-gonic/gin"
	"github.com/opensearch-project/opensearch-go/v2"
	"github.com/opensearch-project/opensearch-go/v2/opensearchapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	ltype "google.golang.org/genproto/googleapis/logging/type"
)

// ---------------------------------------------------------------------------
// GCP Configuration & State
// ---------------------------------------------------------------------------

// GCPConfig represents the GCP integration configuration
type GCPConfig struct {
	ProjectID           string   `json:"project_id"`
	OrganizationID      string   `json:"organization_id"`
	CredentialsJSON     string   `json:"credentials_json,omitempty"` // Service Account JSON key
	CredentialsFilePath string   `json:"credentials_file_path,omitempty"`
	Enabled             bool     `json:"enabled"`
	SyncPeriodMinutes   int      `json:"sync_period_minutes"`
	EnabledServices     []string `json:"enabled_services"` // scc, asset, audit, iam
}

// GCPCollector manages GCP data collection
type GCPCollector struct {
	config           GCPConfig
	opensearchClient *opensearch.Client
	mu               sync.RWMutex
	running          bool
	stopCh           chan struct{}
	lastSync         time.Time
	eventsCollected  int64
	lastError        string
}

var (
	gcpCollector     *GCPCollector
	gcpCollectorOnce sync.Once
)

const gcpEventsIndex = "siem-gcp-findings"
const gcpConfigDocID = "gcp-config"

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

// InitGCPCollector initializes the GCP collector (singleton)
func InitGCPCollector(osClient *opensearch.Client) *GCPCollector {
	gcpCollectorOnce.Do(func() {
		gcpCollector = &GCPCollector{
			opensearchClient: osClient,
			stopCh:           make(chan struct{}),
			config: GCPConfig{
				SyncPeriodMinutes: 30,
				EnabledServices:   []string{"scc", "asset", "audit"},
			},
		}
		gcpCollector.loadConfig()
		gcpCollector.createIndex()
		log.Println("✅ GCP Collector initialized")
	})
	return gcpCollector
}

func (c *GCPCollector) loadConfig() {
	if c.opensearchClient == nil {
		return
	}
	req := opensearchapi.GetRequest{
		Index:      "siem-integrations-config",
		DocumentID: gcpConfigDocID,
	}
	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil || res.IsError() {
		return
	}
	defer res.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return
	}
	source, ok := result["_source"].(map[string]interface{})
	if !ok {
		return
	}
	data, _ := json.Marshal(source)
	json.Unmarshal(data, &c.config)
}

func (c *GCPCollector) saveConfig() error {
	if c.opensearchClient == nil {
		return fmt.Errorf("opensearch client not available")
	}
	// Strip credentials_json from persisted data for security
	configCopy := c.config
	configCopy.CredentialsJSON = "" // Don't persist raw JSON creds in OpenSearch
	data, err := json.Marshal(configCopy)
	if err != nil {
		return err
	}
	req := opensearchapi.IndexRequest{
		Index:      "siem-integrations-config",
		DocumentID: gcpConfigDocID,
		Body:       strings.NewReader(string(data)),
	}
	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return nil
}

func (c *GCPCollector) createIndex() {
	if c.opensearchClient == nil {
		return
	}
	mapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 1
		},
		"mappings": {
			"properties": {
				"finding_id":        {"type": "keyword"},
				"source":            {"type": "keyword"},
				"category":          {"type": "keyword"},
				"severity":          {"type": "keyword"},
				"state":             {"type": "keyword"},
				"resource_name":     {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
				"resource_type":     {"type": "keyword"},
				"project_id":        {"type": "keyword"},
				"organization_id":   {"type": "keyword"},
				"title":             {"type": "text"},
				"description":       {"type": "text"},
				"recommendation":    {"type": "text"},
				"event_time":        {"type": "date"},
				"create_time":       {"type": "date"},
				"external_uri":      {"type": "keyword"},
				"canonical_name":    {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
				"mute_state":        {"type": "keyword"},
				"provider":          {"type": "keyword"},
				"raw_finding":       {"type": "object", "enabled": false},
				"indexed_at":        {"type": "date"}
			}
		}
	}`
	req := opensearchapi.IndicesCreateRequest{
		Index: gcpEventsIndex,
		Body:  strings.NewReader(mapping),
	}
	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		log.Printf("[GCP] Error creating index: %v", err)
		return
	}
	defer res.Body.Close()
	if !res.IsError() {
		log.Printf("✅ GCP findings index created: %s", gcpEventsIndex)
	}
}

// ---------------------------------------------------------------------------
// Client creation helpers
// ---------------------------------------------------------------------------

func (c *GCPCollector) getClientOptions() []option.ClientOption {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Priority: 1) Inline JSON creds, 2) Creds file path, 3) GOOGLE_APPLICATION_CREDENTIALS env
	if c.config.CredentialsJSON != "" {
		return []option.ClientOption{option.WithCredentialsJSON([]byte(c.config.CredentialsJSON))}
	}
	if c.config.CredentialsFilePath != "" {
		return []option.ClientOption{option.WithCredentialsFile(c.config.CredentialsFilePath)}
	}
	envPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if envPath != "" {
		return []option.ClientOption{option.WithCredentialsFile(envPath)}
	}
	return []option.ClientOption{} // Use Application Default Credentials
}

func (c *GCPCollector) getParent() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.config.OrganizationID != "" {
		return fmt.Sprintf("organizations/%s", c.config.OrganizationID)
	}
	if c.config.ProjectID != "" {
		return fmt.Sprintf("projects/%s", c.config.ProjectID)
	}
	return ""
}

// ---------------------------------------------------------------------------
// Data Collection
// ---------------------------------------------------------------------------

func (c *GCPCollector) collectFindings() {
	parent := c.getParent()
	if parent == "" {
		c.mu.Lock()
		c.lastError = "No project_id or organization_id configured"
		c.mu.Unlock()
		log.Println("[GCP] No parent configured, skipping collection")
		return
	}

	ctx := context.Background()
	opts := c.getClientOptions()

	// Collect from Security Command Center
	if c.isServiceEnabled("scc") {
		c.collectSCCFindings(ctx, parent, opts)
	}

	// Collect from Cloud Asset Inventory
	if c.isServiceEnabled("asset") {
		c.collectAssetFindings(ctx, opts)
	}

	// Collect from Cloud Audit Logs
	if c.isServiceEnabled("audit") {
		c.collectAuditLogs(ctx, opts)
	}

	c.mu.Lock()
	c.lastSync = time.Now()
	c.lastError = ""
	c.mu.Unlock()
}

func (c *GCPCollector) isServiceEnabled(service string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, s := range c.config.EnabledServices {
		if s == service {
			return true
		}
	}
	return false
}

func (c *GCPCollector) collectSCCFindings(ctx context.Context, parent string, opts []option.ClientOption) {
	client, err := securitycenter.NewClient(ctx, opts...)
	if err != nil {
		log.Printf("[GCP SCC] Error creating client: %v", err)
		c.mu.Lock()
		c.lastError = fmt.Sprintf("SCC client error: %v", err)
		c.mu.Unlock()
		return
	}
	defer client.Close()

	// List active findings from the last 24 hours
	filter := `state="ACTIVE"`

	sourceParent := fmt.Sprintf("%s/sources/-", parent)
	req := &securitycenterpb.ListFindingsRequest{
		Parent: sourceParent,
		Filter: filter,
	}

	it := client.ListFindings(ctx, req)
	count := 0
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("[GCP SCC] Error iterating findings: %v", err)
			break
		}

		finding := resp.Finding
		if finding == nil {
			continue
		}

		doc := map[string]interface{}{
			"finding_id":     finding.Name,
			"source":         "scc",
			"category":       finding.Category,
			"severity":       finding.Severity.String(),
			"state":          finding.State.String(),
			"resource_name":  finding.ResourceName,
			"title":          finding.Category,
			"description":    finding.Description,
			"external_uri":   finding.ExternalUri,
			"canonical_name": finding.CanonicalName,
			"mute_state":     finding.Mute.String(),
			"provider":       "gcp",
			"indexed_at":     time.Now().UTC().Format(time.RFC3339),
		}

		if finding.EventTime != nil {
			doc["event_time"] = finding.EventTime.AsTime().Format(time.RFC3339)
		}
		if finding.CreateTime != nil {
			doc["create_time"] = finding.CreateTime.AsTime().Format(time.RFC3339)
		}

		c.mu.RLock()
		doc["project_id"] = c.config.ProjectID
		doc["organization_id"] = c.config.OrganizationID
		c.mu.RUnlock()

		c.indexFinding(doc)
		count++
	}

	c.mu.Lock()
	c.eventsCollected += int64(count)
	c.mu.Unlock()
	log.Printf("[GCP SCC] Collected %d findings", count)
}

func (c *GCPCollector) collectAssetFindings(ctx context.Context, opts []option.ClientOption) {
	c.mu.RLock()
	projectID := c.config.ProjectID
	orgID := c.config.OrganizationID
	c.mu.RUnlock()

	client, err := asset.NewClient(ctx, opts...)
	if err != nil {
		log.Printf("[GCP Asset] Error creating client: %v", err)
		return
	}
	defer client.Close()

	parent := ""
	if orgID != "" {
		parent = fmt.Sprintf("organizations/%s", orgID)
	} else if projectID != "" {
		parent = fmt.Sprintf("projects/%s", projectID)
	} else {
		return
	}

	// List IAM-related assets for security analysis
	assetTypes := []string{
		"compute.googleapis.com/Instance",
		"storage.googleapis.com/Bucket",
		"iam.googleapis.com/ServiceAccount",
		"compute.googleapis.com/Firewall",
	}

	req := &assetpb.ListAssetsRequest{
		Parent:     parent,
		AssetTypes: assetTypes,
		PageSize:   100,
	}

	it := client.ListAssets(ctx, req)
	count := 0
	for {
		assetItem, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("[GCP Asset] Error iterating assets: %v", err)
			break
		}

		if assetItem == nil {
			continue
		}

		doc := map[string]interface{}{
			"finding_id":      fmt.Sprintf("asset-%s", assetItem.Name),
			"source":          "asset_inventory",
			"category":        "Asset Discovery",
			"severity":        "INFO",
			"state":           "ACTIVE",
			"resource_name":   assetItem.Name,
			"resource_type":   assetItem.AssetType,
			"title":           fmt.Sprintf("Asset: %s", assetItem.AssetType),
			"description":     fmt.Sprintf("Cloud asset discovered: %s", assetItem.Name),
			"provider":        "gcp",
			"project_id":      projectID,
			"organization_id": orgID,
			"indexed_at":      time.Now().UTC().Format(time.RFC3339),
		}

		if assetItem.UpdateTime != nil {
			doc["event_time"] = assetItem.UpdateTime.AsTime().Format(time.RFC3339)
		}

		c.indexFinding(doc)
		count++
	}

	c.mu.Lock()
	c.eventsCollected += int64(count)
	c.mu.Unlock()
	log.Printf("[GCP Asset] Collected %d assets", count)
}

func (c *GCPCollector) collectAuditLogs(ctx context.Context, opts []option.ClientOption) {
	c.mu.RLock()
	projectID := c.config.ProjectID
	c.mu.RUnlock()

	if projectID == "" {
		return
	}

	client, err := logging.NewClient(ctx, opts...)
	if err != nil {
		log.Printf("[GCP Audit] Error creating client: %v", err)
		return
	}
	defer client.Close()

	// Query security-relevant audit logs from the last 24 hours
	since := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	filter := fmt.Sprintf(
		`logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity" AND timestamp>="%s"`,
		projectID, since,
	)

	req := &loggingpb.ListLogEntriesRequest{
		ResourceNames: []string{fmt.Sprintf("projects/%s", projectID)},
		Filter:        filter,
		PageSize:      200,
		OrderBy:       "timestamp desc",
	}

	it := client.ListLogEntries(ctx, req)
	count := 0
	for {
		entry, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("[GCP Audit] Error iterating logs: %v", err)
			break
		}

		severity := "INFO"
		if entry.Severity >= ltype.LogSeverity_WARNING {
			severity = "MEDIUM"
		}
		if entry.Severity >= ltype.LogSeverity_ERROR {
			severity = "HIGH"
		}
		if entry.Severity >= ltype.LogSeverity_CRITICAL {
			severity = "CRITICAL"
		}

		doc := map[string]interface{}{
			"finding_id":    entry.InsertId,
			"source":        "audit_log",
			"category":      "Audit Log",
			"severity":      severity,
			"state":         "ACTIVE",
			"resource_name": entry.Resource.String(),
			"title":         entry.LogName,
			"description":   fmt.Sprintf("Audit log entry: %s", entry.LogName),
			"provider":      "gcp",
			"project_id":    projectID,
			"indexed_at":    time.Now().UTC().Format(time.RFC3339),
		}

		if entry.Timestamp != nil {
			doc["event_time"] = entry.Timestamp.AsTime().Format(time.RFC3339)
		}

		c.indexFinding(doc)
		count++
	}

	c.mu.Lock()
	c.eventsCollected += int64(count)
	c.mu.Unlock()
	log.Printf("[GCP Audit] Collected %d audit log entries", count)
}

func (c *GCPCollector) indexFinding(doc map[string]interface{}) {
	if c.opensearchClient == nil {
		return
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return
	}
	findingID, _ := doc["finding_id"].(string)
	docID := strings.ReplaceAll(findingID, "/", "_")
	if docID == "" {
		docID = fmt.Sprintf("gcp-%d", time.Now().UnixNano())
	}

	req := opensearchapi.IndexRequest{
		Index:      gcpEventsIndex,
		DocumentID: docID,
		Body:       strings.NewReader(string(data)),
	}
	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return
	}
	defer res.Body.Close()
}

// ---------------------------------------------------------------------------
// Start / Stop
// ---------------------------------------------------------------------------

func (c *GCPCollector) Start() {
	c.mu.Lock()
	if !c.config.Enabled || c.running {
		c.mu.Unlock()
		return
	}
	c.running = true
	c.stopCh = make(chan struct{})
	period := time.Duration(c.config.SyncPeriodMinutes) * time.Minute
	if period < 5*time.Minute {
		period = 30 * time.Minute
	}
	c.mu.Unlock()

	log.Printf("[GCP] Collector started (period: %v)", period)

	go func() {
		// Initial collection
		c.collectFindings()

		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.collectFindings()
			case <-c.stopCh:
				log.Println("[GCP] Collector stopped")
				return
			}
		}
	}()
}

func (c *GCPCollector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		close(c.stopCh)
		c.running = false
	}
}

// ---------------------------------------------------------------------------
// Index count helper
// ---------------------------------------------------------------------------

func (c *GCPCollector) getIndexCount() int64 {
	if c.opensearchClient == nil {
		return 0
	}
	countQuery := `{"query": {"match_all": {}}}`
	req := opensearchapi.CountRequest{
		Index: []string{gcpEventsIndex},
		Body:  strings.NewReader(countQuery),
	}
	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return 0
	}
	if count, ok := result["count"].(float64); ok {
		return int64(count)
	}
	return 0
}

// ---------------------------------------------------------------------------
// HTTP Handlers
// ---------------------------------------------------------------------------

// handleGCPStatus returns the GCP integration status
func (s *APIServer) handleGCPStatus(c *gin.Context) {
	if gcpCollector == nil {
		c.JSON(http.StatusOK, gin.H{
			"configured": false,
			"enabled":    false,
			"message":    "GCP collector not initialized",
		})
		return
	}

	gcpCollector.mu.RLock()
	defer gcpCollector.mu.RUnlock()

	totalEvents := gcpCollector.getIndexCount()

	c.JSON(http.StatusOK, gin.H{
		"configured":       gcpCollector.config.ProjectID != "" || gcpCollector.config.OrganizationID != "",
		"enabled":          gcpCollector.config.Enabled,
		"running":          gcpCollector.running,
		"project_id":       gcpCollector.config.ProjectID,
		"organization_id":  gcpCollector.config.OrganizationID,
		"last_sync":        gcpCollector.lastSync,
		"events_collected": totalEvents,
		"last_error":       gcpCollector.lastError,
		"sync_period":      gcpCollector.config.SyncPeriodMinutes,
		"enabled_services": gcpCollector.config.EnabledServices,
	})
}

// handleGCPConfig manages the GCP config (GET / POST)
func (s *APIServer) handleGCPConfig(c *gin.Context) {
	if gcpCollector == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "GCP collector not initialized"})
		return
	}

	if c.Request.Method == "GET" {
		gcpCollector.mu.RLock()
		defer gcpCollector.mu.RUnlock()
		c.JSON(http.StatusOK, gin.H{
			"project_id":          gcpCollector.config.ProjectID,
			"organization_id":     gcpCollector.config.OrganizationID,
			"enabled":             gcpCollector.config.Enabled,
			"sync_period_minutes": gcpCollector.config.SyncPeriodMinutes,
			"enabled_services":    gcpCollector.config.EnabledServices,
			"has_credentials":     gcpCollector.config.CredentialsJSON != "" || gcpCollector.config.CredentialsFilePath != "" || os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "",
		})
		return
	}

	// POST - Save config
	var body struct {
		ProjectID         string   `json:"project_id"`
		OrganizationID    string   `json:"organization_id"`
		CredentialsJSON   string   `json:"credentials_json"`
		Enabled           bool     `json:"enabled"`
		SyncPeriodMinutes int      `json:"sync_period_minutes"`
		EnabledServices   []string `json:"enabled_services"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	gcpCollector.mu.Lock()
	wasEnabled := gcpCollector.config.Enabled

	gcpCollector.config.ProjectID = body.ProjectID
	gcpCollector.config.OrganizationID = body.OrganizationID
	if body.CredentialsJSON != "" {
		gcpCollector.config.CredentialsJSON = body.CredentialsJSON
	}
	gcpCollector.config.Enabled = body.Enabled
	if body.SyncPeriodMinutes > 0 {
		gcpCollector.config.SyncPeriodMinutes = body.SyncPeriodMinutes
	}
	if len(body.EnabledServices) > 0 {
		gcpCollector.config.EnabledServices = body.EnabledServices
	}
	gcpCollector.mu.Unlock()

	if err := gcpCollector.saveConfig(); err != nil {
		log.Printf("[GCP] Error saving config: %v", err)
	}

	// Start/stop collector as needed
	if body.Enabled && !wasEnabled {
		gcpCollector.Start()
	} else if !body.Enabled && wasEnabled {
		gcpCollector.Stop()
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "GCP configuration saved"})
}

// handleGCPTest tests the GCP connection
func (s *APIServer) handleGCPTest(c *gin.Context) {
	var body struct {
		ProjectID       string `json:"project_id"`
		OrganizationID  string `json:"organization_id"`
		CredentialsJSON string `json:"credentials_json"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	ctx := context.Background()
	var opts []option.ClientOption
	if body.CredentialsJSON != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(body.CredentialsJSON)))
	}

	tests := []map[string]interface{}{}

	// Test 1: Security Command Center
	func() {
		client, err := securitycenter.NewClient(ctx, opts...)
		if err != nil {
			tests = append(tests, map[string]interface{}{"name": "Security Command Center", "success": false, "error": err.Error()})
			return
		}
		defer client.Close()

		parent := ""
		if body.OrganizationID != "" {
			parent = fmt.Sprintf("organizations/%s/sources/-", body.OrganizationID)
		} else if body.ProjectID != "" {
			parent = fmt.Sprintf("projects/%s/sources/-", body.ProjectID)
		}

		if parent == "" {
			tests = append(tests, map[string]interface{}{"name": "Security Command Center", "success": false, "error": "No project_id or organization_id"})
			return
		}

		it := client.ListFindings(ctx, &securitycenterpb.ListFindingsRequest{
			Parent:   parent,
			PageSize: 1,
		})
		_, err = it.Next()
		if err != nil && err != iterator.Done {
			tests = append(tests, map[string]interface{}{"name": "Security Command Center", "success": false, "error": err.Error()})
			return
		}
		tests = append(tests, map[string]interface{}{"name": "Security Command Center", "success": true})
	}()

	// Test 2: Cloud Asset Inventory
	func() {
		client, err := asset.NewClient(ctx, opts...)
		if err != nil {
			tests = append(tests, map[string]interface{}{"name": "Cloud Asset Inventory", "success": false, "error": err.Error()})
			return
		}
		defer client.Close()

		parent := ""
		if body.OrganizationID != "" {
			parent = fmt.Sprintf("organizations/%s", body.OrganizationID)
		} else if body.ProjectID != "" {
			parent = fmt.Sprintf("projects/%s", body.ProjectID)
		}
		if parent == "" {
			tests = append(tests, map[string]interface{}{"name": "Cloud Asset Inventory", "success": false, "error": "No parent"})
			return
		}

		it := client.ListAssets(ctx, &assetpb.ListAssetsRequest{Parent: parent, PageSize: 1})
		_, err = it.Next()
		if err != nil && err != iterator.Done {
			tests = append(tests, map[string]interface{}{"name": "Cloud Asset Inventory", "success": false, "error": err.Error()})
			return
		}
		tests = append(tests, map[string]interface{}{"name": "Cloud Asset Inventory", "success": true})
	}()

	// Test 3: Cloud Audit Logs
	func() {
		client, err := logging.NewClient(ctx, opts...)
		if err != nil {
			tests = append(tests, map[string]interface{}{"name": "Cloud Audit Logs", "success": false, "error": err.Error()})
			return
		}
		defer client.Close()

		if body.ProjectID == "" {
			tests = append(tests, map[string]interface{}{"name": "Cloud Audit Logs", "success": false, "error": "project_id required"})
			return
		}

		it := client.ListLogEntries(ctx, &loggingpb.ListLogEntriesRequest{
			ResourceNames: []string{fmt.Sprintf("projects/%s", body.ProjectID)},
			PageSize:      1,
		})
		_, err = it.Next()
		if err != nil && err != iterator.Done {
			tests = append(tests, map[string]interface{}{"name": "Cloud Audit Logs", "success": false, "error": err.Error()})
			return
		}
		tests = append(tests, map[string]interface{}{"name": "Cloud Audit Logs", "success": true})
	}()

	allOK := true
	for _, t := range tests {
		if t["success"] != true {
			allOK = false
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": allOK,
		"tests":   tests,
		"message": func() string {
			if allOK {
				return "All GCP services connected successfully"
			}
			return "Some GCP services failed to connect"
		}(),
	})
}

// handleGCPSync triggers a manual sync
func (s *APIServer) handleGCPSync(c *gin.Context) {
	if gcpCollector == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "GCP collector not initialized"})
		return
	}

	go gcpCollector.collectFindings()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "GCP sync triggered",
	})
}

// handleGCPFindings returns GCP findings from OpenSearch
func (s *APIServer) handleGCPFindings(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "500"))
	if page < 1 {
		page = 1
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	from := (page - 1) * pageSize

	// Build query
	must := []interface{}{}
	if source := c.Query("source"); source != "" {
		must = append(must, map[string]interface{}{"term": map[string]interface{}{"source": source}})
	}
	if severity := c.Query("severity"); severity != "" {
		must = append(must, map[string]interface{}{"term": map[string]interface{}{"severity": strings.ToUpper(severity)}})
	}
	if category := c.Query("category"); category != "" {
		must = append(must, map[string]interface{}{"term": map[string]interface{}{"category": category}})
	}
	if search := c.Query("search"); search != "" {
		must = append(must, map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  search,
				"fields": []string{"title", "description", "resource_name", "category"},
			},
		})
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": func() interface{} {
					if len(must) > 0 {
						return must
					}
					return []interface{}{map[string]interface{}{"match_all": map[string]interface{}{}}}
				}(),
			},
		},
		"sort":             []interface{}{map[string]interface{}{"event_time": map[string]interface{}{"order": "desc", "unmapped_type": "date"}}},
		"from":             from,
		"size":             pageSize,
		"track_total_hits": true,
	}

	data, _ := json.Marshal(query)
	req := opensearchapi.SearchRequest{
		Index: []string{gcpEventsIndex},
		Body:  strings.NewReader(string(data)),
	}
	res, err := req.Do(context.Background(), s.opensearch)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0, "error": err.Error()})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	findings := []interface{}{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			if v, ok := totalObj["value"].(float64); ok {
				total = int(v)
			}
		}
		if hitList, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitList {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					source := hitMap["_source"]
					if sourceMap, ok := source.(map[string]interface{}); ok {
						sourceMap["_id"] = hitMap["_id"]
						findings = append(findings, sourceMap)
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"findings": findings,
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
	})
}

// handleGCPStats returns aggregated GCP statistics
func (s *APIServer) handleGCPStats(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"event_time": map[string]interface{}{
					"gte": "now-24h",
				},
			},
		},
		"track_total_hits": true,
		"aggs": map[string]interface{}{
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{"field": "severity", "size": 10},
			},
			"by_source": map[string]interface{}{
				"terms": map[string]interface{}{"field": "source", "size": 10},
			},
			"by_category": map[string]interface{}{
				"terms": map[string]interface{}{"field": "category", "size": 20},
			},
			"by_state": map[string]interface{}{
				"terms": map[string]interface{}{"field": "state", "size": 10},
			},
		},
	}

	data, _ := json.Marshal(query)
	req := opensearchapi.SearchRequest{
		Index: []string{gcpEventsIndex},
		Body:  strings.NewReader(string(data)),
	}
	res, err := req.Do(context.Background(), s.opensearch)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	// Parse aggregations
	stats := map[string]interface{}{
		"total_24h": 0,
	}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			if v, ok := totalObj["value"].(float64); ok {
				stats["total_24h"] = int(v)
			}
		}
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		for key, agg := range aggs {
			if aggMap, ok := agg.(map[string]interface{}); ok {
				if buckets, ok := aggMap["buckets"].([]interface{}); ok {
					items := []map[string]interface{}{}
					for _, b := range buckets {
						if bMap, ok := b.(map[string]interface{}); ok {
							items = append(items, map[string]interface{}{
								"key":   bMap["key"],
								"count": bMap["doc_count"],
							})
						}
					}
					stats[key] = items
				}
			}
		}
	}

	// Total findings count
	stats["total_findings"] = gcpCollector.getIndexCount()

	c.JSON(http.StatusOK, stats)
}

// handleGCPDiagnostic runs a diagnostic check
func (s *APIServer) handleGCPDiagnostic(c *gin.Context) {
	checks := []map[string]interface{}{}

	// Check 1: Collector initialized
	checks = append(checks, map[string]interface{}{
		"name":   "GCP Collector",
		"status": gcpCollector != nil,
		"message": func() string {
			if gcpCollector != nil {
				return "Initialized"
			}
			return "Not initialized"
		}(),
	})

	if gcpCollector != nil {
		gcpCollector.mu.RLock()
		// Check 2: Configuration
		hasConfig := gcpCollector.config.ProjectID != "" || gcpCollector.config.OrganizationID != ""
		checks = append(checks, map[string]interface{}{
			"name":   "Configuration",
			"status": hasConfig,
			"message": func() string {
				if hasConfig {
					return fmt.Sprintf("Project: %s, Org: %s", gcpCollector.config.ProjectID, gcpCollector.config.OrganizationID)
				}
				return "No project_id or organization_id configured"
			}(),
		})

		// Check 3: Credentials
		hasCreds := gcpCollector.config.CredentialsJSON != "" ||
			gcpCollector.config.CredentialsFilePath != "" ||
			os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != ""
		checks = append(checks, map[string]interface{}{
			"name":   "Credentials",
			"status": hasCreds,
			"message": func() string {
				if gcpCollector.config.CredentialsJSON != "" {
					return "Service Account JSON configured"
				}
				if gcpCollector.config.CredentialsFilePath != "" {
					return fmt.Sprintf("Credentials file: %s", gcpCollector.config.CredentialsFilePath)
				}
				if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
					return "Using GOOGLE_APPLICATION_CREDENTIALS env"
				}
				return "No credentials configured"
			}(),
		})

		// Check 4: Collector running
		checks = append(checks, map[string]interface{}{
			"name":   "Collector Running",
			"status": gcpCollector.running,
			"message": func() string {
				if gcpCollector.running {
					return "Active"
				}
				return "Stopped"
			}(),
		})

		// Check 5: Last error
		checks = append(checks, map[string]interface{}{
			"name":   "Last Error",
			"status": gcpCollector.lastError == "",
			"message": func() string {
				if gcpCollector.lastError == "" {
					return "No errors"
				}
				return gcpCollector.lastError
			}(),
		})

		gcpCollector.mu.RUnlock()
	}

	// Check 6: OpenSearch index
	indexCount := int64(0)
	if gcpCollector != nil {
		indexCount = gcpCollector.getIndexCount()
	}
	checks = append(checks, map[string]interface{}{
		"name":    "OpenSearch Index",
		"status":  indexCount >= 0,
		"message": fmt.Sprintf("Index %s: %d documents", gcpEventsIndex, indexCount),
	})

	c.JSON(http.StatusOK, gin.H{
		"checks":    checks,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
