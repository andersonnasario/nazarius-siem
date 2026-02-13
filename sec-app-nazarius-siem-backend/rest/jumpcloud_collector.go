package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opensearch-project/opensearch-go/v2"
	"github.com/opensearch-project/opensearch-go/v2/opensearchapi"
)

// ============== Configuration ==============

// JumpCloudConfig stores JumpCloud integration settings (Service Account OAuth2)
type JumpCloudConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	OrgID        string   `json:"org_id"`
	Enabled      bool     `json:"enabled"`
	SyncPeriod   int      `json:"sync_period_minutes"`
	Services     []string `json:"services"` // all, directory, sso, radius, systems, ldap, mdm, alerts
}

// ============== Collector ==============

// JumpCloudCollector manages log collection from JumpCloud Directory Insights API
type JumpCloudCollector struct {
	config           JumpCloudConfig
	opensearchClient *opensearch.Client
	httpClient       *http.Client
	mu               sync.RWMutex
	running          bool
	stopChan         chan struct{}
	lastSync         time.Time
	eventsCollected  int64
	// OAuth2 token cache
	accessToken string
	tokenExpiry time.Time
}

var (
	jumpcloudCollector *JumpCloudCollector
	jumpcloudOnce      sync.Once
)

const (
	jumpcloudAPIBaseURL = "https://api.jumpcloud.com/insights/directory/v1/events"
	jumpcloudTokenURL   = "https://admin-oauth.id.jumpcloud.com/oauth2/token"
	jumpcloudIndexName  = "siem-jumpcloud-events"
)

// InitJumpCloudCollector initializes the JumpCloud collector (singleton)
func InitJumpCloudCollector(opensearchClient *opensearch.Client) *JumpCloudCollector {
	jumpcloudOnce.Do(func() {
		jumpcloudCollector = &JumpCloudCollector{
			opensearchClient: opensearchClient,
			httpClient: &http.Client{
				Timeout: 60 * time.Second,
			},
			stopChan: make(chan struct{}),
		}
		jumpcloudCollector.loadConfig()
		jumpcloudCollector.createIndex()
	})
	return jumpcloudCollector
}

// ============== Config Management ==============

func (c *JumpCloudCollector) loadConfig() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.opensearchClient != nil {
		cfg, err := c.loadConfigFromOpenSearch()
		if err == nil && cfg.ClientID != "" {
			c.config = cfg
			return
		}
	}

	// Fallback to env vars
	services := os.Getenv("JUMPCLOUD_SERVICES")
	if services == "" {
		services = "all"
	}
	c.config = JumpCloudConfig{
		ClientID:     os.Getenv("JUMPCLOUD_CLIENT_ID"),
		ClientSecret: os.Getenv("JUMPCLOUD_CLIENT_SECRET"),
		OrgID:        os.Getenv("JUMPCLOUD_ORG_ID"),
		Enabled:      os.Getenv("JUMPCLOUD_ENABLED") == "true",
		SyncPeriod:   5,
		Services:     strings.Split(services, ","),
	}
}

func (c *JumpCloudCollector) loadConfigFromOpenSearch() (JumpCloudConfig, error) {
	var cfg JumpCloudConfig
	req := opensearchapi.GetRequest{
		Index:      "siem-integrations-config",
		DocumentID: "jumpcloud",
	}
	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return cfg, err
	}
	defer res.Body.Close()
	if res.IsError() {
		return cfg, fmt.Errorf("error getting config: %s", res.Status())
	}
	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return cfg, err
	}
	if source, ok := result["_source"].(map[string]interface{}); ok {
		if v, ok := source["client_id"].(string); ok {
			cfg.ClientID = v
		}
		if v, ok := source["client_secret"].(string); ok {
			cfg.ClientSecret = v
		}
		if v, ok := source["org_id"].(string); ok {
			cfg.OrgID = v
		}
		if v, ok := source["enabled"].(bool); ok {
			cfg.Enabled = v
		}
		if v, ok := source["sync_period_minutes"].(float64); ok {
			cfg.SyncPeriod = int(v)
		}
		if v, ok := source["services"].([]interface{}); ok {
			for _, s := range v {
				if str, ok := s.(string); ok {
					cfg.Services = append(cfg.Services, str)
				}
			}
		}
	}
	return cfg, nil
}

func (c *JumpCloudCollector) saveConfigToOpenSearch() error {
	if c.opensearchClient == nil {
		return fmt.Errorf("opensearch client not available")
	}

	// Ensure config index exists
	indexBody := `{"settings": {"number_of_shards": 1, "number_of_replicas": 0}}`
	createReq := opensearchapi.IndicesCreateRequest{
		Index: "siem-integrations-config",
		Body:  strings.NewReader(indexBody),
	}
	createReq.Do(context.Background(), c.opensearchClient)

	configJSON, err := json.Marshal(c.config)
	if err != nil {
		return err
	}

	req := opensearchapi.IndexRequest{
		Index:      "siem-integrations-config",
		DocumentID: "jumpcloud",
		Body:       strings.NewReader(string(configJSON)),
		Refresh:    "true",
	}
	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("error saving config: %s", res.Status())
	}
	return nil
}

// ============== Index Management ==============

func (c *JumpCloudCollector) createIndex() error {
	if c.opensearchClient == nil {
		return fmt.Errorf("opensearch client not available")
	}

	mapping := `{
		"settings": {
			"number_of_shards": 2,
			"number_of_replicas": 0,
			"index": { "refresh_interval": "5s" }
		},
		"mappings": {
			"properties": {
				"event_id":            { "type": "keyword" },
				"timestamp":           { "type": "date" },
				"event_type":          { "type": "keyword" },
				"service":             { "type": "keyword" },
				"client_ip":           { "type": "ip", "ignore_malformed": true },
				"success":             { "type": "boolean" },
				"username":            { "type": "keyword" },
				"organization":        { "type": "keyword" },
				"initiated_by_email":  { "type": "keyword" },
				"initiated_by_type":   { "type": "keyword" },
				"resource_type":       { "type": "keyword" },
				"resource_id":         { "type": "keyword" },
				"resource_name":       { "type": "keyword" },
				"mfa":                 { "type": "boolean" },
				"country_code":        { "type": "keyword" },
				"region":              { "type": "keyword" },
				"severity":            { "type": "keyword" },
				"error_message":       { "type": "text" },
				"auth_method":         { "type": "keyword" },
				"application_name":    { "type": "keyword" },
				"system_hostname":     { "type": "keyword" },
				"changes":             { "type": "text" },
				"raw_event":           { "type": "object", "enabled": false }
			}
		}
	}`

	req := opensearchapi.IndicesCreateRequest{
		Index: jumpcloudIndexName,
		Body:  strings.NewReader(mapping),
	}
	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return nil
}

// ============== OAuth2 Token Management ==============

// getAccessToken obtains or returns a cached OAuth2 Bearer token using Client Credentials flow
func (c *JumpCloudCollector) getAccessToken() (string, error) {
	c.mu.RLock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		token := c.accessToken
		c.mu.RUnlock()
		return token, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.accessToken, nil
	}

	if c.config.ClientID == "" || c.config.ClientSecret == "" {
		return "", fmt.Errorf("JumpCloud Client ID and Client Secret are required")
	}

	fmt.Printf("[JumpCloud] Requesting new OAuth2 access token...\n")

	// Base64 encode client_id:client_secret
	credentials := c.config.ClientID + ":" + c.config.ClientSecret
	encodedCreds := base64.StdEncoding.EncodeToString([]byte(credentials))

	// Build token request
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "api")

	req, err := http.NewRequest("POST", jumpcloudTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %v", err)
	}
	req.Header.Set("Authorization", "Basic "+encodedCreds)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		fmt.Printf("[JumpCloud] Token request failed (HTTP %d): %s\n", resp.StatusCode, string(body[:min(len(body), 500)]))
		return "", fmt.Errorf("OAuth2 token request failed with status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("received empty access token from JumpCloud")
	}

	// Cache the token with a safety margin (refresh 5 minutes before expiry)
	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-300) * time.Second)

	fmt.Printf("[JumpCloud] OAuth2 access token obtained (expires in %ds)\n", tokenResp.ExpiresIn)
	return c.accessToken, nil
}

// clearAccessToken invalidates the cached token (e.g. on 401 response)
func (c *JumpCloudCollector) clearAccessToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = ""
	c.tokenExpiry = time.Time{}
}

// ============== Event Collection ==============

func (c *JumpCloudCollector) collectEvents() error {
	c.mu.RLock()
	config := c.config
	c.mu.RUnlock()

	if config.ClientID == "" || config.ClientSecret == "" {
		fmt.Printf("[JumpCloud] Client ID/Secret not configured, skipping collection\n")
		return fmt.Errorf("JumpCloud credentials not configured")
	}

	// Get OAuth2 token
	token, err := c.getAccessToken()
	if err != nil {
		fmt.Printf("[JumpCloud] Failed to get access token: %v\n", err)
		return err
	}

	fmt.Printf("[JumpCloud] Starting event collection...\n")

	endTime := time.Now().UTC()
	startTime := endTime.Add(-6 * time.Hour)
	if !c.lastSync.IsZero() && c.lastSync.After(startTime) {
		startTime = c.lastSync
	}

	services := config.Services
	if len(services) == 0 {
		services = []string{"all"}
	}

	fmt.Printf("[JumpCloud] Time range: %s to %s, services: %v\n",
		startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), services)

	totalEvents := 0
	totalErrors := 0
	hasMore := true
	var searchAfter interface{}

	for hasMore {
		// Build request body
		body := map[string]interface{}{
			"service":    services,
			"start_time": startTime.Format(time.RFC3339),
			"end_time":   endTime.Format(time.RFC3339),
			"sort":       "ASC",
			"limit":      1000,
		}
		if searchAfter != nil {
			body["search_after"] = searchAfter
		}

		bodyJSON, _ := json.Marshal(body)

		req, err := http.NewRequest("POST", jumpcloudAPIBaseURL, strings.NewReader(string(bodyJSON)))
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if config.OrgID != "" {
			req.Header.Set("x-org-id", config.OrgID)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("API request failed: %v", err)
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 401 {
			// Token may have expired, clear cache and retry once
			fmt.Printf("[JumpCloud] Token expired (401), refreshing...\n")
			c.clearAccessToken()
			newToken, err := c.getAccessToken()
			if err != nil {
				return fmt.Errorf("failed to refresh access token: %v", err)
			}
			token = newToken
			continue // Retry with new token
		}

		if resp.StatusCode != 200 {
			fmt.Printf("[JumpCloud] API returned status %d: %s\n", resp.StatusCode, string(respBody[:min(len(respBody), 500)]))
			return fmt.Errorf("API returned status %d", resp.StatusCode)
		}

		// Parse events array
		var events []map[string]interface{}
		if err := json.Unmarshal(respBody, &events); err != nil {
			fmt.Printf("[JumpCloud] Failed to parse response: %s\n", string(respBody[:min(len(respBody), 500)]))
			return fmt.Errorf("failed to parse response: %v", err)
		}

		// Read pagination headers
		resultCount := 0
		limitVal := 1000
		if rc := resp.Header.Get("X-Result-Count"); rc != "" {
			if v, err := strconv.Atoi(rc); err == nil {
				resultCount = v
			}
		}
		if lv := resp.Header.Get("X-Limit"); lv != "" {
			if v, err := strconv.Atoi(lv); err == nil {
				limitVal = v
			}
		}

		// Parse search_after for pagination
		if sa := resp.Header.Get("X-Search_after"); sa != "" {
			var saVal interface{}
			if json.Unmarshal([]byte(sa), &saVal) == nil {
				searchAfter = saVal
			}
		}

		fmt.Printf("[JumpCloud] Fetched %d events (page result: %d/%d)\n", len(events), resultCount, limitVal)

		// Process and index each event
		for _, event := range events {
			if err := c.indexEvent(event); err != nil {
				totalErrors++
				if totalErrors <= 5 {
					fmt.Printf("[JumpCloud] Error indexing event: %v\n", err)
				}
			} else {
				totalEvents++
			}

			// Generate alert for high-severity events
			eventType, _ := event["event_type"].(string)
			success, _ := event["success"].(bool)
			sev := mapJumpCloudSeverity(eventType, success)
			if sev == "HIGH" || sev == "CRITICAL" {
				if err := c.indexAlert(event, sev); err != nil {
					fmt.Printf("[JumpCloud] Error indexing alert: %v\n", err)
				}
			}
		}

		// Check if more pages exist
		hasMore = resultCount >= limitVal && len(events) > 0

		// Small delay between pages
		if hasMore {
			time.Sleep(500 * time.Millisecond)
		}
	}

	c.mu.Lock()
	c.lastSync = endTime
	c.eventsCollected += int64(totalEvents)
	c.mu.Unlock()

	fmt.Printf("[JumpCloud] Collection complete: %d events indexed (%d errors)\n", totalEvents, totalErrors)
	return nil
}

// indexEvent normalizes and indexes a JumpCloud event into OpenSearch
func (c *JumpCloudCollector) indexEvent(event map[string]interface{}) error {
	if c.opensearchClient == nil {
		return fmt.Errorf("opensearch client not available")
	}

	eventType, _ := event["event_type"].(string)
	service, _ := event["service"].(string)
	success, _ := event["success"].(bool)
	timestamp, _ := event["timestamp"].(string)
	clientIP, _ := event["client_ip"].(string)
	username, _ := event["username"].(string)
	organization, _ := event["organization"].(string)
	eventID, _ := event["id"].(string)
	mfa, _ := event["mfa"].(bool)
	errorMessage, _ := event["error_message"].(string)
	authMethod, _ := event["auth_method"].(string)

	// Extract nested fields
	initiatedByEmail := ""
	initiatedByType := ""
	if ib, ok := event["initiated_by"].(map[string]interface{}); ok {
		initiatedByEmail, _ = ib["email"].(string)
		initiatedByType, _ = ib["type"].(string)
	}

	resourceType := ""
	resourceID := ""
	resourceName := ""
	if res, ok := event["resource"].(map[string]interface{}); ok {
		resourceType, _ = res["type"].(string)
		resourceID, _ = res["id"].(string)
		if name, ok := res["username"].(string); ok {
			resourceName = name
		} else if name, ok := res["name"].(string); ok {
			resourceName = name
		} else if name, ok := res["email"].(string); ok {
			resourceName = name
		}
	}

	countryCode := ""
	region := ""
	if geo, ok := event["geoip"].(map[string]interface{}); ok {
		countryCode, _ = geo["country_code2"].(string)
		if countryCode == "" {
			countryCode, _ = geo["country_code"].(string)
		}
		region, _ = geo["region_name"].(string)
	}

	applicationName := ""
	if app, ok := event["application"].(map[string]interface{}); ok {
		applicationName, _ = app["name"].(string)
	}

	systemHostname := ""
	if sys, ok := event["system"].(map[string]interface{}); ok {
		systemHostname, _ = sys["hostname"].(string)
		if systemHostname == "" {
			systemHostname, _ = sys["displayName"].(string)
		}
	}

	changesStr := ""
	if changes, ok := event["changes"].([]interface{}); ok {
		if cJSON, err := json.Marshal(changes); err == nil {
			changesStr = string(cJSON)
		}
	}

	severity := mapJumpCloudSeverity(eventType, success)

	doc := map[string]interface{}{
		"event_id":           eventID,
		"timestamp":          timestamp,
		"event_type":         eventType,
		"service":            service,
		"client_ip":          clientIP,
		"success":            success,
		"username":           username,
		"organization":       organization,
		"initiated_by_email": initiatedByEmail,
		"initiated_by_type":  initiatedByType,
		"resource_type":      resourceType,
		"resource_id":        resourceID,
		"resource_name":      resourceName,
		"mfa":                mfa,
		"country_code":       countryCode,
		"region":             region,
		"severity":           severity,
		"error_message":      errorMessage,
		"auth_method":        authMethod,
		"application_name":   applicationName,
		"system_hostname":    systemHostname,
		"changes":            changesStr,
		"raw_event":          event,
	}

	// Remove empty client_ip to avoid ip parse errors
	if clientIP == "" {
		delete(doc, "client_ip")
	}

	docJSON, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	docID := eventID
	if docID == "" {
		docID = fmt.Sprintf("jc-%s-%s", eventType, timestamp)
	}

	req := opensearchapi.IndexRequest{
		Index:      jumpcloudIndexName,
		DocumentID: docID,
		Body:       strings.NewReader(string(docJSON)),
	}
	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("index error: %s - %s", res.Status(), string(body[:min(len(body), 200)]))
	}
	return nil
}

// indexAlert generates a SIEM alert for high-severity JumpCloud events
func (c *JumpCloudCollector) indexAlert(event map[string]interface{}, severity string) error {
	if c.opensearchClient == nil {
		return nil
	}

	eventType, _ := event["event_type"].(string)
	username, _ := event["username"].(string)
	clientIP, _ := event["client_ip"].(string)
	timestamp, _ := event["timestamp"].(string)
	service, _ := event["service"].(string)
	success, _ := event["success"].(bool)
	eventID, _ := event["id"].(string)

	successStr := "sucesso"
	if !success {
		successStr = "falha"
	}

	description := fmt.Sprintf("JumpCloud %s: %s por usuário '%s' de IP %s (%s)",
		service, eventType, username, clientIP, successStr)

	alert := map[string]interface{}{
		"title":       fmt.Sprintf("JumpCloud: %s", eventType),
		"description": description,
		"severity":    severity,
		"source":      "jumpcloud",
		"type":        eventType,
		"timestamp":   timestamp,
		"source_ip":   clientIP,
		"username":    username,
		"status":      "open",
		"service":     service,
		"event_id":    eventID,
	}

	alertJSON, _ := json.Marshal(alert)

	req := opensearchapi.IndexRequest{
		Index: "siem-alerts",
		Body:  strings.NewReader(string(alertJSON)),
	}
	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return nil
}

// ============== Severity Mapping ==============

func mapJumpCloudSeverity(eventType string, success bool) string {
	et := strings.ToLower(eventType)

	// Account lockouts
	if strings.Contains(et, "lockout") {
		return "CRITICAL"
	}

	// Auth failures
	if !success {
		if strings.Contains(et, "login") || strings.Contains(et, "auth") ||
			strings.Contains(et, "sso") || strings.Contains(et, "radius") ||
			strings.Contains(et, "ldap_bind") {
			return "HIGH"
		}
	}

	// Admin/destructive operations
	if strings.Contains(et, "admin_") || strings.Contains(et, "user_delete") ||
		strings.Contains(et, "policy_delete") || strings.Contains(et, "group_delete") ||
		strings.Contains(et, "application_delete") {
		return "MEDIUM"
	}

	// User modifications
	if strings.Contains(et, "user_update") || strings.Contains(et, "user_create") ||
		strings.Contains(et, "group_update") || strings.Contains(et, "policy_update") {
		return "LOW"
	}

	// Successful auth
	if success && (strings.Contains(et, "login") || strings.Contains(et, "sso") || strings.Contains(et, "auth")) {
		return "INFO"
	}

	return "LOW"
}

// ============== Start/Stop ==============

func (c *JumpCloudCollector) Start() {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return
	}
	c.running = true
	c.mu.Unlock()

	go func() {
		c.collectEvents()

		period := time.Duration(c.config.SyncPeriod) * time.Minute
		if period < time.Minute {
			period = 5 * time.Minute
		}

		ticker := time.NewTicker(period)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if c.config.Enabled {
					c.collectEvents()
				}
			case <-c.stopChan:
				return
			}
		}
	}()
}

func (c *JumpCloudCollector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		close(c.stopChan)
		c.running = false
	}
}

// ============== HTTP Handlers ==============

func (s *APIServer) handleJumpCloudStatus(c *gin.Context) {
	if jumpcloudCollector == nil {
		c.JSON(http.StatusOK, gin.H{
			"configured": false,
			"enabled":    false,
			"message":    "JumpCloud integration not initialized",
		})
		return
	}

	jumpcloudCollector.mu.RLock()
	defer jumpcloudCollector.mu.RUnlock()

	stats := s.getJumpCloudStats()

	c.JSON(http.StatusOK, gin.H{
		"configured":       jumpcloudCollector.config.ClientID != "" && jumpcloudCollector.config.ClientSecret != "",
		"enabled":          jumpcloudCollector.config.Enabled,
		"running":          jumpcloudCollector.running,
		"last_sync":        jumpcloudCollector.lastSync,
		"events_collected": jumpcloudCollector.eventsCollected,
		"sync_period":      jumpcloudCollector.config.SyncPeriod,
		"services":         jumpcloudCollector.config.Services,
		"api_method":       "Service Account OAuth2 (Directory Insights API v1)",
		"stats":            stats,
	})
}

func (s *APIServer) handleJumpCloudConfig(c *gin.Context) {
	if c.Request.Method == "GET" {
		if jumpcloudCollector == nil {
			c.JSON(http.StatusOK, JumpCloudConfig{})
			return
		}
		jumpcloudCollector.mu.RLock()
		config := jumpcloudCollector.config
		jumpcloudCollector.mu.RUnlock()

		c.JSON(http.StatusOK, gin.H{
			"credentials_configured": config.ClientID != "" && config.ClientSecret != "",
			"client_id":              config.ClientID,
			"org_id":                 config.OrgID,
			"enabled":                config.Enabled,
			"sync_period_minutes":    config.SyncPeriod,
			"services":               config.Services,
		})
		return
	}

	// POST - Update config
	var newConfig JumpCloudConfig
	if err := c.ShouldBindJSON(&newConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if jumpcloudCollector == nil {
		jumpcloudCollector = InitJumpCloudCollector(s.opensearch)
	}

	jumpcloudCollector.mu.Lock()
	// Preserve existing credentials if not provided in the update
	if newConfig.ClientID == "" {
		newConfig.ClientID = jumpcloudCollector.config.ClientID
	}
	if newConfig.ClientSecret == "" {
		newConfig.ClientSecret = jumpcloudCollector.config.ClientSecret
	}
	if len(newConfig.Services) == 0 {
		newConfig.Services = []string{"all"}
	}
	// Clear cached token when credentials change
	if newConfig.ClientID != jumpcloudCollector.config.ClientID || newConfig.ClientSecret != jumpcloudCollector.config.ClientSecret {
		jumpcloudCollector.accessToken = ""
		jumpcloudCollector.tokenExpiry = time.Time{}
	}
	jumpcloudCollector.config = newConfig
	jumpcloudCollector.mu.Unlock()

	if err := jumpcloudCollector.saveConfigToOpenSearch(); err != nil {
		fmt.Printf("[JumpCloud] Error saving config: %v\n", err)
	}

	if newConfig.Enabled {
		jumpcloudCollector.Start()
	} else {
		jumpcloudCollector.Stop()
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Configuration updated successfully",
	})
}

func (s *APIServer) handleJumpCloudTest(c *gin.Context) {
	var testReq struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		OrgID        string `json:"org_id"`
	}
	c.ShouldBindJSON(&testReq)

	clientID := testReq.ClientID
	clientSecret := testReq.ClientSecret
	if clientID == "" && jumpcloudCollector != nil {
		jumpcloudCollector.mu.RLock()
		clientID = jumpcloudCollector.config.ClientID
		clientSecret = jumpcloudCollector.config.ClientSecret
		jumpcloudCollector.mu.RUnlock()
	}
	if clientID == "" || clientSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Client ID and Client Secret are required"})
		return
	}

	// Step 1: Get OAuth2 token
	credentials := clientID + ":" + clientSecret
	encodedCreds := base64.StdEncoding.EncodeToString([]byte(credentials))

	tokenData := url.Values{}
	tokenData.Set("grant_type", "client_credentials")
	tokenData.Set("scope", "api")

	tokenReq, _ := http.NewRequest("POST", jumpcloudTokenURL, strings.NewReader(tokenData.Encode()))
	tokenReq.Header.Set("Authorization", "Basic "+encodedCreds)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": fmt.Sprintf("OAuth2 token request failed: %v", err)})
		return
	}
	defer tokenResp.Body.Close()
	tokenBody, _ := io.ReadAll(tokenResp.Body)

	if tokenResp.StatusCode != 200 {
		errMsg := "Authentication failed"
		if tokenResp.StatusCode == 401 {
			errMsg = "Invalid Client ID or Client Secret"
		} else if tokenResp.StatusCode == 403 {
			errMsg = "Access denied - check Service Account role/permissions"
		}
		c.JSON(http.StatusOK, gin.H{
			"success":     false,
			"error":       fmt.Sprintf("%s (HTTP %d)", errMsg, tokenResp.StatusCode),
			"http_status": tokenResp.StatusCode,
			"step":        "oauth2_token",
		})
		return
	}

	var tokenResult struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	json.Unmarshal(tokenBody, &tokenResult)

	if tokenResult.AccessToken == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": "Received empty access token"})
		return
	}

	// Step 2: Test Directory Insights API with the token
	body := `{"service": ["all"], "start_time": "` + time.Now().UTC().Add(-1*time.Hour).Format(time.RFC3339) + `", "limit": 1}`
	httpReq, _ := http.NewRequest("POST", jumpcloudAPIBaseURL, strings.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+tokenResult.AccessToken)
	httpReq.Header.Set("Content-Type", "application/json")
	if testReq.OrgID != "" {
		httpReq.Header.Set("x-org-id", testReq.OrgID)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": fmt.Sprintf("API request failed: %v", err), "step": "directory_insights"})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		var events []interface{}
		json.Unmarshal(respBody, &events)
		c.JSON(http.StatusOK, gin.H{
			"success":       true,
			"message":       fmt.Sprintf("Connection successful! OAuth2 token obtained. Found %d events in the last hour.", len(events)),
			"events_found":  len(events),
			"token_expires": tokenResult.ExpiresIn,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"success":     false,
			"error":       fmt.Sprintf("OAuth2 token OK, but Directory Insights API returned status %d", resp.StatusCode),
			"http_status": resp.StatusCode,
			"details":     string(respBody[:min(len(respBody), 300)]),
			"step":        "directory_insights",
		})
	}
}

func (s *APIServer) handleJumpCloudSync(c *gin.Context) {
	if jumpcloudCollector == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JumpCloud collector not initialized"})
		return
	}

	jumpcloudCollector.mu.RLock()
	hasCredentials := jumpcloudCollector.config.ClientID != "" && jumpcloudCollector.config.ClientSecret != ""
	jumpcloudCollector.mu.RUnlock()

	if !hasCredentials {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service Account credentials not configured"})
		return
	}

	go func() {
		if err := jumpcloudCollector.collectEvents(); err != nil {
			fmt.Printf("[JumpCloud] Sync failed: %v\n", err)
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Sync initiated - check logs for progress",
	})
}

func (s *APIServer) handleJumpCloudEvents(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{"events": []interface{}{}, "total": 0, "page": 0, "per_page": 500})
		return
	}

	page := 0
	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v >= 0 {
			page = v
		}
	}
	perPage := 500
	if l := c.Query("per_page"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			perPage = v
		}
	}
	from := page * perPage

	// Build filters
	must := []map[string]interface{}{}
	if v := c.Query("service"); v != "" {
		must = append(must, map[string]interface{}{"term": map[string]interface{}{"service": v}})
	}
	if v := c.Query("event_type"); v != "" {
		must = append(must, map[string]interface{}{"term": map[string]interface{}{"event_type": v}})
	}
	if v := c.Query("success"); v != "" {
		boolVal := v == "true"
		must = append(must, map[string]interface{}{"term": map[string]interface{}{"success": boolVal}})
	}
	if v := c.Query("username"); v != "" {
		must = append(must, map[string]interface{}{"term": map[string]interface{}{"username": v}})
	}
	if v := c.Query("severity"); v != "" {
		must = append(must, map[string]interface{}{"term": map[string]interface{}{"severity": v}})
	}
	if v := c.Query("search"); v != "" {
		must = append(must, map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  v,
				"fields": []string{"username", "client_ip", "event_type", "initiated_by_email", "resource_name", "application_name", "system_hostname", "error_message"},
				"type":   "phrase_prefix",
			},
		})
	}

	var queryBody map[string]interface{}
	if len(must) > 0 {
		queryBody = map[string]interface{}{
			"from": from, "size": perPage, "track_total_hits": true,
			"sort":  []map[string]interface{}{{"timestamp": "desc"}},
			"query": map[string]interface{}{"bool": map[string]interface{}{"must": must}},
		}
	} else {
		queryBody = map[string]interface{}{
			"from": from, "size": perPage, "track_total_hits": true,
			"sort":  []map[string]interface{}{{"timestamp": "desc"}},
			"query": map[string]interface{}{"match_all": map[string]interface{}{}},
		}
	}

	queryJSON, _ := json.Marshal(queryBody)
	req := opensearchapi.SearchRequest{
		Index: []string{jumpcloudIndexName},
		Body:  strings.NewReader(string(queryJSON)),
	}
	res, err := req.Do(context.Background(), s.opensearch)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	events := []map[string]interface{}{}
	total := 0
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalHits, ok := hits["total"].(map[string]interface{}); ok {
			if value, ok := totalHits["value"].(float64); ok {
				total = int(value)
			}
		}
		if hitList, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitList {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"].(map[string]interface{}); ok {
						if docID, ok := hitMap["_id"].(string); ok {
							source["_id"] = docID
						}
						events = append(events, source)
					}
				}
			}
		}
	}

	totalPages := (total + perPage - 1) / perPage
	c.JSON(http.StatusOK, gin.H{
		"events": events, "total": total, "page": page,
		"per_page": perPage, "total_pages": totalPages,
	})
}

func (s *APIServer) handleJumpCloudStatsEndpoint(c *gin.Context) {
	stats := s.getJumpCloudStats()
	c.JSON(http.StatusOK, stats)
}

func (s *APIServer) getJumpCloudStats() map[string]interface{} {
	if s.opensearch == nil {
		return map[string]interface{}{
			"total_events": 0, "failed_logins": 0, "mfa_events": 0,
			"by_service": []interface{}{}, "by_event_type": []interface{}{},
			"by_success": []interface{}{}, "top_users": []interface{}{}, "top_ips": []interface{}{},
		}
	}

	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"range": map[string]interface{}{"timestamp": map[string]interface{}{"gte": "now-24h"}},
		},
		"aggs": map[string]interface{}{
			"by_service":    map[string]interface{}{"terms": map[string]interface{}{"field": "service", "size": 20}},
			"by_event_type": map[string]interface{}{"terms": map[string]interface{}{"field": "event_type", "size": 20}},
			"by_success":    map[string]interface{}{"terms": map[string]interface{}{"field": "success", "size": 2}},
			"by_severity":   map[string]interface{}{"terms": map[string]interface{}{"field": "severity", "size": 10}},
			"top_users":     map[string]interface{}{"terms": map[string]interface{}{"field": "username", "size": 10}},
			"top_ips":       map[string]interface{}{"terms": map[string]interface{}{"field": "client_ip", "size": 10}},
			"failed_logins": map[string]interface{}{
				"filter": map[string]interface{}{
					"bool": map[string]interface{}{
						"must": []map[string]interface{}{
							{"term": map[string]interface{}{"success": false}},
						},
					},
				},
			},
			"mfa_events": map[string]interface{}{
				"filter": map[string]interface{}{"term": map[string]interface{}{"mfa": true}},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)
	req := opensearchapi.SearchRequest{
		Index: []string{jumpcloudIndexName},
		Body:  strings.NewReader(string(queryJSON)),
	}

	res, err := req.Do(context.Background(), s.opensearch)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	stats := map[string]interface{}{
		"total_events": 0, "failed_logins": 0, "mfa_events": 0,
		"by_service": []interface{}{}, "by_event_type": []interface{}{},
		"by_success": []interface{}{}, "by_severity": []interface{}{},
		"top_users": []interface{}{}, "top_ips": []interface{}{},
	}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			if value, ok := total["value"].(float64); ok {
				stats["total_events"] = int(value)
			}
		}
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		for _, key := range []string{"by_service", "by_event_type", "by_success", "by_severity", "top_users", "top_ips"} {
			if agg, ok := aggs[key].(map[string]interface{}); ok {
				if buckets, ok := agg["buckets"].([]interface{}); ok {
					stats[key] = buckets
				}
			}
		}
		if fl, ok := aggs["failed_logins"].(map[string]interface{}); ok {
			if dc, ok := fl["doc_count"].(float64); ok {
				stats["failed_logins"] = int(dc)
			}
		}
		if mfa, ok := aggs["mfa_events"].(map[string]interface{}); ok {
			if dc, ok := mfa["doc_count"].(float64); ok {
				stats["mfa_events"] = int(dc)
			}
		}
	}

	return stats
}

func (s *APIServer) handleJumpCloudDiagnostic(c *gin.Context) {
	if jumpcloudCollector == nil || jumpcloudCollector.config.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "JumpCloud Service Account not configured"})
		return
	}

	tests := []map[string]interface{}{}

	// Test 1: OAuth2 Token
	tokenTest := map[string]interface{}{
		"name":     "OAuth2 Token (Service Account)",
		"endpoint": jumpcloudTokenURL,
	}
	token, err := jumpcloudCollector.getAccessToken()
	if err != nil {
		tokenTest["success"] = false
		tokenTest["error"] = err.Error()
	} else {
		tokenTest["success"] = true
		tokenTest["message"] = "OAuth2 access token obtained successfully"
	}
	tests = append(tests, tokenTest)

	// Test 2: Directory Insights API
	apiTest := map[string]interface{}{
		"name":     "Directory Insights API",
		"endpoint": jumpcloudAPIBaseURL,
	}
	if token == "" {
		apiTest["success"] = false
		apiTest["error"] = "No token available (OAuth2 step failed)"
	} else {
		jumpcloudCollector.mu.RLock()
		orgID := jumpcloudCollector.config.OrgID
		jumpcloudCollector.mu.RUnlock()

		body := `{"service": ["all"], "start_time": "` + time.Now().UTC().Add(-1*time.Hour).Format(time.RFC3339) + `", "limit": 5}`
		httpReq, _ := http.NewRequest("POST", jumpcloudAPIBaseURL, strings.NewReader(body))
		httpReq.Header.Set("Authorization", "Bearer "+token)
		httpReq.Header.Set("Content-Type", "application/json")
		if orgID != "" {
			httpReq.Header.Set("x-org-id", orgID)
		}

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(httpReq)

		if err != nil {
			apiTest["success"] = false
			apiTest["error"] = err.Error()
		} else {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			apiTest["http_status"] = resp.StatusCode
			if resp.StatusCode == 200 {
				var events []interface{}
				json.Unmarshal(respBody, &events)
				apiTest["success"] = true
				apiTest["events_returned"] = len(events)
				apiTest["message"] = fmt.Sprintf("OK - %d events in last hour", len(events))
			} else {
				apiTest["success"] = false
				apiTest["error"] = string(respBody[:min(len(respBody), 300)])
			}
		}
	}
	tests = append(tests, apiTest)

	// Test 2: OpenSearch index
	osTest := map[string]interface{}{
		"name": "OpenSearch Index (siem-jumpcloud-events)",
	}
	if s.opensearch != nil {
		countQuery := `{"query": {"match_all": {}}}`
		countReq := opensearchapi.CountRequest{
			Index: []string{jumpcloudIndexName},
			Body:  strings.NewReader(countQuery),
		}
		countRes, err := countReq.Do(context.Background(), s.opensearch)
		if err != nil {
			osTest["success"] = false
			osTest["error"] = err.Error()
		} else {
			defer countRes.Body.Close()
			var countResult map[string]interface{}
			json.NewDecoder(countRes.Body).Decode(&countResult)
			if count, ok := countResult["count"].(float64); ok {
				osTest["success"] = true
				osTest["document_count"] = int(count)
				osTest["message"] = fmt.Sprintf("Index exists with %d documents", int(count))
			} else {
				osTest["success"] = true
				osTest["message"] = "Index exists"
			}
		}
	} else {
		osTest["success"] = false
		osTest["error"] = "OpenSearch client not available"
	}
	tests = append(tests, osTest)

	summary := "Todos os testes passaram"
	allOK := true
	for _, t := range tests {
		if t["success"] != true {
			allOK = false
			summary = "Alguns testes falharam - verifique os detalhes"
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"timestamp": time.Now().Format(time.RFC3339),
		"tests":     tests,
		"summary":   summary,
		"all_ok":    allOK,
	})
}
