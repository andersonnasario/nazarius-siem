package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// THREAT INTELLIGENCE FEEDS
// ============================================================================
// This module integrates with external threat intelligence feeds to enrich
// security events with IOC (Indicators of Compromise) data.
//
// Supported feeds:
// - AbuseIPDB (IP reputation)
// - VirusTotal (file hashes, domains, IPs)
// - AlienVault OTX (pulses)
// - URLhaus (malicious URLs)
// - Emerging Threats (IP blocklist)

// IOCType represents the type of indicator
type IOCType string

const (
	IOCTypeIP       IOCType = "ip"
	IOCTypeDomain   IOCType = "domain"
	IOCTypeURL      IOCType = "url"
	IOCTypeHash     IOCType = "hash"
	IOCTypeEmail    IOCType = "email"
	IOCTypeHostname IOCType = "hostname"
)

// ThreatIntelResult represents the result of a threat intelligence lookup
type ThreatIntelResult struct {
	Indicator       string                 `json:"indicator"`
	Type            IOCType                `json:"type"`
	IsMalicious     bool                   `json:"is_malicious"`
	ThreatScore     int                    `json:"threat_score"` // 0-100
	Confidence      int                    `json:"confidence"`   // 0-100
	Categories      []string               `json:"categories"`
	Tags            []string               `json:"tags"`
	Sources         []string               `json:"sources"`
	FirstSeen       *time.Time             `json:"first_seen,omitempty"`
	LastSeen        *time.Time             `json:"last_seen,omitempty"`
	Description     string                 `json:"description,omitempty"`
	RelatedIOCs     []string               `json:"related_iocs,omitempty"`
	GeoData         *GeoIPData             `json:"geo_data,omitempty"`
	MITRETechniques []string               `json:"mitre_techniques,omitempty"`
	RawData         map[string]interface{} `json:"raw_data,omitempty"`
	CachedAt        time.Time              `json:"cached_at"`
}

// GeoIPData represents geolocation data for an IP
type GeoIPData struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	ASN         string  `json:"asn"`
	ASNOrg      string  `json:"asn_org"`
}

// ThreatIntelFeed represents a threat intelligence feed
type ThreatIntelFeed struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Provider    string    `json:"provider"`
	Type        string    `json:"type"` // ip, domain, hash, mixed
	URL         string    `json:"url"`
	Enabled     bool      `json:"enabled"`
	APIKey      string    `json:"-"` // Hidden from JSON
	LastSync    time.Time `json:"last_sync"`
	IOCCount    int       `json:"ioc_count"`
	Status      string    `json:"status"` // active, error, disabled
	LastError   string    `json:"last_error,omitempty"`
}

// ThreatIntelManager manages threat intelligence feeds and lookups
type ThreatIntelManager struct {
	mu        sync.RWMutex
	feeds     map[string]*ThreatIntelFeed
	cache     map[string]*ThreatIntelResult
	cacheTTL  time.Duration
	httpClient *http.Client
}

var (
	threatIntelManager     *ThreatIntelManager
	threatIntelManagerOnce sync.Once
)

// GetThreatIntelManager returns the singleton threat intel manager
func GetThreatIntelManager() *ThreatIntelManager {
	threatIntelManagerOnce.Do(func() {
		threatIntelManager = &ThreatIntelManager{
			feeds:    make(map[string]*ThreatIntelFeed),
			cache:    make(map[string]*ThreatIntelResult),
			cacheTTL: 24 * time.Hour,
			httpClient: &http.Client{
				Timeout: 10 * time.Second,
			},
		}
		threatIntelManager.initializeFeeds()
	})
	return threatIntelManager
}

// initializeFeeds sets up the default threat feeds
func (tim *ThreatIntelManager) initializeFeeds() {
	// AbuseIPDB
	if apiKey := os.Getenv("ABUSEIPDB_API_KEY"); apiKey != "" {
		tim.feeds["abuseipdb"] = &ThreatIntelFeed{
			ID:       "abuseipdb",
			Name:     "AbuseIPDB",
			Provider: "AbuseIPDB",
			Type:     "ip",
			URL:      "https://api.abuseipdb.com/api/v2",
			Enabled:  true,
			APIKey:   apiKey,
			Status:   "active",
		}
	}

	// VirusTotal
	if apiKey := os.Getenv("VIRUSTOTAL_API_KEY"); apiKey != "" {
		tim.feeds["virustotal"] = &ThreatIntelFeed{
			ID:       "virustotal",
			Name:     "VirusTotal",
			Provider: "VirusTotal",
			Type:     "mixed",
			URL:      "https://www.virustotal.com/api/v3",
			Enabled:  true,
			APIKey:   apiKey,
			Status:   "active",
		}
	}

	// AlienVault OTX
	if apiKey := os.Getenv("OTX_API_KEY"); apiKey != "" {
		tim.feeds["otx"] = &ThreatIntelFeed{
			ID:       "otx",
			Name:     "AlienVault OTX",
			Provider: "AlienVault",
			Type:     "mixed",
			URL:      "https://otx.alienvault.com/api/v1",
			Enabled:  true,
			APIKey:   apiKey,
			Status:   "active",
		}
	}

	// Emerging Threats (free, no API key)
	tim.feeds["emergingthreats"] = &ThreatIntelFeed{
		ID:       "emergingthreats",
		Name:     "Emerging Threats",
		Provider: "Proofpoint",
		Type:     "ip",
		URL:      "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
		Enabled:  true,
		Status:   "active",
	}

	// URLhaus (free, no API key)
	tim.feeds["urlhaus"] = &ThreatIntelFeed{
		ID:       "urlhaus",
		Name:     "URLhaus",
		Provider: "abuse.ch",
		Type:     "url",
		URL:      "https://urlhaus-api.abuse.ch/v1",
		Enabled:  true,
		Status:   "active",
	}

	log.Printf("✅ Threat Intel Manager initialized with %d feeds", len(tim.feeds))
}

// LookupIOC performs a threat intelligence lookup for an indicator
func (tim *ThreatIntelManager) LookupIOC(indicator string, iocType IOCType) (*ThreatIntelResult, error) {
	tim.mu.Lock()
	defer tim.mu.Unlock()

	cacheKey := fmt.Sprintf("%s:%s", iocType, indicator)

	// Check cache
	if cached, ok := tim.cache[cacheKey]; ok {
		if time.Since(cached.CachedAt) < tim.cacheTTL {
			return cached, nil
		}
	}

	result := &ThreatIntelResult{
		Indicator:   indicator,
		Type:        iocType,
		IsMalicious: false,
		ThreatScore: 0,
		Confidence:  0,
		Categories:  []string{},
		Tags:        []string{},
		Sources:     []string{},
		CachedAt:    time.Now(),
	}

	// Query enabled feeds based on IOC type
	switch iocType {
	case IOCTypeIP:
		tim.lookupIPReputation(result)
	case IOCTypeDomain:
		tim.lookupDomainReputation(result)
	case IOCTypeHash:
		tim.lookupHashReputation(result)
	case IOCTypeURL:
		tim.lookupURLReputation(result)
	}

	// Cache the result
	tim.cache[cacheKey] = result

	return result, nil
}

// lookupIPReputation queries IP reputation feeds
func (tim *ThreatIntelManager) lookupIPReputation(result *ThreatIntelResult) {
	// Query AbuseIPDB
	if feed, ok := tim.feeds["abuseipdb"]; ok && feed.Enabled && feed.APIKey != "" {
		abuseResult, err := tim.queryAbuseIPDB(result.Indicator, feed.APIKey)
		if err == nil && abuseResult != nil {
			result.Sources = append(result.Sources, "AbuseIPDB")
			if abuseScore, ok := abuseResult["abuseConfidenceScore"].(float64); ok {
				result.ThreatScore = maxInt(result.ThreatScore, int(abuseScore))
				if abuseScore > 50 {
					result.IsMalicious = true
				}
			}
			if country, ok := abuseResult["countryCode"].(string); ok {
				result.GeoData = &GeoIPData{CountryCode: country}
			}
			if isp, ok := abuseResult["isp"].(string); ok && result.GeoData != nil {
				result.GeoData.ISP = isp
			}
			if usageType, ok := abuseResult["usageType"].(string); ok {
				result.Categories = append(result.Categories, usageType)
			}
			result.RawData = map[string]interface{}{"abuseipdb": abuseResult}
		}
	}

	// Query VirusTotal
	if feed, ok := tim.feeds["virustotal"]; ok && feed.Enabled && feed.APIKey != "" {
		vtResult, err := tim.queryVirusTotalIP(result.Indicator, feed.APIKey)
		if err == nil && vtResult != nil {
			result.Sources = append(result.Sources, "VirusTotal")
			if malicious, ok := vtResult["malicious"].(float64); ok && malicious > 0 {
				result.IsMalicious = true
				result.ThreatScore = maxInt(result.ThreatScore, int(malicious*10))
			}
		}
	}

	// Calculate confidence based on number of sources
	result.Confidence = minInt(len(result.Sources)*30, 100)
}

// lookupDomainReputation queries domain reputation feeds
func (tim *ThreatIntelManager) lookupDomainReputation(result *ThreatIntelResult) {
	// Query VirusTotal
	if feed, ok := tim.feeds["virustotal"]; ok && feed.Enabled && feed.APIKey != "" {
		vtResult, err := tim.queryVirusTotalDomain(result.Indicator, feed.APIKey)
		if err == nil && vtResult != nil {
			result.Sources = append(result.Sources, "VirusTotal")
			if malicious, ok := vtResult["malicious"].(float64); ok && malicious > 0 {
				result.IsMalicious = true
				result.ThreatScore = maxInt(result.ThreatScore, int(malicious*10))
			}
		}
	}

	// Query OTX
	if feed, ok := tim.feeds["otx"]; ok && feed.Enabled && feed.APIKey != "" {
		otxResult, err := tim.queryOTXDomain(result.Indicator, feed.APIKey)
		if err == nil && otxResult != nil {
			result.Sources = append(result.Sources, "AlienVault OTX")
			if pulseCount, ok := otxResult["pulse_count"].(float64); ok && pulseCount > 0 {
				result.IsMalicious = true
				result.ThreatScore = maxInt(result.ThreatScore, int(pulseCount*5))
				result.Tags = append(result.Tags, fmt.Sprintf("%d OTX pulses", int(pulseCount)))
			}
		}
	}

	result.Confidence = minInt(len(result.Sources)*30, 100)
}

// lookupHashReputation queries file hash reputation feeds
func (tim *ThreatIntelManager) lookupHashReputation(result *ThreatIntelResult) {
	// Query VirusTotal
	if feed, ok := tim.feeds["virustotal"]; ok && feed.Enabled && feed.APIKey != "" {
		vtResult, err := tim.queryVirusTotalHash(result.Indicator, feed.APIKey)
		if err == nil && vtResult != nil {
			result.Sources = append(result.Sources, "VirusTotal")
			if malicious, ok := vtResult["malicious"].(float64); ok {
				if malicious > 0 {
					result.IsMalicious = true
					result.ThreatScore = maxInt(result.ThreatScore, int(malicious*2)) // Scale up
				}
				result.Description = fmt.Sprintf("%d/%.0f engines detected as malicious", 
					int(malicious), vtResult["total"].(float64))
			}
		}
	}

	result.Confidence = minInt(len(result.Sources)*30, 100)
}

// lookupURLReputation queries URL reputation feeds
func (tim *ThreatIntelManager) lookupURLReputation(result *ThreatIntelResult) {
	// Query URLhaus
	if feed, ok := tim.feeds["urlhaus"]; ok && feed.Enabled {
		urlhausResult, err := tim.queryURLhaus(result.Indicator)
		if err == nil && urlhausResult != nil {
			result.Sources = append(result.Sources, "URLhaus")
			if queryStatus, ok := urlhausResult["query_status"].(string); ok && queryStatus == "ok" {
				result.IsMalicious = true
				result.ThreatScore = 90
				if threat, ok := urlhausResult["threat"].(string); ok {
					result.Categories = append(result.Categories, threat)
				}
				if tags, ok := urlhausResult["tags"].([]interface{}); ok {
					for _, tag := range tags {
						result.Tags = append(result.Tags, tag.(string))
					}
				}
			}
		}
	}

	result.Confidence = minInt(len(result.Sources)*30, 100)
}

// ============================================================================
// FEED QUERY FUNCTIONS
// ============================================================================

func (tim *ThreatIntelManager) queryAbuseIPDB(ip string, apiKey string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := tim.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("AbuseIPDB returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		return data, nil
	}

	return nil, fmt.Errorf("unexpected response format")
}

func (tim *ThreatIntelManager) queryVirusTotalIP(ip string, apiKey string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", apiKey)

	resp, err := tim.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VirusTotal returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		if attrs, ok := data["attributes"].(map[string]interface{}); ok {
			if stats, ok := attrs["last_analysis_stats"].(map[string]interface{}); ok {
				return stats, nil
			}
		}
	}

	return nil, fmt.Errorf("unexpected response format")
}

func (tim *ThreatIntelManager) queryVirusTotalDomain(domain string, apiKey string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", apiKey)

	resp, err := tim.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VirusTotal returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		if attrs, ok := data["attributes"].(map[string]interface{}); ok {
			if stats, ok := attrs["last_analysis_stats"].(map[string]interface{}); ok {
				return stats, nil
			}
		}
	}

	return nil, fmt.Errorf("unexpected response format")
}

func (tim *ThreatIntelManager) queryVirusTotalHash(hash string, apiKey string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", apiKey)

	resp, err := tim.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VirusTotal returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		if attrs, ok := data["attributes"].(map[string]interface{}); ok {
			if stats, ok := attrs["last_analysis_stats"].(map[string]interface{}); ok {
				stats["total"] = attrs["last_analysis_results"]
				return stats, nil
			}
		}
	}

	return nil, fmt.Errorf("unexpected response format")
}

func (tim *ThreatIntelManager) queryOTXDomain(domain string, apiKey string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/general", domain), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", apiKey)

	resp, err := tim.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OTX returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

func (tim *ThreatIntelManager) queryURLhaus(url string) (map[string]interface{}, error) {
	resp, err := tim.httpClient.Post(
		"https://urlhaus-api.abuse.ch/v1/url/",
		"application/x-www-form-urlencoded",
		strings.NewReader(fmt.Sprintf("url=%s", url)),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("URLhaus returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// ============================================================================
// BULK IOC DOWNLOAD
// ============================================================================

// SyncEmergingThreats downloads the Emerging Threats IP blocklist
func (tim *ThreatIntelManager) SyncEmergingThreats() ([]string, error) {
	feed := tim.feeds["emergingthreats"]
	if feed == nil || !feed.Enabled {
		return nil, fmt.Errorf("Emerging Threats feed not enabled")
	}

	resp, err := tim.httpClient.Get(feed.URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(body), "\n")
	ips := []string{}
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}

	feed.LastSync = time.Now()
	feed.IOCCount = len(ips)

	log.Printf("✅ Synced %d IPs from Emerging Threats", len(ips))
	return ips, nil
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

// handleLookupIOC looks up a single indicator
func (s *APIServer) handleLookupIOC(c *gin.Context) {
	indicator := c.Query("indicator")
	iocType := c.Query("type")

	if indicator == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "indicator is required"})
		return
	}

	if iocType == "" {
		iocType = detectIOCType(indicator)
	}

	tim := GetThreatIntelManager()
	result, err := tim.LookupIOC(indicator, IOCType(iocType))
	if err != nil {
		log.Printf("[ERROR] handleLookupIOC: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"result":  result,
	})
}

// handleBulkLookupIOC looks up multiple indicators
func (s *APIServer) handleBulkLookupIOC(c *gin.Context) {
	var request struct {
		Indicators []string `json:"indicators"`
		Type       string   `json:"type"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		log.Printf("[ERROR] handleBulkLookupIOC bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if len(request.Indicators) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "indicators array is required"})
		return
	}

	if len(request.Indicators) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "maximum 100 indicators per request"})
		return
	}

	tim := GetThreatIntelManager()
	results := make([]*ThreatIntelResult, 0, len(request.Indicators))

	for _, indicator := range request.Indicators {
		iocType := request.Type
		if iocType == "" {
			iocType = detectIOCType(indicator)
		}

		result, err := tim.LookupIOC(indicator, IOCType(iocType))
		if err != nil {
			log.Printf("⚠️ Failed to lookup %s: %v", indicator, err)
			continue
		}
		results = append(results, result)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"results": results,
		"total":   len(results),
	})
}

// handleListThreatIntelFeeds lists all configured threat feeds
func (s *APIServer) handleListThreatIntelFeeds(c *gin.Context) {
	tim := GetThreatIntelManager()
	tim.mu.RLock()
	defer tim.mu.RUnlock()

	feeds := make([]*ThreatIntelFeed, 0, len(tim.feeds))
	for _, feed := range tim.feeds {
		feeds = append(feeds, feed)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"feeds":   feeds,
		"total":   len(feeds),
	})
}

// handleSyncThreatFeed syncs a specific threat feed
func (s *APIServer) handleSyncThreatFeed(c *gin.Context) {
	feedID := c.Param("id")
	
	tim := GetThreatIntelManager()
	
	switch feedID {
	case "emergingthreats":
		ips, err := tim.SyncEmergingThreats()
		if err != nil {
			log.Printf("[ERROR] handleSyncThreatFeed emergingthreats: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": fmt.Sprintf("Synced %d IPs", len(ips)),
		})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Feed not found or sync not supported"})
	}
}

// handleGetThreatIntelStats returns threat intel statistics
func (s *APIServer) handleGetThreatIntelStats(c *gin.Context) {
	tim := GetThreatIntelManager()
	tim.mu.RLock()
	defer tim.mu.RUnlock()

	maliciousCount := 0
	for _, result := range tim.cache {
		if result.IsMalicious {
			maliciousCount++
		}
	}

	stats := map[string]interface{}{
		"enabled_feeds":      len(tim.feeds),
		"cached_iocs":        len(tim.cache),
		"malicious_iocs":     maliciousCount,
		"cache_ttl_hours":    tim.cacheTTL.Hours(),
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// detectIOCType attempts to automatically detect the IOC type
func detectIOCType(indicator string) string {
	indicator = strings.TrimSpace(indicator)

	// Check if it's an IP (simple check)
	if isIP(indicator) {
		return string(IOCTypeIP)
	}

	// Check if it's a hash (MD5, SHA1, SHA256)
	if len(indicator) == 32 || len(indicator) == 40 || len(indicator) == 64 {
		if isHex(indicator) {
			return string(IOCTypeHash)
		}
	}

	// Check if it's a URL
	if strings.HasPrefix(indicator, "http://") || strings.HasPrefix(indicator, "https://") {
		return string(IOCTypeURL)
	}

	// Check if it's an email
	if strings.Contains(indicator, "@") {
		return string(IOCTypeEmail)
	}

	// Default to domain
	return string(IOCTypeDomain)
}

func isIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// maxInt returns the maximum of two integers
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

