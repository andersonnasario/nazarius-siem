package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/opensearch-project/opensearch-go/v2/opensearchapi"
)

// FortiGate Log Types
const (
	FortiLogTypeTraffic      = "traffic"
	FortiLogTypeUTM          = "utm"
	FortiLogTypeEvent        = "event"
	FortiLogTypeAnomaly      = "anomaly"
	FortiLogTypeVirus        = "virus"
	FortiLogTypeWebfilter    = "webfilter"
	FortiLogTypeIPS          = "ips"
	FortiLogTypeEmailfilter  = "emailfilter"
	FortiLogTypeDLP          = "dlp"
	FortiLogTypeAppCtrl      = "app-ctrl"
	FortiLogTypeVoIP         = "voip"
	FortiLogTypeDNS          = "dns"
	FortiLogTypeSSL          = "ssl"
	FortiLogTypeAntiVirus    = "av"
	FortiLogTypeFortiSandbox = "sandbox"
)

// FortiGate Actions
const (
	FortiActionAllow  = "allow"
	FortiActionDeny   = "deny"
	FortiActionBlock  = "block"
	FortiActionDrop   = "drop"
	FortiActionPass   = "pass"
	FortiActionReject = "reject"
)

// FortinetWebhookConfig holds webhook configuration
type FortinetWebhookConfig struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	DeviceIP     string    `json:"device_ip"`
	DeviceName   string    `json:"device_name"`
	VDOM         string    `json:"vdom"`
	APIKey       string    `json:"api_key"`       // For authentication
	SecretKey    string    `json:"secret_key"`    // For HMAC validation
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	LastEventAt  *time.Time `json:"last_event_at"`
	EventCount   int64     `json:"event_count"`
	LogTypes     []string  `json:"log_types"`     // Filter log types to accept
}

// FortinetRawLog represents raw syslog from FortiGate
type FortinetRawLog struct {
	Timestamp   time.Time              `json:"timestamp"`
	RawMessage  string                 `json:"raw_message"`
	DeviceIP    string                 `json:"device_ip"`
	DeviceName  string                 `json:"device_name"`
	Facility    int                    `json:"facility"`
	Severity    int                    `json:"severity"`
	ParsedData  map[string]interface{} `json:"parsed_data"`
}

// FortinetNormalizedEvent represents a normalized SIEM event
type FortinetNormalizedEvent struct {
	ID              string                 `json:"id"`
	Timestamp       time.Time              `json:"timestamp"`
	ReceiveTime     time.Time              `json:"receive_time"`
	DeviceIP        string                 `json:"device_ip"`
	DeviceName      string                 `json:"device_name"`
	DeviceVDOM      string                 `json:"device_vdom"`
	LogType         string                 `json:"log_type"`
	SubType         string                 `json:"sub_type"`
	Level           string                 `json:"level"`
	EventType       string                 `json:"event_type"`
	Action          string                 `json:"action"`
	
	// Source Information
	SrcIP           string                 `json:"src_ip"`
	SrcPort         int                    `json:"src_port"`
	SrcMAC          string                 `json:"src_mac"`
	SrcInterface    string                 `json:"src_interface"`
	SrcCountry      string                 `json:"src_country"`
	SrcUser         string                 `json:"src_user"`
	
	// Destination Information
	DstIP           string                 `json:"dst_ip"`
	DstPort         int                    `json:"dst_port"`
	DstMAC          string                 `json:"dst_mac"`
	DstInterface    string                 `json:"dst_interface"`
	DstCountry      string                 `json:"dst_country"`
	
	// Network Information
	Protocol        string                 `json:"protocol"`
	ProtocolNumber  int                    `json:"protocol_number"`
	Service         string                 `json:"service"`
	Application     string                 `json:"application"`
	AppCategory     string                 `json:"app_category"`
	SessionID       string                 `json:"session_id"`
	
	// Traffic Metrics
	SentBytes       int64                  `json:"sent_bytes"`
	ReceivedBytes   int64                  `json:"received_bytes"`
	SentPackets     int64                  `json:"sent_packets"`
	ReceivedPackets int64                  `json:"received_packets"`
	Duration        int                    `json:"duration"`
	
	// Security Information
	Policy          string                 `json:"policy"`
	PolicyID        int                    `json:"policy_id"`
	PolicyType      string                 `json:"policy_type"`
	Profile         string                 `json:"profile"`
	ThreatLevel     string                 `json:"threat_level"`
	ThreatScore     int                    `json:"threat_score"`
	ThreatType      string                 `json:"threat_type"`
	AttackName      string                 `json:"attack_name"`
	AttackID        string                 `json:"attack_id"`
	CVE             []string               `json:"cve"`
	Severity        string                 `json:"severity"`
	Reference       string                 `json:"reference"`
	
	// UTM Specific
	URL             string                 `json:"url"`
	Hostname        string                 `json:"hostname"`
	Category        string                 `json:"category"`
	CategoryID      int                    `json:"category_id"`
	VirusName       string                 `json:"virus_name"`
	FileName        string                 `json:"file_name"`
	FileType        string                 `json:"file_type"`
	FileSize        int64                  `json:"file_size"`
	FileHash        string                 `json:"file_hash"`
	
	// VPN Information
	VPNTunnel       string                 `json:"vpn_tunnel"`
	VPNType         string                 `json:"vpn_type"`
	VPNUser         string                 `json:"vpn_user"`
	
	// NAT Information
	NATSrcIP        string                 `json:"nat_src_ip"`
	NATSrcPort      int                    `json:"nat_src_port"`
	NATDstIP        string                 `json:"nat_dst_ip"`
	NATDstPort      int                    `json:"nat_dst_port"`
	
	// Message and Metadata
	Message         string                 `json:"message"`
	EventMessage    string                 `json:"event_message"`
	RawLog          string                 `json:"raw_log"`
	Tags            []string               `json:"tags"`
	
	// MITRE ATT&CK Mapping
	MITRETactic     string                 `json:"mitre_tactic"`
	MITRETechnique  string                 `json:"mitre_technique"`
	
	// Threat Intel Enrichment
	IOCMatch        bool                   `json:"ioc_match"`
	IOCType         string                 `json:"ioc_type"`
	IOCFeed         string                 `json:"ioc_feed"`
	
	// Additional Fields
	Extra           map[string]interface{} `json:"extra"`
}

// FortinetWebhookStats holds statistics
type FortinetWebhookStats struct {
	TotalEventsReceived   int64            `json:"total_events_received"`
	EventsLast24h         int64            `json:"events_last_24h"`
	EventsLastHour        int64            `json:"events_last_hour"`
	EventsByType          map[string]int64 `json:"events_by_type"`
	EventsByAction        map[string]int64 `json:"events_by_action"`
	EventsBySeverity      map[string]int64 `json:"events_by_severity"`
	TopSourceIPs          []IPCount        `json:"top_source_ips"`
	TopDestIPs            []IPCount        `json:"top_dest_ips"`
	TopBlockedIPs         []IPCount        `json:"top_blocked_ips"`
	TopApplications       []NameCount      `json:"top_applications"`
	TopCategories         []NameCount      `json:"top_categories"`
	ThreatDetections      int64            `json:"threat_detections"`
	IOCMatches            int64            `json:"ioc_matches"`
	ActiveDevices         int              `json:"active_devices"`
	LastEventTime         *time.Time       `json:"last_event_time"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// In-memory storage
var (
	fortinetConfigs     = make(map[string]*FortinetWebhookConfig)
	fortinetConfigMutex sync.RWMutex
	fortinetStats       = &FortinetWebhookStats{
		EventsByType:     make(map[string]int64),
		EventsByAction:   make(map[string]int64),
		EventsBySeverity: make(map[string]int64),
	}
	fortinetStatsMutex sync.RWMutex
)

// OpenSearch index name
const FortinetIndexName = "siem-fortinet-logs"
const FortinetAlertsIndexName = "siem-fortinet-alerts"

// Initialize Fortinet webhook
func initFortinetWebhook() {
	fortinetConfigMutex.Lock()
	defer fortinetConfigMutex.Unlock()

	// Default configuration
	fortinetConfigs["default"] = &FortinetWebhookConfig{
		ID:         "default",
		Name:       "Default Fortinet Webhook",
		Enabled:    true,
		CreatedAt:  time.Now(),
		EventCount: 0,
		LogTypes:   []string{"traffic", "utm", "event", "anomaly", "ips", "virus", "webfilter", "app-ctrl"},
	}

	log.Println("✅ Fortinet webhook initialized")
}

// =====================================
// WEBHOOK HANDLERS
// =====================================

// handleFortinetWebhook receives logs from FortiGate devices
func (s *APIServer) handleFortinetWebhook(c *gin.Context) {
	// Get API key from header for authentication
	apiKey := c.GetHeader("X-API-Key")
	configID := c.Query("config_id")
	if configID == "" {
		configID = "default"
	}

	// Validate config
	fortinetConfigMutex.RLock()
	config, exists := fortinetConfigs[configID]
	fortinetConfigMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Webhook configuration not found"})
		return
	}

	if !config.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "Webhook is disabled"})
		return
	}

	// Validate API key if configured
	if config.APIKey != "" && apiKey != config.APIKey {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	// Read request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}

	// Validate HMAC signature if secret key is configured
	if config.SecretKey != "" {
		signature := c.GetHeader("X-Signature")
		if !validateHMACSignature(body, signature, config.SecretKey) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			return
		}
	}

	// Get device info from headers or request
	deviceIP := c.GetHeader("X-Device-IP")
	if deviceIP == "" {
		deviceIP = c.ClientIP()
	}
	deviceName := c.GetHeader("X-Device-Name")
	if deviceName == "" {
		deviceName = config.DeviceName
	}

	// Determine content type
	contentType := c.ContentType()
	
	var events []*FortinetNormalizedEvent

	switch {
	case strings.Contains(contentType, "application/json"):
		// JSON format (FortiGate Cloud, FortiAnalyzer, custom)
		events, err = parseFortinetJSON(body, deviceIP, deviceName)
	case strings.Contains(contentType, "text/plain"):
		// Syslog/CEF format
		events, err = parseFortinetSyslog(body, deviceIP, deviceName)
	default:
		// Try auto-detection
		events, err = parseFortinetAuto(body, deviceIP, deviceName)
	}

	if err != nil {
		log.Printf("Error parsing Fortinet logs: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse logs", "details": err.Error()})
		return
	}

	// Process events
	processedCount := 0
	alertCount := 0
	iocMatchCount := 0

	for _, event := range events {
		// Filter by log type if configured
		if len(config.LogTypes) > 0 && !fortinetContainsString(config.LogTypes, event.LogType) {
			continue
		}

		// Enrich with threat intelligence
		enriched := s.enrichFortinetEvent(event)

		// Index to OpenSearch
		if err := s.indexFortinetEvent(enriched); err != nil {
			log.Printf("Error indexing Fortinet event: %v", err)
			continue
		}

		processedCount++

		// Check if it should generate an alert
		if shouldGenerateAlert(enriched) {
			if err := s.generateFortinetAlert(enriched); err != nil {
				log.Printf("Error generating alert: %v", err)
			} else {
				alertCount++
			}
		}

		// Count IOC matches
		if enriched.IOCMatch {
			iocMatchCount++
		}
	}

	// Update stats
	updateFortinetStats(events, processedCount, alertCount, iocMatchCount)

	// Update config last event time
	fortinetConfigMutex.Lock()
	now := time.Now()
	config.LastEventAt = &now
	config.EventCount += int64(processedCount)
	fortinetConfigMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"events_received": len(events),
		"events_processed": processedCount,
		"alerts_generated": alertCount,
		"ioc_matches":     iocMatchCount,
		"timestamp":       time.Now(),
	})
}

// handleFortinetBatchWebhook receives batch logs
func (s *APIServer) handleFortinetBatchWebhook(c *gin.Context) {
	var batch struct {
		Events []json.RawMessage `json:"events"`
		Device struct {
			IP   string `json:"ip"`
			Name string `json:"name"`
			VDOM string `json:"vdom"`
		} `json:"device"`
	}

	if err := c.ShouldBindJSON(&batch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	processedCount := 0
	alertCount := 0
	errors := []string{}

	for i, rawEvent := range batch.Events {
		events, err := parseFortinetJSON(rawEvent, batch.Device.IP, batch.Device.Name)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Event %d: %v", i, err))
			continue
		}

		for _, event := range events {
			enriched := s.enrichFortinetEvent(event)
			if err := s.indexFortinetEvent(enriched); err != nil {
				log.Printf("Error indexing event: %v", err)
				continue
			}
			processedCount++

			if shouldGenerateAlert(enriched) {
				if err := s.generateFortinetAlert(enriched); err == nil {
					alertCount++
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":          true,
		"events_received":  len(batch.Events),
		"events_processed": processedCount,
		"alerts_generated": alertCount,
		"errors":           errors,
	})
}

// =====================================
// PARSERS
// =====================================

// parseFortinetJSON parses JSON formatted logs
func parseFortinetJSON(data []byte, deviceIP, deviceName string) ([]*FortinetNormalizedEvent, error) {
	var events []*FortinetNormalizedEvent

	// Try parsing as array first
	var jsonArray []map[string]interface{}
	if err := json.Unmarshal(data, &jsonArray); err == nil {
		for _, item := range jsonArray {
			event := normalizeFortinetLog(item, deviceIP, deviceName)
			events = append(events, event)
		}
		return events, nil
	}

	// Try as single object
	var jsonObj map[string]interface{}
	if err := json.Unmarshal(data, &jsonObj); err == nil {
		event := normalizeFortinetLog(jsonObj, deviceIP, deviceName)
		return []*FortinetNormalizedEvent{event}, nil
	}

	// Try as line-delimited JSON
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			event := normalizeFortinetLog(obj, deviceIP, deviceName)
			events = append(events, event)
		}
	}

	if len(events) > 0 {
		return events, nil
	}

	return nil, fmt.Errorf("unable to parse JSON data")
}

// parseFortinetSyslog parses syslog/CEF formatted logs
func parseFortinetSyslog(data []byte, deviceIP, deviceName string) ([]*FortinetNormalizedEvent, error) {
	var events []*FortinetNormalizedEvent

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse FortiGate key=value format
		parsed := parseKeyValueLog(line)
		if len(parsed) > 0 {
			event := normalizeFortinetLog(parsed, deviceIP, deviceName)
			event.RawLog = line
			events = append(events, event)
		}
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("no valid syslog entries found")
	}

	return events, nil
}

// parseFortinetAuto auto-detects format and parses
func parseFortinetAuto(data []byte, deviceIP, deviceName string) ([]*FortinetNormalizedEvent, error) {
	// Try JSON first
	events, err := parseFortinetJSON(data, deviceIP, deviceName)
	if err == nil && len(events) > 0 {
		return events, nil
	}

	// Try syslog
	return parseFortinetSyslog(data, deviceIP, deviceName)
}

// parseKeyValueLog parses FortiGate key=value format
func parseKeyValueLog(line string) map[string]interface{} {
	result := make(map[string]interface{})

	// Remove syslog header if present
	// Format: <priority>date time hostname ... key=value key=value
	if strings.HasPrefix(line, "<") {
		idx := strings.Index(line, ">")
		if idx > 0 {
			line = line[idx+1:]
		}
	}

	// Regular expression to match key="value" or key=value
	re := regexp.MustCompile(`(\w+)=("[^"]*"|\S+)`)
	matches := re.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			key := match[1]
			value := strings.Trim(match[2], "\"")

			// Try to convert to appropriate type
			if intVal, err := strconv.Atoi(value); err == nil {
				result[key] = intVal
			} else if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
				result[key] = floatVal
			} else {
				result[key] = value
			}
		}
	}

	return result
}

// normalizeFortinetLog converts parsed data to normalized event
func normalizeFortinetLog(data map[string]interface{}, deviceIP, deviceName string) *FortinetNormalizedEvent {
	event := &FortinetNormalizedEvent{
		ID:          uuid.New().String(),
		ReceiveTime: time.Now(),
		DeviceIP:    deviceIP,
		DeviceName:  deviceName,
		Extra:       make(map[string]interface{}),
		Tags:        []string{"fortinet", "fortigate"},
	}

	// Parse timestamp
	if ts, ok := data["eventtime"].(float64); ok {
		event.Timestamp = time.Unix(int64(ts/1000000), 0)
	} else if ts, ok := data["date"].(string); ok {
		if t, ok := data["time"].(string); ok {
			parsed, _ := time.Parse("2006-01-02 15:04:05", ts+" "+t)
			event.Timestamp = parsed
		}
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Log type and subtype
	event.LogType = fortinetGetString(data, "type", "traffic")
	event.SubType = fortinetGetString(data, "subtype", "")
	event.Level = fortinetGetString(data, "level", "notice")
	event.EventType = fortinetGetString(data, "eventtype", "")

	// Action
	event.Action = fortinetGetString(data, "action", "")
	if event.Action == "" {
		event.Action = fortinetGetString(data, "status", "")
	}

	// Source
	event.SrcIP = fortinetGetString(data, "srcip", "")
	event.SrcPort = fortinetGetInt(data, "srcport", 0)
	event.SrcMAC = fortinetGetString(data, "srcmac", "")
	event.SrcInterface = fortinetGetString(data, "srcintf", "")
	event.SrcCountry = fortinetGetString(data, "srccountry", "")
	event.SrcUser = fortinetGetString(data, "srcuser", "")
	if event.SrcUser == "" {
		event.SrcUser = fortinetGetString(data, "user", "")
	}

	// Destination
	event.DstIP = fortinetGetString(data, "dstip", "")
	event.DstPort = fortinetGetInt(data, "dstport", 0)
	event.DstMAC = fortinetGetString(data, "dstmac", "")
	event.DstInterface = fortinetGetString(data, "dstintf", "")
	event.DstCountry = fortinetGetString(data, "dstcountry", "")

	// Network
	event.Protocol = fortinetGetString(data, "proto", "")
	event.ProtocolNumber = fortinetGetInt(data, "proto", 0)
	event.Service = fortinetGetString(data, "service", "")
	event.Application = fortinetGetString(data, "app", "")
	event.AppCategory = fortinetGetString(data, "appcat", "")
	event.SessionID = fortinetGetString(data, "sessionid", "")

	// Traffic metrics
	event.SentBytes = fortinetGetInt64(data, "sentbyte", 0)
	event.ReceivedBytes = fortinetGetInt64(data, "rcvdbyte", 0)
	event.SentPackets = fortinetGetInt64(data, "sentpkt", 0)
	event.ReceivedPackets = fortinetGetInt64(data, "rcvdpkt", 0)
	event.Duration = fortinetGetInt(data, "duration", 0)

	// Policy
	event.Policy = fortinetGetString(data, "policyname", "")
	event.PolicyID = fortinetGetInt(data, "policyid", 0)
	event.PolicyType = fortinetGetString(data, "policytype", "")
	event.Profile = fortinetGetString(data, "profile", "")

	// Threat information
	event.ThreatLevel = fortinetGetString(data, "threatlevel", "")
	event.ThreatScore = fortinetGetInt(data, "threatweight", 0)
	event.ThreatType = fortinetGetString(data, "threattype", "")
	event.AttackName = fortinetGetString(data, "attack", "")
	event.AttackID = fortinetGetString(data, "attackid", "")
	event.Severity = fortinetGetString(data, "severity", "")
	event.Reference = fortinetGetString(data, "ref", "")

	// CVE parsing
	if cveStr := fortinetGetString(data, "cve", ""); cveStr != "" {
		event.CVE = strings.Split(cveStr, ",")
	}

	// UTM specific
	event.URL = fortinetGetString(data, "url", "")
	event.Hostname = fortinetGetString(data, "hostname", "")
	event.Category = fortinetGetString(data, "catdesc", "")
	event.CategoryID = fortinetGetInt(data, "cat", 0)
	event.VirusName = fortinetGetString(data, "virus", "")
	event.FileName = fortinetGetString(data, "filename", "")
	event.FileType = fortinetGetString(data, "filetype", "")
	event.FileSize = fortinetGetInt64(data, "filesize", 0)
	event.FileHash = fortinetGetString(data, "filehash", "")

	// VPN
	event.VPNTunnel = fortinetGetString(data, "tunnelid", "")
	event.VPNType = fortinetGetString(data, "vpntype", "")
	event.VPNUser = fortinetGetString(data, "vpnuser", "")

	// NAT
	event.NATSrcIP = fortinetGetString(data, "tranip", "")
	event.NATSrcPort = fortinetGetInt(data, "tranport", 0)
	event.NATDstIP = fortinetGetString(data, "transip", "")
	event.NATDstPort = fortinetGetInt(data, "transport", 0)

	// Message
	event.Message = fortinetGetString(data, "msg", "")
	event.EventMessage = fortinetGetString(data, "eventmsg", "")
	event.DeviceVDOM = fortinetGetString(data, "vd", "root")

	// Map MITRE ATT&CK
	event.MITRETactic, event.MITRETechnique = mapFortinetToMITRE(event)

	// Set severity based on log type and action
	if event.Severity == "" {
		event.Severity = determineFortinetSeverity(event)
	}

	// Store remaining fields as extra
	processedKeys := map[string]bool{
		"type": true, "subtype": true, "level": true, "eventtype": true, "action": true,
		"srcip": true, "srcport": true, "srcmac": true, "srcintf": true, "srccountry": true,
		"dstip": true, "dstport": true, "dstmac": true, "dstintf": true, "dstcountry": true,
		"proto": true, "service": true, "app": true, "appcat": true, "sessionid": true,
		"sentbyte": true, "rcvdbyte": true, "sentpkt": true, "rcvdpkt": true, "duration": true,
		"policyname": true, "policyid": true, "policytype": true, "profile": true,
		"threatlevel": true, "threatweight": true, "threattype": true, "attack": true,
		"attackid": true, "severity": true, "ref": true, "cve": true, "url": true,
		"hostname": true, "catdesc": true, "cat": true, "virus": true, "filename": true,
		"filetype": true, "filesize": true, "filehash": true, "tunnelid": true,
		"vpntype": true, "vpnuser": true, "tranip": true, "tranport": true,
		"transip": true, "transport": true, "msg": true, "eventmsg": true, "vd": true,
		"date": true, "time": true, "eventtime": true, "user": true, "srcuser": true, "status": true,
	}

	for k, v := range data {
		if !processedKeys[k] {
			event.Extra[k] = v
		}
	}

	return event
}

// =====================================
// ENRICHMENT
// =====================================

// enrichFortinetEvent enriches event with threat intelligence
func (s *APIServer) enrichFortinetEvent(event *FortinetNormalizedEvent) *FortinetNormalizedEvent {
	// Check source IP against threat intel
	if event.SrcIP != "" && !isFortinetPrivateIP(event.SrcIP) {
		if iocMatch := s.checkIOC(event.SrcIP, "ip"); iocMatch != nil {
			event.IOCMatch = true
			event.IOCType = "ip"
			event.IOCFeed = iocMatch.Feed
			event.Tags = append(event.Tags, "ioc-match", "malicious-ip")
		}
	}

	// Check destination IP
	if event.DstIP != "" && !isFortinetPrivateIP(event.DstIP) {
		if iocMatch := s.checkIOC(event.DstIP, "ip"); iocMatch != nil {
			event.IOCMatch = true
			event.IOCType = "ip"
			event.IOCFeed = iocMatch.Feed
			event.Tags = append(event.Tags, "ioc-match", "malicious-ip")
		}
	}

	// Check URL
	if event.URL != "" {
		if iocMatch := s.checkIOC(event.URL, "url"); iocMatch != nil {
			event.IOCMatch = true
			event.IOCType = "url"
			event.IOCFeed = iocMatch.Feed
			event.Tags = append(event.Tags, "ioc-match", "malicious-url")
		}
	}

	// Check file hash
	if event.FileHash != "" {
		if iocMatch := s.checkIOC(event.FileHash, "hash"); iocMatch != nil {
			event.IOCMatch = true
			event.IOCType = "hash"
			event.IOCFeed = iocMatch.Feed
			event.Tags = append(event.Tags, "ioc-match", "malicious-file")
		}
	}

	// Add tags based on log type
	event.Tags = append(event.Tags, "fortinet-"+event.LogType)
	if event.SubType != "" {
		event.Tags = append(event.Tags, "fortinet-"+event.LogType+"-"+event.SubType)
	}

	return event
}

// IOCMatch represents a match from threat intel
type IOCMatch struct {
	Type  string
	Value string
	Feed  string
	Score int
}

// checkIOC checks an indicator against threat intelligence
// TODO: Integrate with real IOC database/OpenSearch
func (s *APIServer) checkIOC(indicator, indicatorType string) *IOCMatch {
	// Query OpenSearch for IOC matches
	if s.opensearch == nil {
		return nil
	}

	// Build query to search for IOC
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{"term": map[string]interface{}{"type": indicatorType}},
					{"term": map[string]interface{}{"value.keyword": strings.ToLower(indicator)}},
					{"term": map[string]interface{}{"isActive": true}},
				},
			},
		},
		"size": 1,
	}

	queryJSON, _ := json.Marshal(query)

	req := opensearchapi.SearchRequest{
		Index: []string{"siem-iocs", "siem-threat-intel"},
		Body:  bytes.NewReader(queryJSON),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := req.Do(ctx, s.opensearch)
	if err != nil {
		log.Printf("IOC lookup error: %v", err)
		return nil
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil
	}

	hits, ok := result["hits"].(map[string]interface{})
	if !ok {
		return nil
	}

	total, ok := hits["total"].(map[string]interface{})
	if !ok || total["value"].(float64) == 0 {
		return nil
	}

	hitList, ok := hits["hits"].([]interface{})
	if !ok || len(hitList) == 0 {
		return nil
	}

	source, ok := hitList[0].(map[string]interface{})["_source"].(map[string]interface{})
	if !ok {
		return nil
	}

	return &IOCMatch{
		Type:  indicatorType,
		Value: indicator,
		Feed:  fortinetGetString(source, "source", "unknown"),
		Score: fortinetGetInt(source, "confidence", 50),
	}
}

// =====================================
// INDEXING
// =====================================

// indexFortinetEvent indexes event to OpenSearch
func (s *APIServer) indexFortinetEvent(event *FortinetNormalizedEvent) error {
	if s.opensearch == nil {
		return fmt.Errorf("OpenSearch client not initialized")
	}

	// Serialize event
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %v", err)
	}

	// Index to OpenSearch
	req := opensearchapi.IndexRequest{
		Index:      FortinetIndexName,
		DocumentID: event.ID,
		Body:       bytes.NewReader(eventJSON),
		Refresh:    "false",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := req.Do(ctx, s.opensearch)
	if err != nil {
		return fmt.Errorf("failed to index event: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("indexing error: %s", res.String())
	}

	return nil
}

// =====================================
// ALERT GENERATION
// =====================================

// shouldGenerateAlert determines if event warrants an alert
func shouldGenerateAlert(event *FortinetNormalizedEvent) bool {
	// IOC match always generates alert
	if event.IOCMatch {
		return true
	}

	// IPS/threat detections
	if event.LogType == FortiLogTypeIPS || event.LogType == FortiLogTypeAnomaly {
		return true
	}

	// Virus detections
	if event.VirusName != "" {
		return true
	}

	// High severity events
	if event.Severity == "critical" || event.Severity == "high" {
		return true
	}

	// Blocked high-risk actions
	if (event.Action == FortiActionBlock || event.Action == FortiActionDeny) &&
		event.ThreatScore >= 50 {
		return true
	}

	// Attack detections
	if event.AttackName != "" || event.AttackID != "" {
		return true
	}

	// DLP violations
	if event.LogType == FortiLogTypeDLP {
		return true
	}

	return false
}

// generateFortinetAlert creates an alert from a Fortinet event
func (s *APIServer) generateFortinetAlert(event *FortinetNormalizedEvent) error {
	alert := map[string]interface{}{
		"id":          uuid.New().String(),
		"timestamp":   time.Now(),
		"source":      "fortinet",
		"device_ip":   event.DeviceIP,
		"device_name": event.DeviceName,
		"log_type":    event.LogType,
		"sub_type":    event.SubType,
		"severity":    event.Severity,
		"action":      event.Action,
		"title":       generateAlertTitle(event),
		"description": generateAlertDescription(event),
		"src_ip":      event.SrcIP,
		"src_port":    event.SrcPort,
		"dst_ip":      event.DstIP,
		"dst_port":    event.DstPort,
		"protocol":    event.Protocol,
		"service":     event.Service,
		"application": event.Application,
		"attack_name": event.AttackName,
		"attack_id":   event.AttackID,
		"virus_name":  event.VirusName,
		"url":         event.URL,
		"ioc_match":   event.IOCMatch,
		"ioc_type":    event.IOCType,
		"ioc_feed":    event.IOCFeed,
		"mitre_tactic":    event.MITRETactic,
		"mitre_technique": event.MITRETechnique,
		"tags":        event.Tags,
		"status":      "new",
		"event_id":    event.ID,
		"raw_log":     event.RawLog,
	}

	// Index alert
	alertJSON, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	if s.opensearch == nil {
		return fmt.Errorf("OpenSearch client not initialized")
	}

	req := opensearchapi.IndexRequest{
		Index:      FortinetAlertsIndexName,
		DocumentID: alert["id"].(string),
		Body:       bytes.NewReader(alertJSON),
		Refresh:    "true",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := req.Do(ctx, s.opensearch)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// Also create correlation event
	go s.sendToAlertCorrelation(event)

	return nil
}

// sendToAlertCorrelation sends event to correlation engine
func (s *APIServer) sendToAlertCorrelation(event *FortinetNormalizedEvent) {
	// Create correlation-compatible event
	correlationEvent := map[string]interface{}{
		"source":      "fortinet",
		"source_type": event.LogType,
		"timestamp":   event.Timestamp,
		"src_ip":      event.SrcIP,
		"dst_ip":      event.DstIP,
		"severity":    event.Severity,
		"action":      event.Action,
		"attack_type": event.AttackName,
		"tags":        event.Tags,
	}

	// Send to correlation engine (implementation depends on your correlation engine)
	log.Printf("Sending Fortinet event to correlation: %v", correlationEvent)
}

// =====================================
// API HANDLERS
// =====================================

// handleListFortinetConfigs lists webhook configurations
func (s *APIServer) handleListFortinetConfigs(c *gin.Context) {
	fortinetConfigMutex.RLock()
	defer fortinetConfigMutex.RUnlock()

	configs := make([]*FortinetWebhookConfig, 0, len(fortinetConfigs))
	for _, config := range fortinetConfigs {
		// Hide sensitive data
		configCopy := *config
		configCopy.APIKey = ""
		configCopy.SecretKey = ""
		configs = append(configs, &configCopy)
	}

	c.JSON(http.StatusOK, gin.H{
		"configs": configs,
		"total":   len(configs),
	})
}

// handleCreateFortinetConfig creates a new webhook configuration
func (s *APIServer) handleCreateFortinetConfig(c *gin.Context) {
	var config FortinetWebhookConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config.ID = uuid.New().String()
	config.CreatedAt = time.Now()
	config.EventCount = 0

	fortinetConfigMutex.Lock()
	fortinetConfigs[config.ID] = &config
	fortinetConfigMutex.Unlock()

	// Generate webhook URL
	webhookURL := fmt.Sprintf("/api/v1/fortinet/webhook?config_id=%s", config.ID)

	c.JSON(http.StatusCreated, gin.H{
		"config":      config,
		"webhook_url": webhookURL,
	})
}

// handleUpdateFortinetConfig updates a webhook configuration
func (s *APIServer) handleUpdateFortinetConfig(c *gin.Context) {
	id := c.Param("id")

	fortinetConfigMutex.Lock()
	defer fortinetConfigMutex.Unlock()

	config, exists := fortinetConfigs[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Configuration not found"})
		return
	}

	var updates FortinetWebhookConfig
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields
	if updates.Name != "" {
		config.Name = updates.Name
	}
	if updates.DeviceIP != "" {
		config.DeviceIP = updates.DeviceIP
	}
	if updates.DeviceName != "" {
		config.DeviceName = updates.DeviceName
	}
	if updates.VDOM != "" {
		config.VDOM = updates.VDOM
	}
	if updates.APIKey != "" {
		config.APIKey = updates.APIKey
	}
	if updates.SecretKey != "" {
		config.SecretKey = updates.SecretKey
	}
	if len(updates.LogTypes) > 0 {
		config.LogTypes = updates.LogTypes
	}
	config.Enabled = updates.Enabled

	c.JSON(http.StatusOK, config)
}

// handleDeleteFortinetConfig deletes a webhook configuration
func (s *APIServer) handleDeleteFortinetConfig(c *gin.Context) {
	id := c.Param("id")

	fortinetConfigMutex.Lock()
	defer fortinetConfigMutex.Unlock()

	if id == "default" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete default configuration"})
		return
	}

	if _, exists := fortinetConfigs[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Configuration not found"})
		return
	}

	delete(fortinetConfigs, id)
	c.JSON(http.StatusOK, gin.H{"message": "Configuration deleted"})
}

// handleGetFortinetStats returns webhook statistics
func (s *APIServer) handleGetFortinetStats(c *gin.Context) {
	fortinetStatsMutex.RLock()
	stats := *fortinetStats
	fortinetStatsMutex.RUnlock()

	// Count active devices
	fortinetConfigMutex.RLock()
	activeDevices := 0
	for _, config := range fortinetConfigs {
		if config.Enabled && config.LastEventAt != nil {
			if time.Since(*config.LastEventAt) < 1*time.Hour {
				activeDevices++
			}
		}
	}
	fortinetConfigMutex.RUnlock()
	stats.ActiveDevices = activeDevices

	c.JSON(http.StatusOK, stats)
}

// handleGetFortinetEvents queries Fortinet events
func (s *APIServer) handleGetFortinetEvents(c *gin.Context) {
	// Query parameters
	logType := c.Query("type")
	srcIP := c.Query("src_ip")
	dstIP := c.Query("dst_ip")
	action := c.Query("action")
	severity := c.Query("severity")
	from := c.Query("from")
	to := c.Query("to")
	limit := 100
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 1000 {
		limit = l
	}

	// Build query
	must := []map[string]interface{}{}

	if logType != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"log_type": logType},
		})
	}
	if srcIP != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"src_ip": srcIP},
		})
	}
	if dstIP != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"dst_ip": dstIP},
		})
	}
	if action != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"action": action},
		})
	}
	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"severity": severity},
		})
	}

	// Time range
	timeRange := map[string]interface{}{}
	if from != "" {
		timeRange["gte"] = from
	}
	if to != "" {
		timeRange["lte"] = to
	}
	if len(timeRange) > 0 {
		must = append(must, map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": timeRange,
			},
		})
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"sort": []map[string]interface{}{
			{"timestamp": map[string]string{"order": "desc"}},
		},
		"size": limit,
	}

	// Execute search
	events, total, err := s.searchFortinetIndex(FortinetIndexName, query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  total,
	})
}

// handleGetFortinetAlerts queries Fortinet alerts
func (s *APIServer) handleGetFortinetAlerts(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")
	limit := 100
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 1000 {
		limit = l
	}

	must := []map[string]interface{}{}
	if status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"status": status},
		})
	}
	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"severity": severity},
		})
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"sort": []map[string]interface{}{
			{"timestamp": map[string]string{"order": "desc"}},
		},
		"size": limit,
	}

	alerts, total, err := s.searchFortinetIndex(FortinetAlertsIndexName, query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"total":  total,
	})
}

// handleGetFortinetDashboard returns dashboard data
func (s *APIServer) handleGetFortinetDashboard(c *gin.Context) {
	fortinetStatsMutex.RLock()
	stats := *fortinetStats
	fortinetStatsMutex.RUnlock()

	// Get recent events count
	recentQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"gte": "now-24h",
				},
			},
		},
		"size": 0,
	}
	_, events24h, _ := s.searchFortinetIndex(FortinetIndexName, recentQuery)

	// Get alerts count
	alertsQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{"term": map[string]interface{}{"status": "new"}},
				},
			},
		},
		"size": 0,
	}
	_, newAlerts, _ := s.searchFortinetIndex(FortinetAlertsIndexName, alertsQuery)

	// Get IOC matches
	iocQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{"term": map[string]interface{}{"ioc_match": true}},
					{"range": map[string]interface{}{
						"timestamp": map[string]interface{}{"gte": "now-24h"},
					}},
				},
			},
		},
		"size": 0,
	}
	_, iocMatches24h, _ := s.searchFortinetIndex(FortinetIndexName, iocQuery)

	c.JSON(http.StatusOK, gin.H{
		"summary": gin.H{
			"total_events":      stats.TotalEventsReceived,
			"events_24h":        events24h,
			"new_alerts":        newAlerts,
			"ioc_matches_24h":   iocMatches24h,
			"threat_detections": stats.ThreatDetections,
			"active_devices":    stats.ActiveDevices,
			"last_event_time":   stats.LastEventTime,
		},
		"events_by_type":     stats.EventsByType,
		"events_by_action":   stats.EventsByAction,
		"events_by_severity": stats.EventsBySeverity,
		"top_source_ips":     stats.TopSourceIPs,
		"top_dest_ips":       stats.TopDestIPs,
		"top_blocked_ips":    stats.TopBlockedIPs,
		"top_applications":   stats.TopApplications,
	})
}

// searchFortinetIndex executes a search query
func (s *APIServer) searchFortinetIndex(index string, query map[string]interface{}) ([]map[string]interface{}, int64, error) {
	if s.opensearch == nil {
		return nil, 0, fmt.Errorf("OpenSearch client not initialized")
	}

	queryJSON, _ := json.Marshal(query)

	req := opensearchapi.SearchRequest{
		Index: []string{index},
		Body:  bytes.NewReader(queryJSON),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := req.Do(ctx, s.opensearch)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, 0, fmt.Errorf("search error: %s", res.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, err
	}

	hits := result["hits"].(map[string]interface{})
	total := int64(hits["total"].(map[string]interface{})["value"].(float64))

	documents := []map[string]interface{}{}
	for _, hit := range hits["hits"].([]interface{}) {
		doc := hit.(map[string]interface{})["_source"].(map[string]interface{})
		doc["_id"] = hit.(map[string]interface{})["_id"]
		documents = append(documents, doc)
	}

	return documents, total, nil
}

// =====================================
// HELPERS
// =====================================

func validateHMACSignature(body []byte, signature, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

func fortinetGetString(data map[string]interface{}, key, defaultVal string) string {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case string:
			return v
		case float64:
			return fmt.Sprintf("%.0f", v)
		case int:
			return strconv.Itoa(v)
		}
	}
	return defaultVal
}

func fortinetGetInt(data map[string]interface{}, key string, defaultVal int) int {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return defaultVal
}

func fortinetGetInt64(data map[string]interface{}, key string, defaultVal int64) int64 {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case float64:
			return int64(v)
		case int64:
			return v
		case int:
			return int64(v)
		case string:
			if i, err := strconv.ParseInt(v, 10, 64); err == nil {
				return i
			}
		}
	}
	return defaultVal
}

func fortinetContainsString(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func isFortinetPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.",
		"127.",
		"169.254.",
	}
	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

func mapFortinetToMITRE(event *FortinetNormalizedEvent) (tactic, technique string) {
	// Map FortiGate log types and attack patterns to MITRE ATT&CK
	switch event.LogType {
	case FortiLogTypeIPS:
		tactic = "Initial Access"
		technique = "T1190" // Exploit Public-Facing Application
		if strings.Contains(strings.ToLower(event.AttackName), "bruteforce") {
			tactic = "Credential Access"
			technique = "T1110" // Brute Force
		}
		if strings.Contains(strings.ToLower(event.AttackName), "sql") {
			technique = "T1190" // SQL Injection is under Exploit Public-Facing Application
		}
	case FortiLogTypeVirus, FortiLogTypeAntiVirus:
		tactic = "Execution"
		technique = "T1204" // User Execution
	case FortiLogTypeWebfilter:
		tactic = "Command and Control"
		technique = "T1071" // Application Layer Protocol
		if strings.Contains(event.Category, "malware") {
			tactic = "Initial Access"
			technique = "T1566" // Phishing
		}
	case FortiLogTypeDLP:
		tactic = "Exfiltration"
		technique = "T1041" // Exfiltration Over C2 Channel
	case FortiLogTypeAppCtrl:
		tactic = "Command and Control"
		technique = "T1071" // Application Layer Protocol
	case FortiLogTypeAnomaly:
		tactic = "Discovery"
		technique = "T1046" // Network Service Discovery
		if strings.Contains(strings.ToLower(event.Message), "scan") {
			technique = "T1046" // Network Service Scanning
		}
	case FortiLogTypeDNS:
		if event.Action == FortiActionBlock {
			tactic = "Command and Control"
			technique = "T1071.004" // Application Layer Protocol: DNS
		}
	default:
		if event.Action == FortiActionDeny || event.Action == FortiActionBlock {
			tactic = "Lateral Movement"
			technique = "T1021" // Remote Services
		}
	}
	return
}

func determineFortinetSeverity(event *FortinetNormalizedEvent) string {
	// Critical: virus, high-risk IPS, DLP
	if event.VirusName != "" || event.ThreatScore >= 80 {
		return "critical"
	}
	if event.LogType == FortiLogTypeDLP {
		return "high"
	}
	if event.LogType == FortiLogTypeIPS && event.ThreatScore >= 50 {
		return "high"
	}
	if event.Action == FortiActionBlock || event.Action == FortiActionDeny {
		if event.LogType == FortiLogTypeIPS || event.LogType == FortiLogTypeAnomaly {
			return "medium"
		}
	}
	if event.ThreatScore >= 30 {
		return "medium"
	}
	if event.Level == "warning" {
		return "low"
	}
	return "info"
}

func generateAlertTitle(event *FortinetNormalizedEvent) string {
	switch {
	case event.VirusName != "":
		return fmt.Sprintf("Virus Detected: %s", event.VirusName)
	case event.AttackName != "":
		return fmt.Sprintf("Attack Detected: %s", event.AttackName)
	case event.IOCMatch:
		return fmt.Sprintf("IOC Match: %s %s", event.IOCType, event.SrcIP)
	case event.LogType == FortiLogTypeDLP:
		return fmt.Sprintf("DLP Violation: %s", event.FileName)
	case event.LogType == FortiLogTypeIPS:
		return fmt.Sprintf("IPS Alert from %s to %s:%d", event.SrcIP, event.DstIP, event.DstPort)
	case event.LogType == FortiLogTypeAnomaly:
		return fmt.Sprintf("Network Anomaly: %s", event.Message)
	default:
		return fmt.Sprintf("Fortinet %s Alert: %s", strings.ToUpper(event.LogType), event.Action)
	}
}

func generateAlertDescription(event *FortinetNormalizedEvent) string {
	parts := []string{}

	if event.SrcIP != "" {
		parts = append(parts, fmt.Sprintf("Source: %s:%d", event.SrcIP, event.SrcPort))
	}
	if event.DstIP != "" {
		parts = append(parts, fmt.Sprintf("Destination: %s:%d", event.DstIP, event.DstPort))
	}
	if event.Application != "" {
		parts = append(parts, fmt.Sprintf("Application: %s", event.Application))
	}
	if event.Policy != "" {
		parts = append(parts, fmt.Sprintf("Policy: %s", event.Policy))
	}
	if event.Message != "" {
		parts = append(parts, fmt.Sprintf("Message: %s", event.Message))
	}

	return strings.Join(parts, " | ")
}

func updateFortinetStats(events []*FortinetNormalizedEvent, processed, alerts, iocMatches int) {
	fortinetStatsMutex.Lock()
	defer fortinetStatsMutex.Unlock()

	fortinetStats.TotalEventsReceived += int64(processed)
	fortinetStats.IOCMatches += int64(iocMatches)

	now := time.Now()
	fortinetStats.LastEventTime = &now

	for _, event := range events {
		// By type
		fortinetStats.EventsByType[event.LogType]++

		// By action
		if event.Action != "" {
			fortinetStats.EventsByAction[event.Action]++
		}

		// By severity
		if event.Severity != "" {
			fortinetStats.EventsBySeverity[event.Severity]++
		}

		// Count threat detections
		if event.AttackName != "" || event.VirusName != "" || event.LogType == FortiLogTypeIPS {
			fortinetStats.ThreatDetections++
		}
	}
}

// EnsureFortinetIndices creates OpenSearch indices for Fortinet logs
func (s *APIServer) EnsureFortinetIndices() error {
	if s.opensearch == nil {
		return fmt.Errorf("OpenSearch client not initialized")
	}

	indices := map[string]string{
		FortinetIndexName: `{
			"settings": {
				"number_of_shards": 3,
				"number_of_replicas": 1,
				"index.mapping.total_fields.limit": 2000
			},
			"mappings": {
				"properties": {
					"id": {"type": "keyword"},
					"timestamp": {"type": "date"},
					"receive_time": {"type": "date"},
					"device_ip": {"type": "ip"},
					"device_name": {"type": "keyword"},
					"device_vdom": {"type": "keyword"},
					"log_type": {"type": "keyword"},
					"sub_type": {"type": "keyword"},
					"level": {"type": "keyword"},
					"event_type": {"type": "keyword"},
					"action": {"type": "keyword"},
					"src_ip": {"type": "ip"},
					"src_port": {"type": "integer"},
					"src_mac": {"type": "keyword"},
					"src_interface": {"type": "keyword"},
					"src_country": {"type": "keyword"},
					"src_user": {"type": "keyword"},
					"dst_ip": {"type": "ip"},
					"dst_port": {"type": "integer"},
					"dst_mac": {"type": "keyword"},
					"dst_interface": {"type": "keyword"},
					"dst_country": {"type": "keyword"},
					"protocol": {"type": "keyword"},
					"protocol_number": {"type": "integer"},
					"service": {"type": "keyword"},
					"application": {"type": "keyword"},
					"app_category": {"type": "keyword"},
					"session_id": {"type": "keyword"},
					"sent_bytes": {"type": "long"},
					"received_bytes": {"type": "long"},
					"sent_packets": {"type": "long"},
					"received_packets": {"type": "long"},
					"duration": {"type": "integer"},
					"policy": {"type": "keyword"},
					"policy_id": {"type": "integer"},
					"policy_type": {"type": "keyword"},
					"profile": {"type": "keyword"},
					"threat_level": {"type": "keyword"},
					"threat_score": {"type": "integer"},
					"threat_type": {"type": "keyword"},
					"attack_name": {"type": "keyword"},
					"attack_id": {"type": "keyword"},
					"cve": {"type": "keyword"},
					"severity": {"type": "keyword"},
					"reference": {"type": "text"},
					"url": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
					"hostname": {"type": "keyword"},
					"category": {"type": "keyword"},
					"category_id": {"type": "integer"},
					"virus_name": {"type": "keyword"},
					"file_name": {"type": "keyword"},
					"file_type": {"type": "keyword"},
					"file_size": {"type": "long"},
					"file_hash": {"type": "keyword"},
					"vpn_tunnel": {"type": "keyword"},
					"vpn_type": {"type": "keyword"},
					"vpn_user": {"type": "keyword"},
					"nat_src_ip": {"type": "ip"},
					"nat_src_port": {"type": "integer"},
					"nat_dst_ip": {"type": "ip"},
					"nat_dst_port": {"type": "integer"},
					"message": {"type": "text"},
					"event_message": {"type": "text"},
					"raw_log": {"type": "text"},
					"tags": {"type": "keyword"},
					"mitre_tactic": {"type": "keyword"},
					"mitre_technique": {"type": "keyword"},
					"ioc_match": {"type": "boolean"},
					"ioc_type": {"type": "keyword"},
					"ioc_feed": {"type": "keyword"}
				}
			}
		}`,
		FortinetAlertsIndexName: `{
			"settings": {
				"number_of_shards": 1,
				"number_of_replicas": 1
			},
			"mappings": {
				"properties": {
					"id": {"type": "keyword"},
					"timestamp": {"type": "date"},
					"source": {"type": "keyword"},
					"device_ip": {"type": "ip"},
					"device_name": {"type": "keyword"},
					"log_type": {"type": "keyword"},
					"sub_type": {"type": "keyword"},
					"severity": {"type": "keyword"},
					"action": {"type": "keyword"},
					"title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
					"description": {"type": "text"},
					"src_ip": {"type": "ip"},
					"src_port": {"type": "integer"},
					"dst_ip": {"type": "ip"},
					"dst_port": {"type": "integer"},
					"protocol": {"type": "keyword"},
					"service": {"type": "keyword"},
					"application": {"type": "keyword"},
					"attack_name": {"type": "keyword"},
					"attack_id": {"type": "keyword"},
					"virus_name": {"type": "keyword"},
					"url": {"type": "text"},
					"ioc_match": {"type": "boolean"},
					"ioc_type": {"type": "keyword"},
					"ioc_feed": {"type": "keyword"},
					"mitre_tactic": {"type": "keyword"},
					"mitre_technique": {"type": "keyword"},
					"tags": {"type": "keyword"},
					"status": {"type": "keyword"},
					"event_id": {"type": "keyword"},
					"raw_log": {"type": "text"}
				}
			}
		}`,
	}

	for indexName, mapping := range indices {
		// Check if index exists
		res, err := s.opensearch.Indices.Exists([]string{indexName})
		if err != nil {
			return fmt.Errorf("failed to check index %s: %v", indexName, err)
		}
		res.Body.Close()

		if res.StatusCode == 404 {
			// Create index
			res, err := s.opensearch.Indices.Create(
				indexName,
				s.opensearch.Indices.Create.WithBody(strings.NewReader(mapping)),
			)
			if err != nil {
				return fmt.Errorf("failed to create index %s: %v", indexName, err)
			}
			res.Body.Close()

			if res.IsError() {
				return fmt.Errorf("error creating index %s: %s", indexName, res.String())
			}
			log.Printf("✅ Created OpenSearch index: %s", indexName)
		} else {
			log.Printf("✅ Index %s already exists", indexName)
		}
	}

	return nil
}

