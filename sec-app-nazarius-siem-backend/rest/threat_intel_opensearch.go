package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
)

// OpenSearch index names for Threat Intelligence
const (
	iocsIndex         = "siem-iocs"
	threatFeedsIndex  = "siem-threat-feeds"
	campaignsIndex    = "siem-campaigns"
	correlationsIndex = "siem-correlations"
	threatActorsIndex = "siem-threat-actors"
)

// IOCOpenSearch represents an IOC stored in OpenSearch
type IOCOpenSearch struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // ip, domain, hash, url, cve, email
	Value       string                 `json:"value"`
	Threat      string                 `json:"threat"`     // malware, botnet, phishing, c2, apt, etc.
	Severity    string                 `json:"severity"`   // critical, high, medium, low
	Confidence  int                    `json:"confidence"` // 0-100
	Source      string                 `json:"source"`     // otx, abuseipdb, virustotal, manual, internal
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	IsActive    bool                   `json:"is_active"`
	EventCount  int                    `json:"event_count"` // matches with internal events
	Metadata    map[string]interface{} `json:"metadata"`
	Country     string                 `json:"country,omitempty"`
	ASN         string                 `json:"asn,omitempty"`
	CreatedBy   string                 `json:"created_by"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
}

// ThreatFeedOpenSearch represents a threat feed configuration
type ThreatFeedOpenSearch struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Type        string            `json:"type"`      // public, commercial, custom
	FeedType    string            `json:"feed_type"` // stix, taxii, csv, json
	URL         string            `json:"url"`
	Enabled     bool              `json:"enabled"`
	UpdateFreq  int               `json:"update_freq"` // minutes
	LastUpdate  time.Time         `json:"last_update"`
	NextUpdate  time.Time         `json:"next_update"`
	IOCCount    int               `json:"ioc_count"`
	Reliability string            `json:"reliability"` // high, medium, low
	Status      string            `json:"status"`      // active, error, disabled
	LastError   string            `json:"last_error,omitempty"`
	Config      map[string]string `json:"config,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ThreatIntelStatsOS statistics from OpenSearch
type ThreatIntelStatsOS struct {
	TotalIOCs      int             `json:"totalIOCs"`
	ActiveIOCs     int             `json:"activeIOCs"`
	IOCsByType     map[string]int  `json:"iocsByType"`
	IOCsBySeverity map[string]int  `json:"iocsBySeverity"`
	TopThreats     []ThreatSummary `json:"topThreats"`
	RecentIOCs     []IOCOpenSearch `json:"recentIOCs"`
	EventsEnriched int             `json:"eventsEnriched"`
	FeedsActive    int             `json:"feedsActive"`
	TopCountries   []CountryThreat `json:"topCountries"`
}

// CampaignOpenSearch represents a threat campaign stored in OpenSearch
type CampaignOpenSearch struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Status          string    `json:"status"`   // active, dormant, ended
	Severity        string    `json:"severity"` // critical, high, medium, low
	FirstDetected   time.Time `json:"first_detected"`
	LastActivity    time.Time `json:"last_activity"`
	ThreatActors    []string  `json:"threat_actors"`
	TargetSectors   []string  `json:"target_sectors"`
	TargetCountries []string  `json:"target_countries"`
	AttackVectors   []string  `json:"attack_vectors"`
	Objectives      []string  `json:"objectives"`
	TTPs            []string  `json:"ttps"` // MITRE ATT&CK IDs
	IOCsIdentified  int       `json:"iocs_identified"`
	VictimsAffected int       `json:"victims_affected"`
	MITRETactics    []string  `json:"mitre_tactics"`
	Recommendations []string  `json:"recommendations"`
	RelatedIOCs     []string  `json:"related_iocs"` // IOC IDs linked to this campaign
	Tags            []string  `json:"tags"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// CorrelationOpenSearch represents a threat correlation stored in OpenSearch
type CorrelationOpenSearch struct {
	ID              string     `json:"id"`
	Type            string     `json:"type"` // ioc_match, pattern_match, behavior_match, campaign_match
	Severity        string     `json:"severity"`
	Confidence      float64    `json:"confidence"` // 0-100
	DetectedAt      time.Time  `json:"detected_at"`
	SourceEventID   string     `json:"source_event_id"`
	SourceEventType string     `json:"source_event_type"`
	MatchedIOCID    string     `json:"matched_ioc_id,omitempty"`
	MatchedIOCValue string     `json:"matched_ioc_value,omitempty"`
	ThreatActor     string     `json:"threat_actor,omitempty"`
	Campaign        string     `json:"campaign,omitempty"`
	CampaignID      string     `json:"campaign_id,omitempty"`
	MITRETechniques []string   `json:"mitre_techniques"`
	AffectedAssets  []string   `json:"affected_assets"`
	Context         string     `json:"context"`
	Recommendations []string   `json:"recommendations"`
	Status          string     `json:"status"` // new, investigating, resolved, false_positive
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy      string     `json:"resolved_by,omitempty"`
	Resolution      string     `json:"resolution,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ThreatActorOpenSearch represents a threat actor stored in OpenSearch
type ThreatActorOpenSearch struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Aliases         []string  `json:"aliases"`
	Type            string    `json:"type"`           // apt, cybercrime, hacktivist, nation_state
	Sophistication  string    `json:"sophistication"` // advanced, intermediate, basic
	Origin          string    `json:"origin"`
	Description     string    `json:"description"`
	FirstSeen       time.Time `json:"first_seen"`
	LastActivity    time.Time `json:"last_activity"`
	TargetSectors   []string  `json:"target_sectors"`
	TargetCountries []string  `json:"target_countries"`
	TTPs            []string  `json:"ttps"` // MITRE ATT&CK techniques
	Tools           []string  `json:"tools"`
	Malware         []string  `json:"malware"`
	Campaigns       []string  `json:"campaigns"`
	KnownIOCs       int       `json:"known_iocs"`
	ThreatScore     float64   `json:"threat_score"` // 0-100
	Tags            []string  `json:"tags"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// EnsureIOCsIndex creates the IOCs index if it doesn't exist
func (s *APIServer) EnsureIOCsIndex() {
	if s.opensearch == nil {
		log.Println("⚠️ OpenSearch not available, Threat Intel will use mock data")
		return
	}

	mapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0,
			"analysis": {
				"analyzer": {
					"ioc_analyzer": {
						"type": "custom",
						"tokenizer": "standard",
						"filter": ["lowercase"]
					}
				}
			}
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"type": { "type": "keyword" },
				"value": { "type": "keyword", "copy_to": "value_search" },
				"value_search": { "type": "text", "analyzer": "ioc_analyzer" },
				"threat": { "type": "keyword" },
				"severity": { "type": "keyword" },
				"confidence": { "type": "integer" },
				"source": { "type": "keyword" },
				"description": { "type": "text" },
				"tags": { "type": "keyword" },
				"first_seen": { "type": "date" },
				"last_seen": { "type": "date" },
				"is_active": { "type": "boolean" },
				"event_count": { "type": "integer" },
				"metadata": { "type": "object", "enabled": true },
				"country": { "type": "keyword" },
				"asn": { "type": "keyword" },
				"created_by": { "type": "keyword" },
				"created_at": { "type": "date" },
				"updated_at": { "type": "date" },
				"expires_at": { "type": "date" }
			}
		}
	}`

	res, err := s.opensearch.Indices.Exists([]string{iocsIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			iocsIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(mapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", iocsIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", iocsIndex)
			// Seed initial IOCs from threat feeds
			s.seedInitialIOCs()
		}
	}

	// Create threat feeds index
	feedsMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"provider": { "type": "keyword" },
				"type": { "type": "keyword" },
				"feed_type": { "type": "keyword" },
				"url": { "type": "keyword" },
				"enabled": { "type": "boolean" },
				"update_freq": { "type": "integer" },
				"last_update": { "type": "date" },
				"next_update": { "type": "date" },
				"ioc_count": { "type": "integer" },
				"reliability": { "type": "keyword" },
				"status": { "type": "keyword" },
				"last_error": { "type": "text" },
				"config": { "type": "object" },
				"created_at": { "type": "date" },
				"updated_at": { "type": "date" }
			}
		}
	}`

	res, err = s.opensearch.Indices.Exists([]string{threatFeedsIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			threatFeedsIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(feedsMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", threatFeedsIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", threatFeedsIndex)
			s.seedInitialFeeds()
		}
	}

	// Create campaigns index
	campaignsMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"description": { "type": "text" },
				"status": { "type": "keyword" },
				"severity": { "type": "keyword" },
				"first_detected": { "type": "date" },
				"last_activity": { "type": "date" },
				"threat_actors": { "type": "keyword" },
				"target_sectors": { "type": "keyword" },
				"target_countries": { "type": "keyword" },
				"attack_vectors": { "type": "keyword" },
				"objectives": { "type": "keyword" },
				"ttps": { "type": "keyword" },
				"iocs_identified": { "type": "integer" },
				"victims_affected": { "type": "integer" },
				"mitre_tactics": { "type": "keyword" },
				"recommendations": { "type": "text" },
				"related_iocs": { "type": "keyword" },
				"tags": { "type": "keyword" },
				"created_by": { "type": "keyword" },
				"created_at": { "type": "date" },
				"updated_at": { "type": "date" }
			}
		}
	}`

	res, err = s.opensearch.Indices.Exists([]string{campaignsIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			campaignsIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(campaignsMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", campaignsIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", campaignsIndex)
		}
	}

	// Create correlations index
	correlationsMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"type": { "type": "keyword" },
				"severity": { "type": "keyword" },
				"confidence": { "type": "float" },
				"detected_at": { "type": "date" },
				"source_event_id": { "type": "keyword" },
				"source_event_type": { "type": "keyword" },
				"matched_ioc_id": { "type": "keyword" },
				"matched_ioc_value": { "type": "keyword" },
				"threat_actor": { "type": "keyword" },
				"campaign": { "type": "keyword" },
				"campaign_id": { "type": "keyword" },
				"mitre_techniques": { "type": "keyword" },
				"affected_assets": { "type": "keyword" },
				"context": { "type": "text" },
				"recommendations": { "type": "text" },
				"status": { "type": "keyword" },
				"resolved_at": { "type": "date" },
				"resolved_by": { "type": "keyword" },
				"resolution": { "type": "text" },
				"created_at": { "type": "date" },
				"updated_at": { "type": "date" }
			}
		}
	}`

	res, err = s.opensearch.Indices.Exists([]string{correlationsIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			correlationsIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(correlationsMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", correlationsIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", correlationsIndex)
		}
	}

	// Create threat actors index
	actorsMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"aliases": { "type": "keyword" },
				"type": { "type": "keyword" },
				"sophistication": { "type": "keyword" },
				"origin": { "type": "keyword" },
				"description": { "type": "text" },
				"first_seen": { "type": "date" },
				"last_activity": { "type": "date" },
				"target_sectors": { "type": "keyword" },
				"target_countries": { "type": "keyword" },
				"ttps": { "type": "keyword" },
				"tools": { "type": "keyword" },
				"malware": { "type": "keyword" },
				"campaigns": { "type": "keyword" },
				"known_iocs": { "type": "integer" },
				"threat_score": { "type": "float" },
				"tags": { "type": "keyword" },
				"created_by": { "type": "keyword" },
				"created_at": { "type": "date" },
				"updated_at": { "type": "date" }
			}
		}
	}`

	res, err = s.opensearch.Indices.Exists([]string{threatActorsIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			threatActorsIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(actorsMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", threatActorsIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", threatActorsIndex)
		}
	}

	log.Println("✅ Threat Intelligence indices initialized")
}

// seedInitialIOCs seeds the index with initial IOC data
func (s *APIServer) seedInitialIOCs() {
	if s.opensearch == nil {
		return
	}

	now := time.Now()

	// Initial IOCs from common threat sources
	initialIOCs := []IOCOpenSearch{
		{
			ID:          uuid.New().String(),
			Type:        "ip",
			Value:       "45.142.212.61",
			Threat:      "botnet",
			Severity:    "critical",
			Confidence:  95,
			Source:      "abuseipdb",
			Description: "Mirai botnet C2 server - Known malicious infrastructure",
			Tags:        []string{"botnet", "mirai", "ddos", "c2"},
			FirstSeen:   now.Add(-30 * 24 * time.Hour),
			LastSeen:    now.Add(-2 * time.Hour),
			IsActive:    true,
			EventCount:  47,
			Metadata:    map[string]interface{}{"reports": 247, "attack_type": "ddos"},
			Country:     "RU",
			ASN:         "AS12345",
			CreatedBy:   "system",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Type:        "ip",
			Value:       "185.220.101.42",
			Threat:      "c2",
			Severity:    "critical",
			Confidence:  92,
			Source:      "otx",
			Description: "Cobalt Strike C2 infrastructure - Active threat",
			Tags:        []string{"c2", "cobalt-strike", "apt29", "nation-state"},
			FirstSeen:   now.Add(-45 * 24 * time.Hour),
			LastSeen:    now.Add(-1 * time.Hour),
			IsActive:    true,
			EventCount:  34,
			Metadata:    map[string]interface{}{"beacon_type": "https"},
			Country:     "NL",
			ASN:         "AS16276",
			CreatedBy:   "system",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Type:        "domain",
			Value:       "paypal-secure-login.xyz",
			Threat:      "phishing",
			Severity:    "high",
			Confidence:  94,
			Source:      "phishtank",
			Description: "PayPal credential phishing campaign",
			Tags:        []string{"phishing", "credential-theft", "paypal", "financial"},
			FirstSeen:   now.Add(-10 * 24 * time.Hour),
			LastSeen:    now.Add(-3 * time.Hour),
			IsActive:    true,
			EventCount:  67,
			Metadata:    map[string]interface{}{"target": "financial", "registrar": "namecheap"},
			CreatedBy:   "system",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Type:        "hash",
			Value:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Threat:      "malware",
			Severity:    "critical",
			Confidence:  98,
			Source:      "virustotal",
			Description: "Emotet malware variant - Banking trojan",
			Tags:        []string{"malware", "emotet", "trojan", "banking"},
			FirstSeen:   now.Add(-45 * 24 * time.Hour),
			LastSeen:    now.Add(-1 * 24 * time.Hour),
			IsActive:    true,
			EventCount:  12,
			Metadata:    map[string]interface{}{"malware_family": "Emotet", "file_type": "PE32", "vt_detections": 58},
			CreatedBy:   "system",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Type:        "hash",
			Value:       "5d41402abc4b2a76b9719d911017c592",
			Threat:      "ransomware",
			Severity:    "critical",
			Confidence:  99,
			Source:      "virustotal",
			Description: "LockBit 3.0 ransomware - Critical threat",
			Tags:        []string{"ransomware", "lockbit", "encryption", "extortion"},
			FirstSeen:   now.Add(-60 * 24 * time.Hour),
			LastSeen:    now.Add(-2 * 24 * time.Hour),
			IsActive:    true,
			EventCount:  5,
			Metadata:    map[string]interface{}{"malware_family": "LockBit", "version": "3.0", "ransom_note": true},
			CreatedBy:   "system",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Type:        "cve",
			Value:       "CVE-2024-1234",
			Threat:      "exploit",
			Severity:    "critical",
			Confidence:  100,
			Source:      "nvd",
			Description: "Critical RCE vulnerability - Active exploitation",
			Tags:        []string{"exploit", "rce", "critical-vuln", "actively-exploited"},
			FirstSeen:   now.Add(-180 * 24 * time.Hour),
			LastSeen:    now.Add(-1 * time.Hour),
			IsActive:    true,
			EventCount:  456,
			Metadata:    map[string]interface{}{"cvss": "10.0", "exploited_in_wild": true, "patch_available": true},
			CreatedBy:   "system",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Type:        "ip",
			Value:       "103.253.145.28",
			Threat:      "apt",
			Severity:    "critical",
			Confidence:  96,
			Source:      "mandiant",
			Description: "APT28 (Fancy Bear) infrastructure - State-sponsored",
			Tags:        []string{"apt", "apt28", "fancy-bear", "russia", "nation-state"},
			FirstSeen:   now.Add(-90 * 24 * time.Hour),
			LastSeen:    now.Add(-7 * 24 * time.Hour),
			IsActive:    true,
			EventCount:  15,
			Metadata:    map[string]interface{}{"attribution": "APT28", "confidence": "high"},
			Country:     "CN",
			CreatedBy:   "system",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Type:        "url",
			Value:       "https://microsoft-account-verify.com/login",
			Threat:      "phishing",
			Severity:    "high",
			Confidence:  91,
			Source:      "phishtank",
			Description: "Microsoft 365 credential phishing",
			Tags:        []string{"phishing", "microsoft", "o365", "credential-theft"},
			FirstSeen:   now.Add(-5 * 24 * time.Hour),
			LastSeen:    now.Add(-6 * time.Hour),
			IsActive:    true,
			EventCount:  42,
			Metadata:    map[string]interface{}{"campaign": "O365-Phish-2024"},
			CreatedBy:   "system",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Type:        "ip",
			Value:       "91.219.237.244",
			Threat:      "bruteforce",
			Severity:    "high",
			Confidence:  84,
			Source:      "abuseipdb",
			Description: "SSH brute force attacks - Credential stuffing",
			Tags:        []string{"bruteforce", "ssh", "credential-stuffing"},
			FirstSeen:   now.Add(-14 * 24 * time.Hour),
			LastSeen:    now.Add(-2 * time.Hour),
			IsActive:    true,
			EventCount:  892,
			Metadata:    map[string]interface{}{"attempts": 15234, "protocol": "ssh"},
			Country:     "RU",
			CreatedBy:   "system",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Type:        "ip",
			Value:       "185.220.101.1",
			Threat:      "anonymization",
			Severity:    "medium",
			Confidence:  100,
			Source:      "tor-project",
			Description: "Tor exit node - Anonymization network",
			Tags:        []string{"tor", "anonymization", "privacy", "exit-node"},
			FirstSeen:   now.Add(-365 * 24 * time.Hour),
			LastSeen:    now.Add(-1 * time.Hour),
			IsActive:    true,
			EventCount:  1234,
			Metadata:    map[string]interface{}{"tor_node": true, "node_type": "exit"},
			CreatedBy:   "system",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}

	for _, ioc := range initialIOCs {
		iocJSON, _ := json.Marshal(ioc)
		s.opensearch.Index(
			iocsIndex,
			strings.NewReader(string(iocJSON)),
			s.opensearch.Index.WithDocumentID(ioc.ID),
		)
	}

	log.Printf("✅ Seeded %d initial IOCs", len(initialIOCs))
}

// seedInitialFeeds seeds the feeds index
func (s *APIServer) seedInitialFeeds() {
	if s.opensearch == nil {
		return
	}

	now := time.Now()

	feeds := []ThreatFeedOpenSearch{
		{
			ID:          uuid.New().String(),
			Name:        "AlienVault OTX",
			Provider:    "AlienVault",
			Type:        "public",
			FeedType:    "stix",
			URL:         "https://otx.alienvault.com/api/v1",
			Enabled:     true,
			UpdateFreq:  60,
			LastUpdate:  now.Add(-30 * time.Minute),
			NextUpdate:  now.Add(30 * time.Minute),
			IOCCount:    1247,
			Reliability: "high",
			Status:      "active",
			Config:      map[string]string{"requires_key": "true"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Name:        "AbuseIPDB",
			Provider:    "AbuseIPDB",
			Type:        "public",
			FeedType:    "json",
			URL:         "https://api.abuseipdb.com/api/v2",
			Enabled:     true,
			UpdateFreq:  30,
			LastUpdate:  now.Add(-15 * time.Minute),
			NextUpdate:  now.Add(15 * time.Minute),
			IOCCount:    834,
			Reliability: "high",
			Status:      "active",
			Config:      map[string]string{"requires_key": "true"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Name:        "VirusTotal",
			Provider:    "VirusTotal",
			Type:        "commercial",
			FeedType:    "json",
			URL:         "https://www.virustotal.com/api/v3",
			Enabled:     false,
			UpdateFreq:  120,
			LastUpdate:  now.Add(-5 * 24 * time.Hour),
			NextUpdate:  now.Add(-5*24*time.Hour + 120*time.Minute),
			IOCCount:    456,
			Reliability: "high",
			Status:      "disabled",
			LastError:   "API key not configured",
			Config:      map[string]string{"requires_key": "true", "tier": "premium"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Name:        "Emerging Threats",
			Provider:    "Proofpoint",
			Type:        "public",
			FeedType:    "csv",
			URL:         "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
			Enabled:     true,
			UpdateFreq:  1440,
			LastUpdate:  now.Add(-12 * time.Hour),
			NextUpdate:  now.Add(12 * time.Hour),
			IOCCount:    2500,
			Reliability: "medium",
			Status:      "active",
			Config:      map[string]string{"format": "plain_text"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New().String(),
			Name:        "URLhaus",
			Provider:    "abuse.ch",
			Type:        "public",
			FeedType:    "json",
			URL:         "https://urlhaus-api.abuse.ch/v1",
			Enabled:     true,
			UpdateFreq:  60,
			LastUpdate:  now.Add(-45 * time.Minute),
			NextUpdate:  now.Add(15 * time.Minute),
			IOCCount:    1890,
			Reliability: "high",
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}

	for _, feed := range feeds {
		feedJSON, _ := json.Marshal(feed)
		s.opensearch.Index(
			threatFeedsIndex,
			strings.NewReader(string(feedJSON)),
			s.opensearch.Index.WithDocumentID(feed.ID),
		)
	}

	log.Printf("✅ Seeded %d threat feeds", len(feeds))
}

// fetchIOCsFromOS retrieves IOCs from OpenSearch
func (s *APIServer) fetchIOCsFromOS(iocType, severity, threat, search string, limit int) ([]IOCOpenSearch, int, error) {
	if s.opensearch == nil {
		return nil, 0, fmt.Errorf("opensearch not available")
	}

	var mustClauses []map[string]interface{}

	// Only active IOCs by default
	mustClauses = append(mustClauses, map[string]interface{}{
		"term": map[string]interface{}{"is_active": true},
	})

	if iocType != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{"type": iocType},
		})
	}

	if severity != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{"severity": severity},
		})
	}

	if threat != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{"threat": threat},
		})
	}

	if search != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  search,
				"fields": []string{"value", "description", "tags", "threat"},
			},
		})
	}

	if limit == 0 {
		limit = 100
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		},
		"sort": []map[string]interface{}{
			{"last_seen": map[string]interface{}{"order": "desc"}},
		},
		"size": limit,
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(iocsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, err
	}

	iocs := []IOCOpenSearch{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalVal, ok := hits["total"].(map[string]interface{}); ok {
			if value, ok := totalVal["value"].(float64); ok {
				total = int(value)
			}
		}

		if hitArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitArray {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"].(map[string]interface{}); ok {
						ioc := parseIOCFromSource(source)
						iocs = append(iocs, ioc)
					}
				}
			}
		}
	}

	return iocs, total, nil
}

// createIOCInOS creates an IOC in OpenSearch
func (s *APIServer) createIOCInOS(ioc IOCOpenSearch) (*IOCOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	ioc.ID = uuid.New().String()
	ioc.CreatedAt = time.Now()
	ioc.UpdatedAt = time.Now()
	if ioc.FirstSeen.IsZero() {
		ioc.FirstSeen = time.Now()
	}
	if ioc.LastSeen.IsZero() {
		ioc.LastSeen = time.Now()
	}
	ioc.IsActive = true

	iocJSON, _ := json.Marshal(ioc)

	res, err := s.opensearch.Index(
		iocsIndex,
		strings.NewReader(string(iocJSON)),
		s.opensearch.Index.WithDocumentID(ioc.ID),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("failed to create IOC: %s", res.String())
	}

	log.Printf("✅ IOC created: %s (%s: %s)", ioc.ID, ioc.Type, ioc.Value)
	return &ioc, nil
}

// updateIOCInOS updates an IOC in OpenSearch
func (s *APIServer) updateIOCInOS(id string, updates map[string]interface{}) error {
	if s.opensearch == nil {
		return fmt.Errorf("opensearch not available")
	}

	updates["updated_at"] = time.Now()

	updateDoc := map[string]interface{}{
		"doc": updates,
	}

	updateJSON, _ := json.Marshal(updateDoc)

	res, err := s.opensearch.Update(
		iocsIndex,
		id,
		strings.NewReader(string(updateJSON)),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("failed to update IOC: %s", res.String())
	}

	return nil
}

// deleteIOCFromOS deletes (or deactivates) an IOC
func (s *APIServer) deleteIOCFromOS(id string) error {
	if s.opensearch == nil {
		return fmt.Errorf("opensearch not available")
	}

	// Soft delete - mark as inactive
	return s.updateIOCInOS(id, map[string]interface{}{
		"is_active": false,
	})
}

// getIOCByIDFromOS retrieves a single IOC by ID
func (s *APIServer) getIOCByIDFromOS(id string) (*IOCOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	res, err := s.opensearch.Get(iocsIndex, id)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("IOC not found")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	if source, ok := result["_source"].(map[string]interface{}); ok {
		ioc := parseIOCFromSource(source)
		return &ioc, nil
	}

	return nil, fmt.Errorf("IOC not found")
}

// getThreatIntelStatsFromOS gets statistics from OpenSearch
func (s *APIServer) getThreatIntelStatsFromOS() (*ThreatIntelStatsOS, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	// Aggregation query for stats
	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"term": map[string]interface{}{"is_active": true},
		},
		"aggs": map[string]interface{}{
			"total": map[string]interface{}{
				"value_count": map[string]interface{}{"field": "id"},
			},
			"by_type": map[string]interface{}{
				"terms": map[string]interface{}{"field": "type", "size": 10},
			},
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{"field": "severity", "size": 10},
			},
			"by_threat": map[string]interface{}{
				"terms": map[string]interface{}{"field": "threat", "size": 10},
			},
			"by_country": map[string]interface{}{
				"terms": map[string]interface{}{"field": "country", "size": 10},
			},
			"total_events": map[string]interface{}{
				"sum": map[string]interface{}{"field": "event_count"},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(iocsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	stats := &ThreatIntelStatsOS{
		IOCsByType:     make(map[string]int),
		IOCsBySeverity: make(map[string]int),
		TopThreats:     []ThreatSummary{},
		TopCountries:   []CountryThreat{},
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		// Total IOCs
		if total, ok := aggs["total"].(map[string]interface{}); ok {
			if value, ok := total["value"].(float64); ok {
				stats.TotalIOCs = int(value)
				stats.ActiveIOCs = int(value)
			}
		}

		// By type
		if byType, ok := aggs["by_type"].(map[string]interface{}); ok {
			if buckets, ok := byType["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if b, ok := bucket.(map[string]interface{}); ok {
						key := b["key"].(string)
						count := int(b["doc_count"].(float64))
						stats.IOCsByType[key] = count
					}
				}
			}
		}

		// By severity
		if bySeverity, ok := aggs["by_severity"].(map[string]interface{}); ok {
			if buckets, ok := bySeverity["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if b, ok := bucket.(map[string]interface{}); ok {
						key := b["key"].(string)
						count := int(b["doc_count"].(float64))
						stats.IOCsBySeverity[key] = count
					}
				}
			}
		}

		// Top threats
		if byThreat, ok := aggs["by_threat"].(map[string]interface{}); ok {
			if buckets, ok := byThreat["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if b, ok := bucket.(map[string]interface{}); ok {
						threat := ThreatSummary{
							Threat: b["key"].(string),
							Count:  int(b["doc_count"].(float64)),
						}
						// Determine severity based on threat type
						switch threat.Threat {
						case "ransomware", "apt", "c2", "malware":
							threat.Severity = "critical"
						case "phishing", "bruteforce", "exploit":
							threat.Severity = "high"
						default:
							threat.Severity = "medium"
						}
						stats.TopThreats = append(stats.TopThreats, threat)
					}
				}
			}
		}

		// Top countries
		if byCountry, ok := aggs["by_country"].(map[string]interface{}); ok {
			if buckets, ok := byCountry["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if b, ok := bucket.(map[string]interface{}); ok {
						country := CountryThreat{
							Country: b["key"].(string),
							Count:   int(b["doc_count"].(float64)),
						}
						// Calculate risk score based on count
						country.Score = minInt(int(float64(country.Count)*10), 100)
						stats.TopCountries = append(stats.TopCountries, country)
					}
				}
			}
		}

		// Total events enriched
		if totalEvents, ok := aggs["total_events"].(map[string]interface{}); ok {
			if value, ok := totalEvents["value"].(float64); ok {
				stats.EventsEnriched = int(value)
			}
		}
	}

	// Get recent IOCs
	recentIOCs, _, _ := s.fetchIOCsFromOS("", "", "", "", 5)
	stats.RecentIOCs = recentIOCs

	// Count active feeds
	stats.FeedsActive = s.countActiveFeedsFromOS()

	return stats, nil
}

// countActiveFeedsFromOS counts active feeds
func (s *APIServer) countActiveFeedsFromOS() int {
	if s.opensearch == nil {
		return 0
	}

	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"term": map[string]interface{}{"enabled": true},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(threatFeedsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return 0
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return 0
	}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			if value, ok := total["value"].(float64); ok {
				return int(value)
			}
		}
	}

	return 0
}

// fetchFeedsFromOS retrieves feeds from OpenSearch
func (s *APIServer) fetchFeedsFromOS() ([]ThreatFeedOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"match_all": map[string]interface{}{},
		},
		"sort": []map[string]interface{}{
			{"name.keyword": map[string]interface{}{"order": "asc"}},
		},
		"size": 50,
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(threatFeedsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	feeds := []ThreatFeedOpenSearch{}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitArray {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"].(map[string]interface{}); ok {
						feed := parseFeedFromSource(source)
						feeds = append(feeds, feed)
					}
				}
			}
		}
	}

	return feeds, nil
}

// Helper function to parse IOC from OpenSearch source
func parseIOCFromSource(source map[string]interface{}) IOCOpenSearch {
	ioc := IOCOpenSearch{}

	if v, ok := source["id"].(string); ok {
		ioc.ID = v
	}
	if v, ok := source["type"].(string); ok {
		ioc.Type = v
	}
	if v, ok := source["value"].(string); ok {
		ioc.Value = v
	}
	if v, ok := source["threat"].(string); ok {
		ioc.Threat = v
	}
	if v, ok := source["severity"].(string); ok {
		ioc.Severity = v
	}
	if v, ok := source["confidence"].(float64); ok {
		ioc.Confidence = int(v)
	}
	if v, ok := source["source"].(string); ok {
		ioc.Source = v
	}
	if v, ok := source["description"].(string); ok {
		ioc.Description = v
	}
	if v, ok := source["tags"].([]interface{}); ok {
		for _, tag := range v {
			if t, ok := tag.(string); ok {
				ioc.Tags = append(ioc.Tags, t)
			}
		}
	}
	if v, ok := source["first_seen"].(string); ok {
		ioc.FirstSeen, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["last_seen"].(string); ok {
		ioc.LastSeen, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["is_active"].(bool); ok {
		ioc.IsActive = v
	}
	if v, ok := source["event_count"].(float64); ok {
		ioc.EventCount = int(v)
	}
	if v, ok := source["metadata"].(map[string]interface{}); ok {
		ioc.Metadata = v
	}
	if v, ok := source["country"].(string); ok {
		ioc.Country = v
	}
	if v, ok := source["asn"].(string); ok {
		ioc.ASN = v
	}
	if v, ok := source["created_by"].(string); ok {
		ioc.CreatedBy = v
	}

	return ioc
}

// Helper function to parse Feed from OpenSearch source
func parseFeedFromSource(source map[string]interface{}) ThreatFeedOpenSearch {
	feed := ThreatFeedOpenSearch{}

	if v, ok := source["id"].(string); ok {
		feed.ID = v
	}
	if v, ok := source["name"].(string); ok {
		feed.Name = v
	}
	if v, ok := source["provider"].(string); ok {
		feed.Provider = v
	}
	if v, ok := source["type"].(string); ok {
		feed.Type = v
	}
	if v, ok := source["feed_type"].(string); ok {
		feed.FeedType = v
	}
	if v, ok := source["url"].(string); ok {
		feed.URL = v
	}
	if v, ok := source["enabled"].(bool); ok {
		feed.Enabled = v
	}
	if v, ok := source["update_freq"].(float64); ok {
		feed.UpdateFreq = int(v)
	}
	if v, ok := source["last_update"].(string); ok {
		feed.LastUpdate, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["next_update"].(string); ok {
		feed.NextUpdate, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["ioc_count"].(float64); ok {
		feed.IOCCount = int(v)
	}
	if v, ok := source["reliability"].(string); ok {
		feed.Reliability = v
	}
	if v, ok := source["status"].(string); ok {
		feed.Status = v
	}
	if v, ok := source["last_error"].(string); ok {
		feed.LastError = v
	}
	if v, ok := source["config"].(map[string]interface{}); ok {
		feed.Config = make(map[string]string)
		for k, val := range v {
			if s, ok := val.(string); ok {
				feed.Config[k] = s
			}
		}
	}

	return feed
}

// convertIOCOpenSearchToIOC converts IOCOpenSearch to IOC for API compatibility
func convertIOCOpenSearchToIOC(iocOS IOCOpenSearch) IOC {
	return IOC{
		ID:          iocOS.ID,
		Type:        iocOS.Type,
		Value:       iocOS.Value,
		Threat:      iocOS.Threat,
		Severity:    iocOS.Severity,
		Confidence:  iocOS.Confidence,
		Source:      iocOS.Source,
		Description: iocOS.Description,
		Tags:        iocOS.Tags,
		FirstSeen:   iocOS.FirstSeen,
		LastSeen:    iocOS.LastSeen,
		IsActive:    iocOS.IsActive,
		EventCount:  iocOS.EventCount,
		Metadata:    iocOS.Metadata,
	}
}

// convertThreatFeedOpenSearchToThreatFeed converts for API compatibility
func convertThreatFeedOpenSearchToThreatFeed(feedOS ThreatFeedOpenSearch) ThreatFeed {
	return ThreatFeed{
		ID:         feedOS.ID,
		Name:       feedOS.Name,
		Source:     feedOS.Provider,
		Type:       feedOS.Type,
		Enabled:    feedOS.Enabled,
		UpdateFreq: feedOS.UpdateFreq,
		LastUpdate: feedOS.LastUpdate,
		NextUpdate: feedOS.NextUpdate,
		IOCCount:   feedOS.IOCCount,
		Config:     feedOS.Config,
	}
}

// ============================================================================
// CAMPAIGNS CRUD OPERATIONS
// ============================================================================

// fetchCampaignsFromOS retrieves campaigns from OpenSearch
func (s *APIServer) fetchCampaignsFromOS(status string, limit int) ([]CampaignOpenSearch, int, error) {
	if s.opensearch == nil {
		return nil, 0, fmt.Errorf("opensearch not available")
	}

	if limit <= 0 {
		limit = 100
	}

	// Build query
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{},
			},
		},
		"size": limit,
		"sort": []map[string]interface{}{
			{"last_activity": map[string]string{"order": "desc"}},
		},
	}

	must := query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"].([]map[string]interface{})

	if status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]string{"status": status},
		})
		query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = must
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(campaignsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
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
	total := int(hits["total"].(map[string]interface{})["value"].(float64))
	hitList := hits["hits"].([]interface{})

	campaigns := make([]CampaignOpenSearch, 0, len(hitList))
	for _, hit := range hitList {
		source := hit.(map[string]interface{})["_source"].(map[string]interface{})
		campaigns = append(campaigns, parseCampaignFromSource(source))
	}

	return campaigns, total, nil
}

// createCampaignInOS creates a new campaign in OpenSearch
func (s *APIServer) createCampaignInOS(campaign CampaignOpenSearch) (*CampaignOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	campaign.ID = uuid.New().String()
	campaign.CreatedAt = time.Now()
	campaign.UpdatedAt = time.Now()
	if campaign.FirstDetected.IsZero() {
		campaign.FirstDetected = time.Now()
	}
	if campaign.LastActivity.IsZero() {
		campaign.LastActivity = time.Now()
	}
	if campaign.Status == "" {
		campaign.Status = "active"
	}

	campaignJSON, _ := json.Marshal(campaign)

	res, err := s.opensearch.Index(
		campaignsIndex,
		strings.NewReader(string(campaignJSON)),
		s.opensearch.Index.WithDocumentID(campaign.ID),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("failed to create campaign: %s", res.String())
	}

	log.Printf("✅ Campaign created: %s (%s)", campaign.ID, campaign.Name)
	return &campaign, nil
}

// updateCampaignInOS updates a campaign in OpenSearch
func (s *APIServer) updateCampaignInOS(id string, updates map[string]interface{}) error {
	if s.opensearch == nil {
		return fmt.Errorf("opensearch not available")
	}

	updates["updated_at"] = time.Now()

	doc := map[string]interface{}{"doc": updates}
	docJSON, _ := json.Marshal(doc)

	res, err := s.opensearch.Update(
		campaignsIndex,
		id,
		strings.NewReader(string(docJSON)),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("failed to update campaign: %s", res.String())
	}

	return nil
}

// getCampaignByIDFromOS retrieves a campaign by ID
func (s *APIServer) getCampaignByIDFromOS(id string) (*CampaignOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	res, err := s.opensearch.Get(campaignsIndex, id)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("campaign not found: %s", id)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	source := result["_source"].(map[string]interface{})
	campaign := parseCampaignFromSource(source)
	return &campaign, nil
}

// parseCampaignFromSource parses a campaign from OpenSearch source
func parseCampaignFromSource(source map[string]interface{}) CampaignOpenSearch {
	campaign := CampaignOpenSearch{}

	if v, ok := source["id"].(string); ok {
		campaign.ID = v
	}
	if v, ok := source["name"].(string); ok {
		campaign.Name = v
	}
	if v, ok := source["description"].(string); ok {
		campaign.Description = v
	}
	if v, ok := source["status"].(string); ok {
		campaign.Status = v
	}
	if v, ok := source["severity"].(string); ok {
		campaign.Severity = v
	}
	if v, ok := source["first_detected"].(string); ok {
		campaign.FirstDetected, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["last_activity"].(string); ok {
		campaign.LastActivity, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["threat_actors"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				campaign.ThreatActors = append(campaign.ThreatActors, s)
			}
		}
	}
	if v, ok := source["target_sectors"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				campaign.TargetSectors = append(campaign.TargetSectors, s)
			}
		}
	}
	if v, ok := source["target_countries"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				campaign.TargetCountries = append(campaign.TargetCountries, s)
			}
		}
	}
	if v, ok := source["attack_vectors"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				campaign.AttackVectors = append(campaign.AttackVectors, s)
			}
		}
	}
	if v, ok := source["objectives"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				campaign.Objectives = append(campaign.Objectives, s)
			}
		}
	}
	if v, ok := source["ttps"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				campaign.TTPs = append(campaign.TTPs, s)
			}
		}
	}
	if v, ok := source["iocs_identified"].(float64); ok {
		campaign.IOCsIdentified = int(v)
	}
	if v, ok := source["victims_affected"].(float64); ok {
		campaign.VictimsAffected = int(v)
	}
	if v, ok := source["mitre_tactics"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				campaign.MITRETactics = append(campaign.MITRETactics, s)
			}
		}
	}
	if v, ok := source["recommendations"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				campaign.Recommendations = append(campaign.Recommendations, s)
			}
		}
	}
	if v, ok := source["related_iocs"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				campaign.RelatedIOCs = append(campaign.RelatedIOCs, s)
			}
		}
	}
	if v, ok := source["tags"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				campaign.Tags = append(campaign.Tags, s)
			}
		}
	}
	if v, ok := source["created_by"].(string); ok {
		campaign.CreatedBy = v
	}
	if v, ok := source["created_at"].(string); ok {
		campaign.CreatedAt, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["updated_at"].(string); ok {
		campaign.UpdatedAt, _ = time.Parse(time.RFC3339, v)
	}

	return campaign
}

// ============================================================================
// CORRELATIONS CRUD OPERATIONS
// ============================================================================

// fetchCorrelationsFromOS retrieves correlations from OpenSearch
func (s *APIServer) fetchCorrelationsFromOS(status string, severity string, limit int) ([]CorrelationOpenSearch, int, error) {
	if s.opensearch == nil {
		return nil, 0, fmt.Errorf("opensearch not available")
	}

	if limit <= 0 {
		limit = 100
	}

	// Build query
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{},
			},
		},
		"size": limit,
		"sort": []map[string]interface{}{
			{"detected_at": map[string]string{"order": "desc"}},
		},
	}

	must := query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"].([]map[string]interface{})

	if status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]string{"status": status},
		})
	}
	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]string{"severity": severity},
		})
	}
	query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = must

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(correlationsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
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
	total := int(hits["total"].(map[string]interface{})["value"].(float64))
	hitList := hits["hits"].([]interface{})

	correlations := make([]CorrelationOpenSearch, 0, len(hitList))
	for _, hit := range hitList {
		source := hit.(map[string]interface{})["_source"].(map[string]interface{})
		correlations = append(correlations, parseCorrelationFromSource(source))
	}

	return correlations, total, nil
}

// createCorrelationInOS creates a new correlation in OpenSearch
func (s *APIServer) createCorrelationInOS(correlation CorrelationOpenSearch) (*CorrelationOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	correlation.ID = uuid.New().String()
	correlation.CreatedAt = time.Now()
	correlation.UpdatedAt = time.Now()
	if correlation.DetectedAt.IsZero() {
		correlation.DetectedAt = time.Now()
	}
	if correlation.Status == "" {
		correlation.Status = "new"
	}

	correlationJSON, _ := json.Marshal(correlation)

	res, err := s.opensearch.Index(
		correlationsIndex,
		strings.NewReader(string(correlationJSON)),
		s.opensearch.Index.WithDocumentID(correlation.ID),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("failed to create correlation: %s", res.String())
	}

	log.Printf("✅ Correlation created: %s (type: %s, severity: %s)", correlation.ID, correlation.Type, correlation.Severity)
	return &correlation, nil
}

// updateCorrelationInOS updates a correlation in OpenSearch
func (s *APIServer) updateCorrelationInOS(id string, updates map[string]interface{}) error {
	if s.opensearch == nil {
		return fmt.Errorf("opensearch not available")
	}

	updates["updated_at"] = time.Now()

	doc := map[string]interface{}{"doc": updates}
	docJSON, _ := json.Marshal(doc)

	res, err := s.opensearch.Update(
		correlationsIndex,
		id,
		strings.NewReader(string(docJSON)),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("failed to update correlation: %s", res.String())
	}

	return nil
}

// getCorrelationByIDFromOS retrieves a correlation by ID
func (s *APIServer) getCorrelationByIDFromOS(id string) (*CorrelationOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	res, err := s.opensearch.Get(correlationsIndex, id)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("correlation not found: %s", id)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	source := result["_source"].(map[string]interface{})
	correlation := parseCorrelationFromSource(source)
	return &correlation, nil
}

// parseCorrelationFromSource parses a correlation from OpenSearch source
func parseCorrelationFromSource(source map[string]interface{}) CorrelationOpenSearch {
	correlation := CorrelationOpenSearch{}

	if v, ok := source["id"].(string); ok {
		correlation.ID = v
	}
	if v, ok := source["type"].(string); ok {
		correlation.Type = v
	}
	if v, ok := source["severity"].(string); ok {
		correlation.Severity = v
	}
	if v, ok := source["confidence"].(float64); ok {
		correlation.Confidence = v
	}
	if v, ok := source["detected_at"].(string); ok {
		correlation.DetectedAt, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["source_event_id"].(string); ok {
		correlation.SourceEventID = v
	}
	if v, ok := source["source_event_type"].(string); ok {
		correlation.SourceEventType = v
	}
	if v, ok := source["matched_ioc_id"].(string); ok {
		correlation.MatchedIOCID = v
	}
	if v, ok := source["matched_ioc_value"].(string); ok {
		correlation.MatchedIOCValue = v
	}
	if v, ok := source["threat_actor"].(string); ok {
		correlation.ThreatActor = v
	}
	if v, ok := source["campaign"].(string); ok {
		correlation.Campaign = v
	}
	if v, ok := source["campaign_id"].(string); ok {
		correlation.CampaignID = v
	}
	if v, ok := source["mitre_techniques"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				correlation.MITRETechniques = append(correlation.MITRETechniques, s)
			}
		}
	}
	if v, ok := source["affected_assets"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				correlation.AffectedAssets = append(correlation.AffectedAssets, s)
			}
		}
	}
	if v, ok := source["context"].(string); ok {
		correlation.Context = v
	}
	if v, ok := source["recommendations"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				correlation.Recommendations = append(correlation.Recommendations, s)
			}
		}
	}
	if v, ok := source["status"].(string); ok {
		correlation.Status = v
	}
	if v, ok := source["resolved_at"].(string); ok {
		t, _ := time.Parse(time.RFC3339, v)
		correlation.ResolvedAt = &t
	}
	if v, ok := source["resolved_by"].(string); ok {
		correlation.ResolvedBy = v
	}
	if v, ok := source["resolution"].(string); ok {
		correlation.Resolution = v
	}
	if v, ok := source["created_at"].(string); ok {
		correlation.CreatedAt, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["updated_at"].(string); ok {
		correlation.UpdatedAt, _ = time.Parse(time.RFC3339, v)
	}

	return correlation
}

// ============================================================================
// THREAT ACTORS CRUD OPERATIONS
// ============================================================================

// fetchThreatActorsFromOS retrieves threat actors from OpenSearch
func (s *APIServer) fetchThreatActorsFromOS(actorType string, limit int) ([]ThreatActorOpenSearch, int, error) {
	if s.opensearch == nil {
		return nil, 0, fmt.Errorf("opensearch not available")
	}

	if limit <= 0 {
		limit = 100
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{},
			},
		},
		"size": limit,
		"sort": []map[string]interface{}{
			{"threat_score": map[string]string{"order": "desc"}},
		},
	}

	must := query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"].([]map[string]interface{})

	if actorType != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]string{"type": actorType},
		})
		query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = must
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(threatActorsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
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
	total := int(hits["total"].(map[string]interface{})["value"].(float64))
	hitList := hits["hits"].([]interface{})

	actors := make([]ThreatActorOpenSearch, 0, len(hitList))
	for _, hit := range hitList {
		source := hit.(map[string]interface{})["_source"].(map[string]interface{})
		actors = append(actors, parseThreatActorFromSource(source))
	}

	return actors, total, nil
}

// createThreatActorInOS creates a new threat actor in OpenSearch
func (s *APIServer) createThreatActorInOS(actor ThreatActorOpenSearch) (*ThreatActorOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	actor.ID = uuid.New().String()
	actor.CreatedAt = time.Now()
	actor.UpdatedAt = time.Now()
	if actor.FirstSeen.IsZero() {
		actor.FirstSeen = time.Now()
	}
	if actor.LastActivity.IsZero() {
		actor.LastActivity = time.Now()
	}

	actorJSON, _ := json.Marshal(actor)

	res, err := s.opensearch.Index(
		threatActorsIndex,
		strings.NewReader(string(actorJSON)),
		s.opensearch.Index.WithDocumentID(actor.ID),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("failed to create threat actor: %s", res.String())
	}

	log.Printf("✅ Threat Actor created: %s (%s)", actor.ID, actor.Name)
	return &actor, nil
}

// parseThreatActorFromSource parses a threat actor from OpenSearch source
func parseThreatActorFromSource(source map[string]interface{}) ThreatActorOpenSearch {
	actor := ThreatActorOpenSearch{}

	if v, ok := source["id"].(string); ok {
		actor.ID = v
	}
	if v, ok := source["name"].(string); ok {
		actor.Name = v
	}
	if v, ok := source["aliases"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				actor.Aliases = append(actor.Aliases, s)
			}
		}
	}
	if v, ok := source["type"].(string); ok {
		actor.Type = v
	}
	if v, ok := source["sophistication"].(string); ok {
		actor.Sophistication = v
	}
	if v, ok := source["origin"].(string); ok {
		actor.Origin = v
	}
	if v, ok := source["description"].(string); ok {
		actor.Description = v
	}
	if v, ok := source["first_seen"].(string); ok {
		actor.FirstSeen, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["last_activity"].(string); ok {
		actor.LastActivity, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["target_sectors"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				actor.TargetSectors = append(actor.TargetSectors, s)
			}
		}
	}
	if v, ok := source["target_countries"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				actor.TargetCountries = append(actor.TargetCountries, s)
			}
		}
	}
	if v, ok := source["ttps"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				actor.TTPs = append(actor.TTPs, s)
			}
		}
	}
	if v, ok := source["tools"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				actor.Tools = append(actor.Tools, s)
			}
		}
	}
	if v, ok := source["malware"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				actor.Malware = append(actor.Malware, s)
			}
		}
	}
	if v, ok := source["campaigns"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				actor.Campaigns = append(actor.Campaigns, s)
			}
		}
	}
	if v, ok := source["known_iocs"].(float64); ok {
		actor.KnownIOCs = int(v)
	}
	if v, ok := source["threat_score"].(float64); ok {
		actor.ThreatScore = v
	}
	if v, ok := source["tags"].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				actor.Tags = append(actor.Tags, s)
			}
		}
	}
	if v, ok := source["created_by"].(string); ok {
		actor.CreatedBy = v
	}
	if v, ok := source["created_at"].(string); ok {
		actor.CreatedAt, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["updated_at"].(string); ok {
		actor.UpdatedAt, _ = time.Parse(time.RFC3339, v)
	}

	return actor
}

// ============================================================================
// CORRELATION ENGINE - IOC to Event Matching
// ============================================================================

// CorrelateEventWithIOCs checks an event against known IOCs and creates correlations
func (s *APIServer) CorrelateEventWithIOCs(eventID string, eventType string, eventData map[string]interface{}) (*CorrelationOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	// Extract potential IOC values from event
	potentialIOCs := extractPotentialIOCs(eventData)
	if len(potentialIOCs) == 0 {
		return nil, nil // No IOC candidates in event
	}

	// Search for matching IOCs
	for _, candidate := range potentialIOCs {
		iocs, _, err := s.fetchIOCsFromOS(candidate.iocType, "", "", candidate.value, 1)
		if err != nil || len(iocs) == 0 {
			continue
		}

		// Found a match! Create correlation
		matchedIOC := iocs[0]

		// Determine severity based on IOC
		severity := matchedIOC.Severity
		if severity == "" {
			severity = "medium"
		}

		// Build context
		context := fmt.Sprintf("Event field '%s' contains value '%s' which matches known IOC (type: %s, threat: %s)",
			candidate.field, candidate.value, matchedIOC.Type, matchedIOC.Threat)

		// Build recommendations
		recommendations := []string{
			"Investigate the source of this activity",
			"Check for lateral movement indicators",
			"Review related events from the same source",
		}
		if severity == "critical" {
			recommendations = append([]string{"IMMEDIATE: Isolate affected systems"}, recommendations...)
		}

		correlation := CorrelationOpenSearch{
			Type:            "ioc_match",
			Severity:        severity,
			Confidence:      float64(matchedIOC.Confidence),
			SourceEventID:   eventID,
			SourceEventType: eventType,
			MatchedIOCID:    matchedIOC.ID,
			MatchedIOCValue: matchedIOC.Value,
			ThreatActor:     "",              // Would need to look up from IOC metadata
			MITRETechniques: matchedIOC.Tags, // Use tags as proxy for techniques
			AffectedAssets:  extractAffectedAssets(eventData),
			Context:         context,
			Recommendations: recommendations,
			Status:          "new",
		}

		created, err := s.createCorrelationInOS(correlation)
		if err != nil {
			log.Printf("⚠️ Failed to create correlation: %v", err)
			continue
		}

		// Update IOC event count
		s.updateIOCInOS(matchedIOC.ID, map[string]interface{}{
			"event_count": matchedIOC.EventCount + 1,
			"last_seen":   time.Now(),
		})

		return created, nil
	}

	return nil, nil // No matches found
}

// iocCandidate represents a potential IOC value from an event
type iocCandidate struct {
	field   string
	value   string
	iocType string
}

// extractPotentialIOCs extracts potential IOC values from event data
func extractPotentialIOCs(eventData map[string]interface{}) []iocCandidate {
	candidates := []iocCandidate{}

	// IP fields
	ipFields := []string{"source_ip", "src_ip", "sourceip", "dest_ip", "dst_ip", "destip", "client_ip", "remote_ip", "ip_address"}
	for _, field := range ipFields {
		if v, ok := eventData[field].(string); ok && v != "" && isValidIP(v) {
			candidates = append(candidates, iocCandidate{field: field, value: v, iocType: "ip"})
		}
	}

	// Domain fields
	domainFields := []string{"domain", "hostname", "host", "server", "url_domain", "dns_query"}
	for _, field := range domainFields {
		if v, ok := eventData[field].(string); ok && v != "" {
			candidates = append(candidates, iocCandidate{field: field, value: v, iocType: "domain"})
		}
	}

	// Hash fields
	hashFields := []string{"file_hash", "md5", "sha1", "sha256", "hash"}
	for _, field := range hashFields {
		if v, ok := eventData[field].(string); ok && v != "" {
			candidates = append(candidates, iocCandidate{field: field, value: v, iocType: "hash"})
		}
	}

	// URL fields
	urlFields := []string{"url", "uri", "request_url", "referer"}
	for _, field := range urlFields {
		if v, ok := eventData[field].(string); ok && v != "" {
			candidates = append(candidates, iocCandidate{field: field, value: v, iocType: "url"})
		}
	}

	// Email fields
	emailFields := []string{"email", "sender", "from", "recipient", "to"}
	for _, field := range emailFields {
		if v, ok := eventData[field].(string); ok && v != "" && strings.Contains(v, "@") {
			candidates = append(candidates, iocCandidate{field: field, value: v, iocType: "email"})
		}
	}

	return candidates
}

// isValidIP checks if a string is a valid IP address
func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
	}
	return true
}

// extractAffectedAssets extracts asset identifiers from event data
func extractAffectedAssets(eventData map[string]interface{}) []string {
	assets := []string{}

	assetFields := []string{"hostname", "host", "computer_name", "asset_id", "device_id", "machine_name", "workstation"}
	for _, field := range assetFields {
		if v, ok := eventData[field].(string); ok && v != "" {
			assets = append(assets, v)
		}
	}

	// Add source IP as asset if present
	if v, ok := eventData["source_ip"].(string); ok && v != "" {
		assets = append(assets, v)
	}

	return assets
}

// GetCorrelationStats returns correlation statistics
func (s *APIServer) GetCorrelationStats() (map[string]interface{}, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	// Count by status
	query := `{
		"size": 0,
		"aggs": {
			"by_status": {
				"terms": { "field": "status" }
			},
			"by_severity": {
				"terms": { "field": "severity" }
			},
			"by_type": {
				"terms": { "field": "type" }
			},
			"today": {
				"filter": {
					"range": {
						"detected_at": {
							"gte": "now/d"
						}
					}
				}
			}
		}
	}`

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(correlationsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search error: %s", res.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Parse aggregations
	aggs := result["aggregations"].(map[string]interface{})

	byStatus := make(map[string]int)
	if statusBuckets, ok := aggs["by_status"].(map[string]interface{})["buckets"].([]interface{}); ok {
		for _, bucket := range statusBuckets {
			b := bucket.(map[string]interface{})
			byStatus[b["key"].(string)] = int(b["doc_count"].(float64))
		}
	}

	bySeverity := make(map[string]int)
	if severityBuckets, ok := aggs["by_severity"].(map[string]interface{})["buckets"].([]interface{}); ok {
		for _, bucket := range severityBuckets {
			b := bucket.(map[string]interface{})
			bySeverity[b["key"].(string)] = int(b["doc_count"].(float64))
		}
	}

	byType := make(map[string]int)
	if typeBuckets, ok := aggs["by_type"].(map[string]interface{})["buckets"].([]interface{}); ok {
		for _, bucket := range typeBuckets {
			b := bucket.(map[string]interface{})
			byType[b["key"].(string)] = int(b["doc_count"].(float64))
		}
	}

	todayCount := 0
	if today, ok := aggs["today"].(map[string]interface{}); ok {
		todayCount = int(today["doc_count"].(float64))
	}

	total := int(result["hits"].(map[string]interface{})["total"].(map[string]interface{})["value"].(float64))

	return map[string]interface{}{
		"total":       total,
		"today":       todayCount,
		"by_status":   byStatus,
		"by_severity": bySeverity,
		"by_type":     byType,
	}, nil
}
