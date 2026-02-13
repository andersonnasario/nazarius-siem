package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const uebaProfilesIndex = "siem-ueba-profiles"
const uebaAnomaliesIndex = "siem-ueba-anomalies"

// UEBAProfileOpenSearch represents a user behavior profile in OpenSearch
type UEBAProfileOpenSearch struct {
	ID                  string                 `json:"id"`
	UserID              string                 `json:"user_id"`
	Username            string                 `json:"username"`
	Email               string                 `json:"email"`
	Department          string                 `json:"department"`
	RiskScore           float64                `json:"risk_score"`
	RiskLevel           string                 `json:"risk_level"`
	TotalActivities     int                    `json:"total_activities"`
	AnomalyCount        int                    `json:"anomaly_count"`
	LastActivity        time.Time              `json:"last_activity"`
	FirstSeen           time.Time              `json:"first_seen"`
	AvgLoginHour        float64                `json:"avg_login_hour"`
	CommonLocations     []string               `json:"common_locations"`
	CommonDevices       []string               `json:"common_devices"`
	CommonSourceIPs     []string               `json:"common_source_ips"`
	TypicalWorkHours    []int                  `json:"typical_work_hours"`
	AvgEventsPerDay     float64                `json:"avg_events_per_day"`
	FailedLoginCount    int                    `json:"failed_login_count"`
	SuccessfulLogins    int                    `json:"successful_logins"`
	PrivilegedActions   int                    `json:"privileged_actions"`
	DataAccessVolume    int64                  `json:"data_access_volume"`
	BaselineEstablished bool                   `json:"baseline_established"`
	UpdatedAt           time.Time              `json:"updated_at"`
	Tags                []string               `json:"tags"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// UEBAAnomalyOpenSearch represents a detected anomaly in OpenSearch
type UEBAAnomalyOpenSearch struct {
	ID              string                 `json:"id"`
	UserID          string                 `json:"user_id"`
	Username        string                 `json:"username"`
	AnomalyType     string                 `json:"anomaly_type"`
	Severity        string                 `json:"severity"`
	Score           float64                `json:"score"`
	Description     string                 `json:"description"`
	DetectedAt      time.Time              `json:"detected_at"`
	EventID         string                 `json:"event_id"`
	SourceIP        string                 `json:"source_ip"`
	Location        string                 `json:"location"`
	Device          string                 `json:"device"`
	ExpectedValue   string                 `json:"expected_value"`
	ActualValue     string                 `json:"actual_value"`
	Deviation       float64                `json:"deviation"`
	Status          string                 `json:"status"`
	InvestigatedBy  string                 `json:"investigated_by"`
	ResolutionNotes string                 `json:"resolution_notes"`
	RelatedAlertID  string                 `json:"related_alert_id"`
	MITRETechnique  string                 `json:"mitre_technique"`
	Details         map[string]interface{} `json:"details"`
}

type userAggregate struct {
	Count   int
	Aliases map[string]struct{}
}

type userAggregateItem struct {
	Username string
	Agg      *userAggregate
}

type userBehaviorMetrics struct {
	totalEvents     int
	severityCounts  map[string]int
	offHoursEvents  int
	avgHour         float64
	firstActivity   time.Time
	lastActivity    time.Time
	commonRegions   []string
	commonDevices   []string
	commonSourceIPs []string
}

// EnsureUEBAIndices creates UEBA indices if they don't exist
func (s *APIServer) EnsureUEBAIndices() {
	if s.opensearch == nil {
		return
	}

	// Profiles index
	profilesMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"user_id": { "type": "keyword" },
				"username": { "type": "keyword" },
				"email": { "type": "keyword" },
				"department": { "type": "keyword" },
				"risk_score": { "type": "float" },
				"risk_level": { "type": "keyword" },
				"total_activities": { "type": "integer" },
				"anomaly_count": { "type": "integer" },
				"last_activity": { "type": "date" },
				"first_seen": { "type": "date" },
				"avg_login_hour": { "type": "float" },
				"common_locations": { "type": "keyword" },
				"common_devices": { "type": "keyword" },
				"common_source_ips": { "type": "ip" },
				"typical_work_hours": { "type": "integer" },
				"avg_events_per_day": { "type": "float" },
				"failed_login_count": { "type": "integer" },
				"successful_logins": { "type": "integer" },
				"privileged_actions": { "type": "integer" },
				"data_access_volume": { "type": "long" },
				"baseline_established": { "type": "boolean" },
				"updated_at": { "type": "date" },
				"tags": { "type": "keyword" }
			}
		}
	}`

	res, err := s.opensearch.Indices.Exists([]string{uebaProfilesIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			uebaProfilesIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(profilesMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", uebaProfilesIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", uebaProfilesIndex)
		}
	}

	// Anomalies index
	anomaliesMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"user_id": { "type": "keyword" },
				"username": { "type": "keyword" },
				"anomaly_type": { "type": "keyword" },
				"severity": { "type": "keyword" },
				"score": { "type": "float" },
				"description": { "type": "text" },
				"detected_at": { "type": "date" },
				"event_id": { "type": "keyword" },
				"source_ip": { "type": "ip" },
				"location": { "type": "keyword" },
				"device": { "type": "keyword" },
				"expected_value": { "type": "keyword" },
				"actual_value": { "type": "keyword" },
				"deviation": { "type": "float" },
				"status": { "type": "keyword" },
				"investigated_by": { "type": "keyword" },
				"related_alert_id": { "type": "keyword" },
				"mitre_technique": { "type": "keyword" }
			}
		}
	}`

	res, err = s.opensearch.Indices.Exists([]string{uebaAnomaliesIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			uebaAnomaliesIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(anomaliesMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", uebaAnomaliesIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", uebaAnomaliesIndex)
		}
	}
}

// StartUEBAAnalyzer starts the background UEBA analyzer
func (s *APIServer) StartUEBAAnalyzer() {
	log.Println("🧠 Starting UEBA Analyzer...")

	go func() {
		// Initial analysis after 10 seconds
		time.Sleep(10 * time.Second)
		s.analyzeUserBehavior()

		// Run every 5 minutes
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			s.analyzeUserBehavior()
		}
	}()
}

// handleForceUEBAAnalysis forces immediate UEBA analysis - useful for testing
func (s *APIServer) handleForceUEBAAnalysis(c *gin.Context) {
	log.Println("🔄 Forcing UEBA analysis...")
	
	// Option to clean up service accounts first
	cleanup := c.Query("cleanup")
	if cleanup == "true" {
		deleted := s.cleanupServiceAccountProfiles()
		log.Printf("🧹 Cleaned up %d service account profiles", deleted)
	}
	
	// Run analysis synchronously
	s.analyzeUserBehavior()
	
	// Return current stats
	s.handleGetUEBAStatsOpenSearch(c)
}

// cleanupServiceAccountProfiles removes profiles that belong to service accounts
func (s *APIServer) cleanupServiceAccountProfiles() int {
	if s.opensearch == nil {
		return 0
	}
	
	// Get all profiles
	query := `{
		"size": 1000,
		"_source": ["username", "user_id"]
	}`
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaProfilesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		log.Printf("❌ Error fetching profiles for cleanup: %v", err)
		return 0
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)
	
	deleted := 0
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsArr, ok := hits["hits"].([]interface{}); ok {
			for _, h := range hitsArr {
				hit := h.(map[string]interface{})
				docID := hit["_id"].(string)
				source := hit["_source"].(map[string]interface{})
				
				username := getStrVal(source, "username")
				userID := getStrVal(source, "user_id")
				
				// Check if this is a service account
				if isServiceIdentity(username) || isServiceIdentity(userID) {
					// Delete this profile
					delRes, err := s.opensearch.Delete(uebaProfilesIndex, docID)
					if err == nil {
						delRes.Body.Close()
						deleted++
						log.Printf("🗑️ Deleted service account profile: %s", username)
					}
				}
			}
		}
	}
	
	return deleted
}

// handleCleanupUEBAProfiles removes service account profiles and duplicates
func (s *APIServer) handleCleanupUEBAProfiles(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenSearch não configurado"})
		return
	}
	
	deleted := s.cleanupServiceAccountProfiles()
	duplicatesRemoved := s.deduplicateProfiles()
	
	c.JSON(http.StatusOK, gin.H{
		"success":            true,
		"service_accounts_deleted": deleted,
		"duplicates_removed": duplicatesRemoved,
		"message":            fmt.Sprintf("Limpeza concluída: %d contas de serviço removidas, %d duplicatas removidas", deleted, duplicatesRemoved),
	})
}

// deduplicateProfiles removes duplicate user profiles, keeping the most recent
func (s *APIServer) deduplicateProfiles() int {
	if s.opensearch == nil {
		return 0
	}
	
	// Get all profiles grouped by username
	query := `{
		"size": 0,
		"aggs": {
			"by_username": {
				"terms": {
					"field": "username",
					"size": 10000
				},
				"aggs": {
					"docs": {
						"top_hits": {
							"size": 100,
							"sort": [{"updated_at": {"order": "desc"}}],
							"_source": ["id"]
						}
					}
				}
			}
		}
	}`
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaProfilesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		log.Printf("❌ Error fetching profiles for deduplication: %v", err)
		return 0
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)
	
	deleted := 0
	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if byUsername, ok := aggs["by_username"].(map[string]interface{}); ok {
			if buckets, ok := byUsername["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					if docs, ok := bucket["docs"].(map[string]interface{}); ok {
						if hits, ok := docs["hits"].(map[string]interface{}); ok {
							if hitsArr, ok := hits["hits"].([]interface{}); ok {
								// Skip the first one (most recent), delete the rest
								for i := 1; i < len(hitsArr); i++ {
									hit := hitsArr[i].(map[string]interface{})
									docID := hit["_id"].(string)
									
									delRes, err := s.opensearch.Delete(uebaProfilesIndex, docID)
									if err == nil {
										delRes.Body.Close()
										deleted++
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	return deleted
}

// handleUEBADiagnostics returns diagnostic information about UEBA
func (s *APIServer) handleUEBADiagnostics(c *gin.Context) {
	diag := gin.H{
		"opensearch_connected": s.opensearch != nil,
		"indices": gin.H{
			"profiles_index":  uebaProfilesIndex,
			"anomalies_index": uebaAnomaliesIndex,
		},
		"events_sample": []map[string]interface{}{},
		"profiles_count": 0,
		"anomalies_count": 0,
		"events_last_24h": 0,
	}
	
	if s.opensearch == nil {
		c.JSON(http.StatusOK, diag)
		return
	}
	
	// Check events index - get sample and count
	eventsQuery := `{
		"size": 5,
		"sort": [{"timestamp": {"order": "desc"}}],
		"_source": ["timestamp", "type", "source", "severity", "user", "username", "principalId"]
	}`
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(eventsQuery)),
	)
	if err == nil && !res.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res.Body).Decode(&result)
		res.Body.Close()
		
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				diag["events_last_24h"] = int(total["value"].(float64))
			}
			if hitsArr, ok := hits["hits"].([]interface{}); ok {
				samples := []map[string]interface{}{}
				for _, h := range hitsArr {
					hit := h.(map[string]interface{})
					if source, ok := hit["_source"].(map[string]interface{}); ok {
						samples = append(samples, source)
					}
				}
				diag["events_sample"] = samples
			}
		}
	} else if err != nil {
		diag["events_error"] = err.Error()
	} else if res.IsError() {
		diag["events_error"] = res.String()
	}
	
	// Check profiles count
	profilesCountQuery := `{"size": 0}`
	res2, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaProfilesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(profilesCountQuery)),
	)
	if res2 != nil && !res2.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res2.Body).Decode(&result)
		res2.Body.Close()
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				diag["profiles_count"] = int(total["value"].(float64))
			}
		}
	}
	
	// Check anomalies count
	anomaliesCountQuery := `{"size": 0}`
	res3, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(anomaliesCountQuery)),
	)
	if res3 != nil && !res3.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res3.Body).Decode(&result)
		res3.Body.Close()
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				diag["anomalies_count"] = int(total["value"].(float64))
			}
		}
	}
	
	c.JSON(http.StatusOK, diag)
}

// analyzeUserBehavior analyzes events and builds/updates user profiles
func (s *APIServer) analyzeUserBehavior() {
	if s.opensearch == nil {
		return
	}

	log.Println("🔍 UEBA: Analyzing user behavior from events...")

	// Get unique users from recent events
	// Try multiple user fields that might exist in different event types (CloudTrail, GuardDuty, etc)
	usersQuery := `{
		"size": 0,
		"query": {
			"range": {
				"timestamp": {
					"gte": "now-24h"
				}
			}
		},
		"aggs": {
			"users_by_user": {
				"terms": {
					"field": "user.keyword",
					"size": 500,
					"missing": "__no_user__"
				}
			},
			"users_by_username": {
				"terms": {
					"field": "username.keyword",
					"size": 500,
					"missing": "__no_username__"
				}
			},
			"users_by_principal": {
				"terms": {
					"field": "principalId.keyword",
					"size": 500,
					"missing": "__no_principal__"
				}
			},
			"users_by_source_identity": {
				"terms": {
					"field": "sourceIdentity.keyword",
					"size": 500,
					"missing": "__no_source_identity__"
				}
			},
			"by_severity": {
				"terms": { "field": "severity.keyword", "size": 10 }
			},
			"by_source": {
				"terms": { "field": "source.keyword", "size": 20 }
			},
			"by_type": {
				"terms": { "field": "type.keyword", "size": 30 }
			}
		}
	}`

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(usersQuery)),
	)
	if err != nil {
		log.Printf("❌ UEBA: Error querying events: %v", err)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ UEBA: OpenSearch error: %s", res.String())
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	userAggregates := make(map[string]*userAggregate)
	systemSeverity := make(map[string]int)

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		for _, aggName := range []string{"users_by_user", "users_by_username", "users_by_principal", "users_by_source_identity"} {
			if userAgg, ok := aggs[aggName].(map[string]interface{}); ok {
				if buckets, ok := userAgg["buckets"].([]interface{}); ok {
					for _, b := range buckets {
						bucket := b.(map[string]interface{})
						raw := fmt.Sprintf("%v", bucket["key"])
						eventCount := int(bucket["doc_count"].(float64))

						normalized := normalizeUserIdentifier(raw)
						if normalized == "" {
							continue
						}

						agg := userAggregates[normalized]
						if agg == nil {
							agg = newUserAggregate()
							userAggregates[normalized] = agg
						}
						agg.Count += eventCount
						agg.AddAlias(raw)
						agg.AddAlias(normalized)
					}
				}
			}
		}

		if bySev, ok := aggs["by_severity"].(map[string]interface{}); ok {
			if buckets, ok := bySev["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					sev := strings.ToUpper(fmt.Sprintf("%v", bucket["key"]))
					count := int(bucket["doc_count"].(float64))
					systemSeverity[sev] = count
				}
			}
		}
	}

	if len(userAggregates) == 0 {
		log.Println("⚠️ UEBA: Nenhum usuário identificado nos últimos eventos")
		return
	}

	serviceSkipped := 0
	userItems := []userAggregateItem{}

	for username, agg := range userAggregates {
		if isServiceIdentity(username) {
			serviceSkipped++
			continue
		}
		userItems = append(userItems, userAggregateItem{
			Username: username,
			Agg:      agg,
		})
	}

	if len(userItems) == 0 {
		log.Printf("⚠️ UEBA: Todos os %d usuários recentes foram classificados como contas de serviço (TrustedAdvisor/aws-service-role)", len(userAggregates))
		return
	}

	sort.Slice(userItems, func(i, j int) bool {
		return userItems[i].Agg.Count > userItems[j].Agg.Count
	})

	maxUsers := 400
	if len(userItems) < maxUsers {
		maxUsers = len(userItems)
	}
	userItems = userItems[:maxUsers]

	profilesUpdated := 0
	anomaliesDetected := 0

	for _, item := range userItems {
		identifiers := item.Agg.Identifiers()
		metrics, err := s.getUserBehaviorMetrics(item.Username, identifiers)
		if err != nil {
			log.Printf("⚠️ UEBA: Falha ao coletar métricas do usuário %s: %v", item.Username, err)
			continue
		}
		if metrics == nil || metrics.totalEvents == 0 {
			continue
		}

		profile := s.getOrCreateUserProfile(item.Username)
		s.updateProfileFromMetrics(profile, metrics, identifiers)
		anomaliesDetected += s.detectUserMetricAnomalies(profile, metrics)
		s.saveUserProfile(profile)
		profilesUpdated++
	}

	if criticalCount, ok := systemSeverity["CRITICAL"]; ok && criticalCount > 40 {
		anomaly := &UEBAAnomalyOpenSearch{
			ID:            uuid.New().String(),
			UserID:        "system",
			Username:      "SYSTEM",
			AnomalyType:   "high_critical_volume",
			Severity:      "high",
			Score:         85,
			Description:   fmt.Sprintf("Volume elevado de eventos CRÍTICOS nas últimas 24h: %d", criticalCount),
			DetectedAt:    time.Now(),
			ExpectedValue: "< 40 eventos críticos/24h",
			ActualValue:   fmt.Sprintf("%d eventos", criticalCount),
			Status:        "new",
			MITRETechnique: "T1059",
		}
		s.saveAnomaly(anomaly)
		anomaliesDetected++
	}

	log.Printf("✅ UEBA: Perfis atualizados=%d (serviços filtrados=%d), anomalias detectadas=%d", profilesUpdated, serviceSkipped, anomaliesDetected)
}

func newUserAggregate() *userAggregate {
	return &userAggregate{
		Aliases: make(map[string]struct{}),
	}
}

func (a *userAggregate) AddAlias(alias string) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return
	}
	a.Aliases[alias] = struct{}{}
}

func (a *userAggregate) Identifiers() []string {
	ids := make([]string, 0, len(a.Aliases))
	for alias := range a.Aliases {
		ids = append(ids, alias)
	}
	return ids
}

func normalizeUserIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" || value == "unknown" || strings.HasPrefix(value, "__no_") || strings.EqualFold(value, "N/A") {
		return ""
	}

	// Normalize ARNs to last segment
	if strings.HasPrefix(value, "arn:") {
		parts := strings.Split(value, "/")
		value = parts[len(parts)-1]
	}

	return value
}

func isServiceIdentity(value string) bool {
	lower := strings.ToLower(value)
	
	// AWS Service accounts and roles
	if strings.HasPrefix(lower, "trustedadvisor_") || strings.HasPrefix(lower, "trustedadvisor") {
		return true
	}
	if strings.Contains(lower, "awsservicerole") || strings.Contains(lower, "service-role/") {
		return true
	}
	if strings.Contains(lower, "aws-control-tower") || strings.Contains(lower, "awssupport") {
		return true
	}
	
	// Integration and automation accounts
	if strings.Contains(lower, "datadog") || strings.HasPrefix(lower, "datadog") {
		return true
	}
	if strings.Contains(lower, "nat_gateway") || strings.Contains(lower, "natgateway") {
		return true
	}
	if strings.Contains(lower, "_metadata_ingestion") || strings.Contains(lower, "metadata-ingestion") {
		return true
	}
	
	// Common AWS service principals
	servicePatterns := []string{
		"cloudformation", "cloudwatch", "lambda", "ecs-tasks",
		"ec2.amazonaws", "s3.amazonaws", "sns.amazonaws", "sqs.amazonaws",
		"config.amazonaws", "cloudtrail.amazonaws", "guardduty.amazonaws",
		"securityhub.amazonaws", "inspector.amazonaws", "macie.amazonaws",
		"backup.amazonaws", "autoscaling", "elasticloadbalancing",
		"application-autoscaling", "events.amazonaws", "states.amazonaws",
		"ssm.amazonaws", "secretsmanager", "kms.amazonaws",
		"root", "awsreservedssoprovider", "awssso", "identitystore",
		"organization", "terraform", "ansible", "jenkins", "github-actions",
		"codebuild", "codepipeline", "codedeploy", "codecommit",
		"newrelic", "splunk", "sumo", "pagerduty", "opsgenie",
		"monitoring", "healthcheck", "synthetic", "canary",
	}
	
	for _, pattern := range servicePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	
	// Generic patterns for service accounts
	if strings.HasPrefix(lower, "svc-") || strings.HasPrefix(lower, "svc_") {
		return true
	}
	if strings.HasSuffix(lower, "-service") || strings.HasSuffix(lower, "_service") {
		return true
	}
	if strings.HasSuffix(lower, "-automation") || strings.HasSuffix(lower, "_automation") {
		return true
	}
	if strings.HasSuffix(lower, "-integration") || strings.HasSuffix(lower, "_integration") {
		return true
	}
	
	// ARN-based service accounts
	if strings.Contains(lower, ":assumed-role/") && !strings.Contains(lower, "/admin") && !strings.Contains(lower, "/user") {
		// Check if it's a service role
		if strings.Contains(lower, "role/aws") || strings.Contains(lower, "role/service") {
			return true
		}
	}
	
	return false
}

func (s *APIServer) getUserBehaviorMetrics(username string, identifiers []string) (*userBehaviorMetrics, error) {
	if len(identifiers) == 0 {
		identifiers = []string{username}
	}

	should := []map[string]interface{}{}
	seen := map[string]struct{}{}
	for _, id := range identifiers {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		for _, field := range []string{"user.keyword", "username.keyword", "principalId.keyword", "details.user_name.keyword"} {
			should = append(should, map[string]interface{}{
				"term": map[string]interface{}{field: id},
			})
		}
	}

	if len(should) == 0 {
		return nil, fmt.Errorf("nenhum identificador disponível para o usuário %s", username)
	}

	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should":               should,
				"minimum_should_match": 1,
				"filter": []interface{}{
					map[string]interface{}{
						"range": map[string]interface{}{
							"timestamp": map[string]interface{}{
								"gte": "now-7d",
							},
						},
					},
				},
			},
		},
		"aggs": map[string]interface{}{
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "severity.keyword",
					"size":  10,
				},
			},
			"by_hour": map[string]interface{}{
				"date_histogram": map[string]interface{}{
					"field":             "timestamp",
					"calendar_interval": "hour",
				},
			},
			"by_region": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "details.aws_region.keyword",
					"size":  5,
				},
			},
			"by_device": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "details.user_agent.keyword",
					"size":  5,
				},
			},
			"by_source_ip": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "source_ip.keyword",
					"size":  5,
				},
			},
			"first_event": map[string]interface{}{
				"min": map[string]interface{}{"field": "timestamp"},
			},
			"last_event": map[string]interface{}{
				"max": map[string]interface{}{"field": "timestamp"},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("opensearch error: %s", res.String())
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	metrics := &userBehaviorMetrics{
		severityCounts: make(map[string]int),
	}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			metrics.totalEvents = int(totalObj["value"].(float64))
		}
	}

	if metrics.totalEvents == 0 {
		return metrics, nil
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if sevAgg, ok := aggs["by_severity"].(map[string]interface{}); ok {
			if buckets, ok := sevAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					sev := strings.ToUpper(fmt.Sprintf("%v", bucket["key"]))
					count := int(bucket["doc_count"].(float64))
					metrics.severityCounts[sev] = count
				}
			}
		}

		if hourAgg, ok := aggs["by_hour"].(map[string]interface{}); ok {
			if buckets, ok := hourAgg["buckets"].([]interface{}); ok {
				totalWeighted := 0.0
				totalCount := 0.0
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					count := bucket["doc_count"].(float64)
					key := bucket["key"].(float64)
					ts := time.Unix(0, int64(key)*int64(time.Millisecond))
					hour := ts.UTC().Hour()
					totalWeighted += float64(hour) * count
					totalCount += count
					if hour < 6 || hour >= 22 {
						metrics.offHoursEvents += int(count)
					}
				}
				if totalCount > 0 {
					metrics.avgHour = totalWeighted / totalCount
				}
			}
		}

		if firstAgg, ok := aggs["first_event"].(map[string]interface{}); ok {
			if value, ok := firstAgg["value"].(float64); ok && value > 0 {
				metrics.firstActivity = time.Unix(0, int64(value)*int64(time.Millisecond))
			}
		}
		if lastAgg, ok := aggs["last_event"].(map[string]interface{}); ok {
			if value, ok := lastAgg["value"].(float64); ok && value > 0 {
				metrics.lastActivity = time.Unix(0, int64(value)*int64(time.Millisecond))
			}
		}

		if regionAgg, ok := aggs["by_region"].(map[string]interface{}); ok {
			if buckets, ok := regionAgg["buckets"].([]interface{}); ok {
				metrics.commonRegions = topStringsFromBuckets(buckets, 3)
			}
		}
		if deviceAgg, ok := aggs["by_device"].(map[string]interface{}); ok {
			if buckets, ok := deviceAgg["buckets"].([]interface{}); ok {
				metrics.commonDevices = topStringsFromBuckets(buckets, 3)
			}
		}
		if ipAgg, ok := aggs["by_source_ip"].(map[string]interface{}); ok {
			if buckets, ok := ipAgg["buckets"].([]interface{}); ok {
				metrics.commonSourceIPs = topStringsFromBuckets(buckets, 3)
			}
		}
	}

	return metrics, nil
}

func topStringsFromBuckets(buckets []interface{}, limit int) []string {
	values := []string{}
	for _, b := range buckets {
		if len(values) >= limit {
			break
		}
		bucket := b.(map[string]interface{})
		key := strings.TrimSpace(fmt.Sprintf("%v", bucket["key"]))
		if key == "" || key == "__other__" {
			continue
		}
		values = append(values, key)
	}
	return values
}

func (s *APIServer) updateProfileFromMetrics(profile *UEBAProfileOpenSearch, metrics *userBehaviorMetrics, identifiers []string) {
	profile.TotalActivities = metrics.totalEvents
	if !metrics.lastActivity.IsZero() {
		profile.LastActivity = metrics.lastActivity
	} else {
		profile.LastActivity = time.Now()
	}

	if !metrics.firstActivity.IsZero() {
		if profile.FirstSeen.IsZero() || metrics.firstActivity.Before(profile.FirstSeen) {
			profile.FirstSeen = metrics.firstActivity
		}
	}

	if metrics.avgHour > 0 {
		profile.AvgLoginHour = math.Round(metrics.avgHour*10) / 10
	}

	if len(metrics.commonRegions) > 0 {
		profile.CommonLocations = metrics.commonRegions
	}
	if len(metrics.commonDevices) > 0 {
		profile.CommonDevices = metrics.commonDevices
	}
	if len(metrics.commonSourceIPs) > 0 {
		profile.CommonSourceIPs = metrics.commonSourceIPs
	}

	profile.RiskScore = calculateRiskScoreFromMetrics(metrics)
	profile.RiskLevel = getRiskLevel(profile.RiskScore)
	profile.BaselineEstablished = profile.TotalActivities >= 30 && len(profile.CommonLocations) > 0
	profile.UpdatedAt = time.Now()

	if strings.Contains(profile.Username, "@") && profile.Email == "" {
		profile.Email = profile.Username
	}

	if profile.Metadata == nil {
		profile.Metadata = map[string]interface{}{}
	}
	profile.Metadata["aliases"] = identifiers

	if len(profile.Tags) == 0 {
		profile.Tags = []string{"monitored"}
	} else {
		found := false
		for _, tag := range profile.Tags {
			if tag == "monitored" {
				found = true
				break
			}
		}
		if !found {
			profile.Tags = append(profile.Tags, "monitored")
		}
	}
}

func calculateRiskScoreFromMetrics(metrics *userBehaviorMetrics) float64 {
	score := 10.0

	critical := float64(metrics.severityCounts["CRITICAL"])
	high := float64(metrics.severityCounts["HIGH"])
	medium := float64(metrics.severityCounts["MEDIUM"])

	score += critical * 12
	score += high * 6
	score += medium * 2
	score += float64(metrics.totalEvents) * 0.05
	score += float64(metrics.offHoursEvents) * 0.5

	if metrics.offHoursEvents >= 5 {
		score += 10
	}
	if metrics.totalEvents >= 250 {
		score += 10
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return math.Round(score*10) / 10
}

func (s *APIServer) detectUserMetricAnomalies(profile *UEBAProfileOpenSearch, metrics *userBehaviorMetrics) int {
	anomalies := 0
	now := time.Now()

	createAnomaly := func(anomaly *UEBAAnomalyOpenSearch) {
		s.saveAnomaly(anomaly)
		profile.AnomalyCount++
		anomalies++
	}

	if metrics.offHoursEvents >= 5 {
		createAnomaly(&UEBAAnomalyOpenSearch{
			ID:            uuid.New().String(),
			UserID:        profile.UserID,
			Username:      profile.Username,
			AnomalyType:   "unusual_hours",
			Severity:      "medium",
			Score:         math.Min(float64(metrics.offHoursEvents)*5, 95),
			Description:   fmt.Sprintf("%d atividades ocorreram fora do horário padrão (00h-06h ou 22h-23h)", metrics.offHoursEvents),
			DetectedAt:    now,
			ExpectedValue: "Atividades concentradas entre 06h-22h",
			ActualValue:   fmt.Sprintf("%d eventos fora do horário", metrics.offHoursEvents),
			Status:        "new",
			MITRETechnique: "T1078",
			Details: map[string]interface{}{
				"off_hours_events": metrics.offHoursEvents,
			},
			SourceIP: firstOrEmpty(metrics.commonSourceIPs),
		})
	}

	if metrics.severityCounts["CRITICAL"] >= 3 {
		createAnomaly(&UEBAAnomalyOpenSearch{
			ID:            uuid.New().String(),
			UserID:        profile.UserID,
			Username:      profile.Username,
			AnomalyType:   "high_severity_activity",
			Severity:      "high",
			Score:         math.Min(float64(metrics.severityCounts["CRITICAL"])*15, 99),
			Description:   fmt.Sprintf("Usuário associado a %d eventos CRÍTICOS na janela analisada", metrics.severityCounts["CRITICAL"]),
			DetectedAt:    now,
			ExpectedValue: "< 3 eventos críticos/7d",
			ActualValue:   fmt.Sprintf("%d eventos críticos", metrics.severityCounts["CRITICAL"]),
			Status:        "new",
			MITRETechnique: "T1059",
			Details: map[string]interface{}{
				"critical_events": metrics.severityCounts["CRITICAL"],
				"high_events":     metrics.severityCounts["HIGH"],
			},
			SourceIP: firstOrEmpty(metrics.commonSourceIPs),
		})
	}

	if metrics.totalEvents >= 250 {
		createAnomaly(&UEBAAnomalyOpenSearch{
			ID:            uuid.New().String(),
			UserID:        profile.UserID,
			Username:      profile.Username,
			AnomalyType:   "high_activity_volume",
			Severity:      "medium",
			Score:         math.Min(float64(metrics.totalEvents)/5, 90),
			Description:   fmt.Sprintf("Volume elevado de atividades detectado: %d eventos na última semana", metrics.totalEvents),
			DetectedAt:    now,
			ExpectedValue: "< 250 eventos/7d",
			ActualValue:   fmt.Sprintf("%d eventos", metrics.totalEvents),
			Status:        "new",
			MITRETechnique: "T1078",
			Details: map[string]interface{}{
				"total_events": metrics.totalEvents,
			},
			SourceIP: firstOrEmpty(metrics.commonSourceIPs),
		})
	}

	return anomalies
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func buildIdentifierQuery(identifier string) []map[string]interface{} {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil
	}

	queries := []map[string]interface{}{}
	idLower := strings.ToLower(identifier)

	addTerm := func(field, value string) {
		if value == "" {
			return
		}
		queries = append(queries, map[string]interface{}{
			"term": map[string]interface{}{field: value},
		})
	}

	addMatch := func(field, value string) {
		if value == "" {
			return
		}
		queries = append(queries, map[string]interface{}{
			"match_phrase": map[string]interface{}{field: value},
		})
	}

	for _, field := range []string{"user_id", "username", "id"} {
		addTerm(field, identifier)
		addTerm(field, idLower)
		addMatch(field, identifier)
		if idLower != identifier {
			addMatch(field, idLower)
		}
	}

	if normalized := normalizeUserIdentifier(identifier); normalized != "" && normalized != identifier {
		for _, field := range []string{"user_id", "username", "id"} {
			addTerm(field, normalized)
			addMatch(field, normalized)
		}
	}

	return queries
}

// getOrCreateUserProfile gets existing profile or creates new one
// Uses username as the primary key to avoid duplicates
func (s *APIServer) getOrCreateUserProfile(username string) *UEBAProfileOpenSearch {
	// Normalize username for consistency
	normalizedUsername := strings.TrimSpace(username)
	if normalizedUsername == "" {
		return nil
	}
	
	// Try to get existing profile by username OR user_id (both should match)
	query := map[string]interface{}{
		"size": 1,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"term": map[string]interface{}{"username": normalizedUsername}},
					{"term": map[string]interface{}{"user_id": normalizedUsername}},
					{"match_phrase": map[string]interface{}{"username": normalizedUsername}},
					{"match_phrase": map[string]interface{}{"user_id": normalizedUsername}},
				},
				"minimum_should_match": 1,
			},
		},
		"sort": []map[string]interface{}{
			{"updated_at": map[string]interface{}{"order": "desc"}},
		},
	}
	
	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaProfilesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err == nil && !res.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res.Body).Decode(&result)
		res.Body.Close()

		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if hitsArray, ok := hits["hits"].([]interface{}); ok && len(hitsArray) > 0 {
				hit := hitsArray[0].(map[string]interface{})
				source := hit["_source"].(map[string]interface{})
				profile := parseUEBAProfile(source)
				// Ensure we use the document ID from OpenSearch for updates
				if docID, ok := hit["_id"].(string); ok {
					profile.ID = docID
				}
				return profile
			}
		}
	}

	// Create new profile with a deterministic ID based on username
	// This helps prevent duplicates even if the search fails
	deterministicID := fmt.Sprintf("ueba-profile-%s", strings.ToLower(normalizedUsername))
	
	return &UEBAProfileOpenSearch{
		ID:                  deterministicID,
		Username:            normalizedUsername,
		UserID:              normalizedUsername,
		RiskScore:           0,
		RiskLevel:           "low",
		TotalActivities:     0,
		AnomalyCount:        0,
		FirstSeen:           time.Now(),
		LastActivity:        time.Now(),
		CommonLocations:     []string{},
		CommonDevices:       []string{},
		CommonSourceIPs:     []string{},
		TypicalWorkHours:    []int{},
		BaselineEstablished: false,
		UpdatedAt:           time.Now(),
		Tags:                []string{},
		Metadata:            map[string]interface{}{},
	}
}

// calculateUserRiskScore calculates risk score based on activity
func (s *APIServer) calculateUserRiskScore(profile *UEBAProfileOpenSearch, activityData map[string]interface{}) float64 {
	score := 0.0

	// Base score from anomaly count
	score += float64(profile.AnomalyCount) * 5

	// Check severity of events
	if severities, ok := activityData["severities"].(map[string]interface{}); ok {
		if buckets, ok := severities["buckets"].([]interface{}); ok {
			for _, b := range buckets {
				bucket := b.(map[string]interface{})
				sev := bucket["key"].(string)
				count := bucket["doc_count"].(float64)
				switch strings.ToUpper(sev) {
				case "CRITICAL":
					score += count * 20
				case "HIGH":
					score += count * 10
				case "MEDIUM":
					score += count * 3
				}
			}
		}
	}

	// Check failed logins
	score += float64(profile.FailedLoginCount) * 2

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return math.Round(score*10) / 10
}

// detectUserAnomalies detects anomalies in user behavior
func (s *APIServer) detectUserAnomalies(profile *UEBAProfileOpenSearch, activityData map[string]interface{}) []*UEBAAnomalyOpenSearch {
	anomalies := []*UEBAAnomalyOpenSearch{}

	// Check for unusual activity hours
	if hours, ok := activityData["hours"].(map[string]interface{}); ok {
		if buckets, ok := hours["buckets"].([]interface{}); ok {
			for _, hb := range buckets {
				hourBucket := hb.(map[string]interface{})
				hour := int(hourBucket["key"].(float64))
				count := int(hourBucket["doc_count"].(float64))

				// Unusual hours (midnight to 5am)
				if (hour >= 0 && hour <= 5) && count > 10 {
					anomaly := &UEBAAnomalyOpenSearch{
						ID:            uuid.New().String(),
						UserID:        profile.UserID,
						Username:      profile.Username,
						AnomalyType:   "unusual_hours",
						Severity:      "medium",
						Score:         60,
						Description:   fmt.Sprintf("Atividade incomum detectada às %d:00 (%d eventos)", hour, count),
						DetectedAt:    time.Now(),
						ExpectedValue: "Horário comercial (8-18h)",
						ActualValue:   fmt.Sprintf("%d:00", hour),
						Deviation:     100,
						Status:        "new",
						MITRETechnique: "T1078",
						Details: map[string]interface{}{
							"hour":        hour,
							"event_count": count,
						},
					}
					anomalies = append(anomalies, anomaly)
				}
			}
		}
	}

	// Check for high severity events
	if severities, ok := activityData["severities"].(map[string]interface{}); ok {
		if buckets, ok := severities["buckets"].([]interface{}); ok {
			for _, b := range buckets {
				bucket := b.(map[string]interface{})
				sev := strings.ToUpper(bucket["key"].(string))
				count := int(bucket["doc_count"].(float64))

				if sev == "CRITICAL" && count > 5 {
					anomaly := &UEBAAnomalyOpenSearch{
						ID:            uuid.New().String(),
						UserID:        profile.UserID,
						Username:      profile.Username,
						AnomalyType:   "high_severity_activity",
						Severity:      "high",
						Score:         80,
						Description:   fmt.Sprintf("Múltiplos eventos críticos detectados (%d eventos)", count),
						DetectedAt:    time.Now(),
						ExpectedValue: "< 5 eventos críticos",
						ActualValue:   fmt.Sprintf("%d eventos", count),
						Deviation:     float64(count-5) / 5 * 100,
						Status:        "new",
						MITRETechnique: "T1059",
						Details: map[string]interface{}{
							"severity":    sev,
							"event_count": count,
						},
					}
					anomalies = append(anomalies, anomaly)
				}
			}
		}
	}

	return anomalies
}

// saveUserProfile saves a user profile to OpenSearch
func (s *APIServer) saveUserProfile(profile *UEBAProfileOpenSearch) {
	profile.UpdatedAt = time.Now()
	profileJSON, _ := json.Marshal(profile)

	res, err := s.opensearch.Index(
		uebaProfilesIndex,
		strings.NewReader(string(profileJSON)),
		s.opensearch.Index.WithDocumentID(profile.ID),
	)
	if err != nil {
		log.Printf("❌ UEBA: Error saving profile %s: %v", profile.Username, err)
		return
	}
	res.Body.Close()
}

// saveAnomaly saves an anomaly to OpenSearch
func (s *APIServer) saveAnomaly(anomaly *UEBAAnomalyOpenSearch) {
	anomalyJSON, _ := json.Marshal(anomaly)

	res, err := s.opensearch.Index(
		uebaAnomaliesIndex,
		strings.NewReader(string(anomalyJSON)),
		s.opensearch.Index.WithDocumentID(anomaly.ID),
	)
	if err != nil {
		log.Printf("❌ UEBA: Error saving anomaly: %v", err)
		return
	}
	res.Body.Close()
}

// handleListUserProfilesOpenSearch lists user profiles from OpenSearch with filtering and pagination
func (s *APIServer) handleListUserProfilesOpenSearch(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"users":  []UEBAProfileOpenSearch{},
			"total":  0,
			"source": "opensearch",
		})
		return
	}

	// Parse query parameters
	riskLevel := c.Query("risk_level")
	riskLevels := c.QueryArray("risk_levels")
	search := c.Query("search")
	sortBy := c.DefaultQuery("sort_by", "risk_score")
	sortOrder := c.DefaultQuery("sort_order", "desc")
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")
	
	limit := 100
	offset := 0
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
		limit = l
	}
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	must := []map[string]interface{}{}
	should := []map[string]interface{}{}
	
	// Risk level filter (single or multiple)
	if riskLevel != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"risk_level": strings.ToLower(riskLevel)},
		})
	} else if len(riskLevels) > 0 {
		riskShould := []map[string]interface{}{}
		for _, rl := range riskLevels {
			riskShould = append(riskShould, map[string]interface{}{
				"term": map[string]interface{}{"risk_level": strings.ToLower(rl)},
			})
		}
		must = append(must, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": riskShould,
				"minimum_should_match": 1,
			},
		})
	}
	
	// Search filter (username, email, department)
	if search != "" {
		searchLower := strings.ToLower(search)
		should = append(should,
			map[string]interface{}{"wildcard": map[string]interface{}{"username": "*" + searchLower + "*"}},
			map[string]interface{}{"wildcard": map[string]interface{}{"email": "*" + searchLower + "*"}},
			map[string]interface{}{"wildcard": map[string]interface{}{"department": "*" + searchLower + "*"}},
			map[string]interface{}{"match_phrase_prefix": map[string]interface{}{"username": search}},
		)
		must = append(must, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": should,
				"minimum_should_match": 1,
			},
		})
	}

	// Build sort
	sortField := "risk_score"
	switch sortBy {
	case "username":
		sortField = "username"
	case "last_activity":
		sortField = "last_activity"
	case "anomaly_count":
		sortField = "anomaly_count"
	case "total_activities":
		sortField = "total_activities"
	}
	
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	query := map[string]interface{}{
		"size":             limit,
		"from":             offset,
		"track_total_hits": true,
		"sort": []map[string]interface{}{
			{sortField: map[string]interface{}{"order": sortOrder}},
		},
	}

	if len(must) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{"must": must},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaProfilesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ Error searching profiles: %v", err)
		c.JSON(http.StatusOK, gin.H{
			"users":  []UEBAProfileOpenSearch{},
			"total":  0,
			"source": "opensearch",
		})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	profiles := []UEBAProfileOpenSearch{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			total = int(totalObj["value"].(float64))
		}
		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				hitMap := hit.(map[string]interface{})
				source := hitMap["_source"].(map[string]interface{})
				profile := parseUEBAProfile(source)
				if docID, ok := hitMap["_id"].(string); ok {
					profile.ID = docID
				}
				profiles = append(profiles, *profile)
			}
		}
	}

	// Return with pagination info
	c.JSON(http.StatusOK, gin.H{
		"users":   profiles,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"source":  "opensearch",
	})
}

// handleGetUserProfileOpenSearch returns a detailed profile using OpenSearch data
func (s *APIServer) handleGetUserProfileOpenSearch(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenSearch não está configurado"})
		return
	}

	identifier := c.Param("id")
	profile, err := s.fetchUEBAProfile(identifier)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Perfil não encontrado"})
		return
	}

	anomalies, err := s.fetchUserAnomalies(profile.Username, 5)
	if err != nil {
		log.Printf("⚠️ UEBA: Falha ao carregar anomalias do usuário %s: %v", profile.Username, err)
	}

	userProfile := convertProfileToUserProfile(profile, anomalies)

	activities, err := s.fetchUserActivities(profile, 50)
	if err != nil {
		log.Printf("⚠️ UEBA: Falha ao carregar atividades do usuário %s: %v", profile.Username, err)
	}

	c.JSON(http.StatusOK, gin.H{
		"profile":    userProfile,
		"activities": activities,
	})
}

// handleListAnomaliesOpenSearch lists anomalies from OpenSearch with filtering and pagination
func (s *APIServer) handleListAnomaliesOpenSearch(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"anomalies": []UEBAAnomalyOpenSearch{},
			"total":     0,
			"source":    "opensearch",
		})
		return
	}

	// Parse query parameters
	status := c.Query("status")
	statuses := c.QueryArray("statuses")
	severity := c.Query("severity")
	severities := c.QueryArray("severities")
	username := c.Query("username")
	anomalyType := c.Query("type")
	search := c.Query("search")
	sortBy := c.DefaultQuery("sort_by", "detected_at")
	sortOrder := c.DefaultQuery("sort_order", "desc")
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")
	
	limit := 100
	offset := 0
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
		limit = l
	}
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	must := []map[string]interface{}{}
	
	// Status filter (single or multiple)
	if status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"status": status},
		})
	} else if len(statuses) > 0 {
		statusShould := []map[string]interface{}{}
		for _, s := range statuses {
			statusShould = append(statusShould, map[string]interface{}{
				"term": map[string]interface{}{"status": s},
			})
		}
		must = append(must, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": statusShould,
				"minimum_should_match": 1,
			},
		})
	}
	
	// Severity filter (single or multiple)
	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"severity": severity},
		})
	} else if len(severities) > 0 {
		sevShould := []map[string]interface{}{}
		for _, s := range severities {
			sevShould = append(sevShould, map[string]interface{}{
				"term": map[string]interface{}{"severity": s},
			})
		}
		must = append(must, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": sevShould,
				"minimum_should_match": 1,
			},
		})
	}
	
	if username != "" {
		must = append(must, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"term": map[string]interface{}{"username": username}},
					{"term": map[string]interface{}{"user_id": username}},
					{"wildcard": map[string]interface{}{"username": "*" + strings.ToLower(username) + "*"}},
				},
				"minimum_should_match": 1,
			},
		})
	}
	
	if anomalyType != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"anomaly_type": anomalyType},
		})
	}
	
	// General search
	if search != "" {
		searchLower := strings.ToLower(search)
		must = append(must, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"wildcard": map[string]interface{}{"username": "*" + searchLower + "*"}},
					{"wildcard": map[string]interface{}{"description": "*" + searchLower + "*"}},
					{"match_phrase_prefix": map[string]interface{}{"description": search}},
				},
				"minimum_should_match": 1,
			},
		})
	}

	// Build sort
	sortField := "detected_at"
	switch sortBy {
	case "score":
		sortField = "score"
	case "severity":
		sortField = "severity"
	case "username":
		sortField = "username"
	case "status":
		sortField = "status"
	}
	
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	query := map[string]interface{}{
		"size":             limit,
		"from":             offset,
		"track_total_hits": true,
		"sort": []map[string]interface{}{
			{sortField: map[string]interface{}{"order": sortOrder}},
		},
	}

	if len(must) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{"must": must},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ Error searching anomalies: %v", err)
		c.JSON(http.StatusOK, gin.H{
			"anomalies": []UEBAAnomalyOpenSearch{},
			"total":     0,
			"source":    "opensearch",
		})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	anomalies := []UEBAAnomalyOpenSearch{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			total = int(totalObj["value"].(float64))
		}
		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				hitMap := hit.(map[string]interface{})
				source := hitMap["_source"].(map[string]interface{})
				anomaly := parseUEBAAnomaly(source)
				if docID, ok := hitMap["_id"].(string); ok {
					anomaly.ID = docID
				}
				anomalies = append(anomalies, *anomaly)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"anomalies": anomalies,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
		"source":    "opensearch",
	})
}

func (s *APIServer) fetchUEBAProfile(identifier string) (*UEBAProfileOpenSearch, error) {
	shouldQueries := buildIdentifierQuery(identifier)
	if len(shouldQueries) == 0 {
		return nil, fmt.Errorf("identificador inválido")
	}

	query := map[string]interface{}{
		"size": 1,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should":               shouldQueries,
				"minimum_should_match": 1,
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaProfilesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("OpenSearch error: %s", res.String())
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsArr, ok := hits["hits"].([]interface{}); ok && len(hitsArr) > 0 {
			hit := hitsArr[0].(map[string]interface{})
			source := hit["_source"].(map[string]interface{})
			return parseUEBAProfile(source), nil
		}
	}

	return nil, fmt.Errorf("perfil não encontrado")
}

func convertProfileToUserProfile(profile *UEBAProfileOpenSearch, anomalies []Anomaly) UserProfile {
	riskScore := int(math.Round(profile.RiskScore))
	if riskScore > 100 {
		riskScore = 100
	}

	baseline := UserBaseline{
		AvgLoginHour:        profile.AvgLoginHour,
		CommonLocations:     profile.CommonLocations,
		CommonDevices:       profile.CommonDevices,
		AvgSessionDuration:  int(profile.AvgEventsPerDay),
		AvgDataVolume:       profile.DataAccessVolume,
		TypicalWorkHours:    profile.TypicalWorkHours,
		TypicalWorkDays:     []int{1, 2, 3, 4, 5},
		BaselineEstablished: profile.FirstSeen,
	}

	peerGroup := ""
	if profile.Metadata != nil {
		if pg, ok := profile.Metadata["peer_group"].(string); ok {
			peerGroup = pg
		}
	}

	return UserProfile{
		UserID:          firstNonEmpty(profile.UserID, profile.Username),
		Username:        profile.Username,
		Email:           profile.Email,
		Department:      profile.Department,
		RiskScore:       riskScore,
		RiskLevel:       profile.RiskLevel,
		LastActivity:    profile.LastActivity,
		TotalActivities: profile.TotalActivities,
		AnomalyCount:    profile.AnomalyCount,
		Baseline:        baseline,
		RecentAnomalies: anomalies,
		PeerGroup:       peerGroup,
		Tags:            profile.Tags,
	}
}

func (s *APIServer) fetchUserAnomalies(username string, limit int) ([]Anomaly, error) {
	if limit <= 0 {
		limit = 5
	}

	shouldQueries := buildIdentifierQuery(username)
	if len(shouldQueries) == 0 {
		return []Anomaly{}, nil
	}

	query := map[string]interface{}{
		"size": limit,
		"sort": []map[string]interface{}{
			{"detected_at": map[string]interface{}{"order": "desc"}},
		},
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should":               shouldQueries,
				"minimum_should_match": 1,
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("OpenSearch error: %s", res.String())
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	anomalies := []Anomaly{}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsArr, ok := hits["hits"].([]interface{}); ok {
			for _, h := range hitsArr {
				hit := h.(map[string]interface{})
				source := hit["_source"].(map[string]interface{})
				parsed := parseUEBAAnomaly(source)
				anomalies = append(anomalies, Anomaly{
					ID:             parsed.ID,
					UserID:         parsed.UserID,
					Username:       parsed.Username,
					Type:           parsed.AnomalyType,
					Severity:       parsed.Severity,
					Score:          int(math.Round(parsed.Score)),
					Description:    parsed.Description,
					DetectedAt:     parsed.DetectedAt,
					EventID:        parsed.EventID,
					Details:        parsed.Details,
					Status:         parsed.Status,
					AssignedCase:   parsed.RelatedAlertID,
					InvestigatedBy: parsed.InvestigatedBy,
				})
			}
		}
	}

	return anomalies, nil
}

func (s *APIServer) fetchUserActivities(profile *UEBAProfileOpenSearch, limit int) ([]UserActivity, error) {
	if limit <= 0 {
		limit = 50
	}

	identifier := firstNonEmpty(profile.Username, profile.UserID)
	should := []map[string]interface{}{
		{"term": map[string]interface{}{"user.keyword": identifier}},
		{"term": map[string]interface{}{"username.keyword": identifier}},
	}
	if profile.UserID != "" && profile.UserID != profile.Username {
		should = append(should,
			map[string]interface{}{"term": map[string]interface{}{"user.keyword": profile.UserID}},
			map[string]interface{}{"term": map[string]interface{}{"username.keyword": profile.UserID}},
		)
	}

	query := map[string]interface{}{
		"size": limit,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should":               should,
				"minimum_should_match": 1,
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("OpenSearch error: %s", res.String())
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	activities := []UserActivity{}
	userID := firstNonEmpty(profile.UserID, profile.Username)

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsArr, ok := hits["hits"].([]interface{}); ok {
			for _, h := range hitsArr {
				hit := h.(map[string]interface{})
				source := hit["_source"].(map[string]interface{})

				activity := UserActivity{
					ID:         getStrVal(source, "id"),
					UserID:     userID,
					Username:   profile.Username,
					Source:     getStrVal(source, "source"),
					ActivityType: getStrVal(source, "type"),
					Details:    map[string]interface{}{},
				}

				if ts := getStrVal(source, "timestamp"); ts != "" {
					if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
						activity.Timestamp = parsed
					} else {
						activity.Timestamp = time.Now()
					}
				}

				severity := strings.ToUpper(getStrVal(source, "severity"))
				activity.RiskScore = mapSeverityToRiskScore(severity)
				if severity == "CRITICAL" || severity == "HIGH" {
					activity.IsAnomaly = true
				}

				if details, ok := source["details"].(map[string]interface{}); ok {
					activity.Details = details
					if region, ok := details["aws_region"].(string); ok && activity.Location == "" {
						activity.Location = region
					}
					if ip, ok := details["source_ip"].(string); ok && activity.Location == "" {
						activity.Location = ip
					}
					if device, ok := details["user_agent"].(string); ok {
						activity.Device = device
					}
				}

				if activity.Location == "" {
					activity.Location = getStrVal(source, "source_ip")
				}

				activities = append(activities, activity)
			}
		}
	}

	return activities, nil
}

func mapSeverityToRiskScore(severity string) int {
	switch severity {
	case "CRITICAL":
		return 95
	case "HIGH":
		return 75
	case "MEDIUM":
		return 45
	case "LOW":
		return 20
	default:
		return 10
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// handleGetUEBAStatsOpenSearch returns UEBA statistics
func (s *APIServer) handleGetUEBAStatsOpenSearch(c *gin.Context) {
	stats := gin.H{
		"total_users":         0,
		"monitored_users":     0,
		"high_risk_users":     0,
		"critical_risk_users": 0,
		"anomalies_detected":  0,
		"anomalies_last_24h":  0,
		"avg_risk_score":      0.0,
		"baseline_coverage":   0.0,
	}

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": stats, "source": "opensearch"})
		return
	}

	// Get profile stats
	profileQuery := `{
		"size": 0,
		"aggs": {
			"total": { "value_count": { "field": "username" } },
			"by_risk": { "terms": { "field": "risk_level", "size": 10 } },
			"avg_risk": { "avg": { "field": "risk_score" } },
			"with_baseline": { "filter": { "term": { "baseline_established": true } } }
		}
	}`

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaProfilesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(profileQuery)),
	)
	if err == nil && !res.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res.Body).Decode(&result)
		res.Body.Close()

		if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
			if total, ok := aggs["total"].(map[string]interface{}); ok {
				stats["total_users"] = int(total["value"].(float64))
				stats["monitored_users"] = int(total["value"].(float64))
			}
			if avgRisk, ok := aggs["avg_risk"].(map[string]interface{}); ok {
				if v, ok := avgRisk["value"].(float64); ok {
					stats["avg_risk_score"] = math.Round(v*10) / 10
				}
			}
			if byRisk, ok := aggs["by_risk"].(map[string]interface{}); ok {
				if buckets, ok := byRisk["buckets"].([]interface{}); ok {
					for _, b := range buckets {
						bucket := b.(map[string]interface{})
						level := bucket["key"].(string)
						count := int(bucket["doc_count"].(float64))
						if level == "high" {
							stats["high_risk_users"] = count
						} else if level == "critical" {
							stats["critical_risk_users"] = count
						}
					}
				}
			}
		}
	}

	// Get anomaly stats
	anomalyQuery := `{
		"size": 0,
		"aggs": {
			"total": { "value_count": { "field": "id" } },
			"last_24h": {
				"filter": {
					"range": { "detected_at": { "gte": "now-24h" } }
				}
			}
		}
	}`

	res2, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(anomalyQuery)),
	)
	if err == nil && !res2.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res2.Body).Decode(&result)
		res2.Body.Close()

		if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
			if total, ok := aggs["total"].(map[string]interface{}); ok {
				stats["anomalies_detected"] = int(total["value"].(float64))
			}
			if last24h, ok := aggs["last_24h"].(map[string]interface{}); ok {
				stats["anomalies_last_24h"] = int(last24h["doc_count"].(float64))
			}
		}
	}

	// Return stats directly (frontend expects this format)
	c.JSON(http.StatusOK, stats)
}

// handleGetUEBADashboardReal returns UEBA dashboard with real-time data
func (s *APIServer) handleGetUEBADashboardReal(c *gin.Context) {
	dashboard := gin.H{
		"stats": gin.H{
			"total_users":         0,
			"monitored_users":     0,
			"high_risk_users":     0,
			"critical_risk_users": 0,
			"anomalies_detected":  0,
			"anomalies_last_24h":  0,
			"avg_risk_score":      0.0,
			"baseline_coverage":   0.0,
		},
		"top_risk_users":   []map[string]interface{}{},
		"recent_anomalies": []map[string]interface{}{},
		"risk_trends":      []map[string]interface{}{},
		"anomaly_types":    []map[string]interface{}{},
	}

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": dashboard, "source": "opensearch"})
		return
	}

	// Get stats from profiles
	profileQuery := `{
		"size": 0,
		"aggs": {
			"total": { "value_count": { "field": "username" } },
			"by_risk": { "terms": { "field": "risk_level", "size": 10 } },
			"avg_risk": { "avg": { "field": "risk_score" } }
		}
	}`

	res, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaProfilesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(profileQuery)),
	)
	if res != nil && !res.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res.Body).Decode(&result)
		res.Body.Close()

		stats := dashboard["stats"].(gin.H)
		if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
			if total, ok := aggs["total"].(map[string]interface{}); ok {
				stats["total_users"] = int(total["value"].(float64))
				stats["monitored_users"] = int(total["value"].(float64))
			}
			if avgRisk, ok := aggs["avg_risk"].(map[string]interface{}); ok {
				if v, ok := avgRisk["value"].(float64); ok {
					stats["avg_risk_score"] = math.Round(v*10) / 10
				}
			}
			if byRisk, ok := aggs["by_risk"].(map[string]interface{}); ok {
				if buckets, ok := byRisk["buckets"].([]interface{}); ok {
					for _, b := range buckets {
						bucket := b.(map[string]interface{})
						level := bucket["key"].(string)
						count := int(bucket["doc_count"].(float64))
						if level == "high" {
							stats["high_risk_users"] = count
						} else if level == "critical" {
							stats["critical_risk_users"] = count
						}
					}
				}
			}
		}
	}

	// Get top risk users
	topUsersQuery := `{
		"size": 10,
		"sort": [{ "risk_score": { "order": "desc" } }]
	}`

	res2, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaProfilesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(topUsersQuery)),
	)
	if res2 != nil && !res2.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res2.Body).Decode(&result)
		res2.Body.Close()

		topUsers := []map[string]interface{}{}
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if hitsArr, ok := hits["hits"].([]interface{}); ok {
				for _, h := range hitsArr {
					hit := h.(map[string]interface{})
					source := hit["_source"].(map[string]interface{})
					topUsers = append(topUsers, map[string]interface{}{
						"user_id":    getStrVal(source, "user_id"),
						"username":   getStrVal(source, "username"),
						"risk_score": source["risk_score"],
						"risk_level": getStrVal(source, "risk_level"),
						"anomalies":  source["anomaly_count"],
					})
				}
			}
		}
		dashboard["top_risk_users"] = topUsers
	}

	// Get recent anomalies
	anomaliesQuery := `{
		"size": 10,
		"sort": [{ "detected_at": { "order": "desc" } }]
	}`

	res3, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(anomaliesQuery)),
	)
	if res3 != nil && !res3.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res3.Body).Decode(&result)
		res3.Body.Close()

		recentAnomalies := []map[string]interface{}{}
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				stats := dashboard["stats"].(gin.H)
				stats["anomalies_detected"] = int(total["value"].(float64))
			}
			if hitsArr, ok := hits["hits"].([]interface{}); ok {
				for _, h := range hitsArr {
					hit := h.(map[string]interface{})
					source := hit["_source"].(map[string]interface{})
					recentAnomalies = append(recentAnomalies, map[string]interface{}{
						"id":           getStrVal(source, "id"),
						"username":     getStrVal(source, "username"),
						"type":         getStrVal(source, "anomaly_type"),
						"severity":     getStrVal(source, "severity"),
						"score":        source["score"],
						"description":  getStrVal(source, "description"),
						"detected_at":  getStrVal(source, "detected_at"),
						"status":       getStrVal(source, "status"),
					})
				}
			}
		}
		dashboard["recent_anomalies"] = recentAnomalies
	}

	// Get anomaly type distribution
	anomalyTypesQuery := `{
		"size": 0,
		"aggs": {
			"by_type": { "terms": { "field": "anomaly_type", "size": 10 } }
		}
	}`

	res4, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex(uebaAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(anomalyTypesQuery)),
	)
	if res4 != nil && !res4.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res4.Body).Decode(&result)
		res4.Body.Close()

		anomalyTypes := []map[string]interface{}{}
		if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
			if byType, ok := aggs["by_type"].(map[string]interface{}); ok {
				if buckets, ok := byType["buckets"].([]interface{}); ok {
					for _, b := range buckets {
						bucket := b.(map[string]interface{})
						anomalyTypes = append(anomalyTypes, map[string]interface{}{
							"type":  bucket["key"],
							"count": int(bucket["doc_count"].(float64)),
						})
					}
				}
			}
		}
		dashboard["anomaly_types"] = anomalyTypes
	}

	// Return in format expected by frontend (no wrapper)
	c.JSON(http.StatusOK, dashboard)
}

// Helper functions
func getRiskLevel(score float64) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func parseUEBAProfile(source map[string]interface{}) *UEBAProfileOpenSearch {
	profile := &UEBAProfileOpenSearch{
		ID:              getStrVal(source, "id"),
		UserID:          getStrVal(source, "user_id"),
		Username:        getStrVal(source, "username"),
		Email:           getStrVal(source, "email"),
		Department:      getStrVal(source, "department"),
		RiskLevel:       getStrVal(source, "risk_level"),
		CommonLocations: []string{},
		CommonDevices:   []string{},
		CommonSourceIPs: []string{},
		TypicalWorkHours: []int{},
		Tags:            []string{},
		Metadata:        map[string]interface{}{},
	}

	if v, ok := source["risk_score"].(float64); ok {
		profile.RiskScore = v
	}
	if v, ok := source["total_activities"].(float64); ok {
		profile.TotalActivities = int(v)
	}
	if v, ok := source["anomaly_count"].(float64); ok {
		profile.AnomalyCount = int(v)
	}
	if v, ok := source["baseline_established"].(bool); ok {
		profile.BaselineEstablished = v
	}

	return profile
}

func parseUEBAAnomaly(source map[string]interface{}) *UEBAAnomalyOpenSearch {
	anomaly := &UEBAAnomalyOpenSearch{
		ID:              getStrVal(source, "id"),
		UserID:          getStrVal(source, "user_id"),
		Username:        getStrVal(source, "username"),
		AnomalyType:     getStrVal(source, "anomaly_type"),
		Severity:        getStrVal(source, "severity"),
		Description:     getStrVal(source, "description"),
		EventID:         getStrVal(source, "event_id"),
		SourceIP:        getStrVal(source, "source_ip"),
		Location:        getStrVal(source, "location"),
		Device:          getStrVal(source, "device"),
		ExpectedValue:   getStrVal(source, "expected_value"),
		ActualValue:     getStrVal(source, "actual_value"),
		Status:          getStrVal(source, "status"),
		InvestigatedBy:  getStrVal(source, "investigated_by"),
		ResolutionNotes: getStrVal(source, "resolution_notes"),
		MITRETechnique:  getStrVal(source, "mitre_technique"),
		Details:         map[string]interface{}{},
	}

	if v, ok := source["score"].(float64); ok {
		anomaly.Score = v
	}
	if v, ok := source["deviation"].(float64); ok {
		anomaly.Deviation = v
	}
	if detectedStr := getStrVal(source, "detected_at"); detectedStr != "" {
		if t, err := time.Parse(time.RFC3339, detectedStr); err == nil {
			anomaly.DetectedAt = t
		}
	}

	return anomaly
}

