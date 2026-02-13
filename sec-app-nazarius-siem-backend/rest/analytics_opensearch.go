package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const mlAnomaliesIndex = "siem-ml-anomalies"
const mlPredictionsIndex = "siem-ml-predictions"

// MLAnomalyOpenSearch represents an ML-detected anomaly
type MLAnomalyOpenSearch struct {
	ID              string                 `json:"id"`
	Timestamp       time.Time              `json:"timestamp"`
	EntityType      string                 `json:"entity_type"`
	EntityID        string                 `json:"entity_id"`
	EntityName      string                 `json:"entity_name"`
	AnomalyType     string                 `json:"anomaly_type"`
	Severity        string                 `json:"severity"`
	Confidence      float64                `json:"confidence"`
	AnomalyScore    float64                `json:"anomaly_score"`
	Baseline        float64                `json:"baseline"`
	CurrentValue    float64                `json:"current_value"`
	Deviation       float64                `json:"deviation"`
	Description     string                 `json:"description"`
	Indicators      []string               `json:"indicators"`
	RelatedEvents   int                    `json:"related_events"`
	Status          string                 `json:"status"`
	AssignedTo      string                 `json:"assigned_to"`
	MITRETechnique  string                 `json:"mitre_technique"`
	DetectionMethod string                 `json:"detection_method"`
	Details         map[string]interface{} `json:"details"`
}

// ThreatPredictionOpenSearch represents a threat prediction
type ThreatPredictionOpenSearch struct {
	ID              string    `json:"id"`
	PredictionType  string    `json:"prediction_type"`
	TargetType      string    `json:"target_type"`
	TargetID        string    `json:"target_id"`
	TargetName      string    `json:"target_name"`
	Probability     float64   `json:"probability"`
	Severity        string    `json:"severity"`
	TimeWindow      string    `json:"time_window"`
	Indicators      []string  `json:"indicators"`
	MITRETechniques []string  `json:"mitre_techniques"`
	Recommendations []string  `json:"recommendations"`
	Confidence      float64   `json:"confidence"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Status          string    `json:"status"`
}

// EnsureMLIndices creates ML indices if they don't exist
func (s *APIServer) EnsureMLIndices() {
	if s.opensearch == nil {
		return
	}

	// ML Anomalies index
	anomaliesMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"timestamp": { "type": "date" },
				"entity_type": { "type": "keyword" },
				"entity_id": { "type": "keyword" },
				"entity_name": { "type": "keyword" },
				"anomaly_type": { "type": "keyword" },
				"severity": { "type": "keyword" },
				"confidence": { "type": "float" },
				"anomaly_score": { "type": "float" },
				"baseline": { "type": "float" },
				"current_value": { "type": "float" },
				"deviation": { "type": "float" },
				"description": { "type": "text" },
				"indicators": { "type": "keyword" },
				"related_events": { "type": "integer" },
				"status": { "type": "keyword" },
				"assigned_to": { "type": "keyword" },
				"mitre_technique": { "type": "keyword" },
				"detection_method": { "type": "keyword" }
			}
		}
	}`

	res, err := s.opensearch.Indices.Exists([]string{mlAnomaliesIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			mlAnomaliesIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(anomaliesMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", mlAnomaliesIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", mlAnomaliesIndex)
		}
	}

	// Predictions index
	predictionsMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"prediction_type": { "type": "keyword" },
				"target_type": { "type": "keyword" },
				"target_id": { "type": "keyword" },
				"target_name": { "type": "keyword" },
				"probability": { "type": "float" },
				"severity": { "type": "keyword" },
				"time_window": { "type": "keyword" },
				"indicators": { "type": "keyword" },
				"mitre_techniques": { "type": "keyword" },
				"recommendations": { "type": "text" },
				"confidence": { "type": "float" },
				"created_at": { "type": "date" },
				"expires_at": { "type": "date" },
				"status": { "type": "keyword" }
			}
		}
	}`

	res, err = s.opensearch.Indices.Exists([]string{mlPredictionsIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			mlPredictionsIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(predictionsMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", mlPredictionsIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", mlPredictionsIndex)
		}
	}
}

// StartMLAnalyzer starts the background ML analyzer
func (s *APIServer) StartMLAnalyzer() {
	log.Println("🤖 Starting ML Analytics Analyzer...")

	go func() {
		// Initial analysis after 15 seconds
		time.Sleep(15 * time.Second)
		s.runMLAnalysis()

		// Run every 10 minutes
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			s.runMLAnalysis()
		}
	}()
}

// handleForceMLAnalysis forces immediate ML analysis
func (s *APIServer) handleForceMLAnalysis(c *gin.Context) {
	log.Println("🔄 Forcing ML analysis...")
	s.runMLAnalysis()
	s.handleGetMLStatsOpenSearch(c)
}

// handleCleanupDuplicateAnomalies removes duplicate anomalies, keeping only the most recent
func (s *APIServer) handleCleanupDuplicateAnomalies(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "OpenSearch not connected",
		})
		return
	}
	
	log.Println("🧹 Starting cleanup of duplicate anomalies...")
	
	// Get all anomalies grouped by entity_id + anomaly_type
	query := `{
		"size": 0,
		"aggs": {
			"by_entity": {
				"composite": {
					"size": 1000,
					"sources": [
						{ "entity_id": { "terms": { "field": "entity_id" } } },
						{ "anomaly_type": { "terms": { "field": "anomaly_type" } } }
					]
				},
				"aggs": {
					"docs": {
						"top_hits": {
							"size": 100,
							"sort": [{ "timestamp": "desc" }],
							"_source": ["id"]
						}
					}
				}
			}
		}
	}`
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(mlAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)
	
	deletedCount := 0
	keptCount := 0
	
	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if byEntity, ok := aggs["by_entity"].(map[string]interface{}); ok {
			if buckets, ok := byEntity["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					if docs, ok := bucket["docs"].(map[string]interface{}); ok {
						if hits, ok := docs["hits"].(map[string]interface{}); ok {
							if hitList, ok := hits["hits"].([]interface{}); ok {
								// Keep the first one (most recent), delete the rest
								for i, hit := range hitList {
									if i == 0 {
										keptCount++
										continue
									}
									
									// Delete this duplicate
									hitMap := hit.(map[string]interface{})
									docID := hitMap["_id"].(string)
									
									delRes, delErr := s.opensearch.Delete(
										mlAnomaliesIndex,
										docID,
									)
									if delErr == nil && !delRes.IsError() {
										deletedCount++
									}
									if delRes != nil {
										delRes.Body.Close()
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	log.Printf("🧹 Cleanup complete: kept %d, deleted %d duplicates", keptCount, deletedCount)
	
	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"message":       fmt.Sprintf("Cleanup complete: kept %d unique anomalies, deleted %d duplicates", keptCount, deletedCount),
		"kept":          keptCount,
		"deleted":       deletedCount,
	})
}

// handleMLDiagnostics returns diagnostic information about ML Analytics
func (s *APIServer) handleMLDiagnostics(c *gin.Context) {
	diag := gin.H{
		"opensearch_connected": s.opensearch != nil,
		"indices": gin.H{
			"anomalies_index":   mlAnomaliesIndex,
			"predictions_index": mlPredictionsIndex,
		},
		"anomalies_count":   0,
		"predictions_count": 0,
		"events_last_24h":   0,
	}
	
	if s.opensearch == nil {
		c.JSON(http.StatusOK, diag)
		return
	}
	
	// Check events count
	eventsQuery := `{
		"size": 0,
		"query": {
			"range": { "timestamp": { "gte": "now-24h" } }
		}
	}`
	
	res, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(eventsQuery)),
	)
	if res != nil && !res.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res.Body).Decode(&result)
		res.Body.Close()
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				diag["events_last_24h"] = int(total["value"].(float64))
			}
		}
	}
	
	// Check ML anomalies count
	res2, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex(mlAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(`{"size": 0}`)),
	)
	if res2 != nil && !res2.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res2.Body).Decode(&result)
		res2.Body.Close()
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				diag["anomalies_count"] = int(total["value"].(float64))
			}
		}
	}
	
	// Check predictions count
	res3, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex(mlPredictionsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(`{"size": 0}`)),
	)
	if res3 != nil && !res3.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res3.Body).Decode(&result)
		res3.Body.Close()
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				diag["predictions_count"] = int(total["value"].(float64))
			}
		}
	}
	
	c.JSON(http.StatusOK, diag)
}

// runMLAnalysis performs ML-based anomaly detection
func (s *APIServer) runMLAnalysis() {
	if s.opensearch == nil {
		return
	}

	log.Println("🔍 ML Analytics: Running anomaly detection...")

	anomaliesDetected := 0
	predictionsCreated := 0

	// 1. Detect volume anomalies from multiple indices
	volumeAnomalies := s.detectVolumeAnomaliesMultiIndex()
	anomaliesDetected += len(volumeAnomalies)
	for _, a := range volumeAnomalies {
		s.saveMLAnomaly(a)
	}

	// 2. Detect alert severity anomalies
	alertAnomalies := s.detectAlertSeverityAnomalies()
	anomaliesDetected += len(alertAnomalies)
	for _, a := range alertAnomalies {
		s.saveMLAnomaly(a)
	}

	// 3. Detect vulnerability trends
	vulnAnomalies := s.detectVulnerabilityAnomalies()
	anomaliesDetected += len(vulnAnomalies)
	for _, a := range vulnAnomalies {
		s.saveMLAnomaly(a)
	}

	// 4. Detect source/type concentration anomalies
	sourceAnomalies := s.detectSourceAnomaliesMultiIndex()
	anomaliesDetected += len(sourceAnomalies)
	for _, a := range sourceAnomalies {
		s.saveMLAnomaly(a)
	}

	// 5. Generate threat predictions based on all data
	predictions := s.generateThreatPredictionsMultiIndex()
	predictionsCreated += len(predictions)
	for _, p := range predictions {
		s.savePrediction(p)
	}

	log.Printf("✅ ML Analytics: Detected %d anomalies, created %d predictions", anomaliesDetected, predictionsCreated)
}

// detectVolumeAnomaliesMultiIndex detects volume anomalies across multiple indices
func (s *APIServer) detectVolumeAnomaliesMultiIndex() []*MLAnomalyOpenSearch {
	anomalies := []*MLAnomalyOpenSearch{}
	
	// Check multiple indices
	indices := []struct {
		name        string
		displayName string
		timeField   string
	}{
		{"siem-alerts", "Alertas de Segurança", "timestamp"},
		{"siem-cloudtrail-events", "Eventos CloudTrail", "timestamp"},
		{"siem-fortinet-logs", "Logs Fortinet", "timestamp"},
		{"siem-cloudflare-waf", "Eventos Cloudflare WAF", "timestamp"},
		{"siem-ueba-anomalies", "Anomalias UEBA", "timestamp"},
	}
	
	for _, idx := range indices {
		// Check if index exists
		res, err := s.opensearch.Indices.Exists([]string{idx.name})
		if err != nil || res.StatusCode == 404 {
			continue
		}
		res.Body.Close()
		
		// Get hourly counts
		query := fmt.Sprintf(`{
			"size": 0,
			"query": {
				"range": {
					"%s": { "gte": "now-24h" }
				}
			},
			"aggs": {
				"hourly": {
					"date_histogram": {
						"field": "%s",
						"calendar_interval": "hour"
					}
				}
			}
		}`, idx.timeField, idx.timeField)
		
		searchRes, err := s.opensearch.Search(
			s.opensearch.Search.WithIndex(idx.name),
			s.opensearch.Search.WithBody(strings.NewReader(query)),
		)
		if err != nil {
			continue
		}
		
		var result map[string]interface{}
		json.NewDecoder(searchRes.Body).Decode(&result)
		searchRes.Body.Close()
		
		counts := []float64{}
		if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
			if hourly, ok := aggs["hourly"].(map[string]interface{}); ok {
				if buckets, ok := hourly["buckets"].([]interface{}); ok {
					for _, b := range buckets {
						bucket := b.(map[string]interface{})
						count := bucket["doc_count"].(float64)
						counts = append(counts, count)
					}
				}
			}
		}
		
		if len(counts) < 3 {
			continue
		}
		
		// Calculate statistics
		mean := calculateMean(counts)
		stdDev := calculateStdDev(counts, mean)
		lastCount := counts[len(counts)-1]
		
		if stdDev > 0 && mean > 0 {
			zScore := (lastCount - mean) / stdDev
			if math.Abs(zScore) > 2.0 {
				severity := "medium"
				if math.Abs(zScore) > 3.0 {
					severity = "high"
				}
				if math.Abs(zScore) > 4.0 {
					severity = "critical"
				}
				
				direction := "aumento"
				if zScore < 0 {
					direction = "queda"
				}
				
				anomaly := &MLAnomalyOpenSearch{
					ID:              uuid.New().String(),
					Timestamp:       time.Now(),
					EntityType:      "data_source",
					EntityID:        idx.name,
					EntityName:      idx.displayName,
					AnomalyType:     "volume",
					Severity:        severity,
					Confidence:      math.Min(math.Abs(zScore)*25, 99),
					AnomalyScore:    math.Abs(zScore) * 25,
					Baseline:        mean,
					CurrentValue:    lastCount,
					Deviation:       math.Abs(zScore) * 100 / 4,
					Description:     fmt.Sprintf("%s de volume em %s: %s de %.0f%% (média: %.0f, atual: %.0f)", strings.Title(direction), idx.displayName, direction, math.Abs(lastCount-mean)/mean*100, mean, lastCount),
					Indicators:      []string{"volume_anomaly", direction, idx.name},
					RelatedEvents:   int(lastCount),
					Status:          "new",
					DetectionMethod: "z_score_multi_index",
					MITRETechnique:  "T1499",
					Details: map[string]interface{}{
						"z_score":    zScore,
						"mean":       mean,
						"std_dev":    stdDev,
						"index":      idx.name,
						"hours_data": len(counts),
					},
				}
				anomalies = append(anomalies, anomaly)
			}
		}
	}
	
	return anomalies
}

// detectAlertSeverityAnomalies detects unusual alert severity patterns
func (s *APIServer) detectAlertSeverityAnomalies() []*MLAnomalyOpenSearch {
	anomalies := []*MLAnomalyOpenSearch{}
	
	query := `{
		"size": 0,
		"query": {
			"range": {
				"timestamp": { "gte": "now-1h" }
			}
		},
		"aggs": {
			"by_severity": {
				"terms": { "field": "severity.keyword", "size": 10 }
			},
			"total": {
				"value_count": { "field": "_id" }
			}
		}
	}`
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return anomalies
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)
	
	totalAlerts := 0.0
	criticalCount := 0
	highCount := 0
	
	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if total, ok := aggs["total"].(map[string]interface{}); ok {
			totalAlerts = total["value"].(float64)
		}
		if bySev, ok := aggs["by_severity"].(map[string]interface{}); ok {
			if buckets, ok := bySev["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					sev := strings.ToUpper(bucket["key"].(string))
					count := int(bucket["doc_count"].(float64))
					if sev == "CRITICAL" {
						criticalCount = count
					} else if sev == "HIGH" {
						highCount = count
					}
				}
			}
		}
	}
	
	if totalAlerts >= 10 {
		criticalRatio := float64(criticalCount) / totalAlerts
		highRatio := float64(highCount) / totalAlerts
		
		// Alert if critical > 15% or high > 30%
		if criticalRatio > 0.15 {
			anomaly := &MLAnomalyOpenSearch{
				ID:              uuid.New().String(),
				Timestamp:       time.Now(),
				EntityType:      "alert_distribution",
				EntityID:        "severity_critical",
				EntityName:      "Distribuição de Alertas Críticos",
				AnomalyType:     "distribution",
				Severity:        "high",
				Confidence:      math.Min(criticalRatio*200, 95),
				AnomalyScore:    criticalRatio * 100,
				Baseline:        5,
				CurrentValue:    criticalRatio * 100,
				Deviation:       (criticalRatio - 0.05) / 0.05 * 100,
				Description:     fmt.Sprintf("Alta concentração de alertas críticos: %.1f%% (%d de %.0f alertas na última hora)", criticalRatio*100, criticalCount, totalAlerts),
				Indicators:      []string{"critical_alert_spike", "severity_anomaly"},
				RelatedEvents:   criticalCount,
				Status:          "new",
				DetectionMethod: "severity_distribution",
				MITRETechnique:  "T1059",
				Details: map[string]interface{}{
					"critical_count":  criticalCount,
					"high_count":      highCount,
					"total_alerts":    totalAlerts,
					"critical_ratio":  criticalRatio,
					"high_ratio":      highRatio,
				},
			}
			anomalies = append(anomalies, anomaly)
		}
		
		if highRatio > 0.30 {
			anomaly := &MLAnomalyOpenSearch{
				ID:              uuid.New().String(),
				Timestamp:       time.Now(),
				EntityType:      "alert_distribution",
				EntityID:        "severity_high",
				EntityName:      "Distribuição de Alertas de Alta Severidade",
				AnomalyType:     "distribution",
				Severity:        "medium",
				Confidence:      math.Min(highRatio*150, 90),
				AnomalyScore:    highRatio * 80,
				Baseline:        15,
				CurrentValue:    highRatio * 100,
				Deviation:       (highRatio - 0.15) / 0.15 * 100,
				Description:     fmt.Sprintf("Alta concentração de alertas de severidade alta: %.1f%% (%d de %.0f alertas)", highRatio*100, highCount, totalAlerts),
				Indicators:      []string{"high_alert_spike", "severity_anomaly"},
				RelatedEvents:   highCount,
				Status:          "new",
				DetectionMethod: "severity_distribution",
				MITRETechnique:  "T1078",
				Details: map[string]interface{}{
					"high_count":   highCount,
					"total_alerts": totalAlerts,
					"high_ratio":   highRatio,
				},
			}
			anomalies = append(anomalies, anomaly)
		}
	}
	
	return anomalies
}

// detectVulnerabilityAnomalies detects vulnerability trends
func (s *APIServer) detectVulnerabilityAnomalies() []*MLAnomalyOpenSearch {
	anomalies := []*MLAnomalyOpenSearch{}
	
	query := `{
		"size": 0,
		"query": {
			"range": {
				"last_observed_at": { "gte": "now-24h" }
			}
		},
		"aggs": {
			"by_severity": {
				"terms": { "field": "severity.keyword", "size": 10 }
			},
			"new_critical": {
				"filter": {
					"bool": {
						"must": [
							{ "term": { "severity.keyword": "CRITICAL" } },
							{ "range": { "first_observed_at": { "gte": "now-24h" } } }
						]
					}
				}
			},
			"total": {
				"value_count": { "field": "_id" }
			}
		}
	}`
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-vulnerabilities"),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return anomalies
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)
	
	newCritical := 0
	totalVulns := 0.0
	
	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if total, ok := aggs["total"].(map[string]interface{}); ok {
			totalVulns = total["value"].(float64)
		}
		if newCrit, ok := aggs["new_critical"].(map[string]interface{}); ok {
			newCritical = int(newCrit["doc_count"].(float64))
		}
	}
	
	// Alert if more than 5 new critical vulnerabilities in 24h
	if newCritical >= 5 {
		anomaly := &MLAnomalyOpenSearch{
			ID:              uuid.New().String(),
			Timestamp:       time.Now(),
			EntityType:      "vulnerability",
			EntityID:        "new_critical_vulns",
			EntityName:      "Novas Vulnerabilidades Críticas",
			AnomalyType:     "trend",
			Severity:        "critical",
			Confidence:      math.Min(float64(newCritical)*10, 95),
			AnomalyScore:    float64(newCritical) * 10,
			Baseline:        2,
			CurrentValue:    float64(newCritical),
			Deviation:       float64(newCritical-2) / 2 * 100,
			Description:     fmt.Sprintf("Detectadas %d novas vulnerabilidades críticas nas últimas 24h (total: %.0f)", newCritical, totalVulns),
			Indicators:      []string{"new_critical_vulns", "vulnerability_spike"},
			RelatedEvents:   newCritical,
			Status:          "new",
			DetectionMethod: "vulnerability_trend",
			MITRETechnique:  "T1190",
			Details: map[string]interface{}{
				"new_critical":      newCritical,
				"total_vulns":       totalVulns,
				"time_window":       "24h",
			},
		}
		anomalies = append(anomalies, anomaly)
	}
	
	return anomalies
}

// detectSourceAnomaliesMultiIndex detects source concentration across indices
func (s *APIServer) detectSourceAnomaliesMultiIndex() []*MLAnomalyOpenSearch {
	anomalies := []*MLAnomalyOpenSearch{}
	
	// Check alerts by type
	query := `{
		"size": 0,
		"query": {
			"range": {
				"timestamp": { "gte": "now-1h" }
			}
		},
		"aggs": {
			"by_type": {
				"terms": { "field": "type.keyword", "size": 20 }
			},
			"by_source": {
				"terms": { "field": "source.keyword", "size": 20 }
			},
			"total": {
				"value_count": { "field": "_id" }
			}
		}
	}`
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return anomalies
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)
	
	totalAlerts := 0.0
	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if total, ok := aggs["total"].(map[string]interface{}); ok {
			totalAlerts = total["value"].(float64)
		}
		
		// Check type concentration
		if byType, ok := aggs["by_type"].(map[string]interface{}); ok {
			if buckets, ok := byType["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					alertType := bucket["key"].(string)
					count := bucket["doc_count"].(float64)
					
					ratio := count / totalAlerts
					if ratio > 0.5 && totalAlerts >= 20 {
						anomaly := &MLAnomalyOpenSearch{
							ID:              uuid.New().String(),
							Timestamp:       time.Now(),
							EntityType:      "alert_type",
							EntityID:        alertType,
							EntityName:      alertType,
							AnomalyType:     "concentration",
							Severity:        "medium",
							Confidence:      ratio * 100,
							AnomalyScore:    ratio * 80,
							Baseline:        20,
							CurrentValue:    ratio * 100,
							Deviation:       (ratio - 0.2) / 0.2 * 100,
							Description:     fmt.Sprintf("Concentração anômala de alertas do tipo '%s': %.1f%% do total (%.0f de %.0f alertas)", alertType, ratio*100, count, totalAlerts),
							Indicators:      []string{"type_concentration", alertType},
							RelatedEvents:   int(count),
							Status:          "new",
							DetectionMethod: "concentration_analysis",
							MITRETechnique:  "T1071",
							Details: map[string]interface{}{
								"alert_type": alertType,
								"count":      count,
								"total":      totalAlerts,
								"ratio":      ratio,
							},
						}
						anomalies = append(anomalies, anomaly)
					}
				}
			}
		}
	}
	
	return anomalies
}

// generateThreatPredictionsMultiIndex generates predictions from multiple data sources
func (s *APIServer) generateThreatPredictionsMultiIndex() []*ThreatPredictionOpenSearch {
	predictions := []*ThreatPredictionOpenSearch{}
	
	// Count critical/high alerts in last 6h
	alertQuery := `{
		"size": 0,
		"query": {
			"bool": {
				"must": [
					{ "range": { "timestamp": { "gte": "now-6h" } } },
					{ "terms": { "severity.keyword": ["CRITICAL", "HIGH"] } }
				]
			}
		},
		"aggs": {
			"by_type": {
				"terms": { "field": "type.keyword", "size": 10 }
			}
		}
	}`
	
	res, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(alertQuery)),
	)
	
	criticalAlerts := 0
	topAlertTypes := []string{}
	
	if res != nil && !res.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res.Body).Decode(&result)
		res.Body.Close()
		
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				criticalAlerts = int(total["value"].(float64))
			}
		}
		
		if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
			if byType, ok := aggs["by_type"].(map[string]interface{}); ok {
				if buckets, ok := byType["buckets"].([]interface{}); ok {
					for i, b := range buckets {
						if i >= 3 {
							break
						}
						bucket := b.(map[string]interface{})
						topAlertTypes = append(topAlertTypes, bucket["key"].(string))
					}
				}
			}
		}
	}
	
	// Count critical vulnerabilities
	vulnQuery := `{
		"size": 0,
		"query": {
			"bool": {
				"must": [
					{ "term": { "severity.keyword": "CRITICAL" } },
					{ "term": { "status.keyword": "ACTIVE" } }
				]
			}
		}
	}`
	
	vulnRes, _ := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-vulnerabilities"),
		s.opensearch.Search.WithBody(strings.NewReader(vulnQuery)),
	)
	
	criticalVulns := 0
	if vulnRes != nil && !vulnRes.IsError() {
		var result map[string]interface{}
		json.NewDecoder(vulnRes.Body).Decode(&result)
		vulnRes.Body.Close()
		
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				criticalVulns = int(total["value"].(float64))
			}
		}
	}
	
	// Generate predictions based on combined data
	riskScore := float64(criticalAlerts)*2 + float64(criticalVulns)*3
	
	if riskScore >= 20 {
		indicators := []string{"high_alert_volume", "active_vulnerabilities"}
		if len(topAlertTypes) > 0 {
			indicators = append(indicators, topAlertTypes...)
		}
		
		prediction := &ThreatPredictionOpenSearch{
			ID:             uuid.New().String(),
			PredictionType: "attack",
			TargetType:     "infrastructure",
			TargetID:       "all",
			TargetName:     "Infraestrutura Geral",
			Probability:    math.Min(riskScore, 95),
			Severity:       getSeverityFromScore(riskScore),
			TimeWindow:     "next_24h",
			Indicators:     indicators,
			MITRETechniques: []string{"T1059", "T1078", "T1190", "T1499"},
			Recommendations: []string{
				fmt.Sprintf("Revisar %d alertas críticos/altos das últimas 6 horas", criticalAlerts),
				fmt.Sprintf("Priorizar correção de %d vulnerabilidades críticas ativas", criticalVulns),
				"Verificar se há padrões de ataque coordenado",
				"Ativar monitoramento intensivo em sistemas críticos",
				"Preparar equipe de resposta a incidentes",
			},
			Confidence: math.Min(riskScore*0.8, 90),
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(24 * time.Hour),
			Status:     "active",
		}
		predictions = append(predictions, prediction)
	}
	
	// Specific prediction for vulnerability exploitation
	if criticalVulns >= 10 {
		prediction := &ThreatPredictionOpenSearch{
			ID:             uuid.New().String(),
			PredictionType: "exploitation",
			TargetType:     "vulnerable_assets",
			TargetID:       "critical_vulns",
			TargetName:     "Ativos com Vulnerabilidades Críticas",
			Probability:    math.Min(float64(criticalVulns)*5, 85),
			Severity:       "high",
			TimeWindow:     "next_week",
			Indicators:     []string{"critical_vulnerability_count", "public_exposure", "known_exploits"},
			MITRETechniques: []string{"T1190", "T1210"},
			Recommendations: []string{
				fmt.Sprintf("Corrigir urgentemente as %d vulnerabilidades críticas", criticalVulns),
				"Aplicar patches de segurança pendentes",
				"Revisar exposição de serviços à internet",
				"Implementar compensatory controls temporários",
			},
			Confidence: math.Min(float64(criticalVulns)*4, 80),
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(7 * 24 * time.Hour),
			Status:     "active",
		}
		predictions = append(predictions, prediction)
	}
	
	return predictions
}

func getSeverityFromScore(score float64) string {
	if score >= 80 {
		return "critical"
	} else if score >= 50 {
		return "high"
	} else if score >= 30 {
		return "medium"
	}
	return "low"
}


// checkDuplicateAnomaly checks if a similar anomaly already exists in the last 6 hours
func (s *APIServer) checkDuplicateAnomaly(entityID, anomalyType string) (bool, string) {
	if s.opensearch == nil {
		return false, ""
	}
	
	// Search for similar anomalies in the last 6 hours
	query := fmt.Sprintf(`{
		"size": 1,
		"query": {
			"bool": {
				"must": [
					{ "term": { "entity_id": "%s" } },
					{ "term": { "anomaly_type": "%s" } },
					{ "range": { "timestamp": { "gte": "now-6h" } } }
				]
			}
		},
		"sort": [{ "timestamp": "desc" }]
	}`, entityID, anomalyType)
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(mlAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return false, ""
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)
	
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			if count := int(total["value"].(float64)); count > 0 {
				// Get existing anomaly ID
				if hitList, ok := hits["hits"].([]interface{}); ok && len(hitList) > 0 {
					if hit := hitList[0].(map[string]interface{}); ok {
						if existingID, ok := hit["_id"].(string); ok {
							return true, existingID
						}
					}
				}
				return true, ""
			}
		}
	}
	
	return false, ""
}

// saveMLAnomaly saves an ML anomaly to OpenSearch (with deduplication)
func (s *APIServer) saveMLAnomaly(anomaly *MLAnomalyOpenSearch) {
	// Check for duplicates first
	isDuplicate, existingID := s.checkDuplicateAnomaly(anomaly.EntityID, anomaly.AnomalyType)
	
	if isDuplicate {
		// Update existing anomaly instead of creating new
		if existingID != "" {
			anomaly.ID = existingID // Use existing ID to update
			log.Printf("📝 ML: Updating existing anomaly %s for %s", existingID, anomaly.EntityID)
		} else {
			log.Printf("⏭️ ML: Skipping duplicate anomaly for %s (type: %s)", anomaly.EntityID, anomaly.AnomalyType)
			return
		}
	}
	
	anomalyJSON, _ := json.Marshal(anomaly)

	res, err := s.opensearch.Index(
		mlAnomaliesIndex,
		strings.NewReader(string(anomalyJSON)),
		s.opensearch.Index.WithDocumentID(anomaly.ID),
	)
	if err != nil {
		log.Printf("❌ ML: Error saving anomaly: %v", err)
		return
	}
	res.Body.Close()
}

// checkDuplicatePrediction checks if a similar prediction already exists
func (s *APIServer) checkDuplicatePrediction(targetID, predictionType string) (bool, string) {
	if s.opensearch == nil {
		return false, ""
	}
	
	// Search for similar active predictions
	query := fmt.Sprintf(`{
		"size": 1,
		"query": {
			"bool": {
				"must": [
					{ "term": { "target_id": "%s" } },
					{ "term": { "prediction_type": "%s" } },
					{ "term": { "status": "active" } },
					{ "range": { "expires_at": { "gte": "now" } } }
				]
			}
		}
	}`, targetID, predictionType)
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(mlPredictionsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return false, ""
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)
	
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			if count := int(total["value"].(float64)); count > 0 {
				if hitList, ok := hits["hits"].([]interface{}); ok && len(hitList) > 0 {
					if hit := hitList[0].(map[string]interface{}); ok {
						if existingID, ok := hit["_id"].(string); ok {
							return true, existingID
						}
					}
				}
				return true, ""
			}
		}
	}
	
	return false, ""
}

// savePrediction saves a prediction to OpenSearch (with deduplication)
func (s *APIServer) savePrediction(prediction *ThreatPredictionOpenSearch) {
	// Check for duplicates first
	isDuplicate, existingID := s.checkDuplicatePrediction(prediction.TargetID, prediction.PredictionType)
	
	if isDuplicate {
		if existingID != "" {
			prediction.ID = existingID // Update existing
			log.Printf("📝 ML: Updating existing prediction %s for %s", existingID, prediction.TargetID)
		} else {
			log.Printf("⏭️ ML: Skipping duplicate prediction for %s (type: %s)", prediction.TargetID, prediction.PredictionType)
			return
		}
	}
	
	predJSON, _ := json.Marshal(prediction)

	res, err := s.opensearch.Index(
		mlPredictionsIndex,
		strings.NewReader(string(predJSON)),
		s.opensearch.Index.WithDocumentID(prediction.ID),
	)
	if err != nil {
		log.Printf("❌ ML: Error saving prediction: %v", err)
		return
	}
	res.Body.Close()
}

// handleListMLAnomaliesOpenSearch lists ML anomalies
func (s *APIServer) handleListMLAnomaliesOpenSearch(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"anomalies": []MLAnomalyOpenSearch{},
			"total":     0,
			"source":    "opensearch",
		})
		return
	}

	severity := c.Query("severity")
	status := c.Query("status")
	anomalyType := c.Query("type")

	must := []map[string]interface{}{}
	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"severity": severity},
		})
	}
	if status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"status": status},
		})
	}
	if anomalyType != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"anomaly_type": anomalyType},
		})
	}

	query := map[string]interface{}{
		"size":             100,
		"track_total_hits": true,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
	}

	if len(must) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{"must": must},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(mlAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"anomalies": []MLAnomalyOpenSearch{},
			"total":     0,
		})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	anomalies := []MLAnomalyOpenSearch{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			total = int(totalObj["value"].(float64))
		}
		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				hitMap := hit.(map[string]interface{})
				source := hitMap["_source"].(map[string]interface{})
				anomaly := parseMLAnomaly(source)
				anomalies = append(anomalies, *anomaly)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"anomalies": anomalies,
		"total":     total,
		"source":    "opensearch",
	})
}

// handleListPredictionsOpenSearch lists threat predictions
func (s *APIServer) handleListPredictionsOpenSearch(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"predictions": []ThreatPredictionOpenSearch{},
			"total":       0,
			"source":      "opensearch",
		})
		return
	}

	query := map[string]interface{}{
		"size":             50,
		"track_total_hits": true,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{"term": map[string]interface{}{"status": "active"}},
					{"range": map[string]interface{}{"expires_at": map[string]interface{}{"gte": "now"}}},
				},
			},
		},
		"sort": []map[string]interface{}{
			{"probability": map[string]interface{}{"order": "desc"}},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(mlPredictionsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"predictions": []ThreatPredictionOpenSearch{},
			"total":       0,
		})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	predictions := []ThreatPredictionOpenSearch{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			total = int(totalObj["value"].(float64))
		}
		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				hitMap := hit.(map[string]interface{})
				source := hitMap["_source"].(map[string]interface{})
				pred := parsePrediction(source)
				predictions = append(predictions, *pred)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"predictions": predictions,
		"total":       total,
		"source":      "opensearch",
	})
}

// handleGetMLStatsOpenSearch returns ML analytics statistics
func (s *APIServer) handleGetMLStatsOpenSearch(c *gin.Context) {
	stats := gin.H{
		"total_anomalies":     0,
		"new_anomalies":       0,
		"high_severity":       0,
		"active_predictions":  0,
		"avg_confidence":      0.0,
		"detection_rate":      0.0,
		"model_accuracy":      0.0,
		"false_positive_rate": 0.0,
		"threats_prevented":   0,
		"predictions_today":   0,
	}

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": stats, "source": "opensearch"})
		return
	}

	totalAlerts := 0
	detectedByML := 0

	// Anomaly stats
	anomalyQuery := `{
		"size": 0,
		"aggs": {
			"total": { "value_count": { "field": "id" } },
			"new": { "filter": { "term": { "status": "new" } } },
			"high_severity": { 
				"filter": { 
					"terms": { "severity": ["critical", "high"] } 
				} 
			},
			"avg_confidence": { "avg": { "field": "confidence" } },
			"last_24h": { "filter": { "range": { "timestamp": { "gte": "now-24h" } } } },
			"by_status": {
				"terms": { "field": "status", "size": 10 }
			}
		}
	}`

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(mlAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(anomalyQuery)),
	)
	if err == nil && !res.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res.Body).Decode(&result)
		res.Body.Close()

		if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
			if total, ok := aggs["total"].(map[string]interface{}); ok {
				totalAnom := int(total["value"].(float64))
				stats["total_anomalies"] = totalAnom
				detectedByML = totalAnom
			}
			if newAgg, ok := aggs["new"].(map[string]interface{}); ok {
				stats["new_anomalies"] = int(newAgg["doc_count"].(float64))
			}
			if highSev, ok := aggs["high_severity"].(map[string]interface{}); ok {
				stats["high_severity"] = int(highSev["doc_count"].(float64))
			}
			if avgConf, ok := aggs["avg_confidence"].(map[string]interface{}); ok {
				if v, ok := avgConf["value"].(float64); ok {
					stats["avg_confidence"] = math.Round(v*10) / 10
					// Model accuracy is based on average confidence
					stats["model_accuracy"] = math.Round(v*10) / 10
				}
			}
			// Calculate false positive rate from status
			if byStatus, ok := aggs["by_status"].(map[string]interface{}); ok {
				if buckets, ok := byStatus["buckets"].([]interface{}); ok {
					falsePositives := 0
					totalResolved := 0
					for _, b := range buckets {
						bucket := b.(map[string]interface{})
						status := bucket["key"].(string)
						count := int(bucket["doc_count"].(float64))
						if status == "false_positive" {
							falsePositives = count
						}
						if status == "resolved" || status == "false_positive" {
							totalResolved += count
						}
					}
					if totalResolved > 0 {
						stats["false_positive_rate"] = math.Round(float64(falsePositives)/float64(totalResolved)*1000) / 10
					}
					stats["threats_prevented"] = totalResolved - falsePositives
				}
			}
		}
	}

	// Count total alerts for detection rate calculation
	alertQuery := `{
		"size": 0,
		"query": {
			"range": { "timestamp": { "gte": "now-24h" } }
		}
	}`
	
	res3, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(alertQuery)),
	)
	if err == nil && res3 != nil && !res3.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res3.Body).Decode(&result)
		res3.Body.Close()
		
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if total, ok := hits["total"].(map[string]interface{}); ok {
				totalAlerts = int(total["value"].(float64))
			}
		}
	}

	// Calculate detection rate
	if totalAlerts > 0 {
		// Detection rate = anomalies detected / total alerts * 100
		detectionRate := float64(detectedByML) / float64(totalAlerts) * 100
		if detectionRate > 100 {
			detectionRate = 100
		}
		stats["detection_rate"] = math.Round(detectionRate*10) / 10
	}

	// Prediction stats
	predQuery := `{
		"size": 0,
		"aggs": {
			"active": {
				"filter": {
					"bool": {
						"must": [
							{ "term": { "status": "active" } },
							{ "range": { "expires_at": { "gte": "now" } } }
						]
					}
				}
			},
			"today": {
				"filter": {
					"range": { "created_at": { "gte": "now/d" } }
				}
			}
		}
	}`

	res2, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(mlPredictionsIndex),
		s.opensearch.Search.WithBody(strings.NewReader(predQuery)),
	)
	if err == nil && !res2.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res2.Body).Decode(&result)
		res2.Body.Close()

		if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
			if active, ok := aggs["active"].(map[string]interface{}); ok {
				stats["active_predictions"] = int(active["doc_count"].(float64))
			}
			if today, ok := aggs["today"].(map[string]interface{}); ok {
				stats["predictions_today"] = int(today["doc_count"].(float64))
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
		"source":  "opensearch",
	})
}

// RiskAssessmentOpenSearch represents a real risk assessment
type RiskAssessmentOpenSearch struct {
	EntityType        string    `json:"entity_type"`
	EntityID          string    `json:"entity_id"`
	EntityName        string    `json:"entity_name"`
	RiskScore         float64   `json:"risk_score"`
	RiskLevel         string    `json:"risk_level"`
	RiskFactors       []string  `json:"risk_factors"`
	Vulnerabilities   int       `json:"vulnerabilities"`
	Threats           int       `json:"threats"`
	Incidents         int       `json:"incidents"`
	Anomalies         int       `json:"anomalies"`
	LastIncident      *string   `json:"last_incident,omitempty"`
	Trend             string    `json:"trend"`
	LastAssessment    time.Time `json:"last_assessment"`
	MitigationActions []string  `json:"mitigation_actions"`
	Details           map[string]interface{} `json:"details"`
}

// handleListRiskAssessmentsOpenSearch returns real risk assessments from OpenSearch
func (s *APIServer) handleListRiskAssessmentsOpenSearch(c *gin.Context) {
	assessments := []RiskAssessmentOpenSearch{}
	
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    assessments,
			"source":  "mock",
		})
		return
	}

	// 1. Get top assets by vulnerabilities
	vulnQuery := `{
		"size": 0,
		"query": {
			"term": { "status.keyword": "ACTIVE" }
		},
		"aggs": {
			"by_resource": {
				"terms": { 
					"field": "resource_id.keyword", 
					"size": 10,
					"order": { "_count": "desc" }
				},
				"aggs": {
					"critical": {
						"filter": { "term": { "severity.keyword": "CRITICAL" } }
					},
					"high": {
						"filter": { "term": { "severity.keyword": "HIGH" } }
					},
					"resource_type": {
						"terms": { "field": "resource_type.keyword", "size": 1 }
					},
					"instance_id": {
						"terms": { "field": "instance_id.keyword", "size": 1 }
					}
				}
			}
		}
	}`
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-vulnerabilities"),
		s.opensearch.Search.WithBody(strings.NewReader(vulnQuery)),
	)
	
	if err == nil && !res.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res.Body).Decode(&result)
		res.Body.Close()
		
		if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
			if byResource, ok := aggs["by_resource"].(map[string]interface{}); ok {
				if buckets, ok := byResource["buckets"].([]interface{}); ok {
					for _, b := range buckets {
						bucket := b.(map[string]interface{})
						resourceID := bucket["key"].(string)
						totalVulns := int(bucket["doc_count"].(float64))
						
						criticalCount := 0
						if critical, ok := bucket["critical"].(map[string]interface{}); ok {
							criticalCount = int(critical["doc_count"].(float64))
						}
						
						highCount := 0
						if high, ok := bucket["high"].(map[string]interface{}); ok {
							highCount = int(high["doc_count"].(float64))
						}
						
						// Get display name
						displayName := resourceID
						entityType := "host"
						if instanceID, ok := bucket["instance_id"].(map[string]interface{}); ok {
							if buckets, ok := instanceID["buckets"].([]interface{}); ok {
								if len(buckets) > 0 {
									displayName = buckets[0].(map[string]interface{})["key"].(string)
								}
							}
						}
						if resourceType, ok := bucket["resource_type"].(map[string]interface{}); ok {
							if buckets, ok := resourceType["buckets"].([]interface{}); ok {
								if len(buckets) > 0 {
									rt := buckets[0].(map[string]interface{})["key"].(string)
									if strings.Contains(strings.ToLower(rt), "lambda") {
										entityType = "application"
									} else if strings.Contains(strings.ToLower(rt), "container") {
										entityType = "container"
									}
								}
							}
						}
						
						// Calculate risk score
						riskScore := float64(criticalCount)*15 + float64(highCount)*8 + float64(totalVulns-criticalCount-highCount)*2
						if riskScore > 100 {
							riskScore = 100
						}
						
						// Determine risk factors
						riskFactors := []string{}
						if criticalCount > 0 {
							riskFactors = append(riskFactors, fmt.Sprintf("%d vulnerabilidades críticas", criticalCount))
						}
						if highCount > 0 {
							riskFactors = append(riskFactors, fmt.Sprintf("%d vulnerabilidades altas", highCount))
						}
						if totalVulns > 10 {
							riskFactors = append(riskFactors, "Alto volume de vulnerabilidades")
						}
						
						// Get related alerts count
						alertCount := s.getAlertCountForResource(resourceID)
						if alertCount > 0 {
							riskFactors = append(riskFactors, fmt.Sprintf("%d alertas relacionados", alertCount))
						}
						
						// Get anomaly count
						anomalyCount := s.getAnomalyCountForResource(resourceID)
						if anomalyCount > 0 {
							riskFactors = append(riskFactors, fmt.Sprintf("%d anomalias detectadas", anomalyCount))
						}
						
						// Mitigation actions
						mitigations := []string{}
						if criticalCount > 0 {
							mitigations = append(mitigations, "Corrigir vulnerabilidades críticas imediatamente")
						}
						if highCount > 0 {
							mitigations = append(mitigations, "Priorizar patches para vulnerabilidades altas")
						}
						if totalVulns > 5 {
							mitigations = append(mitigations, "Revisar configurações de segurança do ativo")
						}
						mitigations = append(mitigations, "Ativar monitoramento intensivo")
						
						// Determine trend
						trend := "stable"
						if criticalCount > 3 {
							trend = "increasing"
						} else if criticalCount == 0 && highCount < 3 {
							trend = "decreasing"
						}
						
						assessment := RiskAssessmentOpenSearch{
							EntityType:        entityType,
							EntityID:          resourceID,
							EntityName:        displayName,
							RiskScore:         math.Round(riskScore*10) / 10,
							RiskLevel:         getMLRiskLevel(riskScore),
							RiskFactors:       riskFactors,
							Vulnerabilities:   totalVulns,
							Threats:           alertCount,
							Incidents:         0,
							Anomalies:         anomalyCount,
							Trend:             trend,
							LastAssessment:    time.Now(),
							MitigationActions: mitigations,
							Details: map[string]interface{}{
								"critical_vulns": criticalCount,
								"high_vulns":     highCount,
								"medium_vulns":   totalVulns - criticalCount - highCount,
								"resource_type":  entityType,
							},
						}
						
						assessments = append(assessments, assessment)
					}
				}
			}
		}
	}
	
	// 2. Add user-based risk assessments from UEBA
	uebaQuery := `{
		"size": 10,
		"sort": [{ "risk_score": "desc" }],
		"query": {
			"range": { "risk_score": { "gte": 50 } }
		}
	}`
	
	res2, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-ueba-profiles"),
		s.opensearch.Search.WithBody(strings.NewReader(uebaQuery)),
	)
	
	if err == nil && res2 != nil && !res2.IsError() {
		var result map[string]interface{}
		json.NewDecoder(res2.Body).Decode(&result)
		res2.Body.Close()
		
		if hits, ok := result["hits"].(map[string]interface{}); ok {
			if hitList, ok := hits["hits"].([]interface{}); ok {
				for _, h := range hitList {
					hit := h.(map[string]interface{})
					source := hit["_source"].(map[string]interface{})
					
					userID := getStrVal(source, "user_id")
					userName := getStrVal(source, "user_name")
					if userName == "" {
						userName = userID
					}
					
					riskScore := 0.0
					if v, ok := source["risk_score"].(float64); ok {
						riskScore = v
					}
					
					anomalies := 0
					if v, ok := source["anomaly_count"].(float64); ok {
						anomalies = int(v)
					}
					
					riskFactors := []string{}
					if riskScore >= 80 {
						riskFactors = append(riskFactors, "Comportamento de alto risco")
					}
					if anomalies > 0 {
						riskFactors = append(riskFactors, fmt.Sprintf("%d anomalias comportamentais", anomalies))
					}
					riskFactors = append(riskFactors, "Monitoramento UEBA ativo")
					
					mitigations := []string{
						"Revisar acessos e permissões do usuário",
						"Verificar atividades recentes",
						"Considerar treinamento de segurança",
					}
					
					assessment := RiskAssessmentOpenSearch{
						EntityType:        "user",
						EntityID:          userID,
						EntityName:        userName,
						RiskScore:         math.Round(riskScore*10) / 10,
						RiskLevel:         getMLRiskLevel(riskScore),
						RiskFactors:       riskFactors,
						Vulnerabilities:   0,
						Threats:           0,
						Incidents:         0,
						Anomalies:         anomalies,
						Trend:             "stable",
						LastAssessment:    time.Now(),
						MitigationActions: mitigations,
						Details: map[string]interface{}{
							"user_id":       userID,
							"risk_score":    riskScore,
							"anomaly_count": anomalies,
						},
					}
					
					assessments = append(assessments, assessment)
				}
			}
		}
	}
	
	// Sort by risk score
	sortAssessments(assessments)
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    assessments,
		"total":   len(assessments),
		"source":  "opensearch",
	})
}

// Helper to get ML risk level from score
func getMLRiskLevel(score float64) string {
	if score >= 80 {
		return "critical"
	} else if score >= 60 {
		return "high"
	} else if score >= 40 {
		return "medium"
	}
	return "low"
}

// Helper to get alert count for a resource
func (s *APIServer) getAlertCountForResource(resourceID string) int {
	if s.opensearch == nil {
		return 0
	}
	
	query := fmt.Sprintf(`{
		"size": 0,
		"query": {
			"bool": {
				"should": [
					{ "match": { "resource_id": "%s" } },
					{ "match": { "instance_id": "%s" } }
				],
				"minimum_should_match": 1
			}
		}
	}`, resourceID, resourceID)
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil || res.IsError() {
		return 0
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)
	
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			return int(total["value"].(float64))
		}
	}
	return 0
}

// Helper to get anomaly count for a resource
func (s *APIServer) getAnomalyCountForResource(resourceID string) int {
	if s.opensearch == nil {
		return 0
	}
	
	query := fmt.Sprintf(`{
		"size": 0,
		"query": {
			"bool": {
				"should": [
					{ "match": { "entity_id": "%s" } },
					{ "match": { "entity_name": "%s" } }
				],
				"minimum_should_match": 1
			}
		}
	}`, resourceID, resourceID)
	
	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(mlAnomaliesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil || res.IsError() {
		return 0
	}
	defer res.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)
	
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			return int(total["value"].(float64))
		}
	}
	return 0
}

// Helper to sort assessments by risk score
func sortAssessments(assessments []RiskAssessmentOpenSearch) {
	for i := 0; i < len(assessments)-1; i++ {
		for j := i + 1; j < len(assessments); j++ {
			if assessments[j].RiskScore > assessments[i].RiskScore {
				assessments[i], assessments[j] = assessments[j], assessments[i]
			}
		}
	}
}

// Helper functions
func calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func calculateStdDev(values []float64, mean float64) float64 {
	if len(values) < 2 {
		return 0
	}
	sumSquares := 0.0
	for _, v := range values {
		sumSquares += (v - mean) * (v - mean)
	}
	return math.Sqrt(sumSquares / float64(len(values)-1))
}

func parseMLAnomaly(source map[string]interface{}) *MLAnomalyOpenSearch {
	anomaly := &MLAnomalyOpenSearch{
		ID:              getStrVal(source, "id"),
		EntityType:      getStrVal(source, "entity_type"),
		EntityID:        getStrVal(source, "entity_id"),
		EntityName:      getStrVal(source, "entity_name"),
		AnomalyType:     getStrVal(source, "anomaly_type"),
		Severity:        getStrVal(source, "severity"),
		Description:     getStrVal(source, "description"),
		Status:          getStrVal(source, "status"),
		AssignedTo:      getStrVal(source, "assigned_to"),
		MITRETechnique:  getStrVal(source, "mitre_technique"),
		DetectionMethod: getStrVal(source, "detection_method"),
		Indicators:      []string{},
		Details:         map[string]interface{}{},
	}

	if v, ok := source["confidence"].(float64); ok {
		anomaly.Confidence = v
	}
	if v, ok := source["anomaly_score"].(float64); ok {
		anomaly.AnomalyScore = v
	}
	if v, ok := source["baseline"].(float64); ok {
		anomaly.Baseline = v
	}
	if v, ok := source["current_value"].(float64); ok {
		anomaly.CurrentValue = v
	}
	if v, ok := source["deviation"].(float64); ok {
		anomaly.Deviation = v
	}
	if v, ok := source["related_events"].(float64); ok {
		anomaly.RelatedEvents = int(v)
	}
	if ts := getStrVal(source, "timestamp"); ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			anomaly.Timestamp = t
		}
	}

	return anomaly
}

func parsePrediction(source map[string]interface{}) *ThreatPredictionOpenSearch {
	pred := &ThreatPredictionOpenSearch{
		ID:              getStrVal(source, "id"),
		PredictionType:  getStrVal(source, "prediction_type"),
		TargetType:      getStrVal(source, "target_type"),
		TargetID:        getStrVal(source, "target_id"),
		TargetName:      getStrVal(source, "target_name"),
		Severity:        getStrVal(source, "severity"),
		TimeWindow:      getStrVal(source, "time_window"),
		Status:          getStrVal(source, "status"),
		Indicators:      []string{},
		MITRETechniques: []string{},
		Recommendations: []string{},
	}

	if v, ok := source["probability"].(float64); ok {
		pred.Probability = v
	}
	if v, ok := source["confidence"].(float64); ok {
		pred.Confidence = v
	}

	return pred
}

