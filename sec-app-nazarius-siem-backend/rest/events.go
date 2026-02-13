package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// STRUCTS
// ============================================================================

type SearchRequest struct {
	Query      string    `json:"query"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Sources    []string  `json:"sources"`
	Severities []string  `json:"severities"`
	Types      []string  `json:"types"`
	PageSize   int       `json:"page_size"`
	PageNumber int       `json:"page_number"`
	SortField  string    `json:"sort_field"`
	SortOrder  string    `json:"sort_order"`
}

type AggregateRequest struct {
	Field     string    `json:"field"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Interval  string    `json:"interval"`
	Metrics   []string  `json:"metrics"`
}

type Event struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	User        string                 `json:"user,omitempty"`      // For UEBA analysis
	SourceIP    string                 `json:"source_ip,omitempty"` // For analytics
	Details     map[string]interface{} `json:"details,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
}

type EventsResponse struct {
	Events     []Event `json:"events"`
	Total      int64   `json:"total"`
	Page       int     `json:"page"`
	PageSize   int     `json:"page_size"`
	TotalPages int     `json:"total_pages"`
}

type EventStatistics struct {
	Total        int64            `json:"total"`
	BySeverity   map[string]int64 `json:"by_severity"`
	ByType       map[string]int64 `json:"by_type"`
	BySource     map[string]int64 `json:"by_source"`
	Timeline     []TimelinePoint  `json:"timeline"`
	TopSources   []SourceStat     `json:"top_sources"`
	RecentEvents []Event          `json:"recent_events"`
}

type TimelinePoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int64     `json:"count"`
}

type SourceStat struct {
	Source string `json:"source"`
	Count  int64  `json:"count"`
}

// ============================================================================
// HANDLERS
// ============================================================================

func (s *APIServer) handleSearchEvents(c *gin.Context) {
	// Parse query parameters
	query := c.DefaultQuery("query", "*")
	// Default: últimos 30 dias para visualização mais ampla de eventos históricos
	startTime := c.DefaultQuery("start_time", time.Now().Add(-30*24*time.Hour).Format(time.RFC3339))
	endTime := c.DefaultQuery("end_time", time.Now().Format(time.RFC3339))
	sources := c.QueryArray("sources")
	severities := c.QueryArray("severities")
	types := c.QueryArray("types")
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	pageNumber, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	sortField := c.DefaultQuery("sort_field", "timestamp")
	sortOrder := c.DefaultQuery("sort_order", "desc")

	// Parse times
	start, err := time.Parse(time.RFC3339, startTime)
	if err != nil {
		start = time.Now().Add(-30 * 24 * time.Hour) // 30 dias
	}
	end, err := time.Parse(time.RFC3339, endTime)
	if err != nil {
		end = time.Now()
	}

	// Validação
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 50
	}
	if pageNumber < 1 {
		pageNumber = 1
	}

	// Se Elasticsearch não estiver disponível
	if s.opensearch == nil {
		// Se mock está desabilitado, retornar dados vazios
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"events":      []interface{}{},
				"total":       0,
				"page":        pageNumber,
				"page_size":   pageSize,
				"total_pages": 0,
				"source":      "none",
				"message":     "OpenSearch not connected. No real data available.",
			})
			return
		}
		// Fallback para mock apenas se permitido
		eventsResponse := generateMockEvents(query, start, end, sources, severities, types, pageSize, pageNumber)
		c.JSON(http.StatusOK, gin.H{
			"events":      eventsResponse.Events,
			"total":       eventsResponse.Total,
			"page":        eventsResponse.Page,
			"page_size":   eventsResponse.PageSize,
			"total_pages": eventsResponse.TotalPages,
			"source":      "mock",
		})
		return
	}

	// Construir query Elasticsearch
	mustClauses := []map[string]interface{}{
		{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"gte": start.Format(time.RFC3339),
					"lte": end.Format(time.RFC3339),
				},
			},
		},
	}

	// Adicionar query string se não for wildcard
	if query != "*" && query != "" {
		// Verificar se é uma busca por CVE (formato: CVE-YYYY-NNNNN)
		queryUpper := strings.ToUpper(strings.TrimSpace(query))
		if strings.HasPrefix(queryUpper, "CVE-") {
			// Busca exata por CVE - usar query_string com frase exata
			// O formato "\"CVE-XXXX-XXXXX\"" força match de frase exata
			mustClauses = append(mustClauses, map[string]interface{}{
				"query_string": map[string]interface{}{
					"query":            "\"" + queryUpper + "\"",
					"default_operator": "AND",
				},
			})
		} else {
			// Busca geral
			mustClauses = append(mustClauses, map[string]interface{}{
				"query_string": map[string]interface{}{
					"query": query,
				},
			})
		}
	}

	// Adicionar filtros
	if len(sources) > 0 {
		mustClauses = append(mustClauses, map[string]interface{}{
			"terms": map[string]interface{}{
				"source.keyword": sources,
			},
		})
	}
	if len(severities) > 0 {
		mustClauses = append(mustClauses, map[string]interface{}{
			"terms": map[string]interface{}{
				"severity.keyword": severities,
			},
		})
	}
	if len(types) > 0 {
		mustClauses = append(mustClauses, map[string]interface{}{
			"terms": map[string]interface{}{
				"type.keyword": types,
			},
		})
	}

	accessFilters := buildEventAccessFilter(getAccessScope(c))
	if len(accessFilters) > 0 {
		mustClauses = append(mustClauses, accessFilters...)
	}

	esQuery := map[string]interface{}{
		"track_total_hits": true, // Remove 10,000 limit on total count
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		},
		"from": (pageNumber - 1) * pageSize,
		"size": pageSize,
		"sort": []map[string]interface{}{
			{
				sortField: map[string]interface{}{
					"order": sortOrder,
				},
			},
		},
	}

	// Executar busca no Elasticsearch
	queryJSON, err := json.Marshal(esQuery)
	if err != nil {
		s.logger.Printf("Error marshaling query: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao criar query"})
		return
	}

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(c.Request.Context()),
		s.opensearch.Search.WithIndex(s.config.Elasticsearch.IndexPattern),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		s.logger.Printf("Elasticsearch search error: %v", err)
		// Se mock desabilitado, retornar erro
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"events":      []interface{}{},
				"total":       0,
				"page":        pageNumber,
				"page_size":   pageSize,
				"total_pages": 0,
				"source":      "error",
				"message":     "OpenSearch query failed. No real data available.",
			})
			return
		}
		// Fallback para dados mockados
		events := generateMockEvents(query, start, end, sources, severities, types, pageSize, pageNumber)
		c.JSON(http.StatusOK, events)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		s.logger.Printf("Elasticsearch error response: %s", res.String())
		// Se mock desabilitado, retornar erro
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"events":      []interface{}{},
				"total":       0,
				"page":        pageNumber,
				"page_size":   pageSize,
				"total_pages": 0,
				"source":      "error",
				"message":     "OpenSearch returned error. No real data available.",
			})
			return
		}
		// Fallback para dados mockados
		eventsResponse := generateMockEvents(query, start, end, sources, severities, types, pageSize, pageNumber)
		c.JSON(http.StatusOK, gin.H{
			"events":      eventsResponse.Events,
			"total":       eventsResponse.Total,
			"page":        eventsResponse.Page,
			"page_size":   eventsResponse.PageSize,
			"total_pages": eventsResponse.TotalPages,
			"source":      "mock",
		})
		return
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		s.logger.Printf("Error decoding response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao decodificar resposta"})
		return
	}

	// Parse response
	hits := result["hits"].(map[string]interface{})
	total := int64(hits["total"].(map[string]interface{})["value"].(float64))
	hitsList := hits["hits"].([]interface{})

	events := make([]Event, 0, len(hitsList))
	for _, hit := range hitsList {
		hitMap := hit.(map[string]interface{})
		source := hitMap["_source"].(map[string]interface{})

		event := Event{
			ID:          hitMap["_id"].(string),
			Timestamp:   parseTimestamp(source["timestamp"]),
			Severity:    getString(source, "severity"),
			Type:        getString(source, "type"),
			Source:      getString(source, "source"),
			Description: getString(source, "description"),
			Details:     source,
		}
		events = append(events, event)
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	c.JSON(http.StatusOK, gin.H{
		"events":      events,
		"total":       total,
		"page":        pageNumber,
		"page_size":   pageSize,
		"total_pages": totalPages,
		"source":      "opensearch", // Indicates real data from OpenSearch
	})
}

func (s *APIServer) handleAggregateEvents(c *gin.Context) {
	var req AggregateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Construir agregação Elasticsearch
	aggs := map[string]interface{}{
		"results": map[string]interface{}{
			"date_histogram": map[string]interface{}{
				"field":    "timestamp",
				"interval": req.Interval,
			},
		},
	}

	// Adicionar métricas solicitadas
	for _, metric := range req.Metrics {
		switch metric {
		case "count":
			aggs["results"].(map[string]interface{})["aggs"] = map[string]interface{}{
				"event_count": map[string]interface{}{
					"value_count": map[string]interface{}{
						"field": "_id",
					},
				},
			}
		case "severity":
			aggs["results"].(map[string]interface{})["aggs"] = map[string]interface{}{
				"severity_breakdown": map[string]interface{}{
					"terms": map[string]interface{}{
						"field": "severity",
					},
				},
			}
		}
	}

	mustClauses := []map[string]interface{}{
		{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"gte": req.StartTime,
					"lte": req.EndTime,
				},
			},
		},
	}
	accessFilters := buildEventAccessFilter(getAccessScope(c))
	if len(accessFilters) > 0 {
		mustClauses = append(mustClauses, accessFilters...)
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		},
		"aggs": aggs,
		"size": 0,
	}

	// Executar agregação no Elasticsearch
	queryJSON, err := json.Marshal(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao criar query"})
		return
	}

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(c.Request.Context()),
		s.opensearch.Search.WithIndex(s.config.Elasticsearch.IndexPattern),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao agregar eventos"})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao decodificar resposta"})
		return
	}

	c.JSON(http.StatusOK, result["aggregations"])
}

func (s *APIServer) handleGetEvent(c *gin.Context) {
	id := c.Param("id")

	// Buscar evento no Elasticsearch
	res, err := s.opensearch.Get(
		s.config.Elasticsearch.IndexPattern,
		id,
		s.opensearch.Get.WithContext(c.Request.Context()),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao buscar evento"})
		return
	}
	defer res.Body.Close()

	if res.StatusCode == 404 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Evento não encontrado"})
		return
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao decodificar resposta"})
		return
	}

	source, ok := result["_source"].(map[string]interface{})
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Evento inválido"})
		return
	}

	if !eventMatchesScope(source, getAccessScope(c)) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Evento não encontrado"})
		return
	}

	c.JSON(http.StatusOK, source)
}

// handleGetEventStatistics retorna estatísticas dos eventos
func (s *APIServer) handleGetEventStatistics(c *gin.Context) {
	// Default: últimos 30 dias para visualização mais ampla
	startTime := c.DefaultQuery("start_time", time.Now().Add(-30*24*time.Hour).Format(time.RFC3339))
	endTime := c.DefaultQuery("end_time", time.Now().Format(time.RFC3339))

	start, _ := time.Parse(time.RFC3339, startTime)
	end, _ := time.Parse(time.RFC3339, endTime)

	// Se Elasticsearch não estiver disponível
	if s.opensearch == nil {
		// Se mock desabilitado, retornar dados vazios
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"total":         0,
				"critical":      0,
				"high":          0,
				"by_severity":   map[string]int64{},
				"by_type":       map[string]int64{},
				"by_source":     map[string]int64{},
				"timeline":      []interface{}{},
				"top_sources":   []interface{}{},
				"recent_events": []interface{}{},
				"source":        "none",
				"message":       "OpenSearch not connected. No real data available.",
			})
			return
		}
		stats := generateMockStatistics(start, end)
		c.JSON(http.StatusOK, stats)
		return
	}

	// Get real statistics from OpenSearch
	stats, err := s.getOpenSearchEventStatistics(start, end, getAccessScope(c))
	if err != nil {
		log.Printf("❌ Failed to get OpenSearch statistics: %v", err)
		// Fallback to empty data if mock is disabled
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"total":         0,
				"critical":      0,
				"high":          0,
				"by_severity":   map[string]int64{},
				"by_type":       map[string]int64{},
				"by_source":     map[string]int64{},
				"timeline":      []interface{}{},
				"top_sources":   []interface{}{},
				"recent_events": []interface{}{},
				"source":        "opensearch",
				"error":         err.Error(),
			})
			return
		}
		stats := generateMockStatistics(start, end)
		c.JSON(http.StatusOK, stats)
		return
	}

	c.JSON(http.StatusOK, stats)
}

// getOpenSearchEventStatistics retrieves real statistics from OpenSearch
func (s *APIServer) getOpenSearchEventStatistics(start, end time.Time, scope AccessScope) (gin.H, error) {
	log.Printf("📊 Getting OpenSearch statistics from %s to %s", start.Format(time.RFC3339), end.Format(time.RFC3339))

	// Aggregation query to get statistics
	// OpenSearch auto-created index with text fields, so we need to use .keyword suffix
	// track_total_hits: true removes the 10,000 limit on total count
	mustClauses := []map[string]interface{}{
		{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"gte": start.Format(time.RFC3339),
					"lte": end.Format(time.RFC3339),
				},
			},
		},
	}
	accessFilters := buildEventAccessFilter(scope)
	if len(accessFilters) > 0 {
		mustClauses = append(mustClauses, accessFilters...)
	}

	query := map[string]interface{}{
		"size":             0,
		"track_total_hits": true,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		},
		"aggs": map[string]interface{}{
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "severity.keyword",
					"size":  10,
				},
			},
			"by_type": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "type.keyword",
					"size":  20,
				},
			},
			"by_source": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "source.keyword",
					"size":  20,
				},
			},
			"timeline": map[string]interface{}{
				"date_histogram": map[string]interface{}{
					"field":          "timestamp",
					"fixed_interval": "1h",
					"min_doc_count":  0,
				},
			},
		},
	}
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	searchRes, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	defer searchRes.Body.Close()

	if searchRes.IsError() {
		return nil, fmt.Errorf("opensearch error: %s", searchRes.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(searchRes.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract total count
	var total int64 = 0
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			if value, ok := totalObj["value"].(float64); ok {
				total = int64(value)
			}
		}
	}

	// Extract aggregations
	bySeverity := make(map[string]int64)
	byType := make(map[string]int64)
	bySource := make(map[string]int64)
	var timeline []map[string]interface{}
	var critical int64 = 0
	var high int64 = 0

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		// By severity
		if sevAgg, ok := aggs["by_severity"].(map[string]interface{}); ok {
			if buckets, ok := sevAgg["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if b, ok := bucket.(map[string]interface{}); ok {
						key := fmt.Sprintf("%v", b["key"])
						count := int64(b["doc_count"].(float64))
						bySeverity[key] = count
						if strings.ToUpper(key) == "CRITICAL" {
							critical = count
						}
						if strings.ToUpper(key) == "HIGH" {
							high = count
						}
					}
				}
			}
		}

		// By type
		if typeAgg, ok := aggs["by_type"].(map[string]interface{}); ok {
			if buckets, ok := typeAgg["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if b, ok := bucket.(map[string]interface{}); ok {
						key := fmt.Sprintf("%v", b["key"])
						count := int64(b["doc_count"].(float64))
						byType[key] = count
					}
				}
			}
		}

		// By source
		if sourceAgg, ok := aggs["by_source"].(map[string]interface{}); ok {
			if buckets, ok := sourceAgg["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if b, ok := bucket.(map[string]interface{}); ok {
						key := fmt.Sprintf("%v", b["key"])
						count := int64(b["doc_count"].(float64))
						bySource[key] = count
					}
				}
			}
		}

		// Timeline
		if timelineAgg, ok := aggs["timeline"].(map[string]interface{}); ok {
			if buckets, ok := timelineAgg["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if b, ok := bucket.(map[string]interface{}); ok {
						timeline = append(timeline, map[string]interface{}{
							"timestamp": b["key_as_string"],
							"count":     int64(b["doc_count"].(float64)),
						})
					}
				}
			}
		}
	}

	// Build top sources list
	var topSources []map[string]interface{}
	for source, count := range bySource {
		topSources = append(topSources, map[string]interface{}{
			"source": source,
			"count":  count,
		})
	}

	log.Printf("✅ OpenSearch statistics: total=%d, critical=%d, high=%d, sources=%d", total, critical, high, len(bySource))

	// Build events per hour for last 24h
	eventsPerHour := []map[string]interface{}{}
	for i, t := range timeline {
		if i < 24 { // Last 24 hours
			eventsPerHour = append(eventsPerHour, map[string]interface{}{
				"hour":  t["timestamp"],
				"count": t["count"],
			})
		}
	}

	return gin.H{
		"total":           total,
		"total_events":    total, // Also provide as total_events for frontend compatibility
		"critical":        critical,
		"high":            high,
		"by_severity":     bySeverity,
		"by_type":         byType,
		"by_source":       bySource,
		"timeline":        timeline,
		"events_per_hour": eventsPerHour,
		"top_sources":     topSources,
		"unique_sources":  len(bySource),
		"source":          "opensearch",
	}, nil
}

// handleExportEvents exporta eventos em diferentes formatos
func (s *APIServer) handleExportEvents(c *gin.Context) {
	// Parse query parameters (mesmos da busca)
	query := c.DefaultQuery("query", "*")
	// Default: últimos 30 dias para exportação
	startTime := c.DefaultQuery("start_time", time.Now().Add(-30*24*time.Hour).Format(time.RFC3339))
	endTime := c.DefaultQuery("end_time", time.Now().Format(time.RFC3339))
	sources := c.QueryArray("sources")
	severities := c.QueryArray("severities")
	types := c.QueryArray("types")
	format := c.DefaultQuery("format", "csv") // csv, json

	// Parse times
	start, err := time.Parse(time.RFC3339, startTime)
	if err != nil {
		start = time.Now().Add(-24 * time.Hour)
	}
	end, err := time.Parse(time.RFC3339, endTime)
	if err != nil {
		end = time.Now()
	}

	// Limite de segurança para exportação
	maxExportSize := 10000
	var events []Event

	// Tentar buscar do OpenSearch primeiro
	if s.opensearch != nil {
		// Construir query para OpenSearch
		mustClauses := []map[string]interface{}{
			{
				"range": map[string]interface{}{
					"timestamp": map[string]interface{}{
						"gte": start.Format(time.RFC3339),
						"lte": end.Format(time.RFC3339),
					},
				},
			},
		}

		// Adicionar query string se não for wildcard
		if query != "*" && query != "" {
			queryUpper := strings.ToUpper(strings.TrimSpace(query))
			if strings.HasPrefix(queryUpper, "CVE-") {
				mustClauses = append(mustClauses, map[string]interface{}{
					"query_string": map[string]interface{}{
						"query":            "\"" + queryUpper + "\"",
						"default_operator": "AND",
					},
				})
			} else {
				mustClauses = append(mustClauses, map[string]interface{}{
					"query_string": map[string]interface{}{
						"query": query,
					},
				})
			}
		}

		// Adicionar filtros
		if len(sources) > 0 {
			mustClauses = append(mustClauses, map[string]interface{}{
				"terms": map[string]interface{}{
					"source.keyword": sources,
				},
			})
		}
		if len(severities) > 0 {
			mustClauses = append(mustClauses, map[string]interface{}{
				"terms": map[string]interface{}{
					"severity.keyword": severities,
				},
			})
		}
		if len(types) > 0 {
			mustClauses = append(mustClauses, map[string]interface{}{
				"terms": map[string]interface{}{
					"type.keyword": types,
				},
			})
		}

		accessFilters := buildEventAccessFilter(getAccessScope(c))
		if len(accessFilters) > 0 {
			mustClauses = append(mustClauses, accessFilters...)
		}

		esQuery := map[string]interface{}{
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": mustClauses,
				},
			},
			"size": maxExportSize,
			"sort": []map[string]interface{}{
				{"timestamp": map[string]interface{}{"order": "desc"}},
			},
		}

		queryJSON, _ := json.Marshal(esQuery)

		res, err := s.opensearch.Search(
			s.opensearch.Search.WithContext(c.Request.Context()),
			s.opensearch.Search.WithIndex("siem-events-*"),
			s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
		)

		if err == nil && !res.IsError() {
			defer res.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&result); err == nil {
				if hits, ok := result["hits"].(map[string]interface{}); ok {
					if hitArray, ok := hits["hits"].([]interface{}); ok {
						for _, hit := range hitArray {
							if hitMap, ok := hit.(map[string]interface{}); ok {
								if source, ok := hitMap["_source"].(map[string]interface{}); ok {
									event := Event{
										ID:          getString(source, "id"),
										Severity:    getString(source, "severity"),
										Type:        getString(source, "type"),
										Source:      getString(source, "source"),
										Description: getString(source, "description"),
									}
									if ts, ok := source["timestamp"].(string); ok {
										event.Timestamp, _ = time.Parse(time.RFC3339, ts)
									}
									if tags, ok := source["tags"].([]interface{}); ok {
										for _, tag := range tags {
											if t, ok := tag.(string); ok {
												event.Tags = append(event.Tags, t)
											}
										}
									}
									events = append(events, event)
								}
							}
						}
					}
				}
			}
		}
	}

	// Se não conseguiu buscar do OpenSearch ou está vazio, usar mock apenas se permitido
	if len(events) == 0 {
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"error":   "No data available for export",
				"message": "OpenSearch not connected and mock data is disabled",
			})
			return
		}
		// Fallback para mock
		mockEvents := generateMockEvents(query, start, end, sources, severities, types, maxExportSize, 1)
		events = mockEvents.Events
	}

	// Limitar número de eventos exportados
	if len(events) > maxExportSize {
		events = events[:maxExportSize]
	}

	log.Printf("📤 Exporting %d events in %s format", len(events), format)

	// Gerar arquivo baseado no formato
	switch format {
	case "json":
		exportJSON(c, events)
	case "csv":
		exportCSV(c, events)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Formato não suportado. Use 'csv' ou 'json'"})
	}
}

// exportJSON exporta eventos em formato JSON
func exportJSON(c *gin.Context, events []Event) {
	filename := "events_export_" + time.Now().Format("20060102_150405") + ".json"

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "application/json")

	c.JSON(http.StatusOK, gin.H{
		"exported_at": time.Now().Format(time.RFC3339),
		"total":       len(events),
		"events":      events,
	})
}

// exportCSV exporta eventos em formato CSV
func exportCSV(c *gin.Context, events []Event) {
	filename := "events_export_" + time.Now().Format("20060102_150405") + ".csv"

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "text/csv")

	// Escrever cabeçalho CSV
	csv := "ID,Timestamp,Severity,Type,Source,Description,Tags\n"

	// Escrever dados
	for _, event := range events {
		// Escapar campos que podem conter vírgulas ou quebras de linha
		description := strings.ReplaceAll(event.Description, "\"", "\"\"")
		description = strings.ReplaceAll(description, "\n", " ")

		tags := ""
		if len(event.Tags) > 0 {
			tags = strings.Join(event.Tags, ";")
		}

		line := strings.Join([]string{
			event.ID,
			event.Timestamp.Format(time.RFC3339),
			event.Severity,
			event.Type,
			event.Source,
			"\"" + description + "\"",
			tags,
		}, ",") + "\n"

		csv += line
	}

	c.String(http.StatusOK, csv)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func parseTimestamp(val interface{}) time.Time {
	if str, ok := val.(string); ok {
		t, err := time.Parse(time.RFC3339, str)
		if err == nil {
			return t
		}
	}
	return time.Now()
}

// generateMockEvents gera eventos mockados para desenvolvimento/fallback
func generateMockEvents(query string, start, end time.Time, sources, severities, types []string, pageSize, pageNumber int) EventsResponse {
	allEvents := []Event{
		{
			ID:          "1",
			Timestamp:   time.Now().Add(-1 * time.Hour),
			Severity:    "HIGH",
			Type:        "Login Failed",
			Source:      "192.168.1.100",
			Description: "Múltiplas tentativas de login falhadas detectadas",
			Tags:        []string{"authentication", "brute-force"},
		},
		{
			ID:          "2",
			Timestamp:   time.Now().Add(-2 * time.Hour),
			Severity:    "CRITICAL",
			Type:        "SQL Injection",
			Source:      "203.0.113.42",
			Description: "Tentativa de SQL injection detectada no endpoint /api/users",
			Tags:        []string{"web-attack", "injection"},
		},
		{
			ID:          "3",
			Timestamp:   time.Now().Add(-3 * time.Hour),
			Severity:    "MEDIUM",
			Type:        "Firewall Block",
			Source:      "10.0.0.45",
			Description: "Tentativa de acesso a porta bloqueada (porta 3389)",
			Tags:        []string{"network", "firewall"},
		},
		{
			ID:          "4",
			Timestamp:   time.Now().Add(-4 * time.Hour),
			Severity:    "HIGH",
			Type:        "Malware Detected",
			Source:      "192.168.1.50",
			Description: "Arquivo malicioso detectado: trojan.exe",
			Tags:        []string{"malware", "endpoint"},
		},
		{
			ID:          "5",
			Timestamp:   time.Now().Add(-5 * time.Hour),
			Severity:    "MEDIUM",
			Type:        "Brute Force",
			Source:      "198.51.100.23",
			Description: "Ataque de força bruta em andamento no serviço SSH",
			Tags:        []string{"authentication", "brute-force"},
		},
		{
			ID:          "6",
			Timestamp:   time.Now().Add(-6 * time.Hour),
			Severity:    "LOW",
			Type:        "File Access",
			Source:      "192.168.1.75",
			Description: "Acesso a arquivo confidencial: /etc/shadow",
			Tags:        []string{"file-access", "audit"},
		},
		{
			ID:          "7",
			Timestamp:   time.Now().Add(-7 * time.Hour),
			Severity:    "CRITICAL",
			Type:        "Ransomware Activity",
			Source:      "192.168.1.120",
			Description: "Atividade suspeita de ransomware detectada",
			Tags:        []string{"malware", "ransomware"},
		},
		{
			ID:          "8",
			Timestamp:   time.Now().Add(-8 * time.Hour),
			Severity:    "HIGH",
			Type:        "Port Scan",
			Source:      "203.0.113.100",
			Description: "Varredura de portas detectada",
			Tags:        []string{"network", "reconnaissance"},
		},
		{
			ID:          "9",
			Timestamp:   time.Now().Add(-9 * time.Hour),
			Severity:    "MEDIUM",
			Type:        "Suspicious Process",
			Source:      "192.168.1.90",
			Description: "Processo suspeito executado: powershell.exe -enc",
			Tags:        []string{"endpoint", "process"},
		},
		{
			ID:          "10",
			Timestamp:   time.Now().Add(-10 * time.Hour),
			Severity:    "LOW",
			Type:        "Configuration Change",
			Source:      "192.168.1.1",
			Description: "Alteração de configuração no firewall",
			Tags:        []string{"configuration", "audit"},
		},
	}

	// Filtrar eventos
	filtered := make([]Event, 0)
	for _, event := range allEvents {
		// Filtro de tempo
		if event.Timestamp.Before(start) || event.Timestamp.After(end) {
			continue
		}

		// Filtro de severidade
		if len(severities) > 0 {
			found := false
			for _, sev := range severities {
				if event.Severity == sev {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filtro de tipo
		if len(types) > 0 {
			found := false
			for _, t := range types {
				if event.Type == t {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filtro de source
		if len(sources) > 0 {
			found := false
			for _, src := range sources {
				if event.Source == src {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filtro de query
		if query != "*" && query != "" {
			queryLower := strings.ToLower(query)
			if !strings.Contains(strings.ToLower(event.Description), queryLower) &&
				!strings.Contains(strings.ToLower(event.Type), queryLower) &&
				!strings.Contains(strings.ToLower(event.Source), queryLower) {
				continue
			}
		}

		filtered = append(filtered, event)
	}

	// Paginação
	total := int64(len(filtered))
	start_idx := (pageNumber - 1) * pageSize
	end_idx := start_idx + pageSize

	if start_idx > len(filtered) {
		filtered = []Event{}
	} else if end_idx > len(filtered) {
		filtered = filtered[start_idx:]
	} else {
		filtered = filtered[start_idx:end_idx]
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	return EventsResponse{
		Events:     filtered,
		Total:      total,
		Page:       pageNumber,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}
}

// generateMockStatistics gera estatísticas mockadas
func generateMockStatistics(start, end time.Time) EventStatistics {
	return EventStatistics{
		Total: 1247,
		BySeverity: map[string]int64{
			"CRITICAL": 45,
			"HIGH":     234,
			"MEDIUM":   567,
			"LOW":      401,
		},
		ByType: map[string]int64{
			"Login Failed":         156,
			"Firewall Block":       234,
			"Malware Detected":     89,
			"SQL Injection":        45,
			"Brute Force":          123,
			"Port Scan":            78,
			"Suspicious Process":   145,
			"File Access":          267,
			"Configuration Change": 110,
		},
		BySource: map[string]int64{
			"192.168.1.100": 234,
			"192.168.1.50":  189,
			"203.0.113.42":  145,
			"10.0.0.45":     123,
			"198.51.100.23": 98,
		},
		Timeline: []TimelinePoint{
			{Timestamp: time.Now().Add(-23 * time.Hour), Count: 45},
			{Timestamp: time.Now().Add(-22 * time.Hour), Count: 52},
			{Timestamp: time.Now().Add(-21 * time.Hour), Count: 48},
			{Timestamp: time.Now().Add(-20 * time.Hour), Count: 61},
			{Timestamp: time.Now().Add(-19 * time.Hour), Count: 55},
			{Timestamp: time.Now().Add(-18 * time.Hour), Count: 49},
			{Timestamp: time.Now().Add(-17 * time.Hour), Count: 58},
			{Timestamp: time.Now().Add(-16 * time.Hour), Count: 63},
			{Timestamp: time.Now().Add(-15 * time.Hour), Count: 71},
			{Timestamp: time.Now().Add(-14 * time.Hour), Count: 67},
			{Timestamp: time.Now().Add(-13 * time.Hour), Count: 54},
			{Timestamp: time.Now().Add(-12 * time.Hour), Count: 49},
			{Timestamp: time.Now().Add(-11 * time.Hour), Count: 56},
			{Timestamp: time.Now().Add(-10 * time.Hour), Count: 62},
			{Timestamp: time.Now().Add(-9 * time.Hour), Count: 58},
			{Timestamp: time.Now().Add(-8 * time.Hour), Count: 51},
			{Timestamp: time.Now().Add(-7 * time.Hour), Count: 47},
			{Timestamp: time.Now().Add(-6 * time.Hour), Count: 53},
			{Timestamp: time.Now().Add(-5 * time.Hour), Count: 59},
			{Timestamp: time.Now().Add(-4 * time.Hour), Count: 64},
			{Timestamp: time.Now().Add(-3 * time.Hour), Count: 68},
			{Timestamp: time.Now().Add(-2 * time.Hour), Count: 72},
			{Timestamp: time.Now().Add(-1 * time.Hour), Count: 76},
			{Timestamp: time.Now(), Count: 80},
		},
		TopSources: []SourceStat{
			{Source: "192.168.1.100", Count: 234},
			{Source: "192.168.1.50", Count: 189},
			{Source: "203.0.113.42", Count: 145},
			{Source: "10.0.0.45", Count: 123},
			{Source: "198.51.100.23", Count: 98},
		},
		RecentEvents: []Event{
			{
				ID:          "1",
				Timestamp:   time.Now().Add(-5 * time.Minute),
				Severity:    "HIGH",
				Type:        "Login Failed",
				Source:      "192.168.1.100",
				Description: "Múltiplas tentativas de login falhadas",
			},
			{
				ID:          "2",
				Timestamp:   time.Now().Add(-10 * time.Minute),
				Severity:    "CRITICAL",
				Type:        "SQL Injection",
				Source:      "203.0.113.42",
				Description: "Tentativa de SQL injection detectada",
			},
			{
				ID:          "3",
				Timestamp:   time.Now().Add(-15 * time.Minute),
				Severity:    "MEDIUM",
				Type:        "Firewall Block",
				Source:      "10.0.0.45",
				Description: "Tentativa de acesso a porta bloqueada",
			},
		},
	}
}
