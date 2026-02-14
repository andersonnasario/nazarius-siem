package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// IOC (Indicator of Compromise) representa um indicador de comprometimento
type IOC struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // ip, domain, hash, url, cve
	Value       string                 `json:"value"`
	Threat      string                 `json:"threat"`     // malware, botnet, phishing, c2, etc.
	Severity    string                 `json:"severity"`   // critical, high, medium, low
	Confidence  int                    `json:"confidence"` // 0-100
	Source      string                 `json:"source"`     // otx, abuseipdb, virustotal, manual
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
	FirstSeen   time.Time              `json:"firstSeen"`
	LastSeen    time.Time              `json:"lastSeen"`
	IsActive    bool                   `json:"isActive"`
	EventCount  int                    `json:"eventCount"` // quantos eventos internos matcham
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatFeed representa um feed de threat intelligence
type ThreatFeed struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Source     string            `json:"source"`
	Type       string            `json:"type"` // public, commercial, custom
	Enabled    bool              `json:"enabled"`
	UpdateFreq int               `json:"updateFrequency"` // minutos
	LastUpdate time.Time         `json:"lastUpdate"`
	NextUpdate time.Time         `json:"nextUpdate"`
	IOCCount   int               `json:"iocCount"`
	Config     map[string]string `json:"config"`
}

// IPReputation representa a reputação de um IP
type IPReputation struct {
	IP           string    `json:"ip"`
	Score        int       `json:"score"` // 0-100 (0=limpo, 100=malicioso)
	Country      string    `json:"country"`
	ISP          string    `json:"isp"`
	IsTor        bool      `json:"isTor"`
	IsVPN        bool      `json:"isVpn"`
	IsProxy      bool      `json:"isProxy"`
	TotalReports int       `json:"totalReports"`
	Categories   []string  `json:"categories"`
	LastReported time.Time `json:"lastReported"`
	Source       string    `json:"source"`
}

// ThreatActor representa um ator de ameaça (APT, grupo)
type ThreatActor struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Aliases      []string  `json:"aliases"`
	Country      string    `json:"country"`
	Motivation   string    `json:"motivation"` // financial, espionage, sabotage
	Targets      []string  `json:"targets"`    // setores alvo
	TTPs         []string  `json:"ttps"`       // MITRE techniques
	IOCs         []string  `json:"iocs"`       // IDs dos IOCs associados
	FirstSeen    time.Time `json:"firstSeen"`
	LastActivity time.Time `json:"lastActivity"`
}

// ThreatIntelStats estatísticas gerais
type ThreatIntelStats struct {
	TotalIOCs      int             `json:"totalIOCs"`
	ActiveIOCs     int             `json:"activeIOCs"`
	IOCsByType     map[string]int  `json:"iocsByType"`
	IOCsBySeverity map[string]int  `json:"iocsBySeverity"`
	TopThreats     []ThreatSummary `json:"topThreats"`
	RecentIOCs     []IOC           `json:"recentIOCs"`
	EventsEnriched int             `json:"eventsEnriched"`
	FeedsActive    int             `json:"feedsActive"`
	TopCountries   []CountryThreat `json:"topCountries"`
}

// ThreatSummary resumo de ameaça
type ThreatSummary struct {
	Threat   string `json:"threat"`
	Count    int    `json:"count"`
	Severity string `json:"severity"`
}

// CountryThreat ameaças por país
type CountryThreat struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
	Score   int    `json:"score"`
}

// EnrichmentResult resultado do enrichment
type EnrichmentResult struct {
	IP          string        `json:"ip,omitempty"`
	Domain      string        `json:"domain,omitempty"`
	Hash        string        `json:"hash,omitempty"`
	IsMalicious bool          `json:"isMalicious"`
	Reputation  *IPReputation `json:"reputation,omitempty"`
	MatchedIOCs []IOC         `json:"matchedIOCs"`
	RiskScore   int           `json:"riskScore"` // 0-100
	Sources     []string      `json:"sources"`
}

// handleListIOCs lista todos os IOCs from OpenSearch
func (s *APIServer) handleListIOCs(c *gin.Context) {
	// Parâmetros de filtro
	iocType := c.Query("type")
	severity := c.Query("severity")
	threat := c.Query("threat")
	search := c.Query("search")

	// Buscar do OpenSearch
	iocs, total, err := s.fetchIOCsFromOS(iocType, severity, threat, search, 100)
	if err != nil {
		// Se mock estiver desabilitado, retornar array vazio
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"iocs":       []IOC{},
				"total":      0,
				"dataSource": "opensearch",
				"message":    "No IOCs found. Add IOCs via API or sync threat feeds.",
			})
			return
		}
		// Log do erro mas continuar
		s.logger.Printf("OpenSearch error fetching IOCs: %v", err)
	}

	// Converter para formato de API
	apiIOCs := make([]IOC, len(iocs))
	for i, ioc := range iocs {
		apiIOCs[i] = convertIOCOpenSearchToIOC(ioc)
	}

	c.JSON(http.StatusOK, gin.H{
		"iocs":       apiIOCs,
		"total":      total,
		"dataSource": "opensearch",
	})
}

// handleGetIOC obtém detalhes de um IOC do OpenSearch
func (s *APIServer) handleGetIOC(c *gin.Context) {
	iocID := c.Param("id")

	// Buscar do OpenSearch
	iocOS, err := s.getIOCByIDFromOS(iocID)
	if err != nil || iocOS == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "IOC not found",
			"id":      iocID,
			"message": "The requested IOC does not exist in the database.",
		})
		return
	}

	ioc := convertIOCOpenSearchToIOC(*iocOS)
	c.JSON(http.StatusOK, ioc)
}

// handleEnrichIP enriquece um IP com threat intelligence usando APIs reais
func (s *APIServer) handleEnrichIP(c *gin.Context) {
	ip := c.Param("ip")

	// Usar ThreatIntelManager para lookup real
	tim := GetThreatIntelManager()
	tiResult, err := tim.LookupIOC(ip, IOCTypeIP)

	var reputation *IPReputation
	var riskScore int
	var sources []string
	var isMalicious bool

	if err == nil && tiResult != nil {
		// Extrair dados de geo se disponíveis
		country := "Unknown"
		isp := "Unknown"
		if tiResult.GeoData != nil {
			country = tiResult.GeoData.Country
			isp = tiResult.GeoData.ISP
		}

		// Extrair lastSeen
		var lastReported time.Time
		if tiResult.LastSeen != nil {
			lastReported = *tiResult.LastSeen
		}

		// Converter resultado do ThreatIntelManager para IPReputation
		reputation = &IPReputation{
			IP:           ip,
			Score:        tiResult.ThreatScore,
			Country:      country,
			ISP:          isp,
			IsTor:        false, // ThreatIntelResult não tem esses campos
			IsVPN:        false,
			IsProxy:      false,
			TotalReports: 0,
			Categories:   tiResult.Categories,
			LastReported: lastReported,
			Source:       "multi-source",
		}
		riskScore = tiResult.ThreatScore
		sources = tiResult.Sources
		isMalicious = tiResult.IsMalicious
	} else {
		// Sem dados de reputação disponíveis
		reputation = &IPReputation{
			IP:           ip,
			Score:        0,
			Country:      "Unknown",
			ISP:          "Unknown",
			TotalReports: 0,
			Categories:   []string{},
			Source:       "none",
		}
		riskScore = 0
		sources = []string{}
		isMalicious = false
	}

	// Buscar IOCs que correspondem a este IP no OpenSearch
	matchedIOCs := []IOC{}
	iocs, _, _ := s.fetchIOCsFromOS("ip", "", "", ip, 10)
	for _, iocOS := range iocs {
		matchedIOCs = append(matchedIOCs, convertIOCOpenSearchToIOC(iocOS))
	}

	result := EnrichmentResult{
		IP:          ip,
		IsMalicious: isMalicious,
		Reputation:  reputation,
		MatchedIOCs: matchedIOCs,
		RiskScore:   riskScore,
		Sources:     sources,
	}

	c.JSON(http.StatusOK, result)
}

// handleListFeeds lista feeds configurados do OpenSearch
func (s *APIServer) handleListFeeds(c *gin.Context) {
	// Buscar do OpenSearch
	feedsOS, err := s.fetchFeedsFromOS()
	if err != nil {
		// Se mock estiver desabilitado, retornar array vazio
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"feeds":      []ThreatFeed{},
				"total":      0,
				"dataSource": "opensearch",
				"message":    "No feeds configured. Configure threat feeds in settings.",
			})
			return
		}
		s.logger.Printf("OpenSearch error fetching feeds: %v", err)
	}

	feeds := make([]ThreatFeed, len(feedsOS))
	for i, feedOS := range feedsOS {
		feeds[i] = convertThreatFeedOpenSearchToThreatFeed(feedOS)
	}

	c.JSON(http.StatusOK, gin.H{
		"feeds":      feeds,
		"total":      len(feeds),
		"dataSource": "opensearch",
	})
}

// handleGetTIStats retorna estatísticas gerais de TI do OpenSearch
func (s *APIServer) handleGetTIStats(c *gin.Context) {
	// Buscar do OpenSearch
	statsOS, err := s.getThreatIntelStatsFromOS()
	if err != nil || statsOS == nil {
		// Se mock estiver desabilitado ou erro, retornar stats vazias
		if IsMockDataDisabled() || err != nil {
			emptyStats := ThreatIntelStats{
				TotalIOCs:      0,
				ActiveIOCs:     0,
				IOCsByType:     map[string]int{},
				IOCsBySeverity: map[string]int{},
				TopThreats:     []ThreatSummary{},
				RecentIOCs:     []IOC{},
				EventsEnriched: 0,
				FeedsActive:    0,
				TopCountries:   []CountryThreat{},
			}
			c.JSON(http.StatusOK, gin.H{
				"stats":      emptyStats,
				"dataSource": "opensearch",
				"message":    "No threat intelligence data available. Add IOCs or configure feeds.",
			})
			return
		}
	}

	// Converter para formato de API
	recentIOCs := make([]IOC, len(statsOS.RecentIOCs))
	for i, iocOS := range statsOS.RecentIOCs {
		recentIOCs[i] = convertIOCOpenSearchToIOC(iocOS)
	}

	stats := ThreatIntelStats{
		TotalIOCs:      statsOS.TotalIOCs,
		ActiveIOCs:     statsOS.ActiveIOCs,
		IOCsByType:     statsOS.IOCsByType,
		IOCsBySeverity: statsOS.IOCsBySeverity,
		TopThreats:     statsOS.TopThreats,
		RecentIOCs:     recentIOCs,
		EventsEnriched: statsOS.EventsEnriched,
		FeedsActive:    statsOS.FeedsActive,
		TopCountries:   statsOS.TopCountries,
	}

	c.JSON(http.StatusOK, gin.H{
		"stats":      stats,
		"dataSource": "opensearch",
	})
}

// handleCheckIP verifica reputação de um IP usando APIs reais
func (s *APIServer) handleCheckIP(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP parameter required"})
		return
	}

	// Usar ThreatIntelManager para lookup real
	tim := GetThreatIntelManager()
	tiResult, err := tim.LookupIOC(ip, IOCTypeIP)

	var reputation IPReputation
	if err == nil && tiResult != nil {
		// Extrair dados de geo se disponíveis
		country := "Unknown"
		isp := "Unknown"
		if tiResult.GeoData != nil {
			country = tiResult.GeoData.Country
			isp = tiResult.GeoData.ISP
		}

		// Extrair lastSeen
		var lastReported time.Time
		if tiResult.LastSeen != nil {
			lastReported = *tiResult.LastSeen
		}

		reputation = IPReputation{
			IP:           ip,
			Score:        tiResult.ThreatScore,
			Country:      country,
			ISP:          isp,
			IsTor:        false,
			IsVPN:        false,
			IsProxy:      false,
			TotalReports: 0,
			Categories:   tiResult.Categories,
			LastReported: lastReported,
			Source:       "multi-source",
		}
	} else {
		// IP não encontrado em nenhuma fonte (considerado limpo)
		reputation = IPReputation{
			IP:           ip,
			Score:        0,
			Country:      "Unknown",
			ISP:          "Unknown",
			IsTor:        false,
			IsVPN:        false,
			IsProxy:      false,
			TotalReports: 0,
			Categories:   []string{},
			LastReported: time.Time{},
			Source:       "none",
		}
	}

	c.JSON(http.StatusOK, reputation)
}

// handleCreateIOC cria um IOC no OpenSearch
func (s *APIServer) handleCreateIOC(c *gin.Context) {
	var input struct {
		Type        string                 `json:"type" binding:"required"`
		Value       string                 `json:"value" binding:"required"`
		Threat      string                 `json:"threat"`
		Severity    string                 `json:"severity"`
		Confidence  int                    `json:"confidence"`
		Description string                 `json:"description"`
		Tags        []string               `json:"tags"`
		Metadata    map[string]interface{} `json:"metadata"`
		Country     string                 `json:"country"`
		ExpiresAt   *time.Time             `json:"expiresAt"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("[ERROR] create IOC bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validar tipo
	validTypes := map[string]bool{"ip": true, "domain": true, "hash": true, "url": true, "cve": true, "email": true}
	if !validTypes[input.Type] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IOC type. Must be: ip, domain, hash, url, cve, email"})
		return
	}

	// Validar severidade
	if input.Severity == "" {
		input.Severity = "medium"
	}
	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	if !validSeverities[input.Severity] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid severity. Must be: critical, high, medium, low"})
		return
	}

	// Criar IOC no OpenSearch
	iocOS := IOCOpenSearch{
		Type:        input.Type,
		Value:       input.Value,
		Threat:      input.Threat,
		Severity:    input.Severity,
		Confidence:  input.Confidence,
		Source:      "manual",
		Description: input.Description,
		Tags:        input.Tags,
		Metadata:    input.Metadata,
		Country:     input.Country,
		CreatedBy:   "api",
		ExpiresAt:   input.ExpiresAt,
	}

	created, err := s.createIOCInOS(iocOS)
	if err != nil {
		s.logger.Printf("Failed to create IOC in OpenSearch: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create IOC",
			"message": "Unable to save IOC to database. Please try again.",
		})
		return
	}

	ioc := convertIOCOpenSearchToIOC(*created)
	c.JSON(http.StatusCreated, gin.H{
		"ioc":        ioc,
		"message":    "IOC created successfully",
		"dataSource": "opensearch",
	})
}

// handleUpdateIOC atualiza um IOC no OpenSearch
func (s *APIServer) handleUpdateIOC(c *gin.Context) {
	iocID := c.Param("id")

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		log.Printf("[ERROR] update IOC bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validar campos permitidos
	allowedFields := map[string]bool{
		"severity": true, "confidence": true, "description": true,
		"tags": true, "threat": true, "is_active": true, "metadata": true,
	}

	for key := range updates {
		if !allowedFields[key] {
			delete(updates, key)
		}
	}

	err := s.updateIOCInOS(iocID, updates)
	if err != nil {
		s.logger.Printf("Failed to update IOC %s in OpenSearch: %v", iocID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to update IOC",
			"id":      iocID,
			"message": "Unable to update IOC in database. Please try again.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         iocID,
		"message":    "IOC updated successfully",
		"updates":    updates,
		"dataSource": "opensearch",
	})
}

// handleDeleteIOC deleta (desativa) um IOC no OpenSearch
func (s *APIServer) handleDeleteIOC(c *gin.Context) {
	iocID := c.Param("id")

	err := s.deleteIOCFromOS(iocID)
	if err != nil {
		s.logger.Printf("Failed to delete IOC %s from OpenSearch: %v", iocID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to delete IOC",
			"id":      iocID,
			"message": "Unable to delete IOC from database. Please try again.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "IOC deactivated successfully",
		"id":         iocID,
		"dataSource": "opensearch",
	})
}

// handleGetIOCRelatedEvents busca eventos no OpenSearch que referenciam o valor de um IOC
func (s *APIServer) handleGetIOCRelatedEvents(c *gin.Context) {
	iocValue := c.Query("value")
	if iocValue == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parâmetro 'value' é obrigatório"})
		return
	}

	limitStr := c.DefaultQuery("limit", "50")
	limit := 50
	if l, err := parseIntSafe(limitStr); err == nil && l > 0 && l <= 200 {
		limit = l
	}

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"events": []interface{}{},
			"total":  0,
			"source": "none",
		})
		return
	}

	// Buscar em todos os campos usando a mesma lógica do countEventsByCVE
	query := map[string]interface{}{
		"size":             limit,
		"track_total_hits": true,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"match_phrase": map[string]interface{}{"description": iocValue}},
					{"match_phrase": map[string]interface{}{"type": iocValue}},
					{"match_phrase": map[string]interface{}{"source": iocValue}},
					{"match_phrase": map[string]interface{}{"name": iocValue}},
					{"match_phrase": map[string]interface{}{"message": iocValue}},
					{"match_phrase": map[string]interface{}{"source_ip": iocValue}},
					{"match_phrase": map[string]interface{}{"dest_ip": iocValue}},
					{"match_phrase": map[string]interface{}{"domain": iocValue}},
					{"match_phrase": map[string]interface{}{"url": iocValue}},
					{"match_phrase": map[string]interface{}{"query": iocValue}},
					{
						"query_string": map[string]interface{}{
							"query":            "\"" + sanitizeSearchQuery(iocValue) + "\"",
							"default_operator": "AND",
						},
					},
				},
				"minimum_should_match": 1,
			},
		},
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc", "unmapped_type": "date"}},
			{"@timestamp": map[string]interface{}{"order": "desc", "unmapped_type": "date"}},
		},
	}

	queryJSON, _ := json.Marshal(query)

	// Buscar em todos os índices possíveis - eventos, alertas e mais
	indexPatterns := []string{}

	// Adicionar padrão configurado
	if s.config.Elasticsearch.IndexPattern != "" {
		indexPatterns = append(indexPatterns, s.config.Elasticsearch.IndexPattern)
	}
	// Adicionar padrões comuns
	indexPatterns = append(indexPatterns, "siem-events-*", "siem-events", "siem-alerts")

	// Deduplicate
	seen := map[string]bool{}
	uniquePatterns := []string{}
	for _, p := range indexPatterns {
		if !seen[p] {
			seen[p] = true
			uniquePatterns = append(uniquePatterns, p)
		}
	}

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(c.Request.Context()),
		s.opensearch.Search.WithIndex(uniquePatterns...),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
		s.opensearch.Search.WithIgnoreUnavailable(true),
	)
	if err != nil {
		log.Printf("[ERROR] get IOC related events search: %v", err)
		c.JSON(http.StatusOK, gin.H{
			"events": []interface{}{},
			"total":  0,
			"error":  "Connection error",
			"source": "error",
		})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		bodyBytes, _ := io.ReadAll(res.Body)
		c.JSON(http.StatusOK, gin.H{
			"events": []interface{}{},
			"total":  0,
			"error":  string(bodyBytes),
			"source": "error",
		})
		return
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao decodificar resposta"})
		return
	}

	hits := result["hits"].(map[string]interface{})
	total := int(hits["total"].(map[string]interface{})["value"].(float64))
	hitsList := hits["hits"].([]interface{})

	events := make([]map[string]interface{}, 0, len(hitsList))
	for _, hit := range hitsList {
		hitMap := hit.(map[string]interface{})
		source := hitMap["_source"].(map[string]interface{})
		index := hitMap["_index"].(string)

		event := map[string]interface{}{
			"id":    hitMap["_id"],
			"index": index,
		}

		// Copiar campos relevantes
		for _, field := range []string{
			"timestamp", "@timestamp", "severity", "type", "source", "description",
			"message", "name", "source_ip", "dest_ip", "src_ip", "dst_ip",
			"domain", "url", "user", "action", "rule_name", "event_type",
			"category", "tags", "level", "priority", "query", "status",
			"created_at", "updated_at",
		} {
			if v, ok := source[field]; ok {
				event[field] = v
			}
		}

		// Garantir que timestamp existe
		if _, ok := event["timestamp"]; !ok {
			if ts, ok := source["@timestamp"]; ok {
				event["timestamp"] = ts
			} else if ts, ok := source["created_at"]; ok {
				event["timestamp"] = ts
			}
		}

		events = append(events, event)
	}

	c.JSON(http.StatusOK, gin.H{
		"events":  events,
		"total":   total,
		"limit":   limit,
		"source":  "opensearch",
		"indices": uniquePatterns,
	})
}

// EnrichEventWithTI enriquece um evento com threat intelligence real
func EnrichEventWithTI(event map[string]interface{}) map[string]interface{} {
	enriched := event
	enriched["ti_enriched"] = true
	enriched["ti_timestamp"] = time.Now()

	// Usar ThreatIntelManager para enrichment real
	tim := GetThreatIntelManager()

	// Enriquecer source IP se presente
	if sourceIP, ok := event["source_ip"].(string); ok && sourceIP != "" {
		result, err := tim.LookupIOC(sourceIP, IOCTypeIP)
		if err == nil && result != nil {
			country := ""
			if result.GeoData != nil {
				country = result.GeoData.Country
			}
			enriched["source_ip_reputation"] = map[string]interface{}{
				"score":      result.ThreatScore,
				"country":    country,
				"malicious":  result.IsMalicious,
				"categories": result.Categories,
				"sources":    result.Sources,
				"confidence": result.Confidence,
			}
		}
	}

	// Enriquecer destination IP se presente
	if destIP, ok := event["dest_ip"].(string); ok && destIP != "" {
		result, err := tim.LookupIOC(destIP, IOCTypeIP)
		if err == nil && result != nil {
			country := ""
			if result.GeoData != nil {
				country = result.GeoData.Country
			}
			enriched["dest_ip_reputation"] = map[string]interface{}{
				"score":      result.ThreatScore,
				"country":    country,
				"malicious":  result.IsMalicious,
				"categories": result.Categories,
				"sources":    result.Sources,
				"confidence": result.Confidence,
			}
		}
	}

	// Enriquecer domain se presente
	if domain, ok := event["domain"].(string); ok && domain != "" {
		result, err := tim.LookupIOC(domain, IOCTypeDomain)
		if err == nil && result != nil {
			enriched["domain_reputation"] = map[string]interface{}{
				"score":      result.ThreatScore,
				"malicious":  result.IsMalicious,
				"categories": result.Categories,
				"sources":    result.Sources,
				"confidence": result.Confidence,
			}
		}
	}

	return enriched
}
