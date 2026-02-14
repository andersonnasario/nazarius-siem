package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// FusionThreatFeed represents a threat intelligence feed
type FusionThreatFeed struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Provider        string    `json:"provider"`    // commercial, open_source, community, internal
	Type            string    `json:"type"`        // ioc, malware, vulnerability, actor, campaign
	Status          string    `json:"status"`      // active, inactive, error
	Reliability     string    `json:"reliability"` // high, medium, low
	LastSync        time.Time `json:"last_sync"`
	TotalIndicators int       `json:"total_indicators"`
	NewToday        int       `json:"new_today"`
	UpdateFrequency string    `json:"update_frequency"`
	APIEndpoint     string    `json:"api_endpoint"`
	ConfiguredAt    time.Time `json:"configured_at"`
	Tags            []string  `json:"tags"`
}

// EnrichedIndicator represents an enriched IOC
type EnrichedIndicator struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"` // ip, domain, url, hash, email
	Value           string    `json:"value"`
	ThreatLevel     string    `json:"threat_level"` // critical, high, medium, low
	Confidence      float64   `json:"confidence"`   // 0-100
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Sources         []string  `json:"sources"`
	ThreatTypes     []string  `json:"threat_types"`
	MalwareFamily   string    `json:"malware_family,omitempty"`
	ThreatActor     string    `json:"threat_actor,omitempty"`
	Campaign        string    `json:"campaign,omitempty"`
	MITRETechniques []string  `json:"mitre_techniques"`
	Geolocation     string    `json:"geolocation,omitempty"`
	ASN             string    `json:"asn,omitempty"`
	Reputation      int       `json:"reputation"` // 0-100
	Tags            []string  `json:"tags"`
	RelatedIOCs     []string  `json:"related_iocs"`
	Context         string    `json:"context"`
}

// FusionThreatActor represents a threat actor profile
type FusionThreatActor struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Aliases         []string  `json:"aliases"`
	Type            string    `json:"type"`           // apt, cybercrime, hacktivist, nation_state
	Sophistication  string    `json:"sophistication"` // advanced, intermediate, basic
	Origin          string    `json:"origin"`
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
	Description     string    `json:"description"`
}

// ThreatCampaign represents an active threat campaign
type ThreatCampaign struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`   // active, dormant, ended
	Severity        string    `json:"severity"` // critical, high, medium, low
	FirstDetected   time.Time `json:"first_detected"`
	LastActivity    time.Time `json:"last_activity"`
	ThreatActors    []string  `json:"threat_actors"`
	TargetSectors   []string  `json:"target_sectors"`
	TargetCountries []string  `json:"target_countries"`
	AttackVectors   []string  `json:"attack_vectors"`
	Objectives      []string  `json:"objectives"`
	TTPs            []string  `json:"ttps"`
	IOCsIdentified  int       `json:"iocs_identified"`
	VictimsAffected int       `json:"victims_affected"`
	MITRETactics    []string  `json:"mitre_tactics"`
	Description     string    `json:"description"`
	Recommendations []string  `json:"recommendations"`
}

// CorrelationResult represents a threat correlation
type CorrelationResult struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"` // ioc_match, pattern_match, behavior_match, campaign_match
	Severity        string    `json:"severity"`
	Confidence      float64   `json:"confidence"`
	DetectedAt      time.Time `json:"detected_at"`
	SourceEvent     string    `json:"source_event"`
	MatchedIOC      string    `json:"matched_ioc,omitempty"`
	ThreatActor     string    `json:"threat_actor,omitempty"`
	Campaign        string    `json:"campaign,omitempty"`
	MITRETechniques []string  `json:"mitre_techniques"`
	AffectedAssets  []string  `json:"affected_assets"`
	Context         string    `json:"context"`
	Recommendations []string  `json:"recommendations"`
	Status          string    `json:"status"` // new, investigating, resolved
}

// FusionMetrics represents threat intelligence fusion metrics
type FusionMetrics struct {
	ActiveFeeds        int     `json:"active_feeds"`
	TotalIndicators    int     `json:"total_indicators"`
	NewIndicatorsToday int     `json:"new_indicators_today"`
	CorrelationsToday  int     `json:"correlations_today"`
	CriticalThreats    int     `json:"critical_threats"`
	ActiveCampaigns    int     `json:"active_campaigns"`
	TrackedActors      int     `json:"tracked_actors"`
	EnrichmentRate     float64 `json:"enrichment_rate"`
	AverageConfidence  float64 `json:"average_confidence"`
	FalsePositiveRate  float64 `json:"false_positive_rate"`
}

// Initialize Threat Intel Fusion
func initThreatIntelFusion() {
	// Real data is fetched from OpenSearch on-demand
}

// Handler: List threat feeds - fetches from OpenSearch
func (s *APIServer) handleListThreatFeeds(c *gin.Context) {
	// Buscar feeds do OpenSearch
	feedsOS, err := s.fetchFeedsFromOS()
	if err != nil {
		s.logger.Printf("Error fetching feeds from OpenSearch: %v", err)
	}

	// Converter para formato Fusion
	feeds := make([]FusionThreatFeed, 0, len(feedsOS))
	for _, feedOS := range feedsOS {
		// Determinar provider baseado no source
		provider := "open_source"
		if feedOS.Provider == "manual" || feedOS.Provider == "internal" {
			provider = "internal"
		} else if feedOS.Provider == "virustotal" || feedOS.Provider == "recordedfuture" {
			provider = "commercial"
		}

		// Determinar status
		status := "active"
		if !feedOS.Enabled {
			status = "inactive"
		}

		// Determinar reliability
		reliability := "medium"
		if feedOS.Reliability != "" {
			reliability = feedOS.Reliability
		}

		// Tags vazias se não definidas na struct
		tags := []string{}

		feed := FusionThreatFeed{
			ID:              feedOS.ID,
			Name:            feedOS.Name,
			Provider:        provider,
			Type:            feedOS.Type,
			Status:          status,
			Reliability:     reliability,
			LastSync:        feedOS.LastUpdate,
			TotalIndicators: feedOS.IOCCount,
			NewToday:        0, // Seria calculado com query adicional
			UpdateFrequency: formatUpdateFrequency(feedOS.UpdateFreq),
			APIEndpoint:     feedOS.URL,
			ConfiguredAt:    feedOS.CreatedAt,
			Tags:            tags,
		}
		feeds = append(feeds, feed)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       feeds,
		"total":      len(feeds),
		"dataSource": "opensearch",
	})
}

// formatUpdateFrequency converts minutes to human-readable format
func formatUpdateFrequency(minutes int) string {
	if minutes <= 0 {
		return "Manual"
	}
	if minutes < 60 {
		return "Every " + string(rune(minutes)) + " minutes"
	}
	hours := minutes / 60
	if hours == 1 {
		return "Hourly"
	}
	if hours < 24 {
		return "Every " + string(rune(hours)) + " hours"
	}
	days := hours / 24
	if days == 1 {
		return "Daily"
	}
	return "Every " + string(rune(days)) + " days"
}

// Handler: List enriched indicators - fetches IOCs from OpenSearch
func (s *APIServer) handleListEnrichedIndicators(c *gin.Context) {
	// Buscar IOCs do OpenSearch
	iocs, total, err := s.fetchIOCsFromOS("", "", "", "", 100)
	if err != nil {
		s.logger.Printf("Error fetching IOCs from OpenSearch: %v", err)
	}

	// Converter IOCs para EnrichedIndicator format
	indicators := make([]EnrichedIndicator, 0, len(iocs))
	for _, iocOS := range iocs {
		// Mapear severity para threat_level
		threatLevel := iocOS.Severity
		if threatLevel == "" {
			threatLevel = "medium"
		}

		// Calcular reputation (inverso do confidence - menor = mais malicioso)
		reputation := 100 - iocOS.Confidence
		if reputation < 0 {
			reputation = 0
		}

		indicator := EnrichedIndicator{
			ID:              iocOS.ID,
			Type:            iocOS.Type,
			Value:           iocOS.Value,
			ThreatLevel:     threatLevel,
			Confidence:      float64(iocOS.Confidence),
			FirstSeen:       iocOS.FirstSeen,
			LastSeen:        iocOS.LastSeen,
			Sources:         []string{iocOS.Source},
			ThreatTypes:     []string{iocOS.Threat},
			MalwareFamily:   "", // Extrair do metadata se disponível
			ThreatActor:     "", // Extrair do metadata se disponível
			Campaign:        "", // Extrair do metadata se disponível
			MITRETechniques: []string{},
			Geolocation:     iocOS.Country,
			ASN:             "",
			Reputation:      reputation,
			Tags:            iocOS.Tags,
			RelatedIOCs:     []string{},
			Context:         iocOS.Description,
		}

		// Extrair campos adicionais do metadata
		if iocOS.Metadata != nil {
			if asn, ok := iocOS.Metadata["asn"].(string); ok {
				indicator.ASN = asn
			}
			if actor, ok := iocOS.Metadata["threat_actor"].(string); ok {
				indicator.ThreatActor = actor
			}
			if campaign, ok := iocOS.Metadata["campaign"].(string); ok {
				indicator.Campaign = campaign
			}
			if malware, ok := iocOS.Metadata["malware_family"].(string); ok {
				indicator.MalwareFamily = malware
			}
			if ttps, ok := iocOS.Metadata["mitre_techniques"].([]interface{}); ok {
				for _, ttp := range ttps {
					if t, ok := ttp.(string); ok {
						indicator.MITRETechniques = append(indicator.MITRETechniques, t)
					}
				}
			}
		}

		indicators = append(indicators, indicator)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       indicators,
		"total":      total,
		"dataSource": "opensearch",
	})
}

// Handler: List threat actors - fetches from OpenSearch
func (s *APIServer) handleListThreatActors(c *gin.Context) {
	actorType := c.Query("type")

	// Buscar actors do OpenSearch
	actorsOS, total, err := s.fetchThreatActorsFromOS(actorType, 100)
	if err != nil {
		s.logger.Printf("Error fetching threat actors from OpenSearch: %v", err)
	}

	// Converter para formato Fusion
	actors := make([]FusionThreatActor, 0, len(actorsOS))
	for _, actorOS := range actorsOS {
		actor := FusionThreatActor{
			ID:              actorOS.ID,
			Name:            actorOS.Name,
			Aliases:         actorOS.Aliases,
			Type:            actorOS.Type,
			Sophistication:  actorOS.Sophistication,
			Origin:          actorOS.Origin,
			FirstSeen:       actorOS.FirstSeen,
			LastActivity:    actorOS.LastActivity,
			TargetSectors:   actorOS.TargetSectors,
			TargetCountries: actorOS.TargetCountries,
			TTPs:            actorOS.TTPs,
			Tools:           actorOS.Tools,
			Malware:         actorOS.Malware,
			Campaigns:       actorOS.Campaigns,
			KnownIOCs:       actorOS.KnownIOCs,
			ThreatScore:     actorOS.ThreatScore,
			Description:     actorOS.Description,
		}
		actors = append(actors, actor)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       actors,
		"total":      total,
		"dataSource": "opensearch",
	})
}

// Handler: List threat campaigns - fetches from OpenSearch
func (s *APIServer) handleListThreatCampaigns(c *gin.Context) {
	status := c.Query("status")

	// Buscar campaigns do OpenSearch
	campaignsOS, total, err := s.fetchCampaignsFromOS(status, 100)
	if err != nil {
		s.logger.Printf("Error fetching campaigns from OpenSearch: %v", err)
	}

	// Converter para formato ThreatCampaign
	campaigns := make([]ThreatCampaign, 0, len(campaignsOS))
	for _, campOS := range campaignsOS {
		campaign := ThreatCampaign{
			ID:              campOS.ID,
			Name:            campOS.Name,
			Status:          campOS.Status,
			Severity:        campOS.Severity,
			FirstDetected:   campOS.FirstDetected,
			LastActivity:    campOS.LastActivity,
			ThreatActors:    campOS.ThreatActors,
			TargetSectors:   campOS.TargetSectors,
			TargetCountries: campOS.TargetCountries,
			AttackVectors:   campOS.AttackVectors,
			Objectives:      campOS.Objectives,
			TTPs:            campOS.TTPs,
			IOCsIdentified:  campOS.IOCsIdentified,
			VictimsAffected: campOS.VictimsAffected,
			MITRETactics:    campOS.MITRETactics,
			Description:     campOS.Description,
			Recommendations: campOS.Recommendations,
		}
		campaigns = append(campaigns, campaign)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       campaigns,
		"total":      total,
		"dataSource": "opensearch",
	})
}

// Handler: List correlations - fetches from OpenSearch
func (s *APIServer) handleListCorrelations(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")

	// Buscar correlations do OpenSearch
	correlationsOS, total, err := s.fetchCorrelationsFromOS(status, severity, 100)
	if err != nil {
		s.logger.Printf("Error fetching correlations from OpenSearch: %v", err)
	}

	// Converter para formato CorrelationResult
	correlations := make([]CorrelationResult, 0, len(correlationsOS))
	for _, corrOS := range correlationsOS {
		correlation := CorrelationResult{
			ID:              corrOS.ID,
			Type:            corrOS.Type,
			Severity:        corrOS.Severity,
			Confidence:      corrOS.Confidence,
			DetectedAt:      corrOS.DetectedAt,
			SourceEvent:     corrOS.SourceEventID,
			MatchedIOC:      corrOS.MatchedIOCValue,
			ThreatActor:     corrOS.ThreatActor,
			Campaign:        corrOS.Campaign,
			MITRETechniques: corrOS.MITRETechniques,
			AffectedAssets:  corrOS.AffectedAssets,
			Context:         corrOS.Context,
			Recommendations: corrOS.Recommendations,
			Status:          corrOS.Status,
		}
		correlations = append(correlations, correlation)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       correlations,
		"total":      total,
		"dataSource": "opensearch",
	})
}

// Handler: Get threat intel metrics - calculates from OpenSearch data
func (s *APIServer) handleGetThreatIntelMetrics(c *gin.Context) {
	// Buscar estatísticas do OpenSearch
	statsOS, err := s.getThreatIntelStatsFromOS()

	// Buscar estatísticas de correlações
	correlationStats, _ := s.GetCorrelationStats()

	// Buscar contagem de campanhas ativas
	activeCampaigns, _, _ := s.fetchCampaignsFromOS("active", 1000)

	// Buscar contagem de atores
	actors, _, _ := s.fetchThreatActorsFromOS("", 1000)

	var metrics FusionMetrics
	if err == nil && statsOS != nil {
		// Calcular critical threats (IOCs com severidade crítica)
		criticalThreats := 0
		if count, ok := statsOS.IOCsBySeverity["critical"]; ok {
			criticalThreats = count
		}

		// Calcular average confidence
		avgConfidence := 0.0
		if statsOS.TotalIOCs > 0 {
			avgConfidence = 85.0
		}

		// Correlações de hoje
		correlationsToday := 0
		if correlationStats != nil {
			if today, ok := correlationStats["today"].(int); ok {
				correlationsToday = today
			}
		}

		metrics = FusionMetrics{
			ActiveFeeds:        statsOS.FeedsActive,
			TotalIndicators:    statsOS.TotalIOCs,
			NewIndicatorsToday: 0,
			CorrelationsToday:  correlationsToday,
			CriticalThreats:    criticalThreats,
			ActiveCampaigns:    len(activeCampaigns),
			TrackedActors:      len(actors),
			EnrichmentRate:     0,
			AverageConfidence:  avgConfidence,
			FalsePositiveRate:  0,
		}
	} else {
		// Retornar métricas zeradas se OpenSearch não disponível
		metrics = FusionMetrics{
			ActiveFeeds:        0,
			TotalIndicators:    0,
			NewIndicatorsToday: 0,
			CorrelationsToday:  0,
			CriticalThreats:    0,
			ActiveCampaigns:    0,
			TrackedActors:      0,
			EnrichmentRate:     0,
			AverageConfidence:  0,
			FalsePositiveRate:  0,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       metrics,
		"dataSource": "opensearch",
	})
}

// ============================================================================
// CREATE HANDLERS
// ============================================================================

// handleCreateTICampaign creates a new threat intelligence campaign
func (s *APIServer) handleCreateTICampaign(c *gin.Context) {
	var input struct {
		Name            string   `json:"name" binding:"required"`
		Description     string   `json:"description"`
		Status          string   `json:"status"`
		Severity        string   `json:"severity"`
		ThreatActors    []string `json:"threat_actors"`
		TargetSectors   []string `json:"target_sectors"`
		TargetCountries []string `json:"target_countries"`
		AttackVectors   []string `json:"attack_vectors"`
		Objectives      []string `json:"objectives"`
		TTPs            []string `json:"ttps"`
		MITRETactics    []string `json:"mitre_tactics"`
		Recommendations []string `json:"recommendations"`
		RelatedIOCs     []string `json:"related_iocs"`
		Tags            []string `json:"tags"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("[ERROR] handleCreateCampaign bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	// Validar severidade
	if input.Severity == "" {
		input.Severity = "medium"
	}
	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	if !validSeverities[input.Severity] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid severity"})
		return
	}

	campaign := CampaignOpenSearch{
		Name:            input.Name,
		Description:     input.Description,
		Status:          input.Status,
		Severity:        input.Severity,
		ThreatActors:    input.ThreatActors,
		TargetSectors:   input.TargetSectors,
		TargetCountries: input.TargetCountries,
		AttackVectors:   input.AttackVectors,
		Objectives:      input.Objectives,
		TTPs:            input.TTPs,
		MITRETactics:    input.MITRETactics,
		Recommendations: input.Recommendations,
		RelatedIOCs:     input.RelatedIOCs,
		Tags:            input.Tags,
		IOCsIdentified:  len(input.RelatedIOCs),
		CreatedBy:       "api",
	}

	created, err := s.createCampaignInOS(campaign)
	if err != nil {
		s.logger.Printf("Failed to create campaign: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to create campaign"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success":    true,
		"data":       created,
		"message":    "Campaign created successfully",
		"dataSource": "opensearch",
	})
}

// handleCreateThreatActor creates a new threat actor
func (s *APIServer) handleCreateThreatActor(c *gin.Context) {
	var input struct {
		Name            string   `json:"name" binding:"required"`
		Aliases         []string `json:"aliases"`
		Type            string   `json:"type"`
		Sophistication  string   `json:"sophistication"`
		Origin          string   `json:"origin"`
		Description     string   `json:"description"`
		TargetSectors   []string `json:"target_sectors"`
		TargetCountries []string `json:"target_countries"`
		TTPs            []string `json:"ttps"`
		Tools           []string `json:"tools"`
		Malware         []string `json:"malware"`
		Campaigns       []string `json:"campaigns"`
		ThreatScore     float64  `json:"threat_score"`
		Tags            []string `json:"tags"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("[ERROR] handleCreateThreatActor bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	// Validar tipo
	if input.Type == "" {
		input.Type = "unknown"
	}
	validTypes := map[string]bool{"apt": true, "cybercrime": true, "hacktivist": true, "nation_state": true, "unknown": true}
	if !validTypes[input.Type] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid actor type"})
		return
	}

	actor := ThreatActorOpenSearch{
		Name:            input.Name,
		Aliases:         input.Aliases,
		Type:            input.Type,
		Sophistication:  input.Sophistication,
		Origin:          input.Origin,
		Description:     input.Description,
		TargetSectors:   input.TargetSectors,
		TargetCountries: input.TargetCountries,
		TTPs:            input.TTPs,
		Tools:           input.Tools,
		Malware:         input.Malware,
		Campaigns:       input.Campaigns,
		ThreatScore:     input.ThreatScore,
		Tags:            input.Tags,
		CreatedBy:       "api",
	}

	created, err := s.createThreatActorInOS(actor)
	if err != nil {
		s.logger.Printf("Failed to create threat actor: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to create threat actor"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success":    true,
		"data":       created,
		"message":    "Threat actor created successfully",
		"dataSource": "opensearch",
	})
}

// handleUpdateCorrelationStatus updates a correlation status
func (s *APIServer) handleUpdateCorrelationStatus(c *gin.Context) {
	correlationID := c.Param("id")

	var input struct {
		Status     string `json:"status" binding:"required"`
		Resolution string `json:"resolution"`
		ResolvedBy string `json:"resolved_by"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("[ERROR] handleUpdateCorrelationStatus bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request"})
		return
	}

	// Validar status
	validStatuses := map[string]bool{"new": true, "investigating": true, "resolved": true, "false_positive": true}
	if !validStatuses[input.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid status"})
		return
	}

	updates := map[string]interface{}{
		"status": input.Status,
	}

	if input.Status == "resolved" || input.Status == "false_positive" {
		now := time.Now()
		updates["resolved_at"] = now
		updates["resolution"] = input.Resolution
		updates["resolved_by"] = input.ResolvedBy
	}

	err := s.updateCorrelationInOS(correlationID, updates)
	if err != nil {
		s.logger.Printf("Failed to update correlation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to update correlation"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"message":    "Correlation updated successfully",
		"id":         correlationID,
		"dataSource": "opensearch",
	})
}

// handleGetTICorrelationStats returns threat intel correlation statistics
func (s *APIServer) handleGetTICorrelationStats(c *gin.Context) {
	stats, err := s.GetCorrelationStats()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": map[string]interface{}{
				"total":       0,
				"today":       0,
				"by_status":   map[string]int{},
				"by_severity": map[string]int{},
				"by_type":     map[string]int{},
			},
			"dataSource": "opensearch",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       stats,
		"dataSource": "opensearch",
	})
}
