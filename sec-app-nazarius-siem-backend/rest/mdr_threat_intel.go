package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// MDR Threat Intelligence Platform structures
type MDRThreatFeed struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	FeedType    string    `json:"feed_type"`   // STIX, TAXII, CSV, JSON
	FeedStatus  string    `json:"feed_status"` // active, inactive, error
	URL         string    `json:"url"`
	LastSync    time.Time `json:"last_sync"`
	NextSync    time.Time `json:"next_sync"`
	IOCCount    int       `json:"ioc_count"`
	Reliability string    `json:"reliability"` // high, medium, low
	CreatedAt   time.Time `json:"created_at"`
}

type MDRThreatActor struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Aliases     []string  `json:"aliases"`
	Description string    `json:"description"`
	TTP         []string  `json:"ttp"` // MITRE ATT&CK TTPs
	Campaigns   []string  `json:"campaigns"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ThreatLevel string    `json:"threat_level"` // critical, high, medium, low
}

type MDRThreatIOC struct {
	ID         string    `json:"id"`
	FeedID     string    `json:"feed_id"`
	Type       string    `json:"type"` // ip, domain, hash, url, email
	Value      string    `json:"value"`
	Confidence int       `json:"confidence"` // 0-100
	Severity   string    `json:"severity"`
	Tags       []string  `json:"tags"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type MDRThreatCampaign struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Actors      []string  `json:"actors"`
	TTPs        []string  `json:"ttps"`
	Targets     []string  `json:"targets"`
	StartDate   time.Time `json:"start_date"`
	EndDate     time.Time `json:"end_date"`
	Active      bool      `json:"active"`
}

func initMDRThreatIntel() {
	// Real data is fetched from OpenSearch on-demand
	// No more in-memory maps with mock data
}

// Handlers - List feeds from OpenSearch
func (s *APIServer) handleListMDRThreatFeeds(c *gin.Context) {
	// Buscar feeds do OpenSearch
	feedsOS, err := s.fetchFeedsFromOS()
	if err != nil {
		s.logger.Printf("Error fetching MDR threat feeds from OpenSearch: %v", err)
	}

	// Converter para formato MDR
	feeds := make([]MDRThreatFeed, 0, len(feedsOS))
	for _, feedOS := range feedsOS {
		// Determinar feed_type baseado no formato
		feedType := "JSON"
		if feedOS.FeedType != "" {
			feedType = feedOS.FeedType
		}

		// Determinar status
		status := "active"
		if !feedOS.Enabled {
			status = "inactive"
		}

		// Calcular next sync
		nextSync := feedOS.LastUpdate.Add(time.Duration(feedOS.UpdateFreq) * time.Minute)

		feed := MDRThreatFeed{
			ID:          feedOS.ID,
			Name:        feedOS.Name,
			FeedType:    feedType,
			FeedStatus:  status,
			URL:         feedOS.URL,
			LastSync:    feedOS.LastUpdate,
			NextSync:    nextSync,
			IOCCount:    feedOS.IOCCount,
			Reliability: feedOS.Reliability,
			CreatedAt:   feedOS.CreatedAt,
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

// Create feed - stores in OpenSearch
func (s *APIServer) handleCreateMDRThreatFeed(c *gin.Context) {
	var input struct {
		Name        string `json:"name" binding:"required"`
		FeedType    string `json:"feed_type"`
		URL         string `json:"url"`
		Reliability string `json:"reliability"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	// Criar feed no OpenSearch
	feedOS := ThreatFeedOpenSearch{
		Name:        input.Name,
		Provider:    "manual",
		Type:        "custom",
		FeedType:    input.FeedType,
		URL:         input.URL,
		Enabled:     true,
		UpdateFreq:  60,
		Reliability: input.Reliability,
	}

	created, err := s.createMDRFeedInOS(feedOS)
	if err != nil {
		s.logger.Printf("Failed to create MDR threat feed in OpenSearch: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to create feed",
		})
		return
	}

	// Converter para formato MDR
	feed := MDRThreatFeed{
		ID:          created.ID,
		Name:        created.Name,
		FeedType:    created.FeedType,
		FeedStatus:  "active",
		URL:         created.URL,
		LastSync:    created.LastUpdate,
		NextSync:    created.LastUpdate.Add(time.Duration(created.UpdateFreq) * time.Minute),
		IOCCount:    created.IOCCount,
		Reliability: created.Reliability,
		CreatedAt:   created.CreatedAt,
	}

	c.JSON(http.StatusCreated, gin.H{
		"success":    true,
		"data":       feed,
		"dataSource": "opensearch",
	})
}

// Get stats from OpenSearch
func (s *APIServer) handleGetMDRThreatIntelStats(c *gin.Context) {
	// Buscar estatísticas do OpenSearch
	statsOS, err := s.getThreatIntelStatsFromOS()

	var stats map[string]interface{}
	if err == nil && statsOS != nil {
		// Contar feeds ativos
		feedsOS, _ := s.fetchFeedsFromOS()
		activeFeeds := 0
		for _, f := range feedsOS {
			if f.Enabled {
				activeFeeds++
			}
		}

		// Calcular critical actors (baseado em IOCs críticos por enquanto)
		criticalActors := 0
		if count, ok := statsOS.IOCsBySeverity["critical"]; ok {
			criticalActors = count / 10 // Estimativa
		}

		stats = map[string]interface{}{
			"total_feeds":      len(feedsOS),
			"active_feeds":     activeFeeds,
			"total_iocs":       statsOS.TotalIOCs,
			"total_actors":     0, // Requer feed de atores
			"critical_actors":  criticalActors,
			"total_campaigns":  0, // Requer tracking de campanhas
			"active_campaigns": 0,
			"dataSource":       "opensearch",
		}
	} else {
		stats = map[string]interface{}{
			"total_feeds":      0,
			"active_feeds":     0,
			"total_iocs":       0,
			"total_actors":     0,
			"critical_actors":  0,
			"total_campaigns":  0,
			"active_campaigns": 0,
			"dataSource":       "opensearch",
			"message":          "No threat intelligence data available.",
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": stats})
}

// List actors - fetches from OpenSearch
func (s *APIServer) handleListMDRThreatActors(c *gin.Context) {
	// Buscar actors do OpenSearch
	actorsOS, total, err := s.fetchThreatActorsFromOS("", 100)
	if err != nil {
		s.logger.Printf("Error fetching MDR threat actors from OpenSearch: %v", err)
	}

	// Converter para formato MDR
	actors := make([]MDRThreatActor, 0, len(actorsOS))
	for _, actorOS := range actorsOS {
		actor := MDRThreatActor{
			ID:          actorOS.ID,
			Name:        actorOS.Name,
			Aliases:     actorOS.Aliases,
			Description: actorOS.Description,
			TTP:         actorOS.TTPs,
			Campaigns:   actorOS.Campaigns,
			FirstSeen:   actorOS.FirstSeen,
			LastSeen:    actorOS.LastActivity,
			ThreatLevel: mapThreatScoreToLevel(actorOS.ThreatScore),
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

// mapThreatScoreToLevel maps a numeric threat score to a level string
func mapThreatScoreToLevel(score float64) string {
	if score >= 90 {
		return "critical"
	} else if score >= 70 {
		return "high"
	} else if score >= 40 {
		return "medium"
	}
	return "low"
}

// List IOCs from OpenSearch
func (s *APIServer) handleListMDRThreatIOCs(c *gin.Context) {
	// Buscar IOCs do OpenSearch
	iocsOS, total, err := s.fetchIOCsFromOS("", "", "", "", 100)
	if err != nil {
		s.logger.Printf("Error fetching MDR IOCs from OpenSearch: %v", err)
	}

	// Converter para formato MDR
	iocs := make([]MDRThreatIOC, 0, len(iocsOS))
	for _, iocOS := range iocsOS {
		// ExpiresAt precisa ser tratado (é ponteiro)
		var expiresAt time.Time
		if iocOS.ExpiresAt != nil {
			expiresAt = *iocOS.ExpiresAt
		}

		ioc := MDRThreatIOC{
			ID:         iocOS.ID,
			FeedID:     iocOS.Source, // Usar Source como referência ao feed
			Type:       iocOS.Type,
			Value:      iocOS.Value,
			Confidence: iocOS.Confidence,
			Severity:   iocOS.Severity,
			Tags:       iocOS.Tags,
			FirstSeen:  iocOS.FirstSeen,
			LastSeen:   iocOS.LastSeen,
			ExpiresAt:  expiresAt,
		}
		iocs = append(iocs, ioc)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"data":       iocs,
		"total":      total,
		"dataSource": "opensearch",
	})
}

// createFeedInOS creates a new feed in OpenSearch
func (s *APIServer) createMDRFeedInOS(feed ThreatFeedOpenSearch) (*ThreatFeedOpenSearch, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	feed.ID = generateID()
	feed.CreatedAt = time.Now()
	feed.UpdatedAt = time.Now()
	feed.LastUpdate = time.Now()
	feed.NextUpdate = time.Now().Add(time.Duration(feed.UpdateFreq) * time.Minute)
	feed.IOCCount = 0
	feed.Status = "active"

	feedJSON, _ := json.Marshal(feed)

	res, err := s.opensearch.Index(
		threatFeedsIndex,
		strings.NewReader(string(feedJSON)),
		s.opensearch.Index.WithDocumentID(feed.ID),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("failed to create feed: %s", res.String())
	}

	return &feed, nil
}
