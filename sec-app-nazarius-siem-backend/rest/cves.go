package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// CVE DATA STRUCTURES
// ============================================================================

// CVE representa uma vulnerabilidade no banco de dados
type CVE struct {
	ID               string     `json:"id"`                      // CVE-YYYY-NNNNN
	Description      string     `json:"description"`             // Descrição da vulnerabilidade
	Severity         string     `json:"severity"`                // CRITICAL, HIGH, MEDIUM, LOW, NONE
	CVSSScore        float64    `json:"cvssScore"`               // Score CVSS (0-10)
	CVSSVector       string     `json:"cvssVector"`              // Vector string CVSS
	CVSSVersion      string     `json:"cvssVersion"`             // 2.0, 3.0, 3.1
	PublishedDate    time.Time  `json:"publishedDate"`           // Data de publicação
	LastModifiedDate time.Time  `json:"lastModifiedDate"`        // Última modificação
	Status           string     `json:"status"`                  // ANALYZED, MODIFIED, REJECTED
	AffectedProducts []string   `json:"affectedProducts"`        // Produtos afetados (CPE)
	References       []CVERef   `json:"references"`              // Links de referência
	Weaknesses       []string   `json:"weaknesses"`              // CWE IDs
	AlertCount       int        `json:"alertCount"`              // Contagem de alertas relacionados
	EventCount       int        `json:"eventCount"`              // Contagem de eventos relacionados
	ExploitAvailable bool       `json:"exploitAvailable"`        // Se há exploit conhecido
	CISAKnownExploit bool       `json:"cisaKnownExploit"`        // Se está na lista CISA KEV
	PatchAvailable   bool       `json:"patchAvailable"`          // Se há patch disponível
	LastAlertDate    *time.Time `json:"lastAlertDate,omitempty"` // Data do último alerta
	CreatedAt        time.Time  `json:"createdAt"`               // Quando foi adicionado ao SIEM
	UpdatedAt        time.Time  `json:"updatedAt"`               // Última atualização no SIEM
}

// CVERef representa uma referência de um CVE
type CVERef struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// CVEStats representa estatísticas do banco de CVEs
type CVEStats struct {
	TotalCVEs         int                  `json:"totalCVEs"`
	BySeverity        map[string]int       `json:"bySeverity"`
	WithAlerts        int                  `json:"withAlerts"`
	TotalAlerts       int                  `json:"totalAlerts"`
	LastSyncDate      *time.Time           `json:"lastSyncDate"`
	TopCVEsByAlerts   []CVEAlertSummary    `json:"topCVEsByAlerts"`
	RecentCVEs        []CVE                `json:"recentCVEs"`
	ExploitedCVEs     int                  `json:"exploitedCVEs"`
	CISAKnownExploits int                  `json:"cisaKnownExploits"`
	SeverityTrend     []SeverityTrendPoint `json:"severityTrend"`
}

// CVEAlertSummary resume alertas por CVE
type CVEAlertSummary struct {
	CVEID       string  `json:"cveId"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvssScore"`
	AlertCount  int     `json:"alertCount"`
	EventCount  int     `json:"eventCount"`
}

// SeverityTrendPoint representa um ponto no gráfico de tendência
type SeverityTrendPoint struct {
	Date     string `json:"date"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
}

// NVD API Response structures
type NVDResponse struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Format          string             `json:"format"`
	Version         string             `json:"version"`
	Timestamp       string             `json:"timestamp"`
	Vulnerabilities []NVDVulnerability `json:"vulnerabilities"`
}

type NVDVulnerability struct {
	CVE NVDCVEItem `json:"cve"`
}

type NVDCVEItem struct {
	ID               string           `json:"id"`
	SourceIdentifier string           `json:"sourceIdentifier"`
	Published        string           `json:"published"`
	LastModified     string           `json:"lastModified"`
	VulnStatus       string           `json:"vulnStatus"`
	Descriptions     []NVDDescription `json:"descriptions"`
	Metrics          NVDMetrics       `json:"metrics"`
	Weaknesses       []NVDWeakness    `json:"weaknesses"`
	References       []NVDReference   `json:"references"`
}

type NVDDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type NVDMetrics struct {
	CVSSMetricV31 []NVDCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []NVDCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []NVDCVSSMetric `json:"cvssMetricV2"`
}

type NVDCVSSMetric struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CVSSData NVDCVSSData `json:"cvssData"`
}

type NVDCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type NVDWeakness struct {
	Source      string           `json:"source"`
	Type        string           `json:"type"`
	Description []NVDDescription `json:"description"`
}

type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// CVE Database Manager
type CVEManager struct {
	cves         map[string]*CVE
	mu           sync.RWMutex
	lastSync     *time.Time
	syncInterval time.Duration
	apiKey       string // NVD API Key (opcional, aumenta rate limit)
}

// NVDConfig representa a configuração do NVD salva no OpenSearch
type NVDConfig struct {
	APIKey      string    `json:"api_key"`
	Enabled     bool      `json:"enabled"`
	LastUpdated time.Time `json:"last_updated"`
	UpdatedBy   string    `json:"updated_by"`
}

var cveManager *CVEManager

func init() {
	cveManager = &CVEManager{
		cves:         make(map[string]*CVE),
		syncInterval: 6 * time.Hour, // Sincronizar a cada 6 horas
		apiKey:       os.Getenv("NVD_API_KEY"),
	}
}

// getNVDAPIKey retorna a API Key do NVD (prioridade: OpenSearch > env var)
func (s *APIServer) getNVDAPIKey() string {
	// Tentar buscar do OpenSearch primeiro
	if s.opensearch != nil {
		config, err := s.getNVDConfigFromOpenSearch()
		if err == nil && config != nil && config.APIKey != "" && config.Enabled {
			return config.APIKey
		}
	}

	// Fallback para variável de ambiente
	return os.Getenv("NVD_API_KEY")
}

// getNVDConfigFromOpenSearch busca a configuração do NVD salva
func (s *APIServer) getNVDConfigFromOpenSearch() (*NVDConfig, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	res, err := s.opensearch.Get(
		"siem-config",
		"nvd-config",
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("config not found")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	source, ok := result["_source"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid config format")
	}

	config := &NVDConfig{
		APIKey:  getStringFromMap(source, "api_key"),
		Enabled: getBoolFromMap(source, "enabled"),
	}

	if ts, ok := source["last_updated"].(string); ok {
		config.LastUpdated, _ = time.Parse(time.RFC3339, ts)
	}
	config.UpdatedBy = getStringFromMap(source, "updated_by")

	return config, nil
}

// saveNVDConfigToOpenSearch salva a configuração do NVD
func (s *APIServer) saveNVDConfigToOpenSearch(config *NVDConfig) error {
	if s.opensearch == nil {
		return fmt.Errorf("opensearch not available")
	}

	// Garantir que o índice existe
	s.ensureConfigIndex()

	doc, _ := json.Marshal(config)

	res, err := s.opensearch.Index(
		"siem-config",
		strings.NewReader(string(doc)),
		s.opensearch.Index.WithDocumentID("nvd-config"),
		s.opensearch.Index.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("failed to save config: %s", res.Status())
	}

	// Atualizar cache local
	cveManager.mu.Lock()
	cveManager.apiKey = config.APIKey
	cveManager.mu.Unlock()

	return nil
}

// ensureConfigIndex garante que o índice de configuração existe
func (s *APIServer) ensureConfigIndex() {
	if s.opensearch == nil {
		return
	}

	res, _ := s.opensearch.Indices.Exists([]string{"siem-config"})
	if res != nil {
		res.Body.Close()
		if res.StatusCode == 200 {
			return
		}
	}

	mapping := map[string]interface{}{
		"settings": map[string]interface{}{
			"number_of_shards":   1,
			"number_of_replicas": 0,
		},
	}
	mappingJSON, _ := json.Marshal(mapping)

	s.opensearch.Indices.Create(
		"siem-config",
		s.opensearch.Indices.Create.WithBody(strings.NewReader(string(mappingJSON))),
	)
}

// handleGetNVDConfig retorna a configuração atual do NVD
func (s *APIServer) handleGetNVDConfig(c *gin.Context) {
	config, err := s.getNVDConfigFromOpenSearch()
	if err != nil {
		// Retornar configuração padrão
		envKey := os.Getenv("NVD_API_KEY")
		config = &NVDConfig{
			APIKey:  "", // Não expor a chave da env var
			Enabled: envKey != "",
		}

		c.JSON(http.StatusOK, gin.H{
			"config": gin.H{
				"api_key_configured": envKey != "",
				"api_key_source":     "environment",
				"enabled":            envKey != "",
			},
			"source": "environment",
		})
		return
	}

	// Mascarar a API Key
	maskedKey := ""
	if config.APIKey != "" {
		if len(config.APIKey) > 8 {
			maskedKey = config.APIKey[:4] + "****" + config.APIKey[len(config.APIKey)-4:]
		} else {
			maskedKey = "****"
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"config": gin.H{
			"api_key_configured": config.APIKey != "",
			"api_key_masked":     maskedKey,
			"api_key_source":     "database",
			"enabled":            config.Enabled,
			"last_updated":       config.LastUpdated,
			"updated_by":         config.UpdatedBy,
		},
		"source": "database",
	})
}

// handleSaveNVDConfig salva a configuração do NVD
func (s *APIServer) handleSaveNVDConfig(c *gin.Context) {
	var req struct {
		APIKey  string `json:"api_key"`
		Enabled bool   `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validar formato da API Key (UUID)
	if req.APIKey != "" && len(req.APIKey) < 30 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API Key inválida. Deve ser um UUID válido do NVD."})
		return
	}

	// Obter usuário do contexto (se disponível)
	username := "admin"
	if user, exists := c.Get("username"); exists {
		username = user.(string)
	}

	config := &NVDConfig{
		APIKey:      req.APIKey,
		Enabled:     req.Enabled,
		LastUpdated: time.Now(),
		UpdatedBy:   username,
	}

	if err := s.saveNVDConfigToOpenSearch(config); err != nil {
		log.Printf("❌ Error saving NVD config: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao salvar configuração"})
		return
	}

	log.Printf("✅ NVD config saved by %s", username)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Configuração do NVD salva com sucesso",
	})
}

// handleTestNVDConnection testa a conexão com a NVD API
func (s *APIServer) handleTestNVDConnection(c *gin.Context) {
	var req struct {
		APIKey string `json:"api_key"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Usar a chave fornecida ou a salva
	apiKey := req.APIKey
	if apiKey == "" {
		apiKey = s.getNVDAPIKey()
	}

	testCVE := "CVE-2021-44228" // Log4Shell
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", testCVE)

	httpReq, _ := http.NewRequest("GET", url, nil)
	if apiKey != "" {
		httpReq.Header.Set("apiKey", apiKey)
	}

	startTime := time.Now()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	latency := time.Since(startTime)

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   fmt.Sprintf("Erro de conexão: %v", err),
			"latency": latency.String(),
		})
		return
	}
	defer resp.Body.Close()

	result := gin.H{
		"latency":     latency.String(),
		"http_status": resp.StatusCode,
	}

	if resp.StatusCode == 200 {
		var nvdResp NVDResponse
		json.NewDecoder(resp.Body).Decode(&nvdResp)

		result["success"] = true
		result["message"] = fmt.Sprintf("Conexão OK! CVE de teste (%s) recuperado com sucesso.", testCVE)
		result["total_results"] = nvdResp.TotalResults

		if apiKey != "" {
			result["rate_limit"] = "50 requests/30s (com API Key)"
		} else {
			result["rate_limit"] = "5 requests/30s (sem API Key)"
		}
	} else if resp.StatusCode == 403 {
		result["success"] = false
		result["error"] = "Rate limit excedido ou API Key inválida"
	} else {
		result["success"] = false
		result["error"] = fmt.Sprintf("Resposta inesperada: HTTP %d", resp.StatusCode)
	}

	c.JSON(http.StatusOK, result)
}

// ============================================================================
// CVE HANDLERS
// ============================================================================

// handleListCVEs lista CVEs com filtros e paginação
func (s *APIServer) handleListCVEs(c *gin.Context) {
	// Parse query parameters
	page := parseIntParam(c.DefaultQuery("page", "1"), 1)
	limit := parseIntParam(c.DefaultQuery("limit", "50"), 50)
	severity := c.Query("severity")
	search := c.Query("search")
	withAlerts := c.Query("with_alerts") == "true"
	sortBy := c.DefaultQuery("sort_by", "cvssScore")
	sortOrder := c.DefaultQuery("sort_order", "desc")

	// Limitar máximo
	if limit > 200 {
		limit = 200
	}

	// Buscar do OpenSearch primeiro
	if s.opensearch != nil {
		cves, total, err := s.fetchCVEsFromOpenSearch(c, limit, page, severity, search, withAlerts, sortBy, sortOrder)
		if err == nil {
			c.JSON(http.StatusOK, gin.H{
				"cves":       cves,
				"total":      total,
				"page":       page,
				"limit":      limit,
				"totalPages": (total + limit - 1) / limit,
				"source":     "opensearch",
			})
			return
		}
		log.Printf("⚠️ OpenSearch CVE fetch failed, falling back to memory: %v", err)
	}

	// Fallback para memória
	cveManager.mu.RLock()
	allCVEs := make([]CVE, 0, len(cveManager.cves))
	for _, cve := range cveManager.cves {
		// Aplicar filtros
		if severity != "" && !strings.EqualFold(cve.Severity, severity) {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(cve.ID+cve.Description), strings.ToLower(search)) {
			continue
		}
		if withAlerts && cve.AlertCount == 0 {
			continue
		}
		allCVEs = append(allCVEs, *cve)
	}
	cveManager.mu.RUnlock()

	// Ordenar
	sort.Slice(allCVEs, func(i, j int) bool {
		switch sortBy {
		case "cvssScore":
			if sortOrder == "asc" {
				return allCVEs[i].CVSSScore < allCVEs[j].CVSSScore
			}
			return allCVEs[i].CVSSScore > allCVEs[j].CVSSScore
		case "alertCount":
			if sortOrder == "asc" {
				return allCVEs[i].AlertCount < allCVEs[j].AlertCount
			}
			return allCVEs[i].AlertCount > allCVEs[j].AlertCount
		case "publishedDate":
			if sortOrder == "asc" {
				return allCVEs[i].PublishedDate.Before(allCVEs[j].PublishedDate)
			}
			return allCVEs[i].PublishedDate.After(allCVEs[j].PublishedDate)
		default:
			return allCVEs[i].CVSSScore > allCVEs[j].CVSSScore
		}
	})

	// Paginar
	total := len(allCVEs)
	start := (page - 1) * limit
	end := start + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	c.JSON(http.StatusOK, gin.H{
		"cves":       allCVEs[start:end],
		"total":      total,
		"page":       page,
		"limit":      limit,
		"totalPages": (total + limit - 1) / limit,
		"source":     "memory",
	})
}

// handleGetCVE retorna detalhes de um CVE específico
func (s *APIServer) handleGetCVE(c *gin.Context) {
	cveID := strings.ToUpper(c.Param("id"))

	// Validar formato CVE
	if !strings.HasPrefix(cveID, "CVE-") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID de CVE inválido. Formato esperado: CVE-YYYY-NNNNN"})
		return
	}

	// Buscar do OpenSearch primeiro
	if s.opensearch != nil {
		cve, err := s.fetchCVEByIDFromOpenSearch(c, cveID)
		if err == nil && cve != nil {
			// Buscar alertas relacionados
			alerts, _ := s.fetchAlertsByCVE(c, cveID, 10)
			c.JSON(http.StatusOK, gin.H{
				"cve":           cve,
				"relatedAlerts": alerts,
				"source":        "opensearch",
			})
			return
		}
	}

	// Fallback para memória
	cveManager.mu.RLock()
	cve, exists := cveManager.cves[cveID]
	cveManager.mu.RUnlock()

	if !exists {
		// Tentar buscar da NVD
		apiKey := s.getNVDAPIKey()
		cve, err := fetchCVEFromNVD(cveID, apiKey)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "CVE não encontrado"})
			return
		}
		// Salvar no cache
		cveManager.mu.Lock()
		cveManager.cves[cveID] = cve
		cveManager.mu.Unlock()
	}

	// Buscar alertas relacionados
	alerts, _ := s.fetchAlertsByCVE(c, cveID, 10)

	c.JSON(http.StatusOK, gin.H{
		"cve":           cve,
		"relatedAlerts": alerts,
		"source":        "memory",
	})
}

// handleGetCVEStats retorna estatísticas do banco de CVEs
func (s *APIServer) handleGetCVEStats(c *gin.Context) {
	stats := CVEStats{
		BySeverity:      make(map[string]int),
		TopCVEsByAlerts: []CVEAlertSummary{},
		RecentCVEs:      []CVE{},
		SeverityTrend:   []SeverityTrendPoint{},
	}

	// Buscar estatísticas do OpenSearch
	if s.opensearch != nil {
		osStats, err := s.fetchCVEStatsFromOpenSearch(c)
		if err == nil {
			c.JSON(http.StatusOK, osStats)
			return
		}
		log.Printf("⚠️ OpenSearch CVE stats failed: %v", err)
	}

	// Fallback para memória
	cveManager.mu.RLock()
	defer cveManager.mu.RUnlock()

	stats.TotalCVEs = len(cveManager.cves)
	stats.LastSyncDate = cveManager.lastSync

	var cvesWithAlerts []CVE
	for _, cve := range cveManager.cves {
		stats.BySeverity[cve.Severity]++
		if cve.AlertCount > 0 {
			stats.WithAlerts++
			stats.TotalAlerts += cve.AlertCount
			cvesWithAlerts = append(cvesWithAlerts, *cve)
		}
		if cve.ExploitAvailable {
			stats.ExploitedCVEs++
		}
		if cve.CISAKnownExploit {
			stats.CISAKnownExploits++
		}
	}

	// Top CVEs por alertas
	sort.Slice(cvesWithAlerts, func(i, j int) bool {
		return cvesWithAlerts[i].AlertCount > cvesWithAlerts[j].AlertCount
	})

	topCount := 10
	if len(cvesWithAlerts) < topCount {
		topCount = len(cvesWithAlerts)
	}

	for i := 0; i < topCount; i++ {
		stats.TopCVEsByAlerts = append(stats.TopCVEsByAlerts, CVEAlertSummary{
			CVEID:       cvesWithAlerts[i].ID,
			Description: truncateString(cvesWithAlerts[i].Description, 100),
			Severity:    cvesWithAlerts[i].Severity,
			CVSSScore:   cvesWithAlerts[i].CVSSScore,
			AlertCount:  cvesWithAlerts[i].AlertCount,
			EventCount:  cvesWithAlerts[i].EventCount,
		})
	}

	// CVEs recentes (últimos 30 dias)
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	var recentCVEs []CVE
	for _, cve := range cveManager.cves {
		if cve.PublishedDate.After(thirtyDaysAgo) {
			recentCVEs = append(recentCVEs, *cve)
		}
	}
	sort.Slice(recentCVEs, func(i, j int) bool {
		return recentCVEs[i].PublishedDate.After(recentCVEs[j].PublishedDate)
	})
	if len(recentCVEs) > 10 {
		recentCVEs = recentCVEs[:10]
	}
	stats.RecentCVEs = recentCVEs

	c.JSON(http.StatusOK, stats)
}

// handleCVEDiagnostics testa conectividade e retorna diagnóstico completo
func (s *APIServer) handleCVEDiagnostics(c *gin.Context) {
	diagnostics := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"checks":    []map[string]interface{}{},
	}

	checks := []map[string]interface{}{}
	overallStatus := "healthy"

	// Check 1: API Key configurada
	apiKey := s.getNVDAPIKey()
	apiKeyCheck := map[string]interface{}{
		"name":   "NVD API Key",
		"status": "pass",
	}
	if apiKey == "" {
		apiKeyCheck["status"] = "warning"
		apiKeyCheck["message"] = "API Key não configurada. Rate limit será de 5 requests/30s"
		overallStatus = "degraded"
	} else {
		apiKeyCheck["message"] = fmt.Sprintf("API Key configurada (***%s)", apiKey[len(apiKey)-4:])
		apiKeyCheck["rate_limit"] = "50 requests/30s"
	}
	checks = append(checks, apiKeyCheck)

	// Check 2: Conectividade com NVD API
	nvdCheck := map[string]interface{}{
		"name": "NVD API Connectivity",
	}

	testCVE := "CVE-2021-44228" // Log4Shell - CVE famoso para teste
	startTime := time.Now()

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", testCVE)
	req, _ := http.NewRequest("GET", url, nil)
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	latency := time.Since(startTime)

	if err != nil {
		nvdCheck["status"] = "fail"
		nvdCheck["message"] = fmt.Sprintf("Erro de conexão: %v", err)
		nvdCheck["latency"] = latency.String()
		overallStatus = "unhealthy"
	} else {
		defer resp.Body.Close()
		nvdCheck["latency"] = latency.String()
		nvdCheck["http_status"] = resp.StatusCode

		if resp.StatusCode == 200 {
			nvdCheck["status"] = "pass"
			nvdCheck["message"] = fmt.Sprintf("Conexão OK - CVE de teste (%s) recuperado com sucesso", testCVE)

			// Parse response para verificar dados
			var nvdResp NVDResponse
			if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err == nil {
				nvdCheck["test_cve"] = testCVE
				nvdCheck["results_found"] = nvdResp.TotalResults
			}
		} else if resp.StatusCode == 403 {
			nvdCheck["status"] = "fail"
			nvdCheck["message"] = "Rate limit excedido ou API Key inválida"
			overallStatus = "unhealthy"
		} else if resp.StatusCode == 404 {
			nvdCheck["status"] = "warning"
			nvdCheck["message"] = "CVE de teste não encontrado, mas API está respondendo"
		} else {
			nvdCheck["status"] = "fail"
			nvdCheck["message"] = fmt.Sprintf("Resposta inesperada: HTTP %d", resp.StatusCode)
			overallStatus = "unhealthy"
		}
	}
	checks = append(checks, nvdCheck)

	// Check 3: OpenSearch
	osCheck := map[string]interface{}{
		"name": "OpenSearch Connection",
	}
	if s.opensearch == nil {
		osCheck["status"] = "fail"
		osCheck["message"] = "OpenSearch não configurado"
		overallStatus = "unhealthy"
	} else {
		// Tentar contar documentos no índice
		countQuery := map[string]interface{}{
			"query": map[string]interface{}{
				"match_all": map[string]interface{}{},
			},
		}
		countJSON, _ := json.Marshal(countQuery)

		res, err := s.opensearch.Count(
			s.opensearch.Count.WithContext(c.Request.Context()),
			s.opensearch.Count.WithIndex("siem-cves"),
			s.opensearch.Count.WithBody(strings.NewReader(string(countJSON))),
		)

		if err != nil {
			osCheck["status"] = "fail"
			osCheck["message"] = fmt.Sprintf("Erro ao conectar: %v", err)
			overallStatus = "unhealthy"
		} else {
			defer res.Body.Close()
			if res.IsError() {
				osCheck["status"] = "warning"
				osCheck["message"] = "Índice siem-cves não existe ainda (será criado na primeira sincronização)"
				osCheck["cve_count"] = 0
			} else {
				var countResult map[string]interface{}
				json.NewDecoder(res.Body).Decode(&countResult)
				count := int(countResult["count"].(float64))
				osCheck["status"] = "pass"
				osCheck["message"] = fmt.Sprintf("Conectado - %d CVEs indexados", count)
				osCheck["cve_count"] = count
			}
		}
	}
	checks = append(checks, osCheck)

	// Check 4: Memória (cache local)
	cveManager.mu.RLock()
	memoryCount := len(cveManager.cves)
	lastSync := cveManager.lastSync
	cveManager.mu.RUnlock()

	memoryCheck := map[string]interface{}{
		"name":      "Memory Cache",
		"status":    "pass",
		"cve_count": memoryCount,
	}
	if lastSync != nil {
		memoryCheck["last_sync"] = lastSync.Format(time.RFC3339)
		memoryCheck["message"] = fmt.Sprintf("%d CVEs em cache, última sync: %s", memoryCount, lastSync.Format("02/01/2006 15:04"))
	} else {
		memoryCheck["message"] = fmt.Sprintf("%d CVEs em cache, nenhuma sincronização realizada ainda", memoryCount)
		if memoryCount == 0 {
			memoryCheck["status"] = "warning"
		}
	}
	checks = append(checks, memoryCheck)

	diagnostics["checks"] = checks
	diagnostics["overall_status"] = overallStatus
	diagnostics["recommendations"] = []string{}

	// Recomendações baseadas nos checks
	recommendations := []string{}
	if apiKey == "" {
		recommendations = append(recommendations, "Configure NVD_API_KEY para aumentar o rate limit de 5 para 50 requests/30s")
	}
	if memoryCount == 0 {
		recommendations = append(recommendations, "Execute uma sincronização clicando em 'Sincronizar NVD' para popular o banco de CVEs")
	}
	diagnostics["recommendations"] = recommendations

	c.JSON(http.StatusOK, diagnostics)
}

// CVE Sync status tracking
var (
	cveSyncStatus    = "idle" // idle, running, completed, failed
	cveSyncMessage   = ""
	cveSyncProgress  = 0
	cveSyncTotal     = 0
	cveSyncIndexed   = 0
	cveSyncErrors    = 0
	cveSyncLastError = ""
	cveSyncMutex     sync.RWMutex
)

func updateSyncStatus(status, message string, progress, total, indexed, errors int) {
	cveSyncMutex.Lock()
	defer cveSyncMutex.Unlock()
	cveSyncStatus = status
	cveSyncMessage = message
	cveSyncProgress = progress
	cveSyncTotal = total
	cveSyncIndexed = indexed
	cveSyncErrors = errors
}

// handleSyncCVEs sincroniza CVEs com a NVD
func (s *APIServer) handleSyncCVEs(c *gin.Context) {
	// Verificar se já está rodando
	cveSyncMutex.RLock()
	if cveSyncStatus == "running" {
		cveSyncMutex.RUnlock()
		c.JSON(http.StatusConflict, gin.H{
			"message":  "Sincronização já está em andamento",
			"status":   cveSyncStatus,
			"progress": cveSyncProgress,
			"total":    cveSyncTotal,
			"indexed":  cveSyncIndexed,
		})
		return
	}
	cveSyncMutex.RUnlock()

	// Parâmetros de sincronização
	daysBack := parseIntParam(c.DefaultQuery("days", "30"), 30)
	if daysBack > 365 {
		daysBack = 365
	}

	log.Printf("🔄 Starting CVE sync for last %d days...", daysBack)
	updateSyncStatus("running", fmt.Sprintf("Iniciando sincronização dos últimos %d dias...", daysBack), 0, 0, 0, 0)

	go func() {
		err := s.syncCVEsFromNVD(daysBack)
		if err != nil {
			log.Printf("❌ CVE sync failed: %v", err)
			cveSyncMutex.Lock()
			cveSyncStatus = "failed"
			cveSyncLastError = err.Error()
			cveSyncMessage = fmt.Sprintf("Falha na sincronização: %v", err)
			cveSyncMutex.Unlock()
		} else {
			cveSyncMutex.RLock()
			indexed := cveSyncIndexed
			cveSyncMutex.RUnlock()
			log.Printf("✅ CVE sync completed: %d CVEs indexed", indexed)

			// Atualizar contagens de alertas e eventos após sync
			updateSyncStatus("running", "Sincronização concluída. Atualizando contagens de alertas e eventos...", 95, cveSyncTotal, indexed, cveSyncErrors)
			log.Println("🔄 Atualizando contagens de alertas e eventos após sync...")
			if countErr := s.updateAllCVEAlertCounts(); countErr != nil {
				log.Printf("⚠️ Erro ao atualizar contagens: %v", countErr)
			}

			updateSyncStatus("completed", fmt.Sprintf("Sincronização concluída: %d CVEs indexados. Contagens de alertas/eventos atualizadas.", indexed), 100, cveSyncTotal, indexed, cveSyncErrors)
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message": fmt.Sprintf("Sincronização iniciada para os últimos %d dias", daysBack),
		"status":  "running",
	})
}

// handleGetCVESyncStatus retorna o status atual da sincronização de CVEs
func (s *APIServer) handleGetCVESyncStatus(c *gin.Context) {
	cveSyncMutex.RLock()
	defer cveSyncMutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"status":    cveSyncStatus,
		"message":   cveSyncMessage,
		"progress":  cveSyncProgress,
		"total":     cveSyncTotal,
		"indexed":   cveSyncIndexed,
		"errors":    cveSyncErrors,
		"lastError": cveSyncLastError,
	})
}

// handleSearchCVEs busca CVEs por texto
func (s *APIServer) handleSearchCVEs(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parâmetro 'q' é obrigatório"})
		return
	}

	limit := parseIntParam(c.DefaultQuery("limit", "20"), 20)

	// Buscar do OpenSearch
	if s.opensearch != nil {
		cves, total, err := s.searchCVEsInOpenSearch(c, query, limit)
		if err == nil {
			c.JSON(http.StatusOK, gin.H{
				"cves":   cves,
				"total":  total,
				"source": "opensearch",
			})
			return
		}
	}

	// Fallback para memória
	query = strings.ToLower(query)
	var results []CVE

	cveManager.mu.RLock()
	for _, cve := range cveManager.cves {
		if strings.Contains(strings.ToLower(cve.ID), query) ||
			strings.Contains(strings.ToLower(cve.Description), query) {
			results = append(results, *cve)
			if len(results) >= limit {
				break
			}
		}
	}
	cveManager.mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"cves":   results,
		"total":  len(results),
		"source": "memory",
	})
}

// handleGetCVEAlerts retorna alertas associados a um CVE
func (s *APIServer) handleGetCVEAlerts(c *gin.Context) {
	cveID := strings.ToUpper(c.Param("id"))
	limit := parseIntParam(c.DefaultQuery("limit", "50"), 50)

	alerts, err := s.fetchAlertsByCVE(c, cveID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao buscar alertas"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cveId":  cveID,
		"alerts": alerts,
		"total":  len(alerts),
	})
}

// handleUpdateCVEAlertCount atualiza contagem de alertas e eventos para todos os CVEs
func (s *APIServer) handleUpdateCVEAlertCount(c *gin.Context) {
	go func() {
		err := s.updateAllCVEAlertCounts()
		if err != nil {
			log.Printf("❌ CVE alert/event count update failed: %v", err)
		} else {
			log.Printf("✅ CVE alert/event counts updated successfully")
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Atualização de contagem de alertas e eventos iniciada. Este processo busca em todos os índices de eventos e alertas por referências a cada CVE.",
		"status":  "processing",
	})
}

// ============================================================================
// OPENSEARCH FUNCTIONS
// ============================================================================

func (s *APIServer) fetchCVEsFromOpenSearch(c *gin.Context, limit, page int, severity, search string, withAlerts bool, sortBy, sortOrder string) ([]CVE, int, error) {
	must := []map[string]interface{}{}

	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"severity": strings.ToUpper(severity),
			},
		})
	}

	if search != "" {
		must = append(must, map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  search,
				"fields": []string{"id^3", "description", "affectedProducts"},
				"type":   "best_fields",
			},
		})
	}

	if withAlerts {
		must = append(must, map[string]interface{}{
			"range": map[string]interface{}{
				"alertCount": map[string]interface{}{
					"gt": 0,
				},
			},
		})
	}

	query := map[string]interface{}{
		"size": limit,
		"from": (page - 1) * limit,
		"sort": []map[string]interface{}{
			{sortBy: map[string]interface{}{"order": sortOrder}},
		},
	}

	if len(must) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(c.Request.Context()),
		s.opensearch.Search.WithIndex("siem-cves"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, 0, fmt.Errorf("opensearch error: %s", res.Status())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, err
	}

	hits := result["hits"].(map[string]interface{})
	total := int(hits["total"].(map[string]interface{})["value"].(float64))

	var cves []CVE
	for _, hit := range hits["hits"].([]interface{}) {
		hitMap := hit.(map[string]interface{})
		source := hitMap["_source"].(map[string]interface{})

		cve := parseCVEFromSource(source)
		cves = append(cves, cve)
	}

	return cves, total, nil
}

func (s *APIServer) fetchCVEByIDFromOpenSearch(c *gin.Context, cveID string) (*CVE, error) {
	res, err := s.opensearch.Get(
		"siem-cves",
		cveID,
		s.opensearch.Get.WithContext(c.Request.Context()),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("CVE not found")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	source := result["_source"].(map[string]interface{})
	cve := parseCVEFromSource(source)
	return &cve, nil
}

func (s *APIServer) fetchCVEStatsFromOpenSearch(c *gin.Context) (*CVEStats, error) {
	query := map[string]interface{}{
		"size": 0,
		"aggs": map[string]interface{}{
			"severity_breakdown": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "severity",
					"size":  10,
				},
			},
			"with_alerts": map[string]interface{}{
				"filter": map[string]interface{}{
					"range": map[string]interface{}{
						"alertCount": map[string]interface{}{"gt": 0},
					},
				},
			},
			"total_alerts": map[string]interface{}{
				"sum": map[string]interface{}{
					"field": "alertCount",
				},
			},
			"exploited": map[string]interface{}{
				"filter": map[string]interface{}{
					"term": map[string]interface{}{"exploitAvailable": true},
				},
			},
			"cisa_kev": map[string]interface{}{
				"filter": map[string]interface{}{
					"term": map[string]interface{}{"cisaKnownExploit": true},
				},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(c.Request.Context()),
		s.opensearch.Search.WithIndex("siem-cves"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("opensearch error: %s", res.Status())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	hits := result["hits"].(map[string]interface{})
	aggs := result["aggregations"].(map[string]interface{})

	stats := &CVEStats{
		TotalCVEs:       int(hits["total"].(map[string]interface{})["value"].(float64)),
		BySeverity:      make(map[string]int),
		TopCVEsByAlerts: []CVEAlertSummary{},
	}

	// Parse severity breakdown
	if sevAgg, ok := aggs["severity_breakdown"].(map[string]interface{}); ok {
		if buckets, ok := sevAgg["buckets"].([]interface{}); ok {
			for _, bucket := range buckets {
				b := bucket.(map[string]interface{})
				key := b["key"].(string)
				count := int(b["doc_count"].(float64))
				stats.BySeverity[key] = count
			}
		}
	}

	// Parse other aggregations
	if withAlerts, ok := aggs["with_alerts"].(map[string]interface{}); ok {
		stats.WithAlerts = int(withAlerts["doc_count"].(float64))
	}
	if totalAlerts, ok := aggs["total_alerts"].(map[string]interface{}); ok {
		if val, ok := totalAlerts["value"].(float64); ok {
			stats.TotalAlerts = int(val)
		}
	}
	if exploited, ok := aggs["exploited"].(map[string]interface{}); ok {
		stats.ExploitedCVEs = int(exploited["doc_count"].(float64))
	}
	if cisaKev, ok := aggs["cisa_kev"].(map[string]interface{}); ok {
		stats.CISAKnownExploits = int(cisaKev["doc_count"].(float64))
	}

	// Buscar top CVEs por alertas
	stats.TopCVEsByAlerts = s.fetchTopCVEsByAlerts(c, 10)

	return stats, nil
}

func (s *APIServer) fetchTopCVEsByAlerts(c *gin.Context, limit int) []CVEAlertSummary {
	query := map[string]interface{}{
		"size": limit,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"alertCount": map[string]interface{}{"gt": 0},
			},
		},
		"sort": []map[string]interface{}{
			{"alertCount": map[string]interface{}{"order": "desc"}},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(c.Request.Context()),
		s.opensearch.Search.WithIndex("siem-cves"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return []CVEAlertSummary{}
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return []CVEAlertSummary{}
	}

	var summaries []CVEAlertSummary
	hits := result["hits"].(map[string]interface{})["hits"].([]interface{})
	for _, hit := range hits {
		source := hit.(map[string]interface{})["_source"].(map[string]interface{})
		summaries = append(summaries, CVEAlertSummary{
			CVEID:       getStringFromMap(source, "id"),
			Description: truncateString(getStringFromMap(source, "description"), 100),
			Severity:    getStringFromMap(source, "severity"),
			CVSSScore:   getFloatFromMap(source, "cvssScore"),
			AlertCount:  getIntFromMap(source, "alertCount"),
			EventCount:  getIntFromMap(source, "eventCount"),
		})
	}

	return summaries
}

func (s *APIServer) searchCVEsInOpenSearch(c *gin.Context, query string, limit int) ([]CVE, int, error) {
	searchQuery := map[string]interface{}{
		"size": limit,
		"query": map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  query,
				"fields": []string{"id^5", "description^2", "affectedProducts", "weaknesses"},
				"type":   "best_fields",
			},
		},
		"sort": []map[string]interface{}{
			{"_score": map[string]interface{}{"order": "desc"}},
			{"cvssScore": map[string]interface{}{"order": "desc"}},
		},
	}

	queryJSON, _ := json.Marshal(searchQuery)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(c.Request.Context()),
		s.opensearch.Search.WithIndex("siem-cves"),
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

	hits := result["hits"].(map[string]interface{})
	total := int(hits["total"].(map[string]interface{})["value"].(float64))

	var cves []CVE
	for _, hit := range hits["hits"].([]interface{}) {
		source := hit.(map[string]interface{})["_source"].(map[string]interface{})
		cves = append(cves, parseCVEFromSource(source))
	}

	return cves, total, nil
}

func (s *APIServer) fetchAlertsByCVE(c *gin.Context, cveID string, limit int) ([]Alert, error) {
	if s.opensearch == nil {
		return []Alert{}, nil
	}

	query := map[string]interface{}{
		"size": limit,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{
						"match_phrase": map[string]interface{}{
							"name": cveID,
						},
					},
					{
						"match_phrase": map[string]interface{}{
							"description": cveID,
						},
					},
					{
						"match_phrase": map[string]interface{}{
							"query": cveID,
						},
					},
				},
				"minimum_should_match": 1,
			},
		},
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(c.Request.Context()),
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("opensearch error")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	var alerts []Alert
	hits := result["hits"].(map[string]interface{})["hits"].([]interface{})
	for _, hit := range hits {
		source := hit.(map[string]interface{})["_source"].(map[string]interface{})
		alert := parseCVEAlertFromSource(source)
		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// parseCVEAlertFromSource parses an alert from OpenSearch source
func parseCVEAlertFromSource(source map[string]interface{}) Alert {
	alert := Alert{
		ID:           getStringFromMap(source, "id"),
		Name:         getStringFromMap(source, "name"),
		Description:  getStringFromMap(source, "description"),
		Severity:     getStringFromMap(source, "severity"),
		Status:       getStringFromMap(source, "status"),
		Query:        getStringFromMap(source, "query"),
		Source:       getStringFromMap(source, "source"),
		SourceID:     getStringFromMap(source, "source_id"),
		Category:     getStringFromMap(source, "category"),
		ResourceID:   getStringFromMap(source, "resource_id"),
		ResourceType: getStringFromMap(source, "resource_type"),
		Region:       getStringFromMap(source, "region"),
		AccountID:    getStringFromMap(source, "account_id"),
	}

	if ts, ok := source["created_at"].(string); ok {
		alert.CreatedAt, _ = time.Parse(time.RFC3339, ts)
	}
	if ts, ok := source["updated_at"].(string); ok {
		alert.UpdatedAt, _ = time.Parse(time.RFC3339, ts)
	}

	return alert
}

// ============================================================================
// NVD SYNC FUNCTIONS
// ============================================================================

func (s *APIServer) syncCVEsFromNVD(daysBack int) error {
	startDate := time.Now().UTC().AddDate(0, 0, -daysBack)
	endDate := time.Now().UTC()

	apiKey := s.getNVDAPIKey()
	if apiKey == "" {
		log.Printf("⚠️ NVD API Key not configured - sync will use low rate limit (5 req/30s)")
	} else {
		log.Printf("✅ NVD API Key configured - using high rate limit (50 req/30s)")
	}

	// Garantir que o índice existe antes de indexar
	if s.opensearch != nil {
		s.EnsureCVEsIndex()
	} else {
		log.Printf("⚠️ OpenSearch not available - CVEs will only be cached in memory")
	}

	// NVD API v2.0
	baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"

	startIndex := 0
	resultsPerPage := 500 // Reduzido de 2000 para evitar timeouts e respostas grandes
	totalIndexed := 0
	totalErrors := 0
	rateLimitRetries := 0
	maxRateLimitRetries := 5

	for {
		// NVD API v2.0 aceita formato ISO 8601 com timezone UTC
		nvdDateFormat := "2006-01-02T15:04:05.000"
		url := fmt.Sprintf("%s?lastModStartDate=%s&lastModEndDate=%s&startIndex=%d&resultsPerPage=%d",
			baseURL,
			startDate.Format(nvdDateFormat),
			endDate.Format(nvdDateFormat),
			startIndex,
			resultsPerPage,
		)

		log.Printf("🔗 NVD API Request: startIndex=%d, resultsPerPage=%d, dateRange=%s to %s",
			startIndex, resultsPerPage,
			startDate.Format("2006-01-02"),
			endDate.Format("2006-01-02"))

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return fmt.Errorf("error creating request: %w", err)
		}

		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		client := &http.Client{Timeout: 120 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("❌ NVD API request failed: %v", err)
			return fmt.Errorf("error fetching from NVD: %w", err)
		}

		if resp.StatusCode == 403 {
			resp.Body.Close()
			rateLimitRetries++
			if rateLimitRetries >= maxRateLimitRetries {
				return fmt.Errorf("NVD API rate limit excedido %d vezes consecutivas, abortando", maxRateLimitRetries)
			}
			waitTime := 35 * time.Second
			log.Printf("⚠️ NVD API rate limit hit (tentativa %d/%d), aguardando %v...", rateLimitRetries, maxRateLimitRetries, waitTime)
			updateSyncStatus("running", fmt.Sprintf("Rate limit atingido, aguardando %v... (tentativa %d/%d)", waitTime, rateLimitRetries, maxRateLimitRetries), 0, 0, totalIndexed, totalErrors)
			time.Sleep(waitTime)
			continue
		}

		rateLimitRetries = 0 // Reset on success

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("❌ NVD API error response: HTTP %d - %s", resp.StatusCode, string(body))
			return fmt.Errorf("NVD API error: HTTP %d - %s", resp.StatusCode, string(body))
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("error reading NVD response body: %w", err)
		}

		var nvdResp NVDResponse
		if err := json.Unmarshal(bodyBytes, &nvdResp); err != nil {
			log.Printf("❌ Error decoding NVD response (body length: %d bytes): %v", len(bodyBytes), err)
			// Log first 500 chars of response for debugging
			preview := string(bodyBytes)
			if len(preview) > 500 {
				preview = preview[:500]
			}
			log.Printf("📋 Response preview: %s", preview)
			return fmt.Errorf("error decoding NVD response: %w", err)
		}

		log.Printf("📥 Fetched %d CVEs (index %d of %d total)", len(nvdResp.Vulnerabilities), startIndex, nvdResp.TotalResults)

		if nvdResp.TotalResults == 0 {
			log.Printf("ℹ️ NVD returned 0 results for the given date range")
			updateSyncStatus("completed", "NVD não retornou CVEs para o período selecionado", 100, 0, 0, 0)
			return nil
		}

		// Atualizar status com total
		updateSyncStatus("running",
			fmt.Sprintf("Processando CVEs %d-%d de %d...", startIndex+1, startIndex+len(nvdResp.Vulnerabilities), nvdResp.TotalResults),
			int(float64(startIndex)/float64(nvdResp.TotalResults)*100),
			nvdResp.TotalResults, totalIndexed, totalErrors)

		// Processar CVEs
		for _, vuln := range nvdResp.Vulnerabilities {
			cve := convertNVDToCVE(vuln)

			if s.opensearch != nil {
				if err := s.indexCVEToOpenSearch(cve); err != nil {
					totalErrors++
					log.Printf("⚠️ Failed to index CVE %s: %v", cve.ID, err)
				} else {
					totalIndexed++
				}
			} else {
				totalIndexed++
			}

			cveManager.mu.Lock()
			cveManager.cves[cve.ID] = &cve
			cveManager.mu.Unlock()
		}

		log.Printf("📊 Progress: %d indexed, %d errors so far", totalIndexed, totalErrors)

		startIndex += len(nvdResp.Vulnerabilities)
		if startIndex >= nvdResp.TotalResults {
			break
		}

		// Rate limiting - NVD permite 5 requests por 30 segundos sem API key, 50 com
		if apiKey == "" {
			log.Printf("⏳ Waiting 6.5s (no API key rate limit)...")
			time.Sleep(6500 * time.Millisecond)
		} else {
			log.Printf("⏳ Waiting 800ms (API key rate limit)...")
			time.Sleep(800 * time.Millisecond)
		}
	}

	now := time.Now()
	cveManager.mu.Lock()
	cveManager.lastSync = &now
	cveManager.mu.Unlock()

	// Atualizar status final
	cveSyncMutex.Lock()
	cveSyncIndexed = totalIndexed
	cveSyncErrors = totalErrors
	cveSyncMutex.Unlock()

	log.Printf("✅ CVE sync completed: %d indexed, %d errors", totalIndexed, totalErrors)

	return nil
}

func (s *APIServer) indexCVEToOpenSearch(cve CVE) error {
	if s.opensearch == nil {
		return fmt.Errorf("opensearch not available")
	}

	doc, err := json.Marshal(cve)
	if err != nil {
		log.Printf("❌ Error marshaling CVE %s: %v", cve.ID, err)
		return err
	}

	res, err := s.opensearch.Index(
		"siem-cves",
		strings.NewReader(string(doc)),
		s.opensearch.Index.WithDocumentID(cve.ID),
		s.opensearch.Index.WithRefresh("false"),
	)
	if err != nil {
		log.Printf("❌ Error indexing CVE %s to OpenSearch: %v", cve.ID, err)
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		log.Printf("❌ OpenSearch indexing error for CVE %s: %s - %s", cve.ID, res.Status(), string(body))
		return fmt.Errorf("indexing error: %s", res.Status())
	}

	return nil
}

func (s *APIServer) updateAllCVEAlertCounts() error {
	if s.opensearch == nil {
		return fmt.Errorf("opensearch not available")
	}

	log.Println("🔄 Atualizando contagens de alertas e eventos para CVEs...")

	// Buscar todos os CVEs
	query := map[string]interface{}{
		"size":    10000,
		"_source": []string{"id"},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-cves"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return err
	}

	hits := result["hits"].(map[string]interface{})["hits"].([]interface{})
	totalCVEs := len(hits)
	updated := 0
	withAlerts := 0
	withEvents := 0

	log.Printf("📊 Processando contagens para %d CVEs...", totalCVEs)

	for i, hit := range hits {
		source := hit.(map[string]interface{})["_source"].(map[string]interface{})
		cveID := getStringFromMap(source, "id")

		// Contar alertas para este CVE
		alertCount := s.countAlertsByCVE(cveID)

		// Contar eventos para este CVE
		eventCount := s.countEventsByCVE(cveID)

		// Atualizar contagem se houver alertas ou eventos
		if alertCount > 0 || eventCount > 0 {
			updateDoc := map[string]interface{}{
				"doc": map[string]interface{}{
					"alertCount": alertCount,
					"eventCount": eventCount,
					"updatedAt":  time.Now().Format(time.RFC3339),
				},
			}
			updateJSON, _ := json.Marshal(updateDoc)

			updateRes, err := s.opensearch.Update(
				"siem-cves",
				cveID,
				strings.NewReader(string(updateJSON)),
			)
			if err != nil {
				log.Printf("⚠️ Erro ao atualizar contagem para %s: %v", cveID, err)
			} else {
				updateRes.Body.Close()
				updated++
			}

			if alertCount > 0 {
				withAlerts++
			}
			if eventCount > 0 {
				withEvents++
			}
		}

		// Log de progresso a cada 100 CVEs
		if (i+1)%100 == 0 {
			log.Printf("📊 Progresso: %d/%d CVEs processados (%d com alertas, %d com eventos)", i+1, totalCVEs, withAlerts, withEvents)
		}

		// Rate limiting para não sobrecarregar o OpenSearch
		if i > 0 && i%50 == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	log.Printf("✅ Contagens atualizadas: %d CVEs processados, %d atualizados (%d com alertas, %d com eventos)", totalCVEs, updated, withAlerts, withEvents)

	return nil
}

func (s *APIServer) countAlertsByCVE(cveID string) int {
	query := map[string]interface{}{
		"size":             0,
		"track_total_hits": true,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"match_phrase": map[string]interface{}{"name": cveID}},
					{"match_phrase": map[string]interface{}{"description": cveID}},
					{"match_phrase": map[string]interface{}{"query": cveID}},
				},
				"minimum_should_match": 1,
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return 0
	}
	defer res.Body.Close()

	if res.IsError() {
		return 0
	}

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

// countEventsByCVE busca em todos os índices de eventos por referências ao CVE ID
func (s *APIServer) countEventsByCVE(cveID string) int {
	if s.opensearch == nil {
		return 0
	}

	// Buscar em múltiplos campos onde o CVE ID pode aparecer
	query := map[string]interface{}{
		"size":             0,
		"track_total_hits": true,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"match_phrase": map[string]interface{}{"description": cveID}},
					{"match_phrase": map[string]interface{}{"type": cveID}},
					{"match_phrase": map[string]interface{}{"source": cveID}},
					{
						"query_string": map[string]interface{}{
							"query":            "\"" + cveID + "\"",
							"default_operator": "AND",
						},
					},
				},
				"minimum_should_match": 1,
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	// Determinar o padrão de índice de eventos
	indexPattern := "siem-events-*,siem-events"
	if s.config.Elasticsearch.IndexPattern != "" {
		indexPattern = s.config.Elasticsearch.IndexPattern
	}

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex(indexPattern),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
		s.opensearch.Search.WithIgnoreUnavailable(true),
	)
	if err != nil {
		return 0
	}
	defer res.Body.Close()

	if res.IsError() {
		return 0
	}

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

func fetchCVEFromNVD(cveID string, apiKey string) (*CVE, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API error: %d", resp.StatusCode)
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, err
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found")
	}

	cve := convertNVDToCVE(nvdResp.Vulnerabilities[0])
	return &cve, nil
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func convertNVDToCVE(vuln NVDVulnerability) CVE {
	nvdCVE := vuln.CVE

	cve := CVE{
		ID:        nvdCVE.ID,
		Status:    nvdCVE.VulnStatus,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Parse description (prefer English)
	for _, desc := range nvdCVE.Descriptions {
		if desc.Lang == "en" {
			cve.Description = desc.Value
			break
		}
	}

	// Parse dates
	if nvdCVE.Published != "" {
		cve.PublishedDate, _ = time.Parse(time.RFC3339, nvdCVE.Published)
	}
	if nvdCVE.LastModified != "" {
		cve.LastModifiedDate, _ = time.Parse(time.RFC3339, nvdCVE.LastModified)
	}

	// Parse CVSS (prefer v3.1 > v3.0 > v2)
	if len(nvdCVE.Metrics.CVSSMetricV31) > 0 {
		metric := nvdCVE.Metrics.CVSSMetricV31[0]
		cve.CVSSScore = metric.CVSSData.BaseScore
		cve.CVSSVector = metric.CVSSData.VectorString
		cve.CVSSVersion = metric.CVSSData.Version
		cve.Severity = metric.CVSSData.BaseSeverity
	} else if len(nvdCVE.Metrics.CVSSMetricV30) > 0 {
		metric := nvdCVE.Metrics.CVSSMetricV30[0]
		cve.CVSSScore = metric.CVSSData.BaseScore
		cve.CVSSVector = metric.CVSSData.VectorString
		cve.CVSSVersion = metric.CVSSData.Version
		cve.Severity = metric.CVSSData.BaseSeverity
	} else if len(nvdCVE.Metrics.CVSSMetricV2) > 0 {
		metric := nvdCVE.Metrics.CVSSMetricV2[0]
		cve.CVSSScore = metric.CVSSData.BaseScore
		cve.CVSSVector = metric.CVSSData.VectorString
		cve.CVSSVersion = metric.CVSSData.Version
		// Convert v2 score to severity
		cve.Severity = cvssV2ToSeverity(metric.CVSSData.BaseScore)
	}

	// Parse weaknesses (CWE)
	for _, weakness := range nvdCVE.Weaknesses {
		for _, desc := range weakness.Description {
			if desc.Lang == "en" {
				cve.Weaknesses = append(cve.Weaknesses, desc.Value)
			}
		}
	}

	// Parse references
	for _, ref := range nvdCVE.References {
		cve.References = append(cve.References, CVERef{
			URL:    ref.URL,
			Source: ref.Source,
			Tags:   ref.Tags,
		})

		// Check for exploit tags
		for _, tag := range ref.Tags {
			if strings.Contains(strings.ToLower(tag), "exploit") {
				cve.ExploitAvailable = true
			}
			if strings.Contains(strings.ToLower(tag), "patch") {
				cve.PatchAvailable = true
			}
		}
	}

	return cve
}

func cvssV2ToSeverity(score float64) string {
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func parseCVEFromSource(source map[string]interface{}) CVE {
	cve := CVE{
		ID:               getStringFromMap(source, "id"),
		Description:      getStringFromMap(source, "description"),
		Severity:         getStringFromMap(source, "severity"),
		CVSSScore:        getFloatFromMap(source, "cvssScore"),
		CVSSVector:       getStringFromMap(source, "cvssVector"),
		CVSSVersion:      getStringFromMap(source, "cvssVersion"),
		Status:           getStringFromMap(source, "status"),
		AlertCount:       getIntFromMap(source, "alertCount"),
		EventCount:       getIntFromMap(source, "eventCount"),
		ExploitAvailable: getBoolFromMap(source, "exploitAvailable"),
		CISAKnownExploit: getBoolFromMap(source, "cisaKnownExploit"),
		PatchAvailable:   getBoolFromMap(source, "patchAvailable"),
	}

	if ts, ok := source["publishedDate"].(string); ok {
		cve.PublishedDate, _ = time.Parse(time.RFC3339, ts)
	}
	if ts, ok := source["lastModifiedDate"].(string); ok {
		cve.LastModifiedDate, _ = time.Parse(time.RFC3339, ts)
	}
	if ts, ok := source["createdAt"].(string); ok {
		cve.CreatedAt, _ = time.Parse(time.RFC3339, ts)
	}
	if ts, ok := source["updatedAt"].(string); ok {
		cve.UpdatedAt, _ = time.Parse(time.RFC3339, ts)
	}

	if prods, ok := source["affectedProducts"].([]interface{}); ok {
		for _, p := range prods {
			if ps, ok := p.(string); ok {
				cve.AffectedProducts = append(cve.AffectedProducts, ps)
			}
		}
	}

	if weaknesses, ok := source["weaknesses"].([]interface{}); ok {
		for _, w := range weaknesses {
			if ws, ok := w.(string); ok {
				cve.Weaknesses = append(cve.Weaknesses, ws)
			}
		}
	}

	return cve
}

// Note: getFloatFromMap, getIntFromMap, and truncateString are defined in cases.go and cspm_real_data.go

func parseIntParam(s string, defaultVal int) int {
	var val int
	_, err := fmt.Sscanf(s, "%d", &val)
	if err != nil {
		return defaultVal
	}
	return val
}

// ============================================================================
// OPENSEARCH INDEX INITIALIZATION
// ============================================================================

// EnsureCVEsIndex creates the CVE index with proper mappings
func (s *APIServer) EnsureCVEsIndex() {
	if s.opensearch == nil {
		log.Println("⚠️ OpenSearch not available, skipping CVE index creation")
		return
	}

	indexName := "siem-cves"

	// Check if index exists
	res, err := s.opensearch.Indices.Exists([]string{indexName})
	if err != nil {
		log.Printf("⚠️ Error checking CVE index: %v", err)
		return
	}
	res.Body.Close()

	if res.StatusCode == 200 {
		log.Printf("✅ CVE index (%s) already exists", indexName)
		return
	}

	// Create index with mappings
	mapping := map[string]interface{}{
		"settings": map[string]interface{}{
			"number_of_shards":   1,
			"number_of_replicas": 0,
			"analysis": map[string]interface{}{
				"analyzer": map[string]interface{}{
					"cve_analyzer": map[string]interface{}{
						"type":      "custom",
						"tokenizer": "standard",
						"filter":    []string{"lowercase", "asciifolding"},
					},
				},
			},
		},
		"mappings": map[string]interface{}{
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type": "keyword",
				},
				"description": map[string]interface{}{
					"type":     "text",
					"analyzer": "cve_analyzer",
					"fields": map[string]interface{}{
						"keyword": map[string]interface{}{
							"type":         "keyword",
							"ignore_above": 10000,
						},
					},
				},
				"severity": map[string]interface{}{
					"type": "keyword",
				},
				"cvssScore": map[string]interface{}{
					"type": "float",
				},
				"cvssVector": map[string]interface{}{
					"type": "keyword",
				},
				"cvssVersion": map[string]interface{}{
					"type": "keyword",
				},
				"publishedDate": map[string]interface{}{
					"type": "date",
				},
				"lastModifiedDate": map[string]interface{}{
					"type": "date",
				},
				"status": map[string]interface{}{
					"type": "keyword",
				},
				"affectedProducts": map[string]interface{}{
					"type": "keyword",
				},
				"weaknesses": map[string]interface{}{
					"type": "keyword",
				},
				"alertCount": map[string]interface{}{
					"type": "integer",
				},
				"eventCount": map[string]interface{}{
					"type": "integer",
				},
				"exploitAvailable": map[string]interface{}{
					"type": "boolean",
				},
				"cisaKnownExploit": map[string]interface{}{
					"type": "boolean",
				},
				"patchAvailable": map[string]interface{}{
					"type": "boolean",
				},
				"lastAlertDate": map[string]interface{}{
					"type": "date",
				},
				"createdAt": map[string]interface{}{
					"type": "date",
				},
				"updatedAt": map[string]interface{}{
					"type": "date",
				},
				"references": map[string]interface{}{
					"type": "nested",
					"properties": map[string]interface{}{
						"url": map[string]interface{}{
							"type": "keyword",
						},
						"source": map[string]interface{}{
							"type": "keyword",
						},
						"tags": map[string]interface{}{
							"type": "keyword",
						},
					},
				},
			},
		},
	}

	mappingJSON, _ := json.Marshal(mapping)

	res, err = s.opensearch.Indices.Create(
		indexName,
		s.opensearch.Indices.Create.WithBody(strings.NewReader(string(mappingJSON))),
	)
	if err != nil {
		log.Printf("⚠️ Error creating CVE index: %v", err)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("⚠️ Failed to create CVE index: %s", res.String())
	} else {
		log.Printf("✅ CVE index (%s) created successfully", indexName)
	}
}

// StartCVESyncWorker inicia o worker de sincronização de CVEs
func (s *APIServer) StartCVESyncWorker() {
	go func() {
		// Aguardar 1 minuto antes de iniciar a primeira sincronização
		time.Sleep(1 * time.Minute)

		for {
			log.Println("🔄 Starting scheduled CVE sync...")
			err := s.syncCVEsFromNVD(7) // Sincronizar últimos 7 dias
			if err != nil {
				log.Printf("⚠️ Scheduled CVE sync failed: %v", err)
			} else {
				log.Println("✅ Scheduled CVE sync completed")
				// Atualizar contagem de alertas
				s.updateAllCVEAlertCounts()
			}

			// Aguardar 6 horas para próxima sincronização
			time.Sleep(6 * time.Hour)
		}
	}()
}
