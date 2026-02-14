package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opensearch-project/opensearch-go/v2"
	"github.com/opensearch-project/opensearch-go/v2/opensearchapi"
)

// CloudflareConfig armazena as configurações de integração
type CloudflareConfig struct {
	APIToken   string   `json:"api_token"`
	AccountID  string   `json:"account_id"`
	ZoneIDs    []string `json:"zone_ids"`
	Enabled    bool     `json:"enabled"`
	SyncPeriod int      `json:"sync_period_minutes"` // Intervalo de sincronização em minutos
	UseRESTAPI bool     `json:"use_rest_api"`        // Usar REST API em vez de GraphQL (mais compatível)
}

// CloudflareZone representa uma zona do Cloudflare
type CloudflareZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// CloudflareFirewallEvent representa um evento de firewall/WAF
type CloudflareFirewallEvent struct {
	RayID              string    `json:"rayId"`
	Action             string    `json:"action"`
	ClientIP           string    `json:"clientIP"`
	ClientCountry      string    `json:"clientCountry"`
	ClientASN          string    `json:"clientAsn"`
	ClientASNDesc      string    `json:"clientASNDescription"`
	DateTime           time.Time `json:"datetime"`
	Host               string    `json:"host"`
	Method             string    `json:"method"`
	URI                string    `json:"uri"`
	UserAgent          string    `json:"userAgent"`
	RuleID             string    `json:"ruleId"`
	RuleDescription    string    `json:"ruleDescription"`
	RulesetID          string    `json:"rulesetId"`
	RulesetName        string    `json:"rulesetName"`
	Service            string    `json:"service"`
	Source             string    `json:"source"`
	EdgeResponseStatus int       `json:"edgeResponseStatus"`
}

// CloudflareGraphQLResponse representa a resposta da API GraphQL
// Campos alinhados com o schema oficial da Cloudflare firewallEventsAdaptive
type CloudflareGraphQLResponse struct {
	Data struct {
		Viewer struct {
			Zones []struct {
				FirewallEventsAdaptive []struct {
					RayName                     string `json:"rayName"`
					Action                      string `json:"action"`
					ClientIP                    string `json:"clientIP"`
					ClientCountryName           string `json:"clientCountryName"`
					ClientAsn                   string `json:"clientAsn"`
					ClientASNDescription        string `json:"clientASNDescription"`
					Datetime                    string `json:"datetime"`
					ClientRequestHTTPHost       string `json:"clientRequestHTTPHost"`
					ClientRequestHTTPMethodName string `json:"clientRequestHTTPMethodName"`
					ClientRequestPath           string `json:"clientRequestPath"`
					ClientRequestQuery          string `json:"clientRequestQuery"`
					UserAgent                   string `json:"userAgent"`
					RuleId                      string `json:"ruleId"`
					RulesetId                   string `json:"rulesetId"`
					Source                      string `json:"source"`
					EdgeResponseStatus          int    `json:"edgeResponseStatus"`
				} `json:"firewallEventsAdaptive"`
			} `json:"zones"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// CloudflareZonesResponse representa a resposta da API de zonas
type CloudflareZonesResponse struct {
	Success bool `json:"success"`
	Result  []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"result"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// CloudflareSecurityEventsResponse representa a resposta da REST API de Security Events
type CloudflareSecurityEventsResponse struct {
	Success bool `json:"success"`
	Result  []struct {
		RayID                string                 `json:"ray_id"`
		Action               string                 `json:"action"`
		ClientIP             string                 `json:"client_ip"`
		ClientCountry        string                 `json:"client_country"`
		ClientASN            int                    `json:"client_asn"`
		ClientASNDesc        string                 `json:"client_asn_desc"`
		OccurredAt           string                 `json:"occurred_at"`
		Host                 string                 `json:"host"`
		Method               string                 `json:"method"`
		URI                  string                 `json:"uri"`
		UserAgent            string                 `json:"user_agent"`
		RuleID               string                 `json:"rule_id"`
		RuleMessage          string                 `json:"rule_message"`
		RulesetID            string                 `json:"ruleset_id"`
		RulesetName          string                 `json:"ruleset_name"`
		Source               string                 `json:"source"`
		Kind                 string                 `json:"kind"`
		EdgeResponseStatus   int                    `json:"edge_response_status"`
		OriginResponseStatus int                    `json:"origin_response_status"`
		Ref                  string                 `json:"ref"`
		Metadata             map[string]interface{} `json:"metadata"`
	} `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Messages []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"messages"`
}

// CloudflareWAFCollector gerencia a coleta de logs do Cloudflare
type CloudflareWAFCollector struct {
	config           CloudflareConfig
	opensearchClient *opensearch.Client
	httpClient       *http.Client
	mu               sync.RWMutex
	running          bool
	stopChan         chan struct{}
	lastSync         time.Time
	eventsCollected  int64
}

var (
	cloudflareCollector *CloudflareWAFCollector
	cloudflareOnce      sync.Once
)

// InitCloudflareCollector inicializa o coletor do Cloudflare
func InitCloudflareCollector(opensearchClient *opensearch.Client) *CloudflareWAFCollector {
	cloudflareOnce.Do(func() {
		cloudflareCollector = &CloudflareWAFCollector{
			opensearchClient: opensearchClient,
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
			stopChan: make(chan struct{}),
		}

		// Carregar configuração do OpenSearch ou variáveis de ambiente
		cloudflareCollector.loadConfig()

		// Criar índice no OpenSearch
		cloudflareCollector.createIndex()
	})
	return cloudflareCollector
}

// loadConfig carrega a configuração do Cloudflare
func (c *CloudflareWAFCollector) loadConfig() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Tentar carregar do OpenSearch primeiro
	if c.opensearchClient != nil {
		cfg, err := c.loadConfigFromOpenSearch()
		if err == nil && cfg.APIToken != "" {
			c.config = cfg
			return
		}
	}

	// Fallback para variáveis de ambiente
	c.config = CloudflareConfig{
		APIToken:   os.Getenv("CLOUDFLARE_API_TOKEN"),
		AccountID:  os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
		ZoneIDs:    strings.Split(os.Getenv("CLOUDFLARE_ZONE_IDS"), ","),
		Enabled:    os.Getenv("CLOUDFLARE_ENABLED") == "true",
		SyncPeriod: 5, // 5 minutos padrão
	}
}

// loadConfigFromOpenSearch carrega config do OpenSearch
func (c *CloudflareWAFCollector) loadConfigFromOpenSearch() (CloudflareConfig, error) {
	var cfg CloudflareConfig

	req := opensearchapi.GetRequest{
		Index:      "siem-integrations-config",
		DocumentID: "cloudflare",
	}

	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return cfg, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return cfg, fmt.Errorf("error getting config: %s", res.Status())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return cfg, err
	}

	if source, ok := result["_source"].(map[string]interface{}); ok {
		if apiToken, ok := source["api_token"].(string); ok {
			cfg.APIToken = apiToken
		}
		if accountID, ok := source["account_id"].(string); ok {
			cfg.AccountID = accountID
		}
		if zoneIDs, ok := source["zone_ids"].([]interface{}); ok {
			for _, z := range zoneIDs {
				if zoneID, ok := z.(string); ok {
					cfg.ZoneIDs = append(cfg.ZoneIDs, zoneID)
				}
			}
		}
		if enabled, ok := source["enabled"].(bool); ok {
			cfg.Enabled = enabled
		}
		if syncPeriod, ok := source["sync_period_minutes"].(float64); ok {
			cfg.SyncPeriod = int(syncPeriod)
		}
	}

	return cfg, nil
}

// saveConfigToOpenSearch salva a configuração no OpenSearch
func (c *CloudflareWAFCollector) saveConfigToOpenSearch() error {
	if c.opensearchClient == nil {
		return fmt.Errorf("opensearch client not available")
	}

	// Criar índice de configuração se não existir
	indexBody := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		}
	}`

	createReq := opensearchapi.IndicesCreateRequest{
		Index: "siem-integrations-config",
		Body:  strings.NewReader(indexBody),
	}
	createReq.Do(context.Background(), c.opensearchClient)

	// Salvar configuração
	configJSON, err := json.Marshal(c.config)
	if err != nil {
		return err
	}

	req := opensearchapi.IndexRequest{
		Index:      "siem-integrations-config",
		DocumentID: "cloudflare",
		Body:       strings.NewReader(string(configJSON)),
		Refresh:    "true",
	}

	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error saving config: %s", res.Status())
	}

	return nil
}

// createIndex cria o índice para eventos WAF do Cloudflare
func (c *CloudflareWAFCollector) createIndex() error {
	if c.opensearchClient == nil {
		return fmt.Errorf("opensearch client not available")
	}

	mapping := `{
		"settings": {
			"number_of_shards": 2,
			"number_of_replicas": 0,
			"index": {
				"refresh_interval": "5s"
			}
		},
		"mappings": {
			"properties": {
				"ray_id": { "type": "keyword" },
				"action": { "type": "keyword" },
				"client_ip": { "type": "ip" },
				"client_country": { "type": "keyword" },
				"client_asn": { "type": "keyword" },
				"client_asn_desc": { "type": "text" },
				"timestamp": { "type": "date" },
				"host": { "type": "keyword" },
				"method": { "type": "keyword" },
				"uri": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"user_agent": { "type": "text" },
				"rule_id": { "type": "keyword" },
				"rule_description": { "type": "text" },
				"ruleset_id": { "type": "keyword" },
				"ruleset_name": { "type": "keyword" },
				"service": { "type": "keyword" },
				"source": { "type": "keyword" },
				"edge_response_status": { "type": "integer" },
				"zone_id": { "type": "keyword" },
				"severity": { "type": "keyword" },
				"threat_score": { "type": "integer" },
				"mitre_tactic": { "type": "keyword" },
				"mitre_technique": { "type": "keyword" }
			}
		}
	}`

	req := opensearchapi.IndicesCreateRequest{
		Index: "siem-cloudflare-waf",
		Body:  strings.NewReader(mapping),
	}

	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

// Start inicia a coleta periódica
func (c *CloudflareWAFCollector) Start() {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return
	}
	c.running = true
	c.mu.Unlock()

	go func() {
		// Coletar imediatamente na inicialização
		c.collectEvents()

		period := time.Duration(c.config.SyncPeriod) * time.Minute
		if period < time.Minute {
			period = 5 * time.Minute
		}

		ticker := time.NewTicker(period)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if c.config.Enabled {
					c.collectEvents()
				}
			case <-c.stopChan:
				return
			}
		}
	}()
}

// Stop para a coleta
func (c *CloudflareWAFCollector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		close(c.stopChan)
		c.running = false
	}
}

// collectEvents coleta eventos do Cloudflare via REST API (preferencial) ou GraphQL (fallback)
func (c *CloudflareWAFCollector) collectEvents() error {
	c.mu.RLock()
	config := c.config
	c.mu.RUnlock()

	if config.APIToken == "" {
		fmt.Printf("[Cloudflare] API token not configured, skipping collection\n")
		return fmt.Errorf("cloudflare API token not configured")
	}

	fmt.Printf("[Cloudflare] Starting event collection...\n")

	// Buscar zonas se não configuradas
	zoneIDs := config.ZoneIDs
	if len(zoneIDs) == 0 || (len(zoneIDs) == 1 && zoneIDs[0] == "") {
		fmt.Printf("[Cloudflare] No specific zones configured, fetching all zones...\n")
		zones, err := c.listZones()
		if err != nil {
			fmt.Printf("[Cloudflare] Failed to list zones: %v\n", err)
			return fmt.Errorf("failed to list zones: %v", err)
		}
		for _, z := range zones {
			zoneIDs = append(zoneIDs, z.ID)
			fmt.Printf("[Cloudflare] Found zone: %s (ID: %s)\n", z.Name, z.ID)
		}
	}

	if len(zoneIDs) == 0 {
		fmt.Printf("[Cloudflare] No zones found\n")
		return fmt.Errorf("no zones available")
	}

	// Período de busca: últimas 6 horas na primeira sync, depois desde última sync
	endTime := time.Now().UTC()
	startTime := endTime.Add(-6 * time.Hour) // Janela maior para capturar eventos
	if !c.lastSync.IsZero() && c.lastSync.After(startTime) {
		startTime = c.lastSync
	}

	fmt.Printf("[Cloudflare] Time range: %s to %s (%d zones)\n",
		startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), len(zoneIDs))

	totalEvents := 0
	totalErrors := 0
	apiMethod := "GraphQL"

	for _, zoneID := range zoneIDs {
		if zoneID == "" {
			continue
		}

		var events []CloudflareFirewallEvent
		var err error

		// GraphQL é o método primário (validado e mais confiável)
		events, err = c.fetchFirewallEventsGraphQL(zoneID, startTime, endTime)
		if err != nil {
			fmt.Printf("[Cloudflare] GraphQL failed for zone %s: %v, trying REST API...\n", zoneID, err)
			// Fallback para REST API se GraphQL falhar
			events, err = c.fetchFirewallEventsREST(zoneID, startTime, endTime)
			apiMethod = "REST"
			if err != nil {
				fmt.Printf("[Cloudflare] REST API also failed for zone %s: %v\n", zoneID, err)
				totalErrors++
				continue
			}
		}

		fmt.Printf("[Cloudflare] Processing %d events from zone %s\n", len(events), zoneID)

		// Indexar eventos no OpenSearch
		for _, event := range events {
			if err := c.indexEvent(event, zoneID); err != nil {
				fmt.Printf("[Cloudflare] Error indexing event: %v\n", err)
				totalErrors++
			} else {
				totalEvents++
				// Gerar alerta para eventos de alta severidade
				severity := c.mapActionToSeverity(event.Action)
				if severity == "HIGH" || severity == "CRITICAL" {
					if err := c.indexCloudflareAlert(event, zoneID); err != nil {
						fmt.Printf("[Cloudflare] Error indexing alert: %v\n", err)
					}
				}
			}
		}
	}

	c.mu.Lock()
	c.lastSync = endTime
	c.eventsCollected += int64(totalEvents)
	c.mu.Unlock()

	fmt.Printf("[Cloudflare] Collection complete: %d events collected via %s API (%d errors)\n", totalEvents, apiMethod, totalErrors)
	return nil
}

// listZones lista todas as zonas da conta
func (c *CloudflareWAFCollector) listZones() ([]CloudflareZone, error) {
	req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.config.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var zonesResp CloudflareZonesResponse
	if err := json.NewDecoder(resp.Body).Decode(&zonesResp); err != nil {
		return nil, err
	}

	if !zonesResp.Success && len(zonesResp.Errors) > 0 {
		return nil, fmt.Errorf("cloudflare API error: %s", zonesResp.Errors[0].Message)
	}

	var zones []CloudflareZone
	for _, z := range zonesResp.Result {
		zones = append(zones, CloudflareZone{
			ID:     z.ID,
			Name:   z.Name,
			Status: z.Status,
		})
	}

	return zones, nil
}

// fetchFirewallEventsREST busca eventos de firewall via REST API (Security Events)
// Esta API é mais compatível com diferentes planos Cloudflare
func (c *CloudflareWAFCollector) fetchFirewallEventsREST(zoneID string, startTime, endTime time.Time) ([]CloudflareFirewallEvent, error) {
	// Construir URL com parâmetros de filtro
	// Endpoint: GET /zones/{zone_id}/security/events
	baseURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/security/events", zoneID)

	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return nil, err
	}

	// Adicionar query parameters
	q := req.URL.Query()
	q.Add("since", startTime.Format(time.RFC3339))
	q.Add("until", endTime.Format(time.RFC3339))
	q.Add("per_page", "100")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "Bearer "+c.config.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Log para debug se a resposta não for sucesso
	if resp.StatusCode != 200 {
		fmt.Printf("[Cloudflare REST] Status: %d, Response: %s\n", resp.StatusCode, string(body))
	}

	var restResp CloudflareSecurityEventsResponse
	if err := json.Unmarshal(body, &restResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v (body: %s)", err, string(body[:min(len(body), 200)]))
	}

	if !restResp.Success {
		if len(restResp.Errors) > 0 {
			// Se o endpoint de security/events não existir, tentar firewall/events
			if restResp.Errors[0].Code == 10000 || strings.Contains(restResp.Errors[0].Message, "not found") {
				return c.fetchFirewallEventsRESTLegacy(zoneID, startTime, endTime)
			}
			return nil, fmt.Errorf("API error (code %d): %s", restResp.Errors[0].Code, restResp.Errors[0].Message)
		}
		return nil, fmt.Errorf("API request failed without specific error")
	}

	var events []CloudflareFirewallEvent
	for _, e := range restResp.Result {
		datetime, _ := time.Parse(time.RFC3339, e.OccurredAt)
		events = append(events, CloudflareFirewallEvent{
			RayID:              e.RayID,
			Action:             e.Action,
			ClientIP:           e.ClientIP,
			ClientCountry:      e.ClientCountry,
			ClientASN:          fmt.Sprintf("%d", e.ClientASN),
			ClientASNDesc:      e.ClientASNDesc,
			DateTime:           datetime,
			Host:               e.Host,
			Method:             e.Method,
			URI:                e.URI,
			UserAgent:          e.UserAgent,
			RuleID:             e.RuleID,
			RuleDescription:    e.RuleMessage,
			RulesetID:          e.RulesetID,
			RulesetName:        e.RulesetName,
			Source:             e.Source,
			EdgeResponseStatus: e.EdgeResponseStatus,
		})
	}

	fmt.Printf("[Cloudflare REST] Fetched %d events from zone %s (total available: %d)\n",
		len(events), zoneID, restResp.ResultInfo.TotalCount)

	return events, nil
}

// fetchFirewallEventsRESTLegacy usa o endpoint legado /firewall/events
func (c *CloudflareWAFCollector) fetchFirewallEventsRESTLegacy(zoneID string, startTime, endTime time.Time) ([]CloudflareFirewallEvent, error) {
	// Endpoint legado: GET /zones/{zone_id}/firewall/events
	baseURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/firewall/events", zoneID)

	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("since", startTime.Format(time.RFC3339))
	q.Add("until", endTime.Format(time.RFC3339))
	q.Add("per_page", "100")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "Bearer "+c.config.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("legacy request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		fmt.Printf("[Cloudflare REST Legacy] Status: %d, Response: %s\n", resp.StatusCode, string(body))
		return nil, fmt.Errorf("legacy endpoint returned status %d", resp.StatusCode)
	}

	var restResp CloudflareSecurityEventsResponse
	if err := json.Unmarshal(body, &restResp); err != nil {
		return nil, fmt.Errorf("failed to parse legacy response: %v", err)
	}

	if !restResp.Success && len(restResp.Errors) > 0 {
		return nil, fmt.Errorf("legacy API error: %s", restResp.Errors[0].Message)
	}

	var events []CloudflareFirewallEvent
	for _, e := range restResp.Result {
		datetime, _ := time.Parse(time.RFC3339, e.OccurredAt)
		events = append(events, CloudflareFirewallEvent{
			RayID:              e.RayID,
			Action:             e.Action,
			ClientIP:           e.ClientIP,
			ClientCountry:      e.ClientCountry,
			ClientASN:          fmt.Sprintf("%d", e.ClientASN),
			ClientASNDesc:      e.ClientASNDesc,
			DateTime:           datetime,
			Host:               e.Host,
			Method:             e.Method,
			URI:                e.URI,
			UserAgent:          e.UserAgent,
			RuleID:             e.RuleID,
			RuleDescription:    e.RuleMessage,
			RulesetID:          e.RulesetID,
			RulesetName:        e.RulesetName,
			Source:             e.Source,
			EdgeResponseStatus: e.EdgeResponseStatus,
		})
	}

	fmt.Printf("[Cloudflare REST Legacy] Fetched %d events from zone %s\n", len(events), zoneID)
	return events, nil
}

// fetchFirewallEventsGraphQL busca eventos de firewall via GraphQL
// Usa campos válidos conforme schema oficial da Cloudflare:
// https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-firewall-events/
func (c *CloudflareWAFCollector) fetchFirewallEventsGraphQL(zoneID string, startTime, endTime time.Time) ([]CloudflareFirewallEvent, error) {
	// Campos validados contra o schema GraphQL da Cloudflare:
	// - clientCountryName (NÃO clientCountry)
	// - NÃO existe campo "description" em firewallEventsAdaptive
	// - clientAsn retorna como string
	query := fmt.Sprintf(`{
		"query": "query { viewer { zones(filter: {zoneTag: \"%s\"}) { firewallEventsAdaptive(filter: {datetime_gt: \"%s\", datetime_lt: \"%s\"}, limit: 1000, orderBy: [datetime_DESC]) { rayName action clientIP clientCountryName clientAsn clientASNDescription datetime clientRequestHTTPHost clientRequestHTTPMethodName clientRequestPath clientRequestQuery userAgent ruleId rulesetId source edgeResponseStatus } } } }"
	}`, zoneID, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))

	fmt.Printf("[Cloudflare GraphQL] Querying zone %s from %s to %s\n", zoneID, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))

	req, err := http.NewRequest("POST", "https://api.cloudflare.com/client/v4/graphql", strings.NewReader(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.config.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		fmt.Printf("[Cloudflare GraphQL] HTTP Status: %d, Response: %s\n", resp.StatusCode, string(body[:min(len(body), 500)]))
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	var graphResp CloudflareGraphQLResponse
	if err := json.Unmarshal(body, &graphResp); err != nil {
		fmt.Printf("[Cloudflare GraphQL] Failed to parse response: %s\n", string(body[:min(len(body), 500)]))
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if len(graphResp.Errors) > 0 {
		fmt.Printf("[Cloudflare GraphQL] API error: %s\n", graphResp.Errors[0].Message)
		return nil, fmt.Errorf("graphql error: %s", graphResp.Errors[0].Message)
	}

	var events []CloudflareFirewallEvent
	for _, zone := range graphResp.Data.Viewer.Zones {
		for _, e := range zone.FirewallEventsAdaptive {
			datetime, _ := time.Parse(time.RFC3339, e.Datetime)
			events = append(events, CloudflareFirewallEvent{
				RayID:              e.RayName,
				Action:             e.Action,
				ClientIP:           e.ClientIP,
				ClientCountry:      e.ClientCountryName,
				ClientASN:          e.ClientAsn,
				ClientASNDesc:      e.ClientASNDescription,
				DateTime:           datetime,
				Host:               e.ClientRequestHTTPHost,
				Method:             e.ClientRequestHTTPMethodName,
				URI:                e.ClientRequestPath,
				UserAgent:          e.UserAgent,
				RuleID:             e.RuleId,
				RulesetID:          e.RulesetId,
				Source:             e.Source,
				EdgeResponseStatus: e.EdgeResponseStatus,
			})
		}
	}

	fmt.Printf("[Cloudflare GraphQL] Fetched %d events from zone %s\n", len(events), zoneID)
	return events, nil
}

// indexEvent indexa um evento no OpenSearch
func (c *CloudflareWAFCollector) indexEvent(event CloudflareFirewallEvent, zoneID string) error {
	if c.opensearchClient == nil {
		return fmt.Errorf("opensearch client not available")
	}

	// Mapear ação para severidade
	severity := c.mapActionToSeverity(event.Action)

	// Mapear para MITRE ATT&CK
	mitreTactic, mitreTechnique := c.mapToMitre(event)

	doc := map[string]interface{}{
		"ray_id":               event.RayID,
		"action":               event.Action,
		"client_ip":            event.ClientIP,
		"client_country":       event.ClientCountry,
		"client_asn":           event.ClientASN,
		"client_asn_desc":      event.ClientASNDesc,
		"timestamp":            event.DateTime.Format(time.RFC3339),
		"host":                 event.Host,
		"method":               event.Method,
		"uri":                  event.URI,
		"user_agent":           event.UserAgent,
		"rule_id":              event.RuleID,
		"rule_description":     event.RuleDescription,
		"ruleset_id":           event.RulesetID,
		"ruleset_name":         event.RulesetName,
		"service":              event.Service,
		"source":               event.Source,
		"edge_response_status": event.EdgeResponseStatus,
		"zone_id":              zoneID,
		"severity":             severity,
		"mitre_tactic":         mitreTactic,
		"mitre_technique":      mitreTechnique,
	}

	docJSON, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	// Usar ray_id como document ID para evitar duplicatas
	req := opensearchapi.IndexRequest{
		Index:      "siem-cloudflare-waf",
		DocumentID: event.RayID,
		Body:       strings.NewReader(string(docJSON)),
	}

	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

// mapActionToSeverity mapeia ação do Cloudflare para severidade
func (c *CloudflareWAFCollector) mapActionToSeverity(action string) string {
	switch strings.ToLower(action) {
	case "block", "drop":
		return "HIGH"
	case "challenge", "js_challenge", "managed_challenge":
		return "MEDIUM"
	case "log", "allow":
		return "LOW"
	default:
		return "INFO"
	}
}

// indexCloudflareAlert cria um alerta no índice siem-alerts para eventos CloudFlare
func (c *CloudflareWAFCollector) indexCloudflareAlert(event CloudflareFirewallEvent, zoneID string) error {
	if c.opensearchClient == nil {
		return fmt.Errorf("opensearch client not available")
	}

	severity := c.mapActionToSeverity(event.Action)
	mitreTactic, mitreTechnique := c.mapToMitre(event)

	// Gerar nome do alerta baseado na regra
	alertName := event.RuleDescription
	if alertName == "" {
		alertName = fmt.Sprintf("CloudFlare WAF: %s from %s", event.Action, event.ClientIP)
	}

	alert := map[string]interface{}{
		"id":             fmt.Sprintf("alert-cf-%s", event.RayID),
		"name":           alertName,
		"description":    fmt.Sprintf("CloudFlare WAF detectou atividade suspeita. Ação: %s, Origem: %s (%s), URI: %s%s, User-Agent: %s", event.Action, event.ClientIP, event.ClientCountry, event.Host, event.URI, event.UserAgent),
		"source":         "cloudflare",
		"source_id":      event.RayID,
		"severity":       severity,
		"status":         "new",
		"category":       "web-attack",
		"resource_id":    event.Host,
		"resource_type":  "web-application",
		"region":         event.ClientCountry,
		"account_id":     zoneID,
		"created_at":     event.DateTime.Format(time.RFC3339),
		"updated_at":     time.Now().Format(time.RFC3339),
		"detected_at":    event.DateTime.Format(time.RFC3339),
		"recommendation": fmt.Sprintf("Revisar logs do CloudFlare para o Ray ID %s. Verificar se o IP %s é legítimo. Considerar adicionar à blocklist se for tráfego malicioso recorrente.", event.RayID, event.ClientIP),
		"tags":           []string{"cloudflare", "waf", event.Action, mitreTactic},
		"raw_data": map[string]interface{}{
			"ray_id":           event.RayID,
			"action":           event.Action,
			"client_ip":        event.ClientIP,
			"client_country":   event.ClientCountry,
			"client_asn":       event.ClientASN,
			"host":             event.Host,
			"method":           event.Method,
			"uri":              event.URI,
			"user_agent":       event.UserAgent,
			"rule_id":          event.RuleID,
			"rule_description": event.RuleDescription,
			"mitre_tactic":     mitreTactic,
			"mitre_technique":  mitreTechnique,
		},
	}

	alertJSON, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	req := opensearchapi.IndexRequest{
		Index:      "siem-alerts",
		DocumentID: alert["id"].(string),
		Body:       strings.NewReader(string(alertJSON)),
	}

	res, err := req.Do(context.Background(), c.opensearchClient)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

// mapToMitre mapeia evento para MITRE ATT&CK
func (c *CloudflareWAFCollector) mapToMitre(event CloudflareFirewallEvent) (string, string) {
	uri := strings.ToLower(event.URI)
	desc := strings.ToLower(event.RuleDescription)

	// SQL Injection
	if strings.Contains(desc, "sql") || strings.Contains(uri, "select") || strings.Contains(uri, "union") {
		return "Initial Access", "T1190 - Exploit Public-Facing Application"
	}

	// XSS
	if strings.Contains(desc, "xss") || strings.Contains(desc, "cross-site") || strings.Contains(uri, "<script") {
		return "Initial Access", "T1189 - Drive-by Compromise"
	}

	// Command Injection
	if strings.Contains(desc, "command") || strings.Contains(desc, "rce") || strings.Contains(uri, "cmd=") {
		return "Execution", "T1059 - Command and Scripting Interpreter"
	}

	// Path Traversal / LFI
	if strings.Contains(uri, "../") || strings.Contains(desc, "traversal") || strings.Contains(desc, "lfi") {
		return "Collection", "T1005 - Data from Local System"
	}

	// Brute Force / Rate Limiting
	if strings.Contains(desc, "rate") || strings.Contains(desc, "brute") {
		return "Credential Access", "T1110 - Brute Force"
	}

	// Bot / Scanner
	if strings.Contains(desc, "bot") || strings.Contains(desc, "scanner") || strings.Contains(desc, "crawler") {
		return "Reconnaissance", "T1595 - Active Scanning"
	}

	// DDoS
	if strings.Contains(desc, "ddos") || strings.Contains(desc, "flood") {
		return "Impact", "T1499 - Endpoint Denial of Service"
	}

	return "Unknown", "Unknown"
}

// ============== HTTP Handlers ==============

// handleCloudflareStatus retorna o status da integração
func (s *APIServer) handleCloudflareStatus(c *gin.Context) {
	if cloudflareCollector == nil {
		c.JSON(http.StatusOK, gin.H{
			"configured": false,
			"enabled":    false,
			"message":    "Cloudflare integration not initialized",
		})
		return
	}

	cloudflareCollector.mu.RLock()
	defer cloudflareCollector.mu.RUnlock()

	// Buscar estatísticas do OpenSearch
	stats := s.getCloudflareStats()

	// Buscar contagem real de documentos no OpenSearch
	totalIndexed := s.getCloudflareIndexCount()

	c.JSON(http.StatusOK, gin.H{
		"configured":       cloudflareCollector.config.APIToken != "",
		"enabled":          cloudflareCollector.config.Enabled,
		"running":          cloudflareCollector.running,
		"last_sync":        cloudflareCollector.lastSync,
		"events_collected": totalIndexed,
		"sync_period":      cloudflareCollector.config.SyncPeriod,
		"zone_count":       len(cloudflareCollector.config.ZoneIDs),
		"api_method":       "GraphQL (com fallback para REST)",
		"stats":            stats,
	})
}

// getCloudflareIndexCount retorna a contagem total real de documentos no índice
func (s *APIServer) getCloudflareIndexCount() int64 {
	if s.opensearch == nil {
		return 0
	}
	countQuery := `{"query": {"match_all": {}}}`
	req := opensearchapi.CountRequest{
		Index: []string{"siem-cloudflare-waf"},
		Body:  strings.NewReader(countQuery),
	}
	res, err := req.Do(context.Background(), s.opensearch)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return 0
	}
	if count, ok := result["count"].(float64); ok {
		return int64(count)
	}
	return 0
}

// handleCloudflareConfig retorna/atualiza a configuração
func (s *APIServer) handleCloudflareConfig(c *gin.Context) {
	if c.Request.Method == "GET" {
		if cloudflareCollector == nil {
			c.JSON(http.StatusOK, CloudflareConfig{})
			return
		}

		cloudflareCollector.mu.RLock()
		config := cloudflareCollector.config
		cloudflareCollector.mu.RUnlock()

		// Não retornar o token completo por segurança
		maskedConfig := gin.H{
			"api_token_configured": config.APIToken != "",
			"account_id":           config.AccountID,
			"zone_ids":             config.ZoneIDs,
			"enabled":              config.Enabled,
			"sync_period_minutes":  config.SyncPeriod,
		}

		c.JSON(http.StatusOK, maskedConfig)
		return
	}

	// POST - Atualizar configuração
	var newConfig CloudflareConfig
	if err := c.ShouldBindJSON(&newConfig); err != nil {
		log.Printf("[ERROR] Cloudflare config bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if cloudflareCollector == nil {
		cloudflareCollector = InitCloudflareCollector(s.opensearch)
	}

	cloudflareCollector.mu.Lock()

	// Manter token existente se não fornecido
	if newConfig.APIToken == "" {
		newConfig.APIToken = cloudflareCollector.config.APIToken
	}

	cloudflareCollector.config = newConfig
	cloudflareCollector.mu.Unlock()

	// Salvar no OpenSearch
	if err := cloudflareCollector.saveConfigToOpenSearch(); err != nil {
		fmt.Printf("[Cloudflare] Error saving config: %v\n", err)
	}

	// Iniciar/parar coletor conforme configuração
	if newConfig.Enabled {
		cloudflareCollector.Start()
	} else {
		cloudflareCollector.Stop()
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Configuration updated successfully",
	})
}

// handleCloudflareZones lista as zonas disponíveis
func (s *APIServer) handleCloudflareZones(c *gin.Context) {
	if cloudflareCollector == nil || cloudflareCollector.config.APIToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Cloudflare API token not configured",
		})
		return
	}

	zones, err := cloudflareCollector.listZones()
	if err != nil {
		log.Printf("[ERROR] Cloudflare list zones: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"zones": zones,
	})
}

// handleCloudflareSync força uma sincronização
func (s *APIServer) handleCloudflareSync(c *gin.Context) {
	if cloudflareCollector == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Cloudflare collector not initialized",
		})
		return
	}

	cloudflareCollector.mu.RLock()
	token := cloudflareCollector.config.APIToken
	cloudflareCollector.mu.RUnlock()

	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "API Token not configured",
		})
		return
	}

	// Executar coleta síncrona para retornar resultado real
	go func() {
		err := cloudflareCollector.collectEvents()
		if err != nil {
			fmt.Printf("[Cloudflare] Sync failed: %v\n", err)
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Sync initiated - check logs for progress",
	})
}

// handleCloudflareEvents lista eventos WAF com paginação
func (s *APIServer) handleCloudflareEvents(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"events":   []interface{}{},
			"total":    0,
			"page":     0,
			"per_page": 500,
		})
		return
	}

	// Parâmetros de paginação
	page := 0
	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v >= 0 {
			page = v
		}
	}

	perPage := 500
	if l := c.Query("per_page"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			perPage = v
		}
	}

	from := page * perPage

	// Parâmetros de filtro
	severity := c.Query("severity")
	action := c.Query("action")
	country := c.Query("country")
	host := c.Query("host")
	search := c.Query("search")

	// Construir query
	must := []map[string]interface{}{}

	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"severity": severity},
		})
	}

	if action != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"action": action},
		})
	}

	if country != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"client_country": country},
		})
	}

	if host != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"host": host},
		})
	}

	if search != "" {
		must = append(must, map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  search,
				"fields": []string{"client_ip", "host", "uri", "user_agent", "rule_id", "rule_description", "ray_id"},
				"type":   "phrase_prefix",
			},
		})
	}

	var queryBody map[string]interface{}
	if len(must) > 0 {
		queryBody = map[string]interface{}{
			"from":             from,
			"size":             perPage,
			"track_total_hits": true,
			"sort": []map[string]interface{}{
				{"timestamp": "desc"},
			},
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": must,
				},
			},
		}
	} else {
		queryBody = map[string]interface{}{
			"from":             from,
			"size":             perPage,
			"track_total_hits": true,
			"sort": []map[string]interface{}{
				{"timestamp": "desc"},
			},
			"query": map[string]interface{}{
				"match_all": map[string]interface{}{},
			},
		}
	}

	queryJSON, _ := json.Marshal(queryBody)

	req := opensearchapi.SearchRequest{
		Index: []string{"siem-cloudflare-waf"},
		Body:  strings.NewReader(string(queryJSON)),
	}

	res, err := req.Do(context.Background(), s.opensearch)
	if err != nil {
		log.Printf("[ERROR] Cloudflare events search: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		log.Printf("[ERROR] Cloudflare events decode: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	events := []map[string]interface{}{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalHits, ok := hits["total"].(map[string]interface{}); ok {
			if value, ok := totalHits["value"].(float64); ok {
				total = int(value)
			}
		}

		if hitList, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitList {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"].(map[string]interface{}); ok {
						// Incluir _id do documento
						if docID, ok := hitMap["_id"].(string); ok {
							source["_id"] = docID
						}
						events = append(events, source)
					}
				}
			}
		}
	}

	totalPages := (total + perPage - 1) / perPage

	c.JSON(http.StatusOK, gin.H{
		"events":      events,
		"total":       total,
		"page":        page,
		"per_page":    perPage,
		"total_pages": totalPages,
	})
}

// handleCloudflareStats retorna estatísticas
func (s *APIServer) handleCloudflareStats(c *gin.Context) {
	stats := s.getCloudflareStats()
	c.JSON(http.StatusOK, stats)
}

// getCloudflareStats busca estatísticas do OpenSearch
func (s *APIServer) getCloudflareStats() map[string]interface{} {
	if s.opensearch == nil {
		return map[string]interface{}{
			"total_events": 0,
			"blocked":      0,
			"challenged":   0,
			"by_country":   []interface{}{},
			"by_action":    []interface{}{},
			"by_severity":  []interface{}{},
			"top_ips":      []interface{}{},
			"top_rules":    []interface{}{},
		}
	}

	// Agregações - track_total_hits garante contagem exata acima de 10.000
	query := map[string]interface{}{
		"size":             0,
		"track_total_hits": true,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"gte": "now-24h",
				},
			},
		},
		"aggs": map[string]interface{}{
			"by_action": map[string]interface{}{
				"terms": map[string]interface{}{"field": "action", "size": 20},
			},
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{"field": "severity", "size": 10},
			},
			"by_country": map[string]interface{}{
				"terms": map[string]interface{}{"field": "client_country", "size": 20},
			},
			"top_ips": map[string]interface{}{
				"terms": map[string]interface{}{"field": "client_ip", "size": 15},
			},
			"top_rules": map[string]interface{}{
				"terms": map[string]interface{}{"field": "rule_id", "size": 15},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	req := opensearchapi.SearchRequest{
		Index: []string{"siem-cloudflare-waf"},
		Body:  strings.NewReader(string(queryJSON)),
	}

	res, err := req.Do(context.Background(), s.opensearch)
	if err != nil {
		log.Printf("[ERROR] Cloudflare stats search: %v", err)
		return map[string]interface{}{"error": "Internal server error"}
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		log.Printf("[ERROR] Cloudflare stats decode: %v", err)
		return map[string]interface{}{"error": "Internal server error"}
	}

	stats := map[string]interface{}{
		"total_events": 0,
		"blocked":      0,
		"challenged":   0,
		"by_country":   []interface{}{},
		"by_action":    []interface{}{},
		"by_severity":  []interface{}{},
		"top_ips":      []interface{}{},
		"top_rules":    []interface{}{},
	}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			if value, ok := total["value"].(float64); ok {
				stats["total_events"] = int(value)
			}
		}
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if byAction, ok := aggs["by_action"].(map[string]interface{}); ok {
			if buckets, ok := byAction["buckets"].([]interface{}); ok {
				stats["by_action"] = buckets
				for _, b := range buckets {
					if bucket, ok := b.(map[string]interface{}); ok {
						key := bucket["key"].(string)
						count := int(bucket["doc_count"].(float64))
						if key == "block" || key == "drop" {
							stats["blocked"] = stats["blocked"].(int) + count
						} else if strings.Contains(key, "challenge") {
							stats["challenged"] = stats["challenged"].(int) + count
						}
					}
				}
			}
		}

		if bySeverity, ok := aggs["by_severity"].(map[string]interface{}); ok {
			if buckets, ok := bySeverity["buckets"].([]interface{}); ok {
				stats["by_severity"] = buckets
			}
		}

		if byCountry, ok := aggs["by_country"].(map[string]interface{}); ok {
			if buckets, ok := byCountry["buckets"].([]interface{}); ok {
				stats["by_country"] = buckets
			}
		}

		if topIPs, ok := aggs["top_ips"].(map[string]interface{}); ok {
			if buckets, ok := topIPs["buckets"].([]interface{}); ok {
				stats["top_ips"] = buckets
			}
		}

		if topRules, ok := aggs["top_rules"].(map[string]interface{}); ok {
			if buckets, ok := topRules["buckets"].([]interface{}); ok {
				stats["top_rules"] = buckets
			}
		}
	}

	return stats
}

// handleCloudflareTest testa a conexão com a API
func (s *APIServer) handleCloudflareTest(c *gin.Context) {
	var req struct {
		APIToken string `json:"api_token"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] Cloudflare test bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	token := req.APIToken
	if token == "" && cloudflareCollector != nil {
		cloudflareCollector.mu.RLock()
		token = cloudflareCollector.config.APIToken
		cloudflareCollector.mu.RUnlock()
	}

	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "API token not provided",
		})
		return
	}

	// Testar conexão listando zonas
	httpReq, _ := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones?per_page=1", nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("[ERROR] Cloudflare test connection: %v", err)
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "Connection error",
		})
		return
	}
	defer resp.Body.Close()

	var result CloudflareZonesResponse
	json.NewDecoder(resp.Body).Decode(&result)

	if !result.Success {
		errMsg := "Unknown error"
		if len(result.Errors) > 0 {
			errMsg = result.Errors[0].Message
		}
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   errMsg,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"zone_count": len(result.Result),
		"message":    fmt.Sprintf("Connection successful! Found %d zones", len(result.Result)),
	})
}

// handleCloudflareDiagnostic executa diagnóstico completo testando todas as APIs
func (s *APIServer) handleCloudflareDiagnostic(c *gin.Context) {
	if cloudflareCollector == nil || cloudflareCollector.config.APIToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Cloudflare API token not configured",
		})
		return
	}

	cloudflareCollector.mu.RLock()
	token := cloudflareCollector.config.APIToken
	zoneIDs := cloudflareCollector.config.ZoneIDs
	cloudflareCollector.mu.RUnlock()

	diagnostic := gin.H{
		"timestamp":   time.Now().Format(time.RFC3339),
		"tests":       []map[string]interface{}{},
		"summary":     "",
		"recommended": "",
	}

	tests := []map[string]interface{}{}

	// Teste 1: Listar zonas
	zones, err := cloudflareCollector.listZones()
	zonesTest := map[string]interface{}{
		"name":     "List Zones (REST API v4)",
		"endpoint": "/zones",
		"success":  err == nil,
	}
	if err != nil {
		log.Printf("[ERROR] Cloudflare diagnostic list zones: %v", err)
		zonesTest["error"] = "Service unavailable"
	} else {
		zonesTest["zones_found"] = len(zones)
		zonesTest["zones"] = zones
		// Se não temos zone IDs configurados, usar os encontrados
		if len(zoneIDs) == 0 || (len(zoneIDs) == 1 && zoneIDs[0] == "") {
			for _, z := range zones {
				zoneIDs = append(zoneIDs, z.ID)
			}
		}
	}
	tests = append(tests, zonesTest)

	// Usar primeira zona para testes de eventos
	testZoneID := ""
	testZoneName := ""
	if len(zoneIDs) > 0 && zoneIDs[0] != "" {
		testZoneID = zoneIDs[0]
		for _, z := range zones {
			if z.ID == testZoneID {
				testZoneName = z.Name
				break
			}
		}
	}

	if testZoneID == "" {
		diagnostic["tests"] = tests
		diagnostic["summary"] = "Nenhuma zona encontrada para testar coleta de eventos"
		c.JSON(http.StatusOK, diagnostic)
		return
	}

	// Período de teste: última hora
	endTime := time.Now().UTC()
	startTime := endTime.Add(-1 * time.Hour)

	// Teste 2: Security Events REST API (novo)
	restURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/security/events", testZoneID)
	req, _ := http.NewRequest("GET", restURL, nil)
	q := req.URL.Query()
	q.Add("since", startTime.Format(time.RFC3339))
	q.Add("until", endTime.Format(time.RFC3339))
	q.Add("per_page", "5")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)

	restTest := map[string]interface{}{
		"name":      "Security Events REST API",
		"endpoint":  fmt.Sprintf("/zones/%s/security/events", testZoneID),
		"zone_id":   testZoneID,
		"zone_name": testZoneName,
	}

	if err != nil {
		log.Printf("[ERROR] Cloudflare diagnostic Security Events REST: %v", err)
		restTest["success"] = false
		restTest["error"] = "Connection error"
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		restTest["http_status"] = resp.StatusCode

		var restResp CloudflareSecurityEventsResponse
		if json.Unmarshal(body, &restResp) == nil {
			restTest["success"] = restResp.Success
			if restResp.Success {
				restTest["events_returned"] = len(restResp.Result)
				restTest["total_available"] = restResp.ResultInfo.TotalCount
			} else if len(restResp.Errors) > 0 {
				restTest["error_code"] = restResp.Errors[0].Code
				restTest["error"] = restResp.Errors[0].Message
			}
		} else {
			restTest["success"] = false
			restTest["error"] = "Failed to parse response"
			restTest["raw_response"] = string(body[:min(len(body), 500)])
		}
	}
	tests = append(tests, restTest)

	// Teste 3: Firewall Events REST API (legado)
	legacyURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/firewall/events", testZoneID)
	req2, _ := http.NewRequest("GET", legacyURL, nil)
	q2 := req2.URL.Query()
	q2.Add("since", startTime.Format(time.RFC3339))
	q2.Add("until", endTime.Format(time.RFC3339))
	q2.Add("per_page", "5")
	req2.URL.RawQuery = q2.Encode()
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := client.Do(req2)

	legacyTest := map[string]interface{}{
		"name":     "Firewall Events REST API (Legacy)",
		"endpoint": fmt.Sprintf("/zones/%s/firewall/events", testZoneID),
		"zone_id":  testZoneID,
	}

	if err != nil {
		log.Printf("[ERROR] Cloudflare diagnostic Firewall Events REST: %v", err)
		legacyTest["success"] = false
		legacyTest["error"] = "Connection error"
	} else {
		body2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()

		legacyTest["http_status"] = resp2.StatusCode

		var legacyResp CloudflareSecurityEventsResponse
		if json.Unmarshal(body2, &legacyResp) == nil {
			legacyTest["success"] = legacyResp.Success
			if legacyResp.Success {
				legacyTest["events_returned"] = len(legacyResp.Result)
				legacyTest["total_available"] = legacyResp.ResultInfo.TotalCount
			} else if len(legacyResp.Errors) > 0 {
				legacyTest["error_code"] = legacyResp.Errors[0].Code
				legacyTest["error"] = legacyResp.Errors[0].Message
			}
		} else {
			legacyTest["success"] = false
			legacyTest["error"] = "Failed to parse response"
		}
	}
	tests = append(tests, legacyTest)

	// Teste 4: GraphQL Analytics API
	graphqlQuery := fmt.Sprintf(`{
		"query": "query { viewer { zones(filter: {zoneTag: \"%s\"}) { firewallEventsAdaptive(filter: {datetime_gt: \"%s\", datetime_lt: \"%s\"}, limit: 5, orderBy: [datetime_DESC]) { rayName action clientIP datetime } } } }"
	}`, testZoneID, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))

	req3, _ := http.NewRequest("POST", "https://api.cloudflare.com/client/v4/graphql", strings.NewReader(graphqlQuery))
	req3.Header.Set("Authorization", "Bearer "+token)
	req3.Header.Set("Content-Type", "application/json")

	resp3, err := client.Do(req3)

	graphqlTest := map[string]interface{}{
		"name":     "GraphQL Analytics API (firewallEventsAdaptive)",
		"endpoint": "/graphql",
		"zone_id":  testZoneID,
	}

	if err != nil {
		log.Printf("[ERROR] Cloudflare diagnostic GraphQL: %v", err)
		graphqlTest["success"] = false
		graphqlTest["error"] = "Connection error"
	} else {
		body3, _ := io.ReadAll(resp3.Body)
		resp3.Body.Close()

		graphqlTest["http_status"] = resp3.StatusCode

		var graphResp CloudflareGraphQLResponse
		if json.Unmarshal(body3, &graphResp) == nil {
			if len(graphResp.Errors) > 0 {
				graphqlTest["success"] = false
				graphqlTest["error"] = graphResp.Errors[0].Message
			} else {
				eventsCount := 0
				for _, zone := range graphResp.Data.Viewer.Zones {
					eventsCount += len(zone.FirewallEventsAdaptive)
				}
				graphqlTest["success"] = true
				graphqlTest["events_returned"] = eventsCount
			}
		} else {
			graphqlTest["success"] = false
			graphqlTest["error"] = "Failed to parse GraphQL response"
		}
	}
	tests = append(tests, graphqlTest)

	// Gerar sumário e recomendação
	graphqlOK := graphqlTest["success"] == true
	restOK := restTest["success"] == true
	legacyOK := legacyTest["success"] == true

	var summary, recommended string

	if graphqlOK {
		summary = "GraphQL Analytics API funcionando corretamente!"
		recommended = "Usando GraphQL API (método primário e mais confiável)"
	} else if restOK || legacyOK {
		summary = "REST API funcionando, mas GraphQL indisponível"
		if restOK {
			recommended = "Usando Security Events REST API como fallback"
		} else {
			recommended = "Usando Firewall Events REST API (legado) como fallback"
		}
	} else {
		summary = "Nenhuma API de eventos está funcionando"
		recommended = "Verifique as permissões do token: precisa de 'Zone:Logs:Read', 'Zone:Analytics:Read', 'Zone:Firewall Services:Read'"
	}

	diagnostic["tests"] = tests
	diagnostic["summary"] = summary
	diagnostic["recommended"] = recommended
	diagnostic["token_permissions_needed"] = []string{
		"Zone:Read (para listar zonas)",
		"Zone:Logs:Read (para logs de eventos)",
		"Zone:Analytics:Read (para GraphQL Analytics - método primário)",
		"Zone:Firewall Services:Read (para eventos de firewall)",
	}

	c.JSON(http.StatusOK, diagnostic)
}
