package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Alert struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Query         string                 `json:"query"`
	Condition     map[string]interface{} `json:"condition"`
	Severity      string                 `json:"severity"`
	Status        string                 `json:"status"`
	Source        string                 `json:"source"`        // Origem: guardduty, securityhub, inspector, cloudtrail, cloudflare, manual
	SourceID      string                 `json:"source_id"`     // ID do finding original
	Category      string                 `json:"category"`      // Categoria do alerta
	ResourceID    string                 `json:"resource_id"`   // ID do recurso afetado
	ResourceType  string                 `json:"resource_type"` // Tipo do recurso afetado
	Region        string                 `json:"region"`        // Região AWS
	AccountID     string                 `json:"account_id"`    // ID da conta AWS
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	LastTriggered *time.Time             `json:"last_triggered,omitempty"`
	Actions       []AlertAction          `json:"actions"`
}

type AlertAction struct {
	Type    string                 `json:"type"`
	Config  map[string]interface{} `json:"config"`
	Enabled bool                   `json:"enabled"`
}

// ============================================================================
// ESTRUTURAS DETALHADAS PARA ANALISTAS
// ============================================================================

// AlertDetails contém informações detalhadas de um alerta para análise
type AlertDetails struct {
	// Informações básicas
	Alert

	// === ORIGEM DO LOG ===
	LogSource *LogSourceInfo `json:"log_source"` // Detalhes da origem do log

	// === CONTAGEM DE INCIDÊNCIAS ===
	IncidentCount *IncidentCountInfo `json:"incident_count"` // Estatísticas de ocorrências

	// === RECOMENDAÇÕES ===
	Recommendations []Recommendation `json:"recommendations"` // Recomendações de remediação

	// === CONTEXTO DE SEGURANÇA ===
	SecurityContext *SecurityContext `json:"security_context"` // Contexto adicional de segurança

	// === ATIVOS AFETADOS ===
	AffectedAssets []AffectedAsset `json:"affected_assets"` // Lista de ativos afetados

	// === EVIDÊNCIAS ===
	Evidence []AlertEvidence `json:"evidence"` // Evidências coletadas

	// === HISTÓRICO ===
	Timeline []TimelineEntry `json:"timeline"` // Linha do tempo do alerta

	// === AÇÕES SUGERIDAS ===
	SuggestedActions []SuggestedAction `json:"suggested_actions"` // Ações sugeridas para o analista

	// === CASO RELACIONADO ===
	RelatedCase *RelatedCaseInfo `json:"related_case,omitempty"` // Caso vinculado (se existir)
}

// LogSourceInfo detalha a origem do log que gerou o alerta
type LogSourceInfo struct {
	Service      string    `json:"service"`        // Serviço que gerou (GuardDuty, CloudTrail, etc.)
	Type         string    `json:"type"`           // Tipo de log (api_call, network_activity, etc.)
	LogGroup     string    `json:"log_group"`      // Grupo de log (CloudWatch Log Group)
	LogStream    string    `json:"log_stream"`     // Stream de log específico
	EventSource  string    `json:"event_source"`   // Fonte do evento (ec2.amazonaws.com, etc.)
	EventName    string    `json:"event_name"`     // Nome do evento (DescribeInstances, etc.)
	EventTime    time.Time `json:"event_time"`     // Quando o evento ocorreu
	SourceIP     string    `json:"source_ip"`      // IP de origem do evento
	UserAgent    string    `json:"user_agent"`     // User agent (se disponível)
	RequestID    string    `json:"request_id"`     // ID da requisição original
	Region       string    `json:"region"`         // Região onde ocorreu
	AccountID    string    `json:"account_id"`     // Conta AWS
	RawLogSample string    `json:"raw_log_sample"` // Amostra do log original (truncado)
}

// IncidentCountInfo estatísticas de ocorrências do alerta
type IncidentCountInfo struct {
	Total           int       `json:"total"`            // Total de vezes que o alerta foi disparado
	Last24Hours     int       `json:"last_24h"`         // Nas últimas 24 horas
	Last7Days       int       `json:"last_7d"`          // Nos últimos 7 dias
	Last30Days      int       `json:"last_30d"`         // Nos últimos 30 dias
	FirstSeen       time.Time `json:"first_seen"`       // Primeira vez que foi visto
	LastSeen        time.Time `json:"last_seen"`        // Última vez que foi visto
	Trend           string    `json:"trend"`            // increasing, decreasing, stable
	TrendPercentage float64   `json:"trend_percentage"` // Variação percentual
	UniqueResources int       `json:"unique_resources"` // Recursos únicos afetados
	UniqueAccounts  int       `json:"unique_accounts"`  // Contas únicas afetadas
	UniqueRegions   int       `json:"unique_regions"`   // Regiões únicas afetadas
}

// Recommendation recomendação de remediação
type Recommendation struct {
	Priority    int      `json:"priority"`    // 1 = mais urgente
	Title       string   `json:"title"`       // Título da recomendação
	Description string   `json:"description"` // Descrição detalhada
	Action      string   `json:"action"`      // Ação específica a tomar
	Impact      string   `json:"impact"`      // Impacto esperado
	Effort      string   `json:"effort"`      // low, medium, high
	Type        string   `json:"type"`        // immediate, short_term, long_term
	AWSDoc      string   `json:"aws_doc"`     // Link para documentação AWS
	References  []string `json:"references"`  // Links de referência adicionais
	Automated   bool     `json:"automated"`   // Se pode ser automatizado
	PlaybookID  string   `json:"playbook_id"` // ID do playbook (se houver)
}

// SecurityContext contexto de segurança adicional
type SecurityContext struct {
	// MITRE ATT&CK
	MITRETactics    []string `json:"mitre_tactics"`    // Táticas MITRE
	MITRETechniques []string `json:"mitre_techniques"` // Técnicas MITRE
	MITREGroups     []string `json:"mitre_groups"`     // Grupos de ameaça conhecidos

	// Threat Intelligence
	ThreatIntel *ThreatIntelContext `json:"threat_intel,omitempty"` // Informações de TI

	// CVE relacionados
	RelatedCVEs []CVEContext `json:"related_cves,omitempty"` // CVEs relacionados

	// Risco
	RiskScore          int      `json:"risk_score"`          // Score de risco (0-100)
	RiskFactors        []string `json:"risk_factors"`        // Fatores que contribuem para o risco
	BusinessImpact     string   `json:"business_impact"`     // Impacto no negócio
	DataClassification string   `json:"data_classification"` // Classificação de dados afetados

	// Compliance
	ComplianceFrameworks []string `json:"compliance_frameworks"` // Frameworks afetados (PCI-DSS, HIPAA, etc.)
	ComplianceControls   []string `json:"compliance_controls"`   // Controles específicos
}

// ThreatIntelContext contexto de threat intelligence
type ThreatIntelContext struct {
	IOCs         []AlertIOCMatch `json:"iocs"`          // IOCs correspondentes
	ThreatActors []string        `json:"threat_actors"` // Atores de ameaça conhecidos
	Campaigns    []string        `json:"campaigns"`     // Campanhas conhecidas
	Malware      []string        `json:"malware"`       // Malware associado
	Confidence   int             `json:"confidence"`    // Confiança (0-100)
	Sources      []string        `json:"sources"`       // Fontes de TI
}

// AlertIOCMatch IOC correspondente encontrado no alerta
type AlertIOCMatch struct {
	Type       string `json:"type"`        // ip, domain, hash, url
	Value      string `json:"value"`       // Valor do IOC
	ThreatType string `json:"threat_type"` // Tipo de ameaça
	Severity   string `json:"severity"`    // Severidade
	Source     string `json:"source"`      // Fonte que identificou
}

// CVEContext contexto de CVE relacionado
type CVEContext struct {
	CVEID       string  `json:"cve_id"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Published   string  `json:"published"`
	Exploited   bool    `json:"exploited"`
}

// AffectedAsset ativo afetado pelo alerta
type AffectedAsset struct {
	ResourceID   string            `json:"resource_id"`   // ID do recurso
	ResourceType string            `json:"resource_type"` // Tipo (EC2, S3, IAM, etc.)
	ResourceName string            `json:"resource_name"` // Nome do recurso
	Region       string            `json:"region"`        // Região
	AccountID    string            `json:"account_id"`    // Conta AWS
	Tags         map[string]string `json:"tags"`          // Tags do recurso
	Owner        string            `json:"owner"`         // Proprietário
	Environment  string            `json:"environment"`   // prod, staging, dev
	Criticality  string            `json:"criticality"`   // Criticidade do ativo
	IPAddress    string            `json:"ip_address"`    // IP (se aplicável)
	VpcID        string            `json:"vpc_id"`        // VPC (se aplicável)
	SubnetID     string            `json:"subnet_id"`     // Subnet (se aplicável)
}

// AlertEvidence evidência coletada
type AlertEvidence struct {
	Type        string    `json:"type"`        // log, screenshot, packet, file
	Description string    `json:"description"` // Descrição
	Timestamp   time.Time `json:"timestamp"`   // Quando foi coletada
	Source      string    `json:"source"`      // Fonte
	Data        string    `json:"data"`        // Dados (pode ser truncado)
	Hash        string    `json:"hash"`        // Hash do dado completo
	Size        int64     `json:"size"`        // Tamanho em bytes
	Preserved   bool      `json:"preserved"`   // Se foi preservado para forense
}

// TimelineEntry entrada na linha do tempo
type TimelineEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Event       string                 `json:"event"`             // Tipo de evento
	Description string                 `json:"description"`       // Descrição
	User        string                 `json:"user"`              // Usuário responsável (se aplicável)
	Source      string                 `json:"source"`            // Fonte da informação
	Details     map[string]interface{} `json:"details,omitempty"` // Detalhes adicionais
}

// SuggestedAction ação sugerida para o analista
type SuggestedAction struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Type          string `json:"type"`           // investigate, contain, remediate, escalate
	Priority      int    `json:"priority"`       // 1 = mais urgente
	Automated     bool   `json:"automated"`      // Se pode ser executado automaticamente
	PlaybookID    string `json:"playbook_id"`    // ID do playbook associado
	EstimatedTime string `json:"estimated_time"` // Tempo estimado
	RequiredRole  string `json:"required_role"`  // Nível de acesso necessário
}

// RelatedCaseInfo informações do caso relacionado
type RelatedCaseInfo struct {
	CaseID     string    `json:"case_id"`
	CaseTitle  string    `json:"case_title"`
	CaseStatus string    `json:"case_status"`
	AssignedTo string    `json:"assigned_to"`
	CreatedAt  time.Time `json:"created_at"`
	LinkedAt   time.Time `json:"linked_at"`
}

func (s *APIServer) handleListAlerts(c *gin.Context) {
	pageSize := 20
	if size := c.Query("page_size"); size != "" {
		if parsedSize, err := strconv.Atoi(size); err == nil && parsedSize > 0 {
			pageSize = parsedSize
		}
	}

	pageNumber := 1
	if page := c.Query("page"); page != "" {
		if parsedPage, err := strconv.Atoi(page); err == nil && parsedPage > 0 {
			pageNumber = parsedPage
		}
	}

	severity := c.Query("severity")
	status := c.Query("status")
	source := c.Query("source") // Filtro por origem: guardduty, securityhub, inspector, cloudtrail, cloudflare
	search := c.Query("search") // Busca por texto (CVE, nome, descrição)

	// Tentar buscar do Elasticsearch
	if s.opensearch != nil {
		alerts, total, err := s.fetchAlertsFromES(c, pageSize, pageNumber, severity, status, source, search, getAccessScope(c))
		if err == nil {
			totalPages := (total + pageSize - 1) / pageSize
			c.JSON(http.StatusOK, gin.H{
				"alerts":      alerts,
				"total":       total,
				"page":        pageNumber,
				"page_size":   pageSize,
				"total_pages": totalPages,
				"source":      "opensearch",
			})
			return
		}
		// Se falhar e mock desabilitado, retornar vazio
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"alerts":      []interface{}{},
				"total":       0,
				"page":        pageNumber,
				"page_size":   pageSize,
				"total_pages": 0,
				"source":      "none",
				"message":     "OpenSearch query failed. No real data available.",
			})
			return
		}
	}

	// Se mock desabilitado e não há OpenSearch, retornar vazio
	if IsMockDataDisabled() {
		c.JSON(http.StatusOK, gin.H{
			"alerts":      []interface{}{},
			"total":       0,
			"page":        pageNumber,
			"page_size":   pageSize,
			"total_pages": 0,
			"source":      "none",
			"message":     "No data source connected.",
		})
		return
	}

	// Fallback: Gerar dados mock (apenas se permitido)
	mockAlerts := generateMockAlerts()

	// Aplicar filtros
	filteredAlerts := mockAlerts
	if severity != "" {
		filtered := []Alert{}
		for _, alert := range mockAlerts {
			if alert.Severity == severity {
				filtered = append(filtered, alert)
			}
		}
		filteredAlerts = filtered
	}
	if status != "" {
		filtered := []Alert{}
		for _, alert := range filteredAlerts {
			if alert.Status == status {
				filtered = append(filtered, alert)
			}
		}
		filteredAlerts = filtered
	}

	// Paginação
	total := len(filteredAlerts)
	start := (pageNumber - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	paginatedAlerts := filteredAlerts[start:end]
	totalPages := (total + pageSize - 1) / pageSize

	c.JSON(http.StatusOK, gin.H{
		"alerts":      paginatedAlerts,
		"total":       total,
		"page":        pageNumber,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

func (s *APIServer) fetchAlertsFromES(c *gin.Context, pageSize, pageNumber int, severity, status, source, search string, scope AccessScope) ([]Alert, int, error) {
	query := map[string]interface{}{
		"track_total_hits": true, // Remove 10,000 limit on total count
		"from":             (pageNumber - 1) * pageSize,
		"size":             pageSize,
		"sort": []map[string]interface{}{
			{
				"created_at": map[string]interface{}{
					"order": "desc",
				},
			},
		},
	}

	// Aplicar filtros
	must := []map[string]interface{}{}
	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"severity": strings.ToUpper(severity),
			},
		})
	}
	if status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"status": status,
			},
		})
	}
	if source != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"source": strings.ToLower(source),
			},
		})
	}
	// Busca por texto (CVE, nome, descrição)
	if search != "" {
		// Verificar se é uma busca por CVE (formato: CVE-YYYY-NNNNN)
		searchUpper := strings.ToUpper(strings.TrimSpace(search))
		if strings.HasPrefix(searchUpper, "CVE-") {
			// Busca exata por CVE usando query_string com frase exata
			// O formato "\"CVE-XXXX-XXXXX\"" força match de frase exata
			must = append(must, map[string]interface{}{
				"query_string": map[string]interface{}{
					"query":            "\"" + searchUpper + "\"",
					"fields":           []string{"name", "description", "source_id", "category", "title"},
					"default_operator": "AND",
				},
			})
		} else {
			// Busca geral com fuzzy
			must = append(must, map[string]interface{}{
				"multi_match": map[string]interface{}{
					"query":     search,
					"fields":    []string{"name", "name.keyword", "description", "source_id", "category", "title"},
					"type":      "best_fields",
					"fuzziness": "AUTO",
				},
			})
		}
	}

	accessFilters := buildAlertAccessFilter(scope)
	if len(accessFilters) > 0 {
		must = append(must, accessFilters...)
	}

	// Excluir findings do Inspector - vulnerabilidades devem ser tratadas apenas na seção Vulnerabilidades
	mustNot := []map[string]interface{}{
		{
			"term": map[string]interface{}{
				"source": "inspector",
			},
		},
	}

	boolQuery := map[string]interface{}{
		"must_not": mustNot,
	}
	if len(must) > 0 {
		boolQuery["must"] = must
	}

	query["query"] = map[string]interface{}{
		"bool": boolQuery,
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, 0, err
	}

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(c.Request.Context()),
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, 0, errors.New("elasticsearch error")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, err
	}

	hitsObj, ok := result["hits"].(map[string]interface{})
	if !ok {
		return nil, 0, errors.New("invalid response format")
	}

	totalObj, ok := hitsObj["total"].(map[string]interface{})
	if !ok {
		return nil, 0, errors.New("invalid total format")
	}
	total := int(totalObj["value"].(float64))

	alerts := []Alert{}
	hitsArray, ok := hitsObj["hits"].([]interface{})
	if !ok {
		return alerts, total, nil
	}

	for _, hit := range hitsArray {
		hitMap, ok := hit.(map[string]interface{})
		if !ok {
			continue
		}
		source, ok := hitMap["_source"].(map[string]interface{})
		if !ok {
			continue
		}

		// Map AlertFromAWS fields to Alert fields
		alert := Alert{
			ID:           getStringField(source, "id"),
			Name:         getStringField(source, "name"),
			Description:  getStringField(source, "description"),
			Severity:     getStringField(source, "severity"),
			Status:       getStringField(source, "status"),
			Source:       getStringField(source, "source"),
			SourceID:     getStringField(source, "source_id"),
			Category:     getStringField(source, "category"),
			ResourceID:   getStringField(source, "resource_id"),
			ResourceType: getStringField(source, "resource_type"),
			Region:       getStringField(source, "region"),
			AccountID:    getStringField(source, "account_id"),
		}

		// Parse dates
		if createdStr := getStringField(source, "created_at"); createdStr != "" {
			if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
				alert.CreatedAt = t
			}
		}
		if updatedStr := getStringField(source, "updated_at"); updatedStr != "" {
			if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
				alert.UpdatedAt = t
			}
		}
		if detectedStr := getStringField(source, "detected_at"); detectedStr != "" {
			if t, err := time.Parse(time.RFC3339, detectedStr); err == nil {
				alert.LastTriggered = &t
			}
		}

		// Add additional info to condition (mantém compatibilidade)
		alert.Query = getStringField(source, "source_id")
		alert.Condition = map[string]interface{}{
			"recommendation": getStringField(source, "recommendation"),
		}

		alerts = append(alerts, alert)
	}

	return alerts, total, nil
}

func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ============================================================================
// ALERT TO CASE CONVERSION
// ============================================================================

// handleCreateCaseFromAlert cria um Case a partir de um Alerta
func (s *APIServer) handleCreateCaseFromAlert(c *gin.Context) {
	alertID := c.Param("id")

	var req struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Priority    string `json:"priority"` // low, medium, high, urgent
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Buscar o alerta
	var alert map[string]interface{}
	if s.opensearch != nil {
		res, err := s.opensearch.Get("siem-alerts", alertID)
		if err != nil || res.IsError() {
			c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
			return
		}

		var result map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse alert"})
			return
		}
		res.Body.Close()

		if source, ok := result["_source"].(map[string]interface{}); ok {
			alert = source
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
			return
		}
	} else {
		// Fallback para dados mock
		c.JSON(http.StatusNotImplemented, gin.H{"error": "OpenSearch not available"})
		return
	}

	// Extrair dados do alerta
	severity := strings.ToLower(getStringFromMap(alert, "severity"))
	if severity == "" {
		severity = "medium"
	}

	category := getStringFromMap(alert, "category")
	if category == "" {
		category = "security_incident"
	}

	source := getStringFromMap(alert, "source")
	accountID := getStringFromMap(alert, "account_id") // Account ID para filtro de escopo

	// Fallback: usar account_id do escopo do usuário se o alerta não tiver
	if accountID == "" {
		scope := getAccessScope(c)
		if len(scope.AccountIDs) > 0 {
			accountID = scope.AccountIDs[0]
			log.Printf("📌 Using account_id from user scope for case: %s", accountID)
		}
	}

	tags := []string{source, "auto-created", "from-alert"}

	// Construir título e descrição automaticamente se não fornecidos
	title := req.Title
	if title == "" {
		title = fmt.Sprintf("Incidente: %s", getStringFromMap(alert, "name"))
	}

	description := req.Description
	if description == "" {
		description = fmt.Sprintf(
			"Incidente criado automaticamente a partir do alerta %s.\n\n"+
				"**Alerta Original:**\n"+
				"- Nome: %s\n"+
				"- Origem: %s\n"+
				"- Severidade: %s\n"+
				"- Categoria: %s\n"+
				"- Detectado em: %s\n\n"+
				"**Descrição:**\n%s",
			alertID,
			getStringFromMap(alert, "name"),
			source,
			severity,
			category,
			getStringFromMap(alert, "detected_at"),
			getStringFromMap(alert, "description"),
		)
	}

	priority := req.Priority
	if priority == "" {
		// Mapear severidade para prioridade
		switch severity {
		case "critical":
			priority = "urgent"
		case "high":
			priority = "high"
		case "medium":
			priority = "medium"
		default:
			priority = "low"
		}
	}

	// Calcular SLA baseado na severidade
	var slaHours int
	switch severity {
	case "critical":
		slaHours = 2
	case "high":
		slaHours = 24
	case "medium":
		slaHours = 72
	default:
		slaHours = 168
	}
	slaDeadline := time.Now().Add(time.Duration(slaHours) * time.Hour)

	// Criar o Case
	newCase := Case{
		ID:               uuid.New().String(),
		Title:            title,
		Description:      description,
		Severity:         severity,
		Status:           "new",
		Priority:         priority,
		Category:         category,
		AssignedTo:       "",
		CreatedBy:        "system",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		SLADeadline:      &slaDeadline,
		Tags:             tags,
		RelatedAlerts:    []string{alertID},
		RelatedEvents:    []string{},
		RelatedPlaybooks: []string{},
		AccountID:        accountID, // Propagar account_id do alerta para o caso
		TimeToDetect:     0,
		TimeToRespond:    0,
		TimeToResolve:    0,
		SLABreach:        false,
		SLARemaining:     int(time.Until(slaDeadline).Seconds()),
	}

	// Aplicar workflow padrão (checklist + playbooks)
	applyDefaultCaseWorkflow(&newCase)

	ctx := c.Request.Context()

	// Salvar no OpenSearch
	if s.opensearch != nil {
		caseJSON, err := json.Marshal(newCase)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal case"})
			return
		}

		res, err := s.opensearch.Index(
			"siem-cases",
			strings.NewReader(string(caseJSON)),
			s.opensearch.Index.WithDocumentID(newCase.ID),
			s.opensearch.Index.WithRefresh("true"),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create case"})
			return
		}
		res.Body.Close()
	}

	// Salvar no banco de dados (se disponível)
	if s.caseRepo != nil {
		dbCase, err := convertAPICaseToDB(&newCase)
		if err == nil {
			s.caseRepo.Create(ctx, dbCase)
		}
	}

	// Atualizar status do alerta para "escalated"
	if s.opensearch != nil {
		updateDoc := map[string]interface{}{
			"doc": map[string]interface{}{
				"status":       "escalated",
				"case_id":      newCase.ID,
				"escalated_at": time.Now().Format(time.RFC3339),
				"escalated_by": "system",
			},
		}
		updateJSON, _ := json.Marshal(updateDoc)

		res, err := s.opensearch.Update(
			"siem-alerts",
			alertID,
			strings.NewReader(string(updateJSON)),
			s.opensearch.Update.WithRefresh("true"),
		)
		if err == nil {
			res.Body.Close()
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"case":    newCase,
		"message": "Case criado com sucesso a partir do alerta",
	})
}

// handleUpdateAlertStatus atualiza o status de um alerta
func (s *APIServer) handleUpdateAlertStatus(c *gin.Context) {
	alertID := c.Param("id")

	var req struct {
		Status  string `json:"status" binding:"required"` // pending, investigating, resolved, false_positive, acknowledged, escalated
		Reason  string `json:"reason"`
		Comment string `json:"comment"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Atualizar no OpenSearch
	if s.opensearch != nil {
		updateDoc := map[string]interface{}{
			"doc": map[string]interface{}{
				"status":     req.Status,
				"updated_at": time.Now().Format(time.RFC3339),
				"updated_by": "admin", // TODO: Get from JWT token
			},
		}

		if req.Reason != "" {
			updateDoc["doc"].(map[string]interface{})["status_reason"] = req.Reason
		}
		if req.Comment != "" {
			updateDoc["doc"].(map[string]interface{})["status_comment"] = req.Comment
		}

		updateJSON, _ := json.Marshal(updateDoc)

		res, err := s.opensearch.Update(
			"siem-alerts",
			alertID,
			strings.NewReader(string(updateJSON)),
			s.opensearch.Update.WithRefresh("true"),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update alert"})
			return
		}
		res.Body.Close()

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Alert status updated successfully",
		})
	} else {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "OpenSearch not available"})
	}
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case string:
			return v
		case float64:
			return fmt.Sprintf("%.0f", v)
		case int:
			return fmt.Sprintf("%d", v)
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

func generateMockAlerts() []Alert {
	now := time.Now()
	return []Alert{
		{
			ID:          "alert-1",
			Name:        "Alta Taxa de Login Falhado",
			Description: "Mais de 10 tentativas de login falhadas em 5 minutos detectadas",
			Query:       "event.type:login AND event.outcome:failure",
			Condition: map[string]interface{}{
				"threshold": 10,
				"timeframe": "5m",
				"field":     "event.outcome",
			},
			Severity:      "HIGH",
			Status:        "active",
			CreatedAt:     now.Add(-48 * time.Hour),
			UpdatedAt:     now.Add(-1 * time.Hour),
			LastTriggered: &[]time.Time{now.Add(-30 * time.Minute)}[0],
			Actions: []AlertAction{
				{Type: "email", Config: map[string]interface{}{"to": "security@company.com"}, Enabled: true},
				{Type: "webhook", Config: map[string]interface{}{"url": "https://api.company.com/alerts"}, Enabled: true},
			},
		},
		{
			ID:          "alert-2",
			Name:        "Tráfego Suspeito Detectado",
			Description: "Tráfego anômalo detectado na rede interna",
			Query:       "network.bytes > 1000000 AND network.direction:outbound",
			Condition: map[string]interface{}{
				"threshold": 1000000,
				"timeframe": "1m",
				"field":     "network.bytes",
			},
			Severity:      "MEDIUM",
			Status:        "active",
			CreatedAt:     now.Add(-72 * time.Hour),
			UpdatedAt:     now.Add(-2 * time.Hour),
			LastTriggered: &[]time.Time{now.Add(-15 * time.Minute)}[0],
			Actions: []AlertAction{
				{Type: "email", Config: map[string]interface{}{"to": "noc@company.com"}, Enabled: true},
			},
		},
		{
			ID:          "alert-3",
			Name:        "Acesso Não Autorizado",
			Description: "Tentativa de acesso a recurso protegido sem permissão",
			Query:       "event.type:access AND event.outcome:failure AND resource.sensitivity:high",
			Condition: map[string]interface{}{
				"threshold": 1,
				"timeframe": "1m",
				"field":     "event.outcome",
			},
			Severity:      "CRITICAL",
			Status:        "active",
			CreatedAt:     now.Add(-24 * time.Hour),
			UpdatedAt:     now.Add(-30 * time.Minute),
			LastTriggered: &[]time.Time{now.Add(-45 * time.Minute)}[0],
			Actions: []AlertAction{
				{Type: "email", Config: map[string]interface{}{"to": "security@company.com"}, Enabled: true},
				{Type: "sms", Config: map[string]interface{}{"to": "+5511999999999"}, Enabled: true},
				{Type: "slack", Config: map[string]interface{}{"channel": "#security-alerts"}, Enabled: true},
			},
		},
		{
			ID:          "alert-4",
			Name:        "CPU Alta em Servidor Crítico",
			Description: "Uso de CPU acima de 80% por mais de 10 minutos",
			Query:       "host.name:prod-server-01 AND system.cpu.usage > 0.8",
			Condition: map[string]interface{}{
				"threshold": 0.8,
				"timeframe": "10m",
				"field":     "system.cpu.usage",
			},
			Severity:  "LOW",
			Status:    "inactive",
			CreatedAt: now.Add(-96 * time.Hour),
			UpdatedAt: now.Add(-24 * time.Hour),
			Actions: []AlertAction{
				{Type: "email", Config: map[string]interface{}{"to": "ops@company.com"}, Enabled: true},
			},
		},
		{
			ID:          "alert-5",
			Name:        "Malware Detectado",
			Description: "Arquivo malicioso detectado em endpoint",
			Query:       "event.type:malware AND event.outcome:detected",
			Condition: map[string]interface{}{
				"threshold": 1,
				"timeframe": "1m",
				"field":     "event.outcome",
			},
			Severity:      "CRITICAL",
			Status:        "active",
			CreatedAt:     now.Add(-12 * time.Hour),
			UpdatedAt:     now.Add(-1 * time.Hour),
			LastTriggered: &[]time.Time{now.Add(-20 * time.Minute)}[0],
			Actions: []AlertAction{
				{Type: "email", Config: map[string]interface{}{"to": "security@company.com"}, Enabled: true},
				{Type: "webhook", Config: map[string]interface{}{"url": "https://api.company.com/malware"}, Enabled: true},
			},
		},
		{
			ID:          "alert-6",
			Name:        "Varredura de Portas",
			Description: "Atividade de port scan detectada",
			Query:       "event.type:network AND event.category:intrusion_detection",
			Condition: map[string]interface{}{
				"threshold": 100,
				"timeframe": "1m",
				"field":     "network.packets",
			},
			Severity:      "MEDIUM",
			Status:        "active",
			CreatedAt:     now.Add(-36 * time.Hour),
			UpdatedAt:     now.Add(-3 * time.Hour),
			LastTriggered: &[]time.Time{now.Add(-10 * time.Minute)}[0],
			Actions: []AlertAction{
				{Type: "email", Config: map[string]interface{}{"to": "noc@company.com"}, Enabled: true},
			},
		},
		{
			ID:          "alert-7",
			Name:        "SQL Injection Detectado",
			Description: "Tentativa de SQL injection em aplicação web",
			Query:       "event.type:web AND threat.technique.name:\"SQL Injection\"",
			Condition: map[string]interface{}{
				"threshold": 1,
				"timeframe": "1m",
				"field":     "threat.technique.name",
			},
			Severity:      "HIGH",
			Status:        "active",
			CreatedAt:     now.Add(-60 * time.Hour),
			UpdatedAt:     now.Add(-5 * time.Hour),
			LastTriggered: &[]time.Time{now.Add(-25 * time.Minute)}[0],
			Actions: []AlertAction{
				{Type: "email", Config: map[string]interface{}{"to": "security@company.com"}, Enabled: true},
				{Type: "webhook", Config: map[string]interface{}{"url": "https://waf.company.com/block"}, Enabled: true},
			},
		},
		{
			ID:          "alert-8",
			Name:        "Ransomware Activity",
			Description: "Atividade suspeita de ransomware detectada",
			Query:       "event.type:file AND file.extension:(encrypted OR locked)",
			Condition: map[string]interface{}{
				"threshold": 5,
				"timeframe": "1m",
				"field":     "file.extension",
			},
			Severity:  "CRITICAL",
			Status:    "inactive",
			CreatedAt: now.Add(-120 * time.Hour),
			UpdatedAt: now.Add(-48 * time.Hour),
			Actions: []AlertAction{
				{Type: "email", Config: map[string]interface{}{"to": "security@company.com"}, Enabled: true},
				{Type: "sms", Config: map[string]interface{}{"to": "+5511999999999"}, Enabled: true},
			},
		},
	}
}

func (s *APIServer) handleCreateAlert(c *gin.Context) {
	var alert Alert
	if err := c.ShouldBindJSON(&alert); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validar alert
	if err := validateAlert(&alert); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Gerar ID único
	alert.ID = uuid.New().String()
	alert.CreatedAt = time.Now()
	alert.UpdatedAt = time.Now()
	alert.Status = "active"

	// Salvar no Elasticsearch
	alertJSON, err := json.Marshal(alert)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao serializar alerta"})
		return
	}

	res, err := s.opensearch.Index(
		"siem-alerts",
		strings.NewReader(string(alertJSON)),
		s.opensearch.Index.WithContext(c.Request.Context()),
		s.opensearch.Index.WithDocumentID(alert.ID),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao criar alerta"})
		return
	}
	defer res.Body.Close()

	c.JSON(http.StatusCreated, alert)
}

func (s *APIServer) handleUpdateAlert(c *gin.Context) {
	id := c.Param("id")

	// Accept partial updates
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Add updated timestamp
	updates["updated_at"] = time.Now().Format(time.RFC3339)

	// Check if OpenSearch is available
	if s.opensearch == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OpenSearch não disponível"})
		return
	}

	// Atualizar no OpenSearch
	updateDoc := map[string]interface{}{
		"doc": updates,
	}
	alertJSON, err := json.Marshal(updateDoc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao serializar alerta"})
		return
	}

	res, err := s.opensearch.Update(
		"siem-alerts",
		id,
		strings.NewReader(string(alertJSON)),
		s.opensearch.Update.WithContext(c.Request.Context()),
	)
	if err != nil {
		log.Printf("❌ Error updating alert %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao atualizar alerta"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		// Read error response
		var errorResp map[string]interface{}
		json.NewDecoder(res.Body).Decode(&errorResp)
		log.Printf("❌ OpenSearch update error for alert %s: %v", id, errorResp)

		if res.StatusCode == 404 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Alerta não encontrado"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao atualizar alerta no OpenSearch"})
		return
	}

	log.Printf("✅ Alert %s updated successfully", id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Alerta atualizado com sucesso",
		"id":      id,
		"updates": updates,
	})
}

func (s *APIServer) handleDeleteAlert(c *gin.Context) {
	id := c.Param("id")

	// Check if OpenSearch is available
	if s.opensearch == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OpenSearch não disponível"})
		return
	}

	// Deletar do OpenSearch
	res, err := s.opensearch.Delete(
		"siem-alerts",
		id,
		s.opensearch.Delete.WithContext(c.Request.Context()),
	)
	if err != nil {
		log.Printf("❌ Error deleting alert %s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao deletar alerta"})
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Alerta não encontrado"})
			return
		}
		log.Printf("❌ OpenSearch delete error for alert %s: %s", id, res.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao deletar alerta"})
		return
	}

	log.Printf("✅ Alert %s deleted successfully", id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Alerta deletado com sucesso",
		"id":      id,
	})
}

func validateAlert(alert *Alert) error {
	if alert.Name == "" {
		return errors.New("nome do alerta é obrigatório")
	}

	if alert.Query == "" {
		return errors.New("query do alerta é obrigatória")
	}

	if alert.Severity == "" {
		return errors.New("severidade do alerta é obrigatória")
	}

	if len(alert.Actions) == 0 {
		return errors.New("pelo menos uma ação é obrigatória")
	}

	return nil
}

// handleGetAlertStatistics retorna estatísticas sobre os alertas
func (s *APIServer) handleGetAlertStatistics(c *gin.Context) {
	// Try to get real stats from OpenSearch
	if s.opensearch != nil {
		stats, err := s.getAlertStatsFromES(c)
		if err == nil {
			c.JSON(http.StatusOK, stats)
			return
		}
	}

	// Fallback to mock if OpenSearch fails and mock is enabled
	if IsMockDataDisabled() {
		c.JSON(http.StatusOK, gin.H{
			"total":              0,
			"active":             0,
			"inactive":           0,
			"by_severity":        map[string]int{},
			"triggered_last_24h": 0,
			"source":             "none",
		})
		return
	}

	// Gerar dados mock para estatísticas
	mockAlerts := generateMockAlerts()

	total := len(mockAlerts)
	active := 0
	inactive := 0
	bySeverity := make(map[string]int)
	triggeredLast24h := 0

	now := time.Now()
	last24h := now.Add(-24 * time.Hour)

	for _, alert := range mockAlerts {
		if alert.Status == "active" {
			active++
		} else {
			inactive++
		}

		bySeverity[alert.Severity]++

		if alert.LastTriggered != nil && alert.LastTriggered.After(last24h) {
			triggeredLast24h++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":              total,
		"active":             active,
		"inactive":           inactive,
		"by_severity":        bySeverity,
		"triggered_last_24h": triggeredLast24h,
		"source":             "mock",
	})
}

// getAlertStatsFromES returns alert statistics from OpenSearch
func (s *APIServer) getAlertStatsFromES(c *gin.Context) (gin.H, error) {
	// Aggregation query
	query := map[string]interface{}{
		"size":             0,
		"track_total_hits": true, // Remove 10,000 limit on total count
		"aggs": map[string]interface{}{
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "severity",
					"size":  10,
				},
			},
			"by_status": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "status",
					"size":  10,
				},
			},
			"by_source": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "source",
					"size":  20,
				},
			},
			"last_24h": map[string]interface{}{
				"filter": map[string]interface{}{
					"range": map[string]interface{}{
						"created_at": map[string]interface{}{
							"gte": "now-24h",
						},
					},
				},
			},
		},
	}

	// Excluir findings do Inspector das estatísticas de alertas
	statsBoolQuery := map[string]interface{}{
		"must_not": []map[string]interface{}{
			{
				"term": map[string]interface{}{
					"source": "inspector",
				},
			},
		},
	}

	accessFilters := buildAlertAccessFilter(getAccessScope(c))
	if len(accessFilters) > 0 {
		statsBoolQuery["must"] = accessFilters
	}

	query["query"] = map[string]interface{}{
		"bool": statsBoolQuery,
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

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
		return nil, errors.New("opensearch error")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Parse total
	total := 0
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			total = int(totalObj["value"].(float64))
		}
	}

	// Parse aggregations
	bySeverity := make(map[string]int)
	byStatus := make(map[string]int)
	bySource := make(map[string]int)
	triggeredLast24h := 0

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		// By severity
		if sevAgg, ok := aggs["by_severity"].(map[string]interface{}); ok {
			if buckets, ok := sevAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					key := bucket["key"].(string)
					count := int(bucket["doc_count"].(float64))
					bySeverity[key] = count
				}
			}
		}

		// By status
		if statusAgg, ok := aggs["by_status"].(map[string]interface{}); ok {
			if buckets, ok := statusAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					key := bucket["key"].(string)
					count := int(bucket["doc_count"].(float64))
					byStatus[key] = count
				}
			}
		}

		// By source (origem)
		if sourceAgg, ok := aggs["by_source"].(map[string]interface{}); ok {
			if buckets, ok := sourceAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					key := bucket["key"].(string)
					count := int(bucket["doc_count"].(float64))
					bySource[key] = count
				}
			}
		}

		// Last 24h
		if last24hAgg, ok := aggs["last_24h"].(map[string]interface{}); ok {
			triggeredLast24h = int(last24hAgg["doc_count"].(float64))
		}
	}

	active := byStatus["new"] + byStatus["active"] + byStatus["in_progress"]
	inactive := byStatus["resolved"] + byStatus["closed"] + byStatus["acknowledged"]

	return gin.H{
		"total":              total,
		"active":             active,
		"inactive":           inactive,
		"by_severity":        bySeverity,
		"by_status":          byStatus,
		"by_source":          bySource,
		"triggered_last_24h": triggeredLast24h,
		"data_source":        "opensearch",
	}, nil
}

// handleGetAlert retorna um alerta específico por ID com detalhes completos
func (s *APIServer) handleGetAlert(c *gin.Context) {
	id := c.Param("id")
	scope := getAccessScope(c)

	// Tentar buscar do OpenSearch primeiro
	if s.opensearch != nil {
		alertDetails, err := s.getAlertDetailsFromOS(id)
		if err == nil {
			if !alertMatchesScope(alertDetails.Alert, scope) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Alerta não encontrado"})
				return
			}
			c.JSON(http.StatusOK, alertDetails)
			return
		}
		log.Printf("[WARNING] Failed to get alert from OpenSearch: %v", err)
	}

	// Fallback para mock
	if IsMockDataDisabled() {
		c.JSON(http.StatusNotFound, gin.H{"error": "Alerta não encontrado"})
		return
	}

	mockAlerts := generateMockAlerts()
	for _, alert := range mockAlerts {
		if alert.ID == id {
			if !alertMatchesScope(alert, scope) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Alerta não encontrado"})
				return
			}
			// Enriquecer com detalhes mock
			details := s.enrichAlertWithDetails(alert)
			c.JSON(http.StatusOK, details)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Alerta não encontrado"})
}

// getAlertDetailsFromOS busca e enriquece um alerta do OpenSearch
func (s *APIServer) getAlertDetailsFromOS(alertID string) (*AlertDetails, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	// Buscar o alerta
	res, err := s.opensearch.Get(
		"siem-alerts",
		alertID,
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("alert not found")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	source, ok := result["_source"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid alert format")
	}

	// Converter para Alert
	alert := s.parseAlertFromSource(alertID, source)

	// Enriquecer com detalhes
	details := s.enrichAlertWithDetails(alert)

	// Buscar contagem de incidências similar
	details.IncidentCount = s.getIncidentCountFromOS(alert)

	// Buscar caso relacionado (se existir)
	details.RelatedCase = s.getRelatedCaseFromOS(alertID)

	return details, nil
}

// parseAlertFromSource converte um documento OpenSearch em Alert
func (s *APIServer) parseAlertFromSource(id string, source map[string]interface{}) Alert {
	alert := Alert{ID: id}

	if v, ok := source["name"].(string); ok {
		alert.Name = v
	}
	if v, ok := source["title"].(string); ok && alert.Name == "" {
		alert.Name = v
	}
	if v, ok := source["description"].(string); ok {
		alert.Description = v
	}
	if v, ok := source["severity"].(string); ok {
		alert.Severity = v
	}
	if v, ok := source["status"].(string); ok {
		alert.Status = v
	}
	if v, ok := source["source"].(string); ok {
		alert.Source = v
	}
	if v, ok := source["source_id"].(string); ok {
		alert.SourceID = v
	}
	if v, ok := source["category"].(string); ok {
		alert.Category = v
	}
	if v, ok := source["resource_id"].(string); ok {
		alert.ResourceID = v
	}
	if v, ok := source["resource_type"].(string); ok {
		alert.ResourceType = v
	}
	if v, ok := source["region"].(string); ok {
		alert.Region = v
	}
	if v, ok := source["account_id"].(string); ok {
		alert.AccountID = v
	}
	if v, ok := source["created_at"].(string); ok {
		alert.CreatedAt, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := source["updated_at"].(string); ok {
		alert.UpdatedAt, _ = time.Parse(time.RFC3339, v)
	}

	return alert
}

// enrichAlertWithDetails adiciona informações detalhadas ao alerta
func (s *APIServer) enrichAlertWithDetails(alert Alert) *AlertDetails {
	details := &AlertDetails{
		Alert: alert,
	}

	// === ORIGEM DO LOG ===
	details.LogSource = s.generateLogSourceInfo(alert)

	// === CONTAGEM DE INCIDÊNCIAS (valores padrão) ===
	details.IncidentCount = &IncidentCountInfo{
		Total:           1,
		Last24Hours:     1,
		Last7Days:       1,
		Last30Days:      1,
		FirstSeen:       alert.CreatedAt,
		LastSeen:        alert.UpdatedAt,
		Trend:           "stable",
		TrendPercentage: 0,
		UniqueResources: 1,
		UniqueAccounts:  1,
		UniqueRegions:   1,
	}

	// === RECOMENDAÇÕES ===
	details.Recommendations = s.generateRecommendations(alert)

	// === CONTEXTO DE SEGURANÇA ===
	details.SecurityContext = s.generateSecurityContext(alert)

	// === ATIVOS AFETADOS ===
	details.AffectedAssets = s.generateAffectedAssets(alert)

	// === EVIDÊNCIAS ===
	details.Evidence = s.generateEvidence(alert)

	// === TIMELINE ===
	details.Timeline = s.generateTimeline(alert)

	// === AÇÕES SUGERIDAS ===
	details.SuggestedActions = s.generateSuggestedActions(alert)

	return details
}

// generateLogSourceInfo gera informações sobre a origem do log
func (s *APIServer) generateLogSourceInfo(alert Alert) *LogSourceInfo {
	logSource := &LogSourceInfo{
		Service:   alert.Source,
		Region:    alert.Region,
		AccountID: alert.AccountID,
		EventTime: alert.CreatedAt,
	}

	// Mapear detalhes por fonte
	switch strings.ToLower(alert.Source) {
	case "guardduty":
		logSource.Type = "threat_detection"
		logSource.LogGroup = "/aws/guardduty/findings"
		logSource.EventSource = "guardduty.amazonaws.com"
		logSource.EventName = "GenerateFinding"
	case "cloudtrail":
		logSource.Type = "api_activity"
		logSource.LogGroup = "/aws/cloudtrail/" + alert.AccountID
		logSource.EventSource = getEventSourceFromCategory(alert.Category)
		logSource.EventName = getEventNameFromAlert(alert)
	case "securityhub":
		logSource.Type = "security_finding"
		logSource.LogGroup = "/aws/securityhub/findings"
		logSource.EventSource = "securityhub.amazonaws.com"
	case "inspector":
		logSource.Type = "vulnerability_finding"
		logSource.LogGroup = "/aws/inspector/findings"
		logSource.EventSource = "inspector2.amazonaws.com"
	case "cloudflare":
		logSource.Type = "waf_event"
		logSource.Service = "Cloudflare WAF"
		logSource.EventSource = "cloudflare.com"
	case "vpc_flow":
		logSource.Type = "network_flow"
		logSource.LogGroup = "/aws/vpc/flowlogs"
		logSource.EventSource = "ec2.amazonaws.com"
	}

	// Extrair IP se disponível
	if alert.ResourceID != "" && strings.Contains(alert.ResourceID, ".") {
		logSource.SourceIP = alert.ResourceID
	}

	// Gerar amostra do log
	logSource.RawLogSample = generateRawLogSample(alert)

	return logSource
}

// generateRecommendations gera recomendações baseadas no alerta
func (s *APIServer) generateRecommendations(alert Alert) []Recommendation {
	var recs []Recommendation

	severity := strings.ToLower(alert.Severity)
	source := strings.ToLower(alert.Source)
	category := strings.ToLower(alert.Category)

	// Recomendação 1: Ação imediata baseada na severidade
	if severity == "critical" || severity == "high" {
		recs = append(recs, Recommendation{
			Priority:    1,
			Title:       "🚨 Ação Imediata Requerida",
			Description: "Este alerta tem severidade " + strings.ToUpper(severity) + " e requer investigação imediata.",
			Action:      "Iniciar investigação e determinar se há comprometimento ativo.",
			Impact:      "Prevenção de danos maiores e contenção de ameaça.",
			Effort:      "medium",
			Type:        "immediate",
			Automated:   false,
		})
	}

	// Recomendações específicas por fonte
	switch source {
	case "guardduty":
		recs = append(recs, Recommendation{
			Priority:    2,
			Title:       "🔍 Verificar Finding no GuardDuty",
			Description: "Acesse o console do GuardDuty para obter detalhes completos do finding.",
			Action:      "Acessar AWS Console > GuardDuty > Findings e filtrar por ID: " + alert.SourceID,
			Impact:      "Obter contexto completo e evidências adicionais.",
			Effort:      "low",
			Type:        "immediate",
			AWSDoc:      "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html",
			Automated:   false,
		})

		if strings.Contains(category, "crypto") {
			recs = append(recs, Recommendation{
				Priority:    1,
				Title:       "⛏️ Possível Cryptomining Detectado",
				Description: "Verifique se a instância está executando mineração de criptomoedas não autorizada.",
				Action:      "1) Isolar a instância 2) Analisar processos em execução 3) Verificar uso de CPU/GPU",
				Impact:      "Prevenção de custos elevados e uso não autorizado de recursos.",
				Effort:      "medium",
				Type:        "immediate",
				Automated:   true,
				PlaybookID:  "playbook-cryptomining-response",
			})
		}

	case "cloudtrail":
		recs = append(recs, Recommendation{
			Priority:    2,
			Title:       "📋 Analisar Histórico de Atividades",
			Description: "Verifique o histórico de ações do usuário/serviço envolvido.",
			Action:      "Acessar CloudTrail e buscar atividades relacionadas nos últimos 7 dias.",
			Impact:      "Identificar padrão de comportamento e possível comprometimento de credenciais.",
			Effort:      "medium",
			Type:        "short_term",
			AWSDoc:      "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html",
			Automated:   false,
		})

	case "securityhub":
		recs = append(recs, Recommendation{
			Priority:    2,
			Title:       "🛡️ Verificar Recomendações do Security Hub",
			Description: "O Security Hub fornece recomendações específicas de remediação.",
			Action:      "Acessar Security Hub > Findings e seguir as recomendações do padrão de segurança.",
			Impact:      "Correção de vulnerabilidades de configuração.",
			Effort:      "varies",
			Type:        "short_term",
			AWSDoc:      "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html",
			Automated:   true,
		})

	case "inspector":
		recs = append(recs, Recommendation{
			Priority:    2,
			Title:       "🔧 Aplicar Patches de Segurança",
			Description: "O Inspector identificou vulnerabilidades que podem ser corrigidas com patches.",
			Action:      "1) Identificar CVEs afetados 2) Verificar patches disponíveis 3) Aplicar em ambiente de teste primeiro",
			Impact:      "Correção de vulnerabilidades conhecidas e redução de superfície de ataque.",
			Effort:      "medium",
			Type:        "short_term",
			AWSDoc:      "https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html",
			Automated:   true,
			PlaybookID:  "playbook-patch-management",
		})
	}

	// Recomendação de contenção baseada no tipo de recurso
	if alert.ResourceType != "" {
		recs = append(recs, generateContainmentRecommendation(alert))
	}

	// Recomendação de longo prazo
	recs = append(recs, Recommendation{
		Priority:    5,
		Title:       "📊 Revisão de Controles de Segurança",
		Description: "Avaliar se os controles existentes são adequados para prevenir este tipo de incidente.",
		Action:      "Revisar políticas de IAM, Security Groups, e configurações de logging.",
		Impact:      "Prevenção de incidentes futuros similares.",
		Effort:      "high",
		Type:        "long_term",
		Automated:   false,
	})

	return recs
}

// generateSecurityContext gera contexto de segurança
func (s *APIServer) generateSecurityContext(alert Alert) *SecurityContext {
	ctx := &SecurityContext{
		RiskScore:      alertCalculateRiskScore(alert),
		BusinessImpact: getBusinessImpact(alert),
	}

	// Mapear MITRE ATT&CK baseado na categoria
	ctx.MITRETactics, ctx.MITRETechniques = mapToMITRE(alert)

	// Fatores de risco
	ctx.RiskFactors = []string{}
	if strings.ToLower(alert.Severity) == "critical" {
		ctx.RiskFactors = append(ctx.RiskFactors, "Severidade Crítica")
	}
	if strings.ToLower(alert.Severity) == "high" {
		ctx.RiskFactors = append(ctx.RiskFactors, "Severidade Alta")
	}
	if alert.ResourceType == "IAMUser" || alert.ResourceType == "IAMRole" {
		ctx.RiskFactors = append(ctx.RiskFactors, "Recurso de Identidade Afetado")
	}
	if strings.Contains(strings.ToLower(alert.Category), "exposed") {
		ctx.RiskFactors = append(ctx.RiskFactors, "Possível Exposição de Dados")
	}

	// Compliance frameworks afetados
	ctx.ComplianceFrameworks = mapToCompliance(alert)

	return ctx
}

// generateAffectedAssets gera lista de ativos afetados
func (s *APIServer) generateAffectedAssets(alert Alert) []AffectedAsset {
	assets := []AffectedAsset{}

	if alert.ResourceID != "" {
		asset := AffectedAsset{
			ResourceID:   alert.ResourceID,
			ResourceType: alert.ResourceType,
			ResourceName: alert.ResourceID, // Pode ser enriquecido posteriormente
			Region:       alert.Region,
			AccountID:    alert.AccountID,
			Tags:         map[string]string{},
		}

		// Inferir criticidade baseada no tipo de recurso
		asset.Criticality = inferCriticality(alert.ResourceType)

		// Inferir ambiente baseado em padrões de nomenclatura
		asset.Environment = inferEnvironment(alert.ResourceID)

		assets = append(assets, asset)
	}

	return assets
}

// generateEvidence gera evidências do alerta
func (s *APIServer) generateEvidence(alert Alert) []AlertEvidence {
	evidence := []AlertEvidence{
		{
			Type:        "log",
			Description: "Finding original do " + alert.Source,
			Timestamp:   alert.CreatedAt,
			Source:      alert.Source,
			Preserved:   true,
		},
	}

	return evidence
}

// generateTimeline gera linha do tempo do alerta
func (s *APIServer) generateTimeline(alert Alert) []TimelineEntry {
	timeline := []TimelineEntry{
		{
			Timestamp:   alert.CreatedAt,
			Event:       "alert_created",
			Description: "Alerta criado pelo " + alert.Source,
			Source:      "SIEM",
		},
	}

	if !alert.UpdatedAt.IsZero() && alert.UpdatedAt != alert.CreatedAt {
		timeline = append(timeline, TimelineEntry{
			Timestamp:   alert.UpdatedAt,
			Event:       "alert_updated",
			Description: "Alerta atualizado",
			Source:      "SIEM",
		})
	}

	return timeline
}

// generateSuggestedActions gera ações sugeridas para o analista
func (s *APIServer) generateSuggestedActions(alert Alert) []SuggestedAction {
	actions := []SuggestedAction{
		{
			ID:            "action-1",
			Title:         "Investigar Alerta",
			Description:   "Analisar o contexto do alerta e determinar se é um verdadeiro positivo.",
			Type:          "investigate",
			Priority:      1,
			Automated:     false,
			EstimatedTime: "15-30 min",
			RequiredRole:  "analyst",
		},
	}

	severity := strings.ToLower(alert.Severity)
	if severity == "critical" || severity == "high" {
		actions = append(actions, SuggestedAction{
			ID:            "action-2",
			Title:         "Conter Ameaça",
			Description:   "Isolar o recurso afetado para prevenir propagação.",
			Type:          "contain",
			Priority:      1,
			Automated:     true,
			PlaybookID:    "playbook-containment",
			EstimatedTime: "5-10 min",
			RequiredRole:  "analyst",
		})
	}

	actions = append(actions, SuggestedAction{
		ID:            "action-3",
		Title:         "Criar Caso de Investigação",
		Description:   "Abrir um caso para documentar a investigação.",
		Type:          "investigate",
		Priority:      2,
		Automated:     true,
		EstimatedTime: "2-5 min",
		RequiredRole:  "analyst",
	})

	actions = append(actions, SuggestedAction{
		ID:            "action-4",
		Title:         "Escalar para Nível 2",
		Description:   "Escalar para um analista sênior se necessário.",
		Type:          "escalate",
		Priority:      3,
		Automated:     false,
		EstimatedTime: "5 min",
		RequiredRole:  "analyst",
	})

	return actions
}

// getIncidentCountFromOS busca estatísticas de incidências do OpenSearch
func (s *APIServer) getIncidentCountFromOS(alert Alert) *IncidentCountInfo {
	if s.opensearch == nil {
		return nil
	}

	info := &IncidentCountInfo{
		FirstSeen: alert.CreatedAt,
		LastSeen:  alert.UpdatedAt,
		Trend:     "stable",
	}

	// Query para contar alertas similares
	query := fmt.Sprintf(`{
		"query": {
			"bool": {
				"must": [
					{"term": {"name.keyword": %q}},
					{"term": {"source": %q}}
				]
			}
		},
		"aggs": {
			"last_24h": {
				"filter": {"range": {"created_at": {"gte": "now-24h"}}}
			},
			"last_7d": {
				"filter": {"range": {"created_at": {"gte": "now-7d"}}}
			},
			"last_30d": {
				"filter": {"range": {"created_at": {"gte": "now-30d"}}}
			},
			"unique_resources": {
				"cardinality": {"field": "resource_id"}
			},
			"unique_accounts": {
				"cardinality": {"field": "account_id"}
			}
		},
		"size": 0
	}`, alert.Name, alert.Source)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return info
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return info
	}

	// Extrair valores
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			if value, ok := total["value"].(float64); ok {
				info.Total = int(value)
			}
		}
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if last24h, ok := aggs["last_24h"].(map[string]interface{}); ok {
			if docCount, ok := last24h["doc_count"].(float64); ok {
				info.Last24Hours = int(docCount)
			}
		}
		if last7d, ok := aggs["last_7d"].(map[string]interface{}); ok {
			if docCount, ok := last7d["doc_count"].(float64); ok {
				info.Last7Days = int(docCount)
			}
		}
		if last30d, ok := aggs["last_30d"].(map[string]interface{}); ok {
			if docCount, ok := last30d["doc_count"].(float64); ok {
				info.Last30Days = int(docCount)
			}
		}
		if uniqueRes, ok := aggs["unique_resources"].(map[string]interface{}); ok {
			if value, ok := uniqueRes["value"].(float64); ok {
				info.UniqueResources = int(value)
			}
		}
		if uniqueAcc, ok := aggs["unique_accounts"].(map[string]interface{}); ok {
			if value, ok := uniqueAcc["value"].(float64); ok {
				info.UniqueAccounts = int(value)
			}
		}
	}

	// Calcular tendência
	if info.Last7Days > 0 {
		weeklyAvg := float64(info.Last7Days) / 7
		dailyAvg24h := float64(info.Last24Hours)
		if weeklyAvg > 0 {
			info.TrendPercentage = ((dailyAvg24h - weeklyAvg) / weeklyAvg) * 100
			if info.TrendPercentage > 20 {
				info.Trend = "increasing"
			} else if info.TrendPercentage < -20 {
				info.Trend = "decreasing"
			}
		}
	}

	return info
}

// getRelatedCaseFromOS busca caso relacionado ao alerta
func (s *APIServer) getRelatedCaseFromOS(alertID string) *RelatedCaseInfo {
	if s.opensearch == nil {
		return nil
	}

	// Buscar link alerta-caso
	query := fmt.Sprintf(`{
		"query": {
			"term": {"alert_id": %q}
		},
		"size": 1
	}`, alertID)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-alert-case-links"),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return nil
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil
	}

	// Verificar se encontrou
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsArray, ok := hits["hits"].([]interface{}); ok && len(hitsArray) > 0 {
			if hit, ok := hitsArray[0].(map[string]interface{}); ok {
				if source, ok := hit["_source"].(map[string]interface{}); ok {
					caseID, _ := source["case_id"].(string)
					caseStatus, _ := source["case_status"].(string)

					// Buscar detalhes do caso
					return &RelatedCaseInfo{
						CaseID:     caseID,
						CaseStatus: caseStatus,
					}
				}
			}
		}
	}

	return nil
}

// ============================================================================
// FUNÇÕES AUXILIARES
// ============================================================================

func getEventSourceFromCategory(category string) string {
	categoryMap := map[string]string{
		"ec2":        "ec2.amazonaws.com",
		"s3":         "s3.amazonaws.com",
		"iam":        "iam.amazonaws.com",
		"lambda":     "lambda.amazonaws.com",
		"rds":        "rds.amazonaws.com",
		"cloudfront": "cloudfront.amazonaws.com",
	}

	for key, value := range categoryMap {
		if strings.Contains(strings.ToLower(category), key) {
			return value
		}
	}
	return "aws.amazonaws.com"
}

func getEventNameFromAlert(alert Alert) string {
	// Extrair nome do evento baseado na descrição ou categoria
	return "SecurityEvent"
}

func generateRawLogSample(alert Alert) string {
	// Gerar uma amostra do log baseado no alerta
	return fmt.Sprintf(`{
  "eventTime": "%s",
  "eventSource": "%s",
  "eventName": "SecurityFinding",
  "awsRegion": "%s",
  "sourceIPAddress": "N/A",
  "userIdentity": {
    "accountId": "%s"
  },
  "requestParameters": {
    "resourceId": "%s",
    "resourceType": "%s"
  },
  "finding": {
    "severity": "%s",
    "title": "%s"
  }
}`, alert.CreatedAt.Format(time.RFC3339), alert.Source, alert.Region,
		alert.AccountID, alert.ResourceID, alert.ResourceType,
		alert.Severity, alert.Name)
}

func generateContainmentRecommendation(alert Alert) Recommendation {
	resourceType := strings.ToLower(alert.ResourceType)

	rec := Recommendation{
		Priority: 3,
		Type:     "immediate",
		Effort:   "medium",
	}

	switch {
	case strings.Contains(resourceType, "ec2") || strings.Contains(resourceType, "instance"):
		rec.Title = "🔒 Isolar Instância EC2"
		rec.Description = "Isolar a instância afetada modificando seu Security Group."
		rec.Action = "1) Criar SG de isolamento sem regras de entrada 2) Associar à instância 3) Capturar snapshot para análise"
		rec.AWSDoc = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html"
		rec.Automated = true
		rec.PlaybookID = "playbook-ec2-isolation"

	case strings.Contains(resourceType, "iam"):
		rec.Title = "🔑 Desativar Credenciais IAM"
		rec.Description = "Desativar as credenciais do usuário/role suspeito."
		rec.Action = "1) Desativar Access Keys 2) Invalidar sessões 3) Revisar políticas anexadas"
		rec.AWSDoc = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
		rec.Automated = true
		rec.PlaybookID = "playbook-iam-revoke"

	case strings.Contains(resourceType, "s3"):
		rec.Title = "🪣 Restringir Acesso ao Bucket S3"
		rec.Description = "Revisar e restringir permissões do bucket afetado."
		rec.Action = "1) Revisar Bucket Policy 2) Verificar ACLs 3) Habilitar logging 4) Verificar objetos expostos"
		rec.AWSDoc = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
		rec.Automated = false

	default:
		rec.Title = "🛡️ Verificar Acesso ao Recurso"
		rec.Description = "Revisar permissões e acessos ao recurso afetado."
		rec.Action = "1) Verificar quem tem acesso 2) Revisar logs de acesso 3) Aplicar princípio do menor privilégio"
		rec.Automated = false
	}

	return rec
}

func alertCalculateRiskScore(alert Alert) int {
	score := 0

	// Base por severidade
	switch strings.ToLower(alert.Severity) {
	case "critical":
		score = 80
	case "high":
		score = 60
	case "medium":
		score = 40
	case "low":
		score = 20
	default:
		score = 30
	}

	// Ajustes por tipo de recurso
	resourceType := strings.ToLower(alert.ResourceType)
	if strings.Contains(resourceType, "iam") {
		score += 15
	}
	if strings.Contains(resourceType, "secret") || strings.Contains(resourceType, "kms") {
		score += 10
	}

	// Ajuste por fonte
	if strings.ToLower(alert.Source) == "guardduty" {
		score += 5 // GuardDuty tem baixa taxa de falsos positivos
	}

	if score > 100 {
		score = 100
	}

	return score
}

func getBusinessImpact(alert Alert) string {
	severity := strings.ToLower(alert.Severity)

	switch severity {
	case "critical":
		return "Impacto crítico - possível comprometimento de sistemas essenciais ou dados sensíveis"
	case "high":
		return "Impacto alto - pode afetar disponibilidade ou integridade de serviços"
	case "medium":
		return "Impacto moderado - requer atenção mas não é emergencial"
	case "low":
		return "Impacto baixo - informativo ou melhoria de postura de segurança"
	default:
		return "Impacto a ser avaliado"
	}
}

func mapToMITRE(alert Alert) ([]string, []string) {
	tactics := []string{}
	techniques := []string{}

	category := strings.ToLower(alert.Category)
	name := strings.ToLower(alert.Name)

	// Mapear baseado em categoria e nome
	if strings.Contains(name, "brute") || strings.Contains(name, "password") {
		tactics = append(tactics, "Credential Access")
		techniques = append(techniques, "T1110 - Brute Force")
	}
	if strings.Contains(name, "crypto") || strings.Contains(name, "mining") {
		tactics = append(tactics, "Impact")
		techniques = append(techniques, "T1496 - Resource Hijacking")
	}
	if strings.Contains(category, "recon") || strings.Contains(name, "scan") {
		tactics = append(tactics, "Reconnaissance", "Discovery")
		techniques = append(techniques, "T1046 - Network Service Scanning")
	}
	if strings.Contains(name, "exfil") || strings.Contains(category, "data") {
		tactics = append(tactics, "Exfiltration")
		techniques = append(techniques, "T1048 - Exfiltration Over Alternative Protocol")
	}
	if strings.Contains(name, "privilege") || strings.Contains(name, "escalat") {
		tactics = append(tactics, "Privilege Escalation")
		techniques = append(techniques, "T1078 - Valid Accounts")
	}
	if strings.Contains(name, "persist") || strings.Contains(name, "backdoor") {
		tactics = append(tactics, "Persistence")
		techniques = append(techniques, "T1098 - Account Manipulation")
	}

	// Default se não encontrar match
	if len(tactics) == 0 {
		tactics = append(tactics, "Initial Access")
	}
	if len(techniques) == 0 {
		techniques = append(techniques, "T1190 - Exploit Public-Facing Application")
	}

	return tactics, techniques
}

func mapToCompliance(alert Alert) []string {
	frameworks := []string{}

	resourceType := strings.ToLower(alert.ResourceType)
	category := strings.ToLower(alert.Category)

	// Todos os alertas de segurança são relevantes para estes frameworks
	frameworks = append(frameworks, "CIS AWS Foundations")

	if strings.Contains(category, "data") || strings.Contains(category, "s3") {
		frameworks = append(frameworks, "LGPD", "SOC 2")
	}
	if strings.Contains(resourceType, "iam") {
		frameworks = append(frameworks, "SOC 2", "ISO 27001")
	}
	if strings.Contains(category, "network") || strings.Contains(category, "vpc") {
		frameworks = append(frameworks, "PCI-DSS")
	}

	return frameworks
}

func inferCriticality(resourceType string) string {
	rt := strings.ToLower(resourceType)

	// Recursos críticos
	if strings.Contains(rt, "secret") || strings.Contains(rt, "kms") ||
		strings.Contains(rt, "iam") || strings.Contains(rt, "root") {
		return "critical"
	}
	// Recursos de alta importância
	if strings.Contains(rt, "rds") || strings.Contains(rt, "database") ||
		strings.Contains(rt, "production") {
		return "high"
	}
	// Recursos de média importância
	if strings.Contains(rt, "ec2") || strings.Contains(rt, "instance") ||
		strings.Contains(rt, "s3") {
		return "medium"
	}

	return "low"
}

func inferEnvironment(resourceID string) string {
	rid := strings.ToLower(resourceID)

	if strings.Contains(rid, "prod") {
		return "production"
	}
	if strings.Contains(rid, "stag") || strings.Contains(rid, "staging") {
		return "staging"
	}
	if strings.Contains(rid, "dev") || strings.Contains(rid, "test") {
		return "development"
	}

	return "unknown"
}

// handleExportAlerts exporta alertas em diferentes formatos
func (s *APIServer) handleExportAlerts(c *gin.Context) {
	severity := c.Query("severity")
	status := c.Query("status")
	source := c.Query("source")
	search := c.Query("search")
	format := c.DefaultQuery("format", "csv") // csv, json

	// Limite de segurança para exportação
	maxExportSize := 10000
	var alerts []Alert

	// Tentar buscar do OpenSearch primeiro
	if s.opensearch != nil {
		must := []map[string]interface{}{}

		if severity != "" {
			must = append(must, map[string]interface{}{
				"term": map[string]interface{}{
					"severity": strings.ToUpper(severity),
				},
			})
		}
		if status != "" {
			must = append(must, map[string]interface{}{
				"term": map[string]interface{}{
					"status": status,
				},
			})
		}
		if source != "" {
			must = append(must, map[string]interface{}{
				"term": map[string]interface{}{
					"source": strings.ToLower(source),
				},
			})
		}
		if search != "" {
			searchUpper := strings.ToUpper(strings.TrimSpace(search))
			if strings.HasPrefix(searchUpper, "CVE-") {
				must = append(must, map[string]interface{}{
					"query_string": map[string]interface{}{
						"query":            "\"" + searchUpper + "\"",
						"fields":           []string{"name", "description", "source_id", "category", "title"},
						"default_operator": "AND",
					},
				})
			} else {
				must = append(must, map[string]interface{}{
					"multi_match": map[string]interface{}{
						"query":  search,
						"fields": []string{"name", "description", "source_id", "category", "title"},
						"type":   "best_fields",
					},
				})
			}
		}

		accessFilters := buildAlertAccessFilter(getAccessScope(c))
		if len(accessFilters) > 0 {
			must = append(must, accessFilters...)
		}

		// Excluir findings do Inspector na exportação
		mustNot := []map[string]interface{}{
			{
				"term": map[string]interface{}{
					"source": "inspector",
				},
			},
		}

		query := map[string]interface{}{
			"size": maxExportSize,
			"sort": []map[string]interface{}{
				{"created_at": map[string]interface{}{"order": "desc"}},
			},
		}

		exportBoolQuery := map[string]interface{}{
			"must_not": mustNot,
		}
		if len(must) > 0 {
			exportBoolQuery["must"] = must
		}
		query["query"] = map[string]interface{}{
			"bool": exportBoolQuery,
		}

		queryJSON, _ := json.Marshal(query)

		res, err := s.opensearch.Search(
			s.opensearch.Search.WithContext(c.Request.Context()),
			s.opensearch.Search.WithIndex("siem-alerts"),
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
									alert := Alert{
										ID:           getStringField(source, "id"),
										Name:         getStringField(source, "name"),
										Description:  getStringField(source, "description"),
										Severity:     getStringField(source, "severity"),
										Status:       getStringField(source, "status"),
										Source:       getStringField(source, "source"),
										SourceID:     getStringField(source, "source_id"),
										Category:     getStringField(source, "category"),
										ResourceID:   getStringField(source, "resource_id"),
										ResourceType: getStringField(source, "resource_type"),
										Region:       getStringField(source, "region"),
										AccountID:    getStringField(source, "account_id"),
									}
									if ts, ok := source["created_at"].(string); ok {
										alert.CreatedAt, _ = time.Parse(time.RFC3339, ts)
									}
									if ts, ok := source["updated_at"].(string); ok {
										alert.UpdatedAt, _ = time.Parse(time.RFC3339, ts)
									}
									alerts = append(alerts, alert)
								}
							}
						}
					}
				}
			}
		}
	}

	// Se não conseguiu buscar do OpenSearch, usar mock apenas se permitido
	if len(alerts) == 0 {
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"error":   "No data available for export",
				"message": "OpenSearch not connected and mock data is disabled",
			})
			return
		}
		// Fallback para mock
		alerts = generateMockAlerts()
	}

	// Limitar número de alertas exportados
	if len(alerts) > maxExportSize {
		alerts = alerts[:maxExportSize]
	}

	log.Printf("📤 Exporting %d alerts in %s format", len(alerts), format)

	// Gerar arquivo baseado no formato
	switch format {
	case "json":
		exportAlertsJSON(c, alerts)
	case "csv":
		exportAlertsCSV(c, alerts)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Formato não suportado. Use 'csv' ou 'json'"})
	}
}

// exportAlertsJSON exporta alertas em formato JSON
func exportAlertsJSON(c *gin.Context, alerts []Alert) {
	filename := "alerts_export_" + time.Now().Format("20060102_150405") + ".json"

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "application/json")

	c.JSON(http.StatusOK, gin.H{
		"exported_at": time.Now().Format(time.RFC3339),
		"total":       len(alerts),
		"alerts":      alerts,
	})
}

// exportAlertsCSV exporta alertas em formato CSV
func exportAlertsCSV(c *gin.Context, alerts []Alert) {
	filename := "alerts_export_" + time.Now().Format("20060102_150405") + ".csv"

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "text/csv")

	// Escrever cabeçalho CSV
	csv := "ID,Name,Severity,Status,Source,Category,Region,AccountID,ResourceType,ResourceID,Description,CreatedAt,UpdatedAt\n"

	// Escrever dados
	for _, alert := range alerts {
		// Escapar campos que podem conter vírgulas ou quebras de linha
		name := strings.ReplaceAll(alert.Name, "\"", "\"\"")
		name = strings.ReplaceAll(name, "\n", " ")
		description := strings.ReplaceAll(alert.Description, "\"", "\"\"")
		description = strings.ReplaceAll(description, "\n", " ")

		line := strings.Join([]string{
			alert.ID,
			"\"" + name + "\"",
			alert.Severity,
			alert.Status,
			alert.Source,
			alert.Category,
			alert.Region,
			alert.AccountID,
			alert.ResourceType,
			alert.ResourceID,
			"\"" + description + "\"",
			alert.CreatedAt.Format(time.RFC3339),
			alert.UpdatedAt.Format(time.RFC3339),
		}, ",") + "\n"

		csv += line
	}

	c.String(http.StatusOK, csv)
}
