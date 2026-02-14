package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================================
// ESTRUTURAS PARA SINCRONIZAÇÃO DE STATUS E SUPRESSÃO
// ============================================================================

// AlertCaseLink representa o vínculo entre um alerta/evento e um caso
type AlertCaseLink struct {
	ID         string    `json:"id"`
	AlertID    string    `json:"alert_id,omitempty"`
	EventID    string    `json:"event_id,omitempty"`
	CaseID     string    `json:"case_id"`
	CaseStatus string    `json:"case_status"`
	LinkedAt   time.Time `json:"linked_at"`
	LinkedBy   string    `json:"linked_by"`
}

// SuppressionRule representa uma regra de supressão para falsos positivos
type SuppressionRule struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	AlertName       string                 `json:"alert_name,omitempty"`       // Nome do alerta que será suprimido
	AlertSource     string                 `json:"alert_source,omitempty"`     // Fonte do alerta (guardduty, etc)
	ResourceID      string                 `json:"resource_id,omitempty"`      // ID do recurso específico
	ResourceType    string                 `json:"resource_type,omitempty"`    // Tipo de recurso
	AccountID       string                 `json:"account_id,omitempty"`       // ID da conta AWS
	Region          string                 `json:"region,omitempty"`           // Região
	SourceIP        string                 `json:"source_ip,omitempty"`        // IP de origem específico
	Conditions      map[string]interface{} `json:"conditions,omitempty"`       // Condições adicionais
	Reason          string                 `json:"reason"`                     // Motivo da supressão
	OriginalAlertID string                 `json:"original_alert_id"`          // ID do alerta que originou a regra
	OriginalCaseID  string                 `json:"original_case_id,omitempty"` // ID do caso que originou
	CreatedAt       time.Time              `json:"created_at"`
	CreatedBy       string                 `json:"created_by"`
	ExpiresAt       *time.Time             `json:"expires_at,omitempty"` // Opcional: expiração da regra
	IsActive        bool                   `json:"is_active"`
	MatchCount      int                    `json:"match_count"` // Quantas vezes a regra foi aplicada
	LastMatchedAt   *time.Time             `json:"last_matched_at,omitempty"`
}

// CaseStatusUpdate representa uma atualização de status do caso com propagação
type CaseStatusUpdate struct {
	CaseID            string `json:"case_id" binding:"required"`
	NewStatus         string `json:"new_status" binding:"required"`
	PropagateToAlerts bool   `json:"propagate_to_alerts"` // Se deve propagar para alertas
	PropagateToEvents bool   `json:"propagate_to_events"` // Se deve propagar para eventos
	Comment           string `json:"comment,omitempty"`   // Comentário opcional
}

// StatusMapping mapeia status do caso para status de alerta/evento
var StatusMapping = map[string]string{
	"new":         "new",
	"in_progress": "in_analysis",
	"resolved":    "resolved",
	"closed":      "closed",
	"escalated":   "escalated",
}

// ============================================================================
// ÍNDICES DO OPENSEARCH
// ============================================================================

const (
	AlertCaseLinkIndex    = "siem-alert-case-links"
	SuppressionRulesIndex = "siem-suppression-rules"
)

// EnsureCaseAlertSyncIndices cria os índices necessários para sincronização
func (s *APIServer) EnsureCaseAlertSyncIndices() error {
	if s.opensearch == nil {
		log.Println("⚠️ OpenSearch not available, Case-Alert sync will be limited")
		return nil
	}

	// Índice de vínculos alerta-caso
	linkMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"alert_id": { "type": "keyword" },
				"event_id": { "type": "keyword" },
				"case_id": { "type": "keyword" },
				"case_status": { "type": "keyword" },
				"linked_at": { "type": "date" },
				"linked_by": { "type": "keyword" }
			}
		}
	}`

	// Criar índice de vínculos se não existir
	res, err := s.opensearch.Indices.Exists([]string{AlertCaseLinkIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			AlertCaseLinkIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(linkMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", AlertCaseLinkIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", AlertCaseLinkIndex)
		}
	}

	// Índice de regras de supressão
	suppressionMapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"description": { "type": "text" },
				"alert_name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"alert_source": { "type": "keyword" },
				"resource_id": { "type": "keyword" },
				"resource_type": { "type": "keyword" },
				"account_id": { "type": "keyword" },
				"region": { "type": "keyword" },
				"source_ip": { "type": "keyword" },
				"conditions": { "type": "object", "enabled": false },
				"reason": { "type": "text" },
				"original_alert_id": { "type": "keyword" },
				"original_case_id": { "type": "keyword" },
				"created_at": { "type": "date" },
				"created_by": { "type": "keyword" },
				"expires_at": { "type": "date" },
				"is_active": { "type": "boolean" },
				"match_count": { "type": "integer" },
				"last_matched_at": { "type": "date" }
			}
		}
	}`

	// Criar índice de supressão se não existir
	res, err = s.opensearch.Indices.Exists([]string{SuppressionRulesIndex})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			SuppressionRulesIndex,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(suppressionMapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating %s index: %v", SuppressionRulesIndex, err)
		} else {
			res.Body.Close()
			log.Printf("✅ Created %s index", SuppressionRulesIndex)
		}
	}

	log.Println("[INFO] Case-Alert sync indices initialized")
	return nil
}

// ============================================================================
// HANDLERS - VÍNCULO ALERTA/EVENTO <-> CASO
// ============================================================================

// handleLinkAlertToCase vincula um alerta a um caso
func (s *APIServer) handleLinkAlertToCase(c *gin.Context) {
	var req struct {
		AlertID string `json:"alert_id" binding:"required"`
		CaseID  string `json:"case_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleLinkAlertToCase bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	username := getUsernameFromContext(c)

	// Criar vínculo
	link := AlertCaseLink{
		ID:         uuid.New().String(),
		AlertID:    req.AlertID,
		CaseID:     req.CaseID,
		CaseStatus: "new",
		LinkedAt:   time.Now(),
		LinkedBy:   username,
	}

	// Salvar no OpenSearch
	if s.opensearch != nil {
		if err := s.saveAlertCaseLink(&link); err != nil {
			log.Printf("[ERROR] Failed to save alert-case link: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to link alert to case"})
			return
		}

		// Atualizar o alerta com o case_id e status
		if err := s.updateAlertWithCaseInfo(req.AlertID, req.CaseID, "new"); err != nil {
			log.Printf("[WARNING] Failed to update alert with case info: %v", err)
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Alert linked to case successfully",
		"link":    link,
	})
}

// handleLinkEventToCase vincula um evento a um caso
func (s *APIServer) handleLinkEventToCase(c *gin.Context) {
	var req struct {
		EventID string `json:"event_id" binding:"required"`
		CaseID  string `json:"case_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleLinkEventToCase bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	username := getUsernameFromContext(c)

	link := AlertCaseLink{
		ID:         uuid.New().String(),
		EventID:    req.EventID,
		CaseID:     req.CaseID,
		CaseStatus: "new",
		LinkedAt:   time.Now(),
		LinkedBy:   username,
	}

	if s.opensearch != nil {
		if err := s.saveAlertCaseLink(&link); err != nil {
			log.Printf("[ERROR] Failed to save event-case link: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to link event to case"})
			return
		}

		// Atualizar o evento com o case_id
		if err := s.updateEventWithCaseInfo(req.EventID, req.CaseID, "new"); err != nil {
			log.Printf("[WARNING] Failed to update event with case info: %v", err)
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Event linked to case successfully",
		"link":    link,
	})
}

// handleUpdateCaseStatusWithPropagation atualiza o status do caso e propaga para alertas/eventos
func (s *APIServer) handleUpdateCaseStatusWithPropagation(c *gin.Context) {
	caseID := c.Param("id")

	var req struct {
		Status            string `json:"status" binding:"required"`
		PropagateToAlerts bool   `json:"propagate_to_alerts"`
		PropagateToEvents bool   `json:"propagate_to_events"`
		Comment           string `json:"comment,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleUpdateCaseStatusWithPropagation bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	username := getUsernameFromContext(c)
	alertStatus := StatusMapping[req.Status]
	if alertStatus == "" {
		alertStatus = req.Status
	}

	var updatedAlerts, updatedEvents int

	if s.opensearch != nil {
		// Atualizar status do caso no OpenSearch
		if err := s.updateCaseStatusInOS(caseID, req.Status); err != nil {
			log.Printf("[ERROR] Failed to update case status: %v", err)
		}

		// Propagar para alertas vinculados
		if req.PropagateToAlerts {
			links, _ := s.getAlertCaseLinksByCaseID(caseID)
			for _, link := range links {
				if link.AlertID != "" {
					if err := s.updateAlertWithCaseInfo(link.AlertID, caseID, alertStatus); err == nil {
						updatedAlerts++
					}
					// Atualizar o vínculo
					link.CaseStatus = req.Status
					s.saveAlertCaseLink(&link)
				}
			}
		}

		// Propagar para eventos vinculados
		if req.PropagateToEvents {
			links, _ := s.getAlertCaseLinksByCaseID(caseID)
			for _, link := range links {
				if link.EventID != "" {
					if err := s.updateEventWithCaseInfo(link.EventID, caseID, alertStatus); err == nil {
						updatedEvents++
					}
					link.CaseStatus = req.Status
					s.saveAlertCaseLink(&link)
				}
			}
		}
	}

	// Log da ação
	log.Printf("[INFO] Case %s status updated to %s by %s. Alerts: %d, Events: %d updated",
		caseID, req.Status, username, updatedAlerts, updatedEvents)

	c.JSON(http.StatusOK, gin.H{
		"message":        "Case status updated successfully",
		"case_id":        caseID,
		"new_status":     req.Status,
		"alerts_updated": updatedAlerts,
		"events_updated": updatedEvents,
	})
}

// handleGetLinkedAlerts retorna alertas vinculados a um caso
func (s *APIServer) handleGetLinkedAlerts(c *gin.Context) {
	caseID := c.Param("id")

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{"alerts": []interface{}{}, "total": 0})
		return
	}

	links, err := s.getAlertCaseLinksByCaseID(caseID)
	if err != nil {
		log.Printf("[ERROR] handleGetLinkedAlerts get links: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Buscar detalhes dos alertas
	var alerts []map[string]interface{}
	for _, link := range links {
		if link.AlertID != "" {
			alert, err := s.getAlertByID(link.AlertID)
			if err == nil && alert != nil {
				alert["case_status"] = link.CaseStatus
				alert["linked_at"] = link.LinkedAt
				alerts = append(alerts, alert)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"total":  len(alerts),
	})
}

// handleGetLinkedEvents retorna eventos vinculados a um caso
func (s *APIServer) handleGetLinkedEvents(c *gin.Context) {
	caseID := c.Param("id")

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{"events": []interface{}{}, "total": 0})
		return
	}

	links, err := s.getAlertCaseLinksByCaseID(caseID)
	if err != nil {
		log.Printf("[ERROR] handleGetLinkedEvents get links: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	var events []map[string]interface{}
	for _, link := range links {
		if link.EventID != "" {
			event, err := s.getEventByIDFromOS(link.EventID)
			if err == nil && event != nil {
				event["case_status"] = link.CaseStatus
				event["linked_at"] = link.LinkedAt
				events = append(events, event)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  len(events),
	})
}

// ============================================================================
// HANDLERS - REGRAS DE SUPRESSÃO (FALSO POSITIVO)
// ============================================================================

// handleMarkAsFalsePositive marca um alerta/evento como falso positivo e cria regra de supressão
func (s *APIServer) handleMarkAsFalsePositive(c *gin.Context) {
	var req struct {
		AlertID           string `json:"alert_id,omitempty"`
		EventID           string `json:"event_id,omitempty"`
		Reason            string `json:"reason" binding:"required"`
		CreateSuppression bool   `json:"create_suppression"` // Se deve criar regra de supressão
		SuppressionScope  string `json:"suppression_scope"`  // "exact", "resource", "source", "global"
		ExpirationDays    int    `json:"expiration_days"`    // 0 = sem expiração
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleMarkAsFalsePositive bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if req.AlertID == "" && req.EventID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "alert_id or event_id required"})
		return
	}

	username := getUsernameFromContext(c)

	// Marcar como falso positivo
	if s.opensearch != nil {
		if req.AlertID != "" {
			if err := s.updateAlertStatus(req.AlertID, "false_positive"); err != nil {
				log.Printf("[ERROR] Failed to mark alert as false positive: %v", err)
			}
		}
		if req.EventID != "" {
			if err := s.updateEventStatus(req.EventID, "false_positive"); err != nil {
				log.Printf("[ERROR] Failed to mark event as false positive: %v", err)
			}
		}
	}

	var suppressionRule *SuppressionRule

	// Criar regra de supressão se solicitado
	if req.CreateSuppression {
		rule, err := s.createSuppressionRuleFromAlert(req.AlertID, req.EventID, req.Reason, req.SuppressionScope, req.ExpirationDays, username)
		if err != nil {
			log.Printf("[ERROR] Failed to create suppression rule: %v", err)
		} else {
			suppressionRule = rule
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "Marked as false positive",
		"alert_id":         req.AlertID,
		"event_id":         req.EventID,
		"suppression_rule": suppressionRule,
	})
}

// handleListSuppressionRules lista todas as regras de supressão
func (s *APIServer) handleListSuppressionRules(c *gin.Context) {
	active := c.Query("active")

	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{"rules": []interface{}{}, "total": 0})
		return
	}

	rules, err := s.getSuppressionRules(active == "true")
	if err != nil {
		log.Printf("[ERROR] handleListSuppressionRules: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"total": len(rules),
	})
}

// handleCreateSuppressionRule cria uma nova regra de supressão manual
func (s *APIServer) handleCreateSuppressionRule(c *gin.Context) {
	var rule SuppressionRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		log.Printf("[ERROR] handleCreateSuppressionRule bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	username := getUsernameFromContext(c)

	rule.ID = uuid.New().String()
	rule.CreatedAt = time.Now()
	rule.CreatedBy = username
	rule.IsActive = true
	rule.MatchCount = 0

	if s.opensearch != nil {
		if err := s.saveSuppressionRule(&rule); err != nil {
			log.Printf("[ERROR] handleCreateSuppressionRule save: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
	}

	c.JSON(http.StatusCreated, rule)
}

// handleToggleSuppressionRule ativa/desativa uma regra de supressão
func (s *APIServer) handleToggleSuppressionRule(c *gin.Context) {
	ruleID := c.Param("id")

	var req struct {
		Active bool `json:"active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] handleToggleSuppressionRule bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if s.opensearch != nil {
		if err := s.updateSuppressionRuleStatus(ruleID, req.Active); err != nil {
			log.Printf("[ERROR] handleToggleSuppressionRule update: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Suppression rule updated",
		"rule_id": ruleID,
		"active":  req.Active,
	})
}

// handleDeleteSuppressionRule remove uma regra de supressão
func (s *APIServer) handleDeleteSuppressionRule(c *gin.Context) {
	ruleID := c.Param("id")

	if s.opensearch != nil {
		if err := s.deleteSuppressionRule(ruleID); err != nil {
			log.Printf("[ERROR] handleDeleteSuppressionRule: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Suppression rule deleted",
		"rule_id": ruleID,
	})
}

// handleCheckSuppression verifica se um alerta deve ser suprimido
func (s *APIServer) handleCheckSuppression(c *gin.Context) {
	var alert struct {
		Name         string `json:"name"`
		Source       string `json:"source"`
		ResourceID   string `json:"resource_id"`
		ResourceType string `json:"resource_type"`
		AccountID    string `json:"account_id"`
		Region       string `json:"region"`
		SourceIP     string `json:"source_ip"`
	}

	if err := c.ShouldBindJSON(&alert); err != nil {
		log.Printf("[ERROR] handleCheckSuppression bind: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	shouldSuppress, matchedRule := s.checkAlertSuppression(
		alert.Name, alert.Source, alert.ResourceID,
		alert.ResourceType, alert.AccountID, alert.Region, alert.SourceIP,
	)

	c.JSON(http.StatusOK, gin.H{
		"should_suppress": shouldSuppress,
		"matched_rule":    matchedRule,
	})
}

// handleGetAlertsInAnalysis retorna alertas que estão vinculados a casos em análise
func (s *APIServer) handleGetAlertsInAnalysis(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{"alerts": []interface{}{}, "total": 0})
		return
	}

	// Buscar alertas com case_status = "in_analysis" ou "in_progress"
	query := `{
		"query": {
			"bool": {
				"should": [
					{ "term": { "case_status": "in_analysis" } },
					{ "term": { "case_status": "in_progress" } }
				],
				"minimum_should_match": 1
			}
		},
		"size": 1000,
		"sort": [{ "updated_at": "desc" }]
	}`

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(context.Background()),
		s.opensearch.Search.WithIndex("siem-alerts"),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		log.Printf("[ERROR] handleGetAlertsInAnalysis search: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		log.Printf("[ERROR] handleGetAlertsInAnalysis decode: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	var alerts []map[string]interface{}
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"].(map[string]interface{}); ok {
						source["id"] = hitMap["_id"]
						alerts = append(alerts, source)
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"total":  len(alerts),
	})
}

// ============================================================================
// FUNÇÕES AUXILIARES - OPENSEARCH
// ============================================================================

func (s *APIServer) saveAlertCaseLink(link *AlertCaseLink) error {
	data, err := json.Marshal(link)
	if err != nil {
		return err
	}

	res, err := s.opensearch.Index(
		AlertCaseLinkIndex,
		strings.NewReader(string(data)),
		s.opensearch.Index.WithDocumentID(link.ID),
		s.opensearch.Index.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error indexing document: %s", res.String())
	}

	return nil
}

func (s *APIServer) getAlertCaseLinksByCaseID(caseID string) ([]AlertCaseLink, error) {
	// Sanitize caseID to prevent OpenSearch injection
	safeCaseID := sanitizeAlphanumeric(caseID)
	queryMap := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"case_id": safeCaseID,
			},
		},
		"size": 1000,
	}
	queryJSON, _ := json.Marshal(queryMap)
	query := string(queryJSON)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(context.Background()),
		s.opensearch.Search.WithIndex(AlertCaseLinkIndex),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	var links []AlertCaseLink
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"].(map[string]interface{}); ok {
						link := AlertCaseLink{}
						if v, ok := source["id"].(string); ok {
							link.ID = v
						}
						if v, ok := source["alert_id"].(string); ok {
							link.AlertID = v
						}
						if v, ok := source["event_id"].(string); ok {
							link.EventID = v
						}
						if v, ok := source["case_id"].(string); ok {
							link.CaseID = v
						}
						if v, ok := source["case_status"].(string); ok {
							link.CaseStatus = v
						}
						links = append(links, link)
					}
				}
			}
		}
	}

	return links, nil
}

func (s *APIServer) updateAlertWithCaseInfo(alertID, caseID, caseStatus string) error {
	updateDoc := map[string]interface{}{
		"doc": map[string]interface{}{
			"case_id":     caseID,
			"case_status": caseStatus,
			"updated_at":  time.Now().Format(time.RFC3339),
		},
	}

	data, _ := json.Marshal(updateDoc)
	res, err := s.opensearch.Update(
		"siem-alerts",
		alertID,
		strings.NewReader(string(data)),
		s.opensearch.Update.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func (s *APIServer) updateEventWithCaseInfo(eventID, caseID, caseStatus string) error {
	indices := []string{"siem-events-*", "guardduty-events-*", "cloudtrail-*"}

	for _, index := range indices {
		updateDoc := map[string]interface{}{
			"doc": map[string]interface{}{
				"case_id":     caseID,
				"case_status": caseStatus,
			},
		}

		data, _ := json.Marshal(updateDoc)
		res, err := s.opensearch.Update(
			index,
			eventID,
			strings.NewReader(string(data)),
		)
		if err == nil && res != nil && !res.IsError() {
			res.Body.Close()
			return nil
		}
		if res != nil {
			res.Body.Close()
		}
	}

	return nil
}

func (s *APIServer) updateCaseStatusInOS(caseID, status string) error {
	updateDoc := map[string]interface{}{
		"doc": map[string]interface{}{
			"status":     status,
			"updated_at": time.Now().Format(time.RFC3339),
		},
	}

	data, _ := json.Marshal(updateDoc)
	res, err := s.opensearch.Update(
		"siem-cases",
		caseID,
		strings.NewReader(string(data)),
		s.opensearch.Update.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func (s *APIServer) updateAlertStatus(alertID, status string) error {
	updateDoc := map[string]interface{}{
		"doc": map[string]interface{}{
			"status":     status,
			"updated_at": time.Now().Format(time.RFC3339),
		},
	}

	data, _ := json.Marshal(updateDoc)
	res, err := s.opensearch.Update(
		"siem-alerts",
		alertID,
		strings.NewReader(string(data)),
		s.opensearch.Update.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func (s *APIServer) updateEventStatus(eventID, status string) error {
	indices := []string{"siem-events-*", "guardduty-events-*"}

	for _, index := range indices {
		updateDoc := map[string]interface{}{
			"doc": map[string]interface{}{
				"status": status,
			},
		}

		data, _ := json.Marshal(updateDoc)
		res, err := s.opensearch.Update(
			index,
			eventID,
			strings.NewReader(string(data)),
		)
		if err == nil && res != nil && !res.IsError() {
			res.Body.Close()
			return nil
		}
		if res != nil {
			res.Body.Close()
		}
	}

	return nil
}

func (s *APIServer) getAlertByID(alertID string) (map[string]interface{}, error) {
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

	if source, ok := result["_source"].(map[string]interface{}); ok {
		source["id"] = alertID
		return source, nil
	}

	return nil, fmt.Errorf("invalid response")
}

func (s *APIServer) getEventByIDFromOS(eventID string) (map[string]interface{}, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	indexPattern := s.config.Elasticsearch.IndexPattern
	if indexPattern == "" {
		indexPattern = "siem-events-*"
	}

	res, err := s.opensearch.Get(
		indexPattern,
		eventID,
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("event not found")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	if source, ok := result["_source"].(map[string]interface{}); ok {
		source["id"] = eventID
		return source, nil
	}

	return nil, fmt.Errorf("invalid response")
}

// ============================================================================
// FUNÇÕES DE SUPRESSÃO
// ============================================================================

func (s *APIServer) createSuppressionRuleFromAlert(alertID, eventID, reason, scope string, expirationDays int, username string) (*SuppressionRule, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	var alertData map[string]interface{}
	var err error

	if alertID != "" {
		alertData, err = s.getAlertByID(alertID)
		if err != nil {
			return nil, err
		}
	}

	rule := &SuppressionRule{
		ID:              uuid.New().String(),
		Reason:          reason,
		OriginalAlertID: alertID,
		CreatedAt:       time.Now(),
		CreatedBy:       username,
		IsActive:        true,
		MatchCount:      0,
	}

	// Definir escopo da supressão
	if alertData != nil {
		rule.Name = fmt.Sprint("Suppression: ", alertData["name"])
		rule.Description = "Auto-created from false positive alert"

		switch scope {
		case "exact":
			// Suprime apenas este alerta exato (mesmo recurso, fonte, etc)
			rule.AlertName = getStringVal(alertData, "name")
			rule.AlertSource = getStringVal(alertData, "source")
			rule.ResourceID = getStringVal(alertData, "resource_id")
			rule.ResourceType = getStringVal(alertData, "resource_type")
			rule.AccountID = getStringVal(alertData, "account_id")
			rule.Region = getStringVal(alertData, "region")
		case "resource":
			// Suprime alertas do mesmo tipo para este recurso
			rule.AlertName = getStringVal(alertData, "name")
			rule.ResourceID = getStringVal(alertData, "resource_id")
			rule.ResourceType = getStringVal(alertData, "resource_type")
		case "source":
			// Suprime alertas do mesmo tipo para esta fonte/conta
			rule.AlertName = getStringVal(alertData, "name")
			rule.AlertSource = getStringVal(alertData, "source")
			rule.AccountID = getStringVal(alertData, "account_id")
		case "global":
			// Suprime todos os alertas do mesmo tipo
			rule.AlertName = getStringVal(alertData, "name")
		}
	}

	// Definir expiração se especificada
	if expirationDays > 0 {
		expiration := time.Now().AddDate(0, 0, expirationDays)
		rule.ExpiresAt = &expiration
	}

	// Salvar regra
	if err := s.saveSuppressionRule(rule); err != nil {
		return nil, err
	}

	return rule, nil
}

func (s *APIServer) saveSuppressionRule(rule *SuppressionRule) error {
	data, err := json.Marshal(rule)
	if err != nil {
		return err
	}

	res, err := s.opensearch.Index(
		SuppressionRulesIndex,
		strings.NewReader(string(data)),
		s.opensearch.Index.WithDocumentID(rule.ID),
		s.opensearch.Index.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error saving suppression rule: %s", res.String())
	}

	return nil
}

func (s *APIServer) getSuppressionRules(activeOnly bool) ([]SuppressionRule, error) {
	query := `{"query": {"match_all": {}}, "size": 1000, "sort": [{"created_at": "desc"}]}`

	if activeOnly {
		query = `{
			"query": {
				"bool": {
					"must": [
						{ "term": { "is_active": true } }
					],
					"should": [
						{ "bool": { "must_not": { "exists": { "field": "expires_at" } } } },
						{ "range": { "expires_at": { "gte": "now" } } }
					],
					"minimum_should_match": 1
				}
			},
			"size": 1000,
			"sort": [{"created_at": "desc"}]
		}`
	}

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(context.Background()),
		s.opensearch.Search.WithIndex(SuppressionRulesIndex),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	var rules []SuppressionRule
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsArray, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsArray {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"].(map[string]interface{}); ok {
						rule := parseSuppressionRule(source)
						rules = append(rules, rule)
					}
				}
			}
		}
	}

	return rules, nil
}

func (s *APIServer) updateSuppressionRuleStatus(ruleID string, active bool) error {
	updateDoc := map[string]interface{}{
		"doc": map[string]interface{}{
			"is_active": active,
		},
	}

	data, _ := json.Marshal(updateDoc)
	res, err := s.opensearch.Update(
		SuppressionRulesIndex,
		ruleID,
		strings.NewReader(string(data)),
		s.opensearch.Update.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func (s *APIServer) deleteSuppressionRule(ruleID string) error {
	res, err := s.opensearch.Delete(
		SuppressionRulesIndex,
		ruleID,
		s.opensearch.Delete.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

// checkAlertSuppression verifica se um alerta deve ser suprimido
func (s *APIServer) checkAlertSuppression(alertName, source, resourceID, resourceType, accountID, region, sourceIP string) (bool, *SuppressionRule) {
	if s.opensearch == nil {
		return false, nil
	}

	rules, err := s.getSuppressionRules(true)
	if err != nil {
		log.Printf("[WARNING] Failed to get suppression rules: %v", err)
		return false, nil
	}

	for _, rule := range rules {
		if matchesSuppressionRule(&rule, alertName, source, resourceID, resourceType, accountID, region, sourceIP) {
			// Incrementar contador de match
			s.incrementSuppressionMatchCount(rule.ID)
			return true, &rule
		}
	}

	return false, nil
}

func matchesSuppressionRule(rule *SuppressionRule, alertName, source, resourceID, resourceType, accountID, region, sourceIP string) bool {
	// Se o campo da regra está definido, deve corresponder
	if rule.AlertName != "" && !strings.Contains(strings.ToLower(alertName), strings.ToLower(rule.AlertName)) {
		return false
	}
	if rule.AlertSource != "" && rule.AlertSource != source {
		return false
	}
	if rule.ResourceID != "" && rule.ResourceID != resourceID {
		return false
	}
	if rule.ResourceType != "" && rule.ResourceType != resourceType {
		return false
	}
	if rule.AccountID != "" && rule.AccountID != accountID {
		return false
	}
	if rule.Region != "" && rule.Region != region {
		return false
	}
	if rule.SourceIP != "" && rule.SourceIP != sourceIP {
		return false
	}

	return true
}

func (s *APIServer) incrementSuppressionMatchCount(ruleID string) {
	updateDoc := map[string]interface{}{
		"script": map[string]interface{}{
			"source": "ctx._source.match_count += 1; ctx._source.last_matched_at = params.now",
			"params": map[string]interface{}{
				"now": time.Now().Format(time.RFC3339),
			},
		},
	}

	data, _ := json.Marshal(updateDoc)
	res, err := s.opensearch.Update(
		SuppressionRulesIndex,
		ruleID,
		strings.NewReader(string(data)),
	)
	if err == nil && res != nil {
		res.Body.Close()
	}
}

// ============================================================================
// HELPERS
// ============================================================================

func getUsernameFromContext(c *gin.Context) string {
	if usernameVal, exists := c.Get("username"); exists {
		if username, ok := usernameVal.(string); ok {
			return username
		}
	}
	return "unknown"
}

func getStringVal(data map[string]interface{}, key string) string {
	if v, ok := data[key].(string); ok {
		return v
	}
	return ""
}

func parseSuppressionRule(source map[string]interface{}) SuppressionRule {
	rule := SuppressionRule{}

	if v, ok := source["id"].(string); ok {
		rule.ID = v
	}
	if v, ok := source["name"].(string); ok {
		rule.Name = v
	}
	if v, ok := source["description"].(string); ok {
		rule.Description = v
	}
	if v, ok := source["alert_name"].(string); ok {
		rule.AlertName = v
	}
	if v, ok := source["alert_source"].(string); ok {
		rule.AlertSource = v
	}
	if v, ok := source["resource_id"].(string); ok {
		rule.ResourceID = v
	}
	if v, ok := source["resource_type"].(string); ok {
		rule.ResourceType = v
	}
	if v, ok := source["account_id"].(string); ok {
		rule.AccountID = v
	}
	if v, ok := source["region"].(string); ok {
		rule.Region = v
	}
	if v, ok := source["source_ip"].(string); ok {
		rule.SourceIP = v
	}
	if v, ok := source["reason"].(string); ok {
		rule.Reason = v
	}
	if v, ok := source["original_alert_id"].(string); ok {
		rule.OriginalAlertID = v
	}
	if v, ok := source["original_case_id"].(string); ok {
		rule.OriginalCaseID = v
	}
	if v, ok := source["created_by"].(string); ok {
		rule.CreatedBy = v
	}
	if v, ok := source["is_active"].(bool); ok {
		rule.IsActive = v
	}
	if v, ok := source["match_count"].(float64); ok {
		rule.MatchCount = int(v)
	}
	if v, ok := source["created_at"].(string); ok {
		rule.CreatedAt, _ = time.Parse(time.RFC3339, v)
	}

	return rule
}
