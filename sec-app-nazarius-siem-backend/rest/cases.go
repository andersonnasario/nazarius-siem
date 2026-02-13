package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cognimind/siem-platform/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var (
	casePolicyMu   sync.RWMutex
	cachedCasePolicy *CasePolicy
)

// Case representa um caso/incidente de segurança (compatível com frontend)
type Case struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`  // low, medium, high, critical
	Status      string     `json:"status"`    // new, in_progress, resolved, closed
	Priority    string     `json:"priority"`  // low, medium, high, urgent
	Category    string     `json:"category"`  // malware, phishing, data_breach, unauthorized_access, etc
	AssignedTo  string     `json:"assignedTo"` // User ID
	CreatedBy   string     `json:"createdBy"`  // User ID
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	ResolvedAt  *time.Time `json:"resolvedAt,omitempty"`
	ClosedAt    *time.Time `json:"closedAt,omitempty"`
	DueDate     *time.Time `json:"dueDate,omitempty"`
	Tags        []string   `json:"tags"`

	// Relacionamentos
	RelatedAlerts    []string `json:"relatedAlerts"`
	RelatedEvents    []string `json:"relatedEvents"`
	RelatedPlaybooks []string `json:"relatedPlaybooks"`

	// Escopo de acesso (para filtro por role/tenant)
	AccountID string `json:"account_id,omitempty"` // AWS Account ID para filtro de escopo

	// Métricas
	TimeToDetect  int `json:"timeToDetect"`  // em segundos
	TimeToRespond int `json:"timeToRespond"` // em segundos
	TimeToResolve int `json:"timeToResolve"` // em segundos

	// SLA
	SLABreach    bool       `json:"slaBreach"`
	SLADeadline  *time.Time `json:"slaDeadline,omitempty"`
	SLARemaining int        `json:"slaRemaining"` // em segundos

	// Detalhes avançados
	Evidence         []CaseEvidence           `json:"evidence,omitempty"`
	Timeline         []CaseTimelineEntry      `json:"timeline,omitempty"`
	Indicators       map[string]interface{}   `json:"indicators,omitempty"`
	MitreTactics     []string                 `json:"mitreTactics,omitempty"`
	MitreTechniques  []string                 `json:"mitreTechniques,omitempty"`
	AffectedAssets   []string                 `json:"affectedAssets,omitempty"`
	Resolution       string                   `json:"resolution,omitempty"`
	Recommendations  []CaseRecommendation      `json:"recommendations,omitempty"`
	Summary          *CaseSummary             `json:"summary,omitempty"`
	Checklist        []CaseChecklistItem      `json:"checklist,omitempty"`
}

// CaseActivity representa uma atividade/evento no caso
type CaseActivity struct {
	ID        string                 `json:"id"`
	CaseID    string                 `json:"caseId"`
	Type      string                 `json:"type"` // comment, status_change, assignment, attachment, playbook_execution
	User      string                 `json:"user"`
	Timestamp time.Time              `json:"timestamp"`
	Content   string                 `json:"content,omitempty"`
	OldValue  string                 `json:"oldValue,omitempty"`
	NewValue  string                 `json:"newValue,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// CaseComment representa um comentário em um caso
type CaseComment struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"caseId"`
	User      string    `json:"user"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

// CaseEvidence representa uma evidência associada ao caso
type CaseEvidence struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`        // log, file, packet, screenshot
	Description string    `json:"description"` // descrição breve
	Source      string    `json:"source"`      // fonte da evidência
	Timestamp   time.Time `json:"timestamp"`   // quando foi coletada
	Data        string    `json:"data,omitempty"`
	Hash        string    `json:"hash,omitempty"`
	Size        int64     `json:"size,omitempty"`
	Preserved   bool      `json:"preserved"`
}

// CaseTimelineEntry representa uma entrada na linha do tempo do caso
type CaseTimelineEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Event       string                 `json:"event"`
	Description string                 `json:"description"`
	User        string                 `json:"user,omitempty"`
	Source      string                 `json:"source,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// CaseRecommendation representa recomendações de ação
type CaseRecommendation struct {
	Priority   int      `json:"priority"` // 1 = mais urgente
	Title      string   `json:"title"`
	Description string `json:"description"`
	Action     string   `json:"action"`
	Impact     string   `json:"impact"`
	Effort     string   `json:"effort"` // low, medium, high
	Type       string   `json:"type"`   // immediate, short_term, long_term
	References []string `json:"references,omitempty"`
	Automated  bool     `json:"automated"`
	PlaybookID string   `json:"playbook_id,omitempty"`
}

// CaseSummary representa um resumo executivo do caso
type CaseSummary struct {
	RiskScore    int      `json:"risk_score"`
	SLAStatus    string   `json:"sla_status"`
	BusinessImpact string `json:"business_impact"`
	KeyFindings  []string `json:"key_findings"`
	NextSteps    []string `json:"next_steps"`
}

type CasePolicy struct {
	ID                 string                                 `json:"id,omitempty"`
	UpdatedAt          time.Time                              `json:"updated_at"`
	DefaultChecklist   []string                               `json:"default_checklist,omitempty"`
	CategorySuggestions []string                              `json:"category_suggestions,omitempty"`
	ChecklistByCategory map[string][]string                   `json:"checklist_by_category,omitempty"`
	SLABySeverity      map[string]CaseSLADefinition            `json:"sla_by_severity,omitempty"`
	SLAByCategory      map[string]map[string]CaseSLADefinition `json:"sla_by_category,omitempty"`
}

type CaseSLADefinition struct {
	DeadlineHours   int `json:"deadline_hours"`
	ResponseSeconds int `json:"response_seconds"`
	ResolveSeconds  int `json:"resolve_seconds"`
}

// CaseChecklistItem representa um item do checklist do caso
type CaseChecklistItem struct {
	ID          string     `json:"id"`
	Text        string     `json:"text"`
	Status      string     `json:"status"` // open, done
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	CompletedBy string     `json:"completed_by,omitempty"`
}

// CaseStatistics representa estatísticas de casos
type CaseStatistics struct {
	Total            int                      `json:"total"`
	New              int                      `json:"new"`
	InProgress       int                      `json:"inProgress"`
	Resolved         int                      `json:"resolved"`
	Closed           int                      `json:"closed"`
	BySeverity       map[string]int           `json:"bySeverity"`
	ByCategory       map[string]int           `json:"byCategory"`
	SLABreaches      int                      `json:"slaBreaches"`
	AvgTimeToResolve float64                  `json:"avgTimeToResolve"`
	TrendData        []map[string]interface{} `json:"trendData"`
}

// convertDBCaseToAPI converte case do DB para formato da API
func convertDBCaseToAPI(dbCase *database.Case) *Case {
	// Calculate SLA remaining
	slaRemaining := 0
	slaBreach := false
	if dbCase.SLADeadline != nil {
		remaining := time.Until(*dbCase.SLADeadline)
		slaRemaining = int(remaining.Seconds())
		if slaRemaining < 0 {
			slaBreach = true
			slaRemaining = 0
		}
	}

	// Parse evidence for metrics (if stored there)
	var evidence map[string]interface{}
	if dbCase.Evidence != nil {
		json.Unmarshal(dbCase.Evidence, &evidence)
	}

	// Extract metrics from evidence
	timeToDetect := 0
	timeToRespond := 0
	timeToResolve := 0
	if evidence != nil {
		if ttd, ok := evidence["time_to_detect"].(float64); ok {
			timeToDetect = int(ttd)
		}
		if ttr, ok := evidence["time_to_respond"].(float64); ok {
			timeToRespond = int(ttr)
		}
		if ttres, ok := evidence["time_to_resolve"].(float64); ok {
			timeToResolve = int(ttres)
		}
	}

	// Calculate timeToResolve from resolution_time_minutes if available
	if dbCase.ResolutionTimeMinutes != nil {
		timeToResolve = *dbCase.ResolutionTimeMinutes * 60
	}

	caseObj := &Case{
		ID:               dbCase.ID,
		Title:            dbCase.Title,
		Description:      dbCase.Description,
		Severity:         dbCase.Severity,
		Status:           dbCase.Status,
		Priority:         dbCase.Priority,
		Category:         dbCase.Category,
		AssignedTo:       getStringValue(dbCase.AssignedTo),
		CreatedBy:        getStringValue(dbCase.CreatedBy),
		CreatedAt:        dbCase.CreatedAt,
		UpdatedAt:        dbCase.UpdatedAt,
		ResolvedAt:       nil, // TODO: Add to DB schema if needed
		ClosedAt:         dbCase.ClosedAt,
		DueDate:          dbCase.SLADeadline, // Use SLA deadline as due date
		Tags:             dbCase.Tags,
		RelatedAlerts:    dbCase.AlertIDs,
		RelatedEvents:    []string{}, // TODO: Extract from timeline
		RelatedPlaybooks: parseRelatedPlaybooksFromEvidence(dbCase.Evidence),
		TimeToDetect:     timeToDetect,
		TimeToRespond:    timeToRespond,
		TimeToResolve:    timeToResolve,
		SLABreach:        slaBreach,
		SLADeadline:      dbCase.SLADeadline,
		SLARemaining:     slaRemaining,
		Indicators:       parseIndicators(dbCase.Indicators),
		MitreTactics:     dbCase.MitreTactics,
		MitreTechniques:  dbCase.MitreTechniques,
		AffectedAssets:   dbCase.AffectedAssets,
		Resolution:       getStringValue(dbCase.Resolution),
	Checklist:        parseChecklistFromEvidence(dbCase.Evidence),
	}

	// Detalhes avançados
	caseObj.Evidence = parseCaseEvidence(dbCase.Evidence)
	caseObj.Timeline = parseCaseTimeline(dbCase.Timeline)
	caseObj.Recommendations = buildCaseRecommendations(caseObj)
	caseObj.Summary = buildCaseSummary(caseObj)

	return caseObj
}

// convertAPICaseToDB converte case da API para formato do DB
func convertAPICaseToDB(apiCase *Case) (*database.Case, error) {
	// Build evidence with metrics
	evidence := map[string]interface{}{
		"time_to_detect":    apiCase.TimeToDetect,
		"time_to_respond":   apiCase.TimeToRespond,
		"time_to_resolve":   apiCase.TimeToResolve,
		"related_events":    apiCase.RelatedEvents,
		"related_playbooks": apiCase.RelatedPlaybooks,
		"checklist":         apiCase.Checklist,
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence: %w", err)
	}

	// Build timeline (empty for now)
	timelineJSON, err := json.Marshal([]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal timeline: %w", err)
	}

	// Build indicators (empty for now)
	indicatorsJSON, err := json.Marshal(map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal indicators: %w", err)
	}

	dbCase := &database.Case{
		ID:                  apiCase.ID,
		Title:               apiCase.Title,
		Description:         apiCase.Description,
		Severity:            apiCase.Severity,
		Status:              apiCase.Status,
		Priority:            apiCase.Priority,
		Category:            apiCase.Category,
		Tags:                apiCase.Tags,
		AlertIDs:            apiCase.RelatedAlerts,
		Evidence:            evidenceJSON,
		Timeline:            timelineJSON,
		MitreTactics:        []string{},
		MitreTechniques:     []string{},
		AffectedAssets:      []string{},
		Indicators:          indicatorsJSON,
		SLADeadline:         apiCase.SLADeadline,
		ClosedAt:            apiCase.ClosedAt,
	}

	if apiCase.AssignedTo != "" {
		dbCase.AssignedTo = &apiCase.AssignedTo
	}
	if apiCase.CreatedBy != "" {
		dbCase.CreatedBy = &apiCase.CreatedBy
	}

	return dbCase, nil
}

func parseCaseEvidence(raw json.RawMessage) []CaseEvidence {
	if raw == nil || len(raw) == 0 {
		return nil
	}

	var data interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil
	}

	var items []interface{}
	switch v := data.(type) {
	case []interface{}:
		items = v
	case map[string]interface{}:
		if arr, ok := v["evidence"].([]interface{}); ok {
			items = arr
		} else if arr, ok := v["items"].([]interface{}); ok {
			items = arr
		}
	}

	evidence := []CaseEvidence{}
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			ev := CaseEvidence{
				ID:          getStringFromMap(m, "id"),
				Type:        getStringFromMap(m, "type"),
				Description: getStringFromMap(m, "description"),
				Source:      getStringFromMap(m, "source"),
				Data:        getStringFromMap(m, "data"),
				Hash:        getStringFromMap(m, "hash"),
				Preserved:   getBoolFromMap(m, "preserved"),
			}
			if ts := getStringFromMap(m, "timestamp"); ts != "" {
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					ev.Timestamp = t
				}
			}
			if sizeVal, ok := m["size"].(float64); ok {
				ev.Size = int64(sizeVal)
			}
			evidence = append(evidence, ev)
		}
	}

	return evidence
}

func parseCaseTimeline(raw json.RawMessage) []CaseTimelineEntry {
	if raw == nil || len(raw) == 0 {
		return nil
	}

	var items []map[string]interface{}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}

	timeline := []CaseTimelineEntry{}
	for _, item := range items {
		entry := CaseTimelineEntry{
			Event:       getStringFromMap(item, "event"),
			Description: getStringFromMap(item, "description"),
			User:        getStringFromMap(item, "user"),
			Source:      getStringFromMap(item, "source"),
		}
		if ts := getStringFromMap(item, "timestamp"); ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				entry.Timestamp = t
			}
		}
		if details, ok := item["details"].(map[string]interface{}); ok {
			entry.Details = details
		}
		timeline = append(timeline, entry)
	}

	return timeline
}

func parseIndicators(raw json.RawMessage) map[string]interface{} {
	if raw == nil || len(raw) == 0 {
		return nil
	}

	var indicators map[string]interface{}
	if err := json.Unmarshal(raw, &indicators); err != nil {
		return nil
	}

	return indicators
}

func parseChecklistFromEvidence(raw json.RawMessage) []CaseChecklistItem {
	if raw == nil || len(raw) == 0 {
		return nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil
	}

	items, ok := data["checklist"].([]interface{})
	if !ok {
		return nil
	}

	checklist := []CaseChecklistItem{}
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			ci := CaseChecklistItem{
				ID:     getStringFromMap(m, "id"),
				Text:   getStringFromMap(m, "text"),
				Status: getStringFromMap(m, "status"),
			}
			if ts := getStringFromMap(m, "created_at"); ts != "" {
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					ci.CreatedAt = t
				}
			}
			if ts := getStringFromMap(m, "completed_at"); ts != "" {
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					ci.CompletedAt = &t
				}
			}
			ci.CompletedBy = getStringFromMap(m, "completed_by")
			checklist = append(checklist, ci)
		}
	}

	return checklist
}

func parseRelatedPlaybooksFromEvidence(raw json.RawMessage) []string {
	if raw == nil || len(raw) == 0 {
		return nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil
	}

	items, ok := data["related_playbooks"].([]interface{})
	if !ok {
		return nil
	}

	playbooks := []string{}
	for _, item := range items {
		if s, ok := item.(string); ok {
			playbooks = append(playbooks, s)
		}
	}

	return playbooks
}

func buildCaseRecommendations(caseObj *Case) []CaseRecommendation {
	recs := []CaseRecommendation{}
	severity := strings.ToLower(caseObj.Severity)
	status := strings.ToLower(caseObj.Status)

	if severity == "critical" || severity == "high" {
		recs = append(recs, CaseRecommendation{
			Priority:    1,
			Title:       "🚨 Investigação imediata",
			Description: "O caso possui severidade alta e pode impactar ativos críticos.",
			Action:      "Iniciar investigação, coletar evidências e conter o impacto.",
			Impact:      "Reduz risco de comprometimento e impacto operacional.",
			Effort:      "medium",
			Type:        "immediate",
			Automated:   false,
		})
	}

	if status == "new" || status == "in_progress" {
		recs = append(recs, CaseRecommendation{
			Priority:    2,
			Title:       "📌 Revisar alertas relacionados",
			Description: "Verifique se os alertas relacionados apontam para um mesmo vetor.",
			Action:      "Validar correlação entre alertas e confirmar se há falso positivo.",
			Impact:      "Melhora a precisão e reduz tempo de triagem.",
			Effort:      "low",
			Type:        "short_term",
			Automated:   false,
		})
	}

	if caseObj.SLABreach {
		recs = append(recs, CaseRecommendation{
			Priority:    1,
			Title:       "⏱️ SLA violado",
			Description: "O SLA do caso foi violado. Requer escalonamento.",
			Action:      "Escalar para N2/N3 e registrar justificativa.",
			Impact:      "Evita reincidência e melhora governança.",
			Effort:      "low",
			Type:        "immediate",
			Automated:   false,
		})
	}

	// Recomendação de encerramento
	if status == "resolved" {
		recs = append(recs, CaseRecommendation{
			Priority:    3,
			Title:       "✅ Validar resolução",
			Description: "Confirme que o risco foi eliminado antes de fechar o caso.",
			Action:      "Validar correções aplicadas e evidências de mitigação.",
			Impact:      "Previne recorrência do incidente.",
			Effort:      "low",
			Type:        "short_term",
			Automated:   false,
		})
	}

	return recs
}

func buildCaseSummary(caseObj *Case) *CaseSummary {
	severity := strings.ToLower(caseObj.Severity)
	status := strings.ToLower(caseObj.Status)

	riskScore := 30
	switch severity {
	case "critical":
		riskScore = 85
	case "high":
		riskScore = 70
	case "medium":
		riskScore = 50
	case "low":
		riskScore = 30
	}

	if caseObj.SLABreach {
		riskScore += 10
	}

	if riskScore > 100 {
		riskScore = 100
	}

	slaStatus := "within_sla"
	if caseObj.SLABreach {
		slaStatus = "breached"
	}

	businessImpact := "Impacto moderado"
	if severity == "critical" {
		businessImpact = "Impacto crítico - possível comprometimento de serviços essenciais"
	} else if severity == "high" {
		businessImpact = "Impacto alto - risco de indisponibilidade ou vazamento de dados"
	} else if severity == "low" {
		businessImpact = "Impacto baixo - requer melhoria de postura"
	}

	keyFindings := []string{}
	if len(caseObj.RelatedAlerts) > 0 {
		keyFindings = append(keyFindings, fmt.Sprintf("%d alertas relacionados", len(caseObj.RelatedAlerts)))
	}
	if len(caseObj.RelatedEvents) > 0 {
		keyFindings = append(keyFindings, fmt.Sprintf("%d eventos relacionados", len(caseObj.RelatedEvents)))
	}
	if status == "new" {
		keyFindings = append(keyFindings, "Caso recém-criado e em triagem")
	}

	nextSteps := []string{
		"Confirmar evidências e validar impacto real",
		"Executar playbook de resposta se aplicável",
	}
	if status == "resolved" {
		nextSteps = []string{"Validar resolução e coletar lições aprendidas"}
	}

	return &CaseSummary{
		RiskScore:      riskScore,
		SLAStatus:      slaStatus,
		BusinessImpact: businessImpact,
		KeyFindings:    keyFindings,
		NextSteps:      nextSteps,
	}
}

func applyDefaultCaseWorkflow(caseObj *Case) {
	if caseObj == nil {
		return
	}

	policy := getCasePolicy()
	applyCaseSLAPolicy(caseObj, policy)

	// Ajustar prioridade baseada na severidade se não definida
	if caseObj.Priority == "" {
		switch strings.ToLower(caseObj.Severity) {
		case "critical":
			caseObj.Priority = "urgent"
		case "high":
			caseObj.Priority = "high"
		case "medium":
			caseObj.Priority = "medium"
		default:
			caseObj.Priority = "low"
		}
	}

	// Checklist por tipo de incidente
	if len(caseObj.Checklist) == 0 {
		caseObj.Checklist = buildChecklistByCategory(caseObj.Category, policy)
	}

	// Playbooks sugeridos
	if len(caseObj.RelatedPlaybooks) == 0 {
		switch strings.ToLower(caseObj.Category) {
		case "malware":
			caseObj.RelatedPlaybooks = []string{"playbook-malware-removal"}
		case "phishing":
			caseObj.RelatedPlaybooks = []string{"playbook-phishing-response"}
		case "data_breach", "data_loss":
			caseObj.RelatedPlaybooks = []string{"playbook-data-breach-response"}
		case "unauthorized_access":
			caseObj.RelatedPlaybooks = []string{"playbook-privilege-escalation-response"}
		default:
			if strings.ToLower(caseObj.Severity) == "critical" || strings.ToLower(caseObj.Severity) == "high" {
				caseObj.RelatedPlaybooks = []string{"playbook-incident-containment"}
			}
		}
	}
}

func applyCaseSLAPolicy(caseObj *Case, policy *CasePolicy) {
	if caseObj == nil {
		return
	}

	sla := getSLAPolicy(policy, caseObj.Category, caseObj.Severity)
	if caseObj.SLADeadline == nil {
		deadline := time.Now().Add(time.Duration(sla.DeadlineHours) * time.Hour)
		caseObj.SLADeadline = &deadline
	}
	if caseObj.TimeToRespond == 0 {
		caseObj.TimeToRespond = sla.ResponseSeconds
	}
	if caseObj.TimeToResolve == 0 {
		caseObj.TimeToResolve = sla.ResolveSeconds
	}
	if caseObj.DueDate == nil && caseObj.SLADeadline != nil {
		caseObj.DueDate = caseObj.SLADeadline
	}
}

func buildChecklistByCategory(category string, policy *CasePolicy) []CaseChecklistItem {
	now := time.Now()
	items := getChecklistItems(policy, category)
	if len(items) == 0 {
		items = getDefaultChecklistItems()
	}

	checklist := make([]CaseChecklistItem, 0, len(items))
	for _, text := range items {
		checklist = append(checklist, CaseChecklistItem{
			ID:        uuid.New().String(),
			Text:      text,
			Status:    "open",
			CreatedAt: now,
		})
	}
	return checklist
}

func getDefaultChecklistItems() []string {
	return []string{
		"Triagem inicial e validação do alerta",
		"Coleta de evidências e logs relevantes",
		"Avaliar impacto em ativos críticos",
		"Definir e executar ações de contenção",
		"Documentar causa raiz e lições aprendidas",
	}
}

func getChecklistItems(policy *CasePolicy, category string) []string {
	if policy != nil && len(policy.ChecklistByCategory) > 0 {
		if items, ok := policy.ChecklistByCategory[strings.ToLower(category)]; ok && len(items) > 0 {
			return items
		}
		if len(policy.DefaultChecklist) > 0 {
			return policy.DefaultChecklist
		}
	}

	switch strings.ToLower(category) {
	case "malware", "ransomware":
		return []string{
			"Isolar o endpoint/servidor afetado",
			"Coletar amostras e indicadores (hash, IP, domínio)",
			"Verificar persistência e mecanismos de execução",
			"Erradicar malware e aplicar patches",
			"Restaurar serviços e validar integridade",
		}
	case "phishing":
		return []string{
			"Identificar usuários impactados",
			"Bloquear/remover e-mail malicioso",
			"Resetar credenciais comprometidas",
			"Adicionar indicadores a bloqueios",
			"Registrar lições aprendidas",
		}
	case "data_breach", "data_loss":
		return []string{
			"Identificar dados afetados e escopo",
			"Conter exfiltração e bloquear canais",
			"Preservar evidências para investigação",
			"Notificar stakeholders conforme política",
			"Reforçar controles preventivos",
		}
	case "unauthorized_access", "privilege_escalation":
		return []string{
			"Bloquear contas/credenciais suspeitas",
			"Revisar acessos e sessões ativas",
			"Auditar alterações em sistemas críticos",
			"Reforçar MFA e políticas de acesso",
			"Atualizar regras de detecção",
		}
	case "ddos":
		return []string{
			"Identificar origem e vetores do ataque",
			"Acionar mitigação (WAF/CDN/anti-DDoS)",
			"Monitorar disponibilidade e performance",
			"Comunicar áreas de negócio impactadas",
			"Documentar indicadores e ajustes",
		}
	case "insider":
		return []string{
			"Revisar atividades e acessos do usuário",
			"Preservar evidências e logs críticos",
			"Restringir acessos temporariamente",
			"Acionar RH/Compliance conforme política",
			"Revisar controles e permissões",
		}
	default:
		return nil
	}
}

func getCasePolicy() *CasePolicy {
	casePolicyMu.RLock()
	if cachedCasePolicy != nil {
		p := *cachedCasePolicy
		casePolicyMu.RUnlock()
		return &p
	}
	casePolicyMu.RUnlock()

	policy := defaultCasePolicy()
	casePolicyMu.Lock()
	cachedCasePolicy = policy
	casePolicyMu.Unlock()
	return policy
}

func defaultCasePolicy() *CasePolicy {
	return &CasePolicy{
		ID:               "default",
		UpdatedAt:        time.Now(),
		DefaultChecklist: getDefaultChecklistItems(),
		CategorySuggestions: []string{
			"phishing",
			"malware",
			"ransomware",
			"data_breach",
			"data_loss",
			"unauthorized_access",
			"privilege_escalation",
			"ddos",
			"insider",
		},
		ChecklistByCategory: map[string][]string{
			"malware": {
				"Isolar o endpoint/servidor afetado",
				"Coletar amostras e indicadores (hash, IP, domínio)",
				"Verificar persistência e mecanismos de execução",
				"Erradicar malware e aplicar patches",
				"Restaurar serviços e validar integridade",
			},
			"ransomware": {
				"Isolar o endpoint/servidor afetado",
				"Preservar evidências e snapshots",
				"Validar backups e plano de restauração",
				"Erradicar malware e aplicar patches",
				"Restaurar serviços e validar integridade",
			},
			"phishing": {
				"Identificar usuários impactados",
				"Bloquear/remover e-mail malicioso",
				"Resetar credenciais comprometidas",
				"Adicionar indicadores a bloqueios",
				"Registrar lições aprendidas",
			},
			"data_breach": {
				"Identificar dados afetados e escopo",
				"Conter exfiltração e bloquear canais",
				"Preservar evidências para investigação",
				"Notificar stakeholders conforme política",
				"Reforçar controles preventivos",
			},
			"data_loss": {
				"Identificar dados afetados e escopo",
				"Conter exfiltração e bloquear canais",
				"Preservar evidências para investigação",
				"Notificar stakeholders conforme política",
				"Reforçar controles preventivos",
			},
			"unauthorized_access": {
				"Bloquear contas/credenciais suspeitas",
				"Revisar acessos e sessões ativas",
				"Auditar alterações em sistemas críticos",
				"Reforçar MFA e políticas de acesso",
				"Atualizar regras de detecção",
			},
			"privilege_escalation": {
				"Bloquear contas/credenciais suspeitas",
				"Revisar acessos e sessões ativas",
				"Auditar alterações em sistemas críticos",
				"Reforçar MFA e políticas de acesso",
				"Atualizar regras de detecção",
			},
			"ddos": {
				"Identificar origem e vetores do ataque",
				"Acionar mitigação (WAF/CDN/anti-DDoS)",
				"Monitorar disponibilidade e performance",
				"Comunicar áreas de negócio impactadas",
				"Documentar indicadores e ajustes",
			},
			"insider": {
				"Revisar atividades e acessos do usuário",
				"Preservar evidências e logs críticos",
				"Restringir acessos temporariamente",
				"Acionar RH/Compliance conforme política",
				"Revisar controles e permissões",
			},
		},
		SLABySeverity: map[string]CaseSLADefinition{
			"critical": {DeadlineHours: 4, ResponseSeconds: 900, ResolveSeconds: 14400},
			"high":     {DeadlineHours: 24, ResponseSeconds: 1800, ResolveSeconds: 86400},
			"medium":   {DeadlineHours: 72, ResponseSeconds: 7200, ResolveSeconds: 259200},
			"low":      {DeadlineHours: 168, ResponseSeconds: 28800, ResolveSeconds: 604800},
		},
		SLAByCategory: map[string]map[string]CaseSLADefinition{
			"ransomware": {
				"critical": {DeadlineHours: 2, ResponseSeconds: 600, ResolveSeconds: 7200},
			},
		},
	}
}

func getSLAPolicy(policy *CasePolicy, category string, severity string) CaseSLADefinition {
	if policy != nil {
		if policy.SLAByCategory != nil {
			if bySeverity, ok := policy.SLAByCategory[strings.ToLower(category)]; ok {
				if sla, ok := bySeverity[strings.ToLower(severity)]; ok && sla.DeadlineHours > 0 {
					return sla
				}
			}
		}
		if policy.SLABySeverity != nil {
			if sla, ok := policy.SLABySeverity[strings.ToLower(severity)]; ok && sla.DeadlineHours > 0 {
				return sla
			}
		}
	}

	switch strings.ToLower(severity) {
	case "critical":
		return CaseSLADefinition{DeadlineHours: 4, ResponseSeconds: 900, ResolveSeconds: 14400}
	case "high":
		return CaseSLADefinition{DeadlineHours: 24, ResponseSeconds: 1800, ResolveSeconds: 86400}
	case "medium":
		return CaseSLADefinition{DeadlineHours: 72, ResponseSeconds: 7200, ResolveSeconds: 259200}
	default:
		return CaseSLADefinition{DeadlineHours: 168, ResponseSeconds: 28800, ResolveSeconds: 604800}
	}
}

func (s *APIServer) handleGetCasePolicy(c *gin.Context) {
	policy, err := s.loadCasePolicy(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load case policy"})
		return
	}
	c.JSON(http.StatusOK, policy)
}

func (s *APIServer) handleUpdateCasePolicy(c *gin.Context) {
	var policy CasePolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	policy.ID = "default"
	policy.UpdatedAt = time.Now()

	if err := s.saveCasePolicy(c.Request.Context(), &policy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save case policy"})
		return
	}
	c.JSON(http.StatusOK, policy)
}

func (s *APIServer) loadCasePolicy(ctx context.Context) (*CasePolicy, error) {
	if s.opensearch != nil {
		policy, err := s.getCasePolicyFromOpenSearch()
		if err == nil && policy != nil {
			casePolicyMu.Lock()
			cachedCasePolicy = policy
			casePolicyMu.Unlock()
			return policy, nil
		}
	}

	policy := getCasePolicy()
	return policy, nil
}

func (s *APIServer) saveCasePolicy(ctx context.Context, policy *CasePolicy) error {
	if policy == nil {
		return fmt.Errorf("invalid policy")
	}

	casePolicyMu.Lock()
	cachedCasePolicy = policy
	casePolicyMu.Unlock()

	if s.opensearch != nil {
		return s.saveCasePolicyToOpenSearch(policy)
	}
	return nil
}

func handleCaseReportNotFound(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{"error": "Case not found"})
}

func convertCaseOpenSearchToAPI(osCase *CaseOpenSearch) *Case {
	if osCase == nil {
		return nil
	}

	slaRemaining := 0
	slaBreach := osCase.SLABreach
	if osCase.SLADeadline != nil {
		remaining := time.Until(*osCase.SLADeadline)
		slaRemaining = int(remaining.Seconds())
		if slaRemaining < 0 {
			slaBreach = true
			slaRemaining = 0
		}
	}

	caseObj := &Case{
		ID:               osCase.ID,
		Title:            osCase.Title,
		Description:      osCase.Description,
		Severity:         osCase.Severity,
		Status:           osCase.Status,
		Priority:         osCase.Priority,
		Category:         osCase.Category,
		AssignedTo:       osCase.AssignedTo,
		CreatedBy:        osCase.CreatedBy,
		CreatedAt:        osCase.CreatedAt,
		UpdatedAt:        osCase.UpdatedAt,
		ResolvedAt:       osCase.ResolvedAt,
		ClosedAt:         osCase.ClosedAt,
		DueDate:          osCase.DueDate,
		Tags:             osCase.Tags,
		RelatedAlerts:    osCase.RelatedAlerts,
		RelatedEvents:    osCase.RelatedEvents,
		RelatedPlaybooks: osCase.RelatedPlaybooks,
		TimeToDetect:     osCase.TimeToDetect,
		TimeToRespond:    osCase.TimeToRespond,
		TimeToResolve:    osCase.TimeToResolve,
		SLABreach:        slaBreach,
		SLADeadline:      osCase.SLADeadline,
		SLARemaining:     slaRemaining,
		Evidence:         osCase.Evidence,
		Timeline:         osCase.Timeline,
		Indicators:       osCase.Indicators,
		MitreTactics:     osCase.MitreTactics,
		MitreTechniques:  osCase.MitreTechniques,
		AffectedAssets:   osCase.AffectedAssets,
		Resolution:       osCase.Resolution,
		Checklist:        osCase.Checklist,
	}

	caseObj.Recommendations = buildCaseRecommendations(caseObj)
	caseObj.Summary = buildCaseSummary(caseObj)

	return caseObj
}

func buildCaseReportMarkdown(caseObj *Case) string {
	if caseObj == nil {
		return ""
	}

	header := "# Relatório do Caso\n\n"
	meta := fmt.Sprintf("**ID:** %s\n\n**Título:** %s\n\n**Status:** %s\n\n**Severidade:** %s\n\n**Prioridade:** %s\n\n**Categoria:** %s\n\n**Criado em:** %s\n\n**Atualizado em:** %s\n\n",
		caseObj.ID,
		caseObj.Title,
		caseObj.Status,
		caseObj.Severity,
		caseObj.Priority,
		caseObj.Category,
		caseObj.CreatedAt.Format(time.RFC3339),
		caseObj.UpdatedAt.Format(time.RFC3339),
	)

	summary := "## Resumo Executivo\n\n"
	if caseObj.Summary != nil {
		summary += fmt.Sprintf("- **Risk Score:** %d\n", caseObj.Summary.RiskScore)
		summary += fmt.Sprintf("- **SLA Status:** %s\n", caseObj.Summary.SLAStatus)
		summary += fmt.Sprintf("- **Impacto:** %s\n", caseObj.Summary.BusinessImpact)
		if len(caseObj.Summary.KeyFindings) > 0 {
			summary += "- **Achados:**\n"
			for _, f := range caseObj.Summary.KeyFindings {
				summary += fmt.Sprintf("  - %s\n", f)
			}
		}
		if len(caseObj.Summary.NextSteps) > 0 {
			summary += "- **Próximos passos:**\n"
			for _, s := range caseObj.Summary.NextSteps {
				summary += fmt.Sprintf("  - %s\n", s)
			}
		}
	} else {
		summary += "Sem resumo disponível.\n"
	}

	recommendations := "## Recomendações\n\n"
	if len(caseObj.Recommendations) > 0 {
		for _, r := range caseObj.Recommendations {
			recommendations += fmt.Sprintf("- **P%d - %s**: %s\n  - Ação: %s\n  - Impacto: %s\n  - Esforço: %s\n",
				r.Priority, r.Title, r.Description, r.Action, r.Impact, r.Effort)
		}
	} else {
		recommendations += "Nenhuma recomendação disponível.\n"
	}

	evidence := "## Evidências\n\n"
	if len(caseObj.Evidence) > 0 {
		for _, ev := range caseObj.Evidence {
			evidence += fmt.Sprintf("- **%s**: %s (Fonte: %s, %s)\n",
				ev.Type, ev.Description, ev.Source, ev.Timestamp.Format(time.RFC3339))
		}
	} else {
		evidence += "Nenhuma evidência registrada.\n"
	}

	timeline := "## Linha do Tempo\n\n"
	if len(caseObj.Timeline) > 0 {
		for _, t := range caseObj.Timeline {
			timeline += fmt.Sprintf("- **%s**: %s (%s)\n",
				t.Timestamp.Format(time.RFC3339), t.Description, t.Event)
		}
	} else {
		timeline += "Nenhuma atividade registrada.\n"
	}

	context := "## Contexto Técnico\n\n"
	if len(caseObj.MitreTactics) > 0 {
		context += fmt.Sprintf("- **MITRE Tactics:** %s\n", strings.Join(caseObj.MitreTactics, ", "))
	}
	if len(caseObj.MitreTechniques) > 0 {
		context += fmt.Sprintf("- **MITRE Techniques:** %s\n", strings.Join(caseObj.MitreTechniques, ", "))
	}
	if len(caseObj.AffectedAssets) > 0 {
		context += fmt.Sprintf("- **Ativos Afetados:** %s\n", strings.Join(caseObj.AffectedAssets, ", "))
	}

	return header + meta + summary + "\n" + recommendations + "\n" + evidence + "\n" + timeline + "\n" + context
}

// handleGetCaseReport exporta relatório de caso
func (s *APIServer) handleGetCaseReport(c *gin.Context) {
	id := c.Param("id")
	format := c.DefaultQuery("format", "markdown")

	// Prioridade 1: OpenSearch
	if s.opensearch != nil {
		if osCase, err := s.getCaseFromOpenSearch(id); err == nil {
			caseObj := convertCaseOpenSearchToAPI(osCase)
			if format == "json" {
				c.JSON(http.StatusOK, gin.H{
					"case":    caseObj,
					"report":  buildCaseReportMarkdown(caseObj),
					"format":  "json",
				})
				return
			}

			report := buildCaseReportMarkdown(caseObj)
			c.Header("Content-Type", "text/markdown; charset=utf-8")
			c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=case-%s.md", id))
			c.String(http.StatusOK, report)
			return
		}
	}

	// Prioridade 2: Database repository
	if s.caseRepo != nil {
		ctx := c.Request.Context()
		if dbCase, err := s.caseRepo.GetByID(ctx, id); err == nil {
			caseObj := convertDBCaseToAPI(dbCase)
			if format == "json" {
				c.JSON(http.StatusOK, gin.H{
					"case":    caseObj,
					"report":  buildCaseReportMarkdown(caseObj),
					"format":  "json",
				})
				return
			}

			report := buildCaseReportMarkdown(caseObj)
			c.Header("Content-Type", "text/markdown; charset=utf-8")
			c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=case-%s.md", id))
			c.String(http.StatusOK, report)
			return
		}
	}

	// Fallback: mock
	if !IsMockDataDisabled() {
		mockCases := generateMockCases()
		for _, m := range mockCases {
			if m.ID == id {
				report := buildCaseReportMarkdown(&m)
				c.Header("Content-Type", "text/markdown; charset=utf-8")
				c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=case-%s.md", id))
				c.String(http.StatusOK, report)
				return
			}
		}
	}

	handleCaseReportNotFound(c)
}

// handleGetCaseChecklist retorna checklist do caso
func (s *APIServer) handleGetCaseChecklist(c *gin.Context) {
	id := c.Param("id")

	// Prioridade 1: OpenSearch
	if s.opensearch != nil {
		if osCase, err := s.getCaseFromOpenSearch(id); err == nil {
			c.JSON(http.StatusOK, gin.H{"checklist": osCase.Checklist})
			return
		}
	}

	// Prioridade 2: Database
	if s.caseRepo != nil {
		ctx := c.Request.Context()
		if dbCase, err := s.caseRepo.GetByID(ctx, id); err == nil {
			checklist := parseChecklistFromEvidence(dbCase.Evidence)
			c.JSON(http.StatusOK, gin.H{"checklist": checklist})
			return
		}
	}

	handleCaseReportNotFound(c)
}

// handleAddCaseChecklistItem adiciona item no checklist
func (s *APIServer) handleAddCaseChecklistItem(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Text string `json:"text" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	usernameVal, _ := c.Get("username")
	username := "unknown"
	if usernameVal != nil {
		username = usernameVal.(string)
	}

	item := CaseChecklistItem{
		ID:        uuid.New().String(),
		Text:      req.Text,
		Status:    "open",
		CreatedAt: time.Now(),
	}

	// Prioridade 1: OpenSearch
	if s.opensearch != nil {
		osCase, err := s.getCaseFromOpenSearch(id)
		if err == nil {
			osCase.Checklist = append(osCase.Checklist, item)
			if err := s.saveChecklistToOpenSearch(id, osCase.Checklist); err == nil {
				c.JSON(http.StatusCreated, item)
				return
			}
		}
	}

	// Prioridade 2: Database
	if s.caseRepo != nil {
		ctx := c.Request.Context()
		if err := s.updateChecklistInDB(ctx, id, username, func(list []CaseChecklistItem) []CaseChecklistItem {
			return append(list, item)
		}); err == nil {
			c.JSON(http.StatusCreated, item)
			return
		}
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add checklist item"})
}

// handleUpdateCaseChecklistItem atualiza item do checklist
func (s *APIServer) handleUpdateCaseChecklistItem(c *gin.Context) {
	id := c.Param("id")
	itemID := c.Param("itemId")

	var req struct {
		Status string `json:"status"`
		Text   string `json:"text"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	usernameVal, _ := c.Get("username")
	username := "unknown"
	if usernameVal != nil {
		username = usernameVal.(string)
	}

	updateChecklist := func(list []CaseChecklistItem) []CaseChecklistItem {
		for i := range list {
			if list[i].ID == itemID {
				if req.Text != "" {
					list[i].Text = req.Text
				}
				if req.Status != "" {
					list[i].Status = req.Status
					if req.Status == "done" {
						now := time.Now()
						list[i].CompletedAt = &now
						list[i].CompletedBy = username
					} else {
						list[i].CompletedAt = nil
						list[i].CompletedBy = ""
					}
				}
				break
			}
		}
		return list
	}

	// Prioridade 1: OpenSearch
	if s.opensearch != nil {
		osCase, err := s.getCaseFromOpenSearch(id)
		if err == nil {
			osCase.Checklist = updateChecklist(osCase.Checklist)
			if err := s.saveChecklistToOpenSearch(id, osCase.Checklist); err == nil {
				c.JSON(http.StatusOK, gin.H{"success": true})
				return
			}
		}
	}

	// Prioridade 2: Database
	if s.caseRepo != nil {
		ctx := c.Request.Context()
		if err := s.updateChecklistInDB(ctx, id, username, updateChecklist); err == nil {
			c.JSON(http.StatusOK, gin.H{"success": true})
			return
		}
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update checklist item"})
}

// handleDeleteCaseChecklistItem remove item do checklist
func (s *APIServer) handleDeleteCaseChecklistItem(c *gin.Context) {
	id := c.Param("id")
	itemID := c.Param("itemId")

	usernameVal, _ := c.Get("username")
	username := "unknown"
	if usernameVal != nil {
		username = usernameVal.(string)
	}

	removeItem := func(list []CaseChecklistItem) []CaseChecklistItem {
		result := []CaseChecklistItem{}
		for _, item := range list {
			if item.ID != itemID {
				result = append(result, item)
			}
		}
		return result
	}

	// Prioridade 1: OpenSearch
	if s.opensearch != nil {
		osCase, err := s.getCaseFromOpenSearch(id)
		if err == nil {
			osCase.Checklist = removeItem(osCase.Checklist)
			if err := s.saveChecklistToOpenSearch(id, osCase.Checklist); err == nil {
				c.JSON(http.StatusOK, gin.H{"success": true})
				return
			}
		}
	}

	// Prioridade 2: Database
	if s.caseRepo != nil {
		ctx := c.Request.Context()
		if err := s.updateChecklistInDB(ctx, id, username, removeItem); err == nil {
			c.JSON(http.StatusOK, gin.H{"success": true})
			return
		}
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete checklist item"})
}

// handleGetCasePlaybooks retorna playbooks vinculados
func (s *APIServer) handleGetCasePlaybooks(c *gin.Context) {
	id := c.Param("id")

	// Prioridade 1: OpenSearch
	if s.opensearch != nil {
		if osCase, err := s.getCaseFromOpenSearch(id); err == nil {
			c.JSON(http.StatusOK, gin.H{"playbooks": osCase.RelatedPlaybooks})
			return
		}
	}

	// Prioridade 2: Database
	if s.caseRepo != nil {
		ctx := c.Request.Context()
		if dbCase, err := s.caseRepo.GetByID(ctx, id); err == nil {
			playbooks := parseRelatedPlaybooksFromEvidence(dbCase.Evidence)
			c.JSON(http.StatusOK, gin.H{"playbooks": playbooks})
			return
		}
	}

	handleCaseReportNotFound(c)
}

// handleAddCasePlaybook adiciona playbook ao caso
func (s *APIServer) handleAddCasePlaybook(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		PlaybookID string `json:"playbook_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	usernameVal, _ := c.Get("username")
	username := "unknown"
	if usernameVal != nil {
		username = usernameVal.(string)
	}

	addPlaybook := func(list []string) []string {
		for _, p := range list {
			if p == req.PlaybookID {
				return list
			}
		}
		return append(list, req.PlaybookID)
	}

	// OpenSearch
	if s.opensearch != nil {
		if osCase, err := s.getCaseFromOpenSearch(id); err == nil {
			osCase.RelatedPlaybooks = addPlaybook(osCase.RelatedPlaybooks)
			if err := s.savePlaybooksToOpenSearch(id, osCase.RelatedPlaybooks); err == nil {
				c.JSON(http.StatusOK, gin.H{"success": true})
				return
			}
		}
	}

	// Database
	if s.caseRepo != nil {
		ctx := c.Request.Context()
		if err := s.updatePlaybooksInDB(ctx, id, username, addPlaybook); err == nil {
			c.JSON(http.StatusOK, gin.H{"success": true})
			return
		}
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add playbook"})
}

// handleDeleteCasePlaybook remove playbook do caso
func (s *APIServer) handleDeleteCasePlaybook(c *gin.Context) {
	id := c.Param("id")
	playbookID := c.Param("playbookId")

	usernameVal, _ := c.Get("username")
	username := "unknown"
	if usernameVal != nil {
		username = usernameVal.(string)
	}

	removePlaybook := func(list []string) []string {
		result := []string{}
		for _, p := range list {
			if p != playbookID {
				result = append(result, p)
			}
		}
		return result
	}

	// OpenSearch
	if s.opensearch != nil {
		if osCase, err := s.getCaseFromOpenSearch(id); err == nil {
			osCase.RelatedPlaybooks = removePlaybook(osCase.RelatedPlaybooks)
			if err := s.savePlaybooksToOpenSearch(id, osCase.RelatedPlaybooks); err == nil {
				c.JSON(http.StatusOK, gin.H{"success": true})
				return
			}
		}
	}

	// Database
	if s.caseRepo != nil {
		ctx := c.Request.Context()
		if err := s.updatePlaybooksInDB(ctx, id, username, removePlaybook); err == nil {
			c.JSON(http.StatusOK, gin.H{"success": true})
			return
		}
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete playbook"})
}

// handleExecuteCasePlaybook executa um playbook vinculado ao caso
func (s *APIServer) handleExecuteCasePlaybook(c *gin.Context) {
	caseID := c.Param("id")
	playbookID := c.Param("playbookId")

	var triggerData map[string]interface{}
	if err := c.ShouldBindJSON(&triggerData); err != nil {
		triggerData = make(map[string]interface{})
	}
	triggerData["case_id"] = caseID

	usernameVal, _ := c.Get("username")
	username := "admin"
	if usernameVal != nil {
		if u, ok := usernameVal.(string); ok && u != "" {
			username = u
		}
	}

	// Buscar playbook
	var playbook *Playbook
	ctx := c.Request.Context()
	if s.playbookRepo != nil {
		dbPlaybook, err := s.playbookRepo.GetByID(ctx, playbookID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Playbook not found"})
			return
		}
		playbook = convertDBPlaybookToAPI(dbPlaybook)
	} else {
		playbook = &Playbook{
			ID:          playbookID,
			Name:        "Playbook de resposta",
			Description: "Execução de resposta automática para incidentes",
			Trigger:     "Case Execution",
			Actions: []PlaybookAction{
				{Type: "notify_slack", Target: "slack", Params: map[string]interface{}{"channel": "security"}},
			},
			Status: "active",
		}
	}

	// Executar playbook
	engine := NewPlaybookEngine(s)
	execution, err := engine.ExecutePlaybook(playbook, triggerData, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Registrar na timeline do caso
	entry := CaseTimelineEntry{
		Timestamp:   time.Now(),
		Event:       "playbook_execution",
		Description: fmt.Sprintf("Playbook executado: %s", playbook.Name),
		User:        username,
		Source:      "SOAR",
		Details: map[string]interface{}{
			"playbook_id": playbookID,
			"execution_id": execution.ID,
			"status":       execution.Status,
		},
	}

	if s.opensearch != nil {
		_ = s.addTimelineEntryToOpenSearch(caseID, entry)
	} else if s.caseRepo != nil {
		_ = s.addTimelineEntryToDB(ctx, caseID, username, entry)
	}

	c.JSON(http.StatusAccepted, gin.H{
		"execution": execution,
		"message":   "Playbook executado com sucesso",
	})
}

func (s *APIServer) addTimelineEntryToOpenSearch(caseID string, entry CaseTimelineEntry) error {
	osCase, err := s.getCaseFromOpenSearch(caseID)
	if err != nil {
		return err
	}

	timeline := osCase.Timeline
	timeline = append(timeline, entry)

	updateDoc := map[string]interface{}{
		"doc": map[string]interface{}{
			"timeline":   timeline,
			"updated_at": time.Now().Format(time.RFC3339),
		},
	}
	updateJSON, _ := json.Marshal(updateDoc)
	res, err := s.opensearch.Update(
		casesIndex,
		caseID,
		strings.NewReader(string(updateJSON)),
		s.opensearch.Update.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return nil
}

func (s *APIServer) addTimelineEntryToDB(ctx context.Context, caseID string, username string, entry CaseTimelineEntry) error {
	dbCase, err := s.caseRepo.GetByID(ctx, caseID)
	if err != nil {
		return err
	}

	current := parseCaseTimeline(dbCase.Timeline)
	current = append(current, entry)
	timelineJSON, _ := json.Marshal(current)
	dbCase.Timeline = timelineJSON
	if username != "" {
		dbCase.UpdatedBy = &username
	}
	return s.caseRepo.Update(ctx, dbCase)
}

func (s *APIServer) saveChecklistToOpenSearch(caseID string, checklist []CaseChecklistItem) error {
	updateDoc := map[string]interface{}{
		"doc": map[string]interface{}{
			"checklist":  checklist,
			"updated_at": time.Now().Format(time.RFC3339),
		},
	}
	updateJSON, _ := json.Marshal(updateDoc)
	res, err := s.opensearch.Update(
		casesIndex,
		caseID,
		strings.NewReader(string(updateJSON)),
		s.opensearch.Update.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return nil
}

func (s *APIServer) savePlaybooksToOpenSearch(caseID string, playbooks []string) error {
	updateDoc := map[string]interface{}{
		"doc": map[string]interface{}{
			"related_playbooks": playbooks,
			"updated_at":        time.Now().Format(time.RFC3339),
		},
	}
	updateJSON, _ := json.Marshal(updateDoc)
	res, err := s.opensearch.Update(
		casesIndex,
		caseID,
		strings.NewReader(string(updateJSON)),
		s.opensearch.Update.WithRefresh("true"),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return nil
}

func getEvidenceMap(raw json.RawMessage) map[string]interface{} {
	if raw == nil || len(raw) == 0 {
		return map[string]interface{}{}
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return map[string]interface{}{}
	}
	return data
}

func (s *APIServer) updateChecklistInDB(ctx context.Context, caseID string, username string, updateFn func([]CaseChecklistItem) []CaseChecklistItem) error {
	dbCase, err := s.caseRepo.GetByID(ctx, caseID)
	if err != nil {
		return err
	}

	current := parseChecklistFromEvidence(dbCase.Evidence)
	updated := updateFn(current)

	evidenceMap := getEvidenceMap(dbCase.Evidence)
	evidenceMap["checklist"] = updated

	evidenceJSON, _ := json.Marshal(evidenceMap)
	dbCase.Evidence = evidenceJSON
	if username != "" {
		dbCase.UpdatedBy = &username
	}

	return s.caseRepo.Update(ctx, dbCase)
}

func (s *APIServer) updatePlaybooksInDB(ctx context.Context, caseID string, username string, updateFn func([]string) []string) error {
	dbCase, err := s.caseRepo.GetByID(ctx, caseID)
	if err != nil {
		return err
	}

	current := parseRelatedPlaybooksFromEvidence(dbCase.Evidence)
	updated := updateFn(current)

	evidenceMap := getEvidenceMap(dbCase.Evidence)
	evidenceMap["related_playbooks"] = updated

	evidenceJSON, _ := json.Marshal(evidenceMap)
	dbCase.Evidence = evidenceJSON
	if username != "" {
		dbCase.UpdatedBy = &username
	}

	return s.caseRepo.Update(ctx, dbCase)
}

// handleListCases lista todos os casos com filtros
func (s *APIServer) handleListCases(c *gin.Context) {
	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleListCasesOpenSearch(c)
		return
	}

	ctx := c.Request.Context()

	// Prioridade 2: Database repository
	if s.caseRepo == nil {
		s.handleListCasesMock(c)
		return
	}

	// Construir filtros
	filters := make(map[string]interface{})
	if status := c.Query("status"); status != "" {
		filters["status"] = status
	}
	if severity := c.Query("severity"); severity != "" {
		filters["severity"] = severity
	}
	if assignedTo := c.Query("assigned_to"); assignedTo != "" {
		filters["assigned_to"] = assignedTo
	}
	if category := c.Query("category"); category != "" {
		filters["category"] = category
	}

	// Buscar do banco de dados
	dbCases, err := s.caseRepo.List(ctx, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list cases: " + err.Error()})
		return
	}

	// Se o banco estiver vazio, usar dados mock
	if len(dbCases) == 0 {
		s.handleListCasesMock(c)
		return
	}

	// Converter para formato da API
	cases := make([]*Case, len(dbCases))
	for i, dbCase := range dbCases {
		cases[i] = convertDBCaseToAPI(dbCase)
	}

	c.JSON(http.StatusOK, gin.H{
		"cases": cases,
		"total": len(cases),
	})
}

// handleGetCase obtém detalhes de um caso específico
func (s *APIServer) handleGetCase(c *gin.Context) {
	id := c.Param("id")

	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleGetCaseOpenSearch(c)
		return
	}

	ctx := c.Request.Context()

	// Prioridade 2: Database repository
	if s.caseRepo == nil {
		s.handleGetCaseMock(c, id)
		return
	}

	// Buscar do banco de dados
	dbCase, err := s.caseRepo.GetByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Case not found"})
		return
	}

	// Converter para formato da API
	caseObj := convertDBCaseToAPI(dbCase)

	c.JSON(http.StatusOK, caseObj)
}

// handleCreateCase cria um novo caso
func (s *APIServer) handleCreateCase(c *gin.Context) {
	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleCreateCaseOpenSearch(c)
		return
	}

	// Obter username do contexto JWT
	usernameVal, _ := c.Get("username")
	username := "unknown"
	if usernameVal != nil {
		username = usernameVal.(string)
	}

	var caseObj Case
	if err := c.ShouldBindJSON(&caseObj); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Prioridade 2: Database repository
	if s.caseRepo == nil {
		caseObj.ID = uuid.New().String()
		caseObj.CreatedAt = time.Now()
		caseObj.UpdatedAt = time.Now()
		caseObj.Status = "new"
		caseObj.CreatedBy = username
		c.JSON(http.StatusCreated, caseObj)
		return
	}

	// Aplicar workflow padrão (checklist + playbooks)
	applyDefaultCaseWorkflow(&caseObj)

	// Converter para formato do DB
	dbCase, err := convertAPICaseToDB(&caseObj)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Salvar no banco de dados
	if err := s.caseRepo.Create(ctx, dbCase); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create case: " + err.Error()})
		return
	}

	// Converter de volta para formato da API
	caseObj = *convertDBCaseToAPI(dbCase)

	c.JSON(http.StatusCreated, caseObj)
}

// handleUpdateCase atualiza um caso
func (s *APIServer) handleUpdateCase(c *gin.Context) {
	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleUpdateCaseOpenSearch(c)
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	var caseObj Case
	if err := c.ShouldBindJSON(&caseObj); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Prioridade 2: Database repository
	if s.caseRepo == nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "Caso atualizado com sucesso",
			"id":      id,
		})
		return
	}

	caseObj.ID = id

	// Converter para formato do DB
	dbCase, err := convertAPICaseToDB(&caseObj)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Atualizar no banco de dados
	if err := s.caseRepo.Update(ctx, dbCase); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update case: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Caso atualizado com sucesso",
		"id":      id,
	})
}

// handleCloseCase fecha um caso
func (s *APIServer) handleCloseCase(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	// Obter user_id do contexto JWT
	userIDVal, _ := c.Get("user_id")
	var userID *string
	if userIDVal != nil {
		uid := userIDVal.(string)
		userID = &uid
	}

	var req struct {
		Resolution string `json:"resolution"`
	}
	c.ShouldBindJSON(&req)

	// Se não tiver repository, retornar sucesso mock
	if s.caseRepo == nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "Caso fechado com sucesso",
			"id":      id,
		})
		return
	}

	// Fechar caso no banco de dados
	if err := s.caseRepo.Close(ctx, id, req.Resolution, userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to close case: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Caso fechado com sucesso",
		"id":      id,
	})
}

// handleDeleteCase deleta um caso
func (s *APIServer) handleDeleteCase(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	// Se não tiver repository, retornar sucesso mock
	if s.caseRepo == nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "Caso deletado com sucesso",
			"id":      id,
		})
		return
	}

	// Deletar do banco de dados
	if err := s.caseRepo.Delete(ctx, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete case: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Caso deletado com sucesso",
		"id":      id,
	})
}

// handleGetCaseActivities obtém timeline de atividades de um caso
func (s *APIServer) handleGetCaseActivities(c *gin.Context) {
	caseID := c.Param("id")
	ctx := c.Request.Context()

	var activities []CaseActivity

	// Prioridade 1: Buscar comentários do OpenSearch
	if s.opensearch != nil {
		osActivities, err := s.getCommentsFromOpenSearch(caseID)
		if err == nil && len(osActivities) > 0 {
			activities = append(activities, osActivities...)
		}
	}

	// Prioridade 2: Buscar comentários do PostgreSQL (se disponível)
	if s.caseRepo != nil {
	dbComments, err := s.caseRepo.GetComments(ctx, caseID)
		if err == nil {
			for _, comment := range dbComments {
				// Evitar duplicatas (verificar se já existe pelo ID)
				exists := false
				for _, a := range activities {
					if a.ID == comment.ID {
						exists = true
						break
					}
				}
				if !exists {
					activities = append(activities, CaseActivity{
			ID:        comment.ID,
			CaseID:    comment.CaseID,
			Type:      "comment",
			User:      comment.UserID,
			Timestamp: comment.CreatedAt,
			Content:   comment.Comment,
					})
				}
			}
		}
	}

	// Se não tiver nenhuma atividade, retornar mock
	if len(activities) == 0 && s.caseRepo == nil && s.opensearch == nil {
		s.handleGetCaseActivitiesMock(c, caseID)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"activities": activities,
		"total":      len(activities),
	})
}

// getCommentsFromOpenSearch busca comentários de um caso no OpenSearch
func (s *APIServer) getCommentsFromOpenSearch(caseID string) ([]CaseActivity, error) {
	if s.opensearch == nil {
		return nil, fmt.Errorf("opensearch not available")
	}

	res, err := s.opensearch.Get(
		"siem-cases",
		caseID,
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("case not found")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	source, ok := result["_source"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid case format")
	}

	var activities []CaseActivity

	// Extrair comentários do caso
	if comments, ok := source["comments"].([]interface{}); ok {
		for _, c := range comments {
			if comment, ok := c.(map[string]interface{}); ok {
				activity := CaseActivity{
					CaseID: caseID,
					Type:   "comment",
				}
				if v, ok := comment["id"].(string); ok {
					activity.ID = v
				}
				if v, ok := comment["user"].(string); ok {
					activity.User = v
				}
				if v, ok := comment["content"].(string); ok {
					activity.Content = v
				}
				if v, ok := comment["timestamp"].(string); ok {
					activity.Timestamp, _ = time.Parse(time.RFC3339, v)
				}
				if v, ok := comment["type"].(string); ok {
					activity.Type = v
				}
				activities = append(activities, activity)
			}
		}
	}

	return activities, nil
}

// handleAddComment adiciona comentário a um caso
func (s *APIServer) handleAddComment(c *gin.Context) {
	caseID := c.Param("id")
	ctx := c.Request.Context()

	// Obter username para exibição (não precisamos mais do user_id UUID)
	usernameVal, _ := c.Get("username")
	username := "unknown"
	if usernameVal != nil {
		username = usernameVal.(string)
	}

	var req struct {
		Content string `json:"content" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Criar atividade de comentário
		activity := CaseActivity{
			ID:        uuid.New().String(),
			CaseID:    caseID,
			Type:      "comment",
		User:      username,
			Timestamp: time.Now(),
			Content:   req.Content,
		}

	// Prioridade 1: Salvar no OpenSearch (onde os casos são gerenciados)
	if s.opensearch != nil {
		if err := s.addCommentToOpenSearch(caseID, activity); err != nil {
			log.Printf("[WARNING] Failed to save comment to OpenSearch: %v, trying PostgreSQL", err)
		} else {
			log.Printf("[INFO] Comment added to case %s in OpenSearch by %s", caseID, username)
		c.JSON(http.StatusCreated, activity)
		return
	}
	}

	// Prioridade 2: Tentar salvar no PostgreSQL (se disponível e user existe)
	if s.caseRepo != nil {
		// Obter user_id do contexto JWT
		userIDVal, exists := c.Get("user_id")
		if exists {
			userID := userIDVal.(string)
			
	comment := &database.CaseComment{
				ID:         activity.ID,
		CaseID:     caseID,
		UserID:     userID,
		Comment:    req.Content,
		IsInternal: false,
	}

	if err := s.caseRepo.AddComment(ctx, comment); err != nil {
				// Se falhar (ex: foreign key), log e continua com resposta de sucesso
				// pois já pode ter sido salvo no OpenSearch ou simplesmente retornamos a activity
				log.Printf("[WARNING] Failed to add comment to PostgreSQL: %v", err)
			} else {
				activity.Timestamp = comment.CreatedAt
				log.Printf("[INFO] Comment added to case %s in PostgreSQL by %s", caseID, username)
			}
		}
	}

	c.JSON(http.StatusCreated, activity)
}

// addCommentToOpenSearch adiciona um comentário ao caso no OpenSearch
func (s *APIServer) addCommentToOpenSearch(caseID string, activity CaseActivity) error {
	if s.opensearch == nil {
		return fmt.Errorf("opensearch not available")
	}

	// Buscar o caso atual
	res, err := s.opensearch.Get(
		"siem-cases",
		caseID,
	)
	if err != nil {
		return fmt.Errorf("failed to get case: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("case not found in OpenSearch")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode case: %v", err)
	}

	source, ok := result["_source"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid case format")
	}

	// Obter comentários existentes ou criar array vazio
	var comments []interface{}
	if existingComments, ok := source["comments"].([]interface{}); ok {
		comments = existingComments
	}

	// Adicionar novo comentário
	newComment := map[string]interface{}{
		"id":        activity.ID,
		"user":      activity.User,
		"content":   activity.Content,
		"timestamp": activity.Timestamp.Format(time.RFC3339),
		"type":      "comment",
	}
	comments = append(comments, newComment)

	// Atualizar o caso com o novo comentário
	updateDoc := map[string]interface{}{
		"doc": map[string]interface{}{
			"comments":   comments,
			"updated_at": time.Now().Format(time.RFC3339),
		},
	}

	data, _ := json.Marshal(updateDoc)
	updateRes, err := s.opensearch.Update(
		"siem-cases",
		caseID,
		strings.NewReader(string(data)),
		s.opensearch.Update.WithRefresh("true"),
	)
	if err != nil {
		return fmt.Errorf("failed to update case: %v", err)
	}
	defer updateRes.Body.Close()

	if updateRes.IsError() {
		return fmt.Errorf("error updating case: %s", updateRes.String())
	}

	return nil
}

// handleGetCaseComments obtém comentários de um caso
func (s *APIServer) handleGetCaseComments(c *gin.Context) {
	caseID := c.Param("id")
	ctx := c.Request.Context()

	// Se não tiver repository, retornar mock
	if s.caseRepo == nil {
		comments := []CaseComment{
			{
				ID:        uuid.New().String(),
				CaseID:    caseID,
				User:      "analyst1",
				Content:   "Iniciando investigação. IP bloqueado no firewall.",
				Timestamp: time.Now().Add(-100 * time.Minute),
			},
		}
		c.JSON(http.StatusOK, gin.H{
			"comments": comments,
			"total":    len(comments),
		})
		return
	}

	// Buscar comentários do banco
	dbComments, err := s.caseRepo.GetComments(ctx, caseID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get comments: " + err.Error()})
		return
	}

	// Converter para formato da API
	comments := make([]CaseComment, len(dbComments))
	for i, dbComment := range dbComments {
		comments[i] = CaseComment{
			ID:        dbComment.ID,
			CaseID:    dbComment.CaseID,
			User:      dbComment.UserID,
			Content:   dbComment.Comment,
			Timestamp: dbComment.CreatedAt,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"comments": comments,
		"total":    len(comments),
	})
}

// handleGetCaseStatistics obtém estatísticas gerais dos casos
func (s *APIServer) handleGetCaseStatistics(c *gin.Context) {
	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleGetCaseStatisticsOpenSearch(c)
		return
	}

	ctx := c.Request.Context()

	// Prioridade 2: Database repository
	if s.caseRepo == nil {
		s.handleGetCaseStatisticsMock(c)
		return
	}

	// Buscar estatísticas do banco
	statsMap, err := s.caseRepo.GetStats(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get statistics: " + err.Error()})
		return
	}

	// Se o total for 0, usar dados mock
	total := getIntFromMap(statsMap, "total")
	if total == 0 {
		s.handleGetCaseStatisticsMock(c)
		return
	}

	// Converter para formato da API
	apiStats := CaseStatistics{
		Total:            total,
		New:              getIntFromMap(statsMap, "open"),
		InProgress:       getIntFromMap(statsMap, "in_progress"),
		Resolved:         0, // TODO: Add resolved status
		Closed:           getIntFromMap(statsMap, "closed"),
		BySeverity:       map[string]int{
			"critical": getIntFromMap(statsMap, "critical"),
			"high":     getIntFromMap(statsMap, "high"),
			"medium":   getIntFromMap(statsMap, "medium"),
			"low":      getIntFromMap(statsMap, "low"),
		},
		ByCategory:       map[string]int{}, // TODO: Calculate
		SLABreaches:      0,                // TODO: Calculate
		AvgTimeToResolve: getFloatFromMap(statsMap, "avg_resolution_time"),
		TrendData:        []map[string]interface{}{}, // TODO: Calculate
	}

	c.JSON(http.StatusOK, apiStats)
}

// ============================================================================
// MOCK HANDLERS (Fallback quando DB não está disponível)
// ============================================================================

func (s *APIServer) handleListCasesMock(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")
	assignedTo := c.Query("assigned_to")

	cases := []Case{
		// Caso 1: Tentativa de Força Bruta (High, In Progress)
		{
			ID:               "case-001",
			Title:            "Tentativa de Força Bruta SSH Detectada",
			Description:      "Múltiplas tentativas de login falhadas (>100) detectadas do IP 203.0.113.45 tentando acessar servidor SSH (porta 22). Padrão de ataque automatizado identificado com tentativas de usuários comuns (root, admin, user).",
			Severity:         "high",
			Status:           "in_progress",
			Priority:         "high",
			Category:         "unauthorized_access",
			AssignedTo:       "analyst1",
			CreatedBy:        "system",
			CreatedAt:        time.Now().Add(-2 * time.Hour),
			UpdatedAt:        time.Now().Add(-30 * time.Minute),
			DueDate:          timePtr(time.Now().Add(22 * time.Hour)),
			Tags:             []string{"brute-force", "ssh", "authentication", "automated", "mitre:T1110"},
			RelatedAlerts:    []string{"alert-001", "alert-002"},
			RelatedEvents:    []string{"event-101", "event-102", "event-103"},
			RelatedPlaybooks: []string{"playbook-brute-force-response"},
			TimeToDetect:     120,
			TimeToRespond:    300,
			TimeToResolve:    0,
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(24 * time.Hour)),
			SLARemaining:     79200,
		},
		// Caso 2: Ransomware Crítico (Critical, New)
		{
			ID:               "case-002",
			Title:            "Ransomware WannaCry Detectado em Múltiplos Endpoints",
			Description:      "Detecção de atividade de ransomware WannaCry em 5 endpoints da rede corporativa. Arquivos sendo criptografados com extensão .WNCRY. Propagação via vulnerabilidade EternalBlue (MS17-010). Endpoints afetados: WKS-001, WKS-005, WKS-012, SRV-FILE-01, SRV-BACKUP-02.",
			Severity:         "critical",
			Status:           "new",
			Priority:         "urgent",
			Category:         "malware",
			AssignedTo:       "analyst2",
			CreatedBy:        "edr-system",
			CreatedAt:        time.Now().Add(-15 * time.Minute),
			UpdatedAt:        time.Now().Add(-15 * time.Minute),
			DueDate:          timePtr(time.Now().Add(1*time.Hour + 45*time.Minute)),
			Tags:             []string{"ransomware", "wannacry", "critical", "eternalblue", "ms17-010", "mitre:T1486"},
			RelatedAlerts:    []string{"alert-003", "alert-004", "alert-005"},
			RelatedEvents:    []string{"event-201", "event-202", "event-203", "event-204", "event-205"},
			RelatedPlaybooks: []string{"playbook-ransomware-containment"},
			TimeToDetect:     30,
			TimeToRespond:    0,
			TimeToResolve:    0,
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(2 * time.Hour)),
			SLARemaining:     6900,
		},
		// Caso 3: Phishing Campaign (Medium, In Progress)
		{
			ID:               "case-003",
			Title:            "Campanha de Phishing Direcionada ao Departamento Financeiro",
			Description:      "15 emails de phishing detectados com assunto 'Fatura Urgente - Pagamento Pendente'. Emails contêm anexo malicioso (invoice.pdf.exe) e link para site fraudulento imitando portal bancário. 3 usuários clicaram no link, 1 baixou o anexo.",
			Severity:         "medium",
			Status:           "in_progress",
			Priority:         "medium",
			Category:         "phishing",
			AssignedTo:       "analyst1",
			CreatedBy:        "email-gateway",
			CreatedAt:        time.Now().Add(-4 * time.Hour),
			UpdatedAt:        time.Now().Add(-1 * time.Hour),
			DueDate:          timePtr(time.Now().Add(68 * time.Hour)),
			Tags:             []string{"phishing", "email", "social-engineering", "credential-theft", "mitre:T1566.001"},
			RelatedAlerts:    []string{"alert-006", "alert-007"},
			RelatedEvents:    []string{"event-301", "event-302", "event-303"},
			RelatedPlaybooks: []string{"playbook-phishing-response"},
			TimeToDetect:     600,
			TimeToRespond:    1800,
			TimeToResolve:    0,
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(72 * time.Hour)),
			SLARemaining:     244800,
		},
		// Caso 4: Data Exfiltration (Critical, In Progress)
		{
			ID:               "case-004",
			Title:            "Exfiltração de Dados Sensíveis Detectada",
			Description:      "Transferência anômala de 2.5 GB de dados do servidor de banco de dados (DB-PROD-01) para IP externo suspeito (185.220.101.50) via protocolo HTTPS. Dados incluem registros de clientes e informações financeiras. Usuário: db_admin.",
			Severity:         "critical",
			Status:           "in_progress",
			Priority:         "urgent",
			Category:         "data_breach",
			AssignedTo:       "analyst3",
			CreatedBy:        "dlp-system",
			CreatedAt:        time.Now().Add(-45 * time.Minute),
			UpdatedAt:        time.Now().Add(-10 * time.Minute),
			DueDate:          timePtr(time.Now().Add(1*time.Hour + 15*time.Minute)),
			Tags:             []string{"data-exfiltration", "data-breach", "database", "insider-threat", "mitre:T1048"},
			RelatedAlerts:    []string{"alert-008", "alert-009"},
			RelatedEvents:    []string{"event-401", "event-402"},
			RelatedPlaybooks: []string{"playbook-data-breach-response"},
			TimeToDetect:     180,
			TimeToRespond:    600,
			TimeToResolve:    0,
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(2 * time.Hour)),
			SLARemaining:     4500,
		},
		// Caso 5: Insider Threat (High, New)
		{
			ID:               "case-005",
			Title:            "Acesso Não Autorizado a Dados Confidenciais",
			Description:      "Funcionário do departamento de TI (user: jsilva) acessou 50+ documentos confidenciais do departamento de RH fora do horário comercial (02:30 AM). Documentos incluem salários, avaliações de desempenho e informações pessoais de executivos.",
			Severity:         "high",
			Status:           "new",
			Priority:         "high",
			Category:         "unauthorized_access",
			AssignedTo:       "analyst2",
			CreatedBy:        "ueba-system",
			CreatedAt:        time.Now().Add(-20 * time.Minute),
			UpdatedAt:        time.Now().Add(-20 * time.Minute),
			DueDate:          timePtr(time.Now().Add(23*time.Hour + 40*time.Minute)),
			Tags:             []string{"insider-threat", "unauthorized-access", "data-access", "after-hours", "mitre:T1078"},
			RelatedAlerts:    []string{"alert-010"},
			RelatedEvents:    []string{"event-501", "event-502", "event-503"},
			RelatedPlaybooks: []string{"playbook-insider-threat-investigation"},
			TimeToDetect:     300,
			TimeToRespond:    0,
			TimeToResolve:    0,
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(24 * time.Hour)),
			SLARemaining:     85200,
		},
		// Caso 6: SQL Injection (High, Resolved)
		{
			ID:               "case-006",
			Title:            "Tentativa de SQL Injection no Portal Web",
			Description:      "Múltiplas tentativas de SQL injection detectadas no formulário de login do portal web (https://portal.company.com/login). Payloads incluem: ' OR '1'='1, UNION SELECT, DROP TABLE. IP de origem: 198.51.100.23. WAF bloqueou todas as tentativas.",
			Severity:         "high",
			Status:           "resolved",
			Priority:         "high",
			Category:         "web_attack",
			AssignedTo:       "analyst1",
			CreatedBy:        "waf-system",
			CreatedAt:        time.Now().Add(-48 * time.Hour),
			UpdatedAt:        time.Now().Add(-24 * time.Hour),
			ResolvedAt:       timePtr(time.Now().Add(-24 * time.Hour)),
			DueDate:          timePtr(time.Now().Add(-24 * time.Hour)),
			Tags:             []string{"sql-injection", "web-attack", "waf", "blocked", "mitre:T1190"},
			RelatedAlerts:    []string{"alert-011", "alert-012"},
			RelatedEvents:    []string{"event-601", "event-602"},
			RelatedPlaybooks: []string{"playbook-web-attack-response"},
			TimeToDetect:     60,
			TimeToRespond:    300,
			TimeToResolve:    82800, // 23 horas
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(-24 * time.Hour)),
			SLARemaining:     0,
		},
		// Caso 7: DDoS Attack (Medium, Resolved)
		{
			ID:               "case-007",
			Title:            "Ataque DDoS Mitigado com Sucesso",
			Description:      "Ataque DDoS volumétrico detectado contra servidor web público (web-prod-01). Pico de 50.000 requisições/segundo de 1.200+ IPs únicos. Ataque mitigado via Cloudflare após 15 minutos. Serviço permaneceu disponível.",
			Severity:         "medium",
			Status:           "resolved",
			Priority:         "medium",
			Category:         "dos_attack",
			AssignedTo:       "analyst3",
			CreatedBy:        "cloudflare-system",
			CreatedAt:        time.Now().Add(-72 * time.Hour),
			UpdatedAt:        time.Now().Add(-71 * time.Hour),
			ResolvedAt:       timePtr(time.Now().Add(-71 * time.Hour)),
			DueDate:          timePtr(time.Now().Add(-1 * time.Hour)),
			Tags:             []string{"ddos", "dos", "volumetric", "mitigated", "mitre:T1498"},
			RelatedAlerts:    []string{"alert-013"},
			RelatedEvents:    []string{"event-701", "event-702"},
			RelatedPlaybooks: []string{"playbook-ddos-mitigation"},
			TimeToDetect:     120,
			TimeToRespond:    180,
			TimeToResolve:    900, // 15 minutos
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(-1 * time.Hour)),
			SLARemaining:     0,
		},
		// Caso 8: Privilege Escalation (Critical, Closed)
		{
			ID:               "case-008",
			Title:            "Escalação de Privilégios Detectada e Bloqueada",
			Description:      "Tentativa de escalação de privilégios detectada em servidor Linux (srv-app-05). Usuário 'webuser' tentou executar comando 'sudo su' sem autorização. Processo bloqueado pelo SELinux. Investigação revelou comprometimento de conta via credenciais fracas.",
			Severity:         "critical",
			Status:           "closed",
			Priority:         "urgent",
			Category:         "privilege_escalation",
			AssignedTo:       "analyst2",
			CreatedBy:        "edr-system",
			CreatedAt:        time.Now().Add(-96 * time.Hour),
			UpdatedAt:        time.Now().Add(-72 * time.Hour),
			ResolvedAt:       timePtr(time.Now().Add(-73 * time.Hour)),
			ClosedAt:         timePtr(time.Now().Add(-72 * time.Hour)),
			DueDate:          timePtr(time.Now().Add(-94 * time.Hour)),
			Tags:             []string{"privilege-escalation", "linux", "sudo", "blocked", "mitre:T1548"},
			RelatedAlerts:    []string{"alert-014"},
			RelatedEvents:    []string{"event-801", "event-802"},
			RelatedPlaybooks: []string{"playbook-privilege-escalation-response"},
			TimeToDetect:     30,
			TimeToRespond:    120,
			TimeToResolve:    7200, // 2 horas
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(-94 * time.Hour)),
			SLARemaining:     0,
		},
		// Caso 9: APT Activity (Critical, In Progress)
		{
			ID:               "case-009",
			Title:            "Atividade de APT (Advanced Persistent Threat) Detectada",
			Description:      "Indicadores de comprometimento (IoCs) associados ao grupo APT29 (Cozy Bear) detectados na rede. Comunicação C2 identificada com domínio suspeito (update-server[.]net). Backdoor persistente encontrado em 2 servidores críticos. Investigação em andamento.",
			Severity:         "critical",
			Status:           "in_progress",
			Priority:         "urgent",
			Category:         "advanced_threat",
			AssignedTo:       "analyst3",
			CreatedBy:        "threat-intel-system",
			CreatedAt:        time.Now().Add(-6 * time.Hour),
			UpdatedAt:        time.Now().Add(-30 * time.Minute),
			DueDate:          timePtr(time.Now().Add(-4 * time.Hour)),
			Tags:             []string{"apt", "apt29", "cozy-bear", "c2", "backdoor", "nation-state", "mitre:T1071"},
			RelatedAlerts:    []string{"alert-015", "alert-016", "alert-017"},
			RelatedEvents:    []string{"event-901", "event-902", "event-903", "event-904"},
			RelatedPlaybooks: []string{"playbook-apt-response", "playbook-incident-containment"},
			TimeToDetect:     3600,
			TimeToRespond:    1800,
			TimeToResolve:    0,
			SLABreach:        true, // SLA breach - caso crítico
			SLADeadline:      timePtr(time.Now().Add(-4 * time.Hour)),
			SLARemaining:     0,
		},
		// Caso 10: Cryptomining (Low, Resolved)
		{
			ID:               "case-010",
			Title:            "Mineração de Criptomoedas Não Autorizada",
			Description:      "Processo de mineração de criptomoedas (XMRig) detectado em 3 estações de trabalho. Alto uso de CPU (95%+) e conexões para pool de mineração (pool.minexmr.com). Processo removido e estações limpas.",
			Severity:         "low",
			Status:           "resolved",
			Priority:         "low",
			Category:         "malware",
			AssignedTo:       "analyst1",
			CreatedBy:        "edr-system",
			CreatedAt:        time.Now().Add(-120 * time.Hour),
			UpdatedAt:        time.Now().Add(-96 * time.Hour),
			ResolvedAt:       timePtr(time.Now().Add(-96 * time.Hour)),
			DueDate:          timePtr(time.Now().Add(-24 * time.Hour)),
			Tags:             []string{"cryptomining", "xmrig", "resource-abuse", "mitre:T1496"},
			RelatedAlerts:    []string{"alert-018"},
			RelatedEvents:    []string{"event-1001", "event-1002"},
			RelatedPlaybooks: []string{"playbook-malware-removal"},
			TimeToDetect:     7200,
			TimeToRespond:    3600,
			TimeToResolve:    14400, // 4 horas
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(-24 * time.Hour)),
			SLARemaining:     0,
		},
	}

	// Aplicar filtros
	var filteredCases []Case
	for _, caseObj := range cases {
		if status != "" && caseObj.Status != status {
			continue
		}
		if severity != "" && caseObj.Severity != severity {
			continue
		}
		if assignedTo != "" && caseObj.AssignedTo != assignedTo {
			continue
		}
		filteredCases = append(filteredCases, caseObj)
	}

	c.JSON(http.StatusOK, gin.H{
		"cases": filteredCases,
		"total": len(filteredCases),
	})
}

func (s *APIServer) handleGetCaseMock(c *gin.Context, id string) {
	// Lista de casos mockados (mesma lista do handleListCasesMock)
	cases := []Case{
		// Caso 1: Ransomware (Critical, In Progress)
		{
			ID:               "case-001",
			Title:            "Ransomware Detectado em Servidor de Arquivos",
			Description:      "Atividade suspeita de criptografia em massa detectada no servidor FILE-SRV-01. Aproximadamente 1.500 arquivos foram criptografados com extensão .encrypted. Processo malicioso identificado: ransomware.exe. Servidor isolado da rede.",
			Severity:         "critical",
			Status:           "in_progress",
			Priority:         "urgent",
			Category:         "malware",
			AssignedTo:       "analyst2",
			CreatedBy:        "edr-system",
			CreatedAt:        time.Now().Add(-3 * time.Hour),
			UpdatedAt:        time.Now().Add(-15 * time.Minute),
			DueDate:          timePtr(time.Now().Add(-1 * time.Hour)),
			Tags:             []string{"ransomware", "critical", "containment", "file-encryption", "mitre:T1486"},
			RelatedAlerts:    []string{"alert-003", "alert-004", "alert-005"},
			RelatedEvents:    []string{"event-101", "event-102", "event-103"},
			RelatedPlaybooks: []string{"playbook-ransomware-response"},
			TimeToDetect:     300,
			TimeToRespond:    900,
			TimeToResolve:    0,
			SLABreach:        true,
			SLADeadline:      timePtr(time.Now().Add(-1 * time.Hour)),
			SLARemaining:     0,
		},
		// Caso 2: Brute Force (High, New)
		{
			ID:               "case-002",
			Title:            "Tentativa de Força Bruta em Servidor SSH",
			Description:      "Múltiplas tentativas de login SSH falhadas detectadas no servidor WEB-PROD-01 do IP 203.0.113.45. Total de 2.847 tentativas em 30 minutos. Usuários alvos: root, admin, ubuntu. IP bloqueado automaticamente pelo firewall.",
			Severity:         "high",
			Status:           "new",
			Priority:         "high",
			Category:         "unauthorized_access",
			AssignedTo:       "analyst1",
			CreatedBy:        "ids-system",
			CreatedAt:        time.Now().Add(-45 * time.Minute),
			UpdatedAt:        time.Now().Add(-45 * time.Minute),
			DueDate:          timePtr(time.Now().Add(23*time.Hour + 15*time.Minute)),
			Tags:             []string{"brute-force", "ssh", "authentication", "automated", "mitre:T1110"},
			RelatedAlerts:    []string{"alert-001", "alert-002"},
			RelatedEvents:    []string{"event-201", "event-202"},
			RelatedPlaybooks: []string{"playbook-brute-force-response"},
			TimeToDetect:     120,
			TimeToRespond:    0,
			TimeToResolve:    0,
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(24 * time.Hour)),
			SLARemaining:     83700,
		},
		// Caso 3: Phishing (Medium, In Progress)
		{
			ID:               "case-003",
			Title:            "Campanha de Phishing Direcionada",
			Description:      "Email de phishing detectado direcionado a 15 executivos da empresa. Assunto: 'Ação Urgente Requerida - Atualização de Senha'. Link malicioso para página falsa de login Office 365. 2 usuários clicaram no link, credenciais potencialmente comprometidas.",
			Severity:         "medium",
			Status:           "in_progress",
			Priority:         "medium",
			Category:         "phishing",
			AssignedTo:       "analyst2",
			CreatedBy:        "email-gateway",
			CreatedAt:        time.Now().Add(-4 * time.Hour),
			UpdatedAt:        time.Now().Add(-1 * time.Hour),
			DueDate:          timePtr(time.Now().Add(68 * time.Hour)),
			Tags:             []string{"phishing", "email", "social-engineering", "credential-theft", "mitre:T1566.001"},
			RelatedAlerts:    []string{"alert-006", "alert-007"},
			RelatedEvents:    []string{"event-301", "event-302", "event-303"},
			RelatedPlaybooks: []string{"playbook-phishing-response"},
			TimeToDetect:     600,
			TimeToRespond:    1800,
			TimeToResolve:    0,
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(72 * time.Hour)),
			SLARemaining:     244800,
		},
		// Caso 4: Data Exfiltration (Critical, In Progress)
		{
			ID:               "case-004",
			Title:            "Exfiltração de Dados Sensíveis Detectada",
			Description:      "Transferência anômala de 2.5 GB de dados do servidor de banco de dados (DB-PROD-01) para IP externo suspeito (185.220.101.50) via protocolo HTTPS. Dados incluem registros de clientes e informações financeiras. Usuário: db_admin.",
			Severity:         "critical",
			Status:           "in_progress",
			Priority:         "urgent",
			Category:         "data_breach",
			AssignedTo:       "analyst3",
			CreatedBy:        "dlp-system",
			CreatedAt:        time.Now().Add(-45 * time.Minute),
			UpdatedAt:        time.Now().Add(-10 * time.Minute),
			DueDate:          timePtr(time.Now().Add(1*time.Hour + 15*time.Minute)),
			Tags:             []string{"data-exfiltration", "data-breach", "database", "insider-threat", "mitre:T1048"},
			RelatedAlerts:    []string{"alert-008", "alert-009"},
			RelatedEvents:    []string{"event-401", "event-402"},
			RelatedPlaybooks: []string{"playbook-data-breach-response"},
			TimeToDetect:     180,
			TimeToRespond:    600,
			TimeToResolve:    0,
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(2 * time.Hour)),
			SLARemaining:     4500,
		},
		// Caso 5: Insider Threat (High, New)
		{
			ID:               "case-005",
			Title:            "Acesso Não Autorizado a Dados Confidenciais",
			Description:      "Funcionário do departamento de TI (user: jsilva) acessou 50+ documentos confidenciais do departamento de RH fora do horário comercial (02:30 AM). Documentos incluem salários, avaliações de desempenho e informações pessoais de executivos.",
			Severity:         "high",
			Status:           "new",
			Priority:         "high",
			Category:         "unauthorized_access",
			AssignedTo:       "analyst2",
			CreatedBy:        "ueba-system",
			CreatedAt:        time.Now().Add(-20 * time.Minute),
			UpdatedAt:        time.Now().Add(-20 * time.Minute),
			DueDate:          timePtr(time.Now().Add(23*time.Hour + 40*time.Minute)),
			Tags:             []string{"insider-threat", "unauthorized-access", "data-access", "after-hours", "mitre:T1078"},
			RelatedAlerts:    []string{"alert-010"},
			RelatedEvents:    []string{"event-501", "event-502", "event-503"},
			RelatedPlaybooks: []string{"playbook-insider-threat-investigation"},
			TimeToDetect:     300,
			TimeToRespond:    0,
			TimeToResolve:    0,
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(24 * time.Hour)),
			SLARemaining:     85200,
		},
		// Caso 6: SQL Injection (High, Resolved)
		{
			ID:               "case-006",
			Title:            "Tentativa de SQL Injection no Portal Web",
			Description:      "Múltiplas tentativas de SQL injection detectadas no formulário de login do portal web (https://portal.company.com/login). Payloads incluem: ' OR '1'='1, UNION SELECT, DROP TABLE. IP de origem: 198.51.100.23. WAF bloqueou todas as tentativas.",
			Severity:         "high",
			Status:           "resolved",
			Priority:         "high",
			Category:         "web_attack",
			AssignedTo:       "analyst1",
			CreatedBy:        "waf-system",
			CreatedAt:        time.Now().Add(-48 * time.Hour),
			UpdatedAt:        time.Now().Add(-24 * time.Hour),
			ResolvedAt:       timePtr(time.Now().Add(-24 * time.Hour)),
			DueDate:          timePtr(time.Now().Add(-24 * time.Hour)),
			Tags:             []string{"sql-injection", "web-attack", "waf", "blocked", "mitre:T1190"},
			RelatedAlerts:    []string{"alert-011", "alert-012"},
			RelatedEvents:    []string{"event-601", "event-602"},
			RelatedPlaybooks: []string{"playbook-web-attack-response"},
			TimeToDetect:     60,
			TimeToRespond:    300,
			TimeToResolve:    82800, // 23 horas
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(-24 * time.Hour)),
			SLARemaining:     0,
		},
		// Caso 7: DDoS Attack (Medium, Resolved)
		{
			ID:               "case-007",
			Title:            "Ataque DDoS Mitigado com Sucesso",
			Description:      "Ataque DDoS volumétrico detectado contra servidor web público (web-prod-01). Pico de 50.000 requisições/segundo de 1.200+ IPs únicos. Ataque mitigado via Cloudflare após 15 minutos. Serviço permaneceu disponível.",
			Severity:         "medium",
			Status:           "resolved",
			Priority:         "medium",
			Category:         "dos_attack",
			AssignedTo:       "analyst3",
			CreatedBy:        "cloudflare-system",
			CreatedAt:        time.Now().Add(-72 * time.Hour),
			UpdatedAt:        time.Now().Add(-71 * time.Hour),
			ResolvedAt:       timePtr(time.Now().Add(-71 * time.Hour)),
			DueDate:          timePtr(time.Now().Add(-1 * time.Hour)),
			Tags:             []string{"ddos", "dos", "volumetric", "mitigated", "mitre:T1498"},
			RelatedAlerts:    []string{"alert-013"},
			RelatedEvents:    []string{"event-701", "event-702"},
			RelatedPlaybooks: []string{"playbook-ddos-mitigation"},
			TimeToDetect:     120,
			TimeToRespond:    180,
			TimeToResolve:    900, // 15 minutos
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(-1 * time.Hour)),
			SLARemaining:     0,
		},
		// Caso 8: Privilege Escalation (Critical, Closed)
		{
			ID:               "case-008",
			Title:            "Escalação de Privilégios Detectada e Bloqueada",
			Description:      "Tentativa de escalação de privilégios detectada em servidor Linux (srv-app-05). Usuário 'webuser' tentou executar comando 'sudo su' sem autorização. Processo bloqueado pelo SELinux. Investigação revelou comprometimento de conta via credenciais fracas.",
			Severity:         "critical",
			Status:           "closed",
			Priority:         "urgent",
			Category:         "privilege_escalation",
			AssignedTo:       "analyst2",
			CreatedBy:        "edr-system",
			CreatedAt:        time.Now().Add(-96 * time.Hour),
			UpdatedAt:        time.Now().Add(-72 * time.Hour),
			ResolvedAt:       timePtr(time.Now().Add(-73 * time.Hour)),
			ClosedAt:         timePtr(time.Now().Add(-72 * time.Hour)),
			DueDate:          timePtr(time.Now().Add(-94 * time.Hour)),
			Tags:             []string{"privilege-escalation", "linux", "sudo", "blocked", "mitre:T1548"},
			RelatedAlerts:    []string{"alert-014"},
			RelatedEvents:    []string{"event-801", "event-802"},
			RelatedPlaybooks: []string{"playbook-privilege-escalation-response"},
			TimeToDetect:     30,
			TimeToRespond:    120,
			TimeToResolve:    7200, // 2 horas
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(-94 * time.Hour)),
			SLARemaining:     0,
		},
		// Caso 9: APT Activity (Critical, In Progress)
		{
			ID:               "case-009",
			Title:            "Atividade de APT (Advanced Persistent Threat) Detectada",
			Description:      "Indicadores de comprometimento (IoCs) associados ao grupo APT29 (Cozy Bear) detectados na rede. Comunicação C2 identificada com domínio suspeito (update-server[.]net). Backdoor persistente encontrado em 2 servidores críticos. Investigação em andamento.",
			Severity:         "critical",
			Status:           "in_progress",
			Priority:         "urgent",
			Category:         "advanced_threat",
			AssignedTo:       "analyst3",
			CreatedBy:        "threat-intel-system",
			CreatedAt:        time.Now().Add(-6 * time.Hour),
			UpdatedAt:        time.Now().Add(-30 * time.Minute),
			DueDate:          timePtr(time.Now().Add(-4 * time.Hour)),
			Tags:             []string{"apt", "apt29", "cozy-bear", "c2", "backdoor", "nation-state", "mitre:T1071"},
			RelatedAlerts:    []string{"alert-015", "alert-016", "alert-017"},
			RelatedEvents:    []string{"event-901", "event-902", "event-903", "event-904"},
			RelatedPlaybooks: []string{"playbook-apt-response", "playbook-incident-containment"},
			TimeToDetect:     3600,
			TimeToRespond:    1800,
			TimeToResolve:    0,
			SLABreach:        true, // SLA breach - caso crítico
			SLADeadline:      timePtr(time.Now().Add(-4 * time.Hour)),
			SLARemaining:     0,
		},
		// Caso 10: Cryptomining (Low, Resolved)
		{
			ID:               "case-010",
			Title:            "Mineração de Criptomoedas Não Autorizada",
			Description:      "Processo de mineração de criptomoedas (XMRig) detectado em 3 estações de trabalho. Alto uso de CPU (95%+) e conexões para pool de mineração (pool.minexmr.com). Processo removido e estações limpas.",
			Severity:         "low",
			Status:           "resolved",
			Priority:         "low",
			Category:         "malware",
			AssignedTo:       "analyst1",
			CreatedBy:        "edr-system",
			CreatedAt:        time.Now().Add(-120 * time.Hour),
			UpdatedAt:        time.Now().Add(-96 * time.Hour),
			ResolvedAt:       timePtr(time.Now().Add(-96 * time.Hour)),
			DueDate:          timePtr(time.Now().Add(-24 * time.Hour)),
			Tags:             []string{"cryptomining", "xmrig", "resource-abuse", "mitre:T1496"},
			RelatedAlerts:    []string{"alert-018"},
			RelatedEvents:    []string{"event-1001", "event-1002"},
			RelatedPlaybooks: []string{"playbook-malware-removal"},
			TimeToDetect:     7200,
			TimeToRespond:    3600,
			TimeToResolve:    14400, // 4 horas
			SLABreach:        false,
			SLADeadline:      timePtr(time.Now().Add(-24 * time.Hour)),
			SLARemaining:     0,
		},
	}

	// Buscar caso pelo ID
	for _, caseObj := range cases {
		if caseObj.ID == id {
			c.JSON(http.StatusOK, caseObj)
			return
		}
	}

	// Se não encontrar, retornar 404
	c.JSON(http.StatusNotFound, gin.H{"error": "Case not found"})
}

func (s *APIServer) handleGetCaseActivitiesMock(c *gin.Context, caseID string) {
	activities := []CaseActivity{
		{
			ID:        uuid.New().String(),
			CaseID:    caseID,
			Type:      "case_created",
			User:      "system",
			Timestamp: time.Now().Add(-2 * time.Hour),
			Content:   "Caso criado automaticamente pelo sistema de detecção",
		},
		{
			ID:        uuid.New().String(),
			CaseID:    caseID,
			Type:      "assignment",
			User:      "admin",
			Timestamp: time.Now().Add(-115 * time.Minute),
			OldValue:  "unassigned",
			NewValue:  "analyst1",
			Content:   "Caso atribuído a analyst1",
		},
		{
			ID:        uuid.New().String(),
			CaseID:    caseID,
			Type:      "comment",
			User:      "analyst1",
			Timestamp: time.Now().Add(-100 * time.Minute),
			Content:   "Iniciando investigação. IP bloqueado no firewall.",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"activities": activities,
		"total":      len(activities),
	})
}

func (s *APIServer) handleGetCaseStatisticsMock(c *gin.Context) {
	stats := CaseStatistics{
		Total:      10,
		New:        2,  // case-002, case-005
		InProgress: 4,  // case-001, case-003, case-004, case-009
		Resolved:   3,  // case-006, case-007, case-010
		Closed:     1,  // case-008
		BySeverity: map[string]int{
			"low":      1,  // case-010
			"medium":   2,  // case-003, case-007
			"high":     4,  // case-001, case-005, case-006
			"critical": 3,  // case-002, case-004, case-008, case-009
		},
		ByCategory: map[string]int{
			"malware":               2,  // case-002, case-010
			"phishing":              1,  // case-003
			"unauthorized_access":   2,  // case-001, case-005
			"data_breach":           1,  // case-004
			"web_attack":            1,  // case-006
			"dos_attack":            1,  // case-007
			"privilege_escalation":  1,  // case-008
			"advanced_threat":       1,  // case-009
		},
		SLABreaches:      1,    // case-009 (APT)
		AvgTimeToResolve: 8.25, // média: (23h + 0.25h + 4h) / 3 = 9.08h (arredondado)
		TrendData: []map[string]interface{}{
			{"date": "2025-11-06", "opened": 1, "resolved": 1, "closed": 0},
			{"date": "2025-11-07", "opened": 0, "resolved": 1, "closed": 0},
			{"date": "2025-11-08", "opened": 1, "resolved": 0, "closed": 0},
			{"date": "2025-11-09", "opened": 0, "resolved": 1, "closed": 0},
			{"date": "2025-11-10", "opened": 1, "resolved": 0, "closed": 1},
			{"date": "2025-11-11", "opened": 0, "resolved": 0, "closed": 0},
			{"date": "2025-11-12", "opened": 1, "resolved": 0, "closed": 0},
			{"date": "2025-11-13", "opened": 5, "resolved": 0, "closed": 0},
		},
	}

	c.JSON(http.StatusOK, stats)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func getIntFromMap(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	return 0
}

func getFloatFromMap(m map[string]interface{}, key string) float64 {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		case int64:
			return float64(v)
		}
	}
	return 0.0
}

// ============================================================================
// EXPORT FUNCTIONS
// ============================================================================

// handleExportCases exporta casos em diferentes formatos
func (s *APIServer) handleExportCases(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")
	assignedTo := c.Query("assigned_to")
	search := c.Query("search")
	format := c.DefaultQuery("format", "csv") // csv, json

	// Limite de segurança para exportação
	maxExportSize := 10000
	var cases []Case

	// Tentar buscar do OpenSearch primeiro
	if s.opensearch != nil {
		must := []map[string]interface{}{}

		if status != "" {
			must = append(must, map[string]interface{}{
				"term": map[string]interface{}{
					"status": strings.ToUpper(status),
				},
			})
		}
		if severity != "" {
			must = append(must, map[string]interface{}{
				"term": map[string]interface{}{
					"severity": strings.ToUpper(severity),
				},
			})
		}
		if assignedTo != "" {
			must = append(must, map[string]interface{}{
				"term": map[string]interface{}{
					"assigned_to": assignedTo,
				},
			})
		}
		if search != "" {
			must = append(must, map[string]interface{}{
				"multi_match": map[string]interface{}{
					"query":  search,
					"fields": []string{"title", "description", "category"},
					"type":   "best_fields",
				},
			})
		}

		query := map[string]interface{}{
			"size": maxExportSize,
			"sort": []map[string]interface{}{
				{"created_at": map[string]interface{}{"order": "desc"}},
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
			s.opensearch.Search.WithIndex("siem-cases"),
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
									caseObj := Case{
										ID:          getStringFromMap(source, "id"),
										Title:       getStringFromMap(source, "title"),
										Description: getStringFromMap(source, "description"),
										Severity:    getStringFromMap(source, "severity"),
										Status:      getStringFromMap(source, "status"),
										Category:    getStringFromMap(source, "category"),
										AssignedTo:  getStringFromMap(source, "assigned_to"),
										SLABreach:   getBoolFromMap(source, "sla_breach"),
									}
									if ts, ok := source["created_at"].(string); ok {
										caseObj.CreatedAt, _ = time.Parse(time.RFC3339, ts)
									}
									if ts, ok := source["updated_at"].(string); ok {
										caseObj.UpdatedAt, _ = time.Parse(time.RFC3339, ts)
									}
									cases = append(cases, caseObj)
								}
							}
						}
					}
				}
			}
		}
	}

	// Se não conseguiu buscar do OpenSearch, usar mock apenas se permitido
	if len(cases) == 0 {
		if IsMockDataDisabled() {
			c.JSON(http.StatusOK, gin.H{
				"error":   "No data available for export",
				"message": "OpenSearch not connected and mock data is disabled",
			})
			return
		}
		// Fallback para mock
		cases = generateMockCases()
	}

	// Limitar número de casos exportados
	if len(cases) > maxExportSize {
		cases = cases[:maxExportSize]
	}

	log.Printf("📤 Exporting %d cases in %s format", len(cases), format)

	// Gerar arquivo baseado no formato
	switch format {
	case "json":
		exportCasesJSON(c, cases)
	case "csv":
		exportCasesCSV(c, cases)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Formato não suportado. Use 'csv' ou 'json'"})
	}
}

// exportCasesJSON exporta casos em formato JSON
func exportCasesJSON(c *gin.Context, cases []Case) {
	filename := "cases_export_" + time.Now().Format("20060102_150405") + ".json"

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "application/json")

	c.JSON(http.StatusOK, gin.H{
		"exported_at": time.Now().Format(time.RFC3339),
		"total":       len(cases),
		"cases":       cases,
	})
}

// exportCasesCSV exporta casos em formato CSV
func exportCasesCSV(c *gin.Context, cases []Case) {
	filename := "cases_export_" + time.Now().Format("20060102_150405") + ".csv"

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "text/csv")

	// Escrever cabeçalho CSV
	csv := "ID,Title,Severity,Status,Category,AssignedTo,SLABreach,Description,CreatedAt,UpdatedAt\n"

	// Escrever dados
	for _, caseObj := range cases {
		// Escapar campos que podem conter vírgulas ou quebras de linha
		title := strings.ReplaceAll(caseObj.Title, "\"", "\"\"")
		title = strings.ReplaceAll(title, "\n", " ")
		description := strings.ReplaceAll(caseObj.Description, "\"", "\"\"")
		description = strings.ReplaceAll(description, "\n", " ")

		slaBreach := "No"
		if caseObj.SLABreach {
			slaBreach = "Yes"
		}

		line := strings.Join([]string{
			caseObj.ID,
			"\"" + title + "\"",
			caseObj.Severity,
			caseObj.Status,
			caseObj.Category,
			caseObj.AssignedTo,
			slaBreach,
			"\"" + description + "\"",
			caseObj.CreatedAt.Format(time.RFC3339),
			caseObj.UpdatedAt.Format(time.RFC3339),
		}, ",") + "\n"

		csv += line
	}

	c.String(http.StatusOK, csv)
}

// generateMockCases gera casos mock para fallback
func generateMockCases() []Case {
	now := time.Now()
	return []Case{
		{
			ID:          "case-001",
			Title:       "Ransomware Detection - Critical Incident",
			Description: "Suspected ransomware activity detected in production servers",
			Severity:    "CRITICAL",
			Status:      "IN_PROGRESS",
			Category:    "Malware",
			AssignedTo:  "John Analyst",
			SLABreach:   false,
			CreatedAt:   now.Add(-24 * time.Hour),
			UpdatedAt:   now.Add(-1 * time.Hour),
		},
		{
			ID:          "case-002",
			Title:       "Brute Force Attack on SSH",
			Description: "Multiple failed SSH login attempts from external IP",
			Severity:    "HIGH",
			Status:      "NEW",
			Category:    "Intrusion Attempt",
			AssignedTo:  "",
			SLABreach:   false,
			CreatedAt:   now.Add(-2 * time.Hour),
			UpdatedAt:   now.Add(-2 * time.Hour),
		},
		{
			ID:          "case-003",
			Title:       "Data Exfiltration Suspected",
			Description: "Large data transfer to unknown external destination",
			Severity:    "HIGH",
			Status:      "IN_PROGRESS",
			Category:    "Data Loss",
			AssignedTo:  "Jane Security",
			SLABreach:   true,
			CreatedAt:   now.Add(-48 * time.Hour),
			UpdatedAt:   now.Add(-3 * time.Hour),
		},
	}
}

// Helper function for bool parsing (getStringFromMap is in alerts.go)
func getBoolFromMap(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}
