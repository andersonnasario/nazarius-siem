package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/cognimind/siem-platform/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// PlaybookAction representa uma ação individual em um playbook
type PlaybookAction struct {
	Type   string                 `json:"type"`
	Target string                 `json:"target"`
	Params map[string]interface{} `json:"params"`
}

// Playbook representa um playbook SOAR (compatível com frontend)
type Playbook struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Description     string           `json:"description"`
	Trigger         string           `json:"trigger"`
	Actions         []PlaybookAction `json:"actions"`
	Status          string           `json:"status"`
	Executions      int              `json:"executions"`
	LastExecution   *time.Time       `json:"lastExecution,omitempty"`
	SuccessRate     float64          `json:"successRate"`
	AvgResponseTime string           `json:"avgResponseTime"`
	CreatedAt       time.Time        `json:"createdAt"`
	UpdatedAt       time.Time        `json:"updatedAt"`
	CreatedBy       string           `json:"createdBy"`
}

// PlaybookExecution representa uma execução de playbook
type PlaybookExecution struct {
	ID            string                 `json:"id"`
	PlaybookID    string                 `json:"playbookId"`
	PlaybookName  string                 `json:"playbookName"`
	Status        string                 `json:"status"` // running, success, failed, partial
	StartTime     time.Time              `json:"startTime"`
	EndTime       *time.Time             `json:"endTime,omitempty"`
	Duration      string                 `json:"duration,omitempty"`
	Steps         []ExecutionStep        `json:"steps"`
	TriggerData   map[string]interface{} `json:"triggerData"`
	ExecutedBy    string                 `json:"executedBy"`
	ExecutionMode string                 `json:"executionMode"` // automatic, manual
}

// ExecutionStep representa um passo de execução
type ExecutionStep struct {
	Step      int                    `json:"step"`
	Action    string                 `json:"action"`
	Status    string                 `json:"status"` // pending, running, success, failed
	StartTime time.Time              `json:"startTime"`
	EndTime   *time.Time             `json:"endTime,omitempty"`
	Duration  string                 `json:"duration,omitempty"`
	Result    map[string]interface{} `json:"result,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// convertDBPlaybookToAPI converte playbook do DB para formato da API
func convertDBPlaybookToAPI(dbPlaybook *database.Playbook) *Playbook {
	// Parse actions from JSON
	var actions []PlaybookAction
	if err := json.Unmarshal(dbPlaybook.Actions, &actions); err != nil {
		actions = []PlaybookAction{}
	}

	// Calculate success rate
	successRate := 0.0
	if dbPlaybook.ExecutionCount > 0 {
		successRate = (float64(dbPlaybook.SuccessCount) / float64(dbPlaybook.ExecutionCount)) * 100
	}

	// Format avg response time
	avgResponseTime := fmt.Sprintf("%dms", dbPlaybook.AvgExecutionTimeMs)
	if dbPlaybook.AvgExecutionTimeMs > 1000 {
		avgResponseTime = fmt.Sprintf("%.1fs", float64(dbPlaybook.AvgExecutionTimeMs)/1000)
	}

	return &Playbook{
		ID:              dbPlaybook.ID,
		Name:            dbPlaybook.Name,
		Description:     dbPlaybook.Description,
		Trigger:         dbPlaybook.Category, // Using category as trigger for compatibility
		Actions:         actions,
		Status:          dbPlaybook.Status,
		Executions:      dbPlaybook.ExecutionCount,
		LastExecution:   dbPlaybook.LastExecutedAt,
		SuccessRate:     successRate,
		AvgResponseTime: avgResponseTime,
		CreatedAt:       dbPlaybook.CreatedAt,
		UpdatedAt:       dbPlaybook.UpdatedAt,
		CreatedBy:       getStringValue(dbPlaybook.CreatedBy),
	}
}

// convertAPIPlaybookToDB converte playbook da API para formato do DB
func convertAPIPlaybookToDB(apiPlaybook *Playbook) (*database.Playbook, error) {
	// Convert actions to JSON
	actionsJSON, err := json.Marshal(apiPlaybook.Actions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal actions: %w", err)
	}

	dbPlaybook := &database.Playbook{
		ID:          apiPlaybook.ID,
		Name:        apiPlaybook.Name,
		Description: apiPlaybook.Description,
		Category:    apiPlaybook.Trigger,
		Status:      apiPlaybook.Status,
		Actions:     actionsJSON,
		Tags:        []string{},
		Version:     1,
		IsActive:    apiPlaybook.Status == "active",
	}

	if apiPlaybook.CreatedBy != "" {
		dbPlaybook.CreatedBy = &apiPlaybook.CreatedBy
	}

	return dbPlaybook, nil
}

// handleListPlaybooks lista todos os playbooks
func (s *APIServer) handleListPlaybooks(c *gin.Context) {
	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleListPlaybooksOpenSearch(c)
		return
	}

	ctx := c.Request.Context()

	// Prioridade 2: Database repository
	if s.playbookRepo == nil {
		s.handleListPlaybooksMock(c)
		return
	}

	// Buscar do banco de dados
	filters := make(map[string]interface{})
	if status := c.Query("status"); status != "" {
		filters["status"] = status
	}

	dbPlaybooks, err := s.playbookRepo.List(ctx, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list playbooks: " + err.Error()})
		return
	}

	// Se o banco estiver vazio, usar dados mock
	if len(dbPlaybooks) == 0 {
		s.handleListPlaybooksMock(c)
		return
	}

	// Converter para formato da API
	playbooks := make([]*Playbook, len(dbPlaybooks))
	for i, dbPlaybook := range dbPlaybooks {
		playbooks[i] = convertDBPlaybookToAPI(dbPlaybook)
	}

	c.JSON(http.StatusOK, gin.H{
		"playbooks": playbooks,
		"total":     len(playbooks),
	})
}

// handleGetPlaybook obtém detalhes de um playbook específico
func (s *APIServer) handleGetPlaybook(c *gin.Context) {
	id := c.Param("id")

	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleGetPlaybookOpenSearch(c)
		return
	}

	ctx := c.Request.Context()

	// Prioridade 2: Database repository
	if s.playbookRepo == nil {
		s.handleGetPlaybookMock(c, id)
		return
	}

	// Buscar do banco de dados
	dbPlaybook, err := s.playbookRepo.GetByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Playbook not found"})
		return
	}

	// Converter para formato da API
	playbook := convertDBPlaybookToAPI(dbPlaybook)

	c.JSON(http.StatusOK, playbook)
}

// handleCreatePlaybook cria um novo playbook
func (s *APIServer) handleCreatePlaybook(c *gin.Context) {
	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleCreatePlaybookOpenSearch(c)
		return
	}

	var playbook Playbook
	if err := c.ShouldBindJSON(&playbook); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Prioridade 2: Database repository
	if s.playbookRepo == nil {
		playbook.ID = uuid.New().String()
		playbook.CreatedAt = time.Now()
		playbook.UpdatedAt = time.Now()
		playbook.Executions = 0
		playbook.SuccessRate = 0
		playbook.AvgResponseTime = "0s"
		playbook.CreatedBy = "admin" // TODO: Get from JWT token
		c.JSON(http.StatusCreated, playbook)
		return
	}

	// Converter para formato do DB
	dbPlaybook, err := convertAPIPlaybookToDB(&playbook)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Salvar no banco de dados
	if err := s.playbookRepo.Create(ctx, dbPlaybook); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create playbook: " + err.Error()})
		return
	}

	// Converter de volta para formato da API
	playbook = *convertDBPlaybookToAPI(dbPlaybook)

	c.JSON(http.StatusCreated, playbook)
}

// handleUpdatePlaybook atualiza um playbook existente
func (s *APIServer) handleUpdatePlaybook(c *gin.Context) {
	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleUpdatePlaybookOpenSearch(c)
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	var playbook Playbook
	if err := c.ShouldBindJSON(&playbook); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Prioridade 2: Database repository
	if s.playbookRepo == nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "Playbook atualizado com sucesso",
			"id":      id,
		})
		return
	}

	playbook.ID = id

	// Converter para formato do DB
	dbPlaybook, err := convertAPIPlaybookToDB(&playbook)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Atualizar no banco de dados
	if err := s.playbookRepo.Update(ctx, dbPlaybook); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update playbook: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Playbook atualizado com sucesso",
		"id":      id,
	})
}

// handleDeletePlaybook deleta um playbook
func (s *APIServer) handleDeletePlaybook(c *gin.Context) {
	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleDeletePlaybookOpenSearch(c)
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	// Prioridade 2: Database repository
	if s.playbookRepo == nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "Playbook deletado com sucesso",
			"id":      id,
		})
		return
	}

	// Deletar do banco de dados
	if err := s.playbookRepo.Delete(ctx, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete playbook: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Playbook deletado com sucesso",
		"id":      id,
	})
}

// handleExecutePlaybook executa um playbook
func (s *APIServer) handleExecutePlaybook(c *gin.Context) {
	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleExecutePlaybookOpenSearch(c)
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	var triggerData map[string]interface{}
	if err := c.ShouldBindJSON(&triggerData); err != nil {
		triggerData = make(map[string]interface{})
	}

	// Buscar playbook
	var playbook *Playbook
	if s.playbookRepo != nil {
		dbPlaybook, err := s.playbookRepo.GetByID(ctx, id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Playbook not found"})
			return
		}
		playbook = convertDBPlaybookToAPI(dbPlaybook)
	} else {
		// Mock playbook
		playbook = &Playbook{
			ID:          id,
			Name:        "Bloqueio de IP Malicioso",
			Description: "Bloqueia automaticamente IPs identificados como maliciosos no firewall",
			Trigger:     "Alerta de Força Bruta",
			Actions: []PlaybookAction{
				{Type: "block_ip", Target: "firewall", Params: map[string]interface{}{"duration": "24h", "ip": triggerData["source_ip"]}},
				{Type: "create_ticket", Target: "jira", Params: map[string]interface{}{"priority": "high"}},
				{Type: "notify_slack", Target: "slack", Params: map[string]interface{}{"channel": "security"}},
			},
			Status: "active",
		}
	}

	// Criar motor de execução
	engine := NewPlaybookEngine(s)

	// Executar playbook
	execution, err := engine.ExecutePlaybook(playbook, triggerData, "admin") // TODO: Get from JWT token
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, execution)
}

// handleGetExecution obtém detalhes de uma execução
func (s *APIServer) handleGetExecution(c *gin.Context) {
	id := c.Param("id")

	// Buscar do Redis
	executionJSON, err := s.redis.Get(context.Background(), "execution:"+id).Result()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Execução não encontrada"})
		return
	}

	var execution PlaybookExecution
	if err := json.Unmarshal([]byte(executionJSON), &execution); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao processar execução"})
		return
	}

	c.JSON(http.StatusOK, execution)
}

// handleListExecutions lista histórico de execuções
func (s *APIServer) handleListExecutions(c *gin.Context) {
	playbookID := c.Query("playbook_id")
	ctx := c.Request.Context()

	// Se não tiver repository, retornar mock
	if s.playbookRepo == nil {
		executions := []PlaybookExecution{
			{
				ID:            uuid.New().String(),
				PlaybookID:    playbookID,
				PlaybookName:  "Bloqueio de IP Malicioso",
				Status:        "success",
				StartTime:     time.Now().Add(-2 * time.Hour),
				EndTime:       timePtr(time.Now().Add(-2*time.Hour + 3*time.Second)),
				Duration:      "3.2s",
				ExecutedBy:    "system",
				ExecutionMode: "automatic",
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"executions": executions,
			"total":      len(executions),
		})
		return
	}

	// Buscar do banco de dados
	limit := 50
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	dbExecutions, err := s.playbookRepo.GetExecutionsByPlaybookID(ctx, playbookID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list executions: " + err.Error()})
		return
	}

	// Converter para formato da API
	executions := make([]PlaybookExecution, len(dbExecutions))
	for i, dbExec := range dbExecutions {
		var steps []ExecutionStep
		if err := json.Unmarshal(dbExec.Steps, &steps); err != nil {
			steps = []ExecutionStep{}
		}

		var triggerData map[string]interface{}
		if dbExec.TriggerData != nil {
			json.Unmarshal(dbExec.TriggerData, &triggerData)
		}

		duration := ""
		if dbExec.DurationMs != nil {
			duration = fmt.Sprintf("%dms", *dbExec.DurationMs)
			if *dbExec.DurationMs > 1000 {
				duration = fmt.Sprintf("%.1fs", float64(*dbExec.DurationMs)/1000)
			}
		}

		executions[i] = PlaybookExecution{
			ID:            dbExec.ID,
			PlaybookID:    dbExec.PlaybookID,
			PlaybookName:  "", // TODO: Join with playbooks table
			Status:        dbExec.Status,
			StartTime:     dbExec.StartedAt,
			EndTime:       dbExec.CompletedAt,
			Duration:      duration,
			Steps:         steps,
			TriggerData:   triggerData,
			ExecutedBy:    getStringValue(dbExec.ExecutedBy),
			ExecutionMode: "automatic",
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"executions": executions,
		"total":      len(executions),
	})
}

// handleGetPlaybookStatistics obtém estatísticas de um playbook
func (s *APIServer) handleGetPlaybookStatistics(c *gin.Context) {
	// Prioridade 1: OpenSearch (real-time)
	if s.opensearch != nil {
		s.handleGetPlaybookStatisticsOpenSearch(c)
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	// Prioridade 2: Database repository
	if s.playbookRepo == nil {
		stats := gin.H{
			"playbook_id": id,
			"executions": gin.H{
				"total":      147,
				"successful": 145,
				"failed":     2,
				"today":      23,
				"this_week":  67,
				"this_month": 147,
			},
			"performance": gin.H{
				"avg_response_time": "2.3s",
				"min_response_time": "1.8s",
				"max_response_time": "4.5s",
				"success_rate":      98.5,
			},
			"actions": gin.H{
				"most_used":   "block_ip",
				"most_failed": "create_ticket",
			},
		}
		c.JSON(http.StatusOK, stats)
		return
	}

	// Buscar playbook do banco
	dbPlaybook, err := s.playbookRepo.GetByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Playbook not found"})
		return
	}

	// Calcular success rate
	successRate := 0.0
	if dbPlaybook.ExecutionCount > 0 {
		successRate = (float64(dbPlaybook.SuccessCount) / float64(dbPlaybook.ExecutionCount)) * 100
	}

	stats := gin.H{
		"playbook_id": id,
		"executions": gin.H{
			"total":      dbPlaybook.ExecutionCount,
			"successful": dbPlaybook.SuccessCount,
			"failed":     dbPlaybook.FailureCount,
			"today":      0, // TODO: Calculate from executions table
			"this_week":  0,
			"this_month": dbPlaybook.ExecutionCount,
		},
		"performance": gin.H{
			"avg_response_time": fmt.Sprintf("%dms", dbPlaybook.AvgExecutionTimeMs),
			"min_response_time": "N/A", // TODO: Calculate from executions
			"max_response_time": "N/A",
			"success_rate":      successRate,
		},
		"actions": gin.H{
			"most_used":   "N/A", // TODO: Analyze from executions
			"most_failed": "N/A",
		},
	}

	c.JSON(http.StatusOK, stats)
}

// ============================================================================
// MOCK HANDLERS (Fallback quando DB não está disponível)
// ============================================================================

func (s *APIServer) handleListPlaybooksMock(c *gin.Context) {
	playbooks := []Playbook{
		{
			ID:              "pb-001",
			Name:            "Bloqueio de IP Malicioso",
			Description:     "Bloqueia automaticamente IPs identificados como maliciosos no firewall após detecção de força bruta",
			Trigger:         "Alerta de Força Bruta",
			Actions: []PlaybookAction{
				{Type: "block_ip", Target: "firewall", Params: map[string]interface{}{"duration": "24h", "rule_name": "auto_block"}},
				{Type: "create_ticket", Target: "jira", Params: map[string]interface{}{"priority": "high", "assignee": "soc-team"}},
				{Type: "notify", Target: "slack", Params: map[string]interface{}{"channel": "security-alerts"}},
			},
			Status:          "active",
			Executions:      147,
			LastExecution:   timePtr(time.Now().Add(-2 * time.Hour)),
			SuccessRate:     98.5,
			AvgResponseTime: "2.3s",
			CreatedAt:       time.Now().Add(-30 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-002",
			Name:            "Isolamento de Host Comprometido",
			Description:     "Isola host da rede ao detectar comportamento suspeito ou malware ativo",
			Trigger:         "Anomalia de Comportamento (ML)",
			Actions: []PlaybookAction{
				{Type: "isolate_host", Target: "edr", Params: map[string]interface{}{"method": "network_isolation"}},
				{Type: "create_incident", Target: "case_management", Params: map[string]interface{}{"severity": "critical"}},
				{Type: "notify", Target: "email", Params: map[string]interface{}{"recipients": "soc@company.com"}},
				{Type: "run_scan", Target: "antivirus", Params: map[string]interface{}{"full_scan": true}},
			},
			Status:          "active",
			Executions:      23,
			LastExecution:   timePtr(time.Now().Add(-26 * time.Hour)),
			SuccessRate:     100,
			AvgResponseTime: "5.7s",
			CreatedAt:       time.Now().Add(-60 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-30 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-003",
			Name:            "Resposta a Phishing",
			Description:     "Resposta automatizada para tentativas de phishing: bloqueia URLs, quarentena emails e notifica usuários",
			Trigger:         "Detecção de Phishing",
			Actions: []PlaybookAction{
				{Type: "block_url", Target: "proxy", Params: map[string]interface{}{"category": "phishing"}},
				{Type: "quarantine_email", Target: "email_gateway", Params: map[string]interface{}{"action": "delete_all"}},
				{Type: "notify_users", Target: "email", Params: map[string]interface{}{"template": "phishing_warning"}},
				{Type: "create_case", Target: "case_management", Params: map[string]interface{}{"severity": "high", "category": "phishing"}},
			},
			Status:          "active",
			Executions:      89,
			LastExecution:   timePtr(time.Now().Add(-5 * time.Hour)),
			SuccessRate:     96.6,
			AvgResponseTime: "3.1s",
			CreatedAt:       time.Now().Add(-45 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-10 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-004",
			Name:            "Mitigação de Ransomware",
			Description:     "Resposta rápida a detecção de ransomware: isola host, bloqueia C2, backup de dados críticos",
			Trigger:         "Detecção de Ransomware",
			Actions: []PlaybookAction{
				{Type: "isolate_host", Target: "edr", Params: map[string]interface{}{"immediate": true}},
				{Type: "block_c2", Target: "firewall", Params: map[string]interface{}{"threat_feed": "ransomware_iocs"}},
				{Type: "snapshot_vm", Target: "hypervisor", Params: map[string]interface{}{"preserve_state": true}},
				{Type: "kill_process", Target: "edr", Params: map[string]interface{}{"suspicious_only": true}},
				{Type: "create_incident", Target: "case_management", Params: map[string]interface{}{"severity": "critical", "category": "ransomware"}},
				{Type: "notify", Target: "pagerduty", Params: map[string]interface{}{"escalation": "immediate"}},
			},
			Status:          "active",
			Executions:      7,
			LastExecution:   timePtr(time.Now().Add(-72 * time.Hour)),
			SuccessRate:     100,
			AvgResponseTime: "8.2s",
			CreatedAt:       time.Now().Add(-90 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-15 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-005",
			Name:            "Bloqueio de DDoS",
			Description:     "Mitigação automática de ataques DDoS através de rate limiting e blackholing",
			Trigger:         "Detecção de DDoS",
			Actions: []PlaybookAction{
				{Type: "enable_rate_limit", Target: "waf", Params: map[string]interface{}{"threshold": "1000req/s"}},
				{Type: "blackhole_traffic", Target: "cdn", Params: map[string]interface{}{"duration": "1h"}},
				{Type: "notify", Target: "slack", Params: map[string]interface{}{"channel": "infrastructure"}},
				{Type: "create_ticket", Target: "jira", Params: map[string]interface{}{"priority": "critical"}},
			},
			Status:          "active",
			Executions:      34,
			LastExecution:   timePtr(time.Now().Add(-18 * time.Hour)),
			SuccessRate:     94.1,
			AvgResponseTime: "1.8s",
			CreatedAt:       time.Now().Add(-120 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-5 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-006",
			Name:            "Revogação de Credenciais Comprometidas",
			Description:     "Revoga automaticamente credenciais comprometidas e força reset de senha",
			Trigger:         "Credenciais Vazadas",
			Actions: []PlaybookAction{
				{Type: "revoke_tokens", Target: "identity_provider", Params: map[string]interface{}{"all_sessions": true}},
				{Type: "disable_account", Target: "active_directory", Params: map[string]interface{}{"temporary": true}},
				{Type: "force_password_reset", Target: "identity_provider", Params: map[string]interface{}{"notify_user": true}},
				{Type: "create_case", Target: "case_management", Params: map[string]interface{}{"severity": "high", "category": "credential_theft"}},
				{Type: "notify", Target: "email", Params: map[string]interface{}{"template": "account_compromised"}},
			},
			Status:          "active",
			Executions:      56,
			LastExecution:   timePtr(time.Now().Add(-8 * time.Hour)),
			SuccessRate:     98.2,
			AvgResponseTime: "4.5s",
			CreatedAt:       time.Now().Add(-75 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-20 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-007",
			Name:            "Resposta a Data Exfiltration",
			Description:     "Detecta e bloqueia tentativas de exfiltração de dados sensíveis",
			Trigger:         "Anomalia de Transferência de Dados",
			Actions: []PlaybookAction{
				{Type: "block_connection", Target: "firewall", Params: map[string]interface{}{"direction": "outbound"}},
				{Type: "isolate_host", Target: "edr", Params: map[string]interface{}{"partial": true}},
				{Type: "capture_traffic", Target: "network_monitor", Params: map[string]interface{}{"duration": "5m"}},
				{Type: "create_incident", Target: "case_management", Params: map[string]interface{}{"severity": "critical", "category": "data_breach"}},
				{Type: "notify", Target: "pagerduty", Params: map[string]interface{}{"escalation": "high"}},
			},
			Status:          "active",
			Executions:      12,
			LastExecution:   timePtr(time.Now().Add(-48 * time.Hour)),
			SuccessRate:     100,
			AvgResponseTime: "6.3s",
			CreatedAt:       time.Now().Add(-50 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-12 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-008",
			Name:            "Bloqueio de Malware em Email",
			Description:     "Quarentena automática de emails com anexos maliciosos",
			Trigger:         "Detecção de Malware em Email",
			Actions: []PlaybookAction{
				{Type: "quarantine_email", Target: "email_gateway", Params: map[string]interface{}{"action": "quarantine"}},
				{Type: "block_sender", Target: "email_gateway", Params: map[string]interface{}{"duration": "permanent"}},
				{Type: "notify_recipient", Target: "email", Params: map[string]interface{}{"template": "malware_blocked"}},
				{Type: "create_ticket", Target: "jira", Params: map[string]interface{}{"priority": "medium"}},
			},
			Status:          "active",
			Executions:      203,
			LastExecution:   timePtr(time.Now().Add(-1 * time.Hour)),
			SuccessRate:     99.5,
			AvgResponseTime: "1.2s",
			CreatedAt:       time.Now().Add(-180 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-7 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-009",
			Name:            "Resposta a Insider Threat",
			Description:     "Resposta a comportamento anômalo de usuário interno",
			Trigger:         "Anomalia de Comportamento de Usuário",
			Actions: []PlaybookAction{
				{Type: "increase_monitoring", Target: "ueba", Params: map[string]interface{}{"level": "high"}},
				{Type: "restrict_access", Target: "identity_provider", Params: map[string]interface{}{"sensitive_only": true}},
				{Type: "create_case", Target: "case_management", Params: map[string]interface{}{"severity": "high", "category": "insider_threat", "confidential": true}},
				{Type: "notify", Target: "email", Params: map[string]interface{}{"recipients": "security_manager@company.com"}},
			},
			Status:          "active",
			Executions:      18,
			LastExecution:   timePtr(time.Now().Add(-36 * time.Hour)),
			SuccessRate:     94.4,
			AvgResponseTime: "3.7s",
			CreatedAt:       time.Now().Add(-65 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-18 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-010",
			Name:            "Patch de Vulnerabilidade Crítica",
			Description:     "Aplicação automática de patches críticos em sistemas vulneráveis",
			Trigger:         "Vulnerabilidade Crítica Detectada",
			Actions: []PlaybookAction{
				{Type: "scan_assets", Target: "vulnerability_scanner", Params: map[string]interface{}{"severity": "critical"}},
				{Type: "deploy_patch", Target: "patch_management", Params: map[string]interface{}{"auto_approve": true, "test_group": "pilot"}},
				{Type: "verify_patch", Target: "vulnerability_scanner", Params: map[string]interface{}{"rescan": true}},
				{Type: "create_report", Target: "reporting", Params: map[string]interface{}{"template": "patch_deployment"}},
				{Type: "notify", Target: "email", Params: map[string]interface{}{"recipients": "it_ops@company.com"}},
			},
			Status:          "testing",
			Executions:      5,
			LastExecution:   timePtr(time.Now().Add(-96 * time.Hour)),
			SuccessRate:     80.0,
			AvgResponseTime: "12.5s",
			CreatedAt:       time.Now().Add(-20 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-3 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-011",
			Name:            "Resposta a SQL Injection",
			Description:     "Bloqueia tentativas de SQL injection e protege banco de dados",
			Trigger:         "Detecção de SQL Injection",
			Actions: []PlaybookAction{
				{Type: "block_ip", Target: "waf", Params: map[string]interface{}{"duration": "48h"}},
				{Type: "enable_waf_rule", Target: "waf", Params: map[string]interface{}{"rule_id": "sqli_protection"}},
				{Type: "audit_database", Target: "database", Params: map[string]interface{}{"check_integrity": true}},
				{Type: "create_incident", Target: "case_management", Params: map[string]interface{}{"severity": "high", "category": "sql_injection"}},
				{Type: "notify", Target: "slack", Params: map[string]interface{}{"channel": "security-alerts"}},
			},
			Status:          "active",
			Executions:      41,
			LastExecution:   timePtr(time.Now().Add(-12 * time.Hour)),
			SuccessRate:     97.6,
			AvgResponseTime: "2.8s",
			CreatedAt:       time.Now().Add(-100 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-8 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
		{
			ID:              "pb-012",
			Name:            "Contenção de Lateral Movement",
			Description:     "Detecta e bloqueia movimentação lateral na rede",
			Trigger:         "Detecção de Lateral Movement",
			Actions: []PlaybookAction{
				{Type: "segment_network", Target: "firewall", Params: map[string]interface{}{"micro_segmentation": true}},
				{Type: "isolate_affected_hosts", Target: "edr", Params: map[string]interface{}{"count": "multiple"}},
				{Type: "revoke_credentials", Target: "identity_provider", Params: map[string]interface{}{"compromised_accounts": true}},
				{Type: "create_incident", Target: "case_management", Params: map[string]interface{}{"severity": "critical", "category": "lateral_movement"}},
				{Type: "notify", Target: "pagerduty", Params: map[string]interface{}{"escalation": "immediate"}},
			},
			Status:          "active",
			Executions:      9,
			LastExecution:   timePtr(time.Now().Add(-120 * time.Hour)),
			SuccessRate:     100,
			AvgResponseTime: "7.9s",
			CreatedAt:       time.Now().Add(-85 * 24 * time.Hour),
			UpdatedAt:       time.Now().Add(-25 * 24 * time.Hour),
			CreatedBy:       "admin",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"playbooks": playbooks,
		"total":     len(playbooks),
	})
}

func (s *APIServer) handleGetPlaybookMock(c *gin.Context, id string) {
	playbook := Playbook{
		ID:              id,
		Name:            "Bloqueio de IP Malicioso",
		Description:     "Bloqueia automaticamente IPs identificados como maliciosos no firewall",
		Trigger:         "Alerta de Força Bruta",
		Actions: []PlaybookAction{
			{Type: "block_ip", Target: "firewall", Params: map[string]interface{}{"duration": "24h"}},
			{Type: "create_ticket", Target: "jira", Params: map[string]interface{}{"priority": "high"}},
			{Type: "notify", Target: "slack", Params: map[string]interface{}{"channel": "security"}},
		},
		Status:          "active",
		Executions:      147,
		LastExecution:   timePtr(time.Now().Add(-2 * time.Hour)),
		SuccessRate:     98.5,
		AvgResponseTime: "2.3s",
		CreatedAt:       time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:       time.Now().Add(-24 * time.Hour),
		CreatedBy:       "admin",
	}

	c.JSON(http.StatusOK, playbook)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func timePtr(t time.Time) *time.Time {
	return &t
}

func getStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
