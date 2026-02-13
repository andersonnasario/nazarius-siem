package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

// PlaybookEngine é o motor de execução de playbooks
type PlaybookEngine struct {
	server          *APIServer
	executions      map[string]*PlaybookExecution
	integrations    *Integrations
	awsIntegrations *AWSIntegrations
}

// Integrations contém todas as integrações externas
type Integrations struct {
	slack    *SlackIntegration
	email    *EmailIntegration
	webhook  *WebhookIntegration
	firewall *FirewallIntegration
}

// NewPlaybookEngine cria uma nova instância do motor
func NewPlaybookEngine(server *APIServer) *PlaybookEngine {
	return &PlaybookEngine{
		server:     server,
		executions: make(map[string]*PlaybookExecution),
		integrations: &Integrations{
			slack:    NewSlackIntegration(),
			email:    NewEmailIntegration(),
			webhook:  NewWebhookIntegration(),
			firewall: NewFirewallIntegration(),
		},
		awsIntegrations: InitAWSIntegrations(),
	}
}

// ExecutePlaybook executa um playbook de forma assíncrona
func (pe *PlaybookEngine) ExecutePlaybook(playbook *Playbook, triggerData map[string]interface{}, executedBy string) (*PlaybookExecution, error) {
	execution := &PlaybookExecution{
		ID:            uuid.New().String(),
		PlaybookID:    playbook.ID,
		PlaybookName:  playbook.Name,
		Status:        "running",
		StartTime:     time.Now(),
		TriggerData:   triggerData,
		ExecutedBy:    executedBy,
		ExecutionMode: "automatic",
		Steps:         []ExecutionStep{},
	}

	pe.executions[execution.ID] = execution

	// Executar em background
	go pe.executeAsync(execution, playbook)

	return execution, nil
}

// executeAsync executa o playbook de forma assíncrona
func (pe *PlaybookEngine) executeAsync(execution *PlaybookExecution, playbook *Playbook) {
	ctx := context.Background()
	log.Printf("[SOAR] Iniciando execução do playbook: %s (ID: %s)", playbook.Name, execution.ID)

	for i, action := range playbook.Actions {
		step := ExecutionStep{
			Step:      i + 1,
			Action:    fmt.Sprintf("%s on %s", action.Type, action.Target),
			Status:    "running",
			StartTime: time.Now(),
		}

		execution.Steps = append(execution.Steps, step)

		// Executar ação
		result, err := pe.executeAction(ctx, &action, execution.TriggerData)
		
		endTime := time.Now()
		duration := endTime.Sub(step.StartTime)

		if err != nil {
			log.Printf("[SOAR] Erro na ação %d: %v", i+1, err)
			execution.Steps[i].Status = "failed"
			execution.Steps[i].Error = err.Error()
			execution.Steps[i].EndTime = &endTime
			execution.Steps[i].Duration = duration.String()
			
			// Falha crítica? Abortar playbook
			execution.Status = "failed"
			break
		}

		// Sucesso
		execution.Steps[i].Status = "success"
		execution.Steps[i].Result = result
		execution.Steps[i].EndTime = &endTime
		execution.Steps[i].Duration = duration.String()

		log.Printf("[SOAR] Ação %d completada com sucesso em %s", i+1, duration)
	}

	// Finalizar execução
	endTime := time.Now()
	duration := endTime.Sub(execution.StartTime)
	
	if execution.Status != "failed" {
		execution.Status = "success"
	}
	
	execution.EndTime = &endTime
	execution.Duration = duration.String()

	log.Printf("[SOAR] Execução finalizada: %s - Status: %s - Duração: %s", 
		execution.ID, execution.Status, execution.Duration)

	// Salvar no Redis e Elasticsearch
	pe.saveExecution(ctx, execution)
}

// executeAction executa uma ação específica
func (pe *PlaybookEngine) executeAction(ctx context.Context, action *PlaybookAction, triggerData map[string]interface{}) (map[string]interface{}, error) {
	log.Printf("[SOAR] Executando ação: %s -> %s", action.Type, action.Target)

	switch action.Type {
	// ===== AWS Actions (Real) =====
	case "invoke_lambda":
		return pe.awsIntegrations.ExecuteAWSAction(ctx, action.Type, action.Params, triggerData)
	
	case "send_sns", "notify_sns":
		return pe.awsIntegrations.ExecuteAWSAction(ctx, "send_sns", action.Params, triggerData)
	
	case "isolate_ec2", "isolate_instance":
		return pe.awsIntegrations.ExecuteAWSAction(ctx, "isolate_instance", action.Params, triggerData)
	
	case "revoke_iam_access":
		return pe.awsIntegrations.ExecuteAWSAction(ctx, "revoke_iam_access", action.Params, triggerData)
	
	case "block_ip_waf":
		return pe.awsIntegrations.ExecuteAWSAction(ctx, "block_ip_waf", action.Params, triggerData)

	// ===== Legacy/Simulated Actions =====
	case "block_ip":
		return pe.integrations.firewall.BlockIP(ctx, action.Params, triggerData)
	
	case "block_domain":
		return pe.integrations.firewall.BlockDomain(ctx, action.Params, triggerData)
	
	case "isolate_host":
		return pe.executeIsolateHost(ctx, action.Params)
	
	case "revoke_access":
		return pe.executeRevokeAccess(ctx, action.Params)
	
	case "reset_password":
		return pe.executeResetPassword(ctx, action.Params)
	
	case "create_ticket":
		return pe.executeCreateTicket(ctx, action.Params)
	
	case "create_incident":
		return pe.executeCreateIncident(ctx, action.Params)
	
	case "notify", "notify_email":
		return pe.integrations.email.SendNotification(ctx, action.Params, triggerData)
	
	case "notify_slack":
		return pe.integrations.slack.SendNotification(ctx, action.Params, triggerData)
	
	case "notify_teams", "notify_webhook", "webhook":
		return pe.integrations.webhook.SendNotification(ctx, action.Params, triggerData)
	
	case "run_scan":
		return pe.executeRunScan(ctx, action.Params)
	
	case "log_event":
		return pe.executeLogEvent(ctx, action.Params)
	
	default:
		return nil, fmt.Errorf("ação não suportada: %s", action.Type)
	}
}

// Implementações das ações
func (pe *PlaybookEngine) executeIsolateHost(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	host := params["host"]
	method := params["method"]
	
	log.Printf("[SOAR] Isolando host: %v (método: %v)", host, method)
	time.Sleep(500 * time.Millisecond) // Simular execução
	
	return map[string]interface{}{
		"status":  "success",
		"host":    host,
		"method":  method,
		"message": "Host isolado com sucesso",
	}, nil
}

func (pe *PlaybookEngine) executeRevokeAccess(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	user := params["user"]
	
	log.Printf("[SOAR] Revogando acesso do usuário: %v", user)
	time.Sleep(300 * time.Millisecond)
	
	return map[string]interface{}{
		"status":  "success",
		"user":    user,
		"message": "Acesso revogado com sucesso",
	}, nil
}

func (pe *PlaybookEngine) executeResetPassword(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	user := params["user"]
	requireMFA := params["require_mfa"]
	
	log.Printf("[SOAR] Resetando senha do usuário: %v (MFA: %v)", user, requireMFA)
	time.Sleep(400 * time.Millisecond)
	
	return map[string]interface{}{
		"status":      "success",
		"user":        user,
		"require_mfa": requireMFA,
		"message":     "Senha resetada com sucesso",
	}, nil
}

func (pe *PlaybookEngine) executeCreateTicket(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	priority := params["priority"]
	ticketID := fmt.Sprintf("TICKET-%d", time.Now().Unix())
	
	log.Printf("[SOAR] Criando ticket: %s (prioridade: %v)", ticketID, priority)
	time.Sleep(600 * time.Millisecond)
	
	return map[string]interface{}{
		"status":    "success",
		"ticket_id": ticketID,
		"priority":  priority,
		"message":   "Ticket criado com sucesso",
	}, nil
}

func (pe *PlaybookEngine) executeCreateIncident(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	severity := params["severity"]
	incidentID := uuid.New().String()
	
	log.Printf("[SOAR] Criando incidente: %s (severidade: %v)", incidentID, severity)
	time.Sleep(500 * time.Millisecond)
	
	return map[string]interface{}{
		"status":      "success",
		"incident_id": incidentID,
		"severity":    severity,
		"message":     "Incidente criado com sucesso",
	}, nil
}

func (pe *PlaybookEngine) executeRunScan(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	target := params["target"]
	scanType := params["scan_type"]
	
	log.Printf("[SOAR] Iniciando scan: %v (tipo: %v)", target, scanType)
	time.Sleep(700 * time.Millisecond)
	
	return map[string]interface{}{
		"status":    "success",
		"target":    target,
		"scan_type": scanType,
		"message":   "Scan iniciado com sucesso",
	}, nil
}

func (pe *PlaybookEngine) executeLogEvent(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	severity := params["severity"]
	message := params["message"]
	
	log.Printf("[SOAR] Registrando evento: %v (severidade: %v)", message, severity)
	
	return map[string]interface{}{
		"status":   "success",
		"severity": severity,
		"message":  "Evento registrado com sucesso",
	}, nil
}

// saveExecution salva a execução no Redis e Elasticsearch
func (pe *PlaybookEngine) saveExecution(ctx context.Context, execution *PlaybookExecution) {
	// Salvar no Redis (cache de curto prazo)
	executionJSON, _ := json.Marshal(execution)
	pe.server.redis.Set(ctx, "execution:"+execution.ID, executionJSON, 24*time.Hour)
	
	// TODO: Salvar no Elasticsearch para histórico de longo prazo
	// Index: siem-playbook-executions
	
	log.Printf("[SOAR] Execução salva: %s", execution.ID)
}

// GetExecution retorna uma execução específica
func (pe *PlaybookEngine) GetExecution(id string) (*PlaybookExecution, error) {
	if execution, exists := pe.executions[id]; exists {
		return execution, nil
	}
	
	// Tentar buscar do Redis
	ctx := context.Background()
	executionJSON, err := pe.server.redis.Get(ctx, "execution:"+id).Result()
	if err != nil {
		return nil, fmt.Errorf("execução não encontrada")
	}
	
	var execution PlaybookExecution
	if err := json.Unmarshal([]byte(executionJSON), &execution); err != nil {
		return nil, err
	}
	
	return &execution, nil
}

// ===== INTEGRAÇÕES =====

// SlackIntegration - Integração com Slack
type SlackIntegration struct{}

func NewSlackIntegration() *SlackIntegration {
	return &SlackIntegration{}
}

func (s *SlackIntegration) SendNotification(ctx context.Context, params map[string]interface{}, triggerData map[string]interface{}) (map[string]interface{}, error) {
	channel := params["channel"]
	message := params["message"]
	
	if message == nil {
		message = fmt.Sprintf("Alerta de segurança! Trigger data: %v", triggerData)
	}
	
	log.Printf("[SLACK] Enviando para #%v: %v", channel, message)
	time.Sleep(200 * time.Millisecond)
	
	return map[string]interface{}{
		"status":    "success",
		"channel":   channel,
		"timestamp": time.Now().Unix(),
		"message":   "Notificação enviada para Slack",
	}, nil
}

// EmailIntegration - Integração com Email
type EmailIntegration struct{}

func NewEmailIntegration() *EmailIntegration {
	return &EmailIntegration{}
}

func (e *EmailIntegration) SendNotification(ctx context.Context, params map[string]interface{}, triggerData map[string]interface{}) (map[string]interface{}, error) {
	recipients := params["recipients"]
	subject := params["subject"]
	
	if subject == nil {
		subject = "Alerta de Segurança - SIEM Platform"
	}
	
	log.Printf("[EMAIL] Enviando para %v: %v", recipients, subject)
	time.Sleep(300 * time.Millisecond)
	
	return map[string]interface{}{
		"status":     "success",
		"recipients": recipients,
		"subject":    subject,
		"message":    "Email enviado com sucesso",
	}, nil
}

// WebhookIntegration - Integração com Webhooks
type WebhookIntegration struct{}

func NewWebhookIntegration() *WebhookIntegration {
	return &WebhookIntegration{}
}

func (w *WebhookIntegration) SendNotification(ctx context.Context, params map[string]interface{}, triggerData map[string]interface{}) (map[string]interface{}, error) {
	endpoint := params["endpoint"]
	
	log.Printf("[WEBHOOK] Chamando endpoint: %v", endpoint)
	time.Sleep(250 * time.Millisecond)
	
	return map[string]interface{}{
		"status":      "success",
		"endpoint":    endpoint,
		"status_code": 200,
		"message":     "Webhook chamado com sucesso",
	}, nil
}

// FirewallIntegration - Integração com Firewall
type FirewallIntegration struct{}

func NewFirewallIntegration() *FirewallIntegration {
	return &FirewallIntegration{}
}

func (f *FirewallIntegration) BlockIP(ctx context.Context, params map[string]interface{}, triggerData map[string]interface{}) (map[string]interface{}, error) {
	ip := params["ip"]
	if ip == nil {
		// Extrair IP do triggerData
		ip = triggerData["source_ip"]
	}
	
	duration := params["duration"]
	
	log.Printf("[FIREWALL] Bloqueando IP: %v (duração: %v)", ip, duration)
	time.Sleep(400 * time.Millisecond)
	
	return map[string]interface{}{
		"status":   "success",
		"ip":       ip,
		"duration": duration,
		"rule_id":  fmt.Sprintf("RULE-%d", time.Now().Unix()),
		"message":  "IP bloqueado no firewall",
	}, nil
}

func (f *FirewallIntegration) BlockDomain(ctx context.Context, params map[string]interface{}, triggerData map[string]interface{}) (map[string]interface{}, error) {
	domain := params["domain"]
	if domain == nil {
		domain = triggerData["domain"]
	}
	
	scope := params["scope"]
	
	log.Printf("[FIREWALL] Bloqueando domínio: %v (escopo: %v)", domain, scope)
	time.Sleep(350 * time.Millisecond)
	
	return map[string]interface{}{
		"status":  "success",
		"domain":  domain,
		"scope":   scope,
		"rule_id": fmt.Sprintf("DOMAIN-RULE-%d", time.Now().Unix()),
		"message": "Domínio bloqueado",
	}, nil
}

