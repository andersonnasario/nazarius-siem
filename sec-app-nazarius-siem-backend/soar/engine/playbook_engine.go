package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
)

// PlaybookAction representa uma ação em um playbook
type PlaybookAction struct {
	Type   string                 `json:"type"`
	Target string                 `json:"target"`
	Params map[string]interface{} `json:"params"`
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

// PlaybookEngine é o motor de execução de playbooks
type PlaybookEngine struct {
	redis      *redis.Client
	integrations map[string]Integration
}

// Integration define a interface para integrações
type Integration interface {
	Execute(ctx context.Context, action PlaybookAction) (map[string]interface{}, error)
	Name() string
	Type() string
}

// NewPlaybookEngine cria uma nova instância do motor
func NewPlaybookEngine(redis *redis.Client) *PlaybookEngine {
	engine := &PlaybookEngine{
		redis:        redis,
		integrations: make(map[string]Integration),
	}

	// Registrar integrações disponíveis
	engine.RegisterIntegration(&FirewallIntegration{})
	engine.RegisterIntegration(&EDRIntegration{})
	engine.RegisterIntegration(&EmailIntegration{})
	engine.RegisterIntegration(&SlackIntegration{})
	engine.RegisterIntegration(&JiraIntegration{})
	engine.RegisterIntegration(&ActiveDirectoryIntegration{})

	return engine
}

// RegisterIntegration registra uma nova integração
func (e *PlaybookEngine) RegisterIntegration(integration Integration) {
	e.integrations[integration.Name()] = integration
	log.Printf("Integração registrada: %s (%s)", integration.Name(), integration.Type())
}

// ExecutePlaybook executa um playbook completo
func (e *PlaybookEngine) ExecutePlaybook(ctx context.Context, execution *PlaybookExecution, actions []PlaybookAction) error {
	log.Printf("Iniciando execução do playbook %s (ID: %s)", execution.PlaybookName, execution.PlaybookID)

	for i, action := range actions {
		step := ExecutionStep{
			Step:      i + 1,
			Action:    fmt.Sprintf("%s on %s", action.Type, action.Target),
			Status:    "running",
			StartTime: time.Now(),
		}

		execution.Steps = append(execution.Steps, step)

		// Salvar estado no Redis
		e.saveExecution(ctx, execution)

		// Executar ação
		result, err := e.executeAction(ctx, action)

		endTime := time.Now()
		duration := endTime.Sub(step.StartTime)
		execution.Steps[i].EndTime = &endTime
		execution.Steps[i].Duration = duration.String()

		if err != nil {
			execution.Steps[i].Status = "failed"
			execution.Steps[i].Error = err.Error()
			log.Printf("Erro ao executar ação %d: %v", i+1, err)

			// Continuar com próxima ação ou falhar?
			// Por enquanto, continuamos
			continue
		}

		execution.Steps[i].Status = "success"
		execution.Steps[i].Result = result
		log.Printf("Ação %d executada com sucesso", i+1)

		// Salvar estado atualizado
		e.saveExecution(ctx, execution)
	}

	// Finalizar execução
	endTime := time.Now()
	duration := endTime.Sub(execution.StartTime)
	execution.EndTime = &endTime
	execution.Duration = duration.String()

	// Determinar status final
	failedSteps := 0
	for _, step := range execution.Steps {
		if step.Status == "failed" {
			failedSteps++
		}
	}

	if failedSteps == 0 {
		execution.Status = "success"
	} else if failedSteps == len(execution.Steps) {
		execution.Status = "failed"
	} else {
		execution.Status = "partial"
	}

	// Salvar execução final
	e.saveExecution(ctx, execution)

	log.Printf("Execução finalizada: %s (Duração: %s, Steps failed: %d/%d)",
		execution.Status, execution.Duration, failedSteps, len(execution.Steps))

	return nil
}

// executeAction executa uma ação específica
func (e *PlaybookEngine) executeAction(ctx context.Context, action PlaybookAction) (map[string]interface{}, error) {
	integration, exists := e.integrations[action.Target]
	if !exists {
		return nil, fmt.Errorf("integração não encontrada: %s", action.Target)
	}

	return integration.Execute(ctx, action)
}

// saveExecution salva o estado da execução no Redis
func (e *PlaybookEngine) saveExecution(ctx context.Context, execution *PlaybookExecution) error {
	data, err := json.Marshal(execution)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("execution:%s", execution.ID)
	return e.redis.Set(ctx, key, data, 24*time.Hour).Err()
}

// =====================================================
// INTEGRAÇÕES
// =====================================================

// FirewallIntegration - Integração com firewall
type FirewallIntegration struct{}

func (i *FirewallIntegration) Name() string { return "firewall" }
func (i *FirewallIntegration) Type() string { return "network" }

func (i *FirewallIntegration) Execute(ctx context.Context, action PlaybookAction) (map[string]interface{}, error) {
	time.Sleep(500 * time.Millisecond) // Simular latência

	switch action.Type {
	case "block_ip":
		ip := action.Params["ip"]
		duration := action.Params["duration"]
		log.Printf("✅ IP %s bloqueado no firewall por %s", ip, duration)
		return map[string]interface{}{
			"blocked_ip": ip,
			"duration":   duration,
			"rule_id":    "fw-rule-12345",
		}, nil
	case "block_domain":
		domain := action.Params["domain"]
		log.Printf("✅ Domínio %s bloqueado no firewall", domain)
		return map[string]interface{}{
			"blocked_domain": domain,
			"rule_id":        "fw-rule-67890",
		}, nil
	}

	return nil, fmt.Errorf("ação não suportada: %s", action.Type)
}

// EDRIntegration - Integração com EDR (Endpoint Detection and Response)
type EDRIntegration struct{}

func (i *EDRIntegration) Name() string { return "edr" }
func (i *EDRIntegration) Type() string { return "endpoint" }

func (i *EDRIntegration) Execute(ctx context.Context, action PlaybookAction) (map[string]interface{}, error) {
	time.Sleep(800 * time.Millisecond)

	switch action.Type {
	case "isolate_host":
		hostname := action.Params["hostname"]
		log.Printf("✅ Host %s isolado da rede via EDR", hostname)
		return map[string]interface{}{
			"isolated_host": hostname,
			"isolation_id":  "edr-iso-54321",
		}, nil
	case "run_scan":
		hostname := action.Params["hostname"]
		log.Printf("✅ Scan iniciado no host %s", hostname)
		return map[string]interface{}{
			"scan_id": "edr-scan-99999",
			"status":  "running",
		}, nil
	}

	return nil, fmt.Errorf("ação não suportada: %s", action.Type)
}

// EmailIntegration - Integração com email
type EmailIntegration struct{}

func (i *EmailIntegration) Name() string { return "email" }
func (i *EmailIntegration) Type() string { return "notification" }

func (i *EmailIntegration) Execute(ctx context.Context, action PlaybookAction) (map[string]interface{}, error) {
	time.Sleep(300 * time.Millisecond)

	recipients := action.Params["recipients"]
	log.Printf("✅ Email enviado para %s", recipients)

	return map[string]interface{}{
		"sent_to":    recipients,
		"message_id": "email-msg-11111",
	}, nil
}

// SlackIntegration - Integração com Slack
type SlackIntegration struct{}

func (i *SlackIntegration) Name() string { return "slack" }
func (i *SlackIntegration) Type() string { return "notification" }

func (i *SlackIntegration) Execute(ctx context.Context, action PlaybookAction) (map[string]interface{}, error) {
	time.Sleep(200 * time.Millisecond)

	channel := action.Params["channel"]
	log.Printf("✅ Mensagem enviada no Slack (#%s)", channel)

	return map[string]interface{}{
		"channel":    channel,
		"message_ts": "1699123456.789",
	}, nil
}

// JiraIntegration - Integração com Jira
type JiraIntegration struct{}

func (i *JiraIntegration) Name() string { return "jira" }
func (i *JiraIntegration) Type() string { return "ticketing" }

func (i *JiraIntegration) Execute(ctx context.Context, action PlaybookAction) (map[string]interface{}, error) {
	time.Sleep(600 * time.Millisecond)

	priority := action.Params["priority"]
	log.Printf("✅ Ticket criado no Jira (Priority: %s)", priority)

	return map[string]interface{}{
		"ticket_id": "SEC-1234",
		"priority":  priority,
		"status":    "Open",
	}, nil
}

// ActiveDirectoryIntegration - Integração com Active Directory
type ActiveDirectoryIntegration struct{}

func (i *ActiveDirectoryIntegration) Name() string { return "active_directory" }
func (i *ActiveDirectoryIntegration) Type() string { return "iam" }

func (i *ActiveDirectoryIntegration) Execute(ctx context.Context, action PlaybookAction) (map[string]interface{}, error) {
	time.Sleep(700 * time.Millisecond)

	switch action.Type {
	case "revoke_access":
		username := action.Params["username"]
		log.Printf("✅ Acesso revogado para usuário %s no Active Directory", username)
		return map[string]interface{}{
			"username": username,
			"revoked":  true,
		}, nil
	case "reset_password":
		username := action.Params["username"]
		log.Printf("✅ Senha resetada para usuário %s", username)
		return map[string]interface{}{
			"username":       username,
			"password_reset": true,
			"temp_password":  "***hidden***",
		}, nil
	}

	return nil, fmt.Errorf("ação não suportada: %s", action.Type)
}

