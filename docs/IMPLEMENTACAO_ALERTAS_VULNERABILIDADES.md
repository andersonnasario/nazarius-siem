# 🎯 Implementação Completa: Alertas → Cases + Gestão de Vulnerabilidades

## 📋 **Resumo das Implementações**

Este documento descreve todas as funcionalidades implementadas para completar o fluxo de gestão de alertas, vulnerabilidades e incidentes na plataforma SIEM.

---

## ✅ **1. Funcionalidades Implementadas**

### **Backend (Go)**

#### **1.1. Criar Case a partir de Alerta**
**Arquivo**: `sec-app-nazarius-siem-backend/rest/alerts.go`

**Endpoint**: `POST /api/v1/alerts/:id/create-case`

**Funcionalidade**:
- Busca o alerta no OpenSearch
- Extrai informações relevantes (severidade, categoria, fonte)
- Cria automaticamente um Case com:
  - Título e descrição pré-preenchidos
  - Severidade mapeada do alerta
  - SLA calculado automaticamente (crítico: 2h, high: 24h, medium: 72h, low: 168h)
  - Relacionamento com o alerta original (`RelatedAlerts`)
- Atualiza o status do alerta para `escalated`
- Salva no OpenSearch e no banco de dados (se disponível)

**Request Body**:
```json
{
  "title": "Título opcional (auto-gerado se vazio)",
  "description": "Descrição opcional (auto-gerada se vazia)",
  "priority": "high"
}
```

**Response**:
```json
{
  "success": true,
  "case": {
    "id": "uuid",
    "title": "Incidente: Nome do Alerta",
    "severity": "high",
    "status": "new",
    "relatedAlerts": ["alert-id"],
    "slaDeadline": "2025-01-07T10:00:00Z",
    "slaRemaining": 7200
  },
  "message": "Case criado com sucesso a partir do alerta"
}
```

---

#### **1.2. Atualizar Status de Alerta**
**Arquivo**: `sec-app-nazarius-siem-backend/rest/alerts.go`

**Endpoint**: `PUT /api/v1/alerts/:id/status`

**Status Válidos**:
- `pending` - Pendente de análise
- `investigating` - Sob investigação
- `resolved` - Resolvido
- `false_positive` - Falso positivo
- `acknowledged` - Reconhecido
- `escalated` - Escalado para Case

**Request Body**:
```json
{
  "status": "acknowledged",
  "reason": "Motivo opcional",
  "comment": "Comentário opcional"
}
```

---

#### **1.3. Atualizar Status de Vulnerabilidade**
**Arquivo**: `sec-app-nazarius-siem-backend/rest/vulnerability_status.go` (novo)

**Endpoint**: `PUT /api/v1/vulnerabilities/:id/status`

**Status Válidos**:
- `ACTIVE` - Ativa, aguardando remediação
- `ACKNOWLEDGED` - Reconhecida pela equipe
- `IN_REMEDIATION` - Em processo de correção
- `RISK_ACCEPTED` - Risco aceito (não será corrigido)
- `FALSE_POSITIVE` - Falso positivo
- `RESOLVED` - Resolvida

**Request Body**:
```json
{
  "status": "ACKNOWLEDGED",
  "reason": "Vulnerabilidade reconhecida, ticket JIRA-123 criado",
  "comment": "Correção planejada para próximo sprint"
}
```

**Funcionalidade**:
- Atualiza status no OpenSearch
- Adiciona timestamps específicos (`acknowledged_at`, `remediation_started_at`, etc.)
- Armazena motivo e comentário
- Rastreia quem fez a atualização

---

### **Frontend (React)**

#### **1.4. Interface de Criação de Case**
**Arquivo**: `sec-app-nazarius-siem-frontend/src/pages/Alerts.js`

**Já Implementado**:
- Dialog modal para criar Case a partir de alerta
- Campos pré-preenchidos com dados do alerta
- Botão "Criar Incidente" disponível em cada alerta
- Feedback visual ao usuário após criação

**Localização**: 
- O botão está nas ações de cada linha da tabela de alertas
- Dialog aparece com título, descrição e prioridade pré-preenchidos

---

#### **1.5. Atualização da API Service**
**Arquivo**: `sec-app-nazarius-siem-frontend/src/services/api.js`

**Novos Métodos Adicionados**:

```javascript
// Alertas
alertsAPI.createFromAlert(alertId, data) // Rota corrigida
alertsAPI.updateStatus(alertId, status, reason, comment)

// Vulnerabilidades
vulnerabilityAPI.updateStatus(id, status, reason, comment)
```

---

## 🔄 **2. Fluxo Completo Implementado**

### **Fluxo 1: Alerta → Incidente**

```
┌─────────────────────────────────────────────────┐
│ 1. ALERTA DETECTADO                             │
│    Fonte: GuardDuty, CloudTrail, Security Hub   │
│    Index: siem-alerts                           │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│ 2. ANALISTA VISUALIZA ALERTA                    │
│    - Vê detalhes do alerta                      │
│    - Analisa severidade e contexto              │
│    - Decide ação                                │
└────────────────┬────────────────────────────────┘
                 │
         ┌───────┴────────┬──────────────┬─────────────┐
         │                │              │             │
         ▼                ▼              ▼             ▼
    Falso Positivo    Reconhecido   Investigar    Criar Case
         │                │              │             │
         ▼                ▼              ▼             ▼
   Status:          Status:        Status:       Status:
false_positive   acknowledged  investigating   escalated
                                                     │
                                                     ▼
                            ┌────────────────────────────────┐
                            │ 3. CASE CRIADO AUTOMATICAMENTE  │
                            │    - ID gerado                  │
                            │    - SLA calculado              │
                            │    - Alerta relacionado         │
                            │    - Status: new                │
                            │    Index: siem-cases            │
                            └────────┬───────────────────────┘
                                     │
                                     ▼
                            ┌────────────────────────────────┐
                            │ 4. RESPOSTA A INCIDENTE         │
                            │    - Investigação               │
                            │    - Coleta de evidências       │
                            │    - Ações de remediação        │
                            │    - Documentação               │
                            │    - Resolução                  │
                            └─────────────────────────────────┘
```

---

### **Fluxo 2: Gestão de Vulnerabilidades**

```
┌─────────────────────────────────────────────────┐
│ 1. VULNERABILIDADE DETECTADA                    │
│    Fonte: AWS Inspector                         │
│    Index: siem-vulnerabilities                  │
│    Status inicial: ACTIVE                       │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│ 2. ANÁLISE DE RISCO                             │
│    - Severidade: CRITICAL, HIGH, MEDIUM, LOW    │
│    - CVSS Score                                 │
│    - Exploit disponível?                        │
│    - Correção disponível?                       │
└────────────────┬────────────────────────────────┘
                 │
         ┌───────┴───────┬─────────────┬────────────┐
         │               │             │            │
         ▼               ▼             ▼            ▼
    Crítica         Alta          Média         Baixa
    SLA: 24-48h    SLA: 7d      SLA: 30d     SLA: 90d
         │               │             │            │
         └───────┬───────┴─────────────┴────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│ 3. DECISÃO                                      │
└────────────────┬────────────────────────────────┘
                 │
    ┌────────────┼────────────┬─────────────┐
    │            │            │             │
    ▼            ▼            ▼             ▼
ACKNOWLEDGED  REMEDIATE  RISK_ACCEPTED  FALSE_POSITIVE
    │            │            │             │
    ▼            ▼            ▼             ▼
Reconhecer   Corrigir    Aceitar        Marcar FP
Criar         Ticket      Risco          e ignorar
Ticket                    Documentar
    │            │            │             │
    ▼            ▼            ▼             ▼
Status:      Status:       Status:       Status:
IN_REMEDIATION  RESOLVED  RISK_ACCEPTED  FALSE_POSITIVE
```

---

## 📊 **3. Status e Estados**

### **Alertas**
| Status | Descrição | Ação Requerida |
|--------|-----------|----------------|
| `pending` | Novo alerta não analisado | Analisar |
| `investigating` | Sob investigação | Continuar investigação |
| `acknowledged` | Reconhecido mas não é problema | Nenhuma |
| `false_positive` | Falso alarme | Ajustar regras |
| `resolved` | Resolvido | Nenhuma |
| `escalated` | Escalado para Case | Trabalhar no Case |

### **Vulnerabilidades**
| Status | Descrição | Próximos Passos |
|--------|-----------|----------------|
| `ACTIVE` | Aguardando ação | Analisar e decidir |
| `ACKNOWLEDGED` | Reconhecida | Criar plano de remediação |
| `IN_REMEDIATION` | Em correção | Aplicar correção |
| `RESOLVED` | Corrigida | Verificar correção |
| `RISK_ACCEPTED` | Risco aceito | Documentar decisão |
| `FALSE_POSITIVE` | Não é vulnerabilidade | Ajustar detecção |

### **Cases (Incidentes)**
| Status | Descrição | Ação Requerida |
|--------|-----------|----------------|
| `new` | Novo incidente | Atribuir analista |
| `in_progress` | Em investigação | Continuar resposta |
| `resolved` | Resolvido | Documentar lições |
| `closed` | Fechado | Arquivar |

---

## 🧪 **4. Como Testar**

### **Teste 1: Criar Case a partir de Alerta**

**Via Frontend**:
1. Acesse `/alerts`
2. Localize um alerta com severidade HIGH ou CRITICAL
3. Clique no botão "Criar Incidente" (ícone de pasta)
4. Revise título, descrição e prioridade
5. Clique em "Criar Caso"
6. Verifique a mensagem de sucesso
7. Acesse `/cases` e confirme que o caso foi criado

**Via API (curl)**:
```bash
# Criar Case a partir do alerta
curl -X POST http://localhost:8080/api/v1/alerts/alert-12345/create-case \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-token" \
  -d '{
    "title": "Investigação: Tentativa de Força Bruta",
    "description": "Múltiplas tentativas de login SSH",
    "priority": "high"
  }'
```

**Resultado Esperado**:
- Case criado com ID único
- Alerta atualizado para status `escalated`
- SLA calculado corretamente
- Relacionamento `relatedAlerts` contém o ID do alerta

---

### **Teste 2: Atualizar Status de Alerta**

**Via API (curl)**:
```bash
# Marcar como falso positivo
curl -X PUT http://localhost:8080/api/v1/alerts/alert-12345/status \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-token" \
  -d '{
    "status": "false_positive",
    "reason": "Teste interno de segurança",
    "comment": "Teste autorizado pelo time de SecOps"
  }'

# Reconhecer alerta
curl -X PUT http://localhost:8080/api/v1/alerts/alert-67890/status \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-token" \
  -d '{
    "status": "acknowledged",
    "reason": "Comportamento esperado",
    "comment": "Deploy em andamento"
  }'
```

---

### **Teste 3: Atualizar Status de Vulnerabilidade**

**Via API (curl)**:
```bash
# Reconhecer vulnerabilidade
curl -X PUT http://localhost:8080/api/v1/vulnerabilities/vuln-123/status \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-token" \
  -d '{
    "status": "ACKNOWLEDGED",
    "reason": "Ticket JIRA-456 criado",
    "comment": "Correção agendada para próximo sprint"
  }'

# Marcar como em remediação
curl -X PUT http://localhost:8080/api/v1/vulnerabilities/vuln-123/status \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-token" \
  -d '{
    "status": "IN_REMEDIATION",
    "comment": "Patch aplicado no ambiente de staging"
  }'

# Aceitar risco
curl -X PUT http://localhost:8080/api/v1/vulnerabilities/vuln-789/status \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-token" \
  -d '{
    "status": "RISK_ACCEPTED",
    "reason": "Bastion host necessita SSH exposto",
    "comment": "Controles compensatórios: MFA + IP whitelist + logging"
  }'
```

---

## 📁 **5. Arquivos Modificados/Criados**

### **Backend**
```
✅ sec-app-nazarius-siem-backend/rest/alerts.go
   - Adicionado: handleCreateCaseFromAlert()
   - Adicionado: handleUpdateAlertStatus()
   - Adicionado: getStringFromMap() helper

✅ sec-app-nazarius-siem-backend/rest/vulnerability_status.go (NOVO)
   - Adicionado: handleUpdateVulnerabilityStatus()

✅ sec-app-nazarius-siem-backend/rest/main.go
   - Adicionado: POST /alerts/:id/create-case
   - Adicionado: PUT /alerts/:id/status
   - Adicionado: PUT /vulnerabilities/:id/status
```

### **Frontend**
```
✅ sec-app-nazarius-siem-frontend/src/services/api.js
   - Modificado: alertsAPI.createFromAlert() - rota corrigida
   - Adicionado: alertsAPI.updateStatus()
   - Adicionado: vulnerabilityAPI.updateStatus()

✅ sec-app-nazarius-siem-frontend/src/pages/Alerts.js
   - JÁ EXISTIA: Dialog de criação de Case
   - JÁ EXISTIA: Botão "Criar Incidente"
   - JÁ EXISTIA: handleCreateCase()
```

---

## 🔐 **6. Segurança e Validações**

### **Backend**
- ✅ Validação de status válidos
- ✅ Sanitização de IDs
- ✅ Autenticação via Bearer token
- ✅ Logs de auditoria (updated_by, updated_at)
- ✅ Tratamento de erros (404, 500)

### **Frontend**
- ✅ Confirmação antes de criar Case
- ✅ Validação de campos obrigatórios
- ✅ Feedback visual ao usuário
- ✅ Tratamento de erros de API

---

## 📈 **7. Métricas e KPIs**

### **Alertas**
- Total de alertas por status
- Taxa de falsos positivos
- Tempo médio de triagem
- Alertas escalados para Cases

### **Vulnerabilidades**
- Distribuição por severidade
- Taxa de remediação (por prazo)
- Riscos aceitos (com justificativa)
- Tempo médio de correção

### **Cases**
- Total de casos abertos/resolvidos
- MTTR (Mean Time To Resolve)
- SLA compliance
- Casos por origem (alertas vs manual)

---

## 🎯 **8. Próximos Passos (Opcional)**

1. **Automação de Resposta**
   - Auto-criar Cases para alertas CRITICAL
   - Auto-executar playbooks básicos

2. **Dashboard de Gestão**
   - Widget mostrando alertas pendentes
   - Widget mostrando vulnerabilidades críticas
   - Widget mostrando casos próximos ao SLA

3. **Notificações**
   - Email quando Case criado
   - Slack quando vulnerabilidade crítica detectada
   - SMS para SLA breaches

4. **Integrações**
   - JIRA (criar tickets automaticamente)
   - ServiceNow (sync de casos)
   - PagerDuty (escalações)

---

## ✅ **Conclusão**

Todas as funcionalidades foram implementadas com sucesso! O sistema agora possui:

✅ Fluxo completo: **Alerta → Case**
✅ Gestão de status de **Alertas**
✅ Gestão de status de **Vulnerabilidades**
✅ **Frontend** já tinha a interface pronta
✅ **Backend** endpoints criados e testados
✅ **Documentação** completa

**Status**: 🎉 **100% CONCLUÍDO**

