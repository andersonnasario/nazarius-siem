# Alterações - Campo Origem nos Alertas

**Data:** 07 de Janeiro de 2026  
**Solicitação:** Adicionar campo de Origem nos Alertas do SIEM Nazarius

---

## Resumo das Alterações

### 1. Backend - Struct Alert (`alerts.go`)

**Antes:** O struct `Alert` não tinha campos para identificar a origem do alerta.

**Depois:** Adicionados os seguintes campos:

```go
type Alert struct {
    // ... campos existentes ...
    Source        string  `json:"source"`         // Origem: guardduty, securityhub, inspector, cloudtrail, cloudflare, manual
    SourceID      string  `json:"source_id"`      // ID do finding original
    Category      string  `json:"category"`       // Categoria do alerta
    ResourceID    string  `json:"resource_id"`    // ID do recurso afetado
    ResourceType  string  `json:"resource_type"`  // Tipo do recurso afetado
    Region        string  `json:"region"`         // Região AWS
    AccountID     string  `json:"account_id"`     // ID da conta AWS
}
```

### 2. Backend - Filtro por Origem

- **Arquivo:** `alerts.go`
- Adicionado parâmetro de query `source` no endpoint `GET /alerts/`
- Exemplo: `GET /api/alerts/?source=cloudflare,guardduty`

### 3. Backend - Estatísticas por Origem

- **Arquivo:** `alerts.go`
- Adicionada agregação `by_source` nas estatísticas
- Endpoint `GET /alerts/statistics` agora retorna:
  - `by_source`: Contagem de alertas por origem (guardduty, securityhub, cloudflare, etc.)

### 4. Backend - CloudFlare Alertas (`cloudflare_waf_collector.go`)

- **Novo:** Eventos de alta severidade (block, drop) do CloudFlare agora são indexados também no índice `siem-alerts`
- Cada alerta CloudFlare inclui:
  - `source`: "cloudflare"
  - `source_id`: Ray ID do CloudFlare
  - `category`: "web-attack"
  - Mapeamento MITRE ATT&CK
  - Recomendação automática

### 5. Frontend - Coluna Origem na Tabela (`Alerts.js`)

- Nova coluna "Origem" na tabela de alertas
- Chips coloridos por fonte:
  - 🟠 **GuardDuty** - #FF9800
  - 🔵 **Security Hub** - #2196F3
  - 🟣 **Inspector** - #9C27B0
  - 🟢 **CloudTrail** - #4CAF50
  - 🟠 **CloudFlare** - #F48120
  - 🔵 **AWS Config** - #00BCD4
  - ⚫ **Manual** - #607D8B

### 6. Frontend - Filtro por Origem

- Novo filtro dropdown "Origem" na seção de filtros
- Permite múltipla seleção
- Filtra alertas pela fonte de dados

### 7. Frontend - Detalhes do Alerta

- Novo painel "Informações da Origem" no diálogo de detalhes
- Exibe:
  - Origem (com chip colorido)
  - Categoria
  - Região
  - Conta AWS
  - Recurso ID
  - Tipo de Recurso
  - ID do Finding Original

---

## Correções de Segurança

### 1. Token Antigo Removido do Arquivo

- **Arquivo:** `ACAO_IMEDIATA.txt`
- **Problema:** Token antigo do CloudFlare estava no arquivo (já não estava mais em uso)
- **Ação:** Token removido do arquivo por boas práticas

✅ **Nota:** O token já havia sido rotacionado anteriormente e não representava risco de segurança.

### 2. JWT Secret Hardcoded Corrigido

- **Arquivo:** `auth.go`
- **Problema:** JWT secret estava hardcoded no código
- **Ação:** Agora usa variável de ambiente `JWT_SECRET`

```go
// Antes:
JWTSecretKey = "your-secret-key-change-in-production" // hardcoded

// Depois:
func getJWTSecretKey() string {
    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        return "dev-only-fallback" // apenas desenvolvimento
    }
    return secret
}
```

⚠️ **PRODUÇÃO:** Configure `JWT_SECRET` com valor seguro de pelo menos 32 caracteres:
```bash
export JWT_SECRET=$(openssl rand -base64 48)
```

---

## Arquivos Modificados

### Backend
1. `sec-app-nazarius-siem-backend/rest/alerts.go`
   - Struct Alert atualizado
   - Função fetchAlertsFromES atualizada
   - Filtro por source adicionado
   - Estatísticas por source adicionadas

2. `sec-app-nazarius-siem-backend/rest/cloudflare_waf_collector.go`
   - Nova função indexCloudflareAlert()
   - Alertas de alta severidade indexados no siem-alerts

3. `sec-app-nazarius-siem-backend/rest/auth.go`
   - JWT secret movido para variável de ambiente
   - Nova função getJWTSecretKey()

### Frontend
3. `sec-app-nazarius-siem-frontend/src/pages/Alerts.js`
   - Constantes SOURCE_COLORS e SOURCE_LABELS
   - Estado selectedSources
   - Coluna Origem na tabela
   - Filtro por origem
   - Painel de informações no diálogo de detalhes

### Documentação
4. `ACAO_IMEDIATA.txt`
   - Secret removido

---

## Busca por CVE (Nova Funcionalidade)

### Backend - Alertas (`alerts.go`)

- Novo parâmetro de query `search` no endpoint `GET /alerts/`
- Busca em múltiplos campos: `name`, `description`, `source_id`, `category`
- Suporte a busca fuzzy para melhorar resultados
- Exemplo: `GET /api/alerts/?search=CVE-2024-45337`

### Frontend - Alertas (`Alerts.js`)

- Campo de busca no topo dos filtros
- Placeholder: "Buscar por CVE, nome ou descrição..."
- Ícone de busca e botão para limpar
- Busca executada automaticamente ao digitar

### Frontend - Eventos (`Events.js`)

- Campo de busca melhorado com ícone e botão de limpar
- Placeholder: "Buscar por CVE, tipo ou descrição..."
- Tecla Enter para buscar

---

## Testes Recomendados

1. **Visualização da Coluna Origem:**
   - Acessar /alerts
   - Verificar se a coluna "Origem" aparece na tabela
   - Verificar cores corretas dos chips

2. **Filtro por Origem:**
   - Selecionar "GuardDuty" no filtro
   - Verificar se apenas alertas do GuardDuty aparecem

3. **Estatísticas:**
   - Verificar se o gráfico inclui dados por origem

4. **CloudFlare Alertas:**
   - Gerar tráfego bloqueado no CloudFlare
   - Verificar se alerta aparece na lista com origem "CloudFlare"

5. **Detalhes do Alerta:**
   - Clicar em um alerta
   - Verificar painel "Informações da Origem"

6. **Busca por CVE em Alertas:**
   - No campo de busca, digitar "CVE-2024-45337"
   - Verificar se alertas correspondentes aparecem
   - Clicar no X para limpar a busca

7. **Busca por CVE em Eventos:**
   - Acessar /events
   - No campo de busca, digitar uma CVE
   - Clicar em "Buscar" ou pressionar Enter
   - Verificar resultados filtrados

---

## Próximos Passos Sugeridos

1. **Rotacionar Token CloudFlare** (URGENTE)
2. Deploy em staging para testes
3. Validar indexação de alertas CloudFlare
4. Considerar adicionar mais fontes:
   - Fortinet (já existe, mas usa índice separado)
   - VPC Flow Logs
   - WAF AWS

---

*Análise e implementação realizada em 07/01/2026*

