# 🔧 GUIA DE VALIDAÇÃO - INTEGRAÇÃO CLOUDFLARE

**Objetivo:** Testar e validar a conectividade com CloudFlare após aplicar as correções

---

## 📋 PRÉ-REQUISITOS

Antes de iniciar os testes:

- [ ] Correções aplicadas em `env.example`
- [ ] Correções aplicadas em `docker-compose.yml`
- [ ] Script `clean-for-production.sh` executado com sucesso
- [ ] Containers reiniciados: `docker-compose restart`

---

## 🔐 OBTER CREDENCIAIS CLOUDFLARE

### Passo 1: Criar API Token

1. Acesse: https://dash.cloudflare.com/profile/api-tokens
2. Clique em **"Create Token"**
3. Use o template **"Read logs"** ou crie customizado com permissões:
   - `Zone:Logs:Read`
   - `Zone:Analytics:Read`
   - `Zone:Firewall Services:Read`
4. Clique em **"Continue to summary"** → **"Create Token"**
5. **COPIE O TOKEN** (será exibido apenas uma vez!)

### Passo 2: Obter Account ID

1. Acesse: https://dash.cloudflare.com/
2. Selecione qualquer zona/domínio
3. Na barra lateral direita, procure por **"Account ID"**
4. Clique para copiar

### Passo 3: Obter Zone IDs (Opcional)

```bash
# Substituir YOUR_API_TOKEN pelo token criado
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" | jq '.result[] | {id, name}'
```

Resposta esperada:
```json
{
  "id": "abc123...",
  "name": "seudominio.com"
}
```

---

## ⚙️ CONFIGURAR CLOUDFLARE

### ⭐ Método 1: Via Interface Web (RECOMENDADO)

**Vantagens:**
- ✅ Mais seguro (token criptografado no OpenSearch)
- ✅ Sem restart de containers
- ✅ Validação integrada
- ✅ Auditável
- ✅ Interface amigável

**Passos:**

**Deixar `.env` vazio:**
```bash
# Editar: sec-app-nazarius-siem-backend/.env
CLOUDFLARE_API_TOKEN=
CLOUDFLARE_ACCOUNT_ID=
CLOUDFLARE_ZONE_IDS=
CLOUDFLARE_ENABLED=false  # Ativado pela interface
```

**Configurar pela Interface:**
1. Acessar: http://localhost:3000 (ou seu domínio)
2. Login
3. Menu: **Integrações** → **CloudFlare**
4. Botão: **"CONFIGURAR"** (laranja)
5. Colar **API Token**
6. Colar **Account ID**
7. Botão: **"TESTAR CONEXÃO"**
8. Se OK, ativar toggle: **"Habilitar coleta automática"**
9. Botão: **"SALVAR"**

### Método 2: Via Arquivo .env (Fallback)

⚠️ Menos seguro - Token fica em texto no arquivo

Editar `sec-app-nazarius-siem-backend/.env`:

```bash
# CloudFlare WAF Integration
CLOUDFLARE_API_TOKEN=seu_token_aqui
CLOUDFLARE_ACCOUNT_ID=seu_account_id_aqui
CLOUDFLARE_ZONE_IDS=  # vazio = todas as zonas
CLOUDFLARE_ENABLED=true
CLOUDFLARE_SYNC_INTERVAL_MINUTES=5
```

### Método 3: Via Export (Temporário - apenas testes)

```bash
export CLOUDFLARE_API_TOKEN="seu_token_aqui"
export CLOUDFLARE_ACCOUNT_ID="seu_account_id_aqui"
export CLOUDFLARE_ENABLED="true"
```

---

## 🚀 INICIAR/REINICIAR CONTAINERS

```bash
cd /home/anderson.nasario/Documentos/GitHub/Siem_Prod/sec-app-nazarius-siem-backend

# Parar containers
docker-compose down

# Iniciar novamente
docker-compose up -d

# Aguardar inicialização (30 segundos)
sleep 30

# Verificar status
docker-compose ps
```

Todos os containers devem estar **Up** e **healthy**.

---

## 🧪 TESTES DE CONECTIVIDADE

### Teste 1: Verificar Logs de Inicialização

```bash
docker logs siem-backend | grep -i cloudflare
```

**Saída esperada:**
```
✅ Cloudflare WAF Collector initialized
🔄 Cloudflare WAF Collector started (sync every 5 minutes)
```

**Saída de ERRO (se token inválido):**
```
❌ Cloudflare API token not configured
```

---

### Teste 2: Validar Token via API CloudFlare

```bash
# Substituir YOUR_TOKEN
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json"
```

**Resposta OK:**
```json
{
  "success": true,
  "result": {
    "id": "...",
    "status": "active"
  }
}
```

**Resposta ERRO:**
```json
{
  "success": false,
  "errors": [{"code": 6003, "message": "Invalid request headers"}]
}
```

---

### Teste 3: ⭐ Testar via Interface Web (RECOMENDADO)

**Passos:**
1. Acessar: http://localhost:3000
2. Login
3. Menu: **Integrações** → **CloudFlare**
4. Botão: **"CONFIGURAR"**
5. Colar API Token e Account ID
6. Botão: **"TESTAR CONEXÃO"** (ícone de link)
7. Aguardar 2-5 segundos

**Resposta OK:**
```
✅ Connection successful! Found 3 zones
```

**Possíveis Erros:**

| Erro | Causa | Solução |
|------|-------|---------|
| `Invalid request headers` | Token com espaços ou incompleto | Copiar token novamente |
| `Invalid API Token` | Token sem permissões | Criar novo token com permissões corretas |
| `No zones found` | Account ID incorreto | Verificar Account ID no dashboard |
| Sem resposta | Backend não rodando | `docker logs siem-backend` |

---

### Teste 3b: Testar via API (Alternativo - Para Debug)

#### Obter JWT Token

```bash
# Login (substituir credenciais)
JWT_TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.token')

echo "JWT Token: $JWT_TOKEN"
```

#### Testar Conexão CloudFlare

```bash
curl -X POST http://localhost:8080/api/v1/cloudflare/test \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"api_token\":\"$CLOUDFLARE_API_TOKEN\"}"
```

**Resposta OK:**
```json
{
  "success": true,
  "zone_count": 3,
  "message": "Connection successful! Found 3 zones"
}
```

**Resposta ERRO:**
```json
{
  "success": false,
  "error": "Cloudflare API error: Invalid API Token"
}
```

---

### Teste 4: Verificar Status da Integração

```bash
curl http://localhost:8080/api/v1/cloudflare/status \
  -H "Authorization: Bearer $JWT_TOKEN"
```

**Resposta esperada:**
```json
{
  "configured": true,
  "enabled": true,
  "running": true,
  "last_sync": "2025-01-06T20:30:00Z",
  "events_collected": 150,
  "sync_period": 5,
  "zone_count": 3
}
```

---

### Teste 5: Listar Zonas Disponíveis

```bash
curl http://localhost:8080/api/v1/cloudflare/zones \
  -H "Authorization: Bearer $JWT_TOKEN"
```

**Resposta esperada:**
```json
{
  "zones": [
    {
      "id": "abc123...",
      "name": "seudominio.com",
      "status": "active"
    }
  ]
}
```

---

### Teste 6: Forçar Sincronização Manual

```bash
curl -X POST http://localhost:8080/api/v1/cloudflare/sync \
  -H "Authorization: Bearer $JWT_TOKEN"
```

**Resposta esperada:**
```json
{
  "success": true,
  "message": "Sync initiated"
}
```

#### Monitorar Logs Durante Sincronização

```bash
docker logs -f siem-backend | grep Cloudflare
```

**Saída esperada:**
```
[Cloudflare] Collected 150 WAF events
```

---

### Teste 7: Consultar Eventos Coletados

```bash
curl http://localhost:8080/api/v1/cloudflare/events \
  -H "Authorization: Bearer $JWT_TOKEN"
```

**Resposta esperada:**
```json
{
  "events": [
    {
      "ray_id": "12345...",
      "action": "block",
      "client_ip": "1.2.3.4",
      "client_country": "BR",
      "timestamp": "2025-01-06T20:00:00Z",
      "severity": "HIGH",
      "host": "seudominio.com",
      "uri": "/admin/login"
    }
  ],
  "total": 150
}
```

Se `"events": []` e `"total": 0`, pode significar:
- Nenhum evento WAF nas últimas 24h
- Token sem permissões corretas
- Zonas sem tráfego WAF

---

### Teste 8: Verificar Estatísticas

```bash
curl http://localhost:8080/api/v1/cloudflare/stats \
  -H "Authorization: Bearer $JWT_TOKEN"
```

**Resposta esperada:**
```json
{
  "total_events": 150,
  "blocked": 45,
  "challenged": 30,
  "by_action": [
    {"key": "block", "doc_count": 45},
    {"key": "challenge", "doc_count": 30}
  ],
  "by_country": [
    {"key": "BR", "doc_count": 50},
    {"key": "US", "doc_count": 30}
  ]
}
```

---

### Teste 9: Verificar Índice OpenSearch

```bash
# Verificar se índice foi criado
curl http://localhost:9200/siem-cloudflare-waf/_count
```

**Resposta esperada:**
```json
{
  "count": 150,
  "_shards": {"total": 2, "successful": 2, "failed": 0}
}
```

---

### Teste 10: ⭐ Validação Completa via Interface Web

**Após configuração inicial:**

1. **Acesse:** http://localhost:3000
2. **Login** com credenciais
3. **Menu:** Integrações → CloudFlare

4. **Verificar Dashboard Principal:**
   - ✅ Status: **"Configurado"** (card verde)
   - ✅ Coleta: **"Ativa"** 
   - ✅ Eventos (24h): Número aparecendo
     - Se 0: Normal se não houver tráfego WAF
     - Se > 0: CloudFlare funcionando perfeitamente!
   - ✅ Bloqueados: Contagem de requisições bloqueadas
   - ✅ Desafiados: CAPTCHA/JS Challenges
   - ✅ Última Sincronização: Timestamp recente

5. **Testar Reconfigurá-lo (Opcional):**
   - Clicar em **"CONFIGURAR"**
   - Verificar: Campo "Token já configurado (deixe em branco para manter)"
   - Clicar em **"TESTAR CONEXÃO"**
   - Deve aparecer: ✅ "Connection successful! Found X zones"

6. **Testar Sincronização Manual:**
   - Clicar em **"SINCRONIZAR AGORA"** (botão com ícone play)
   - Aguardar 2-3 segundos
   - Verificar se "Última Sincronização" atualiza
   - Números podem atualizar (se houver novos eventos)

7. **Validar Abas:**
   - **Dashboard:** Gráficos carregando (pizza, barras)
   - **Eventos:** Tabela com eventos WAF (se houver)
   - **Análise:** Top 10 regras WAF acionadas

8. **Verificar Detalhes de Evento (se houver):**
   - Clicar no ícone 👁️ em qualquer evento
   - Deve abrir modal com:
     - Ray ID, IP, País, Host, URI
     - Ação tomada (block/challenge)
     - Severidade (HIGH/MEDIUM/LOW)
     - Regra WAF acionada
     - Mapeamento MITRE ATT&CK

**✅ Se todos estes pontos estiverem OK, CloudFlare está 100% funcional!**

---

## 🐛 TROUBLESHOOTING

### Problema: "Cloudflare integration not initialized"

**Causa:** Container iniciou antes das variáveis serem carregadas

**Solução:**
```bash
docker-compose restart backend
```

---

### Problema: "Invalid API Token"

**Causa:** Token incorreto ou sem permissões

**Solução:**
1. Verificar se token foi copiado corretamente (sem espaços)
2. Validar permissões do token:
   - Zone:Logs:Read ✅
   - Zone:Analytics:Read ✅
   - Zone:Firewall Services:Read ✅
3. Criar novo token se necessário

---

### Problema: "No zones found"

**Causa:** Token não tem acesso às zonas ou account ID incorreto

**Solução:**
```bash
# Listar zonas disponíveis para o token
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN"
```

Se retornar vazio, revisar permissões do token.

---

### Problema: Eventos coletados = 0

**Causa:** Pode ser normal se não houver tráfego WAF

**Verificar:**
1. Acessar CloudFlare Dashboard
2. Ir em **Security** → **Events**
3. Verificar se há eventos WAF nas últimas 24h
4. Se não houver eventos no dashboard, é normal estar vazio no SIEM

**Para gerar eventos de teste:**
1. Criar regra WAF de teste no CloudFlare
2. Fazer requisição que acione a regra
3. Aguardar 5 minutos (próxima sincronização)
4. Verificar novamente

---

### Problema: "Connection timeout"

**Causa:** Firewall bloqueando saída para CloudFlare

**Solução:**
Liberar saída para:
- `api.cloudflare.com` (443/TCP)
- IPs CloudFlare: https://www.cloudflare.com/ips/

---

## ✅ CHECKLIST DE VALIDAÇÃO

Marque conforme testa:

- [ ] Variáveis de ambiente configuradas
- [ ] Containers reiniciados
- [ ] Logs mostram inicialização do CloudFlare Collector
- [ ] Token validado via API CloudFlare
- [ ] Endpoint `/cloudflare/test` retorna sucesso
- [ ] Endpoint `/cloudflare/status` mostra `configured: true`
- [ ] Endpoint `/cloudflare/zones` lista zonas
- [ ] Sincronização manual funciona
- [ ] Eventos sendo coletados (ou zero se sem tráfego WAF)
- [ ] Índice `siem-cloudflare-waf` criado no OpenSearch
- [ ] Interface web carregando dados
- [ ] Gráficos e estatísticas funcionando

---

## 📊 MÉTRICAS DE SUCESSO

Após 24h de operação, validar:

- ✅ Eventos coletados > 0 (se houver tráfego WAF)
- ✅ Sincronizações executadas: ~288 (24h ÷ 5min)
- ✅ Nenhum erro nos logs
- ✅ Dashboard CloudFlare correspondendo ao CloudFlare real
- ✅ Alertas de WAF sendo gerados corretamente

---

## 📞 SUPORTE

Se após seguir este guia a integração não funcionar:

1. **Coletar informações:**
```bash
# Logs completos
docker logs siem-backend > backend-logs.txt

# Status dos containers
docker-compose ps > containers-status.txt

# Variáveis de ambiente (sem expor secrets!)
env | grep CLOUDFLARE | sed 's/TOKEN=.*/TOKEN=***/' > env-vars.txt
```

2. **Verificar arquivo de análise:**
   - Consultar: `ANALISE_CRITERIOSA_PRODUCAO.md`
   - Seção: "PROBLEMA 1: CLOUDFLARE - CONECTIVIDADE FALHANDO"

3. **Contato:**
   - Incluir logs, status e descrição do problema
   - Mencionar qual teste falhou

---

**Documento gerado em:** 06/01/2025  
**Versão:** 1.0

