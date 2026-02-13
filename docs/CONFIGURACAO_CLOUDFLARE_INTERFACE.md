# 🌐 CONFIGURAÇÃO CLOUDFLARE - VIA INTERFACE WEB

**Método Recomendado e Mais Seguro** ⭐

---

## 🎯 POR QUE CONFIGURAR VIA INTERFACE WEB?

### ✅ Vantagens

| Aspecto | Via .env | ⭐ Via Interface Web |
|---------|----------|---------------------|
| **Segurança** | ⚠️ Token em texto plano | ✅ Token criptografado no OpenSearch |
| **Facilidade** | ⚠️ Editar arquivo manualmente | ✅ Interface visual amigável |
| **Validação** | ❌ Sem validação imediata | ✅ Botão "Testar Conexão" integrado |
| **Restart** | ❌ Precisa reiniciar containers | ✅ Configuração dinâmica, sem restart |
| **Auditoria** | ❌ Sem rastreamento | ✅ Log de quem configurou e quando |
| **Multi-usuário** | ⚠️ Conflitos de edição | ✅ Seguro para múltiplos admins |
| **Backup** | ⚠️ Depende de .env | ✅ Backup automático no OpenSearch |

### 🔐 Como Funciona a Segurança

1. **Token inserido na interface** → Criptografado imediatamente
2. **Salvo no OpenSearch** → Índice `siem-integrations-config`
3. **Documentos protegidos** → ACL do OpenSearch
4. **Nunca exibido novamente** → Apenas "Token já configurado"
5. **Uso interno** → Backend decripta apenas para fazer requisições

---

## 📋 PRÉ-REQUISITOS

- [ ] Plataforma SIEM rodando (containers up)
- [ ] Acesso ao CloudFlare Dashboard
- [ ] Permissões de administrador no SIEM

---

## 🔑 PASSO 1: OBTER CREDENCIAIS CLOUDFLARE

### 1.1 Criar API Token

1. **Acessar:** https://dash.cloudflare.com/profile/api-tokens
2. **Clicar:** Botão azul "Create Token"
3. **Opção A - Template "Read Logs":**
   - Mais rápido
   - Permissões pré-configuradas
   - Recomendado para maioria dos casos
   
4. **Opção B - Custom Token:**
   - Clicar: "Create Custom Token"
   - **Permissions:**
     - Zone → Logs → Read ✅
     - Zone → Analytics → Read ✅
     - Zone → Firewall Services → Read ✅
   
5. **Zone Resources:**
   - **All zones** (monitorar todos os domínios) OU
   - **Specific zone** (selecionar domínios específicos)

6. **IP Address Filtering:** (Opcional)
   - Deixe vazio para permitir qualquer IP
   - Ou restrinja ao IP do servidor SIEM

7. **TTL:** (Validade)
   - Recomendado: Sem expiração
   - Ou defina período específico

8. **Clicar:** "Continue to summary" → "Create Token"

9. **⚠️ IMPORTANTE:** Copie o token **AGORA**
   - Aparece apenas UMA vez
   - Não será exibido novamente
   - Formato: 40 caracteres alfanuméricos

**Exemplo de token:**
```
k9hn3rK8xT5mP2wL6qY9vF4cB7nM1eR3sJ8dG5hN2pQ6
```

---

### 1.2 Obter Account ID

1. **Acessar:** https://dash.cloudflare.com/
2. **Selecionar:** Qualquer zona/domínio
3. **Localizar:** Barra lateral direita
4. **Procurar:** Seção "API"
5. **Copiar:** "Account ID"

**Exemplo de Account ID:**
```
4d4d97e7bb08de1e0eb86a324f794e00
```

---

### 1.3 (Opcional) Listar Zone IDs

Se quiser monitorar apenas zonas específicas:

```bash
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer SEU_TOKEN_AQUI" \
  -H "Content-Type: application/json" | jq -r '.result[] | "\(.id) - \(.name)"'
```

**Saída esperada:**
```
abc123def456... - seudominio.com
ghi789jkl012... - outrodominio.com.br
```

---

## ⚙️ PASSO 2: PREPARAR AMBIENTE

### 2.1 Configurar .env (Deixar Vazio)

Editar: `sec-app-nazarius-siem-backend/.env`

```bash
# ============================================================================
# CLOUDFLARE WAF INTEGRATION
# ============================================================================
# ⭐ Configurar via Interface Web (Método Recomendado)
# Deixar vazio - será configurado pela UI e salvo no OpenSearch
CLOUDFLARE_API_TOKEN=
CLOUDFLARE_ACCOUNT_ID=
CLOUDFLARE_ZONE_IDS=
CLOUDFLARE_ENABLED=false  # Ativado automaticamente pela interface
CLOUDFLARE_SYNC_INTERVAL_MINUTES=5
```

### 2.2 Reiniciar Containers (Apenas Uma Vez)

```bash
cd sec-app-nazarius-siem-backend
docker-compose restart
```

Aguardar ~30 segundos para inicialização completa.

---

## 🌐 PASSO 3: CONFIGURAR VIA INTERFACE WEB

### 3.1 Acessar Interface

1. **URL:** http://localhost:3000 (ou seu domínio de produção)
2. **Login:** Usar credenciais de administrador
3. **Menu:** Integrações → CloudFlare

### 3.2 Abrir Formulário de Configuração

- **Localizar:** Botão laranja "CONFIGURAR" (canto superior direito)
- **Clicar:** Abre modal/dialog de configuração

### 3.3 Preencher Credenciais

**Campo: API Token**
- **Label:** "API Token"
- **Tipo:** Password (oculto)
- **Colar:** Token obtido no Passo 1.1
- **Validar:** Sem espaços no início/fim
- **Dica:** Se já configurado antes, aparece: "Token já configurado (deixe em branco para manter)"

**Campo: Account ID (opcional mas recomendado)**
- **Label:** "Account ID (opcional)"
- **Tipo:** Text
- **Colar:** Account ID obtido no Passo 1.2
- **Exemplo:** `4d4d97e7bb08de1e0eb86a324f794e00`

**Campo: Intervalo de Sincronização**
- **Label:** "Intervalo de Sincronização (minutos)"
- **Valor padrão:** 5 minutos
- **Range:** 1-60 minutos
- **Recomendado:** Manter 5 minutos

### 3.4 Testar Conexão

1. **Clicar:** Botão "TESTAR CONEXÃO" (ícone de link 🔗)
2. **Aguardar:** 2-5 segundos
3. **Observar resposta:**

**✅ Sucesso:**
```
Connection successful! Found 3 zones
```
- Card verde aparece
- Lista de zonas disponíveis carrega

**❌ Erro - "Invalid request headers":**
- Token com espaços (copiar novamente)
- Token incompleto
- Copiar e colar novamente com cuidado

**❌ Erro - "Invalid API Token":**
- Token expirado
- Token sem permissões corretas
- Criar novo token com permissões adequadas

**❌ Erro - "No zones found":**
- Account ID incorreto (verificar no dashboard)
- Token sem acesso às zonas

**❌ Sem resposta:**
- Backend não está rodando
- Verificar: `docker logs siem-backend`

### 3.5 Selecionar Zonas (Opcional)

**Se teste bem-sucedido:**
- Aparecerão chips/badges com os nomes das zonas
- Exemplos: `seudominio.com`, `outrosite.com.br`

**Interação:**
- **Clicar em um chip:** Seleciona a zona (cor primária)
- **Clicar novamente:** Deseleciona (cor padrão)
- **Deixar todos desmarcados:** Monitora TODAS as zonas (recomendado)
- **Selecionar específicas:** Monitora apenas as selecionadas

### 3.6 Ativar Coleta Automática

- **Localizar:** Toggle/Switch "Habilitar coleta automática de eventos"
- **Ativar:** Deslizar para a direita (cor primária)
- **Efeito:** Sistema iniciará coleta a cada 5 minutos

### 3.7 Salvar Configuração

1. **Clicar:** Botão laranja "SALVAR"
2. **Aguardar:** Confirmação de salvamento
3. **Verificar:** Modal fecha automaticamente
4. **Dashboard atualiza:** Cards mostram status "Configurado"

---

## ✅ PASSO 4: VALIDAR CONFIGURAÇÃO

### 4.1 Verificar Dashboard Principal

**Após salvar, você deve ver:**

```
┌─────────────────────────────────────────┐
│ Status: ✅ Configurado                  │
│ Coleta: 🔄 Ativa                        │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ Eventos (24h): 0                        │
│ (aguardar primeira sincronização)       │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ Última Sincronização:                   │
│ 2025-01-06 20:53:32                     │
└─────────────────────────────────────────┘
```

### 4.2 Verificar Logs do Backend

```bash
docker logs siem-backend | grep -i cloudflare
```

**Esperado:**
```
✅ Cloudflare WAF Collector initialized
🔄 Cloudflare WAF Collector started (sync every 5 minutes)
[Cloudflare] Collected 0 WAF events  # Normal na primeira vez
```

### 4.3 Aguardar Primeira Sincronização

- **Tempo:** 5 minutos (intervalo configurado)
- **Após 5 minutos:** Dashboard atualiza automaticamente
- **Eventos coletados:** Aparecerão no contador

### 4.4 Testar Sincronização Manual

1. **Clicar:** Botão "SINCRONIZAR AGORA" (▶️ play)
2. **Aguardar:** 2-3 segundos
3. **Verificar:** "Última Sincronização" atualiza
4. **Logs:**
   ```bash
   docker logs -f siem-backend | grep Cloudflare
   ```
   Deve mostrar: `[Cloudflare] Collected X WAF events`

---

## 📊 VERIFICAR DADOS COLETADOS

### Após 5-10 minutos de configuração:

**Dashboard - Aba Principal:**
- Gráfico de pizza: Eventos por Ação
- Gráfico de barras: Eventos por Severidade
- Tabela: Top 10 IPs Atacantes
- Tabela: Top 10 Países de Origem

**Dashboard - Aba Eventos:**
- Tabela com eventos WAF em tempo real
- Filtros: Severidade, Ação, País
- Ações: Visualizar detalhes do evento (👁️)

**Dashboard - Aba Análise:**
- Gráfico: Top 10 Regras WAF Acionadas

### Se Eventos = 0 (Normal)

**Motivos possíveis:**
1. **Sem tráfego WAF nas últimas 24h** (mais comum)
2. **Sem regras WAF ativas no CloudFlare**
3. **Zonas sem proteção WAF habilitada**

**Como verificar:**
1. Acessar: https://dash.cloudflare.com
2. Menu: **Security** → **Events**
3. Verificar se há eventos lá
4. Se houver eventos no CloudFlare mas não no SIEM:
   - Aguardar próxima sincronização (5 min)
   - Verificar logs de erro
   - Testar conexão novamente

---

## 🔧 TROUBLESHOOTING

### Problema: "Invalid request headers"

**Causa:** Token com formatação incorreta

**Solução:**
1. Validar token via curl:
   ```bash
   curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
     -H "Authorization: Bearer SEU_TOKEN" \
     -H "Content-Type: application/json"
   ```
2. Se `"success": false`, criar novo token
3. Copiar token com cuidado (sem espaços)
4. Colar novamente na interface

---

### Problema: Token não salva (campo vazio após SALVAR)

**Status:** ✅ Normal e esperado!

**Explicação:**
- Por segurança, o token é armazenado criptografado
- Nunca é exibido novamente após salvar
- Campo mostra: "Token já configurado (deixe em branco para manter)"
- Isso protege o token de visualização não autorizada

---

### Problema: Botão "TESTAR CONEXÃO" não responde

**Soluções:**
1. Verificar se backend está rodando:
   ```bash
   docker-compose ps
   ```
2. Verificar logs:
   ```bash
   docker logs siem-backend | tail -50
   ```
3. Verificar OpenSearch:
   ```bash
   curl http://localhost:9200/_cluster/health
   ```

---

### Problema: Configuração não persiste após restart

**Causa:** OpenSearch não está salvando

**Solução:**
1. Verificar se OpenSearch está acessível
2. Verificar se índice existe:
   ```bash
   curl http://localhost:9200/siem-integrations-config/_search
   ```
3. Recriar configuração via interface

---

## 🔄 ATUALIZAR CONFIGURAÇÃO EXISTENTE

### Para Alterar Token ou Account ID:

1. **Acessar:** Integrações → CloudFlare
2. **Clicar:** Botão "CONFIGURAR"
3. **Campos:**
   - API Token: Deixar vazio = manter atual OU colar novo
   - Account ID: Atualizar se necessário
4. **Testar:** Clicar "TESTAR CONEXÃO"
5. **Salvar:** Clicar "SALVAR"

---

## 📝 BOAS PRÁTICAS

### ✅ Fazer:
- ✅ Configurar via interface web (método seguro)
- ✅ Usar token com permissões mínimas necessárias
- ✅ Definir validade do token (TTL)
- ✅ Monitorar logs periodicamente
- ✅ Testar após cada configuração

### ❌ Evitar:
- ❌ Colocar token no arquivo `.env`
- ❌ Commitar arquivos com tokens
- ❌ Compartilhar token via email/chat
- ❌ Usar token com permissões excessivas
- ❌ Ignorar erros de validação

---

## 🎯 CHECKLIST FINAL

- [ ] Token CloudFlare criado com permissões corretas
- [ ] Account ID obtido
- [ ] Arquivo `.env` deixado vazio (campos CloudFlare)
- [ ] Containers reiniciados
- [ ] Configurado via interface web
- [ ] Teste de conexão bem-sucedido
- [ ] Coleta automática ativada
- [ ] Configuração salva
- [ ] Logs mostrando inicialização OK
- [ ] Dashboard mostrando status "Configurado"
- [ ] Aguardado 5 minutos para primeira sincronização
- [ ] Eventos aparecendo (ou 0 se sem tráfego WAF)

---

## 📞 SUPORTE

Se problemas persistirem após seguir este guia:

1. **Consultar:** `GUIA_VALIDACAO_CLOUDFLARE.md` (10 testes detalhados)
2. **Consultar:** `ANALISE_CRITERIOSA_PRODUCAO.md` (análise completa)
3. **Coletar logs:**
   ```bash
   docker logs siem-backend > backend-logs.txt
   ```
4. **Verificar OpenSearch:**
   ```bash
   curl http://localhost:9200/siem-integrations-config/_search?pretty
   ```

---

**Documento criado em:** 06/01/2025  
**Versão:** 1.0  
**Método:** Interface Web (Recomendado) ⭐

