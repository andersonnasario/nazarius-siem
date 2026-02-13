# 🧪 Scripts de Teste e Diagnóstico - Cloudflare WAF Integration

Este documento descreve como usar os scripts de teste para validar a integração Cloudflare em **produção na AWS**.

---

## 📋 **Scripts Disponíveis**

### **1. test-cloudflare-diagnostico.sh** (PRINCIPAL)
**Propósito**: Diagnóstico completo da integração

**O que faz**:
- ✅ Valida token Cloudflare diretamente na API
- ✅ Lista zonas disponíveis
- ✅ Verifica se há eventos WAF no Cloudflare (últimas 24h)
- ✅ Verifica status da integração no SIEM
- ✅ Força sincronização manual
- ✅ Verifica se eventos estão chegando no SIEM
- ✅ Mostra estatísticas

**Como usar**:
```bash
./test-cloudflare-diagnostico.sh
```

**Quando usar**: **SEMPRE** - Este é o primeiro teste a executar!

---

### **2. gerar-evento-teste-cloudflare.sh**
**Propósito**: Gerar eventos de teste para validar que a integração funciona

**O que faz**:
- ✅ Cria uma regra WAF temporária
- ✅ Gera 10 requisições que serão bloqueadas
- ✅ Verifica se eventos aparecem no Cloudflare
- ✅ Remove a regra temporária automaticamente

**Como usar**:
```bash
./gerar-evento-teste-cloudflare.sh
```

**Quando usar**: 
- Quando não há eventos naturais no Cloudflare
- Para validar que eventos chegam no SIEM
- **ATENÇÃO**: Use apenas em zona de TESTE/DESENVOLVIMENTO

---

### **3. verificar-logs-cloudflare.sh** (AVANÇADO)
**Propósito**: Ver logs do backend na AWS CloudWatch

**O que faz**:
- ✅ Busca logs relacionados ao Cloudflare
- ✅ Identifica erros
- ✅ Mostra logs de inicialização
- ✅ Fornece comandos úteis para debugging

**Como usar**:
```bash
# Pré-requisito: AWS CLI configurado
aws configure

# Executar
./verificar-logs-cloudflare.sh
```

**Quando usar**:
- Para debugging avançado
- Quando eventos não estão chegando
- Para ver mensagens de erro do backend

---

## 🚀 **PASSO A PASSO COMPLETO DE DIAGNÓSTICO**

### **Cenário 1: Primeira Configuração**

```bash
# 1. Diagnóstico inicial
./test-cloudflare-diagnostico.sh

# 2. Se não houver eventos no Cloudflare, gerar teste
./gerar-evento-teste-cloudflare.sh

# 3. Aguardar 5 minutos

# 4. Executar diagnóstico novamente
./test-cloudflare-diagnostico.sh
```

---

### **Cenário 2: Configurado mas Sem Eventos**

```bash
# 1. Verificar configuração
./test-cloudflare-diagnostico.sh

# Analisar resultado:
# ✅ enabled: true → Coleta está ativa
# ❌ enabled: false → Ativar na interface web

# 2. Se enabled=true mas sem eventos
# Verificar logs do backend
./verificar-logs-cloudflare.sh

# 3. Gerar evento de teste
./gerar-evento-teste-cloudflare.sh

# 4. Verificar novamente
./test-cloudflare-diagnostico.sh
```

---

### **Cenário 3: Debugging Avançado**

```bash
# 1. Diagnóstico completo
./test-cloudflare-diagnostico.sh > diagnostico-$(date +%Y%m%d-%H%M%S).log

# 2. Ver logs em tempo real
aws logs tail "/ecs/nazarius-siem-backend" --follow --filter-pattern cloudflare

# 3. Buscar erros específicos
aws logs filter-log-events \
  --log-group-name "/ecs/nazarius-siem-backend" \
  --filter-pattern "ERROR cloudflare" \
  --start-time $(($(date +%s) - 3600))000
```

---

## 📊 **Interpretando os Resultados**

### **✅ Tudo Funcionando**

```
[TESTE 1] ✅ Token Cloudflare VÁLIDO
[TESTE 2] ✅ Encontradas 4 zona(s)
[TESTE 3] ✅ Encontrados 15 evento(s) WAF nas últimas 24h
[TESTE 4] ✅ Coletor ATIVO e FUNCIONANDO
          enabled: true
          running: true
[TESTE 6] ✅ Encontrados 15 evento(s) no SIEM

🎉 TUDO FUNCIONANDO PERFEITAMENTE!
```

**Ação**: Nenhuma! Está tudo OK ✅

---

### **⚠️ Sem Eventos no Cloudflare**

```
[TESTE 1] ✅ Token Cloudflare VÁLIDO
[TESTE 2] ✅ Encontradas 4 zona(s)
[TESTE 3] ⚠️  Nenhum evento WAF encontrado nas últimas 24h
[TESTE 4] ✅ Coletor ATIVO e FUNCIONANDO
[TESTE 6] ⚠️  Nenhum evento no SIEM ainda

Isso é NORMAL se:
- Seus sites não estão sob ataque
- WAF está em modo 'Log Only'
```

**Ação**: 
1. ✅ Aguardar tráfego natural
2. ✅ Ou executar `./gerar-evento-teste-cloudflare.sh`

---

### **❌ Coletor Não Está Ativo**

```
[TESTE 1] ✅ Token Cloudflare VÁLIDO
[TESTE 2] ✅ Encontradas 4 zona(s)
[TESTE 4] ❌ Coletor NÃO ESTÁ ATIVO
          enabled: false
          running: false

AÇÃO: Ativar o switch 'Habilitar coleta' na interface web
```

**Ação**:
1. Acesse: https://nazarius-siem.secops.superlogica.com/cloudflare
2. Clique em **"CONFIGURAR"**
3. **ATIVE** o switch "Habilitar coleta automática de eventos"
4. Clique em **"SALVAR"**
5. Aguarde 5 minutos
6. Execute novamente: `./test-cloudflare-diagnostico.sh`

---

### **⚠️ Eventos no Cloudflare mas Não no SIEM**

```
[TESTE 1] ✅ Token Cloudflare VÁLIDO
[TESTE 3] ✅ Encontrados 15 evento(s) WAF nas últimas 24h
[TESTE 4] ✅ Coletor ATIVO e FUNCIONANDO
[TESTE 6] ⚠️  Nenhum evento no SIEM ainda

POSSÍVEIS CAUSAS:
1. Sincronização ainda não rodou (aguarde 5 minutos)
2. Problema na indexação no OpenSearch
3. Verificar logs do backend
```

**Ação**:
1. Aguardar próxima sincronização (a cada 5 minutos)
2. Ou clicar "SINCRONIZAR AGORA" na interface
3. Se persistir, executar: `./verificar-logs-cloudflare.sh`

---

## 🔧 **Troubleshooting Comum**

### **Problema: "Token inválido"**

```bash
# Verificar token diretamente
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer SEU_TOKEN"

# Se inválido, gerar novo token em:
# https://dash.cloudflare.com/profile/api-tokens
```

**Permissões necessárias**:
- ✅ `Zone:Zone:Read`
- ✅ `Zone:Analytics:Read`
- ✅ `Account:Account Settings:Read`

---

### **Problema: "Nenhuma zona encontrada"**

**Causas**:
- Token não tem permissões para as zonas
- Account ID incorreto
- Token de outro account Cloudflare

**Solução**:
```bash
# Verificar zonas acessíveis com o token
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer SEU_TOKEN"
```

---

### **Problema: "AWS CLI not configured"**

```bash
# Instalar AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Configurar
aws configure
# Fornecer:
# - AWS Access Key ID
# - AWS Secret Access Key
# - Default region: us-east-1
# - Default output format: json
```

---

## 📝 **Checklist de Validação Completa**

Use este checklist para validar completamente a integração:

```
1. Configuração Básica
   [ ] Token Cloudflare válido
   [ ] Account ID correto
   [ ] Zonas selecionadas
   [ ] Período de sincronização configurado (5 min)

2. Ativação do Coletor
   [ ] Switch "Habilitar coleta" ATIVADO
   [ ] Status mostra "Coleta ativa"
   [ ] enabled: true
   [ ] running: true

3. Eventos no Cloudflare
   [ ] Há eventos WAF nas últimas 24h
   [ ] OU eventos de teste gerados

4. Sincronização
   [ ] Sincronização manual executada
   [ ] Aguardado 5 minutos
   [ ] Página atualizada (F5)

5. Eventos no SIEM
   [ ] Eventos aparecem na tabela
   [ ] Estatísticas corretas
   [ ] Gráficos funcionando

6. Verificação de Logs (se problemas)
   [ ] Logs do backend verificados
   [ ] Sem erros relacionados a Cloudflare
   [ ] Mensagens de coleta aparecem
```

---

## 🎯 **Comandos Rápidos**

```bash
# Diagnóstico rápido
./test-cloudflare-diagnostico.sh

# Gerar eventos de teste
./gerar-evento-teste-cloudflare.sh

# Ver logs em tempo real
aws logs tail "/ecs/nazarius-siem-backend" --follow --filter-pattern cloudflare

# Forçar sincronização via API
curl -X POST "https://nazarius-siem.secops.superlogica.com/api/v1/cloudflare/sync" \
  -H "Authorization: Bearer dev-token"

# Verificar status via API
curl "https://nazarius-siem.secops.superlogica.com/api/v1/cloudflare/status" \
  -H "Authorization: Bearer dev-token" | jq

# Ver eventos via API
curl "https://nazarius-siem.secops.superlogica.com/api/v1/cloudflare/events" \
  -H "Authorization: Bearer dev-token" | jq '.[:3]'
```

---

## 📞 **Suporte**

Se após executar todos os testes ainda houver problemas:

1. **Salvar logs completos**:
```bash
./test-cloudflare-diagnostico.sh > diagnostico-completo.log 2>&1
./verificar-logs-cloudflare.sh > logs-backend.log 2>&1
```

2. **Anexar aos logs**:
   - Screenshot da interface Cloudflare no SIEM
   - Screenshot do Cloudflare Dashboard mostrando eventos
   - Configuração atual (sem expor token)

3. **Informações úteis**:
   - Plano Cloudflare (Free/Pro/Business/Enterprise)
   - Quantas zonas configuradas
   - Há quanto tempo a integração está ativa
   - Frequência de ataques WAF (se conhecida)

---

## ✅ **Resumo**

- **Script principal**: `test-cloudflare-diagnostico.sh` 
- **Primeiro teste**: Sempre executar o diagnóstico completo
- **Sem eventos**: Normal se não há ataques recentes
- **Gerar teste**: `gerar-evento-teste-cloudflare.sh` (apenas em zona de teste)
- **Debugging**: `verificar-logs-cloudflare.sh` (requer AWS CLI)

**Dúvidas?** Execute o diagnóstico e compartilhe o resultado! 🚀

