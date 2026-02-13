#!/bin/bash

# ==============================================================================
# SCRIPT DE DIAGNÓSTICO - Cloudflare WAF Integration
# ==============================================================================
# Este script testa todos os aspectos da integração Cloudflare
# Para uso em produção AWS (sem acesso direto ao backend)
# ==============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuração
API_URL="https://nazarius-siem.secops.superlogica.com/api/v1"
TOKEN="dev-token"  # Substitua pelo token real se necessário

# Cloudflare API
CF_API_URL="https://api.cloudflare.com/client/v4"
CF_TOKEN="c2CrroNcJiXhACKc98Q6K5fOw8S1m9SdwuTXMKy"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  DIAGNÓSTICO COMPLETO - CLOUDFLARE WAF INTEGRATION           ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo ""

# ==============================================================================
# TESTE 1: Verificar Token Cloudflare Diretamente
# ==============================================================================
echo -e "${YELLOW}[TESTE 1] Verificando Token Cloudflare diretamente...${NC}"
echo ""

CF_VERIFY=$(curl -s -X GET "${CF_API_URL}/user/tokens/verify" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json")

CF_STATUS=$(echo "$CF_VERIFY" | grep -o '"success":[^,]*' | cut -d':' -f2)

if [ "$CF_STATUS" == "true" ]; then
  echo -e "${GREEN}✅ Token Cloudflare VÁLIDO${NC}"
  echo -e "   $(echo "$CF_VERIFY" | grep -o '"name":"[^"]*"' | cut -d':' -f2)"
else
  echo -e "${RED}❌ Token Cloudflare INVÁLIDO${NC}"
  echo -e "   Erro: $(echo "$CF_VERIFY" | grep -o '"message":"[^"]*"')"
  exit 1
fi
echo ""

# ==============================================================================
# TESTE 2: Listar Zonas Disponíveis
# ==============================================================================
echo -e "${YELLOW}[TESTE 2] Listando zonas disponíveis...${NC}"
echo ""

CF_ZONES=$(curl -s -X GET "${CF_API_URL}/zones" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json")

ZONE_COUNT=$(echo "$CF_ZONES" | grep -o '"name":"[^"]*"' | wc -l)

if [ "$ZONE_COUNT" -gt 0 ]; then
  echo -e "${GREEN}✅ Encontradas $ZONE_COUNT zona(s)${NC}"
  echo "$CF_ZONES" | grep -o '"name":"[^"]*"' | cut -d':' -f2 | sed 's/"//g' | while read zone; do
    echo "   - $zone"
  done
else
  echo -e "${RED}❌ Nenhuma zona encontrada${NC}"
  exit 1
fi
echo ""

# Extrair primeira zona para teste
FIRST_ZONE_ID=$(echo "$CF_ZONES" | grep -o '"id":"[^"]*"' | head -1 | cut -d':' -f2 | sed 's/"//g')
FIRST_ZONE_NAME=$(echo "$CF_ZONES" | grep -o '"name":"[^"]*"' | head -1 | cut -d':' -f2 | sed 's/"//g')

echo -e "   ${BLUE}Usando zona para teste: $FIRST_ZONE_NAME ($FIRST_ZONE_ID)${NC}"
echo ""

# ==============================================================================
# TESTE 3: Verificar se há eventos WAF no Cloudflare (últimas 24h)
# ==============================================================================
echo -e "${YELLOW}[TESTE 3] Verificando eventos WAF no Cloudflare (últimas 24h)...${NC}"
echo ""

# Calcular timestamps (últimas 24h)
END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TIME=$(date -u -d '24 hours ago' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v-24H +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "2025-01-05T00:00:00Z")

echo "   Período: $START_TIME até $END_TIME"
echo ""

# Query GraphQL para buscar eventos
GRAPHQL_QUERY=$(cat <<EOF
{
  "query": "query { viewer { zones(filter: {zoneTag: \"$FIRST_ZONE_ID\"}) { firewallEventsAdaptive(filter: {datetime_geq: \"$START_TIME\", datetime_leq: \"$END_TIME\"}, limit: 10) { action clientIP clientCountry datetime userAgent ruleId source } } } }"
}
EOF
)

CF_EVENTS=$(curl -s -X POST "https://api.cloudflare.com/client/v4/graphql" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$GRAPHQL_QUERY")

EVENT_COUNT=$(echo "$CF_EVENTS" | grep -o '"clientIP"' | wc -l)

if [ "$EVENT_COUNT" -gt 0 ]; then
  echo -e "${GREEN}✅ Encontrados $EVENT_COUNT evento(s) WAF nas últimas 24h${NC}"
  echo ""
  echo "   Amostra de eventos:"
  echo "$CF_EVENTS" | grep -o '"action":"[^"]*"' | head -5 | cut -d':' -f2 | sed 's/"//g' | while read action; do
    echo "   - Action: $action"
  done
else
  echo -e "${YELLOW}⚠️  Nenhum evento WAF encontrado nas últimas 24h${NC}"
  echo -e "   ${YELLOW}Isso é NORMAL se:${NC}"
  echo "   - Seus sites não estão sob ataque"
  echo "   - WAF está em modo 'Log Only'"
  echo "   - Poucas regras WAF ativas"
  echo ""
  echo -e "   ${BLUE}💡 RECOMENDAÇÃO: Gerar evento de teste (próximo passo)${NC}"
fi
echo ""

# ==============================================================================
# TESTE 4: Status da Integração no SIEM
# ==============================================================================
echo -e "${YELLOW}[TESTE 4] Verificando status da integração no SIEM...${NC}"
echo ""

SIEM_STATUS=$(curl -s -X GET "${API_URL}/cloudflare/status" \
  -H "Authorization: Bearer ${TOKEN}")

CONFIGURED=$(echo "$SIEM_STATUS" | grep -o '"configured":[^,]*' | cut -d':' -f2)
ENABLED=$(echo "$SIEM_STATUS" | grep -o '"enabled":[^,]*' | cut -d':' -f2)
RUNNING=$(echo "$SIEM_STATUS" | grep -o '"running":[^,]*' | cut -d':' -f2)
EVENTS_COLLECTED=$(echo "$SIEM_STATUS" | grep -o '"events_collected":[^,]*' | cut -d':' -f2)

echo "   Configurado: $CONFIGURED"
echo "   Habilitado: $ENABLED"
echo "   Em execução: $RUNNING"
echo "   Eventos coletados: $EVENTS_COLLECTED"
echo ""

if [ "$ENABLED" == "true" ] && [ "$RUNNING" == "true" ]; then
  echo -e "${GREEN}✅ Coletor ATIVO e FUNCIONANDO${NC}"
else
  echo -e "${RED}❌ Coletor NÃO ESTÁ ATIVO${NC}"
  echo -e "   ${YELLOW}AÇÃO: Ativar o switch 'Habilitar coleta' na interface web${NC}"
  echo -e "   URL: https://nazarius-siem.secops.superlogica.com/cloudflare"
  exit 1
fi
echo ""

# ==============================================================================
# TESTE 5: Forçar Sincronização Manual
# ==============================================================================
echo -e "${YELLOW}[TESTE 5] Forçando sincronização manual...${NC}"
echo ""

SYNC_RESULT=$(curl -s -X POST "${API_URL}/cloudflare/sync" \
  -H "Authorization: Bearer ${TOKEN}")

echo "$SYNC_RESULT"
echo ""

# Aguardar processamento
echo -e "   ${BLUE}Aguardando 30 segundos para processamento...${NC}"
for i in {30..1}; do
  echo -ne "   $i segundos restantes...\r"
  sleep 1
done
echo ""

# ==============================================================================
# TESTE 6: Verificar Eventos no SIEM
# ==============================================================================
echo -e "${YELLOW}[TESTE 6] Verificando eventos no SIEM...${NC}"
echo ""

SIEM_EVENTS=$(curl -s -X GET "${API_URL}/cloudflare/events" \
  -H "Authorization: Bearer ${TOKEN}")

SIEM_EVENT_COUNT=$(echo "$SIEM_EVENTS" | grep -o '"clientIP"' | wc -l)

if [ "$SIEM_EVENT_COUNT" -gt 0 ]; then
  echo -e "${GREEN}✅ Encontrados $SIEM_EVENT_COUNT evento(s) no SIEM${NC}"
  echo ""
  echo "   Amostra:"
  echo "$SIEM_EVENTS" | head -20
else
  echo -e "${YELLOW}⚠️  Nenhum evento no SIEM ainda${NC}"
fi
echo ""

# ==============================================================================
# TESTE 7: Estatísticas
# ==============================================================================
echo -e "${YELLOW}[TESTE 7] Verificando estatísticas...${NC}"
echo ""

SIEM_STATS=$(curl -s -X GET "${API_URL}/cloudflare/stats" \
  -H "Authorization: Bearer ${TOKEN}")

echo "$SIEM_STATS"
echo ""

# ==============================================================================
# DIAGNÓSTICO FINAL
# ==============================================================================
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  RESUMO DO DIAGNÓSTICO                                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$CONFIGURED" == "true" ] && [ "$ENABLED" == "true" ] && [ "$RUNNING" == "true" ]; then
  echo -e "${GREEN}✅ INTEGRAÇÃO CONFIGURADA CORRETAMENTE${NC}"
  echo ""
  
  if [ "$EVENT_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✅ HÁ EVENTOS NO CLOUDFLARE${NC}"
    
    if [ "$SIEM_EVENT_COUNT" -gt 0 ]; then
      echo -e "${GREEN}✅ EVENTOS SENDO COLETADOS PELO SIEM${NC}"
      echo ""
      echo -e "${GREEN}🎉 TUDO FUNCIONANDO PERFEITAMENTE!${NC}"
    else
      echo -e "${YELLOW}⚠️  EVENTOS NÃO ESTÃO CHEGANDO NO SIEM${NC}"
      echo ""
      echo -e "${YELLOW}POSSÍVEIS CAUSAS:${NC}"
      echo "1. Sincronização ainda não rodou (aguarde 5 minutos)"
      echo "2. Problema na indexação no OpenSearch"
      echo "3. Verificar logs do backend"
      echo ""
      echo -e "${BLUE}AÇÃO: Aguardar próxima sincronização automática${NC}"
    fi
  else
    echo -e "${YELLOW}⚠️  SEM EVENTOS NO CLOUDFLARE (últimas 24h)${NC}"
    echo ""
    echo -e "${YELLOW}Isso é NORMAL se suas zonas não tiveram ataques.${NC}"
    echo ""
    echo -e "${BLUE}💡 RECOMENDAÇÃO: Gerar evento de teste${NC}"
    echo "   Execute: ./gerar-evento-teste-cloudflare.sh"
  fi
else
  echo -e "${RED}❌ PROBLEMAS NA CONFIGURAÇÃO${NC}"
  echo ""
  echo "AÇÕES NECESSÁRIAS:"
  echo "1. Acessar: https://nazarius-siem.secops.superlogica.com/cloudflare"
  echo "2. Clicar em CONFIGURAR"
  echo "3. ATIVAR o switch 'Habilitar coleta automática'"
  echo "4. SALVAR"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

