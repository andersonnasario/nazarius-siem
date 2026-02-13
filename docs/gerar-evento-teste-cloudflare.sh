#!/bin/bash

# ==============================================================================
# GERADOR DE EVENTOS DE TESTE - Cloudflare WAF
# ==============================================================================
# Este script cria uma regra temporária no Cloudflare e gera eventos de teste
# ATENÇÃO: Executar apenas em zona de TESTE ou DESENVOLVIMENTO
# ==============================================================================

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CF_API_URL="https://api.cloudflare.com/client/v4"
CF_TOKEN="c2CrroNcJiXhACKc98Q6K5fOw8S1m9SdwuTXMKy"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  GERADOR DE EVENTOS DE TESTE - CLOUDFLARE WAF                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ==============================================================================
# PASSO 1: Listar Zonas
# ==============================================================================
echo -e "${YELLOW}[1/6] Listando zonas disponíveis...${NC}"
echo ""

CF_ZONES=$(curl -s -X GET "${CF_API_URL}/zones" \
  -H "Authorization: Bearer ${CF_TOKEN}")

ZONES_INFO=$(echo "$CF_ZONES" | grep -o '"id":"[^"]*","name":"[^"]*"' | while read line; do
  ZONE_ID=$(echo "$line" | grep -o '"id":"[^"]*"' | cut -d':' -f2 | sed 's/"//g')
  ZONE_NAME=$(echo "$line" | grep -o '"name":"[^"]*"' | cut -d':' -f2 | sed 's/"//g')
  echo "$ZONE_ID|$ZONE_NAME"
done)

i=1
while IFS='|' read -r zone_id zone_name; do
  echo "   $i) $zone_name ($zone_id)"
  i=$((i+1))
done <<< "$ZONES_INFO"

echo ""
echo -e "${RED}⚠️  ATENÇÃO: Este script vai criar uma regra WAF e gerar tráfego de teste${NC}"
echo -e "${RED}    Use apenas em zona de DESENVOLVIMENTO/TESTE!${NC}"
echo ""
read -p "Digite o número da zona para teste (ou 'q' para cancelar): " ZONE_CHOICE

if [ "$ZONE_CHOICE" == "q" ]; then
  echo "Cancelado."
  exit 0
fi

# Extrair zona selecionada
SELECTED_ZONE=$(echo "$ZONES_INFO" | sed -n "${ZONE_CHOICE}p")
ZONE_ID=$(echo "$SELECTED_ZONE" | cut -d'|' -f1)
ZONE_NAME=$(echo "$SELECTED_ZONE" | cut -d'|' -f2)

if [ -z "$ZONE_ID" ]; then
  echo -e "${RED}❌ Zona inválida${NC}"
  exit 1
fi

echo ""
echo -e "${GREEN}✅ Zona selecionada: $ZONE_NAME${NC}"
echo ""

# ==============================================================================
# PASSO 2: Criar Regra WAF Temporária
# ==============================================================================
echo -e "${YELLOW}[2/6] Criando regra WAF temporária...${NC}"
echo ""

RULE_PAYLOAD=$(cat <<EOF
{
  "action": "block",
  "priority": 1,
  "description": "TESTE_SIEM - Regra temporária para validação",
  "filter": {
    "expression": "(http.user_agent contains \"SIEM_TEST_BOT\")"
  },
  "enabled": true
}
EOF
)

CREATE_RULE=$(curl -s -X POST "${CF_API_URL}/zones/${ZONE_ID}/firewall/rules" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$RULE_PAYLOAD")

RULE_ID=$(echo "$CREATE_RULE" | grep -o '"id":"[^"]*"' | head -1 | cut -d':' -f2 | sed 's/"//g')

if [ -z "$RULE_ID" ]; then
  echo -e "${RED}❌ Erro ao criar regra${NC}"
  echo "$CREATE_RULE"
  exit 1
fi

echo -e "${GREEN}✅ Regra criada: $RULE_ID${NC}"
echo ""

# ==============================================================================
# PASSO 3: Gerar Eventos de Teste
# ==============================================================================
echo -e "${YELLOW}[3/6] Gerando eventos de teste (10 requisições)...${NC}"
echo ""

for i in {1..10}; do
  echo -ne "   Requisição $i/10...\r"
  curl -s -A "SIEM_TEST_BOT" "https://${ZONE_NAME}/" -o /dev/null -w "%{http_code}\n" >> /tmp/test_results.txt 2>&1 &
  sleep 0.5
done

wait
echo ""

BLOCKED_COUNT=$(grep -c "403" /tmp/test_results.txt 2>/dev/null || echo "0")

if [ "$BLOCKED_COUNT" -gt 0 ]; then
  echo -e "${GREEN}✅ $BLOCKED_COUNT requisições bloqueadas com sucesso!${NC}"
else
  echo -e "${YELLOW}⚠️  Nenhuma requisição foi bloqueada (pode demorar alguns segundos)${NC}"
fi

rm -f /tmp/test_results.txt
echo ""

# ==============================================================================
# PASSO 4: Aguardar Propagação
# ==============================================================================
echo -e "${YELLOW}[4/6] Aguardando propagação no Cloudflare (60s)...${NC}"
echo ""

for i in {60..1}; do
  echo -ne "   $i segundos restantes...\r"
  sleep 1
done
echo ""

# ==============================================================================
# PASSO 5: Verificar Eventos no Cloudflare
# ==============================================================================
echo -e "${YELLOW}[5/6] Verificando eventos no Cloudflare...${NC}"
echo ""

END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TIME=$(date -u -d '5 minutes ago' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v-5M +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "2025-01-06T00:00:00Z")

GRAPHQL_QUERY=$(cat <<EOF
{
  "query": "query { viewer { zones(filter: {zoneTag: \"$ZONE_ID\"}) { firewallEventsAdaptive(filter: {datetime_geq: \"$START_TIME\", datetime_leq: \"$END_TIME\"}, limit: 20) { action clientIP datetime userAgent ruleId } } } }"
}
EOF
)

CF_EVENTS=$(curl -s -X POST "https://api.cloudflare.com/client/v4/graphql" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$GRAPHQL_QUERY")

EVENT_COUNT=$(echo "$CF_EVENTS" | grep -o '"SIEM_TEST_BOT"' | wc -l)

if [ "$EVENT_COUNT" -gt 0 ]; then
  echo -e "${GREEN}✅ Encontrados $EVENT_COUNT evento(s) de teste!${NC}"
else
  echo -e "${YELLOW}⚠️  Eventos ainda não apareceram no Cloudflare${NC}"
  echo -e "   (Pode levar até 2-3 minutos para aparecer)"
fi
echo ""

# ==============================================================================
# PASSO 6: Deletar Regra Temporária
# ==============================================================================
echo -e "${YELLOW}[6/6] Removendo regra temporária...${NC}"
echo ""

DELETE_RULE=$(curl -s -X DELETE "${CF_API_URL}/zones/${ZONE_ID}/firewall/rules/${RULE_ID}" \
  -H "Authorization: Bearer ${CF_TOKEN}")

DELETE_SUCCESS=$(echo "$DELETE_RULE" | grep -o '"success":true')

if [ -n "$DELETE_SUCCESS" ]; then
  echo -e "${GREEN}✅ Regra removida com sucesso${NC}"
else
  echo -e "${RED}❌ Erro ao remover regra${NC}"
  echo -e "${YELLOW}   Execute manualmente: DELETE /zones/$ZONE_ID/firewall/rules/$RULE_ID${NC}"
fi
echo ""

# ==============================================================================
# RESULTADO FINAL
# ==============================================================================
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  TESTE CONCLUÍDO                                              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$EVENT_COUNT" -gt 0 ]; then
  echo -e "${GREEN}✅ SUCESSO! Eventos de teste gerados e capturados${NC}"
  echo ""
  echo -e "${BLUE}PRÓXIMOS PASSOS:${NC}"
  echo "1. Aguarde 5 minutos para sincronização automática"
  echo "2. OU force sincronização no SIEM: Botão 'SINCRONIZAR AGORA'"
  echo "3. Acesse: https://nazarius-siem.secops.superlogica.com/cloudflare"
  echo "4. Verifique se os eventos aparecem na tabela"
  echo ""
  echo -e "${BLUE}Eventos devem mostrar:${NC}"
  echo "   - Action: block"
  echo "   - User Agent: SIEM_TEST_BOT"
  echo "   - Rule: TESTE_SIEM"
else
  echo -e "${YELLOW}⚠️  Eventos ainda não apareceram no Cloudflare${NC}"
  echo ""
  echo -e "${BLUE}AGUARDE 2-3 minutos e execute:${NC}"
  echo "   ./test-cloudflare-diagnostico.sh"
  echo ""
  echo -e "${BLUE}Ou verifique manualmente em:${NC}"
  echo "   https://dash.cloudflare.com → $ZONE_NAME → Security → Events"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

