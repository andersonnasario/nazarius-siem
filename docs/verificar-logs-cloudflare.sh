#!/bin/bash

# ==============================================================================
# VERIFICADOR DE LOGS - Cloudflare Integration (AWS Production)
# ==============================================================================
# Este script verifica os logs do backend na AWS CloudWatch
# para diagnosticar problemas na coleta do Cloudflare
# ==============================================================================

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  VERIFICADOR DE LOGS - CLOUDFLARE (AWS PRODUCTION)            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Verificar se AWS CLI está instalado
if ! command -v aws &> /dev/null; then
  echo -e "${RED}❌ AWS CLI não está instalado${NC}"
  echo ""
  echo -e "${YELLOW}Instale com:${NC}"
  echo "   curl \"https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip\" -o \"awscliv2.zip\""
  echo "   unzip awscliv2.zip"
  echo "   sudo ./aws/install"
  exit 1
fi

# Verificar se está configurado
if ! aws sts get-caller-identity &> /dev/null; then
  echo -e "${RED}❌ AWS CLI não está configurado${NC}"
  echo ""
  echo -e "${YELLOW}Configure com:${NC}"
  echo "   aws configure"
  exit 1
fi

echo -e "${GREEN}✅ AWS CLI configurado${NC}"
echo ""

# ==============================================================================
# Descobrir Log Group
# ==============================================================================
echo -e "${YELLOW}[1/4] Procurando Log Group do SIEM...${NC}"
echo ""

# Procurar por possíveis nomes de log group
LOG_GROUP_OPTIONS=(
  "/ecs/nazarius-siem-backend"
  "/aws/ecs/nazarius-siem-backend"
  "/ecs/siem-backend"
  "/aws/ecs/siem-backend"
  "/ecs/sec-app-nazarius-siem-backend"
)

LOG_GROUP=""
for group in "${LOG_GROUP_OPTIONS[@]}"; do
  if aws logs describe-log-groups --log-group-name-prefix "$group" 2>/dev/null | grep -q "logGroups"; then
    LOG_GROUP="$group"
    echo -e "${GREEN}✅ Encontrado: $LOG_GROUP${NC}"
    break
  fi
done

if [ -z "$LOG_GROUP" ]; then
  echo -e "${YELLOW}⚠️  Log group não encontrado automaticamente${NC}"
  echo ""
  echo "Listando todos os log groups disponíveis:"
  aws logs describe-log-groups --query 'logGroups[*].logGroupName' --output text
  echo ""
  read -p "Digite o nome do log group: " LOG_GROUP
  
  if [ -z "$LOG_GROUP" ]; then
    echo -e "${RED}❌ Log group não fornecido${NC}"
    exit 1
  fi
fi

echo ""

# ==============================================================================
# Buscar Logs Relacionados ao Cloudflare
# ==============================================================================
echo -e "${YELLOW}[2/4] Buscando logs do Cloudflare (últimos 30 minutos)...${NC}"
echo ""

START_TIME=$(($(date +%s) - 1800))000  # 30 minutos atrás em milissegundos
END_TIME=$(date +%s)000

echo "   Período: $(date -d @$((START_TIME/1000)) '+%Y-%m-%d %H:%M:%S') até $(date -d @$((END_TIME/1000)) '+%Y-%m-%d %H:%M:%S')"
echo ""

# Buscar logs com palavra-chave "cloudflare" ou "Cloudflare"
CLOUDFLARE_LOGS=$(aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --filter-pattern "cloudflare" \
  --max-items 50 \
  --query 'events[*].[timestamp,message]' \
  --output text 2>/dev/null || echo "")

if [ -n "$CLOUDFLARE_LOGS" ]; then
  echo -e "${GREEN}✅ Logs encontrados:${NC}"
  echo ""
  echo "$CLOUDFLARE_LOGS" | while read -r timestamp message; do
    # Converter timestamp de milissegundos para data legível
    readable_time=$(date -d @$((timestamp/1000)) '+%Y-%m-%d %H:%M:%S')
    echo "[$readable_time] $message"
  done
else
  echo -e "${YELLOW}⚠️  Nenhum log relacionado ao Cloudflare encontrado${NC}"
  echo ""
  echo -e "${BLUE}Possíveis motivos:${NC}"
  echo "   1. Coletor não foi iniciado (verificar se enabled=true)"
  echo "   2. Período de logs muito curto (eventos são a cada 5 minutos)"
  echo "   3. Log group incorreto"
fi

echo ""

# ==============================================================================
# Buscar Erros
# ==============================================================================
echo -e "${YELLOW}[3/4] Buscando erros relacionados ao Cloudflare...${NC}"
echo ""

ERROR_LOGS=$(aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --filter-pattern "?ERROR ?Cloudflare ?error" \
  --max-items 20 \
  --query 'events[*].[timestamp,message]' \
  --output text 2>/dev/null || echo "")

if [ -n "$ERROR_LOGS" ]; then
  echo -e "${RED}❌ Erros encontrados:${NC}"
  echo ""
  echo "$ERROR_LOGS" | while read -r timestamp message; do
    readable_time=$(date -d @$((timestamp/1000)) '+%Y-%m-%d %H:%M:%S')
    echo "[$readable_time] $message"
  done
else
  echo -e "${GREEN}✅ Nenhum erro relacionado ao Cloudflare${NC}"
fi

echo ""

# ==============================================================================
# Buscar Logs de Inicialização
# ==============================================================================
echo -e "${YELLOW}[4/4] Verificando inicialização do coletor...${NC}"
echo ""

INIT_LOGS=$(aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --filter-pattern "\"Cloudflare WAF Collector\"" \
  --max-items 10 \
  --query 'events[*].[timestamp,message]' \
  --output text 2>/dev/null || echo "")

if [ -n "$INIT_LOGS" ]; then
  echo -e "${GREEN}✅ Logs de inicialização encontrados:${NC}"
  echo ""
  echo "$INIT_LOGS" | while read -r timestamp message; do
    readable_time=$(date -d @$((timestamp/1000)) '+%Y-%m-%d %H:%M:%S')
    echo "[$readable_time] $message"
  done
else
  echo -e "${YELLOW}⚠️  Nenhum log de inicialização encontrado${NC}"
  echo ""
  echo -e "${BLUE}Isso pode significar:${NC}"
  echo "   1. Coletor ainda não foi inicializado"
  echo "   2. Backend foi reiniciado recentemente (logs mais antigos)"
fi

echo ""

# ==============================================================================
# RESUMO
# ==============================================================================
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  RESUMO                                                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ -n "$CLOUDFLARE_LOGS" ]; then
  echo -e "${GREEN}✅ Coletor está rodando (logs encontrados)${NC}"
  
  if [ -n "$ERROR_LOGS" ]; then
    echo -e "${RED}⚠️  Há erros na coleta (ver acima)${NC}"
  else
    echo -e "${GREEN}✅ Sem erros detectados${NC}"
  fi
else
  echo -e "${YELLOW}⚠️  Coletor pode não estar ativo${NC}"
  echo ""
  echo -e "${BLUE}AÇÕES RECOMENDADAS:${NC}"
  echo "1. Verificar se coleta está habilitada:"
  echo "   https://nazarius-siem.secops.superlogica.com/cloudflare"
  echo ""
  echo "2. Ativar o switch 'Habilitar coleta automática'"
  echo ""
  echo "3. Executar diagnóstico completo:"
  echo "   ./test-cloudflare-diagnostico.sh"
fi

echo ""

# ==============================================================================
# COMANDOS ÚTEIS
# ==============================================================================
echo -e "${BLUE}COMANDOS ÚTEIS PARA DEBUGGING:${NC}"
echo ""
echo "# Ver últimos logs em tempo real:"
echo "aws logs tail \"$LOG_GROUP\" --follow --filter-pattern cloudflare"
echo ""
echo "# Ver todos os erros recentes:"
echo "aws logs filter-log-events --log-group-name \"$LOG_GROUP\" --filter-pattern ERROR --start-time \$(($(date +%s) - 3600))000"
echo ""
echo "# Ver log streams disponíveis:"
echo "aws logs describe-log-streams --log-group-name \"$LOG_GROUP\" --order-by LastEventTime --descending --max-items 5"
echo ""

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

