#!/bin/bash

###############################################################################
# Script de Limpeza para Produção - SIEM Platform
# Remove arquivos stub e valida configurações para ambiente PCI-DSS
###############################################################################

set -e  # Exit on error

echo "========================================="
echo "🧹 LIMPEZA PARA PRODUÇÃO - SIEM Platform"
echo "========================================="
echo ""

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BACKEND_DIR="sec-app-nazarius-siem-backend"
ERRORS=0

# Função para log com cores
log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
    ERRORS=$((ERRORS + 1))
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_info() {
    echo "ℹ️  $1"
}

echo "PASSO 1: Verificando estrutura de diretórios..."
echo "================================================"

if [ ! -d "$BACKEND_DIR" ]; then
    log_error "Diretório $BACKEND_DIR não encontrado!"
    echo "Execute este script a partir da raiz do projeto."
    exit 1
fi

log_success "Estrutura de diretórios OK"
echo ""

echo "PASSO 2: Removendo arquivos stub..."
echo "===================================="

# Lista de arquivos stub que NÃO devem ir para produção
STUB_FILES=(
    "$BACKEND_DIR/rest/local_vars_stub.go"
    "$BACKEND_DIR/rest/cspm_aws_stubs.go"
)

for file in "${STUB_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  Removendo: $file"
        rm -f "$file"
        log_success "Removido: $(basename $file)"
    else
        log_info "Arquivo não encontrado (já removido?): $(basename $file)"
    fi
done

echo ""

echo "PASSO 3: Verificando arquivos problemáticos..."
echo "==============================================="

# Verificar se stubs.go ainda existe (pode existir, mas avisar)
if [ -f "$BACKEND_DIR/rest/stubs.go" ]; then
    log_warning "Arquivo stubs.go encontrado - Revisar antes de deploy"
    echo "         Este arquivo contém funções não implementadas."
    echo "         Considere implementá-las ou remover os endpoints."
fi

echo ""

echo "PASSO 4: Validando variáveis de ambiente..."
echo "============================================"

ENV_FILE="$BACKEND_DIR/.env"
ENV_EXAMPLE="$BACKEND_DIR/env.example"

# Verificar se .env existe
if [ ! -f "$ENV_FILE" ]; then
    log_warning "Arquivo .env não encontrado"
    echo "         Copie o env.example: cp $ENV_EXAMPLE $ENV_FILE"
    echo "         E configure as variáveis obrigatórias."
else
    log_success "Arquivo .env encontrado"
    
    # Validar variáveis críticas
    echo ""
    echo "  Validando variáveis críticas:"
    
    # DISABLE_MOCK_DATA
    if grep -q "^DISABLE_MOCK_DATA=true" "$ENV_FILE"; then
        log_success "DISABLE_MOCK_DATA=true"
    else
        log_error "DISABLE_MOCK_DATA não está configurado como 'true'"
    fi
    
    # USE_REAL_AWS_DATA
    if grep -q "^USE_REAL_AWS_DATA=true" "$ENV_FILE"; then
        log_success "USE_REAL_AWS_DATA=true"
    else
        log_warning "USE_REAL_AWS_DATA não está configurado como 'true'"
    fi
    
    # CLOUDFLARE_API_TOKEN
    if grep -q "^CLOUDFLARE_API_TOKEN=" "$ENV_FILE" && ! grep -q "^CLOUDFLARE_API_TOKEN=$" "$ENV_FILE"; then
        log_success "CLOUDFLARE_API_TOKEN configurado"
    else
        log_warning "CLOUDFLARE_API_TOKEN não configurado"
    fi
    
    # AUTOMATED_RESPONSE_ENABLED
    if grep -q "^AUTOMATED_RESPONSE_ENABLED=false" "$ENV_FILE"; then
        log_success "AUTOMATED_RESPONSE_ENABLED=false (seguro para deploy inicial)"
    else
        log_warning "AUTOMATED_RESPONSE_ENABLED deve ser 'false' para deploy inicial PCI-DSS"
    fi
    
    # Senhas fortes
    if grep -q "change_in_production\|your-secret-key" "$ENV_FILE"; then
        log_error "Senhas/secrets padrão detectadas! Altere antes de deploy."
    else
        log_success "Senhas padrão não detectadas"
    fi
fi

echo ""

echo "PASSO 5: Verificando docker-compose.yml..."
echo "==========================================="

COMPOSE_FILE="$BACKEND_DIR/docker-compose.yml"

if [ -f "$COMPOSE_FILE" ]; then
    # Verificar se CloudFlare foi adicionado
    if grep -q "CLOUDFLARE_API_TOKEN" "$COMPOSE_FILE"; then
        log_success "CloudFlare configurado no docker-compose.yml"
    else
        log_error "CloudFlare NÃO configurado no docker-compose.yml"
        echo "         Execute as correções do arquivo ANALISE_CRITERIOSA_PRODUCAO.md"
    fi
    
    # Verificar duplicações de USE_REAL_AWS_DATA
    AWS_DATA_COUNT=$(grep -c "USE_REAL_AWS_DATA:" "$COMPOSE_FILE" || true)
    if [ "$AWS_DATA_COUNT" -gt 1 ]; then
        log_warning "USE_REAL_AWS_DATA aparece $AWS_DATA_COUNT vezes (possível duplicação)"
    fi
else
    log_error "docker-compose.yml não encontrado"
fi

echo ""

echo "PASSO 6: Gerando relatório de limpeza..."
echo "=========================================="

REPORT_FILE="PRODUCTION_CLEANUP_REPORT_$(date +%Y%m%d_%H%M%S).txt"

cat > "$REPORT_FILE" << EOF
========================================
RELATÓRIO DE LIMPEZA PARA PRODUÇÃO
========================================
Data: $(date)
Executado por: $(whoami)
Diretório: $(pwd)

ARQUIVOS REMOVIDOS:
EOF

for file in "${STUB_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "✅ $(basename $file)" >> "$REPORT_FILE"
    else
        echo "❌ $(basename $file) - NÃO removido" >> "$REPORT_FILE"
    fi
done

cat >> "$REPORT_FILE" << EOF

VALIDAÇÕES:
- DISABLE_MOCK_DATA: $(grep "^DISABLE_MOCK_DATA=" "$ENV_FILE" 2>/dev/null || echo "NÃO CONFIGURADO")
- USE_REAL_AWS_DATA: $(grep "^USE_REAL_AWS_DATA=" "$ENV_FILE" 2>/dev/null || echo "NÃO CONFIGURADO")
- CLOUDFLARE_ENABLED: $(grep "^CLOUDFLARE_ENABLED=" "$ENV_FILE" 2>/dev/null || echo "NÃO CONFIGURADO")
- AUTOMATED_RESPONSE_ENABLED: $(grep "^AUTOMATED_RESPONSE_ENABLED=" "$ENV_FILE" 2>/dev/null || echo "NÃO CONFIGURADO")

PRÓXIMOS PASSOS:
1. Configurar senhas fortes em .env
2. Configurar CLOUDFLARE_API_TOKEN
3. Testar conexão CloudFlare
4. Validar integrações AWS
5. Executar testes de integração
6. Deploy em staging primeiro
7. Validação completa antes de produção

ERROS ENCONTRADOS: $ERRORS
EOF

log_success "Relatório salvo em: $REPORT_FILE"

echo ""
echo "========================================="
echo "RESUMO DA LIMPEZA"
echo "========================================="

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}"
    echo "✅ LIMPEZA CONCLUÍDA COM SUCESSO!"
    echo ""
    echo "O código está pronto para próximos passos:"
    echo "1. Configurar variáveis de ambiente restantes"
    echo "2. Testar integrações (especialmente CloudFlare)"
    echo "3. Deploy em ambiente de staging"
    echo "4. Validação completa de funcionalidades"
    echo "5. Deploy em produção"
    echo -e "${NC}"
else
    echo -e "${RED}"
    echo "❌ LIMPEZA CONCLUÍDA COM $ERRORS ERRO(S)"
    echo ""
    echo "Revise os erros acima antes de prosseguir."
    echo "Consulte o arquivo ANALISE_CRITERIOSA_PRODUCAO.md"
    echo "para instruções detalhadas de correção."
    echo -e "${NC}"
fi

echo ""
echo "Relatório completo: $REPORT_FILE"
echo "Análise detalhada: ANALISE_CRITERIOSA_PRODUCAO.md"
echo ""

exit $ERRORS

