#!/bin/bash
# Script para testar e debugar a geração do env-config.js

set -e

echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                           ║"
echo "║   🔧 TESTAR GERAÇÃO DO ENV-CONFIG.JS                                     ║"
echo "║                                                                           ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""

# Verificar se está no diretório correto
if [ ! -f "Dockerfile" ]; then
    echo "❌ Erro: Execute este script no diretório Frontend/"
    exit 1
fi

CONTAINER_NAME="siem-frontend-test"
IMAGE_NAME="siem-frontend:debug"
API_URL="${1:-http://localhost:8080/api/v1}"

echo "🔍 Configurações:"
echo "   Container: $CONTAINER_NAME"
echo "   Image: $IMAGE_NAME"
echo "   API URL: $API_URL"
echo ""

# Remover container antigo se existir
if docker ps -a | grep -q $CONTAINER_NAME; then
    echo "🗑️  Removendo container antigo..."
    docker rm -f $CONTAINER_NAME >/dev/null 2>&1 || true
fi

# Build da imagem
echo ""
echo "🔨 Fazendo build da imagem..."
docker build -t $IMAGE_NAME . --no-cache

if [ $? -ne 0 ]; then
    echo "❌ Erro no build!"
    exit 1
fi

echo "✅ Build concluído"
echo ""

# Rodar container
echo "🚀 Iniciando container..."
docker run -d \
  --name $CONTAINER_NAME \
  -p 8090:80 \
  -e REACT_APP_API_URL="$API_URL" \
  $IMAGE_NAME

if [ $? -ne 0 ]; then
    echo "❌ Erro ao iniciar container!"
    exit 1
fi

echo "✅ Container iniciado"
echo ""

# Aguardar nginx iniciar
echo "⏳ Aguardando nginx iniciar (3s)..."
sleep 3
echo ""

# Verificar logs do script env-config
echo "═══════════════════════════════════════════════════════════════════════════"
echo "📋 LOGS DO CONTAINER:"
echo "═══════════════════════════════════════════════════════════════════════════"
docker logs $CONTAINER_NAME
echo ""

# Verificar se env-config.js foi criado
echo "═══════════════════════════════════════════════════════════════════════════"
echo "📄 VERIFICANDO ENV-CONFIG.JS:"
echo "═══════════════════════════════════════════════════════════════════════════"

if docker exec $CONTAINER_NAME test -f /usr/share/nginx/html/env-config.js; then
    echo "✅ Arquivo env-config.js encontrado!"
    echo ""
    echo "Conteúdo:"
    echo "─────────"
    docker exec $CONTAINER_NAME cat /usr/share/nginx/html/env-config.js
    echo ""
else
    echo "❌ Arquivo env-config.js NÃO foi criado!"
    echo ""
    echo "🔍 Verificando estrutura de diretórios:"
    docker exec $CONTAINER_NAME ls -la /usr/share/nginx/html/ | head -20
    echo ""
fi

# Testar acesso HTTP
echo "═══════════════════════════════════════════════════════════════════════════"
echo "🌐 TESTANDO ACESSO HTTP:"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""

sleep 2

echo "1️⃣  Testando index.html..."
if curl -s http://localhost:8090/ | grep -q "SIEM Platform"; then
    echo "   ✅ index.html acessível"
else
    echo "   ❌ Erro ao acessar index.html"
fi

echo ""
echo "2️⃣  Testando env-config.js..."
if curl -s http://localhost:8090/env-config.js | grep -q "window.__ENV__"; then
    echo "   ✅ env-config.js acessível via HTTP"
    echo ""
    echo "   Conteúdo retornado:"
    curl -s http://localhost:8090/env-config.js | sed 's/^/   /'
else
    echo "   ❌ env-config.js não acessível via HTTP"
    
    echo ""
    echo "   Response completo:"
    curl -v http://localhost:8090/env-config.js 2>&1 | sed 's/^/   /'
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo "🧪 VERIFICAÇÕES ADICIONAIS:"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""

echo "📌 Scripts no container:"
docker exec $CONTAINER_NAME ls -la /usr/local/bin/ | grep env-config || echo "   ⚠️  env-config.sh não encontrado em /usr/local/bin/"
echo ""

echo "📌 Entrypoint:"
docker exec $CONTAINER_NAME cat /docker-entrypoint.sh
echo ""

echo "📌 Variáveis de ambiente no container:"
docker exec $CONTAINER_NAME env | grep REACT_APP || echo "   ⚠️  REACT_APP_API_URL não definida"
echo ""

echo "═══════════════════════════════════════════════════════════════════════════"
echo "✅ TESTE CONCLUÍDO"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""
echo "🌐 Frontend disponível em: http://localhost:8090"
echo "📝 Ver logs: docker logs $CONTAINER_NAME"
echo "🔍 Inspecionar: docker exec -it $CONTAINER_NAME sh"
echo "🗑️  Parar: docker rm -f $CONTAINER_NAME"
echo ""

