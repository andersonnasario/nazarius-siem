#!/bin/bash
# Script para atualizar dependências Go

set -e

echo "🔄 Atualizando dependências Go..."

# Usar container Docker temporário para atualizar go.mod e go.sum
docker run --rm \
  -v "$(pwd)":/app \
  -w /app \
  golang:1.23-alpine \
  sh -c "export GOTOOLCHAIN=auto && go mod download && go mod tidy"

echo "✅ Dependências atualizadas com sucesso!"
echo ""
echo "Arquivos atualizados:"
ls -lh go.mod go.sum

