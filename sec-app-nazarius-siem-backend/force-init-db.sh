#!/bin/bash
# Script para forçar execução dos scripts SQL de inicialização
# Use quando os scripts não executaram automaticamente

set -e

echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                           ║"
echo "║   🔧 FORÇAR EXECUÇÃO DOS SCRIPTS SQL DE INICIALIZAÇÃO                    ║"
echo "║                                                                           ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""

# Verificar se está no diretório correto
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Erro: Execute este script no diretório Backend/"
    exit 1
fi

# Verificar se os scripts existem
if [ ! -f "database/init/01_schema.sql" ]; then
    echo "❌ Erro: Arquivo database/init/01_schema.sql não encontrado"
    exit 1
fi

if [ ! -f "database/init/02_seed.sql" ]; then
    echo "❌ Erro: Arquivo database/init/02_seed.sql não encontrado"
    exit 1
fi

echo "🔍 Verificando status do container PostgreSQL..."
if docker ps | grep -q siem-postgres; then
    echo "✅ Container siem-postgres está rodando"
else
    echo "⚠️  Container siem-postgres não está rodando"
    echo "   Iniciando container..."
    docker-compose up -d postgres
    sleep 10
fi

echo ""
echo "📊 Verificando se as tabelas já existem..."

# Verificar se tabelas existem
TABLES=$(docker exec siem-postgres psql -U siem_user -d siem -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';")

if [ "$TABLES" -gt "5" ]; then
    echo "⚠️  ATENÇÃO: Banco já possui $TABLES tabelas!"
    echo ""
    read -p "   Deseja RECRIAR o banco? Isso APAGARÁ TODOS OS DADOS! (sim/não): " -r
    echo ""
    if [[ ! $REPLY =~ ^[Ss][Ii][Mm]$ ]]; then
        echo "❌ Operação cancelada."
        exit 0
    fi
    
    echo ""
    echo "🗑️  Removendo dados existentes..."
    docker exec siem-postgres psql -U siem_user -d siem -c "DROP SCHEMA public CASCADE;" 2>/dev/null || true
    docker exec siem-postgres psql -U siem_user -d siem -c "CREATE SCHEMA public;"
    docker exec siem-postgres psql -U siem_user -d siem -c "GRANT ALL ON SCHEMA public TO siem_user;"
    docker exec siem-postgres psql -U siem_user -d siem -c "GRANT ALL ON SCHEMA public TO public;"
    echo "✅ Schema recreado"
fi

echo ""
echo "📝 Executando scripts SQL..."
echo ""

# 1. Executar schema
echo "1️⃣  Criando estrutura do banco (01_schema.sql)..."
docker exec -i siem-postgres psql -U siem_user -d siem < database/init/01_schema.sql
if [ $? -eq 0 ]; then
    echo "   ✅ Schema criado com sucesso"
else
    echo "   ❌ Erro ao criar schema"
    exit 1
fi

# 2. Executar seed
echo ""
echo "2️⃣  Inserindo dados iniciais (02_seed.sql)..."
docker exec -i siem-postgres psql -U siem_user -d siem < database/init/02_seed.sql
if [ $? -eq 0 ]; then
    echo "   ✅ Dados inseridos com sucesso"
else
    echo "   ❌ Erro ao inserir dados"
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo "🎉 SCRIPTS EXECUTADOS COM SUCESSO!"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""

# Validação
echo "🧪 Validando instalação..."
echo ""

# Verificar roles
echo "📌 Roles criadas:"
docker exec siem-postgres psql -U siem_user -d siem -c "SELECT name, description FROM roles ORDER BY name;" -t
echo ""

# Verificar usuário admin
echo "📌 Usuário admin:"
docker exec siem-postgres psql -U siem_user -d siem -c "SELECT username, email, role, status FROM users WHERE username = 'admin';" -t
echo ""

# Verificar módulos
MODULES=$(docker exec siem-postgres psql -U siem_user -d siem -t -c "SELECT COUNT(*) FROM modules WHERE status = 'active';")
echo "📌 Módulos ativos: $MODULES"
echo ""

echo "═══════════════════════════════════════════════════════════════════════════"
echo "✅ BANCO DE DADOS INICIALIZADO COM SUCESSO!"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""
echo "🔐 Credenciais padrão:"
echo "   Usuário: admin"
echo "   Senha: admin"
echo ""
echo "🌐 Testar login:"
echo "   curl -X POST http://localhost:8080/api/v1/auth/login \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"username\":\"admin\",\"password\":\"admin\"}'"
echo ""

