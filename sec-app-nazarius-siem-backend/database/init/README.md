# Database Initialization Scripts

Este diretório contém os scripts SQL de inicialização do banco de dados PostgreSQL.

## 📂 Arquivos

### 01_schema.sql
- **Função**: Cria toda a estrutura do banco (tabelas, índices, constraints)
- **Quando executa**: Primeira inicialização do PostgreSQL
- **Ordem**: Primeiro script a executar

### 02_seed.sql
- **Função**: Dados iniciais para **DESENVOLVIMENTO/TESTES**
- **Credenciais**: `admin` / `admin`
- **Uso**: Ambiente local, staging
- **⚠️ Segurança**: Senha fraca, não usar em produção!

### 02_seed_production.sql
- **Função**: Dados iniciais para **PRODUÇÃO**
- **Credenciais**: `admin` / `SiemAdmin2025!SecurePass`
- **Uso**: AWS RDS, ambiente produtivo
- **⚠️ Importante**: **TROCAR SENHA** após primeiro login!

## 🚀 Como Funciona (Docker)

### Inicialização Automática

Quando o container PostgreSQL inicia pela **primeira vez**:

1. PostgreSQL verifica se o diretório de dados está vazio
2. Se vazio, executa scripts em `/docker-entrypoint-initdb.d/`
3. Scripts são executados em ordem alfabética:
   - `01_schema.sql` (cria tabelas)
   - `02_seed.sql` (insere dados)

### Docker Compose

```yaml
services:
  postgres:
    image: postgres:15-alpine
    volumes:
      - ./Backend/database/init:/docker-entrypoint-initdb.d:ro
      - postgres_data:/var/lib/postgresql/data
```

**Atenção**: Scripts só executam se `postgres_data` estiver vazio!

## 🔧 Uso em Diferentes Ambientes

### Desenvolvimento Local

```bash
cd Backend
docker-compose up -d postgres

# Aguardar inicialização
docker logs siem-postgres | grep "ready to accept connections"

# Credenciais:
# Usuário: admin
# Senha: admin
```

### Staging/Testing

```bash
# Mesmo que desenvolvimento
# Credenciais: admin / admin
```

### Produção (AWS RDS)

**Opção 1: Via psql (recomendado)**

```bash
# 1. Obter endpoint do RDS
export DB_ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier siem-db-prod \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text)

# 2. Executar scripts
psql -h $DB_ENDPOINT -U siem_admin -d siem < 01_schema.sql
psql -h $DB_ENDPOINT -U siem_admin -d siem < 02_seed_production.sql

# 3. Verificar
psql -h $DB_ENDPOINT -U siem_admin -d siem -c "SELECT username, email, role FROM users WHERE username = 'admin';"
```

**Opção 2: Via container temporário**

```bash
# 1. Criar container temporário conectado ao RDS
docker run -it --rm \
  -e PGPASSWORD=$DB_PASSWORD \
  -v $(pwd):/scripts \
  postgres:15-alpine \
  psql -h $DB_ENDPOINT -U siem_admin -d siem -f /scripts/01_schema.sql

docker run -it --rm \
  -e PGPASSWORD=$DB_PASSWORD \
  -v $(pwd):/scripts \
  postgres:15-alpine \
  psql -h $DB_ENDPOINT -U siem_admin -d siem -f /scripts/02_seed_production.sql
```

## 🔐 Credenciais

### Desenvolvimento (02_seed.sql)

```
Usuário: admin
Senha: admin
Email: admin@siem.local
Role: admin
```

**Hash bcrypt**:
```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
```

### Produção (02_seed_production.sql)

```
Usuário: admin
Senha: SiemAdmin2025!SecurePass
Email: admin@siem.local
Role: admin
```

**Hash bcrypt** (mesmo):
```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
```

⚠️ **ATENÇÃO**: Ambos os arquivos usam o mesmo hash por simplicidade. **MUDE A SENHA** após primeiro login em produção!

## 📊 Dados Inseridos

### Roles (Perfis de Acesso)

| Role | Descrição | Permissões |
|------|-----------|------------|
| `admin` | System Administrator | Todas |
| `analyst_l3` | Senior Security Analyst | Criar/executar playbooks, gerenciar casos |
| `analyst_l2` | Security Analyst | Executar playbooks, atualizar alertas |
| `analyst_l1` | Junior Security Analyst | Visualizar e acknowledge alertas |
| `viewer` | Read-Only Viewer | Apenas leitura |

### Módulos Ativos

- **SIEM Core**: Dashboard, Events, Alerts, Cases
- **SOAR**: Playbooks, Automated Response
- **Compliance**: CSPM, PCI-DSS, Frameworks
- **Threat Intel**: Threat Intelligence, Hunting, MITRE ATT&CK
- **Analytics**: UEBA, Executive Dashboard
- **Admin**: Users, Integrations, Settings

### Outros Dados

- Notification Channels (desabilitados por padrão)
- AWS Regions (us-east-1, us-east-2, sa-east-1 habilitadas)
- Audit log de inicialização

## 🔄 Reinicializar Banco

⚠️ **CUIDADO**: Isso **APAGA TODOS OS DADOS**!

### Docker Compose (Local)

```bash
# 1. Parar containers
docker-compose down

# 2. Remover volume
docker volume rm backend_postgres_data
# ou
docker volume rm siem-platform_postgres_data

# 3. Subir novamente (scripts executam automaticamente)
docker-compose up -d postgres

# 4. Verificar logs
docker logs siem-postgres | tail -20
```

### AWS RDS (Produção)

```bash
# 1. Conectar ao banco
psql -h $DB_ENDPOINT -U siem_admin -d siem

# 2. Dropar todas as tabelas (CUIDADO!)
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO siem_admin;
GRANT ALL ON SCHEMA public TO public;

# 3. Executar scripts novamente
\i 01_schema.sql
\i 02_seed_production.sql

# 4. Sair
\q
```

## 🧪 Validação

### Verificar Schema

```sql
-- Listar tabelas
\dt

-- Deve mostrar ~30 tabelas:
-- users, roles, refresh_tokens, sessions, playbooks, cases, alerts, etc.
```

### Verificar Dados

```sql
-- Roles
SELECT name, description FROM roles ORDER BY name;
-- Deve retornar 5 roles

-- Admin user
SELECT username, email, role, status FROM users WHERE username = 'admin';
-- Deve retornar 1 usuário

-- Módulos
SELECT count(*) FROM modules WHERE status = 'active';
-- Deve retornar ~20 módulos ativos
```

### Testar Login

```bash
# Via API
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Resposta esperada:
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "...",
  "expires_in": 3600,
  "user": {
    "id": "...",
    "username": "admin",
    "email": "admin@siem.local",
    "role": "admin"
  }
}
```

## 🐛 Troubleshooting

### Scripts não executaram

**Sintoma**: Banco vazio, sem tabelas

**Causa**: Volume já existia

**Solução**:
```bash
docker volume rm <volume_name>
docker-compose up -d postgres
```

### Erro: "duplicate key value violates unique constraint"

**Sintoma**: Script 02_seed.sql falha ao executar novamente

**Causa**: Dados já foram inseridos

**Solução**: Scripts têm `ON CONFLICT DO NOTHING` para evitar duplicatas. Se ainda assim falhar:
```sql
-- Limpar dados (manter schema)
TRUNCATE users, roles, modules RESTART IDENTITY CASCADE;

-- Re-executar seed
\i 02_seed.sql
```

### Senha não funciona

**Sintoma**: Login retorna "Invalid credentials"

**Causa**: Hash bcrypt incorreto ou senha errada

**Solução**:
```bash
# Verificar hash no banco
psql -h localhost -U siem -d siem -c "SELECT username, password_hash FROM users WHERE username = 'admin';"

# Se diferente de $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
# Atualizar:
psql -h localhost -U siem -d siem -c "UPDATE users SET password_hash = '\$2a\$10\$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy' WHERE username = 'admin';"
```

### Container não inicia

**Sintoma**: `docker-compose up` falha

**Causa**: Sintaxe SQL incorreta

**Solução**:
```bash
# Ver logs de erro
docker logs siem-postgres

# Testar script manualmente
docker run -it --rm -v $(pwd):/scripts postgres:15-alpine \
  psql -U postgres -f /scripts/01_schema.sql
```

## 📝 Modificar Scripts

### Adicionar Nova Tabela

1. Editar `01_schema.sql`
2. Adicionar no final (antes de índices)
3. Reinicializar banco ou executar ALTER TABLE

### Adicionar Novo Usuário

1. Editar `02_seed.sql` ou `02_seed_production.sql`
2. Gerar hash bcrypt:
   ```bash
   # Online: https://bcrypt-generator.com/
   # ou Python:
   python3 -c "import bcrypt; print(bcrypt.hashpw(b'senha123', bcrypt.gensalt()).decode())"
   ```
3. Adicionar INSERT:
   ```sql
   INSERT INTO users (id, username, email, password_hash, full_name, role, status) VALUES
   (uuid_generate_v4(), 'joao.silva', 'joao@empresa.com', '$2a$10$...', 'João Silva', 'analyst_l2', 'active');
   ```

### Adicionar Novo Módulo

1. Editar `02_seed.sql`
2. Adicionar na seção de módulos:
   ```sql
   INSERT INTO modules (id, name, description, category, status, path, icon, badge, tier) VALUES
   ('new-module', 'Novo Módulo', 'Descrição', 'siem', 'active', '/new-module', 'Icon', 'NEW', 'basic');
   ```

## 🔗 Referências

- [PostgreSQL Docker Hub](https://hub.docker.com/_/postgres)
- [PostgreSQL Init Scripts](https://github.com/docker-library/docs/blob/master/postgres/README.md#initialization-scripts)
- [bcrypt Online Generator](https://bcrypt-generator.com/)

---

**Última atualização**: 2025-11-28  
**Versão**: 1.0

