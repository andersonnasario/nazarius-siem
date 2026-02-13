# SIEM Platform - Backend

Backend da plataforma SIEM desenvolvido em Go (Golang) com Gin Framework.

## 🚀 Tecnologias

- **Go** 1.23
- **Gin** Web Framework
- **PostgreSQL** 15
- **Redis** 7
- **Elasticsearch** 8.11
- **AWS SDK** para integrações cloud
- **JWT** para autenticação

## 📋 Pré-requisitos

- Go 1.23 ou superior
- PostgreSQL 15+
- Redis 7+
- Elasticsearch 8.11+
- Docker (para build de produção)

## 🛠️ Instalação e Desenvolvimento

### Desenvolvimento Local

```bash
# Instalar dependências
go mod download

# Executar a aplicação
go run rest/*.go

# API estará disponível em http://localhost:8080
```

### Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto:

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=siem
DB_PASSWORD=ChangeMeInProduction123!
DB_NAME=siem

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=ChangeMeInProduction456!
REDIS_USE_TLS=false  # Set to 'true' for AWS ElastiCache

# Elasticsearch / OpenSearch
ELASTICSEARCH_HOST=http://localhost:9200
ELASTICSEARCH_INDEX=siem-*
ELASTICSEARCH_USERNAME=  # For AWS OpenSearch
ELASTICSEARCH_PASSWORD=  # For AWS OpenSearch
ELASTICSEARCH_USE_TLS=false  # Set to 'true' for AWS OpenSearch

# JWT
JWT_SECRET=ChangeMeInProductionJWTSecret789!

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost

# AWS Integration
USE_REAL_AWS_DATA=true

# Server
PORT=8080
GIN_MODE=release
```

## 🐳 Docker

### Build da Imagem

```bash
# Build da imagem Docker
docker build -t siem-backend:latest .

# Executar container
docker run -p 8080:8080 \
  -e DB_HOST=postgres \
  -e REDIS_HOST=redis \
  -e ELASTICSEARCH_URL=http://elasticsearch:9200 \
  siem-backend:latest
```

### Docker Compose

```bash
# Subir todos os serviços (backend + dependências)
docker-compose up

# Subir apenas o backend
docker-compose up backend
```

## 🏗️ Estrutura do Projeto

```
Backend/
├── rest/                    # Handlers HTTP
│   ├── main.go             # Entry point
│   ├── auth.go             # Autenticação
│   ├── alerts.go           # Alertas
│   ├── cases.go            # Casos
│   ├── playbooks.go        # Playbooks
│   ├── cspm_*.go           # Cloud Security
│   ├── aws_*.go            # Integrações AWS
│   ├── ueba.go             # User Behavior Analytics
│   └── ...
├── database/               # Camada de dados
│   ├── database.go         # Conexão DB
│   ├── auth_repository.go  # Repositório de autenticação
│   ├── cases_repository.go # Repositório de casos
│   └── playbooks_repository.go
├── database/init/          # Scripts SQL
│   ├── 01_schema.sql       # Schema inicial
│   └── 02_seed.sql         # Dados iniciais
├── Dockerfile              # Build de produção
├── docker-compose.yml      # Orquestração
├── go.mod                  # Dependências Go
└── go.sum                  # Checksums
```

## 🔌 Endpoints Principais

### Autenticação
- `POST /api/auth/login` - Login
- `POST /api/auth/register` - Registro
- `POST /api/auth/refresh` - Refresh token
- `POST /api/auth/logout` - Logout

### SIEM Core
- `GET /api/events` - Listar eventos
- `GET /api/alerts` - Listar alertas
- `GET /api/cases` - Listar casos
- `POST /api/cases` - Criar caso

### SOAR
- `GET /api/playbooks` - Listar playbooks
- `POST /api/playbooks` - Criar playbook
- `POST /api/playbooks/:id/execute` - Executar playbook

### Compliance
- `GET /api/cspm/dashboard` - Dashboard CSPM
- `GET /api/pci-dss/dashboard` - Dashboard PCI-DSS
- `GET /api/compliance/reports` - Relatórios

### AWS Integration
- `GET /api/aws/cloudtrail` - Eventos CloudTrail
- `GET /api/aws/guardduty` - Findings GuardDuty
- `GET /api/aws/connections` - Conexões AWS
- `POST /api/aws/connections` - Adicionar conexão

### Threat Intelligence
- `GET /api/threat-intelligence` - Indicadores
- `GET /api/threat-hunting` - Hunting queries
- `GET /api/ueba` - User behavior analytics

### Health & Metrics
- `GET /health` - Health check
- `GET /api/metrics` - Métricas da aplicação

## 🗄️ Banco de Dados

### Migrations

Os scripts SQL em `database/init/` são executados automaticamente na primeira inicialização do PostgreSQL via Docker.

Para ambientes AWS RDS:

```bash
# Aplicar schema manualmente
psql -h <rds-endpoint> -U siem -d siem -f database/init/01_schema.sql
psql -h <rds-endpoint> -U siem -d siem -f database/init/02_seed.sql
```

### Tabelas Principais

- `users` - Usuários do sistema
- `refresh_tokens` - Tokens de refresh
- `alerts` - Alertas de segurança
- `cases` - Casos de investigação
- `playbooks` - Playbooks de automação
- `playbook_executions` - Histórico de execuções
- `threat_indicators` - Indicadores de ameaça
- `modules` - Módulos do sistema
- `audit_log` - Log de auditoria

## 🔐 Autenticação e Autorização

### JWT Tokens

- Access Token: 15 minutos de validade
- Refresh Token: 7 dias de validade
- Armazenados em `refresh_tokens` table

### Roles (RBAC)

- `admin` - Acesso total
- `analyst` - Analista SOC
- `viewer` - Visualização apenas
- `auditor` - Acesso a logs e relatórios

### Middleware

```go
// Requer autenticação
router.Use(authMiddleware())

// Requer role específica
router.Use(requireRole("admin"))
```

## ☁️ Integrações AWS

### Credenciais

Três métodos suportados (em ordem de prioridade):

1. **IAM Role** (recomendado para produção)
   - Instance Profile (EC2)
   - Task Role (ECS Fargate)
   - Automático, sem configuração

2. **AWS Connections** (via UI)
   - STS AssumeRole
   - Tokens temporários
   - Auto-refresh

3. **Environment Variables** (desenvolvimento)
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`
   - `AWS_REGION`

### Serviços Integrados

- **CloudTrail** - Audit logs
- **GuardDuty** - Threat detection
- **Security Hub** - Compliance
- **AWS Config** - Resource tracking
- **Inspector** - Vulnerability scanning
- **IAM** - Identity management

## 🧪 Testes

```bash
# Executar todos os testes
go test ./...

# Testes com coverage
go test -cover ./...

# Testes de integração
go test ./tests/integration/...

# Testes unitários
go test ./tests/unit/...
```

## 📊 Build e Deploy

### Build Local

```bash
# Build do binário
go build -o siem-api ./rest/*.go

# Executar
./siem-api
```

### AWS ECS/Fargate

1. Build da imagem:
```bash
docker build -t siem-backend:latest .
```

2. Tag para ECR:
```bash
docker tag siem-backend:latest <account-id>.dkr.ecr.<region>.amazonaws.com/siem-backend:latest
```

3. Push para ECR:
```bash
aws ecr get-login-password --region <region> | docker login --username AWS --password-stdin <account-id>.dkr.ecr.<region>.amazonaws.com
docker push <account-id>.dkr.ecr.<region>.amazonaws.com/siem-backend:latest
```

4. Deploy no ECS via console ou CLI

### Task Definition (ECS)

```json
{
  "family": "siem-backend",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "4096",
  "taskRoleArn": "arn:aws:iam::<account>:role/SIEMTaskRole",
  "executionRoleArn": "arn:aws:iam::<account>:role/SIEMExecutionRole",
  "containerDefinitions": [
    {
      "name": "siem-backend",
      "image": "<account>.dkr.ecr.<region>.amazonaws.com/siem-backend:latest",
      "portMappings": [{"containerPort": 8080}],
      "environment": [
        {"name": "USE_REAL_AWS_DATA", "value": "true"},
        {"name": "GIN_MODE", "value": "release"}
      ],
      "secrets": [
        {"name": "DB_PASSWORD", "valueFrom": "arn:aws:secretsmanager:..."},
        {"name": "JWT_SECRET", "valueFrom": "arn:aws:secretsmanager:..."}
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -q -O- http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

## 🔒 Segurança

### Boas Práticas Implementadas

- ✅ JWT com refresh tokens
- ✅ Passwords hasheados (bcrypt)
- ✅ CORS configurável
- ✅ Rate limiting
- ✅ Input validation
- ✅ SQL injection prevention (prepared statements)
- ✅ XSS protection
- ✅ HTTPS only em produção
- ✅ Secrets via AWS Secrets Manager
- ✅ Audit logging

### Secrets Management

**Desenvolvimento:**
```bash
# Usar .env file
cp env.example .env
```

**Produção:**
```bash
# AWS Secrets Manager
aws secretsmanager create-secret \
  --name siem/db-password \
  --secret-string "SecurePassword123!"
```

## 📈 Performance

### Otimizações

- Connection pooling (PostgreSQL, Redis)
- Cache de queries frequentes (Redis)
- Índices otimizados no banco
- Compression middleware (gzip)
- Paginação em todas as listagens
- Lazy loading de dados

### Monitoramento

```bash
# Métricas da aplicação
curl http://localhost:8080/api/metrics

# Health check
curl http://localhost:8080/health
```

## 🐛 Troubleshooting

### Erro de conexão com banco

```bash
# Verificar se PostgreSQL está rodando
docker ps | grep postgres

# Testar conexão
psql -h localhost -U siem -d siem

# Verificar logs
docker logs siem-postgres
```

### Erro de conexão com Redis

```bash
# Verificar se Redis está rodando
docker ps | grep redis

# Testar conexão
redis-cli -h localhost -a ChangeMeInProduction456! ping

# Verificar logs
docker logs siem-redis
```

### Build falha

```bash
# Limpar cache e rebuild
go clean -modcache
go mod download
go build ./rest/*.go
```

### Container não inicia

```bash
# Verificar logs
docker logs siem-backend

# Verificar health check
docker inspect siem-backend | grep -A 10 Health
```

## 📝 Desenvolvimento

### Adicionar novo endpoint

1. Criar handler em `rest/`:
```go
func handleNewFeature(c *gin.Context) {
    // Implementation
}
```

2. Registrar rota em `main.go`:
```go
api.GET("/new-feature", handleNewFeature)
```

3. Adicionar testes em `tests/`:
```go
func TestNewFeature(t *testing.T) {
    // Test implementation
}
```

### Adicionar nova integração

1. Criar collector em `rest/`:
```go
type NewServiceCollector struct {
    // Fields
}
```

2. Implementar métodos de coleta
3. Registrar em `main.go`
4. Adicionar configuração em `.env`

## 🤝 Contribuindo

1. Clone o repositório
2. Crie uma branch: `git checkout -b feature/nova-funcionalidade`
3. Commit suas mudanças: `git commit -m 'Adiciona nova funcionalidade'`
4. Push para a branch: `git push origin feature/nova-funcionalidade`
5. Abra um Pull Request

## 📄 Licença

Proprietary - Todos os direitos reservados

## 📞 Suporte

- Email: suporte@empresa.com
- Slack: #siem-support
- Documentação: [docs/](../docs/)

## 🔗 Links Relacionados

- [Frontend Repository](https://github.com/empresa/siem-frontend)
- [Documentação Completa](../docs/)
- [AWS Integration Guide](../docs/AWS-IAM-ROLE-INTEGRATION.md)
- [Production Deployment](../docs/PRODUCTION-DEPLOYMENT.md)

