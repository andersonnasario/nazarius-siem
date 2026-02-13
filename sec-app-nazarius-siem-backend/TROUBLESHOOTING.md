# Troubleshooting - Backend

Soluções para problemas comuns no build e deploy do backend.

## 🐛 Erro: "cannot find module providing package"

### Sintomas
```
rest/aws_cloudtrail_collector.go:8:2: cannot find module providing package github.com/aws/aws-sdk-go/aws
```

### Causa
O arquivo `go.sum` está desatualizado ou faltando dependências.

### Solução

**Opção 1: Usando Docker (recomendado)**
```bash
cd Backend
./update-deps.sh
```

**Opção 2: Com Go instalado localmente**
```bash
cd Backend
go mod download
go mod tidy
```

**Opção 3: Manualmente no Dockerfile**
O Dockerfile já está configurado para fazer isso automaticamente:
```dockerfile
RUN export GOTOOLCHAIN=auto && go mod download && go mod tidy
```

---

## 🐛 Erro: "package X is not in std"

### Sintomas
```
rest/auth.go:9:2: package siem-platform/api/database is not in std
```

### Causa
Import paths estão usando caminhos relativos incorretos ao invés do module path completo.

### Solução

**Verificar o module name em `go.mod`:**
```go
module github.com/cognimind/siem-platform
```

**Corrigir imports nos arquivos `.go`:**

❌ Incorreto:
```go
import "siem-platform/api/database"
```

✅ Correto:
```go
import "github.com/cognimind/siem-platform/database"
```

**Comando para corrigir em massa:**
```bash
cd Backend
sed -i 's|siem-platform/api/database|github.com/cognimind/siem-platform/database|g' rest/*.go
```

---

## 🐛 Erro: Build falha com "-mod=readonly"

### Sintomas
```
go build -mod=readonly: build failed
```

### Causa
A flag `-mod=readonly` impede que o Go atualize o `go.sum` durante o build.

### Solução

**Atualizar o Dockerfile:**

❌ Incorreto:
```dockerfile
RUN go build -mod=readonly -o /out/siem-api ./rest/*.go
```

✅ Correto:
```dockerfile
RUN go build -mod=mod -o /out/siem-api ./rest/*.go
```

---

## 🐛 Erro: "missing go.sum entry"

### Sintomas
```
missing go.sum entry for module providing package github.com/xxx
```

### Causa
O `go.sum` não contém checksums para todas as dependências.

### Solução

```bash
cd Backend
go mod download
go mod tidy
```

Ou use o script:
```bash
./update-deps.sh
```

---

## 🐛 Erro: Container não inicia

### Sintomas
```
docker run siem-backend:latest
# Container para imediatamente
```

### Diagnóstico

**1. Verificar logs:**
```bash
docker logs <container-id>
```

**2. Verificar variáveis de ambiente:**
```bash
docker inspect <container-id> | grep -A 20 Env
```

**3. Testar manualmente:**
```bash
docker run -it --entrypoint sh siem-backend:latest
# Dentro do container:
/usr/local/bin/siem-api
```

### Soluções Comuns

**Falta variáveis de ambiente:**
```bash
docker run -p 8080:8080 \
  -e DB_HOST=postgres \
  -e DB_PORT=5432 \
  -e DB_USER=siem \
  -e DB_PASSWORD=password \
  -e DB_NAME=siem \
  -e REDIS_HOST=redis \
  -e REDIS_PORT=6379 \
  -e ELASTICSEARCH_URL=http://elasticsearch:9200 \
  -e JWT_SECRET=your-secret \
  siem-backend:latest
```

**Banco de dados não acessível:**
- Verificar se PostgreSQL está rodando
- Verificar network do Docker
- Verificar credenciais

---

## 🐛 Erro: "dial tcp: lookup postgres: no such host"

### Sintomas
```
Error connecting to database: dial tcp: lookup postgres: no such host
```

### Causa
Container não consegue resolver o hostname `postgres`.

### Solução

**Opção 1: Usar Docker Compose**
```bash
docker-compose up
```

**Opção 2: Criar network manualmente**
```bash
# Criar network
docker network create siem-network

# Rodar PostgreSQL
docker run -d \
  --name postgres \
  --network siem-network \
  -e POSTGRES_PASSWORD=password \
  postgres:15-alpine

# Rodar backend
docker run -d \
  --name backend \
  --network siem-network \
  -e DB_HOST=postgres \
  siem-backend:latest
```

**Opção 3: Usar IP do host**
```bash
docker run -p 8080:8080 \
  -e DB_HOST=host.docker.internal \
  siem-backend:latest
```

---

## 🐛 Erro: "permission denied" ao executar binário

### Sintomas
```
/usr/local/bin/siem-api: permission denied
```

### Causa
Binário não tem permissão de execução ou problema com non-root user.

### Solução

**Verificar Dockerfile:**
```dockerfile
# Deve ter estas linhas:
COPY --from=builder /out/siem-api /usr/local/bin/siem-api
RUN chown siem:siem /usr/local/bin/siem-api
USER siem
```

**Rebuild a imagem:**
```bash
docker build --no-cache -t siem-backend:latest .
```

---

## 🐛 Erro: Build muito lento

### Sintomas
Build do Docker demora mais de 5 minutos.

### Soluções

**1. Usar cache do Docker:**
```bash
# Não usar --no-cache a menos que necessário
docker build -t siem-backend:latest .
```

**2. Otimizar .dockerignore:**
```
# Adicionar em .dockerignore:
vendor/
*.test
*.out
.git
docs/
```

**3. Usar BuildKit:**
```bash
DOCKER_BUILDKIT=1 docker build -t siem-backend:latest .
```

**4. Multi-stage build (já implementado):**
O Dockerfile já usa multi-stage build para otimização.

---

## 🐛 Erro: Health check failing

### Sintomas
```
docker ps
# STATUS: unhealthy
```

### Diagnóstico

```bash
# Ver logs do health check
docker inspect <container-id> | grep -A 10 Health

# Testar manualmente
docker exec <container-id> wget -q -O- http://localhost:8080/health
```

### Soluções

**1. Endpoint /health não existe:**
Verificar se o handler está registrado em `main.go`:
```go
router.GET("/health", handleHealth)
```

**2. Porta incorreta:**
Verificar se a aplicação está escutando na porta 8080:
```go
router.Run(":8080")
```

**3. Timeout muito curto:**
Ajustar no Dockerfile:
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1
```

---

## 🐛 Erro: "out of memory" durante build

### Sintomas
```
Error: failed to build: signal: killed
```

### Causa
Docker não tem memória suficiente alocada.

### Solução

**1. Aumentar memória do Docker:**
- Docker Desktop: Settings > Resources > Memory (mínimo 4GB)

**2. Limpar cache do Docker:**
```bash
docker system prune -a
docker builder prune -a
```

**3. Build com menos paralelismo:**
```bash
docker build --cpus 2 -t siem-backend:latest .
```

---

## 🐛 Erro: AWS SDK não funciona

### Sintomas
```
Error: NoCredentialProviders: no valid providers in chain
```

### Causa
Credenciais AWS não configuradas.

### Solução

**Opção 1: IAM Role (produção - recomendado)**
- Deploy no ECS com Task Role configurado
- Nenhuma configuração adicional necessária

**Opção 2: AWS Connections (via UI)**
- Configurar conexões AWS na interface web
- Sistema usa STS AssumeRole automaticamente

**Opção 3: Environment Variables (desenvolvimento)**
```bash
docker run -p 8080:8080 \
  -e AWS_ACCESS_KEY_ID=xxx \
  -e AWS_SECRET_ACCESS_KEY=yyy \
  -e AWS_REGION=us-east-1 \
  siem-backend:latest
```

---

## 🔧 Comandos Úteis para Diagnóstico

### Verificar versão do Go no container
```bash
docker run --rm --entrypoint go siem-backend:latest version
```

### Listar dependências
```bash
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go list -m all
```

### Verificar tamanho da imagem
```bash
docker images siem-backend:latest
docker history siem-backend:latest
```

### Analisar camadas da imagem
```bash
docker inspect siem-backend:latest | jq '.[0].RootFS.Layers'
```

### Testar conectividade de dentro do container
```bash
docker exec -it <container-id> sh
# Dentro do container:
wget -O- http://postgres:5432
ping redis
nslookup elasticsearch
```

### Ver variáveis de ambiente
```bash
docker exec <container-id> env
```

### Verificar processos
```bash
docker exec <container-id> ps aux
```

---

## 📚 Recursos Adicionais

- [Go Modules Reference](https://go.dev/ref/mod)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [AWS SDK for Go](https://aws.github.io/aws-sdk-go-v2/docs/)
- [Gin Framework Documentation](https://gin-gonic.com/docs/)

---

## 🆘 Suporte

Se o problema persistir:

1. **Verificar logs completos:**
   ```bash
   docker logs -f <container-id> 2>&1 | tee backend.log
   ```

2. **Coletar informações do sistema:**
   ```bash
   docker version
   docker info
   go version  # se instalado localmente
   ```

3. **Contatar suporte:**
   - Email: devops@empresa.com
   - Slack: #siem-support
   - Anexar: logs, Dockerfile, go.mod, go.sum

---

**Última Atualização:** Novembro 2025  
**Versão:** 1.0

