# SIEM Platform - Frontend

Frontend da plataforma SIEM desenvolvido em React com Material-UI.

## 🚀 Tecnologias

- **React** 18.x
- **Material-UI** (MUI) 5.x
- **React Router** 6.x
- **Axios** para comunicação com API
- **Recharts** para gráficos
- **Nginx** para servir em produção

## 📋 Pré-requisitos

- Node.js 18.x ou superior
- npm ou yarn
- Docker (para build de produção)

## 🛠️ Instalação e Desenvolvimento

### Desenvolvimento Local

```bash
# Instalar dependências
npm install

# Iniciar servidor de desenvolvimento
npm start

# Aplicação estará disponível em http://localhost:3000
```

### Variáveis de Ambiente

**IMPORTANTE**: A URL da API é configurada em **runtime** para permitir mudanças sem rebuild.

#### Desenvolvimento Local (npm start)

Crie um arquivo `.env.local`:

```env
REACT_APP_API_URL=http://localhost:8080/api/v1
```

#### Produção (Docker/AWS)

**Não precisa rebuild!** Configure a variável de ambiente ao executar o container:

```bash
# Docker Run
docker run -p 80:80 \
  -e REACT_APP_API_URL=https://api.siem.empresa.com/api/v1 \
  siem-frontend:latest

# Docker Compose
environment:
  REACT_APP_API_URL: https://api.siem.empresa.com/api/v1

# AWS ECS Task Definition
{
  "environment": [
    {
      "name": "REACT_APP_API_URL",
      "value": "https://your-alb-url.us-east-1.elb.amazonaws.com/api/v1"
    }
  ]
}
```

**Como funciona:**
1. O container gera um arquivo `env-config.js` ao iniciar
2. Esse arquivo é carregado antes do React no `index.html`
3. O `api.js` lê de `window.__ENV__.REACT_APP_API_URL`
4. Fallback para `process.env.REACT_APP_API_URL` (dev) ou localhost

## 🐳 Docker

### Build da Imagem

```bash
# Build da imagem Docker
docker build -t siem-frontend:latest .

# Executar container
docker run -p 80:80 siem-frontend:latest
```

### Docker Compose

```bash
# Subir apenas o frontend (requer backend rodando)
docker-compose up frontend
```

## 📦 Build de Produção

```bash
# Criar build otimizado
npm run build

# Os arquivos estarão em ./build/
```

## 🏗️ Estrutura do Projeto

```
Frontend/
├── public/              # Arquivos estáticos
├── src/
│   ├── components/      # Componentes reutilizáveis
│   ├── contexts/        # Context API (AuthContext)
│   ├── pages/           # Páginas da aplicação
│   ├── services/        # Serviços (API)
│   ├── App.js           # Componente principal
│   └── index.js         # Entry point
├── Dockerfile           # Build de produção
├── nginx.conf           # Configuração Nginx
└── package.json         # Dependências
```

## 🎨 Páginas Principais

### Autenticação
- `/login` - Login
- `/register` - Registro

### Dashboard
- `/` - Dashboard principal
- `/executive` - Dashboard executivo

### SIEM Core
- `/events` - Monitoramento de eventos
- `/alerts` - Gerenciamento de alertas
- `/cases` - Gerenciamento de casos

### SOAR
- `/playbooks` - Playbooks de automação
- `/automated-response` - Respostas automatizadas

### Compliance
- `/cspm` - Cloud Security Posture Management
- `/pci-dss` - Compliance PCI-DSS
- `/compliance` - Outros frameworks

### Threat Intelligence
- `/threat-intelligence` - Inteligência de ameaças
- `/threat-hunting` - Caça a ameaças
- `/ueba` - User Behavior Analytics

### Configurações
- `/users` - Gerenciamento de usuários
- `/integrations` - Integrações
- `/notifications` - Notificações
- `/settings` - Configurações gerais

## 🔧 Configuração do Nginx

O arquivo `nginx.conf` está configurado para:
- Servir arquivos estáticos
- Redirecionar todas as rotas para `index.html` (SPA)
- Proxy reverso para API (se necessário)
- Compressão gzip
- Cache de assets

## 🧪 Testes

```bash
# Executar testes
npm test

# Executar testes com coverage
npm test -- --coverage
```

## 📊 Build e Deploy

### AWS ECS/Fargate

1. Build da imagem:
```bash
docker build -t siem-frontend:latest .
```

2. Tag para ECR:
```bash
docker tag siem-frontend:latest <account-id>.dkr.ecr.<region>.amazonaws.com/siem-frontend:latest
```

3. Push para ECR:
```bash
docker push <account-id>.dkr.ecr.<region>.amazonaws.com/siem-frontend:latest
```

4. Deploy no ECS via console ou CLI

### Variáveis de Ambiente em Produção

Configure no ECS Task Definition ou via `.env`:

```env
REACT_APP_API_URL=https://api.siem.empresa.com
```

## 🔒 Segurança

- Todas as comunicações com API via HTTPS
- JWT tokens armazenados em localStorage
- CORS configurado no backend
- Content Security Policy via Nginx
- Sanitização de inputs

## 📈 Performance

- Code splitting automático
- Lazy loading de rotas
- Compressão gzip/brotli
- Cache de assets
- Service Worker (PWA ready)

## 🐛 Troubleshooting

### Erro de conexão com API

Verifique se:
1. Backend está rodando
2. `REACT_APP_API_URL` está correto
3. CORS está configurado no backend

### Build falha

```bash
# Limpar cache e reinstalar
rm -rf node_modules package-lock.json
npm install
npm run build
```

### Container não inicia

```bash
# Verificar logs
docker logs siem-frontend

# Verificar se porta 80 está livre
netstat -tulpn | grep :80
```

## 📝 Scripts Disponíveis

- `npm start` - Inicia servidor de desenvolvimento
- `npm test` - Executa testes
- `npm run build` - Build de produção
- `npm run eject` - Ejeta configuração (irreversível)

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

- [Backend Repository](https://github.com/empresa/siem-backend)
- [Documentação Completa](../docs/)
- [API Documentation](https://api.siem.empresa.com/docs)

