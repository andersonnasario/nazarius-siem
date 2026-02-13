<p align="center">
  <h1 align="center">Nazarius SIEM</h1>
  <p align="center">
    Open-source, enterprise-grade Security Information and Event Management platform
  </p>
</p>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/React-18.2-61DAFB?logo=react&logoColor=black" alt="React"></a>
  <a href="https://opensearch.org/"><img src="https://img.shields.io/badge/OpenSearch-2.x-005EB8?logo=opensearch&logoColor=white" alt="OpenSearch"></a>
  <a href="https://www.postgresql.org/"><img src="https://img.shields.io/badge/PostgreSQL-15-336791?logo=postgresql&logoColor=white" alt="PostgreSQL"></a>
  <a href="https://redis.io/"><img src="https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white" alt="Redis"></a>
</p>

---

Nazarius SIEM is a full-featured **Security Information and Event Management** platform that unifies real-time threat detection, cloud security posture management (CSPM), user & entity behavior analytics (UEBA), security orchestration & automated response (SOAR), and compliance management into a single deployable solution.

Built with a **Go** backend and **React** frontend, it integrates natively with AWS, Google Cloud, Cloudflare, JumpCloud, and multiple threat intelligence feeds.

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Screenshots](#screenshots)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Modules in Detail](#modules-in-detail)
- [API Reference](#api-reference)
- [Data Storage](#data-storage)
- [Security](#security)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## Architecture

```
                    +-----------------------+
                    |     React Frontend    |
                    |  Material-UI + Recharts|
                    |      (Port 3000)      |
                    +----------+------------+
                               |
                           REST API (JWT)
                               |
                    +----------+------------+
                    |      Go Backend       |
                    |    Gin Framework      |
                    |      (Port 8080)      |
                    +--+-------+--------+---+
                       |       |        |
            +----------+  +----+----+  ++----------+
            | OpenSearch|  |PostgreSQL| |   Redis   |
            |  Events,  |  |  Users,  | |  Cache,   |
            |  Alerts,  |  |  Auth,   | |  Sessions,|
            |  Cases,   |  |  Cases,  | |  Rate     |
            |  IOCs,    |  |  Config  | |  Limiting |
            |  35+ idx  |  |          | |           |
            +-----------+  +----------+ +-----------+
                  |
     +------------+---+----------+-----------+
     |            |   |          |           |
  +--+---+  +----+-+ +---+--+ +-+------+ +--+------+
  | AWS  |  | GCP  | |Cloud-| |Jump-   | |Threat   |
  |      |  |      | |flare | |Cloud   | |Intel    |
  +------+  +------+ +------+ +--------+ +---------+
  CloudTrail  SCC      WAF     Directory   VirusTotal
  GuardDuty   Asset    Events  Insights    AbuseIPDB
  Inspector   Audit                        NVD (CVE)
  SecHub      Logs
  Config
  VPC Flows
```

### Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| **Backend** | Go + Gin | 1.24 |
| **Frontend** | React + Material-UI | 18.2 + 5.13 |
| **Search/Analytics** | OpenSearch (or Elasticsearch) | 2.x / 8.x |
| **Database** | PostgreSQL | 15+ |
| **Cache** | Redis | 7+ |
| **Charts** | Recharts | 2.6 |
| **HTTP Client** | Axios | 1.4 |
| **Auth** | JWT (HS256) | - |
| **Cloud SDK** | AWS SDK Go v1/v2, GCP Go SDK | - |
| **Metrics** | Prometheus client | - |
| **Messaging** | Kafka (optional) | - |

---

## Features

### Core SIEM

| Feature | Description |
|---------|-------------|
| **Event Ingestion** | Collect, normalize, and index security events from multiple sources into OpenSearch |
| **Event Search** | Full-text search with aggregations, filters, and export capabilities |
| **Alert Management** | Automated alert generation with severity levels (critical/high/medium/low/info), status tracking, and assignment |
| **Alert Correlation** | Correlation engine that groups related alerts into incidents |
| **Alert Triage** | Prioritized triage queue with bulk actions and auto-triage rules |
| **Case Management** | Full incident lifecycle -- creation, assignment, checklists, comments, attachments, activity log |
| **Case Policies** | Configurable policies for automatic case creation from alerts |
| **Suppression Rules** | Alert suppression and false-positive management |
| **Dashboard** | Real-time security operations dashboard with customizable widgets |
| **Executive Dashboard** | High-level KPIs, trends, and risk posture for leadership |
| **Custom Dashboards** | Drag-and-drop dashboard builder with multiple widget types |
| **Reports** | Report templates, generation, scheduling, and export (PDF/CSV) |

### Cloud Security Posture Management (CSPM)

| Feature | Description |
|---------|-------------|
| **AWS Security Hub** | Ingest aggregated findings with severity and compliance status |
| **AWS GuardDuty** | Collect threat detection findings with MITRE ATT&CK mapping |
| **AWS Inspector** | Vulnerability findings with CVE/CVSS details |
| **AWS CloudTrail** | Audit trail events with user and resource tracking |
| **AWS Config** | Configuration compliance rules and findings |
| **AWS VPC Flow Logs** | Network traffic analysis from S3 |
| **GCP Security Command Center** | Security findings with severity and state tracking |
| **GCP Cloud Asset Inventory** | Resource discovery (Instances, Buckets, Service Accounts, Firewalls) |
| **GCP Cloud Audit Logs** | Admin activity audit log collection |
| **Multi-Account (AWS)** | STS AssumeRole for cross-account access with credential rotation |
| **Config Aggregator** | Multi-account AWS Config aggregation |
| **PCI-DSS Dashboard** | Requirements tracking, controls, and compliance scoring |
| **Drift Detection** | Detect configuration drift from security baselines |
| **Auto-Remediation** | Rule-based remediation with approval workflows and rollback |
| **CSPM Alerts** | Dedicated alert system with channels, rules, and escalation policies |

### User & Entity Behavior Analytics (UEBA)

| Feature | Description |
|---------|-------------|
| **User Profiles** | Behavioral baselines per user/entity stored in OpenSearch |
| **Anomaly Detection** | ML-based detection of unusual patterns |
| **Risk Scoring** | Dynamic risk scores combining multiple signals |
| **Peer Group Analysis** | Compare behavior against peer groups |
| **Insider Threat** | Detect unusual access, data exfiltration, privilege abuse |

### Security Orchestration, Automation & Response (SOAR)

| Feature | Description |
|---------|-------------|
| **Playbooks** | Visual playbook editor with versioning |
| **Playbook Engine** | Automated execution with conditional logic |
| **Integrations** | AWS Lambda actions, webhooks, email notifications |
| **Execution History** | Full audit trail of playbook runs |
| **Automated Response** | Rules for automatic containment and response actions |
| **Approval Workflows** | Human-in-the-loop for critical actions |

### Threat Intelligence

| Feature | Description |
|---------|-------------|
| **IOC Management** | Indicators of Compromise (IP, domain, hash, URL, email) |
| **Threat Feeds** | Subscribe and sync external threat feeds |
| **IP Reputation** | Real-time lookups against VirusTotal and AbuseIPDB |
| **CVE Database** | NVD synchronization with CVE search and tracking |
| **Threat Actors** | Track threat actor profiles and campaigns |
| **Intel Fusion** | Correlate indicators across multiple feeds |

### Threat Hunting

| Feature | Description |
|---------|-------------|
| **Hunt Queries** | Advanced search with pivot capabilities |
| **Hypotheses** | Document and track hunting hypotheses |
| **Campaigns** | Organize hunts into campaigns |
| **Notebooks** | Investigation notebooks for collaborative hunting |
| **MITRE ATT&CK** | Full matrix with technique coverage analysis and detection mapping |
| **Hunter Ranking** | Track and rank analyst hunting performance |

### Integrations

| Integration | Method | Features |
|------------|--------|----------|
| **Cloudflare WAF** | GraphQL API (Bearer token) | Real-time event collection, zone management, IP reputation analysis, case creation from events |
| **JumpCloud** | OAuth2 Service Account (Client ID + Secret) | Directory Insights events, severity mapping, multi-service support |
| **Fortinet** | Webhook receiver | Log ingestion, alert generation, dashboard |
| **AWS (6+ services)** | IAM Role / Access Key / STS | CloudTrail, GuardDuty, Inspector, SecurityHub, Config, VPC Flows |
| **GCP (3 services)** | Service Account JSON | Security Command Center, Cloud Asset, Audit Logs |
| **VirusTotal** | API Key | IP/domain/hash reputation lookups |
| **AbuseIPDB** | API Key | IP abuse reports and confidence scores |
| **NVD** | API Key (optional) | CVE synchronization (50 req/30s with key) |

### Additional Modules

| Module | Description |
|--------|-------------|
| **Digital Forensics** | Evidence collection, chain-of-custody, timeline reconstruction |
| **Incident Response** | Automation rules, response workflows, containment actions |
| **Network Analysis** | Flow log analysis, top talkers, anomaly detection |
| **File Integrity Monitoring (FIM)** | Baseline management, change detection, rules |
| **Data Loss Prevention (DLP)** | Policy-based detection with regex patterns (SSN, credit cards, API keys) |
| **Endpoint Detection (EDR)** | Agent management, threat detection, endpoint forensics |
| **Zero Trust** | Identity monitoring, device trust, policy enforcement |
| **Deception Technology** | Honeypots, honeytokens, decoy management |
| **Continuous Validation** | Security control testing and coverage tracking |
| **Security Awareness** | Training campaigns, phishing simulations, completion tracking |
| **SLA Metrics** | SLA policy management, tracking, breach alerts |
| **Multi-Tenancy** | Tenant isolation for managed security providers |
| **PLA Risk Matrix** | Risk assessments and guard rails |
| **Module Manager** | Enable/disable modules dynamically via UI |
| **Data Retention** | Configurable retention policies with automated cleanup |

---

## Screenshots

> Screenshots coming soon. Contributions welcome!

---

## Quick Start

### Prerequisites

- **Go** 1.21+ ([install](https://go.dev/dl/))
- **Node.js** 18+ ([install](https://nodejs.org/))
- **Docker & Docker Compose** ([install](https://docs.docker.com/get-docker/))

### Option 1: Docker Compose (recommended)

```bash
# Clone the repository
git clone https://github.com/andersonnasario/nazarius-siem.git
cd nazarius-siem

# Configure environment
cp sec-app-nazarius-siem-backend/.env.example sec-app-nazarius-siem-backend/.env

# IMPORTANT: Edit .env and set required passwords
# At minimum, set: POSTGRES_PASSWORD, REDIS_PASSWORD, JWT_SECRET
nano sec-app-nazarius-siem-backend/.env

# Start all services
cd sec-app-nazarius-siem-backend
docker compose up -d
```

### Option 2: Manual Development Setup

**1. Start infrastructure services:**

```bash
# Start PostgreSQL, Redis, and OpenSearch/Elasticsearch
# You can use docker for just the services:
docker run -d --name siem-postgres -e POSTGRES_DB=siem -e POSTGRES_USER=siem_user -e POSTGRES_PASSWORD=yourpassword -p 5432:5432 postgres:15-alpine
docker run -d --name siem-redis -p 6379:6379 redis:7-alpine
docker run -d --name siem-opensearch -e "discovery.type=single-node" -e "DISABLE_SECURITY_PLUGIN=true" -p 9200:9200 opensearchproject/opensearch:2.11.0
```

**2. Start the backend:**

```bash
cd sec-app-nazarius-siem-backend
cp .env.example .env
# Edit .env with your configuration
go mod download
go run ./rest/
```

**3. Start the frontend:**

```bash
cd sec-app-nazarius-siem-frontend
cp .env.example .env
npm install
npm start
```

**4. Access the application:**

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8080/api/v1 |
| Health Check | http://localhost:8080/api/v1/health |
| OpenSearch | http://localhost:9200 |

### Default Credentials

On first startup with the seed database, a default admin user is created:

> **Important:** Change the default password immediately after first login.

---

## Configuration

All configuration is managed via environment variables. Copy `.env.example` to `.env` and customize:

```bash
cp sec-app-nazarius-siem-backend/.env.example sec-app-nazarius-siem-backend/.env
```

### Required Variables

| Variable | Description | How to Generate |
|----------|-------------|-----------------|
| `POSTGRES_PASSWORD` | PostgreSQL password | `openssl rand -base64 32` |
| `REDIS_PASSWORD` | Redis password | `openssl rand -base64 32` |
| `JWT_SECRET` | JWT signing secret (min 32 chars) | `openssl rand -base64 48` |

### Infrastructure

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `siem` | Database name |
| `DB_USER` | `siem_user` | Database user |
| `ELASTICSEARCH_URL` | `http://localhost:9200` | OpenSearch/Elasticsearch URL |
| `ELASTICSEARCH_USERNAME` | *(empty)* | Auth for AWS OpenSearch Service |
| `ELASTICSEARCH_PASSWORD` | *(empty)* | Auth for AWS OpenSearch Service |
| `ELASTICSEARCH_USE_TLS` | `false` | Enable TLS for AWS OpenSearch |
| `REDIS_HOST` | `localhost` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_USE_TLS` | `false` | Enable TLS for AWS ElastiCache |
| `PORT` | `8080` | Backend server port |
| `GIN_MODE` | `debug` | Gin mode (`debug` / `release`) |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins (comma-separated) |

### Data Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `DISABLE_MOCK_DATA` | `false` | Set `true` to show only real data |
| `USE_REAL_AWS_DATA` | `false` | Set `true` to connect to AWS services |
| `USE_SECURITY_HUB` | `false` | Enable Security Hub indexer |

### AWS Integration

| Variable | Description |
|----------|-------------|
| `AWS_REGION` | AWS region (default: `us-east-1`) |
| `AWS_ACCOUNT_ID` | AWS account ID |
| `AWS_ACCESS_KEY_ID` | Access key (prefer IAM Roles) |
| `AWS_SECRET_ACCESS_KEY` | Secret key (prefer IAM Roles) |
| `CLOUDTRAIL_S3_BUCKET` | S3 bucket for CloudTrail logs |
| `VPC_FLOWLOGS_S3_BUCKET` | S3 bucket for VPC Flow Logs |

> **Production Tip:** Use IAM Instance Profiles (EC2) or Task Roles (ECS) instead of access keys.

### GCP Integration

| Variable | Description |
|----------|-------------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to Service Account JSON key file |

> GCP can also be configured via the UI with inline JSON credentials.

### Integrations

| Variable | Description |
|----------|-------------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID |
| `CLOUDFLARE_ZONE_IDS` | Comma-separated zone IDs |
| `CLOUDFLARE_ENABLED` | Enable Cloudflare collector (`true`/`false`) |
| `NVD_API_KEY` | NVD API key for CVE sync |
| `AUTOMATED_RESPONSE_ENABLED` | Enable automated response actions |

### Frontend

| Variable | Default | Description |
|----------|---------|-------------|
| `REACT_APP_API_URL` | `http://localhost:8080/api/v1` | Backend API URL |

---

## Project Structure

```
nazarius-siem/
├── .github/                              # GitHub templates
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md
│
├── docs/                                 # Documentation
│   ├── LEIA-ME-PRIMEIRO.md               # Getting started (PT-BR)
│   ├── RESUMO_EXECUTIVO.md               # Executive summary
│   ├── ANALISE_CRITERIOSA_PRODUCAO.md    # Production analysis
│   ├── MANUAL_OPERACIONAL_*.md           # Operational manuals
│   └── ...                               # Module-specific docs
│
├── sec-app-nazarius-siem-backend/        # Go Backend
│   ├── rest/                             # API handlers (103 Go files)
│   │   ├── main.go                       # Server, routes, initialization
│   │   ├── auth.go                       # JWT authentication
│   │   ├── config.go                     # Configuration loading
│   │   ├── middleware_security.go        # Security middleware
│   │   ├── events.go                     # Event ingestion & search
│   │   ├── alerts.go                     # Alert management
│   │   ├── cases.go / cases_opensearch.go # Case management
│   │   ├── cspm*.go                      # CSPM module (7 files)
│   │   ├── aws_*.go                      # AWS integrations (12 files)
│   │   ├── cspm_gcp.go                   # GCP integration
│   │   ├── ueba*.go                      # UEBA module (3 files)
│   │   ├── soar.go / playbook*.go        # SOAR module (4 files)
│   │   ├── threat_intel*.go              # Threat intelligence (4 files)
│   │   ├── cloudflare_waf_collector.go   # Cloudflare integration
│   │   ├── jumpcloud_collector.go        # JumpCloud integration
│   │   ├── fortinet_webhook.go           # Fortinet integration
│   │   ├── vulnerability*.go             # Vulnerability management (4 files)
│   │   ├── forensics_opensearch.go       # Digital forensics
│   │   ├── hunting.go                    # Threat hunting
│   │   ├── dlp.go                        # Data loss prevention
│   │   ├── fim.go                        # File integrity monitoring
│   │   ├── edr.go                        # Endpoint detection
│   │   ├── zero_trust.go                 # Zero Trust
│   │   └── ...                           # 50+ more modules
│   ├── database/                         # PostgreSQL layer
│   │   ├── init/01_schema.sql            # Schema (20 tables)
│   │   ├── init/02_seed.sql              # Development seed data
│   │   └── init/02_seed_production.sql   # Production seed
│   ├── processors/ingest/                # Event ingest processor
│   ├── soar/engine/                      # SOAR playbook engine
│   ├── tests/                            # Unit & integration tests
│   ├── docker-compose.yml                # Full stack deployment
│   ├── Dockerfile                        # Backend container
│   ├── go.mod / go.sum                   # Go dependencies
│   └── .env.example                      # Environment template
│
├── sec-app-nazarius-siem-frontend/       # React Frontend
│   ├── src/
│   │   ├── pages/                        # 73 page components
│   │   │   ├── Dashboard.js              # Main dashboard
│   │   │   ├── Events.js                 # Event management
│   │   │   ├── Alerts.js                 # Alert management
│   │   │   ├── Cases.js                  # Case management
│   │   │   ├── CSPM*.js                  # Cloud security (7 pages)
│   │   │   ├── UEBA.js                   # Behavior analytics
│   │   │   ├── SOAR.js / Playbooks.js    # Orchestration
│   │   │   ├── CloudflareIntegration.js  # Cloudflare
│   │   │   ├── JumpCloudIntegration.js   # JumpCloud
│   │   │   └── ...                       # 60+ more pages
│   │   ├── components/                   # Shared components
│   │   │   ├── Layout.js                 # App shell, sidebar, navigation
│   │   │   ├── AdminRoute.js             # Admin-only route guard
│   │   │   └── PrivateRoute.js           # Auth route guard
│   │   ├── contexts/
│   │   │   ├── AuthContext.js            # Authentication state
│   │   │   └── ModuleContext.js          # Module visibility
│   │   ├── services/api.js              # API client (1600+ lines)
│   │   └── App.js                        # Routes and lazy loading
│   ├── public/                           # Static assets
│   ├── Dockerfile                        # Frontend container (nginx)
│   ├── nginx.conf                        # Nginx configuration
│   ├── package.json                      # Node dependencies
│   └── .env.example                      # Frontend env template
│
├── LICENSE                               # Apache 2.0
├── README.md                             # This file
├── CONTRIBUTING.md                       # Contribution guide
├── CODE_OF_CONDUCT.md                    # Community standards
└── SECURITY.md                           # Vulnerability reporting
```

---

## Modules in Detail

### Authentication & Authorization

- **JWT-based** with access tokens (15 min) and refresh tokens (7 days)
- **Role-Based Access Control (RBAC)**: `admin`, `analyst_l1`, `analyst_l2`, and custom roles
- **Session management** with multi-device tracking and remote logout
- **Brute force protection**: 5 failed attempts triggers 30-minute lockout
- **Access scoping**: Filter data by `allowed_account_ids` and `allowed_bucket_names` per user
- **Audit logging**: Every authentication event is logged

### Security Middleware

The backend applies multiple security layers:

| Middleware | Function |
|-----------|----------|
| Rate Limiting | Per-IP rate limiting using token bucket |
| Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| CORS | Configurable origin allowlist with credentials |
| Input Validation | Content-Type enforcement, 10MB body limit |
| Brute Force | IP-based lockout after failed login attempts |
| Audit Log | Request logging (IP, method, path, status, latency) |
| IP Whitelist | Optional IP restriction for sensitive endpoints |
| API Key | X-API-Key header for external integrations |

### Health Checks

Kubernetes-compatible probes:

| Probe | Endpoint | Logic |
|-------|----------|-------|
| Health | `/api/v1/health` | Full component check (OpenSearch, Redis, PostgreSQL) |
| Liveness | liveness handler | Always 200 if process is running |
| Readiness | readiness handler | 200 only when OpenSearch + Redis are healthy |
| Startup | startup handler | 503 for first 5 seconds, then 200 |

---

## API Reference

The backend exposes 300+ REST API endpoints organized into groups. All protected endpoints require a JWT `Authorization: Bearer <token>` header.

### Public Endpoints

```
POST   /api/v1/auth/login              # Authenticate
POST   /api/v1/auth/refresh            # Refresh token
POST   /api/v1/auth/logout             # Logout
GET    /api/v1/health                   # Health check
POST   /api/v1/fortinet/webhook        # Fortinet webhook receiver
```

### Protected Endpoint Groups

| Group | Base Path | Key Endpoints |
|-------|-----------|---------------|
| **Events** | `/events` | search, aggregate, statistics, export |
| **Alerts** | `/alerts` | CRUD, status update, create-case, triage |
| **Cases** | `/cases` | CRUD, comments, checklist, link alerts/events |
| **Dashboards** | `/dashboards` | CRUD, custom widgets |
| **Playbooks** | `/playbooks` | CRUD, execute, versions, executions |
| **MITRE** | `/mitre` | tactics, techniques, coverage, detections |
| **Threat Intel** | `/threat-intel` | IOCs, enrichment, feeds, stats |
| **CVEs** | `/cves` | list, search, sync, NVD config |
| **UEBA** | `/ueba` | dashboard, users, anomalies, peer-groups |
| **Hunting** | `/hunting` | search, pivot, campaigns, findings |
| **Vulnerabilities** | `/vulnerabilities` | dashboard, list, assets, scans |
| **CSPM** | `/cspm` | accounts, resources, findings, compliance |
| **CSPM AWS** | `/cspm/aws/*` | config, security-hub, guardduty, inspector, cloudtrail |
| **CSPM GCP** | `/cspm/gcp/*` | status, config, test, sync, findings, stats |
| **Network** | `/network` | flowlogs, anomalies, top-talkers |
| **Forensics** | `/forensics` | cases, evidence, timeline |
| **DLP** | `/dlp` | policies, incidents, inspect |
| **FIM** | `/fim` | baselines, changes, rules |
| **EDR** | `/edr` | agents, endpoints, threats |
| **SOAR** | `/soar` | playbooks, executions, integrations |
| **Zero Trust** | `/zero-trust` | identities, devices, policies |
| **Reports** | `/reports` | templates, generate, export, schedules |

### Admin-Only Endpoints

| Group | Base Path | Key Endpoints |
|-------|-----------|---------------|
| **Users** | `/users` | CRUD, roles |
| **System** | `/system` | logs, status, config, OpenSearch management |
| **Modules** | `/modules` | list, config, enable/disable |
| **Integrations** | `/integrations` | CRUD, test, sync |
| **Cloudflare** | `/cloudflare` | status, config, zones, sync, events |
| **JumpCloud** | `/jumpcloud` | status, config, test, sync, events, stats |
| **Fortinet** | `/fortinet` | configs, dashboard, events |

---

## Data Storage

### PostgreSQL (Relational Data)

20 tables for structured data:

| Table | Purpose |
|-------|---------|
| `users` | User accounts, roles, skills, access scopes |
| `roles` | Role definitions and permissions |
| `sessions` | Active sessions with device info |
| `refresh_tokens` | JWT refresh tokens |
| `cases` | Incident cases |
| `case_comments` | Case discussion |
| `case_attachments` | Evidence files |
| `case_activity_log` | Case audit trail |
| `alerts` | Security alerts |
| `playbooks` | SOAR playbooks |
| `playbook_executions` | Execution history |
| `playbook_versions` | Playbook version control |
| `threat_indicators` | IOCs |
| `threat_feeds` | Feed configurations |
| `modules` | Module state |
| `system_config` | System settings |
| `audit_log` | Full audit trail |
| `auth_audit_log` | Authentication events |

### OpenSearch (Event Data)

35+ indices for high-volume event data:

| Index | Content |
|-------|---------|
| `siem-events` / `siem-events-*` | Security events |
| `siem-alerts` | Generated alerts |
| `siem-cases` | Cases (OpenSearch mirror) |
| `siem-iocs` | Indicators of Compromise |
| `siem-threat-feeds` | Threat feed data |
| `siem-threat-actors` | Threat actor profiles |
| `siem-campaigns` | Threat campaigns |
| `siem-cves` | CVE database |
| `siem-vulnerabilities` | Vulnerability findings |
| `siem-ueba-profiles` | User behavioral profiles |
| `siem-ueba-anomalies` | UEBA anomalies |
| `siem-ml-anomalies` | ML-detected anomalies |
| `siem-ml-predictions` | ML predictions |
| `siem-correlations` | Alert correlations |
| `siem-playbooks` | Playbook definitions |
| `siem-executions` | Playbook executions |
| `siem-forensics` | Forensic investigations |
| `siem-forensics-evidence` | Digital evidence |
| `siem-forensics-timeline` | Forensic timelines |
| `siem-vpc-flowlogs` | VPC Flow Logs |
| `siem-network-anomalies` | Network anomalies |
| `siem-cloudflare-waf` | Cloudflare WAF events |
| `siem-jumpcloud-events` | JumpCloud events |
| `siem-fortinet-logs` | Fortinet logs |
| `siem-gcp-findings` | GCP security findings |
| `siem-dashboards` | Custom dashboards |
| `siem-integrations-config` | Integration configs |
| `siem-module-config` | Module configs |
| `siem-pla-assessments` | Risk assessments |
| `siem-alert-case-links` | Alert-case relationships |
| `siem-suppression-rules` | Suppression rules |

---

## Security

### Built-in Security Features

- JWT authentication with short-lived access tokens
- RBAC with granular role-based permissions
- Brute force protection with IP lockout
- Security headers (HSTS, CSP, X-Frame-Options)
- Per-IP rate limiting
- Input validation and body size limits
- Audit logging for all operations
- Non-root container execution
- TLS support for all service connections

### Reporting Vulnerabilities

If you discover a security vulnerability, please **do not** open a public issue. See our [Security Policy](SECURITY.md) for responsible disclosure instructions.

---

## Deployment

### Docker Compose (Development/Small Production)

The included `docker-compose.yml` deploys the full stack:

```bash
cd sec-app-nazarius-siem-backend
docker compose up -d
```

Services: PostgreSQL, Redis, Elasticsearch/OpenSearch, Backend (Go), Frontend (React/nginx)

### Container Images

| Service | Base Image | Port |
|---------|-----------|------|
| Backend | `golang:1.23-alpine` (build) / `alpine:3.18` (runtime) | 8080 |
| Frontend | `node:18-alpine` (build) / `nginx:1.23-alpine` (runtime) | 80 |

### Production Recommendations

- Use managed services for PostgreSQL (RDS), Redis (ElastiCache), and OpenSearch (AWS OpenSearch Service)
- Deploy behind a reverse proxy (nginx, ALB) with TLS termination
- Use IAM Roles instead of access keys for AWS integration
- Set `GIN_MODE=release` and `DISABLE_MOCK_DATA=true`
- Configure proper `CORS_ORIGINS` for your domain
- Use strong, unique passwords for all services
- Enable TLS for Redis and OpenSearch connections (`*_USE_TLS=true`)
- Set up log rotation and data retention policies
- Monitor the `/api/v1/health` endpoint

### Kubernetes

The backend includes liveness, readiness, and startup probes compatible with Kubernetes health checks. Helm charts are planned for a future release.

---

## Contributing

We welcome contributions from the community! Whether it's bug fixes, new features, documentation, or translations, your help makes Nazarius SIEM better for everyone.

Please read our [Contributing Guide](CONTRIBUTING.md) for:

- Development setup instructions
- Code style guidelines (Go and React)
- Pull request process
- Commit message conventions

### Areas Where Help is Needed

- Azure cloud integration
- Oracle Cloud integration
- Additional log source collectors (Palo Alto, CrowdStrike, SentinelOne)
- Improved MITRE ATT&CK detection rules
- UI/UX improvements and accessibility
- Internationalization (i18n)
- Performance optimization
- Test coverage (unit and integration)
- Helm charts for Kubernetes deployment
- Documentation and tutorials

---

## Roadmap

- [ ] Azure Sentinel / Defender integration
- [ ] Oracle Cloud Infrastructure integration
- [ ] Helm charts for Kubernetes
- [ ] Plugin system for custom collectors
- [ ] GraphQL API layer
- [ ] Real-time WebSocket event streaming
- [ ] SIGMA rule support
- [ ] STIX/TAXII threat intelligence protocol
- [ ] Multi-language UI (i18n)
- [ ] Dark/Light theme toggle
- [ ] Mobile-responsive dashboard

---

## License

This project is licensed under the **Apache License 2.0** -- see the [LICENSE](LICENSE) file for details.

```
Copyright 2025 Nazarius SIEM Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

---

<p align="center">
  Built with security in mind. Made open source for the community.
</p>
