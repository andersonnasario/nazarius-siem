# Nazarius SIEM

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![React](https://img.shields.io/badge/React-18+-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-2.x-005EB8?logo=opensearch&logoColor=white)](https://opensearch.org/)

An open-source, enterprise-grade **Security Information and Event Management (SIEM)** platform built with Go and React. Nazarius SIEM provides real-time threat detection, cloud security posture management (CSPM), user behavior analytics (UEBA), and security orchestration (SOAR) in a single unified platform.

---

## Architecture

```
                          +------------------+
                          |   React Frontend |
                          |    (Port 3000)   |
                          +--------+---------+
                                   |
                                   | REST API
                                   v
                          +------------------+
                          |   Go Backend     |
                          |  (Gin - Port 8080)
                          +--------+---------+
                                   |
                    +--------------+--------------+
                    |              |               |
              +-----+----+  +-----+-----+  +-----+-----+
              | OpenSearch|  | PostgreSQL |  |   Redis   |
              | (Events)  |  |  (Users)   |  |  (Cache)  |
              +-----------+  +-----------+  +-----------+
                    |
        +-----------+-----------+
        |           |           |
   +----+---+  +---+----+  +---+----+
   |  AWS   |  |  GCP   |  | 3rd    |
   |Services|  |Services|  | Party  |
   +--------+  +--------+  +--------+
   CloudTrail   SCC         Cloudflare
   GuardDuty    Asset Inv.  JumpCloud
   Inspector    Audit Logs  VirusTotal
   SecurityHub              AbuseIPDB
   Config
```

## Features

### Core SIEM
- **Real-time Event Collection** -- Ingest and normalize security events from multiple sources
- **Alert Management** -- Automated alert generation with severity classification and case management
- **Dashboard** -- Unified security operations dashboard with real-time metrics
- **Threat Intelligence** -- Integrated feeds from VirusTotal, AbuseIPDB, and NVD

### Cloud Security Posture Management (CSPM)
- **AWS Integration** -- Security Hub, GuardDuty, Inspector, CloudTrail, AWS Config
- **GCP Integration** -- Security Command Center, Cloud Asset Inventory, Cloud Audit Logs
- **Multi-Account Support** -- STS-based cross-account credential management
- **Compliance** -- PCI-DSS dashboard, CIS benchmarks, drift detection
- **Auto-Remediation** -- Rule-based automated remediation with approval workflows

### User & Entity Behavior Analytics (UEBA)
- **Behavioral Baselines** -- Machine learning-based anomaly detection
- **Risk Scoring** -- Dynamic risk scores for users and entities
- **Insider Threat Detection** -- Detect unusual access patterns and data exfiltration

### Security Orchestration (SOAR)
- **Playbooks** -- Automated response playbooks for common incidents
- **Case Management** -- Full incident lifecycle management with assignment and tracking
- **Integration Actions** -- Automated actions via AWS Lambda, webhooks, and more

### Additional Modules
- **Zero Trust Architecture** -- Identity-based access controls and micro-segmentation monitoring
- **Threat Hunting** -- Advanced hunt queries with MITRE ATT&CK mapping
- **Security Awareness** -- Training campaign management and phishing simulations
- **DLP (Data Loss Prevention)** -- Pattern-based sensitive data detection
- **Vulnerability Management** -- CVE tracking with NVD integration
- **Forensics** -- Evidence collection and chain-of-custody tracking

### Integrations
- **Cloudflare WAF** -- Real-time WAF event collection and analysis with IP reputation
- **JumpCloud** -- Directory event ingestion via OAuth2 Service Account
- **AWS Services** -- Full integration with 6+ AWS security services
- **GCP Services** -- Security Command Center, Asset Inventory, Audit Logs

## Prerequisites

- **Go** 1.21 or later
- **Node.js** 18 or later
- **OpenSearch** 2.x (or Elasticsearch 8.x)
- **PostgreSQL** 15+
- **Redis** 7+
- **Docker & Docker Compose** (optional, for containerized deployment)

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/<your-org>/nazarius-siem.git
cd nazarius-siem
```

### 2. Configure environment

```bash
# Backend
cp sec-app-nazarius-siem-backend/.env.example sec-app-nazarius-siem-backend/.env
# Edit .env with your credentials (database passwords, JWT secret, API keys)

# Frontend (optional)
cp sec-app-nazarius-siem-frontend/.env.example sec-app-nazarius-siem-frontend/.env
```

### 3. Start with Docker Compose

```bash
cd sec-app-nazarius-siem-backend
docker compose up -d
```

This starts PostgreSQL, Redis, OpenSearch, the Go backend, and the React frontend.

### 4. Start manually (development)

**Backend:**

```bash
cd sec-app-nazarius-siem-backend
go mod download
go run ./rest/
```

**Frontend:**

```bash
cd sec-app-nazarius-siem-frontend
npm install
npm start
```

### 5. Access the application

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8080/api/v1
- **Health Check:** http://localhost:8080/api/v1/health

## Project Structure

```
nazarius-siem/
├── sec-app-nazarius-siem-backend/     # Go backend (Gin framework)
│   ├── rest/                          # All Go source files
│   │   ├── main.go                    # Entry point, routes, server init
│   │   ├── cspm.go                    # CSPM core structs and handlers
│   │   ├── cspm_gcp.go               # GCP Security integration
│   │   ├── cspm_aws_stubs.go         # AWS CSPM handlers
│   │   ├── aws_*.go                   # AWS service collectors
│   │   ├── cloudflare_waf_collector.go
│   │   ├── jumpcloud_collector.go
│   │   ├── ueba*.go                   # UEBA module
│   │   ├── soar*.go                   # SOAR module
│   │   └── ...                        # 100+ Go files
│   ├── docker-compose.yml             # Full stack deployment
│   ├── go.mod / go.sum                # Go dependencies
│   └── .env.example                   # Environment template
│
├── sec-app-nazarius-siem-frontend/    # React frontend (Material-UI)
│   ├── src/
│   │   ├── pages/                     # 70+ page components
│   │   ├── components/                # Shared components (Layout, etc.)
│   │   ├── services/api.js            # API client definitions
│   │   └── App.js                     # Routes and lazy loading
│   ├── package.json
│   └── .env.example                   # Frontend env template
│
├── docs/                              # Documentation
├── LICENSE                            # Apache 2.0
├── CONTRIBUTING.md                    # Contribution guide
├── CODE_OF_CONDUCT.md                 # Community standards
├── SECURITY.md                        # Vulnerability reporting
└── README.md                          # This file
```

## Configuration

All configuration is done via environment variables. See the `.env.example` files for a complete list:

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_PASSWORD` | PostgreSQL password | *Required* |
| `REDIS_PASSWORD` | Redis password | *Required* |
| `JWT_SECRET` | JWT signing secret (min 32 chars) | *Required* |
| `ELASTICSEARCH_URL` | OpenSearch/Elasticsearch URL | `http://localhost:9200` |
| `USE_REAL_AWS_DATA` | Enable real AWS data collection | `false` |
| `DISABLE_MOCK_DATA` | Disable demo/mock data | `false` |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token | *(optional)* |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP service account JSON | *(optional)* |
| `NVD_API_KEY` | NVD API key for CVE sync | *(optional)* |

See [`sec-app-nazarius-siem-backend/.env.example`](sec-app-nazarius-siem-backend/.env.example) for the full list.

## Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) for details on:

- How to submit issues and pull requests
- Code style and conventions
- Development workflow
- Review process

## Security

If you discover a security vulnerability, please **do not** open a public issue. Instead, follow our [Security Policy](SECURITY.md) for responsible disclosure.

## License

This project is licensed under the Apache License 2.0 -- see the [LICENSE](LICENSE) file for details.

```
Copyright 2025 Nazarius SIEM Contributors

Licensed under the Apache License, Version 2.0
```
