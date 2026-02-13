# Contributing to Nazarius SIEM

Thank you for your interest in contributing to Nazarius SIEM! This document provides guidelines and information about contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/nazarius-siem.git
   cd nazarius-siem
   ```
3. **Create a branch** for your work:
   ```bash
   git checkout -b feature/my-feature
   ```
4. **Set up** the development environment (see below)

## Development Setup

### Prerequisites

- Go 1.21+
- Node.js 18+
- Docker & Docker Compose (for services)
- OpenSearch 2.x, PostgreSQL 15+, Redis 7+

### Backend

```bash
cd sec-app-nazarius-siem-backend
cp .env.example .env
# Edit .env with your local settings

go mod download
go run ./rest/
```

### Frontend

```bash
cd sec-app-nazarius-siem-frontend
cp .env.example .env
npm install
npm start
```

### Running Tests

```bash
# Backend
cd sec-app-nazarius-siem-backend
go test ./...

# Frontend
cd sec-app-nazarius-siem-frontend
npm test
```

## How to Contribute

### Reporting Bugs

- Use the [Bug Report](https://github.com/<your-org>/nazarius-siem/issues/new?template=bug_report.md) issue template
- Include steps to reproduce, expected behavior, and actual behavior
- Include environment details (OS, Go version, Node version)

### Suggesting Features

- Use the [Feature Request](https://github.com/<your-org>/nazarius-siem/issues/new?template=feature_request.md) issue template
- Describe the problem your feature would solve
- Propose a solution if you have one

### Code Contributions

1. Check existing issues for similar work
2. For major changes, open an issue first to discuss the approach
3. Write clean, well-documented code
4. Include tests where applicable
5. Update documentation if needed

### Areas Where Help is Needed

- New cloud provider integrations (Azure, Oracle Cloud)
- Additional log source collectors
- Improved detection rules and MITRE ATT&CK coverage
- UI/UX improvements
- Documentation and tutorials
- Translations (the UI currently mixes Portuguese and English)
- Performance optimizations
- Test coverage

## Pull Request Process

1. **Update your branch** with the latest changes from `main`:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Ensure your code builds** without errors:
   ```bash
   # Backend
   cd sec-app-nazarius-siem-backend && go build ./...

   # Frontend
   cd sec-app-nazarius-siem-frontend && npm run build
   ```

3. **Submit your PR** with:
   - A clear title describing the change
   - A description of what was changed and why
   - Reference to any related issues (e.g., "Fixes #123")
   - Screenshots for UI changes

4. **Review process:**
   - At least one maintainer must approve the PR
   - CI checks must pass
   - No merge conflicts with `main`

## Code Style

### Go (Backend)

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use meaningful variable and function names
- Add comments for exported functions
- Handle errors explicitly -- do not ignore them
- Use structured logging with `log.Printf`

### JavaScript/React (Frontend)

- Use functional components with hooks
- Follow Material-UI patterns used in existing code
- Use `const` by default, `let` when reassignment is needed
- Prefer `async/await` over raw Promises

### General

- Keep functions focused and short
- No hardcoded secrets or credentials
- Use environment variables for configuration
- Write self-documenting code; add comments for complex logic

## Commit Messages

Follow the conventional format:

```
type: short description

Longer description if needed.

Fixes #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring (no behavior change)
- `test`: Adding or updating tests
- `chore`: Build, CI, or tooling changes

Examples:
```
feat: add Azure Sentinel integration
fix: correct pagination in CloudTrail events handler
docs: update GCP setup instructions in README
refactor: extract common OpenSearch query builder
```

## Reporting Issues

- **Bugs**: Use the bug report template
- **Features**: Use the feature request template
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) -- do NOT open public issues for security problems
- **Questions**: Use GitHub Discussions

## License

By contributing to Nazarius SIEM, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
