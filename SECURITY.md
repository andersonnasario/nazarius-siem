# Security Policy

## Reporting a Vulnerability

The Nazarius SIEM team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

1. **Email**: Send a detailed report to **[INSERT SECURITY EMAIL]**
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability and determine its severity within 7 days
- **Fix**: We aim to release a fix within 30 days for critical vulnerabilities
- **Disclosure**: We will coordinate with you on public disclosure timing

### Scope

The following are in scope for security reports:

- Authentication and authorization bypasses
- SQL injection, XSS, CSRF, and other web vulnerabilities
- Sensitive data exposure (credentials, tokens, PII)
- Remote code execution
- Privilege escalation
- Denial of service (when caused by a specific vulnerability)

The following are **out of scope**:

- Issues in third-party dependencies (report to the upstream project)
- Social engineering attacks
- Physical security issues
- Denial of service through brute force or resource exhaustion

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| Older   | Best effort |

## Security Best Practices for Deployment

When deploying Nazarius SIEM in production:

1. **Never use default passwords** -- generate strong passwords for PostgreSQL, Redis, and JWT secrets
2. **Use TLS** -- enable HTTPS for the frontend and API
3. **Restrict network access** -- use firewalls to limit access to management ports
4. **Use IAM Roles** -- for AWS/GCP integrations, prefer IAM roles over access keys
5. **Rotate credentials** -- regularly rotate API keys and passwords
6. **Enable audit logging** -- monitor access to the SIEM platform itself
7. **Keep dependencies updated** -- regularly run `go mod tidy` and `npm audit`

## Acknowledgments

We thank the following individuals for responsibly reporting security vulnerabilities:

*(This list will be updated as vulnerabilities are reported and fixed.)*
