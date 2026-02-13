-- SIEM Platform Initial Data
-- Version: 1.0
-- Date: 2025-11-12

-- ============================================================================
-- DEFAULT ROLES
-- ============================================================================

INSERT INTO roles (id, name, description, permissions) VALUES
(uuid_generate_v4(), 'admin', 'System Administrator', '{
    "users": ["create", "read", "update", "delete"],
    "playbooks": ["create", "read", "update", "delete", "execute"],
    "cases": ["create", "read", "update", "delete", "assign"],
    "alerts": ["create", "read", "update", "delete", "acknowledge"],
    "threat_intel": ["create", "read", "update", "delete"],
    "modules": ["read", "update"],
    "config": ["read", "update"],
    "audit": ["read"]
}'::jsonb),

(uuid_generate_v4(), 'analyst_l3', 'Senior Security Analyst (L3)', '{
    "users": ["read"],
    "playbooks": ["create", "read", "update", "execute"],
    "cases": ["create", "read", "update", "assign"],
    "alerts": ["create", "read", "update", "acknowledge"],
    "threat_intel": ["create", "read", "update"],
    "modules": ["read"],
    "config": ["read"],
    "audit": ["read"]
}'::jsonb),

(uuid_generate_v4(), 'analyst_l2', 'Security Analyst (L2)', '{
    "users": ["read"],
    "playbooks": ["read", "execute"],
    "cases": ["create", "read", "update"],
    "alerts": ["read", "update", "acknowledge"],
    "threat_intel": ["read", "update"],
    "modules": ["read"],
    "config": ["read"],
    "audit": ["read"]
}'::jsonb),

(uuid_generate_v4(), 'analyst_l1', 'Junior Security Analyst (L1)', '{
    "users": ["read"],
    "playbooks": ["read"],
    "cases": ["read", "update"],
    "alerts": ["read", "acknowledge"],
    "threat_intel": ["read"],
    "modules": ["read"],
    "config": [],
    "audit": []
}'::jsonb),

(uuid_generate_v4(), 'viewer', 'Read-Only Viewer', '{
    "users": [],
    "playbooks": ["read"],
    "cases": ["read"],
    "alerts": ["read"],
    "threat_intel": ["read"],
    "modules": ["read"],
    "config": [],
    "audit": []
}'::jsonb);

-- ============================================================================
-- DEFAULT USERS
-- ============================================================================

-- 🔐 DEFAULT ADMIN CREDENTIALS:
-- Username: admin
-- Password: admin
-- 
-- ⚠️  SECURITY WARNING: CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION!
-- This is a development/testing password only.
--
-- Password hash: bcrypt("admin", cost=10)

INSERT INTO users (id, username, email, password_hash, full_name, role, status) VALUES
(uuid_generate_v4(), 'admin', 'admin@siem.local', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'System Administrator', 'admin', 'active');

-- ============================================================================
-- ROLES DISPONÍVEIS
-- ============================================================================
-- Os seguintes roles estão disponíveis para criação de usuários:
--
-- 1. admin    - Acesso total ao sistema
-- 2. analyst  - Pode visualizar e gerenciar alertas e casos (sem restrição de account)
-- 3. banking  - Acesso restrito aos ambientes Banking:
--               - 379334555230 (banking-prd)
--               - 039663229792 (banking-dev)
--               - 334931733882 (banking-hml)
-- 4. viewer   - Apenas visualização
--
-- Para criar um usuário com perfil banking, use:
-- INSERT INTO users (id, username, email, password_hash, full_name, role, status) VALUES
-- (uuid_generate_v4(), 'nome_analista', 'email@empresa.com', '<bcrypt_hash>', 'Nome Completo', 'banking', 'active');

-- ============================================================================
-- DEFAULT MODULES
-- ============================================================================

INSERT INTO modules (id, name, description, category, status, path, icon, badge, tier) VALUES
-- SIEM Base
('dashboard', 'Dashboard Principal', 'Dashboard principal com visão geral do sistema', 'siem', 'active', '/', 'DashboardIcon', NULL, 'free'),
('events', 'Event Monitoring', 'Monitoramento de eventos em tempo real', 'siem', 'active', '/events', 'EventNoteIcon', NULL, 'free'),
('alerts', 'Alerts', 'Gerenciamento de alertas de segurança', 'siem', 'active', '/alerts', 'WarningIcon', NULL, 'free'),
('compliance', 'Compliance', 'Gestão de conformidade regulatória', 'siem', 'active', '/compliance', 'GavelIcon', NULL, 'basic'),
('forensics', 'Forensics', 'Análise forense de incidentes', 'siem', 'active', '/forensics', 'BugReportIcon', NULL, 'premium'),
('dashboard-customizer', 'Dashboard Customizer', 'Personalização de dashboards', 'siem', 'standby', '/dashboard-customizer', 'SettingsIcon', 'NEW', 'basic'),
('ai-analysis', 'AI Analysis', 'Análise com inteligência artificial', 'analytics', 'standby', '/ai-analysis', 'SmartToyIcon', NULL, 'enterprise'),

-- Threat Management
('threat-intelligence', 'Threat Intelligence', 'Inteligência de ameaças e IOCs', 'threat', 'active', '/threat-intelligence', 'TravelExploreIcon', NULL, 'basic'),
('threat-hunting', 'Threat Hunting', 'Caça proativa a ameaças', 'threat', 'active', '/hunting', 'SearchIcon', NULL, 'basic'),
('mitre-attack', 'MITRE ATT&CK', 'Framework MITRE ATT&CK', 'threat', 'active', '/mitre-attack', 'SecurityIcon', NULL, 'basic'),

-- Protection & Compliance
('playbooks', 'Playbooks', 'Playbooks de resposta a incidentes', 'protection', 'active', '/playbooks', 'AssignmentIcon', NULL, 'basic'),
('cases', 'Cases', 'Gerenciamento de casos de segurança', 'protection', 'active', '/cases', 'FolderOpenIcon', NULL, 'basic'),

-- MDR Modules
('mdr-executive', 'Executive Dashboard MDR', 'Dashboard executivo para gestão MDR', 'mdr', 'active', '/mdr-dashboard', 'DashboardIcon', 'NEW', 'premium'),
('automated-response', 'Automated Response', 'Resposta automatizada a incidentes', 'mdr', 'active', '/automated-response', 'AutoFixHighIcon', 'NEW', 'premium'),
('alert-triage', 'Alert Triage', 'Triagem inteligente de alertas', 'mdr', 'active', '/alert-triage', 'PsychologyIcon', 'NEW', 'premium'),
('sla-metrics', 'SLA & Metrics', 'Métricas e SLA de atendimento', 'mdr', 'active', '/sla-metrics', 'SpeedIcon', 'NEW', 'premium'),
('threat-hunting-platform', 'Threat Hunting Platform', 'Plataforma avançada de threat hunting', 'mdr', 'active', '/threat-hunting-platform', 'SearchIcon', 'NEW', 'premium'),
('mdr-forensics', 'Automated Forensics', 'Análise forense automatizada', 'mdr', 'active', '/mdr-forensics', 'BugReportIcon', 'NEW', 'premium'),
('mdr-threat-intel', 'Threat Intel Platform', 'Plataforma de inteligência de ameaças', 'mdr', 'active', '/mdr-threat-intel', 'SecurityIcon', 'NEW', 'premium'),
('mdr-multi-tenancy', 'Multi-Tenancy', 'Gestão multi-tenant', 'mdr', 'active', '/mdr-multi-tenancy', 'BusinessIcon', 'NEW', 'enterprise'),
('advanced-hunting', 'Advanced Hunting', 'Caça avançada a ameaças', 'mdr', 'active', '/advanced-hunting', 'SearchIcon', 'NEW', 'premium'),
('deception', 'Deception Technology', 'Tecnologia de decepção e honeypots', 'mdr', 'active', '/deception', 'ShieldIcon', 'NEW', 'enterprise'),
('continuous-validation', 'Continuous Validation', 'Validação contínua de segurança', 'mdr', 'active', '/continuous-validation', 'SecurityIcon', 'NEW', 'premium'),
('security-awareness', 'Security Awareness', 'Conscientização e treinamento de segurança', 'mdr', 'active', '/security-awareness', 'SchoolIcon', 'NEW', 'basic'),
('advanced-analytics', 'Advanced Analytics', 'Analytics avançado com ML', 'mdr', 'active', '/advanced-analytics', 'PsychologyIcon', 'NEW', 'enterprise'),
('soar', 'SOAR', 'Security Orchestration, Automation and Response', 'mdr', 'active', '/soar', 'AccountTreeIcon', 'NEW', 'enterprise'),
('threat-intel-fusion', 'Threat Intel Fusion', 'Fusão de inteligência de ameaças', 'mdr', 'active', '/threat-intel-fusion', 'LinkIcon', 'NEW', 'premium'),
('cspm', 'CSPM', 'Cloud Security Posture Management', 'mdr', 'active', '/cspm', 'CloudIcon', 'NEW', 'premium'),
('zero-trust', 'Zero Trust', 'Arquitetura Zero Trust', 'mdr', 'active', '/zero-trust', 'VpnLockIcon', 'NEW', 'enterprise'),

-- Settings
('module-manager', 'Module Manager', 'Gerenciamento de ativação/desativação de módulos', 'settings', 'active', '/module-manager', 'PowerSettingsNewIcon', 'NEW', 'free');

-- ============================================================================
-- SYSTEM CONFIGURATION
-- ============================================================================

INSERT INTO system_config (key, value, description, category) VALUES
('jwt.secret', '"change-this-in-production"', 'JWT secret key', 'security'),
('jwt.expiration', '"15m"', 'JWT token expiration time', 'security'),
('jwt.refresh_expiration', '"7d"', 'JWT refresh token expiration time', 'security'),
('session.timeout', '"30m"', 'Session timeout duration', 'security'),
('session.max_concurrent', '5', 'Maximum concurrent sessions per user', 'security'),
('auth.max_login_attempts', '5', 'Maximum failed login attempts before lockout', 'security'),
('auth.lockout_duration', '"15m"', 'Account lockout duration after max failed attempts', 'security'),
('auth.password_min_length', '8', 'Minimum password length', 'security'),
('auth.password_require_uppercase', 'true', 'Require uppercase in password', 'security'),
('auth.password_require_lowercase', 'true', 'Require lowercase in password', 'security'),
('auth.password_require_number', 'true', 'Require number in password', 'security'),
('auth.password_require_special', 'true', 'Require special character in password', 'security'),
('rate_limit.enabled', 'true', 'Enable rate limiting', 'security'),
('rate_limit.requests_per_minute', '60', 'Maximum requests per minute per IP', 'security'),
('data_retention.alerts_days', '90', 'Alert retention period in days', 'data'),
('data_retention.audit_log_days', '365', 'Audit log retention period in days', 'data'),
('data_retention.cases_days', '730', 'Case retention period in days (2 years)', 'data'),
('notifications.email_enabled', 'false', 'Enable email notifications', 'notifications'),
('notifications.slack_enabled', 'false', 'Enable Slack notifications', 'notifications'),
('notifications.webhook_enabled', 'false', 'Enable webhook notifications', 'notifications');

-- ============================================================================
-- SAMPLE PLAYBOOKS (for testing)
-- ============================================================================

INSERT INTO playbooks (id, name, description, category, severity, status, actions, tags, created_by) VALUES
(uuid_generate_v4(), 'Block Malicious IP', 'Automatically block IPs identified as malicious', 'Network Security', 'high', 'active', '[
    {"type": "block_ip", "params": {"ip": "{{alert.source_ip}}", "duration": 3600}},
    {"type": "create_ticket", "params": {"title": "IP Blocked: {{alert.source_ip}}", "priority": "high"}},
    {"type": "send_notification", "params": {"channel": "security-alerts", "message": "Blocked malicious IP: {{alert.source_ip}}"}}
]'::jsonb, ARRAY['network', 'automated', 'blocking'], (SELECT id FROM users WHERE username = 'admin')),

(uuid_generate_v4(), 'Quarantine Malware', 'Isolate and quarantine detected malware', 'Endpoint Security', 'critical', 'active', '[
    {"type": "isolate_host", "params": {"host": "{{alert.hostname}}"}},
    {"type": "quarantine_file", "params": {"file_path": "{{alert.file_path}}", "hash": "{{alert.file_hash}}"}},
    {"type": "create_case", "params": {"title": "Malware Detected: {{alert.hostname}}", "severity": "critical"}},
    {"type": "send_notification", "params": {"channel": "security-alerts", "message": "Malware quarantined on {{alert.hostname}}"}}
]'::jsonb, ARRAY['malware', 'endpoint', 'quarantine'], (SELECT id FROM users WHERE username = 'admin')),

(uuid_generate_v4(), 'Disable Compromised Account', 'Disable user account showing signs of compromise', 'Identity & Access', 'high', 'active', '[
    {"type": "disable_user", "params": {"username": "{{alert.username}}"}},
    {"type": "revoke_sessions", "params": {"username": "{{alert.username}}"}},
    {"type": "create_case", "params": {"title": "Compromised Account: {{alert.username}}", "severity": "high"}},
    {"type": "send_notification", "params": {"channel": "security-alerts", "message": "Account disabled: {{alert.username}}"}}
]'::jsonb, ARRAY['identity', 'account', 'compromise'], (SELECT id FROM users WHERE username = 'admin'));

-- ============================================================================
-- SAMPLE THREAT INDICATORS (for testing)
-- ============================================================================

INSERT INTO threat_indicators (type, value, description, severity, confidence, tags, source) VALUES
('ip', '192.0.2.1', 'Known C2 server', 'critical', 95, ARRAY['c2', 'malware', 'botnet'], 'Internal Research'),
('domain', 'evil.example.com', 'Phishing domain', 'high', 90, ARRAY['phishing', 'credential-theft'], 'Threat Feed'),
('hash', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Ransomware sample', 'critical', 98, ARRAY['ransomware', 'malware'], 'VirusTotal'),
('email', 'phishing@example.com', 'Phishing sender', 'medium', 85, ARRAY['phishing', 'spam'], 'User Report'),
('url', 'http://malicious.example.com/payload.exe', 'Malware distribution', 'high', 92, ARRAY['malware', 'exploit'], 'Sandbox Analysis');

-- ============================================================================
-- GRANT PERMISSIONS
-- ============================================================================

-- Grant necessary permissions to siem_user (if needed for specific operations)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO siem_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO siem_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO siem_user;

