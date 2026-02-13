-- SIEM Platform Initial Data - PRODUCTION VERSION
-- Version: 1.0
-- Date: 2025-11-28
-- WARNING: This file contains the PRODUCTION admin password!

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
-- DEFAULT ADMIN USER
-- ============================================================================

-- 🔐 PRODUCTION ADMIN CREDENTIALS:
-- Username: admin
-- Password: SiemAdmin2025!SecurePass
-- 
-- ⚠️  IMPORTANT: CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!
--
-- Password hash generated with bcrypt (cost 10):
-- bcrypt.GenerateFromPassword([]byte("SiemAdmin2025!SecurePass"), 10)

INSERT INTO users (id, username, email, password_hash, full_name, role, status) VALUES
(uuid_generate_v4(), 
 'admin', 
 'admin@siem.local', 
 '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 
 'System Administrator', 
 'admin', 
 'active');

-- ============================================================================
-- PERFIS/ROLES DISPONÍVEIS
-- ============================================================================
-- Os seguintes perfis estão disponíveis para criação de usuários:
--
-- 1. admin    - Acesso total ao sistema
-- 2. analyst  - Pode visualizar e gerenciar alertas e casos (sem restrição de account)
-- 3. banking  - Acesso restrito aos ambientes Banking:
--               - 379334555230 (banking-prd)
--               - 039663229792 (banking-dev)
--               - 334931733882 (banking-hml)
-- 4. viewer   - Apenas visualização
--
-- 📝 Para criar um analista com perfil banking:
-- 
-- 1. Gere o hash bcrypt da senha (custo 10):
--    go run -e 'import "golang.org/x/crypto/bcrypt"; h,_:=bcrypt.GenerateFromPassword([]byte("SENHA"),10); println(string(h))'
--
-- 2. Execute o INSERT:
--    INSERT INTO users (id, username, email, password_hash, full_name, role, status) VALUES
--    (uuid_generate_v4(), 'nome_analista', 'email@empresa.com', '<bcrypt_hash>', 'Nome Completo', 'banking', 'active');

-- ============================================================================
-- DEFAULT MODULES
-- ============================================================================

INSERT INTO modules (id, name, description, category, status, path, icon, badge, tier) VALUES
-- SIEM Base (POC PCI-DSS)
('dashboard', 'Dashboard Principal', 'Dashboard principal com visão geral do sistema', 'siem', 'active', '/', 'DashboardIcon', NULL, 'free'),
('events', 'Event Monitoring', 'Monitoramento de eventos em tempo real', 'siem', 'active', '/events', 'EventNoteIcon', NULL, 'free'),
('alerts', 'Alerts', 'Gerenciamento de alertas de segurança', 'siem', 'active', '/alerts', 'WarningIcon', NULL, 'free'),
('cases', 'Case Management', 'Gerenciamento de casos de segurança', 'siem', 'active', '/cases', 'FolderIcon', NULL, 'free'),

-- SOAR
('playbooks', 'Playbooks SOAR', 'Automação de resposta a incidentes', 'soar', 'active', '/playbooks', 'PlayArrowIcon', NULL, 'basic'),
('automated-response', 'Automated Response', 'Respostas automatizadas a ameaças', 'mdr', 'active', '/automated-response', 'SmartToyIcon', NULL, 'premium'),

-- Compliance (PCI-DSS FOCUS)
('cspm', 'Cloud Security Posture', 'Gestão de postura de segurança na nuvem', 'compliance', 'active', '/cspm', 'CloudIcon', 'HOT', 'basic'),
('pci-dss', 'PCI-DSS Compliance', 'Conformidade PCI-DSS', 'compliance', 'active', '/pci-dss', 'PaymentIcon', 'HOT', 'basic'),
('compliance', 'Compliance Frameworks', 'Gestão de conformidade regulatória', 'compliance', 'active', '/compliance', 'GavelIcon', NULL, 'basic'),
('aws-connections', 'AWS Connections', 'Gerenciamento de conexões AWS', 'integrations', 'active', '/aws-connections', 'CloudUploadIcon', NULL, 'basic'),

-- Threat Intelligence
('threat-intelligence', 'Threat Intelligence', 'Inteligência de ameaças', 'threat_intel', 'active', '/threat-intelligence', 'SecurityIcon', NULL, 'basic'),
('threat-hunting-platform', 'Threat Hunting', 'Plataforma de caça a ameaças', 'threat_intel', 'active', '/threat-hunting-platform', 'SearchIcon', NULL, 'premium'),
('mitre-attack', 'MITRE ATT&CK', 'Framework MITRE ATT&CK', 'threat_intel', 'active', '/mitre-attack', 'AccountTreeIcon', NULL, 'basic'),

-- Advanced Features
('ueba', 'User Behavior Analytics', 'Análise de comportamento de usuários', 'analytics', 'active', '/ueba', 'PersonSearchIcon', NULL, 'premium'),
('executive', 'Executive Dashboard', 'Dashboard executivo', 'siem', 'active', '/executive', 'BusinessIcon', NULL, 'premium'),
('notifications', 'Notifications', 'Central de notificações', 'siem', 'active', '/notifications', 'NotificationsIcon', NULL, 'free'),

-- Settings & Admin
('users', 'User Management', 'Gerenciamento de usuários', 'admin', 'active', '/users', 'PeopleIcon', NULL, 'free'),
('integrations', 'Integrations', 'Gerenciamento de integrações', 'integrations', 'active', '/integrations', 'ExtensionIcon', NULL, 'basic'),
('modules', 'Module Manager', 'Gerenciador de módulos', 'admin', 'active', '/modules', 'AppsIcon', NULL, 'free'),
('settings', 'Settings', 'Configurações gerais', 'admin', 'active', '/settings', 'SettingsIcon', NULL, 'free'),

-- Monitoring
('monitoring', 'System Monitoring', 'Monitoramento do sistema', 'admin', 'active', '/monitoring', 'MonitorHeartIcon', NULL, 'free')

ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- INITIAL NOTIFICATION CHANNELS (for alerts)
-- ============================================================================

INSERT INTO notification_channels (id, name, type, config, enabled) VALUES
(uuid_generate_v4(), 'Email Alerts', 'email', '{"smtp_host": "smtp.example.com", "smtp_port": 587, "from": "siem-alerts@empresa.com"}'::jsonb, false),
(uuid_generate_v4(), 'Slack Security', 'slack', '{"webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"}'::jsonb, false),
(uuid_generate_v4(), 'Teams Channel', 'teams', '{"webhook_url": "https://outlook.office.com/webhook/YOUR/WEBHOOK/URL"}'::jsonb, false)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- AWS REGIONS (for CSPM)
-- ============================================================================

INSERT INTO aws_regions (code, name, enabled) VALUES
('us-east-1', 'US East (N. Virginia)', true),
('us-east-2', 'US East (Ohio)', true),
('us-west-1', 'US West (N. California)', false),
('us-west-2', 'US West (Oregon)', true),
('sa-east-1', 'South America (São Paulo)', true),
('eu-west-1', 'Europe (Ireland)', false),
('eu-central-1', 'Europe (Frankfurt)', false),
('ap-southeast-1', 'Asia Pacific (Singapore)', false),
('ap-northeast-1', 'Asia Pacific (Tokyo)', false)
ON CONFLICT (code) DO NOTHING;

-- ============================================================================
-- AUDIT LOG - Track database initialization
-- ============================================================================

INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, details, ip_address, user_agent) VALUES
(uuid_generate_v4(), 
 (SELECT id FROM users WHERE username = 'admin'), 
 'system.initialize', 
 'database', 
 'init', 
 '{"action": "database_initialized", "version": "1.0", "environment": "production"}'::jsonb,
 '127.0.0.1',
 'PostgreSQL Init Script');

