import axios from 'axios';

// Get API URL from runtime config (set by env-config.js) or fallback to localhost
const getAPIBaseURL = () => {
  // Try to get from window.__ENV__ (runtime config)
  if (window.__ENV__ && window.__ENV__.REACT_APP_API_URL) {
    return window.__ENV__.REACT_APP_API_URL;
  }
  
  // Fallback for development (when running with npm start)
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // Final fallback
  return 'http://localhost:8080/api/v1';
};

const API_BASE_URL = getAPIBaseURL();

console.log('🔗 API Base URL:', API_BASE_URL);

// Custom param serializer for arrays - Go/Gin expects "key=val1&key=val2" not "key[]=val1"
const paramsSerializer = (params) => {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      value.forEach(v => searchParams.append(key, v));
    } else if (value !== undefined && value !== null && value !== '') {
      searchParams.append(key, value);
    }
  });
  return searchParams.toString();
};

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  paramsSerializer,
});

// Interceptor para adicionar token de autenticação em todas as requisições
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Interceptor para tratar erros
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      // Tentar renovar o token
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        try {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refreshToken
          });
          
          const { access_token } = response.data;
          localStorage.setItem('access_token', access_token);
          
          // Repetir a requisição original com novo token
          originalRequest.headers['Authorization'] = `Bearer ${access_token}`;
          return api(originalRequest);
        } catch (refreshError) {
          // Refresh falhou - limpar tokens e redirecionar
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          window.location.href = '/login';
          return Promise.reject(refreshError);
        }
      } else {
        // Sem refresh token - redirecionar para login
        localStorage.removeItem('access_token');
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// ============================================================================
// PLAYBOOKS
// ============================================================================

export const playbooksAPI = {
  // Listar todos os playbooks
  list: () => api.get('/playbooks/'),
  
  // Obter detalhes de um playbook
  get: (id) => api.get(`/playbooks/${id}`),
  
  // Criar novo playbook
  create: (playbook) => api.post('/playbooks/', playbook),
  
  // Atualizar playbook
  update: (id, updates) => api.put(`/playbooks/${id}`, updates),
  
  // Deletar playbook
  delete: (id) => api.delete(`/playbooks/${id}`),
  
  // Executar playbook
  execute: (id, triggerData = {}) => api.post(`/playbooks/${id}/execute`, triggerData),
  
  // Obter estatísticas de um playbook
  getStatistics: (id) => api.get(`/playbooks/${id}/statistics`),
  
  // Listar execuções
  listExecutions: (playbookId) => api.get('/playbooks/executions', {
    params: { playbook_id: playbookId }
  }),
  
  // Obter detalhes de uma execução
  getExecution: (id) => api.get(`/playbooks/executions/${id}`),
};

// ============================================================================
// EVENTS
// ============================================================================

export const eventsAPI = {
  // Buscar eventos
  search: (params) => api.get('/events/search', { params }),
  
  // Agregar eventos
  aggregate: (params) => api.get('/events/aggregate', { params }),
  
  // Obter estatísticas de eventos
  getStatistics: (params) => api.get('/events/statistics', { params }),
  
  // Exportar eventos
  export: (params) => api.get('/events/export', { 
    params,
    responseType: 'blob' // Para download de arquivo
  }),
  
  // Obter evento específico
  get: (id) => api.get(`/events/${id}`),
};

// ============================================================================
// ALERTS
// ============================================================================

export const alertsAPI = {
  // Listar alertas
  list: (params) => api.get('/alerts/', { params }),
  
  // Obter estatísticas de alertas
  getStatistics: () => api.get('/alerts/statistics'),
  
  // Exportar alertas
  export: (params) => api.get('/alerts/export', { 
    params,
    responseType: 'blob' // Para download de arquivo
  }),
  
  // Criar alerta
  create: (alert) => api.post('/alerts/', alert),
  
  // Obter alerta
  get: (id) => api.get(`/alerts/${id}`),
  
  // Atualizar alerta
  update: (id, updates) => api.put(`/alerts/${id}`, updates),
  
  // Deletar alerta
  delete: (id) => api.delete(`/alerts/${id}`),
  
  // Alertas em análise (vinculados a casos)
  getInAnalysis: () => api.get('/alerts/in-analysis'),
};

// ============================================================================
// SUPPRESSION RULES (False Positives)
// ============================================================================

export const suppressionAPI = {
  // Listar regras de supressão
  listRules: (activeOnly = false) => api.get('/suppression/rules', { 
    params: activeOnly ? { active: 'true' } : {} 
  }),
  
  // Criar regra de supressão manual
  createRule: (rule) => api.post('/suppression/rules', rule),
  
  // Ativar/Desativar regra
  toggleRule: (id, active) => api.put(`/suppression/rules/${id}`, { active }),
  
  // Deletar regra
  deleteRule: (id) => api.delete(`/suppression/rules/${id}`),
  
  // Marcar alerta/evento como falso positivo
  markFalsePositive: (data) => api.post('/suppression/false-positive', data),
  
  // Verificar se alerta deve ser suprimido
  checkSuppression: (alertData) => api.post('/suppression/check', alertData),
};

// ============================================================================
// DASHBOARDS
// ============================================================================

export const dashboardsAPI = {
  // Listar dashboards
  list: () => api.get('/dashboards/'),
  
  // Criar dashboard
  create: (dashboard) => api.post('/dashboards/', dashboard),
  
  // Obter dashboard
  get: (id) => api.get(`/dashboards/${id}`),
  
  // Atualizar dashboard
  update: (id, updates) => api.put(`/dashboards/${id}`, updates),
  
  // Deletar dashboard
  delete: (id) => api.delete(`/dashboards/${id}`),
};

// ============================================================================
// ANALYSIS
// ============================================================================

export const analysisAPI = {
  // Obter estatísticas
  getStatistics: () => api.get('/analysis/statistics'),
  
  // Obter trends
  getTrends: () => api.get('/analysis/trends'),
  
  // Obter anomalias
  getAnomalies: () => api.get('/analysis/anomalies'),
};

// ============================================================================
// AUTH
// ============================================================================

export const authAPI = {
  // Login
  login: (username, password) => api.post('/auth/login', { username, password }),
  
  // Refresh token
  refresh: (refreshToken) => api.post('/auth/refresh', { refresh_token: refreshToken }),
  
  // Logout
  logout: (refreshToken) => api.post('/auth/logout', { refresh_token: refreshToken }),
  
  // Get current user
  getMe: () => api.get('/auth/me'),
  
  // Change password
  changePassword: (oldPassword, newPassword) => api.post('/auth/change-password', { 
    old_password: oldPassword, 
    new_password: newPassword 
  }),
};

// ============================================================================
// CASES (Case Management)
// ============================================================================

export const casesAPI = {
  // Listar casos
  list: (params) => api.get('/cases/', { params }),
  
  // Criar caso
  create: (caseData) => api.post('/cases/', caseData),
  
  // Criar caso a partir de um alerta
  createFromAlert: (alertId, data = {}) => api.post(`/alerts/${alertId}/create-case`, {
    title: data.title || '',
    description: data.description || '',
    priority: data.priority || 'medium',
    assign_to: data.assignTo || '',
  }),
  
  // Atualizar status de um alerta
  updateStatus: (alertId, status, reason = '', comment = '') => api.put(`/alerts/${alertId}/status`, {
    status,
    reason,
    comment,
  }),
  
  // Criar caso a partir de um evento
  createFromEvent: (eventId, data = {}) => api.post('/cases/from-event', {
    event_id: eventId,
    title: data.title || '',
    description: data.description || '',
    priority: data.priority || 'medium',
    assign_to: data.assignTo || '',
  }),
  
  // Obter caso específico
  get: (id) => api.get(`/cases/${id}`),
  
  // Atualizar caso
  update: (id, updates) => api.put(`/cases/${id}`, updates),
  
  // Obter atividades/timeline do caso
  getActivities: (id) => api.get(`/cases/${id}/activities`),
  
  // Adicionar comentário
  addComment: (id, content) => api.post(`/cases/${id}/comments`, { content }),
  
  // Obter estatísticas
  getStatistics: () => api.get('/cases/statistics'),
  
  // Exportar casos
  export: (params) => api.get('/cases/export', { 
    params,
    responseType: 'blob' // Para download de arquivo
  }),

  // Política de casos (SLA/Checklist)
  getPolicy: () => api.get('/cases/policy'),
  updatePolicy: (policy) => api.put('/cases/policy', policy),

  // Relatório do caso (markdown/json)
  getReport: (id, format = 'markdown') => api.get(`/cases/${id}/report`, {
    params: { format },
    responseType: format === 'markdown' ? 'blob' : 'json',
  }),
  
  // Deletar caso
  delete: (id) => api.delete(`/cases/${id}`),
  
  // === SINCRONIZAÇÃO DE STATUS (CASO <-> ALERTAS/EVENTOS) ===
  
  // Atualizar status com propagação para alertas/eventos vinculados
  updateStatusWithPropagation: (id, status, propagateToAlerts = true, propagateToEvents = true, comment = '') => 
    api.post(`/cases/${id}/status-propagate`, { 
      status, 
      propagate_to_alerts: propagateToAlerts,
      propagate_to_events: propagateToEvents,
      comment
    }),
  
  // Obter alertas vinculados ao caso
  getLinkedAlerts: (id) => api.get(`/cases/${id}/linked-alerts`),

  // Obter eventos vinculados ao caso
  getLinkedEvents: (id) => api.get(`/cases/${id}/linked-events`),
  
  // Vincular alerta ao caso
  linkAlert: (caseId, alertId) => api.post(`/cases/${caseId}/link-alert`, { alert_id: alertId, case_id: caseId }),
  
  // Vincular evento ao caso
  linkEvent: (caseId, eventId) => api.post(`/cases/${caseId}/link-event`, { event_id: eventId, case_id: caseId }),

  // === CHECKLIST ===
  getChecklist: (id) => api.get(`/cases/${id}/checklist`),
  addChecklistItem: (id, text) => api.post(`/cases/${id}/checklist`, { text }),
  updateChecklistItem: (id, itemId, data) => api.put(`/cases/${id}/checklist/${itemId}`, data),
  deleteChecklistItem: (id, itemId) => api.delete(`/cases/${id}/checklist/${itemId}`),

  // === PLAYBOOKS ===
  getPlaybooks: (id) => api.get(`/cases/${id}/playbooks`),
  addPlaybook: (id, playbookId) => api.post(`/cases/${id}/playbooks`, { playbook_id: playbookId }),
  deletePlaybook: (id, playbookId) => api.delete(`/cases/${id}/playbooks/${playbookId}`),
  executePlaybook: (id, playbookId, triggerData = {}) =>
    api.post(`/cases/${id}/playbooks/${playbookId}/execute`, triggerData),
};

// ============================================================================
// MITRE ATT&CK
// ============================================================================

export const mitreAPI = {
  // Obter todas as táticas
  getTactics: () => api.get('/mitre/tactics'),
  
  // Obter técnicas (com filtros opcionais)
  getTechniques: (params) => api.get('/mitre/techniques', { params }),
  
  // Obter análise de cobertura
  getCoverage: () => api.get('/mitre/coverage'),
  
  // Obter timeline de ataques
  getTimeline: (hours = 24) => api.get('/mitre/timeline', { params: { hours } }),
  
  // Obter detecções recentes
  getDetections: (params) => api.get('/mitre/detections', { params }),
};

// API de Threat Intelligence
export const threatIntelAPI = {
  // IOCs
  getIOCs: (params) => api.get('/threat-intelligence/iocs', { params }),
  getIOC: (id) => api.get(`/threat-intelligence/iocs/${id}`),
  createIOC: (ioc) => api.post('/threat-intelligence/iocs', ioc),
  updateIOC: (id, updates) => api.put(`/threat-intelligence/iocs/${id}`, updates),
  deleteIOC: (id) => api.delete(`/threat-intelligence/iocs/${id}`),

  // Eventos relacionados a um IOC
  getIOCRelatedEvents: (value, limit = 50) => api.get('/threat-intelligence/iocs/related-events', { params: { value, limit } }),

  // Enrichment
  enrichIP: (ip) => api.get(`/threat-intelligence/enrich/ip/${ip}`),
  checkIP: (ip) => api.get('/threat-intelligence/check/ip', { params: { ip } }),

  // Feeds
  getFeeds: () => api.get('/threat-intelligence/feeds'),

  // Stats
  getStats: () => api.get('/threat-intelligence/stats'),
};

// API de CVE Database - Banco de Vulnerabilidades
export const cveAPI = {
  // Listar CVEs com filtros e paginação
  list: (params) => api.get('/cves/', { params }),
  
  // Buscar CVE por ID
  get: (id) => api.get(`/cves/${id}`),
  
  // Buscar CVEs por texto
  search: (query, limit = 20) => api.get('/cves/search', { params: { q: query, limit } }),
  
  // Estatísticas do banco de CVEs
  getStats: () => api.get('/cves/stats'),
  
  // Alertas relacionados a um CVE
  getAlerts: (id, limit = 50) => api.get(`/cves/${id}/alerts`, { params: { limit } }),
  
  // Sincronizar com NVD
  sync: (days = 30) => api.post('/cves/sync', null, { params: { days } }),

  // Status da sincronização
  getSyncStatus: () => api.get('/cves/sync/status'),
  
  // Atualizar contagem de alertas
  updateCounts: () => api.post('/cves/update-counts'),
  
  // Diagnóstico e teste de conectividade
  diagnostics: () => api.get('/cves/diagnostics'),
  
  // Configuração do NVD
  getConfig: () => api.get('/cves/config'),
  saveConfig: (config) => api.post('/cves/config', config),
  testConnection: (apiKey) => api.post('/cves/test-connection', { api_key: apiKey }),
};

// API de Dashboard Executivo
export const executiveAPI = {
  // Dashboard completo
  getDashboard: (params) => api.get('/executive/dashboard', { params }),
  
  // KPIs
  getKPIs: () => api.get('/executive/kpis'),
  
  // Trends
  getTrends: (params) => api.get('/executive/trends', { params }),
  
  // Relatórios
  generateReport: (reportData) => api.post('/executive/reports/generate', reportData),
};

// API de Integrações Avançadas (Legacy - Deprecated)
// Renomeado para evitar conflito com o novo integrationsAPI
export const advancedIntegrationsAPI = {
  // Enrichment
  enrichEvent: (event, options) => api.post('/integrations/enrich', { event, options }),
  
  // IOC Matching
  matchIOCs: (event) => api.post('/integrations/match-iocs', event),
  
  // MITRE Mapping
  mapMITRE: (event) => api.post('/integrations/map-mitre', event),
  
  // Stats & Cache
  getStats: () => api.get('/integrations/stats'),
  invalidateCache: (type) => api.post('/integrations/cache/invalidate', null, { params: { type } }),
};

// API de Threat Hunting
export const huntingAPI = {
  // Queries
  executeSearch: (query) => api.post('/hunting/search', query),
  pivot: (pivotRequest) => api.post('/hunting/pivot', pivotRequest),
  
  // Saved Searches
  getSavedSearches: (params) => api.get('/hunting/searches', { params }),
  createSavedSearch: (search) => api.post('/hunting/searches', search),
  
  // Campaigns
  getCampaigns: (params) => api.get('/hunting/campaigns', { params }),
  createCampaign: (campaign) => api.post('/hunting/campaigns', campaign),
  
  // Findings
  createFinding: (finding) => api.post('/hunting/findings', finding),
  
  // Timeline
  getTimeline: (params) => api.get('/hunting/timeline', { params }),
  
  // Stats
  getStats: () => api.get('/hunting/stats'),
};

// API de UEBA (User Behavior Analytics)
export const uebaAPI = {
  // Dashboard
  getDashboard: () => api.get('/ueba/dashboard'),
  
  // Users
  getUsers: (params) => api.get('/ueba/users', { params }),
  getUserProfile: (userId) => api.get(`/ueba/users/${encodeURIComponent(userId)}`),
  analyzeUser: (userId) => api.post(`/ueba/users/${encodeURIComponent(userId)}/analyze`),
  
  // Anomalies
  getAnomalies: (params) => api.get('/ueba/anomalies', { params }),
  updateAnomaly: (anomalyId, update) => api.put(`/ueba/anomalies/${anomalyId}`, update),
  
  // Peer Groups
  getPeerGroups: () => api.get('/ueba/peer-groups'),
  
  // Stats
  getStats: () => api.get('/ueba/stats'),
  
  // Diagnostics & Maintenance
  getDiagnostics: () => api.get('/ueba/diagnostics'),
  forceAnalysis: (cleanup = false) => api.post(`/ueba/force-analysis${cleanup ? '?cleanup=true' : ''}`),
  cleanup: () => api.post('/ueba/cleanup'),
};

// API de Compliance & Audit
export const complianceAPI = {
  // Dashboard
  getDashboard: () => api.get('/compliance/dashboard'),
  
  // Frameworks
  getFrameworks: () => api.get('/compliance/frameworks'),
  getFramework: (id) => api.get(`/compliance/frameworks/${id}`),
  runAssessment: (id) => api.post(`/compliance/frameworks/${id}/assess`),
  
  // Controls
  getControls: (params) => api.get('/compliance/controls', { params }),
  updateControl: (id, update) => api.put(`/compliance/controls/${id}`, update),
  
  // Audit Logs
  getAuditLogs: (params) => api.get('/compliance/audit-logs', { params }),
  getAuditTrail: (params) => api.get('/compliance/audit-trail', { params }),
  
  // Violations
  getViolations: (params) => api.get('/compliance/violations', { params }),
  updateViolation: (id, update) => api.put(`/compliance/violations/${id}`, update),
  
  // Reports
  getReports: () => api.get('/compliance/reports'),
  generateReport: (reportData) => api.post('/compliance/reports/generate', reportData),
  downloadReport: (id) => api.get(`/compliance/reports/${id}/download`, { responseType: 'text' }),
  
  // Gap Analysis
  getGapAnalysis: (frameworkId) => api.get(`/compliance/frameworks/${frameworkId}/gap-analysis`),
};

// ============================================================================
// VULNERABILITY MANAGEMENT
// ============================================================================

export const vulnerabilityAPI = {
  // Dashboard
  getDashboard: () => api.get('/vulnerabilities/dashboard'),
  getStats: () => api.get('/vulnerabilities/stats'),
  
  // Vulnerabilities
  getVulnerabilities: (params) => api.get('/vulnerabilities/', { params }),
  getVulnerability: (id) => api.get(`/vulnerabilities/${id}`),
  updateVulnerability: (id, update) => api.put(`/vulnerabilities/${id}`, update),
  
  // Atualizar status de uma vulnerabilidade
  updateStatus: (id, status, reason = '', comment = '') => api.put(`/vulnerabilities/${id}/status`, {
    status,
    reason,
    comment,
  }),
  
  // Assets
  getAssets: (params) => api.get('/vulnerabilities/assets', { params }),
  getAsset: (id) => api.get(`/vulnerabilities/assets/${encodeURIComponent(id)}`),
  
  // Scans
  getScans: (params) => api.get('/vulnerabilities/scans', { params }),
  getScan: (id) => api.get(`/vulnerabilities/scans/${id}`),
  createScan: (scanData) => api.post('/vulnerabilities/scans', scanData),
  
  // Sync - Force synchronization with AWS
  syncFromSecurityHub: () => api.post('/vulnerabilities/sync-securityhub'),
  syncFromInspector: () => api.post('/vulnerabilities/sync'),
  getFromSecurityHub: () => api.get('/vulnerabilities/from-securityhub'),
  
  // Diagnostics - AWS Inspector connectivity check
  getDiagnostics: () => api.get('/vulnerabilities/diagnostics'),
  forceSync: () => api.post('/vulnerabilities/sync'),
};

// ============================================================================
// NETWORK TRAFFIC ANALYSIS
// ============================================================================

export const networkAPI = {
  // Dashboard
  getDashboard: () => api.get('/network/dashboard').then(res => res.data),
  getStats: () => api.get('/network/stats').then(res => res.data),
  
  // Flows
  getFlows: (params) => api.get('/network/flows', { params }).then(res => res.data),
  
  // Connections
  getConnections: (params) => api.get('/network/connections', { params }).then(res => res.data),
  
  // Top Talkers
  getTopTalkers: (params) => api.get('/network/top-talkers', { params }).then(res => res.data),
  
  // Protocol Analysis
  getProtocols: (params) => api.get('/network/protocols', { params }).then(res => res.data),
  
  // Anomalies
  getAnomalies: (params) => api.get('/network/anomalies', { params }).then(res => res.data),
  
  // Bandwidth
  getBandwidth: (params) => api.get('/network/bandwidth', { params }).then(res => res.data),
  
  // Geographic Distribution
  getGeoLocations: (params) => api.get('/network/geo-locations', { params }).then(res => res.data),
  
  // Port Scans
  getPortScans: (params) => api.get('/network/port-scans', { params }).then(res => res.data),
};

// ============================================================================
// FILE INTEGRITY MONITORING
// ============================================================================

export const fimAPI = {
  // Dashboard
  getDashboard: () => api.get('/fim/dashboard').then(res => res.data),
  getStats: () => api.get('/fim/stats').then(res => res.data),
  
  // Files
  getFiles: (params) => api.get('/fim/files', { params }).then(res => res.data),
  
  // Changes
  getChanges: (params) => api.get('/fim/changes', { params }).then(res => res.data),
  acknowledgeChange: (id, notes) => api.post(`/fim/changes/${id}/acknowledge`, { notes }).then(res => res.data),
  
  // Baselines
  getBaselines: (params) => api.get('/fim/baselines', { params }).then(res => res.data),
  createBaseline: (baseline) => api.post('/fim/baselines', baseline).then(res => res.data),
  
  // Rules
  getRules: (params) => api.get('/fim/rules', { params }).then(res => res.data),
  createRule: (rule) => api.post('/fim/rules', rule).then(res => res.data),
  
  // Alerts
  getAlerts: (params) => api.get('/fim/alerts', { params }).then(res => res.data),
};

// ============================================================================
// DATA LOSS PREVENTION (DLP)
// ============================================================================

export const dlpAPI = {
  // Dashboard
  getDashboard: () => api.get('/v1/dlp/dashboard').then(res => res.data),
  getStats: () => api.get('/v1/dlp/stats').then(res => res.data),
  
  // Policies
  getPolicies: () => api.get('/v1/dlp/policies').then(res => res.data),
  getPolicy: (id) => api.get(`/v1/dlp/policies/${id}`).then(res => res.data),
  createPolicy: (policy) => api.post('/v1/dlp/policies', policy).then(res => res.data),
  updatePolicy: (id, policy) => api.put(`/v1/dlp/policies/${id}`, policy).then(res => res.data),
  deletePolicy: (id) => api.delete(`/v1/dlp/policies/${id}`).then(res => res.data),
  
  // Incidents
  getIncidents: (params) => api.get('/v1/dlp/incidents', { params }).then(res => res.data),
  getIncident: (id) => api.get(`/v1/dlp/incidents/${id}`).then(res => res.data),
  updateIncident: (id, updates) => api.put(`/v1/dlp/incidents/${id}`, updates).then(res => res.data),
  
  // Content Inspection
  inspectContent: (content) => api.post('/v1/dlp/inspect', content).then(res => res.data),
  
  // Patterns
  getPatterns: () => api.get('/v1/dlp/patterns').then(res => res.data),
  createPattern: (pattern) => api.post('/v1/dlp/patterns', pattern).then(res => res.data),
  
  // Data Classification
  getClassifications: () => api.get('/v1/dlp/classifications').then(res => res.data),
  classifyData: (data) => api.post('/v1/dlp/classify', data).then(res => res.data),
};

// ============================================================================
// ENDPOINT DETECTION & RESPONSE (EDR)
// ============================================================================

export const edrAPI = {
  // Dashboard
  getDashboard: () => api.get('/v1/edr/dashboard').then(res => res.data),
  getStats: () => api.get('/v1/edr/stats').then(res => res.data),
  
  // Agents
  getAgents: (params) => api.get('/v1/edr/agents', { params }).then(res => res.data),
  getAgent: (id) => api.get(`/v1/edr/agents/${id}`).then(res => res.data),
  deployAgent: (agent) => api.post('/v1/edr/agents', agent).then(res => res.data),
  uninstallAgent: (id) => api.delete(`/v1/edr/agents/${id}`).then(res => res.data),
  
  // Endpoints
  getEndpoints: () => api.get('/v1/edr/endpoints').then(res => res.data),
  getEndpoint: (id) => api.get(`/v1/edr/endpoints/${id}`).then(res => res.data),
  isolateEndpoint: (id, reason, notes) => api.post(`/v1/edr/endpoints/${id}/isolate`, { reason, notes }).then(res => res.data),
  restoreEndpoint: (id) => api.post(`/v1/edr/endpoints/${id}/restore`).then(res => res.data),
  
  // Threats
  getThreats: (params) => api.get('/v1/edr/threats', { params }).then(res => res.data),
  getThreat: (id) => api.get(`/v1/edr/threats/${id}`).then(res => res.data),
  takeActionOnThreat: (id, action) => api.post(`/v1/edr/threats/${id}/action`, action).then(res => res.data),
  
  // Processes
  getProcesses: (params) => api.get('/v1/edr/processes', { params }).then(res => res.data),
  terminateProcess: (id) => api.post(`/v1/edr/processes/${id}/terminate`).then(res => res.data),
  
  // Memory Scans
  getMemoryScans: () => api.get('/v1/edr/memory-scans').then(res => res.data),
  initiateMemoryScan: (scan) => api.post('/v1/edr/memory-scans', scan).then(res => res.data),
  
  // Forensics
  getForensics: () => api.get('/v1/edr/forensics').then(res => res.data),
  collectForensics: (forensic) => api.post('/v1/edr/forensics', forensic).then(res => res.data),
};

// ============================================================================
// ML ANALYTICS
// ============================================================================

export const mlAnalyticsAPI = {
  // Dashboard
  getDashboard: () => api.get('/v1/ml-analytics/dashboard').then(res => res.data),
  getStats: () => api.get('/v1/ml-analytics/stats').then(res => res.data),
  
  // Models
  getModels: () => api.get('/v1/ml-analytics/models').then(res => res.data),
  getModel: (id) => api.get(`/v1/ml-analytics/models/${id}`).then(res => res.data),
  createModel: (model) => api.post('/v1/ml-analytics/models', model).then(res => res.data),
  trainModel: (id, config) => api.post(`/v1/ml-analytics/models/${id}/train`, config).then(res => res.data),
  deployModel: (id) => api.post(`/v1/ml-analytics/models/${id}/deploy`).then(res => res.data),
  getModelMetrics: (id) => api.get(`/v1/ml-analytics/models/${id}/metrics`).then(res => res.data),
  getFeatureImportance: (id) => api.get(`/v1/ml-analytics/models/${id}/feature-importance`).then(res => res.data),
  
  // Anomalies
  getAnomalies: (params) => api.get('/v1/ml-analytics/anomalies', { params }).then(res => res.data),
  getAnomaly: (id) => api.get(`/v1/ml-analytics/anomalies/${id}`).then(res => res.data),
  updateAnomalyStatus: (id, status, notes) => api.put(`/v1/ml-analytics/anomalies/${id}/status`, { status, notes }).then(res => res.data),
  
  // Predictions
  getPredictions: (params) => api.get('/v1/ml-analytics/predictions', { params }).then(res => res.data),
  getRiskPredictions: () => api.get('/v1/ml-analytics/risk-predictions').then(res => res.data),
  
  // Training
  getTrainingJobs: () => api.get('/v1/ml-analytics/training-jobs').then(res => res.data),
};

// ============================================================================
// INCIDENT RESPONSE AUTOMATION
// ============================================================================

export const incidentResponseAPI = {
  // Dashboard
  getDashboard: () => api.get('/incident-response/dashboard').then(res => res.data),
  getStats: () => api.get('/incident-response/stats').then(res => res.data),
  
  // Incidents
  getIncidents: (params) => api.get('/incident-response/incidents', { params }).then(res => res.data),
  getIncident: (id) => api.get(`/incident-response/incidents/${id}`).then(res => res.data),
  createIncident: (incident) => api.post('/incident-response/incidents', incident).then(res => res.data),
  updateIncident: (id, updates) => api.put(`/incident-response/incidents/${id}`, updates).then(res => res.data),
  
  // Automation Rules
  getAutomationRules: () => api.get('/incident-response/automation-rules').then(res => res.data),
  createAutomationRule: (rule) => api.post('/incident-response/automation-rules', rule).then(res => res.data),
  
  // Escalation Rules
  getEscalationRules: () => api.get('/incident-response/escalation-rules').then(res => res.data),
  
  // Assignment Rules
  getAssignmentRules: () => api.get('/incident-response/assignment-rules').then(res => res.data),
};

// ============================================================================
// REPORTS & ANALYTICS
// ============================================================================

export const reportsAPI = {
  // Templates
  listTemplates: () => api.get('/reports/templates').then(res => res.data),
  getTemplate: (id) => api.get(`/reports/templates/${id}`).then(res => res.data),
  
  // Report Generation
  generateReport: (reportData) => api.post('/reports/generate', reportData).then(res => res.data),
  listReports: (params) => api.get('/reports', { params }).then(res => res.data),
  
  // Export
  exportPDF: (id) => api.get(`/reports/${id}/export/pdf`, { responseType: 'blob' }),
  exportExcel: (id) => api.get(`/reports/${id}/export/excel`, { responseType: 'blob' }),
  exportCSV: (id) => api.get(`/reports/${id}/export/csv`, { responseType: 'blob' }),
  
  // Scheduled Reports
  listSchedules: () => api.get('/reports/schedules').then(res => res.data),
  createSchedule: (schedule) => api.post('/reports/schedules', schedule).then(res => res.data),
  
  // Stats
  getStats: () => api.get('/reports/stats').then(res => res.data),
};

// ============================================================================
// DASHBOARD CUSTOMIZATION
// ============================================================================

export const dashboardCustomizationAPI = {
  // Dashboard CRUD
  list: (params) => api.get('/custom-dashboards', { params }).then(res => res.data),
  get: (id) => api.get(`/custom-dashboards/${id}`).then(res => res.data),
  create: (dashboard) => api.post('/custom-dashboards', dashboard).then(res => res.data),
  update: (id, dashboard) => api.put(`/custom-dashboards/${id}`, dashboard).then(res => res.data),
  delete: (id) => api.delete(`/custom-dashboards/${id}`).then(res => res.data),
  
  // Templates
  listTemplates: () => api.get('/custom-dashboards/templates/list').then(res => res.data),
  getTemplate: (id) => api.get(`/custom-dashboards/templates/${id}`).then(res => res.data),
  createFromTemplate: (id) => api.post(`/custom-dashboards/templates/${id}/create`).then(res => res.data),
  
  // Widget Management
  addWidget: (dashboardId, widget) => api.post(`/custom-dashboards/${dashboardId}/widgets`, widget).then(res => res.data),
  updateWidget: (dashboardId, widgetId, widget) => api.put(`/custom-dashboards/${dashboardId}/widgets/${widgetId}`, widget).then(res => res.data),
  deleteWidget: (dashboardId, widgetId) => api.delete(`/custom-dashboards/${dashboardId}/widgets/${widgetId}`).then(res => res.data),
  
  // Widget Types & Data
  getWidgetTypes: () => api.get('/custom-dashboards/widget-types').then(res => res.data),
  getWidgetData: (type, source) => api.get('/custom-dashboards/widget-data', { params: { type, source } }).then(res => res.data),
  
  // Export/Import
  export: (id) => api.get(`/custom-dashboards/${id}/export`, { responseType: 'blob' }),
  import: (dashboard) => api.post('/custom-dashboards/import', dashboard).then(res => res.data),
  
  // Stats
  getStats: () => api.get('/custom-dashboards/stats/all').then(res => res.data),
};

// ============================================================================
// HEALTH
// ============================================================================

export const healthAPI = {
  // Health check
  check: () => api.get('/health'),
};

// ============================================================================
// MONITORING API
// ============================================================================

export const monitoringAPI = {
  // Health check
  getHealth: () => api.get('/monitoring/health'),
  
  // System metrics
  getMetrics: () => api.get('/monitoring/metrics'),
  
  // Combined health and metrics
  getStatus: () => api.get('/health'),
};

// ============================================================================
// DATA RETENTION POLICIES
// ============================================================================

export const retentionAPI = {
  // Policies CRUD
  getPolicies: (params) => api.get('/retention/policies', { params }).then(res => res.data),
  getPolicy: (id) => api.get(`/retention/policies/${id}`).then(res => res.data),
  createPolicy: (policy) => api.post('/retention/policies', policy).then(res => res.data),
  updatePolicy: (id, policy) => api.put(`/retention/policies/${id}`, policy).then(res => res.data),
  deletePolicy: (id) => api.delete(`/retention/policies/${id}`).then(res => res.data),
  
  // Execute policy
  executePolicy: (id) => api.post(`/retention/policies/${id}/execute`).then(res => res.data),
  
  // Executions
  getExecutions: (params) => api.get('/retention/executions', { params }).then(res => res.data),
  getExecution: (id) => api.get(`/retention/executions/${id}`).then(res => res.data),
  
  // Statistics
  getStats: () => api.get('/retention/stats').then(res => res.data),
  
  // Data type configs
  getConfigs: () => api.get('/retention/configs').then(res => res.data),
  updateConfig: (type, config) => api.put(`/retention/configs/${type}`, config).then(res => res.data),
};

// ============================================================================
// NOTIFICATIONS
// ============================================================================

export const notificationsAPI = {
  // Notifications CRUD
  getAll: (params) => api.get('/notifications/', { params }).then(res => res.data),
  get: (id) => api.get(`/notifications/${id}`).then(res => res.data),
  create: (notification) => api.post('/notifications/', notification).then(res => res.data),
  delete: (id) => api.delete(`/notifications/${id}`).then(res => res.data),
  
  // Mark as read
  markAsRead: (id) => api.post(`/notifications/${id}/read`).then(res => res.data),
  markAllAsRead: (userId) => api.post('/notifications/read-all', null, { params: { user_id: userId } }).then(res => res.data),
  
  // Stats
  getStats: (userId) => api.get('/notifications/stats/summary', { params: { user_id: userId } }).then(res => res.data),
  
  // Rules
  getRules: () => api.get('/notifications/rules').then(res => res.data),
  createRule: (rule) => api.post('/notifications/rules', rule).then(res => res.data),
  updateRule: (id, rule) => api.put(`/notifications/rules/${id}`, rule).then(res => res.data),
  deleteRule: (id) => api.delete(`/notifications/rules/${id}`).then(res => res.data),
  
  // Templates
  getTemplates: () => api.get('/notifications/templates').then(res => res.data),
  createTemplate: (template) => api.post('/notifications/templates', template).then(res => res.data),
  deleteTemplate: (id) => api.delete(`/notifications/templates/${id}`).then(res => res.data),
  
  // Channels
  getChannels: () => api.get('/notifications/channels').then(res => res.data),
  createChannel: (channel) => api.post('/notifications/channels', channel).then(res => res.data),
  updateChannel: (id, channel) => api.put(`/notifications/channels/${id}`, channel).then(res => res.data),
  deleteChannel: (id) => api.delete(`/notifications/channels/${id}`).then(res => res.data),
};

// ============================================================================
// AUTOMATED RESPONSE ENGINE (MDR)
// ============================================================================

export const automatedResponseAPI = {
  // Response Rules CRUD
  listRules: (params) => api.get('/automated-response/rules', { params }),
  getRule: (id) => api.get(`/automated-response/rules/${id}`),
  createRule: (rule) => api.post('/automated-response/rules', rule),
  updateRule: (id, rule) => api.put(`/automated-response/rules/${id}`, rule),
  deleteRule: (id) => api.delete(`/automated-response/rules/${id}`),
  
  // Executions
  listExecutions: (params) => api.get('/automated-response/executions', { params }),
  getExecution: (id) => api.get(`/automated-response/executions/${id}`),
  triggerExecution: (data) => api.post('/automated-response/executions/trigger', data),
  cancelExecution: (id) => api.post(`/automated-response/executions/${id}/cancel`),
  rollbackExecution: (id) => api.post(`/automated-response/executions/${id}/rollback`),
  
  // Approvals
  listApprovals: (params) => api.get('/automated-response/approvals', { params }),
  approveExecution: (id, data) => api.post(`/automated-response/executions/${id}/approve`, data),
  rejectExecution: (id, data) => api.post(`/automated-response/executions/${id}/reject`, data),
  
  // Statistics
  getStats: () => api.get('/automated-response/stats'),
};

// ============================================================================
// INTELLIGENT ALERT TRIAGE (MDR)
// ============================================================================

export const alertTriageAPI = {
  // ============ PRODUCTION ENDPOINTS (OpenSearch) ============
  // Alert Queue - Real alerts from OpenSearch
  getQueue: (params) => api.get('/alert-triage/queue', { params }),
  
  // Triage Actions - Update alerts in OpenSearch
  performAction: (alertId, action) => api.post(`/alert-triage/action/${alertId}`, action),
  bulkAction: (data) => api.post('/alert-triage/bulk-action', data),
  
  // Statistics - Real-time from OpenSearch
  getStatistics: () => api.get('/alert-triage/statistics'),
  
  // ============ LEGACY ENDPOINTS (ML Triage - Demo) ============
  // Triage Operations
  triageAlert: (data) => api.post('/alert-triage/triage', data),
  listResults: (params) => api.get('/alert-triage/results', { params }),
  getResult: (id) => api.get(`/alert-triage/results/${id}`),
  updateResult: (id, data) => api.put(`/alert-triage/results/${id}`, data),
  markFalsePositive: (id, data) => api.post(`/alert-triage/results/${id}/false-positive`, data),
  
  // Alias for backward compatibility
  getStats: () => api.get('/alert-triage/statistics'),
  
  // Triage Rules
  listRules: (params) => api.get('/alert-triage/rules', { params }),
  createRule: (rule) => api.post('/alert-triage/rules', rule),
  updateRule: (id, rule) => api.put(`/alert-triage/rules/${id}`, rule),
  deleteRule: (id) => api.delete(`/alert-triage/rules/${id}`),
  
  // Analyst Management
  listAnalysts: (params) => api.get('/alert-triage/analysts', { params }),
  updateAnalyst: (id, data) => api.put(`/alert-triage/analysts/${id}`, data),
  
  // Statistics
  getStats: () => api.get('/alert-triage/stats'),
};

// ============================================================================
// SLA & METRICS TRACKING (MDR)
// ============================================================================

export const slaMetricsAPI = {
  // SLA Policies
  listPolicies: (params) => api.get('/sla-metrics/policies', { params }),
  createPolicy: (policy) => api.post('/sla-metrics/policies', policy),
  updatePolicy: (id, policy) => api.put(`/sla-metrics/policies/${id}`, policy),
  deletePolicy: (id) => api.delete(`/sla-metrics/policies/${id}`),
  
  // SLA Tracking
  listTrackings: (params) => api.get('/sla-metrics/trackings', { params }),
  getTracking: (id) => api.get(`/sla-metrics/trackings/${id}`),
  
  // Breaches
  listBreaches: (params) => api.get('/sla-metrics/breaches', { params }),
  
  // Statistics & Metrics
  getStats: () => api.get('/sla-metrics/stats'),
  getMetrics: (params) => api.get('/sla-metrics/metrics', { params }),
};

// ============================================================================
// MDR EXECUTIVE DASHBOARD
// ============================================================================

export const mdrDashboardAPI = {
  getDashboard: () => api.get('/mdr-dashboard/'),
  getSecurityPosture: () => api.get('/mdr-dashboard/security-posture'),
  getMDRPerformance: () => api.get('/mdr-dashboard/mdr-performance'),
  getBusinessImpact: () => api.get('/mdr-dashboard/business-impact'),
  getThreatIntelSummary: () => api.get('/mdr-dashboard/threat-intel-summary'),
  getComplianceStatus: () => api.get('/mdr-dashboard/compliance-status'),
  getCriticalAlerts: () => api.get('/mdr-dashboard/critical-alerts'),
};

// ============================================================================
// THREAT HUNTING PLATFORM (MDR PHASE 2)
// ============================================================================

export const threatHuntingPlatformAPI = {
  listHypotheses: (params) => api.get('/threat-hunting-platform/hypotheses', { params }),
  createHypothesis: (data) => api.post('/threat-hunting-platform/hypotheses', data),
  getHypothesis: (id) => api.get(`/threat-hunting-platform/hypotheses/${id}`),
  updateHypothesis: (id, data) => api.put(`/threat-hunting-platform/hypotheses/${id}`, data),
  deleteHypothesis: (id) => api.delete(`/threat-hunting-platform/hypotheses/${id}`),
  listTemplates: (params) => api.get('/threat-hunting-platform/templates', { params }),
  executeQuery: (data) => api.post('/threat-hunting-platform/execute', data),
  listNotebooks: () => api.get('/threat-hunting-platform/notebooks'),
  createNotebook: (data) => api.post('/threat-hunting-platform/notebooks', data),
  listScheduled: () => api.get('/threat-hunting-platform/scheduled'),
  createScheduled: (data) => api.post('/threat-hunting-platform/scheduled', data),
  getMetrics: () => api.get('/threat-hunting-platform/metrics'),
  
  // Hunting History / Activities
  getActivities: (params) => api.get('/threat-hunting-platform/activities', { params }),
  getActivityStatistics: () => api.get('/threat-hunting-platform/activities/statistics'),
};

// ============================================================================
// CONTINUOUS VALIDATION (MDR PHASE 3)
// ============================================================================

export const continuousValidationAPI = {
  listControls: () => api.get('/validation/controls'),
  listTests: () => api.get('/validation/tests'),
  getCoverage: () => api.get('/validation/coverage'),
  getGaps: () => api.get('/validation/gaps'),
  getReports: () => api.get('/validation/reports'),
  getMetrics: () => api.get('/validation/metrics'),
};

// ============================================================================
// SECURITY AWARENESS (MDR PHASE 3)
// ============================================================================

export const securityAwarenessAPI = {
  listCampaigns: () => api.get('/awareness/campaigns'),
  createCampaign: (data) => api.post('/awareness/campaigns', data),
  listTemplates: () => api.get('/awareness/templates'),
  listTrainings: () => api.get('/awareness/trainings'),
  listUsers: () => api.get('/awareness/users'),
  getMetrics: () => api.get('/awareness/metrics'),
  getLeaderboard: () => api.get('/awareness/leaderboard'),
};

// ============================================================================
// ADVANCED ANALYTICS & ML (MDR PHASE 4)
// ============================================================================

export const advancedAnalyticsAPI = {
  listAnomalies: () => api.get('/analytics/anomalies'),
  listBehavioralProfiles: () => api.get('/analytics/behavioral-profiles'),
  listPredictions: () => api.get('/analytics/predictions'),
  listModels: () => api.get('/analytics/models'),
  listRiskAssessments: () => api.get('/analytics/risk-assessments'),
  getMetrics: () => api.get('/analytics/metrics'),
  getDiagnostics: () => api.get('/analytics/diagnostics'),
  forceAnalysis: () => api.post('/analytics/force-analysis'),
  cleanupDuplicates: () => api.post('/analytics/cleanup-duplicates'),
};

export const soarAPI = {
  listPlaybooks: () => api.get('/soar/playbooks'),
  listExecutions: () => api.get('/soar/executions'),
  listIntegrations: () => api.get('/soar/integrations'),
  listCases: () => api.get('/soar/cases'),
  listWorkflows: () => api.get('/soar/workflows'),
  getMetrics: () => api.get('/soar/metrics'),
};

export const threatIntelFusionAPI = {
  listFeeds: () => api.get('/threat-intel-fusion/feeds'),
  listIndicators: () => api.get('/threat-intel-fusion/indicators'),
  listActors: () => api.get('/threat-intel-fusion/actors'),
  listCampaigns: () => api.get('/threat-intel-fusion/campaigns'),
  listCorrelations: () => api.get('/threat-intel-fusion/correlations'),
  getMetrics: () => api.get('/threat-intel-fusion/metrics'),
};

export const cspmAPI = {
  listAccounts: () => api.get('/cspm/accounts'),
  listResources: () => api.get('/cspm/resources'),
  listFindings: () => api.get('/cspm/findings'),
  listCompliance: () => api.get('/cspm/compliance'),
  listRemediation: () => api.get('/cspm/remediation'),
  getMetrics: () => api.get('/cspm/metrics'),
  
  // AWS Integrations
  aws: {
    // AWS Config
    getConfigFindings: () => api.get('/cspm/aws/config/findings'),
    getConfigRules: () => api.get('/cspm/aws/config/rules'),
    
    // AWS Security Hub
    getSecurityHubFindings: () => api.get('/cspm/aws/security-hub/findings'),
    
    // AWS GuardDuty
    getGuardDutyFindings: () => api.get('/cspm/aws/guardduty/findings'),
    
    // AWS Inspector
    getInspectorFindings: () => api.get('/cspm/aws/inspector/findings'),
    
    // AWS CloudTrail
    getCloudTrailEvents: () => api.get('/cspm/aws/cloudtrail/events'),
    
    // AWS Integration Management
    getStatus: () => api.get('/cspm/aws/status'),
    sync: () => api.post('/cspm/aws/sync'),
    testConnection: (config) => api.post('/cspm/aws/test', config),
  },
  
  // Auto-Remediation
  remediation: {
    // Rules
    getRules: () => api.get('/cspm/remediation/rules'),
    getRule: (id) => api.get(`/cspm/remediation/rules/${id}`),
    
    // Executions
    getExecutions: () => api.get('/cspm/remediation/executions'),
    getExecution: (id) => api.get(`/cspm/remediation/executions/${id}`),
    rollback: (id) => api.post(`/cspm/remediation/executions/${id}/rollback`),
    
    // Approvals
    getApprovals: () => api.get('/cspm/remediation/approvals'),
    approve: (id, data) => api.post(`/cspm/remediation/approvals/${id}/approve`, data),
    reject: (id, data) => api.post(`/cspm/remediation/approvals/${id}/reject`, data),
    
    // Statistics
    getStatistics: () => api.get('/cspm/remediation/statistics'),
  },
  
  // Alert System
  alerts: {
    // Channels
    getChannels: () => api.get('/cspm/alerts/channels'),
    getChannel: (id) => api.get(`/cspm/alerts/channels/${id}`),
    createChannel: (channel) => api.post('/cspm/alerts/channels', channel),
    updateChannel: (id, updates) => api.put(`/cspm/alerts/channels/${id}`, updates),
    deleteChannel: (id) => api.delete(`/cspm/alerts/channels/${id}`),
    testChannel: (id) => api.post(`/cspm/alerts/channels/${id}/test`),
    
    // Rules
    getRules: () => api.get('/cspm/alerts/rules'),
    getRule: (id) => api.get(`/cspm/alerts/rules/${id}`),
    createRule: (rule) => api.post('/cspm/alerts/rules', rule),
    updateRule: (id, updates) => api.put(`/cspm/alerts/rules/${id}`, updates),
    deleteRule: (id) => api.delete(`/cspm/alerts/rules/${id}`),
    
    // Alerts
    getAlerts: (params) => api.get('/cspm/alerts', { params }),
    getAlert: (id) => api.get(`/cspm/alerts/${id}`),
    acknowledge: (id, data) => api.post(`/cspm/alerts/${id}/acknowledge`, data),
    resolve: (id, data) => api.post(`/cspm/alerts/${id}/resolve`, data),
    
    // Statistics
    getStatistics: () => api.get('/cspm/alerts/statistics'),
    
    // Escalation Policies
    getEscalationPolicies: () => api.get('/cspm/alerts/escalation-policies'),
    getEscalationPolicy: (id) => api.get(`/cspm/alerts/escalation-policies/${id}`),
  },

  // PCI-DSS Compliance
  pciDss: {
    getDashboard: () => api.get('/cspm/pci-dss/dashboard'),
    getRequirements: () => api.get('/cspm/pci-dss/requirements'),
    getRequirement: (id) => api.get(`/cspm/pci-dss/requirements/${id}`),
    getControls: () => api.get('/cspm/pci-dss/controls'),
    getControl: (id) => api.get(`/cspm/pci-dss/controls/${id}`),
  },
  
  // Drift Detection
  drift: {
    // Baselines
    getBaselines: () => api.get('/cspm/drift/baselines'),
    getBaseline: (id) => api.get(`/cspm/drift/baselines/${id}`),
    createBaseline: (baseline) => api.post('/cspm/drift/baselines', baseline),
    
    // Detections
    getDetections: (params) => api.get('/cspm/drift/detections', { params }),
    getDetection: (id) => api.get(`/cspm/drift/detections/${id}`),
    updateStatus: (id, data) => api.put(`/cspm/drift/detections/${id}/status`, data),
    
    // Statistics
    getStatistics: () => api.get('/cspm/drift/statistics'),
    
    // Scan Configs
    getScanConfigs: () => api.get('/cspm/drift/scan-configs'),
    runScan: (id) => api.post(`/cspm/drift/scan-configs/${id}/run`),
  },

  // AWS Config Aggregator (Multi-Account)
  aggregator: {
    // Accounts
    getAccounts: () => api.get('/cspm/aggregator/accounts'),
    getAccount: (id) => api.get(`/cspm/aggregator/accounts/${id}`),
    addAccount: (account) => api.post('/cspm/aggregator/accounts', account),
    updateAccount: (id, account) => api.put(`/cspm/aggregator/accounts/${id}`, account),
    deleteAccount: (id) => api.delete(`/cspm/aggregator/accounts/${id}`),
    
    // Aggregators
    getAggregators: () => api.get('/cspm/aggregator/aggregators'),
    getAggregator: (id) => api.get(`/cspm/aggregator/aggregators/${id}`),
    
    // Aggregated Data
    getAggregatedData: (id) => api.get(`/cspm/aggregator/aggregators/${id}/data`),
    
    // Sync
    getSyncStatus: (id) => api.get(`/cspm/aggregator/aggregators/${id}/sync-status`),
    triggerSync: (id) => api.post(`/cspm/aggregator/aggregators/${id}/sync`),
  },

  // AWS STS Connection Management
  connections: {
    // List all connections
    list: () => api.get('/cspm/connections'),
    
    // Get connection details
    get: (id) => api.get(`/cspm/connections/${id}`),
    
    // Create new connection
    create: (connection) => api.post('/cspm/connections', connection),
    
    // Update connection
    update: (id, updates) => api.put(`/cspm/connections/${id}`, updates),
    
    // Delete connection
    delete: (id) => api.delete(`/cspm/connections/${id}`),
    
    // Refresh credentials
    refresh: (id) => api.post(`/cspm/connections/${id}/refresh`),
    
    // Test connection
    test: (id) => api.post(`/cspm/connections/${id}/test`),
    
    // Get connection health
    getHealth: (id) => api.get(`/cspm/connections/${id}/health`),
    
    // Get statistics
    getStatistics: () => api.get('/cspm/connections/statistics'),
    
    // Bulk refresh all connections
    bulkRefresh: () => api.post('/cspm/connections/bulk-refresh'),
  },

  // GCP Integrations
  gcp: {
    getStatus: () => api.get('/cspm/gcp/status'),
    getConfig: () => api.get('/cspm/gcp/config'),
    saveConfig: (config) => api.post('/cspm/gcp/config', config),
    testConnection: (config) => api.post('/cspm/gcp/test', config),
    sync: () => api.post('/cspm/gcp/sync'),
    getFindings: (params) => api.get('/cspm/gcp/findings', { params }),
    getStats: () => api.get('/cspm/gcp/stats'),
    getDiagnostic: () => api.get('/cspm/gcp/diagnostic'),
  },
};

export const zeroTrustAPI = {
  listIdentities: () => api.get('/zero-trust/identities'),
  listDevices: () => api.get('/zero-trust/devices'),
  listPolicies: () => api.get('/zero-trust/policies'),
  createPolicy: (policy) => api.post('/zero-trust/policies', policy),
  updatePolicy: (id, policy) => api.put(`/zero-trust/policies/${id}`, policy),
  deletePolicy: (id) => api.delete(`/zero-trust/policies/${id}`),
  togglePolicy: (id) => api.post(`/zero-trust/policies/${id}/toggle`),
  listAccess: () => api.get('/zero-trust/access'),
  listSegments: () => api.get('/zero-trust/segments'),
  getMetrics: () => api.get('/zero-trust/metrics'),
};

// ============================================================================
// MODULE MANAGER
// ============================================================================

export const moduleManagerAPI = {
  getModules: () => api.get('/modules/'),
  getConfig: () => api.get('/modules/config'),
  updateModuleStatus: (moduleId, status) => api.put(`/modules/${moduleId}/status`, { status }),
  bulkUpdateModules: (modules) => api.post('/modules/bulk-update', { modules }),
};

// ============================================================================
// USER MANAGEMENT
// ============================================================================

// ============================================================================
// USER PROFILE (self-service)
// ============================================================================

export const profileAPI = {
  // Get my profile
  get: () => api.get('/profile/'),
  
  // Update my profile
  update: (profileData) => api.put('/profile/', profileData),
  
  // Change my password
  changePassword: (currentPassword, newPassword) => api.post('/profile/change-password', {
    current_password: currentPassword,
    new_password: newPassword,
  }),
};

// ============================================================================
// USER MANAGEMENT (admin only)
// ============================================================================

export const usersAPI = {
  // List users
  list: (params) => api.get('/users/', { params }),
  
  // Get user by ID
  get: (id) => api.get(`/users/${id}`),
  
  // Create user
  create: (userData) => api.post('/users/', userData),
  
  // Update user
  update: (id, userData) => api.put(`/users/${id}`, userData),
  
  // Delete user
  delete: (id) => api.delete(`/users/${id}`),
  
  // Get roles
  getRoles: () => api.get('/users/roles'),
};

export default api;


// ============================================================================
// MDR FORENSICS (Legacy - kept for backward compatibility)
// ============================================================================

export const mdrForensicsAPI = {
  getCases: () => api.get('/mdr-forensics/cases'),
  createCase: (data) => api.post('/mdr-forensics/cases', data),
  getCase: (id) => api.get(`/mdr-forensics/cases/${id}`),
  getEvidence: (caseId) => api.get('/mdr-forensics/evidence', { params: { case_id: caseId } }),
  createEvidence: (data) => api.post('/mdr-forensics/evidence', data),
  getTimeline: (caseId) => api.get(`/mdr-forensics/cases/${caseId}/timeline`),
  getStats: () => api.get('/mdr-forensics/stats'),
};

// ============================================================================
// DIGITAL FORENSICS (Full OpenSearch Integration)
// ============================================================================

export const forensicsAPI = {
  // Investigations
  listInvestigations: (params) => api.get('/forensics/investigations', { params }),
  createInvestigation: (data) => api.post('/forensics/investigations', data),
  getInvestigation: (id) => api.get(`/forensics/investigations/${id}`),
  updateInvestigation: (id, data) => api.put(`/forensics/investigations/${id}`, data),
  deleteInvestigation: (id) => api.delete(`/forensics/investigations/${id}`),
  
  // Timeline
  getTimeline: (id) => api.get(`/forensics/investigations/${id}/timeline`),
  addTimelineEntry: (id, data) => api.post(`/forensics/investigations/${id}/timeline`, data),
  
  // Evidence
  listEvidence: (params) => api.get('/forensics/evidence', { params }),
  createEvidence: (data) => api.post('/forensics/evidence', data),
  
  // Stats
  getStats: () => api.get('/forensics/stats'),
};

// ============================================================================
// MDR THREAT INTELLIGENCE
// ============================================================================

export const mdrThreatIntelAPI = {
  getFeeds: () => api.get('/mdr-threat-intel/feeds'),
  createFeed: (data) => api.post('/mdr-threat-intel/feeds', data),
  getActors: () => api.get('/mdr-threat-intel/actors'),
  getIOCs: () => api.get('/mdr-threat-intel/iocs'),
  getStats: () => api.get('/mdr-threat-intel/stats'),
};

// ============================================================================
// MDR MULTI-TENANCY
// ============================================================================

export const mdrMultiTenancyAPI = {
  getTenants: () => api.get('/mdr-tenants/'),
  createTenant: (data) => api.post('/mdr-tenants/', data),
  getTenant: (id) => api.get(`/mdr-tenants/${id}`),
  updateTenant: (id, data) => api.put(`/mdr-tenants/${id}`, data),
  getTenantConfig: (id) => api.get(`/mdr-tenants/${id}/config`),
  getStats: () => api.get('/mdr-tenants/stats'),
};


// ============================================================================
// ADVANCED THREAT HUNTING (MDR Phase 3)
// ============================================================================

export const advancedHuntingAPI = {
  getCampaigns: () => api.get('/advanced-hunting/campaigns'),
  createCampaign: (data) => api.post('/advanced-hunting/campaigns', data),
  getCampaign: (id) => api.get(`/advanced-hunting/campaigns/${id}`),
  getQueries: (campaignId) => api.get('/advanced-hunting/queries', { params: { campaign_id: campaignId } }),
  createQuery: (data) => api.post('/advanced-hunting/queries', data),
  getNotebooks: () => api.get('/advanced-hunting/notebooks'),
  createNotebook: (data) => api.post('/advanced-hunting/notebooks', data),
  getMetrics: () => api.get('/advanced-hunting/metrics'),
  getMITRECoverage: () => api.get('/advanced-hunting/mitre-coverage'),
};

// ============================================================================
// DECEPTION TECHNOLOGY (MDR Phase 3)
// ============================================================================

export const deceptionAPI = {
  getHoneypots: () => api.get('/deception/honeypots'),
  createHoneypot: (data) => api.post('/deception/honeypots', data),
  getHoneytokens: () => api.get('/deception/honeytokens'),
  createHoneytoken: (data) => api.post('/deception/honeytokens', data),
  getDecoys: () => api.get('/deception/decoys'),
  getActivity: () => api.get('/deception/activity'),
  getMetrics: () => api.get('/deception/metrics'),
};

// ============================================================================
// INTEGRATIONS
// ============================================================================

export const integrationsAPI = {
  // List all integrations
  list: (params) => api.get('/integrations/', { params }),
  
  // Get integration details
  get: (id) => api.get(`/integrations/${id}`),
  
  // Create new integration
  create: (integration) => api.post('/integrations/', integration),
  
  // Update integration
  update: (id, updates) => api.put(`/integrations/${id}`, updates),
  
  // Delete integration
  delete: (id) => api.delete(`/integrations/${id}`),
  
  // Test integration connection
  test: (id) => api.post(`/integrations/${id}/test`),
  
  // Sync integration data
  sync: (id) => api.post(`/integrations/${id}/sync`),
  
  // Get integration logs
  getLogs: (id) => api.get(`/integrations/${id}/logs`),
  
  // Get integration templates
  getTemplates: (params) => api.get('/integrations/templates', { params }),
  
  // Get integration statistics
  getStats: () => api.get('/integrations/stats'),
};

// ============================================================================
// SYSTEM LOGS & DIAGNOSTICS API
// ============================================================================

export const systemLogsAPI = {
  // Get system logs
  getLogs: (params) => api.get('/system/logs', { params }),
  
  // Add manual log entry
  addLog: (log) => api.post('/system/logs', log),
  
  // Clear all logs
  clearLogs: () => api.delete('/system/logs'),
  
  // Get system status
  getStatus: () => api.get('/system/status'),
  
  // Get system configuration (sanitized)
  getConfig: () => api.get('/system/config'),
};

// ============================================================================
// PLA - PROTECTION LEVEL AGREEMENTS API
// Risk Matrix with Guard Rails Assessment
// ============================================================================

export const plaAPI = {
  // Dashboard
  getDashboard: () => api.get('/pla/dashboard'),
  getConfig: () => api.get('/pla/config'),
  
  // Risk Calculator
  calculateRisk: (params) => api.post('/pla/calculate', params),
  
  // Assessments
  getAssessments: (params) => api.get('/pla/assessments', { params }),
  createAssessment: (data) => api.post('/pla/assessments', data),
  getAssessment: (id) => api.get(`/pla/assessments/${id}`),
  updateAssessment: (id, data) => api.put(`/pla/assessments/${id}`, data),
  addGuardRail: (id, guardRail) => api.post(`/pla/assessments/${id}/guard-rails`, guardRail),
  
  // Guard Rails Catalog
  getGuardRails: (params) => api.get('/pla/guard-rails', { params }),
};

// ============================================================================
// CLOUDFLARE WAF INTEGRATION API
// Pull-based integration with Cloudflare Web Application Firewall
// ============================================================================

// ============================================================================
// JUMPCLOUD INTEGRATION API
// Pull-based integration with JumpCloud Directory Insights
// ============================================================================

export const jumpcloudAPI = {
  getStatus: () => api.get('/jumpcloud/status'),
  getConfig: () => api.get('/jumpcloud/config'),
  saveConfig: (config) => api.post('/jumpcloud/config', config),
  testConnection: (params) => api.post('/jumpcloud/test', params),
  sync: () => api.post('/jumpcloud/sync'),
  getEvents: (filters = {}, page = 0, perPage = 500) => api.get('/jumpcloud/events', {
    params: { ...filters, page, per_page: perPage }
  }),
  getStats: () => api.get('/jumpcloud/stats'),
  runDiagnostic: () => api.get('/jumpcloud/diagnostic'),
};

export const cloudflareAPI = {
  // Status da integração
  getStatus: () => api.get('/cloudflare/status'),
  
  // Configuração
  getConfig: () => api.get('/cloudflare/config'),
  saveConfig: (config) => api.post('/cloudflare/config', config),
  
  // Zonas disponíveis
  getZones: () => api.get('/cloudflare/zones'),
  
  // Testar conexão
  testConnection: (params) => api.post('/cloudflare/test', params),
  
  // Sincronização manual
  sync: () => api.post('/cloudflare/sync'),
  
  // Eventos WAF (com paginação)
  getEvents: (filters = {}, page = 0, perPage = 500) => api.get('/cloudflare/events', { 
    params: { ...filters, page, per_page: perPage } 
  }),
  
  // Estatísticas
  getStats: () => api.get('/cloudflare/stats'),
  
  // Diagnóstico completo - testa todas as APIs
  runDiagnostic: () => api.get('/cloudflare/diagnostic'),
};
