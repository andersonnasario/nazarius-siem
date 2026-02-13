import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Paper, Typography, Grid, Card, CardContent, Button, TextField,
  Switch, FormControlLabel, Chip, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, CircularProgress, Alert, AlertTitle, Dialog, DialogTitle,
  DialogContent, DialogActions, IconButton, Tabs, Tab, Select, MenuItem,
  FormControl, InputLabel, Divider, List, ListItem, ListItemText, ListItemIcon,
  Tooltip, TablePagination, InputAdornment, Checkbox, FormGroup, Snackbar,
} from '@mui/material';
import {
  Security as SecurityIcon, CheckCircle as CheckCircleIcon,
  Refresh as RefreshIcon, Settings as SettingsIcon, Visibility as VisibilityIcon,
  PlayArrow as PlayIcon, TrendingUp as TrendingIcon, Timeline as TimelineIcon,
  FilterList as FilterIcon, Info as InfoIcon, Error as ErrorIcon,
  Link as LinkIcon, Search as SearchIcon, NavigateBefore as PrevIcon,
  NavigateNext as NextIcon, FirstPage as FirstPageIcon, LastPage as LastPageIcon,
  Person as PersonIcon, VpnKey as VpnKeyIcon, Block as BlockIcon,
  Warning as WarningIcon, Radar as RadarIcon, GppBad as MaliciousIcon,
  GppMaybe as SuspiciousIcon, GppGood as CleanIcon, Dns as DnsIcon,
  Category as CategoryIcon, Public as PublicIcon, Shield as ShieldIcon,
  Language as LanguageIcon,
  Assignment as AssignmentIcon,
} from '@mui/icons-material';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell,
} from 'recharts';
import { jumpcloudAPI, threatIntelAPI, casesAPI, usersAPI } from '../services/api';
import { useAuth } from '../contexts/AuthContext';

const SEVERITY_COLORS = { CRITICAL: '#d32f2f', HIGH: '#f44336', MEDIUM: '#ff9800', LOW: '#4caf50', INFO: '#2196f3' };
const SERVICE_COLORS = {
  directory: '#1976d2', sso: '#9c27b0', radius: '#ff9800', systems: '#4caf50',
  ldap: '#00bcd4', mdm: '#795548', alerts: '#f44336', software: '#607d8b',
  password_manager: '#e91e63', all: '#455a64',
};
const PIE_COLORS = ['#1976d2', '#9c27b0', '#ff9800', '#4caf50', '#00bcd4', '#795548', '#f44336', '#607d8b', '#e91e63', '#455a64'];

const ALL_SERVICES = ['all', 'directory', 'sso', 'radius', 'systems', 'ldap', 'mdm', 'alerts', 'software', 'password_manager'];

function TabPanel({ children, value, index, ...other }) {
  return (<div hidden={value !== index} {...other}>{value === index && <Box sx={{ pt: 3 }}>{children}</Box>}</div>);
}

const JumpCloudIntegration = () => {
  const { user } = useAuth();
  const isAdmin = user?.role_name?.toLowerCase() === 'admin';
  const currentUserName = user?.full_name || user?.username || '';

  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [analysts, setAnalysts] = useState([]);
  const [testing, setTesting] = useState(false);

  const [status, setStatus] = useState(null);
  const [config, setConfig] = useState({
    client_id: '', client_secret: '', org_id: '', enabled: false, sync_period_minutes: 5, services: ['all'],
  });
  const [events, setEvents] = useState([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [eventsPage, setEventsPage] = useState(0);
  const [eventsPerPage] = useState(500);
  const [totalPages, setTotalPages] = useState(0);
  const [stats, setStats] = useState(null);
  const [filters, setFilters] = useState({ service: '', event_type: '', success: '', severity: '', search: '' });

  const [testResult, setTestResult] = useState(null);
  const [configDialog, setConfigDialog] = useState(false);
  const [eventDetailDialog, setEventDetailDialog] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [ipReputation, setIpReputation] = useState(null);
  const [ipReputationLoading, setIpReputationLoading] = useState(false);
  const [ipReputationCache, setIpReputationCache] = useState({});

  // Create Case
  const [createCaseDialog, setCreateCaseDialog] = useState(false);
  const [creatingCase, setCreatingCase] = useState(false);
  const [newCase, setNewCase] = useState({ title: '', description: '', priority: 'medium', assignTo: '' });
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [statusRes, configRes, statsRes, eventsRes] = await Promise.all([
        jumpcloudAPI.getStatus(), jumpcloudAPI.getConfig(),
        jumpcloudAPI.getStats(), jumpcloudAPI.getEvents(filters, eventsPage, eventsPerPage),
      ]);
      setStatus(statusRes.data);
      setConfig(prev => ({ ...prev, ...configRes.data, client_secret: '' }));
      setStats(statsRes.data);
      setEvents(eventsRes.data.events || []);
      setTotalEvents(eventsRes.data.total || 0);
      setTotalPages(eventsRes.data.total_pages || 0);
    } catch (error) {
      console.error('Erro ao carregar dados:', error);
    } finally {
      setLoading(false);
    }
  }, [filters, eventsPage, eventsPerPage]);

  useEffect(() => { loadData(); const iv = setInterval(loadData, 60000); return () => clearInterval(iv); }, [loadData]);

  // Carregar lista de analistas uma vez
  useEffect(() => {
    const loadAnalysts = async () => {
      try {
        const response = await usersAPI.list();
        const userList = response.data?.users || response.data?.data || [];
        setAnalysts(Array.isArray(userList) ? userList : []);
      } catch (error) { console.error('Erro ao carregar analistas:', error); }
    };
    loadAnalysts();
  }, []);

  const handleTestConnection = async () => {
    setTesting(true); setTestResult(null);
    try {
      const response = await jumpcloudAPI.testConnection({
        client_id: config.client_id || undefined,
        client_secret: config.client_secret || undefined,
        org_id: config.org_id || undefined,
      });
      setTestResult(response.data);
    } catch (error) {
      setTestResult({ success: false, error: error.response?.data?.error || error.message });
    } finally { setTesting(false); }
  };

  const handleSaveConfig = async () => {
    setSaving(true);
    try {
      await jumpcloudAPI.saveConfig(config);
      setConfigDialog(false); loadData();
    } catch (error) { console.error('Erro ao salvar:', error); }
    finally { setSaving(false); }
  };

  const handleSync = async () => {
    setSyncing(true);
    try { await jumpcloudAPI.sync(); setTimeout(loadData, 3000); }
    catch (error) { console.error('Erro ao sincronizar:', error); }
    finally { setSyncing(false); }
  };

  const handleViewEvent = (event) => {
    setSelectedEvent(event); setEventDetailDialog(true);
    if (event.client_ip && ipReputationCache[event.client_ip]) {
      setIpReputation(ipReputationCache[event.client_ip]);
    } else { setIpReputation(null); }
  };

  const handleCheckIPReputation = async (ip) => {
    if (!ip) return;
    if (ipReputationCache[ip]) { setIpReputation(ipReputationCache[ip]); return; }
    setIpReputationLoading(true); setIpReputation(null);
    try {
      const response = await threatIntelAPI.enrichIP(ip);
      setIpReputation(response.data);
      setIpReputationCache(prev => ({ ...prev, [ip]: response.data }));
    } catch (error) {
      try {
        const response = await threatIntelAPI.checkIP(ip);
        const repData = { ip, isMalicious: response.data.score > 50, reputation: response.data, matchedIOCs: [], riskScore: response.data.score || 0, sources: response.data.source ? [response.data.source] : [] };
        setIpReputation(repData); setIpReputationCache(prev => ({ ...prev, [ip]: repData }));
      } catch (err2) { setIpReputation({ error: 'Nao foi possivel consultar reputacao deste IP' }); }
    } finally { setIpReputationLoading(false); }
  };

  // Abrir dialog de criar caso a partir de evento JumpCloud
  const handleOpenCreateCase = (event) => {
    setSelectedEvent(event);
    const severity = (event.severity || 'LOW').toUpperCase();
    const priority = severity === 'CRITICAL' ? 'critical' : severity === 'HIGH' ? 'high' : severity === 'MEDIUM' ? 'medium' : 'low';
    setNewCase({
      title: `[JumpCloud] ${event.event_type || 'Event'} - ${event.username || event.client_ip || 'Unknown'}`,
      description: `Evento detectado pelo JumpCloud Directory Insights:\n\n` +
        `- Tipo: ${event.event_type || '-'}\n` +
        `- Servico: ${event.service || '-'}\n` +
        `- Usuario: ${event.username || '-'}\n` +
        `- IP Origem: ${event.client_ip || '-'}\n` +
        `- Pais: ${event.country_code || '-'}\n` +
        `- Resultado: ${event.success === true ? 'Sucesso' : event.success === false ? 'Falha' : '-'}\n` +
        `- MFA: ${event.mfa ? 'Sim' : 'Nao'}\n` +
        `- Recurso: ${event.resource_type || '-'} ${event.resource_name || event.resource_id || ''}\n` +
        `- Iniciado por: ${event.initiated_by_email || '-'}\n` +
        `- Severidade: ${event.severity || '-'}\n` +
        `- Timestamp: ${event.timestamp || '-'}`,
      priority,
      assignTo: isAdmin ? '' : currentUserName,
    });
    setCreateCaseDialog(true);
  };

  const handleCreateCase = async () => {
    if (!newCase.title) return;
    setCreatingCase(true);
    try {
      const caseData = {
        title: newCase.title,
        description: newCase.description,
        priority: newCase.priority,
        assign_to: newCase.assignTo,
        source: 'jumpcloud',
        source_ref: selectedEvent?.event_id || selectedEvent?._id || '',
        tags: ['jumpcloud', selectedEvent?.service || '', selectedEvent?.event_type || ''].filter(Boolean),
      };
      const response = await casesAPI.create(caseData);
      const caseId = response.data?.data?.id || response.data?.id || 'N/A';
      setSnackbar({ open: true, message: `Caso criado com sucesso! ID: ${caseId}`, severity: 'success' });
      setCreateCaseDialog(false);
      setNewCase({ title: '', description: '', priority: 'medium', assignTo: '' });
    } catch (error) {
      console.error('Erro ao criar caso:', error);
      setSnackbar({ open: true, message: 'Erro ao criar caso: ' + (error.response?.data?.error || error.message), severity: 'error' });
    } finally {
      setCreatingCase(false);
    }
  };

  const formatDate = (dateStr) => { if (!dateStr) return '-'; return new Date(dateStr).toLocaleString('pt-BR'); };
  const getRiskColor = (score) => { if (score >= 75) return '#f44336'; if (score >= 50) return '#ff9800'; if (score >= 25) return '#ffeb3b'; return '#4caf50'; };
  const getRiskLabel = (score) => { if (score >= 75) return 'Critico'; if (score >= 50) return 'Alto'; if (score >= 25) return 'Medio'; return 'Baixo'; };

  const renderSeverityChip = (severity) => (
    <Chip label={severity} size="small" sx={{ bgcolor: SEVERITY_COLORS[severity] || '#9e9e9e', color: 'white', fontWeight: 'bold' }} />
  );
  const renderServiceChip = (service) => (
    <Chip label={service} size="small" sx={{ bgcolor: SERVICE_COLORS[service] || '#607d8b', color: 'white' }} />
  );
  const renderSuccessChip = (success) => (
    <Chip label={success ? 'OK' : 'FALHA'} size="small" color={success ? 'success' : 'error'} variant="outlined" />
  );

  const toggleService = (svc) => {
    setConfig(prev => {
      let services = [...(prev.services || [])];
      if (svc === 'all') return { ...prev, services: ['all'] };
      services = services.filter(s => s !== 'all');
      if (services.includes(svc)) { services = services.filter(s => s !== svc); }
      else { services.push(svc); }
      if (services.length === 0) services = ['all'];
      return { ...prev, services };
    });
  };

  if (loading && !status) {
    return (<Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}><CircularProgress /></Box>);
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <PersonIcon sx={{ fontSize: 40, color: '#36b37e' }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">JumpCloud Integration</Typography>
            <Typography variant="body2" color="text.secondary">Monitoramento de eventos de diretorio, autenticacao e identidade</Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={loadData} disabled={loading}>Atualizar</Button>
          <Button variant="contained" startIcon={<PlayIcon />} onClick={handleSync} disabled={syncing} color="success">
            {syncing ? 'Sincronizando...' : 'Sincronizar Agora'}
          </Button>
          <Button variant="contained" startIcon={<SettingsIcon />} onClick={() => setConfigDialog(true)} color="primary">Configurar</Button>
        </Box>
      </Box>

      {/* Status Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card sx={{ bgcolor: status?.configured ? '#2e7d32' : '#616161', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {status?.configured ? <CheckCircleIcon /> : <ErrorIcon />}
                <Typography variant="h6">Status</Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>{status?.configured ? 'Configurado' : 'Pendente'}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.8 }}>{status?.enabled ? 'Coleta ativa' : 'Coleta inativa'}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card sx={{ bgcolor: '#1a237e', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><TimelineIcon /><Typography variant="h6">Eventos (24h)</Typography></Box>
              <Typography variant="h4" sx={{ mt: 1 }}>{stats?.total_events?.toLocaleString() || 0}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.8 }}>Total de eventos coletados</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card sx={{ bgcolor: '#b71c1c', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><BlockIcon /><Typography variant="h6">Falhas de Login</Typography></Box>
              <Typography variant="h4" sx={{ mt: 1 }}>{stats?.failed_logins?.toLocaleString() || 0}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.8 }}>Autenticacoes com falha (24h)</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card sx={{ bgcolor: '#4a148c', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><VpnKeyIcon /><Typography variant="h6">MFA</Typography></Box>
              <Typography variant="h4" sx={{ mt: 1 }}>{stats?.mfa_events?.toLocaleString() || 0}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.8 }}>Eventos com MFA (24h)</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Last sync info */}
      {status?.last_sync && status.last_sync !== '0001-01-01T00:00:00Z' && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>Ultima Sincronizacao</AlertTitle>
          {formatDate(status.last_sync)} - {status.events_collected?.toLocaleString() || 0} eventos coletados desde o inicio
        </Alert>
      )}

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tab label="Dashboard" icon={<TrendingIcon />} iconPosition="start" />
          <Tab label="Eventos" icon={<SecurityIcon />} iconPosition="start" />
          <Tab label="Analise" icon={<TimelineIcon />} iconPosition="start" />
        </Tabs>

        {/* Dashboard Tab */}
        <TabPanel value={activeTab} index={0}>
          <Box sx={{ p: 2 }}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}><Typography variant="h6" gutterBottom>Eventos por Servico</Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie data={(stats?.by_service || []).map((item, i) => ({ name: item.key, value: item.doc_count, fill: PIE_COLORS[i % PIE_COLORS.length] }))}
                        dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100} label={({ name, value }) => `${name}: ${value}`}>
                        {(stats?.by_service || []).map((_, i) => (<Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />))}
                      </Pie>
                      <RechartsTooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}><Typography variant="h6" gutterBottom>Eventos por Severidade</Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={(stats?.by_severity || []).map(item => ({ name: item.key, value: item.doc_count }))}>
                      <CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="name" /><YAxis /><RechartsTooltip />
                      <Bar dataKey="value" fill="#36b37e" />
                    </BarChart>
                  </ResponsiveContainer>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}><Typography variant="h6" gutterBottom>Top 10 Usuarios</Typography>
                  <TableContainer><Table size="small">
                    <TableHead><TableRow><TableCell>Usuario</TableCell><TableCell align="right">Eventos</TableCell></TableRow></TableHead>
                    <TableBody>
                      {(stats?.top_users || []).map((item, i) => (
                        <TableRow key={i}><TableCell>{item.key || 'N/A'}</TableCell><TableCell align="right">{item.doc_count}</TableCell></TableRow>
                      ))}
                    </TableBody>
                  </Table></TableContainer>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}><Typography variant="h6" gutterBottom>Top 10 IPs</Typography>
                  <TableContainer><Table size="small">
                    <TableHead><TableRow><TableCell>IP</TableCell><TableCell align="right">Eventos</TableCell></TableRow></TableHead>
                    <TableBody>
                      {(stats?.top_ips || []).map((item, i) => (
                        <TableRow key={i}><TableCell sx={{ fontFamily: 'monospace' }}>{item.key || 'N/A'}</TableCell><TableCell align="right">{item.doc_count}</TableCell></TableRow>
                      ))}
                    </TableBody>
                  </Table></TableContainer>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        {/* Events Tab */}
        <TabPanel value={activeTab} index={1}>
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap', alignItems: 'center' }}>
              <TextField size="small" placeholder="Buscar por usuario, IP, tipo, aplicacao..." value={filters.search}
                onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
                onKeyDown={(e) => { if (e.key === 'Enter') { setEventsPage(0); loadData(); } }}
                sx={{ minWidth: 300, flexGrow: 1 }}
                InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon /></InputAdornment> }}
              />
              <FormControl size="small" sx={{ minWidth: 130 }}>
                <InputLabel>Servico</InputLabel>
                <Select value={filters.service} label="Servico" onChange={(e) => { setFilters(prev => ({ ...prev, service: e.target.value })); setEventsPage(0); }}>
                  <MenuItem value="">Todos</MenuItem>
                  {ALL_SERVICES.filter(s => s !== 'all').map(s => (<MenuItem key={s} value={s}>{s}</MenuItem>))}
                </Select>
              </FormControl>
              <FormControl size="small" sx={{ minWidth: 120 }}>
                <InputLabel>Resultado</InputLabel>
                <Select value={filters.success} label="Resultado" onChange={(e) => { setFilters(prev => ({ ...prev, success: e.target.value })); setEventsPage(0); }}>
                  <MenuItem value="">Todos</MenuItem><MenuItem value="true">Sucesso</MenuItem><MenuItem value="false">Falha</MenuItem>
                </Select>
              </FormControl>
              <FormControl size="small" sx={{ minWidth: 120 }}>
                <InputLabel>Severidade</InputLabel>
                <Select value={filters.severity} label="Severidade" onChange={(e) => { setFilters(prev => ({ ...prev, severity: e.target.value })); setEventsPage(0); }}>
                  <MenuItem value="">Todas</MenuItem><MenuItem value="CRITICAL">Critica</MenuItem><MenuItem value="HIGH">Alta</MenuItem>
                  <MenuItem value="MEDIUM">Media</MenuItem><MenuItem value="LOW">Baixa</MenuItem><MenuItem value="INFO">Info</MenuItem>
                </Select>
              </FormControl>
              <Button variant="contained" startIcon={<FilterIcon />} onClick={() => { setEventsPage(0); loadData(); }}>Filtrar</Button>
              {(filters.service || filters.success || filters.severity || filters.search) && (
                <Button variant="outlined" size="small" onClick={() => { setFilters({ service: '', event_type: '', success: '', severity: '', search: '' }); setEventsPage(0); }}>Limpar</Button>
              )}
            </Box>

            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="body2" color="text.secondary">
                {totalEvents > 0 ? `Exibindo ${eventsPage * eventsPerPage + 1} - ${Math.min((eventsPage + 1) * eventsPerPage, totalEvents)} de ${totalEvents.toLocaleString()} eventos` : 'Nenhum evento encontrado'}
              </Typography>
              {totalPages > 1 && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <IconButton size="small" disabled={eventsPage === 0} onClick={() => setEventsPage(0)}><FirstPageIcon /></IconButton>
                  <IconButton size="small" disabled={eventsPage === 0} onClick={() => setEventsPage(p => p - 1)}><PrevIcon /></IconButton>
                  <Typography variant="body2">Pagina {eventsPage + 1} de {totalPages}</Typography>
                  <IconButton size="small" disabled={eventsPage >= totalPages - 1} onClick={() => setEventsPage(p => p + 1)}><NextIcon /></IconButton>
                  <IconButton size="small" disabled={eventsPage >= totalPages - 1} onClick={() => setEventsPage(totalPages - 1)}><LastPageIcon /></IconButton>
                </Box>
              )}
            </Box>

            <TableContainer component={Paper} sx={{ maxHeight: 'calc(100vh - 420px)' }}>
              <Table stickyHeader size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 'bold' }}>Timestamp</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Servico</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Tipo</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Usuario</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>IP</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Pais</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Resultado</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>MFA</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Severidade</TableCell>
                    <TableCell align="center" sx={{ fontWeight: 'bold' }}>Detalhes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {events.length === 0 ? (
                    <TableRow><TableCell colSpan={10} align="center"><Typography color="text.secondary" sx={{ py: 3 }}>Nenhum evento encontrado. Clique em "Sincronizar Agora" para coletar eventos.</Typography></TableCell></TableRow>
                  ) : events.map((event, index) => (
                    <TableRow key={event.event_id || event._id || index} hover>
                      <TableCell><Typography variant="body2" sx={{ whiteSpace: 'nowrap', fontSize: '0.8rem' }}>{formatDate(event.timestamp)}</Typography></TableCell>
                      <TableCell>{renderServiceChip(event.service)}</TableCell>
                      <TableCell><Typography variant="body2" sx={{ fontSize: '0.8rem' }}>{event.event_type}</Typography></TableCell>
                      <TableCell><Typography variant="body2" sx={{ fontSize: '0.8rem' }}>{event.username || event.initiated_by_email || '-'}</Typography></TableCell>
                      <TableCell><Typography variant="body2" fontFamily="monospace" sx={{ fontSize: '0.8rem' }}>{event.client_ip || '-'}</Typography></TableCell>
                      <TableCell><Typography variant="body2" sx={{ fontSize: '0.8rem' }}>{event.country_code || '-'}</Typography></TableCell>
                      <TableCell>{event.success !== undefined ? renderSuccessChip(event.success) : '-'}</TableCell>
                      <TableCell>{event.mfa ? <Chip label="MFA" size="small" color="info" variant="outlined" /> : '-'}</TableCell>
                      <TableCell>{renderSeverityChip(event.severity)}</TableCell>
                      <TableCell align="center">
                        <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'center' }}>
                          {event.client_ip && (
                            <Tooltip title="Analisar IP"><IconButton size="small" onClick={() => { handleViewEvent(event); handleCheckIPReputation(event.client_ip); }}
                              sx={{ color: ipReputationCache[event.client_ip] ? getRiskColor(ipReputationCache[event.client_ip].riskScore || 0) : 'text.secondary' }}><RadarIcon fontSize="small" /></IconButton></Tooltip>
                          )}
                          <Tooltip title="Detalhes"><IconButton size="small" onClick={() => handleViewEvent(event)}><VisibilityIcon fontSize="small" /></IconButton></Tooltip>
                          <Tooltip title="Abrir Caso"><IconButton size="small" onClick={() => handleOpenCreateCase(event)} sx={{ color: '#ff9800' }}><AssignmentIcon fontSize="small" /></IconButton></Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            {totalEvents > 0 && (
              <TablePagination component="div" count={totalEvents} page={eventsPage} onPageChange={(e, p) => setEventsPage(p)}
                rowsPerPage={eventsPerPage} rowsPerPageOptions={[500]}
                labelDisplayedRows={({ from, to, count }) => `${from}-${to} de ${count !== -1 ? count.toLocaleString() : `mais de ${to}`}`} labelRowsPerPage="Por pagina:" />
            )}
          </Box>
        </TabPanel>

        {/* Analysis Tab */}
        <TabPanel value={activeTab} index={2}>
          <Box sx={{ p: 2 }}>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Paper sx={{ p: 2 }}><Typography variant="h6" gutterBottom>Top Tipos de Evento (24h)</Typography>
                  <ResponsiveContainer width="100%" height={350}>
                    <BarChart data={(stats?.by_event_type || []).slice(0, 15).map(item => ({ name: item.key?.substring(0, 30) || 'Unknown', value: item.doc_count }))} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" /><XAxis type="number" /><YAxis dataKey="name" type="category" width={220} tick={{ fontSize: 11 }} /><RechartsTooltip />
                      <Bar dataKey="value" fill="#36b37e" />
                    </BarChart>
                  </ResponsiveContainer>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}><Typography variant="h6" gutterBottom>Sucesso vs Falha (24h)</Typography>
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie data={(stats?.by_success || []).map((item) => ({ name: item.key === 'true' || item.key === true ? 'Sucesso' : 'Falha', value: item.doc_count }))}
                        dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                        <Cell fill="#4caf50" /><Cell fill="#f44336" />
                      </Pie>
                      <RechartsTooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}><Typography variant="h6" gutterBottom>Informacoes da Integracao</Typography>
                  <List dense>
                    <ListItem><ListItemIcon><InfoIcon /></ListItemIcon><ListItemText primary="API" secondary="JumpCloud Directory Insights v1" /></ListItem>
                    <ListItem><ListItemIcon><InfoIcon /></ListItemIcon><ListItemText primary="Retencao" secondary="90 dias (JumpCloud)" /></ListItem>
                    <ListItem><ListItemIcon><InfoIcon /></ListItemIcon><ListItemText primary="Metodo" secondary="Pull (POST /insights/directory/v1/events)" /></ListItem>
                    <ListItem><ListItemIcon><InfoIcon /></ListItemIcon><ListItemText primary="Servicos" secondary={status?.services?.join(', ') || 'all'} /></ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>
      </Paper>

      {/* Config Dialog */}
      <Dialog open={configDialog} onClose={() => setConfigDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><SettingsIcon />Configuracao da Integracao JumpCloud</Box></DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Como obter as credenciais (Service Account)</AlertTitle>
              1. Acesse o <a href="https://console.jumpcloud.com" target="_blank" rel="noreferrer">JumpCloud Admin Portal</a><br />
              2. Va em <strong>Settings &gt; Service Accounts</strong><br />
              3. Clique em <strong>+ New</strong>, defina um nome (ex: siem-nazarius) e selecione a Role<br />
              4. Em <strong>Key Type</strong>, selecione <strong>Client Secret</strong><br />
              5. Copie o <strong>Client ID</strong> e o <strong>Client Secret</strong> gerados<br />
              <em>Importante: O Client Secret so e exibido uma vez na criacao.</em>
            </Alert>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField fullWidth label="Client ID" value={config.client_id}
                  onChange={(e) => setConfig(prev => ({ ...prev, client_id: e.target.value }))}
                  placeholder="sa_xxxxxxxxxxxxxxxxxxxxxxxx"
                  helperText={config.credentials_configured ? `Client ID atual: ${config.client_id}` : 'ID da Service Account (formato: sa_...)'} />
              </Grid>
              <Grid item xs={12}>
                <TextField fullWidth label="Client Secret" type="password" value={config.client_secret}
                  onChange={(e) => setConfig(prev => ({ ...prev, client_secret: e.target.value }))}
                  placeholder={config.credentials_configured ? 'Secret ja configurado (deixe em branco para manter)' : 'Cole o Client Secret aqui'}
                  helperText={config.credentials_configured ? 'Deixe em branco para manter o secret atual' : 'Secret gerado na criacao da Service Account'} />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField fullWidth label="Org ID (opcional)" value={config.org_id}
                  onChange={(e) => setConfig(prev => ({ ...prev, org_id: e.target.value }))}
                  placeholder="Apenas para MSP/Multi-tenant" helperText="Necessario apenas para Managed Service Providers" />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField fullWidth label="Intervalo de Sincronizacao (minutos)" type="number" value={config.sync_period_minutes}
                  onChange={(e) => setConfig(prev => ({ ...prev, sync_period_minutes: parseInt(e.target.value) || 5 }))}
                  inputProps={{ min: 1, max: 60 }} />
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" gutterBottom>Servicos a Monitorar</Typography>
                <FormGroup row>
                  {ALL_SERVICES.map(svc => (
                    <FormControlLabel key={svc} control={<Checkbox checked={(config.services || []).includes(svc) || (config.services || []).includes('all')}
                      onChange={() => toggleService(svc)} disabled={svc !== 'all' && (config.services || []).includes('all')} />}
                      label={svc === 'all' ? 'Todos' : svc} />
                  ))}
                </FormGroup>
              </Grid>
              <Grid item xs={12}>
                <Button variant="outlined" startIcon={testing ? <CircularProgress size={16} /> : <PlayIcon />}
                  onClick={handleTestConnection} disabled={testing}>
                  {testing ? 'Testando...' : 'Testar Conexao'}
                </Button>
              </Grid>
              {testResult && (
                <Grid item xs={12}>
                  <Alert severity={testResult.success ? 'success' : 'error'}>
                    {testResult.success ? testResult.message : testResult.error}
                  </Alert>
                </Grid>
              )}
              <Grid item xs={12}>
                <FormControlLabel control={<Switch checked={config.enabled} onChange={(e) => setConfig(prev => ({ ...prev, enabled: e.target.checked })) } color="primary" />}
                  label="Habilitar coleta automatica de eventos" />
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigDialog(false)}>Cancelar</Button>
          <Button variant="contained" onClick={handleSaveConfig} disabled={saving}>{saving ? 'Salvando...' : 'Salvar'}</Button>
        </DialogActions>
      </Dialog>

      {/* Event Detail Dialog */}
      <Dialog open={eventDetailDialog} onClose={() => { setEventDetailDialog(false); setIpReputation(null); }} maxWidth="lg" fullWidth>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><SecurityIcon color="primary" />Detalhes do Evento JumpCloud</Box>
            {selectedEvent && <Chip label={selectedEvent.event_type} size="small" color="primary" variant="outlined" />}
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedEvent && (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={3}>
                <Grid item xs={12} md={7}>
                  <Typography variant="subtitle1" fontWeight="bold" gutterBottom>Informacoes do Evento</Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Timestamp</Typography><Typography variant="body1">{formatDate(selectedEvent.timestamp)}</Typography></Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Servico</Typography>{renderServiceChip(selectedEvent.service)}</Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Tipo de Evento</Typography><Typography variant="body1" fontFamily="monospace">{selectedEvent.event_type}</Typography></Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Resultado</Typography>{selectedEvent.success !== undefined ? renderSuccessChip(selectedEvent.success) : '-'}</Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Usuario</Typography><Typography variant="body1">{selectedEvent.username || '-'}</Typography></Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">MFA</Typography>{selectedEvent.mfa ? <Chip label="Ativo" size="small" color="success" /> : <Chip label="Nao" size="small" variant="outlined" />}</Grid>
                    <Grid item xs={12}><Divider /></Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Iniciado Por</Typography><Typography variant="body2">{selectedEvent.initiated_by_email || '-'} ({selectedEvent.initiated_by_type || '-'})</Typography></Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Metodo Auth</Typography><Typography variant="body2">{selectedEvent.auth_method || '-'}</Typography></Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Recurso</Typography><Typography variant="body2">{selectedEvent.resource_type || '-'}: {selectedEvent.resource_name || selectedEvent.resource_id || '-'}</Typography></Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Aplicacao</Typography><Typography variant="body2">{selectedEvent.application_name || '-'}</Typography></Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Sistema/Host</Typography><Typography variant="body2">{selectedEvent.system_hostname || '-'}</Typography></Grid>
                    <Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">Severidade</Typography>{renderSeverityChip(selectedEvent.severity)}</Grid>
                    {selectedEvent.error_message && (<Grid item xs={12}><Typography variant="subtitle2" color="text.secondary">Mensagem de Erro</Typography><Alert severity="error" sx={{ mt: 0.5 }}>{selectedEvent.error_message}</Alert></Grid>)}
                    {selectedEvent.changes && selectedEvent.changes !== '[]' && selectedEvent.changes !== 'null' && (
                      <Grid item xs={12}><Typography variant="subtitle2" color="text.secondary">Alteracoes</Typography>
                        <Paper sx={{ p: 1, bgcolor: 'action.hover', mt: 0.5 }}><Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: 'break-all', fontSize: '0.75rem' }}>{selectedEvent.changes}</Typography></Paper>
                      </Grid>
                    )}
                  </Grid>
                </Grid>

                {/* IP Reputation */}
                <Grid item xs={12} md={5}>
                  <Paper sx={{ p: 2, bgcolor: 'background.default', height: '100%' }}>
                    <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 2 }}><RadarIcon sx={{ verticalAlign: 'middle', mr: 0.5, fontSize: 20 }} />Reputacao do IP</Typography>
                    {selectedEvent.client_ip ? (
                      <>
                        <Paper sx={{ p: 1.5, mb: 2, bgcolor: 'action.hover' }}>
                          <Typography variant="body2" fontFamily="monospace" fontWeight="bold" sx={{ fontSize: '1rem' }}>{selectedEvent.client_ip}</Typography>
                          <Typography variant="body2" color="text.secondary">{selectedEvent.country_code || ''} {selectedEvent.region ? `- ${selectedEvent.region}` : ''}</Typography>
                        </Paper>
                        {!ipReputation && !ipReputationLoading && (
                          <Button variant="contained" fullWidth startIcon={<RadarIcon />} onClick={() => handleCheckIPReputation(selectedEvent.client_ip)} sx={{ mb: 2 }} color="warning">Analisar Reputacao do IP</Button>
                        )}
                        {ipReputationLoading && (<Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 3 }}><CircularProgress size={40} /><Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>Consultando AbuseIPDB, VirusTotal...</Typography></Box>)}
                        {ipReputation?.error && <Alert severity="warning" sx={{ mb: 2 }}>{ipReputation.error}</Alert>}
                        {ipReputation && !ipReputation.error && (
                          <Box>
                            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 2, p: 2, borderRadius: 2,
                              bgcolor: `${getRiskColor(ipReputation.riskScore || ipReputation.reputation?.score || 0)}15`,
                              border: `2px solid ${getRiskColor(ipReputation.riskScore || ipReputation.reputation?.score || 0)}` }}>
                              <Box sx={{ textAlign: 'center' }}>
                                {(ipReputation.riskScore || 0) >= 50 ? <MaliciousIcon sx={{ fontSize: 36, color: getRiskColor(ipReputation.riskScore || 0) }} />
                                  : (ipReputation.riskScore || 0) >= 25 ? <SuspiciousIcon sx={{ fontSize: 36, color: getRiskColor(ipReputation.riskScore || 0) }} />
                                  : <CleanIcon sx={{ fontSize: 36, color: getRiskColor(ipReputation.riskScore || 0) }} />}
                                <Typography variant="h4" fontWeight="bold" sx={{ color: getRiskColor(ipReputation.riskScore || ipReputation.reputation?.score || 0) }}>{ipReputation.riskScore || ipReputation.reputation?.score || 0}/100</Typography>
                                <Typography variant="body2" fontWeight="bold" sx={{ color: getRiskColor(ipReputation.riskScore || 0) }}>Risco {getRiskLabel(ipReputation.riskScore || 0)}</Typography>
                                {ipReputation.isMalicious && <Chip label="MALICIOSO" size="small" color="error" sx={{ mt: 0.5 }} />}
                              </Box>
                            </Box>
                            <List dense disablePadding>
                              {ipReputation.reputation?.country && ipReputation.reputation.country !== 'Unknown' && (<ListItem disableGutters><ListItemIcon sx={{ minWidth: 32 }}><PublicIcon fontSize="small" /></ListItemIcon><ListItemText primary="Pais" secondary={ipReputation.reputation.country} /></ListItem>)}
                              {ipReputation.reputation?.isp && ipReputation.reputation.isp !== 'Unknown' && (<ListItem disableGutters><ListItemIcon sx={{ minWidth: 32 }}><DnsIcon fontSize="small" /></ListItemIcon><ListItemText primary="ISP" secondary={ipReputation.reputation.isp} /></ListItem>)}
                              {ipReputation.reputation?.isTor && (<ListItem disableGutters><ListItemIcon sx={{ minWidth: 32 }}><WarningIcon fontSize="small" color="error" /></ListItemIcon><ListItemText primary="Tor Exit Node" /></ListItem>)}
                              {ipReputation.reputation?.isVpn && (<ListItem disableGutters><ListItemIcon sx={{ minWidth: 32 }}><ShieldIcon fontSize="small" color="warning" /></ListItemIcon><ListItemText primary="VPN" /></ListItem>)}
                              {ipReputation.reputation?.isProxy && (<ListItem disableGutters><ListItemIcon sx={{ minWidth: 32 }}><LanguageIcon fontSize="small" color="warning" /></ListItemIcon><ListItemText primary="Proxy" /></ListItem>)}
                            </List>
                            {ipReputation.reputation?.categories?.length > 0 && (
                              <Box sx={{ mt: 1 }}><Typography variant="subtitle2" color="text.secondary" gutterBottom><CategoryIcon sx={{ verticalAlign: 'middle', mr: 0.5, fontSize: 16 }} />Categorias</Typography>
                                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{ipReputation.reputation.categories.map((cat, i) => (<Chip key={i} label={cat} size="small" color="error" variant="outlined" />))}</Box>
                              </Box>
                            )}
                            {ipReputation.matchedIOCs?.length > 0 && (
                              <Box sx={{ mt: 2 }}><Typography variant="subtitle2" color="text.secondary" gutterBottom><WarningIcon sx={{ verticalAlign: 'middle', mr: 0.5, fontSize: 16, color: '#f44336' }} />IOCs ({ipReputation.matchedIOCs.length})</Typography>
                                {ipReputation.matchedIOCs.map((ioc, i) => (<Alert key={i} severity="error" sx={{ mb: 0.5, py: 0 }}><Typography variant="body2" sx={{ fontSize: '0.75rem' }}><strong>{ioc.type}:</strong> {ioc.value}</Typography></Alert>))}
                              </Box>
                            )}
                            {ipReputation.sources?.length > 0 && <Box sx={{ mt: 1 }}><Typography variant="caption" color="text.secondary">Fontes: {ipReputation.sources.join(', ')}</Typography></Box>}
                          </Box>
                        )}
                        <Divider sx={{ my: 2 }} />
                        <Typography variant="subtitle2" color="text.secondary" gutterBottom>Consultar externamente</Typography>
                        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                          <Button size="small" variant="outlined" startIcon={<LinkIcon />} onClick={() => window.open(`https://www.abuseipdb.com/check/${selectedEvent.client_ip}`, '_blank')}>AbuseIPDB</Button>
                          <Button size="small" variant="outlined" startIcon={<LinkIcon />} onClick={() => window.open(`https://www.virustotal.com/gui/ip-address/${selectedEvent.client_ip}`, '_blank')}>VirusTotal</Button>
                          <Button size="small" variant="outlined" startIcon={<LinkIcon />} onClick={() => window.open(`https://www.shodan.io/host/${selectedEvent.client_ip}`, '_blank')}>Shodan</Button>
                        </Box>
                      </>
                    ) : (
                      <Typography variant="body2" color="text.secondary">Este evento nao possui IP de cliente registrado.</Typography>
                    )}
                  </Paper>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setEventDetailDialog(false); setIpReputation(null); }}>Fechar</Button>
          <Button variant="contained" color="warning" startIcon={<AssignmentIcon />}
            onClick={() => { setEventDetailDialog(false); setIpReputation(null); handleOpenCreateCase(selectedEvent); }}>
            Abrir Caso
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Criar Caso */}
      <Dialog open={createCaseDialog} onClose={() => setCreateCaseDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><AssignmentIcon color="warning" />Criar Caso a partir do Evento</Box></DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <TextField fullWidth label="Titulo do Caso" value={newCase.title}
              onChange={(e) => setNewCase(prev => ({ ...prev, title: e.target.value }))} sx={{ mb: 2 }} />
            <TextField fullWidth multiline rows={5} label="Descricao" value={newCase.description}
              onChange={(e) => setNewCase(prev => ({ ...prev, description: e.target.value }))} sx={{ mb: 2 }} />
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Prioridade</InputLabel>
              <Select value={newCase.priority} label="Prioridade"
                onChange={(e) => setNewCase(prev => ({ ...prev, priority: e.target.value }))}>
                <MenuItem value="critical">Critica</MenuItem>
                <MenuItem value="high">Alta</MenuItem>
                <MenuItem value="medium">Media</MenuItem>
                <MenuItem value="low">Baixa</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth>
              <InputLabel>Atribuir para</InputLabel>
              <Select value={newCase.assignTo} label="Atribuir para"
                onChange={(e) => setNewCase(prev => ({ ...prev, assignTo: e.target.value }))}>
                <MenuItem value=""><em>Nao atribuido</em></MenuItem>
                {analysts.map((a) => (
                  <MenuItem key={a.id || a.username} value={a.full_name || a.username}>
                    {a.full_name || a.username} {a.email ? `(${a.email})` : ''} {a.role_name ? `- ${a.role_name}` : ''}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            {!isAdmin && newCase.assignTo && (
              <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
                Pre-atribuido a voce. Selecione outro analista se necessario.
              </Typography>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateCaseDialog(false)} disabled={creatingCase}>Cancelar</Button>
          <Button variant="contained" color="primary" onClick={handleCreateCase}
            disabled={creatingCase || !newCase.title}>{creatingCase ? 'Criando...' : 'Criar Caso'}</Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar open={snackbar.open} autoHideDuration={6000} onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
        <Alert severity={snackbar.severity} onClose={() => setSnackbar(prev => ({ ...prev, open: false }))} variant="filled">
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default JumpCloudIntegration;
