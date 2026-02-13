import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  TextField,
  Switch,
  FormControlLabel,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  CircularProgress,
  Alert,
  AlertTitle,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tabs,
  Tab,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  LinearProgress,
  Tooltip,
  TablePagination,
  InputAdornment,
  Snackbar,
} from '@mui/material';
import {
  CloudQueue as CloudIcon,
  Security as SecurityIcon,
  Block as BlockIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Refresh as RefreshIcon,
  Settings as SettingsIcon,
  Visibility as VisibilityIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Public as PublicIcon,
  Language as LanguageIcon,
  Shield as ShieldIcon,
  Gavel as GavelIcon,
  TrendingUp as TrendingIcon,
  Timeline as TimelineIcon,
  FilterList as FilterIcon,
  ExpandMore as ExpandMoreIcon,
  Info as InfoIcon,
  Error as ErrorIcon,
  Link as LinkIcon,
  Search as SearchIcon,
  NavigateBefore as PrevIcon,
  NavigateNext as NextIcon,
  FirstPage as FirstPageIcon,
  LastPage as LastPageIcon,
  Radar as RadarIcon,
  GppBad as MaliciousIcon,
  GppMaybe as SuspiciousIcon,
  GppGood as CleanIcon,
  Dns as DnsIcon,
  ReportProblem as ReportIcon,
  Category as CategoryIcon,
  Assignment as AssignmentIcon,
} from '@mui/icons-material';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Legend,
} from 'recharts';
import { cloudflareAPI, threatIntelAPI, casesAPI, usersAPI } from '../services/api';
import { useAuth } from '../contexts/AuthContext';

const SEVERITY_COLORS = {
  HIGH: '#f44336',
  MEDIUM: '#ff9800',
  LOW: '#4caf50',
  INFO: '#2196f3',
};

const ACTION_COLORS = {
  block: '#f44336',
  drop: '#d32f2f',
  challenge: '#ff9800',
  js_challenge: '#ffa726',
  managed_challenge: '#ffb74d',
  skip: '#78909c',
  log: '#4caf50',
  allow: '#81c784',
};

const COUNTRY_FLAGS = {
  US: '🇺🇸', BR: '🇧🇷', CN: '🇨🇳', RU: '🇷🇺', DE: '🇩🇪',
  FR: '🇫🇷', GB: '🇬🇧', IN: '🇮🇳', JP: '🇯🇵', KR: '🇰🇷',
  NL: '🇳🇱', CA: '🇨🇦', AU: '🇦🇺', IT: '🇮🇹', ES: '🇪🇸',
};

function TabPanel({ children, value, index, ...other }) {
  return (
    <div hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

const CloudflareIntegration = () => {
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
    api_token: '',
    account_id: '',
    zone_ids: [],
    enabled: false,
    sync_period_minutes: 5,
  });
  const [zones, setZones] = useState([]);
  const [events, setEvents] = useState([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [eventsPage, setEventsPage] = useState(0);
  const [eventsPerPage] = useState(500);
  const [totalPages, setTotalPages] = useState(0);
  const [stats, setStats] = useState(null);
  const [filters, setFilters] = useState({
    severity: '',
    action: '',
    country: '',
    search: '',
  });
  
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

  // Carregar status e dados
  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [statusRes, configRes, statsRes, eventsRes] = await Promise.all([
        cloudflareAPI.getStatus(),
        cloudflareAPI.getConfig(),
        cloudflareAPI.getStats(),
        cloudflareAPI.getEvents(filters, eventsPage, eventsPerPage),
      ]);
      
      setStatus(statusRes.data);
      setConfig(prev => ({
        ...prev,
        ...configRes.data,
        api_token: '', // Nunca mostrar o token
      }));
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

  useEffect(() => {
    loadData();
    
    // Auto-refresh a cada 30 segundos
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Carregar lista de analistas uma vez
  useEffect(() => {
    const loadAnalysts = async () => {
      try {
        const response = await usersAPI.list();
        const userList = response.data?.users || response.data?.data || [];
        setAnalysts(Array.isArray(userList) ? userList : []);
      } catch (error) {
        console.error('Erro ao carregar analistas:', error);
      }
    };
    loadAnalysts();
  }, []);

  // Carregar zonas
  const loadZones = async () => {
    try {
      const response = await cloudflareAPI.getZones();
      setZones(response.data.zones || []);
    } catch (error) {
      console.error('Erro ao carregar zonas:', error);
    }
  };

  // Testar conexão
  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const response = await cloudflareAPI.testConnection({
        api_token: config.api_token || undefined,
      });
      setTestResult(response.data);
      if (response.data.success) {
        loadZones();
      }
    } catch (error) {
      setTestResult({
        success: false,
        error: error.response?.data?.error || error.message,
      });
    } finally {
      setTesting(false);
    }
  };

  // Salvar configuração
  const handleSaveConfig = async () => {
    setSaving(true);
    try {
      await cloudflareAPI.saveConfig(config);
      setConfigDialog(false);
      loadData();
    } catch (error) {
      console.error('Erro ao salvar configuração:', error);
    } finally {
      setSaving(false);
    }
  };

  // Forçar sincronização
  const handleSync = async () => {
    setSyncing(true);
    try {
      await cloudflareAPI.sync();
      setTimeout(loadData, 2000);
    } catch (error) {
      console.error('Erro ao sincronizar:', error);
    } finally {
      setSyncing(false);
    }
  };

  // Abrir detalhes do evento
  const handleViewEvent = (event) => {
    setSelectedEvent(event);
    setEventDetailDialog(true);
    // Auto-consultar reputação se já estiver em cache
    if (event.client_ip && ipReputationCache[event.client_ip]) {
      setIpReputation(ipReputationCache[event.client_ip]);
    } else {
      setIpReputation(null);
    }
  };

  // Consultar reputação de IP
  const handleCheckIPReputation = async (ip) => {
    if (!ip) return;
    
    // Verificar cache
    if (ipReputationCache[ip]) {
      setIpReputation(ipReputationCache[ip]);
      return;
    }

    setIpReputationLoading(true);
    setIpReputation(null);
    try {
      const response = await threatIntelAPI.enrichIP(ip);
      const data = response.data;
      setIpReputation(data);
      setIpReputationCache(prev => ({ ...prev, [ip]: data }));
    } catch (error) {
      console.error('Erro ao consultar reputação do IP:', error);
      // Tentar endpoint alternativo
      try {
        const response = await threatIntelAPI.checkIP(ip);
        const repData = {
          ip: ip,
          isMalicious: response.data.score > 50,
          reputation: response.data,
          matchedIOCs: [],
          riskScore: response.data.score || 0,
          sources: response.data.source ? [response.data.source] : [],
        };
        setIpReputation(repData);
        setIpReputationCache(prev => ({ ...prev, [ip]: repData }));
      } catch (err2) {
        console.error('Fallback também falhou:', err2);
        setIpReputation({ error: 'Não foi possível consultar reputação deste IP' });
      }
    } finally {
      setIpReputationLoading(false);
    }
  };

  // Obter cor do score de risco
  const getRiskColor = (score) => {
    if (score >= 75) return '#f44336'; // vermelho - crítico
    if (score >= 50) return '#ff9800'; // laranja - alto
    if (score >= 25) return '#ffeb3b'; // amarelo - médio
    return '#4caf50'; // verde - baixo
  };

  const getRiskLabel = (score) => {
    if (score >= 75) return 'Crítico';
    if (score >= 50) return 'Alto';
    if (score >= 25) return 'Médio';
    return 'Baixo';
  };

  // Abrir dialog de criar caso a partir de evento
  const handleOpenCreateCase = (event) => {
    setSelectedEvent(event);
    const severity = (event.severity || 'INFO').toUpperCase();
    const priority = severity === 'CRITICAL' ? 'critical' : severity === 'HIGH' ? 'high' : severity === 'MEDIUM' ? 'medium' : 'low';
    setNewCase({
      title: `[Cloudflare WAF] ${event.action || 'Event'} - ${event.host || event.client_ip || 'Unknown'}`,
      description: `Evento WAF detectado pelo Cloudflare:\n\n` +
        `- Acao: ${event.action || '-'}\n` +
        `- IP Origem: ${event.client_ip || '-'}\n` +
        `- Host: ${event.host || '-'}\n` +
        `- URI: ${event.uri || '-'}\n` +
        `- Metodo: ${event.method || '-'}\n` +
        `- Pais: ${event.client_country || '-'}\n` +
        `- Regra: ${event.rule_id || '-'}\n` +
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
        source: 'cloudflare_waf',
        source_ref: selectedEvent?._id || selectedEvent?.ray_id || '',
        tags: ['cloudflare', 'waf', selectedEvent?.action || ''].filter(Boolean),
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

  // Formatar data
  const formatDate = (dateStr) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleString('pt-BR');
  };

  // Renderizar chip de severidade
  const renderSeverityChip = (severity) => (
    <Chip
      label={severity}
      size="small"
      sx={{
        bgcolor: SEVERITY_COLORS[severity] || '#9e9e9e',
        color: 'white',
        fontWeight: 'bold',
      }}
    />
  );

  // Renderizar chip de ação
  const renderActionChip = (action) => (
    <Chip
      label={action?.toUpperCase()}
      size="small"
      sx={{
        bgcolor: ACTION_COLORS[action?.toLowerCase()] || '#9e9e9e',
        color: 'white',
      }}
    />
  );

  if (loading && !status) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <CloudIcon sx={{ fontSize: 40, color: '#f38020' }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Cloudflare WAF Integration
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Monitoramento de eventos de Web Application Firewall
            </Typography>
          </Box>
        </Box>
        
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={loadData}
            disabled={loading}
          >
            Atualizar
          </Button>
          <Button
            variant="outlined"
            startIcon={syncing ? <CircularProgress size={20} /> : <PlayIcon />}
            onClick={handleSync}
            disabled={syncing || !status?.configured}
          >
            Sincronizar Agora
          </Button>
          <Button
            variant="contained"
            startIcon={<SettingsIcon />}
            onClick={() => setConfigDialog(true)}
            sx={{ bgcolor: '#f38020', '&:hover': { bgcolor: '#d66d18' } }}
          >
            Configurar
          </Button>
        </Box>
      </Box>

      {/* Status Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card sx={{ bgcolor: status?.configured ? '#1b5e20' : '#b71c1c', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {status?.configured ? <CheckCircleIcon /> : <ErrorIcon />}
                <Typography variant="h6">Status</Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>
                {status?.configured ? 'Configurado' : 'Não Configurado'}
              </Typography>
              <Typography variant="body2" sx={{ opacity: 0.8 }}>
                {status?.enabled ? 'Coleta ativa' : 'Coleta inativa'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={3}>
          <Card sx={{ bgcolor: '#1a237e', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <TimelineIcon />
                <Typography variant="h6">Eventos (24h)</Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>
                {stats?.total_events?.toLocaleString() || 0}
              </Typography>
              <Typography variant="body2" sx={{ opacity: 0.8 }}>
                Total de eventos WAF
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={3}>
          <Card sx={{ bgcolor: '#b71c1c', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <BlockIcon />
                <Typography variant="h6">Bloqueados</Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>
                {stats?.blocked?.toLocaleString() || 0}
              </Typography>
              <Typography variant="body2" sx={{ opacity: 0.8 }}>
                Requisições bloqueadas
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={3}>
          <Card sx={{ bgcolor: '#e65100', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <GavelIcon />
                <Typography variant="h6">Desafiados</Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>
                {stats?.challenged?.toLocaleString() || 0}
              </Typography>
              <Typography variant="body2" sx={{ opacity: 0.8 }}>
                CAPTCHA/JS Challenge
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Última Sincronização */}
      {status?.last_sync && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>Última Sincronização</AlertTitle>
          {formatDate(status.last_sync)} - {status.events_collected?.toLocaleString() || 0} eventos coletados desde o início
        </Alert>
      )}

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(e, v) => setActiveTab(v)}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label="Dashboard" icon={<TrendingIcon />} iconPosition="start" />
          <Tab label="Eventos" icon={<SecurityIcon />} iconPosition="start" />
          <Tab label="Análise" icon={<TimelineIcon />} iconPosition="start" />
        </Tabs>

        {/* Tab Dashboard */}
        <TabPanel value={activeTab} index={0}>
          <Box sx={{ p: 2 }}>
            <Grid container spacing={3}>
              {/* Gráfico por Ação */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="h6" gutterBottom>
                    Eventos por Ação
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={(stats?.by_action || []).map(item => ({
                          name: item.key,
                          value: item.doc_count,
                        }))}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={100}
                        paddingAngle={2}
                        dataKey="value"
                        label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                      >
                        {(stats?.by_action || []).map((entry, index) => (
                          <Cell
                            key={index}
                            fill={ACTION_COLORS[entry.key?.toLowerCase()] || '#9e9e9e'}
                          />
                        ))}
                      </Pie>
                      <RechartsTooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </Paper>
              </Grid>

              {/* Gráfico por Severidade */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="h6" gutterBottom>
                    Eventos por Severidade
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={(stats?.by_severity || []).map(item => ({
                      name: item.key,
                      value: item.doc_count,
                    }))}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" />
                      <YAxis />
                      <RechartsTooltip />
                      <Bar dataKey="value" fill="#f38020">
                        {(stats?.by_severity || []).map((entry, index) => (
                          <Cell key={index} fill={SEVERITY_COLORS[entry.key] || '#9e9e9e'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </Paper>
              </Grid>

              {/* Top IPs */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="h6" gutterBottom>
                    Top 10 IPs Atacantes
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>IP</TableCell>
                          <TableCell align="right">Eventos</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {(stats?.top_ips || []).map((ip, index) => (
                          <TableRow key={index}>
                            <TableCell>
                              <Typography variant="body2" fontFamily="monospace">
                                {ip.key}
                              </Typography>
                            </TableCell>
                            <TableCell align="right">
                              <Chip
                                label={ip.doc_count?.toLocaleString()}
                                size="small"
                                color={ip.doc_count > 100 ? 'error' : 'default'}
                              />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              </Grid>

              {/* Países */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="h6" gutterBottom>
                    Top 10 Países de Origem
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>País</TableCell>
                          <TableCell align="right">Eventos</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {(stats?.by_country || []).map((country, index) => (
                          <TableRow key={index}>
                            <TableCell>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <span>{COUNTRY_FLAGS[country.key] || '🌍'}</span>
                                <Typography variant="body2">{country.key}</Typography>
                              </Box>
                            </TableCell>
                            <TableCell align="right">
                              {country.doc_count?.toLocaleString()}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        {/* Tab Eventos */}
        <TabPanel value={activeTab} index={1}>
          <Box sx={{ p: 2 }}>
            {/* Barra de busca e filtros */}
            <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap', alignItems: 'center' }}>
              <TextField
                size="small"
                placeholder="Buscar por IP, host, URI, user-agent, regra..."
                value={filters.search}
                onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
                onKeyDown={(e) => { if (e.key === 'Enter') { setEventsPage(0); loadData(); } }}
                sx={{ minWidth: 300, flexGrow: 1 }}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon />
                    </InputAdornment>
                  ),
                }}
              />

              <FormControl size="small" sx={{ minWidth: 130 }}>
                <InputLabel>Severidade</InputLabel>
                <Select
                  value={filters.severity}
                  label="Severidade"
                  onChange={(e) => { setFilters(prev => ({ ...prev, severity: e.target.value })); setEventsPage(0); }}
                >
                  <MenuItem value="">Todas</MenuItem>
                  <MenuItem value="CRITICAL">Crítica</MenuItem>
                  <MenuItem value="HIGH">Alta</MenuItem>
                  <MenuItem value="MEDIUM">Média</MenuItem>
                  <MenuItem value="LOW">Baixa</MenuItem>
                  <MenuItem value="INFO">Info</MenuItem>
                </Select>
              </FormControl>
              
              <FormControl size="small" sx={{ minWidth: 130 }}>
                <InputLabel>Ação</InputLabel>
                <Select
                  value={filters.action}
                  label="Ação"
                  onChange={(e) => { setFilters(prev => ({ ...prev, action: e.target.value })); setEventsPage(0); }}
                >
                  <MenuItem value="">Todas</MenuItem>
                  <MenuItem value="block">Block</MenuItem>
                  <MenuItem value="drop">Drop</MenuItem>
                  <MenuItem value="challenge">Challenge</MenuItem>
                  <MenuItem value="js_challenge">JS Challenge</MenuItem>
                  <MenuItem value="managed_challenge">Managed Challenge</MenuItem>
                  <MenuItem value="skip">Skip</MenuItem>
                  <MenuItem value="log">Log</MenuItem>
                  <MenuItem value="allow">Allow</MenuItem>
                </Select>
              </FormControl>
              
              <TextField
                size="small"
                label="País"
                value={filters.country}
                onChange={(e) => setFilters(prev => ({ ...prev, country: e.target.value.toUpperCase() }))}
                placeholder="Ex: BR, US"
                sx={{ width: 100 }}
              />
              
              <Button
                variant="contained"
                startIcon={<FilterIcon />}
                onClick={() => { setEventsPage(0); loadData(); }}
              >
                Filtrar
              </Button>

              {(filters.severity || filters.action || filters.country || filters.search) && (
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => { setFilters({ severity: '', action: '', country: '', search: '' }); setEventsPage(0); }}
                >
                  Limpar filtros
                </Button>
              )}
            </Box>

            {/* Info de total e paginação superior */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="body2" color="text.secondary">
                {totalEvents > 0 
                  ? `Exibindo ${eventsPage * eventsPerPage + 1} - ${Math.min((eventsPage + 1) * eventsPerPage, totalEvents)} de ${totalEvents.toLocaleString()} eventos`
                  : 'Nenhum evento encontrado'
                }
              </Typography>
              {totalPages > 1 && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <IconButton size="small" disabled={eventsPage === 0} onClick={() => setEventsPage(0)}>
                    <FirstPageIcon />
                  </IconButton>
                  <IconButton size="small" disabled={eventsPage === 0} onClick={() => setEventsPage(prev => prev - 1)}>
                    <PrevIcon />
                  </IconButton>
                  <Typography variant="body2">
                    Página {eventsPage + 1} de {totalPages}
                  </Typography>
                  <IconButton size="small" disabled={eventsPage >= totalPages - 1} onClick={() => setEventsPage(prev => prev + 1)}>
                    <NextIcon />
                  </IconButton>
                  <IconButton size="small" disabled={eventsPage >= totalPages - 1} onClick={() => setEventsPage(totalPages - 1)}>
                    <LastPageIcon />
                  </IconButton>
                </Box>
              )}
            </Box>

            {/* Tabela de Eventos */}
            <TableContainer component={Paper} sx={{ maxHeight: 'calc(100vh - 400px)' }}>
              <Table stickyHeader size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 'bold', bgcolor: 'background.paper' }}>Timestamp</TableCell>
                    <TableCell sx={{ fontWeight: 'bold', bgcolor: 'background.paper' }}>IP</TableCell>
                    <TableCell sx={{ fontWeight: 'bold', bgcolor: 'background.paper' }}>País</TableCell>
                    <TableCell sx={{ fontWeight: 'bold', bgcolor: 'background.paper' }}>Host</TableCell>
                    <TableCell sx={{ fontWeight: 'bold', bgcolor: 'background.paper' }}>URI</TableCell>
                    <TableCell sx={{ fontWeight: 'bold', bgcolor: 'background.paper' }}>Método</TableCell>
                    <TableCell sx={{ fontWeight: 'bold', bgcolor: 'background.paper' }}>Ação</TableCell>
                    <TableCell sx={{ fontWeight: 'bold', bgcolor: 'background.paper' }}>Severidade</TableCell>
                    <TableCell sx={{ fontWeight: 'bold', bgcolor: 'background.paper' }}>Regra</TableCell>
                    <TableCell align="center" sx={{ fontWeight: 'bold', bgcolor: 'background.paper' }}>Detalhes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {events.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={10} align="center">
                        <Typography color="text.secondary" sx={{ py: 3 }}>
                          Nenhum evento encontrado. Clique em "Sincronizar Agora" para coletar eventos do Cloudflare.
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    events.map((event, index) => (
                      <TableRow key={event.ray_id || event._id || index} hover>
                        <TableCell>
                          <Typography variant="body2" sx={{ whiteSpace: 'nowrap', fontSize: '0.8rem' }}>
                            {formatDate(event.timestamp)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace" sx={{ fontSize: '0.8rem' }}>
                            {event.client_ip}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            {COUNTRY_FLAGS[event.client_country] || '🌍'}
                            <span style={{ fontSize: '0.8rem' }}>{event.client_country}</span>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Tooltip title={event.host}>
                            <Typography variant="body2" noWrap sx={{ maxWidth: 180, fontSize: '0.8rem' }}>
                              {event.host}
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          <Tooltip title={event.uri}>
                            <Typography variant="body2" noWrap sx={{ maxWidth: 220, fontSize: '0.8rem' }}>
                              {event.uri}
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                            {event.method || '-'}
                          </Typography>
                        </TableCell>
                        <TableCell>{renderActionChip(event.action)}</TableCell>
                        <TableCell>{renderSeverityChip(event.severity)}</TableCell>
                        <TableCell>
                          <Tooltip title={event.rule_description || event.rule_id || '-'}>
                            <Typography variant="body2" noWrap sx={{ maxWidth: 120, fontSize: '0.8rem' }}>
                              {event.rule_id || '-'}
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell align="center">
                          <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'center' }}>
                            <Tooltip title="Analisar reputação do IP">
                              <IconButton
                                size="small"
                                onClick={() => {
                                  handleViewEvent(event);
                                  handleCheckIPReputation(event.client_ip);
                                }}
                                sx={{ 
                                  color: ipReputationCache[event.client_ip] 
                                    ? getRiskColor(ipReputationCache[event.client_ip].riskScore || ipReputationCache[event.client_ip].reputation?.score || 0)
                                    : 'text.secondary'
                                }}
                              >
                                <RadarIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Ver detalhes">
                              <IconButton
                                size="small"
                                onClick={() => handleViewEvent(event)}
                              >
                                <VisibilityIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Abrir Caso">
                              <IconButton
                                size="small"
                                onClick={() => handleOpenCreateCase(event)}
                                sx={{ color: '#ff9800' }}
                              >
                                <AssignmentIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Paginação inferior */}
            {totalEvents > 0 && (
              <TablePagination
                component="div"
                count={totalEvents}
                page={eventsPage}
                onPageChange={(e, newPage) => setEventsPage(newPage)}
                rowsPerPage={eventsPerPage}
                rowsPerPageOptions={[500]}
                labelDisplayedRows={({ from, to, count }) =>
                  `${from}-${to} de ${count !== -1 ? count.toLocaleString() : `mais de ${to}`}`
                }
                labelRowsPerPage="Por página:"
              />
            )}
          </Box>
        </TabPanel>

        {/* Tab Análise */}
        <TabPanel value={activeTab} index={2}>
          <Box sx={{ p: 2 }}>
            <Grid container spacing={3}>
              {/* Top Regras */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="h6" gutterBottom>
                    Top 10 Regras WAF Acionadas
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart
                      data={(stats?.top_rules || []).map(item => ({
                        name: item.key?.substring(0, 20) || 'Unknown',
                        value: item.doc_count,
                      }))}
                      layout="vertical"
                    >
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis type="number" />
                      <YAxis dataKey="name" type="category" width={150} />
                      <RechartsTooltip />
                      <Bar dataKey="value" fill="#f38020" />
                    </BarChart>
                  </ResponsiveContainer>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>
      </Paper>

      {/* Dialog de Configuração */}
      <Dialog open={configDialog} onClose={() => setConfigDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CloudIcon sx={{ color: '#f38020' }} />
            Configuração da Integração Cloudflare
          </Box>
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Como obter as credenciais</AlertTitle>
              <ol style={{ margin: 0, paddingLeft: 20 }}>
                <li>Acesse o <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener noreferrer">Dashboard do Cloudflare</a></li>
                <li>Crie um API Token com permissões: <strong>Zone:Logs:Read</strong>, <strong>Zone:Analytics:Read</strong>, <strong>Zone:Firewall Services:Read</strong></li>
                <li>Copie o token gerado e cole abaixo</li>
              </ol>
            </Alert>

            <Grid container spacing={3}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="API Token"
                  type="password"
                  value={config.api_token}
                  onChange={(e) => setConfig(prev => ({ ...prev, api_token: e.target.value }))}
                  placeholder="Seu Cloudflare API Token"
                  helperText={config.api_token_configured ? 'Token já configurado (deixe em branco para manter)' : 'Token obrigatório'}
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Account ID (opcional)"
                  value={config.account_id}
                  onChange={(e) => setConfig(prev => ({ ...prev, account_id: e.target.value }))}
                  placeholder="ID da conta Cloudflare"
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Intervalo de Sincronização (minutos)"
                  type="number"
                  value={config.sync_period_minutes}
                  onChange={(e) => setConfig(prev => ({ ...prev, sync_period_minutes: parseInt(e.target.value) || 5 }))}
                  inputProps={{ min: 1, max: 60 }}
                />
              </Grid>
              
              <Grid item xs={12}>
                <Button
                  variant="outlined"
                  onClick={handleTestConnection}
                  disabled={testing}
                  startIcon={testing ? <CircularProgress size={20} /> : <LinkIcon />}
                >
                  Testar Conexão
                </Button>
                
                {testResult && (
                  <Alert severity={testResult.success ? 'success' : 'error'} sx={{ mt: 2 }}>
                    {testResult.success ? testResult.message : testResult.error}
                  </Alert>
                )}
              </Grid>
              
              {zones.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>
                    Zonas Disponíveis:
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {zones.map(zone => (
                      <Chip
                        key={zone.id}
                        label={zone.name}
                        onClick={() => {
                          const newZones = config.zone_ids.includes(zone.id)
                            ? config.zone_ids.filter(z => z !== zone.id)
                            : [...config.zone_ids, zone.id];
                          setConfig(prev => ({ ...prev, zone_ids: newZones }));
                        }}
                        color={config.zone_ids.includes(zone.id) ? 'primary' : 'default'}
                        variant={config.zone_ids.includes(zone.id) ? 'filled' : 'outlined'}
                      />
                    ))}
                  </Box>
                  <Typography variant="caption" color="text.secondary">
                    Clique para selecionar/deselecionar zonas (deixe vazio para monitorar todas)
                  </Typography>
                </Grid>
              )}
              
              <Grid item xs={12}>
                <Divider sx={{ my: 1 }} />
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.enabled}
                      onChange={(e) => setConfig(prev => ({ ...prev, enabled: e.target.checked }))}
                      color="primary"
                    />
                  }
                  label="Habilitar coleta automática de eventos"
                />
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigDialog(false)}>Cancelar</Button>
          <Button
            variant="contained"
            onClick={handleSaveConfig}
            disabled={saving}
            sx={{ bgcolor: '#f38020', '&:hover': { bgcolor: '#d66d18' } }}
          >
            {saving ? <CircularProgress size={20} /> : 'Salvar'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Detalhes do Evento */}
      <Dialog open={eventDetailDialog} onClose={() => { setEventDetailDialog(false); setIpReputation(null); }} maxWidth="lg" fullWidth>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SecurityIcon color="error" />
              Detalhes do Evento WAF
            </Box>
            {selectedEvent && (
              <Chip 
                label={`Ray: ${selectedEvent.ray_id || 'N/A'}`} 
                size="small" 
                variant="outlined"
                sx={{ fontFamily: 'monospace' }}
              />
            )}
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedEvent && (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={3}>
                {/* Coluna esquerda - Detalhes do evento */}
                <Grid item xs={12} md={7}>
                  <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                    Informações do Evento
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" color="text.secondary">Timestamp</Typography>
                      <Typography variant="body1">{formatDate(selectedEvent.timestamp)}</Typography>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" color="text.secondary">Status HTTP</Typography>
                      <Typography variant="body1">{selectedEvent.edge_response_status}</Typography>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" color="text.secondary">Host</Typography>
                      <Typography variant="body1">{selectedEvent.host}</Typography>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" color="text.secondary">Método</Typography>
                      <Typography variant="body1">{selectedEvent.method}</Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" color="text.secondary">URI</Typography>
                      <Paper sx={{ p: 1, bgcolor: 'action.hover' }}>
                        <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: 'break-all' }}>
                          {selectedEvent.uri}
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" color="text.secondary">User Agent</Typography>
                      <Paper sx={{ p: 1, bgcolor: 'action.hover' }}>
                        <Typography variant="body2" sx={{ wordBreak: 'break-all', fontSize: '0.8rem' }}>
                          {selectedEvent.user_agent}
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12}>
                      <Divider />
                    </Grid>
                    <Grid item xs={4}>
                      <Typography variant="subtitle2" color="text.secondary">Ação</Typography>
                      {renderActionChip(selectedEvent.action)}
                    </Grid>
                    <Grid item xs={4}>
                      <Typography variant="subtitle2" color="text.secondary">Severidade</Typography>
                      {renderSeverityChip(selectedEvent.severity)}
                    </Grid>
                    <Grid item xs={4}>
                      <Typography variant="subtitle2" color="text.secondary">Source</Typography>
                      <Typography variant="body2">{selectedEvent.source || '-'}</Typography>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" color="text.secondary">Regra ID</Typography>
                      <Typography variant="body1" fontFamily="monospace">{selectedEvent.rule_id || '-'}</Typography>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" color="text.secondary">Descrição da Regra</Typography>
                      <Typography variant="body1">{selectedEvent.rule_description || 'Sem descrição'}</Typography>
                    </Grid>
                    {selectedEvent.mitre_tactic && (
                      <>
                        <Grid item xs={12}>
                          <Divider />
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" color="text.secondary">MITRE ATT&CK Tactic</Typography>
                          <Chip label={selectedEvent.mitre_tactic} size="small" color="error" />
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" color="text.secondary">MITRE ATT&CK Technique</Typography>
                          <Chip label={selectedEvent.mitre_technique} size="small" color="warning" />
                        </Grid>
                      </>
                    )}
                  </Grid>
                </Grid>

                {/* Coluna direita - Reputação do IP */}
                <Grid item xs={12} md={5}>
                  <Paper sx={{ p: 2, bgcolor: 'background.default', height: '100%' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                      <Typography variant="subtitle1" fontWeight="bold">
                        <RadarIcon sx={{ verticalAlign: 'middle', mr: 0.5, fontSize: 20 }} />
                        Reputação do IP
                      </Typography>
                    </Box>

                    {/* Info básica do IP */}
                    <Paper sx={{ p: 1.5, mb: 2, bgcolor: 'action.hover' }}>
                      <Typography variant="body2" fontFamily="monospace" fontWeight="bold" sx={{ fontSize: '1rem' }}>
                        {selectedEvent.client_ip}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {COUNTRY_FLAGS[selectedEvent.client_country] || '🌍'} {selectedEvent.client_country} 
                        {selectedEvent.client_asn_desc ? ` - ${selectedEvent.client_asn_desc}` : selectedEvent.client_asn ? ` - ASN ${selectedEvent.client_asn}` : ''}
                      </Typography>
                    </Paper>

                    {/* Botão de análise */}
                    {!ipReputation && !ipReputationLoading && (
                      <Button
                        variant="contained"
                        fullWidth
                        startIcon={<RadarIcon />}
                        onClick={() => handleCheckIPReputation(selectedEvent.client_ip)}
                        sx={{ mb: 2 }}
                        color="warning"
                      >
                        Analisar Reputação do IP
                      </Button>
                    )}

                    {/* Loading */}
                    {ipReputationLoading && (
                      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 3 }}>
                        <CircularProgress size={40} />
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                          Consultando AbuseIPDB, VirusTotal...
                        </Typography>
                      </Box>
                    )}

                    {/* Erro */}
                    {ipReputation?.error && (
                      <Alert severity="warning" sx={{ mb: 2 }}>
                        {ipReputation.error}
                      </Alert>
                    )}

                    {/* Resultado da reputação */}
                    {ipReputation && !ipReputation.error && (
                      <Box>
                        {/* Score visual */}
                        <Box sx={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          justifyContent: 'center', 
                          mb: 2,
                          p: 2,
                          borderRadius: 2,
                          bgcolor: `${getRiskColor(ipReputation.riskScore || ipReputation.reputation?.score || 0)}15`,
                          border: `2px solid ${getRiskColor(ipReputation.riskScore || ipReputation.reputation?.score || 0)}`,
                        }}>
                          <Box sx={{ textAlign: 'center' }}>
                            {(ipReputation.riskScore || ipReputation.reputation?.score || 0) >= 50 
                              ? <MaliciousIcon sx={{ fontSize: 40, color: getRiskColor(ipReputation.riskScore || ipReputation.reputation?.score || 0) }} />
                              : (ipReputation.riskScore || ipReputation.reputation?.score || 0) >= 25
                              ? <SuspiciousIcon sx={{ fontSize: 40, color: getRiskColor(ipReputation.riskScore || ipReputation.reputation?.score || 0) }} />
                              : <CleanIcon sx={{ fontSize: 40, color: getRiskColor(ipReputation.riskScore || ipReputation.reputation?.score || 0) }} />
                            }
                            <Typography variant="h4" fontWeight="bold" sx={{ color: getRiskColor(ipReputation.riskScore || ipReputation.reputation?.score || 0) }}>
                              {ipReputation.riskScore || ipReputation.reputation?.score || 0}/100
                            </Typography>
                            <Typography variant="body2" fontWeight="bold" sx={{ color: getRiskColor(ipReputation.riskScore || ipReputation.reputation?.score || 0) }}>
                              Risco {getRiskLabel(ipReputation.riskScore || ipReputation.reputation?.score || 0)}
                            </Typography>
                            {ipReputation.isMalicious && (
                              <Chip label="MALICIOSO" size="small" color="error" sx={{ mt: 0.5 }} />
                            )}
                          </Box>
                        </Box>

                        {/* Detalhes da reputação */}
                        <List dense disablePadding>
                          {ipReputation.reputation?.country && ipReputation.reputation.country !== 'Unknown' && (
                            <ListItem disableGutters>
                              <ListItemIcon sx={{ minWidth: 32 }}><PublicIcon fontSize="small" /></ListItemIcon>
                              <ListItemText primary="País" secondary={ipReputation.reputation.country} />
                            </ListItem>
                          )}
                          {ipReputation.reputation?.isp && ipReputation.reputation.isp !== 'Unknown' && (
                            <ListItem disableGutters>
                              <ListItemIcon sx={{ minWidth: 32 }}><DnsIcon fontSize="small" /></ListItemIcon>
                              <ListItemText primary="ISP" secondary={ipReputation.reputation.isp} />
                            </ListItem>
                          )}
                          {ipReputation.reputation?.totalReports > 0 && (
                            <ListItem disableGutters>
                              <ListItemIcon sx={{ minWidth: 32 }}><ReportIcon fontSize="small" color="warning" /></ListItemIcon>
                              <ListItemText primary="Denúncias" secondary={`${ipReputation.reputation.totalReports} reportes`} />
                            </ListItem>
                          )}
                          {ipReputation.reputation?.isTor && (
                            <ListItem disableGutters>
                              <ListItemIcon sx={{ minWidth: 32 }}><WarningIcon fontSize="small" color="error" /></ListItemIcon>
                              <ListItemText primary="Tor Exit Node" secondary="Este IP é um nó de saída Tor" />
                            </ListItem>
                          )}
                          {ipReputation.reputation?.isVpn && (
                            <ListItem disableGutters>
                              <ListItemIcon sx={{ minWidth: 32 }}><ShieldIcon fontSize="small" color="warning" /></ListItemIcon>
                              <ListItemText primary="VPN" secondary="Este IP pertence a um serviço VPN" />
                            </ListItem>
                          )}
                          {ipReputation.reputation?.isProxy && (
                            <ListItem disableGutters>
                              <ListItemIcon sx={{ minWidth: 32 }}><LanguageIcon fontSize="small" color="warning" /></ListItemIcon>
                              <ListItemText primary="Proxy" secondary="Este IP é um proxy" />
                            </ListItem>
                          )}
                        </List>

                        {/* Categorias */}
                        {ipReputation.reputation?.categories?.length > 0 && (
                          <Box sx={{ mt: 1 }}>
                            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                              <CategoryIcon sx={{ verticalAlign: 'middle', mr: 0.5, fontSize: 16 }} />
                              Categorias
                            </Typography>
                            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                              {ipReputation.reputation.categories.map((cat, i) => (
                                <Chip key={i} label={cat} size="small" color="error" variant="outlined" />
                              ))}
                            </Box>
                          </Box>
                        )}

                        {/* IOCs correspondentes */}
                        {ipReputation.matchedIOCs?.length > 0 && (
                          <Box sx={{ mt: 2 }}>
                            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                              <WarningIcon sx={{ verticalAlign: 'middle', mr: 0.5, fontSize: 16, color: '#f44336' }} />
                              IOCs Correspondentes ({ipReputation.matchedIOCs.length})
                            </Typography>
                            {ipReputation.matchedIOCs.map((ioc, i) => (
                              <Alert key={i} severity="error" sx={{ mb: 0.5, py: 0 }}>
                                <Typography variant="body2" sx={{ fontSize: '0.75rem' }}>
                                  <strong>{ioc.type}:</strong> {ioc.value} - {ioc.threat || ioc.description || 'Sem descrição'}
                                </Typography>
                              </Alert>
                            ))}
                          </Box>
                        )}

                        {/* Fontes consultadas */}
                        {ipReputation.sources?.length > 0 && (
                          <Box sx={{ mt: 2 }}>
                            <Typography variant="caption" color="text.secondary">
                              Fontes: {ipReputation.sources.join(', ')}
                            </Typography>
                          </Box>
                        )}

                        {/* Botão para re-consultar */}
                        <Button
                          variant="outlined"
                          size="small"
                          fullWidth
                          startIcon={<RefreshIcon />}
                          onClick={() => {
                            setIpReputationCache(prev => {
                              const copy = { ...prev };
                              delete copy[selectedEvent.client_ip];
                              return copy;
                            });
                            handleCheckIPReputation(selectedEvent.client_ip);
                          }}
                          sx={{ mt: 2 }}
                        >
                          Consultar novamente
                        </Button>
                      </Box>
                    )}

                    {/* Links externos */}
                    <Divider sx={{ my: 2 }} />
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      Consultar externamente
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<LinkIcon />}
                        onClick={() => window.open(`https://www.abuseipdb.com/check/${selectedEvent.client_ip}`, '_blank')}
                      >
                        AbuseIPDB
                      </Button>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<LinkIcon />}
                        onClick={() => window.open(`https://www.virustotal.com/gui/ip-address/${selectedEvent.client_ip}`, '_blank')}
                      >
                        VirusTotal
                      </Button>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<LinkIcon />}
                        onClick={() => window.open(`https://www.shodan.io/host/${selectedEvent.client_ip}`, '_blank')}
                      >
                        Shodan
                      </Button>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<LinkIcon />}
                        onClick={() => window.open(`https://otx.alienvault.com/indicator/ip/${selectedEvent.client_ip}`, '_blank')}
                      >
                        OTX
                      </Button>
                    </Box>
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

export default CloudflareIntegration;

