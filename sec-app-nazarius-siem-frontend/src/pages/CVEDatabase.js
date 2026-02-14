import React, { useState, useEffect, useCallback } from 'react';
import { safeUrl } from '../utils/security';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  TextField,
  InputAdornment,
  IconButton,
  Button,
  Tooltip,
  CircularProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  LinearProgress,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Link,
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  BugReport as BugReportIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  OpenInNew as OpenInNewIcon,
  Sync as SyncIcon,
  Assessment as AssessmentIcon,
  NotificationsActive as AlertIcon,
  Timeline as TimelineIcon,
  Shield as ShieldIcon,
  NetworkCheck as NetworkCheckIcon,
  Cancel as CancelIcon,
  Settings as SettingsIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  Key as KeyIcon,
} from '@mui/icons-material';
import { cveAPI } from '../services/api';

// Cores por severidade
const severityColors = {
  CRITICAL: { bg: '#dc2626', text: '#fff', light: '#fef2f2' },
  HIGH: { bg: '#ea580c', text: '#fff', light: '#fff7ed' },
  MEDIUM: { bg: '#ca8a04', text: '#fff', light: '#fefce8' },
  LOW: { bg: '#16a34a', text: '#fff', light: '#f0fdf4' },
  NONE: { bg: '#6b7280', text: '#fff', light: '#f9fafb' },
};

// Componente de Chip de Severidade
const SeverityChip = ({ severity }) => {
  const color = severityColors[severity?.toUpperCase()] || severityColors.NONE;
  return (
    <Chip
      label={severity || 'N/A'}
      size="small"
      sx={{
        bgcolor: color.bg,
        color: color.text,
        fontWeight: 'bold',
        fontSize: '0.7rem',
      }}
    />
  );
};

// Componente de Score CVSS
const CVSSScore = ({ score }) => {
  const getColor = () => {
    if (score >= 9) return '#dc2626';
    if (score >= 7) return '#ea580c';
    if (score >= 4) return '#ca8a04';
    return '#16a34a';
  };

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Box
        sx={{
          width: 40,
          height: 40,
          borderRadius: '50%',
          bgcolor: getColor(),
          color: '#fff',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 'bold',
          fontSize: '0.9rem',
        }}
      >
        {score?.toFixed(1) || 'N/A'}
      </Box>
    </Box>
  );
};

// Componente de Card de Estatística
const StatCard = ({ title, value, icon: Icon, color, subtitle }) => (
  <Card sx={{ height: '100%', borderLeft: `4px solid ${color}` }}>
    <CardContent>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
            {title}
          </Typography>
          <Typography variant="h4" sx={{ fontWeight: 'bold', color }}>
            {value?.toLocaleString() || 0}
          </Typography>
          {subtitle && (
            <Typography variant="caption" color="text.secondary">
              {subtitle}
            </Typography>
          )}
        </Box>
        <Box sx={{ p: 1, borderRadius: 2, bgcolor: `${color}15` }}>
          <Icon sx={{ color, fontSize: 32 }} />
        </Box>
      </Box>
    </CardContent>
  </Card>
);

// Dialog de Detalhes do CVE
const CVEDetailDialog = ({ open, onClose, cveId }) => {
  const [cve, setCve] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [tabValue, setTabValue] = useState(0);

  const fetchCVEDetails = useCallback(async () => {
    setLoading(true);
    try {
      const response = await cveAPI.get(cveId);
      setCve(response.data.cve);
      setAlerts(response.data.relatedAlerts || []);
    } catch (error) {
      console.error('Error fetching CVE details:', error);
    } finally {
      setLoading(false);
    }
  }, [cveId]);

  useEffect(() => {
    if (open && cveId) {
      fetchCVEDetails();
    }
  }, [open, cveId, fetchCVEDetails]);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <BugReportIcon color="error" />
        <Box>
          <Typography variant="h6">{cveId}</Typography>
          {cve && <SeverityChip severity={cve.severity} />}
        </Box>
      </DialogTitle>
      <DialogContent dividers>
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
            <CircularProgress />
          </Box>
        ) : cve ? (
          <>
            <Tabs value={tabValue} onChange={(_, v) => setTabValue(v)} sx={{ mb: 2 }}>
              <Tab label="Detalhes" />
              <Tab label={`Alertas (${alerts.length})`} />
              <Tab label="Referências" />
            </Tabs>

            {tabValue === 0 && (
              <Box>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" color="text.secondary">Score CVSS</Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                      <CVSSScore score={cve.cvssScore} />
                      <Box>
                        <Typography variant="body2">
                          Versão: {cve.cvssVersion || 'N/A'}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ wordBreak: 'break-all' }}>
                          {cve.cvssVector || 'N/A'}
                        </Typography>
                      </Box>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" color="text.secondary">Status</Typography>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
                      <Chip label={cve.status || 'ANALYZED'} size="small" variant="outlined" />
                      {cve.exploitAvailable && <Chip label="Exploit Disponível" size="small" color="error" />}
                      {cve.cisaKnownExploit && <Chip label="CISA KEV" size="small" color="warning" />}
                      {cve.patchAvailable && <Chip label="Patch Disponível" size="small" color="success" />}
                    </Box>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>Descrição</Typography>
                    <Typography variant="body2">{cve.description}</Typography>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <Typography variant="subtitle2" color="text.secondary">Data de Publicação</Typography>
                    <Typography variant="body2">
                      {cve.publishedDate ? new Date(cve.publishedDate).toLocaleDateString('pt-BR') : 'N/A'}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <Typography variant="subtitle2" color="text.secondary">Última Modificação</Typography>
                    <Typography variant="body2">
                      {cve.lastModifiedDate ? new Date(cve.lastModifiedDate).toLocaleDateString('pt-BR') : 'N/A'}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <Typography variant="subtitle2" color="text.secondary">Alertas Relacionados</Typography>
                    <Chip 
                      label={cve.alertCount || 0} 
                      size="small" 
                      color={cve.alertCount > 0 ? 'warning' : 'default'}
                      sx={{ fontWeight: 'bold' }}
                    />
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <Typography variant="subtitle2" color="text.secondary">Eventos Relacionados</Typography>
                    <Chip 
                      label={cve.eventCount || 0} 
                      size="small" 
                      color={cve.eventCount > 0 ? 'info' : 'default'}
                      sx={{ fontWeight: 'bold' }}
                    />
                  </Grid>
                  {cve.weaknesses && cve.weaknesses.length > 0 && (
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" color="text.secondary" gutterBottom>Fraquezas (CWE)</Typography>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        {cve.weaknesses.map((cwe, idx) => (
                          <Chip key={idx} label={cwe} size="small" variant="outlined" />
                        ))}
                      </Box>
                    </Grid>
                  )}
                </Grid>
              </Box>
            )}

            {tabValue === 1 && (
              <Box>
                {alerts.length === 0 ? (
                  <Alert severity="info">Nenhum alerta relacionado encontrado</Alert>
                ) : (
                  <List>
                    {alerts.map((alert) => (
                      <ListItem key={alert.id} divider>
                        <ListItemIcon>
                          <AlertIcon color="warning" />
                        </ListItemIcon>
                        <ListItemText
                          primary={alert.name}
                          secondary={
                            <>
                              <Typography variant="caption" component="span">
                                {alert.description?.substring(0, 100)}...
                              </Typography>
                              <br />
                              <SeverityChip severity={alert.severity} />
                              <Typography variant="caption" sx={{ ml: 1 }}>
                                {new Date(alert.created_at).toLocaleDateString('pt-BR')}
                              </Typography>
                            </>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                )}
              </Box>
            )}

            {tabValue === 2 && (
              <Box>
                {!cve.references || cve.references.length === 0 ? (
                  <Alert severity="info">Nenhuma referência disponível</Alert>
                ) : (
                  <List>
                    {cve.references.map((ref, idx) => (
                      <ListItem key={idx} divider>
                        <ListItemIcon>
                          <OpenInNewIcon />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Link href={safeUrl(ref.url)} target="_blank" rel="noopener noreferrer">
                              {ref.url}
                            </Link>
                          }
                          secondary={
                            <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5 }}>
                              <Chip label={ref.source} size="small" variant="outlined" />
                              {ref.tags?.map((tag, i) => (
                                <Chip key={i} label={tag} size="small" />
                              ))}
                            </Box>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                )}
              </Box>
            )}
          </>
        ) : (
          <Alert severity="error">Não foi possível carregar os detalhes do CVE</Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button
          href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
          target="_blank"
          startIcon={<OpenInNewIcon />}
        >
          Ver no NVD
        </Button>
        <Button onClick={onClose}>Fechar</Button>
      </DialogActions>
    </Dialog>
  );
};

// Componente Principal
const CVEDatabase = () => {
  const [cves, setCves] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [withAlertsFilter, setWithAlertsFilter] = useState(false);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalCVEs, setTotalCVEs] = useState(0);
  const [selectedCVE, setSelectedCVE] = useState(null);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [sortBy, setSortBy] = useState('cvssScore');
  const [sortOrder] = useState('desc');
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false);
  const [diagnosticsData, setDiagnosticsData] = useState(null);
  const [diagnosticsLoading, setDiagnosticsLoading] = useState(false);
  
  // Estado para configuração
  const [configOpen, setConfigOpen] = useState(false);
  const [configLoading, setConfigLoading] = useState(false);
  const [configData, setConfigData] = useState(null);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
  const [testingConnection, setTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState(null);
  
  // Estado para acompanhar sincronização
  const [syncStatus, setSyncStatus] = useState(null);
  const [syncPolling, setSyncPolling] = useState(false);

  // Carregar CVEs
  const fetchCVEs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await cveAPI.list({
        page: page + 1,
        limit: rowsPerPage,
        severity: severityFilter,
        search: searchTerm,
        with_alerts: withAlertsFilter,
        sort_by: sortBy,
        sort_order: sortOrder,
      });
      setCves(response.data.cves || []);
      setTotalCVEs(response.data.total || 0);
    } catch (err) {
      console.error('Error fetching CVEs:', err);
      setError('Erro ao carregar CVEs. Verifique a conexão com o servidor.');
    } finally {
      setLoading(false);
    }
  }, [page, rowsPerPage, severityFilter, searchTerm, withAlertsFilter, sortBy, sortOrder]);

  // Carregar estatísticas
  const fetchStats = async () => {
    try {
      const response = await cveAPI.getStats();
      setStats(response.data);
    } catch (err) {
      console.error('Error fetching CVE stats:', err);
    }
  };

  // Polling do status de sincronização
  const pollSyncStatus = useCallback(async () => {
    try {
      const response = await cveAPI.getSyncStatus();
      const status = response.data;
      setSyncStatus(status);

      if (status.status === 'running') {
        setSyncing(true);
        setSyncPolling(true);
      } else if (status.status === 'completed') {
        setSyncing(false);
        setSyncPolling(false);
        // Recarregar dados após conclusão
        fetchCVEs();
        fetchStats();
      } else if (status.status === 'failed') {
        setSyncing(false);
        setSyncPolling(false);
      } else {
        setSyncing(false);
        setSyncPolling(false);
      }
    } catch (err) {
      console.error('Error polling sync status:', err);
      setSyncPolling(false);
      setSyncing(false);
    }
  }, [fetchCVEs]);

  // Polling automático durante sincronização
  useEffect(() => {
    let interval;
    if (syncPolling) {
      interval = setInterval(() => {
        pollSyncStatus();
      }, 3000); // Poll a cada 3 segundos
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [syncPolling, pollSyncStatus]);

  // Sincronizar com NVD
  const handleSync = async () => {
    setSyncing(true);
    setSyncStatus({ status: 'running', message: 'Iniciando sincronização...', progress: 0 });
    try {
      const response = await cveAPI.sync(30);
      if (response.data.status === 'running' || response.status === 202) {
        setSyncPolling(true);
      }
    } catch (err) {
      console.error('Error syncing CVEs:', err);
      if (err.response?.status === 409) {
        // Já está sincronizando
        setSyncPolling(true);
        pollSyncStatus();
      } else {
        setSyncing(false);
        setSyncStatus({ status: 'failed', message: 'Erro ao iniciar sincronização: ' + (err.response?.data?.message || err.message) });
      }
    }
  };

  // Atualizar contagens
  const handleUpdateCounts = async () => {
    try {
      await cveAPI.updateCounts();
      alert('Atualização de contagens iniciada!');
      setTimeout(fetchStats, 3000);
    } catch (err) {
      console.error('Error updating counts:', err);
    }
  };

  // Diagnóstico de conectividade
  const handleDiagnostics = async () => {
    setDiagnosticsOpen(true);
    setDiagnosticsLoading(true);
    setDiagnosticsData(null);
    try {
      const response = await cveAPI.diagnostics();
      setDiagnosticsData(response.data);
    } catch (err) {
      console.error('Error running diagnostics:', err);
      setDiagnosticsData({
        overall_status: 'error',
        error: err.message || 'Erro ao executar diagnóstico',
        checks: []
      });
    } finally {
      setDiagnosticsLoading(false);
    }
  };

  // Abrir configuração
  const handleOpenConfig = async () => {
    setConfigOpen(true);
    setConfigLoading(true);
    setTestResult(null);
    try {
      const response = await cveAPI.getConfig();
      setConfigData(response.data);
      setApiKeyInput('');
    } catch (err) {
      console.error('Error loading config:', err);
    } finally {
      setConfigLoading(false);
    }
  };

  // Salvar configuração
  const handleSaveConfig = async () => {
    if (!apiKeyInput.trim()) {
      alert('Por favor, insira uma API Key válida');
      return;
    }
    
    setConfigLoading(true);
    try {
      await cveAPI.saveConfig({
        api_key: apiKeyInput.trim(),
        enabled: true
      });
      alert('Configuração salva com sucesso!');
      setConfigOpen(false);
      setApiKeyInput('');
      // Recarregar diagnóstico se estiver aberto
      if (diagnosticsOpen) {
        handleDiagnostics();
      }
    } catch (err) {
      console.error('Error saving config:', err);
      alert('Erro ao salvar configuração: ' + (err.response?.data?.error || err.message));
    } finally {
      setConfigLoading(false);
    }
  };

  // Testar conexão
  const handleTestConnection = async () => {
    setTestingConnection(true);
    setTestResult(null);
    try {
      const response = await cveAPI.testConnection(apiKeyInput.trim() || null);
      setTestResult(response.data);
    } catch (err) {
      console.error('Error testing connection:', err);
      setTestResult({
        success: false,
        error: err.response?.data?.error || err.message
      });
    } finally {
      setTestingConnection(false);
    }
  };

  useEffect(() => {
    fetchCVEs();
  }, [fetchCVEs]);

  useEffect(() => {
    fetchStats();
    // Verificar se há sincronização em andamento ao carregar a página
    pollSyncStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Abrir detalhes do CVE
  const handleOpenDetails = (cveId) => {
    setSelectedCVE(cveId);
    setDetailDialogOpen(true);
  };

  // Pesquisa com debounce
  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
    setPage(0);
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 1 }}>
            <BugReportIcon fontSize="large" color="error" />
            Banco de CVEs
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Base de dados de vulnerabilidades com sincronização NVD
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            color="secondary"
            startIcon={<SettingsIcon />}
            onClick={handleOpenConfig}
          >
            Configurar API
          </Button>
          <Button
            variant="outlined"
            color="info"
            startIcon={<NetworkCheckIcon />}
            onClick={handleDiagnostics}
          >
            Diagnóstico
          </Button>
          <Button
            variant="outlined"
            startIcon={<AssessmentIcon />}
            onClick={handleUpdateCounts}
          >
            Atualizar Contagens
          </Button>
          <Button
            variant="contained"
            color="primary"
            startIcon={syncing ? <CircularProgress size={20} color="inherit" /> : <SyncIcon />}
            onClick={handleSync}
            disabled={syncing}
          >
            {syncing ? 'Sincronizando...' : 'Sincronizar NVD'}
          </Button>
        </Box>
      </Box>

      {/* Status da Sincronização */}
      {syncStatus && syncStatus.status !== 'idle' && (
        <Paper sx={{ p: 2, mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: syncStatus.status === 'running' ? 1 : 0 }}>
            {syncStatus.status === 'running' && <CircularProgress size={20} />}
            {syncStatus.status === 'completed' && <CheckCircleIcon color="success" />}
            {syncStatus.status === 'failed' && <ErrorIcon color="error" />}
            <Box sx={{ flex: 1 }}>
              <Typography variant="subtitle2">
                {syncStatus.status === 'running' ? 'Sincronização em andamento...' :
                 syncStatus.status === 'completed' ? 'Sincronização concluída' :
                 syncStatus.status === 'failed' ? 'Falha na sincronização' : ''}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {syncStatus.message}
              </Typography>
              {syncStatus.status === 'running' && syncStatus.total > 0 && (
                <Typography variant="caption" color="text.secondary">
                  {syncStatus.indexed || 0} de {syncStatus.total} CVEs indexados
                  {syncStatus.errors > 0 && ` (${syncStatus.errors} erros)`}
                </Typography>
              )}
            </Box>
            {(syncStatus.status === 'completed' || syncStatus.status === 'failed') && (
              <IconButton size="small" onClick={() => setSyncStatus(null)}>
                <CancelIcon fontSize="small" />
              </IconButton>
            )}
          </Box>
          {syncStatus.status === 'running' && (
            <LinearProgress 
              variant={syncStatus.total > 0 ? 'determinate' : 'indeterminate'} 
              value={syncStatus.progress || 0}
              sx={{ mt: 1, borderRadius: 1 }}
            />
          )}
          {syncStatus.status === 'failed' && syncStatus.lastError && (
            <Alert severity="error" sx={{ mt: 1 }}>
              {syncStatus.lastError}
            </Alert>
          )}
        </Paper>
      )}

      {/* Cards de Estatísticas */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Total CVEs"
            value={stats?.totalCVEs}
            icon={BugReportIcon}
            color="#6366f1"
            subtitle="Vulnerabilidades registradas"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Críticos"
            value={stats?.bySeverity?.CRITICAL}
            icon={ErrorIcon}
            color="#dc2626"
            subtitle="Score CVSS 9.0+"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Com Alertas"
            value={stats?.withAlerts}
            icon={AlertIcon}
            color="#f59e0b"
            subtitle={`${stats?.totalAlerts || 0} alertas totais`}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Exploits Conhecidos"
            value={stats?.exploitedCVEs}
            icon={WarningIcon}
            color="#ef4444"
            subtitle="Com exploit público"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="CISA KEV"
            value={stats?.cisaKnownExploits}
            icon={ShieldIcon}
            color="#8b5cf6"
            subtitle="Exploits conhecidos CISA"
          />
        </Grid>
      </Grid>

      {/* Top CVEs por Alertas */}
      {stats?.topCVEsByAlerts && stats.topCVEsByAlerts.length > 0 && (
        <Paper sx={{ p: 2, mb: 3 }}>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <TimelineIcon color="warning" />
            Top CVEs com Mais Alertas
          </Typography>
          <Grid container spacing={2}>
            {stats.topCVEsByAlerts.slice(0, 5).map((cve) => (
              <Grid item xs={12} sm={6} md={2.4} key={cve.cveId}>
                <Card
                  sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
                  onClick={() => handleOpenDetails(cve.cveId)}
                >
                  <CardContent sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontFamily: 'monospace' }}>
                        {cve.cveId}
                      </Typography>
                      <SeverityChip severity={cve.severity} />
                    </Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <Typography variant="caption" color="text.secondary">
                        Score: {cve.cvssScore?.toFixed(1)}
                      </Typography>
                      <Chip
                        label={`${cve.alertCount} alertas`}
                        size="small"
                        color="warning"
                        variant="outlined"
                      />
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
      )}

      {/* Filtros e Busca */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              placeholder="Buscar por CVE ID ou descrição..."
              value={searchTerm}
              onChange={handleSearch}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
              size="small"
            />
          </Grid>
          <Grid item xs={6} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Severidade</InputLabel>
              <Select
                value={severityFilter}
                label="Severidade"
                onChange={(e) => { setSeverityFilter(e.target.value); setPage(0); }}
              >
                <MenuItem value="">Todas</MenuItem>
                <MenuItem value="CRITICAL">Crítico</MenuItem>
                <MenuItem value="HIGH">Alto</MenuItem>
                <MenuItem value="MEDIUM">Médio</MenuItem>
                <MenuItem value="LOW">Baixo</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={6} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Ordenar por</InputLabel>
              <Select
                value={sortBy}
                label="Ordenar por"
                onChange={(e) => setSortBy(e.target.value)}
              >
                <MenuItem value="cvssScore">Score CVSS</MenuItem>
                <MenuItem value="alertCount">Alertas</MenuItem>
                <MenuItem value="publishedDate">Data Publicação</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={6} md={2}>
            <Button
              variant={withAlertsFilter ? 'contained' : 'outlined'}
              color={withAlertsFilter ? 'warning' : 'inherit'}
              onClick={() => { setWithAlertsFilter(!withAlertsFilter); setPage(0); }}
              startIcon={<AlertIcon />}
              fullWidth
            >
              Com Alertas
            </Button>
          </Grid>
          <Grid item xs={6} md={2}>
            <Button
              variant="outlined"
              onClick={() => fetchCVEs()}
              startIcon={<RefreshIcon />}
              fullWidth
            >
              Atualizar
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Tabela de CVEs */}
      <Paper>
        {loading && <LinearProgress />}
        {error && <Alert severity="error" sx={{ m: 2 }}>{error}</Alert>}
        
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: 'action.hover' }}>
                <TableCell sx={{ fontWeight: 'bold' }}>CVE ID</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }}>Severidade</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }}>CVSS</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }}>Descrição</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }} align="center">Alertas</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }} align="center">Eventos</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }}>Status</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }}>Publicado</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }} align="center">Ações</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {cves.length === 0 && !loading ? (
                <TableRow>
                  <TableCell colSpan={9} align="center" sx={{ py: 4 }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                      <BugReportIcon sx={{ fontSize: 48, color: 'text.disabled' }} />
                      <Typography color="text.secondary">
                        Nenhum CVE encontrado. Clique em "Sincronizar NVD" para importar dados.
                      </Typography>
                    </Box>
                  </TableCell>
                </TableRow>
              ) : (
                cves.map((cve) => (
                  <TableRow
                    key={cve.id}
                    hover
                    sx={{ cursor: 'pointer' }}
                    onClick={() => handleOpenDetails(cve.id)}
                  >
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontWeight: 'bold' }}>
                        {cve.id}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <SeverityChip severity={cve.severity} />
                    </TableCell>
                    <TableCell>
                      <CVSSScore score={cve.cvssScore} />
                    </TableCell>
                    <TableCell sx={{ maxWidth: 400 }}>
                      <Tooltip title={cve.description}>
                        <Typography variant="body2" noWrap>
                          {cve.description?.substring(0, 100)}...
                        </Typography>
                      </Tooltip>
                    </TableCell>
                    <TableCell align="center">
                      {cve.alertCount > 0 ? (
                        <Chip
                          label={cve.alertCount}
                          size="small"
                          color="warning"
                        />
                      ) : (
                        <Typography variant="body2" color="text.disabled">0</Typography>
                      )}
                    </TableCell>
                    <TableCell align="center">
                      {cve.eventCount > 0 ? (
                        <Chip
                          label={cve.eventCount}
                          size="small"
                          color="info"
                        />
                      ) : (
                        <Typography variant="body2" color="text.disabled">0</Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {cve.exploitAvailable && (
                          <Tooltip title="Exploit Disponível">
                            <WarningIcon fontSize="small" color="error" />
                          </Tooltip>
                        )}
                        {cve.cisaKnownExploit && (
                          <Tooltip title="CISA Known Exploit">
                            <ShieldIcon fontSize="small" color="warning" />
                          </Tooltip>
                        )}
                        {cve.patchAvailable && (
                          <Tooltip title="Patch Disponível">
                            <CheckCircleIcon fontSize="small" color="success" />
                          </Tooltip>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {cve.publishedDate ? new Date(cve.publishedDate).toLocaleDateString('pt-BR') : 'N/A'}
                      </Typography>
                    </TableCell>
                    <TableCell align="center">
                      <Tooltip title="Ver no NVD">
                        <IconButton
                          size="small"
                          onClick={(e) => {
                            e.stopPropagation();
                            window.open(`https://nvd.nist.gov/vuln/detail/${cve.id}`, '_blank');
                          }}
                        >
                          <OpenInNewIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
        
        <TablePagination
          component="div"
          count={totalCVEs}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[10, 25, 50, 100]}
          labelRowsPerPage="Por página:"
          labelDisplayedRows={({ from, to, count }) => `${from}-${to} de ${count}`}
        />
      </Paper>

      {/* Dialog de Detalhes */}
      <CVEDetailDialog
        open={detailDialogOpen}
        onClose={() => setDetailDialogOpen(false)}
        cveId={selectedCVE}
      />

      {/* Dialog de Diagnóstico */}
      <Dialog open={diagnosticsOpen} onClose={() => setDiagnosticsOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <NetworkCheckIcon color="info" />
          Diagnóstico de Conectividade NVD
        </DialogTitle>
        <DialogContent dividers>
          {diagnosticsLoading ? (
            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', p: 4, gap: 2 }}>
              <CircularProgress />
              <Typography>Executando diagnóstico...</Typography>
            </Box>
          ) : diagnosticsData ? (
            <Box>
              {/* Status Geral */}
              <Alert 
                severity={
                  diagnosticsData.overall_status === 'healthy' ? 'success' :
                  diagnosticsData.overall_status === 'degraded' ? 'warning' : 'error'
                }
                sx={{ mb: 3 }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>
                  Status Geral: {diagnosticsData.overall_status?.toUpperCase()}
                </Typography>
                <Typography variant="caption">
                  {diagnosticsData.timestamp && new Date(diagnosticsData.timestamp).toLocaleString('pt-BR')}
                </Typography>
              </Alert>

              {/* Checks */}
              <Typography variant="h6" gutterBottom>Verificações</Typography>
              <List>
                {diagnosticsData.checks?.map((check, index) => (
                  <ListItem key={index} divider>
                    <ListItemIcon>
                      {check.status === 'pass' ? (
                        <CheckCircleIcon color="success" />
                      ) : check.status === 'warning' ? (
                        <WarningIcon color="warning" />
                      ) : (
                        <CancelIcon color="error" />
                      )}
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="subtitle2">{check.name}</Typography>
                          <Chip 
                            label={check.status?.toUpperCase()} 
                            size="small" 
                            color={
                              check.status === 'pass' ? 'success' :
                              check.status === 'warning' ? 'warning' : 'error'
                            }
                          />
                        </Box>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary">
                            {check.message}
                          </Typography>
                          {check.latency && (
                            <Typography variant="caption" color="text.secondary">
                              Latência: {check.latency}
                            </Typography>
                          )}
                          {check.cve_count !== undefined && (
                            <Typography variant="caption" sx={{ ml: 2 }} color="text.secondary">
                              CVEs: {check.cve_count}
                            </Typography>
                          )}
                          {check.rate_limit && (
                            <Typography variant="caption" sx={{ ml: 2 }} color="text.secondary">
                              Rate Limit: {check.rate_limit}
                            </Typography>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>

              {/* Recomendações */}
              {diagnosticsData.recommendations?.length > 0 && (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="h6" gutterBottom>Recomendações</Typography>
                  <Alert severity="info">
                    <ul style={{ margin: 0, paddingLeft: 20 }}>
                      {diagnosticsData.recommendations.map((rec, idx) => (
                        <li key={idx}>{rec}</li>
                      ))}
                    </ul>
                  </Alert>
                </Box>
              )}
            </Box>
          ) : (
            <Alert severity="error">Erro ao carregar diagnóstico</Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDiagnostics} startIcon={<RefreshIcon />}>
            Executar Novamente
          </Button>
          <Button onClick={() => setDiagnosticsOpen(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Configuração */}
      <Dialog open={configOpen} onClose={() => setConfigOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <KeyIcon color="secondary" />
          Configurar NVD API Key
        </DialogTitle>
        <DialogContent dividers>
          {configLoading && !configData ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
              <CircularProgress />
            </Box>
          ) : (
            <Box>
              {/* Status atual */}
              {configData && (
                <Alert 
                  severity={configData.config?.api_key_configured ? 'success' : 'warning'}
                  sx={{ mb: 3 }}
                >
                  <Typography variant="subtitle2">
                    {configData.config?.api_key_configured 
                      ? `API Key configurada (${configData.config.api_key_masked || '****'})`
                      : 'API Key não configurada'}
                  </Typography>
                  <Typography variant="caption">
                    Fonte: {configData.source === 'database' ? 'Banco de dados' : 'Variável de ambiente'}
                    {configData.config?.last_updated && (
                      <> | Atualizado: {new Date(configData.config.last_updated).toLocaleString('pt-BR')}</>
                    )}
                  </Typography>
                </Alert>
              )}

              {/* Formulário */}
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Insira sua API Key do NVD para aumentar o rate limit de 5 para 50 requests/30s.
                Obtenha sua chave em: <Link href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank">nvd.nist.gov</Link>
              </Typography>

              <TextField
                fullWidth
                label="NVD API Key"
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                value={apiKeyInput}
                onChange={(e) => setApiKeyInput(e.target.value)}
                type={showApiKey ? 'text' : 'password'}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton onClick={() => setShowApiKey(!showApiKey)} edge="end">
                        {showApiKey ? <VisibilityOffIcon /> : <VisibilityIcon />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
                sx={{ mb: 2 }}
              />

              {/* Botão de teste */}
              <Button
                variant="outlined"
                onClick={handleTestConnection}
                disabled={testingConnection}
                startIcon={testingConnection ? <CircularProgress size={20} /> : <NetworkCheckIcon />}
                sx={{ mb: 2 }}
              >
                {testingConnection ? 'Testando...' : 'Testar Conexão'}
              </Button>

              {/* Resultado do teste */}
              {testResult && (
                <Alert severity={testResult.success ? 'success' : 'error'} sx={{ mt: 2 }}>
                  <Typography variant="subtitle2">
                    {testResult.success ? 'Conexão OK!' : 'Falha na conexão'}
                  </Typography>
                  <Typography variant="body2">
                    {testResult.message || testResult.error}
                  </Typography>
                  {testResult.latency && (
                    <Typography variant="caption">
                      Latência: {testResult.latency}
                      {testResult.rate_limit && <> | Rate Limit: {testResult.rate_limit}</>}
                    </Typography>
                  )}
                </Alert>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigOpen(false)}>Cancelar</Button>
          <Button 
            variant="contained" 
            onClick={handleSaveConfig}
            disabled={configLoading || !apiKeyInput.trim()}
          >
            Salvar Configuração
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default CVEDatabase;

