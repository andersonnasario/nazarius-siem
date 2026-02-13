import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TablePagination,
  Chip, CircularProgress, Alert, Button, IconButton, Tooltip,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField, Snackbar,
  FormControlLabel, Switch, Checkbox, FormGroup, FormLabel
} from '@mui/material';
import {
  Cloud as CloudIcon,
  Security as SecurityIcon,
  Sync as SyncIcon,
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Settings as SettingsIcon,
  Visibility as VisibilityIcon,
  BugReport as BugReportIcon,
  Storage as StorageIcon,
  Article as ArticleIcon,
} from '@mui/icons-material';
import { cspmAPI } from '../services/api';

const CSPMGCPIntegrations = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [syncing, setSyncing] = useState(false);

  // GCP Data
  const [status, setStatus] = useState(null);
  const [config, setConfig] = useState({
    project_id: '',
    organization_id: '',
    credentials_json: '',
    enabled: false,
    sync_period_minutes: 30,
    enabled_services: ['scc', 'asset', 'audit'],
  });
  const [findings, setFindings] = useState([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [stats, setStats] = useState({});
  const [diagnostic, setDiagnostic] = useState(null);

  // Pagination & Filters
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(500);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');

  // Dialogs
  const [configDialog, setConfigDialog] = useState(false);
  const [eventDialog, setEventDialog] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'info' });

  // Config form state
  const [configForm, setConfigForm] = useState({ ...config });
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const [statusRes, statsRes] = await Promise.all([
        cspmAPI.gcp.getStatus(),
        cspmAPI.gcp.getStats(),
      ]);

      setStatus(statusRes.data || {});
      setStats(statsRes.data || {});

      // Load findings
      await loadFindings();
    } catch (err) {
      setError('Falha ao carregar dados GCP');
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadFindings = useCallback(async () => {
    try {
      const params = {
        page: page + 1,
        page_size: rowsPerPage,
      };
      if (searchTerm) params.search = searchTerm;
      if (severityFilter) params.severity = severityFilter;
      if (sourceFilter) params.source = sourceFilter;

      const res = await cspmAPI.gcp.getFindings(params);
      setFindings(res.data?.findings || []);
      setFindingsTotal(res.data?.total || 0);
    } catch (err) {
      console.error('Error loading findings:', err);
    }
  }, [page, rowsPerPage, searchTerm, severityFilter, sourceFilter]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    if (!loading) {
      loadFindings();
    }
  }, [page, rowsPerPage, searchTerm, severityFilter, sourceFilter]);

  const handleSync = async () => {
    try {
      setSyncing(true);
      await cspmAPI.gcp.sync();
      setSnackbar({ open: true, message: 'Sincronizacao GCP iniciada', severity: 'success' });
      setTimeout(() => loadData(), 3000);
    } catch (err) {
      setSnackbar({ open: true, message: 'Falha na sincronizacao', severity: 'error' });
    } finally {
      setSyncing(false);
    }
  };

  const handleOpenConfig = async () => {
    try {
      const res = await cspmAPI.gcp.getConfig();
      const data = res.data || {};
      setConfigForm({
        project_id: data.project_id || '',
        organization_id: data.organization_id || '',
        credentials_json: '',
        enabled: data.enabled || false,
        sync_period_minutes: data.sync_period_minutes || 30,
        enabled_services: data.enabled_services || ['scc', 'asset', 'audit'],
      });
      setTestResult(null);
      setConfigDialog(true);
    } catch (err) {
      console.error(err);
    }
  };

  const handleTestConnection = async () => {
    try {
      setTesting(true);
      setTestResult(null);
      const res = await cspmAPI.gcp.testConnection({
        project_id: configForm.project_id,
        organization_id: configForm.organization_id,
        credentials_json: configForm.credentials_json,
      });
      setTestResult(res.data);
    } catch (err) {
      setTestResult({ success: false, message: err.message });
    } finally {
      setTesting(false);
    }
  };

  const handleSaveConfig = async () => {
    try {
      await cspmAPI.gcp.saveConfig(configForm);
      setSnackbar({ open: true, message: 'Configuracao GCP salva com sucesso', severity: 'success' });
      setConfigDialog(false);
      loadData();
    } catch (err) {
      setSnackbar({ open: true, message: 'Erro ao salvar configuracao', severity: 'error' });
    }
  };

  const handleViewEvent = (event) => {
    setSelectedEvent(event);
    setEventDialog(true);
  };

  const toggleService = (service) => {
    setConfigForm(prev => {
      const services = [...prev.enabled_services];
      const idx = services.indexOf(service);
      if (idx > -1) {
        services.splice(idx, 1);
      } else {
        services.push(service);
      }
      return { ...prev, enabled_services: services };
    });
  };

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: 'error', critical: 'error',
      HIGH: 'error', high: 'error',
      MEDIUM: 'warning', medium: 'warning',
      LOW: 'info', low: 'info',
      INFO: 'default', info: 'default',
      INFORMATIONAL: 'default',
    };
    return colors[severity] || 'default';
  };

  const getSourceLabel = (source) => {
    const labels = {
      scc: 'Security Command Center',
      asset_inventory: 'Cloud Asset Inventory',
      audit_log: 'Cloud Audit Logs',
    };
    return labels[source] || source;
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box mb={3} display="flex" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" gutterBottom>
            <CloudIcon sx={{ mr: 1, verticalAlign: 'middle', color: '#4285F4' }} />
            Google Cloud Platform - CSPM
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Monitoramento de postura de seguranca via Security Command Center, Cloud Asset Inventory e Cloud Audit Logs
          </Typography>
        </Box>
        <Box>
          <Button
            variant="outlined"
            startIcon={<SettingsIcon />}
            onClick={handleOpenConfig}
            sx={{ mr: 1 }}
          >
            Configurar
          </Button>
          <Button
            variant="outlined"
            startIcon={syncing ? <CircularProgress size={20} /> : <SyncIcon />}
            onClick={handleSync}
            disabled={syncing}
            sx={{ mr: 1 }}
          >
            {syncing ? 'Sincronizando...' : 'Sincronizar'}
          </Button>
          <Button
            variant="contained"
            startIcon={<RefreshIcon />}
            onClick={loadData}
          >
            Atualizar
          </Button>
        </Box>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {/* Status Cards */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Status</Typography>
                  <Typography variant="h5">
                    {status?.enabled ? 'Ativo' : 'Inativo'}
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    {status?.configured ? 'Configurado' : 'Nao configurado'}
                  </Typography>
                </Box>
                {status?.enabled ? (
                  <CheckCircleIcon sx={{ fontSize: 40, color: 'success.main', opacity: 0.5 }} />
                ) : (
                  <ErrorIcon sx={{ fontSize: 40, color: 'grey.400', opacity: 0.5 }} />
                )}
              </Box>
              <Chip
                label={status?.running ? 'Coletando' : 'Parado'}
                color={status?.running ? 'success' : 'default'}
                size="small"
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Total Findings</Typography>
                  <Typography variant="h4">
                    {(status?.events_collected || 0).toLocaleString()}
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    {stats?.total_24h || 0} nas ultimas 24h
                  </Typography>
                </Box>
                <SecurityIcon sx={{ fontSize: 40, color: '#4285F4', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Projeto</Typography>
                  <Typography variant="h6" noWrap>
                    {status?.project_id || 'N/A'}
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    Org: {status?.organization_id || 'N/A'}
                  </Typography>
                </Box>
                <StorageIcon sx={{ fontSize: 40, color: '#34A853', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Ultima Sincronizacao</Typography>
                  <Typography variant="body1">
                    {status?.last_sync ? new Date(status.last_sync).toLocaleString('pt-BR') : 'Nunca'}
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    Periodo: {status?.sync_period || 30} min
                  </Typography>
                </Box>
                <SyncIcon sx={{ fontSize: 40, color: '#FBBC04', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)}>
          <Tab label="Findings" icon={<SecurityIcon />} iconPosition="start" />
          <Tab label="Estatisticas" icon={<ArticleIcon />} iconPosition="start" />
          <Tab label="Diagnostico" icon={<BugReportIcon />} iconPosition="start" />
        </Tabs>
      </Paper>

      {/* Tab Panels */}
      {activeTab === 0 && (
        <Paper>
          {/* Filters */}
          <Box p={2} display="flex" gap={2} alignItems="center" flexWrap="wrap">
            <TextField
              size="small"
              label="Buscar"
              value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setPage(0); }}
              sx={{ minWidth: 250 }}
            />
            <TextField
              select
              size="small"
              label="Severidade"
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value); setPage(0); }}
              sx={{ minWidth: 150 }}
              SelectProps={{ native: true }}
            >
              <option value="">Todas</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </TextField>
            <TextField
              select
              size="small"
              label="Fonte"
              value={sourceFilter}
              onChange={(e) => { setSourceFilter(e.target.value); setPage(0); }}
              sx={{ minWidth: 200 }}
              SelectProps={{ native: true }}
            >
              <option value="">Todas</option>
              <option value="scc">Security Command Center</option>
              <option value="asset_inventory">Cloud Asset Inventory</option>
              <option value="audit_log">Cloud Audit Logs</option>
            </TextField>
            <Typography variant="body2" color="textSecondary" sx={{ ml: 'auto' }}>
              {findingsTotal.toLocaleString()} findings encontrados
            </Typography>
          </Box>

          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Severidade</TableCell>
                  <TableCell>Categoria</TableCell>
                  <TableCell>Titulo</TableCell>
                  <TableCell>Recurso</TableCell>
                  <TableCell>Fonte</TableCell>
                  <TableCell>Data</TableCell>
                  <TableCell>Estado</TableCell>
                  <TableCell align="center">Acoes</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {findings.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      <Typography color="textSecondary" py={3}>
                        Nenhum finding encontrado. Configure a integracao GCP para comecar a coletar.
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  findings.map((finding, idx) => (
                    <TableRow key={finding._id || idx} hover>
                      <TableCell>
                        <Chip
                          label={finding.severity || 'N/A'}
                          color={getSeverityColor(finding.severity)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>{finding.category || '-'}</TableCell>
                      <TableCell sx={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {finding.title || '-'}
                      </TableCell>
                      <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        <Tooltip title={finding.resource_name || ''}>
                          <span>{finding.resource_name?.split('/').pop() || '-'}</span>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <Chip label={getSourceLabel(finding.source)} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        {finding.event_time ? new Date(finding.event_time).toLocaleString('pt-BR') : '-'}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={finding.state || 'N/A'}
                          color={finding.state === 'ACTIVE' ? 'warning' : 'default'}
                          size="small"
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="Ver detalhes">
                          <IconButton size="small" onClick={() => handleViewEvent(finding)}>
                            <VisibilityIcon fontSize="small" />
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
            count={findingsTotal}
            page={page}
            onPageChange={(_, newPage) => setPage(newPage)}
            rowsPerPage={rowsPerPage}
            onRowsPerPageChange={(e) => { setRowsPerPage(parseInt(e.target.value, 10)); setPage(0); }}
            rowsPerPageOptions={[100, 250, 500]}
            labelRowsPerPage="Findings por pagina:"
          />
        </Paper>
      )}

      {activeTab === 1 && (
        <Grid container spacing={3}>
          {/* Severity Distribution */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Distribuicao por Severidade (24h)</Typography>
              {stats?.by_severity?.length > 0 ? (
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Severidade</TableCell>
                      <TableCell align="right">Quantidade</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {stats.by_severity.map((item, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Chip label={item.key} color={getSeverityColor(item.key)} size="small" />
                        </TableCell>
                        <TableCell align="right">{item.count?.toLocaleString()}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <Typography color="textSecondary">Sem dados</Typography>
              )}
            </Paper>
          </Grid>

          {/* Source Distribution */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Distribuicao por Fonte (24h)</Typography>
              {stats?.by_source?.length > 0 ? (
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Fonte</TableCell>
                      <TableCell align="right">Quantidade</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {stats.by_source.map((item, idx) => (
                      <TableRow key={idx}>
                        <TableCell>{getSourceLabel(item.key)}</TableCell>
                        <TableCell align="right">{item.count?.toLocaleString()}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <Typography color="textSecondary">Sem dados</Typography>
              )}
            </Paper>
          </Grid>

          {/* Category Distribution */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Distribuicao por Categoria (24h)</Typography>
              {stats?.by_category?.length > 0 ? (
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Categoria</TableCell>
                      <TableCell align="right">Quantidade</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {stats.by_category.map((item, idx) => (
                      <TableRow key={idx}>
                        <TableCell>{item.key}</TableCell>
                        <TableCell align="right">{item.count?.toLocaleString()}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <Typography color="textSecondary">Sem dados</Typography>
              )}
            </Paper>
          </Grid>

          {/* State Distribution */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Distribuicao por Estado (24h)</Typography>
              {stats?.by_state?.length > 0 ? (
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Estado</TableCell>
                      <TableCell align="right">Quantidade</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {stats.by_state.map((item, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Chip label={item.key} color={item.key === 'ACTIVE' ? 'warning' : 'default'} size="small" />
                        </TableCell>
                        <TableCell align="right">{item.count?.toLocaleString()}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <Typography color="textSecondary">Sem dados</Typography>
              )}
            </Paper>
          </Grid>
        </Grid>
      )}

      {activeTab === 2 && (
        <Paper sx={{ p: 3 }}>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">Diagnostico GCP</Typography>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={async () => {
                try {
                  const res = await cspmAPI.gcp.getDiagnostic();
                  setDiagnostic(res.data);
                } catch (err) {
                  console.error(err);
                }
              }}
            >
              Executar Diagnostico
            </Button>
          </Box>

          {diagnostic ? (
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Verificacao</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Detalhes</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {diagnostic.checks?.map((check, idx) => (
                  <TableRow key={idx}>
                    <TableCell><strong>{check.name}</strong></TableCell>
                    <TableCell>
                      {check.status ? (
                        <CheckCircleIcon color="success" fontSize="small" />
                      ) : (
                        <ErrorIcon color="error" fontSize="small" />
                      )}
                    </TableCell>
                    <TableCell>{check.message}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <Typography color="textSecondary">
              Clique em "Executar Diagnostico" para verificar o estado da integracao GCP.
            </Typography>
          )}
        </Paper>
      )}

      {/* Config Dialog */}
      <Dialog open={configDialog} onClose={() => setConfigDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Configuracao Google Cloud Platform</DialogTitle>
        <DialogContent dividers>
          <Box display="flex" flexDirection="column" gap={2} mt={1}>
            <Alert severity="info">
              Para conectar ao GCP, voce precisa de uma Service Account com as permissoes necessarias
              (Security Command Center Viewer, Cloud Asset Viewer, Logs Viewer).
              Exporte o JSON da chave e cole abaixo, ou configure a variavel de ambiente GOOGLE_APPLICATION_CREDENTIALS no servidor.
            </Alert>

            <TextField
              fullWidth
              label="Project ID"
              value={configForm.project_id}
              onChange={(e) => setConfigForm(prev => ({ ...prev, project_id: e.target.value }))}
              helperText="ID do projeto GCP (ex: my-project-123)"
            />

            <TextField
              fullWidth
              label="Organization ID (opcional)"
              value={configForm.organization_id}
              onChange={(e) => setConfigForm(prev => ({ ...prev, organization_id: e.target.value }))}
              helperText="ID da organizacao para escopo organizacional (ex: 123456789)"
            />

            <TextField
              fullWidth
              multiline
              minRows={4}
              maxRows={8}
              label="Service Account JSON Key"
              value={configForm.credentials_json}
              onChange={(e) => setConfigForm(prev => ({ ...prev, credentials_json: e.target.value }))}
              helperText="Cole o conteudo do arquivo JSON da Service Account. Deixe vazio para usar GOOGLE_APPLICATION_CREDENTIALS."
              placeholder='{"type": "service_account", "project_id": "...", ...}'
            />

            <TextField
              fullWidth
              type="number"
              label="Periodo de Sincronizacao (minutos)"
              value={configForm.sync_period_minutes}
              onChange={(e) => setConfigForm(prev => ({ ...prev, sync_period_minutes: parseInt(e.target.value, 10) || 30 }))}
              helperText="Intervalo entre coletas automaticas"
              inputProps={{ min: 5, max: 1440 }}
            />

            <Box>
              <FormLabel component="legend">Servicos Habilitados</FormLabel>
              <FormGroup row>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={configForm.enabled_services.includes('scc')}
                      onChange={() => toggleService('scc')}
                    />
                  }
                  label="Security Command Center"
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={configForm.enabled_services.includes('asset')}
                      onChange={() => toggleService('asset')}
                    />
                  }
                  label="Cloud Asset Inventory"
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={configForm.enabled_services.includes('audit')}
                      onChange={() => toggleService('audit')}
                    />
                  }
                  label="Cloud Audit Logs"
                />
              </FormGroup>
            </Box>

            <FormControlLabel
              control={
                <Switch
                  checked={configForm.enabled}
                  onChange={(e) => setConfigForm(prev => ({ ...prev, enabled: e.target.checked }))}
                  color="primary"
                />
              }
              label="Habilitar coleta automatica"
            />

            {/* Test Connection */}
            <Box>
              <Button
                variant="outlined"
                onClick={handleTestConnection}
                disabled={testing || (!configForm.project_id && !configForm.organization_id)}
                startIcon={testing ? <CircularProgress size={20} /> : <SecurityIcon />}
              >
                {testing ? 'Testando...' : 'Testar Conexao'}
              </Button>
            </Box>

            {testResult && (
              <Alert severity={testResult.success ? 'success' : 'warning'}>
                <Typography variant="subtitle2">{testResult.message}</Typography>
                {testResult.tests?.map((test, idx) => (
                  <Box key={idx} display="flex" alignItems="center" gap={1} mt={0.5}>
                    {test.success ? (
                      <CheckCircleIcon fontSize="small" color="success" />
                    ) : (
                      <ErrorIcon fontSize="small" color="error" />
                    )}
                    <Typography variant="body2">
                      {test.name}: {test.success ? 'OK' : test.error}
                    </Typography>
                  </Box>
                ))}
              </Alert>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigDialog(false)}>Cancelar</Button>
          <Button onClick={handleSaveConfig} variant="contained" color="primary">
            Salvar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Event Detail Dialog */}
      <Dialog open={eventDialog} onClose={() => setEventDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Detalhes do Finding</DialogTitle>
        <DialogContent dividers>
          {selectedEvent && (
            <Box>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="caption" color="textSecondary">Categoria</Typography>
                  <Typography>{selectedEvent.category || '-'}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="textSecondary">Severidade</Typography>
                  <Box>
                    <Chip label={selectedEvent.severity || 'N/A'} color={getSeverityColor(selectedEvent.severity)} size="small" />
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="textSecondary">Fonte</Typography>
                  <Typography>{getSourceLabel(selectedEvent.source)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="textSecondary">Estado</Typography>
                  <Typography>{selectedEvent.state || '-'}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="textSecondary">Titulo</Typography>
                  <Typography>{selectedEvent.title || '-'}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="textSecondary">Descricao</Typography>
                  <Typography variant="body2">{selectedEvent.description || '-'}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="textSecondary">Recurso</Typography>
                  <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
                    {selectedEvent.resource_name || '-'}
                  </Typography>
                </Grid>
                {selectedEvent.resource_type && (
                  <Grid item xs={6}>
                    <Typography variant="caption" color="textSecondary">Tipo de Recurso</Typography>
                    <Typography variant="body2">{selectedEvent.resource_type}</Typography>
                  </Grid>
                )}
                <Grid item xs={6}>
                  <Typography variant="caption" color="textSecondary">Projeto</Typography>
                  <Typography variant="body2">{selectedEvent.project_id || '-'}</Typography>
                </Grid>
                {selectedEvent.external_uri && (
                  <Grid item xs={12}>
                    <Typography variant="caption" color="textSecondary">Link Externo</Typography>
                    <Typography variant="body2">
                      <a href={selectedEvent.external_uri} target="_blank" rel="noopener noreferrer">
                        {selectedEvent.external_uri}
                      </a>
                    </Typography>
                  </Grid>
                )}
                {selectedEvent.recommendation && (
                  <Grid item xs={12}>
                    <Typography variant="caption" color="textSecondary">Recomendacao</Typography>
                    <Typography variant="body2">{selectedEvent.recommendation}</Typography>
                  </Grid>
                )}
                <Grid item xs={6}>
                  <Typography variant="caption" color="textSecondary">Data do Evento</Typography>
                  <Typography variant="body2">
                    {selectedEvent.event_time ? new Date(selectedEvent.event_time).toLocaleString('pt-BR') : '-'}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="textSecondary">Indexado em</Typography>
                  <Typography variant="body2">
                    {selectedEvent.indexed_at ? new Date(selectedEvent.indexed_at).toLocaleString('pt-BR') : '-'}
                  </Typography>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEventDialog(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
          severity={snackbar.severity}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default CSPMGCPIntegrations;
