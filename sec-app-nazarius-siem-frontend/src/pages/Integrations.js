import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Button,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  LinearProgress,
  Tooltip,
  Switch,
  FormControlLabel,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  PlayArrow as PlayArrowIcon,
  Sync as SyncIcon,
  Security as SecurityIcon,
  Cloud as CloudIcon,
  Shield as ShieldIcon,
  People as PeopleIcon,
  CheckBox as CheckBoxIcon,
  Settings as SettingsIcon,
  History as HistoryIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { integrationsAPI } from '../services/api';

const Integrations = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [integrations, setIntegrations] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Dialogs
  const [openCreateDialog, setOpenCreateDialog] = useState(false);
  const [openEditDialog, setOpenEditDialog] = useState(false);
  const [openDeleteDialog, setOpenDeleteDialog] = useState(false);
  const [openTestDialog, setOpenTestDialog] = useState(false);
  const [openLogsDialog, setOpenLogsDialog] = useState(false);
  const [openTemplateDialog, setOpenTemplateDialog] = useState(false);
  
  // Selected items
  const [selectedIntegration, setSelectedIntegration] = useState(null);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [integrationLogs, setIntegrationLogs] = useState([]);
  const [testResult, setTestResult] = useState(null);
  
  // Form data
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    type: '',
    vendor: '',
    enabled: true,
    configuration: {},
    credentials: {
      type: 'api_key',
      endpoint: '',
      api_key: '',
      secret_key: '',
      username: '',
      password: '',
      region: '',
      tenant_id: '',
    },
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [integrationsRes, templatesRes, statsRes] = await Promise.all([
        integrationsAPI.list(),
        integrationsAPI.getTemplates(),
        integrationsAPI.getStats(),
      ]);
      setIntegrations(integrationsRes.data.integrations || []);
      setTemplates(templatesRes.data.templates || []);
      setStats(statsRes.data);
      setError(null);
    } catch (err) {
      setError('Erro ao carregar integrações');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateFromTemplate = (template) => {
    setSelectedTemplate(template);
    setFormData({
      name: template.name,
      description: template.description,
      type: template.type,
      vendor: template.vendor,
      enabled: true,
      configuration: template.default_config || {},
      credentials: {
        type: 'api_key',
        endpoint: '',
        api_key: '',
        secret_key: '',
        username: '',
        password: '',
        region: '',
        tenant_id: '',
      },
    });
    setOpenTemplateDialog(true);
  };

  const handleCreateIntegration = async () => {
    try {
      await integrationsAPI.create(formData);
      setOpenCreateDialog(false);
      setOpenTemplateDialog(false);
      loadData();
    } catch (err) {
      console.error('Erro ao criar integração:', err);
    }
  };

  const handleUpdateIntegration = async () => {
    try {
      await integrationsAPI.update(selectedIntegration.id, formData);
      setOpenEditDialog(false);
      loadData();
    } catch (err) {
      console.error('Erro ao atualizar integração:', err);
    }
  };

  const handleDeleteIntegration = async () => {
    try {
      await integrationsAPI.delete(selectedIntegration.id);
      setOpenDeleteDialog(false);
      loadData();
    } catch (err) {
      console.error('Erro ao deletar integração:', err);
    }
  };

  const handleTestConnection = async (integration) => {
    setSelectedIntegration(integration);
    setTestResult(null);
    setOpenTestDialog(true);
    
    try {
      const response = await integrationsAPI.test(integration.id);
      setTestResult(response.data);
    } catch (err) {
      setTestResult({
        success: false,
        message: err.response?.data?.error || 'Erro ao testar conexão',
      });
    }
  };

  const handleSyncIntegration = async (integration) => {
    try {
      await integrationsAPI.sync(integration.id);
      loadData();
    } catch (err) {
      console.error('Erro ao sincronizar:', err);
    }
  };

  const handleViewLogs = async (integration) => {
    setSelectedIntegration(integration);
    try {
      const response = await integrationsAPI.getLogs(integration.id);
      setIntegrationLogs(response.data.logs || []);
      setOpenLogsDialog(true);
    } catch (err) {
      console.error('Erro ao carregar logs:', err);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'success';
      case 'inactive': return 'default';
      case 'error': return 'error';
      case 'configuring': return 'warning';
      case 'testing': return 'info';
      default: return 'default';
    }
  };

  const getHealthColor = (health) => {
    if (!health) return 'default';
    if (health.success_rate >= 95) return 'success';
    if (health.success_rate >= 80) return 'warning';
    return 'error';
  };

  const getVendorIcon = (vendor) => {
    switch (vendor) {
      case 'fortinet': return <SecurityIcon />;
      case 'aws': return <CloudIcon />;
      case 'acronis': return <ShieldIcon />;
      case 'jumpcloud': return <PeopleIcon />;
      default: return <SettingsIcon />;
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatNumber = (num) => {
    return new Intl.NumberFormat('pt-BR').format(num);
  };

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography variant="h4" gutterBottom>Integrações</Typography>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">Integrações</Typography>
        <Box>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={loadData}
            sx={{ mr: 1 }}
          >
            Atualizar
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setOpenCreateDialog(true)}
          >
            Nova Integração
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Statistics Cards */}
      {stats && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total de Integrações
                </Typography>
                <Typography variant="h4">{stats.total_integrations}</Typography>
                <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                  <Chip label={`${stats.active} Ativas`} color="success" size="small" />
                  <Chip label={`${stats.inactive} Inativas`} size="small" />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Eventos Coletados
                </Typography>
                <Typography variant="h4">{formatNumber(stats.total_events)}</Typography>
                <Typography variant="body2" color="textSecondary">
                  Total acumulado
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Dados Coletados
                </Typography>
                <Typography variant="h4">{formatBytes(stats.total_data)}</Typography>
                <Typography variant="body2" color="textSecondary">
                  Volume total
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Status de Saúde
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                  <Chip
                    icon={<CheckCircleIcon />}
                    label={stats.health_summary.healthy}
                    color="success"
                    size="small"
                  />
                  <Chip
                    icon={<WarningIcon />}
                    label={stats.health_summary.degraded}
                    color="warning"
                    size="small"
                  />
                  <Chip
                    icon={<ErrorIcon />}
                    label={stats.health_summary.unhealthy}
                    color="error"
                    size="small"
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ mb: 3 }}>
        <Tab label="Integrações Ativas" />
        <Tab label="Templates Disponíveis" />
      </Tabs>

      {/* Active Integrations Tab */}
      {activeTab === 0 && (
        <Grid container spacing={3}>
          {integrations.map((integration) => (
            <Grid item xs={12} md={6} lg={4} key={integration.id}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {getVendorIcon(integration.vendor)}
                      <Typography variant="h6">{integration.name}</Typography>
                    </Box>
                    <Chip
                      label={integration.status}
                      color={getStatusColor(integration.status)}
                      size="small"
                    />
                  </Box>

                  <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
                    {integration.description}
                  </Typography>

                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" color="textSecondary">
                      Tipo: {integration.type} | Vendor: {integration.vendor}
                    </Typography>
                  </Box>

                  {integration.health && (
                    <Box sx={{ mb: 2 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                        <Typography variant="caption">Taxa de Sucesso</Typography>
                        <Typography variant="caption">{integration.health.success_rate}%</Typography>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={integration.health.success_rate}
                        color={getHealthColor(integration.health)}
                      />
                    </Box>
                  )}

                  <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                    <Chip
                      label={`${formatNumber(integration.events_collected)} eventos`}
                      size="small"
                      variant="outlined"
                    />
                    <Chip
                      label={formatBytes(integration.data_collected)}
                      size="small"
                      variant="outlined"
                    />
                  </Box>

                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    <Tooltip title="Testar Conexão">
                      <IconButton
                        size="small"
                        onClick={() => handleTestConnection(integration)}
                        color="primary"
                      >
                        <PlayArrowIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Sincronizar">
                      <IconButton
                        size="small"
                        onClick={() => handleSyncIntegration(integration)}
                        color="primary"
                        disabled={!integration.enabled}
                      >
                        <SyncIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Ver Logs">
                      <IconButton
                        size="small"
                        onClick={() => handleViewLogs(integration)}
                      >
                        <HistoryIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Editar">
                      <IconButton
                        size="small"
                        onClick={() => {
                          setSelectedIntegration(integration);
                          setFormData(integration);
                          setOpenEditDialog(true);
                        }}
                      >
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Deletar">
                      <IconButton
                        size="small"
                        onClick={() => {
                          setSelectedIntegration(integration);
                          setOpenDeleteDialog(true);
                        }}
                        color="error"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Templates Tab */}
      {activeTab === 1 && (
        <Grid container spacing={3}>
          {templates.map((template) => (
            <Grid item xs={12} md={6} key={template.id}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {getVendorIcon(template.vendor)}
                      <Typography variant="h6">{template.name}</Typography>
                    </Box>
                    <Chip label={template.type} size="small" />
                  </Box>

                  <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
                    {template.description}
                  </Typography>

                  <Typography variant="subtitle2" gutterBottom>
                    Capacidades:
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 2 }}>
                    {template.capabilities.slice(0, 4).map((cap) => (
                      <Chip key={cap} label={cap} size="small" variant="outlined" />
                    ))}
                    {template.capabilities.length > 4 && (
                      <Chip label={`+${template.capabilities.length - 4}`} size="small" />
                    )}
                  </Box>

                  <Button
                    variant="contained"
                    fullWidth
                    startIcon={<AddIcon />}
                    onClick={() => handleCreateFromTemplate(template)}
                  >
                    Criar Integração
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Create Dialog - Select Template */}
      <Dialog
        open={openCreateDialog}
        onClose={() => setOpenCreateDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Nova Integração</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
            Selecione um template para criar uma nova integração
          </Typography>
          <Grid container spacing={2}>
            {templates.map((template) => (
              <Grid item xs={12} sm={6} key={template.id}>
                <Card
                  sx={{
                    cursor: 'pointer',
                    '&:hover': { boxShadow: 4 },
                    border: selectedTemplate?.id === template.id ? 2 : 0,
                    borderColor: 'primary.main',
                  }}
                  onClick={() => setSelectedTemplate(template)}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                      {template.category === 'firewall' && <SecurityIcon color="primary" sx={{ mr: 1 }} />}
                      {template.category === 'waf' && <CloudIcon color="primary" sx={{ mr: 1 }} />}
                      {template.category === 'edr' && <ShieldIcon color="primary" sx={{ mr: 1 }} />}
                      {template.category === 'iam' && <PeopleIcon color="primary" sx={{ mr: 1 }} />}
                      <Typography variant="h6">{template.name}</Typography>
                    </Box>
                    <Typography variant="body2" color="textSecondary">
                      {template.description}
                    </Typography>
                    <Box sx={{ mt: 2 }}>
                      <Chip label={template.category} size="small" sx={{ mr: 1 }} />
                      <Chip label={template.vendor} size="small" variant="outlined" />
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setOpenCreateDialog(false);
            setSelectedTemplate(null);
          }}>
            Cancelar
          </Button>
          <Button
            variant="contained"
            disabled={!selectedTemplate}
            onClick={() => {
              setOpenCreateDialog(false);
              setOpenTemplateDialog(true);
            }}
          >
            Continuar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Template Dialog */}
      <Dialog
        open={openTemplateDialog}
        onClose={() => setOpenTemplateDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Criar Integração: {selectedTemplate?.name}
        </DialogTitle>
        <DialogContent>
          {selectedTemplate && (
            <Box sx={{ mt: 2 }}>
              <Alert severity="info" sx={{ mb: 3 }}>
                {selectedTemplate.description}
              </Alert>

              <Typography variant="h6" gutterBottom>
                Passos de Configuração
              </Typography>
              <Stepper orientation="vertical" sx={{ mb: 3 }}>
                {selectedTemplate.setup_steps.map((step, index) => (
                  <Step key={index} active>
                    <StepLabel>{`Passo ${index + 1}`}</StepLabel>
                    <StepContent>
                      <Typography>{step}</Typography>
                    </StepContent>
                  </Step>
                ))}
              </Stepper>

              <Typography variant="h6" gutterBottom>
                Permissões Necessárias
              </Typography>
              <List dense sx={{ mb: 3 }}>
                {selectedTemplate.permissions.map((permission, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <CheckBoxIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText primary={permission} />
                  </ListItem>
                ))}
              </List>

              <Divider sx={{ my: 3 }} />

              <Typography variant="h6" gutterBottom>
                Configuração
              </Typography>

              <TextField
                fullWidth
                label="Nome da Integração"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                sx={{ mb: 2 }}
              />

              {selectedTemplate.required_fields.map((field) => (
                <TextField
                  key={field.name}
                  fullWidth
                  label={field.label}
                  type={field.type === 'password' ? 'password' : 'text'}
                  placeholder={field.placeholder}
                  helperText={field.description}
                  required={field.required}
                  value={formData.credentials[field.name] || ''}
                  onChange={(e) => setFormData({
                    ...formData,
                    credentials: {
                      ...formData.credentials,
                      [field.name]: e.target.value,
                    },
                  })}
                  sx={{ mb: 2 }}
                />
              ))}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenTemplateDialog(false)}>Cancelar</Button>
          <Button variant="contained" onClick={handleCreateIntegration}>
            Criar Integração
          </Button>
        </DialogActions>
      </Dialog>

      {/* Test Dialog */}
      <Dialog open={openTestDialog} onClose={() => setOpenTestDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Teste de Conexão</DialogTitle>
        <DialogContent>
          {testResult === null ? (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, p: 3 }}>
              <LinearProgress sx={{ flex: 1 }} />
              <Typography>Testando conexão...</Typography>
            </Box>
          ) : (
            <Alert severity={testResult.success ? 'success' : 'error'} sx={{ mt: 2 }}>
              <Typography variant="h6">{testResult.message}</Typography>
              {testResult.details && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    Tempo de resposta: {testResult.response_time}ms
                  </Typography>
                </Box>
              )}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenTestDialog(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>

      {/* Logs Dialog */}
      <Dialog open={openLogsDialog} onClose={() => setOpenLogsDialog(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Logs de Integração</DialogTitle>
        <DialogContent>
          <TableContainer component={Paper} sx={{ mt: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Timestamp</TableCell>
                  <TableCell>Ação</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Mensagem</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {integrationLogs.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>{new Date(log.timestamp).toLocaleString('pt-BR')}</TableCell>
                    <TableCell>{log.action}</TableCell>
                    <TableCell>
                      <Chip
                        label={log.status}
                        color={log.status === 'success' ? 'success' : 'error'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{log.message}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenLogsDialog(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>

      {/* Delete Dialog */}
      <Dialog open={openDeleteDialog} onClose={() => setOpenDeleteDialog(false)}>
        <DialogTitle>Confirmar Exclusão</DialogTitle>
        <DialogContent>
          <Typography>
            Tem certeza que deseja excluir a integração "{selectedIntegration?.name}"?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDeleteDialog(false)}>Cancelar</Button>
          <Button color="error" variant="contained" onClick={handleDeleteIntegration}>
            Excluir
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Integrations;
