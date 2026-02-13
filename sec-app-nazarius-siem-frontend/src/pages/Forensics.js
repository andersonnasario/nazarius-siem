import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Button,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  LinearProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  IconButton,
  Tooltip,
  Snackbar,
  Tabs,
  Tab,
  Divider,
  FormControl,
  InputLabel,
  Select,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  CircularProgress,
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  Security as SecurityIcon,
  Computer as ComputerIcon,
  Storage as StorageIcon,
  Timeline as TimelineIcon,
  Visibility as VisibilityIcon,
  Delete as DeleteIcon,
  CloudSync as LiveIcon,
  CloudOff as MockIcon,
  Warning as WarningIcon,
  Description as DescriptionIcon,
  Memory as MemoryIcon,
  NetworkCheck as NetworkIcon,
  Article as LogIcon,
  Person as PersonIcon,
  Event as EventIcon,
  CheckCircle as CheckCircleIcon,
  Schedule as ScheduleIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import { forensicsAPI } from '../services/api';

const SEVERITY_COLORS = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#fbc02d',
  low: '#388e3c',
  info: '#1976d2',
};

const STATUS_COLORS = {
  active: 'success',
  completed: 'default',
  pending: 'warning',
  archived: 'default',
};

const EVIDENCE_TYPE_ICONS = {
  file: <DescriptionIcon />,
  memory: <MemoryIcon />,
  network: <NetworkIcon />,
  log: <LogIcon />,
  registry: <StorageIcon />,
  disk: <StorageIcon />,
  process: <ComputerIcon />,
};

const Forensics = () => {
  // State
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    total_investigations: 0,
    active_investigations: 0,
    total_evidence: 0,
    total_artifacts: 0,
  });
  const [investigations, setInvestigations] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [dataSource, setDataSource] = useState('loading');
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [tabValue, setTabValue] = useState(0);

  // Filters
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  // Dialogs
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [selectedInvestigation, setSelectedInvestigation] = useState(null);
  const [evidenceDialogOpen, setEvidenceDialogOpen] = useState(false);
  const [timelineDialogOpen, setTimelineDialogOpen] = useState(false);

  // New investigation form
  const [newInvestigation, setNewInvestigation] = useState({
    title: '',
    description: '',
    severity: 'medium',
    priority: 'medium',
    incident_id: '',
    case_id: '',
    tags: '',
    notes: '',
  });

  // New evidence form
  const [newEvidence, setNewEvidence] = useState({
    investigation_id: '',
    type: 'file',
    name: '',
    source: '',
    hash: '',
    size: 0,
    tags: '',
  });

  // New timeline entry form
  const [newTimelineEntry, setNewTimelineEntry] = useState({
    event: '',
    event_type: 'system',
    target: '',
    details: '',
    severity: 'info',
  });

  // Load data
  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const params = {};
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;
      if (searchQuery) params.search = searchQuery;

      const [invRes, statsRes, evidenceRes] = await Promise.all([
        forensicsAPI.listInvestigations(params),
        forensicsAPI.getStats(),
        forensicsAPI.listEvidence({}),
      ]);

      const invData = invRes.data?.data || [];
      const statsData = statsRes.data?.data || {};
      const evidenceData = evidenceRes.data?.data || [];

      setInvestigations(Array.isArray(invData) ? invData : []);
      setStats({
        total_investigations: statsData.total_investigations || 0,
        active_investigations: statsData.active_investigations || 0,
        total_evidence: statsData.total_evidence || 0,
        total_artifacts: statsData.total_artifacts || 0,
        by_severity: statsData.by_severity || {},
        by_status: statsData.by_status || {},
      });
      setEvidence(Array.isArray(evidenceData) ? evidenceData : []);

      // Set data source
      const source = invRes.data?.source || statsRes.data?.source || 'unknown';
      setDataSource(source === 'opensearch' ? 'live' : source === 'mock' ? 'mock' : 'unknown');

    } catch (error) {
      console.error('Failed to load forensics data:', error);
      showSnackbar('Erro ao carregar dados de forensics', 'error');
      setDataSource('error');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter, searchQuery]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Load timeline for selected investigation
  const loadTimeline = useCallback(async (investigationId) => {
    if (!investigationId) return;
    try {
      const res = await forensicsAPI.getTimeline(investigationId);
      const timelineData = res.data?.data || [];
      setTimeline(Array.isArray(timelineData) ? timelineData : []);
    } catch (error) {
      console.error('Failed to load timeline:', error);
      setTimeline([]);
    }
  }, []);

  // Handlers
  const handleRefresh = () => {
    loadData();
    showSnackbar('Dados atualizados', 'success');
  };

  const handleCreateInvestigation = async () => {
    try {
      const data = {
        ...newInvestigation,
        tags: newInvestigation.tags ? newInvestigation.tags.split(',').map(t => t.trim()) : [],
      };
      await forensicsAPI.createInvestigation(data);
      showSnackbar('Investigação criada com sucesso!', 'success');
      setCreateDialogOpen(false);
      setNewInvestigation({
        title: '',
        description: '',
        severity: 'medium',
        priority: 'medium',
        incident_id: '',
        case_id: '',
        tags: '',
        notes: '',
      });
      loadData();
    } catch (error) {
      console.error('Failed to create investigation:', error);
      showSnackbar('Erro ao criar investigação', 'error');
    }
  };

  const handleViewDetails = async (investigation) => {
    setSelectedInvestigation(investigation);
    await loadTimeline(investigation.id);
    setDetailsDialogOpen(true);
  };

  const handleDeleteInvestigation = async (id) => {
    if (!window.confirm('Tem certeza que deseja excluir esta investigação?')) return;
    try {
      await forensicsAPI.deleteInvestigation(id);
      showSnackbar('Investigação excluída com sucesso!', 'success');
      loadData();
    } catch (error) {
      console.error('Failed to delete investigation:', error);
      showSnackbar('Erro ao excluir investigação', 'error');
    }
  };

  const handleOpenEvidenceDialog = (investigation) => {
    setSelectedInvestigation(investigation);
    setNewEvidence({
      ...newEvidence,
      investigation_id: investigation.id,
    });
    setEvidenceDialogOpen(true);
  };

  const handleCreateEvidence = async () => {
    try {
      const data = {
        ...newEvidence,
        size: parseInt(newEvidence.size) || 0,
        tags: newEvidence.tags ? newEvidence.tags.split(',').map(t => t.trim()) : [],
      };
      await forensicsAPI.createEvidence(data);
      showSnackbar('Evidência adicionada com sucesso!', 'success');
      setEvidenceDialogOpen(false);
      setNewEvidence({
        investigation_id: '',
        type: 'file',
        name: '',
        source: '',
        hash: '',
        size: 0,
        tags: '',
      });
      loadData();
    } catch (error) {
      console.error('Failed to create evidence:', error);
      showSnackbar('Erro ao adicionar evidência', 'error');
    }
  };

  const handleOpenTimelineDialog = (investigation) => {
    setSelectedInvestigation(investigation);
    setTimelineDialogOpen(true);
  };

  const handleAddTimelineEntry = async () => {
    try {
      await forensicsAPI.addTimelineEntry(selectedInvestigation.id, newTimelineEntry);
      showSnackbar('Evento adicionado à timeline!', 'success');
      setTimelineDialogOpen(false);
      setNewTimelineEntry({
        event: '',
        event_type: 'system',
        target: '',
        details: '',
        severity: 'info',
      });
      // Reload timeline if details dialog is open
      if (detailsDialogOpen) {
        await loadTimeline(selectedInvestigation.id);
      }
    } catch (error) {
      console.error('Failed to add timeline entry:', error);
      showSnackbar('Erro ao adicionar evento', 'error');
    }
  };

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  const getSeverityColor = (severity) => SEVERITY_COLORS[severity] || '#999';
  const getStatusColor = (status) => STATUS_COLORS[status] || 'default';

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleString('pt-BR');
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
  };

  if (loading && investigations.length === 0) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography variant="h4" gutterBottom>Forensics & Investigation</Typography>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">Forensics & Investigation</Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {/* Data Source Indicator */}
          {dataSource === 'live' && (
            <Chip
              icon={<LiveIcon />}
              label="LIVE DATA"
              color="success"
              size="small"
              sx={{ fontWeight: 'bold' }}
            />
          )}
          {dataSource === 'mock' && (
            <Chip
              icon={<MockIcon />}
              label="DEMO DATA"
              color="error"
              size="small"
              sx={{ fontWeight: 'bold' }}
            />
          )}
          {(dataSource === 'error' || dataSource === 'unknown') && (
            <Chip
              icon={<WarningIcon />}
              label="NO DATA"
              color="warning"
              size="small"
              sx={{ fontWeight: 'bold' }}
            />
          )}
          
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={handleRefresh}
          >
            Atualizar
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setCreateDialogOpen(true)}
          >
            Nova Investigação
          </Button>
        </Box>
      </Box>

      {/* Info Alert */}
      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          <strong>Módulo Forensics:</strong> Análise forense digital com persistência em OpenSearch. 
          Coleta de evidências, timeline de eventos e investigação de incidentes de segurança.
        </Typography>
      </Alert>

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <SearchIcon color="primary" sx={{ mr: 1 }} />
                <Typography color="textSecondary">
                  Total de Investigações
                </Typography>
              </Box>
              <Typography variant="h4">{stats.total_investigations}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <TimelineIcon color="warning" sx={{ mr: 1 }} />
                <Typography color="textSecondary">
                  Investigações Ativas
                </Typography>
              </Box>
              <Typography variant="h4" color="warning.main">{stats.active_investigations}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <StorageIcon color="info" sx={{ mr: 1 }} />
                <Typography color="textSecondary">
                  Evidências Coletadas
                </Typography>
              </Box>
              <Typography variant="h4">{stats.total_evidence}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <ComputerIcon color="success" sx={{ mr: 1 }} />
                <Typography color="textSecondary">
                  Artefatos Analisados
                </Typography>
              </Box>
              <Typography variant="h4">{stats.total_artifacts}</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="Investigações" />
          <Tab label="Evidências" />
        </Tabs>
      </Paper>

      {/* Filters */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              size="small"
              placeholder="Buscar investigações..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && loadData()}
              InputProps={{
                startAdornment: <SearchIcon color="action" sx={{ mr: 1 }} />,
              }}
            />
          </Grid>
          <Grid item xs={12} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Status</InputLabel>
              <Select
                value={statusFilter}
                label="Status"
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <MenuItem value="">Todos</MenuItem>
                <MenuItem value="active">Ativo</MenuItem>
                <MenuItem value="completed">Concluído</MenuItem>
                <MenuItem value="pending">Pendente</MenuItem>
                <MenuItem value="archived">Arquivado</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Severidade</InputLabel>
              <Select
                value={severityFilter}
                label="Severidade"
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <MenuItem value="">Todas</MenuItem>
                <MenuItem value="critical">Crítica</MenuItem>
                <MenuItem value="high">Alta</MenuItem>
                <MenuItem value="medium">Média</MenuItem>
                <MenuItem value="low">Baixa</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={2}>
            <Button fullWidth variant="outlined" onClick={loadData}>
              Filtrar
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Investigations Tab */}
      {tabValue === 0 && (
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
              Investigações Forenses
          </Typography>
          <TableContainer component={Paper} variant="outlined">
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Título</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Severidade</TableCell>
                  <TableCell>Evidências</TableCell>
                    <TableCell>Analista</TableCell>
                  <TableCell>Data de Criação</TableCell>
                  <TableCell>Ações</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                  {investigations.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center">
                        <Typography color="textSecondary">
                          Nenhuma investigação encontrada
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    investigations.map((inv) => (
                  <TableRow key={inv.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {inv.title}
                      </Typography>
                          {inv.incident_id && (
                            <Typography variant="caption" color="textSecondary">
                              Incident: {inv.incident_id}
                            </Typography>
                          )}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={inv.status}
                        color={getStatusColor(inv.status)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={inv.severity}
                        size="small"
                            sx={{
                              backgroundColor: getSeverityColor(inv.severity),
                              color: 'white',
                            }}
                      />
                    </TableCell>
                        <TableCell>{inv.evidence_count || 0}</TableCell>
                        <TableCell>{inv.analyst || '-'}</TableCell>
                        <TableCell>{formatDate(inv.created_at)}</TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5 }}>
                            <Tooltip title="Ver Detalhes">
                              <IconButton size="small" onClick={() => handleViewDetails(inv)}>
                                <VisibilityIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Adicionar Evidência">
                              <IconButton size="small" onClick={() => handleOpenEvidenceDialog(inv)} color="primary">
                                <StorageIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Adicionar Evento">
                              <IconButton size="small" onClick={() => handleOpenTimelineDialog(inv)} color="info">
                                <TimelineIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Excluir">
                              <IconButton size="small" onClick={() => handleDeleteInvestigation(inv.id)} color="error">
                                <DeleteIcon />
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
          </CardContent>
        </Card>
      )}

      {/* Evidence Tab */}
      {tabValue === 1 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Evidências Coletadas
            </Typography>
            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Nome</TableCell>
                    <TableCell>Tipo</TableCell>
                    <TableCell>Origem</TableCell>
                    <TableCell>Hash (SHA-256)</TableCell>
                    <TableCell>Tamanho</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Coletado em</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {evidence.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center">
                        <Typography color="textSecondary">
                          Nenhuma evidência encontrada
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    evidence.map((ev) => (
                      <TableRow key={ev.id} hover>
                    <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {EVIDENCE_TYPE_ICONS[ev.type] || <DescriptionIcon />}
                            <Typography variant="body2">{ev.name}</Typography>
                          </Box>
                    </TableCell>
                    <TableCell>
                          <Chip label={ev.type} size="small" />
                        </TableCell>
                        <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {ev.source}
                        </TableCell>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                          {ev.hash ? `${ev.hash.substring(0, 16)}...` : '-'}
                        </TableCell>
                        <TableCell>{formatBytes(ev.size)}</TableCell>
                        <TableCell>
                          <Chip
                            label={ev.status}
                        size="small"
                            color={ev.is_malicious ? 'error' : 'default'}
                          />
                    </TableCell>
                        <TableCell>{formatDate(ev.collected_at)}</TableCell>
                  </TableRow>
                    ))
                  )}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
      )}

      {/* Capabilities Section */}
      <Grid container spacing={3} sx={{ mt: 3 }}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <SecurityIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Coleta de Evidências
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Coleta automatizada de evidências digitais de múltiplas fontes incluindo logs, memória, disco e rede.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <ComputerIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Análise de Artefatos
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Análise profunda de artefatos digitais incluindo arquivos, processos, registry, e network traffic.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <TimelineIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Timeline de Eventos
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Reconstrução cronológica de eventos para entender a sequência de ações durante um incidente.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Create Investigation Dialog */}
      <Dialog open={createDialogOpen} onClose={() => setCreateDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Nova Investigação Forense</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Título"
              fullWidth
              required
              value={newInvestigation.title}
              onChange={(e) => setNewInvestigation({ ...newInvestigation, title: e.target.value })}
            />
            <TextField
              label="Descrição"
              fullWidth
              multiline
              rows={3}
              value={newInvestigation.description}
              onChange={(e) => setNewInvestigation({ ...newInvestigation, description: e.target.value })}
            />
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <TextField
                  select
                  label="Severidade"
                  fullWidth
                  value={newInvestigation.severity}
                  onChange={(e) => setNewInvestigation({ ...newInvestigation, severity: e.target.value })}
                >
                  <MenuItem value="critical">Crítica</MenuItem>
                  <MenuItem value="high">Alta</MenuItem>
                  <MenuItem value="medium">Média</MenuItem>
                  <MenuItem value="low">Baixa</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={6}>
                <TextField
                  select
                  label="Prioridade"
                  fullWidth
                  value={newInvestigation.priority}
                  onChange={(e) => setNewInvestigation({ ...newInvestigation, priority: e.target.value })}
                >
                  <MenuItem value="critical">Crítica</MenuItem>
                  <MenuItem value="high">Alta</MenuItem>
                  <MenuItem value="medium">Média</MenuItem>
                  <MenuItem value="low">Baixa</MenuItem>
                </TextField>
              </Grid>
            </Grid>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <TextField
                  label="ID do Incidente"
                  fullWidth
                  value={newInvestigation.incident_id}
                  onChange={(e) => setNewInvestigation({ ...newInvestigation, incident_id: e.target.value })}
                  placeholder="ex: INC-2025-001"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="ID do Caso"
                  fullWidth
                  value={newInvestigation.case_id}
                  onChange={(e) => setNewInvestigation({ ...newInvestigation, case_id: e.target.value })}
                  placeholder="ex: CASE-001"
                />
              </Grid>
            </Grid>
            <TextField
              label="Tags (separadas por vírgula)"
              fullWidth
              value={newInvestigation.tags}
              onChange={(e) => setNewInvestigation({ ...newInvestigation, tags: e.target.value })}
              placeholder="ex: ransomware, critical, production"
            />
            <TextField
              label="Notas"
              fullWidth
              multiline
              rows={2}
              value={newInvestigation.notes}
              onChange={(e) => setNewInvestigation({ ...newInvestigation, notes: e.target.value })}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancelar</Button>
          <Button
            variant="contained"
            onClick={handleCreateInvestigation}
            disabled={!newInvestigation.title}
          >
            Criar Investigação
          </Button>
        </DialogActions>
      </Dialog>

      {/* Investigation Details Dialog */}
      <Dialog open={detailsDialogOpen} onClose={() => setDetailsDialogOpen(false)} maxWidth="lg" fullWidth>
        <DialogTitle>
          Detalhes da Investigação
          {selectedInvestigation && (
            <Chip
              label={selectedInvestigation.severity}
              size="small"
              sx={{
                ml: 2,
                backgroundColor: getSeverityColor(selectedInvestigation.severity),
                color: 'white',
              }}
            />
          )}
        </DialogTitle>
        <DialogContent>
          {selectedInvestigation && (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" color="textSecondary">Título</Typography>
                  <Typography variant="body1" gutterBottom>{selectedInvestigation.title}</Typography>
                  
                  <Typography variant="subtitle2" color="textSecondary" sx={{ mt: 2 }}>Descrição</Typography>
                  <Typography variant="body2" gutterBottom>{selectedInvestigation.description || '-'}</Typography>
                  
                  <Typography variant="subtitle2" color="textSecondary" sx={{ mt: 2 }}>Analista</Typography>
                  <Typography variant="body2" gutterBottom>{selectedInvestigation.analyst || '-'}</Typography>
                  
                  {selectedInvestigation.tags && selectedInvestigation.tags.length > 0 && (
                    <>
                      <Typography variant="subtitle2" color="textSecondary" sx={{ mt: 2 }}>Tags</Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {selectedInvestigation.tags.map((tag, idx) => (
                          <Chip key={idx} label={tag} size="small" />
                        ))}
                      </Box>
                    </>
                  )}
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" color="textSecondary">Status</Typography>
                  <Chip label={selectedInvestigation.status} color={getStatusColor(selectedInvestigation.status)} size="small" sx={{ mb: 2 }} />
                  
                  <Typography variant="subtitle2" color="textSecondary" sx={{ mt: 2 }}>ID do Incidente</Typography>
                  <Typography variant="body2" gutterBottom>{selectedInvestigation.incident_id || '-'}</Typography>
                  
                  <Typography variant="subtitle2" color="textSecondary" sx={{ mt: 2 }}>Evidências Coletadas</Typography>
                  <Typography variant="body2" gutterBottom>{selectedInvestigation.evidence_count || 0}</Typography>
                  
                  <Typography variant="subtitle2" color="textSecondary" sx={{ mt: 2 }}>Criado em</Typography>
                  <Typography variant="body2" gutterBottom>{formatDate(selectedInvestigation.created_at)}</Typography>
                </Grid>
              </Grid>

              <Divider sx={{ my: 3 }} />

              <Typography variant="h6" gutterBottom>Timeline de Eventos</Typography>
              {timeline.length === 0 ? (
                <Typography color="textSecondary">Nenhum evento na timeline</Typography>
              ) : (
                <List dense>
                  {timeline.map((entry, idx) => (
                    <ListItem key={entry.id || idx} sx={{ borderLeft: `3px solid ${getSeverityColor(entry.severity)}`, mb: 1, bgcolor: 'background.paper' }}>
                      <ListItemIcon>
                        {entry.event_type === 'system' && <ComputerIcon />}
                        {entry.event_type === 'evidence' && <StorageIcon />}
                        {entry.event_type === 'finding' && <SecurityIcon />}
                        {entry.event_type === 'analysis' && <SearchIcon />}
                        {!['system', 'evidence', 'finding', 'analysis'].includes(entry.event_type) && <EventIcon />}
                      </ListItemIcon>
                      <ListItemText
                        primary={entry.event}
                        secondary={
                          <>
                            <Typography variant="caption" display="block">
                              {formatDate(entry.timestamp)} • {entry.actor}
                            </Typography>
                            <Typography variant="caption" color="textSecondary">
                              {entry.details}
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
        </DialogContent>
        <DialogActions>
          <Button onClick={() => handleOpenTimelineDialog(selectedInvestigation)} color="primary">
            Adicionar Evento
          </Button>
          <Button onClick={() => setDetailsDialogOpen(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>

      {/* Add Evidence Dialog */}
      <Dialog open={evidenceDialogOpen} onClose={() => setEvidenceDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Adicionar Evidência</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              select
              label="Tipo de Evidência"
              fullWidth
              value={newEvidence.type}
              onChange={(e) => setNewEvidence({ ...newEvidence, type: e.target.value })}
            >
              <MenuItem value="file">Arquivo</MenuItem>
              <MenuItem value="memory">Memória</MenuItem>
              <MenuItem value="network">Rede</MenuItem>
              <MenuItem value="log">Log</MenuItem>
              <MenuItem value="registry">Registry</MenuItem>
              <MenuItem value="disk">Disco</MenuItem>
              <MenuItem value="process">Processo</MenuItem>
            </TextField>
            <TextField
              label="Nome"
              fullWidth
              required
              value={newEvidence.name}
              onChange={(e) => setNewEvidence({ ...newEvidence, name: e.target.value })}
              placeholder="ex: malware.exe"
            />
            <TextField
              label="Origem"
              fullWidth
              value={newEvidence.source}
              onChange={(e) => setNewEvidence({ ...newEvidence, source: e.target.value })}
              placeholder="ex: C:\\Windows\\Temp\\malware.exe"
            />
            <TextField
              label="Hash (SHA-256)"
              fullWidth
              value={newEvidence.hash}
              onChange={(e) => setNewEvidence({ ...newEvidence, hash: e.target.value })}
              placeholder="ex: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            />
            <TextField
              label="Tamanho (bytes)"
              fullWidth
              type="number"
              value={newEvidence.size}
              onChange={(e) => setNewEvidence({ ...newEvidence, size: e.target.value })}
            />
            <TextField
              label="Tags (separadas por vírgula)"
              fullWidth
              value={newEvidence.tags}
              onChange={(e) => setNewEvidence({ ...newEvidence, tags: e.target.value })}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEvidenceDialogOpen(false)}>Cancelar</Button>
          <Button
            variant="contained"
            onClick={handleCreateEvidence}
            disabled={!newEvidence.name}
          >
            Adicionar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Add Timeline Entry Dialog */}
      <Dialog open={timelineDialogOpen} onClose={() => setTimelineDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Adicionar Evento à Timeline</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Evento"
              fullWidth
              required
              value={newTimelineEntry.event}
              onChange={(e) => setNewTimelineEntry({ ...newTimelineEntry, event: e.target.value })}
              placeholder="ex: Malware sample collected"
            />
            <TextField
              select
              label="Tipo de Evento"
              fullWidth
              value={newTimelineEntry.event_type}
              onChange={(e) => setNewTimelineEntry({ ...newTimelineEntry, event_type: e.target.value })}
            >
              <MenuItem value="system">Sistema</MenuItem>
              <MenuItem value="evidence">Evidência</MenuItem>
              <MenuItem value="finding">Descoberta</MenuItem>
              <MenuItem value="analysis">Análise</MenuItem>
              <MenuItem value="network">Rede</MenuItem>
              <MenuItem value="user">Usuário</MenuItem>
              <MenuItem value="file">Arquivo</MenuItem>
              <MenuItem value="process">Processo</MenuItem>
            </TextField>
            <TextField
              label="Alvo"
              fullWidth
              value={newTimelineEntry.target}
              onChange={(e) => setNewTimelineEntry({ ...newTimelineEntry, target: e.target.value })}
              placeholder="ex: WORKSTATION-001"
            />
            <TextField
              label="Detalhes"
              fullWidth
              multiline
              rows={3}
              value={newTimelineEntry.details}
              onChange={(e) => setNewTimelineEntry({ ...newTimelineEntry, details: e.target.value })}
            />
            <TextField
              select
              label="Severidade"
              fullWidth
              value={newTimelineEntry.severity}
              onChange={(e) => setNewTimelineEntry({ ...newTimelineEntry, severity: e.target.value })}
            >
              <MenuItem value="critical">Crítica</MenuItem>
              <MenuItem value="high">Alta</MenuItem>
              <MenuItem value="medium">Média</MenuItem>
              <MenuItem value="low">Baixa</MenuItem>
              <MenuItem value="info">Info</MenuItem>
            </TextField>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTimelineDialogOpen(false)}>Cancelar</Button>
          <Button
            variant="contained"
            onClick={handleAddTimelineEntry}
            disabled={!newTimelineEntry.event}
          >
            Adicionar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert onClose={() => setSnackbar({ ...snackbar, open: false })} severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Forensics;
