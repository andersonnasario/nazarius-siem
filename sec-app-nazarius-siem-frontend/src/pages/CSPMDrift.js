import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  CircularProgress,
  Alert,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  List,
  ListItem,
  ListItemText,
  Divider,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  CompareArrows as CompareArrowsIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
  PlayArrow as PlayArrowIcon,
  Info as InfoIcon,
  Security as SecurityIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { PieChart, Pie, Cell, BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as ChartTooltip, Legend, ResponsiveContainer } from 'recharts';
import { cspmAPI } from '../services/api';

const CSPMDrift = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  
  // Data states
  const [statistics, setStatistics] = useState(null);
  const [drifts, setDrifts] = useState([]);
  const [baselines, setBaselines] = useState([]);
  const [scanConfigs, setScanConfigs] = useState([]);
  
  // Dialog states
  const [driftDialogOpen, setDriftDialogOpen] = useState(false);
  const [selectedDrift, setSelectedDrift] = useState(null);
  const [baselineDialogOpen, setBaselineDialogOpen] = useState(false);
  const [selectedBaseline, setSelectedBaseline] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [statsRes, driftsRes, baselinesRes, scanConfigsRes] = await Promise.all([
        cspmAPI.drift.getStatistics(),
        cspmAPI.drift.getDetections(),
        cspmAPI.drift.getBaselines(),
        cspmAPI.drift.getScanConfigs(),
      ]);
      
      setStatistics(statsRes.data.statistics);
      setDrifts(driftsRes.data.drifts);
      setBaselines(baselinesRes.data.baselines);
      setScanConfigs(scanConfigsRes.data.configs);
    } catch (err) {
      console.error('Error loading drift data:', err);
      setError('Erro ao carregar dados de drift detection');
    } finally {
      setLoading(false);
    }
  };

  const handleViewDrift = (drift) => {
    setSelectedDrift(drift);
    setDriftDialogOpen(true);
  };

  const handleUpdateDriftStatus = async (driftId, status, notes = '') => {
    try {
      await cspmAPI.drift.updateStatus(driftId, { status, resolution_notes: notes });
      setDriftDialogOpen(false);
      loadData();
    } catch (err) {
      console.error('Error updating drift status:', err);
      alert('Erro ao atualizar status do drift');
    }
  };

  const handleViewBaseline = (baseline) => {
    setSelectedBaseline(baseline);
    setBaselineDialogOpen(true);
  };

  const handleRunScan = async (configId) => {
    try {
      await cspmAPI.drift.runScan(configId);
      alert('Scan de drift iniciado com sucesso!');
      loadData();
    } catch (err) {
      console.error('Error running scan:', err);
      alert('Erro ao iniciar scan');
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'error',
      high: 'warning',
      medium: 'info',
      low: 'success',
    };
    return colors[severity] || 'default';
  };

  const getStatusColor = (status) => {
    const colors = {
      detected: 'error',
      investigating: 'warning',
      approved: 'success',
      rejected: 'default',
      remediated: 'success',
    };
    return colors[status] || 'default';
  };

  const COLORS = ['#f44336', '#ff9800', '#2196f3', '#4caf50'];

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            🔍 Drift Detection
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Detecção de mudanças não autorizadas na configuração
          </Typography>
        </Box>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={loadData}
        >
          Atualizar
        </Button>
      </Box>

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <CompareArrowsIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Total de Drifts
                </Typography>
              </Box>
              <Typography variant="h4">{statistics?.total_drifts || 0}</Typography>
              <Typography variant="caption" color="text.secondary">
                {statistics?.detected_today || 0} detectados hoje
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <ErrorIcon sx={{ mr: 1, color: 'error.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Drifts Críticos
                </Typography>
              </Box>
              <Typography variant="h4" color="error">
                {statistics?.critical_drifts || 0}
              </Typography>
              <Typography variant="caption" color="error">
                Requerem ação imediata
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <CheckCircleIcon sx={{ mr: 1, color: 'success.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Remediados Hoje
                </Typography>
              </Box>
              <Typography variant="h4" color="success.main">
                {statistics?.remediated_today || 0}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Tempo médio: {statistics?.average_time_to_resolve || 'N/A'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <SecurityIcon sx={{ mr: 1, color: 'warning.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Impacto Compliance
                </Typography>
              </Box>
              <Typography variant="h4" color="warning.main">
                {statistics?.compliance_impact || 0}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Drifts afetando compliance
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Alert Info */}
      <Alert severity="info" sx={{ mb: 3 }}>
        <strong>Drift Detection</strong> monitora continuamente suas configurações de infraestrutura e detecta 
        mudanças não autorizadas que podem comprometer a segurança ou compliance.
      </Alert>

      {/* Tabs */}
      <Card>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="Dashboard" />
          <Tab label="Drifts Detectados" />
          <Tab label="Baselines" />
          <Tab label="Configurações de Scan" />
        </Tabs>

        <CardContent>
          {/* Tab 0: Dashboard */}
          {tabValue === 0 && (
            <Box>
              <Grid container spacing={3}>
                {/* Drifts by Severity */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Drifts por Severidade
                      </Typography>
                      <ResponsiveContainer width="100%" height={300}>
                        <PieChart>
                          <Pie
                            data={[
                              { name: 'Crítico', value: statistics?.critical_drifts || 0 },
                              { name: 'Alto', value: statistics?.high_drifts || 0 },
                              { name: 'Médio', value: statistics?.medium_drifts || 0 },
                              { name: 'Baixo', value: statistics?.low_drifts || 0 },
                            ]}
                            dataKey="value"
                            nameKey="name"
                            cx="50%"
                            cy="50%"
                            outerRadius={80}
                            label
                          >
                            {[0, 1, 2, 3].map((index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index]} />
                            ))}
                          </Pie>
                          <ChartTooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Drifts by Type */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Drifts por Tipo
                      </Typography>
                      <ResponsiveContainer width="100%" height={300}>
                        <BarChart data={Object.entries(statistics?.drifts_by_type || {}).map(([key, value]) => ({
                          name: key.replace(/_/g, ' '),
                          value: value,
                        }))}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                          <YAxis />
                          <ChartTooltip />
                          <Bar dataKey="value" fill="#2196f3" />
                        </BarChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Drifts by Resource Type */}
                <Grid item xs={12}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Drifts por Tipo de Recurso
                      </Typography>
                      <ResponsiveContainer width="100%" height={300}>
                        <BarChart data={Object.entries(statistics?.drifts_by_resource || {}).map(([key, value]) => ({
                          name: key.replace(/_/g, ' '),
                          value: value,
                        }))}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="name" />
                          <YAxis />
                          <ChartTooltip />
                          <Bar dataKey="value" fill="#4caf50" />
                        </BarChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Box>
          )}

          {/* Tab 1: Drifts Detectados */}
          {tabValue === 1 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Drifts Detectados
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Recurso</TableCell>
                      <TableCell>Tipo</TableCell>
                      <TableCell>Severidade</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Detectado em</TableCell>
                      <TableCell>Impacto</TableCell>
                      <TableCell>Ações</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {drifts.map((drift) => (
                      <TableRow key={drift.id}>
                        <TableCell>
                          <Typography variant="body2" fontWeight="bold">
                            {drift.resource_name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {drift.resource_type}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={drift.drift_type.replace(/_/g, ' ')} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={drift.severity}
                            size="small"
                            color={getSeverityColor(drift.severity)}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={drift.status}
                            size="small"
                            color={getStatusColor(drift.status)}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(drift.detected_at).toLocaleString('pt-BR')}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                            {drift.impact}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Button
                            size="small"
                            onClick={() => handleViewDrift(drift)}
                          >
                            Ver Detalhes
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Tab 2: Baselines */}
          {tabValue === 2 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6">
                  Configuration Baselines
                </Typography>
                <Button variant="contained" size="small">
                  Nova Baseline
                </Button>
              </Box>
              <Grid container spacing={2}>
                {baselines.map((baseline) => (
                  <Grid item xs={12} md={6} key={baseline.id}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', mb: 2 }}>
                          <Box>
                            <Typography variant="h6">{baseline.name}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {baseline.description}
                            </Typography>
                          </Box>
                          <Chip
                            label={baseline.status}
                            size="small"
                            color={baseline.status === 'active' ? 'success' : 'default'}
                          />
                        </Box>
                        
                        <Typography variant="body2" gutterBottom>
                          <strong>Tipo de Recurso:</strong> {baseline.resource_type}
                        </Typography>
                        
                        <Typography variant="body2" gutterBottom>
                          <strong>Regras de Compliance:</strong> {baseline.compliance_rules?.join(', ')}
                        </Typography>
                        
                        <Typography variant="body2" gutterBottom>
                          <strong>Última Verificação:</strong> {new Date(baseline.last_verified).toLocaleDateString('pt-BR')}
                        </Typography>

                        <Button
                          fullWidth
                          size="small"
                          variant="outlined"
                          sx={{ mt: 2 }}
                          onClick={() => handleViewBaseline(baseline)}
                        >
                          Ver Detalhes
                        </Button>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          )}

          {/* Tab 3: Scan Configurations */}
          {tabValue === 3 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Configurações de Scan Automático
              </Typography>
              <Grid container spacing={2}>
                {scanConfigs.map((config) => (
                  <Grid item xs={12} md={6} key={config.id}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', mb: 2 }}>
                          <Typography variant="h6">{config.name}</Typography>
                          <Chip
                            label={config.enabled ? 'Ativo' : 'Inativo'}
                            size="small"
                            color={config.enabled ? 'success' : 'default'}
                          />
                        </Box>

                        <Typography variant="body2" gutterBottom>
                          <strong>Frequência:</strong> {config.scan_frequency}
                        </Typography>

                        <Typography variant="body2" gutterBottom>
                          <strong>Tipos de Recurso:</strong> {config.resource_types?.join(', ')}
                        </Typography>

                        <Typography variant="body2" gutterBottom>
                          <strong>Regiões:</strong> {config.regions?.join(', ')}
                        </Typography>

                        <Typography variant="body2" gutterBottom>
                          <strong>Último Scan:</strong> {new Date(config.last_scan).toLocaleString('pt-BR')}
                        </Typography>

                        <Typography variant="body2" gutterBottom>
                          <strong>Próximo Scan:</strong> {new Date(config.next_scan).toLocaleString('pt-BR')}
                        </Typography>

                        <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                          <Button
                            fullWidth
                            size="small"
                            variant="contained"
                            startIcon={<PlayArrowIcon />}
                            onClick={() => handleRunScan(config.id)}
                            disabled={!config.enabled}
                          >
                            Executar Scan
                          </Button>
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Drift Detail Dialog */}
      <Dialog open={driftDialogOpen} onClose={() => setDriftDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Detalhes do Drift
        </DialogTitle>
        <DialogContent>
          {selectedDrift && (
            <Box>
              <Typography variant="body1" gutterBottom>
                <strong>Recurso:</strong> {selectedDrift.resource_name} ({selectedDrift.resource_id})
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Tipo:</strong> {selectedDrift.resource_type}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Baseline:</strong> {selectedDrift.baseline_name}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Tipo de Drift:</strong> {selectedDrift.drift_type}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Severidade:</strong> <Chip label={selectedDrift.severity} size="small" color={getSeverityColor(selectedDrift.severity)} />
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Status:</strong> <Chip label={selectedDrift.status} size="small" color={getStatusColor(selectedDrift.status)} />
              </Typography>
              
              <Divider sx={{ my: 2 }} />
              
              <Typography variant="h6" gutterBottom>
                Mudanças Detectadas
              </Typography>
              <List dense>
                {selectedDrift.changes?.map((change, idx) => (
                  <ListItem key={idx}>
                    <ListItemText
                      primary={
                        <Box>
                          <Typography variant="body2" fontWeight="bold">
                            {change.property}
                            {change.is_critical && <Chip label="CRÍTICO" size="small" color="error" sx={{ ml: 1 }} />}
                          </Typography>
                        </Box>
                      }
                      secondary={
                        <Box sx={{ mt: 1 }}>
                          <Typography variant="caption" display="block">
                            <strong>Esperado:</strong> {JSON.stringify(change.expected_value)}
                          </Typography>
                          <Typography variant="caption" display="block">
                            <strong>Atual:</strong> {JSON.stringify(change.current_value)}
                          </Typography>
                          <Typography variant="caption" display="block" color="text.secondary">
                            Alterado em: {new Date(change.changed_at).toLocaleString('pt-BR')}
                            {change.changed_by && ` por ${change.changed_by}`}
                          </Typography>
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
              
              <Divider sx={{ my: 2 }} />
              
              <Typography variant="body1" gutterBottom>
                <strong>Impacto:</strong> {selectedDrift.impact}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Recomendação:</strong> {selectedDrift.recommendation}
              </Typography>
              
              {selectedDrift.compliance_impact && selectedDrift.compliance_impact.length > 0 && (
                <Typography variant="body1" gutterBottom>
                  <strong>Impacto em Compliance:</strong> {selectedDrift.compliance_impact.join(', ')}
                </Typography>
              )}
              
              {selectedDrift.auto_remediation && (
                <Alert severity="info" sx={{ mt: 2 }}>
                  <strong>Auto-remediation disponível</strong> - Este drift pode ser corrigido automaticamente.
                </Alert>
              )}
              
              <Box sx={{ mt: 3 }}>
                <Typography variant="subtitle2" gutterBottom>Atualizar Status:</Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => handleUpdateDriftStatus(selectedDrift.id, 'investigating')}
                  >
                    Investigando
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    color="success"
                    onClick={() => handleUpdateDriftStatus(selectedDrift.id, 'approved', 'Mudança aprovada')}
                  >
                    Aprovar
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    color="error"
                    onClick={() => handleUpdateDriftStatus(selectedDrift.id, 'rejected', 'Mudança rejeitada')}
                  >
                    Rejeitar
                  </Button>
                  <Button
                    variant="contained"
                    size="small"
                    color="primary"
                    onClick={() => handleUpdateDriftStatus(selectedDrift.id, 'remediated', 'Drift remediado')}
                  >
                    Marcar como Remediado
                  </Button>
                </Box>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDriftDialogOpen(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>

      {/* Baseline Detail Dialog */}
      <Dialog open={baselineDialogOpen} onClose={() => setBaselineDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Detalhes da Baseline
        </DialogTitle>
        <DialogContent>
          {selectedBaseline && (
            <Box>
              <Typography variant="body1" gutterBottom>
                <strong>Nome:</strong> {selectedBaseline.name}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Descrição:</strong> {selectedBaseline.description}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Tipo de Recurso:</strong> {selectedBaseline.resource_type}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Status:</strong> <Chip label={selectedBaseline.status} size="small" color={selectedBaseline.status === 'active' ? 'success' : 'default'} />
              </Typography>
              
              <Divider sx={{ my: 2 }} />
              
              <Typography variant="h6" gutterBottom>
                Configuração Esperada
              </Typography>
              <Box sx={{ bgcolor: 'grey.100', p: 2, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
                <pre>{JSON.stringify(selectedBaseline.configuration, null, 2)}</pre>
              </Box>
              
              <Divider sx={{ my: 2 }} />
              
              <Typography variant="body1" gutterBottom>
                <strong>Settings Críticos:</strong> {selectedBaseline.critical_settings?.join(', ')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Regras de Compliance:</strong> {selectedBaseline.compliance_rules?.join(', ')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Criado em:</strong> {new Date(selectedBaseline.created_at).toLocaleDateString('pt-BR')} por {selectedBaseline.created_by}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Última Verificação:</strong> {new Date(selectedBaseline.last_verified).toLocaleDateString('pt-BR')}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setBaselineDialogOpen(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default CSPMDrift;

