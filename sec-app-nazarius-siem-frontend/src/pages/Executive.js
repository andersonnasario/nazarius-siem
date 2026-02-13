import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  CircularProgress,
  Alert,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Divider,
} from '@mui/material';
import {
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  TrendingFlat as TrendingFlatIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  Event as EventIcon,
  Warning as WarningIcon,
  Assignment as AssignmentIcon,
  AutoFixHigh as AutoFixHighIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  Timer as TimerIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  AttachMoney as AttachMoneyIcon,
  TrendingUp as GainIcon,
} from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, Legend } from 'recharts';
import { executiveAPI } from '../services/api';

const Executive = () => {
  const [period, setPeriod] = useState('last_30d');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dashboard, setDashboard] = useState(null);

  useEffect(() => {
    loadData();
  }, [period]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await executiveAPI.getDashboard({ period });
      setDashboard(response.data);
    } catch (err) {
      console.error('Error loading executive dashboard:', err);
      setError('Erro ao carregar dashboard executivo');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (format) => {
    try {
      await executiveAPI.generateReport({
        period,
        format,
        sections: ['all'],
      });
      alert(`Relatório ${format.toUpperCase()} gerado com sucesso!`);
    } catch (err) {
      console.error('Error generating report:', err);
      alert('Erro ao gerar relatório');
    }
  };

  const getTrendIcon = (trend) => {
    if (trend === 'up') return <TrendingUpIcon sx={{ color: 'success.main' }} />;
    if (trend === 'down') return <TrendingDownIcon sx={{ color: 'error.main' }} />;
    return <TrendingFlatIcon sx={{ color: 'grey.500' }} />;
  };

  const getTrendColor = (trend) => {
    if (trend === 'up') return 'success.main';
    if (trend === 'down') return 'error.main';
    return 'grey.500';
  };

  const formatNumber = (num) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toLocaleString();
  };

  const formatCurrency = (num) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'USD',
    }).format(num);
  };

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
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      </Box>
    );
  }

  if (!dashboard) return null;

  const { kpis, modules, trends, topInsights, roi, comparison } = dashboard;

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>
          Dashboard Executivo
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Período</InputLabel>
            <Select value={period} label="Período" onChange={(e) => setPeriod(e.target.value)}>
              <MenuItem value="last_24h">Últimas 24h</MenuItem>
              <MenuItem value="last_7d">Últimos 7 dias</MenuItem>
              <MenuItem value="last_30d">Últimos 30 dias</MenuItem>
              <MenuItem value="last_90d">Últimos 90 dias</MenuItem>
            </Select>
          </FormControl>
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={loadData}>
            Atualizar
          </Button>
          <Button variant="outlined" startIcon={<DownloadIcon />} onClick={() => handleExport('pdf')}>
            Export PDF
          </Button>
          <Button variant="outlined" startIcon={<DownloadIcon />} onClick={() => handleExport('excel')}>
            Export Excel
          </Button>
        </Box>
      </Box>

      {/* KPIs Principais */}
      <Typography variant="h6" gutterBottom sx={{ mb: 2, fontWeight: 600 }}>
        Métricas Principais
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Total de Eventos
                  </Typography>
                  <Typography variant="h4">{formatNumber(kpis.totalEvents)}</Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                    {getTrendIcon(comparison.events.trend)}
                    <Typography variant="caption" sx={{ ml: 0.5, color: getTrendColor(comparison.events.trend) }}>
                      {comparison.events.changePercent > 0 ? '+' : ''}{comparison.events.changePercent.toFixed(1)}%
                    </Typography>
                  </Box>
                </Box>
                <EventIcon sx={{ fontSize: 40, color: 'primary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Total de Alertas
                  </Typography>
                  <Typography variant="h4">{formatNumber(kpis.totalAlerts)}</Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                    {getTrendIcon(comparison.alerts.trend)}
                    <Typography variant="caption" sx={{ ml: 0.5, color: getTrendColor(comparison.alerts.trend) }}>
                      {comparison.alerts.changePercent > 0 ? '+' : ''}{comparison.alerts.changePercent.toFixed(1)}%
                    </Typography>
                  </Box>
                </Box>
                <WarningIcon sx={{ fontSize: 40, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box>
                  <Typography variant="body2" sx={{ color: 'white', opacity: 0.9 }} gutterBottom>
                    Alertas Críticos
                  </Typography>
                  <Typography variant="h4" sx={{ color: 'white' }}>{kpis.criticalAlerts}</Typography>
                  <Typography variant="caption" sx={{ color: 'white', opacity: 0.8 }}>
                    {((kpis.criticalAlerts / kpis.totalAlerts) * 100).toFixed(1)}% do total
                  </Typography>
                </Box>
                <ErrorIcon sx={{ fontSize: 40, color: 'white', opacity: 0.5 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Total de Casos
                  </Typography>
                  <Typography variant="h4">{kpis.totalCases}</Typography>
                  <Typography variant="caption" color="success.main">
                    {kpis.openCases} abertos
                  </Typography>
                </Box>
                <AssignmentIcon sx={{ fontSize: 40, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Playbooks Executados
                  </Typography>
                  <Typography variant="h4">{kpis.playbooksExecuted}</Typography>
                  <Typography variant="caption" color="success.main">
                    {modules.soar.successRate.toFixed(1)}% sucesso
                  </Typography>
                </Box>
                <AutoFixHighIcon sx={{ fontSize: 40, color: 'secondary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    IOCs Detectados
                  </Typography>
                  <Typography variant="h4">{formatNumber(kpis.iocsDetected)}</Typography>
                  <Typography variant="caption" color="error.main">
                    {modules.threatIntel.maliciousIPsBlocked} IPs bloqueados
                  </Typography>
                </Box>
                <SecurityIcon sx={{ fontSize: 40, color: 'error.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box>
                  <Typography variant="body2" sx={{ color: 'white', opacity: 0.9 }} gutterBottom>
                    Cobertura MITRE
                  </Typography>
                  <Typography variant="h4" sx={{ color: 'white' }}>{kpis.mitreCoverage.toFixed(1)}%</Typography>
                  <Typography variant="caption" sx={{ color: 'white', opacity: 0.8 }}>
                    {modules.mitreAttack.detectedTechniques}/{modules.mitreAttack.totalTechniques} técnicas
                  </Typography>
                </Box>
                <SecurityIcon sx={{ fontSize: 40, color: 'white', opacity: 0.5 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box>
                  <Typography variant="body2" sx={{ color: 'white', opacity: 0.9 }} gutterBottom>
                    Taxa de Automação
                  </Typography>
                  <Typography variant="h4" sx={{ color: 'white' }}>{kpis.automationRate.toFixed(1)}%</Typography>
                  <Typography variant="caption" sx={{ color: 'white', opacity: 0.8 }}>
                    {roi.automatedActions} ações automáticas
                  </Typography>
                </Box>
                <SpeedIcon sx={{ fontSize: 40, color: 'white', opacity: 0.5 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  MTTD (Mean Time to Detect)
                </Typography>
                <Typography variant="h4">{kpis.mttd} min</Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                  {getTrendIcon(comparison.mttd.trend)}
                  <Typography variant="caption" sx={{ ml: 0.5, color: getTrendColor(comparison.mttd.trend) }}>
                    {comparison.mttd.change} min vs anterior
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  MTTR (Mean Time to Respond)
                </Typography>
                <Typography variant="h4">{kpis.mttr} min</Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                  {getTrendIcon(comparison.mttr.trend)}
                  <Typography variant="caption" sx={{ ml: 0.5, color: getTrendColor(comparison.mttr.trend) }}>
                    {comparison.mttr.change} min vs anterior
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  System Uptime
                </Typography>
                <Typography variant="h4">{kpis.systemUptime.toFixed(2)}%</Typography>
                <Chip label="Saudável" size="small" color="success" sx={{ mt: 1 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Resolução de Incidentes
                </Typography>
                <Typography variant="h4">{kpis.incidentResolution.toFixed(1)}%</Typography>
                <Typography variant="caption" color="success.main">
                  {modules.caseManagement.slaCompliance.toFixed(1)}% SLA
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* ROI Metrics - Destaque */}
      <Card sx={{ mb: 4, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
        <CardContent>
          <Typography variant="h6" sx={{ color: 'white', mb: 3, fontWeight: 600 }}>
            Retorno sobre Investimento (ROI)
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center' }}>
                <CheckCircleIcon sx={{ fontSize: 48, color: 'white', mb: 1 }} />
                <Typography variant="h4" sx={{ color: 'white' }}>{roi.incidentsPrevented}</Typography>
                <Typography variant="body2" sx={{ color: 'white', opacity: 0.9 }}>
                  Incidentes Prevenidos
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center' }}>
                <TimerIcon sx={{ fontSize: 48, color: 'white', mb: 1 }} />
                <Typography variant="h4" sx={{ color: 'white' }}>{formatNumber(roi.timesSaved)}h</Typography>
                <Typography variant="body2" sx={{ color: 'white', opacity: 0.9 }}>
                  Tempo Economizado
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center' }}>
                <AttachMoneyIcon sx={{ fontSize: 48, color: 'white', mb: 1 }} />
                <Typography variant="h4" sx={{ color: 'white' }}>{formatCurrency(roi.costSavings)}</Typography>
                <Typography variant="body2" sx={{ color: 'white', opacity: 0.9 }}>
                  Economia em Custos
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center' }}>
                <GainIcon sx={{ fontSize: 48, color: 'white', mb: 1 }} />
                <Typography variant="h4" sx={{ color: 'white' }}>{roi.efficiencyGain.toFixed(1)}%</Typography>
                <Typography variant="body2" sx={{ color: 'white', opacity: 0.9 }}>
                  Ganho de Eficiência
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Trends Charts */}
      <Typography variant="h6" gutterBottom sx={{ mb: 2, fontWeight: 600 }}>
        Tendências
      </Typography>
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Eventos e Alertas
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={trends.events}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" tickFormatter={(value) => new Date(value).toLocaleDateString('pt-BR', { month: 'short', day: 'numeric' })} />
                  <YAxis />
                  <RechartsTooltip />
                  <Legend />
                  <Line type="monotone" dataKey="value" stroke="#1976d2" name="Eventos" />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Casos e Playbooks
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={trends.cases}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" tickFormatter={(value) => new Date(value).toLocaleDateString('pt-BR', { month: 'short', day: 'numeric' })} />
                  <YAxis />
                  <RechartsTooltip />
                  <Legend />
                  <Line type="monotone" dataKey="value" stroke="#f57c00" name="Casos" />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Modules Overview */}
      <Typography variant="h6" gutterBottom sx={{ mb: 2, fontWeight: 600 }}>
        Visão Geral dos Módulos
      </Typography>
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* SOAR */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                SOAR (Playbooks)
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Total de Playbooks</Typography>
                  <Typography variant="h5">{modules.soar.totalPlaybooks}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Execuções</Typography>
                  <Typography variant="h5">{modules.soar.executionsTotal}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Taxa de Sucesso</Typography>
                  <Typography variant="h5" color="success.main">{modules.soar.successRate.toFixed(1)}%</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Tempo Médio</Typography>
                  <Typography variant="h5">{modules.soar.avgExecutionTime}s</Typography>
                </Grid>
              </Grid>
              <Divider sx={{ my: 2 }} />
              <Typography variant="body2" color="text.secondary" gutterBottom>Top Playbooks</Typography>
              {modules.soar.topPlaybooks.slice(0, 3).map((pb, idx) => (
                <Box key={idx} sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">{pb.name}</Typography>
                  <Chip label={`${pb.executions} exec`} size="small" />
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>

        {/* Case Management */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Gestão de Casos
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Total de Casos</Typography>
                  <Typography variant="h5">{modules.caseManagement.totalCases}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Casos Abertos</Typography>
                  <Typography variant="h5" color="warning.main">{modules.caseManagement.openCases}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">SLA Compliance</Typography>
                  <Typography variant="h5" color="success.main">{modules.caseManagement.slaCompliance.toFixed(1)}%</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Tempo Médio Resolução</Typography>
                  <Typography variant="h5">{modules.caseManagement.avgResolutionTime}h</Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* MITRE ATT&CK */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                MITRE ATT&CK
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Cobertura</Typography>
                  <Typography variant="h5" color="primary.main">{modules.mitreAttack.coveragePercent.toFixed(1)}%</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Técnicas Detectadas</Typography>
                  <Typography variant="h5">{modules.mitreAttack.detectedTechniques}</Typography>
                </Grid>
              </Grid>
              <Divider sx={{ my: 2 }} />
              <Typography variant="body2" color="text.secondary" gutterBottom>Top Táticas</Typography>
              {modules.mitreAttack.topTactics.slice(0, 3).map((tactic, idx) => (
                <Box key={idx} sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">{tactic.name}</Typography>
                  <Chip label={tactic.count} size="small" color="primary" />
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>

        {/* Threat Intelligence */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Threat Intelligence
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Total IOCs</Typography>
                  <Typography variant="h5">{formatNumber(modules.threatIntel.totalIOCs)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Eventos Enriquecidos</Typography>
                  <Typography variant="h5">{formatNumber(modules.threatIntel.eventsEnriched)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">Taxa de Enrichment</Typography>
                  <Typography variant="h5" color="success.main">{modules.threatIntel.enrichmentRate.toFixed(1)}%</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">IPs Bloqueados</Typography>
                  <Typography variant="h5" color="error.main">{modules.threatIntel.maliciousIPsBlocked}</Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Top Insights */}
      <Typography variant="h6" gutterBottom sx={{ mb: 2, fontWeight: 600 }}>
        Top Insights
      </Typography>
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Top Alertas
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Nome</TableCell>
                      <TableCell align="right">Count</TableCell>
                      <TableCell>Severidade</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {topInsights.topAlerts.map((alert, idx) => (
                      <TableRow key={idx}>
                        <TableCell>{alert.name}</TableCell>
                        <TableCell align="right">{alert.count}</TableCell>
                        <TableCell>
                          <Chip label={alert.severity} size="small" color={alert.severity === 'critical' ? 'error' : 'warning'} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Top Ameaças
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Ameaça</TableCell>
                      <TableCell align="right">Count</TableCell>
                      <TableCell>Severidade</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {topInsights.topThreats.map((threat, idx) => (
                      <TableRow key={idx}>
                        <TableCell>{threat.threat}</TableCell>
                        <TableCell align="right">{threat.count}</TableCell>
                        <TableCell>
                          <Chip label={threat.severity} size="small" color={threat.severity === 'critical' ? 'error' : 'warning'} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Executive;


