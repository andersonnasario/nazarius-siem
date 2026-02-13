import React, { useState, useEffect, useCallback } from 'react';
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
  Chip,
  IconButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Tooltip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Slider,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Checkbox,
  LinearProgress,
} from '@mui/material';
import { plaAPI } from '../services/api';
import {
  Security as SecurityIcon,
  Shield as ShieldIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Calculate as CalculateIcon,
  Assessment as AssessmentIcon,
  Timeline as TimelineIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Speed as SpeedIcon,
  Visibility as VisibilityIcon,
  ExpandMore as ExpandMoreIcon,
  BugReport as BugReportIcon,
  Gavel as GavelIcon,
  NetworkCheck as NetworkCheckIcon,
  VpnKey as VpnKeyIcon,
  Backup as BackupIcon,
} from '@mui/icons-material';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis } from 'recharts';

// Tab Panel Component
function TabPanel({ children, value, index, ...other }) {
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

// Risk level colors
const getRiskColor = (level) => {
  const colors = {
    critical: '#f44336',
    high: '#ff9800',
    medium: '#ffeb3b',
    low: '#4caf50',
  };
  return colors[level?.toLowerCase()] || '#9e9e9e';
};

// PLA Tier colors
const getTierColor = (tier) => {
  const colors = {
    platinum: '#4CAF50',
    gold: '#8BC34A',
    silver: '#FFC107',
    bronze: '#F44336',
  };
  return colors[tier?.toLowerCase()] || '#9e9e9e';
};

// Category icons
const getCategoryIcon = (category) => {
  const icons = {
    network: <NetworkCheckIcon />,
    identity: <VpnKeyIcon />,
    detection: <VisibilityIcon />,
    protection: <ShieldIcon />,
    recovery: <BackupIcon />,
  };
  return icons[category] || <SecurityIcon />;
};

const PLARiskMatrix = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [dashboard, setDashboard] = useState(null);
  const [assessments, setAssessments] = useState([]);
  const [guardRails, setGuardRails] = useState([]);
  const [plaConfig, setPlaConfig] = useState(null);
  const [error, setError] = useState('');

  // Dialog states
  const [calculatorDialog, setCalculatorDialog] = useState(false);
  const [assessmentDialog, setAssessmentDialog] = useState(false);
  const [selectedAssessment, setSelectedAssessment] = useState(null);

  // Calculator state
  const [calcParams, setCalcParams] = useState({
    cvss_score: 7.5,
    asset_criticality: 'medium',
    data_classification: 'internal',
    exposure_level: 'internal',
    exploit_available: false,
    exploit_maturity: 'none',
    attack_vector: 'network',
    guard_rail_ids: [],
  });
  const [calcResult, setCalcResult] = useState(null);
  const [calculating, setCalculating] = useState(false);

  // Fetch dashboard
  const fetchDashboard = useCallback(async () => {
    try {
      const response = await plaAPI.getDashboard();
      setDashboard(response.data);
    } catch (err) {
      console.error('Error fetching dashboard:', err);
    }
  }, []);

  // Fetch assessments
  const fetchAssessments = useCallback(async () => {
    try {
      const response = await plaAPI.getAssessments();
      setAssessments(response.data.assessments || []);
    } catch (err) {
      console.error('Error fetching assessments:', err);
    }
  }, []);

  // Fetch guard rails
  const fetchGuardRails = useCallback(async () => {
    try {
      const response = await plaAPI.getGuardRails();
      setGuardRails(response.data.guard_rails || []);
    } catch (err) {
      console.error('Error fetching guard rails:', err);
    }
  }, []);

  // Fetch config
  const fetchConfig = useCallback(async () => {
    try {
      const response = await plaAPI.getConfig();
      setPlaConfig(response.data);
    } catch (err) {
      console.error('Error fetching config:', err);
    }
  }, []);

  // Initial load
  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([
        fetchDashboard(),
        fetchAssessments(),
        fetchGuardRails(),
        fetchConfig(),
      ]);
      setLoading(false);
    };
    loadData();
  }, [fetchDashboard, fetchAssessments, fetchGuardRails, fetchConfig]);

  // Calculate risk preview
  const handleCalculateRisk = async () => {
    setCalculating(true);
    try {
      const response = await plaAPI.calculateRisk(calcParams);
      setCalcResult(response.data);
    } catch (err) {
      setError('Erro ao calcular risco');
      console.error('Error calculating risk:', err);
    } finally {
      setCalculating(false);
    }
  };

  // Toggle guard rail selection
  const toggleGuardRail = (grId) => {
    const newIds = calcParams.guard_rail_ids.includes(grId)
      ? calcParams.guard_rail_ids.filter(id => id !== grId)
      : [...calcParams.guard_rail_ids, grId];
    setCalcParams({ ...calcParams, guard_rail_ids: newIds });
  };

  // Format percentage
  const formatPercent = (value) => `${(value * 100).toFixed(1)}%`;

  // Risk Matrix Cell Component
  const RiskMatrixCell = ({ value, probIndex, impactIndex }) => {
    // Calculate risk level for cell color
    const prob = (probIndex + 1) / 5;
    const impact = (impactIndex + 1) / 5;
    const riskScore = prob * impact * 100;
    
    let bgColor = '#4caf50';
    if (riskScore >= 80) bgColor = '#f44336';
    else if (riskScore >= 60) bgColor = '#ff9800';
    else if (riskScore >= 40) bgColor = '#ffeb3b';
    else if (riskScore >= 20) bgColor = '#8bc34a';

    return (
      <Box
        sx={{
          width: 60,
          height: 60,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: bgColor,
          color: riskScore >= 40 ? 'white' : 'black',
          fontWeight: 'bold',
          borderRadius: 1,
          cursor: 'pointer',
          '&:hover': { opacity: 0.8 },
        }}
      >
        {value || 0}
      </Box>
    );
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <GavelIcon sx={{ fontSize: 40, color: 'primary.main' }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              PLA - Risk Matrix
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Protection Level Agreements com Análise de Guard Rails
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            startIcon={<CalculateIcon />}
            variant="outlined"
            onClick={() => setCalculatorDialog(true)}
          >
            Calculadora de Risco
          </Button>
          <Button
            startIcon={<RefreshIcon />}
            onClick={() => {
              fetchDashboard();
              fetchAssessments();
            }}
          >
            Atualizar
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab icon={<AssessmentIcon />} label="Dashboard" />
          <Tab icon={<BugReportIcon />} label="Assessments" />
          <Tab icon={<ShieldIcon />} label="Guard Rails" />
          <Tab icon={<TimelineIcon />} label="Matriz de Risco" />
        </Tabs>
      </Paper>

      {/* Dashboard Tab */}
      <TabPanel value={activeTab} index={0}>
        {dashboard && (
          <Grid container spacing={3}>
            {/* Summary Cards */}
            <Grid item xs={12} md={3}>
              <Card sx={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white' }}>
                <CardContent>
                  <Typography variant="body2">Total Assessments</Typography>
                  <Typography variant="h3" fontWeight="bold">
                    {dashboard.summary?.total_assessments || 0}
                  </Typography>
                  <Typography variant="caption">
                    Pendentes: {dashboard.summary?.pending_remediation || 0}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={3}>
              <Card sx={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)', color: 'white' }}>
                <CardContent>
                  <Typography variant="body2">Risco Médio</Typography>
                  <Typography variant="h3" fontWeight="bold">
                    {(dashboard.summary?.average_risk_score || 0).toFixed(1)}
                  </Typography>
                  <Typography variant="caption">
                    Mitigação média: {formatPercent(dashboard.summary?.average_mitigation || 0)}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={3}>
              <Card sx={{ background: 'linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%)', color: '#333' }}>
                <CardContent>
                  <Typography variant="body2">SLA Críticos</Typography>
                  <Typography variant="h3" fontWeight="bold">
                    {dashboard.summary?.sla_breached || 0}
                  </Typography>
                  <Typography variant="caption">
                    Em risco: {dashboard.summary?.sla_at_risk || 0}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={3}>
              <Card sx={{ background: 'linear-gradient(135deg, #a8edea 0%, #fed6e3 100%)', color: '#333' }}>
                <CardContent>
                  <Typography variant="body2">Riscos Aceitos</Typography>
                  <Typography variant="h3" fontWeight="bold">
                    {dashboard.summary?.accepted_risks || 0}
                  </Typography>
                  <Typography variant="caption">
                    Remediados: {dashboard.summary?.remediated || 0}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            {/* Risk Distribution */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Distribuição por Nível de Risco
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Critical', value: dashboard.summary?.critical_count || 0, color: '#f44336' },
                        { name: 'High', value: dashboard.summary?.high_count || 0, color: '#ff9800' },
                        { name: 'Medium', value: dashboard.summary?.medium_count || 0, color: '#ffeb3b' },
                        { name: 'Low', value: dashboard.summary?.low_count || 0, color: '#4caf50' },
                      ]}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, value }) => value > 0 ? `${name}: ${value}` : ''}
                      outerRadius={100}
                      dataKey="value"
                    >
                      {[
                        { color: '#f44336' },
                        { color: '#ff9800' },
                        { color: '#ffeb3b' },
                        { color: '#4caf50' },
                      ].map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* By PLA Tier */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Distribuição por PLA Tier
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={Object.entries(dashboard.by_tier || {}).map(([name, value]) => ({ name, value }))}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="value">
                      {Object.entries(dashboard.by_tier || {}).map(([name], index) => (
                        <Cell key={`cell-${index}`} fill={getTierColor(name)} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* Guard Rail Coverage */}
            <Grid item xs={12}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Cobertura de Guard Rails
                </Typography>
                <Grid container spacing={2}>
                  {(dashboard.guard_rail_coverage || []).slice(0, 6).map((gr, idx) => (
                    <Grid item xs={12} md={4} key={idx}>
                      <Box sx={{ mb: 2 }}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2">{gr.guard_rail_name}</Typography>
                          <Typography variant="body2" fontWeight="bold">
                            {gr.coverage_percentage?.toFixed(1)}%
                          </Typography>
                        </Box>
                        <LinearProgress 
                          variant="determinate" 
                          value={gr.coverage_percentage || 0}
                          sx={{ height: 10, borderRadius: 5 }}
                        />
                        <Typography variant="caption" color="text.secondary">
                          {gr.assets_protected} assets • Eficácia: {(gr.effectiveness_avg * 100).toFixed(0)}%
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            {/* Top Risks */}
            <Grid item xs={12}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Top Riscos (Maior Urgência)
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Prioridade</TableCell>
                        <TableCell>Vulnerabilidade</TableCell>
                        <TableCell>Asset</TableCell>
                        <TableCell>CVSS</TableCell>
                        <TableCell>Risco Inerente</TableCell>
                        <TableCell>Mitigação</TableCell>
                        <TableCell>Risco Residual</TableCell>
                        <TableCell>PLA Tier</TableCell>
                        <TableCell>SLA</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {(dashboard.top_risks || []).slice(0, 5).map((risk) => (
                        <TableRow key={risk.id}>
                          <TableCell>
                            <Chip 
                              label={`P${risk.priority}`} 
                              size="small"
                              color={risk.priority <= 2 ? 'error' : risk.priority <= 3 ? 'warning' : 'default'}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" fontWeight="bold">
                              {risk.cve_id || 'N/A'}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {risk.vulnerability_title?.substring(0, 40)}...
                            </Typography>
                          </TableCell>
                          <TableCell>{risk.asset_name}</TableCell>
                          <TableCell>
                            <Chip 
                              label={risk.cvss_score?.toFixed(1)} 
                              size="small"
                              sx={{ backgroundColor: getRiskColor(risk.cvss_score >= 9 ? 'critical' : risk.cvss_score >= 7 ? 'high' : 'medium'), color: 'white' }}
                            />
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={risk.inherent_risk_score?.toFixed(1)} 
                              size="small"
                              sx={{ backgroundColor: getRiskColor(risk.inherent_risk_level), color: 'white' }}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" color={risk.total_mitigation > 0.5 ? 'success.main' : 'warning.main'}>
                              {formatPercent(risk.total_mitigation)}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={risk.residual_risk_score?.toFixed(1)} 
                              size="small"
                              sx={{ backgroundColor: getRiskColor(risk.residual_risk_level), color: 'white' }}
                            />
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={risk.pla_tier?.toUpperCase()} 
                              size="small"
                              sx={{ backgroundColor: getTierColor(risk.pla_tier), color: 'white' }}
                            />
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={`${risk.days_remaining}d`}
                              size="small"
                              color={risk.sla_status === 'breached' ? 'error' : risk.sla_status === 'at_risk' ? 'warning' : 'success'}
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
          </Grid>
        )}
      </TabPanel>

      {/* Assessments Tab */}
      <TabPanel value={activeTab} index={1}>
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>CVE / Vulnerabilidade</TableCell>
                <TableCell>Asset</TableCell>
                <TableCell>CVSS</TableCell>
                <TableCell>Exposição</TableCell>
                <TableCell>Guard Rails</TableCell>
                <TableCell>Risco Inerente</TableCell>
                <TableCell>Mitigação</TableCell>
                <TableCell>Risco Residual</TableCell>
                <TableCell>PLA Tier</TableCell>
                <TableCell>SLA Status</TableCell>
                <TableCell>Ações</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {assessments.map((a) => (
                <TableRow key={a.id}>
                  <TableCell>
                    <Typography variant="body2" fontWeight="bold">
                      {a.cve_id || 'N/A'}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {a.vulnerability_title?.substring(0, 30)}...
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">{a.asset_name}</Typography>
                    <Chip label={a.asset_criticality} size="small" variant="outlined" />
                  </TableCell>
                  <TableCell>{a.cvss_score?.toFixed(1)}</TableCell>
                  <TableCell>
                    <Chip label={a.exposure_level} size="small" variant="outlined" />
                  </TableCell>
                  <TableCell>
                    <Tooltip title={(a.guard_rails || []).map(gr => gr.guard_rail_name).join(', ')}>
                      <Chip label={`${(a.guard_rails || []).length} ativos`} size="small" />
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={`${a.inherent_risk_score?.toFixed(1)} (${a.inherent_risk_level})`}
                      size="small"
                      sx={{ backgroundColor: getRiskColor(a.inherent_risk_level), color: 'white' }}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography color={a.total_mitigation > 0.5 ? 'success.main' : 'warning.main'}>
                      {formatPercent(a.total_mitigation)}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={`${a.residual_risk_score?.toFixed(1)} (${a.residual_risk_level})`}
                      size="small"
                      sx={{ backgroundColor: getRiskColor(a.residual_risk_level), color: 'white' }}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={a.pla_tier?.toUpperCase()}
                      size="small"
                      sx={{ backgroundColor: getTierColor(a.pla_tier), color: 'white' }}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={`${a.days_remaining}d - ${a.sla_status}`}
                      size="small"
                      color={a.sla_status === 'breached' ? 'error' : a.sla_status === 'at_risk' ? 'warning' : 'success'}
                    />
                  </TableCell>
                  <TableCell>
                    <IconButton size="small" onClick={() => { setSelectedAssessment(a); setAssessmentDialog(true); }}>
                      <VisibilityIcon fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
              {assessments.length === 0 && (
                <TableRow>
                  <TableCell colSpan={11} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      Nenhum assessment encontrado. Use a Calculadora de Risco para criar assessments a partir de vulnerabilidades.
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* Guard Rails Tab */}
      <TabPanel value={activeTab} index={2}>
        <Grid container spacing={3}>
          {['network', 'identity', 'detection', 'protection', 'recovery'].map((category) => (
            <Grid item xs={12} md={6} lg={4} key={category}>
              <Paper sx={{ p: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  {getCategoryIcon(category)}
                  <Typography variant="h6" sx={{ textTransform: 'capitalize' }}>
                    {category}
                  </Typography>
                </Box>
                <List dense>
                  {guardRails.filter(gr => gr.category === category).map((gr) => (
                    <ListItem key={gr.id}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText 
                        primary={gr.name}
                        secondary={
                          <Box>
                            <Typography variant="caption" display="block">
                              Eficácia Network: {(gr.network_effectiveness * 100).toFixed(0)}%
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {gr.provider} • {gr.type}
                            </Typography>
                          </Box>
                        }
                      />
                      <Chip 
                        label={gr.integration_status} 
                        size="small" 
                        color={gr.integration_status === 'integrated' ? 'success' : 'default'}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Risk Matrix Tab */}
      <TabPanel value={activeTab} index={3}>
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Matriz de Risco (Probabilidade x Impacto)
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Número de assessments em cada célula da matriz
          </Typography>

          <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: 2 }}>
            {/* Y-axis label */}
            <Box sx={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)', textAlign: 'center' }}>
              <Typography variant="body2" fontWeight="bold">
                PROBABILIDADE →
              </Typography>
            </Box>

            <Box>
              {/* Matrix */}
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                {['Muito Alta', 'Alta', 'Média', 'Baixa', 'Muito Baixa'].map((probLabel, probIdx) => (
                  <Box key={probIdx} sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                    <Typography variant="caption" sx={{ width: 80, textAlign: 'right' }}>
                      {probLabel}
                    </Typography>
                    {[0, 1, 2, 3, 4].map((impactIdx) => (
                      <RiskMatrixCell 
                        key={impactIdx}
                        value={dashboard?.risk_matrix?.[4 - probIdx]?.[impactIdx] || 0}
                        probIndex={4 - probIdx}
                        impactIndex={impactIdx}
                      />
                    ))}
                  </Box>
                ))}
                {/* X-axis labels */}
                <Box sx={{ display: 'flex', gap: 1, ml: 10 }}>
                  {['Muito Baixo', 'Baixo', 'Médio', 'Alto', 'Muito Alto'].map((label, idx) => (
                    <Box key={idx} sx={{ width: 60, textAlign: 'center' }}>
                      <Typography variant="caption">{label}</Typography>
                    </Box>
                  ))}
                </Box>
                <Box sx={{ textAlign: 'center', ml: 10 }}>
                  <Typography variant="body2" fontWeight="bold">
                    ← IMPACTO →
                  </Typography>
                </Box>
              </Box>
            </Box>
          </Box>

          {/* Legend */}
          <Box sx={{ display: 'flex', gap: 2, mt: 4, justifyContent: 'center' }}>
            <Chip label="Baixo (< 20)" sx={{ backgroundColor: '#4caf50', color: 'white' }} />
            <Chip label="Médio-Baixo (20-40)" sx={{ backgroundColor: '#8bc34a', color: 'white' }} />
            <Chip label="Médio (40-60)" sx={{ backgroundColor: '#ffeb3b', color: 'black' }} />
            <Chip label="Alto (60-80)" sx={{ backgroundColor: '#ff9800', color: 'white' }} />
            <Chip label="Crítico (≥ 80)" sx={{ backgroundColor: '#f44336', color: 'white' }} />
          </Box>
        </Paper>
      </TabPanel>

      {/* Risk Calculator Dialog */}
      <Dialog open={calculatorDialog} onClose={() => setCalculatorDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CalculateIcon color="primary" />
            Calculadora de Risco PLA
          </Box>
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={3} sx={{ mt: 1 }}>
            {/* Input Parameters */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Parâmetros da Vulnerabilidade
              </Typography>
              
              <Box sx={{ mb: 3 }}>
                <Typography variant="body2">CVSS Score: {calcParams.cvss_score}</Typography>
                <Slider
                  value={calcParams.cvss_score}
                  onChange={(e, v) => setCalcParams({ ...calcParams, cvss_score: v })}
                  min={0}
                  max={10}
                  step={0.1}
                  marks={[
                    { value: 0, label: '0' },
                    { value: 4, label: '4' },
                    { value: 7, label: '7' },
                    { value: 9, label: '9' },
                    { value: 10, label: '10' },
                  ]}
                />
              </Box>

              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Criticidade do Asset</InputLabel>
                    <Select
                      value={calcParams.asset_criticality}
                      label="Criticidade do Asset"
                      onChange={(e) => setCalcParams({ ...calcParams, asset_criticality: e.target.value })}
                    >
                      <MenuItem value="critical">Crítico</MenuItem>
                      <MenuItem value="high">Alto</MenuItem>
                      <MenuItem value="medium">Médio</MenuItem>
                      <MenuItem value="low">Baixo</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Classificação de Dados</InputLabel>
                    <Select
                      value={calcParams.data_classification}
                      label="Classificação de Dados"
                      onChange={(e) => setCalcParams({ ...calcParams, data_classification: e.target.value })}
                    >
                      <MenuItem value="confidential">Confidencial</MenuItem>
                      <MenuItem value="internal">Interno</MenuItem>
                      <MenuItem value="public">Público</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Nível de Exposição</InputLabel>
                    <Select
                      value={calcParams.exposure_level}
                      label="Nível de Exposição"
                      onChange={(e) => setCalcParams({ ...calcParams, exposure_level: e.target.value })}
                    >
                      <MenuItem value="internet">Internet</MenuItem>
                      <MenuItem value="dmz">DMZ</MenuItem>
                      <MenuItem value="internal">Interno</MenuItem>
                      <MenuItem value="isolated">Isolado</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Vetor de Ataque</InputLabel>
                    <Select
                      value={calcParams.attack_vector}
                      label="Vetor de Ataque"
                      onChange={(e) => setCalcParams({ ...calcParams, attack_vector: e.target.value })}
                    >
                      <MenuItem value="network">Network</MenuItem>
                      <MenuItem value="adjacent">Adjacent</MenuItem>
                      <MenuItem value="local">Local</MenuItem>
                      <MenuItem value="physical">Physical</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Exploit Disponível</InputLabel>
                    <Select
                      value={calcParams.exploit_available ? 'yes' : 'no'}
                      label="Exploit Disponível"
                      onChange={(e) => setCalcParams({ 
                        ...calcParams, 
                        exploit_available: e.target.value === 'yes',
                        exploit_maturity: e.target.value === 'yes' ? 'poc' : 'none'
                      })}
                    >
                      <MenuItem value="yes">Sim</MenuItem>
                      <MenuItem value="no">Não</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                {calcParams.exploit_available && (
                  <Grid item xs={6}>
                    <FormControl fullWidth size="small">
                      <InputLabel>Maturidade do Exploit</InputLabel>
                      <Select
                        value={calcParams.exploit_maturity}
                        label="Maturidade do Exploit"
                        onChange={(e) => setCalcParams({ ...calcParams, exploit_maturity: e.target.value })}
                      >
                        <MenuItem value="weaponized">Weaponized</MenuItem>
                        <MenuItem value="poc">PoC</MenuItem>
                        <MenuItem value="theoretical">Teórico</MenuItem>
                        <MenuItem value="none">Nenhum</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                )}
              </Grid>

              <Typography variant="subtitle2" sx={{ mt: 3, mb: 1 }}>
                Guard Rails Aplicáveis
              </Typography>
              <Box sx={{ maxHeight: 200, overflow: 'auto' }}>
                {guardRails.map((gr) => (
                  <Box key={gr.id} sx={{ display: 'flex', alignItems: 'center' }}>
                    <Checkbox
                      checked={calcParams.guard_rail_ids.includes(gr.id)}
                      onChange={() => toggleGuardRail(gr.id)}
                      size="small"
                    />
                    <Typography variant="body2">{gr.name}</Typography>
                    <Chip 
                      label={`${(gr.network_effectiveness * 100).toFixed(0)}%`}
                      size="small"
                      sx={{ ml: 'auto' }}
                    />
                  </Box>
                ))}
              </Box>
            </Grid>

            {/* Results */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Resultado da Análise
              </Typography>

              {calcResult ? (
                <Box>
                  {/* Inherent Risk */}
                  <Paper sx={{ p: 2, mb: 2, backgroundColor: 'error.dark' }}>
                    <Typography variant="subtitle2" color="white">
                      Risco Inerente (sem controles)
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 1 }}>
                      <Typography variant="h3" color="white" fontWeight="bold">
                        {calcResult.inherent_risk_score?.toFixed(1)}
                      </Typography>
                      <Chip 
                        label={calcResult.inherent_risk_level?.toUpperCase()}
                        sx={{ backgroundColor: 'white' }}
                      />
                    </Box>
                    <Typography variant="caption" color="white">
                      Probabilidade: {formatPercent(calcResult.inherent_probability)} • 
                      Impacto: {formatPercent(calcResult.inherent_impact)}
                    </Typography>
                  </Paper>

                  {/* Mitigation */}
                  <Paper sx={{ p: 2, mb: 2, backgroundColor: 'info.dark' }}>
                    <Typography variant="subtitle2" color="white">
                      Mitigação pelos Guard Rails
                    </Typography>
                    <Typography variant="h3" color="white" fontWeight="bold">
                      {formatPercent(calcResult.total_mitigation)}
                    </Typography>
                    <Typography variant="caption" color="white">
                      {calcParams.guard_rail_ids.length} controles aplicados
                    </Typography>
                  </Paper>

                  {/* Residual Risk */}
                  <Paper sx={{ p: 2, mb: 2, backgroundColor: getTierColor(calcResult.pla_tier) }}>
                    <Typography variant="subtitle2" color="white">
                      Risco Residual (após controles)
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 1 }}>
                      <Typography variant="h3" color="white" fontWeight="bold">
                        {calcResult.residual_risk_score?.toFixed(1)}
                      </Typography>
                      <Chip 
                        label={calcResult.residual_risk_level?.toUpperCase()}
                        sx={{ backgroundColor: 'white' }}
                      />
                    </Box>
                    <Typography variant="caption" color="white">
                      PLA Tier: {calcResult.pla_tier?.toUpperCase()} • 
                      SLA: {calcResult.remediation_sla_days} dias
                    </Typography>
                  </Paper>

                  {/* Priority & Recommendation */}
                  <Alert severity={calcResult.priority <= 2 ? 'error' : calcResult.priority <= 3 ? 'warning' : 'info'}>
                    <Typography variant="subtitle2">
                      Prioridade: P{calcResult.priority} (Score Final: {calcResult.final_score?.toFixed(1)})
                    </Typography>
                    <Typography variant="body2">
                      {calcResult.recommendation}
                    </Typography>
                  </Alert>
                </Box>
              ) : (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                  <Typography color="text.secondary">
                    Configure os parâmetros e clique em "Calcular" para ver o resultado
                  </Typography>
                </Box>
              )}
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCalculatorDialog(false)}>Fechar</Button>
          <Button 
            variant="contained" 
            onClick={handleCalculateRisk}
            disabled={calculating}
            startIcon={calculating ? <CircularProgress size={20} /> : <CalculateIcon />}
          >
            {calculating ? 'Calculando...' : 'Calcular'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Assessment Details Dialog */}
      <Dialog open={assessmentDialog} onClose={() => setAssessmentDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Detalhes do Assessment</DialogTitle>
        <DialogContent>
          {selectedAssessment && (
            <Grid container spacing={2} sx={{ mt: 1 }}>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">CVE ID</Typography>
                <Typography>{selectedAssessment.cve_id || 'N/A'}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">CVSS Score</Typography>
                <Typography>{selectedAssessment.cvss_score?.toFixed(1)}</Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="caption" color="text.secondary">Vulnerabilidade</Typography>
                <Typography>{selectedAssessment.vulnerability_title}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">Asset</Typography>
                <Typography>{selectedAssessment.asset_name}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">Criticidade</Typography>
                <Chip label={selectedAssessment.asset_criticality} size="small" />
              </Grid>
              <Grid item xs={12}>
                <Divider sx={{ my: 1 }} />
                <Typography variant="subtitle2">Análise de Risco</Typography>
              </Grid>
              <Grid item xs={4}>
                <Typography variant="caption" color="text.secondary">Risco Inerente</Typography>
                <Typography fontWeight="bold" color="error.main">
                  {selectedAssessment.inherent_risk_score?.toFixed(1)} ({selectedAssessment.inherent_risk_level})
                </Typography>
              </Grid>
              <Grid item xs={4}>
                <Typography variant="caption" color="text.secondary">Mitigação</Typography>
                <Typography fontWeight="bold" color="success.main">
                  {formatPercent(selectedAssessment.total_mitigation)}
                </Typography>
              </Grid>
              <Grid item xs={4}>
                <Typography variant="caption" color="text.secondary">Risco Residual</Typography>
                <Typography fontWeight="bold" color="warning.main">
                  {selectedAssessment.residual_risk_score?.toFixed(1)} ({selectedAssessment.residual_risk_level})
                </Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="caption" color="text.secondary">Guard Rails Aplicados</Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                  {(selectedAssessment.guard_rails || []).map((gr) => (
                    <Chip 
                      key={gr.guard_rail_id}
                      label={`${gr.guard_rail_name} (${(gr.effectiveness_score * 100).toFixed(0)}%)`}
                      size="small"
                      color={gr.status === 'active' ? 'success' : 'default'}
                    />
                  ))}
                </Box>
              </Grid>
              <Grid item xs={12}>
                <Divider sx={{ my: 1 }} />
                <Typography variant="subtitle2">PLA & SLA</Typography>
              </Grid>
              <Grid item xs={4}>
                <Typography variant="caption" color="text.secondary">PLA Tier</Typography>
                <Chip 
                  label={selectedAssessment.pla_tier?.toUpperCase()}
                  sx={{ backgroundColor: getTierColor(selectedAssessment.pla_tier), color: 'white' }}
                />
              </Grid>
              <Grid item xs={4}>
                <Typography variant="caption" color="text.secondary">SLA</Typography>
                <Typography>{selectedAssessment.remediation_sla_days} dias</Typography>
              </Grid>
              <Grid item xs={4}>
                <Typography variant="caption" color="text.secondary">Dias Restantes</Typography>
                <Chip 
                  label={`${selectedAssessment.days_remaining}d`}
                  color={selectedAssessment.sla_status === 'breached' ? 'error' : selectedAssessment.sla_status === 'at_risk' ? 'warning' : 'success'}
                />
              </Grid>
              <Grid item xs={12}>
                <Typography variant="caption" color="text.secondary">Recomendação</Typography>
                <Alert severity="info" sx={{ mt: 1 }}>
                  {selectedAssessment.recommendation}
                </Alert>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAssessmentDialog(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default PLARiskMatrix;

