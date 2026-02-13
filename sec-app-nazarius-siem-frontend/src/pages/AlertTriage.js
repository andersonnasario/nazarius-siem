import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Container,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  LinearProgress,
  Alert,
  Tooltip,
  Avatar,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  TrendingUp as TrendingUpIcon,
  Psychology as PsychologyIcon,
  Speed as SpeedIcon,
  ThumbDown as ThumbDownIcon,
  Refresh as RefreshIcon,
  Visibility as VisibilityIcon,
  CheckCircleOutline as AcknowledgeIcon,
  Cancel as DismissIcon,
  ArrowUpward as EscalateIcon,
  Done as ResolveIcon,
} from '@mui/icons-material';
import DetailsDialog from '../components/DetailsDialog';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { alertTriageAPI } from '../services/api';

const COLORS = ['#f44336', '#ff9800', '#ffc107', '#4caf50', '#2196f3'];

const AlertTriage = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(false);
  
  // Data states
  const [stats, setStats] = useState(null);
  const [triageResults, setTriageResults] = useState([]);
  const [analysts, setAnalysts] = useState([]);
  
  // Dialog states
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [selectedResult, setSelectedResult] = useState(null);
  const [fpDialogOpen, setFpDialogOpen] = useState(false);
  const [fpReason, setFpReason] = useState('');
  
  // Details Dialog states
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsTitle, setDetailsTitle] = useState('');
  const [detailsData, setDetailsData] = useState(null);
  const [detailsFields, setDetailsFields] = useState([]);

  // Helper function to convert severity to score
  const getSeverityScore = useCallback((severity) => {
    const scores = {
      'CRITICAL': 95,
      'HIGH': 75,
      'MEDIUM': 50,
      'LOW': 25,
      'INFORMATIONAL': 10,
    };
    return scores[severity?.toUpperCase()] || 50;
  }, []);
  
  // Helper function to map severity to classification
  const mapSeverityToClassification = useCallback((severity) => {
    const mapping = {
      'CRITICAL': 'critical',
      'HIGH': 'high',
      'MEDIUM': 'medium',
      'LOW': 'low',
      'INFORMATIONAL': 'info',
    };
    return mapping[severity?.toUpperCase()] || 'medium';
  }, []);

  const loadData = useCallback(async () => {
    try {
      // Load production data from OpenSearch + legacy data for analysts
      const [statsRes, queueRes, analystsRes] = await Promise.all([
        alertTriageAPI.getStatistics(),
        alertTriageAPI.getQueue({ page_size: 100 }),
        alertTriageAPI.listAnalysts(),
      ]);
      
      // Map statistics from OpenSearch format
      const statsData = statsRes.data.data;
      setStats({
        total_alerts: statsData.total_alerts || 0,
        triaged_alerts: statsData.triaged_alerts || 0,
        pending_alerts: statsData.pending_alerts || 0,
        false_positives: statsData.false_positives || 0,
        average_triage_time: 0, // Not available in real data yet
        false_positive_rate: statsData.false_positive_rate || 0,
        alerts_by_classification: statsData.by_severity || {},
        alerts_by_status: statsData.by_status || {},
        by_triage_status: statsData.by_triage_status || {},
        by_source: statsData.by_source || {},
        top_correlations: [],
        analyst_workload: analystsRes.data?.data?.map(a => ({
          analyst_id: a.id,
          analyst_name: a.name,
          assigned: a.current_load || 0,
          in_progress: 0,
          resolved: 0,
          load_percent: a.max_load ? (a.current_load / a.max_load) * 100 : 0,
        })) || [],
        time_series_data: [],
      });
      
      // Map queue data from OpenSearch alerts format to triage results format
      const alertsData = queueRes.data.data || [];
      const mappedResults = alertsData.map(alert => ({
        id: alert.id,
        alert_id: alert.id,
        timestamp: alert.created_at || new Date().toISOString(),
        // Calculate scores based on severity
        severity_score: getSeverityScore(alert.severity),
        confidence_score: 70,
        impact_score: getSeverityScore(alert.severity) * 0.9,
        urgency_score: alert.priority_score || getSeverityScore(alert.severity),
        priority_score: alert.priority_score || getSeverityScore(alert.severity),
        false_positive_prob: alert.false_positive ? 1.0 : 0.1,
        classification: mapSeverityToClassification(alert.severity),
        assigned_to: alert.triaged_by || '',
        assignment_reason: '',
        status: alert.triage_status || alert.status || 'pending',
        // Original alert data
        name: alert.name,
        description: alert.description,
        source: alert.source,
        severity: alert.severity,
        category: alert.category,
        resource_id: alert.resource_id,
        resource_type: alert.resource_type,
        region: alert.region,
        account_id: alert.account_id,
        recommendation: alert.recommendation,
        tags: alert.tags || [],
        enrichment: {
          asset_criticality: alert.resource_type === 'AwsAccount' ? 'high' : 'medium',
          asset_owner: alert.account_id || 'Unknown',
          asset_location: alert.region || 'Unknown',
          user_risk_score: 50,
        },
        correlation: {},
        suggestions: alert.recommendation ? [{
          id: 'sug-auto',
          action: 'review',
          description: alert.recommendation,
          confidence: 0.8,
          priority: 1,
          playbook: 'standard_review',
          automated: false,
        }] : [],
        metadata: alert.metadata || {},
      }));
      
      setTriageResults(mappedResults);
      setAnalysts(analystsRes.data.data || []);
    } catch (error) {
      console.error('Error loading data:', error);
    }
  }, [getSeverityScore, mapSeverityToClassification]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, [loadData]);

  const handleMarkFalsePositive = async () => {
    if (!selectedResult) return;

    try {
      setLoading(true);
      // Use production endpoint to mark as false positive
      await alertTriageAPI.performAction(selectedResult.id, {
        action: 'false_positive',
        reason: fpReason,
        notes: 'User marked as false positive',
      });
      setFpDialogOpen(false);
      setFpReason('');
      loadData();
    } catch (error) {
      console.error('Error marking false positive:', error);
    } finally {
      setLoading(false);
    }
  };
  
  // Quick action handlers for triage queue
  const handleQuickAction = async (alertId, action, reason = '') => {
    try {
      setLoading(true);
      await alertTriageAPI.performAction(alertId, {
        action: action,
        reason: reason,
        notes: '',
      });
      loadData();
    } catch (error) {
      console.error(`Error performing ${action}:`, error);
    } finally {
      setLoading(false);
    }
  };

  const handleViewAnalystDetails = (analyst) => {
    setDetailsData(analyst);
    setDetailsTitle(`Analyst: ${analyst.name}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Name', key: 'name' },
      { label: 'Email', key: 'email' },
      { label: 'Assigned Alerts', key: 'assigned_alerts' },
      { label: 'Resolved Alerts', key: 'resolved_alerts' },
      { label: 'Average Response Time', key: 'avg_response_time' },
      { label: 'Expertise', key: 'expertise', type: 'array' },
      { label: 'Status', key: 'status', type: 'status' },
      { label: 'Last Active', key: 'last_active', type: 'date' }
    ]);
    setDetailsOpen(true);
  };

  const getClassificationColor = (classification) => {
    const colors = {
      critical: 'error',
      high: 'warning',
      medium: 'info',
      low: 'success',
      info: 'default',
    };
    return colors[classification] || 'default';
  };
  
  // Tradução de status para português
  const getStatusLabel = (status) => {
    const labels = {
      'pending': 'PENDENTE',
      'new': 'NOVO',
      'acknowledged': 'RECONHECIDO',
      'investigating': 'INVESTIGANDO',
      'resolved': 'RESOLVIDO',
      'dismissed': 'DESCARTADO',
      'escalated': 'ESCALADO',
      'false_positive': 'FALSO POSITIVO',
    };
    return labels[status?.toLowerCase()] || (status || 'PENDENTE').toUpperCase();
  };

  const getClassificationIcon = (classification) => {
    const icons = {
      critical: <ErrorIcon />,
      high: <WarningIcon />,
      medium: <InfoIcon />,
      low: <CheckCircleIcon />,
      info: <InfoIcon />,
    };
    return icons[classification] || <InfoIcon />;
  };

  const getScoreColor = (score) => {
    if (score >= 80) return '#f44336';
    if (score >= 60) return '#ff9800';
    if (score >= 40) return '#ffc107';
    if (score >= 20) return '#4caf50';
    return '#2196f3';
  };

  // KPI Cards
  const renderKPICards = () => {
    if (!stats) return null;

    // Calculate severity counts from alerts_by_classification (which is by_severity from OpenSearch)
    const criticalCount = stats.alerts_by_classification?.CRITICAL || 0;
    const highCount = stats.alerts_by_classification?.HIGH || 0;

    return (
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Total de Alertas
                  </Typography>
                  <Typography variant="h4">{stats.total_alerts}</Typography>
                  <Typography variant="body2" color="success.main">
                    {stats.triaged_alerts} processados
                  </Typography>
                </Box>
                <PsychologyIcon sx={{ fontSize: 40, color: 'primary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: stats.pending_alerts > 10 ? 'warning.dark' : 'inherit' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Pendentes de Triage
                  </Typography>
                  <Typography variant="h4">{stats.pending_alerts}</Typography>
                  <Typography variant="body2" color="warning.main">
                    {criticalCount > 0 && `${criticalCount} críticos`}
                    {criticalCount > 0 && highCount > 0 && ', '}
                    {highCount > 0 && `${highCount} altos`}
                    {criticalCount === 0 && highCount === 0 && 'Requer atenção'}
                  </Typography>
                </Box>
                <SpeedIcon sx={{ fontSize: 40, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Falsos Positivos
                  </Typography>
                  <Typography variant="h4">{stats.false_positives}</Typography>
                  <Typography variant="body2" color="info.main">
                    {(stats.false_positive_rate || 0).toFixed(1)}% taxa
                  </Typography>
                </Box>
                <ThumbDownIcon sx={{ fontSize: 40, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Por Origem
                  </Typography>
                  <Box display="flex" gap={0.5} flexWrap="wrap">
                    {Object.entries(stats.by_source || {}).slice(0, 3).map(([source, count]) => (
                      <Chip key={source} label={`${source}: ${count}`} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Box>
                <TrendingUpIcon sx={{ fontSize: 40, color: 'success.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    );
  };

  // Overview Tab
  const renderOverviewTab = () => {
    if (!stats) return <LinearProgress />;

    const classificationData = Object.entries(stats.alerts_by_classification || {}).map(([name, value]) => ({
      name: name.toUpperCase(),
      value,
    }));

    const statusData = Object.entries(stats.alerts_by_status || {}).map(([name, value]) => ({
      name: getStatusLabel(name),
      value,
    }));

    return (
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Alertas por Classificação
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={classificationData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {classificationData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Alertas por Status
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={statusData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                  <YAxis />
                  <RechartsTooltip />
                  <Bar dataKey="value" fill="#8884d8" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Linha do Tempo de Triage (Últimas 24h)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={stats.time_series_data || []}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="timestamp" 
                    tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                  />
                  <YAxis />
                  <RechartsTooltip 
                    labelFormatter={(value) => new Date(value).toLocaleString()}
                  />
                  <Legend />
                  <Line type="monotone" dataKey="triaged_alerts" stroke="#8884d8" name="Triagem Realizada" />
                  <Line type="monotone" dataKey="false_positives" stroke="#ff7c7c" name="Falsos Positivos" />
                  <Line type="monotone" dataKey="avg_score" stroke="#82ca9d" name="Score Médio" />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Principais Correlações
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>ID Correlação</TableCell>
                      <TableCell>Tipo</TableCell>
                      <TableCell align="right">Alertas</TableCell>
                      <TableCell>Severidade</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(stats.top_correlations || []).slice(0, 5).map((corr) => (
                      <TableRow key={corr.correlation_id}>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {corr.correlation_id.substring(0, 8)}
                          </Typography>
                        </TableCell>
                        <TableCell>{corr.correlation_type}</TableCell>
                        <TableCell align="right">
                          <Chip label={corr.alert_count} size="small" />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={corr.severity.toUpperCase()}
                            color={getClassificationColor(corr.severity)}
                            size="small"
                          />
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
                Carga de Trabalho dos Analistas
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Analista</TableCell>
                      <TableCell align="right">Atribuídos</TableCell>
                      <TableCell align="right">Em Progresso</TableCell>
                      <TableCell align="right">Carga %</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(stats.analyst_workload || []).map((analyst) => (
                      <TableRow key={analyst.analyst_id}>
                        <TableCell>{analyst.analyst_name}</TableCell>
                        <TableCell align="right">{analyst.assigned}</TableCell>
                        <TableCell align="right">{analyst.in_progress}</TableCell>
                        <TableCell align="right">
                          <Box display="flex" alignItems="center" gap={1}>
                            <LinearProgress
                              variant="determinate"
                              value={analyst.load_percent}
                              sx={{ flexGrow: 1, height: 8, borderRadius: 4 }}
                              color={analyst.load_percent > 80 ? 'error' : 'primary'}
                            />
                            <Typography variant="body2">
                              {analyst.load_percent.toFixed(0)}%
                            </Typography>
                          </Box>
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
    );
  };

  // Triage Queue Tab
  const renderTriageQueueTab = () => {
    const getStatusColor = (status) => {
      const colors = {
        'pending': 'warning',
        'new': 'warning',
        'acknowledged': 'info',
        'investigating': 'primary',
        'resolved': 'success',
        'dismissed': 'default',
        'escalated': 'error',
        'false_positive': 'default',
      };
      return colors[status?.toLowerCase()] || 'default';
    };

    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Box>
              <Typography variant="h6">Fila de Triage</Typography>
              <Typography variant="body2" color="textSecondary">
                {triageResults.length} alertas pendentes de triage
              </Typography>
            </Box>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={loadData}
              disabled={loading}
            >
              Atualizar
            </Button>
          </Box>

          {loading && <LinearProgress sx={{ mb: 2 }} />}

          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Alerta</TableCell>
                  <TableCell>Severidade</TableCell>
                  <TableCell>Origem</TableCell>
                  <TableCell>Recurso</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Score</TableCell>
                  <TableCell>Data</TableCell>
                  <TableCell align="center">Ações Rápidas</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {triageResults.map((result) => (
                  <TableRow 
                    key={result.id}
                    sx={{ 
                      '&:hover': { bgcolor: 'action.hover' },
                      bgcolor: result.classification === 'critical' ? 'error.dark' : 'inherit',
                      opacity: result.status === 'resolved' || result.status === 'dismissed' ? 0.6 : 1,
                    }}
                  >
                    <TableCell>
                      <Box>
                        <Typography variant="body2" fontWeight="medium" noWrap sx={{ maxWidth: 250 }}>
                          {result.name || result.alert_id?.substring(0, 20)}
                        </Typography>
                        <Typography variant="caption" color="textSecondary" noWrap sx={{ maxWidth: 250 }}>
                          {result.category || result.description?.substring(0, 40)}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        icon={getClassificationIcon(result.classification)}
                        label={result.classification?.toUpperCase() || 'UNKNOWN'}
                        color={getClassificationColor(result.classification)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={result.source || 'unknown'} 
                        size="small" 
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      <Box>
                        <Typography variant="caption" display="block">
                          {result.resource_type || '-'}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          {result.region || '-'}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={(result.status || 'pending').replace('_', ' ').toUpperCase()}
                        size="small"
                        color={getStatusColor(result.status)}
                      />
                    </TableCell>
                    <TableCell>
                      <Box display="flex" alignItems="center" gap={0.5}>
                        <LinearProgress
                          variant="determinate"
                          value={result.priority_score || 50}
                          sx={{ width: 50, height: 6, borderRadius: 3 }}
                          color={result.priority_score > 70 ? 'error' : result.priority_score > 40 ? 'warning' : 'success'}
                        />
                        <Typography variant="caption">
                          {Math.round(result.priority_score || 50)}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption">
                        {new Date(result.timestamp).toLocaleString('pt-BR', { 
                          day: '2-digit', 
                          month: '2-digit', 
                          hour: '2-digit', 
                          minute: '2-digit' 
                        })}
                      </Typography>
                    </TableCell>
                    <TableCell align="center">
                      <Box display="flex" justifyContent="center" gap={0.5}>
                        <Tooltip title="Reconhecer">
                          <IconButton
                            size="small"
                            onClick={() => handleQuickAction(result.id, 'acknowledge')}
                            color="info"
                            disabled={loading || result.status === 'acknowledged'}
                          >
                            <AcknowledgeIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Escalar">
                          <IconButton
                            size="small"
                            onClick={() => handleQuickAction(result.id, 'escalate', 'Requer revisão sênior')}
                            color="error"
                            disabled={loading}
                          >
                            <EscalateIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Resolver">
                          <IconButton
                            size="small"
                            onClick={() => handleQuickAction(result.id, 'resolve', 'Problema tratado')}
                            color="success"
                            disabled={loading || result.status === 'resolved'}
                          >
                            <ResolveIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Falso Positivo">
                          <IconButton
                            size="small"
                            onClick={() => {
                              setSelectedResult(result);
                              setFpDialogOpen(true);
                            }}
                            color="warning"
                            disabled={loading}
                          >
                            <ThumbDownIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Descartar">
                          <IconButton
                            size="small"
                            onClick={() => handleQuickAction(result.id, 'dismiss', 'Não relevante')}
                            disabled={loading || result.status === 'dismissed'}
                          >
                            <DismissIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Ver Detalhes">
                          <IconButton
                            size="small"
                            onClick={() => {
                              setSelectedResult(result);
                              setDetailsDialogOpen(true);
                            }}
                          >
                            <VisibilityIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
                {triageResults.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      <Box py={4}>
                        <CheckCircleIcon sx={{ fontSize: 48, color: 'success.main', mb: 1 }} />
                        <Typography variant="h6" color="success.main">
                          Nenhum alerta pendente de triage
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                          Todos os alertas foram processados
                        </Typography>
                      </Box>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    );
  };

  // Analysts Tab
  // Tradução de disponibilidade
  const getAvailabilityLabel = (availability) => {
    const labels = {
      'available': 'DISPONÍVEL',
      'busy': 'OCUPADO',
      'offline': 'OFFLINE',
    };
    return labels[availability?.toLowerCase()] || availability?.toUpperCase() || 'DISPONÍVEL';
  };

  // Tradução de habilidades e especializações
  const translateSkill = (skill) => {
    const translations = {
      // Skills
      'incident_response': 'Resposta a Incidentes',
      'threat_hunting': 'Caça a Ameaças',
      'forensics': 'Forense Digital',
      'management': 'Gestão',
      'alert_analysis': 'Análise de Alertas',
      'log_analysis': 'Análise de Logs',
      'compliance': 'Compliance',
      'monitoring': 'Monitoramento',
      // Specializations
      'security_operations': 'Operações de Segurança',
      'audit': 'Auditoria',
      'siem': 'SIEM',
      'pci_dss': 'PCI-DSS',
      'financial_security': 'Segurança Financeira',
      'general': 'Geral',
    };
    return translations[skill?.toLowerCase()] || skill?.replace(/_/g, ' ') || skill;
  };

  const renderAnalystsTab = () => {
    if (analysts.length === 0) {
      return (
        <Card>
          <CardContent>
            <Box textAlign="center" py={4}>
              <Typography variant="h6" color="textSecondary">
                Nenhum analista cadastrado
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Cadastre usuários no sistema para visualizá-los aqui
              </Typography>
            </Box>
          </CardContent>
        </Card>
      );
    }

    return (
      <Grid container spacing={3}>
        {analysts.map((analyst) => (
          <Grid item xs={12} md={6} lg={4} key={analyst.id}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" gap={2} mb={2}>
                  <Avatar sx={{ width: 56, height: 56, bgcolor: 'primary.main' }}>
                    {analyst.name?.charAt(0)?.toUpperCase() || 'U'}
                  </Avatar>
                  <Box flexGrow={1}>
                    <Typography variant="h6">{analyst.name || 'Usuário'}</Typography>
                    <Typography variant="body2" color="textSecondary">
                      {analyst.email}
                    </Typography>
                  </Box>
                  <Chip
                    label={getAvailabilityLabel(analyst.availability)}
                    color={analyst.availability === 'available' ? 'success' : 'warning'}
                    size="small"
                  />
                </Box>

                <Box mb={2}>
                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    Carga de Trabalho
                  </Typography>
                  <Box display="flex" alignItems="center" gap={1}>
                    <LinearProgress
                      variant="determinate"
                      value={(analyst.current_load / analyst.max_load) * 100}
                      sx={{ flexGrow: 1, height: 10, borderRadius: 5 }}
                      color={(analyst.current_load / analyst.max_load) > 0.8 ? 'error' : 'primary'}
                    />
                    <Typography variant="body2">
                      {analyst.current_load}/{analyst.max_load}
                    </Typography>
                  </Box>
                </Box>

                <Box mb={2}>
                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    Habilidades
                  </Typography>
                  <Box display="flex" flexWrap="wrap" gap={0.5}>
                    {(analyst.skills || []).map((skill, idx) => (
                      <Chip key={idx} label={translateSkill(skill)} size="small" />
                    ))}
                  </Box>
                </Box>

                <Box>
                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    Especializações
                  </Typography>
                  <Box display="flex" flexWrap="wrap" gap={0.5}>
                    {(analyst.specializations || []).map((spec, idx) => (
                      <Chip key={idx} label={translateSkill(spec)} size="small" color="primary" />
                    ))}
                  </Box>
                </Box>

                <Box mt={2} display="flex" justifyContent="flex-end">
                  <Tooltip title="Ver Detalhes">
                    <IconButton
                      size="small"
                      onClick={() => handleViewAnalystDetails(analyst)}
                    >
                      <VisibilityIcon />
                    </IconButton>
                  </Tooltip>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    );
  };

  // Details Dialog
  const renderDetailsDialog = () => {
    if (!selectedResult) return null;

    return (
      <Dialog 
        open={detailsDialogOpen} 
        onClose={() => setDetailsDialogOpen(false)} 
        maxWidth="md" 
        fullWidth
      >
        <DialogTitle>
          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Typography variant="h6">Detalhes do Alerta</Typography>
            <Chip
              label={selectedResult.classification?.toUpperCase() || 'DESCONHECIDO'}
              color={getClassificationColor(selectedResult.classification)}
            />
          </Box>
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            {/* Informações do Alerta */}
            <Typography variant="subtitle2" color="primary" gutterBottom>Informações do Alerta</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12}>
                <Typography variant="body2" color="textSecondary">Nome</Typography>
                <Typography variant="body1" fontWeight="medium">{selectedResult.name || selectedResult.alert_id}</Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="body2" color="textSecondary">Descrição</Typography>
                <Typography variant="body1">{selectedResult.description || 'Nenhuma descrição disponível'}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Origem</Typography>
                <Chip label={selectedResult.source || 'desconhecido'} size="small" />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Categoria</Typography>
                <Typography variant="body1">{selectedResult.category || '-'}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Status</Typography>
                <Chip 
                  label={getStatusLabel(selectedResult.status)} 
                  size="small"
                  color={selectedResult.status === 'resolved' ? 'success' : 'default'}
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">ID do Alerta</Typography>
                <Typography variant="body1" fontFamily="monospace" fontSize="0.85rem">
                  {selectedResult.id}
                </Typography>
              </Grid>
            </Grid>

            {/* Informações do Recurso */}
            <Typography variant="subtitle2" color="primary" gutterBottom>Informações do Recurso</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Tipo de Recurso</Typography>
                <Typography variant="body1">{selectedResult.resource_type || '-'}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">ID do Recurso</Typography>
                <Typography variant="body1" fontFamily="monospace" fontSize="0.85rem">
                  {selectedResult.resource_id || '-'}
                </Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Região</Typography>
                <Typography variant="body1">{selectedResult.region || '-'}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">ID da Conta</Typography>
                <Typography variant="body1">{selectedResult.account_id || '-'}</Typography>
              </Grid>
            </Grid>

            {/* Scores de Prioridade */}
            <Typography variant="subtitle2" color="primary" gutterBottom>Scores de Prioridade</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={3}>
                <Typography variant="body2" color="textSecondary">Severidade</Typography>
                <Typography variant="h6" style={{ color: getScoreColor(selectedResult.severity_score) }}>
                  {(selectedResult.severity_score || 0).toFixed(0)}
                </Typography>
              </Grid>
              <Grid item xs={3}>
                <Typography variant="body2" color="textSecondary">Confiança</Typography>
                <Typography variant="h6" style={{ color: getScoreColor(selectedResult.confidence_score) }}>
                  {(selectedResult.confidence_score || 0).toFixed(0)}
                </Typography>
              </Grid>
              <Grid item xs={3}>
                <Typography variant="body2" color="textSecondary">Impacto</Typography>
                <Typography variant="h6" style={{ color: getScoreColor(selectedResult.impact_score) }}>
                  {(selectedResult.impact_score || 0).toFixed(0)}
                </Typography>
              </Grid>
              <Grid item xs={3}>
                <Typography variant="body2" color="textSecondary">Prioridade</Typography>
                <Typography variant="h6" style={{ color: getScoreColor(selectedResult.priority_score) }}>
                  {(selectedResult.priority_score || 0).toFixed(0)}
                </Typography>
              </Grid>
            </Grid>

            {/* Recomendação */}
            {selectedResult.recommendation && (
              <>
                <Typography variant="subtitle2" color="primary" gutterBottom>Recomendação</Typography>
                <Alert severity="info" sx={{ mb: 3 }}>
                  <Typography variant="body2">{selectedResult.recommendation}</Typography>
                </Alert>
              </>
            )}

            {/* Tags */}
            {selectedResult.tags && selectedResult.tags.length > 0 && (
              <>
                <Typography variant="subtitle2" color="primary" gutterBottom>Tags</Typography>
                <Box display="flex" gap={0.5} flexWrap="wrap" sx={{ mb: 3 }}>
                  {selectedResult.tags.map((tag, idx) => (
                    <Chip key={idx} label={tag} size="small" variant="outlined" />
                  ))}
                </Box>
              </>
            )}

            {/* Ações Sugeridas */}
            {selectedResult.suggestions && selectedResult.suggestions.length > 0 && (
              <>
                <Typography variant="subtitle2" color="primary" gutterBottom>Ações Sugeridas</Typography>
                {selectedResult.suggestions.map((suggestion, idx) => (
                  <Alert key={idx} severity="info" sx={{ mb: 1 }}>
                    <Typography variant="body2" fontWeight="bold">{suggestion.action}</Typography>
                    <Typography variant="body2">{suggestion.description}</Typography>
                  </Alert>
                ))}
              </>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button 
            onClick={() => handleQuickAction(selectedResult.id, 'acknowledge')}
            color="info"
            disabled={loading}
          >
            Reconhecer
          </Button>
          <Button 
            onClick={() => handleQuickAction(selectedResult.id, 'resolve', 'Resolvido via detalhes')}
            color="success"
            disabled={loading}
          >
            Resolver
          </Button>
          <Button 
            onClick={() => {
              setFpDialogOpen(true);
            }}
            color="warning"
            disabled={loading}
          >
            Falso Positivo
          </Button>
          <Button onClick={() => setDetailsDialogOpen(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>
    );
  };

  // False Positive Dialog
  const renderFPDialog = () => {
    return (
      <Dialog open={fpDialogOpen} onClose={() => setFpDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Marcar como Falso Positivo</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <TextField
              fullWidth
              label="Motivo"
              value={fpReason}
              onChange={(e) => setFpReason(e.target.value)}
              multiline
              rows={4}
              placeholder="Por favor, informe o motivo para marcar este alerta como falso positivo..."
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setFpDialogOpen(false)}>Cancelar</Button>
          <Button 
            onClick={handleMarkFalsePositive} 
            variant="contained" 
            color="warning"
            disabled={loading || !fpReason}
          >
            Marcar como Falso Positivo
          </Button>
        </DialogActions>
      </Dialog>
    );
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          🎯 Triage Inteligente de Alertas
        </Typography>
        <Typography variant="body1" color="textSecondary">
          Classificação, priorização e atribuição automática de alertas
        </Typography>
      </Box>

      {renderKPICards()}

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
          <Tab label="Visão Geral" />
          <Tab label="Fila de Triage" />
          <Tab label="Analistas" />
        </Tabs>
      </Box>

      {activeTab === 0 && renderOverviewTab()}
      {activeTab === 1 && renderTriageQueueTab()}
      {activeTab === 2 && renderAnalystsTab()}

      {renderDetailsDialog()}
      {renderFPDialog()}

      {/* Details Dialog */}
      <DetailsDialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        title={detailsTitle}
        data={detailsData}
        fields={detailsFields}
      />
    </Container>
  );
};

export default AlertTriage;

