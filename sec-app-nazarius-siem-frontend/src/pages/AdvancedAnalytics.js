import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, LinearProgress, IconButton, Tooltip, Button,
  AlertTitle, Divider
} from '@mui/material';
import {
  Psychology as PsychologyIcon,
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Visibility as VisibilityIcon,
  Assessment as AssessmentIcon,
  Refresh as RefreshIcon,
  PlayArrow as PlayIcon,
  Storage as StorageIcon,
  BugReport as BugReportIcon,
  Info as InfoIcon,
  CleaningServices as CleanIcon
} from '@mui/icons-material';
import { advancedAnalyticsAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const AdvancedAnalytics = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [anomalies, setAnomalies] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [predictions, setPredictions] = useState([]);
  const [models, setModels] = useState([]);
  const [riskAssessments, setRiskAssessments] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Details Dialog States
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsTitle, setDetailsTitle] = useState('');
  const [detailsData, setDetailsData] = useState(null);
  const [detailsFields, setDetailsFields] = useState([]);

  const [forceAnalyzing, setForceAnalyzing] = useState(false);
  const [diagnostics, setDiagnostics] = useState(null);

  useEffect(() => {
    loadData();
    loadDiagnostics();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [anomaliesRes, profilesRes, predictionsRes, modelsRes, riskRes, metricsRes] = await Promise.all([
        advancedAnalyticsAPI.listAnomalies(),
        advancedAnalyticsAPI.listBehavioralProfiles(),
        advancedAnalyticsAPI.listPredictions(),
        advancedAnalyticsAPI.listModels(),
        advancedAnalyticsAPI.listRiskAssessments(),
        advancedAnalyticsAPI.getMetrics(),
      ]);

      // Handle different response formats (OpenSearch vs mock)
      setAnomalies(anomaliesRes.data.anomalies || anomaliesRes.data.data || []);
      setProfiles(profilesRes.data.profiles || profilesRes.data.data || []);
      setPredictions(predictionsRes.data.predictions || predictionsRes.data.data || []);
      setModels(modelsRes.data.data || modelsRes.data.models || []);
      setRiskAssessments(riskRes.data.data || riskRes.data.assessments || []);
      setMetrics(metricsRes.data.data || metricsRes.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load analytics data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadDiagnostics = async () => {
    try {
      const res = await advancedAnalyticsAPI.getDiagnostics();
      setDiagnostics(res.data);
    } catch (err) {
      console.error('Failed to load diagnostics:', err);
    }
  };

  const handleForceAnalysis = async () => {
    setForceAnalyzing(true);
    try {
      await advancedAnalyticsAPI.forceAnalysis();
      // Wait a bit and reload data
      setTimeout(() => {
        loadData();
        loadDiagnostics();
        setForceAnalyzing(false);
      }, 2000);
    } catch (err) {
      console.error('Failed to force analysis:', err);
      setForceAnalyzing(false);
    }
  };

  const [cleaning, setCleaning] = useState(false);
  const [cleanupResult, setCleanupResult] = useState(null);

  const handleCleanupDuplicates = async () => {
    setCleaning(true);
    setCleanupResult(null);
    try {
      const res = await advancedAnalyticsAPI.cleanupDuplicates();
      setCleanupResult(res.data);
      // Reload data after cleanup
      setTimeout(() => {
        loadData();
        loadDiagnostics();
        setCleaning(false);
      }, 1000);
    } catch (err) {
      console.error('Failed to cleanup duplicates:', err);
      setCleanupResult({ success: false, message: 'Erro ao limpar duplicatas' });
      setCleaning(false);
    }
  };

  const handleViewAnomaly = (anomaly) => {
    // Enhance data with formatted values
    const enhancedData = {
      ...anomaly,
      confidence_display: `${anomaly.confidence?.toFixed(1) || 0}%`,
      score_display: `${anomaly.anomaly_score?.toFixed(1) || 0}/100`,
      deviation_display: `${anomaly.deviation?.toFixed(1) || 0}%`,
      comparison: `Baseline: ${anomaly.baseline?.toFixed(0) || 0} → Atual: ${anomaly.current_value?.toFixed(0) || 0}`,
      mitre_link: anomaly.mitre_technique ? `https://attack.mitre.org/techniques/${anomaly.mitre_technique}` : null,
    };
    
    setDetailsData(enhancedData);
    setDetailsTitle(`🚨 Anomalia Detectada: ${anomaly.entity_name}`);
    setDetailsFields([
      { label: '📋 Identificação', type: 'header' },
      { label: 'ID da Anomalia', key: 'id', type: 'code' },
      { label: 'Data/Hora', key: 'timestamp', type: 'date' },
      { label: 'Status', key: 'status', type: 'badge' },
      
      { label: '🎯 Entidade Afetada', type: 'header' },
      { label: 'Nome', key: 'entity_name', type: 'text' },
      { label: 'ID', key: 'entity_id', type: 'code' },
      { label: 'Tipo', key: 'entity_type', type: 'badge' },
      
      { label: '⚠️ Classificação', type: 'header' },
      { label: 'Tipo de Anomalia', key: 'anomaly_type', type: 'badge' },
      { label: 'Severidade', key: 'severity', type: 'badge' },
      { label: 'Método de Detecção', key: 'detection_method', type: 'text' },
      
      { label: '📊 Métricas', type: 'header' },
      { label: 'Confiança', key: 'confidence_display', type: 'highlight' },
      { label: 'Score de Anomalia', key: 'score_display', type: 'highlight' },
      { label: 'Desvio', key: 'deviation_display', type: 'text' },
      { label: 'Comparação', key: 'comparison', type: 'text' },
      { label: 'Eventos Relacionados', key: 'related_events', type: 'number' },
      
      { label: '📝 Descrição', type: 'header' },
      { label: 'Detalhes', key: 'description', type: 'text', fullWidth: true },
      
      { label: '🔍 Indicadores', type: 'header' },
      { label: 'Indicadores Detectados', key: 'indicators', type: 'array' },
      
      { label: '🛡️ MITRE ATT&CK', type: 'header' },
      { label: 'Técnica', key: 'mitre_technique', type: 'text' },
      
      { label: '👤 Atribuição', type: 'header' },
      { label: 'Atribuído a', key: 'assigned_to', type: 'text' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewPrediction = (prediction) => {
    // Enhance data with formatted values
    const enhancedData = {
      ...prediction,
      probability_display: `${prediction.probability?.toFixed(1) || 0}%`,
      confidence_display: `${prediction.confidence?.toFixed(1) || 0}%`,
      time_window_display: prediction.time_window?.replace(/_/g, ' ').replace('next', 'Próximas') || prediction.time_window,
      status_display: prediction.status === 'active' ? '🟢 Ativa' : '⚪ Expirada',
    };
    
    setDetailsData(enhancedData);
    setDetailsTitle(`🔮 Predição de Ameaça: ${prediction.target_name}`);
    setDetailsFields([
      { label: '📋 Identificação', type: 'header' },
      { label: 'ID da Predição', key: 'id', type: 'code' },
      { label: 'Tipo de Predição', key: 'prediction_type', type: 'badge' },
      { label: 'Status', key: 'status_display', type: 'text' },
      
      { label: '🎯 Alvo', type: 'header' },
      { label: 'Nome do Alvo', key: 'target_name', type: 'text' },
      { label: 'Tipo do Alvo', key: 'target_type', type: 'badge' },
      { label: 'ID do Alvo', key: 'target_id', type: 'code' },
      
      { label: '📊 Métricas de Risco', type: 'header' },
      { label: 'Probabilidade', key: 'probability_display', type: 'highlight' },
      { label: 'Confiança', key: 'confidence_display', type: 'highlight' },
      { label: 'Severidade', key: 'severity', type: 'badge' },
      { label: 'Janela de Tempo', key: 'time_window_display', type: 'text' },
      
      { label: '🔍 Indicadores Detectados', type: 'header' },
      { label: 'Indicadores', key: 'indicators', type: 'array' },
      
      { label: '🛡️ MITRE ATT&CK', type: 'header' },
      { label: 'Técnicas Associadas', key: 'mitre_techniques', type: 'array' },
      
      { label: '✅ Recomendações', type: 'header' },
      { label: 'Ações Recomendadas', key: 'recommendations', type: 'array' },
      
      { label: '📅 Validade', type: 'header' },
      { label: 'Criada em', key: 'created_at', type: 'date' },
      { label: 'Expira em', key: 'expires_at', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewModel = (model) => {
    setDetailsData(model);
    setDetailsTitle(`ML Model: ${model.name}`);
    setDetailsFields([
      { label: 'Model ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Algorithm', key: 'algorithm', type: 'text' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Version', key: 'version', type: 'text' },
      { label: 'Accuracy (%)', key: 'accuracy', type: 'text' },
      { label: 'Precision (%)', key: 'precision', type: 'text' },
      { label: 'Recall (%)', key: 'recall', type: 'text' },
      { label: 'F1 Score (%)', key: 'f1_score', type: 'text' },
      { label: 'Training Data Samples', key: 'training_data', type: 'text' },
      { label: 'Last Trained', key: 'last_trained', type: 'date' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Features', key: 'features', type: 'array' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewProfile = (profile) => {
    setDetailsData(profile);
    setDetailsTitle(`Behavioral Profile: ${profile.entity_name}`);
    setDetailsFields([
      { label: 'Entity Type', key: 'entity_type', type: 'badge' },
      { label: 'Entity ID', key: 'entity_id', type: 'text' },
      { label: 'Entity Name', key: 'entity_name', type: 'text' },
      { label: 'Risk Score', key: 'risk_score', type: 'text' },
      { label: 'Total Events', key: 'total_events', type: 'text' },
      { label: 'Anomalies Detected', key: 'anomalies', type: 'text' },
      { label: 'Profile Created', key: 'profile_created', type: 'date' },
      { label: 'Last Updated', key: 'last_updated', type: 'date' },
      { label: 'Last Anomaly', key: 'last_anomaly', type: 'date' },
      { label: 'Patterns', key: 'patterns', type: 'array' },
      { label: 'Normal Behavior', key: 'normal_behavior', type: 'json', fullWidth: true },
    ]);
    setDetailsOpen(true);
  };

  const handleViewRiskAssessment = (assessment) => {
    // Enhance data with formatted details
    const enhancedData = {
      ...assessment,
      risk_score_display: `${assessment.risk_score?.toFixed(1) || 0}/100`,
      vulnerability_breakdown: assessment.details ? 
        `Críticas: ${assessment.details.critical_vulns || 0}, Altas: ${assessment.details.high_vulns || 0}, Médias: ${assessment.details.medium_vulns || 0}` : 
        `Total: ${assessment.vulnerabilities || 0}`,
    };
    
    setDetailsData(enhancedData);
    setDetailsTitle(`🎯 Avaliação de Risco: ${assessment.entity_name}`);
    setDetailsFields([
      { label: '📋 Identificação', type: 'header' },
      { label: 'Nome da Entidade', key: 'entity_name', type: 'text' },
      { label: 'ID da Entidade', key: 'entity_id', type: 'code' },
      { label: 'Tipo', key: 'entity_type', type: 'badge' },
      
      { label: '⚠️ Avaliação de Risco', type: 'header' },
      { label: 'Score de Risco', key: 'risk_score_display', type: 'highlight' },
      { label: 'Nível de Risco', key: 'risk_level', type: 'badge' },
      { label: 'Tendência', key: 'trend', type: 'badge' },
      
      { label: '📊 Métricas de Segurança', type: 'header' },
      { label: 'Vulnerabilidades', key: 'vulnerability_breakdown', type: 'text' },
      { label: 'Ameaças/Alertas', key: 'threats', type: 'number' },
      { label: 'Anomalias Detectadas', key: 'anomalies', type: 'number' },
      
      { label: '🔍 Fatores de Risco', type: 'header' },
      { label: 'Fatores Identificados', key: 'risk_factors', type: 'array' },
      
      { label: '🛡️ Ações de Mitigação Recomendadas', type: 'header' },
      { label: 'Ações', key: 'mitigation_actions', type: 'array' },
      
      { label: '📅 Histórico', type: 'header' },
      { label: 'Última Avaliação', key: 'last_assessment', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const getSeverityColor = (severity) => {
    const colors = { critical: 'error', high: 'error', medium: 'warning', low: 'info' };
    return colors[severity] || 'default';
  };

  const getStatusColor = (status) => {
    const colors = { new: 'warning', investigating: 'info', resolved: 'success', false_positive: 'default' };
    return colors[status] || 'default';
  };

  const getRiskColor = (level) => {
    const colors = { critical: 'error', high: 'error', medium: 'warning', low: 'success' };
    return colors[level] || 'default';
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      {/* Header with Actions */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <PsychologyIcon sx={{ fontSize: 40, color: 'primary.main' }} />
          <Box>
            <Typography variant="h4">
              Advanced Analytics & ML
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Detecção de anomalias e predições de ameaças baseadas em Machine Learning
            </Typography>
          </Box>
        </Box>
        
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => { loadData(); loadDiagnostics(); }}
            disabled={loading}
          >
            Atualizar
          </Button>
          <Button
            variant="contained"
            color="primary"
            startIcon={forceAnalyzing ? <CircularProgress size={20} color="inherit" /> : <PlayIcon />}
            onClick={handleForceAnalysis}
            disabled={forceAnalyzing}
          >
            {forceAnalyzing ? 'Analisando...' : 'Forçar Análise'}
          </Button>
          <Button
            variant="outlined"
            color="warning"
            startIcon={cleaning ? <CircularProgress size={20} color="inherit" /> : <CleanIcon />}
            onClick={handleCleanupDuplicates}
            disabled={cleaning}
          >
            {cleaning ? 'Limpando...' : 'Limpar Duplicatas'}
          </Button>
        </Box>
      </Box>

      {/* Cleanup Result */}
      {cleanupResult && (
        <Alert 
          severity={cleanupResult.success ? "success" : "error"} 
          sx={{ mb: 2 }}
          onClose={() => setCleanupResult(null)}
        >
          {cleanupResult.message}
          {cleanupResult.deleted > 0 && (
            <Typography variant="body2" sx={{ mt: 1 }}>
              Mantidas: {cleanupResult.kept} | Removidas: {cleanupResult.deleted}
            </Typography>
          )}
        </Alert>
      )}

      {/* Diagnostics Info */}
      {diagnostics && (
        <Alert 
          severity={diagnostics.opensearch_connected ? "info" : "warning"} 
          sx={{ mb: 3 }}
          icon={<StorageIcon />}
        >
          <AlertTitle>Status do ML Analytics</AlertTitle>
          <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
            <Chip 
              label={diagnostics.opensearch_connected ? "OpenSearch Conectado" : "OpenSearch Desconectado"} 
              color={diagnostics.opensearch_connected ? "success" : "error"}
              size="small"
            />
            <Typography variant="body2">
              <strong>Anomalias detectadas:</strong> {diagnostics.anomalies_count || 0}
            </Typography>
            <Typography variant="body2">
              <strong>Predições ativas:</strong> {diagnostics.predictions_count || 0}
            </Typography>
            <Typography variant="body2">
              <strong>Eventos (24h):</strong> {diagnostics.events_last_24h || 0}
            </Typography>
          </Box>
        </Alert>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Metrics Cards */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Detection Rate</Typography>
                  <Typography variant="h4">{metrics.detection_rate?.toFixed(1) || 0}%</Typography>
                  <LinearProgress variant="determinate" value={metrics.detection_rate || 0} sx={{ mt: 1 }} color="success" />
                </Box>
                <CheckCircleIcon sx={{ fontSize: 48, color: 'success.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Model Accuracy</Typography>
                  <Typography variant="h4">{metrics.model_accuracy?.toFixed(1) || 0}%</Typography>
                  <LinearProgress variant="determinate" value={metrics.model_accuracy || 0} sx={{ mt: 1 }} color="info" />
                </Box>
                <PsychologyIcon sx={{ fontSize: 48, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>New Anomalies</Typography>
                  <Typography variant="h4">{metrics.new_anomalies || 0}</Typography>
                  <Typography variant="caption" color="textSecondary">
                    {metrics.high_severity || 0} High Severity
                  </Typography>
                </Box>
                <WarningIcon sx={{ fontSize: 48, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Threats Prevented</Typography>
                  <Typography variant="h4">{metrics.threats_prevented || 0}</Typography>
                  <Typography variant="caption" color="success.main">
                    {metrics.predictions_today || 0} Predictions Today
                  </Typography>
                </Box>
                <TrendingUpIcon sx={{ fontSize: 48, color: 'primary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label="Anomaly Detection" />
          <Tab label="Threat Predictions" />
          <Tab label="ML Models" />
          <Tab label="Risk Assessments" />
          <Tab label="Behavioral Profiles" />
        </Tabs>
      </Paper>

      {/* Tab 0: Anomaly Detection */}
      {activeTab === 0 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Anomaly Detection</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>Entity</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Confidence</TableCell>
                    <TableCell>Score</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {anomalies.map((anomaly) => (
                    <TableRow key={anomaly.id} hover>
                      <TableCell>{new Date(anomaly.timestamp).toLocaleString()}</TableCell>
                      <TableCell>
                        <strong>{anomaly.entity_name}</strong>
                        <br />
                        <Typography variant="caption" color="textSecondary">{anomaly.entity_type}</Typography>
                      </TableCell>
                      <TableCell><Chip label={anomaly.anomaly_type} size="small" color="primary" /></TableCell>
                      <TableCell><Chip label={anomaly.severity} color={getSeverityColor(anomaly.severity)} size="small" /></TableCell>
                      <TableCell>{anomaly.confidence.toFixed(1)}%</TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>{anomaly.anomaly_score.toFixed(1)}</Typography>
                          <LinearProgress variant="determinate" value={anomaly.anomaly_score} sx={{ width: 60 }} color={anomaly.anomaly_score > 80 ? 'error' : 'warning'} />
                        </Box>
                      </TableCell>
                      <TableCell><Chip label={anomaly.status} color={getStatusColor(anomaly.status)} size="small" /></TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewAnomaly(anomaly)}>
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        </Paper>
      )}

      {/* Tab 1: Threat Predictions */}
      {activeTab === 1 && (
        <Grid container spacing={3}>
          {predictions.map((prediction) => (
            <Grid item xs={12} md={6} key={prediction.id}>
              <Card>
                <CardContent>
                  <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
                    <Box>
                      <Typography variant="h6">{prediction.target_name}</Typography>
                      <Box mt={1}>
                        <Chip label={prediction.prediction_type} size="small" color="primary" sx={{ mr: 1 }} />
                        <Chip label={prediction.severity} size="small" color={getSeverityColor(prediction.severity)} />
                      </Box>
                    </Box>
                    <Tooltip title="View Details">
                      <IconButton size="small" onClick={() => handleViewPrediction(prediction)}>
                        <VisibilityIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>

                  <Grid container spacing={2} sx={{ mt: 1 }}>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Probability</Typography>
                      <Typography variant="h6">{prediction.probability.toFixed(1)}%</Typography>
                      <LinearProgress variant="determinate" value={prediction.probability} sx={{ mt: 0.5 }} color="error" />
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Confidence</Typography>
                      <Typography variant="h6">{prediction.confidence.toFixed(1)}%</Typography>
                      <LinearProgress variant="determinate" value={prediction.confidence} sx={{ mt: 0.5 }} color="info" />
                    </Grid>
                  </Grid>

                  <Box mt={2}>
                    <Typography variant="caption" color="textSecondary">Time Window:</Typography>
                    <Typography variant="body2">{prediction.time_window.replace(/_/g, ' ')}</Typography>
                  </Box>

                  <Box mt={1}>
                    <Typography variant="caption" color="textSecondary">MITRE Techniques:</Typography>
                    <Box mt={0.5}>
                      {prediction.mitre_techniques.map((tech) => (
                        <Chip key={tech} label={tech} size="small" variant="outlined" sx={{ mr: 0.5, mb: 0.5 }} />
                      ))}
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Tab 2: ML Models */}
      {activeTab === 2 && (
        <Grid container spacing={3}>
          {models.map((model) => (
            <Grid item xs={12} md={6} key={model.id}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                    <Box display="flex" alignItems="center">
                      <PsychologyIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
                      <Box>
                        <Typography variant="h6">{model.name}</Typography>
                        <Typography variant="caption" color="textSecondary">
                          {model.algorithm} • v{model.version}
                        </Typography>
                      </Box>
                    </Box>
                    <Tooltip title="View Details">
                      <IconButton size="small" onClick={() => handleViewModel(model)}>
                        <VisibilityIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>

                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Accuracy</Typography>
                      <Typography variant="body2"><strong>{model.accuracy.toFixed(1)}%</strong></Typography>
                      <LinearProgress variant="determinate" value={model.accuracy} sx={{ mt: 0.5 }} color="success" />
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">F1 Score</Typography>
                      <Typography variant="body2"><strong>{model.f1_score.toFixed(1)}%</strong></Typography>
                      <LinearProgress variant="determinate" value={model.f1_score} sx={{ mt: 0.5 }} color="info" />
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Precision</Typography>
                      <Typography variant="body2">{model.precision.toFixed(1)}%</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Recall</Typography>
                      <Typography variant="body2">{model.recall.toFixed(1)}%</Typography>
                    </Grid>
                  </Grid>

                  <Box mt={2}>
                    <Chip label={model.status} color={model.status === 'active' ? 'success' : 'default'} size="small" sx={{ mr: 1 }} />
                    <Chip label={`${model.training_data.toLocaleString()} samples`} size="small" variant="outlined" />
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Tab 3: Risk Assessments */}
      {activeTab === 3 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Risk Assessments</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Entity</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Risk Score</TableCell>
                    <TableCell>Risk Level</TableCell>
                    <TableCell>Vulnerabilities</TableCell>
                    <TableCell>Threats</TableCell>
                    <TableCell>Anomalies</TableCell>
                    <TableCell>Trend</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {riskAssessments.map((assessment, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell><strong>{assessment.entity_name}</strong></TableCell>
                      <TableCell><Chip label={assessment.entity_type} size="small" /></TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>{assessment.risk_score.toFixed(1)}</Typography>
                          <LinearProgress variant="determinate" value={assessment.risk_score} sx={{ width: 80 }} color={assessment.risk_score > 70 ? 'error' : 'warning'} />
                        </Box>
                      </TableCell>
                      <TableCell><Chip label={assessment.risk_level} color={getRiskColor(assessment.risk_level)} size="small" /></TableCell>
                      <TableCell>{assessment.vulnerabilities}</TableCell>
                      <TableCell>{assessment.threats}</TableCell>
                      <TableCell>{assessment.anomalies}</TableCell>
                      <TableCell>
                        <Chip 
                          label={assessment.trend} 
                          size="small" 
                          color={assessment.trend === 'decreasing' ? 'success' : assessment.trend === 'increasing' ? 'error' : 'default'}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewRiskAssessment(assessment)}>
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        </Paper>
      )}

      {/* Tab 4: Behavioral Profiles */}
      {activeTab === 4 && (
        <Grid container spacing={3}>
          {profiles.map((profile, idx) => (
            <Grid item xs={12} md={6} key={idx}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between" mb={1}>
                    <Box>
                      <Typography variant="h6">{profile.entity_name}</Typography>
                      <Chip label={profile.entity_type} size="small" color="primary" sx={{ mt: 0.5 }} />
                    </Box>
                    <Tooltip title="View Details">
                      <IconButton size="small" onClick={() => handleViewProfile(profile)}>
                        <VisibilityIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>

                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Risk Score</Typography>
                      <Typography variant="h6">{profile.risk_score.toFixed(1)}</Typography>
                      <LinearProgress variant="determinate" value={profile.risk_score} sx={{ mt: 0.5 }} color={profile.risk_score > 70 ? 'error' : 'warning'} />
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Total Events</Typography>
                      <Typography variant="h6">{profile.total_events.toLocaleString()}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Anomalies</Typography>
                      <Typography variant="body2">{profile.anomalies}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Last Updated</Typography>
                      <Typography variant="body2">{new Date(profile.last_updated).toLocaleDateString()}</Typography>
                    </Grid>
                  </Grid>

                  <Box mt={2}>
                    <Typography variant="caption" color="textSecondary">Patterns:</Typography>
                    <Box mt={0.5}>
                      {profile.patterns.map((pattern, i) => (
                        <Chip key={i} label={pattern} size="small" variant="outlined" sx={{ mr: 0.5, mb: 0.5 }} />
                      ))}
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Details Dialog */}
      <DetailsDialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        title={detailsTitle}
        data={detailsData}
        fields={detailsFields}
      />
    </Box>
  );
};

export default AdvancedAnalytics;

