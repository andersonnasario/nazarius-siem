import React, { useState, useEffect } from 'react';
import {
  Box, Container, Grid, Card, CardContent, Typography, Tab, Tabs, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Paper, Chip, IconButton, Button, Dialog, DialogTitle,
  DialogContent, DialogActions, TextField, Alert, LinearProgress, Tooltip, MenuItem, Select,
  FormControl, InputLabel, List, ListItem, ListItemText, ListItemIcon, Divider,
} from '@mui/material';
import {
  TrendingUp as TrendingUpIcon, Warning as WarningIcon, CheckCircle as CheckCircleIcon,
  Error as ErrorIcon, Psychology as PsychologyIcon, ShowChart as ShowChartIcon,
  Science as ScienceIcon, Memory as MemoryIcon, Timeline as TimelineIcon,
  Visibility as VisibilityIcon, PlayArrow as PlayArrowIcon, Stop as StopIcon,
  CloudUpload as CloudUploadIcon, Assessment as AssessmentIcon, Delete as DeleteIcon,
  Refresh as RefreshIcon, Close as CloseIcon, GetApp as GetAppIcon,
  TrendingDown as TrendingDownIcon, Star as StarIcon,
} from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer, ScatterChart, Scatter } from 'recharts';
import { mlAnalyticsAPI } from '../services/api';

const COLORS = ['#1976d2', '#dc004e', '#f57c00', '#388e3c', '#9c27b0', '#00bcd4', '#ff9800'];
const SEVERITY_COLORS = { critical: '#d32f2f', high: '#f57c00', medium: '#fbc02d', low: '#388e3c' };
const STATUS_COLORS = { 
  training: '#1976d2', 
  deployed: '#388e3c', 
  failed: '#d32f2f', 
  pending: '#f57c00',
  investigating: '#1976d2',
  confirmed: '#d32f2f',
  false_positive: '#757575',
  resolved: '#388e3c',
};
const MODEL_TYPES = {
  anomaly_detection: 'Anomaly Detection',
  threat_classification: 'Threat Classification',
  risk_prediction: 'Risk Prediction',
  behavioral_analysis: 'Behavioral Analysis',
  pattern_recognition: 'Pattern Recognition',
};

function MLAnalytics() {
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(0);
  const [dashboard, setDashboard] = useState(null);
  const [models, setModels] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [predictions, setPredictions] = useState([]);
  const [riskPredictions, setRiskPredictions] = useState([]);
  const [trainingJobs, setTrainingJobs] = useState([]);
  
  const [selectedModel, setSelectedModel] = useState(null);
  const [selectedAnomaly, setSelectedAnomaly] = useState(null);
  const [modelDialogOpen, setModelDialogOpen] = useState(false);
  const [anomalyDialogOpen, setAnomalyDialogOpen] = useState(false);
  const [trainDialogOpen, setTrainDialogOpen] = useState(false);
  const [metricsDialogOpen, setMetricsDialogOpen] = useState(false);
  
  const [filters, setFilters] = useState({ 
    modelType: '', 
    modelStatus: '', 
    anomalySeverity: '', 
    anomalyStatus: '' 
  });

  useEffect(() => {
    loadDashboard();
    loadModels();
    loadAnomalies();
    loadPredictions();
    loadRiskPredictions();
    loadTrainingJobs();
  }, []);

  const loadDashboard = async () => {
    try {
      setLoading(true);
      const data = await mlAnalyticsAPI.getDashboard();
      setDashboard(data);
    } catch (error) {
      console.error('Error loading dashboard:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadModels = async () => {
    try {
      const data = await mlAnalyticsAPI.getModels();
      setModels(data || []);
    } catch (error) {
      console.error('Error loading models:', error);
      setModels([]);
    }
  };

  const loadAnomalies = async () => {
    try {
      const params = {};
      if (filters.anomalySeverity) params.severity = filters.anomalySeverity;
      if (filters.anomalyStatus) params.status = filters.anomalyStatus;
      const data = await mlAnalyticsAPI.getAnomalies(params);
      setAnomalies(data || []);
    } catch (error) {
      console.error('Error loading anomalies:', error);
      setAnomalies([]);
    }
  };

  const loadPredictions = async () => {
    try {
      const data = await mlAnalyticsAPI.getPredictions({});
      setPredictions(data || []);
    } catch (error) {
      console.error('Error loading predictions:', error);
      setPredictions([]);
    }
  };

  const loadRiskPredictions = async () => {
    try {
      const data = await mlAnalyticsAPI.getRiskPredictions();
      setRiskPredictions(data || []);
    } catch (error) {
      console.error('Error loading risk predictions:', error);
      setRiskPredictions([]);
    }
  };

  const loadTrainingJobs = async () => {
    try {
      const data = await mlAnalyticsAPI.getTrainingJobs();
      setTrainingJobs(data || []);
    } catch (error) {
      console.error('Error loading training jobs:', error);
      setTrainingJobs([]);
    }
  };

  const handleViewModel = async (model) => {
    try {
      const fullModel = await mlAnalyticsAPI.getModel(model.id);
      setSelectedModel(fullModel);
      setModelDialogOpen(true);
    } catch (error) {
      console.error('Error loading model details:', error);
    }
  };

  const handleViewAnomaly = async (anomaly) => {
    try {
      const fullAnomaly = await mlAnalyticsAPI.getAnomaly(anomaly.id);
      setSelectedAnomaly(fullAnomaly);
      setAnomalyDialogOpen(true);
    } catch (error) {
      console.error('Error loading anomaly details:', error);
    }
  };

  const handleTrainModel = async (modelId, config) => {
    try {
      await mlAnalyticsAPI.trainModel(modelId, config);
      loadModels();
      loadTrainingJobs();
      setTrainDialogOpen(false);
      alert('Model training started successfully!');
    } catch (error) {
      console.error('Error training model:', error);
      alert('Failed to start model training');
    }
  };

  const handleDeployModel = async (modelId) => {
    try {
      await mlAnalyticsAPI.deployModel(modelId);
      loadModels();
      alert('Model deployed successfully!');
    } catch (error) {
      console.error('Error deploying model:', error);
      alert('Failed to deploy model');
    }
  };

  const handleUpdateAnomalyStatus = async (anomalyId, status, notes) => {
    try {
      await mlAnalyticsAPI.updateAnomalyStatus(anomalyId, status, notes);
      loadAnomalies();
      setAnomalyDialogOpen(false);
      alert('Anomaly status updated successfully!');
    } catch (error) {
      console.error('Error updating anomaly status:', error);
      alert('Failed to update anomaly status');
    }
  };

  const handleViewMetrics = async (model) => {
    try {
      const metrics = await mlAnalyticsAPI.getModelMetrics(model.id);
      const featureImportance = await mlAnalyticsAPI.getFeatureImportance(model.id);
      setSelectedModel({ ...model, metrics, featureImportance });
      setMetricsDialogOpen(true);
    } catch (error) {
      console.error('Error loading model metrics:', error);
    }
  };

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
  };

  const handleFilterChange = (filterName, value) => {
    setFilters(prev => ({ ...prev, [filterName]: value }));
  };

  useEffect(() => {
    if (activeTab === 1) loadModels();
    if (activeTab === 2) loadAnomalies();
    if (activeTab === 3) loadPredictions();
  }, [filters]);

  if (loading) {
    return (
      <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
        <LinearProgress />
        <Typography variant="h6" sx={{ mt: 2, textAlign: 'center' }}>
          Loading ML Analytics Dashboard...
        </Typography>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          <PsychologyIcon sx={{ mr: 1, verticalAlign: 'middle', fontSize: 40 }} />
          Advanced ML Analytics
        </Typography>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={() => {
            loadDashboard();
            loadModels();
            loadAnomalies();
            loadPredictions();
          }}
        >
          Refresh
        </Button>
      </Box>

      {/* KPI Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Active Models
                  </Typography>
                  <Typography variant="h4">
                    {dashboard?.total_models || 0}
                  </Typography>
                  <Typography variant="body2" color="success.main">
                    {dashboard?.deployed_models || 0} deployed
                  </Typography>
                </Box>
                <MemoryIcon sx={{ fontSize: 48, color: '#1976d2', opacity: 0.7 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Anomalies Detected
                  </Typography>
                  <Typography variant="h4">
                    {dashboard?.anomalies_detected || 0}
                  </Typography>
                  <Typography variant="body2" color="warning.main">
                    {dashboard?.anomalies_last_24h || 0} last 24h
                  </Typography>
                </Box>
                <WarningIcon sx={{ fontSize: 48, color: '#f57c00', opacity: 0.7 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Avg Model Accuracy
                  </Typography>
                  <Typography variant="h4">
                    {dashboard?.avg_accuracy ? `${(dashboard.avg_accuracy * 100).toFixed(1)}%` : 'N/A'}
                  </Typography>
                  <Typography variant="body2" color="success.main">
                    {dashboard?.models_above_90 || 0} above 90%
                  </Typography>
                </Box>
                <TrendingUpIcon sx={{ fontSize: 48, color: '#388e3c', opacity: 0.7 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Predictions Made
                  </Typography>
                  <Typography variant="h4">
                    {dashboard?.predictions_made || 0}
                  </Typography>
                  <Typography variant="body2" color="info.main">
                    {dashboard?.predictions_today || 0} today
                  </Typography>
                </Box>
                <ShowChartIcon sx={{ fontSize: 48, color: '#9c27b0', opacity: 0.7 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={handleTabChange} variant="fullWidth">
          <Tab label="Overview" icon={<AssessmentIcon />} iconPosition="start" />
          <Tab label="ML Models" icon={<MemoryIcon />} iconPosition="start" />
          <Tab label="Anomalies" icon={<WarningIcon />} iconPosition="start" />
          <Tab label="Predictions" icon={<ShowChartIcon />} iconPosition="start" />
          <Tab label="Training" icon={<ScienceIcon />} iconPosition="start" />
        </Tabs>
      </Paper>

      {/* Tab 0: Overview */}
      {activeTab === 0 && (
        <Grid container spacing={3}>
          {/* Model Performance Chart */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Model Performance Trends
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={dashboard?.performance_trend || []}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <RechartsTooltip />
                    <Legend />
                    <Line type="monotone" dataKey="accuracy" stroke="#1976d2" name="Accuracy" />
                    <Line type="monotone" dataKey="precision" stroke="#388e3c" name="Precision" />
                    <Line type="monotone" dataKey="recall" stroke="#f57c00" name="Recall" />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>

          {/* Anomaly Detection Chart */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Anomalies by Severity
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={dashboard?.anomalies_by_severity || []}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, value }) => `${name}: ${value}`}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="count"
                    >
                      {(dashboard?.anomalies_by_severity || []).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>

          {/* Model Types Distribution */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Model Types Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={dashboard?.model_types || []}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="type" />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="count" fill="#1976d2" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>

          {/* Recent High-Risk Predictions */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Recent High-Risk Predictions
                </Typography>
                <List>
                  {(riskPredictions.slice(0, 5) || []).map((pred, index) => (
                    <React.Fragment key={pred.id || index}>
                      <ListItem>
                        <ListItemIcon>
                          <ErrorIcon color="error" />
                        </ListItemIcon>
                        <ListItemText
                          primary={pred.entity || `Entity ${pred.entity_id}`}
                          secondary={`Risk Score: ${pred.risk_score?.toFixed(2) || 'N/A'} | ${pred.prediction_time || 'Unknown time'}`}
                        />
                        <Chip
                          label={pred.risk_level || 'unknown'}
                          color={pred.risk_level === 'critical' ? 'error' : 'warning'}
                          size="small"
                        />
                      </ListItem>
                      {index < 4 && <Divider />}
                    </React.Fragment>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tab 1: ML Models */}
      {activeTab === 1 && (
        <Grid container spacing={3}>
          {/* Filters */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <FormControl fullWidth size="small">
                      <InputLabel>Model Type</InputLabel>
                      <Select
                        value={filters.modelType}
                        onChange={(e) => handleFilterChange('modelType', e.target.value)}
                        label="Model Type"
                      >
                        <MenuItem value="">All Types</MenuItem>
                        {Object.entries(MODEL_TYPES).map(([key, value]) => (
                          <MenuItem key={key} value={key}>{value}</MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <FormControl fullWidth size="small">
                      <InputLabel>Status</InputLabel>
                      <Select
                        value={filters.modelStatus}
                        onChange={(e) => handleFilterChange('modelStatus', e.target.value)}
                        label="Status"
                      >
                        <MenuItem value="">All Statuses</MenuItem>
                        <MenuItem value="training">Training</MenuItem>
                        <MenuItem value="deployed">Deployed</MenuItem>
                        <MenuItem value="failed">Failed</MenuItem>
                        <MenuItem value="pending">Pending</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Button
                      variant="contained"
                      fullWidth
                      startIcon={<CloudUploadIcon />}
                      onClick={() => alert('Create model feature coming soon!')}
                    >
                      Create New Model
                    </Button>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          {/* Models Table */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  ML Models ({models.length})
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Model Name</TableCell>
                        <TableCell>Type</TableCell>
                        <TableCell>Version</TableCell>
                        <TableCell>Accuracy</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Last Trained</TableCell>
                        <TableCell align="center">Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {models
                        .filter(m => !filters.modelType || m.model_type === filters.modelType)
                        .filter(m => !filters.modelStatus || m.status === filters.modelStatus)
                        .map((model) => (
                          <TableRow key={model.id} hover>
                            <TableCell>
                              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <MemoryIcon sx={{ mr: 1, color: '#1976d2' }} />
                                {model.name}
                              </Box>
                            </TableCell>
                            <TableCell>{MODEL_TYPES[model.model_type] || model.model_type}</TableCell>
                            <TableCell>v{model.version || '1.0'}</TableCell>
                            <TableCell>
                              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                {model.accuracy ? (
                                  <>
                                    <LinearProgress
                                      variant="determinate"
                                      value={model.accuracy * 100}
                                      sx={{ width: 60, mr: 1 }}
                                    />
                                    {(model.accuracy * 100).toFixed(1)}%
                                  </>
                                ) : (
                                  'N/A'
                                )}
                              </Box>
                            </TableCell>
                            <TableCell>
                              <Chip
                                label={model.status}
                                color={
                                  model.status === 'deployed' ? 'success' :
                                  model.status === 'training' ? 'info' :
                                  model.status === 'failed' ? 'error' : 'default'
                                }
                                size="small"
                              />
                            </TableCell>
                            <TableCell>{new Date(model.last_trained).toLocaleDateString()}</TableCell>
                            <TableCell align="center">
                              <Tooltip title="View Details">
                                <IconButton size="small" onClick={() => handleViewModel(model)}>
                                  <VisibilityIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="View Metrics">
                                <IconButton size="small" onClick={() => handleViewMetrics(model)}>
                                  <AssessmentIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                              {model.status !== 'deployed' && (
                                <Tooltip title="Deploy Model">
                                  <IconButton size="small" onClick={() => handleDeployModel(model.id)}>
                                    <PlayArrowIcon fontSize="small" color="success" />
                                  </IconButton>
                                </Tooltip>
                              )}
                              <Tooltip title="Retrain">
                                <IconButton 
                                  size="small" 
                                  onClick={() => {
                                    setSelectedModel(model);
                                    setTrainDialogOpen(true);
                                  }}
                                >
                                  <ScienceIcon fontSize="small" color="primary" />
                                </IconButton>
                              </Tooltip>
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
      )}

      {/* Tab 2: Anomalies */}
      {activeTab === 2 && (
        <Grid container spacing={3}>
          {/* Filters */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth size="small">
                      <InputLabel>Severity</InputLabel>
                      <Select
                        value={filters.anomalySeverity}
                        onChange={(e) => handleFilterChange('anomalySeverity', e.target.value)}
                        label="Severity"
                      >
                        <MenuItem value="">All Severities</MenuItem>
                        <MenuItem value="critical">Critical</MenuItem>
                        <MenuItem value="high">High</MenuItem>
                        <MenuItem value="medium">Medium</MenuItem>
                        <MenuItem value="low">Low</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth size="small">
                      <InputLabel>Status</InputLabel>
                      <Select
                        value={filters.anomalyStatus}
                        onChange={(e) => handleFilterChange('anomalyStatus', e.target.value)}
                        label="Status"
                      >
                        <MenuItem value="">All Statuses</MenuItem>
                        <MenuItem value="investigating">Investigating</MenuItem>
                        <MenuItem value="confirmed">Confirmed</MenuItem>
                        <MenuItem value="false_positive">False Positive</MenuItem>
                        <MenuItem value="resolved">Resolved</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          {/* Anomalies Table */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Detected Anomalies ({anomalies.length})
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Timestamp</TableCell>
                        <TableCell>Entity</TableCell>
                        <TableCell>Anomaly Type</TableCell>
                        <TableCell>Anomaly Score</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Model</TableCell>
                        <TableCell align="center">Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {anomalies.map((anomaly) => (
                        <TableRow key={anomaly.id} hover>
                          <TableCell>{new Date(anomaly.detected_at).toLocaleString()}</TableCell>
                          <TableCell>{anomaly.entity_id || 'N/A'}</TableCell>
                          <TableCell>{anomaly.anomaly_type || 'Unknown'}</TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              <LinearProgress
                                variant="determinate"
                                value={anomaly.anomaly_score * 100}
                                sx={{ width: 60, mr: 1 }}
                                color={anomaly.anomaly_score > 0.8 ? 'error' : anomaly.anomaly_score > 0.6 ? 'warning' : 'success'}
                              />
                              {(anomaly.anomaly_score * 100).toFixed(1)}%
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={anomaly.severity}
                              sx={{ 
                                bgcolor: SEVERITY_COLORS[anomaly.severity],
                                color: 'white',
                              }}
                              size="small"
                            />
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={anomaly.status}
                              color={
                                anomaly.status === 'resolved' ? 'success' :
                                anomaly.status === 'confirmed' ? 'error' :
                                anomaly.status === 'false_positive' ? 'default' : 'info'
                              }
                              size="small"
                            />
                          </TableCell>
                          <TableCell>{anomaly.model_name || 'Unknown'}</TableCell>
                          <TableCell align="center">
                            <Tooltip title="View Details">
                              <IconButton size="small" onClick={() => handleViewAnomaly(anomaly)}>
                                <VisibilityIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
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
      )}

      {/* Tab 3: Predictions */}
      {activeTab === 3 && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Recent Predictions
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Time</TableCell>
                        <TableCell>Entity</TableCell>
                        <TableCell>Prediction</TableCell>
                        <TableCell>Confidence</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {predictions.slice(0, 10).map((pred) => (
                        <TableRow key={pred.id} hover>
                          <TableCell>{new Date(pred.prediction_time).toLocaleString()}</TableCell>
                          <TableCell>{pred.entity_id || 'N/A'}</TableCell>
                          <TableCell>{pred.predicted_class || 'N/A'}</TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              <LinearProgress
                                variant="determinate"
                                value={pred.confidence * 100}
                                sx={{ width: 60, mr: 1 }}
                              />
                              {(pred.confidence * 100).toFixed(1)}%
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

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Risk Score Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={400}>
                  <ScatterChart>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="timestamp" name="Time" />
                    <YAxis dataKey="risk_score" name="Risk Score" />
                    <RechartsTooltip cursor={{ strokeDasharray: '3 3' }} />
                    <Scatter
                      name="Risk Predictions"
                      data={riskPredictions.map(p => ({
                        timestamp: new Date(p.prediction_time).getTime(),
                        risk_score: p.risk_score,
                      }))}
                      fill="#d32f2f"
                    />
                  </ScatterChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tab 4: Training Jobs */}
      {activeTab === 4 && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Training Jobs ({trainingJobs.length})
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Job ID</TableCell>
                        <TableCell>Model</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Progress</TableCell>
                        <TableCell>Started</TableCell>
                        <TableCell>Duration</TableCell>
                        <TableCell>Metrics</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {trainingJobs.map((job) => (
                        <TableRow key={job.id} hover>
                          <TableCell>{job.id}</TableCell>
                          <TableCell>{job.model_name || 'N/A'}</TableCell>
                          <TableCell>
                            <Chip
                              label={job.status}
                              color={
                                job.status === 'completed' ? 'success' :
                                job.status === 'failed' ? 'error' :
                                job.status === 'running' ? 'info' : 'default'
                              }
                              size="small"
                            />
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              <LinearProgress
                                variant="determinate"
                                value={job.progress * 100}
                                sx={{ width: 100, mr: 1 }}
                              />
                              {(job.progress * 100).toFixed(0)}%
                            </Box>
                          </TableCell>
                          <TableCell>{new Date(job.started_at).toLocaleString()}</TableCell>
                          <TableCell>{job.duration || 'N/A'}</TableCell>
                          <TableCell>
                            {job.final_metrics ? (
                              <Tooltip title={JSON.stringify(job.final_metrics, null, 2)}>
                                <AssessmentIcon fontSize="small" color="primary" />
                              </Tooltip>
                            ) : (
                              'N/A'
                            )}
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
      )}

      {/* Model Details Dialog */}
      <Dialog open={modelDialogOpen} onClose={() => setModelDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Model Details: {selectedModel?.name}
          <IconButton
            onClick={() => setModelDialogOpen(false)}
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent dividers>
          {selectedModel && (
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Model ID</Typography>
                <Typography variant="body1">{selectedModel.id}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Type</Typography>
                <Typography variant="body1">{MODEL_TYPES[selectedModel.model_type] || selectedModel.model_type}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Version</Typography>
                <Typography variant="body1">v{selectedModel.version || '1.0'}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Status</Typography>
                <Chip label={selectedModel.status} color={selectedModel.status === 'deployed' ? 'success' : 'default'} />
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Accuracy</Typography>
                <Typography variant="body1">{selectedModel.accuracy ? `${(selectedModel.accuracy * 100).toFixed(2)}%` : 'N/A'}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Precision</Typography>
                <Typography variant="body1">{selectedModel.precision ? `${(selectedModel.precision * 100).toFixed(2)}%` : 'N/A'}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Recall</Typography>
                <Typography variant="body1">{selectedModel.recall ? `${(selectedModel.recall * 100).toFixed(2)}%` : 'N/A'}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">F1 Score</Typography>
                <Typography variant="body1">{selectedModel.f1_score ? `${(selectedModel.f1_score * 100).toFixed(2)}%` : 'N/A'}</Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="textSecondary">Description</Typography>
                <Typography variant="body1">{selectedModel.description || 'No description available'}</Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="textSecondary">Last Trained</Typography>
                <Typography variant="body1">{new Date(selectedModel.last_trained).toLocaleString()}</Typography>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setModelDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Anomaly Details Dialog */}
      <Dialog open={anomalyDialogOpen} onClose={() => setAnomalyDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Anomaly Details
          <IconButton
            onClick={() => setAnomalyDialogOpen(false)}
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent dividers>
          {selectedAnomaly && (
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <Alert severity={selectedAnomaly.severity === 'critical' || selectedAnomaly.severity === 'high' ? 'error' : 'warning'}>
                  Anomaly Score: {(selectedAnomaly.anomaly_score * 100).toFixed(2)}%
                </Alert>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Detected At</Typography>
                <Typography variant="body1">{new Date(selectedAnomaly.detected_at).toLocaleString()}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Entity</Typography>
                <Typography variant="body1">{selectedAnomaly.entity_id || 'N/A'}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Type</Typography>
                <Typography variant="body1">{selectedAnomaly.anomaly_type || 'Unknown'}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" color="textSecondary">Model</Typography>
                <Typography variant="body1">{selectedAnomaly.model_name || 'Unknown'}</Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="textSecondary">Description</Typography>
                <Typography variant="body1">{selectedAnomaly.description || 'No description available'}</Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="textSecondary">Features</Typography>
                <Typography variant="body2" component="pre" sx={{ bgcolor: '#f5f5f5', p: 2, borderRadius: 1 }}>
                  {JSON.stringify(selectedAnomaly.features, null, 2)}
                </Typography>
              </Grid>
              <Grid item xs={12}>
                <FormControl fullWidth>
                  <InputLabel>Update Status</InputLabel>
                  <Select
                    defaultValue={selectedAnomaly.status}
                    label="Update Status"
                  >
                    <MenuItem value="investigating">Investigating</MenuItem>
                    <MenuItem value="confirmed">Confirmed</MenuItem>
                    <MenuItem value="false_positive">False Positive</MenuItem>
                    <MenuItem value="resolved">Resolved</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  multiline
                  rows={3}
                  label="Notes"
                  placeholder="Add notes about this anomaly..."
                />
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAnomalyDialogOpen(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={() => {
              const status = document.querySelector('select').value;
              const notes = document.querySelector('textarea').value;
              handleUpdateAnomalyStatus(selectedAnomaly.id, status, notes);
            }}
          >
            Update
          </Button>
        </DialogActions>
      </Dialog>

      {/* Training Dialog */}
      <Dialog open={trainDialogOpen} onClose={() => setTrainDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Train Model</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
            Configure training parameters for {selectedModel?.name}
          </Typography>
          <TextField
            fullWidth
            label="Epochs"
            type="number"
            defaultValue={100}
            sx={{ mb: 2 }}
          />
          <TextField
            fullWidth
            label="Batch Size"
            type="number"
            defaultValue={32}
            sx={{ mb: 2 }}
          />
          <TextField
            fullWidth
            label="Learning Rate"
            type="number"
            defaultValue={0.001}
            inputProps={{ step: 0.0001 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTrainDialogOpen(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={() => {
              handleTrainModel(selectedModel.id, {
                epochs: 100,
                batch_size: 32,
                learning_rate: 0.001,
              });
            }}
          >
            Start Training
          </Button>
        </DialogActions>
      </Dialog>

      {/* Metrics Dialog */}
      <Dialog open={metricsDialogOpen} onClose={() => setMetricsDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Model Metrics: {selectedModel?.name}
          <IconButton
            onClick={() => setMetricsDialogOpen(false)}
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent dividers>
          {selectedModel?.metrics && (
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>Performance Metrics</Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} md={3}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="textSecondary" variant="body2">Accuracy</Typography>
                        <Typography variant="h5">{(selectedModel.metrics.accuracy * 100).toFixed(2)}%</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="textSecondary" variant="body2">Precision</Typography>
                        <Typography variant="h5">{(selectedModel.metrics.precision * 100).toFixed(2)}%</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="textSecondary" variant="body2">Recall</Typography>
                        <Typography variant="h5">{(selectedModel.metrics.recall * 100).toFixed(2)}%</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="textSecondary" variant="body2">F1 Score</Typography>
                        <Typography variant="h5">{(selectedModel.metrics.f1_score * 100).toFixed(2)}%</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </Grid>
              {selectedModel.featureImportance && (
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>Feature Importance</Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={selectedModel.featureImportance} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis type="number" />
                      <YAxis dataKey="feature" type="category" width={150} />
                      <RechartsTooltip />
                      <Bar dataKey="importance" fill="#1976d2" />
                    </BarChart>
                  </ResponsiveContainer>
                </Grid>
              )}
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMetricsDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}

export default MLAnalytics;

