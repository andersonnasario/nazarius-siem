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
  LinearProgress,
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
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  TrendingUp as TrendingUpIcon,
  Description as DescriptionIcon,
  Assessment as AssessmentIcon,
  Gavel as GavelIcon,
  Refresh as RefreshIcon,
  Error as ErrorIcon,
  Timeline as TimelineIcon,
  PlayArrow as PlayArrowIcon,
} from '@mui/icons-material';
import { PieChart, Pie, Cell, BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { complianceAPI } from '../services/api';

const Compliance = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  
  // Dashboard data
  const [stats, setStats] = useState(null);
  const [frameworks, setFrameworks] = useState([]);
  const [recentViolations, setRecentViolations] = useState([]);
  
  // Violations
  const [violations, setViolations] = useState([]);
  const [selectedViolation, setSelectedViolation] = useState(null);
  const [violationDialogOpen, setViolationDialogOpen] = useState(false);
  
  // Audit logs
  const [auditLogs, setAuditLogs] = useState([]);
  
  // Reports
  const [reports, setReports] = useState([]);
  
  // Framework details
  const [selectedFramework, setSelectedFramework] = useState(null);
  const [frameworkDialogOpen, setFrameworkDialogOpen] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [dashboardRes, violationsRes, auditLogsRes, reportsRes] = await Promise.all([
        complianceAPI.getDashboard(),
        complianceAPI.getViolations(),
        complianceAPI.getAuditTrail(),
        complianceAPI.getReports(),
      ]);
      
      setStats(dashboardRes.data.stats);
      setFrameworks(dashboardRes.data.frameworks);
      setRecentViolations(dashboardRes.data.recent_violations);
      setViolations(violationsRes.data.violations);
      setAuditLogs(auditLogsRes.data.audit_logs);
      setReports(reportsRes.data.reports);
    } catch (err) {
      console.error('Error loading compliance data:', err);
      setError('Erro ao carregar dados de compliance');
    } finally {
      setLoading(false);
    }
  };

  const handleViewFramework = async (frameworkId) => {
    try {
      const response = await complianceAPI.getFramework(frameworkId);
      setSelectedFramework(response.data);
      setFrameworkDialogOpen(true);
    } catch (err) {
      console.error('Error loading framework:', err);
    }
  };

  const handleRunAssessment = async (frameworkId) => {
    try {
      await complianceAPI.runAssessment(frameworkId);
      alert('Assessment iniciado! Isso pode levar alguns minutos.');
      loadData();
    } catch (err) {
      console.error('Error running assessment:', err);
    }
  };

  const handleViewViolation = (violation) => {
    setSelectedViolation(violation);
    setViolationDialogOpen(true);
  };

  const handleUpdateViolation = async (status) => {
    try {
      await complianceAPI.updateViolation(selectedViolation.id, { status });
      setViolationDialogOpen(false);
      loadData();
    } catch (err) {
      console.error('Error updating violation:', err);
    }
  };

  const handleGenerateReport = async (framework, reportType) => {
    try {
      const now = new Date();
      const periodStart = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      const periodEnd = new Date(now.getFullYear(), now.getMonth(), 0);
      
      await complianceAPI.generateReport({
        framework,
        report_type: reportType,
        period_start: periodStart.toISOString(),
        period_end: periodEnd.toISOString(),
      });
      
      alert('Relatório gerado com sucesso!');
      loadData();
    } catch (err) {
      console.error('Error generating report:', err);
    }
  };

  const handleDownloadReport = async (reportId) => {
    try {
      const response = await complianceAPI.downloadReport(reportId);
      
      // Criar blob e fazer download
      const blob = new Blob([response.data], { type: 'text/html' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${reportId}.html`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Error downloading report:', err);
      alert('Erro ao fazer download do relatório');
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      compliant: 'success',
      non_compliant: 'error',
      in_progress: 'warning',
      implemented: 'success',
      failed: 'error',
      not_implemented: 'warning',
      open: 'error',
      investigating: 'warning',
      resolved: 'success',
    };
    return colors[status] || 'default';
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

  const COLORS = ['#4caf50', '#f44336', '#ff9800', '#2196f3', '#9c27b0'];

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
            📜 Compliance & Audit
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Gerenciamento de conformidade e trilha de auditoria
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

      {/* KPI Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <SecurityIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Score Geral
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.overall_score?.toFixed(1)}%</Typography>
              <LinearProgress
                variant="determinate"
                value={stats?.overall_score}
                color={stats?.overall_score >= 80 ? 'success' : stats?.overall_score >= 60 ? 'warning' : 'error'}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <CheckCircleIcon sx={{ mr: 1, color: 'success.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Frameworks Conformes
                </Typography>
              </Box>
              <Typography variant="h4">
                {stats?.compliant_frameworks}/{stats?.total_frameworks}
              </Typography>
              <Typography variant="caption">
                {((stats?.compliant_frameworks / stats?.total_frameworks) * 100).toFixed(0)}% compliant
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
                  Violações Abertas
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.open_violations}</Typography>
              <Typography variant="caption" color="error">
                {stats?.critical_violations} críticas
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <TrendingUpIcon sx={{ mr: 1, color: stats?.compliance_trend === 'improving' ? 'success.main' : 'warning.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Tendência
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ textTransform: 'capitalize' }}>
                {stats?.compliance_trend === 'improving' ? '↑ Melhorando' : 
                 stats?.compliance_trend === 'declining' ? '↓ Piorando' : '→ Estável'}
              </Typography>
              <Typography variant="caption">
                {stats?.resolved_last_30_days} resolvidas (30d)
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Card>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="Overview" />
          <Tab label="Frameworks" />
          <Tab label="Violações" />
          <Tab label="Audit Trail" />
          <Tab label="Relatórios" />
        </Tabs>

        <CardContent>
          {/* Tab 0: Overview */}
          {tabValue === 0 && (
            <Box>
              <Grid container spacing={3}>
                {/* Compliance Score by Framework */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Compliance Score por Framework
                      </Typography>
                      <ResponsiveContainer width="100%" height={300}>
                        <BarChart data={frameworks}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                          <YAxis domain={[0, 100]} />
                          <Tooltip />
                          <Bar dataKey="compliance_score" fill="#4caf50" />
                        </BarChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Controls Status */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Status dos Controles
                      </Typography>
                      <ResponsiveContainer width="100%" height={300}>
                        <PieChart>
                          <Pie
                            data={[
                              { name: 'Implementados', value: stats?.implemented_controls },
                              { name: 'Falhados', value: stats?.failed_controls },
                              { name: 'Não Implementados', value: stats?.total_controls - stats?.implemented_controls - stats?.failed_controls },
                            ]}
                            dataKey="value"
                            nameKey="name"
                            cx="50%"
                            cy="50%"
                            outerRadius={80}
                            label
                          >
                            {[0, 1, 2].map((index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Recent Violations */}
                <Grid item xs={12}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Violações Recentes
                      </Typography>
                      <TableContainer>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Framework</TableCell>
                              <TableCell>Política</TableCell>
                              <TableCell>Severidade</TableCell>
                              <TableCell>Descrição</TableCell>
                              <TableCell>Status</TableCell>
                              <TableCell>Ações</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {recentViolations.slice(0, 5).map((violation) => (
                              <TableRow key={violation.id}>
                                <TableCell>
                                  <Chip label={violation.framework} size="small" variant="outlined" />
                                </TableCell>
                                <TableCell>{violation.policy_name}</TableCell>
                                <TableCell>
                                  <Chip
                                    label={violation.severity}
                                    size="small"
                                    color={getSeverityColor(violation.severity)}
                                  />
                                </TableCell>
                                <TableCell>
                                  <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
                                    {violation.description}
                                  </Typography>
                                </TableCell>
                                <TableCell>
                                  <Chip
                                    label={violation.status}
                                    size="small"
                                    color={getStatusColor(violation.status)}
                                  />
                                </TableCell>
                                <TableCell>
                                  <Button
                                    size="small"
                                    onClick={() => handleViewViolation(violation)}
                                  >
                                    Ver
                                  </Button>
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
          )}

          {/* Tab 1: Frameworks */}
          {tabValue === 1 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Frameworks de Compliance
              </Typography>
              <Grid container spacing={3}>
                {frameworks.map((framework) => (
                  <Grid item xs={12} md={6} lg={4} key={framework.id}>
                    <Card
                      variant="outlined"
                      sx={{
                        borderLeft: 4,
                        borderLeftColor: framework.status === 'compliant' ? 'success.main' : 
                                        framework.status === 'non_compliant' ? 'error.main' : 'warning.main'
                      }}
                    >
                      <CardContent>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', mb: 2 }}>
                          <Box>
                            <Typography variant="h6">{framework.name}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {framework.description}
                            </Typography>
                          </Box>
                          <Chip
                            label={framework.status}
                            size="small"
                            color={getStatusColor(framework.status)}
                          />
                        </Box>
                        
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="body2" gutterBottom>
                            Score: {framework.compliance_score}%
                          </Typography>
                          <LinearProgress
                            variant="determinate"
                            value={framework.compliance_score}
                            color={framework.compliance_score >= 80 ? 'success' : 
                                   framework.compliance_score >= 60 ? 'warning' : 'error'}
                          />
                        </Box>

                        <Grid container spacing={1} sx={{ mb: 2 }}>
                          <Grid item xs={4}>
                            <Typography variant="caption" color="text.secondary">Total</Typography>
                            <Typography variant="body2" fontWeight="bold">{framework.total_controls}</Typography>
                          </Grid>
                          <Grid item xs={4}>
                            <Typography variant="caption" color="text.secondary">OK</Typography>
                            <Typography variant="body2" fontWeight="bold" color="success.main">
                              {framework.implemented_controls}
                            </Typography>
                          </Grid>
                          <Grid item xs={4}>
                            <Typography variant="caption" color="text.secondary">Falhas</Typography>
                            <Typography variant="body2" fontWeight="bold" color="error.main">
                              {framework.failed_controls}
                            </Typography>
                          </Grid>
                        </Grid>

                        <Box sx={{ display: 'flex', gap: 1 }}>
                          <Button
                            fullWidth
                            size="small"
                            variant="outlined"
                            onClick={() => handleViewFramework(framework.id)}
                          >
                            Ver Detalhes
                          </Button>
                          <Button
                            size="small"
                            variant="contained"
                            startIcon={<PlayArrowIcon />}
                            onClick={() => handleRunAssessment(framework.id)}
                          >
                            Avaliar
                          </Button>
                        </Box>

                        <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                          Última avaliação: {new Date(framework.last_assessment).toLocaleDateString('pt-BR')}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          )}

          {/* Tab 2: Violações */}
          {tabValue === 2 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Todas as Violações de Política
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Framework</TableCell>
                      <TableCell>Política</TableCell>
                      <TableCell>Controle</TableCell>
                      <TableCell>Severidade</TableCell>
                      <TableCell>Descrição</TableCell>
                      <TableCell>Detectada em</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Ações</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {violations.map((violation) => (
                      <TableRow key={violation.id}>
                        <TableCell>
                          <Chip label={violation.framework} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>{violation.policy_name}</TableCell>
                        <TableCell>{violation.control_id}</TableCell>
                        <TableCell>
                          <Chip
                            label={violation.severity}
                            size="small"
                            color={getSeverityColor(violation.severity)}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
                            {violation.description}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(violation.detected_at).toLocaleString('pt-BR')}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={violation.status}
                            size="small"
                            color={getStatusColor(violation.status)}
                          />
                        </TableCell>
                        <TableCell>
                          <Button
                            size="small"
                            onClick={() => handleViewViolation(violation)}
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

          {/* Tab 3: Audit Trail */}
          {tabValue === 3 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Trilha de Auditoria
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Timestamp</TableCell>
                      <TableCell>Usuário</TableCell>
                      <TableCell>Ação</TableCell>
                      <TableCell>Recurso</TableCell>
                      <TableCell>IP</TableCell>
                      <TableCell>Status</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {auditLogs.map((log) => (
                      <TableRow key={log.id}>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(log.timestamp).toLocaleString('pt-BR')}
                          </Typography>
                        </TableCell>
                        <TableCell>{log.username}</TableCell>
                        <TableCell>
                          <Chip label={log.action} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>
                          {log.resource} ({log.resource_id})
                        </TableCell>
                        <TableCell>{log.ip_address}</TableCell>
                        <TableCell>
                          <Chip
                            label={log.status}
                            size="small"
                            color={log.status === 'success' ? 'success' : 'error'}
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Tab 4: Relatórios */}
          {tabValue === 4 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
                <Typography variant="h6">
                  Relatórios de Compliance
                </Typography>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  {frameworks.map((fw) => (
                    <Button
                      key={fw.id}
                      size="small"
                      variant="outlined"
                      onClick={() => handleGenerateReport(fw.id, 'executive')}
                    >
                      Gerar {fw.name}
                    </Button>
                  ))}
                </Box>
              </Box>

              <Grid container spacing={2}>
                {reports.map((report) => (
                  <Grid item xs={12} sm={6} md={4} key={report.id}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                          <DescriptionIcon sx={{ mr: 1, color: 'primary.main' }} />
                          <Typography variant="subtitle1">
                            {report.framework}
                          </Typography>
                        </Box>
                        <Typography variant="caption" color="text.secondary">
                          {report.report_type} Report
                        </Typography>
                        <Box sx={{ my: 2 }}>
                          <Typography variant="h4" color="primary">
                            {report.compliance_score}%
                          </Typography>
                          <Typography variant="caption">
                            Compliance Score
                          </Typography>
                        </Box>
                        <Typography variant="body2" sx={{ mb: 2 }}>
                          {report.summary}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Gerado em: {new Date(report.generated_at).toLocaleDateString('pt-BR')}
                        </Typography>
                        <Button
                          fullWidth
                          size="small"
                          variant="outlined"
                          sx={{ mt: 2 }}
                          onClick={() => handleDownloadReport(report.id)}
                        >
                          Download HTML
                        </Button>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Framework Detail Dialog */}
      <Dialog open={frameworkDialogOpen} onClose={() => setFrameworkDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {selectedFramework?.name}
        </DialogTitle>
        <DialogContent>
          {selectedFramework && (
            <Box>
              <Typography variant="body2" gutterBottom>
                {selectedFramework.description}
              </Typography>
              <Typography variant="body2" gutterBottom>
                <strong>Versão:</strong> {selectedFramework.version}
              </Typography>
              <Typography variant="body2" gutterBottom>
                <strong>Score:</strong> {selectedFramework.compliance_score}%
              </Typography>
              <Typography variant="body2" gutterBottom>
                <strong>Status:</strong> {selectedFramework.status}
              </Typography>
              
              <Divider sx={{ my: 2 }} />
              
              <Typography variant="h6" gutterBottom>
                Categorias e Controles
              </Typography>
              {selectedFramework.categories?.map((category, idx) => (
                <Box key={idx} sx={{ mb: 2 }}>
                  <Typography variant="subtitle1" fontWeight="bold">
                    {category.name}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {category.description}
                  </Typography>
                  <List dense>
                    {category.controls?.map((control) => (
                      <ListItem key={control.id}>
                        <ListItemText
                          primary={`${control.control_id}: ${control.title}`}
                          secondary={
                            <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                              <Chip
                                label={control.status}
                                size="small"
                                color={getStatusColor(control.status)}
                              />
                              <Chip
                                label={control.severity}
                                size="small"
                                color={getSeverityColor(control.severity)}
                              />
                            </Box>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              ))}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setFrameworkDialogOpen(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>

      {/* Violation Detail Dialog */}
      <Dialog open={violationDialogOpen} onClose={() => setViolationDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Detalhes da Violação
        </DialogTitle>
        <DialogContent>
          {selectedViolation && (
            <Box>
              <Typography variant="body1" gutterBottom>
                <strong>Framework:</strong> {selectedViolation.framework}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Política:</strong> {selectedViolation.policy_name}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Controle:</strong> {selectedViolation.control_id}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Severidade:</strong> {selectedViolation.severity}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Descrição:</strong> {selectedViolation.description}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Fonte:</strong> {selectedViolation.source}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Detectada em:</strong> {new Date(selectedViolation.detected_at).toLocaleString('pt-BR')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                <strong>Status:</strong> {selectedViolation.status}
              </Typography>
              
              {selectedViolation.assigned_to && (
                <Typography variant="body1" gutterBottom>
                  <strong>Atribuído para:</strong> {selectedViolation.assigned_to}
                </Typography>
              )}
              
              <Box sx={{ mt: 3 }}>
                <Typography variant="subtitle2" gutterBottom>Atualizar Status:</Typography>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => handleUpdateViolation('investigating')}
                  >
                    Investigando
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    color="success"
                    onClick={() => handleUpdateViolation('resolved')}
                  >
                    Resolver
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    color="error"
                    onClick={() => handleUpdateViolation('open')}
                  >
                    Reabrir
                  </Button>
                </Box>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setViolationDialogOpen(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Compliance;
