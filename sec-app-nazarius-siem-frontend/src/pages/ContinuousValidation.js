import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, LinearProgress, IconButton, Tooltip
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  Assessment as AssessmentIcon,
  Visibility as VisibilityIcon
} from '@mui/icons-material';
import { continuousValidationAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const ContinuousValidation = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [controls, setControls] = useState([]);
  const [tests, setTests] = useState([]);
  const [coverage, setCoverage] = useState([]);
  const [gaps, setGaps] = useState([]);
  const [reports, setReports] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Details Dialog States
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsTitle, setDetailsTitle] = useState('');
  const [detailsData, setDetailsData] = useState(null);
  const [detailsFields, setDetailsFields] = useState([]);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [controlsRes, testsRes, coverageRes, gapsRes, reportsRes, metricsRes] = await Promise.all([
        continuousValidationAPI.listControls(),
        continuousValidationAPI.listTests(),
        continuousValidationAPI.getCoverage(),
        continuousValidationAPI.getGaps(),
        continuousValidationAPI.getReports(),
        continuousValidationAPI.getMetrics(),
      ]);

      setControls(controlsRes.data.data || []);
      setTests(testsRes.data.data || []);
      setCoverage(coverageRes.data.data || []);
      setGaps(gapsRes.data.data || []);
      setReports(reportsRes.data.data || []);
      setMetrics(metricsRes.data.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load validation data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleViewControl = (control) => {
    setDetailsData(control);
    setDetailsTitle(`Security Control: ${control.name}`);
    setDetailsFields([
      { label: 'Control ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Category', key: 'category', type: 'badge' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'MITRE Techniques', key: 'mitre_techniques', type: 'array' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Enabled', key: 'enabled', type: 'status' },
      { label: 'Validation Score', key: 'validation_score', type: 'text' },
      { label: 'Last Validated', key: 'last_validated', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewTest = (test) => {
    setDetailsData(test);
    setDetailsTitle(`Validation Test: ${test.name}`);
    setDetailsFields([
      { label: 'Test ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Control ID', key: 'control_id', type: 'text' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Technique', key: 'technique', type: 'text' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Severity', key: 'severity', type: 'badge' },
      { label: 'Detection Rate', key: 'detection_rate', type: 'text' },
      { label: 'True Positives', key: 'true_positives', type: 'text' },
      { label: 'False Positives', key: 'false_positives', type: 'text' },
      { label: 'Execution Time (s)', key: 'execution_time', type: 'text' },
      { label: 'Last Run', key: 'last_run', type: 'date' },
      { label: 'Next Run', key: 'next_run', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewGap = (gap) => {
    setDetailsData(gap);
    setDetailsTitle(`Security Gap: ${gap.title}`);
    setDetailsFields([
      { label: 'Gap ID', key: 'id', type: 'text' },
      { label: 'Title', key: 'title', type: 'text' },
      { label: 'Category', key: 'category', type: 'badge' },
      { label: 'Severity', key: 'severity', type: 'badge' },
      { label: 'Priority', key: 'priority', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'MITRE Techniques', key: 'mitre_techniques', type: 'array' },
      { label: 'Recommendation', key: 'recommendation', type: 'text', fullWidth: true },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Resolved At', key: 'resolved_at', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success',
      inactive: 'default',
      testing: 'info',
      passed: 'success',
      failed: 'error',
      running: 'info',
      pending: 'warning',
      open: 'error',
      in_progress: 'warning',
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

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Typography variant="h4" gutterBottom>
        🔒 Continuous Validation
      </Typography>

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
                  <Typography color="textSecondary" gutterBottom>
                    Validation Score
                  </Typography>
                  <Typography variant="h4">{metrics.validation_score?.toFixed(1) || 0}%</Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={metrics.validation_score || 0} 
                    sx={{ mt: 1 }}
                    color={metrics.validation_score >= 90 ? 'success' : metrics.validation_score >= 70 ? 'warning' : 'error'}
                  />
                </Box>
                <TrendingUpIcon sx={{ fontSize: 48, color: 'primary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    MITRE Coverage
                  </Typography>
                  <Typography variant="h4">{metrics.mitre_coverage?.toFixed(1) || 0}%</Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={metrics.mitre_coverage || 0} 
                    sx={{ mt: 1 }}
                    color="info"
                  />
                </Box>
                <SecurityIcon sx={{ fontSize: 48, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Detection Rate
                  </Typography>
                  <Typography variant="h4">{metrics.detection_rate?.toFixed(1) || 0}%</Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={metrics.detection_rate || 0} 
                    sx={{ mt: 1 }}
                    color="success"
                  />
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
                  <Typography color="textSecondary" gutterBottom>
                    Open Gaps
                  </Typography>
                  <Typography variant="h4">{metrics.open_gaps || 0}</Typography>
                  <Typography variant="caption" color="error">
                    {metrics.critical_gaps || 0} Critical
                  </Typography>
                </Box>
                <WarningIcon sx={{ fontSize: 48, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label="Security Controls" />
          <Tab label="Validation Tests" />
          <Tab label="MITRE Coverage" />
          <Tab label="Gap Analysis" />
          <Tab label="Reports" />
        </Tabs>
      </Paper>

      {/* Tab 0: Security Controls */}
      {activeTab === 0 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>
              Security Controls
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>ID</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Category</TableCell>
                    <TableCell>MITRE Techniques</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Score</TableCell>
                    <TableCell>Last Validated</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {controls.map((control) => (
                    <TableRow key={control.id} hover>
                      <TableCell>{control.id}</TableCell>
                      <TableCell><strong>{control.name}</strong></TableCell>
                      <TableCell>
                        <Chip label={control.category} size="small" color="primary" />
                      </TableCell>
                      <TableCell>
                        {control.mitre_techniques.slice(0, 2).map(t => (
                          <Chip key={t} label={t} size="small" sx={{ mr: 0.5 }} />
                        ))}
                        {control.mitre_techniques.length > 2 && (
                          <Chip label={`+${control.mitre_techniques.length - 2}`} size="small" />
                        )}
                      </TableCell>
                      <TableCell>
                        <Chip label={control.status} color={getStatusColor(control.status)} size="small" />
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>
                            {control.validation_score}%
                          </Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={control.validation_score} 
                            sx={{ width: 60 }}
                            color={control.validation_score >= 90 ? 'success' : 'warning'}
                          />
                        </Box>
                      </TableCell>
                      <TableCell>{new Date(control.last_validated).toLocaleDateString()}</TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewControl(control)}>
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

      {/* Tab 1: Validation Tests */}
      {activeTab === 1 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>
              Validation Tests
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>ID</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Technique</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Detection Rate</TableCell>
                    <TableCell>Last Run</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {tests.map((test) => (
                    <TableRow key={test.id} hover>
                      <TableCell>{test.id}</TableCell>
                      <TableCell><strong>{test.name}</strong></TableCell>
                      <TableCell>
                        <Chip label={test.type} size="small" color="info" />
                      </TableCell>
                      <TableCell>
                        <Chip label={test.technique} size="small" />
                      </TableCell>
                      <TableCell>
                        <Chip label={test.status} color={getStatusColor(test.status)} size="small" />
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>
                            {test.detection_rate.toFixed(1)}%
                          </Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={test.detection_rate} 
                            sx={{ width: 60 }}
                            color={test.detection_rate >= 90 ? 'success' : 'warning'}
                          />
                        </Box>
                      </TableCell>
                      <TableCell>{new Date(test.last_run).toLocaleString()}</TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewTest(test)}>
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

      {/* Tab 2: MITRE Coverage */}
      {activeTab === 2 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>
              MITRE ATT&CK Coverage
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Tactic</TableCell>
                    <TableCell>Technique</TableCell>
                    <TableCell>Covered</TableCell>
                    <TableCell>Controls</TableCell>
                    <TableCell>Validation Rate</TableCell>
                    <TableCell>Last Tested</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {coverage.map((item, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell>
                        <strong>{item.tactic_id}</strong>
                        <br />
                        <Typography variant="caption">{item.tactic_name}</Typography>
                      </TableCell>
                      <TableCell>
                        <strong>{item.technique_id}</strong>
                        <br />
                        <Typography variant="caption">{item.technique_name}</Typography>
                      </TableCell>
                      <TableCell>
                        {item.covered ? (
                          <CheckCircleIcon color="success" />
                        ) : (
                          <WarningIcon color="error" />
                        )}
                      </TableCell>
                      <TableCell>
                        {item.controls.map(c => (
                          <Chip key={c} label={c} size="small" sx={{ mr: 0.5 }} />
                        ))}
                        {item.controls.length === 0 && (
                          <Typography variant="caption" color="error">No controls</Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>
                            {item.validation_rate.toFixed(1)}%
                          </Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={item.validation_rate} 
                            sx={{ width: 80 }}
                            color={item.validation_rate >= 90 ? 'success' : item.validation_rate > 0 ? 'warning' : 'error'}
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        {item.last_tested && new Date(item.last_tested).toLocaleDateString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        </Paper>
      )}

      {/* Tab 3: Gap Analysis */}
      {activeTab === 3 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>
              Security Gaps
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>ID</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell>Category</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Priority</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {gaps.map((gap) => (
                    <TableRow key={gap.id} hover>
                      <TableCell>{gap.id}</TableCell>
                      <TableCell><strong>{gap.title}</strong></TableCell>
                      <TableCell>
                        <Chip label={gap.category} size="small" color="primary" />
                      </TableCell>
                      <TableCell>
                        <Chip label={gap.severity} color={getSeverityColor(gap.severity)} size="small" />
                      </TableCell>
                      <TableCell>
                        <Chip label={gap.priority} color={getSeverityColor(gap.priority)} size="small" />
                      </TableCell>
                      <TableCell>
                        <Chip label={gap.status} color={getStatusColor(gap.status)} size="small" />
                      </TableCell>
                      <TableCell>{new Date(gap.created_at).toLocaleDateString()}</TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewGap(gap)}>
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

      {/* Tab 4: Reports */}
      {activeTab === 4 && (
        <Grid container spacing={3}>
          {reports.map((report) => (
            <Grid item xs={12} md={6} key={report.id}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <AssessmentIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
                    <Box>
                      <Typography variant="h6">{report.title}</Typography>
                      <Typography variant="caption" color="textSecondary">
                        {report.period}
                      </Typography>
                    </Box>
                  </Box>

                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">
                        Controls Validated
                      </Typography>
                      <Typography variant="h6">
                        {report.validated_controls}/{report.total_controls}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">
                        Tests Passed
                      </Typography>
                      <Typography variant="h6">
                        {report.passed_tests}/{report.passed_tests + report.failed_tests}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">
                        Coverage Rate
                      </Typography>
                      <Typography variant="h6">{report.coverage_rate.toFixed(1)}%</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">
                        Detection Rate
                      </Typography>
                      <Typography variant="h6">{report.detection_rate.toFixed(1)}%</Typography>
                    </Grid>
                  </Grid>

                  <Box mt={2}>
                    <Typography variant="caption" color="textSecondary" gutterBottom>
                      Recommendations:
                    </Typography>
                    {report.recommendations.map((rec, idx) => (
                      <Typography key={idx} variant="body2" sx={{ ml: 2 }}>
                        • {rec}
                      </Typography>
                    ))}
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

export default ContinuousValidation;

