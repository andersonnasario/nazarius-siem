import React, { useState, useEffect } from 'react';
import { Box, Container, Grid, Card, CardContent, Typography, Chip, LinearProgress, Alert, IconButton, Tooltip, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper } from '@mui/material';
import { TrendingUp, Security, Speed, AttachMoney, Warning, CheckCircle, Visibility as VisibilityIcon } from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';
import { mdrDashboardAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const COLORS = ['#4caf50', '#2196f3', '#ff9800', '#f44336'];

const MDRDashboard = () => {
  const [dashboard, setDashboard] = useState(null);
  
  // Details Dialog states
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsTitle, setDetailsTitle] = useState('');
  const [detailsData, setDetailsData] = useState(null);
  const [detailsFields, setDetailsFields] = useState([]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 60000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      const res = await mdrDashboardAPI.getDashboard();
      setDashboard(res.data.data);
    } catch (error) {
      console.error('Error loading dashboard:', error);
    }
  };

  // View Details Handlers
  const handleViewSecurityPosture = () => {
    if (!dashboard) return;
    setDetailsData(dashboard.security_posture);
    setDetailsTitle('Security Posture Details');
    setDetailsFields([
      { label: 'Overall Score', key: 'overall_score' },
      { label: 'Threat Level', key: 'threat_level', type: 'badge' },
      { label: 'Active Incidents', key: 'active_incidents' },
      { label: 'Critical Alerts', key: 'critical_alerts' },
      { label: 'Vulnerabilities', key: 'vulnerabilities' },
      { label: 'Coverage %', key: 'coverage_percentage' },
      { label: 'Last Updated', key: 'last_updated', type: 'date' },
      { label: 'Details', key: 'details', type: 'json', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  const handleViewMDRPerformance = () => {
    if (!dashboard) return;
    setDetailsData(dashboard.mdr_performance);
    setDetailsTitle('MDR Performance Metrics');
    setDetailsFields([
      { label: 'SLA Compliance %', key: 'sla_compliance' },
      { label: 'MTTR (minutes)', key: 'mttr' },
      { label: 'MTTA (minutes)', key: 'mtta' },
      { label: 'Automated Responses', key: 'automated_responses' },
      { label: 'Triage Efficiency %', key: 'triage_efficiency' },
      { label: 'Detection Rate %', key: 'detection_rate' },
      { label: 'False Positive Rate %', key: 'false_positive_rate' },
      { label: 'Details', key: 'details', type: 'json', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  const handleViewBusinessImpact = () => {
    if (!dashboard) return;
    setDetailsData(dashboard.business_impact);
    setDetailsTitle('Business Impact Analysis');
    setDetailsFields([
      { label: 'Cost Savings ($)', key: 'cost_savings' },
      { label: 'ROI %', key: 'roi' },
      { label: 'Risk Reduction %', key: 'risk_reduction' },
      { label: 'Incidents Prevented', key: 'incidents_prevented' },
      { label: 'Downtime Avoided (hours)', key: 'downtime_avoided' },
      { label: 'Compliance Score', key: 'compliance_score' },
      { label: 'Period', key: 'period' },
      { label: 'Details', key: 'details', type: 'json', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  const handleViewAlert = (alert) => {
    setDetailsData(alert);
    setDetailsTitle(`Critical Alert: ${alert.title}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Title', key: 'title' },
      { label: 'Severity', key: 'severity', type: 'badge' },
      { label: 'Status', key: 'status', type: 'status' },
      { label: 'Source', key: 'source' },
      { label: 'Target', key: 'target' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'SLA Deadline', key: 'sla_deadline', type: 'date' },
      { label: 'Assigned To', key: 'assigned_to' },
      { label: 'Description', key: 'description', fullWidth: true },
      { label: 'Details', key: 'details', type: 'json', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  if (!dashboard) return <LinearProgress />;

  const { security_posture, mdr_performance, business_impact, threat_intel_summary, compliance_status, critical_alerts } = dashboard;

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>📊 MDR Executive Dashboard</Typography>
      <Typography variant="body1" color="textSecondary" gutterBottom>Comprehensive MDR performance and security posture overview</Typography>

      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" variant="body2">Security Score</Typography>
                  <Typography variant="h4">{security_posture.overall_score.toFixed(1)}</Typography>
                  <Chip label={security_posture.threat_level.toUpperCase()} size="small" color={security_posture.threat_level === 'low' ? 'success' : 'warning'} />
                </Box>
                <Security sx={{ fontSize: 40, color: 'primary.main', opacity: 0.3 }} />
              </Box>
              <Box mt={2} display="flex" justifyContent="flex-end">
                <Tooltip title="View Details">
                  <IconButton size="small" onClick={handleViewSecurityPosture}>
                    <VisibilityIcon />
                  </IconButton>
                </Tooltip>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" variant="body2">SLA Compliance</Typography>
                  <Typography variant="h4">{mdr_performance.sla_compliance.toFixed(1)}%</Typography>
                  <Typography variant="body2" color="success.main">MTTR: {Math.round(mdr_performance.mttr)}m</Typography>
                </Box>
                <Speed sx={{ fontSize: 40, color: 'success.main', opacity: 0.3 }} />
              </Box>
              <Box mt={2} display="flex" justifyContent="flex-end">
                <Tooltip title="View Details">
                  <IconButton size="small" onClick={handleViewMDRPerformance}>
                    <VisibilityIcon />
                  </IconButton>
                </Tooltip>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" variant="body2">Cost Savings</Typography>
                  <Typography variant="h4">${(business_impact.cost_savings / 1000).toFixed(0)}K</Typography>
                  <Typography variant="body2" color="info.main">ROI: {business_impact.roi.toFixed(0)}%</Typography>
                </Box>
                <AttachMoney sx={{ fontSize: 40, color: 'info.main', opacity: 0.3 }} />
              </Box>
              <Box mt={2} display="flex" justifyContent="flex-end">
                <Tooltip title="View Details">
                  <IconButton size="small" onClick={handleViewBusinessImpact}>
                    <VisibilityIcon />
                  </IconButton>
                </Tooltip>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" variant="body2">Active Incidents</Typography>
                  <Typography variant="h4">{security_posture.active_incidents}</Typography>
                  <Typography variant="body2" color="warning.main">{business_impact.prevented_incidents} prevented</Typography>
                </Box>
                <Warning sx={{ fontSize: 40, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>MDR Performance Trends (30 Days)</Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={dashboard.trend_data || []}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" tickFormatter={(value) => new Date(value).toLocaleDateString()} />
                  <YAxis yAxisId="left" />
                  <YAxis yAxisId="right" orientation="right" />
                  <Tooltip labelFormatter={(value) => new Date(value).toLocaleDateString()} />
                  <Legend />
                  <Line yAxisId="left" type="monotone" dataKey="incidents" stroke="#f44336" name="Incidents" />
                  <Line yAxisId="left" type="monotone" dataKey="resolved" stroke="#4caf50" name="Resolved" />
                  <Line yAxisId="right" type="monotone" dataKey="security_score" stroke="#2196f3" name="Security Score" />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Top Threats</Typography>
              {threat_intel_summary.top_threats.map((threat, idx) => (
                <Box key={idx} sx={{ mb: 2 }}>
                  <Box display="flex" justifyContent="space-between" alignItems="center">
                    <Typography variant="body2">{threat.name}</Typography>
                    <Chip label={threat.count} size="small" color={threat.severity === 'critical' ? 'error' : 'warning'} />
                  </Box>
                  <LinearProgress variant="determinate" value={Math.min(threat.count * 3, 100)} sx={{ mt: 0.5 }} />
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Business Impact</Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Risk Reduction</Typography>
                  <Typography variant="h5">{business_impact.risk_reduction.toFixed(0)}%</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Avoided Downtime</Typography>
                  <Typography variant="h5">{business_impact.avoided_downtime.toFixed(1)}h</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Automation Rate</Typography>
                  <Typography variant="h5">{mdr_performance.automation_rate.toFixed(0)}%</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Productivity Gain</Typography>
                  <Typography variant="h5">{business_impact.productivity_gain.toFixed(0)}%</Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Compliance Status</Typography>
              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="textSecondary">Overall Compliance: {compliance_status.overall_compliance.toFixed(1)}%</Typography>
                <LinearProgress variant="determinate" value={compliance_status.overall_compliance} sx={{ my: 1 }} color="success" />
              </Box>
              {Object.entries(compliance_status.frameworks).map(([framework, compliance]) => (
                <Box key={framework} sx={{ mb: 1 }}>
                  <Box display="flex" justifyContent="space-between">
                    <Typography variant="body2">{framework}</Typography>
                    <Typography variant="body2">{compliance.toFixed(0)}%</Typography>
                  </Box>
                  <LinearProgress variant="determinate" value={compliance} sx={{ height: 6 }} />
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Critical Alerts</Typography>
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Title</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Impact</TableCell>
                      <TableCell>Action Taken</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {critical_alerts.map((alert) => (
                      <TableRow key={alert.id}>
                        <TableCell>{alert.title}</TableCell>
                        <TableCell>
                          <Chip 
                            label={alert.severity.toUpperCase()} 
                            color={alert.severity === 'critical' ? 'error' : 'warning'} 
                            size="small" 
                          />
                        </TableCell>
                        <TableCell>
                          <Chip label={alert.status} size="small" />
                        </TableCell>
                        <TableCell>{alert.impact}</TableCell>
                        <TableCell>{alert.action_taken}</TableCell>
                        <TableCell align="right">
                          <Tooltip title="View Details">
                            <IconButton
                              size="small"
                              onClick={() => handleViewAlert(alert)}
                            >
                              <VisibilityIcon />
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

export default MDRDashboard;
