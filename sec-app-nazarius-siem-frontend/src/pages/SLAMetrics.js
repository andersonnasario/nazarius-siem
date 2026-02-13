import React, { useState, useEffect } from 'react';
import { Box, Container, Grid, Card, CardContent, Typography, Chip, LinearProgress, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, IconButton, Tooltip, Paper, Tabs, Tab } from '@mui/material';
import { Speed as SpeedIcon, CheckCircle as CheckIcon, Warning as WarningIcon, Error as ErrorIcon, Visibility as VisibilityIcon } from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';
import { slaMetricsAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const COLORS = ['#4caf50', '#ff9800', '#f44336'];

const SLAMetrics = () => {
  const [stats, setStats] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [activeTab, setActiveTab] = useState(0);
  
  // Details Dialog states
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsTitle, setDetailsTitle] = useState('');
  const [detailsData, setDetailsData] = useState(null);
  const [detailsFields, setDetailsFields] = useState([]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      const [statsRes, metricsRes] = await Promise.all([
        slaMetricsAPI.getStats(),
        slaMetricsAPI.getMetrics(),
      ]);
      setStats(statsRes.data.data);
      setMetrics(metricsRes.data.data);
    } catch (error) {
      console.error('Error loading data:', error);
    }
  };

  // View Details Handler
  const handleViewMetricDetails = (metric) => {
    setDetailsData(metric);
    setDetailsTitle(`SLA Metric: ${metric.name || metric.metric_name || 'Details'}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Name', key: 'name' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Value', key: 'value' },
      { label: 'Target', key: 'target' },
      { label: 'Status', key: 'status', type: 'status' },
      { label: 'Compliance %', key: 'compliance_percentage' },
      { label: 'Threshold', key: 'threshold' },
      { label: 'Current Value', key: 'current_value' },
      { label: 'Breaches', key: 'breaches' },
      { label: 'Last Breach', key: 'last_breach', type: 'date' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Updated At', key: 'updated_at', type: 'date' },
      { label: 'Description', key: 'description', fullWidth: true },
      { label: 'Details', key: 'details', type: 'json', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  if (!stats || !metrics) return <LinearProgress />;

  const complianceData = [
    { name: 'Compliant', value: stats.compliant },
    { name: 'At Risk', value: stats.at_risk },
    { name: 'Breached', value: stats.breached },
  ];

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>📊 SLA & Metrics Tracking</Typography>
      <Typography variant="body1" color="textSecondary" gutterBottom>Real-time SLA monitoring and operational metrics</Typography>

      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" variant="body2">SLA Compliance</Typography>
                  <Typography variant="h4">{stats.compliance_rate.toFixed(1)}%</Typography>
                  <Typography variant="body2" color="success.main">{stats.compliant} compliant</Typography>
                </Box>
                <CheckIcon sx={{ fontSize: 40, color: 'success.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" variant="body2">MTTR</Typography>
                  <Typography variant="h4">{Math.round(metrics.mttr)}m</Typography>
                  <Typography variant="body2" color="info.main">Mean Time To Resolve</Typography>
                </Box>
                <SpeedIcon sx={{ fontSize: 40, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" variant="body2">At Risk</Typography>
                  <Typography variant="h4">{stats.at_risk}</Typography>
                  <Typography variant="body2" color="warning.main">Requires attention</Typography>
                </Box>
                <WarningIcon sx={{ fontSize: 40, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" variant="body2">Breaches</Typography>
                  <Typography variant="h4">{stats.breached}</Typography>
                  <Typography variant="body2" color="error.main">SLA violations</Typography>
                </Box>
                <ErrorIcon sx={{ fontSize: 40, color: 'error.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>SLA Compliance Distribution</Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie data={complianceData} cx="50%" cy="50%" labelLine={false} label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`} outerRadius={80} fill="#8884d8" dataKey="value">
                    {complianceData.map((entry, index) => (<Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Key Metrics</Typography>
              <Box sx={{ mt: 2 }}>
                <Typography variant="body2">MTTA (Mean Time To Acknowledge): {Math.round(metrics.mtta)}m</Typography>
                <LinearProgress variant="determinate" value={Math.min(metrics.mtta, 100)} sx={{ my: 1 }} />
                <Typography variant="body2">First Response Time: {Math.round(metrics.first_response_time)}m</Typography>
                <LinearProgress variant="determinate" value={Math.min(metrics.first_response_time, 100)} sx={{ my: 1 }} />
                <Typography variant="body2">Resolution Rate: {metrics.resolution_rate.toFixed(1)}%</Typography>
                <LinearProgress variant="determinate" value={metrics.resolution_rate} sx={{ my: 1 }} color="success" />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>SLA Compliance Timeline (Last 24h)</Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={stats.time_series_data || []}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" tickFormatter={(value) => new Date(value).toLocaleTimeString()} />
                  <YAxis />
                  <RechartsTooltip labelFormatter={(value) => new Date(value).toLocaleString()} />
                  <Legend />
                  <Line type="monotone" dataKey="compliant" stroke="#4caf50" name="Compliant" />
                  <Line type="monotone" dataKey="at_risk" stroke="#ff9800" name="At Risk" />
                  <Line type="monotone" dataKey="breached" stroke="#f44336" name="Breached" />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Detailed Metrics</Typography>
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Metric</TableCell>
                      <TableCell>Value</TableCell>
                      <TableCell>Target</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    <TableRow>
                      <TableCell>MTTR (Mean Time To Resolve)</TableCell>
                      <TableCell>{Math.round(metrics.mttr)}m</TableCell>
                      <TableCell>60m</TableCell>
                      <TableCell>
                        <Chip 
                          label={metrics.mttr <= 60 ? 'Compliant' : 'At Risk'} 
                          color={metrics.mttr <= 60 ? 'success' : 'warning'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton
                            size="small"
                            onClick={() => handleViewMetricDetails({
                              id: 'mttr',
                              name: 'MTTR (Mean Time To Resolve)',
                              type: 'Time-based',
                              value: `${Math.round(metrics.mttr)}m`,
                              target: '60m',
                              status: metrics.mttr <= 60 ? 'compliant' : 'at_risk',
                              compliance_percentage: Math.min((60 / metrics.mttr) * 100, 100).toFixed(1),
                              description: 'Average time taken to resolve incidents',
                              details: metrics
                            })}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>MTTA (Mean Time To Acknowledge)</TableCell>
                      <TableCell>{Math.round(metrics.mtta)}m</TableCell>
                      <TableCell>15m</TableCell>
                      <TableCell>
                        <Chip 
                          label={metrics.mtta <= 15 ? 'Compliant' : 'At Risk'} 
                          color={metrics.mtta <= 15 ? 'success' : 'warning'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton
                            size="small"
                            onClick={() => handleViewMetricDetails({
                              id: 'mtta',
                              name: 'MTTA (Mean Time To Acknowledge)',
                              type: 'Time-based',
                              value: `${Math.round(metrics.mtta)}m`,
                              target: '15m',
                              status: metrics.mtta <= 15 ? 'compliant' : 'at_risk',
                              compliance_percentage: Math.min((15 / metrics.mtta) * 100, 100).toFixed(1),
                              description: 'Average time taken to acknowledge alerts',
                              details: metrics
                            })}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>First Response Time</TableCell>
                      <TableCell>{Math.round(metrics.first_response_time)}m</TableCell>
                      <TableCell>30m</TableCell>
                      <TableCell>
                        <Chip 
                          label={metrics.first_response_time <= 30 ? 'Compliant' : 'At Risk'} 
                          color={metrics.first_response_time <= 30 ? 'success' : 'warning'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton
                            size="small"
                            onClick={() => handleViewMetricDetails({
                              id: 'first_response_time',
                              name: 'First Response Time',
                              type: 'Time-based',
                              value: `${Math.round(metrics.first_response_time)}m`,
                              target: '30m',
                              status: metrics.first_response_time <= 30 ? 'compliant' : 'at_risk',
                              compliance_percentage: Math.min((30 / metrics.first_response_time) * 100, 100).toFixed(1),
                              description: 'Time to first response on incidents',
                              details: metrics
                            })}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Resolution Rate</TableCell>
                      <TableCell>{metrics.resolution_rate.toFixed(1)}%</TableCell>
                      <TableCell>95%</TableCell>
                      <TableCell>
                        <Chip 
                          label={metrics.resolution_rate >= 95 ? 'Compliant' : 'At Risk'} 
                          color={metrics.resolution_rate >= 95 ? 'success' : 'warning'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton
                            size="small"
                            onClick={() => handleViewMetricDetails({
                              id: 'resolution_rate',
                              name: 'Resolution Rate',
                              type: 'Percentage',
                              value: `${metrics.resolution_rate.toFixed(1)}%`,
                              target: '95%',
                              status: metrics.resolution_rate >= 95 ? 'compliant' : 'at_risk',
                              compliance_percentage: metrics.resolution_rate.toFixed(1),
                              description: 'Percentage of incidents successfully resolved',
                              details: metrics
                            })}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
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

export default SLAMetrics;
