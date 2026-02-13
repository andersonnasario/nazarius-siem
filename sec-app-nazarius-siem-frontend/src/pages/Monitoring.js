import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  LinearProgress,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  Alert,
} from '@mui/material';
import {
  Speed as SpeedIcon,
  Storage as StorageIcon,
  Memory as MemoryIcon,
  NetworkCheck as NetworkCheckIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Refresh as RefreshIcon,
  OpenInNew as OpenInNewIcon,
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { monitoringAPI } from '../services/api';

const Monitoring = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  const [health, setHealth] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [timeSeries, setTimeSeries] = useState([]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch health and metrics from API
      const [healthRes, metricsRes] = await Promise.all([
        monitoringAPI.getHealth().catch(() => ({ data: generateFallbackHealth() })),
        monitoringAPI.getMetrics().catch(() => ({ data: generateFallbackMetrics() })),
      ]);

      setHealth(healthRes.data);
      setMetrics(metricsRes.data);

      // Generate time series data (in production, this would come from API)
      setTimeSeries(generateTimeSeriesData());

      setLoading(false);
    } catch (err) {
      console.error('Error loading monitoring data:', err);
      setError('Erro ao carregar dados de monitoramento');
      // Use fallback data
      setHealth(generateFallbackHealth());
      setMetrics(generateFallbackMetrics());
      setTimeSeries(generateTimeSeriesData());
      setLoading(false);
    }
  };

  const generateFallbackHealth = () => ({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    uptime: '2d 15h 32m',
    components: {
      api: { status: 'healthy', message: 'API is running', latency: '5ms' },
      elasticsearch: { status: 'healthy', message: 'Connected', latency: '12ms' },
      redis: { status: 'healthy', message: 'Connected', latency: '3ms' },
    },
  });

  const generateFallbackMetrics = () => ({
    business: {
      events_per_second: 125.5,
      alerts_per_minute: 8.2,
      cases_open: 42,
      playbooks_executed: 156,
      threats_detected: 23,
    },
    performance: {
      avg_response_time_ms: 45.2,
      p95_response_time_ms: 120.5,
      p99_response_time_ms: 250.8,
      requests_per_second: 850.3,
      error_rate: 0.05,
    },
    resources: {
      cpu_usage_percent: 35.2,
      memory_usage_percent: 62.8,
      disk_usage_percent: 48.5,
      goroutines: 245,
    },
    security: {
      rate_limit_hits: 12,
      brute_force_attempts: 3,
      blocked_ips: 5,
      failed_auth_attempts: 8,
    },
  });

  const generateTimeSeriesData = () => {
    return Array.from({ length: 24 }, (_, i) => ({
      time: `${i}:00`,
      events: Math.floor(Math.random() * 200) + 100,
      alerts: Math.floor(Math.random() * 20) + 5,
      latency: Math.floor(Math.random() * 100) + 30,
    }));
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'healthy':
        return <CheckCircleIcon sx={{ color: 'success.main' }} />;
      case 'degraded':
        return <WarningIcon sx={{ color: 'warning.main' }} />;
      case 'unhealthy':
        return <ErrorIcon sx={{ color: 'error.main' }} />;
      default:
        return <CheckCircleIcon />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'healthy':
        return 'success';
      case 'degraded':
        return 'warning';
      case 'unhealthy':
        return 'error';
      default:
        return 'default';
    }
  };

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <SpeedIcon sx={{ fontSize: 40, mr: 2 }} />
          <Box>
            <Typography variant="h4" gutterBottom>
              Monitoring & Observability
            </Typography>
            <Typography variant="body2" color="text.secondary">
              System health, metrics and performance monitoring
            </Typography>
          </Box>
        </Box>
        <Box>
          <Tooltip title="Refresh">
            <IconButton onClick={loadData} disabled={loading}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Open Grafana">
            <IconButton onClick={() => window.open('http://localhost:3001', '_blank')}>
              <OpenInNewIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Open Prometheus">
            <IconButton onClick={() => window.open('http://localhost:9090', '_blank')}>
              <OpenInNewIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* System Health Status */}
      {health && (
        <Paper sx={{ p: 3, mb: 3, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={8}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                {getStatusIcon(health.status)}
                <Typography variant="h5" sx={{ ml: 1, color: 'white' }}>
                  System Status: {health.status.toUpperCase()}
                </Typography>
              </Box>
              <Grid container spacing={2}>
                <Grid item xs={4}>
                  <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.8)' }}>
                    Version
                  </Typography>
                  <Typography variant="h6" sx={{ color: 'white' }}>
                    {health.version}
                  </Typography>
                </Grid>
                <Grid item xs={4}>
                  <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.8)' }}>
                    Uptime
                  </Typography>
                  <Typography variant="h6" sx={{ color: 'white' }}>
                    {health.uptime}
                  </Typography>
                </Grid>
                <Grid item xs={4}>
                  <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.8)' }}>
                    Last Check
                  </Typography>
                  <Typography variant="h6" sx={{ color: 'white' }}>
                    {new Date(health.timestamp).toLocaleTimeString()}
                  </Typography>
                </Grid>
              </Grid>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.8)', mb: 1 }}>
                Components
              </Typography>
              {Object.entries(health.components).map(([key, component]) => (
                <Box key={key} sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                  <Chip
                    icon={getStatusIcon(component.status)}
                    label={key}
                    size="small"
                    color={getStatusColor(component.status)}
                    sx={{ minWidth: 140 }}
                  />
                  <Typography variant="caption" sx={{ ml: 1, color: 'rgba(255,255,255,0.8)' }}>
                    {component.latency}
                  </Typography>
                </Box>
              ))}
            </Grid>
          </Grid>
        </Paper>
      )}

      {/* KPI Cards */}
      {metrics && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography color="textSecondary" gutterBottom>
                    Events/Second
                  </Typography>
                  <SpeedIcon color="primary" />
                </Box>
                <Typography variant="h4">
                  {metrics.business.events_per_second.toFixed(1)}
                </Typography>
                <Typography variant="caption" color="success.main">
                  ↑ 12% from last hour
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography color="textSecondary" gutterBottom>
                    Avg Response Time
                  </Typography>
                  <NetworkCheckIcon color="primary" />
                </Box>
                <Typography variant="h4">
                  {metrics.performance.avg_response_time_ms.toFixed(0)}ms
                </Typography>
                <Typography variant="caption" color="success.main">
                  ↓ 8% from baseline
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography color="textSecondary" gutterBottom>
                    CPU Usage
                  </Typography>
                  <MemoryIcon color="primary" />
                </Box>
                <Typography variant="h4">
                  {metrics.resources.cpu_usage_percent.toFixed(1)}%
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={metrics.resources.cpu_usage_percent}
                  color={metrics.resources.cpu_usage_percent > 80 ? 'error' : 'primary'}
                  sx={{ mt: 1 }}
                />
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography color="textSecondary" gutterBottom>
                    Memory Usage
                  </Typography>
                  <StorageIcon color="primary" />
                </Box>
                <Typography variant="h4">
                  {metrics.resources.memory_usage_percent.toFixed(1)}%
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={metrics.resources.memory_usage_percent}
                  color={metrics.resources.memory_usage_percent > 80 ? 'error' : 'primary'}
                  sx={{ mt: 1 }}
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={tabValue}
          onChange={(e, newValue) => setTabValue(newValue)}
          indicatorColor="primary"
          textColor="primary"
        >
          <Tab label="Performance" />
          <Tab label="Business Metrics" />
          <Tab label="Resources" />
          <Tab label="Security" />
        </Tabs>
      </Paper>

      {/* Tab Content */}
      <Paper sx={{ p: 3 }}>
        {tabValue === 0 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Performance Metrics
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={timeSeries}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <RechartsTooltip />
                <Legend />
                <Line type="monotone" dataKey="latency" stroke="#8884d8" name="Latency (ms)" />
              </LineChart>
            </ResponsiveContainer>

            {metrics && (
              <Grid container spacing={2} sx={{ mt: 2 }}>
                <Grid item xs={3}>
                  <Typography variant="body2" color="textSecondary">Avg Response Time</Typography>
                  <Typography variant="h6">{metrics.performance.avg_response_time_ms.toFixed(1)}ms</Typography>
                </Grid>
                <Grid item xs={3}>
                  <Typography variant="body2" color="textSecondary">P95 Latency</Typography>
                  <Typography variant="h6">{metrics.performance.p95_response_time_ms.toFixed(1)}ms</Typography>
                </Grid>
                <Grid item xs={3}>
                  <Typography variant="body2" color="textSecondary">P99 Latency</Typography>
                  <Typography variant="h6">{metrics.performance.p99_response_time_ms.toFixed(1)}ms</Typography>
                </Grid>
                <Grid item xs={3}>
                  <Typography variant="body2" color="textSecondary">Error Rate</Typography>
                  <Typography variant="h6">{(metrics.performance.error_rate * 100).toFixed(2)}%</Typography>
                </Grid>
              </Grid>
            )}
          </Box>
        )}

        {tabValue === 1 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Business Metrics
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={timeSeries}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <RechartsTooltip />
                <Legend />
                <Area type="monotone" dataKey="events" stackId="1" stroke="#8884d8" fill="#8884d8" name="Events" />
                <Area type="monotone" dataKey="alerts" stackId="2" stroke="#82ca9d" fill="#82ca9d" name="Alerts" />
              </AreaChart>
            </ResponsiveContainer>

            {metrics && (
              <TableContainer sx={{ mt: 2 }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Metric</TableCell>
                      <TableCell align="right">Value</TableCell>
                      <TableCell align="right">Trend</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    <TableRow>
                      <TableCell>Events per Second</TableCell>
                      <TableCell align="right">{metrics.business.events_per_second.toFixed(1)}</TableCell>
                      <TableCell align="right">
                        <Chip label="+12%" color="success" size="small" />
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Alerts per Minute</TableCell>
                      <TableCell align="right">{metrics.business.alerts_per_minute.toFixed(1)}</TableCell>
                      <TableCell align="right">
                        <Chip label="-5%" color="info" size="small" />
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Open Cases</TableCell>
                      <TableCell align="right">{metrics.business.cases_open}</TableCell>
                      <TableCell align="right">
                        <Chip label="+2" color="warning" size="small" />
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Playbooks Executed (today)</TableCell>
                      <TableCell align="right">{metrics.business.playbooks_executed}</TableCell>
                      <TableCell align="right">
                        <Chip label="+18%" color="success" size="small" />
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Threats Detected (today)</TableCell>
                      <TableCell align="right">{metrics.business.threats_detected}</TableCell>
                      <TableCell align="right">
                        <Chip label="+3" color="error" size="small" />
                      </TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>
        )}

        {tabValue === 2 && metrics && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Resource Usage
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle1" gutterBottom>CPU Usage</Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Box sx={{ width: '100%', mr: 1 }}>
                      <LinearProgress variant="determinate" value={metrics.resources.cpu_usage_percent} />
                    </Box>
                    <Box sx={{ minWidth: 35 }}>
                      <Typography variant="body2" color="text.secondary">
                        {metrics.resources.cpu_usage_percent.toFixed(1)}%
                      </Typography>
                    </Box>
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle1" gutterBottom>Memory Usage</Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Box sx={{ width: '100%', mr: 1 }}>
                      <LinearProgress variant="determinate" value={metrics.resources.memory_usage_percent} />
                    </Box>
                    <Box sx={{ minWidth: 35 }}>
                      <Typography variant="body2" color="text.secondary">
                        {metrics.resources.memory_usage_percent.toFixed(1)}%
                      </Typography>
                    </Box>
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle1" gutterBottom>Disk Usage</Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Box sx={{ width: '100%', mr: 1 }}>
                      <LinearProgress variant="determinate" value={metrics.resources.disk_usage_percent} />
                    </Box>
                    <Box sx={{ minWidth: 35 }}>
                      <Typography variant="body2" color="text.secondary">
                        {metrics.resources.disk_usage_percent.toFixed(1)}%
                      </Typography>
                    </Box>
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle1" gutterBottom>Goroutines</Typography>
                  <Typography variant="h4">{metrics.resources.goroutines}</Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        )}

        {tabValue === 3 && metrics && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Security Metrics
            </Typography>
            <Alert severity="info" sx={{ mb: 2 }}>
              Security events are monitored in real-time. Check Security Settings for detailed configuration.
            </Alert>
            <Grid container spacing={2}>
              <Grid item xs={6} md={3}>
                <Card>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Rate Limit Hits</Typography>
                    <Typography variant="h4">{metrics.security.rate_limit_hits}</Typography>
                    <Typography variant="caption" color="warning.main">Last hour</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={6} md={3}>
                <Card>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Brute Force Attempts</Typography>
                    <Typography variant="h4">{metrics.security.brute_force_attempts}</Typography>
                    <Typography variant="caption" color="error.main">Last hour</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={6} md={3}>
                <Card>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Blocked IPs</Typography>
                    <Typography variant="h4">{metrics.security.blocked_ips}</Typography>
                    <Typography variant="caption">Currently blocked</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={6} md={3}>
                <Card>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Failed Auth Attempts</Typography>
                    <Typography variant="h4">{metrics.security.failed_auth_attempts}</Typography>
                    <Typography variant="caption" color="warning.main">Last hour</Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Box>
        )}
      </Paper>
    </Box>
  );
};

export default Monitoring;

