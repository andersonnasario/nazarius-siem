import React, { useState, useEffect } from 'react';
import {
  Box, Grid, Paper, Typography, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, IconButton, Dialog, DialogTitle, DialogContent, DialogActions,
  Button, TextField, MenuItem, LinearProgress, Tooltip
} from '@mui/material';
import {
  NetworkCheck as NetworkIcon,
  Storage as ServerIcon,
  Speed as SpeedIcon,
  Warning as WarningIcon,
  Public as PublicIcon,
  TrendingUp as TrendingUpIcon,
  Security as SecurityIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import { LineChart, Line, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';
import { networkAPI } from '../services/api';

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8', '#82ca9d', '#ffc658', '#ff7c7c'];

function NetworkTraffic() {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [dashboard, setDashboard] = useState(null);
  const [flows, setFlows] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [selectedAnomaly, setSelectedAnomaly] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [filters, setFilters] = useState({
    protocol: '',
    direction: '',
    threat: ''
  });

  useEffect(() => {
    loadDashboard();
    loadFlows();
    loadAnomalies();
  }, []);

  const loadDashboard = async () => {
    try {
      setLoading(true);
      const data = await networkAPI.getDashboard();
      setDashboard(data);
    } catch (error) {
      console.error('Error loading network dashboard:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadFlows = async () => {
    try {
      const data = await networkAPI.getFlows(filters);
      setFlows(data.flows || []);
    } catch (error) {
      console.error('Error loading flows:', error);
    }
  };

  const loadAnomalies = async () => {
    try {
      const data = await networkAPI.getAnomalies();
      setAnomalies(data.anomalies || []);
    } catch (error) {
      console.error('Error loading anomalies:', error);
    }
  };

  const handleViewAnomalyDetails = async (anomaly) => {
    try {
      const details = await networkAPI.getAnomalyDetails(anomaly.id);
      setSelectedAnomaly(details);
      setDetailsOpen(true);
    } catch (error) {
      console.error('Error loading anomaly details:', error);
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const formatBandwidth = (bytesPerSec) => {
    return formatBytes(bytesPerSec) + '/s';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      low: '#4caf50',
      medium: '#ff9800',
      high: '#ff5722',
      critical: '#f44336'
    };
    return colors[severity] || '#9e9e9e';
  };

  const getThreatLevelColor = (level) => {
    const colors = {
      low: 'success',
      medium: 'warning',
      high: 'error'
    };
    return colors[level] || 'default';
  };

  const renderKPIs = () => {
    if (!dashboard) return null;

    return (
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Total Connections
                  </Typography>
                  <Typography variant="h4">
                    {dashboard.total_connections?.toLocaleString() || 0}
                  </Typography>
                  <Typography variant="caption" color="success.main">
                    {dashboard.active_connections} active
                  </Typography>
                </Box>
                <NetworkIcon sx={{ fontSize: 40, color: 'primary.main', opacity: 0.3 }} />
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
                    Total Bandwidth
                  </Typography>
                  <Typography variant="h4">
                    {formatBandwidth(dashboard.total_bandwidth)}
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    Current throughput
                  </Typography>
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
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Threats Detected
                  </Typography>
                  <Typography variant="h4" color="error">
                    {dashboard.threats_detected}
                  </Typography>
                  <Typography variant="caption" color="error.main">
                    Requires attention
                  </Typography>
                </Box>
                <WarningIcon sx={{ fontSize: 40, color: 'error.main', opacity: 0.3 }} />
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
                    Active Flows
                  </Typography>
                  <Typography variant="h4">
                    {dashboard.active_connections}
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    Real-time monitoring
                  </Typography>
                </Box>
                <TrendingUpIcon sx={{ fontSize: 40, color: 'success.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    );
  };

  const renderOverviewTab = () => {
    if (!dashboard) return <Typography>Loading...</Typography>;

    return (
      <Grid container spacing={3}>
        {/* Bandwidth History Chart */}
        <Grid item xs={12} lg={8}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Bandwidth Usage (24h)
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={dashboard.bandwidth_history}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="timestamp" 
                  tickFormatter={(value) => new Date(value).toLocaleTimeString('en-US', { hour: '2-digit' })}
                />
                <YAxis tickFormatter={(value) => formatBandwidth(value)} />
                <RechartsTooltip 
                  labelFormatter={(value) => new Date(value).toLocaleString()}
                  formatter={(value) => formatBandwidth(value)}
                />
                <Legend />
                <Line type="monotone" dataKey="inbound" stroke="#8884d8" name="Inbound" />
                <Line type="monotone" dataKey="outbound" stroke="#82ca9d" name="Outbound" />
                <Line type="monotone" dataKey="total" stroke="#ffc658" name="Total" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        {/* Protocol Distribution */}
        <Grid item xs={12} lg={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Protocol Distribution
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={dashboard.protocol_distribution}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percentage }) => `${name} ${percentage.toFixed(1)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="connections"
                >
                  {dashboard.protocol_distribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        {/* Top Talkers */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom display="flex" alignItems="center">
              <TrendingUpIcon sx={{ mr: 1 }} /> Top Talkers (Outbound)
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>IP / Hostname</TableCell>
                    <TableCell align="right">Bytes</TableCell>
                    <TableCell align="right">Connections</TableCell>
                    <TableCell align="center">Threat</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {dashboard.top_talkers?.slice(0, 5).map((talker, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        <Typography variant="body2" fontWeight="bold">{talker.ip}</Typography>
                        <Typography variant="caption" color="textSecondary">{talker.hostname}</Typography>
                      </TableCell>
                      <TableCell align="right">{formatBytes(talker.total_bytes)}</TableCell>
                      <TableCell align="right">{talker.connections}</TableCell>
                      <TableCell align="center">
                        <Chip 
                          label={talker.threat_score} 
                          size="small"
                          color={talker.threat_score > 70 ? 'error' : talker.threat_score > 40 ? 'warning' : 'success'}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Grid>

        {/* Top Listeners */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom display="flex" alignItems="center">
              <ServerIcon sx={{ mr: 1 }} /> Top Listeners (Inbound)
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>IP / Hostname</TableCell>
                    <TableCell align="right">Bytes</TableCell>
                    <TableCell align="right">Connections</TableCell>
                    <TableCell align="center">Threat</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {dashboard.top_listeners?.slice(0, 5).map((listener, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        <Typography variant="body2" fontWeight="bold">{listener.ip}</Typography>
                        <Typography variant="caption" color="textSecondary">{listener.hostname}</Typography>
                      </TableCell>
                      <TableCell align="right">{formatBytes(listener.total_bytes)}</TableCell>
                      <TableCell align="right">{listener.connections}</TableCell>
                      <TableCell align="center">
                        <Chip 
                          label={listener.threat_score} 
                          size="small"
                          color={listener.threat_score > 70 ? 'error' : listener.threat_score > 40 ? 'warning' : 'success'}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Grid>

        {/* Geographic Distribution */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom display="flex" alignItems="center">
              <PublicIcon sx={{ mr: 1 }} /> Geographic Distribution
            </Typography>
            <Grid container spacing={2}>
              {dashboard.geo_distribution?.map((geo, index) => (
                <Grid item xs={12} sm={6} md={3} key={index}>
                  <Card variant="outlined">
                    <CardContent>
                      <Box display="flex" justifyContent="space-between" alignItems="center">
                        <Box>
                          <Typography variant="body2" fontWeight="bold">
                            {geo.country}
                          </Typography>
                          <Typography variant="caption" color="textSecondary">
                            {geo.city}
                          </Typography>
                        </Box>
                        <Chip 
                          label={geo.threat_level.toUpperCase()} 
                          size="small" 
                          color={getThreatLevelColor(geo.threat_level)}
                        />
                      </Box>
                      <Box mt={2}>
                        <Typography variant="caption" color="textSecondary">
                          Connections: {geo.connections}
                        </Typography>
                        <br />
                        <Typography variant="caption" color="textSecondary">
                          Data: {formatBytes(geo.bytes)}
                        </Typography>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Grid>
      </Grid>
    );
  };

  const renderFlowsTab = () => {
    return (
      <Paper sx={{ p: 3 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6">Network Flows</Typography>
          <Box display="flex" gap={2}>
            <TextField
              select
              size="small"
              label="Protocol"
              value={filters.protocol}
              onChange={(e) => setFilters({ ...filters, protocol: e.target.value })}
              sx={{ minWidth: 120 }}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="TCP">TCP</MenuItem>
              <MenuItem value="UDP">UDP</MenuItem>
              <MenuItem value="ICMP">ICMP</MenuItem>
              <MenuItem value="HTTP">HTTP</MenuItem>
              <MenuItem value="HTTPS">HTTPS</MenuItem>
            </TextField>
            <TextField
              select
              size="small"
              label="Direction"
              value={filters.direction}
              onChange={(e) => setFilters({ ...filters, direction: e.target.value })}
              sx={{ minWidth: 120 }}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="inbound">Inbound</MenuItem>
              <MenuItem value="outbound">Outbound</MenuItem>
              <MenuItem value="internal">Internal</MenuItem>
            </TextField>
            <TextField
              select
              size="small"
              label="Threat"
              value={filters.threat}
              onChange={(e) => setFilters({ ...filters, threat: e.target.value })}
              sx={{ minWidth: 120 }}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="true">Only Threats</MenuItem>
              <MenuItem value="false">Non-Threats</MenuItem>
            </TextField>
            <Button variant="contained" onClick={loadFlows}>Apply</Button>
          </Box>
        </Box>

        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Timestamp</TableCell>
                <TableCell>Source</TableCell>
                <TableCell>Destination</TableCell>
                <TableCell>Protocol</TableCell>
                <TableCell align="right">Bytes</TableCell>
                <TableCell align="right">Packets</TableCell>
                <TableCell align="center">Direction</TableCell>
                <TableCell align="center">Threat</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {flows.slice(0, 50).map((flow, index) => (
                <TableRow key={index} sx={{ bgcolor: flow.threat ? 'error.light' : 'inherit' }}>
                  <TableCell>{new Date(flow.timestamp).toLocaleString()}</TableCell>
                  <TableCell>
                    <Typography variant="body2">{flow.source_ip}:{flow.source_port}</Typography>
                    <Typography variant="caption" color="textSecondary">{flow.country}</Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">{flow.dest_ip}:{flow.dest_port}</Typography>
                  </TableCell>
                  <TableCell>
                    <Chip label={flow.protocol} size="small" />
                  </TableCell>
                  <TableCell align="right">{formatBytes(flow.bytes)}</TableCell>
                  <TableCell align="right">{flow.packets}</TableCell>
                  <TableCell align="center">
                    <Chip label={flow.direction} size="small" variant="outlined" />
                  </TableCell>
                  <TableCell align="center">
                    {flow.threat ? (
                      <Tooltip title={`${flow.threat_type} (Score: ${flow.threat_score})`}>
                        <Chip label="THREAT" size="small" color="error" icon={<WarningIcon />} />
                      </Tooltip>
                    ) : (
                      <Chip label="Safe" size="small" color="success" />
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>
    );
  };

  const renderAnomaliesTab = () => {
    return (
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom display="flex" alignItems="center">
          <SecurityIcon sx={{ mr: 1 }} /> Network Anomalies
        </Typography>

        <Grid container spacing={2}>
          {anomalies.map((anomaly) => (
            <Grid item xs={12} key={anomaly.id}>
              <Card 
                variant="outlined" 
                sx={{ 
                  borderLeft: 4, 
                  borderLeftColor: getSeverityColor(anomaly.severity)
                }}
              >
                <CardContent>
                  <Box display="flex" justifyContent="space-between" alignItems="flex-start">
                    <Box flex={1}>
                      <Box display="flex" alignItems="center" gap={1} mb={1}>
                        <Chip 
                          label={anomaly.severity.toUpperCase()} 
                          size="small" 
                          sx={{ bgcolor: getSeverityColor(anomaly.severity), color: 'white' }}
                        />
                        <Chip label={anomaly.type.replace(/_/g, ' ').toUpperCase()} size="small" variant="outlined" />
                        <Chip label={anomaly.status.toUpperCase()} size="small" />
                        <Typography variant="caption" color="textSecondary">
                          {new Date(anomaly.timestamp).toLocaleString()}
                        </Typography>
                      </Box>
                      
                      <Typography variant="h6" gutterBottom>
                        {anomaly.description}
                      </Typography>
                      
                      <Box display="flex" gap={3} mb={1}>
                        <Typography variant="body2">
                          <strong>Source:</strong> {anomaly.source_ip}
                        </Typography>
                        <Typography variant="body2">
                          <strong>Destination:</strong> {anomaly.dest_ip}
                        </Typography>
                        <Typography variant="body2">
                          <strong>Threat Score:</strong> {anomaly.score}/100
                        </Typography>
                      </Box>

                      <Box display="flex" gap={1} flexWrap="wrap">
                        {anomaly.indicators?.map((indicator, idx) => (
                          <Chip key={idx} label={indicator} size="small" variant="outlined" />
                        ))}
                      </Box>
                    </Box>

                    <IconButton 
                      color="primary" 
                      onClick={() => handleViewAnomalyDetails(anomaly)}
                    >
                      <InfoIcon />
                    </IconButton>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>
    );
  };

  const renderProtocolsTab = () => {
    if (!dashboard) return null;

    return (
      <Grid container spacing={3}>
        <Grid item xs={12} lg={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Protocol Statistics
            </Typography>
            <ResponsiveContainer width="100%" height={400}>
              <BarChart data={dashboard.protocol_distribution}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="protocol" />
                <YAxis yAxisId="left" orientation="left" stroke="#8884d8" />
                <YAxis yAxisId="right" orientation="right" stroke="#82ca9d" />
                <RechartsTooltip />
                <Legend />
                <Bar yAxisId="left" dataKey="connections" fill="#8884d8" name="Connections" />
                <Bar yAxisId="right" dataKey="bytes" fill="#82ca9d" name="Bytes" />
              </BarChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12} lg={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Protocol Details
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Protocol</TableCell>
                    <TableCell align="right">Connections</TableCell>
                    <TableCell align="right">Data</TableCell>
                    <TableCell align="right">Avg Duration</TableCell>
                    <TableCell align="right">%</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {dashboard.protocol_distribution?.map((protocol, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        <Chip label={protocol.protocol} />
                      </TableCell>
                      <TableCell align="right">{protocol.connections.toLocaleString()}</TableCell>
                      <TableCell align="right">{formatBytes(protocol.bytes)}</TableCell>
                      <TableCell align="right">{protocol.avg_duration.toFixed(1)}s</TableCell>
                      <TableCell align="right">
                        <Box display="flex" alignItems="center" justifyContent="flex-end">
                          <Box width={100} mr={1}>
                            <LinearProgress 
                              variant="determinate" 
                              value={protocol.percentage} 
                              sx={{ height: 8, borderRadius: 4 }}
                            />
                          </Box>
                          {protocol.percentage.toFixed(1)}%
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Grid>
      </Grid>
    );
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom display="flex" alignItems="center">
        <NetworkIcon sx={{ mr: 2, fontSize: 40 }} />
        Network Traffic Analysis
      </Typography>

      {loading && <LinearProgress sx={{ mb: 2 }} />}

      {renderKPIs()}

      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label="Overview" />
          <Tab label="Network Flows" />
          <Tab label="Anomalies" />
          <Tab label="Protocols" />
        </Tabs>
      </Paper>

      {activeTab === 0 && renderOverviewTab()}
      {activeTab === 1 && renderFlowsTab()}
      {activeTab === 2 && renderAnomaliesTab()}
      {activeTab === 3 && renderProtocolsTab()}

      {/* Anomaly Details Dialog */}
      <Dialog open={detailsOpen} onClose={() => setDetailsOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Anomaly Details
          {selectedAnomaly && (
            <Chip 
              label={selectedAnomaly.severity.toUpperCase()} 
              size="small" 
              sx={{ ml: 2, bgcolor: getSeverityColor(selectedAnomaly.severity), color: 'white' }}
            />
          )}
        </DialogTitle>
        <DialogContent>
          {selectedAnomaly && (
            <Box>
              <Typography variant="h6" gutterBottom>
                {selectedAnomaly.description}
              </Typography>
              
              <Grid container spacing={2} sx={{ mt: 2 }}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Type</Typography>
                  <Typography variant="body1">{selectedAnomaly.type.replace(/_/g, ' ')}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Threat Score</Typography>
                  <Typography variant="body1">{selectedAnomaly.score}/100</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Source IP</Typography>
                  <Typography variant="body1">{selectedAnomaly.source_ip}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Destination IP</Typography>
                  <Typography variant="body1">{selectedAnomaly.dest_ip}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="body2" color="textSecondary">Timestamp</Typography>
                  <Typography variant="body1">{new Date(selectedAnomaly.timestamp).toLocaleString()}</Typography>
                </Grid>
              </Grid>

              <Box mt={3}>
                <Typography variant="h6" gutterBottom>Indicators</Typography>
                {selectedAnomaly.indicators?.map((indicator, idx) => (
                  <Chip key={idx} label={indicator} sx={{ m: 0.5 }} />
                ))}
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsOpen(false)}>Close</Button>
          <Button variant="contained" color="primary">Create Case</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default NetworkTraffic;
