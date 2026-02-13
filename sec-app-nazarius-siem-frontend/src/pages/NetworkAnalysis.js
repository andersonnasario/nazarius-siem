import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  LinearProgress,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Info as InfoIcon,
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Public as PublicIcon,
} from '@mui/icons-material';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { networkAPI } from '../services/api';

function TabPanel({ children, value, index }) {
  return (
    <div hidden={value !== index}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

export default function NetworkAnalysis() {
  const [loading, setLoading] = useState(true);
  const [tabValue, setTabValue] = useState(0);
  const [dashboard, setDashboard] = useState(null);
  const [flows, setFlows] = useState([]);
  const [connections, setConnections] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [selectedAnomaly, setSelectedAnomaly] = useState(null);
  const [flowDialogOpen, setFlowDialogOpen] = useState(false);
  const [anomalyDialogOpen, setAnomalyDialogOpen] = useState(false);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    setLoading(true);
    try {
      const data = await networkAPI.getDashboard();
      setDashboard(data);
      
      // Load additional data
      const flowsData = await networkAPI.getFlows();
      setFlows(flowsData.flows || []);
      
      const connsData = await networkAPI.getConnections();
      setConnections(connsData.connections || []);
      
      const anomsData = await networkAPI.getAnomalies();
      setAnomalies(anomsData.anomalies || []);
      
    } catch (error) {
      console.error('Error loading network dashboard:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFlowClick = (flow) => {
    setSelectedFlow(flow);
    setFlowDialogOpen(true);
  };

  const handleAnomalyClick = (anomaly) => {
    setSelectedAnomaly(anomaly);
    setAnomalyDialogOpen(true);
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getRiskColor = (risk) => {
    switch (risk?.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#fbc02d';
      case 'low': return '#388e3c';
      default: return '#757575';
    }
  };

  const formatBytes = (bytes) => {
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return bytes + ' B';
  };

  const formatBps = (bps) => {
    if (bps >= 1000000000) return (bps / 1000000000).toFixed(2) + ' Gbps';
    if (bps >= 1000000) return (bps / 1000000).toFixed(2) + ' Mbps';
    if (bps >= 1000) return (bps / 1000).toFixed(2) + ' Kbps';
    return bps + ' bps';
  };

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D', '#FFC658', '#FF6B9D'];

  if (loading || !dashboard) {
    return (
      <Container maxWidth="xl">
        <Box sx={{ mt: 4 }}>
          <LinearProgress />
          <Typography sx={{ mt: 2, textAlign: 'center' }}>Carregando análise de rede...</Typography>
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl">
      <Box sx={{ mt: 4, mb: 4 }}>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 600 }}>
            🌐 Network Traffic Analysis
          </Typography>
          <IconButton onClick={loadDashboard} color="primary">
            <RefreshIcon />
          </IconButton>
        </Box>

        {/* KPI Cards */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Active Flows
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 600 }}>
                  {dashboard.active_flows?.toLocaleString()}
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                  <TrendingUpIcon color="success" fontSize="small" />
                  <Typography variant="body2" color="success.main" sx={{ ml: 0.5 }}>
                    +12% vs last hour
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total Connections
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 600 }}>
                  {dashboard.total_connections?.toLocaleString()}
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                  <TrendingUpIcon color="success" fontSize="small" />
                  <Typography variant="body2" color="success.main" sx={{ ml: 0.5 }}>
                    +5% vs last hour
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Bandwidth Usage
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 600 }}>
                  {dashboard.bandwidth_usage?.toFixed(1)}%
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={dashboard.bandwidth_usage} 
                  sx={{ mt: 1, height: 8, borderRadius: 4 }}
                  color={dashboard.bandwidth_usage > 80 ? 'error' : dashboard.bandwidth_usage > 60 ? 'warning' : 'success'}
                />
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card sx={{ bgcolor: dashboard.anomalies_detected > 0 ? '#fff3e0' : 'background.paper' }}>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Anomalies Detected
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 600, color: dashboard.anomalies_detected > 0 ? '#f57c00' : 'text.primary' }}>
                  {dashboard.anomalies_detected}
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                  <WarningIcon color="warning" fontSize="small" />
                  <Typography variant="body2" color="warning.main" sx={{ ml: 0.5 }}>
                    Requires attention
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Tabs */}
        <Paper sx={{ mb: 3 }}>
          <Tabs value={tabValue} onChange={(e, newValue) => setTabValue(newValue)}>
            <Tab label="Overview" />
            <Tab label="Flows" />
            <Tab label="Connections" />
            <Tab label="Anomalies" />
            <Tab label="Geographic" />
          </Tabs>
        </Paper>

        {/* Tab 1: Overview */}
        <TabPanel value={tabValue} index={0}>
          <Grid container spacing={3}>
            {/* Bandwidth Trend */}
            <Grid item xs={12} md={8}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Bandwidth Trend (24h)
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={dashboard.bandwidth_trend || []}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(value) => new Date(value).toLocaleTimeString([], { hour: '2-digit' })}
                    />
                    <YAxis tickFormatter={(value) => formatBps(value)} />
                    <Tooltip 
                      formatter={(value) => formatBps(value)}
                      labelFormatter={(value) => new Date(value).toLocaleString()}
                    />
                    <Legend />
                    <Line type="monotone" dataKey="inbound_bps" stroke="#0088FE" name="Inbound" />
                    <Line type="monotone" dataKey="outbound_bps" stroke="#00C49F" name="Outbound" />
                  </LineChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* Protocol Distribution */}
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Protocol Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={dashboard.top_protocols || []}
                      dataKey="percentage"
                      nameKey="protocol"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      label={(entry) => `${entry.protocol} ${entry.percentage}%`}
                    >
                      {(dashboard.top_protocols || []).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* Top Talkers */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Top Talkers
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>IP Address</TableCell>
                        <TableCell>Hostname</TableCell>
                        <TableCell align="right">Sent</TableCell>
                        <TableCell align="right">Received</TableCell>
                        <TableCell align="right">Total</TableCell>
                        <TableCell align="right">Flows</TableCell>
                        <TableCell align="center">Risk Score</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {(dashboard.top_talkers || []).map((talker) => (
                        <TableRow key={talker.ip}>
                          <TableCell>{talker.ip}</TableCell>
                          <TableCell>{talker.hostname}</TableCell>
                          <TableCell align="right">{formatBytes(talker.bytes_sent)}</TableCell>
                          <TableCell align="right">{formatBytes(talker.bytes_received)}</TableCell>
                          <TableCell align="right" sx={{ fontWeight: 600 }}>{formatBytes(talker.total_bytes)}</TableCell>
                          <TableCell align="right">{talker.flow_count?.toLocaleString()}</TableCell>
                          <TableCell align="center">
                            <Chip 
                              label={talker.risk_score} 
                              size="small"
                              sx={{ 
                                bgcolor: getRiskColor(
                                  talker.risk_score > 80 ? 'critical' : 
                                  talker.risk_score > 60 ? 'high' : 
                                  talker.risk_score > 40 ? 'medium' : 'low'
                                ),
                                color: 'white'
                              }}
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>

            {/* Recent Anomalies */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Recent Anomalies
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Type</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Source IP</TableCell>
                        <TableCell>Destination IP</TableCell>
                        <TableCell>Description</TableCell>
                        <TableCell>Detected At</TableCell>
                        <TableCell align="center">Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {(dashboard.recent_anomalies || []).map((anomaly) => (
                        <TableRow key={anomaly.id}>
                          <TableCell>
                            <Chip label={anomaly.type} size="small" variant="outlined" />
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={anomaly.severity} 
                              size="small" 
                              color={getSeverityColor(anomaly.severity)}
                            />
                          </TableCell>
                          <TableCell>{anomaly.source_ip}</TableCell>
                          <TableCell>{anomaly.dest_ip}</TableCell>
                          <TableCell>{anomaly.description}</TableCell>
                          <TableCell>{new Date(anomaly.detected_at).toLocaleString()}</TableCell>
                          <TableCell align="center">
                            <IconButton size="small" onClick={() => handleAnomalyClick(anomaly)}>
                              <InfoIcon />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 2: Flows */}
        <TabPanel value={tabValue} index={1}>
          <Paper sx={{ p: 3 }}>
            <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="h6">
                Network Flows
              </Typography>
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Protocol</InputLabel>
                <Select value={protocolFilter} onChange={(e) => setProtocolFilter(e.target.value)}>
                  <MenuItem value="all">All Protocols</MenuItem>
                  <MenuItem value="HTTPS">HTTPS</MenuItem>
                  <MenuItem value="HTTP">HTTP</MenuItem>
                  <MenuItem value="DNS">DNS</MenuItem>
                  <MenuItem value="SSH">SSH</MenuItem>
                  <MenuItem value="RDP">RDP</MenuItem>
                </Select>
              </FormControl>
            </Box>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Source IP</TableCell>
                    <TableCell>Destination IP</TableCell>
                    <TableCell>Protocol</TableCell>
                    <TableCell align="right">Bytes Sent</TableCell>
                    <TableCell align="right">Bytes Received</TableCell>
                    <TableCell align="right">Duration</TableCell>
                    <TableCell>Country</TableCell>
                    <TableCell align="center">Threat Score</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {flows.filter(f => protocolFilter === 'all' || f.protocol === protocolFilter).map((flow) => (
                    <TableRow 
                      key={flow.id}
                      sx={{ bgcolor: flow.is_anomaly ? '#fff3e0' : 'inherit' }}
                    >
                      <TableCell>{flow.source_ip}:{flow.source_port}</TableCell>
                      <TableCell>{flow.dest_ip}:{flow.dest_port}</TableCell>
                      <TableCell>
                        <Chip label={flow.protocol} size="small" />
                      </TableCell>
                      <TableCell align="right">{formatBytes(flow.bytes_sent)}</TableCell>
                      <TableCell align="right">{formatBytes(flow.bytes_received)}</TableCell>
                      <TableCell align="right">{flow.duration}s</TableCell>
                      <TableCell>{flow.country}</TableCell>
                      <TableCell align="center">
                        <Chip 
                          label={flow.threat_score} 
                          size="small"
                          color={flow.threat_score > 70 ? 'error' : flow.threat_score > 40 ? 'warning' : 'success'}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <IconButton size="small" onClick={() => handleFlowClick(flow)}>
                          <InfoIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </TabPanel>

        {/* Tab 3: Connections */}
        <TabPanel value={tabValue} index={2}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Active Connections
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Source IP</TableCell>
                    <TableCell>Destination IP</TableCell>
                    <TableCell>Protocol</TableCell>
                    <TableCell>State</TableCell>
                    <TableCell align="right">Duration</TableCell>
                    <TableCell align="right">Total Bytes</TableCell>
                    <TableCell>Application</TableCell>
                    <TableCell align="center">Risk</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {connections.map((conn) => (
                    <TableRow key={conn.id}>
                      <TableCell>{conn.source_ip}:{conn.source_port}</TableCell>
                      <TableCell>{conn.dest_ip}:{conn.dest_port}</TableCell>
                      <TableCell>
                        <Chip label={conn.protocol} size="small" />
                      </TableCell>
                      <TableCell>
                        <Chip label={conn.state} size="small" color="success" />
                      </TableCell>
                      <TableCell align="right">{conn.duration}s</TableCell>
                      <TableCell align="right">{formatBytes(conn.bytes_total)}</TableCell>
                      <TableCell>{conn.application}</TableCell>
                      <TableCell align="center">
                        <Chip 
                          label={conn.risk} 
                          size="small"
                          color={getSeverityColor(conn.risk)}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </TabPanel>

        {/* Tab 4: Anomalies */}
        <TabPanel value={tabValue} index={3}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Network Anomalies
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Source IP</TableCell>
                    <TableCell>Destination IP</TableCell>
                    <TableCell>Description</TableCell>
                    <TableCell>Detected At</TableCell>
                    <TableCell align="center">Confidence</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {anomalies.map((anomaly) => (
                    <TableRow key={anomaly.id}>
                      <TableCell>
                        <Chip label={anomaly.type} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={anomaly.severity} 
                          size="small" 
                          color={getSeverityColor(anomaly.severity)}
                        />
                      </TableCell>
                      <TableCell>{anomaly.source_ip}</TableCell>
                      <TableCell>{anomaly.dest_ip}</TableCell>
                      <TableCell>{anomaly.description}</TableCell>
                      <TableCell>{new Date(anomaly.detected_at).toLocaleString()}</TableCell>
                      <TableCell align="center">
                        <Chip label={`${anomaly.confidence_score}%`} size="small" />
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={anomaly.status} 
                          size="small"
                          color={anomaly.status === 'confirmed' ? 'error' : anomaly.status === 'investigating' ? 'warning' : 'default'}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <IconButton size="small" onClick={() => handleAnomalyClick(anomaly)}>
                          <InfoIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </TabPanel>

        {/* Tab 5: Geographic */}
        <TabPanel value={tabValue} index={4}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  <PublicIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  Geographic Distribution
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Country</TableCell>
                        <TableCell>City</TableCell>
                        <TableCell align="right">Flow Count</TableCell>
                        <TableCell align="right">Total Bytes</TableCell>
                        <TableCell align="center">Threat Level</TableCell>
                        <TableCell>Coordinates</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {(dashboard.geo_distribution || []).map((location, index) => (
                        <TableRow key={index}>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              {location.country_code && (
                                <Box
                                  component="span"
                                  sx={{ 
                                    mr: 1, 
                                    fontSize: '1.5em'
                                  }}
                                >
                                  {String.fromCodePoint(...location.country_code.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0)))}
                                </Box>
                              )}
                              {location.country}
                            </Box>
                          </TableCell>
                          <TableCell>{location.city}</TableCell>
                          <TableCell align="right">{location.flow_count?.toLocaleString()}</TableCell>
                          <TableCell align="right">{formatBytes(location.bytes_total)}</TableCell>
                          <TableCell align="center">
                            <Chip 
                              label={location.threat_level} 
                              size="small"
                              color={getSeverityColor(location.threat_level)}
                            />
                          </TableCell>
                          <TableCell>
                            {location.latitude.toFixed(4)}, {location.longitude.toFixed(4)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Flow Details Dialog */}
        <Dialog open={flowDialogOpen} onClose={() => setFlowDialogOpen(false)} maxWidth="md" fullWidth>
          <DialogTitle>Flow Details</DialogTitle>
          <DialogContent>
            {selectedFlow && (
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Source</Typography>
                  <Typography variant="body1">{selectedFlow.source_ip}:{selectedFlow.source_port}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Destination</Typography>
                  <Typography variant="body1">{selectedFlow.dest_ip}:{selectedFlow.dest_port}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Protocol</Typography>
                  <Typography variant="body1">{selectedFlow.protocol}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Duration</Typography>
                  <Typography variant="body1">{selectedFlow.duration}s</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Bytes Sent</Typography>
                  <Typography variant="body1">{formatBytes(selectedFlow.bytes_sent)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Bytes Received</Typography>
                  <Typography variant="body1">{formatBytes(selectedFlow.bytes_received)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Location</Typography>
                  <Typography variant="body1">{selectedFlow.city}, {selectedFlow.country}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">ASN</Typography>
                  <Typography variant="body1">{selectedFlow.asn}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">Flags</Typography>
                  <Box sx={{ mt: 1 }}>
                    {selectedFlow.flags?.map((flag, index) => (
                      <Chip key={index} label={flag} size="small" sx={{ mr: 1 }} />
                    ))}
                  </Box>
                </Grid>
              </Grid>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setFlowDialogOpen(false)}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* Anomaly Details Dialog */}
        <Dialog open={anomalyDialogOpen} onClose={() => setAnomalyDialogOpen(false)} maxWidth="md" fullWidth>
          <DialogTitle>Anomaly Details</DialogTitle>
          <DialogContent>
            {selectedAnomaly && (
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Chip 
                    label={selectedAnomaly.severity} 
                    color={getSeverityColor(selectedAnomaly.severity)}
                    sx={{ mr: 1 }}
                  />
                  <Chip label={selectedAnomaly.type} variant="outlined" />
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">Description</Typography>
                  <Typography variant="body1">{selectedAnomaly.description}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Source IP</Typography>
                  <Typography variant="body1">{selectedAnomaly.source_ip}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Destination IP</Typography>
                  <Typography variant="body1">{selectedAnomaly.dest_ip}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Flow Count</Typography>
                  <Typography variant="body1">{selectedAnomaly.flow_count}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Total Bytes</Typography>
                  <Typography variant="body1">{formatBytes(selectedAnomaly.bytes_total)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Confidence Score</Typography>
                  <Typography variant="body1">{selectedAnomaly.confidence_score}%</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Status</Typography>
                  <Chip label={selectedAnomaly.status} size="small" />
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">MITRE ATT&CK IDs</Typography>
                  <Box sx={{ mt: 1 }}>
                    {selectedAnomaly.mitre_ids?.map((id, index) => (
                      <Chip key={index} label={id} size="small" sx={{ mr: 1 }} color="primary" />
                    ))}
                  </Box>
                </Grid>
                {selectedAnomaly.assigned_to && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" color="textSecondary">Assigned To</Typography>
                    <Typography variant="body1">{selectedAnomaly.assigned_to}</Typography>
                  </Grid>
                )}
              </Grid>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setAnomalyDialogOpen(false)}>Close</Button>
            <Button variant="contained" color="primary">
              Investigate
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Container>
  );
}

