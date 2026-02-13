import React, { useState, useEffect } from 'react';
import {
  Box, Container, Grid, Card, CardContent, Typography, Tab, Tabs, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Paper, Chip, IconButton, Button, Dialog, DialogTitle,
  DialogContent, DialogActions, TextField, Alert, LinearProgress, Tooltip, MenuItem, Select,
  FormControl, InputLabel, List, ListItem, ListItemText, ListItemIcon,
} from '@mui/material';
import {
  Computer as ComputerIcon, Security as SecurityIcon, Warning as WarningIcon,
  CheckCircle as CheckCircleIcon, Block as BlockIcon, Delete as DeleteIcon, Visibility as VisibilityIcon,
  PlayArrow as PlayArrowIcon, Stop as StopIcon, Memory as MemoryIcon, Assessment as AssessmentIcon,
  CloudDownload as CloudDownloadIcon, TrendingUp as TrendingUpIcon, TrendingDown as TrendingDownIcon,
  Storage as StorageIcon, Speed as SpeedIcon, Close as CloseIcon, Refresh as RefreshIcon,
  Download as DownloadIcon,
} from '@mui/icons-material';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';
import { edrAPI } from '../services/api';

const COLORS = ['#1976d2', '#dc004e', '#f57c00', '#388e3c', '#9c27b0'];
const SEVERITY_COLORS = { critical: '#d32f2f', high: '#f57c00', medium: '#fbc02d', low: '#388e3c' };
const STATUS_COLORS = { online: '#388e3c', offline: '#757575', isolated: '#d32f2f', updating: '#1976d2' };
const THREAT_STATUS_COLORS = { detected: '#f57c00', quarantined: '#1976d2', removed: '#388e3c', whitelisted: '#757575' };

function EDR() {
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(0);
  const [dashboard, setDashboard] = useState(null);
  const [agents, setAgents] = useState([]);
  const [endpoints, setEndpoints] = useState([]);
  const [threats, setThreats] = useState([]);
  const [processes, setProcesses] = useState([]);
  const [memoryScans, setMemoryScans] = useState([]);
  const [forensics, setForensics] = useState([]);
  
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [agentDialogOpen, setAgentDialogOpen] = useState(false);
  const [threatDialogOpen, setThreatDialogOpen] = useState(false);
  const [isolateDialogOpen, setIsolateDialogOpen] = useState(false);
  const [scanDialogOpen, setScanDialogOpen] = useState(false);
  
  const [filters, setFilters] = useState({ agentStatus: '', threatSeverity: '', threatType: '' });

  useEffect(() => {
    loadDashboard();
    loadAgents();
    loadEndpoints();
    loadThreats();
    loadProcesses();
    loadMemoryScans();
    loadForensics();
  }, []);

  const loadDashboard = async () => {
    try {
      setLoading(true);
      const data = await edrAPI.getDashboard();
      setDashboard(data);
    } catch (error) {
      console.error('Error loading dashboard:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadAgents = async () => {
    try {
      const params = filters.agentStatus ? { status: filters.agentStatus } : {};
      const data = await edrAPI.getAgents(params);
      setAgents(data);
    } catch (error) {
      console.error('Error loading agents:', error);
    }
  };

  const loadEndpoints = async () => {
    try {
      const data = await edrAPI.getEndpoints();
      setEndpoints(data);
    } catch (error) {
      console.error('Error loading endpoints:', error);
    }
  };

  const loadThreats = async () => {
    try {
      const params = {};
      if (filters.threatSeverity) params.severity = filters.threatSeverity;
      if (filters.threatType) params.type = filters.threatType;
      const data = await edrAPI.getThreats(params);
      setThreats(data);
    } catch (error) {
      console.error('Error loading threats:', error);
    }
  };

  const loadProcesses = async () => {
    try {
      const data = await edrAPI.getProcesses({ suspicious: 'true' });
      setProcesses(data);
    } catch (error) {
      console.error('Error loading processes:', error);
    }
  };

  const loadMemoryScans = async () => {
    try {
      const data = await edrAPI.getMemoryScans();
      setMemoryScans(data);
    } catch (error) {
      console.error('Error loading memory scans:', error);
    }
  };

  const loadForensics = async () => {
    try {
      const data = await edrAPI.getForensics();
      setForensics(data);
    } catch (error) {
      console.error('Error loading forensics:', error);
    }
  };

  const handleIsolateEndpoint = async (endpointId, reason) => {
    try {
      await edrAPI.isolateEndpoint(endpointId, reason, 'Isolated due to threat');
      loadEndpoints();
      loadDashboard();
      setIsolateDialogOpen(false);
    } catch (error) {
      console.error('Error isolating endpoint:', error);
    }
  };

  const handleRestoreEndpoint = async (endpointId) => {
    try {
      await edrAPI.restoreEndpoint(endpointId);
      loadEndpoints();
      loadDashboard();
    } catch (error) {
      console.error('Error restoring endpoint:', error);
    }
  };

  const handleThreatAction = async (threatId, action) => {
    try {
      await edrAPI.takeActionOnThreat(threatId, { action, notes: `Action: ${action}` });
      loadThreats();
      loadDashboard();
      setThreatDialogOpen(false);
    } catch (error) {
      console.error('Error taking action:', error);
    }
  };

  const handleInitiateMemoryScan = async (agentId, scanType) => {
    try {
      await edrAPI.initiateMemoryScan({ agent_id: agentId, scan_type: scanType });
      loadMemoryScans();
      setScanDialogOpen(false);
    } catch (error) {
      console.error('Error initiating scan:', error);
    }
  };

  if (loading) {
    return (
      <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
        <LinearProgress />
        <Typography variant="h6" sx={{ mt: 2, textAlign: 'center' }}>Loading EDR Dashboard...</Typography>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <SecurityIcon fontSize="large" />
          Endpoint Detection & Response (EDR)
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Real-time endpoint protection, threat detection, and automated response
        </Typography>
      </Box>

      {dashboard && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">Total Agents</Typography>
                    <Typography variant="h4">{dashboard.overview.total_agents}</Typography>
                    <Typography variant="caption" color="success.main">
                      {dashboard.overview.online_agents} online
                    </Typography>
                  </Box>
                  <ComputerIcon sx={{ fontSize: 48, color: '#1976d2', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">Threats Detected</Typography>
                    <Typography variant="h4">{dashboard.overview.threats_detected}</Typography>
                    <Typography variant="caption" color="error.main">
                      {dashboard.overview.threats_quarantined} quarantined
                    </Typography>
                  </Box>
                  <WarningIcon sx={{ fontSize: 48, color: '#f57c00', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">Isolated Endpoints</Typography>
                    <Typography variant="h4">{dashboard.overview.isolated_agents}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Quarantined
                    </Typography>
                  </Box>
                  <BlockIcon sx={{ fontSize: 48, color: '#d32f2f', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">Avg Response Time</Typography>
                    <Typography variant="h4">{dashboard.overview.avg_response_time}s</Typography>
                    <Typography variant="caption" color="success.main">
                      Fast response
                    </Typography>
                  </Box>
                  <SpeedIcon sx={{ fontSize: 48, color: '#388e3c', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      <Card>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} variant="scrollable" scrollButtons="auto">
          <Tab icon={<AssessmentIcon />} label="Overview" iconPosition="start" />
          <Tab icon={<ComputerIcon />} label="Agents" iconPosition="start" />
          <Tab icon={<StorageIcon />} label="Endpoints" iconPosition="start" />
          <Tab icon={<WarningIcon />} label="Threats" iconPosition="start" />
          <Tab icon={<CloudDownloadIcon />} label="Forensics" iconPosition="start" />
        </Tabs>

        <CardContent>
          {/* Overview Tab */}
          {activeTab === 0 && dashboard && (
            <Grid container spacing={3}>
              <Grid item xs={12} md={8}>
                <Typography variant="h6" gutterBottom>Threat Detection Trend</Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={dashboard.threat_trend}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <RechartsTooltip />
                    <Legend />
                    <Line type="monotone" dataKey="detected" stroke="#f57c00" name="Detected" strokeWidth={2} />
                    <Line type="monotone" dataKey="quarantined" stroke="#1976d2" name="Quarantined" strokeWidth={2} />
                    <Line type="monotone" dataKey="removed" stroke="#388e3c" name="Removed" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </Grid>

              <Grid item xs={12} md={4}>
                <Typography variant="h6" gutterBottom>Endpoint Health</Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie data={dashboard.endpoint_health} cx="50%" cy="50%" outerRadius={80} fill="#8884d8" dataKey="count" label={(entry) => entry.status}>
                      {dashboard.endpoint_health.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Top Threats</Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Threat Type</TableCell>
                        <TableCell align="right">Count</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Trend</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dashboard.top_threats.map((threat, idx) => (
                        <TableRow key={idx}>
                          <TableCell>{threat.threat_type}</TableCell>
                          <TableCell align="right">{threat.count}</TableCell>
                          <TableCell>
                            <Chip label={threat.severity} size="small" sx={{ bgcolor: SEVERITY_COLORS[threat.severity], color: 'white' }} />
                          </TableCell>
                          <TableCell>
                            {threat.trend === 'up' ? <TrendingUpIcon color="error" /> : threat.trend === 'down' ? <TrendingDownIcon color="success" /> : <span>—</span>}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Critical Agents</Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Hostname</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell align="right">Threats</TableCell>
                        <TableCell>Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dashboard.critical_agents.map((agent) => (
                        <TableRow key={agent.id}>
                          <TableCell>{agent.hostname}</TableCell>
                          <TableCell>
                            <Chip label={agent.status} size="small" sx={{ bgcolor: STATUS_COLORS[agent.status], color: 'white' }} />
                          </TableCell>
                          <TableCell align="right">{agent.threat_count}</TableCell>
                          <TableCell>
                            <Tooltip title="View Details">
                              <IconButton size="small" onClick={() => { setSelectedAgent(agent); setAgentDialogOpen(true); }}>
                                <VisibilityIcon />
                              </IconButton>
                            </Tooltip>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>
            </Grid>
          )}

          {/* Agents Tab */}
          {activeTab === 1 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
                <FormControl size="small" sx={{ minWidth: 150 }}>
                  <InputLabel>Status</InputLabel>
                  <Select value={filters.agentStatus} label="Status" onChange={(e) => { setFilters({...filters, agentStatus: e.target.value}); loadAgents(); }}>
                    <MenuItem value="">All</MenuItem>
                    <MenuItem value="online">Online</MenuItem>
                    <MenuItem value="offline">Offline</MenuItem>
                    <MenuItem value="isolated">Isolated</MenuItem>
                  </Select>
                </FormControl>
                <Button variant="outlined" startIcon={<RefreshIcon />} onClick={loadAgents}>Refresh</Button>
              </Box>

              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Hostname</TableCell>
                      <TableCell>IP Address</TableCell>
                      <TableCell>OS</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Agent Version</TableCell>
                      <TableCell align="right">Threats</TableCell>
                      <TableCell>Last Seen</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {agents.map((agent) => (
                      <TableRow key={agent.id} hover>
                        <TableCell>{agent.hostname}</TableCell>
                        <TableCell>{agent.ip_address}</TableCell>
                        <TableCell>{agent.os}</TableCell>
                        <TableCell>
                          <Chip label={agent.status} size="small" sx={{ bgcolor: STATUS_COLORS[agent.status], color: 'white' }} />
                        </TableCell>
                        <TableCell>{agent.agent_version}</TableCell>
                        <TableCell align="right">
                          <Chip label={agent.threat_count} size="small" color={agent.threat_count > 0 ? 'error' : 'default'} />
                        </TableCell>
                        <TableCell>{new Date(agent.last_seen).toLocaleString()}</TableCell>
                        <TableCell>
                          <Tooltip title="View Details">
                            <IconButton size="small" onClick={() => { setSelectedAgent(agent); setAgentDialogOpen(true); }}>
                              <VisibilityIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Memory Scan">
                            <IconButton size="small" onClick={() => { setSelectedAgent(agent); setScanDialogOpen(true); }}>
                              <MemoryIcon />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Endpoints Tab */}
          {activeTab === 2 && (
            <Box>
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Hostname</TableCell>
                      <TableCell>IP / MAC</TableCell>
                      <TableCell>OS</TableCell>
                      <TableCell align="right">Risk Score</TableCell>
                      <TableCell>Compliance</TableCell>
                      <TableCell>Isolated</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {endpoints.map((endpoint) => (
                      <TableRow key={endpoint.id} hover>
                        <TableCell>{endpoint.hostname}</TableCell>
                        <TableCell>
                          <Typography variant="body2">{endpoint.ip_address}</Typography>
                          <Typography variant="caption" color="text.secondary">{endpoint.mac_address}</Typography>
                        </TableCell>
                        <TableCell>{endpoint.os}</TableCell>
                        <TableCell align="right">
                          <Chip label={endpoint.risk_score} size="small" sx={{ bgcolor: endpoint.risk_score > 70 ? '#d32f2f' : endpoint.risk_score > 50 ? '#f57c00' : '#388e3c', color: 'white' }} />
                        </TableCell>
                        <TableCell>
                          {endpoint.compliance ? <CheckCircleIcon color="success" /> : <CloseIcon color="error" />}
                        </TableCell>
                        <TableCell>
                          {endpoint.isolated ? <Chip label="Isolated" size="small" color="error" /> : <Chip label="Active" size="small" color="success" />}
                        </TableCell>
                        <TableCell>
                          {!endpoint.isolated ? (
                            <Button size="small" variant="outlined" color="error" onClick={() => handleIsolateEndpoint(endpoint.id, 'Manual isolation')}>
                              Isolate
                            </Button>
                          ) : (
                            <Button size="small" variant="outlined" color="success" onClick={() => handleRestoreEndpoint(endpoint.id)}>
                              Restore
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Threats Tab */}
          {activeTab === 3 && (
            <Box>
              <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
                <FormControl size="small" sx={{ minWidth: 150 }}>
                  <InputLabel>Severity</InputLabel>
                  <Select value={filters.threatSeverity} label="Severity" onChange={(e) => { setFilters({...filters, threatSeverity: e.target.value}); loadThreats(); }}>
                    <MenuItem value="">All</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="low">Low</MenuItem>
                  </Select>
                </FormControl>
                <FormControl size="small" sx={{ minWidth: 150 }}>
                  <InputLabel>Type</InputLabel>
                  <Select value={filters.threatType} label="Type" onChange={(e) => { setFilters({...filters, threatType: e.target.value}); loadThreats(); }}>
                    <MenuItem value="">All</MenuItem>
                    <MenuItem value="ransomware">Ransomware</MenuItem>
                    <MenuItem value="trojan">Trojan</MenuItem>
                    <MenuItem value="malware">Malware</MenuItem>
                    <MenuItem value="rootkit">Rootkit</MenuItem>
                    <MenuItem value="exploit">Exploit</MenuItem>
                  </Select>
                </FormControl>
              </Box>

              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Threat Name</TableCell>
                      <TableCell>Hostname</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell align="right">Threat Score</TableCell>
                      <TableCell>Detected</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {threats.map((threat) => (
                      <TableRow key={threat.id} hover>
                        <TableCell>{threat.name}</TableCell>
                        <TableCell>{threat.hostname}</TableCell>
                        <TableCell><Chip label={threat.type} size="small" /></TableCell>
                        <TableCell>
                          <Chip label={threat.severity} size="small" sx={{ bgcolor: SEVERITY_COLORS[threat.severity], color: 'white' }} />
                        </TableCell>
                        <TableCell>
                          <Chip label={threat.status} size="small" sx={{ bgcolor: THREAT_STATUS_COLORS[threat.status], color: 'white' }} />
                        </TableCell>
                        <TableCell align="right">{threat.threat_score}</TableCell>
                        <TableCell>{new Date(threat.detected_at).toLocaleString()}</TableCell>
                        <TableCell>
                          <Tooltip title="View Details">
                            <IconButton size="small" onClick={() => { setSelectedThreat(threat); setThreatDialogOpen(true); }}>
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
          )}

          {/* Forensics Tab */}
          {activeTab === 4 && (
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Memory Scans</Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Hostname</TableCell>
                        <TableCell>Type</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell align="right">Threats</TableCell>
                        <TableCell>Start Time</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {memoryScans.map((scan) => (
                        <TableRow key={scan.id}>
                          <TableCell>{scan.hostname}</TableCell>
                          <TableCell>{scan.scan_type}</TableCell>
                          <TableCell>
                            <Chip label={scan.status} size="small" color={scan.status === 'completed' ? 'success' : scan.status === 'running' ? 'primary' : 'default'} />
                          </TableCell>
                          <TableCell align="right">{scan.threats_found}</TableCell>
                          <TableCell>{new Date(scan.start_time).toLocaleString()}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Forensic Collections</Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Hostname</TableCell>
                        <TableCell>Type</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Size</TableCell>
                        <TableCell>Collected</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {forensics.map((forensic) => (
                        <TableRow key={forensic.id}>
                          <TableCell>{forensic.hostname}</TableCell>
                          <TableCell>{forensic.type.replace(/_/g, ' ')}</TableCell>
                          <TableCell>
                            <Chip label={forensic.status} size="small" color={forensic.status === 'collected' ? 'success' : forensic.status === 'collecting' ? 'primary' : 'default'} />
                          </TableCell>
                          <TableCell>{forensic.size > 0 ? `${(forensic.size / 1024 / 1024 / 1024).toFixed(2)} GB` : '—'}</TableCell>
                          <TableCell>{new Date(forensic.start_time).toLocaleString()}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>
            </Grid>
          )}
        </CardContent>
      </Card>

      {/* Agent Details Dialog */}
      <Dialog open={agentDialogOpen} onClose={() => setAgentDialogOpen(false)} maxWidth="md" fullWidth>
        {selectedAgent && (
          <>
            <DialogTitle>
              Agent Details: {selectedAgent.hostname}
            </DialogTitle>
            <DialogContent dividers>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Status</Typography>
                  <Typography><Chip label={selectedAgent.status} sx={{ bgcolor: STATUS_COLORS[selectedAgent.status], color: 'white' }} /></Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">IP Address</Typography>
                  <Typography>{selectedAgent.ip_address}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">OS</Typography>
                  <Typography>{selectedAgent.os} {selectedAgent.os_version}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Agent Version</Typography>
                  <Typography>{selectedAgent.agent_version}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Resource Usage</Typography>
                  <Box sx={{ mt: 1 }}>
                    <Typography variant="caption">CPU: {selectedAgent.cpu_usage}%</Typography>
                    <LinearProgress variant="determinate" value={selectedAgent.cpu_usage} sx={{ mb: 1 }} />
                    <Typography variant="caption">Memory: {selectedAgent.memory_usage}%</Typography>
                    <LinearProgress variant="determinate" value={selectedAgent.memory_usage} sx={{ mb: 1 }} />
                    <Typography variant="caption">Disk: {selectedAgent.disk_usage}%</Typography>
                    <LinearProgress variant="determinate" value={selectedAgent.disk_usage} />
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Threats</Typography>
                  <Typography>{selectedAgent.threat_count}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Quarantined</Typography>
                  <Typography>{selectedAgent.quarantine_count}</Typography>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setAgentDialogOpen(false)}>Close</Button>
              <Button variant="contained" startIcon={<MemoryIcon />} onClick={() => { setScanDialogOpen(true); setAgentDialogOpen(false); }}>
                Memory Scan
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Threat Details Dialog */}
      <Dialog open={threatDialogOpen} onClose={() => setThreatDialogOpen(false)} maxWidth="md" fullWidth>
        {selectedThreat && (
          <>
            <DialogTitle>Threat Details: {selectedThreat.name}</DialogTitle>
            <DialogContent dividers>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Hostname</Typography>
                  <Typography>{selectedThreat.hostname}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Severity</Typography>
                  <Typography><Chip label={selectedThreat.severity} sx={{ bgcolor: SEVERITY_COLORS[selectedThreat.severity], color: 'white' }} /></Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">File Path</Typography>
                  <Typography sx={{ fontFamily: 'monospace', bgcolor: '#f5f5f5', p: 1, borderRadius: 1 }}>{selectedThreat.file_path}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">File Hash (SHA-256)</Typography>
                  <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{selectedThreat.file_hash}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Process</Typography>
                  <Typography>{selectedThreat.process_name} (PID: {selectedThreat.process_id})</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Detection Method</Typography>
                  <Typography>{selectedThreat.detection_method}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">MITRE ATT&CK</Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5, flexWrap: 'wrap' }}>
                    {selectedThreat.mitre_tactics.map((tactic, i) => (
                      <Chip key={i} label={tactic} size="small" color="error" variant="outlined" />
                    ))}
                    {selectedThreat.mitre_techniques.map((tech, i) => (
                      <Chip key={i} label={tech} size="small" color="primary" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              {selectedThreat.status === 'detected' && (
                <>
                  <Button onClick={() => handleThreatAction(selectedThreat.id, 'quarantine')} color="warning">Quarantine</Button>
                  <Button onClick={() => handleThreatAction(selectedThreat.id, 'remove')} color="error">Remove</Button>
                  <Button onClick={() => handleThreatAction(selectedThreat.id, 'whitelist')}>Whitelist</Button>
                </>
              )}
              <Button onClick={() => setThreatDialogOpen(false)}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Memory Scan Dialog */}
      <Dialog open={scanDialogOpen} onClose={() => setScanDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Initiate Memory Scan</DialogTitle>
        <DialogContent>
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Scan Type</InputLabel>
            <Select defaultValue="quick" label="Scan Type">
              <MenuItem value="quick">Quick Scan (5 min)</MenuItem>
              <MenuItem value="full">Full Scan (1 hour)</MenuItem>
              <MenuItem value="targeted">Targeted Scan (15 min)</MenuItem>
            </Select>
          </FormControl>
          <Alert severity="info" sx={{ mt: 2 }}>
            Memory scan will analyze running processes and detect hidden threats, code injection, and rootkits.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setScanDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={() => selectedAgent && handleInitiateMemoryScan(selectedAgent.id, 'quick')}>
            Start Scan
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}

export default EDR;

