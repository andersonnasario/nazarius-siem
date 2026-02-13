import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Grid,
  Card,
  CardContent,
  Typography,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  LinearProgress,
  Tooltip,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Policy as PolicyIcon,
  Warning as WarningIcon,
  Block as BlockIcon,
  CheckCircle as CheckCircleIcon,
  Info as InfoIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as VisibilityIcon,
  Search as SearchIcon,
  Shield as ShieldIcon,
  Lock as LockIcon,
  Description as DescriptionIcon,
  Assessment as AssessmentIcon,
  TrendingDown as TrendingDownIcon,
  TrendingUp as TrendingUpIcon,
  Email as EmailIcon,
  CloudUpload as CloudUploadIcon,
  Api as ApiIcon,
  WebAsset as WebAssetIcon,
  Pattern as PatternIcon,
  Category as CategoryIcon,
} from '@mui/icons-material';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';
import { dlpAPI } from '../services/api';

// Color palettes
const COLORS = ['#1976d2', '#dc004e', '#f57c00', '#388e3c', '#9c27b0', '#00897b', '#5e35b1'];
const SEVERITY_COLORS = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#fbc02d',
  low: '#388e3c',
};

const STATUS_COLORS = {
  open: '#f57c00',
  investigating: '#1976d2',
  resolved: '#388e3c',
  false_positive: '#757575',
};

const ACTION_COLORS = {
  block: '#d32f2f',
  alert: '#f57c00',
  encrypt: '#1976d2',
  quarantine: '#7b1fa2',
};

function DLP() {
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(0);
  
  // Dashboard data
  const [dashboard, setDashboard] = useState(null);
  
  // Policies
  const [policies, setPolicies] = useState([]);
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [policyDialogOpen, setPolicyDialogOpen] = useState(false);
  
  // Incidents
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [incidentDialogOpen, setIncidentDialogOpen] = useState(false);
  const [incidentFilters, setIncidentFilters] = useState({ status: '', severity: '' });
  
  // Patterns
  const [patterns, setPatterns] = useState([]);
  const [patternDialogOpen, setPatternDialogOpen] = useState(false);
  
  // Classifications
  const [classifications, setClassifications] = useState([]);
  const [testContent, setTestContent] = useState('');
  const [classificationResult, setClassificationResult] = useState(null);
  const [inspectionResult, setInspectionResult] = useState(null);

  useEffect(() => {
    loadDashboard();
    loadPolicies();
    loadIncidents();
    loadPatterns();
    loadClassifications();
  }, []);

  const loadDashboard = async () => {
    try {
      setLoading(true);
      const data = await dlpAPI.getDashboard();
      setDashboard(data);
    } catch (error) {
      console.error('Error loading dashboard:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadPolicies = async () => {
    try {
      const data = await dlpAPI.getPolicies();
      setPolicies(data);
    } catch (error) {
      console.error('Error loading policies:', error);
    }
  };

  const loadIncidents = async () => {
    try {
      const params = {};
      if (incidentFilters.status) params.status = incidentFilters.status;
      if (incidentFilters.severity) params.severity = incidentFilters.severity;
      
      const data = await dlpAPI.getIncidents(params);
      setIncidents(data);
    } catch (error) {
      console.error('Error loading incidents:', error);
    }
  };

  const loadPatterns = async () => {
    try {
      const data = await dlpAPI.getPatterns();
      setPatterns(data);
    } catch (error) {
      console.error('Error loading patterns:', error);
    }
  };

  const loadClassifications = async () => {
    try {
      const data = await dlpAPI.getClassifications();
      setClassifications(data);
    } catch (error) {
      console.error('Error loading classifications:', error);
    }
  };

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
  };

  const handleViewPolicy = async (policy) => {
    try {
      const detailed = await dlpAPI.getPolicy(policy.id);
      setSelectedPolicy(detailed);
      setPolicyDialogOpen(true);
    } catch (error) {
      console.error('Error loading policy:', error);
    }
  };

  const handleViewIncident = async (incident) => {
    try {
      const detailed = await dlpAPI.getIncident(incident.id);
      setSelectedIncident(detailed);
      setIncidentDialogOpen(true);
    } catch (error) {
      console.error('Error loading incident:', error);
    }
  };

  const handleUpdateIncidentStatus = async (status, notes = '') => {
    try {
      await dlpAPI.updateIncident(selectedIncident.id, { status, notes });
      setIncidentDialogOpen(false);
      loadIncidents();
      loadDashboard();
    } catch (error) {
      console.error('Error updating incident:', error);
    }
  };

  const handleTestContent = async () => {
    try {
      const result = await dlpAPI.inspectContent({
        content: testContent,
        channel: 'test',
        user: 'tester@company.com',
      });
      setInspectionResult(result);
    } catch (error) {
      console.error('Error inspecting content:', error);
    }
  };

  const handleClassifyContent = async () => {
    try {
      const result = await dlpAPI.classifyData({
        content: testContent,
      });
      setClassificationResult(result);
    } catch (error) {
      console.error('Error classifying data:', error);
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return <BlockIcon sx={{ color: SEVERITY_COLORS.critical }} />;
      case 'high':
        return <WarningIcon sx={{ color: SEVERITY_COLORS.high }} />;
      case 'medium':
        return <InfoIcon sx={{ color: SEVERITY_COLORS.medium }} />;
      case 'low':
        return <CheckCircleIcon sx={{ color: SEVERITY_COLORS.low }} />;
      default:
        return <InfoIcon />;
    }
  };

  const getChannelIcon = (channel) => {
    switch (channel) {
      case 'email':
        return <EmailIcon />;
      case 'file_upload':
        return <CloudUploadIcon />;
      case 'api':
        return <ApiIcon />;
      case 'web_form':
        return <WebAssetIcon />;
      default:
        return <InfoIcon />;
    }
  };

  if (loading) {
    return (
      <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
        <LinearProgress />
        <Typography variant="h6" sx={{ mt: 2, textAlign: 'center' }}>
          Loading DLP Dashboard...
        </Typography>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <SecurityIcon fontSize="large" />
          Data Loss Prevention (DLP)
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Protect sensitive data with content inspection, policy enforcement, and automated classification
        </Typography>
      </Box>

      {/* KPI Cards */}
      {dashboard && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">Total Incidents</Typography>
                    <Typography variant="h4">{dashboard.overview.total_incidents.toLocaleString()}</Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 1 }}>
                      {dashboard.overview.trend_percentage < 0 ? (
                        <TrendingDownIcon sx={{ color: '#388e3c', fontSize: 16 }} />
                      ) : (
                        <TrendingUpIcon sx={{ color: '#d32f2f', fontSize: 16 }} />
                      )}
                      <Typography variant="caption" color={dashboard.overview.trend_percentage < 0 ? '#388e3c' : '#d32f2f'}>
                        {Math.abs(dashboard.overview.trend_percentage)}% vs last week
                      </Typography>
                    </Box>
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
                    <Typography color="text.secondary" variant="body2">Blocked Today</Typography>
                    <Typography variant="h4">{dashboard.overview.blocked_attempts}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                      {dashboard.overview.incidents_today} incidents today
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
                    <Typography color="text.secondary" variant="body2">Active Policies</Typography>
                    <Typography variant="h4">{dashboard.overview.active_policies}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                      Enforcement enabled
                    </Typography>
                  </Box>
                  <PolicyIcon sx={{ fontSize: 48, color: '#1976d2', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">Compliance Rate</Typography>
                    <Typography variant="h4">{dashboard.overview.compliance_rate}%</Typography>
                    <Box sx={{ mt: 1 }}>
                      <LinearProgress 
                        variant="determinate" 
                        value={dashboard.overview.compliance_rate} 
                        sx={{ height: 6, borderRadius: 3 }}
                      />
                    </Box>
                  </Box>
                  <ShieldIcon sx={{ fontSize: 48, color: '#388e3c', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tabs */}
      <Card>
        <Tabs value={activeTab} onChange={handleTabChange} variant="scrollable" scrollButtons="auto">
          <Tab icon={<AssessmentIcon />} label="Overview" iconPosition="start" />
          <Tab icon={<PolicyIcon />} label="Policies" iconPosition="start" />
          <Tab icon={<WarningIcon />} label="Incidents" iconPosition="start" />
          <Tab icon={<PatternIcon />} label="Patterns" iconPosition="start" />
          <Tab icon={<CategoryIcon />} label="Classification" iconPosition="start" />
        </Tabs>

        <CardContent>
          {/* Overview Tab */}
          {activeTab === 0 && dashboard && (
            <Grid container spacing={3}>
              {/* Incident Trend */}
              <Grid item xs={12} md={8}>
                <Typography variant="h6" gutterBottom>Incident Trend (Last 7 Days)</Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={dashboard.incident_trend}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <RechartsTooltip />
                    <Legend />
                    <Line type="monotone" dataKey="incidents" stroke="#1976d2" strokeWidth={2} name="Incidents" />
                    <Line type="monotone" dataKey="blocked" stroke="#d32f2f" strokeWidth={2} name="Blocked" />
                  </LineChart>
                </ResponsiveContainer>
              </Grid>

              {/* Data Type Breakdown */}
              <Grid item xs={12} md={4}>
                <Typography variant="h6" gutterBottom>Data Type Distribution</Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={dashboard.data_type_breakdown}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={(entry) => entry.data_type.split(' ')[0]}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="count"
                    >
                      {dashboard.data_type_breakdown.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </Grid>

              {/* Top Policies */}
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Top Policies by Incidents</Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Policy</TableCell>
                        <TableCell align="right">Incidents</TableCell>
                        <TableCell align="right">Block Rate</TableCell>
                        <TableCell>Severity</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dashboard.top_policies.map((policy) => (
                        <TableRow key={policy.policy_id}>
                          <TableCell>{policy.policy_name}</TableCell>
                          <TableCell align="right">{policy.incident_count}</TableCell>
                          <TableCell align="right">{policy.block_rate}%</TableCell>
                          <TableCell>
                            <Chip 
                              label={policy.severity} 
                              size="small" 
                              sx={{ bgcolor: SEVERITY_COLORS[policy.severity], color: 'white' }}
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>

              {/* Top Users */}
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>High-Risk Users</Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>User</TableCell>
                        <TableCell align="right">Incidents</TableCell>
                        <TableCell align="right">Risk Score</TableCell>
                        <TableCell>Data Types</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dashboard.top_users.map((user, idx) => (
                        <TableRow key={idx}>
                          <TableCell>{user.user}</TableCell>
                          <TableCell align="right">{user.incident_count}</TableCell>
                          <TableCell align="right">
                            <Chip 
                              label={user.risk_score} 
                              size="small" 
                              sx={{ 
                                bgcolor: user.risk_score > 70 ? '#d32f2f' : user.risk_score > 50 ? '#f57c00' : '#388e3c',
                                color: 'white'
                              }}
                            />
                          </TableCell>
                          <TableCell>
                            {user.data_types.map((dt, i) => (
                              <Chip key={i} label={dt} size="small" sx={{ mr: 0.5 }} />
                            ))}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>

              {/* Recent Incidents */}
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>Recent Incidents</Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>ID</TableCell>
                        <TableCell>Policy</TableCell>
                        <TableCell>User</TableCell>
                        <TableCell>Data Type</TableCell>
                        <TableCell>Channel</TableCell>
                        <TableCell>Action</TableCell>
                        <TableCell>Risk Score</TableCell>
                        <TableCell>Time</TableCell>
                        <TableCell>Status</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dashboard.recent_incidents.map((incident) => (
                        <TableRow key={incident.id} hover onClick={() => handleViewIncident(incident)} sx={{ cursor: 'pointer' }}>
                          <TableCell>{incident.id}</TableCell>
                          <TableCell>{incident.policy_name}</TableCell>
                          <TableCell>{incident.user}</TableCell>
                          <TableCell>
                            <Chip label={incident.data_type} size="small" />
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              {getChannelIcon(incident.channel)}
                              {incident.channel}
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={incident.action} 
                              size="small" 
                              sx={{ bgcolor: ACTION_COLORS[incident.action], color: 'white' }}
                            />
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={incident.risk_score} 
                              size="small" 
                              sx={{ 
                                bgcolor: incident.risk_score > 80 ? '#d32f2f' : incident.risk_score > 60 ? '#f57c00' : '#388e3c',
                                color: 'white'
                              }}
                            />
                          </TableCell>
                          <TableCell>{new Date(incident.detected_at).toLocaleString()}</TableCell>
                          <TableCell>
                            <Chip 
                              label={incident.status} 
                              size="small" 
                              sx={{ bgcolor: STATUS_COLORS[incident.status], color: 'white' }}
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>
            </Grid>
          )}

          {/* Policies Tab */}
          {activeTab === 1 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h6">DLP Policies</Typography>
                <Button variant="contained" startIcon={<AddIcon />} onClick={() => setPolicyDialogOpen(true)}>
                  Create Policy
                </Button>
              </Box>

              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Policy Name</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Action</TableCell>
                      <TableCell>Data Types</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Scope</TableCell>
                      <TableCell align="right">Incidents</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {policies.map((policy) => (
                      <TableRow key={policy.id} hover>
                        <TableCell>
                          <Box>
                            <Typography variant="body2" fontWeight="bold">{policy.name}</Typography>
                            <Typography variant="caption" color="text.secondary">{policy.description}</Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={policy.status} 
                            size="small" 
                            color={policy.status === 'active' ? 'success' : 'default'}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={policy.action} 
                            size="small" 
                            sx={{ bgcolor: ACTION_COLORS[policy.action], color: 'white' }}
                          />
                        </TableCell>
                        <TableCell>
                          {policy.data_types.map((dt, i) => (
                            <Chip key={i} label={dt} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                          ))}
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={policy.severity} 
                            size="small" 
                            sx={{ bgcolor: SEVERITY_COLORS[policy.severity], color: 'white' }}
                          />
                        </TableCell>
                        <TableCell>
                          {policy.scope.map((s, i) => (
                            <Chip key={i} label={s} size="small" variant="outlined" sx={{ mr: 0.5, mb: 0.5 }} />
                          ))}
                        </TableCell>
                        <TableCell align="right">{policy.incident_count}</TableCell>
                        <TableCell>
                          <Tooltip title="View Details">
                            <IconButton size="small" onClick={() => handleViewPolicy(policy)}>
                              <VisibilityIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Edit">
                            <IconButton size="small">
                              <EditIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete">
                            <IconButton size="small" color="error">
                              <DeleteIcon />
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

          {/* Incidents Tab */}
          {activeTab === 2 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h6">DLP Incidents</Typography>
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <FormControl size="small" sx={{ minWidth: 150 }}>
                    <InputLabel>Status</InputLabel>
                    <Select
                      value={incidentFilters.status}
                      label="Status"
                      onChange={(e) => {
                        setIncidentFilters({ ...incidentFilters, status: e.target.value });
                        loadIncidents();
                      }}
                    >
                      <MenuItem value="">All</MenuItem>
                      <MenuItem value="open">Open</MenuItem>
                      <MenuItem value="investigating">Investigating</MenuItem>
                      <MenuItem value="resolved">Resolved</MenuItem>
                      <MenuItem value="false_positive">False Positive</MenuItem>
                    </Select>
                  </FormControl>
                  <FormControl size="small" sx={{ minWidth: 150 }}>
                    <InputLabel>Severity</InputLabel>
                    <Select
                      value={incidentFilters.severity}
                      label="Severity"
                      onChange={(e) => {
                        setIncidentFilters({ ...incidentFilters, severity: e.target.value });
                        loadIncidents();
                      }}
                    >
                      <MenuItem value="">All</MenuItem>
                      <MenuItem value="critical">Critical</MenuItem>
                      <MenuItem value="high">High</MenuItem>
                      <MenuItem value="medium">Medium</MenuItem>
                      <MenuItem value="low">Low</MenuItem>
                    </Select>
                  </FormControl>
                </Box>
              </Box>

              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Incident ID</TableCell>
                      <TableCell>Policy</TableCell>
                      <TableCell>User</TableCell>
                      <TableCell>Data Type</TableCell>
                      <TableCell>Channel</TableCell>
                      <TableCell>Action</TableCell>
                      <TableCell>Risk Score</TableCell>
                      <TableCell>Detected</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {incidents.map((incident) => (
                      <TableRow key={incident.id} hover>
                        <TableCell>
                          <Typography variant="body2" fontWeight="bold">{incident.id}</Typography>
                        </TableCell>
                        <TableCell>
                          <Box>
                            <Typography variant="body2">{incident.policy_name}</Typography>
                            <Chip 
                              label={incident.severity} 
                              size="small" 
                              sx={{ bgcolor: SEVERITY_COLORS[incident.severity], color: 'white', mt: 0.5 }}
                            />
                          </Box>
                        </TableCell>
                        <TableCell>{incident.user}</TableCell>
                        <TableCell>
                          <Chip label={incident.data_type} size="small" />
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {getChannelIcon(incident.channel)}
                            {incident.channel}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={incident.action} 
                            size="small" 
                            sx={{ bgcolor: ACTION_COLORS[incident.action], color: 'white' }}
                          />
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <LinearProgress 
                              variant="determinate" 
                              value={incident.risk_score} 
                              sx={{ 
                                width: 60, 
                                height: 6, 
                                borderRadius: 3,
                                '& .MuiLinearProgress-bar': {
                                  bgcolor: incident.risk_score > 80 ? '#d32f2f' : incident.risk_score > 60 ? '#f57c00' : '#388e3c'
                                }
                              }}
                            />
                            <Typography variant="caption">{incident.risk_score}</Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">{new Date(incident.detected_at).toLocaleString()}</Typography>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={incident.status} 
                            size="small" 
                            sx={{ bgcolor: STATUS_COLORS[incident.status], color: 'white' }}
                          />
                        </TableCell>
                        <TableCell>
                          <Tooltip title="View Details">
                            <IconButton size="small" onClick={() => handleViewIncident(incident)}>
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

          {/* Patterns Tab */}
          {activeTab === 3 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h6">Detection Patterns</Typography>
                <Button variant="contained" startIcon={<AddIcon />} onClick={() => setPatternDialogOpen(true)}>
                  Add Pattern
                </Button>
              </Box>

              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Pattern Name</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Data Type</TableCell>
                      <TableCell>Pattern</TableCell>
                      <TableCell>Built-In</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell align="right">Matches</TableCell>
                      <TableCell>Examples</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {patterns.map((pattern) => (
                      <TableRow key={pattern.id} hover>
                        <TableCell>
                          <Typography variant="body2" fontWeight="bold">{pattern.name}</Typography>
                          <Typography variant="caption" color="text.secondary">{pattern.description}</Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={pattern.type} size="small" color="primary" variant="outlined" />
                        </TableCell>
                        <TableCell>
                          <Chip label={pattern.data_type} size="small" />
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" sx={{ fontFamily: 'monospace', bgcolor: '#f5f5f5', p: 0.5, borderRadius: 1 }}>
                            {pattern.pattern.substring(0, 40)}...
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {pattern.is_built_in ? (
                            <Chip label="Built-in" size="small" color="info" />
                          ) : (
                            <Chip label="Custom" size="small" />
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={pattern.enabled ? 'Enabled' : 'Disabled'} 
                            size="small" 
                            color={pattern.enabled ? 'success' : 'default'}
                          />
                        </TableCell>
                        <TableCell align="right">{pattern.match_count.toLocaleString()}</TableCell>
                        <TableCell>
                          {pattern.examples.slice(0, 2).map((ex, i) => (
                            <Typography key={i} variant="caption" display="block">• {ex}</Typography>
                          ))}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Classification Tab */}
          {activeTab === 4 && (
            <Grid container spacing={3}>
              {/* Data Classifications */}
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Data Classification Levels</Typography>
                <Grid container spacing={2}>
                  {classifications.map((classification) => (
                    <Grid item xs={12} key={classification.id}>
                      <Card sx={{ border: `2px solid ${classification.color}` }}>
                        <CardContent>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                            <LockIcon sx={{ color: classification.color, fontSize: 32 }} />
                            <Box sx={{ flexGrow: 1 }}>
                              <Typography variant="h6">{classification.name}</Typography>
                              <Typography variant="body2" color="text.secondary">
                                {classification.description}
                              </Typography>
                            </Box>
                          </Box>
                          
                          <Divider sx={{ my: 2 }} />
                          
                          <Typography variant="caption" fontWeight="bold" display="block" gutterBottom>
                            Requirements:
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {classification.requirements.map((req, i) => (
                              <Chip key={i} label={req.replace(/_/g, ' ')} size="small" variant="outlined" />
                            ))}
                          </Box>
                          
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 2 }}>
                            <Typography variant="caption">
                              {classification.policy_count} policies
                            </Typography>
                            <Typography variant="caption">
                              {(classification.data_count / 1000).toFixed(0)}K data items
                            </Typography>
                          </Box>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Grid>

              {/* Test Content Inspection & Classification */}
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Test Content Inspection & Classification</Typography>
                <Card>
                  <CardContent>
                    <TextField
                      fullWidth
                      multiline
                      rows={6}
                      label="Test Content"
                      placeholder="Enter content to inspect and classify (e.g., text with SSN, credit cards, etc.)"
                      value={testContent}
                      onChange={(e) => setTestContent(e.target.value)}
                      sx={{ mb: 2 }}
                    />
                    
                    <Box sx={{ display: 'flex', gap: 2 }}>
                      <Button 
                        variant="contained" 
                        startIcon={<SearchIcon />}
                        onClick={handleTestContent}
                        disabled={!testContent}
                        fullWidth
                      >
                        Inspect Content
                      </Button>
                      <Button 
                        variant="outlined" 
                        startIcon={<CategoryIcon />}
                        onClick={handleClassifyContent}
                        disabled={!testContent}
                        fullWidth
                      >
                        Classify Data
                      </Button>
                    </Box>

                    {inspectionResult && (
                      <Box sx={{ mt: 3 }}>
                        <Typography variant="subtitle2" gutterBottom>Inspection Result:</Typography>
                        <Alert 
                          severity={inspectionResult.is_violation ? 'error' : 'success'}
                          sx={{ mb: 2 }}
                        >
                          {inspectionResult.is_violation 
                            ? `Policy Violation Detected! Action: ${inspectionResult.action.toUpperCase()}`
                            : 'No violations detected'
                          }
                        </Alert>

                        {inspectionResult.detected_data.length > 0 && (
                          <Box sx={{ mb: 2 }}>
                            <Typography variant="caption" fontWeight="bold">Detected Sensitive Data:</Typography>
                            <List dense>
                              {inspectionResult.detected_data.map((data, i) => (
                                <ListItem key={i}>
                                  <ListItemIcon>
                                    <WarningIcon color="warning" />
                                  </ListItemIcon>
                                  <ListItemText
                                    primary={`${data.type} (${data.count}x)`}
                                    secondary={`Pattern: ${data.pattern} • Value: ${data.value} • Confidence: ${data.confidence}%`}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </Box>
                        )}

                        <Box sx={{ mb: 2 }}>
                          <Typography variant="caption" fontWeight="bold">Risk Score:</Typography>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 1 }}>
                            <LinearProgress 
                              variant="determinate" 
                              value={inspectionResult.risk_score} 
                              sx={{ 
                                flexGrow: 1, 
                                height: 10, 
                                borderRadius: 5,
                                '& .MuiLinearProgress-bar': {
                                  bgcolor: inspectionResult.risk_score > 80 ? '#d32f2f' : inspectionResult.risk_score > 60 ? '#f57c00' : '#388e3c'
                                }
                              }}
                            />
                            <Typography variant="body2" fontWeight="bold">
                              {inspectionResult.risk_score}/100
                            </Typography>
                          </Box>
                        </Box>

                        {inspectionResult.matched_policies.length > 0 && (
                          <Box>
                            <Typography variant="caption" fontWeight="bold">Matched Policies:</Typography>
                            <Box sx={{ display: 'flex', gap: 0.5, mt: 1, flexWrap: 'wrap' }}>
                              {inspectionResult.matched_policies.map((policy, i) => (
                                <Chip key={i} label={policy} size="small" color="error" />
                              ))}
                            </Box>
                          </Box>
                        )}
                      </Box>
                    )}

                    {classificationResult && (
                      <Box sx={{ mt: 3 }}>
                        <Typography variant="subtitle2" gutterBottom>Classification Result:</Typography>
                        <Card variant="outlined" sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                            <LockIcon />
                            <Box>
                              <Typography variant="h6" textTransform="capitalize">
                                {classificationResult.classification}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Confidence: {classificationResult.confidence}%
                              </Typography>
                            </Box>
                          </Box>
                          
                          {classificationResult.requirements.length > 0 && (
                            <Box sx={{ mb: 2 }}>
                              <Typography variant="caption" fontWeight="bold">Required Security Controls:</Typography>
                              <Box sx={{ display: 'flex', gap: 0.5, mt: 1, flexWrap: 'wrap' }}>
                                {classificationResult.requirements.map((req, i) => (
                                  <Chip key={i} label={req.replace(/_/g, ' ')} size="small" />
                                ))}
                              </Box>
                            </Box>
                          )}
                          
                          <Alert severity="info" sx={{ mt: 2 }}>
                            {classificationResult.recommendation}
                          </Alert>
                        </Card>
                      </Box>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          )}
        </CardContent>
      </Card>

      {/* Incident Details Dialog */}
      <Dialog open={incidentDialogOpen} onClose={() => setIncidentDialogOpen(false)} maxWidth="md" fullWidth>
        {selectedIncident && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="h6">Incident Details: {selectedIncident.id}</Typography>
                <Chip 
                  label={selectedIncident.status} 
                  sx={{ bgcolor: STATUS_COLORS[selectedIncident.status], color: 'white' }}
                />
              </Box>
            </DialogTitle>
            <DialogContent dividers>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="caption" color="text.secondary">Policy</Typography>
                  <Typography variant="body1" gutterBottom>{selectedIncident.policy_name}</Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="caption" color="text.secondary">Severity</Typography>
                  <Box>
                    <Chip 
                      label={selectedIncident.severity} 
                      sx={{ bgcolor: SEVERITY_COLORS[selectedIncident.severity], color: 'white' }}
                    />
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="caption" color="text.secondary">User</Typography>
                  <Typography variant="body1" gutterBottom>{selectedIncident.user}</Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="caption" color="text.secondary">Action Taken</Typography>
                  <Box>
                    <Chip 
                      label={selectedIncident.action} 
                      sx={{ bgcolor: ACTION_COLORS[selectedIncident.action], color: 'white' }}
                    />
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="caption" color="text.secondary">Source</Typography>
                  <Typography variant="body1" gutterBottom>{selectedIncident.source}</Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="caption" color="text.secondary">Destination</Typography>
                  <Typography variant="body1" gutterBottom>{selectedIncident.destination}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Detected Data</Typography>
                  <List dense>
                    {selectedIncident.detected_data.map((data, i) => (
                      <ListItem key={i}>
                        <ListItemIcon>
                          <WarningIcon color="warning" />
                        </ListItemIcon>
                        <ListItemText
                          primary={`${data.type} (${data.count}x)`}
                          secondary={`${data.pattern} • ${data.value} • Confidence: ${data.confidence}%`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Content Preview</Typography>
                  <Paper sx={{ p: 2, bgcolor: '#f5f5f5', mt: 1 }}>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {selectedIncident.content_preview}
                    </Typography>
                  </Paper>
                </Grid>
                {selectedIncident.notes && (
                  <Grid item xs={12}>
                    <Typography variant="caption" color="text.secondary">Notes</Typography>
                    <Typography variant="body2">{selectedIncident.notes}</Typography>
                  </Grid>
                )}
              </Grid>
            </DialogContent>
            <DialogActions>
              {selectedIncident.status === 'open' && (
                <>
                  <Button onClick={() => handleUpdateIncidentStatus('investigating')} color="primary">
                    Start Investigation
                  </Button>
                  <Button onClick={() => handleUpdateIncidentStatus('false_positive')} color="warning">
                    Mark as False Positive
                  </Button>
                  <Button onClick={() => handleUpdateIncidentStatus('resolved')} color="success">
                    Resolve
                  </Button>
                </>
              )}
              <Button onClick={() => setIncidentDialogOpen(false)}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Policy Details Dialog */}
      <Dialog open={policyDialogOpen} onClose={() => setPolicyDialogOpen(false)} maxWidth="md" fullWidth>
        {selectedPolicy && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="h6">{selectedPolicy.name}</Typography>
                <Chip 
                  label={selectedPolicy.status} 
                  color={selectedPolicy.status === 'active' ? 'success' : 'default'}
                />
              </Box>
            </DialogTitle>
            <DialogContent dividers>
              <Typography variant="body2" paragraph>{selectedPolicy.description}</Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="caption" color="text.secondary">Action</Typography>
                  <Box>
                    <Chip 
                      label={selectedPolicy.action} 
                      sx={{ bgcolor: ACTION_COLORS[selectedPolicy.action], color: 'white' }}
                    />
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="caption" color="text.secondary">Severity</Typography>
                  <Box>
                    <Chip 
                      label={selectedPolicy.severity} 
                      sx={{ bgcolor: SEVERITY_COLORS[selectedPolicy.severity], color: 'white' }}
                    />
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Data Types</Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, mt: 1, flexWrap: 'wrap' }}>
                    {selectedPolicy.data_types.map((dt, i) => (
                      <Chip key={i} label={dt} size="small" />
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Scope</Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, mt: 1, flexWrap: 'wrap' }}>
                    {selectedPolicy.scope.map((s, i) => (
                      <Chip key={i} label={s} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Detection Patterns</Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, mt: 1, flexWrap: 'wrap' }}>
                    {selectedPolicy.patterns.map((p, i) => (
                      <Chip key={i} label={p} size="small" color="primary" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
                {selectedPolicy.exclusion_rules.length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="caption" color="text.secondary">Exclusion Rules</Typography>
                    <List dense>
                      {selectedPolicy.exclusion_rules.map((rule, i) => (
                        <ListItem key={i}>
                          <ListItemText primary={rule} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                )}
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Statistics</Typography>
                  <Box sx={{ display: 'flex', gap: 2, mt: 1 }}>
                    <Typography variant="body2">Total Incidents: {selectedPolicy.incident_count}</Typography>
                    <Typography variant="body2">Created by: {selectedPolicy.created_by}</Typography>
                  </Box>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setPolicyDialogOpen(false)}>Close</Button>
              <Button variant="contained" startIcon={<EditIcon />}>Edit Policy</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Container>
  );
}

export default DLP;

