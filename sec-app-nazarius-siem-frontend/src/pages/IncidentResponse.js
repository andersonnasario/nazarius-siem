import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
  Tabs,
  Tab,
  Button,
  TextField,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Alert,
  LinearProgress,
  Tooltip,
} from '@mui/material';
import {
  Security as SecurityIcon,
  TrendingUp as TrendingUpIcon,
  Speed as SpeedIcon,
  CheckCircle as CheckCircleIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Visibility as VisibilityIcon,
  PlayArrow as PlayArrowIcon,
  AutoMode as AutoModeIcon,
  Assignment as AssignmentIcon,
  Timeline as TimelineIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as ChartTooltip, Legend, ResponsiveContainer } from 'recharts';
import { incidentResponseAPI } from '../services/api';

const COLORS = ['#f44336', '#ff9800', '#2196f3', '#4caf50', '#9c27b0'];

const IncidentResponse = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState(0);
  const [dashboard, setDashboard] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [automationRules, setAutomationRules] = useState([]);
  const [escalationRules, setEscalationRules] = useState([]);
  const [assignmentRules, setAssignmentRules] = useState([]);
  const [incidentDialog, setIncidentDialog] = useState(false);
  const [ruleDialog, setRuleDialog] = useState(false);
  const [viewDialog, setViewDialog] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [newIncident, setNewIncident] = useState({
    title: '',
    description: '',
    severity: 'medium',
    alert_id: '',
    auto_trigger: true,
  });
  const [newRule, setNewRule] = useState({
    name: '',
    description: '',
    enabled: true,
    priority: 1,
  });

  useEffect(() => {
    loadData();
  }, [activeTab]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);

      const dashboardData = await incidentResponseAPI.getDashboard();
      setDashboard(dashboardData);

      if (activeTab === 1) {
        const incidentsData = await incidentResponseAPI.getIncidents();
        setIncidents(incidentsData.incidents || []);
      } else if (activeTab === 2) {
        const rulesData = await incidentResponseAPI.getAutomationRules();
        setAutomationRules(rulesData.rules || []);
      } else if (activeTab === 3) {
        const escalationData = await incidentResponseAPI.getEscalationRules();
        setEscalationRules(escalationData.rules || []);
      } else if (activeTab === 4) {
        const assignmentData = await incidentResponseAPI.getAssignmentRules();
        setAssignmentRules(assignmentData.rules || []);
      }
    } catch (err) {
      console.error('Error loading data:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateIncident = async () => {
    try {
      await incidentResponseAPI.createIncident(newIncident);
      setIncidentDialog(false);
      setNewIncident({
        title: '',
        description: '',
        severity: 'medium',
        alert_id: '',
        auto_trigger: true,
      });
      loadData();
    } catch (err) {
      console.error('Error creating incident:', err);
      setError(err.message);
    }
  };

  const handleCreateRule = async () => {
    try {
      await incidentResponseAPI.createAutomationRule(newRule);
      setRuleDialog(false);
      setNewRule({
        name: '',
        description: '',
        enabled: true,
        priority: 1,
      });
      loadData();
    } catch (err) {
      console.error('Error creating rule:', err);
      setError(err.message);
    }
  };

  const handleViewIncident = async (incident) => {
    try {
      const details = await incidentResponseAPI.getIncident(incident.id);
      setSelectedIncident(details);
      setViewDialog(true);
    } catch (err) {
      console.error('Error loading incident details:', err);
      setError(err.message);
    }
  };

  const handleUpdateIncidentStatus = async (incidentId, newStatus) => {
    try {
      await incidentResponseAPI.updateIncident(incidentId, { status: newStatus });
      loadData();
      setViewDialog(false);
    } catch (err) {
      console.error('Error updating incident:', err);
      setError(err.message);
    }
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

  const getStatusColor = (status) => {
    const colors = {
      open: 'error',
      investigating: 'warning',
      contained: 'info',
      resolved: 'success',
    };
    return colors[status] || 'default';
  };

  if (loading && !dashboard) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
            <SecurityIcon sx={{ mr: 1, fontSize: 32 }} />
            Incident Response Automation
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Automated incident creation, escalation, and response
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setIncidentDialog(true)}
        >
          Create Incident
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* KPIs */}
      {dashboard && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Active Incidents
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 600, mt: 1 }}>
                      {dashboard.active_incidents}
                    </Typography>
                    <Typography variant="caption" color="success.main">
                      {dashboard.resolved_today} resolved today
                    </Typography>
                  </Box>
                  <SecurityIcon sx={{ fontSize: 48, color: 'primary.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Average MTTR
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 600, mt: 1 }}>
                      {dashboard.average_mttr}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Mean Time To Respond
                    </Typography>
                  </Box>
                  <SpeedIcon sx={{ fontSize: 48, color: 'warning.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Automation Rate
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 600, mt: 1 }}>
                      {dashboard.automation.automation_rate.toFixed(1)}%
                    </Typography>
                    <Typography variant="caption" color="success.main">
                      {dashboard.automation.executions_today} executions today
                    </Typography>
                  </Box>
                  <AutoModeIcon sx={{ fontSize: 48, color: 'success.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      SLA Compliance
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 600, mt: 1 }}>
                      {dashboard.sla_compliance.toFixed(1)}%
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {dashboard.auto_created} auto-created
                    </Typography>
                  </Box>
                  <CheckCircleIcon sx={{ fontSize: 48, color: 'info.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tabs */}
      <Card>
        <Tabs
          value={activeTab}
          onChange={(e, newValue) => setActiveTab(newValue)}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label="Overview" />
          <Tab label="Incidents" />
          <Tab label="Automation Rules" />
          <Tab label="Escalation Rules" />
          <Tab label="Assignment Rules" />
        </Tabs>

        <CardContent>
          {/* Tab 0: Overview */}
          {activeTab === 0 && dashboard && (
            <Grid container spacing={3}>
              {/* Incidents by Severity */}
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Incidents by Severity
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={Object.entries(dashboard.incidents_by_severity).map(([key, value]) => ({
                        name: key,
                        value: value,
                      }))}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={(entry) => `${entry.name}: ${entry.value}`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {Object.entries(dashboard.incidents_by_severity).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <ChartTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </Grid>

              {/* Incidents by Status */}
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Incidents by Status
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart
                    data={Object.entries(dashboard.incidents_by_status).map(([key, value]) => ({
                      status: key,
                      count: value,
                    }))}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="status" />
                    <YAxis />
                    <ChartTooltip />
                    <Legend />
                    <Bar dataKey="count" fill="#2196f3" />
                  </BarChart>
                </ResponsiveContainer>
              </Grid>

              {/* Top Assignees */}
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Top Assignees
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>User</TableCell>
                        <TableCell align="right">Assigned</TableCell>
                        <TableCell align="right">Resolved</TableCell>
                        <TableCell align="right">Avg MTTR</TableCell>
                        <TableCell align="right">SLA Compliance</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dashboard.top_assignees.map((assignee) => (
                        <TableRow key={assignee.user_id}>
                          <TableCell>{assignee.user_name}</TableCell>
                          <TableCell align="right">{assignee.assigned_count}</TableCell>
                          <TableCell align="right">{assignee.resolved_count}</TableCell>
                          <TableCell align="right">{assignee.average_mttr}</TableCell>
                          <TableCell align="right">
                            <Chip
                              label={`${assignee.sla_compliance.toFixed(1)}%`}
                              color={assignee.sla_compliance > 95 ? 'success' : assignee.sla_compliance > 90 ? 'warning' : 'error'}
                              size="small"
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>

              {/* Recent Incidents */}
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Recent Incidents
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>ID</TableCell>
                        <TableCell>Title</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Assigned To</TableCell>
                        <TableCell>Created</TableCell>
                        <TableCell>Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dashboard.recent_incidents.slice(0, 5).map((incident) => (
                        <TableRow key={incident.id}>
                          <TableCell>{incident.id.substring(0, 8)}</TableCell>
                          <TableCell>{incident.title}</TableCell>
                          <TableCell>
                            <Chip label={incident.severity} color={getSeverityColor(incident.severity)} size="small" />
                          </TableCell>
                          <TableCell>
                            <Chip label={incident.status} color={getStatusColor(incident.status)} size="small" />
                          </TableCell>
                          <TableCell>{incident.assigned_to}</TableCell>
                          <TableCell>{new Date(incident.created_at).toLocaleString()}</TableCell>
                          <TableCell>
                            <IconButton size="small" onClick={() => handleViewIncident(incident)}>
                              <VisibilityIcon fontSize="small" />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>
            </Grid>
          )}

          {/* Tab 1: Incidents */}
          {activeTab === 1 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6">All Incidents</Typography>
                <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setIncidentDialog(true)}>
                  Create Incident
                </Button>
              </Box>
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>ID</TableCell>
                      <TableCell>Title</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>ML Priority</TableCell>
                      <TableCell>Assigned To</TableCell>
                      <TableCell>Auto Created</TableCell>
                      <TableCell>Created</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {incidents.map((incident) => (
                      <TableRow key={incident.id}>
                        <TableCell>{incident.id.substring(0, 8)}</TableCell>
                        <TableCell>{incident.title}</TableCell>
                        <TableCell>
                          <Chip label={incident.severity} color={getSeverityColor(incident.severity)} size="small" />
                        </TableCell>
                        <TableCell>
                          <Chip label={incident.status} color={getStatusColor(incident.status)} size="small" />
                        </TableCell>
                        <TableCell>
                          <Chip label={incident.ml_priority} color="primary" size="small" />
                        </TableCell>
                        <TableCell>{incident.assigned_to}</TableCell>
                        <TableCell>
                          {incident.auto_created && <Chip label="Auto" color="success" size="small" />}
                        </TableCell>
                        <TableCell>{new Date(incident.created_at).toLocaleString()}</TableCell>
                        <TableCell>
                          <IconButton size="small" onClick={() => handleViewIncident(incident)}>
                            <VisibilityIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Tab 2: Automation Rules */}
          {activeTab === 2 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6">Automation Rules</Typography>
                <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setRuleDialog(true)}>
                  Create Rule
                </Button>
              </Box>
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Description</TableCell>
                      <TableCell>Priority</TableCell>
                      <TableCell>Enabled</TableCell>
                      <TableCell>Executions</TableCell>
                      <TableCell>Last Executed</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {automationRules.map((rule) => (
                      <TableRow key={rule.id}>
                        <TableCell>{rule.name}</TableCell>
                        <TableCell>{rule.description}</TableCell>
                        <TableCell>
                          <Chip label={rule.priority} color="primary" size="small" />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={rule.enabled ? 'Enabled' : 'Disabled'}
                            color={rule.enabled ? 'success' : 'default'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>{rule.execution_count}</TableCell>
                        <TableCell>
                          {rule.last_executed_at
                            ? new Date(rule.last_executed_at).toLocaleString()
                            : 'Never'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Tab 3: Escalation Rules */}
          {activeTab === 3 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Escalation Rules
              </Typography>
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Condition</TableCell>
                      <TableCell>Threshold</TableCell>
                      <TableCell>Action</TableCell>
                      <TableCell>Enabled</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {escalationRules.map((rule) => (
                      <TableRow key={rule.id}>
                        <TableCell>{rule.name}</TableCell>
                        <TableCell>
                          <Chip label={rule.severity} color={getSeverityColor(rule.severity)} size="small" />
                        </TableCell>
                        <TableCell>{rule.condition}</TableCell>
                        <TableCell>{String(rule.threshold)}</TableCell>
                        <TableCell>{rule.action}</TableCell>
                        <TableCell>
                          <Chip
                            label={rule.enabled ? 'Enabled' : 'Disabled'}
                            color={rule.enabled ? 'success' : 'default'}
                            size="small"
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Tab 4: Assignment Rules */}
          {activeTab === 4 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Assignment Rules
              </Typography>
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Category</TableCell>
                      <TableCell>Skills Required</TableCell>
                      <TableCell>Assign To</TableCell>
                      <TableCell>Priority</TableCell>
                      <TableCell>Enabled</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {assignmentRules.map((rule) => (
                      <TableRow key={rule.id}>
                        <TableCell>{rule.name}</TableCell>
                        <TableCell>
                          {rule.severity.map((s) => (
                            <Chip key={s} label={s} color={getSeverityColor(s)} size="small" sx={{ mr: 0.5 }} />
                          ))}
                        </TableCell>
                        <TableCell>{rule.category.join(', ')}</TableCell>
                        <TableCell>{rule.skills_required.join(', ')}</TableCell>
                        <TableCell>{rule.assign_to}</TableCell>
                        <TableCell>
                          <Chip label={rule.priority} color="primary" size="small" />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={rule.enabled ? 'Enabled' : 'Disabled'}
                            color={rule.enabled ? 'success' : 'default'}
                            size="small"
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Create Incident Dialog */}
      <Dialog open={incidentDialog} onClose={() => setIncidentDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create New Incident</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Title"
            value={newIncident.title}
            onChange={(e) => setNewIncident({ ...newIncident, title: e.target.value })}
            margin="normal"
          />
          <TextField
            fullWidth
            label="Description"
            value={newIncident.description}
            onChange={(e) => setNewIncident({ ...newIncident, description: e.target.value })}
            margin="normal"
            multiline
            rows={4}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Severity</InputLabel>
            <Select
              value={newIncident.severity}
              onChange={(e) => setNewIncident({ ...newIncident, severity: e.target.value })}
            >
              <MenuItem value="critical">Critical</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="low">Low</MenuItem>
            </Select>
          </FormControl>
          <TextField
            fullWidth
            label="Alert ID (optional)"
            value={newIncident.alert_id}
            onChange={(e) => setNewIncident({ ...newIncident, alert_id: e.target.value })}
            margin="normal"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setIncidentDialog(false)}>Cancel</Button>
          <Button onClick={handleCreateIncident} variant="contained">
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* Create Rule Dialog */}
      <Dialog open={ruleDialog} onClose={() => setRuleDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create Automation Rule</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Rule Name"
            value={newRule.name}
            onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
            margin="normal"
          />
          <TextField
            fullWidth
            label="Description"
            value={newRule.description}
            onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
            margin="normal"
            multiline
            rows={3}
          />
          <TextField
            fullWidth
            type="number"
            label="Priority (1-10)"
            value={newRule.priority}
            onChange={(e) => setNewRule({ ...newRule, priority: parseInt(e.target.value) })}
            margin="normal"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRuleDialog(false)}>Cancel</Button>
          <Button onClick={handleCreateRule} variant="contained">
            Create Rule
          </Button>
        </DialogActions>
      </Dialog>

      {/* View Incident Dialog */}
      <Dialog open={viewDialog} onClose={() => setViewDialog(false)} maxWidth="md" fullWidth>
        {selectedIncident && (
          <>
            <DialogTitle>
              Incident Details - {selectedIncident.id.substring(0, 8)}
            </DialogTitle>
            <DialogContent>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="h6">{selectedIncident.title}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                    {selectedIncident.description}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">
                    Severity
                  </Typography>
                  <Box>
                    <Chip label={selectedIncident.severity} color={getSeverityColor(selectedIncident.severity)} />
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">
                    Status
                  </Typography>
                  <Box>
                    <Chip label={selectedIncident.status} color={getStatusColor(selectedIncident.status)} />
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">
                    ML Priority
                  </Typography>
                  <Typography variant="body1">
                    {selectedIncident.ml_priority} (Confidence: {(selectedIncident.ml_confidence * 100).toFixed(1)}%)
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">
                    Assigned To
                  </Typography>
                  <Typography variant="body1">
                    {selectedIncident.assigned_to} ({selectedIncident.assignment_method})
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">
                    Created At
                  </Typography>
                  <Typography variant="body1">
                    {new Date(selectedIncident.created_at).toLocaleString()}
                  </Typography>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setViewDialog(false)}>Close</Button>
              {selectedIncident.status !== 'resolved' && (
                <Button
                  variant="contained"
                  color="success"
                  onClick={() => handleUpdateIncidentStatus(selectedIncident.id, 'resolved')}
                >
                  Mark as Resolved
                </Button>
              )}
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
};

export default IncidentResponse;
