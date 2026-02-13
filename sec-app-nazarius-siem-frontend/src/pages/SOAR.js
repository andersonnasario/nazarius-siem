import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, LinearProgress, IconButton, Tooltip
} from '@mui/material';
import {
  PlayArrow as PlayArrowIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Visibility as VisibilityIcon,
  AccountTree as AccountTreeIcon,
  IntegrationInstructions as IntegrationIcon,
  Assignment as AssignmentIcon,
  AutoAwesome as AutoAwesomeIcon
} from '@mui/icons-material';
import { soarAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const SOAR = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [playbooks, setPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [integrations, setIntegrations] = useState([]);
  const [cases, setCases] = useState([]);
  const [workflows, setWorkflows] = useState([]);
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
      const [playbooksRes, executionsRes, integrationsRes, casesRes, workflowsRes, metricsRes] = await Promise.all([
        soarAPI.listPlaybooks(),
        soarAPI.listExecutions(),
        soarAPI.listIntegrations(),
        soarAPI.listCases(),
        soarAPI.listWorkflows(),
        soarAPI.getMetrics(),
      ]);

      setPlaybooks(playbooksRes.data.data || []);
      setExecutions(executionsRes.data.data || []);
      setIntegrations(integrationsRes.data.data || []);
      setCases(casesRes.data.data || []);
      setWorkflows(workflowsRes.data.data || []);
      setMetrics(metricsRes.data.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load SOAR data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Details Handlers
  const handleViewPlaybook = (playbook) => {
    setDetailsData(playbook);
    setDetailsTitle(`Playbook: ${playbook.name}`);
    setDetailsFields([
      { label: 'Playbook ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Category', key: 'category', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Trigger Type', key: 'trigger_type', type: 'badge' },
      { label: 'Trigger Conditions', key: 'trigger_conditions', type: 'array' },
      { label: 'Actions', key: 'actions', type: 'array' },
      { label: 'Steps', key: 'steps', type: 'text' },
      { label: 'Avg Execution Time', key: 'avg_execution_time', type: 'text' },
      { label: 'Success Rate (%)', key: 'success_rate', type: 'text' },
      { label: 'Execution Count', key: 'execution_count', type: 'text' },
      { label: 'Last Executed', key: 'last_executed', type: 'date' },
      { label: 'Created By', key: 'created_by', type: 'text' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Updated At', key: 'updated_at', type: 'date' },
      { label: 'Tags', key: 'tags', type: 'array' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewExecution = (execution) => {
    setDetailsData(execution);
    setDetailsTitle(`Execution: ${execution.playbook_name}`);
    setDetailsFields([
      { label: 'Execution ID', key: 'id', type: 'text' },
      { label: 'Playbook ID', key: 'playbook_id', type: 'text' },
      { label: 'Playbook Name', key: 'playbook_name', type: 'text' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Trigger Type', key: 'trigger_type', type: 'badge' },
      { label: 'Trigger Source', key: 'trigger_source', type: 'text' },
      { label: 'Start Time', key: 'start_time', type: 'date' },
      { label: 'End Time', key: 'end_time', type: 'date' },
      { label: 'Duration', key: 'duration', type: 'text' },
      { label: 'Current Step', key: 'current_step', type: 'text' },
      { label: 'Total Steps', key: 'total_steps', type: 'text' },
      { label: 'Successful Steps', key: 'successful_steps', type: 'text' },
      { label: 'Failed Steps', key: 'failed_steps', type: 'text' },
      { label: 'Executed By', key: 'executed_by', type: 'text' },
      { label: 'Results', key: 'results', type: 'json', fullWidth: true },
      { label: 'Logs', key: 'logs', type: 'array' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewIntegration = (integration) => {
    setDetailsData(integration);
    setDetailsTitle(`Integration: ${integration.name}`);
    setDetailsFields([
      { label: 'Integration ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Vendor', key: 'vendor', type: 'text' },
      { label: 'Version', key: 'version', type: 'text' },
      { label: 'Capabilities', key: 'capabilities', type: 'array' },
      { label: 'Actions Available', key: 'actions_available', type: 'text' },
      { label: 'Last Sync', key: 'last_sync', type: 'date' },
      { label: 'Health', key: 'health', type: 'badge' },
      { label: 'API Endpoint', key: 'api_endpoint', type: 'text' },
      { label: 'Configured At', key: 'configured_at', type: 'date' },
      { label: 'Used By Playbooks', key: 'used_by_playbooks', type: 'text' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewCase = (caseItem) => {
    setDetailsData(caseItem);
    setDetailsTitle(`Case: ${caseItem.title}`);
    setDetailsFields([
      { label: 'Case ID', key: 'id', type: 'text' },
      { label: 'Title', key: 'title', type: 'text' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Severity', key: 'severity', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Priority', key: 'priority', type: 'badge' },
      { label: 'Category', key: 'category', type: 'text' },
      { label: 'Assigned To', key: 'assigned_to', type: 'text' },
      { label: 'Assigned Team', key: 'assigned_team', type: 'text' },
      { label: 'Related Alerts', key: 'related_alerts', type: 'text' },
      { label: 'Related Incidents', key: 'related_incidents', type: 'text' },
      { label: 'Playbooks Run', key: 'playbooks_run', type: 'text' },
      { label: 'Artifacts', key: 'artifacts', type: 'array' },
      { label: 'Timeline', key: 'timeline', type: 'array' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Updated At', key: 'updated_at', type: 'date' },
      { label: 'Resolved At', key: 'resolved_at', type: 'date' },
      { label: 'SLA', key: 'sla', type: 'text' },
      { label: 'SLA Status', key: 'sla_status', type: 'badge' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewWorkflow = (workflow) => {
    setDetailsData(workflow);
    setDetailsTitle(`Workflow: ${workflow.name}`);
    setDetailsFields([
      { label: 'Workflow ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Trigger Event', key: 'trigger_event', type: 'text' },
      { label: 'Conditions', key: 'conditions', type: 'array' },
      { label: 'Actions', key: 'actions', type: 'array' },
      { label: 'Execution Count', key: 'execution_count', type: 'text' },
      { label: 'Success Rate (%)', key: 'success_rate', type: 'text' },
      { label: 'Avg Duration', key: 'avg_duration', type: 'text' },
      { label: 'Last Triggered', key: 'last_triggered', type: 'date' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Integrations Used', key: 'integrations_used', type: 'array' },
    ]);
    setDetailsOpen(true);
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success', enabled: 'success', connected: 'success', completed: 'success', resolved: 'success',
      running: 'info', investigating: 'info', open: 'info',
      draft: 'default', disabled: 'default', disconnected: 'default',
      failed: 'error', error: 'error', closed: 'error',
      paused: 'warning',
    };
    return colors[status] || 'default';
  };

  const getSeverityColor = (severity) => {
    const colors = { critical: 'error', high: 'error', medium: 'warning', low: 'info' };
    return colors[severity] || 'default';
  };

  const getHealthColor = (health) => {
    const colors = { healthy: 'success', degraded: 'warning', unhealthy: 'error' };
    return colors[health] || 'default';
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box m={3}>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  return (
    <Box>
      <Box mb={3}>
        <Typography variant="h4" gutterBottom>
          <AccountTreeIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          SOAR - Security Orchestration, Automation & Response
        </Typography>
        <Typography variant="body2" color="textSecondary">
          Automate security operations with playbooks, workflows, and integrations
        </Typography>
      </Box>

      {/* KPI Cards */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Active Playbooks</Typography>
              <Typography variant="h4">{metrics.active_playbooks || 0}</Typography>
              <Typography variant="caption" color="textSecondary">
                of {metrics.total_playbooks || 0} total
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Success Rate</Typography>
              <Typography variant="h4">{metrics.success_rate || 0}%</Typography>
              <LinearProgress variant="determinate" value={metrics.success_rate || 0} sx={{ mt: 1 }} />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Executions Today</Typography>
              <Typography variant="h4">{metrics.executions_today || 0}</Typography>
              <Typography variant="caption" color="textSecondary">
                Avg: {metrics.avg_execution_time || 'N/A'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Time Saved</Typography>
              <Typography variant="h4">{metrics.times_saved || 'N/A'}</Typography>
              <Typography variant="caption" color="textSecondary">
                MTTR ↓ {metrics.mttr_reduction || 0}%
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tab label="Playbooks" />
          <Tab label="Executions" />
          <Tab label="Integrations" />
          <Tab label="Cases" />
          <Tab label="Workflows" />
        </Tabs>

        {/* Tab 0: Playbooks */}
        {activeTab === 0 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Security Playbooks</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Category</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Trigger</TableCell>
                    <TableCell>Steps</TableCell>
                    <TableCell>Success Rate</TableCell>
                    <TableCell>Executions</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {playbooks.map((playbook) => (
                    <TableRow key={playbook.id} hover>
                      <TableCell>
                        <strong>{playbook.name}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {playbook.description}
                        </Typography>
                      </TableCell>
                      <TableCell><Chip label={playbook.category} size="small" /></TableCell>
                      <TableCell><Chip label={playbook.status} color={getStatusColor(playbook.status)} size="small" /></TableCell>
                      <TableCell><Chip label={playbook.trigger_type} size="small" variant="outlined" /></TableCell>
                      <TableCell>{playbook.steps}</TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>{playbook.success_rate.toFixed(1)}%</Typography>
                          <LinearProgress variant="determinate" value={playbook.success_rate} sx={{ width: 60 }} />
                        </Box>
                      </TableCell>
                      <TableCell>{playbook.execution_count}</TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewPlaybook(playbook)}>
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

        {/* Tab 1: Executions */}
        {activeTab === 1 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Playbook Executions</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Playbook</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Trigger</TableCell>
                    <TableCell>Progress</TableCell>
                    <TableCell>Duration</TableCell>
                    <TableCell>Executed By</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {executions.map((execution) => (
                    <TableRow key={execution.id} hover>
                      <TableCell>
                        <strong>{execution.playbook_name}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {execution.id}
                        </Typography>
                      </TableCell>
                      <TableCell><Chip label={execution.status} color={getStatusColor(execution.status)} size="small" /></TableCell>
                      <TableCell><Chip label={execution.trigger_type} size="small" variant="outlined" /></TableCell>
                      <TableCell>
                        <Box>
                          <Typography variant="caption">
                            {execution.current_step}/{execution.total_steps} steps
                          </Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={(execution.current_step / execution.total_steps) * 100} 
                            sx={{ mt: 0.5 }}
                          />
                        </Box>
                      </TableCell>
                      <TableCell>{execution.duration}</TableCell>
                      <TableCell>{execution.executed_by}</TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewExecution(execution)}>
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

        {/* Tab 2: Integrations */}
        {activeTab === 2 && (
          <Grid container spacing={3} p={2}>
            {integrations.map((integration) => (
              <Grid item xs={12} md={6} key={integration.id}>
                <Card>
                  <CardContent>
                    <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                      <Box display="flex" alignItems="center">
                        <IntegrationIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
                        <Box>
                          <Typography variant="h6">{integration.name}</Typography>
                          <Typography variant="caption" color="textSecondary">
                            {integration.vendor} • {integration.type}
                          </Typography>
                        </Box>
                      </Box>
                      <Tooltip title="View Details">
                        <IconButton size="small" onClick={() => handleViewIntegration(integration)}>
                          <VisibilityIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>

                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Chip label={integration.status} color={getStatusColor(integration.status)} size="small" sx={{ mr: 1 }} />
                        <Chip label={integration.health} color={getHealthColor(integration.health)} size="small" />
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="textSecondary">Version</Typography>
                        <Typography variant="body2">{integration.version}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="textSecondary">Actions Available</Typography>
                        <Typography variant="body2"><strong>{integration.actions_available}</strong></Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="textSecondary">Used by Playbooks</Typography>
                        <Typography variant="body2"><strong>{integration.used_by_playbooks}</strong></Typography>
                      </Grid>
                    </Grid>

                    <Box mt={2}>
                      <Typography variant="caption" color="textSecondary">Capabilities:</Typography>
                      <Box mt={0.5}>
                        {integration.capabilities.slice(0, 3).map((cap, i) => (
                          <Chip key={i} label={cap} size="small" variant="outlined" sx={{ mr: 0.5, mb: 0.5 }} />
                        ))}
                        {integration.capabilities.length > 3 && (
                          <Chip label={`+${integration.capabilities.length - 3} more`} size="small" variant="outlined" />
                        )}
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}

        {/* Tab 3: Cases */}
        {activeTab === 3 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Case Management</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Title</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Priority</TableCell>
                    <TableCell>Assigned To</TableCell>
                    <TableCell>Alerts/Incidents</TableCell>
                    <TableCell>SLA Status</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {cases.map((caseItem) => (
                    <TableRow key={caseItem.id} hover>
                      <TableCell>
                        <strong>{caseItem.title}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {caseItem.category}
                        </Typography>
                      </TableCell>
                      <TableCell><Chip label={caseItem.severity} color={getSeverityColor(caseItem.severity)} size="small" /></TableCell>
                      <TableCell><Chip label={caseItem.status} color={getStatusColor(caseItem.status)} size="small" /></TableCell>
                      <TableCell><Chip label={caseItem.priority} size="small" variant="outlined" /></TableCell>
                      <TableCell>
                        <Typography variant="body2">{caseItem.assigned_to}</Typography>
                        <Typography variant="caption" color="textSecondary">{caseItem.assigned_team}</Typography>
                      </TableCell>
                      <TableCell>
                        {caseItem.related_alerts} / {caseItem.related_incidents}
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={caseItem.sla_status} 
                          color={caseItem.sla_status === 'on_track' ? 'success' : caseItem.sla_status === 'at_risk' ? 'warning' : 'error'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewCase(caseItem)}>
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

        {/* Tab 4: Workflows */}
        {activeTab === 4 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Workflow Automations</Typography>
            <Grid container spacing={3}>
              {workflows.map((workflow) => (
                <Grid item xs={12} md={6} key={workflow.id}>
                  <Card>
                    <CardContent>
                      <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                        <Box display="flex" alignItems="center">
                          <AutoAwesomeIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
                          <Box>
                            <Typography variant="h6">{workflow.name}</Typography>
                            <Typography variant="caption" color="textSecondary">
                              {workflow.type}
                            </Typography>
                          </Box>
                        </Box>
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewWorkflow(workflow)}>
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </Box>

                      <Typography variant="body2" color="textSecondary" mb={2}>
                        {workflow.description}
                      </Typography>

                      <Grid container spacing={2}>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">Status</Typography>
                          <Box>
                            <Chip label={workflow.status} color={getStatusColor(workflow.status)} size="small" />
                          </Box>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">Trigger Event</Typography>
                          <Typography variant="body2">{workflow.trigger_event}</Typography>
                        </Grid>
                        <Grid item xs={4}>
                          <Typography variant="caption" color="textSecondary">Executions</Typography>
                          <Typography variant="body2"><strong>{workflow.execution_count}</strong></Typography>
                        </Grid>
                        <Grid item xs={4}>
                          <Typography variant="caption" color="textSecondary">Success Rate</Typography>
                          <Typography variant="body2"><strong>{workflow.success_rate.toFixed(1)}%</strong></Typography>
                        </Grid>
                        <Grid item xs={4}>
                          <Typography variant="caption" color="textSecondary">Avg Duration</Typography>
                          <Typography variant="body2">{workflow.avg_duration}</Typography>
                        </Grid>
                      </Grid>

                      <Box mt={2}>
                        <Typography variant="caption" color="textSecondary">Integrations:</Typography>
                        <Box mt={0.5}>
                          {workflow.integrations_used.map((int, i) => (
                            <Chip key={i} label={int} size="small" variant="outlined" sx={{ mr: 0.5, mb: 0.5 }} />
                          ))}
                        </Box>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Box>
        )}
      </Paper>

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

export default SOAR;

