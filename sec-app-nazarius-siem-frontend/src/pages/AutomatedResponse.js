import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Switch,
  FormControlLabel,
  List,
  ListItem,
  ListItemText,
  Divider,
  Alert,
  Tooltip,
  LinearProgress,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Undo as UndoIcon,
  CheckCircle as ApproveIcon,
  Cancel as RejectIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import DetailsDialog from '../components/DetailsDialog';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { automatedResponseAPI } from '../services/api';

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8'];

const AutomatedResponse = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(false);
  
  // Data states
  const [stats, setStats] = useState(null);
  const [rules, setRules] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [approvals, setApprovals] = useState([]);
  
  // Dialog states
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false);
  const [executionDialogOpen, setExecutionDialogOpen] = useState(false);
  const [approvalDialogOpen, setApprovalDialogOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState(null);
  const [selectedExecution, setSelectedExecution] = useState(null);
  const [selectedApproval, setSelectedApproval] = useState(null);
  
  // Details Dialog states
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsTitle, setDetailsTitle] = useState('');
  const [detailsData, setDetailsData] = useState(null);
  const [detailsFields, setDetailsFields] = useState([]);
  
  // Form states
  const [ruleForm, setRuleForm] = useState({
    name: '',
    description: '',
    enabled: true,
    priority: 1,
    require_approval: false,
    auto_rollback: false,
    conditions: [],
    actions: [],
  });

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      const [statsRes, rulesRes, executionsRes, approvalsRes] = await Promise.all([
        automatedResponseAPI.getStats(),
        automatedResponseAPI.listRules(),
        automatedResponseAPI.listExecutions(),
        automatedResponseAPI.listApprovals(),
      ]);
      
      setStats(statsRes.data.data);
      setRules(rulesRes.data.data || []);
      setExecutions(executionsRes.data.data || []);
      setApprovals(approvalsRes.data.data || []);
    } catch (error) {
      console.error('Error loading data:', error);
    }
  };

  const handleCreateRule = async () => {
    try {
      setLoading(true);
      await automatedResponseAPI.createRule(ruleForm);
      setRuleDialogOpen(false);
      setRuleForm({
        name: '',
        description: '',
        enabled: true,
        priority: 1,
        require_approval: false,
        auto_rollback: false,
        conditions: [],
        actions: [],
      });
      loadData();
    } catch (error) {
      console.error('Error creating rule:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateRule = async (id, updates) => {
    try {
      setLoading(true);
      await automatedResponseAPI.updateRule(id, updates);
      loadData();
    } catch (error) {
      console.error('Error updating rule:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteRule = async (id) => {
    if (!window.confirm('Are you sure you want to delete this rule?')) return;
    
    try {
      setLoading(true);
      await automatedResponseAPI.deleteRule(id);
      loadData();
    } catch (error) {
      console.error('Error deleting rule:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleTriggerExecution = async (ruleId) => {
    try {
      setLoading(true);
      await automatedResponseAPI.triggerExecution({
        rule_id: ruleId,
        alert_id: 'manual-trigger',
        incident_id: '',
      });
      loadData();
    } catch (error) {
      console.error('Error triggering execution:', error);
    } finally {
      setLoading(false);
    }
  };

  // View Details Handlers
  const handleViewRuleDetails = (rule) => {
    setDetailsData(rule);
    setDetailsTitle(`Rule: ${rule.name}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Name', key: 'name' },
      { label: 'Description', key: 'description', fullWidth: true },
      { label: 'Enabled', key: 'enabled', type: 'status' },
      { label: 'Priority', key: 'priority', type: 'badge' },
      { label: 'Require Approval', key: 'require_approval', type: 'status' },
      { label: 'Auto Rollback', key: 'auto_rollback', type: 'status' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Updated At', key: 'updated_at', type: 'date' },
      { label: 'Conditions', key: 'conditions', type: 'json', fullWidth: true },
      { label: 'Actions', key: 'actions', type: 'json', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  const handleViewExecutionDetails = (execution) => {
    setDetailsData(execution);
    setDetailsTitle(`Execution: ${execution.id}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Rule ID', key: 'rule_id' },
      { label: 'Status', key: 'status', type: 'status' },
      { label: 'Started At', key: 'started_at', type: 'date' },
      { label: 'Completed At', key: 'completed_at', type: 'date' },
      { label: 'Duration (s)', key: 'duration' },
      { label: 'Success', key: 'success', type: 'status' },
      { label: 'Result', key: 'result', fullWidth: true },
      { label: 'Error', key: 'error', fullWidth: true },
      { label: 'Rollback Available', key: 'rollback_available', type: 'status' }
    ]);
    setDetailsOpen(true);
  };

  const handleViewApprovalDetails = (approval) => {
    setDetailsData(approval);
    setDetailsTitle(`Approval: ${approval.id}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Rule ID', key: 'rule_id' },
      { label: 'Execution ID', key: 'execution_id' },
      { label: 'Status', key: 'status', type: 'status' },
      { label: 'Requested At', key: 'requested_at', type: 'date' },
      { label: 'Requested By', key: 'requested_by' },
      { label: 'Reviewed At', key: 'reviewed_at', type: 'date' },
      { label: 'Reviewed By', key: 'reviewed_by' },
      { label: 'Reason', key: 'reason', fullWidth: true },
      { label: 'Comments', key: 'comments', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  const handleCancelExecution = async (id) => {
    try {
      setLoading(true);
      await automatedResponseAPI.cancelExecution(id);
      loadData();
    } catch (error) {
      console.error('Error cancelling execution:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRollbackExecution = async (id) => {
    if (!window.confirm('Are you sure you want to rollback this execution?')) return;
    
    try {
      setLoading(true);
      await automatedResponseAPI.rollbackExecution(id);
      loadData();
    } catch (error) {
      console.error('Error rolling back execution:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleApproveExecution = async (id) => {
    try {
      setLoading(true);
      await automatedResponseAPI.approveExecution(id, {
        approved_by: 'current_user',
        comments: 'Approved',
      });
      loadData();
      setApprovalDialogOpen(false);
    } catch (error) {
      console.error('Error approving execution:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRejectExecution = async (id) => {
    try {
      setLoading(true);
      await automatedResponseAPI.rejectExecution(id, {
        rejected_by: 'current_user',
        reason: 'Rejected',
      });
      loadData();
      setApprovalDialogOpen(false);
    } catch (error) {
      console.error('Error rejecting execution:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      pending: 'warning',
      pending_approval: 'info',
      executing: 'primary',
      completed: 'success',
      failed: 'error',
      cancelled: 'default',
      rolled_back: 'secondary',
    };
    return colors[status] || 'default';
  };

  const getActionTypeIcon = (type) => {
    const icons = {
      isolate_host: '🔒',
      block_ip: '🚫',
      disable_user: '👤',
      kill_process: '⚠️',
      quarantine_file: '📦',
      segment_network: '🌐',
    };
    return icons[type] || '⚡';
  };

  // KPI Cards
  const renderKPICards = () => {
    if (!stats) return null;

    return (
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Total Executions
                  </Typography>
                  <Typography variant="h4">{stats.total_executions}</Typography>
                  <Typography variant="body2" color="success.main">
                    {stats.successful_actions} successful
                  </Typography>
                </Box>
                <SpeedIcon sx={{ fontSize: 40, color: 'primary.main', opacity: 0.3 }} />
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
                    Pending Approvals
                  </Typography>
                  <Typography variant="h4">{stats.pending_approvals}</Typography>
                  <Typography variant="body2" color="warning.main">
                    Requires attention
                  </Typography>
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
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Avg Response Time
                  </Typography>
                  <Typography variant="h4">{Math.round(stats.average_response_time)}s</Typography>
                  <Typography variant="body2" color="info.main">
                    Automated containment
                  </Typography>
                </Box>
                <TrendingUpIcon sx={{ fontSize: 40, color: 'info.main', opacity: 0.3 }} />
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
                    Active Rules
                  </Typography>
                  <Typography variant="h4">{rules.filter(r => r.enabled).length}</Typography>
                  <Typography variant="body2" color="success.main">
                    {rules.length} total rules
                  </Typography>
                </Box>
                <SecurityIcon sx={{ fontSize: 40, color: 'success.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    );
  };

  // Overview Tab
  const renderOverviewTab = () => {
    if (!stats) return <LinearProgress />;

    const executionStatusData = Object.entries(stats.executions_by_status || {}).map(([name, value]) => ({
      name: name.replace('_', ' ').toUpperCase(),
      value,
    }));

    const actionTypeData = Object.entries(stats.actions_by_type || {}).map(([name, value]) => ({
      name: name.replace('_', ' ').toUpperCase(),
      value,
    }));

    return (
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Execution Status Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={executionStatusData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {executionStatusData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Actions by Type
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={actionTypeData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                  <YAxis />
                  <RechartsTooltip />
                  <Bar dataKey="value" fill="#8884d8" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Execution Timeline (Last 24h)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={stats.time_series_data || []}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="timestamp" 
                    tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                  />
                  <YAxis />
                  <RechartsTooltip 
                    labelFormatter={(value) => new Date(value).toLocaleString()}
                  />
                  <Legend />
                  <Line type="monotone" dataKey="executions" stroke="#8884d8" name="Total" />
                  <Line type="monotone" dataKey="successful" stroke="#82ca9d" name="Successful" />
                  <Line type="monotone" dataKey="failed" stroke="#ff7c7c" name="Failed" />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Top Performing Rules
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Rule Name</TableCell>
                      <TableCell align="right">Executions</TableCell>
                      <TableCell align="right">Success Rate</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(stats.top_rules || []).map((rule) => (
                      <TableRow key={rule.rule_id}>
                        <TableCell>{rule.rule_name}</TableCell>
                        <TableCell align="right">{rule.executions}</TableCell>
                        <TableCell align="right">
                          <Chip 
                            label={`${rule.success_rate.toFixed(1)}%`}
                            color={rule.success_rate > 80 ? 'success' : 'warning'}
                            size="small"
                          />
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
    );
  };

  // Rules Tab
  const renderRulesTab = () => {
    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">Response Rules</Typography>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => {
                setSelectedRule(null);
                setRuleDialogOpen(true);
              }}
            >
              New Rule
            </Button>
          </Box>

          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Priority</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Actions</TableCell>
                  <TableCell>Approval</TableCell>
                  <TableCell>Auto Rollback</TableCell>
                  <TableCell align="right">Operations</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell>
                      <Typography variant="body2" fontWeight="bold">
                        {rule.name}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {rule.description}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={`P${rule.priority}`} size="small" />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={rule.enabled ? 'Enabled' : 'Disabled'}
                        color={rule.enabled ? 'success' : 'default'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      {rule.actions.map((action, idx) => (
                        <Tooltip key={idx} title={action.description}>
                          <Chip
                            label={`${getActionTypeIcon(action.type)} ${action.type}`}
                            size="small"
                            sx={{ mr: 0.5, mb: 0.5 }}
                          />
                        </Tooltip>
                      ))}
                    </TableCell>
                    <TableCell>
                      {rule.require_approval ? (
                        <Chip label="Required" color="warning" size="small" />
                      ) : (
                        <Chip label="Not Required" size="small" />
                      )}
                    </TableCell>
                    <TableCell>
                      {rule.auto_rollback ? (
                        <Chip label={`${rule.rollback_after}m`} color="info" size="small" />
                      ) : (
                        <Chip label="Disabled" size="small" />
                      )}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Trigger Execution">
                        <IconButton
                          size="small"
                          onClick={() => handleTriggerExecution(rule.id)}
                          disabled={!rule.enabled}
                        >
                          <PlayIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit Rule">
                        <IconButton
                          size="small"
                          onClick={() => {
                            setSelectedRule(rule);
                            setRuleForm(rule);
                            setRuleDialogOpen(true);
                          }}
                        >
                          <EditIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete Rule">
                        <IconButton
                          size="small"
                          onClick={() => handleDeleteRule(rule.id)}
                          color="error"
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="View Details">
                        <IconButton
                          size="small"
                          onClick={() => handleViewRuleDetails(rule)}
                        >
                          <ViewIcon />
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
    );
  };

  // Executions Tab
  const renderExecutionsTab = () => {
    return (
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Execution History
          </Typography>

          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>Rule</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Actions</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell>Duration</TableCell>
                  <TableCell align="right">Operations</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {executions.map((execution) => (
                  <TableRow key={execution.id}>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {execution.id.substring(0, 8)}
                      </Typography>
                    </TableCell>
                    <TableCell>{execution.rule_name}</TableCell>
                    <TableCell>
                      <Chip
                        label={execution.status.replace('_', ' ').toUpperCase()}
                        color={getStatusColor(execution.status)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      {execution.actions.map((action, idx) => (
                        <Tooltip key={idx} title={`${action.status}: ${action.result}`}>
                          <Chip
                            label={getActionTypeIcon(action.type)}
                            color={getStatusColor(action.status)}
                            size="small"
                            sx={{ mr: 0.5 }}
                          />
                        </Tooltip>
                      ))}
                    </TableCell>
                    <TableCell>
                      {new Date(execution.started_at).toLocaleString()}
                    </TableCell>
                    <TableCell>{execution.duration}s</TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Details">
                        <IconButton
                          size="small"
                          onClick={() => handleViewExecutionDetails(execution)}
                        >
                          <ViewIcon />
                        </IconButton>
                      </Tooltip>
                      {execution.status === 'pending' && (
                        <Tooltip title="Cancel">
                          <IconButton
                            size="small"
                            onClick={() => handleCancelExecution(execution.id)}
                            color="error"
                          >
                            <StopIcon />
                          </IconButton>
                        </Tooltip>
                      )}
                      {execution.status === 'completed' && (
                        <Tooltip title="Rollback">
                          <IconButton
                            size="small"
                            onClick={() => handleRollbackExecution(execution.id)}
                            color="warning"
                          >
                            <UndoIcon />
                          </IconButton>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    );
  };

  // Approvals Tab
  const renderApprovalsTab = () => {
    return (
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Pending Approvals
          </Typography>

          {approvals.filter(a => a.status === 'pending').length === 0 ? (
            <Alert severity="info">No pending approvals</Alert>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Rule</TableCell>
                    <TableCell>Actions</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Requested</TableCell>
                    <TableCell>Expires</TableCell>
                    <TableCell align="right">Operations</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {approvals
                    .filter(a => a.status === 'pending')
                    .map((approval) => (
                      <TableRow key={approval.id}>
                        <TableCell>{approval.rule_name}</TableCell>
                        <TableCell>
                          <List dense>
                            {approval.actions.map((action, idx) => (
                              <ListItem key={idx} disableGutters>
                                <ListItemText primary={action} />
                              </ListItem>
                            ))}
                          </List>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={approval.severity.toUpperCase()}
                            color={approval.severity === 'critical' ? 'error' : 'warning'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          {new Date(approval.requested_at).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          {new Date(approval.expires_at).toLocaleString()}
                        </TableCell>
                        <TableCell align="right">
                          <Tooltip title="Approve">
                            <IconButton
                              size="small"
                              onClick={() => handleApproveExecution(approval.execution_id)}
                              color="success"
                            >
                              <ApproveIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Reject">
                            <IconButton
                              size="small"
                              onClick={() => handleRejectExecution(approval.execution_id)}
                              color="error"
                            >
                              <RejectIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="View Details">
                            <IconButton
                              size="small"
                              onClick={() => handleViewApprovalDetails(approval)}
                            >
                              <ViewIcon />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>
    );
  };

  // Rule Dialog
  const renderRuleDialog = () => {
    return (
      <Dialog open={ruleDialogOpen} onClose={() => setRuleDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {selectedRule ? 'Edit Response Rule' : 'Create Response Rule'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <TextField
              fullWidth
              label="Rule Name"
              value={ruleForm.name}
              onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })}
              sx={{ mb: 2 }}
            />
            <TextField
              fullWidth
              label="Description"
              value={ruleForm.description}
              onChange={(e) => setRuleForm({ ...ruleForm, description: e.target.value })}
              multiline
              rows={3}
              sx={{ mb: 2 }}
            />
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Priority</InputLabel>
                  <Select
                    value={ruleForm.priority}
                    onChange={(e) => setRuleForm({ ...ruleForm, priority: e.target.value })}
                    label="Priority"
                  >
                    <MenuItem value={1}>1 - Critical</MenuItem>
                    <MenuItem value={2}>2 - High</MenuItem>
                    <MenuItem value={3}>3 - Medium</MenuItem>
                    <MenuItem value={4}>4 - Low</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={ruleForm.enabled}
                      onChange={(e) => setRuleForm({ ...ruleForm, enabled: e.target.checked })}
                    />
                  }
                  label="Enabled"
                />
              </Grid>
            </Grid>
            <Divider sx={{ my: 2 }} />
            <FormControlLabel
              control={
                <Switch
                  checked={ruleForm.require_approval}
                  onChange={(e) => setRuleForm({ ...ruleForm, require_approval: e.target.checked })}
                />
              }
              label="Require Approval"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={ruleForm.auto_rollback}
                  onChange={(e) => setRuleForm({ ...ruleForm, auto_rollback: e.target.checked })}
                />
              }
              label="Auto Rollback"
            />
            <Alert severity="info" sx={{ mt: 2 }}>
              Note: Conditions and actions configuration will be available in the next version.
            </Alert>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRuleDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleCreateRule} variant="contained" disabled={loading}>
            {selectedRule ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>
    );
  };

  // Execution Details Dialog
  const renderExecutionDialog = () => {
    if (!selectedExecution) return null;

    return (
      <Dialog 
        open={executionDialogOpen} 
        onClose={() => setExecutionDialogOpen(false)} 
        maxWidth="md" 
        fullWidth
      >
        <DialogTitle>Execution Details</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Execution ID</Typography>
                <Typography variant="body1" fontFamily="monospace">{selectedExecution.id}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Status</Typography>
                <Chip
                  label={selectedExecution.status.replace('_', ' ').toUpperCase()}
                  color={getStatusColor(selectedExecution.status)}
                  size="small"
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Rule</Typography>
                <Typography variant="body1">{selectedExecution.rule_name}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Duration</Typography>
                <Typography variant="body1">{selectedExecution.duration}s</Typography>
              </Grid>
            </Grid>

            <Divider sx={{ my: 2 }} />

            <Typography variant="h6" gutterBottom>Actions</Typography>
            <List>
              {selectedExecution.actions.map((action, idx) => (
                <React.Fragment key={idx}>
                  <ListItem>
                    <ListItemText
                      primary={`${getActionTypeIcon(action.type)} ${action.type} - ${action.target}`}
                      secondary={
                        <>
                          <Typography variant="body2">Status: {action.status}</Typography>
                          <Typography variant="body2">Result: {action.result}</Typography>
                          {action.error_message && (
                            <Typography variant="body2" color="error">
                              Error: {action.error_message}
                            </Typography>
                          )}
                        </>
                      }
                    />
                  </ListItem>
                  {idx < selectedExecution.actions.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>

            <Divider sx={{ my: 2 }} />

            <Typography variant="h6" gutterBottom>Audit Log</Typography>
            <List dense>
              {selectedExecution.audit_log.map((entry, idx) => (
                <ListItem key={idx}>
                  <ListItemText
                    primary={entry.event.replace('_', ' ').toUpperCase()}
                    secondary={`${new Date(entry.timestamp).toLocaleString()} - ${entry.user}`}
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExecutionDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    );
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          🤖 Automated Response Engine
        </Typography>
        <Typography variant="body1" color="textSecondary">
          Automated threat containment and response orchestration
        </Typography>
      </Box>

      {renderKPICards()}

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
          <Tab label="Overview" />
          <Tab label="Rules" />
          <Tab label="Executions" />
          <Tab label={`Approvals ${approvals.filter(a => a.status === 'pending').length > 0 ? `(${approvals.filter(a => a.status === 'pending').length})` : ''}`} />
        </Tabs>
      </Box>

      {activeTab === 0 && renderOverviewTab()}
      {activeTab === 1 && renderRulesTab()}
      {activeTab === 2 && renderExecutionsTab()}
      {activeTab === 3 && renderApprovalsTab()}

      {renderRuleDialog()}
      {renderExecutionDialog()}

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

export default AutomatedResponse;

