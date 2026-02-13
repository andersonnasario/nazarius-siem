import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Tabs,
  Tab,
  Button,
  Card,
  CardContent,
  Grid,
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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  List,
  ListItem,
  ListItemText,
  Divider,
  Tooltip,
  LinearProgress,
} from '@mui/material';
import {
  Storage as StorageIcon,
  Delete as DeleteIcon,
  Archive as ArchiveIcon,
  Compress as CompressIcon,
  PlayArrow as PlayArrowIcon,
  Edit as EditIcon,
  Add as AddIcon,
  History as HistoryIcon,
  Settings as SettingsIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Schedule as ScheduleIcon,
  DataUsage as DataUsageIcon,
} from '@mui/icons-material';
import { retentionAPI } from '../services/api';

// ============================================================================
// MAIN DATA RETENTION PAGE
// ============================================================================

const DataRetentionPage = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [policies, setPolicies] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [configs, setConfigs] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  
  // Dialogs
  const [policyDialog, setPolicyDialog] = useState(false);
  const [configDialog, setConfigDialog] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [selectedConfig, setSelectedConfig] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      const [policiesData, executionsData, configsData, statsData] = await Promise.all([
        retentionAPI.getPolicies(),
        retentionAPI.getExecutions(),
        retentionAPI.getConfigs(),
        retentionAPI.getStats(),
      ]);
      
      setPolicies(policiesData.policies || []);
      setExecutions(executionsData.executions || []);
      setConfigs(configsData.configs || []);
      setStats(statsData);
      
    } catch (error) {
      console.error('Error loading retention data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleExecutePolicy = async (id) => {
    try {
      await retentionAPI.executePolicy(id);
      loadData();
    } catch (error) {
      console.error('Error executing policy:', error);
    }
  };

  const handleDeletePolicy = async (id) => {
    if (window.confirm('Are you sure you want to delete this policy?')) {
      try {
        await retentionAPI.deletePolicy(id);
        loadData();
      } catch (error) {
        console.error('Error deleting policy:', error);
      }
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <StorageIcon sx={{ fontSize: 40, color: 'primary.main' }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Data Retention Policies
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Automated data lifecycle management
            </Typography>
          </Box>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => {
            setSelectedPolicy(null);
            setPolicyDialog(true);
          }}
        >
          New Policy
        </Button>
      </Box>

      {/* Stats Cards */}
      {stats && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Total Policies
                    </Typography>
                    <Typography variant="h4" fontWeight="bold">
                      {stats.total_policies}
                    </Typography>
                    <Typography variant="caption" color="success.main">
                      {stats.active_policies} active
                    </Typography>
                  </Box>
                  <SettingsIcon sx={{ fontSize: 40, color: 'primary.main', opacity: 0.3 }} />
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
                      Items Deleted
                    </Typography>
                    <Typography variant="h4" fontWeight="bold">
                      {stats.total_items_deleted.toLocaleString()}
                    </Typography>
                  </Box>
                  <DeleteIcon sx={{ fontSize: 40, color: 'error.main', opacity: 0.3 }} />
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
                      Space Freed
                    </Typography>
                    <Typography variant="h4" fontWeight="bold">
                      {formatBytes(stats.total_bytes_freed)}
                    </Typography>
                  </Box>
                  <DataUsageIcon sx={{ fontSize: 40, color: 'success.main', opacity: 0.3 }} />
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
                      Total Executions
                    </Typography>
                    <Typography variant="h4" fontWeight="bold">
                      {stats.total_executions}
                    </Typography>
                  </Box>
                  <HistoryIcon sx={{ fontSize: 40, color: 'info.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Main Content */}
      <Paper sx={{ width: '100%' }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label="Policies" />
          <Tab label="Execution History" />
          <Tab label="Data Type Configs" />
        </Tabs>
        
        <Divider />

        {loading && <LinearProgress />}

        {/* Tab: Policies */}
        {activeTab === 0 && (
          <Box sx={{ p: 2 }}>
            <Grid container spacing={2}>
              {policies.length === 0 ? (
                <Grid item xs={12}>
                  <Box sx={{ textAlign: 'center', py: 4 }}>
                    <StorageIcon sx={{ fontSize: 60, color: 'text.disabled', mb: 2 }} />
                    <Typography variant="h6" color="text.secondary">
                      No policies configured
                    </Typography>
                  </Box>
                </Grid>
              ) : (
                policies.map((policy) => (
                  <Grid item xs={12} md={6} key={policy.id}>
                    <PolicyCard
                      policy={policy}
                      onExecute={handleExecutePolicy}
                      onEdit={(p) => {
                        setSelectedPolicy(p);
                        setPolicyDialog(true);
                      }}
                      onDelete={handleDeletePolicy}
                    />
                  </Grid>
                ))
              )}
            </Grid>
          </Box>
        )}

        {/* Tab: Execution History */}
        {activeTab === 1 && (
          <Box sx={{ p: 2 }}>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Policy</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Start Time</TableCell>
                    <TableCell>Duration</TableCell>
                    <TableCell>Items Processed</TableCell>
                    <TableCell>Items Deleted</TableCell>
                    <TableCell>Space Saved</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {executions.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center">
                        <Typography color="text.secondary">No executions yet</Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    executions.map((exec) => (
                      <TableRow key={exec.id}>
                        <TableCell>{exec.policy_name}</TableCell>
                        <TableCell>
                          <Chip
                            label={exec.status}
                            size="small"
                            color={exec.status === 'completed' ? 'success' : exec.status === 'failed' ? 'error' : 'default'}
                            icon={exec.status === 'completed' ? <CheckCircleIcon /> : exec.status === 'failed' ? <ErrorIcon /> : undefined}
                          />
                        </TableCell>
                        <TableCell>{new Date(exec.start_time).toLocaleString()}</TableCell>
                        <TableCell>
                          {exec.end_time ? 
                            `${Math.round((new Date(exec.end_time) - new Date(exec.start_time)) / 1000)}s` : 
                            'Running...'}
                        </TableCell>
                        <TableCell>{exec.items_processed.toLocaleString()}</TableCell>
                        <TableCell>{exec.items_deleted.toLocaleString()}</TableCell>
                        <TableCell>{formatBytes(exec.bytes_saved)}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* Tab: Data Type Configs */}
        {activeTab === 2 && (
          <Box sx={{ p: 2 }}>
            <Grid container spacing={2}>
              {configs.map((config) => (
                <Grid item xs={12} md={6} key={config.data_type}>
                  <ConfigCard
                    config={config}
                    onEdit={(c) => {
                      setSelectedConfig(c);
                      setConfigDialog(true);
                    }}
                  />
                </Grid>
              ))}
            </Grid>
          </Box>
        )}
      </Paper>

      {/* Policy Dialog */}
      <PolicyDialog
        open={policyDialog}
        policy={selectedPolicy}
        onClose={() => setPolicyDialog(false)}
        onSave={loadData}
      />

      {/* Config Dialog */}
      <ConfigDialog
        open={configDialog}
        config={selectedConfig}
        onClose={() => setConfigDialog(false)}
        onSave={loadData}
      />
    </Box>
  );
};

// ============================================================================
// POLICY CARD COMPONENT
// ============================================================================

const PolicyCard = ({ policy, onExecute, onEdit, onDelete }) => {
  const getActionIcon = (type) => {
    switch (type) {
      case 'archive':
        return <ArchiveIcon fontSize="small" />;
      case 'compress':
        return <CompressIcon fontSize="small" />;
      case 'delete':
        return <DeleteIcon fontSize="small" />;
      default:
        return null;
    }
  };

  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Box>
            <Typography variant="h6" fontWeight="bold">
              {policy.name}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              {policy.description}
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Chip label={policy.data_type} size="small" color="primary" />
              <Chip
                label={policy.enabled ? 'Enabled' : 'Disabled'}
                size="small"
                color={policy.enabled ? 'success' : 'default'}
              />
              <Chip
                icon={<ScheduleIcon />}
                label={policy.schedule}
                size="small"
                variant="outlined"
              />
            </Box>
          </Box>
          <Switch checked={policy.enabled} disabled />
        </Box>

        <Divider sx={{ my: 2 }} />

        <Box sx={{ mb: 2 }}>
          <Typography variant="caption" color="text.secondary" fontWeight="bold">
            CONDITIONS:
          </Typography>
          <List dense>
            {policy.conditions.map((cond, idx) => (
              <ListItem key={idx} sx={{ py: 0 }}>
                <ListItemText
                  primary={`${cond.field} ${cond.operator} ${cond.value}`}
                  primaryTypographyProps={{ variant: 'body2' }}
                />
              </ListItem>
            ))}
          </List>
        </Box>

        <Box sx={{ mb: 2 }}>
          <Typography variant="caption" color="text.secondary" fontWeight="bold">
            ACTIONS:
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
            {policy.actions.map((action, idx) => (
              <Chip
                key={idx}
                icon={getActionIcon(action.type)}
                label={action.type}
                size="small"
                variant="outlined"
              />
            ))}
          </Box>
        </Box>

        {policy.last_run && (
          <Typography variant="caption" color="text.disabled">
            Last run: {new Date(policy.last_run).toLocaleString()}
          </Typography>
        )}

        <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
          <Tooltip title="Execute Now">
            <IconButton size="small" color="primary" onClick={() => onExecute(policy.id)}>
              <PlayArrowIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Edit">
            <IconButton size="small" onClick={() => onEdit(policy)}>
              <EditIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete">
            <IconButton size="small" color="error" onClick={() => onDelete(policy.id)}>
              <DeleteIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </CardContent>
    </Card>
  );
};

// ============================================================================
// CONFIG CARD COMPONENT
// ============================================================================

const ConfigCard = ({ config, onEdit }) => {
  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Typography variant="h6" fontWeight="bold" textTransform="capitalize">
            {config.data_type.replace('_', ' ')}
          </Typography>
          <IconButton size="small" onClick={() => onEdit(config)}>
            <EditIcon />
          </IconButton>
        </Box>

        <Grid container spacing={2}>
          <Grid item xs={6}>
            <Typography variant="caption" color="text.secondary">
              Default Retention
            </Typography>
            <Typography variant="h6">{config.default_retention} days</Typography>
          </Grid>
          <Grid item xs={6}>
            <Typography variant="caption" color="text.secondary">
              Min / Max
            </Typography>
            <Typography variant="h6">
              {config.min_retention} / {config.max_retention}
            </Typography>
          </Grid>
        </Grid>

        <Divider sx={{ my: 2 }} />

        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          {config.can_archive && <Chip label="Can Archive" size="small" color="success" />}
          {config.can_compress && <Chip label="Can Compress" size="small" color="info" />}
          {config.can_delete && <Chip label="Can Delete" size="small" color="error" />}
        </Box>
      </CardContent>
    </Card>
  );
};

// ============================================================================
// POLICY DIALOG (Simplified)
// ============================================================================

const PolicyDialog = ({ open, policy, onClose, onSave }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    enabled: true,
    data_type: 'events',
    schedule: '0 2 * * *',
  });

  useEffect(() => {
    if (policy) {
      setFormData(policy);
    } else {
      setFormData({
        name: '',
        description: '',
        enabled: true,
        data_type: 'events',
        schedule: '0 2 * * *',
      });
    }
  }, [policy, open]);

  const handleSave = async () => {
    try {
      if (policy) {
        await retentionAPI.updatePolicy(policy.id, formData);
      } else {
        await retentionAPI.createPolicy({
          ...formData,
          conditions: [{ field: 'age', operator: 'gt', value: 90 }],
          actions: [{ type: 'archive' }],
          priority: 1,
        });
      }
      onSave();
      onClose();
    } catch (error) {
      console.error('Error saving policy:', error);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{policy ? 'Edit Policy' : 'New Policy'}</DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 2 }}>
          <TextField
            label="Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            fullWidth
          />
          <TextField
            label="Description"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            fullWidth
            multiline
            rows={2}
          />
          <FormControl fullWidth>
            <InputLabel>Data Type</InputLabel>
            <Select
              value={formData.data_type}
              onChange={(e) => setFormData({ ...formData, data_type: e.target.value })}
              label="Data Type"
            >
              <MenuItem value="events">Events</MenuItem>
              <MenuItem value="logs">Logs</MenuItem>
              <MenuItem value="alerts">Alerts</MenuItem>
              <MenuItem value="reports">Reports</MenuItem>
              <MenuItem value="audit_logs">Audit Logs</MenuItem>
            </Select>
          </FormControl>
          <TextField
            label="Schedule (Cron)"
            value={formData.schedule}
            onChange={(e) => setFormData({ ...formData, schedule: e.target.value })}
            fullWidth
            helperText="Example: 0 2 * * * (Daily at 2 AM)"
          />
          <FormControlLabel
            control={
              <Switch
                checked={formData.enabled}
                onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
              />
            }
            label="Enabled"
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSave} variant="contained">
          Save
        </Button>
      </DialogActions>
    </Dialog>
  );
};

// ============================================================================
// CONFIG DIALOG (Simplified)
// ============================================================================

const ConfigDialog = ({ open, config, onClose, onSave }) => {
  const [formData, setFormData] = useState({
    default_retention: 90,
    min_retention: 7,
    max_retention: 365,
  });

  useEffect(() => {
    if (config) {
      setFormData(config);
    }
  }, [config, open]);

  const handleSave = async () => {
    try {
      if (config) {
        await retentionAPI.updateConfig(config.data_type, formData);
      }
      onSave();
      onClose();
    } catch (error) {
      console.error('Error saving config:', error);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Edit Data Type Configuration</DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 2 }}>
          <TextField
            label="Default Retention (days)"
            type="number"
            value={formData.default_retention}
            onChange={(e) => setFormData({ ...formData, default_retention: parseInt(e.target.value) })}
            fullWidth
          />
          <TextField
            label="Minimum Retention (days)"
            type="number"
            value={formData.min_retention}
            onChange={(e) => setFormData({ ...formData, min_retention: parseInt(e.target.value) })}
            fullWidth
          />
          <TextField
            label="Maximum Retention (days)"
            type="number"
            value={formData.max_retention}
            onChange={(e) => setFormData({ ...formData, max_retention: parseInt(e.target.value) })}
            fullWidth
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSave} variant="contained">
          Save
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default DataRetentionPage;

