import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, LinearProgress, IconButton, Tooltip, Button,
  Dialog, DialogTitle, DialogContent, DialogContentText, DialogActions, Snackbar
} from '@mui/material';
import {
  Visibility as VisibilityIcon,
  Security as SecurityIcon,
  Devices as DevicesIcon,
  Policy as PolicyIcon,
  VpnLock as VpnLockIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  PowerSettingsNew as PowerIcon
} from '@mui/icons-material';
import { zeroTrustAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';
import PolicyFormDialog from '../components/PolicyFormDialog';

const ZeroTrust = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [identities, setIdentities] = useState([]);
  const [devices, setDevices] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [access, setAccess] = useState([]);
  const [segments, setSegments] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsTitle, setDetailsTitle] = useState('');
  const [detailsData, setDetailsData] = useState(null);
  const [detailsFields, setDetailsFields] = useState([]);

  // Policy management states
  const [policyFormOpen, setPolicyFormOpen] = useState(false);
  const [policyFormMode, setPolicyFormMode] = useState('create');
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [policyToDelete, setPolicyToDelete] = useState(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [identitiesRes, devicesRes, policiesRes, accessRes, segmentsRes, metricsRes] = await Promise.all([
        zeroTrustAPI.listIdentities(),
        zeroTrustAPI.listDevices(),
        zeroTrustAPI.listPolicies(),
        zeroTrustAPI.listAccess(),
        zeroTrustAPI.listSegments(),
        zeroTrustAPI.getMetrics(),
      ]);

      setIdentities(identitiesRes.data.data || []);
      setDevices(devicesRes.data.data || []);
      setPolicies(policiesRes.data.data || []);
      setAccess(accessRes.data.data || []);
      setSegments(segmentsRes.data.data || []);
      setMetrics(metricsRes.data.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load Zero Trust data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Policy Management Functions
  const handleCreatePolicy = () => {
    setSelectedPolicy(null);
    setPolicyFormMode('create');
    setPolicyFormOpen(true);
  };

  const handleEditPolicy = (policy) => {
    setSelectedPolicy(policy);
    setPolicyFormMode('edit');
    setPolicyFormOpen(true);
  };

  const handleDeleteClick = (policy) => {
    setPolicyToDelete(policy);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = async () => {
    try {
      await zeroTrustAPI.deletePolicy(policyToDelete.id);
      setPolicies(policies.filter(p => p.id !== policyToDelete.id));
      setSnackbar({ open: true, message: 'Policy deleted successfully', severity: 'success' });
      setDeleteDialogOpen(false);
      setPolicyToDelete(null);
    } catch (err) {
      setSnackbar({ open: true, message: 'Failed to delete policy', severity: 'error' });
      console.error(err);
    }
  };

  const handleTogglePolicy = async (policy) => {
    try {
      const response = await zeroTrustAPI.togglePolicy(policy.id);
      const updatedPolicy = response.data.data;
      setPolicies(policies.map(p => p.id === policy.id ? updatedPolicy : p));
      setSnackbar({ 
        open: true, 
        message: `Policy ${updatedPolicy.status === 'active' ? 'activated' : 'deactivated'} successfully`, 
        severity: 'success' 
      });
    } catch (err) {
      setSnackbar({ open: true, message: 'Failed to toggle policy status', severity: 'error' });
      console.error(err);
    }
  };

  const handleSavePolicy = async (policyData) => {
    try {
      if (policyFormMode === 'create') {
        const response = await zeroTrustAPI.createPolicy(policyData);
        setPolicies([...policies, response.data.data]);
        setSnackbar({ open: true, message: 'Policy created successfully', severity: 'success' });
      } else {
        const response = await zeroTrustAPI.updatePolicy(selectedPolicy.id, policyData);
        setPolicies(policies.map(p => p.id === selectedPolicy.id ? response.data.data : p));
        setSnackbar({ open: true, message: 'Policy updated successfully', severity: 'success' });
      }
      setPolicyFormOpen(false);
      setSelectedPolicy(null);
    } catch (err) {
      setSnackbar({ open: true, message: `Failed to ${policyFormMode} policy`, severity: 'error' });
      console.error(err);
    }
  };

  const handleViewIdentity = (identity) => {
    setDetailsData(identity);
    setDetailsTitle(`Identity: ${identity.username}`);
    setDetailsFields([
      { label: 'ID', key: 'id', type: 'text' },
      { label: 'Username', key: 'username', type: 'text' },
      { label: 'Email', key: 'email', type: 'text' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Trust Score', key: 'trust_score', type: 'text' },
      { label: 'Risk Level', key: 'risk_level', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'MFA Enabled', key: 'mfa_enabled', type: 'text' },
      { label: 'Last Authentication', key: 'last_auth', type: 'date' },
      { label: 'Failed Attempts', key: 'failed_attempts', type: 'text' },
      { label: 'Devices', key: 'devices', type: 'text' },
      { label: 'Locations', key: 'locations', type: 'array' },
      { label: 'Roles', key: 'roles', type: 'array' },
      { label: 'Created At', key: 'created_at', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewDevice = (device) => {
    setDetailsData(device);
    setDetailsTitle(`Device: ${device.name}`);
    setDetailsFields([
      { label: 'Device ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Operating System', key: 'os', type: 'text' },
      { label: 'OS Version', key: 'os_version', type: 'text' },
      { label: 'User ID', key: 'user_id', type: 'text' },
      { label: 'Username', key: 'username', type: 'text' },
      { label: 'Trust Score', key: 'trust_score', type: 'text' },
      { label: 'Compliance Score', key: 'compliance_score', type: 'text' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Encrypted', key: 'encrypted', type: 'text' },
      { label: 'Antivirus Status', key: 'antivirus_status', type: 'badge' },
      { label: 'Last Seen', key: 'last_seen', type: 'date' },
      { label: 'IP Address', key: 'ip_address', type: 'text' },
      { label: 'Location', key: 'location', type: 'text' },
      { label: 'Vulnerabilities', key: 'vulnerabilities', type: 'text' },
      { label: 'Registered At', key: 'registered_at', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewPolicy = (policy) => {
    setDetailsData(policy);
    setDetailsTitle(`Policy: ${policy.name}`);
    setDetailsFields([
      { label: 'Policy ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Priority', key: 'priority', type: 'text' },
      { label: 'Conditions', key: 'conditions', type: 'array' },
      { label: 'Actions', key: 'actions', type: 'array' },
      { label: 'Applies To', key: 'applies_to', type: 'array' },
      { label: 'Violations', key: 'violations', type: 'text' },
      { label: 'Enforcements', key: 'enforcements', type: 'text' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Updated At', key: 'updated_at', type: 'date' },
      { label: 'Created By', key: 'created_by', type: 'text' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewAccess = (accessItem) => {
    setDetailsData(accessItem);
    setDetailsTitle(`Access Request: ${accessItem.resource}`);
    setDetailsFields([
      { label: 'Access ID', key: 'id', type: 'text' },
      { label: 'User ID', key: 'user_id', type: 'text' },
      { label: 'Username', key: 'username', type: 'text' },
      { label: 'Device ID', key: 'device_id', type: 'text' },
      { label: 'Device Name', key: 'device_name', type: 'text' },
      { label: 'Resource', key: 'resource', type: 'text' },
      { label: 'Resource Type', key: 'resource_type', type: 'badge' },
      { label: 'Action', key: 'action', type: 'text' },
      { label: 'Decision', key: 'decision', type: 'badge' },
      { label: 'Reason', key: 'reason', type: 'text', fullWidth: true },
      { label: 'Trust Score', key: 'trust_score', type: 'text' },
      { label: 'Risk Score', key: 'risk_score', type: 'text' },
      { label: 'Context Factors', key: 'context_factors', type: 'array' },
      { label: 'IP Address', key: 'ip_address', type: 'text' },
      { label: 'Location', key: 'location', type: 'text' },
      { label: 'Timestamp', key: 'timestamp', type: 'date' },
      { label: 'Duration (s)', key: 'duration', type: 'text' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewSegment = (segment) => {
    setDetailsData(segment);
    setDetailsTitle(`Segment: ${segment.name}`);
    setDetailsFields([
      { label: 'Segment ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Resources', key: 'resources', type: 'text' },
      { label: 'Policies', key: 'policies', type: 'text' },
      { label: 'Allowed Sources', key: 'allowed_sources', type: 'array' },
      { label: 'Blocked Sources', key: 'blocked_sources', type: 'array' },
      { label: 'Traffic In (bytes)', key: 'traffic_in', type: 'text' },
      { label: 'Traffic Out (bytes)', key: 'traffic_out', type: 'text' },
      { label: 'Violations', key: 'violations', type: 'text' },
      { label: 'Last Activity', key: 'last_activity', type: 'date' },
      { label: 'Created At', key: 'created_at', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const getRiskColor = (risk) => {
    const colors = { low: 'success', medium: 'warning', high: 'error', critical: 'error' };
    return colors[risk] || 'default';
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success', compliant: 'success', allow: 'success',
      inactive: 'default', suspended: 'warning', testing: 'warning', challenge: 'warning',
      blocked: 'error', non_compliant: 'error', quarantined: 'error', deny: 'error',
    };
    return colors[status] || 'default';
  };

  const getTypeColor = (type) => {
    const colors = { user: 'primary', service: 'info', device: 'secondary', laptop: 'primary', mobile: 'info' };
    return colors[type] || 'default';
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
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
          <VpnLockIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Zero Trust Architecture
        </Typography>
        <Typography variant="body2" color="textSecondary">
          Never trust, always verify - Continuous authentication and authorization
        </Typography>
      </Box>

      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Active Identities</Typography>
              <Typography variant="h4">{(metrics.active_identities || 0).toLocaleString()}</Typography>
              <Typography variant="caption" color="error">
                {metrics.high_risk_identities || 0} high risk
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Avg Trust Score</Typography>
              <Typography variant="h4">{metrics.avg_trust_score || 0}%</Typography>
              <LinearProgress variant="determinate" value={metrics.avg_trust_score || 0} sx={{ mt: 1 }} />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Compliant Devices</Typography>
              <Typography variant="h4">{(metrics.compliant_devices || 0).toLocaleString()}</Typography>
              <Typography variant="caption" color="warning.main">
                {metrics.quarantined_devices || 0} quarantined
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>MFA Adoption</Typography>
              <Typography variant="h4">{metrics.mfa_adoption || 0}%</Typography>
              <LinearProgress variant="determinate" value={metrics.mfa_adoption || 0} color="success" sx={{ mt: 1 }} />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Paper>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tab label="Identities" />
          <Tab label="Devices" />
          <Tab label="Policies" />
          <Tab label="Access Logs" />
          <Tab label="Network Segments" />
        </Tabs>

        {activeTab === 0 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Identities</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Identity</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Trust Score</TableCell>
                    <TableCell>Risk Level</TableCell>
                    <TableCell>MFA</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Last Auth</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {identities.map((identity) => (
                    <TableRow key={identity.id} hover>
                      <TableCell>
                        <strong>{identity.username}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {identity.email}
                        </Typography>
                      </TableCell>
                      <TableCell><Chip label={identity.type} color={getTypeColor(identity.type)} size="small" /></TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>{identity.trust_score.toFixed(0)}</Typography>
                          <LinearProgress variant="determinate" value={identity.trust_score} sx={{ width: 60 }} />
                        </Box>
                      </TableCell>
                      <TableCell><Chip label={identity.risk_level} color={getRiskColor(identity.risk_level)} size="small" /></TableCell>
                      <TableCell>
                        <Chip label={identity.mfa_enabled ? 'Enabled' : 'Disabled'} color={identity.mfa_enabled ? 'success' : 'error'} size="small" />
                      </TableCell>
                      <TableCell><Chip label={identity.status} color={getStatusColor(identity.status)} size="small" /></TableCell>
                      <TableCell>
                        <Typography variant="caption">{new Date(identity.last_auth).toLocaleString()}</Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewIdentity(identity)}>
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

        {activeTab === 1 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Devices</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Device</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>User</TableCell>
                    <TableCell>Trust Score</TableCell>
                    <TableCell>Compliance</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {devices.map((device) => (
                    <TableRow key={device.id} hover>
                      <TableCell>
                        <strong>{device.name}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {device.os} {device.os_version}
                        </Typography>
                        <Box mt={0.5}>
                          {!device.encrypted && <Chip label="Unencrypted" color="error" size="small" sx={{ mr: 0.5 }} />}
                          {device.vulnerabilities > 0 && <Chip label={`${device.vulnerabilities} vulns`} color="warning" size="small" />}
                        </Box>
                      </TableCell>
                      <TableCell><Chip label={device.type} color={getTypeColor(device.type)} size="small" /></TableCell>
                      <TableCell>
                        <Typography variant="caption">{device.username}</Typography>
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>{device.trust_score.toFixed(0)}</Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={device.trust_score} 
                            sx={{ width: 60 }}
                            color={device.trust_score > 70 ? 'success' : device.trust_score > 50 ? 'warning' : 'error'}
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>{device.compliance_score.toFixed(0)}%</Typography>
                        </Box>
                      </TableCell>
                      <TableCell><Chip label={device.status} color={getStatusColor(device.status)} size="small" /></TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewDevice(device)}>
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

        {activeTab === 2 && (
          <Box p={2}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
              <Typography variant="h6">Policies</Typography>
              <Button
                variant="contained"
                color="primary"
                startIcon={<AddIcon />}
                onClick={handleCreatePolicy}
              >
                Create Policy
              </Button>
            </Box>
            <Grid container spacing={3}>
              {policies.map((policy) => (
                <Grid item xs={12} md={6} key={policy.id}>
                  <Card>
                    <CardContent>
                      <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                        <Box display="flex" alignItems="center">
                          <PolicyIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
                          <Box>
                            <Typography variant="h6">{policy.name}</Typography>
                            <Typography variant="caption" color="textSecondary">
                              {policy.type} • Priority {policy.priority}
                            </Typography>
                          </Box>
                        </Box>
                        <Box>
                          <Tooltip title="View Details">
                            <IconButton size="small" onClick={() => handleViewPolicy(policy)}>
                              <VisibilityIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Edit Policy">
                            <IconButton size="small" onClick={() => handleEditPolicy(policy)} color="primary">
                              <EditIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={policy.status === 'active' ? 'Deactivate' : 'Activate'}>
                            <IconButton 
                              size="small" 
                              onClick={() => handleTogglePolicy(policy)}
                              color={policy.status === 'active' ? 'success' : 'default'}
                            >
                              <PowerIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete Policy">
                            <IconButton size="small" onClick={() => handleDeleteClick(policy)} color="error">
                              <DeleteIcon />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </Box>

                      <Typography variant="body2" color="textSecondary" mb={2}>
                        {policy.description}
                      </Typography>

                      <Box mb={2}>
                        <Chip label={policy.status} color={getStatusColor(policy.status)} size="small" sx={{ mr: 1 }} />
                        <Chip label={`${policy.enforcements} enforcements`} size="small" variant="outlined" sx={{ mr: 1 }} />
                        {policy.violations > 0 && <Chip label={`${policy.violations} violations`} color="error" size="small" />}
                      </Box>

                      <Grid container spacing={2}>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">Conditions</Typography>
                          <Typography variant="body2">{policy.conditions.length}</Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">Actions</Typography>
                          <Typography variant="body2">{policy.actions.length}</Typography>
                        </Grid>
                      </Grid>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Box>
        )}

        {activeTab === 3 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Access Logs</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>User</TableCell>
                    <TableCell>Resource</TableCell>
                    <TableCell>Action</TableCell>
                    <TableCell>Decision</TableCell>
                    <TableCell>Trust Score</TableCell>
                    <TableCell>Risk Score</TableCell>
                    <TableCell>Timestamp</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {access.map((accessItem) => (
                    <TableRow key={accessItem.id} hover>
                      <TableCell>
                        <strong>{accessItem.username}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {accessItem.device_name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">{accessItem.resource}</Typography>
                        <Chip label={accessItem.resource_type} size="small" variant="outlined" sx={{ ml: 1 }} />
                      </TableCell>
                      <TableCell>{accessItem.action}</TableCell>
                      <TableCell><Chip label={accessItem.decision} color={getStatusColor(accessItem.decision)} size="small" /></TableCell>
                      <TableCell>{accessItem.trust_score.toFixed(0)}</TableCell>
                      <TableCell>
                        <Typography variant="body2" color={accessItem.risk_score > 50 ? 'error' : 'success.main'}>
                          {accessItem.risk_score.toFixed(0)}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">{new Date(accessItem.timestamp).toLocaleString()}</Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewAccess(accessItem)}>
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

        {activeTab === 4 && (
          <Grid container spacing={3} p={2}>
            {segments.map((segment) => (
              <Grid item xs={12} md={6} key={segment.id}>
                <Card>
                  <CardContent>
                    <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                      <Box display="flex" alignItems="center">
                        <SecurityIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
                        <Box>
                          <Typography variant="h6">{segment.name}</Typography>
                          <Typography variant="caption" color="textSecondary">
                            {segment.type}
                          </Typography>
                        </Box>
                      </Box>
                      <Tooltip title="View Details">
                        <IconButton size="small" onClick={() => handleViewSegment(segment)}>
                          <VisibilityIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>

                    <Typography variant="body2" color="textSecondary" mb={2}>
                      {segment.description}
                    </Typography>

                    <Box mb={2}>
                      <Chip label={segment.status} color={getStatusColor(segment.status)} size="small" sx={{ mr: 1 }} />
                      {segment.violations > 0 && <Chip label={`${segment.violations} violations`} color="error" size="small" />}
                    </Box>

                    <Grid container spacing={2}>
                      <Grid item xs={4}>
                        <Typography variant="caption" color="textSecondary">Resources</Typography>
                        <Typography variant="h6">{segment.resources}</Typography>
                      </Grid>
                      <Grid item xs={4}>
                        <Typography variant="caption" color="textSecondary">Policies</Typography>
                        <Typography variant="h6">{segment.policies}</Typography>
                      </Grid>
                      <Grid item xs={4}>
                        <Typography variant="caption" color="textSecondary">Traffic In</Typography>
                        <Typography variant="body2">{formatBytes(segment.traffic_in)}</Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}
      </Paper>

      <DetailsDialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        title={detailsTitle}
        data={detailsData}
        fields={detailsFields}
      />

      <PolicyFormDialog
        open={policyFormOpen}
        onClose={() => {
          setPolicyFormOpen(false);
          setSelectedPolicy(null);
        }}
        onSave={handleSavePolicy}
        policy={selectedPolicy}
        mode={policyFormMode}
      />

      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete Policy</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to delete the policy "{policyToDelete?.name}"? This action cannot be undone.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)} color="inherit">
            Cancel
          </Button>
          <Button onClick={handleDeleteConfirm} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ZeroTrust;
