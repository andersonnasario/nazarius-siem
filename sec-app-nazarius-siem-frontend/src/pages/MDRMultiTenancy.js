import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, Button, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, MenuItem, CircularProgress, Alert, LinearProgress, IconButton, Tooltip
} from '@mui/material';
import {
  Business as BusinessIcon,
  People as PeopleIcon,
  Storage as StorageIcon,
  Event as EventIcon,
  Visibility as VisibilityIcon
} from '@mui/icons-material';
import { mdrMultiTenancyAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const MDRMultiTenancy = () => {
  const [tenants, setTenants] = useState([]);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [openDialog, setOpenDialog] = useState(false);
  const [newTenant, setNewTenant] = useState({
    name: '',
    domain: '',
    plan: 'basic'
  });

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
      const [tenantsRes, statsRes] = await Promise.all([
        mdrMultiTenancyAPI.getTenants(),
        mdrMultiTenancyAPI.getStats()
      ]);
      
      // Axios already extracts .data, so response.data is the actual API response
      // API returns: { data: [...] } so we need response.data.data
      setTenants(Array.isArray(tenantsRes.data.data) ? tenantsRes.data.data : []);
      setStats(statsRes.data.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load multi-tenancy data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTenant = async () => {
    try {
      await mdrMultiTenancyAPI.createTenant(newTenant);
      setOpenDialog(false);
      setNewTenant({ name: '', domain: '', plan: 'basic' });
      loadData();
    } catch (err) {
      setError('Failed to create tenant');
      console.error(err);
    }
  };

  const getPlanColor = (plan) => {
    const colors = {
      enterprise: 'error',
      professional: 'warning',
      basic: 'info'
    };
    return colors[plan] || 'default';
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success',
      trial: 'info',
      suspended: 'error'
    };
    return colors[status] || 'default';
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 GB';
    const gb = bytes / (1024 * 1024 * 1024);
    return `${gb.toFixed(2)} GB`;
  };

  const getStoragePercentage = (used, max) => {
    return (used / max) * 100;
  };

  // View Tenant Details
  const handleViewTenant = (tenant) => {
    setDetailsData(tenant);
    setDetailsTitle(`Tenant: ${tenant.name}`);
    setDetailsFields([
      { label: 'Tenant ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Domain', key: 'domain', type: 'text' },
      { label: 'Plan', key: 'plan', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Users', key: 'user_count', type: 'text' },
      { label: 'Max Users', key: 'max_users', type: 'text' },
      { label: 'Event Count', key: 'event_count', type: 'text' },
      { label: 'Storage Used (GB)', key: 'storage_used', type: 'text' },
      { label: 'Max Storage (GB)', key: 'max_storage', type: 'text' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Last Activity', key: 'last_activity', type: 'date' },
      { label: 'Contact Email', key: 'contact_email', type: 'text' },
      { label: 'Contact Phone', key: 'contact_phone', type: 'text' },
      { label: 'Configuration', key: 'config', type: 'json', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" gutterBottom>
          🏢 Multi-Tenancy Management
        </Typography>
        <Button variant="contained" color="primary" onClick={() => setOpenDialog(true)}>
          Create New Tenant
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Stats Cards */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Total Tenants</Typography>
                  <Typography variant="h4">{stats.total_tenants || 0}</Typography>
                </Box>
                <BusinessIcon sx={{ fontSize: 48, color: 'primary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Total Users</Typography>
                  <Typography variant="h4">{stats.total_users || 0}</Typography>
                </Box>
                <PeopleIcon sx={{ fontSize: 48, color: 'success.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Total Events</Typography>
                  <Typography variant="h4">{(stats.total_events || 0).toLocaleString()}</Typography>
                </Box>
                <EventIcon sx={{ fontSize: 48, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Total Storage</Typography>
                  <Typography variant="h4">{stats.total_storage_gb || 0} GB</Typography>
                </Box>
                <StorageIcon sx={{ fontSize: 48, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tenants Table */}
      <Paper>
        <Box p={2}>
          <Typography variant="h6" gutterBottom>Tenants</Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Domain</TableCell>
                  <TableCell>Plan</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Users</TableCell>
                  <TableCell>Events</TableCell>
                  <TableCell>Storage Usage</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {tenants.map((tenant) => (
                  <TableRow key={tenant.id} hover>
                    <TableCell><strong>{tenant.name}</strong></TableCell>
                    <TableCell>{tenant.domain}</TableCell>
                    <TableCell>
                      <Chip label={tenant.plan} color={getPlanColor(tenant.plan)} size="small" />
                    </TableCell>
                    <TableCell>
                      <Chip label={tenant.status} color={getStatusColor(tenant.status)} size="small" />
                    </TableCell>
                    <TableCell>{tenant.user_count} / {tenant.max_users}</TableCell>
                    <TableCell>{tenant.event_count.toLocaleString()}</TableCell>
                    <TableCell>
                      <Box sx={{ minWidth: 150 }}>
                        <Box display="flex" justifyContent="space-between" mb={0.5}>
                          <Typography variant="caption">
                            {formatBytes(tenant.storage_used)} / {formatBytes(tenant.max_storage)}
                          </Typography>
                        </Box>
                        <LinearProgress 
                          variant="determinate" 
                          value={getStoragePercentage(tenant.storage_used, tenant.max_storage)} 
                          color={getStoragePercentage(tenant.storage_used, tenant.max_storage) > 80 ? 'error' : 'primary'}
                        />
                      </Box>
                    </TableCell>
                    <TableCell>{new Date(tenant.created_at).toLocaleDateString()}</TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Details">
                        <IconButton size="small" onClick={() => handleViewTenant(tenant)}>
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
      </Paper>

      {/* Create Tenant Dialog */}
      <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Tenant</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Tenant Name"
              fullWidth
              value={newTenant.name}
              onChange={(e) => setNewTenant({ ...newTenant, name: e.target.value })}
            />
            <TextField
              label="Domain"
              fullWidth
              value={newTenant.domain}
              onChange={(e) => setNewTenant({ ...newTenant, domain: e.target.value })}
              placeholder="example.com"
            />
            <TextField
              select
              label="Plan"
              fullWidth
              value={newTenant.plan}
              onChange={(e) => setNewTenant({ ...newTenant, plan: e.target.value })}
            >
              <MenuItem value="basic">Basic (10 users, 50 GB)</MenuItem>
              <MenuItem value="professional">Professional (50 users, 200 GB)</MenuItem>
              <MenuItem value="enterprise">Enterprise (100 users, 500 GB)</MenuItem>
            </TextField>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>Cancel</Button>
          <Button onClick={handleCreateTenant} variant="contained" color="primary">
            Create
          </Button>
        </DialogActions>
      </Dialog>

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

export default MDRMultiTenancy;

