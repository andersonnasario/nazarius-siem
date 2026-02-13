import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, IconButton, Tooltip
} from '@mui/material';
import {
  Security as SecurityIcon,
  Token as TokenIcon,
  Computer as ComputerIcon,
  Warning as WarningIcon,
  Visibility as VisibilityIcon
} from '@mui/icons-material';
import { deceptionAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const DeceptionTechnology = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [honeypots, setHoneypots] = useState([]);
  const [honeytokens, setHoneytokens] = useState([]);
  const [decoys, setDecoys] = useState([]);
  const [activity, setActivity] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedItem, setSelectedItem] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsTitle, setDetailsTitle] = useState('');
  const [detailsFields, setDetailsFields] = useState([]);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [hpRes, htRes, decoyRes, actRes, metricsRes] = await Promise.all([
        deceptionAPI.getHoneypots(),
        deceptionAPI.getHoneytokens(),
        deceptionAPI.getDecoys(),
        deceptionAPI.getActivity(),
        deceptionAPI.getMetrics()
      ]);
      
      setHoneypots(Array.isArray(hpRes.data.data) ? hpRes.data.data : []);
      setHoneytokens(Array.isArray(htRes.data.data) ? htRes.data.data : []);
      setDecoys(Array.isArray(decoyRes.data.data) ? decoyRes.data.data : []);
      setActivity(Array.isArray(actRes.data.data) ? actRes.data.data : []);
      setMetrics(metricsRes.data.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load deception data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleViewHoneypot = (hp) => {
    setSelectedItem(hp);
    setDetailsTitle(`Honeypot: ${hp.name}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Name', key: 'name' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Status', key: 'status', type: 'status' },
      { label: 'IP Address', key: 'ip_address' },
      { label: 'Port', key: 'port' },
      { label: 'Location', key: 'location' },
      { label: 'Deployed At', key: 'deployed_at', type: 'date' },
      { label: 'Last Activity', key: 'last_activity', type: 'date' },
      { label: 'Interactions', key: 'interactions' },
      { label: 'Alerts', key: 'alerts' }
    ]);
    setDetailsOpen(true);
  };

  const handleViewHoneytoken = (token) => {
    setSelectedItem(token);
    setDetailsTitle(`Honeytoken: ${token.name}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Name', key: 'name' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Status', key: 'status', type: 'status' },
      { label: 'Value', key: 'value' },
      { label: 'Location', key: 'location', fullWidth: true },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Triggered At', key: 'triggered_at', type: 'date' },
      { label: 'Metadata', key: 'metadata', type: 'json', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  const handleViewDecoy = (decoy) => {
    setSelectedItem(decoy);
    setDetailsTitle(`Decoy System: ${decoy.name}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Name', key: 'name' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'OS', key: 'os' },
      { label: 'Services', key: 'services', type: 'array' },
      { label: 'Status', key: 'status', type: 'status' },
      { label: 'IP Address', key: 'ip_address' },
      { label: 'Hostname', key: 'hostname' },
      { label: 'Deployed At', key: 'deployed_at', type: 'date' },
      { label: 'Interactions', key: 'interactions' }
    ]);
    setDetailsOpen(true);
  };

  const handleViewActivity = (act) => {
    setSelectedItem(act);
    setDetailsTitle(`Attacker Activity: ${act.id}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Source IP', key: 'source_ip' },
      { label: 'Target ID', key: 'target_id' },
      { label: 'Target Type', key: 'target_type', type: 'badge' },
      { label: 'Activity Type', key: 'activity_type', type: 'badge' },
      { label: 'Timestamp', key: 'timestamp', type: 'date' },
      { label: 'Details', key: 'details', fullWidth: true },
      { label: 'Severity', key: 'severity', type: 'status' },
      { label: 'Alert Generated', key: 'alert_generated', type: 'status' }
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
      <Typography variant="h4" gutterBottom>
        🍯 Deception Technology
      </Typography>

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
                  <Typography color="textSecondary" gutterBottom>Active Honeypots</Typography>
                  <Typography variant="h4">{metrics.active_honeypots || 0}</Typography>
                </Box>
                <SecurityIcon sx={{ fontSize: 48, color: 'primary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Triggered Tokens</Typography>
                  <Typography variant="h4">{metrics.triggered_tokens || 0}</Typography>
                </Box>
                <TokenIcon sx={{ fontSize: 48, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Total Decoys</Typography>
                  <Typography variant="h4">{metrics.total_decoys || 0}</Typography>
                </Box>
                <ComputerIcon sx={{ fontSize: 48, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Alerts Generated</Typography>
                  <Typography variant="h4">{metrics.alerts_generated || 0}</Typography>
                </Box>
                <WarningIcon sx={{ fontSize: 48, color: 'error.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 2 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label="Honeypots" />
          <Tab label="Honeytokens" />
          <Tab label="Decoy Systems" />
          <Tab label="Attacker Activity" />
        </Tabs>
      </Paper>

      {/* Honeypots Tab */}
      {activeTab === 0 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Honeypots</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>IP Address</TableCell>
                    <TableCell>Interactions</TableCell>
                    <TableCell>Alerts</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {honeypots.map((hp) => (
                    <TableRow key={hp.id} hover>
                      <TableCell><strong>{hp.name}</strong></TableCell>
                      <TableCell><Chip label={hp.type} size="small" /></TableCell>
                      <TableCell>
                        <Chip label={hp.status} color={hp.status === 'active' ? 'success' : 'error'} size="small" />
                      </TableCell>
                      <TableCell>{hp.ip_address}</TableCell>
                      <TableCell>{hp.interactions}</TableCell>
                      <TableCell>{hp.alerts}</TableCell>
                      <TableCell>
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewHoneypot(hp)}>
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
      )}

      {/* Honeytokens Tab */}
      {activeTab === 1 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Honeytokens</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Location</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {honeytokens.map((token) => (
                    <TableRow key={token.id} hover>
                      <TableCell><strong>{token.name}</strong></TableCell>
                      <TableCell><Chip label={token.type} size="small" /></TableCell>
                      <TableCell>
                        <Chip 
                          label={token.status} 
                          color={token.status === 'triggered' ? 'error' : 'success'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell>{token.location}</TableCell>
                      <TableCell>{new Date(token.created_at).toLocaleDateString()}</TableCell>
                      <TableCell>
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewHoneytoken(token)}>
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
      )}

      {/* Decoys Tab */}
      {activeTab === 2 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Decoy Systems</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>OS</TableCell>
                    <TableCell>IP Address</TableCell>
                    <TableCell>Interactions</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {decoys.map((decoy) => (
                    <TableRow key={decoy.id} hover>
                      <TableCell><strong>{decoy.name}</strong></TableCell>
                      <TableCell><Chip label={decoy.type} size="small" /></TableCell>
                      <TableCell>{decoy.os}</TableCell>
                      <TableCell>{decoy.ip_address}</TableCell>
                      <TableCell>{decoy.interactions}</TableCell>
                      <TableCell>
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewDecoy(decoy)}>
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
      )}

      {/* Activity Tab */}
      {activeTab === 3 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Attacker Activity</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Source IP</TableCell>
                    <TableCell>Target</TableCell>
                    <TableCell>Activity Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {activity.map((act) => (
                    <TableRow key={act.id} hover>
                      <TableCell><strong>{act.source_ip}</strong></TableCell>
                      <TableCell>{act.target_type}</TableCell>
                      <TableCell><Chip label={act.activity_type} size="small" /></TableCell>
                      <TableCell>
                        <Chip 
                          label={act.severity} 
                          color={act.severity === 'high' ? 'error' : 'warning'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell>{new Date(act.timestamp).toLocaleString()}</TableCell>
                      <TableCell>
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewActivity(act)}>
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
      )}

      {/* Details Dialog */}
      <DetailsDialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        title={detailsTitle}
        data={selectedItem}
        fields={detailsFields}
      />
    </Box>
  );
};

export default DeceptionTechnology;
