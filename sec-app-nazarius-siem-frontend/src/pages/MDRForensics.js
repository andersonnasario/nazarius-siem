import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, Button, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, MenuItem, CircularProgress, Alert, IconButton, Tooltip
} from '@mui/material';
import {
  BugReport as BugReportIcon,
  Folder as FolderIcon,
  Description as DescriptionIcon,
  CheckCircle as CheckCircleIcon,
  Visibility as VisibilityIcon
} from '@mui/icons-material';
import { mdrForensicsAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const MDRForensics = () => {
  const [cases, setCases] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [openDialog, setOpenDialog] = useState(false);
  const [newCase, setNewCase] = useState({
    incident_id: '',
    title: '',
    priority: 'medium',
    analyst: ''
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
      const [casesRes, evidenceRes, statsRes] = await Promise.all([
        mdrForensicsAPI.getCases(),
        mdrForensicsAPI.getEvidence(),
        mdrForensicsAPI.getStats()
      ]);
      
      // Axios already extracts .data, so response.data is the actual API response
      // API returns: { data: [...] } so we need response.data.data
      setCases(Array.isArray(casesRes.data.data) ? casesRes.data.data : []);
      setEvidence(Array.isArray(evidenceRes.data.data) ? evidenceRes.data.data : []);
      setStats(statsRes.data.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load forensics data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCase = async () => {
    try {
      await mdrForensicsAPI.createCase(newCase);
      setOpenDialog(false);
      setNewCase({ incident_id: '', title: '', priority: 'medium', analyst: '' });
      loadData();
    } catch (err) {
      setError('Failed to create case');
      console.error(err);
    }
  };

  const getPriorityColor = (priority) => {
    const colors = {
      critical: 'error',
      high: 'warning',
      medium: 'info',
      low: 'success'
    };
    return colors[priority] || 'default';
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success',
      closed: 'default',
      archived: 'default'
    };
    return colors[status] || 'default';
  };

  // View Case Details
  const handleViewCase = (caseItem) => {
    setDetailsData(caseItem);
    setDetailsTitle(`Forensic Case: ${caseItem.title}`);
    setDetailsFields([
      { label: 'Case ID', key: 'id', type: 'text' },
      { label: 'Title', key: 'title', type: 'text', fullWidth: true },
      { label: 'Incident ID', key: 'incident_id', type: 'text' },
      { label: 'Priority', key: 'priority', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Analyst', key: 'analyst', type: 'text' },
      { label: 'Evidence Count', key: 'evidence_count', type: 'text' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Updated At', key: 'updated_at', type: 'date' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Findings', key: 'findings', type: 'text', fullWidth: true },
      { label: 'Timeline', key: 'timeline', type: 'json', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  // View Evidence Details
  const handleViewEvidence = (evidenceItem) => {
    setDetailsData(evidenceItem);
    setDetailsTitle(`Evidence: ${evidenceItem.type}`);
    setDetailsFields([
      { label: 'Evidence ID', key: 'id', type: 'text' },
      { label: 'Case ID', key: 'case_id', type: 'text' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Source', key: 'source', type: 'text', fullWidth: true },
      { label: 'Hash (SHA256)', key: 'hash', type: 'text', fullWidth: true },
      { label: 'Size (bytes)', key: 'size', type: 'text' },
      { label: 'Collected At', key: 'collected_at', type: 'date' },
      { label: 'Collected By', key: 'collected_by', type: 'text' },
      { label: 'Chain of Custody', key: 'chain_of_custody', type: 'json', fullWidth: true },
      { label: 'Metadata', key: 'metadata', type: 'json', fullWidth: true }
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
          🔬 Automated Forensics
        </Typography>
        <Button variant="contained" color="primary" onClick={() => setOpenDialog(true)}>
          Create New Case
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
                  <Typography color="textSecondary" gutterBottom>
                    Total Cases
                  </Typography>
                  <Typography variant="h4">{stats.total_cases || 0}</Typography>
                </Box>
                <FolderIcon sx={{ fontSize: 48, color: 'primary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Active Cases
                  </Typography>
                  <Typography variant="h4">{stats.active_cases || 0}</Typography>
                </Box>
                <BugReportIcon sx={{ fontSize: 48, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Total Evidence
                  </Typography>
                  <Typography variant="h4">{stats.total_evidence || 0}</Typography>
                </Box>
                <DescriptionIcon sx={{ fontSize: 48, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Closed Cases
                  </Typography>
                  <Typography variant="h4">{stats.closed_cases || 0}</Typography>
                </Box>
                <CheckCircleIcon sx={{ fontSize: 48, color: 'success.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Cases Table */}
      <Paper sx={{ mb: 3 }}>
        <Box p={2}>
          <Typography variant="h6" gutterBottom>
            Forensic Cases
          </Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>Title</TableCell>
                  <TableCell>Incident ID</TableCell>
                  <TableCell>Priority</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Evidence</TableCell>
                  <TableCell>Analyst</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {cases.map((c) => (
                  <TableRow key={c.id} hover>
                    <TableCell>{c.id}</TableCell>
                    <TableCell>{c.title}</TableCell>
                    <TableCell>{c.incident_id}</TableCell>
                    <TableCell>
                      <Chip label={c.priority} color={getPriorityColor(c.priority)} size="small" />
                    </TableCell>
                    <TableCell>
                      <Chip label={c.status} color={getStatusColor(c.status)} size="small" />
                    </TableCell>
                    <TableCell>{c.evidence_count}</TableCell>
                    <TableCell>{c.analyst}</TableCell>
                    <TableCell>{new Date(c.created_at).toLocaleDateString()}</TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Details">
                        <IconButton size="small" onClick={() => handleViewCase(c)}>
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

      {/* Evidence Table */}
      <Paper>
        <Box p={2}>
          <Typography variant="h6" gutterBottom>
            Evidence Collection
          </Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>Case ID</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Source</TableCell>
                  <TableCell>Hash</TableCell>
                  <TableCell>Size</TableCell>
                  <TableCell>Collected</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {evidence.map((ev) => (
                  <TableRow key={ev.id} hover>
                    <TableCell>{ev.id}</TableCell>
                    <TableCell>{ev.case_id}</TableCell>
                    <TableCell>
                      <Chip label={ev.type} size="small" />
                    </TableCell>
                    <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {ev.source}
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                      {ev.hash}
                    </TableCell>
                    <TableCell>{(ev.size / 1024).toFixed(2)} KB</TableCell>
                    <TableCell>{new Date(ev.collected_at).toLocaleString()}</TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Details">
                        <IconButton size="small" onClick={() => handleViewEvidence(ev)}>
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

      {/* Create Case Dialog */}
      <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Forensic Case</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Incident ID"
              fullWidth
              value={newCase.incident_id}
              onChange={(e) => setNewCase({ ...newCase, incident_id: e.target.value })}
            />
            <TextField
              label="Title"
              fullWidth
              value={newCase.title}
              onChange={(e) => setNewCase({ ...newCase, title: e.target.value })}
            />
            <TextField
              select
              label="Priority"
              fullWidth
              value={newCase.priority}
              onChange={(e) => setNewCase({ ...newCase, priority: e.target.value })}
            >
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="critical">Critical</MenuItem>
            </TextField>
            <TextField
              label="Analyst"
              fullWidth
              value={newCase.analyst}
              onChange={(e) => setNewCase({ ...newCase, analyst: e.target.value })}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>Cancel</Button>
          <Button onClick={handleCreateCase} variant="contained" color="primary">
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

export default MDRForensics;

