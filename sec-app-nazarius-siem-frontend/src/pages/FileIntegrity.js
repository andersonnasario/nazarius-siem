import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  LinearProgress,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  TextField,
  Alert,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  FolderOpen as FolderOpenIcon,
  Description as DescriptionIcon,
  Check as CheckIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { LineChart, Line, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

import { fimAPI } from '../services/api';

function TabPanel({ children, value, index }) {
  return (
    <div hidden={value !== index}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

export default function FileIntegrity() {
  const [loading, setLoading] = useState(true);
  const [tabValue, setTabValue] = useState(0);
  const [dashboard, setDashboard] = useState(null);
  const [files, setFiles] = useState([]);
  const [changes, setChanges] = useState([]);
  const [baselines, setBaselines] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedChange, setSelectedChange] = useState(null);
  const [fileDialogOpen, setFileDialogOpen] = useState(false);
  const [changeDialogOpen, setChangeDialogOpen] = useState(false);
  const [acknowledgeDialogOpen, setAcknowledgeDialogOpen] = useState(false);
  const [acknowledgeNotes, setAcknowledgeNotes] = useState('');

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    setLoading(true);
    try {
      const data = await fimAPI.getDashboard();
      setDashboard(data);
      
      const filesData = await fimAPI.getFiles();
      setFiles(filesData.files || []);
      
      const changesData = await fimAPI.getChanges();
      setChanges(changesData.changes || []);
      
      const baselinesData = await fimAPI.getBaselines();
      setBaselines(baselinesData.baselines || []);
      
      const alertsData = await fimAPI.getAlerts();
      setAlerts(alertsData.alerts || []);
      
    } catch (error) {
      console.error('Error loading FIM dashboard:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFileClick = (file) => {
    setSelectedFile(file);
    setFileDialogOpen(true);
  };

  const handleChangeClick = (change) => {
    setSelectedChange(change);
    setChangeDialogOpen(true);
  };

  const handleAcknowledgeClick = (change) => {
    setSelectedChange(change);
    setAcknowledgeDialogOpen(true);
  };

  const handleAcknowledgeSubmit = async () => {
    try {
      await fimAPI.acknowledgeChange(selectedChange.id, acknowledgeNotes);
      setAcknowledgeDialogOpen(false);
      setAcknowledgeNotes('');
      loadDashboard();
    } catch (error) {
      console.error('Error acknowledging change:', error);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getStatusIcon = (status) => {
    switch (status?.toLowerCase()) {
      case 'ok': return <CheckCircleIcon color="success" />;
      case 'changed': return <WarningIcon color="warning" />;
      case 'missing': return <ErrorIcon color="error" />;
      default: return <InfoIcon />;
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const formatBytes = (bytes) => {
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return bytes + ' B';
  };

  const COLORS = ['#d32f2f', '#f57c00', '#1976d2', '#388e3c'];

  if (loading || !dashboard) {
    return (
      <Container maxWidth="xl">
        <Box sx={{ mt: 4 }}>
          <LinearProgress />
          <Typography sx={{ mt: 2, textAlign: 'center' }}>
            Carregando File Integrity Monitoring...
          </Typography>
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl">
      <Box sx={{ mt: 4, mb: 4 }}>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 600 }}>
            🔒 File Integrity Monitoring
          </Typography>
          <IconButton onClick={loadDashboard} color="primary">
            <RefreshIcon />
          </IconButton>
        </Box>

        {/* KPI Cards */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total Files Monitored
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 600 }}>
                  {dashboard.total_files?.toLocaleString()}
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                  <CheckCircleIcon color="success" fontSize="small" />
                  <Typography variant="body2" color="success.main" sx={{ ml: 0.5 }}>
                    {dashboard.files_ok} OK
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card sx={{ bgcolor: dashboard.files_changed > 0 ? '#fff3e0' : 'background.paper' }}>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Files Changed
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 600, color: dashboard.files_changed > 0 ? '#f57c00' : 'text.primary' }}>
                  {dashboard.files_changed}
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                  <WarningIcon color="warning" fontSize="small" />
                  <Typography variant="body2" color="warning.main" sx={{ ml: 0.5 }}>
                    Requires review
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Changes (24h)
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 600 }}>
                  {dashboard.changes_last_24h}
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                  <InfoIcon color="info" fontSize="small" />
                  <Typography variant="body2" color="info.main" sx={{ ml: 0.5 }}>
                    Last 24 hours
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Compliance Score
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 600, color: dashboard.compliance_score >= 90 ? '#388e3c' : '#f57c00' }}>
                  {dashboard.compliance_score?.toFixed(1)}%
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={dashboard.compliance_score} 
                  sx={{ mt: 1, height: 8, borderRadius: 4 }}
                  color={dashboard.compliance_score >= 90 ? 'success' : 'warning'}
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Tabs */}
        <Paper sx={{ mb: 3 }}>
          <Tabs value={tabValue} onChange={(e, newValue) => setTabValue(newValue)}>
            <Tab label="Overview" />
            <Tab label="Monitored Files" />
            <Tab label="Changes" />
            <Tab label="Baselines" />
            <Tab label="Alerts" />
          </Tabs>
        </Paper>

        {/* Tab 1: Overview */}
        <TabPanel value={tabValue} index={0}>
          <Grid container spacing={3}>
            {/* Changes Trend */}
            <Grid item xs={12} md={8}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Changes Trend (24h)
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={dashboard.changes_trend || []}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(value) => new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    />
                    <YAxis />
                    <Tooltip labelFormatter={(value) => new Date(value).toLocaleString()} />
                    <Legend />
                    <Line type="monotone" dataKey="file_modified" stroke="#1976d2" name="Modified" />
                    <Line type="monotone" dataKey="file_deleted" stroke="#d32f2f" name="Deleted" />
                    <Line type="monotone" dataKey="file_created" stroke="#388e3c" name="Created" />
                  </LineChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* Alerts by Severity */}
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Alerts by Severity
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={Object.entries(dashboard.alerts_by_severity || {}).map(([name, value]) => ({ name, value }))}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      label={(entry) => `${entry.name}: ${entry.value}`}
                    >
                      {Object.keys(dashboard.alerts_by_severity || {}).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* File Status Distribution */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  File Status Distribution
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <CheckCircleIcon sx={{ fontSize: 48, color: '#388e3c' }} />
                      <Typography variant="h5">{dashboard.files_ok}</Typography>
                      <Typography color="textSecondary">OK</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <WarningIcon sx={{ fontSize: 48, color: '#f57c00' }} />
                      <Typography variant="h5">{dashboard.files_changed}</Typography>
                      <Typography color="textSecondary">Changed</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <ErrorIcon sx={{ fontSize: 48, color: '#d32f2f' }} />
                      <Typography variant="h5">{dashboard.files_missing}</Typography>
                      <Typography color="textSecondary">Missing</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <FolderOpenIcon sx={{ fontSize: 48, color: '#1976d2' }} />
                      <Typography variant="h5">{dashboard.total_files}</Typography>
                      <Typography color="textSecondary">Total</Typography>
                    </Box>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 2: Monitored Files */}
        <TabPanel value={tabValue} index={1}>
          <Paper sx={{ p: 3 }}>
            <Box sx={{ mb: 2, display: 'flex', gap: 2 }}>
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Status</InputLabel>
                <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                  <MenuItem value="all">All Status</MenuItem>
                  <MenuItem value="ok">OK</MenuItem>
                  <MenuItem value="changed">Changed</MenuItem>
                  <MenuItem value="missing">Missing</MenuItem>
                </Select>
              </FormControl>
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Severity</InputLabel>
                <Select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                  <MenuItem value="all">All Severities</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                </Select>
              </FormControl>
            </Box>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Status</TableCell>
                    <TableCell>File Path</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell align="right">Size</TableCell>
                    <TableCell>Permissions</TableCell>
                    <TableCell>Owner</TableCell>
                    <TableCell align="right">Changes</TableCell>
                    <TableCell>Last Modified</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {files
                    .filter(f => statusFilter === 'all' || f.status === statusFilter)
                    .filter(f => severityFilter === 'all' || f.severity === severityFilter)
                    .map((file) => (
                      <TableRow 
                        key={file.id}
                        sx={{ bgcolor: file.status === 'changed' ? '#fff3e0' : file.status === 'missing' ? '#ffebee' : 'inherit' }}
                      >
                        <TableCell>{getStatusIcon(file.status)}</TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <DescriptionIcon sx={{ mr: 1 }} fontSize="small" />
                            {file.path}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip label={file.severity} size="small" color={getSeverityColor(file.severity)} />
                        </TableCell>
                        <TableCell align="right">{formatBytes(file.size)}</TableCell>
                        <TableCell>{file.permissions}</TableCell>
                        <TableCell>{file.owner}</TableCell>
                        <TableCell align="right">
                          <Chip label={file.change_count} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>{formatTimestamp(file.last_modified)}</TableCell>
                        <TableCell align="center">
                          <IconButton size="small" onClick={() => handleFileClick(file)}>
                            <InfoIcon />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </TabPanel>

        {/* Tab 3: Changes */}
        <TabPanel value={tabValue} index={2}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              File Changes
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>File Path</TableCell>
                    <TableCell>Change Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Detected At</TableCell>
                    <TableCell>Alert</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {changes.map((change) => (
                    <TableRow key={change.id}>
                      <TableCell>{change.file_path}</TableCell>
                      <TableCell>
                        <Chip label={change.change_type} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Chip label={change.severity} size="small" color={getSeverityColor(change.severity)} />
                      </TableCell>
                      <TableCell>{formatTimestamp(change.detected_at)}</TableCell>
                      <TableCell>
                        {change.alert_generated && <Chip label="Alert" size="small" color="warning" />}
                      </TableCell>
                      <TableCell>
                        {change.acknowledged ? (
                          <Chip label="Acknowledged" size="small" color="success" icon={<CheckIcon />} />
                        ) : (
                          <Chip label="Pending" size="small" color="warning" />
                        )}
                      </TableCell>
                      <TableCell align="center">
                        <IconButton size="small" onClick={() => handleChangeClick(change)}>
                          <InfoIcon />
                        </IconButton>
                        {!change.acknowledged && (
                          <IconButton size="small" color="success" onClick={() => handleAcknowledgeClick(change)}>
                            <CheckIcon />
                          </IconButton>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </TabPanel>

        {/* Tab 4: Baselines */}
        <TabPanel value={tabValue} index={3}>
          <Paper sx={{ p: 3 }}>
            <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between' }}>
              <Typography variant="h6">Baselines</Typography>
              <Button variant="contained" color="primary">
                Create Baseline
              </Button>
            </Box>
            <Grid container spacing={3}>
              {baselines.map((baseline) => (
                <Grid item xs={12} md={6} lg={4} key={baseline.id}>
                  <Card>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        {baseline.name}
                      </Typography>
                      <Typography color="textSecondary" paragraph>
                        {baseline.description}
                      </Typography>
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="body2" color="textSecondary">
                          Files: <strong>{baseline.file_count}</strong>
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                          Created: {formatTimestamp(baseline.created_at)}
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                          Status: <Chip label={baseline.status} size="small" color={baseline.status === 'active' ? 'success' : 'default'} />
                        </Typography>
                      </Box>
                      <Button size="small" variant="outlined">
                        View Details
                      </Button>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </TabPanel>

        {/* Tab 5: Alerts */}
        <TabPanel value={tabValue} index={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              FIM Alerts
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Title</TableCell>
                    <TableCell>File Path</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Change Type</TableCell>
                    <TableCell>Detected At</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Assigned To</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {alerts.map((alert) => (
                    <TableRow key={alert.id}>
                      <TableCell>{alert.title}</TableCell>
                      <TableCell>{alert.file_path}</TableCell>
                      <TableCell>
                        <Chip label={alert.severity} size="small" color={getSeverityColor(alert.severity)} />
                      </TableCell>
                      <TableCell>
                        <Chip label={alert.change_type} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>{formatTimestamp(alert.detected_at)}</TableCell>
                      <TableCell>
                        <Chip 
                          label={alert.status} 
                          size="small"
                          color={alert.status === 'resolved' ? 'success' : alert.status === 'investigating' ? 'warning' : 'error'}
                        />
                      </TableCell>
                      <TableCell>{alert.assigned_to || '-'}</TableCell>
                      <TableCell align="center">
                        <IconButton size="small">
                          <InfoIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </TabPanel>

        {/* File Details Dialog */}
        <Dialog open={fileDialogOpen} onClose={() => setFileDialogOpen(false)} maxWidth="md" fullWidth>
          <DialogTitle>File Details</DialogTitle>
          <DialogContent>
            {selectedFile && (
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Alert severity={selectedFile.status === 'changed' ? 'warning' : selectedFile.status === 'missing' ? 'error' : 'success'}>
                    Status: {selectedFile.status}
                  </Alert>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">File Path</Typography>
                  <Typography variant="body1">{selectedFile.path}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Size</Typography>
                  <Typography variant="body1">{formatBytes(selectedFile.size)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Permissions</Typography>
                  <Typography variant="body1">{selectedFile.permissions}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Owner</Typography>
                  <Typography variant="body1">{selectedFile.owner}:{selectedFile.group}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Change Count</Typography>
                  <Typography variant="body1">{selectedFile.change_count}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">MD5 Hash</Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {selectedFile.md5_hash}
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">SHA256 Hash</Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {selectedFile.sha256_hash}
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">Compliance Frameworks</Typography>
                  <Box sx={{ mt: 1 }}>
                    {selectedFile.compliance_frameworks?.map((framework, index) => (
                      <Chip key={index} label={framework} size="small" sx={{ mr: 1, mb: 1 }} />
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">Tags</Typography>
                  <Box sx={{ mt: 1 }}>
                    {selectedFile.tags?.map((tag, index) => (
                      <Chip key={index} label={tag} size="small" variant="outlined" sx={{ mr: 1, mb: 1 }} />
                    ))}
                  </Box>
                </Grid>
              </Grid>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setFileDialogOpen(false)}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* Change Details Dialog */}
        <Dialog open={changeDialogOpen} onClose={() => setChangeDialogOpen(false)} maxWidth="md" fullWidth>
          <DialogTitle>Change Details</DialogTitle>
          <DialogContent>
            {selectedChange && (
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Alert severity={getSeverityColor(selectedChange.severity)}>
                    Severity: {selectedChange.severity}
                  </Alert>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">File Path</Typography>
                  <Typography variant="body1">{selectedChange.file_path}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Change Type</Typography>
                  <Chip label={selectedChange.change_type} />
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Detected At</Typography>
                  <Typography variant="body1">{formatTimestamp(selectedChange.detected_at)}</Typography>
                </Grid>
                {selectedChange.old_hash && (
                  <>
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" color="textSecondary">Old Hash</Typography>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                        {selectedChange.old_hash}
                      </Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" color="textSecondary">New Hash</Typography>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                        {selectedChange.new_hash}
                      </Typography>
                    </Grid>
                  </>
                )}
                {selectedChange.acknowledged && (
                  <Grid item xs={12}>
                    <Alert severity="success">
                      Acknowledged by {selectedChange.acknowledged_by} at {formatTimestamp(selectedChange.acknowledged_at)}
                      {selectedChange.notes && (
                        <Typography variant="body2" sx={{ mt: 1 }}>
                          Notes: {selectedChange.notes}
                        </Typography>
                      )}
                    </Alert>
                  </Grid>
                )}
              </Grid>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setChangeDialogOpen(false)}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* Acknowledge Dialog */}
        <Dialog open={acknowledgeDialogOpen} onClose={() => setAcknowledgeDialogOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>Acknowledge Change</DialogTitle>
          <DialogContent>
            <Typography variant="body2" paragraph>
              Please provide notes for acknowledging this change:
            </Typography>
            <TextField
              fullWidth
              multiline
              rows={4}
              label="Notes"
              value={acknowledgeNotes}
              onChange={(e) => setAcknowledgeNotes(e.target.value)}
              placeholder="Explain why this change is expected or authorized..."
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setAcknowledgeDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleAcknowledgeSubmit} variant="contained" color="success">
              Acknowledge
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Container>
  );
}

