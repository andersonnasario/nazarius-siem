import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Switch,
  FormControlLabel,
  Button,
  Alert,
  Divider,
  IconButton,
  Tooltip,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Shield as ShieldIcon,
  Lock as LockIcon,
  VpnKey as VpnKeyIcon,
  Person as PersonIcon,
  Assessment as AssessmentIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
} from '@mui/icons-material';

const SecuritySettings = () => {
  // State
  const [loading, setLoading] = useState(false);
  const [securityStatus, setSecurityStatus] = useState({
    rateLimiting: { enabled: true, status: 'active', requests: 100, burst: 200 },
    bruteForceProtection: { enabled: true, status: 'active', maxAttempts: 5, blockDuration: 30 },
    securityHeaders: { enabled: true, status: 'active', headers: 7 },
    inputValidation: { enabled: true, status: 'active', maxBodySize: 10 },
    auditLogging: { enabled: true, status: 'active', retention: 90 },
    apiKeyManagement: { enabled: true, status: 'active', activeKeys: 3 },
    passwordPolicy: { enabled: true, status: 'active', minLength: 8 },
    corsProtection: { enabled: true, status: 'active', allowedOrigins: 1 },
  });

  const [recentEvents, setRecentEvents] = useState([
    { id: 1, type: 'rate_limit', severity: 'medium', ip: '192.168.1.100', timestamp: '2025-11-07T14:30:00Z', message: 'Rate limit exceeded' },
    { id: 2, type: 'brute_force', severity: 'high', ip: '10.0.0.50', timestamp: '2025-11-07T14:25:00Z', message: 'Brute force attempt detected' },
    { id: 3, type: 'xss_attempt', severity: 'high', ip: '172.16.0.10', timestamp: '2025-11-07T14:20:00Z', message: 'XSS injection blocked' },
    { id: 4, type: 'sql_injection', severity: 'critical', ip: '203.0.113.5', timestamp: '2025-11-07T14:15:00Z', message: 'SQL injection attempt blocked' },
    { id: 5, type: 'unauthorized', severity: 'medium', ip: '198.51.100.20', timestamp: '2025-11-07T14:10:00Z', message: 'Unauthorized access attempt' },
  ]);

  const [blockedIPs, setBlockedIPs] = useState([
    { ip: '10.0.0.50', reason: 'Brute force attack', blockedAt: '2025-11-07T14:25:00Z', expiresAt: '2025-11-07T14:55:00Z' },
    { ip: '203.0.113.5', reason: 'SQL injection attempts', blockedAt: '2025-11-07T14:15:00Z', expiresAt: '2025-11-07T14:45:00Z' },
  ]);

  const [apiKeys, setApiKeys] = useState([
    { id: 1, name: 'Production API', key: 'sk_prod_...abc123', created: '2025-10-01', lastUsed: '2025-11-07T14:00:00Z', status: 'active' },
    { id: 2, name: 'Staging API', key: 'sk_test_...def456', created: '2025-10-15', lastUsed: '2025-11-06T10:00:00Z', status: 'active' },
    { id: 3, name: 'Development API', key: 'sk_dev_...ghi789', created: '2025-11-01', lastUsed: '2025-11-07T12:00:00Z', status: 'active' },
  ]);

  const [showAddKeyDialog, setShowAddKeyDialog] = useState(false);
  const [showKeyDialog, setShowKeyDialog] = useState(false);
  const [selectedKey, setSelectedKey] = useState(null);
  const [newKeyName, setNewKeyName] = useState('');

  // Mock data loading
  useEffect(() => {
    // In production, fetch from API
  }, []);

  const getSeverityColor = (severity) => {
    const colors = {
      low: 'success',
      medium: 'warning',
      high: 'error',
      critical: 'error',
    };
    return colors[severity] || 'default';
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'low':
        return <CheckCircleIcon />;
      case 'medium':
        return <WarningIcon />;
      case 'high':
      case 'critical':
        return <ErrorIcon />;
      default:
        return <CheckCircleIcon />;
    }
  };

  const handleToggleFeature = (feature) => {
    setSecurityStatus((prev) => ({
      ...prev,
      [feature]: {
        ...prev[feature],
        enabled: !prev[feature].enabled,
      },
    }));
  };

  const handleUnblockIP = (ip) => {
    setBlockedIPs((prev) => prev.filter((item) => item.ip !== ip));
  };

  const handleGenerateKey = () => {
    const newKey = {
      id: apiKeys.length + 1,
      name: newKeyName,
      key: `sk_prod_${Math.random().toString(36).substring(2, 15)}`,
      created: new Date().toISOString().split('T')[0],
      lastUsed: null,
      status: 'active',
    };
    setApiKeys((prev) => [...prev, newKey]);
    setSelectedKey(newKey);
    setShowAddKeyDialog(false);
    setShowKeyDialog(true);
    setNewKeyName('');
  };

  const handleDeleteKey = (id) => {
    setApiKeys((prev) => prev.filter((key) => key.id !== id));
  };

  // Security score calculation
  const calculateSecurityScore = () => {
    const features = Object.values(securityStatus);
    const enabled = features.filter((f) => f.enabled).length;
    return Math.round((enabled / features.length) * 100);
  };

  const securityScore = calculateSecurityScore();

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <SecurityIcon sx={{ fontSize: 40, mr: 2 }} />
        <Box>
          <Typography variant="h4" gutterBottom>
            Configurações de Segurança
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Gerencie as configurações de segurança e proteção da plataforma
          </Typography>
        </Box>
      </Box>

      {/* Security Score */}
      <Paper sx={{ p: 3, mb: 3, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
        <Grid container alignItems="center" spacing={2}>
          <Grid item xs={12} md={8}>
            <Typography variant="h6" sx={{ color: 'white', mb: 1 }}>
              Security Score
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <Typography variant="h2" sx={{ color: 'white', mr: 2 }}>
                {securityScore}%
              </Typography>
              <Chip
                label={securityScore >= 90 ? 'Excellent' : securityScore >= 70 ? 'Good' : 'Needs Improvement'}
                color={securityScore >= 90 ? 'success' : securityScore >= 70 ? 'warning' : 'error'}
                sx={{ fontWeight: 'bold' }}
              />
            </Box>
            <LinearProgress
              variant="determinate"
              value={securityScore}
              sx={{
                height: 10,
                borderRadius: 5,
                backgroundColor: 'rgba(255,255,255,0.3)',
                '& .MuiLinearProgress-bar': {
                  backgroundColor: 'white',
                },
              }}
            />
          </Grid>
          <Grid item xs={12} md={4} sx={{ textAlign: 'center' }}>
            <ShieldIcon sx={{ fontSize: 80, color: 'white', opacity: 0.8 }} />
          </Grid>
        </Grid>
      </Paper>

      {/* Security Features Status */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {Object.entries(securityStatus).map(([key, value]) => (
          <Grid item xs={12} sm={6} md={3} key={key}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Chip
                    size="small"
                    label={value.status}
                    color={value.enabled ? 'success' : 'default'}
                  />
                  <Switch
                    checked={value.enabled}
                    onChange={() => handleToggleFeature(key)}
                    size="small"
                  />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ textTransform: 'capitalize', mb: 1 }}>
                  {key.replace(/([A-Z])/g, ' $1').trim()}
                </Typography>
                <Typography variant="h6">
                  {key === 'rateLimiting' && `${value.requests} req/s`}
                  {key === 'bruteForceProtection' && `${value.maxAttempts} attempts`}
                  {key === 'securityHeaders' && `${value.headers} headers`}
                  {key === 'inputValidation' && `${value.maxBodySize}MB max`}
                  {key === 'auditLogging' && `${value.retention} days`}
                  {key === 'apiKeyManagement' && `${value.activeKeys} keys`}
                  {key === 'passwordPolicy' && `${value.minLength} chars min`}
                  {key === 'corsProtection' && `${value.allowedOrigins} origins`}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Recent Security Events */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">
            <AssessmentIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
            Recent Security Events
          </Typography>
          <Button startIcon={<RefreshIcon />} size="small">
            Refresh
          </Button>
        </Box>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Severity</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>IP Address</TableCell>
                <TableCell>Message</TableCell>
                <TableCell>Timestamp</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {recentEvents.map((event) => (
                <TableRow key={event.id}>
                  <TableCell>
                    <Chip
                      icon={getSeverityIcon(event.severity)}
                      label={event.severity}
                      color={getSeverityColor(event.severity)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>{event.type.replace('_', ' ').toUpperCase()}</TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {event.ip}
                    </Typography>
                  </TableCell>
                  <TableCell>{event.message}</TableCell>
                  <TableCell>{new Date(event.timestamp).toLocaleString()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Blocked IPs */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          <LockIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
          Blocked IP Addresses
        </Typography>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>IP Address</TableCell>
                <TableCell>Reason</TableCell>
                <TableCell>Blocked At</TableCell>
                <TableCell>Expires At</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {blockedIPs.map((item) => (
                <TableRow key={item.ip}>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {item.ip}
                    </Typography>
                  </TableCell>
                  <TableCell>{item.reason}</TableCell>
                  <TableCell>{new Date(item.blockedAt).toLocaleString()}</TableCell>
                  <TableCell>{new Date(item.expiresAt).toLocaleString()}</TableCell>
                  <TableCell align="right">
                    <Button
                      size="small"
                      color="primary"
                      onClick={() => handleUnblockIP(item.ip)}
                    >
                      Unblock
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        {blockedIPs.length === 0 && (
          <Alert severity="success" sx={{ mt: 2 }}>
            No IP addresses are currently blocked
          </Alert>
        )}
      </Paper>

      {/* API Keys Management */}
      <Paper sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">
            <VpnKeyIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
            API Keys
          </Typography>
          <Button
            startIcon={<AddIcon />}
            variant="contained"
            onClick={() => setShowAddKeyDialog(true)}
          >
            Generate New Key
          </Button>
        </Box>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Key</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Last Used</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {apiKeys.map((key) => (
                <TableRow key={key.id}>
                  <TableCell>{key.name}</TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {key.key}
                    </Typography>
                  </TableCell>
                  <TableCell>{key.created}</TableCell>
                  <TableCell>
                    {key.lastUsed ? new Date(key.lastUsed).toLocaleString() : 'Never'}
                  </TableCell>
                  <TableCell>
                    <Chip label={key.status} color="success" size="small" />
                  </TableCell>
                  <TableCell align="right">
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => handleDeleteKey(key.id)}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Add Key Dialog */}
      <Dialog open={showAddKeyDialog} onClose={() => setShowAddKeyDialog(false)}>
        <DialogTitle>Generate New API Key</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Key Name"
            fullWidth
            value={newKeyName}
            onChange={(e) => setNewKeyName(e.target.value)}
            placeholder="e.g., Production API"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowAddKeyDialog(false)}>Cancel</Button>
          <Button
            onClick={handleGenerateKey}
            variant="contained"
            disabled={!newKeyName}
          >
            Generate
          </Button>
        </DialogActions>
      </Dialog>

      {/* Show Key Dialog */}
      <Dialog open={showKeyDialog} onClose={() => setShowKeyDialog(false)}>
        <DialogTitle>API Key Generated</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Save this key now. You won't be able to see it again!
          </Alert>
          <TextField
            fullWidth
            value={selectedKey?.key || ''}
            InputProps={{
              readOnly: true,
              sx: { fontFamily: 'monospace' },
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowKeyDialog(false)} variant="contained">
            I've Saved It
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default SecuritySettings;

