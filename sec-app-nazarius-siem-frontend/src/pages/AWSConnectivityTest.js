import React, { useState, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  CircularProgress,
  Alert,
  AlertTitle,
  Chip,
  Card,
  CardContent,
  CardHeader,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Collapse,
  IconButton,
  Grid,
  Tooltip,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Refresh as RefreshIcon,
  Cloud as CloudIcon,
  Storage as StorageIcon,
  Security as SecurityIcon,
  VpnKey as KeyIcon,
} from '@mui/icons-material';
import api from '../services/api';

const AWSConnectivityTest = () => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [expandedTests, setExpandedTests] = useState({});

  const runTest = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.get('/system/aws-test');
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to run AWS connectivity test');
    } finally {
      setLoading(false);
    }
  }, []);

  const toggleExpand = (service) => {
    setExpandedTests(prev => ({
      ...prev,
      [service]: !prev[service]
    }));
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'connected':
        return <CheckIcon sx={{ color: '#4caf50' }} />;
      case 'error':
        return <ErrorIcon sx={{ color: '#f44336' }} />;
      case 'not_configured':
        return <WarningIcon sx={{ color: '#ff9800' }} />;
      default:
        return <InfoIcon sx={{ color: '#2196f3' }} />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'connected':
        return 'success';
      case 'error':
        return 'error';
      case 'not_configured':
        return 'warning';
      default:
        return 'info';
    }
  };

  const getServiceIcon = (service) => {
    if (service.includes('S3')) return <StorageIcon />;
    if (service.includes('Security')) return <SecurityIcon />;
    if (service.includes('Guard')) return <SecurityIcon />;
    if (service.includes('STS')) return <KeyIcon />;
    return <CloudIcon />;
  };

  const getOverallStatusColor = (status) => {
    switch (status) {
      case 'all_connected':
        return '#4caf50';
      case 'partial_connected':
        return '#ff9800';
      case 'partial_error':
        return '#f44336';
      default:
        return '#9e9e9e';
    }
  };

  const getOverallStatusText = (status) => {
    switch (status) {
      case 'all_connected':
        return 'All Services Connected';
      case 'partial_connected':
        return 'Partial Connection';
      case 'partial_error':
        return 'Connection Errors';
      default:
        return 'Unknown Status';
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Paper sx={{ p: 3, mb: 3, background: 'linear-gradient(135deg, #1a237e 0%, #0d47a1 100%)' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography variant="h4" sx={{ color: '#fff', fontWeight: 600 }}>
              🔍 AWS Connectivity Test
            </Typography>
            <Typography variant="body1" sx={{ color: 'rgba(255,255,255,0.7)', mt: 1 }}>
              Test connectivity and data access for AWS services
            </Typography>
          </Box>
          <Button
            variant="contained"
            size="large"
            startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <PlayIcon />}
            onClick={runTest}
            disabled={loading}
            sx={{
              bgcolor: '#fff',
              color: '#1a237e',
              '&:hover': { bgcolor: '#e3f2fd' },
              px: 4,
              py: 1.5,
            }}
          >
            {loading ? 'Testing...' : 'Run Test'}
          </Button>
        </Box>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          <AlertTitle>Error</AlertTitle>
          {error}
        </Alert>
      )}

      {result && (
        <>
          {/* Overall Status */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="overline" color="textSecondary">Overall Status</Typography>
                  <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', mt: 1 }}>
                    <Box
                      sx={{
                        width: 16,
                        height: 16,
                        borderRadius: '50%',
                        bgcolor: getOverallStatusColor(result.overall_status),
                        mr: 1,
                        animation: result.overall_status === 'all_connected' ? 'pulse 2s infinite' : 'none',
                        '@keyframes pulse': {
                          '0%': { boxShadow: `0 0 0 0 ${getOverallStatusColor(result.overall_status)}80` },
                          '70%': { boxShadow: '0 0 0 10px transparent' },
                          '100%': { boxShadow: '0 0 0 0 transparent' },
                        },
                      }}
                    />
                    <Typography variant="h6" sx={{ color: getOverallStatusColor(result.overall_status) }}>
                      {getOverallStatusText(result.overall_status)}
                    </Typography>
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={4}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="overline" color="textSecondary">AWS Account</Typography>
                  <Typography variant="h6">{result.aws_account_id || 'N/A'}</Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={4}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="overline" color="textSecondary">Credential Source</Typography>
                  <Chip
                    label={result.credential_source || 'Unknown'}
                    color="primary"
                    size="small"
                  />
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* Environment Variables */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              📋 Environment Configuration
            </Typography>
            <Grid container spacing={2}>
              {result.environment && Object.entries(result.environment).map(([key, value]) => (
                <Grid item xs={12} sm={6} md={4} key={key}>
                  <Box sx={{ p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
                    <Typography variant="caption" color="textSecondary">{key}</Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {value === 'true' ? (
                        <Chip label="ENABLED" size="small" color="success" />
                      ) : value === 'false' ? (
                        <Chip label="DISABLED" size="small" color="default" />
                      ) : value === 'not set' ? (
                        <Chip label="NOT SET" size="small" color="warning" />
                      ) : (
                        value
                      )}
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Test Results */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              🧪 Test Results
            </Typography>
            {result.tests && result.tests.map((test, index) => (
              <Card key={index} sx={{ mb: 2 }}>
                <CardHeader
                  avatar={getServiceIcon(test.service)}
                  action={
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <Chip
                        label={test.status.replace('_', ' ').toUpperCase()}
                        color={getStatusColor(test.status)}
                        size="small"
                        sx={{ mr: 1 }}
                      />
                      <Typography variant="caption" color="textSecondary" sx={{ mr: 1 }}>
                        {test.latency}
                      </Typography>
                      <IconButton
                        onClick={() => toggleExpand(test.service)}
                        size="small"
                      >
                        {expandedTests[test.service] ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                      </IconButton>
                    </Box>
                  }
                  title={test.service}
                  subheader={test.message}
                  sx={{
                    '& .MuiCardHeader-avatar': {
                      color: getStatusColor(test.status) === 'success' ? '#4caf50' :
                             getStatusColor(test.status) === 'error' ? '#f44336' : '#ff9800'
                    }
                  }}
                />
                <Collapse in={expandedTests[test.service]}>
                  <CardContent>
                    {test.details && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom>Details:</Typography>
                        <Box sx={{ bgcolor: 'background.default', p: 2, borderRadius: 1 }}>
                          <pre style={{ margin: 0, fontSize: '0.85rem', overflow: 'auto' }}>
                            {JSON.stringify(test.details, null, 2)}
                          </pre>
                        </Box>
                      </Box>
                    )}
                    {test.sample_data && (
                      <Box>
                        <Typography variant="subtitle2" gutterBottom>Sample Data:</Typography>
                        <Box sx={{ bgcolor: '#1a1a2e', p: 2, borderRadius: 1 }}>
                          <pre style={{ margin: 0, fontSize: '0.85rem', overflow: 'auto', color: '#4caf50' }}>
                            {JSON.stringify(test.sample_data, null, 2)}
                          </pre>
                        </Box>
                      </Box>
                    )}
                  </CardContent>
                </Collapse>
              </Card>
            ))}
          </Paper>

          {/* Recommendations */}
          {result.recommendations && result.recommendations.length > 0 && (
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                💡 Recommendations
              </Typography>
              <List>
                {result.recommendations.map((rec, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <InfoIcon color="info" />
                    </ListItemIcon>
                    <ListItemText primary={rec} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}
        </>
      )}

      {!result && !loading && (
        <Paper sx={{ p: 5, textAlign: 'center' }}>
          <CloudIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" color="textSecondary" gutterBottom>
            Click "Run Test" to check AWS connectivity
          </Typography>
          <Typography variant="body2" color="textSecondary">
            This will test connections to S3, GuardDuty, Security Hub, and verify credentials.
          </Typography>
        </Paper>
      )}
    </Box>
  );
};

export default AWSConnectivityTest;

