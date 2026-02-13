import React, { useState, useEffect } from 'react';
import {
  Box,
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
  Button,
  LinearProgress,
  Alert,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Assessment as AssessmentIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Security as SecurityIcon,
  Shield as ShieldIcon,
  Gavel as GavelIcon,
  Storage as StorageIcon,
  Lock as LockIcon,
  VpnLock as VpnLockIcon,
  BugReport as BugReportIcon,
  Speed as SpeedIcon,
  Visibility as VisibilityIcon,
} from '@mui/icons-material';
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
import { cspmAPI } from '../services/api';

const PCIDSS = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Data states
  const [dashboard, setDashboard] = useState(null);
  const [requirements, setRequirements] = useState([]);
  const [controls, setControls] = useState([]);
  const [selectedRequirement, setSelectedRequirement] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [dashboardRes, requirementsRes, controlsRes] = await Promise.all([
        cspmAPI.pciDss.getDashboard(),
        cspmAPI.pciDss.getRequirements(),
        cspmAPI.pciDss.getControls(),
      ]);
      
      setDashboard(dashboardRes.data.dashboard);
      setRequirements(requirementsRes.data.requirements || []);
      setControls(controlsRes.data.controls || []);
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao carregar dados');
      console.error('Erro ao carregar dados:', err);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'compliant': return 'success';
      case 'partial_compliant': return 'warning';
      case 'non_compliant': return 'error';
      default: return 'default';
    }
  };

  const getStatusLabel = (status) => {
    switch (status) {
      case 'compliant': return 'Compliant';
      case 'partial_compliant': return 'Partial';
      case 'non_compliant': return 'Non-Compliant';
      default: return status;
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getCategoryIcon = (category) => {
    switch (category) {
      case 'network_security': return <SecurityIcon />;
      case 'data_protection': return <LockIcon />;
      case 'access_control': return <VpnLockIcon />;
      case 'monitoring': return <VisibilityIcon />;
      case 'vulnerability_management': return <BugReportIcon />;
      case 'configuration': return <StorageIcon />;
      case 'malware_protection': return <ShieldIcon />;
      case 'physical_security': return <SecurityIcon />;
      case 'security_testing': return <SpeedIcon />;
      case 'policy': return <GavelIcon />;
      default: return <AssessmentIcon />;
    }
  };

  const COLORS = ['#4caf50', '#ff9800', '#f44336', '#2196f3', '#9c27b0'];

  // Overview Dashboard
  const renderOverview = () => {
    if (!dashboard) return null;

    const complianceData = [
      { name: 'Compliant', value: dashboard.compliant_requirements, color: '#4caf50' },
      { name: 'Partial', value: dashboard.partial_compliant_requirements, color: '#ff9800' },
      { name: 'Non-Compliant', value: dashboard.non_compliant_requirements, color: '#f44336' },
    ];

    const findingsData = [
      { name: 'Critical', value: dashboard.critical_findings, color: '#d32f2f' },
      { name: 'High', value: dashboard.high_findings, color: '#f57c00' },
      { name: 'Medium', value: dashboard.medium_findings, color: '#fbc02d' },
      { name: 'Low', value: dashboard.low_findings, color: '#388e3c' },
    ];

    const categoryData = Object.entries(dashboard.compliance_by_category || {}).map(([key, value]) => ({
      name: key.replace(/_/g, ' ').toUpperCase(),
      compliance: parseFloat(value.toFixed(1)),
    }));

    return (
      <Box>
        {/* Header Cards */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography variant="body2" color="textSecondary">
                      Overall Compliance
                    </Typography>
                    <Typography variant="h4" fontWeight="bold" color="primary">
                      {dashboard.overall_compliance.toFixed(1)}%
                    </Typography>
                  </Box>
                  <AssessmentIcon sx={{ fontSize: 40, color: 'primary.main' }} />
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={dashboard.overall_compliance}
                  sx={{ mt: 2, height: 8, borderRadius: 4 }}
                />
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography variant="body2" color="textSecondary">
                      Requirements
                    </Typography>
                    <Typography variant="h4" fontWeight="bold">
                      {dashboard.compliant_requirements}/{dashboard.total_requirements}
                    </Typography>
                    <Typography variant="caption" color="success.main">
                      Compliant
                    </Typography>
                  </Box>
                  <CheckCircleIcon sx={{ fontSize: 40, color: 'success.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography variant="body2" color="textSecondary">
                      Active Controls
                    </Typography>
                    <Typography variant="h4" fontWeight="bold">
                      {dashboard.active_controls}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      {dashboard.automated_controls} automated
                    </Typography>
                  </Box>
                  <SecurityIcon sx={{ fontSize: 40, color: 'info.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography variant="body2" color="textSecondary">
                      Total Findings
                    </Typography>
                    <Typography variant="h4" fontWeight="bold">
                      {dashboard.total_findings}
                    </Typography>
                    <Typography variant="caption" color="error.main">
                      {dashboard.critical_findings} critical
                    </Typography>
                  </Box>
                  <WarningIcon sx={{ fontSize: 40, color: 'warning.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Charts */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Compliance Trend (30 days)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={dashboard.compliance_trend}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis domain={[0, 100]} />
                  <RechartsTooltip />
                  <Legend />
                  <Line 
                    type="monotone" 
                    dataKey="compliance" 
                    stroke="#2196f3" 
                    strokeWidth={2}
                    name="Compliance %"
                  />
                </LineChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Compliance by Category
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={categoryData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                  <YAxis domain={[0, 100]} />
                  <RechartsTooltip />
                  <Legend />
                  <Bar dataKey="compliance" fill="#4caf50" name="Compliance %" />
                </BarChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Requirements Status
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={complianceData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, value }) => `${name}: ${value}`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {complianceData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Findings by Severity
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={findingsData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, value }) => `${name}: ${value}`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {findingsData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
        </Grid>

        {/* Top Issues */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Top Issues
              </Typography>
              <List>
                {dashboard.top_issues.map((issue, index) => (
                  <React.Fragment key={index}>
                    <ListItem>
                      <ListItemIcon>
                        <ErrorIcon color={issue.severity === 'critical' ? 'error' : 'warning'} />
                      </ListItemIcon>
                      <ListItemText
                        primary={issue.requirement}
                        secondary={`${issue.count} findings | Severity: ${issue.severity} | Impact: ${issue.impact}`}
                      />
                      <Chip 
                        label={issue.count} 
                        color={issue.severity === 'critical' ? 'error' : 'warning'} 
                        size="small" 
                      />
                    </ListItem>
                    {index < dashboard.top_issues.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Audit Readiness
              </Typography>
              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="textSecondary">
                  Overall Score
                </Typography>
                <Typography variant="h4" fontWeight="bold" color="primary">
                  {dashboard.audit_readiness.score.toFixed(1)}%
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={dashboard.audit_readiness.score}
                  sx={{ mt: 1, height: 8, borderRadius: 4 }}
                />
                <Chip 
                  label={dashboard.audit_readiness.status.toUpperCase()} 
                  color={dashboard.audit_readiness.status === 'ready' ? 'success' : 'warning'}
                  sx={{ mt: 1 }}
                />
              </Box>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                <Grid item xs={4}>
                  <Typography variant="body2" color="textSecondary">
                    Ready
                  </Typography>
                  <Typography variant="h6" color="success.main">
                    {dashboard.audit_readiness.ready_controls}
                  </Typography>
                </Grid>
                <Grid item xs={4}>
                  <Typography variant="body2" color="textSecondary">
                    Pending
                  </Typography>
                  <Typography variant="h6" color="warning.main">
                    {dashboard.audit_readiness.pending_controls}
                  </Typography>
                </Grid>
                <Grid item xs={4}>
                  <Typography variant="body2" color="textSecondary">
                    Failed
                  </Typography>
                  <Typography variant="h6" color="error.main">
                    {dashboard.audit_readiness.failed_controls}
                  </Typography>
                </Grid>
              </Grid>
              <Typography variant="body2" color="textSecondary" sx={{ mt: 2 }}>
                Evidence Complete: {dashboard.audit_readiness.evidence_complete.toFixed(1)}%
              </Typography>
              <LinearProgress
                variant="determinate"
                value={dashboard.audit_readiness.evidence_complete}
                sx={{ mt: 1, height: 6, borderRadius: 3 }}
              />
            </Paper>
          </Grid>
        </Grid>

        {/* Compliance Gaps */}
        {dashboard.audit_readiness.gaps.length > 0 && (
          <Paper sx={{ p: 2, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Compliance Gaps
            </Typography>
            <List>
              {dashboard.audit_readiness.gaps.map((gap, index) => (
                <React.Fragment key={index}>
                  <ListItem>
                    <ListItemIcon>
                      <WarningIcon color={gap.severity === 'critical' ? 'error' : 'warning'} />
                    </ListItemIcon>
                    <ListItemText
                      primary={`${gap.requirement} - ${gap.control}`}
                      secondary={
                        <>
                          <Typography component="span" variant="body2" color="textPrimary">
                            {gap.description}
                          </Typography>
                          <br />
                          <Typography component="span" variant="body2" color="textSecondary">
                            Remediation: {gap.remediation}
                          </Typography>
                        </>
                      }
                    />
                    <Chip 
                      label={gap.severity.toUpperCase()} 
                      color={gap.severity === 'critical' ? 'error' : 'warning'} 
                      size="small" 
                    />
                  </ListItem>
                  {index < dashboard.audit_readiness.gaps.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>
          </Paper>
        )}
      </Box>
    );
  };

  // Requirements Tab
  const renderRequirements = () => (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>#</TableCell>
            <TableCell>Requirement</TableCell>
            <TableCell>Category</TableCell>
            <TableCell>Priority</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Compliance</TableCell>
            <TableCell>Findings</TableCell>
            <TableCell>Last Audit</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {requirements.map((req) => (
            <TableRow key={req.id} hover>
              <TableCell>{req.number}</TableCell>
              <TableCell>
                <Box display="flex" alignItems="center" gap={1}>
                  {getCategoryIcon(req.category)}
                  <Box>
                    <Typography variant="body2" fontWeight="bold">
                      {req.title}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      {req.description.substring(0, 60)}...
                    </Typography>
                  </Box>
                </Box>
              </TableCell>
              <TableCell>
                <Chip 
                  label={req.category.replace(/_/g, ' ')} 
                  size="small"
                  variant="outlined"
                />
              </TableCell>
              <TableCell>
                <Chip 
                  label={req.priority.toUpperCase()} 
                  color={getPriorityColor(req.priority)}
                  size="small"
                />
              </TableCell>
              <TableCell>
                <Chip 
                  label={getStatusLabel(req.status)} 
                  color={getStatusColor(req.status)}
                  size="small"
                />
              </TableCell>
              <TableCell>
                <Box sx={{ minWidth: 100 }}>
                  <Typography variant="body2" fontWeight="bold">
                    {req.compliance.toFixed(1)}%
                  </Typography>
                  <LinearProgress
                    variant="determinate"
                    value={req.compliance}
                    sx={{ height: 6, borderRadius: 3 }}
                    color={req.compliance >= 90 ? 'success' : req.compliance >= 70 ? 'warning' : 'error'}
                  />
                </Box>
              </TableCell>
              <TableCell>
                <Box>
                  <Typography variant="body2">{req.findings} total</Typography>
                  {req.critical > 0 && (
                    <Chip label={`${req.critical} critical`} color="error" size="small" />
                  )}
                  {req.high > 0 && (
                    <Chip label={`${req.high} high`} color="warning" size="small" sx={{ ml: 0.5 }} />
                  )}
                </Box>
              </TableCell>
              <TableCell>
                <Typography variant="caption">
                  {new Date(req.last_audit).toLocaleDateString()}
                </Typography>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  // Controls Tab
  const renderControls = () => (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>Control</TableCell>
            <TableCell>Requirement</TableCell>
            <TableCell>Type</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Compliance</TableCell>
            <TableCell>AWS Services</TableCell>
            <TableCell>Automated</TableCell>
            <TableCell>Findings</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {controls.map((ctrl) => (
            <TableRow key={ctrl.id} hover>
              <TableCell>
                <Typography variant="body2" fontWeight="bold">
                  {ctrl.name}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  {ctrl.description.substring(0, 60)}...
                </Typography>
              </TableCell>
              <TableCell>
                {requirements.find(r => r.id === ctrl.requirement_id)?.number || 'N/A'}
              </TableCell>
              <TableCell>
                <Chip label={ctrl.type} size="small" variant="outlined" />
              </TableCell>
              <TableCell>
                <Chip 
                  label={ctrl.status} 
                  color={ctrl.status === 'active' ? 'success' : 'default'}
                  size="small"
                />
              </TableCell>
              <TableCell>
                <Box sx={{ minWidth: 80 }}>
                  <Typography variant="body2" fontWeight="bold">
                    {ctrl.compliance.toFixed(1)}%
                  </Typography>
                  <LinearProgress
                    variant="determinate"
                    value={ctrl.compliance}
                    sx={{ height: 4, borderRadius: 2 }}
                    color={ctrl.compliance >= 90 ? 'success' : 'warning'}
                  />
                </Box>
              </TableCell>
              <TableCell>
                <Box display="flex" flexWrap="wrap" gap={0.5}>
                  {ctrl.aws_services.map((service, idx) => (
                    <Chip key={idx} label={service} size="small" variant="outlined" />
                  ))}
                </Box>
              </TableCell>
              <TableCell>
                {ctrl.automated ? (
                  <Chip label="Yes" color="success" size="small" />
                ) : (
                  <Chip label="No" color="default" size="small" />
                )}
              </TableCell>
              <TableCell>
                <Chip 
                  label={ctrl.findings} 
                  color={ctrl.findings > 5 ? 'error' : ctrl.findings > 0 ? 'warning' : 'success'}
                  size="small"
                />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  return (
    <Box sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" fontWeight="bold" gutterBottom>
            PCI-DSS Compliance Dashboard
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Payment Card Industry Data Security Standard v3.2.1
          </Typography>
        </Box>
        <Button
          startIcon={<RefreshIcon />}
          onClick={loadData}
          disabled={loading}
          variant="outlined"
        >
          Refresh
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {loading && <LinearProgress sx={{ mb: 3 }} />}

      {dashboard && (
        <>
          <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ mb: 3 }}>
            <Tab label="Overview" />
            <Tab label={`Requirements (${requirements.length})`} />
            <Tab label={`Controls (${controls.length})`} />
          </Tabs>

          {activeTab === 0 && renderOverview()}
          {activeTab === 1 && renderRequirements()}
          {activeTab === 2 && renderControls()}
        </>
      )}
    </Box>
  );
};

export default PCIDSS;

