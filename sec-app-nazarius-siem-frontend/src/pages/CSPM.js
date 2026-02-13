import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, LinearProgress, IconButton, Tooltip
} from '@mui/material';
import {
  Visibility as VisibilityIcon,
  Cloud as CloudIcon,
  Storage as StorageIcon,
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  Build as BuildIcon
} from '@mui/icons-material';
import { cspmAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const CSPM = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [accounts, setAccounts] = useState([]);
  const [resources, setResources] = useState([]);
  const [findings, setFindings] = useState([]);
  const [compliance, setCompliance] = useState([]);
  const [remediation, setRemediation] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

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
      const [accountsRes, resourcesRes, findingsRes, complianceRes, remediationRes, metricsRes] = await Promise.all([
        cspmAPI.listAccounts(),
        cspmAPI.listResources(),
        cspmAPI.listFindings(),
        cspmAPI.listCompliance(),
        cspmAPI.listRemediation(),
        cspmAPI.getMetrics(),
      ]);

      setAccounts(accountsRes.data.data || []);
      setResources(resourcesRes.data.data || []);
      setFindings(findingsRes.data.data || []);
      setCompliance(complianceRes.data.data || []);
      setRemediation(remediationRes.data.data || []);
      setMetrics(metricsRes.data.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load CSPM data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleViewAccount = (account) => {
    setDetailsData(account);
    setDetailsTitle(`Cloud Account: ${account.name}`);
    setDetailsFields([
      { label: 'Account ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Provider', key: 'provider', type: 'badge' },
      { label: 'Account ID', key: 'account_id', type: 'text' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Region', key: 'region', type: 'text' },
      { label: 'Environment', key: 'environment', type: 'badge' },
      { label: 'Resources', key: 'resources', type: 'text' },
      { label: 'Misconfigurations', key: 'misconfigurations', type: 'text' },
      { label: 'Critical Issues', key: 'critical_issues', type: 'text' },
      { label: 'Compliance Score (%)', key: 'compliance_score', type: 'text' },
      { label: 'Last Scan', key: 'last_scan', type: 'date' },
      { label: 'Next Scan', key: 'next_scan', type: 'date' },
      { label: 'Tags', key: 'tags', type: 'array' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewResource = (resource) => {
    setDetailsData(resource);
    setDetailsTitle(`Resource: ${resource.name}`);
    setDetailsFields([
      { label: 'Resource ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Provider', key: 'provider', type: 'badge' },
      { label: 'Account ID', key: 'account_id', type: 'text' },
      { label: 'Region', key: 'region', type: 'text' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Security Score', key: 'security_score', type: 'text' },
      { label: 'Issues', key: 'issues', type: 'text' },
      { label: 'Critical Issues', key: 'critical_issues', type: 'text' },
      { label: 'Public Exposure', key: 'public_exposure', type: 'text' },
      { label: 'Encrypted', key: 'encrypted', type: 'text' },
      { label: 'Backup Enabled', key: 'backup_enabled', type: 'text' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Last Modified', key: 'last_modified', type: 'date' },
      { label: 'Tags', key: 'tags', type: 'json', fullWidth: true },
    ]);
    setDetailsOpen(true);
  };

  const handleViewFinding = (finding) => {
    setDetailsData(finding);
    setDetailsTitle(`Finding: ${finding.title}`);
    setDetailsFields([
      { label: 'Finding ID', key: 'id', type: 'text' },
      { label: 'Title', key: 'title', type: 'text' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Severity', key: 'severity', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Category', key: 'category', type: 'badge' },
      { label: 'Resource ID', key: 'resource_id', type: 'text' },
      { label: 'Resource Name', key: 'resource_name', type: 'text' },
      { label: 'Resource Type', key: 'resource_type', type: 'text' },
      { label: 'Provider', key: 'provider', type: 'text' },
      { label: 'Account ID', key: 'account_id', type: 'text' },
      { label: 'Region', key: 'region', type: 'text' },
      { label: 'Recommendation', key: 'recommendation', type: 'text', fullWidth: true },
      { label: 'Remediation Steps', key: 'remediation_steps', type: 'array' },
      { label: 'Compliance Frameworks', key: 'compliance_frameworks', type: 'array' },
      { label: 'CVSS Score', key: 'cvss', type: 'text' },
      { label: 'Detected At', key: 'detected_at', type: 'date' },
      { label: 'Updated At', key: 'updated_at', type: 'date' },
      { label: 'Resolved At', key: 'resolved_at', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewCompliance = (report) => {
    setDetailsData(report);
    setDetailsTitle(`Compliance: ${report.framework}`);
    setDetailsFields([
      { label: 'Report ID', key: 'id', type: 'text' },
      { label: 'Framework', key: 'framework', type: 'text' },
      { label: 'Provider', key: 'provider', type: 'badge' },
      { label: 'Account ID', key: 'account_id', type: 'text' },
      { label: 'Score (%)', key: 'score', type: 'text' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Total Controls', key: 'total_controls', type: 'text' },
      { label: 'Passed Controls', key: 'passed_controls', type: 'text' },
      { label: 'Failed Controls', key: 'failed_controls', type: 'text' },
      { label: 'Not Applicable', key: 'not_applicable', type: 'text' },
      { label: 'Critical Failures', key: 'critical_failures', type: 'text' },
      { label: 'Generated At', key: 'generated_at', type: 'date' },
      { label: 'Valid Until', key: 'valid_until', type: 'date' },
      { label: 'Related Findings', key: 'findings', type: 'array' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewRemediation = (task) => {
    setDetailsData(task);
    setDetailsTitle(`Remediation: ${task.title}`);
    setDetailsFields([
      { label: 'Task ID', key: 'id', type: 'text' },
      { label: 'Finding ID', key: 'finding_id', type: 'text' },
      { label: 'Title', key: 'title', type: 'text' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Priority', key: 'priority', type: 'badge' },
      { label: 'Resource ID', key: 'resource_id', type: 'text' },
      { label: 'Resource Type', key: 'resource_type', type: 'text' },
      { label: 'Provider', key: 'provider', type: 'text' },
      { label: 'Actions', key: 'actions', type: 'array' },
      { label: 'Executed By', key: 'executed_by', type: 'text' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Started At', key: 'started_at', type: 'date' },
      { label: 'Completed At', key: 'completed_at', type: 'date' },
      { label: 'Result', key: 'result', type: 'text', fullWidth: true },
      { label: 'Error Message', key: 'error_message', type: 'text', fullWidth: true },
    ]);
    setDetailsOpen(true);
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success', running: 'info', completed: 'success', compliant: 'success',
      inactive: 'default', stopped: 'default', pending: 'default',
      error: 'error', failed: 'error', non_compliant: 'error',
      in_progress: 'warning', partial: 'warning', open: 'warning',
    };
    return colors[status] || 'default';
  };

  const getSeverityColor = (severity) => {
    const colors = { critical: 'error', high: 'error', medium: 'warning', low: 'info' };
    return colors[severity] || 'default';
  };

  const getProviderColor = (provider) => {
    const colors = { aws: 'warning', azure: 'info', gcp: 'success', multi: 'default' };
    return colors[provider] || 'default';
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
          <CloudIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          CSPM - Cloud Security Posture Management
        </Typography>
        <Typography variant="body2" color="textSecondary">
          Monitor and secure your cloud infrastructure across AWS, Azure, and GCP
        </Typography>
      </Box>

      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Total Resources</Typography>
              <Typography variant="h4">{(metrics.total_resources || 0).toLocaleString()}</Typography>
              <Typography variant="caption" color="textSecondary">
                {metrics.active_accounts || 0} accounts
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Compliance Score</Typography>
              <Typography variant="h4">{metrics.avg_compliance_score || 0}%</Typography>
              <LinearProgress variant="determinate" value={metrics.avg_compliance_score || 0} sx={{ mt: 1 }} />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Critical Findings</Typography>
              <Typography variant="h4" color="error">{metrics.critical_findings || 0}</Typography>
              <Typography variant="caption" color="textSecondary">
                {metrics.total_findings || 0} total
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Remediation Rate</Typography>
              <Typography variant="h4">{metrics.remediation_rate || 0}%</Typography>
              <Typography variant="caption" color="success.main">
                {metrics.auto_remediations || 0} automated
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Paper>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tab label="Cloud Accounts" />
          <Tab label="Resources" />
          <Tab label="Security Findings" />
          <Tab label="Compliance" />
          <Tab label="Remediation" />
        </Tabs>

        {activeTab === 0 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Cloud Accounts</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Account</TableCell>
                    <TableCell>Provider</TableCell>
                    <TableCell>Environment</TableCell>
                    <TableCell>Resources</TableCell>
                    <TableCell>Issues</TableCell>
                    <TableCell>Compliance</TableCell>
                    <TableCell>Last Scan</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {accounts.map((account) => (
                    <TableRow key={account.id} hover>
                      <TableCell>
                        <strong>{account.name}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {account.account_id}
                        </Typography>
                      </TableCell>
                      <TableCell><Chip label={account.provider} color={getProviderColor(account.provider)} size="small" /></TableCell>
                      <TableCell><Chip label={account.environment} size="small" variant="outlined" /></TableCell>
                      <TableCell>{account.resources.toLocaleString()}</TableCell>
                      <TableCell>
                        <Typography variant="body2">{account.misconfigurations}</Typography>
                        <Typography variant="caption" color="error">{account.critical_issues} critical</Typography>
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>{account.compliance_score.toFixed(1)}%</Typography>
                          <LinearProgress variant="determinate" value={account.compliance_score} sx={{ width: 60 }} />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">{new Date(account.last_scan).toLocaleString()}</Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewAccount(account)}>
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
            <Typography variant="h6" gutterBottom>Cloud Resources</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Resource</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Provider</TableCell>
                    <TableCell>Security Score</TableCell>
                    <TableCell>Issues</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {resources.map((resource) => (
                    <TableRow key={resource.id} hover>
                      <TableCell>
                        <strong>{resource.name}</strong>
                        <Box mt={0.5}>
                          {resource.public_exposure && <Chip label="Public" color="error" size="small" sx={{ mr: 0.5 }} />}
                          {!resource.encrypted && <Chip label="Unencrypted" color="warning" size="small" sx={{ mr: 0.5 }} />}
                          {resource.backup_enabled && <Chip label="Backup" color="success" size="small" />}
                        </Box>
                      </TableCell>
                      <TableCell><Chip label={resource.type} size="small" variant="outlined" /></TableCell>
                      <TableCell><Chip label={resource.provider} color={getProviderColor(resource.provider)} size="small" /></TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>{resource.security_score.toFixed(0)}</Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={resource.security_score} 
                            sx={{ width: 60 }} 
                            color={resource.security_score > 70 ? 'success' : resource.security_score > 50 ? 'warning' : 'error'}
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">{resource.issues}</Typography>
                        {resource.critical_issues > 0 && (
                          <Typography variant="caption" color="error">{resource.critical_issues} critical</Typography>
                        )}
                      </TableCell>
                      <TableCell><Chip label={resource.status} color={getStatusColor(resource.status)} size="small" /></TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewResource(resource)}>
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
            <Typography variant="h6" gutterBottom>Security Findings</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Finding</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Category</TableCell>
                    <TableCell>Resource</TableCell>
                    <TableCell>Provider</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {findings.map((finding) => (
                    <TableRow key={finding.id} hover>
                      <TableCell>
                        <strong>{finding.title}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {finding.description.substring(0, 60)}...
                        </Typography>
                      </TableCell>
                      <TableCell><Chip label={finding.severity} color={getSeverityColor(finding.severity)} size="small" /></TableCell>
                      <TableCell><Chip label={finding.category} size="small" variant="outlined" /></TableCell>
                      <TableCell>
                        <Typography variant="caption">{finding.resource_name}</Typography>
                      </TableCell>
                      <TableCell><Chip label={finding.provider} color={getProviderColor(finding.provider)} size="small" /></TableCell>
                      <TableCell><Chip label={finding.status} color={getStatusColor(finding.status)} size="small" /></TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewFinding(finding)}>
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

        {activeTab === 3 && (
          <Grid container spacing={3} p={2}>
            {compliance.map((report) => (
              <Grid item xs={12} md={6} key={report.id}>
                <Card>
                  <CardContent>
                    <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                      <Box display="flex" alignItems="center">
                        <AssessmentIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
                        <Box>
                          <Typography variant="h6">{report.framework}</Typography>
                          <Typography variant="caption" color="textSecondary">
                            {report.provider} • {report.account_id}
                          </Typography>
                        </Box>
                      </Box>
                      <Tooltip title="View Details">
                        <IconButton size="small" onClick={() => handleViewCompliance(report)}>
                          <VisibilityIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>

                    <Box mb={2}>
                      <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                        <Typography variant="body2">Compliance Score</Typography>
                        <Typography variant="h5">{report.score.toFixed(1)}%</Typography>
                      </Box>
                      <LinearProgress variant="determinate" value={report.score} sx={{ height: 8, borderRadius: 1 }} />
                      <Chip label={report.status} color={getStatusColor(report.status)} size="small" sx={{ mt: 1 }} />
                    </Box>

                    <Grid container spacing={2}>
                      <Grid item xs={4}>
                        <Typography variant="caption" color="textSecondary">Passed</Typography>
                        <Typography variant="h6" color="success.main">{report.passed_controls}</Typography>
                      </Grid>
                      <Grid item xs={4}>
                        <Typography variant="caption" color="textSecondary">Failed</Typography>
                        <Typography variant="h6" color="error.main">{report.failed_controls}</Typography>
                      </Grid>
                      <Grid item xs={4}>
                        <Typography variant="caption" color="textSecondary">Critical</Typography>
                        <Typography variant="h6" color="error">{report.critical_failures}</Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}

        {activeTab === 4 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Remediation Tasks</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Task</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Priority</TableCell>
                    <TableCell>Resource</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Executed By</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {remediation.map((task) => (
                    <TableRow key={task.id} hover>
                      <TableCell>
                        <strong>{task.title}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {task.actions.length} actions
                        </Typography>
                      </TableCell>
                      <TableCell><Chip label={task.type} size="small" variant="outlined" /></TableCell>
                      <TableCell><Chip label={task.priority} color={getSeverityColor(task.priority)} size="small" /></TableCell>
                      <TableCell>
                        <Typography variant="caption">{task.resource_id}</Typography>
                      </TableCell>
                      <TableCell><Chip label={task.status} color={getStatusColor(task.status)} size="small" /></TableCell>
                      <TableCell>
                        <Typography variant="caption">{task.executed_by}</Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewRemediation(task)}>
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
      </Paper>

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

export default CSPM;
