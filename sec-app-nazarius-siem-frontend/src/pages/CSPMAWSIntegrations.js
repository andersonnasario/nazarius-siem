import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, Button, IconButton, Tooltip, Badge
} from '@mui/material';
import {
  Cloud as CloudIcon,
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  Shield as ShieldIcon,
  Description as DescriptionIcon,
  Refresh as RefreshIcon,
  Sync as SyncIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { cspmAPI } from '../services/api';

const CSPMAWSIntegrations = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [syncing, setSyncing] = useState(false);
  
  // AWS Data
  const [awsStatus, setAwsStatus] = useState(null);
  const [configFindings, setConfigFindings] = useState([]);
  const [configRules, setConfigRules] = useState([]);
  const [securityHubFindings, setSecurityHubFindings] = useState([]);
  const [guardDutyFindings, setGuardDutyFindings] = useState([]);
  const [inspectorFindings, setInspectorFindings] = useState([]);
  const [cloudTrailEvents, setCloudTrailEvents] = useState([]);

  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [
        statusRes,
        configFindingsRes,
        configRulesRes,
        securityHubRes,
        guardDutyRes,
        inspectorRes,
        cloudTrailRes
      ] = await Promise.all([
        cspmAPI.aws.getStatus(),
        cspmAPI.aws.getConfigFindings(),
        cspmAPI.aws.getConfigRules(),
        cspmAPI.aws.getSecurityHubFindings(),
        cspmAPI.aws.getGuardDutyFindings(),
        cspmAPI.aws.getInspectorFindings(),
        cspmAPI.aws.getCloudTrailEvents(),
      ]);

      setAwsStatus(statusRes.data.data || {});
      setConfigFindings(configFindingsRes.data.data || []);
      setConfigRules(configRulesRes.data.data || []);
      setSecurityHubFindings(securityHubRes.data.data || []);
      setGuardDutyFindings(guardDutyRes.data.data || []);
      setInspectorFindings(inspectorRes.data.data || []);
      setCloudTrailEvents(cloudTrailRes.data.data || []);
    } catch (err) {
      setError('Failed to load AWS integration data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSync = async () => {
    try {
      setSyncing(true);
      await cspmAPI.aws.sync();
      await loadAllData();
    } catch (err) {
      console.error('Sync failed:', err);
    } finally {
      setSyncing(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'error',
      CRITICAL: 'error',
      high: 'error',
      HIGH: 'error',
      medium: 'warning',
      MEDIUM: 'warning',
      low: 'info',
      LOW: 'info',
      informational: 'default',
      INFORMATIONAL: 'default',
    };
    return colors[severity] || 'default';
  };

  const getComplianceColor = (type) => {
    const colors = {
      COMPLIANT: 'success',
      NON_COMPLIANT: 'error',
      PASSED: 'success',
      FAILED: 'error',
      WARNING: 'warning',
    };
    return colors[type] || 'default';
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
      {/* Header */}
      <Box mb={3} display="flex" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" gutterBottom>
            <CloudIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            AWS Security Integrations
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Real-time security posture monitoring via AWS Config, Security Hub, GuardDuty, Inspector, and CloudTrail
          </Typography>
        </Box>
        <Box>
          <Button
            variant="outlined"
            startIcon={syncing ? <CircularProgress size={20} /> : <SyncIcon />}
            onClick={handleSync}
            disabled={syncing}
            sx={{ mr: 1 }}
          >
            {syncing ? 'Syncing...' : 'Sync Now'}
          </Button>
          <Button
            variant="contained"
            startIcon={<RefreshIcon />}
            onClick={loadAllData}
          >
            Refresh
          </Button>
        </Box>
      </Box>

      {/* Status Cards */}
      {awsStatus && (
        <Grid container spacing={3} mb={3}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography color="textSecondary" gutterBottom>AWS Config</Typography>
                    <Typography variant="h4">{awsStatus.services?.config?.findings || 0}</Typography>
                    <Typography variant="caption" color="textSecondary">
                      {awsStatus.services?.config?.rules || 0} rules
                    </Typography>
                  </Box>
                  <SecurityIcon sx={{ fontSize: 40, color: 'primary.main', opacity: 0.3 }} />
                </Box>
                <Chip
                  label={awsStatus.services?.config?.enabled ? 'Enabled' : 'Disabled'}
                  color={awsStatus.services?.config?.enabled ? 'success' : 'default'}
                  size="small"
                  sx={{ mt: 1 }}
                />
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography color="textSecondary" gutterBottom>Security Hub</Typography>
                    <Typography variant="h4">{awsStatus.services?.security_hub?.findings || 0}</Typography>
                    <Typography variant="caption" color="textSecondary">
                      aggregated findings
                    </Typography>
                  </Box>
                  <ShieldIcon sx={{ fontSize: 40, color: 'error.main', opacity: 0.3 }} />
                </Box>
                <Chip
                  label={awsStatus.services?.security_hub?.enabled ? 'Enabled' : 'Disabled'}
                  color={awsStatus.services?.security_hub?.enabled ? 'success' : 'default'}
                  size="small"
                  sx={{ mt: 1 }}
                />
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography color="textSecondary" gutterBottom>GuardDuty</Typography>
                    <Typography variant="h4">{awsStatus.services?.guardduty?.findings || 0}</Typography>
                    <Typography variant="caption" color="textSecondary">
                      threat findings
                    </Typography>
                  </Box>
                  <WarningIcon sx={{ fontSize: 40, color: 'warning.main', opacity: 0.3 }} />
                </Box>
                <Chip
                  label={awsStatus.services?.guardduty?.enabled ? 'Enabled' : 'Disabled'}
                  color={awsStatus.services?.guardduty?.enabled ? 'success' : 'default'}
                  size="small"
                  sx={{ mt: 1 }}
                />
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography color="textSecondary" gutterBottom>Inspector</Typography>
                    <Typography variant="h4">{awsStatus.services?.inspector?.findings || 0}</Typography>
                    <Typography variant="caption" color="textSecondary">
                      vulnerabilities
                    </Typography>
                  </Box>
                  <BugReportIcon sx={{ fontSize: 40, color: 'info.main', opacity: 0.3 }} />
                </Box>
                <Chip
                  label={awsStatus.services?.inspector?.enabled ? 'Enabled' : 'Disabled'}
                  color={awsStatus.services?.inspector?.enabled ? 'success' : 'default'}
                  size="small"
                  sx={{ mt: 1 }}
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tabs */}
      <Paper>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tab label={<Badge badgeContent={configFindings.length} color="error">AWS Config</Badge>} />
          <Tab label={<Badge badgeContent={securityHubFindings.length} color="error">Security Hub</Badge>} />
          <Tab label={<Badge badgeContent={guardDutyFindings.length} color="warning">GuardDuty</Badge>} />
          <Tab label={<Badge badgeContent={inspectorFindings.length} color="error">Inspector</Badge>} />
          <Tab label={<Badge badgeContent={cloudTrailEvents.length} color="info">CloudTrail</Badge>} />
        </Tabs>

        {/* AWS Config Tab */}
        {activeTab === 0 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>AWS Config Findings</Typography>
            <Typography variant="body2" color="textSecondary" paragraph>
              Configuration compliance findings from AWS Config rules
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Rule Name</TableCell>
                    <TableCell>Resource Type</TableCell>
                    <TableCell>Resource ID</TableCell>
                    <TableCell>Compliance</TableCell>
                    <TableCell>Annotation</TableCell>
                    <TableCell>Recorded Time</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {configFindings.map((finding, index) => (
                    <TableRow key={index} hover>
                      <TableCell><strong>{finding.config_rule_name}</strong></TableCell>
                      <TableCell><Chip label={finding.resource_type} size="small" variant="outlined" /></TableCell>
                      <TableCell>
                        <Typography variant="caption" sx={{ wordBreak: 'break-all' }}>
                          {finding.resource_id}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={finding.compliance_type}
                          color={getComplianceColor(finding.compliance_type)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>{finding.annotation}</TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(finding.result_recorded_time).toLocaleString()}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* Security Hub Tab */}
        {activeTab === 1 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Security Hub Findings</Typography>
            <Typography variant="body2" color="textSecondary" paragraph>
              Aggregated security findings from AWS Security Hub (CIS, PCI-DSS, AWS Foundational)
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Title</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Compliance Status</TableCell>
                    <TableCell>Related Requirements</TableCell>
                    <TableCell>Workflow State</TableCell>
                    <TableCell>Updated At</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {securityHubFindings.map((finding, index) => (
                    <TableRow key={index} hover>
                      <TableCell>
                        <strong>{finding.title}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {finding.description?.substring(0, 80)}...
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={finding.severity?.label || 'N/A'}
                          color={getSeverityColor(finding.severity?.label)}
                          size="small"
                        />
                        <Typography variant="caption" display="block">
                          Score: {finding.severity?.normalized || 0}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={finding.compliance?.status || 'N/A'}
                          color={getComplianceColor(finding.compliance?.status)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {finding.compliance?.related_requirements?.slice(0, 2).map((req, i) => (
                          <Chip key={i} label={req} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                        ))}
                      </TableCell>
                      <TableCell>
                        <Chip label={finding.workflow_state} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(finding.updated_at).toLocaleString()}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* GuardDuty Tab */}
        {activeTab === 2 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>GuardDuty Findings</Typography>
            <Typography variant="body2" color="textSecondary" paragraph>
              Threat detection findings from AWS GuardDuty
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Title</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Region</TableCell>
                    <TableCell>Event Count</TableCell>
                    <TableCell>First Seen</TableCell>
                    <TableCell>Last Seen</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {guardDutyFindings.map((finding, index) => (
                    <TableRow key={index} hover>
                      <TableCell>
                        <strong>{finding.title}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {finding.description?.substring(0, 60)}...
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={finding.type} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={finding.severity >= 7 ? 'HIGH' : finding.severity >= 4 ? 'MEDIUM' : 'LOW'}
                          color={finding.severity >= 7 ? 'error' : finding.severity >= 4 ? 'warning' : 'info'}
                          size="small"
                        />
                        <Typography variant="caption" display="block">
                          {finding.severity.toFixed(1)}
                        </Typography>
                      </TableCell>
                      <TableCell>{finding.region}</TableCell>
                      <TableCell>
                        <Badge badgeContent={finding.service?.count || 0} color="error">
                          <Typography variant="body2">Events</Typography>
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(finding.service?.event_first_seen).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(finding.service?.event_last_seen).toLocaleString()}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* Inspector Tab */}
        {activeTab === 3 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Inspector Findings</Typography>
            <Typography variant="body2" color="textSecondary" paragraph>
              Vulnerability findings from AWS Inspector (CVEs, package vulnerabilities)
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Title</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>CVE / Score</TableCell>
                    <TableCell>Resource</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>First Observed</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {inspectorFindings.map((finding, index) => (
                    <TableRow key={index} hover>
                      <TableCell>
                        <strong>{finding.title}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {finding.description?.substring(0, 60)}...
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={finding.type} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={finding.severity}
                          color={getSeverityColor(finding.severity)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {finding.package_vulnerability && (
                          <>
                            <Typography variant="body2">
                              {finding.package_vulnerability.vulnerability_id}
                            </Typography>
                            <Typography variant="caption" color="error">
                              CVSS: {finding.package_vulnerability.cvss}
                            </Typography>
                          </>
                        )}
                      </TableCell>
                      <TableCell>
                        {finding.resources?.map((res, i) => (
                          <Chip key={i} label={res.type} size="small" sx={{ mr: 0.5 }} />
                        ))}
                      </TableCell>
                      <TableCell>
                        <Chip label={finding.status} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(finding.first_observed_at).toLocaleString()}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* CloudTrail Tab */}
        {activeTab === 4 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>CloudTrail Events</Typography>
            <Typography variant="body2" color="textSecondary" paragraph>
              API audit logs from AWS CloudTrail (PCI-DSS Req 10.2)
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Event Name</TableCell>
                    <TableCell>Event Source</TableCell>
                    <TableCell>User Identity</TableCell>
                    <TableCell>Source IP</TableCell>
                    <TableCell>Event Type</TableCell>
                    <TableCell>Read Only</TableCell>
                    <TableCell>Event Time</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {cloudTrailEvents.map((event, index) => (
                    <TableRow key={index} hover>
                      <TableCell>
                        <strong>{event.event_name}</strong>
                        {event.error_code && (
                          <Chip label={event.error_code} color="error" size="small" sx={{ ml: 1 }} />
                        )}
                      </TableCell>
                      <TableCell>{event.event_source}</TableCell>
                      <TableCell>
                        <Chip label={event.user_identity?.type || 'N/A'} size="small" variant="outlined" />
                        <Typography variant="caption" display="block">
                          {event.user_identity?.user_name || event.user_identity?.principal_id}
                        </Typography>
                      </TableCell>
                      <TableCell>{event.source_ip_address}</TableCell>
                      <TableCell>
                        <Chip label={event.event_type} size="small" />
                      </TableCell>
                      <TableCell>
                        {event.read_only ? (
                          <CheckCircleIcon color="success" fontSize="small" />
                        ) : (
                          <ErrorIcon color="warning" fontSize="small" />
                        )}
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(event.event_time).toLocaleString()}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}
      </Paper>
    </Box>
  );
};

export default CSPMAWSIntegrations;

