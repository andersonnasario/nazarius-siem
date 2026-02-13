import React, { useState, useEffect } from 'react';
import {
  Box, Container, Grid, Card, CardContent, Typography, Button,
  Tab, Tabs, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Select, MenuItem, FormControl, InputLabel, Chip,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Paper, IconButton, Alert, CircularProgress, FormControlLabel, Checkbox
} from '@mui/material';
import {
  PictureAsPdf, Description, GetApp, Schedule, History,
  PlayArrow, Assessment, Security, BugReport, Speed
} from '@mui/icons-material';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';

const Reports = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [templates, setTemplates] = useState([]);
  const [reports, setReports] = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(false);
  
  // Dialog states
  const [generateDialog, setGenerateDialog] = useState(false);
  const [scheduleDialog, setScheduleDialog] = useState(false);
  const [previewDialog, setPreviewDialog] = useState(false);
  
  // Form states
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [reportName, setReportName] = useState('');
  const [reportFormat, setReportFormat] = useState('pdf');
  const [dateRange, setDateRange] = useState({ start: new Date(), end: new Date() });
  const [parameters, setParameters] = useState({});

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      // Load templates (mock data)
      setTemplates([
        {
          id: 'executive-summary',
          name: 'Executive Summary Report',
          description: 'High-level security overview for executive leadership',
          category: 'executive',
          icon: <Assessment />,
          color: '#2196f3'
        },
        {
          id: 'compliance-report',
          name: 'Compliance Report',
          description: 'Compliance status report (PCI-DSS, HIPAA, SOC 2)',
          category: 'compliance',
          icon: <Security />,
          color: '#4caf50'
        },
        {
          id: 'incident-response',
          name: 'Incident Response Report',
          description: 'Detailed incident investigation and response report',
          category: 'incident',
          icon: <Description />,
          color: '#ff9800'
        },
        {
          id: 'vulnerability-assessment',
          name: 'Vulnerability Assessment Report',
          description: 'Comprehensive vulnerability scan and assessment results',
          category: 'vulnerability',
          icon: <BugReport />,
          color: '#f44336'
        },
        {
          id: 'security-metrics',
          name: 'Security Metrics Dashboard',
          description: 'Key security metrics and KPIs for operational tracking',
          category: 'operations',
          icon: <Speed />,
          color: '#9c27b0'
        }
      ]);

      // Load reports history
      setReports([
        {
          id: 'report-001',
          name: 'Monthly Executive Summary',
          template: 'executive-summary',
          format: 'pdf',
          createdAt: '2025-11-06T10:30:00Z',
          status: 'completed',
          fileUrl: '#'
        },
        {
          id: 'report-002',
          name: 'Q4 Compliance Report',
          template: 'compliance-report',
          format: 'excel',
          createdAt: '2025-11-05T14:20:00Z',
          status: 'completed',
          fileUrl: '#'
        }
      ]);

      // Load schedules
      setSchedules([
        {
          id: 'schedule-001',
          name: 'Monthly Executive Report',
          template: 'executive-summary',
          schedule: 'Monthly (1st at 9:00 AM)',
          format: 'pdf',
          recipients: ['ceo@company.com', 'ciso@company.com'],
          enabled: true,
          nextRun: '2025-12-01T09:00:00Z'
        }
      ]);

      // Load stats
      setStats({
        totalReports: 147,
        reportsThisMonth: 23,
        scheduledReports: 8,
        avgGenerationTime: '2.3s'
      });
    } catch (error) {
      console.error('Error loading data:', error);
    }
  };

  const handleGenerateReport = async () => {
    if (!selectedTemplate || !reportName) {
      return;
    }

    setLoading(true);
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      alert(`Report "${reportName}" generated successfully!`);
      setGenerateDialog(false);
      resetForm();
      loadData();
    } catch (error) {
      console.error('Error generating report:', error);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setSelectedTemplate(null);
    setReportName('');
    setReportFormat('pdf');
    setParameters({});
  };

  const handleDownload = (report) => {
    alert(`Downloading ${report.name} (${report.format})`);
  };

  const getFormatIcon = (format) => {
    switch (format) {
      case 'pdf': return <PictureAsPdf color="error" />;
      case 'excel': return <Description style={{ color: '#217346' }} />;
      case 'csv': return <Description style={{ color: '#666' }} />;
      default: return <Description />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'success';
      case 'generating': return 'warning';
      case 'failed': return 'error';
      default: return 'default';
    }
  };

  return (
    <LocalizationProvider dateAdapter={AdapterDateFns}>
      <Container maxWidth="xl">
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" gutterBottom>
            Reports & Analytics
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Generate, schedule, and manage security reports
          </Typography>
        </Box>

        {/* Stats Cards */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Total Reports
                </Typography>
                <Typography variant="h4">{stats.totalReports}</Typography>
                <Typography variant="caption" color="text.secondary">
                  All time
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  This Month
                </Typography>
                <Typography variant="h4">{stats.reportsThisMonth}</Typography>
                <Typography variant="caption" color="success.main">
                  +15% vs last month
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Scheduled Reports
                </Typography>
                <Typography variant="h4">{stats.scheduledReports}</Typography>
                <Typography variant="caption" color="text.secondary">
                  Active schedules
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Avg Generation Time
                </Typography>
                <Typography variant="h4">{stats.avgGenerationTime}</Typography>
                <Typography variant="caption" color="success.main">
                  -20% faster
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Tabs */}
        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
          <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
            <Tab label="Templates" icon={<Assessment />} iconPosition="start" />
            <Tab label="History" icon={<History />} iconPosition="start" />
            <Tab label="Scheduled" icon={<Schedule />} iconPosition="start" />
          </Tabs>
        </Box>

        {/* Tab: Templates */}
        {activeTab === 0 && (
          <Grid container spacing={3}>
            {templates.map((template) => (
              <Grid item xs={12} md={6} lg={4} key={template.id}>
                <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                  <CardContent sx={{ flexGrow: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <Box sx={{ color: template.color, mr: 2 }}>
                        {template.icon}
                      </Box>
                      <Typography variant="h6">{template.name}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {template.description}
                    </Typography>
                    <Chip
                      label={template.category}
                      size="small"
                      sx={{ bgcolor: template.color, color: 'white' }}
                    />
                  </CardContent>
                  <Box sx={{ p: 2, pt: 0 }}>
                    <Button
                      variant="contained"
                      fullWidth
                      startIcon={<PlayArrow />}
                      onClick={() => {
                        setSelectedTemplate(template);
                        setGenerateDialog(true);
                      }}
                    >
                      Generate Report
                    </Button>
                  </Box>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}

        {/* Tab: History */}
        {activeTab === 1 && (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Report Name</TableCell>
                  <TableCell>Template</TableCell>
                  <TableCell>Format</TableCell>
                  <TableCell>Created At</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {reports.map((report) => (
                  <TableRow key={report.id}>
                    <TableCell>{report.name}</TableCell>
                    <TableCell>{report.template}</TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {getFormatIcon(report.format)}
                        {report.format.toUpperCase()}
                      </Box>
                    </TableCell>
                    <TableCell>
                      {new Date(report.createdAt).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={report.status}
                        size="small"
                        color={getStatusColor(report.status)}
                      />
                    </TableCell>
                    <TableCell>
                      <IconButton
                        size="small"
                        onClick={() => handleDownload(report)}
                        color="primary"
                      >
                        <GetApp />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Tab: Scheduled */}
        {activeTab === 2 && (
          <Box>
            <Box sx={{ mb: 3, display: 'flex', justifyContent: 'flex-end' }}>
              <Button
                variant="contained"
                startIcon={<Schedule />}
                onClick={() => setScheduleDialog(true)}
              >
                New Schedule
              </Button>
            </Box>
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Template</TableCell>
                    <TableCell>Schedule</TableCell>
                    <TableCell>Format</TableCell>
                    <TableCell>Recipients</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Next Run</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {schedules.map((schedule) => (
                    <TableRow key={schedule.id}>
                      <TableCell>{schedule.name}</TableCell>
                      <TableCell>{schedule.template}</TableCell>
                      <TableCell>{schedule.schedule}</TableCell>
                      <TableCell>{schedule.format.toUpperCase()}</TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {schedule.recipients.length} recipients
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={schedule.enabled ? 'Enabled' : 'Disabled'}
                          size="small"
                          color={schedule.enabled ? 'success' : 'default'}
                        />
                      </TableCell>
                      <TableCell>
                        {new Date(schedule.nextRun).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* Generate Report Dialog */}
        <Dialog
          open={generateDialog}
          onClose={() => setGenerateDialog(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            Generate Report: {selectedTemplate?.name}
          </DialogTitle>
          <DialogContent>
            <Box sx={{ pt: 2 }}>
              <TextField
                label="Report Name"
                fullWidth
                value={reportName}
                onChange={(e) => setReportName(e.target.value)}
                sx={{ mb: 3 }}
              />

              <FormControl fullWidth sx={{ mb: 3 }}>
                <InputLabel>Format</InputLabel>
                <Select
                  value={reportFormat}
                  onChange={(e) => setReportFormat(e.target.value)}
                  label="Format"
                >
                  <MenuItem value="pdf">PDF</MenuItem>
                  <MenuItem value="excel">Excel</MenuItem>
                  <MenuItem value="csv">CSV</MenuItem>
                  <MenuItem value="json">JSON</MenuItem>
                </Select>
              </FormControl>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6}>
                  <DatePicker
                    label="Start Date"
                    value={dateRange.start}
                    onChange={(date) => setDateRange({ ...dateRange, start: date })}
                    renderInput={(params) => <TextField {...params} fullWidth />}
                  />
                </Grid>
                <Grid item xs={6}>
                  <DatePicker
                    label="End Date"
                    value={dateRange.end}
                    onChange={(date) => setDateRange({ ...dateRange, end: date })}
                    renderInput={(params) => <TextField {...params} fullWidth />}
                  />
                </Grid>
              </Grid>

              {selectedTemplate?.id === 'compliance-report' && (
                <FormControl fullWidth sx={{ mb: 3 }}>
                  <InputLabel>Framework</InputLabel>
                  <Select label="Framework" defaultValue="PCI-DSS">
                    <MenuItem value="PCI-DSS">PCI-DSS</MenuItem>
                    <MenuItem value="HIPAA">HIPAA</MenuItem>
                    <MenuItem value="SOC2">SOC 2</MenuItem>
                    <MenuItem value="ISO27001">ISO 27001</MenuItem>
                    <MenuItem value="GDPR">GDPR</MenuItem>
                  </Select>
                </FormControl>
              )}

              <Alert severity="info" sx={{ mt: 2 }}>
                Report will be generated and available for download in a few seconds.
              </Alert>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setGenerateDialog(false)}>Cancel</Button>
            <Button
              variant="contained"
              onClick={handleGenerateReport}
              disabled={loading || !reportName}
              startIcon={loading ? <CircularProgress size={20} /> : <PlayArrow />}
            >
              {loading ? 'Generating...' : 'Generate'}
            </Button>
          </DialogActions>
        </Dialog>

      </Container>
    </LocalizationProvider>
  );
};

export default Reports;

