import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, IconButton, Tooltip
} from '@mui/material';
import {
  Campaign as CampaignIcon,
  Search as SearchIcon,
  Book as BookIcon,
  TrendingUp as TrendingUpIcon,
  Visibility as VisibilityIcon
} from '@mui/icons-material';
import { advancedHuntingAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const AdvancedThreatHunting = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [campaigns, setCampaigns] = useState([]);
  const [queries, setQueries] = useState([]);
  const [notebooks, setNotebooks] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [mitreCoverage, setMitreCoverage] = useState([]);
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
      const [campaignsRes, queriesRes, notebooksRes, metricsRes, coverageRes] = await Promise.all([
        advancedHuntingAPI.getCampaigns(),
        advancedHuntingAPI.getQueries(),
        advancedHuntingAPI.getNotebooks(),
        advancedHuntingAPI.getMetrics(),
        advancedHuntingAPI.getMITRECoverage()
      ]);
      
      setCampaigns(Array.isArray(campaignsRes.data.data) ? campaignsRes.data.data : []);
      setQueries(Array.isArray(queriesRes.data.data) ? queriesRes.data.data : []);
      setNotebooks(Array.isArray(notebooksRes.data.data) ? notebooksRes.data.data : []);
      setMetrics(metricsRes.data.data || {});
      setMitreCoverage(Array.isArray(coverageRes.data.data) ? coverageRes.data.data : []);
      setError(null);
    } catch (err) {
      setError('Failed to load hunting data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleViewCampaign = (campaign) => {
    setSelectedItem(campaign);
    setDetailsTitle(`Campaign: ${campaign.name}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Name', key: 'name' },
      { label: 'Description', key: 'description', fullWidth: true },
      { label: 'Status', key: 'status', type: 'status' },
      { label: 'Priority', key: 'priority', type: 'badge' },
      { label: 'Created By', key: 'created_by' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Updated At', key: 'updated_at', type: 'date' },
      { label: 'Queries', key: 'queries', type: 'array' },
      { label: 'Findings', key: 'findings' },
      { label: 'Coverage (%)', key: 'coverage' }
    ]);
    setDetailsOpen(true);
  };

  const handleViewQuery = (query) => {
    setSelectedItem(query);
    setDetailsTitle(`Query: ${query.name}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Name', key: 'name' },
      { label: 'Description', key: 'description', fullWidth: true },
      { label: 'Query', key: 'query', fullWidth: true },
      { label: 'Query Type', key: 'query_type', type: 'badge' },
      { label: 'Schedule', key: 'schedule' },
      { label: 'Enabled', key: 'enabled', type: 'status' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Last Run', key: 'last_run', type: 'date' },
      { label: 'Next Run', key: 'next_run', type: 'date' },
      { label: 'Results', key: 'results' },
      { label: 'Metadata', key: 'metadata', type: 'json', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  const handleViewNotebook = (notebook) => {
    setSelectedItem(notebook);
    setDetailsTitle(`Notebook: ${notebook.title}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Title', key: 'title' },
      { label: 'Description', key: 'description', fullWidth: true },
      { label: 'Author', key: 'author' },
      { label: 'Created At', key: 'created_at', type: 'date' },
      { label: 'Updated At', key: 'updated_at', type: 'date' },
      { label: 'Cells Count', key: 'cells' },
      { label: 'Tags', key: 'tags', type: 'array' },
      { label: 'Shared', key: 'shared', type: 'status' },
      { label: 'Collaborators', key: 'collaborators', type: 'array', fullWidth: true }
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
        🎯 Advanced Threat Hunting
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
                  <Typography color="textSecondary" gutterBottom>Active Campaigns</Typography>
                  <Typography variant="h4">{metrics.active_campaigns || 0}</Typography>
                </Box>
                <CampaignIcon sx={{ fontSize: 48, color: 'primary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Total Queries</Typography>
                  <Typography variant="h4">{metrics.total_queries || 0}</Typography>
                </Box>
                <SearchIcon sx={{ fontSize: 48, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Total Findings</Typography>
                  <Typography variant="h4">{metrics.total_findings || 0}</Typography>
                </Box>
                <TrendingUpIcon sx={{ fontSize: 48, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Avg Coverage</Typography>
                  <Typography variant="h4">{(metrics.avg_coverage || 0).toFixed(1)}%</Typography>
                </Box>
                <BookIcon sx={{ fontSize: 48, color: 'success.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 2 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label="Campaigns" />
          <Tab label="Queries" />
          <Tab label="Notebooks" />
          <Tab label="MITRE Coverage" />
        </Tabs>
      </Paper>

      {/* Campaigns Tab */}
      {activeTab === 0 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Hunting Campaigns</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Priority</TableCell>
                    <TableCell>Findings</TableCell>
                    <TableCell>Coverage</TableCell>
                    <TableCell>Created By</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {campaigns.map((campaign) => (
                    <TableRow key={campaign.id} hover>
                      <TableCell><strong>{campaign.name}</strong></TableCell>
                      <TableCell>
                        <Chip label={campaign.status} color={campaign.status === 'active' ? 'success' : 'default'} size="small" />
                      </TableCell>
                      <TableCell>
                        <Chip label={campaign.priority} color={campaign.priority === 'critical' ? 'error' : 'warning'} size="small" />
                      </TableCell>
                      <TableCell>{campaign.findings}</TableCell>
                      <TableCell>{campaign.coverage.toFixed(1)}%</TableCell>
                      <TableCell>{campaign.created_by}</TableCell>
                      <TableCell>
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewCampaign(campaign)}>
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

      {/* Queries Tab */}
      {activeTab === 1 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Hunting Queries</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Enabled</TableCell>
                    <TableCell>Results</TableCell>
                    <TableCell>Last Run</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {queries.map((query) => (
                    <TableRow key={query.id} hover>
                      <TableCell><strong>{query.name}</strong></TableCell>
                      <TableCell><Chip label={query.query_type} size="small" /></TableCell>
                      <TableCell>
                        <Chip label={query.enabled ? 'Yes' : 'No'} color={query.enabled ? 'success' : 'default'} size="small" />
                      </TableCell>
                      <TableCell>{query.results}</TableCell>
                      <TableCell>{new Date(query.last_run).toLocaleString()}</TableCell>
                      <TableCell>
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewQuery(query)}>
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

      {/* Notebooks Tab */}
      {activeTab === 2 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Hunting Notebooks</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Title</TableCell>
                    <TableCell>Author</TableCell>
                    <TableCell>Cells</TableCell>
                    <TableCell>Shared</TableCell>
                    <TableCell>Updated</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {notebooks.map((notebook) => (
                    <TableRow key={notebook.id} hover>
                      <TableCell><strong>{notebook.title}</strong></TableCell>
                      <TableCell>{notebook.author}</TableCell>
                      <TableCell>{notebook.cells.length}</TableCell>
                      <TableCell>
                        <Chip label={notebook.shared ? 'Yes' : 'No'} color={notebook.shared ? 'success' : 'default'} size="small" />
                      </TableCell>
                      <TableCell>{new Date(notebook.updated_at).toLocaleDateString()}</TableCell>
                      <TableCell>
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewNotebook(notebook)}>
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

      {/* MITRE Coverage Tab */}
      {activeTab === 3 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>MITRE ATT&CK Coverage</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Tactic</TableCell>
                    <TableCell>Total Techniques</TableCell>
                    <TableCell>Covered</TableCell>
                    <TableCell>Coverage %</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {mitreCoverage.map((tactic) => (
                    <TableRow key={tactic.tactic_id} hover>
                      <TableCell><strong>{tactic.tactic_name}</strong></TableCell>
                      <TableCell>{tactic.techniques}</TableCell>
                      <TableCell>{tactic.covered}</TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center" gap={1}>
                          <Typography>{tactic.coverage.toFixed(1)}%</Typography>
                          <Chip 
                            label={tactic.coverage >= 80 ? 'Good' : tactic.coverage >= 60 ? 'Fair' : 'Low'} 
                            color={tactic.coverage >= 80 ? 'success' : tactic.coverage >= 60 ? 'warning' : 'error'} 
                            size="small" 
                          />
                        </Box>
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

export default AdvancedThreatHunting;
