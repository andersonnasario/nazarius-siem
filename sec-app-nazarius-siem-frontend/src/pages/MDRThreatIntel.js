import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, Tabs, Tab, IconButton, Tooltip
} from '@mui/material';
import {
  RssFeed as RssFeedIcon,
  Person as PersonIcon,
  Security as SecurityIcon,
  TrendingUp as TrendingUpIcon,
  Visibility as VisibilityIcon
} from '@mui/icons-material';
import { mdrThreatIntelAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const MDRThreatIntel = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [feeds, setFeeds] = useState([]);
  const [actors, setActors] = useState([]);
  const [iocs, setIOCs] = useState([]);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Details Dialog states
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
      const [feedsRes, actorsRes, iocsRes, statsRes] = await Promise.all([
        mdrThreatIntelAPI.getFeeds(),
        mdrThreatIntelAPI.getActors(),
        mdrThreatIntelAPI.getIOCs(),
        mdrThreatIntelAPI.getStats()
      ]);
      
      // Axios already extracts .data, so response.data is the actual API response
      // API returns: { data: [...] } so we need response.data.data
      setFeeds(Array.isArray(feedsRes.data.data) ? feedsRes.data.data : []);
      setActors(Array.isArray(actorsRes.data.data) ? actorsRes.data.data : []);
      setIOCs(Array.isArray(iocsRes.data.data) ? iocsRes.data.data : []);
      setStats(statsRes.data.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load threat intelligence data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // View Details Handlers
  const handleViewFeed = (feed) => {
    setDetailsData(feed);
    setDetailsTitle(`Threat Feed: ${feed.name}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Name', key: 'name' },
      { label: 'Type', key: 'feed_type', type: 'badge' },
      { label: 'Status', key: 'feed_status', type: 'status' },
      { label: 'IOC Count', key: 'ioc_count' },
      { label: 'Reliability', key: 'reliability', type: 'badge' },
      { label: 'Last Sync', key: 'last_sync', type: 'date' },
      { label: 'URL', key: 'url', fullWidth: true },
      { label: 'Description', key: 'description', fullWidth: true }
    ]);
    setDetailsOpen(true);
  };

  const handleViewActor = (actor) => {
    setDetailsData(actor);
    setDetailsTitle(`Threat Actor: ${actor.name}`);
    setDetailsFields([
      { label: 'ID', key: 'id' },
      { label: 'Name', key: 'name' },
      { label: 'Aliases', key: 'aliases', type: 'array' },
      { label: 'Threat Level', key: 'threat_level', type: 'badge' },
      { label: 'TTPs Count', key: 'ttp', type: 'array' },
      { label: 'Campaigns Count', key: 'campaigns', type: 'array' },
      { label: 'First Seen', key: 'first_seen', type: 'date' },
      { label: 'Last Seen', key: 'last_seen', type: 'date' },
      { label: 'Description', key: 'description', fullWidth: true },
      { label: 'Motivation', key: 'motivation', fullWidth: true }
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
        🛡️ Threat Intelligence Platform
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
                  <Typography color="textSecondary" gutterBottom>Total Feeds</Typography>
                  <Typography variant="h4">{stats.total_feeds || 0}</Typography>
                </Box>
                <RssFeedIcon sx={{ fontSize: 48, color: 'primary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Total IOCs</Typography>
                  <Typography variant="h4">{stats.total_iocs || 0}</Typography>
                </Box>
                <SecurityIcon sx={{ fontSize: 48, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Threat Actors</Typography>
                  <Typography variant="h4">{stats.total_actors || 0}</Typography>
                </Box>
                <PersonIcon sx={{ fontSize: 48, color: 'error.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>Active Campaigns</Typography>
                  <Typography variant="h4">{stats.active_campaigns || 0}</Typography>
                </Box>
                <TrendingUpIcon sx={{ fontSize: 48, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 2 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label="Threat Feeds" />
          <Tab label="Threat Actors" />
          <Tab label="IOCs" />
        </Tabs>
      </Paper>

      {/* Threat Feeds Tab */}
      {activeTab === 0 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Threat Intelligence Feeds</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>IOC Count</TableCell>
                    <TableCell>Reliability</TableCell>
                    <TableCell>Last Sync</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {feeds.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center">
                        <Alert severity="info">
                          Nenhum feed configurado. Configure feeds de ameaças nas configurações de Integrações.
                        </Alert>
                      </TableCell>
                    </TableRow>
                  ) : feeds.map((feed) => (
                    <TableRow key={feed.id} hover>
                      <TableCell>{feed.name}</TableCell>
                      <TableCell><Chip label={feed.feed_type || 'JSON'} size="small" /></TableCell>
                      <TableCell>
                        <Chip 
                          label={feed.feed_status || 'unknown'} 
                          color={feed.feed_status === 'active' ? 'success' : 'default'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell>{feed.ioc_count || 0}</TableCell>
                      <TableCell>
                        <Chip 
                          label={feed.reliability || 'medium'} 
                          color={feed.reliability === 'high' ? 'success' : 'warning'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell>{feed.last_sync ? new Date(feed.last_sync).toLocaleString() : '-'}</TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewFeed(feed)}>
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

      {/* Threat Actors Tab */}
      {activeTab === 1 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Threat Actors</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Aliases</TableCell>
                    <TableCell>Threat Level</TableCell>
                    <TableCell>TTPs</TableCell>
                    <TableCell>Campaigns</TableCell>
                    <TableCell>Last Seen</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {actors.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center">
                        <Alert severity="info">
                          Nenhum ator de ameaça cadastrado. Configure um feed de atores (MISP, MITRE) nas Integrações.
                        </Alert>
                      </TableCell>
                    </TableRow>
                  ) : actors.map((actor) => (
                    <TableRow key={actor.id} hover>
                      <TableCell><strong>{actor.name}</strong></TableCell>
                      <TableCell>{actor.aliases?.join(', ') || '-'}</TableCell>
                      <TableCell>
                        <Chip 
                          label={actor.threat_level || 'unknown'} 
                          color={actor.threat_level === 'critical' ? 'error' : 'warning'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell>{actor.ttp?.length || 0}</TableCell>
                      <TableCell>{actor.campaigns?.length || 0}</TableCell>
                      <TableCell>{actor.last_seen ? new Date(actor.last_seen).toLocaleDateString() : '-'}</TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewActor(actor)}>
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

      {/* IOCs Tab */}
      {activeTab === 2 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Indicators of Compromise (IOCs)</Typography>
            {iocs.length === 0 ? (
              <Alert severity="info" sx={{ mb: 2 }}>
                Nenhum IOC cadastrado. IOCs serão populados a partir dos feeds de ameaças ou podem ser adicionados manualmente via Threat Intelligence.
              </Alert>
            ) : (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Tipo</TableCell>
                      <TableCell>Valor</TableCell>
                      <TableCell>Severidade</TableCell>
                      <TableCell>Confiança</TableCell>
                      <TableCell>Tags</TableCell>
                      <TableCell>Primeira Detecção</TableCell>
                      <TableCell>Última Detecção</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {iocs.map((ioc) => (
                      <TableRow key={ioc.id} hover>
                        <TableCell>
                          <Chip 
                            label={ioc.type?.toUpperCase() || 'N/A'} 
                            size="small" 
                            color="primary"
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                          {ioc.value || 'N/A'}
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={ioc.severity || 'unknown'} 
                            color={
                              ioc.severity === 'critical' ? 'error' : 
                              ioc.severity === 'high' ? 'warning' : 
                              ioc.severity === 'medium' ? 'info' : 'default'
                            } 
                            size="small" 
                          />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={`${ioc.confidence || 0}%`} 
                            size="small"
                            color={ioc.confidence >= 80 ? 'success' : ioc.confidence >= 50 ? 'warning' : 'default'}
                          />
                        </TableCell>
                        <TableCell>
                          {ioc.tags?.slice(0, 3).map((tag, idx) => (
                            <Chip key={idx} label={tag} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                          )) || '-'}
                        </TableCell>
                        <TableCell>
                          {ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : '-'}
                        </TableCell>
                        <TableCell>
                          {ioc.last_seen ? new Date(ioc.last_seen).toLocaleDateString() : '-'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>
        </Paper>
      )}

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

export default MDRThreatIntel;

