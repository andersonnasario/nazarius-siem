import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, LinearProgress, IconButton, Tooltip
} from '@mui/material';
import {
  Visibility as VisibilityIcon,
  RssFeed as RssFeedIcon,
  BugReport as BugReportIcon,
  Person as PersonIcon,
  Campaign as CampaignIcon,
  Link as LinkIcon,
  TrendingUp as TrendingUpIcon
} from '@mui/icons-material';
import { threatIntelFusionAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const ThreatIntelFusion = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [feeds, setFeeds] = useState([]);
  const [indicators, setIndicators] = useState([]);
  const [actors, setActors] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

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
      const [feedsRes, indicatorsRes, actorsRes, campaignsRes, correlationsRes, metricsRes] = await Promise.all([
        threatIntelFusionAPI.listFeeds(),
        threatIntelFusionAPI.listIndicators(),
        threatIntelFusionAPI.listActors(),
        threatIntelFusionAPI.listCampaigns(),
        threatIntelFusionAPI.listCorrelations(),
        threatIntelFusionAPI.getMetrics(),
      ]);

      setFeeds(feedsRes.data.data || []);
      setIndicators(indicatorsRes.data.data || []);
      setActors(actorsRes.data.data || []);
      setCampaigns(campaignsRes.data.data || []);
      setCorrelations(correlationsRes.data.data || []);
      setMetrics(metricsRes.data.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load threat intelligence data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Details Handlers
  const handleViewFeed = (feed) => {
    setDetailsData(feed);
    setDetailsTitle(`Threat Feed: ${feed.name}`);
    setDetailsFields([
      { label: 'Feed ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Provider', key: 'provider', type: 'badge' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Reliability', key: 'reliability', type: 'badge' },
      { label: 'Last Sync', key: 'last_sync', type: 'date' },
      { label: 'Total Indicators', key: 'total_indicators', type: 'text' },
      { label: 'New Today', key: 'new_today', type: 'text' },
      { label: 'Update Frequency', key: 'update_frequency', type: 'text' },
      { label: 'API Endpoint', key: 'api_endpoint', type: 'text' },
      { label: 'Configured At', key: 'configured_at', type: 'date' },
      { label: 'Tags', key: 'tags', type: 'array' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewIndicator = (indicator) => {
    setDetailsData(indicator);
    setDetailsTitle(`IOC: ${indicator.value}`);
    setDetailsFields([
      { label: 'Indicator ID', key: 'id', type: 'text' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Value', key: 'value', type: 'text', fullWidth: true },
      { label: 'Threat Level', key: 'threat_level', type: 'badge' },
      { label: 'Confidence (%)', key: 'confidence', type: 'text' },
      { label: 'First Seen', key: 'first_seen', type: 'date' },
      { label: 'Last Seen', key: 'last_seen', type: 'date' },
      { label: 'Sources', key: 'sources', type: 'array' },
      { label: 'Threat Types', key: 'threat_types', type: 'array' },
      { label: 'Malware Family', key: 'malware_family', type: 'text' },
      { label: 'Threat Actor', key: 'threat_actor', type: 'text' },
      { label: 'Campaign', key: 'campaign', type: 'text' },
      { label: 'MITRE Techniques', key: 'mitre_techniques', type: 'array' },
      { label: 'Geolocation', key: 'geolocation', type: 'text' },
      { label: 'ASN', key: 'asn', type: 'text' },
      { label: 'Reputation', key: 'reputation', type: 'text' },
      { label: 'Tags', key: 'tags', type: 'array' },
      { label: 'Related IOCs', key: 'related_iocs', type: 'array' },
      { label: 'Context', key: 'context', type: 'text', fullWidth: true },
    ]);
    setDetailsOpen(true);
  };

  const handleViewActor = (actor) => {
    setDetailsData(actor);
    setDetailsTitle(`Threat Actor: ${actor.name}`);
    setDetailsFields([
      { label: 'Actor ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Aliases', key: 'aliases', type: 'array' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Sophistication', key: 'sophistication', type: 'badge' },
      { label: 'Origin', key: 'origin', type: 'text' },
      { label: 'First Seen', key: 'first_seen', type: 'date' },
      { label: 'Last Activity', key: 'last_activity', type: 'date' },
      { label: 'Target Sectors', key: 'target_sectors', type: 'array' },
      { label: 'Target Countries', key: 'target_countries', type: 'array' },
      { label: 'TTPs', key: 'ttps', type: 'array' },
      { label: 'Tools', key: 'tools', type: 'array' },
      { label: 'Malware', key: 'malware', type: 'array' },
      { label: 'Campaigns', key: 'campaigns', type: 'array' },
      { label: 'Known IOCs', key: 'known_iocs', type: 'text' },
      { label: 'Threat Score', key: 'threat_score', type: 'text' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
    ]);
    setDetailsOpen(true);
  };

  const handleViewCampaign = (campaign) => {
    setDetailsData(campaign);
    setDetailsTitle(`Campaign: ${campaign.name}`);
    setDetailsFields([
      { label: 'Campaign ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Severity', key: 'severity', type: 'badge' },
      { label: 'First Detected', key: 'first_detected', type: 'date' },
      { label: 'Last Activity', key: 'last_activity', type: 'date' },
      { label: 'Threat Actors', key: 'threat_actors', type: 'array' },
      { label: 'Target Sectors', key: 'target_sectors', type: 'array' },
      { label: 'Target Countries', key: 'target_countries', type: 'array' },
      { label: 'Attack Vectors', key: 'attack_vectors', type: 'array' },
      { label: 'Objectives', key: 'objectives', type: 'array' },
      { label: 'TTPs', key: 'ttps', type: 'array' },
      { label: 'IOCs Identified', key: 'iocs_identified', type: 'text' },
      { label: 'Victims Affected', key: 'victims_affected', type: 'text' },
      { label: 'MITRE Tactics', key: 'mitre_tactics', type: 'array' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Recommendations', key: 'recommendations', type: 'array' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewCorrelation = (correlation) => {
    setDetailsData(correlation);
    setDetailsTitle(`Correlation: ${correlation.id}`);
    setDetailsFields([
      { label: 'Correlation ID', key: 'id', type: 'text' },
      { label: 'Type', key: 'type', type: 'badge' },
      { label: 'Severity', key: 'severity', type: 'badge' },
      { label: 'Confidence (%)', key: 'confidence', type: 'text' },
      { label: 'Detected At', key: 'detected_at', type: 'date' },
      { label: 'Source Event', key: 'source_event', type: 'text' },
      { label: 'Matched IOC', key: 'matched_ioc', type: 'text' },
      { label: 'Threat Actor', key: 'threat_actor', type: 'text' },
      { label: 'Campaign', key: 'campaign', type: 'text' },
      { label: 'MITRE Techniques', key: 'mitre_techniques', type: 'array' },
      { label: 'Affected Assets', key: 'affected_assets', type: 'array' },
      { label: 'Context', key: 'context', type: 'text', fullWidth: true },
      { label: 'Recommendations', key: 'recommendations', type: 'array' },
      { label: 'Status', key: 'status', type: 'badge' },
    ]);
    setDetailsOpen(true);
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success', connected: 'success',
      inactive: 'default', dormant: 'default', ended: 'default',
      error: 'error',
      new: 'info', investigating: 'warning', resolved: 'success'
    };
    return colors[status] || 'default';
  };

  const getSeverityColor = (severity) => {
    const colors = { critical: 'error', high: 'error', medium: 'warning', low: 'info' };
    return colors[severity] || 'default';
  };

  const getThreatLevelColor = (level) => {
    const colors = { critical: 'error', high: 'error', medium: 'warning', low: 'info' };
    return colors[level] || 'default';
  };

  const getReliabilityColor = (reliability) => {
    const colors = { high: 'success', medium: 'warning', low: 'error' };
    return colors[reliability] || 'default';
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
          <LinkIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Threat Intelligence Fusion
        </Typography>
        <Typography variant="body2" color="textSecondary">
          Aggregate, enrich, and correlate threat intelligence from multiple sources
        </Typography>
      </Box>

      {/* KPI Cards */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Total Indicators</Typography>
              <Typography variant="h4">{(metrics.total_indicators || 0).toLocaleString()}</Typography>
              <Typography variant="caption" color="success.main">
                +{(metrics.new_indicators_today || 0).toLocaleString()} today
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Active Feeds</Typography>
              <Typography variant="h4">{metrics.active_feeds || 0}</Typography>
              <Typography variant="caption" color="textSecondary">
                Enrichment: {metrics.enrichment_rate || 0}%
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Correlations Today</Typography>
              <Typography variant="h4">{metrics.correlations_today || 0}</Typography>
              <Typography variant="caption" color="error.main">
                {metrics.critical_threats || 0} critical
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Active Campaigns</Typography>
              <Typography variant="h4">{metrics.active_campaigns || 0}</Typography>
              <Typography variant="caption" color="textSecondary">
                {metrics.tracked_actors || 0} actors tracked
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tab label="Threat Feeds" />
          <Tab label="Indicators (IOCs)" />
          <Tab label="Threat Actors" />
          <Tab label="Campaigns" />
          <Tab label="Correlations" />
        </Tabs>

        {/* Tab 0: Threat Feeds */}
        {activeTab === 0 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Threat Intelligence Feeds</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Feed Name</TableCell>
                    <TableCell>Provider</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Reliability</TableCell>
                    <TableCell>Indicators</TableCell>
                    <TableCell>Last Sync</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {feeds.map((feed) => (
                    <TableRow key={feed.id} hover>
                      <TableCell>
                        <strong>{feed.name}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {feed.update_frequency}
                        </Typography>
                      </TableCell>
                      <TableCell><Chip label={feed.provider} size="small" /></TableCell>
                      <TableCell><Chip label={feed.type} size="small" variant="outlined" /></TableCell>
                      <TableCell><Chip label={feed.status} color={getStatusColor(feed.status)} size="small" /></TableCell>
                      <TableCell><Chip label={feed.reliability} color={getReliabilityColor(feed.reliability)} size="small" /></TableCell>
                      <TableCell>
                        <Typography variant="body2">{feed.total_indicators.toLocaleString()}</Typography>
                        <Typography variant="caption" color="success.main">+{feed.new_today} today</Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(feed.last_sync).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell align="center">
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
        )}

        {/* Tab 1: Indicators */}
        {activeTab === 1 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Enriched Indicators (IOCs)</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Indicator</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Threat Level</TableCell>
                    <TableCell>Confidence</TableCell>
                    <TableCell>Sources</TableCell>
                    <TableCell>Threat Actor</TableCell>
                    <TableCell>Campaign</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {indicators.map((indicator) => (
                    <TableRow key={indicator.id} hover>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {indicator.value}
                        </Typography>
                        {indicator.malware_family && (
                          <Chip label={indicator.malware_family} size="small" sx={{ mt: 0.5 }} />
                        )}
                      </TableCell>
                      <TableCell><Chip label={indicator.type} size="small" variant="outlined" /></TableCell>
                      <TableCell><Chip label={indicator.threat_level} color={getThreatLevelColor(indicator.threat_level)} size="small" /></TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>{indicator.confidence.toFixed(1)}%</Typography>
                          <LinearProgress variant="determinate" value={indicator.confidence} sx={{ width: 50 }} />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">{indicator.sources.length} sources</Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">{indicator.threat_actor || 'Unknown'}</Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">{indicator.campaign || 'N/A'}</Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewIndicator(indicator)}>
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

        {/* Tab 2: Threat Actors */}
        {activeTab === 2 && (
          <Grid container spacing={3} p={2}>
            {actors.map((actor) => (
              <Grid item xs={12} md={6} key={actor.id}>
                <Card>
                  <CardContent>
                    <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                      <Box display="flex" alignItems="center">
                        <PersonIcon sx={{ fontSize: 40, mr: 2, color: 'error.main' }} />
                        <Box>
                          <Typography variant="h6">{actor.name}</Typography>
                          <Typography variant="caption" color="textSecondary">
                            {actor.type} • {actor.origin}
                          </Typography>
                        </Box>
                      </Box>
                      <Tooltip title="View Details">
                        <IconButton size="small" onClick={() => handleViewActor(actor)}>
                          <VisibilityIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>

                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="textSecondary">Sophistication</Typography>
                        <Box>
                          <Chip label={actor.sophistication} size="small" color="error" />
                        </Box>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="textSecondary">Threat Score</Typography>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}><strong>{actor.threat_score.toFixed(0)}</strong></Typography>
                          <LinearProgress variant="determinate" value={actor.threat_score} sx={{ width: 60 }} color="error" />
                        </Box>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="textSecondary">Known IOCs</Typography>
                        <Typography variant="body2"><strong>{actor.known_iocs}</strong></Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="textSecondary">Last Activity</Typography>
                        <Typography variant="body2">{new Date(actor.last_activity).toLocaleDateString()}</Typography>
                      </Grid>
                    </Grid>

                    <Box mt={2}>
                      <Typography variant="caption" color="textSecondary">Target Sectors:</Typography>
                      <Box mt={0.5}>
                        {actor.target_sectors.slice(0, 3).map((sector, i) => (
                          <Chip key={i} label={sector} size="small" variant="outlined" sx={{ mr: 0.5, mb: 0.5 }} />
                        ))}
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}

        {/* Tab 3: Campaigns */}
        {activeTab === 3 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Active Threat Campaigns</Typography>
            <Grid container spacing={3}>
              {campaigns.map((campaign) => (
                <Grid item xs={12} key={campaign.id}>
                  <Card>
                    <CardContent>
                      <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                        <Box display="flex" alignItems="center" flex={1}>
                          <CampaignIcon sx={{ fontSize: 40, mr: 2, color: 'warning.main' }} />
                          <Box flex={1}>
                            <Box display="flex" alignItems="center" gap={1}>
                              <Typography variant="h6">{campaign.name}</Typography>
                              <Chip label={campaign.status} color={getStatusColor(campaign.status)} size="small" />
                              <Chip label={campaign.severity} color={getSeverityColor(campaign.severity)} size="small" />
                            </Box>
                            <Typography variant="body2" color="textSecondary" mt={1}>
                              {campaign.description}
                            </Typography>
                          </Box>
                        </Box>
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewCampaign(campaign)}>
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </Box>

                      <Grid container spacing={2}>
                        <Grid item xs={3}>
                          <Typography variant="caption" color="textSecondary">IOCs Identified</Typography>
                          <Typography variant="h6">{campaign.iocs_identified}</Typography>
                        </Grid>
                        <Grid item xs={3}>
                          <Typography variant="caption" color="textSecondary">Victims Affected</Typography>
                          <Typography variant="h6">{campaign.victims_affected}</Typography>
                        </Grid>
                        <Grid item xs={3}>
                          <Typography variant="caption" color="textSecondary">First Detected</Typography>
                          <Typography variant="body2">{new Date(campaign.first_detected).toLocaleDateString()}</Typography>
                        </Grid>
                        <Grid item xs={3}>
                          <Typography variant="caption" color="textSecondary">Last Activity</Typography>
                          <Typography variant="body2">{new Date(campaign.last_activity).toLocaleDateString()}</Typography>
                        </Grid>
                      </Grid>

                      <Box mt={2}>
                        <Typography variant="caption" color="textSecondary">Target Sectors:</Typography>
                        <Box mt={0.5}>
                          {campaign.target_sectors.map((sector, i) => (
                            <Chip key={i} label={sector} size="small" variant="outlined" sx={{ mr: 0.5, mb: 0.5 }} />
                          ))}
                        </Box>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Box>
        )}

        {/* Tab 4: Correlations */}
        {activeTab === 4 && (
          <Box p={2}>
            <Typography variant="h6" gutterBottom>Threat Correlations</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Correlation</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Confidence</TableCell>
                    <TableCell>Detected</TableCell>
                    <TableCell>Affected Assets</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {correlations.map((corr) => (
                    <TableRow key={corr.id} hover>
                      <TableCell>
                        <strong>{corr.id}</strong>
                        <Typography variant="caption" display="block" color="textSecondary">
                          {corr.campaign || corr.threat_actor || 'N/A'}
                        </Typography>
                      </TableCell>
                      <TableCell><Chip label={corr.type} size="small" variant="outlined" /></TableCell>
                      <TableCell><Chip label={corr.severity} color={getSeverityColor(corr.severity)} size="small" /></TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>{corr.confidence.toFixed(0)}%</Typography>
                          <LinearProgress variant="determinate" value={corr.confidence} sx={{ width: 50 }} />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(corr.detected_at).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">{corr.affected_assets.length} assets</Typography>
                      </TableCell>
                      <TableCell><Chip label={corr.status} color={getStatusColor(corr.status)} size="small" /></TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewCorrelation(corr)}>
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

export default ThreatIntelFusion;

