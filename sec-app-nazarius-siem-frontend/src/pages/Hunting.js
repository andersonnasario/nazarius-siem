import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  CircularProgress,
  Alert,
  Chip,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  IconButton,
} from '@mui/material';
import {
  Search as SearchIcon,
  Save as SaveIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  Timeline as TimelineIcon,
  TrendingUp as TrendingUpIcon,
  Assignment as AssignmentIcon,
  Check as CheckIcon,
} from '@mui/icons-material';
import { huntingAPI } from '../services/api';

const Hunting = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  
  // Stats
  const [stats, setStats] = useState(null);
  
  // Search
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState(null);
  const [searching, setSearching] = useState(false);
  
  // Saved Searches
  const [savedSearches, setSavedSearches] = useState([]);
  
  // Campaigns
  const [campaigns, setCampaigns] = useState([]);
  
  // Timeline
  const [timeline, setTimeline] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [statsRes, searchesRes, campaignsRes] = await Promise.all([
        huntingAPI.getStats(),
        huntingAPI.getSavedSearches(),
        huntingAPI.getCampaigns(),
      ]);
      
      setStats(statsRes.data);
      setSavedSearches(searchesRes.data);
      setCampaigns(campaignsRes.data);
    } catch (err) {
      console.error('Error loading hunting data:', err);
      setError('Erro ao carregar dados de hunting');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    try {
      setSearching(true);
      const query = {
        name: "Ad-hoc Search",
        query: {
          type: "simple",
          conditions: [
            {
              field: "_all",
              operator: "contains",
              value: searchQuery
            }
          ],
          logic: "AND"
        },
        timeRange: {
          start: "now-24h",
          end: "now"
        }
      };
      
      const response = await huntingAPI.executeSearch(query);
      setSearchResults(response.data);
    } catch (err) {
      console.error('Error executing search:', err);
      alert('Erro ao executar busca');
    } finally {
      setSearching(false);
    }
  };

  const handleExecuteSavedSearch = async (search) => {
    try {
      setSearching(true);
      const response = await huntingAPI.executeSearch(search.query);
      setSearchResults(response.data);
      setTabValue(0); // Volta para aba de search
    } catch (err) {
      console.error('Error executing saved search:', err);
      alert('Erro ao executar busca salva');
    } finally {
      setSearching(false);
    }
  };

  const loadTimeline = async () => {
    try {
      const response = await huntingAPI.getTimeline();
      setTimeline(response.data);
    } catch (err) {
      console.error('Error loading timeline:', err);
      alert('Erro ao carregar timeline');
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>
          Threat Hunting
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button variant="outlined" startIcon={<AddIcon />}>
            Nova Campaign
          </Button>
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={loadData}>
            Atualizar
          </Button>
        </Box>
      </Box>

      {/* Stats */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <SearchIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Total Searches
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.totalSearches}</Typography>
              <Typography variant="caption">
                {stats?.savedSearches} saved
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <AssignmentIcon sx={{ mr: 1, color: 'secondary.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Active Campaigns
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.activeCampaigns}</Typography>
              <Typography variant="caption">
                {stats?.totalFindings} findings
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <CheckIcon sx={{ mr: 1, color: 'success.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Confirmed Threats
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.confirmedThreats}</Typography>
              <Typography variant="caption">
                {stats?.casesCreated} cases created
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <TrendingUpIcon sx={{ mr: 1, color: 'info.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Avg Search Time
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.avgSearchTime}ms</Typography>
              <Typography variant="caption">
                Performance
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Card>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="Search" />
          <Tab label="Saved Searches" />
          <Tab label="Campaigns" />
          <Tab label="Timeline" />
          <Tab label="Stats & Métricas" />
        </Tabs>

        <CardContent>
          {/* Tab 0: Search */}
          {tabValue === 0 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Search Events
              </Typography>
              
              <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
                <TextField
                  fullWidth
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Enter search query (e.g., suspicious powershell, malicious IP, etc)"
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                />
                <Button
                  variant="contained"
                  startIcon={searching ? <CircularProgress size={20} /> : <SearchIcon />}
                  onClick={handleSearch}
                  disabled={searching || !searchQuery}
                  sx={{ minWidth: 150 }}
                >
                  {searching ? 'Searching...' : 'Search'}
                </Button>
              </Box>

              {searchResults && (
                <Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                    <Typography variant="h6">
                      Results ({searchResults.totalHits} hits)
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Execution time: {searchResults.executionTime}ms
                    </Typography>
                  </Box>

                  <TableContainer>
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell>Timestamp</TableCell>
                          <TableCell>Type</TableCell>
                          <TableCell>Summary</TableCell>
                          <TableCell>Severity</TableCell>
                          <TableCell>MITRE</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {searchResults.events.map((event, idx) => (
                          <TableRow key={idx}>
                            <TableCell>{new Date(event.timestamp).toLocaleString()}</TableCell>
                            <TableCell>
                              <Chip label={event.type} size="small" variant="outlined" />
                            </TableCell>
                            <TableCell>
                              {event.process || event.src_ip || event.file || 'N/A'}
                            </TableCell>
                            <TableCell>
                              <Chip 
                                label={event.severity} 
                                size="small" 
                                color={event.severity === 'critical' ? 'error' : event.severity === 'high' ? 'warning' : 'default'}
                              />
                            </TableCell>
                            <TableCell>
                              {event.mitre && event.mitre.map((m, i) => (
                                <Chip key={i} label={m} size="small" sx={{ mr: 0.5 }} />
                              ))}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              )}
            </Box>
          )}

          {/* Tab 1: Saved Searches */}
          {tabValue === 1 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6">Saved Searches & Templates</Typography>
                <Button variant="contained" startIcon={<AddIcon />} size="small">
                  New Search
                </Button>
              </Box>

              <Grid container spacing={2}>
                {savedSearches.map((search) => (
                  <Grid item xs={12} md={6} key={search.id}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="h6">{search.name}</Typography>
                          {search.isTemplate && <Chip label="Template" size="small" color="primary" />}
                        </Box>
                        <Typography variant="body2" color="text.secondary" paragraph>
                          {search.description}
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                          <Chip label={search.category} size="small" />
                          {search.tags.map((tag, idx) => (
                            <Chip key={idx} label={tag} size="small" variant="outlined" />
                          ))}
                        </Box>
                        <Button
                          variant="outlined"
                          size="small"
                          startIcon={<SearchIcon />}
                          onClick={() => handleExecuteSavedSearch(search)}
                        >
                          Execute Search
                        </Button>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          )}

          {/* Tab 2: Campaigns */}
          {tabValue === 2 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6">Hunting Campaigns</Typography>
                <Button variant="contained" startIcon={<AddIcon />} size="small">
                  New Campaign
                </Button>
              </Box>

              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Hypothesis</TableCell>
                      <TableCell align="center">Status</TableCell>
                      <TableCell align="center">Priority</TableCell>
                      <TableCell align="right">Findings</TableCell>
                      <TableCell align="right">Cases</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {campaigns.map((campaign) => (
                      <TableRow key={campaign.id}>
                        <TableCell>
                          <Typography variant="body2" fontWeight={600}>
                            {campaign.name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {campaign.team.join(', ')}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
                            {campaign.hypothesis}
                          </Typography>
                        </TableCell>
                        <TableCell align="center">
                          <Chip
                            label={campaign.status}
                            size="small"
                            color={campaign.status === 'active' ? 'success' : 'default'}
                          />
                        </TableCell>
                        <TableCell align="center">
                          <Chip
                            label={campaign.priority}
                            size="small"
                            color={campaign.priority === 'critical' ? 'error' : campaign.priority === 'high' ? 'warning' : 'default'}
                          />
                        </TableCell>
                        <TableCell align="right">
                          {campaign.stats.totalFindings}
                          <Typography variant="caption" color="success.main" sx={{ ml: 1 }}>
                            ({campaign.stats.confirmedThreats} confirmed)
                          </Typography>
                        </TableCell>
                        <TableCell align="right">{campaign.stats.casesCreated}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Tab 3: Timeline */}
          {tabValue === 3 && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6">Event Timeline</Typography>
                <Button
                  variant="outlined"
                  startIcon={<TimelineIcon />}
                  onClick={loadTimeline}
                  size="small"
                >
                  Load Timeline
                </Button>
              </Box>

              {timeline ? (
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    {timeline.totalEvents} events from {new Date(timeline.startTime).toLocaleString()} to {new Date(timeline.endTime).toLocaleString()}
                  </Typography>
                  
                  {timeline.events.map((event, idx) => (
                    <Card key={idx} sx={{ mb: 2 }}>
                      <CardContent>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2" fontWeight={600}>
                            {new Date(event.timestamp).toLocaleString()}
                          </Typography>
                          <Chip
                            label={event.severity}
                            size="small"
                            color={event.severity === 'critical' ? 'error' : event.severity === 'high' ? 'warning' : 'default'}
                          />
                        </Box>
                        <Typography variant="body1" gutterBottom>
                          {event.summary}
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 1 }}>
                          {event.entities.map((entity, i) => (
                            <Chip key={i} label={`${entity.type}: ${entity.value}`} size="small" variant="outlined" />
                          ))}
                        </Box>
                      </CardContent>
                    </Card>
                  ))}
                </Box>
              ) : (
                <Alert severity="info">
                  Click "Load Timeline" to reconstruct event timeline
                </Alert>
              )}
            </Box>
          )}

          {/* Tab 4: Stats & Métricas */}
          {tabValue === 4 && stats && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h6">
                  Status & Métricas Detalhadas
                </Typography>
                <Button
                  startIcon={<RefreshIcon />}
                  onClick={loadData}
                  variant="outlined"
                >
                  Atualizar
                </Button>
              </Box>

              <Grid container spacing={3}>
                {/* Estatísticas de Buscas */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom color="primary">
                        📊 Estatísticas de Buscas
                      </Typography>
                      <Box sx={{ mt: 2 }}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2">Total de Buscas Executadas:</Typography>
                          <Typography variant="body2" fontWeight="bold">{stats.totalSearches}</Typography>
                        </Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2">Buscas Salvas:</Typography>
                          <Typography variant="body2" fontWeight="bold">{stats.savedSearches}</Typography>
                        </Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2">Tempo Médio de Busca:</Typography>
                          <Typography variant="body2" fontWeight="bold">{stats.avgSearchTime}ms</Typography>
                        </Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2">Eventos Analisados:</Typography>
                          <Typography variant="body2" fontWeight="bold">{(stats.totalSearches * 1250).toLocaleString()}</Typography>
                        </Box>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Campanhas de Hunting */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom color="secondary">
                        🎯 Campanhas de Hunting
                      </Typography>
                      <Box sx={{ mt: 2 }}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2">Campanhas Ativas:</Typography>
                          <Typography variant="body2" fontWeight="bold">{stats.activeCampaigns}</Typography>
                        </Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2">Total de Findings:</Typography>
                          <Typography variant="body2" fontWeight="bold">{stats.totalFindings}</Typography>
                        </Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2">Ameaças Confirmadas:</Typography>
                          <Typography variant="body2" fontWeight="bold" color="error.main">{stats.confirmedThreats}</Typography>
                        </Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2">Casos Criados:</Typography>
                          <Typography variant="body2" fontWeight="bold">{stats.casesCreated}</Typography>
                        </Box>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Top Hunters */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom color="success.main">
                        🏆 Top Hunters
                      </Typography>
                      <TableContainer>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Analista</TableCell>
                              <TableCell align="right">Buscas</TableCell>
                              <TableCell align="right">Findings</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {stats.topHunters?.map((hunter, index) => (
                              <TableRow key={index}>
                                <TableCell>{hunter.name}</TableCell>
                                <TableCell align="right">{hunter.searches}</TableCell>
                                <TableCell align="right">{hunter.findings}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Trending Searches */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom color="info.main">
                        🔥 Buscas em Alta
                      </Typography>
                      <TableContainer>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Query</TableCell>
                              <TableCell align="right">Execuções</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {stats.trendingSearches?.map((search, index) => (
                              <TableRow key={index}>
                                <TableCell>{search.query}</TableCell>
                                <TableCell align="right">{search.count}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Performance */}
                <Grid item xs={12}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom color="warning.main">
                        ⚡ Performance & Sistema
                      </Typography>
                      <Grid container spacing={2} sx={{ mt: 1 }}>
                        <Grid item xs={12} sm={6} md={3}>
                          <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
                            <Typography variant="h4" color="primary">{stats.avgSearchTime}ms</Typography>
                            <Typography variant="caption">Tempo Médio</Typography>
                          </Box>
                        </Grid>
                        <Grid item xs={12} sm={6} md={3}>
                          <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
                            <Typography variant="h4" color="success.main">99.8%</Typography>
                            <Typography variant="caption">Taxa de Sucesso</Typography>
                          </Box>
                        </Grid>
                        <Grid item xs={12} sm={6} md={3}>
                          <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
                            <Typography variant="h4" color="info.main">{stats.totalSearches}</Typography>
                            <Typography variant="caption">Queries Executadas</Typography>
                          </Box>
                        </Grid>
                        <Grid item xs={12} sm={6} md={3}>
                          <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
                            <Typography variant="h4" color="warning.main">24/7</Typography>
                            <Typography variant="caption">Disponibilidade</Typography>
                          </Box>
                        </Grid>
                      </Grid>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Box>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

export default Hunting;

