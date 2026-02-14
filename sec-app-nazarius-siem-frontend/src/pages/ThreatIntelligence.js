import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Button,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  CircularProgress,
  Alert,
  LinearProgress,
  Tooltip,
  Collapse,
  Divider,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  BugReport as BugIcon,
  Public as PublicIcon,
  CloudSync as CloudSyncIcon,
  Shield as ShieldIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Close as CloseIcon,
  LocationOn as LocationIcon,
  Timeline as TimelineIcon,
  Storage as StorageIcon,
  Dns as DnsIcon,
  Link as LinkIcon,
  EventNote as EventNoteIcon,
  Assessment as AssessmentIcon,
  Gavel as GavelIcon,
  ContentCopy as CopyIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  OpenInNew as OpenInNewIcon,
} from '@mui/icons-material';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, Legend } from 'recharts';
import { threatIntelAPI } from '../services/api';

const COLORS = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#fbc02d',
  low: '#388e3c',
};

const ThreatIntelligence = () => {
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Data states
  const [stats, setStats] = useState(null);
  const [iocs, setIOCs] = useState([]);
  const [feeds, setFeeds] = useState([]);
  const [dataSource, setDataSource] = useState('unknown');
  
  // Filter states
  const [typeFilter, setTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  
  // Dialog states
  const [openIOCDialog, setOpenIOCDialog] = useState(false);
  const [selectedIOC, setSelectedIOC] = useState(null);
  const [openCreateDialog, setOpenCreateDialog] = useState(false);
  
  // Related events states
  const [relatedEvents, setRelatedEvents] = useState([]);
  const [relatedEventsLoading, setRelatedEventsLoading] = useState(false);
  const [relatedEventsOpen, setRelatedEventsOpen] = useState(false);
  const [relatedEventsError, setRelatedEventsError] = useState(null);
  const [relatedEventsTotal, setRelatedEventsTotal] = useState(0);

  // Form state
  const [newIOC, setNewIOC] = useState({
    type: 'ip',
    value: '',
    threat: '',
    severity: 'medium',
    confidence: 50,
    description: '',
    tags: '',
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [statsRes, iocsRes, feedsRes] = await Promise.all([
        threatIntelAPI.getStats(),
        threatIntelAPI.getIOCs(),
        threatIntelAPI.getFeeds(),
      ]);
      
      // Handle new API response format which may return { stats: {...}, dataSource: "..." }
      const statsData = statsRes.data?.stats || statsRes.data;
      setStats(statsData);
      setIOCs(iocsRes.data.iocs || []);
      setFeeds(feedsRes.data.feeds || []);
      
      // Set data source indicator
      const source = iocsRes.data?.dataSource || 'unknown';
      setDataSource(source);
      
      // Data source identified from response
    } catch (err) {
      console.error('Error loading threat intelligence data:', err);
      setError('Erro ao carregar dados de Threat Intelligence');
    } finally {
      setLoading(false);
    }
  };

  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
  };

  const handleIOCClick = (ioc) => {
    setSelectedIOC(ioc);
    setOpenIOCDialog(true);
  };

  const handleCloseIOCDialog = () => {
    setOpenIOCDialog(false);
    setSelectedIOC(null);
    setRelatedEvents([]);
    setRelatedEventsOpen(false);
    setRelatedEventsError(null);
    setRelatedEventsTotal(0);
  };

  const handleLoadRelatedEvents = useCallback(async (ioc) => {
    if (!ioc) return;
    
    setRelatedEventsLoading(true);
    setRelatedEventsError(null);
    setRelatedEventsOpen(true);
    
    try {
      // Usar endpoint dedicado que busca em todos os índices sem filtro de timestamp
      const res = await threatIntelAPI.getIOCRelatedEvents(ioc.value, 50);
      
      const events = res.data?.events || [];
      const total = res.data?.total || 0;
      
      setRelatedEvents(events);
      setRelatedEventsTotal(total);

      if (res.data?.error) {
        console.warn('IOC related events search warning:', res.data.error);
      }
    } catch (err) {
      console.error('Error loading related events:', err);
      setRelatedEventsError('Erro ao carregar eventos relacionados');
      setRelatedEvents([]);
    } finally {
      setRelatedEventsLoading(false);
    }
  }, []);

  const handleOpenCreateDialog = () => {
    setOpenCreateDialog(true);
  };

  const handleCloseCreateDialog = () => {
    setOpenCreateDialog(false);
    setNewIOC({
      type: 'ip',
      value: '',
      threat: '',
      severity: 'medium',
      confidence: 50,
      description: '',
      tags: '',
    });
  };

  const handleCreateIOC = async () => {
    try {
      const iocData = {
        ...newIOC,
        tags: newIOC.tags.split(',').map(t => t.trim()).filter(t => t),
      };
      
      await threatIntelAPI.createIOC(iocData);
      handleCloseCreateDialog();
      loadData();
    } catch (err) {
      console.error('Error creating IOC:', err);
      setError('Erro ao criar IOC');
    }
  };

  const handleDeleteIOC = async (iocId) => {
    if (window.confirm('Tem certeza que deseja deletar este IOC?')) {
      try {
        await threatIntelAPI.deleteIOC(iocId);
        loadData();
      } catch (err) {
        console.error('Error deleting IOC:', err);
        setError('Erro ao deletar IOC');
      }
    }
  };

  const getSeverityColor = (severity) => {
    return COLORS[severity] || '#757575';
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return <ErrorIcon sx={{ color: COLORS.critical, fontSize: 20 }} />;
      case 'high':
        return <WarningIcon sx={{ color: COLORS.high, fontSize: 20 }} />;
      case 'medium':
        return <InfoIcon sx={{ color: COLORS.medium, fontSize: 20 }} />;
      case 'low':
        return <CheckCircleIcon sx={{ color: COLORS.low, fontSize: 20 }} />;
      default:
        return <InfoIcon sx={{ fontSize: 20 }} />;
    }
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'ip':
        return <PublicIcon />;
      case 'domain':
        return <PublicIcon />;
      case 'hash':
        return <ShieldIcon />;
      case 'url':
        return <PublicIcon />;
      case 'cve':
        return <BugIcon />;
      default:
        return <SecurityIcon />;
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  // Filter IOCs
  const filteredIOCs = iocs.filter(ioc => {
    if (typeFilter && ioc.type !== typeFilter) return false;
    if (severityFilter && ioc.severity !== severityFilter) return false;
    return true;
  });

  // Prepare chart data
  const severityData = stats ? Object.entries(stats.iocsBySeverity).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    color: COLORS[name],
  })) : [];

  const typeData = stats ? Object.entries(stats.iocsByType).map(([name, value]) => ({
    name: name.toUpperCase(),
    value,
  })) : [];

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>
          Threat Intelligence
        </Typography>
          <Chip 
            label={dataSource === 'opensearch' ? 'OpenSearch' : dataSource === 'mock' ? 'Demo Mode' : 'Carregando...'} 
            size="small"
            color={dataSource === 'opensearch' ? 'success' : 'warning'}
            variant="outlined"
          />
        </Box>
        <Box>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={loadData}
            sx={{ mr: 1 }}
          >
            Atualizar
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleOpenCreateDialog}
          >
            Novo IOC
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Stats Cards */}
      {stats && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={2}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <SecurityIcon sx={{ mr: 1, color: 'primary.main' }} />
                  <Typography variant="body2" color="text.secondary">
                    Total IOCs
                  </Typography>
                </Box>
                <Typography variant="h4">{stats.totalIOCs.toLocaleString()}</Typography>
                <Typography variant="caption" color="success.main">
                  {stats.activeIOCs} ativos
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={2}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <ErrorIcon sx={{ mr: 1, color: COLORS.critical }} />
                  <Typography variant="body2" color="text.secondary">
                    Critical
                  </Typography>
                </Box>
                <Typography variant="h4">{stats.iocsBySeverity.critical}</Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={2}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <WarningIcon sx={{ mr: 1, color: COLORS.high }} />
                  <Typography variant="body2" color="text.secondary">
                    High
                  </Typography>
                </Box>
                <Typography variant="h4">{stats.iocsBySeverity.high}</Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={2}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <CloudSyncIcon sx={{ mr: 1, color: 'primary.main' }} />
                  <Typography variant="body2" color="text.secondary">
                    Feeds Ativos
                  </Typography>
                </Box>
                <Typography variant="h4">{stats.feedsActive}</Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={2}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <ShieldIcon sx={{ mr: 1, color: 'success.main' }} />
                  <Typography variant="body2" color="text.secondary">
                    Eventos Enriquecidos
                  </Typography>
                </Box>
                <Typography variant="h4">{stats.eventsEnriched.toLocaleString()}</Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={2}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <BugIcon sx={{ mr: 1, color: 'error.main' }} />
                  <Typography variant="body2" color="text.secondary">
                    Top Threat
                  </Typography>
                </Box>
                <Typography variant="h6" sx={{ mt: 1 }}>
                  {stats.topThreats[0]?.threat || 'N/A'}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {stats.topThreats[0]?.count || 0} IOCs
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Charts */}
      {stats && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  IOCs por Severidade
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  IOCs por Tipo
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={typeData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="value" fill="#1976d2" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Top Threats */}
      {stats && stats.topThreats && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Top 5 Ameaças
            </Typography>
            <Grid container spacing={2}>
              {stats.topThreats.map((threat, index) => (
                <Grid item xs={12} sm={6} md={2.4} key={index}>
                  <Box
                    sx={{
                      p: 2,
                      border: '1px solid',
                      borderColor: 'divider',
                      borderRadius: 1,
                      background: `linear-gradient(135deg, ${getSeverityColor(threat.severity)}15 0%, transparent 100%)`,
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                      {getSeverityIcon(threat.severity)}
                      <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                        #{index + 1}
                      </Typography>
                    </Box>
                    <Typography variant="h6" sx={{ textTransform: 'capitalize' }}>
                      {threat.threat}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {threat.count} IOCs
                    </Typography>
                    <Chip
                      label={threat.severity}
                      size="small"
                      sx={{
                        mt: 1,
                        backgroundColor: getSeverityColor(threat.severity),
                        color: 'white',
                        fontSize: '0.7rem',
                      }}
                    />
                  </Box>
                </Grid>
              ))}
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Card>
        <Tabs value={tabValue} onChange={handleTabChange} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tab label="IOCs" />
          <Tab label="Feeds" />
          <Tab label="Top Países" />
        </Tabs>

        {/* Tab 1: IOCs */}
        {tabValue === 0 && (
          <CardContent>
            {/* Filters */}
            <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
              <TextField
                select
                label="Tipo"
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                size="small"
                sx={{ minWidth: 150 }}
              >
                <MenuItem value="">Todos</MenuItem>
                <MenuItem value="ip">IP</MenuItem>
                <MenuItem value="domain">Domain</MenuItem>
                <MenuItem value="hash">Hash</MenuItem>
                <MenuItem value="url">URL</MenuItem>
                <MenuItem value="cve">CVE</MenuItem>
              </TextField>

              <TextField
                select
                label="Severidade"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                size="small"
                sx={{ minWidth: 150 }}
              >
                <MenuItem value="">Todas</MenuItem>
                <MenuItem value="critical">Critical</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="low">Low</MenuItem>
              </TextField>

              <Typography variant="body2" sx={{ ml: 'auto', alignSelf: 'center', color: 'text.secondary' }}>
                {filteredIOCs.length} IOCs encontrados
              </Typography>
            </Box>

            {/* IOCs Table */}
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Tipo</TableCell>
                    <TableCell>Valor</TableCell>
                    <TableCell>Ameaça</TableCell>
                    <TableCell>Severidade</TableCell>
                    <TableCell>Confidence</TableCell>
                    <TableCell>Source</TableCell>
                    <TableCell>Eventos</TableCell>
                    <TableCell>Última Detecção</TableCell>
                    <TableCell>Ações</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredIOCs.map((ioc) => (
                    <TableRow
                      key={ioc.id}
                      hover
                      sx={{ cursor: 'pointer' }}
                      onClick={() => handleIOCClick(ioc)}
                    >
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          {getTypeIcon(ioc.type)}
                          <Typography variant="body2" sx={{ ml: 1, textTransform: 'uppercase' }}>
                            {ioc.type}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                          {ioc.value.length > 40 ? `${ioc.value.substring(0, 40)}...` : ioc.value}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={ioc.threat}
                          size="small"
                          sx={{ textTransform: 'capitalize' }}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={ioc.severity}
                          size="small"
                          sx={{
                            backgroundColor: getSeverityColor(ioc.severity),
                            color: 'white',
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <LinearProgress
                            variant="determinate"
                            value={ioc.confidence}
                            sx={{ width: 60, mr: 1 }}
                          />
                          <Typography variant="body2">{ioc.confidence}%</Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip label={ioc.source} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={ioc.eventCount}
                          size="small"
                          color={ioc.eventCount > 0 ? 'error' : 'default'}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {formatDate(ioc.lastSeen)}
                        </Typography>
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Tooltip title="Deletar">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => handleDeleteIOC(ioc.id)}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        )}

        {/* Tab 2: Feeds */}
        {tabValue === 1 && (
          <CardContent>
            <Grid container spacing={2}>
              {feeds.map((feed) => (
                <Grid item xs={12} md={6} key={feed.id}>
                  <Card variant="outlined">
                    <CardContent>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                        <Box>
                          <Typography variant="h6">{feed.name}</Typography>
                          <Chip
                            label={feed.type}
                            size="small"
                            sx={{ mt: 0.5, textTransform: 'capitalize' }}
                          />
                        </Box>
                        <Chip
                          label={feed.enabled ? 'Ativo' : 'Inativo'}
                          color={feed.enabled ? 'success' : 'default'}
                          size="small"
                        />
                      </Box>

                      <Box sx={{ mb: 2 }}>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                          IOCs: <strong>{feed.iocCount.toLocaleString()}</strong>
                        </Typography>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                          Atualização: <strong>A cada {feed.updateFreq} min</strong>
                        </Typography>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                          Última atualização: <strong>{formatDate(feed.lastUpdate)}</strong>
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Próxima atualização: <strong>{formatDate(feed.nextUpdate)}</strong>
                        </Typography>
                      </Box>

                      {feed.config && (
                        <Box sx={{ p: 1, bgcolor: 'grey.100', borderRadius: 1 }}>
                          {Object.entries(feed.config).map(([key, value]) => (
                            <Typography key={key} variant="caption" display="block" sx={{ fontFamily: 'monospace' }}>
                              {key}: {value}
                            </Typography>
                          ))}
                        </Box>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </CardContent>
        )}

        {/* Tab 3: Top Países */}
        {tabValue === 2 && stats && stats.topCountries && (
          <CardContent>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Posição</TableCell>
                    <TableCell>País</TableCell>
                    <TableCell>Total de IOCs</TableCell>
                    <TableCell>Risk Score</TableCell>
                    <TableCell>Nível de Ameaça</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {stats.topCountries.map((country, index) => (
                    <TableRow key={country.country}>
                      <TableCell>
                        <Chip label={`#${index + 1}`} size="small" />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body1" fontWeight={500}>
                          {country.country}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">{country.count.toLocaleString()}</Typography>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <LinearProgress
                            variant="determinate"
                            value={country.score}
                            sx={{
                              width: 100,
                              mr: 1,
                              '& .MuiLinearProgress-bar': {
                                backgroundColor: country.score >= 80 ? COLORS.critical : country.score >= 60 ? COLORS.high : COLORS.medium,
                              },
                            }}
                          />
                          <Typography variant="body2">{country.score}/100</Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        {country.score >= 80 && (
                          <Chip label="Muito Alto" size="small" sx={{ backgroundColor: COLORS.critical, color: 'white' }} />
                        )}
                        {country.score >= 60 && country.score < 80 && (
                          <Chip label="Alto" size="small" sx={{ backgroundColor: COLORS.high, color: 'white' }} />
                        )}
                        {country.score < 60 && (
                          <Chip label="Moderado" size="small" sx={{ backgroundColor: COLORS.medium, color: 'white' }} />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        )}
      </Card>

      {/* IOC Details Dialog - Redesenhado */}
      <Dialog open={openIOCDialog} onClose={handleCloseIOCDialog} maxWidth="lg" fullWidth>
        {selectedIOC && (
          <>
            <DialogTitle sx={{ pb: 1 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                    {getTypeIcon(selectedIOC.type)}
                    <Typography variant="h5" sx={{ fontWeight: 600 }}>
                      Detalhes do IOC
                    </Typography>
                    <Chip
                      label={selectedIOC.severity}
                      size="small"
                      sx={{
                        backgroundColor: getSeverityColor(selectedIOC.severity),
                        color: 'white',
                        fontWeight: 600,
                      }}
                    />
                    <Chip
                      label={selectedIOC.isActive ? 'ATIVO' : 'INATIVO'}
                      size="small"
                      color={selectedIOC.isActive ? 'error' : 'default'}
                      variant="outlined"
                    />
                  </Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                      ID: {selectedIOC.id}
                    </Typography>
                    <IconButton size="small" onClick={() => navigator.clipboard.writeText(selectedIOC.id)} title="Copiar ID">
                      <CopyIcon sx={{ fontSize: 14 }} />
                    </IconButton>
                  </Box>
                </Box>
                <IconButton onClick={handleCloseIOCDialog}>
                  <CloseIcon />
                </IconButton>
              </Box>
            </DialogTitle>
            <DialogContent dividers>
              {/* Seção 1: Identificação Principal */}
              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <SecurityIcon color="primary" />
                  <Typography variant="h6" sx={{ fontWeight: 600 }}>
                    Identificação
                  </Typography>
                </Box>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={3}>
                      <Typography variant="caption" color="text.secondary">Tipo</Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                        {getTypeIcon(selectedIOC.type)}
                        <Typography variant="body1" sx={{ fontWeight: 600, textTransform: 'uppercase' }}>
                          {selectedIOC.type}
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="caption" color="text.secondary">Valor</Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                        <Typography variant="body1" sx={{ 
                          fontFamily: 'monospace', 
                          fontWeight: 600, 
                          wordBreak: 'break-all',
                          color: 'error.main',
                          fontSize: '1rem'
                        }}>
                          {selectedIOC.value}
                        </Typography>
                        <IconButton size="small" onClick={() => navigator.clipboard.writeText(selectedIOC.value)} title="Copiar valor">
                          <CopyIcon sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Typography variant="caption" color="text.secondary">Ameaça</Typography>
                      <Box sx={{ mt: 0.5 }}>
                        <Chip label={selectedIOC.threat} sx={{ textTransform: 'capitalize', fontWeight: 600 }} color="error" variant="outlined" />
                      </Box>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="caption" color="text.secondary">Descrição</Typography>
                      <Typography variant="body1" sx={{ mt: 0.5 }}>
                        {selectedIOC.description || 'Sem descrição disponível'}
                      </Typography>
                    </Grid>
                  </Grid>
                </Paper>
              </Box>

              {/* Seção 2: Avaliação de Risco */}
              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <AssessmentIcon color="warning" />
                  <Typography variant="h6" sx={{ fontWeight: 600 }}>
                    Avaliação de Risco
                  </Typography>
                </Box>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Grid container spacing={3}>
                    <Grid item xs={12} md={3}>
                      <Typography variant="caption" color="text.secondary">Severidade</Typography>
                      <Box sx={{ mt: 0.5 }}>
                        <Chip
                          icon={getSeverityIcon(selectedIOC.severity)}
                          label={selectedIOC.severity?.toUpperCase()}
                          sx={{
                            backgroundColor: getSeverityColor(selectedIOC.severity),
                            color: 'white',
                            fontWeight: 700,
                            fontSize: '0.9rem',
                            '& .MuiChip-icon': { color: 'white' }
                          }}
                        />
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Typography variant="caption" color="text.secondary">Nível de Confiança</Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                        <LinearProgress
                          variant="determinate"
                          value={selectedIOC.confidence}
                          sx={{ 
                            width: '100%', 
                            mr: 1, 
                            height: 10, 
                            borderRadius: 5,
                            '& .MuiLinearProgress-bar': {
                              backgroundColor: selectedIOC.confidence >= 80 ? '#4caf50' : selectedIOC.confidence >= 50 ? '#ff9800' : '#f44336',
                              borderRadius: 5,
                            }
                          }}
                        />
                        <Typography variant="body1" sx={{ fontWeight: 700, minWidth: 45 }}>
                          {selectedIOC.confidence}%
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={2}>
                      <Typography variant="caption" color="text.secondary">Fonte</Typography>
                      <Box sx={{ mt: 0.5 }}>
                        <Chip label={selectedIOC.source} variant="outlined" color="info" />
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Typography variant="caption" color="text.secondary">Status</Typography>
                      <Box sx={{ mt: 0.5 }}>
                        <Chip 
                          label={selectedIOC.isActive ? 'Ameaça Ativa' : 'Inativo'} 
                          color={selectedIOC.isActive ? 'error' : 'default'}
                          sx={{ fontWeight: 600 }}
                        />
                      </Box>
                    </Grid>
                  </Grid>
                </Paper>
              </Box>

              {/* Seção 3: Linha do Tempo e Impacto */}
              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <TimelineIcon color="info" />
                  <Typography variant="h6" sx={{ fontWeight: 600 }}>
                    Linha do Tempo e Impacto
                  </Typography>
                </Box>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Grid container spacing={3}>
                    <Grid item xs={12} md={3}>
                      <Typography variant="caption" color="text.secondary">Primeira Detecção</Typography>
                      <Typography variant="body1" sx={{ mt: 0.5, fontWeight: 500 }}>
                        {formatDate(selectedIOC.firstSeen)}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Typography variant="caption" color="text.secondary">Última Detecção</Typography>
                      <Typography variant="body1" sx={{ mt: 0.5, fontWeight: 500 }}>
                        {formatDate(selectedIOC.lastSeen)}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Typography variant="caption" color="text.secondary">Tempo de Exposição</Typography>
                      <Typography variant="body1" sx={{ mt: 0.5, fontWeight: 500, color: 'warning.main' }}>
                        {(() => {
                          const first = new Date(selectedIOC.firstSeen);
                          const last = new Date(selectedIOC.lastSeen);
                          const diffDays = Math.ceil((last - first) / (1000 * 60 * 60 * 24));
                          if (diffDays <= 0) return 'Menos de 1 dia';
                          if (diffDays === 1) return '1 dia';
                          return `${diffDays} dias`;
                        })()}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Typography variant="caption" color="text.secondary">Eventos Correlacionados</Typography>
                      <Box 
                        sx={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          gap: 1, 
                          mt: 0.5,
                          cursor: 'pointer',
                          p: 1,
                          borderRadius: 1,
                          transition: 'all 0.2s',
                          '&:hover': {
                            bgcolor: 'action.hover',
                          }
                        }}
                        onClick={() => {
                          if (relatedEventsOpen) {
                            setRelatedEventsOpen(false);
                          } else {
                            handleLoadRelatedEvents(selectedIOC);
                          }
                        }}
                      >
                        <EventNoteIcon sx={{ color: selectedIOC.eventCount > 0 ? 'error.main' : 'text.secondary' }} />
                        <Typography variant="h5" sx={{ fontWeight: 700, color: selectedIOC.eventCount > 0 ? 'error.main' : 'text.secondary' }}>
                          {selectedIOC.eventCount}
                        </Typography>
                        {relatedEventsOpen ? (
                          <ExpandLessIcon sx={{ color: 'text.secondary' }} />
                        ) : (
                          <ExpandMoreIcon sx={{ color: 'text.secondary' }} />
                        )}
                      </Box>
                      {selectedIOC.eventCount > 0 && !relatedEventsOpen && (
                        <Typography variant="caption" color="primary.main" sx={{ cursor: 'pointer', textDecoration: 'underline' }}
                          onClick={() => handleLoadRelatedEvents(selectedIOC)}
                        >
                          Clique para ver os eventos
                        </Typography>
                      )}
                    </Grid>
                  </Grid>

                  {/* Eventos Relacionados - Seção Expandível */}
                  <Collapse in={relatedEventsOpen} timeout="auto" unmountOnExit>
                    <Box sx={{ mt: 2, pt: 2, borderTop: '1px solid', borderColor: 'divider' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <EventNoteIcon color="primary" />
                          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                            Eventos Relacionados a "{selectedIOC.value}"
                          </Typography>
                          {relatedEventsTotal > 0 && (
                            <Chip label={`${relatedEventsTotal} evento${relatedEventsTotal !== 1 ? 's' : ''}`} size="small" color="primary" />
                          )}
                        </Box>
                        <IconButton size="small" onClick={() => setRelatedEventsOpen(false)}>
                          <CloseIcon fontSize="small" />
                        </IconButton>
                      </Box>

                      {relatedEventsLoading && (
                        <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
                          <CircularProgress size={30} />
                          <Typography variant="body2" color="text.secondary" sx={{ ml: 2 }}>
                            Buscando eventos...
                          </Typography>
                        </Box>
                      )}

                      {relatedEventsError && (
                        <Alert severity="error" sx={{ mb: 2 }}>
                          {relatedEventsError}
                        </Alert>
                      )}

                      {!relatedEventsLoading && !relatedEventsError && relatedEvents.length === 0 && (
                        <Alert severity="info" variant="outlined">
                          Nenhum evento ou alerta encontrado relacionado ao valor "{selectedIOC?.value}" nos índices do OpenSearch.
                        </Alert>
                      )}

                      {!relatedEventsLoading && relatedEvents.length > 0 && (
                        <TableContainer sx={{ maxHeight: 400 }}>
                          <Table size="small" stickyHeader>
                            <TableHead>
                              <TableRow>
                                <TableCell sx={{ fontWeight: 700, bgcolor: 'background.paper' }}>Timestamp</TableCell>
                                <TableCell sx={{ fontWeight: 700, bgcolor: 'background.paper' }}>Tipo/Fonte</TableCell>
                                <TableCell sx={{ fontWeight: 700, bgcolor: 'background.paper' }}>Severidade</TableCell>
                                <TableCell sx={{ fontWeight: 700, bgcolor: 'background.paper' }}>IP Origem</TableCell>
                                <TableCell sx={{ fontWeight: 700, bgcolor: 'background.paper' }}>IP Destino</TableCell>
                                <TableCell sx={{ fontWeight: 700, bgcolor: 'background.paper' }}>Descrição / Mensagem</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {relatedEvents.map((event, idx) => {
                                // Extrair campos do evento (formato pode variar)
                                const timestamp = event.timestamp || event['@timestamp'] || event.created_at || '';
                                const eventType = event.event_type || event.type || event.source || event.rule_name || '-';
                                const severity = event.severity || event.level || event.priority || '-';
                                const srcIp = event.source_ip || event.src_ip || event.sourceip || event.client_ip || '-';
                                const dstIp = event.dest_ip || event.dst_ip || event.destip || event.destination_ip || '-';
                                const message = event.message || event.description || event.title || event.rule_name || event.action || '-';
                                
                                const severityColor = {
                                  'critical': 'error',
                                  'high': 'warning',
                                  'medium': 'info',
                                  'low': 'success',
                                  'CRITICAL': 'error',
                                  'HIGH': 'warning',
                                  'MEDIUM': 'info',
                                  'LOW': 'success',
                                }[severity] || 'default';

                                return (
                                  <TableRow key={event.id || idx} hover>
                                    <TableCell sx={{ whiteSpace: 'nowrap', fontSize: '0.8rem' }}>
                                      {timestamp ? formatDate(timestamp) : '-'}
                                    </TableCell>
                                    <TableCell>
                                      <Chip label={eventType} size="small" variant="outlined" sx={{ maxWidth: 150, fontSize: '0.75rem' }} />
                                    </TableCell>
                                    <TableCell>
                                      {severity !== '-' ? (
                                        <Chip 
                                          label={severity} 
                                          size="small" 
                                          color={severityColor}
                                          sx={{ fontSize: '0.75rem' }}
                                        />
                                      ) : '-'}
                                    </TableCell>
                                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                                      <Typography 
                                        variant="body2" 
                                        sx={{ 
                                          fontFamily: 'monospace',
                                          fontSize: '0.8rem',
                                          color: srcIp === selectedIOC.value ? 'error.main' : 'text.primary',
                                          fontWeight: srcIp === selectedIOC.value ? 700 : 400,
                                        }}
                                      >
                                        {srcIp}
                                      </Typography>
                                    </TableCell>
                                    <TableCell>
                                      <Typography 
                                        variant="body2" 
                                        sx={{ 
                                          fontFamily: 'monospace',
                                          fontSize: '0.8rem',
                                          color: dstIp === selectedIOC.value ? 'error.main' : 'text.primary',
                                          fontWeight: dstIp === selectedIOC.value ? 700 : 400,
                                        }}
                                      >
                                        {dstIp}
                                      </Typography>
                                    </TableCell>
                                    <TableCell sx={{ maxWidth: 300 }}>
                                      <Tooltip title={typeof message === 'string' ? message : JSON.stringify(message)}>
                                        <Typography variant="body2" sx={{ fontSize: '0.8rem' }} noWrap>
                                          {typeof message === 'string' ? (message.length > 80 ? `${message.substring(0, 80)}...` : message) : JSON.stringify(message).substring(0, 80)}
                                        </Typography>
                                      </Tooltip>
                                    </TableCell>
                                  </TableRow>
                                );
                              })}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      )}

                      {!relatedEventsLoading && relatedEventsTotal > 50 && (
                        <Box sx={{ mt: 1, display: 'flex', justifyContent: 'center' }}>
                          <Alert severity="info" variant="outlined" sx={{ width: 'auto' }}>
                            <Typography variant="caption">
                              Exibindo 50 de {relatedEventsTotal} eventos. Acesse a página de Eventos para visualizar todos.
                            </Typography>
                          </Alert>
                        </Box>
                      )}
                    </Box>
                  </Collapse>
                </Paper>
              </Box>

              {/* Seção 4: Geolocalização e Rede */}
              {selectedIOC.metadata && (
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                    <LocationIcon color="success" />
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      Geolocalização e Rede
                    </Typography>
                  </Box>
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Grid container spacing={2}>
                      {selectedIOC.metadata?.country && (
                        <Grid item xs={12} md={3}>
                          <Typography variant="caption" color="text.secondary">País de Origem</Typography>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                            <LocationIcon sx={{ fontSize: 18 }} />
                            <Typography variant="body1" sx={{ fontWeight: 600 }}>
                              {selectedIOC.metadata.country}
                            </Typography>
                          </Box>
                        </Grid>
                      )}
                      {selectedIOC.metadata?.asn && (
                        <Grid item xs={12} md={3}>
                          <Typography variant="caption" color="text.secondary">ASN</Typography>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                            <DnsIcon sx={{ fontSize: 18 }} />
                            <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                              {selectedIOC.metadata.asn}
                            </Typography>
                          </Box>
                        </Grid>
                      )}
                      {selectedIOC.metadata?.isp && (
                        <Grid item xs={12} md={3}>
                          <Typography variant="caption" color="text.secondary">ISP / Provedor</Typography>
                          <Typography variant="body1" sx={{ mt: 0.5 }}>
                            {selectedIOC.metadata.isp}
                          </Typography>
                        </Grid>
                      )}
                      {selectedIOC.metadata?.reports && (
                        <Grid item xs={12} md={3}>
                          <Typography variant="caption" color="text.secondary">Reports Externos</Typography>
                          <Typography variant="body1" sx={{ mt: 0.5, fontWeight: 600, color: 'error.main' }}>
                            {selectedIOC.metadata.reports} denúncias
                          </Typography>
                        </Grid>
                      )}
                      {selectedIOC.metadata?.threat_actor && (
                        <Grid item xs={12} md={3}>
                          <Typography variant="caption" color="text.secondary">Ator de Ameaça</Typography>
                          <Chip label={selectedIOC.metadata.threat_actor} color="error" size="small" sx={{ mt: 0.5 }} />
                        </Grid>
                      )}
                      {selectedIOC.metadata?.campaign && (
                        <Grid item xs={12} md={3}>
                          <Typography variant="caption" color="text.secondary">Campanha Associada</Typography>
                          <Chip label={selectedIOC.metadata.campaign} color="warning" size="small" sx={{ mt: 0.5 }} />
                        </Grid>
                      )}
                      {selectedIOC.metadata?.malware_family && (
                        <Grid item xs={12} md={3}>
                          <Typography variant="caption" color="text.secondary">Família de Malware</Typography>
                          <Chip label={selectedIOC.metadata.malware_family} color="error" variant="outlined" size="small" sx={{ mt: 0.5 }} />
                        </Grid>
                      )}
                      {selectedIOC.metadata?.['beacon-type'] && (
                        <Grid item xs={12} md={3}>
                          <Typography variant="caption" color="text.secondary">Beacon Type</Typography>
                          <Typography variant="body1" sx={{ mt: 0.5, fontFamily: 'monospace' }}>
                            {selectedIOC.metadata['beacon-type']}
                          </Typography>
                        </Grid>
                      )}
                      {/* Se não houver dados de geolocalização, exibir mensagem */}
                      {!selectedIOC.metadata?.country && !selectedIOC.metadata?.asn && !selectedIOC.metadata?.isp && (
                        <Grid item xs={12}>
                          <Alert severity="info" variant="outlined">
                            Dados de geolocalização não disponíveis para este tipo de IOC.
                          </Alert>
                        </Grid>
                      )}
                    </Grid>
                  </Paper>
                </Box>
              )}

              {/* Seção 5: Tags e Classificação */}
              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <StorageIcon color="secondary" />
                  <Typography variant="h6" sx={{ fontWeight: 600 }}>
                    Tags e Classificação
                  </Typography>
                </Box>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {selectedIOC.tags && selectedIOC.tags.length > 0 ? (
                      selectedIOC.tags.map((tag, index) => (
                        <Chip 
                          key={index} 
                          label={tag} 
                          size="small" 
                          color="primary" 
                          variant="outlined"
                          sx={{ fontWeight: 500 }}
                        />
                      ))
                    ) : (
                      <Typography variant="body2" color="text.secondary">
                        Nenhuma tag associada
                      </Typography>
                    )}
                  </Box>
                </Paper>
              </Box>

              {/* Seção 6: Metadados Completos (JSON) */}
              {selectedIOC.metadata && Object.keys(selectedIOC.metadata).length > 0 && (
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                    <LinkIcon color="action" />
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      Metadados Adicionais
                    </Typography>
                  </Box>
                  <Paper 
                    variant="outlined" 
                    sx={{ 
                      p: 2, 
                      bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.04)',
                      border: (theme) => `1px solid ${theme.palette.divider}`,
                    }}
                  >
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 700, width: '30%' }}>Campo</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Valor</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {Object.entries(selectedIOC.metadata).map(([key, value]) => (
                            <TableRow key={key} hover>
                              <TableCell sx={{ fontFamily: 'monospace', fontWeight: 500, color: 'primary.main' }}>
                                {key}
                              </TableCell>
                              <TableCell sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                                {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Paper>
                </Box>
              )}

              {/* Seção 7: Recomendações de Ação */}
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <GavelIcon sx={{ color: '#ff9800' }} />
                  <Typography variant="h6" sx={{ fontWeight: 600 }}>
                    Ações Recomendadas
                  </Typography>
                </Box>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  {selectedIOC.severity === 'critical' && (
                    <Alert severity="error" sx={{ mb: 2 }}>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>
                        URGENTE: Este IOC é classificado como CRITICAL. Ação imediata necessária.
                      </Typography>
                    </Alert>
                  )}
                  <Grid container spacing={2}>
                    {/* Recomendações baseadas no tipo do IOC */}
                    {selectedIOC.type === 'ip' && (
                      <>
                        <Grid item xs={12} md={6}>
                          <Alert severity="warning" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>1. Bloquear IP no Firewall</Typography>
                            <Typography variant="caption">
                              Adicionar regra de bloqueio para {selectedIOC.value} em todos os firewalls de borda e internos.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="info" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>2. Verificar Logs de Conexão</Typography>
                            <Typography variant="caption">
                              Buscar nos logs de firewall/proxy todas as conexões de/para {selectedIOC.value} nos últimos 30 dias.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="info" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>3. Isolar Máquinas Afetadas</Typography>
                            <Typography variant="caption">
                              Se houver conexões detectadas, isolar as máquinas de origem para análise forense.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="success" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>4. Monitorar Recorrência</Typography>
                            <Typography variant="caption">
                              Criar regra de alerta para futuras tentativas de conexão com este IP.
                            </Typography>
                          </Alert>
                        </Grid>
                      </>
                    )}
                    {selectedIOC.type === 'domain' && (
                      <>
                        <Grid item xs={12} md={6}>
                          <Alert severity="warning" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>1. Bloquear Domínio no DNS/Proxy</Typography>
                            <Typography variant="caption">
                              Adicionar {selectedIOC.value} à lista de bloqueio do DNS e proxy corporativo.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="info" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>2. Verificar Resoluções DNS</Typography>
                            <Typography variant="caption">
                              Verificar logs DNS para identificar quais máquinas resolveram este domínio.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="info" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>3. Verificar E-mails Recebidos</Typography>
                            <Typography variant="caption">
                              Buscar e-mails com links para {selectedIOC.value} e quarentenar se necessário.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="success" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>4. Alertar Usuários</Typography>
                            <Typography variant="caption">
                              Se credenciais foram inseridas neste domínio, forçar reset de senhas.
                            </Typography>
                          </Alert>
                        </Grid>
                      </>
                    )}
                    {selectedIOC.type === 'hash' && (
                      <>
                        <Grid item xs={12} md={6}>
                          <Alert severity="warning" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>1. Scan de Endpoint</Typography>
                            <Typography variant="caption">
                              Executar scan completo em todos os endpoints buscando arquivos com este hash.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="info" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>2. Bloquear Hash no EDR/AV</Typography>
                            <Typography variant="caption">
                              Adicionar hash à lista de bloqueio do EDR e antivírus corporativo.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="info" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>3. Análise em Sandbox</Typography>
                            <Typography variant="caption">
                              Se o arquivo foi encontrado, executar análise dinâmica em sandbox isolado.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="success" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>4. Verificar Origem</Typography>
                            <Typography variant="caption">
                              Identificar como o arquivo chegou ao ambiente (e-mail, download, USB).
                            </Typography>
                          </Alert>
                        </Grid>
                      </>
                    )}
                    {selectedIOC.type === 'url' && (
                      <>
                        <Grid item xs={12} md={6}>
                          <Alert severity="warning" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>1. Bloquear URL no Proxy</Typography>
                            <Typography variant="caption">
                              Adicionar à blacklist do proxy e filtro de conteúdo web.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="info" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>2. Verificar Acessos</Typography>
                            <Typography variant="caption">
                              Buscar nos logs de proxy quais usuários acessaram esta URL.
                            </Typography>
                          </Alert>
                        </Grid>
                      </>
                    )}
                    {selectedIOC.type === 'cve' && (
                      <>
                        <Grid item xs={12} md={6}>
                          <Alert severity="warning" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>1. Identificar Sistemas Vulneráveis</Typography>
                            <Typography variant="caption">
                              Executar scan de vulnerabilidades para identificar sistemas afetados por {selectedIOC.value}.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="info" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>2. Aplicar Patches</Typography>
                            <Typography variant="caption">
                              Priorizar aplicação de patches para esta vulnerabilidade em todos os sistemas afetados.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="info" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>3. Mitigação Temporária</Typography>
                            <Typography variant="caption">
                              Se patch não disponível, aplicar workarounds e hardening recomendados.
                            </Typography>
                          </Alert>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Alert severity="success" variant="outlined" sx={{ height: '100%' }}>
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>4. Monitorar Exploração</Typography>
                            <Typography variant="caption">
                              Criar regras de detecção para tentativas de exploração desta vulnerabilidade.
                            </Typography>
                          </Alert>
                        </Grid>
                      </>
                    )}
                  </Grid>
                </Paper>
              </Box>

              <Divider sx={{ my: 2 }} />

              {/* Links externos de consulta */}
              <Box>
                <Typography variant="caption" color="text.secondary" gutterBottom sx={{ display: 'block', mb: 1 }}>
                  Consulta Externa
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {selectedIOC.type === 'ip' && (
                    <>
                      <Chip
                        label="AbuseIPDB"
                        size="small"
                        clickable
                        component="a"
                        href={`https://www.abuseipdb.com/check/${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                      <Chip
                        label="Shodan"
                        size="small"
                        clickable
                        component="a"
                        href={`https://www.shodan.io/host/${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                      <Chip
                        label="VirusTotal"
                        size="small"
                        clickable
                        component="a"
                        href={`https://www.virustotal.com/gui/ip-address/${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                      <Chip
                        label="OTX AlienVault"
                        size="small"
                        clickable
                        component="a"
                        href={`https://otx.alienvault.com/indicator/ip/${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                    </>
                  )}
                  {selectedIOC.type === 'domain' && (
                    <>
                      <Chip
                        label="VirusTotal"
                        size="small"
                        clickable
                        component="a"
                        href={`https://www.virustotal.com/gui/domain/${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                      <Chip
                        label="URLhaus"
                        size="small"
                        clickable
                        component="a"
                        href={`https://urlhaus.abuse.ch/browse.php?search=${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                      <Chip
                        label="OTX AlienVault"
                        size="small"
                        clickable
                        component="a"
                        href={`https://otx.alienvault.com/indicator/domain/${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                    </>
                  )}
                  {selectedIOC.type === 'hash' && (
                    <>
                      <Chip
                        label="VirusTotal"
                        size="small"
                        clickable
                        component="a"
                        href={`https://www.virustotal.com/gui/file/${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                      <Chip
                        label="MalwareBazaar"
                        size="small"
                        clickable
                        component="a"
                        href={`https://bazaar.abuse.ch/browse.php?search=sha256:${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                    </>
                  )}
                  {selectedIOC.type === 'cve' && (
                    <>
                      <Chip
                        label="NVD (NIST)"
                        size="small"
                        clickable
                        component="a"
                        href={`https://nvd.nist.gov/vuln/detail/${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                      <Chip
                        label="MITRE CVE"
                        size="small"
                        clickable
                        component="a"
                        href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${selectedIOC.value}`}
                        target="_blank"
                        variant="outlined"
                        color="primary"
                      />
                    </>
                  )}
                </Box>
              </Box>
            </DialogContent>
            <DialogActions sx={{ px: 3, py: 2 }}>
              <Button onClick={handleCloseIOCDialog} variant="contained">
                FECHAR
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Create IOC Dialog */}
      <Dialog open={openCreateDialog} onClose={handleCloseCreateDialog} maxWidth="sm" fullWidth>
        <DialogTitle>Criar Novo IOC</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              select
              label="Tipo"
              value={newIOC.type}
              onChange={(e) => setNewIOC({ ...newIOC, type: e.target.value })}
              fullWidth
            >
              <MenuItem value="ip">IP Address</MenuItem>
              <MenuItem value="domain">Domain</MenuItem>
              <MenuItem value="hash">File Hash</MenuItem>
              <MenuItem value="url">URL</MenuItem>
              <MenuItem value="cve">CVE</MenuItem>
            </TextField>

            <TextField
              label="Valor"
              value={newIOC.value}
              onChange={(e) => setNewIOC({ ...newIOC, value: e.target.value })}
              placeholder="Ex: 192.168.1.1"
              fullWidth
              required
            />

            <TextField
              label="Ameaça"
              value={newIOC.threat}
              onChange={(e) => setNewIOC({ ...newIOC, threat: e.target.value })}
              placeholder="Ex: botnet, malware, phishing"
              fullWidth
              required
            />

            <TextField
              select
              label="Severidade"
              value={newIOC.severity}
              onChange={(e) => setNewIOC({ ...newIOC, severity: e.target.value })}
              fullWidth
            >
              <MenuItem value="critical">Critical</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="low">Low</MenuItem>
            </TextField>

            <TextField
              label="Confidence"
              type="number"
              value={newIOC.confidence}
              onChange={(e) => setNewIOC({ ...newIOC, confidence: parseInt(e.target.value) })}
              inputProps={{ min: 0, max: 100 }}
              fullWidth
            />

            <TextField
              label="Descrição"
              value={newIOC.description}
              onChange={(e) => setNewIOC({ ...newIOC, description: e.target.value })}
              multiline
              rows={3}
              fullWidth
            />

            <TextField
              label="Tags (separadas por vírgula)"
              value={newIOC.tags}
              onChange={(e) => setNewIOC({ ...newIOC, tags: e.target.value })}
              placeholder="Ex: malware, apt28, russia"
              fullWidth
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseCreateDialog}>Cancelar</Button>
          <Button onClick={handleCreateIOC} variant="contained" disabled={!newIOC.value || !newIOC.threat}>
            Criar IOC
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ThreatIntelligence;

