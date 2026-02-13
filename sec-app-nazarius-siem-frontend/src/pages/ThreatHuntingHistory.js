import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  Grid,
  CircularProgress,
  Alert,
  Button,
  TextField,
  MenuItem,
  Chip,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  Tab,
  Select,
  FormControl,
  InputLabel
} from '@mui/material';
import {
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineConnector,
  TimelineContent,
  TimelineDot,
  TimelineOppositeContent
} from '@mui/lab';
import {
  History as HistoryIcon,
  Science as ScienceIcon,
  Search as SearchIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  PlayArrow as PlayArrowIcon,
  Refresh as RefreshIcon,
  FilterList as FilterListIcon
} from '@mui/icons-material';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, Legend, PieChart, Pie, Cell } from 'recharts';
import { threatHuntingPlatformAPI } from '../services/api';

const ACTIVITY_TYPES = {
  hypothesis_created: { label: 'Hipótese Criada', icon: ScienceIcon, color: 'primary' },
  hypothesis_validated: { label: 'Hipótese Validada', icon: CheckCircleIcon, color: 'success' },
  query_executed: { label: 'Query Executada', icon: PlayArrowIcon, color: 'info' },
  finding_created: { label: 'Finding Criado', icon: WarningIcon, color: 'warning' },
};

const SEVERITY_COLORS = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#fbc02d',
  low: '#388e3c',
};

const CHART_COLORS = ['#1976d2', '#2e7d32', '#f57c00', '#d32f2f', '#7b1fa2'];

const ThreatHuntingHistory = () => {
  const [activities, setActivities] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState(0);
  
  // Filters
  const [hunterFilter, setHunterFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [periodFilter, setPeriodFilter] = useState('7d');

  useEffect(() => {
    loadData();
  }, [hunterFilter, typeFilter, periodFilter]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Build query params
      const params = {};
      if (hunterFilter) params.hunter_id = hunterFilter;
      if (typeFilter) params.type = typeFilter;
      
      // Add date range based on period
      const now = new Date();
      if (periodFilter === '24h') {
        params.start_date = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
      } else if (periodFilter === '7d') {
        params.start_date = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
      } else if (periodFilter === '30d') {
        params.start_date = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
      }

      const [activitiesResponse, statsResponse] = await Promise.all([
        threatHuntingPlatformAPI.getActivities(params),
        threatHuntingPlatformAPI.getActivityStatistics()
      ]);

      if (activitiesResponse.data && activitiesResponse.data.success) {
        setActivities(activitiesResponse.data.data || []);
      }

      if (statsResponse.data && statsResponse.data.success) {
        setStatistics(statsResponse.data.data || {});
      }
    } catch (err) {
      console.error('Error loading hunting history:', err);
      setError('Erro ao carregar histórico de atividades. Verifique a conexão com a API.');
    } finally {
      setLoading(false);
    }
  };

  const getActivityIcon = (type) => {
    const activityType = ACTIVITY_TYPES[type];
    if (!activityType) return <HistoryIcon />;
    const Icon = activityType.icon;
    return <Icon />;
  };

  const getActivityColor = (type) => {
    const activityType = ACTIVITY_TYPES[type];
    return activityType ? activityType.color : 'default';
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d atrás`;
    if (hours > 0) return `${hours}h atrás`;
    return 'Agora';
  };

  // Prepare chart data
  const activityTypeData = statistics?.by_type
    ? Object.entries(statistics.by_type).map(([key, value]) => ({
        name: ACTIVITY_TYPES[key]?.label || key,
        value: value
      }))
    : [];

  const hunterActivityData = statistics?.by_hunter
    ? Object.entries(statistics.by_hunter).map(([key, value]) => ({
        name: key,
        activities: value
      })).slice(0, 5)
    : [];

  // Get unique hunters for filter
  const uniqueHunters = [...new Set(activities.map(a => a.hunter_id))];

  if (loading) {
    return (
      <Container maxWidth="xl" sx={{ mt: 4, mb: 4, display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '60vh' }}>
        <CircularProgress size={60} />
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <HistoryIcon sx={{ fontSize: 40 }} />
            Histórico de Threat Hunting
          </Typography>
          <Typography variant="body1" color="textSecondary">
            Timeline e estatísticas de atividades de hunting
          </Typography>
        </Box>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={loadData}
          disabled={loading}
        >
          Atualizar
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Statistics Cards */}
      {statistics && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Total de Atividades
                </Typography>
                <Typography variant="h3">{statistics.total_activities || 0}</Typography>
                <Typography variant="caption" color="text.secondary">
                  Todas as atividades registradas
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Últimas 24h
                </Typography>
                <Typography variant="h3">{statistics.last_24h || 0}</Typography>
                <Typography variant="caption" color="text.secondary">
                  Atividades recentes
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Últimos 7 dias
                </Typography>
                <Typography variant="h3">{statistics.last_7d || 0}</Typography>
                <Typography variant="caption" color="text.secondary">
                  Atividades da semana
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Últimos 30 dias
                </Typography>
                <Typography variant="h3">{statistics.last_30d || 0}</Typography>
                <Typography variant="caption" color="text.secondary">
                  Atividades do mês
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Charts */}
      {statistics && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Atividades por Tipo
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={activityTypeData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      label
                    >
                      {activityTypeData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Top 5 Hunters Mais Ativos
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={hunterActivityData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" angle={-45} textAnchor="end" height={80} />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="activities" fill="#1976d2" name="Atividades" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <FilterListIcon />
            <Typography variant="h6">Filtros</Typography>
          </Box>
          <Grid container spacing={2}>
            <Grid item xs={12} md={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Hunter</InputLabel>
                <Select
                  value={hunterFilter}
                  label="Hunter"
                  onChange={(e) => setHunterFilter(e.target.value)}
                >
                  <MenuItem value="">Todos</MenuItem>
                  {uniqueHunters.map((hunter) => (
                    <MenuItem key={hunter} value={hunter}>{hunter}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} md={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Tipo de Atividade</InputLabel>
                <Select
                  value={typeFilter}
                  label="Tipo de Atividade"
                  onChange={(e) => setTypeFilter(e.target.value)}
                >
                  <MenuItem value="">Todos</MenuItem>
                  {Object.entries(ACTIVITY_TYPES).map(([key, value]) => (
                    <MenuItem key={key} value={key}>{value.label}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} md={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Período</InputLabel>
                <Select
                  value={periodFilter}
                  label="Período"
                  onChange={(e) => setPeriodFilter(e.target.value)}
                >
                  <MenuItem value="24h">Últimas 24 horas</MenuItem>
                  <MenuItem value="7d">Últimos 7 dias</MenuItem>
                  <MenuItem value="30d">Últimos 30 dias</MenuItem>
                  <MenuItem value="all">Todos</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} md={3}>
              <Button
                fullWidth
                variant="outlined"
                onClick={() => {
                  setHunterFilter('');
                  setTypeFilter('');
                  setPeriodFilter('7d');
                }}
              >
                Limpar Filtros
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Card>
        <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
          <Tab label="Timeline" />
          <Tab label="Tabela" />
        </Tabs>

        <CardContent>
          {/* Timeline View */}
          {activeTab === 0 && (
            <Box>
              {activities.length === 0 ? (
                <Typography variant="body2" color="text.secondary" align="center" sx={{ py: 4 }}>
                  Nenhuma atividade encontrada para os filtros selecionados.
                </Typography>
              ) : (
                <Timeline position="right">
                  {activities.map((activity, index) => (
                    <TimelineItem key={activity.id}>
                      <TimelineOppositeContent color="text.secondary" sx={{ flex: 0.2 }}>
                        <Typography variant="caption">
                          {formatTimestamp(activity.timestamp)}
                        </Typography>
                        <Typography variant="caption" display="block">
                          {new Date(activity.timestamp).toLocaleString('pt-BR')}
                        </Typography>
                      </TimelineOppositeContent>
                      <TimelineSeparator>
                        <TimelineDot color={getActivityColor(activity.type)}>
                          {getActivityIcon(activity.type)}
                        </TimelineDot>
                        {index < activities.length - 1 && <TimelineConnector />}
                      </TimelineSeparator>
                      <TimelineContent>
                        <Paper elevation={3} sx={{ p: 2, mb: 2 }}>
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                            <Box>
                              <Typography variant="h6" component="span">
                                {activity.title}
                              </Typography>
                              <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                                <Chip
                                  label={ACTIVITY_TYPES[activity.type]?.label || activity.type}
                                  color={getActivityColor(activity.type)}
                                  size="small"
                                />
                                <Chip
                                  label={activity.hunter_name || activity.hunter_id}
                                  variant="outlined"
                                  size="small"
                                />
                                {activity.severity && (
                                  <Chip
                                    label={activity.severity.toUpperCase()}
                                    size="small"
                                    sx={{
                                      backgroundColor: SEVERITY_COLORS[activity.severity],
                                      color: 'white'
                                    }}
                                  />
                                )}
                              </Box>
                            </Box>
                          </Box>
                          <Typography variant="body2" color="text.secondary">
                            {activity.description}
                          </Typography>
                          {activity.metadata && Object.keys(activity.metadata).length > 0 && (
                            <Box sx={{ mt: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1 }}>
                              <Typography variant="caption" color="text.secondary">
                                {JSON.stringify(activity.metadata, null, 2)}
                              </Typography>
                            </Box>
                          )}
                        </Paper>
                      </TimelineContent>
                    </TimelineItem>
                  ))}
                </Timeline>
              )}
            </Box>
          )}

          {/* Table View */}
          {activeTab === 1 && (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>Tipo</TableCell>
                    <TableCell>Hunter</TableCell>
                    <TableCell>Título</TableCell>
                    <TableCell>Severidade</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {activities.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} align="center">
                        <Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                          Nenhuma atividade encontrada para os filtros selecionados.
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    activities.map((activity) => (
                      <TableRow key={activity.id} hover>
                        <TableCell>
                          <Typography variant="body2">
                            {new Date(activity.timestamp).toLocaleString('pt-BR')}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {formatTimestamp(activity.timestamp)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={ACTIVITY_TYPES[activity.type]?.label || activity.type}
                            color={getActivityColor(activity.type)}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>{activity.hunter_name || activity.hunter_id}</TableCell>
                        <TableCell>{activity.title}</TableCell>
                        <TableCell>
                          {activity.severity && (
                            <Chip
                              label={activity.severity.toUpperCase()}
                              size="small"
                              sx={{
                                backgroundColor: SEVERITY_COLORS[activity.severity],
                                color: 'white'
                              }}
                            />
                          )}
                        </TableCell>
                        <TableCell>
                          {activity.status && (
                            <Chip label={activity.status} variant="outlined" size="small" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>
    </Container>
  );
};

export default ThreatHuntingHistory;

