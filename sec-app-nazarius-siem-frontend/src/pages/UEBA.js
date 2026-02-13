import React, { useState, useEffect, useCallback } from 'react';
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
  CircularProgress,
  Alert,
  Chip,
  Avatar,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  InputAdornment,
  IconButton,
  Pagination,
  FormControl,
  InputLabel,
  Select,
  OutlinedInput,
  Checkbox,
  ListItemText,
  Tooltip,
} from '@mui/material';
import {
  Person as PersonIcon,
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  Security as SecurityIcon,
  Refresh as RefreshIcon,
  Group as GroupIcon,
  Timeline as TimelineIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  Clear as ClearIcon,
  CleaningServices as CleanupIcon,
} from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';
import { uebaAPI } from '../services/api';

const RISK_LEVELS = ['critical', 'high', 'medium', 'low'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const STATUSES = ['new', 'investigating', 'confirmed', 'false_positive', 'resolved'];

const UEBA = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  
  // Dashboard data
  const [stats, setStats] = useState(null);
  const [topRiskUsers, setTopRiskUsers] = useState([]);
  const [recentAnomalies, setRecentAnomalies] = useState([]);
  const [riskTrends, setRiskTrends] = useState([]);
  const [anomalyTypes, setAnomalyTypes] = useState([]);
  
  // Users
  const [users, setUsers] = useState([]);
  const [usersTotal, setUsersTotal] = useState(0);
  const [usersPage, setUsersPage] = useState(1);
  const [usersPerPage] = useState(12);
  const [userSearch, setUserSearch] = useState('');
  const [userRiskFilter, setUserRiskFilter] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [userDialogOpen, setUserDialogOpen] = useState(false);
  
  // Anomalies
  const [anomalies, setAnomalies] = useState([]);
  const [anomaliesTotal, setAnomaliesTotal] = useState(0);
  const [anomaliesPage, setAnomaliesPage] = useState(1);
  const [anomaliesPerPage] = useState(20);
  const [anomalySearch, setAnomalySearch] = useState('');
  const [anomalySeverityFilter, setAnomalySeverityFilter] = useState([]);
  const [anomalyStatusFilter, setAnomalyStatusFilter] = useState([]);
  const [selectedAnomaly, setSelectedAnomaly] = useState(null);
  const [anomalyDialogOpen, setAnomalyDialogOpen] = useState(false);
  
  // Peer Groups
  const [peerGroups, setPeerGroups] = useState([]);
  
  // Cleanup status
  const [cleaningUp, setCleaningUp] = useState(false);

  // Load dashboard data
  const loadDashboard = useCallback(async () => {
    try {
      const [dashboardRes, peerGroupsRes] = await Promise.all([
        uebaAPI.getDashboard(),
        uebaAPI.getPeerGroups(),
      ]);
      
      // Handle stats (convert snake_case to camelCase)
      const rawStats = dashboardRes.data.stats || dashboardRes.data;
      setStats({
        totalUsers: rawStats.total_users || rawStats.totalUsers || 0,
        monitoredUsers: rawStats.monitored_users || rawStats.monitoredUsers || 0,
        highRiskUsers: rawStats.high_risk_users || rawStats.highRiskUsers || 0,
        criticalRiskUsers: rawStats.critical_risk_users || rawStats.criticalRiskUsers || 0,
        anomaliesDetected: rawStats.anomalies_detected || rawStats.anomaliesDetected || 0,
        anomaliesLast24h: rawStats.anomalies_last_24h || rawStats.anomaliesLast24h || 0,
        avgRiskScore: rawStats.avg_risk_score || rawStats.avgRiskScore || 0,
        baselineCoverage: rawStats.baseline_coverage || rawStats.baselineCoverage || 0,
      });
      
      setTopRiskUsers(dashboardRes.data.top_risk_users || []);
      setRecentAnomalies(dashboardRes.data.recent_anomalies || []);
      setRiskTrends(dashboardRes.data.risk_trends || []);
      setAnomalyTypes(dashboardRes.data.anomaly_types || []);
      setPeerGroups(peerGroupsRes.data.peer_groups || []);
    } catch (err) {
      console.error('Error loading dashboard:', err);
      throw err;
    }
  }, []);

  // Load users with filters
  const loadUsers = useCallback(async () => {
    try {
      const params = {
        limit: usersPerPage,
        offset: (usersPage - 1) * usersPerPage,
      };
      
      if (userSearch) params.search = userSearch;
      if (userRiskFilter.length > 0) params.risk_levels = userRiskFilter;
      
      const response = await uebaAPI.getUsers(params);
      setUsers(response.data.users || []);
      setUsersTotal(response.data.total || 0);
    } catch (err) {
      console.error('Error loading users:', err);
    }
  }, [usersPage, usersPerPage, userSearch, userRiskFilter]);

  // Load anomalies with filters
  const loadAnomalies = useCallback(async () => {
    try {
      const params = {
        limit: anomaliesPerPage,
        offset: (anomaliesPage - 1) * anomaliesPerPage,
      };
      
      if (anomalySearch) params.search = anomalySearch;
      if (anomalySeverityFilter.length > 0) params.severities = anomalySeverityFilter;
      if (anomalyStatusFilter.length > 0) params.statuses = anomalyStatusFilter;
      
      const response = await uebaAPI.getAnomalies(params);
      setAnomalies(response.data.anomalies || []);
      setAnomaliesTotal(response.data.total || 0);
    } catch (err) {
      console.error('Error loading anomalies:', err);
    }
  }, [anomaliesPage, anomaliesPerPage, anomalySearch, anomalySeverityFilter, anomalyStatusFilter]);

  // Initial load
  useEffect(() => {
    const loadAll = async () => {
      try {
        setLoading(true);
        setError(null);
        await loadDashboard();
        await Promise.all([loadUsers(), loadAnomalies()]);
      } catch (err) {
        setError('Erro ao carregar dados de UEBA');
      } finally {
        setLoading(false);
      }
    };
    loadAll();
  }, [loadDashboard, loadUsers, loadAnomalies]);

  // Reload users when filters change
  useEffect(() => {
    if (!loading) {
      loadUsers();
    }
  }, [usersPage, userSearch, userRiskFilter, loadUsers, loading]);

  // Reload anomalies when filters change
  useEffect(() => {
    if (!loading) {
      loadAnomalies();
    }
  }, [anomaliesPage, anomalySearch, anomalySeverityFilter, anomalyStatusFilter, loadAnomalies, loading]);

  const handleRefresh = async () => {
    setLoading(true);
    try {
      await loadDashboard();
      await Promise.all([loadUsers(), loadAnomalies()]);
      setError(null);
    } catch (err) {
      setError('Erro ao atualizar dados');
    } finally {
      setLoading(false);
    }
  };

  const handleCleanup = async () => {
    if (!window.confirm('Isso irá remover perfis de contas de serviço e duplicatas. Continuar?')) {
      return;
    }
    
    setCleaningUp(true);
    try {
      await uebaAPI.cleanup();
      await handleRefresh();
    } catch (err) {
      console.error('Error cleaning up:', err);
      setError('Erro ao limpar perfis');
    } finally {
      setCleaningUp(false);
    }
  };

  const handleViewUser = async (userId) => {
    try {
      const response = await uebaAPI.getUserProfile(userId);
      setSelectedUser(response.data);
      setUserDialogOpen(true);
    } catch (err) {
      console.error('Error loading user profile:', err);
      setError('Erro ao carregar perfil do usuário');
    }
  };

  const handleViewAnomaly = (anomaly) => {
    setSelectedAnomaly(anomaly);
    setAnomalyDialogOpen(true);
  };

  const handleUpdateAnomaly = async (status) => {
    try {
      await uebaAPI.updateAnomaly(selectedAnomaly.id, { status });
      setAnomalyDialogOpen(false);
      await loadAnomalies();
      await loadDashboard();
    } catch (err) {
      console.error('Error updating anomaly:', err);
    }
  };

  const getRiskColor = (score) => {
    if (score >= 80) return 'error';
    if (score >= 60) return 'warning';
    if (score >= 40) return 'info';
    return 'success';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'error',
      high: 'warning',
      medium: 'info',
      low: 'success',
    };
    return colors[severity?.toLowerCase()] || 'default';
  };

  const getStatusColor = (status) => {
    const colors = {
      new: 'error',
      investigating: 'warning',
      confirmed: 'error',
      false_positive: 'default',
      resolved: 'success',
    };
    return colors[status] || 'default';
  };

  const formatRiskLevel = (level) => {
    const labels = {
      critical: 'Crítico',
      high: 'Alto',
      medium: 'Médio',
      low: 'Baixo',
    };
    return labels[level?.toLowerCase()] || level;
  };

  const formatAnomalyType = (type) => {
    const labels = {
      unusual_hours: 'Horário Incomum',
      high_severity_activity: 'Atividade de Alta Severidade',
      high_activity_volume: 'Volume Alto de Atividade',
      high_critical_volume: 'Volume Alto de Críticos',
      new_location: 'Nova Localização',
      new_device: 'Novo Dispositivo',
      failed_logins: 'Falhas de Login',
    };
    return labels[type] || type?.replace(/_/g, ' ') || type;
  };

  const COLORS = ['#f44336', '#ff9800', '#2196f3', '#4caf50', '#9c27b0', '#00bcd4'];

  if (loading && !stats) {
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
        <Box>
          <Typography variant="h4" gutterBottom>
            🤖 UEBA - User Behavior Analytics
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Análise comportamental e detecção de anomalias de usuários
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Remover contas de serviço e duplicatas">
            <Button
              variant="outlined"
              color="warning"
              startIcon={cleaningUp ? <CircularProgress size={16} /> : <CleanupIcon />}
              onClick={handleCleanup}
              disabled={cleaningUp}
            >
              Limpar
            </Button>
          </Tooltip>
          <Button
            variant="outlined"
            startIcon={loading ? <CircularProgress size={16} /> : <RefreshIcon />}
            onClick={handleRefresh}
            disabled={loading}
          >
            Atualizar
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* KPI Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <PersonIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Usuários Monitorados
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.monitoredUsers || 0}</Typography>
              <Typography variant="caption" color="text.secondary">
                total
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <ErrorIcon sx={{ mr: 1, color: 'error.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Usuários de Alto Risco
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.highRiskUsers || 0}</Typography>
              <Typography variant="caption" color="error">
                {stats?.criticalRiskUsers || 0} críticos
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <WarningIcon sx={{ mr: 1, color: 'warning.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Anomalias Detectadas
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.anomaliesDetected || 0}</Typography>
              <Typography variant="caption">
                últimas 24h
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <SecurityIcon sx={{ mr: 1, color: 'success.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Cobertura Baseline
                </Typography>
              </Box>
              <Typography variant="h4">{(stats?.baselineCoverage || 0).toFixed(1)}%</Typography>
              <Typography variant="caption" color="text.secondary">
                usuários
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Card>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="Overview" />
          <Tab label="Anomalias" />
          <Tab label="Usuários de Risco" />
          <Tab label="Timeline" />
        </Tabs>

        <CardContent>
          {/* Tab 0: Overview */}
          {tabValue === 0 && (
            <Box>
              <Grid container spacing={3}>
                {/* Risk Trends */}
                <Grid item xs={12} md={8}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Tendência de Risco (7 dias)
                      </Typography>
                      {riskTrends.length > 0 ? (
                        <ResponsiveContainer width="100%" height={300}>
                          <LineChart data={riskTrends}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="date" />
                            <YAxis />
                            <RechartsTooltip />
                            <Legend />
                            <Line type="monotone" dataKey="avg_risk" stroke="#f44336" name="Risco Médio" />
                            <Line type="monotone" dataKey="high_risk" stroke="#ff9800" name="Alto Risco" />
                          </LineChart>
                        </ResponsiveContainer>
                      ) : (
                        <Box sx={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <Typography color="text.secondary">Dados insuficientes para tendência</Typography>
                        </Box>
                      )}
                    </CardContent>
                  </Card>
                </Grid>

                {/* Anomaly Types */}
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Tipos de Anomalias
                      </Typography>
                      {anomalyTypes.length > 0 ? (
                        <ResponsiveContainer width="100%" height={300}>
                          <PieChart>
                            <Pie
                              data={anomalyTypes}
                              dataKey="count"
                              nameKey="type"
                              cx="50%"
                              cy="50%"
                              outerRadius={80}
                              label={({ type, count }) => `${count}`}
                            >
                              {anomalyTypes.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                              ))}
                            </Pie>
                            <RechartsTooltip formatter={(value, name) => [value, formatAnomalyType(name)]} />
                          </PieChart>
                        </ResponsiveContainer>
                      ) : (
                        <Box sx={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <Typography color="text.secondary">Nenhuma anomalia detectada</Typography>
                        </Box>
                      )}
                    </CardContent>
                  </Card>
                </Grid>

                {/* Top Risk Users */}
                <Grid item xs={12}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Top {topRiskUsers.length} Usuários de Risco
                      </Typography>
                      {topRiskUsers.length > 0 ? (
                        <TableContainer>
                          <Table>
                            <TableHead>
                              <TableRow>
                                <TableCell>Usuário</TableCell>
                                <TableCell>Departamento</TableCell>
                                <TableCell>Risk Score</TableCell>
                                <TableCell>Anomalias</TableCell>
                                <TableCell>Última Atividade</TableCell>
                                <TableCell>Ações</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {topRiskUsers.map((user, index) => (
                                <TableRow key={user.user_id || index}>
                                  <TableCell>
                                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                      <Avatar sx={{ mr: 1, width: 32, height: 32, bgcolor: getRiskColor(user.risk_score) + '.main' }}>
                                        {(user.username || 'U').charAt(0).toUpperCase()}
                                      </Avatar>
                                      <Box>
                                        <Typography variant="body2">{user.username || 'N/A'}</Typography>
                                        <Typography variant="caption" color="text.secondary">
                                          {user.email || ''}
                                        </Typography>
                                      </Box>
                                    </Box>
                                  </TableCell>
                                  <TableCell>{user.department || '-'}</TableCell>
                                  <TableCell>
                                    <Box>
                                      <Chip
                                        label={Math.round(user.risk_score || 0)}
                                        size="small"
                                        color={getRiskColor(user.risk_score)}
                                      />
                                      <LinearProgress
                                        variant="determinate"
                                        value={Math.min(user.risk_score || 0, 100)}
                                        color={getRiskColor(user.risk_score)}
                                        sx={{ mt: 1 }}
                                      />
                                    </Box>
                                  </TableCell>
                                  <TableCell>
                                    <Chip
                                      label={user.anomalies || user.anomaly_count || 0}
                                      size="small"
                                      color="warning"
                                    />
                                  </TableCell>
                                  <TableCell>
                                    <Typography variant="caption">
                                      {user.last_activity ? new Date(user.last_activity).toLocaleString('pt-BR') : 'Invalid Date'}
                                    </Typography>
                                  </TableCell>
                                  <TableCell>
                                    <Button
                                      size="small"
                                      onClick={() => handleViewUser(user.user_id || user.username)}
                                    >
                                      Ver Detalhes
                                    </Button>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      ) : (
                        <Typography color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                          Nenhum usuário de risco identificado
                        </Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Box>
          )}

          {/* Tab 1: Anomalias */}
          {tabValue === 1 && (
            <Box>
              {/* Filters */}
              <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
                <TextField
                  size="small"
                  placeholder="Buscar por usuário ou descrição..."
                  value={anomalySearch}
                  onChange={(e) => { setAnomalySearch(e.target.value); setAnomaliesPage(1); }}
                  InputProps={{
                    startAdornment: <InputAdornment position="start"><SearchIcon /></InputAdornment>,
                    endAdornment: anomalySearch && (
                      <InputAdornment position="end">
                        <IconButton size="small" onClick={() => setAnomalySearch('')}>
                          <ClearIcon />
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                  sx={{ minWidth: 250 }}
                />
                
                <FormControl size="small" sx={{ minWidth: 150 }}>
                  <InputLabel>Severidade</InputLabel>
                  <Select
                    multiple
                    value={anomalySeverityFilter}
                    onChange={(e) => { setAnomalySeverityFilter(e.target.value); setAnomaliesPage(1); }}
                    input={<OutlinedInput label="Severidade" />}
                    renderValue={(selected) => selected.map(s => formatRiskLevel(s)).join(', ')}
                  >
                    {SEVERITIES.map((sev) => (
                      <MenuItem key={sev} value={sev}>
                        <Checkbox checked={anomalySeverityFilter.includes(sev)} />
                        <ListItemText primary={formatRiskLevel(sev)} />
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                
                <FormControl size="small" sx={{ minWidth: 150 }}>
                  <InputLabel>Status</InputLabel>
                  <Select
                    multiple
                    value={anomalyStatusFilter}
                    onChange={(e) => { setAnomalyStatusFilter(e.target.value); setAnomaliesPage(1); }}
                    input={<OutlinedInput label="Status" />}
                    renderValue={(selected) => selected.join(', ')}
                  >
                    {STATUSES.map((status) => (
                      <MenuItem key={status} value={status}>
                        <Checkbox checked={anomalyStatusFilter.includes(status)} />
                        <ListItemText primary={status} />
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                
                {(anomalySearch || anomalySeverityFilter.length > 0 || anomalyStatusFilter.length > 0) && (
                  <Button
                    size="small"
                    startIcon={<ClearIcon />}
                    onClick={() => {
                      setAnomalySearch('');
                      setAnomalySeverityFilter([]);
                      setAnomalyStatusFilter([]);
                      setAnomaliesPage(1);
                    }}
                  >
                    Limpar Filtros
                  </Button>
                )}
              </Box>

              <Typography variant="h6" gutterBottom>
                Anomalias Detectadas ({anomaliesTotal} total)
              </Typography>
              
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Usuário</TableCell>
                      <TableCell>Tipo</TableCell>
                      <TableCell>Severidade</TableCell>
                      <TableCell>Score</TableCell>
                      <TableCell>Descrição</TableCell>
                      <TableCell>Detectada em</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Ações</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {anomalies.length > 0 ? anomalies.map((anomaly) => (
                      <TableRow key={anomaly.id}>
                        <TableCell>{anomaly.username}</TableCell>
                        <TableCell>
                          <Chip
                            label={formatAnomalyType(anomaly.anomaly_type || anomaly.type)}
                            size="small"
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={formatRiskLevel(anomaly.severity)}
                            size="small"
                            color={getSeverityColor(anomaly.severity)}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={Math.round(anomaly.score || 0)}
                            size="small"
                            color={getRiskColor(anomaly.score)}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
                            {anomaly.description}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {anomaly.detected_at ? new Date(anomaly.detected_at).toLocaleString('pt-BR') : '-'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={anomaly.status}
                            size="small"
                            color={getStatusColor(anomaly.status)}
                          />
                        </TableCell>
                        <TableCell>
                          <Button
                            size="small"
                            onClick={() => handleViewAnomaly(anomaly)}
                          >
                            Ver Detalhes
                          </Button>
                        </TableCell>
                      </TableRow>
                    )) : (
                      <TableRow>
                        <TableCell colSpan={8} align="center">
                          <Typography color="text.secondary" sx={{ py: 4 }}>
                            Nenhuma anomalia encontrada
                          </Typography>
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
              
              {anomaliesTotal > anomaliesPerPage && (
                <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
                  <Pagination
                    count={Math.ceil(anomaliesTotal / anomaliesPerPage)}
                    page={anomaliesPage}
                    onChange={(e, page) => setAnomaliesPage(page)}
                    color="primary"
                  />
                </Box>
              )}
            </Box>
          )}

          {/* Tab 2: Usuários de Risco */}
          {tabValue === 2 && (
            <Box>
              {/* Filters */}
              <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
                <TextField
                  size="small"
                  placeholder="Buscar por nome, email..."
                  value={userSearch}
                  onChange={(e) => { setUserSearch(e.target.value); setUsersPage(1); }}
                  InputProps={{
                    startAdornment: <InputAdornment position="start"><SearchIcon /></InputAdornment>,
                    endAdornment: userSearch && (
                      <InputAdornment position="end">
                        <IconButton size="small" onClick={() => setUserSearch('')}>
                          <ClearIcon />
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                  sx={{ minWidth: 250 }}
                />
                
                <FormControl size="small" sx={{ minWidth: 150 }}>
                  <InputLabel>Nível de Risco</InputLabel>
                  <Select
                    multiple
                    value={userRiskFilter}
                    onChange={(e) => { setUserRiskFilter(e.target.value); setUsersPage(1); }}
                    input={<OutlinedInput label="Nível de Risco" />}
                    renderValue={(selected) => selected.map(s => formatRiskLevel(s)).join(', ')}
                  >
                    {RISK_LEVELS.map((level) => (
                      <MenuItem key={level} value={level}>
                        <Checkbox checked={userRiskFilter.includes(level)} />
                        <ListItemText primary={formatRiskLevel(level)} />
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                
                {(userSearch || userRiskFilter.length > 0) && (
                  <Button
                    size="small"
                    startIcon={<ClearIcon />}
                    onClick={() => {
                      setUserSearch('');
                      setUserRiskFilter([]);
                      setUsersPage(1);
                    }}
                  >
                    Limpar Filtros
                  </Button>
                )}
              </Box>

              <Typography variant="h6" gutterBottom>
                Todos os Usuários Monitorados ({usersTotal} total)
              </Typography>
              
              <Grid container spacing={2}>
                {users.length > 0 ? users.map((user) => (
                  <Grid item xs={12} sm={6} md={4} key={user.id || user.user_id}>
                    <Card
                      variant="outlined"
                      sx={{
                        borderLeft: 4,
                        borderLeftColor: user.risk_level === 'critical' ? 'error.main' : 
                                        user.risk_level === 'high' ? 'warning.main' : 
                                        user.risk_level === 'medium' ? 'info.main' : 'success.main'
                      }}
                    >
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                          <Avatar sx={{ mr: 2, bgcolor: getRiskColor(user.risk_score) + '.main' }}>
                            {(user.username || 'U').charAt(0).toUpperCase()}
                          </Avatar>
                          <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                            <Typography variant="subtitle1" noWrap>{user.username}</Typography>
                            <Typography variant="caption" color="text.secondary" noWrap>
                              {user.department || user.email || '-'}
                            </Typography>
                          </Box>
                          <Chip
                            label={formatRiskLevel(user.risk_level)}
                            size="small"
                            color={getRiskColor(user.risk_score)}
                          />
                        </Box>
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="body2" gutterBottom>
                            Risk Score: {Math.round(user.risk_score || 0)}
                          </Typography>
                          <LinearProgress
                            variant="determinate"
                            value={Math.min(user.risk_score || 0, 100)}
                            color={getRiskColor(user.risk_score)}
                          />
                        </Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="caption">Anomalias:</Typography>
                          <Typography variant="caption" fontWeight="bold">
                            {user.anomaly_count || 0}
                          </Typography>
                        </Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                          <Typography variant="caption">Atividades:</Typography>
                          <Typography variant="caption" fontWeight="bold">
                            {user.total_activities || 0}
                          </Typography>
                        </Box>
                        <Button
                          fullWidth
                          size="small"
                          variant="outlined"
                          onClick={() => handleViewUser(user.id || user.user_id || user.username)}
                        >
                          Ver Perfil Completo
                        </Button>
                      </CardContent>
                    </Card>
                  </Grid>
                )) : (
                  <Grid item xs={12}>
                    <Typography color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                      Nenhum usuário encontrado
                    </Typography>
                  </Grid>
                )}
              </Grid>
              
              {usersTotal > usersPerPage && (
                <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
                  <Pagination
                    count={Math.ceil(usersTotal / usersPerPage)}
                    page={usersPage}
                    onChange={(e, page) => setUsersPage(page)}
                    color="primary"
                  />
                </Box>
              )}
            </Box>
          )}

          {/* Tab 3: Timeline */}
          {tabValue === 3 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Peer Groups
              </Typography>
              {peerGroups.length > 0 ? (
                <Grid container spacing={2}>
                  {peerGroups.map((group) => (
                    <Grid item xs={12} md={6} key={group.id}>
                      <Card variant="outlined">
                        <CardContent>
                          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                            <GroupIcon sx={{ mr: 1, color: 'primary.main' }} />
                            <Typography variant="h6">{group.name}</Typography>
                          </Box>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            {group.description}
                          </Typography>
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 2 }}>
                            <Box>
                              <Typography variant="caption" color="text.secondary">
                                Membros
                              </Typography>
                              <Typography variant="h6">{group.user_count || 0}</Typography>
                            </Box>
                            <Box>
                              <Typography variant="caption" color="text.secondary">
                                Risco Médio
                              </Typography>
                              <Typography variant="h6" color={(group.avg_risk || 0) > 50 ? 'error' : 'success.main'}>
                                {(group.avg_risk || 0).toFixed(1)}
                              </Typography>
                            </Box>
                          </Box>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              ) : (
                <Typography color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                  Nenhum peer group configurado
                </Typography>
              )}
            </Box>
          )}
        </CardContent>
      </Card>

      {/* User Detail Dialog */}
      <Dialog open={userDialogOpen} onClose={() => setUserDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Perfil do Usuário: {selectedUser?.profile?.username || 'N/A'}
        </DialogTitle>
        <DialogContent>
          {selectedUser && (
            <Box>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Informações Básicas</Typography>
                  <Typography variant="body2">Email: {selectedUser.profile?.email || '-'}</Typography>
                  <Typography variant="body2">Departamento: {selectedUser.profile?.department || '-'}</Typography>
                  <Typography variant="body2">Peer Group: {selectedUser.profile?.peer_group || '-'}</Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Risk Assessment</Typography>
                  <Typography variant="body2">Risk Score: {selectedUser.profile?.risk_score || 0}</Typography>
                  <Typography variant="body2">Risk Level: {formatRiskLevel(selectedUser.profile?.risk_level)}</Typography>
                  <Typography variant="body2">Anomalias: {selectedUser.profile?.anomaly_count || 0}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>Baseline Comportamental</Typography>
                  <Typography variant="body2">Hora média de login: {selectedUser.profile?.baseline?.avg_login_hour?.toFixed(1) || '-'}h</Typography>
                  <Typography variant="body2">Locais comuns: {selectedUser.profile?.baseline?.common_locations?.join(', ') || '-'}</Typography>
                  <Typography variant="body2">Dispositivos: {selectedUser.profile?.baseline?.common_devices?.join(', ') || '-'}</Typography>
                </Grid>
                
                {selectedUser.activities && selectedUser.activities.length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>Atividades Recentes</Typography>
                    <TableContainer sx={{ maxHeight: 300 }}>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Data</TableCell>
                            <TableCell>Tipo</TableCell>
                            <TableCell>Fonte</TableCell>
                            <TableCell>Risco</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {selectedUser.activities.slice(0, 20).map((activity, idx) => (
                            <TableRow key={idx}>
                              <TableCell>
                                <Typography variant="caption">
                                  {activity.timestamp ? new Date(activity.timestamp).toLocaleString('pt-BR') : '-'}
                                </Typography>
                              </TableCell>
                              <TableCell>{activity.activity_type || activity.type || '-'}</TableCell>
                              <TableCell>{activity.source || '-'}</TableCell>
                              <TableCell>
                                <Chip
                                  label={activity.risk_score || 0}
                                  size="small"
                                  color={getRiskColor(activity.risk_score)}
                                />
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Grid>
                )}
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setUserDialogOpen(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>

      {/* Anomaly Detail Dialog */}
      <Dialog open={anomalyDialogOpen} onClose={() => setAnomalyDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Detalhes da Anomalia
        </DialogTitle>
        <DialogContent>
          {selectedAnomaly && (
            <Box>
              <Typography variant="body1" gutterBottom><strong>Usuário:</strong> {selectedAnomaly.username}</Typography>
              <Typography variant="body1" gutterBottom><strong>Tipo:</strong> {formatAnomalyType(selectedAnomaly.anomaly_type || selectedAnomaly.type)}</Typography>
              <Typography variant="body1" gutterBottom><strong>Severidade:</strong> {formatRiskLevel(selectedAnomaly.severity)}</Typography>
              <Typography variant="body1" gutterBottom><strong>Score:</strong> {Math.round(selectedAnomaly.score || 0)}</Typography>
              <Typography variant="body1" gutterBottom><strong>Descrição:</strong> {selectedAnomaly.description}</Typography>
              <Typography variant="body1" gutterBottom><strong>Detectada em:</strong> {selectedAnomaly.detected_at ? new Date(selectedAnomaly.detected_at).toLocaleString('pt-BR') : '-'}</Typography>
              <Typography variant="body1" gutterBottom><strong>Status Atual:</strong> {selectedAnomaly.status}</Typography>
              
              {selectedAnomaly.expected_value && (
                <Typography variant="body1" gutterBottom><strong>Valor Esperado:</strong> {selectedAnomaly.expected_value}</Typography>
              )}
              {selectedAnomaly.actual_value && (
                <Typography variant="body1" gutterBottom><strong>Valor Atual:</strong> {selectedAnomaly.actual_value}</Typography>
              )}
              {selectedAnomaly.mitre_technique && (
                <Typography variant="body1" gutterBottom><strong>MITRE ATT&CK:</strong> {selectedAnomaly.mitre_technique}</Typography>
              )}
              
              <Box sx={{ mt: 3 }}>
                <Typography variant="subtitle2" gutterBottom>Atualizar Status:</Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => handleUpdateAnomaly('investigating')}
                    disabled={selectedAnomaly.status === 'investigating'}
                  >
                    Investigando
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    color="error"
                    onClick={() => handleUpdateAnomaly('confirmed')}
                    disabled={selectedAnomaly.status === 'confirmed'}
                  >
                    Confirmar
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    color="success"
                    onClick={() => handleUpdateAnomaly('resolved')}
                    disabled={selectedAnomaly.status === 'resolved'}
                  >
                    Resolvido
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => handleUpdateAnomaly('false_positive')}
                    disabled={selectedAnomaly.status === 'false_positive'}
                  >
                    Falso Positivo
                  </Button>
                </Box>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAnomalyDialogOpen(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default UEBA;
