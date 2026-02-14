import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Button,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Tooltip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  LinearProgress,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Shield as ShieldIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  ContentCopy as ContentCopyIcon,
  Visibility as VisibilityIcon,
  CloudUpload as CloudUploadIcon,
  Router as RouterIcon,
  Timeline as TimelineIcon,
  TrendingUp as TrendingUpIcon,
  Block as BlockIcon,
  BugReport as BugReportIcon,
  Speed as SpeedIcon,
  Storage as StorageIcon,
} from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';

const API_BASE = process.env.REACT_APP_API_URL || '';

// Tab Panel Component
function TabPanel({ children, value, index, ...other }) {
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

// Severity colors
const getSeverityColor = (severity) => {
  const colors = {
    critical: '#f44336',
    high: '#ff9800',
    medium: '#ffeb3b',
    low: '#4caf50',
    info: '#2196f3',
  };
  return colors[severity?.toLowerCase()] || colors.info;
};

// Action colors
const getActionColor = (action) => {
  const colors = {
    allow: 'success',
    pass: 'success',
    deny: 'error',
    block: 'error',
    drop: 'error',
    reject: 'warning',
  };
  return colors[action?.toLowerCase()] || 'default';
};

const FortinetIntegration = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [dashboard, setDashboard] = useState(null);
  const [configs, setConfigs] = useState([]);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [error, setError] = useState('');
  
  // Dialog states
  const [configDialog, setConfigDialog] = useState(false);
  const [editingConfig, setEditingConfig] = useState(null);
  const [eventDetailsDialog, setEventDetailsDialog] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  
  // Filters
  const [eventFilters, setEventFilters] = useState({
    type: '',
    severity: '',
    action: '',
    limit: 100,
  });

  // New config form
  const [newConfig, setNewConfig] = useState({
    name: '',
    device_ip: '',
    device_name: '',
    vdom: 'root',
    api_key: '',
    enabled: true,
    log_types: ['traffic', 'utm', 'ips', 'virus', 'webfilter', 'event', 'anomaly'],
  });

  // Fetch dashboard data
  const fetchDashboard = useCallback(async () => {
    try {
      const token = sessionStorage.getItem('access_token') || localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/v1/fortinet/dashboard`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.ok) {
        const data = await response.json();
        setDashboard(data);
      }
    } catch (err) {
      console.error('Error fetching dashboard:', err);
    }
  }, []);

  // Fetch configurations
  const fetchConfigs = useCallback(async () => {
    try {
      const token = sessionStorage.getItem('access_token') || localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/v1/fortinet/configs`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.ok) {
        const data = await response.json();
        setConfigs(data.configs || []);
      }
    } catch (err) {
      console.error('Error fetching configs:', err);
    }
  }, []);

  // Fetch events
  const fetchEvents = useCallback(async () => {
    try {
      const token = sessionStorage.getItem('access_token') || localStorage.getItem('access_token');
      const params = new URLSearchParams();
      if (eventFilters.type) params.append('type', eventFilters.type);
      if (eventFilters.severity) params.append('severity', eventFilters.severity);
      if (eventFilters.action) params.append('action', eventFilters.action);
      params.append('limit', eventFilters.limit);
      
      const response = await fetch(`${API_BASE}/api/v1/fortinet/events?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.ok) {
        const data = await response.json();
        setEvents(data.events || []);
      }
    } catch (err) {
      console.error('Error fetching events:', err);
    }
  }, [eventFilters]);

  // Fetch alerts
  const fetchAlerts = useCallback(async () => {
    try {
      const token = sessionStorage.getItem('access_token') || localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/v1/fortinet/alerts?status=new&limit=50`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.ok) {
        const data = await response.json();
        setAlerts(data.alerts || []);
      }
    } catch (err) {
      console.error('Error fetching alerts:', err);
    }
  }, []);

  // Fetch statistics
  const fetchStats = useCallback(async () => {
    try {
      const token = sessionStorage.getItem('access_token') || localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/v1/fortinet/stats`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Error fetching stats:', err);
    }
  }, []);

  // Initial data load
  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([
        fetchDashboard(),
        fetchConfigs(),
        fetchEvents(),
        fetchAlerts(),
        fetchStats(),
      ]);
      setLoading(false);
    };
    loadData();
  }, [fetchDashboard, fetchConfigs, fetchEvents, fetchAlerts, fetchStats]);

  // Refresh data periodically
  useEffect(() => {
    const interval = setInterval(() => {
      if (activeTab === 0) {
        fetchDashboard();
        fetchStats();
      } else if (activeTab === 1) {
        fetchEvents();
      } else if (activeTab === 2) {
        fetchAlerts();
      }
    }, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, [activeTab, fetchDashboard, fetchStats, fetchEvents, fetchAlerts]);

  // Create configuration
  const handleCreateConfig = async () => {
    try {
      const token = sessionStorage.getItem('access_token') || localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/v1/fortinet/configs`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newConfig),
      });

      if (response.ok) {
        const data = await response.json();
        setConfigs([...configs, data.config]);
        setConfigDialog(false);
        setNewConfig({
          name: '',
          device_ip: '',
          device_name: '',
          vdom: 'root',
          api_key: '',
          enabled: true,
          log_types: ['traffic', 'utm', 'ips', 'virus', 'webfilter', 'event', 'anomaly'],
        });
        // Show webhook URL
        alert(`Webhook criado!\n\nURL do Webhook:\n${window.location.origin}${API_BASE}${data.webhook_url}`);
      } else {
        const err = await response.json();
        setError(err.error || 'Erro ao criar configuração');
      }
    } catch (err) {
      setError('Erro ao criar configuração');
    }
  };

  // Delete configuration
  const handleDeleteConfig = async (id) => {
    if (!window.confirm('Tem certeza que deseja excluir esta configuração?')) return;
    
    try {
      const token = sessionStorage.getItem('access_token') || localStorage.getItem('access_token');
      const response = await fetch(`${API_BASE}/api/v1/fortinet/configs/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });

      if (response.ok) {
        setConfigs(configs.filter(c => c.id !== id));
      }
    } catch (err) {
      setError('Erro ao excluir configuração');
    }
  };

  // Copy webhook URL
  const copyWebhookUrl = (configId) => {
    const url = `${window.location.origin}${API_BASE}/api/v1/fortinet/webhook?config_id=${configId}`;
    navigator.clipboard.writeText(url);
    alert('URL do webhook copiada para a área de transferência!');
  };

  // Format number
  const formatNumber = (num) => {
    if (!num) return '0';
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
  };

  // Format bytes
  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Pie chart colors
  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D'];

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
          <ShieldIcon sx={{ fontSize: 40, color: 'primary.main' }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Fortinet Integration
            </Typography>
            <Typography variant="body2" color="text.secondary">
              FortiGate Firewall Logs & Security Events
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            startIcon={<RefreshIcon />}
            onClick={() => {
              fetchDashboard();
              fetchConfigs();
              fetchEvents();
              fetchAlerts();
              fetchStats();
            }}
          >
            Atualizar
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setConfigDialog(true)}
          >
            Nova Configuração
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab icon={<TrendingUpIcon />} label="Dashboard" />
          <Tab icon={<StorageIcon />} label="Eventos" />
          <Tab icon={<WarningIcon />} label="Alertas" />
          <Tab icon={<RouterIcon />} label="Configurações" />
        </Tabs>
      </Paper>

      {/* Dashboard Tab */}
      <TabPanel value={activeTab} index={0}>
        {dashboard && (
          <Grid container spacing={3}>
            {/* Summary Cards */}
            <Grid item xs={12} md={3}>
              <Card sx={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <StorageIcon />
                    <Typography variant="body2">Total de Eventos</Typography>
                  </Box>
                  <Typography variant="h3" fontWeight="bold">
                    {formatNumber(dashboard.summary?.total_events)}
                  </Typography>
                  <Typography variant="caption">
                    Últimas 24h: {formatNumber(dashboard.summary?.events_24h)}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={3}>
              <Card sx={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)', color: 'white' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <WarningIcon />
                    <Typography variant="body2">Alertas Novos</Typography>
                  </Box>
                  <Typography variant="h3" fontWeight="bold">
                    {formatNumber(dashboard.summary?.new_alerts)}
                  </Typography>
                  <Typography variant="caption">
                    Ameaças: {formatNumber(dashboard.summary?.threat_detections)}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={3}>
              <Card sx={{ background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)', color: 'white' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <BugReportIcon />
                    <Typography variant="body2">IOC Matches</Typography>
                  </Box>
                  <Typography variant="h3" fontWeight="bold">
                    {formatNumber(dashboard.summary?.ioc_matches_24h)}
                  </Typography>
                  <Typography variant="caption">
                    Nas últimas 24h
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={3}>
              <Card sx={{ background: 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)', color: 'white' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <RouterIcon />
                    <Typography variant="body2">Dispositivos Ativos</Typography>
                  </Box>
                  <Typography variant="h3" fontWeight="bold">
                    {dashboard.summary?.active_devices || 0}
                  </Typography>
                  <Typography variant="caption">
                    FortiGate conectados
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            {/* Charts */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Eventos por Tipo
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={Object.entries(dashboard.events_by_type || {}).map(([name, value]) => ({ name, value }))}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {Object.entries(dashboard.events_by_type || {}).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Eventos por Ação
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={Object.entries(dashboard.events_by_action || {}).map(([name, value]) => ({ name, value }))}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="value" fill="#8884d8" />
                  </BarChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* Top IPs */}
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Top Source IPs
                </Typography>
                <List dense>
                  {(dashboard.top_source_ips || []).slice(0, 5).map((ip, idx) => (
                    <ListItem key={idx}>
                      <ListItemText 
                        primary={ip.ip} 
                        secondary={`${formatNumber(ip.count)} eventos`} 
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Top Destination IPs
                </Typography>
                <List dense>
                  {(dashboard.top_dest_ips || []).slice(0, 5).map((ip, idx) => (
                    <ListItem key={idx}>
                      <ListItemText 
                        primary={ip.ip} 
                        secondary={`${formatNumber(ip.count)} eventos`} 
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Top Applications
                </Typography>
                <List dense>
                  {(dashboard.top_applications || []).slice(0, 5).map((app, idx) => (
                    <ListItem key={idx}>
                      <ListItemText 
                        primary={app.name || 'Unknown'} 
                        secondary={`${formatNumber(app.count)} eventos`} 
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>
        )}
      </TabPanel>

      {/* Events Tab */}
      <TabPanel value={activeTab} index={1}>
        <Paper sx={{ p: 2, mb: 2 }}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Tipo de Log</InputLabel>
                <Select
                  value={eventFilters.type}
                  label="Tipo de Log"
                  onChange={(e) => setEventFilters({ ...eventFilters, type: e.target.value })}
                >
                  <MenuItem value="">Todos</MenuItem>
                  <MenuItem value="traffic">Traffic</MenuItem>
                  <MenuItem value="utm">UTM</MenuItem>
                  <MenuItem value="ips">IPS</MenuItem>
                  <MenuItem value="virus">Virus</MenuItem>
                  <MenuItem value="webfilter">Web Filter</MenuItem>
                  <MenuItem value="app-ctrl">App Control</MenuItem>
                  <MenuItem value="anomaly">Anomaly</MenuItem>
                  <MenuItem value="event">Event</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Severidade</InputLabel>
                <Select
                  value={eventFilters.severity}
                  label="Severidade"
                  onChange={(e) => setEventFilters({ ...eventFilters, severity: e.target.value })}
                >
                  <MenuItem value="">Todas</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                  <MenuItem value="info">Info</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Ação</InputLabel>
                <Select
                  value={eventFilters.action}
                  label="Ação"
                  onChange={(e) => setEventFilters({ ...eventFilters, action: e.target.value })}
                >
                  <MenuItem value="">Todas</MenuItem>
                  <MenuItem value="allow">Allow</MenuItem>
                  <MenuItem value="deny">Deny</MenuItem>
                  <MenuItem value="block">Block</MenuItem>
                  <MenuItem value="drop">Drop</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={3}>
              <Button
                variant="contained"
                onClick={fetchEvents}
                fullWidth
              >
                Filtrar
              </Button>
            </Grid>
          </Grid>
        </Paper>

        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Timestamp</TableCell>
                <TableCell>Tipo</TableCell>
                <TableCell>Source</TableCell>
                <TableCell>Destination</TableCell>
                <TableCell>Action</TableCell>
                <TableCell>Application</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>IOC</TableCell>
                <TableCell>Ações</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {events.map((event) => (
                <TableRow 
                  key={event.id}
                  sx={{ 
                    backgroundColor: event.ioc_match ? 'rgba(244, 67, 54, 0.1)' : 'inherit',
                    '&:hover': { backgroundColor: 'action.hover' }
                  }}
                >
                  <TableCell>
                    {new Date(event.timestamp).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <Chip label={event.log_type} size="small" variant="outlined" />
                  </TableCell>
                  <TableCell>
                    {event.src_ip}
                    {event.src_port > 0 && `:${event.src_port}`}
                  </TableCell>
                  <TableCell>
                    {event.dst_ip}
                    {event.dst_port > 0 && `:${event.dst_port}`}
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={event.action || 'N/A'} 
                      size="small" 
                      color={getActionColor(event.action)}
                    />
                  </TableCell>
                  <TableCell>{event.application || '-'}</TableCell>
                  <TableCell>
                    <Chip 
                      label={event.severity || 'info'} 
                      size="small"
                      sx={{ 
                        backgroundColor: getSeverityColor(event.severity),
                        color: 'white'
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    {event.ioc_match && (
                      <Chip 
                        icon={<WarningIcon />}
                        label="IOC Match" 
                        size="small" 
                        color="error"
                      />
                    )}
                  </TableCell>
                  <TableCell>
                    <IconButton 
                      size="small"
                      onClick={() => {
                        setSelectedEvent(event);
                        setEventDetailsDialog(true);
                      }}
                    >
                      <VisibilityIcon fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* Alerts Tab */}
      <TabPanel value={activeTab} index={2}>
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Timestamp</TableCell>
                <TableCell>Título</TableCell>
                <TableCell>Tipo</TableCell>
                <TableCell>Source IP</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>IOC</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {alerts.map((alert) => (
                <TableRow key={alert.id}>
                  <TableCell>
                    {new Date(alert.timestamp).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontWeight="bold">
                      {alert.title}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {alert.description}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip label={alert.log_type} size="small" variant="outlined" />
                  </TableCell>
                  <TableCell>{alert.src_ip}</TableCell>
                  <TableCell>
                    <Chip 
                      label={alert.severity} 
                      size="small"
                      sx={{ 
                        backgroundColor: getSeverityColor(alert.severity),
                        color: 'white'
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={alert.status} 
                      size="small"
                      color={alert.status === 'new' ? 'warning' : 'default'}
                    />
                  </TableCell>
                  <TableCell>
                    {alert.ioc_match && (
                      <Chip 
                        icon={<ErrorIcon />}
                        label={alert.ioc_type} 
                        size="small" 
                        color="error"
                      />
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* Configurations Tab */}
      <TabPanel value={activeTab} index={3}>
        <Grid container spacing={3}>
          {/* Webhook URL Info */}
          <Grid item xs={12}>
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="subtitle2" fontWeight="bold">
                Como configurar o FortiGate para enviar logs:
              </Typography>
              <Typography variant="body2">
                1. Configure o FortiGate para enviar logs via HTTP POST<br />
                2. Use a URL do webhook abaixo<br />
                3. Adicione o header X-API-Key com a chave configurada<br />
                4. Formato suportado: JSON ou Syslog key=value
              </Typography>
            </Alert>
          </Grid>

          {/* Configurations List */}
          {configs.map((config) => (
            <Grid item xs={12} md={6} key={config.id}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <Box>
                      <Typography variant="h6">
                        {config.name}
                      </Typography>
                      <Chip 
                        label={config.enabled ? 'Ativo' : 'Inativo'} 
                        size="small"
                        color={config.enabled ? 'success' : 'default'}
                        sx={{ mt: 1 }}
                      />
                    </Box>
                    <Box>
                      <Tooltip title="Copiar URL do Webhook">
                        <IconButton onClick={() => copyWebhookUrl(config.id)}>
                          <ContentCopyIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Excluir">
                        <IconButton 
                          color="error"
                          onClick={() => handleDeleteConfig(config.id)}
                          disabled={config.id === 'default'}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Box>
                  
                  <Divider sx={{ my: 2 }} />
                  
                  <Grid container spacing={1}>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">Device IP</Typography>
                      <Typography variant="body2">{config.device_ip || 'Qualquer'}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">Device Name</Typography>
                      <Typography variant="body2">{config.device_name || 'N/A'}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">VDOM</Typography>
                      <Typography variant="body2">{config.vdom || 'root'}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">Eventos Recebidos</Typography>
                      <Typography variant="body2">{formatNumber(config.event_count)}</Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="caption" color="text.secondary">Último Evento</Typography>
                      <Typography variant="body2">
                        {config.last_event_at ? new Date(config.last_event_at).toLocaleString() : 'Nenhum'}
                      </Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="caption" color="text.secondary">Tipos de Log</Typography>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                        {(config.log_types || []).map((type) => (
                          <Chip key={type} label={type} size="small" variant="outlined" />
                        ))}
                      </Box>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* New Configuration Dialog */}
      <Dialog open={configDialog} onClose={() => setConfigDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Nova Configuração de Webhook</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Nome da Configuração"
                value={newConfig.name}
                onChange={(e) => setNewConfig({ ...newConfig, name: e.target.value })}
                placeholder="Ex: FortiGate 100F - Matriz"
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="Device IP"
                value={newConfig.device_ip}
                onChange={(e) => setNewConfig({ ...newConfig, device_ip: e.target.value })}
                placeholder="Ex: 192.168.1.1"
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="Device Name"
                value={newConfig.device_name}
                onChange={(e) => setNewConfig({ ...newConfig, device_name: e.target.value })}
                placeholder="Ex: FGT-MATRIZ"
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="VDOM"
                value={newConfig.vdom}
                onChange={(e) => setNewConfig({ ...newConfig, vdom: e.target.value })}
                placeholder="root"
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="API Key (Opcional)"
                type="password"
                value={newConfig.api_key}
                onChange={(e) => setNewConfig({ ...newConfig, api_key: e.target.value })}
                helperText="Para autenticação do webhook"
              />
            </Grid>
            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Switch
                    checked={newConfig.enabled}
                    onChange={(e) => setNewConfig({ ...newConfig, enabled: e.target.checked })}
                  />
                }
                label="Habilitado"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigDialog(false)}>Cancelar</Button>
          <Button 
            variant="contained" 
            onClick={handleCreateConfig}
            disabled={!newConfig.name}
          >
            Criar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Event Details Dialog */}
      <Dialog open={eventDetailsDialog} onClose={() => setEventDetailsDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Detalhes do Evento</DialogTitle>
        <DialogContent>
          {selectedEvent && (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Timestamp</Typography>
                  <Typography>{new Date(selectedEvent.timestamp).toLocaleString()}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Log Type</Typography>
                  <Typography>{selectedEvent.log_type} / {selectedEvent.sub_type}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Source</Typography>
                  <Typography>{selectedEvent.src_ip}:{selectedEvent.src_port}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Destination</Typography>
                  <Typography>{selectedEvent.dst_ip}:{selectedEvent.dst_port}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Protocol / Service</Typography>
                  <Typography>{selectedEvent.protocol} / {selectedEvent.service}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Application</Typography>
                  <Typography>{selectedEvent.application || 'N/A'}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Action</Typography>
                  <Chip label={selectedEvent.action} color={getActionColor(selectedEvent.action)} />
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Policy</Typography>
                  <Typography>{selectedEvent.policy} (ID: {selectedEvent.policy_id})</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Bytes Sent/Received</Typography>
                  <Typography>{formatBytes(selectedEvent.sent_bytes)} / {formatBytes(selectedEvent.received_bytes)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Duration</Typography>
                  <Typography>{selectedEvent.duration}s</Typography>
                </Grid>
                {selectedEvent.attack_name && (
                  <>
                    <Grid item xs={12}>
                      <Divider sx={{ my: 1 }} />
                      <Typography variant="subtitle2" color="error">Threat Information</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">Attack Name</Typography>
                      <Typography color="error">{selectedEvent.attack_name}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">Threat Score</Typography>
                      <Typography>{selectedEvent.threat_score}</Typography>
                    </Grid>
                  </>
                )}
                {selectedEvent.mitre_tactic && (
                  <>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">MITRE Tactic</Typography>
                      <Typography>{selectedEvent.mitre_tactic}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">MITRE Technique</Typography>
                      <Typography>{selectedEvent.mitre_technique}</Typography>
                    </Grid>
                  </>
                )}
                {selectedEvent.ioc_match && (
                  <Grid item xs={12}>
                    <Alert severity="error">
                      IOC Match Detected: {selectedEvent.ioc_type} from {selectedEvent.ioc_feed}
                    </Alert>
                  </Grid>
                )}
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Message</Typography>
                  <Typography>{selectedEvent.message || selectedEvent.event_message || 'N/A'}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Tags</Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                    {(selectedEvent.tags || []).map((tag) => (
                      <Chip key={tag} label={tag} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEventDetailsDialog(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default FortinetIntegration;

