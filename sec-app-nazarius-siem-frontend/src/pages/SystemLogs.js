import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Tooltip,
  Alert,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Collapse,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Switch,
  FormControlLabel,
  Divider,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Search as SearchIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  CheckCircle as HealthyIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Storage as DatabaseIcon,
  Cloud as CloudIcon,
  Memory as MemoryIcon,
  Schedule as UptimeIcon,
  Settings as ConfigIcon,
  BugReport as DebugIcon,
} from '@mui/icons-material';
import { systemLogsAPI } from '../services/api';

const LEVEL_COLORS = {
  INFO: { bg: '#e3f2fd', color: '#1565c0', icon: <InfoIcon fontSize="small" /> },
  WARN: { bg: '#fff3e0', color: '#ef6c00', icon: <WarningIcon fontSize="small" /> },
  ERROR: { bg: '#ffebee', color: '#c62828', icon: <ErrorIcon fontSize="small" /> },
  DEBUG: { bg: '#f3e5f5', color: '#7b1fa2', icon: <DebugIcon fontSize="small" /> },
};

const STATUS_COLORS = {
  healthy: { color: 'success', icon: <HealthyIcon /> },
  degraded: { color: 'warning', icon: <WarningIcon /> },
  unhealthy: { color: 'error', icon: <ErrorIcon /> },
  enabled: { color: 'success', icon: <HealthyIcon /> },
  disabled: { color: 'default', icon: <WarningIcon /> },
};

const SystemLogs = () => {
  const [loading, setLoading] = useState(true);
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState(null);
  const [config, setConfig] = useState(null);
  const [filters, setFilters] = useState({ levels: [], sources: [] });
  const [selectedLevel, setSelectedLevel] = useState('');
  const [selectedSource, setSelectedSource] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [expandedLog, setExpandedLog] = useState(null);
  const [configDialogOpen, setConfigDialogOpen] = useState(false);
  const [error, setError] = useState(null);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const [logsRes, statusRes] = await Promise.all([
        systemLogsAPI.getLogs({
          level: selectedLevel,
          source: selectedSource,
          search: searchQuery,
          limit: 200,
        }),
        systemLogsAPI.getStatus(),
      ]);

      setLogs(logsRes.data.logs || []);
      setFilters(logsRes.data.filters || { levels: [], sources: [] });
      setStatus(statusRes.data.data || null);
    } catch (err) {
      console.error('Error loading system logs:', err);
      setError('Erro ao carregar logs do sistema. Verifique se você tem permissão de administrador.');
    } finally {
      setLoading(false);
    }
  }, [selectedLevel, selectedSource, searchQuery]);

  const loadConfig = async () => {
    try {
      const res = await systemLogsAPI.getConfig();
      setConfig(res.data.config || null);
      setConfigDialogOpen(true);
    } catch (err) {
      console.error('Error loading config:', err);
      setError('Erro ao carregar configuração');
    }
  };

  const handleClearLogs = async () => {
    if (!window.confirm('Tem certeza que deseja limpar todos os logs?')) return;
    
    try {
      await systemLogsAPI.clearLogs();
      loadData();
    } catch (err) {
      console.error('Error clearing logs:', err);
      setError('Erro ao limpar logs');
    }
  };

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, loadData]);

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  const renderStatusCard = (title, component, icon) => {
    if (!component) return null;
    const statusConfig = STATUS_COLORS[component.status] || STATUS_COLORS.disabled;
    
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
            {icon}
            <Typography variant="subtitle2" color="text.secondary">
              {title}
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Chip
              icon={statusConfig.icon}
              label={component.status?.toUpperCase()}
              color={statusConfig.color}
              size="small"
            />
          </Box>
          <Typography variant="body2" sx={{ mt: 1, color: 'text.secondary' }}>
            {component.message || component.host || component.url || '-'}
          </Typography>
          {component.tls && (
            <Chip label="TLS" size="small" color="info" sx={{ mt: 1 }} />
          )}
        </CardContent>
      </Card>
    );
  };

  if (loading && logs.length === 0) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          🔧 System Logs & Diagnostics
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <FormControlLabel
            control={
              <Switch
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                color="primary"
              />
            }
            label="Auto-refresh (5s)"
          />
          <Tooltip title="Ver Configuração">
            <IconButton onClick={loadConfig} color="primary">
              <ConfigIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Atualizar">
            <IconButton onClick={loadData} color="primary">
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* System Status Cards */}
      {status && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            Status do Sistema
          </Typography>
          <Grid container spacing={2}>
            {/* Overall Status */}
            <Grid item xs={12} sm={6} md={3}>
              <Card sx={{ 
                height: '100%',
                background: status.status === 'healthy' 
                  ? 'linear-gradient(135deg, #4caf50 0%, #2e7d32 100%)'
                  : status.status === 'degraded'
                  ? 'linear-gradient(135deg, #ff9800 0%, #f57c00 100%)'
                  : 'linear-gradient(135deg, #f44336 0%, #c62828 100%)',
                color: 'white'
              }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <UptimeIcon />
                    <Typography variant="subtitle2">Status Geral</Typography>
                  </Box>
                  <Typography variant="h5" sx={{ fontWeight: 'bold' }}>
                    {status.status?.toUpperCase()}
                  </Typography>
                  <Typography variant="body2" sx={{ mt: 1, opacity: 0.9 }}>
                    Uptime: {status.uptime}
                  </Typography>
                  <Typography variant="caption" sx={{ opacity: 0.8 }}>
                    v{status.version} • {status.environment}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            {/* Database */}
            <Grid item xs={12} sm={6} md={2}>
              {renderStatusCard('Database', status.components?.database, <DatabaseIcon color="primary" />)}
            </Grid>

            {/* Redis */}
            <Grid item xs={12} sm={6} md={2}>
              {renderStatusCard('Redis', status.components?.redis, <MemoryIcon color="secondary" />)}
            </Grid>

            {/* OpenSearch */}
            <Grid item xs={12} sm={6} md={2}>
              {renderStatusCard('OpenSearch', status.components?.opensearch, <SearchIcon color="info" />)}
            </Grid>

            {/* AWS Integration */}
            <Grid item xs={12} sm={6} md={3}>
              {renderStatusCard('AWS Integration', status.components?.aws_integration, <CloudIcon color="warning" />)}
            </Grid>
          </Grid>

          {/* Resources */}
          {status.resources && (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="caption" color="text.secondary">Memória Alocada</Typography>
                    <Typography variant="h6">{status.resources.memory?.alloc_mb} MB</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="caption" color="text.secondary">Goroutines</Typography>
                    <Typography variant="h6">{status.resources.goroutines}</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="caption" color="text.secondary">CPU Cores</Typography>
                    <Typography variant="h6">{status.resources.cpu_cores}</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="caption" color="text.secondary">GC Cycles</Typography>
                    <Typography variant="h6">{status.resources.memory?.gc_cycles}</Typography>
                  </Paper>
                </Grid>
              </Grid>
            </Box>
          )}
        </Box>
      )}

      <Divider sx={{ my: 3 }} />

      {/* Logs Section */}
      <Typography variant="h6" gutterBottom>
        Application Logs
      </Typography>

      {/* Filters */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} sm={3}>
            <TextField
              fullWidth
              size="small"
              placeholder="Buscar nos logs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: <SearchIcon color="action" sx={{ mr: 1 }} />,
              }}
            />
          </Grid>
          <Grid item xs={6} sm={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Level</InputLabel>
              <Select
                value={selectedLevel}
                onChange={(e) => setSelectedLevel(e.target.value)}
                label="Level"
              >
                <MenuItem value="">Todos</MenuItem>
                {filters.levels?.map((level) => (
                  <MenuItem key={level} value={level}>{level}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={6} sm={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Source</InputLabel>
              <Select
                value={selectedSource}
                onChange={(e) => setSelectedSource(e.target.value)}
                label="Source"
              >
                <MenuItem value="">Todos</MenuItem>
                {filters.sources?.map((source) => (
                  <MenuItem key={source} value={source}>{source}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={6} sm={2}>
            <Button
              fullWidth
              variant="outlined"
              startIcon={<SearchIcon />}
              onClick={loadData}
            >
              Buscar
            </Button>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Button
              fullWidth
              variant="outlined"
              color="error"
              startIcon={<DeleteIcon />}
              onClick={handleClearLogs}
            >
              Limpar Logs
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Logs Table */}
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell width={50}></TableCell>
              <TableCell width={150}>Timestamp</TableCell>
              <TableCell width={80}>Level</TableCell>
              <TableCell width={120}>Source</TableCell>
              <TableCell>Message</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} align="center" sx={{ py: 4 }}>
                  <Typography color="text.secondary">
                    Nenhum log encontrado
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              logs.map((log) => (
                <React.Fragment key={log.id}>
                  <TableRow 
                    hover
                    sx={{ 
                      cursor: log.details ? 'pointer' : 'default',
                      backgroundColor: LEVEL_COLORS[log.level]?.bg || 'inherit',
                    }}
                    onClick={() => log.details && setExpandedLog(expandedLog === log.id ? null : log.id)}
                  >
                    <TableCell>
                      {log.details && (
                        <IconButton size="small">
                          {expandedLog === log.id ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                        </IconButton>
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                        {formatTimestamp(log.timestamp)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        icon={LEVEL_COLORS[log.level]?.icon}
                        label={log.level}
                        size="small"
                        sx={{
                          backgroundColor: LEVEL_COLORS[log.level]?.bg,
                          color: LEVEL_COLORS[log.level]?.color,
                          fontWeight: 'bold',
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip label={log.source} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {log.message}
                      </Typography>
                    </TableCell>
                  </TableRow>
                  {log.details && (
                    <TableRow>
                      <TableCell colSpan={5} sx={{ p: 0 }}>
                        <Collapse in={expandedLog === log.id}>
                          <Box sx={{ p: 2, backgroundColor: '#f5f5f5' }}>
                            <Typography variant="subtitle2" gutterBottom>
                              Detalhes:
                            </Typography>
                            <Paper sx={{ p: 2, backgroundColor: '#1e1e1e', color: '#d4d4d4' }}>
                              <pre style={{ margin: 0, fontSize: '12px', overflow: 'auto' }}>
                                {JSON.stringify(log.details, null, 2)}
                              </pre>
                            </Paper>
                          </Box>
                        </Collapse>
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          Mostrando {logs.length} logs
        </Typography>
        {loading && <CircularProgress size={20} />}
      </Box>

      {/* Config Dialog */}
      <Dialog open={configDialogOpen} onClose={() => setConfigDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          ⚙️ Configuração do Sistema
        </DialogTitle>
        <DialogContent>
          {config && (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={3}>
                {Object.entries(config).map(([section, values]) => (
                  <Grid item xs={12} sm={6} key={section}>
                    <Paper sx={{ p: 2 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 'bold', mb: 2, textTransform: 'capitalize' }}>
                        {section.replace('_', ' ')}
                      </Typography>
                      {Object.entries(values).map(([key, value]) => (
                        <Box key={key} sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="body2" color="text.secondary">
                            {key}:
                          </Typography>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {String(value) || '-'}
                          </Typography>
                        </Box>
                      ))}
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigDialogOpen(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default SystemLogs;

