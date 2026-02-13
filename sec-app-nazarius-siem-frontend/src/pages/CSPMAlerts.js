import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  IconButton,
  Tooltip,
  LinearProgress,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Switch,
  FormControlLabel,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Notifications as NotificationsIcon,
  NotificationsActive as NotificationsActiveIcon,
  Send as SendIcon,
  Schedule as ScheduleIcon,
  TrendingUp as TrendingUpIcon,
  Speed as SpeedIcon,
} from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';
import { cspmAPI } from '../services/api';

const CSPMAlerts = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Data states
  const [channels, setChannels] = useState([]);
  const [rules, setRules] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [statistics, setStatistics] = useState(null);
  
  // Dialog states
  const [channelDialog, setChannelDialog] = useState(false);
  const [ruleDialog, setRuleDialog] = useState(false);
  const [selectedChannel, setSelectedChannel] = useState(null);
  const [selectedRule, setSelectedRule] = useState(null);
  const [deleteDialog, setDeleteDialog] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [channelsRes, rulesRes, alertsRes, statsRes] = await Promise.all([
        cspmAPI.alerts.getChannels(),
        cspmAPI.alerts.getRules(),
        cspmAPI.alerts.getAlerts(),
        cspmAPI.alerts.getStatistics(),
      ]);
      
      setChannels(channelsRes.data.channels || []);
      setRules(rulesRes.data.rules || []);
      setAlerts(alertsRes.data.alerts || []);
      setStatistics(statsRes.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao carregar dados');
      console.error('Erro ao carregar dados:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleTestChannel = async (channelId) => {
    try {
      const res = await cspmAPI.alerts.testChannel(channelId);
      alert(res.data.message);
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao testar canal');
    }
  };

  const handleDeleteChannel = async () => {
    if (!deleteTarget) return;
    try {
      await cspmAPI.alerts.deleteChannel(deleteTarget.id);
      setDeleteDialog(false);
      setDeleteTarget(null);
      loadData();
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao deletar canal');
    }
  };

  const handleDeleteRule = async () => {
    if (!deleteTarget) return;
    try {
      await cspmAPI.alerts.deleteRule(deleteTarget.id);
      setDeleteDialog(false);
      setDeleteTarget(null);
      loadData();
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao deletar regra');
    }
  };

  const handleAcknowledge = async (alertId) => {
    try {
      await cspmAPI.alerts.acknowledge(alertId, {
        acknowledged_by: 'admin@company.com', // TODO: Get from auth context
        comment: 'Acknowledged via UI',
      });
      loadData();
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao reconhecer alerta');
    }
  };

  const handleResolve = async (alertId) => {
    try {
      await cspmAPI.alerts.resolve(alertId, {
        resolved_by: 'admin@company.com', // TODO: Get from auth context
        comment: 'Resolved via UI',
      });
      loadData();
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao resolver alerta');
    }
  };

  const getChannelTypeIcon = (type) => {
    const icons = {
      slack: '💬',
      pagerduty: '📟',
      email: '📧',
      webhook: '🔗',
      sms: '📱',
    };
    return icons[type] || '📡';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'error',
      high: 'warning',
      medium: 'info',
      low: 'default',
      info: 'default',
    };
    return colors[severity] || 'default';
  };

  const getStatusColor = (status) => {
    const colors = {
      pending: 'warning',
      sent: 'info',
      failed: 'error',
      acknowledged: 'primary',
      resolved: 'success',
      suppressed: 'default',
    };
    return colors[status] || 'default';
  };

  // Statistics Cards
  const renderStatistics = () => {
    if (!statistics) return null;

    return (
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <NotificationsIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">Total Alertas</Typography>
              </Box>
              <Typography variant="h3">{statistics.total_alerts}</Typography>
              <Typography variant="body2" color="text.secondary">
                Críticos: {statistics.alerts_by_severity?.critical || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <SpeedIcon sx={{ mr: 1, color: 'success.main' }} />
                <Typography variant="h6">Taxa de Sucesso</Typography>
              </Box>
              <Typography variant="h3">{statistics.success_rate?.toFixed(1)}%</Typography>
              <Typography variant="body2" color="text.secondary">
                Avg Response: {statistics.avg_response_time}min
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <ScheduleIcon sx={{ mr: 1, color: 'warning.main' }} />
                <Typography variant="h6">Tempo Médio</Typography>
              </Box>
              <Typography variant="h3">{statistics.avg_resolution_time}min</Typography>
              <Typography variant="body2" color="text.secondary">
                Resolução média
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <TrendingUpIcon sx={{ mr: 1, color: 'info.main' }} />
                <Typography variant="h6">Canais Ativos</Typography>
              </Box>
              <Typography variant="h3">{channels.filter(c => c.enabled).length}</Typography>
              <Typography variant="body2" color="text.secondary">
                de {channels.length} totais
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    );
  };

  // Channels Tab
  const renderChannelsTab = () => (
    <>
      <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between' }}>
        <Typography variant="h6">Canais de Notificação</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => {
            setSelectedChannel(null);
            setChannelDialog(true);
          }}
        >
          Novo Canal
        </Button>
      </Box>
      
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Nome</TableCell>
              <TableCell>Tipo</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Taxa de Sucesso</TableCell>
              <TableCell>Total Enviados</TableCell>
              <TableCell align="center">Ações</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {channels.map((channel) => (
              <TableRow key={channel.id}>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Typography sx={{ mr: 1 }}>{getChannelTypeIcon(channel.type)}</Typography>
                    <Typography variant="body2" fontWeight="bold">
                      {channel.name}
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip label={channel.type} size="small" />
                </TableCell>
                <TableCell>
                  {channel.enabled ? (
                    <Chip
                      icon={<CheckCircleIcon />}
                      label="Ativo"
                      color="success"
                      size="small"
                    />
                  ) : (
                    <Chip
                      icon={<ErrorIcon />}
                      label="Inativo"
                      color="default"
                      size="small"
                    />
                  )}
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Box sx={{ width: '100%', mr: 1 }}>
                      <LinearProgress
                        variant="determinate"
                        value={channel.success_rate}
                        color={channel.success_rate >= 95 ? 'success' : 'warning'}
                      />
                    </Box>
                    <Typography variant="caption">
                      {channel.success_rate.toFixed(1)}%
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell>
                  <Typography variant="body2">
                    {channel.total_sent}
                    {channel.total_failed > 0 && (
                      <Typography variant="caption" color="error">
                        {' '}({channel.total_failed} falhas)
                      </Typography>
                    )}
                  </Typography>
                </TableCell>
                <TableCell align="center">
                  <Tooltip title="Testar Canal">
                    <IconButton
                      size="small"
                      color="primary"
                      onClick={() => handleTestChannel(channel.id)}
                    >
                      <SendIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Editar">
                    <IconButton
                      size="small"
                      onClick={() => {
                        setSelectedChannel(channel);
                        setChannelDialog(true);
                      }}
                    >
                      <EditIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Deletar">
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => {
                        setDeleteTarget({ ...channel, type: 'channel' });
                        setDeleteDialog(true);
                      }}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );

  // Rules Tab
  const renderRulesTab = () => (
    <>
      <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between' }}>
        <Typography variant="h6">Regras de Alerta</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => {
            setSelectedRule(null);
            setRuleDialog(true);
          }}
        >
          Nova Regra
        </Button>
      </Box>
      
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Nome</TableCell>
              <TableCell>Severidades</TableCell>
              <TableCell>Canais</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Acionamentos</TableCell>
              <TableCell align="center">Ações</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rules.map((rule) => (
              <TableRow key={rule.id}>
                <TableCell>
                  <Typography variant="body2" fontWeight="bold">
                    {rule.name}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {rule.description}
                  </Typography>
                </TableCell>
                <TableCell>
                  {rule.severities.map((sev) => (
                    <Chip
                      key={sev}
                      label={sev}
                      size="small"
                      color={getSeverityColor(sev)}
                      sx={{ mr: 0.5, mb: 0.5 }}
                    />
                  ))}
                </TableCell>
                <TableCell>
                  <Chip label={`${rule.channels?.length || 0} canais`} size="small" />
                </TableCell>
                <TableCell>
                  {rule.enabled ? (
                    <Chip
                      icon={<NotificationsActiveIcon />}
                      label="Ativa"
                      color="success"
                      size="small"
                    />
                  ) : (
                    <Chip
                      icon={<NotificationsIcon />}
                      label="Inativa"
                      color="default"
                      size="small"
                    />
                  )}
                </TableCell>
                <TableCell>
                  <Typography variant="body2">{rule.trigger_count}</Typography>
                </TableCell>
                <TableCell align="center">
                  <Tooltip title="Editar">
                    <IconButton
                      size="small"
                      onClick={() => {
                        setSelectedRule(rule);
                        setRuleDialog(true);
                      }}
                    >
                      <EditIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Deletar">
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => {
                        setDeleteTarget({ ...rule, type: 'rule' });
                        setDeleteDialog(true);
                      }}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );

  // Alerts Tab
  const renderAlertsTab = () => (
    <>
      <Box sx={{ mb: 2 }}>
        <Typography variant="h6">Alertas Ativos</Typography>
      </Box>
      
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Título</TableCell>
              <TableCell>Severidade</TableCell>
              <TableCell>Recurso</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Enviado Em</TableCell>
              <TableCell align="center">Ações</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {alerts.map((alert) => (
              <TableRow key={alert.id}>
                <TableCell>
                  <Typography variant="caption" fontFamily="monospace">
                    {alert.id}
                  </Typography>
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
                  <Chip
                    label={alert.severity}
                    size="small"
                    color={getSeverityColor(alert.severity)}
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="body2">{alert.resource_id}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {alert.resource_type}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={alert.status}
                    size="small"
                    color={getStatusColor(alert.status)}
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="caption">
                    {alert.sent_at ? new Date(alert.sent_at).toLocaleString() : '-'}
                  </Typography>
                </TableCell>
                <TableCell align="center">
                  {alert.status === 'sent' && (
                    <Tooltip title="Reconhecer">
                      <IconButton
                        size="small"
                        color="primary"
                        onClick={() => handleAcknowledge(alert.id)}
                      >
                        <CheckCircleIcon />
                      </IconButton>
                    </Tooltip>
                  )}
                  {(alert.status === 'sent' || alert.status === 'acknowledged') && (
                    <Tooltip title="Resolver">
                      <IconButton
                        size="small"
                        color="success"
                        onClick={() => handleResolve(alert.id)}
                      >
                        <CheckCircleIcon />
                      </IconButton>
                    </Tooltip>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );

  // Statistics Tab
  const renderStatisticsTab = () => {
    if (!statistics) return null;

    const trendData = statistics.alert_trend || [];
    const severityData = Object.entries(statistics.alerts_by_severity || {}).map(([name, value]) => ({
      name,
      value,
    }));

    return (
      <>
        <Typography variant="h6" gutterBottom>
          Estatísticas de Alertas
        </Typography>

        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Tendência de Alertas (7 dias)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={(ts) => new Date(ts).toLocaleDateString()}
                  />
                  <YAxis />
                  <RechartsTooltip />
                  <Legend />
                  <Line type="monotone" dataKey="count" stroke="#8884d8" name="Alertas" />
                </LineChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Alertas por Severidade
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={severityData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <RechartsTooltip />
                  <Legend />
                  <Bar dataKey="value" fill="#8884d8" name="Quantidade" />
                </BarChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
        </Grid>

        <Paper sx={{ p: 2 }}>
          <Typography variant="h6" gutterBottom>
            Top Regras Mais Acionadas
          </Typography>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Regra</TableCell>
                <TableCell align="right">Acionamentos</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {statistics.top_rules?.map((rule) => (
                <TableRow key={rule.rule_id}>
                  <TableCell>{rule.rule_name}</TableCell>
                  <TableCell align="right">{rule.trigger_count}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      </>
    );
  };

  // Delete Confirmation Dialog
  const renderDeleteDialog = () => (
    <Dialog open={deleteDialog} onClose={() => setDeleteDialog(false)}>
      <DialogTitle>Confirmar Exclusão</DialogTitle>
      <DialogContent>
        <Typography>
          Tem certeza que deseja deletar {deleteTarget?.type === 'channel' ? 'o canal' : 'a regra'}{' '}
          "{deleteTarget?.name}"?
        </Typography>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => setDeleteDialog(false)}>Cancelar</Button>
        <Button
          onClick={deleteTarget?.type === 'channel' ? handleDeleteChannel : handleDeleteRule}
          color="error"
          variant="contained"
        >
          Deletar
        </Button>
      </DialogActions>
    </Dialog>
  );

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Sistema de Alertas
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Gerenciamento de canais, regras e alertas de segurança
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
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {loading && <LinearProgress sx={{ mb: 3 }} />}

      {renderStatistics()}

      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label={`Canais (${channels.length})`} />
          <Tab label={`Regras (${rules.length})`} />
          <Tab label={`Alertas (${alerts.length})`} />
          <Tab label="Estatísticas" />
        </Tabs>
      </Paper>

      <Box sx={{ mt: 3 }}>
        {activeTab === 0 && renderChannelsTab()}
        {activeTab === 1 && renderRulesTab()}
        {activeTab === 2 && renderAlertsTab()}
        {activeTab === 3 && renderStatisticsTab()}
      </Box>

      {renderDeleteDialog()}
    </Box>
  );
};

export default CSPMAlerts;

