import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  LinearProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  PieChart,
  Pie,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import CloudIcon from '@mui/icons-material/Cloud';
import AccountBalanceIcon from '@mui/icons-material/AccountBalance';
import PublicIcon from '@mui/icons-material/Public';
import SyncIcon from '@mui/icons-material/Sync';
import AddIcon from '@mui/icons-material/Add';
import RefreshIcon from '@mui/icons-material/Refresh';
import VisibilityIcon from '@mui/icons-material/Visibility';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import { cspmAPI } from '../services/api';

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8'];

function CSPMConfigAggregator() {
  const [tabValue, setTabValue] = useState(0);
  const [accounts, setAccounts] = useState([]);
  const [aggregators, setAggregators] = useState([]);
  const [aggregatedData, setAggregatedData] = useState(null);
  const [syncStatus, setSyncStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedAggregator, setSelectedAggregator] = useState(null);
  const [addAccountDialog, setAddAccountDialog] = useState(false);
  const [editAccountDialog, setEditAccountDialog] = useState(false);
  const [detailsDialog, setDetailsDialog] = useState(false);
  const [selectedAccount, setSelectedAccount] = useState(null);
  const [formData, setFormData] = useState({
    account_id: '',
    account_name: '',
    email: '',
    organization_unit: '',
    role: 'member',
    regions: [],
  });

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (aggregators.length > 0 && !selectedAggregator) {
      setSelectedAggregator(aggregators[0].id);
      loadAggregatedData(aggregators[0].id);
      loadSyncStatus(aggregators[0].id);
    }
  }, [aggregators]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [accountsRes, aggregatorsRes] = await Promise.all([
        cspmAPI.aggregator.getAccounts(),
        cspmAPI.aggregator.getAggregators(),
      ]);
      setAccounts(accountsRes.data.accounts || []);
      setAggregators(aggregatorsRes.data.aggregators || []);
    } catch (error) {
      console.error('Error loading data:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadAggregatedData = async (aggregatorId) => {
    try {
      const response = await cspmAPI.aggregator.getAggregatedData(aggregatorId);
      setAggregatedData(response.data.data);
    } catch (error) {
      console.error('Error loading aggregated data:', error);
    }
  };

  const loadSyncStatus = async (aggregatorId) => {
    try {
      const response = await cspmAPI.aggregator.getSyncStatus(aggregatorId);
      setSyncStatus(response.data.status);
    } catch (error) {
      console.error('Error loading sync status:', error);
    }
  };

  const handleTriggerSync = async () => {
    if (!selectedAggregator) return;
    try {
      await cspmAPI.aggregator.triggerSync(selectedAggregator);
      alert('Sincronização iniciada com sucesso!');
      loadSyncStatus(selectedAggregator);
    } catch (error) {
      console.error('Error triggering sync:', error);
      alert('Erro ao iniciar sincronização');
    }
  };

  const handleAddAccount = async () => {
    try {
      await cspmAPI.aggregator.addAccount(formData);
      alert('Conta adicionada com sucesso!');
      setAddAccountDialog(false);
      resetForm();
      loadData();
    } catch (error) {
      console.error('Error adding account:', error);
      alert('Erro ao adicionar conta');
    }
  };

  const handleUpdateAccount = async () => {
    try {
      await cspmAPI.aggregator.updateAccount(selectedAccount.id, formData);
      alert('Conta atualizada com sucesso!');
      setEditAccountDialog(false);
      resetForm();
      loadData();
    } catch (error) {
      console.error('Error updating account:', error);
      alert('Erro ao atualizar conta');
    }
  };

  const handleDeleteAccount = async (accountId) => {
    if (!window.confirm('Tem certeza que deseja remover esta conta?')) return;
    try {
      await cspmAPI.aggregator.deleteAccount(accountId);
      alert('Conta removida com sucesso!');
      loadData();
    } catch (error) {
      console.error('Error deleting account:', error);
      alert('Erro ao remover conta');
    }
  };

  const openAddDialog = () => {
    resetForm();
    setAddAccountDialog(true);
  };

  const openEditDialog = (account) => {
    setSelectedAccount(account);
    setFormData({
      account_id: account.account_id,
      account_name: account.account_name,
      email: account.email,
      organization_unit: account.organization_unit,
      role: account.role,
      regions: account.regions || [],
    });
    setEditAccountDialog(true);
  };

  const resetForm = () => {
    setFormData({
      account_id: '',
      account_name: '',
      email: '',
      organization_unit: '',
      role: 'member',
      regions: [],
    });
    setSelectedAccount(null);
  };

  const handleFormChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleRegionToggle = (region) => {
    setFormData(prev => {
      const regions = prev.regions.includes(region)
        ? prev.regions.filter(r => r !== region)
        : [...prev.regions, region];
      return { ...prev, regions };
    });
  };

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: 'error',
      HIGH: 'warning',
      MEDIUM: 'info',
      LOW: 'success',
    };
    return colors[severity] || 'default';
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success',
      pending: 'warning',
      suspended: 'error',
      completed: 'success',
      syncing: 'info',
      failed: 'error',
    };
    return colors[status] || 'default';
  };

  const getRoleColor = (role) => {
    const colors = {
      management: 'error',
      delegated_admin: 'warning',
      member: 'info',
    };
    return colors[role] || 'default';
  };

  const renderDashboard = () => {
    if (!aggregatedData) return <Typography>Carregando dados agregados...</Typography>;

    const severityData = [
      { name: 'Crítico', value: aggregatedData.critical_findings },
      { name: 'Alto', value: aggregatedData.high_findings },
      { name: 'Médio', value: aggregatedData.medium_findings },
      { name: 'Baixo', value: aggregatedData.low_findings },
    ];

    return (
      <Box>
        {/* Statistics Cards */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total de Contas
                </Typography>
                <Typography variant="h4">{aggregatedData.total_accounts}</Typography>
                <Typography variant="body2" color="success.main">
                  {accounts.filter(a => a.status === 'active').length} ativas
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total de Recursos
                </Typography>
                <Typography variant="h4">{aggregatedData.total_resources.toLocaleString()}</Typography>
                <Typography variant="body2" color="textSecondary">
                  Em {aggregatedData.total_regions} regiões
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total de Findings
                </Typography>
                <Typography variant="h4">{aggregatedData.total_findings}</Typography>
                <Typography variant="body2" color="error.main">
                  {aggregatedData.critical_findings} críticos
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Compliance Geral
                </Typography>
                <Typography variant="h4">{aggregatedData.overall_compliance.toFixed(1)}%</Typography>
                <LinearProgress
                  variant="determinate"
                  value={aggregatedData.overall_compliance}
                  sx={{ mt: 1 }}
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Charts */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Findings por Severidade
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={(entry) => `${entry.name}: ${entry.value}`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
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
                Compliance por Conta
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={aggregatedData.by_account}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="account_name" angle={-45} textAnchor="end" height={100} />
                  <YAxis domain={[0, 100]} />
                  <RechartsTooltip />
                  <Bar dataKey="compliance_score" fill="#8884d8" />
                </BarChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
        </Grid>

        {/* Compliance Trend */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Tendência de Compliance (7 dias)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={aggregatedData.trends}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis yAxisId="left" domain={[0, 100]} />
                  <YAxis yAxisId="right" orientation="right" />
                  <RechartsTooltip />
                  <Legend />
                  <Line
                    yAxisId="left"
                    type="monotone"
                    dataKey="compliance_score"
                    stroke="#8884d8"
                    name="Compliance Score (%)"
                  />
                  <Line
                    yAxisId="right"
                    type="monotone"
                    dataKey="total_findings"
                    stroke="#82ca9d"
                    name="Total Findings"
                  />
                </LineChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
        </Grid>

        {/* Top Findings */}
        <Paper sx={{ p: 2 }}>
          <Typography variant="h6" gutterBottom>
            Top Findings Multi-Conta
          </Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Título</TableCell>
                  <TableCell>Severidade</TableCell>
                  <TableCell>Tipo de Recurso</TableCell>
                  <TableCell>Contas Afetadas</TableCell>
                  <TableCell>Ocorrências</TableCell>
                  <TableCell>Recomendação</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {aggregatedData.top_findings?.map((finding) => (
                  <TableRow key={finding.id}>
                    <TableCell>{finding.title}</TableCell>
                    <TableCell>
                      <Chip
                        label={finding.severity}
                        color={getSeverityColor(finding.severity)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{finding.resource_type}</TableCell>
                    <TableCell>{finding.affected_accounts.length}</TableCell>
                    <TableCell>{finding.total_occurrences}</TableCell>
                    <TableCell>{finding.recommendation}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      </Box>
    );
  };

  const renderAccounts = () => (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
        <Typography variant="h6">Contas AWS</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={openAddDialog}
        >
          Adicionar Conta
        </Button>
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>ID da Conta</TableCell>
              <TableCell>Nome</TableCell>
              <TableCell>Organization Unit</TableCell>
              <TableCell>Role</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Compliance</TableCell>
              <TableCell>Recursos</TableCell>
              <TableCell>Findings</TableCell>
              <TableCell>Última Sync</TableCell>
              <TableCell>Ações</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {accounts.map((account) => (
              <TableRow key={account.id}>
                <TableCell>{account.account_id}</TableCell>
                <TableCell>{account.account_name}</TableCell>
                <TableCell>{account.organization_unit}</TableCell>
                <TableCell>
                  <Chip
                    label={account.role}
                    color={getRoleColor(account.role)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={account.status}
                    color={getStatusColor(account.status)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Box sx={{ width: '100%', mr: 1 }}>
                      <LinearProgress
                        variant="determinate"
                        value={account.compliance_score}
                      />
                    </Box>
                    <Box sx={{ minWidth: 35 }}>
                      <Typography variant="body2" color="text.secondary">
                        {account.compliance_score.toFixed(1)}%
                      </Typography>
                    </Box>
                  </Box>
                </TableCell>
                <TableCell>{account.total_resources}</TableCell>
                <TableCell>
                  {account.total_findings}
                  {account.critical_findings > 0 && (
                    <Chip
                      label={`${account.critical_findings} críticos`}
                      color="error"
                      size="small"
                      sx={{ ml: 1 }}
                    />
                  )}
                </TableCell>
                <TableCell>
                  {new Date(account.last_sync).toLocaleString('pt-BR')}
                </TableCell>
                <TableCell>
                  <Tooltip title="Ver Detalhes">
                    <IconButton
                      size="small"
                      onClick={() => {
                        setSelectedAccount(account);
                        setDetailsDialog(true);
                      }}
                    >
                      <VisibilityIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Editar">
                    <IconButton
                      size="small"
                      onClick={() => openEditDialog(account)}
                    >
                      <EditIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Remover">
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => handleDeleteAccount(account.id)}
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
    </Box>
  );

  const renderRegions = () => {
    if (!aggregatedData) return <Typography>Carregando dados...</Typography>;

    return (
      <Box>
        <Typography variant="h6" gutterBottom>
          Compliance por Região
        </Typography>
        <Grid container spacing={2}>
          {aggregatedData.by_region?.map((region) => (
            <Grid item xs={12} md={6} key={region.region}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                    <Typography variant="h6">{region.region}</Typography>
                    <Chip
                      label={`${region.compliance_score.toFixed(1)}%`}
                      color={region.compliance_score >= 90 ? 'success' : region.compliance_score >= 75 ? 'warning' : 'error'}
                    />
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={region.compliance_score}
                    sx={{ mb: 2 }}
                  />
                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="textSecondary">
                        Recursos
                      </Typography>
                      <Typography variant="h6">{region.total_resources}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="textSecondary">
                        Findings
                      </Typography>
                      <Typography variant="h6">{region.total_findings}</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="textSecondary">
                        Críticos
                      </Typography>
                      <Typography variant="h6" color="error">
                        {region.critical_findings}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="textSecondary">
                        Contas
                      </Typography>
                      <Typography variant="h6">{region.account_count}</Typography>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>
    );
  };

  const renderSyncStatus = () => {
    if (!syncStatus) return <Typography>Carregando status...</Typography>;

    return (
      <Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
          <Typography variant="h6">Status de Sincronização</Typography>
          <Button
            variant="contained"
            startIcon={<RefreshIcon />}
            onClick={handleTriggerSync}
            disabled={syncStatus.status === 'syncing'}
          >
            Sincronizar Agora
          </Button>
        </Box>

        <Paper sx={{ p: 2, mb: 3 }}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={3}>
              <Typography variant="body2" color="textSecondary">
                Status
              </Typography>
              <Chip
                label={syncStatus.status}
                color={getStatusColor(syncStatus.status)}
                sx={{ mt: 1 }}
              />
            </Grid>
            <Grid item xs={12} md={3}>
              <Typography variant="body2" color="textSecondary">
                Progresso
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                <Box sx={{ width: '100%', mr: 1 }}>
                  <LinearProgress variant="determinate" value={syncStatus.progress} />
                </Box>
                <Typography variant="body2">{syncStatus.progress}%</Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={3}>
              <Typography variant="body2" color="textSecondary">
                Contas Sincronizadas
              </Typography>
              <Typography variant="h6">
                {syncStatus.synced_accounts} / {syncStatus.total_accounts}
              </Typography>
            </Grid>
            <Grid item xs={12} md={3}>
              <Typography variant="body2" color="textSecondary">
                Iniciado em
              </Typography>
              <Typography variant="body2">
                {new Date(syncStatus.started_at).toLocaleString('pt-BR')}
              </Typography>
            </Grid>
          </Grid>
        </Paper>

        <Typography variant="h6" gutterBottom>
          Status por Conta
        </Typography>
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>ID da Conta</TableCell>
                <TableCell>Nome</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Progresso</TableCell>
                <TableCell>Última Sync</TableCell>
                <TableCell>Erro</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {syncStatus.account_statuses?.map((accountStatus) => (
                <TableRow key={accountStatus.account_id}>
                  <TableCell>{accountStatus.account_id}</TableCell>
                  <TableCell>{accountStatus.account_name}</TableCell>
                  <TableCell>
                    <Chip
                      label={accountStatus.status}
                      color={getStatusColor(accountStatus.status)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <Box sx={{ width: '100%', mr: 1 }}>
                        <LinearProgress
                          variant="determinate"
                          value={accountStatus.progress}
                        />
                      </Box>
                      <Typography variant="body2">{accountStatus.progress}%</Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    {new Date(accountStatus.last_sync).toLocaleString('pt-BR')}
                  </TableCell>
                  <TableCell>
                    {accountStatus.error && (
                      <Typography variant="body2" color="error">
                        {accountStatus.error}
                      </Typography>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Box>
    );
  };

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography>Carregando...</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <CloudIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
        <Box>
          <Typography variant="h4">AWS Config Aggregator</Typography>
          <Typography variant="body2" color="textSecondary">
            Visão consolidada multi-conta e multi-região
          </Typography>
        </Box>
      </Box>

      {aggregators.length > 0 && (
        <Alert severity="info" sx={{ mb: 3 }}>
          Agregador ativo: <strong>{aggregators[0].name}</strong> - {aggregators[0].total_accounts} contas em {aggregators[0].total_regions} regiões
        </Alert>
      )}

      <Paper sx={{ width: '100%', mb: 3 }}>
        <Tabs value={tabValue} onChange={(e, newValue) => setTabValue(newValue)}>
          <Tab label="Dashboard" icon={<AccountBalanceIcon />} iconPosition="start" />
          <Tab label="Contas" icon={<CloudIcon />} iconPosition="start" />
          <Tab label="Regiões" icon={<PublicIcon />} iconPosition="start" />
          <Tab label="Sincronização" icon={<SyncIcon />} iconPosition="start" />
        </Tabs>
      </Paper>

      {tabValue === 0 && renderDashboard()}
      {tabValue === 1 && renderAccounts()}
      {tabValue === 2 && renderRegions()}
      {tabValue === 3 && renderSyncStatus()}

      {/* Add Account Dialog */}
      <Dialog
        open={addAccountDialog}
        onClose={() => {
          setAddAccountDialog(false);
          resetForm();
        }}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Adicionar Nova Conta AWS</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Account ID"
                  value={formData.account_id}
                  onChange={(e) => handleFormChange('account_id', e.target.value)}
                  placeholder="123456789012"
                  required
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Nome da Conta"
                  value={formData.account_name}
                  onChange={(e) => handleFormChange('account_name', e.target.value)}
                  required
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Email"
                  type="email"
                  value={formData.email}
                  onChange={(e) => handleFormChange('email', e.target.value)}
                  required
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Organization Unit"
                  value={formData.organization_unit}
                  onChange={(e) => handleFormChange('organization_unit', e.target.value)}
                  placeholder="Production, Development, etc."
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  select
                  label="Role"
                  value={formData.role}
                  onChange={(e) => handleFormChange('role', e.target.value)}
                >
                  <MenuItem value="member">Member</MenuItem>
                  <MenuItem value="delegated_admin">Delegated Admin</MenuItem>
                  <MenuItem value="management">Management</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  Regiões AWS (selecione uma ou mais):
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'sa-east-1'].map((region) => (
                    <Chip
                      key={region}
                      label={region}
                      onClick={() => handleRegionToggle(region)}
                      color={formData.regions.includes(region) ? 'primary' : 'default'}
                      variant={formData.regions.includes(region) ? 'filled' : 'outlined'}
                    />
                  ))}
                </Box>
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setAddAccountDialog(false);
            resetForm();
          }}>
            Cancelar
          </Button>
          <Button
            variant="contained"
            onClick={handleAddAccount}
            disabled={!formData.account_id || !formData.account_name || !formData.email}
          >
            Adicionar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Account Dialog */}
      <Dialog
        open={editAccountDialog}
        onClose={() => {
          setEditAccountDialog(false);
          resetForm();
        }}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Editar Conta AWS</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Account ID"
                  value={formData.account_id}
                  disabled
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Nome da Conta"
                  value={formData.account_name}
                  onChange={(e) => handleFormChange('account_name', e.target.value)}
                  required
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Email"
                  type="email"
                  value={formData.email}
                  onChange={(e) => handleFormChange('email', e.target.value)}
                  required
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Organization Unit"
                  value={formData.organization_unit}
                  onChange={(e) => handleFormChange('organization_unit', e.target.value)}
                  placeholder="Production, Development, etc."
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  select
                  label="Role"
                  value={formData.role}
                  onChange={(e) => handleFormChange('role', e.target.value)}
                >
                  <MenuItem value="member">Member</MenuItem>
                  <MenuItem value="delegated_admin">Delegated Admin</MenuItem>
                  <MenuItem value="management">Management</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  Regiões AWS (selecione uma ou mais):
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'sa-east-1'].map((region) => (
                    <Chip
                      key={region}
                      label={region}
                      onClick={() => handleRegionToggle(region)}
                      color={formData.regions.includes(region) ? 'primary' : 'default'}
                      variant={formData.regions.includes(region) ? 'filled' : 'outlined'}
                    />
                  ))}
                </Box>
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setEditAccountDialog(false);
            resetForm();
          }}>
            Cancelar
          </Button>
          <Button
            variant="contained"
            onClick={handleUpdateAccount}
            disabled={!formData.account_name || !formData.email}
          >
            Salvar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Account Details Dialog */}
      <Dialog
        open={detailsDialog}
        onClose={() => setDetailsDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Detalhes da Conta</DialogTitle>
        <DialogContent>
          {selectedAccount && (
            <Box>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">
                    ID da Conta
                  </Typography>
                  <Typography variant="body1">{selectedAccount.account_id}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">
                    Nome
                  </Typography>
                  <Typography variant="body1">{selectedAccount.account_name}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">
                    Email
                  </Typography>
                  <Typography variant="body1">{selectedAccount.email}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">
                    Organization Unit
                  </Typography>
                  <Typography variant="body1">{selectedAccount.organization_unit}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="body2" color="textSecondary">
                    Regiões
                  </Typography>
                  <Box sx={{ mt: 1 }}>
                    {selectedAccount.regions?.map((region) => (
                      <Chip key={region} label={region} size="small" sx={{ mr: 1, mb: 1 }} />
                    ))}
                  </Box>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsDialog(false)}>Fechar</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default CSPMConfigAggregator;


