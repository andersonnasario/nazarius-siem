import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  Chip,
  Switch,
  FormControlLabel,
  Alert,
  Snackbar,
  TextField,
  InputAdornment,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Tabs,
  Tab,
  IconButton,
  Tooltip,
  Badge,
} from '@mui/material';
import {
  PowerSettingsNew as PowerIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  CheckCircle as ActiveIcon,
  PauseCircle as StandbyIcon,
  Cancel as DisabledIcon,
  Info as InfoIcon,
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  Analytics as AnalyticsIcon,
  Shield as ShieldIcon,
  Cloud as CloudIcon,
} from '@mui/icons-material';
import { useModules } from '../contexts/ModuleContext';

const ModuleManager = () => {
  // Usar o contexto de módulos para sincronização global
  const { 
    modules: contextModules, 
    loading: contextLoading, 
    updateModuleStatus: contextUpdateStatus,
    bulkUpdateModules: contextBulkUpdate,
    refreshModules 
  } = useModules();
  
  const [modules, setModules] = useState([]);
  const [filteredModules, setFilteredModules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [tierFilter, setTierFilter] = useState('all');
  const [activeTab, setActiveTab] = useState(0);
  const [confirmDialog, setConfirmDialog] = useState({ open: false, module: null, action: '' });
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  // Sincronizar com o contexto
  useEffect(() => {
    if (contextModules && contextModules.length > 0) {
      setModules(contextModules);
      setLoading(false);
    }
  }, [contextModules]);

  useEffect(() => {
    filterModules();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modules, searchTerm, categoryFilter, statusFilter, tierFilter, activeTab]);

  const loadModules = async () => {
    await refreshModules();
  };

  const filterModules = () => {
    let filtered = [...modules];

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(
        (m) =>
          m.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          m.description.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Filter by category
    if (categoryFilter !== 'all') {
      filtered = filtered.filter((m) => m.category === categoryFilter);
    }

    // Filter by status
    if (statusFilter !== 'all') {
      filtered = filtered.filter((m) => m.status === statusFilter);
    }

    // Filter by tier
    if (tierFilter !== 'all') {
      filtered = filtered.filter((m) => m.tier === tierFilter);
    }

    // Filter by tab (category groups)
    if (activeTab === 1) {
      filtered = filtered.filter((m) => m.category === 'siem');
    } else if (activeTab === 2) {
      filtered = filtered.filter((m) => m.category === 'mdr');
    } else if (activeTab === 3) {
      filtered = filtered.filter((m) => m.category === 'threat');
    } else if (activeTab === 4) {
      filtered = filtered.filter((m) => ['analytics', 'protection'].includes(m.category));
    }

    setFilteredModules(filtered);
  };

  const handleStatusChange = (module, newStatus) => {
    setConfirmDialog({
      open: true,
      module,
      action: newStatus,
    });
  };

  const confirmStatusChange = async () => {
    const { module, action } = confirmDialog;
    try {
      const result = await contextUpdateStatus(module.id, action);
      if (result.success) {
        showSnackbar(`Módulo ${module.name} ${getStatusLabel(action)}`, 'success');
        // Atualizar lista local também
        setModules(prevModules => 
          prevModules.map(m => 
            m.id === module.id ? { ...m, status: action } : m
          )
        );
      } else {
        showSnackbar('Erro ao atualizar módulo', 'error');
      }
    } catch (error) {
      console.error('Error updating module:', error);
      showSnackbar('Erro ao atualizar módulo', 'error');
    } finally {
      setConfirmDialog({ open: false, module: null, action: '' });
    }
  };

  const handleBulkAction = async (status) => {
    const modulesToUpdate = filteredModules.map((m) => ({
      id: m.id,
      status,
    }));

    try {
      const result = await contextBulkUpdate(modulesToUpdate);
      if (result.success) {
        showSnackbar(
          `${result.data?.updated?.length || modulesToUpdate.length} módulos atualizados`,
          'success'
        );
        // O contexto já atualiza os módulos, mas vamos forçar refresh local
        setModules(prevModules => 
          prevModules.map(m => {
            const update = modulesToUpdate.find(u => u.id === m.id);
            return update ? { ...m, status: update.status } : m;
          })
        );
      } else {
        showSnackbar('Erro ao atualizar módulos', 'error');
      }
    } catch (error) {
      console.error('Error bulk updating:', error);
      showSnackbar('Erro ao atualizar módulos', 'error');
    }
  };

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  const getStatusLabel = (status) => {
    const labels = {
      active: 'ativado',
      standby: 'em standby',
      disabled: 'desativado',
    };
    return labels[status] || status;
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success',
      standby: 'warning',
      disabled: 'error',
    };
    return colors[status] || 'default';
  };

  const getStatusIcon = (status) => {
    const icons = {
      active: <ActiveIcon />,
      standby: <StandbyIcon />,
      disabled: <DisabledIcon />,
    };
    return icons[status] || <InfoIcon />;
  };

  const getCategoryIcon = (category) => {
    const icons = {
      siem: <DashboardIcon />,
      mdr: <ShieldIcon />,
      threat: <SecurityIcon />,
      analytics: <AnalyticsIcon />,
      protection: <SecurityIcon />,
    };
    return icons[category] || <DashboardIcon />;
  };

  const getTierColor = (tier) => {
    const colors = {
      free: 'default',
      basic: 'primary',
      premium: 'secondary',
      enterprise: 'error',
    };
    return colors[tier] || 'default';
  };

  const stats = {
    total: modules.length,
    active: modules.filter((m) => m.status === 'active').length,
    standby: modules.filter((m) => m.status === 'standby').length,
    disabled: modules.filter((m) => m.status === 'disabled').length,
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          <PowerIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Gerenciador de Módulos
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Ative ou desative módulos do sistema conforme necessário
        </Typography>
      </Box>

      {/* Statistics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total de Módulos
              </Typography>
              <Typography variant="h3">{stats.total}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ borderLeft: '4px solid #4caf50' }}>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Ativos
              </Typography>
              <Typography variant="h3" color="success.main">
                {stats.active}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ borderLeft: '4px solid #ff9800' }}>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Standby
              </Typography>
              <Typography variant="h3" color="warning.main">
                {stats.standby}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ borderLeft: '4px solid #f44336' }}>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Desativados
              </Typography>
              <Typography variant="h3" color="error.main">
                {stats.disabled}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                placeholder="Buscar módulos..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon />
                    </InputAdornment>
                  ),
                }}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <FormControl fullWidth>
                <InputLabel>Status</InputLabel>
                <Select
                  value={statusFilter}
                  label="Status"
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <MenuItem value="all">Todos</MenuItem>
                  <MenuItem value="active">Ativos</MenuItem>
                  <MenuItem value="standby">Standby</MenuItem>
                  <MenuItem value="disabled">Desativados</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={2}>
              <FormControl fullWidth>
                <InputLabel>Categoria</InputLabel>
                <Select
                  value={categoryFilter}
                  label="Categoria"
                  onChange={(e) => setCategoryFilter(e.target.value)}
                >
                  <MenuItem value="all">Todas</MenuItem>
                  <MenuItem value="siem">SIEM</MenuItem>
                  <MenuItem value="mdr">MDR</MenuItem>
                  <MenuItem value="threat">Threat</MenuItem>
                  <MenuItem value="analytics">Analytics</MenuItem>
                  <MenuItem value="protection">Protection</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={2}>
              <FormControl fullWidth>
                <InputLabel>Tier</InputLabel>
                <Select
                  value={tierFilter}
                  label="Tier"
                  onChange={(e) => setTierFilter(e.target.value)}
                >
                  <MenuItem value="all">Todos</MenuItem>
                  <MenuItem value="free">Free</MenuItem>
                  <MenuItem value="basic">Basic</MenuItem>
                  <MenuItem value="premium">Premium</MenuItem>
                  <MenuItem value="enterprise">Enterprise</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={2}>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<FilterIcon />}
                onClick={() => {
                  setSearchTerm('');
                  setCategoryFilter('all');
                  setStatusFilter('all');
                  setTierFilter('all');
                }}
              >
                Limpar
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label="Todos" />
          <Tab label="SIEM Base" />
          <Tab label="MDR" />
          <Tab label="Threat Intel" />
          <Tab label="Outros" />
        </Tabs>
      </Box>

      {/* Bulk Actions */}
      {filteredModules.length > 0 && (
        <Box sx={{ mb: 3, display: 'flex', gap: 2 }}>
          <Button
            variant="contained"
            color="success"
            onClick={() => handleBulkAction('active')}
          >
            Ativar Todos ({filteredModules.length})
          </Button>
          <Button
            variant="contained"
            color="warning"
            onClick={() => handleBulkAction('standby')}
          >
            Standby Todos ({filteredModules.length})
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={() => handleBulkAction('disabled')}
          >
            Desativar Todos ({filteredModules.length})
          </Button>
        </Box>
      )}

      {/* Module Cards */}
      <Grid container spacing={3}>
        {filteredModules.map((module) => (
          <Grid item xs={12} sm={6} md={4} key={module.id}>
            <Card
              sx={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                borderLeft: `4px solid ${
                  module.status === 'active'
                    ? '#4caf50'
                    : module.status === 'standby'
                    ? '#ff9800'
                    : '#f44336'
                }`,
              }}
            >
              <CardContent sx={{ flexGrow: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  {getCategoryIcon(module.category)}
                  <Typography variant="h6" sx={{ ml: 1, flexGrow: 1 }}>
                    {module.name}
                  </Typography>
                  {module.badge && (
                    <Chip label={module.badge} size="small" color="primary" />
                  )}
                </Box>

                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {module.description}
                </Typography>

                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 1 }}>
                  <Chip
                    icon={getStatusIcon(module.status)}
                    label={module.status.toUpperCase()}
                    color={getStatusColor(module.status)}
                    size="small"
                  />
                  <Chip
                    label={module.tier.toUpperCase()}
                    color={getTierColor(module.tier)}
                    size="small"
                  />
                  <Chip
                    label={module.category.toUpperCase()}
                    variant="outlined"
                    size="small"
                  />
                </Box>

                <Typography variant="caption" color="text.secondary">
                  Path: {module.path}
                </Typography>
              </CardContent>

              <CardActions sx={{ justifyContent: 'space-between', px: 2, pb: 2 }}>
                <Button
                  size="small"
                  color="success"
                  disabled={module.status === 'active'}
                  onClick={() => handleStatusChange(module, 'active')}
                >
                  Ativar
                </Button>
                <Button
                  size="small"
                  color="warning"
                  disabled={module.status === 'standby'}
                  onClick={() => handleStatusChange(module, 'standby')}
                >
                  Standby
                </Button>
                <Button
                  size="small"
                  color="error"
                  disabled={module.status === 'disabled'}
                  onClick={() => handleStatusChange(module, 'disabled')}
                >
                  Desativar
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      {filteredModules.length === 0 && !loading && (
        <Alert severity="info">
          Nenhum módulo encontrado com os filtros aplicados.
        </Alert>
      )}

      {/* Confirmation Dialog */}
      <Dialog open={confirmDialog.open} onClose={() => setConfirmDialog({ open: false })}>
        <DialogTitle>Confirmar Alteração</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Tem certeza que deseja {getStatusLabel(confirmDialog.action)} o módulo{' '}
            <strong>{confirmDialog.module?.name}</strong>?
          </DialogContentText>
          {confirmDialog.action === 'disabled' && (
            <Alert severity="warning" sx={{ mt: 2 }}>
              Atenção: Desativar este módulo pode afetar funcionalidades dependentes.
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmDialog({ open: false })}>Cancelar</Button>
          <Button onClick={confirmStatusChange} variant="contained" autoFocus>
            Confirmar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default ModuleManager;

