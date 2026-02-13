import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Button,
  Chip,
  Card,
  CardContent,
  Grid,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  OutlinedInput,
  Alert,
  Snackbar,
  Menu,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  InputAdornment,
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import {
  Add as AddIcon,
  NotificationsActive as NotificationsActiveIcon,
  Refresh as RefreshIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as VisibilityIcon,
  GetApp as ExportIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  TrendingUp as TrendingUpIcon,
  Email as EmailIcon,
  Sms as SmsIcon,
  Webhook as WebhookIcon,
  Notifications as NotificationsIcon,
  Search as SearchIcon,
  Clear as ClearIcon,
} from '@mui/icons-material';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend } from 'recharts';
import { alertsAPI, casesAPI } from '../services/api';
import FolderIcon from '@mui/icons-material/Folder';

const SEVERITY_COLORS = {
  CRITICAL: '#d32f2f',
  HIGH: '#f57c00',
  MEDIUM: '#fbc02d',
  LOW: '#388e3c',
  INFO: '#1976d2',
};

const SOURCE_COLORS = {
  guardduty: '#FF9800',
  securityhub: '#2196F3',
  cloudtrail: '#4CAF50',
  cloudflare: '#F48120',
  config: '#00BCD4',
  manual: '#607D8B',
};

const SOURCE_LABELS = {
  guardduty: 'GuardDuty',
  securityhub: 'Security Hub',
  cloudtrail: 'CloudTrail',
  cloudflare: 'CloudFlare',
  config: 'AWS Config',
  manual: 'Manual',
};

const CHART_COLORS = ['#8884d8', '#82ca9d', '#ffc658', '#ff7c7c', '#8dd1e1'];

const Alerts = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [selectedSeverities, setSelectedSeverities] = useState([]);
  const [selectedStatuses, setSelectedStatuses] = useState([]);
  const [selectedSources, setSelectedSources] = useState([]);
  const [searchQuery, setSearchQuery] = useState(''); // Busca por CVE, nome, descrição
  const [debouncedSearch, setDebouncedSearch] = useState(''); // Valor debounced para API
  const debounceTimer = useRef(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [exportMenuAnchor, setExportMenuAnchor] = useState(null);
  const [selectedAlertIds, setSelectedAlertIds] = useState([]);
  
  // Create Case from Alert
  const [createCaseDialogOpen, setCreateCaseDialogOpen] = useState(false);
  const [creatingCase, setCreatingCase] = useState(false);
  const [newCase, setNewCase] = useState({
    title: '',
    description: '',
    priority: 'medium',
    assignTo: '',
  });

  // Novo alerta
  const [newAlert, setNewAlert] = useState({
    name: '',
    description: '',
    query: '',
    severity: 'MEDIUM',
    condition: {
      threshold: 1,
      timeframe: '5m',
      field: '',
    },
    actions: [
      { type: 'email', config: { to: '' }, enabled: true },
    ],
  });

  const showSnackbar = useCallback((message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  }, []);

  // Debounce para busca - aguardar 500ms após parar de digitar
  useEffect(() => {
    if (debounceTimer.current) {
      clearTimeout(debounceTimer.current);
    }
    debounceTimer.current = setTimeout(() => {
      setDebouncedSearch(searchQuery);
    }, 500);

    return () => {
      if (debounceTimer.current) {
        clearTimeout(debounceTimer.current);
      }
    };
  }, [searchQuery]);

  const loadAlerts = useCallback(async () => {
    try {
      setLoading(true);
      const params = {
        page,
        page_size: pageSize,
      };

      if (selectedSeverities.length > 0) {
        params.severity = selectedSeverities.join(',');
      }
      if (selectedStatuses.length > 0) {
        params.status = selectedStatuses.join(',');
      }
      if (selectedSources.length > 0) {
        params.source = selectedSources.join(',');
      }
      if (debouncedSearch.trim()) {
        params.search = debouncedSearch.trim();
      }

      const response = await alertsAPI.list(params);
      setAlerts(response.data.alerts || []);
      setTotal(response.data.total || 0);
    } catch (error) {
      console.error('Failed to load alerts:', error);
      showSnackbar('Erro ao carregar alertas', 'error');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, selectedSeverities, selectedStatuses, selectedSources, debouncedSearch, showSnackbar]);

  const loadStatistics = useCallback(async () => {
    try {
      const response = await alertsAPI.getStatistics();
      setStatistics(response.data);
    } catch (error) {
      console.error('Failed to load statistics:', error);
    }
  }, []);

  useEffect(() => {
    loadAlerts();
    loadStatistics();
  }, [loadAlerts, loadStatistics]);

  const handleCreateAlert = async () => {
    try {
      setLoading(true);
      await alertsAPI.create(newAlert);
      showSnackbar('Alerta criado com sucesso!', 'success');
      setCreateDialogOpen(false);
      loadAlerts();
      loadStatistics();
      resetNewAlert();
    } catch (error) {
      console.error('Failed to create alert:', error);
      showSnackbar('Erro ao criar alerta', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateAlert = async () => {
    try {
      setLoading(true);
      await alertsAPI.update(selectedAlert.id, selectedAlert);
      showSnackbar('Alerta atualizado com sucesso!', 'success');
      setEditDialogOpen(false);
      loadAlerts();
      loadStatistics();
    } catch (error) {
      console.error('Failed to update alert:', error);
      showSnackbar('Erro ao atualizar alerta', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteAlert = async () => {
    try {
      setLoading(true);
      await alertsAPI.delete(selectedAlert.id);
      showSnackbar('Alerta deletado com sucesso!', 'success');
      setDeleteDialogOpen(false);
      setSelectedAlert(null);
      loadAlerts();
      loadStatistics();
    } catch (error) {
      console.error('Failed to delete alert:', error);
      showSnackbar('Erro ao deletar alerta', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = () => {
    loadAlerts();
    loadStatistics();
    showSnackbar('Dados atualizados', 'success');
  };

  // Open create case dialog with alert data
  const handleOpenCreateCase = (alert) => {
    setSelectedAlert(alert);
    setNewCase({
      title: `Investigação: ${alert.name || alert.title || 'Alerta'}`,
      description: alert.description || '',
      priority: (alert.severity || 'medium').toLowerCase(),
      assignTo: '',
    });
    setCreateCaseDialogOpen(true);
  };

  // Create case from alert
  const handleCreateCase = async () => {
    if (!selectedAlert) return;
    
    try {
      setCreatingCase(true);
      const response = await casesAPI.createFromAlert(selectedAlert.id, newCase);
      showSnackbar(`Caso criado com sucesso! ID: ${response.data?.data?.id || 'N/A'}`, 'success');
      setCreateCaseDialogOpen(false);
      setDetailsOpen(false);
      setNewCase({ title: '', description: '', priority: 'medium', assignTo: '' });
    } catch (error) {
      console.error('Failed to create case:', error);
      showSnackbar('Erro ao criar caso', 'error');
    } finally {
      setCreatingCase(false);
    }
  };

  const handleViewDetails = (alert) => {
    // Navegar para a página de detalhes completos do alerta
    navigate(`/alerts/${alert.id}`);
  };

  const handleEdit = (alert) => {
    setSelectedAlert(alert);
    setEditDialogOpen(true);
  };

  const handleDeleteClick = (alert) => {
    setSelectedAlert(alert);
    setDeleteDialogOpen(true);
  };

  const handleExport = async (format = 'json') => {
    setExportMenuAnchor(null);
    
    try {
      setLoading(true);
      showSnackbar(`Exportando alertas em formato ${format.toUpperCase()}...`, 'info');

      // Se há alertas selecionados, exportar localmente (dados já carregados)
    if (selectedAlertIds.length > 0) {
        const dataToExport = alerts.filter(alert => selectedAlertIds.includes(alert.id));
        exportLocalData(dataToExport, format);
        showSnackbar(`${dataToExport.length} alerta(s) selecionado(s) exportado(s) com sucesso!`, 'success');
        return;
      }

      // Caso contrário, buscar todos do servidor com filtros
      const params = { format };
      if (selectedSeverities.length > 0) {
        params.severity = selectedSeverities.join(',');
      }
      if (selectedStatuses.length > 0) {
        params.status = selectedStatuses.join(',');
      }
      if (selectedSources.length > 0) {
        params.source = selectedSources.join(',');
      }
      if (debouncedSearch.trim()) {
        params.search = debouncedSearch.trim();
      }

      const response = await alertsAPI.export(params);
      
      // Criar blob e fazer download
      const blob = new Blob([response.data], {
        type: format === 'json' ? 'application/json' : 'text/csv'
      });
      
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
      link.download = `alerts_export_${timestamp}.${format}`;
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      showSnackbar(`Alertas exportados com sucesso em ${format.toUpperCase()}!`, 'success');
    } catch (error) {
      console.error('Failed to export alerts:', error);
      showSnackbar('Erro ao exportar alertas', 'error');
    } finally {
      setLoading(false);
    }
  };

  const exportLocalData = (dataToExport, format) => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    const filename = `alerts_export_${timestamp}.${format}`;

    if (format === 'json') {
      const content = JSON.stringify({
        exported_at: new Date().toISOString(),
        total: dataToExport.length,
        alerts: dataToExport,
      }, null, 2);
      
      const blob = new Blob([content], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } else if (format === 'csv') {
      const headers = ['ID', 'Name', 'Severity', 'Status', 'Source', 'Category', 'Description', 'Created At'];
      const csvRows = [headers.join(',')];
      
      dataToExport.forEach(alert => {
        const row = [
          alert.id,
          `"${(alert.name || '').replace(/"/g, '""')}"`,
          alert.severity,
          alert.status,
          alert.source || '',
          alert.category || '',
          `"${(alert.description || '').replace(/"/g, '""').replace(/\n/g, ' ')}"`,
          new Date(alert.created_at).toISOString(),
        ];
        csvRows.push(row.join(','));
      });
      
      const content = csvRows.join('\n');
      const blob = new Blob([content], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    }
  };

  const resetNewAlert = () => {
    setNewAlert({
      name: '',
      description: '',
      query: '',
      severity: 'MEDIUM',
      condition: {
        threshold: 1,
        timeframe: '5m',
        field: '',
      },
      actions: [
        { type: 'email', config: { to: '' }, enabled: true },
      ],
    });
  };

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const getActionIcon = (type) => {
    switch (type) {
      case 'email': return <EmailIcon fontSize="small" />;
      case 'sms': return <SmsIcon fontSize="small" />;
      case 'webhook': return <WebhookIcon fontSize="small" />;
      case 'slack': return <NotificationsIcon fontSize="small" />;
      default: return <NotificationsIcon fontSize="small" />;
    }
  };

  const columns = [
    {
      field: 'name',
      headerName: 'Nome',
      flex: 1,
      minWidth: 200,
    },
    {
      field: 'severity',
      headerName: 'Severidade',
      width: 110,
      renderCell: (params) => (
        <Chip
          label={params.value}
          size="small"
          sx={{
            backgroundColor: SEVERITY_COLORS[params.value] || '#999',
            color: 'white',
            fontWeight: 'bold',
          }}
        />
      ),
    },
    {
      field: 'source',
      headerName: 'Origem',
      width: 130,
      renderCell: (params) => {
        const source = params.value || 'manual';
        return (
          <Chip
            label={SOURCE_LABELS[source] || source}
            size="small"
            sx={{
              backgroundColor: SOURCE_COLORS[source] || '#607D8B',
              color: 'white',
              fontWeight: 'bold',
            }}
          />
        );
      },
    },
    {
      field: 'status',
      headerName: 'Status',
      width: 100,
      renderCell: (params) => (
        <Chip
          label={params.value === 'active' ? 'Ativo' : 'Inativo'}
          size="small"
          color={params.value === 'active' ? 'success' : 'default'}
        />
      ),
    },
    {
      field: 'last_triggered',
      headerName: 'Último Trigger',
      width: 160,
      valueFormatter: (params) => {
        if (!params.value) return 'Nunca';
        const date = new Date(params.value);
        return date.toLocaleString('pt-BR');
      },
    },
    {
      field: 'actions',
      headerName: 'Ações',
      width: 150,
      sortable: false,
      renderCell: (params) => (
        <Box>
          <Tooltip title="Ver Detalhes">
            <IconButton
              size="small"
              onClick={() => handleViewDetails(params.row)}
              color="primary"
            >
              <VisibilityIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Editar">
            <IconButton
              size="small"
              onClick={() => handleEdit(params.row)}
              color="primary"
            >
              <EditIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Deletar">
            <IconButton
              size="small"
              onClick={() => handleDeleteClick(params.row)}
              color="error"
            >
              <DeleteIcon />
            </IconButton>
          </Tooltip>
        </Box>
      ),
    },
  ];

  // Preparar dados para gráfico
  const severityChartData = statistics?.by_severity
    ? Object.entries(statistics.by_severity).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          Alertas
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Atualizar">
            <IconButton onClick={handleRefresh} color="primary">
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Exportar">
            <IconButton 
              onClick={(e) => setExportMenuAnchor(e.currentTarget)} 
              color="primary"
            >
              <ExportIcon />
            </IconButton>
          </Tooltip>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setCreateDialogOpen(true)}
          >
            Novo Alerta
          </Button>
        </Box>
      </Box>

      {/* Menu de Exportação */}
      <Menu
        anchorEl={exportMenuAnchor}
        open={Boolean(exportMenuAnchor)}
        onClose={() => setExportMenuAnchor(null)}
      >
        <MenuItem onClick={() => handleExport('csv')}>
          <Box sx={{ display: 'flex', flexDirection: 'column' }}>
            <Typography variant="body1">Exportar como CSV</Typography>
            <Typography variant="caption" color="text.secondary">
              {selectedAlertIds.length > 0 
                ? `${selectedAlertIds.length} alerta(s) selecionado(s)` 
                : 'Todos os alertas'}
            </Typography>
          </Box>
        </MenuItem>
        <MenuItem onClick={() => handleExport('json')}>
          <Box sx={{ display: 'flex', flexDirection: 'column' }}>
            <Typography variant="body1">Exportar como JSON</Typography>
            <Typography variant="caption" color="text.secondary">
              {selectedAlertIds.length > 0 
                ? `${selectedAlertIds.length} alerta(s) selecionado(s)` 
                : 'Todos os alertas'}
            </Typography>
          </Box>
        </MenuItem>
      </Menu>

      {/* Estatísticas */}
      {statistics && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Total de Alertas
                    </Typography>
                    <Typography variant="h4">
                      {statistics.total}
                    </Typography>
                  </Box>
                  <InfoIcon sx={{ fontSize: 40, color: 'primary.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Alertas Ativos
                    </Typography>
                    <Typography variant="h4" color="success.main">
                      {statistics.active}
                    </Typography>
                  </Box>
                  <NotificationsActiveIcon sx={{ fontSize: 40, color: 'success.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Triggers (24h)
                    </Typography>
                    <Typography variant="h4" color="warning.main">
                      {statistics.triggered_last_24h}
                    </Typography>
                  </Box>
                  <TrendingUpIcon sx={{ fontSize: 40, color: 'warning.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Alertas Inativos
                    </Typography>
                    <Typography variant="h4">
                      {statistics.inactive}
                    </Typography>
                  </Box>
                  <WarningIcon sx={{ fontSize: 40, color: 'text.secondary', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Alertas por Severidade
              </Typography>
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={severityChartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    label
                  >
                    {severityChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || CHART_COLORS[index % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* Filtros */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2}>
          {/* Campo de Busca por CVE/Texto */}
          <Grid item xs={12}>
            <TextField
              fullWidth
              size="small"
              placeholder="Buscar por CVE, nome ou descrição... (ex: CVE-2024-45337) - Pressione Enter para buscar"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  // Busca imediata ao pressionar Enter
                  setDebouncedSearch(searchQuery);
                }
              }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon color="action" />
                  </InputAdornment>
                ),
                endAdornment: searchQuery && (
                  <InputAdornment position="end">
                    <IconButton
                      size="small"
                      onClick={() => {
                        setSearchQuery('');
                        setDebouncedSearch('');
                      }}
                      edge="end"
                    >
                      <ClearIcon fontSize="small" />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
              sx={{
                '& .MuiOutlinedInput-root': {
                  backgroundColor: 'background.paper',
                },
              }}
            />
          </Grid>

          <Grid item xs={12} md={4}>
            <FormControl fullWidth size="small">
              <InputLabel>Severidade</InputLabel>
              <Select
                multiple
                value={selectedSeverities}
                onChange={(e) => setSelectedSeverities(e.target.value)}
                input={<OutlinedInput label="Severidade" />}
                renderValue={(selected) => selected.join(', ')}
              >
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((severity) => (
                  <MenuItem key={severity} value={severity}>
                    {severity}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} md={4}>
            <FormControl fullWidth size="small">
              <InputLabel>Origem</InputLabel>
              <Select
                multiple
                value={selectedSources}
                onChange={(e) => setSelectedSources(e.target.value)}
                input={<OutlinedInput label="Origem" />}
                renderValue={(selected) => selected.map(s => SOURCE_LABELS[s] || s).join(', ')}
              >
                {Object.entries(SOURCE_LABELS).map(([key, label]) => (
                  <MenuItem key={key} value={key}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Box
                        sx={{
                          width: 12,
                          height: 12,
                          borderRadius: '50%',
                          backgroundColor: SOURCE_COLORS[key],
                        }}
                      />
                      {label}
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} md={4}>
            <FormControl fullWidth size="small">
              <InputLabel>Status</InputLabel>
              <Select
                multiple
                value={selectedStatuses}
                onChange={(e) => setSelectedStatuses(e.target.value)}
                input={<OutlinedInput label="Status" />}
                renderValue={(selected) => selected.map(s => s === 'active' ? 'Ativo' : 'Inativo').join(', ')}
              >
                <MenuItem value="active">Ativo</MenuItem>
                <MenuItem value="inactive">Inativo</MenuItem>
              </Select>
            </FormControl>
          </Grid>
        </Grid>
      </Paper>

      {/* Tabela de Alertas */}
      <Paper sx={{ height: 600, width: '100%' }}>
        {selectedAlertIds.length > 0 && (
          <Box sx={{ p: 2, backgroundColor: 'primary.light', color: 'primary.contrastText' }}>
            <Typography variant="body2">
              {selectedAlertIds.length} alerta(s) selecionado(s)
              <Button
                size="small"
                onClick={() => setSelectedAlertIds([])}
                sx={{ ml: 2, color: 'inherit' }}
              >
                Limpar Seleção
              </Button>
            </Typography>
          </Box>
        )}
        <DataGrid
          rows={alerts}
          columns={columns}
          page={page - 1}
          pageSize={pageSize}
          rowCount={total}
          paginationMode="server"
          onPageChange={(newPage) => setPage(newPage + 1)}
          onPageSizeChange={(newPageSize) => setPageSize(newPageSize)}
          rowsPerPageOptions={[10, 20, 50, 100]}
          loading={loading}
          checkboxSelection
          rowSelectionModel={selectedAlertIds}
          onRowSelectionModelChange={(newSelection) => {
            setSelectedAlertIds(newSelection);
          }}
          keepNonExistentRowsSelected
          disableRowSelectionOnClick
          sx={{
            '& .MuiDataGrid-cell': {
              borderBottom: '1px solid rgba(224, 224, 224, 1)',
            },
          }}
        />
      </Paper>

      {/* Dialog de Detalhes */}
      <Dialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Detalhes do Alerta
        </DialogTitle>
        <DialogContent>
          {selectedAlert && (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>
                    {selectedAlert.name}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  <Chip
                    label={selectedAlert.severity}
                    size="small"
                    sx={{
                      backgroundColor: SEVERITY_COLORS[selectedAlert.severity] || '#999',
                      color: 'white',
                      fontWeight: 'bold',
                      }}
                    />
                    <Chip
                      label={SOURCE_LABELS[selectedAlert.source] || selectedAlert.source || 'Manual'}
                      size="small"
                      sx={{
                        backgroundColor: SOURCE_COLORS[selectedAlert.source] || '#607D8B',
                        color: 'white',
                        fontWeight: 'bold',
                    }}
                  />
                  <Chip
                    label={selectedAlert.status === 'active' ? 'Ativo' : 'Inativo'}
                    size="small"
                    color={selectedAlert.status === 'active' ? 'success' : 'default'}
                  />
                  </Box>
                </Grid>

                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Descrição
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedAlert.description}
                  </Typography>
                </Grid>

                {/* Informações de Origem */}
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Informações da Origem
                  </Typography>
                  <Paper sx={{ p: 2, backgroundColor: 'background.default' }}>
                    <Grid container spacing={2}>
                      <Grid item xs={6} md={3}>
                        <Typography variant="caption" color="text.secondary">Origem</Typography>
                        <Typography variant="body2" fontWeight="bold">
                          {SOURCE_LABELS[selectedAlert.source] || selectedAlert.source || 'Manual'}
                        </Typography>
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <Typography variant="caption" color="text.secondary">Categoria</Typography>
                        <Typography variant="body2">
                          {selectedAlert.category || 'N/A'}
                        </Typography>
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <Typography variant="caption" color="text.secondary">Região</Typography>
                        <Typography variant="body2">
                          {selectedAlert.region || 'N/A'}
                        </Typography>
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <Typography variant="caption" color="text.secondary">Conta AWS</Typography>
                        <Typography variant="body2" fontFamily="monospace">
                          {selectedAlert.account_id || 'N/A'}
                        </Typography>
                      </Grid>
                      {selectedAlert.resource_id && (
                        <>
                          <Grid item xs={6}>
                            <Typography variant="caption" color="text.secondary">Recurso ID</Typography>
                            <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: 'break-all' }}>
                              {selectedAlert.resource_id}
                            </Typography>
                          </Grid>
                          <Grid item xs={6}>
                            <Typography variant="caption" color="text.secondary">Tipo de Recurso</Typography>
                            <Typography variant="body2">
                              {selectedAlert.resource_type || 'N/A'}
                            </Typography>
                          </Grid>
                        </>
                      )}
                    </Grid>
                  </Paper>
                </Grid>

                {selectedAlert.query && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">
                      ID do Finding Original
                  </Typography>
                  <Paper sx={{ 
                    p: 2, 
                    backgroundColor: '#0d1117', 
                    border: '1px solid #30363d',
                    borderRadius: 1
                  }}>
                    <Typography 
                      variant="body2" 
                      sx={{ 
                        fontFamily: 'monospace',
                        color: '#c9d1d9',
                        wordBreak: 'break-all',
                        whiteSpace: 'pre-wrap'
                      }}
                    >
                        {selectedAlert.query || selectedAlert.source_id || 'N/A'}
                    </Typography>
                  </Paper>
                </Grid>
                )}

                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Ações Configuradas
                  </Typography>
                  <List dense>
                    {selectedAlert.actions && selectedAlert.actions.length > 0 ? (
                      selectedAlert.actions.map((action, index) => (
                      <ListItem key={index}>
                        <ListItemIcon>
                          {getActionIcon(action.type)}
                        </ListItemIcon>
                        <ListItemText
                          primary={action.type.toUpperCase()}
                          secondary={JSON.stringify(action.config)}
                        />
                        <Chip
                          label={action.enabled ? 'Ativo' : 'Inativo'}
                          size="small"
                          color={action.enabled ? 'success' : 'default'}
                        />
                      </ListItem>
                      ))
                    ) : (
                      <ListItem>
                        <ListItemText
                          primary="Nenhuma ação configurada"
                          secondary="Este alerta foi importado automaticamente"
                        />
                      </ListItem>
                    )}
                  </List>
                </Grid>

                {selectedAlert.last_triggered && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Último Trigger
                    </Typography>
                    <Typography variant="body1">
                      {new Date(selectedAlert.last_triggered).toLocaleString('pt-BR')}
                    </Typography>
                  </Grid>
                )}
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button 
            startIcon={<FolderIcon />}
            variant="contained"
            color="primary"
            onClick={() => handleOpenCreateCase(selectedAlert)}
          >
            Criar Caso
          </Button>
          <Button onClick={() => setDetailsOpen(false)}>
            Fechar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Criar Caso a partir do Alerta */}
      <Dialog
        open={createCaseDialogOpen}
        onClose={() => setCreateCaseDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          Criar Caso a partir do Alerta
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <TextField
              fullWidth
              label="Título do Caso"
              value={newCase.title}
              onChange={(e) => setNewCase({ ...newCase, title: e.target.value })}
              sx={{ mb: 2 }}
            />
            <TextField
              fullWidth
              multiline
              rows={4}
              label="Descrição"
              value={newCase.description}
              onChange={(e) => setNewCase({ ...newCase, description: e.target.value })}
              sx={{ mb: 2 }}
            />
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Prioridade</InputLabel>
              <Select
                value={newCase.priority}
                label="Prioridade"
                onChange={(e) => setNewCase({ ...newCase, priority: e.target.value })}
              >
                <MenuItem value="critical">Crítica</MenuItem>
                <MenuItem value="high">Alta</MenuItem>
                <MenuItem value="medium">Média</MenuItem>
                <MenuItem value="low">Baixa</MenuItem>
              </Select>
            </FormControl>
            <TextField
              fullWidth
              label="Atribuir para (opcional)"
              value={newCase.assignTo}
              onChange={(e) => setNewCase({ ...newCase, assignTo: e.target.value })}
              placeholder="Nome do analista"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateCaseDialogOpen(false)} disabled={creatingCase}>
            Cancelar
          </Button>
          <Button 
            variant="contained" 
            color="primary" 
            onClick={handleCreateCase}
            disabled={creatingCase || !newCase.title}
          >
            {creatingCase ? 'Criando...' : 'Criar Caso'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Criar Alerta */}
      <Dialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Criar Novo Alerta</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Nome"
                  value={newAlert.name}
                  onChange={(e) => setNewAlert({ ...newAlert, name: e.target.value })}
                  required
                />
              </Grid>

              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Descrição"
                  value={newAlert.description}
                  onChange={(e) => setNewAlert({ ...newAlert, description: e.target.value })}
                  multiline
                  rows={2}
                  required
                />
              </Grid>

              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Query"
                  value={newAlert.query}
                  onChange={(e) => setNewAlert({ ...newAlert, query: e.target.value })}
                  multiline
                  rows={3}
                  required
                  helperText="Ex: event.type:login AND event.outcome:failure"
                />
              </Grid>

              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Severidade</InputLabel>
                  <Select
                    value={newAlert.severity}
                    onChange={(e) => setNewAlert({ ...newAlert, severity: e.target.value })}
                    label="Severidade"
                  >
                    <MenuItem value="CRITICAL">CRITICAL</MenuItem>
                    <MenuItem value="HIGH">HIGH</MenuItem>
                    <MenuItem value="MEDIUM">MEDIUM</MenuItem>
                    <MenuItem value="LOW">LOW</MenuItem>
                    <MenuItem value="INFO">INFO</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12}>
                <Divider sx={{ my: 2 }} />
                <Typography variant="subtitle1" gutterBottom>
                  Condições
                </Typography>
              </Grid>

              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="Threshold"
                  type="number"
                  value={newAlert.condition.threshold}
                  onChange={(e) => setNewAlert({
                    ...newAlert,
                    condition: { ...newAlert.condition, threshold: parseInt(e.target.value) }
                  })}
                />
              </Grid>

              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="Timeframe"
                  value={newAlert.condition.timeframe}
                  onChange={(e) => setNewAlert({
                    ...newAlert,
                    condition: { ...newAlert.condition, timeframe: e.target.value }
                  })}
                  helperText="Ex: 5m, 1h, 1d"
                />
              </Grid>

              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="Campo"
                  value={newAlert.condition.field}
                  onChange={(e) => setNewAlert({
                    ...newAlert,
                    condition: { ...newAlert.condition, field: e.target.value }
                  })}
                />
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>
            Cancelar
          </Button>
          <Button 
            onClick={handleCreateAlert} 
            variant="contained"
            disabled={!newAlert.name || !newAlert.query || !newAlert.severity}
          >
            Criar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Editar */}
      <Dialog
        open={editDialogOpen}
        onClose={() => setEditDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Editar Alerta</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Nome"
                  value={selectedAlert?.name || ''}
                  onChange={(e) => setSelectedAlert({ ...selectedAlert, name: e.target.value })}
                />
              </Grid>

              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Descrição"
                  value={selectedAlert?.description || ''}
                  onChange={(e) => setSelectedAlert({ ...selectedAlert, description: e.target.value })}
                  multiline
                  rows={3}
                />
              </Grid>

              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Severidade</InputLabel>
                  <Select
                    value={selectedAlert?.severity || 'MEDIUM'}
                    onChange={(e) => setSelectedAlert({ ...selectedAlert, severity: e.target.value })}
                    label="Severidade"
                  >
                    <MenuItem value="CRITICAL">CRITICAL</MenuItem>
                    <MenuItem value="HIGH">HIGH</MenuItem>
                    <MenuItem value="MEDIUM">MEDIUM</MenuItem>
                    <MenuItem value="LOW">LOW</MenuItem>
                    <MenuItem value="INFO">INFO</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Status</InputLabel>
                  <Select
                    value={selectedAlert?.status || 'new'}
                    onChange={(e) => setSelectedAlert({ ...selectedAlert, status: e.target.value })}
                    label="Status"
                  >
                    <MenuItem value="new">Novo</MenuItem>
                    <MenuItem value="acknowledged">Reconhecido</MenuItem>
                    <MenuItem value="investigating">Investigando</MenuItem>
                    <MenuItem value="resolved">Resolvido</MenuItem>
                    <MenuItem value="dismissed">Dispensado</MenuItem>
                    <MenuItem value="false_positive">Falso Positivo</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Notas"
                  value={selectedAlert?.notes || ''}
                  onChange={(e) => setSelectedAlert({ ...selectedAlert, notes: e.target.value })}
                  multiline
                  rows={3}
                  placeholder="Adicione notas sobre este alerta..."
                />
              </Grid>

              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Atribuído a"
                  value={selectedAlert?.assigned_to || selectedAlert?.triaged_by || ''}
                  onChange={(e) => setSelectedAlert({ ...selectedAlert, assigned_to: e.target.value })}
                  placeholder="Nome do analista responsável"
                />
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialogOpen(false)}>
            Cancelar
          </Button>
          <Button 
            onClick={handleUpdateAlert} 
            variant="contained"
            color="primary"
          >
            Salvar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Deletar */}
      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
      >
        <DialogTitle>Confirmar Exclusão</DialogTitle>
        <DialogContent>
          <Typography>
            Tem certeza que deseja deletar o alerta "{selectedAlert?.name}"?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>
            Cancelar
          </Button>
          <Button onClick={handleDeleteAlert} color="error" variant="contained">
            Deletar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert onClose={handleCloseSnackbar} severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Alerts;
