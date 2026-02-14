import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Grid,
  Typography,
  Button,
  Card,
  CardContent,
  Box,
  Chip,
  IconButton,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  CircularProgress,
  Alert,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Snackbar,
  Menu,
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import {
  Add as AddIcon,
  Visibility as ViewIcon,
  FilterList as FilterIcon,
  Refresh as RefreshIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Schedule as ScheduleIcon,
  FileDownload as ExportIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import { casesAPI } from '../services/api';

const SEVERITY_COLORS = {
  CRITICAL: '#d32f2f',
  HIGH: '#f57c00',
  MEDIUM: '#fbc02d',
  LOW: '#66bb6a',
};

const STATUS_COLORS = {
  NEW: '#2196f3',
  IN_PROGRESS: '#ff9800',
  RESOLVED: '#4caf50',
  CLOSED: '#9e9e9e',
};

const Cases = () => {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Filtros
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  
  // Paginação
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  
  // Seleção
  const [selectedCaseIds, setSelectedCaseIds] = useState([]);
  
  // Dialogs
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [selectedCase, setSelectedCase] = useState(null);
  
  // Snackbar
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  
  // Export menu
  const [exportMenuAnchor, setExportMenuAnchor] = useState(null);

  useEffect(() => {
    loadData();
  }, [statusFilter, severityFilter]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Carregar casos e estatísticas em paralelo
      const [casesResponse, statsResponse] = await Promise.all([
        casesAPI.list({ status: statusFilter, severity: severityFilter }),
        casesAPI.getStatistics(),
      ]);
      
      if (casesResponse.data && casesResponse.data.cases) {
        setCases(casesResponse.data.cases);
      }
      
      if (statsResponse.data) {
        setStatistics(statsResponse.data);
      }
    } catch (err) {
      console.error('Erro ao carregar casos:', err);
      setError('Erro ao carregar casos. Verifique a conexão com a API.');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'new': return 'info';
      case 'in_progress': return 'warning';
      case 'resolved': return 'success';
      case 'closed': return 'default';
      default: return 'default';
    }
  };

  const getStatusIcon = (status) => {
    switch (status?.toLowerCase()) {
      case 'new': return <ScheduleIcon fontSize="small" />;
      case 'in_progress': return <WarningIcon fontSize="small" />;
      case 'resolved': return <CheckCircleIcon fontSize="small" />;
      case 'closed': return <CheckCircleIcon fontSize="small" />;
      default: return null;
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString('pt-BR');
  };

  const formatDuration = (seconds) => {
    if (!seconds || seconds <= 0) return 'N/A';
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const getStatusLabel = (status) => {
    const labels = {
      'new': 'Novo',
      'in_progress': 'Em Progresso',
      'resolved': 'Resolvido',
      'closed': 'Fechado',
    };
    return labels[status] || status;
  };

  const getSeverityLabel = (severity) => {
    const labels = {
      'critical': 'Crítico',
      'high': 'Alto',
      'medium': 'Médio',
      'low': 'Baixo',
    };
    return labels[severity] || severity;
  };

  const getCategoryLabel = (category) => {
    const labels = {
      'malware': 'Malware',
      'phishing': 'Phishing',
      'unauthorized_access': 'Acesso Não Autorizado',
      'data_breach': 'Vazamento de Dados',
      'web_attack': 'Ataque Web',
      'dos_attack': 'Ataque DoS/DDoS',
      'privilege_escalation': 'Escalação de Privilégios',
      'advanced_threat': 'Ameaça Avançada',
    };
    return labels[category] || category;
  };

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const handleViewDetails = (caseItem) => {
    setSelectedCase(caseItem);
    setDetailsDialogOpen(true);
  };

  const handleExport = async (format) => {
    setExportMenuAnchor(null);
    
    try {
      setLoading(true);
      showSnackbar(`Exportando casos em formato ${format.toUpperCase()}...`, 'info');

      // Se há casos selecionados, exportar localmente (dados já carregados)
    if (selectedCaseIds.length > 0) {
      const selectedCases = cases.filter(c => selectedCaseIds.includes(c.id));
        exportLocalCases(selectedCases, format);
        showSnackbar(`${selectedCases.length} caso(s) selecionado(s) exportado(s) com sucesso!`, 'success');
        return;
      }

      // Caso contrário, buscar todos do servidor com filtros
      const params = { format };
      if (statusFilter) {
        params.status = statusFilter;
      }
      if (severityFilter) {
        params.severity = severityFilter;
      }
      if (searchTerm.trim()) {
        params.search = searchTerm.trim();
      }

      const response = await casesAPI.export(params);
      
      // Criar blob e fazer download
      const blob = new Blob([response.data], {
        type: format === 'json' ? 'application/json' : 'text/csv'
      });
      
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
      link.download = `cases_export_${timestamp}.${format}`;
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      showSnackbar(`Casos exportados com sucesso em ${format.toUpperCase()}!`, 'success');
    } catch (error) {
      console.error('Failed to export cases:', error);
      showSnackbar('Erro ao exportar casos', 'error');
    } finally {
      setLoading(false);
    }
  };

  const exportLocalCases = (casesToExport, format) => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    
    if (format === 'csv') {
    const headers = ['ID', 'Título', 'Severidade', 'Status', 'Categoria', 'Atribuído', 'Criado Em', 'SLA Breach'];
    const rows = casesToExport.map(c => [
      c.id,
      c.title,
      c.severity,
      c.status,
      c.category,
      c.assignedTo || 'N/A',
      formatDate(c.createdAt),
      c.slaBreach ? 'Sim' : 'Não',
    ]);
    
    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
      link.download = `cases_export_${timestamp}.csv`;
    link.click();
    } else {
    const jsonContent = JSON.stringify({
      exported_at: new Date().toISOString(),
      total: casesToExport.length,
      cases: casesToExport,
    }, null, 2);
    
    const blob = new Blob([jsonContent], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
      link.download = `cases_export_${timestamp}.json`;
    link.click();
    }
  };

  // Filtrar casos por termo de busca
  const filteredCases = cases.filter(c => 
    searchTerm === '' || 
    c.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    c.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    c.category?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Preparar dados para gráficos
  const severityChartData = statistics ? Object.entries(statistics.bySeverity || {}).map(([key, value]) => ({
    name: getSeverityLabel(key),
    value: value,
    color: SEVERITY_COLORS[key.toUpperCase()] || '#999',
  })) : [];

  const categoryChartData = statistics ? Object.entries(statistics.byCategory || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([key, value]) => ({
      name: getCategoryLabel(key),
      value: value,
    })) : [];

  // Colunas do DataGrid
  const columns = [
    {
      field: 'id',
      headerName: 'ID',
      width: 90,
      renderCell: (params) => (
        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
          {params.value.substring(0, 8)}
        </Typography>
      ),
    },
    {
      field: 'title',
      headerName: 'Título',
      flex: 1,
      minWidth: 200,
      renderCell: (params) => (
        <Box>
          <Typography variant="body2" fontWeight={600} noWrap>
            {params.value}
          </Typography>
          <Typography variant="caption" color="text.secondary" noWrap>
            {getCategoryLabel(params.row.category)}
          </Typography>
        </Box>
      ),
    },
    {
      field: 'severity',
      headerName: 'Severidade',
      width: 110,
      renderCell: (params) => (
        <Chip
          label={getSeverityLabel(params.value)}
          color={getSeverityColor(params.value)}
          size="small"
        />
      ),
    },
    {
      field: 'status',
      headerName: 'Status',
      width: 140,
      renderCell: (params) => (
        <Chip
          icon={getStatusIcon(params.value)}
          label={getStatusLabel(params.value)}
          color={getStatusColor(params.value)}
          size="small"
        />
      ),
    },
    {
      field: 'assignedTo',
      headerName: 'Atribuído',
      width: 110,
    },
    {
      field: 'createdAt',
      headerName: 'Criado Em',
      width: 150,
      renderCell: (params) => formatDate(params.value),
    },
    {
      field: 'slaBreach',
      headerName: 'SLA',
      width: 100,
      renderCell: (params) => (
        <Tooltip title={params.value ? 'SLA violado!' : 'Dentro do SLA'}>
          <Chip
            icon={params.value ? <ErrorIcon /> : <CheckCircleIcon />}
            label={formatDuration(params.row.slaRemaining)}
            color={params.value ? 'error' : 'success'}
            size="small"
          />
        </Tooltip>
      ),
    },
    {
      field: 'actions',
      headerName: 'Ações',
      width: 80,
      sortable: false,
      renderCell: (params) => (
        <IconButton
          size="small"
          color="primary"
          onClick={() => handleViewDetails(params.row)}
        >
          <ViewIcon />
        </IconButton>
      ),
    },
  ];

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          🎯 Gestão de Casos
        </Typography>
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
            variant="outlined"
            startIcon={<ExportIcon />}
            onClick={(e) => setExportMenuAnchor(e.currentTarget)}
            sx={{ mr: 1 }}
          >
            Exportar
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => navigate('/cases/new')}
          >
            Novo Caso
          </Button>
        </Box>
      </Box>

      {/* Export Menu */}
      <Menu
        anchorEl={exportMenuAnchor}
        open={Boolean(exportMenuAnchor)}
        onClose={() => setExportMenuAnchor(null)}
      >
        <MenuItem onClick={() => handleExport('csv')}>
          Exportar como CSV {selectedCaseIds.length > 0 && `(${selectedCaseIds.length} selecionados)`}
        </MenuItem>
        <MenuItem onClick={() => handleExport('json')}>
          Exportar como JSON {selectedCaseIds.length > 0 && `(${selectedCaseIds.length} selecionados)`}
        </MenuItem>
      </Menu>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Estatísticas */}
      {statistics && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card sx={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
              <CardContent>
                <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                  Total de Casos
                </Typography>
                <Typography variant="h3" color="white">
                  {statistics.total}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card sx={{ background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)' }}>
              <CardContent>
                <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                  Novos
                </Typography>
                <Typography variant="h3" color="white">
                  {statistics.new}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card sx={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)' }}>
              <CardContent>
                <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                  Em Progresso
                </Typography>
                <Typography variant="h3" color="white">
                  {statistics.inProgress}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card sx={{ background: 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)' }}>
              <CardContent>
                <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                  Resolvidos
                </Typography>
                <Typography variant="h3" color="white">
                  {statistics.resolved}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card sx={{ background: 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)' }}>
              <CardContent>
                <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                  SLA Breach
                </Typography>
                <Typography variant="h3" color="white">
                  {statistics.slaBreaches}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Gráficos */}
      {statistics && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Distribuição por Severidade
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={severityChartData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {severityChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
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
                  Top 5 Categorias
                </Typography>
                <Box sx={{ width: '100%', overflow: 'hidden' }}>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={categoryChartData} margin={{ bottom: 60, left: 10, right: 10 }}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis 
                        dataKey="name" 
                        angle={-45} 
                        textAnchor="end" 
                        height={80}
                        interval={0}
                        tick={{ fontSize: 11 }}
                      />
                      <YAxis />
                      <RechartsTooltip />
                      <Bar dataKey="value" fill="#667eea" />
                    </BarChart>
                  </ResponsiveContainer>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Filtros */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                size="small"
                label="Buscar"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Buscar por título, descrição ou categoria..."
              />
            </Grid>
            <Grid item xs={12} sm={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Status</InputLabel>
                <Select
                  value={statusFilter}
                  label="Status"
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <MenuItem value="">Todos</MenuItem>
                  <MenuItem value="new">Novo</MenuItem>
                  <MenuItem value="in_progress">Em Progresso</MenuItem>
                  <MenuItem value="resolved">Resolvido</MenuItem>
                  <MenuItem value="closed">Fechado</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Severidade</InputLabel>
                <Select
                  value={severityFilter}
                  label="Severidade"
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <MenuItem value="">Todas</MenuItem>
                  <MenuItem value="critical">Crítico</MenuItem>
                  <MenuItem value="high">Alto</MenuItem>
                  <MenuItem value="medium">Médio</MenuItem>
                  <MenuItem value="low">Baixo</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={2}>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<FilterIcon />}
                onClick={() => {
                  setStatusFilter('');
                  setSeverityFilter('');
                  setSearchTerm('');
                }}
              >
                Limpar
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Seleção Info */}
      {selectedCaseIds.length > 0 && (
        <Box sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="body2" color="primary">
            {selectedCaseIds.length} caso(s) selecionado(s)
          </Typography>
          <Button
            size="small"
            variant="outlined"
            onClick={() => setSelectedCaseIds([])}
          >
            Limpar Seleção
          </Button>
        </Box>
      )}

      {/* DataGrid */}
      <Card>
        <Box sx={{ width: '100%', overflow: 'hidden' }}>
          <DataGrid
            rows={filteredCases}
            columns={columns}
            pageSize={pageSize}
            onPageSizeChange={(newSize) => setPageSize(newSize)}
            rowsPerPageOptions={[10, 25, 50, 100]}
            checkboxSelection
            disableRowSelectionOnClick
            rowSelectionModel={selectedCaseIds}
            onRowSelectionModelChange={(newSelection) => {
              setSelectedCaseIds(newSelection);
            }}
            autoHeight
            disableColumnMenu
            sx={{
              '& .MuiDataGrid-cell': {
                borderBottom: '1px solid rgba(224, 224, 224, 1)',
              },
              '& .MuiDataGrid-root': {
                overflowX: 'auto',
              },
            }}
          />
        </Box>
      </Card>

      {/* Details Dialog */}
      <Dialog
        open={detailsDialogOpen}
        onClose={() => setDetailsDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h6">Detalhes do Caso</Typography>
            <IconButton onClick={() => setDetailsDialogOpen(false)}>
              <CloseIcon />
            </IconButton>
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          {selectedCase && (
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary">ID</Typography>
                <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>{selectedCase.id}</Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary">Título</Typography>
                <Typography variant="body1" fontWeight={600}>{selectedCase.title}</Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary">Descrição</Typography>
                <Typography variant="body2">{selectedCase.description}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="subtitle2" color="text.secondary">Severidade</Typography>
                <Chip
                  label={getSeverityLabel(selectedCase.severity)}
                  color={getSeverityColor(selectedCase.severity)}
                  size="small"
                  sx={{ mt: 0.5 }}
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="subtitle2" color="text.secondary">Status</Typography>
                <Chip
                  icon={getStatusIcon(selectedCase.status)}
                  label={getStatusLabel(selectedCase.status)}
                  color={getStatusColor(selectedCase.status)}
                  size="small"
                  sx={{ mt: 0.5 }}
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="subtitle2" color="text.secondary">Categoria</Typography>
                <Typography variant="body2">{getCategoryLabel(selectedCase.category)}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="subtitle2" color="text.secondary">Atribuído</Typography>
                <Typography variant="body2">{selectedCase.assignedTo || 'N/A'}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="subtitle2" color="text.secondary">Criado Por</Typography>
                <Typography variant="body2">{selectedCase.createdBy || 'N/A'}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="subtitle2" color="text.secondary">Criado Em</Typography>
                <Typography variant="body2">{formatDate(selectedCase.createdAt)}</Typography>
              </Grid>
              {selectedCase.tags && selectedCase.tags.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>Tags</Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {selectedCase.tags.map((tag, idx) => (
                      <Chip key={idx} label={tag} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
              {selectedCase.relatedAlerts && selectedCase.relatedAlerts.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">Alertas Relacionados</Typography>
                  <Typography variant="body2">{selectedCase.relatedAlerts.join(', ')}</Typography>
                </Grid>
              )}
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsDialogOpen(false)}>Fechar</Button>
          <Button
            variant="contained"
            onClick={() => {
              setDetailsDialogOpen(false);
              navigate(`/cases/${selectedCase.id}`);
            }}
          >
            Ver Detalhes Completos
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

export default Cases;
