import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Chip,
  Grid,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  OutlinedInput,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  Alert,
  Snackbar,
  Menu,
  InputAdornment,
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
  GetApp as ExportIcon,
  Visibility as VisibilityIcon,
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CloudSync as LiveIcon,
  CloudOff as MockIcon,
  Clear as ClearIcon,
} from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';
import { eventsAPI, cspmAPI, casesAPI } from '../services/api';
import FolderIcon from '@mui/icons-material/Folder';

const SEVERITY_COLORS = {
  CRITICAL: '#d32f2f',
  HIGH: '#f57c00',
  MEDIUM: '#fbc02d',
  LOW: '#388e3c',
  INFO: '#1976d2',
};

const CHART_COLORS = ['#8884d8', '#82ca9d', '#ffc658', '#ff7c7c', '#8dd1e1'];

const Events = () => {
  const [loading, setLoading] = useState(false);
  const [events, setEvents] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverities, setSelectedSeverities] = useState([]);
  const [selectedTypes, setSelectedTypes] = useState([]);
  const [selectedSources, setSelectedSources] = useState([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [total, setTotal] = useState(0);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [exportMenuAnchor, setExportMenuAnchor] = useState(null);
  const [selectedEventIds, setSelectedEventIds] = useState([]);
  const [dataSource, setDataSource] = useState('loading');
  const [lastUpdate, setLastUpdate] = useState(null);
  
  // Create Case from Event
  const [createCaseDialogOpen, setCreateCaseDialogOpen] = useState(false);
  const [creatingCase, setCreatingCase] = useState(false);
  const [newCase, setNewCase] = useState({
    title: '',
    description: '',
    priority: 'medium',
    assignTo: '',
  });

  // Carregar eventos e status
  useEffect(() => {
    loadEvents();
    loadStatistics();
    loadDataSourceStatus();
  }, [page, pageSize, selectedSeverities, selectedTypes, selectedSources]);

  const loadDataSourceStatus = async () => {
    try {
      const response = await cspmAPI.aws.getStatus();
      const status = response.data || {};
      setDataSource(status.data_source || 'mock');
    } catch (error) {
      setDataSource('mock');
    }
  };

  // Auto-refresh a cada 30 segundos
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      loadEvents();
      loadStatistics();
    }, 30000);

    return () => clearInterval(interval);
  }, [autoRefresh, page, pageSize, selectedSeverities, selectedTypes, selectedSources]);

  const loadEvents = async () => {
    try {
      setLoading(true);
      const params = {
        query: searchQuery || '*',
        page,
        page_size: pageSize,
        sort_field: 'timestamp',
        sort_order: 'desc',
      };

      if (selectedSeverities.length > 0) {
        params.severities = selectedSeverities;
      }
      if (selectedTypes.length > 0) {
        params.types = selectedTypes;
      }
      if (selectedSources.length > 0) {
        params.sources = selectedSources;
      }

      const response = await eventsAPI.search(params);
      setEvents(response.data.events || []);
      setTotal(response.data.total || 0);
      setLastUpdate(new Date());
      
      // Check if data is from OpenSearch (real), mock, or none
      const source = response.data.source;
      if (source === 'opensearch') {
        setDataSource('live');
      } else if (source === 'none' || source === 'error') {
        setDataSource('none');
      } else if (source === 'mock') {
        setDataSource('mock');
      } else {
        // Default based on data presence
        setDataSource(response.data.total > 0 ? 'live' : 'none');
      }
    } catch (error) {
      console.error('Failed to load events:', error);
      showSnackbar('Erro ao carregar eventos', 'error');
      setDataSource('error');
    } finally {
      setLoading(false);
    }
  };

  const loadStatistics = async () => {
    try {
      const response = await eventsAPI.getStatistics();
      setStatistics(response.data);
    } catch (error) {
      console.error('Failed to load statistics:', error);
    }
  };

  const handleSearch = () => {
    setPage(1);
    loadEvents();
  };

  const handleRefresh = () => {
    loadEvents();
    loadStatistics();
    showSnackbar('Dados atualizados', 'success');
  };

  const handleViewDetails = (event) => {
    setSelectedEvent(event);
    setDetailsOpen(true);
  };

  const handleExport = async (format = 'csv') => {
    try {
      // Fechar o menu de exportação
      setExportMenuAnchor(null);
      setLoading(true);
      
      // Se houver eventos selecionados, exportar apenas eles
      if (selectedEventIds.length > 0) {
        const selectedEvents = events.filter(event => selectedEventIds.includes(event.id));
        exportSelectedEvents(selectedEvents, format);
        showSnackbar(`${selectedEventIds.length} evento(s) selecionado(s) exportado(s) com sucesso em ${format.toUpperCase()}!`, 'success');
        setLoading(false);
        return;
      }
      
      // Exportar todos com filtros atuais

      // Caso contrário, exportar com filtros atuais
      const params = {
        query: searchQuery || '*',
        format: format, // 'csv' ou 'json'
      };

      if (selectedSeverities.length > 0) {
        params.severities = selectedSeverities;
      }
      if (selectedTypes.length > 0) {
        params.types = selectedTypes;
      }
      if (selectedSources.length > 0) {
        params.sources = selectedSources;
      }

      showSnackbar(`Exportando eventos em formato ${format.toUpperCase()}...`, 'info');

      // Fazer requisição de exportação
      const response = await eventsAPI.export(params);

      // Criar blob e fazer download
      const blob = new Blob([response.data], {
        type: format === 'json' ? 'application/json' : 'text/csv'
      });
      
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      
      // Nome do arquivo com timestamp
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
      link.download = `events_export_${timestamp}.${format}`;
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      showSnackbar(`Eventos exportados com sucesso em ${format.toUpperCase()}!`, 'success');
    } catch (error) {
      console.error('Failed to export events:', error);
      showSnackbar('Erro ao exportar eventos', 'error');
    } finally {
      setLoading(false);
    }
  };

  const exportSelectedEvents = (selectedEvents, format) => {
    let content;
    let mimeType;
    
    if (format === 'json') {
      // Exportar como JSON
      content = JSON.stringify({
        exported_at: new Date().toISOString(),
        total: selectedEvents.length,
        events: selectedEvents
      }, null, 2);
      mimeType = 'application/json';
    } else {
      // Exportar como CSV
      const headers = ['ID', 'Timestamp', 'Severity', 'Type', 'Source', 'Description', 'Tags'];
      const csvRows = [headers.join(',')];
      
      selectedEvents.forEach(event => {
        const row = [
          event.id,
          new Date(event.timestamp).toISOString(),
          event.severity,
          event.type,
          event.source,
          `"${(event.description || '').replace(/"/g, '""')}"`,
          `"${(event.tags || []).join(';')}"`
        ];
        csvRows.push(row.join(','));
      });
      
      content = csvRows.join('\n');
      mimeType = 'text/csv';
    }
    
    // Criar blob e fazer download
    const blob = new Blob([content], { type: mimeType });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    
    // Nome do arquivo com timestamp
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    link.download = `events_export_${timestamp}.${format}`;
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  };

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  // Open create case dialog with event data
  const handleOpenCreateCase = (event) => {
    setSelectedEvent(event);
    setNewCase({
      title: `Investigação: ${event.type || 'Evento'} (${event.severity || 'N/A'})`,
      description: event.description || '',
      priority: (event.severity || 'medium').toLowerCase() === 'critical' ? 'critical' : 
                (event.severity || 'medium').toLowerCase() === 'high' ? 'high' : 'medium',
      assignTo: '',
    });
    setCreateCaseDialogOpen(true);
  };

  // Create case from event
  const handleCreateCase = async () => {
    if (!selectedEvent) return;
    
    try {
      setCreatingCase(true);
      const response = await casesAPI.createFromEvent(selectedEvent.id, newCase);
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

  const columns = [
    {
      field: 'timestamp',
      headerName: 'Data/Hora',
      width: 180,
      valueFormatter: (params) => {
        if (!params.value) return '';
        const date = new Date(params.value);
        return date.toLocaleString('pt-BR');
      },
    },
    {
      field: 'severity',
      headerName: 'Severidade',
      width: 130,
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
    { field: 'type', headerName: 'Tipo', width: 180 },
    { field: 'source', headerName: 'Origem', width: 140 },
    { 
      field: 'description', 
      headerName: 'Descrição', 
      flex: 1, 
      minWidth: 200,
      renderCell: (params) => (
        <Tooltip title={params.value || ''}>
          <Typography 
            variant="body2" 
            sx={{ 
              overflow: 'hidden', 
              textOverflow: 'ellipsis', 
              whiteSpace: 'nowrap',
              maxWidth: '100%'
            }}
          >
            {params.value}
          </Typography>
        </Tooltip>
      )
    },
    {
      field: 'actions',
      headerName: 'Ações',
      width: 100,
      sortable: false,
      renderCell: (params) => (
        <Tooltip title="Ver Detalhes">
          <IconButton
            size="small"
            onClick={() => handleViewDetails(params.row)}
            color="primary"
          >
            <VisibilityIcon />
          </IconButton>
        </Tooltip>
      ),
    },
  ];

  // Preparar dados para gráficos
  const severityChartData = statistics?.by_severity
    ? Object.entries(statistics.by_severity).map(([name, value]) => ({ name, value }))
    : [];

  const typeChartData = statistics?.by_type
    ? Object.entries(statistics.by_type)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([name, value]) => ({ name, value }))
    : [];

  const timelineChartData = statistics?.timeline || [];

  return (
    <Box 
      sx={{ 
        p: 3, 
        width: '100%', 
        maxWidth: 'calc(100vw - 280px)', // Subtrair largura do menu lateral
        overflowX: 'hidden',
        overflowY: 'auto',
        boxSizing: 'border-box',
        '& *': {
          maxWidth: '100%',
        }
      }}
    >
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          Eventos de Segurança
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {/* Data Source Indicator */}
          {dataSource === 'live' && (
            <Chip
              icon={<LiveIcon />}
              label={`LIVE DATA • ${formatTimeAgo(lastUpdate)}`}
              color="success"
              size="small"
              sx={{ fontWeight: 'bold' }}
            />
          )}
          {dataSource === 'mock' && (
            <Chip
              icon={<MockIcon />}
              label="DEMO DATA"
              color="error"
              size="small"
              sx={{ fontWeight: 'bold' }}
            />
          )}
          {(dataSource === 'none' || dataSource === 'error') && (
            <Chip
              icon={<WarningIcon />}
              label="NO DATA - Configure OpenSearch"
              color="warning"
              size="small"
              sx={{ fontWeight: 'bold' }}
            />
          )}
          {dataSource === 'loading' && (
            <Chip
              label="Carregando..."
              color="default"
              size="small"
            />
          )}
          
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
              {selectedEventIds.length > 0 
                ? `${selectedEventIds.length} evento(s) selecionado(s)` 
                : 'Todos os eventos com filtros atuais'}
            </Typography>
          </Box>
        </MenuItem>
        <MenuItem onClick={() => handleExport('json')}>
          <Box sx={{ display: 'flex', flexDirection: 'column' }}>
            <Typography variant="body1">Exportar como JSON</Typography>
            <Typography variant="caption" color="text.secondary">
              {selectedEventIds.length > 0 
                ? `${selectedEventIds.length} evento(s) selecionado(s)` 
                : 'Todos os eventos com filtros atuais'}
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
                      Total de Eventos
                    </Typography>
                    <Typography variant="h4">
                      {statistics.total?.toLocaleString('pt-BR')}
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
                      Críticos
                    </Typography>
                    <Typography variant="h4" color="error">
                      {statistics.by_severity?.CRITICAL || 0}
                    </Typography>
                  </Box>
                  <WarningIcon sx={{ fontSize: 40, color: 'error.main', opacity: 0.3 }} />
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
                      Alta Severidade
                    </Typography>
                    <Typography variant="h4" color="warning.main">
                      {statistics.by_severity?.HIGH || 0}
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
                      Fontes Únicas
                    </Typography>
                    <Typography variant="h4">
                      {Object.keys(statistics.by_source || {}).length}
                    </Typography>
                  </Box>
                  <FilterIcon sx={{ fontSize: 40, color: 'primary.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Gráficos */}
      {statistics && (
        <Grid container spacing={2} sx={{ mb: 3, width: '100%', maxWidth: '100%', overflow: 'hidden' }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 2, overflow: 'hidden' }}>
              <Typography variant="h6" gutterBottom>
                Eventos por Severidade
              </Typography>
              <Box sx={{ width: '100%', overflow: 'hidden' }}>
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
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12} md={8}>
            <Paper sx={{ p: 2, overflow: 'hidden' }}>
              <Typography variant="h6" gutterBottom>
                Top 10 Tipos de Eventos
              </Typography>
              <Box sx={{ width: '100%', overflow: 'hidden' }}>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={typeChartData} margin={{ bottom: 60 }}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="name" 
                      angle={-45} 
                      textAnchor="end" 
                      height={80}
                      interval={0}
                      tick={{ fontSize: 10 }}
                    />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="value" fill="#8884d8" />
                  </BarChart>
                </ResponsiveContainer>
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Paper sx={{ p: 2, overflow: 'hidden' }}>
              <Typography variant="h6" gutterBottom>
                Timeline de Eventos (últimas 24h)
              </Typography>
              <Box sx={{ width: '100%', overflow: 'hidden' }}>
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={timelineChartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis
                      dataKey="timestamp"
                      tickFormatter={(value) => {
                        const date = new Date(value);
                        return `${date.getHours()}:00`;
                      }}
                      tick={{ fontSize: 11 }}
                    />
                    <YAxis tick={{ fontSize: 11 }} />
                    <RechartsTooltip
                      labelFormatter={(value) => {
                        const date = new Date(value);
                        return date.toLocaleString('pt-BR');
                      }}
                    />
                    <Legend />
                    <Line type="monotone" dataKey="count" stroke="#8884d8" name="Eventos" />
                  </LineChart>
                </ResponsiveContainer>
              </Box>
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* Filtros e Busca */}
      <Paper sx={{ p: 2, mb: 3, overflow: 'hidden' }}>
        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              placeholder="Buscar por CVE, tipo ou descrição... (ex: CVE-2024-45337)"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              variant="outlined"
              size="small"
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
                        setPage(1);
                        loadEvents();
                      }}
                      edge="end"
                    >
                      <ClearIcon fontSize="small" />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </Grid>

          <Grid item xs={12} md={2}>
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

          <Grid item xs={12} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Tipo</InputLabel>
              <Select
                multiple
                value={selectedTypes}
                onChange={(e) => setSelectedTypes(e.target.value)}
                input={<OutlinedInput label="Tipo" />}
                renderValue={(selected) => `${selected.length} selecionados`}
              >
                {statistics?.by_type && Object.keys(statistics.by_type).map((type) => (
                  <MenuItem key={type} value={type}>
                    {type}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Origem</InputLabel>
              <Select
                multiple
                value={selectedSources}
                onChange={(e) => setSelectedSources(e.target.value)}
                input={<OutlinedInput label="Origem" />}
                renderValue={(selected) => `${selected.length} selecionados`}
              >
                {statistics?.by_source && Object.keys(statistics.by_source).map((source) => (
                  <MenuItem key={source} value={source}>
                    {source}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} md={2}>
            <Button
              fullWidth
              variant="contained"
              startIcon={<SearchIcon />}
              onClick={handleSearch}
              sx={{ height: '40px' }}
            >
              Buscar
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Tabela de Eventos */}
      <Paper sx={{ height: 600, width: '100%', maxWidth: '100%', overflow: 'hidden' }}>
        {selectedEventIds.length > 0 && (
          <Box sx={{ p: 2, backgroundColor: 'primary.light', color: 'primary.contrastText' }}>
            <Typography variant="body2">
              {selectedEventIds.length} evento(s) selecionado(s)
              <Button
                size="small"
                onClick={() => {
                  setSelectedEventIds([]);
                }}
                sx={{ ml: 2, color: 'inherit' }}
              >
                Limpar Seleção
              </Button>
            </Typography>
          </Box>
        )}
        <DataGrid
          rows={events}
          columns={columns}
          page={page - 1}
          pageSize={pageSize}
          rowCount={total}
          paginationMode="server"
          onPageChange={(newPage) => setPage(newPage + 1)}
          onPageSizeChange={(newPageSize) => setPageSize(newPageSize)}
          rowsPerPageOptions={[10, 25, 50, 100]}
          loading={loading}
          checkboxSelection
          rowSelectionModel={selectedEventIds}
          onRowSelectionModelChange={(newSelection) => {
            setSelectedEventIds(newSelection);
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
          Detalhes do Evento
        </DialogTitle>
        <DialogContent>
          {selectedEvent && (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    ID
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedEvent.id}
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Data/Hora
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {new Date(selectedEvent.timestamp).toLocaleString('pt-BR')}
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Severidade
                  </Typography>
                  <Chip
                    label={selectedEvent.severity}
                    size="small"
                    sx={{
                      backgroundColor: SEVERITY_COLORS[selectedEvent.severity] || '#999',
                      color: 'white',
                      fontWeight: 'bold',
                      mt: 0.5,
                    }}
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Tipo
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedEvent.type}
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Origem
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedEvent.source}
                  </Typography>
                </Grid>

                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Descrição
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedEvent.description}
                  </Typography>
                </Grid>

                {selectedEvent.tags && selectedEvent.tags.length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      Tags
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      {selectedEvent.tags.map((tag, index) => (
                        <Chip key={index} label={tag} size="small" />
                      ))}
                    </Box>
                  </Grid>
                )}

                {selectedEvent.details && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      Detalhes Técnicos
                    </Typography>
                    <Paper 
                      sx={{ 
                        p: 2, 
                        backgroundColor: '#0d1117', 
                        maxHeight: 300, 
                        overflow: 'auto',
                        border: '1px solid #30363d',
                        borderRadius: 1
                      }}
                    >
                      <pre 
                        style={{ 
                          margin: 0, 
                          fontSize: '12px', 
                          color: '#c9d1d9', 
                          fontFamily: '"Fira Code", "Consolas", "Monaco", monospace',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word'
                        }}
                      >
                        {JSON.stringify(selectedEvent.details, null, 2)}
                      </pre>
                    </Paper>
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
            onClick={() => handleOpenCreateCase(selectedEvent)}
          >
            Criar Caso
          </Button>
          <Button onClick={() => setDetailsOpen(false)}>
            Fechar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Criar Caso a partir do Evento */}
      <Dialog
        open={createCaseDialogOpen}
        onClose={() => setCreateCaseDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          Criar Caso a partir do Evento
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

// Helper function to format time ago
function formatTimeAgo(date) {
  if (!date) return '';
  const now = new Date();
  const diffMs = now - date;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);

  if (diffSec < 60) return 'agora';
  if (diffMin < 60) return `${diffMin} min`;
  if (diffHour < 24) return `${diffHour}h`;
  return date.toLocaleDateString('pt-BR');
}

export default Events;
