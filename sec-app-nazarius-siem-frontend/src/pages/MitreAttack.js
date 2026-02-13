import React, { useState, useEffect } from 'react';
import {
  Grid,
  Typography,
  Card,
  CardContent,
  Box,
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
  CircularProgress,
  Alert,
  Tooltip,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  List,
  ListItem,
  ListItemText,
  Divider,
  IconButton,
  TextField,
  InputAdornment,
  Pagination,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  Close as CloseIcon,
  OpenInNew as OpenInNewIcon,
  Search as SearchIcon,
  Visibility as VisibilityIcon,
  Person as PersonIcon,
  Computer as ComputerIcon,
  Public as PublicIcon,
  FolderOpen as FolderIcon,
  Refresh as RefreshIcon,
  Info as InfoIcon,
  Security as SecurityIcon,
  Language as LanguageIcon,
  Storage as StorageIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { mitreAPI, casesAPI } from '../services/api';

const MitreAttack = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);
  const [tactics, setTactics] = useState([]);
  const [techniques, setTechniques] = useState([]);
  const [coverage, setCoverage] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedTactic, setSelectedTactic] = useState(null);
  const [openTacticDialog, setOpenTacticDialog] = useState(false);
  const [tacticDetails, setTacticDetails] = useState(null);
  const [openTechniqueDialog, setOpenTechniqueDialog] = useState(false);
  const [techniqueDetails, setTechniqueDetails] = useState(null);
  
  // New states for detections
  const [techniqueDetections, setTechniqueDetections] = useState([]);
  const [loadingDetections, setLoadingDetections] = useState(false);
  const [detectionsPage, setDetectionsPage] = useState(1);
  const [detectionsPerPage] = useState(10);
  
  // All detections tab
  const [allDetections, setAllDetections] = useState([]);
  const [loadingAllDetections, setLoadingAllDetections] = useState(false);
  const [allDetectionsPage, setAllDetectionsPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState('');
  
  // Create case dialog
  const [createCaseDialogOpen, setCreateCaseDialogOpen] = useState(false);
  const [selectedDetection, setSelectedDetection] = useState(null);
  const [creatingCase, setCreatingCase] = useState(false);
  
  // Detection details dialog
  const [detectionDetailsOpen, setDetectionDetailsOpen] = useState(false);
  const [selectedDetectionDetails, setSelectedDetectionDetails] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [tacticsRes, techniquesRes, coverageRes, timelineRes] = await Promise.all([
        mitreAPI.getTactics(),
        mitreAPI.getTechniques(),
        mitreAPI.getCoverage(),
        mitreAPI.getTimeline(24),
      ]);
      
      if (tacticsRes.data && tacticsRes.data.tactics) {
        setTactics(tacticsRes.data.tactics);
      }
      
      if (techniquesRes.data && techniquesRes.data.techniques) {
        setTechniques(techniquesRes.data.techniques);
      }
      
      if (coverageRes.data) {
        setCoverage(coverageRes.data);
      }
      
      if (timelineRes.data && timelineRes.data.timeline) {
        setTimeline(timelineRes.data.timeline);
      }
    } catch (err) {
      console.error('Erro ao carregar dados MITRE:', err);
      setError('Erro ao carregar dados do MITRE ATT&CK.');
    } finally {
      setLoading(false);
    }
  };

  // Load detections for a specific technique
  const loadTechniqueDetections = async (techniqueId) => {
    try {
      setLoadingDetections(true);
      const response = await mitreAPI.getDetections({ technique_id: techniqueId, limit: 100 });
      setTechniqueDetections(response.data?.detections || []);
    } catch (err) {
      console.error('Erro ao carregar detecções:', err);
      setTechniqueDetections([]);
    } finally {
      setLoadingDetections(false);
    }
  };

  // Load all detections for the tab
  const loadAllDetections = async () => {
    try {
      setLoadingAllDetections(true);
      const response = await mitreAPI.getDetections({ limit: 200 });
      setAllDetections(response.data?.detections || []);
    } catch (err) {
      console.error('Erro ao carregar todas as detecções:', err);
      setAllDetections([]);
    } finally {
      setLoadingAllDetections(false);
    }
  };

  // Load all detections when tab 4 is selected
  useEffect(() => {
    if (activeTab === 4 && allDetections.length === 0) {
      loadAllDetections();
    }
  }, [activeTab]);

  const getCoverageColor = (coverage) => {
    switch (coverage) {
      case 'high': return '#4caf50';
      case 'medium': return '#ff9800';
      case 'low': return '#f44336';
      case 'none': return '#9e9e9e';
      default: return '#9e9e9e';
    }
  };

  const getCoverageIcon = (coverage) => {
    switch (coverage) {
      case 'high': return <CheckCircleIcon />;
      case 'medium': return <WarningIcon />;
      case 'low': return <WarningIcon />;
      case 'none': return <CancelIcon />;
      default: return null;
    }
  };

  const getCoverageLabel = (coverage) => {
    const labels = {
      'high': 'Alta',
      'medium': 'Média',
      'low': 'Baixa',
      'none': 'Nenhuma',
    };
    return labels[coverage] || coverage;
  };

  const getSeverityColor = (severity) => {
    const s = (severity || '').toUpperCase();
    if (s === 'CRITICAL') return 'error';
    if (s === 'HIGH') return 'warning';
    if (s === 'MEDIUM') return 'info';
    return 'success';
  };

  const getTechniquesForTactic = (tacticId) => {
    return techniques.filter(tech => tech.tacticIds?.includes(tacticId));
  };

  const handleTacticClick = (tactic) => {
    const tacticTechniques = getTechniquesForTactic(tactic.id);
    const tacticCoverage = coverage?.tacticsCoverage[tactic.id];
    
    setTacticDetails({
      ...tactic,
      techniques: tacticTechniques,
      coverage: tacticCoverage,
    });
    setOpenTacticDialog(true);
  };

  const handleTechniqueClick = async (technique) => {
    setTechniqueDetails(technique);
    setTechniqueDetections([]);
    setDetectionsPage(1);
    setOpenTechniqueDialog(true);
    
    // Load detections for this technique
    await loadTechniqueDetections(technique.id);
  };

  const handleCloseTacticDialog = () => {
    setOpenTacticDialog(false);
    setTacticDetails(null);
  };

  const handleCloseTechniqueDialog = () => {
    setOpenTechniqueDialog(false);
    setTechniqueDetails(null);
    setTechniqueDetections([]);
  };

  const handleViewEvent = (eventId) => {
    // Navigate to events page with filter
    navigate(`/events?search=${eventId}`);
  };

  const handleViewDetectionDetails = (detection) => {
    setSelectedDetectionDetails(detection);
    setDetectionDetailsOpen(true);
  };

  const handleCreateCaseFromDetection = (detection) => {
    setSelectedDetection(detection);
    setCreateCaseDialogOpen(true);
  };

  const handleConfirmCreateCase = async () => {
    if (!selectedDetection) return;
    
    try {
      setCreatingCase(true);
      await casesAPI.createFromEvent(selectedDetection.event_id, {
        title: `MITRE ${selectedDetection.technique_id}: ${selectedDetection.technique_name}`,
        description: `Detecção de técnica MITRE ATT&CK.\n\nTécnica: ${selectedDetection.technique_id} - ${selectedDetection.technique_name}\nTática: ${selectedDetection.tactic_id} - ${selectedDetection.tactic_name}\n\nDescrição do evento:\n${selectedDetection.description}`,
        priority: selectedDetection.severity?.toLowerCase() === 'critical' ? 'critical' : 
                  selectedDetection.severity?.toLowerCase() === 'high' ? 'high' : 'medium',
      });
      setCreateCaseDialogOpen(false);
      setSelectedDetection(null);
      alert('Caso criado com sucesso!');
    } catch (err) {
      console.error('Erro ao criar caso:', err);
      alert('Erro ao criar caso');
    } finally {
      setCreatingCase(false);
    }
  };

  // Extract user/IP info from detection
  const extractOffenderInfo = (detection) => {
    const info = {
      user: '-',
      ip: '-',
      resource: '-',
      region: '-',
    };
    
    // Try to extract from description or event_type
    const desc = detection.description || '';
    const eventType = detection.event_type || '';
    
    // Common patterns
    if (desc.includes('IP:')) {
      const match = desc.match(/IP:\s*([^\s,]+)/);
      if (match) info.ip = match[1];
    }
    
    // GuardDuty often has resource info in the event type
    if (eventType.includes('EC2')) {
      info.resource = 'EC2 Instance';
    } else if (eventType.includes('S3')) {
      info.resource = 'S3 Bucket';
    } else if (eventType.includes('IAM')) {
      info.resource = 'IAM';
    } else if (eventType.includes('Kubernetes')) {
      info.resource = 'Kubernetes';
    } else if (eventType.includes('RDS')) {
      info.resource = 'RDS Database';
    }
    
    return info;
  };

  // Filter detections based on search
  const filteredDetections = allDetections.filter(d => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      d.technique_id?.toLowerCase().includes(term) ||
      d.technique_name?.toLowerCase().includes(term) ||
      d.tactic_name?.toLowerCase().includes(term) ||
      d.description?.toLowerCase().includes(term) ||
      d.event_type?.toLowerCase().includes(term) ||
      d.source?.toLowerCase().includes(term)
    );
  });

  // Paginated detections for technique dialog
  const paginatedTechniqueDetections = techniqueDetections.slice(
    (detectionsPage - 1) * detectionsPerPage,
    detectionsPage * detectionsPerPage
  );

  // Paginated all detections
  const paginatedAllDetections = filteredDetections.slice(
    (allDetectionsPage - 1) * detectionsPerPage,
    allDetectionsPage * detectionsPerPage
  );

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
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            📊 MITRE ATT&CK Framework
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Mapeamento de táticas, técnicas e procedimentos de adversários
          </Typography>
        </Box>
        <Button 
          variant="outlined" 
          startIcon={<RefreshIcon />}
          onClick={loadData}
        >
          Atualizar
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Cards de Métricas */}
      {coverage && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card sx={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
              <CardContent>
                <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                  Cobertura Total
                </Typography>
                <Typography variant="h3" color="white">
                  {coverage.coveragePercentage?.toFixed(1) || 0}%
                </Typography>
                <Typography variant="caption" color="white" sx={{ opacity: 0.8 }}>
                  {coverage.coveredTechniques || 0} de {coverage.totalTechniques || 0} técnicas
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card sx={{ background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)' }}>
              <CardContent>
                <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                  Táticas Cobertas
                </Typography>
                <Typography variant="h3" color="white">
                  {coverage.coveredTactics || 0}/{coverage.totalTactics || 14}
                </Typography>
                <Typography variant="caption" color="white" sx={{ opacity: 0.8 }}>
                  Táticas com detecções
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card sx={{ background: 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)' }}>
              <CardContent>
                <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                  Detecções Recentes
                </Typography>
                <Typography variant="h3" color="white">
                  {coverage.recentDetections || 0}
                </Typography>
                <Typography variant="caption" color="white" sx={{ opacity: 0.8 }}>
                  Últimas 24 horas
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card sx={{ background: 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)' }}>
              <CardContent>
                <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                  Gaps Críticos
                </Typography>
                <Typography variant="h3" color="white">
                  {coverage.criticalGaps?.length || 0}
                </Typography>
                <Typography variant="caption" color="white" sx={{ opacity: 0.8 }}>
                  Técnicas sem detecção
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
          <Tab label="Matriz de Táticas" />
          <Tab label="Coverage Analysis" />
          <Tab label="Timeline de Ataques" />
          <Tab label="Top Técnicas" />
          <Tab label="🔍 Todas as Detecções" />
        </Tabs>
      </Box>

      {/* Tab 1: Matriz de Táticas */}
      {activeTab === 0 && (
        <Grid container spacing={2}>
          {tactics.map((tactic) => {
            const tacticTechniques = getTechniquesForTactic(tactic.id);
            const tacticCoverage = coverage?.tacticsCoverage?.[tactic.id];
            
            return (
              <Grid item xs={12} sm={6} md={4} lg={3} key={tactic.id}>
                <Card 
                  sx={{ 
                    height: '100%',
                    cursor: 'pointer',
                    '&:hover': { boxShadow: 6 },
                    border: selectedTactic === tactic.id ? 2 : 0,
                    borderColor: 'primary.main',
                  }}
                  onClick={() => {
                    setSelectedTactic(tactic.id);
                    handleTacticClick(tactic);
                  }}
                >
                  <CardContent>
                    <Box sx={{ mb: 2 }}>
                      <Chip 
                        label={tactic.id} 
                        size="small" 
                        sx={{ mb: 1, fontFamily: 'monospace' }}
                      />
                      <Typography variant="h6" gutterBottom>
                        {tactic.name}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {tactic.description}
                      </Typography>
                    </Box>

                    {tacticCoverage && (
                      <Box sx={{ mt: 2 }}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                          <Typography variant="caption">
                            Cobertura
                          </Typography>
                          <Typography variant="caption" fontWeight={600}>
                            {tacticCoverage.coveragePercentage?.toFixed(0) || 0}%
                          </Typography>
                        </Box>
                        <LinearProgress 
                          variant="determinate" 
                          value={tacticCoverage.coveragePercentage || 0} 
                          sx={{ height: 8, borderRadius: 4 }}
                        />
                        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                          {tacticCoverage.coveredTechniques || 0} de {tacticCoverage.totalTechniques || 0} técnicas
                        </Typography>
                      </Box>
                    )}

                    {/* Mini heatmap de técnicas */}
                    <Box sx={{ mt: 2, display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {tacticTechniques.slice(0, 20).map((tech) => (
                        <Tooltip 
                          key={tech.id} 
                          title={`${tech.id}: ${tech.name} (${getCoverageLabel(tech.detectionCoverage)})`}
                        >
                          <Box
                            sx={{
                              width: 16,
                              height: 16,
                              backgroundColor: getCoverageColor(tech.detectionCoverage),
                              borderRadius: 0.5,
                              cursor: 'pointer',
                            }}
                          />
                        </Tooltip>
                      ))}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      {/* Tab 2: Coverage Analysis */}
      {activeTab === 1 && coverage && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Cobertura por Tática
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Tática</TableCell>
                        <TableCell>Técnicas</TableCell>
                        <TableCell>Cobertura</TableCell>
                        <TableCell>%</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {Object.values(coverage.tacticsCoverage || {}).map((tactic) => (
                        <TableRow key={tactic.tacticId}>
                          <TableCell>
                            <Typography variant="body2" fontWeight={600}>
                              {tactic.tacticName}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {tactic.tacticId}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {tactic.coveredTechniques}/{tactic.totalTechniques}
                          </TableCell>
                          <TableCell>
                            <LinearProgress 
                              variant="determinate" 
                              value={tactic.coveragePercentage || 0} 
                              sx={{ height: 8, borderRadius: 4 }}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" fontWeight={600}>
                              {tactic.coveragePercentage?.toFixed(1) || 0}%
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={4}>
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Gaps Críticos
                </Typography>
                {(coverage.criticalGaps || []).length === 0 ? (
                  <Typography color="text.secondary">Nenhum gap crítico identificado</Typography>
                ) : (
                  coverage.criticalGaps.map((gap) => (
                    <Box key={gap.id} sx={{ mb: 2, p: 1, border: 1, borderColor: 'error.main', borderRadius: 1 }}>
                      <Typography variant="body2" fontWeight={600}>
                        {gap.id}: {gap.name}
                      </Typography>
                      <Chip 
                        label="Sem Detecção" 
                        size="small" 
                        color="error" 
                        sx={{ mt: 0.5 }}
                        icon={<CancelIcon />}
                      />
                    </Box>
                  ))
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tab 3: Timeline */}
      {activeTab === 2 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Timeline de Ataques (Últimas 24h)
            </Typography>
            {timeline.length === 0 ? (
              <Typography color="text.secondary">Nenhuma detecção nas últimas 24 horas</Typography>
            ) : (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Timestamp</TableCell>
                      <TableCell>Tática</TableCell>
                      <TableCell>Técnica</TableCell>
                      <TableCell>Eventos</TableCell>
                      <TableCell>Severidade</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {timeline.map((entry, index) => (
                      <TableRow key={index}>
                        <TableCell>
                          {new Date(entry.timestamp).toLocaleString('pt-BR')}
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontWeight={600}>
                            {entry.tacticName}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {entry.tacticId}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {entry.techniqueName}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {entry.techniqueId}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={entry.eventCount} size="small" />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={entry.severity} 
                            size="small"
                            color={getSeverityColor(entry.severity)}
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </CardContent>
        </Card>
      )}

      {/* Tab 4: Top Técnicas */}
      {activeTab === 3 && coverage && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Top Técnicas Mais Detectadas
            </Typography>
            {(coverage.topTechniques || []).length === 0 ? (
              <Typography color="text.secondary">Nenhuma técnica detectada</Typography>
            ) : (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Rank</TableCell>
                      <TableCell>Técnica</TableCell>
                      <TableCell>Tática</TableCell>
                      <TableCell>Eventos</TableCell>
                      <TableCell>Severidade</TableCell>
                      <TableCell>Ações</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {coverage.topTechniques.map((tech, index) => {
                      const fullTechnique = techniques.find(t => t.id === tech.techniqueId);
                      return (
                        <TableRow 
                          key={tech.techniqueId}
                          hover
                          sx={{ cursor: 'pointer' }}
                        >
                          <TableCell>
                            <Chip 
                              label={`#${index + 1}`} 
                              size="small" 
                              color="primary"
                              icon={<TrendingUpIcon />}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" fontWeight={600}>
                              {tech.techniqueName}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {tech.techniqueId}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {tech.tacticId}
                          </TableCell>
                          <TableCell>
                            <Typography variant="h6">
                              {tech.eventCount}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={tech.severity} 
                              size="small"
                              color={getSeverityColor(tech.severity)}
                            />
                          </TableCell>
                          <TableCell>
                            <Button
                              size="small"
                              startIcon={<VisibilityIcon />}
                              onClick={() => fullTechnique && handleTechniqueClick(fullTechnique)}
                            >
                              Ver Detalhes
                            </Button>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </CardContent>
        </Card>
      )}

      {/* Tab 5: Todas as Detecções */}
      {activeTab === 4 && (
        <Card>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Todas as Detecções MITRE ({filteredDetections.length})
              </Typography>
              <Box sx={{ display: 'flex', gap: 2 }}>
                <TextField
                  size="small"
                  placeholder="Buscar detecções..."
                  value={searchTerm}
                  onChange={(e) => { setSearchTerm(e.target.value); setAllDetectionsPage(1); }}
                  InputProps={{
                    startAdornment: <InputAdornment position="start"><SearchIcon /></InputAdornment>,
                  }}
                  sx={{ width: 300 }}
                />
                <Button
                  variant="outlined"
                  startIcon={<RefreshIcon />}
                  onClick={loadAllDetections}
                  disabled={loadingAllDetections}
                >
                  Atualizar
                </Button>
              </Box>
            </Box>
            
            {loadingAllDetections ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
                <CircularProgress />
              </Box>
            ) : filteredDetections.length === 0 ? (
              <Typography color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                Nenhuma detecção encontrada
              </Typography>
            ) : (
              <>
                {/* Enhanced Detection Cards */}
                {paginatedAllDetections.map((detection, index) => (
                  <Paper 
                    key={detection.id || index} 
                    variant="outlined" 
                    sx={{ 
                      mb: 2, 
                      p: 2,
                      '&:hover': { borderColor: 'primary.main' }
                    }}
                  >
                    <Grid container spacing={2}>
                      {/* Header Row */}
                      <Grid item xs={12}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 1 }}>
                          <Box>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                              <Chip label={detection.technique_id} size="small" color="primary" />
                              <Chip label={detection.tactic_id} size="small" variant="outlined" />
                              <Chip 
                                label={detection.severity} 
                                size="small"
                                color={getSeverityColor(detection.severity)}
                              />
                            </Box>
                            <Typography variant="subtitle1" fontWeight={600} sx={{ mt: 1 }}>
                              {detection.technique_name}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              {detection.event_type}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {detection.timestamp 
                                ? new Date(detection.timestamp).toLocaleString('pt-BR')
                                : '-'} • {detection.source}
                            </Typography>
                          </Box>
                            <Box sx={{ display: 'flex', gap: 1 }}>
                            <Tooltip title="Ver Detalhes Completos">
                              <IconButton 
                                size="small"
                                color="info"
                                onClick={() => handleViewDetectionDetails(detection)}
                              >
                                <InfoIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Ver Evento">
                              <IconButton 
                                size="small"
                                onClick={() => handleViewEvent(detection.event_id)}
                              >
                                <VisibilityIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Criar Caso">
                              <IconButton 
                                size="small"
                                color="primary"
                                onClick={() => handleCreateCaseFromDetection(detection)}
                              >
                                <FolderIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </Box>
                      </Grid>

                      {/* Description */}
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary">
                          {detection.description || 'Sem descrição disponível'}
                        </Typography>
                      </Grid>

                      {/* Details Grid */}
                      <Grid item xs={12}>
                        <Grid container spacing={1}>
                          {/* User */}
                          {detection.user && (
                            <Grid item xs={6} sm={4} md={2}>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                <PersonIcon fontSize="small" color="action" />
                                <Box>
                                  <Typography variant="caption" color="text.secondary" display="block">
                                    Usuário
                                  </Typography>
                                  <Typography variant="body2" fontWeight={500}>
                                    {detection.user}
                                  </Typography>
                                </Box>
                              </Box>
                            </Grid>
                          )}

                          {/* Source IP */}
                          {detection.source_ip && (
                            <Grid item xs={6} sm={4} md={2}>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                <PublicIcon fontSize="small" color="error" />
                                <Box>
                                  <Typography variant="caption" color="text.secondary" display="block">
                                    IP Origem
                                  </Typography>
                                  <Typography variant="body2" fontWeight={600} sx={{ fontFamily: 'monospace', color: 'error.main' }}>
                                    {detection.source_ip}
                                  </Typography>
                                </Box>
                              </Box>
                            </Grid>
                          )}

                          {/* Resource */}
                          {(detection.resource_type || detection.resource_id) && (
                            <Grid item xs={6} sm={4} md={2}>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                <ComputerIcon fontSize="small" color="action" />
                                <Box>
                                  <Typography variant="caption" color="text.secondary" display="block">
                                    {detection.resource_type || 'Recurso'}
                                  </Typography>
                                  <Typography variant="body2" fontWeight={500} noWrap sx={{ maxWidth: 120 }}>
                                    {detection.resource_id || '-'}
                                  </Typography>
                                </Box>
                              </Box>
                            </Grid>
                          )}

                          {/* Region */}
                          {detection.region && (
                            <Grid item xs={6} sm={4} md={2}>
                              <Box>
                                <Typography variant="caption" color="text.secondary" display="block">
                                  Região
                                </Typography>
                                <Typography variant="body2">
                                  {detection.region}
                                </Typography>
                              </Box>
                            </Grid>
                          )}

                          {/* Account ID */}
                          {detection.account_id && (
                            <Grid item xs={6} sm={4} md={2}>
                              <Box>
                                <Typography variant="caption" color="text.secondary" display="block">
                                  Account
                                </Typography>
                                <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '11px' }}>
                                  {detection.account_id}
                                </Typography>
                              </Box>
                            </Grid>
                          )}

                          {/* Port */}
                          {detection.port > 0 && (
                            <Grid item xs={6} sm={4} md={2}>
                              <Box>
                                <Typography variant="caption" color="text.secondary" display="block">
                                  Porta
                                </Typography>
                                <Typography variant="body2">
                                  {detection.port} {detection.protocol && `(${detection.protocol})`}
                                </Typography>
                              </Box>
                            </Grid>
                          )}

                          {/* Action */}
                          {detection.action && (
                            <Grid item xs={6} sm={4} md={2}>
                              <Box>
                                <Typography variant="caption" color="text.secondary" display="block">
                                  Ação
                                </Typography>
                                <Typography variant="body2">
                                  {detection.action}
                                </Typography>
                              </Box>
                            </Grid>
                          )}

                          {/* Threat */}
                          {detection.threat_name && (
                            <Grid item xs={6} sm={4} md={2}>
                              <Box>
                                <Typography variant="caption" color="text.secondary" display="block">
                                  Ameaça
                                </Typography>
                                <Chip 
                                  label={detection.threat_name} 
                                  size="small" 
                                  color="error"
                                  variant="outlined"
                                />
                              </Box>
                            </Grid>
                          )}
                        </Grid>
                      </Grid>
                    </Grid>
                  </Paper>
                ))}
                
                {filteredDetections.length > detectionsPerPage && (
                  <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
                    <Pagination
                      count={Math.ceil(filteredDetections.length / detectionsPerPage)}
                      page={allDetectionsPage}
                      onChange={(e, page) => setAllDetectionsPage(page)}
                      color="primary"
                    />
                  </Box>
                )}
              </>
            )}
          </CardContent>
        </Card>
      )}

      {/* Dialog de Detalhes da Tática */}
      <Dialog 
        open={openTacticDialog} 
        onClose={handleCloseTacticDialog}
        maxWidth="md"
        fullWidth
      >
        {tacticDetails && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Box>
                  <Typography variant="h5">
                    {tacticDetails.name}
                  </Typography>
                  <Chip 
                    label={tacticDetails.id} 
                    size="small" 
                    sx={{ mt: 0.5, fontFamily: 'monospace' }}
                  />
                </Box>
                <IconButton onClick={handleCloseTacticDialog}>
                  <CloseIcon />
                </IconButton>
              </Box>
            </DialogTitle>
            <DialogContent dividers>
              <Typography variant="body1" paragraph>
                {tacticDetails.description}
              </Typography>

              {tacticDetails.coverage && (
                <Box sx={{ mb: 3 }}>
                  <Typography variant="h6" gutterBottom>
                    Cobertura de Detecção
                  </Typography>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                    <Typography variant="body2">
                      {tacticDetails.coverage.coveredTechniques} de {tacticDetails.coverage.totalTechniques} técnicas detectadas
                    </Typography>
                    <Typography variant="body2" fontWeight={600}>
                      {tacticDetails.coverage.coveragePercentage?.toFixed(1) || 0}%
                    </Typography>
                  </Box>
                  <LinearProgress 
                    variant="determinate" 
                    value={tacticDetails.coverage.coveragePercentage || 0} 
                    sx={{ height: 10, borderRadius: 5 }}
                  />
                </Box>
              )}

              <Divider sx={{ my: 2 }} />

              <Typography variant="h6" gutterBottom>
                Técnicas ({tacticDetails.techniques?.length || 0})
              </Typography>
              
              <List>
                {(tacticDetails.techniques || []).map((tech) => (
                  <ListItem 
                    key={tech.id}
                    button
                    onClick={() => handleTechniqueClick(tech)}
                    sx={{ 
                      border: 1, 
                      borderColor: 'divider', 
                      borderRadius: 1, 
                      mb: 1,
                      '&:hover': { bgcolor: 'action.hover' }
                    }}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="body1" fontWeight={600}>
                            {tech.id}: {tech.name}
                          </Typography>
                          <Chip 
                            size="small"
                            label={getCoverageLabel(tech.detectionCoverage)}
                            icon={getCoverageIcon(tech.detectionCoverage)}
                            sx={{ 
                              bgcolor: getCoverageColor(tech.detectionCoverage),
                              color: 'white'
                            }}
                          />
                        </Box>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary">
                            {tech.description}
                          </Typography>
                          {tech.eventCount > 0 && (
                            <Typography variant="caption" color="primary">
                              {tech.eventCount} eventos detectados
                              {tech.lastDetected && ` · Última detecção: ${new Date(tech.lastDetected).toLocaleString('pt-BR')}`}
                            </Typography>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </DialogContent>
            <DialogActions>
              <Button 
                startIcon={<OpenInNewIcon />}
                href={tacticDetails.url}
                target="_blank"
                rel="noopener noreferrer"
              >
                Ver no MITRE ATT&CK
              </Button>
              <Button onClick={handleCloseTacticDialog} variant="contained">
                Fechar
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Dialog de Detalhes da Técnica - ENHANCED */}
      <Dialog 
        open={openTechniqueDialog} 
        onClose={handleCloseTechniqueDialog}
        maxWidth="lg"
        fullWidth
      >
        {techniqueDetails && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Box>
                  <Typography variant="h5">
                    {techniqueDetails.name}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                    <Chip 
                      label={techniqueDetails.id} 
                      size="small" 
                      sx={{ fontFamily: 'monospace' }}
                    />
                    <Chip 
                      size="small"
                      label={getCoverageLabel(techniqueDetails.detectionCoverage)}
                      icon={getCoverageIcon(techniqueDetails.detectionCoverage)}
                      sx={{ 
                        bgcolor: getCoverageColor(techniqueDetails.detectionCoverage),
                        color: 'white'
                      }}
                    />
                  </Box>
                </Box>
                <IconButton onClick={handleCloseTechniqueDialog}>
                  <CloseIcon />
                </IconButton>
              </Box>
            </DialogTitle>
            <DialogContent dividers>
              <Typography variant="body1" paragraph>
                {techniqueDetails.description}
              </Typography>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} sm={4}>
                  <Paper sx={{ p: 2, bgcolor: 'background.default' }}>
                    <Typography variant="caption" color="text.secondary">
                      Eventos Detectados
                    </Typography>
                    <Typography variant="h4" color="primary">
                      {techniqueDetails.eventCount || techniqueDetections.length}
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} sm={4}>
                  <Paper sx={{ p: 2, bgcolor: 'background.default' }}>
                    <Typography variant="caption" color="text.secondary">
                      Nível de Cobertura
                    </Typography>
                    <Typography variant="h4" sx={{ color: getCoverageColor(techniqueDetails.detectionCoverage) }}>
                      {getCoverageLabel(techniqueDetails.detectionCoverage)}
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} sm={4}>
                  <Paper sx={{ p: 2, bgcolor: 'background.default' }}>
                    <Typography variant="caption" color="text.secondary">
                      Última Detecção
                    </Typography>
                    <Typography variant="body1">
                      {techniqueDetails.lastDetected 
                        ? new Date(techniqueDetails.lastDetected).toLocaleString('pt-BR')
                        : 'N/A'}
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Divider sx={{ my: 2 }} />

              {/* ENHANCED: Detections Table */}
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                🔍 Eventos Detectados
                {loadingDetections && <CircularProgress size={20} />}
              </Typography>
              
              {loadingDetections ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                  <CircularProgress />
                </Box>
              ) : techniqueDetections.length === 0 ? (
                <Alert severity="info" sx={{ mb: 2 }}>
                  Nenhuma detecção encontrada para esta técnica. Os dados podem estar em eventos do GuardDuty.
                </Alert>
              ) : (
                <>
                  {/* Detection Cards with Full Details */}
                  {paginatedTechniqueDetections.map((detection, index) => (
                    <Paper 
                      key={detection.id || index} 
                      variant="outlined" 
                      sx={{ 
                        mb: 2, 
                        p: 2,
                        '&:hover': { borderColor: 'primary.main' }
                      }}
                    >
                      <Grid container spacing={2}>
                        {/* Header Row */}
                        <Grid item xs={12}>
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                            <Box>
                              <Typography variant="subtitle1" fontWeight={600}>
                                {detection.event_type || 'Evento Desconhecido'}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                {detection.timestamp 
                                  ? new Date(detection.timestamp).toLocaleString('pt-BR')
                                  : '-'} • {detection.source}
                              </Typography>
                            </Box>
                            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                              <Chip 
                                label={detection.severity} 
                                size="small"
                                color={getSeverityColor(detection.severity)}
                              />
                              <Tooltip title="Ver Detalhes Completos">
                                <IconButton 
                                  size="small"
                                  color="info"
                                  onClick={() => handleViewDetectionDetails(detection)}
                                >
                                  <InfoIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="Ver Evento Completo">
                                <IconButton 
                                  size="small"
                                  onClick={() => handleViewEvent(detection.event_id)}
                                >
                                  <VisibilityIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="Criar Caso">
                                <IconButton 
                                  size="small"
                                  color="primary"
                                  onClick={() => handleCreateCaseFromDetection(detection)}
                                >
                                  <FolderIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                            </Box>
                          </Box>
                        </Grid>

                        {/* Description */}
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">
                            {detection.description || 'Sem descrição disponível'}
                          </Typography>
                        </Grid>

                        {/* Details Grid */}
                        <Grid item xs={12}>
                          <Grid container spacing={1}>
                            {/* User */}
                            {detection.user && (
                              <Grid item xs={6} sm={3}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                  <PersonIcon fontSize="small" color="action" />
                                  <Box>
                                    <Typography variant="caption" color="text.secondary" display="block">
                                      Usuário
                                    </Typography>
                                    <Typography variant="body2" fontWeight={500}>
                                      {detection.user}
                                    </Typography>
                                  </Box>
                                </Box>
                              </Grid>
                            )}

                            {/* Source IP */}
                            {detection.source_ip && (
                              <Grid item xs={6} sm={3}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                  <PublicIcon fontSize="small" color="action" />
                                  <Box>
                                    <Typography variant="caption" color="text.secondary" display="block">
                                      IP de Origem
                                    </Typography>
                                    <Typography variant="body2" fontWeight={500} sx={{ fontFamily: 'monospace' }}>
                                      {detection.source_ip}
                                    </Typography>
                                  </Box>
                                </Box>
                              </Grid>
                            )}

                            {/* Destination IP */}
                            {detection.destination_ip && (
                              <Grid item xs={6} sm={3}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                  <PublicIcon fontSize="small" color="action" />
                                  <Box>
                                    <Typography variant="caption" color="text.secondary" display="block">
                                      IP de Destino
                                    </Typography>
                                    <Typography variant="body2" fontWeight={500} sx={{ fontFamily: 'monospace' }}>
                                      {detection.destination_ip}
                                    </Typography>
                                  </Box>
                                </Box>
                              </Grid>
                            )}

                            {/* Resource */}
                            {(detection.resource_type || detection.resource_id) && (
                              <Grid item xs={6} sm={3}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                  <ComputerIcon fontSize="small" color="action" />
                                  <Box>
                                    <Typography variant="caption" color="text.secondary" display="block">
                                      {detection.resource_type || 'Recurso'}
                                    </Typography>
                                    <Typography variant="body2" fontWeight={500} noWrap sx={{ maxWidth: 150 }}>
                                      {detection.resource_id || '-'}
                                    </Typography>
                                  </Box>
                                </Box>
                              </Grid>
                            )}

                            {/* Region */}
                            {detection.region && (
                              <Grid item xs={6} sm={3}>
                                <Box>
                                  <Typography variant="caption" color="text.secondary" display="block">
                                    Região
                                  </Typography>
                                  <Typography variant="body2">
                                    {detection.region}
                                  </Typography>
                                </Box>
                              </Grid>
                            )}

                            {/* Account ID */}
                            {detection.account_id && (
                              <Grid item xs={6} sm={3}>
                                <Box>
                                  <Typography variant="caption" color="text.secondary" display="block">
                                    Account ID
                                  </Typography>
                                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                    {detection.account_id}
                                  </Typography>
                                </Box>
                              </Grid>
                            )}

                            {/* Port */}
                            {detection.port > 0 && (
                              <Grid item xs={6} sm={3}>
                                <Box>
                                  <Typography variant="caption" color="text.secondary" display="block">
                                    Porta
                                  </Typography>
                                  <Typography variant="body2">
                                    {detection.port} {detection.protocol && `(${detection.protocol})`}
                                  </Typography>
                                </Box>
                              </Grid>
                            )}

                            {/* Action */}
                            {detection.action && (
                              <Grid item xs={6} sm={3}>
                                <Box>
                                  <Typography variant="caption" color="text.secondary" display="block">
                                    Ação
                                  </Typography>
                                  <Typography variant="body2">
                                    {detection.action}
                                  </Typography>
                                </Box>
                              </Grid>
                            )}

                            {/* Threat Name */}
                            {detection.threat_name && (
                              <Grid item xs={6} sm={3}>
                                <Box>
                                  <Typography variant="caption" color="text.secondary" display="block">
                                    Ameaça
                                  </Typography>
                                  <Chip 
                                    label={detection.threat_name} 
                                    size="small" 
                                    color="error"
                                    variant="outlined"
                                  />
                                </Box>
                              </Grid>
                            )}

                            {/* Threat List */}
                            {detection.threat_list_name && (
                              <Grid item xs={6} sm={3}>
                                <Box>
                                  <Typography variant="caption" color="text.secondary" display="block">
                                    Lista de Ameaças
                                  </Typography>
                                  <Typography variant="body2">
                                    {detection.threat_list_name}
                                  </Typography>
                                </Box>
                              </Grid>
                            )}
                          </Grid>
                        </Grid>

                        {/* Resource ARN if available */}
                        {detection.resource_arn && (
                          <Grid item xs={12}>
                            <Typography variant="caption" color="text.secondary">
                              ARN: <code style={{ fontSize: '11px' }}>{detection.resource_arn}</code>
                            </Typography>
                          </Grid>
                        )}
                      </Grid>
                    </Paper>
                  ))}
                  
                  {techniqueDetections.length > detectionsPerPage && (
                    <Box sx={{ display: 'flex', justifyContent: 'center' }}>
                      <Pagination
                        count={Math.ceil(techniqueDetections.length / detectionsPerPage)}
                        page={detectionsPage}
                        onChange={(e, page) => setDetectionsPage(page)}
                        color="primary"
                        size="small"
                      />
                    </Box>
                  )}
                </>
              )}

              <Divider sx={{ my: 2 }} />

              {/* Metadata */}
              <Grid container spacing={2}>
                {techniqueDetails.platforms && techniqueDetails.platforms.length > 0 && (
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle2" gutterBottom>
                      Plataformas
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      {techniqueDetails.platforms.map((platform) => (
                        <Chip key={platform} label={platform} size="small" variant="outlined" />
                      ))}
                    </Box>
                  </Grid>
                )}

                {techniqueDetails.tacticIds && (
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle2" gutterBottom>
                      Táticas Relacionadas
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      {techniqueDetails.tacticIds.map((tacticId) => {
                        const tactic = tactics.find(t => t.id === tacticId);
                        return tactic ? (
                          <Chip 
                            key={tacticId} 
                            label={`${tacticId}: ${tactic.name}`} 
                            size="small" 
                            color="secondary"
                          />
                        ) : null;
                      })}
                    </Box>
                  </Grid>
                )}
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button 
                startIcon={<OpenInNewIcon />}
                href={`https://attack.mitre.org/techniques/${techniqueDetails.id}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                Ver no MITRE ATT&CK
              </Button>
              <Button onClick={handleCloseTechniqueDialog} variant="contained">
                Fechar
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Dialog de Criar Caso */}
      <Dialog
        open={createCaseDialogOpen}
        onClose={() => setCreateCaseDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Criar Caso de Investigação</DialogTitle>
        <DialogContent>
          {selectedDetection && (
            <Box sx={{ mt: 2 }}>
              <Alert severity="info" sx={{ mb: 2 }}>
                Será criado um caso para investigar esta detecção MITRE ATT&CK.
              </Alert>
              
              <Typography variant="subtitle2" gutterBottom>Técnica</Typography>
              <Typography variant="body1" sx={{ mb: 2 }}>
                {selectedDetection.technique_id}: {selectedDetection.technique_name}
              </Typography>
              
              <Typography variant="subtitle2" gutterBottom>Tática</Typography>
              <Typography variant="body1" sx={{ mb: 2 }}>
                {selectedDetection.tactic_id}: {selectedDetection.tactic_name}
              </Typography>
              
              <Typography variant="subtitle2" gutterBottom>Severidade</Typography>
              <Chip 
                label={selectedDetection.severity} 
                color={getSeverityColor(selectedDetection.severity)}
                sx={{ mb: 2 }}
              />
              
              <Typography variant="subtitle2" gutterBottom>Descrição</Typography>
              <Paper sx={{ p: 2, bgcolor: 'background.default', maxHeight: 150, overflow: 'auto' }}>
                <Typography variant="body2">
                  {selectedDetection.description || 'Sem descrição'}
                </Typography>
              </Paper>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateCaseDialogOpen(false)} disabled={creatingCase}>
            Cancelar
          </Button>
          <Button 
            variant="contained" 
            color="primary"
            onClick={handleConfirmCreateCase}
            disabled={creatingCase}
            startIcon={creatingCase ? <CircularProgress size={16} /> : <FolderIcon />}
          >
            {creatingCase ? 'Criando...' : 'Criar Caso'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Detalhes Completos da Detecção */}
      <Dialog
        open={detectionDetailsOpen}
        onClose={() => setDetectionDetailsOpen(false)}
        maxWidth="lg"
        fullWidth
      >
        {selectedDetectionDetails && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <SecurityIcon color="error" />
                    <Typography variant="h6">
                      Detalhes da Detecção MITRE
                    </Typography>
                  </Box>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    <Chip label={selectedDetectionDetails.technique_id} size="small" color="primary" />
                    <Chip label={selectedDetectionDetails.tactic_id} size="small" variant="outlined" />
                    <Chip 
                      label={selectedDetectionDetails.severity} 
                      size="small"
                      color={getSeverityColor(selectedDetectionDetails.severity)}
                    />
                  </Box>
                </Box>
                <IconButton onClick={() => setDetectionDetailsOpen(false)}>
                  <CloseIcon />
                </IconButton>
              </Box>
            </DialogTitle>
            <DialogContent dividers>
              {/* MITRE Info */}
              <Paper sx={{ p: 2, mb: 3, bgcolor: 'primary.dark', color: 'white' }}>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" sx={{ opacity: 0.8 }}>Técnica MITRE</Typography>
                    <Typography variant="h6">
                      {selectedDetectionDetails.technique_id}: {selectedDetectionDetails.technique_name}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" sx={{ opacity: 0.8 }}>Tática</Typography>
                    <Typography variant="h6">
                      {selectedDetectionDetails.tactic_id}: {selectedDetectionDetails.tactic_name}
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>

              {/* Event Info */}
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <StorageIcon /> Informações do Evento
              </Typography>
              <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" color="text.secondary">Tipo de Evento</Typography>
                    <Typography variant="body1" fontWeight={500}>
                      {selectedDetectionDetails.event_type || '-'}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" color="text.secondary">Timestamp</Typography>
                    <Typography variant="body1">
                      {selectedDetectionDetails.timestamp 
                        ? new Date(selectedDetectionDetails.timestamp).toLocaleString('pt-BR')
                        : '-'}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" color="text.secondary">Fonte</Typography>
                    <Typography variant="body1">
                      {selectedDetectionDetails.source || '-'}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="caption" color="text.secondary">Event ID</Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                      {selectedDetectionDetails.event_id || selectedDetectionDetails.id}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="caption" color="text.secondary">Descrição</Typography>
                    <Typography variant="body1">
                      {selectedDetectionDetails.description || 'Sem descrição disponível'}
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>

              {/* Offender/Actor Info */}
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <PersonIcon /> Informações do Ofensor/Ator
              </Typography>
              <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
                <Grid container spacing={2}>
                  {selectedDetectionDetails.user && (
                    <Grid item xs={12} md={4}>
                      <Typography variant="caption" color="text.secondary">Usuário/Principal</Typography>
                      <Typography variant="body1" fontWeight={600} color="error.main">
                        {selectedDetectionDetails.user}
                      </Typography>
                    </Grid>
                  )}
                  {selectedDetectionDetails.source_ip && (
                    <Grid item xs={12} md={4}>
                      <Typography variant="caption" color="text.secondary">IP de Origem</Typography>
                      <Typography variant="body1" fontWeight={600} color="error.main" sx={{ fontFamily: 'monospace' }}>
                        {selectedDetectionDetails.source_ip}
                      </Typography>
                    </Grid>
                  )}
                  {selectedDetectionDetails.destination_ip && (
                    <Grid item xs={12} md={4}>
                      <Typography variant="caption" color="text.secondary">IP de Destino</Typography>
                      <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                        {selectedDetectionDetails.destination_ip}
                      </Typography>
                    </Grid>
                  )}
                  {selectedDetectionDetails.account_id && (
                    <Grid item xs={12} md={4}>
                      <Typography variant="caption" color="text.secondary">Account ID AWS</Typography>
                      <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                        {selectedDetectionDetails.account_id}
                      </Typography>
                    </Grid>
                  )}
                  {selectedDetectionDetails.port > 0 && (
                    <Grid item xs={12} md={4}>
                      <Typography variant="caption" color="text.secondary">Porta</Typography>
                      <Typography variant="body1">
                        {selectedDetectionDetails.port} 
                        {selectedDetectionDetails.protocol && ` (${selectedDetectionDetails.protocol})`}
                      </Typography>
                    </Grid>
                  )}
                  {selectedDetectionDetails.action && (
                    <Grid item xs={12} md={4}>
                      <Typography variant="caption" color="text.secondary">Tipo de Ação</Typography>
                      <Typography variant="body1">
                        {selectedDetectionDetails.action}
                      </Typography>
                    </Grid>
                  )}
                  {!selectedDetectionDetails.user && !selectedDetectionDetails.source_ip && (
                    <Grid item xs={12}>
                      <Alert severity="warning" variant="outlined">
                        Informações do ofensor não disponíveis para este evento
                      </Alert>
                    </Grid>
                  )}
                </Grid>
              </Paper>

              {/* Resource/Target Info */}
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ComputerIcon /> Recurso Alvo
              </Typography>
              <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
                <Grid container spacing={2}>
                  {selectedDetectionDetails.resource_type && (
                    <Grid item xs={12} md={4}>
                      <Typography variant="caption" color="text.secondary">Tipo de Recurso</Typography>
                      <Chip label={selectedDetectionDetails.resource_type} size="small" color="info" />
                    </Grid>
                  )}
                  {selectedDetectionDetails.resource_id && (
                    <Grid item xs={12} md={4}>
                      <Typography variant="caption" color="text.secondary">ID do Recurso</Typography>
                      <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                        {selectedDetectionDetails.resource_id}
                      </Typography>
                    </Grid>
                  )}
                  {selectedDetectionDetails.region && (
                    <Grid item xs={12} md={4}>
                      <Typography variant="caption" color="text.secondary">Região AWS</Typography>
                      <Typography variant="body1">
                        {selectedDetectionDetails.region}
                      </Typography>
                    </Grid>
                  )}
                  {selectedDetectionDetails.resource_arn && (
                    <Grid item xs={12}>
                      <Typography variant="caption" color="text.secondary">ARN do Recurso</Typography>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                        {selectedDetectionDetails.resource_arn}
                      </Typography>
                    </Grid>
                  )}
                  {!selectedDetectionDetails.resource_type && !selectedDetectionDetails.resource_id && (
                    <Grid item xs={12}>
                      <Alert severity="info" variant="outlined">
                        Informações do recurso alvo não disponíveis para este evento
                      </Alert>
                    </Grid>
                  )}
                </Grid>
              </Paper>

              {/* Threat Intel */}
              {(selectedDetectionDetails.threat_name || selectedDetectionDetails.threat_list_name) && (
                <>
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <WarningIcon color="error" /> Inteligência de Ameaças
                  </Typography>
                  <Paper variant="outlined" sx={{ p: 2, mb: 3, borderColor: 'error.main' }}>
                    <Grid container spacing={2}>
                      {selectedDetectionDetails.threat_name && (
                        <Grid item xs={12} md={6}>
                          <Typography variant="caption" color="text.secondary">Nome da Ameaça</Typography>
                          <Typography variant="body1" fontWeight={600} color="error.main">
                            {selectedDetectionDetails.threat_name}
                          </Typography>
                        </Grid>
                      )}
                      {selectedDetectionDetails.threat_list_name && (
                        <Grid item xs={12} md={6}>
                          <Typography variant="caption" color="text.secondary">Lista de Ameaças</Typography>
                          <Typography variant="body1">
                            {selectedDetectionDetails.threat_list_name}
                          </Typography>
                        </Grid>
                      )}
                    </Grid>
                  </Paper>
                </>
              )}

              {/* Raw Details */}
              {selectedDetectionDetails.raw_details && Object.keys(selectedDetectionDetails.raw_details).length > 0 && (
                <>
                  <Typography variant="h6" gutterBottom>
                    📋 Dados Brutos (JSON)
                  </Typography>
                  <Paper 
                    sx={{ 
                      p: 2, 
                      bgcolor: '#0d1117', 
                      maxHeight: 400, 
                      overflow: 'auto' 
                    }}
                  >
                    <pre style={{ 
                      margin: 0, 
                      color: '#c9d1d9', 
                      fontFamily: 'Monaco, Consolas, monospace',
                      fontSize: '12px',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all'
                    }}>
                      {JSON.stringify(selectedDetectionDetails.raw_details, null, 2)}
                    </pre>
                  </Paper>
                </>
              )}
            </DialogContent>
            <DialogActions>
              <Button 
                startIcon={<VisibilityIcon />}
                onClick={() => handleViewEvent(selectedDetectionDetails.event_id)}
              >
                Ver Evento Original
              </Button>
              <Button 
                startIcon={<OpenInNewIcon />}
                href={`https://attack.mitre.org/techniques/${selectedDetectionDetails.technique_id}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                Ver no MITRE
              </Button>
              <Button 
                variant="contained"
                color="primary"
                startIcon={<FolderIcon />}
                onClick={() => {
                  setDetectionDetailsOpen(false);
                  handleCreateCaseFromDetection(selectedDetectionDetails);
                }}
              >
                Criar Caso
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
};

export default MitreAttack;
