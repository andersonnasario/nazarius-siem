import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { safeUrl } from '../utils/security';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  Alert,
  CircularProgress,
  Divider,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemText,
  Paper,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  IconButton,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
} from '@mui/material';
import {
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineConnector,
  TimelineContent,
  TimelineDot,
  TimelineOppositeContent,
} from '@mui/lab';
import {
  ArrowBack as ArrowBackIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Storage as StorageIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Remove as StableIcon,
  Recommend as RecommendIcon,
  BugReport as BugIcon,
  Computer as ComputerIcon,
  History as HistoryIcon,
  PlayArrow as PlayIcon,
  ExpandMore as ExpandMoreIcon,
  ContentCopy as CopyIcon,
  OpenInNew as OpenInNewIcon,
  Check as CheckIcon,
  Info as InfoIcon,
  Folder as FolderIcon,
  Assessment as AssessmentIcon,
  Gavel as GavelIcon,
} from '@mui/icons-material';
import { alertsAPI, casesAPI } from '../services/api';

// ============================================================================
// HELPERS
// ============================================================================

const getSeverityColor = (severity) => {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return 'error';
  if (s === 'high') return 'warning';
  if (s === 'medium') return 'info';
  return 'success';
};

const getSeverityBgColor = (severity) => {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return '#d32f2f';
  if (s === 'high') return '#f57c00';
  if (s === 'medium') return '#1976d2';
  return '#388e3c';
};

const formatDate = (dateStr) => {
  if (!dateStr) return 'N/A';
  const date = new Date(dateStr);
  return date.toLocaleString('pt-BR');
};

const getTrendIcon = (trend) => {
  if (trend === 'increasing') return <TrendingUpIcon color="error" />;
  if (trend === 'decreasing') return <TrendingDownIcon color="success" />;
  return <StableIcon color="info" />;
};

// ============================================================================
// TAB PANEL
// ============================================================================

function TabPanel({ children, value, index, ...other }) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`alert-tabpanel-${index}`}
      aria-labelledby={`alert-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

const AlertDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  const [creatingCase, setCreatingCase] = useState(false);
  const [caseCreated, setCaseCreated] = useState(false);

  const loadAlertDetails = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await alertsAPI.get(id);
      setAlert(response.data);
    } catch (err) {
      console.error('Erro ao carregar alerta:', err);
      setError('Erro ao carregar detalhes do alerta.');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadAlertDetails();
  }, [loadAlertDetails]);

  const handleCreateCase = async () => {
    try {
      setCreatingCase(true);
      await casesAPI.createFromAlert(id, {
        title: `Caso: ${alert.name}`,
        description: alert.description,
        priority: alert.severity === 'critical' ? 'critical' : alert.severity,
      });
      setCaseCreated(true);
    } catch (err) {
      console.error('Erro ao criar caso:', err);
    } finally {
      setCreatingCase(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box p={3}>
        <Alert severity="error">{error}</Alert>
        <Button onClick={() => navigate(-1)} sx={{ mt: 2 }}>
          Voltar
        </Button>
      </Box>
    );
  }

  if (!alert) return null;

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <Box>
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate(-1)}
            sx={{ mb: 2 }}
          >
            Voltar para Alertas
          </Button>
          <Typography variant="h4" fontWeight={700} gutterBottom>
            {alert.name || alert.title || 'Detalhes do Alerta'}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Chip 
              label={alert.severity?.toUpperCase()} 
              color={getSeverityColor(alert.severity)}
              size="medium"
            />
            <Chip 
              label={alert.status} 
              variant="outlined"
              size="medium"
            />
            <Chip 
              label={alert.source?.toUpperCase()} 
              variant="outlined"
              color="primary"
              size="medium"
            />
            {alert.category && (
              <Chip label={alert.category} variant="outlined" size="medium" />
            )}
          </Box>
        </Box>
        
        <Box sx={{ display: 'flex', gap: 2 }}>
          {!caseCreated && !alert.related_case && (
            <Button
              variant="contained"
              color="warning"
              startIcon={<FolderIcon />}
              onClick={handleCreateCase}
              disabled={creatingCase}
            >
              {creatingCase ? 'Criando...' : 'Criar Caso'}
            </Button>
          )}
          {(caseCreated || alert.related_case) && (
            <Chip 
              icon={<CheckIcon />} 
              label="Caso Criado" 
              color="success" 
              variant="outlined"
            />
          )}
        </Box>
      </Box>

      {/* Risk Score Card */}
      {alert.security_context && (
        <Card 
          sx={{ 
            mb: 3, 
            bgcolor: getSeverityBgColor(alert.severity),
            color: 'white'
          }}
        >
          <CardContent>
            <Grid container spacing={3} alignItems="center">
              <Grid item>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h2" fontWeight={700}>
                    {alert.security_context.risk_score || 0}
                  </Typography>
                  <Typography variant="body2">Risk Score</Typography>
                </Box>
              </Grid>
              <Grid item xs>
                <Typography variant="h6" gutterBottom>
                  {alert.security_context.business_impact}
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {alert.security_context.risk_factors?.map((factor, idx) => (
                    <Chip 
                      key={idx}
                      label={factor}
                      size="small"
                      sx={{ bgcolor: 'rgba(255,255,255,0.2)', color: 'white' }}
                    />
                  ))}
                </Box>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs 
          value={tabValue} 
          onChange={(e, newValue) => setTabValue(newValue)}
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab icon={<InfoIcon />} label="Visão Geral" />
          <Tab icon={<StorageIcon />} label="Origem do Log" />
          <Tab icon={<AssessmentIcon />} label="Incidências" />
          <Tab icon={<RecommendIcon />} label="Recomendações" />
          <Tab icon={<SecurityIcon />} label="Contexto de Segurança" />
          <Tab icon={<ComputerIcon />} label="Ativos Afetados" />
          <Tab icon={<HistoryIcon />} label="Timeline" />
          <Tab icon={<PlayIcon />} label="Ações Sugeridas" />
        </Tabs>
      </Paper>

      {/* Tab: Visão Geral */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  📋 Descrição
                </Typography>
                <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
                  {alert.description || 'Sem descrição disponível.'}
                </Typography>
                
                <Divider sx={{ my: 3 }} />
                
                <Typography variant="h6" gutterBottom>
                  📍 Detalhes do Recurso
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} md={3}>
                    <Typography variant="caption" color="text.secondary">
                      Resource ID
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {alert.resource_id || 'N/A'}
                    </Typography>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Typography variant="caption" color="text.secondary">
                      Resource Type
                    </Typography>
                    <Typography variant="body2">
                      {alert.resource_type || 'N/A'}
                    </Typography>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Typography variant="caption" color="text.secondary">
                      Região
                    </Typography>
                    <Typography variant="body2">
                      {alert.region || 'N/A'}
                    </Typography>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Typography variant="caption" color="text.secondary">
                      Account ID
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {alert.account_id || 'N/A'}
                    </Typography>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={4}>
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  ⏰ Timestamps
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemText 
                      primary="Criado em"
                      secondary={formatDate(alert.created_at)}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText 
                      primary="Atualizado em"
                      secondary={formatDate(alert.updated_at)}
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>

            {alert.related_case && (
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    📁 Caso Relacionado
                  </Typography>
                  <Typography variant="body2">
                    ID: {alert.related_case.case_id}
                  </Typography>
                  <Chip 
                    label={alert.related_case.case_status}
                    size="small"
                    sx={{ mt: 1 }}
                  />
                </CardContent>
              </Card>
            )}
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab: Origem do Log */}
      <TabPanel value={tabValue} index={1}>
        {alert.log_source ? (
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    📡 Informações da Fonte
                  </Typography>
                  <Table size="small">
                    <TableBody>
                      <TableRow>
                        <TableCell><strong>Serviço</strong></TableCell>
                        <TableCell>{alert.log_source.service}</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell><strong>Tipo</strong></TableCell>
                        <TableCell>{alert.log_source.type}</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell><strong>Log Group</strong></TableCell>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                          {alert.log_source.log_group || 'N/A'}
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell><strong>Event Source</strong></TableCell>
                        <TableCell>{alert.log_source.event_source}</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell><strong>Event Name</strong></TableCell>
                        <TableCell>{alert.log_source.event_name}</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell><strong>IP de Origem</strong></TableCell>
                        <TableCell sx={{ fontFamily: 'monospace' }}>
                          {alert.log_source.source_ip || 'N/A'}
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell><strong>Região</strong></TableCell>
                        <TableCell>{alert.log_source.region}</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell><strong>Account ID</strong></TableCell>
                        <TableCell sx={{ fontFamily: 'monospace' }}>
                          {alert.log_source.account_id}
                        </TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6">
                      📄 Amostra do Log
                    </Typography>
                    <Tooltip title="Copiar">
                      <IconButton 
                        size="small"
                        onClick={() => copyToClipboard(alert.log_source.raw_log_sample)}
                      >
                        <CopyIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                  <Paper 
                    sx={{ 
                      p: 2, 
                      bgcolor: '#1e1e1e', 
                      color: '#d4d4d4',
                      fontFamily: 'monospace',
                      fontSize: '0.8rem',
                      overflow: 'auto',
                      maxHeight: 400,
                      whiteSpace: 'pre-wrap'
                    }}
                  >
                    {alert.log_source.raw_log_sample || 'Log não disponível'}
                  </Paper>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        ) : (
          <Alert severity="info">Informações da origem do log não disponíveis.</Alert>
        )}
      </TabPanel>

      {/* Tab: Incidências */}
      <TabPanel value={tabValue} index={2}>
        {alert.incident_count ? (
          <Grid container spacing={3}>
            <Grid item xs={12} md={3}>
              <Card sx={{ textAlign: 'center', py: 3 }}>
                <Typography variant="h3" color="primary" fontWeight={700}>
                  {alert.incident_count.total}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Total de Ocorrências
                </Typography>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card sx={{ textAlign: 'center', py: 3 }}>
                <Typography variant="h3" color="error" fontWeight={700}>
                  {alert.incident_count.last_24h}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Últimas 24h
                </Typography>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card sx={{ textAlign: 'center', py: 3 }}>
                <Typography variant="h3" color="warning.main" fontWeight={700}>
                  {alert.incident_count.last_7d}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Últimos 7 dias
                </Typography>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card sx={{ textAlign: 'center', py: 3 }}>
                <Typography variant="h3" color="info.main" fontWeight={700}>
                  {alert.incident_count.last_30d}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Últimos 30 dias
                </Typography>
              </Card>
            </Grid>

            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Grid container spacing={3}>
                    <Grid item xs={12} md={4}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        {getTrendIcon(alert.incident_count.trend)}
                        <Box>
                          <Typography variant="h6">
                            {alert.incident_count.trend === 'increasing' ? 'Tendência de Alta' :
                             alert.incident_count.trend === 'decreasing' ? 'Tendência de Queda' : 'Estável'}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {alert.incident_count.trend_percentage > 0 ? '+' : ''}
                            {alert.incident_count.trend_percentage?.toFixed(1)}% vs média semanal
                          </Typography>
                        </Box>
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Typography variant="body2" color="text.secondary">
                        Recursos Únicos Afetados
                      </Typography>
                      <Typography variant="h5">
                        {alert.incident_count.unique_resources}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Typography variant="body2" color="text.secondary">
                        Contas Únicas Afetadas
                      </Typography>
                      <Typography variant="h5">
                        {alert.incident_count.unique_accounts}
                      </Typography>
                    </Grid>
                  </Grid>
                  
                  <Divider sx={{ my: 3 }} />
                  
                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">
                        Primeira ocorrência
                      </Typography>
                      <Typography variant="body2">
                        {formatDate(alert.incident_count.first_seen)}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">
                        Última ocorrência
                      </Typography>
                      <Typography variant="body2">
                        {formatDate(alert.incident_count.last_seen)}
                      </Typography>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        ) : (
          <Alert severity="info">Estatísticas de incidências não disponíveis.</Alert>
        )}
      </TabPanel>

      {/* Tab: Recomendações */}
      <TabPanel value={tabValue} index={3}>
        {alert.recommendations && alert.recommendations.length > 0 ? (
          <Box>
            {alert.recommendations.map((rec, idx) => (
              <Accordion key={idx} defaultExpanded={rec.priority === 1}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                    <Chip 
                      label={`P${rec.priority}`}
                      size="small"
                      color={rec.priority === 1 ? 'error' : rec.priority === 2 ? 'warning' : 'default'}
                    />
                    <Typography fontWeight={600}>{rec.title}</Typography>
                    <Box sx={{ ml: 'auto', display: 'flex', gap: 1 }}>
                      <Chip label={rec.type} size="small" variant="outlined" />
                      <Chip label={`Esforço: ${rec.effort}`} size="small" variant="outlined" />
                      {rec.automated && (
                        <Chip label="Automatizável" size="small" color="success" />
                      )}
                    </Box>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" paragraph>
                    {rec.description}
                  </Typography>
                  
                  <Paper sx={{ p: 2, bgcolor: 'action.hover', mb: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      📋 Ação Recomendada:
                    </Typography>
                    <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                      {rec.action}
                    </Typography>
                  </Paper>
                  
                  <Typography variant="body2" color="text.secondary" paragraph>
                    <strong>Impacto esperado:</strong> {rec.impact}
                  </Typography>
                  
                  {rec.aws_doc && (
                    <Button
                      size="small"
                      startIcon={<OpenInNewIcon />}
                      href={safeUrl(rec.aws_doc)}
                      target="_blank"
                    >
                      Documentação AWS
                    </Button>
                  )}
                  
                  {rec.playbook_id && (
                    <Button
                      size="small"
                      startIcon={<PlayIcon />}
                      color="secondary"
                      sx={{ ml: 1 }}
                    >
                      Executar Playbook
                    </Button>
                  )}
                </AccordionDetails>
              </Accordion>
            ))}
          </Box>
        ) : (
          <Alert severity="info">Nenhuma recomendação disponível.</Alert>
        )}
      </TabPanel>

      {/* Tab: Contexto de Segurança */}
      <TabPanel value={tabValue} index={4}>
        {alert.security_context ? (
          <Grid container spacing={3}>
            {/* MITRE ATT&CK */}
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    🎯 MITRE ATT&CK
                  </Typography>
                  
                  {alert.security_context.mitre_tactics?.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" color="text.secondary">
                        Táticas
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        {alert.security_context.mitre_tactics.map((tactic, idx) => (
                          <Chip 
                            key={idx}
                            label={tactic}
                            color="error"
                            variant="outlined"
                            size="small"
                          />
                        ))}
                      </Box>
                    </Box>
                  )}
                  
                  {alert.security_context.mitre_techniques?.length > 0 && (
                    <Box>
                      <Typography variant="subtitle2" color="text.secondary">
                        Técnicas
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        {alert.security_context.mitre_techniques.map((tech, idx) => (
                          <Chip 
                            key={idx}
                            label={tech}
                            color="warning"
                            variant="outlined"
                            size="small"
                          />
                        ))}
                      </Box>
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>
            
            {/* Compliance */}
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    <GavelIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                    Compliance
                  </Typography>
                  
                  {alert.security_context.compliance_frameworks?.length > 0 && (
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      {alert.security_context.compliance_frameworks.map((fw, idx) => (
                        <Chip 
                          key={idx}
                          label={fw}
                          color="primary"
                          variant="outlined"
                        />
                      ))}
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>

            {/* CVEs Relacionados */}
            {alert.security_context.related_cves?.length > 0 && (
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      <BugIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                      CVEs Relacionados
                    </Typography>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>CVE ID</TableCell>
                          <TableCell>CVSS</TableCell>
                          <TableCell>Severidade</TableCell>
                          <TableCell>Descrição</TableCell>
                          <TableCell>Explorado</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {alert.security_context.related_cves.map((cve, idx) => (
                          <TableRow key={idx}>
                            <TableCell sx={{ fontFamily: 'monospace' }}>
                              {cve.cve_id}
                            </TableCell>
                            <TableCell>{cve.cvss}</TableCell>
                            <TableCell>
                              <Chip 
                                label={cve.severity}
                                size="small"
                                color={getSeverityColor(cve.severity)}
                              />
                            </TableCell>
                            <TableCell>{cve.description}</TableCell>
                            <TableCell>
                              {cve.exploited ? (
                                <Chip label="Sim" color="error" size="small" />
                              ) : (
                                <Chip label="Não" variant="outlined" size="small" />
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </Grid>
            )}
          </Grid>
        ) : (
          <Alert severity="info">Contexto de segurança não disponível.</Alert>
        )}
      </TabPanel>

      {/* Tab: Ativos Afetados */}
      <TabPanel value={tabValue} index={5}>
        {alert.affected_assets && alert.affected_assets.length > 0 ? (
          <Grid container spacing={3}>
            {alert.affected_assets.map((asset, idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <Box>
                        <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                          {asset.resource_name || asset.resource_id}
                        </Typography>
                        <Chip 
                          label={asset.resource_type}
                          size="small"
                          sx={{ mt: 1 }}
                        />
                      </Box>
                      <Chip 
                        label={`Criticidade: ${asset.criticality}`}
                        color={asset.criticality === 'critical' ? 'error' : 
                               asset.criticality === 'high' ? 'warning' : 'default'}
                        size="small"
                      />
                    </Box>
                    
                    <Divider sx={{ my: 2 }} />
                    
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">
                          Região
                        </Typography>
                        <Typography variant="body2">{asset.region || 'N/A'}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">
                          Account ID
                        </Typography>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {asset.account_id || 'N/A'}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">
                          Ambiente
                        </Typography>
                        <Typography variant="body2">
                          {asset.environment || 'N/A'}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">
                          Proprietário
                        </Typography>
                        <Typography variant="body2">
                          {asset.owner || 'N/A'}
                        </Typography>
                      </Grid>
                      {asset.ip_address && (
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">
                            IP Address
                          </Typography>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {asset.ip_address}
                          </Typography>
                        </Grid>
                      )}
                      {asset.vpc_id && (
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">
                            VPC ID
                          </Typography>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {asset.vpc_id}
                          </Typography>
                        </Grid>
                      )}
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        ) : (
          <Alert severity="info">Nenhum ativo afetado identificado.</Alert>
        )}
      </TabPanel>

      {/* Tab: Timeline */}
      <TabPanel value={tabValue} index={6}>
        {alert.timeline && alert.timeline.length > 0 ? (
          <Timeline position="alternate">
            {alert.timeline.map((entry, idx) => (
              <TimelineItem key={idx}>
                <TimelineOppositeContent color="text.secondary">
                  {formatDate(entry.timestamp)}
                </TimelineOppositeContent>
                <TimelineSeparator>
                  <TimelineDot color={
                    entry.event === 'alert_created' ? 'error' :
                    entry.event === 'alert_updated' ? 'warning' : 'grey'
                  }>
                    {entry.event === 'alert_created' ? <WarningIcon /> : <HistoryIcon />}
                  </TimelineDot>
                  {idx < alert.timeline.length - 1 && <TimelineConnector />}
                </TimelineSeparator>
                <TimelineContent>
                  <Paper elevation={3} sx={{ p: 2 }}>
                    <Typography variant="subtitle2">
                      {entry.description}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Fonte: {entry.source}
                    </Typography>
                  </Paper>
                </TimelineContent>
              </TimelineItem>
            ))}
          </Timeline>
        ) : (
          <Alert severity="info">Timeline não disponível.</Alert>
        )}
      </TabPanel>

      {/* Tab: Ações Sugeridas */}
      <TabPanel value={tabValue} index={7}>
        {alert.suggested_actions && alert.suggested_actions.length > 0 ? (
          <Grid container spacing={2}>
            {alert.suggested_actions.map((action, idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Card sx={{ 
                  borderLeft: 4, 
                  borderColor: action.priority === 1 ? 'error.main' : 
                               action.priority === 2 ? 'warning.main' : 'grey.400'
                }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <Typography variant="h6" gutterBottom>
                        {action.title}
                      </Typography>
                      <Chip 
                        label={`P${action.priority}`}
                        size="small"
                        color={action.priority === 1 ? 'error' : action.priority === 2 ? 'warning' : 'default'}
                      />
                    </Box>
                    
                    <Typography variant="body2" color="text.secondary" paragraph>
                      {action.description}
                    </Typography>
                    
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
                      <Chip label={action.type} size="small" variant="outlined" />
                      <Chip label={`⏱️ ${action.estimated_time}`} size="small" variant="outlined" />
                      <Chip label={`👤 ${action.required_role}`} size="small" variant="outlined" />
                    </Box>
                    
                    {action.automated && (
                      <Button
                        variant="contained"
                        size="small"
                        startIcon={<PlayIcon />}
                        color="primary"
                      >
                        Executar Automaticamente
                      </Button>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        ) : (
          <Alert severity="info">Nenhuma ação sugerida disponível.</Alert>
        )}
      </TabPanel>
    </Box>
  );
};

export default AlertDetails;
