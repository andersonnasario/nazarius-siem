import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  CircularProgress,
  Alert,
  Chip,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Link,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  IconButton,
  Tooltip,
  Paper,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Computer as ComputerIcon,
  Refresh as RefreshIcon,
  PlayArrow as PlayArrowIcon,
  BugReport as BugReportIcon,
  TrendingUp as TrendingUpIcon,
  OpenInNew as OpenInNewIcon,
  Shield as ShieldIcon,
  Build as BuildIcon,
  Info as InfoIcon,
  LocalHospital as LocalHospitalIcon,
  Timeline as TimelineIcon,
  Link as LinkIcon,
  Code as CodeIcon,
} from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';
import { vulnerabilityAPI } from '../services/api';

const Vulnerabilities = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  
  // Dashboard data
  const [stats, setStats] = useState(null);
  const [topVulnerabilities, setTopVulnerabilities] = useState([]);
  const [topAssets, setTopAssets] = useState([]);
  const [trends, setTrends] = useState([]);
  
  // Vulnerabilities
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [vulnDialogOpen, setVulnDialogOpen] = useState(false);
  
  // Assets
  const [assets, setAssets] = useState([]);
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [assetDialogOpen, setAssetDialogOpen] = useState(false);
  
  // Scans
  const [scans, setScans] = useState([]);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [dashboardRes, vulnsRes, assetsRes, scansRes] = await Promise.all([
        vulnerabilityAPI.getDashboard(),
        vulnerabilityAPI.getVulnerabilities(),
        vulnerabilityAPI.getAssets(),
        vulnerabilityAPI.getScans(),
      ]);
      
      setStats(dashboardRes.data.stats);
      setTopVulnerabilities(dashboardRes.data.top_vulnerabilities);
      setTopAssets(dashboardRes.data.top_assets);
      setTrends(dashboardRes.data.trends);
      setVulnerabilities(vulnsRes.data.vulnerabilities);
      setAssets(assetsRes.data.assets);
      setScans(scansRes.data.scans);
    } catch (err) {
      console.error('Error loading vulnerability data:', err);
      setError('Erro ao carregar dados de vulnerabilidades');
    } finally {
      setLoading(false);
    }
  };

  const handleViewVulnerability = async (vulnId) => {
    try {
      const response = await vulnerabilityAPI.getVulnerability(vulnId);
      // A API retorna { vulnerability: {...}, related_findings: [...] }
      const vulnData = response.data.vulnerability || response.data;
      setSelectedVuln({
        ...vulnData,
        related_findings: response.data.related_findings || [],
      });
      setVulnDialogOpen(true);
    } catch (err) {
      console.error('Error loading vulnerability:', err);
    }
  };

  const handleUpdateVulnerability = async (status) => {
    try {
      await vulnerabilityAPI.updateVulnerability(selectedVuln.id, { status });
      setVulnDialogOpen(false);
      loadData();
    } catch (err) {
      console.error('Error updating vulnerability:', err);
    }
  };

  const handleViewAsset = async (assetId) => {
    try {
      console.log('🔍 Loading asset with ID:', assetId);
      console.log('🔗 API URL will be:', `/vulnerabilities/assets/${encodeURIComponent(assetId)}`);
      
      const response = await vulnerabilityAPI.getAsset(assetId);
      console.log('📥 Full API response:', JSON.stringify(response.data, null, 2));
      
      // A API retorna { asset: {...}, vulnerabilities: [...], source: "opensearch" }
      const assetData = response.data.asset || response.data;
      const vulnList = response.data.vulnerabilities || assetData.vulnerabilities || [];
      
      console.log('✅ Asset data:', assetData);
      console.log('📊 Vulnerabilities found:', vulnList.length);
      if (vulnList.length > 0) {
        console.log('📊 First vulnerability:', vulnList[0]);
      }
      
      // Merge com dados do card original para ter os counts
      const localAsset = assets.find(a => (a.resource_id || a.id) === assetId);
      console.log('📋 Local asset data:', localAsset);
      
      setSelectedAsset({
        ...localAsset, // Dados do card (counts, etc.)
        ...assetData,  // Dados detalhados do backend
        vulnerabilities: vulnList,
      });
      setAssetDialogOpen(true);
    } catch (err) {
      console.error('❌ Error loading asset:', err);
      console.error('❌ Error details:', err.response?.data || err.message);
      // Fallback: buscar no array local
      const localAsset = assets.find(a => (a.resource_id || a.id) === assetId);
      if (localAsset) {
        console.log('📂 Using local asset data:', localAsset);
        setSelectedAsset({
          ...localAsset,
          vulnerabilities: [],
        });
        setAssetDialogOpen(true);
      }
    }
  };

  const [syncing, setSyncing] = useState(false);

  const handleStartScan = async () => {
    if (syncing) return;
    
    setSyncing(true);
    try {
      // Sincronizar com Security Hub (que já tem dados do Inspector)
      const response = await vulnerabilityAPI.syncFromSecurityHub();
      console.log('✅ Sync response:', response.data);
      
      // Mostrar feedback
      alert('🔄 Sincronização iniciada!\n\nOs dados do AWS Security Hub estão sendo sincronizados em background.\n\nAtualize a página em alguns segundos para ver os novos dados.');
      
      // Aguardar um pouco e recarregar
      setTimeout(() => {
        loadData();
        setSyncing(false);
      }, 3000);
    } catch (err) {
      console.error('❌ Error syncing:', err);
      alert('Erro ao iniciar sincronização: ' + (err.response?.data?.error || err.message));
      setSyncing(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'error',
      high: 'warning',
      medium: 'info',
      low: 'success',
    };
    return colors[severity] || 'default';
  };

  const getStatusColor = (status) => {
    const colors = {
      open: 'error',
      in_progress: 'warning',
      patched: 'success',
      accepted_risk: 'info',
      false_positive: 'default',
    };
    return colors[status] || 'default';
  };

  const getCVSSColor = (score) => {
    if (score >= 9.0) return 'error';
    if (score >= 7.0) return 'warning';
    if (score >= 4.0) return 'info';
    return 'success';
  };

  const COLORS = ['#f44336', '#ff9800', '#2196f3', '#4caf50'];

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            🛡️ Vulnerability Management
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Gerenciamento de vulnerabilidades e patches
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="contained"
            startIcon={syncing ? <RefreshIcon className="spin" /> : <PlayArrowIcon />}
            onClick={handleStartScan}
            disabled={syncing}
          >
            Iniciar Scan
          </Button>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={loadData}
          >
            Atualizar
          </Button>
        </Box>
      </Box>

      {/* KPI Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <BugReportIcon sx={{ mr: 1, color: 'error.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Vulnerabilidades Abertas
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.open_vulns}</Typography>
              <Typography variant="caption" color="error">
                {stats?.critical_vulns} críticas
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <CheckCircleIcon sx={{ mr: 1, color: 'success.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Patch Compliance
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.patch_compliance?.toFixed(1)}%</Typography>
              <LinearProgress
                variant="determinate"
                value={stats?.patch_compliance}
                color={stats?.patch_compliance >= 80 ? 'success' : stats?.patch_compliance >= 60 ? 'warning' : 'error'}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <ComputerIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Ativos Vulneráveis
                </Typography>
              </Box>
              <Typography variant="h4">
                {stats?.vulnerable_assets}/{stats?.total_assets}
              </Typography>
              <Typography variant="caption">
                {stats?.assets_with_critical} com críticas
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <TrendingUpIcon sx={{ mr: 1, color: 'info.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Tempo Médio Remediação
                </Typography>
              </Box>
              <Typography variant="h4">{stats?.average_remediation_time}d</Typography>
              <Typography variant="caption">
                Último scan: {stats?.last_scan_date && new Date(stats.last_scan_date).toLocaleDateString('pt-BR')}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Card>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="Overview" />
          <Tab label="Vulnerabilidades" />
          <Tab label="Ativos" />
          <Tab label="Scans" />
        </Tabs>

        <CardContent>
          {/* Tab 0: Overview */}
          {tabValue === 0 && (
            <Box>
              <Grid container spacing={3}>
                {/* Vulnerability Trends */}
                <Grid item xs={12} md={8}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Tendência de Vulnerabilidades (7 dias)
                      </Typography>
                      <ResponsiveContainer width="100%" height={300}>
                        <LineChart data={trends}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="date" />
                          <YAxis />
                          <RechartsTooltip />
                          <Legend />
                          <Line type="monotone" dataKey="critical" stroke="#f44336" name="Críticas" />
                          <Line type="monotone" dataKey="high" stroke="#ff9800" name="Altas" />
                          <Line type="monotone" dataKey="medium" stroke="#2196f3" name="Médias" />
                        </LineChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Severity Distribution */}
                <Grid item xs={12} md={4}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Distribuição por Severidade
                      </Typography>
                      <ResponsiveContainer width="100%" height={300}>
                        <PieChart>
                          <Pie
                            data={[
                              { name: 'Críticas', value: stats?.critical_vulns },
                              { name: 'Altas', value: stats?.high_vulns },
                              { name: 'Médias', value: stats?.medium_vulns },
                              { name: 'Baixas', value: stats?.low_vulns },
                            ]}
                            dataKey="value"
                            nameKey="name"
                            cx="50%"
                            cy="50%"
                            outerRadius={80}
                            label
                          >
                            {[0, 1, 2, 3].map((index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index]} />
                            ))}
                          </Pie>
                          <RechartsTooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                </Grid>

                {/* Top Vulnerabilities */}
                <Grid item xs={12}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        Top 5 Vulnerabilidades Críticas
                      </Typography>
                      <TableContainer>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>CVE ID</TableCell>
                              <TableCell>Título</TableCell>
                              <TableCell>CVSS</TableCell>
                              <TableCell>Severidade</TableCell>
                              <TableCell>Ativos Afetados</TableCell>
                              <TableCell>Status</TableCell>
                              <TableCell>Ações</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {topVulnerabilities.map((vuln) => (
                              <TableRow key={vuln.id}>
                                <TableCell>
                                  <Typography variant="body2" fontWeight="bold">
                                    {vuln.cve_id}
                                  </Typography>
                                </TableCell>
                                <TableCell>{vuln.title}</TableCell>
                                <TableCell>
                                  <Chip
                                    label={vuln.cvss_score}
                                    size="small"
                                    color={getCVSSColor(vuln.cvss_score)}
                                  />
                                </TableCell>
                                <TableCell>
                                  <Chip
                                    label={vuln.severity}
                                    size="small"
                                    color={getSeverityColor(vuln.severity)}
                                  />
                                </TableCell>
                                <TableCell>{vuln.asset_count}</TableCell>
                                <TableCell>
                                  <Chip
                                    label={vuln.status}
                                    size="small"
                                    color={getStatusColor(vuln.status)}
                                  />
                                </TableCell>
                                <TableCell>
                                  <Button
                                    size="small"
                                    onClick={() => handleViewVulnerability(vuln.id)}
                                  >
                                    Ver
                                  </Button>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </Box>
          )}

          {/* Tab 1: Vulnerabilities */}
          {tabValue === 1 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Todas as Vulnerabilidades
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>CVE ID</TableCell>
                      <TableCell>Título</TableCell>
                      <TableCell>CVSS</TableCell>
                      <TableCell>Severidade</TableCell>
                      <TableCell>Ativos</TableCell>
                      <TableCell>Patch</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Detectada em</TableCell>
                      <TableCell>Ações</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {vulnerabilities.map((vuln) => (
                      <TableRow key={vuln.id}>
                        <TableCell>
                          <Typography variant="body2" fontWeight="bold">
                            {vuln.cve_id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
                            {vuln.title}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={vuln.cvss_score}
                            size="small"
                            color={getCVSSColor(vuln.cvss_score)}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={vuln.severity}
                            size="small"
                            color={getSeverityColor(vuln.severity)}
                          />
                        </TableCell>
                        <TableCell>{vuln.asset_count}</TableCell>
                        <TableCell>
                          {vuln.patch_available ? (
                            <Chip label="Disponível" size="small" color="success" />
                          ) : (
                            <Chip label="N/A" size="small" variant="outlined" />
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={vuln.status}
                            size="small"
                            color={getStatusColor(vuln.status)}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(vuln.detected_at).toLocaleDateString('pt-BR')}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Button
                            size="small"
                            onClick={() => handleViewVulnerability(vuln.id)}
                          >
                            Detalhes
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}

          {/* Tab 2: Assets */}
          {tabValue === 2 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Ativos Vulneráveis
              </Typography>
              <Grid container spacing={2}>
                {assets.map((asset) => {
                  // Determinar criticidade baseado no risk_score ou vulnerabilidades críticas
                  const riskScore = asset.risk_score || 0;
                  const hasCritical = (asset.critical_vulns || 0) > 0;
                  const criticality = hasCritical ? 'critical' : riskScore >= 70 ? 'high' : 'medium';
                  
                  // Criar nome amigável do ativo - prioridade: name > display_name > hostname > instance_id
                  const assetName = asset.name || asset.display_name || asset.hostname || asset.instance_id || 
                                   asset.resource_id?.split('/').pop() || 'Unknown Asset';
                  const assetType = asset.resource_type?.replace('AWS_', '').replace('_', ' ') || 'EC2 Instance';
                  
                  // Informações adicionais do ativo
                  const platform = asset.platform || '';
                  const topPackage = asset.top_vulnerable_package || (asset.vulnerable_packages?.length > 0 ? asset.vulnerable_packages[0] : '');
                  const topCVE = asset.top_cve_id || '';
                  
                  return (
                    <Grid item xs={12} sm={6} md={4} key={asset.id || asset.resource_id}>
                      <Card
                        variant="outlined"
                        sx={{
                          borderLeft: 4,
                          borderLeftColor: criticality === 'critical' ? 'error.main' : 
                                          criticality === 'high' ? 'warning.main' : 'info.main',
                          '&:hover': { boxShadow: 3, transform: 'translateY(-2px)' },
                          transition: 'all 0.2s ease'
                        }}
                      >
                        <CardContent>
                          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                            <ComputerIcon sx={{ mr: 1, color: criticality === 'critical' ? 'error.main' : 'primary.main' }} />
                            <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                              <Typography variant="subtitle1" noWrap title={assetName} fontWeight="bold">
                                {assetName}
                              </Typography>
                              <Typography variant="caption" color="text.secondary" noWrap>
                                {assetType} • {asset.region || 'us-east-1'}
                              </Typography>
                            </Box>
                            <Chip
                              label={criticality.toUpperCase()}
                              size="small"
                              color={criticality === 'critical' ? 'error' : 
                                     criticality === 'high' ? 'warning' : 'info'}
                            />
                          </Box>
                          
                          {/* Informações do Host/Serviço */}
                          <Box sx={{ mb: 1.5, p: 1, bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 1 }}>
                            {platform && (
                              <Typography variant="caption" display="block" sx={{ color: 'info.light' }}>
                                🖥️ {platform}
                              </Typography>
                            )}
                            {asset.instance_id && assetName !== asset.instance_id && (
                              <Typography variant="caption" display="block" sx={{ fontFamily: 'monospace', color: 'text.secondary' }}>
                                ID: {asset.instance_id}
                              </Typography>
                            )}
                            {topPackage && (
                              <Typography variant="caption" display="block" color="warning.main" noWrap title={topPackage}>
                                📦 {topPackage}
                              </Typography>
                            )}
                            {topCVE && (
                              <Typography variant="caption" display="block" color="error.light">
                                🔴 {topCVE}
                              </Typography>
                            )}
                          </Box>

                          <Box sx={{ mb: 1.5 }}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                              <Typography variant="caption">Risk Score</Typography>
                              <Typography variant="caption" fontWeight="bold" color={riskScore >= 80 ? 'error.main' : 'text.primary'}>
                                {Math.round(riskScore)}%
                              </Typography>
                            </Box>
                            <LinearProgress
                              variant="determinate"
                              value={Math.min(riskScore, 100)}
                              color={riskScore >= 80 ? 'error' : 
                                     riskScore >= 60 ? 'warning' : 'success'}
                              sx={{ height: 6, borderRadius: 1 }}
                            />
                          </Box>
                          <Grid container spacing={1} sx={{ mb: 1 }}>
                            <Grid item xs={4}>
                              <Typography variant="caption" color="text.secondary">Total</Typography>
                              <Typography variant="body2" fontWeight="bold">
                                {asset.vulnerability_count || 0}
                              </Typography>
                            </Grid>
                            <Grid item xs={4}>
                              <Typography variant="caption" color="error">Críticas</Typography>
                              <Typography variant="body2" fontWeight="bold" color="error.main">
                                {asset.critical_vulns || 0}
                              </Typography>
                            </Grid>
                            <Grid item xs={4}>
                              <Typography variant="caption" color="warning.main">Altas</Typography>
                              <Typography variant="body2" fontWeight="bold" color="warning.main">
                                {asset.high_vulns || 0}
                              </Typography>
                            </Grid>
                          </Grid>
                          <Button
                            fullWidth
                            size="small"
                            variant="outlined"
                            onClick={() => {
                              // Usar instance_id se disponível, senão extrair do ARN, senão usar resource_id
                              let assetIdToUse = asset.instance_id;
                              if (!assetIdToUse && asset.resource_id) {
                                // Extrair instance ID do ARN se for um ARN
                                if (asset.resource_id.includes('instance/')) {
                                  assetIdToUse = asset.resource_id.split('instance/')[1];
                                } else {
                                  assetIdToUse = asset.resource_id;
                                }
                              }
                              handleViewAsset(assetIdToUse || asset.id);
                            }}
                          >
                            Ver Vulnerabilidades
                          </Button>
                          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                            {asset.account_id && `Conta: ${asset.account_id.slice(-4)}`}
                            {asset.last_scanned && ` • Scan: ${new Date(asset.last_scanned).toLocaleDateString('pt-BR')}`}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  );
                })}
              </Grid>
            </Box>
          )}

          {/* Tab 3: Scans */}
          {tabValue === 3 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Histórico de Scans
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Nome</TableCell>
                      <TableCell>Tipo</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Ativos</TableCell>
                      <TableCell>Vulnerabilidades</TableCell>
                      <TableCell>Críticas</TableCell>
                      <TableCell>Iniciado em</TableCell>
                      <TableCell>Duração</TableCell>
                      <TableCell>Por</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {scans.map((scan) => (
                      <TableRow key={scan.id}>
                        <TableCell>{scan.name}</TableCell>
                        <TableCell>
                          <Chip label={scan.scan_type} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={scan.status}
                            size="small"
                            color={scan.status === 'completed' ? 'success' : 
                                   scan.status === 'running' ? 'info' : 'error'}
                          />
                        </TableCell>
                        <TableCell>{scan.assets_scanned}</TableCell>
                        <TableCell>{scan.vulns_found || '-'}</TableCell>
                        <TableCell>
                          {scan.critical_found ? (
                            <Chip label={scan.critical_found} size="small" color="error" />
                          ) : '-'}
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(scan.started_at).toLocaleString('pt-BR')}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {scan.duration ? `${Math.floor(scan.duration / 60)}min` : '-'}
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {scan.initiated_by}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Vulnerability Detail Dialog - Enhanced */}
      <Dialog 
        open={vulnDialogOpen} 
        onClose={() => setVulnDialogOpen(false)} 
        maxWidth="lg" 
        fullWidth
        PaperProps={{
          sx: { 
            backgroundColor: '#1a1a2e',
            backgroundImage: 'linear-gradient(rgba(255,255,255,0.02), rgba(255,255,255,0.02))',
          }
        }}
      >
        <DialogTitle sx={{ 
          borderBottom: '1px solid rgba(255,255,255,0.1)',
          display: 'flex',
          alignItems: 'center',
          gap: 2,
        }}>
          <BugReportIcon color="error" />
          <Box sx={{ flexGrow: 1 }}>
            <Typography variant="h6" component="span">
              {selectedVuln?.cve_id || 'Vulnerabilidade'}
            </Typography>
            {selectedVuln?.severity && (
              <Chip 
                label={selectedVuln.severity} 
                color={getSeverityColor(selectedVuln.severity)} 
                size="small" 
                sx={{ ml: 2 }}
              />
            )}
          </Box>
          {selectedVuln?.cve_id && (
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Tooltip title="Ver no NVD">
                <IconButton 
                  size="small" 
                  component={Link}
                  href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cve_id}`}
                  target="_blank"
                  sx={{ color: '#90caf9' }}
                >
                  <OpenInNewIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title="Ver no MITRE">
                <IconButton 
                  size="small"
                  component={Link}
                  href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${selectedVuln.cve_id}`}
                  target="_blank"
                  sx={{ color: '#90caf9' }}
                >
                  <ShieldIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Box>
          )}
        </DialogTitle>
        <DialogContent sx={{ pt: 3 }}>
          {selectedVuln && (
            <Grid container spacing={3}>
              {/* Left Column - Main Info */}
              <Grid item xs={12} md={8}>
                {/* Title & Description */}
                <Paper sx={{ p: 2, mb: 2, backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  <Typography variant="h6" gutterBottom sx={{ color: '#fff' }}>
                    {selectedVuln.title || 'Detalhes da Vulnerabilidade'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {selectedVuln.description || 'Sem descrição disponível.'}
                  </Typography>
                </Paper>

                {/* Remediation Section */}
                <Accordion defaultExpanded sx={{ backgroundColor: 'rgba(76, 175, 80, 0.1)', mb: 2 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <LocalHospitalIcon sx={{ mr: 1, color: '#4caf50' }} />
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                      🛠️ Recomendações de Remediação
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {selectedVuln.fix_available && selectedVuln.fixed_version && (
                        <ListItem>
                          <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                          <ListItemText 
                            primary="Atualizar para versão corrigida"
                            secondary={`Atualizar ${selectedVuln.vulnerable_package || 'o pacote'} para versão ${selectedVuln.fixed_version}`}
                          />
                        </ListItem>
                      )}
                      {!selectedVuln.fix_available && (
                        <ListItem>
                          <ListItemIcon><WarningIcon color="warning" /></ListItemIcon>
                          <ListItemText 
                            primary="Nenhum patch oficial disponível"
                            secondary="Considere medidas mitigatórias como isolamento de rede, WAF rules, ou compensating controls."
                          />
                        </ListItem>
                      )}
                      <ListItem>
                        <ListItemIcon><ShieldIcon color="info" /></ListItemIcon>
                        <ListItemText 
                          primary="Aplicar controles compensatórios"
                          secondary="Firewall rules, IDS/IPS signatures, network segmentation, least privilege access"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><SecurityIcon color="primary" /></ListItemIcon>
                        <ListItemText 
                          primary="Monitorar exploração"
                          secondary="Configure alertas para detecção de tentativas de exploração desta vulnerabilidade"
                        />
                      </ListItem>
                      {selectedVuln.exploit_available && (
                        <ListItem sx={{ backgroundColor: 'rgba(244, 67, 54, 0.1)', borderRadius: 1 }}>
                          <ListItemIcon><WarningIcon color="error" /></ListItemIcon>
                          <ListItemText 
                            primary="⚠️ EXPLOITS PÚBLICOS DISPONÍVEIS"
                            secondary="Prioridade máxima! Existem exploits públicos para esta vulnerabilidade."
                            primaryTypographyProps={{ color: 'error', fontWeight: 'bold' }}
                          />
                        </ListItem>
                      )}
                    </List>
                  </AccordionDetails>
                </Accordion>

                {/* MITRE ATT&CK Mapping */}
                <Accordion sx={{ backgroundColor: 'rgba(156, 39, 176, 0.1)', mb: 2 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <ShieldIcon sx={{ mr: 1, color: '#9c27b0' }} />
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                      🎯 MITRE ATT&CK Mapping
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      Táticas e técnicas potencialmente associadas a esta vulnerabilidade:
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                      <Chip label="TA0001 - Initial Access" size="small" variant="outlined" />
                      <Chip label="TA0002 - Execution" size="small" variant="outlined" />
                      {selectedVuln.exploit_available && (
                        <Chip label="T1190 - Exploit Public-Facing App" size="small" color="error" />
                      )}
                      {selectedVuln.type === 'NETWORK_REACHABILITY' && (
                        <Chip label="T1133 - External Remote Services" size="small" color="warning" />
                      )}
                      {selectedVuln.cvss_score >= 9 && (
                        <Chip label="TA0004 - Privilege Escalation" size="small" variant="outlined" />
                      )}
                    </Box>
                    <Box sx={{ mt: 2 }}>
                      <Button
                        size="small"
                        startIcon={<OpenInNewIcon />}
                        component={Link}
                        href="https://attack.mitre.org/"
                        target="_blank"
                        sx={{ textTransform: 'none' }}
                      >
                        Explorar MITRE ATT&CK Framework
                      </Button>
                    </Box>
                  </AccordionDetails>
                </Accordion>

                {/* Technical Details */}
                <Accordion sx={{ backgroundColor: 'rgba(33, 150, 243, 0.1)', mb: 2 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <CodeIcon sx={{ mr: 1, color: '#2196f3' }} />
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                      🔧 Detalhes Técnicos
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      {selectedVuln.vulnerable_package && (
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">Pacote Vulnerável</Typography>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', color: '#f44336' }}>
                            {selectedVuln.vulnerable_package} @ {selectedVuln.package_version || 'N/A'}
                          </Typography>
                        </Grid>
                      )}
                      {selectedVuln.fixed_version && (
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">Versão Corrigida</Typography>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', color: '#4caf50' }}>
                            {selectedVuln.fixed_version}
                          </Typography>
                        </Grid>
                      )}
                      {selectedVuln.cvss_vector && (
                        <Grid item xs={12}>
                          <Typography variant="caption" color="text.secondary">CVSS Vector</Typography>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                            {selectedVuln.cvss_vector}
                          </Typography>
                        </Grid>
                      )}
                      {selectedVuln.type && (
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">Tipo</Typography>
                          <Typography variant="body2">{selectedVuln.type}</Typography>
                        </Grid>
                      )}
                      {selectedVuln.package_manager && (
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">Package Manager</Typography>
                          <Typography variant="body2">{selectedVuln.package_manager}</Typography>
                        </Grid>
                      )}
                    </Grid>
                  </AccordionDetails>
                </Accordion>

                {/* Related Findings */}
                {selectedVuln.related_findings?.length > 0 && (
                  <Accordion sx={{ backgroundColor: 'rgba(255, 152, 0, 0.1)' }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <LinkIcon sx={{ mr: 1, color: '#ff9800' }} />
                      <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                        🔗 Findings Relacionados ({selectedVuln.related_findings.length})
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <TableContainer>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Recurso</TableCell>
                              <TableCell>Tipo</TableCell>
                              <TableCell>Status</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {selectedVuln.related_findings.slice(0, 5).map((finding, idx) => (
                              <TableRow key={idx}>
                                <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                  {finding.resource_id || finding.instance_id || 'N/A'}
                                </TableCell>
                                <TableCell>{finding.resource_type || 'N/A'}</TableCell>
                                <TableCell>
                                  <Chip label={finding.status} size="small" color={getStatusColor(finding.status)} />
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </AccordionDetails>
                  </Accordion>
                )}
              </Grid>

              {/* Right Column - Quick Info */}
              <Grid item xs={12} md={4}>
                {/* CVSS Score Card */}
                <Paper sx={{ p: 2, mb: 2, textAlign: 'center', backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  <Typography variant="caption" color="text.secondary">CVSS Score</Typography>
                  <Box sx={{ 
                    my: 1, 
                    fontSize: '2.5rem', 
                    fontWeight: 700,
                    color: selectedVuln.cvss_score >= 9 ? '#f44336' : 
                           selectedVuln.cvss_score >= 7 ? '#ff9800' :
                           selectedVuln.cvss_score >= 4 ? '#ffeb3b' : '#4caf50'
                  }}>
                    {selectedVuln.cvss_score?.toFixed(1) || 'N/A'}
                  </Box>
                  <Chip 
                    label={selectedVuln.severity || 'UNKNOWN'} 
                    color={getSeverityColor(selectedVuln.severity)} 
                    sx={{ fontWeight: 600 }}
                  />
                </Paper>

                {/* Status & Info */}
                <Paper sx={{ p: 2, mb: 2, backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  <List dense disablePadding>
                    <ListItem disablePadding sx={{ mb: 1 }}>
                      <ListItemText 
                        primary="Status"
                        secondary={
                          <Chip 
                            label={selectedVuln.status || 'OPEN'} 
                            size="small" 
                            color={getStatusColor(selectedVuln.status)} 
                          />
                        }
                      />
                    </ListItem>
                    <Divider sx={{ my: 1 }} />
                    <ListItem disablePadding sx={{ mb: 1 }}>
                      <ListItemText 
                        primary="Fix Disponível"
                        secondary={selectedVuln.fix_available ? '✅ Sim' : '❌ Não'}
                      />
                    </ListItem>
                    <ListItem disablePadding sx={{ mb: 1 }}>
                      <ListItemText 
                        primary="Exploit Público"
                        secondary={selectedVuln.exploit_available ? '⚠️ SIM - CRÍTICO' : '✅ Não conhecido'}
                        secondaryTypographyProps={{
                          color: selectedVuln.exploit_available ? 'error' : 'success'
                        }}
                      />
                    </ListItem>
                    <Divider sx={{ my: 1 }} />
                    <ListItem disablePadding sx={{ mb: 1 }}>
                      <ListItemText 
                        primary="Recurso Afetado"
                        secondary={selectedVuln.resource_id || selectedVuln.instance_id || 'N/A'}
                        secondaryTypographyProps={{ sx: { fontFamily: 'monospace', fontSize: '0.7rem' } }}
                      />
                    </ListItem>
                    <ListItem disablePadding>
                      <ListItemText 
                        primary="Tipo de Recurso"
                        secondary={selectedVuln.resource_type || 'N/A'}
                      />
                    </ListItem>
                  </List>
                </Paper>

                {/* Quick Links */}
                <Paper sx={{ p: 2, mb: 2, backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  <Typography variant="subtitle2" gutterBottom>🔗 Links Úteis</Typography>
                  <List dense disablePadding>
                    {selectedVuln.cve_id && (
                      <>
                        <ListItem disablePadding>
                          <Button
                            size="small"
                            fullWidth
                            startIcon={<OpenInNewIcon />}
                            component={Link}
                            href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cve_id}`}
                            target="_blank"
                            sx={{ justifyContent: 'flex-start', textTransform: 'none', mb: 0.5 }}
                          >
                            NVD - National Vulnerability DB
                          </Button>
                        </ListItem>
                        <ListItem disablePadding>
                          <Button
                            size="small"
                            fullWidth
                            startIcon={<OpenInNewIcon />}
                            component={Link}
                            href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${selectedVuln.cve_id}`}
                            target="_blank"
                            sx={{ justifyContent: 'flex-start', textTransform: 'none', mb: 0.5 }}
                          >
                            MITRE CVE
                          </Button>
                        </ListItem>
                        <ListItem disablePadding>
                          <Button
                            size="small"
                            fullWidth
                            startIcon={<OpenInNewIcon />}
                            component={Link}
                            href={`https://www.cvedetails.com/cve/${selectedVuln.cve_id}`}
                            target="_blank"
                            sx={{ justifyContent: 'flex-start', textTransform: 'none', mb: 0.5 }}
                          >
                            CVE Details
                          </Button>
                        </ListItem>
                        <ListItem disablePadding>
                          <Button
                            size="small"
                            fullWidth
                            startIcon={<OpenInNewIcon />}
                            component={Link}
                            href={`https://www.exploit-db.com/search?cve=${selectedVuln.cve_id.replace('CVE-', '')}`}
                            target="_blank"
                            sx={{ justifyContent: 'flex-start', textTransform: 'none' }}
                          >
                            Exploit-DB
                          </Button>
                        </ListItem>
                      </>
                    )}
                  </List>
                </Paper>

                {/* Timeline */}
                <Paper sx={{ p: 2, backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  <Typography variant="subtitle2" gutterBottom>📅 Timeline</Typography>
                  <List dense disablePadding>
                    {selectedVuln.first_observed_at && (
                      <ListItem disablePadding sx={{ mb: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 30 }}>
                          <TimelineIcon fontSize="small" />
                        </ListItemIcon>
                        <ListItemText 
                          primary="Primeira detecção"
                          secondary={new Date(selectedVuln.first_observed_at).toLocaleDateString('pt-BR')}
                          primaryTypographyProps={{ variant: 'caption' }}
                        />
                      </ListItem>
                    )}
                    {selectedVuln.last_observed_at && (
                      <ListItem disablePadding>
                        <ListItemIcon sx={{ minWidth: 30 }}>
                          <TimelineIcon fontSize="small" />
                        </ListItemIcon>
                        <ListItemText 
                          primary="Última verificação"
                          secondary={new Date(selectedVuln.last_observed_at).toLocaleDateString('pt-BR')}
                          primaryTypographyProps={{ variant: 'caption' }}
                        />
                      </ListItem>
                    )}
                  </List>
                </Paper>
              </Grid>

              {/* Actions Row */}
              <Grid item xs={12}>
                <Divider sx={{ my: 2 }} />
                <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                  <Typography variant="subtitle2">Atualizar Status:</Typography>
                  <Button 
                    size="small" 
                    variant="outlined" 
                    startIcon={<BuildIcon />}
                    onClick={() => handleUpdateVulnerability('in_progress')}
                  >
                    Em Progresso
                  </Button>
                  <Button 
                    size="small" 
                    variant="outlined" 
                    color="success" 
                    startIcon={<CheckCircleIcon />}
                    onClick={() => handleUpdateVulnerability('patched')}
                  >
                    Corrigido
                  </Button>
                  <Button 
                    size="small" 
                    variant="outlined" 
                    color="warning"
                    startIcon={<InfoIcon />}
                    onClick={() => handleUpdateVulnerability('accepted_risk')}
                  >
                    Risco Aceito
                  </Button>
                </Box>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions sx={{ borderTop: '1px solid rgba(255,255,255,0.1)', px: 3, py: 2 }}>
          <Button onClick={() => setVulnDialogOpen(false)} variant="contained">
            Fechar
          </Button>
        </DialogActions>
      </Dialog>

      {/* Asset Detail Dialog - Enhanced */}
      <Dialog 
        open={assetDialogOpen} 
        onClose={() => setAssetDialogOpen(false)} 
        maxWidth="lg" 
        fullWidth
        PaperProps={{
          sx: { 
            backgroundColor: '#1a1a2e',
            backgroundImage: 'linear-gradient(rgba(255,255,255,0.02), rgba(255,255,255,0.02))',
          }
        }}
      >
        <DialogTitle sx={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <ComputerIcon />
            <Box sx={{ flexGrow: 1 }}>
              <Typography variant="h6">
                {selectedAsset?.instance_id || selectedAsset?.hostname || selectedAsset?.resource_id?.split('/').pop() || 'Ativo'}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {selectedAsset?.resource_type?.replace('AWS_', '').replace('_', ' ') || 'Recurso'} • {selectedAsset?.region || 'N/A'}
              </Typography>
            </Box>
            <Chip 
              label={`Risk: ${Math.round(selectedAsset?.risk_score || 0)}`}
              color={selectedAsset?.risk_score >= 80 ? 'error' : selectedAsset?.risk_score >= 60 ? 'warning' : 'success'}
            />
          </Box>
        </DialogTitle>
        <DialogContent sx={{ pt: 3 }}>
          {selectedAsset && (
            <Grid container spacing={3}>
              {/* Asset Info */}
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ color: '#90caf9' }}>
                    📋 Informações do Ativo
                  </Typography>
                  <List dense disablePadding>
                    <ListItem disablePadding sx={{ mb: 1 }}>
                      <ListItemText 
                        primary="Resource ID"
                        secondary={
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all' }}>
                            {selectedAsset.resource_id || 'N/A'}
                          </Typography>
                        }
                      />
                    </ListItem>
                    {selectedAsset.instance_id && (
                      <ListItem disablePadding sx={{ mb: 1 }}>
                        <ListItemText 
                          primary="Instance ID"
                          secondary={selectedAsset.instance_id}
                        />
                      </ListItem>
                    )}
                    {selectedAsset.platform && (
                      <ListItem disablePadding sx={{ mb: 1 }}>
                        <ListItemText 
                          primary="Plataforma"
                          secondary={selectedAsset.platform}
                        />
                      </ListItem>
                    )}
                    {selectedAsset.account_id && (
                      <ListItem disablePadding sx={{ mb: 1 }}>
                        <ListItemText 
                          primary="Conta AWS"
                          secondary={selectedAsset.account_id}
                        />
                      </ListItem>
                    )}
                    <Divider sx={{ my: 1 }} />
                    <ListItem disablePadding>
                      <ListItemText 
                        primary="Vulnerabilidades"
                        secondary={
                          <Box sx={{ mt: 1 }}>
                            <Chip label={`Total: ${selectedAsset.vulnerability_count || 0}`} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                            <Chip label={`Críticas: ${selectedAsset.critical_vulns || 0}`} size="small" color="error" sx={{ mr: 0.5, mb: 0.5 }} />
                            <Chip label={`Altas: ${selectedAsset.high_vulns || 0}`} size="small" color="warning" sx={{ mb: 0.5 }} />
                          </Box>
                        }
                      />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>

              {/* Vulnerabilities List */}
              <Grid item xs={12} md={8}>
                <Paper sx={{ p: 2, backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ color: '#f44336' }}>
                    🔴 Vulnerabilidades Detectadas ({selectedAsset.vulnerabilities?.length || 0})
                  </Typography>
                  {selectedAsset.vulnerabilities?.length > 0 ? (
                    <TableContainer sx={{ maxHeight: 400 }}>
                      <Table size="small" stickyHeader>
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ backgroundColor: '#1a1a2e' }}>CVE ID</TableCell>
                            <TableCell sx={{ backgroundColor: '#1a1a2e' }}>Título</TableCell>
                            <TableCell sx={{ backgroundColor: '#1a1a2e' }}>Severidade</TableCell>
                            <TableCell sx={{ backgroundColor: '#1a1a2e' }}>CVSS</TableCell>
                            <TableCell sx={{ backgroundColor: '#1a1a2e' }}>Fix</TableCell>
                            <TableCell sx={{ backgroundColor: '#1a1a2e' }}>Ação</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {selectedAsset.vulnerabilities.map((vuln, idx) => (
                            <TableRow 
                              key={vuln.id || idx}
                              hover
                              sx={{ '&:hover': { backgroundColor: 'rgba(255,255,255,0.05)' } }}
                            >
                              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                {vuln.cve_id || 'N/A'}
                              </TableCell>
                              <TableCell sx={{ maxWidth: 200 }}>
                                <Typography variant="body2" noWrap title={vuln.title}>
                                  {vuln.title || vuln.vulnerable_package || 'N/A'}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                <Chip 
                                  label={vuln.severity || 'UNKNOWN'} 
                                  size="small" 
                                  color={getSeverityColor(vuln.severity)} 
                                />
                              </TableCell>
                              <TableCell>
                                <Typography 
                                  variant="body2" 
                                  fontWeight="bold"
                                  color={vuln.cvss_score >= 9 ? 'error.main' : vuln.cvss_score >= 7 ? 'warning.main' : 'text.primary'}
                                >
                                  {vuln.cvss_score?.toFixed(1) || 'N/A'}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                {vuln.fix_available ? (
                                  <Chip label="Disponível" size="small" color="success" variant="outlined" />
                                ) : (
                                  <Chip label="Não" size="small" color="default" variant="outlined" />
                                )}
                              </TableCell>
                              <TableCell>
                                <Button 
                                  size="small" 
                                  onClick={() => {
                                    setAssetDialogOpen(false);
                                    handleViewVulnerability(vuln.cve_id || vuln.id);
                                  }}
                                >
                                  Ver
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  ) : (
                    <Box>
                      <Alert severity="warning" sx={{ mt: 1 }}>
                        {selectedAsset.vulnerability_count > 0 ? (
                          <>
                            Este ativo possui <strong>{selectedAsset.vulnerability_count}</strong> vulnerabilidades registradas, 
                            mas não foi possível carregar os detalhes. O backend pode estar processando a consulta.
                          </>
                        ) : (
                          'Nenhuma vulnerabilidade encontrada para este ativo.'
                        )}
                      </Alert>
                      {selectedAsset.vulnerability_count > 0 && (
                        <Box sx={{ mt: 2, textAlign: 'center' }}>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            Resumo das vulnerabilidades:
                          </Typography>
                          <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2 }}>
                            <Chip label={`${selectedAsset.critical_vulns || 0} Críticas`} color="error" />
                            <Chip label={`${selectedAsset.high_vulns || 0} Altas`} color="warning" />
                            <Chip label={`${selectedAsset.medium_vulns || 0} Médias`} color="info" />
                          </Box>
                        </Box>
                      )}
                    </Box>
                  )}
                </Paper>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions sx={{ borderTop: '1px solid rgba(255,255,255,0.1)', px: 3, py: 2 }}>
          <Button onClick={() => setAssetDialogOpen(false)} variant="contained">
            Fechar
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Vulnerabilities;
