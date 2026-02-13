import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Avatar,
  LinearProgress,
  Grid,
  CircularProgress,
  Alert,
  Button,
  Tooltip,
  IconButton
} from '@mui/material';
import {
  EmojiEvents as TrophyIcon,
  TrendingUp as TrendingUpIcon,
  Star as StarIcon,
  Refresh as RefreshIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, Legend } from 'recharts';
import { threatHuntingPlatformAPI } from '../services/api';

const COLORS = {
  gold: '#FFD700',
  silver: '#C0C0C0',
  bronze: '#CD7F32',
  default: '#1976d2'
};

const ThreatHuntingRanking = () => {
  const [hunters, setHunters] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [totalMetrics, setTotalMetrics] = useState({
    total_hypotheses: 0,
    total_findings: 0,
    avg_validation_rate: 0
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await threatHuntingPlatformAPI.getMetrics();

      if (response.data && response.data.success) {
        const metricsData = response.data.data;
        
        // Sort hunters by validation rate and findings
        const sortedHunters = (metricsData.top_hunters || []).sort((a, b) => {
          // First by findings count, then by validation rate
          if (b.findings_count !== a.findings_count) {
            return b.findings_count - a.findings_count;
          }
          return b.validation_rate - a.validation_rate;
        });

        setHunters(sortedHunters);
        setTotalMetrics({
          total_hypotheses: metricsData.total_hypotheses || 0,
          total_findings: metricsData.total_findings || 0,
          avg_validation_rate: metricsData.validation_rate || 0
        });
      }
    } catch (err) {
      console.error('Error loading hunters ranking:', err);
      setError('Erro ao carregar ranking de hunters. Verifique a conexão com a API.');
    } finally {
      setLoading(false);
    }
  };

  const getMedalIcon = (position) => {
    if (position === 0) return <TrophyIcon sx={{ color: COLORS.gold, fontSize: 32 }} />;
    if (position === 1) return <TrophyIcon sx={{ color: COLORS.silver, fontSize: 28 }} />;
    if (position === 2) return <TrophyIcon sx={{ color: COLORS.bronze, fontSize: 24 }} />;
    return null;
  };

  const getPositionColor = (position) => {
    if (position === 0) return COLORS.gold;
    if (position === 1) return COLORS.silver;
    if (position === 2) return COLORS.bronze;
    return COLORS.default;
  };

  const getPerformanceLevel = (validationRate) => {
    if (validationRate >= 50) return { label: 'Excelente', color: 'success' };
    if (validationRate >= 30) return { label: 'Bom', color: 'primary' };
    if (validationRate >= 20) return { label: 'Regular', color: 'warning' };
    return { label: 'Iniciante', color: 'default' };
  };

  // Prepare chart data
  const huntersChartData = hunters.slice(0, 5).map((hunter, index) => ({
    name: hunter.hunter_name || hunter.hunter_id,
    findings: hunter.findings_count || 0,
    hypotheses: hunter.hypotheses_count || 0
  }));

  const validationRateData = hunters.slice(0, 5).map((hunter) => ({
    name: hunter.hunter_name || hunter.hunter_id,
    rate: hunter.validation_rate || 0
  }));

  if (loading) {
    return (
      <Container maxWidth="xl" sx={{ mt: 4, mb: 4, display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '60vh' }}>
        <CircularProgress size={60} />
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <TrophyIcon sx={{ color: COLORS.gold, fontSize: 40 }} />
            Ranking de Threat Hunters
          </Typography>
          <Typography variant="body1" color="textSecondary">
            Performance e métricas dos analistas de threat hunting
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
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <StarIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Total de Hunters
                </Typography>
              </Box>
              <Typography variant="h3">{hunters.length}</Typography>
              <Typography variant="caption" color="text.secondary">
                Analistas ativos
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <TrendingUpIcon sx={{ mr: 1, color: 'success.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Total de Hipóteses
                </Typography>
              </Box>
              <Typography variant="h3">{totalMetrics.total_hypotheses}</Typography>
              <Typography variant="caption" color="text.secondary">
                Criadas por todos os hunters
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <TrophyIcon sx={{ mr: 1, color: 'warning.main' }} />
                <Typography variant="body2" color="text.secondary">
                  Taxa de Validação Média
                </Typography>
              </Box>
              <Typography variant="h3">{totalMetrics.avg_validation_rate.toFixed(1)}%</Typography>
              <Typography variant="caption" color="text.secondary">
                Hipóteses validadas
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Top 5 Hunters - Hipóteses vs Findings
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={huntersChartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" angle={-45} textAnchor="end" height={80} />
                  <YAxis />
                  <RechartsTooltip />
                  <Legend />
                  <Bar dataKey="hypotheses" fill="#1976d2" name="Hipóteses" />
                  <Bar dataKey="findings" fill="#2e7d32" name="Findings" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Top 5 Hunters - Taxa de Validação
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={validationRateData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" angle={-45} textAnchor="end" height={80} />
                  <YAxis />
                  <RechartsTooltip />
                  <Bar dataKey="rate" fill="#f57c00" name="Taxa de Validação (%)" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Ranking Table */}
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">
              Ranking Completo
            </Typography>
            <Tooltip title="Ranking baseado em findings confirmados e taxa de validação">
              <IconButton size="small">
                <InfoIcon />
              </IconButton>
            </Tooltip>
          </Box>

          <TableContainer component={Paper} variant="outlined">
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell align="center" width={80}>Posição</TableCell>
                  <TableCell>Hunter</TableCell>
                  <TableCell align="center">Hipóteses</TableCell>
                  <TableCell align="center">Findings</TableCell>
                  <TableCell align="center">Taxa de Validação</TableCell>
                  <TableCell align="center">Performance</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {hunters.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      <Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                        Nenhum hunter encontrado. Crie hipóteses para aparecer no ranking!
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  hunters.map((hunter, index) => {
                    const performance = getPerformanceLevel(hunter.validation_rate || 0);
                    return (
                      <TableRow
                        key={hunter.hunter_id}
                        sx={{
                          backgroundColor: index < 3 ? `${getPositionColor(index)}10` : 'inherit',
                          '&:hover': { backgroundColor: 'action.hover' }
                        }}
                      >
                        <TableCell align="center">
                          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
                            {getMedalIcon(index)}
                            <Typography variant="h6" sx={{ color: getPositionColor(index) }}>
                              #{index + 1}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                            <Avatar sx={{ bgcolor: getPositionColor(index) }}>
                              {(hunter.hunter_name || hunter.hunter_id).charAt(0).toUpperCase()}
                            </Avatar>
                            <Box>
                              <Typography variant="body1" fontWeight={index < 3 ? 600 : 400}>
                                {hunter.hunter_name || hunter.hunter_id}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                ID: {hunter.hunter_id}
                              </Typography>
                            </Box>
                          </Box>
                        </TableCell>
                        <TableCell align="center">
                          <Chip
                            label={hunter.hypotheses_count || 0}
                            color="primary"
                            variant="outlined"
                            size="small"
                          />
                        </TableCell>
                        <TableCell align="center">
                          <Chip
                            label={hunter.findings_count || 0}
                            color="success"
                            size="small"
                          />
                        </TableCell>
                        <TableCell align="center">
                          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0.5 }}>
                            <Typography variant="body2" fontWeight={600}>
                              {(hunter.validation_rate || 0).toFixed(1)}%
                            </Typography>
                            <LinearProgress
                              variant="determinate"
                              value={Math.min(hunter.validation_rate || 0, 100)}
                              sx={{
                                width: 80,
                                height: 6,
                                borderRadius: 3,
                                backgroundColor: 'grey.300',
                                '& .MuiLinearProgress-bar': {
                                  backgroundColor: getPositionColor(index)
                                }
                              }}
                            />
                          </Box>
                        </TableCell>
                        <TableCell align="center">
                          <Chip
                            label={performance.label}
                            color={performance.color}
                            size="small"
                          />
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>

      {/* Info Box */}
      <Box sx={{ mt: 3 }}>
        <Alert severity="info">
          <Typography variant="body2">
            <strong>Como funciona o ranking:</strong> Os hunters são classificados primeiro pelo número de findings confirmados, 
            e depois pela taxa de validação. Quanto mais hipóteses validadas e findings gerados, melhor a posição no ranking.
          </Typography>
        </Alert>
      </Box>
    </Container>
  );
};

export default ThreatHuntingRanking;

