import React from 'react';
import { Grid, Paper, Typography, Box, Card, CardContent, Chip } from '@mui/material';
import PsychologyIcon from '@mui/icons-material/Psychology';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';

const AIAnalysis = () => {
  const analyses = [
    {
      title: 'Anomalia Detectada',
      severity: 'HIGH',
      description: 'Padrão de acesso incomum detectado para o usuário admin',
      confidence: 92,
      timestamp: '2025-11-04 16:25:00',
    },
    {
      title: 'Comportamento Suspeito',
      severity: 'MEDIUM',
      description: 'Tráfego de rede anômalo identificado',
      confidence: 78,
      timestamp: '2025-11-04 16:10:00',
    },
    {
      title: 'Correlação de Eventos',
      severity: 'LOW',
      description: 'Múltiplos eventos relacionados detectados',
      confidence: 65,
      timestamp: '2025-11-04 15:55:00',
    },
  ];

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <PsychologyIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
        <Typography variant="h4">
          Análise por IA
        </Typography>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <TrendingUpIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">
                  Análises Hoje
                </Typography>
              </Box>
              <Typography variant="h3" color="primary">
                47
              </Typography>
              <Typography variant="body2" color="text.secondary">
                +12% em relação a ontem
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <WarningAmberIcon color="warning" sx={{ mr: 1 }} />
                <Typography variant="h6">
                  Anomalias
                </Typography>
              </Box>
              <Typography variant="h3" color="warning.main">
                8
              </Typography>
              <Typography variant="body2" color="text.secondary">
                3 críticas, 5 médias
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <PsychologyIcon color="success" sx={{ mr: 1 }} />
                <Typography variant="h6">
                  Confiança Média
                </Typography>
              </Box>
              <Typography variant="h3" color="success.main">
                85%
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Alta precisão
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Typography variant="h5" gutterBottom sx={{ mt: 2 }}>
            Análises Recentes
          </Typography>
        </Grid>

        {analyses.map((analysis, index) => (
          <Grid item xs={12} key={index}>
            <Paper sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', mb: 2 }}>
                <Typography variant="h6">
                  {analysis.title}
                </Typography>
                <Chip
                  label={analysis.severity}
                  color={
                    analysis.severity === 'HIGH' ? 'error' :
                    analysis.severity === 'MEDIUM' ? 'warning' : 'info'
                  }
                  size="small"
                />
              </Box>

              <Typography variant="body1" paragraph>
                {analysis.description}
              </Typography>

              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Box>
                  <Typography variant="body2" color="text.secondary">
                    Confiança: <strong>{analysis.confidence}%</strong>
                  </Typography>
                </Box>
                <Typography variant="caption" color="text.secondary">
                  {analysis.timestamp}
                </Typography>
              </Box>
            </Paper>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

export default AIAnalysis;
