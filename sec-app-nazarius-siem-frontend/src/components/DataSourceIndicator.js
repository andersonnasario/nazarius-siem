import React from 'react';
import { Chip, Tooltip, Box, Typography } from '@mui/material';
import {
  CloudSync as LiveIcon,
  Cached as CachedIcon,
  CloudOff as MockIcon,
  CheckCircle as ConnectedIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';

/**
 * DataSourceIndicator - Shows if data is real (live), cached, or mock
 * 
 * Usage:
 * <DataSourceIndicator 
 *   source="live"           // 'live' | 'cached' | 'mock'
 *   lastUpdate="2 min ago"  // Human readable time
 *   service="CloudTrail"    // Optional: specific service name
 * />
 */
export const DataSourceIndicator = ({ source, lastUpdate, service }) => {
  const getConfig = () => {
    switch (source) {
      case 'live':
      case 'opensearch':
        return {
          color: 'success',
          icon: <LiveIcon fontSize="small" />,
          label: 'LIVE DATA',
          description: 'Dados reais em tempo real',
        };
      case 'cached':
      case 'partial':
        return {
          color: 'warning',
          icon: <CachedIcon fontSize="small" />,
          label: 'PARTIAL DATA',
          description: 'Dados parcialmente disponíveis',
        };
      case 'mock':
        return {
          color: 'error',
          icon: <MockIcon fontSize="small" />,
          label: 'DEMO DATA',
          description: 'Dados de demonstração (sem conexão)',
        };
      case 'none':
      case 'error':
        return {
          color: 'default',
          icon: <ErrorIcon fontSize="small" />,
          label: 'NO DATA',
          description: 'Nenhuma fonte de dados conectada. Configure OpenSearch ou AWS.',
        };
      default:
        return {
          color: 'default',
          icon: <WarningIcon fontSize="small" />,
          label: 'UNKNOWN',
          description: 'Status desconhecido',
        };
    }
  };

  const config = getConfig();

  return (
    <Tooltip 
      title={
        <Box>
          <Typography variant="body2" fontWeight="bold">
            {config.description}
          </Typography>
          {service && (
            <Typography variant="caption">
              Serviço: {service}
            </Typography>
          )}
          {lastUpdate && (
            <Typography variant="caption" display="block">
              Última atualização: {lastUpdate}
            </Typography>
          )}
        </Box>
      }
    >
      <Chip
        icon={config.icon}
        label={`${config.label}${lastUpdate ? ` • ${lastUpdate}` : ''}`}
        color={config.color}
        size="small"
        sx={{ 
          fontWeight: 'bold',
          fontSize: '0.7rem',
        }}
      />
    </Tooltip>
  );
};

/**
 * ServiceStatusIndicator - Shows connection status for a specific AWS service
 * 
 * Usage:
 * <ServiceStatusIndicator 
 *   service="CloudTrail"
 *   status="connected"      // 'connected' | 'disconnected' | 'error'
 *   count={1250}            // Optional: number of items
 *   lastSync="2025-11-28T15:30:00Z"
 * />
 */
export const ServiceStatusIndicator = ({ service, status, count, lastSync }) => {
  const getConfig = () => {
    switch (status) {
      case 'connected':
        return {
          color: 'success',
          icon: <ConnectedIcon fontSize="small" />,
          label: 'Connected',
        };
      case 'disconnected':
        return {
          color: 'warning',
          icon: <WarningIcon fontSize="small" />,
          label: 'Disconnected',
        };
      case 'error':
        return {
          color: 'error',
          icon: <ErrorIcon fontSize="small" />,
          label: 'Error',
        };
      default:
        return {
          color: 'default',
          icon: <WarningIcon fontSize="small" />,
          label: 'Unknown',
        };
    }
  };

  const config = getConfig();
  const timeAgo = lastSync ? formatTimeAgo(new Date(lastSync)) : null;

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Chip
        icon={config.icon}
        label={service}
        color={config.color}
        size="small"
        variant="outlined"
      />
      {count !== undefined && (
        <Typography variant="caption" color="text.secondary">
          {count.toLocaleString()} items
        </Typography>
      )}
      {timeAgo && (
        <Typography variant="caption" color="text.secondary">
          • {timeAgo}
        </Typography>
      )}
    </Box>
  );
};

/**
 * AWSIntegrationStatus - Shows overall AWS integration status
 */
export const AWSIntegrationStatus = ({ integration }) => {
  if (!integration) {
    return (
      <DataSourceIndicator source="mock" lastUpdate="N/A" />
    );
  }

  const { enabled, credential_source, last_sync, services } = integration;

  if (!enabled) {
    return (
      <DataSourceIndicator 
        source="mock" 
        lastUpdate="AWS Integration disabled" 
      />
    );
  }

  const allConnected = services && Object.values(services).every(s => s.status === 'connected');
  const anyConnected = services && Object.values(services).some(s => s.status === 'connected');

  let source = 'mock';
  if (allConnected) {
    source = 'live';
  } else if (anyConnected) {
    source = 'cached';
  }

  const timeAgo = last_sync ? formatTimeAgo(new Date(last_sync)) : 'Never';

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      <DataSourceIndicator 
        source={source} 
        lastUpdate={timeAgo}
        service={credential_source}
      />
      {services && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
          {Object.entries(services).map(([name, info]) => (
            <ServiceStatusIndicator
              key={name}
              service={name}
              status={info.status}
              count={info.events_count || info.findings_count || info.rules_count}
              lastSync={info.last_sync}
            />
          ))}
        </Box>
      )}
    </Box>
  );
};

/**
 * DataFreshnessIndicator - Shows how fresh the data is
 */
export const DataFreshnessIndicator = ({ lastUpdate, refreshInterval }) => {
  const timeAgo = lastUpdate ? formatTimeAgo(new Date(lastUpdate)) : 'Never';
  const isStale = lastUpdate && (Date.now() - new Date(lastUpdate).getTime()) > (refreshInterval || 300000); // 5 min default

  return (
    <Tooltip title={`Dados atualizados ${timeAgo}. Refresh automático a cada ${(refreshInterval || 300000) / 60000} minutos.`}>
      <Chip
        icon={isStale ? <WarningIcon fontSize="small" /> : <LiveIcon fontSize="small" />}
        label={timeAgo}
        color={isStale ? 'warning' : 'success'}
        size="small"
        variant="outlined"
      />
    </Tooltip>
  );
};

// Helper function to format time ago
function formatTimeAgo(date) {
  const now = new Date();
  const diffMs = now - date;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffSec < 60) return 'agora';
  if (diffMin < 60) return `${diffMin} min atrás`;
  if (diffHour < 24) return `${diffHour}h atrás`;
  if (diffDay < 7) return `${diffDay}d atrás`;
  return date.toLocaleDateString('pt-BR');
}

export default DataSourceIndicator;

