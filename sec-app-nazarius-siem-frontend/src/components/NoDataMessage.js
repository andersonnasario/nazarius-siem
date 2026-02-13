import React from 'react';
import { Box, Typography, Paper, Button, Alert } from '@mui/material';
import {
  CloudOff as CloudOffIcon,
  Storage as StorageIcon,
  Settings as SettingsIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

/**
 * NoDataMessage - Shows when no real data is available
 * 
 * Usage:
 * <NoDataMessage 
 *   title="No Events Found"
 *   message="Connect to OpenSearch to see real events."
 *   dataType="events"
 *   showSetupButton={true}
 *   onRefresh={() => loadData()}
 * />
 */
const NoDataMessage = ({ 
  title = "No Data Available",
  message = "No real data is available. Connect your data sources to see live data.",
  dataType = "data",
  showSetupButton = true,
  onRefresh,
  source = "none",
}) => {
  const navigate = useNavigate();

  const getIcon = () => {
    switch (dataType) {
      case 'events':
      case 'alerts':
        return <StorageIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />;
      case 'aws':
      case 'cloudtrail':
      case 'guardduty':
        return <CloudOffIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />;
      default:
        return <StorageIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />;
    }
  };

  const getSetupPath = () => {
    switch (dataType) {
      case 'events':
      case 'alerts':
        return '/integrations';
      case 'aws':
      case 'cloudtrail':
      case 'guardduty':
        return '/aws-connections';
      default:
        return '/integrations';
    }
  };

  const getSetupLabel = () => {
    switch (dataType) {
      case 'events':
      case 'alerts':
        return 'Configure OpenSearch';
      case 'aws':
      case 'cloudtrail':
      case 'guardduty':
        return 'Configure AWS Connection';
      default:
        return 'Configure Data Sources';
    }
  };

  return (
    <Paper 
      sx={{ 
        p: 4, 
        textAlign: 'center',
        backgroundColor: 'background.default',
        border: '1px dashed',
        borderColor: 'divider',
      }}
    >
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        {getIcon()}
        
        <Typography variant="h6" gutterBottom>
          {title}
        </Typography>
        
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3, maxWidth: 400 }}>
          {message}
        </Typography>

        {source === 'none' && (
          <Alert severity="info" sx={{ mb: 3, maxWidth: 500 }}>
            <Typography variant="body2">
              <strong>Modo Produção Ativo:</strong> Apenas dados reais são exibidos. 
              Configure suas fontes de dados para ver informações.
            </Typography>
          </Alert>
        )}

        <Box sx={{ display: 'flex', gap: 2 }}>
          {showSetupButton && (
            <Button
              variant="contained"
              startIcon={<SettingsIcon />}
              onClick={() => navigate(getSetupPath())}
            >
              {getSetupLabel()}
            </Button>
          )}
          
          {onRefresh && (
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={onRefresh}
            >
              Refresh
            </Button>
          )}
        </Box>
      </Box>
    </Paper>
  );
};

/**
 * EmptyStateCard - Smaller version for cards/widgets
 */
export const EmptyStateCard = ({ 
  title = "No Data",
  icon: IconComponent = StorageIcon,
}) => {
  return (
    <Box 
      sx={{ 
        display: 'flex', 
        flexDirection: 'column', 
        alignItems: 'center',
        justifyContent: 'center',
        p: 3,
        minHeight: 150,
        color: 'text.secondary',
      }}
    >
      <IconComponent sx={{ fontSize: 40, mb: 1, opacity: 0.5 }} />
      <Typography variant="body2">
        {title}
      </Typography>
    </Box>
  );
};

/**
 * DataLoadingError - Shows when data loading fails
 */
export const DataLoadingError = ({ 
  error,
  onRetry,
}) => {
  return (
    <Alert 
      severity="error" 
      sx={{ mb: 2 }}
      action={
        onRetry && (
          <Button color="inherit" size="small" onClick={onRetry}>
            Retry
          </Button>
        )
      }
    >
      <Typography variant="body2">
        {error || 'Failed to load data. Please try again.'}
      </Typography>
    </Alert>
  );
};

export default NoDataMessage;

