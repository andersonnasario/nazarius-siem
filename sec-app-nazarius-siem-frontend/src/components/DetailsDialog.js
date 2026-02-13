import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  Chip,
  Divider,
  Grid,
  IconButton,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText
} from '@mui/material';
import { 
  Close as CloseIcon,
  ArrowRight as ArrowIcon
} from '@mui/icons-material';

const DetailsDialog = ({ open, onClose, title, data, fields = [] }) => {
  if (!data) return null;

  const getSeverityColor = (value) => {
    const val = String(value).toLowerCase();
    if (['critical', 'error', 'high', 'increasing'].includes(val)) return 'error';
    if (['warning', 'medium'].includes(val)) return 'warning';
    if (['success', 'low', 'decreasing', 'resolved'].includes(val)) return 'success';
    if (['info', 'new'].includes(val)) return 'info';
    return 'default';
  };

  const renderValue = (value, type = 'text', field = {}) => {
    if (value === null || value === undefined || value === '') return <Typography color="text.secondary">N/A</Typography>;

    switch (type) {
      case 'header':
        return null; // Headers are rendered separately
        
      case 'date':
        try {
          return new Date(value).toLocaleString('pt-BR');
        } catch {
          return String(value);
        }
        
      case 'badge':
        return (
          <Chip 
            label={String(value).toUpperCase()} 
            size="small" 
            color={getSeverityColor(value)}
            sx={{ fontWeight: 'bold' }}
          />
        );
        
      case 'status':
        return (
          <Chip 
            label={value} 
            color={getSeverityColor(value)} 
            size="small" 
          />
        );
        
      case 'array':
        if (!Array.isArray(value) || value.length === 0) {
          return <Typography color="text.secondary">Nenhum item</Typography>;
        }
        return (
          <List dense disablePadding>
            {value.map((item, idx) => (
              <ListItem key={idx} disablePadding sx={{ py: 0.25 }}>
                <ListItemIcon sx={{ minWidth: 24 }}>
                  <ArrowIcon fontSize="small" color="primary" />
                </ListItemIcon>
                <ListItemText 
                  primary={item} 
                  primaryTypographyProps={{ variant: 'body2' }}
                />
              </ListItem>
            ))}
          </List>
        );
        
      case 'json':
        return (
          <Paper variant="outlined" sx={{ p: 1, bgcolor: 'grey.900' }}>
            <pre style={{ fontSize: '11px', margin: 0, overflow: 'auto', color: '#4fc3f7' }}>
              {JSON.stringify(value, null, 2)}
            </pre>
          </Paper>
        );
        
      case 'code':
        return (
          <Typography 
            variant="body2" 
            sx={{ 
              fontFamily: 'monospace', 
              bgcolor: 'action.hover', 
              px: 1, 
              py: 0.5, 
              borderRadius: 1,
              display: 'inline-block',
              wordBreak: 'break-all'
            }}
          >
            {String(value)}
          </Typography>
        );
        
      case 'highlight':
        return (
          <Typography 
            variant="h6" 
            sx={{ 
              color: 'primary.main', 
              fontWeight: 'bold' 
            }}
          >
            {String(value)}
          </Typography>
        );
        
      case 'number':
        return (
          <Typography variant="h6" fontWeight="bold">
            {typeof value === 'number' ? value.toLocaleString() : value}
          </Typography>
        );
        
      case 'text':
      default:
        return <Typography variant="body1">{String(value)}</Typography>;
    }
  };

  const renderField = (field, index) => {
    // Render header as a section divider
    if (field.type === 'header') {
      return (
        <Grid item xs={12} key={index}>
          {index > 0 && <Divider sx={{ my: 2 }} />}
          <Typography 
            variant="subtitle1" 
            fontWeight="bold" 
            color="primary"
            sx={{ mb: 1 }}
          >
            {field.label}
          </Typography>
        </Grid>
      );
    }

    return (
      <Grid item xs={12} sm={field.fullWidth ? 12 : 6} key={index}>
        <Box sx={{ mb: 1 }}>
          <Typography 
            variant="caption" 
            color="text.secondary" 
            sx={{ textTransform: 'uppercase', letterSpacing: 0.5 }}
          >
            {field.label}
          </Typography>
          <Box sx={{ mt: 0.5 }}>
            {renderValue(data[field.key], field.type, field)}
          </Box>
        </Box>
      </Grid>
    );
  };

  return (
    <Dialog 
      open={open} 
      onClose={onClose} 
      maxWidth="md" 
      fullWidth
      PaperProps={{
        sx: { bgcolor: 'background.paper' }
      }}
    >
      <DialogTitle sx={{ pb: 1 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Typography variant="h6" fontWeight="bold">{title}</Typography>
          <IconButton onClick={onClose} size="small">
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>
      <Divider />
      <DialogContent sx={{ pt: 2 }}>
        <Grid container spacing={2}>
          {fields.length > 0 ? (
            fields.map((field, index) => renderField(field, index))
          ) : (
            // Fallback: mostrar todos os campos do objeto
            Object.entries(data).map(([key, value], index) => (
              <Grid item xs={12} sm={6} key={index}>
                <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase' }}>
                  {key.replace(/_/g, ' ')}
                </Typography>
                <Typography variant="body1">
                  {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                </Typography>
              </Grid>
            ))
          )}
        </Grid>
      </DialogContent>
      <Divider />
      <DialogActions sx={{ p: 2 }}>
        <Button onClick={onClose} variant="contained" color="primary">
          Fechar
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default DetailsDialog;
