import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  Tooltip,
  LinearProgress,
  MenuItem,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import RefreshIcon from '@mui/icons-material/Refresh';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import CloudIcon from '@mui/icons-material/Cloud';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import { cspmAPI } from '../services/api';

function AWSConnections() {
  const [connections, setConnections] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [createDialog, setCreateDialog] = useState(false);
  const [editDialog, setEditDialog] = useState(false);
  const [selectedConnection, setSelectedConnection] = useState(null);
  const [newConnection, setNewConnection] = useState({
    account_id: '',
    account_name: '',
    role_arn: '',
    external_id: '',
    region: 'us-east-1',
  });

  useEffect(() => {
    loadConnections();
    // Atualizar a cada 30 segundos
    const interval = setInterval(loadConnections, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadConnections = async () => {
    try {
      const response = await cspmAPI.connections.list();
      setConnections(response.data.connections || []);
      setStatistics(response.data.statistics);
    } catch (error) {
      console.error('Error loading connections:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateConnection = async () => {
    try {
      await cspmAPI.connections.create(newConnection);
      alert('Conexão criada com sucesso!');
      setCreateDialog(false);
      setNewConnection({
        account_id: '',
        account_name: '',
        role_arn: '',
        external_id: '',
        region: 'us-east-1',
      });
      loadConnections();
    } catch (error) {
      alert('Erro ao criar conexão: ' + (error.response?.data?.error || error.message));
    }
  };

  const handleUpdateConnection = async () => {
    try {
      await cspmAPI.connections.update(selectedConnection.id, {
        account_name: selectedConnection.account_name,
        role_arn: selectedConnection.role_arn,
        external_id: selectedConnection.external_id,
        region: selectedConnection.region,
      });
      alert('Conexão atualizada com sucesso!');
      setEditDialog(false);
      setSelectedConnection(null);
      loadConnections();
    } catch (error) {
      alert('Erro ao atualizar conexão: ' + (error.response?.data?.error || error.message));
    }
  };

  const handleDeleteConnection = async (id) => {
    if (!window.confirm('Tem certeza que deseja remover esta conexão?')) return;
    
    try {
      await cspmAPI.connections.delete(id);
      alert('Conexão removida com sucesso!');
      loadConnections();
    } catch (error) {
      alert('Erro ao remover conexão: ' + (error.response?.data?.error || error.message));
    }
  };

  const handleRefreshConnection = async (id) => {
    try {
      await cspmAPI.connections.refresh(id);
      alert('Credenciais renovadas com sucesso!');
      loadConnections();
    } catch (error) {
      alert('Erro ao renovar credenciais: ' + (error.response?.data?.error || error.message));
    }
  };

  const handleBulkRefresh = async () => {
    if (!window.confirm('Renovar credenciais de todas as conexões?')) return;
    
    try {
      const response = await cspmAPI.connections.bulkRefresh();
      alert(`Renovação concluída: ${response.data.refreshed} sucesso, ${response.data.failed} falhas`);
      loadConnections();
    } catch (error) {
      alert('Erro ao renovar conexões: ' + (error.response?.data?.error || error.message));
    }
  };

  const handleTestConnection = async (id) => {
    try {
      await cspmAPI.connections.test(id);
      alert('Teste de conexão bem-sucedido!');
      loadConnections();
    } catch (error) {
      alert('Teste de conexão falhou: ' + (error.response?.data?.error || error.message));
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'active':
        return <CheckCircleIcon color="success" />;
      case 'expired':
        return <WarningIcon color="warning" />;
      case 'failed':
        return <ErrorIcon color="error" />;
      default:
        return <CloudIcon color="disabled" />;
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success',
      expired: 'warning',
      failed: 'error',
      pending: 'info',
    };
    return colors[status] || 'default';
  };

  const formatTimeRemaining = (expiration) => {
    if (!expiration) return 'N/A';
    const now = new Date();
    const exp = new Date(expiration);
    const diff = exp - now;
    
    if (diff <= 0) return 'Expirado';
    
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    }
    return `${minutes}m`;
  };

  const getExpirationColor = (expiration) => {
    if (!expiration) return 'default';
    const now = new Date();
    const exp = new Date(expiration);
    const diff = exp - now;
    const minutes = Math.floor(diff / 60000);
    
    if (minutes <= 5) return 'error';
    if (minutes <= 15) return 'warning';
    return 'success';
  };

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography>Carregando conexões...</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <VpnKeyIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h4">Conexões AWS</Typography>
          <Typography variant="body2" color="textSecondary">
            Gerenciamento de credenciais temporárias via AWS STS
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialog(true)}
          sx={{ mr: 1 }}
        >
          Nova Conexão
        </Button>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={handleBulkRefresh}
        >
          Renovar Todas
        </Button>
      </Box>

      {/* Statistics Cards */}
      {statistics && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total de Conexões
                </Typography>
                <Typography variant="h4">{statistics.total_connections}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Conexões Ativas
                </Typography>
                <Typography variant="h4" color="success.main">
                  {statistics.active_connections}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Expiradas
                </Typography>
                <Typography variant="h4" color="warning.main">
                  {statistics.expired_connections}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total de Renovações
                </Typography>
                <Typography variant="h4">{statistics.total_refreshes}</Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      <Alert severity="info" sx={{ mb: 3 }}>
        <strong>AWS STS (Security Token Service):</strong> As credenciais são renovadas automaticamente a cada hora. 
        O sistema verifica e renova credenciais que estão a 5 minutos de expirar.
      </Alert>

      {/* Connections Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Status</TableCell>
              <TableCell>Account ID</TableCell>
              <TableCell>Nome da Conta</TableCell>
              <TableCell>Região</TableCell>
              <TableCell>Role ARN</TableCell>
              <TableCell>Expira em</TableCell>
              <TableCell>Última Renovação</TableCell>
              <TableCell>Renovações</TableCell>
              <TableCell>Ações</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {connections.map((conn) => (
              <TableRow key={conn.id}>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    {getStatusIcon(conn.status)}
                    <Chip
                      label={conn.status}
                      color={getStatusColor(conn.status)}
                      size="small"
                      sx={{ ml: 1 }}
                    />
                  </Box>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {conn.account_id}
                  </Typography>
                </TableCell>
                <TableCell>{conn.account_name}</TableCell>
                <TableCell>{conn.region}</TableCell>
                <TableCell>
                  <Tooltip title={conn.role_arn}>
                    <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                      {conn.role_arn}
                    </Typography>
                  </Tooltip>
                </TableCell>
                <TableCell>
                  {conn.credentials && (
                    <Chip
                      label={formatTimeRemaining(conn.credentials.expiration)}
                      color={getExpirationColor(conn.credentials.expiration)}
                      size="small"
                    />
                  )}
                </TableCell>
                <TableCell>
                  {new Date(conn.last_refresh).toLocaleString('pt-BR')}
                </TableCell>
                <TableCell>{conn.refresh_count || 0}</TableCell>
                <TableCell>
                  <Tooltip title="Renovar Credenciais">
                    <IconButton
                      size="small"
                      onClick={() => handleRefreshConnection(conn.id)}
                      color="primary"
                    >
                      <RefreshIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Editar">
                    <IconButton
                      size="small"
                      onClick={() => {
                        setSelectedConnection(conn);
                        setEditDialog(true);
                      }}
                    >
                      <EditIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Remover">
                    <IconButton
                      size="small"
                      onClick={() => handleDeleteConnection(conn.id)}
                      color="error"
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Create Connection Dialog */}
      <Dialog open={createDialog} onClose={() => setCreateDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Nova Conexão AWS</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2 }}>
            Configure uma conexão usando AWS STS AssumeRole. Você precisará criar uma IAM Role na conta AWS 
            com permissões adequadas e trust policy configurada.
          </Alert>
          <TextField
            label="Account ID"
            value={newConnection.account_id}
            onChange={(e) => setNewConnection({ ...newConnection, account_id: e.target.value })}
            fullWidth
            margin="normal"
            required
            helperText="ID da conta AWS (12 dígitos)"
          />
          <TextField
            label="Nome da Conta"
            value={newConnection.account_name}
            onChange={(e) => setNewConnection({ ...newConnection, account_name: e.target.value })}
            fullWidth
            margin="normal"
            required
            helperText="Nome descritivo para identificar a conta"
          />
          <TextField
            label="Role ARN"
            value={newConnection.role_arn}
            onChange={(e) => setNewConnection({ ...newConnection, role_arn: e.target.value })}
            fullWidth
            margin="normal"
            required
            placeholder="arn:aws:iam::123456789012:role/ConfigAggregatorRole"
            helperText="ARN da IAM Role que será assumida"
          />
          <TextField
            label="External ID (opcional)"
            value={newConnection.external_id}
            onChange={(e) => setNewConnection({ ...newConnection, external_id: e.target.value })}
            fullWidth
            margin="normal"
            helperText="External ID para segurança adicional (recomendado)"
          />
          <TextField
            select
            label="Região"
            value={newConnection.region}
            onChange={(e) => setNewConnection({ ...newConnection, region: e.target.value })}
            fullWidth
            margin="normal"
          >
            <MenuItem value="us-east-1">us-east-1 (N. Virginia)</MenuItem>
            <MenuItem value="us-east-2">us-east-2 (Ohio)</MenuItem>
            <MenuItem value="us-west-1">us-west-1 (N. California)</MenuItem>
            <MenuItem value="us-west-2">us-west-2 (Oregon)</MenuItem>
            <MenuItem value="eu-west-1">eu-west-1 (Ireland)</MenuItem>
            <MenuItem value="eu-central-1">eu-central-1 (Frankfurt)</MenuItem>
            <MenuItem value="ap-southeast-1">ap-southeast-1 (Singapore)</MenuItem>
            <MenuItem value="ap-northeast-1">ap-northeast-1 (Tokyo)</MenuItem>
            <MenuItem value="sa-east-1">sa-east-1 (São Paulo)</MenuItem>
          </TextField>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialog(false)}>Cancelar</Button>
          <Button onClick={handleCreateConnection} variant="contained">
            Criar Conexão
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Connection Dialog */}
      <Dialog open={editDialog} onClose={() => setEditDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Editar Conexão</DialogTitle>
        <DialogContent>
          {selectedConnection && (
            <>
              <TextField
                label="Account ID"
                value={selectedConnection.account_id}
                fullWidth
                margin="normal"
                disabled
                helperText="Account ID não pode ser alterado"
              />
              <TextField
                label="Nome da Conta"
                value={selectedConnection.account_name}
                onChange={(e) =>
                  setSelectedConnection({ ...selectedConnection, account_name: e.target.value })
                }
                fullWidth
                margin="normal"
              />
              <TextField
                label="Role ARN"
                value={selectedConnection.role_arn}
                onChange={(e) =>
                  setSelectedConnection({ ...selectedConnection, role_arn: e.target.value })
                }
                fullWidth
                margin="normal"
              />
              <TextField
                label="External ID"
                value={selectedConnection.external_id}
                onChange={(e) =>
                  setSelectedConnection({ ...selectedConnection, external_id: e.target.value })
                }
                fullWidth
                margin="normal"
              />
              <TextField
                select
                label="Região"
                value={selectedConnection.region}
                onChange={(e) =>
                  setSelectedConnection({ ...selectedConnection, region: e.target.value })
                }
                fullWidth
                margin="normal"
              >
                <MenuItem value="us-east-1">us-east-1 (N. Virginia)</MenuItem>
                <MenuItem value="us-east-2">us-east-2 (Ohio)</MenuItem>
                <MenuItem value="us-west-1">us-west-1 (N. California)</MenuItem>
                <MenuItem value="us-west-2">us-west-2 (Oregon)</MenuItem>
                <MenuItem value="eu-west-1">eu-west-1 (Ireland)</MenuItem>
                <MenuItem value="eu-central-1">eu-central-1 (Frankfurt)</MenuItem>
                <MenuItem value="ap-southeast-1">ap-southeast-1 (Singapore)</MenuItem>
                <MenuItem value="ap-northeast-1">ap-northeast-1 (Tokyo)</MenuItem>
                <MenuItem value="sa-east-1">sa-east-1 (São Paulo)</MenuItem>
              </TextField>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialog(false)}>Cancelar</Button>
          <Button onClick={handleUpdateConnection} variant="contained">
            Salvar Alterações
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default AWSConnections;

