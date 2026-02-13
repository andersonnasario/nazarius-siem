import React, { useState, useEffect } from 'react';
import {
  Grid,
  Typography,
  Button,
  Card,
  CardContent,
  CardActions,
  Chip,
  Box,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  IconButton,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  CircularProgress,
  Alert,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Block as BlockIcon,
  AccessTime as AccessTimeIcon,
} from '@mui/icons-material';
import { playbooksAPI } from '../services/api';

const Playbooks = () => {
  const [playbooks, setPlaybooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [openDialog, setOpenDialog] = useState(false);
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [openExecutionDialog, setOpenExecutionDialog] = useState(false);
  const [executionLog, setExecutionLog] = useState([]);
  const [executing, setExecuting] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [playbookToDelete, setPlaybookToDelete] = useState(null);

  // Form data para novo playbook
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    trigger: '',
    status: 'testing',
    actions: [],
  });

  // Métricas calculadas
  const [metrics, setMetrics] = useState({
    activePlaybooks: 0,
    executionsToday: 537,
    successRate: 97.8,
    avgResponseTime: '3.8s',
  });

  useEffect(() => {
    loadPlaybooks();
  }, []);

  const loadPlaybooks = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await playbooksAPI.list();
      
      if (response.data && response.data.playbooks) {
        setPlaybooks(response.data.playbooks);
        
        // Calcular métricas
        const active = response.data.playbooks.filter(p => p.status === 'active').length;
        const totalExecs = response.data.playbooks.reduce((sum, p) => sum + p.executions, 0);
        const avgSuccess = response.data.playbooks.reduce((sum, p) => sum + p.successRate, 0) / response.data.playbooks.length;
        
        setMetrics({
          activePlaybooks: active,
          executionsToday: totalExecs,
          successRate: avgSuccess.toFixed(1),
          avgResponseTime: '3.8s',
        });
      }
    } catch (err) {
      console.error('Erro ao carregar playbooks:', err);
      setError('Erro ao carregar playbooks. Verifique a conexão com a API.');
    } finally {
      setLoading(false);
    }
  };

  const handleExecutePlaybook = async (playbook) => {
    setSelectedPlaybook(playbook);
    setExecutionLog([
      { step: 1, action: 'Iniciando playbook...', status: 'success', timestamp: new Date() },
    ]);
    setOpenExecutionDialog(true);
    setExecuting(true);

    try {
      // Executar playbook
      const response = await playbooksAPI.execute(playbook.id);
      
      setExecutionLog(prev => [...prev, 
        { step: 2, action: 'Playbook aceito para execução', status: 'success', timestamp: new Date() }
      ]);

      // Simular progresso das ações
      playbook.actions.forEach((action, index) => {
        setTimeout(() => {
          setExecutionLog(prev => [...prev, {
            step: index + 3,
            action: `Executando: ${action.type} em ${action.target}`,
            status: 'running',
            timestamp: new Date()
          }]);
          
          setTimeout(() => {
            setExecutionLog(prev => {
              const newLog = [...prev];
              newLog[newLog.length - 1].status = 'success';
              return newLog;
            });
          }, 800);
        }, (index + 1) * 1200);
      });

      setTimeout(() => {
        setExecutionLog(prev => [...prev, {
          step: playbook.actions.length + 3,
          action: '✓ Playbook executado com sucesso!',
          status: 'success',
          timestamp: new Date()
        }]);
        setExecuting(false);
        
        // Recarregar playbooks para atualizar estatísticas
        setTimeout(() => loadPlaybooks(), 1000);
      }, (playbook.actions.length + 1) * 1200);

    } catch (err) {
      console.error('Erro ao executar playbook:', err);
      setExecutionLog(prev => [...prev, {
        step: prev.length + 1,
        action: '❌ Erro na execução do playbook',
        status: 'error',
        timestamp: new Date()
      }]);
      setExecuting(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'success';
      case 'testing': return 'warning';
      case 'disabled': return 'error';
      default: return 'default';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'active': return <CheckCircleIcon />;
      case 'testing': return <WarningIcon />;
      case 'disabled': return <BlockIcon />;
      default: return null;
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Nunca';
    const date = new Date(dateString);
    return date.toLocaleString('pt-BR');
  };

  const handleAddAction = () => {
    setFormData({
      ...formData,
      actions: [
        ...formData.actions,
        { type: '', target: '', params: {} }
      ]
    });
  };

  const handleRemoveAction = (index) => {
    const newActions = formData.actions.filter((_, i) => i !== index);
    setFormData({ ...formData, actions: newActions });
  };

  const handleActionChange = (index, field, value) => {
    const newActions = [...formData.actions];
    newActions[index][field] = value;
    setFormData({ ...formData, actions: newActions });
  };

  const handleSavePlaybook = async () => {
    try {
      if (selectedPlaybook) {
        // Editar playbook existente
        await playbooksAPI.update(selectedPlaybook.id, formData);
      } else {
        // Criar novo playbook
        await playbooksAPI.create(formData);
      }
      setOpenDialog(false);
      setSelectedPlaybook(null);
      setFormData({
        name: '',
        description: '',
        trigger: '',
        status: 'testing',
        actions: [],
      });
      loadPlaybooks();
    } catch (err) {
      console.error('Erro ao salvar playbook:', err);
      setError('Erro ao salvar playbook. Tente novamente.');
    }
  };

  const handleEditPlaybook = (playbook) => {
    setSelectedPlaybook(playbook);
    setFormData({
      name: playbook.name,
      description: playbook.description,
      trigger: playbook.trigger,
      status: playbook.status,
      actions: playbook.actions || [],
    });
    setOpenDialog(true);
  };

  const handleDeleteClick = (playbook) => {
    setPlaybookToDelete(playbook);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = async () => {
    try {
      await playbooksAPI.delete(playbookToDelete.id);
      setDeleteDialogOpen(false);
      setPlaybookToDelete(null);
      loadPlaybooks();
    } catch (err) {
      console.error('Erro ao deletar playbook:', err);
      setError('Erro ao deletar playbook. Tente novamente.');
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          🤖 Playbooks Automatizados (SOAR)
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setOpenDialog(true)}
        >
          Novo Playbook
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Métricas Gerais */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
            <CardContent>
              <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                Playbooks Ativos
              </Typography>
              <Typography variant="h3" color="white">
                {metrics.activePlaybooks}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)' }}>
            <CardContent>
              <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                Total de Execuções
              </Typography>
              <Typography variant="h3" color="white">
                {metrics.executionsToday}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)' }}>
            <CardContent>
              <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                Taxa de Sucesso
              </Typography>
              <Typography variant="h3" color="white">
                {metrics.successRate}%
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)' }}>
            <CardContent>
              <Typography color="white" variant="body2" sx={{ opacity: 0.9 }}>
                Tempo Médio
              </Typography>
              <Typography variant="h3" color="white">
                {metrics.avgResponseTime}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Lista de Playbooks */}
      {playbooks.length === 0 ? (
        <Alert severity="info">
          Nenhum playbook encontrado. Crie um novo playbook para começar!
        </Alert>
      ) : (
        <Grid container spacing={3}>
          {playbooks.map((playbook) => (
            <Grid item xs={12} md={6} lg={4} key={playbook.id}>
              <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                <CardContent sx={{ flexGrow: 1 }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', mb: 2 }}>
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      {playbook.name}
                    </Typography>
                    <Chip
                      icon={getStatusIcon(playbook.status)}
                      label={playbook.status}
                      color={getStatusColor(playbook.status)}
                      size="small"
                    />
                  </Box>

                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {playbook.description}
                  </Typography>

                  <Box sx={{ mb: 2 }}>
                    <Chip
                      label={`Trigger: ${playbook.trigger}`}
                      size="small"
                      sx={{ mb: 1 }}
                    />
                    <Typography variant="caption" display="block" color="text.secondary">
                      {playbook.actions.length} ações configuradas
                    </Typography>
                  </Box>

                  <Divider sx={{ my: 2 }} />

                  <Grid container spacing={1}>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">
                        Execuções
                      </Typography>
                      <Typography variant="body1" fontWeight={600}>
                        {playbook.executions}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">
                        Sucesso
                      </Typography>
                      <Typography variant="body1" fontWeight={600} color="success.main">
                        {playbook.successRate}%
                      </Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="caption" color="text.secondary">
                        Tempo Médio: {playbook.avgResponseTime}
                      </Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="caption" color="text.secondary">
                        Última execução: {formatDate(playbook.lastExecution)}
                      </Typography>
                    </Grid>
                  </Grid>
                </CardContent>

                <CardActions sx={{ justifyContent: 'space-between', px: 2, pb: 2 }}>
                  <Box>
                    <IconButton 
                      size="small" 
                      color="primary"
                      onClick={() => handleEditPlaybook(playbook)}
                    >
                      <EditIcon />
                    </IconButton>
                    <IconButton 
                      size="small" 
                      color="error"
                      onClick={() => handleDeleteClick(playbook)}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Box>
                  <Button
                    variant="contained"
                    size="small"
                    startIcon={<PlayIcon />}
                    onClick={() => handleExecutePlaybook(playbook)}
                    disabled={executing}
                  >
                    Executar
                  </Button>
                </CardActions>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Dialog de Execução */}
      <Dialog open={openExecutionDialog} onClose={() => !executing && setOpenExecutionDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Executando Playbook: {selectedPlaybook?.name}
        </DialogTitle>
        <DialogContent>
          <List>
            {executionLog.map((log, index) => (
              <ListItem key={index}>
                <ListItemIcon>
                  {log.status === 'success' ? (
                    <CheckCircleIcon color="success" />
                  ) : log.status === 'running' ? (
                    <CircularProgress size={24} />
                  ) : log.status === 'error' ? (
                    <WarningIcon color="error" />
                  ) : (
                    <AccessTimeIcon color="primary" />
                  )}
                </ListItemIcon>
                <ListItemText
                  primary={log.action}
                  secondary={`Step ${log.step} - ${log.timestamp.toLocaleTimeString()}`}
                />
              </ListItem>
            ))}
          </List>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenExecutionDialog(false)} disabled={executing}>
            {executing ? 'Executando...' : 'Fechar'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Criação/Edição */}
      <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>{selectedPlaybook ? 'Editar Playbook' : 'Novo Playbook'}</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Nome do Playbook"
            margin="normal"
            variant="outlined"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          />
          <TextField
            fullWidth
            label="Descrição"
            margin="normal"
            multiline
            rows={3}
            variant="outlined"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Trigger</InputLabel>
            <Select 
              label="Trigger"
              value={formData.trigger}
              onChange={(e) => setFormData({ ...formData, trigger: e.target.value })}
            >
              <MenuItem value="Alerta de Força Bruta">Alerta de Força Bruta</MenuItem>
              <MenuItem value="Detecção de Malware">Detecção de Malware</MenuItem>
              <MenuItem value="Anomalia de Comportamento">Anomalia de Comportamento</MenuItem>
              <MenuItem value="Credenciais Comprometidas">Credenciais Comprometidas</MenuItem>
              <MenuItem value="Detecção de Phishing">Detecção de Phishing</MenuItem>
              <MenuItem value="Detecção de Ransomware">Detecção de Ransomware</MenuItem>
              <MenuItem value="Detecção de DDoS">Detecção de DDoS</MenuItem>
            </Select>
          </FormControl>
          
          <FormControl fullWidth margin="normal">
            <InputLabel>Status</InputLabel>
            <Select 
              label="Status"
              value={formData.status}
              onChange={(e) => setFormData({ ...formData, status: e.target.value })}
            >
              <MenuItem value="testing">Testing</MenuItem>
              <MenuItem value="active">Active</MenuItem>
              <MenuItem value="disabled">Disabled</MenuItem>
            </Select>
          </FormControl>

          <Typography variant="subtitle2" sx={{ mt: 3, mb: 2 }}>
            Ações ({formData.actions.length})
          </Typography>
          
          {formData.actions.map((action, index) => (
            <Card key={index} sx={{ mb: 2, p: 2, bgcolor: 'background.default' }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="body2" fontWeight={600}>
                  Ação {index + 1}
                </Typography>
                <IconButton size="small" color="error" onClick={() => handleRemoveAction(index)}>
                  <DeleteIcon />
                </IconButton>
              </Box>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Tipo</InputLabel>
                    <Select
                      label="Tipo"
                      value={action.type}
                      onChange={(e) => handleActionChange(index, 'type', e.target.value)}
                    >
                      <MenuItem value="block_ip">Bloquear IP</MenuItem>
                      <MenuItem value="isolate_host">Isolar Host</MenuItem>
                      <MenuItem value="quarantine_email">Quarentenar Email</MenuItem>
                      <MenuItem value="create_ticket">Criar Ticket</MenuItem>
                      <MenuItem value="notify">Notificar</MenuItem>
                      <MenuItem value="revoke_tokens">Revogar Tokens</MenuItem>
                      <MenuItem value="disable_account">Desabilitar Conta</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Alvo</InputLabel>
                    <Select
                      label="Alvo"
                      value={action.target}
                      onChange={(e) => handleActionChange(index, 'target', e.target.value)}
                    >
                      <MenuItem value="firewall">Firewall</MenuItem>
                      <MenuItem value="edr">EDR</MenuItem>
                      <MenuItem value="email_gateway">Email Gateway</MenuItem>
                      <MenuItem value="jira">Jira</MenuItem>
                      <MenuItem value="slack">Slack</MenuItem>
                      <MenuItem value="identity_provider">Identity Provider</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>
            </Card>
          ))}
          
          <Button 
            startIcon={<AddIcon />} 
            variant="outlined" 
            size="small"
            onClick={handleAddAction}
            fullWidth
          >
            Adicionar Ação
          </Button>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>
            Cancelar
          </Button>
          <Button 
            variant="contained" 
            onClick={handleSavePlaybook}
            disabled={!formData.name || !formData.trigger || formData.actions.length === 0}
          >
            Salvar Playbook
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Confirmação de Exclusão */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Confirmar Exclusão</DialogTitle>
        <DialogContent>
          <Typography>
            Tem certeza que deseja excluir o playbook <strong>{playbookToDelete?.name}</strong>?
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            Esta ação não pode ser desfeita. Todas as execuções e histórico deste playbook serão mantidos.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>
            Cancelar
          </Button>
          <Button 
            variant="contained" 
            color="error" 
            onClick={handleDeleteConfirm}
          >
            Excluir
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Playbooks;
