import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
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
  Chip,
  Divider,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  Save as SaveIcon,
  PlayArrow as PlayIcon,
  ArrowDownward as ArrowDownIcon,
  Security as SecurityIcon,
  Block as BlockIcon,
  Email as EmailIcon,
  Webhook as WebhookIcon,
  BugReport as BugReportIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
} from '@mui/icons-material';

const PlaybookEditor = () => {
  const [playbookName, setPlaybookName] = useState('Novo Playbook');
  const [playbookDescription, setPlaybookDescription] = useState('');
  const [trigger, setTrigger] = useState('');
  const [actions, setActions] = useState([
    { id: 1, type: 'block_ip', target: 'firewall', params: { duration: '24h' }, description: 'Bloquear IP no Firewall' },
  ]);
  const [openActionDialog, setOpenActionDialog] = useState(false);
  const [editingAction, setEditingAction] = useState(null);
  const [testResults, setTestResults] = useState(null);

  const actionTypes = [
    { value: 'block_ip', label: 'Bloquear IP', icon: <BlockIcon />, category: 'Network' },
    { value: 'block_domain', label: 'Bloquear Domínio', icon: <BlockIcon />, category: 'Network' },
    { value: 'isolate_host', label: 'Isolar Host', icon: <SecurityIcon />, category: 'Endpoint' },
    { value: 'revoke_access', label: 'Revogar Acesso', icon: <SecurityIcon />, category: 'Identity' },
    { value: 'reset_password', label: 'Reset de Senha', icon: <SecurityIcon />, category: 'Identity' },
    { value: 'create_ticket', label: 'Criar Ticket', icon: <BugReportIcon />, category: 'Ticketing' },
    { value: 'create_incident', label: 'Criar Incidente', icon: <WarningIcon />, category: 'Incident' },
    { value: 'notify_email', label: 'Notificar Email', icon: <EmailIcon />, category: 'Notification' },
    { value: 'notify_slack', label: 'Notificar Slack', icon: <WebhookIcon />, category: 'Notification' },
    { value: 'notify_teams', label: 'Notificar Teams', icon: <WebhookIcon />, category: 'Notification' },
  ];

  const triggers = [
    { value: 'brute_force', label: 'Alerta de Força Bruta' },
    { value: 'malware', label: 'Detecção de Malware' },
    { value: 'anomaly', label: 'Anomalia de Comportamento (ML)' },
    { value: 'data_breach', label: 'Credenciais Comprometidas' },
    { value: 'ransomware', label: 'Detecção de Ransomware' },
    { value: 'exfiltration', label: 'Exfiltração de Dados' },
    { value: 'privilege_escalation', label: 'Escalação de Privilégios' },
    { value: 'lateral_movement', label: 'Movimento Lateral' },
  ];

  const handleAddAction = () => {
    setEditingAction(null);
    setOpenActionDialog(true);
  };

  const handleEditAction = (action) => {
    setEditingAction(action);
    setOpenActionDialog(true);
  };

  const handleDeleteAction = (id) => {
    setActions(actions.filter(a => a.id !== id));
  };

  const handleSaveAction = (actionData) => {
    if (editingAction) {
      setActions(actions.map(a => a.id === editingAction.id ? { ...a, ...actionData } : a));
    } else {
      const newAction = {
        id: Date.now(),
        ...actionData,
      };
      setActions([...actions, newAction]);
    }
    setOpenActionDialog(false);
  };

  const handleTestPlaybook = () => {
    setTestResults({
      status: 'running',
      steps: actions.map((action, index) => ({
        step: index + 1,
        action: action.description,
        status: 'pending',
      })),
    });

    // Simular execução
    let currentStep = 0;
    const interval = setInterval(() => {
      if (currentStep >= actions.length) {
        clearInterval(interval);
        setTestResults(prev => ({
          ...prev,
          status: 'success',
        }));
        return;
      }

      setTestResults(prev => ({
        ...prev,
        steps: prev.steps.map((step, index) => {
          if (index === currentStep) {
            return { ...step, status: 'success' };
          }
          if (index === currentStep + 1) {
            return { ...step, status: 'running' };
          }
          return step;
        }),
      }));

      currentStep++;
    }, 1000);
  };

  const handleSavePlaybook = () => {
    const playbook = {
      name: playbookName,
      description: playbookDescription,
      trigger,
      actions: actions.map(a => ({
        type: a.type,
        target: a.target,
        params: a.params,
      })),
    };

    console.log('Salvando playbook:', playbook);
    alert('Playbook salvo com sucesso!');
  };

  const getActionIcon = (type) => {
    const action = actionTypes.find(a => a.value === type);
    return action?.icon || <SecurityIcon />;
  };

  const getStepStatus = (status) => {
    switch (status) {
      case 'success':
        return { icon: <CheckCircleIcon color="success" />, color: 'success' };
      case 'running':
        return { icon: <PlayIcon color="primary" />, color: 'primary' };
      case 'pending':
        return { icon: <WarningIcon color="disabled" />, color: 'default' };
      default:
        return { icon: <WarningIcon />, color: 'default' };
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          ⚙️ Editor de Playbooks
        </Typography>
        <Box>
          <Button
            variant="outlined"
            startIcon={<PlayIcon />}
            onClick={handleTestPlaybook}
            sx={{ mr: 1 }}
          >
            Testar
          </Button>
          <Button
            variant="contained"
            startIcon={<SaveIcon />}
            onClick={handleSavePlaybook}
          >
            Salvar Playbook
          </Button>
        </Box>
      </Box>

      <Grid container spacing={3}>
        {/* Informações Básicas */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>
              📋 Informações Básicas
            </Typography>
            <TextField
              fullWidth
              label="Nome do Playbook"
              value={playbookName}
              onChange={(e) => setPlaybookName(e.target.value)}
              sx={{ mb: 2 }}
            />
            <TextField
              fullWidth
              label="Descrição"
              value={playbookDescription}
              onChange={(e) => setPlaybookDescription(e.target.value)}
              multiline
              rows={3}
              sx={{ mb: 2 }}
            />
            <FormControl fullWidth>
              <InputLabel>Trigger (Gatilho)</InputLabel>
              <Select
                value={trigger}
                label="Trigger (Gatilho)"
                onChange={(e) => setTrigger(e.target.value)}
              >
                {triggers.map(t => (
                  <MenuItem key={t.value} value={t.value}>
                    {t.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Paper>

          {/* Workflow Visual */}
          <Paper sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                🔄 Workflow de Ações
              </Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={handleAddAction}
                size="small"
              >
                Adicionar Ação
              </Button>
            </Box>

            <Stepper orientation="vertical">
              {/* Trigger Step */}
              <Step active completed>
                <StepLabel icon={<SecurityIcon color="primary" />}>
                  <Typography variant="subtitle1" fontWeight={600}>
                    Trigger: {triggers.find(t => t.value === trigger)?.label || 'Selecione um trigger'}
                  </Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    Quando este evento for detectado, o playbook será executado automaticamente
                  </Typography>
                </StepContent>
              </Step>

              {/* Action Steps */}
              {actions.map((action, index) => (
                <Step key={action.id} active>
                  <StepLabel
                    icon={getActionIcon(action.type)}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="subtitle1" fontWeight={600}>
                        Ação {index + 1}: {action.description}
                      </Typography>
                      <Chip
                        label={action.target}
                        size="small"
                        color="primary"
                        variant="outlined"
                      />
                    </Box>
                  </StepLabel>
                  <StepContent>
                    <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                      <Typography variant="body2" color="text.secondary" sx={{ flexGrow: 1 }}>
                        Tipo: {action.type} | Alvo: {action.target}
                      </Typography>
                      <IconButton size="small" onClick={() => handleEditAction(action)}>
                        <EditIcon fontSize="small" />
                      </IconButton>
                      <IconButton size="small" color="error" onClick={() => handleDeleteAction(action.id)}>
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Box>
                  </StepContent>
                </Step>
              ))}

              {/* Final Step */}
              <Step active={false}>
                <StepLabel icon={<CheckCircleIcon color="success" />}>
                  <Typography variant="subtitle1" fontWeight={600}>
                    Playbook Finalizado
                  </Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    Registrar execução e atualizar métricas
                  </Typography>
                </StepContent>
              </Step>
            </Stepper>
          </Paper>
        </Grid>

        {/* Sidebar - Biblioteca de Ações */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2, position: 'sticky', top: 20 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>
              📚 Biblioteca de Ações
            </Typography>
            <List dense>
              {['Network', 'Endpoint', 'Identity', 'Notification', 'Ticketing', 'Incident'].map(category => (
                <Box key={category}>
                  <Typography variant="caption" color="primary" sx={{ ml: 1, fontWeight: 600 }}>
                    {category}
                  </Typography>
                  {actionTypes.filter(a => a.category === category).map(action => (
                    <ListItem
                      key={action.value}
                      sx={{
                        cursor: 'pointer',
                        '&:hover': { bgcolor: 'action.hover' },
                        borderRadius: 1,
                        mb: 0.5,
                      }}
                    >
                      <ListItemIcon sx={{ minWidth: 36 }}>
                        {action.icon}
                      </ListItemIcon>
                      <ListItemText
                        primary={action.label}
                        primaryTypographyProps={{ variant: 'body2' }}
                      />
                    </ListItem>
                  ))}
                  <Divider sx={{ my: 1 }} />
                </Box>
              ))}
            </List>
          </Paper>
        </Grid>
      </Grid>

      {/* Dialog de Teste */}
      {testResults && (
        <Dialog open={true} onClose={() => setTestResults(null)} maxWidth="sm" fullWidth>
          <DialogTitle>
            🧪 Teste do Playbook: {playbookName}
          </DialogTitle>
          <DialogContent>
            <List>
              {testResults.steps.map((step) => {
                const stepStatus = getStepStatus(step.status);
                return (
                  <ListItem key={step.step}>
                    <ListItemIcon>
                      {stepStatus.icon}
                    </ListItemIcon>
                    <ListItemText
                      primary={`Step ${step.step}: ${step.action}`}
                      secondary={step.status}
                    />
                  </ListItem>
                );
              })}
            </List>
            {testResults.status === 'success' && (
              <Box sx={{ mt: 2, p: 2, bgcolor: 'success.main', color: 'white', borderRadius: 1 }}>
                <Typography variant="body1" fontWeight={600}>
                  ✅ Teste concluído com sucesso!
                </Typography>
                <Typography variant="body2">
                  Todas as ações foram executadas corretamente.
                </Typography>
              </Box>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setTestResults(null)}>
              Fechar
            </Button>
          </DialogActions>
        </Dialog>
      )}

      {/* Dialog de Adicionar/Editar Ação */}
      <ActionDialog
        open={openActionDialog}
        onClose={() => setOpenActionDialog(false)}
        onSave={handleSaveAction}
        action={editingAction}
        actionTypes={actionTypes}
      />
    </Box>
  );
};

// Componente Dialog de Ação
const ActionDialog = ({ open, onClose, onSave, action, actionTypes }) => {
  const [type, setType] = useState(action?.type || '');
  const [target, setTarget] = useState(action?.target || '');
  const [description, setDescription] = useState(action?.description || '');
  const [params, setParams] = useState(action?.params || {});

  const handleSave = () => {
    onSave({
      type,
      target,
      description: description || actionTypes.find(a => a.value === type)?.label,
      params,
    });
    onClose();
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        {action ? 'Editar Ação' : 'Nova Ação'}
      </DialogTitle>
      <DialogContent>
        <FormControl fullWidth sx={{ mt: 2, mb: 2 }}>
          <InputLabel>Tipo de Ação</InputLabel>
          <Select
            value={type}
            label="Tipo de Ação"
            onChange={(e) => setType(e.target.value)}
          >
            {actionTypes.map(a => (
              <MenuItem key={a.value} value={a.value}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {a.icon}
                  {a.label}
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <TextField
          fullWidth
          label="Alvo (Target)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          sx={{ mb: 2 }}
          placeholder="Ex: firewall, edr, slack"
        />

        <TextField
          fullWidth
          label="Descrição"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          multiline
          rows={2}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>
          Cancelar
        </Button>
        <Button variant="contained" onClick={handleSave}>
          Salvar
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default PlaybookEditor;

