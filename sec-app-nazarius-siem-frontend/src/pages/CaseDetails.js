import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Grid,
  Typography,
  Button,
  Card,
  CardContent,
  Box,
  Chip,
  Paper,
  IconButton,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  CircularProgress,
  Alert,
  Divider,
  List,
  ListItem,
  ListItemText,
  Checkbox,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
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
  Edit as EditIcon,
  Person as PersonIcon,
  Comment as CommentIcon,
  PlayArrow as PlayIcon,
  Assignment as AssignmentIcon,
  Flag as FlagIcon,
  Schedule as ScheduleIcon,
  Send as SendIcon,
  Save as SaveIcon,
  Close as CloseIcon,
  Sync as SyncIcon,
  NotificationsActive as AlertIcon,
  FileDownload as FileDownloadIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material';
import { casesAPI, usersAPI } from '../services/api';

const CaseDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  
  const [caseData, setCaseData] = useState(null);
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [commentText, setCommentText] = useState('');
  const [submittingComment, setSubmittingComment] = useState(false);
  const [editingStatus, setEditingStatus] = useState(false);
  const [newStatus, setNewStatus] = useState('');
  const [analysts, setAnalysts] = useState([]);

  // Estado para modal de edição
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editForm, setEditForm] = useState({
    title: '',
    description: '',
    severity: '',
    priority: '',
    status: '',
    category: '',
    assignedTo: '',
  });
  const [saving, setSaving] = useState(false);
  
  // Estado para alertas vinculados e propagação de status
  const [linkedAlerts, setLinkedAlerts] = useState([]);
  const [linkedEvents, setLinkedEvents] = useState([]);
  const [propagateToAlerts, setPropagateToAlerts] = useState(true);
  const [propagateToEvents, setPropagateToEvents] = useState(true);
  const [statusDialogOpen, setStatusDialogOpen] = useState(false);
  const [statusComment, setStatusComment] = useState('');
  const [downloadingReport, setDownloadingReport] = useState(false);
  const [checklistItems, setChecklistItems] = useState([]);
  const [newChecklistItem, setNewChecklistItem] = useState('');
  const [playbooks, setPlaybooks] = useState([]);
  const [newPlaybookId, setNewPlaybookId] = useState('');

  const getMitreTactics = () => caseData?.mitreTactics || caseData?.mitre_tactics || [];
  const getMitreTechniques = () => caseData?.mitreTechniques || caseData?.mitre_techniques || [];
  const getAffectedAssets = () => caseData?.affectedAssets || caseData?.affected_assets || [];
  const getIndicators = () => caseData?.indicators || {};
  const getEvidence = () => caseData?.evidence || [];
  const getSummary = () => caseData?.summary || {};
  const getRecommendations = () => caseData?.recommendations || [];

  const loadCaseData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [caseResponse, activitiesResponse] = await Promise.all([
        casesAPI.get(id),
        casesAPI.getActivities(id),
      ]);
      
      if (caseResponse.data) {
        setCaseData(caseResponse.data);
        setNewStatus(caseResponse.data.status);
        setChecklistItems(caseResponse.data.checklist || []);
        setPlaybooks(caseResponse.data.relatedPlaybooks || caseResponse.data.related_playbooks || []);
      }
      
      if (activitiesResponse.data && activitiesResponse.data.activities) {
        setActivities(activitiesResponse.data.activities);
      }
      
      // Carregar alertas vinculados
      try {
        const linkedResponse = await casesAPI.getLinkedAlerts(id);
        if (linkedResponse.data && linkedResponse.data.alerts) {
          setLinkedAlerts(linkedResponse.data.alerts);
        }
      } catch (linkedErr) {
        console.log('Alertas vinculados não disponíveis:', linkedErr);
      }

      // Carregar eventos vinculados
      try {
        const linkedEventsResponse = await casesAPI.getLinkedEvents(id);
        if (linkedEventsResponse.data && linkedEventsResponse.data.events) {
          setLinkedEvents(linkedEventsResponse.data.events);
        }
      } catch (linkedEventsErr) {
        console.log('Eventos vinculados não disponíveis:', linkedEventsErr);
      }

      // Carregar checklist
      try {
        const checklistResponse = await casesAPI.getChecklist(id);
        if (checklistResponse.data && checklistResponse.data.checklist) {
          setChecklistItems(checklistResponse.data.checklist);
        }
      } catch (checklistErr) {
        console.log('Checklist não disponível:', checklistErr);
      }

      // Carregar playbooks
      try {
        const playbooksResponse = await casesAPI.getPlaybooks(id);
        if (playbooksResponse.data && playbooksResponse.data.playbooks) {
          setPlaybooks(playbooksResponse.data.playbooks);
        }
      } catch (playbookErr) {
        console.log('Playbooks não disponíveis:', playbookErr);
      }
    } catch (err) {
      console.error('Erro ao carregar caso:', err);
      setError('Erro ao carregar detalhes do caso.');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadCaseData();
  }, [loadCaseData]);

  // Carregar lista de analistas para atribuição
  useEffect(() => {
    const loadAnalysts = async () => {
      try {
        const response = await usersAPI.list();
        if (response.data && response.data.users) {
          // Filtrar apenas usuários ativos que podem receber casos
          const activeAnalysts = response.data.users.filter(u => u.is_active !== false);
          setAnalysts(activeAnalysts);
        }
      } catch (err) {
        console.log('Erro ao carregar analistas:', err);
        // Não é crítico, o campo continua funcionando como texto livre
      }
    };
    loadAnalysts();
  }, []);

  const handleDownloadReport = async () => {
    try {
      setDownloadingReport(true);
      const response = await casesAPI.getReport(id, 'markdown');
      const blob = new Blob([response.data], { type: 'text/markdown;charset=utf-8' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `case-${id}.md`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Erro ao baixar relatório:', err);
      setError('Erro ao gerar relatório do caso.');
    } finally {
      setDownloadingReport(false);
    }
  };

  const handleAddChecklistItem = async () => {
    if (!newChecklistItem.trim()) return;
    try {
      const response = await casesAPI.addChecklistItem(id, newChecklistItem.trim());
      setChecklistItems((prev) => [...prev, response.data]);
      setNewChecklistItem('');
    } catch (err) {
      console.error('Erro ao adicionar item:', err);
      setError('Erro ao adicionar item no checklist.');
    }
  };

  const handleToggleChecklistItem = async (item) => {
    try {
      const newStatus = item.status === 'done' ? 'open' : 'done';
      await casesAPI.updateChecklistItem(id, item.id, { status: newStatus });
      setChecklistItems((prev) =>
        prev.map((i) => (i.id === item.id ? { ...i, status: newStatus } : i))
      );
    } catch (err) {
      console.error('Erro ao atualizar checklist:', err);
      setError('Erro ao atualizar item do checklist.');
    }
  };

  const handleDeleteChecklistItem = async (itemId) => {
    try {
      await casesAPI.deleteChecklistItem(id, itemId);
      setChecklistItems((prev) => prev.filter((i) => i.id !== itemId));
    } catch (err) {
      console.error('Erro ao remover item:', err);
      setError('Erro ao remover item do checklist.');
    }
  };

  const handleAddPlaybook = async () => {
    if (!newPlaybookId.trim()) return;
    try {
      await casesAPI.addPlaybook(id, newPlaybookId.trim());
      setPlaybooks((prev) => [...prev, newPlaybookId.trim()]);
      setNewPlaybookId('');
    } catch (err) {
      console.error('Erro ao adicionar playbook:', err);
      setError('Erro ao adicionar playbook ao caso.');
    }
  };

  const handleDeletePlaybook = async (playbookId) => {
    try {
      await casesAPI.deletePlaybook(id, playbookId);
      setPlaybooks((prev) => prev.filter((p) => p !== playbookId));
    } catch (err) {
      console.error('Erro ao remover playbook:', err);
      setError('Erro ao remover playbook do caso.');
    }
  };

  const handleExecutePlaybook = async (playbookId) => {
    try {
      const triggerData = {
        case_id: id,
        severity: caseData?.severity,
        category: caseData?.category,
      };
      await casesAPI.executePlaybook(id, playbookId, triggerData);
      setSuccess('Playbook executado com sucesso!');
      await loadCaseData();
    } catch (err) {
      console.error('Erro ao executar playbook:', err);
      setError('Erro ao executar playbook.');
    }
  };

  const handleAddComment = async () => {
    if (!commentText.trim()) return;
    
    try {
      setSubmittingComment(true);
      await casesAPI.addComment(id, commentText);
      setCommentText('');
      await loadCaseData(); // Recarregar para mostrar novo comentário
    } catch (err) {
      console.error('Erro ao adicionar comentário:', err);
      setError('Erro ao adicionar comentário.');
    } finally {
      setSubmittingComment(false);
    }
  };

  const handleUpdateStatus = async () => {
    if (newStatus === caseData.status) {
      setEditingStatus(false);
      return;
    }
    
    // Se existem alertas vinculados, mostrar dialog de confirmação
    if (linkedAlerts.length > 0) {
      setStatusDialogOpen(true);
      return;
    }
    
    // Sem alertas vinculados, atualizar diretamente
    try {
      await casesAPI.update(id, { status: newStatus });
      setEditingStatus(false);
      setSuccess('Status atualizado com sucesso!');
      await loadCaseData();
    } catch (err) {
      console.error('Erro ao atualizar status:', err);
      setError('Erro ao atualizar status.');
    }
  };

  // Confirmar atualização de status com propagação
  const handleConfirmStatusUpdate = async () => {
    try {
      setEditingStatus(false);
      setStatusDialogOpen(false);
      
      // Usar a API com propagação
      const response = await casesAPI.updateStatusWithPropagation(
        id, 
        newStatus, 
        propagateToAlerts, 
        propagateToEvents,
        statusComment
      );
      
      const { alerts_updated, events_updated } = response.data;
      let message = 'Status atualizado com sucesso!';
      if (alerts_updated > 0 || events_updated > 0) {
        message += ` (${alerts_updated} alertas e ${events_updated} eventos atualizados)`;
      }
      
      setSuccess(message);
      setStatusComment('');
      await loadCaseData();
    } catch (err) {
      console.error('Erro ao atualizar status:', err);
      setError('Erro ao atualizar status: ' + (err.response?.data?.error || err.message));
    }
  };

  // Abrir modal de edição
  const handleOpenEditDialog = () => {
    if (caseData) {
      setEditForm({
        title: caseData.title || '',
        description: caseData.description || '',
        severity: caseData.severity || 'medium',
        priority: caseData.priority || 'medium',
        status: caseData.status || 'new',
        category: caseData.category || '',
        assignedTo: caseData.assignedTo || '',
      });
      setEditDialogOpen(true);
    }
  };

  // Fechar modal de edição
  const handleCloseEditDialog = () => {
    setEditDialogOpen(false);
    setEditForm({
      title: '',
      description: '',
      severity: '',
      priority: '',
      status: '',
      category: '',
      assignedTo: '',
    });
  };

  // Atualizar campo do formulário
  const handleEditFormChange = (field) => (event) => {
    setEditForm(prev => ({
      ...prev,
      [field]: event.target.value
    }));
  };

  // Salvar edição do caso
  const handleSaveCase = async () => {
    try {
      setSaving(true);
      setError(null);
      
      // Preparar dados para atualização
      const updateData = {
        title: editForm.title,
        description: editForm.description,
        severity: editForm.severity,
        priority: editForm.priority,
        status: editForm.status,
        category: editForm.category,
        assigned_to: editForm.assignedTo,
      };
      
      await casesAPI.update(id, updateData);
      setSuccess('Caso atualizado com sucesso!');
      handleCloseEditDialog();
      await loadCaseData();
    } catch (err) {
      console.error('Erro ao atualizar caso:', err);
      setError('Erro ao atualizar caso: ' + (err.response?.data?.error || err.message));
    } finally {
      setSaving(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'new': return 'info';
      case 'in_progress': return 'warning';
      case 'resolved': return 'success';
      case 'closed': return 'default';
      default: return 'default';
    }
  };

  const getActivityIcon = (type) => {
    switch (type) {
      case 'comment': return <CommentIcon />;
      case 'status_change': return <FlagIcon />;
      case 'assignment': return <PersonIcon />;
      case 'playbook_execution': return <PlayIcon />;
      case 'case_created': return <AssignmentIcon />;
      default: return <ScheduleIcon />;
    }
  };

  const getActivityColor = (type) => {
    switch (type) {
      case 'comment': return 'primary';
      case 'status_change': return 'warning';
      case 'assignment': return 'info';
      case 'playbook_execution': return 'success';
      case 'case_created': return 'secondary';
      default: return 'grey';
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString('pt-BR');
  };

  const formatDuration = (seconds) => {
    if (!seconds) return 'N/A';
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress size={60} />
      </Box>
    );
  }

  if (!caseData) {
    return (
      <Box>
        <Alert severity="error">Caso não encontrado.</Alert>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/cases')} sx={{ mt: 2 }}>
          Voltar
        </Button>
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <IconButton onClick={() => navigate('/cases')} sx={{ mr: 2 }}>
            <ArrowBackIcon />
          </IconButton>
          <Box>
            <Typography variant="h4">
              Caso #{caseData.id.substring(0, 8)}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Criado em {formatDate(caseData.createdAt)} por {caseData.createdBy}
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<FileDownloadIcon />}
            onClick={handleDownloadReport}
            disabled={downloadingReport}
          >
            {downloadingReport ? 'Gerando...' : 'Relatório'}
          </Button>
        <Button
          variant="outlined"
          startIcon={<EditIcon />}
            onClick={handleOpenEditDialog}
        >
          Editar
        </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 3 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Coluna Esquerda - Informações do Caso */}
        <Grid item xs={12} md={8}>
          {/* Informações Principais */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                {caseData.title}
              </Typography>
              
              <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                <Chip
                  label={caseData.severity}
                  color={getSeverityColor(caseData.severity)}
                  size="small"
                />
                {editingStatus ? (
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <FormControl size="small" sx={{ minWidth: 150 }}>
                      <Select
                        value={newStatus}
                        onChange={(e) => setNewStatus(e.target.value)}
                      >
                        <MenuItem value="new">Novo</MenuItem>
                        <MenuItem value="in_progress">Em Progresso</MenuItem>
                        <MenuItem value="resolved">Resolvido</MenuItem>
                        <MenuItem value="closed">Fechado</MenuItem>
                      </Select>
                    </FormControl>
                    <Button size="small" onClick={handleUpdateStatus}>Salvar</Button>
                    <Button size="small" onClick={() => setEditingStatus(false)}>Cancelar</Button>
                  </Box>
                ) : (
                  <Chip
                    label={caseData.status}
                    color={getStatusColor(caseData.status)}
                    size="small"
                    onClick={() => setEditingStatus(true)}
                    clickable
                  />
                )}
                <Chip label={caseData.category} size="small" variant="outlined" />
              </Box>

              <Typography variant="body1" paragraph>
                {caseData.description}
              </Typography>

              <Divider sx={{ my: 2 }} />

              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">
                    Atribuído a
                  </Typography>
                  <Typography variant="body2" fontWeight={600}>
                    {caseData.assignedTo}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">
                    Prioridade
                  </Typography>
                  <Typography variant="body2" fontWeight={600}>
                    {caseData.priority}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">
                    Tempo para Detectar
                  </Typography>
                  <Typography variant="body2">
                    {formatDuration(caseData.timeToDetect)}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">
                    Tempo para Responder
                  </Typography>
                  <Typography variant="body2">
                    {formatDuration(caseData.timeToRespond)}
                  </Typography>
                </Grid>
              </Grid>

              {caseData.tags && caseData.tags.length > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="caption" color="text.secondary">
                    Tags
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                    {caseData.tags.map((tag, index) => (
                      <Chip key={index} label={tag} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Box>
              )}
            </CardContent>
          </Card>

          {/* Timeline de Atividades */}
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                📅 Timeline de Investigação
              </Typography>
              
              <Timeline>
                {activities.map((activity, index) => (
                  <TimelineItem key={activity.id}>
                    <TimelineOppositeContent color="text.secondary" sx={{ flex: 0.2 }}>
                      <Typography variant="caption">
                        {formatDate(activity.timestamp)}
                      </Typography>
                    </TimelineOppositeContent>
                    <TimelineSeparator>
                      <TimelineDot color={getActivityColor(activity.type)}>
                        {getActivityIcon(activity.type)}
                      </TimelineDot>
                      {index < activities.length - 1 && <TimelineConnector />}
                    </TimelineSeparator>
                    <TimelineContent>
                      <Paper elevation={2} sx={{ p: 2 }}>
                        <Typography variant="body2" fontWeight={600}>
                          {activity.type === 'comment' && '💬 Comentário'}
                          {activity.type === 'status_change' && '🔄 Mudança de Status'}
                          {activity.type === 'assignment' && '👤 Atribuição'}
                          {activity.type === 'playbook_execution' && '🤖 Execução de Playbook'}
                          {activity.type === 'case_created' && '📝 Caso Criado'}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" display="block">
                          por {activity.user}
                        </Typography>
                        <Typography variant="body2" sx={{ mt: 1 }}>
                          {activity.content}
                        </Typography>
                        {activity.oldValue && activity.newValue && (
                          <Typography variant="caption" color="text.secondary">
                            {activity.oldValue} → {activity.newValue}
                          </Typography>
                        )}
                      </Paper>
                    </TimelineContent>
                  </TimelineItem>
                ))}
              </Timeline>
            </CardContent>
          </Card>

          {/* Resumo do Caso */}
          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                📌 Resumo do Caso
              </Typography>
              {getSummary().risk_score !== undefined ? (
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 3, mb: 2 }}>
                    <Box>
                      <Typography variant="h3" color="primary" fontWeight={700}>
                        {getSummary().risk_score}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Risk Score
                      </Typography>
                    </Box>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        SLA Status
                      </Typography>
                      <Chip 
                        label={getSummary().sla_status === 'breached' ? 'SLA Violado' : 'Dentro do SLA'} 
                        color={getSummary().sla_status === 'breached' ? 'error' : 'success'} 
                        size="small" 
                      />
                    </Box>
                  </Box>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    {getSummary().business_impact}
                  </Typography>
                  {getSummary().key_findings?.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" color="text.secondary">Principais achados</Typography>
                      <List dense>
                        {getSummary().key_findings.map((f, idx) => (
                          <ListItem key={idx}>
                            <ListItemText primary={f} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}
                  {getSummary().next_steps?.length > 0 && (
                    <Box>
                      <Typography variant="subtitle2" color="text.secondary">Próximos passos</Typography>
                      <List dense>
                        {getSummary().next_steps.map((s, idx) => (
                          <ListItem key={idx}>
                            <ListItemText primary={s} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}
                </Box>
              ) : (
                <Alert severity="info">Resumo não disponível para este caso.</Alert>
              )}
            </CardContent>
          </Card>

          {/* Recomendações */}
          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                ✅ Recomendações
              </Typography>
              {getRecommendations().length > 0 ? (
                <List>
                  {getRecommendations().map((rec, idx) => (
                    <ListItem key={idx} alignItems="flex-start">
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Chip label={`P${rec.priority}`} size="small" color={rec.priority === 1 ? 'error' : rec.priority === 2 ? 'warning' : 'default'} />
                            <Typography variant="subtitle2">{rec.title}</Typography>
                          </Box>
                        }
                        secondary={
                          <Box sx={{ mt: 1 }}>
                            <Typography variant="body2">{rec.description}</Typography>
                            <Typography variant="caption" color="text.secondary">Ação: {rec.action}</Typography>
                          </Box>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Alert severity="info">Nenhuma recomendação disponível.</Alert>
              )}
            </CardContent>
          </Card>

          {/* Evidências */}
          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                🧾 Evidências
              </Typography>
              {getEvidence().length > 0 ? (
                <List>
                  {getEvidence().map((ev, idx) => (
                    <ListItem key={ev.id || idx} alignItems="flex-start">
                      <ListItemText
                        primary={`${ev.type || 'evidence'} - ${ev.description || 'Sem descrição'}`}
                        secondary={
                          <Box sx={{ mt: 0.5 }}>
                            <Typography variant="caption" color="text.secondary">
                              Fonte: {ev.source || 'N/A'} | {ev.timestamp ? new Date(ev.timestamp).toLocaleString('pt-BR') : 'N/A'}
                            </Typography>
                          </Box>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Alert severity="info">Nenhuma evidência registrada.</Alert>
              )}
            </CardContent>
          </Card>

          {/* Indicadores e MITRE */}
          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                🎯 Indicadores e MITRE ATT&CK
              </Typography>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" color="text.secondary">Indicadores</Typography>
                {Object.keys(getIndicators()).length > 0 ? (
                  <List dense>
                    {Object.entries(getIndicators()).map(([key, value]) => (
                      <ListItem key={key}>
                        <ListItemText 
                          primary={key} 
                          secondary={Array.isArray(value) ? value.join(', ') : String(value)} 
                        />
                      </ListItem>
                    ))}
                  </List>
                ) : (
                  <Alert severity="info">Nenhum indicador disponível.</Alert>
                )}
              </Box>
              <Divider sx={{ my: 2 }} />
              <Box>
                <Typography variant="subtitle2" color="text.secondary">MITRE ATT&CK</Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
                  {getMitreTactics().map((t, idx) => (
                    <Chip key={`tactic-${idx}`} label={t} size="small" color="error" variant="outlined" />
                  ))}
                  {getMitreTechniques().map((t, idx) => (
                    <Chip key={`tech-${idx}`} label={t} size="small" color="warning" variant="outlined" />
                  ))}
                </Box>
                {getAffectedAssets().length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" color="text.secondary">Ativos afetados</Typography>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
                      {getAffectedAssets().map((a, idx) => (
                        <Chip key={`asset-${idx}`} label={a} size="small" variant="outlined" />
                      ))}
                    </Box>
                  </Box>
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Coluna Direita - Painel Lateral */}
        <Grid item xs={12} md={4}>
          {/* SLA Status */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                ⏱️ SLA Status
              </Typography>
              <Box sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h2" color={caseData.slaBreach ? 'error' : 'success.main'}>
                  {formatDuration(caseData.slaRemaining)}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {caseData.slaBreach ? 'SLA VIOLADO' : 'Tempo Restante'}
                </Typography>
                {caseData.slaDeadline && (
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                    Deadline: {formatDate(caseData.slaDeadline)}
                  </Typography>
                )}
              </Box>
            </CardContent>
          </Card>

          {/* Alertas Vinculados */}
          {linkedAlerts.length > 0 && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <AlertIcon color="warning" />
                  <Typography variant="h6">
                    Alertas Vinculados ({linkedAlerts.length})
                  </Typography>
                </Box>
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="caption">
                    Ao mudar o status deste caso, você pode propagar a mudança para estes alertas automaticamente.
                  </Typography>
                </Alert>
                <List dense>
                  {linkedAlerts.map((alert, index) => (
                    <ListItem key={alert.id || index} sx={{ bgcolor: 'background.default', borderRadius: 1, mb: 0.5 }}>
                      <ListItemText 
                        primary={alert.name || alert.description || `Alerta ${index + 1}`}
                        secondary={
                          <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                            <Chip 
                              label={alert.severity || 'N/A'} 
                              size="small" 
                              color={alert.severity === 'critical' ? 'error' : alert.severity === 'high' ? 'warning' : 'default'}
                            />
                            <Chip 
                              label={alert.case_status || alert.status || 'N/A'} 
                              size="small" 
                              variant="outlined"
                            />
                          </Box>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          )}

          {/* Eventos Vinculados */}
          {linkedEvents.length > 0 && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <AlertIcon color="info" />
                  <Typography variant="h6">
                    Eventos Vinculados ({linkedEvents.length})
                  </Typography>
                </Box>
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="caption">
                    Eventos relacionados a este caso, úteis para análise forense e contexto adicional.
                  </Typography>
                </Alert>
                <List dense>
                  {linkedEvents.map((event, index) => (
                    <ListItem key={event.id || index} sx={{ bgcolor: 'background.default', borderRadius: 1, mb: 0.5 }}>
                      <ListItemText 
                        primary={event.type || event.description || `Evento ${index + 1}`}
                        secondary={
                          <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                            <Chip 
                              label={event.severity || 'N/A'} 
                              size="small" 
                              color={event.severity === 'critical' ? 'error' : event.severity === 'high' ? 'warning' : 'default'}
                            />
                            {event.source && (
                              <Chip 
                                label={event.source} 
                                size="small" 
                                variant="outlined"
                              />
                            )}
                          </Box>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          )}

          {/* Relacionamentos */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                🔗 Relacionamentos
              </Typography>
              
              {caseData.relatedAlerts && caseData.relatedAlerts.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="caption" color="text.secondary">
                    Alertas Relacionados
                  </Typography>
                  <List dense>
                    {caseData.relatedAlerts.map((alert) => (
                      <ListItem key={alert}>
                        <ListItemText primary={alert} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              )}

              {caseData.relatedPlaybooks && caseData.relatedPlaybooks.length > 0 && (
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    Playbooks Executados
                  </Typography>
                  <List dense>
                    {caseData.relatedPlaybooks.map((playbook) => (
                      <ListItem key={playbook}>
                        <ListItemText primary={playbook} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              )}
            </CardContent>
          </Card>

          {/* Checklist */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                ✅ Checklist
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Adicionar item..."
                  value={newChecklistItem}
                  onChange={(e) => setNewChecklistItem(e.target.value)}
                />
                <Button variant="contained" size="small" startIcon={<AddIcon />} onClick={handleAddChecklistItem}>
                  Adicionar
                </Button>
              </Box>
              {checklistItems.length > 0 ? (
                <List dense>
                  {checklistItems.map((item) => (
                    <ListItem
                      key={item.id}
                      secondaryAction={
                        <IconButton edge="end" onClick={() => handleDeleteChecklistItem(item.id)}>
                          <DeleteIcon />
                        </IconButton>
                      }
                    >
                      <Checkbox
                        checked={item.status === 'done'}
                        onChange={() => handleToggleChecklistItem(item)}
                      />
                      <ListItemText
                        primary={item.text}
                        secondary={item.completed_at ? `Concluído em ${formatDate(item.completed_at)}` : undefined}
                      />
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Alert severity="info">Nenhum item no checklist.</Alert>
              )}
            </CardContent>
          </Card>

          {/* Playbooks */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                🤖 Playbooks
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="ID do playbook..."
                  value={newPlaybookId}
                  onChange={(e) => setNewPlaybookId(e.target.value)}
                />
                <Button variant="contained" size="small" startIcon={<AddIcon />} onClick={handleAddPlaybook}>
                  Vincular
                </Button>
              </Box>
              {playbooks.length > 0 ? (
                <List dense>
                  {playbooks.map((pb) => (
                    <ListItem
                      key={pb}
                      secondaryAction={
                        <Box sx={{ display: 'flex', gap: 1 }}>
                          <IconButton edge="end" onClick={() => handleExecutePlaybook(pb)}>
                            <PlayIcon />
                          </IconButton>
                          <IconButton edge="end" onClick={() => handleDeletePlaybook(pb)}>
                            <DeleteIcon />
                          </IconButton>
                        </Box>
                      }
                    >
                      <ListItemText primary={pb} />
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Alert severity="info">Nenhum playbook vinculado.</Alert>
              )}
            </CardContent>
          </Card>

          {/* Adicionar Comentário */}
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                💬 Adicionar Comentário
              </Typography>
              <TextField
                fullWidth
                multiline
                rows={4}
                value={commentText}
                onChange={(e) => setCommentText(e.target.value)}
                placeholder="Escreva seu comentário..."
                disabled={submittingComment}
                sx={{ mb: 2 }}
              />
              <Button
                fullWidth
                variant="contained"
                startIcon={<SendIcon />}
                onClick={handleAddComment}
                disabled={submittingComment || !commentText.trim()}
              >
                {submittingComment ? 'Enviando...' : 'Enviar Comentário'}
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Modal de Edição do Caso */}
      <Dialog 
        open={editDialogOpen} 
        onClose={handleCloseEditDialog}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <EditIcon color="primary" />
            Editar Caso #{caseData?.id?.substring(0, 8)}
          </Box>
          <IconButton onClick={handleCloseEditDialog} size="small">
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent dividers>
          <Grid container spacing={3} sx={{ mt: 1 }}>
            {/* Título */}
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Título"
                value={editForm.title}
                onChange={handleEditFormChange('title')}
                required
              />
            </Grid>

            {/* Descrição */}
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Descrição"
                value={editForm.description}
                onChange={handleEditFormChange('description')}
                multiline
                rows={4}
              />
            </Grid>

            {/* Severidade e Prioridade */}
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Severidade</InputLabel>
                <Select
                  value={editForm.severity}
                  onChange={handleEditFormChange('severity')}
                  label="Severidade"
                >
                  <MenuItem value="critical">Crítica</MenuItem>
                  <MenuItem value="high">Alta</MenuItem>
                  <MenuItem value="medium">Média</MenuItem>
                  <MenuItem value="low">Baixa</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Prioridade</InputLabel>
                <Select
                  value={editForm.priority}
                  onChange={handleEditFormChange('priority')}
                  label="Prioridade"
                >
                  <MenuItem value="critical">Crítica</MenuItem>
                  <MenuItem value="high">Alta</MenuItem>
                  <MenuItem value="medium">Média</MenuItem>
                  <MenuItem value="low">Baixa</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            {/* Status e Categoria */}
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Status</InputLabel>
                <Select
                  value={editForm.status}
                  onChange={handleEditFormChange('status')}
                  label="Status"
                >
                  <MenuItem value="new">Novo</MenuItem>
                  <MenuItem value="in_progress">Em Progresso</MenuItem>
                  <MenuItem value="resolved">Resolvido</MenuItem>
                  <MenuItem value="closed">Fechado</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Categoria"
                value={editForm.category}
                onChange={handleEditFormChange('category')}
              />
            </Grid>

            {/* Atribuído a */}
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Atribuído a</InputLabel>
                <Select
                  value={editForm.assignedTo}
                  onChange={handleEditFormChange('assignedTo')}
                  label="Atribuído a"
                >
                  <MenuItem value="">
                    <em>Não atribuído</em>
                  </MenuItem>
                  {analysts.map((analyst) => (
                    <MenuItem key={analyst.id} value={analyst.username}>
                      <Box sx={{ display: 'flex', flexDirection: 'column' }}>
                        <Typography variant="body1">
                          {analyst.full_name || analyst.username}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {analyst.email} • {analyst.role_name || analyst.role_id}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button 
            onClick={handleCloseEditDialog} 
            color="inherit"
            disabled={saving}
          >
            Cancelar
          </Button>
          <Button 
            onClick={handleSaveCase}
            variant="contained"
            startIcon={saving ? <CircularProgress size={20} /> : <SaveIcon />}
            disabled={saving || !editForm.title.trim()}
          >
            {saving ? 'Salvando...' : 'Salvar Alterações'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Dialog de Confirmação de Mudança de Status com Propagação */}
      <Dialog 
        open={statusDialogOpen} 
        onClose={() => setStatusDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SyncIcon color="primary" />
          Atualizar Status do Caso
        </DialogTitle>
        <DialogContent dividers>
          <Alert severity="warning" sx={{ mb: 3 }}>
            <Typography variant="body2">
              Este caso possui <strong>{linkedAlerts.length} alertas vinculados</strong>. 
              Você pode propagar a mudança de status para eles.
            </Typography>
          </Alert>

          <Box sx={{ mb: 3 }}>
            <Typography variant="subtitle2" gutterBottom>
              Novo Status:
            </Typography>
            <Chip 
              label={newStatus === 'in_progress' ? 'Em Progresso' : 
                     newStatus === 'resolved' ? 'Resolvido' : 
                     newStatus === 'closed' ? 'Fechado' : 'Novo'}
              color={newStatus === 'in_progress' ? 'warning' : 
                     newStatus === 'resolved' ? 'success' : 
                     newStatus === 'closed' ? 'default' : 'info'}
            />
          </Box>

          <Box sx={{ mb: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              Opções de Propagação:
            </Typography>
            <FormControl component="fieldset">
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input 
                    type="checkbox" 
                    checked={propagateToAlerts}
                    onChange={(e) => setPropagateToAlerts(e.target.checked)}
                    style={{ marginRight: 8 }}
                  />
                  <Typography variant="body2">
                    Propagar para Alertas Vinculados ({linkedAlerts.length})
                  </Typography>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input 
                    type="checkbox" 
                    checked={propagateToEvents}
                    onChange={(e) => setPropagateToEvents(e.target.checked)}
                    style={{ marginRight: 8 }}
                  />
                  <Typography variant="body2">
                    Propagar para Eventos Vinculados
                  </Typography>
                </label>
              </Box>
            </FormControl>
          </Box>

          <TextField
            fullWidth
            label="Comentário (opcional)"
            value={statusComment}
            onChange={(e) => setStatusComment(e.target.value)}
            multiline
            rows={2}
            placeholder="Motivo da mudança de status..."
          />
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button 
            onClick={() => {
              setStatusDialogOpen(false);
              setEditingStatus(false);
            }} 
            color="inherit"
          >
            Cancelar
          </Button>
          <Button 
            onClick={handleConfirmStatusUpdate}
            variant="contained"
            startIcon={<SyncIcon />}
          >
            Confirmar Atualização
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default CaseDetails;

