import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  IconButton,
  Tooltip,
  LinearProgress,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Undo as UndoIcon,
  Info as InfoIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  PlayArrow as PlayArrowIcon,
  Schedule as ScheduleIcon,
  ThumbUp as ThumbUpIcon,
  ThumbDown as ThumbDownIcon,
  AutoFixHigh as AutoFixHighIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  TrendingUp as TrendingUpIcon,
} from '@mui/icons-material';
import { cspmAPI } from '../services/api';

const CSPMRemediation = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Data states
  const [rules, setRules] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [statistics, setStatistics] = useState(null);
  
  // Dialog states
  const [selectedRule, setSelectedRule] = useState(null);
  const [selectedExecution, setSelectedExecution] = useState(null);
  const [selectedApproval, setSelectedApproval] = useState(null);
  const [approvalDialog, setApprovalDialog] = useState(false);
  const [approvalComment, setApprovalComment] = useState('');
  const [rejectionReason, setRejectionReason] = useState('');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [rulesRes, executionsRes, approvalsRes, statsRes] = await Promise.all([
        cspmAPI.remediation.getRules(),
        cspmAPI.remediation.getExecutions(),
        cspmAPI.remediation.getApprovals(),
        cspmAPI.remediation.getStatistics(),
      ]);
      
      setRules(rulesRes.data.rules || []);
      setExecutions(executionsRes.data.executions || []);
      setApprovals(approvalsRes.data.approvals || []);
      setStatistics(statsRes.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao carregar dados');
      console.error('Erro ao carregar dados:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async () => {
    if (!selectedApproval) return;
    
    try {
      await cspmAPI.remediation.approve(selectedApproval.id, {
        approved_by: 'admin@company.com', // TODO: Get from auth context
        comment: approvalComment,
      });
      
      setApprovalDialog(false);
      setApprovalComment('');
      setSelectedApproval(null);
      loadData();
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao aprovar remediação');
    }
  };

  const handleReject = async () => {
    if (!selectedApproval) return;
    
    try {
      await cspmAPI.remediation.reject(selectedApproval.id, {
        rejected_by: 'admin@company.com', // TODO: Get from auth context
        reason: rejectionReason,
      });
      
      setApprovalDialog(false);
      setRejectionReason('');
      setSelectedApproval(null);
      loadData();
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao rejeitar remediação');
    }
  };

  const handleRollback = async (executionId) => {
    if (!window.confirm('Tem certeza que deseja fazer rollback desta remediação?')) {
      return;
    }
    
    try {
      await cspmAPI.remediation.rollback(executionId);
      loadData();
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao fazer rollback');
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'error',
      high: 'warning',
      medium: 'info',
      low: 'default',
    };
    return colors[severity] || 'default';
  };

  const getStatusColor = (status) => {
    const colors = {
      pending: 'warning',
      approved: 'success',
      rejected: 'error',
      running: 'info',
      completed: 'success',
      failed: 'error',
      rolled_back: 'default',
    };
    return colors[status] || 'default';
  };

  const getStatusIcon = (status) => {
    const icons = {
      pending: <ScheduleIcon />,
      approved: <ThumbUpIcon />,
      rejected: <ThumbDownIcon />,
      running: <PlayArrowIcon />,
      completed: <CheckCircleIcon />,
      failed: <ErrorIcon />,
      rolled_back: <UndoIcon />,
    };
    return icons[status] || <InfoIcon />;
  };

  const formatDuration = (seconds) => {
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}m ${secs}s`;
  };

  // Statistics Cards
  const renderStatistics = () => {
    if (!statistics) return null;

    return (
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <AutoFixHighIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">Total Execuções</Typography>
              </Box>
              <Typography variant="h3">{statistics.total_executions}</Typography>
              <Typography variant="body2" color="text.secondary">
                {statistics.successful_executions} bem-sucedidas
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <SpeedIcon sx={{ mr: 1, color: 'success.main' }} />
                <Typography variant="h6">Taxa de Sucesso</Typography>
              </Box>
              <Typography variant="h3">{statistics.success_rate?.toFixed(1)}%</Typography>
              <Typography variant="body2" color="text.secondary">
                Avg: {formatDuration(statistics.avg_execution_time)}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <ScheduleIcon sx={{ mr: 1, color: 'warning.main' }} />
                <Typography variant="h6">Aprovações Pendentes</Typography>
              </Box>
              <Typography variant="h3">{statistics.pending_approvals}</Typography>
              <Typography variant="body2" color="text.secondary">
                {statistics.auto_approved} auto-aprovadas
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <TrendingUpIcon sx={{ mr: 1, color: 'info.main' }} />
                <Typography variant="h6">Tempo Economizado</Typography>
              </Box>
              <Typography variant="h3">{statistics.total_time_saved}h</Typography>
              <Typography variant="body2" color="text.secondary">
                {statistics.rolled_back} rollbacks
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    );
  };

  // Rules Tab
  const renderRulesTab = () => (
    <TableContainer component={Paper}>
      <Box sx={{ p: 2, mb: 2 }}>
        <Alert severity="info">
          <Typography variant="body2" fontWeight="bold" gutterBottom>
            Regras de Remediação Automática
          </Typography>
          <Typography variant="body2">
            As regras de remediação são pré-configuradas no sistema para garantir segurança e compliance.
            Cada regra define quando e como um finding será automaticamente remediado.
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            <strong>Como funciona:</strong>
          </Typography>
          <List dense sx={{ pl: 2 }}>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="1. Um finding é detectado (ex: S3 bucket público)" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="2. A regra correspondente é acionada automaticamente" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="3. Se auto_approve=true: Remedia imediatamente" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="4. Se auto_approve=false: Cria solicitação de aprovação" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="5. Após execução: Pode fazer rollback se necessário" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
          </List>
        </Alert>
      </Box>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>Regra</TableCell>
            <TableCell>Finding Type</TableCell>
            <TableCell>Severidade</TableCell>
            <TableCell>Auto-Approve</TableCell>
            <TableCell>Ações</TableCell>
            <TableCell>Notificações</TableCell>
            <TableCell align="center">Detalhes</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rules.map((rule) => (
            <TableRow key={rule.id}>
              <TableCell>
                <Typography variant="body2" fontWeight="bold">
                  {rule.name}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {rule.description}
                </Typography>
              </TableCell>
              <TableCell>
                <Chip label={rule.finding_type} size="small" />
              </TableCell>
              <TableCell>
                {rule.severity?.map((sev) => (
                  <Chip
                    key={sev}
                    label={sev}
                    size="small"
                    color={getSeverityColor(sev)}
                    sx={{ mr: 0.5 }}
                  />
                ))}
              </TableCell>
              <TableCell>
                {rule.auto_approve ? (
                  <Chip icon={<CheckCircleIcon />} label="Sim" color="success" size="small" />
                ) : (
                  <Chip icon={<WarningIcon />} label="Não" color="warning" size="small" />
                )}
              </TableCell>
              <TableCell>
                <Typography variant="caption">
                  {rule.actions?.length || 0} ações
                </Typography>
              </TableCell>
              <TableCell>
                {rule.notify_channels?.map((notif) => (
                  <Chip key={notif} label={notif} size="small" sx={{ mr: 0.5 }} />
                ))}
              </TableCell>
              <TableCell align="center">
                <Tooltip title="Ver detalhes">
                  <IconButton size="small" onClick={() => setSelectedRule(rule)}>
                    <InfoIcon />
                  </IconButton>
                </Tooltip>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  // Executions Tab
  const renderExecutionsTab = () => (
    <TableContainer component={Paper}>
      <Box sx={{ p: 2, mb: 2 }}>
        <Alert severity="info">
          <Typography variant="body2" fontWeight="bold" gutterBottom>
            Execuções de Remediação
          </Typography>
          <Typography variant="body2">
            As execuções representam tentativas de remediação automática de findings de segurança.
            Cada execução mostra o progresso, status e permite fazer rollback se necessário.
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            <strong>Status possíveis:</strong>
          </Typography>
          <List dense sx={{ pl: 2 }}>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="• Pending: Aguardando aprovação" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="• Running: Executando ações de remediação" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="• Completed: Remediação concluída com sucesso" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="• Failed: Erro durante a execução" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="• Rolled Back: Remediação revertida" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
          </List>
        </Alert>
      </Box>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>ID</TableCell>
            <TableCell>Regra</TableCell>
            <TableCell>Recurso</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Progresso</TableCell>
            <TableCell>Duração</TableCell>
            <TableCell>Executado Por</TableCell>
            <TableCell align="center">Ações</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {executions.map((exec) => (
            <TableRow key={exec.id}>
              <TableCell>
                <Typography variant="caption" fontFamily="monospace">
                  {exec.id}
                </Typography>
              </TableCell>
              <TableCell>{exec.rule_name}</TableCell>
              <TableCell>
                <Typography variant="body2">{exec.resource_id}</Typography>
                <Typography variant="caption" color="text.secondary">
                  {exec.resource_type}
                </Typography>
              </TableCell>
              <TableCell>
                <Chip
                  icon={getStatusIcon(exec.status)}
                  label={exec.status}
                  color={getStatusColor(exec.status)}
                  size="small"
                />
              </TableCell>
              <TableCell sx={{ minWidth: 150 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <Box sx={{ width: '100%', mr: 1 }}>
                    <LinearProgress
                      variant="determinate"
                      value={(exec.completed_actions / exec.total_actions) * 100}
                      color={getStatusColor(exec.status)}
                    />
                  </Box>
                  <Typography variant="caption">
                    {exec.completed_actions}/{exec.total_actions}
                  </Typography>
                </Box>
              </TableCell>
              <TableCell>
                {exec.duration ? formatDuration(exec.duration) : '-'}
              </TableCell>
              <TableCell>{exec.executed_by}</TableCell>
              <TableCell align="center">
                <Tooltip title="Ver detalhes">
                  <IconButton size="small" onClick={() => setSelectedExecution(exec)}>
                    <InfoIcon />
                  </IconButton>
                </Tooltip>
                {exec.status === 'completed' && exec.rollback_available && !exec.rolled_back && (
                  <Tooltip title="Rollback">
                    <IconButton
                      size="small"
                      color="warning"
                      onClick={() => handleRollback(exec.id)}
                    >
                      <UndoIcon />
                    </IconButton>
                  </Tooltip>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  // Approvals Tab
  const renderApprovalsTab = () => (
    <TableContainer component={Paper}>
      <Box sx={{ p: 2, mb: 2 }}>
        <Alert severity="warning">
          <Typography variant="body2" fontWeight="bold" gutterBottom>
            Aprovações de Remediação
          </Typography>
          <Typography variant="body2">
            Algumas remediações requerem aprovação manual devido ao seu impacto potencial (ex: downtime, alterações críticas).
            Você pode aprovar ou rejeitar cada solicitação após revisar a análise de impacto.
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            <strong>Quando uma aprovação é necessária:</strong>
          </Typography>
          <List dense sx={{ pl: 2 }}>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="• Remediações que causam downtime (ex: criptografia de EBS/RDS)" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="• Alterações em recursos críticos de produção" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="• Ações que afetam múltiplos serviços ou usuários" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
            <ListItem sx={{ py: 0 }}>
              <ListItemText 
                primary="• Mudanças com risco classificado como MEDIUM ou HIGH" 
                primaryTypographyProps={{ variant: 'body2' }}
              />
            </ListItem>
          </List>
          <Typography variant="body2" sx={{ mt: 1 }}>
            <strong>Ações disponíveis:</strong> Clique nos botões 👍 (Aprovar) ou 👎 (Rejeitar) para cada solicitação.
          </Typography>
        </Alert>
      </Box>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>ID</TableCell>
            <TableCell>Execution ID</TableCell>
            <TableCell>Regra</TableCell>
            <TableCell>Recurso</TableCell>
            <TableCell>Impacto</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Solicitado Por</TableCell>
            <TableCell>Expira Em</TableCell>
            <TableCell align="center">Ações</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {approvals.map((approval) => (
            <TableRow key={approval.id}>
              <TableCell>
                <Typography variant="caption" fontFamily="monospace">
                  {approval.id}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="caption" fontFamily="monospace">
                  {approval.execution_id}
                </Typography>
              </TableCell>
              <TableCell>{approval.rule_name}</TableCell>
              <TableCell>
                <Typography variant="body2">{approval.resource_id}</Typography>
              </TableCell>
              <TableCell>
                <Chip
                  label={approval.impact_analysis?.risk_level || 'unknown'}
                  color={getSeverityColor(approval.impact_analysis?.risk_level)}
                  size="small"
                />
                {approval.impact_analysis?.downtime_expected && (
                  <Tooltip title={`Downtime: ${approval.impact_analysis.downtime_duration} min`}>
                    <WarningIcon fontSize="small" color="warning" sx={{ ml: 1 }} />
                  </Tooltip>
                )}
              </TableCell>
              <TableCell>
                <Chip
                  icon={getStatusIcon(approval.status)}
                  label={approval.status}
                  color={getStatusColor(approval.status)}
                  size="small"
                />
              </TableCell>
              <TableCell>{approval.requested_by}</TableCell>
              <TableCell>
                <Typography variant="caption">
                  {new Date(approval.expires_at).toLocaleString()}
                </Typography>
              </TableCell>
              <TableCell align="center">
                <Tooltip title="Ver detalhes">
                  <IconButton
                    size="small"
                    onClick={() => {
                      setSelectedApproval(approval);
                      setApprovalDialog(true);
                    }}
                  >
                    <InfoIcon />
                  </IconButton>
                </Tooltip>
                {approval.status === 'pending' && (
                  <>
                    <Tooltip title="Aprovar">
                      <IconButton
                        size="small"
                        color="success"
                        onClick={() => {
                          setSelectedApproval(approval);
                          setApprovalDialog(true);
                        }}
                      >
                        <ThumbUpIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Rejeitar">
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => {
                          setSelectedApproval(approval);
                          setApprovalDialog(true);
                        }}
                      >
                        <ThumbDownIcon />
                      </IconButton>
                    </Tooltip>
                  </>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  // Rule Details Dialog
  const renderRuleDetailsDialog = () => (
    <Dialog
      open={!!selectedRule}
      onClose={() => setSelectedRule(null)}
      maxWidth="md"
      fullWidth
    >
      {selectedRule && (
        <>
          <DialogTitle>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <SecurityIcon sx={{ mr: 1 }} />
              {selectedRule.name}
            </Box>
          </DialogTitle>
          <DialogContent>
            <Typography variant="body2" color="text.secondary" paragraph>
              {selectedRule.description}
            </Typography>

            <Divider sx={{ my: 2 }} />

            <Typography variant="h6" gutterBottom>
              Configuração
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Finding Type:
                </Typography>
                <Chip label={selectedRule.finding_type} size="small" />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Auto-Approve:
                </Typography>
                <Chip
                  label={selectedRule.auto_approve ? 'Sim' : 'Não'}
                  color={selectedRule.auto_approve ? 'success' : 'warning'}
                  size="small"
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Max Retries:
                </Typography>
                <Typography variant="body1">{selectedRule.max_retries}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Timeout:
                </Typography>
                <Typography variant="body1">{selectedRule.timeout}s</Typography>
              </Grid>
            </Grid>

            <Divider sx={{ my: 2 }} />

            <Typography variant="h6" gutterBottom>
              Ações ({selectedRule.actions?.length || 0})
            </Typography>
            <List dense>
              {selectedRule.actions?.map((action, idx) => (
                <ListItem key={idx}>
                  <ListItemIcon>
                    <PlayArrowIcon />
                  </ListItemIcon>
                  <ListItemText
                    primary={action.action}
                    secondary={action.description}
                  />
                </ListItem>
              ))}
            </List>

            {selectedRule.rollback_actions && selectedRule.rollback_actions.length > 0 && (
              <>
                <Divider sx={{ my: 2 }} />
                <Typography variant="h6" gutterBottom>
                  Ações de Rollback ({selectedRule.rollback_actions.length})
                </Typography>
                <List dense>
                  {selectedRule.rollback_actions.map((action, idx) => (
                    <ListItem key={idx}>
                      <ListItemIcon>
                        <UndoIcon />
                      </ListItemIcon>
                      <ListItemText
                        primary={action.action}
                        secondary={action.description}
                      />
                    </ListItem>
                  ))}
                </List>
              </>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setSelectedRule(null)}>Fechar</Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );

  // Execution Details Dialog
  const renderExecutionDetailsDialog = () => (
    <Dialog
      open={!!selectedExecution}
      onClose={() => setSelectedExecution(null)}
      maxWidth="md"
      fullWidth
    >
      {selectedExecution && (
        <>
          <DialogTitle>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <AutoFixHighIcon sx={{ mr: 1 }} />
                Execution Details
              </Box>
              <Chip
                icon={getStatusIcon(selectedExecution.status)}
                label={selectedExecution.status}
                color={getStatusColor(selectedExecution.status)}
              />
            </Box>
          </DialogTitle>
          <DialogContent>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Execution ID:
                </Typography>
                <Typography variant="body1" fontFamily="monospace">
                  {selectedExecution.id}
                </Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Regra:
                </Typography>
                <Typography variant="body1">{selectedExecution.rule_name}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Recurso:
                </Typography>
                <Typography variant="body1">{selectedExecution.resource_id}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Tipo:
                </Typography>
                <Typography variant="body1">{selectedExecution.resource_type}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Executado Por:
                </Typography>
                <Typography variant="body1">{selectedExecution.executed_by}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Duração:
                </Typography>
                <Typography variant="body1">
                  {selectedExecution.duration ? formatDuration(selectedExecution.duration) : '-'}
                </Typography>
              </Grid>
            </Grid>

            <Divider sx={{ my: 2 }} />

            <Typography variant="h6" gutterBottom>
              Progresso
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <Box sx={{ width: '100%', mr: 1 }}>
                <LinearProgress
                  variant="determinate"
                  value={(selectedExecution.completed_actions / selectedExecution.total_actions) * 100}
                  color={getStatusColor(selectedExecution.status)}
                />
              </Box>
              <Typography variant="body2">
                {selectedExecution.completed_actions}/{selectedExecution.total_actions}
              </Typography>
            </Box>

            {selectedExecution.error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {selectedExecution.error}
              </Alert>
            )}

            {selectedExecution.impact_analysis && (
              <>
                <Divider sx={{ my: 2 }} />
                <Typography variant="h6" gutterBottom>
                  Análise de Impacto
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Nível de Risco:
                    </Typography>
                    <Chip
                      label={selectedExecution.impact_analysis.risk_level}
                      color={getSeverityColor(selectedExecution.impact_analysis.risk_level)}
                      size="small"
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Downtime Esperado:
                    </Typography>
                    <Typography variant="body1">
                      {selectedExecution.impact_analysis.downtime_expected
                        ? `Sim (${selectedExecution.impact_analysis.downtime_duration} min)`
                        : 'Não'}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary">
                      Impacto no Negócio:
                    </Typography>
                    <Typography variant="body1">
                      {selectedExecution.impact_analysis.business_impact}
                    </Typography>
                  </Grid>
                </Grid>
              </>
            )}
          </DialogContent>
          <DialogActions>
            {selectedExecution.status === 'completed' &&
              selectedExecution.rollback_available &&
              !selectedExecution.rolled_back && (
                <Button
                  startIcon={<UndoIcon />}
                  color="warning"
                  onClick={() => {
                    handleRollback(selectedExecution.id);
                    setSelectedExecution(null);
                  }}
                >
                  Rollback
                </Button>
              )}
            <Button onClick={() => setSelectedExecution(null)}>Fechar</Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );

  // Approval Dialog
  const renderApprovalDialog = () => (
    <Dialog
      open={approvalDialog}
      onClose={() => {
        setApprovalDialog(false);
        setApprovalComment('');
        setRejectionReason('');
      }}
      maxWidth="md"
      fullWidth
    >
      {selectedApproval && (
        <>
          <DialogTitle>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <ScheduleIcon sx={{ mr: 1 }} />
              Aprovação de Remediação
            </Box>
          </DialogTitle>
          <DialogContent>
            <Alert severity="warning" sx={{ mb: 2 }}>
              Esta remediação requer aprovação manual devido ao seu impacto potencial.
            </Alert>

            <Typography variant="h6" gutterBottom>
              Detalhes da Remediação
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Regra:
                </Typography>
                <Typography variant="body1">{selectedApproval.rule_name}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Recurso:
                </Typography>
                <Typography variant="body1">{selectedApproval.resource_id}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Solicitado Por:
                </Typography>
                <Typography variant="body1">{selectedApproval.requested_by}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="text.secondary">
                  Expira Em:
                </Typography>
                <Typography variant="body1">
                  {new Date(selectedApproval.expires_at).toLocaleString()}
                </Typography>
              </Grid>
            </Grid>

            {selectedApproval.impact_analysis && (
              <>
                <Divider sx={{ my: 2 }} />
                <Typography variant="h6" gutterBottom>
                  Análise de Impacto
                </Typography>
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Nível de Risco:
                    </Typography>
                    <Chip
                      label={selectedApproval.impact_analysis.risk_level}
                      color={getSeverityColor(selectedApproval.impact_analysis.risk_level)}
                      size="small"
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Downtime Esperado:
                    </Typography>
                    <Typography variant="body1">
                      {selectedApproval.impact_analysis.downtime_expected
                        ? `Sim (${selectedApproval.impact_analysis.downtime_duration} min)`
                        : 'Não'}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary">
                      Impacto no Negócio:
                    </Typography>
                    <Typography variant="body1">
                      {selectedApproval.impact_analysis.business_impact}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary">
                      Recursos Afetados:
                    </Typography>
                    <Typography variant="body1">
                      {selectedApproval.impact_analysis.affected_resources?.join(', ') || 'N/A'}
                    </Typography>
                  </Grid>
                </Grid>
              </>
            )}

            <Divider sx={{ my: 2 }} />

            {selectedApproval.status === 'pending' && (
              <>
                <TextField
                  fullWidth
                  multiline
                  rows={3}
                  label="Comentário (para aprovação)"
                  value={approvalComment}
                  onChange={(e) => setApprovalComment(e.target.value)}
                  sx={{ mb: 2 }}
                />
                <TextField
                  fullWidth
                  multiline
                  rows={3}
                  label="Motivo da Rejeição"
                  value={rejectionReason}
                  onChange={(e) => setRejectionReason(e.target.value)}
                />
              </>
            )}
          </DialogContent>
          <DialogActions>
            {selectedApproval.status === 'pending' && (
              <>
                <Button
                  startIcon={<ThumbDownIcon />}
                  color="error"
                  onClick={handleReject}
                  disabled={!rejectionReason}
                >
                  Rejeitar
                </Button>
                <Button
                  startIcon={<ThumbUpIcon />}
                  color="success"
                  variant="contained"
                  onClick={handleApprove}
                >
                  Aprovar
                </Button>
              </>
            )}
            <Button
              onClick={() => {
                setApprovalDialog(false);
                setApprovalComment('');
                setRejectionReason('');
              }}
            >
              Fechar
            </Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Auto-Remediation
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Remediação automática de findings de segurança
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
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {loading && <LinearProgress sx={{ mb: 3 }} />}

      {renderStatistics()}

      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label={`Regras (${rules.length})`} />
          <Tab label={`Execuções (${executions.length})`} />
          <Tab label={`Aprovações (${approvals.length})`} />
        </Tabs>
      </Paper>

      {activeTab === 0 && renderRulesTab()}
      {activeTab === 1 && renderExecutionsTab()}
      {activeTab === 2 && renderApprovalsTab()}

      {renderRuleDetailsDialog()}
      {renderExecutionDetailsDialog()}
      {renderApprovalDialog()}
    </Box>
  );
};

export default CSPMRemediation;

