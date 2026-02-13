import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Box,
  Alert,
  CircularProgress,
  Autocomplete,
  Divider,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  PersonAdd as PersonAddIcon,
} from '@mui/icons-material';
import { usersAPI } from '../services/api';

// Available skills options
const AVAILABLE_SKILLS = [
  { id: 'alert_analysis', label: 'Análise de Alertas' },
  { id: 'incident_response', label: 'Resposta a Incidentes' },
  { id: 'threat_hunting', label: 'Threat Hunting' },
  { id: 'forensics', label: 'Forense Digital' },
  { id: 'log_analysis', label: 'Análise de Logs' },
  { id: 'malware_analysis', label: 'Análise de Malware' },
  { id: 'network_analysis', label: 'Análise de Rede' },
  { id: 'vulnerability_assessment', label: 'Avaliação de Vulnerabilidades' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'management', label: 'Gestão' },
  { id: 'monitoring', label: 'Monitoramento' },
  { id: 'automation', label: 'Automação' },
  { id: 'cloud_security', label: 'Segurança em Nuvem' },
];

// Available specializations options
const AVAILABLE_SPECIALIZATIONS = [
  { id: 'siem', label: 'SIEM' },
  { id: 'security_operations', label: 'Operações de Segurança (SOC)' },
  { id: 'monitoring', label: 'Monitoramento' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'audit', label: 'Auditoria' },
  { id: 'pci_dss', label: 'PCI-DSS' },
  { id: 'financial_security', label: 'Segurança Financeira' },
  { id: 'network_security', label: 'Segurança de Rede' },
  { id: 'endpoint_security', label: 'Segurança de Endpoint' },
  { id: 'cloud_security', label: 'Segurança em Nuvem' },
  { id: 'identity_management', label: 'Gestão de Identidade' },
  { id: 'data_protection', label: 'Proteção de Dados' },
  { id: 'threat_intelligence', label: 'Inteligência de Ameaças' },
  { id: 'general', label: 'Geral' },
];

function Users() {
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Dialog states
  const [openDialog, setOpenDialog] = useState(false);
  const [dialogMode, setDialogMode] = useState('create'); // 'create' or 'edit'
  const [selectedUser, setSelectedUser] = useState(null);
  
  // Form states
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    password: '',
    role_id: 'analyst',
    is_active: true,
    skills: [],
    specializations: [],
  });

  useEffect(() => {
    loadUsers();
    loadRoles();
  }, []);

  const loadUsers = async () => {
    try {
      setLoading(true);
      const response = await usersAPI.list();
      setUsers(response.data.users || []);
    } catch (err) {
      setError('Erro ao carregar usuários');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadRoles = async () => {
    try {
      const response = await usersAPI.getRoles();
      setRoles(response.data.roles || []);
    } catch (err) {
      console.error('Erro ao carregar roles:', err);
      // Fallback roles
      setRoles([
        { id: 'admin', name: 'Administrador' },
        { id: 'analyst', name: 'Analista' },
        { id: 'viewer', name: 'Visualizador' },
      ]);
    }
  };

  const handleOpenDialog = (mode, user = null) => {
    setDialogMode(mode);
    setSelectedUser(user);
    
    if (mode === 'edit' && user) {
      setFormData({
        username: user.username,
        email: user.email,
        full_name: user.full_name || '',
        password: '',
        role_id: user.role_id || 'analyst',
        is_active: user.is_active !== false,
        skills: user.skills || [],
        specializations: user.specializations || [],
      });
    } else {
      setFormData({
        username: '',
        email: '',
        full_name: '',
        password: '',
        role_id: 'analyst',
        is_active: true,
        skills: [],
        specializations: [],
      });
    }
    
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setSelectedUser(null);
    setError('');
  };

  const handleSubmit = async () => {
    try {
      setError('');
      
      if (dialogMode === 'create') {
        await usersAPI.create(formData);
        setSuccess('Usuário criado com sucesso!');
      } else {
        const updateData = { ...formData };
        if (!updateData.password) {
          delete updateData.password; // Não atualizar senha se vazio
        }
        await usersAPI.update(selectedUser.id, updateData);
        setSuccess('Usuário atualizado com sucesso!');
      }
      
      handleCloseDialog();
      loadUsers();
      
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao salvar usuário');
    }
  };

  const handleDelete = async (userId) => {
    if (!window.confirm('Tem certeza que deseja deletar este usuário?')) {
      return;
    }
    
    try {
      await usersAPI.delete(userId);
      setSuccess('Usuário deletado com sucesso!');
      loadUsers();
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.response?.data?.error || 'Erro ao deletar usuário');
    }
  };

  const getRoleColor = (roleId) => {
    switch (roleId) {
      case 'admin':
        return 'error';
      case 'analyst':
        return 'primary';
      case 'banking':
        return 'warning';
      case 'viewer':
        return 'default';
      default:
        return 'default';
    }
  };

  // Informações sobre escopo de acesso por perfil
  const getRoleDescription = (roleId) => {
    switch (roleId) {
      case 'admin':
        return 'Acesso total ao sistema sem restrições.';
      case 'analyst':
        return 'Pode visualizar e gerenciar alertas e casos de todos os ambientes.';
      case 'banking':
        return 'Acesso restrito aos ambientes Banking: banking-prd (379334555230), banking-dev (039663229792), banking-hml (334931733882).';
      case 'viewer':
        return 'Apenas visualização, sem permissão para criar ou editar.';
      default:
        return '';
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Paper sx={{ p: 3 }}>
        {/* Header */}
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
          <Typography variant="h4" fontWeight="bold">
            Gerenciamento de Usuários
          </Typography>
          <Button
            variant="contained"
            startIcon={<PersonAddIcon />}
            onClick={() => handleOpenDialog('create')}
          >
            Novo Usuário
          </Button>
        </Box>

        {/* Alerts */}
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}
        {success && (
          <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>
            {success}
          </Alert>
        )}

        {/* Users Table */}
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Usuário</TableCell>
                <TableCell>Nome Completo</TableCell>
                <TableCell>Email</TableCell>
                <TableCell>Perfil</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Ações</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {users.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    Nenhum usuário encontrado
                  </TableCell>
                </TableRow>
              ) : (
                users.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell>{user.username}</TableCell>
                    <TableCell>{user.full_name || '-'}</TableCell>
                    <TableCell>{user.email}</TableCell>
                    <TableCell>
                      <Chip
                        label={user.role_name || user.role_id}
                        color={getRoleColor(user.role_id)}
                        size="small"
                        sx={{ textTransform: 'capitalize' }}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={user.is_active !== false ? 'Ativo' : 'Inativo'}
                        color={user.is_active !== false ? 'success' : 'default'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell align="right">
                      <IconButton
                        size="small"
                        onClick={() => handleOpenDialog('edit', user)}
                      >
                        <EditIcon />
                      </IconButton>
                      <IconButton
                        size="small"
                        onClick={() => handleDelete(user.id)}
                        color="error"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Create/Edit Dialog */}
      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          {dialogMode === 'create' ? 'Novo Usuário' : 'Editar Usuário'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 2 }}>
            <TextField
              label="Usuário"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              required
              fullWidth
              disabled={dialogMode === 'edit'}
            />
            
            <TextField
              label="Nome Completo"
              value={formData.full_name}
              onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
              fullWidth
            />
            
            <TextField
              label="Email"
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              required
              fullWidth
            />
            
            <TextField
              label={dialogMode === 'create' ? 'Senha' : 'Nova Senha (deixe vazio para manter)'}
              type="password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              required={dialogMode === 'create'}
              fullWidth
            />
            
            <FormControl fullWidth>
              <InputLabel>Perfil de Acesso</InputLabel>
              <Select
                value={formData.role_id}
                onChange={(e) => setFormData({ ...formData, role_id: e.target.value })}
                label="Perfil de Acesso"
              >
                {roles.map((role) => (
                  <MenuItem key={role.id} value={role.id}>
                    <Box>
                      <Typography variant="body1">{role.name}</Typography>
                      {role.description && (
                        <Typography variant="caption" color="text.secondary">
                          {role.description}
                        </Typography>
                      )}
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            
            {/* Descrição do perfil selecionado */}
            {formData.role_id && getRoleDescription(formData.role_id) && (
              <Alert 
                severity={formData.role_id === 'banking' ? 'warning' : 'info'} 
                sx={{ mt: 1 }}
              >
                <Typography variant="body2">
                  <strong>Escopo de Acesso:</strong> {getRoleDescription(formData.role_id)}
                </Typography>
              </Alert>
            )}
            
            <FormControl fullWidth>
              <InputLabel>Status</InputLabel>
              <Select
                value={formData.is_active}
                onChange={(e) => setFormData({ ...formData, is_active: e.target.value })}
                label="Status"
              >
                <MenuItem value={true}>Ativo</MenuItem>
                <MenuItem value={false}>Inativo</MenuItem>
              </Select>
            </FormControl>
            
            <Divider sx={{ my: 2 }} />
            <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
              Habilidades e Especializações (Triagem de Alertas)
            </Typography>
            
            <Autocomplete
              multiple
              options={AVAILABLE_SKILLS}
              getOptionLabel={(option) => {
                if (typeof option === 'string') {
                  const found = AVAILABLE_SKILLS.find(s => s.id === option);
                  return found ? found.label : option;
                }
                return option.label;
              }}
              value={formData.skills.map(id => AVAILABLE_SKILLS.find(s => s.id === id) || { id, label: id })}
              onChange={(event, newValue) => {
                setFormData({ 
                  ...formData, 
                  skills: newValue.map(v => typeof v === 'string' ? v : v.id) 
                });
              }}
              isOptionEqualToValue={(option, value) => option.id === (value?.id || value)}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Habilidades"
                  placeholder="Selecione as habilidades..."
                  helperText="Habilidades técnicas do analista para triagem de alertas"
                />
              )}
              renderTags={(value, getTagProps) =>
                value.map((option, index) => (
                  <Chip
                    size="small"
                    label={option?.label || option}
                    {...getTagProps({ index })}
                    key={option?.id || index}
                    color="primary"
                    variant="outlined"
                  />
                ))
              }
            />
            
            <Autocomplete
              multiple
              options={AVAILABLE_SPECIALIZATIONS}
              getOptionLabel={(option) => {
                if (typeof option === 'string') {
                  const found = AVAILABLE_SPECIALIZATIONS.find(s => s.id === option);
                  return found ? found.label : option;
                }
                return option.label;
              }}
              value={formData.specializations.map(id => AVAILABLE_SPECIALIZATIONS.find(s => s.id === id) || { id, label: id })}
              onChange={(event, newValue) => {
                setFormData({ 
                  ...formData, 
                  specializations: newValue.map(v => typeof v === 'string' ? v : v.id) 
                });
              }}
              isOptionEqualToValue={(option, value) => option.id === (value?.id || value)}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Especializações"
                  placeholder="Selecione as especializações..."
                  helperText="Áreas de especialização do analista"
                />
              )}
              renderTags={(value, getTagProps) =>
                value.map((option, index) => (
                  <Chip
                    size="small"
                    label={option?.label || option}
                    {...getTagProps({ index })}
                    key={option?.id || index}
                    color="secondary"
                    variant="outlined"
                  />
                ))
              }
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancelar</Button>
          <Button onClick={handleSubmit} variant="contained">
            {dialogMode === 'create' ? 'Criar' : 'Salvar'}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}

export default Users;
