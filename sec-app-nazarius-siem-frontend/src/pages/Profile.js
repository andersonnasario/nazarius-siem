import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  Alert,
  Snackbar,
  Divider,
  Card,
  CardContent,
  CardHeader,
  Avatar,
  Chip,
  Autocomplete,
} from '@mui/material';
import {
  Person as PersonIcon,
  Lock as LockIcon,
  Save as SaveIcon,
  Psychology as PsychologyIcon,
} from '@mui/icons-material';
import { profileAPI } from '../services/api';
import { useAuth } from '../contexts/AuthContext';

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

const Profile = () => {
  const { user: authUser, refreshUser } = useAuth();
  const [loading, setLoading] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  // Profile data
  const [profile, setProfile] = useState({
    username: '',
    email: '',
    full_name: '',
    role_name: '',
    skills: [],
    specializations: [],
  });

  // Password change
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });

  const [errors, setErrors] = useState({});

  useEffect(() => {
    loadProfile();
  }, []);

  const loadProfile = async () => {
    try {
      setLoading(true);
      const response = await profileAPI.get();
      setProfile(response.data);
    } catch (error) {
      console.error('Failed to load profile:', error);
      showSnackbar('Erro ao carregar perfil', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleProfileChange = (e) => {
    const { name, value } = e.target;
    setProfile(prev => ({ ...prev, [name]: value }));
    // Clear error for this field
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    setPasswordData(prev => ({ ...prev, [name]: value }));
    // Clear error for this field
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const validateProfile = () => {
    const newErrors = {};
    if (!profile.email) {
      newErrors.email = 'Email é obrigatório';
    } else if (!/\S+@\S+\.\S+/.test(profile.email)) {
      newErrors.email = 'Email inválido';
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const validatePassword = () => {
    const newErrors = {};
    if (!passwordData.currentPassword) {
      newErrors.currentPassword = 'Senha atual é obrigatória';
    }
    if (!passwordData.newPassword) {
      newErrors.newPassword = 'Nova senha é obrigatória';
    } else if (passwordData.newPassword.length < 6) {
      newErrors.newPassword = 'Senha deve ter no mínimo 6 caracteres';
    }
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      newErrors.confirmPassword = 'Senhas não conferem';
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSaveProfile = async () => {
    if (!validateProfile()) return;

    try {
      setLoading(true);
      await profileAPI.update({
        email: profile.email,
        full_name: profile.full_name,
        skills: profile.skills,
        specializations: profile.specializations,
      });
      showSnackbar('Perfil atualizado com sucesso!', 'success');
      await refreshUser(); // Atualizar dados do usuário no contexto
    } catch (error) {
      console.error('Failed to update profile:', error);
      showSnackbar(error.response?.data?.error || 'Erro ao atualizar perfil', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async () => {
    if (!validatePassword()) return;

    try {
      setLoading(true);
      await profileAPI.changePassword(passwordData.currentPassword, passwordData.newPassword);
      showSnackbar('Senha alterada com sucesso!', 'success');
      // Limpar campos de senha
      setPasswordData({
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
      });
    } catch (error) {
      console.error('Failed to change password:', error);
      const errorMsg = error.response?.data?.error || 'Erro ao alterar senha';
      showSnackbar(errorMsg, 'error');
      if (errorMsg.includes('incorrect')) {
        setErrors({ currentPassword: 'Senha atual incorreta' });
      }
    } finally {
      setLoading(false);
    }
  };

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Meu Perfil
      </Typography>

      <Grid container spacing={3}>
        {/* Profile Information Card */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader
              avatar={
                <Avatar sx={{ bgcolor: 'primary.main' }}>
                  <PersonIcon />
                </Avatar>
              }
              title="Informações do Perfil"
              subheader="Atualize seus dados pessoais"
            />
            <CardContent>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Usuário"
                    name="username"
                    value={profile.username}
                    disabled
                    helperText="Nome de usuário não pode ser alterado"
                  />
                </Grid>

                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Email"
                    name="email"
                    type="email"
                    value={profile.email}
                    onChange={handleProfileChange}
                    error={!!errors.email}
                    helperText={errors.email}
                    disabled={loading}
                  />
                </Grid>

                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Nome Completo"
                    name="full_name"
                    value={profile.full_name || ''}
                    onChange={handleProfileChange}
                    disabled={loading}
                  />
                </Grid>

                <Grid item xs={12}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography variant="body2" color="text.secondary">
                      Perfil de Acesso:
                    </Typography>
                    <Chip
                      label={profile.role_name || 'N/A'}
                      color="primary"
                      size="small"
                      sx={{ textTransform: 'capitalize' }}
                    />
                  </Box>
                </Grid>

                <Grid item xs={12}>
                  <Button
                    variant="contained"
                    startIcon={<SaveIcon />}
                    onClick={handleSaveProfile}
                    disabled={loading}
                    fullWidth
                  >
                    Salvar Alterações
                  </Button>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Change Password Card */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader
              avatar={
                <Avatar sx={{ bgcolor: 'secondary.main' }}>
                  <LockIcon />
                </Avatar>
              }
              title="Alterar Senha"
              subheader="Mantenha sua conta segura"
            />
            <CardContent>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Senha Atual"
                    name="currentPassword"
                    type="password"
                    value={passwordData.currentPassword}
                    onChange={handlePasswordChange}
                    error={!!errors.currentPassword}
                    helperText={errors.currentPassword}
                    disabled={loading}
                  />
                </Grid>

                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Nova Senha"
                    name="newPassword"
                    type="password"
                    value={passwordData.newPassword}
                    onChange={handlePasswordChange}
                    error={!!errors.newPassword}
                    helperText={errors.newPassword || 'Mínimo de 6 caracteres'}
                    disabled={loading}
                  />
                </Grid>

                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Confirmar Nova Senha"
                    name="confirmPassword"
                    type="password"
                    value={passwordData.confirmPassword}
                    onChange={handlePasswordChange}
                    error={!!errors.confirmPassword}
                    helperText={errors.confirmPassword}
                    disabled={loading}
                  />
                </Grid>

                <Grid item xs={12}>
                  <Button
                    variant="contained"
                    color="secondary"
                    startIcon={<LockIcon />}
                    onClick={handleChangePassword}
                    disabled={loading}
                    fullWidth
                  >
                    Alterar Senha
                  </Button>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Skills and Specializations Card */}
        <Grid item xs={12}>
          <Card>
            <CardHeader
              avatar={
                <Avatar sx={{ bgcolor: 'info.main' }}>
                  <PsychologyIcon />
                </Avatar>
              }
              title="Habilidades e Especializações"
              subheader="Defina suas competências para triagem de alertas"
            />
            <CardContent>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
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
                    value={(profile.skills || []).map(id => AVAILABLE_SKILLS.find(s => s.id === id) || { id, label: id })}
                    onChange={(event, newValue) => {
                      setProfile({ 
                        ...profile, 
                        skills: newValue.map(v => typeof v === 'string' ? v : v.id) 
                      });
                    }}
                    isOptionEqualToValue={(option, value) => option.id === (value?.id || value)}
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Habilidades Técnicas"
                        placeholder="Selecione suas habilidades..."
                        helperText="Habilidades que você domina para análise de alertas"
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
                    disabled={loading}
                  />
                </Grid>

                <Grid item xs={12} md={6}>
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
                    value={(profile.specializations || []).map(id => AVAILABLE_SPECIALIZATIONS.find(s => s.id === id) || { id, label: id })}
                    onChange={(event, newValue) => {
                      setProfile({ 
                        ...profile, 
                        specializations: newValue.map(v => typeof v === 'string' ? v : v.id) 
                      });
                    }}
                    isOptionEqualToValue={(option, value) => option.id === (value?.id || value)}
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Áreas de Especialização"
                        placeholder="Selecione suas especializações..."
                        helperText="Áreas em que você possui expertise"
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
                    disabled={loading}
                  />
                </Grid>

                <Grid item xs={12}>
                  <Alert severity="info" sx={{ mt: 1 }}>
                    <Typography variant="body2">
                      Estas informações serão utilizadas na <strong>Triagem de Alertas</strong> para direcionar 
                      alertas relevantes às suas competências e para exibir seu perfil na lista de analistas.
                    </Typography>
                  </Alert>
                </Grid>

                <Grid item xs={12}>
                  <Button
                    variant="contained"
                    startIcon={<SaveIcon />}
                    onClick={handleSaveProfile}
                    disabled={loading}
                  >
                    Salvar Habilidades
                  </Button>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert onClose={handleCloseSnackbar} severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Profile;

