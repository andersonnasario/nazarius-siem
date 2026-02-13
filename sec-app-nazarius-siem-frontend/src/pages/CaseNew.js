import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Grid,
  Chip,
  IconButton,
  Alert,
  Snackbar,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Add as AddIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { casesAPI } from '../services/api';

const CaseNew = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  
  // Form state
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: 'medium',
    priority: 'medium',
    category: 'malware',
    assignedTo: '',
    tags: [],
  });
  
  const [tagInput, setTagInput] = useState('');

  const handleChange = (field) => (event) => {
    setFormData({
      ...formData,
      [field]: event.target.value,
    });
  };

  const handleAddTag = () => {
    if (tagInput.trim() && !formData.tags.includes(tagInput.trim())) {
      setFormData({
        ...formData,
        tags: [...formData.tags, tagInput.trim()],
      });
      setTagInput('');
    }
  };

  const handleRemoveTag = (tagToRemove) => {
    setFormData({
      ...formData,
      tags: formData.tags.filter(tag => tag !== tagToRemove),
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.title || !formData.description) {
      showSnackbar('Título e descrição são obrigatórios', 'error');
      return;
    }

    try {
      setLoading(true);
      const response = await casesAPI.create(formData);
      showSnackbar('Caso criado com sucesso!', 'success');
      
      // Redirecionar para detalhes do caso após 1 segundo
      setTimeout(() => {
        if (response.data && response.data.id) {
          navigate(`/cases/${response.data.id}`);
        } else {
          navigate('/cases');
        }
      }, 1000);
    } catch (error) {
      console.error('Erro ao criar caso:', error);
      showSnackbar('Erro ao criar caso. Tente novamente.', 'error');
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
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <IconButton onClick={() => navigate('/cases')} sx={{ mr: 2 }}>
          <ArrowBackIcon />
        </IconButton>
        <Typography variant="h4">
          Criar Novo Caso
        </Typography>
      </Box>

      {/* Form */}
      <Card>
        <CardContent>
          <form onSubmit={handleSubmit}>
            <Grid container spacing={3}>
              {/* Título */}
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  required
                  label="Título do Caso"
                  value={formData.title}
                  onChange={handleChange('title')}
                  placeholder="Ex: Tentativa de Acesso Não Autorizado"
                />
              </Grid>

              {/* Descrição */}
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  required
                  multiline
                  rows={4}
                  label="Descrição"
                  value={formData.description}
                  onChange={handleChange('description')}
                  placeholder="Descreva o incidente de segurança em detalhes..."
                />
              </Grid>

              {/* Severidade */}
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Severidade</InputLabel>
                  <Select
                    value={formData.severity}
                    label="Severidade"
                    onChange={handleChange('severity')}
                  >
                    <MenuItem value="low">Baixo</MenuItem>
                    <MenuItem value="medium">Médio</MenuItem>
                    <MenuItem value="high">Alto</MenuItem>
                    <MenuItem value="critical">Crítico</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {/* Prioridade */}
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Prioridade</InputLabel>
                  <Select
                    value={formData.priority}
                    label="Prioridade"
                    onChange={handleChange('priority')}
                  >
                    <MenuItem value="low">Baixa</MenuItem>
                    <MenuItem value="medium">Média</MenuItem>
                    <MenuItem value="high">Alta</MenuItem>
                    <MenuItem value="urgent">Urgente</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {/* Categoria */}
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth>
                  <InputLabel>Categoria</InputLabel>
                  <Select
                    value={formData.category}
                    label="Categoria"
                    onChange={handleChange('category')}
                  >
                    <MenuItem value="malware">Malware</MenuItem>
                    <MenuItem value="phishing">Phishing</MenuItem>
                    <MenuItem value="unauthorized_access">Acesso Não Autorizado</MenuItem>
                    <MenuItem value="data_breach">Vazamento de Dados</MenuItem>
                    <MenuItem value="web_attack">Ataque Web</MenuItem>
                    <MenuItem value="dos_attack">Ataque DoS/DDoS</MenuItem>
                    <MenuItem value="privilege_escalation">Escalação de Privilégios</MenuItem>
                    <MenuItem value="advanced_threat">Ameaça Avançada</MenuItem>
                    <MenuItem value="other">Outro</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {/* Atribuir a */}
              <Grid item xs={12} sm={6} md={3}>
                <TextField
                  fullWidth
                  label="Atribuir a (opcional)"
                  value={formData.assignedTo}
                  onChange={handleChange('assignedTo')}
                  placeholder="ID do analista"
                />
              </Grid>

              {/* Tags */}
              <Grid item xs={12}>
                <Typography variant="subtitle2" gutterBottom>
                  Tags
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Adicionar tag"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleAddTag();
                      }
                    }}
                    placeholder="Ex: brute-force, ssh, mitre:T1110"
                  />
                  <Button
                    variant="outlined"
                    startIcon={<AddIcon />}
                    onClick={handleAddTag}
                  >
                    Adicionar
                  </Button>
                </Box>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {formData.tags.map((tag, index) => (
                    <Chip
                      key={index}
                      label={tag}
                      onDelete={() => handleRemoveTag(tag)}
                      deleteIcon={<CloseIcon />}
                    />
                  ))}
                </Box>
              </Grid>

              {/* Informação sobre SLA */}
              <Grid item xs={12}>
                <Alert severity="info">
                  <Typography variant="body2">
                    <strong>SLA será calculado automaticamente:</strong>
                    <br />
                    • Crítico: 2 horas
                    <br />
                    • Alto: 24 horas
                    <br />
                    • Médio: 72 horas (3 dias)
                    <br />
                    • Baixo: 168 horas (7 dias)
                  </Typography>
                </Alert>
              </Grid>

              {/* Botões */}
              <Grid item xs={12}>
                <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
                  <Button
                    variant="outlined"
                    onClick={() => navigate('/cases')}
                    disabled={loading}
                  >
                    Cancelar
                  </Button>
                  <Button
                    type="submit"
                    variant="contained"
                    disabled={loading}
                  >
                    {loading ? 'Criando...' : 'Criar Caso'}
                  </Button>
                </Box>
              </Grid>
            </Grid>
          </form>
        </CardContent>
      </Card>

      {/* Snackbar */}
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

export default CaseNew;

