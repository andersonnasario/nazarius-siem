import React from 'react';
import { Box, Typography, Alert } from '@mui/material';
import { useAuth } from '../contexts/AuthContext';
import BlockIcon from '@mui/icons-material/Block';

/**
 * AdminRoute - Componente que protege rotas que só admins podem acessar
 * Se o usuário não for admin, mostra uma mensagem de acesso negado
 */
const AdminRoute = ({ children }) => {
  const { user, loading } = useAuth();

  // Enquanto carrega, não renderizar nada
  if (loading) {
    return null;
  }

  // Verificar se é admin
  const isAdmin = user?.role_name?.toLowerCase() === 'admin';

  if (!isAdmin) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '60vh',
          gap: 3,
          p: 4,
        }}
      >
        <BlockIcon sx={{ fontSize: 80, color: 'error.main' }} />
        <Typography variant="h4" color="error.main" gutterBottom>
          Acesso Negado
        </Typography>
        <Alert severity="error" sx={{ maxWidth: 500 }}>
          <Typography variant="body1">
            Você não tem permissão para acessar esta página.
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            Esta funcionalidade está disponível apenas para administradores.
            Entre em contato com o administrador do sistema se você acredita que deveria ter acesso.
          </Typography>
        </Alert>
        <Typography variant="caption" color="text.secondary">
          Usuário atual: {user?.username} | Role: {user?.role_name}
        </Typography>
      </Box>
    );
  }

  return children;
};

export default AdminRoute;

