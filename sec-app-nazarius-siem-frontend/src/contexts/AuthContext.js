import React, { createContext, useState, useContext, useEffect } from 'react';
import { authAPI } from '../services/api';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [accessToken, setAccessToken] = useState(null);
  const [refreshToken, setRefreshToken] = useState(null);

  // Verificar token ao carregar
  useEffect(() => {
    const checkAuth = async () => {
      const storedAccessToken = localStorage.getItem('access_token');
      const storedRefreshToken = localStorage.getItem('refresh_token');
      const storedUser = localStorage.getItem('user');

      if (storedAccessToken && storedUser) {
        setAccessToken(storedAccessToken);
        setRefreshToken(storedRefreshToken);
        setUser(JSON.parse(storedUser));
      }

      setLoading(false);
    };

    checkAuth();
  }, []);

  // Auto-refresh token antes de expirar (a cada 10 minutos)
  useEffect(() => {
    if (!refreshToken) return;

    const interval = setInterval(async () => {
      try {
        const response = await authAPI.refresh(refreshToken);
        const newAccessToken = response.data.access_token;
        
        setAccessToken(newAccessToken);
        localStorage.setItem('access_token', newAccessToken);
        
        console.log('[AUTH] Token refreshed successfully');
      } catch (error) {
        console.error('[AUTH] Failed to refresh token:', error);
        // Se falhar, fazer logout
        logout();
      }
    }, 10 * 60 * 1000); // 10 minutos

    return () => clearInterval(interval);
  }, [refreshToken]);

  const login = async (username, password) => {
    try {
      const response = await authAPI.login(username, password);
      const { access_token, refresh_token, user: userData } = response.data;

      // Salvar no estado
      setAccessToken(access_token);
      setRefreshToken(refresh_token);
      setUser(userData);

      // Salvar no localStorage
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('refresh_token', refresh_token);
      localStorage.setItem('user', JSON.stringify(userData));

      return { success: true };
    } catch (error) {
      console.error('[AUTH] Login failed:', error);
      return { 
        success: false, 
        error: error.response?.data?.error || 'Falha ao fazer login' 
      };
    }
  };

  const logout = async () => {
    try {
      // Tentar fazer logout no backend
      if (refreshToken) {
        await authAPI.logout(refreshToken);
      }
    } catch (error) {
      console.error('[AUTH] Logout error:', error);
    } finally {
      // Limpar estado e localStorage
      setUser(null);
      setAccessToken(null);
      setRefreshToken(null);
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('user');
    }
  };

  const refreshUser = async () => {
    try {
      const response = await authAPI.getMe();
      const userData = response.data;
      setUser(userData);
      localStorage.setItem('user', JSON.stringify(userData));
      return userData;
    } catch (error) {
      console.error('[AUTH] Failed to refresh user data:', error);
      throw error;
    }
  };

  const value = {
    user,
    accessToken,
    refreshToken,
    loading,
    isAuthenticated: !!user,
    login,
    logout,
    refreshUser,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;

