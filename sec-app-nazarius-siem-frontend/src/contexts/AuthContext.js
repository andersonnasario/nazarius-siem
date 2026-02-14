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

  // Check for stored tokens on load.
  // Security: Using sessionStorage instead of localStorage to limit XSS token theft
  // (sessionStorage is per-tab and cleared when the tab closes).
  // Migration: Also check localStorage for existing sessions, then remove from localStorage.
  useEffect(() => {
    const checkAuth = async () => {
      // Try sessionStorage first, then fallback to localStorage (migration)
      let storedAccessToken = sessionStorage.getItem('access_token') || localStorage.getItem('access_token');
      let storedRefreshToken = sessionStorage.getItem('refresh_token') || localStorage.getItem('refresh_token');
      let storedUser = sessionStorage.getItem('user') || localStorage.getItem('user');

      // Migrate from localStorage to sessionStorage if needed
      if (localStorage.getItem('access_token')) {
        sessionStorage.setItem('access_token', localStorage.getItem('access_token'));
        sessionStorage.setItem('refresh_token', localStorage.getItem('refresh_token') || '');
        sessionStorage.setItem('user', localStorage.getItem('user') || '');
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
      }

      if (storedAccessToken && storedUser) {
        setAccessToken(storedAccessToken);
        setRefreshToken(storedRefreshToken);
        try {
          setUser(JSON.parse(storedUser));
        } catch {
          // Invalid stored user data
          sessionStorage.clear();
        }
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
        const newRefreshToken = response.data.refresh_token;
        
        setAccessToken(newAccessToken);
        sessionStorage.setItem('access_token', newAccessToken);
        
        // Handle refresh token rotation (if server sends a new refresh token)
        if (newRefreshToken) {
          setRefreshToken(newRefreshToken);
          sessionStorage.setItem('refresh_token', newRefreshToken);
        }
      } catch (error) {
        // Token refresh failed - logout
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

      // Save to sessionStorage (more secure against XSS)
      sessionStorage.setItem('access_token', access_token);
      sessionStorage.setItem('refresh_token', refresh_token);
      sessionStorage.setItem('user', JSON.stringify(userData));

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
      // Logout error - continue with cleanup
    } finally {
      // Clear state and storage
      setUser(null);
      setAccessToken(null);
      setRefreshToken(null);
      sessionStorage.removeItem('access_token');
      sessionStorage.removeItem('refresh_token');
      sessionStorage.removeItem('user');
      // Also clear localStorage in case of migration remnants
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
      sessionStorage.setItem('user', JSON.stringify(userData));
      return userData;
    } catch (error) {
      // Failed to refresh user data
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

