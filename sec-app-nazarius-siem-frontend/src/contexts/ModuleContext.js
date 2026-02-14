import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { moduleManagerAPI } from '../services/api';

const ModuleContext = createContext();

export const useModules = () => {
  const context = useContext(ModuleContext);
  if (!context) {
    throw new Error('useModules must be used within a ModuleProvider');
  }
  return context;
};

export const ModuleProvider = ({ children }) => {
  const [modules, setModules] = useState([]);
  const [enabledModules, setEnabledModules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(Date.now());

  // Carregar módulos da API
  const loadModules = useCallback(async () => {
    try {
      setLoading(true);
      const response = await moduleManagerAPI.getModules();
      if (response.data.success) {
        const allModules = response.data.data;
        setModules(allModules);
        
        // Filtrar apenas módulos ativos
        const activeModules = allModules
          .filter(m => m.status === 'active')
          .map(m => m.path);
        
        // Sempre incluir o Module Manager
        if (!activeModules.includes('/module-manager')) {
          activeModules.push('/module-manager');
        }
        
        setEnabledModules(activeModules);
      }
    } catch (error) {
      console.error('Error loading modules:', error);
      // Em caso de erro, mostrar todos os módulos
      setEnabledModules([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // Carregar módulos na inicialização
  useEffect(() => {
    loadModules();
  }, [loadModules]);

  // Verificar se um módulo está habilitado
  const isModuleEnabled = useCallback((path) => {
    // Se ainda não carregou, mostrar todos
    if (loading) return true;
    // Se lista vazia (erro), mostrar todos
    if (enabledModules.length === 0) return true;
    // Module Manager sempre visível
    if (path === '/module-manager') return true;
    // Verificar se está na lista de ativos
    return enabledModules.includes(path);
  }, [loading, enabledModules]);

  // Forçar atualização dos módulos
  const refreshModules = useCallback(async () => {
    await loadModules();
    setLastUpdate(Date.now());
  }, [loadModules]);

  // Atualizar status de um módulo
  const updateModuleStatus = useCallback(async (moduleId, newStatus) => {
    try {
      const response = await moduleManagerAPI.updateModuleStatus(moduleId, newStatus);
      if (response.data.success) {
        // Atualizar estado local imediatamente
        setModules(prevModules => 
          prevModules.map(m => 
            m.id === moduleId ? { ...m, status: newStatus } : m
          )
        );
        
        // Recalcular módulos habilitados
        setModules(prevModules => {
          const activeModules = prevModules
            .map(m => m.id === moduleId ? { ...m, status: newStatus } : m)
            .filter(m => m.status === 'active')
            .map(m => m.path);
          
          if (!activeModules.includes('/module-manager')) {
            activeModules.push('/module-manager');
          }
          
          setEnabledModules(activeModules);
          return prevModules.map(m => 
            m.id === moduleId ? { ...m, status: newStatus } : m
          );
        });
        
        setLastUpdate(Date.now());
        return { success: true };
      }
      return { success: false, error: 'Failed to update' };
    } catch (error) {
      console.error('Error updating module:', error);
      return { success: false, error: error.message };
    }
  }, []);

  // Atualização em massa
  const bulkUpdateModules = useCallback(async (modulesToUpdate) => {
    try {
      const response = await moduleManagerAPI.bulkUpdateModules(modulesToUpdate);
      if (response.data.success) {
        // Recarregar todos os módulos
        await loadModules();
        return { success: true, data: response.data.data };
      }
      return { success: false, error: 'Failed to bulk update' };
    } catch (error) {
      console.error('Error bulk updating modules:', error);
      return { success: false, error: error.message };
    }
  }, [loadModules]);

  const value = {
    modules,
    enabledModules,
    loading,
    lastUpdate,
    isModuleEnabled,
    refreshModules,
    updateModuleStatus,
    bulkUpdateModules,
    loadModules,
  };

  return (
    <ModuleContext.Provider value={value}>
      {children}
    </ModuleContext.Provider>
  );
};

export default ModuleContext;

