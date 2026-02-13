import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import Dashboard from '../Dashboard';

// Mock do serviço API
jest.mock('../../services/api', () => ({
  dashboardAPI: {
    getStats: jest.fn(() => Promise.resolve({
      data: {
        total_events: 12458,
        active_alerts: 47,
        active_users: 892,
        blocked_threats: 156,
      }
    })),
  }
}));

describe('Dashboard Component', () => {
  test('renderiza o título do dashboard', () => {
    render(<Dashboard />);
    expect(screen.getByText('Dashboard SIEM')).toBeInTheDocument();
  });

  test('exibe os KPIs corretamente', async () => {
    render(<Dashboard />);
    
    await waitFor(() => {
      expect(screen.getByText('Total de Eventos')).toBeInTheDocument();
      expect(screen.getByText('Alertas Ativos')).toBeInTheDocument();
      expect(screen.getByText('Usuários Ativos')).toBeInTheDocument();
      expect(screen.getByText('Ameaças Bloqueadas')).toBeInTheDocument();
    });
  });

  test('exibe valores numéricos dos KPIs', async () => {
    render(<Dashboard />);
    
    await waitFor(() => {
      expect(screen.getByText(/12,458|12458/)).toBeInTheDocument();
      expect(screen.getByText(/47/)).toBeInTheDocument();
      expect(screen.getByText(/892/)).toBeInTheDocument();
      expect(screen.getByText(/156/)).toBeInTheDocument();
    });
  });

  test('exibe cards de informação adicional', () => {
    render(<Dashboard />);
    
    expect(screen.getByText('Anomalias Detectadas (IA)')).toBeInTheDocument();
    expect(screen.getByText('Modelos ML Ativos')).toBeInTheDocument();
    expect(screen.getByText('Precisão da IA')).toBeInTheDocument();
    expect(screen.getByText('Correlações Auto')).toBeInTheDocument();
  });

  test('exibe gráficos do dashboard', () => {
    const { container } = render(<Dashboard />);
    
    // Verifica se há elementos de gráfico
    expect(screen.getByText('Taxa de Eventos em Tempo Real')).toBeInTheDocument();
    expect(screen.getByText('Distribuição de Ataques')).toBeInTheDocument();
  });

  test('exibe seções de análise', () => {
    render(<Dashboard />);
    
    expect(screen.getByText('Anomalias Detectadas por Machine Learning')).toBeInTheDocument();
    expect(screen.getByText('Uso de Recursos do Sistema')).toBeInTheDocument();
  });
});

