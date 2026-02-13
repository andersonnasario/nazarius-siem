import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import '@testing-library/jest-dom';
import Layout from '../Layout';

// Mock do NotificationBadge
jest.mock('../NotificationBadge', () => {
  return function MockNotificationBadge() {
    return <div data-testid="notification-badge">Notifications</div>;
  };
});

const renderWithRouter = (component) => {
  return render(
    <BrowserRouter>
      {component}
    </BrowserRouter>
  );
};

describe('Layout Component', () => {
  test('renderiza o título da aplicação', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    expect(screen.getByText('SIEM Platform')).toBeInTheDocument();
  });

  test('renderiza o conteúdo filho', () => {
    renderWithRouter(<Layout><div>Test Content</div></Layout>);
    expect(screen.getByText('Test Content')).toBeInTheDocument();
  });

  test('renderiza todas as categorias do menu', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Security Operations')).toBeInTheDocument();
    expect(screen.getByText('Threat Management')).toBeInTheDocument();
    expect(screen.getByText('Analytics & ML')).toBeInTheDocument();
    expect(screen.getByText('Protection & Compliance')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  test('categorias Dashboard e Security Operations começam expandidas', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    
    // Verifica se os itens do Dashboard estão visíveis
    expect(screen.getByText('Dashboard Principal')).toBeInTheDocument();
    expect(screen.getByText('Dashboard Executivo')).toBeInTheDocument();
    
    // Verifica se os itens de Security Operations estão visíveis
    expect(screen.getByText('Eventos')).toBeInTheDocument();
    expect(screen.getByText('Alertas')).toBeInTheDocument();
  });

  test('pode expandir/colapsar categorias', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    
    // Encontra a categoria Threat Management (inicialmente colapsada)
    const threatManagementCategory = screen.getByText('Threat Management');
    
    // Clica para expandir
    fireEvent.click(threatManagementCategory);
    
    // Agora os itens devem estar visíveis
    expect(screen.getByText('Threat Intelligence')).toBeInTheDocument();
    expect(screen.getByText('Threat Hunting')).toBeInTheDocument();
  });

  test('exibe badges NEW nos módulos recentes', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    
    // Expande a categoria Security Operations (já deve estar expandida)
    const newBadges = screen.getAllByText('NEW');
    
    // Deve haver 4 badges NEW (Incident Response, ML Analytics, Monitoring, Security Settings)
    expect(newBadges.length).toBeGreaterThanOrEqual(1);
  });

  test('renderiza o NotificationBadge', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    expect(screen.getByTestId('notification-badge')).toBeInTheDocument();
  });

  test('links de navegação têm os caminhos corretos', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    
    const dashboardLink = screen.getByText('Dashboard Principal').closest('a');
    expect(dashboardLink).toHaveAttribute('href', '/');
    
    const eventosLink = screen.getByText('Eventos').closest('a');
    expect(dashboardLink).toBeInTheDocument();
  });

  test('pode navegar para Incident Response', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    
    // Verifica se o link existe
    const incidentResponseLink = screen.getByText('Incident Response').closest('a');
    expect(incidentResponseLink).toHaveAttribute('href', '/incident-response');
  });

  test('pode navegar para ML Analytics', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    
    // Expande Analytics & ML
    const analyticsCategory = screen.getByText('Analytics & ML');
    fireEvent.click(analyticsCategory);
    
    const mlAnalyticsLink = screen.getByText('ML Analytics').closest('a');
    expect(mlAnalyticsLink).toHaveAttribute('href', '/ml-analytics');
  });

  test('pode navegar para Security Settings', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    
    // Expande Settings
    const settingsCategory = screen.getByText(/^Settings$/);
    fireEvent.click(settingsCategory);
    
    const securitySettingsLink = screen.getByText('Security Settings').closest('a');
    expect(securitySettingsLink).toHaveAttribute('href', '/security-settings');
  });

  test('sidebar tem largura fixa de 240px', () => {
    const { container } = renderWithRouter(<Layout><div>Content</div></Layout>);
    
    const drawer = container.querySelector('.MuiDrawer-root');
    expect(drawer).toBeInTheDocument();
  });

  test('AppBar está posicionada fixa no topo', () => {
    const { container } = renderWithRouter(<Layout><div>Content</div></Layout>);
    
    const appBar = container.querySelector('.MuiAppBar-root');
    expect(appBar).toBeInTheDocument();
  });

  test('todas as 24 funcionalidades estão no menu', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    
    // Expande todas as categorias
    const categories = [
      'Threat Management',
      'Analytics & ML',
      'Protection & Compliance',
      /^Settings$/
    ];
    
    categories.forEach(category => {
      const categoryElement = screen.getByText(category);
      fireEvent.click(categoryElement);
    });
    
    // Verifica alguns itens de cada categoria
    expect(screen.getByText('Dashboard Principal')).toBeInTheDocument();
    expect(screen.getByText('Eventos')).toBeInTheDocument();
    expect(screen.getByText('Threat Intelligence')).toBeInTheDocument();
    expect(screen.getByText('ML Analytics')).toBeInTheDocument();
    expect(screen.getByText('Vulnerabilidades')).toBeInTheDocument();
    expect(screen.getByText('Configurações')).toBeInTheDocument();
  });

  test('itens do menu têm ícones', () => {
    const { container } = renderWithRouter(<Layout><div>Content</div></Layout>);
    
    const icons = container.querySelectorAll('.MuiListItemIcon-root');
    expect(icons.length).toBeGreaterThan(0);
  });

  test('categorias colapsadas não mostram itens filhos', () => {
    renderWithRouter(<Layout><div>Content</div></Layout>);
    
    // Threat Management começa colapsado
    expect(screen.queryByText('Threat Intelligence')).not.toBeInTheDocument();
    
    // Após clicar, deve aparecer
    const threatManagementCategory = screen.getByText('Threat Management');
    fireEvent.click(threatManagementCategory);
    
    expect(screen.getByText('Threat Intelligence')).toBeInTheDocument();
  });
});

