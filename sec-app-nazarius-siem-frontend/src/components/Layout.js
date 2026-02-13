import React, { useState } from 'react';
import { Box, AppBar, Toolbar, Typography, Drawer, List, ListItem, ListItemIcon, ListItemText, Collapse, Divider, IconButton, Menu, MenuItem, Avatar, Chip } from '@mui/material';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useModules } from '../contexts/ModuleContext';
import DashboardIcon from '@mui/icons-material/Dashboard';
import LogoutIcon from '@mui/icons-material/Logout';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import EventNoteIcon from '@mui/icons-material/EventNote';
import WarningIcon from '@mui/icons-material/Warning';
import SettingsIcon from '@mui/icons-material/Settings';
import PsychologyIcon from '@mui/icons-material/Psychology';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import AssignmentIcon from '@mui/icons-material/Assignment';
import SecurityIcon from '@mui/icons-material/Security';
import NotificationsIcon from '@mui/icons-material/Notifications';
import NotificationsActiveIcon from '@mui/icons-material/NotificationsActive';
import AssessmentIcon from '@mui/icons-material/Assessment';
import TravelExploreIcon from '@mui/icons-material/TravelExplore';
import BusinessCenterIcon from '@mui/icons-material/BusinessCenter';
import LinkIcon from '@mui/icons-material/Link';
import SearchIcon from '@mui/icons-material/Search';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import GavelIcon from '@mui/icons-material/Gavel';
import BugReportIcon from '@mui/icons-material/BugReport';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import ShieldIcon from '@mui/icons-material/Shield';
import DesktopWindowsIcon from '@mui/icons-material/DesktopWindows';
import ShowChartIcon from '@mui/icons-material/ShowChart';
import LockIcon from '@mui/icons-material/Lock';
import SpeedIcon from '@mui/icons-material/Speed';
import ManageAccountsIcon from '@mui/icons-material/ManageAccounts';
import ExpandLess from '@mui/icons-material/ExpandLess';
import ExpandMore from '@mui/icons-material/ExpandMore';
import BusinessIcon from '@mui/icons-material/Business';
import SchoolIcon from '@mui/icons-material/School';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import LocalFireDepartmentIcon from '@mui/icons-material/LocalFireDepartment';
import BarChartIcon from '@mui/icons-material/BarChart';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import StorageIcon from '@mui/icons-material/Storage';
import VpnLockIcon from '@mui/icons-material/VpnLock';
import CloudIcon from '@mui/icons-material/Cloud';
import PowerSettingsNewIcon from '@mui/icons-material/PowerSettingsNew';
import EmojiEventsIcon from '@mui/icons-material/EmojiEvents';
import HistoryIcon from '@mui/icons-material/History';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import AccountBalanceIcon from '@mui/icons-material/AccountBalance';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import NotificationBadge from './NotificationBadge';
import NazariusLogo from '../assets/logo.png';

const drawerWidth = 240;

const Layout = ({ children }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [anchorEl, setAnchorEl] = useState(null);
  
  // Helper para verificar se o usuário é admin
  const isAdmin = () => {
    const roleName = user?.role_name?.toLowerCase() || '';
    return roleName === 'admin';
  };
  
  // Estado para controlar quais categorias estão expandidas
  const [openCategories, setOpenCategories] = useState({
    dashboard: true,
    secops: true,
    mdr: true,
    threat: false,
    analytics: true, // Analytics & ML aberto por padrão (UEBA, ML)
    protection: false,
    settings: true,
  });

  // Módulos do contexto global
  const { isModuleEnabled } = useModules();

  const handleCategoryClick = (category) => {
    setOpenCategories(prev => ({
      ...prev,
      [category]: !prev[category]
    }));
  };

  // Organização dos itens por categoria
  const menuCategories = [
    {
      id: 'dashboard',
      title: 'Dashboard',
      icon: <AssessmentIcon />,
      items: [
        { text: 'Dashboard Principal', icon: <DashboardIcon />, path: '/' },
        { text: 'Dashboard Executivo', icon: <BusinessCenterIcon />, path: '/executive' },
        { text: 'Dashboard Customizer', icon: <SettingsIcon />, path: '/dashboard-customizer', badge: 'NEW' },
      ]
    },
    {
      id: 'secops',
      title: 'Security Operations',
      icon: <LocalFireDepartmentIcon />,
      items: [
        { text: 'Eventos', icon: <EventNoteIcon />, path: '/events' },
        { text: 'Alertas', icon: <WarningIcon />, path: '/alerts' },
        { text: 'Casos', icon: <AssignmentIcon />, path: '/cases' },
        { text: 'Forensics', icon: <SearchIcon />, path: '/forensics' },
        { text: 'Incident Response', icon: <ManageAccountsIcon />, path: '/incident-response', badge: 'NEW' },
        { text: 'Playbooks (SOAR)', icon: <AutoFixHighIcon />, path: '/playbooks' },
        { text: 'Cloudflare WAF', icon: <CloudIcon />, path: '/cloudflare', badge: 'NEW', requireAdmin: true },
        { text: 'JumpCloud', icon: <ManageAccountsIcon />, path: '/jumpcloud', badge: 'NEW', requireAdmin: true },
      ]
    },
    {
      id: 'mdr',
      title: 'MDR (Managed Detection & Response)',
      icon: <AutoFixHighIcon />,
      items: [
        { text: 'Executive Dashboard', icon: <DashboardIcon />, path: '/mdr-dashboard', badge: 'NEW' },
        { text: 'Automated Response', icon: <AutoFixHighIcon />, path: '/automated-response', badge: 'NEW' },
        { text: 'Alert Triage', icon: <PsychologyIcon />, path: '/alert-triage', badge: 'NEW' },
        { text: 'SLA & Metrics', icon: <SpeedIcon />, path: '/sla-metrics', badge: 'NEW' },
        { text: 'Threat Hunting Platform', icon: <SearchIcon />, path: '/threat-hunting-platform', badge: 'NEW' },
        { text: 'Hunters Ranking', icon: <EmojiEventsIcon />, path: '/threat-hunting-ranking', badge: 'NEW' },
        { text: 'Hunting History', icon: <HistoryIcon />, path: '/threat-hunting-history', badge: 'NEW' },
        { text: 'Automated Forensics', icon: <BugReportIcon />, path: '/mdr-forensics', badge: 'NEW' },
        { text: 'Threat Intel Platform', icon: <SecurityIcon />, path: '/mdr-threat-intel', badge: 'NEW' },
        { text: 'Multi-Tenancy', icon: <BusinessIcon />, path: '/mdr-multi-tenancy', badge: 'NEW' },
        { text: 'Advanced Hunting', icon: <SearchIcon />, path: '/advanced-hunting', badge: 'NEW' },
        { text: 'Deception Technology', icon: <ShieldIcon />, path: '/deception', badge: 'NEW' },
        { text: 'Continuous Validation', icon: <SecurityIcon />, path: '/continuous-validation', badge: 'NEW' },
        { text: 'Security Awareness', icon: <SchoolIcon />, path: '/security-awareness', badge: 'NEW' },
        { text: 'SOAR', icon: <AccountTreeIcon />, path: '/soar', badge: 'NEW' },
        { text: 'Threat Intel Fusion', icon: <LinkIcon />, path: '/threat-intel-fusion', badge: 'NEW' },
        { text: 'CSPM', icon: <CloudIcon />, path: '/cspm', badge: 'NEW' },
        { text: 'AWS Integrations', icon: <CloudIcon />, path: '/cspm-aws', badge: 'AWS' },
        { text: 'GCP Integrations', icon: <CloudIcon />, path: '/cspm-gcp', badge: 'GCP' },
        { text: 'Auto-Remediation', icon: <AutoFixHighIcon />, path: '/cspm-remediation', badge: 'NEW' },
        { text: 'Sistema de Alertas', icon: <NotificationsActiveIcon />, path: '/cspm-alerts', badge: 'NEW' },
        { text: 'PCI-DSS Dashboard', icon: <AssessmentIcon />, path: '/cspm-pci-dss', badge: 'NEW' },
        { text: 'Drift Detection', icon: <CompareArrowsIcon />, path: '/cspm-drift', badge: 'NEW' },
        { text: 'Config Aggregator', icon: <AccountBalanceIcon />, path: '/cspm-config-aggregator', badge: 'NEW' },
        { text: 'AWS Connections', icon: <VpnKeyIcon />, path: '/aws-connections', badge: 'NEW' },
        { text: 'Zero Trust', icon: <VpnLockIcon />, path: '/zero-trust', badge: 'NEW' },
      ]
    },
    {
      id: 'threat',
      title: 'Threat Management',
      icon: <SecurityIcon />,
      items: [
        { text: 'Threat Intelligence', icon: <TravelExploreIcon />, path: '/threat-intelligence' },
        { text: 'CVE Database', icon: <BugReportIcon />, path: '/cve-database', badge: 'NVD' },
        { text: 'Threat Hunting', icon: <SearchIcon />, path: '/hunting' },
        { text: 'MITRE ATT&CK', icon: <SecurityIcon />, path: '/mitre-attack' },
      ]
    },
    {
      id: 'analytics',
      title: '🧠 Analytics & IA',
      icon: <BarChartIcon />,
      items: [
        { text: 'UEBA (Comportamento)', icon: <SmartToyIcon />, path: '/ueba', badge: 'IA' },
        { text: 'Advanced Analytics', icon: <PsychologyIcon />, path: '/advanced-analytics', badge: 'ML' },
        { text: 'ML Analytics', icon: <ShowChartIcon />, path: '/ml-analytics', badge: 'ML' },
        { text: 'Análise IA', icon: <PsychologyIcon />, path: '/ai-analysis', badge: 'IA' },
        { text: 'Reports & Analytics', icon: <AssessmentIcon />, path: '/reports', badge: 'NEW' },
        { text: 'Monitoring', icon: <SpeedIcon />, path: '/monitoring', badge: 'NEW' },
      ]
    },
    {
      id: 'protection',
      title: 'Protection & Compliance',
      icon: <AdminPanelSettingsIcon />,
      items: [
        { text: 'Vulnerabilidades', icon: <BugReportIcon />, path: '/vulnerabilities' },
        { text: 'PLA Risk Matrix', icon: <GavelIcon />, path: '/pla-risk-matrix', badge: 'NEW' },
        { text: 'Diagnóstico AWS', icon: <CloudIcon />, path: '/vulnerability-diagnostics', badge: 'NEW', requireAdmin: true },
        { text: 'EDR (Endpoint)', icon: <DesktopWindowsIcon />, path: '/edr' },
        { text: 'Network Analysis', icon: <NetworkCheckIcon />, path: '/network' },
        { text: 'File Integrity', icon: <FolderOpenIcon />, path: '/file-integrity' },
        { text: 'Data Loss Prevention', icon: <ShieldIcon />, path: '/dlp' },
        { text: 'Compliance', icon: <GavelIcon />, path: '/compliance' },
      ]
    },
    {
      id: 'settings',
      title: 'Settings',
      icon: <SettingsIcon />,
      requireAdmin: true, // Categoria inteira só para admins
      items: [
        { text: 'Module Manager', icon: <PowerSettingsNewIcon />, path: '/module-manager', badge: 'NEW', requireAdmin: true },
        { text: 'Security Settings', icon: <LockIcon />, path: '/security-settings', badge: 'NEW', requireAdmin: true },
        { text: 'Políticas de Casos', icon: <AssignmentIcon />, path: '/case-policies', badge: 'NEW', requireAdmin: true },
        { text: 'Data Retention', icon: <StorageIcon />, path: '/data-retention', badge: 'NEW', requireAdmin: true },
        { text: 'Integrações', icon: <LinkIcon />, path: '/integrations', requireAdmin: true },
        { text: 'Fortinet', icon: <ShieldIcon />, path: '/fortinet', badge: 'NEW', requireAdmin: true },
        { text: 'Notificações', icon: <NotificationsIcon />, path: '/notifications', badge: 'NEW' }, // Notificações para todos
        { text: 'System Logs', icon: <StorageIcon />, path: '/system-logs', badge: 'NEW', requireAdmin: true },
        { text: 'AWS Connectivity', icon: <CloudIcon />, path: '/aws-connectivity', badge: 'NEW', requireAdmin: true },
        { text: 'Configurações', icon: <SettingsIcon />, path: '/settings', requireAdmin: true },
      ]
    },
  ];

  const handleUserMenuOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleUserMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = async () => {
    handleUserMenuClose();
    await logout();
    navigate('/login');
  };

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
        <Toolbar>
          <Box sx={{ display: 'flex', alignItems: 'center', flexGrow: 1 }}>
            <img 
              src={NazariusLogo} 
              alt="Nazarius Logo" 
              style={{ 
                height: 40, 
                marginRight: 12,
                filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.3))'
              }} 
            />
            <Typography variant="h6" noWrap component="div" sx={{ fontWeight: 700 }}>
              Nazarius
            </Typography>
          </Box>
          
          <NotificationBadge />
          
          {/* User Menu */}
          <Box sx={{ ml: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
            <Chip
              label={user?.role_name || 'user'}
              size="small"
              color="primary"
              sx={{ textTransform: 'capitalize' }}
            />
            <IconButton
              onClick={handleUserMenuOpen}
              size="small"
              sx={{ ml: 1 }}
            >
              <Avatar sx={{ width: 32, height: 32, bgcolor: 'primary.main' }}>
                {user?.username?.charAt(0).toUpperCase() || 'U'}
              </Avatar>
            </IconButton>
            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleUserMenuClose}
              anchorOrigin={{
                vertical: 'bottom',
                horizontal: 'right',
              }}
              transformOrigin={{
                vertical: 'top',
                horizontal: 'right',
              }}
            >
              <MenuItem disabled>
                <Box>
                  <Typography variant="body2" fontWeight="bold">
                    {user?.username}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {user?.email}
                  </Typography>
                </Box>
              </MenuItem>
              <Divider />
              <MenuItem onClick={() => { handleUserMenuClose(); navigate('/profile'); }}>
                <ListItemIcon>
                  <AccountCircleIcon fontSize="small" />
                </ListItemIcon>
                <ListItemText>Meu Perfil</ListItemText>
              </MenuItem>
              {isAdmin() && (
                <MenuItem onClick={() => { handleUserMenuClose(); navigate('/users'); }}>
                  <ListItemIcon>
                    <AccountCircleIcon fontSize="small" />
                  </ListItemIcon>
                  <ListItemText>Gerenciar Usuários</ListItemText>
                </MenuItem>
              )}
              <MenuItem onClick={handleLogout}>
                <ListItemIcon>
                  <LogoutIcon fontSize="small" />
                </ListItemIcon>
                <ListItemText>Sair</ListItemText>
              </MenuItem>
            </Menu>
          </Box>
        </Toolbar>
      </AppBar>
      <Drawer
        variant="permanent"
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: drawerWidth,
            boxSizing: 'border-box',
            backgroundColor: '#1a1a2e',
          },
        }}
      >
        <Toolbar />
        {/* Logo e Nome no topo da Sidebar */}
        <Box 
          sx={{ 
            display: 'flex', 
            flexDirection: 'column',
            alignItems: 'center', 
            py: 2,
            borderBottom: '1px solid rgba(255,255,255,0.1)',
            mb: 1,
          }}
        >
          <img 
            src={NazariusLogo} 
            alt="Nazarius" 
            style={{ 
              height: 60, 
              marginBottom: 8,
              filter: 'drop-shadow(0 2px 8px rgba(0,0,0,0.5))'
            }} 
          />
          <Typography 
            variant="h6" 
            sx={{ 
              color: '#fff', 
              fontWeight: 700,
              letterSpacing: '2px',
              textTransform: 'uppercase',
            }}
          >
            Nazarius
          </Typography>
          <Typography 
            variant="caption" 
            sx={{ 
              color: 'rgba(255,255,255,0.6)', 
              fontSize: '0.7rem',
            }}
          >
            SIEM & SOC Platform
          </Typography>
        </Box>
        <Box sx={{ overflow: 'auto' }}>
          <List>
            {menuCategories
              // Filtrar categorias que requerem admin
              .filter(category => {
                if (category.requireAdmin && !isAdmin()) return false;
                return true;
              })
              .map((category, categoryIndex) => (
              <React.Fragment key={category.id}>
                {categoryIndex > 0 && <Divider sx={{ my: 0.5, backgroundColor: 'rgba(255,255,255,0.12)' }} />}
                
                {/* Cabeçalho da Categoria */}
                <ListItem
                  button
                  onClick={() => handleCategoryClick(category.id)}
                  sx={{
                    color: 'white',
                    backgroundColor: 'rgba(255, 255, 255, 0.05)',
                    '&:hover': {
                      backgroundColor: 'rgba(255, 255, 255, 0.1)',
                    },
                    py: 1,
                  }}
                >
                  <ListItemIcon sx={{ color: '#90caf9', minWidth: 40 }}>
                    {category.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={category.title}
                    primaryTypographyProps={{
                      sx: {
                        fontWeight: 600,
                        fontSize: '0.85rem',
                        textTransform: 'uppercase',
                        letterSpacing: '0.5px',
                      }
                    }}
                  />
                  {openCategories[category.id] ? <ExpandLess /> : <ExpandMore />}
                </ListItem>

                {/* Itens da Categoria */}
                <Collapse in={openCategories[category.id]} timeout="auto" unmountOnExit>
                  <List component="div" disablePadding>
                    {category.items.filter(item => {
                      // Verificar se item requer admin
                      if (item.requireAdmin && !isAdmin()) return false;
                      // Settings sempre visíveis (se passou no filtro acima)
                      if (category.id === 'settings') return true;
                      // Integrações admin (Cloudflare, JumpCloud, etc.) sempre visíveis para admins
                      if (item.requireAdmin && isAdmin()) return true;
                      // Dashboard Principal (/) sempre visível, outros dashboards verificar módulos
                      if (item.path === '/') return true;
                      // Outros itens verificar se estão habilitados
                      return isModuleEnabled(item.path);
                    }).map((item) => (
                      <ListItem
                        key={item.text}
                        component={Link}
                        to={item.path}
                        selected={location.pathname === item.path}
                        sx={{
                          pl: 4,
                          cursor: 'pointer',
                          color: 'white',
                          backgroundColor: location.pathname === item.path ? 'rgba(144, 202, 249, 0.16)' : 'transparent',
                          '&:hover': {
                            backgroundColor: 'rgba(255, 255, 255, 0.08)',
                            color: '#90caf9'
                          },
                          '&.Mui-selected': {
                            backgroundColor: 'rgba(144, 202, 249, 0.16)',
                            borderLeft: '3px solid #90caf9',
                            '&:hover': {
                              backgroundColor: 'rgba(144, 202, 249, 0.24)',
                            }
                          },
                          py: 0.75,
                        }}
                      >
                        <ListItemIcon sx={{ color: 'white', minWidth: 36 }}>
                          {item.icon}
                        </ListItemIcon>
                        <ListItemText
                          primary={item.text}
                          primaryTypographyProps={{
                            sx: {
                              fontWeight: location.pathname === item.path ? 600 : 400,
                              fontSize: '0.875rem',
                            }
                          }}
                        />
                        {item.badge && (
                          <Box
                            sx={{
                              backgroundColor: '#4caf50',
                              color: 'white',
                              fontSize: '0.65rem',
                              fontWeight: 700,
                              px: 0.75,
                              py: 0.25,
                              borderRadius: '4px',
                              ml: 0.5,
                            }}
                          >
                            {item.badge}
                          </Box>
                        )}
                      </ListItem>
                    ))}
                  </List>
                </Collapse>
              </React.Fragment>
            ))}
          </List>
        </Box>
      </Drawer>
      <Box component="main" sx={{ flexGrow: 1, p: 3 }}>
        <Toolbar />
        {children}
      </Box>
    </Box>
  );
};

export default Layout;