import React, { useState, useEffect } from 'react';
import {
  Box, Container, Grid, Card, CardContent, Typography, Button, Drawer,
  IconButton, Tabs, Tab, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, List, ListItem, ListItemIcon, ListItemText, ListItemButton,
  Chip, Alert, Tooltip, FormControlLabel, Switch, Divider, Menu, MenuItem
} from '@mui/material';
import {
  Add, Edit, Delete, Save, Download, Upload, Close, DragIndicator,
  Widgets, Dashboard as DashboardIcon, Settings, Share, ContentCopy,
  Assessment, ShowChart, BarChart, PieChart, TableChart, Speed,
  Notifications, TrendingUp, Map, Timeline, GridOn, Feed
} from '@mui/icons-material';
import GridLayout from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';
import { dashboardsAPI } from '../services/api';

const DashboardCustomizer = () => {
  const [dashboards, setDashboards] = useState([]);
  const [currentDashboard, setCurrentDashboard] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(true);
  const [activeTab, setActiveTab] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Widget Library
  const [widgetTypes, setWidgetTypes] = useState([]);
  const [templates, setTemplates] = useState([]);
  
  // Layout state
  const [layout, setLayout] = useState([]);
  const [widgets, setWidgets] = useState([]);
  
  // New dashboard form
  const [dashboardName, setDashboardName] = useState('');
  const [dashboardDesc, setDashboardDesc] = useState('');
  
  // Context menu
  const [contextMenu, setContextMenu] = useState(null);
  const [selectedWidget, setSelectedWidget] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Load dashboards from API
      const dashboardsRes = await dashboardsAPI.list().catch(() => ({ data: { dashboards: [] } }));
      const loadedDashboards = dashboardsRes.data.dashboards || [];
      
      // If no dashboards exist, create default ones
      if (loadedDashboards.length === 0) {
        const defaultDashboards = [
          { id: 'dash-001', name: 'My Security Dashboard', isDefault: true, widgets: 6 },
          { id: 'dash-002', name: 'Executive View', isDefault: false, widgets: 4 }
        ];
        setDashboards(defaultDashboards);
      } else {
        setDashboards(loadedDashboards);
      }

      // Load widget types
      setWidgetTypes([
        { type: 'kpi', name: 'KPI Card', icon: <Assessment />, category: 'metrics', color: '#2196f3' },
        { type: 'line-chart', name: 'Line Chart', icon: <ShowChart />, category: 'charts', color: '#4caf50' },
        { type: 'bar-chart', name: 'Bar Chart', icon: <BarChart />, category: 'charts', color: '#ff9800' },
        { type: 'pie-chart', name: 'Pie Chart', icon: <PieChart />, category: 'charts', color: '#f44336' },
        { type: 'table', name: 'Data Table', icon: <TableChart />, category: 'data', color: '#9c27b0' },
        { type: 'gauge', name: 'Gauge Meter', icon: <Speed />, category: 'metrics', color: '#00bcd4' },
        { type: 'feed', name: 'Event Feed', icon: <Feed />, category: 'realtime', color: '#673ab7' },
        { type: 'alert-list', name: 'Alert List', icon: <Notifications />, category: 'alerts', color: '#e91e63' },
        { type: 'top-n', name: 'Top N Ranking', icon: <TrendingUp />, category: 'analytics', color: '#009688' },
        { type: 'heatmap', name: 'Heatmap', icon: <GridOn />, category: 'analytics', color: '#ff5722' },
        { type: 'timeline', name: 'Timeline', icon: <Timeline />, category: 'analytics', color: '#795548' },
        { type: 'geo-map', name: 'Geographic Map', icon: <Map />, category: 'geo', color: '#607d8b' }
      ]);

      // Load templates
      setTemplates([
        { id: 'security-overview', name: 'Security Overview', category: 'security' },
        { id: 'executive-summary', name: 'Executive Summary', category: 'executive' },
        { id: 'soc-operations', name: 'SOC Operations', category: 'operations' }
      ]);

      setLoading(false);
    } catch (error) {
      console.error('Error loading data:', error);
      setError('Erro ao carregar dashboards');
      setLoading(false);
    }
  };

  const handleLoadDashboard = async (dashboardId) => {
    try {
      setLoading(true);
      
      // Try to load from API first
      try {
        const response = await dashboardsAPI.get(dashboardId);
        const dashboard = response.data;
        
        setCurrentDashboard(dashboard);
        setWidgets(dashboard.widgets || []);
        setLayout((dashboard.widgets || []).map(w => ({ i: w.i, x: w.x, y: w.y, w: w.w, h: w.h })));
        setLoading(false);
        return;
      } catch (apiError) {
        console.log('Dashboard not found in API, using mock data');
      }

      // Fallback to mock data
      const dashboardFromList = dashboards.find(d => d.id === dashboardId);
      
      if (!dashboardFromList) {
        console.error('Dashboard not found');
        setLoading(false);
        return;
      }

      const dashboard = {
        id: dashboardId,
        name: dashboardFromList.name,
        description: dashboardFromList.description,
        widgets: dashboardFromList.widgets === 0 ? [] : [
          {
            i: 'w1',
            x: 0,
            y: 0,
            w: 3,
            h: 2,
            type: 'kpi',
            title: 'Active Alerts',
            data: { value: 127, trend: '+12%' }
          },
          {
            i: 'w2',
            x: 3,
            y: 0,
            w: 3,
            h: 2,
            type: 'kpi',
            title: 'Events/Second',
            data: { value: 342, trend: '+5%' }
          },
          {
            i: 'w3',
            x: 6,
            y: 0,
            w: 6,
            h: 4,
            type: 'line-chart',
            title: 'Event Trends'
          },
          {
            i: 'w4',
            x: 0,
            y: 2,
            w: 6,
            h: 4,
            type: 'pie-chart',
            title: 'Alerts by Severity'
          },
        ]
      };

      setCurrentDashboard(dashboard);
      setWidgets(dashboard.widgets);
      setLayout(dashboard.widgets.map(w => ({ i: w.i, x: w.x, y: w.y, w: w.w, h: w.h })));
    } catch (error) {
      console.error('Error loading dashboard:', error);
    }
  };

  const handleAddWidget = (widgetType) => {
    const newWidget = {
      i: `w-${Date.now()}`,
      x: (widgets.length * 2) % 12,
      y: Math.floor(widgets.length / 6) * 2,
      w: widgetType.type === 'kpi' ? 3 : 6,
      h: widgetType.type === 'kpi' ? 2 : 4,
      type: widgetType.type,
      title: widgetType.name
    };

    setWidgets([...widgets, newWidget]);
    setLayout([...layout, { i: newWidget.i, x: newWidget.x, y: newWidget.y, w: newWidget.w, h: newWidget.h }]);
  };

  const handleDeleteWidget = (widgetId) => {
    setWidgets(widgets.filter(w => w.i !== widgetId));
    setLayout(layout.filter(l => l.i !== widgetId));
    setContextMenu(null);
  };

  const handleLayoutChange = (newLayout) => {
    setLayout(newLayout);
  };

  const handleSaveDashboard = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Update dashboard with current widgets and layout
      const updatedDashboard = {
        ...currentDashboard,
        widgets: widgets.map((w, idx) => {
          const layoutItem = layout.find(l => l.i === w.i);
          return {
            ...w,
            x: layoutItem?.x ?? w.x,
            y: layoutItem?.y ?? w.y,
            w: layoutItem?.w ?? w.w,
            h: layoutItem?.h ?? w.h
          };
        })
      };
      
      // Save to API
      try {
        await dashboardsAPI.update(currentDashboard.id, updatedDashboard);
        
        // Reload dashboards list from API
        const dashboardsRes = await dashboardsAPI.list();
        setDashboards(dashboardsRes.data.dashboards || []);
        
        setCurrentDashboard(updatedDashboard);
        
        // Show success message
        setError(null);
        
        // Switch to DASHBOARDS tab to show the updated list
        setActiveTab(2);
      } catch (apiError) {
        console.error('API save failed, using local state:', apiError);
        
        // Fallback: Update in local dashboards list
        const dashboardIndex = dashboards.findIndex(d => d.id === currentDashboard.id);
        
        if (dashboardIndex >= 0) {
          const updatedDashboards = [...dashboards];
          updatedDashboards[dashboardIndex] = {
            ...updatedDashboards[dashboardIndex],
            widgets: widgets.length,
            updated_at: new Date().toISOString()
          };
          setDashboards(updatedDashboards);
        }
        
        setCurrentDashboard(updatedDashboard);
        setActiveTab(2);
      }
    } catch (error) {
      console.error('Error saving dashboard:', error);
      setError('Erro ao salvar dashboard');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateDashboard = async () => {
    if (!dashboardName) {
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const newDashboardData = {
        name: dashboardName,
        description: dashboardDesc,
        is_default: dashboards.length === 0,
        widgets: []
      };

      // Try to create via API
      try {
        const response = await dashboardsAPI.create(newDashboardData);
        const createdDashboard = response.data;

        // Reload dashboards list
        const dashboardsRes = await dashboardsAPI.list();
        setDashboards(dashboardsRes.data.dashboards || []);

        setCurrentDashboard(createdDashboard);
        setWidgets([]);
        setLayout([]);
      } catch (apiError) {
        console.error('API create failed, using local state:', apiError);

        // Fallback: Create locally
        const newDashboard = {
          id: `dash-${Date.now()}`,
          name: dashboardName,
          description: dashboardDesc,
          isDefault: dashboards.length === 0,
          widgets: 0
        };

        const newDashboardFull = {
          id: newDashboard.id,
          name: dashboardName,
          description: dashboardDesc,
          widgets: []
        };

        setDashboards([...dashboards, newDashboard]);
        setCurrentDashboard(newDashboardFull);
        setWidgets([]);
        setLayout([]);
      }

      // Close dialog and clear form
      setDialogOpen(false);
      setDashboardName('');
      setDashboardDesc('');
    } catch (error) {
      console.error('Error creating dashboard:', error);
      setError('Erro ao criar dashboard');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateFromTemplate = async (templateId) => {
    try {
      // Load template and create dashboard
      alert(`Creating dashboard from template: ${templateId}`);
      setActiveTab(0);
    } catch (error) {
      console.error('Error creating from template:', error);
    }
  };

  const renderWidget = (widget) => {
    const widgetType = widgetTypes.find(t => t.type === widget.type);
    const color = widgetType?.color || '#2196f3';

    return (
      <Card
        key={widget.i}
        sx={{
          height: '100%',
          cursor: editMode ? 'move' : 'default',
          border: editMode ? '2px dashed #90caf9' : '1px solid rgba(255,255,255,0.12)',
          '&:hover': editMode ? { borderColor: '#2196f3' } : {}
        }}
        onContextMenu={(e) => {
          if (editMode) {
            e.preventDefault();
            setSelectedWidget(widget);
            setContextMenu({
              mouseX: e.clientX - 2,
              mouseY: e.clientY - 4,
            });
          }
        }}
      >
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6" sx={{ fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box sx={{ color }}>{widgetType?.icon}</Box>
              {widget.title}
            </Typography>
            {editMode && (
              <DragIndicator sx={{ color: 'text.secondary', cursor: 'grab' }} />
            )}
          </Box>
          
          {/* Widget Content Preview */}
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 100 }}>
            {widget.type === 'kpi' && widget.data && (
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" sx={{ color }}>{widget.data.value}</Typography>
                <Typography variant="caption" color="success.main">{widget.data.trend}</Typography>
              </Box>
            )}
            {widget.type.includes('chart') && (
              <Typography variant="body2" color="text.secondary">
                [{widget.type.toUpperCase()}]
              </Typography>
            )}
            {!widget.data && !widget.type.includes('chart') && (
              <Typography variant="body2" color="text.secondary">
                {widget.type}
              </Typography>
            )}
          </Box>
        </CardContent>
      </Card>
    );
  };

  return (
    <Container maxWidth="xl">
      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Dashboard Customizer
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {currentDashboard ? `Editing: ${currentDashboard.name}` : 'Create and customize your dashboards'}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <FormControlLabel
            control={<Switch checked={editMode} onChange={(e) => setEditMode(e.target.checked)} />}
            label="Edit Mode"
          />
          {currentDashboard && (
            <>
              <Button 
                variant="outlined" 
                startIcon={<Save />} 
                onClick={() => {
                  alert('💾 Botão SAVE clicado!');
                  handleSaveDashboard();
                }}
                disabled={loading}
              >
                Save
              </Button>
              <Button variant="outlined" startIcon={<Download />}>Export</Button>
            </>
          )}
          <Button variant="contained" startIcon={<Add />} onClick={() => {
            alert('🔵 Botão NEW DASHBOARD clicado!');
            setDialogOpen(true);
          }}>
            New Dashboard
          </Button>
          <IconButton onClick={() => setDrawerOpen(!drawerOpen)}>
            <Widgets />
          </IconButton>
        </Box>
      </Box>

      <Box sx={{ display: 'flex', gap: 2 }}>
        {/* Main Content */}
        <Box sx={{ flexGrow: 1 }}>
          {currentDashboard ? (
            <GridLayout
              className="layout"
              layout={layout}
              onLayoutChange={handleLayoutChange}
              cols={12}
              rowHeight={60}
              width={1200}
              isDraggable={editMode}
              isResizable={editMode}
              compactType="vertical"
              preventCollision={false}
            >
              {widgets.map(renderWidget)}
            </GridLayout>
          ) : (
            <Card sx={{ p: 8, textAlign: 'center' }}>
              <DashboardIcon sx={{ fontSize: 80, color: 'text.secondary', mb: 2 }} />
              <Typography variant="h5" gutterBottom>No Dashboard Selected</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Create a new dashboard or load an existing one to get started
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
                <Button variant="contained" startIcon={<Add />} onClick={() => setDialogOpen(true)}>
                  Create Dashboard
                </Button>
                {dashboards.length > 0 && (
                  <Button variant="outlined" onClick={() => handleLoadDashboard(dashboards[0].id)}>
                    Load Dashboard
                  </Button>
                )}
              </Box>
            </Card>
          )}
        </Box>

        {/* Right Drawer - Widget Library */}
        <Drawer
          anchor="right"
          variant="persistent"
          open={drawerOpen}
          sx={{
            width: 320,
            flexShrink: 0,
            '& .MuiDrawer-paper': {
              width: 320,
              boxSizing: 'border-box',
              position: 'relative',
              height: 'auto',
              border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: 1,
            },
          }}
        >
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Widgets & Templates</Typography>
              <IconButton size="small" onClick={() => setDrawerOpen(false)}>
                <Close />
              </IconButton>
            </Box>

            <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ mb: 2 }}>
              <Tab label="Widgets" />
              <Tab label="Templates" />
              <Tab label="Dashboards" />
            </Tabs>

            {/* Tab: Widgets */}
            {activeTab === 0 && (
              <List>
                {widgetTypes.map((widget) => (
                  <ListItemButton
                    key={widget.type}
                    onClick={() => editMode && currentDashboard && handleAddWidget(widget)}
                    disabled={!editMode || !currentDashboard}
                    sx={{
                      border: '1px solid rgba(255,255,255,0.12)',
                      borderRadius: 1,
                      mb: 1,
                      '&:hover': { borderColor: widget.color }
                    }}
                  >
                    <ListItemIcon sx={{ color: widget.color }}>
                      {widget.icon}
                    </ListItemIcon>
                    <ListItemText
                      primary={widget.name}
                      secondary={widget.category}
                    />
                    {editMode && currentDashboard && <Add fontSize="small" />}
                  </ListItemButton>
                ))}
              </List>
            )}

            {/* Tab: Templates */}
            {activeTab === 1 && (
              <List>
                {templates.map((template) => (
                  <ListItem key={template.id} sx={{ border: '1px solid rgba(255,255,255,0.12)', borderRadius: 1, mb: 1 }}>
                    <ListItemText
                      primary={template.name}
                      secondary={template.category}
                    />
                    <Button size="small" onClick={() => handleCreateFromTemplate(template.id)}>
                      Use
                    </Button>
                  </ListItem>
                ))}
              </List>
            )}

            {/* Tab: Dashboards */}
            {activeTab === 2 && (
              <List key={`dashboards-list-${dashboards.length}-${Date.now()}`}>
                {dashboards.map((dashboard, index) => (
                  <ListItemButton
                    key={`${dashboard.id}-${index}-${dashboard.widgets}`}
                    onClick={() => handleLoadDashboard(dashboard.id)}
                    selected={currentDashboard?.id === dashboard.id}
                    sx={{ border: '1px solid rgba(255,255,255,0.12)', borderRadius: 1, mb: 1 }}
                  >
                    <ListItemIcon>
                      <DashboardIcon />
                    </ListItemIcon>
                    <ListItemText
                      primary={dashboard.name}
                      secondary={`${dashboard.widgets} widgets`}
                    />
                    {dashboard.isDefault && <Chip label="Default" size="small" color="primary" />}
                  </ListItemButton>
                ))}
              </List>
            )}
          </Box>
        </Drawer>
      </Box>

      {/* Create Dashboard Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Dashboard</DialogTitle>
        <DialogContent>
          <TextField
            label="Dashboard Name"
            fullWidth
            value={dashboardName}
            onChange={(e) => setDashboardName(e.target.value)}
            sx={{ mt: 2, mb: 2 }}
          />
          <TextField
            label="Description (optional)"
            fullWidth
            multiline
            rows={3}
            value={dashboardDesc}
            onChange={(e) => setDashboardDesc(e.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={() => {
              alert('🟢 Botão CREATE clicado!');
              handleCreateDashboard();
            }}
            disabled={!dashboardName}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* Widget Context Menu */}
      <Menu
        open={contextMenu !== null}
        onClose={() => setContextMenu(null)}
        anchorReference="anchorPosition"
        anchorPosition={
          contextMenu !== null
            ? { top: contextMenu.mouseY, left: contextMenu.mouseX }
            : undefined
        }
      >
        <MenuItem onClick={() => selectedWidget && handleDeleteWidget(selectedWidget.i)}>
          <ListItemIcon><Delete fontSize="small" /></ListItemIcon>
          Delete Widget
        </MenuItem>
        <MenuItem onClick={() => setContextMenu(null)}>
          <ListItemIcon><ContentCopy fontSize="small" /></ListItemIcon>
          Duplicate
        </MenuItem>
        <MenuItem onClick={() => setContextMenu(null)}>
          <ListItemIcon><Settings fontSize="small" /></ListItemIcon>
          Configure
        </MenuItem>
      </Menu>
    </Container>
  );
};

export default DashboardCustomizer;

