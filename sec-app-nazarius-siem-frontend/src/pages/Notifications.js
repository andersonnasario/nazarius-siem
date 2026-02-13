import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Badge,
  IconButton,
  Button,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Switch,
  FormControlLabel,
  Grid,
  Card,
  CardContent,
  Divider,
  Menu,
  Tooltip,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Delete as DeleteIcon,
  MarkEmailRead as MarkEmailReadIcon,
  Settings as SettingsIcon,
  Add as AddIcon,
  Edit as EditIcon,
  FilterList as FilterListIcon,
  Security as SecurityIcon,
  Computer as ComputerIcon,
  Description as DescriptionIcon,
  Email as EmailIcon,
  Sms as SmsIcon,
  Webhook as WebhookIcon,
  NotificationsActive as NotificationsActiveIcon,
} from '@mui/icons-material';
import { notificationsAPI } from '../services/api';

// ============================================================================
// MAIN NOTIFICATIONS PAGE
// ============================================================================

const NotificationsPage = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [notifications, setNotifications] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('all'); // all, unread, type, category
  const [selectedCategory, setSelectedCategory] = useState('all');
  
  // Dialogs
  const [ruleDialog, setRuleDialog] = useState(false);
  const [templateDialog, setTemplateDialog] = useState(false);
  const [channelDialog, setChannelDialog] = useState(false);

  // Rules, Templates, Channels
  const [rules, setRules] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [channels, setChannels] = useState([]);

  useEffect(() => {
    loadData();
  }, [filter, selectedCategory]);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Load notifications
      const params = {
        user_id: 'user-1', // TODO: Get from auth context
      };
      
      if (filter === 'unread') {
        params.unread = true;
      }
      
      if (selectedCategory !== 'all') {
        params.category = selectedCategory;
      }
      
      const notifData = await notificationsAPI.getAll(params);
      setNotifications(notifData.notifications || []);
      
      // Load stats
      const statsData = await notificationsAPI.getStats('user-1');
      setStats(statsData);
      
      // Load rules, templates, channels (only on first load)
      if (rules.length === 0) {
        const rulesData = await notificationsAPI.getRules();
        setRules(rulesData.rules || []);
      }
      
      if (templates.length === 0) {
        const templatesData = await notificationsAPI.getTemplates();
        setTemplates(templatesData.templates || []);
      }
      
      if (channels.length === 0) {
        const channelsData = await notificationsAPI.getChannels();
        setChannels(channelsData.channels || []);
      }
      
    } catch (error) {
      console.error('Error loading notifications:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleMarkAsRead = async (id) => {
    try {
      await notificationsAPI.markAsRead(id);
      setNotifications(notifications.map(n => 
        n.id === id ? { ...n, read: true, read_at: new Date().toISOString() } : n
      ));
      if (stats) {
        setStats({ ...stats, unread: stats.unread - 1 });
      }
    } catch (error) {
      console.error('Error marking as read:', error);
    }
  };

  const handleMarkAllAsRead = async () => {
    try {
      await notificationsAPI.markAllAsRead('user-1');
      setNotifications(notifications.map(n => ({ ...n, read: true, read_at: new Date().toISOString() })));
      if (stats) {
        setStats({ ...stats, unread: 0 });
      }
    } catch (error) {
      console.error('Error marking all as read:', error);
    }
  };

  const handleDelete = async (id) => {
    try {
      await notificationsAPI.delete(id);
      setNotifications(notifications.filter(n => n.id !== id));
      if (stats) {
        setStats({ ...stats, total: stats.total - 1 });
      }
    } catch (error) {
      console.error('Error deleting notification:', error);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <NotificationsIcon sx={{ fontSize: 40, color: 'primary.main' }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Notifications
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Manage your notifications, rules, and channels
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<MarkEmailReadIcon />}
            onClick={handleMarkAllAsRead}
            disabled={!stats || stats.unread === 0}
          >
            Mark All as Read
          </Button>
          <Button
            variant="contained"
            startIcon={<SettingsIcon />}
            onClick={() => setActiveTab(2)}
          >
            Settings
          </Button>
        </Box>
      </Box>

      {/* Stats Cards */}
      {stats && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Total
                    </Typography>
                    <Typography variant="h4" fontWeight="bold">
                      {stats.total}
                    </Typography>
                  </Box>
                  <NotificationsIcon sx={{ fontSize: 40, color: 'primary.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Unread
                    </Typography>
                    <Typography variant="h4" fontWeight="bold" color="warning.main">
                      {stats.unread}
                    </Typography>
                  </Box>
                  <NotificationsActiveIcon sx={{ fontSize: 40, color: 'warning.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Recent (24h)
                    </Typography>
                    <Typography variant="h4" fontWeight="bold" color="info.main">
                      {stats.recent}
                    </Typography>
                  </Box>
                  <InfoIcon sx={{ fontSize: 40, color: 'info.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2">
                      Critical
                    </Typography>
                    <Typography variant="h4" fontWeight="bold" color="error.main">
                      {stats.by_severity?.critical || 0}
                    </Typography>
                  </Box>
                  <ErrorIcon sx={{ fontSize: 40, color: 'error.main', opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Main Content */}
      <Paper sx={{ width: '100%' }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label={<Badge badgeContent={stats?.unread || 0} color="error">Notifications</Badge>} />
          <Tab label="Rules" />
          <Tab label="Templates" />
          <Tab label="Channels" />
        </Tabs>
        
        <Divider />

        {/* Tab: Notifications */}
        {activeTab === 0 && (
          <Box sx={{ p: 2 }}>
            {/* Filters */}
            <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Status</InputLabel>
                <Select value={filter} onChange={(e) => setFilter(e.target.value)} label="Status">
                  <MenuItem value="all">All</MenuItem>
                  <MenuItem value="unread">Unread Only</MenuItem>
                </Select>
              </FormControl>
              
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Category</InputLabel>
                <Select value={selectedCategory} onChange={(e) => setSelectedCategory(e.target.value)} label="Category">
                  <MenuItem value="all">All Categories</MenuItem>
                  <MenuItem value="security">Security</MenuItem>
                  <MenuItem value="system">System</MenuItem>
                  <MenuItem value="alert">Alert</MenuItem>
                  <MenuItem value="report">Report</MenuItem>
                </Select>
              </FormControl>
            </Box>

            {/* Notifications List */}
            <List>
              {notifications.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                  <NotificationsIcon sx={{ fontSize: 60, color: 'text.disabled', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary">
                    No notifications found
                  </Typography>
                </Box>
              ) : (
                notifications.map((notif) => (
                  <NotificationItem
                    key={notif.id}
                    notification={notif}
                    onMarkAsRead={handleMarkAsRead}
                    onDelete={handleDelete}
                  />
                ))
              )}
            </List>
          </Box>
        )}

        {/* Tab: Rules */}
        {activeTab === 1 && (
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="h6">Notification Rules</Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => setRuleDialog(true)}
              >
                Add Rule
              </Button>
            </Box>
            
            <List>
              {rules.length === 0 ? (
                <Typography color="text.secondary" sx={{ p: 2 }}>
                  No rules configured
                </Typography>
              ) : (
                rules.map((rule) => (
                  <RuleItem key={rule.id} rule={rule} onRefresh={loadData} />
                ))
              )}
            </List>
          </Box>
        )}

        {/* Tab: Templates */}
        {activeTab === 2 && (
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="h6">Notification Templates</Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => setTemplateDialog(true)}
              >
                Add Template
              </Button>
            </Box>
            
            <Grid container spacing={2}>
              {templates.length === 0 ? (
                <Grid item xs={12}>
                  <Typography color="text.secondary" sx={{ p: 2 }}>
                    No templates configured
                  </Typography>
                </Grid>
              ) : (
                templates.map((template) => (
                  <Grid item xs={12} md={6} key={template.id}>
                    <TemplateCard template={template} onRefresh={loadData} />
                  </Grid>
                ))
              )}
            </Grid>
          </Box>
        )}

        {/* Tab: Channels */}
        {activeTab === 3 && (
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="h6">Notification Channels</Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => setChannelDialog(true)}
              >
                Add Channel
              </Button>
            </Box>
            
            <Grid container spacing={2}>
              {channels.length === 0 ? (
                <Grid item xs={12}>
                  <Typography color="text.secondary" sx={{ p: 2 }}>
                    No channels configured
                  </Typography>
                </Grid>
              ) : (
                channels.map((channel) => (
                  <Grid item xs={12} md={6} key={channel.id}>
                    <ChannelCard channel={channel} onRefresh={loadData} />
                  </Grid>
                ))
              )}
            </Grid>
          </Box>
        )}
      </Paper>
    </Box>
  );
};

// ============================================================================
// NOTIFICATION ITEM COMPONENT
// ============================================================================

const NotificationItem = ({ notification, onMarkAsRead, onDelete }) => {
  const getIcon = () => {
    switch (notification.type) {
      case 'error':
        return <ErrorIcon sx={{ color: 'error.main' }} />;
      case 'warning':
        return <WarningIcon sx={{ color: 'warning.main' }} />;
      case 'success':
        return <CheckCircleIcon sx={{ color: 'success.main' }} />;
      default:
        return <InfoIcon sx={{ color: 'info.main' }} />;
    }
  };

  const getCategoryIcon = () => {
    switch (notification.category) {
      case 'security':
        return <SecurityIcon fontSize="small" />;
      case 'system':
        return <ComputerIcon fontSize="small" />;
      case 'report':
        return <DescriptionIcon fontSize="small" />;
      default:
        return <NotificationsIcon fontSize="small" />;
    }
  };

  return (
    <ListItem
      sx={{
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 1,
        mb: 1,
        bgcolor: notification.read ? 'transparent' : 'action.hover',
        opacity: notification.read ? 0.7 : 1,
      }}
      secondaryAction={
        <Box sx={{ display: 'flex', gap: 1 }}>
          {!notification.read && (
            <Tooltip title="Mark as read">
              <IconButton size="small" onClick={() => onMarkAsRead(notification.id)}>
                <MarkEmailReadIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
          <Tooltip title="Delete">
            <IconButton size="small" onClick={() => onDelete(notification.id)}>
              <DeleteIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      }
    >
      <ListItemIcon>{getIcon()}</ListItemIcon>
      <ListItemText
        primary={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
            <Typography variant="subtitle1" fontWeight={notification.read ? 'normal' : 'bold'}>
              {notification.title}
            </Typography>
            <Chip
              label={notification.severity}
              size="small"
              color={
                notification.severity === 'critical' ? 'error' :
                notification.severity === 'high' ? 'warning' :
                notification.severity === 'medium' ? 'info' : 'default'
              }
            />
            <Chip
              icon={getCategoryIcon()}
              label={notification.category}
              size="small"
              variant="outlined"
            />
          </Box>
        }
        secondary={
          <Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              {notification.message}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="caption" color="text.disabled">
                {new Date(notification.created_at).toLocaleString()}
              </Typography>
              {notification.source && (
                <>
                  <Typography variant="caption" color="text.disabled">•</Typography>
                  <Typography variant="caption" color="text.disabled">
                    {notification.source}
                  </Typography>
                </>
              )}
            </Box>
            {notification.action_url && (
              <Button
                size="small"
                variant="outlined"
                sx={{ mt: 1 }}
                href={notification.action_url}
              >
                {notification.action_label || 'View Details'}
              </Button>
            )}
          </Box>
        }
      />
    </ListItem>
  );
};

// ============================================================================
// RULE ITEM COMPONENT
// ============================================================================

const RuleItem = ({ rule, onRefresh }) => {
  const handleToggle = async () => {
    try {
      await notificationsAPI.updateRule(rule.id, { ...rule, enabled: !rule.enabled });
      onRefresh();
    } catch (error) {
      console.error('Error toggling rule:', error);
    }
  };

  return (
    <ListItem
      sx={{
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 1,
        mb: 1,
      }}
    >
      <ListItemText
        primary={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="subtitle1" fontWeight="bold">
              {rule.name}
            </Typography>
            <Chip
              label={rule.enabled ? 'Enabled' : 'Disabled'}
              size="small"
              color={rule.enabled ? 'success' : 'default'}
            />
            <Chip label={`Priority: ${rule.priority}`} size="small" variant="outlined" />
          </Box>
        }
        secondary={
          <Box>
            <Typography variant="body2" color="text.secondary">
              {rule.description}
            </Typography>
            <Typography variant="caption" color="text.disabled" sx={{ mt: 1, display: 'block' }}>
              {rule.conditions?.length || 0} conditions • {rule.actions?.length || 0} actions
              {rule.cooldown > 0 && ` • ${rule.cooldown}min cooldown`}
            </Typography>
          </Box>
        }
      />
      <Box sx={{ display: 'flex', gap: 1 }}>
        <Switch checked={rule.enabled} onChange={handleToggle} />
      </Box>
    </ListItem>
  );
};

// ============================================================================
// TEMPLATE CARD COMPONENT
// ============================================================================

const TemplateCard = ({ template, onRefresh }) => {
  const getIcon = () => {
    switch (template.type) {
      case 'email':
        return <EmailIcon />;
      case 'sms':
        return <SmsIcon />;
      case 'webhook':
        return <WebhookIcon />;
      default:
        return <NotificationsIcon />;
    }
  };

  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {getIcon()}
            <Box>
              <Typography variant="h6">{template.name}</Typography>
              <Chip label={template.type} size="small" />
            </Box>
          </Box>
        </Box>
        
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {template.description}
        </Typography>
        
        {template.subject && (
          <Typography variant="caption" color="text.disabled" sx={{ display: 'block', mb: 1 }}>
            <strong>Subject:</strong> {template.subject}
          </Typography>
        )}
        
        <Typography variant="caption" color="text.disabled" sx={{ display: 'block' }}>
          <strong>Variables:</strong> {template.variables?.join(', ') || 'None'}
        </Typography>
      </CardContent>
    </Card>
  );
};

// ============================================================================
// CHANNEL CARD COMPONENT
// ============================================================================

const ChannelCard = ({ channel, onRefresh }) => {
  const getIcon = () => {
    switch (channel.type) {
      case 'email':
        return <EmailIcon sx={{ fontSize: 40 }} />;
      case 'sms':
        return <SmsIcon sx={{ fontSize: 40 }} />;
      case 'webhook':
        return <WebhookIcon sx={{ fontSize: 40 }} />;
      default:
        return <NotificationsIcon sx={{ fontSize: 40 }} />;
    }
  };

  const handleToggle = async () => {
    try {
      await notificationsAPI.updateChannel(channel.id, { ...channel, enabled: !channel.enabled });
      onRefresh();
    } catch (error) {
      console.error('Error toggling channel:', error);
    }
  };

  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Box sx={{ color: channel.enabled ? 'primary.main' : 'text.disabled' }}>
              {getIcon()}
            </Box>
            <Box>
              <Typography variant="h6">{channel.name}</Typography>
              <Chip
                label={channel.enabled ? 'Active' : 'Inactive'}
                size="small"
                color={channel.enabled ? 'success' : 'default'}
              />
            </Box>
          </Box>
          <Switch checked={channel.enabled} onChange={handleToggle} />
        </Box>
        
        <Typography variant="body2" color="text.secondary" fontWeight="bold" sx={{ mb: 1 }}>
          {channel.type.toUpperCase()}
        </Typography>
        
        <Typography variant="caption" color="text.disabled">
          Configured {new Date(channel.created_at).toLocaleDateString()}
        </Typography>
      </CardContent>
    </Card>
  );
};

export default NotificationsPage;
