import React, { useState, useEffect } from 'react';
import {
  IconButton,
  Badge,
  Menu,
  MenuItem,
  ListItemText,
  ListItemIcon,
  Typography,
  Box,
  Divider,
  Button,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { notificationsAPI } from '../services/api';

const NotificationBadge = () => {
  const [anchorEl, setAnchorEl] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const navigate = useNavigate();

  useEffect(() => {
    loadNotifications();
    // Poll for new notifications every 30 seconds
    const interval = setInterval(loadNotifications, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadNotifications = async () => {
    try {
      const response = await notificationsAPI.getAll({ user_id: 'user-1', limit: 10 });
      const recentNotifications = response.notifications || [];
      setNotifications(recentNotifications);
      
      // Get stats for unread count
      const stats = await notificationsAPI.getStats('user-1');
      setUnreadCount(stats.unread || 0);
    } catch (error) {
      console.error('Error loading notifications:', error);
    }
  };

  const handleClick = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleViewAll = () => {
    handleClose();
    navigate('/notifications');
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return <ErrorIcon color="error" fontSize="small" />;
      case 'high':
        return <WarningIcon color="warning" fontSize="small" />;
      case 'medium':
        return <InfoIcon color="info" fontSize="small" />;
      case 'low':
        return <CheckCircleIcon color="success" fontSize="small" />;
      default:
        return <InfoIcon fontSize="small" />;
    }
  };

  return (
    <>
      <IconButton color="inherit" onClick={handleClick}>
        <Badge badgeContent={unreadCount} color="error">
          <NotificationsIcon />
        </Badge>
      </IconButton>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
        PaperProps={{
          sx: { width: 360, maxHeight: 500 },
        }}
      >
        <Box sx={{ px: 2, py: 1 }}>
          <Typography variant="h6">Notificações</Typography>
        </Box>
        <Divider />

        {notifications.length === 0 ? (
          <MenuItem disabled>
            <ListItemText primary="Nenhuma notificação recente" />
          </MenuItem>
        ) : (
          notifications.slice(0, 5).map((notif) => (
            <MenuItem key={notif.id} onClick={handleClose}>
              <ListItemIcon>{getSeverityIcon(notif.severity)}</ListItemIcon>
              <ListItemText
                primary={notif.title}
                secondary={
                  <>
                    <Typography variant="caption" display="block">
                      {notif.message.substring(0, 60)}...
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {new Date(notif.created_at).toLocaleString('pt-BR')}
                    </Typography>
                  </>
                }
              />
            </MenuItem>
          ))
        )}

        <Divider />
        <Box sx={{ p: 1, textAlign: 'center' }}>
          <Button size="small" onClick={handleViewAll}>
            Ver Todas
          </Button>
        </Box>
      </Menu>
    </>
  );
};

export default NotificationBadge;

