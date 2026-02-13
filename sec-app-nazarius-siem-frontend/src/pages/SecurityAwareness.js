import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Paper, Grid, Card, CardContent, Tabs, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, CircularProgress, Alert, LinearProgress, IconButton, Tooltip,
  Avatar, List, ListItem, ListItemAvatar, ListItemText
} from '@mui/material';
import {
  Email as EmailIcon,
  School as SchoolIcon,
  Person as PersonIcon,
  EmojiEvents as TrophyIcon,
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Visibility as VisibilityIcon,
  Security as SecurityIcon
} from '@mui/icons-material';
import { securityAwarenessAPI } from '../services/api';
import DetailsDialog from '../components/DetailsDialog';

const SecurityAwareness = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [campaigns, setCampaigns] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [trainings, setTrainings] = useState([]);
  const [users, setUsers] = useState([]);
  const [leaderboard, setLeaderboard] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Details Dialog States
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsTitle, setDetailsTitle] = useState('');
  const [detailsData, setDetailsData] = useState(null);
  const [detailsFields, setDetailsFields] = useState([]);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [campaignsRes, templatesRes, trainingsRes, usersRes, leaderboardRes, metricsRes] = await Promise.all([
        securityAwarenessAPI.listCampaigns(),
        securityAwarenessAPI.listTemplates(),
        securityAwarenessAPI.listTrainings(),
        securityAwarenessAPI.listUsers(),
        securityAwarenessAPI.getLeaderboard(),
        securityAwarenessAPI.getMetrics(),
      ]);

      setCampaigns(campaignsRes.data.data || []);
      setTemplates(templatesRes.data.data || []);
      setTrainings(trainingsRes.data.data || []);
      setUsers(usersRes.data.data || []);
      setLeaderboard(leaderboardRes.data.data || []);
      setMetrics(metricsRes.data.data || {});
      setError(null);
    } catch (err) {
      setError('Failed to load security awareness data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleViewCampaign = (campaign) => {
    setDetailsData(campaign);
    setDetailsTitle(`Campaign: ${campaign.name}`);
    setDetailsFields([
      { label: 'Campaign ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Status', key: 'status', type: 'badge' },
      { label: 'Template ID', key: 'template_id', type: 'text' },
      { label: 'Target Groups', key: 'target_groups', type: 'array' },
      { label: 'Total Targets', key: 'total_targets', type: 'text' },
      { label: 'Emails Sent', key: 'emails_sent', type: 'text' },
      { label: 'Emails Opened', key: 'emails_opened', type: 'text' },
      { label: 'Links Clicked', key: 'links_clicked', type: 'text' },
      { label: 'Data Submitted', key: 'data_submitted', type: 'text' },
      { label: 'Reported', key: 'reported', type: 'text' },
      { label: 'Click Rate (%)', key: 'click_rate', type: 'text' },
      { label: 'Report Rate (%)', key: 'report_rate', type: 'text' },
      { label: 'Start Date', key: 'start_date', type: 'date' },
      { label: 'End Date', key: 'end_date', type: 'date' },
      { label: 'Created By', key: 'created_by', type: 'text' },
      { label: 'Created At', key: 'created_at', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewTemplate = (template) => {
    setDetailsData(template);
    setDetailsTitle(`Template: ${template.name}`);
    setDetailsFields([
      { label: 'Template ID', key: 'id', type: 'text' },
      { label: 'Name', key: 'name', type: 'text' },
      { label: 'Category', key: 'category', type: 'badge' },
      { label: 'Difficulty', key: 'difficulty', type: 'badge' },
      { label: 'Subject', key: 'subject', type: 'text', fullWidth: true },
      { label: 'From Name', key: 'from_name', type: 'text' },
      { label: 'From Email', key: 'from_email', type: 'text' },
      { label: 'Body', key: 'body', type: 'text', fullWidth: true },
      { label: 'Landing Page', key: 'landing_page', type: 'text', fullWidth: true },
      { label: 'Language', key: 'language', type: 'text' },
      { label: 'Tags', key: 'tags', type: 'array' },
      { label: 'Created At', key: 'created_at', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewTraining = (training) => {
    setDetailsData(training);
    setDetailsTitle(`Training: ${training.title}`);
    setDetailsFields([
      { label: 'Training ID', key: 'id', type: 'text' },
      { label: 'Title', key: 'title', type: 'text' },
      { label: 'Description', key: 'description', type: 'text', fullWidth: true },
      { label: 'Category', key: 'category', type: 'badge' },
      { label: 'Difficulty', key: 'difficulty', type: 'badge' },
      { label: 'Duration (min)', key: 'duration', type: 'text' },
      { label: 'Quiz Questions', key: 'quiz_questions', type: 'text' },
      { label: 'Passing Score', key: 'passing_score', type: 'text' },
      { label: 'Enrolled', key: 'enrolled', type: 'text' },
      { label: 'Completed', key: 'completed', type: 'text' },
      { label: 'Average Score', key: 'average_score', type: 'text' },
      { label: 'Completion Rate (%)', key: 'completion_rate', type: 'text' },
      { label: 'Mandatory', key: 'mandatory', type: 'status' },
      { label: 'Content URL', key: 'content_url', type: 'text', fullWidth: true },
      { label: 'Created At', key: 'created_at', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const handleViewUser = (user) => {
    setDetailsData(user);
    setDetailsTitle(`User Risk Profile: ${user.username}`);
    setDetailsFields([
      { label: 'User ID', key: 'user_id', type: 'text' },
      { label: 'Username', key: 'username', type: 'text' },
      { label: 'Email', key: 'email', type: 'text' },
      { label: 'Department', key: 'department', type: 'text' },
      { label: 'Risk Score', key: 'risk_score', type: 'text' },
      { label: 'Risk Level', key: 'risk_level', type: 'badge' },
      { label: 'Phishing Tests', key: 'phishing_tests', type: 'text' },
      { label: 'Phishing Failed', key: 'phishing_failed', type: 'text' },
      { label: 'Phishing Reported', key: 'phishing_reported', type: 'text' },
      { label: 'Trainings Assigned', key: 'trainings_assigned', type: 'text' },
      { label: 'Trainings Completed', key: 'trainings_completed', type: 'text' },
      { label: 'Avg Training Score', key: 'average_training_score', type: 'text' },
      { label: 'Last Incident', key: 'last_incident', type: 'date' },
      { label: 'Last Training', key: 'last_training', type: 'date' },
      { label: 'Updated At', key: 'updated_at', type: 'date' },
    ]);
    setDetailsOpen(true);
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'success',
      completed: 'info',
      draft: 'default',
      paused: 'warning',
    };
    return colors[status] || 'default';
  };

  const getRiskColor = (level) => {
    const colors = {
      critical: 'error',
      high: 'error',
      medium: 'warning',
      low: 'success',
    };
    return colors[level] || 'default';
  };

  const getDifficultyColor = (difficulty) => {
    const colors = {
      easy: 'success',
      beginner: 'success',
      medium: 'warning',
      intermediate: 'warning',
      hard: 'error',
      advanced: 'error',
    };
    return colors[difficulty] || 'default';
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Typography variant="h4" gutterBottom>
        🎓 Security Awareness
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Metrics Cards */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Avg Click Rate
                  </Typography>
                  <Typography variant="h4">{metrics.avg_click_rate?.toFixed(1) || 0}%</Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={metrics.avg_click_rate || 0} 
                    sx={{ mt: 1 }}
                    color={metrics.avg_click_rate < 20 ? 'success' : 'error'}
                  />
                </Box>
                <EmailIcon sx={{ fontSize: 48, color: 'primary.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Avg Report Rate
                  </Typography>
                  <Typography variant="h4">{metrics.avg_report_rate?.toFixed(1) || 0}%</Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={metrics.avg_report_rate || 0} 
                    sx={{ mt: 1 }}
                    color="success"
                  />
                </Box>
                <SecurityIcon sx={{ fontSize: 48, color: 'success.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Training Completion
                  </Typography>
                  <Typography variant="h4">{metrics.training_completion_rate?.toFixed(1) || 0}%</Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={metrics.training_completion_rate || 0} 
                    sx={{ mt: 1 }}
                    color="info"
                  />
                </Box>
                <SchoolIcon sx={{ fontSize: 48, color: 'info.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    High Risk Users
                  </Typography>
                  <Typography variant="h4">{metrics.high_risk_users || 0}</Typography>
                  <Typography variant="caption" color="textSecondary">
                    of {metrics.total_users || 0} total
                  </Typography>
                </Box>
                <WarningIcon sx={{ fontSize: 48, color: 'warning.main', opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label="Phishing Campaigns" />
          <Tab label="Email Templates" />
          <Tab label="Training Modules" />
          <Tab label="User Risk Profiles" />
          <Tab label="Leaderboard" />
        </Tabs>
      </Paper>

      {/* Tab 0: Phishing Campaigns */}
      {activeTab === 0 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>
              Phishing Simulation Campaigns
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Campaign</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Targets</TableCell>
                    <TableCell>Opened</TableCell>
                    <TableCell>Clicked</TableCell>
                    <TableCell>Reported</TableCell>
                    <TableCell>Click Rate</TableCell>
                    <TableCell>Period</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {campaigns.map((campaign) => (
                    <TableRow key={campaign.id} hover>
                      <TableCell>
                        <strong>{campaign.name}</strong>
                        <br />
                        <Typography variant="caption" color="textSecondary">
                          {campaign.description}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={campaign.status} color={getStatusColor(campaign.status)} size="small" />
                      </TableCell>
                      <TableCell>{campaign.total_targets}</TableCell>
                      <TableCell>{campaign.emails_opened}</TableCell>
                      <TableCell>
                        <Chip 
                          label={campaign.links_clicked} 
                          color={campaign.links_clicked > 0 ? 'error' : 'default'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={campaign.reported} 
                          color="success" 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>
                            {campaign.click_rate.toFixed(1)}%
                          </Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={campaign.click_rate} 
                            sx={{ width: 60 }}
                            color={campaign.click_rate < 20 ? 'success' : 'error'}
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(campaign.start_date).toLocaleDateString()} - {new Date(campaign.end_date).toLocaleDateString()}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewCampaign(campaign)}>
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        </Paper>
      )}

      {/* Tab 1: Email Templates */}
      {activeTab === 1 && (
        <Grid container spacing={3}>
          {templates.map((template) => (
            <Grid item xs={12} md={6} key={template.id}>
              <Card>
                <CardContent>
                  <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
                    <Box>
                      <Typography variant="h6">{template.name}</Typography>
                      <Box mt={1}>
                        <Chip label={template.category} size="small" color="primary" sx={{ mr: 1 }} />
                        <Chip label={template.difficulty} size="small" color={getDifficultyColor(template.difficulty)} />
                      </Box>
                    </Box>
                    <Tooltip title="View Details">
                      <IconButton size="small" onClick={() => handleViewTemplate(template)}>
                        <VisibilityIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>

                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    <strong>Subject:</strong> {template.subject}
                  </Typography>
                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    <strong>From:</strong> {template.from_name} &lt;{template.from_email}&gt;
                  </Typography>
                  <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                    {template.body}
                  </Typography>

                  <Box mt={2}>
                    {template.tags.map((tag) => (
                      <Chip key={tag} label={tag} size="small" variant="outlined" sx={{ mr: 0.5, mb: 0.5 }} />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Tab 2: Training Modules */}
      {activeTab === 2 && (
        <Grid container spacing={3}>
          {trainings.map((training) => (
            <Grid item xs={12} md={6} key={training.id}>
              <Card>
                <CardContent>
                  <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
                    <Box>
                      <Typography variant="h6">{training.title}</Typography>
                      <Box mt={1}>
                        <Chip label={training.category} size="small" color="primary" sx={{ mr: 1 }} />
                        <Chip label={training.difficulty} size="small" color={getDifficultyColor(training.difficulty)} sx={{ mr: 1 }} />
                        {training.mandatory && <Chip label="Mandatory" size="small" color="error" />}
                      </Box>
                    </Box>
                    <Tooltip title="View Details">
                      <IconButton size="small" onClick={() => handleViewTraining(training)}>
                        <VisibilityIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>

                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    {training.description}
                  </Typography>

                  <Grid container spacing={2} sx={{ mt: 2 }}>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Duration</Typography>
                      <Typography variant="body2"><strong>{training.duration} min</strong></Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Enrolled</Typography>
                      <Typography variant="body2"><strong>{training.enrolled}</strong></Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Completion Rate</Typography>
                      <Typography variant="body2"><strong>{training.completion_rate.toFixed(1)}%</strong></Typography>
                      <LinearProgress 
                        variant="determinate" 
                        value={training.completion_rate} 
                        sx={{ mt: 0.5 }}
                        color="success"
                      />
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="textSecondary">Avg Score</Typography>
                      <Typography variant="body2"><strong>{training.average_score.toFixed(1)}%</strong></Typography>
                      <LinearProgress 
                        variant="determinate" 
                        value={training.average_score} 
                        sx={{ mt: 0.5 }}
                        color="info"
                      />
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Tab 3: User Risk Profiles */}
      {activeTab === 3 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>
              User Security Risk Profiles
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>User</TableCell>
                    <TableCell>Department</TableCell>
                    <TableCell>Risk Level</TableCell>
                    <TableCell>Risk Score</TableCell>
                    <TableCell>Phishing Tests</TableCell>
                    <TableCell>Training Progress</TableCell>
                    <TableCell>Avg Score</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {users.map((user) => (
                    <TableRow key={user.user_id} hover>
                      <TableCell>
                        <strong>{user.username}</strong>
                        <br />
                        <Typography variant="caption" color="textSecondary">
                          {user.email}
                        </Typography>
                      </TableCell>
                      <TableCell>{user.department}</TableCell>
                      <TableCell>
                        <Chip label={user.risk_level} color={getRiskColor(user.risk_level)} size="small" />
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2" sx={{ mr: 1 }}>
                            {user.risk_score}
                          </Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={user.risk_score} 
                            sx={{ width: 60 }}
                            color={user.risk_score < 40 ? 'success' : user.risk_score < 70 ? 'warning' : 'error'}
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          Failed: {user.phishing_failed}/{user.phishing_tests}
                        </Typography>
                        <Typography variant="caption" color="success.main">
                          Reported: {user.phishing_reported}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {user.trainings_completed}/{user.trainings_assigned}
                        </Typography>
                        <LinearProgress 
                          variant="determinate" 
                          value={(user.trainings_completed / user.trainings_assigned) * 100} 
                          sx={{ mt: 0.5 }}
                          color="info"
                        />
                      </TableCell>
                      <TableCell>{user.average_training_score.toFixed(1)}%</TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => handleViewUser(user)}>
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        </Paper>
      )}

      {/* Tab 4: Leaderboard */}
      {activeTab === 4 && (
        <Paper>
          <Box p={2}>
            <Typography variant="h6" gutterBottom>
              🏆 Security Champions Leaderboard
            </Typography>
            <List>
              {leaderboard.map((entry) => (
                <ListItem
                  key={entry.user_id}
                  sx={{
                    mb: 2,
                    border: '1px solid',
                    borderColor: 'divider',
                    borderRadius: 1,
                    bgcolor: entry.rank === 1 ? 'action.hover' : 'background.paper',
                  }}
                >
                  <ListItemAvatar>
                    <Avatar sx={{ bgcolor: entry.rank === 1 ? 'gold' : entry.rank === 2 ? 'silver' : entry.rank === 3 ? '#CD7F32' : 'primary.main' }}>
                      {entry.rank === 1 ? '🥇' : entry.rank === 2 ? '🥈' : entry.rank === 3 ? '🥉' : entry.rank}
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center">
                        <Typography variant="h6" sx={{ mr: 2 }}>
                          {entry.username}
                        </Typography>
                        <Chip label={`Level ${entry.level}`} size="small" color="primary" sx={{ mr: 1 }} />
                        <Chip label={entry.department} size="small" variant="outlined" />
                      </Box>
                    }
                    secondary={
                      <Box mt={1}>
                        <Grid container spacing={2}>
                          <Grid item xs={3}>
                            <Typography variant="caption" color="textSecondary">Points</Typography>
                            <Typography variant="body2"><strong>{entry.points.toLocaleString()}</strong></Typography>
                          </Grid>
                          <Grid item xs={3}>
                            <Typography variant="caption" color="textSecondary">Trainings</Typography>
                            <Typography variant="body2"><strong>{entry.trainings_completed}</strong></Typography>
                          </Grid>
                          <Grid item xs={3}>
                            <Typography variant="caption" color="textSecondary">Reported</Typography>
                            <Typography variant="body2"><strong>{entry.phishing_reported}</strong></Typography>
                          </Grid>
                          <Grid item xs={3}>
                            <Typography variant="caption" color="textSecondary">Streak</Typography>
                            <Typography variant="body2"><strong>{entry.streak} days 🔥</strong></Typography>
                          </Grid>
                        </Grid>
                        <Box mt={1}>
                          {entry.badges.map((badge) => (
                            <Chip key={badge} label={badge} size="small" icon={<TrophyIcon />} sx={{ mr: 0.5 }} color="warning" />
                          ))}
                        </Box>
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        </Paper>
      )}

      {/* Details Dialog */}
      <DetailsDialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        title={detailsTitle}
        data={detailsData}
        fields={detailsFields}
      />
    </Box>
  );
};

export default SecurityAwareness;

