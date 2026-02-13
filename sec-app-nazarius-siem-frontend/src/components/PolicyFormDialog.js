import React, { useState, useEffect } from 'react';
import {
  Dialog, DialogTitle, DialogContent, DialogActions,
  Button, TextField, Select, MenuItem, FormControl, InputLabel,
  Box, Typography, Chip, IconButton, Grid, Alert, FormHelperText,
  Divider, Switch, FormControlLabel
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  Close as CloseIcon
} from '@mui/icons-material';

const PolicyFormDialog = ({ open, onClose, onSave, policy, mode = 'create' }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    type: 'access',
    status: 'inactive',
    priority: 10,
    conditions: [''],
    actions: [''],
    applies_to: []
  });

  const [errors, setErrors] = useState({});

  useEffect(() => {
    if (policy && mode === 'edit') {
      setFormData({
        name: policy.name || '',
        description: policy.description || '',
        type: policy.type || 'access',
        status: policy.status || 'inactive',
        priority: policy.priority || 10,
        conditions: policy.conditions || [''],
        actions: policy.actions || [''],
        applies_to: policy.applies_to || []
      });
    } else {
      // Reset form for create mode
      setFormData({
        name: '',
        description: '',
        type: 'access',
        status: 'inactive',
        priority: 10,
        conditions: [''],
        actions: [''],
        applies_to: []
      });
    }
    setErrors({});
  }, [policy, mode, open]);

  const policyTypes = [
    { value: 'access', label: 'Access Policy' },
    { value: 'device', label: 'Device Policy' },
    { value: 'network', label: 'Network Policy' },
    { value: 'data', label: 'Data Policy' }
  ];

  const appliesToOptions = [
    { value: 'users', label: 'Users' },
    { value: 'devices', label: 'Devices' },
    { value: 'services', label: 'Services' },
    { value: 'resources', label: 'Resources' }
  ];

  const conditionExamples = {
    access: ['role=admin', 'action=admin_*', 'mfa_enabled=true', 'trust_score>80'],
    device: ['compliance_score>70', 'encryption=true', 'antivirus=active', 'os_version>=10'],
    network: ['source_ip=10.0.0.0/8', 'destination_port=443', 'protocol=https'],
    data: ['classification=sensitive', 'location!=high_risk', 'encryption_required=true']
  };

  const actionExamples = {
    access: ['allow', 'deny', 'require_mfa', 'log_access', 'challenge'],
    device: ['allow', 'quarantine', 'block', 'notify_admin', 'require_update'],
    network: ['allow', 'block', 'log', 'rate_limit', 'redirect'],
    data: ['allow', 'encrypt', 'block', 'watermark', 'audit']
  };

  const handleChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    // Clear error for this field
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
  };

  const handleConditionChange = (index, value) => {
    const newConditions = [...formData.conditions];
    newConditions[index] = value;
    setFormData(prev => ({ ...prev, conditions: newConditions }));
  };

  const handleAddCondition = () => {
    setFormData(prev => ({
      ...prev,
      conditions: [...prev.conditions, '']
    }));
  };

  const handleRemoveCondition = (index) => {
    if (formData.conditions.length > 1) {
      const newConditions = formData.conditions.filter((_, i) => i !== index);
      setFormData(prev => ({ ...prev, conditions: newConditions }));
    }
  };

  const handleActionChange = (index, value) => {
    const newActions = [...formData.actions];
    newActions[index] = value;
    setFormData(prev => ({ ...prev, actions: newActions }));
  };

  const handleAddAction = () => {
    setFormData(prev => ({
      ...prev,
      actions: [...prev.actions, '']
    }));
  };

  const handleRemoveAction = (index) => {
    if (formData.actions.length > 1) {
      const newActions = formData.actions.filter((_, i) => i !== index);
      setFormData(prev => ({ ...prev, actions: newActions }));
    }
  };

  const handleAppliesToToggle = (value) => {
    const current = formData.applies_to || [];
    const newAppliesTo = current.includes(value)
      ? current.filter(v => v !== value)
      : [...current, value];
    setFormData(prev => ({ ...prev, applies_to: newAppliesTo }));
  };

  const validate = () => {
    const newErrors = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Policy name is required';
    }

    if (!formData.type) {
      newErrors.type = 'Policy type is required';
    }

    if (formData.priority < 1 || formData.priority > 100) {
      newErrors.priority = 'Priority must be between 1 and 100';
    }

    const validConditions = formData.conditions.filter(c => c.trim());
    if (validConditions.length === 0) {
      newErrors.conditions = 'At least one condition is required';
    }

    const validActions = formData.actions.filter(a => a.trim());
    if (validActions.length === 0) {
      newErrors.actions = 'At least one action is required';
    }

    if (formData.applies_to.length === 0) {
      newErrors.applies_to = 'Select at least one target';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = () => {
    if (!validate()) {
      return;
    }

    // Clean up empty conditions and actions
    const cleanedData = {
      ...formData,
      conditions: formData.conditions.filter(c => c.trim()),
      actions: formData.actions.filter(a => a.trim())
    };

    onSave(cleanedData);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Typography variant="h6">
            {mode === 'create' ? 'Create New Policy' : 'Edit Policy'}
          </Typography>
          <IconButton onClick={onClose} size="small">
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>

      <DialogContent dividers>
        <Grid container spacing={3}>
          {/* Basic Information */}
          <Grid item xs={12}>
            <Typography variant="subtitle2" color="primary" gutterBottom>
              Basic Information
            </Typography>
          </Grid>

          <Grid item xs={12}>
            <TextField
              fullWidth
              label="Policy Name *"
              value={formData.name}
              onChange={(e) => handleChange('name', e.target.value)}
              error={!!errors.name}
              helperText={errors.name || 'Enter a descriptive name for this policy'}
              placeholder="e.g., MFA Required for Admin Access"
            />
          </Grid>

          <Grid item xs={12}>
            <TextField
              fullWidth
              label="Description"
              value={formData.description}
              onChange={(e) => handleChange('description', e.target.value)}
              multiline
              rows={2}
              placeholder="Describe what this policy does and why it's needed"
            />
          </Grid>

          <Grid item xs={12} sm={6}>
            <FormControl fullWidth error={!!errors.type}>
              <InputLabel>Policy Type *</InputLabel>
              <Select
                value={formData.type}
                onChange={(e) => handleChange('type', e.target.value)}
                label="Policy Type *"
              >
                {policyTypes.map(type => (
                  <MenuItem key={type.value} value={type.value}>
                    {type.label}
                  </MenuItem>
                ))}
              </Select>
              {errors.type && <FormHelperText>{errors.type}</FormHelperText>}
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              type="number"
              label="Priority *"
              value={formData.priority}
              onChange={(e) => handleChange('priority', parseInt(e.target.value) || 10)}
              error={!!errors.priority}
              helperText={errors.priority || 'Lower number = higher priority (1-100)'}
              InputProps={{ inputProps: { min: 1, max: 100 } }}
            />
          </Grid>

          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  checked={formData.status === 'active'}
                  onChange={(e) => handleChange('status', e.target.checked ? 'active' : 'inactive')}
                  color="primary"
                />
              }
              label={formData.status === 'active' ? 'Active (Policy will be enforced)' : 'Inactive (Policy will not be enforced)'}
            />
          </Grid>

          <Grid item xs={12}>
            <Divider />
          </Grid>

          {/* Conditions */}
          <Grid item xs={12}>
            <Typography variant="subtitle2" color="primary" gutterBottom>
              Conditions *
            </Typography>
            <Typography variant="caption" color="textSecondary" display="block" gutterBottom>
              Define when this policy should be evaluated. Examples: {conditionExamples[formData.type].join(', ')}
            </Typography>
          </Grid>

          {formData.conditions.map((condition, index) => (
            <Grid item xs={12} key={index}>
              <Box display="flex" gap={1}>
                <TextField
                  fullWidth
                  label={`Condition ${index + 1}`}
                  value={condition}
                  onChange={(e) => handleConditionChange(index, e.target.value)}
                  placeholder={conditionExamples[formData.type][index % conditionExamples[formData.type].length]}
                  error={!!errors.conditions && index === 0}
                />
                <IconButton
                  onClick={() => handleRemoveCondition(index)}
                  disabled={formData.conditions.length === 1}
                  color="error"
                >
                  <DeleteIcon />
                </IconButton>
              </Box>
            </Grid>
          ))}

          {errors.conditions && (
            <Grid item xs={12}>
              <Alert severity="error">{errors.conditions}</Alert>
            </Grid>
          )}

          <Grid item xs={12}>
            <Button
              startIcon={<AddIcon />}
              onClick={handleAddCondition}
              variant="outlined"
              size="small"
            >
              Add Condition
            </Button>
          </Grid>

          <Grid item xs={12}>
            <Divider />
          </Grid>

          {/* Actions */}
          <Grid item xs={12}>
            <Typography variant="subtitle2" color="primary" gutterBottom>
              Actions *
            </Typography>
            <Typography variant="caption" color="textSecondary" display="block" gutterBottom>
              Define what happens when conditions are met. Examples: {actionExamples[formData.type].join(', ')}
            </Typography>
          </Grid>

          {formData.actions.map((action, index) => (
            <Grid item xs={12} key={index}>
              <Box display="flex" gap={1}>
                <TextField
                  fullWidth
                  label={`Action ${index + 1}`}
                  value={action}
                  onChange={(e) => handleActionChange(index, e.target.value)}
                  placeholder={actionExamples[formData.type][index % actionExamples[formData.type].length]}
                  error={!!errors.actions && index === 0}
                />
                <IconButton
                  onClick={() => handleRemoveAction(index)}
                  disabled={formData.actions.length === 1}
                  color="error"
                >
                  <DeleteIcon />
                </IconButton>
              </Box>
            </Grid>
          ))}

          {errors.actions && (
            <Grid item xs={12}>
              <Alert severity="error">{errors.actions}</Alert>
            </Grid>
          )}

          <Grid item xs={12}>
            <Button
              startIcon={<AddIcon />}
              onClick={handleAddAction}
              variant="outlined"
              size="small"
            >
              Add Action
            </Button>
          </Grid>

          <Grid item xs={12}>
            <Divider />
          </Grid>

          {/* Applies To */}
          <Grid item xs={12}>
            <Typography variant="subtitle2" color="primary" gutterBottom>
              Applies To *
            </Typography>
            <Typography variant="caption" color="textSecondary" display="block" gutterBottom>
              Select which entities this policy applies to
            </Typography>
          </Grid>

          <Grid item xs={12}>
            <Box display="flex" gap={1} flexWrap="wrap">
              {appliesToOptions.map(option => (
                <Chip
                  key={option.value}
                  label={option.label}
                  onClick={() => handleAppliesToToggle(option.value)}
                  color={formData.applies_to.includes(option.value) ? 'primary' : 'default'}
                  variant={formData.applies_to.includes(option.value) ? 'filled' : 'outlined'}
                />
              ))}
            </Box>
            {errors.applies_to && (
              <FormHelperText error>{errors.applies_to}</FormHelperText>
            )}
          </Grid>
        </Grid>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} color="inherit">
          Cancel
        </Button>
        <Button onClick={handleSubmit} variant="contained" color="primary">
          {mode === 'create' ? 'Create Policy' : 'Update Policy'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default PolicyFormDialog;
