import React, { useEffect, useMemo, useState, useCallback } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Grid,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  Typography,
  Alert,
  CircularProgress,
} from '@mui/material';
import { casesAPI } from '../services/api';

const DEFAULT_SLA = {
  critical: { deadline_hours: 4, response_seconds: 900, resolve_seconds: 14400 },
  high: { deadline_hours: 24, response_seconds: 1800, resolve_seconds: 86400 },
  medium: { deadline_hours: 72, response_seconds: 7200, resolve_seconds: 259200 },
  low: { deadline_hours: 168, response_seconds: 28800, resolve_seconds: 604800 },
};

const DEFAULT_CHECKLIST = [
  'Triagem inicial e validação do alerta',
  'Coleta de evidências e logs relevantes',
  'Avaliar impacto em ativos críticos',
  'Definir e executar ações de contenção',
  'Documentar causa raiz e lições aprendidas',
];

const EXAMPLE_POLICY = {
  checklist_by_category: {
    phishing: [
      'Identificar usuários impactados',
      'Bloquear/remover e-mail malicioso',
      'Resetar credenciais comprometidas',
      'Adicionar indicadores a bloqueios',
      'Registrar lições aprendidas',
    ],
    ransomware: [
      'Isolar o endpoint/servidor afetado',
      'Preservar evidências e snapshots',
      'Validar backups e plano de restauração',
      'Erradicar malware e aplicar patches',
      'Restaurar serviços e validar integridade',
    ],
  },
  sla_by_severity: DEFAULT_SLA,
  sla_by_category: {
    ransomware: {
      critical: { deadline_hours: 2, response_seconds: 600, resolve_seconds: 7200 },
    },
  },
};

const formatJson = (value) => JSON.stringify(value || {}, null, 2);
const safeParseJson = (value) => {
  try {
    return JSON.parse(value || '{}');
  } catch (err) {
    return null;
  }
};

const normalizeChecklistLines = (value) =>
  value
    .split('\n')
    .map((item) => item.trim())
    .filter(Boolean);

const sanitizeChecklistByCategory = (obj) => {
  const result = {};
  if (!obj || typeof obj !== 'object') {
    return result;
  }
  Object.entries(obj).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      const items = value.map((item) => `${item}`.trim()).filter(Boolean);
      if (items.length > 0) {
        result[key.toLowerCase()] = items;
      }
    }
  });
  return result;
};

const sanitizeSLABySeverity = (obj) => {
  const result = { ...DEFAULT_SLA };
  if (!obj || typeof obj !== 'object') {
    return result;
  }
  Object.entries(obj).forEach(([key, value]) => {
    if (!value || typeof value !== 'object') {
      return;
    }
    const normalizedKey = key.toLowerCase();
    result[normalizedKey] = {
      deadline_hours: Number(value.deadline_hours || result[normalizedKey]?.deadline_hours || 0),
      response_seconds: Number(value.response_seconds || result[normalizedKey]?.response_seconds || 0),
      resolve_seconds: Number(value.resolve_seconds || result[normalizedKey]?.resolve_seconds || 0),
    };
  });
  return result;
};

const sanitizeSLAByCategory = (obj) => {
  const result = {};
  if (!obj || typeof obj !== 'object') {
    return result;
  }
  Object.entries(obj).forEach(([category, severityMap]) => {
    if (!severityMap || typeof severityMap !== 'object') {
      return;
    }
    const normalizedCategory = category.toLowerCase();
    result[normalizedCategory] = {};
    Object.entries(severityMap).forEach(([severity, value]) => {
      if (!value || typeof value !== 'object') {
        return;
      }
      result[normalizedCategory][severity.toLowerCase()] = {
        deadline_hours: Number(value.deadline_hours || 0),
        response_seconds: Number(value.response_seconds || 0),
        resolve_seconds: Number(value.resolve_seconds || 0),
      };
    });
    if (Object.keys(result[normalizedCategory]).length === 0) {
      delete result[normalizedCategory];
    }
  });
  return result;
};

const sanitizeCategorySuggestions = (values) => {
  if (!Array.isArray(values)) {
    return [];
  }
  return values
    .map((item) => `${item}`.trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 20);
};

const hasInvalidSLANumbers = (obj) => {
  const check = (value) =>
    value &&
    typeof value === 'object' &&
    ['deadline_hours', 'response_seconds', 'resolve_seconds'].some(
      (field) => Number(value[field]) <= 0 || Number.isNaN(Number(value[field]))
    );

  if (!obj || typeof obj !== 'object') return false;
  return Object.values(obj).some((value) => {
    if (value && typeof value === 'object' && value.deadline_hours !== undefined) {
      return check(value);
    }
    if (value && typeof value === 'object') {
      return Object.values(value).some((inner) => check(inner));
    }
    return false;
  });
};

const CasePolicySettings = () => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [defaultChecklistText, setDefaultChecklistText] = useState('');
  const [checklistByCategoryText, setChecklistByCategoryText] = useState(formatJson({}));
  const [slaBySeverityText, setSlaBySeverityText] = useState(formatJson(DEFAULT_SLA));
  const [slaByCategoryText, setSlaByCategoryText] = useState(formatJson({}));
  const [previewCategory, setPreviewCategory] = useState('phishing');
  const [previewCategoryInput, setPreviewCategoryInput] = useState('phishing');
  const [previewSeverity, setPreviewSeverity] = useState('high');
  const [categorySuggestions, setCategorySuggestions] = useState([
    'phishing',
    'malware',
    'ransomware',
    'data_breach',
    'data_loss',
    'unauthorized_access',
    'privilege_escalation',
    'ddos',
    'insider',
  ]);

  const defaultChecklistHelp = useMemo(
    () => 'Uma linha por item. As categorias específicas sobrescrevem este padrão.',
    []
  );

  const loadPolicy = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const response = await casesAPI.getPolicy();
      const policy = response.data || {};
      setDefaultChecklistText((policy.default_checklist || []).join('\n'));
      setCategorySuggestions((prev) =>
        sanitizeCategorySuggestions(policy.category_suggestions || prev)
      );
      setChecklistByCategoryText(formatJson(policy.checklist_by_category || {}));
      setSlaBySeverityText(formatJson(policy.sla_by_severity || DEFAULT_SLA));
      setSlaByCategoryText(formatJson(policy.sla_by_category || {}));
    } catch (err) {
      setError('Erro ao carregar política de casos.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPolicy();
  }, [loadPolicy]);

  const computePreview = () => {
    const checklistByCategoryRaw = safeParseJson(checklistByCategoryText);
    const slaBySeverityRaw = safeParseJson(slaBySeverityText);
    const slaByCategoryRaw = safeParseJson(slaByCategoryText);
    if (!checklistByCategoryRaw || !slaBySeverityRaw || !slaByCategoryRaw) {
      return { error: 'JSON inválido. Corrija os campos para visualizar o preview.' };
    }

    const checklistByCategory = sanitizeChecklistByCategory(checklistByCategoryRaw);
    const slaBySeverity = sanitizeSLABySeverity(slaBySeverityRaw);
    const slaByCategory = sanitizeSLAByCategory(slaByCategoryRaw);
    const defaultChecklist = normalizeChecklistLines(defaultChecklistText);

    const categoryKey = previewCategoryInput.trim().toLowerCase() || previewCategory.toLowerCase();
    const severityKey = previewSeverity.toLowerCase();
    const checklist =
      checklistByCategory[categoryKey] ||
      (defaultChecklist.length > 0 ? defaultChecklist : DEFAULT_CHECKLIST);

    let sla = slaBySeverity[severityKey] || DEFAULT_SLA[severityKey] || DEFAULT_SLA.low;
    if (slaByCategory[categoryKey] && slaByCategory[categoryKey][severityKey]) {
      sla = slaByCategory[categoryKey][severityKey];
    }

    return { checklist, sla };
  };

  const handleAddSuggestion = () => {
    const value = previewCategoryInput.trim().toLowerCase();
    if (!value) {
      return;
    }
    setCategorySuggestions((prev) => {
      if (prev.includes(value)) {
        return prev;
      }
      return [...prev, value].slice(0, 20);
    });
  };

  const handleRemoveSuggestion = (value) => {
    setCategorySuggestions((prev) => prev.filter((item) => item !== value));
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setSuccess('');

    try {
      const checklistByCategoryRaw = safeParseJson(checklistByCategoryText);
      const slaBySeverityRaw = safeParseJson(slaBySeverityText);
      const slaByCategoryRaw = safeParseJson(slaByCategoryText);
      if (!checklistByCategoryRaw || !slaBySeverityRaw || !slaByCategoryRaw) {
        setError('JSON inválido. Corrija os campos antes de salvar.');
        setSaving(false);
        return;
      }

      const payload = {
        default_checklist: normalizeChecklistLines(defaultChecklistText),
        category_suggestions: sanitizeCategorySuggestions(categorySuggestions),
        checklist_by_category: sanitizeChecklistByCategory(checklistByCategoryRaw),
        sla_by_severity: sanitizeSLABySeverity(slaBySeverityRaw),
        sla_by_category: sanitizeSLAByCategory(slaByCategoryRaw),
      };

      if (hasInvalidSLANumbers(payload.sla_by_severity) || hasInvalidSLANumbers(payload.sla_by_category)) {
        setError('SLA inválido: use valores numéricos maiores que zero.');
        setSaving(false);
        return;
      }

      await casesAPI.updatePolicy(payload);
      setSuccess('Política salva com sucesso!');
      await loadPolicy();
    } catch (err) {
      setError('Erro ao salvar política. Verifique os JSONs e tente novamente.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" sx={{ mb: 2, fontWeight: 700 }}>
        Políticas de Casos (Checklist & SLA)
      </Typography>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 2 }}>{success}</Alert>}

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
          <CircularProgress />
        </Box>
      ) : (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 1 }}>
                  Checklist padrão
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, color: 'text.secondary' }}>
                  {defaultChecklistHelp}
                </Typography>
                <TextField
                  fullWidth
                  multiline
                  minRows={5}
                  value={defaultChecklistText}
                  onChange={(e) => setDefaultChecklistText(e.target.value)}
                  placeholder="Ex: Triagem inicial e validação do alerta"
                />
                <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
                  <Button
                    variant="outlined"
                    onClick={() => setDefaultChecklistText(DEFAULT_CHECKLIST.join('\n'))}
                  >
                    Resetar padrão
                  </Button>
                  <Button
                    variant="outlined"
                    onClick={() => {
                      setChecklistByCategoryText(formatJson(EXAMPLE_POLICY.checklist_by_category));
                      setSlaByCategoryText(formatJson(EXAMPLE_POLICY.sla_by_category));
                    }}
                  >
                    Carregar exemplos
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Checklist por categoria (JSON)
                </Typography>
                <TextField
                  fullWidth
                  multiline
                  minRows={12}
                  value={checklistByCategoryText}
                  onChange={(e) => setChecklistByCategoryText(e.target.value)}
                  placeholder='{"phishing": ["Identificar usuários impactados", "..."]}'
                />
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  SLA por severidade (JSON)
                </Typography>
                <TextField
                  fullWidth
                  multiline
                  minRows={12}
                  value={slaBySeverityText}
                  onChange={(e) => setSlaBySeverityText(e.target.value)}
                />
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  SLA por categoria e severidade (JSON)
                </Typography>
                <TextField
                  fullWidth
                  multiline
                  minRows={10}
                  value={slaByCategoryText}
                  onChange={(e) => setSlaByCategoryText(e.target.value)}
                  placeholder='{"ransomware": {"critical": {"deadline_hours": 2, "response_seconds": 600, "resolve_seconds": 7200}}}'
                />
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Preview (categoria + severidade)
                </Typography>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth>
                      <InputLabel id="preview-category-label">Categoria</InputLabel>
                      <Select
                        labelId="preview-category-label"
                        value={previewCategory}
                        label="Categoria"
                        onChange={(e) => {
                          setPreviewCategory(e.target.value);
                          setPreviewCategoryInput(e.target.value);
                        }}
                      >
                        <MenuItem value="phishing">phishing</MenuItem>
                        <MenuItem value="malware">malware</MenuItem>
                        <MenuItem value="ransomware">ransomware</MenuItem>
                        <MenuItem value="data_breach">data_breach</MenuItem>
                        <MenuItem value="data_loss">data_loss</MenuItem>
                        <MenuItem value="unauthorized_access">unauthorized_access</MenuItem>
                        <MenuItem value="privilege_escalation">privilege_escalation</MenuItem>
                        <MenuItem value="ddos">ddos</MenuItem>
                        <MenuItem value="insider">insider</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth>
                      <InputLabel id="preview-severity-label">Severidade</InputLabel>
                      <Select
                        labelId="preview-severity-label"
                        value={previewSeverity}
                        label="Severidade"
                        onChange={(e) => setPreviewSeverity(e.target.value)}
                      >
                        <MenuItem value="critical">critical</MenuItem>
                        <MenuItem value="high">high</MenuItem>
                        <MenuItem value="medium">medium</MenuItem>
                        <MenuItem value="low">low</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Categoria livre (opcional)"
                      value={previewCategoryInput}
                      onChange={(e) => setPreviewCategoryInput(e.target.value)}
                      placeholder="Ex: insider_threat, supply_chain, mobile"
                    />
                    <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
                      <Button variant="text" size="small" onClick={handleAddSuggestion}>
                        Salvar sugestao
                      </Button>
                      {categorySuggestions.map((value) => (
                        <Chip
                          key={value}
                          label={value}
                          size="small"
                          onClick={() => setPreviewCategoryInput(value)}
                          onDelete={() => handleRemoveSuggestion(value)}
                        />
                      ))}
                    </Box>
                  </Grid>
                </Grid>

                {(() => {
                  const preview = computePreview();
                  if (preview.error) {
                    return <Alert severity="warning">{preview.error}</Alert>;
                  }
                  return (
                    <Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                        SLA aplicado
                      </Typography>
                      <Typography variant="body2" sx={{ mb: 2 }}>
                        Prazo: {preview.sla.deadline_hours}h · Resposta: {preview.sla.response_seconds}s ·
                        Resolução: {preview.sla.resolve_seconds}s
                      </Typography>
                      <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                        Checklist aplicado
                      </Typography>
                      <Box component="ul" sx={{ m: 0, pl: 3 }}>
                        {preview.checklist.map((item, idx) => (
                          <li key={`${item}-${idx}`}>
                            <Typography variant="body2">{item}</Typography>
                          </li>
                        ))}
                      </Box>
                    </Box>
                  );
                })()}
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sx={{ display: 'flex', gap: 2 }}>
            <Button variant="outlined" onClick={loadPolicy} disabled={saving}>
              Recarregar
            </Button>
            <Button variant="contained" onClick={handleSave} disabled={saving}>
              {saving ? 'Salvando...' : 'Salvar políticas'}
            </Button>
          </Grid>
        </Grid>
      )}
    </Box>
  );
};

export default CasePolicySettings;
