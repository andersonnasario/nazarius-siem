import React, { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CircularProgress, Box } from '@mui/material';
import CssBaseline from '@mui/material/CssBaseline';
import { AuthProvider } from './contexts/AuthContext';
import { ModuleProvider } from './contexts/ModuleContext';
import PrivateRoute from './components/PrivateRoute';
import AdminRoute from './components/AdminRoute';
import Layout from './components/Layout';

// Eager loading para páginas críticas
import Dashboard from './pages/Dashboard';
import Login from './pages/Login';

// Lazy loading para todas as outras páginas
const Executive = lazy(() => import('./pages/Executive'));
const Events = lazy(() => import('./pages/Events'));
const Alerts = lazy(() => import('./pages/Alerts'));
const AlertDetails = lazy(() => import('./pages/AlertDetails'));
const Settings = lazy(() => import('./pages/Settings'));
const CasePolicySettings = lazy(() => import('./pages/CasePolicySettings'));
const AIAnalysis = lazy(() => import('./pages/AIAnalysis'));
const Playbooks = lazy(() => import('./pages/Playbooks'));
const PlaybookEditor = lazy(() => import('./pages/PlaybookEditor'));
const Cases = lazy(() => import('./pages/Cases'));
const CaseNew = lazy(() => import('./pages/CaseNew'));
const CaseDetails = lazy(() => import('./pages/CaseDetails'));
const MitreAttack = lazy(() => import('./pages/MitreAttack'));
const Notifications = lazy(() => import('./pages/Notifications'));
const ThreatIntelligence = lazy(() => import('./pages/ThreatIntelligence'));
const CVEDatabase = lazy(() => import('./pages/CVEDatabase'));
const Integrations = lazy(() => import('./pages/Integrations'));
const Hunting = lazy(() => import('./pages/Hunting'));
const UEBA = lazy(() => import('./pages/UEBA'));
const Compliance = lazy(() => import('./pages/Compliance'));
const Forensics = lazy(() => import('./pages/Forensics'));
const Vulnerabilities = lazy(() => import('./pages/Vulnerabilities'));
const NetworkAnalysis = lazy(() => import('./pages/NetworkAnalysis'));
const FileIntegrity = lazy(() => import('./pages/FileIntegrity'));
const DLP = lazy(() => import('./pages/DLP'));
const EDR = lazy(() => import('./pages/EDR'));
const MLAnalytics = lazy(() => import('./pages/MLAnalytics'));
const SecuritySettings = lazy(() => import('./pages/SecuritySettings'));
const Monitoring = lazy(() => import('./pages/Monitoring'));
const IncidentResponse = lazy(() => import('./pages/IncidentResponse'));
const Reports = lazy(() => import('./pages/Reports'));
const DashboardCustomizer = lazy(() => import('./pages/DashboardCustomizer'));
const DataRetention = lazy(() => import('./pages/DataRetention'));
const AutomatedResponse = lazy(() => import('./pages/AutomatedResponse'));
const AlertTriage = lazy(() => import('./pages/AlertTriage'));
const SLAMetrics = lazy(() => import('./pages/SLAMetrics'));
const MDRDashboard = lazy(() => import('./pages/MDRDashboard'));
const ThreatHuntingPlatform = lazy(() => import('./pages/ThreatHuntingPlatform'));
const ThreatHuntingRanking = lazy(() => import('./pages/ThreatHuntingRanking'));
const ThreatHuntingHistory = lazy(() => import('./pages/ThreatHuntingHistory'));
const MDRForensics = lazy(() => import('./pages/MDRForensics'));
const MDRThreatIntel = lazy(() => import('./pages/MDRThreatIntel'));
const MDRMultiTenancy = lazy(() => import('./pages/MDRMultiTenancy'));
const AdvancedThreatHunting = lazy(() => import('./pages/AdvancedThreatHunting'));
const DeceptionTechnology = lazy(() => import('./pages/DeceptionTechnology'));
const ContinuousValidation = lazy(() => import('./pages/ContinuousValidation'));
const SecurityAwareness = lazy(() => import('./pages/SecurityAwareness'));
const AdvancedAnalytics = lazy(() => import('./pages/AdvancedAnalytics'));
const SOAR = lazy(() => import('./pages/SOAR'));
const ThreatIntelFusion = lazy(() => import('./pages/ThreatIntelFusion'));
const CSPM = lazy(() => import('./pages/CSPM'));
const CSPMAWSIntegrations = lazy(() => import('./pages/CSPMAWSIntegrations'));
const CSPMGCPIntegrations = lazy(() => import('./pages/CSPMGCPIntegrations'));
const CSPMRemediation = lazy(() => import('./pages/CSPMRemediation'));
const CSPMAlerts = lazy(() => import('./pages/CSPMAlerts'));
const PCIDSS = lazy(() => import('./pages/PCIDSS'));
const CSPMDrift = lazy(() => import('./pages/CSPMDrift'));
const CSPMConfigAggregator = lazy(() => import('./pages/CSPMConfigAggregator'));
const AWSConnections = lazy(() => import('./pages/AWSConnections'));
const ZeroTrust = lazy(() => import('./pages/ZeroTrust'));
const ModuleManager = lazy(() => import('./pages/ModuleManager'));
const Users = lazy(() => import('./pages/Users'));
const Profile = lazy(() => import('./pages/Profile'));
const SystemLogs = lazy(() => import('./pages/SystemLogs'));
const AWSConnectivityTest = lazy(() => import('./pages/AWSConnectivityTest'));
const FortinetIntegration = lazy(() => import('./pages/FortinetIntegration'));
const CloudflareIntegration = lazy(() => import('./pages/CloudflareIntegration'));
const JumpCloudIntegration = lazy(() => import('./pages/JumpCloudIntegration'));
const PLARiskMatrix = lazy(() => import('./pages/PLARiskMatrix'));
const VulnerabilityDiagnostics = lazy(() => import('./pages/VulnerabilityDiagnostics'));

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#90caf9',
    },
    secondary: {
      main: '#f48fb1',
    },
    background: {
      default: '#0a1929',
      paper: '#1e293b',
    },
  },
});

// Loading component para Suspense
const LoadingFallback = () => (
  <Box
    sx={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      height: '100vh',
      flexDirection: 'column',
      gap: 2,
    }}
  >
    <CircularProgress size={60} />
    <Box sx={{ color: 'text.secondary', fontSize: '1.1rem' }}>
      Carregando...
    </Box>
  </Box>
);

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <AuthProvider>
        <Router>
          <Routes>
            {/* Public Route */}
            <Route path="/login" element={<Login />} />
            
            {/* Protected Routes */}
            <Route
              path="/*"
              element={
                <PrivateRoute>
                  <ModuleProvider>
                    <Layout>
                    <Suspense fallback={<LoadingFallback />}>
                      <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/executive" element={<Executive />} />
                        <Route path="/events" element={<Events />} />
                        <Route path="/alerts" element={<Alerts />} />
                        <Route path="/alerts/:id" element={<AlertDetails />} />
                        <Route path="/playbooks" element={<Playbooks />} />
                        <Route path="/playbooks/editor" element={<PlaybookEditor />} />
                        <Route path="/playbooks/editor/:id" element={<PlaybookEditor />} />
                        <Route path="/cases" element={<Cases />} />
                        <Route path="/cases/new" element={<CaseNew />} />
                        <Route path="/cases/:id" element={<CaseDetails />} />
                        <Route path="/mitre-attack" element={<MitreAttack />} />
                        <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
                        <Route path="/cve-database" element={<CVEDatabase />} />
                        <Route path="/notifications" element={<Notifications />} />
                        <Route path="/integrations" element={<AdminRoute><Integrations /></AdminRoute>} />
                        <Route path="/fortinet" element={<AdminRoute><FortinetIntegration /></AdminRoute>} />
                        <Route path="/cloudflare" element={<AdminRoute><CloudflareIntegration /></AdminRoute>} />
                        <Route path="/jumpcloud" element={<AdminRoute><JumpCloudIntegration /></AdminRoute>} />
                        <Route path="/hunting" element={<Hunting />} />
                        <Route path="/ueba" element={<UEBA />} />
                        <Route path="/compliance" element={<Compliance />} />
                        <Route path="/forensics" element={<Forensics />} />
                        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
                        <Route path="/pla-risk-matrix" element={<PLARiskMatrix />} />
                        <Route path="/vulnerability-diagnostics" element={<AdminRoute><VulnerabilityDiagnostics /></AdminRoute>} />
                        <Route path="/network" element={<NetworkAnalysis />} />
                        <Route path="/file-integrity" element={<FileIntegrity />} />
                        <Route path="/dlp" element={<DLP />} />
                        <Route path="/edr" element={<EDR />} />
                        <Route path="/ml-analytics" element={<MLAnalytics />} />
                        <Route path="/security-settings" element={<AdminRoute><SecuritySettings /></AdminRoute>} />
                        <Route path="/monitoring" element={<Monitoring />} />
                        <Route path="/incident-response" element={<IncidentResponse />} />
                        <Route path="/reports" element={<Reports />} />
                        <Route path="/dashboard-customizer" element={<DashboardCustomizer />} />
                        <Route path="/data-retention" element={<AdminRoute><DataRetention /></AdminRoute>} />
                        <Route path="/automated-response" element={<AutomatedResponse />} />
                        <Route path="/alert-triage" element={<AlertTriage />} />
                        <Route path="/sla-metrics" element={<SLAMetrics />} />
                        <Route path="/mdr-dashboard" element={<MDRDashboard />} />
                        <Route path="/threat-hunting-platform" element={<ThreatHuntingPlatform />} />
                        <Route path="/threat-hunting-ranking" element={<ThreatHuntingRanking />} />
                        <Route path="/threat-hunting-history" element={<ThreatHuntingHistory />} />
                        <Route path="/mdr-forensics" element={<MDRForensics />} />
                        <Route path="/mdr-threat-intel" element={<MDRThreatIntel />} />
                        <Route path="/mdr-multi-tenancy" element={<MDRMultiTenancy />} />
                        <Route path="/advanced-hunting" element={<AdvancedThreatHunting />} />
                        <Route path="/deception" element={<DeceptionTechnology />} />
                        <Route path="/continuous-validation" element={<ContinuousValidation />} />
                        <Route path="/security-awareness" element={<SecurityAwareness />} />
                        <Route path="/advanced-analytics" element={<AdvancedAnalytics />} />
                        <Route path="/soar" element={<SOAR />} />
                        <Route path="/threat-intel-fusion" element={<ThreatIntelFusion />} />
                        <Route path="/cspm" element={<CSPM />} />
                        <Route path="/cspm-aws" element={<CSPMAWSIntegrations />} />
                        <Route path="/cspm-gcp" element={<CSPMGCPIntegrations />} />
                        <Route path="/cspm-remediation" element={<CSPMRemediation />} />
                        <Route path="/cspm-alerts" element={<CSPMAlerts />} />
                        <Route path="/cspm-pci-dss" element={<PCIDSS />} />
                        <Route path="/cspm-drift" element={<CSPMDrift />} />
                        <Route path="/cspm-config-aggregator" element={<CSPMConfigAggregator />} />
                        <Route path="/aws-connections" element={<AWSConnections />} />
                        <Route path="/zero-trust" element={<ZeroTrust />} />
                        <Route path="/module-manager" element={<AdminRoute><ModuleManager /></AdminRoute>} />
                        <Route path="/users" element={<AdminRoute><Users /></AdminRoute>} />
                        <Route path="/profile" element={<Profile />} />
                        <Route path="/ai-analysis" element={<AIAnalysis />} />
                        <Route path="/settings" element={<AdminRoute><Settings /></AdminRoute>} />
                        <Route path="/case-policies" element={<AdminRoute><CasePolicySettings /></AdminRoute>} />
                        <Route path="/system-logs" element={<AdminRoute><SystemLogs /></AdminRoute>} />
                        <Route path="/aws-connectivity" element={<AdminRoute><AWSConnectivityTest /></AdminRoute>} />
                      </Routes>
                    </Suspense>
                  </Layout>
                  </ModuleProvider>
                </PrivateRoute>
              }
            />
          </Routes>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;