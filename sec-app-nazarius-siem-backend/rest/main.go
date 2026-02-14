package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cognimind/siem-platform/database"

	"github.com/opensearch-project/opensearch-go/v2"
	// "github.com/gin-contrib/cors" // TODO: implement CORS if needed
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

type APIServer struct {
	router               *gin.Engine
	opensearch           *opensearch.Client
	redis                *redis.Client
	config               *Config
	jwtSecret            []byte
	rateLimiter          *RateLimiter
	bruteForceProtection *BruteForceProtection
	playbookRepo         *database.PlaybookRepository
	caseRepo             *database.CaseRepository
	authRepo             *database.AuthRepository
	logger               *log.Logger
}

func NewAPIServer(config *Config) (*APIServer, error) {
	// Configurar OpenSearch
	opensearchConfig := opensearch.Config{
		Addresses: config.Elasticsearch.Hosts,
	}

	// Add authentication for AWS OpenSearch
	if config.Elasticsearch.Username != "" && config.Elasticsearch.Password != "" {
		opensearchConfig.Username = config.Elasticsearch.Username
		opensearchConfig.Password = config.Elasticsearch.Password
		log.Printf("🔐 OpenSearch authentication enabled (username: %s)", config.Elasticsearch.Username)
	}

	// Enable TLS for AWS OpenSearch
	if config.Elasticsearch.UseTLS {
		opensearchConfig.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
		log.Printf("🔒 OpenSearch TLS enabled for production (AWS)")
	} else {
		log.Printf("⚠️  OpenSearch TLS disabled (local development)")
	}

	opensearchClient, err := opensearch.NewClient(opensearchConfig)
	if err != nil {
		AddSystemLog("ERROR", "opensearch", "❌ Failed to connect to OpenSearch", map[string]interface{}{
			"error": err.Error(),
			"hosts": config.Elasticsearch.Hosts,
		})
		return nil, fmt.Errorf("failed to create OpenSearch client: %v", err)
	}
	AddSystemLog("INFO", "opensearch", "✅ OpenSearch client created successfully", map[string]interface{}{
		"hosts":   config.Elasticsearch.Hosts,
		"use_tls": config.Elasticsearch.UseTLS,
	})

	// Configurar Redis
	redisOptions := &redis.Options{
		Addr:     config.Redis.Address,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	}

	// Enable TLS for AWS ElastiCache in production
	if config.Redis.UseTLS {
		log.Printf("🔒 Redis TLS enabled for production (AWS ElastiCache)")
		redisOptions.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	} else {
		log.Printf("⚠️  Redis TLS disabled (local development)")
	}

	redisClient := redis.NewClient(redisOptions)
	AddSystemLog("INFO", "redis", "✅ Redis client created", map[string]interface{}{
		"address": config.Redis.Address,
		"use_tls": config.Redis.UseTLS,
	})

	// Configurar Gin
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Configure trusted proxies for secure IP extraction
	// Set TRUSTED_PROXIES env var with comma-separated CIDRs (e.g. "10.0.0.0/8,172.16.0.0/12")
	trustedProxies := os.Getenv("TRUSTED_PROXIES")
	if trustedProxies != "" {
		proxies := strings.Split(trustedProxies, ",")
		for i, p := range proxies {
			proxies[i] = strings.TrimSpace(p)
		}
		if err := router.SetTrustedProxies(proxies); err != nil {
			log.Printf("⚠️  Failed to set trusted proxies: %v", err)
		} else {
			log.Printf("🔒 Trusted proxies configured: %v", proxies)
		}
	} else {
		// Default: trust only loopback/private ranges
		router.SetTrustedProxies([]string{"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
	}

	// Inicializar componentes de segurança
	rateLimiter := NewRateLimiter(rate.Limit(100), 200) // 100 req/s, burst 200
	bruteForceProtection := NewBruteForceProtection()

	// Inicializar repositórios (se DB estiver conectado)
	var playbookRepo *database.PlaybookRepository
	var caseRepo *database.CaseRepository
	var authRepo *database.AuthRepository
	if database.DB != nil {
		playbookRepo = database.NewPlaybookRepository(database.DB)
		caseRepo = database.NewCaseRepository(database.DB)
		authRepo = database.NewAuthRepository(database.DB)
		log.Println("✅ Database repositories initialized")
		AddSystemLog("INFO", "database", "✅ Database connected and repositories initialized", map[string]interface{}{
			"host": getEnvOrDefault("DB_HOST", "unknown"),
			"name": getEnvOrDefault("DB_NAME", "siem"),
		})
	} else {
		log.Println("⚠️  Database not connected, using in-memory storage")
		AddSystemLog("WARN", "database", "⚠️ Database not connected - using in-memory storage", nil)
	}

	// Create logger
	logger := log.New(os.Stdout, "[SIEM-API] ", log.LstdFlags)

	server := &APIServer{
		router:               router,
		opensearch:           opensearchClient,
		redis:                redisClient,
		config:               config,
		jwtSecret:            []byte(config.JWT.Secret),
		rateLimiter:          rateLimiter,
		bruteForceProtection: bruteForceProtection,
		playbookRepo:         playbookRepo,
		caseRepo:             caseRepo,
		authRepo:             authRepo,
		logger:               logger,
	}

	// Configure OpenSearch for Module Manager persistence
	SetModuleOpenSearch(opensearchClient)

	// Configurar middlewares
	server.setupMiddlewares()

	// Configurar rotas
	server.setupRoutes()

	return server, nil
}

func (s *APIServer) setupMiddlewares() {
	// =========================================================================
	// MONITORING MIDDLEWARES (Applied First for Complete Visibility)
	// =========================================================================

	// 1. Prometheus Metrics
	s.router.Use(PrometheusMiddleware())

	// =========================================================================
	// SECURITY MIDDLEWARES (Applied After Monitoring for Maximum Protection)
	// =========================================================================

	// 2. Security Headers (HSTS, CSP, X-Frame-Options, etc)
	s.router.Use(SecurityHeadersMiddleware())

	// 3. CORS with security best practices
	allowedOrigins := s.config.CORS.AllowOrigins
	if len(allowedOrigins) == 0 {
		// Default to localhost for development only - set CORS_ORIGINS in production
		allowedOrigins = []string{"http://localhost:3000", "http://localhost:8080"}
		log.Println("⚠️  CORS_ORIGINS not set, defaulting to localhost only. Set CORS_ORIGINS for production.")
	}
	s.router.Use(CORSMiddleware(allowedOrigins))

	// 4. Rate Limiting (100 req/s per IP)
	s.router.Use(RateLimitMiddleware(s.rateLimiter))

	// 5. Brute Force Protection (for login endpoints)
	s.router.Use(BruteForceProtectionMiddleware(s.bruteForceProtection))

	// 6. Input Validation (Content-Type, Body Size)
	s.router.Use(InputValidationMiddleware())

	// 7. Audit Logging (all requests)
	s.router.Use(AuditLogMiddleware())

	// 8. API Key validation (for external APIs)
	s.router.Use(APIKeyMiddleware())

	// =========================================================================
	// STANDARD MIDDLEWARES
	// =========================================================================

	// Logger personalizado
	s.router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))

	// =========================================================================
	// MONITORING ENDPOINTS (without authentication for K8s/load balancers)
	// =========================================================================

	// Prometheus Metrics
	s.router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Health Checks (Kubernetes probes)
	s.router.GET("/health", s.handleHealthCheck)
	s.router.GET("/healthz", s.handleHealthCheck)
	s.router.GET("/livez", s.handleLivenessProbe)
	s.router.GET("/readyz", s.handleReadinessProbe)
	s.router.GET("/startupz", s.handleStartupProbe)
}

func (s *APIServer) setupRoutes() {
	// Create rate limiters
	loginRateLimiter := NewRateLimiter(rate.Limit(5), 10)  // 5 login attempts per second, burst 10
	apiRateLimiter := NewRateLimiter(rate.Limit(100), 200) // 100 req/s, burst 200

	// Rotas públicas
	public := s.router.Group("/api/v1")
	{
		// Health check na rota pública também
		public.GET("/health", s.handleHealthCheck)

		// ========================================
		// FORTINET WEBHOOK (Public - authenticated via API Key)
		// ========================================
		// Webhook endpoints for FortiGate devices to send logs
		// Authentication is done via X-API-Key header instead of JWT
		public.POST("/fortinet/webhook", s.handleFortinetWebhook)
		public.POST("/fortinet/webhook/batch", s.handleFortinetBatchWebhook)

		// Auth routes with stricter rate limiting
		auth := public.Group("/auth")
		auth.Use(s.LoginRateLimitMiddleware(loginRateLimiter))
		{
			auth.POST("/login", s.handleLogin)
			auth.POST("/refresh", s.handleRefreshToken)
			auth.POST("/logout", s.handleLogout)
		}
	}

	// Rotas protegidas (requerem autenticação)
	protected := s.router.Group("/api/v1")
	protected.Use(s.AuthMiddleware())
	protected.Use(s.RateLimitMiddleware(apiRateLimiter))
	protected.Use(s.AuditMiddleware())
	{
		// Auth management (authenticated users)
		authManagement := protected.Group("/auth")
		{
			authManagement.GET("/me", s.handleGetMe)
			authManagement.POST("/logout-all", s.handleLogoutAll)
			authManagement.GET("/sessions", s.handleGetSessions)
			authManagement.POST("/change-password", s.handleChangePassword)
		}

		// User profile (self-service)
		profile := protected.Group("/profile")
		{
			profile.GET("/", s.handleGetMyProfile)
			profile.PUT("/", s.handleUpdateMyProfile)
			profile.POST("/change-password", s.handleChangeMyPassword)
		}

		// User management (admin only)
		users := protected.Group("/users")
		users.Use(RequireAdmin())
		{
			users.GET("/", s.handleListUsers)
			users.GET("/:id", s.handleGetUser)
			users.POST("/", s.handleCreateUser)
			users.PUT("/:id", s.handleUpdateUser)
			users.DELETE("/:id", s.handleDeleteUser)
			users.GET("/roles", s.handleListRoles)
		}
		// Eventos
		events := protected.Group("/events")
		{
			events.GET("/search", s.handleSearchEvents)
			events.GET("/aggregate", s.handleAggregateEvents)
			events.GET("/statistics", s.handleGetEventStatistics)
			events.GET("/export", s.handleExportEvents)
			events.GET("/:id", s.handleGetEvent)
		}

		// Alertas
		alerts := protected.Group("/alerts")
		{
			alerts.GET("/", s.handleListAlerts)
			alerts.GET("/statistics", s.handleGetAlertStatistics)
			alerts.GET("/export", s.handleExportAlerts)
			alerts.GET("/:id", s.handleGetAlert)
			alerts.POST("/", s.handleCreateAlert)
			alerts.PUT("/:id", s.handleUpdateAlert)
			alerts.DELETE("/:id", s.handleDeleteAlert)

			// Novas rotas para gerenciamento de alertas
			alerts.POST("/:id/create-case", s.handleCreateCaseFromAlert)
			alerts.PUT("/:id/status", s.handleUpdateAlertStatus)
		}

		// Dashboards
		dashboards := protected.Group("/dashboards")
		{
			dashboards.GET("/", s.handleListDashboards)
			dashboards.POST("/", s.handleCreateDashboard)
			// dashboards.GET("/:id", s.handleGetDashboard) // TODO: implement
			dashboards.PUT("/:id", s.handleUpdateDashboard)
			// dashboards.DELETE("/:id", s.handleDeleteDashboard) // TODO: implement
		}

		// Análise (TODO: Implementar handlers)
		// analysis := protected.Group("/analysis")
		// {
		// 	analysis.GET("/statistics", s.handleGetStatistics)
		// 	analysis.GET("/trends", s.handleGetAnalysisTrends)
		// 	analysis.GET("/anomalies", s.handleGetAnomalies)
		// }

		// Configuração - TODO: implement these handlers
		// config := protected.Group("/config")
		// {
		// 	config.GET("/collectors", s.handleListCollectors)
		// 	config.PUT("/collectors/:id", s.handleUpdateCollector)
		// 	config.GET("/retention", s.handleGetRetentionPolicy)
		// 	config.PUT("/retention", s.handleUpdateRetentionPolicy)
		// }

		// Playbooks SOAR
		playbooks := protected.Group("/playbooks")
		{
			playbooks.GET("/", s.handleListPlaybooks)
			playbooks.POST("/", s.handleCreatePlaybook)
			playbooks.GET("/:id", s.handleGetPlaybook)
			playbooks.PUT("/:id", s.handleUpdatePlaybook)
			playbooks.DELETE("/:id", s.handleDeletePlaybook)
			playbooks.POST("/:id/execute", s.handleExecutePlaybook)
			playbooks.GET("/:id/statistics", s.handleGetPlaybookStatistics)
			playbooks.GET("/executions", s.handleListExecutions)
			playbooks.GET("/executions/:id", s.handleGetExecution)
		}

		// Case Management
		cases := protected.Group("/cases")
		{
			cases.GET("/", s.handleListCases)
			cases.POST("/", s.handleCreateCase)
			cases.GET("/policy", s.handleGetCasePolicy)
			cases.PUT("/policy", s.handleUpdateCasePolicy)
			cases.POST("/from-alert", s.handleCreateCaseFromAlert) // Create case from alert
			cases.POST("/from-event", s.handleCreateCaseFromEvent) // Create case from event
			cases.GET("/statistics", s.handleGetCaseStatistics)
			cases.GET("/export", s.handleExportCases)
			cases.GET("/:id/report", s.handleGetCaseReport) // Case report export
			cases.GET("/:id", s.handleGetCase)
			cases.PUT("/:id", s.handleUpdateCase)
			cases.DELETE("/:id", s.handleDeleteCaseOpenSearch) // Delete case
			cases.POST("/:id/close", s.handleCloseCase)
			cases.GET("/:id/activities", s.handleGetCaseActivities)
			cases.POST("/:id/comments", s.handleAddComment)
			// Checklist
			cases.GET("/:id/checklist", s.handleGetCaseChecklist)
			cases.POST("/:id/checklist", s.handleAddCaseChecklistItem)
			cases.PUT("/:id/checklist/:itemId", s.handleUpdateCaseChecklistItem)
			cases.DELETE("/:id/checklist/:itemId", s.handleDeleteCaseChecklistItem)
			// Playbooks
			cases.GET("/:id/playbooks", s.handleGetCasePlaybooks)
			cases.POST("/:id/playbooks", s.handleAddCasePlaybook)
			cases.POST("/:id/playbooks/:playbookId/execute", s.handleExecuteCasePlaybook)
			cases.DELETE("/:id/playbooks/:playbookId", s.handleDeleteCasePlaybook)
			// Case-Alert/Event sync
			cases.POST("/:id/status-propagate", s.handleUpdateCaseStatusWithPropagation) // Update status with propagation
			cases.GET("/:id/linked-alerts", s.handleGetLinkedAlerts)                     // Get linked alerts
			cases.GET("/:id/linked-events", s.handleGetLinkedEvents)                     // Get linked events
			cases.POST("/:id/link-alert", s.handleLinkAlertToCase)                       // Link alert to case
			cases.POST("/:id/link-event", s.handleLinkEventToCase)                       // Link event to case
		}

		// Alert/Event Suppression (False Positive Rules)
		suppression := protected.Group("/suppression")
		{
			suppression.GET("/rules", s.handleListSuppressionRules)          // List suppression rules
			suppression.POST("/rules", s.handleCreateSuppressionRule)        // Create suppression rule
			suppression.PUT("/rules/:id", s.handleToggleSuppressionRule)     // Toggle rule active/inactive
			suppression.DELETE("/rules/:id", s.handleDeleteSuppressionRule)  // Delete rule
			suppression.POST("/false-positive", s.handleMarkAsFalsePositive) // Mark alert/event as false positive
			suppression.POST("/check", s.handleCheckSuppression)             // Check if alert should be suppressed
		}

		// Alerts in Analysis (linked to cases)
		protected.GET("/alerts/in-analysis", s.handleGetAlertsInAnalysis)

		// MITRE ATT&CK
		mitre := protected.Group("/mitre")
		{
			mitre.GET("/tactics", s.handleGetMITRETactics)
			mitre.GET("/techniques", s.handleGetMITRETechniques)
			mitre.GET("/coverage", s.handleGetMITRECoverageReal)     // Real data from GuardDuty events
			mitre.GET("/timeline", s.handleGetMITRETimelineReal)     // Real data from GuardDuty events
			mitre.GET("/detections", s.handleGetMITREDetectionsReal) // Real data from GuardDuty events
			mitre.GET("/diagnostics", s.handleMITREDiagnostics)      // Diagnostic info
		}

		// Threat Intelligence
		ti := protected.Group("/threat-intelligence")
		{
			// IOCs
			ti.GET("/iocs", s.handleListIOCs)
			ti.POST("/iocs", s.handleCreateIOC)
			ti.GET("/iocs/:id", s.handleGetIOC)
			ti.PUT("/iocs/:id", s.handleUpdateIOC)
			ti.DELETE("/iocs/:id", s.handleDeleteIOC)
			ti.GET("/iocs/related-events", s.handleGetIOCRelatedEvents) // Eventos relacionados a um IOC

			// Enrichment
			ti.GET("/enrich/ip/:ip", s.handleEnrichIP)
			ti.GET("/check/ip", s.handleCheckIP)

			// Feeds
			ti.GET("/feeds", s.handleListFeeds)

			// Stats
			ti.GET("/stats", s.handleGetTIStats)
		}

		// CVE Database - Banco de Vulnerabilidades
		cves := protected.Group("/cves")
		{
			cves.GET("/", s.handleListCVEs)                          // Lista CVEs com filtros e paginação
			cves.GET("/search", s.handleSearchCVEs)                  // Busca CVEs por texto
			cves.GET("/stats", s.handleGetCVEStats)                  // Estatísticas do banco de CVEs
			cves.GET("/diagnostics", s.handleCVEDiagnostics)         // Diagnóstico e teste de conectividade
			cves.GET("/config", s.handleGetNVDConfig)                // Obter configuração do NVD
			cves.POST("/config", s.handleSaveNVDConfig)              // Salvar configuração do NVD
			cves.POST("/test-connection", s.handleTestNVDConnection) // Testar conexão com NVD
			cves.GET("/:id", s.handleGetCVE)                         // Detalhes de um CVE específico
			cves.GET("/:id/alerts", s.handleGetCVEAlerts)            // Alertas relacionados a um CVE
			cves.POST("/sync", s.handleSyncCVEs)                     // Sincronizar com NVD
			cves.GET("/sync/status", s.handleGetCVESyncStatus)       // Status da sincronização
			cves.POST("/update-counts", s.handleUpdateCVEAlertCount) // Atualizar contagem de alertas
		}

		// Executive Dashboard
		executive := protected.Group("/executive")
		{
			// Dashboard completo
			executive.GET("/dashboard", s.handleGetExecutiveDashboard)

			// KPIs
			executive.GET("/kpis", s.handleGetKPIs)

			// Trends
			executive.GET("/trends", s.handleGetTrends)

			// Relatórios
			executive.POST("/reports/generate", s.handleGenerateExecutiveReport)
		}

		// Threat Hunting
		hunting := protected.Group("/hunting")
		{
			// Queries
			hunting.POST("/search", s.handleExecuteHuntingQuery)
			hunting.POST("/pivot", s.handlePivot)

			// Saved Searches
			hunting.GET("/searches", s.handleListSavedSearches)
			hunting.POST("/searches", s.handleCreateSavedSearch)

			// Campaigns
			hunting.GET("/campaigns", s.handleListCampaigns)
			hunting.POST("/campaigns", s.handleCreateCampaign)

			// Findings
			hunting.POST("/findings", s.handleCreateFinding)

			// Timeline
			hunting.GET("/timeline", s.handleGetTimeline)

			// Stats
			hunting.GET("/stats", s.handleGetHuntingStats)
		}

		// UEBA (User Behavior Analytics)
		ueba := protected.Group("/ueba")
		{
			// Dashboard - Real-time from OpenSearch
			ueba.GET("/dashboard", s.handleGetUEBADashboardReal)

			// Users/Profiles - Real-time from OpenSearch
			ueba.GET("/users", s.handleListUserProfilesOpenSearch)
			ueba.GET("/users/:id", s.handleGetUserProfileOpenSearch)
			ueba.POST("/users/:id/analyze", s.handleAnalyzeUser)

			// Anomalies - Real-time from OpenSearch
			ueba.GET("/anomalies", s.handleListAnomaliesOpenSearch)
			ueba.PUT("/anomalies/:id", s.handleUpdateAnomaly)

			// Peer Groups
			ueba.GET("/peer-groups", s.handleGetPeerGroups)

			// Stats - Real-time from OpenSearch
			ueba.GET("/stats", s.handleGetUEBAStatsOpenSearch)

			// Diagnostics and Force Analysis
			ueba.GET("/diagnostics", s.handleUEBADiagnostics)
			ueba.POST("/force-analysis", s.handleForceUEBAAnalysis)
			ueba.POST("/cleanup", s.handleCleanupUEBAProfiles)
		}

		// Compliance & Audit
		compliance := protected.Group("/compliance")
		{
			// Dashboard
			compliance.GET("/dashboard", s.handleGetComplianceDashboard)

			// Frameworks
			compliance.GET("/frameworks", s.handleListFrameworks)
			compliance.GET("/frameworks/:id", s.handleGetFramework)
			compliance.POST("/frameworks/:id/assess", s.handleRunAssessment)

			// Controls
			compliance.GET("/controls", s.handleListControls)
			compliance.PUT("/controls/:id", s.handleUpdateControl)

			// Audit Logs
			compliance.GET("/audit-logs", s.handleListAuditLogs)
			compliance.GET("/audit-trail", s.handleGetAuditTrail)

			// Policy Violations
			compliance.GET("/violations", s.handleListViolations)
			compliance.PUT("/violations/:id", s.handleUpdateViolation)

			// Reports
			compliance.GET("/reports", s.handleListReports)
			compliance.POST("/reports/generate", s.handleGenerateComplianceReport)
			compliance.GET("/reports/:id/download", s.handleDownloadComplianceReport)

			// Gap Analysis
			compliance.GET("/frameworks/:id/gap-analysis", s.handleGetGapAnalysis)

			// Stats
			compliance.GET("/stats", s.handleGetComplianceStats)
		}

		// Vulnerability Management (AWS Inspector Integration)
		vulnerabilities := protected.Group("/vulnerabilities")
		{
			// Dashboard - Real data from AWS Inspector
			vulnerabilities.GET("/dashboard", s.handleGetVulnerabilityDashboardReal)

			// Vulnerabilities - Real data from OpenSearch
			vulnerabilities.GET("/", s.handleListVulnerabilitiesReal)
			vulnerabilities.GET("/:id", s.handleGetVulnerabilityReal)
			vulnerabilities.PUT("/:id", s.handleUpdateVulnerability)

			// Status Management
			vulnerabilities.PUT("/:id/status", s.handleUpdateVulnerabilityStatus)

			// Assets - Real data from OpenSearch
			vulnerabilities.GET("/assets", s.handleListVulnerableAssetsReal)
			vulnerabilities.GET("/assets/:id", s.handleGetVulnerableAssetReal)

			// Scans / Coverage - Real data from AWS Inspector
			vulnerabilities.GET("/scans", s.handleListScansReal)
			vulnerabilities.POST("/scans", s.handleCreateScanReal)
			vulnerabilities.GET("/scans/:id", s.handleGetScanReal)

			// Stats - Real data from OpenSearch
			vulnerabilities.GET("/stats", s.handleGetVulnerabilityStatsReal)

			// Diagnostics - Check AWS Inspector connectivity
			vulnerabilities.GET("/diagnostics", s.handleAWSDiagnostics)
			vulnerabilities.POST("/sync", s.handleForceInspectorSync)

			// Security Hub Integration - Get vulnerabilities from existing Security Hub integration
			vulnerabilities.GET("/from-securityhub", s.handleGetVulnerabilitiesFromSecurityHub)
			vulnerabilities.POST("/sync-securityhub", s.handleSyncVulnerabilitiesFromSecurityHub)
		}

		// ========================================
		// PLA - PROTECTION LEVEL AGREEMENTS
		// Risk Matrix with Guard Rails Assessment
		// ========================================
		pla := protected.Group("/pla")
		{
			// Dashboard
			pla.GET("/dashboard", s.handleGetPLADashboard)
			pla.GET("/config", s.handleGetPLAConfig)

			// Risk Calculator (Preview)
			pla.POST("/calculate", s.handleCalculateRisk)

			// Assessments
			pla.GET("/assessments", s.handleListPLAAssessments)
			pla.POST("/assessments", s.handleCreatePLAAssessment)
			pla.GET("/assessments/:id", s.handleGetPLAAssessment)
			pla.PUT("/assessments/:id", s.handleUpdatePLAAssessment)
			pla.POST("/assessments/:id/guard-rails", s.handleAddGuardRailToAssessment)

			// Guard Rails Catalog
			pla.GET("/guard-rails", s.handleListGuardRails)
		}

		// Network Traffic Analysis (VPC Flow Logs)
		network := protected.Group("/network")
		{
			// Dashboard - Real data from VPC Flow Logs
			network.GET("/dashboard", s.handleGetNetworkDashboardReal)

			// VPC Flow Logs
			network.GET("/flowlogs", s.handleListFlowLogs)
			network.GET("/flowlogs/stats", s.handleGetFlowLogsStats)
			network.POST("/flowlogs/collect", s.handleTriggerFlowLogsCollection)

			// Network Anomalies
			network.GET("/anomalies", s.handleListNetworkAnomalies)

			// Legacy endpoints
			network.GET("/flows", s.handleGetNetworkFlows)

			// Connections
			network.GET("/connections", s.handleGetActiveConnections)

			// Top Talkers
			network.GET("/top-talkers", s.handleGetTopTalkers)

			// Protocol Analysis
			network.GET("/protocols", s.handleGetProtocolStats)

			// Geographic Distribution
			network.GET("/geo-locations", s.handleGetGeoLocations)

			// Bandwidth
			network.GET("/bandwidth", s.handleGetBandwidthMetrics)

			// Port Scans
			network.GET("/port-scans", s.handleGetPortScans)

			// Stats
			network.GET("/stats", s.handleGetNetworkStats)
		}

		// File Integrity Monitoring
		fim := protected.Group("/fim")
		{
			// Dashboard
			fim.GET("/dashboard", s.handleGetFIMDashboard)

			// Monitored Files
			fim.GET("/files", s.handleGetMonitoredFiles)

			// Changes
			fim.GET("/changes", s.handleGetFileChanges)
			fim.POST("/changes/:id/acknowledge", s.handleAcknowledgeChange)

			// Baselines
			fim.GET("/baselines", s.handleGetBaselines)
			fim.POST("/baselines", s.handleCreateBaseline)

			// Rules
			fim.GET("/rules", s.handleGetFIMRules)
			fim.POST("/rules", s.handleCreateFIMRule)

			// Alerts
			fim.GET("/alerts", s.handleGetFIMAlerts)

			// Stats
			fim.GET("/stats", s.handleGetFIMStats)
		}

		// Data Loss Prevention (DLP)
		dlp := protected.Group("/dlp")
		{
			// Dashboard
			dlp.GET("/dashboard", s.handleGetDLPDashboard)

			// Policies
			dlp.GET("/policies", s.handleGetDLPPolicies)
			dlp.POST("/policies", s.handleCreateDLPPolicy)
			dlp.GET("/policies/:id", s.handleGetDLPPolicy)
			dlp.PUT("/policies/:id", s.handleUpdateDLPPolicy)
			dlp.DELETE("/policies/:id", s.handleDeleteDLPPolicy)

			// Incidents
			dlp.GET("/incidents", s.handleGetDLPIncidents)
			dlp.GET("/incidents/:id", s.handleGetDLPIncident)
			dlp.PUT("/incidents/:id", s.handleUpdateDLPIncident)

			// Content Inspection
			dlp.POST("/inspect", s.handleInspectContent)

			// Patterns
			dlp.GET("/patterns", s.handleGetDLPPatterns)
			dlp.POST("/patterns", s.handleCreateDLPPattern)

			// Data Classification
			dlp.GET("/classifications", s.handleGetDataClassifications)
			dlp.POST("/classify", s.handleClassifyData)

			// Stats
			dlp.GET("/stats", s.handleGetDLPStats)
		}

		// Endpoint Detection & Response (EDR)
		edr := protected.Group("/edr")
		{
			// Dashboard
			edr.GET("/dashboard", s.handleGetEDRDashboard)

			// Agents
			edr.GET("/agents", s.handleGetEDRAgents)
			edr.POST("/agents", s.handleDeployAgent)
			edr.GET("/agents/:id", s.handleGetEDRAgent)
			edr.DELETE("/agents/:id", s.handleUninstallAgent)

			// Endpoints
			edr.GET("/endpoints", s.handleGetEndpoints)
			edr.GET("/endpoints/:id", s.handleGetEndpoint)
			edr.POST("/endpoints/:id/isolate", s.handleIsolateEndpoint)
			edr.POST("/endpoints/:id/restore", s.handleRestoreEndpoint)

			// Threats
			edr.GET("/threats", s.handleGetEDRThreats)
			edr.GET("/threats/:id", s.handleGetEDRThreat)
			edr.POST("/threats/:id/action", s.handleTakeActionOnThreat)

			// Processes
			edr.GET("/processes", s.handleGetProcesses)
			edr.POST("/processes/:id/terminate", s.handleTerminateProcess)

			// Memory Scans
			edr.GET("/memory-scans", s.handleGetMemoryScans)
			edr.POST("/memory-scans", s.handleInitiateMemoryScan)

			// Forensics
			edr.GET("/forensics", s.handleGetForensics)
			edr.POST("/forensics", s.handleCollectForensics)

			// Stats
			edr.GET("/stats", s.handleGetEDRStats)
		}

		// Monitoring & Observability
		monitoring := protected.Group("/monitoring")
		{
			// System Metrics
			monitoring.GET("/metrics", s.handleGetMetrics)

			// Health Status
			monitoring.GET("/health", s.handleHealthCheck)
		}

		// System Logs & Diagnostics (Admin only)
		systemLogs := protected.Group("/system")
		systemLogs.Use(RequireAdmin())
		{
			// Logs
			systemLogs.GET("/logs", s.handleGetSystemLogs)
			systemLogs.POST("/logs", s.handleAddSystemLog)
			systemLogs.DELETE("/logs", s.handleClearSystemLogs)

			// Status & Diagnostics
			systemLogs.GET("/status", s.handleGetSystemStatus)
			systemLogs.GET("/config", s.handleGetSystemConfig)

			// AWS Connectivity Test
			systemLogs.GET("/aws-test", s.handleTestAWSConnectivity)

			// OpenSearch Index Management
			systemLogs.GET("/opensearch/index-status", s.handleCheckOpenSearchIndex)
			systemLogs.POST("/opensearch/create-index", s.handleCreateOpenSearchIndex)
			systemLogs.POST("/opensearch/recreate-index", s.handleRecreateIndex)
			systemLogs.POST("/opensearch/force-sync", s.handleForceSyncAWSData)
			systemLogs.GET("/opensearch/recent-events", s.handleGetRecentEvents)
			systemLogs.GET("/opensearch/diagnose-statistics", s.handleDiagnoseStatistics)
			systemLogs.GET("/opensearch/diagnose-s3-cloudtrail", s.handleDiagnoseS3CloudTrail)
		}

		// Incident Response Automation
		incidentResponse := protected.Group("/incident-response")
		{
			// Dashboard
			incidentResponse.GET("/dashboard", s.handleGetIRDashboard)

			// Incidents
			incidentResponse.GET("/incidents", s.handleGetIncidents)
			incidentResponse.POST("/incidents", s.handleCreateIncident)
			incidentResponse.GET("/incidents/:id", s.handleGetIncident)
			incidentResponse.PUT("/incidents/:id", s.handleUpdateIncident)

			// Automation Rules
			incidentResponse.GET("/automation-rules", s.handleGetAutomationRules)
			incidentResponse.POST("/automation-rules", s.handleCreateAutomationRule)

			// Escalation Rules
			incidentResponse.GET("/escalation-rules", s.handleGetEscalationRules)

			// Assignment Rules
			incidentResponse.GET("/assignment-rules", s.handleGetAssignmentRules)

			// Stats
			incidentResponse.GET("/stats", s.handleGetIRStats)
		}

		// Reports & Analytics
		reports := protected.Group("/reports")
		{
			// Report Templates
			reports.GET("/templates", handleListReportTemplates)
			reports.GET("/templates/:id", handleGetReportTemplate)

			// Report Generation
			reports.POST("/generate", handleGenerateReport)
			reports.GET("/", handleListReports)

			// Export
			reports.GET("/:id/export/pdf", handleExportReportPDF)
			reports.GET("/:id/export/excel", handleExportReportExcel)
			reports.GET("/:id/export/csv", handleExportReportCSV)

			// Scheduled Reports
			reports.GET("/schedules", handleListScheduledReports)
			reports.POST("/schedules", handleCreateScheduledReport)

			// Stats
			reports.GET("/stats", handleGetReportStats)
		}

		// Dashboard Customization
		customDashboards := protected.Group("/custom-dashboards")
		{
			// Dashboard CRUD
			customDashboards.GET("/", handleListDashboards)
			customDashboards.POST("/", handleCreateDashboard)
			customDashboards.GET("/:id", handleGetDashboard)
			customDashboards.PUT("/:id", handleUpdateDashboardCustom)
			customDashboards.DELETE("/:id", handleDeleteDashboardCustom)

			// Templates
			customDashboards.GET("/templates/list", handleListTemplates)
			customDashboards.GET("/templates/:id", handleGetTemplate)
			customDashboards.POST("/templates/:id/create", handleCreateFromTemplate)

			// Widget Management
			customDashboards.POST("/:id/widgets", handleAddWidget)
			customDashboards.PUT("/:id/widgets/:widget_id", handleUpdateWidget)
			customDashboards.DELETE("/:id/widgets/:widget_id", handleDeleteWidget)

			// Widget Types & Data
			customDashboards.GET("/widget-types", handleListWidgetTypes)
			customDashboards.GET("/widget-data", handleGetWidgetData)

			// Export/Import
			customDashboards.GET("/:id/export", handleExportDashboard)
			customDashboards.POST("/import", handleImportDashboard)

			// Stats
			customDashboards.GET("/stats/all", handleGetDashboardStats)
		}

		// Notifications
		notifications := protected.Group("/notifications")
		{
			// Notification CRUD
			notifications.GET("/", handleListNotifications)
			notifications.POST("/", handleCreateNotification)
			notifications.GET("/:id", handleGetNotification)
			notifications.DELETE("/:id", handleDeleteNotification)

			// Mark as read
			notifications.POST("/:id/read", handleMarkAsRead)
			notifications.POST("/read-all", handleMarkAllAsRead)

			// Stats
			notifications.GET("/stats/summary", handleGetNotificationStats)

			// Rules
			notifications.GET("/rules", handleListNotificationRules)
			notifications.POST("/rules", handleCreateNotificationRule)
			notifications.PUT("/rules/:id", handleUpdateNotificationRule)
			notifications.DELETE("/rules/:id", handleDeleteNotificationRule)

			// Templates
			notifications.GET("/templates", handleListNotificationTemplates)
			notifications.POST("/templates", handleCreateNotificationTemplate)
			notifications.DELETE("/templates/:id", handleDeleteNotificationTemplate)

			// Channels
			notifications.GET("/channels", handleListNotificationChannels)
			notifications.POST("/channels", handleCreateNotificationChannel)
			notifications.PUT("/channels/:id", handleUpdateNotificationChannel)
			notifications.DELETE("/channels/:id", handleDeleteNotificationChannel)
		}

		// Data Retention Policies
		retention := protected.Group("/retention")
		{
			// Policies CRUD
			retention.GET("/policies", handleListRetentionPolicies)
			retention.POST("/policies", handleCreateRetentionPolicy)
			retention.GET("/policies/:id", handleGetRetentionPolicy)
			retention.PUT("/policies/:id", handleUpdateRetentionPolicy)
			retention.DELETE("/policies/:id", handleDeleteRetentionPolicy)

			// Execute policy
			retention.POST("/policies/:id/execute", handleExecuteRetentionPolicy)

			// Executions
			retention.GET("/executions", handleListRetentionExecutions)
			retention.GET("/executions/:id", handleGetRetentionExecution)

			// Statistics
			retention.GET("/stats", handleGetRetentionStats)

			// Data type configs
			retention.GET("/configs", handleListDataTypeConfigs)
			retention.PUT("/configs/:type", handleUpdateDataTypeConfig)
		}

		// Automated Response Engine (MDR)
		automatedResponse := protected.Group("/automated-response")
		{
			// Response Rules CRUD
			automatedResponse.GET("/rules", s.handleListResponseRules)
			automatedResponse.POST("/rules", s.handleCreateResponseRule)
			automatedResponse.GET("/rules/:id", s.handleGetResponseRule)
			automatedResponse.PUT("/rules/:id", s.handleUpdateResponseRule)
			automatedResponse.DELETE("/rules/:id", s.handleDeleteResponseRule)

			// Executions
			automatedResponse.GET("/executions", s.handleListResponseExecutions)
			automatedResponse.GET("/executions/:id", s.handleGetResponseExecution)
			automatedResponse.POST("/executions/trigger", s.handleTriggerExecution)
			automatedResponse.POST("/executions/:id/cancel", s.handleCancelExecution)
			automatedResponse.POST("/executions/:id/rollback", s.handleRollbackExecution)

			// Approvals
			automatedResponse.GET("/approvals", s.handleListApprovals)
			automatedResponse.POST("/executions/:id/approve", s.handleApproveExecution)
			automatedResponse.POST("/executions/:id/reject", s.handleRejectExecution)

			// Statistics
			automatedResponse.GET("/stats", s.handleGetResponseStats)
		}

		// Intelligent Alert Triage (MDR)
		alertTriage := protected.Group("/alert-triage")
		{
			// Real-time Triage Operations (integrated with OpenSearch)
			alertTriage.GET("/queue", s.handleGetAlertsForTriage)       // Get alerts pending triage
			alertTriage.POST("/action/:id", s.handleTriageAlertAction)  // Perform triage action
			alertTriage.POST("/bulk-action", s.handleBulkTriageAction)  // Bulk triage actions
			alertTriage.GET("/statistics", s.handleGetTriageStatistics) // Real-time stats

			// Legacy Triage Operations (ML-based)
			alertTriage.POST("/triage", s.handleTriageAlert)
			alertTriage.GET("/results", s.handleListTriageResults)
			alertTriage.GET("/results/:id", s.handleGetTriageResult)
			alertTriage.PUT("/results/:id", s.handleUpdateTriageResult)
			alertTriage.POST("/results/:id/false-positive", s.handleMarkFalsePositive)

			// Triage Rules
			alertTriage.GET("/rules", s.handleListTriageRules)
			alertTriage.POST("/rules", s.handleCreateTriageRule)
			alertTriage.PUT("/rules/:id", s.handleUpdateTriageRule)
			alertTriage.DELETE("/rules/:id", s.handleDeleteTriageRule)

			// Analyst Management
			alertTriage.GET("/analysts", s.handleListAnalystProfiles)
			alertTriage.PUT("/analysts/:id", s.handleUpdateAnalystProfile)

			// Statistics (legacy)
			alertTriage.GET("/stats", s.handleGetTriageStats)
		}

		// Alert Correlation Engine
		correlation := protected.Group("/correlation")
		{
			// Correlated Incidents
			correlation.GET("/incidents", s.handleListCorrelatedIncidents)
			correlation.GET("/incidents/:id", s.handleGetCorrelatedIncident)
			correlation.PUT("/incidents/:id", s.handleUpdateCorrelatedIncident)
			correlation.POST("/incidents/:id/create-case", s.handleCreateCaseFromIncident)

			// Correlation Rules
			correlation.GET("/rules", s.handleListCorrelationRules)

			// Statistics
			correlation.GET("/stats", s.handleGetCorrelationStats)
		}

		// SLA & Metrics Tracking (MDR)
		slaMetrics := protected.Group("/sla-metrics")
		{
			// SLA Policies
			slaMetrics.GET("/policies", s.handleListSLAPolicies)
			slaMetrics.POST("/policies", s.handleCreateSLAPolicy)
			slaMetrics.PUT("/policies/:id", s.handleUpdateSLAPolicy)
			slaMetrics.DELETE("/policies/:id", s.handleDeleteSLAPolicy)

			// SLA Tracking
			slaMetrics.GET("/trackings", s.handleListSLATrackings)
			slaMetrics.GET("/trackings/:id", s.handleGetSLATracking)

			// Breaches
			slaMetrics.GET("/breaches", s.handleListSLABreaches)

			// Statistics & Metrics
			slaMetrics.GET("/stats", s.handleGetSLAStats)
			slaMetrics.GET("/metrics", s.handleGetSLAMetrics)
		}

		// Executive Dashboard (MDR)
		mdrDashboard := protected.Group("/mdr-dashboard")
		{
			mdrDashboard.GET("/", s.handleGetMDRExecutiveDashboard)
			mdrDashboard.GET("/security-posture", s.handleGetMDRSecurityPosture)
			mdrDashboard.GET("/mdr-performance", s.handleGetMDRPerformanceMetrics)
			mdrDashboard.GET("/business-impact", s.handleGetMDRBusinessImpact)
			mdrDashboard.GET("/threat-intel-summary", s.handleGetMDRThreatIntelSummary)
			mdrDashboard.GET("/compliance-status", s.handleGetMDRComplianceStatus)
			mdrDashboard.GET("/critical-alerts", s.handleGetMDRCriticalAlerts)
		}

		// Threat Hunting Platform (MDR Phase 2)
		threatHuntingPlatform := protected.Group("/threat-hunting-platform")
		{
			threatHuntingPlatform.GET("/hypotheses", s.handleListThreatHuntHypotheses)
			threatHuntingPlatform.POST("/hypotheses", s.handleCreateThreatHuntHypothesis)
			threatHuntingPlatform.GET("/hypotheses/:id", s.handleGetThreatHuntHypothesis)
			threatHuntingPlatform.PUT("/hypotheses/:id", s.handleUpdateThreatHuntHypothesis)
			threatHuntingPlatform.DELETE("/hypotheses/:id", s.handleDeleteThreatHuntHypothesis)
			threatHuntingPlatform.GET("/templates", s.handleListQueryTemplates)
			threatHuntingPlatform.POST("/execute", s.handleExecuteThreatHuntQuery)
			threatHuntingPlatform.GET("/notebooks", s.handleListThreatHuntNotebooks)
			threatHuntingPlatform.POST("/notebooks", s.handleCreateThreatHuntNotebook)
			threatHuntingPlatform.GET("/scheduled", s.handleListThreatScheduledHunts)
			threatHuntingPlatform.POST("/scheduled", s.handleCreateThreatScheduledHunt)
			threatHuntingPlatform.GET("/metrics", s.handleGetThreatHuntMetrics)

			// Hunting History / Activities
			threatHuntingPlatform.GET("/activities", s.handleGetHuntingActivities)
			threatHuntingPlatform.GET("/activities/statistics", s.handleGetActivityStatistics)
		}

		// Automated Forensics (MDR Phase 2) - Now uses OpenSearch for persistence
		mdrForensics := protected.Group("/mdr-forensics")
		{
			mdrForensics.GET("/cases", s.handleListMDRForensicCases)
			mdrForensics.POST("/cases", s.handleCreateMDRForensicCase)
			mdrForensics.GET("/cases/:id", s.handleGetMDRForensicCase)
			mdrForensics.GET("/evidence", s.handleListMDRForensicEvidence)
			mdrForensics.POST("/evidence", s.handleCreateMDRForensicEvidence)
			mdrForensics.GET("/cases/:id/timeline", s.handleGetMDRForensicTimeline)
			mdrForensics.GET("/stats", s.handleGetMDRForensicStats)
		}

		// Digital Forensics (Full OpenSearch Integration)
		forensics := protected.Group("/forensics")
		{
			forensics.GET("/investigations", s.handleListForensicInvestigations)
			forensics.POST("/investigations", s.handleCreateForensicInvestigation)
			forensics.GET("/investigations/:id", s.handleGetForensicInvestigation)
			forensics.PUT("/investigations/:id", s.handleUpdateForensicInvestigation)
			forensics.DELETE("/investigations/:id", s.handleDeleteForensicInvestigation)
			forensics.GET("/investigations/:id/timeline", s.handleGetForensicTimeline)
			forensics.POST("/investigations/:id/timeline", s.handleAddForensicTimelineEntry)
			forensics.GET("/evidence", s.handleListForensicEvidence)
			forensics.POST("/evidence", s.handleCreateForensicEvidence)
			forensics.GET("/stats", s.handleGetForensicStats)
		}

		// Threat Intelligence Platform (MDR Phase 2)
		mdrThreatIntel := protected.Group("/mdr-threat-intel")
		{
			mdrThreatIntel.GET("/feeds", s.handleListMDRThreatFeeds)
			mdrThreatIntel.POST("/feeds", s.handleCreateMDRThreatFeed)
			mdrThreatIntel.GET("/actors", s.handleListMDRThreatActors)
			mdrThreatIntel.GET("/iocs", s.handleListMDRThreatIOCs)
			mdrThreatIntel.GET("/stats", s.handleGetMDRThreatIntelStats)
		}

		// Multi-Tenancy (MDR Phase 2)
		mdrMultiTenancy := protected.Group("/mdr-tenants")
		{
			mdrMultiTenancy.GET("/", s.handleListMDRTenants)
			mdrMultiTenancy.POST("/", s.handleCreateMDRTenant)
			mdrMultiTenancy.GET("/:id", s.handleGetMDRTenant)
			mdrMultiTenancy.PUT("/:id", s.handleUpdateMDRTenant)
			mdrMultiTenancy.GET("/:id/config", s.handleGetMDRTenantConfig)
			mdrMultiTenancy.GET("/stats", s.handleGetMDRTenantStats)
		}

		// Advanced Threat Hunting (MDR Phase 3)
		advHunting := protected.Group("/advanced-hunting")
		{
			advHunting.GET("/campaigns", s.handleListAdvHuntingCampaigns)
			advHunting.POST("/campaigns", s.handleCreateAdvHuntingCampaign)
			advHunting.GET("/campaigns/:id", s.handleGetAdvHuntingCampaign)
			advHunting.GET("/queries", s.handleListAdvHuntingQueries)
			advHunting.POST("/queries", s.handleCreateAdvHuntingQuery)
			advHunting.GET("/notebooks", s.handleListAdvHuntingNotebooks)
			advHunting.POST("/notebooks", s.handleCreateAdvHuntingNotebook)
			advHunting.GET("/metrics", s.handleGetAdvHuntingMetrics)
			advHunting.GET("/mitre-coverage", s.handleGetAdvancedMITRECoverage)
		}

		// Deception Technology (MDR Phase 3)
		deception := protected.Group("/deception")
		{
			deception.GET("/honeypots", s.handleListHoneypots)
			deception.POST("/honeypots", s.handleCreateHoneypot)
			deception.GET("/honeytokens", s.handleListHoneytokens)
			deception.POST("/honeytokens", s.handleCreateHoneytoken)
			deception.GET("/decoys", s.handleListDecoySystems)
			deception.GET("/activity", s.handleListAttackerActivity)
			deception.GET("/metrics", s.handleGetDeceptionMetrics)
		}

		// Continuous Validation (MDR Phase 3)
		validation := protected.Group("/validation")
		{
			validation.GET("/controls", s.handleListSecurityControls)
			validation.GET("/tests", s.handleListValidationTests)
			validation.GET("/coverage", s.handleGetValidationCoverage)
			validation.GET("/gaps", s.handleGetValidationGaps)
			validation.GET("/reports", s.handleGetValidationReports)
			validation.GET("/metrics", s.handleGetValidationMetrics)
		}

		// Security Awareness (MDR Phase 3)
		awareness := protected.Group("/awareness")
		{
			awareness.GET("/campaigns", s.handleListPhishingCampaigns)
			awareness.POST("/campaigns", s.handleCreatePhishingCampaign)
			awareness.GET("/templates", s.handleListPhishingTemplates)
			awareness.GET("/trainings", s.handleListTrainingModules)
			awareness.GET("/users", s.handleListUserRiskProfiles)
			awareness.GET("/metrics", s.handleGetAwarenessMetrics)
			awareness.GET("/leaderboard", s.handleGetGamificationLeaderboard)
		}

		// Advanced Analytics & ML (MDR Phase 4)
		analytics := protected.Group("/analytics")
		{
			// Real-time from OpenSearch
			analytics.GET("/anomalies", s.handleListMLAnomaliesOpenSearch)
			analytics.GET("/behavioral-profiles", s.handleListUserProfilesOpenSearch)
			analytics.GET("/predictions", s.handleListPredictionsOpenSearch)
			analytics.GET("/models", s.handleListMLModels)                            // Keep mock for now
			analytics.GET("/risk-assessments", s.handleListRiskAssessmentsOpenSearch) // Real data from OpenSearch
			analytics.GET("/metrics", s.handleGetMLStatsOpenSearch)

			// Diagnostics and Force Analysis
			analytics.GET("/diagnostics", s.handleMLDiagnostics)
			analytics.POST("/force-analysis", s.handleForceMLAnalysis)
			analytics.POST("/cleanup-duplicates", s.handleCleanupDuplicateAnomalies)
		}

		// SOAR - Security Orchestration, Automation and Response (MDR Phase 4)
		soar := protected.Group("/soar")
		{
			soar.GET("/playbooks", s.handleListSOARPlaybooks)
			soar.GET("/executions", s.handleListSOARExecutions)
			soar.GET("/integrations", s.handleListSOARIntegrations)
			soar.GET("/cases", s.handleListSOARCases)
			soar.GET("/workflows", s.handleListSOARWorkflows)
			soar.GET("/metrics", s.handleGetSOARMetrics)
		}

		// Threat Intelligence Fusion (MDR Phase 4)
		threatIntel := protected.Group("/threat-intel-fusion")
		{
			threatIntel.GET("/feeds", s.handleListThreatIntelFeeds)
			threatIntel.GET("/indicators", s.handleListEnrichedIndicators)
			threatIntel.GET("/actors", s.handleListThreatActors)
			threatIntel.POST("/actors", s.handleCreateThreatActor)
			threatIntel.GET("/campaigns", s.handleListThreatCampaigns)
			threatIntel.POST("/campaigns", s.handleCreateTICampaign)
			threatIntel.GET("/correlations", s.handleListCorrelations)
			threatIntel.PUT("/correlations/:id", s.handleUpdateCorrelationStatus)
			threatIntel.GET("/correlations/stats", s.handleGetTICorrelationStats)
			threatIntel.GET("/metrics", s.handleGetThreatIntelMetrics)

			// IOC Lookup (Real-time threat intelligence)
			threatIntel.GET("/lookup", s.handleLookupIOC)               // Single IOC lookup
			threatIntel.POST("/lookup/bulk", s.handleBulkLookupIOC)     // Bulk IOC lookup
			threatIntel.POST("/feeds/:id/sync", s.handleSyncThreatFeed) // Sync threat feed
			threatIntel.GET("/stats", s.handleGetThreatIntelStats)      // Threat intel stats
		}

		// CSPM - Cloud Security Posture Management (MDR Phase 4)
		cspm := protected.Group("/cspm")
		{
			cspm.GET("/accounts", s.handleListCloudAccounts)
			cspm.GET("/resources", s.handleListCloudResources)
			cspm.GET("/findings", s.handleListSecurityFindings)
			cspm.GET("/compliance", s.handleListComplianceReports)
			cspm.GET("/compliance/:id/findings", s.handleGetComplianceFindings)
			cspm.GET("/remediation", s.handleListRemediationTasks)
			cspm.GET("/metrics", s.handleGetCSPMMetrics)

			// AWS Integrations
			cspm.GET("/aws/config/findings", s.handleGetAWSConfigFindings)
			cspm.GET("/aws/config/rules", s.handleGetAWSConfigRules)
			cspm.GET("/aws/security-hub/findings", s.handleGetSecurityHubFindings)
			cspm.GET("/aws/guardduty/findings", s.handleGetGuardDutyFindings)
			cspm.GET("/aws/inspector/findings", s.handleGetInspectorFindings)
			cspm.GET("/aws/cloudtrail/events", s.handleGetCloudTrailEvents)
			cspm.GET("/aws/status", s.handleGetAWSIntegrationStatus)
			cspm.POST("/aws/sync", s.handleSyncAWSData)
			cspm.POST("/aws/test", s.handleTestAWSConnection)

			// Auto-Remediation
			cspm.GET("/remediation/rules", s.handleListRemediationRules)
			cspm.GET("/remediation/rules/:id", s.handleGetRemediationRule)
			cspm.GET("/remediation/executions", s.handleListRemediationExecutions)
			cspm.GET("/remediation/executions/:id", s.handleGetRemediationExecution)
			cspm.GET("/remediation/approvals", s.handleListApprovalRequests)
			cspm.POST("/remediation/approvals/:id/approve", s.handleApproveRemediation)
			cspm.POST("/remediation/approvals/:id/reject", s.handleRejectRemediation)
			cspm.POST("/remediation/executions/:id/rollback", s.handleRollbackRemediation)
			cspm.GET("/remediation/statistics", s.handleGetRemediationStatistics)

			// Alert System
			cspm.GET("/alerts/channels", s.handleListAlertChannels)
			cspm.GET("/alerts/channels/:id", s.handleGetAlertChannel)
			cspm.POST("/alerts/channels", s.handleCreateAlertChannel)
			cspm.PUT("/alerts/channels/:id", s.handleUpdateAlertChannel)
			cspm.DELETE("/alerts/channels/:id", s.handleDeleteAlertChannel)
			cspm.POST("/alerts/channels/:id/test", s.handleTestAlertChannel)

			cspm.GET("/alerts/rules", s.handleListAlertRules)
			cspm.GET("/alerts/rules/:id", s.handleGetAlertRule)
			cspm.POST("/alerts/rules", s.handleCreateAlertRule)
			cspm.PUT("/alerts/rules/:id", s.handleUpdateAlertRule)
			cspm.DELETE("/alerts/rules/:id", s.handleDeleteAlertRule)

			cspm.GET("/alerts", s.handleListCSPMAlerts)
			cspm.GET("/alerts/:id", s.handleGetCSPMAlert)
			cspm.POST("/alerts/:id/acknowledge", s.handleAcknowledgeAlert)
			cspm.POST("/alerts/:id/resolve", s.handleResolveAlert)
			cspm.GET("/alerts/statistics", s.handleGetCSPMAlertStatistics)

			cspm.GET("/alerts/escalation-policies", s.handleListEscalationPolicies)
			cspm.GET("/alerts/escalation-policies/:id", s.handleGetEscalationPolicy)

			// PCI-DSS Compliance Dashboard
			cspm.GET("/pci-dss/dashboard", s.handleGetPCIDSSDashboard)
			cspm.GET("/pci-dss/requirements", s.handleListPCIDSSRequirements)
			cspm.GET("/pci-dss/requirements/:id", s.handleGetPCIDSSRequirement)
			cspm.GET("/pci-dss/controls", s.handleListPCIDSSControls)
			cspm.GET("/pci-dss/controls/:id", s.handleGetPCIDSSControl)

			// Drift Detection
			cspm.GET("/drift/baselines", s.handleListDriftBaselines)
			cspm.GET("/drift/baselines/:id", s.handleGetDriftBaseline)
			cspm.POST("/drift/baselines", s.handleCreateDriftBaseline)
			cspm.GET("/drift/detections", s.handleListDrifts)
			cspm.GET("/drift/detections/:id", s.handleGetDrift)
			cspm.PUT("/drift/detections/:id/status", s.handleUpdateDriftStatus)
			cspm.GET("/drift/statistics", s.handleGetDriftStatistics)
			cspm.GET("/drift/scan-configs", s.handleListScanConfigs)
			cspm.POST("/drift/scan-configs/:id/run", s.handleRunDriftScan)

			// AWS Config Aggregator (Multi-Account)
			cspm.GET("/aggregator/accounts", s.handleListAccounts)
			cspm.GET("/aggregator/accounts/:id", s.handleGetAccount)
			cspm.POST("/aggregator/accounts", s.handleAddAccount)
			cspm.PUT("/aggregator/accounts/:id", s.handleUpdateAccount)
			cspm.DELETE("/aggregator/accounts/:id", s.handleDeleteAccount)
			cspm.GET("/aggregator/aggregators", s.handleListAggregators)
			cspm.GET("/aggregator/aggregators/:id", s.handleGetAggregator)
			cspm.GET("/aggregator/aggregators/:id/data", s.handleGetAggregatedData)
			cspm.GET("/aggregator/aggregators/:id/sync-status", s.handleGetSyncStatus)
			cspm.POST("/aggregator/aggregators/:id/sync", s.handleTriggerSync)

			// AWS STS Connection Management
			cspm.GET("/connections", s.handleListConnections)
			cspm.GET("/connections/:id", s.handleGetConnection)
			cspm.POST("/connections", s.handleCreateConnection)
			cspm.PUT("/connections/:id", s.handleUpdateConnection)
			cspm.DELETE("/connections/:id", s.handleDeleteConnection)
			cspm.POST("/connections/:id/refresh", s.handleRefreshConnection)
			cspm.POST("/connections/:id/test", s.handleTestConnection)
			cspm.GET("/connections/:id/health", s.handleGetConnectionHealth)
			cspm.GET("/connections/statistics", s.handleGetConnectionStatistics)
			cspm.POST("/connections/bulk-refresh", s.handleBulkRefreshConnections)

			// GCP Integrations
			cspm.GET("/gcp/status", s.handleGCPStatus)
			cspm.GET("/gcp/config", s.handleGCPConfig)
			cspm.POST("/gcp/config", s.handleGCPConfig)
			cspm.POST("/gcp/test", s.handleGCPTest)
			cspm.POST("/gcp/sync", s.handleGCPSync)
			cspm.GET("/gcp/findings", s.handleGCPFindings)
			cspm.GET("/gcp/stats", s.handleGCPStats)
			cspm.GET("/gcp/diagnostic", s.handleGCPDiagnostic)
		}

		// Zero Trust Architecture (MDR Phase 4)
		zeroTrust := protected.Group("/zero-trust")
		{
			zeroTrust.GET("/identities", s.handleListZeroTrustIdentities)
			zeroTrust.GET("/devices", s.handleListZeroTrustDevices)
			zeroTrust.GET("/policies", s.handleListZeroTrustPolicies)
			zeroTrust.POST("/policies", s.handleCreateZeroTrustPolicy)
			zeroTrust.PUT("/policies/:id", s.handleUpdateZeroTrustPolicy)
			zeroTrust.DELETE("/policies/:id", s.handleDeleteZeroTrustPolicy)
			zeroTrust.POST("/policies/:id/toggle", s.handleToggleZeroTrustPolicy)
			zeroTrust.GET("/access", s.handleListZeroTrustAccess)
			zeroTrust.GET("/segments", s.handleListZeroTrustSegments)
			zeroTrust.GET("/metrics", s.handleGetZeroTrustMetrics)
		}

		// Module Manager - Leitura para todos, escrita apenas admin
		modules := protected.Group("/modules")
		{
			// Leitura de módulos - todos os usuários autenticados
			modules.GET("/", s.handleListModules)
			modules.GET("/config", s.handleGetModuleConfig)

			// Modificação de módulos - apenas admin
			modules.PUT("/:id/status", RequireAdmin(), s.handleUpdateModuleStatus)
			modules.POST("/bulk-update", RequireAdmin(), s.handleBulkUpdateModules)
		}

		// Integrations (System Administration - Admin Only)
		integrationsGroup := protected.Group("/integrations")
		integrationsGroup.Use(RequireAdmin())
		{
			integrationsGroup.GET("/", s.handleListIntegrations)
			integrationsGroup.POST("/", s.handleCreateIntegration)
			integrationsGroup.GET("/templates", s.handleGetIntegrationTemplates)
			integrationsGroup.GET("/stats", s.handleGetIntegrationStats)
			integrationsGroup.GET("/:id", s.handleGetIntegration)
			integrationsGroup.PUT("/:id", s.handleUpdateIntegration)
			integrationsGroup.DELETE("/:id", s.handleDeleteIntegration)
			integrationsGroup.POST("/:id/test", s.handleTestIntegration)
			integrationsGroup.POST("/:id/sync", s.handleSyncIntegration)
			integrationsGroup.GET("/:id/logs", s.handleGetIntegrationLogs)
		}

		// ========================================
		// FORTINET WEBHOOK & LOGS
		// ========================================
		// Fortinet Webhook Configuration (Admin only)
		fortinetAdmin := protected.Group("/fortinet")
		fortinetAdmin.Use(RequireAdmin())
		{
			// Webhook Configurations
			fortinetAdmin.GET("/configs", s.handleListFortinetConfigs)
			fortinetAdmin.POST("/configs", s.handleCreateFortinetConfig)
			fortinetAdmin.PUT("/configs/:id", s.handleUpdateFortinetConfig)
			fortinetAdmin.DELETE("/configs/:id", s.handleDeleteFortinetConfig)

			// Dashboard & Statistics
			fortinetAdmin.GET("/dashboard", s.handleGetFortinetDashboard)
			fortinetAdmin.GET("/stats", s.handleGetFortinetStats)

			// Events & Alerts Query
			fortinetAdmin.GET("/events", s.handleGetFortinetEvents)
			fortinetAdmin.GET("/alerts", s.handleGetFortinetAlerts)
		}

		// ========================================
		// CLOUDFLARE WAF INTEGRATION
		// ========================================
		cloudflareGroup := protected.Group("/cloudflare")
		cloudflareGroup.Use(RequireAdmin())
		{
			// Status e Configuração
			cloudflareGroup.GET("/status", s.handleCloudflareStatus)
			cloudflareGroup.GET("/config", s.handleCloudflareConfig)
			cloudflareGroup.POST("/config", s.handleCloudflareConfig)

			// Zonas e Teste de Conexão
			cloudflareGroup.GET("/zones", s.handleCloudflareZones)
			cloudflareGroup.POST("/test", s.handleCloudflareTest)

			// Sincronização e Eventos
			cloudflareGroup.POST("/sync", s.handleCloudflareSync)
			cloudflareGroup.GET("/events", s.handleCloudflareEvents)
			cloudflareGroup.GET("/stats", s.handleCloudflareStats)

			// Diagnóstico - testa todas as APIs disponíveis
			cloudflareGroup.GET("/diagnostic", s.handleCloudflareDiagnostic)
		}

		// ========================================
		// JUMPCLOUD INTEGRATION
		// ========================================
		jumpcloudGroup := protected.Group("/jumpcloud")
		jumpcloudGroup.Use(RequireAdmin())
		{
			jumpcloudGroup.GET("/status", s.handleJumpCloudStatus)
			jumpcloudGroup.GET("/config", s.handleJumpCloudConfig)
			jumpcloudGroup.POST("/config", s.handleJumpCloudConfig)
			jumpcloudGroup.POST("/test", s.handleJumpCloudTest)
			jumpcloudGroup.POST("/sync", s.handleJumpCloudSync)
			jumpcloudGroup.GET("/events", s.handleJumpCloudEvents)
			jumpcloudGroup.GET("/stats", s.handleJumpCloudStatsEndpoint)
			jumpcloudGroup.GET("/diagnostic", s.handleJumpCloudDiagnostic)
		}
	}
}

func (s *APIServer) Start() error {
	srv := &http.Server{
		Addr:    s.config.Server.Address,
		Handler: s.router,
	}

	// Iniciar servidor em goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Erro ao iniciar servidor: %v", err)
		}
	}()

	// Aguardar sinal de interrupção
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Shutdown gracioso
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return err
	}

	return nil
}

func main() {
	config := loadConfig()

	// =========================================================================
	// VALIDATE CRITICAL SECURITY CONFIGURATION
	// =========================================================================
	if config.JWT.Secret == "" || len(config.JWT.Secret) < 32 {
		log.Fatal("FATAL: JWT_SECRET environment variable must be set with at least 32 characters. " +
			"Generate one with: openssl rand -base64 48")
	}

	// =========================================================================
	// CONNECT TO DATABASE
	// =========================================================================
	log.Println("🔌 Connecting to PostgreSQL database...")
	dbConfig := database.LoadConfigFromEnv()
	if err := database.Connect(dbConfig); err != nil {
		log.Printf("⚠️  Failed to connect to database: %v", err)
		log.Println("⚠️  Continuing with in-memory storage...")
	} else {
		log.Println("✅ Successfully connected to PostgreSQL")
		// Ensure database connection is closed on shutdown
		defer func() {
			if err := database.Close(); err != nil {
				log.Printf("Error closing database: %v", err)
			}
		}()
	}

	// Initialize systems
	initNotificationSystem()
	initRetentionSystem()
	initAutomatedResponseSystem()
	initAlertTriageSystem()
	initSLAMetricsSystem()
	initThreatHuntingPlatform()
	initHuntingActivities() // Initialize hunting history
	initMDRForensics()
	initMDRThreatIntel()
	initMDRMultiTenancy()
	initAdvancedThreatHunting()
	initDeceptionTechnology()
	initContinuousValidation()
	initSecurityAwareness()
	initAdvancedAnalytics()
	initSOAR()
	initThreatIntelFusion()
	initCSPM()
	initCSPMAWS()           // Initialize AWS integrations for CSPM
	initAutoRemediation()   // Initialize auto-remediation system
	initCSPMAlerts()        // Initialize alert system for CSPM
	initPCIDSS()            // Initialize PCI-DSS compliance tracking
	initComplianceReports() // Initialize compliance reports storage
	initDriftDetection()    // Initialize drift detection system
	initConfigAggregator()  // Initialize AWS Config Aggregator
	initAWSSTSManager()     // Initialize AWS STS Manager for credential management
	initZeroTrust()
	initModuleManager()
	initIntegrations()    // Initialize integrations
	initFortinetWebhook() // Initialize Fortinet webhook receiver
	initPLASystem()       // Initialize PLA Risk Matrix system
	initSystemLogs()      // Initialize system logs for frontend diagnostics

	server, err := NewAPIServer(config)
	if err != nil {
		log.Fatalf("Erro ao criar servidor API: %v", err)
	}

	// ==========================================================================
	// ENSURE OPENSEARCH INDICES EXIST
	// ==========================================================================
	if err := server.EnsureSIEMEventsIndex(); err != nil {
		log.Printf("⚠️ Failed to ensure siem-events index: %v", err)
		AddSystemLog("WARN", "opensearch", fmt.Sprintf("Failed to create index: %v", err), nil)
	}

	// Ensure Cases index exists for Case Management
	server.EnsureCasesIndex()
	log.Printf("✅ Cases index (siem-cases) ensured")

	// Ensure Case Policies index exists
	server.EnsureCasePoliciesIndex()
	log.Printf("✅ Case Policies index (siem-case-policies) ensured")

	// Ensure Playbooks and Executions indices exist for SOAR
	server.EnsurePlaybooksIndex()
	server.EnsureExecutionsIndex()
	log.Printf("✅ Playbooks indices (siem-playbooks, siem-executions) ensured")

	// Ensure UEBA indices exist for User Behavior Analytics
	server.EnsureUEBAIndices()
	log.Printf("✅ UEBA indices (siem-ueba-profiles, siem-ueba-anomalies) ensured")

	// Ensure ML Analytics indices exist
	server.EnsureMLIndices()
	log.Printf("✅ ML Analytics indices (siem-ml-anomalies, siem-ml-predictions) ensured")

	// Ensure Vulnerabilities index exists for AWS Inspector
	server.EnsureVulnerabilitiesIndex()
	log.Printf("✅ Vulnerabilities index (siem-vulnerabilities) ensured")

	// Ensure VPC Flow Logs indices exist
	server.EnsureVPCFlowLogsIndex()
	log.Printf("✅ VPC Flow Logs indices (siem-vpc-flowlogs, siem-network-anomalies) ensured")

	// Ensure Fortinet indices exist for FortiGate integration
	server.EnsureFortinetIndices()
	log.Printf("✅ Fortinet indices (siem-fortinet-logs, siem-fortinet-alerts) ensured")

	// Ensure Forensics indices exist for Digital Forensics
	server.EnsureForensicsIndex()
	log.Printf("✅ Forensics indices (siem-forensics, siem-forensics-evidence, siem-forensics-timeline) ensured")

	// Ensure Threat Intelligence indices exist for IOCs and Feeds
	server.EnsureIOCsIndex()
	log.Printf("✅ Threat Intelligence indices (siem-iocs, siem-threat-feeds) ensured")

	// Ensure CVE Database index exists
	server.EnsureCVEsIndex()
	log.Printf("✅ CVE Database index (siem-cves) ensured")

	// Ensure Case-Alert sync and Suppression indices exist
	server.EnsureCaseAlertSyncIndices()
	log.Printf("✅ Case-Alert sync indices (siem-alert-case-links, siem-suppression-rules) ensured")

	// Initialize GCP Collector for CSPM
	InitGCPCollector(server.opensearch)

	// Initialize Cloudflare WAF Collector
	cloudflareCollector := InitCloudflareCollector(server.opensearch)
	if cloudflareCollector != nil {
		log.Printf("✅ Cloudflare WAF Collector initialized")
		// Auto-start if enabled in config
		if cloudflareCollector.config.Enabled {
			cloudflareCollector.Start()
			log.Printf("🔄 Cloudflare WAF Collector started (sync every %d minutes)", cloudflareCollector.config.SyncPeriod)
		}
	}

	// Initialize JumpCloud Collector
	jcCollector := InitJumpCloudCollector(server.opensearch)
	if jcCollector != nil {
		log.Printf("✅ JumpCloud Collector initialized")
		if jcCollector.config.Enabled {
			jcCollector.Start()
			log.Printf("🔄 JumpCloud Collector started (sync every %d minutes)", jcCollector.config.SyncPeriod)
		}
	}

	// Auto-start GCP Collector if enabled
	if gcpCollector != nil && gcpCollector.config.Enabled {
		gcpCollector.Start()
		log.Printf("🔄 GCP Collector started (sync every %d minutes)", gcpCollector.config.SyncPeriodMinutes)
	}

	// ==========================================================================
	// START BACKGROUND INDEXERS FOR REAL-TIME DATA
	// ==========================================================================

	// Check environment variables for indexer configuration
	useS3CloudTrailMode := os.Getenv("CLOUDTRAIL_S3_BUCKET") != ""
	useSecurityHubMode := os.Getenv("USE_SECURITY_HUB") == "true"
	useRealAWSData := os.Getenv("USE_REAL_AWS_DATA") == "true"

	log.Printf("🔧 Indexer Configuration:")
	log.Printf("   - S3 CloudTrail Mode: %v (CLOUDTRAIL_S3_BUCKET=%s)", useS3CloudTrailMode, os.Getenv("CLOUDTRAIL_S3_BUCKET"))
	log.Printf("   - Security Hub Mode: %v", useSecurityHubMode)
	log.Printf("   - Real AWS Data Mode: %v", useRealAWSData)
	log.Printf("   - Mock Data Disabled: %v", os.Getenv("DISABLE_MOCK_DATA") == "true")

	// Start S3 CloudTrail Indexer (for centralized logs from multiple accounts)
	if useS3CloudTrailMode {
		log.Println("📦 Starting S3 CloudTrail Indexer for centralized logs...")
		bucketName := os.Getenv("CLOUDTRAIL_S3_BUCKET")
		prefix := os.Getenv("CLOUDTRAIL_S3_PREFIX")
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}
		InitS3CloudTrailIndexerGlobal(bucketName, prefix, region)
		server.StartS3CloudTrailIndexer(5) // 5 minute interval
		AddSystemLog("INFO", "indexer", "S3 CloudTrail Indexer started", map[string]interface{}{
			"bucket":           bucketName,
			"interval_minutes": 5,
		})
	}

	// Start GuardDuty Indexer (if real AWS data is enabled)
	if useRealAWSData {
		log.Println("🔍 Starting GuardDuty Indexer...")
		server.StartGuardDutyIndexer(5) // 5 minute interval
		AddSystemLog("INFO", "indexer", "GuardDuty Indexer started", map[string]interface{}{
			"interval_minutes": 5,
		})

		// Start AWS Inspector Indexer for Vulnerability Management
		log.Println("🛡️ Starting AWS Inspector Indexer...")
		server.StartInspectorIndexer(15) // 15 minute interval (Inspector findings change less frequently)
		AddSystemLog("INFO", "indexer", "AWS Inspector Indexer started", map[string]interface{}{
			"interval_minutes": 15,
		})

		// Start Security Hub Vulnerability Indexer (uses existing Security Hub integration)
		log.Println("🔐 Starting Security Hub Vulnerability Indexer...")
		server.StartSecurityHubVulnerabilityIndexer(10) // 10 minute interval
		AddSystemLog("INFO", "indexer", "Security Hub Vulnerability Indexer started", map[string]interface{}{
			"interval_minutes": 10,
		})

		// Start VPC Flow Logs Indexer for Network Analysis
		vpcFlowLogsBucket := os.Getenv("VPC_FLOWLOGS_S3_BUCKET")
		if vpcFlowLogsBucket != "" {
			log.Println("🌐 Starting VPC Flow Logs Indexer...")
			server.StartVPCFlowLogsIndexer(5) // 5 minute interval
			AddSystemLog("INFO", "indexer", "VPC Flow Logs Indexer started", map[string]interface{}{
				"interval_minutes": 5,
				"bucket":           vpcFlowLogsBucket,
			})
		}
	}

	// Start Security Hub Indexer (for centralized CSPM)
	if useSecurityHubMode {
		log.Println("🛡️ Starting Security Hub Indexer for centralized CSPM...")
		shRegion := os.Getenv("AWS_REGION")
		if shRegion == "" {
			shRegion = "us-east-1"
		}
		InitSecurityHubIndexerGlobal(shRegion)
		server.StartSecurityHubIndexer(5) // 5 minute interval
		AddSystemLog("INFO", "indexer", "Security Hub Indexer started", map[string]interface{}{
			"interval_minutes": 5,
			"region":           shRegion,
		})

		// Start Alerts Indexer
		log.Println("🔔 Starting Alerts Indexer...")
		server.StartAlertsIndexer()
		AddSystemLog("INFO", "indexer", "Alerts Indexer started", map[string]interface{}{
			"interval_minutes": 5,
		})
	}

	// ==========================================================================
	// START AI/ML ANALYZERS
	// ==========================================================================

	// Start UEBA (User & Entity Behavior Analytics) Analyzer
	server.StartUEBAAnalyzer()
	AddSystemLog("INFO", "ueba", "UEBA Analyzer started", map[string]interface{}{
		"interval_minutes": 5,
		"features":         []string{"user_profiling", "anomaly_detection", "risk_scoring"},
	})

	// Start ML Analytics Analyzer
	server.StartMLAnalyzer()
	AddSystemLog("INFO", "ml_analytics", "ML Analytics Analyzer started", map[string]interface{}{
		"interval_minutes": 10,
		"features":         []string{"volume_anomaly", "severity_anomaly", "threat_prediction"},
	})

	// If no real data sources, start mock event indexer
	if !useS3CloudTrailMode && !useRealAWSData {
		log.Println("⚠️ No real AWS data sources configured, AWS Event Indexer not started")
		AddSystemLog("WARN", "indexer", "No real AWS data sources configured", nil)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Erro ao executar servidor API: %v", err)
	}
}
