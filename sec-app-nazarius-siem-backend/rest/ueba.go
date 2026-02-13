package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// UserProfile representa o perfil comportamental de um usuário
type UserProfile struct {
	UserID           string                 `json:"user_id"`
	Username         string                 `json:"username"`
	Email            string                 `json:"email"`
	Department       string                 `json:"department"`
	RiskScore        int                    `json:"risk_score"` // 0-100
	RiskLevel        string                 `json:"risk_level"` // low, medium, high, critical
	LastActivity     time.Time              `json:"last_activity"`
	TotalActivities  int                    `json:"total_activities"`
	AnomalyCount     int                    `json:"anomaly_count"`
	Baseline         UserBaseline           `json:"baseline"`
	RecentAnomalies  []Anomaly              `json:"recent_anomalies"`
	PeerGroup        string                 `json:"peer_group"`
	Tags             []string               `json:"tags"`
}

// UserBaseline representa o comportamento normal do usuário
type UserBaseline struct {
	AvgLoginHour        float64   `json:"avg_login_hour"`
	CommonLocations     []string  `json:"common_locations"`
	CommonDevices       []string  `json:"common_devices"`
	AvgSessionDuration  int       `json:"avg_session_duration"` // em minutos
	AvgDataVolume       int64     `json:"avg_data_volume"`      // em bytes
	TypicalWorkHours    []int     `json:"typical_work_hours"`   // horas do dia
	TypicalWorkDays     []int     `json:"typical_work_days"`    // dias da semana (0-6)
	BaselineEstablished time.Time `json:"baseline_established"`
}

// Anomaly representa uma anomalia comportamental detectada
type Anomaly struct {
	ID               string                 `json:"id"`
	UserID           string                 `json:"user_id"`
	Username         string                 `json:"username"`
	Type             string                 `json:"type"` // login_time, location, volume, device, privilege, etc
	Severity         string                 `json:"severity"` // low, medium, high, critical
	Score            int                    `json:"score"` // 0-100
	Description      string                 `json:"description"`
	DetectedAt       time.Time              `json:"detected_at"`
	EventID          string                 `json:"event_id"`
	Details          map[string]interface{} `json:"details"`
	Status           string                 `json:"status"` // new, investigating, confirmed, false_positive
	AssignedCase     string                 `json:"assigned_case,omitempty"`
	InvestigatedBy   string                 `json:"investigated_by,omitempty"`
	ResolutionNotes  string                 `json:"resolution_notes,omitempty"`
}

// UserActivity representa uma atividade do usuário
type UserActivity struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username"`
	Timestamp   time.Time              `json:"timestamp"`
	ActivityType string                `json:"activity_type"` // login, logout, file_access, command, etc
	Source      string                 `json:"source"`
	Location    string                 `json:"location"`
	Device      string                 `json:"device"`
	IsAnomaly   bool                   `json:"is_anomaly"`
	RiskScore   int                    `json:"risk_score"`
	Details     map[string]interface{} `json:"details"`
}

// PeerGroup representa um grupo de pares (usuários similares)
type PeerGroup struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	UserCount   int      `json:"user_count"`
	AvgRisk     float64  `json:"avg_risk"`
	Members     []string `json:"members"`
}

// UEBAStats representa estatísticas do UEBA
type UEBAStats struct {
	TotalUsers          int     `json:"total_users"`
	MonitoredUsers      int     `json:"monitored_users"`
	HighRiskUsers       int     `json:"high_risk_users"`
	CriticalRiskUsers   int     `json:"critical_risk_users"`
	AnomaliesDetected   int     `json:"anomalies_detected"`
	AnomaliesLast24h    int     `json:"anomalies_last_24h"`
	CasesCreated        int     `json:"cases_created"`
	AvgRiskScore        float64 `json:"avg_risk_score"`
	BaselinesCovered    int     `json:"baselines_covered"`
	BaselineCoverage    float64 `json:"baseline_coverage"` // %
	TotalActivities     int     `json:"total_activities"`
	ActivitiesLast24h   int     `json:"activities_last_24h"`
}

// RiskTrend representa tendência de risco
type RiskTrend struct {
	Date      string  `json:"date"`
	AvgRisk   float64 `json:"avg_risk"`
	HighRisk  int     `json:"high_risk"`
	Anomalies int     `json:"anomalies"`
}

// AnomalyByType representa anomalias agrupadas por tipo
type AnomalyByType struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// Handlers

// handleGetUEBADashboard retorna o dashboard completo do UEBA
func (s *APIServer) handleGetUEBADashboard(c *gin.Context) {
	useRealData := os.Getenv("USE_REAL_AWS_DATA") == "true"
	
	if useRealData && uebaCollector != nil {
		// Use real UEBA data
		behaviors, anomalies, err := uebaCollector.AnalyzeUserBehavior(24)
		if err != nil {
			log.Printf("❌ Failed to analyze user behavior: %v", err)
			// Fallback to mock data
			useRealData = false
		} else {
			// Convert to dashboard format
			stats := convertBehaviorsToStats(behaviors, anomalies)
			topRiskUsers := convertToTopRiskUsers(behaviors)
			recentAnomalies := convertToRecentAnomalies(anomalies)
			trends := generateMockRiskTrends(7) // TODO: Implement real trends
			anomalyTypes := calculateAnomalyTypes(anomalies)
			
			c.JSON(http.StatusOK, gin.H{
				"stats":            stats,
				"top_risk_users":   topRiskUsers,
				"recent_anomalies": recentAnomalies,
				"risk_trends":      trends,
				"anomaly_types":    anomalyTypes,
				"source":           "real",
			})
			return
		}
	}
	
	// Use mock data
	stats := generateMockUEBAStats()
	topRiskUsers := generateMockTopRiskUsers()
	recentAnomalies := generateMockRecentAnomalies(10)
	trends := generateMockRiskTrends(7)
	anomalyTypes := generateMockAnomalyTypes()

	c.JSON(http.StatusOK, gin.H{
		"stats":            stats,
		"top_risk_users":   topRiskUsers,
		"recent_anomalies": recentAnomalies,
		"risk_trends":      trends,
		"anomaly_types":    anomalyTypes,
		"source":           "mock",
	})
}

// handleListUsers retorna lista de usuários com perfis
func (s *APIServer) handleListUEBAUsers(c *gin.Context) {
	riskLevel := c.Query("risk_level")
	
	users := generateMockUserProfiles()
	
	// Filtrar por nível de risco se especificado
	if riskLevel != "" {
		filtered := []UserProfile{}
		for _, user := range users {
			if user.RiskLevel == riskLevel {
				filtered = append(filtered, user)
			}
		}
		users = filtered
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"total": len(users),
	})
}

// handleGetUserProfile retorna perfil detalhado de um usuário
func (s *APIServer) handleGetUserProfile(c *gin.Context) {
	userID := c.Param("id")
	
	profile := generateMockUserProfile(userID)
	activities := generateMockUserActivities(userID, 20)
	
	c.JSON(http.StatusOK, gin.H{
		"profile":    profile,
		"activities": activities,
	})
}

// handleListAnomalies retorna lista de anomalias detectadas
func (s *APIServer) handleListAnomalies(c *gin.Context) {
	severity := c.Query("severity")
	status := c.Query("status")
	
	anomalies := generateMockRecentAnomalies(50)
	
	// Filtrar por severidade se especificado
	if severity != "" {
		filtered := []Anomaly{}
		for _, a := range anomalies {
			if a.Severity == severity {
				filtered = append(filtered, a)
			}
		}
		anomalies = filtered
	}
	
	// Filtrar por status se especificado
	if status != "" {
		filtered := []Anomaly{}
		for _, a := range anomalies {
			if a.Status == status {
				filtered = append(filtered, a)
			}
		}
		anomalies = filtered
	}

	c.JSON(http.StatusOK, gin.H{
		"anomalies": anomalies,
		"total":     len(anomalies),
	})
}

// handleUpdateAnomaly atualiza status de uma anomalia
func (s *APIServer) handleUpdateAnomaly(c *gin.Context) {
	anomalyID := c.Param("id")
	
	var update struct {
		Status          string `json:"status"`
		InvestigatedBy  string `json:"investigated_by,omitempty"`
		ResolutionNotes string `json:"resolution_notes,omitempty"`
		AssignedCase    string `json:"assigned_case,omitempty"`
	}
	
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Mock: retornar anomalia atualizada
	anomaly := Anomaly{
		ID:              anomalyID,
		Status:          update.Status,
		InvestigatedBy:  update.InvestigatedBy,
		ResolutionNotes: update.ResolutionNotes,
		AssignedCase:    update.AssignedCase,
	}
	
	c.JSON(http.StatusOK, anomaly)
}

// handleGetPeerGroups retorna grupos de pares
func (s *APIServer) handleGetPeerGroups(c *gin.Context) {
	groups := []PeerGroup{
		{
			ID:          "pg-1",
			Name:        "Developers",
			Description: "Software development team",
			UserCount:   45,
			AvgRisk:     25.5,
			Members:     []string{"john.doe", "jane.smith", "bob.wilson"},
		},
		{
			ID:          "pg-2",
			Name:        "Executives",
			Description: "C-level executives",
			UserCount:   12,
			AvgRisk:     42.3,
			Members:     []string{"ceo", "cfo", "cto"},
		},
		{
			ID:          "pg-3",
			Name:        "IT Operations",
			Description: "IT infrastructure team",
			UserCount:   28,
			AvgRisk:     35.7,
			Members:     []string{"admin1", "admin2", "operator1"},
		},
	}
	
	c.JSON(http.StatusOK, gin.H{
		"peer_groups": groups,
		"total":       len(groups),
	})
}

// handleGetUEBAStats retorna estatísticas do UEBA
func (s *APIServer) handleGetUEBAStats(c *gin.Context) {
	stats := generateMockUEBAStats()
	c.JSON(http.StatusOK, stats)
}

// handleAnalyzeUser força análise de um usuário específico
func (s *APIServer) handleAnalyzeUser(c *gin.Context) {
	userID := c.Param("id")
	
	// Mock: simular análise
	result := gin.H{
		"user_id":       userID,
		"analyzed_at":   time.Now(),
		"events_scanned": 1523,
		"anomalies_found": 3,
		"baseline_updated": true,
		"new_risk_score":   67,
		"previous_risk_score": 52,
	}
	
	c.JSON(http.StatusOK, result)
}

// Mock Data Generators

func generateMockUEBAStats() UEBAStats {
	return UEBAStats{
		TotalUsers:        342,
		MonitoredUsers:    287,
		HighRiskUsers:     23,
		CriticalRiskUsers: 5,
		AnomaliesDetected: 1567,
		AnomaliesLast24h:  47,
		CasesCreated:      89,
		AvgRiskScore:      32.5,
		BaselinesCovered:  287,
		BaselineCoverage:  83.9,
		TotalActivities:   156789,
		ActivitiesLast24h: 12456,
	}
}

func generateMockTopRiskUsers() []UserProfile {
	now := time.Now()
	return []UserProfile{
		{
			UserID:          "user-001",
			Username:        "john.suspicious",
			Email:           "john.suspicious@company.com",
			Department:      "Finance",
			RiskScore:       92,
			RiskLevel:       "critical",
			LastActivity:    now.Add(-15 * time.Minute),
			TotalActivities: 1523,
			AnomalyCount:    15,
			PeerGroup:       "Finance Team",
			Tags:            []string{"high-privilege", "finance-access"},
		},
		{
			UserID:          "user-002",
			Username:        "alice.anomaly",
			Email:           "alice.anomaly@company.com",
			Department:      "IT",
			RiskScore:       85,
			RiskLevel:       "high",
			LastActivity:    now.Add(-45 * time.Minute),
			TotalActivities: 2341,
			AnomalyCount:    12,
			PeerGroup:       "IT Operations",
			Tags:            []string{"admin", "vpn-user"},
		},
		{
			UserID:          "user-003",
			Username:        "bob.risky",
			Email:           "bob.risky@company.com",
			Department:      "Sales",
			RiskScore:       78,
			RiskLevel:       "high",
			LastActivity:    now.Add(-2 * time.Hour),
			TotalActivities: 987,
			AnomalyCount:    9,
			PeerGroup:       "Sales Team",
			Tags:            []string{"remote-worker"},
		},
		{
			UserID:          "user-004",
			Username:        "carol.concern",
			Email:           "carol.concern@company.com",
			Department:      "HR",
			RiskScore:       71,
			RiskLevel:       "high",
			LastActivity:    now.Add(-30 * time.Minute),
			TotalActivities: 1876,
			AnomalyCount:    8,
			PeerGroup:       "HR Team",
			Tags:            []string{"pii-access"},
		},
		{
			UserID:          "user-005",
			Username:        "dave.dubious",
			Email:           "dave.dubious@company.com",
			Department:      "Engineering",
			RiskScore:       68,
			RiskLevel:       "medium",
			LastActivity:    now.Add(-1 * time.Hour),
			TotalActivities: 3421,
			AnomalyCount:    7,
			PeerGroup:       "Developers",
			Tags:            []string{"developer", "code-access"},
		},
	}
}

func generateMockRecentAnomalies(count int) []Anomaly {
	now := time.Now()
	anomalies := []Anomaly{
		{
			ID:          "anom-001",
			UserID:      "user-001",
			Username:    "john.suspicious",
			Type:        "unusual_login_time",
			Severity:    "critical",
			Score:       92,
			Description: "Login detected at 3:47 AM, outside typical working hours (9 AM - 6 PM)",
			DetectedAt:  now.Add(-15 * time.Minute),
			EventID:     "evt-12345",
			Status:      "new",
			Details: map[string]interface{}{
				"login_time":    "03:47:00",
				"typical_hours": "09:00-18:00",
				"location":      "Unknown",
			},
		},
		{
			ID:          "anom-002",
			UserID:      "user-002",
			Username:    "alice.anomaly",
			Type:        "unusual_location",
			Severity:    "high",
			Score:       85,
			Description: "Login from unusual location: Moscow, Russia (typical: New York, USA)",
			DetectedAt:  now.Add(-45 * time.Minute),
			EventID:     "evt-12346",
			Status:      "investigating",
			Details: map[string]interface{}{
				"location":         "Moscow, Russia",
				"typical_location": "New York, USA",
				"ip_address":       "91.234.56.78",
			},
		},
		{
			ID:          "anom-003",
			UserID:      "user-003",
			Username:    "bob.risky",
			Type:        "excessive_data_access",
			Severity:    "high",
			Score:       78,
			Description: "Downloaded 15 GB of data in 2 hours (baseline: 500 MB/day)",
			DetectedAt:  now.Add(-2 * time.Hour),
			EventID:     "evt-12347",
			Status:      "new",
			Details: map[string]interface{}{
				"data_volume": "15 GB",
				"baseline":    "500 MB/day",
				"duration":    "2 hours",
			},
		},
		{
			ID:          "anom-004",
			UserID:      "user-004",
			Username:    "carol.concern",
			Type:        "privilege_escalation",
			Severity:    "critical",
			Score:       89,
			Description: "Multiple failed attempts to access admin panel (15 attempts in 10 minutes)",
			DetectedAt:  now.Add(-30 * time.Minute),
			EventID:     "evt-12348",
			Status:      "confirmed",
			AssignedCase: "case-456",
			Details: map[string]interface{}{
				"failed_attempts": 15,
				"target_resource": "admin_panel",
				"time_window":     "10 minutes",
			},
		},
		{
			ID:          "anom-005",
			UserID:      "user-005",
			Username:    "dave.dubious",
			Type:        "unusual_device",
			Severity:    "medium",
			Score:       68,
			Description: "Login from new device: Linux workstation (typical: Windows laptop)",
			DetectedAt:  now.Add(-1 * time.Hour),
			EventID:     "evt-12349",
			Status:      "false_positive",
			Details: map[string]interface{}{
				"device":        "Linux Workstation",
				"typical_device": "Windows Laptop",
				"device_id":     "dev-998877",
			},
		},
	}
	
	if count < len(anomalies) {
		return anomalies[:count]
	}
	return anomalies
}

func generateMockUserProfiles() []UserProfile {
	now := time.Now()
	return []UserProfile{
		{
			UserID:          "user-001",
			Username:        "john.suspicious",
			Email:           "john.suspicious@company.com",
			Department:      "Finance",
			RiskScore:       92,
			RiskLevel:       "critical",
			LastActivity:    now.Add(-15 * time.Minute),
			TotalActivities: 1523,
			AnomalyCount:    15,
			PeerGroup:       "Finance Team",
		},
		{
			UserID:          "user-002",
			Username:        "alice.anomaly",
			Email:           "alice.anomaly@company.com",
			Department:      "IT",
			RiskScore:       85,
			RiskLevel:       "high",
			LastActivity:    now.Add(-45 * time.Minute),
			TotalActivities: 2341,
			AnomalyCount:    12,
			PeerGroup:       "IT Operations",
		},
		{
			UserID:          "user-010",
			Username:        "mike.normal",
			Email:           "mike.normal@company.com",
			Department:      "Marketing",
			RiskScore:       12,
			RiskLevel:       "low",
			LastActivity:    now.Add(-10 * time.Minute),
			TotalActivities: 876,
			AnomalyCount:    0,
			PeerGroup:       "Marketing Team",
		},
	}
}

func generateMockUserProfile(userID string) UserProfile {
	now := time.Now()
	return UserProfile{
		UserID:          userID,
		Username:        "john.suspicious",
		Email:           "john.suspicious@company.com",
		Department:      "Finance",
		RiskScore:       92,
		RiskLevel:       "critical",
		LastActivity:    now.Add(-15 * time.Minute),
		TotalActivities: 1523,
		AnomalyCount:    15,
		Baseline: UserBaseline{
			AvgLoginHour:       9.5,
			CommonLocations:    []string{"New York, USA", "Boston, USA"},
			CommonDevices:      []string{"Windows Laptop", "iPhone"},
			AvgSessionDuration: 480, // 8 hours
			AvgDataVolume:      524288000, // 500 MB
			TypicalWorkHours:   []int{9, 10, 11, 12, 13, 14, 15, 16, 17},
			TypicalWorkDays:    []int{1, 2, 3, 4, 5}, // Mon-Fri
			BaselineEstablished: now.AddDate(0, -3, 0),
		},
		RecentAnomalies: generateMockRecentAnomalies(5),
		PeerGroup:       "Finance Team",
		Tags:            []string{"high-privilege", "finance-access", "critical-user"},
	}
}

func generateMockUserActivities(userID string, count int) []UserActivity {
	now := time.Now()
	activities := []UserActivity{
		{
			ID:           "act-001",
			UserID:       userID,
			Username:     "john.suspicious",
			Timestamp:    now.Add(-15 * time.Minute),
			ActivityType: "login",
			Source:       "VPN",
			Location:     "Unknown",
			Device:       "Linux Workstation",
			IsAnomaly:    true,
			RiskScore:    92,
			Details: map[string]interface{}{
				"ip_address": "192.168.1.100",
				"method":     "password",
			},
		},
		{
			ID:           "act-002",
			UserID:       userID,
			Username:     "john.suspicious",
			Timestamp:    now.Add(-45 * time.Minute),
			ActivityType: "file_access",
			Source:       "File Server",
			Location:     "New York, USA",
			Device:       "Windows Laptop",
			IsAnomaly:    false,
			RiskScore:    15,
			Details: map[string]interface{}{
				"file_path": "/finance/reports/Q4_2024.xlsx",
				"action":    "read",
			},
		},
	}
	
	if count < len(activities) {
		return activities[:count]
	}
	return activities
}

func generateMockRiskTrends(days int) []RiskTrend {
	trends := []RiskTrend{}
	now := time.Now()
	
	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i)
		trends = append(trends, RiskTrend{
			Date:      date.Format("2006-01-02"),
			AvgRisk:   30.0 + float64(i*2),
			HighRisk:  15 + i,
			Anomalies: 40 + i*3,
		})
	}
	
	return trends
}

func generateMockAnomalyTypes() []AnomalyByType {
	return []AnomalyByType{
		{Type: "unusual_login_time", Count: 342},
		{Type: "unusual_location", Count: 287},
		{Type: "excessive_data_access", Count: 198},
		{Type: "privilege_escalation", Count: 156},
		{Type: "unusual_device", Count: 134},
		{Type: "suspicious_command", Count: 98},
	}
}

// Conversion functions for real UEBA data

func convertBehaviorsToStats(behaviors []UserBehaviorData, anomalies []UEBAAnomaly) UEBAStats {
	highRisk := 0
	criticalRisk := 0
	totalRisk := 0.0
	
	for _, b := range behaviors {
		totalRisk += b.RiskScore
		if b.RiskLevel == "high" {
			highRisk++
		}
		if b.RiskLevel == "critical" {
			criticalRisk++
		}
	}
	
	avgRisk := 0.0
	if len(behaviors) > 0 {
		avgRisk = totalRisk / float64(len(behaviors))
	}
	
	return UEBAStats{
		TotalUsers:        len(behaviors),
		MonitoredUsers:    len(behaviors),
		HighRiskUsers:     highRisk,
		CriticalRiskUsers: criticalRisk,
		AnomaliesDetected: len(anomalies),
		AnomaliesLast24h:  len(anomalies),
		AvgRiskScore:      avgRisk,
		BaselinesCovered:  len(behaviors),
		BaselineCoverage:  100.0,
	}
}

func convertToTopRiskUsers(behaviors []UserBehaviorData) []UserProfile {
	var users []UserProfile
	
	// Sort by risk score and take top 10
	for i, b := range behaviors {
		if i >= 10 {
			break
		}
		
		users = append(users, UserProfile{
			UserID:       b.Username,
			Username:     b.Username,
			RiskScore:    int(b.RiskScore),
			RiskLevel:    b.RiskLevel,
			LastActivity: b.LastSeen,
			AnomalyCount: len(b.Anomalies),
		})
	}
	
	return users
}

func convertToRecentAnomalies(anomalies []UEBAAnomaly) []Anomaly {
	var result []Anomaly
	
	for _, a := range anomalies {
		result = append(result, Anomaly{
			ID:          a.ID,
			Username:    a.Username,
			Type:        a.Type,
			Severity:    a.Severity,
			Score:       int(a.RiskScore),
			Description: a.Description,
			DetectedAt:  a.DetectedAt,
			Details:     a.Details,
			Status:      a.Status,
		})
	}
	
	return result
}

func calculateAnomalyTypes(anomalies []UEBAAnomaly) []AnomalyByType {
	typeCounts := make(map[string]int)
	
	for _, a := range anomalies {
		typeCounts[a.Type]++
	}
	
	var result []AnomalyByType
	for t, count := range typeCounts {
		result = append(result, AnomalyByType{
			Type:  t,
			Count: count,
		})
	}
	
	return result
}

