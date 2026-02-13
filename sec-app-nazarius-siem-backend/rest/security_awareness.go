package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// PhishingCampaign represents a phishing simulation campaign
type PhishingCampaign struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Status          string    `json:"status"` // draft, active, completed, paused
	TemplateID      string    `json:"template_id"`
	TargetGroups    []string  `json:"target_groups"`
	TotalTargets    int       `json:"total_targets"`
	EmailsSent      int       `json:"emails_sent"`
	EmailsOpened    int       `json:"emails_opened"`
	LinksClicked    int       `json:"links_clicked"`
	DataSubmitted   int       `json:"data_submitted"`
	Reported        int       `json:"reported"`
	ClickRate       float64   `json:"click_rate"`
	ReportRate      float64   `json:"report_rate"`
	StartDate       time.Time `json:"start_date"`
	EndDate         time.Time `json:"end_date"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
}

// PhishingTemplate represents an email template for phishing simulations
type PhishingTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"` // credential_harvest, malware, social_engineering
	Difficulty  string   `json:"difficulty"` // easy, medium, hard
	Subject     string   `json:"subject"`
	FromName    string   `json:"from_name"`
	FromEmail   string   `json:"from_email"`
	Body        string   `json:"body"`
	LandingPage string   `json:"landing_page"`
	Language    string   `json:"language"`
	Tags        []string `json:"tags"`
	CreatedAt   time.Time `json:"created_at"`
}

// TrainingModule represents a security awareness training module
type TrainingModule struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Category        string    `json:"category"` // phishing, passwords, social_engineering, malware, data_protection
	Duration        int       `json:"duration"` // minutes
	Difficulty      string    `json:"difficulty"`
	ContentURL      string    `json:"content_url"`
	QuizQuestions   int       `json:"quiz_questions"`
	PassingScore    int       `json:"passing_score"`
	Enrolled        int       `json:"enrolled"`
	Completed       int       `json:"completed"`
	AverageScore    float64   `json:"average_score"`
	CompletionRate  float64   `json:"completion_rate"`
	Mandatory       bool      `json:"mandatory"`
	CreatedAt       time.Time `json:"created_at"`
}

// UserRiskProfile represents a user's security risk profile
type UserRiskProfile struct {
	UserID              string    `json:"user_id"`
	Username            string    `json:"username"`
	Email               string    `json:"email"`
	Department          string    `json:"department"`
	RiskScore           int       `json:"risk_score"` // 0-100 (higher = more risky)
	RiskLevel           string    `json:"risk_level"` // low, medium, high, critical
	PhishingTests       int       `json:"phishing_tests"`
	PhishingFailed      int       `json:"phishing_failed"`
	PhishingReported    int       `json:"phishing_reported"`
	TrainingsAssigned   int       `json:"trainings_assigned"`
	TrainingsCompleted  int       `json:"trainings_completed"`
	AverageTrainingScore float64  `json:"average_training_score"`
	LastIncident        *time.Time `json:"last_incident,omitempty"`
	LastTraining        *time.Time `json:"last_training,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// AwarenessMetrics represents overall security awareness metrics
type AwarenessMetrics struct {
	TotalUsers              int     `json:"total_users"`
	ActiveCampaigns         int     `json:"active_campaigns"`
	TotalCampaigns          int     `json:"total_campaigns"`
	AvgClickRate            float64 `json:"avg_click_rate"`
	AvgReportRate           float64 `json:"avg_report_rate"`
	TotalTrainings          int     `json:"total_trainings"`
	ActiveTrainings         int     `json:"active_trainings"`
	TrainingCompletionRate  float64 `json:"training_completion_rate"`
	AvgTrainingScore        float64 `json:"avg_training_score"`
	HighRiskUsers           int     `json:"high_risk_users"`
	MediumRiskUsers         int     `json:"medium_risk_users"`
	LowRiskUsers            int     `json:"low_risk_users"`
	TrendImprovement        float64 `json:"trend_improvement"` // percentage
	LastCampaign            time.Time `json:"last_campaign"`
}

// GamificationLeaderboard represents gamification leaderboard entry
type GamificationLeaderboard struct {
	Rank            int       `json:"rank"`
	UserID          string    `json:"user_id"`
	Username        string    `json:"username"`
	Department      string    `json:"department"`
	Points          int       `json:"points"`
	Badges          []string  `json:"badges"`
	Level           int       `json:"level"`
	TrainingsCompleted int    `json:"trainings_completed"`
	PhishingReported   int    `json:"phishing_reported"`
	Streak          int       `json:"streak"` // consecutive days
	LastActivity    time.Time `json:"last_activity"`
}

// Initialize security awareness data
func initSecurityAwareness() {
	// Mock data will be generated on-the-fly
}

// Handler: List phishing campaigns
func (s *APIServer) handleListPhishingCampaigns(c *gin.Context) {
	campaigns := []PhishingCampaign{
		{
			ID:            "camp-001",
			Name:          "Q4 2025 Phishing Test",
			Description:   "Quarterly phishing awareness test for all employees",
			Status:        "active",
			TemplateID:    "tpl-001",
			TargetGroups:  []string{"Engineering", "Sales", "Marketing"},
			TotalTargets:  250,
			EmailsSent:    250,
			EmailsOpened:  180,
			LinksClicked:  45,
			DataSubmitted: 12,
			Reported:      38,
			ClickRate:     18.0,
			ReportRate:    15.2,
			StartDate:     time.Now().Add(-7 * 24 * time.Hour),
			EndDate:       time.Now().Add(7 * 24 * time.Hour),
			CreatedBy:     "security-team",
			CreatedAt:     time.Now().Add(-10 * 24 * time.Hour),
		},
		{
			ID:            "camp-002",
			Name:          "Executive Spear Phishing",
			Description:   "Targeted phishing test for executives",
			Status:        "completed",
			TemplateID:    "tpl-003",
			TargetGroups:  []string{"Executive"},
			TotalTargets:  25,
			EmailsSent:    25,
			EmailsOpened:  22,
			LinksClicked:  3,
			DataSubmitted: 1,
			Reported:      18,
			ClickRate:     12.0,
			ReportRate:    72.0,
			StartDate:     time.Now().Add(-30 * 24 * time.Hour),
			EndDate:       time.Now().Add(-23 * 24 * time.Hour),
			CreatedBy:     "security-team",
			CreatedAt:     time.Now().Add(-35 * 24 * time.Hour),
		},
		{
			ID:            "camp-003",
			Name:          "Holiday Season Scam Test",
			Description:   "Testing awareness of holiday-themed scams",
			Status:        "draft",
			TemplateID:    "tpl-005",
			TargetGroups:  []string{"All Employees"},
			TotalTargets:  500,
			EmailsSent:    0,
			EmailsOpened:  0,
			LinksClicked:  0,
			DataSubmitted: 0,
			Reported:      0,
			ClickRate:     0.0,
			ReportRate:    0.0,
			StartDate:     time.Now().Add(14 * 24 * time.Hour),
			EndDate:       time.Now().Add(21 * 24 * time.Hour),
			CreatedBy:     "security-team",
			CreatedAt:     time.Now().Add(-2 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    campaigns,
	})
}

// Handler: Create phishing campaign
func (s *APIServer) handleCreatePhishingCampaign(c *gin.Context) {
	var campaign PhishingCampaign
	if err := c.ShouldBindJSON(&campaign); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	campaign.ID = "camp-" + time.Now().Format("20060102150405")
	campaign.CreatedAt = time.Now()
	campaign.Status = "draft"

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    campaign,
	})
}

// Handler: List phishing templates
func (s *APIServer) handleListPhishingTemplates(c *gin.Context) {
	templates := []PhishingTemplate{
		{
			ID:          "tpl-001",
			Name:        "Password Reset Request",
			Category:    "credential_harvest",
			Difficulty:  "medium",
			Subject:     "Urgent: Reset Your Password",
			FromName:    "IT Support",
			FromEmail:   "support@company-it.com",
			Body:        "Your password will expire in 24 hours. Click here to reset.",
			LandingPage: "https://phishing-sim.local/reset",
			Language:    "en",
			Tags:        []string{"password", "urgent", "it"},
			CreatedAt:   time.Now().Add(-60 * 24 * time.Hour),
		},
		{
			ID:          "tpl-002",
			Name:        "Invoice Payment Required",
			Category:    "malware",
			Difficulty:  "hard",
			Subject:     "Invoice #12345 - Payment Overdue",
			FromName:    "Accounts Payable",
			FromEmail:   "billing@vendor-company.com",
			Body:        "Please review the attached invoice and process payment.",
			LandingPage: "https://phishing-sim.local/invoice",
			Language:    "en",
			Tags:        []string{"invoice", "payment", "attachment"},
			CreatedAt:   time.Now().Add(-45 * 24 * time.Hour),
		},
		{
			ID:          "tpl-003",
			Name:        "CEO Urgent Request",
			Category:    "social_engineering",
			Difficulty:  "hard",
			Subject:     "URGENT: Need Your Help",
			FromName:    "CEO",
			FromEmail:   "ceo@company.com",
			Body:        "I'm in a meeting and need you to process this wire transfer immediately.",
			LandingPage: "https://phishing-sim.local/transfer",
			Language:    "en",
			Tags:        []string{"ceo", "urgent", "wire_transfer"},
			CreatedAt:   time.Now().Add(-30 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    templates,
	})
}

// Handler: List training modules
func (s *APIServer) handleListTrainingModules(c *gin.Context) {
	modules := []TrainingModule{
		{
			ID:              "train-001",
			Title:           "Phishing Awareness 101",
			Description:     "Learn to identify and report phishing emails",
			Category:        "phishing",
			Duration:        30,
			Difficulty:      "beginner",
			ContentURL:      "/training/phishing-101",
			QuizQuestions:   10,
			PassingScore:    80,
			Enrolled:        450,
			Completed:       380,
			AverageScore:    87.5,
			CompletionRate:  84.4,
			Mandatory:       true,
			CreatedAt:       time.Now().Add(-90 * 24 * time.Hour),
		},
		{
			ID:              "train-002",
			Title:           "Password Security Best Practices",
			Description:     "Creating and managing strong passwords",
			Category:        "passwords",
			Duration:        20,
			Difficulty:      "beginner",
			ContentURL:      "/training/passwords",
			QuizQuestions:   8,
			PassingScore:    75,
			Enrolled:        450,
			Completed:       420,
			AverageScore:    91.2,
			CompletionRate:  93.3,
			Mandatory:       true,
			CreatedAt:       time.Now().Add(-85 * 24 * time.Hour),
		},
		{
			ID:              "train-003",
			Title:           "Social Engineering Tactics",
			Description:     "Understanding and defending against social engineering",
			Category:        "social_engineering",
			Duration:        45,
			Difficulty:      "intermediate",
			ContentURL:      "/training/social-engineering",
			QuizQuestions:   15,
			PassingScore:    80,
			Enrolled:        200,
			Completed:       145,
			AverageScore:    82.8,
			CompletionRate:  72.5,
			Mandatory:       false,
			CreatedAt:       time.Now().Add(-60 * 24 * time.Hour),
		},
		{
			ID:              "train-004",
			Title:           "Data Protection & Privacy",
			Description:     "Handling sensitive data and GDPR compliance",
			Category:        "data_protection",
			Duration:        40,
			Difficulty:      "intermediate",
			ContentURL:      "/training/data-protection",
			QuizQuestions:   12,
			PassingScore:    85,
			Enrolled:        300,
			Completed:       250,
			AverageScore:    88.9,
			CompletionRate:  83.3,
			Mandatory:       true,
			CreatedAt:       time.Now().Add(-70 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    modules,
	})
}

// Handler: List user risk profiles
func (s *APIServer) handleListUserRiskProfiles(c *gin.Context) {
	lastIncident := time.Now().Add(-15 * 24 * time.Hour)
	lastTraining := time.Now().Add(-5 * 24 * time.Hour)

	profiles := []UserRiskProfile{
		{
			UserID:               "user-001",
			Username:             "john.doe",
			Email:                "john.doe@company.com",
			Department:           "Engineering",
			RiskScore:            75,
			RiskLevel:            "high",
			PhishingTests:        5,
			PhishingFailed:       3,
			PhishingReported:     1,
			TrainingsAssigned:    4,
			TrainingsCompleted:   2,
			AverageTrainingScore: 72.5,
			LastIncident:         &lastIncident,
			LastTraining:         &lastTraining,
			UpdatedAt:            time.Now(),
		},
		{
			UserID:               "user-002",
			Username:             "jane.smith",
			Email:                "jane.smith@company.com",
			Department:           "Sales",
			RiskScore:            25,
			RiskLevel:            "low",
			PhishingTests:        5,
			PhishingFailed:       0,
			PhishingReported:     5,
			TrainingsAssigned:    4,
			TrainingsCompleted:   4,
			AverageTrainingScore: 95.8,
			LastTraining:         &lastTraining,
			UpdatedAt:            time.Now(),
		},
		{
			UserID:               "user-003",
			Username:             "bob.wilson",
			Email:                "bob.wilson@company.com",
			Department:           "Marketing",
			RiskScore:            50,
			RiskLevel:            "medium",
			PhishingTests:        5,
			PhishingFailed:       2,
			PhishingReported:     2,
			TrainingsAssigned:    4,
			TrainingsCompleted:   3,
			AverageTrainingScore: 81.2,
			LastIncident:         &lastIncident,
			LastTraining:         &lastTraining,
			UpdatedAt:            time.Now(),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    profiles,
	})
}

// Handler: Get awareness metrics
func (s *APIServer) handleGetAwarenessMetrics(c *gin.Context) {
	metrics := AwarenessMetrics{
		TotalUsers:             450,
		ActiveCampaigns:        1,
		TotalCampaigns:         3,
		AvgClickRate:           15.0,
		AvgReportRate:          43.6,
		TotalTrainings:         4,
		ActiveTrainings:        4,
		TrainingCompletionRate: 85.7,
		AvgTrainingScore:       87.6,
		HighRiskUsers:          45,
		MediumRiskUsers:        125,
		LowRiskUsers:           280,
		TrendImprovement:       12.5,
		LastCampaign:           time.Now().Add(-7 * 24 * time.Hour),
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    metrics,
	})
}

// Handler: Get gamification leaderboard
func (s *APIServer) handleGetGamificationLeaderboard(c *gin.Context) {
	leaderboard := []GamificationLeaderboard{
		{
			Rank:               1,
			UserID:             "user-002",
			Username:           "jane.smith",
			Department:         "Sales",
			Points:             2850,
			Badges:             []string{"Phishing Hunter", "Training Champion", "Perfect Score"},
			Level:              12,
			TrainingsCompleted: 8,
			PhishingReported:   15,
			Streak:             45,
			LastActivity:       time.Now().Add(-2 * time.Hour),
		},
		{
			Rank:               2,
			UserID:             "user-005",
			Username:           "alice.johnson",
			Department:         "Engineering",
			Points:             2620,
			Badges:             []string{"Phishing Hunter", "Training Champion"},
			Level:              11,
			TrainingsCompleted: 7,
			PhishingReported:   12,
			Streak:             38,
			LastActivity:       time.Now().Add(-5 * time.Hour),
		},
		{
			Rank:               3,
			UserID:             "user-008",
			Username:           "mike.brown",
			Department:         "Marketing",
			Points:             2450,
			Badges:             []string{"Phishing Hunter", "Quick Learner"},
			Level:              10,
			TrainingsCompleted: 6,
			PhishingReported:   10,
			Streak:             30,
			LastActivity:       time.Now().Add(-1 * 24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    leaderboard,
	})
}

