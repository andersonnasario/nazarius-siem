package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Security Control represents a security control to be validated
type SecurityControl struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Category        string    `json:"category"` // detection, prevention, response
	Description     string    `json:"description"`
	MITRETechniques []string  `json:"mitre_techniques"`
	Status          string    `json:"status"` // active, inactive, testing
	LastValidated   time.Time `json:"last_validated"`
	ValidationScore int       `json:"validation_score"` // 0-100
	Enabled         bool      `json:"enabled"`
}

// ValidationTest represents a test to validate a control
type ValidationTest struct {
	ID              string    `json:"id"`
	ControlID       string    `json:"control_id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"` // automated, manual, purple_team
	Technique       string    `json:"technique"`
	Description     string    `json:"description"`
	Status          string    `json:"status"` // pending, running, passed, failed
	LastRun         time.Time `json:"last_run"`
	NextRun         time.Time `json:"next_run"`
	ExecutionTime   int       `json:"execution_time"` // seconds
	DetectionRate   float64   `json:"detection_rate"` // 0-100
	FalsePositives  int       `json:"false_positives"`
	TruePositives   int       `json:"true_positives"`
	Severity        string    `json:"severity"`
}

// MITRECoverageValidation represents MITRE ATT&CK coverage
type MITRECoverageValidation struct {
	TacticID       string   `json:"tactic_id"`
	TacticName     string   `json:"tactic_name"`
	TechniqueID    string   `json:"technique_id"`
	TechniqueName  string   `json:"technique_name"`
	Covered        bool     `json:"covered"`
	Controls       []string `json:"controls"`
	ValidationRate float64  `json:"validation_rate"` // 0-100
	LastTested     time.Time `json:"last_tested"`
}

// ValidationGap represents security gaps identified in validation
type ValidationGap struct {
	ID              string    `json:"id"`
	Category        string    `json:"category"` // coverage, detection, response
	Severity        string    `json:"severity"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	MITRETechniques []string  `json:"mitre_techniques"`
	Recommendation  string    `json:"recommendation"`
	Priority        string    `json:"priority"`
	Status          string    `json:"status"` // open, in_progress, resolved
	CreatedAt       time.Time `json:"created_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
}

// ValidationReport represents a validation report
type ValidationReport struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Period          string    `json:"period"`
	GeneratedAt     time.Time `json:"generated_at"`
	TotalControls   int       `json:"total_controls"`
	ValidatedControls int     `json:"validated_controls"`
	PassedTests     int       `json:"passed_tests"`
	FailedTests     int       `json:"failed_tests"`
	CoverageRate    float64   `json:"coverage_rate"`
	DetectionRate   float64   `json:"detection_rate"`
	Gaps            int       `json:"gaps"`
	Recommendations []string  `json:"recommendations"`
}

// ValidationMetrics represents overall validation metrics
type ValidationMetrics struct {
	TotalControls       int     `json:"total_controls"`
	ActiveControls      int     `json:"active_controls"`
	ValidatedControls   int     `json:"validated_controls"`
	TotalTests          int     `json:"total_tests"`
	PassedTests         int     `json:"passed_tests"`
	FailedTests         int     `json:"failed_tests"`
	PendingTests        int     `json:"pending_tests"`
	MITRECoverage       float64 `json:"mitre_coverage"`
	DetectionRate       float64 `json:"detection_rate"`
	ValidationScore     float64 `json:"validation_score"`
	OpenGaps            int     `json:"open_gaps"`
	CriticalGaps        int     `json:"critical_gaps"`
	LastValidation      time.Time `json:"last_validation"`
}

// Initialize continuous validation data
func initContinuousValidation() {
	// Mock data will be generated on-the-fly
}

// Handler: List security controls
func (s *APIServer) handleListSecurityControls(c *gin.Context) {
	controls := []SecurityControl{
		{
			ID:              "ctrl-001",
			Name:            "Brute Force Detection",
			Category:        "detection",
			Description:     "Detects multiple failed login attempts",
			MITRETechniques: []string{"T1110", "T1078"},
			Status:          "active",
			LastValidated:   time.Now().Add(-24 * time.Hour),
			ValidationScore: 95,
			Enabled:         true,
		},
		{
			ID:              "ctrl-002",
			Name:            "Malware Execution Prevention",
			Category:        "prevention",
			Description:     "Blocks execution of known malware",
			MITRETechniques: []string{"T1204", "T1059"},
			Status:          "active",
			LastValidated:   time.Now().Add(-12 * time.Hour),
			ValidationScore: 88,
			Enabled:         true,
		},
		{
			ID:              "ctrl-003",
			Name:            "Lateral Movement Detection",
			Category:        "detection",
			Description:     "Detects suspicious lateral movement",
			MITRETechniques: []string{"T1021", "T1570"},
			Status:          "active",
			LastValidated:   time.Now().Add(-48 * time.Hour),
			ValidationScore: 92,
			Enabled:         true,
		},
		{
			ID:              "ctrl-004",
			Name:            "Data Exfiltration Prevention",
			Category:        "prevention",
			Description:     "Prevents unauthorized data transfer",
			MITRETechniques: []string{"T1041", "T1048"},
			Status:          "testing",
			LastValidated:   time.Now().Add(-6 * time.Hour),
			ValidationScore: 78,
			Enabled:         false,
		},
		{
			ID:              "ctrl-005",
			Name:            "Automated Incident Response",
			Category:        "response",
			Description:     "Automatically responds to threats",
			MITRETechniques: []string{"T1486", "T1490"},
			Status:          "active",
			LastValidated:   time.Now().Add(-2 * time.Hour),
			ValidationScore: 85,
			Enabled:         true,
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    controls,
	})
}

// Handler: List validation tests
func (s *APIServer) handleListValidationTests(c *gin.Context) {
	tests := []ValidationTest{
		{
			ID:             "test-001",
			ControlID:      "ctrl-001",
			Name:           "Brute Force Attack Simulation",
			Type:           "automated",
			Technique:      "T1110",
			Description:    "Simulates brute force attack with 10 failed attempts",
			Status:         "passed",
			LastRun:        time.Now().Add(-24 * time.Hour),
			NextRun:        time.Now().Add(24 * time.Hour),
			ExecutionTime:  45,
			DetectionRate:  95.5,
			FalsePositives: 1,
			TruePositives:  19,
			Severity:       "high",
		},
		{
			ID:             "test-002",
			ControlID:      "ctrl-002",
			Name:           "Malware Execution Test",
			Type:           "purple_team",
			Technique:      "T1204",
			Description:    "Tests malware detection with EICAR samples",
			Status:         "passed",
			LastRun:        time.Now().Add(-12 * time.Hour),
			NextRun:        time.Now().Add(12 * time.Hour),
			ExecutionTime:  30,
			DetectionRate:  100.0,
			FalsePositives: 0,
			TruePositives:  25,
			Severity:       "critical",
		},
		{
			ID:             "test-003",
			ControlID:      "ctrl-003",
			Name:           "Lateral Movement Detection",
			Type:           "automated",
			Technique:      "T1021",
			Description:    "Simulates RDP lateral movement",
			Status:         "failed",
			LastRun:        time.Now().Add(-48 * time.Hour),
			NextRun:        time.Now().Add(1 * time.Hour),
			ExecutionTime:  60,
			DetectionRate:  65.0,
			FalsePositives: 5,
			TruePositives:  13,
			Severity:       "high",
		},
		{
			ID:             "test-004",
			ControlID:      "ctrl-004",
			Name:           "Data Exfiltration Test",
			Type:           "manual",
			Technique:      "T1041",
			Description:    "Tests DLP controls with sensitive data",
			Status:         "running",
			LastRun:        time.Now().Add(-1 * time.Hour),
			NextRun:        time.Now().Add(23 * time.Hour),
			ExecutionTime:  120,
			DetectionRate:  78.0,
			FalsePositives: 3,
			TruePositives:  15,
			Severity:       "medium",
		},
		{
			ID:             "test-005",
			ControlID:      "ctrl-005",
			Name:           "Ransomware Response Test",
			Type:           "purple_team",
			Technique:      "T1486",
			Description:    "Tests automated response to ransomware",
			Status:         "passed",
			LastRun:        time.Now().Add(-2 * time.Hour),
			NextRun:        time.Now().Add(22 * time.Hour),
			ExecutionTime:  90,
			DetectionRate:  92.0,
			FalsePositives: 2,
			TruePositives:  23,
			Severity:       "critical",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    tests,
	})
}

// Handler: Get MITRE ATT&CK coverage
func (s *APIServer) handleGetValidationCoverage(c *gin.Context) {
	coverage := []MITRECoverageValidation{
		{
			TacticID:       "TA0001",
			TacticName:     "Initial Access",
			TechniqueID:    "T1078",
			TechniqueName:  "Valid Accounts",
			Covered:        true,
			Controls:       []string{"ctrl-001", "ctrl-005"},
			ValidationRate: 95.0,
			LastTested:     time.Now().Add(-24 * time.Hour),
		},
		{
			TacticID:       "TA0002",
			TacticName:     "Execution",
			TechniqueID:    "T1204",
			TechniqueName:  "User Execution",
			Covered:        true,
			Controls:       []string{"ctrl-002"},
			ValidationRate: 100.0,
			LastTested:     time.Now().Add(-12 * time.Hour),
		},
		{
			TacticID:       "TA0008",
			TacticName:     "Lateral Movement",
			TechniqueID:    "T1021",
			TechniqueName:  "Remote Services",
			Covered:        true,
			Controls:       []string{"ctrl-003"},
			ValidationRate: 65.0,
			LastTested:     time.Now().Add(-48 * time.Hour),
		},
		{
			TacticID:       "TA0010",
			TacticName:     "Exfiltration",
			TechniqueID:    "T1041",
			TechniqueName:  "Exfiltration Over C2 Channel",
			Covered:        true,
			Controls:       []string{"ctrl-004"},
			ValidationRate: 78.0,
			LastTested:     time.Now().Add(-6 * time.Hour),
		},
		{
			TacticID:       "TA0040",
			TacticName:     "Impact",
			TechniqueID:    "T1486",
			TechniqueName:  "Data Encrypted for Impact",
			Covered:        true,
			Controls:       []string{"ctrl-005"},
			ValidationRate: 92.0,
			LastTested:     time.Now().Add(-2 * time.Hour),
		},
		{
			TacticID:       "TA0003",
			TacticName:     "Persistence",
			TechniqueID:    "T1053",
			TechniqueName:  "Scheduled Task/Job",
			Covered:        false,
			Controls:       []string{},
			ValidationRate: 0.0,
			LastTested:     time.Time{},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    coverage,
	})
}

// Handler: Get validation gaps
func (s *APIServer) handleGetValidationGaps(c *gin.Context) {
	gaps := []ValidationGap{
		{
			ID:              "gap-001",
			Category:        "coverage",
			Severity:        "high",
			Title:           "No Persistence Detection",
			Description:     "No controls in place to detect persistence mechanisms",
			MITRETechniques: []string{"T1053", "T1547"},
			Recommendation:  "Implement scheduled task monitoring and registry persistence detection",
			Priority:        "high",
			Status:          "open",
			CreatedAt:       time.Now().Add(-72 * time.Hour),
		},
		{
			ID:              "gap-002",
			Category:        "detection",
			Severity:        "medium",
			Title:           "Low Lateral Movement Detection Rate",
			Description:     "Lateral movement detection rate is only 65%",
			MITRETechniques: []string{"T1021"},
			Recommendation:  "Tune detection rules and reduce false positives",
			Priority:        "medium",
			Status:          "in_progress",
			CreatedAt:       time.Now().Add(-48 * time.Hour),
		},
		{
			ID:              "gap-003",
			Category:        "response",
			Severity:        "low",
			Title:           "Manual Response for Some Threats",
			Description:     "Some threat types still require manual response",
			MITRETechniques: []string{"T1566"},
			Recommendation:  "Implement automated response playbooks for phishing",
			Priority:        "low",
			Status:          "open",
			CreatedAt:       time.Now().Add(-24 * time.Hour),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    gaps,
	})
}

// Handler: Get validation reports
func (s *APIServer) handleGetValidationReports(c *gin.Context) {
	reports := []ValidationReport{
		{
			ID:                "report-001",
			Title:             "Weekly Validation Report",
			Period:            "2025-11-04 to 2025-11-10",
			GeneratedAt:       time.Now(),
			TotalControls:     5,
			ValidatedControls: 5,
			PassedTests:       4,
			FailedTests:       1,
			CoverageRate:      83.3,
			DetectionRate:     86.1,
			Gaps:              3,
			Recommendations: []string{
				"Implement persistence detection controls",
				"Tune lateral movement detection rules",
				"Add automated phishing response",
			},
		},
		{
			ID:                "report-002",
			Title:             "Monthly Validation Report",
			Period:            "October 2025",
			GeneratedAt:       time.Now().Add(-7 * 24 * time.Hour),
			TotalControls:     5,
			ValidatedControls: 4,
			PassedTests:       12,
			FailedTests:       3,
			CoverageRate:      80.0,
			DetectionRate:     82.5,
			Gaps:              5,
			Recommendations: []string{
				"Increase test frequency",
				"Expand MITRE coverage",
				"Reduce false positives",
			},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    reports,
	})
}

// Handler: Get validation metrics
func (s *APIServer) handleGetValidationMetrics(c *gin.Context) {
	metrics := ValidationMetrics{
		TotalControls:     5,
		ActiveControls:    4,
		ValidatedControls: 5,
		TotalTests:        5,
		PassedTests:       4,
		FailedTests:       1,
		PendingTests:      0,
		MITRECoverage:     83.3,
		DetectionRate:     86.1,
		ValidationScore:   87.6,
		OpenGaps:          2,
		CriticalGaps:      0,
		LastValidation:    time.Now().Add(-2 * time.Hour),
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    metrics,
	})
}

