package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

// UEBACollector collects and analyzes user behavior data from AWS
type UEBACollector struct {
	cloudtrailCollector *CloudTrailCollector
	iamClient           *iam.IAM
	region              string
}

// UserBehaviorData represents analyzed user behavior
type UserBehaviorData struct {
	Username      string                 `json:"username"`
	UserType      string                 `json:"user_type"`
	Actions       []string               `json:"actions"`
	LoginCount    int                    `json:"login_count"`
	FailedLogins  int                    `json:"failed_logins"`
	APICallCount  int                    `json:"api_call_count"`
	UniqueIPs     map[string]bool        `json:"-"`
	UniqueIPCount int                    `json:"unique_ip_count"`
	Regions       map[string]bool        `json:"-"`
	RegionCount   int                    `json:"region_count"`
	RiskScore     float64                `json:"risk_score"`
	RiskLevel     string                 `json:"risk_level"`
	Anomalies     []string               `json:"anomalies"`
	FirstSeen     time.Time              `json:"first_seen"`
	LastSeen      time.Time              `json:"last_seen"`
	Details       map[string]interface{} `json:"details"`
}

// UEBAAnomaly represents a detected anomaly
type UEBAAnomaly struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Username    string                 `json:"username"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	RiskScore   float64                `json:"risk_score"`
	DetectedAt  time.Time              `json:"detected_at"`
	Details     map[string]interface{} `json:"details"`
	Status      string                 `json:"status"`
}

// NewUEBACollector creates a new UEBA collector (without session token)
func NewUEBACollector(accessKey, secretKey, region string) (*UEBACollector, error) {
	return NewUEBACollectorWithToken(accessKey, secretKey, "", region)
}

// NewUEBACollectorWithToken creates a new UEBA collector with session token support
func NewUEBACollectorWithToken(accessKey, secretKey, sessionToken, region string) (*UEBACollector, error) {
	// Create CloudTrail collector with token
	cloudtrailCollector, err := NewCloudTrailCollectorWithToken(accessKey, secretKey, sessionToken, region)
	if err != nil {
		return nil, fmt.Errorf("failed to create CloudTrail collector: %w", err)
	}

	// Create IAM client with token
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, sessionToken),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	return &UEBACollector{
		cloudtrailCollector: cloudtrailCollector,
		iamClient:           iam.New(sess),
		region:              region,
	}, nil
}

// NewUEBACollectorFromSession creates a new UEBA collector from an existing session
func NewUEBACollectorFromSession(sess *session.Session, region string) (*UEBACollector, error) {
	if sess == nil {
		return nil, fmt.Errorf("session is nil")
	}

	// Create CloudTrail collector from session
	cloudtrailCollector, err := NewCloudTrailCollectorFromSession(sess, region)
	if err != nil {
		return nil, fmt.Errorf("failed to create CloudTrail collector: %w", err)
	}

	return &UEBACollector{
		cloudtrailCollector: cloudtrailCollector,
		iamClient:           iam.New(sess),
		region:              region,
	}, nil
}

// AnalyzeUserBehavior collects and analyzes user behavior
func (u *UEBACollector) AnalyzeUserBehavior(hours int) ([]UserBehaviorData, []UEBAAnomaly, error) {
	log.Printf("🔍 Analyzing user behavior for the last %d hours", hours)

	// Collect CloudTrail events
	events, err := u.cloudtrailCollector.GetRecentEvents(hours, 1000)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to collect CloudTrail events: %w", err)
	}

	if len(events) == 0 {
		log.Printf("ℹ️  No CloudTrail events found for analysis")
		return []UserBehaviorData{}, []UEBAAnomaly{}, nil
	}

	log.Printf("📊 Analyzing %d CloudTrail events", len(events))

	// Analyze behavior
	behaviorMap := u.analyzeEvents(events)

	// Calculate risk scores
	behaviors := u.calculateRiskScores(behaviorMap)

	// Detect anomalies
	anomalies := u.detectAnomalies(behaviors)

	log.Printf("✅ Analysis complete: %d users, %d anomalies detected", len(behaviors), len(anomalies))

	return behaviors, anomalies, nil
}

// analyzeEvents analyzes CloudTrail events and builds user behavior profiles
func (u *UEBACollector) analyzeEvents(events []CloudTrailEvent) map[string]*UserBehaviorData {
	behaviorMap := make(map[string]*UserBehaviorData)

	for _, event := range events {
		username := event.UserIdentity.UserName
		if username == "" {
			continue
		}

		// Initialize behavior data if not exists
		if _, exists := behaviorMap[username]; !exists {
			behaviorMap[username] = &UserBehaviorData{
				Username:  username,
				UserType:  u.determineUserType(username),
				Actions:   []string{},
				UniqueIPs: make(map[string]bool),
				Regions:   make(map[string]bool),
				Anomalies: []string{},
				FirstSeen: event.EventTime,
				LastSeen:  event.EventTime,
				Details:   make(map[string]interface{}),
			}
		}

		behavior := behaviorMap[username]

		// Update behavior data
		behavior.Actions = append(behavior.Actions, event.EventName)
		behavior.APICallCount++

		// Track unique IPs
		if event.SourceIPAddress != "" {
			behavior.UniqueIPs[event.SourceIPAddress] = true
		}

		// Track regions
		if event.AwsRegion != "" {
			behavior.Regions[event.AwsRegion] = true
		}

		// Track logins
		if event.EventName == "ConsoleLogin" {
			behavior.LoginCount++
			if event.ErrorCode != "" {
				behavior.FailedLogins++
			}
		}

		// Update timestamps
		if event.EventTime.Before(behavior.FirstSeen) {
			behavior.FirstSeen = event.EventTime
		}
		if event.EventTime.After(behavior.LastSeen) {
			behavior.LastSeen = event.EventTime
		}
	}

	// Finalize counts
	for _, behavior := range behaviorMap {
		behavior.UniqueIPCount = len(behavior.UniqueIPs)
		behavior.RegionCount = len(behavior.Regions)
	}

	return behaviorMap
}

// determineUserType determines if user is human, service, or system
func (u *UEBACollector) determineUserType(username string) string {
	username = strings.ToLower(username)
	
	if strings.Contains(username, "service") || strings.Contains(username, "lambda") || 
	   strings.Contains(username, "ecs") || strings.Contains(username, "ec2") {
		return "service"
	}
	
	if strings.Contains(username, "root") || strings.Contains(username, "admin") {
		return "privileged"
	}
	
	return "user"
}

// calculateRiskScores calculates risk scores for each user
func (u *UEBACollector) calculateRiskScores(behaviorMap map[string]*UserBehaviorData) []UserBehaviorData {
	var behaviors []UserBehaviorData

	for _, behavior := range behaviorMap {
		score := 0.0

		// Factor 1: Multiple IPs (suspicious)
		if behavior.UniqueIPCount > 5 {
			score += 25.0
			behavior.Anomalies = append(behavior.Anomalies, "multiple_ips")
		} else if behavior.UniqueIPCount > 3 {
			score += 15.0
		}

		// Factor 2: Multiple regions (suspicious)
		if behavior.RegionCount > 3 {
			score += 20.0
			behavior.Anomalies = append(behavior.Anomalies, "multiple_regions")
		} else if behavior.RegionCount > 2 {
			score += 10.0
		}

		// Factor 3: Failed logins (suspicious)
		if behavior.FailedLogins > 5 {
			score += 30.0
			behavior.Anomalies = append(behavior.Anomalies, "multiple_failed_logins")
		} else if behavior.FailedLogins > 3 {
			score += 20.0
		}

		// Factor 4: High API call volume (suspicious)
		if behavior.APICallCount > 500 {
			score += 15.0
			behavior.Anomalies = append(behavior.Anomalies, "high_api_volume")
		} else if behavior.APICallCount > 200 {
			score += 10.0
		}

		// Factor 5: Privileged user activity
		if behavior.UserType == "privileged" {
			score += 10.0
		}

		// Factor 6: Time-based anomalies (simplified)
		hoursSinceFirstSeen := time.Since(behavior.FirstSeen).Hours()
		if hoursSinceFirstSeen < 1 && behavior.APICallCount > 100 {
			score += 15.0
			behavior.Anomalies = append(behavior.Anomalies, "rapid_activity")
		}

		behavior.RiskScore = score

		// Determine risk level
		if score >= 70 {
			behavior.RiskLevel = "critical"
		} else if score >= 50 {
			behavior.RiskLevel = "high"
		} else if score >= 30 {
			behavior.RiskLevel = "medium"
		} else {
			behavior.RiskLevel = "low"
		}

		// Add details
		behavior.Details["ip_addresses"] = u.mapKeysToSlice(behavior.UniqueIPs)
		behavior.Details["regions"] = u.mapKeysToSlice(behavior.Regions)
		behavior.Details["action_count"] = len(behavior.Actions)

		behaviors = append(behaviors, *behavior)
	}

	return behaviors
}

// detectAnomalies detects specific anomalies from user behavior
func (u *UEBACollector) detectAnomalies(behaviors []UserBehaviorData) []UEBAAnomaly {
	var anomalies []UEBAAnomaly
	anomalyID := 1

	for _, behavior := range behaviors {
		// Anomaly 1: High risk users
		if behavior.RiskScore >= 50 {
			anomalies = append(anomalies, UEBAAnomaly{
				ID:          fmt.Sprintf("ueba-anom-%d", anomalyID),
				Type:        "high_risk_user",
				Username:    behavior.Username,
				Severity:    u.riskLevelToSeverity(behavior.RiskLevel),
				Description: fmt.Sprintf("User %s has high risk score: %.1f", behavior.Username, behavior.RiskScore),
				RiskScore:   behavior.RiskScore,
				DetectedAt:  time.Now(),
				Details: map[string]interface{}{
					"anomalies":      behavior.Anomalies,
					"unique_ips":     behavior.UniqueIPCount,
					"regions":        behavior.RegionCount,
					"failed_logins":  behavior.FailedLogins,
					"api_call_count": behavior.APICallCount,
				},
				Status: "open",
			})
			anomalyID++
		}

		// Anomaly 2: Multiple IPs
		if behavior.UniqueIPCount > 5 {
			anomalies = append(anomalies, UEBAAnomaly{
				ID:          fmt.Sprintf("ueba-anom-%d", anomalyID),
				Type:        "multiple_ips",
				Username:    behavior.Username,
				Severity:    "medium",
				Description: fmt.Sprintf("User %s accessed from %d different IPs", behavior.Username, behavior.UniqueIPCount),
				RiskScore:   25.0,
				DetectedAt:  time.Now(),
				Details: map[string]interface{}{
					"ip_count":    behavior.UniqueIPCount,
					"ip_addresses": behavior.Details["ip_addresses"],
				},
				Status: "open",
			})
			anomalyID++
		}

		// Anomaly 3: Failed logins
		if behavior.FailedLogins > 5 {
			anomalies = append(anomalies, UEBAAnomaly{
				ID:          fmt.Sprintf("ueba-anom-%d", anomalyID),
				Type:        "failed_logins",
				Username:    behavior.Username,
				Severity:    "high",
				Description: fmt.Sprintf("User %s had %d failed login attempts", behavior.Username, behavior.FailedLogins),
				RiskScore:   30.0,
				DetectedAt:  time.Now(),
				Details: map[string]interface{}{
					"failed_count": behavior.FailedLogins,
					"login_count":  behavior.LoginCount,
				},
				Status: "open",
			})
			anomalyID++
		}

		// Anomaly 4: Unusual regions
		if behavior.RegionCount > 3 {
			anomalies = append(anomalies, UEBAAnomaly{
				ID:          fmt.Sprintf("ueba-anom-%d", anomalyID),
				Type:        "unusual_regions",
				Username:    behavior.Username,
				Severity:    "medium",
				Description: fmt.Sprintf("User %s accessed from %d different regions", behavior.Username, behavior.RegionCount),
				RiskScore:   20.0,
				DetectedAt:  time.Now(),
				Details: map[string]interface{}{
					"region_count": behavior.RegionCount,
					"regions":      behavior.Details["regions"],
				},
				Status: "open",
			})
			anomalyID++
		}
	}

	return anomalies
}

// riskLevelToSeverity converts risk level to severity
func (u *UEBACollector) riskLevelToSeverity(riskLevel string) string {
	switch riskLevel {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// mapKeysToSlice converts map keys to slice
func (u *UEBACollector) mapKeysToSlice(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestConnection tests the UEBA collector connections
func (u *UEBACollector) TestConnection() error {
	log.Printf("🧪 Testing UEBA collector connections...")

	// Test CloudTrail
	if err := u.cloudtrailCollector.TestConnection(); err != nil {
		return fmt.Errorf("CloudTrail test failed: %w", err)
	}

	// Test IAM
	_, err := u.iamClient.ListUsers(&iam.ListUsersInput{
		MaxItems: aws.Int64(1),
	})
	if err != nil {
		return fmt.Errorf("IAM test failed: %w", err)
	}

	log.Printf("✅ UEBA collector connections successful")
	return nil
}

