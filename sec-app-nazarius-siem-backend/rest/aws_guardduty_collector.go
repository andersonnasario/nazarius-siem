package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/guardduty"
)

// GuardDutyCollector collects real GuardDuty findings from AWS
type GuardDutyCollector struct {
	client     *guardduty.GuardDuty
	region     string
	detectorID string
}

// NewGuardDutyCollector creates a new GuardDuty collector (without session token)
func NewGuardDutyCollector(accessKey, secretKey, region string) (*GuardDutyCollector, error) {
	return NewGuardDutyCollectorWithToken(accessKey, secretKey, "", region)
}

// NewGuardDutyCollectorWithToken creates a new GuardDuty collector with session token support
func NewGuardDutyCollectorWithToken(accessKey, secretKey, sessionToken, region string) (*GuardDutyCollector, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, sessionToken),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	client := guardduty.New(sess)

	// Get or create detector
	detectorID, err := getOrCreateDetector(client)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create GuardDuty detector: %w", err)
	}

	return &GuardDutyCollector{
		client:     client,
		region:     region,
		detectorID: detectorID,
	}, nil
}

// NewGuardDutyCollectorFromSession creates a new GuardDuty collector from an existing session
func NewGuardDutyCollectorFromSession(sess *session.Session, region string) (*GuardDutyCollector, error) {
	if sess == nil {
		return nil, fmt.Errorf("session is nil")
	}

	client := guardduty.New(sess)

	// Get or create detector
	detectorID, err := getOrCreateDetector(client)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create GuardDuty detector: %w", err)
	}

	return &GuardDutyCollector{
		client:     client,
		region:     region,
		detectorID: detectorID,
	}, nil
}

// getOrCreateDetector gets existing detector or returns empty string if none exists
func getOrCreateDetector(client *guardduty.GuardDuty) (string, error) {
	// List existing detectors
	listOutput, err := client.ListDetectors(&guardduty.ListDetectorsInput{})
	if err != nil {
		return "", fmt.Errorf("failed to list detectors: %w", err)
	}

	if len(listOutput.DetectorIds) > 0 {
		detectorID := aws.StringValue(listOutput.DetectorIds[0])
		log.Printf("✅ Using existing GuardDuty detector: %s", detectorID)
		return detectorID, nil
	}

	log.Printf("⚠️  No GuardDuty detector found. Please enable GuardDuty in AWS Console first.")
	return "", fmt.Errorf("no GuardDuty detector found - please enable GuardDuty")
}

// CollectFindings collects GuardDuty findings from AWS
func (g *GuardDutyCollector) CollectFindings(maxResults int) ([]GuardDutyFinding, error) {
	if g.detectorID == "" {
		return nil, fmt.Errorf("no GuardDuty detector available")
	}

	// GuardDuty API only accepts maxResults between 1-50
	if maxResults > 50 {
		maxResults = 50
	}
	if maxResults < 1 {
		maxResults = 50
	}

	log.Printf("🔍 Collecting GuardDuty findings from detector: %s (max: %d)", g.detectorID, maxResults)

	// List finding IDs
	listInput := &guardduty.ListFindingsInput{
		DetectorId: aws.String(g.detectorID),
		MaxResults: aws.Int64(int64(maxResults)),
		FindingCriteria: &guardduty.FindingCriteria{
			Criterion: map[string]*guardduty.Condition{
				"service.archived": {
					Eq: []*string{aws.String("false")},
				},
			},
		},
	}

	listOutput, err := g.client.ListFindings(listInput)
	if err != nil {
		return nil, fmt.Errorf("failed to list findings: %w", err)
	}

	if len(listOutput.FindingIds) == 0 {
		log.Printf("ℹ️  No GuardDuty findings found")
		return []GuardDutyFinding{}, nil
	}

	log.Printf("📄 Found %d GuardDuty findings, fetching details...", len(listOutput.FindingIds))

	// Get finding details
	getInput := &guardduty.GetFindingsInput{
		DetectorId: aws.String(g.detectorID),
		FindingIds: listOutput.FindingIds,
	}

	getOutput, err := g.client.GetFindings(getInput)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %w", err)
	}

	// Convert findings
	var findings []GuardDutyFinding
	for _, f := range getOutput.Findings {
		findings = append(findings, g.convertFinding(f))
	}

	log.Printf("✅ Collected %d GuardDuty findings", len(findings))
	return findings, nil
}

// convertFinding converts AWS GuardDuty finding to our internal format
func (g *GuardDutyCollector) convertFinding(finding *guardduty.Finding) GuardDutyFinding {
	// Parse timestamps from strings
	createdAt := parseAWSTimestamp(aws.StringValue(finding.CreatedAt))
	updatedAt := parseAWSTimestamp(aws.StringValue(finding.UpdatedAt))
	
	return GuardDutyFinding{
		ID:          aws.StringValue(finding.Id),
		ARN:         aws.StringValue(finding.Arn),
		Type:        aws.StringValue(finding.Type),
		Severity:    aws.Float64Value(finding.Severity),
		Title:       aws.StringValue(finding.Title),
		Description: aws.StringValue(finding.Description),
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		Region:      aws.StringValue(finding.Region),
		AccountID:   aws.StringValue(finding.AccountId),
		Resource:    g.extractResource(finding),
		Service:     g.extractService(finding),
	}
}

// convertSeverity converts numeric severity to string
func (g *GuardDutyCollector) convertSeverity(severity float64) string {
	if severity >= 7.0 {
		return "HIGH"
	} else if severity >= 4.0 {
		return "MEDIUM"
	}
	return "LOW"
}

// extractResource extracts resource information from finding
func (g *GuardDutyCollector) extractResource(finding *guardduty.Finding) GuardDutyResource {
	resource := GuardDutyResource{
		InstanceDetails:  make(map[string]interface{}),
		AccessKeyDetails: make(map[string]interface{}),
	}

	if finding.Resource != nil {
		if finding.Resource.ResourceType != nil {
			resource.ResourceType = aws.StringValue(finding.Resource.ResourceType)
		}

		if finding.Resource.InstanceDetails != nil {
			resource.InstanceDetails["instance_id"] = aws.StringValue(finding.Resource.InstanceDetails.InstanceId)
			resource.InstanceDetails["instance_type"] = aws.StringValue(finding.Resource.InstanceDetails.InstanceType)
			
			if finding.Resource.InstanceDetails.IamInstanceProfile != nil {
				resource.InstanceDetails["iam_profile"] = aws.StringValue(finding.Resource.InstanceDetails.IamInstanceProfile.Arn)
			}
		}
	}

	return resource
}

// extractService extracts service information from finding
func (g *GuardDutyCollector) extractService(finding *guardduty.Finding) GuardDutyService {
	service := GuardDutyService{
		Action:         make(map[string]interface{}),
		Evidence:       make(map[string]interface{}),
		AdditionalInfo: make(map[string]interface{}),
	}

	if finding.Service != nil {
		if finding.Service.Action != nil {
			service.Action["action_type"] = aws.StringValue(finding.Service.Action.ActionType)

			if finding.Service.Action.NetworkConnectionAction != nil && finding.Service.Action.NetworkConnectionAction.RemoteIpDetails != nil {
				service.Action["remote_ip"] = aws.StringValue(finding.Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4)
			}

			if finding.Service.Action.AwsApiCallAction != nil {
				service.Action["api_name"] = aws.StringValue(finding.Service.Action.AwsApiCallAction.Api)
				service.Action["service_name"] = aws.StringValue(finding.Service.Action.AwsApiCallAction.ServiceName)
			}
		}

		service.EventFirstSeen = parseAWSTimestamp(aws.StringValue(finding.Service.EventFirstSeen))
		service.EventLastSeen = parseAWSTimestamp(aws.StringValue(finding.Service.EventLastSeen))
		service.Count = int(aws.Int64Value(finding.Service.Count))
	}

	return service
}

// parseAWSTimestamp parses AWS timestamp string to time.Time
func parseAWSTimestamp(timestamp string) time.Time {
	if timestamp == "" {
		return time.Time{}
	}
	
	// Try RFC3339 format first
	t, err := time.Parse(time.RFC3339, timestamp)
	if err == nil {
		return t
	}
	
	// Try RFC3339Nano format
	t, err = time.Parse(time.RFC3339Nano, timestamp)
	if err == nil {
		return t
	}
	
	// Return zero time if parsing fails
	return time.Time{}
}

// GetRecentFindings is a convenience method to get recent findings
func (g *GuardDutyCollector) GetRecentFindings(maxResults int) ([]GuardDutyFinding, error) {
	return g.CollectFindings(maxResults)
}

// TestConnection tests the GuardDuty connection
func (g *GuardDutyCollector) TestConnection() error {
	log.Printf("🧪 Testing GuardDuty connection...")

	if g.detectorID == "" {
		return fmt.Errorf("no GuardDuty detector available")
	}

	input := &guardduty.GetDetectorInput{
		DetectorId: aws.String(g.detectorID),
	}

	output, err := g.client.GetDetector(input)
	if err != nil {
		return fmt.Errorf("GuardDuty connection test failed: %w", err)
	}

	log.Printf("✅ GuardDuty connection successful, detector status: %s", aws.StringValue(output.Status))
	return nil
}

// ArchiveFinding archives a GuardDuty finding
func (g *GuardDutyCollector) ArchiveFinding(findingID string) error {
	if g.detectorID == "" {
		return fmt.Errorf("no GuardDuty detector available")
	}

	input := &guardduty.ArchiveFindingsInput{
		DetectorId: aws.String(g.detectorID),
		FindingIds: []*string{aws.String(findingID)},
	}

	_, err := g.client.ArchiveFindings(input)
	if err != nil {
		return fmt.Errorf("failed to archive finding: %w", err)
	}

	log.Printf("✅ Archived GuardDuty finding: %s", findingID)
	return nil
}

// StartGuardDutyIndexer starts a background job to collect and index GuardDuty findings
func (s *APIServer) StartGuardDutyIndexer(intervalMinutes int) {
	useRealAWS := os.Getenv("USE_REAL_AWS_DATA")
	if useRealAWS != "true" {
		log.Printf("⚠️ USE_REAL_AWS_DATA not set to true, GuardDuty indexer disabled")
		return
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	if intervalMinutes <= 0 {
		intervalMinutes = 5
	}

	go func() {
		ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
		defer ticker.Stop()

		// Index immediately on start
		s.syncGuardDutyFindings(region)

		for range ticker.C {
			s.syncGuardDutyFindings(region)
		}
	}()

	log.Printf("🔄 GuardDuty Indexer started (interval: %d min)", intervalMinutes)
	AddSystemLog("INFO", "guardduty", fmt.Sprintf("Indexer started (interval: %d min)", intervalMinutes), nil)
}

// syncGuardDutyFindings syncs GuardDuty findings to OpenSearch
func (s *APIServer) syncGuardDutyFindings(region string) {
	log.Printf("🔄 Starting GuardDuty sync...")

	// Get AWS session
	sess, err := getAWSSession()
	if err != nil {
		log.Printf("❌ Failed to create AWS session: %v", err)
		AddSystemLog("ERROR", "guardduty", fmt.Sprintf("AWS session failed: %v", err), nil)
		return
	}

	// Create collector
	collector, err := NewGuardDutyCollectorFromSession(sess, region)
	if err != nil {
		log.Printf("❌ Failed to create GuardDuty collector: %v", err)
		AddSystemLog("ERROR", "guardduty", fmt.Sprintf("Failed to create collector: %v", err), nil)
		return
	}

	// Collect findings
	findings, err := collector.CollectFindings(100)
	if err != nil {
		log.Printf("❌ Failed to collect findings: %v", err)
		AddSystemLog("ERROR", "guardduty", fmt.Sprintf("Failed to collect: %v", err), nil)
		return
	}

	if len(findings) == 0 {
		log.Printf("📭 No GuardDuty findings found")
		return
	}

	// Update global variable for other components
	awsConfigMutex.Lock()
	guardDutyFindings = findings
	awsConfigMutex.Unlock()

	// Index findings into OpenSearch
	if err := s.IndexGuardDutyFindings(findings); err != nil {
		log.Printf("❌ Failed to index findings: %v", err)
		AddSystemLog("ERROR", "guardduty", fmt.Sprintf("Failed to index: %v", err), nil)
		return
	}

	log.Printf("✅ Synced %d GuardDuty findings", len(findings))
	AddSystemLog("INFO", "guardduty", fmt.Sprintf("Synced %d findings", len(findings)), nil)
}

