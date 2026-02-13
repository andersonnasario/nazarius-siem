package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
)

// SecurityHubCollector collects findings from AWS Security Hub
type SecurityHubCollector struct {
	client *securityhub.SecurityHub
	region string
}

// NewSecurityHubCollector creates a new Security Hub collector
func NewSecurityHubCollector(sess *session.Session, region string) (*SecurityHubCollector, error) {
	if sess == nil {
		return nil, fmt.Errorf("AWS session is nil")
	}

	return &SecurityHubCollector{
		client: securityhub.New(sess, aws.NewConfig().WithRegion(region)),
		region: region,
	}, nil
}

// NewSecurityHubCollectorFromSession creates a new Security Hub collector from an existing session
// This is an alias for NewSecurityHubCollector for compatibility with cspm_aws.go
func NewSecurityHubCollectorFromSession(sess *session.Session, region string) (*SecurityHubCollector, error) {
	return NewSecurityHubCollector(sess, region)
}

// TestConnection tests the Security Hub connection
func (c *SecurityHubCollector) TestConnection() error {
	log.Printf("🧪 Testing Security Hub connection...")

	// Try to describe the hub
	_, err := c.client.DescribeHub(&securityhub.DescribeHubInput{})
	if err != nil {
		return fmt.Errorf("Security Hub connection test failed: %w", err)
	}

	log.Printf("✅ Security Hub connection successful")
	return nil
}

// CollectFindings collects findings from Security Hub
func (c *SecurityHubCollector) CollectFindings(maxResults int) ([]SecurityHubFindingInternal, error) {
	log.Printf("🔍 Collecting Security Hub findings...")
	AddSystemLog("INFO", "securityhub", "Collecting findings from Security Hub", nil)

	input := &securityhub.GetFindingsInput{
		MaxResults: aws.Int64(int64(maxResults)),
		Filters: &securityhub.AwsSecurityFindingFilters{
			RecordState: []*securityhub.StringFilter{
				{
					Value:      aws.String("ACTIVE"),
					Comparison: aws.String("EQUALS"),
				},
			},
		},
		SortCriteria: []*securityhub.SortCriterion{
			{
				Field:     aws.String("UpdatedAt"),
				SortOrder: aws.String("desc"),
			},
		},
	}

	var allFindings []SecurityHubFindingInternal

	err := c.client.GetFindingsPages(input, func(page *securityhub.GetFindingsOutput, lastPage bool) bool {
		for _, finding := range page.Findings {
			converted := c.convertFindingInternal(finding)
			allFindings = append(allFindings, converted)
		}
		return !lastPage && len(allFindings) < maxResults
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %w", err)
	}

	log.Printf("✅ Collected %d Security Hub findings", len(allFindings))
	AddSystemLog("INFO", "securityhub", fmt.Sprintf("Collected %d findings", len(allFindings)), nil)

	return allFindings, nil
}

// convertFindingInternal converts AWS Security Hub finding to internal format
func (c *SecurityHubCollector) convertFindingInternal(f *securityhub.AwsSecurityFinding) SecurityHubFindingInternal {
	finding := SecurityHubFindingInternal{
		ID:          aws.StringValue(f.Id),
		ProductARN:  aws.StringValue(f.ProductArn),
		GeneratorID: aws.StringValue(f.GeneratorId),
		AccountID:   aws.StringValue(f.AwsAccountId),
		Region:      c.region,
		Title:       aws.StringValue(f.Title),
		Description: aws.StringValue(f.Description),
		Types:       aws.StringValueSlice(f.Types),
	}

	// Handle severity
	if f.Severity != nil {
		if f.Severity.Normalized != nil {
			finding.Severity = float64(*f.Severity.Normalized)
		}
		if f.Severity.Label != nil {
			finding.SeverityLabel = aws.StringValue(f.Severity.Label)
		}
	}

	// Handle timestamps
	if f.CreatedAt != nil {
		if t, err := time.Parse(time.RFC3339, *f.CreatedAt); err == nil {
			finding.CreatedAt = t
		}
	}
	if f.UpdatedAt != nil {
		if t, err := time.Parse(time.RFC3339, *f.UpdatedAt); err == nil {
			finding.UpdatedAt = t
		}
	}

	// Handle compliance
	if f.Compliance != nil {
		if f.Compliance.Status != nil {
			finding.ComplianceStatus = aws.StringValue(f.Compliance.Status)
		}
	}

	// Handle resources
	if len(f.Resources) > 0 {
		res := f.Resources[0]
		finding.ResourceType = aws.StringValue(res.Type)
		finding.ResourceID = aws.StringValue(res.Id)
		finding.ResourceARN = aws.StringValue(res.Id)
	}

	// Handle remediation
	if f.Remediation != nil && f.Remediation.Recommendation != nil {
		finding.Recommendation = aws.StringValue(f.Remediation.Recommendation.Text)
		finding.RecommendationURL = aws.StringValue(f.Remediation.Recommendation.Url)
	}

	// Handle workflow
	if f.Workflow != nil && f.Workflow.Status != nil {
		finding.WorkflowStatus = aws.StringValue(f.Workflow.Status)
	}

	return finding
}

// SecurityHubFindingInternal represents a Security Hub finding for internal indexer use
// This is separate from the SecurityHubFinding struct in cspm_aws.go
type SecurityHubFindingInternal struct {
	ID                string    `json:"id"`
	ProductARN        string    `json:"product_arn"`
	GeneratorID       string    `json:"generator_id"`
	AccountID         string    `json:"account_id"`
	Region            string    `json:"region"`
	Title             string    `json:"title"`
	Description       string    `json:"description"`
	Severity          float64   `json:"severity"`
	SeverityLabel     string    `json:"severity_label"`
	Types             []string  `json:"types"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	ComplianceStatus  string    `json:"compliance_status"`
	ResourceType      string    `json:"resource_type"`
	ResourceID        string    `json:"resource_id"`
	ResourceARN       string    `json:"resource_arn"`
	Recommendation    string    `json:"recommendation"`
	RecommendationURL string    `json:"recommendation_url"`
	WorkflowStatus    string    `json:"workflow_status"`
}

// StartSecurityHubIndexer starts a background job to collect and index Security Hub findings
func (s *APIServer) StartSecurityHubIndexer(intervalMinutes int) {
	useSecurityHub := os.Getenv("USE_SECURITY_HUB")
	if useSecurityHub != "true" {
		log.Printf("⚠️ USE_SECURITY_HUB not set to true, Security Hub indexer disabled")
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
		s.syncSecurityHubFindings(region)

		for range ticker.C {
			s.syncSecurityHubFindings(region)
		}
	}()

	log.Printf("🔄 Security Hub Indexer started (interval: %d min)", intervalMinutes)
	AddSystemLog("INFO", "securityhub", fmt.Sprintf("Indexer started (interval: %d min)", intervalMinutes), nil)
}

// syncSecurityHubFindings syncs Security Hub findings to OpenSearch
func (s *APIServer) syncSecurityHubFindings(region string) {
	log.Printf("🔄 Starting Security Hub sync...")

	// Get AWS session
	sess, err := getAWSSession()
	if err != nil {
		log.Printf("❌ Failed to create AWS session: %v", err)
		AddSystemLog("ERROR", "securityhub", fmt.Sprintf("AWS session failed: %v", err), nil)
		return
	}

	// Create collector
	collector, err := NewSecurityHubCollector(sess, region)
	if err != nil {
		log.Printf("❌ Failed to create Security Hub collector: %v", err)
		AddSystemLog("ERROR", "securityhub", fmt.Sprintf("Failed to create collector: %v", err), nil)
		return
	}

	// Collect findings
	findings, err := collector.CollectFindings(100)
	if err != nil {
		log.Printf("❌ Failed to collect findings: %v", err)
		AddSystemLog("ERROR", "securityhub", fmt.Sprintf("Failed to collect: %v", err), nil)
		return
	}

	if len(findings) == 0 {
		log.Printf("📭 No Security Hub findings found")
		return
	}

	// Index findings into OpenSearch
	if err := s.IndexSecurityHubFindingsInternal(findings); err != nil {
		log.Printf("❌ Failed to index findings: %v", err)
		AddSystemLog("ERROR", "securityhub", fmt.Sprintf("Failed to index: %v", err), nil)
		return
	}

	log.Printf("✅ Synced %d Security Hub findings", len(findings))
	AddSystemLog("INFO", "securityhub", fmt.Sprintf("Synced %d findings", len(findings)), nil)
}

// IndexSecurityHubFindingsInternal indexes Security Hub findings into OpenSearch
func (s *APIServer) IndexSecurityHubFindingsInternal(findings []SecurityHubFindingInternal) error {
	if s.opensearch == nil {
		log.Printf("❌ OpenSearch client is nil - cannot index Security Hub findings")
		AddSystemLog("ERROR", "securityhub", "OpenSearch client is nil", nil)
		return fmt.Errorf("opensearch not available")
	}

	indexed := 0
	errors := 0
	var lastError string

	for _, finding := range findings {
		// Convert to SIEM event format
		event := s.convertSecurityHubInternalToSIEMEvent(finding)

		// Index into OpenSearch
		if err := s.indexEvent(event); err != nil {
			lastError = err.Error()
			if errors < 3 { // Only log first 3 errors to avoid spam
				log.Printf("❌ Failed to index Security Hub finding %s: %v", finding.ID, err)
			}
			errors++
			continue
		}
		indexed++
	}

	// Log summary with last error if any
	if errors > 0 && lastError != "" {
		AddSystemLog("WARN", "securityhub", fmt.Sprintf("Indexing had %d errors. Last error: %s", errors, lastError), nil)
	}

	log.Printf("✅ Indexed %d Security Hub findings (%d errors)", indexed, errors)
	AddSystemLog("INFO", "securityhub", fmt.Sprintf("Indexed %d findings", indexed), map[string]interface{}{
		"total":   len(findings),
		"indexed": indexed,
		"errors":  errors,
	})

	return nil
}

// convertSecurityHubInternalToSIEMEvent converts a Security Hub finding to SIEM Event format
func (s *APIServer) convertSecurityHubInternalToSIEMEvent(sh SecurityHubFindingInternal) Event {
	// Map severity
	severity := mapSecurityHubSeverityInternal(sh.SeverityLabel, sh.Severity)

	// Build event type from types
	eventType := "Security Finding"
	if len(sh.Types) > 0 {
		eventType = sh.Types[0]
	}

	// Sanitize the ID to remove special characters that OpenSearch doesn't like
	// ARNs contain : which cause issues in document IDs
	sanitizedID := strings.ReplaceAll(sh.ID, ":", "_")
	sanitizedID = strings.ReplaceAll(sanitizedID, "/", "_")

	return Event{
		ID:          fmt.Sprintf("securityhub-%s", sanitizedID),
		Timestamp:   sh.UpdatedAt,
		Source:      "AWS Security Hub",
		Type:        eventType,
		Severity:    severity,
		Description: fmt.Sprintf("%s: %s", sh.Title, sh.Description),
		Details: map[string]interface{}{
			"finding_id":        sh.ID,
			"product_arn":       sh.ProductARN,
			"generator_id":      sh.GeneratorID,
			"account_id":        sh.AccountID,
			"region":            sh.Region,
			"title":             sh.Title,
			"description":       sh.Description,
			"severity":          sh.Severity,
			"severity_label":    sh.SeverityLabel,
			"types":             sh.Types,
			"compliance_status": sh.ComplianceStatus,
			"resource_type":     sh.ResourceType,
			"resource_id":       sh.ResourceID,
			"resource_arn":      sh.ResourceARN,
			"recommendation":    sh.Recommendation,
			"workflow_status":   sh.WorkflowStatus,
			"created_at":        sh.CreatedAt,
			"updated_at":        sh.UpdatedAt,
		},
		Tags: []string{"aws", "securityhub", "compliance", sh.SeverityLabel},
	}
}

// mapSecurityHubSeverityInternal maps Security Hub severity to SIEM severity
func mapSecurityHubSeverityInternal(label string, normalized float64) string {
	switch label {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "INFORMATIONAL":
		return "INFO"
	default:
		// Fallback to normalized score
		if normalized >= 80 {
			return "CRITICAL"
		} else if normalized >= 60 {
			return "HIGH"
		} else if normalized >= 40 {
			return "MEDIUM"
		} else if normalized >= 1 {
			return "LOW"
		}
		return "INFO"
	}
}
