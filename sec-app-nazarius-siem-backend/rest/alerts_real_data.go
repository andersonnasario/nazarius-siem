package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/securityhub"
)

// AlertFromAWS represents an alert generated from AWS findings
type AlertFromAWS struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Source         string                 `json:"source"` // guardduty, securityhub, inspector, cloudtrail
	SourceID       string                 `json:"source_id"`
	Severity       string                 `json:"severity"`
	Status         string                 `json:"status"`
	Category       string                 `json:"category"`
	ResourceID     string                 `json:"resource_id"`
	ResourceType   string                 `json:"resource_type"`
	Region         string                 `json:"region"`
	AccountID      string                 `json:"account_id"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	DetectedAt     time.Time              `json:"detected_at"`
	Recommendation string                 `json:"recommendation"`
	RawData        map[string]interface{} `json:"raw_data,omitempty"`
	Tags           []string               `json:"tags"`
}

// StartAlertsIndexer starts a background process to sync AWS findings to alerts
func (s *APIServer) StartAlertsIndexer() {
	if os.Getenv("USE_REAL_AWS_DATA") != "true" && os.Getenv("DISABLE_MOCK_DATA") != "true" {
		log.Println("⚠️ Alerts indexer disabled - set USE_REAL_AWS_DATA=true or DISABLE_MOCK_DATA=true")
		return
	}

	// Initial sync
	go func() {
		time.Sleep(10 * time.Second) // Wait for other services to start
		log.Println("🔔 Starting initial alerts sync...")
		s.syncAlertsFromAWS()
	}()

	// Periodic sync every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			log.Println("🔔 Syncing alerts from AWS...")
			s.syncAlertsFromAWS()
		}
	}()

	log.Println("✅ Alerts indexer started")
}

// syncAlertsFromAWS fetches findings from AWS and indexes them as alerts
func (s *APIServer) syncAlertsFromAWS() {
	sess, err := getAWSSession()
	if err != nil {
		log.Printf("❌ Failed to create AWS session for alerts: %v", err)
		return
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	accountID := os.Getenv("AWS_ACCOUNT_ID")
	if accountID == "" {
		accountID = "unknown"
	}

	var alerts []AlertFromAWS

	// 1. Get Security Hub findings
	shAlerts := s.getSecurityHubAlerts(sess, region, accountID)
	alerts = append(alerts, shAlerts...)
	log.Printf("📊 Got %d alerts from Security Hub", len(shAlerts))

	// 2. Get GuardDuty findings
	gdAlerts := s.getGuardDutyAlerts(sess, region, accountID)
	alerts = append(alerts, gdAlerts...)
	log.Printf("📊 Got %d alerts from GuardDuty", len(gdAlerts))

	// 3. Index alerts to OpenSearch
	if s.opensearch != nil && len(alerts) > 0 {
		s.indexAlerts(alerts)
	}

	log.Printf("✅ Total alerts synced: %d", len(alerts))
}

// getSecurityHubAlerts fetches Security Hub findings and converts to alerts
func (s *APIServer) getSecurityHubAlerts(sess interface{}, region, accountID string) []AlertFromAWS {
	awsSess, err := getAWSSession()
	if err != nil {
		return []AlertFromAWS{}
	}

	shClient := securityhub.New(awsSess, aws.NewConfig().WithRegion(region))

	input := &securityhub.GetFindingsInput{
		MaxResults: aws.Int64(100),
		Filters: &securityhub.AwsSecurityFindingFilters{
			RecordState: []*securityhub.StringFilter{
				{Value: aws.String("ACTIVE"), Comparison: aws.String("EQUALS")},
			},
		},
	}

	result, err := shClient.GetFindings(input)
	if err != nil {
		log.Printf("⚠️ Error getting Security Hub findings for alerts: %v", err)
		return []AlertFromAWS{}
	}

	var alerts []AlertFromAWS

	for _, finding := range result.Findings {
		severity := mapAWSSeverityToAlert(aws.StringValue(finding.Severity.Label))

		resourceID := ""
		resourceType := ""
		if len(finding.Resources) > 0 {
			resourceID = aws.StringValue(finding.Resources[0].Id)
			resourceType = aws.StringValue(finding.Resources[0].Type)
		}

		createdAt := time.Now()
		if finding.CreatedAt != nil {
			if parsed, err := time.Parse(time.RFC3339, *finding.CreatedAt); err == nil {
				createdAt = parsed
			}
		}

		// Determine source/category
		source := "securityhub"
		generatorID := strings.ToLower(aws.StringValue(finding.GeneratorId))
		productName := strings.ToLower(aws.StringValue(finding.ProductName))

		if strings.Contains(generatorID, "guardduty") || strings.Contains(productName, "guardduty") {
			source = "guardduty"
		} else if strings.Contains(generatorID, "inspector") || strings.Contains(productName, "inspector") {
			// Inspector findings devem ser tratadas apenas em Vulnerabilidades, não em Alertas
			// Pular este finding - será indexado pelo pipeline de vulnerabilidades (siem-vulnerabilities)
			log.Printf("ℹ️ Skipping Inspector finding %s - handled by vulnerability pipeline", aws.StringValue(finding.Id))
			continue
		} else if strings.Contains(generatorID, "config") {
			source = "config"
		}

		category := getCategoryFromFinding(finding)

		// Build unique ID
		findingID := aws.StringValue(finding.Id)
		alertID := fmt.Sprintf("alert-sh-%s", sanitizeID(findingID))

		recommendation := ""
		if finding.Remediation != nil && finding.Remediation.Recommendation != nil {
			recommendation = aws.StringValue(finding.Remediation.Recommendation.Text)
		}

		// Usar o account_id do finding se disponível, senão usar o padrão
		findingAccountID := aws.StringValue(finding.AwsAccountId)
		if findingAccountID == "" {
			findingAccountID = accountID
		}

		// Extrair região do finding se disponível
		findingRegion := region
		if len(finding.Resources) > 0 && finding.Resources[0].Region != nil {
			findingRegion = aws.StringValue(finding.Resources[0].Region)
		}

		alert := AlertFromAWS{
			ID:             alertID,
			Name:           truncateString(aws.StringValue(finding.Title), 100),
			Description:    aws.StringValue(finding.Description),
			Source:         source,
			SourceID:       findingID,
			Severity:       severity,
			Status:         "new",
			Category:       category,
			ResourceID:     resourceID,
			ResourceType:   resourceType,
			Region:         findingRegion,
			AccountID:      findingAccountID, // Usar account_id do finding
			CreatedAt:      createdAt,
			UpdatedAt:      time.Now(),
			DetectedAt:     createdAt,
			Recommendation: recommendation,
			Tags:           getTagsFromFinding(finding),
		}

		alerts = append(alerts, alert)
	}

	return alerts
}

// getGuardDutyAlerts fetches GuardDuty findings and converts to alerts
func (s *APIServer) getGuardDutyAlerts(sess interface{}, region, accountID string) []AlertFromAWS {
	awsSess, err := getAWSSession()
	if err != nil {
		return []AlertFromAWS{}
	}

	gdClient := guardduty.New(awsSess, aws.NewConfig().WithRegion(region))

	// Get detector ID
	detectorsOutput, err := gdClient.ListDetectors(&guardduty.ListDetectorsInput{})
	if err != nil || len(detectorsOutput.DetectorIds) == 0 {
		return []AlertFromAWS{}
	}

	detectorID := detectorsOutput.DetectorIds[0]

	// Get findings
	findingsInput := &guardduty.ListFindingsInput{
		DetectorId: detectorID,
		MaxResults: aws.Int64(50),
		FindingCriteria: &guardduty.FindingCriteria{
			Criterion: map[string]*guardduty.Condition{
				"service.archived": {
					Eq: []*string{aws.String("false")},
				},
			},
		},
	}

	findingsOutput, err := gdClient.ListFindings(findingsInput)
	if err != nil {
		log.Printf("⚠️ Error listing GuardDuty findings: %v", err)
		return []AlertFromAWS{}
	}

	if len(findingsOutput.FindingIds) == 0 {
		return []AlertFromAWS{}
	}

	// Get finding details
	getInput := &guardduty.GetFindingsInput{
		DetectorId: detectorID,
		FindingIds: findingsOutput.FindingIds,
	}

	detailsOutput, err := gdClient.GetFindings(getInput)
	if err != nil {
		log.Printf("⚠️ Error getting GuardDuty finding details: %v", err)
		return []AlertFromAWS{}
	}

	var alerts []AlertFromAWS

	for _, finding := range detailsOutput.Findings {
		severity := mapGuardDutySeverityToAlert(aws.Float64Value(finding.Severity))

		resourceType := aws.StringValue(finding.Resource.ResourceType)
		resourceID := ""
		if finding.Resource.InstanceDetails != nil {
			resourceID = aws.StringValue(finding.Resource.InstanceDetails.InstanceId)
		} else if finding.Resource.AccessKeyDetails != nil {
			resourceID = aws.StringValue(finding.Resource.AccessKeyDetails.AccessKeyId)
		}

		createdAt := time.Now()
		if finding.CreatedAt != nil {
			createdAt = parseGuardDutyTime(*finding.CreatedAt)
		}

		category := aws.StringValue(finding.Type)
		if parts := strings.Split(category, "/"); len(parts) > 0 {
			category = parts[0]
		}

		alertID := fmt.Sprintf("alert-gd-%s", sanitizeID(aws.StringValue(finding.Id)))

		// Usar o account_id do finding se disponível, senão usar o padrão
		findingAccountID := aws.StringValue(finding.AccountId)
		if findingAccountID == "" {
			findingAccountID = accountID
		}

		// Extrair região do finding se disponível
		findingRegion := aws.StringValue(finding.Region)
		if findingRegion == "" {
			findingRegion = region
		}

		alert := AlertFromAWS{
			ID:             alertID,
			Name:           truncateString(aws.StringValue(finding.Title), 100),
			Description:    aws.StringValue(finding.Description),
			Source:         "guardduty",
			SourceID:       aws.StringValue(finding.Id),
			Severity:       severity,
			Status:         "new",
			Category:       category,
			ResourceID:     resourceID,
			ResourceType:   resourceType,
			Region:         findingRegion,
			AccountID:      findingAccountID, // Usar account_id do finding
			CreatedAt:      createdAt,
			UpdatedAt:      time.Now(),
			DetectedAt:     createdAt,
			Recommendation: getGuardDutyRecommendation(finding),
			Tags:           []string{"guardduty", category},
		}

		alerts = append(alerts, alert)
	}

	return alerts
}

// indexAlerts indexes alerts to OpenSearch
func (s *APIServer) indexAlerts(alerts []AlertFromAWS) {
	if s.opensearch == nil {
		return
	}

	// Ensure index exists
	s.ensureAlertsIndex()

	indexed := 0
	errors := 0

	for _, alert := range alerts {
		alertJSON, err := json.Marshal(alert)
		if err != nil {
			errors++
			continue
		}

		res, err := s.opensearch.Index(
			"siem-alerts",
			strings.NewReader(string(alertJSON)),
			s.opensearch.Index.WithDocumentID(alert.ID),
		)
		if err != nil {
			errors++
			continue
		}
		res.Body.Close()

		if !res.IsError() {
			indexed++
		} else {
			errors++
		}
	}

	log.Printf("📊 Alerts indexing: %d indexed, %d errors", indexed, errors)
}

// ensureAlertsIndex creates the siem-alerts index if it doesn't exist
func (s *APIServer) ensureAlertsIndex() {
	if s.opensearch == nil {
		return
	}

	mapping := `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"description": { "type": "text" },
				"source": { "type": "keyword" },
				"source_id": { "type": "keyword" },
				"severity": { "type": "keyword" },
				"status": { "type": "keyword" },
				"category": { "type": "keyword" },
				"resource_id": { "type": "keyword" },
				"resource_type": { "type": "keyword" },
				"region": { "type": "keyword" },
				"account_id": { "type": "keyword" },
				"created_at": { "type": "date" },
				"updated_at": { "type": "date" },
				"detected_at": { "type": "date" },
				"recommendation": { "type": "text" },
				"tags": { "type": "keyword" }
			}
		}
	}`

	res, err := s.opensearch.Indices.Exists([]string{"siem-alerts"})
	if err == nil && res.StatusCode == 404 {
		res, err := s.opensearch.Indices.Create(
			"siem-alerts",
			s.opensearch.Indices.Create.WithBody(strings.NewReader(mapping)),
		)
		if err != nil {
			log.Printf("⚠️ Error creating siem-alerts index: %v", err)
		} else {
			res.Body.Close()
			log.Println("✅ Created siem-alerts index")
		}
	}
}

// Helper functions

func mapAWSSeverityToAlert(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW", "INFORMATIONAL":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

func mapGuardDutySeverityToAlert(severity float64) string {
	if severity >= 7.0 {
		return "CRITICAL"
	} else if severity >= 4.0 {
		return "HIGH"
	} else if severity >= 1.0 {
		return "MEDIUM"
	}
	return "LOW"
}

func getCategoryFromFinding(finding *securityhub.AwsSecurityFinding) string {
	if finding.Types != nil && len(finding.Types) > 0 {
		typeStr := aws.StringValue(finding.Types[0])
		parts := strings.Split(typeStr, "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return "Security"
}

func getTagsFromFinding(finding *securityhub.AwsSecurityFinding) []string {
	tags := []string{}

	// Add source as tag
	generatorID := strings.ToLower(aws.StringValue(finding.GeneratorId))
	if strings.Contains(generatorID, "guardduty") {
		tags = append(tags, "guardduty")
	} else if strings.Contains(generatorID, "inspector") {
		tags = append(tags, "inspector")
	} else if strings.Contains(generatorID, "config") {
		tags = append(tags, "config")
	} else {
		tags = append(tags, "securityhub")
	}

	// Add severity as tag
	tags = append(tags, strings.ToLower(aws.StringValue(finding.Severity.Label)))

	// Add type as tag
	if finding.Types != nil && len(finding.Types) > 0 {
		typeStr := aws.StringValue(finding.Types[0])
		parts := strings.Split(typeStr, "/")
		if len(parts) > 0 {
			tags = append(tags, strings.ToLower(parts[0]))
		}
	}

	return tags
}

func getGuardDutyRecommendation(finding *guardduty.Finding) string {
	findingType := aws.StringValue(finding.Type)

	recommendations := map[string]string{
		"UnauthorizedAccess": "Review IAM policies and restrict access. Check for compromised credentials.",
		"Recon":              "Implement network ACLs and security groups to restrict reconnaissance activities.",
		"Trojan":             "Isolate the affected instance immediately and perform a security investigation.",
		"CryptoCurrency":     "Terminate any unauthorized cryptocurrency mining processes.",
		"PenTest":            "Review if this is an authorized penetration test. If not, investigate immediately.",
		"Policy":             "Review and update IAM policies to enforce least privilege.",
		"Stealth":            "Investigate potential attempts to hide malicious activity.",
		"CredentialAccess":   "Rotate potentially compromised credentials and enable MFA.",
		"Exfiltration":       "Block suspected data exfiltration and investigate the source.",
		"Impact":             "Assess the impact and implement incident response procedures.",
	}

	for key, rec := range recommendations {
		if strings.Contains(findingType, key) {
			return rec
		}
	}

	return "Review the finding details and take appropriate action based on your security policies."
}

func parseGuardDutyTime(timeStr string) time.Time {
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, timeStr); err == nil {
			return t
		}
	}

	return time.Now()
}

func sanitizeID(id string) string {
	// Replace characters that might cause issues in OpenSearch
	replacer := strings.NewReplacer(":", "_", "/", "_", "+", "_", "=", "_")
	result := replacer.Replace(id)
	// Limit length
	if len(result) > 100 {
		result = result[:100]
	}
	return result
}
