package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/inspector2"
	"github.com/opensearch-project/opensearch-go/v2"
)

// ============================================================================
// AWS INSPECTOR V2 COLLECTOR
// ============================================================================
// Collects vulnerability findings from AWS Inspector v2 and indexes them
// in OpenSearch for real-time vulnerability management

// InspectorFinding represents a vulnerability finding from AWS Inspector
type InspectorFinding struct {
	ID               string                 `json:"id"`
	FindingARN       string                 `json:"finding_arn"`
	Type             string                 `json:"type"` // PACKAGE_VULNERABILITY, NETWORK_REACHABILITY, CODE_VULNERABILITY
	Title            string                 `json:"title"`
	Description      string                 `json:"description"`
	Severity         string                 `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
	Status           string                 `json:"status"`   // ACTIVE, SUPPRESSED, CLOSED
	CVEID            string                 `json:"cve_id,omitempty"`
	CVSSScore        float64                `json:"cvss_score"`
	CVSSVector       string                 `json:"cvss_vector,omitempty"`
	ExploitAvailable bool                   `json:"exploit_available"`
	FixAvailable     bool                   `json:"fix_available"`
	
	// Resource information
	ResourceType     string                 `json:"resource_type"` // AWS_EC2_INSTANCE, AWS_ECR_CONTAINER_IMAGE, AWS_LAMBDA_FUNCTION
	ResourceID       string                 `json:"resource_id"`
	ResourceARN      string                 `json:"resource_arn"`
	ResourceTags     map[string]string      `json:"resource_tags,omitempty"`
	
	// EC2 specific
	InstanceID       string                 `json:"instance_id,omitempty"`
	InstanceType     string                 `json:"instance_type,omitempty"`
	Platform         string                 `json:"platform,omitempty"`
	
	// ECR specific
	ImageDigest      string                 `json:"image_digest,omitempty"`
	ImageRepository  string                 `json:"image_repository,omitempty"`
	ImageTags        []string               `json:"image_tags,omitempty"`
	
	// Lambda specific
	FunctionName     string                 `json:"function_name,omitempty"`
	Runtime          string                 `json:"runtime,omitempty"`
	
	// Package vulnerability details
	VulnerablePackage string                `json:"vulnerable_package,omitempty"`
	PackageVersion    string                `json:"package_version,omitempty"`
	FixedVersion      string                `json:"fixed_version,omitempty"`
	PackageManager    string                `json:"package_manager,omitempty"`
	
	// Network reachability details
	NetworkPath       []string              `json:"network_path,omitempty"`
	OpenPortRange     string                `json:"open_port_range,omitempty"`
	Protocol          string                `json:"protocol,omitempty"`
	
	// Metadata
	AccountID         string                `json:"account_id"`
	Region            string                `json:"region"`
	FirstObservedAt   time.Time             `json:"first_observed_at"`
	LastObservedAt    time.Time             `json:"last_observed_at"`
	UpdatedAt         time.Time             `json:"updated_at"`
	
	// SIEM metadata
	Timestamp         time.Time             `json:"timestamp"`
	Source            string                `json:"source"`
	IndexedAt         time.Time             `json:"indexed_at"`
}

// InspectorCollector collects findings from AWS Inspector
type InspectorCollector struct {
	client     *inspector2.Inspector2
	opensearch *opensearch.Client
	region     string
	mu         sync.RWMutex
	lastRun    time.Time
	findings   map[string]*InspectorFinding
}

var (
	inspectorCollector     *InspectorCollector
	inspectorCollectorOnce sync.Once
)

// InitInspectorCollector initializes the AWS Inspector collector
func InitInspectorCollector(region string, osClient *opensearch.Client) (*InspectorCollector, error) {
	var initErr error
	inspectorCollectorOnce.Do(func() {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(region),
		})
		if err != nil {
			initErr = fmt.Errorf("failed to create AWS session: %v", err)
			return
		}

		inspectorCollector = &InspectorCollector{
			client:     inspector2.New(sess),
			opensearch: osClient,
			region:     region,
			findings:   make(map[string]*InspectorFinding),
		}

		log.Printf("✅ AWS Inspector Collector initialized for region: %s", region)
	})

	return inspectorCollector, initErr
}

// GetInspectorCollector returns the singleton instance
func GetInspectorCollector() *InspectorCollector {
	return inspectorCollector
}

// CollectFindings fetches all findings from AWS Inspector
func (ic *InspectorCollector) CollectFindings(ctx context.Context) ([]*InspectorFinding, error) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	log.Println("🔍 Collecting findings from AWS Inspector...")

	var allFindings []*InspectorFinding
	var nextToken *string

	// Filter for active findings
	filterCriteria := &inspector2.FilterCriteria{
		FindingStatus: []*inspector2.StringFilter{
			{
				Comparison: aws.String("EQUALS"),
				Value:      aws.String("ACTIVE"),
			},
		},
	}

	for {
		input := &inspector2.ListFindingsInput{
			FilterCriteria: filterCriteria,
			MaxResults:     aws.Int64(100),
			NextToken:      nextToken,
		}

		output, err := ic.client.ListFindingsWithContext(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list findings: %v", err)
		}

		for _, finding := range output.Findings {
			inspFinding := ic.convertFinding(finding)
			allFindings = append(allFindings, inspFinding)
			ic.findings[inspFinding.ID] = inspFinding
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	ic.lastRun = time.Now()
	log.Printf("✅ Collected %d findings from AWS Inspector", len(allFindings))

	return allFindings, nil
}

// convertFinding converts an AWS Inspector finding to our internal format
func (ic *InspectorCollector) convertFinding(finding *inspector2.Finding) *InspectorFinding {
	f := &InspectorFinding{
		ID:          aws.StringValue(finding.FindingArn),
		FindingARN:  aws.StringValue(finding.FindingArn),
		Type:        aws.StringValue(finding.Type),
		Title:       aws.StringValue(finding.Title),
		Description: aws.StringValue(finding.Description),
		Severity:    aws.StringValue(finding.Severity),
		Status:      aws.StringValue(finding.Status),
		AccountID:   aws.StringValue(finding.AwsAccountId),
		Region:      ic.region,
		Timestamp:   time.Now(),
		Source:      "AWS Inspector",
		IndexedAt:   time.Now(),
	}

	// Parse timestamps
	if finding.FirstObservedAt != nil {
		f.FirstObservedAt = *finding.FirstObservedAt
	}
	if finding.LastObservedAt != nil {
		f.LastObservedAt = *finding.LastObservedAt
	}
	if finding.UpdatedAt != nil {
		f.UpdatedAt = *finding.UpdatedAt
	}

	// Extract CVSS information
	if finding.InspectorScore != nil {
		f.CVSSScore = *finding.InspectorScore
	}
	if finding.InspectorScoreDetails != nil && finding.InspectorScoreDetails.AdjustedCvss != nil {
		f.CVSSVector = aws.StringValue(finding.InspectorScoreDetails.AdjustedCvss.ScoringVector)
	}

	// Extract resource information
	if finding.Resources != nil && len(finding.Resources) > 0 {
		resource := finding.Resources[0]
		f.ResourceType = aws.StringValue(resource.Type)
		f.ResourceID = aws.StringValue(resource.Id)

		// Extract tags
		if resource.Tags != nil {
			f.ResourceTags = make(map[string]string)
			for k, v := range resource.Tags {
				f.ResourceTags[k] = aws.StringValue(v)
			}
		}

		// EC2 specific details - use resource ID as instance ID
		if resource.Type != nil && *resource.Type == "AWS_EC2_INSTANCE" {
			// Resource ID for EC2 is typically the instance ID
			f.InstanceID = f.ResourceID
			f.ResourceARN = fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", 
				ic.region, f.AccountID, f.InstanceID)
			
			// Try to extract platform from tags
			if resource.Tags != nil {
				if platform, ok := resource.Tags["Platform"]; ok {
					f.Platform = aws.StringValue(platform)
				}
			}
		}

		// ECR specific details
		if resource.Type != nil && *resource.Type == "AWS_ECR_CONTAINER_IMAGE" {
			// Parse repository and digest from resource ID
			// Format: repository:digest or repository@sha256:...
			if strings.Contains(f.ResourceID, "@") {
				parts := strings.Split(f.ResourceID, "@")
				f.ImageRepository = parts[0]
				if len(parts) > 1 {
					f.ImageDigest = parts[1]
				}
			} else if strings.Contains(f.ResourceID, ":") {
				parts := strings.Split(f.ResourceID, ":")
				f.ImageRepository = parts[0]
			}
		}

		// Lambda specific details
		if resource.Type != nil && *resource.Type == "AWS_LAMBDA_FUNCTION" {
			// Resource ID for Lambda is typically the function name or ARN
			if strings.HasPrefix(f.ResourceID, "arn:") {
				f.ResourceARN = f.ResourceID
				// Extract function name from ARN
				parts := strings.Split(f.ResourceID, ":")
				if len(parts) > 0 {
					f.FunctionName = parts[len(parts)-1]
				}
			} else {
				f.FunctionName = f.ResourceID
			}
		}
	}

	// Package vulnerability details
	if finding.PackageVulnerabilityDetails != nil {
		pvd := finding.PackageVulnerabilityDetails
		
		// Get CVE ID
		if pvd.VulnerabilityId != nil {
			f.CVEID = aws.StringValue(pvd.VulnerabilityId)
		}

		// Get vulnerable packages
		if pvd.VulnerablePackages != nil && len(pvd.VulnerablePackages) > 0 {
			pkg := pvd.VulnerablePackages[0]
			f.VulnerablePackage = aws.StringValue(pkg.Name)
			f.PackageVersion = aws.StringValue(pkg.Version)
			f.FixedVersion = aws.StringValue(pkg.FixedInVersion)
			f.PackageManager = aws.StringValue(pkg.PackageManager)
			f.FixAvailable = pkg.FixedInVersion != nil && *pkg.FixedInVersion != ""
		}
	}

	// Network reachability details
	if finding.NetworkReachabilityDetails != nil {
		nrd := finding.NetworkReachabilityDetails
		if nrd.NetworkPath != nil && nrd.NetworkPath.Steps != nil {
			for _, step := range nrd.NetworkPath.Steps {
				if step.ComponentId != nil {
					f.NetworkPath = append(f.NetworkPath, aws.StringValue(step.ComponentId))
				}
			}
		}
		if nrd.OpenPortRange != nil {
			f.OpenPortRange = fmt.Sprintf("%d-%d", 
				aws.Int64Value(nrd.OpenPortRange.Begin),
				aws.Int64Value(nrd.OpenPortRange.End))
		}
		f.Protocol = aws.StringValue(nrd.Protocol)
	}

	// Check for exploit availability
	if finding.ExploitAvailable != nil {
		f.ExploitAvailable = aws.StringValue(finding.ExploitAvailable) == "YES"
	}

	// Generate a shorter ID for UI
	if f.FindingARN != "" {
		parts := strings.Split(f.FindingARN, "/")
		if len(parts) > 0 {
			f.ID = parts[len(parts)-1]
		}
	}

	return f
}

// IndexFindings indexes findings into OpenSearch
func (ic *InspectorCollector) IndexFindings(ctx context.Context, findings []*InspectorFinding) error {
	if ic.opensearch == nil {
		return fmt.Errorf("OpenSearch client not initialized")
	}

	log.Printf("📦 Indexing %d Inspector findings to OpenSearch...", len(findings))

	indexName := "siem-vulnerabilities"
	indexed := 0

	for _, finding := range findings {
		docID := finding.ID
		
		docJSON, err := json.Marshal(finding)
		if err != nil {
			log.Printf("⚠️ Failed to marshal finding %s: %v", docID, err)
			continue
		}

		res, err := ic.opensearch.Index(
			indexName,
			strings.NewReader(string(docJSON)),
			ic.opensearch.Index.WithDocumentID(docID),
			ic.opensearch.Index.WithRefresh("false"),
		)
		if err != nil {
			log.Printf("⚠️ Failed to index finding %s: %v", docID, err)
			continue
		}
		res.Body.Close()

		if res.IsError() {
			log.Printf("⚠️ OpenSearch error for finding %s: %s", docID, res.String())
			continue
		}

		indexed++
	}

	log.Printf("✅ Indexed %d/%d Inspector findings", indexed, len(findings))
	return nil
}

// GetFindingsByResource gets all findings for a specific resource
func (ic *InspectorCollector) GetFindingsByResource(resourceID string) []*InspectorFinding {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	var results []*InspectorFinding
	for _, finding := range ic.findings {
		if finding.ResourceID == resourceID || finding.InstanceID == resourceID {
			results = append(results, finding)
		}
	}
	return results
}

// GetFindingsBySeverity gets all findings of a specific severity
func (ic *InspectorCollector) GetFindingsBySeverity(severity string) []*InspectorFinding {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	var results []*InspectorFinding
	for _, finding := range ic.findings {
		if strings.EqualFold(finding.Severity, severity) {
			results = append(results, finding)
		}
	}
	return results
}

// GetStatistics returns vulnerability statistics
func (ic *InspectorCollector) GetStatistics() map[string]interface{} {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	stats := map[string]int{
		"total":        0,
		"critical":     0,
		"high":         0,
		"medium":       0,
		"low":          0,
		"informational": 0,
		"with_fix":     0,
		"exploitable":  0,
	}

	resourceSet := make(map[string]bool)

	for _, finding := range ic.findings {
		stats["total"]++
		
		switch strings.ToUpper(finding.Severity) {
		case "CRITICAL":
			stats["critical"]++
		case "HIGH":
			stats["high"]++
		case "MEDIUM":
			stats["medium"]++
		case "LOW":
			stats["low"]++
		case "INFORMATIONAL":
			stats["informational"]++
		}

		if finding.FixAvailable {
			stats["with_fix"]++
		}
		if finding.ExploitAvailable {
			stats["exploitable"]++
		}

		if finding.ResourceID != "" {
			resourceSet[finding.ResourceID] = true
		}
	}

	return map[string]interface{}{
		"counts":           stats,
		"affected_resources": len(resourceSet),
		"last_scan":        ic.lastRun,
	}
}

// ============================================================================
// OPENSEARCH INDEX MANAGEMENT
// ============================================================================

// EnsureVulnerabilitiesIndex creates the vulnerabilities index if it doesn't exist
func (s *APIServer) EnsureVulnerabilitiesIndex() error {
	if s.opensearch == nil {
		return fmt.Errorf("OpenSearch client not initialized")
	}

	indexName := "siem-vulnerabilities"

	// Check if index exists
	res, err := s.opensearch.Indices.Exists([]string{indexName})
	if err != nil {
		return fmt.Errorf("failed to check index existence: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 200 {
		log.Printf("✅ Index %s already exists", indexName)
		return nil
	}

	// Create index with mapping
	mapping := `{
		"settings": {
			"number_of_shards": 2,
			"number_of_replicas": 1,
			"index": {
				"refresh_interval": "5s"
			}
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"finding_arn": { "type": "keyword" },
				"type": { "type": "keyword" },
				"title": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
				"description": { "type": "text" },
				"severity": { "type": "keyword" },
				"status": { "type": "keyword" },
				"cve_id": { "type": "keyword" },
				"cvss_score": { "type": "float" },
				"cvss_vector": { "type": "keyword" },
				"exploit_available": { "type": "boolean" },
				"fix_available": { "type": "boolean" },
				"resource_type": { "type": "keyword" },
				"resource_id": { "type": "keyword" },
				"resource_arn": { "type": "keyword" },
				"resource_tags": { "type": "object", "enabled": false },
				"instance_id": { "type": "keyword" },
				"instance_type": { "type": "keyword" },
				"platform": { "type": "keyword" },
				"image_digest": { "type": "keyword" },
				"image_repository": { "type": "keyword" },
				"image_tags": { "type": "keyword" },
				"function_name": { "type": "keyword" },
				"runtime": { "type": "keyword" },
				"vulnerable_package": { "type": "keyword" },
				"package_version": { "type": "keyword" },
				"fixed_version": { "type": "keyword" },
				"package_manager": { "type": "keyword" },
				"network_path": { "type": "keyword" },
				"open_port_range": { "type": "keyword" },
				"protocol": { "type": "keyword" },
				"account_id": { "type": "keyword" },
				"region": { "type": "keyword" },
				"first_observed_at": { "type": "date" },
				"last_observed_at": { "type": "date" },
				"updated_at": { "type": "date" },
				"timestamp": { "type": "date" },
				"source": { "type": "keyword" },
				"indexed_at": { "type": "date" }
			}
		}
	}`

	res, err = s.opensearch.Indices.Create(
		indexName,
		s.opensearch.Indices.Create.WithBody(strings.NewReader(mapping)),
	)
	if err != nil {
		return fmt.Errorf("failed to create index: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error creating index: %s", res.String())
	}

	log.Printf("✅ Created index %s", indexName)
	return nil
}

// ============================================================================
// BACKGROUND INDEXER
// ============================================================================

// StartInspectorIndexer starts the background Inspector indexer
func (s *APIServer) StartInspectorIndexer(intervalMinutes int) {
	go func() {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}

		collector, err := InitInspectorCollector(region, s.opensearch)
		if err != nil {
			log.Printf("❌ Failed to initialize Inspector collector: %v", err)
			return
		}

		// Ensure index exists
		if err := s.EnsureVulnerabilitiesIndex(); err != nil {
			log.Printf("⚠️ Failed to ensure vulnerabilities index: %v", err)
		}

		ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
		defer ticker.Stop()

		// Initial collection
		ctx := context.Background()
		findings, err := collector.CollectFindings(ctx)
		if err != nil {
			log.Printf("❌ Initial Inspector collection failed: %v", err)
		} else if len(findings) > 0 {
			if err := collector.IndexFindings(ctx, findings); err != nil {
				log.Printf("⚠️ Failed to index initial findings: %v", err)
			}
		}

		log.Printf("🔄 Inspector Indexer started - collecting every %d minutes", intervalMinutes)

		for range ticker.C {
			findings, err := collector.CollectFindings(ctx)
			if err != nil {
				log.Printf("❌ Inspector collection failed: %v", err)
				AddSystemLog("ERROR", "inspector", fmt.Sprintf("Collection failed: %v", err), nil)
				continue
			}

			if len(findings) > 0 {
				if err := collector.IndexFindings(ctx, findings); err != nil {
					log.Printf("⚠️ Failed to index findings: %v", err)
				}
			}

			AddSystemLog("INFO", "inspector", fmt.Sprintf("Collected %d findings", len(findings)), map[string]interface{}{
				"count": len(findings),
			})
		}
	}()
}

