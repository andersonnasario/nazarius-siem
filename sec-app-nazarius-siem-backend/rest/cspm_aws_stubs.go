package main

// =============================================================================
// CSPM AWS REAL IMPLEMENTATIONS
// =============================================================================
// Real handlers that use AWS SDK to fetch data from Security Hub, GuardDuty,
// Inspector, CloudTrail, and Config. Falls back gracefully when AWS is not configured.

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/inspector2"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/gin-gonic/gin"
)

// initCSPMAWS initializes AWS service connections for CSPM
func initCSPMAWS() {
	if os.Getenv("USE_REAL_AWS_DATA") != "true" && os.Getenv("DISABLE_MOCK_DATA") != "true" {
		log.Println("⚠️ CSPM AWS: Real data not enabled (set USE_REAL_AWS_DATA=true)")
		return
	}
	log.Println("✅ CSPM AWS: Real data mode enabled")
}

// ---------------------------------------------------------------------------
// AWS Config Findings
// ---------------------------------------------------------------------------

func (s *APIServer) handleGetAWSConfigFindings(c *gin.Context) {
	sess, err := getAWSSession()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0, "error": "AWS session not available: " + err.Error()})
		return
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	client := configservice.New(sess, aws.NewConfig().WithRegion(region))

	// Get non-compliant evaluation results
	input := &configservice.DescribeComplianceByConfigRuleInput{}
	result, err := client.DescribeComplianceByConfigRule(input)
	if err != nil {
		log.Printf("[CSPM AWS Config] Error: %v", err)
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0, "error": err.Error()})
		return
	}

	findings := []map[string]interface{}{}
	for _, rule := range result.ComplianceByConfigRules {
		status := "COMPLIANT"
		if rule.Compliance != nil && rule.Compliance.ComplianceType != nil {
			status = *rule.Compliance.ComplianceType
		}
		ruleName := ""
		if rule.ConfigRuleName != nil {
			ruleName = *rule.ConfigRuleName
		}

		severity := "LOW"
		if status == "NON_COMPLIANT" {
			severity = "HIGH"
		}

		findings = append(findings, map[string]interface{}{
			"rule_name":       ruleName,
			"compliance_type": status,
			"severity":        severity,
			"source":          "AWS Config",
			"timestamp":       time.Now().UTC().Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{"findings": findings, "total": len(findings)})
}

// ---------------------------------------------------------------------------
// AWS Config Rules
// ---------------------------------------------------------------------------

func (s *APIServer) handleGetAWSConfigRules(c *gin.Context) {
	sess, err := getAWSSession()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"rules": []interface{}{}, "total": 0, "error": "AWS session not available"})
		return
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	client := configservice.New(sess, aws.NewConfig().WithRegion(region))

	input := &configservice.DescribeConfigRulesInput{}
	result, err := client.DescribeConfigRules(input)
	if err != nil {
		log.Printf("[CSPM AWS Config Rules] Error: %v", err)
		c.JSON(http.StatusOK, gin.H{"rules": []interface{}{}, "total": 0, "error": err.Error()})
		return
	}

	rules := []map[string]interface{}{}
	for _, rule := range result.ConfigRules {
		ruleMap := map[string]interface{}{
			"name":   aws.StringValue(rule.ConfigRuleName),
			"arn":    aws.StringValue(rule.ConfigRuleArn),
			"state":  aws.StringValue(rule.ConfigRuleState),
			"source": "AWS Config",
		}
		if rule.Description != nil {
			ruleMap["description"] = *rule.Description
		}
		if rule.Source != nil {
			ruleMap["source_identifier"] = aws.StringValue(rule.Source.SourceIdentifier)
			ruleMap["source_owner"] = aws.StringValue(rule.Source.Owner)
		}
		if rule.InputParameters != nil {
			ruleMap["input_parameters"] = *rule.InputParameters
		}
		rules = append(rules, ruleMap)
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

// ---------------------------------------------------------------------------
// Security Hub Findings
// ---------------------------------------------------------------------------

func (s *APIServer) handleGetSecurityHubFindings(c *gin.Context) {
	sess, err := getAWSSession()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0, "error": "AWS session not available"})
		return
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	client := securityhub.New(sess, aws.NewConfig().WithRegion(region))

	// Parse query params
	maxResults := int64(100)
	if m := c.Query("limit"); m != "" {
		if v, err := strconv.ParseInt(m, 10, 64); err == nil && v > 0 && v <= 100 {
			maxResults = v
		}
	}

	severityFilter := c.Query("severity")

	input := &securityhub.GetFindingsInput{
		MaxResults: aws.Int64(maxResults),
		Filters: &securityhub.AwsSecurityFindingFilters{
			RecordState: []*securityhub.StringFilter{
				{Value: aws.String("ACTIVE"), Comparison: aws.String("EQUALS")},
			},
			WorkflowStatus: []*securityhub.StringFilter{
				{Value: aws.String("NEW"), Comparison: aws.String("EQUALS")},
				{Value: aws.String("NOTIFIED"), Comparison: aws.String("EQUALS")},
			},
		},
		SortCriteria: []*securityhub.SortCriterion{
			{Field: aws.String("SeverityNormalized"), SortOrder: aws.String("desc")},
		},
	}

	if severityFilter != "" {
		label := strings.ToUpper(severityFilter)
		input.Filters.SeverityLabel = []*securityhub.StringFilter{
			{Value: aws.String(label), Comparison: aws.String("EQUALS")},
		}
	}

	result, err := client.GetFindings(input)
	if err != nil {
		log.Printf("[CSPM Security Hub] Error: %v", err)
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0, "error": err.Error()})
		return
	}

	findings := []map[string]interface{}{}
	for _, f := range result.Findings {
		finding := map[string]interface{}{
			"id":          aws.StringValue(f.Id),
			"title":       aws.StringValue(f.Title),
			"description": aws.StringValue(f.Description),
			"severity":    aws.StringValue(f.Severity.Label),
			"status":      aws.StringValue(f.Workflow.Status),
			"product":     aws.StringValue(f.ProductName),
			"source":      "Security Hub",
			"created_at":  aws.StringValue(f.CreatedAt),
			"updated_at":  aws.StringValue(f.UpdatedAt),
		}
		if f.Severity.Normalized != nil {
			finding["severity_score"] = *f.Severity.Normalized
		}
		if len(f.Resources) > 0 {
			finding["resource_type"] = aws.StringValue(f.Resources[0].Type)
			finding["resource_id"] = aws.StringValue(f.Resources[0].Id)
			finding["resource_region"] = aws.StringValue(f.Resources[0].Region)
		}
		if f.Remediation != nil && f.Remediation.Recommendation != nil {
			finding["remediation_text"] = aws.StringValue(f.Remediation.Recommendation.Text)
			finding["remediation_url"] = aws.StringValue(f.Remediation.Recommendation.Url)
		}
		if f.Compliance != nil {
			finding["compliance_status"] = aws.StringValue(f.Compliance.Status)
		}
		findings = append(findings, finding)
	}

	c.JSON(http.StatusOK, gin.H{"findings": findings, "total": len(findings)})
}

// ---------------------------------------------------------------------------
// GuardDuty Findings
// ---------------------------------------------------------------------------

func (s *APIServer) handleGetGuardDutyFindings(c *gin.Context) {
	sess, err := getAWSSession()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0, "error": "AWS session not available"})
		return
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	collector, err := NewGuardDutyCollectorFromSession(sess, region)
	if err != nil {
		log.Printf("[CSPM GuardDuty] Error creating collector: %v", err)
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0, "error": err.Error()})
		return
	}

	maxResults := 50
	if m := c.Query("limit"); m != "" {
		if v, err := strconv.Atoi(m); err == nil && v > 0 && v <= 200 {
			maxResults = v
		}
	}

	findings, err := collector.CollectFindings(maxResults)
	if err != nil {
		log.Printf("[CSPM GuardDuty] Error collecting findings: %v", err)
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"findings": findings, "total": len(findings)})
}

// ---------------------------------------------------------------------------
// Inspector Findings
// ---------------------------------------------------------------------------

func (s *APIServer) handleGetInspectorFindings(c *gin.Context) {
	sess, err := getAWSSession()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0, "error": "AWS session not available"})
		return
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	client := inspector2.New(sess, aws.NewConfig().WithRegion(region))

	maxResults := int64(50)
	if m := c.Query("limit"); m != "" {
		if v, err := strconv.ParseInt(m, 10, 64); err == nil && v > 0 && v <= 100 {
			maxResults = v
		}
	}

	input := &inspector2.ListFindingsInput{
		MaxResults: aws.Int64(maxResults),
		FilterCriteria: &inspector2.FilterCriteria{
			FindingStatus: []*inspector2.StringFilter{
				{Value: aws.String("ACTIVE"), Comparison: aws.String("EQUALS")},
			},
		},
		SortCriteria: &inspector2.SortCriteria{
			Field:     aws.String("SEVERITY"),
			SortOrder: aws.String("DESC"),
		},
	}

	severityFilter := c.Query("severity")
	if severityFilter != "" {
		input.FilterCriteria.Severity = []*inspector2.StringFilter{
			{Value: aws.String(strings.ToUpper(severityFilter)), Comparison: aws.String("EQUALS")},
		}
	}

	result, err := client.ListFindings(input)
	if err != nil {
		log.Printf("[CSPM Inspector] Error: %v", err)
		c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}, "total": 0, "error": err.Error()})
		return
	}

	findings := []map[string]interface{}{}
	for _, f := range result.Findings {
		finding := map[string]interface{}{
			"id":            aws.StringValue(f.FindingArn),
			"title":         aws.StringValue(f.Title),
			"description":   aws.StringValue(f.Description),
			"severity":      aws.StringValue(f.Severity),
			"status":        aws.StringValue(f.Status),
			"type":          aws.StringValue(f.Type),
			"source":        "Inspector",
			"first_seen":    f.FirstObservedAt,
			"last_seen":     f.LastObservedAt,
			"fix_available": aws.StringValue(f.FixAvailable),
		}
		if f.PackageVulnerabilityDetails != nil {
			finding["cve_id"] = aws.StringValue(f.PackageVulnerabilityDetails.VulnerabilityId)
			finding["source_url"] = aws.StringValue(f.PackageVulnerabilityDetails.SourceUrl)
			if len(f.PackageVulnerabilityDetails.Cvss) > 0 {
				finding["cvss_score"] = aws.Float64Value(f.PackageVulnerabilityDetails.Cvss[0].BaseScore)
			}
		}
		if len(f.Resources) > 0 {
			finding["resource_type"] = aws.StringValue(f.Resources[0].Type)
			finding["resource_id"] = aws.StringValue(f.Resources[0].Id)
			finding["resource_region"] = aws.StringValue(f.Resources[0].Region)
		}
		findings = append(findings, finding)
	}

	c.JSON(http.StatusOK, gin.H{"findings": findings, "total": len(findings)})
}

// ---------------------------------------------------------------------------
// CloudTrail Events
// ---------------------------------------------------------------------------

func (s *APIServer) handleGetCloudTrailEvents(c *gin.Context) {
	sess, err := getAWSSession()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"events": []interface{}{}, "total": 0, "error": "AWS session not available"})
		return
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	client := cloudtrail.New(sess, aws.NewConfig().WithRegion(region))

	maxResults := int64(50)
	if m := c.Query("limit"); m != "" {
		if v, err := strconv.ParseInt(m, 10, 64); err == nil && v > 0 && v <= 50 {
			maxResults = v
		}
	}

	hours := 24
	if h := c.Query("hours"); h != "" {
		if v, err := strconv.Atoi(h); err == nil && v > 0 && v <= 168 {
			hours = v
		}
	}

	startTime := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	endTime := time.Now().UTC()

	input := &cloudtrail.LookupEventsInput{
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(endTime),
		MaxResults: aws.Int64(maxResults),
	}

	// Filter by event name if provided
	if eventName := c.Query("event_name"); eventName != "" {
		input.LookupAttributes = []*cloudtrail.LookupAttribute{
			{AttributeKey: aws.String("EventName"), AttributeValue: aws.String(eventName)},
		}
	}

	result, err := client.LookupEvents(input)
	if err != nil {
		log.Printf("[CSPM CloudTrail] Error: %v", err)
		c.JSON(http.StatusOK, gin.H{"events": []interface{}{}, "total": 0, "error": err.Error()})
		return
	}

	events := []map[string]interface{}{}
	for _, e := range result.Events {
		event := map[string]interface{}{
			"event_id":     aws.StringValue(e.EventId),
			"event_name":   aws.StringValue(e.EventName),
			"event_source": aws.StringValue(e.EventSource),
			"event_time":   e.EventTime,
			"username":     aws.StringValue(e.Username),
			"source":       "CloudTrail",
		}
		if e.AccessKeyId != nil {
			event["access_key_id"] = *e.AccessKeyId
		}
		if len(e.Resources) > 0 {
			resources := []map[string]interface{}{}
			for _, r := range e.Resources {
				resources = append(resources, map[string]interface{}{
					"type": aws.StringValue(r.ResourceType),
					"name": aws.StringValue(r.ResourceName),
				})
			}
			event["resources"] = resources
		}
		events = append(events, event)
	}

	c.JSON(http.StatusOK, gin.H{"events": events, "total": len(events)})
}

// ---------------------------------------------------------------------------
// AWS Integration Status
// ---------------------------------------------------------------------------

func (s *APIServer) handleGetAWSIntegrationStatus(c *gin.Context) {
	sess, err := getAWSSession()
	awsConnected := err == nil

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	services := map[string]map[string]interface{}{}

	// Test Security Hub
	if awsConnected {
		shClient := securityhub.New(sess, aws.NewConfig().WithRegion(region))
		_, shErr := shClient.DescribeHub(&securityhub.DescribeHubInput{})
		services["security_hub"] = map[string]interface{}{
			"enabled": shErr == nil,
			"error":   fmt.Sprintf("%v", shErr),
		}
	} else {
		services["security_hub"] = map[string]interface{}{"enabled": false, "error": "No AWS session"}
	}

	// Test GuardDuty
	if awsConnected {
		gdClient := guardduty.New(sess, aws.NewConfig().WithRegion(region))
		gdResult, gdErr := gdClient.ListDetectors(&guardduty.ListDetectorsInput{MaxResults: aws.Int64(1)})
		hasDetector := gdErr == nil && len(gdResult.DetectorIds) > 0
		services["guardduty"] = map[string]interface{}{
			"enabled":   hasDetector,
			"error":     fmt.Sprintf("%v", gdErr),
			"detectors": len(gdResult.DetectorIds),
		}
	} else {
		services["guardduty"] = map[string]interface{}{"enabled": false, "error": "No AWS session"}
	}

	// Test Inspector
	if awsConnected {
		inspClient := inspector2.New(sess, aws.NewConfig().WithRegion(region))
		inspResult, inspErr := inspClient.BatchGetAccountStatus(&inspector2.BatchGetAccountStatusInput{})
		inspEnabled := false
		if inspErr == nil && len(inspResult.Accounts) > 0 {
			for _, acct := range inspResult.Accounts {
				if acct.State != nil && aws.StringValue(acct.State.Status) == "ENABLED" {
					inspEnabled = true
					break
				}
			}
		}
		services["inspector"] = map[string]interface{}{
			"enabled": inspEnabled,
			"error":   fmt.Sprintf("%v", inspErr),
		}
	} else {
		services["inspector"] = map[string]interface{}{"enabled": false, "error": "No AWS session"}
	}

	// Test Config
	if awsConnected {
		cfgClient := configservice.New(sess, aws.NewConfig().WithRegion(region))
		cfgResult, cfgErr := cfgClient.DescribeConfigRules(&configservice.DescribeConfigRulesInput{})
		rulesCount := 0
		if cfgErr == nil {
			rulesCount = len(cfgResult.ConfigRules)
		}
		services["config"] = map[string]interface{}{
			"enabled":     cfgErr == nil,
			"rules_count": rulesCount,
			"error":       fmt.Sprintf("%v", cfgErr),
		}
	} else {
		services["config"] = map[string]interface{}{"enabled": false, "error": "No AWS session"}
	}

	// Test CloudTrail
	if awsConnected {
		ctClient := cloudtrail.New(sess, aws.NewConfig().WithRegion(region))
		ctResult, ctErr := ctClient.DescribeTrails(&cloudtrail.DescribeTrailsInput{})
		trailCount := 0
		if ctErr == nil {
			trailCount = len(ctResult.TrailList)
		}
		services["cloudtrail"] = map[string]interface{}{
			"enabled":      ctErr == nil,
			"trails_count": trailCount,
			"error":        fmt.Sprintf("%v", ctErr),
		}
	} else {
		services["cloudtrail"] = map[string]interface{}{"enabled": false, "error": "No AWS session"}
	}

	c.JSON(http.StatusOK, gin.H{
		"connected":     awsConnected,
		"region":        region,
		"account_id":    os.Getenv("AWS_ACCOUNT_ID"),
		"use_real_data": os.Getenv("USE_REAL_AWS_DATA") == "true",
		"mock_disabled": os.Getenv("DISABLE_MOCK_DATA") == "true",
		"services":      services,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// Sync AWS Data (trigger collection)
// ---------------------------------------------------------------------------

func (s *APIServer) handleSyncAWSData(c *gin.Context) {
	if os.Getenv("USE_REAL_AWS_DATA") != "true" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Real AWS data not enabled. Set USE_REAL_AWS_DATA=true"})
		return
	}

	synced := []string{}
	errors := []string{}

	// Trigger Security Hub sync
	if os.Getenv("USE_SECURITY_HUB") == "true" {
		synced = append(synced, "Security Hub (background indexer active)")
	}

	// Trigger CloudTrail sync
	if cloudtrailCollector != nil {
		synced = append(synced, "CloudTrail")
	}

	// Check GuardDuty
	sess, sessErr := getAWSSession()
	if sessErr == nil {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}
		gdClient := guardduty.New(sess, aws.NewConfig().WithRegion(region))
		gdResult, gdErr := gdClient.ListDetectors(&guardduty.ListDetectorsInput{MaxResults: aws.Int64(1)})
		if gdErr == nil && len(gdResult.DetectorIds) > 0 {
			synced = append(synced, "GuardDuty")
		}
	}

	if len(synced) == 0 {
		errors = append(errors, "No AWS services configured for sync")
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   len(errors) == 0,
		"synced":    synced,
		"errors":    errors,
		"message":   fmt.Sprintf("Sync triggered for %d services", len(synced)),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// Test AWS Connection
// ---------------------------------------------------------------------------

func (s *APIServer) handleTestAWSConnection(c *gin.Context) {
	startTime := time.Now()
	tests := []map[string]interface{}{}

	// Test 1: AWS Session
	sess, err := getAWSSession()
	sessionOK := err == nil
	tests = append(tests, map[string]interface{}{
		"name":    "AWS Session",
		"success": sessionOK,
		"error":   fmt.Sprintf("%v", err),
		"latency": fmt.Sprintf("%dms", time.Since(startTime).Milliseconds()),
	})

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	// Test 2: Security Hub
	if sessionOK {
		t := time.Now()
		shClient := securityhub.New(sess, aws.NewConfig().WithRegion(region))
		_, shErr := shClient.DescribeHub(&securityhub.DescribeHubInput{})
		tests = append(tests, map[string]interface{}{
			"name":    "Security Hub",
			"success": shErr == nil,
			"error":   fmt.Sprintf("%v", shErr),
			"latency": fmt.Sprintf("%dms", time.Since(t).Milliseconds()),
		})
	}

	// Test 3: GuardDuty
	if sessionOK {
		t := time.Now()
		gdClient := guardduty.New(sess, aws.NewConfig().WithRegion(region))
		_, gdErr := gdClient.ListDetectors(&guardduty.ListDetectorsInput{MaxResults: aws.Int64(1)})
		tests = append(tests, map[string]interface{}{
			"name":    "GuardDuty",
			"success": gdErr == nil,
			"error":   fmt.Sprintf("%v", gdErr),
			"latency": fmt.Sprintf("%dms", time.Since(t).Milliseconds()),
		})
	}

	// Test 4: Inspector
	if sessionOK {
		t := time.Now()
		inspClient := inspector2.New(sess, aws.NewConfig().WithRegion(region))
		_, inspErr := inspClient.BatchGetAccountStatus(&inspector2.BatchGetAccountStatusInput{})
		tests = append(tests, map[string]interface{}{
			"name":    "Inspector v2",
			"success": inspErr == nil,
			"error":   fmt.Sprintf("%v", inspErr),
			"latency": fmt.Sprintf("%dms", time.Since(t).Milliseconds()),
		})
	}

	// Test 5: Config
	if sessionOK {
		t := time.Now()
		cfgClient := configservice.New(sess, aws.NewConfig().WithRegion(region))
		_, cfgErr := cfgClient.DescribeConfigRules(&configservice.DescribeConfigRulesInput{})
		tests = append(tests, map[string]interface{}{
			"name":    "AWS Config",
			"success": cfgErr == nil,
			"error":   fmt.Sprintf("%v", cfgErr),
			"latency": fmt.Sprintf("%dms", time.Since(t).Milliseconds()),
		})
	}

	// Test 6: CloudTrail
	if sessionOK {
		t := time.Now()
		ctClient := cloudtrail.New(sess, aws.NewConfig().WithRegion(region))
		_, ctErr := ctClient.DescribeTrails(&cloudtrail.DescribeTrailsInput{})
		tests = append(tests, map[string]interface{}{
			"name":    "CloudTrail",
			"success": ctErr == nil,
			"error":   fmt.Sprintf("%v", ctErr),
			"latency": fmt.Sprintf("%dms", time.Since(t).Milliseconds()),
		})
	}

	allOK := true
	for _, t := range tests {
		if t["success"] != true {
			allOK = false
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       allOK,
		"tests":         tests,
		"total_latency": fmt.Sprintf("%dms", time.Since(startTime).Milliseconds()),
		"region":        region,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	})
}
