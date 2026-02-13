package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// ============================================================================
// AWS EVENTS INDEXER
// ============================================================================
// This module indexes CloudTrail and GuardDuty events into OpenSearch
// so they appear in the Events page and dashboards.

// IndexCloudTrailEvents indexes CloudTrail events into OpenSearch
func (s *APIServer) IndexCloudTrailEvents(events []CloudTrailEvent) error {
	if s.opensearch == nil {
		log.Printf("⚠️ OpenSearch not available, skipping CloudTrail indexing")
		return fmt.Errorf("opensearch not available")
	}

	if len(events) == 0 {
		log.Printf("📭 No CloudTrail events to index")
		return nil
	}

	log.Printf("📤 Indexing %d CloudTrail events into OpenSearch...", len(events))
	
	indexed := 0
	errors := 0

	for _, event := range events {
		// Convert CloudTrail event to SIEM event format
		siemEvent := s.convertCloudTrailToSIEMEvent(event)
		
		// Index into OpenSearch
		if err := s.indexEvent(siemEvent); err != nil {
			log.Printf("❌ Failed to index CloudTrail event %s: %v", event.EventID, err)
			errors++
			continue
		}
		indexed++
	}

	log.Printf("✅ Indexed %d CloudTrail events (%d errors)", indexed, errors)
	AddSystemLog("INFO", "aws-indexer", fmt.Sprintf("✅ Indexed %d CloudTrail events", indexed), map[string]interface{}{
		"total":   len(events),
		"indexed": indexed,
		"errors":  errors,
	})

	return nil
}

// IndexGuardDutyFindings indexes GuardDuty findings into OpenSearch
func (s *APIServer) IndexGuardDutyFindings(findings []GuardDutyFinding) error {
	if s.opensearch == nil {
		log.Printf("⚠️ OpenSearch not available, skipping GuardDuty indexing")
		return fmt.Errorf("opensearch not available")
	}

	if len(findings) == 0 {
		log.Printf("📭 No GuardDuty findings to index")
		return nil
	}

	log.Printf("📤 Indexing %d GuardDuty findings into OpenSearch...", len(findings))
	
	indexed := 0
	errors := 0

	for _, finding := range findings {
		// Convert GuardDuty finding to SIEM event format
		siemEvent := s.convertGuardDutyToSIEMEvent(finding)
		
		// Index into OpenSearch
		if err := s.indexEvent(siemEvent); err != nil {
			log.Printf("❌ Failed to index GuardDuty finding %s: %v", finding.ID, err)
			errors++
			continue
		}
		indexed++
	}

	log.Printf("✅ Indexed %d GuardDuty findings (%d errors)", indexed, errors)
	AddSystemLog("INFO", "aws-indexer", fmt.Sprintf("✅ Indexed %d GuardDuty findings", indexed), map[string]interface{}{
		"total":   len(findings),
		"indexed": indexed,
		"errors":  errors,
	})

	return nil
}

// convertCloudTrailToSIEMEvent converts a CloudTrail event to SIEM Event format
func (s *APIServer) convertCloudTrailToSIEMEvent(ct CloudTrailEvent) Event {
	// Determine severity based on event type
	severity := determineSeverityFromCloudTrail(ct)
	
	// Build description
	description := fmt.Sprintf("AWS CloudTrail: %s from %s", ct.EventName, ct.EventSource)
	if ct.ErrorCode != "" {
		description = fmt.Sprintf("%s (Error: %s)", description, ct.ErrorCode)
	}

	// Extract user info
	userName := "unknown"
	if ct.UserIdentity.UserName != "" {
		userName = ct.UserIdentity.UserName
	} else if ct.UserIdentity.ARN != "" {
		parts := strings.Split(ct.UserIdentity.ARN, "/")
		if len(parts) > 0 {
			userName = parts[len(parts)-1]
		}
	}

	return Event{
		ID:          fmt.Sprintf("cloudtrail-%s", ct.EventID),
		Timestamp:   ct.EventTime,
		Source:      "AWS CloudTrail",
		Type:        categorizeCloudTrailEvent(ct.EventName),
		Severity:    severity,
		Description: description,
		User:        userName, // Top-level user field for UEBA
		SourceIP:    ct.SourceIPAddress, // Top-level source_ip for analytics
		Details: map[string]interface{}{
			"event_id":           ct.EventID,
			"event_name":         ct.EventName,
			"event_source":       ct.EventSource,
			"aws_region":         ct.AwsRegion,
			"source_ip":          ct.SourceIPAddress,
			"user_agent":         ct.UserAgent,
			"user_name":          userName,
			"user_type":          ct.UserIdentity.Type,
			"user_arn":           ct.UserIdentity.ARN,
			"account_id":         ct.UserIdentity.AccountID,
			"error_code":         ct.ErrorCode,
			"error_message":      ct.ErrorMessage,
			"request_parameters": ct.RequestParameters,
			"response_elements":  ct.ResponseElements,
		},
		Tags: []string{"aws", "cloudtrail", ct.EventSource},
	}
}

// convertGuardDutyToSIEMEvent converts a GuardDuty finding to SIEM Event format
func (s *APIServer) convertGuardDutyToSIEMEvent(gd GuardDutyFinding) Event {
	// Extract user and sourceIP from GuardDuty finding if available
	user := extractGuardDutyUser(gd)
	sourceIP := extractGuardDutySourceIP(gd)

	return Event{
		ID:          fmt.Sprintf("guardduty-%s", gd.ID),
		Timestamp:   gd.CreatedAt,
		Source:      "AWS GuardDuty",
		Type:        gd.Type,
		Severity:    mapGuardDutySeverity(gd.Severity),
		Description: gd.Description,
		User:        user,     // Top-level user for UEBA
		SourceIP:    sourceIP, // Top-level source_ip for analytics
		Details: map[string]interface{}{
			"finding_id":     gd.ID,
			"type":           gd.Type,
			"title":          gd.Title,
			"description":    gd.Description,
			"severity":       gd.Severity,
			"aws_region":     gd.Region,
			"account_id":     gd.AccountID,
			"arn":            gd.ARN,
			"resource_type":  gd.Resource.ResourceType,
			"updated_at":     gd.UpdatedAt,
		},
		Tags: []string{"aws", "guardduty", "threat"},
	}
}

// extractGuardDutyUser extracts user from GuardDuty finding
func extractGuardDutyUser(gd GuardDutyFinding) string {
	// Try AccessKeyDetails
	if gd.Resource.AccessKeyDetails != nil {
		if userName, ok := gd.Resource.AccessKeyDetails["userName"].(string); ok && userName != "" {
			return userName
		}
		if principalId, ok := gd.Resource.AccessKeyDetails["principalId"].(string); ok && principalId != "" {
			return principalId
		}
	}
	// Try InstanceDetails for instance user
	if gd.Resource.InstanceDetails != nil {
		if iamProfile, ok := gd.Resource.InstanceDetails["iamInstanceProfile"].(map[string]interface{}); ok {
			if arn, ok := iamProfile["arn"].(string); ok {
				parts := strings.Split(arn, "/")
				if len(parts) > 0 {
					return parts[len(parts)-1]
				}
			}
		}
	}
	return ""
}

// extractGuardDutySourceIP extracts source IP from GuardDuty finding
func extractGuardDutySourceIP(gd GuardDutyFinding) string {
	if gd.Service.Action != nil {
		// Try NetworkConnectionAction
		if netAction, ok := gd.Service.Action["networkConnectionAction"].(map[string]interface{}); ok {
			if remoteIP, ok := netAction["remoteIpDetails"].(map[string]interface{}); ok {
				if ip, ok := remoteIP["ipAddressV4"].(string); ok {
					return ip
				}
			}
		}
		// Try AwsApiCallAction
		if apiAction, ok := gd.Service.Action["awsApiCallAction"].(map[string]interface{}); ok {
			if remoteIP, ok := apiAction["remoteIpDetails"].(map[string]interface{}); ok {
				if ip, ok := remoteIP["ipAddressV4"].(string); ok {
					return ip
				}
			}
		}
		// Try PortProbeAction
		if portAction, ok := gd.Service.Action["portProbeAction"].(map[string]interface{}); ok {
			if details, ok := portAction["portProbeDetails"].([]interface{}); ok && len(details) > 0 {
				if detail, ok := details[0].(map[string]interface{}); ok {
					if remoteIP, ok := detail["remoteIpDetails"].(map[string]interface{}); ok {
						if ip, ok := remoteIP["ipAddressV4"].(string); ok {
							return ip
						}
					}
				}
			}
		}
	}
	return ""
}

// indexEvent indexes a single event into OpenSearch
func (s *APIServer) indexEvent(event Event) error {
	// Serialize event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Index into OpenSearch
	res, err := s.opensearch.Index(
		"siem-events",
		bytes.NewReader(eventJSON),
		s.opensearch.Index.WithDocumentID(event.ID),
		s.opensearch.Index.WithRefresh("false"), // Don't wait for refresh
	)
	if err != nil {
		return fmt.Errorf("failed to index event: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("opensearch error: %s", res.String())
	}

	return nil
}

// determineSeverityFromCloudTrail determines severity based on CloudTrail event
func determineSeverityFromCloudTrail(ct CloudTrailEvent) string {
	// High severity events
	highSeverityEvents := map[string]bool{
		"ConsoleLogin":                   true,
		"CreateUser":                     true,
		"DeleteUser":                     true,
		"CreateAccessKey":                true,
		"DeleteAccessKey":                true,
		"AttachUserPolicy":               true,
		"AttachRolePolicy":               true,
		"PutBucketPolicy":                true,
		"DeleteBucketPolicy":             true,
		"AuthorizeSecurityGroupIngress":  true,
		"AuthorizeSecurityGroupEgress":   true,
		"CreateSecurityGroup":            true,
		"DeleteSecurityGroup":            true,
		"ModifyInstanceAttribute":        true,
		"StopInstances":                  true,
		"TerminateInstances":             true,
		"DeleteBucket":                   true,
		"PutBucketAcl":                   true,
	}

	// Critical if there's an error on sensitive operations
	if ct.ErrorCode != "" {
		if highSeverityEvents[ct.EventName] {
			return "HIGH"
		}
		return "MEDIUM"
	}

	// Check if it's a high severity event
	if highSeverityEvents[ct.EventName] {
		return "HIGH"
	}

	// Medium severity for IAM and security events
	if strings.Contains(ct.EventSource, "iam.") || 
	   strings.Contains(ct.EventSource, "sts.") ||
	   strings.Contains(ct.EventSource, "kms.") {
		return "MEDIUM"
	}

	// Low severity for read-only events
	if strings.HasPrefix(ct.EventName, "Get") || 
	   strings.HasPrefix(ct.EventName, "List") ||
	   strings.HasPrefix(ct.EventName, "Describe") {
		return "LOW"
	}

	return "INFO"
}

// categorizeCloudTrailEvent categorizes the event type
func categorizeCloudTrailEvent(eventName string) string {
	// Authentication events
	if strings.Contains(eventName, "Login") || 
	   strings.Contains(eventName, "Logout") ||
	   eventName == "AssumeRole" ||
	   eventName == "GetSessionToken" {
		return "Authentication"
	}

	// IAM events
	if strings.HasPrefix(eventName, "Create") && (strings.Contains(eventName, "User") || strings.Contains(eventName, "Role") || strings.Contains(eventName, "Policy")) {
		return "IAM Change"
	}
	if strings.HasPrefix(eventName, "Delete") && (strings.Contains(eventName, "User") || strings.Contains(eventName, "Role") || strings.Contains(eventName, "Policy")) {
		return "IAM Change"
	}
	if strings.HasPrefix(eventName, "Attach") || strings.HasPrefix(eventName, "Detach") {
		return "IAM Change"
	}

	// Security Group events
	if strings.Contains(eventName, "SecurityGroup") {
		return "Network Security"
	}

	// S3 events
	if strings.Contains(eventName, "Bucket") || strings.Contains(eventName, "Object") {
		return "Data Access"
	}

	// EC2 events
	if strings.Contains(eventName, "Instance") {
		return "Compute"
	}

	// KMS events
	if strings.Contains(eventName, "Key") || strings.Contains(eventName, "Encrypt") || strings.Contains(eventName, "Decrypt") {
		return "Encryption"
	}

	return "AWS Activity"
}

// mapGuardDutySeverity maps GuardDuty severity (0-10) to SIEM severity
func mapGuardDutySeverity(severity float64) string {
	if severity >= 7.0 {
		return "CRITICAL"
	} else if severity >= 4.0 {
		return "HIGH"
	} else if severity >= 2.0 {
		return "MEDIUM"
	} else if severity >= 1.0 {
		return "LOW"
	}
	return "INFO"
}

// StartAWSEventIndexer starts a background job to periodically index AWS events
func (s *APIServer) StartAWSEventIndexer(intervalMinutes int) {
	if intervalMinutes <= 0 {
		intervalMinutes = 5 // Default 5 minutes
	}

	go func() {
		ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
		defer ticker.Stop()

		// Index immediately on start
		s.indexAWSEvents()

		for range ticker.C {
			s.indexAWSEvents()
		}
	}()

	log.Printf("🔄 AWS Event Indexer started (interval: %d minutes)", intervalMinutes)
	AddSystemLog("INFO", "aws-indexer", fmt.Sprintf("🔄 AWS Event Indexer started (interval: %d min)", intervalMinutes), nil)
}

// indexAWSEvents indexes all current AWS events
func (s *APIServer) indexAWSEvents() {
	awsConfigMutex.RLock()
	ctEvents := cloudTrailEvents
	gdFindings := guardDutyFindings
	awsConfigMutex.RUnlock()

	// Index CloudTrail events
	if len(ctEvents) > 0 {
		if err := s.IndexCloudTrailEvents(ctEvents); err != nil {
			log.Printf("❌ Failed to index CloudTrail events: %v", err)
		}
	}

	// Index GuardDuty findings
	if len(gdFindings) > 0 {
		if err := s.IndexGuardDutyFindings(gdFindings); err != nil {
			log.Printf("❌ Failed to index GuardDuty findings: %v", err)
		}
	}
}

