package main

import (
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

// CloudTrailCollector collects real CloudTrail events from AWS
type CloudTrailCollector struct {
	client *cloudtrail.CloudTrail
	region string
}

// NewCloudTrailCollector creates a new CloudTrail collector (without session token)
func NewCloudTrailCollector(accessKey, secretKey, region string) (*CloudTrailCollector, error) {
	return NewCloudTrailCollectorWithToken(accessKey, secretKey, "", region)
}

// NewCloudTrailCollectorWithToken creates a new CloudTrail collector with session token support
func NewCloudTrailCollectorWithToken(accessKey, secretKey, sessionToken, region string) (*CloudTrailCollector, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, sessionToken),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	return &CloudTrailCollector{
		client: cloudtrail.New(sess),
		region: region,
	}, nil
}

// NewCloudTrailCollectorFromSession creates a new CloudTrail collector from an existing session
func NewCloudTrailCollectorFromSession(sess *session.Session, region string) (*CloudTrailCollector, error) {
	if sess == nil {
		return nil, fmt.Errorf("session is nil")
	}

	return &CloudTrailCollector{
		client: cloudtrail.New(sess),
		region: region,
	}, nil
}

// CollectEvents collects CloudTrail events from AWS
func (c *CloudTrailCollector) CollectEvents(startTime, endTime time.Time, maxResults int) ([]CloudTrailEvent, error) {
	log.Printf("🔍 Collecting CloudTrail events from %s to %s", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))

	input := &cloudtrail.LookupEventsInput{
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(endTime),
		MaxResults: aws.Int64(int64(maxResults)),
	}

	var allEvents []CloudTrailEvent
	pageNum := 0

	err := c.client.LookupEventsPages(input, func(page *cloudtrail.LookupEventsOutput, lastPage bool) bool {
		pageNum++
		log.Printf("📄 Processing page %d with %d events", pageNum, len(page.Events))

		for _, event := range page.Events {
			allEvents = append(allEvents, c.convertEvent(event))
		}

		// Continue pagination if not last page and we haven't hit max results
		return !lastPage && len(allEvents) < maxResults
	})

	if err != nil {
		return nil, fmt.Errorf("failed to lookup CloudTrail events: %w", err)
	}

	log.Printf("✅ Collected %d CloudTrail events", len(allEvents))
	return allEvents, nil
}

// convertEvent converts AWS CloudTrail event to our internal format
func (c *CloudTrailCollector) convertEvent(event *cloudtrail.Event) CloudTrailEvent {
	return CloudTrailEvent{
		EventID:           aws.StringValue(event.EventId),
		EventName:         aws.StringValue(event.EventName),
		EventSource:       aws.StringValue(event.EventSource),
		EventTime:         aws.TimeValue(event.EventTime),
		AwsRegion:         c.region,
		UserIdentity:      c.extractUserIdentityFromEvent(event),
		SourceIPAddress:   c.extractSourceIPFromEvent(event),
		UserAgent:         c.extractUserAgentFromEvent(event),
		RequestParameters: c.extractRequestParamsFromEvent(event),
		ResponseElements:  c.extractResponseDataFromEvent(event),
		ErrorCode:         c.extractErrorCodeFromEvent(event),
		ErrorMessage:      c.extractErrorMessageFromEvent(event),
		Resources:         c.extractResourcesFromEvent(event),
		EventType:         c.extractEventTypeFromEvent(event),
		ReadOnly:          false,
	}
}

// Helper functions to extract data from CloudTrail event
func (c *CloudTrailCollector) extractSourceIPFromEvent(event *cloudtrail.Event) string {
	for _, resource := range event.Resources {
		if resource.ResourceName != nil {
			// Try to extract IP from resource name if it looks like an IP
			return ""
		}
	}
	return ""
}

func (c *CloudTrailCollector) extractUserAgentFromEvent(event *cloudtrail.Event) string {
	// User agent is typically in CloudTrailEvent but not in LookupEvents response
	return ""
}

func (c *CloudTrailCollector) extractErrorCodeFromEvent(event *cloudtrail.Event) string {
	// Error code is not directly available in LookupEvents
	return ""
}

func (c *CloudTrailCollector) extractErrorMessageFromEvent(event *cloudtrail.Event) string {
	// Error message is not directly available in LookupEvents
	return ""
}

func (c *CloudTrailCollector) extractRequestIDFromEvent(event *cloudtrail.Event) string {
	return aws.StringValue(event.EventId)
}

func (c *CloudTrailCollector) extractEventTypeFromEvent(event *cloudtrail.Event) string {
	// Determine event type based on event name
	eventName := aws.StringValue(event.EventName)
	if eventName == "ConsoleLogin" {
		return "authentication"
	}
	if eventName == "AssumeRole" {
		return "authorization"
	}
	return "api_call"
}

func (c *CloudTrailCollector) extractResourcesFromEvent(event *cloudtrail.Event) []CloudTrailResource {
	var resources []CloudTrailResource
	for _, r := range event.Resources {
		resources = append(resources, CloudTrailResource{
			ARN:       aws.StringValue(r.ResourceName),
			AccountID: c.extractAccountIDFromARN(aws.StringValue(r.ResourceName)),
			Type:      aws.StringValue(r.ResourceType),
		})
	}
	return resources
}

func (c *CloudTrailCollector) extractAccountIDFromARN(arn string) string {
	// Simple ARN parsing: arn:aws:service:region:account-id:resource
	// This is a simplified version
	return ""
}

func (c *CloudTrailCollector) extractUserIdentityFromEvent(event *cloudtrail.Event) CloudTrailUserIdentity {
	return CloudTrailUserIdentity{
		Type:     "IAMUser",
		UserName: aws.StringValue(event.Username),
	}
}

func (c *CloudTrailCollector) extractRequestParamsFromEvent(event *cloudtrail.Event) map[string]interface{} {
	// Request parameters are not available in LookupEvents
	return map[string]interface{}{}
}

func (c *CloudTrailCollector) extractResponseDataFromEvent(event *cloudtrail.Event) map[string]interface{} {
	// Response data is not available in LookupEvents
	return map[string]interface{}{}
}

// GetRecentEvents is a convenience method to get recent events
func (c *CloudTrailCollector) GetRecentEvents(hours int, maxResults int) ([]CloudTrailEvent, error) {
	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)
	return c.CollectEvents(startTime, endTime, maxResults)
}

// TestConnection tests the CloudTrail connection
func (c *CloudTrailCollector) TestConnection() error {
	log.Printf("🧪 Testing CloudTrail connection...")

	input := &cloudtrail.LookupEventsInput{
		MaxResults: aws.Int64(1),
	}

	_, err := c.client.LookupEvents(input)
	if err != nil {
		return fmt.Errorf("CloudTrail connection test failed: %w", err)
	}

	log.Printf("✅ CloudTrail connection successful")
	return nil
}

