package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// S3CloudTrailReader reads CloudTrail logs from S3 bucket
type S3CloudTrailReader struct {
	s3Client   *s3.S3
	bucketName string
	prefix     string
	region     string
}

// CloudTrailS3Record represents the CloudTrail log format in S3
type CloudTrailS3Record struct {
	Records []CloudTrailS3Event `json:"Records"`
}

// CloudTrailS3Event represents a single event in CloudTrail S3 logs
type CloudTrailS3Event struct {
	EventVersion       string                 `json:"eventVersion"`
	UserIdentity       CloudTrailUserIdentity `json:"userIdentity"`
	EventTime          string                 `json:"eventTime"`
	EventSource        string                 `json:"eventSource"`
	EventName          string                 `json:"eventName"`
	AwsRegion          string                 `json:"awsRegion"`
	SourceIPAddress    string                 `json:"sourceIPAddress"`
	UserAgent          string                 `json:"userAgent"`
	RequestParameters  interface{}            `json:"requestParameters"`
	ResponseElements   interface{}            `json:"responseElements"`
	EventID            string                 `json:"eventID"`
	EventType          string                 `json:"eventType"`
	RecipientAccountId string                 `json:"recipientAccountId"`
	ErrorCode          string                 `json:"errorCode,omitempty"`
	ErrorMessage       string                 `json:"errorMessage,omitempty"`
}

// NewS3CloudTrailReader creates a new S3 CloudTrail reader
func NewS3CloudTrailReader(sess *session.Session, bucketName, prefix, region string) (*S3CloudTrailReader, error) {
	if sess == nil {
		return nil, fmt.Errorf("AWS session is nil")
	}

	return &S3CloudTrailReader{
		s3Client:   s3.New(sess, aws.NewConfig().WithRegion(region)),
		bucketName: bucketName,
		prefix:     prefix,
		region:     region,
	}, nil
}

// ReadRecentLogs reads CloudTrail logs from S3 for the specified time range
func (r *S3CloudTrailReader) ReadRecentLogs(hoursBack int) ([]CloudTrailEvent, error) {
	log.Printf("📂 Reading CloudTrail logs from S3 bucket: %s (last %d hours)", r.bucketName, hoursBack)
	AddSystemLog("INFO", "s3-cloudtrail", fmt.Sprintf("Reading from bucket %s", r.bucketName), nil)

	// List objects in the bucket
	prefix := r.prefix
	if prefix == "" {
		prefix = "AWSLogs/"
	}

	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(r.bucketName),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int64(100), // Limit for performance
	}

	var allEvents []CloudTrailEvent
	cutoffTime := time.Now().Add(-time.Duration(hoursBack) * time.Hour)

	filesProcessed := 0
	filesSkipped := 0
	
	err := r.s3Client.ListObjectsV2Pages(input, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		log.Printf("📂 S3 page: %d objects found", len(page.Contents))
		
		for _, obj := range page.Contents {
			key := aws.StringValue(obj.Key)
			
			// Skip CloudTrail-Digest files - we want actual CloudTrail logs
			if strings.Contains(key, "CloudTrail-Digest") {
				filesSkipped++
				continue
			}
			
			// Only process .json.gz files that are actual CloudTrail logs
			if !strings.HasSuffix(key, ".json.gz") {
				continue
			}
			
			// Must contain "CloudTrail" in the path (actual logs)
			if !strings.Contains(key, "/CloudTrail/") {
				filesSkipped++
				continue
			}

			// Filter by modification time
			if obj.LastModified != nil && obj.LastModified.Before(cutoffTime) {
				filesSkipped++
				continue
			}

			// Read and parse the file
			events, err := r.readLogFile(key)
			if err != nil {
				log.Printf("⚠️ Error reading %s: %v", key, err)
				continue
			}

			allEvents = append(allEvents, events...)
			filesProcessed++

			// Limit total events
			if len(allEvents) >= 1000 {
				return false
			}
		}
		return !lastPage && len(allEvents) < 1000
	})
	
	log.Printf("📊 S3 CloudTrail: processed %d files, skipped %d files", filesProcessed, filesSkipped)

	if err != nil {
		return nil, fmt.Errorf("failed to list S3 objects: %w", err)
	}

	log.Printf("✅ Read %d CloudTrail events from S3", len(allEvents))
	AddSystemLog("INFO", "s3-cloudtrail", fmt.Sprintf("Read %d events from S3", len(allEvents)), nil)

	return allEvents, nil
}

// readLogFile reads and parses a single CloudTrail log file from S3
func (r *S3CloudTrailReader) readLogFile(key string) ([]CloudTrailEvent, error) {
	// Get the object
	result, err := r.s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(r.bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	defer result.Body.Close()

	// Log S3 object metadata for debugging
	contentType := ""
	if result.ContentType != nil {
		contentType = *result.ContentType
	}
	contentEncoding := ""
	if result.ContentEncoding != nil {
		contentEncoding = *result.ContentEncoding
	}
	log.Printf("📥 S3 Object: %s (ContentType: %s, ContentEncoding: %s, Size: %d)", 
		key, contentType, contentEncoding, aws.Int64Value(result.ContentLength))

	// Read all raw content first
	rawData, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object: %w", err)
	}

	// Log first bytes for debugging
	if len(rawData) > 0 {
		headerBytes := rawData[:min(16, len(rawData))]
		log.Printf("📊 File header bytes: %v (hex: %x)", headerBytes, headerBytes)
	}

	var data []byte

	// Check if it's actually gzip (magic bytes: 0x1f 0x8b)
	isGzip := len(rawData) >= 2 && rawData[0] == 0x1f && rawData[1] == 0x8b

	if isGzip {
		// It's a gzip file, decompress it
		gzReader, err := gzip.NewReader(bytes.NewReader(rawData))
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		decompressed, err := io.ReadAll(gzReader)
		gzReader.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to decompress gzip: %w", err)
		}
		data = decompressed
		log.Printf("📦 Decompressed gzip file: %s (%d -> %d bytes)", key, len(rawData), len(data))
	} else {
		// Not gzip - check if it's JSON directly
		log.Printf("📄 File is NOT gzip (magic bytes don't match), trying as plain text: %s", key)
		data = rawData
	}

	// Check if data looks like JSON
	if len(data) == 0 {
		return nil, fmt.Errorf("empty file content")
	}

	// Trim any BOM or whitespace
	data = bytes.TrimSpace(data)
	
	// Check for JSON start
	if len(data) > 0 && data[0] != '{' {
		// Log first few bytes for debugging
		preview := string(data[:min(100, len(data))])
		return nil, fmt.Errorf("data does not appear to be JSON (starts with: %q)", preview)
	}

	// Parse JSON
	var record CloudTrailS3Record
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w (data preview: %s)", err, string(data[:min(200, len(data))]))
	}

	// Convert to CloudTrailEvent format
	var events []CloudTrailEvent
	for _, s3Event := range record.Records {
		event := r.convertS3EventToCloudTrailEvent(s3Event)
		events = append(events, event)
	}

	log.Printf("✅ Parsed %d events from %s", len(events), key)
	return events, nil
}

// convertS3EventToCloudTrailEvent converts S3 format to internal format
func (r *S3CloudTrailReader) convertS3EventToCloudTrailEvent(s3Event CloudTrailS3Event) CloudTrailEvent {
	// Parse time
	eventTime, _ := time.Parse(time.RFC3339, s3Event.EventTime)

	// Convert request parameters
	var requestParams map[string]interface{}
	if s3Event.RequestParameters != nil {
		if params, ok := s3Event.RequestParameters.(map[string]interface{}); ok {
			requestParams = params
		}
	}

	// Convert response elements
	var responseElems map[string]interface{}
	if s3Event.ResponseElements != nil {
		if elems, ok := s3Event.ResponseElements.(map[string]interface{}); ok {
			responseElems = elems
		}
	}

	return CloudTrailEvent{
		EventID:           s3Event.EventID,
		EventName:         s3Event.EventName,
		EventSource:       s3Event.EventSource,
		EventTime:         eventTime,
		AwsRegion:         s3Event.AwsRegion,
		SourceIPAddress:   s3Event.SourceIPAddress,
		UserAgent:         s3Event.UserAgent,
		UserIdentity:      s3Event.UserIdentity,
		RequestParameters: requestParams,
		ResponseElements:  responseElems,
		ErrorCode:         s3Event.ErrorCode,
		ErrorMessage:      s3Event.ErrorMessage,
	}
}

// StartS3CloudTrailIndexer starts a background job to read S3 and index events
func (s *APIServer) StartS3CloudTrailIndexer(intervalMinutes int) {
	bucketName := os.Getenv("CLOUDTRAIL_S3_BUCKET")
	if bucketName == "" {
		log.Printf("⚠️ CLOUDTRAIL_S3_BUCKET not set, S3 indexer disabled")
		return
	}

	prefix := os.Getenv("CLOUDTRAIL_S3_PREFIX")
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
		s.syncS3CloudTrailEvents(bucketName, prefix, region)

		for range ticker.C {
			s.syncS3CloudTrailEvents(bucketName, prefix, region)
		}
	}()

	log.Printf("🔄 S3 CloudTrail Indexer started (bucket: %s, interval: %d min)", bucketName, intervalMinutes)
	AddSystemLog("INFO", "s3-cloudtrail", fmt.Sprintf("Indexer started (bucket: %s)", bucketName), nil)
}

// syncS3CloudTrailEvents syncs CloudTrail events from S3 to OpenSearch
func (s *APIServer) syncS3CloudTrailEvents(bucketName, prefix, region string) {
	log.Printf("🔄 Starting S3 CloudTrail sync from bucket: %s, prefix: %s", bucketName, prefix)
	AddSystemLog("INFO", "s3-cloudtrail", fmt.Sprintf("Starting sync from bucket: %s, prefix: %s", bucketName, prefix), nil)

	// Get AWS session
	sess, err := getAWSSession()
	if err != nil {
		log.Printf("❌ Failed to create AWS session: %v", err)
		AddSystemLog("ERROR", "s3-cloudtrail", fmt.Sprintf("AWS session failed: %v", err), nil)
		return
	}

	// Create reader
	reader, err := NewS3CloudTrailReader(sess, bucketName, prefix, region)
	if err != nil {
		log.Printf("❌ Failed to create S3 reader: %v", err)
		AddSystemLog("ERROR", "s3-cloudtrail", fmt.Sprintf("Failed to create reader: %v", err), nil)
		return
	}

	// Read recent logs (last 24 hours)
	events, err := reader.ReadRecentLogs(24)
	if err != nil {
		log.Printf("❌ Failed to read S3 logs: %v", err)
		AddSystemLog("ERROR", "s3-cloudtrail", fmt.Sprintf("Failed to read logs: %v", err), nil)
		return
	}

	if len(events) == 0 {
		log.Printf("📭 No CloudTrail events found in S3 bucket: %s", bucketName)
		AddSystemLog("WARN", "s3-cloudtrail", fmt.Sprintf("No events found in bucket: %s with prefix: %s", bucketName, prefix), nil)
		return
	}

	// Update global variable for other components
	awsConfigMutex.Lock()
	cloudTrailEvents = events
	awsConfigMutex.Unlock()

	// Index into OpenSearch
	if err := s.IndexCloudTrailEvents(events); err != nil {
		log.Printf("❌ Failed to index events: %v", err)
		AddSystemLog("ERROR", "s3-cloudtrail", fmt.Sprintf("Failed to index: %v", err), nil)
		return
	}

	log.Printf("✅ Synced %d CloudTrail events from S3", len(events))
	AddSystemLog("INFO", "s3-cloudtrail", fmt.Sprintf("Synced %d events", len(events)), nil)
}

// getAWSSession creates an AWS session using environment credentials or IAM role
func getAWSSession() (*session.Session, error) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	// Use default credential chain (env vars, IAM role, etc.)
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, err
	}

	return sess, nil
}

