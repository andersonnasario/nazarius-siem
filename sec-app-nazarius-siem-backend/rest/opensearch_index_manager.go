package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/gin-gonic/gin"
)

// OpenSearch index mapping for SIEM events
const siemEventsMapping = `{
	"settings": {
		"number_of_shards": 1,
		"number_of_replicas": 1,
		"index.mapping.total_fields.limit": 2000
	},
	"mappings": {
		"properties": {
			"id": { "type": "keyword" },
			"timestamp": { "type": "date" },
			"severity": { "type": "keyword" },
			"type": { "type": "keyword" },
			"source": { "type": "keyword" },
			"description": { "type": "text" },
			"user": { "type": "keyword" },
			"source_ip": { "type": "keyword" },
			"details": { "type": "object", "enabled": true },
			"tags": { "type": "keyword" }
		}
	}
}`

// handleCheckOpenSearchIndex checks if the siem-events index exists and creates it if not
func (s *APIServer) handleCheckOpenSearchIndex(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "OpenSearch client not available",
		})
		return
	}

	// Check if index exists
	existsRes, err := s.opensearch.Indices.Exists([]string{"siem-events"})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   fmt.Sprintf("Failed to check index: %v", err),
		})
		return
	}
	defer existsRes.Body.Close()

	indexExists := existsRes.StatusCode == 200

	// Get document count if index exists
	var docCount int64 = 0
	if indexExists {
		countRes, err := s.opensearch.Count(
			s.opensearch.Count.WithIndex("siem-events"),
		)
		if err == nil && !countRes.IsError() {
			defer countRes.Body.Close()
			var countResult map[string]interface{}
			if json.NewDecoder(countRes.Body).Decode(&countResult) == nil {
				if count, ok := countResult["count"].(float64); ok {
					docCount = int64(count)
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"index_exists":  indexExists,
		"index_name":    "siem-events",
		"document_count": docCount,
		"message":       fmt.Sprintf("Index exists: %v, Documents: %d", indexExists, docCount),
	})
}

// handleRecreateIndex deletes and recreates the siem-events index with new mapping
func (s *APIServer) handleRecreateIndex(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "OpenSearch client not available",
		})
		return
	}

	indexName := c.Query("index")
	if indexName == "" {
		indexName = "siem-events"
	}

	log.Printf("🔄 Recreating index: %s", indexName)

	// Delete index if exists
	deleteRes, _ := s.opensearch.Indices.Delete([]string{indexName})
	if deleteRes != nil {
		defer deleteRes.Body.Close()
		log.Printf("🗑️ Deleted index %s: %s", indexName, deleteRes.Status())
	}

	// Create index with new mapping or ensure helper
	var recreateFunc func() error
	switch indexName {
	case "siem-events":
		recreateFunc = func() error {
			createRes, err := s.opensearch.Indices.Create(
				indexName,
				s.opensearch.Indices.Create.WithBody(strings.NewReader(siemEventsMapping)),
			)
			if err != nil {
				return err
			}
			defer createRes.Body.Close()
			if createRes.IsError() {
				return fmt.Errorf("OpenSearch error: %s", createRes.String())
			}
			return nil
		}
	case "siem-ueba-profiles", "siem-ueba-anomalies":
		recreateFunc = func() error {
			s.EnsureUEBAIndices()
			return nil
		}
	case "siem-ml-anomalies", "siem-ml-predictions":
		recreateFunc = func() error {
			s.EnsureMLIndices()
			return nil
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Unknown index: " + indexName,
		})
		return
	}

	if err := recreateFunc(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   fmt.Sprintf("Failed to recreate index: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Index %s recreated successfully with new mapping", indexName),
	})
}

func (s *APIServer) createSimpleIndex(indexName, mapping string) error {
	createRes, err := s.opensearch.Indices.Create(
		indexName,
		s.opensearch.Indices.Create.WithBody(strings.NewReader(mapping)),
	)
	if err != nil {
		return err
	}
	defer createRes.Body.Close()
	if createRes.IsError() {
		return fmt.Errorf("OpenSearch error: %s", createRes.String())
	}
	return nil
}

// handleCreateOpenSearchIndex creates the siem-events index
func (s *APIServer) handleCreateOpenSearchIndex(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "OpenSearch client not available",
		})
		return
	}

	// Check if index already exists
	existsRes, err := s.opensearch.Indices.Exists([]string{"siem-events"})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   fmt.Sprintf("Failed to check index: %v", err),
		})
		return
	}
	defer existsRes.Body.Close()

	if existsRes.StatusCode == 200 {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Index 'siem-events' already exists",
			"created": false,
		})
		return
	}

	// Create the index
	createRes, err := s.opensearch.Indices.Create(
		"siem-events",
		s.opensearch.Indices.Create.WithBody(strings.NewReader(siemEventsMapping)),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   fmt.Sprintf("Failed to create index: %v", err),
		})
		return
	}
	defer createRes.Body.Close()

	if createRes.IsError() {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   fmt.Sprintf("OpenSearch error: %s", createRes.String()),
		})
		return
	}

	log.Printf("✅ Created OpenSearch index 'siem-events'")
	AddSystemLog("INFO", "opensearch", "Created index 'siem-events'", nil)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Index 'siem-events' created successfully",
		"created": true,
	})
}

// handleForceSyncAWSData forces a sync of all AWS data sources
func (s *APIServer) handleForceSyncAWSData(c *gin.Context) {
	results := make(map[string]interface{})

	// Ensure index exists first
	if s.opensearch != nil {
		existsRes, err := s.opensearch.Indices.Exists([]string{"siem-events"})
		if err == nil {
			defer existsRes.Body.Close()
			if existsRes.StatusCode != 200 {
				// Create index if it doesn't exist
				createRes, err := s.opensearch.Indices.Create(
					"siem-events",
					s.opensearch.Indices.Create.WithBody(strings.NewReader(siemEventsMapping)),
				)
				if err == nil {
					defer createRes.Body.Close()
					if !createRes.IsError() {
						results["index_created"] = true
						log.Printf("✅ Auto-created OpenSearch index 'siem-events'")
						AddSystemLog("INFO", "opensearch", "Auto-created index 'siem-events'", nil)
					}
				}
			}
		}
	}

	// Sync GuardDuty
	go func() {
		region := getEnvOrDefault("AWS_REGION", "us-east-1")
		s.syncGuardDutyFindings(region)
	}()
	results["guardduty"] = "sync started"

	// Sync Security Hub
	go func() {
		region := getEnvOrDefault("AWS_REGION", "us-east-1")
		s.syncSecurityHubFindings(region)
	}()
	results["securityhub"] = "sync started"

	// Sync S3 CloudTrail
	go func() {
		bucketName := getEnvOrDefault("CLOUDTRAIL_S3_BUCKET", "")
		prefix := getEnvOrDefault("CLOUDTRAIL_S3_PREFIX", "AWSLogs/")
		region := getEnvOrDefault("AWS_REGION", "us-east-1")
		if bucketName != "" {
			s.syncS3CloudTrailEvents(bucketName, prefix, region)
		}
	}()
	results["cloudtrail_s3"] = "sync started"

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Force sync initiated for all AWS data sources",
		"results": results,
	})
}

// handleGetRecentEvents returns recent events from OpenSearch for debugging
func (s *APIServer) handleGetRecentEvents(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "OpenSearch client not available",
		})
		return
	}

	// Query for recent events
	query := `{
		"size": 20,
		"sort": [{"timestamp": {"order": "desc"}}],
		"query": {"match_all": {}}
	}`

	searchRes, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   fmt.Sprintf("Search failed: %v", err),
		})
		return
	}
	defer searchRes.Body.Close()

	if searchRes.IsError() {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   fmt.Sprintf("OpenSearch error: %s", searchRes.String()),
		})
		return
	}

	var result map[string]interface{}
	if err := json.NewDecoder(searchRes.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   fmt.Sprintf("Failed to parse response: %v", err),
		})
		return
	}

	// Extract hits
	var events []interface{}
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsList, ok := hits["hits"].([]interface{}); ok {
			for _, hit := range hitsList {
				if hitMap, ok := hit.(map[string]interface{}); ok {
					if source, ok := hitMap["_source"]; ok {
						events = append(events, source)
					}
				}
			}
		}
	}

	// Get total count
	var total int64 = 0
	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalObj, ok := hits["total"].(map[string]interface{}); ok {
			if value, ok := totalObj["value"].(float64); ok {
				total = int64(value)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"total_events": total,
		"showing":      len(events),
		"events":       events,
	})
}

// handleDiagnoseStatistics provides detailed diagnostic info about event statistics
func (s *APIServer) handleDiagnoseStatistics(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "OpenSearch client not available",
		})
		return
	}

	diagnostics := make(map[string]interface{})

	// 1. Get total document count
	countRes, err := s.opensearch.Count(
		s.opensearch.Count.WithIndex("siem-events"),
	)
	if err != nil {
		diagnostics["count_error"] = err.Error()
	} else {
		defer countRes.Body.Close()
		var countResult map[string]interface{}
		if json.NewDecoder(countRes.Body).Decode(&countResult) == nil {
			diagnostics["total_documents"] = countResult["count"]
		}
	}

	// 2. Query sample events to see their structure
	sampleQuery := `{
		"size": 5,
		"sort": [{"timestamp": {"order": "desc"}}],
		"query": {"match_all": {}}
	}`

	sampleRes, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(sampleQuery)),
	)
	if err != nil {
		diagnostics["sample_error"] = err.Error()
	} else {
		defer sampleRes.Body.Close()
		var sampleResult map[string]interface{}
		if json.NewDecoder(sampleRes.Body).Decode(&sampleResult) == nil {
			if hits, ok := sampleResult["hits"].(map[string]interface{}); ok {
				if hitsList, ok := hits["hits"].([]interface{}); ok {
					var sampleEvents []interface{}
					for _, hit := range hitsList {
						if hitMap, ok := hit.(map[string]interface{}); ok {
							sampleEvents = append(sampleEvents, hitMap["_source"])
						}
					}
					diagnostics["sample_events"] = sampleEvents
				}
			}
		}
	}

	// 3. Try aggregation query
	aggQuery := `{
		"size": 0,
		"query": {"match_all": {}},
		"aggs": {
			"by_severity": {
				"terms": { "field": "severity.keyword", "size": 10 }
			},
			"by_source": {
				"terms": { "field": "source.keyword", "size": 10 }
			},
			"by_type": {
				"terms": { "field": "type.keyword", "size": 10 }
			}
		}
	}`

	aggRes, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(aggQuery)),
	)
	if err != nil {
		diagnostics["agg_error"] = err.Error()
	} else {
		defer aggRes.Body.Close()
		if aggRes.IsError() {
			diagnostics["agg_opensearch_error"] = aggRes.String()
		} else {
			var aggResult map[string]interface{}
			if json.NewDecoder(aggRes.Body).Decode(&aggResult) == nil {
				if aggs, ok := aggResult["aggregations"].(map[string]interface{}); ok {
					diagnostics["aggregations"] = aggs
				}
				if hits, ok := aggResult["hits"].(map[string]interface{}); ok {
					if total, ok := hits["total"].(map[string]interface{}); ok {
						diagnostics["total_from_agg"] = total["value"]
					}
				}
			}
		}
	}

	// 4. Get index mapping
	mappingRes, err := s.opensearch.Indices.GetMapping(
		s.opensearch.Indices.GetMapping.WithIndex("siem-events"),
	)
	if err != nil {
		diagnostics["mapping_error"] = err.Error()
	} else {
		defer mappingRes.Body.Close()
		var mappingResult map[string]interface{}
		if json.NewDecoder(mappingRes.Body).Decode(&mappingResult) == nil {
			diagnostics["index_mapping"] = mappingResult
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"diagnostics": diagnostics,
	})
}

// handleDiagnoseS3CloudTrail provides detailed diagnostic info about S3 CloudTrail
func (s *APIServer) handleDiagnoseS3CloudTrail(c *gin.Context) {
	diagnostics := make(map[string]interface{})

	bucketName := getEnvOrDefault("CLOUDTRAIL_S3_BUCKET", "")
	prefix := getEnvOrDefault("CLOUDTRAIL_S3_PREFIX", "AWSLogs/")
	region := getEnvOrDefault("AWS_REGION", "us-east-1")

	diagnostics["config"] = map[string]string{
		"bucket": bucketName,
		"prefix": prefix,
		"region": region,
	}

	if bucketName == "" {
		diagnostics["error"] = "CLOUDTRAIL_S3_BUCKET not configured"
		c.JSON(http.StatusOK, gin.H{
			"success":     false,
			"diagnostics": diagnostics,
		})
		return
	}

	// Try to list S3 objects
	sess, err := getAWSSession()
	if err != nil {
		diagnostics["session_error"] = err.Error()
		c.JSON(http.StatusOK, gin.H{
			"success":     false,
			"diagnostics": diagnostics,
		})
		return
	}

	s3Client := s3.New(sess, aws.NewConfig().WithRegion(region))

	// List first 20 objects to see the bucket structure
	listInput := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucketName),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int64(50),
	}

	result, err := s3Client.ListObjectsV2(listInput)
	if err != nil {
		diagnostics["list_error"] = err.Error()
		c.JSON(http.StatusOK, gin.H{
			"success":     false,
			"diagnostics": diagnostics,
		})
		return
	}

	// Analyze files found
	var files []map[string]interface{}
	jsonGzCount := 0
	digestCount := 0
	cloudTrailLogCount := 0
	otherCount := 0

	for _, obj := range result.Contents {
		key := aws.StringValue(obj.Key)
		fileInfo := map[string]interface{}{
			"key":           key,
			"size":          aws.Int64Value(obj.Size),
			"last_modified": obj.LastModified.Format("2006-01-02 15:04:05"),
		}

		// Categorize files
		if strings.HasSuffix(key, ".json.gz") {
			jsonGzCount++
			if strings.Contains(key, "CloudTrail-Digest") {
				fileInfo["type"] = "digest"
				digestCount++
			} else if strings.Contains(key, "/CloudTrail/") {
				fileInfo["type"] = "cloudtrail_log"
				cloudTrailLogCount++
			} else {
				fileInfo["type"] = "other_json_gz"
				otherCount++
			}
		} else {
			fileInfo["type"] = "other"
			otherCount++
		}

		files = append(files, fileInfo)
	}

	diagnostics["summary"] = map[string]interface{}{
		"total_files_found":    len(result.Contents),
		"is_truncated":         aws.BoolValue(result.IsTruncated),
		"json_gz_files":        jsonGzCount,
		"digest_files":         digestCount,
		"cloudtrail_log_files": cloudTrailLogCount,
		"other_files":          otherCount,
	}

	diagnostics["files"] = files

	// Provide recommendation
	if cloudTrailLogCount == 0 {
		diagnostics["recommendation"] = "No CloudTrail log files found with pattern '/CloudTrail/' in path. Check prefix configuration. CloudTrail logs typically have pattern: AWSLogs/<account>/CloudTrail/<region>/<year>/<month>/<day>/*.json.gz"
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"diagnostics": diagnostics,
	})
}

// EnsureSIEMEventsIndex creates the siem-events index if it doesn't exist
func (s *APIServer) EnsureSIEMEventsIndex() error {
	if s.opensearch == nil {
		return fmt.Errorf("opensearch client not available")
	}

	// Check if index exists
	existsRes, err := s.opensearch.Indices.Exists([]string{"siem-events"})
	if err != nil {
		return fmt.Errorf("failed to check index: %w", err)
	}
	defer existsRes.Body.Close()

	if existsRes.StatusCode == 200 {
		log.Printf("✅ Index 'siem-events' already exists")
		return nil
	}

	// Create the index
	createRes, err := s.opensearch.Indices.Create(
		"siem-events",
		s.opensearch.Indices.Create.WithBody(bytes.NewReader([]byte(siemEventsMapping))),
	)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	defer createRes.Body.Close()

	if createRes.IsError() {
		return fmt.Errorf("opensearch error: %s", createRes.String())
	}

	log.Printf("✅ Created OpenSearch index 'siem-events'")
	AddSystemLog("INFO", "opensearch", "Created index 'siem-events' on startup", nil)
	return nil
}

