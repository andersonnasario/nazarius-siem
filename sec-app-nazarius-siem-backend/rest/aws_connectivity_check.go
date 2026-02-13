package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gin-gonic/gin"
)

// AWSConnectivityResult represents the result of a connectivity test
type AWSConnectivityResult struct {
	Service    string                 `json:"service"`
	Status     string                 `json:"status"`
	Message    string                 `json:"message"`
	Latency    string                 `json:"latency"`
	Details    map[string]interface{} `json:"details,omitempty"`
	SampleData interface{}            `json:"sample_data,omitempty"`
	TestedAt   time.Time              `json:"tested_at"`
}

// AWSConnectivityTestResponse represents the full test response
type AWSConnectivityTestResponse struct {
	OverallStatus    string                  `json:"overall_status"`
	AWSAccountID     string                  `json:"aws_account_id"`
	AWSRegion        string                  `json:"aws_region"`
	CredentialSource string                  `json:"credential_source"`
	Environment      map[string]string       `json:"environment"`
	Tests            []AWSConnectivityResult `json:"tests"`
	Recommendations  []string                `json:"recommendations,omitempty"`
	TestedAt         time.Time               `json:"tested_at"`
}

// handleTestAWSConnectivity handles the AWS connectivity test endpoint
func (s *APIServer) handleTestAWSConnectivity(c *gin.Context) {
	log.Printf("[AWS-TEST] Starting AWS connectivity test...")

	response := AWSConnectivityTestResponse{
		TestedAt: time.Now().UTC(),
		Tests:    []AWSConnectivityResult{},
		Environment: map[string]string{
			"USE_REAL_AWS_DATA":    getEnvWithDefault("USE_REAL_AWS_DATA", "false"),
			"DISABLE_MOCK_DATA":    getEnvWithDefault("DISABLE_MOCK_DATA", "false"),
			"CLOUDTRAIL_S3_BUCKET": maskEnvValue(os.Getenv("CLOUDTRAIL_S3_BUCKET")),
			"USE_SECURITY_HUB":     getEnvWithDefault("USE_SECURITY_HUB", "false"),
			"AWS_REGION":           getEnvWithDefault("AWS_REGION", "not set"),
		},
	}

	// Try to create AWS session
	region := getEnvWithDefault("AWS_REGION", "us-east-1")
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	if err != nil {
		response.OverallStatus = "error"
		response.Recommendations = append(response.Recommendations,
			fmt.Sprintf("Failed to create AWS session: %v", err))
		c.JSON(http.StatusOK, response)
		return
	}

	// Test STS
	stsResult := testSTSConnectivity(sess)
	response.Tests = append(response.Tests, stsResult)
	if stsResult.Status == "connected" {
		if details, ok := stsResult.Details["account_id"].(string); ok {
			response.AWSAccountID = details
		}
	}
	response.AWSRegion = region
	response.CredentialSource = "IAM Role / Environment"

	// Test S3 CloudTrail
	s3Result := testS3CloudTrailConnectivity(sess)
	response.Tests = append(response.Tests, s3Result)

	// Test GuardDuty
	gdResult := testGuardDutyConnectivity(sess, region)
	response.Tests = append(response.Tests, gdResult)

	// Test Security Hub
	shResult := testSecurityHubConnectivity(sess, region)
	response.Tests = append(response.Tests, shResult)

	// Calculate overall status
	allConnected := true
	hasErrors := false
	for _, test := range response.Tests {
		if test.Status == "error" {
			hasErrors = true
			allConnected = false
		} else if test.Status == "not_configured" {
			allConnected = false
		}
	}

	if allConnected {
		response.OverallStatus = "all_connected"
	} else if hasErrors {
		response.OverallStatus = "partial_error"
	} else {
		response.OverallStatus = "partial_connected"
	}

	// Generate recommendations
	response.Recommendations = generateAWSRecommendations(response)

	log.Printf("[AWS-TEST] Test completed: %s", response.OverallStatus)
	c.JSON(http.StatusOK, response)
}

// Helper functions

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func maskEnvValue(s string) string {
	if s == "" {
		return "not set"
	}
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

func testSTSConnectivity(sess *session.Session) AWSConnectivityResult {
	start := time.Now()
	result := AWSConnectivityResult{
		Service:  "STS (Identity)",
		TestedAt: time.Now().UTC(),
	}

	stsClient := sts.New(sess)
	identity, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	result.Latency = time.Since(start).String()

	if err != nil {
		result.Status = "error"
		result.Message = fmt.Sprintf("Failed: %v", err)
		return result
	}

	result.Status = "connected"
	result.Message = "Successfully authenticated with AWS"
	result.Details = map[string]interface{}{
		"account_id": aws.StringValue(identity.Account),
		"arn":        aws.StringValue(identity.Arn),
		"user_id":    aws.StringValue(identity.UserId),
	}
	return result
}

func testS3CloudTrailConnectivity(sess *session.Session) AWSConnectivityResult {
	start := time.Now()
	result := AWSConnectivityResult{
		Service:  "S3 CloudTrail Bucket",
		TestedAt: time.Now().UTC(),
	}

	bucketName := os.Getenv("CLOUDTRAIL_S3_BUCKET")
	if bucketName == "" {
		result.Status = "not_configured"
		result.Message = "CLOUDTRAIL_S3_BUCKET not configured"
		result.Latency = "0ms"
		return result
	}

	prefix := os.Getenv("CLOUDTRAIL_S3_PREFIX")
	s3Client := s3.New(sess)

	listInput := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucketName),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int64(5),
	}

	listResult, err := s3Client.ListObjectsV2(listInput)
	result.Latency = time.Since(start).String()

	if err != nil {
		result.Status = "error"
		result.Message = fmt.Sprintf("Failed: %v", err)
		return result
	}

	result.Status = "connected"
	result.Message = fmt.Sprintf("Found %d objects", aws.Int64Value(listResult.KeyCount))
	result.Details = map[string]interface{}{
		"bucket":       bucketName,
		"prefix":       prefix,
		"object_count": aws.Int64Value(listResult.KeyCount),
	}

	if len(listResult.Contents) > 0 {
		sampleFiles := []string{}
		for i, obj := range listResult.Contents {
			if i < 3 {
				sampleFiles = append(sampleFiles, aws.StringValue(obj.Key))
			}
		}
		result.SampleData = map[string]interface{}{"sample_files": sampleFiles}
	}
	return result
}

func testGuardDutyConnectivity(sess *session.Session, region string) AWSConnectivityResult {
	start := time.Now()
	result := AWSConnectivityResult{
		Service:  "GuardDuty",
		TestedAt: time.Now().UTC(),
	}

	gdClient := guardduty.New(sess, aws.NewConfig().WithRegion(region))
	detectorsResult, err := gdClient.ListDetectors(&guardduty.ListDetectorsInput{MaxResults: aws.Int64(1)})
	result.Latency = time.Since(start).String()

	if err != nil {
		result.Status = "error"
		result.Message = fmt.Sprintf("Failed: %v", err)
		return result
	}

	if len(detectorsResult.DetectorIds) == 0 {
		result.Status = "error"
		result.Message = "No GuardDuty detectors found"
		return result
	}

	detectorID := aws.StringValue(detectorsResult.DetectorIds[0])
	findingsResult, err := gdClient.ListFindings(&guardduty.ListFindingsInput{
		DetectorId: aws.String(detectorID),
		MaxResults: aws.Int64(5),
	})

	if err != nil {
		result.Status = "error"
		result.Message = fmt.Sprintf("Failed to list findings: %v", err)
		return result
	}

	result.Status = "connected"
	result.Message = fmt.Sprintf("Found %d findings", len(findingsResult.FindingIds))
	result.Details = map[string]interface{}{
		"detector_id":    detectorID,
		"findings_count": len(findingsResult.FindingIds),
	}
	return result
}

func testSecurityHubConnectivity(sess *session.Session, region string) AWSConnectivityResult {
	start := time.Now()
	result := AWSConnectivityResult{
		Service:  "Security Hub",
		TestedAt: time.Now().UTC(),
	}

	if os.Getenv("USE_SECURITY_HUB") != "true" {
		result.Status = "not_configured"
		result.Message = "USE_SECURITY_HUB not enabled"
		result.Latency = "0ms"
		return result
	}

	shClient := securityhub.New(sess, aws.NewConfig().WithRegion(region))
	hubResult, err := shClient.DescribeHub(&securityhub.DescribeHubInput{})
	result.Latency = time.Since(start).String()

	if err != nil {
		result.Status = "error"
		result.Message = fmt.Sprintf("Failed: %v", err)
		return result
	}

	findingsResult, err := shClient.GetFindings(&securityhub.GetFindingsInput{
		MaxResults: aws.Int64(5),
		Filters: &securityhub.AwsSecurityFindingFilters{
			RecordState: []*securityhub.StringFilter{
				{Comparison: aws.String("EQUALS"), Value: aws.String("ACTIVE")},
			},
		},
	})

	if err != nil {
		result.Status = "error"
		result.Message = fmt.Sprintf("Failed to get findings: %v", err)
		return result
	}

	result.Status = "connected"
	result.Message = fmt.Sprintf("Found %d findings", len(findingsResult.Findings))
	result.Details = map[string]interface{}{
		"hub_arn":        aws.StringValue(hubResult.HubArn),
		"findings_count": len(findingsResult.Findings),
	}
	return result
}

func generateAWSRecommendations(response AWSConnectivityTestResponse) []string {
	recommendations := []string{}

	if response.Environment["USE_REAL_AWS_DATA"] != "true" {
		recommendations = append(recommendations,
			"Set USE_REAL_AWS_DATA=true to enable real AWS data")
	}

	if response.Environment["DISABLE_MOCK_DATA"] != "true" {
		recommendations = append(recommendations,
			"Set DISABLE_MOCK_DATA=true to disable demo data")
	}

	for _, test := range response.Tests {
		if test.Status == "not_configured" {
			switch test.Service {
			case "S3 CloudTrail Bucket":
				recommendations = append(recommendations,
					"Set CLOUDTRAIL_S3_BUCKET for CloudTrail logs")
			case "Security Hub":
				recommendations = append(recommendations,
					"Set USE_SECURITY_HUB=true for Security Hub")
			}
		} else if test.Status == "error" {
			switch test.Service {
			case "S3 CloudTrail Bucket":
				recommendations = append(recommendations,
					"Check IAM: s3:GetObject, s3:ListBucket")
			case "GuardDuty":
				recommendations = append(recommendations,
					"Check IAM: guardduty:ListDetectors, guardduty:ListFindings")
			case "Security Hub":
				recommendations = append(recommendations,
					"Check IAM: securityhub:DescribeHub, securityhub:GetFindings")
			}
		}
	}

	return recommendations
}
