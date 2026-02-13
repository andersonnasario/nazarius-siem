package main

import (
	"sync"
)

// =============================================================================
// GLOBAL INDEXER TYPES AND INSTANCES
// =============================================================================
// These types and variables are used by cspm_aws.go to check indexer status

// S3CloudTrailIndexer represents the S3 CloudTrail indexer state
// This is the TYPE that cspm_aws.go expects
type S3CloudTrailIndexer struct {
	mu          sync.RWMutex
	running     bool
	lastSync    string
	eventsCount int
	errorCount  int
	bucketName  string
	prefix      string
	region      string
}

// SecurityHubIndexer represents the Security Hub indexer state
// This is the TYPE that cspm_aws.go expects
type SecurityHubIndexer struct {
	mu            sync.RWMutex
	running       bool
	lastSync      string
	findingsCount int
	errorCount    int
	region        string
}

// Global instances (lowercase to avoid conflict with type names)
var (
	s3CloudTrailIndexerInstance  *S3CloudTrailIndexer
	securityHubIndexerInstance   *SecurityHubIndexer
)

// GetS3CloudTrailIndexer returns the global S3 CloudTrail indexer instance
func GetS3CloudTrailIndexer() *S3CloudTrailIndexer {
	return s3CloudTrailIndexerInstance
}

// GetSecurityHubIndexer returns the global Security Hub indexer instance
func GetSecurityHubIndexer() *SecurityHubIndexer {
	return securityHubIndexerInstance
}

// IsRunning returns whether the S3 CloudTrail indexer is running
func (i *S3CloudTrailIndexer) IsRunning() bool {
	if i == nil {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.running
}

// GetStatus returns the status of the S3 CloudTrail indexer
func (i *S3CloudTrailIndexer) GetStatus() map[string]interface{} {
	if i == nil {
		return map[string]interface{}{
			"running": false,
			"status":  "not_initialized",
		}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return map[string]interface{}{
		"running":      i.running,
		"last_sync":    i.lastSync,
		"events_count": i.eventsCount,
		"error_count":  i.errorCount,
		"bucket_name":  i.bucketName,
		"prefix":       i.prefix,
		"region":       i.region,
	}
}

// IsRunning returns whether the Security Hub indexer is running
func (i *SecurityHubIndexer) IsRunning() bool {
	if i == nil {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.running
}

// GetStatus returns the status of the Security Hub indexer
func (i *SecurityHubIndexer) GetStatus() map[string]interface{} {
	if i == nil {
		return map[string]interface{}{
			"running": false,
			"status":  "not_initialized",
		}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return map[string]interface{}{
		"running":        i.running,
		"last_sync":      i.lastSync,
		"findings_count": i.findingsCount,
		"error_count":    i.errorCount,
		"region":         i.region,
	}
}

// InitS3CloudTrailIndexerGlobal initializes the global S3 CloudTrail indexer instance
func InitS3CloudTrailIndexerGlobal(bucketName, prefix, region string) {
	s3CloudTrailIndexerInstance = &S3CloudTrailIndexer{
		running:    true,
		bucketName: bucketName,
		prefix:     prefix,
		region:     region,
	}
}

// InitSecurityHubIndexerGlobal initializes the global Security Hub indexer instance
func InitSecurityHubIndexerGlobal(region string) {
	securityHubIndexerInstance = &SecurityHubIndexer{
		running: true,
		region:  region,
	}
}

// UpdateS3CloudTrailIndexerStatus updates the S3 CloudTrail indexer status
func UpdateS3CloudTrailIndexerStatus(eventsCount int, errorCount int, lastSync string) {
	if s3CloudTrailIndexerInstance == nil {
		return
	}
	s3CloudTrailIndexerInstance.mu.Lock()
	defer s3CloudTrailIndexerInstance.mu.Unlock()
	s3CloudTrailIndexerInstance.eventsCount = eventsCount
	s3CloudTrailIndexerInstance.errorCount = errorCount
	s3CloudTrailIndexerInstance.lastSync = lastSync
}

// UpdateSecurityHubIndexerStatus updates the Security Hub indexer status
func UpdateSecurityHubIndexerStatus(findingsCount int, errorCount int, lastSync string) {
	if securityHubIndexerInstance == nil {
		return
	}
	securityHubIndexerInstance.mu.Lock()
	defer securityHubIndexerInstance.mu.Unlock()
	securityHubIndexerInstance.findingsCount = findingsCount
	securityHubIndexerInstance.errorCount = errorCount
	securityHubIndexerInstance.lastSync = lastSync
}
