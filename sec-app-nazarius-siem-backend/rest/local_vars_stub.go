package main

// =============================================================================
// LOCAL VARIABLES STUB - DO NOT COPY TO REMOTE REPOSITORY!
// =============================================================================
// These variables are defined in cspm_aws.go in the remote repository.
// This file exists only for local compilation testing.

import "sync"

// Global variables that exist in cspm_aws.go on remote repository
var (
	awsConfigMutex      sync.RWMutex
	cloudTrailEvents    []CloudTrailEvent
	guardDutyFindings   []GuardDutyFinding
	cloudtrailCollector *CloudTrailCollector
	uebaCollector       *UEBACollector
)

