package main

import (
	"time"
)

// =============================================================================
// AWS CLOUDTRAIL TYPES
// =============================================================================

// CloudTrailEvent represents a CloudTrail event
type CloudTrailEvent struct {
	EventID           string                 `json:"eventID"`
	EventName         string                 `json:"eventName"`
	EventSource       string                 `json:"eventSource"`
	EventTime         time.Time              `json:"eventTime"`
	EventType         string                 `json:"eventType,omitempty"`
	AwsRegion         string                 `json:"awsRegion"`
	SourceIPAddress   string                 `json:"sourceIPAddress"`
	UserAgent         string                 `json:"userAgent"`
	UserIdentity      CloudTrailUserIdentity `json:"userIdentity"`
	RequestParameters map[string]interface{} `json:"requestParameters"`
	ResponseElements  map[string]interface{} `json:"responseElements"`
	ErrorCode         string                 `json:"errorCode,omitempty"`
	ErrorMessage      string                 `json:"errorMessage,omitempty"`
	ReadOnly          bool                   `json:"readOnly,omitempty"`
	Resources         []CloudTrailResource   `json:"resources,omitempty"`
}

// CloudTrailUserIdentity represents the user identity in a CloudTrail event
type CloudTrailUserIdentity struct {
	Type           string `json:"type"`
	PrincipalID    string `json:"principalId"`
	ARN            string `json:"arn"`
	AccountID      string `json:"accountId"`
	UserName       string `json:"userName,omitempty"`
	SessionContext struct {
		Attributes struct {
			MfaAuthenticated string `json:"mfaAuthenticated"`
			CreationDate     string `json:"creationDate"`
		} `json:"attributes"`
		SessionIssuer struct {
			Type        string `json:"type"`
			PrincipalID string `json:"principalId"`
			ARN         string `json:"arn"`
			AccountID   string `json:"accountId"`
			UserName    string `json:"userName"`
		} `json:"sessionIssuer"`
	} `json:"sessionContext,omitempty"`
}

// CloudTrailResource represents a resource in a CloudTrail event
type CloudTrailResource struct {
	Type      string `json:"type"`
	ARN       string `json:"ARN"`
	AccountID string `json:"accountId,omitempty"`
}

// =============================================================================
// AWS GUARDDUTY TYPES
// =============================================================================

// GuardDutyFinding represents a GuardDuty finding
type GuardDutyFinding struct {
	ID          string           `json:"id"`
	ARN         string           `json:"arn"`
	Type        string           `json:"type"`
	Severity    float64          `json:"severity"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	CreatedAt   time.Time        `json:"createdAt"`
	UpdatedAt   time.Time        `json:"updatedAt"`
	Region      string           `json:"region"`
	AccountID   string           `json:"accountId"`
	Resource    GuardDutyResource `json:"resource"`
	Service     GuardDutyService  `json:"service"`
}

// GuardDutyResource represents the resource affected by a GuardDuty finding
type GuardDutyResource struct {
	ResourceType     string                 `json:"resourceType"`
	InstanceDetails  map[string]interface{} `json:"instanceDetails,omitempty"`
	AccessKeyDetails map[string]interface{} `json:"accessKeyDetails,omitempty"`
}

// GuardDutyService represents service information in a GuardDuty finding
type GuardDutyService struct {
	Action         map[string]interface{} `json:"action"`
	Evidence       map[string]interface{} `json:"evidence,omitempty"`
	AdditionalInfo map[string]interface{} `json:"additionalInfo,omitempty"`
	EventFirstSeen time.Time              `json:"eventFirstSeen"`
	EventLastSeen  time.Time              `json:"eventLastSeen"`
	Count          int                    `json:"count"`
}

// =============================================================================
// AWS GLOBAL VARIABLES FOR SYNC
// =============================================================================
// NOTE: The following variables are defined in cspm_aws.go in the remote repository:
// - awsConfigMutex
// - cloudTrailEvents  
// - guardDutyFindings
// - cloudtrailCollector
// - uebaCollector
// DO NOT redeclare them here!

