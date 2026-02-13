package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/wafv2"
)

// ============================================================================
// AWS LAMBDA ACTIONS - Real Incident Response Actions
// ============================================================================
// This file implements real AWS actions for incident response automation:
// - Lambda function invocations
// - SNS notifications
// - EC2 instance isolation (security groups)
// - IAM access revocation
// - WAF IP blocking

// AWSActionExecutor handles real AWS action execution
type AWSActionExecutor struct {
	sess       *session.Session
	region     string
	lambdaSvc  *lambda.Lambda
	snsSvc     *sns.SNS
	ec2Svc     *ec2.EC2
	iamSvc     *iam.IAM
	wafSvc     *wafv2.WAFV2
}

// NewAWSActionExecutor creates a new AWS action executor
func NewAWSActionExecutor() (*AWSActionExecutor, error) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}

	return &AWSActionExecutor{
		sess:      sess,
		region:    region,
		lambdaSvc: lambda.New(sess),
		snsSvc:    sns.New(sess),
		ec2Svc:    ec2.New(sess),
		iamSvc:    iam.New(sess),
		wafSvc:    wafv2.New(sess),
	}, nil
}

// ============================================================================
// LAMBDA FUNCTION INVOCATION
// ============================================================================

// InvokeLambdaAction invokes an AWS Lambda function
func (ae *AWSActionExecutor) InvokeLambdaAction(ctx context.Context, functionName string, payload map[string]interface{}) (map[string]interface{}, error) {
	log.Printf("🔧 [LAMBDA] Invoking function: %s", functionName)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	input := &lambda.InvokeInput{
		FunctionName:   aws.String(functionName),
		InvocationType: aws.String("RequestResponse"), // Synchronous
		Payload:        payloadJSON,
	}

	output, err := ae.lambdaSvc.InvokeWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("lambda invocation failed: %v", err)
	}

	result := map[string]interface{}{
		"status":        "success",
		"function_name": functionName,
		"status_code":   aws.Int64Value(output.StatusCode),
		"executed_at":   time.Now().Format(time.RFC3339),
	}

	// Parse response if available
	if output.Payload != nil {
		var responsePayload map[string]interface{}
		if err := json.Unmarshal(output.Payload, &responsePayload); err == nil {
			result["response"] = responsePayload
		} else {
			result["response_raw"] = string(output.Payload)
		}
	}

	// Check for function error
	if output.FunctionError != nil {
		result["status"] = "error"
		result["function_error"] = aws.StringValue(output.FunctionError)
	}

	log.Printf("✅ [LAMBDA] Function %s completed with status %d", functionName, aws.Int64Value(output.StatusCode))
	return result, nil
}

// ============================================================================
// SNS NOTIFICATIONS
// ============================================================================

// SendSNSNotification sends a notification via SNS
func (ae *AWSActionExecutor) SendSNSNotification(ctx context.Context, topicARN string, subject string, message string, attributes map[string]string) (map[string]interface{}, error) {
	log.Printf("📢 [SNS] Sending notification to topic: %s", topicARN)

	input := &sns.PublishInput{
		TopicArn: aws.String(topicARN),
		Subject:  aws.String(subject),
		Message:  aws.String(message),
	}

	// Add message attributes if provided
	if len(attributes) > 0 {
		msgAttributes := make(map[string]*sns.MessageAttributeValue)
		for k, v := range attributes {
			msgAttributes[k] = &sns.MessageAttributeValue{
				DataType:    aws.String("String"),
				StringValue: aws.String(v),
			}
		}
		input.MessageAttributes = msgAttributes
	}

	output, err := ae.snsSvc.PublishWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("SNS publish failed: %v", err)
	}

	result := map[string]interface{}{
		"status":      "success",
		"topic_arn":   topicARN,
		"message_id":  aws.StringValue(output.MessageId),
		"subject":     subject,
		"sent_at":     time.Now().Format(time.RFC3339),
	}

	log.Printf("✅ [SNS] Notification sent, MessageID: %s", aws.StringValue(output.MessageId))
	return result, nil
}

// ============================================================================
// EC2 INSTANCE ISOLATION
// ============================================================================

// IsolateEC2Instance isolates an EC2 instance by modifying its security group
func (ae *AWSActionExecutor) IsolateEC2Instance(ctx context.Context, instanceID string, isolationSGID string) (map[string]interface{}, error) {
	log.Printf("🔒 [EC2] Isolating instance: %s", instanceID)

	// First, get current security groups
	descInput := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(instanceID)},
	}

	descOutput, err := ae.ec2Svc.DescribeInstancesWithContext(ctx, descInput)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instance: %v", err)
	}

	if len(descOutput.Reservations) == 0 || len(descOutput.Reservations[0].Instances) == 0 {
		return nil, fmt.Errorf("instance not found: %s", instanceID)
	}

	instance := descOutput.Reservations[0].Instances[0]
	
	// Store original security groups for rollback
	originalSGs := []string{}
	for _, sg := range instance.SecurityGroups {
		originalSGs = append(originalSGs, aws.StringValue(sg.GroupId))
	}

	// If no isolation SG provided, create one
	if isolationSGID == "" {
		isolationSGID, err = ae.createIsolationSecurityGroup(ctx, aws.StringValue(instance.VpcId))
		if err != nil {
			return nil, fmt.Errorf("failed to create isolation SG: %v", err)
		}
	}

	// Modify instance to use isolation security group
	modifyInput := &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		Groups:     []*string{aws.String(isolationSGID)},
	}

	_, err = ae.ec2Svc.ModifyInstanceAttributeWithContext(ctx, modifyInput)
	if err != nil {
		return nil, fmt.Errorf("failed to modify instance security groups: %v", err)
	}

	result := map[string]interface{}{
		"status":              "success",
		"action":              "isolate_instance",
		"instance_id":         instanceID,
		"isolation_sg":        isolationSGID,
		"original_sgs":        originalSGs,
		"isolated_at":         time.Now().Format(time.RFC3339),
		"message":             "Instance isolated - network access restricted",
	}

	log.Printf("✅ [EC2] Instance %s isolated with SG %s", instanceID, isolationSGID)
	return result, nil
}

// createIsolationSecurityGroup creates a security group that denies all traffic
func (ae *AWSActionExecutor) createIsolationSecurityGroup(ctx context.Context, vpcID string) (string, error) {
	sgName := fmt.Sprintf("siem-isolation-sg-%d", time.Now().Unix())
	
	createInput := &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(sgName),
		Description: aws.String("SIEM Platform - Isolation Security Group - Denies all traffic"),
		VpcId:       aws.String(vpcID),
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: aws.String("security-group"),
				Tags: []*ec2.Tag{
					{Key: aws.String("Name"), Value: aws.String(sgName)},
					{Key: aws.String("Purpose"), Value: aws.String("incident-response-isolation")},
					{Key: aws.String("ManagedBy"), Value: aws.String("SIEM-Platform")},
				},
			},
		},
	}

	output, err := ae.ec2Svc.CreateSecurityGroupWithContext(ctx, createInput)
	if err != nil {
		return "", err
	}

	sgID := aws.StringValue(output.GroupId)

	// Remove default egress rule (deny all outbound)
	revokeInput := &ec2.RevokeSecurityGroupEgressInput{
		GroupId: aws.String(sgID),
		IpPermissions: []*ec2.IpPermission{
			{
				IpProtocol: aws.String("-1"),
				IpRanges: []*ec2.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
		},
	}
	ae.ec2Svc.RevokeSecurityGroupEgressWithContext(ctx, revokeInput)

	log.Printf("✅ [EC2] Created isolation security group: %s", sgID)
	return sgID, nil
}

// ============================================================================
// IAM ACCESS REVOCATION
// ============================================================================

// RevokeIAMUserAccess revokes all access for an IAM user
func (ae *AWSActionExecutor) RevokeIAMUserAccess(ctx context.Context, username string, reason string) (map[string]interface{}, error) {
	log.Printf("🔐 [IAM] Revoking access for user: %s", username)

	actions := []string{}
	errors := []string{}

	// 1. Deactivate all access keys
	listKeysOutput, err := ae.iamSvc.ListAccessKeysWithContext(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	})
	if err == nil {
		for _, key := range listKeysOutput.AccessKeyMetadata {
			_, err := ae.iamSvc.UpdateAccessKeyWithContext(ctx, &iam.UpdateAccessKeyInput{
				UserName:    aws.String(username),
				AccessKeyId: key.AccessKeyId,
				Status:      aws.String("Inactive"),
			})
			if err != nil {
				errors = append(errors, fmt.Sprintf("Failed to deactivate key %s: %v", aws.StringValue(key.AccessKeyId), err))
			} else {
				actions = append(actions, fmt.Sprintf("Deactivated access key: %s", aws.StringValue(key.AccessKeyId)))
			}
		}
	} else {
		errors = append(errors, fmt.Sprintf("Failed to list access keys: %v", err))
	}

	// 2. Deactivate MFA devices
	listMFAOutput, err := ae.iamSvc.ListMFADevicesWithContext(ctx, &iam.ListMFADevicesInput{
		UserName: aws.String(username),
	})
	if err == nil {
		for _, device := range listMFAOutput.MFADevices {
			_, err := ae.iamSvc.DeactivateMFADeviceWithContext(ctx, &iam.DeactivateMFADeviceInput{
				UserName:     aws.String(username),
				SerialNumber: device.SerialNumber,
			})
			if err != nil {
				errors = append(errors, fmt.Sprintf("Failed to deactivate MFA: %v", err))
			} else {
				actions = append(actions, fmt.Sprintf("Deactivated MFA device: %s", aws.StringValue(device.SerialNumber)))
			}
		}
	}

	// 3. Attach deny all policy
	denyPolicyARN := os.Getenv("IAM_DENY_ALL_POLICY_ARN")
	if denyPolicyARN != "" {
		_, err := ae.iamSvc.AttachUserPolicyWithContext(ctx, &iam.AttachUserPolicyInput{
			UserName:  aws.String(username),
			PolicyArn: aws.String(denyPolicyARN),
		})
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to attach deny policy: %v", err))
		} else {
			actions = append(actions, "Attached deny-all policy")
		}
	}

	// 4. Delete login profile (console access)
	_, err = ae.iamSvc.DeleteLoginProfileWithContext(ctx, &iam.DeleteLoginProfileInput{
		UserName: aws.String(username),
	})
	if err != nil {
		// Ignore if no login profile exists
		if !strings.Contains(err.Error(), "NoSuchEntity") {
			errors = append(errors, fmt.Sprintf("Failed to delete login profile: %v", err))
		}
	} else {
		actions = append(actions, "Deleted console login profile")
	}

	result := map[string]interface{}{
		"status":      "success",
		"action":      "revoke_access",
		"username":    username,
		"reason":      reason,
		"actions":     actions,
		"errors":      errors,
		"revoked_at":  time.Now().Format(time.RFC3339),
	}

	if len(errors) > 0 && len(actions) == 0 {
		result["status"] = "failed"
	} else if len(errors) > 0 {
		result["status"] = "partial"
	}

	log.Printf("✅ [IAM] Access revocation completed for %s: %d actions, %d errors", username, len(actions), len(errors))
	return result, nil
}

// ============================================================================
// WAF IP BLOCKING
// ============================================================================

// BlockIPInWAF adds an IP to the WAF block list
func (ae *AWSActionExecutor) BlockIPInWAF(ctx context.Context, ipAddress string, ipSetID string, ipSetName string, scope string, reason string) (map[string]interface{}, error) {
	log.Printf("🛡️ [WAF] Blocking IP: %s", ipAddress)

	if scope == "" {
		scope = "REGIONAL" // REGIONAL or CLOUDFRONT
	}

	// Get current IP set
	getInput := &wafv2.GetIPSetInput{
		Id:    aws.String(ipSetID),
		Name:  aws.String(ipSetName),
		Scope: aws.String(scope),
	}

	getOutput, err := ae.wafSvc.GetIPSetWithContext(ctx, getInput)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP set: %v", err)
	}

	// Add IP to the list (ensure CIDR notation)
	ipCIDR := ipAddress
	if !strings.Contains(ipCIDR, "/") {
		ipCIDR = ipAddress + "/32"
	}

	newAddresses := append(getOutput.IPSet.Addresses, aws.String(ipCIDR))

	// Update IP set
	updateInput := &wafv2.UpdateIPSetInput{
		Id:          aws.String(ipSetID),
		Name:        aws.String(ipSetName),
		Scope:       aws.String(scope),
		Addresses:   newAddresses,
		LockToken:   getOutput.LockToken,
		Description: aws.String(fmt.Sprintf("Updated by SIEM Platform - Blocked %s: %s", ipAddress, reason)),
	}

	_, err = ae.wafSvc.UpdateIPSetWithContext(ctx, updateInput)
	if err != nil {
		return nil, fmt.Errorf("failed to update IP set: %v", err)
	}

	result := map[string]interface{}{
		"status":      "success",
		"action":      "block_ip_waf",
		"ip_address":  ipAddress,
		"ip_set_id":   ipSetID,
		"ip_set_name": ipSetName,
		"scope":       scope,
		"reason":      reason,
		"blocked_at":  time.Now().Format(time.RFC3339),
	}

	log.Printf("✅ [WAF] IP %s blocked in IP set %s", ipAddress, ipSetName)
	return result, nil
}

// ============================================================================
// ENHANCED PLAYBOOK ENGINE INTEGRATION
// ============================================================================

// AWSIntegrations holds AWS service integrations
type AWSIntegrations struct {
	executor *AWSActionExecutor
	enabled  bool
}

// InitAWSIntegrations initializes AWS integrations for the playbook engine
func InitAWSIntegrations() *AWSIntegrations {
	if os.Getenv("USE_REAL_AWS_DATA") != "true" {
		log.Println("⚠️ AWS integrations disabled (USE_REAL_AWS_DATA != true)")
		return &AWSIntegrations{enabled: false}
	}

	executor, err := NewAWSActionExecutor()
	if err != nil {
		log.Printf("❌ Failed to initialize AWS action executor: %v", err)
		return &AWSIntegrations{enabled: false}
	}

	log.Println("✅ AWS integrations initialized for incident response")
	return &AWSIntegrations{
		executor: executor,
		enabled:  true,
	}
}

// ExecuteAWSAction executes an AWS action based on the action type
func (ai *AWSIntegrations) ExecuteAWSAction(ctx context.Context, actionType string, params map[string]interface{}, triggerData map[string]interface{}) (map[string]interface{}, error) {
	if !ai.enabled || ai.executor == nil {
		return map[string]interface{}{
			"status":  "skipped",
			"message": "AWS integrations not enabled",
		}, nil
	}

	switch actionType {
	case "invoke_lambda":
		functionName := getStringParam(params, "function_name")
		if functionName == "" {
			return nil, fmt.Errorf("function_name is required for invoke_lambda")
		}
		payload := mergePayload(params["payload"], triggerData)
		return ai.executor.InvokeLambdaAction(ctx, functionName, payload)

	case "send_sns", "notify_sns":
		topicARN := getStringParam(params, "topic_arn")
		if topicARN == "" {
			topicARN = os.Getenv("SNS_INCIDENT_TOPIC_ARN")
		}
		if topicARN == "" {
			return nil, fmt.Errorf("topic_arn is required for send_sns")
		}
		subject := getStringParam(params, "subject")
		if subject == "" {
			subject = "SIEM Platform - Security Alert"
		}
		message := formatSNSMessage(params, triggerData)
		return ai.executor.SendSNSNotification(ctx, topicARN, subject, message, nil)

	case "isolate_instance", "isolate_ec2":
		instanceID := getStringParam(params, "instance_id")
		if instanceID == "" {
			instanceID = getStringParam(triggerData, "instance_id")
		}
		if instanceID == "" {
			return nil, fmt.Errorf("instance_id is required for isolate_instance")
		}
		isolationSG := getStringParam(params, "isolation_sg")
		return ai.executor.IsolateEC2Instance(ctx, instanceID, isolationSG)

	case "revoke_iam_access", "revoke_access":
		username := getStringParam(params, "username")
		if username == "" {
			username = getStringParam(triggerData, "user_identity")
		}
		if username == "" {
			return nil, fmt.Errorf("username is required for revoke_iam_access")
		}
		reason := getStringParam(params, "reason")
		if reason == "" {
			reason = "Automated incident response"
		}
		return ai.executor.RevokeIAMUserAccess(ctx, username, reason)

	case "block_ip_waf":
		ipAddress := getStringParam(params, "ip_address")
		if ipAddress == "" {
			ipAddress = getStringParam(triggerData, "source_ip")
		}
		if ipAddress == "" {
			return nil, fmt.Errorf("ip_address is required for block_ip_waf")
		}
		ipSetID := getStringParam(params, "ip_set_id")
		ipSetName := getStringParam(params, "ip_set_name")
		scope := getStringParam(params, "scope")
		reason := getStringParam(params, "reason")
		if ipSetID == "" {
			ipSetID = os.Getenv("WAF_BLOCK_IP_SET_ID")
		}
		if ipSetName == "" {
			ipSetName = os.Getenv("WAF_BLOCK_IP_SET_NAME")
		}
		if ipSetID == "" || ipSetName == "" {
			return nil, fmt.Errorf("ip_set_id and ip_set_name are required for block_ip_waf")
		}
		return ai.executor.BlockIPInWAF(ctx, ipAddress, ipSetID, ipSetName, scope, reason)

	default:
		return nil, fmt.Errorf("unknown AWS action type: %s", actionType)
	}
}

// Helper functions
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func mergePayload(payload interface{}, triggerData map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	
	// Copy trigger data first
	for k, v := range triggerData {
		result[k] = v
	}
	
	// Overlay with payload if it's a map
	if p, ok := payload.(map[string]interface{}); ok {
		for k, v := range p {
			result[k] = v
		}
	}
	
	return result
}

func formatSNSMessage(params map[string]interface{}, triggerData map[string]interface{}) string {
	if msg := getStringParam(params, "message"); msg != "" {
		return msg
	}

	// Build message from trigger data
	messageData := map[string]interface{}{
		"source":      "SIEM Platform",
		"timestamp":   time.Now().Format(time.RFC3339),
		"trigger_data": triggerData,
	}

	if alertType := getStringParam(triggerData, "alert_type"); alertType != "" {
		messageData["alert_type"] = alertType
	}
	if severity := getStringParam(triggerData, "severity"); severity != "" {
		messageData["severity"] = severity
	}

	jsonBytes, _ := json.MarshalIndent(messageData, "", "  ")
	return string(jsonBytes)
}

