package main

import "fmt"

// normalizeCloudTrailEvent normaliza eventos do CloudTrail para o formato padrão
func (p *IngestPipeline) normalizeCloudTrailEvent(normalized *NormalizedEvent, event Event) (*NormalizedEvent, error) {
	if data, ok := event.Data["detail"].(map[string]interface{}); ok {
		normalized.Account = getStringValue(data, "userIdentity", "accountId")
		normalized.Region = getStringValue(data, "awsRegion")
		normalized.Resource = getStringValue(data, "resources", "0", "ARN")
		normalized.Action = getStringValue(data, "eventName")
		normalized.Actor = getStringValue(data, "userIdentity", "principalId")
		
		// Determinar severidade baseado no tipo de evento
		if isSecurityEvent(data) {
			normalized.Severity = "HIGH"
		} else if isComplianceEvent(data) {
			normalized.Severity = "MEDIUM"
		} else {
			normalized.Severity = "LOW"
		}
	}
	return normalized, nil
}

// normalizeVPCFlowEvent normaliza eventos do VPC Flow Logs para o formato padrão
func (p *IngestPipeline) normalizeVPCFlowEvent(normalized *NormalizedEvent, event Event) (*NormalizedEvent, error) {
	if data, ok := event.Data["message"].(map[string]interface{}); ok {
		normalized.Account = getStringValue(data, "account-id")
		normalized.Region = getStringValue(data, "region")
		normalized.Resource = getStringValue(data, "vpc-id")
		normalized.Action = getStringValue(data, "action")
		
		// Determinar severidade baseado nas flags de rejeição
		if isRejectedTraffic(data) {
			normalized.Severity = "MEDIUM"
		} else {
			normalized.Severity = "LOW"
		}
	}
	return normalized, nil
}

// normalizeGuardDutyEvent normaliza eventos do GuardDuty para o formato padrão
func (p *IngestPipeline) normalizeGuardDutyEvent(normalized *NormalizedEvent, event Event) (*NormalizedEvent, error) {
	if data, ok := event.Data["detail"].(map[string]interface{}); ok {
		normalized.Account = getStringValue(data, "accountId")
		normalized.Region = getStringValue(data, "region")
		normalized.Resource = getStringValue(data, "resource", "resourceId")
		normalized.Action = getStringValue(data, "type")
		normalized.Actor = getStringValue(data, "service", "action", "awsApiCallAction", "callerType")
		
		// Mapear severidade do GuardDuty
		severity := getFloat64Value(data, "severity")
		switch {
		case severity >= 7.0:
			normalized.Severity = "HIGH"
		case severity >= 4.0:
			normalized.Severity = "MEDIUM"
		default:
			normalized.Severity = "LOW"
		}
	}
	return normalized, nil
}

// normalizeConfigEvent normaliza eventos do AWS Config para o formato padrão
func (p *IngestPipeline) normalizeConfigEvent(normalized *NormalizedEvent, event Event) (*NormalizedEvent, error) {
	if data, ok := event.Data["detail"].(map[string]interface{}); ok {
		normalized.Account = getStringValue(data, "configurationItem", "awsAccountId")
		normalized.Region = getStringValue(data, "configurationItem", "awsRegion")
		normalized.Resource = getStringValue(data, "configurationItem", "resourceId")
		normalized.Action = getStringValue(data, "configurationItem", "configurationItemStatus")
		
		// Determinar severidade baseado no tipo de alteração
		if isNonCompliant(data) {
			normalized.Severity = "HIGH"
		} else if isConfigurationChange(data) {
			normalized.Severity = "MEDIUM"
		} else {
			normalized.Severity = "LOW"
		}
	}
	return normalized, nil
}

// Funções auxiliares para avaliação de eventos
func isSecurityEvent(data map[string]interface{}) bool {
	eventName := getStringValue(data, "eventName")
	securityEvents := []string{
		"DeleteSecurityGroup",
		"RevokeSecurityGroupIngress",
		"UpdateUser",
		"DeleteRole",
		"DeleteBucket",
	}
	
	for _, secEvent := range securityEvents {
		if eventName == secEvent {
			return true
		}
	}
	return false
}

func isComplianceEvent(data map[string]interface{}) bool {
	eventSource := getStringValue(data, "eventSource")
	complianceSources := []string{
		"config.amazonaws.com",
		"iam.amazonaws.com",
		"s3.amazonaws.com",
	}
	
	for _, source := range complianceSources {
		if eventSource == source {
			return true
		}
	}
	return false
}

func isRejectedTraffic(data map[string]interface{}) bool {
	action := getStringValue(data, "action")
	return action == "REJECT"
}

func isNonCompliant(data map[string]interface{}) bool {
	compliance := getStringValue(data, "configurationItem", "configurationItemStatus")
	return compliance == "NON_COMPLIANT"
}

func isConfigurationChange(data map[string]interface{}) bool {
	changeType := getStringValue(data, "configurationItem", "configurationItemChangeType")
	return changeType == "UPDATE"
}

// Funções auxiliares para extração de dados
func getStringValue(data map[string]interface{}, keys ...string) string {
	current := data
	for i, key := range keys[:len(keys)-1] {
		if val, ok := current[key].(map[string]interface{}); ok {
			current = val
		} else if val, ok := current[key].([]interface{}); ok && i < len(keys)-1 {
			if idx, err := parseIndex(keys[i+1]); err == nil && idx < len(val) {
				if mapVal, ok := val[idx].(map[string]interface{}); ok {
					current = mapVal
				} else {
					return ""
				}
			} else {
				return ""
			}
		} else {
			return ""
		}
	}
	
	lastKey := keys[len(keys)-1]
	if val, ok := current[lastKey].(string); ok {
		return val
	}
	return ""
}

func getFloat64Value(data map[string]interface{}, keys ...string) float64 {
	current := data
	for _, key := range keys[:len(keys)-1] {
		if val, ok := current[key].(map[string]interface{}); ok {
			current = val
		} else {
			return 0
		}
	}
	
	lastKey := keys[len(keys)-1]
	if val, ok := current[lastKey].(float64); ok {
		return val
	}
	return 0
}

func parseIndex(s string) (int, error) {
	i := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("não é um número: %s", s)
		}
		i = i*10 + int(c-'0')
	}
	return i, nil
}