package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// GuardDutyMITREMapping maps GuardDuty finding types to MITRE techniques
var GuardDutyMITREMapping = map[string]MITREMapping{
	// Reconnaissance (TA0043) / Discovery (TA0007)
	"Recon:EC2/PortProbeUnprotectedPort":     {TechniqueID: "T1046", TechniqueName: "Network Service Scanning", TacticID: "TA0007", TacticName: "Discovery"},
	"Recon:EC2/Portscan":                     {TechniqueID: "T1046", TechniqueName: "Network Service Scanning", TacticID: "TA0007", TacticName: "Discovery"},
	"Recon:IAMUser/UserPermissions":          {TechniqueID: "T1087", TechniqueName: "Account Discovery", TacticID: "TA0007", TacticName: "Discovery"},
	"Recon:IAMUser/ResourcePermissions":      {TechniqueID: "T1087", TechniqueName: "Account Discovery", TacticID: "TA0007", TacticName: "Discovery"},
	"Recon:IAMUser/MaliciousIPCaller":        {TechniqueID: "T1590", TechniqueName: "Gather Victim Network Information", TacticID: "TA0043", TacticName: "Reconnaissance"},
	"Recon:IAMUser/MaliciousIPCaller.Custom": {TechniqueID: "T1590", TechniqueName: "Gather Victim Network Information", TacticID: "TA0043", TacticName: "Reconnaissance"},
	"Recon:IAMUser/TorIPCaller":              {TechniqueID: "T1590", TechniqueName: "Gather Victim Network Information", TacticID: "TA0043", TacticName: "Reconnaissance"},
	"Discovery:S3/MaliciousIPCaller":         {TechniqueID: "T1619", TechniqueName: "Cloud Storage Object Discovery", TacticID: "TA0007", TacticName: "Discovery"},
	"Discovery:S3/MaliciousIPCaller.Custom":  {TechniqueID: "T1619", TechniqueName: "Cloud Storage Object Discovery", TacticID: "TA0007", TacticName: "Discovery"},
	"Discovery:S3/TorIPCaller":               {TechniqueID: "T1619", TechniqueName: "Cloud Storage Object Discovery", TacticID: "TA0007", TacticName: "Discovery"},

	// Initial Access (TA0001)
	"UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B":        {TechniqueID: "T1078", TechniqueName: "Valid Accounts", TacticID: "TA0001", TacticName: "Initial Access"},
	"UnauthorizedAccess:IAMUser/MaliciousIPCaller":            {TechniqueID: "T1078", TechniqueName: "Valid Accounts", TacticID: "TA0001", TacticName: "Initial Access"},
	"UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom":     {TechniqueID: "T1078", TechniqueName: "Valid Accounts", TacticID: "TA0001", TacticName: "Initial Access"},
	"UnauthorizedAccess:IAMUser/TorIPCaller":                  {TechniqueID: "T1078", TechniqueName: "Valid Accounts", TacticID: "TA0001", TacticName: "Initial Access"},
	"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS": {TechniqueID: "T1078.004", TechniqueName: "Valid Accounts: Cloud Accounts", TacticID: "TA0001", TacticName: "Initial Access"},
	"InitialAccess:IAMUser/AnomalousBehavior":                 {TechniqueID: "T1078", TechniqueName: "Valid Accounts", TacticID: "TA0001", TacticName: "Initial Access"},

	// Execution (TA0002)
	"Execution:EC2/SuspiciousFile":                            {TechniqueID: "T1204", TechniqueName: "User Execution", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:EC2/MaliciousFile":                             {TechniqueID: "T1204", TechniqueName: "User Execution", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Container/SuspiciousFile":                      {TechniqueID: "T1204", TechniqueName: "User Execution", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Container/MaliciousFile":                       {TechniqueID: "T1204", TechniqueName: "User Execution", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Kubernetes/ExecInKubeSystemPod":                {TechniqueID: "T1609", TechniqueName: "Container Administration Command", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Kubernetes/AnomalousBehavior.WorkloadDeployed": {TechniqueID: "T1610", TechniqueName: "Deploy Container", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Runtime/NewBinaryExecuted":                     {TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Runtime/NewLibraryLoaded":                      {TechniqueID: "T1055", TechniqueName: "Process Injection", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Runtime/SuspiciousTool":                        {TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Runtime/SuspiciousCommand":                     {TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Runtime/ReverseShell":                          {TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Runtime/ProcessInjection.Proc":                 {TechniqueID: "T1055", TechniqueName: "Process Injection", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Runtime/ProcessInjection.Ptrace":               {TechniqueID: "T1055", TechniqueName: "Process Injection", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Runtime/ProcessInjection.VirtualMemoryWrite":   {TechniqueID: "T1055", TechniqueName: "Process Injection", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:Runtime/MaliciousFileExecuted":                 {TechniqueID: "T1203", TechniqueName: "Exploitation for Client Execution", TacticID: "TA0002", TacticName: "Execution"},
	"Execution:EC2/Malware":                                   {TechniqueID: "T1203", TechniqueName: "Exploitation for Client Execution", TacticID: "TA0002", TacticName: "Execution"},
	
	// Scheduled Task/Job (T1053)
	"Persistence:Runtime/ScheduledTaskCreated":                {TechniqueID: "T1053", TechniqueName: "Scheduled Task/Job", TacticID: "TA0003", TacticName: "Persistence"},
	"Execution:Runtime/ScheduledTaskExecuted":                 {TechniqueID: "T1053", TechniqueName: "Scheduled Task/Job", TacticID: "TA0002", TacticName: "Execution"},

	// Persistence (TA0003)
	"Persistence:IAMUser/AnomalousBehavior":                   {TechniqueID: "T1098", TechniqueName: "Account Manipulation", TacticID: "TA0003", TacticName: "Persistence"},
	"Persistence:IAMUser/UserPermissions":                     {TechniqueID: "T1098", TechniqueName: "Account Manipulation", TacticID: "TA0003", TacticName: "Persistence"},
	"Persistence:Kubernetes/ContainerWithSensitiveMount":      {TechniqueID: "T1525", TechniqueName: "Implant Internal Image", TacticID: "TA0003", TacticName: "Persistence"},
	"Persistence:Kubernetes/MaliciousIPCaller":                {TechniqueID: "T1525", TechniqueName: "Implant Internal Image", TacticID: "TA0003", TacticName: "Persistence"},

	// Privilege Escalation (TA0004)
	"PrivilegeEscalation:IAMUser/AnomalousBehavior":           {TechniqueID: "T1078", TechniqueName: "Valid Accounts", TacticID: "TA0004", TacticName: "Privilege Escalation"},
	"PrivilegeEscalation:Kubernetes/PrivilegedContainer":      {TechniqueID: "T1611", TechniqueName: "Escape to Host", TacticID: "TA0004", TacticName: "Privilege Escalation"},
	"PrivilegeEscalation:Kubernetes/AnomalousBehavior.WorkloadDeployed": {TechniqueID: "T1611", TechniqueName: "Escape to Host", TacticID: "TA0004", TacticName: "Privilege Escalation"},
	"PrivilegeEscalation:Runtime/ContainerMountHostDirectory": {TechniqueID: "T1611", TechniqueName: "Escape to Host", TacticID: "TA0004", TacticName: "Privilege Escalation"},
	"PrivilegeEscalation:Runtime/UserfaultfdUsage":            {TechniqueID: "T1068", TechniqueName: "Exploitation for Privilege Escalation", TacticID: "TA0004", TacticName: "Privilege Escalation"},

	// Defense Evasion (TA0005)
	"DefenseEvasion:EC2/UnusualNetworkProtocol":               {TechniqueID: "T1095", TechniqueName: "Non-Application Layer Protocol", TacticID: "TA0005", TacticName: "Defense Evasion"},
	"DefenseEvasion:EC2/UnusualDNSResolver":                   {TechniqueID: "T1071.004", TechniqueName: "Application Layer Protocol: DNS", TacticID: "TA0005", TacticName: "Defense Evasion"},
	"DefenseEvasion:Kubernetes/AnomalousBehavior.WorkloadDeployed": {TechniqueID: "T1610", TechniqueName: "Deploy Container", TacticID: "TA0005", TacticName: "Defense Evasion"},
	"Stealth:IAMUser/CloudTrailLoggingDisabled":               {TechniqueID: "T1562.008", TechniqueName: "Impair Defenses: Disable Cloud Logs", TacticID: "TA0005", TacticName: "Defense Evasion"},
	"Stealth:IAMUser/PasswordPolicyChange":                    {TechniqueID: "T1562", TechniqueName: "Impair Defenses", TacticID: "TA0005", TacticName: "Defense Evasion"},
	"Stealth:IAMUser/LoggingConfigurationModified":            {TechniqueID: "T1562.008", TechniqueName: "Impair Defenses: Disable Cloud Logs", TacticID: "TA0005", TacticName: "Defense Evasion"},
	"Stealth:S3/ServerAccessLoggingDisabled":                  {TechniqueID: "T1562.008", TechniqueName: "Impair Defenses: Disable Cloud Logs", TacticID: "TA0005", TacticName: "Defense Evasion"},

	// Credential Access (TA0006)
	"CredentialAccess:IAMUser/AnomalousBehavior":              {TechniqueID: "T1528", TechniqueName: "Steal Application Access Token", TacticID: "TA0006", TacticName: "Credential Access"},
	"CredentialAccess:Kubernetes/MaliciousIPCaller":           {TechniqueID: "T1552", TechniqueName: "Unsecured Credentials", TacticID: "TA0006", TacticName: "Credential Access"},
	"CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed": {TechniqueID: "T1552.007", TechniqueName: "Unsecured Credentials: Container API", TacticID: "TA0006", TacticName: "Credential Access"},
	"CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin":  {TechniqueID: "T1110", TechniqueName: "Brute Force", TacticID: "TA0006", TacticName: "Credential Access"},
	"CredentialAccess:RDS/AnomalousBehavior.FailedLogin":      {TechniqueID: "T1110", TechniqueName: "Brute Force", TacticID: "TA0006", TacticName: "Credential Access"},

	// Collection (TA0009)
	"Exfiltration:S3/MaliciousIPCaller":                       {TechniqueID: "T1530", TechniqueName: "Data from Cloud Storage Object", TacticID: "TA0009", TacticName: "Collection"},
	"Exfiltration:S3/ObjectRead.Unusual":                      {TechniqueID: "T1530", TechniqueName: "Data from Cloud Storage Object", TacticID: "TA0009", TacticName: "Collection"},
	"Exfiltration:IAMUser/AnomalousBehavior":                  {TechniqueID: "T1530", TechniqueName: "Data from Cloud Storage Object", TacticID: "TA0009", TacticName: "Collection"},

	// Command and Control (TA0011)
	"Backdoor:EC2/C&CActivity.B":                              {TechniqueID: "T1071", TechniqueName: "Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control"},
	"Backdoor:EC2/C&CActivity.B!DNS":                          {TechniqueID: "T1071.004", TechniqueName: "Application Layer Protocol: DNS", TacticID: "TA0011", TacticName: "Command and Control"},
	"Backdoor:EC2/DenialOfService.Dns":                        {TechniqueID: "T1071.004", TechniqueName: "Application Layer Protocol: DNS", TacticID: "TA0011", TacticName: "Command and Control"},
	"Backdoor:EC2/DenialOfService.Tcp":                        {TechniqueID: "T1071.001", TechniqueName: "Application Layer Protocol: Web", TacticID: "TA0011", TacticName: "Command and Control"},
	"Backdoor:EC2/DenialOfService.Udp":                        {TechniqueID: "T1095", TechniqueName: "Non-Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control"},
	"Backdoor:EC2/DenialOfService.UdpOnTcpPorts":              {TechniqueID: "T1095", TechniqueName: "Non-Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control"},
	"Backdoor:EC2/Spambot":                                    {TechniqueID: "T1071.003", TechniqueName: "Application Layer Protocol: Mail", TacticID: "TA0011", TacticName: "Command and Control"},
	"Trojan:EC2/BlackholeTraffic":                             {TechniqueID: "T1071", TechniqueName: "Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control"},
	"Trojan:EC2/BlackholeTraffic!DNS":                         {TechniqueID: "T1071.004", TechniqueName: "Application Layer Protocol: DNS", TacticID: "TA0011", TacticName: "Command and Control"},
	"Trojan:EC2/DropPoint":                                    {TechniqueID: "T1071", TechniqueName: "Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control"},
	"Trojan:EC2/DropPoint!DNS":                                {TechniqueID: "T1071.004", TechniqueName: "Application Layer Protocol: DNS", TacticID: "TA0011", TacticName: "Command and Control"},
	"Trojan:EC2/DriveBySourceTraffic!DNS":                     {TechniqueID: "T1071.004", TechniqueName: "Application Layer Protocol: DNS", TacticID: "TA0011", TacticName: "Command and Control"},
	"Trojan:EC2/PhishingDomainRequest!DNS":                    {TechniqueID: "T1071.004", TechniqueName: "Application Layer Protocol: DNS", TacticID: "TA0011", TacticName: "Command and Control"},
	"Trojan:EC2/DGADomainRequest.B":                           {TechniqueID: "T1568.002", TechniqueName: "Dynamic Resolution: Domain Generation Algorithms", TacticID: "TA0011", TacticName: "Command and Control"},
	"Trojan:EC2/DGADomainRequest.C!DNS":                       {TechniqueID: "T1568.002", TechniqueName: "Dynamic Resolution: Domain Generation Algorithms", TacticID: "TA0011", TacticName: "Command and Control"},
	"CryptoCurrency:EC2/BitcoinTool.B":                        {TechniqueID: "T1496", TechniqueName: "Resource Hijacking", TacticID: "TA0040", TacticName: "Impact"},
	"CryptoCurrency:EC2/BitcoinTool.B!DNS":                    {TechniqueID: "T1496", TechniqueName: "Resource Hijacking", TacticID: "TA0040", TacticName: "Impact"},

	// Impact (TA0040)
	"Impact:EC2/WinRMBruteForce":                              {TechniqueID: "T1110", TechniqueName: "Brute Force", TacticID: "TA0006", TacticName: "Credential Access"},
	"Impact:EC2/PortSweep":                                    {TechniqueID: "T1046", TechniqueName: "Network Service Scanning", TacticID: "TA0007", TacticName: "Discovery"},
	"Impact:Kubernetes/MaliciousIPCaller":                     {TechniqueID: "T1499", TechniqueName: "Endpoint Denial of Service", TacticID: "TA0040", TacticName: "Impact"},
	"Impact:Runtime/AbusedDomainRequest.Reputation":           {TechniqueID: "T1499", TechniqueName: "Endpoint Denial of Service", TacticID: "TA0040", TacticName: "Impact"},
	"Impact:S3/MaliciousIPCaller":                             {TechniqueID: "T1485", TechniqueName: "Data Destruction", TacticID: "TA0040", TacticName: "Impact"},

	// Policy Violations (map to appropriate techniques)
	"Policy:IAMUser/RootCredentialUsage":                      {TechniqueID: "T1078.004", TechniqueName: "Valid Accounts: Cloud Accounts", TacticID: "TA0001", TacticName: "Initial Access"},
	"Policy:S3/AccountBlockPublicAccessDisabled":              {TechniqueID: "T1562", TechniqueName: "Impair Defenses", TacticID: "TA0005", TacticName: "Defense Evasion"},
	"Policy:S3/BucketBlockPublicAccessDisabled":               {TechniqueID: "T1562", TechniqueName: "Impair Defenses", TacticID: "TA0005", TacticName: "Defense Evasion"},
	"Policy:S3/BucketAnonymousAccessGranted":                  {TechniqueID: "T1190", TechniqueName: "Exploit Public-Facing Application", TacticID: "TA0001", TacticName: "Initial Access"},
	"Policy:S3/BucketPublicAccessGranted":                     {TechniqueID: "T1190", TechniqueName: "Exploit Public-Facing Application", TacticID: "TA0001", TacticName: "Initial Access"},
}

// MITREMapping represents a mapping entry
type MITREMapping struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	TacticID      string `json:"tactic_id"`
	TacticName    string `json:"tactic_name"`
}

// MITREDetectionReal represents a real detection from events with full details
type MITREDetectionReal struct {
	ID            string    `json:"id"`
	TechniqueID   string    `json:"technique_id"`
	TechniqueName string    `json:"technique_name"`
	TacticID      string    `json:"tactic_id"`
	TacticName    string    `json:"tactic_name"`
	EventID       string    `json:"event_id"`
	EventType     string    `json:"event_type"`
	Timestamp     time.Time `json:"timestamp"`
	Severity      string    `json:"severity"`
	Source        string    `json:"source"`
	Description   string    `json:"description"`
	Count         int       `json:"count"`
	
	// Enhanced details for investigation
	User          string   `json:"user,omitempty"`
	SourceIP      string   `json:"source_ip,omitempty"`
	DestinationIP string   `json:"destination_ip,omitempty"`
	Region        string   `json:"region,omitempty"`
	AccountID     string   `json:"account_id,omitempty"`
	ResourceType  string   `json:"resource_type,omitempty"`
	ResourceID    string   `json:"resource_id,omitempty"`
	ResourceARN   string   `json:"resource_arn,omitempty"`
	Action        string   `json:"action,omitempty"`
	Port          int      `json:"port,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	ThreatName    string   `json:"threat_name,omitempty"`
	ThreatListName string  `json:"threat_list_name,omitempty"`
	RawDetails    map[string]interface{} `json:"raw_details,omitempty"`
}

// handleGetMITRECoverageReal returns coverage based on real events
func (s *APIServer) handleGetMITRECoverageReal(c *gin.Context) {
	if s.opensearch == nil {
		s.handleGetMITRECoverage(c) // Fallback to mock
		return
	}

	// Query GuardDuty events and aggregate by type
	query := `{
		"size": 0,
		"query": {
			"bool": {
				"should": [
					{"term": {"source.keyword": "AWS GuardDuty"}},
					{"term": {"source": "AWS GuardDuty"}}
				],
				"minimum_should_match": 1
			}
		},
		"aggs": {
			"by_type": {
				"terms": {
					"field": "type.keyword",
					"size": 500
				},
				"aggs": {
					"latest": {
						"max": {"field": "timestamp"}
					},
					"by_severity": {
						"terms": {"field": "severity.keyword", "size": 10}
					}
				}
			}
		}
	}`

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		log.Printf("❌ MITRE: Error querying events: %v", err)
		s.handleGetMITRECoverage(c)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ MITRE: OpenSearch error: %s", res.String())
		s.handleGetMITRECoverage(c)
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	// Process results and map to MITRE
	tacticsCoverage := make(map[string]*TacticCoverage)
	techniquesCovered := make(map[string]bool)
	topTechniques := []TechniqueActivity{}
	recentDetections := 0

	// Initialize all tactics
	allTactics := map[string]string{
		"TA0043": "Reconnaissance",
		"TA0042": "Resource Development",
		"TA0001": "Initial Access",
		"TA0002": "Execution",
		"TA0003": "Persistence",
		"TA0004": "Privilege Escalation",
		"TA0005": "Defense Evasion",
		"TA0006": "Credential Access",
		"TA0007": "Discovery",
		"TA0008": "Lateral Movement",
		"TA0009": "Collection",
		"TA0011": "Command and Control",
		"TA0010": "Exfiltration",
		"TA0040": "Impact",
	}

	// Technique counts per tactic (approximate based on MITRE)
	tacticTechniqueCount := map[string]int{
		"TA0043": 10, "TA0042": 8, "TA0001": 9, "TA0002": 12,
		"TA0003": 19, "TA0004": 13, "TA0005": 42, "TA0006": 17,
		"TA0007": 31, "TA0008": 9, "TA0009": 17, "TA0011": 16,
		"TA0010": 9, "TA0040": 14,
	}

	for tacticID, tacticName := range allTactics {
		tacticsCoverage[tacticID] = &TacticCoverage{
			TacticID:          tacticID,
			TacticName:        tacticName,
			TotalTechniques:   tacticTechniqueCount[tacticID],
			CoveredTechniques: 0,
			CoveragePercentage: 0,
		}
	}

	// Process aggregation results
	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if byType, ok := aggs["by_type"].(map[string]interface{}); ok {
			if buckets, ok := byType["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					eventType := bucket["key"].(string)
					count := int(bucket["doc_count"].(float64))

					// Try to map this event type to MITRE
					mapping := mapEventTypeToMITRE(eventType)
					if mapping != nil {
						techniquesCovered[mapping.TechniqueID] = true
						
						if tc, exists := tacticsCoverage[mapping.TacticID]; exists {
							tc.CoveredTechniques++
						}

						// Get severity from nested aggregation
						severity := "MEDIUM"
						if bySeverity, ok := bucket["by_severity"].(map[string]interface{}); ok {
							if sevBuckets, ok := bySeverity["buckets"].([]interface{}); ok && len(sevBuckets) > 0 {
								sevBucket := sevBuckets[0].(map[string]interface{})
								severity = sevBucket["key"].(string)
							}
						}

						topTechniques = append(topTechniques, TechniqueActivity{
							TechniqueID:   mapping.TechniqueID,
							TechniqueName: mapping.TechniqueName,
							EventCount:    count,
							Severity:      severity,
							TacticID:      mapping.TacticID,
						})
						recentDetections += count
					}
				}
			}
		}
	}

	// Calculate coverage percentages
	totalTactics := len(allTactics)
	coveredTactics := 0
	totalTechniques := 0
	coveredTechniques := len(techniquesCovered)

	for _, tc := range tacticsCoverage {
		totalTechniques += tc.TotalTechniques
		if tc.CoveredTechniques > 0 {
			coveredTactics++
			tc.CoveragePercentage = float64(tc.CoveredTechniques) / float64(tc.TotalTechniques) * 100
		}
	}

	coveragePercentage := 0.0
	if totalTechniques > 0 {
		coveragePercentage = float64(coveredTechniques) / float64(totalTechniques) * 100
	}

	// Convert map to proper format
	tacticsCoverageMap := make(map[string]TacticCoverage)
	for k, v := range tacticsCoverage {
		tacticsCoverageMap[k] = *v
	}

	coverage := MITRECoverage{
		TotalTactics:       totalTactics,
		CoveredTactics:     coveredTactics,
		TotalTechniques:    totalTechniques,
		CoveredTechniques:  coveredTechniques,
		CoveragePercentage: coveragePercentage,
		TacticsCoverage:    tacticsCoverageMap,
		RecentDetections:   recentDetections,
		TopTechniques:      topTechniques,
		CriticalGaps:       []MITRETechnique{},
	}

	c.JSON(http.StatusOK, coverage)
}

// handleGetMITRETimelineReal returns timeline based on real events
func (s *APIServer) handleGetMITRETimelineReal(c *gin.Context) {
	if s.opensearch == nil {
		s.handleGetMITRETimeline(c)
		return
	}

	hoursStr := c.DefaultQuery("hours", "24")
	hours := 24
	if h, err := time.ParseDuration(hoursStr + "h"); err == nil {
		hours = int(h.Hours())
	}

	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"bool": map[string]interface{}{
							"should": []map[string]interface{}{
								{"term": map[string]interface{}{"source.keyword": "AWS GuardDuty"}},
								{"term": map[string]interface{}{"source": "AWS GuardDuty"}},
							},
							"minimum_should_match": 1,
						},
					},
					{
						"range": map[string]interface{}{
							"timestamp": map[string]interface{}{
								"gte": "now-" + hoursStr + "h",
							},
						},
					},
				},
			},
		},
		"aggs": map[string]interface{}{
			"by_hour": map[string]interface{}{
				"date_histogram": map[string]interface{}{
					"field":             "timestamp",
					"calendar_interval": "hour",
				},
				"aggs": map[string]interface{}{
					"by_type": map[string]interface{}{
						"terms": map[string]interface{}{
							"field": "type.keyword",
							"size":  20,
						},
						"aggs": map[string]interface{}{
							"by_severity": map[string]interface{}{
								"terms": map[string]interface{}{
									"field": "severity.keyword",
									"size":  1,
								},
							},
						},
					},
				},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		s.handleGetMITRETimeline(c)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		s.handleGetMITRETimeline(c)
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	timeline := []MITRETimelineEntry{}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if byHour, ok := aggs["by_hour"].(map[string]interface{}); ok {
			if buckets, ok := byHour["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					timestamp := time.Unix(0, int64(bucket["key"].(float64))*int64(time.Millisecond))

					if byType, ok := bucket["by_type"].(map[string]interface{}); ok {
						if typeBuckets, ok := byType["buckets"].([]interface{}); ok {
							for _, tb := range typeBuckets {
								typeBucket := tb.(map[string]interface{})
								eventType := typeBucket["key"].(string)
								count := int(typeBucket["doc_count"].(float64))

								mapping := mapEventTypeToMITRE(eventType)
								if mapping != nil {
									severity := "MEDIUM"
									if bySeverity, ok := typeBucket["by_severity"].(map[string]interface{}); ok {
										if sevBuckets, ok := bySeverity["buckets"].([]interface{}); ok && len(sevBuckets) > 0 {
											severity = sevBuckets[0].(map[string]interface{})["key"].(string)
										}
									}

									timeline = append(timeline, MITRETimelineEntry{
										Timestamp:     timestamp,
										TacticID:      mapping.TacticID,
										TacticName:    mapping.TacticName,
										TechniqueID:   mapping.TechniqueID,
										TechniqueName: mapping.TechniqueName,
										EventCount:    count,
										Severity:      severity,
									})
								}
							}
						}
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"timeline": timeline,
		"hours":    hours,
		"source":   "opensearch",
	})
}

// getEventTypesForMITRETechnique returns all GuardDuty event types that map to a specific MITRE technique
func getEventTypesForMITRETechnique(techniqueID string) []string {
	eventTypes := []string{}
	for eventType, mapping := range GuardDutyMITREMapping {
		if mapping.TechniqueID == techniqueID {
			eventTypes = append(eventTypes, eventType)
		}
	}
	return eventTypes
}

// getEventTypesForMITRETactic returns all GuardDuty event types that map to a specific MITRE tactic
func getEventTypesForMITRETactic(tacticID string) []string {
	eventTypes := []string{}
	for eventType, mapping := range GuardDutyMITREMapping {
		if mapping.TacticID == tacticID {
			eventTypes = append(eventTypes, eventType)
		}
	}
	return eventTypes
}

// getEventTypePrefixesForMITRETechnique returns wildcard prefixes for event types
func getEventTypePrefixesForMITRETechnique(techniqueID string) []string {
	prefixes := []string{}
	
	// Map technique IDs to GuardDuty event type prefixes
	techniquePrefixMap := map[string][]string{
		"T1190": {"Policy:S3/BucketAnonymousAccessGranted", "Policy:S3/BucketPublicAccessGranted", "UnauthorizedAccess:"},
		"T1133": {"UnauthorizedAccess:EC2/", "Backdoor:EC2/"},
		"T1078": {"UnauthorizedAccess:IAMUser/", "InitialAccess:IAMUser/", "Policy:IAMUser/"},
		"T1078.004": {"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration", "Policy:IAMUser/RootCredentialUsage"},
		"T1046": {"Recon:EC2/Port", "Impact:EC2/PortSweep"},
		"T1087": {"Recon:IAMUser/", "Discovery:"},
		"T1590": {"Recon:IAMUser/MaliciousIPCaller", "Recon:IAMUser/TorIPCaller"},
		"T1619": {"Discovery:S3/"},
		"T1204": {"Execution:EC2/SuspiciousFile", "Execution:EC2/MaliciousFile", "Execution:Container/"},
		"T1609": {"Execution:Kubernetes/ExecInKubeSystemPod"},
		"T1610": {"Execution:Kubernetes/AnomalousBehavior", "DefenseEvasion:Kubernetes/"},
		"T1059": {"Execution:Runtime/NewBinaryExecuted", "Execution:Runtime/SuspiciousTool", "Execution:Runtime/SuspiciousCommand", "Execution:Runtime/ReverseShell"},
		"T1055": {"Execution:Runtime/NewLibraryLoaded", "Execution:Runtime/ProcessInjection"},
		"T1203": {"Execution:Runtime/MaliciousFileExecuted", "Execution:EC2/Malware"},
		"T1098": {"Persistence:IAMUser/"},
		"T1525": {"Persistence:Kubernetes/"},
		"T1611": {"PrivilegeEscalation:Kubernetes/", "PrivilegeEscalation:Runtime/"},
		"T1068": {"PrivilegeEscalation:Runtime/UserfaultfdUsage"},
		"T1095": {"DefenseEvasion:EC2/UnusualNetworkProtocol", "Backdoor:EC2/DenialOfService.Udp"},
		"T1071": {"Backdoor:EC2/C&CActivity", "Trojan:EC2/BlackholeTraffic", "Trojan:EC2/DropPoint"},
		"T1071.001": {"Backdoor:EC2/DenialOfService.Tcp"},
		"T1071.003": {"Backdoor:EC2/Spambot"},
		"T1071.004": {"DefenseEvasion:EC2/UnusualDNSResolver", "Backdoor:EC2/C&CActivity.B!DNS", "Trojan:EC2/"},
		"T1562": {"Stealth:IAMUser/", "Policy:S3/AccountBlockPublicAccessDisabled", "Policy:S3/BucketBlockPublicAccessDisabled"},
		"T1562.008": {"Stealth:IAMUser/CloudTrailLoggingDisabled", "Stealth:IAMUser/LoggingConfigurationModified", "Stealth:S3/"},
		"T1528": {"CredentialAccess:IAMUser/"},
		"T1552": {"CredentialAccess:Kubernetes/MaliciousIPCaller"},
		"T1552.007": {"CredentialAccess:Kubernetes/AnomalousBehavior"},
		"T1110": {"CredentialAccess:RDS/", "Impact:EC2/WinRMBruteForce"},
		"T1530": {"Exfiltration:S3/", "Exfiltration:IAMUser/"},
		"T1568.002": {"Trojan:EC2/DGADomainRequest"},
		"T1496": {"CryptoCurrency:EC2/"},
		"T1499": {"Impact:Kubernetes/", "Impact:Runtime/"},
		"T1485": {"Impact:S3/"},
		"T1053": {"Persistence:Runtime/ScheduledTask", "Execution:Runtime/ScheduledTask"},
	}
	
	if p, ok := techniquePrefixMap[techniqueID]; ok {
		prefixes = append(prefixes, p...)
	}
	
	return prefixes
}

// handleGetMITREDetectionsReal returns detections based on real events with full details
// This function uses the SAME mapping logic as the coverage function to ensure consistency
func (s *APIServer) handleGetMITREDetectionsReal(c *gin.Context) {
	if s.opensearch == nil {
		s.handleGetMITREDetections(c)
		return
	}

	techniqueID := c.Query("technique_id")
	tacticID := c.Query("tactic_id")
	limitStr := c.DefaultQuery("limit", "100")
	limit := 100
	if l, err := parseIntSafe(limitStr); err == nil && l > 0 {
		limit = l
		if limit > 500 {
			limit = 500
		}
	}

	log.Printf("🔍 MITRE Detections: techniqueID=%s, tacticID=%s, limit=%d", techniqueID, tacticID, limit)

	// STRATEGY: Fetch ALL GuardDuty/Security Hub events and filter using mapEventTypeToMITRE
	// This ensures consistency with the coverage calculation
	
	// Calculate how many events to fetch - we need enough to find matches
	// If filtering by technique, fetch more since we'll filter many out
	fetchSize := limit * 20  // Fetch 20x more to ensure we find enough matches
	if fetchSize > 5000 {
		fetchSize = 5000
	}
	if techniqueID == "" && tacticID == "" {
		fetchSize = limit * 3
		if fetchSize > 1000 {
			fetchSize = 1000
		}
	}

	query := map[string]interface{}{
		"size": fetchSize,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"term": map[string]interface{}{"source.keyword": "AWS GuardDuty"}},
					{"term": map[string]interface{}{"source": "AWS GuardDuty"}},
					{"term": map[string]interface{}{"source.keyword": "AWS Security Hub"}},
					{"term": map[string]interface{}{"source": "AWS Security Hub"}},
				},
				"minimum_should_match": 1,
			},
		},
	}

	queryJSON, _ := json.Marshal(query)
	log.Printf("🔍 MITRE Query (fetching %d events): %s", fetchSize, string(queryJSON))

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		log.Printf("❌ MITRE Detections: OpenSearch query error: %v", err)
		s.handleGetMITREDetections(c)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("❌ MITRE Detections: OpenSearch response error: %s", res.String())
		s.handleGetMITREDetections(c)
		return
	}

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	detections := []MITREDetectionReal{}
	totalHits := 0
	processedCount := 0
	matchedCount := 0
	filteredOutCount := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			if val, ok := total["value"].(float64); ok {
				totalHits = int(val)
			}
		}
		
		if hitsArr, ok := hits["hits"].([]interface{}); ok {
			log.Printf("🔍 MITRE: Processing %d hits (total in DB: %d)", len(hitsArr), totalHits)
			
			for _, h := range hitsArr {
				processedCount++
				hit := h.(map[string]interface{})
				source := hit["_source"].(map[string]interface{})

				eventType := getStrVal(source, "type")
				
				// Use the SAME mapping function as coverage to ensure consistency
				mapping := mapEventTypeToMITRE(eventType)

				if mapping == nil {
					continue
				}
				
				matchedCount++

				// Filter by technique if specified
				if techniqueID != "" && mapping.TechniqueID != techniqueID {
					filteredOutCount++
					continue
				}
				
				// Filter by tactic if specified
				if tacticID != "" && mapping.TacticID != tacticID {
					filteredOutCount++
					continue
				}

				var timestamp time.Time
				if ts := getStrVal(source, "timestamp"); ts != "" {
					timestamp, _ = time.Parse(time.RFC3339, ts)
				}

				// Extract enhanced details from the event
				detection := extractMITREDetectionDetails(hit["_id"].(string), source, mapping, timestamp)
				detections = append(detections, detection)
				
				// Stop if we have enough
				if len(detections) >= limit {
					break
				}
			}
		}
	}

	log.Printf("✅ MITRE: Processed=%d, Matched=%d, FilteredOut=%d, Returning=%d for technique=%s, tactic=%s", 
		processedCount, matchedCount, filteredOutCount, len(detections), techniqueID, tacticID)

	c.JSON(http.StatusOK, gin.H{
		"detections":       detections,
		"total":            len(detections),
		"total_hits":       totalHits,
		"processed_count":  processedCount,
		"matched_count":    matchedCount,
		"filtered_out":     filteredOutCount,
		"technique_id":     techniqueID,
		"tactic_id":        tacticID,
		"source":           "opensearch",
	})
}

// extractMITREDetectionDetails extracts detailed information from an event for MITRE detection
func extractMITREDetectionDetails(docID string, source map[string]interface{}, mapping *MITREMapping, timestamp time.Time) MITREDetectionReal {
	detection := MITREDetectionReal{
		ID:            docID,
		TechniqueID:   mapping.TechniqueID,
		TechniqueName: mapping.TechniqueName,
		TacticID:      mapping.TacticID,
		TacticName:    mapping.TacticName,
		EventID:       getStrVal(source, "id"),
		EventType:     getStrVal(source, "type"),
		Timestamp:     timestamp,
		Severity:      getStrVal(source, "severity"),
		Source:        getStrVal(source, "source"),
		Description:   getStrVal(source, "description"),
		Count:         1,
	}

	// Extract user information from various fields
	if user := getStrVal(source, "user"); user != "" {
		detection.User = user
	} else if user := getStrVal(source, "username"); user != "" {
		detection.User = user
	} else if user := getStrVal(source, "principalId"); user != "" {
		detection.User = user
	}

	// Extract source IP
	if ip := getStrVal(source, "source_ip"); ip != "" {
		detection.SourceIP = ip
	} else if ip := getStrVal(source, "sourceIPAddress"); ip != "" {
		detection.SourceIP = ip
	}

	// Extract region
	if region := getStrVal(source, "region"); region != "" {
		detection.Region = region
	} else if region := getStrVal(source, "awsRegion"); region != "" {
		detection.Region = region
	}

	// Extract account ID
	if accountID := getStrVal(source, "accountId"); accountID != "" {
		detection.AccountID = accountID
	} else if accountID := getStrVal(source, "account_id"); accountID != "" {
		detection.AccountID = accountID
	}

	// Extract details from nested 'details' field (GuardDuty findings have this)
	if details, ok := source["details"].(map[string]interface{}); ok {
		detection.RawDetails = details
		
		// Extract user from details
		if detection.User == "" {
			if user := getNestedStr(details, "userIdentity", "userName"); user != "" {
				detection.User = user
			} else if user := getNestedStr(details, "userIdentity", "principalId"); user != "" {
				detection.User = user
			} else if user := getNestedStr(details, "actor", "name"); user != "" {
				detection.User = user
			}
		}

		// Extract IP from details
		if detection.SourceIP == "" {
			if ip := getNestedStr(details, "service", "action", "networkConnectionAction", "remoteIpDetails", "ipAddressV4"); ip != "" {
				detection.SourceIP = ip
			} else if ip := getNestedStr(details, "remoteIpDetails", "ipAddressV4"); ip != "" {
				detection.SourceIP = ip
			} else if ip := getNestedStr(details, "action", "remoteIpDetails", "ipAddressV4"); ip != "" {
				detection.SourceIP = ip
			}
		}

		// Extract destination IP
		if destIP := getNestedStr(details, "service", "action", "networkConnectionAction", "localIpDetails", "ipAddressV4"); destIP != "" {
			detection.DestinationIP = destIP
		}

		// Extract resource information
		if resourceType := getNestedStr(details, "resource", "resourceType"); resourceType != "" {
			detection.ResourceType = resourceType
		}
		
		// Instance details
		if instanceID := getNestedStr(details, "resource", "instanceDetails", "instanceId"); instanceID != "" {
			detection.ResourceID = instanceID
			if detection.ResourceType == "" {
				detection.ResourceType = "EC2 Instance"
			}
		}

		// S3 bucket details
		if bucketName := getNestedStr(details, "resource", "s3BucketDetails", "name"); bucketName != "" {
			detection.ResourceID = bucketName
			if detection.ResourceType == "" {
				detection.ResourceType = "S3 Bucket"
			}
		}

		// Access key details
		if accessKeyID := getNestedStr(details, "resource", "accessKeyDetails", "accessKeyId"); accessKeyID != "" {
			if detection.ResourceID == "" {
				detection.ResourceID = accessKeyID
			}
			if detection.ResourceType == "" {
				detection.ResourceType = "IAM Access Key"
			}
			if userName := getNestedStr(details, "resource", "accessKeyDetails", "userName"); userName != "" {
				if detection.User == "" {
					detection.User = userName
				}
			}
		}

		// EKS details
		if clusterName := getNestedStr(details, "resource", "eksClusterDetails", "name"); clusterName != "" {
			detection.ResourceID = clusterName
			if detection.ResourceType == "" {
				detection.ResourceType = "EKS Cluster"
			}
		}

		// Kubernetes workload details
		if workloadName := getNestedStr(details, "resource", "kubernetesDetails", "kubernetesWorkloadDetails", "name"); workloadName != "" {
			if detection.ResourceID == "" {
				detection.ResourceID = workloadName
			}
			if detection.ResourceType == "" {
				detection.ResourceType = "Kubernetes Workload"
			}
		}

		// Container details
		if containerID := getNestedStr(details, "resource", "containerDetails", "id"); containerID != "" {
			if detection.ResourceID == "" {
				detection.ResourceID = containerID
			}
			if detection.ResourceType == "" {
				detection.ResourceType = "Container"
			}
		}

		// RDS details
		if dbInstanceID := getNestedStr(details, "resource", "rdsDbInstanceDetails", "dbInstanceIdentifier"); dbInstanceID != "" {
			detection.ResourceID = dbInstanceID
			if detection.ResourceType == "" {
				detection.ResourceType = "RDS Instance"
			}
		}

		// Lambda details
		if functionARN := getNestedStr(details, "resource", "lambdaDetails", "functionArn"); functionARN != "" {
			detection.ResourceARN = functionARN
			if detection.ResourceType == "" {
				detection.ResourceType = "Lambda Function"
			}
		}

		// Extract port and protocol
		if port := getNestedFloat(details, "service", "action", "networkConnectionAction", "remotePortDetails", "port"); port > 0 {
			detection.Port = int(port)
		} else if port := getNestedFloat(details, "service", "action", "portProbeAction", "portProbeDetails", "remoteIpDetails", "port"); port > 0 {
			detection.Port = int(port)
		}
		
		if protocol := getNestedStr(details, "service", "action", "networkConnectionAction", "protocol"); protocol != "" {
			detection.Protocol = protocol
		}

		// Extract action name
		if actionType := getNestedStr(details, "service", "action", "actionType"); actionType != "" {
			detection.Action = actionType
		}

		// Extract threat information
		if threatName := getNestedStr(details, "service", "additionalInfo", "threatName"); threatName != "" {
			detection.ThreatName = threatName
		}
		if threatListName := getNestedStr(details, "service", "additionalInfo", "threatListName"); threatListName != "" {
			detection.ThreatListName = threatListName
		}

		// Extract region from details
		if detection.Region == "" {
			if region := getStrVal(details, "region"); region != "" {
				detection.Region = region
			}
		}

		// Extract account ID from details
		if detection.AccountID == "" {
			if accountID := getStrVal(details, "accountId"); accountID != "" {
				detection.AccountID = accountID
			}
		}
	}

	return detection
}

// getNestedStr safely gets a nested string value from a map
func getNestedStr(m map[string]interface{}, keys ...string) string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key, return string value
			if val, ok := current[key].(string); ok {
				return val
			}
			return ""
		}
		// Not last key, traverse deeper
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else if arr, ok := current[key].([]interface{}); ok && len(arr) > 0 {
			// Handle array (take first element)
			if next, ok := arr[0].(map[string]interface{}); ok {
				current = next
			} else {
				return ""
			}
		} else {
			return ""
		}
	}
	return ""
}

// getNestedFloat safely gets a nested float value from a map
func getNestedFloat(m map[string]interface{}, keys ...string) float64 {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key, return float value
			if val, ok := current[key].(float64); ok {
				return val
			}
			return 0
		}
		// Not last key, traverse deeper
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else if arr, ok := current[key].([]interface{}); ok && len(arr) > 0 {
			// Handle array (take first element)
			if next, ok := arr[0].(map[string]interface{}); ok {
				current = next
			} else {
				return 0
			}
		} else {
			return 0
		}
	}
	return 0
}

// parseIntSafe safely parses an integer string
func parseIntSafe(s string) (int, error) {
	return strconv.Atoi(s)
}

// handleMITREDiagnostics provides diagnostic information about MITRE mappings
func (s *APIServer) handleMITREDiagnostics(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusOK, gin.H{
			"error": "OpenSearch not configured",
		})
		return
	}

	// Get all unique event types from GuardDuty/Security Hub events
	query := `{
		"size": 0,
		"query": {
			"bool": {
				"should": [
					{"term": {"source.keyword": "AWS GuardDuty"}},
					{"term": {"source": "AWS GuardDuty"}},
					{"term": {"source.keyword": "AWS Security Hub"}},
					{"term": {"source": "AWS Security Hub"}}
				],
				"minimum_should_match": 1
			}
		},
		"aggs": {
			"event_types": {
				"terms": {
					"field": "type.keyword",
					"size": 500
				}
			},
			"event_types_text": {
				"terms": {
					"field": "type",
					"size": 500
				}
			}
		}
	}`

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-events"),
		s.opensearch.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	eventTypes := []map[string]interface{}{}
	unmappedTypes := []string{}
	mappedTypes := []map[string]interface{}{}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		// Try keyword field first
		aggField := "event_types"
		if etAgg, ok := aggs[aggField].(map[string]interface{}); ok {
			if buckets, ok := etAgg["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					eventType := bucket["key"].(string)
					count := int(bucket["doc_count"].(float64))
					
					mapping := mapEventTypeToMITRE(eventType)
					
					entry := map[string]interface{}{
						"event_type": eventType,
						"count":      count,
					}
					
					if mapping != nil {
						entry["technique_id"] = mapping.TechniqueID
						entry["technique_name"] = mapping.TechniqueName
						entry["tactic_id"] = mapping.TacticID
						entry["tactic_name"] = mapping.TacticName
						mappedTypes = append(mappedTypes, entry)
					} else {
						unmappedTypes = append(unmappedTypes, eventType)
					}
					
					eventTypes = append(eventTypes, entry)
				}
			}
		}
		
		// Also try text field if keyword didn't return results
		if len(eventTypes) == 0 {
			if etAgg, ok := aggs["event_types_text"].(map[string]interface{}); ok {
				if buckets, ok := etAgg["buckets"].([]interface{}); ok {
					for _, b := range buckets {
						bucket := b.(map[string]interface{})
						eventType := bucket["key"].(string)
						count := int(bucket["doc_count"].(float64))
						
						mapping := mapEventTypeToMITRE(eventType)
						
						entry := map[string]interface{}{
							"event_type": eventType,
							"count":      count,
						}
						
						if mapping != nil {
							entry["technique_id"] = mapping.TechniqueID
							entry["technique_name"] = mapping.TechniqueName
							entry["tactic_id"] = mapping.TacticID
							entry["tactic_name"] = mapping.TacticName
							mappedTypes = append(mappedTypes, entry)
						} else {
							unmappedTypes = append(unmappedTypes, eventType)
						}
						
						eventTypes = append(eventTypes, entry)
					}
				}
			}
		}
	}

	// Group mapped types by technique
	byTechnique := make(map[string][]map[string]interface{})
	for _, mt := range mappedTypes {
		techID := mt["technique_id"].(string)
		byTechnique[techID] = append(byTechnique[techID], mt)
	}

	c.JSON(http.StatusOK, gin.H{
		"total_event_types":   len(eventTypes),
		"mapped_count":        len(mappedTypes),
		"unmapped_count":      len(unmappedTypes),
		"all_event_types":     eventTypes,
		"mapped_types":        mappedTypes,
		"unmapped_types":      unmappedTypes,
		"by_technique":        byTechnique,
	})
}

// mapEventTypeToMITRE maps an event type to MITRE technique
func mapEventTypeToMITRE(eventType string) *MITREMapping {
	// Direct match
	if mapping, ok := GuardDutyMITREMapping[eventType]; ok {
		return &mapping
	}

	// Try partial match (GuardDuty types can have variations)
	eventTypeLower := strings.ToLower(eventType)
	
	// Check for common patterns
	for key, mapping := range GuardDutyMITREMapping {
		keyLower := strings.ToLower(key)
		// Check if the event type starts with the key pattern
		if strings.HasPrefix(eventTypeLower, strings.Split(keyLower, ".")[0]) {
			return &mapping
		}
	}

	// Map by category prefix
	switch {
	case strings.HasPrefix(eventType, "Recon:"):
		return &MITREMapping{TechniqueID: "T1595", TechniqueName: "Active Scanning", TacticID: "TA0043", TacticName: "Reconnaissance"}
	case strings.HasPrefix(eventType, "UnauthorizedAccess:"):
		return &MITREMapping{TechniqueID: "T1078", TechniqueName: "Valid Accounts", TacticID: "TA0001", TacticName: "Initial Access"}
	case strings.HasPrefix(eventType, "Execution:"):
		return &MITREMapping{TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter", TacticID: "TA0002", TacticName: "Execution"}
	case strings.HasPrefix(eventType, "Persistence:"):
		return &MITREMapping{TechniqueID: "T1098", TechniqueName: "Account Manipulation", TacticID: "TA0003", TacticName: "Persistence"}
	case strings.HasPrefix(eventType, "PrivilegeEscalation:"):
		return &MITREMapping{TechniqueID: "T1068", TechniqueName: "Exploitation for Privilege Escalation", TacticID: "TA0004", TacticName: "Privilege Escalation"}
	case strings.HasPrefix(eventType, "DefenseEvasion:"), strings.HasPrefix(eventType, "Stealth:"):
		return &MITREMapping{TechniqueID: "T1562", TechniqueName: "Impair Defenses", TacticID: "TA0005", TacticName: "Defense Evasion"}
	case strings.HasPrefix(eventType, "CredentialAccess:"):
		return &MITREMapping{TechniqueID: "T1552", TechniqueName: "Unsecured Credentials", TacticID: "TA0006", TacticName: "Credential Access"}
	case strings.HasPrefix(eventType, "Discovery:"):
		return &MITREMapping{TechniqueID: "T1087", TechniqueName: "Account Discovery", TacticID: "TA0007", TacticName: "Discovery"}
	case strings.HasPrefix(eventType, "Exfiltration:"):
		return &MITREMapping{TechniqueID: "T1530", TechniqueName: "Data from Cloud Storage Object", TacticID: "TA0009", TacticName: "Collection"}
	case strings.HasPrefix(eventType, "Backdoor:"), strings.HasPrefix(eventType, "Trojan:"):
		return &MITREMapping{TechniqueID: "T1071", TechniqueName: "Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control"}
	case strings.HasPrefix(eventType, "Impact:"), strings.HasPrefix(eventType, "CryptoCurrency:"):
		return &MITREMapping{TechniqueID: "T1496", TechniqueName: "Resource Hijacking", TacticID: "TA0040", TacticName: "Impact"}
	case strings.HasPrefix(eventType, "Policy:"):
		return &MITREMapping{TechniqueID: "T1562", TechniqueName: "Impair Defenses", TacticID: "TA0005", TacticName: "Defense Evasion"}
	}

	return nil
}

