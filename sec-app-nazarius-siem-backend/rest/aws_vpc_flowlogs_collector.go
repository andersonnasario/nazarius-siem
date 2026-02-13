package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/opensearch-project/opensearch-go/v2"
)

// ============================================================================
// AWS VPC FLOW LOGS COLLECTOR
// ============================================================================
// Collects and analyzes VPC Flow Logs from S3 for network traffic analysis
// Supports detection of:
// - Data exfiltration
// - C2 communication
// - Port scanning
// - Lateral movement
// - Unusual traffic patterns

// VPCFlowLog represents a single VPC Flow Log record
type VPCFlowLog struct {
	ID                string    `json:"id"`
	Version           int       `json:"version"`
	AccountID         string    `json:"account_id"`
	InterfaceID       string    `json:"interface_id"`
	SourceIP          string    `json:"source_ip"`
	DestIP            string    `json:"dest_ip"`
	SourcePort        int       `json:"source_port"`
	DestPort          int       `json:"dest_port"`
	Protocol          int       `json:"protocol"`
	ProtocolName      string    `json:"protocol_name"`
	Packets           int64     `json:"packets"`
	Bytes             int64     `json:"bytes"`
	StartTime         time.Time `json:"start_time"`
	EndTime           time.Time `json:"end_time"`
	Action            string    `json:"action"` // ACCEPT, REJECT
	LogStatus         string    `json:"log_status"`
	
	// Enhanced fields (v3+)
	VPCID             string    `json:"vpc_id,omitempty"`
	SubnetID          string    `json:"subnet_id,omitempty"`
	InstanceID        string    `json:"instance_id,omitempty"`
	TCPFlags          int       `json:"tcp_flags,omitempty"`
	TrafficType       string    `json:"traffic_type,omitempty"` // IPv4, IPv6
	PacketSourceAddr  string    `json:"pkt_src_addr,omitempty"`
	PacketDestAddr    string    `json:"pkt_dst_addr,omitempty"`
	Region            string    `json:"region,omitempty"`
	AZId              string    `json:"az_id,omitempty"`
	SublocationID     string    `json:"sublocation_id,omitempty"`
	SublocationTypes  string    `json:"sublocation_type,omitempty"`
	
	// Analysis fields
	Direction         string    `json:"direction"` // inbound, outbound, internal
	IsPrivateSource   bool      `json:"is_private_source"`
	IsPrivateDest     bool      `json:"is_private_dest"`
	GeoSourceCountry  string    `json:"geo_source_country,omitempty"`
	GeoDestCountry    string    `json:"geo_dest_country,omitempty"`
	ThreatIndicators  []string  `json:"threat_indicators,omitempty"`
	RiskScore         int       `json:"risk_score"`
	
	// SIEM metadata
	Timestamp         time.Time `json:"timestamp"`
	Source            string    `json:"source"`
	IndexedAt         time.Time `json:"indexed_at"`
}

// NetworkAnomaly represents a detected network anomaly
type NetworkAnomalyDetection struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	SourceIP        string                 `json:"source_ip,omitempty"`
	DestIP          string                 `json:"dest_ip,omitempty"`
	Port            int                    `json:"port,omitempty"`
	Protocol        string                 `json:"protocol,omitempty"`
	FlowCount       int                    `json:"flow_count"`
	TotalBytes      int64                  `json:"total_bytes"`
	TotalPackets    int64                  `json:"total_packets"`
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
	RelatedFlows    []string               `json:"related_flows,omitempty"`
	MITRETechnique  string                 `json:"mitre_technique,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
	RawData         map[string]interface{} `json:"raw_data,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
}

// VPCFlowLogsCollector collects and processes VPC Flow Logs
type VPCFlowLogsCollector struct {
	s3Client      *s3.S3
	opensearch    *opensearch.Client
	bucket        string
	prefix        string
	region        string
	mu            sync.RWMutex
	lastProcessed time.Time
	stats         FlowLogStats
}

// FlowLogStats tracks collection statistics
type FlowLogStats struct {
	TotalFlows       int64     `json:"total_flows"`
	AcceptedFlows    int64     `json:"accepted_flows"`
	RejectedFlows    int64     `json:"rejected_flows"`
	TotalBytes       int64     `json:"total_bytes"`
	AnomaliesFound   int       `json:"anomalies_found"`
	LastCollection   time.Time `json:"last_collection"`
	FilesProcessed   int       `json:"files_processed"`
}

var (
	vpcFlowCollector     *VPCFlowLogsCollector
	vpcFlowCollectorOnce sync.Once
)

// Known malicious ports for detection
var suspiciousPorts = map[int]string{
	4444:  "Metasploit default",
	5555:  "Android Debug Bridge",
	6666:  "IRC (often C2)",
	6667:  "IRC (often C2)",
	1337:  "Common backdoor",
	31337: "Back Orifice",
	12345: "NetBus",
	27374: "SubSeven",
	20000: "Millennium",
	23:    "Telnet",
	445:   "SMB (lateral movement)",
	3389:  "RDP",
	5900:  "VNC",
	22:    "SSH (if unusual)",
}

// Private IP ranges
var privateIPRanges = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("127.0.0.0/8"),
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, _ := net.ParseCIDR(s)
	return ipnet
}

// InitVPCFlowLogsCollector initializes the VPC Flow Logs collector
func InitVPCFlowLogsCollector(bucket, prefix, region string, osClient *opensearch.Client) (*VPCFlowLogsCollector, error) {
	var initErr error
	vpcFlowCollectorOnce.Do(func() {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(region),
		})
		if err != nil {
			initErr = fmt.Errorf("failed to create AWS session: %v", err)
			return
		}

		vpcFlowCollector = &VPCFlowLogsCollector{
			s3Client:   s3.New(sess),
			opensearch: osClient,
			bucket:     bucket,
			prefix:     prefix,
			region:     region,
		}

		log.Printf("✅ VPC Flow Logs Collector initialized - Bucket: %s, Prefix: %s", bucket, prefix)
	})

	return vpcFlowCollector, initErr
}

// GetVPCFlowLogsCollector returns the singleton instance
func GetVPCFlowLogsCollector() *VPCFlowLogsCollector {
	return vpcFlowCollector
}

// CollectFlowLogs collects and processes flow logs from S3
func (vc *VPCFlowLogsCollector) CollectFlowLogs(hoursBack int) ([]VPCFlowLog, error) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	log.Printf("🔍 Collecting VPC Flow Logs from last %d hours...", hoursBack)

	startTime := time.Now().Add(-time.Duration(hoursBack) * time.Hour)
	var allFlows []VPCFlowLog

	// List objects in S3
	listInput := &s3.ListObjectsV2Input{
		Bucket: aws.String(vc.bucket),
		Prefix: aws.String(vc.prefix),
	}

	err := vc.s3Client.ListObjectsV2Pages(listInput, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, obj := range page.Contents {
			// Skip if older than our time window
			if obj.LastModified.Before(startTime) {
				continue
			}

			// Process this log file
			flows, err := vc.processLogFile(aws.StringValue(obj.Key))
			if err != nil {
				log.Printf("⚠️ Failed to process %s: %v", aws.StringValue(obj.Key), err)
				continue
			}

			allFlows = append(allFlows, flows...)
			vc.stats.FilesProcessed++
		}
		return true
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list S3 objects: %v", err)
	}

	vc.stats.LastCollection = time.Now()
	vc.stats.TotalFlows += int64(len(allFlows))
	vc.lastProcessed = time.Now()

	log.Printf("✅ Collected %d flow logs from %d files", len(allFlows), vc.stats.FilesProcessed)

	return allFlows, nil
}

// processLogFile processes a single VPC Flow Log file from S3
func (vc *VPCFlowLogsCollector) processLogFile(key string) ([]VPCFlowLog, error) {
	getInput := &s3.GetObjectInput{
		Bucket: aws.String(vc.bucket),
		Key:    aws.String(key),
	}

	result, err := vc.s3Client.GetObject(getInput)
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()

	var reader io.Reader = result.Body

	// Handle gzip compressed files
	if strings.HasSuffix(key, ".gz") {
		gzReader, err := gzip.NewReader(result.Body)
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()
		reader = gzReader
	}

	return vc.parseFlowLogs(reader)
}

// parseFlowLogs parses VPC Flow Log records
func (vc *VPCFlowLogsCollector) parseFlowLogs(reader io.Reader) ([]VPCFlowLog, error) {
	var flows []VPCFlowLog
	scanner := bufio.NewScanner(reader)

	// Skip header line
	headerSkipped := false
	var fieldOrder []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// First line is header
		if !headerSkipped {
			fieldOrder = strings.Fields(line)
			headerSkipped = true
			continue
		}

		flow, err := vc.parseFlowLine(line, fieldOrder)
		if err != nil {
			continue // Skip malformed lines
		}

		// Enrich flow data
		vc.enrichFlowData(flow)

		flows = append(flows, *flow)
	}

	return flows, scanner.Err()
}

// parseFlowLine parses a single flow log line
func (vc *VPCFlowLogsCollector) parseFlowLine(line string, fieldOrder []string) (*VPCFlowLog, error) {
	fields := strings.Fields(line)
	if len(fields) < 14 {
		return nil, fmt.Errorf("insufficient fields: %d", len(fields))
	}

	flow := &VPCFlowLog{
		Source:    "VPC Flow Logs",
		IndexedAt: time.Now(),
		Timestamp: time.Now(),
	}

	// Parse based on field order or standard format
	fieldMap := make(map[string]string)
	for i, field := range fields {
		if i < len(fieldOrder) {
			fieldMap[fieldOrder[i]] = field
		}
	}

	// Standard v2 format parsing
	if len(fieldOrder) == 0 {
		// Default v2 format
		flow.Version, _ = strconv.Atoi(fields[0])
		flow.AccountID = fields[1]
		flow.InterfaceID = fields[2]
		flow.SourceIP = fields[3]
		flow.DestIP = fields[4]
		flow.SourcePort, _ = strconv.Atoi(fields[5])
		flow.DestPort, _ = strconv.Atoi(fields[6])
		flow.Protocol, _ = strconv.Atoi(fields[7])
		flow.Packets, _ = strconv.ParseInt(fields[8], 10, 64)
		flow.Bytes, _ = strconv.ParseInt(fields[9], 10, 64)
		startUnix, _ := strconv.ParseInt(fields[10], 10, 64)
		endUnix, _ := strconv.ParseInt(fields[11], 10, 64)
		flow.StartTime = time.Unix(startUnix, 0)
		flow.EndTime = time.Unix(endUnix, 0)
		flow.Action = fields[12]
		flow.LogStatus = fields[13]
	} else {
		// Parse using field order
		if v, ok := fieldMap["version"]; ok {
			flow.Version, _ = strconv.Atoi(v)
		}
		if v, ok := fieldMap["account-id"]; ok {
			flow.AccountID = v
		}
		if v, ok := fieldMap["interface-id"]; ok {
			flow.InterfaceID = v
		}
		if v, ok := fieldMap["srcaddr"]; ok {
			flow.SourceIP = v
		}
		if v, ok := fieldMap["dstaddr"]; ok {
			flow.DestIP = v
		}
		if v, ok := fieldMap["srcport"]; ok {
			flow.SourcePort, _ = strconv.Atoi(v)
		}
		if v, ok := fieldMap["dstport"]; ok {
			flow.DestPort, _ = strconv.Atoi(v)
		}
		if v, ok := fieldMap["protocol"]; ok {
			flow.Protocol, _ = strconv.Atoi(v)
		}
		if v, ok := fieldMap["packets"]; ok {
			flow.Packets, _ = strconv.ParseInt(v, 10, 64)
		}
		if v, ok := fieldMap["bytes"]; ok {
			flow.Bytes, _ = strconv.ParseInt(v, 10, 64)
		}
		if v, ok := fieldMap["start"]; ok {
			startUnix, _ := strconv.ParseInt(v, 10, 64)
			flow.StartTime = time.Unix(startUnix, 0)
		}
		if v, ok := fieldMap["end"]; ok {
			endUnix, _ := strconv.ParseInt(v, 10, 64)
			flow.EndTime = time.Unix(endUnix, 0)
		}
		if v, ok := fieldMap["action"]; ok {
			flow.Action = v
		}
		if v, ok := fieldMap["log-status"]; ok {
			flow.LogStatus = v
		}
		// Enhanced fields
		if v, ok := fieldMap["vpc-id"]; ok {
			flow.VPCID = v
		}
		if v, ok := fieldMap["subnet-id"]; ok {
			flow.SubnetID = v
		}
		if v, ok := fieldMap["instance-id"]; ok {
			flow.InstanceID = v
		}
		if v, ok := fieldMap["tcp-flags"]; ok {
			flow.TCPFlags, _ = strconv.Atoi(v)
		}
		if v, ok := fieldMap["region"]; ok {
			flow.Region = v
		}
		if v, ok := fieldMap["az-id"]; ok {
			flow.AZId = v
		}
	}

	// Generate unique ID
	flow.ID = fmt.Sprintf("flow-%s-%s-%d-%d-%d",
		flow.InterfaceID,
		flow.StartTime.Format("20060102150405"),
		flow.SourcePort,
		flow.DestPort,
		flow.Protocol)

	// Set timestamp
	flow.Timestamp = flow.StartTime

	return flow, nil
}

// enrichFlowData adds analysis data to a flow
func (vc *VPCFlowLogsCollector) enrichFlowData(flow *VPCFlowLog) {
	// Protocol name
	flow.ProtocolName = getProtocolName(flow.Protocol)

	// Check if IPs are private
	flow.IsPrivateSource = isPrivateIP(flow.SourceIP)
	flow.IsPrivateDest = isPrivateIP(flow.DestIP)

	// Determine direction
	if flow.IsPrivateSource && !flow.IsPrivateDest {
		flow.Direction = "outbound"
	} else if !flow.IsPrivateSource && flow.IsPrivateDest {
		flow.Direction = "inbound"
	} else {
		flow.Direction = "internal"
	}

	// Calculate risk score
	flow.RiskScore = vc.calculateRiskScore(flow)

	// Check for threat indicators
	flow.ThreatIndicators = vc.checkThreatIndicators(flow)

	// Update stats
	if flow.Action == "ACCEPT" {
		vc.stats.AcceptedFlows++
	} else {
		vc.stats.RejectedFlows++
	}
	vc.stats.TotalBytes += flow.Bytes
}

// calculateRiskScore calculates a risk score for a flow
func (vc *VPCFlowLogsCollector) calculateRiskScore(flow *VPCFlowLog) int {
	score := 0

	// Suspicious ports
	if _, ok := suspiciousPorts[flow.DestPort]; ok {
		score += 30
	}

	// Large data transfer outbound
	if flow.Direction == "outbound" && flow.Bytes > 100*1024*1024 { // > 100MB
		score += 25
	}

	// Rejected traffic from external IP
	if flow.Action == "REJECT" && !flow.IsPrivateSource {
		score += 15
	}

	// Uncommon protocols
	if flow.Protocol != 6 && flow.Protocol != 17 { // Not TCP or UDP
		score += 10
	}

	// High port to low port (possible scan)
	if flow.SourcePort > 1024 && flow.DestPort < 1024 {
		score += 5
	}

	// External to internal on sensitive port
	if flow.Direction == "inbound" {
		switch flow.DestPort {
		case 22, 3389, 5900: // SSH, RDP, VNC
			score += 20
		case 445, 139: // SMB
			score += 25
		case 1433, 3306, 5432: // Databases
			score += 30
		}
	}

	if score > 100 {
		score = 100
	}

	return score
}

// checkThreatIndicators checks for known threat indicators
func (vc *VPCFlowLogsCollector) checkThreatIndicators(flow *VPCFlowLog) []string {
	var indicators []string

	// Check suspicious ports
	if portDesc, ok := suspiciousPorts[flow.DestPort]; ok {
		indicators = append(indicators, fmt.Sprintf("Suspicious port: %d (%s)", flow.DestPort, portDesc))
	}

	// Data exfiltration indicator
	if flow.Direction == "outbound" && flow.Bytes > 50*1024*1024 {
		indicators = append(indicators, "Large outbound data transfer")
	}

	// Port scan indicator (many connections to different ports)
	if flow.Action == "REJECT" && flow.Packets < 5 {
		indicators = append(indicators, "Possible port scan attempt")
	}

	// Lateral movement indicator
	if flow.IsPrivateSource && flow.IsPrivateDest && (flow.DestPort == 445 || flow.DestPort == 3389) {
		indicators = append(indicators, "Possible lateral movement")
	}

	// C2 beaconing pattern (regular intervals, small packets)
	if flow.Direction == "outbound" && flow.Packets > 10 && flow.Bytes/flow.Packets < 100 {
		indicators = append(indicators, "Possible C2 beaconing pattern")
	}

	return indicators
}

// DetectAnomalies analyzes flow logs for anomalies
func (vc *VPCFlowLogsCollector) DetectAnomalies(flows []VPCFlowLog) []NetworkAnomalyDetection {
	var anomalies []NetworkAnomalyDetection

	// Group flows by source IP
	sourceIPFlows := make(map[string][]VPCFlowLog)
	for _, flow := range flows {
		sourceIPFlows[flow.SourceIP] = append(sourceIPFlows[flow.SourceIP], flow)
	}

	// Detect port scanning
	for ip, ipFlows := range sourceIPFlows {
		destPorts := make(map[int]bool)
		rejectCount := 0
		for _, flow := range ipFlows {
			destPorts[flow.DestPort] = true
			if flow.Action == "REJECT" {
				rejectCount++
			}
		}

		if len(destPorts) > 20 && rejectCount > 10 {
			anomaly := NetworkAnomalyDetection{
				ID:             fmt.Sprintf("anomaly-portscan-%s-%d", ip, time.Now().Unix()),
				Type:           "port_scan",
				Severity:       "high",
				Description:    fmt.Sprintf("Port scanning detected from %s: %d unique ports, %d rejected connections", ip, len(destPorts), rejectCount),
				SourceIP:       ip,
				FlowCount:      len(ipFlows),
				FirstSeen:      ipFlows[0].StartTime,
				LastSeen:       ipFlows[len(ipFlows)-1].EndTime,
				MITRETechnique: "T1046",
				Recommendations: []string{
					"Block the source IP in the security group",
					"Investigate the source IP for compromise",
					"Review firewall rules for the targeted ports",
				},
				Timestamp: time.Now(),
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	// Detect data exfiltration
	for ip, ipFlows := range sourceIPFlows {
		var totalBytesOut int64
		for _, flow := range ipFlows {
			if flow.Direction == "outbound" {
				totalBytesOut += flow.Bytes
			}
		}

		if totalBytesOut > 1024*1024*1024 { // > 1GB
			anomaly := NetworkAnomalyDetection{
				ID:             fmt.Sprintf("anomaly-exfil-%s-%d", ip, time.Now().Unix()),
				Type:           "data_exfiltration",
				Severity:       "critical",
				Description:    fmt.Sprintf("Large data transfer detected from %s: %.2f GB outbound", ip, float64(totalBytesOut)/(1024*1024*1024)),
				SourceIP:       ip,
				TotalBytes:     totalBytesOut,
				FlowCount:      len(ipFlows),
				MITRETechnique: "T1041",
				Recommendations: []string{
					"Investigate the source instance immediately",
					"Check for unauthorized data access",
					"Review S3 bucket access logs",
					"Consider isolating the instance",
				},
				Timestamp: time.Now(),
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	// Detect C2 communication patterns
	for ip, ipFlows := range sourceIPFlows {
		if isPrivateIP(ip) {
			continue // Skip internal IPs
		}

		// Check for regular interval connections (beaconing)
		if len(ipFlows) >= 10 {
			intervals := make([]time.Duration, 0)
			for i := 1; i < len(ipFlows); i++ {
				intervals = append(intervals, ipFlows[i].StartTime.Sub(ipFlows[i-1].StartTime))
			}

			// Check if intervals are regular (within 10% variance)
			if isRegularInterval(intervals) {
				anomaly := NetworkAnomalyDetection{
					ID:             fmt.Sprintf("anomaly-c2-%s-%d", ip, time.Now().Unix()),
					Type:           "c2_communication",
					Severity:       "critical",
					Description:    fmt.Sprintf("Possible C2 beaconing detected to %s: %d regular interval connections", ip, len(ipFlows)),
					DestIP:         ip,
					FlowCount:      len(ipFlows),
					MITRETechnique: "T1071",
					Recommendations: []string{
						"Block the destination IP immediately",
						"Investigate the source instance for malware",
						"Capture network traffic for analysis",
						"Check for persistence mechanisms",
					},
					Timestamp: time.Now(),
				}
				anomalies = append(anomalies, anomaly)
			}
		}
	}

	// Detect lateral movement
	internalFlows := make(map[string][]VPCFlowLog)
	for _, flow := range flows {
		if flow.IsPrivateSource && flow.IsPrivateDest {
			key := flow.SourceIP
			internalFlows[key] = append(internalFlows[key], flow)
		}
	}

	for ip, ipFlows := range internalFlows {
		destIPs := make(map[string]bool)
		smbRdpCount := 0
		for _, flow := range ipFlows {
			destIPs[flow.DestIP] = true
			if flow.DestPort == 445 || flow.DestPort == 3389 || flow.DestPort == 22 {
				smbRdpCount++
			}
		}

		if len(destIPs) > 5 && smbRdpCount > 10 {
			anomaly := NetworkAnomalyDetection{
				ID:             fmt.Sprintf("anomaly-lateral-%s-%d", ip, time.Now().Unix()),
				Type:           "lateral_movement",
				Severity:       "high",
				Description:    fmt.Sprintf("Possible lateral movement from %s: %d unique internal destinations, %d SMB/RDP/SSH connections", ip, len(destIPs), smbRdpCount),
				SourceIP:       ip,
				FlowCount:      len(ipFlows),
				MITRETechnique: "T1021",
				Recommendations: []string{
					"Isolate the source instance",
					"Check for compromised credentials",
					"Review authentication logs",
					"Scan destination hosts for compromise",
				},
				Timestamp: time.Now(),
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	vc.stats.AnomaliesFound = len(anomalies)
	return anomalies
}

// IndexFlowLogs indexes flow logs into OpenSearch
func (vc *VPCFlowLogsCollector) IndexFlowLogs(flows []VPCFlowLog) error {
	if vc.opensearch == nil {
		return fmt.Errorf("OpenSearch client not initialized")
	}

	log.Printf("📦 Indexing %d flow logs to OpenSearch...", len(flows))

	indexName := "siem-vpc-flowlogs"
	indexed := 0

	for _, flow := range flows {
		docJSON, err := json.Marshal(flow)
		if err != nil {
			continue
		}

		res, err := vc.opensearch.Index(
			indexName,
			strings.NewReader(string(docJSON)),
			vc.opensearch.Index.WithDocumentID(flow.ID),
			vc.opensearch.Index.WithRefresh("false"),
		)
		if err != nil {
			continue
		}
		res.Body.Close()

		if !res.IsError() {
			indexed++
		}
	}

	log.Printf("✅ Indexed %d/%d flow logs", indexed, len(flows))
	return nil
}

// IndexAnomalies indexes detected anomalies
func (vc *VPCFlowLogsCollector) IndexAnomalies(anomalies []NetworkAnomalyDetection) error {
	if vc.opensearch == nil {
		return fmt.Errorf("OpenSearch client not initialized")
	}

	indexName := "siem-network-anomalies"

	for _, anomaly := range anomalies {
		docJSON, err := json.Marshal(anomaly)
		if err != nil {
			continue
		}

		res, err := vc.opensearch.Index(
			indexName,
			strings.NewReader(string(docJSON)),
			vc.opensearch.Index.WithDocumentID(anomaly.ID),
			vc.opensearch.Index.WithRefresh("true"),
		)
		if err != nil {
			continue
		}
		res.Body.Close()
	}

	return nil
}

// GetStats returns collection statistics
func (vc *VPCFlowLogsCollector) GetStats() FlowLogStats {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.stats
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func getProtocolName(protocol int) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("Protocol-%d", protocol)
	}
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, privateRange := range privateIPRanges {
		if privateRange.Contains(ip) {
			return true
		}
	}
	return false
}

func isRegularInterval(intervals []time.Duration) bool {
	if len(intervals) < 5 {
		return false
	}

	// Calculate average
	var sum time.Duration
	for _, interval := range intervals {
		sum += interval
	}
	avg := sum / time.Duration(len(intervals))

	// Check variance (within 20%)
	tolerance := avg / 5
	regularCount := 0
	for _, interval := range intervals {
		if interval > avg-tolerance && interval < avg+tolerance {
			regularCount++
		}
	}

	return float64(regularCount)/float64(len(intervals)) > 0.7
}

// ============================================================================
// OPENSEARCH INDEX MANAGEMENT
// ============================================================================

// EnsureVPCFlowLogsIndex creates the VPC Flow Logs index
func (s *APIServer) EnsureVPCFlowLogsIndex() error {
	if s.opensearch == nil {
		return fmt.Errorf("OpenSearch client not initialized")
	}

	indices := []string{"siem-vpc-flowlogs", "siem-network-anomalies"}

	for _, indexName := range indices {
		res, err := s.opensearch.Indices.Exists([]string{indexName})
		if err != nil {
			return err
		}
		res.Body.Close()

		if res.StatusCode == 200 {
			continue
		}

		mapping := getVPCFlowLogsMapping(indexName)
		res, err = s.opensearch.Indices.Create(
			indexName,
			s.opensearch.Indices.Create.WithBody(strings.NewReader(mapping)),
		)
		if err != nil {
			return err
		}
		res.Body.Close()

		log.Printf("✅ Created index %s", indexName)
	}

	return nil
}

func getVPCFlowLogsMapping(indexName string) string {
	if indexName == "siem-network-anomalies" {
		return `{
			"settings": {
				"number_of_shards": 1,
				"number_of_replicas": 1
			},
			"mappings": {
				"properties": {
					"id": { "type": "keyword" },
					"type": { "type": "keyword" },
					"severity": { "type": "keyword" },
					"description": { "type": "text" },
					"source_ip": { "type": "ip" },
					"dest_ip": { "type": "ip" },
					"port": { "type": "integer" },
					"protocol": { "type": "keyword" },
					"flow_count": { "type": "integer" },
					"total_bytes": { "type": "long" },
					"total_packets": { "type": "long" },
					"first_seen": { "type": "date" },
					"last_seen": { "type": "date" },
					"mitre_technique": { "type": "keyword" },
					"recommendations": { "type": "keyword" },
					"timestamp": { "type": "date" }
				}
			}
		}`
	}

	return `{
		"settings": {
			"number_of_shards": 3,
			"number_of_replicas": 1,
			"index": {
				"refresh_interval": "10s"
			}
		},
		"mappings": {
			"properties": {
				"id": { "type": "keyword" },
				"version": { "type": "integer" },
				"account_id": { "type": "keyword" },
				"interface_id": { "type": "keyword" },
				"source_ip": { "type": "ip" },
				"dest_ip": { "type": "ip" },
				"source_port": { "type": "integer" },
				"dest_port": { "type": "integer" },
				"protocol": { "type": "integer" },
				"protocol_name": { "type": "keyword" },
				"packets": { "type": "long" },
				"bytes": { "type": "long" },
				"start_time": { "type": "date" },
				"end_time": { "type": "date" },
				"action": { "type": "keyword" },
				"log_status": { "type": "keyword" },
				"vpc_id": { "type": "keyword" },
				"subnet_id": { "type": "keyword" },
				"instance_id": { "type": "keyword" },
				"direction": { "type": "keyword" },
				"is_private_source": { "type": "boolean" },
				"is_private_dest": { "type": "boolean" },
				"risk_score": { "type": "integer" },
				"threat_indicators": { "type": "keyword" },
				"timestamp": { "type": "date" },
				"source": { "type": "keyword" },
				"indexed_at": { "type": "date" }
			}
		}
	}`
}

// ============================================================================
// BACKGROUND INDEXER
// ============================================================================

// StartVPCFlowLogsIndexer starts the background VPC Flow Logs indexer
func (s *APIServer) StartVPCFlowLogsIndexer(intervalMinutes int) {
	go func() {
		bucket := os.Getenv("VPC_FLOWLOGS_S3_BUCKET")
		prefix := os.Getenv("VPC_FLOWLOGS_S3_PREFIX")
		region := os.Getenv("AWS_REGION")
		
		if bucket == "" {
			log.Println("⚠️ VPC_FLOWLOGS_S3_BUCKET not set, VPC Flow Logs indexer not started")
			return
		}

		if region == "" {
			region = "us-east-1"
		}

		collector, err := InitVPCFlowLogsCollector(bucket, prefix, region, s.opensearch)
		if err != nil {
			log.Printf("❌ Failed to initialize VPC Flow Logs collector: %v", err)
			return
		}

		// Ensure indices exist
		if err := s.EnsureVPCFlowLogsIndex(); err != nil {
			log.Printf("⚠️ Failed to ensure VPC Flow Logs indices: %v", err)
		}

		ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
		defer ticker.Stop()

		// Initial collection
		flows, err := collector.CollectFlowLogs(1) // Last 1 hour
		if err != nil {
			log.Printf("❌ Initial VPC Flow Logs collection failed: %v", err)
		} else if len(flows) > 0 {
			if err := collector.IndexFlowLogs(flows); err != nil {
				log.Printf("⚠️ Failed to index flow logs: %v", err)
			}

			// Detect anomalies
			anomalies := collector.DetectAnomalies(flows)
			if len(anomalies) > 0 {
				log.Printf("🚨 Detected %d network anomalies", len(anomalies))
				if err := collector.IndexAnomalies(anomalies); err != nil {
					log.Printf("⚠️ Failed to index anomalies: %v", err)
				}
			}
		}

		log.Printf("🔄 VPC Flow Logs Indexer started - collecting every %d minutes", intervalMinutes)

		for range ticker.C {
			flows, err := collector.CollectFlowLogs(1)
			if err != nil {
				log.Printf("❌ VPC Flow Logs collection failed: %v", err)
				continue
			}

			if len(flows) > 0 {
				if err := collector.IndexFlowLogs(flows); err != nil {
					log.Printf("⚠️ Failed to index flow logs: %v", err)
				}

				anomalies := collector.DetectAnomalies(flows)
				if len(anomalies) > 0 {
					log.Printf("🚨 Detected %d network anomalies", len(anomalies))
					if err := collector.IndexAnomalies(anomalies); err != nil {
						log.Printf("⚠️ Failed to index anomalies: %v", err)
					}
				}
			}
		}
	}()
}

