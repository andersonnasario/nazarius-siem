package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// NetworkFlow representa um fluxo de rede
type NetworkFlow struct {
	ID            string    `json:"id"`
	SourceIP      string    `json:"source_ip"`
	DestIP        string    `json:"dest_ip"`
	SourcePort    int       `json:"source_port"`
	DestPort      int       `json:"dest_port"`
	Protocol      string    `json:"protocol"`
	BytesSent     int64     `json:"bytes_sent"`
	BytesReceived int64     `json:"bytes_received"`
	PacketsSent   int       `json:"packets_sent"`
	PacketsRecv   int       `json:"packets_recv"`
	Duration      int       `json:"duration"` // segundos
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	Country       string    `json:"country"`
	City          string    `json:"city"`
	ASN           string    `json:"asn"`
	ThreatScore   int       `json:"threat_score"`
	IsAnomaly     bool      `json:"is_anomaly"`
	Flags         []string  `json:"flags"`
}

// Connection representa uma conexão ativa
type Connection struct {
	ID          string    `json:"id"`
	SourceIP    string    `json:"source_ip"`
	DestIP      string    `json:"dest_ip"`
	SourcePort  int       `json:"source_port"`
	DestPort    int       `json:"dest_port"`
	Protocol    string    `json:"protocol"`
	State       string    `json:"state"`
	Duration    int       `json:"duration"`
	BytesTotal  int64     `json:"bytes_total"`
	Established time.Time `json:"established"`
	LastSeen    time.Time `json:"last_seen"`
	Application string    `json:"application"`
	Risk        string    `json:"risk"` // low, medium, high, critical
}

// ProtocolStats estatísticas por protocolo
type ProtocolStats struct {
	Protocol       string  `json:"protocol"`
	FlowCount      int     `json:"flow_count"`
	TotalBytes     int64   `json:"total_bytes"`
	TotalPackets   int     `json:"total_packets"`
	AvgBytesPerSec float64 `json:"avg_bytes_per_sec"`
	Percentage     float64 `json:"percentage"`
}

// TopTalker representa host com maior tráfego
type TopTalker struct {
	IP               string  `json:"ip"`
	Hostname         string  `json:"hostname"`
	BytesSent        int64   `json:"bytes_sent"`
	BytesReceived    int64   `json:"bytes_received"`
	TotalBytes       int64   `json:"total_bytes"`
	FlowCount        int     `json:"flow_count"`
	ConnectionCount  int     `json:"connection_count"`
	TopProtocols     []string `json:"top_protocols"`
	Country          string   `json:"country"`
	RiskScore        int      `json:"risk_score"`
}

// NetworkAnomaly representa uma anomalia de rede detectada
type NetworkAnomaly struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"` // port_scan, ddos, data_exfiltration, lateral_movement, c2_beacon
	Severity       string    `json:"severity"`
	SourceIP       string    `json:"source_ip"`
	DestIP         string    `json:"dest_ip"`
	Description    string    `json:"description"`
	DetectedAt     time.Time `json:"detected_at"`
	FlowCount      int       `json:"flow_count"`
	BytesTotal     int64     `json:"bytes_total"`
	ConfidenceScore int      `json:"confidence_score"`
	MitreIDs       []string  `json:"mitre_ids"`
	Status         string    `json:"status"` // new, investigating, confirmed, false_positive
	AssignedTo     string    `json:"assigned_to,omitempty"`
}

// GeoLocation localização geográfica de tráfego
type GeoLocation struct {
	Country      string  `json:"country"`
	CountryCode  string  `json:"country_code"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	FlowCount    int     `json:"flow_count"`
	BytesTotal   int64   `json:"bytes_total"`
	ThreatLevel  string  `json:"threat_level"`
}

// BandwidthMetric métricas de largura de banda
type BandwidthMetric struct {
	Timestamp      time.Time `json:"timestamp"`
	InboundBps     int64     `json:"inbound_bps"`
	OutboundBps    int64     `json:"outbound_bps"`
	TotalBps       int64     `json:"total_bps"`
	InboundPps     int       `json:"inbound_pps"`
	OutboundPps    int       `json:"outbound_pps"`
	Utilization    float64   `json:"utilization"` // percentage
}

// PortScanEvent evento de port scanning
type PortScanEvent struct {
	ID            string    `json:"id"`
	ScannerIP     string    `json:"scanner_ip"`
	TargetIP      string    `json:"target_ip"`
	PortsScanned  []int     `json:"ports_scanned"`
	PortCount     int       `json:"port_count"`
	DetectedAt    time.Time `json:"detected_at"`
	Duration      int       `json:"duration"`
	ScanType      string    `json:"scan_type"` // syn, connect, udp, xmas
	ThreatScore   int       `json:"threat_score"`
}

// NetworkDashboard dashboard overview de rede
type NetworkDashboard struct {
	ActiveFlows       int              `json:"active_flows"`
	TotalConnections  int              `json:"total_connections"`
	BandwidthUsage    float64          `json:"bandwidth_usage"` // percentage
	AnomaliesDetected int              `json:"anomalies_detected"`
	TopProtocols      []ProtocolStats  `json:"top_protocols"`
	TopTalkers        []TopTalker      `json:"top_talkers"`
	RecentAnomalies   []NetworkAnomaly `json:"recent_anomalies"`
	GeoDistribution   []GeoLocation    `json:"geo_distribution"`
	BandwidthTrend    []BandwidthMetric `json:"bandwidth_trend"`
	PortScans         int              `json:"port_scans"`
	SuspiciousIPs     int              `json:"suspicious_ips"`
}

// handleGetNetworkDashboard retorna overview do tráfego de rede
func (s *APIServer) handleGetNetworkDashboard(c *gin.Context) {
	dashboard := NetworkDashboard{
		ActiveFlows:       1247,
		TotalConnections:  3856,
		BandwidthUsage:    67.3,
		AnomaliesDetected: 12,
		PortScans:         5,
		SuspiciousIPs:     8,
		TopProtocols:      generateMockProtocolStats(),
		TopTalkers:        generateMockTopTalkers()[:5],
		RecentAnomalies:   generateMockNetworkAnomalies()[:3],
		GeoDistribution:   generateMockGeoLocations(),
		BandwidthTrend:    generateMockBandwidthTrend(),
	}

	c.JSON(http.StatusOK, dashboard)
}

// handleGetNetworkFlows lista fluxos de rede
func (s *APIServer) handleGetNetworkFlows(c *gin.Context) {
	protocol := c.Query("protocol")
	anomalyOnly := c.Query("anomaly_only") == "true"

	flows := generateMockNetworkFlows()

	// Filtrar por protocolo
	if protocol != "" && protocol != "all" {
		filtered := []NetworkFlow{}
		for _, f := range flows {
			if f.Protocol == protocol {
				filtered = append(filtered, f)
			}
		}
		flows = filtered
	}

	// Filtrar por anomalias
	if anomalyOnly {
		filtered := []NetworkFlow{}
		for _, f := range flows {
			if f.IsAnomaly {
				filtered = append(filtered, f)
			}
		}
		flows = filtered
	}

	c.JSON(http.StatusOK, gin.H{
		"flows": flows,
		"total": len(flows),
	})
}

// handleGetActiveConnections lista conexões ativas
func (s *APIServer) handleGetActiveConnections(c *gin.Context) {
	connections := generateMockConnections()

	c.JSON(http.StatusOK, gin.H{
		"connections": connections,
		"total":       len(connections),
	})
}

// handleGetTopTalkers retorna hosts com maior tráfego
func (s *APIServer) handleGetTopTalkers(c *gin.Context) {
	talkers := generateMockTopTalkers()

	c.JSON(http.StatusOK, gin.H{
		"talkers": talkers,
		"total":   len(talkers),
	})
}

// handleGetProtocolStats retorna estatísticas por protocolo
func (s *APIServer) handleGetProtocolStats(c *gin.Context) {
	stats := generateMockProtocolStats()

	c.JSON(http.StatusOK, gin.H{
		"protocols": stats,
		"total":     len(stats),
	})
}

// handleGetNetworkAnomalies lista anomalias detectadas
func (s *APIServer) handleGetNetworkAnomalies(c *gin.Context) {
	anomalies := generateMockNetworkAnomalies()

	c.JSON(http.StatusOK, gin.H{
		"anomalies": anomalies,
		"total":     len(anomalies),
	})
}

// handleGetGeoLocations retorna distribuição geográfica do tráfego
func (s *APIServer) handleGetGeoLocations(c *gin.Context) {
	locations := generateMockGeoLocations()

	c.JSON(http.StatusOK, gin.H{
		"locations": locations,
		"total":     len(locations),
	})
}

// handleGetBandwidthMetrics retorna métricas de largura de banda
func (s *APIServer) handleGetBandwidthMetrics(c *gin.Context) {
	metrics := generateMockBandwidthTrend()

	c.JSON(http.StatusOK, gin.H{
		"metrics": metrics,
		"total":   len(metrics),
	})
}

// handleGetPortScans lista eventos de port scanning
func (s *APIServer) handleGetPortScans(c *gin.Context) {
	scans := generateMockPortScans()

	c.JSON(http.StatusOK, gin.H{
		"scans": scans,
		"total": len(scans),
	})
}

// handleGetNetworkStats retorna estatísticas gerais
func (s *APIServer) handleGetNetworkStats(c *gin.Context) {
	stats := gin.H{
		"total_flows_24h":      87432,
		"total_bytes_24h":      5428736512,
		"avg_flow_duration":    127,
		"unique_ips":           2847,
		"unique_destinations":  1923,
		"protocols_detected":   15,
		"anomalies_24h":        47,
		"port_scans_24h":       23,
		"blocked_connections":  156,
		"allowed_connections":  87276,
		"top_country":          "United States",
		"peak_bandwidth":       "892.5 Mbps",
		"avg_bandwidth":        "456.2 Mbps",
	}

	c.JSON(http.StatusOK, stats)
}

// === Mock Data Generators ===

func generateMockNetworkFlows() []NetworkFlow {
	flows := []NetworkFlow{
		{
			ID: "flow-001", SourceIP: "192.168.1.100", DestIP: "8.8.8.8",
			SourcePort: 54231, DestPort: 53, Protocol: "DNS",
			BytesSent: 256, BytesReceived: 512, PacketsSent: 2, PacketsRecv: 2,
			Duration: 1, StartTime: time.Now().Add(-5 * time.Minute),
			EndTime: time.Now().Add(-5*time.Minute + 1*time.Second),
			Country: "United States", City: "Mountain View", ASN: "AS15169",
			ThreatScore: 0, IsAnomaly: false, Flags: []string{"normal"},
		},
		{
			ID: "flow-002", SourceIP: "192.168.1.105", DestIP: "185.220.101.23",
			SourcePort: 49152, DestPort: 443, Protocol: "HTTPS",
			BytesSent: 15234567, BytesReceived: 2456789, PacketsSent: 10234, PacketsRecv: 7823,
			Duration: 1847, StartTime: time.Now().Add(-31 * time.Minute),
			EndTime: time.Now().Add(-1 * time.Minute),
			Country: "Russia", City: "Moscow", ASN: "AS51395",
			ThreatScore: 85, IsAnomaly: true, Flags: []string{"suspicious", "large_upload"},
		},
		{
			ID: "flow-003", SourceIP: "192.168.1.110", DestIP: "1.1.1.1",
			SourcePort: 52341, DestPort: 53, Protocol: "DNS",
			BytesSent: 128, BytesReceived: 256, PacketsSent: 1, PacketsRecv: 1,
			Duration: 0, StartTime: time.Now().Add(-2 * time.Minute),
			EndTime: time.Now().Add(-2 * time.Minute),
			Country: "United States", City: "Los Angeles", ASN: "AS13335",
			ThreatScore: 0, IsAnomaly: false, Flags: []string{"normal"},
		},
		{
			ID: "flow-004", SourceIP: "192.168.1.115", DestIP: "10.0.0.50",
			SourcePort: 3389, DestPort: 3389, Protocol: "RDP",
			BytesSent: 524288, BytesReceived: 1048576, PacketsSent: 512, PacketsRecv: 1024,
			Duration: 3600, StartTime: time.Now().Add(-61 * time.Minute),
			EndTime: time.Now().Add(-1 * time.Minute),
			Country: "Internal", City: "Internal", ASN: "Private",
			ThreatScore: 45, IsAnomaly: true, Flags: []string{"lateral_movement"},
		},
		{
			ID: "flow-005", SourceIP: "45.142.120.10", DestIP: "192.168.1.100",
			SourcePort: 1234, DestPort: 22, Protocol: "SSH",
			BytesSent: 15678, BytesReceived: 8234, PacketsSent: 234, PacketsRecv: 156,
			Duration: 120, StartTime: time.Now().Add(-10 * time.Minute),
			EndTime: time.Now().Add(-8 * time.Minute),
			Country: "China", City: "Beijing", ASN: "AS4134",
			ThreatScore: 92, IsAnomaly: true, Flags: []string{"brute_force", "suspicious_source"},
		},
	}
	return flows
}

func generateMockConnections() []Connection {
	connections := []Connection{
		{
			ID: "conn-001", SourceIP: "192.168.1.100", DestIP: "172.217.14.206",
			SourcePort: 54320, DestPort: 443, Protocol: "HTTPS", State: "ESTABLISHED",
			Duration: 245, BytesTotal: 2456789, Established: time.Now().Add(-4 * time.Minute),
			LastSeen: time.Now(), Application: "Chrome", Risk: "low",
		},
		{
			ID: "conn-002", SourceIP: "192.168.1.105", DestIP: "52.96.88.45",
			SourcePort: 49876, DestPort: 443, Protocol: "HTTPS", State: "ESTABLISHED",
			Duration: 1823, BytesTotal: 8945673, Established: time.Now().Add(-31 * time.Minute),
			LastSeen: time.Now(), Application: "Outlook", Risk: "low",
		},
		{
			ID: "conn-003", SourceIP: "192.168.1.110", DestIP: "185.220.101.23",
			SourcePort: 52341, DestPort: 9050, Protocol: "TOR", State: "ESTABLISHED",
			Duration: 3600, BytesTotal: 15234567, Established: time.Now().Add(-60 * time.Minute),
			LastSeen: time.Now(), Application: "Unknown", Risk: "critical",
		},
		{
			ID: "conn-004", SourceIP: "192.168.1.115", DestIP: "10.0.0.50",
			SourcePort: 54123, DestPort: 3389, Protocol: "RDP", State: "ESTABLISHED",
			Duration: 3600, BytesTotal: 1572864, Established: time.Now().Add(-60 * time.Minute),
			LastSeen: time.Now(), Application: "mstsc.exe", Risk: "medium",
		},
	}
	return connections
}

func generateMockTopTalkers() []TopTalker {
	talkers := []TopTalker{
		{
			IP: "192.168.1.105", Hostname: "workstation-01.local",
			BytesSent: 15234567890, BytesReceived: 8945673210, TotalBytes: 24180241100,
			FlowCount: 2847, ConnectionCount: 156,
			TopProtocols: []string{"HTTPS", "DNS", "SMTP"},
			Country: "Internal", RiskScore: 25,
		},
		{
			IP: "192.168.1.110", Hostname: "server-web-01.local",
			BytesSent: 8234567890, BytesReceived: 12345678901, TotalBytes: 20580246791,
			FlowCount: 8234, ConnectionCount: 423,
			TopProtocols: []string{"HTTPS", "HTTP", "DNS"},
			Country: "Internal", RiskScore: 15,
		},
		{
			IP: "192.168.1.100", Hostname: "laptop-05.local",
			BytesSent: 5678901234, BytesReceived: 3456789012, TotalBytes: 9135690246,
			FlowCount: 1234, ConnectionCount: 89,
			TopProtocols: []string{"HTTPS", "DNS", "NTP"},
			Country: "Internal", RiskScore: 10,
		},
		{
			IP: "185.220.101.23", Hostname: "unknown-external",
			BytesSent: 2456789012, BytesReceived: 15234567890, TotalBytes: 17691356902,
			FlowCount: 45, ConnectionCount: 12,
			TopProtocols: []string{"HTTPS", "TOR"},
			Country: "Russia", RiskScore: 89,
		},
		{
			IP: "45.142.120.10", Hostname: "scanner-cn",
			BytesSent: 3456789, BytesReceived: 1234567, TotalBytes: 4691356,
			FlowCount: 523, ConnectionCount: 523,
			TopProtocols: []string{"SSH", "TELNET", "HTTP"},
			Country: "China", RiskScore: 95,
		},
	}
	return talkers
}

func generateMockProtocolStats() []ProtocolStats {
	stats := []ProtocolStats{
		{Protocol: "HTTPS", FlowCount: 12847, TotalBytes: 45678901234, TotalPackets: 8234567, AvgBytesPerSec: 4567890, Percentage: 52.3},
		{Protocol: "HTTP", FlowCount: 3456, TotalBytes: 12345678901, TotalPackets: 2345678, AvgBytesPerSec: 1234567, Percentage: 14.1},
		{Protocol: "DNS", FlowCount: 8234, TotalBytes: 8234567, TotalPackets: 16468, AvgBytesPerSec: 8234, Percentage: 0.01},
		{Protocol: "SSH", FlowCount: 234, TotalBytes: 8945672, TotalPackets: 67234, AvgBytesPerSec: 89456, Percentage: 0.01},
		{Protocol: "RDP", FlowCount: 45, TotalBytes: 1572864000, TotalPackets: 1048576, AvgBytesPerSec: 157286, Percentage: 1.8},
		{Protocol: "SMTP", FlowCount: 567, TotalBytes: 2456789012, TotalPackets: 456789, AvgBytesPerSec: 245678, Percentage: 2.8},
		{Protocol: "FTP", FlowCount: 123, TotalBytes: 5678901234, TotalPackets: 789012, AvgBytesPerSec: 567890, Percentage: 6.5},
		{Protocol: "Others", FlowCount: 1845, TotalBytes: 19234567890, TotalPackets: 3456789, AvgBytesPerSec: 1923456, Percentage: 22.0},
	}
	return stats
}

func generateMockNetworkAnomalies() []NetworkAnomaly {
	anomalies := []NetworkAnomaly{
		{
			ID: "anom-001", Type: "port_scan", Severity: "high",
			SourceIP: "45.142.120.10", DestIP: "192.168.1.0/24",
			Description: "Port scanning detected from external IP targeting internal network",
			DetectedAt: time.Now().Add(-15 * time.Minute), FlowCount: 523,
			BytesTotal: 52300, ConfidenceScore: 95,
			MitreIDs: []string{"T1046"}, Status: "new",
		},
		{
			ID: "anom-002", Type: "data_exfiltration", Severity: "critical",
			SourceIP: "192.168.1.105", DestIP: "185.220.101.23",
			Description: "Large data transfer to suspicious external IP (15.2 GB in 30 minutes)",
			DetectedAt: time.Now().Add(-31 * time.Minute), FlowCount: 12,
			BytesTotal: 15234567890, ConfidenceScore: 87,
			MitreIDs: []string{"T1041"}, Status: "investigating", AssignedTo: "admin@company.com",
		},
		{
			ID: "anom-003", Type: "lateral_movement", Severity: "high",
			SourceIP: "192.168.1.115", DestIP: "10.0.0.50",
			Description: "RDP connection between internal hosts with unusual pattern",
			DetectedAt: time.Now().Add(-62 * time.Minute), FlowCount: 3,
			BytesTotal: 1572864000, ConfidenceScore: 72,
			MitreIDs: []string{"T1021.001"}, Status: "investigating",
		},
		{
			ID: "anom-004", Type: "c2_beacon", Severity: "critical",
			SourceIP: "192.168.1.120", DestIP: "23.95.108.25",
			Description: "Periodic beaconing behavior detected (every 5 minutes)",
			DetectedAt: time.Now().Add(-120 * time.Minute), FlowCount: 24,
			BytesTotal: 245678, ConfidenceScore: 92,
			MitreIDs: []string{"T1071", "T1573"}, Status: "confirmed", AssignedTo: "security@company.com",
		},
		{
			ID: "anom-005", Type: "ddos", Severity: "medium",
			SourceIP: "multiple", DestIP: "192.168.1.200",
			Description: "Unusual spike in connections to web server (3000 connections in 1 minute)",
			DetectedAt: time.Now().Add(-5 * time.Minute), FlowCount: 3000,
			BytesTotal: 3000000, ConfidenceScore: 68,
			MitreIDs: []string{"T1498"}, Status: "new",
		},
	}
	return anomalies
}

func generateMockGeoLocations() []GeoLocation {
	locations := []GeoLocation{
		{Country: "United States", CountryCode: "US", City: "Mountain View", Latitude: 37.4224, Longitude: -122.0842, FlowCount: 2847, BytesTotal: 12345678901, ThreatLevel: "low"},
		{Country: "United Kingdom", CountryCode: "GB", City: "London", Latitude: 51.5074, Longitude: -0.1278, FlowCount: 1234, BytesTotal: 5678901234, ThreatLevel: "low"},
		{Country: "Germany", CountryCode: "DE", City: "Frankfurt", Latitude: 50.1109, Longitude: 8.6821, FlowCount: 987, BytesTotal: 4567890123, ThreatLevel: "low"},
		{Country: "Russia", CountryCode: "RU", City: "Moscow", Latitude: 55.7558, Longitude: 37.6173, FlowCount: 156, BytesTotal: 15234567890, ThreatLevel: "critical"},
		{Country: "China", CountryCode: "CN", City: "Beijing", Latitude: 39.9042, Longitude: 116.4074, FlowCount: 523, BytesTotal: 4691356, ThreatLevel: "high"},
		{Country: "Brazil", CountryCode: "BR", City: "São Paulo", Latitude: -23.5505, Longitude: -46.6333, FlowCount: 678, BytesTotal: 3456789012, ThreatLevel: "low"},
	}
	return locations
}

func generateMockBandwidthTrend() []BandwidthMetric {
	metrics := []BandwidthMetric{}
	now := time.Now()
	for i := 0; i < 24; i++ {
		t := now.Add(-time.Duration(23-i) * time.Hour)
		inbound := int64(300000000 + (i*10000000))
		outbound := int64(150000000 + (i*5000000))
		metrics = append(metrics, BandwidthMetric{
			Timestamp:   t,
			InboundBps:  inbound,
			OutboundBps: outbound,
			TotalBps:    inbound + outbound,
			InboundPps:  int(inbound / 1500),
			OutboundPps: int(outbound / 1500),
			Utilization: float64(inbound+outbound) / 1000000000.0 * 100,
		})
	}
	return metrics
}

func generateMockPortScans() []PortScanEvent {
	scans := []PortScanEvent{
		{
			ID: "scan-001", ScannerIP: "45.142.120.10", TargetIP: "192.168.1.100",
			PortsScanned: []int{22, 23, 80, 443, 3389, 8080}, PortCount: 6,
			DetectedAt: time.Now().Add(-15 * time.Minute), Duration: 120,
			ScanType: "syn", ThreatScore: 85,
		},
		{
			ID: "scan-002", ScannerIP: "123.45.67.89", TargetIP: "192.168.1.0/24",
			PortsScanned: []int{}, PortCount: 1024,
			DetectedAt: time.Now().Add(-45 * time.Minute), Duration: 300,
			ScanType: "connect", ThreatScore: 92,
		},
		{
			ID: "scan-003", ScannerIP: "89.248.172.16", TargetIP: "192.168.1.200",
			PortsScanned: []int{445, 135, 139}, PortCount: 3,
			DetectedAt: time.Now().Add(-120 * time.Minute), Duration: 5,
			ScanType: "syn", ThreatScore: 78,
		},
	}
	return scans
}
