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

// ============================================================================
// VPC FLOW LOGS HANDLERS
// ============================================================================
// HTTP handlers for VPC Flow Logs analysis

// handleGetNetworkDashboardReal returns real-time network dashboard data
func (s *APIServer) handleGetNetworkDashboardReal(c *gin.Context) {
	if s.opensearch == nil {
		s.handleGetNetworkDashboard(c)
		return
	}

	// Get flow logs statistics
	stats, err := s.getFlowLogsStats()
	if err != nil {
		log.Printf("⚠️ Failed to get flow logs stats: %v", err)
	}

	// Get top talkers
	topTalkers, err := s.getTopTalkers(10)
	if err != nil {
		log.Printf("⚠️ Failed to get top talkers: %v", err)
	}

	// Get top ports
	topPorts, err := s.getTopPorts(10)
	if err != nil {
		log.Printf("⚠️ Failed to get top ports: %v", err)
	}

	// Get recent anomalies
	anomalies, err := s.getRecentNetworkAnomalies(10)
	if err != nil {
		log.Printf("⚠️ Failed to get anomalies: %v", err)
	}

	// Get traffic by direction
	trafficByDirection, err := s.getTrafficByDirection()
	if err != nil {
		log.Printf("⚠️ Failed to get traffic by direction: %v", err)
	}

	// Get traffic trends
	trends, err := s.getTrafficTrends(24)
	if err != nil {
		log.Printf("⚠️ Failed to get traffic trends: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"stats":                stats,
			"top_talkers":          topTalkers,
			"top_ports":            topPorts,
			"recent_anomalies":     anomalies,
			"traffic_by_direction": trafficByDirection,
			"traffic_trends":       trends,
		},
		"source": "opensearch",
	})
}

// handleListFlowLogs lists VPC flow logs with filtering
func (s *APIServer) handleListFlowLogs(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenSearch not available"})
		return
	}

	// Parse query parameters
	sourceIP := c.Query("source_ip")
	destIP := c.Query("dest_ip")
	port := c.Query("port")
	protocol := c.Query("protocol")
	action := c.Query("action")
	direction := c.Query("direction")
	minRiskScore := c.Query("min_risk_score")
	
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")
	sortBy := c.DefaultQuery("sort_by", "timestamp")
	sortOrder := c.DefaultQuery("sort_order", "desc")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	// Build query
	must := []map[string]interface{}{}

	if sourceIP != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"source_ip": sourceIP},
		})
	}
	if destIP != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"dest_ip": destIP},
		})
	}
	if port != "" {
		portNum, _ := strconv.Atoi(port)
		must = append(must, map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"term": map[string]interface{}{"source_port": portNum}},
					{"term": map[string]interface{}{"dest_port": portNum}},
				},
				"minimum_should_match": 1,
			},
		})
	}
	if protocol != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"protocol_name": strings.ToUpper(protocol)},
		})
	}
	if action != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"action": strings.ToUpper(action)},
		})
	}
	if direction != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"direction": direction},
		})
	}
	if minRiskScore != "" {
		riskScore, _ := strconv.Atoi(minRiskScore)
		must = append(must, map[string]interface{}{
			"range": map[string]interface{}{
				"risk_score": map[string]interface{}{"gte": riskScore},
			},
		})
	}

	query := map[string]interface{}{
		"size": limit,
		"from": offset,
		"sort": []map[string]interface{}{
			{sortBy: map[string]interface{}{"order": sortOrder}},
		},
	}

	if len(must) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{"must": must},
		}
	} else {
		query["query"] = map[string]interface{}{
			"match_all": map[string]interface{}{},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-vpc-flowlogs"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	flows := []VPCFlowLog{}
	total := 0

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if totalVal, ok := hits["total"].(map[string]interface{}); ok {
			if val, ok := totalVal["value"].(float64); ok {
				total = int(val)
			}
		}

		if hitsArr, ok := hits["hits"].([]interface{}); ok {
			for _, h := range hitsArr {
				hit := h.(map[string]interface{})
				source := hit["_source"].(map[string]interface{})
				flow := parseFlowLog(source)
				flows = append(flows, flow)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"flows":   flows,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// handleListNetworkAnomalies lists detected network anomalies
func (s *APIServer) handleListNetworkAnomalies(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenSearch not available"})
		return
	}

	severity := c.Query("severity")
	anomalyType := c.Query("type")
	limitStr := c.DefaultQuery("limit", "50")
	
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	must := []map[string]interface{}{}

	if severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"severity": severity},
		})
	}
	if anomalyType != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"type": anomalyType},
		})
	}

	query := map[string]interface{}{
		"size": limit,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
	}

	if len(must) > 0 {
		query["query"] = map[string]interface{}{
			"bool": map[string]interface{}{"must": must},
		}
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-network-anomalies"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	anomalies := []NetworkAnomalyDetection{}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsArr, ok := hits["hits"].([]interface{}); ok {
			for _, h := range hitsArr {
				hit := h.(map[string]interface{})
				source := hit["_source"].(map[string]interface{})
				anomaly := parseNetworkAnomaly(source)
				anomalies = append(anomalies, anomaly)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"anomalies": anomalies,
		"total":     len(anomalies),
	})
}

// handleGetFlowLogsStats returns VPC Flow Logs statistics
func (s *APIServer) handleGetFlowLogsStats(c *gin.Context) {
	if s.opensearch == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OpenSearch not available"})
		return
	}

	stats, err := s.getFlowLogsStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
	})
}

// handleTriggerFlowLogsCollection manually triggers flow logs collection
func (s *APIServer) handleTriggerFlowLogsCollection(c *gin.Context) {
	collector := GetVPCFlowLogsCollector()
	if collector == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "VPC Flow Logs collector not initialized"})
		return
	}

	hoursStr := c.DefaultQuery("hours", "1")
	hours, _ := strconv.Atoi(hoursStr)
	if hours <= 0 || hours > 24 {
		hours = 1
	}

	go func() {
		flows, err := collector.CollectFlowLogs(hours)
		if err != nil {
			log.Printf("❌ Manual flow logs collection failed: %v", err)
			return
		}

		if len(flows) > 0 {
			if err := collector.IndexFlowLogs(flows); err != nil {
				log.Printf("⚠️ Failed to index flow logs: %v", err)
			}

			anomalies := collector.DetectAnomalies(flows)
			if len(anomalies) > 0 {
				if err := collector.IndexAnomalies(anomalies); err != nil {
					log.Printf("⚠️ Failed to index anomalies: %v", err)
				}
			}
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"success": true,
		"message": "Flow logs collection triggered",
		"hours":   hours,
	})
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func (s *APIServer) getFlowLogsStats() (map[string]interface{}, error) {
	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"gte": "now-24h",
				},
			},
		},
		"aggs": map[string]interface{}{
			"total_bytes": map[string]interface{}{
				"sum": map[string]interface{}{"field": "bytes"},
			},
			"total_packets": map[string]interface{}{
				"sum": map[string]interface{}{"field": "packets"},
			},
			"by_action": map[string]interface{}{
				"terms": map[string]interface{}{"field": "action", "size": 5},
			},
			"by_protocol": map[string]interface{}{
				"terms": map[string]interface{}{"field": "protocol_name", "size": 10},
			},
			"high_risk": map[string]interface{}{
				"filter": map[string]interface{}{
					"range": map[string]interface{}{
						"risk_score": map[string]interface{}{"gte": 50},
					},
				},
			},
			"unique_source_ips": map[string]interface{}{
				"cardinality": map[string]interface{}{"field": "source_ip"},
			},
			"unique_dest_ips": map[string]interface{}{
				"cardinality": map[string]interface{}{"field": "dest_ip"},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-vpc-flowlogs"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	stats := map[string]interface{}{
		"total_flows":      0,
		"total_bytes":      0,
		"total_packets":    0,
		"accepted_flows":   0,
		"rejected_flows":   0,
		"high_risk_flows":  0,
		"unique_source_ips": 0,
		"unique_dest_ips":  0,
		"by_protocol":      []map[string]interface{}{},
	}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			if val, ok := total["value"].(float64); ok {
				stats["total_flows"] = int(val)
			}
		}
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if totalBytes, ok := aggs["total_bytes"].(map[string]interface{}); ok {
			if val, ok := totalBytes["value"].(float64); ok {
				stats["total_bytes"] = int64(val)
			}
		}
		if totalPackets, ok := aggs["total_packets"].(map[string]interface{}); ok {
			if val, ok := totalPackets["value"].(float64); ok {
				stats["total_packets"] = int64(val)
			}
		}
		if byAction, ok := aggs["by_action"].(map[string]interface{}); ok {
			if buckets, ok := byAction["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					action := bucket["key"].(string)
					count := int(bucket["doc_count"].(float64))
					if action == "ACCEPT" {
						stats["accepted_flows"] = count
					} else if action == "REJECT" {
						stats["rejected_flows"] = count
					}
				}
			}
		}
		if highRisk, ok := aggs["high_risk"].(map[string]interface{}); ok {
			if val, ok := highRisk["doc_count"].(float64); ok {
				stats["high_risk_flows"] = int(val)
			}
		}
		if uniqueSrc, ok := aggs["unique_source_ips"].(map[string]interface{}); ok {
			if val, ok := uniqueSrc["value"].(float64); ok {
				stats["unique_source_ips"] = int(val)
			}
		}
		if uniqueDst, ok := aggs["unique_dest_ips"].(map[string]interface{}); ok {
			if val, ok := uniqueDst["value"].(float64); ok {
				stats["unique_dest_ips"] = int(val)
			}
		}
		if byProtocol, ok := aggs["by_protocol"].(map[string]interface{}); ok {
			if buckets, ok := byProtocol["buckets"].([]interface{}); ok {
				protocols := []map[string]interface{}{}
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					protocols = append(protocols, map[string]interface{}{
						"protocol": bucket["key"],
						"count":    int(bucket["doc_count"].(float64)),
					})
				}
				stats["by_protocol"] = protocols
			}
		}
	}

	return stats, nil
}

func (s *APIServer) getTopTalkers(limit int) ([]map[string]interface{}, error) {
	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{"gte": "now-24h"},
			},
		},
		"aggs": map[string]interface{}{
			"top_sources": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "source_ip",
					"size":  limit,
					"order": map[string]interface{}{"total_bytes": "desc"},
				},
				"aggs": map[string]interface{}{
					"total_bytes": map[string]interface{}{
						"sum": map[string]interface{}{"field": "bytes"},
					},
					"flow_count": map[string]interface{}{
						"value_count": map[string]interface{}{"field": "_id"},
					},
				},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-vpc-flowlogs"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	topTalkers := []map[string]interface{}{}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if topSources, ok := aggs["top_sources"].(map[string]interface{}); ok {
			if buckets, ok := topSources["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					talker := map[string]interface{}{
						"ip":         bucket["key"],
						"flow_count": int(bucket["doc_count"].(float64)),
					}
					if totalBytes, ok := bucket["total_bytes"].(map[string]interface{}); ok {
						talker["total_bytes"] = int64(totalBytes["value"].(float64))
					}
					topTalkers = append(topTalkers, talker)
				}
			}
		}
	}

	return topTalkers, nil
}

func (s *APIServer) getTopPorts(limit int) ([]map[string]interface{}, error) {
	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{"gte": "now-24h"},
			},
		},
		"aggs": map[string]interface{}{
			"top_dest_ports": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "dest_port",
					"size":  limit,
				},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-vpc-flowlogs"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	topPorts := []map[string]interface{}{}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if topDestPorts, ok := aggs["top_dest_ports"].(map[string]interface{}); ok {
			if buckets, ok := topDestPorts["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					port := int(bucket["key"].(float64))
					topPorts = append(topPorts, map[string]interface{}{
						"port":    port,
						"count":   int(bucket["doc_count"].(float64)),
						"service": getServiceName(port),
					})
				}
			}
		}
	}

	return topPorts, nil
}

func (s *APIServer) getRecentNetworkAnomalies(limit int) ([]NetworkAnomalyDetection, error) {
	query := map[string]interface{}{
		"size": limit,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-network-anomalies"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	anomalies := []NetworkAnomalyDetection{}

	if hits, ok := result["hits"].(map[string]interface{}); ok {
		if hitsArr, ok := hits["hits"].([]interface{}); ok {
			for _, h := range hitsArr {
				hit := h.(map[string]interface{})
				source := hit["_source"].(map[string]interface{})
				anomalies = append(anomalies, parseNetworkAnomaly(source))
			}
		}
	}

	return anomalies, nil
}

func (s *APIServer) getTrafficByDirection() (map[string]interface{}, error) {
	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{"gte": "now-24h"},
			},
		},
		"aggs": map[string]interface{}{
			"by_direction": map[string]interface{}{
				"terms": map[string]interface{}{"field": "direction"},
				"aggs": map[string]interface{}{
					"total_bytes": map[string]interface{}{
						"sum": map[string]interface{}{"field": "bytes"},
					},
				},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-vpc-flowlogs"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	trafficByDirection := map[string]interface{}{
		"inbound":  map[string]interface{}{"flows": 0, "bytes": int64(0)},
		"outbound": map[string]interface{}{"flows": 0, "bytes": int64(0)},
		"internal": map[string]interface{}{"flows": 0, "bytes": int64(0)},
	}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if byDir, ok := aggs["by_direction"].(map[string]interface{}); ok {
			if buckets, ok := byDir["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					direction := bucket["key"].(string)
					flows := int(bucket["doc_count"].(float64))
					var bytes int64 = 0
					if totalBytes, ok := bucket["total_bytes"].(map[string]interface{}); ok {
						bytes = int64(totalBytes["value"].(float64))
					}
					trafficByDirection[direction] = map[string]interface{}{
						"flows": flows,
						"bytes": bytes,
					}
				}
			}
		}
	}

	return trafficByDirection, nil
}

func (s *APIServer) getTrafficTrends(hours int) ([]map[string]interface{}, error) {
	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"gte": "now-" + strconv.Itoa(hours) + "h",
				},
			},
		},
		"aggs": map[string]interface{}{
			"hourly": map[string]interface{}{
				"date_histogram": map[string]interface{}{
					"field":             "timestamp",
					"calendar_interval": "hour",
				},
				"aggs": map[string]interface{}{
					"total_bytes": map[string]interface{}{
						"sum": map[string]interface{}{"field": "bytes"},
					},
				},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithIndex("siem-vpc-flowlogs"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	trends := []map[string]interface{}{}

	if aggs, ok := result["aggregations"].(map[string]interface{}); ok {
		if hourly, ok := aggs["hourly"].(map[string]interface{}); ok {
			if buckets, ok := hourly["buckets"].([]interface{}); ok {
				for _, b := range buckets {
					bucket := b.(map[string]interface{})
					trend := map[string]interface{}{
						"timestamp": bucket["key_as_string"],
						"flows":     int(bucket["doc_count"].(float64)),
					}
					if totalBytes, ok := bucket["total_bytes"].(map[string]interface{}); ok {
						trend["bytes"] = int64(totalBytes["value"].(float64))
					}
					trends = append(trends, trend)
				}
			}
		}
	}

	return trends, nil
}

func parseFlowLog(source map[string]interface{}) VPCFlowLog {
	flow := VPCFlowLog{
		Source: "VPC Flow Logs",
	}

	if v, ok := source["id"].(string); ok {
		flow.ID = v
	}
	if v, ok := source["version"].(float64); ok {
		flow.Version = int(v)
	}
	if v, ok := source["account_id"].(string); ok {
		flow.AccountID = v
	}
	if v, ok := source["interface_id"].(string); ok {
		flow.InterfaceID = v
	}
	if v, ok := source["source_ip"].(string); ok {
		flow.SourceIP = v
	}
	if v, ok := source["dest_ip"].(string); ok {
		flow.DestIP = v
	}
	if v, ok := source["source_port"].(float64); ok {
		flow.SourcePort = int(v)
	}
	if v, ok := source["dest_port"].(float64); ok {
		flow.DestPort = int(v)
	}
	if v, ok := source["protocol"].(float64); ok {
		flow.Protocol = int(v)
	}
	if v, ok := source["protocol_name"].(string); ok {
		flow.ProtocolName = v
	}
	if v, ok := source["packets"].(float64); ok {
		flow.Packets = int64(v)
	}
	if v, ok := source["bytes"].(float64); ok {
		flow.Bytes = int64(v)
	}
	if v, ok := source["action"].(string); ok {
		flow.Action = v
	}
	if v, ok := source["direction"].(string); ok {
		flow.Direction = v
	}
	if v, ok := source["risk_score"].(float64); ok {
		flow.RiskScore = int(v)
	}
	if v, ok := source["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			flow.Timestamp = t
		}
	}

	return flow
}

func parseNetworkAnomaly(source map[string]interface{}) NetworkAnomalyDetection {
	anomaly := NetworkAnomalyDetection{}

	if v, ok := source["id"].(string); ok {
		anomaly.ID = v
	}
	if v, ok := source["type"].(string); ok {
		anomaly.Type = v
	}
	if v, ok := source["severity"].(string); ok {
		anomaly.Severity = v
	}
	if v, ok := source["description"].(string); ok {
		anomaly.Description = v
	}
	if v, ok := source["source_ip"].(string); ok {
		anomaly.SourceIP = v
	}
	if v, ok := source["dest_ip"].(string); ok {
		anomaly.DestIP = v
	}
	if v, ok := source["flow_count"].(float64); ok {
		anomaly.FlowCount = int(v)
	}
	if v, ok := source["total_bytes"].(float64); ok {
		anomaly.TotalBytes = int64(v)
	}
	if v, ok := source["mitre_technique"].(string); ok {
		anomaly.MITRETechnique = v
	}
	if v, ok := source["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			anomaly.Timestamp = t
		}
	}
	if v, ok := source["recommendations"].([]interface{}); ok {
		for _, r := range v {
			if rec, ok := r.(string); ok {
				anomaly.Recommendations = append(anomaly.Recommendations, rec)
			}
		}
	}

	return anomaly
}

func getServiceName(port int) string {
	services := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		445:   "SMB",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP-Alt",
		8443:  "HTTPS-Alt",
		27017: "MongoDB",
	}

	if name, ok := services[port]; ok {
		return name
	}
	return ""
}

