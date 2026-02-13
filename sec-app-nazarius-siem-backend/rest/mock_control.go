package main

import (
	"os"
	"sync"
)

// ============================================================================
// MOCK DATA CONTROL
// ============================================================================
// This file controls whether mock data is returned when real data is unavailable.
// Set DISABLE_MOCK_DATA=true to disable all mock data and return empty results.

var (
	mockControlOnce  sync.Once
	mockDataDisabled bool
)

// IsMockDataDisabled returns true if mock data should be disabled
// When disabled, endpoints return empty results instead of fake data
func IsMockDataDisabled() bool {
	mockControlOnce.Do(func() {
		mockDataDisabled = os.Getenv("DISABLE_MOCK_DATA") == "true"
		if mockDataDisabled {
			AddSystemLog("INFO", "config", "🚫 Mock data DISABLED - Only real data will be shown", nil)
		}
	})
	return mockDataDisabled
}

// EmptyResponse helper for returning empty but valid responses
type EmptyResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// NewEmptyResponse creates a standard empty response
func NewEmptyResponse(dataType string) EmptyResponse {
	return EmptyResponse{
		Status:  "success",
		Message: "No real data available. Connect data sources to see live data.",
		Data:    getEmptyDataForType(dataType),
	}
}

// getEmptyDataForType returns appropriate empty structure for each data type
func getEmptyDataForType(dataType string) interface{} {
	switch dataType {
	case "events":
		return map[string]interface{}{
			"events":      []interface{}{},
			"total":       0,
			"page":        1,
			"page_size":   50,
			"total_pages": 0,
			"source":      "none",
		}
	case "alerts":
		return map[string]interface{}{
			"alerts": []interface{}{},
			"total":  0,
			"source": "none",
		}
	case "statistics":
		return map[string]interface{}{
			"total":       0,
			"by_severity": map[string]int{},
			"by_type":     map[string]int{},
			"by_source":   map[string]int{},
			"timeline":    []interface{}{},
			"source":      "none",
		}
	case "vulnerabilities":
		return map[string]interface{}{
			"vulnerabilities": []interface{}{},
			"total":           0,
			"source":          "none",
		}
	case "users":
		return map[string]interface{}{
			"users":  []interface{}{},
			"total":  0,
			"source": "none",
		}
	case "incidents":
		return map[string]interface{}{
			"incidents": []interface{}{},
			"total":     0,
			"source":    "none",
		}
	case "network":
		return map[string]interface{}{
			"flows":       []interface{}{},
			"connections": []interface{}{},
			"total":       0,
			"source":      "none",
		}
	case "compliance":
		return map[string]interface{}{
			"frameworks": []interface{}{},
			"score":      0,
			"source":     "none",
		}
	case "dashboard":
		return map[string]interface{}{
			"widgets": []interface{}{},
			"source":  "none",
		}
	case "iocs":
		return map[string]interface{}{
			"iocs":       []interface{}{},
			"total":      0,
			"dataSource": "none",
		}
	case "feeds":
		return map[string]interface{}{
			"feeds":      []interface{}{},
			"total":      0,
			"dataSource": "none",
		}
	case "threat_stats":
		return map[string]interface{}{
			"stats": map[string]interface{}{
				"totalIOCs":      0,
				"activeIOCs":     0,
				"iocsByType":     map[string]int{},
				"iocsBySeverity": map[string]int{},
				"topThreats":     []interface{}{},
				"recentIOCs":     []interface{}{},
				"eventsEnriched": 0,
				"feedsActive":    0,
				"topCountries":   []interface{}{},
			},
			"dataSource": "none",
		}
	default:
		return map[string]interface{}{
			"items":  []interface{}{},
			"total":  0,
			"source": "none",
		}
	}
}
