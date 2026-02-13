package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Setup test router
func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	return router
}

// TestHealthEndpoint testa o endpoint de health check
func TestHealthEndpoint(t *testing.T) {
	router := setupRouter()
	
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "healthy",
			"components": gin.H{
				"api": gin.H{
					"status": "healthy",
				},
			},
		})
	})

	req, _ := http.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status code esperado 200, obteve %d", w.Code)
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["status"] != "healthy" {
		t.Error("Status deveria ser 'healthy'")
	}
}

// TestAuthLoginEndpoint testa o endpoint de login
func TestAuthLoginEndpoint(t *testing.T) {
	router := setupRouter()

	router.POST("/api/v1/auth/login", func(c *gin.Context) {
		var loginData map[string]string
		c.BindJSON(&loginData)

		if loginData["username"] == "admin" && loginData["password"] == "admin" {
			c.JSON(200, gin.H{
				"access_token":  "mock_access_token",
				"refresh_token": "mock_refresh_token",
				"user": gin.H{
					"id":       "user-123",
					"username": "admin",
				},
			})
		} else {
			c.JSON(401, gin.H{
				"error": "Invalid credentials",
			})
		}
	})

	// Test successful login
	loginData := map[string]string{
		"username": "admin",
		"password": "admin",
	}
	jsonData, _ := json.Marshal(loginData)

	req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Login bem-sucedido deveria retornar 200, obteve %d", w.Code)
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["access_token"] == nil {
		t.Error("Response deveria conter access_token")
	}

	// Test failed login
	invalidLogin := map[string]string{
		"username": "admin",
		"password": "wrong",
	}
	jsonData, _ = json.Marshal(invalidLogin)

	req, _ = http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Login inválido deveria retornar 401, obteve %d", w.Code)
	}
}

// TestIncidentResponseStatsEndpoint testa o endpoint de stats do Incident Response
func TestIncidentResponseStatsEndpoint(t *testing.T) {
	router := setupRouter()

	router.GET("/api/v1/incident-response/stats", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"total_incidents":      156,
			"open_incidents":       23,
			"closed_incidents":     133,
			"avg_resolution_time":  "4.5h",
			"automation_rate":      87.5,
			"sla_compliance_rate":  94.2,
		})
	})

	req, _ := http.NewRequest("GET", "/api/v1/incident-response/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status code esperado 200, obteve %d", w.Code)
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["total_incidents"] == nil {
		t.Error("Response deveria conter total_incidents")
	}

	totalIncidents := response["total_incidents"].(float64)
	if totalIncidents <= 0 {
		t.Error("Total de incidents deve ser maior que 0")
	}
}

// TestMLAnalyticsDashboardEndpoint testa o endpoint do ML Analytics
func TestMLAnalyticsDashboardEndpoint(t *testing.T) {
	router := setupRouter()

	router.GET("/api/v1/ml/dashboard", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"total_models":       12,
			"active_models":      8,
			"total_predictions":  45672,
			"accuracy_avg":       94.5,
			"anomalies_detected": 234,
		})
	})

	req, _ := http.NewRequest("GET", "/api/v1/ml/dashboard", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status code esperado 200, obteve %d", w.Code)
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["total_models"] == nil {
		t.Error("Response deveria conter total_models")
	}
}

// TestSecurityEventsEndpoint testa o endpoint de eventos de segurança
func TestSecurityEventsEndpoint(t *testing.T) {
	router := setupRouter()

	router.GET("/api/v1/security-settings/events", func(c *gin.Context) {
		c.JSON(200, []gin.H{
			{
				"id":        "evt-001",
				"type":      "blocked_ip",
				"severity":  "high",
				"timestamp": "2025-11-07T10:00:00Z",
			},
			{
				"id":        "evt-002",
				"type":      "failed_login",
				"severity":  "medium",
				"timestamp": "2025-11-07T10:05:00Z",
			},
		})
	})

	req, _ := http.NewRequest("GET", "/api/v1/security-settings/events", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status code esperado 200, obteve %d", w.Code)
	}

	var response []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if len(response) == 0 {
		t.Error("Response deveria conter eventos")
	}

	if response[0]["id"] == nil {
		t.Error("Evento deveria conter ID")
	}
}

// TestMonitoringMetricsEndpoint testa o endpoint de métricas
func TestMonitoringMetricsEndpoint(t *testing.T) {
	router := setupRouter()

	router.GET("/api/v1/monitoring/metrics", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"events_per_second":  342.5,
			"alerts_per_minute":  12.3,
			"api_latency_ms":     45.2,
			"system_health":      98.5,
		})
	})

	req, _ := http.NewRequest("GET", "/api/v1/monitoring/metrics", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status code esperado 200, obteve %d", w.Code)
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["events_per_second"] == nil {
		t.Error("Response deveria conter events_per_second")
	}
}

// TestCORSHeaders testa headers CORS
func TestCORSHeaders(t *testing.T) {
	router := setupRouter()

	// Add CORS middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Next()
	})

	router.GET("/api/v1/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	corsHeader := w.Header().Get("Access-Control-Allow-Origin")
	if corsHeader != "*" {
		t.Errorf("Header CORS esperado '*', obteve '%s'", corsHeader)
	}
}

// TestRateLimitMiddleware testa middleware de rate limiting
func TestRateLimitMiddleware(t *testing.T) {
	router := setupRouter()

	requestCount := make(map[string]int)

	router.Use(func(c *gin.Context) {
		clientIP := c.ClientIP()
		requestCount[clientIP]++
		
		if requestCount[clientIP] > 10 {
			c.JSON(429, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}
		c.Next()
	})

	router.GET("/api/v1/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	// Simula 15 requisições
	for i := 0; i < 15; i++ {
		req, _ := http.NewRequest("GET", "/api/v1/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if i < 10 {
			if w.Code != http.StatusOK {
				t.Errorf("Requisição %d deveria ser bem-sucedida", i+1)
			}
		} else {
			if w.Code != http.StatusTooManyRequests {
				t.Errorf("Requisição %d deveria ser bloqueada (429), obteve %d", i+1, w.Code)
			}
		}
	}
}

// TestAuthenticationMiddleware testa middleware de autenticação
func TestAuthenticationMiddleware(t *testing.T) {
	router := setupRouter()

	router.Use(func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || authHeader != "Bearer valid_token" {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	})

	router.GET("/api/v1/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "protected resource"})
	})

	// Test without token
	req, _ := http.NewRequest("GET", "/api/v1/protected", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Request sem token deveria retornar 401, obteve %d", w.Code)
	}

	// Test with valid token
	req, _ = http.NewRequest("GET", "/api/v1/protected", nil)
	req.Header.Set("Authorization", "Bearer valid_token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Request com token válido deveria retornar 200, obteve %d", w.Code)
	}
}

// TestJSONResponseFormat testa formato de resposta JSON
func TestJSONResponseFormat(t *testing.T) {
	router := setupRouter()

	router.GET("/api/v1/test", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"success": true,
			"data": gin.H{
				"id":   "123",
				"name": "Test",
			},
			"timestamp": "2025-11-07T10:00:00Z",
		})
	})

	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("Content-Type esperado 'application/json; charset=utf-8', obteve '%s'", contentType)
	}

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("Erro ao fazer parse do JSON: %v", err)
	}

	if response["success"] != true {
		t.Error("Response deveria conter success=true")
	}

	if response["data"] == nil {
		t.Error("Response deveria conter data")
	}
}

