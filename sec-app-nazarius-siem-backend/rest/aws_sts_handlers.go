package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// handleListConnections lista todas as conexões AWS
func (s *APIServer) handleListConnections(c *gin.Context) {
	connectionsMutex.RLock()
	defer connectionsMutex.RUnlock()

	connections := make([]*AccountConnection, 0, len(accountConnections))
	for _, conn := range accountConnections {
		// Sanitizar credenciais antes de enviar
		sanitized := *conn
		if sanitized.Credentials != nil {
			sanitized.Credentials = &AWSCredentials{
				AccessKeyID:     sanitized.Credentials.AccessKeyID[:10] + "...",
				SecretAccessKey: "***hidden***",
				SessionToken:    "***hidden***",
				Expiration:      sanitized.Credentials.Expiration,
				Region:          sanitized.Credentials.Region,
			}
		}
		connections = append(connections, &sanitized)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"connections": connections,
		"total":       len(connections),
		"statistics":  connectionStats,
	})
}

// handleGetConnection retorna uma conexão específica
func (s *APIServer) handleGetConnection(c *gin.Context) {
	connectionID := c.Param("id")

	connectionsMutex.RLock()
	defer connectionsMutex.RUnlock()

	conn, exists := accountConnections[connectionID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Connection not found",
		})
		return
	}

	// Sanitizar credenciais
	sanitized := *conn
	if sanitized.Credentials != nil {
		sanitized.Credentials = &AWSCredentials{
			AccessKeyID:     sanitized.Credentials.AccessKeyID[:10] + "...",
			SecretAccessKey: "***hidden***",
			SessionToken:    "***hidden***",
			Expiration:      sanitized.Credentials.Expiration,
			Region:          sanitized.Credentials.Region,
		}
	}

	// Adicionar informações extras
	timeUntilExpiration := conn.TimeUntilExpiration()
	
	c.JSON(http.StatusOK, gin.H{
		"success":               true,
		"connection":            &sanitized,
		"time_until_expiration": timeUntilExpiration.String(),
		"is_expired":            conn.IsExpired(),
	})
}

// handleCreateConnection cria uma nova conexão AWS
func (s *APIServer) handleCreateConnection(c *gin.Context) {
	var input struct {
		AccountID   string `json:"account_id" binding:"required"`
		AccountName string `json:"account_name" binding:"required"`
		RoleARN     string `json:"role_arn" binding:"required"`
		ExternalID  string `json:"external_id"`
		Region      string `json:"region"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// Validar Role ARN
	if err := ValidateRoleARN(input.RoleARN); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// Definir região padrão
	if input.Region == "" {
		input.Region = "us-east-1"
	}

	// Gerar External ID se não fornecido
	if input.ExternalID == "" {
		input.ExternalID = GenerateExternalID()
	}

	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	// Verificar se já existe conexão para esta conta
	for _, conn := range accountConnections {
		if conn.AccountID == input.AccountID {
			c.JSON(http.StatusConflict, gin.H{
				"success": false,
				"error":   "Connection already exists for this account",
			})
			return
		}
	}

	// Criar nova conexão
	newConn := &AccountConnection{
		ID:          uuid.New().String(),
		AccountID:   input.AccountID,
		AccountName: input.AccountName,
		RoleARN:     input.RoleARN,
		ExternalID:  input.ExternalID,
		Region:      input.Region,
		Status:      "pending",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Testar conexão
	if err := newConn.TestConnection(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Failed to test connection: " + err.Error(),
		})
		return
	}

	// Tentar obter credenciais iniciais
	if err := newConn.RefreshCredentials(); err != nil {
		newConn.Status = "failed"
		newConn.ErrorMessage = err.Error()
	}

	accountConnections[newConn.ID] = newConn
	updateConnectionStats()

	c.JSON(http.StatusCreated, gin.H{
		"success":    true,
		"message":    "Connection created successfully",
		"connection": newConn,
	})
}

// handleUpdateConnection atualiza uma conexão existente
func (s *APIServer) handleUpdateConnection(c *gin.Context) {
	connectionID := c.Param("id")

	var input struct {
		AccountName string `json:"account_name"`
		RoleARN     string `json:"role_arn"`
		ExternalID  string `json:"external_id"`
		Region      string `json:"region"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	conn, exists := accountConnections[connectionID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Connection not found",
		})
		return
	}

	// Atualizar campos
	if input.AccountName != "" {
		conn.AccountName = input.AccountName
	}
	if input.RoleARN != "" {
		if err := ValidateRoleARN(input.RoleARN); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   err.Error(),
			})
			return
		}
		conn.RoleARN = input.RoleARN
	}
	if input.ExternalID != "" {
		conn.ExternalID = input.ExternalID
	}
	if input.Region != "" {
		conn.Region = input.Region
	}

	conn.UpdatedAt = time.Now()

	// Forçar refresh de credenciais com novas configurações
	conn.Credentials = nil
	if err := conn.RefreshCredentials(); err != nil {
		conn.Status = "failed"
		conn.ErrorMessage = err.Error()
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"message":    "Connection updated successfully",
		"connection": conn,
	})
}

// handleDeleteConnection remove uma conexão
func (s *APIServer) handleDeleteConnection(c *gin.Context) {
	connectionID := c.Param("id")

	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	if _, exists := accountConnections[connectionID]; !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Connection not found",
		})
		return
	}

	delete(accountConnections, connectionID)
	updateConnectionStats()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Connection deleted successfully",
	})
}

// handleRefreshConnection força a renovação de credenciais
func (s *APIServer) handleRefreshConnection(c *gin.Context) {
	connectionID := c.Param("id")

	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	conn, exists := accountConnections[connectionID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Connection not found",
		})
		return
	}

	// Forçar refresh
	conn.Credentials = nil
	if err := conn.RefreshCredentials(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to refresh credentials: " + err.Error(),
		})
		return
	}

	updateConnectionStats()

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"message":    "Credentials refreshed successfully",
		"connection": conn,
		"expires_in": conn.TimeUntilExpiration().String(),
	})
}

// handleTestConnection testa uma conexão
func (s *APIServer) handleTestConnection(c *gin.Context) {
	connectionID := c.Param("id")

	connectionsMutex.RLock()
	conn, exists := accountConnections[connectionID]
	connectionsMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Connection not found",
		})
		return
	}

	if err := conn.TestConnection(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Connection test failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Connection test successful",
		"status":  conn.Status,
	})
}

// handleGetConnectionStatistics retorna estatísticas de conexões
func (s *APIServer) handleGetConnectionStatistics(c *gin.Context) {
	connectionsMutex.RLock()
	defer connectionsMutex.RUnlock()

	// Calcular estatísticas adicionais
	expiringIn5Min := 0
	expiringIn15Min := 0
	expiringIn30Min := 0

	for _, conn := range accountConnections {
		if conn.Credentials != nil {
			timeUntil := conn.TimeUntilExpiration()
			if timeUntil <= 5*time.Minute {
				expiringIn5Min++
			} else if timeUntil <= 15*time.Minute {
				expiringIn15Min++
			} else if timeUntil <= 30*time.Minute {
				expiringIn30Min++
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"statistics": connectionStats,
		"expiration_alerts": gin.H{
			"expiring_in_5_minutes":  expiringIn5Min,
			"expiring_in_15_minutes": expiringIn15Min,
			"expiring_in_30_minutes": expiringIn30Min,
		},
	})
}

// handleBulkRefreshConnections força refresh em todas as conexões
func (s *APIServer) handleBulkRefreshConnections(c *gin.Context) {
	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	refreshed := 0
	failed := 0
	errors := make([]string, 0)

	for _, conn := range accountConnections {
		conn.Credentials = nil
		if err := conn.RefreshCredentials(); err != nil {
			failed++
			errors = append(errors, conn.AccountID+": "+err.Error())
		} else {
			refreshed++
		}
	}

	updateConnectionStats()

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"message":   "Bulk refresh completed",
		"refreshed": refreshed,
		"failed":    failed,
		"errors":    errors,
	})
}

// handleGetConnectionHealth retorna o health de uma conexão
func (s *APIServer) handleGetConnectionHealth(c *gin.Context) {
	connectionID := c.Param("id")

	connectionsMutex.RLock()
	defer connectionsMutex.RUnlock()

	conn, exists := accountConnections[connectionID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Connection not found",
		})
		return
	}

	health := gin.H{
		"connection_id":   conn.ID,
		"account_id":      conn.AccountID,
		"status":          conn.Status,
		"is_expired":      conn.IsExpired(),
		"has_credentials": conn.Credentials != nil,
	}

	if conn.Credentials != nil {
		timeUntil := conn.TimeUntilExpiration()
		health["time_until_expiration"] = timeUntil.String()
		health["expiration_timestamp"] = conn.Credentials.Expiration
		
		// Determinar health status
		if timeUntil <= 5*time.Minute {
			health["health_status"] = "critical"
		} else if timeUntil <= 15*time.Minute {
			health["health_status"] = "warning"
		} else {
			health["health_status"] = "healthy"
		}
	} else {
		health["health_status"] = "no_credentials"
	}

	health["last_refresh"] = conn.LastRefresh
	health["refresh_count"] = conn.RefreshCount
	health["error_message"] = conn.ErrorMessage

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"health":  health,
	})
}

