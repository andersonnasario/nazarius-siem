package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"time"

	"github.com/cognimind/siem-platform/database"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// JWT configuration
const (
	AccessTokenDuration  = 15 * time.Minute   // Short-lived access token
	RefreshTokenDuration = 7 * 24 * time.Hour // 7 days refresh token
)

// getJWTSecretKey returns the JWT secret key from environment variable
// IMPORTANTE: Em produção, configure JWT_SECRET com um valor seguro de pelo menos 32 caracteres
func getJWTSecretKey() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// WARNING: This is only for development! Set JWT_SECRET in production.
		return "your-secret-key-change-in-production-dev-only"
	}
	return secret
}

// Claims represents JWT claims
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	RoleID   string `json:"role_id"`
	RoleName string `json:"role_name"`
	jwt.RegisteredClaims
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds
	User         *UserInfo `json:"user"`
}

// UserInfo represents user information (without sensitive data)
type UserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"full_name,omitempty"`
	RoleID   string `json:"role_id"`
	RoleName string `json:"role_name"`
	IsActive bool   `json:"is_active"`
}

// RefreshRequest represents a refresh token request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ============================================================================
// JWT GENERATION
// ============================================================================

// generateAccessToken generates a new JWT access token
func generateAccessToken(user *database.User) (string, error) {
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		RoleID:   user.RoleID,
		RoleName: user.RoleName,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "siem-platform",
			Subject:   user.ID,
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(getJWTSecretKey()))
}

// generateRefreshToken generates a random refresh token
func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// parseAccessToken parses and validates an access token
func parseAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(getJWTSecretKey()), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}

// ============================================================================
// AUTH HANDLERS
// ============================================================================

// handleLogin handles user login
func (s *APIServer) handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Verify credentials
	s.logger.Printf("Login attempt for user: %s", req.Username)
	AddSystemLog("INFO", "auth", "🔑 Login attempt", map[string]interface{}{
		"username": req.Username,
		"ip":       c.ClientIP(),
	})
	
	user, err := s.authRepo.VerifyPassword(ctx, req.Username, req.Password)
	if err != nil {
		// Log failed attempt for audit
		s.logger.Printf("Login failed for user %s: %v", req.Username, err)
		AddSystemLog("WARN", "auth", "❌ Login failed - Invalid credentials", map[string]interface{}{
			"username": req.Username,
			"ip":       c.ClientIP(),
			"error":    err.Error(),
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	s.logger.Printf("Login successful for user: %s (ID: %s)", user.Username, user.ID)
	AddSystemLog("INFO", "auth", "✅ Login successful", map[string]interface{}{
		"username": user.Username,
		"user_id":  user.ID,
		"role":     user.RoleName,
		"ip":       c.ClientIP(),
	})

	// Generate tokens
	accessToken, err := generateAccessToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Store refresh token in database
	dbRefreshToken := &database.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(RefreshTokenDuration),
	}
	if err := s.authRepo.CreateRefreshToken(ctx, dbRefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	// Create session
	ipAddress := c.ClientIP()
	userAgent := c.Request.UserAgent()
	session := &database.Session{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		IPAddress:    &ipAddress,
		UserAgent:    &userAgent,
		ExpiresAt:    time.Now().Add(RefreshTokenDuration),
	}
	if err := s.authRepo.CreateSession(ctx, session); err != nil {
		// Log error but don't fail login
		s.logger.Printf("Failed to create session: %v", err)
	}

	// Update last login
	if err := s.authRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		// Log error but don't fail login
		s.logger.Printf("Failed to update last login: %v", err)
	}

	// Prepare response
	fullName := ""
	if user.FullName != nil {
		fullName = *user.FullName
	}

	response := LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenDuration.Seconds()),
		User: &UserInfo{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			FullName: fullName,
			RoleID:   user.RoleID,
			RoleName: user.RoleName,
			IsActive: user.IsActive,
		},
	}

	c.JSON(http.StatusOK, response)
}

// handleRefreshToken handles refresh token requests
func (s *APIServer) handleRefreshToken(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Validate refresh token
	dbRefreshToken, err := s.authRepo.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	// Get user
	user, err := s.authRepo.GetUserByID(ctx, dbRefreshToken.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User is not active"})
		return
	}

	// Generate new access token
	accessToken, err := generateAccessToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Update session activity
	if err := s.authRepo.UpdateSessionActivity(ctx, req.RefreshToken); err != nil {
		// Log error but don't fail refresh
		s.logger.Printf("Failed to update session activity: %v", err)
	}

	response := gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(AccessTokenDuration.Seconds()),
	}

	c.JSON(http.StatusOK, response)
}

// handleLogout handles user logout
func (s *APIServer) handleLogout(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Revoke refresh token
	if err := s.authRepo.RevokeRefreshToken(ctx, req.RefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	// Delete session
	if err := s.authRepo.DeleteSession(ctx, req.RefreshToken); err != nil {
		// Log error but don't fail logout
		s.logger.Printf("Failed to delete session: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// handleLogoutAll handles logout from all devices
func (s *APIServer) handleLogoutAll(c *gin.Context) {
	// Get user ID from JWT (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	ctx := c.Request.Context()

	// Revoke all refresh tokens
	if err := s.authRepo.RevokeAllUserTokens(ctx, userID.(string)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout from all devices"})
		return
	}

	// Delete all sessions
	if err := s.authRepo.DeleteAllUserSessions(ctx, userID.(string)); err != nil {
		// Log error but don't fail logout
		s.logger.Printf("Failed to delete all sessions: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out from all devices successfully"})
}

// handleGetMe returns current user information
func (s *APIServer) handleGetMe(c *gin.Context) {
	// Get user ID from JWT (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	ctx := c.Request.Context()

	// Get user from database
	user, err := s.authRepo.GetUserByID(ctx, userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	fullName := ""
	if user.FullName != nil {
		fullName = *user.FullName
	}

	userInfo := UserInfo{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		FullName: fullName,
		RoleID:   user.RoleID,
		RoleName: user.RoleName,
		IsActive: user.IsActive,
	}

	c.JSON(http.StatusOK, userInfo)
}

// handleGetSessions returns all active sessions for the current user
func (s *APIServer) handleGetSessions(c *gin.Context) {
	// Get user ID from JWT (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	ctx := c.Request.Context()

	// Get sessions
	sessions, err := s.authRepo.GetUserSessions(ctx, userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get sessions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
		"total":    len(sessions),
	})
}

// handleChangePassword handles password change
func (s *APIServer) handleChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Get user ID from JWT (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	username, _ := c.Get("username")
	ctx := c.Request.Context()

	// Verify old password
	_, err := s.authRepo.VerifyPassword(ctx, username.(string), req.OldPassword)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid old password"})
		return
	}

	// Change password
	if err := s.authRepo.ChangePassword(ctx, userID.(string), req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to change password"})
		return
	}

	// Revoke all other tokens (force re-login on all devices)
	if err := s.authRepo.RevokeAllUserTokens(ctx, userID.(string)); err != nil {
		s.logger.Printf("Failed to revoke tokens after password change: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}
