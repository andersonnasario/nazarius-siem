package main

import (
	"crypto/rand"
	"encoding/base64"
	"log"
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

// getJWTSecretKey returns the JWT secret key from environment variable.
// JWT_SECRET must be set and at least 32 characters long.
func getJWTSecretKey() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("FATAL: JWT_SECRET environment variable is not set. Set a secure secret of at least 32 characters.")
	}
	if len(secret) < 32 {
		log.Fatal("FATAL: JWT_SECRET must be at least 32 characters long for security.")
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
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"` // seconds
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
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
		// Record failed attempt for brute force protection
		if s.bruteForceProtection != nil {
			s.bruteForceProtection.RecordFailedAttempt(c.ClientIP())
		}
		// Log failed attempt for audit (do NOT include err.Error() to prevent user enumeration)
		s.logger.Printf("Login failed for user: %s from IP: %s", req.Username, c.ClientIP())
		AddSystemLog("WARN", "auth", "Login failed - Invalid credentials", map[string]interface{}{
			"username": req.Username,
			"ip":       c.ClientIP(),
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Reset brute force counter on successful login
	if s.bruteForceProtection != nil {
		s.bruteForceProtection.ResetAttempts(c.ClientIP())
	}

	s.logger.Printf("Login successful for user: %s (ID: %s)", user.Username, user.ID)
	AddSystemLog("INFO", "auth", "Login successful", map[string]interface{}{
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
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

	// Refresh Token Rotation: revoke the old refresh token and issue a new one.
	// This prevents stolen refresh tokens from being reused.
	if err := s.authRepo.RevokeRefreshToken(ctx, req.RefreshToken); err != nil {
		s.logger.Printf("Failed to revoke old refresh token during rotation: %v", err)
	}

	// Generate new refresh token
	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Store the new refresh token
	newDBRefreshToken := &database.RefreshToken{
		UserID:    user.ID,
		Token:     newRefreshToken,
		ExpiresAt: time.Now().Add(RefreshTokenDuration),
	}
	if err := s.authRepo.CreateRefreshToken(ctx, newDBRefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	// Update session with new refresh token
	if err := s.authRepo.UpdateSessionActivity(ctx, req.RefreshToken); err != nil {
		// Log error but don't fail refresh
		s.logger.Printf("Failed to update session activity: %v", err)
	}

	response := gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(AccessTokenDuration.Seconds()),
	}

	c.JSON(http.StatusOK, response)
}

// handleLogout handles user logout
func (s *APIServer) handleLogout(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	ctx := c.Request.Context()

	// Blacklist the current access token in Redis (expires when the token would)
	if tokenID, exists := c.Get("token_id"); exists && s.redis != nil {
		blacklistKey := "token_blacklist:" + tokenID.(string)
		s.redis.Set(ctx, blacklistKey, "revoked", AccessTokenDuration)
	}

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

	// Blacklist current access token
	if tokenID, exists := c.Get("token_id"); exists && s.redis != nil {
		blacklistKey := "token_blacklist:" + tokenID.(string)
		s.redis.Set(ctx, blacklistKey, "revoked", AccessTokenDuration)
	}

	// Also blacklist all tokens for this user (using a user-level key)
	if s.redis != nil {
		userBlacklistKey := "user_tokens_revoked:" + userID.(string)
		s.redis.Set(ctx, userBlacklistKey, time.Now().Unix(), AccessTokenDuration)
	}

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

// sessionResponse is a safe subset of Session that excludes the refresh token
type sessionResponse struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	IPAddress    *string   `json:"ip_address,omitempty"`
	UserAgent    *string   `json:"user_agent,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
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

	// Strip refresh tokens from response to prevent token exposure
	safeSessions := make([]sessionResponse, len(sessions))
	for i, sess := range sessions {
		safeSessions[i] = sessionResponse{
			ID:           sess.ID,
			UserID:       sess.UserID,
			IPAddress:    sess.IPAddress,
			UserAgent:    sess.UserAgent,
			ExpiresAt:    sess.ExpiresAt,
			CreatedAt:    sess.CreatedAt,
			LastActivity: sess.LastActivity,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": safeSessions,
		"total":    len(safeSessions),
	})
}

// handleChangePassword handles password change
func (s *APIServer) handleChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Enforce strong password policy on new password
	if valid, reason := ValidatePassword(req.NewPassword); !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": reason})
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
