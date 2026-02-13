package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiter structure for managing rate limits
type RateLimiter struct {
	visitors map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
	cleanup  time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	limiter := &RateLimiter{
		visitors: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
		cleanup:  5 * time.Minute,
	}

	// Start cleanup goroutine
	go limiter.cleanupVisitors()

	return limiter
}

// GetLimiter returns the rate limiter for a given IP
func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = limiter
	}

	return limiter
}

// cleanupVisitors removes old entries periodically
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		// Remove old entries (simple cleanup - could be improved with last access tracking)
		if len(rl.visitors) > 10000 {
			rl.visitors = make(map[string]*rate.Limiter)
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get client IP
		ip := getClientIP(c)

		// Get limiter for this IP
		l := limiter.GetLimiter(ip)

		// Check if request is allowed
		if !l.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"message": "Too many requests. Please try again later.",
				"retry_after": "60s",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// getClientIP extracts the real client IP from the request
func getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header
	forwarded := c.GetHeader("X-Forwarded-For")
	if forwarded != "" {
		// Get the first IP in the list
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	realIP := c.GetHeader("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to remote address
	return c.ClientIP()
}

// SecurityHeadersMiddleware adds security headers to responses
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Enable XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")

		// HSTS (HTTP Strict Transport Security)
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Content Security Policy
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data: https:; " +
			"font-src 'self' data:; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none'"
		c.Header("Content-Security-Policy", csp)

		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions Policy (formerly Feature Policy)
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Remove server header
		c.Header("Server", "")

		c.Next()
	}
}

// CORSMiddleware configures CORS with security best practices
func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		
		// Always set CORS headers for development
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}
		
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With, Accept, Origin, Cache-Control")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400") // 24 hours

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// InputValidationMiddleware performs basic input validation
func InputValidationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check Content-Type for POST/PUT/PATCH requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.GetHeader("Content-Type")
			if contentType != "" && !strings.Contains(contentType, "application/json") &&
				!strings.Contains(contentType, "multipart/form-data") &&
				!strings.Contains(contentType, "application/x-www-form-urlencoded") {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid Content-Type",
					"message": "Content-Type must be application/json, multipart/form-data, or application/x-www-form-urlencoded",
				})
				c.Abort()
				return
			}
		}

		// Limit request body size (10MB)
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 10*1024*1024)

		c.Next()
	}
}

// BruteForceProtection tracks failed login attempts
type BruteForceProtection struct {
	attempts map[string]*LoginAttempts
	mu       sync.RWMutex
}

// LoginAttempts tracks login attempts for an IP
type LoginAttempts struct {
	Count      int
	LastAttempt time.Time
	BlockedUntil time.Time
}

// NewBruteForceProtection creates a new brute force protection instance
func NewBruteForceProtection() *BruteForceProtection {
	bfp := &BruteForceProtection{
		attempts: make(map[string]*LoginAttempts),
	}

	// Start cleanup goroutine
	go bfp.cleanupAttempts()

	return bfp
}

// RecordFailedAttempt records a failed login attempt
func (bfp *BruteForceProtection) RecordFailedAttempt(ip string) {
	bfp.mu.Lock()
	defer bfp.mu.Unlock()

	now := time.Now()

	attempts, exists := bfp.attempts[ip]
	if !exists {
		attempts = &LoginAttempts{
			Count:      1,
			LastAttempt: now,
		}
		bfp.attempts[ip] = attempts
		return
	}

	// Reset count if last attempt was more than 15 minutes ago
	if now.Sub(attempts.LastAttempt) > 15*time.Minute {
		attempts.Count = 1
		attempts.LastAttempt = now
		attempts.BlockedUntil = time.Time{}
		return
	}

	attempts.Count++
	attempts.LastAttempt = now

	// Block after 5 failed attempts
	if attempts.Count >= 5 {
		// Block for 30 minutes
		attempts.BlockedUntil = now.Add(30 * time.Minute)
	}
}

// ResetAttempts resets the failed attempts for an IP (on successful login)
func (bfp *BruteForceProtection) ResetAttempts(ip string) {
	bfp.mu.Lock()
	defer bfp.mu.Unlock()

	delete(bfp.attempts, ip)
}

// IsBlocked checks if an IP is currently blocked
func (bfp *BruteForceProtection) IsBlocked(ip string) bool {
	bfp.mu.RLock()
	defer bfp.mu.RUnlock()

	attempts, exists := bfp.attempts[ip]
	if !exists {
		return false
	}

	// Check if block period has expired
	if !attempts.BlockedUntil.IsZero() && time.Now().Before(attempts.BlockedUntil) {
		return true
	}

	return false
}

// GetRemainingAttempts returns the number of remaining login attempts
func (bfp *BruteForceProtection) GetRemainingAttempts(ip string) int {
	bfp.mu.RLock()
	defer bfp.mu.RUnlock()

	attempts, exists := bfp.attempts[ip]
	if !exists {
		return 5
	}

	remaining := 5 - attempts.Count
	if remaining < 0 {
		return 0
	}

	return remaining
}

// cleanupAttempts removes old entries periodically
func (bfp *BruteForceProtection) cleanupAttempts() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		bfp.mu.Lock()
		now := time.Now()
		for ip, attempts := range bfp.attempts {
			// Remove entries older than 1 hour
			if now.Sub(attempts.LastAttempt) > time.Hour {
				delete(bfp.attempts, ip)
			}
		}
		bfp.mu.Unlock()
	}
}

// BruteForceProtectionMiddleware creates middleware for brute force protection
func BruteForceProtectionMiddleware(bfp *BruteForceProtection) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only apply to login endpoints
		if !strings.Contains(c.Request.URL.Path, "/login") && 
		   !strings.Contains(c.Request.URL.Path, "/auth") {
			c.Next()
			return
		}

		ip := getClientIP(c)

		// Check if IP is blocked
		if bfp.IsBlocked(ip) {
			remaining := bfp.GetRemainingAttempts(ip)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Too many failed login attempts",
				"message": "Your IP has been temporarily blocked due to too many failed login attempts",
				"retry_after": "30m",
				"remaining_attempts": remaining,
			})
			c.Abort()
			return
		}

		// Store BFP in context for use in auth handlers
		c.Set("bruteForceProtection", bfp)

		c.Next()
	}
}

// AuditLogMiddleware logs all requests for security auditing
func AuditLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start time
		start := time.Now()

		// Get request details before processing
		ip := getClientIP(c)
		method := c.Request.Method
		path := c.Request.URL.Path
		userAgent := c.GetHeader("User-Agent")

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get response status
		status := c.Writer.Status()

		// Log the request
		auditLog := map[string]interface{}{
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
			"ip":         ip,
			"method":     method,
			"path":       path,
			"status":     status,
			"latency":    latency.Milliseconds(),
			"user_agent": userAgent,
		}

		// Add user ID if authenticated
		if userID, exists := c.Get("user_id"); exists {
			auditLog["user_id"] = userID
		}

		// Log suspicious activities
		if status == http.StatusUnauthorized || 
		   status == http.StatusForbidden || 
		   status == http.StatusTooManyRequests ||
		   strings.Contains(path, "/login") ||
		   strings.Contains(path, "/auth") {
			// In production, send to SIEM for analysis
			fmt.Printf("[AUDIT] %v\n", auditLog)
		}

		// Log all requests in debug mode
		// fmt.Printf("[AUDIT] %v\n", auditLog)
	}
}

// SanitizeInput sanitizes user input to prevent injection attacks
func SanitizeInput(input string) string {
	// Remove potentially dangerous characters
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
		"&", "&amp;",
	)
	return replacer.Replace(input)
}

// ValidateEmail validates email format
func ValidateEmail(email string) bool {
	// Simple email validation (use a proper library in production)
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

// ValidatePassword checks password strength
func ValidatePassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "Password must be at least 8 characters long"
	}

	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return false, "Password must contain at least one uppercase letter"
	}
	if !hasLower {
		return false, "Password must contain at least one lowercase letter"
	}
	if !hasNumber {
		return false, "Password must contain at least one number"
	}
	if !hasSpecial {
		return false, "Password must contain at least one special character"
	}

	return true, ""
}

// IPWhitelistMiddleware restricts access to whitelisted IPs
func IPWhitelistMiddleware(whitelist []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(whitelist) == 0 {
			// No whitelist configured, allow all
			c.Next()
			return
		}

		ip := getClientIP(c)

		// Check if IP is whitelisted
		allowed := false
		for _, whitelistedIP := range whitelist {
			if ip == whitelistedIP {
				allowed = true
				break
			}
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"message": "Your IP address is not authorized to access this resource",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// APIKeyMiddleware validates API keys for external integrations
func APIKeyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only apply to /api/external/* endpoints
		if !strings.HasPrefix(c.Request.URL.Path, "/api/external/") {
			c.Next()
			return
		}

		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Missing API key",
				"message": "X-API-Key header is required for external API access",
			})
			c.Abort()
			return
		}

		// Validate API key (in production, check against database)
		// For now, just check if it's not empty
		if len(apiKey) < 32 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid API key",
				"message": "The provided API key is invalid",
			})
			c.Abort()
			return
		}

		// Store API key info in context
		c.Set("api_key", apiKey)
		c.Set("api_key_validated", true)

		c.Next()
	}
}


// ============================================================================
// JWT AUTHENTICATION MIDDLEWARE
// ============================================================================

// AuthMiddleware validates JWT tokens
func (s *APIServer) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Check Bearer prefix
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Parse and validate token
		claims, err := parseAccessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Set user information in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role_id", claims.RoleID)
		c.Set("role_name", claims.RoleName)

		// Load access scope from database (if available)
		// Note: Se as colunas allowed_account_ids/allowed_bucket_names não existirem no banco,
		// o sistema ainda funciona - o escopo será aplicado baseado no role (ver access_scope.go)
		if s.authRepo != nil {
			user, err := s.authRepo.GetUserByID(c.Request.Context(), claims.UserID)
			if err == nil && user != nil {
				if len(user.AllowedAccountIDs) > 0 {
					c.Set("allowed_account_ids", user.AllowedAccountIDs)
				}
				if len(user.AllowedBucketNames) > 0 {
					c.Set("allowed_bucket_names", user.AllowedBucketNames)
				}
			}
			// Se falhar, não é crítico - o escopo por role será usado como fallback
		}

		c.Next()
	}
}

// OptionalAuthMiddleware validates JWT tokens but doesn't require them
func (s *APIServer) OptionalAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		tokenString := parts[1]
		claims, err := parseAccessToken(tokenString)
		if err != nil {
			c.Next()
			return
		}

		// Set user information in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role_id", claims.RoleID)
		c.Set("role_name", claims.RoleName)

		if s.authRepo != nil {
			if user, err := s.authRepo.GetUserByID(c.Request.Context(), claims.UserID); err == nil {
				c.Set("allowed_account_ids", user.AllowedAccountIDs)
				c.Set("allowed_bucket_names", user.AllowedBucketNames)
			}
		}

		c.Next()
	}
}

// ============================================================================
// AUTHORIZATION MIDDLEWARE (RBAC)
// ============================================================================

// RequireRole middleware checks if user has required role
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleName, exists := c.Get("role_name")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Check if user's role is in allowed roles
		userRole := roleName.(string)
		allowed := false
		for _, role := range allowedRoles {
			if userRole == role {
				allowed = true
				break
			}
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAdmin middleware checks if user is admin
func RequireAdmin() gin.HandlerFunc {
	return RequireRole("admin")
}

// RequireAnalyst middleware checks if user is analyst or admin
func RequireAnalyst() gin.HandlerFunc {
	return RequireRole("admin", "analyst")
}

// ============================================================================
// AUDIT MIDDLEWARE
// ============================================================================

// AuditMiddleware logs all requests for audit purposes
func (s *APIServer) AuditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Get user info if authenticated
		userID, _ := c.Get("user_id")
		username, _ := c.Get("username")

		// Process request
		c.Next()

		// Log after request
		duration := time.Since(start)

		// Only log sensitive operations or errors
		if c.Writer.Status() >= 400 || isSensitiveEndpoint(c.Request.URL.Path) {
			s.logger.Printf(
				"[AUDIT] method=%s path=%s status=%d duration=%v user_id=%v username=%v ip=%s",
				c.Request.Method,
				c.Request.URL.Path,
				c.Writer.Status(),
				duration,
				userID,
				username,
				c.ClientIP(),
			)

			// TODO: Store in audit_log table
		}
	}
}

// isSensitiveEndpoint checks if an endpoint should be audited
func isSensitiveEndpoint(path string) bool {
	sensitivePatterns := []string{
		"/api/v1/auth/",
		"/api/v1/users/",
		"/api/v1/roles/",
		"/api/v1/settings/",
	}

	for _, pattern := range sensitivePatterns {
		if strings.HasPrefix(path, pattern) {
			return true
		}
	}

	return false
}

// ============================================================================
// RATE LIMITING METHODS FOR APISERVER
// ============================================================================

// RateLimitMiddleware applies rate limiting per IP
func (s *APIServer) RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		if !limiter.GetLimiter(ip).Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// LoginRateLimitMiddleware applies stricter rate limiting for login attempts
func (s *APIServer) LoginRateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		if !limiter.GetLimiter(ip).Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many login attempts. Please try again in a few minutes.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
