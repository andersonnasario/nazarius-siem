package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	Email              string     `json:"email"`
	PasswordHash       string     `json:"-"` // Never expose password hash
	FullName           *string    `json:"full_name,omitempty"`
	RoleID             string     `json:"role_id"`
	RoleName           string     `json:"role_name,omitempty"` // Joined from roles table
	IsActive           bool       `json:"is_active"`
	MustChangePass     bool       `json:"must_change_password"`
	AllowedAccountIDs  []string   `json:"allowed_account_ids,omitempty"`
	AllowedBucketNames []string   `json:"allowed_bucket_names,omitempty"`
	Skills             []string   `json:"skills,omitempty"`
	Specializations    []string   `json:"specializations,omitempty"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// RefreshToken represents a refresh token
type RefreshToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Token     string     `json:"token"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Session represents a user session
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	RefreshToken string    `json:"refresh_token"`
	IPAddress    *string   `json:"ip_address,omitempty"`
	UserAgent    *string   `json:"user_agent,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
}

// Role represents a user role
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AuthRepository handles authentication-related database operations
type AuthRepository struct {
	db *sql.DB
}

// NewAuthRepository creates a new auth repository
func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{db: db}
}

// ============================================================================
// USER OPERATIONS
// ============================================================================

// GetUserByUsername retrieves a user by username
func (r *AuthRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	// Query básica sem campos de escopo (compatível com bancos antigos)
	query := `
		SELECT id, username, email, password_hash, full_name, role, 
		       CASE WHEN status = 'active' THEN true ELSE false END as is_active,
		       false as must_change_password,
		       last_login, created_at, updated_at
		FROM users
		WHERE username = $1
	`

	user := &User{}
	var roleName string
	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&roleName,
		&user.IsActive,
		&user.MustChangePass,
		&user.LastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Set role_id and role_name from the role string
	user.RoleID = roleName
	user.RoleName = roleName

	// Tentar carregar campos de escopo (se existirem no banco)
	r.loadUserAccessScope(ctx, user)

	return user, nil
}

// GetUserByEmail retrieves a user by email
func (r *AuthRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, full_name, role, 
		       CASE WHEN status = 'active' THEN true ELSE false END as is_active,
		       false as must_change_password,
		       last_login, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	user := &User{}
	var roleName string
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&roleName,
		&user.IsActive,
		&user.MustChangePass,
		&user.LastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	user.RoleID = roleName
	user.RoleName = roleName

	// Tentar carregar campos de escopo (se existirem no banco)
	r.loadUserAccessScope(ctx, user)

	return user, nil
}

// GetUserByID retrieves a user by ID
func (r *AuthRepository) GetUserByID(ctx context.Context, userID string) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, full_name, role, 
		       CASE WHEN status = 'active' THEN true ELSE false END as is_active,
		       false as must_change_password,
		       last_login, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	user := &User{}
	var roleName string
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&roleName,
		&user.IsActive,
		&user.MustChangePass,
		&user.LastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Set role_id and role_name from the role string
	user.RoleID = roleName
	user.RoleName = roleName

	// Tentar carregar campos de escopo (se existirem no banco)
	r.loadUserAccessScope(ctx, user)

	return user, nil
}

// loadUserAccessScope tenta carregar os campos de escopo de acesso (se existirem no banco)
// Esta função é tolerante a falhas para compatibilidade com bancos que não têm as colunas
func (r *AuthRepository) loadUserAccessScope(ctx context.Context, user *User) {
	query := `SELECT allowed_account_ids, allowed_bucket_names FROM users WHERE id = $1`
	var allowedAccounts, allowedBuckets []string
	err := r.db.QueryRowContext(ctx, query, user.ID).Scan(
		pq.Array(&allowedAccounts),
		pq.Array(&allowedBuckets),
	)
	if err == nil {
		user.AllowedAccountIDs = allowedAccounts
		user.AllowedBucketNames = allowedBuckets
	}
	// Se falhar (colunas não existem), ignora silenciosamente
}

// CreateUser creates a new user
func (r *AuthRepository) CreateUser(ctx context.Context, user *User, password string) error {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Map is_active to status
	status := "active"
	if !user.IsActive {
		status = "inactive"
	}

	// Query básica (compatível com bancos antigos)
	query := `
		INSERT INTO users (id, username, email, password_hash, full_name, role, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at, updated_at
	`

	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	err = r.db.QueryRowContext(
		ctx,
		query,
		user.ID,
		user.Username,
		user.Email,
		string(hashedPassword),
		user.FullName,
		user.RoleID,
		status,
	).Scan(&user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Tentar atualizar campos de escopo (se existirem no banco)
	if len(user.AllowedAccountIDs) > 0 || len(user.AllowedBucketNames) > 0 {
		r.updateUserAccessScope(ctx, user)
	}

	return nil
}

// updateUserAccessScope tenta atualizar os campos de escopo (se existirem no banco)
func (r *AuthRepository) updateUserAccessScope(ctx context.Context, user *User) {
	query := `UPDATE users SET allowed_account_ids = $1, allowed_bucket_names = $2 WHERE id = $3`
	r.db.ExecContext(ctx, query, pq.Array(user.AllowedAccountIDs), pq.Array(user.AllowedBucketNames), user.ID)
	// Ignora erros (colunas podem não existir)
}

// updateUserSkills updates a user's skills and specializations (if columns exist)
func (r *AuthRepository) updateUserSkills(ctx context.Context, user *User) {
	query := `UPDATE users SET skills = $1, specializations = $2 WHERE id = $3`
	r.db.ExecContext(ctx, query, pq.Array(user.Skills), pq.Array(user.Specializations), user.ID)
	// Ignora erros (colunas podem não existir)
}

// UpdateLastLogin updates the last login timestamp
func (r *AuthRepository) UpdateLastLogin(ctx context.Context, userID string) error {
	query := `UPDATE users SET last_login = NOW() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}

// VerifyPassword verifies a password against the stored hash
func (r *AuthRepository) VerifyPassword(ctx context.Context, username, password string) (*User, error) {
	user, err := r.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	if !user.IsActive {
		return nil, fmt.Errorf("user is not active")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	return user, nil
}

// ChangePassword changes a user's password
func (r *AuthRepository) ChangePassword(ctx context.Context, userID, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	query := `
		UPDATE users 
		SET password_hash = $1, must_change_password = false, updated_at = NOW()
		WHERE id = $2
	`

	_, err = r.db.ExecContext(ctx, query, string(hashedPassword), userID)
	if err != nil {
		return fmt.Errorf("failed to change password: %w", err)
	}

	return nil
}

// ============================================================================
// REFRESH TOKEN OPERATIONS
// ============================================================================

// CreateRefreshToken creates a new refresh token
func (r *AuthRepository) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at
	`

	if token.ID == "" {
		token.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(
		ctx,
		query,
		token.ID,
		token.UserID,
		token.Token,
		token.ExpiresAt,
	).Scan(&token.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}

	return nil
}

// GetRefreshToken retrieves a refresh token
func (r *AuthRepository) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, created_at, revoked_at
		FROM refresh_tokens
		WHERE token = $1 AND revoked_at IS NULL
	`

	refreshToken := &RefreshToken{}
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.Token,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
		&refreshToken.RevokedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("refresh token not found or revoked")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	// Check if expired
	if time.Now().After(refreshToken.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expired")
	}

	return refreshToken, nil
}

// RevokeRefreshToken revokes a refresh token
func (r *AuthRepository) RevokeRefreshToken(ctx context.Context, token string) error {
	query := `UPDATE refresh_tokens SET revoked_at = NOW() WHERE token = $1`
	_, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (r *AuthRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	query := `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all user tokens: %w", err)
	}
	return nil
}

// CleanupExpiredTokens removes expired refresh tokens
func (r *AuthRepository) CleanupExpiredTokens(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW() OR revoked_at < NOW() - INTERVAL '30 days'`
	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}
	return nil
}

// ============================================================================
// SESSION OPERATIONS
// ============================================================================

// CreateSession creates a new session
func (r *AuthRepository) CreateSession(ctx context.Context, session *Session) error {
	query := `
		INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, last_activity)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at
	`

	if session.ID == "" {
		session.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(
		ctx,
		query,
		session.ID,
		session.UserID,
		session.RefreshToken, // RefreshToken maps to token column
		session.IPAddress,
		session.UserAgent,
		session.ExpiresAt,
		time.Now(),
	).Scan(&session.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetUserSessions retrieves all active sessions for a user
func (r *AuthRepository) GetUserSessions(ctx context.Context, userID string) ([]*Session, error) {
	query := `
		SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at, last_activity, is_active
		FROM sessions
		WHERE user_id = $1 AND expires_at > NOW() AND is_active = true
		ORDER BY last_activity DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		session := &Session{}
		var isActive bool
		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.RefreshToken,
			&session.IPAddress,
			&session.UserAgent,
			&session.ExpiresAt,
			&session.CreatedAt,
			&session.LastActivity,
			&isActive,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// UpdateSessionActivity updates the last activity timestamp
func (r *AuthRepository) UpdateSessionActivity(ctx context.Context, refreshToken string) error {
	query := `UPDATE sessions SET last_activity = NOW() WHERE refresh_token = $1`
	_, err := r.db.ExecContext(ctx, query, refreshToken)
	if err != nil {
		return fmt.Errorf("failed to update session activity: %w", err)
	}
	return nil
}

// DeleteSession deletes a session
func (r *AuthRepository) DeleteSession(ctx context.Context, refreshToken string) error {
	query := `DELETE FROM sessions WHERE refresh_token = $1`
	_, err := r.db.ExecContext(ctx, query, refreshToken)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// DeleteAllUserSessions deletes all sessions for a user
func (r *AuthRepository) DeleteAllUserSessions(ctx context.Context, userID string) error {
	query := `DELETE FROM sessions WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete all user sessions: %w", err)
	}
	return nil
}

// CleanupExpiredSessions removes expired sessions
func (r *AuthRepository) CleanupExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`
	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	return nil
}

// ============================================================================
// ROLE OPERATIONS
// ============================================================================

// GetRoleByID retrieves a role by ID
func (r *AuthRepository) GetRoleByID(ctx context.Context, roleID string) (*Role, error) {
	query := `
		SELECT id, name, description, permissions, created_at, updated_at
		FROM roles
		WHERE id = $1
	`

	role := &Role{}
	var permissionsJSON []byte
	err := r.db.QueryRowContext(ctx, query, roleID).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&permissionsJSON,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	// Parse permissions JSON
	if len(permissionsJSON) > 0 {
		// PostgreSQL stores JSONB, we need to unmarshal it
		// For simplicity, we'll use a string array
		role.Permissions = []string{} // TODO: Parse JSON properly
	}

	return role, nil
}

// GetRoleByName retrieves a role by name
func (r *AuthRepository) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	query := `
		SELECT id, name, description, permissions, created_at, updated_at
		FROM roles
		WHERE name = $1
	`

	role := &Role{}
	var permissionsJSON []byte
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&permissionsJSON,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return role, nil
}

// ListUsers lists all users
func (r *AuthRepository) ListUsers(ctx context.Context) ([]*User, error) {
	// Try query with skills and specializations first
	query := `
		SELECT id, username, email, full_name, role, 
		       CASE WHEN status = 'active' THEN true ELSE false END as is_active,
		       false as must_change_password,
		       last_login, created_at, updated_at,
		       skills, specializations
		FROM users
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		// Fallback to query without skills/specializations for older databases
		query = `
			SELECT id, username, email, full_name, role, 
			       CASE WHEN status = 'active' THEN true ELSE false END as is_active,
			       false as must_change_password,
			       last_login, created_at, updated_at
			FROM users
			ORDER BY created_at DESC
		`
		rows, err = r.db.QueryContext(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}
		defer rows.Close()

		var users []*User
		for rows.Next() {
			user := &User{}
			var roleName string
			err := rows.Scan(
				&user.ID,
				&user.Username,
				&user.Email,
				&user.FullName,
				&roleName,
				&user.IsActive,
				&user.MustChangePass,
				&user.LastLoginAt,
				&user.CreatedAt,
				&user.UpdatedAt,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to scan user: %w", err)
			}
			user.RoleID = roleName
			user.RoleName = roleName
			users = append(users, user)
		}
		return users, nil
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		var roleName string
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.FullName,
			&roleName,
			&user.IsActive,
			&user.MustChangePass,
			&user.LastLoginAt,
			&user.CreatedAt,
			&user.UpdatedAt,
			pq.Array(&user.Skills),
			pq.Array(&user.Specializations),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		// Set role_id and role_name from the role string
		user.RoleID = roleName
		user.RoleName = roleName

		users = append(users, user)
	}

	return users, nil
}

// UpdateUser updates a user
func (r *AuthRepository) UpdateUser(ctx context.Context, user *User) error {
	// Map is_active to status
	status := "active"
	if !user.IsActive {
		status = "inactive"
	}

	// Query básica (compatível com bancos antigos)
	query := `
		UPDATE users
		SET email = $1, full_name = $2, role = $3, status = $4, updated_at = $5
		WHERE id = $6
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		user.Email,
		user.FullName,
		user.RoleID,
		status,
		user.UpdatedAt,
		user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Tentar atualizar campos de escopo (se existirem no banco)
	r.updateUserAccessScope(ctx, user)

	// Tentar atualizar skills e specializations (se existirem no banco)
	r.updateUserSkills(ctx, user)

	return nil
}

// UpdatePassword updates a user's password
func (r *AuthRepository) UpdatePassword(ctx context.Context, userID, newPassword string) error {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	query := `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`
	_, err = r.db.ExecContext(ctx, query, string(hashedPassword), userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// DeleteUser deletes a user
func (r *AuthRepository) DeleteUser(ctx context.Context, userID string) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// ============================================================================
// AUDIT LOG
// ============================================================================

// InsertAuditLog writes an entry to the audit_log table.
// This is used by the AuditMiddleware to persist sensitive operations.
func (r *AuthRepository) InsertAuditLog(ctx context.Context, userID, username, action, resourceType, resourceID, ipAddress, userAgent string, success bool, errorMsg string) error {
	query := `
		INSERT INTO audit_log (user_id, username, action, resource_type, resource_id, ip_address, user_agent, success, error_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	var uid interface{}
	if userID != "" {
		uid = userID
	}

	_, err := r.db.ExecContext(ctx, query, uid, username, action, resourceType, resourceID, ipAddress, userAgent, success, errorMsg)
	return err
}
