package main

import (
	"context"
	"net/http"
	"time"

	"github.com/cognimind/siem-platform/database"

	"github.com/gin-gonic/gin"
)

// UserResponse representa um usuário sem dados sensíveis
type UserResponse struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	Email              string     `json:"email"`
	FullName           *string    `json:"full_name,omitempty"`
	RoleID             string     `json:"role_id"`
	RoleName           string     `json:"role_name"`
	IsActive           bool       `json:"is_active"`
	AllowedAccountIDs  []string   `json:"allowed_account_ids,omitempty"`
	AllowedBucketNames []string   `json:"allowed_bucket_names,omitempty"`
	Skills             []string   `json:"skills,omitempty"`
	Specializations    []string   `json:"specializations,omitempty"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// sanitizeUser remove dados sensíveis de um usuário
func sanitizeUser(user *database.User) *UserResponse {
	if user == nil {
		return nil
	}
	return &UserResponse{
		ID:                 user.ID,
		Username:           user.Username,
		Email:              user.Email,
		FullName:           user.FullName,
		RoleID:             user.RoleID,
		RoleName:           user.RoleName,
		IsActive:           user.IsActive,
		AllowedAccountIDs:  user.AllowedAccountIDs,
		AllowedBucketNames: user.AllowedBucketNames,
		Skills:             user.Skills,
		Specializations:    user.Specializations,
		LastLoginAt:        user.LastLoginAt,
		CreatedAt:          user.CreatedAt,
		UpdatedAt:          user.UpdatedAt,
	}
}

// sanitizeUsers remove dados sensíveis de uma lista de usuários
func sanitizeUsers(users []*database.User) []*UserResponse {
	result := make([]*UserResponse, len(users))
	for i, user := range users {
		result[i] = sanitizeUser(user)
	}
	return result
}

// handleListUsers lista todos os usuários
func (s *APIServer) handleListUsers(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	users, err := s.authRepo.ListUsers(ctx)
	if err != nil {
		s.logger.Printf("Failed to list users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}

	// Sanitizar dados sensíveis
	sanitizedUsers := sanitizeUsers(users)

	c.JSON(http.StatusOK, gin.H{
		"users": sanitizedUsers,
		"total": len(sanitizedUsers),
	})
}

// handleGetUser obtém um usuário por ID
func (s *APIServer) handleGetUser(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userID := c.Param("id")

	user, err := s.authRepo.GetUserByID(ctx, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Sanitizar dados sensíveis
	c.JSON(http.StatusOK, sanitizeUser(user))
}

// handleCreateUser cria um novo usuário
func (s *APIServer) handleCreateUser(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var req struct {
		Username           string   `json:"username" binding:"required"`
		Email              string   `json:"email" binding:"required,email"`
		FullName           string   `json:"full_name"`
		Password           string   `json:"password" binding:"required,min=6"`
		RoleID             string   `json:"role_id" binding:"required"`
		IsActive           bool     `json:"is_active"`
		AllowedAccountIDs  []string `json:"allowed_account_ids"`
		AllowedBucketNames []string `json:"allowed_bucket_names"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verificar se usuário já existe (por username)
	existingUser, _ := s.authRepo.GetUserByUsername(ctx, req.Username)
	if existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// Verificar se email já existe
	existingEmail, _ := s.authRepo.GetUserByEmail(ctx, req.Email)
	if existingEmail != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}

	// Criar usuário
	user := &database.User{
		Username:           req.Username,
		Email:              req.Email,
		FullName:           &req.FullName,
		RoleID:             req.RoleID,
		RoleName:           req.RoleID, // Será atualizado pelo CreateUser
		IsActive:           req.IsActive,
		AllowedAccountIDs:  req.AllowedAccountIDs,
		AllowedBucketNames: req.AllowedBucketNames,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	err := s.authRepo.CreateUser(ctx, user, req.Password)
	if err != nil {
		s.logger.Printf("Failed to create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Sanitizar dados sensíveis
	c.JSON(http.StatusCreated, sanitizeUser(user))
}

// handleUpdateUser atualiza um usuário
func (s *APIServer) handleUpdateUser(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userID := c.Param("id")

	var req struct {
		Email              string    `json:"email"`
		FullName           string    `json:"full_name"`
		Password           string    `json:"password"`
		RoleID             string    `json:"role_id"`
		IsActive           *bool     `json:"is_active"`
		AllowedAccountIDs  *[]string `json:"allowed_account_ids"`
		AllowedBucketNames *[]string `json:"allowed_bucket_names"`
		Skills             *[]string `json:"skills"`
		Specializations    *[]string `json:"specializations"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Buscar usuário existente
	user, err := s.authRepo.GetUserByID(ctx, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Atualizar campos
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.FullName != "" {
		user.FullName = &req.FullName
	}
	if req.RoleID != "" {
		user.RoleID = req.RoleID
		user.RoleName = req.RoleID
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	if req.AllowedAccountIDs != nil {
		user.AllowedAccountIDs = *req.AllowedAccountIDs
	}
	if req.AllowedBucketNames != nil {
		user.AllowedBucketNames = *req.AllowedBucketNames
	}
	if req.Skills != nil {
		user.Skills = *req.Skills
	}
	if req.Specializations != nil {
		user.Specializations = *req.Specializations
	}

	user.UpdatedAt = time.Now()

	// Atualizar no banco
	err = s.authRepo.UpdateUser(ctx, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	// Atualizar senha se fornecida
	if req.Password != "" {
		s.logger.Printf("Updating password for user: %s", userID)
		err = s.authRepo.UpdatePassword(ctx, userID, req.Password)
		if err != nil {
			s.logger.Printf("Failed to update password for user %s: %v", userID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
			return
		}
		s.logger.Printf("Password updated successfully for user: %s", userID)
	}

	// Sanitizar dados sensíveis
	c.JSON(http.StatusOK, sanitizeUser(user))
}

// handleDeleteUser deleta um usuário
func (s *APIServer) handleDeleteUser(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userID := c.Param("id")

	// Verificar se usuário existe
	_, err := s.authRepo.GetUserByID(ctx, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Deletar usuário
	err = s.authRepo.DeleteUser(ctx, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// handleListRoles lista todos os roles disponíveis
func (s *APIServer) handleListRoles(c *gin.Context) {
	roles := []gin.H{
		{"id": "admin", "name": "Administrador", "description": "Acesso total ao sistema"},
		{"id": "analyst", "name": "Analista", "description": "Pode visualizar e gerenciar alertas e casos"},
		{"id": "banking", "name": "Banking", "description": "Acesso restrito aos ambientes Banking (PRD, HML, DEV)"},
		{"id": "viewer", "name": "Visualizador", "description": "Apenas visualização"},
	}

	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

// ============================================================================
// USER PROFILE HANDLERS (self-service)
// ============================================================================

// handleGetMyProfile obtém o perfil do usuário logado
func (s *APIServer) handleGetMyProfile(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Pegar user_id do contexto (injetado pelo AuthMiddleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	user, err := s.authRepo.GetUserByID(ctx, userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Sanitizar dados sensíveis
	c.JSON(http.StatusOK, sanitizeUser(user))
}

// handleUpdateMyProfile atualiza o perfil do usuário logado
func (s *APIServer) handleUpdateMyProfile(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Pegar user_id do contexto
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		Email           string   `json:"email" binding:"omitempty,email"`
		FullName        string   `json:"full_name"`
		Skills          []string `json:"skills"`
		Specializations []string `json:"specializations"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Buscar usuário existente
	user, err := s.authRepo.GetUserByID(ctx, userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Atualizar apenas campos permitidos (email, full_name, skills, specializations)
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.FullName != "" {
		user.FullName = &req.FullName
	}
	// Skills e specializations podem ser arrays vazios (limpar)
	if req.Skills != nil {
		user.Skills = req.Skills
	}
	if req.Specializations != nil {
		user.Specializations = req.Specializations
	}

	user.UpdatedAt = time.Now()

	// Atualizar no banco
	err = s.authRepo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Printf("Failed to update profile for user %s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	s.logger.Printf("Profile updated successfully for user: %s", userID)

	// Sanitizar dados sensíveis
	c.JSON(http.StatusOK, sanitizeUser(user))
}

// handleChangeMyPassword altera a senha do usuário logado
func (s *APIServer) handleChangeMyPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Pegar user_id e username do contexto
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	username, _ := c.Get("username")

	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verificar senha atual
	_, err := s.authRepo.VerifyPassword(ctx, username.(string), req.CurrentPassword)
	if err != nil {
		s.logger.Printf("Current password verification failed for user %s", userID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
		return
	}

	// Atualizar senha
	err = s.authRepo.UpdatePassword(ctx, userID.(string), req.NewPassword)
	if err != nil {
		s.logger.Printf("Failed to change password for user %s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to change password"})
		return
	}

	s.logger.Printf("Password changed successfully for user: %s", userID)

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}
