package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Dashboard struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Layout      []Panel        `json:"layout"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	CreatedBy   string         `json:"created_by"`
	IsPublic    bool          `json:"is_public"`
}

type Panel struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Title    string                 `json:"title"`
	Query    string                 `json:"query"`
	Config   map[string]interface{} `json:"config"`
	Position map[string]int         `json:"position"`
}

func (s *APIServer) handleListDashboards(c *gin.Context) {
	userID := c.GetString("user_id")
	isAdmin := c.GetBool("is_admin")

	// Construir query para listar dashboards
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"should": []map[string]interface{}{
				{
					"term": map[string]interface{}{
						"created_by": userID,
					},
				},
				{
					"term": map[string]interface{}{
						"is_public": true,
					},
				},
			},
			"minimum_should_match": 1,
		},
	}

	if isAdmin {
		query = map[string]interface{}{
			"match_all": map[string]interface{}{},
		}
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao criar query"})
		return
	}

	res, err := s.opensearch.Search(
		s.opensearch.Search.WithContext(c.Request.Context()),
		s.opensearch.Search.WithIndex("siem-dashboards"),
		s.opensearch.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao buscar dashboards"})
		return
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao decodificar resposta"})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (s *APIServer) handleCreateDashboard(c *gin.Context) {
	var dashboard Dashboard
	if err := c.ShouldBindJSON(&dashboard); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validar dashboard
	if err := validateDashboard(&dashboard); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Definir metadados
	dashboard.ID = uuid.New().String()
	dashboard.CreatedAt = time.Now()
	dashboard.UpdatedAt = time.Now()
	dashboard.CreatedBy = c.GetString("user_id")

	// Salvar no Elasticsearch
	dashboardJSON, err := json.Marshal(dashboard)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao serializar dashboard"})
		return
	}

	res, err := s.opensearch.Index(
		"siem-dashboards",
		strings.NewReader(string(dashboardJSON)),
		s.opensearch.Index.WithContext(c.Request.Context()),
		s.opensearch.Index.WithDocumentID(dashboard.ID),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao criar dashboard"})
		return
	}
	defer res.Body.Close()

	c.JSON(http.StatusCreated, dashboard)
}

func (s *APIServer) handleUpdateDashboard(c *gin.Context) {
	id := c.Param("id")
	userID := c.GetString("user_id")
	isAdmin := c.GetBool("is_admin")

	// Verificar permissão
	if !isAdmin {
		// Buscar dashboard atual
		res, err := s.opensearch.Get(
			"siem-dashboards",
			id,
			s.opensearch.Get.WithContext(c.Request.Context()),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao buscar dashboard"})
			return
		}
		defer res.Body.Close()

		var currentDashboard Dashboard
		if err := json.NewDecoder(res.Body).Decode(&currentDashboard); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao decodificar dashboard"})
			return
		}

		if currentDashboard.CreatedBy != userID {
			c.JSON(http.StatusForbidden, gin.H{"error": "Sem permissão para editar este dashboard"})
			return
		}
	}

	var dashboard Dashboard
	if err := c.ShouldBindJSON(&dashboard); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validar dashboard
	if err := validateDashboard(&dashboard); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dashboard.UpdatedAt = time.Now()

	// Atualizar no Elasticsearch
	dashboardJSON, err := json.Marshal(map[string]interface{}{
		"doc": dashboard,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao serializar dashboard"})
		return
	}

	res, err := s.opensearch.Update(
		"siem-dashboards",
		id,
		strings.NewReader(string(dashboardJSON)),
		s.opensearch.Update.WithContext(c.Request.Context()),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao atualizar dashboard"})
		return
	}
	defer res.Body.Close()

	if res.StatusCode == 404 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dashboard não encontrado"})
		return
	}

	c.JSON(http.StatusOK, dashboard)
}

func validateDashboard(dashboard *Dashboard) error {
	if dashboard.Name == "" {
		return errors.New("nome do dashboard é obrigatório")
	}

	if len(dashboard.Layout) == 0 {
		return errors.New("dashboard deve ter pelo menos um painel")
	}

	for _, panel := range dashboard.Layout {
		if panel.Title == "" {
			return errors.New("título do painel é obrigatório")
		}
		if panel.Type == "" {
			return errors.New("tipo do painel é obrigatório")
		}
		if panel.Query == "" {
			return errors.New("query do painel é obrigatória")
		}
	}

	return nil
}