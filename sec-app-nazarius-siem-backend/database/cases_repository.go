package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Case represents a security incident case
type Case struct {
	ID                    string          `json:"id"`
	Title                 string          `json:"title"`
	Description           string          `json:"description"`
	Severity              string          `json:"severity"`
	Status                string          `json:"status"`
	Priority              string          `json:"priority"`
	Category              string          `json:"category"`
	AssignedTo            *string         `json:"assigned_to,omitempty"`
	SLADeadline           *time.Time      `json:"sla_deadline,omitempty"`
	Tags                  []string        `json:"tags"`
	AlertIDs              []string        `json:"alert_ids"`
	Evidence              json.RawMessage `json:"evidence"`
	Timeline              json.RawMessage `json:"timeline"`
	MitreTactics          []string        `json:"mitre_tactics"`
	MitreTechniques       []string        `json:"mitre_techniques"`
	AffectedAssets        []string        `json:"affected_assets"`
	Indicators            json.RawMessage `json:"indicators"`
	Resolution            *string         `json:"resolution,omitempty"`
	ResolutionTimeMinutes *int            `json:"resolution_time_minutes,omitempty"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
	ClosedAt              *time.Time      `json:"closed_at,omitempty"`
	CreatedBy             *string         `json:"created_by,omitempty"`
	UpdatedBy             *string         `json:"updated_by,omitempty"`
}

// CaseComment represents a comment on a case
type CaseComment struct {
	ID         string    `json:"id"`
	CaseID     string    `json:"case_id"`
	UserID     string    `json:"user_id"`
	Comment    string    `json:"comment"`
	IsInternal bool      `json:"is_internal"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CaseRepository handles case database operations
type CaseRepository struct {
	db *sql.DB
}

// NewCaseRepository creates a new case repository
func NewCaseRepository(db *sql.DB) *CaseRepository {
	return &CaseRepository{db: db}
}

// Create creates a new case
func (r *CaseRepository) Create(ctx context.Context, c *Case) error {
	query := `
		INSERT INTO cases (
			id, title, description, severity, status, priority, category,
			assigned_to, sla_deadline, tags, alert_ids, evidence, timeline,
			mitre_tactics, mitre_techniques, affected_assets, indicators, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		RETURNING created_at, updated_at
	`

	if c.ID == "" {
		c.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(
		ctx,
		query,
		c.ID,
		c.Title,
		c.Description,
		c.Severity,
		c.Status,
		c.Priority,
		c.Category,
		c.AssignedTo,
		c.SLADeadline,
		pq.Array(c.Tags),
		pq.Array(c.AlertIDs),
		c.Evidence,
		c.Timeline,
		pq.Array(c.MitreTactics),
		pq.Array(c.MitreTechniques),
		pq.Array(c.AffectedAssets),
		c.Indicators,
		c.CreatedBy,
	).Scan(&c.CreatedAt, &c.UpdatedAt)

	if err != nil {
		return fmt.Errorf("error creating case: %w", err)
	}

	return nil
}

// GetByID retrieves a case by ID
func (r *CaseRepository) GetByID(ctx context.Context, id string) (*Case, error) {
	query := `
		SELECT 
			id, title, description, severity, status, priority, category,
			assigned_to, sla_deadline, tags, alert_ids, evidence, timeline,
			mitre_tactics, mitre_techniques, affected_assets, indicators,
			resolution, resolution_time_minutes, created_at, updated_at,
			closed_at, created_by, updated_by
		FROM cases
		WHERE id = $1
	`

	c := &Case{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&c.ID,
		&c.Title,
		&c.Description,
		&c.Severity,
		&c.Status,
		&c.Priority,
		&c.Category,
		&c.AssignedTo,
		&c.SLADeadline,
		pq.Array(&c.Tags),
		pq.Array(&c.AlertIDs),
		&c.Evidence,
		&c.Timeline,
		pq.Array(&c.MitreTactics),
		pq.Array(&c.MitreTechniques),
		pq.Array(&c.AffectedAssets),
		&c.Indicators,
		&c.Resolution,
		&c.ResolutionTimeMinutes,
		&c.CreatedAt,
		&c.UpdatedAt,
		&c.ClosedAt,
		&c.CreatedBy,
		&c.UpdatedBy,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("case not found")
	}
	if err != nil {
		return nil, fmt.Errorf("error getting case: %w", err)
	}

	return c, nil
}

// List retrieves all cases with optional filters
func (r *CaseRepository) List(ctx context.Context, filters map[string]interface{}) ([]*Case, error) {
	query := `
		SELECT 
			id, title, description, severity, status, priority, category,
			assigned_to, sla_deadline, tags, alert_ids, evidence, timeline,
			mitre_tactics, mitre_techniques, affected_assets, indicators,
			resolution, resolution_time_minutes, created_at, updated_at,
			closed_at, created_by, updated_by
		FROM cases
		WHERE 1=1
	`

	args := []interface{}{}
	argCount := 1

	// Apply filters
	if status, ok := filters["status"].(string); ok && status != "" {
		query += fmt.Sprintf(" AND status = $%d", argCount)
		args = append(args, status)
		argCount++
	}

	if severity, ok := filters["severity"].(string); ok && severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argCount)
		args = append(args, severity)
		argCount++
	}

	if assignedTo, ok := filters["assigned_to"].(string); ok && assignedTo != "" {
		query += fmt.Sprintf(" AND assigned_to = $%d", argCount)
		args = append(args, assignedTo)
		argCount++
	}

	query += " ORDER BY created_at DESC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("error listing cases: %w", err)
	}
	defer rows.Close()

	cases := []*Case{}
	for rows.Next() {
		c := &Case{}
		err := rows.Scan(
			&c.ID,
			&c.Title,
			&c.Description,
			&c.Severity,
			&c.Status,
			&c.Priority,
			&c.Category,
			&c.AssignedTo,
			&c.SLADeadline,
			pq.Array(&c.Tags),
			pq.Array(&c.AlertIDs),
			&c.Evidence,
			&c.Timeline,
			pq.Array(&c.MitreTactics),
			pq.Array(&c.MitreTechniques),
			pq.Array(&c.AffectedAssets),
			&c.Indicators,
			&c.Resolution,
			&c.ResolutionTimeMinutes,
			&c.CreatedAt,
			&c.UpdatedAt,
			&c.ClosedAt,
			&c.CreatedBy,
			&c.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning case: %w", err)
		}
		cases = append(cases, c)
	}

	return cases, nil
}

// Update updates an existing case
func (r *CaseRepository) Update(ctx context.Context, c *Case) error {
	query := `
		UPDATE cases
		SET title = $2, description = $3, severity = $4, status = $5, priority = $6,
			category = $7, assigned_to = $8, sla_deadline = $9, tags = $10, alert_ids = $11,
			evidence = $12, timeline = $13, mitre_tactics = $14, mitre_techniques = $15,
			affected_assets = $16, indicators = $17, resolution = $18, updated_by = $19,
			updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at
	`

	err := r.db.QueryRowContext(
		ctx,
		query,
		c.ID,
		c.Title,
		c.Description,
		c.Severity,
		c.Status,
		c.Priority,
		c.Category,
		c.AssignedTo,
		c.SLADeadline,
		pq.Array(c.Tags),
		pq.Array(c.AlertIDs),
		c.Evidence,
		c.Timeline,
		pq.Array(c.MitreTactics),
		pq.Array(c.MitreTechniques),
		pq.Array(c.AffectedAssets),
		c.Indicators,
		c.Resolution,
		c.UpdatedBy,
	).Scan(&c.UpdatedAt)

	if err == sql.ErrNoRows {
		return fmt.Errorf("case not found")
	}
	if err != nil {
		return fmt.Errorf("error updating case: %w", err)
	}

	return nil
}

// Close closes a case
func (r *CaseRepository) Close(ctx context.Context, id string, resolution string, updatedBy *string) error {
	query := `
		UPDATE cases
		SET status = 'closed',
			resolution = $2,
			closed_at = NOW(),
			resolution_time_minutes = EXTRACT(EPOCH FROM (NOW() - created_at)) / 60,
			updated_by = $3,
			updated_at = NOW()
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, id, resolution, updatedBy)
	if err != nil {
		return fmt.Errorf("error closing case: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("case not found")
	}

	return nil
}

// Delete deletes a case
func (r *CaseRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM cases WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("error deleting case: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("case not found")
	}

	return nil
}

// AddComment adds a comment to a case
func (r *CaseRepository) AddComment(ctx context.Context, comment *CaseComment) error {
	query := `
		INSERT INTO case_comments (id, case_id, user_id, comment, is_internal)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at, updated_at
	`

	if comment.ID == "" {
		comment.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(
		ctx,
		query,
		comment.ID,
		comment.CaseID,
		comment.UserID,
		comment.Comment,
		comment.IsInternal,
	).Scan(&comment.CreatedAt, &comment.UpdatedAt)

	if err != nil {
		return fmt.Errorf("error adding comment: %w", err)
	}

	return nil
}

// GetComments retrieves all comments for a case
func (r *CaseRepository) GetComments(ctx context.Context, caseID string) ([]*CaseComment, error) {
	query := `
		SELECT id, case_id, user_id, comment, is_internal, created_at, updated_at
		FROM case_comments
		WHERE case_id = $1
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, caseID)
	if err != nil {
		return nil, fmt.Errorf("error getting comments: %w", err)
	}
	defer rows.Close()

	comments := []*CaseComment{}
	for rows.Next() {
		comment := &CaseComment{}
		err := rows.Scan(
			&comment.ID,
			&comment.CaseID,
			&comment.UserID,
			&comment.Comment,
			&comment.IsInternal,
			&comment.CreatedAt,
			&comment.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning comment: %w", err)
		}
		comments = append(comments, comment)
	}

	return comments, nil
}

// GetStats retrieves case statistics
func (r *CaseRepository) GetStats(ctx context.Context) (map[string]interface{}, error) {
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'open') as open,
			COUNT(*) FILTER (WHERE status = 'in_progress') as in_progress,
			COUNT(*) FILTER (WHERE status = 'closed') as closed,
			COUNT(*) FILTER (WHERE severity = 'critical') as critical,
			COUNT(*) FILTER (WHERE severity = 'high') as high,
			COUNT(*) FILTER (WHERE severity = 'medium') as medium,
			COUNT(*) FILTER (WHERE severity = 'low') as low,
			AVG(resolution_time_minutes) FILTER (WHERE resolution_time_minutes IS NOT NULL) as avg_resolution_time
		FROM cases
	`

	var stats struct {
		Total               int
		Open                int
		InProgress          int
		Closed              int
		Critical            int
		High                int
		Medium              int
		Low                 int
		AvgResolutionTime   sql.NullFloat64
	}

	err := r.db.QueryRowContext(ctx, query).Scan(
		&stats.Total,
		&stats.Open,
		&stats.InProgress,
		&stats.Closed,
		&stats.Critical,
		&stats.High,
		&stats.Medium,
		&stats.Low,
		&stats.AvgResolutionTime,
	)

	if err != nil {
		return nil, fmt.Errorf("error getting stats: %w", err)
	}

	result := map[string]interface{}{
		"total":       stats.Total,
		"open":        stats.Open,
		"in_progress": stats.InProgress,
		"closed":      stats.Closed,
		"critical":    stats.Critical,
		"high":        stats.High,
		"medium":      stats.Medium,
		"low":         stats.Low,
	}

	if stats.AvgResolutionTime.Valid {
		result["avg_resolution_time_minutes"] = stats.AvgResolutionTime.Float64
	} else {
		result["avg_resolution_time_minutes"] = 0
	}

	return result, nil
}

