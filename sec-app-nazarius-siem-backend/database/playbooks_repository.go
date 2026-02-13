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

// Playbook represents a security playbook
type Playbook struct {
	ID                 string          `json:"id"`
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	Category           string          `json:"category"`
	Severity           string          `json:"severity"`
	Status             string          `json:"status"`
	Actions            json.RawMessage `json:"actions"`
	Triggers           json.RawMessage `json:"triggers,omitempty"`
	Schedule           json.RawMessage `json:"schedule,omitempty"`
	Tags               []string        `json:"tags"`
	Version            int             `json:"version"`
	IsActive           bool            `json:"is_active"`
	ExecutionCount     int             `json:"execution_count"`
	SuccessCount       int             `json:"success_count"`
	FailureCount       int             `json:"failure_count"`
	AvgExecutionTimeMs int             `json:"avg_execution_time_ms"`
	LastExecutedAt     *time.Time      `json:"last_executed_at,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
	CreatedBy          *string         `json:"created_by,omitempty"`
	UpdatedBy          *string         `json:"updated_by,omitempty"`
}

// PlaybookExecution represents a playbook execution record
type PlaybookExecution struct {
	ID           string          `json:"id"`
	PlaybookID   string          `json:"playbook_id"`
	Status       string          `json:"status"`
	TriggerType  *string         `json:"trigger_type,omitempty"`
	TriggerData  json.RawMessage `json:"trigger_data,omitempty"`
	Steps        json.RawMessage `json:"steps"`
	Result       json.RawMessage `json:"result,omitempty"`
	ErrorMessage *string         `json:"error_message,omitempty"`
	StartedAt    time.Time       `json:"started_at"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	DurationMs   *int            `json:"duration_ms,omitempty"`
	ExecutedBy   *string         `json:"executed_by,omitempty"`
}

// PlaybookRepository handles playbook database operations
type PlaybookRepository struct {
	db *sql.DB
}

// NewPlaybookRepository creates a new playbook repository
func NewPlaybookRepository(db *sql.DB) *PlaybookRepository {
	return &PlaybookRepository{db: db}
}

// Create creates a new playbook
func (r *PlaybookRepository) Create(ctx context.Context, playbook *Playbook) error {
	query := `
		INSERT INTO playbooks (
			id, name, description, category, severity, status, actions, 
			triggers, schedule, tags, version, is_active, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING created_at, updated_at
	`

	if playbook.ID == "" {
		playbook.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(
		ctx,
		query,
		playbook.ID,
		playbook.Name,
		playbook.Description,
		playbook.Category,
		playbook.Severity,
		playbook.Status,
		playbook.Actions,
		playbook.Triggers,
		playbook.Schedule,
		pq.Array(playbook.Tags),
		playbook.Version,
		playbook.IsActive,
		playbook.CreatedBy,
	).Scan(&playbook.CreatedAt, &playbook.UpdatedAt)

	if err != nil {
		return fmt.Errorf("error creating playbook: %w", err)
	}

	return nil
}

// GetByID retrieves a playbook by ID
func (r *PlaybookRepository) GetByID(ctx context.Context, id string) (*Playbook, error) {
	query := `
		SELECT 
			id, name, description, category, severity, status, actions, triggers, schedule,
			tags, version, is_active, execution_count, success_count, failure_count,
			avg_execution_time_ms, last_executed_at, created_at, updated_at, created_by, updated_by
		FROM playbooks
		WHERE id = $1
	`

	playbook := &Playbook{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&playbook.ID,
		&playbook.Name,
		&playbook.Description,
		&playbook.Category,
		&playbook.Severity,
		&playbook.Status,
		&playbook.Actions,
		&playbook.Triggers,
		&playbook.Schedule,
		pq.Array(&playbook.Tags),
		&playbook.Version,
		&playbook.IsActive,
		&playbook.ExecutionCount,
		&playbook.SuccessCount,
		&playbook.FailureCount,
		&playbook.AvgExecutionTimeMs,
		&playbook.LastExecutedAt,
		&playbook.CreatedAt,
		&playbook.UpdatedAt,
		&playbook.CreatedBy,
		&playbook.UpdatedBy,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("playbook not found")
	}
	if err != nil {
		return nil, fmt.Errorf("error getting playbook: %w", err)
	}

	return playbook, nil
}

// List retrieves all playbooks with optional filters
func (r *PlaybookRepository) List(ctx context.Context, filters map[string]interface{}) ([]*Playbook, error) {
	query := `
		SELECT 
			id, name, description, category, severity, status, actions, triggers, schedule,
			tags, version, is_active, execution_count, success_count, failure_count,
			avg_execution_time_ms, last_executed_at, created_at, updated_at, created_by, updated_by
		FROM playbooks
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

	if category, ok := filters["category"].(string); ok && category != "" {
		query += fmt.Sprintf(" AND category = $%d", argCount)
		args = append(args, category)
		argCount++
	}

	if isActive, ok := filters["is_active"].(bool); ok {
		query += fmt.Sprintf(" AND is_active = $%d", argCount)
		args = append(args, isActive)
		argCount++
	}

	query += " ORDER BY created_at DESC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("error listing playbooks: %w", err)
	}
	defer rows.Close()

	playbooks := []*Playbook{}
	for rows.Next() {
		playbook := &Playbook{}
		err := rows.Scan(
			&playbook.ID,
			&playbook.Name,
			&playbook.Description,
			&playbook.Category,
			&playbook.Severity,
			&playbook.Status,
			&playbook.Actions,
			&playbook.Triggers,
			&playbook.Schedule,
			pq.Array(&playbook.Tags),
			&playbook.Version,
			&playbook.IsActive,
			&playbook.ExecutionCount,
			&playbook.SuccessCount,
			&playbook.FailureCount,
			&playbook.AvgExecutionTimeMs,
			&playbook.LastExecutedAt,
			&playbook.CreatedAt,
			&playbook.UpdatedAt,
			&playbook.CreatedBy,
			&playbook.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning playbook: %w", err)
		}
		playbooks = append(playbooks, playbook)
	}

	return playbooks, nil
}

// Update updates an existing playbook
func (r *PlaybookRepository) Update(ctx context.Context, playbook *Playbook) error {
	query := `
		UPDATE playbooks
		SET name = $2, description = $3, category = $4, severity = $5, status = $6,
			actions = $7, triggers = $8, schedule = $9, tags = $10, version = version + 1,
			is_active = $11, updated_by = $12, updated_at = NOW()
		WHERE id = $1
		RETURNING version, updated_at
	`

	err := r.db.QueryRowContext(
		ctx,
		query,
		playbook.ID,
		playbook.Name,
		playbook.Description,
		playbook.Category,
		playbook.Severity,
		playbook.Status,
		playbook.Actions,
		playbook.Triggers,
		playbook.Schedule,
		pq.Array(playbook.Tags),
		playbook.IsActive,
		playbook.UpdatedBy,
	).Scan(&playbook.Version, &playbook.UpdatedAt)

	if err == sql.ErrNoRows {
		return fmt.Errorf("playbook not found")
	}
	if err != nil {
		return fmt.Errorf("error updating playbook: %w", err)
	}

	return nil
}

// Delete deletes a playbook
func (r *PlaybookRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM playbooks WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("error deleting playbook: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("playbook not found")
	}

	return nil
}

// UpdateExecutionStats updates playbook execution statistics
func (r *PlaybookRepository) UpdateExecutionStats(ctx context.Context, id string, success bool, durationMs int) error {
	query := `
		UPDATE playbooks
		SET execution_count = execution_count + 1,
			success_count = success_count + CASE WHEN $2 THEN 1 ELSE 0 END,
			failure_count = failure_count + CASE WHEN $2 THEN 0 ELSE 1 END,
			avg_execution_time_ms = (avg_execution_time_ms * execution_count + $3) / (execution_count + 1),
			last_executed_at = NOW()
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, id, success, durationMs)
	if err != nil {
		return fmt.Errorf("error updating execution stats: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("playbook not found")
	}

	return nil
}

// CreateExecution creates a new playbook execution record
func (r *PlaybookRepository) CreateExecution(ctx context.Context, execution *PlaybookExecution) error {
	query := `
		INSERT INTO playbook_executions (
			id, playbook_id, status, trigger_type, trigger_data, steps, executed_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING started_at
	`

	if execution.ID == "" {
		execution.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(
		ctx,
		query,
		execution.ID,
		execution.PlaybookID,
		execution.Status,
		execution.TriggerType,
		execution.TriggerData,
		execution.Steps,
		execution.ExecutedBy,
	).Scan(&execution.StartedAt)

	if err != nil {
		return fmt.Errorf("error creating execution: %w", err)
	}

	return nil
}

// UpdateExecution updates a playbook execution
func (r *PlaybookRepository) UpdateExecution(ctx context.Context, execution *PlaybookExecution) error {
	query := `
		UPDATE playbook_executions
		SET status = $2, steps = $3, result = $4, error_message = $5,
			completed_at = $6, duration_ms = $7
		WHERE id = $1
	`

	result, err := r.db.ExecContext(
		ctx,
		query,
		execution.ID,
		execution.Status,
		execution.Steps,
		execution.Result,
		execution.ErrorMessage,
		execution.CompletedAt,
		execution.DurationMs,
	)

	if err != nil {
		return fmt.Errorf("error updating execution: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("execution not found")
	}

	return nil
}

// GetExecutionsByPlaybookID retrieves all executions for a playbook
func (r *PlaybookRepository) GetExecutionsByPlaybookID(ctx context.Context, playbookID string, limit int) ([]*PlaybookExecution, error) {
	query := `
		SELECT 
			id, playbook_id, status, trigger_type, trigger_data, steps, result,
			error_message, started_at, completed_at, duration_ms, executed_by
		FROM playbook_executions
		WHERE playbook_id = $1
		ORDER BY started_at DESC
		LIMIT $2
	`

	if limit == 0 {
		limit = 50 // default limit
	}

	rows, err := r.db.QueryContext(ctx, query, playbookID, limit)
	if err != nil {
		return nil, fmt.Errorf("error getting executions: %w", err)
	}
	defer rows.Close()

	executions := []*PlaybookExecution{}
	for rows.Next() {
		execution := &PlaybookExecution{}
		err := rows.Scan(
			&execution.ID,
			&execution.PlaybookID,
			&execution.Status,
			&execution.TriggerType,
			&execution.TriggerData,
			&execution.Steps,
			&execution.Result,
			&execution.ErrorMessage,
			&execution.StartedAt,
			&execution.CompletedAt,
			&execution.DurationMs,
			&execution.ExecutedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning execution: %w", err)
		}
		executions = append(executions, execution)
	}

	return executions, nil
}

