package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aibbp/aibbp/internal/models"
)

// Repository provides data access operations.
type Repository struct {
	db *DB
}

// NewRepository creates a new Repository.
func NewRepository(db *DB) *Repository {
	return &Repository{db: db}
}

// ── Programs ─────────────────────────────────────────────────────────

// CreateProgram inserts a new program.
func (r *Repository) CreateProgram(ctx context.Context, p *models.Program) error {
	p.ID = uuid.New()
	p.CreatedAt = time.Now().UTC()
	p.UpdatedAt = p.CreatedAt

	_, err := r.db.Pool.Exec(ctx,
		`INSERT INTO programs (id, platform, handle, name, policy_url, scope_raw, max_severity, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		p.ID, p.Platform, p.Handle, p.Name, p.PolicyURL, p.ScopeRaw, p.MaxSeverity, p.Status, p.CreatedAt, p.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert program: %w", err)
	}
	return nil
}

// GetProgram retrieves a program by ID.
func (r *Repository) GetProgram(ctx context.Context, id uuid.UUID) (*models.Program, error) {
	var p models.Program
	err := r.db.Pool.QueryRow(ctx,
		`SELECT id, platform, handle, name, policy_url, scope_raw, max_severity, status, created_at, updated_at
		 FROM programs WHERE id = $1`, id,
	).Scan(&p.ID, &p.Platform, &p.Handle, &p.Name, &p.PolicyURL, &p.ScopeRaw, &p.MaxSeverity, &p.Status, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get program: %w", err)
	}
	return &p, nil
}

// ListPrograms returns all programs with the given status.
func (r *Repository) ListPrograms(ctx context.Context, status string) ([]models.Program, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT id, platform, handle, name, policy_url, scope_raw, max_severity, status, created_at, updated_at
		 FROM programs WHERE status = $1 ORDER BY created_at DESC`, status,
	)
	if err != nil {
		return nil, fmt.Errorf("list programs: %w", err)
	}
	defer rows.Close()

	var programs []models.Program
	for rows.Next() {
		var p models.Program
		if err := rows.Scan(&p.ID, &p.Platform, &p.Handle, &p.Name, &p.PolicyURL, &p.ScopeRaw, &p.MaxSeverity, &p.Status, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan program row: %w", err)
		}
		programs = append(programs, p)
	}
	return programs, rows.Err()
}

// ── Subdomains ───────────────────────────────────────────────────────

// UpsertSubdomain inserts or updates a subdomain.
func (r *Repository) UpsertSubdomain(ctx context.Context, s *models.Subdomain) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	now := time.Now().UTC()
	if s.FirstSeen.IsZero() {
		s.FirstSeen = now
	}
	s.LastSeen = now

	techJSON, _ := json.Marshal(s.Technologies)

	_, err := r.db.Pool.Exec(ctx,
		`INSERT INTO subdomains (id, root_domain_id, program_id, hostname, ip_addresses, cnames, is_alive, http_status, title, technologies, priority, source, first_seen, last_seen)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 ON CONFLICT (program_id, hostname) DO UPDATE SET
		   ip_addresses = EXCLUDED.ip_addresses,
		   cnames = EXCLUDED.cnames,
		   is_alive = EXCLUDED.is_alive,
		   http_status = EXCLUDED.http_status,
		   title = EXCLUDED.title,
		   technologies = EXCLUDED.technologies,
		   last_seen = EXCLUDED.last_seen`,
		s.ID, s.RootDomainID, s.ProgramID, s.Hostname, s.IPAddresses, s.CNAMEs,
		s.IsAlive, s.HTTPStatus, s.Title, techJSON, s.Priority, s.Source, s.FirstSeen, s.LastSeen,
	)
	if err != nil {
		return fmt.Errorf("upsert subdomain: %w", err)
	}
	return nil
}

// GetAliveSubdomains returns alive subdomains ordered by priority.
func (r *Repository) GetAliveSubdomains(ctx context.Context, programID uuid.UUID) ([]models.Subdomain, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT id, root_domain_id, program_id, hostname, ip_addresses, cnames, is_alive, http_status, title, technologies, priority, source, first_seen, last_seen
		 FROM subdomains WHERE program_id = $1 AND is_alive = TRUE ORDER BY priority DESC`, programID,
	)
	if err != nil {
		return nil, fmt.Errorf("get alive subdomains: %w", err)
	}
	defer rows.Close()

	var subs []models.Subdomain
	for rows.Next() {
		var s models.Subdomain
		if err := rows.Scan(&s.ID, &s.RootDomainID, &s.ProgramID, &s.Hostname, &s.IPAddresses, &s.CNAMEs,
			&s.IsAlive, &s.HTTPStatus, &s.Title, &s.Technologies, &s.Priority, &s.Source, &s.FirstSeen, &s.LastSeen); err != nil {
			return nil, fmt.Errorf("scan subdomain row: %w", err)
		}
		subs = append(subs, s)
	}
	return subs, rows.Err()
}

// ── Vulnerabilities ──────────────────────────────────────────────────

// CreateVulnerability inserts a new vulnerability.
func (r *Repository) CreateVulnerability(ctx context.Context, v *models.Vulnerability) error {
	v.ID = uuid.New()
	v.DiscoveredAt = time.Now().UTC()

	_, err := r.db.Pool.Exec(ctx,
		`INSERT INTO vulnerabilities (id, program_id, subdomain_id, url_id, type, severity, status, title, description,
		 evidence, confidence, cvss_score, cvss_vector, endpoint, parameter, payload, impact, remediation, source, dedup_hash, discovered_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		v.ID, v.ProgramID, v.SubdomainID, v.URLID, v.Type, v.Severity, v.Status, v.Title, v.Description,
		v.Evidence, v.Confidence, v.CVSSScore, v.CVSSVector, v.Endpoint, v.Parameter, v.Payload, v.Impact, v.Remediation,
		v.Source, v.DedupHash, v.DiscoveredAt,
	)
	if err != nil {
		return fmt.Errorf("insert vulnerability: %w", err)
	}
	return nil
}

// VulnExistsByHash checks if a vulnerability with the same dedup hash exists.
func (r *Repository) VulnExistsByHash(ctx context.Context, programID uuid.UUID, dedupHash string) (bool, error) {
	var exists bool
	err := r.db.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM vulnerabilities WHERE program_id = $1 AND dedup_hash = $2)`,
		programID, dedupHash,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check vuln exists: %w", err)
	}
	return exists, nil
}

// UpdateVulnStatus updates the status of a vulnerability.
func (r *Repository) UpdateVulnStatus(ctx context.Context, vulnID uuid.UUID, status models.VulnStatus) error {
	_, err := r.db.Pool.Exec(ctx,
		`UPDATE vulnerabilities SET status = $1, validated_at = $2 WHERE id = $3`,
		status, time.Now().UTC(), vulnID,
	)
	if err != nil {
		return fmt.Errorf("update vuln status: %w", err)
	}
	return nil
}

// GetVulnerabilities returns vulnerabilities for a program filtered by status.
func (r *Repository) GetVulnerabilities(ctx context.Context, programID uuid.UUID, status models.VulnStatus) ([]models.Vulnerability, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT id, program_id, subdomain_id, url_id, type, severity, status, title, description,
		 evidence, confidence, cvss_score, cvss_vector, endpoint, parameter, payload, impact, remediation,
		 source, dedup_hash, report_url, discovered_at, validated_at, reported_at
		 FROM vulnerabilities WHERE program_id = $1 AND status = $2 ORDER BY confidence DESC, severity DESC`,
		programID, status,
	)
	if err != nil {
		return nil, fmt.Errorf("get vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulns []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		if err := rows.Scan(&v.ID, &v.ProgramID, &v.SubdomainID, &v.URLID, &v.Type, &v.Severity, &v.Status,
			&v.Title, &v.Description, &v.Evidence, &v.Confidence, &v.CVSSScore, &v.CVSSVector,
			&v.Endpoint, &v.Parameter, &v.Payload, &v.Impact, &v.Remediation,
			&v.Source, &v.DedupHash, &v.ReportURL, &v.DiscoveredAt, &v.ValidatedAt, &v.ReportedAt); err != nil {
			return nil, fmt.Errorf("scan vuln row: %w", err)
		}
		vulns = append(vulns, v)
	}
	return vulns, rows.Err()
}

// ── Scans ────────────────────────────────────────────────────────────

// CreateScan inserts a new scan record.
func (r *Repository) CreateScan(ctx context.Context, s *models.Scan) error {
	s.ID = uuid.New()
	s.CreatedAt = time.Now().UTC()

	_, err := r.db.Pool.Exec(ctx,
		`INSERT INTO scans (id, program_id, scanner_type, target, status, config, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		s.ID, s.ProgramID, s.ScannerType, s.Target, s.Status, s.Config, s.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}
	return nil
}

// UpdateScanStatus updates scan status and optional fields.
func (r *Repository) UpdateScanStatus(ctx context.Context, scanID uuid.UUID, status models.ScanStatus, resultCount int, errMsg string, durationMs int64) error {
	now := time.Now().UTC()
	var startedAt, completedAt *time.Time

	switch status {
	case models.ScanStatusRunning:
		startedAt = &now
	case models.ScanStatusCompleted, models.ScanStatusFailed, models.ScanStatusCancelled:
		completedAt = &now
	}

	_, err := r.db.Pool.Exec(ctx,
		`UPDATE scans SET status = $1, result_count = $2, error_msg = $3, duration_ms = $4,
		 started_at = COALESCE($5, started_at), completed_at = COALESCE($6, completed_at)
		 WHERE id = $7`,
		status, resultCount, errMsg, durationMs, startedAt, completedAt, scanID,
	)
	if err != nil {
		return fmt.Errorf("update scan status: %w", err)
	}
	return nil
}

// ── Cost Tracking ────────────────────────────────────────────────────

// RecordCost inserts a cost tracking entry.
func (r *Repository) RecordCost(ctx context.Context, ct *models.CostTracking) error {
	ct.ID = uuid.New()
	ct.CreatedAt = time.Now().UTC()

	_, err := r.db.Pool.Exec(ctx,
		`INSERT INTO cost_tracking (id, program_id, scan_id, phase, model, input_tokens, output_tokens,
		 cache_read_tokens, cache_creation_tokens, cost_dollars, prompt_type, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		ct.ID, ct.ProgramID, ct.ScanID, ct.Phase, ct.Model, ct.InputTokens, ct.OutputTokens,
		ct.CacheRead, ct.CacheCreation, ct.CostDollars, ct.PromptType, ct.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert cost tracking: %w", err)
	}
	return nil
}

// GetTotalCost returns the total cost for a program.
func (r *Repository) GetTotalCost(ctx context.Context, programID uuid.UUID) (float64, error) {
	var total float64
	err := r.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(cost_dollars), 0) FROM cost_tracking WHERE program_id = $1`,
		programID,
	).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("get total cost: %w", err)
	}
	return total, nil
}
