package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ScannerType identifies a scanner tool.
type ScannerType string

const (
	ScannerNmap      ScannerType = "nmap"
	ScannerNuclei    ScannerType = "nuclei"
	ScannerHTTPX     ScannerType = "httpx"
	ScannerSubfinder ScannerType = "subfinder"
	ScannerMasscan   ScannerType = "masscan"
	ScannerFfuf      ScannerType = "ffuf"
	ScannerKatana    ScannerType = "katana"
	ScannerDNSX      ScannerType = "dnsx"
	ScannerGowitness ScannerType = "gowitness"
)

// ScanStatus tracks scan lifecycle.
type ScanStatus string

const (
	ScanStatusPending    ScanStatus = "pending"
	ScanStatusRunning    ScanStatus = "running"
	ScanStatusCompleted  ScanStatus = "completed"
	ScanStatusFailed     ScanStatus = "failed"
	ScanStatusCancelled  ScanStatus = "cancelled"
)

// VulnStatus tracks vulnerability lifecycle.
type VulnStatus string

const (
	VulnStatusRaw       VulnStatus = "raw"
	VulnStatusValidated VulnStatus = "validated"
	VulnStatusFalsePos  VulnStatus = "false_positive"
	VulnStatusReported  VulnStatus = "reported"
	VulnStatusDuplicate VulnStatus = "duplicate"
)

// Severity levels for vulnerabilities.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Program represents a bug bounty program.
type Program struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	Platform    string          `json:"platform" db:"platform"`       // hackerone, bugcrowd, etc.
	Handle      string          `json:"handle" db:"handle"`           // program handle/slug
	Name        string          `json:"name" db:"name"`
	PolicyURL   string          `json:"policy_url" db:"policy_url"`
	ScopeRaw    json.RawMessage `json:"scope_raw" db:"scope_raw"`     // Original scope JSON
	InScope     []string        `json:"in_scope" db:"-"`              // Parsed in-scope domains
	OutOfScope  []string        `json:"out_of_scope" db:"-"`          // Parsed OOS domains
	MaxSeverity Severity        `json:"max_severity" db:"max_severity"`
	Status      string          `json:"status" db:"status"`           // active, paused, ended
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at" db:"updated_at"`
}

// RootDomain represents a root domain in scope.
type RootDomain struct {
	ID        uuid.UUID `json:"id" db:"id"`
	ProgramID uuid.UUID `json:"program_id" db:"program_id"`
	Domain    string    `json:"domain" db:"domain"`
	Wildcard  bool      `json:"wildcard" db:"wildcard"` // *.example.com
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Subdomain represents a discovered subdomain.
type Subdomain struct {
	ID           uuid.UUID       `json:"id" db:"id"`
	RootDomainID uuid.UUID       `json:"root_domain_id" db:"root_domain_id"`
	ProgramID    uuid.UUID       `json:"program_id" db:"program_id"`
	Hostname     string          `json:"hostname" db:"hostname"`
	IPAddresses  []string        `json:"ip_addresses" db:"ip_addresses"`
	CNAMEs       []string        `json:"cnames" db:"cnames"`
	IsAlive      bool            `json:"is_alive" db:"is_alive"`
	HTTPStatus   int             `json:"http_status" db:"http_status"`
	Title        string          `json:"title" db:"title"`
	Technologies json.RawMessage `json:"technologies" db:"technologies"` // JSONB
	Priority     int             `json:"priority" db:"priority"`         // 1-10, higher = more interesting
	Source       ScannerType     `json:"source" db:"source"`
	FirstSeen    time.Time       `json:"first_seen" db:"first_seen"`
	LastSeen     time.Time       `json:"last_seen" db:"last_seen"`
}

// OpenPort represents an open port on a subdomain.
type OpenPort struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	SubdomainID uuid.UUID   `json:"subdomain_id" db:"subdomain_id"`
	Port        int         `json:"port" db:"port"`
	Protocol    string      `json:"protocol" db:"protocol"` // tcp, udp
	Service     string      `json:"service" db:"service"`
	Version     string      `json:"version" db:"version"`
	Banner      string      `json:"banner" db:"banner"`
	Source      ScannerType `json:"source" db:"source"`
	DiscoveredAt time.Time  `json:"discovered_at" db:"discovered_at"`
}

// URL represents a discovered URL/endpoint.
type URL struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	SubdomainID uuid.UUID       `json:"subdomain_id" db:"subdomain_id"`
	ProgramID   uuid.UUID       `json:"program_id" db:"program_id"`
	URL         string          `json:"url" db:"url"`
	Method      string          `json:"method" db:"method"`   // GET, POST, etc.
	StatusCode  int             `json:"status_code" db:"status_code"`
	ContentType string          `json:"content_type" db:"content_type"`
	ContentLen  int64           `json:"content_length" db:"content_length"`
	Title       string          `json:"title" db:"title"`
	Parameters  json.RawMessage `json:"parameters" db:"parameters"` // JSONB: query params, form fields
	Headers     json.RawMessage `json:"headers" db:"headers"`       // JSONB: response headers
	Source      ScannerType     `json:"source" db:"source"`
	DiscoveredAt time.Time      `json:"discovered_at" db:"discovered_at"`
}

// Technology represents a detected technology/framework.
type Technology struct {
	ID          uuid.UUID `json:"id" db:"id"`
	SubdomainID uuid.UUID `json:"subdomain_id" db:"subdomain_id"`
	Name        string    `json:"name" db:"name"`
	Version     string    `json:"version" db:"version"`
	Category    string    `json:"category" db:"category"` // framework, server, cms, etc.
	Confidence  int       `json:"confidence" db:"confidence"` // 0-100
	Source      ScannerType `json:"source" db:"source"`
}

// JSFile represents a discovered JavaScript file.
type JSFile struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	SubdomainID uuid.UUID       `json:"subdomain_id" db:"subdomain_id"`
	URL         string          `json:"url" db:"url"`
	Hash        string          `json:"hash" db:"hash"`             // SHA256 of content
	Size        int64           `json:"size" db:"size"`
	Endpoints   json.RawMessage `json:"endpoints" db:"endpoints"`   // JSONB: extracted API endpoints
	Secrets     json.RawMessage `json:"secrets" db:"secrets"`       // JSONB: potential secrets/keys
	DiscoveredAt time.Time      `json:"discovered_at" db:"discovered_at"`
}

// Vulnerability represents a discovered vulnerability.
type Vulnerability struct {
	ID           uuid.UUID       `json:"id" db:"id"`
	ProgramID    uuid.UUID       `json:"program_id" db:"program_id"`
	SubdomainID  uuid.UUID       `json:"subdomain_id" db:"subdomain_id"`
	URLID        *uuid.UUID      `json:"url_id,omitempty" db:"url_id"`
	Type         string          `json:"type" db:"type"`             // idor, xss, sqli, ssrf, etc.
	Severity     Severity        `json:"severity" db:"severity"`
	Status       VulnStatus      `json:"status" db:"status"`
	Title        string          `json:"title" db:"title"`
	Description  string          `json:"description" db:"description"`
	Evidence     json.RawMessage `json:"evidence" db:"evidence"`     // JSONB: request/response pairs
	Confidence   int             `json:"confidence" db:"confidence"` // 0-100
	CVSSScore    float64         `json:"cvss_score" db:"cvss_score"`
	CVSSVector   string          `json:"cvss_vector" db:"cvss_vector"`
	Endpoint     string          `json:"endpoint" db:"endpoint"`
	Parameter    string          `json:"parameter" db:"parameter"`
	Payload      string          `json:"payload" db:"payload"`
	Impact       string          `json:"impact" db:"impact"`
	Remediation  string          `json:"remediation" db:"remediation"`
	Source       string          `json:"source" db:"source"`         // nuclei, ai-idor, ai-auth, etc.
	DedupHash    string          `json:"dedup_hash" db:"dedup_hash"` // For deduplication
	ReportURL    string          `json:"report_url" db:"report_url"` // HackerOne report URL
	DiscoveredAt time.Time       `json:"discovered_at" db:"discovered_at"`
	ValidatedAt  *time.Time      `json:"validated_at,omitempty" db:"validated_at"`
	ReportedAt   *time.Time      `json:"reported_at,omitempty" db:"reported_at"`
}

// Scan represents a scanner execution.
type Scan struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	ProgramID   uuid.UUID       `json:"program_id" db:"program_id"`
	ScannerType ScannerType     `json:"scanner_type" db:"scanner_type"`
	Target      string          `json:"target" db:"target"`         // Domain, IP, or URL
	Status      ScanStatus      `json:"status" db:"status"`
	Config      json.RawMessage `json:"config" db:"config"`         // JSONB: scanner-specific config
	ResultRaw   json.RawMessage `json:"result_raw" db:"result_raw"` // JSONB: raw output
	ResultCount int             `json:"result_count" db:"result_count"`
	ErrorMsg    string          `json:"error_msg" db:"error_msg"`
	Duration    time.Duration   `json:"duration" db:"duration_ms"`
	StartedAt   *time.Time      `json:"started_at,omitempty" db:"started_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
}

// VulnChain represents a chain of vulnerabilities for higher impact.
type VulnChain struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	ProgramID   uuid.UUID       `json:"program_id" db:"program_id"`
	Title       string          `json:"title" db:"title"`
	Description string          `json:"description" db:"description"`
	VulnIDs     []uuid.UUID     `json:"vuln_ids" db:"-"`         // Ordered chain
	Steps       json.RawMessage `json:"steps" db:"steps"`        // JSONB: step-by-step chain
	Severity    Severity        `json:"severity" db:"severity"`  // Combined severity
	CVSSScore   float64         `json:"cvss_score" db:"cvss_score"`
	Impact      string          `json:"impact" db:"impact"`
	Confidence  int             `json:"confidence" db:"confidence"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
}

// MonitorDelta represents a change detected between scans.
type MonitorDelta struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	ProgramID   uuid.UUID       `json:"program_id" db:"program_id"`
	SubdomainID *uuid.UUID      `json:"subdomain_id,omitempty" db:"subdomain_id"`
	DeltaType   string          `json:"delta_type" db:"delta_type"` // new_subdomain, new_port, content_change
	Before      json.RawMessage `json:"before" db:"before_data"`
	After       json.RawMessage `json:"after" db:"after_data"`
	DetectedAt  time.Time       `json:"detected_at" db:"detected_at"`
}

// CostTracking records API cost per call.
type CostTracking struct {
	ID            uuid.UUID `json:"id" db:"id"`
	ProgramID     uuid.UUID `json:"program_id" db:"program_id"`
	ScanID        uuid.UUID `json:"scan_id" db:"scan_id"`
	Phase         string    `json:"phase" db:"phase"`
	Model         string    `json:"model" db:"model"`
	InputTokens   int       `json:"input_tokens" db:"input_tokens"`
	OutputTokens  int       `json:"output_tokens" db:"output_tokens"`
	CacheRead     int       `json:"cache_read_tokens" db:"cache_read_tokens"`
	CacheCreation int       `json:"cache_creation_tokens" db:"cache_creation_tokens"`
	CostDollars   float64   `json:"cost_dollars" db:"cost_dollars"`
	PromptType    string    `json:"prompt_type" db:"prompt_type"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// ScanInput is the input to a scanner execution.
type ScanInput struct {
	ID       uuid.UUID       `json:"id"`
	Target   string          `json:"target"`
	Type     ScannerType     `json:"type"`
	Options  json.RawMessage `json:"options,omitempty"`
	Timeout  time.Duration   `json:"timeout"`
}

// ScanOutput is the output from a scanner execution.
type ScanOutput struct {
	ScanID      uuid.UUID    `json:"scan_id"`
	ScannerType ScannerType  `json:"scanner_type"`
	Target      string       `json:"target"`
	Results     []ScanResult `json:"results"`
	RawOutput   []byte       `json:"raw_output"`
	Stats       ScanStats    `json:"stats"`
	Error       string       `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
}

// ScanResult is a single finding from a scanner.
type ScanResult struct {
	Type       string          `json:"type"`                  // subdomain, port, url, vuln, tech, js
	Host       string          `json:"host,omitempty"`
	IP         string          `json:"ip,omitempty"`
	Port       int             `json:"port,omitempty"`
	Protocol   string          `json:"protocol,omitempty"`
	URL        string          `json:"url,omitempty"`
	Method     string          `json:"method,omitempty"`
	StatusCode int             `json:"status_code,omitempty"`
	Title      string          `json:"title,omitempty"`
	Severity   string          `json:"severity,omitempty"`
	Template   string          `json:"template,omitempty"`    // nuclei template ID
	Matched    string          `json:"matched,omitempty"`     // nuclei matched-at
	Extra      json.RawMessage `json:"extra,omitempty"`       // Scanner-specific data
}

// ScanStats holds scanner execution statistics.
type ScanStats struct {
	TotalResults  int    `json:"total_results"`
	Duration      string `json:"duration"`
	TargetsScanned int   `json:"targets_scanned"`
	ErrorCount    int    `json:"error_count"`
}
