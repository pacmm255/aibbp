package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// TaskType identifies the kind of work to be done.
type TaskType string

const (
	TaskTypeScan          TaskType = "scan"
	TaskTypePreprocess    TaskType = "preprocess"
	TaskTypeAnalyze       TaskType = "analyze"
	TaskTypeValidate      TaskType = "validate"
)

// TaskPriority controls queue ordering.
type TaskPriority int

const (
	TaskPriorityLow    TaskPriority = 1
	TaskPriorityNormal TaskPriority = 5
	TaskPriorityHigh   TaskPriority = 10
)

// TaskMessage is published to NATS to request work.
type TaskMessage struct {
	ID         uuid.UUID       `json:"id"`
	ProgramID  uuid.UUID       `json:"program_id"`
	Type       TaskType        `json:"type"`
	Priority   TaskPriority    `json:"priority"`
	Target     string          `json:"target"`
	Scanner    ScannerType     `json:"scanner,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	RetryCount int             `json:"retry_count"`
	MaxRetries int             `json:"max_retries"`
}

// NewTaskMessage creates a TaskMessage with defaults.
func NewTaskMessage(programID uuid.UUID, taskType TaskType, target string) TaskMessage {
	return TaskMessage{
		ID:         uuid.New(),
		ProgramID:  programID,
		Type:       taskType,
		Priority:   TaskPriorityNormal,
		Target:     target,
		CreatedAt:  time.Now().UTC(),
		MaxRetries: 3,
	}
}

// ScanResultMessage carries preprocessed scan results for the AI brain.
type ScanResultMessage struct {
	ID          uuid.UUID       `json:"id"`
	ScanID      uuid.UUID       `json:"scan_id"`
	ProgramID   uuid.UUID       `json:"program_id"`
	ScannerType ScannerType     `json:"scanner_type"`
	Target      string          `json:"target"`
	Results     json.RawMessage `json:"results"`      // Preprocessed results
	ResultCount int             `json:"result_count"`
	ByteSize    int             `json:"byte_size"`    // Size after preprocessing
	CreatedAt   time.Time       `json:"created_at"`
}

// ScanStatusUpdate notifies status changes.
type ScanStatusUpdate struct {
	ScanID    uuid.UUID  `json:"scan_id"`
	ProgramID uuid.UUID  `json:"program_id"`
	Status    ScanStatus `json:"status"`
	Message   string     `json:"message,omitempty"`
	Error     string     `json:"error,omitempty"`
	Timestamp time.Time  `json:"timestamp"`
}

// NewScanStatusUpdate creates a status update event.
func NewScanStatusUpdate(scanID, programID uuid.UUID, status ScanStatus) ScanStatusUpdate {
	return ScanStatusUpdate{
		ScanID:    scanID,
		ProgramID: programID,
		Status:    status,
		Timestamp: time.Now().UTC(),
	}
}

// VulnFoundEvent is emitted when a vulnerability is discovered.
type VulnFoundEvent struct {
	VulnID      uuid.UUID `json:"vuln_id"`
	ProgramID   uuid.UUID `json:"program_id"`
	SubdomainID uuid.UUID `json:"subdomain_id"`
	Type        string    `json:"type"`
	Severity    Severity  `json:"severity"`
	Confidence  int       `json:"confidence"`
	Title       string    `json:"title"`
	Source      string    `json:"source"`
	Timestamp   time.Time `json:"timestamp"`
}

// BudgetUpdateEvent tracks cost changes.
type BudgetUpdateEvent struct {
	ProgramID   uuid.UUID `json:"program_id"`
	Phase       string    `json:"phase"`
	Model       string    `json:"model"`
	CostDollars float64   `json:"cost_dollars"`
	TotalSpent  float64   `json:"total_spent"`
	Remaining   float64   `json:"remaining"`
	Timestamp   time.Time `json:"timestamp"`
}

// PhaseTransitionEvent marks phase changes in the orchestrator.
type PhaseTransitionEvent struct {
	ProgramID uuid.UUID `json:"program_id"`
	FromPhase string    `json:"from_phase"`
	ToPhase   string    `json:"to_phase"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}
