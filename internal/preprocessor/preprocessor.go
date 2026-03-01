package preprocessor

import (
	"github.com/aibbp/aibbp/internal/models"
)

// Stage is a single step in the preprocessing pipeline.
type Stage interface {
	// Name returns the stage identifier.
	Name() string

	// Process takes scan results and returns filtered/transformed results.
	Process(results []models.ScanResult) ([]models.ScanResult, error)
}
