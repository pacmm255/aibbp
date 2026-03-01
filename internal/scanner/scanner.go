package scanner

import (
	"context"

	"github.com/aibbp/aibbp/internal/models"
)

// Scanner is the interface all scanner implementations must satisfy.
type Scanner interface {
	// Type returns the scanner type identifier.
	Type() models.ScannerType

	// Validate checks that the input is valid for this scanner.
	Validate(input models.ScanInput) error

	// Run executes the scan and returns structured output.
	Run(ctx context.Context, input models.ScanInput) (*models.ScanOutput, error)

	// Available returns true if the scanner binary is installed and accessible.
	Available() bool
}
