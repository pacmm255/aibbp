package scanner

import (
	"fmt"

	"github.com/aibbp/aibbp/internal/config"
	"github.com/aibbp/aibbp/internal/models"
)

// Factory creates a scanner of the given type.
type Factory func(cfg config.ScanConfig) Scanner

// registry maps scanner types to their factories.
var registry = map[models.ScannerType]Factory{}

// Register adds a scanner factory to the registry.
func Register(scannerType models.ScannerType, factory Factory) {
	registry[scannerType] = factory
}

// Create instantiates a scanner by type from the registry.
func Create(scannerType models.ScannerType, cfg config.ScanConfig) (Scanner, error) {
	factory, ok := registry[scannerType]
	if !ok {
		return nil, fmt.Errorf("unknown scanner type: %s", scannerType)
	}
	return factory(cfg), nil
}

// CreateAll instantiates all registered scanners.
func CreateAll(cfg config.ScanConfig) map[models.ScannerType]Scanner {
	scanners := make(map[models.ScannerType]Scanner)
	for st, factory := range registry {
		s := factory(cfg)
		if s.Available() {
			scanners[st] = s
		}
	}
	return scanners
}

// AvailableScanners returns a list of all scanner types that have binaries installed.
func AvailableScanners(cfg config.ScanConfig) []models.ScannerType {
	var available []models.ScannerType
	for st, factory := range registry {
		if factory(cfg).Available() {
			available = append(available, st)
		}
	}
	return available
}
