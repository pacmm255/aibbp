package masscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/aibbp/aibbp/internal/config"
	"github.com/aibbp/aibbp/internal/models"
	"github.com/aibbp/aibbp/internal/scanner"
)

func init() {
	scanner.Register(models.ScannerMasscan, func(cfg config.ScanConfig) scanner.Scanner {
		return New(cfg)
	})
}

// Scanner wraps masscan for fast port scanning.
type Scanner struct {
	cfg     config.MasscanConfig
	timeout time.Duration
}

func New(cfg config.ScanConfig) *Scanner {
	timeout := 600
	if t, ok := cfg.Timeouts["masscan"]; ok {
		timeout = t
	}
	return &Scanner{
		cfg:     cfg.Masscan,
		timeout: time.Duration(timeout) * time.Second,
	}
}

func (s *Scanner) Type() models.ScannerType { return models.ScannerMasscan }
func (s *Scanner) Available() bool           { return scanner.BinaryAvailable("masscan") }

func (s *Scanner) Validate(input models.ScanInput) error {
	if input.Target == "" {
		return fmt.Errorf("masscan: target IP/CIDR is required")
	}
	return nil
}

func (s *Scanner) Run(ctx context.Context, input models.ScanInput) (*models.ScanOutput, error) {
	if err := s.Validate(input); err != nil {
		return nil, err
	}

	timeout := s.timeout
	if input.Timeout > 0 {
		timeout = input.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("masscan-%s.json", uuid.New().String()))
	defer os.Remove(outFile)

	args := []string{
		input.Target,
		"-p", s.cfg.Ports,
		"--rate", strconv.Itoa(s.cfg.Rate),
		"-oJ", outFile,
	}

	result, err := scanner.ExecCommand(ctx, "masscan", args...)
	if err != nil {
		return &models.ScanOutput{
			ScanID:      input.ID,
			ScannerType: s.Type(),
			Target:      input.Target,
			Error:       err.Error(),
			Duration:    result.Duration,
		}, err
	}

	jsonData, readErr := os.ReadFile(outFile)
	if readErr != nil {
		return &models.ScanOutput{
			ScanID:      input.ID,
			ScannerType: s.Type(),
			Target:      input.Target,
			Error:       fmt.Sprintf("read output: %v", readErr),
			Duration:    result.Duration,
		}, readErr
	}

	results := ParseMasscanJSON(jsonData)

	return &models.ScanOutput{
		ScanID:      input.ID,
		ScannerType: s.Type(),
		Target:      input.Target,
		Results:     results,
		RawOutput:   jsonData,
		Stats: models.ScanStats{
			TotalResults: len(results),
			Duration:     result.Duration.String(),
		},
		Duration: result.Duration,
	}, nil
}
