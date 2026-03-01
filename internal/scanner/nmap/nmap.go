package nmap

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
	scanner.Register(models.ScannerNmap, func(cfg config.ScanConfig) scanner.Scanner {
		return New(cfg)
	})
}

// Scanner wraps nmap for port scanning and service detection.
type Scanner struct {
	cfg     config.NmapConfig
	timeout time.Duration
}

func New(cfg config.ScanConfig) *Scanner {
	timeout := 900
	if t, ok := cfg.Timeouts["nmap"]; ok {
		timeout = t
	}
	return &Scanner{
		cfg:     cfg.Nmap,
		timeout: time.Duration(timeout) * time.Second,
	}
}

func (s *Scanner) Type() models.ScannerType { return models.ScannerNmap }
func (s *Scanner) Available() bool           { return scanner.BinaryAvailable("nmap") }

func (s *Scanner) Validate(input models.ScanInput) error {
	if input.Target == "" {
		return fmt.Errorf("nmap: target is required")
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

	// Output to XML for structured parsing
	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("nmap-%s.xml", uuid.New().String()))
	defer os.Remove(outFile)

	args := []string{
		"-sV",
		"--top-ports", strconv.Itoa(s.cfg.TopPorts),
		"-oX", outFile,
		"--open",
		"-T4",
		input.Target,
	}

	if s.cfg.Scripts != "" {
		args = append([]string{"--script", s.cfg.Scripts}, args...)
	}

	result, err := scanner.ExecCommand(ctx, "nmap", args...)
	if err != nil {
		return &models.ScanOutput{
			ScanID:      input.ID,
			ScannerType: s.Type(),
			Target:      input.Target,
			Error:       err.Error(),
			Duration:    result.Duration,
		}, err
	}

	xmlData, readErr := os.ReadFile(outFile)
	if readErr != nil {
		return &models.ScanOutput{
			ScanID:      input.ID,
			ScannerType: s.Type(),
			Target:      input.Target,
			Error:       fmt.Sprintf("read output: %v", readErr),
			Duration:    result.Duration,
		}, readErr
	}

	results := ParseNmapXML(xmlData)

	return &models.ScanOutput{
		ScanID:      input.ID,
		ScannerType: s.Type(),
		Target:      input.Target,
		Results:     results,
		RawOutput:   xmlData,
		Stats: models.ScanStats{
			TotalResults: len(results),
			Duration:     result.Duration.String(),
		},
		Duration: result.Duration,
	}, nil
}
