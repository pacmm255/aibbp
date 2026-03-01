package subfinder

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aibbp/aibbp/internal/config"
	"github.com/aibbp/aibbp/internal/models"
	"github.com/aibbp/aibbp/internal/scanner"
)

func init() {
	scanner.Register(models.ScannerSubfinder, func(cfg config.ScanConfig) scanner.Scanner {
		return New(cfg)
	})
}

// Scanner wraps the subfinder subdomain enumeration tool.
type Scanner struct {
	timeout time.Duration
}

// New creates a subfinder scanner.
func New(cfg config.ScanConfig) *Scanner {
	timeout := 600
	if t, ok := cfg.Timeouts["subfinder"]; ok {
		timeout = t
	}
	return &Scanner{timeout: time.Duration(timeout) * time.Second}
}

func (s *Scanner) Type() models.ScannerType { return models.ScannerSubfinder }

func (s *Scanner) Available() bool { return scanner.BinaryAvailable("subfinder") }

func (s *Scanner) Validate(input models.ScanInput) error {
	if input.Target == "" {
		return fmt.Errorf("subfinder: target domain is required")
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

	args := []string{
		"-d", input.Target,
		"-silent",
		"-all",
	}

	result, err := scanner.ExecCommand(ctx, "subfinder", args...)
	if err != nil {
		return &models.ScanOutput{
			ScanID:      input.ID,
			ScannerType: s.Type(),
			Target:      input.Target,
			Error:       err.Error(),
			Duration:    result.Duration,
		}, err
	}

	results := parseSubdomains(result.Stdout, input.Target)

	return &models.ScanOutput{
		ScanID:      input.ID,
		ScannerType: s.Type(),
		Target:      input.Target,
		Results:     results,
		RawOutput:   result.Stdout,
		Stats: models.ScanStats{
			TotalResults: len(results),
			Duration:     result.Duration.String(),
		},
		Duration: result.Duration,
	}, nil
}

func parseSubdomains(data []byte, target string) []models.ScanResult {
	var results []models.ScanResult
	seen := make(map[string]bool)

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		host := strings.TrimSpace(sc.Text())
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true

		results = append(results, models.ScanResult{
			Type: "subdomain",
			Host: host,
			Extra: mustJSON(map[string]string{
				"id":     uuid.New().String(),
				"source": "subfinder",
				"parent": target,
			}),
		})
	}
	return results
}
