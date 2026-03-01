package gowitness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aibbp/aibbp/internal/config"
	"github.com/aibbp/aibbp/internal/models"
	"github.com/aibbp/aibbp/internal/scanner"
)

func init() {
	scanner.Register(models.ScannerGowitness, func(cfg config.ScanConfig) scanner.Scanner {
		return New(cfg)
	})
}

// Scanner wraps gowitness for web screenshot capture.
type Scanner struct {
	timeout time.Duration
}

func New(cfg config.ScanConfig) *Scanner {
	timeout := 300
	if t, ok := cfg.Timeouts["gowitness"]; ok {
		timeout = t
	}
	return &Scanner{timeout: time.Duration(timeout) * time.Second}
}

func (s *Scanner) Type() models.ScannerType { return models.ScannerGowitness }
func (s *Scanner) Available() bool           { return scanner.BinaryAvailable("gowitness") }

func (s *Scanner) Validate(input models.ScanInput) error {
	if input.Target == "" {
		return fmt.Errorf("gowitness: target URL is required")
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
		"single",
		input.Target,
		"--json",
	}

	result, err := scanner.ExecCommand(ctx, "gowitness", args...)
	if err != nil {
		return &models.ScanOutput{
			ScanID:      input.ID,
			ScannerType: s.Type(),
			Target:      input.Target,
			Error:       err.Error(),
			Duration:    result.Duration,
		}, err
	}

	results := parseGoWitnessOutput(result.Stdout)

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

func parseGoWitnessOutput(data []byte) []models.ScanResult {
	var results []models.ScanResult

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			continue
		}

		url, _ := raw["url"].(string)
		title, _ := raw["title"].(string)
		statusCode := 0
		if sc, ok := raw["status_code"].(float64); ok {
			statusCode = int(sc)
		}

		extra, _ := json.Marshal(raw)

		results = append(results, models.ScanResult{
			Type:       "url",
			URL:        url,
			Title:      title,
			StatusCode: statusCode,
			Extra:      extra,
		})
	}
	return results
}
