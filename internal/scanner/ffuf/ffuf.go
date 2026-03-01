package ffuf

import (
	"context"
	"encoding/json"
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
	scanner.Register(models.ScannerFfuf, func(cfg config.ScanConfig) scanner.Scanner {
		return New(cfg)
	})
}

type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

type ffufResult struct {
	Input       map[string]string `json:"input"`
	Position    int               `json:"position"`
	StatusCode  int               `json:"status"`
	Length      int64             `json:"length"`
	Words       int               `json:"words"`
	Lines       int               `json:"lines"`
	ContentType string            `json:"content-type"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
}

// Scanner wraps ffuf for directory/file fuzzing.
type Scanner struct {
	cfg     config.FfufConfig
	timeout time.Duration
}

func New(cfg config.ScanConfig) *Scanner {
	timeout := 600
	if t, ok := cfg.Timeouts["ffuf"]; ok {
		timeout = t
	}
	return &Scanner{
		cfg:     cfg.Ffuf,
		timeout: time.Duration(timeout) * time.Second,
	}
}

func (s *Scanner) Type() models.ScannerType { return models.ScannerFfuf }
func (s *Scanner) Available() bool           { return scanner.BinaryAvailable("ffuf") }

func (s *Scanner) Validate(input models.ScanInput) error {
	if input.Target == "" {
		return fmt.Errorf("ffuf: target URL is required")
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

	outFile := filepath.Join(os.TempDir(), fmt.Sprintf("ffuf-%s.json", uuid.New().String()))
	defer os.Remove(outFile)

	target := input.Target
	if target[len(target)-1] != '/' {
		target += "/"
	}
	target += "FUZZ"

	args := []string{
		"-u", target,
		"-w", s.cfg.Wordlist,
		"-t", strconv.Itoa(s.cfg.Threads),
		"-rate", strconv.Itoa(s.cfg.Rate),
		"-o", outFile,
		"-of", "json",
		"-mc", "200,201,204,301,302,307,308,401,403,405",
		"-s",
	}

	result, err := scanner.ExecCommand(ctx, "ffuf", args...)
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
			RawOutput:   result.Stdout,
			Duration:    result.Duration,
		}, nil
	}

	results := parseFfufOutput(jsonData, input.Target)

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

func parseFfufOutput(data []byte, baseTarget string) []models.ScanResult {
	var output ffufOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil
	}

	var results []models.ScanResult
	for _, r := range output.Results {
		extra, _ := json.Marshal(map[string]any{
			"words":        r.Words,
			"lines":        r.Lines,
			"length":       r.Length,
			"content_type": r.ContentType,
			"input":        r.Input,
		})

		results = append(results, models.ScanResult{
			Type:       "url",
			Host:       r.Host,
			URL:        r.URL,
			StatusCode: r.StatusCode,
			Extra:      extra,
		})
	}
	return results
}
