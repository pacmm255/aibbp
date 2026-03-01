package httpx

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
	scanner.Register(models.ScannerHTTPX, func(cfg config.ScanConfig) scanner.Scanner {
		return New(cfg)
	})
}

type httpxResult struct {
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	Title       string `json:"title"`
	Host        string `json:"host"`
	ContentType string `json:"content_type"`
	ContentLen  int64  `json:"content_length"`
	Method      string `json:"method"`
	Scheme      string `json:"scheme"`
	WebServer   string `json:"webserver"`
	Tech        []string `json:"tech"`
}

// Scanner wraps the httpx HTTP probing tool.
type Scanner struct {
	timeout time.Duration
}

func New(cfg config.ScanConfig) *Scanner {
	timeout := 300
	if t, ok := cfg.Timeouts["httpx"]; ok {
		timeout = t
	}
	return &Scanner{timeout: time.Duration(timeout) * time.Second}
}

func (s *Scanner) Type() models.ScannerType { return models.ScannerHTTPX }
func (s *Scanner) Available() bool           { return scanner.BinaryAvailable("httpx") }

func (s *Scanner) Validate(input models.ScanInput) error {
	if input.Target == "" {
		return fmt.Errorf("httpx: target is required")
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
		"-u", input.Target,
		"-json",
		"-silent",
		"-status-code",
		"-title",
		"-content-type",
		"-content-length",
		"-web-server",
		"-tech-detect",
		"-follow-redirects",
		"-threads", "50",
	}

	result, err := scanner.ExecCommand(ctx, "httpx", args...)
	if err != nil {
		return &models.ScanOutput{
			ScanID:      input.ID,
			ScannerType: s.Type(),
			Target:      input.Target,
			Error:       err.Error(),
			Duration:    result.Duration,
		}, err
	}

	results := parseHTTPXOutput(result.Stdout)

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

func parseHTTPXOutput(data []byte) []models.ScanResult {
	var results []models.ScanResult

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var hr httpxResult
		if err := json.Unmarshal(sc.Bytes(), &hr); err != nil {
			continue
		}

		extra, _ := json.Marshal(map[string]any{
			"web_server": hr.WebServer,
			"tech":       hr.Tech,
			"scheme":     hr.Scheme,
		})

		results = append(results, models.ScanResult{
			Type:       "url",
			Host:       hr.Host,
			URL:        hr.URL,
			StatusCode: hr.StatusCode,
			Title:      hr.Title,
			Method:     hr.Method,
			Extra:      extra,
		})
	}
	return results
}
