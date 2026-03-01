package katana

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/aibbp/aibbp/internal/config"
	"github.com/aibbp/aibbp/internal/models"
	"github.com/aibbp/aibbp/internal/scanner"
)

func init() {
	scanner.Register(models.ScannerKatana, func(cfg config.ScanConfig) scanner.Scanner {
		return New(cfg)
	})
}

type katanaResult struct {
	Request struct {
		Method string `json:"method"`
		URL    string `json:"endpoint"`
	} `json:"request"`
	Response struct {
		StatusCode  int    `json:"status_code"`
		URL         string `json:"url"`
		ContentType string `json:"content_type,omitempty"`
	} `json:"response"`
	Tag    string `json:"tag,omitempty"`
	Source string `json:"source,omitempty"`
}

// Scanner wraps katana for crawling.
type Scanner struct {
	cfg     config.KatanaConfig
	timeout time.Duration
}

func New(cfg config.ScanConfig) *Scanner {
	timeout := 600
	if t, ok := cfg.Timeouts["katana"]; ok {
		timeout = t
	}
	return &Scanner{
		cfg:     cfg.Katana,
		timeout: time.Duration(timeout) * time.Second,
	}
}

func (s *Scanner) Type() models.ScannerType { return models.ScannerKatana }
func (s *Scanner) Available() bool           { return scanner.BinaryAvailable("katana") }

func (s *Scanner) Validate(input models.ScanInput) error {
	if input.Target == "" {
		return fmt.Errorf("katana: target URL is required")
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
		"-jsonl",
		"-silent",
		"-depth", strconv.Itoa(s.cfg.Depth),
		"-max-duration", strconv.Itoa(s.cfg.MaxDuration),
	}

	if s.cfg.JSCrawl {
		args = append(args, "-js-crawl")
	}

	result, err := scanner.ExecCommand(ctx, "katana", args...)
	if err != nil {
		return &models.ScanOutput{
			ScanID:      input.ID,
			ScannerType: s.Type(),
			Target:      input.Target,
			Error:       err.Error(),
			Duration:    result.Duration,
		}, err
	}

	results := parseKatanaOutput(result.Stdout)

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

func parseKatanaOutput(data []byte) []models.ScanResult {
	var results []models.ScanResult

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var kr katanaResult
		if err := json.Unmarshal(sc.Bytes(), &kr); err != nil {
			continue
		}

		url := kr.Response.URL
		if url == "" {
			url = kr.Request.URL
		}

		extra, _ := json.Marshal(map[string]any{
			"tag":          kr.Tag,
			"source":       kr.Source,
			"content_type": kr.Response.ContentType,
		})

		results = append(results, models.ScanResult{
			Type:       "url",
			URL:        url,
			Method:     kr.Request.Method,
			StatusCode: kr.Response.StatusCode,
			Extra:      extra,
		})
	}
	return results
}
