package nuclei

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
	scanner.Register(models.ScannerNuclei, func(cfg config.ScanConfig) scanner.Scanner {
		return New(cfg)
	})
}

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		Reference   []string `json:"reference"`
	} `json:"info"`
	Type      string `json:"type"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
	URL       string `json:"url,omitempty"`
	IP        string `json:"ip"`
	Port      string `json:"port,omitempty"`
	Matcher   struct {
		Name string `json:"name"`
	} `json:"matcher-name,omitempty"`
	ExtractedResults []string `json:"extracted-results,omitempty"`
	CurlCommand      string   `json:"curl-command,omitempty"`
}

// Scanner wraps the nuclei vulnerability scanner.
type Scanner struct {
	cfg     config.NucleiConfig
	timeout time.Duration
}

func New(cfg config.ScanConfig) *Scanner {
	timeout := 1800
	if t, ok := cfg.Timeouts["nuclei"]; ok {
		timeout = t
	}
	return &Scanner{
		cfg:     cfg.Nuclei,
		timeout: time.Duration(timeout) * time.Second,
	}
}

func (s *Scanner) Type() models.ScannerType { return models.ScannerNuclei }
func (s *Scanner) Available() bool           { return scanner.BinaryAvailable("nuclei") }

func (s *Scanner) Validate(input models.ScanInput) error {
	if input.Target == "" {
		return fmt.Errorf("nuclei: target is required")
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
		"-severity", s.cfg.Severity,
		"-rate-limit", strconv.Itoa(s.cfg.RateLimit),
		"-bulk-size", strconv.Itoa(s.cfg.BulkSize),
	}

	if s.cfg.TemplatesDir != "" {
		args = append(args, "-t", s.cfg.TemplatesDir)
	}

	result, err := scanner.ExecCommand(ctx, "nuclei", args...)
	if err != nil {
		return &models.ScanOutput{
			ScanID:      input.ID,
			ScannerType: s.Type(),
			Target:      input.Target,
			Error:       err.Error(),
			Duration:    result.Duration,
		}, err
	}

	results := parseNucleiOutput(result.Stdout)

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

func parseNucleiOutput(data []byte) []models.ScanResult {
	var results []models.ScanResult

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var nr nucleiResult
		if err := json.Unmarshal(sc.Bytes(), &nr); err != nil {
			continue
		}

		extra, _ := json.Marshal(map[string]any{
			"template_id": nr.TemplateID,
			"description": nr.Info.Description,
			"tags":        nr.Info.Tags,
			"reference":   nr.Info.Reference,
			"matched_at":  nr.MatchedAt,
			"curl":        nr.CurlCommand,
			"extractions": nr.ExtractedResults,
		})

		results = append(results, models.ScanResult{
			Type:     "vuln",
			Host:     nr.Host,
			IP:       nr.IP,
			URL:      nr.MatchedAt,
			Title:    nr.Info.Name,
			Severity: nr.Info.Severity,
			Template: nr.TemplateID,
			Matched:  nr.MatchedAt,
			Extra:    extra,
		})
	}
	return results
}
