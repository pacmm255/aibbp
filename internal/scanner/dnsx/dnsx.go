package dnsx

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
	scanner.Register(models.ScannerDNSX, func(cfg config.ScanConfig) scanner.Scanner {
		return New(cfg)
	})
}

type dnsxResult struct {
	Host       string   `json:"host"`
	A          []string `json:"a,omitempty"`
	AAAA       []string `json:"aaaa,omitempty"`
	CNAME      []string `json:"cname,omitempty"`
	MX         []string `json:"mx,omitempty"`
	NS         []string `json:"ns,omitempty"`
	TXT        []string `json:"txt,omitempty"`
	StatusCode string   `json:"status_code,omitempty"`
}

// Scanner wraps dnsx for DNS resolution and record enumeration.
type Scanner struct {
	timeout time.Duration
}

func New(cfg config.ScanConfig) *Scanner {
	timeout := 300
	if t, ok := cfg.Timeouts["dnsx"]; ok {
		timeout = t
	}
	return &Scanner{timeout: time.Duration(timeout) * time.Second}
}

func (s *Scanner) Type() models.ScannerType { return models.ScannerDNSX }
func (s *Scanner) Available() bool           { return scanner.BinaryAvailable("dnsx") }

func (s *Scanner) Validate(input models.ScanInput) error {
	if input.Target == "" {
		return fmt.Errorf("dnsx: target domain is required")
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
		"-json",
		"-silent",
		"-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
		"-resp",
	}

	result, err := scanner.ExecCommand(ctx, "dnsx", args...)
	if err != nil {
		return &models.ScanOutput{
			ScanID:      input.ID,
			ScannerType: s.Type(),
			Target:      input.Target,
			Error:       err.Error(),
			Duration:    result.Duration,
		}, err
	}

	results := parseDNSXOutput(result.Stdout)

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

func parseDNSXOutput(data []byte) []models.ScanResult {
	var results []models.ScanResult

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var dr dnsxResult
		if err := json.Unmarshal(sc.Bytes(), &dr); err != nil {
			continue
		}

		ip := ""
		if len(dr.A) > 0 {
			ip = dr.A[0]
		}

		extra, _ := json.Marshal(map[string]any{
			"a":     dr.A,
			"aaaa":  dr.AAAA,
			"cname": dr.CNAME,
			"mx":    dr.MX,
			"ns":    dr.NS,
			"txt":   dr.TXT,
		})

		results = append(results, models.ScanResult{
			Type:  "subdomain",
			Host:  dr.Host,
			IP:    ip,
			Extra: extra,
		})
	}
	return results
}
