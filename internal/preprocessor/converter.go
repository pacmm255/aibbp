package preprocessor

import (
	"strings"

	"github.com/aibbp/aibbp/internal/models"
)

// Converter normalizes formats and ensures consistent structure.
type Converter struct{}

func NewConverter() *Converter {
	return &Converter{}
}

func (c *Converter) Name() string { return "converter" }

func (c *Converter) Process(results []models.ScanResult) ([]models.ScanResult, error) {
	for i := range results {
		results[i] = normalize(results[i])
	}
	return results, nil
}

// normalize ensures consistent formatting across scanner outputs.
func normalize(r models.ScanResult) models.ScanResult {
	// Normalize host: strip protocol, trailing slashes
	r.Host = normalizeHost(r.Host)

	// Normalize severity to lowercase
	r.Severity = strings.ToLower(r.Severity)

	// Ensure method is uppercase
	if r.Method != "" {
		r.Method = strings.ToUpper(r.Method)
	}

	// Default method for URL types
	if r.Type == "url" && r.Method == "" {
		r.Method = "GET"
	}

	// Normalize protocol
	if r.Protocol != "" {
		r.Protocol = strings.ToLower(r.Protocol)
	}

	return r
}

// normalizeHost strips protocol and trailing slashes from hostnames.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimSuffix(host, "/")
	host = strings.ToLower(host)
	return host
}
