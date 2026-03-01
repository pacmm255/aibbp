package preprocessor

import (
	"encoding/json"
	"strings"

	"github.com/aibbp/aibbp/internal/config"
	"github.com/aibbp/aibbp/internal/models"
)

// Filter removes noise: 404s, default pages, closed ports, standard headers.
type Filter struct {
	cfg config.FilterConfig
}

func NewFilter(cfg config.FilterConfig) *Filter {
	return &Filter{cfg: cfg}
}

func (f *Filter) Name() string { return "filter" }

func (f *Filter) Process(results []models.ScanResult) ([]models.ScanResult, error) {
	var filtered []models.ScanResult

	for _, r := range results {
		if f.shouldRemove(r) {
			continue
		}
		filtered = append(filtered, r)
	}

	return filtered, nil
}

func (f *Filter) shouldRemove(r models.ScanResult) bool {
	// Remove results with filtered status codes
	if r.StatusCode != 0 {
		for _, code := range f.cfg.RemoveStatusCodes {
			if r.StatusCode == code {
				return true
			}
		}
	}

	// Remove closed ports
	if f.cfg.RemoveClosedPorts && r.Type == "port" {
		// Ports without state info in extra are likely closed
		if r.Port == 0 {
			return true
		}
	}

	// Remove default pages
	if f.cfg.RemoveDefaultPages && r.Type == "url" {
		if isDefaultPage(r) {
			return true
		}
	}

	// Remove standard headers (strip from extra if URL type)
	if f.cfg.RemoveStandardHdrs && r.Type == "url" && len(r.Extra) > 0 {
		r.Extra = stripStandardHeaders(r.Extra)
	}

	return false
}

// isDefaultPage detects common default/placeholder pages.
func isDefaultPage(r models.ScanResult) bool {
	title := strings.ToLower(r.Title)
	defaultTitles := []string{
		"welcome to nginx",
		"apache2 ubuntu default page",
		"apache2 debian default page",
		"iis windows server",
		"test page for the nginx",
		"test page for apache",
		"it works!",
		"default web site page",
		"congratulations",
		"coming soon",
		"under construction",
		"parked domain",
	}

	for _, dt := range defaultTitles {
		if strings.Contains(title, dt) {
			return true
		}
	}
	return false
}

// stripStandardHeaders removes common headers that add no security value.
func stripStandardHeaders(extra json.RawMessage) json.RawMessage {
	var data map[string]any
	if err := json.Unmarshal(extra, &data); err != nil {
		return extra
	}

	// Remove standard headers from headers map if present
	if headers, ok := data["headers"].(map[string]any); ok {
		standardHeaders := []string{
			"date", "content-type", "content-length", "connection",
			"keep-alive", "accept-ranges", "etag", "last-modified",
			"cache-control", "expires", "pragma", "vary", "age",
			"transfer-encoding",
		}
		for _, h := range standardHeaders {
			delete(headers, h)
		}
		data["headers"] = headers
	}

	result, _ := json.Marshal(data)
	return result
}
