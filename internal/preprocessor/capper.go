package preprocessor

import (
	"encoding/json"

	"github.com/aibbp/aibbp/internal/models"
)

// Capper enforces maximum output size by truncating arrays if needed.
type Capper struct {
	maxBytes int
	maxItems int
}

func NewCapper(maxBytes, maxItems int) *Capper {
	if maxBytes <= 0 {
		maxBytes = 51200 // 50KB default
	}
	if maxItems <= 0 {
		maxItems = 100
	}
	return &Capper{maxBytes: maxBytes, maxItems: maxItems}
}

func (c *Capper) Name() string { return "capper" }

func (c *Capper) Process(results []models.ScanResult) ([]models.ScanResult, error) {
	if len(results) == 0 {
		return results, nil
	}

	// First: cap array items in each result's Extra field
	for i := range results {
		if len(results[i].Extra) > 0 {
			results[i].Extra = capExtraArrays(results[i].Extra, c.maxItems)
		}
	}

	// Second: progressively remove results until under size cap
	for len(results) > 0 {
		data, _ := json.Marshal(results)
		if len(data) <= c.maxBytes {
			break
		}

		// Remove lowest-value results first (info severity, low status codes)
		// Simple strategy: remove the last result
		results = results[:len(results)-1]
	}

	return results, nil
}

// capExtraArrays truncates any array fields in the Extra JSON to maxItems.
func capExtraArrays(extra json.RawMessage, maxItems int) json.RawMessage {
	var data map[string]any
	if err := json.Unmarshal(extra, &data); err != nil {
		return extra
	}

	changed := false
	for k, v := range data {
		if arr, ok := v.([]any); ok && len(arr) > maxItems {
			data[k] = arr[:maxItems]
			changed = true
		}
	}

	if !changed {
		return extra
	}

	result, _ := json.Marshal(data)
	return result
}
