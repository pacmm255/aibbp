package preprocessor

import (
	"encoding/json"

	"github.com/aibbp/aibbp/internal/models"
)

// Dedup removes near-duplicate scan results using SimHash.
type Dedup struct {
	threshold int // Hamming distance threshold (default: 3)
}

func NewDedup(threshold int) *Dedup {
	if threshold <= 0 {
		threshold = 3
	}
	return &Dedup{threshold: threshold}
}

func (d *Dedup) Name() string { return "dedup" }

func (d *Dedup) Process(results []models.ScanResult) ([]models.ScanResult, error) {
	if len(results) == 0 {
		return results, nil
	}

	type entry struct {
		result models.ScanResult
		hash   uint64
	}

	var kept []entry

	for _, r := range results {
		data, _ := json.Marshal(r)
		hash := SimHash(data)

		isDup := false
		for _, k := range kept {
			// Only compare results of the same type
			if k.result.Type != r.Type {
				continue
			}
			if HammingDistance(hash, k.hash) <= d.threshold {
				isDup = true
				break
			}
		}

		if !isDup {
			kept = append(kept, entry{result: r, hash: hash})
		}
	}

	deduped := make([]models.ScanResult, len(kept))
	for i, k := range kept {
		deduped[i] = k.result
	}

	return deduped, nil
}
