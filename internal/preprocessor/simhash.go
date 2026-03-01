package preprocessor

import (
	"encoding/json"
	"hash/fnv"
	"math/bits"
	"strings"
)

// SimHash computes a 64-bit similarity hash for a ScanResult.
// Near-duplicate results will have similar hashes (low Hamming distance).
func SimHash(data []byte) uint64 {
	// Extract features (shingles) from the JSON representation
	features := extractFeatures(data)

	var vector [64]int

	for _, feature := range features {
		h := hashFeature(feature)
		for i := 0; i < 64; i++ {
			if h&(1<<uint(i)) != 0 {
				vector[i]++
			} else {
				vector[i]--
			}
		}
	}

	var hash uint64
	for i := 0; i < 64; i++ {
		if vector[i] > 0 {
			hash |= 1 << uint(i)
		}
	}

	return hash
}

// HammingDistance returns the number of differing bits between two hashes.
func HammingDistance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

// extractFeatures creates shingles from JSON data for SimHash computation.
func extractFeatures(data []byte) []string {
	// Parse JSON and extract meaningful fields
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		// Fall back to character-level shingles
		return charShingles(string(data), 4)
	}

	var features []string

	// Key structural features
	for k, v := range raw {
		switch val := v.(type) {
		case string:
			if val != "" {
				features = append(features, k+"="+strings.ToLower(val))
				// Add word-level shingles for long strings
				words := strings.Fields(strings.ToLower(val))
				for i := 0; i+1 < len(words); i++ {
					features = append(features, words[i]+" "+words[i+1])
				}
			}
		case float64:
			features = append(features, k+"=num")
		case bool:
			if val {
				features = append(features, k+"=true")
			}
		}
	}

	// If very few features, add character shingles as fallback
	if len(features) < 3 {
		features = append(features, charShingles(string(data), 4)...)
	}

	return features
}

// charShingles creates character n-grams.
func charShingles(s string, n int) []string {
	s = strings.ToLower(s)
	if len(s) < n {
		return []string{s}
	}
	shingles := make([]string, 0, len(s)-n+1)
	for i := 0; i <= len(s)-n; i++ {
		shingles = append(shingles, s[i:i+n])
	}
	return shingles
}

// hashFeature computes a 64-bit hash for a single feature string.
func hashFeature(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}
