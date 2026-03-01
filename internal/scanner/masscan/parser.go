package masscan

import (
	"encoding/json"

	"github.com/aibbp/aibbp/internal/models"
)

type masscanEntry struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Status string `json:"status"`
		Reason string `json:"reason"`
		TTL    int    `json:"ttl"`
	} `json:"ports"`
	Timestamp string `json:"timestamp"`
}

// ParseMasscanJSON parses masscan JSON output into ScanResults.
func ParseMasscanJSON(data []byte) []models.ScanResult {
	var entries []masscanEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		// masscan JSON output may have trailing comma issues
		return nil
	}

	var results []models.ScanResult
	for _, entry := range entries {
		for _, port := range entry.Ports {
			if port.Status != "open" {
				continue
			}

			extra, _ := json.Marshal(map[string]any{
				"reason":    port.Reason,
				"ttl":       port.TTL,
				"timestamp": entry.Timestamp,
			})

			results = append(results, models.ScanResult{
				Type:     "port",
				Host:     entry.IP,
				IP:       entry.IP,
				Port:     port.Port,
				Protocol: port.Proto,
				Extra:    extra,
			})
		}
	}
	return results
}
