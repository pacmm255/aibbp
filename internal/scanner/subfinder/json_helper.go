package subfinder

import "encoding/json"

func mustJSON(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
