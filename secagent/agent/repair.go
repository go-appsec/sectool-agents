package agent

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/go-appsec/secagent/util"
)

var fencedJSON = regexp.MustCompile("(?s)^\\s*```(?:json)?\\s*(.*?)\\s*```\\s*$")

// RepairToolArgs returns raw normalized to a JSON object suitable for handing to a tool.
// Returns a *RepairError when the input cannot be recovered.
func RepairToolArgs(raw string) (json.RawMessage, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return json.RawMessage("{}"), nil
	}
	if m := fencedJSON.FindStringSubmatch(raw); m != nil {
		raw = strings.TrimSpace(m[1])
	}

	// First decode attempt: maybe it's already a JSON object
	var any1 any
	if err := json.Unmarshal([]byte(raw), &any1); err == nil {
		// some local models double-encode: if the value is a JSON string, decode once more
		if s, ok := any1.(string); ok {
			var any2 any
			if err2 := json.Unmarshal([]byte(s), &any2); err2 == nil {
				return json.RawMessage(s), nil
			}
		}
		return json.RawMessage(raw), nil
	}

	// Balance trailing braces
	var open, close int
	for _, r := range raw {
		switch r {
		case '{':
			open++
		case '}':
			close++
		}
	}
	if close < open {
		balanced := raw + strings.Repeat("}", open-close)
		if json.Valid([]byte(balanced)) {
			return json.RawMessage(balanced), nil
		}
	}

	// Last: try to peel outer quotes and decode
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		var s string
		if err := json.Unmarshal([]byte(raw), &s); err == nil {
			if json.Valid([]byte(s)) {
				return json.RawMessage(s), nil
			}
		}
	}

	return nil, &RepairError{Raw: raw}
}

// RepairError reports a non-recoverable argument-parse failure.
type RepairError struct{ Raw string }

func (e *RepairError) Error() string {
	return "unable to parse tool arguments as JSON: " + util.Truncate(e.Raw, 200)
}
