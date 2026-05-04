package agent

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/secagent/util"
)

// outputMarkers are common patterns reasoning models use to demarcate their intended response from
// internal thinking. Ordered most-specific-first so longer markers match before shorter substrings of the same pattern.
var outputMarkers = []string{
	"final output:",
	"final answer:",
	"my response:",
	"my answer:",
	"final:",
	"output:",
	"answer:",
	"response:",
}

// jsonSummaryFields are field names we'll probe on a JSON-wrapped response to extract the actual prose line.
var jsonSummaryFields = []string{
	"summary", "status", "description", "message",
	"text", "content", "response", "output", "answer",
}

// ExtractProse returns a best-effort single-line prose summary from s, or "" when nothing usable remains.
func ExtractProse(s string) string {
	s = util.StripCodeFences(StripThinkBlocks(s))
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Unclosed think tag residue, not usable prose; caller should fall back to Tail/TruncatedThinkTail.
	if HasLeadingThinkOpen(s) {
		return ""
	}
	if len(s) > 0 && (s[0] == '{' || s[0] == '[') {
		line, validJSON := extractFromJSON(s)
		if validJSON {
			// Commit to JSON path: line may be "" (object had no usable
			// strings), but falling through would surface structural noise.
			return line
		}
	}
	if line := ExtractMarkedOutput(s); line != "" {
		return line
	}
	return firstMeaningfulLine(s)
}

// ExtractMarkedOutput returns the first sentence of prose following the last output-marker
// (e.g. "Final:", "Output:") in s, or "" when no marker is found.
func ExtractMarkedOutput(s string) string {
	lower := strings.ToLower(s)
	bestIdx := -1
	var bestLen int
	for _, m := range outputMarkers {
		idx := strings.LastIndex(lower, m)
		if idx > bestIdx {
			bestIdx = idx
			bestLen = len(m)
		}
	}
	if bestIdx < 0 {
		return ""
	}
	after := strings.TrimSpace(s[bestIdx+bestLen:])
	return firstSentenceOrLine(after)
}

// extractFromJSON parses s as a JSON object and returns the first non-empty string value from a known
// summary-field name (or any string value as fallback). The second return reports whether s parsed as valid JSON.
func extractFromJSON(s string) (string, bool) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(s), &obj); err != nil {
		return "", false
	}
	for _, k := range jsonSummaryFields {
		if v, ok := obj[k].(string); ok {
			if trimmed := strings.TrimSpace(v); trimmed != "" {
				return firstSentenceOrLine(trimmed), true
			}
		}
	}
	keys := bulk.MapKeysSlice(obj)
	sort.Strings(keys)
	for _, k := range keys {
		if v, ok := obj[k].(string); ok {
			if trimmed := strings.TrimSpace(v); trimmed != "" {
				return firstSentenceOrLine(trimmed), true
			}
		}
	}
	return "", true
}

// firstSentenceOrLine returns s up to the first newline or sentence-ending punctuation (.!?), trimmed.
// Returns the whole trimmed string when neither boundary exists.
func firstSentenceOrLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' {
			return strings.TrimSpace(s[:i])
		}
		if c == '.' || c == '!' || c == '?' {
			return strings.TrimSpace(s[:i+1])
		}
	}
	return s
}

// structuralOnlyLines is the set of trimmed line contents we treat as "structural noise".
// A model emitting `{` on its own line is almost certainly wrapping JSON, not producing a summary.
var structuralOnlyLines = map[string]bool{
	"{": true, "}": true, "[": true, "]": true,
	"\"": true, "'": true, "`": true,
	",": true, ":": true,
	"```": true,
}

// firstMeaningfulLine returns the first non-empty, non-structural line of
// s, trimmed. Returns "" when every line is empty or structural.
func firstMeaningfulLine(s string) string {
	for s != "" {
		var line string
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			line = s[:nl]
			s = s[nl+1:]
		} else {
			line = s
			s = ""
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || structuralOnlyLines[trimmed] {
			continue
		}
		return trimmed
	}
	return ""
}
