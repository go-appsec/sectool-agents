package util

import "strings"

// ExtractJSONObject returns the first {..} block from raw, tolerating fences and prose.
func ExtractJSONObject(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end < 0 || end < start {
		return s
	}
	return s[start : end+1]
}
