package util

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var nonSlugChar = regexp.MustCompile(`[^a-z0-9\s-]+`)
var slugDashes = regexp.MustCompile(`[-\s]+`)

// Truncate returns s trimmed and truncated to at most n runes, with an ellipsis
// appended on truncation. Multi-byte UTF-8 codepoints are never split.
func Truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	if n < 1 {
		return "…"
	}
	var count int
	for i := range s {
		if count == n-1 {
			return s[:i] + "…"
		}
		count++
	}
	return s
}

// StripCodeFences removes a leading and trailing markdown fenced-code line from s.
func StripCodeFences(s string) string {
	lines := strings.Split(s, "\n")
	var start int
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	if start < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[start]), "```") {
		start++
	}
	end := len(lines)
	for end > start && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	if end > start && strings.TrimSpace(lines[end-1]) == "```" {
		end--
	}
	return strings.Join(lines[start:end], "\n")
}

// Slugify produces a URL-safe slug from text. Underscores are normalized
// to spaces, so `client_secret` and `client-secret` yield the same slug.
func Slugify(text string) string {
	t := strings.ToLower(strings.TrimSpace(text))
	t = strings.ReplaceAll(t, "_", " ")
	t = nonSlugChar.ReplaceAllString(t, "")
	t = slugDashes.ReplaceAllString(t, "-")
	return strings.Trim(t, "-")
}
