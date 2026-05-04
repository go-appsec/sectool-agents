package agent

import (
	"regexp"
	"strings"
)

// underscoreRun collapses runs of '_' to a single '_' for canonical matching.
var underscoreRun = regexp.MustCompile(`_+`)

// canonicalToolName returns s lowercased with runs of underscores collapsed to a single underscore.
func canonicalToolName(s string) string {
	return underscoreRun.ReplaceAllString(strings.ToLower(s), "_")
}

// fuzzyContainsToolMatch returns the unique key in canonNames whose canonical form is a
// word-bounded substring of req (or vice-versa). Returns "" on zero or multiple matches.
func fuzzyContainsToolMatch(req string, canonNames map[string]string) string {
	var match string
	var matches int
	for canon := range canonNames {
		if canon == "" || canon == req {
			continue
		} else if !wordBoundedContains(req, canon) && !wordBoundedContains(canon, req) {
			continue
		}
		matches++
		if matches > 1 {
			return ""
		}
		match = canon
	}
	if matches == 1 {
		return match
	}
	return ""
}

// wordBoundedContains reports whether needle appears in haystack at a position
// flanked by '_' or string edges on both sides.
func wordBoundedContains(haystack, needle string) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	var from int
	for {
		i := strings.Index(haystack[from:], needle)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(needle)
		startOK := start == 0 || haystack[start-1] == '_'
		endOK := end == len(haystack) || haystack[end] == '_'
		if startOK && endOK {
			return true
		}
		from = start + 1
	}
}
