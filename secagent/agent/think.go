package agent

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// thinkTagNames are the tag words recognized as inline think delimiters.
// Single source of truth: open/close/block patterns and the synthesized
// canonical tags all derive from this list.
var thinkTagNames = []string{"think", "thinking", "reasoning"}

// Canonical inline tags, used when synthesizing an inline think block.
const (
	thinkOpenTag  = "<think>"
	thinkCloseTag = "</think>"
)

var (
	// Patterns tolerate whitespace/pipe variants around the tag names so
	// `< think>`, `</think>`, `<|thinking|>`, `< think >`, etc. all match.
	thinkNamePattern  = `(?:` + strings.Join(thinkTagNames, "|") + `)`
	thinkOpenPattern  = `<[\s|]*` + thinkNamePattern + `[\s|]*>`
	thinkClosePattern = `<[\s|]*/[\s|]*` + thinkNamePattern + `[\s|]*>`

	thinkOpenRe  = regexp.MustCompile(`(?i)` + thinkOpenPattern)
	thinkCloseRe = regexp.MustCompile(`(?i)` + thinkClosePattern)
	thinkBlockRe = regexp.MustCompile(`(?is)` + thinkOpenPattern + `.*?` + thinkClosePattern)
	thinkLeadRe  = regexp.MustCompile(`(?i)^\s*` + thinkOpenPattern)
)

// wrapThinkBlock wraps s in the canonical inline think tags.
func wrapThinkBlock(s string) string {
	return thinkOpenTag + s + thinkCloseTag
}

// StripThinkBlocks removes recognized thinking-block variants from s,
// handling mixed and nested blocks. Unclosed blocks are left intact; pair
// with HasLeadingThinkOpen to detect them.
func StripThinkBlocks(s string) string {
	opens := thinkOpenRe.FindAllStringIndex(s, -1)
	closes := thinkCloseRe.FindAllStringIndex(s, -1)
	if len(opens) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	depth, openStart, prev := 0, 0, 0
	oi, ci := 0, 0
	for oi < len(opens) || ci < len(closes) {
		switch {
		case ci >= len(closes) || (oi < len(opens) && opens[oi][0] < closes[ci][0]):
			if depth == 0 {
				openStart = opens[oi][0]
			}
			depth++
			oi++
		default:
			if depth > 0 {
				depth--
				if depth == 0 {
					b.WriteString(s[prev:openStart])
					prev = closes[ci][1]
				}
			}
			ci++
		}
	}
	b.WriteString(s[prev:])
	return b.String()
}

// FilterThinkBlocks returns a copy of msgs with think blocks preserved on the last keepLastN
// assistant messages and stripped from older assistants. keepLastN <= 0 strips think from every
// assistant message. Non-assistant messages pass through untouched.
func FilterThinkBlocks(msgs []Message, keepLastN int) []Message {
	if len(msgs) == 0 {
		return msgs
	}
	out := slices.Clone(msgs)
	remaining := keepLastN
	for i := len(out) - 1; i >= 0; i-- {
		if out[i].Role != RoleAssistant {
			continue
		}
		if remaining > 0 {
			remaining--
			continue
		}
		out[i].Content = StripThinkBlocks(out[i].Content)
	}
	return out
}

// HasLeadingThinkOpen reports whether s begins with an opening think tag, signaling an unclosed block.
func HasLeadingThinkOpen(s string) bool {
	return thinkLeadRe.MatchString(s)
}

// HasInlineThink reports whether s contains a balanced inline think pair.
func HasInlineThink(s string) bool {
	return thinkBlockRe.MatchString(s)
}

// TruncatedThinkTail returns a best-effort tail of the content inside an
// unclosed think block in s, or "" when no unclosed think tag is found.
func TruncatedThinkTail(s string) string {
	opens := thinkOpenRe.FindAllStringIndex(s, -1)
	for i := len(opens) - 1; i >= 0; i-- {
		after := s[opens[i][1]:]
		if thinkCloseRe.MatchString(after) {
			continue
		}
		return compactThinkTail(after, 240)
	}
	return ""
}

// compactThinkTail returns the final portion of s up to maxChars, with
// whitespace collapsed and aligned to a word/sentence boundary.
func compactThinkTail(s string, maxChars int) string {
	collapsed := strings.Join(strings.Fields(s), " ")
	if collapsed == "" {
		return ""
	}
	if len(collapsed) <= maxChars {
		return collapsed
	}
	tail := collapsed[len(collapsed)-maxChars:]
	for len(tail) > 0 && !utf8.RuneStart(tail[0]) {
		tail = tail[1:]
	}
	if sp := strings.IndexByte(tail, ' '); sp > 0 {
		tail = tail[sp+1:]
	}
	for i := 0; i < len(tail); i++ {
		c := tail[i]
		if c == '.' || c == '!' || c == '?' {
			rest := strings.TrimSpace(tail[i+1:])
			if rest != "" {
				return "…" + rest
			}
			break
		}
	}
	return "…" + tail
}
