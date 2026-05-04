package agent

import (
	"regexp"
	"slices"
	"strings"
)

// Think-block variants seen in practice; case-insensitive, non-greedy.
var thinkBlockPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<think>.*?</think>`),
	regexp.MustCompile(`(?is)<thinking>.*?</thinking>`),
	regexp.MustCompile(`(?is)<\|thinking\|>.*?<\|/thinking\|>`),
	regexp.MustCompile(`(?is)<reasoning>.*?</reasoning>`),
}

// Literal open/close strings mirroring thinkBlockPatterns for unclosed-tag detection; must be kept in sync.
var thinkTagPairs = []struct {
	open, close string
}{
	{"<think>", "</think>"},
	{"<thinking>", "</thinking>"},
	{"<|thinking|>", "<|/thinking|>"},
	{"<reasoning>", "</reasoning>"},
}

// StripThinkBlocks removes recognized thinking-block variants from s.
// Unclosed blocks are left intact; pair with HasLeadingThinkOpen to detect them.
func StripThinkBlocks(s string) string {
	out := s
	for _, re := range thinkBlockPatterns {
		out = re.ReplaceAllString(out, "")
	}
	return out
}

// FilterThinkBlocks returns a copy of msgs with `<think>` blocks preserved on the last keepLastN
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
	lower := strings.ToLower(strings.TrimSpace(s))
	for _, p := range thinkTagPairs {
		if strings.HasPrefix(lower, strings.ToLower(p.open)) {
			return true
		}
	}
	return false
}

// HasInlineThink reports whether s contains a balanced `<think>...</think>` pair.
func HasInlineThink(s string) bool {
	return slices.ContainsFunc(thinkBlockPatterns, func(re *regexp.Regexp) bool { return re.MatchString(s) })
}

// TruncatedThinkTail returns a best-effort tail of the content inside an
// unclosed think block in s, or "" when no unclosed think tag is found.
func TruncatedThinkTail(s string) string {
	lower := strings.ToLower(s)
	for _, p := range thinkTagPairs {
		openLow := strings.ToLower(p.open)
		closeLow := strings.ToLower(p.close)
		openIdx := strings.LastIndex(lower, openLow)
		if openIdx < 0 {
			continue
		}
		afterStart := openIdx + len(p.open)
		if strings.Contains(lower[afterStart:], closeLow) {
			continue
		}
		return compactThinkTail(s[afterStart:], 240)
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
