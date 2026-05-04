package orchestrator

import (
	"regexp"
	"strings"
)

// Flow IDs (sectool/service/ids/ids.go): base62, default length 6, entity IDs 4.
// Only match prefixed forms; a bare "flow" keyword mis-matches prose.
var flowIDRegex = regexp.MustCompile(
	`(?i)(?:flow[_ ]?id|flow_a|flow_b|source_flow_id)\b\s*[:=]?\s*["']?([0-9A-Za-z]{4,16})`,
)

var flowIDKeyNames = map[string]bool{
	"flow_id":        true,
	"flow_a":         true,
	"flow_b":         true,
	"source_flow_id": true,
}

// ExtractFlowIDs returns sectool flow IDs found in sources
// (strings, maps, and slices), preserving order and deduplicating.
func ExtractFlowIDs(sources ...any) []string {
	seen := map[string]struct{}{}
	var out []string
	walk := func(any) {}
	walk = func(v any) {
		if v == nil {
			return
		}
		switch t := v.(type) {
		case string:
			for _, m := range flowIDRegex.FindAllStringSubmatch(t, -1) {
				fid := m[1]
				if _, ok := seen[fid]; !ok {
					seen[fid] = struct{}{}
					out = append(out, fid)
				}
			}
		case map[string]any:
			for k, child := range t {
				if flowIDKeyNames[strings.ToLower(k)] {
					if s, ok := child.(string); ok && s != "" {
						if _, ok := seen[s]; !ok {
							seen[s] = struct{}{}
							out = append(out, s)
						}
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	for _, src := range sources {
		walk(src)
	}
	return out
}
