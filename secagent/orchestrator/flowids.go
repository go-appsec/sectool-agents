package orchestrator

import (
	"regexp"
	"strconv"
	"strings"
)

// Flow IDs (sectool/service/ids/ids.go): base62, default length 6, entity IDs 4.
// The key requires word boundaries on both sides and an explicit [:=]
// separator so suffix-embedded names (workflow_id) and bare prose never match.
var flowIDRegex = regexp.MustCompile(
	`(?i)\b(?:flow[_ ]?id|flow_a|flow_b|source_flow_id)\b["']?\s*[:=]\s*["']?([0-9A-Za-z]{4,16})`,
)

// Same shape constraint as flowIDRegex, applied to map-key values.
var flowIDValueRegex = regexp.MustCompile(`^[0-9A-Za-z]{4,16}$`)

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
	add := func(fid string) {
		if fid == "" {
			return
		}
		if _, ok := seen[fid]; !ok {
			seen[fid] = struct{}{}
			out = append(out, fid)
		}
	}
	walk := func(any) {}
	walk = func(v any) {
		if v == nil {
			return
		}
		switch t := v.(type) {
		case string:
			for _, m := range flowIDRegex.FindAllStringSubmatch(t, -1) {
				add(m[1])
			}
		case map[string]any:
			for k, child := range t {
				if flowIDKeyNames[strings.ToLower(k)] {
					add(flowIDValue(child))
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

// flowIDValue validates a map-key value as a flow ID, returning "" for
// non-string/numeric values or values failing the flow ID shape check.
func flowIDValue(v any) string {
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case int:
		s = strconv.Itoa(t)
	case int64:
		s = strconv.FormatInt(t, 10)
	case float64:
		s = strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
	if !flowIDValueRegex.MatchString(s) {
		return ""
	}
	return s
}
