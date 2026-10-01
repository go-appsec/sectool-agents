package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractFlowIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		inputs []any
		want   []string
	}{
		{
			name:   "plain_text",
			inputs: []any{"flow_id=abc123 and flow_id=def456"},
			want:   []string{"abc123", "def456"},
		},
		{
			name:   "dict_keys",
			inputs: []any{map[string]any{"flow_id": "aaaa11", "other": "ignore"}},
			want:   []string{"aaaa11"},
		},
		{
			name: "nested_slice",
			inputs: []any{[]any{
				map[string]any{"flow_a": "IDAaA11"},
				map[string]any{"flow_b": "IDBbB22"},
			}},
			want: []string{"IDAaA11", "IDBbB22"},
		},
		{
			name:   "quoted_json_style",
			inputs: []any{"\"flow_id\": \"abc123\""},
			want:   []string{"abc123"},
		},
		{
			name:   "dedup",
			inputs: []any{"flow_id=abc123", "flow_id=abc123"},
			want:   []string{"abc123"},
		},
		{
			name:   "rejects_bare_flow_word",
			inputs: []any{"the flow chart shows details"},
			want:   nil,
		},
		{
			name:   "rejects_suffix_embedded_key",
			inputs: []any{"workflow_id=abc123 and dataflow_id=def456"},
			want:   nil,
		},
		{
			name:   "rejects_prose_without_separator",
			inputs: []any{"flow_a returned nothing", "flow a was dismissed", "flow_id abc123"},
			want:   nil,
		},
		{
			name:   "rejects_invalid_map_value",
			inputs: []any{map[string]any{"flow_id": "ab1", "flow_a": "abc-123!"}},
			want:   nil,
		},
		{
			name:   "numeric_map_value",
			inputs: []any{map[string]any{"flow_id": 123456, "flow_b": int64(123457)}},
			want:   []string{"123456", "123457"},
		},
		{
			name:   "rejects_non_string_map_value",
			inputs: []any{map[string]any{"flow_id": true}},
			want:   nil,
		},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ExtractFlowIDs(c.inputs...))
		})
	}
}
