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
				map[string]any{"flow_a": "ID_AAA1"},
				map[string]any{"flow_b": "ID_BBB2"},
			}},
			want: []string{"ID_AAA1", "ID_BBB2"},
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
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ExtractFlowIDs(c.inputs...))
		})
	}
}
