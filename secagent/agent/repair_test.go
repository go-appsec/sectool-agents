package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepairToolArgs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "empty", input: "", want: "{}"},
		{name: "whitespace_only", input: "  \n\t  ", want: "{}"},
		{name: "simple_object", input: `{"a":1}`, want: `{"a":1}`},
		{name: "fenced", input: "```json\n{\"a\":1}\n```", want: `{"a":1}`},
		{name: "fenced_no_lang", input: "```\n{\"a\":1}\n```", want: `{"a":1}`},
		{name: "double_encoded", input: `"{\"a\":1}"`, want: `{"a":1}`},
		{name: "missing_brace", input: `{"a":1`, want: `{"a":1}`},
		{name: "garbage", input: "not json", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RepairToolArgs(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(got))
		})
	}
}
