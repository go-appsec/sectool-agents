package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractJSONObject(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "bare_object", in: `{"a":1}`, want: `{"a":1}`},
		{name: "fenced_json_block", in: "```json\n{\"a\":1}\n```", want: `{"a":1}`},
		{name: "fenced_no_lang", in: "```\n{\"a\":1}\n```", want: `{"a":1}`},
		{name: "prose_before_after", in: "here is the result:\n{\"a\":1}\ngood.", want: `{"a":1}`},
		{name: "no_braces", in: "just text", want: "just text"},
		{name: "empty", in: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ExtractJSONObject(tc.in))
		})
	}
}
