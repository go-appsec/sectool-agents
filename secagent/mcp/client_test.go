package mcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateResult(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 1000)
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{
			name: "under_cap",
			in:   "small",
			max:  100,
			want: "small",
		},
		{
			name: "equal_cap",
			in:   "abcde",
			max:  5,
			want: "abcde",
		},
		{
			name: "empty_input",
			in:   "",
			max:  10,
			want: "",
		},
		{
			name: "disabled_zero_cap",
			in:   long,
			max:  0,
			want: long,
		},
		{
			name: "disabled_negative_cap",
			in:   long,
			max:  -1,
			want: long,
		},
		{
			name: "one_over_cap",
			in:   "abcdef",
			max:  5,
			want: "abcde\n…(truncated: 5 of 6 bytes shown. Reduce scope — e.g., add filters, raise `since`, or request specific fields — then call again.)",
		},
		{
			name: "over_cap_with_notice",
			in:   long,
			max:  100,
			want: strings.Repeat("x", 100) +
				"\n…(truncated: 100 of 1000 bytes shown. Reduce scope — e.g., add filters, raise `since`, or request specific fields — then call again.)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, truncateResult(tc.in, tc.max))
		})
	}
}
