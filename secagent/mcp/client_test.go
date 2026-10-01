package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEstablishTimeout(t *testing.T) {
	t.Parallel()

	prev := handshakeTimeout
	handshakeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = prev })

	t.Run("unresponsive_server", func(t *testing.T) {
		// accepts connections but never answers the handshake
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			select {
			case <-t.Context().Done():
			case <-time.After(10 * time.Second):
			}
		}))
		t.Cleanup(srv.Close)

		cl, defs, err := Establish(t.Context(), srv.URL, "mcp__sectool__", 1024)
		assert.Nil(t, cl)
		assert.Empty(t, defs)
		assert.ErrorIs(t, err, ErrHandshakeTimeout)
	})

	t.Run("connection_refused", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()

		cl, defs, err := Establish(t.Context(), url, "mcp__sectool__", 1024)
		assert.Nil(t, cl)
		assert.Empty(t, defs)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrHandshakeTimeout)
	})
}

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
