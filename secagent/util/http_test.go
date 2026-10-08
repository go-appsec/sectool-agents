package util

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/sectool-agents/secagent/version"
)

func TestUserAgent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		set  string
		want string
	}{
		{"default injected", "", "secagent/" + version.Version},
		{"explicit preserved", "custom/1.0", "custom/1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = append(got, r.Header.Get("User-Agent"))
			}))
			t.Cleanup(srv.Close)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
			require.NoError(t, err)
			if tt.set != "" {
				req.Header.Set("User-Agent", tt.set)
			}
			_, err = HTTPClient.Do(req)
			require.NoError(t, err)

			assert.Equal(t, []string{tt.want}, got)
		})
	}
}
