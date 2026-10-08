package version

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		injected string
		bi       *debug.BuildInfo
		want     string
	}{
		{"injected wins", "v1.2.3", nil, "v1.2.3"},
		{"injected wins over devel", "v1.2.3", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "v1.2.3"},
		{"module version used", "dev", &debug.BuildInfo{Main: debug.Module{Version: "v0.9.0"}}, "v0.9.0"},
		{"devel falls back", "dev", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "dev"},
		{"nil build info", "dev", nil, "dev"},
		{"empty module version", "dev", &debug.BuildInfo{}, "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveVersion(tt.injected, tt.bi))
		})
	}
}
