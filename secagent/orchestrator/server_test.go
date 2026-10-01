package orchestrator

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubBin is the compiled mcpstub binary, built once in TestMain.
var stubBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mcpstub")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		os.Exit(1)
	}
	stubBin = filepath.Join(dir, "mcpstub")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", stubBin, "testdata/mcpstub/main.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build mcpstub: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestStartSectool(t *testing.T) {
	// mutates readiness timers and cwd; keep cases serial
	t.Run("attached", func(t *testing.T) {
		srv, err := StartSectool(t.Context(), 8080, 9119, stubBin, true, nil)
		require.NoError(t, err)
		assert.Nil(t, srv.Cmd)
		assert.Nil(t, srv.LogFile)
		assert.Equal(t, "http://127.0.0.1:9119/mcp", srv.URL)
	})

	t.Run("ready", func(t *testing.T) {
		t.Chdir(t.TempDir())
		proxy, mcp := freePort(t), freePort(t)
		srv, err := StartSectool(t.Context(), proxy, mcp, stubBin, false, nil)
		require.NoError(t, err)
		require.NotNil(t, srv.Cmd)
		t.Cleanup(srv.Terminate)
		assert.Equal(t, fmt.Sprintf("http://127.0.0.1:%d/mcp", mcp), srv.URL)
	})

	t.Run("early exit", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv("MCPSTUB_MODE", "crash")
		proxy, mcp := freePort(t), freePort(t)
		_, err := StartSectool(t.Context(), proxy, mcp, stubBin, false, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exited early (code 3)")
	})

	t.Run("not ready", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv("MCPSTUB_MODE", "notfound")
		restoreTimeout(t, 500*time.Millisecond)
		proxy, mcp := freePort(t), freePort(t)
		_, err := StartSectool(t.Context(), proxy, mcp, stubBin, false, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "did not become ready within")
	})

	t.Run("context cancel", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv("MCPSTUB_MODE", "hang")
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		proxy, mcp := freePort(t), freePort(t)
		_, err := StartSectool(ctx, proxy, mcp, stubBin, false, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func TestMCPReachable(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   bool
	}{
		{"ok", http.StatusOK, true},
		{"method not allowed", http.StatusMethodNotAllowed, true},
		{"not found", http.StatusNotFound, false},
		{"server error", http.StatusBadGateway, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			t.Cleanup(srv.Close)
			assert.Equal(t, tt.want, mcpReady(t.Context(), srv.URL))
		})
	}

	t.Run("connection refused", func(t *testing.T) {
		assert.False(t, MCPReachable(t.Context(), freePort(t)))
	})
}

func TestTerminate(t *testing.T) {
	t.Run("no child", func(t *testing.T) {
		(&SectoolServer{URL: "http://x"}).Terminate()
	})

	t.Run("reaps child and closes log", func(t *testing.T) {
		t.Chdir(t.TempDir())
		proxy, mcp := freePort(t), freePort(t)
		srv, err := StartSectool(t.Context(), proxy, mcp, stubBin, false, nil)
		require.NoError(t, err)
		srv.Terminate()
		assert.NotNil(t, srv.Cmd.ProcessState)
		assert.Error(t, srv.LogFile.Close(), "log file should already be closed")
	})

	t.Run("force kills on grace expiry", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv("MCPSTUB_MODE", "ignore-term")
		restoreGrace(t, 50*time.Millisecond)
		proxy, mcp := freePort(t), freePort(t)
		srv, err := StartSectool(t.Context(), proxy, mcp, stubBin, false, nil)
		require.NoError(t, err)
		start := time.Now()
		srv.Terminate()
		assert.Less(t, time.Since(start), 3*time.Second)
		assert.NotNil(t, srv.Cmd.ProcessState)
	})
}

// freePort returns a free TCP port; racy but adequate for tests.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// restoreTimeout sets readinessTimeout for the test and restores it at cleanup.
func restoreTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := readinessTimeout
	readinessTimeout = d
	t.Cleanup(func() { readinessTimeout = orig })
}

// restoreGrace sets terminateGrace for the test and restores it at cleanup.
func restoreGrace(t *testing.T, d time.Duration) {
	t.Helper()
	orig := terminateGrace
	terminateGrace = d
	t.Cleanup(func() { terminateGrace = orig })
}
