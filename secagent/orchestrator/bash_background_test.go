package orchestrator

import (
	"os"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var bgPidRe = regexp.MustCompile(`pid (\d+)`)

var bgPathRe = regexp.MustCompile(`(stdout|stderr) log: (.+)\n`)

// bgExtract pulls the pid and both log paths out of a background start message.
func bgExtract(t *testing.T, text string) (int, string, string) {
	t.Helper()
	m := bgPidRe.FindStringSubmatch(text)
	require.NotNil(t, m)
	pid, err := strconv.Atoi(m[1])
	require.NoError(t, err)
	matches := bgPathRe.FindAllStringSubmatch(text, 2)
	require.Len(t, matches, 2)
	return pid, matches[0][2], matches[1][2]
}

// bgWaitStopped polls a log file until the stopped line appears.
func bgWaitStopped(t *testing.T, path string) string {
	t.Helper()
	var contents string
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		contents = string(data)
		return regexp.MustCompile(`=== background process stopped`).Match(data)
	}, 5*time.Second, 10*time.Millisecond)
	return contents
}

func TestBashBackground(t *testing.T) {
	t.Parallel()

	t.Run("logs_output_and_stopped_line", func(t *testing.T) {
		bg := NewBashBackground(t.Context())
		text, err := bg.Start(t.Context(), "echo hello-bg")
		require.NoError(t, err)
		pid, stdoutPath, stderrPath := bgExtract(t, text)

		stdoutLog := bgWaitStopped(t, stdoutPath)
		assert.Contains(t, stdoutLog, "hello-bg")
		assert.Contains(t, stdoutLog, "stopped")
		assert.Contains(t, bgWaitStopped(t, stderrPath), "stopped")
		assert.Equal(t, 0, bg.Len())

		// process fully reaped
		require.Error(t, syscall.Kill(pid, 0), "process %d should be gone", pid)
	})

	t.Run("kill_all_terminates_process", func(t *testing.T) {
		bg := NewBashBackground(t.Context())
		text, err := bg.Start(t.Context(), "tail -f /dev/null")
		require.NoError(t, err)
		pid, stdoutPath, stderrPath := bgExtract(t, text)
		require.Equal(t, 1, bg.Len())

		// SIGKILL to the process group guarantees exit, so this returns promptly
		bg.KillAll()

		assert.Equal(t, 0, bg.Len())
		require.Error(t, syscall.Kill(pid, 0), "process %d should be killed", pid)
		assert.Contains(t, bgWaitStopped(t, stdoutPath), "stopped")
		assert.Contains(t, bgWaitStopped(t, stderrPath), "stopped")
	})
}

func TestBashToolDefBackground(t *testing.T) {
	t.Parallel()

	t.Run("returns_pid_and_log_paths", func(t *testing.T) {
		bg := NewBashBackground(t.Context())
		bt := BashToolDef(0, bg)
		res := bt.Handler(t.Context(), mustMarshal(t, map[string]any{
			"command": "echo bg-tool", "background": true,
		}))
		assert.False(t, res.IsError, res.Text)
		_, stdoutPath, stderrPath := bgExtract(t, res.Text)
		assert.FileExists(t, stdoutPath)
		assert.FileExists(t, stderrPath)

		// echo already exited; KillAll is a fast no-kill join
		bg.KillAll()
		assert.Contains(t, bgWaitStopped(t, stdoutPath), "stopped")
	})

	t.Run("nil_tracker_rejects_background", func(t *testing.T) {
		bt := BashToolDef(0, nil)
		res := bt.Handler(t.Context(), mustMarshal(t, map[string]any{
			"command": "echo hi", "background": true,
		}))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "unavailable")
	})

	t.Run("foreground_unchanged", func(t *testing.T) {
		bg := NewBashBackground(t.Context())
		bt := BashToolDef(0, bg)
		res := bt.Handler(t.Context(), mustMarshal(t, map[string]any{"command": "echo plain"}))
		assert.False(t, res.IsError, res.Text)
		assert.Contains(t, res.Text, "plain")
		assert.Equal(t, 0, bg.Len())
	})
}
