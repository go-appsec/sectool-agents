package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/sectool-agents/secagent/agent"
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

		// process fully reaped
		require.Error(t, syscall.Kill(pid, 0), "process %d should be gone", pid)
	})

	t.Run("ignores_tool_call_deadline", func(t *testing.T) {
		bg := NewBashBackground(t.Context())
		toolCtx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		text, err := bg.Start(toolCtx, "sleep 1 && echo survived-deadline")
		require.NoError(t, err)
		_, stdoutPath, _ := bgExtract(t, text)

		// the per-tool timeout fires while the job is still running
		<-toolCtx.Done()
		require.ErrorIs(t, toolCtx.Err(), context.DeadlineExceeded)
		// the job ignores it and runs to completion
		assert.Contains(t, bgWaitStopped(t, stdoutPath), "survived-deadline")
		bg.KillAll()
	})

	t.Run("kill_all_terminates_process", func(t *testing.T) {
		bg := NewBashBackground(t.Context())
		text, err := bg.Start(t.Context(), "tail -f /dev/null")
		require.NoError(t, err)
		pid, stdoutPath, stderrPath := bgExtract(t, text)
		require.NoError(t, syscall.Kill(pid, 0))

		// SIGKILL to the process group guarantees exit, so this returns promptly
		bg.KillAll()

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
	})
}

func TestBashToolDefForegroundGroupKill(t *testing.T) {
	t.Parallel()

	t.Run("timeout_kills_process_group", func(t *testing.T) {
		pidPath := filepath.Join(t.TempDir(), "child.pid")
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		bt := BashToolDef(0, nil)
		// child outlives the call AND the poll window below (a short sleep
		// would exit on its own and mask a missing group kill); wait keeps
		// bash alive until the timeout
		args := mustMarshal(t, map[string]any{
			"command": fmt.Sprintf("sleep 60 & echo $! > '%s'; wait", pidPath),
		})
		done := make(chan agent.ToolResult, 1)
		go func() { done <- bt.Handler(ctx, args) }()

		// the grandchild must die while the call is still pending — checking
		// after the handler returns lets an orphan's natural expiry mask a
		// missing kill (and a pipe-holding orphan delays that return anyway)
		require.Eventually(t, func() bool {
			data, err := os.ReadFile(pidPath)
			if err != nil {
				return false
			}
			child, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				return false
			}
			return syscall.Kill(child, 0) != nil
		}, 5*time.Second, 10*time.Millisecond,
			"grandchild should die with the process group on timeout")

		select {
		case res := <-done:
			assert.True(t, res.IsError)
		case <-time.After(2 * time.Second):
			t.Fatal("bash handler did not return after the timeout kill")
		}
	})
}
