package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// BashBackground owns backgrounded `bash` tool processes. Each runs detached
// in its own process group with stdout/stderr in temp files, gets a stopped
// line appended to both log files on exit, and is killed by KillAll.
type BashBackground struct {
	ctx    context.Context // run lifetime; canceled when Run ends or KillAll fires
	cancel context.CancelCauseFunc
	wg     sync.WaitGroup
	active atomic.Int32
}

// NewBashBackground returns a tracker whose processes are killed when parent
// is canceled or KillAll is called.
func NewBashBackground(parent context.Context) *BashBackground {
	ctx, cancel := context.WithCancelCause(parent)
	return &BashBackground{ctx: ctx, cancel: cancel}
}

// Len returns the number of still-running background processes.
func (b *BashBackground) Len() int {
	return int(b.active.Load())
}

// killWaitTimeout bounds KillAll so the stage-3 kill path can never hang on
// a process stuck in uninterruptible sleep (D state ignores SIGKILL).
const killWaitTimeout = 5 * time.Second

// KillAll kills every tracked process group and waits for the stopped lines
// to land in the log files. Idempotent; the wait is bounded by
// killWaitTimeout — stopped lines are best-effort.
func (b *BashBackground) KillAll() {
	b.cancel(nil)
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(killWaitTimeout):
	}
}

// Start runs command via `bash -c` in its own process group with stdout and
// stderr redirected to separate temp files. ctx is the tool-call context —
// it is checked for aborts but the job outlives it, so it is detached with
// context.WithoutCancel. Returns the tool-result text naming the pid and
// both log paths.
func (b *BashBackground) Start(ctx context.Context, command string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("tool call aborted: %w", err)
	}
	if b.ctx.Err() != nil {
		return "", errors.New("background execution is shut down")
	}
	stdout, err := os.CreateTemp("", "secagent-bash-*.out")
	if err != nil {
		return "", err
	}
	stderr, err := os.CreateTemp("", "secagent-bash-*.err")
	if err != nil {
		discardTemp(stdout)
		return "", err
	}
	header := fmt.Sprintf("=== started %s\n$ %s\n", time.Now().Format(time.RFC3339), command)
	_, _ = stdout.WriteString(header)
	_, _ = stderr.WriteString(header)

	cmd := exec.CommandContext(context.WithoutCancel(ctx), "bash", "-c", command)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// own process group so the reap kill takes out the whole child tree
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	b.wg.Add(1)
	b.active.Add(1)
	if b.ctx.Err() != nil {
		// re-check after registering so KillAll can't miss this process
		discardTemp(stdout)
		discardTemp(stderr)
		b.active.Add(-1)
		b.wg.Done()
		return "", errors.New("background execution is shut down")
	}
	if err := cmd.Start(); err != nil {
		discardTemp(stdout)
		discardTemp(stderr)
		b.active.Add(-1)
		b.wg.Done()
		return "", err
	}
	go b.reap(cmd, stdout, stderr)
	return fmt.Sprintf(
		"Background process started: pid %d\nstdout log: %s\nstderr log: %s\n"+
			"Tail the log files to review progress; `kill %d` stops it (children share process group %d).",
		cmd.Process.Pid, stdout.Name(), stderr.Name(), cmd.Process.Pid, cmd.Process.Pid,
	), nil
}

// reap waits for the process to exit naturally or for the tracker's lifetime
// context to end (killing the whole process group), then appends the stopped
// line to both log files. Parent and child share the file offset, so these
// writes land after the child's output.
func (b *BashBackground) reap(cmd *exec.Cmd, stdout, stderr *os.File) {
	defer b.wg.Done()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var err error
	select {
	case err = <-waited:
	case <-b.ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		err = <-waited
	}
	b.active.Add(-1)
	line := fmt.Sprintf("=== background process stopped (%s) at %s\n",
		waitStatus(err), time.Now().Format(time.RFC3339))
	_, _ = stdout.WriteString(line)
	_, _ = stderr.WriteString(line)
	_ = stdout.Close()
	_ = stderr.Close()
}

// waitStatus renders the exit cause for the stopped line.
func waitStatus(err error) string {
	if err == nil {
		return "exit status 0"
	}
	return err.Error()
}

// discardTemp closes and removes a temp file after a failed start.
func discardTemp(f *os.File) {
	_ = f.Close()
	_ = os.Remove(f.Name())
}
