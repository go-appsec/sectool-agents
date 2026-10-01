package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-appsec/sectool-agents/secagent/util"
)

// SectoolServer represents the sectool MCP endpoint. Cmd is nil when secagent attached to an already-running server.
type SectoolServer struct {
	Cmd     *exec.Cmd
	LogFile *os.File
	URL     string
	// waitCh is closed once Cmd has been reaped; non-nil for spawned children.
	waitCh chan struct{}
}

var (
	// readinessProbeTimeout caps each MCP readiness probe.
	readinessProbeTimeout = 500 * time.Millisecond
	// readinessTimeout bounds the total MCP startup wait.
	readinessTimeout = 10 * time.Second
	// readinessInterval spaces out readiness probes.
	readinessInterval = 500 * time.Millisecond
	// terminateGrace bounds the SIGTERM wait before killing the child.
	terminateGrace = 5 * time.Second
)

// StartSectool returns a SectoolServer at mcpPort. When attached is true the
// caller has already verified that an MCP server is reachable and no child
// process is started. Otherwise `sectool mcp` is launched (using binary) and
// secagent waits for readiness.
func StartSectool(ctx context.Context, proxyPort, mcpPort int, binary string, attached bool, log *Logger) (*SectoolServer, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/mcp", mcpPort)

	if attached {
		log.Log("server", "attaching to running sectool", map[string]any{
			"mcp_port": mcpPort, "url": url,
		})
		return &SectoolServer{URL: url}, nil
	}

	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}
	logPath := filepath.Join(cwd, "sectool-mcp.log")
	f, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("create log file: %w", err)
	}
	cmd := exec.CommandContext(ctx, binary, "mcp",
		fmt.Sprintf("--proxy-port=%d", proxyPort),
		fmt.Sprintf("--port=%d", mcpPort),
		"--workflow=multi",
	)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("start sectool: %w", err)
	}
	log.Log("server", "started sectool", map[string]any{
		"mcp_port": mcpPort, "proxy_port": proxyPort,
		"log": logPath, "binary": binary,
	})

	// Reap the child as soon as it exits so an early crash is observed
	// promptly and no zombie survives a startup failure.
	waitCh := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(waitCh)
	}()

	deadline := time.NewTimer(readinessTimeout)
	defer deadline.Stop()
	for {
		if mcpReady(ctx, url) {
			log.Log("server", "ready", map[string]any{"url": url})
			return &SectoolServer{Cmd: cmd, LogFile: f, URL: url, waitCh: waitCh}, nil
		}
		select {
		case <-waitCh:
			_ = f.Close()
			return nil, fmt.Errorf("sectool exited early (code %d)", cmd.ProcessState.ExitCode())
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("sectool startup: %w", ctx.Err())
		case <-deadline.C:
			_ = cmd.Process.Kill()
			<-waitCh
			_ = f.Close()
			return nil, errors.New("sectool MCP server did not become ready within " + readinessTimeout.String())
		case <-time.After(readinessInterval):
		}
	}
}

// MCPReachable reports whether the sectool MCP at mcpPort responds to an HTTP GET within readinessProbeTimeout.
func MCPReachable(ctx context.Context, mcpPort int) bool {
	return mcpReady(ctx, fmt.Sprintf("http://127.0.0.1:%d/mcp", mcpPort))
}

// mcpReady reports whether url is serving the sectool MCP endpoint within readinessProbeTimeout.
// The streamable endpoint answers a GET with 200 (SSE stream) or 405 (no GET
// stream); any other status means something else owns the port.
func mcpReady(ctx context.Context, url string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, readinessProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := util.HTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusMethodNotAllowed
}

// Terminate tears down the child sectool process. No-op when attached to a server secagent didn't start.
func (s *SectoolServer) Terminate() {
	if s == nil || s.Cmd == nil || s.Cmd.Process == nil {
		return
	}
	if s.waitCh == nil {
		s.waitCh = make(chan struct{})
		go func() {
			_, _ = s.Cmd.Process.Wait()
			close(s.waitCh)
		}()
	}
	_ = s.Cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.waitCh:
	case <-time.After(terminateGrace):
		_ = s.Cmd.Process.Kill()
		<-s.waitCh
	}
	if s.LogFile != nil {
		_ = s.LogFile.Close()
	}
}
