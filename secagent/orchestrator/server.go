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

	"github.com/go-appsec/secagent/util"
)

// SectoolServer represents the sectool MCP endpoint. Cmd is nil when secagent attached to an already-running server.
type SectoolServer struct {
	Cmd     *exec.Cmd
	LogFile *os.File
	URL     string
}

// readinessProbeTimeout caps each MCP readiness probe.
const readinessProbeTimeout = 500 * time.Millisecond

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
	cmd := exec.Command(binary, "mcp",
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

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			_ = f.Close()
			return nil, fmt.Errorf("sectool exited early (code %d)", cmd.ProcessState.ExitCode())
		}
		if cmd.Process != nil {
			if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("sectool died during startup: %w", err)
			}
		}
		if mcpReachable(ctx, url) {
			log.Log("server", "ready", map[string]any{"url": url})
			return &SectoolServer{Cmd: cmd, LogFile: f, URL: url}, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	_ = f.Close()
	return nil, errors.New("sectool MCP server did not become ready within 10s")
}

// MCPReachable reports whether the sectool MCP at mcpPort responds to an HTTP GET within readinessProbeTimeout.
func MCPReachable(ctx context.Context, mcpPort int) bool {
	return mcpReachable(ctx, fmt.Sprintf("http://127.0.0.1:%d/mcp", mcpPort))
}

// mcpReachable reports whether url responds to an HTTP GET within readinessProbeTimeout.
func mcpReachable(ctx context.Context, url string) bool {
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
	_ = resp.Body.Close()
	return true
}

// Terminate tears down the child sectool process. No-op when attached to a server secagent didn't start.
func (s *SectoolServer) Terminate() {
	if s == nil || s.Cmd == nil || s.Cmd.Process == nil {
		return
	}
	_ = s.Cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_, _ = s.Cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = s.Cmd.Process.Kill()
		<-done
	}
	if s.LogFile != nil {
		_ = s.LogFile.Close()
	}
}
