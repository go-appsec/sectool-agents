// Package sectoolcheck performs a presence + best-effort staleness check on
// the external sectool binary at agent startup. Missing-binary is fatal at
// resolve time; staleness is fatal only when secagent will spawn sectool
// itself, and informational (log-only) when attaching to an already-running
// MCP. Transient failures (network error, unparseable output) are logged
// and ignored. The latest-version lookup hits the Go module proxy directly
// so no local Go toolchain is required.
package sectoolcheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-appsec/secagent/state"
	"github.com/go-appsec/secagent/util"
)

// ToolboxModule is the Go module path used for the staleness lookup.
const ToolboxModule = "github.com/go-appsec/toolbox"

// InstallCommand is the canonical `go install` line shown to the user.
const InstallCommand = "go install " + ToolboxModule + "/sectool@latest"

// proxyBaseURL is the Go module proxy used for the @v/list lookup.
const proxyBaseURL = "https://proxy.golang.org"

const (
	successTTL = 24 * time.Hour
	failureTTL = time.Hour

	subprocessTimeout = 5 * time.Second
	fetchTimeout      = 5 * time.Second
)

// LogFunc is the minimal logging callback used by this package.
// orchestrator.Logger.Log satisfies it as a method value.
type LogFunc func(tag, msg string, fields map[string]any)

// resolveSectoolBinary returns the sectool absolute path. When preferred is
// non-empty it is used as the user's explicit choice (absolute-existing path,
// otherwise resolved through $PATH). When preferred is empty the fallback
// prefers a binary co-located with the running secagent, then $PATH.
func resolveSectoolBinary(preferred string) (string, error) {
	if preferred != "" {
		if filepath.IsAbs(preferred) {
			if info, err := os.Stat(preferred); err == nil && !info.IsDir() {
				return preferred, nil
			}
			return "", fmt.Errorf("sectool binary not found at %q (install via `%s`)", preferred, InstallCommand)
		}
		binary, err := exec.LookPath(preferred)
		if err != nil {
			return "", fmt.Errorf("sectool binary %q not found on $PATH (install via `%s`): %w", preferred, InstallCommand, err)
		}
		return binary, nil
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		candidate := filepath.Join(filepath.Dir(exe), "sectool")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	binary, err := exec.LookPath("sectool")
	if err != nil {
		return "", fmt.Errorf("sectool not found alongside secagent or in $PATH (install via `%s`): %w", InstallCommand, err)
	}
	return binary, nil
}

// CheckVersion resolves the sectool binary (preferring preferred, otherwise
// using the co-located/$PATH fallback) and, unless skipped, compares its
// version to the latest tagged release of ToolboxModule. Returns the
// resolved absolute path. A non-nil error means the caller should exit:
// either no usable binary was found, or fatalOnStale was true and a strict
// newer release exists. Transient failures (dirty installed, network error)
// yield (resolved, nil).
func CheckVersion(ctx context.Context, log LogFunc, preferred, statePath string, skipVersion, fatalOnStale bool) (string, error) {
	binary, err := resolveSectoolBinary(preferred)
	if err != nil {
		return "", err
	}
	if skipVersion {
		return binary, nil
	}
	return binary, checkVersion(ctx, log, binary, statePath, fatalOnStale, time.Now())
}

// readInstalledFn and fetchLatestFn are package-level seams so tests can swap
// the subprocess- and HTTP-driven implementations without touching real `sectool` / the network.
var (
	readInstalledFn = readInstalledVersion
	fetchLatestFn   = fetchLatest
)

// proxyURLFn is a seam so tests can point fetchLatest at httptest.
var proxyURLFn = func() string { return proxyBaseURL }

// checkVersion is the testable core; statePath and now are injected.
func checkVersion(ctx context.Context, log LogFunc, binary, statePath string, fatalOnStale bool, now time.Time) error {
	installed, ok := readInstalledFn(ctx, binary)
	if !ok {
		log("sectool-check", "skipping staleness check: installed version not a clean vX.Y.Z", nil)
		return nil
	}

	latest, ok := latestFromStateOrFetch(ctx, log, statePath, now)
	if !ok {
		return nil
	}

	if !installed.less(latest) {
		return nil
	}

	if fatalOnStale {
		return fmt.Errorf("sectool %s installed; %s available.\nRun: %s\n(Use --skip-version-check to bypass.)",
			installed.String(), latest.String(), InstallCommand)
	}
	log("sectool-check", "newer sectool available; attaching to running MCP so continuing", map[string]any{
		"installed":   installed.String(),
		"latest":      latest.String(),
		"install_cmd": InstallCommand,
	})
	return nil
}

// latestFromStateOrFetch returns the latest clean release version, consulting
// the state cache first and refreshing on miss. Returns (zero, false) when
// no usable answer is available.
func latestFromStateOrFetch(ctx context.Context, log LogFunc, statePath string, now time.Time) (semver, bool) {
	st, _ := state.Load(statePath)
	if st == nil {
		st = &state.State{}
	}
	if entry := st.SectoolVersionCheck; entry != nil && !entryExpired(entry, now) {
		if entry.Status == "ok" {
			if v, ok := parseVersion(entry.LatestVersion); ok {
				return v, true
			}
		}
		// failure entry within TTL — skip the comparison entirely
		return semver{}, false
	}

	latest, err := fetchLatestFn(ctx)
	if err != nil {
		log("sectool-check", "could not check sectool version", map[string]any{"err": err.Error()})
		st.SectoolVersionCheck = &state.SectoolVersionCheckEntry{Status: "failed", CheckedAt: now.Unix()}
		_ = state.Save(statePath, st)
		return semver{}, false
	}
	st.SectoolVersionCheck = &state.SectoolVersionCheckEntry{
		LatestVersion: latest.String(),
		CheckedAt:     now.Unix(),
		Status:        "ok",
	}
	_ = state.Save(statePath, st)
	return latest, true
}

func entryExpired(e *state.SectoolVersionCheckEntry, now time.Time) bool {
	ttl := successTTL
	if e.Status != "ok" {
		ttl = failureTTL
	}
	return now.Sub(time.Unix(e.CheckedAt, 0)) >= ttl
}

// readInstalledVersion runs `sectool --version` and returns the parsed semver.
// Returns (zero, false) when the binary fails to run or reports a non-clean version.
func readInstalledVersion(ctx context.Context, binary string) (semver, bool) {
	cctx, cancel := context.WithTimeout(ctx, subprocessTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, binary, "--version").Output()
	if err != nil {
		return semver{}, false
	}
	return parseInstalledVersion(string(out))
}

// fetchLatest hits the Go module proxy's @v/list endpoint and returns the
// highest clean vX.Y.Z release.
func fetchLatest(ctx context.Context) (semver, error) {
	cctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	url := proxyURLFn() + "/" + ToolboxModule + "/@v/list"
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return semver{}, fmt.Errorf("new request: %w", err)
	}
	resp, err := util.HTTPClient.Do(req)
	if err != nil {
		return semver{}, fmt.Errorf("proxy get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return semver{}, fmt.Errorf("proxy status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return semver{}, fmt.Errorf("read body: %w", err)
	}
	versions := parseAvailableVersions(string(body))
	if len(versions) == 0 {
		return semver{}, errors.New("no clean vX.Y.Z tags returned")
	}
	max := versions[0]
	for _, v := range versions[1:] {
		if max.less(v) {
			max = v
		}
	}
	return max, nil
}

// cleanVersion matches a strict semver release tag, no pre-release suffixes.
var cleanVersion = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// versionLine extracts the trailing version token from a `sectool --version` line.
var versionLine = regexp.MustCompile(`\bv\d+\.\d+\.\d+\S*`)

// parseInstalledVersion finds the version token in `sectool --version` output and
// returns it only when it is a clean release tag.
func parseInstalledVersion(out string) (semver, bool) {
	token := versionLine.FindString(strings.TrimSpace(out))
	if token == "" {
		return semver{}, false
	}
	return parseVersion(token)
}

// parseAvailableVersions filters whitespace-separated tokens to clean vX.Y.Z.
func parseAvailableVersions(out string) []semver {
	var versions []semver
	for _, tok := range strings.Fields(out) {
		if v, ok := parseVersion(tok); ok {
			versions = append(versions, v)
		}
	}
	return versions
}

func parseVersion(s string) (semver, bool) {
	m := cleanVersion.FindStringSubmatch(s)
	if m == nil {
		return semver{}, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return semver{Major: major, Minor: minor, Patch: patch}, true
}

type semver struct {
	Major, Minor, Patch int
}

func (v semver) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v semver) less(o semver) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Patch < o.Patch
}
