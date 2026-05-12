package sectoolcheck

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/state"
)

type logEntry struct {
	tag, msg string
	fields   map[string]any
}

func recorder() (LogFunc, *[]logEntry) {
	var entries []logEntry
	fn := func(tag, msg string, fields map[string]any) {
		entries = append(entries, logEntry{tag: tag, msg: msg, fields: fields})
	}
	return fn, &entries
}

func TestParseInstalledVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want semver
		ok   bool
	}{
		{"clean_release", "sectool version v0.1.15", semver{0, 1, 15}, true},
		{"git_suffix", "sectool version v0.1.15-1-g1ae5950", semver{}, false},
		{"devel", "sectool version (devel)", semver{}, false},
		{"empty", "", semver{}, false},
		{"trailing_newline", "sectool version v1.2.3\n", semver{1, 2, 3}, true},
		{"prefix_then_release", "sectool version: v2.0.0", semver{2, 0, 0}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseInstalledVersion(tc.in)
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestParseAvailableVersions(t *testing.T) {
	t.Parallel()
	in := "v0.1.0\nv0.1.1\nv0.2.0-rc1\nv0.2.0\nv0.3.0\n"
	got := parseAvailableVersions(in)
	require.Len(t, got, 4)
	assert.Equal(t, semver{0, 1, 0}, got[0])
	assert.Equal(t, semver{0, 1, 1}, got[1])
	assert.Equal(t, semver{0, 2, 0}, got[2])
	assert.Equal(t, semver{0, 3, 0}, got[3])
}

func TestSemverLess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		a, b       semver
		aLessThanB bool
	}{
		{"patch_diff", semver{0, 1, 0}, semver{0, 1, 1}, true},
		{"minor_diff", semver{0, 1, 9}, semver{0, 2, 0}, true},
		{"major_diff", semver{0, 9, 9}, semver{1, 0, 0}, true},
		{"equal", semver{1, 2, 3}, semver{1, 2, 3}, false},
		{"greater", semver{1, 2, 4}, semver{1, 2, 3}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.aLessThanB, tc.a.less(tc.b))
		})
	}
}

func TestEntryExpired(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cases := []struct {
		name    string
		entry   state.SectoolVersionCheckEntry
		expired bool
	}{
		{"fresh_ok", state.SectoolVersionCheckEntry{Status: "ok", CheckedAt: now.Add(-1 * time.Hour).Unix()}, false},
		{"stale_ok", state.SectoolVersionCheckEntry{Status: "ok", CheckedAt: now.Add(-25 * time.Hour).Unix()}, true},
		{"fresh_fail", state.SectoolVersionCheckEntry{Status: "failed", CheckedAt: now.Add(-30 * time.Minute).Unix()}, false},
		{"stale_fail", state.SectoolVersionCheckEntry{Status: "failed", CheckedAt: now.Add(-2 * time.Hour).Unix()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expired, entryExpired(&tc.entry, now))
		})
	}
}

func TestCheckVersion(t *testing.T) {
	// not parallel: shared package-level seams readInstalledFn / fetchLatestFn
	now := time.Unix(1_700_000_000, 0)

	t.Run("dirty_installed_skips_silently", func(t *testing.T) {
		restore := swap(t,
			func(context.Context, string) (semver, bool) { return semver{}, false },
			func(context.Context) (semver, error) {
				t.Fatalf("fetchLatest must not be called for dirty installed")
				return semver{}, nil
			},
		)
		defer restore()

		log, entries := recorder()
		err := checkVersion(t.Context(), log, "/fake/sectool", filepath.Join(t.TempDir(), "s.json"), true, now)
		require.NoError(t, err)
		require.Len(t, *entries, 1)
		assert.Contains(t, (*entries)[0].msg, "not a clean")
	})

	t.Run("up_to_date_passes", func(t *testing.T) {
		restore := swap(t,
			func(context.Context, string) (semver, bool) { return semver{0, 4, 0}, true },
			func(context.Context) (semver, error) { return semver{0, 4, 0}, nil },
		)
		defer restore()

		log, _ := recorder()
		err := checkVersion(t.Context(), log, "/fake/sectool", filepath.Join(t.TempDir(), "s.json"), true, now)
		assert.NoError(t, err)
	})

	t.Run("stale_fatal_returns_install_command", func(t *testing.T) {
		restore := swap(t,
			func(context.Context, string) (semver, bool) { return semver{0, 3, 1}, true },
			func(context.Context) (semver, error) { return semver{0, 4, 0}, nil },
		)
		defer restore()

		log, _ := recorder()
		err := checkVersion(t.Context(), log, "/fake/sectool", filepath.Join(t.TempDir(), "s.json"), true, now)
		require.Error(t, err)
		msg := err.Error()
		assert.Contains(t, msg, "v0.3.1")
		assert.Contains(t, msg, "v0.4.0")
		assert.Contains(t, msg, InstallCommand)
		assert.Contains(t, msg, "--skip-version-check")
	})

	t.Run("stale_nonfatal_logs_only", func(t *testing.T) {
		restore := swap(t,
			func(context.Context, string) (semver, bool) { return semver{0, 3, 1}, true },
			func(context.Context) (semver, error) { return semver{0, 4, 0}, nil },
		)
		defer restore()

		log, entries := recorder()
		err := checkVersion(t.Context(), log, "/fake/sectool", filepath.Join(t.TempDir(), "s.json"), false, now)
		require.NoError(t, err)
		require.Len(t, *entries, 1)
		assert.Contains(t, (*entries)[0].msg, "newer sectool")
		assert.Equal(t, "v0.3.1", (*entries)[0].fields["installed"])
		assert.Equal(t, "v0.4.0", (*entries)[0].fields["latest"])
	})

	t.Run("fetch_failure_warns_and_continues", func(t *testing.T) {
		restore := swap(t,
			func(context.Context, string) (semver, bool) { return semver{0, 3, 1}, true },
			func(context.Context) (semver, error) { return semver{}, errors.New("network down") },
		)
		defer restore()

		log, entries := recorder()
		statePath := filepath.Join(t.TempDir(), "s.json")
		err := checkVersion(t.Context(), log, "/fake/sectool", statePath, true, now)
		require.NoError(t, err)
		require.Len(t, *entries, 1)
		assert.Contains(t, (*entries)[0].msg, "could not check")

		st, err := state.Load(statePath)
		require.NoError(t, err)
		require.NotNil(t, st.SectoolVersionCheck)
		assert.Equal(t, "failed", st.SectoolVersionCheck.Status)
	})

	t.Run("cache_hit_skips_network", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "s.json")
		require.NoError(t, state.Save(statePath, &state.State{SectoolVersionCheck: &state.SectoolVersionCheckEntry{
			LatestVersion: "v0.4.0",
			CheckedAt:     now.Unix(),
			Status:        "ok",
		}}))

		restore := swap(t,
			func(context.Context, string) (semver, bool) { return semver{0, 4, 0}, true },
			func(context.Context) (semver, error) {
				t.Fatalf("fetchLatest must not be called on fresh cache hit")
				return semver{}, nil
			},
		)
		defer restore()

		log, _ := recorder()
		err := checkVersion(t.Context(), log, "/fake/sectool", statePath, true, now)
		assert.NoError(t, err)
	})

	t.Run("failure_cache_hit_skips_comparison", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "s.json")
		require.NoError(t, state.Save(statePath, &state.State{SectoolVersionCheck: &state.SectoolVersionCheckEntry{
			Status:    "failed",
			CheckedAt: now.Add(-30 * time.Minute).Unix(),
		}}))

		fetchCalls := 0
		restore := swap(t,
			func(context.Context, string) (semver, bool) { return semver{0, 0, 1}, true },
			func(context.Context) (semver, error) {
				fetchCalls++
				return semver{0, 4, 0}, nil
			},
		)
		defer restore()

		log, _ := recorder()
		err := checkVersion(t.Context(), log, "/fake/sectool", statePath, true, now)
		require.NoError(t, err)
		assert.Equal(t, 0, fetchCalls, "failure cache within TTL must not re-fetch")
	})
}

func TestFetchLatestAgainstHTTPServer(t *testing.T) {
	// not parallel: mutates package-level proxyURLFn
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+ToolboxModule+"/@v/list" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("v0.1.0\nv0.2.0\nv0.3.0-rc1\nv0.4.0\n"))
	}))
	defer srv.Close()

	prev := proxyURLFn
	proxyURLFn = func() string { return srv.URL }
	defer func() { proxyURLFn = prev }()

	got, err := fetchLatest(t.Context())
	require.NoError(t, err)
	assert.Equal(t, semver{0, 4, 0}, got)
}

func TestFetchLatestProxyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusInternalServerError)
	}))
	defer srv.Close()

	prev := proxyURLFn
	proxyURLFn = func() string { return srv.URL }
	defer func() { proxyURLFn = prev }()

	_, err := fetchLatest(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy status 500")
}

func TestResolveSectoolBinary(t *testing.T) {
	// not parallel: mutates PATH via t.Setenv
	writeBin := func(t *testing.T, dir, name string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755))
		return path
	}

	t.Run("preferred_absolute_existing", func(t *testing.T) {
		dir := t.TempDir()
		bin := writeBin(t, dir, "sectool")
		t.Setenv("PATH", "")
		got, err := resolveSectoolBinary(bin)
		require.NoError(t, err)
		assert.Equal(t, bin, got)
	})

	t.Run("preferred_absolute_missing", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("PATH", "")
		_, err := resolveSectoolBinary(filepath.Join(dir, "nope"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), InstallCommand)
	})

	t.Run("preferred_bare_name_found_on_path", func(t *testing.T) {
		dir := t.TempDir()
		bin := writeBin(t, dir, "mysectool")
		t.Setenv("PATH", dir)
		got, err := resolveSectoolBinary("mysectool")
		require.NoError(t, err)
		assert.Equal(t, bin, got)
	})

	t.Run("preferred_bare_name_missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		_, err := resolveSectoolBinary("mysectool")
		require.Error(t, err)
		assert.Contains(t, err.Error(), InstallCommand)
	})

	t.Run("empty_falls_back_to_path", func(t *testing.T) {
		dir := t.TempDir()
		bin := writeBin(t, dir, "sectool")
		t.Setenv("PATH", dir)
		got, err := resolveSectoolBinary("")
		require.NoError(t, err)
		// os.Executable + co-located check returns empty here (test binary dir
		// has no `sectool`), so $PATH lookup wins.
		assert.Equal(t, bin, got)
	})

	t.Run("empty_and_missing_returns_install_hint", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		_, err := resolveSectoolBinary("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), InstallCommand)
	})
}

func TestCheckVersionResolutionFailureFatal(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	log, _ := recorder()
	_, err := CheckVersion(t.Context(), log, "/nonexistent/sectool", filepath.Join(t.TempDir(), "s.json"), true, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), InstallCommand)
}

func swap(
	t *testing.T,
	read func(context.Context, string) (semver, bool),
	fetch func(context.Context) (semver, error),
) func() {
	t.Helper()
	prevRead, prevFetch := readInstalledFn, fetchLatestFn
	readInstalledFn = read
	fetchLatestFn = fetch
	return func() {
		readInstalledFn = prevRead
		fetchLatestFn = prevFetch
	}
}
