package config

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()

	parse := func(t *testing.T, args ...string) *Config {
		t.Helper()
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		c, err := Parse(fs, args)
		require.NoError(t, err)
		require.NotNil(t, c)
		return c
	}

	t.Run("prompt_required", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		_, err := Parse(fs, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--prompt")
	})

	t.Run("flag_parse_error", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		_, err := Parse(fs, []string{"-prompt", "x", "-no-such-flag"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no-such-flag")
	})

	t.Run("max_workers_clamped_high", func(t *testing.T) {
		c := parse(t, "-prompt", "x", "-max-workers", "99")
		assert.Equal(t, MaxWorkers, c.MaxWorkers)
	})

	t.Run("max_workers_clamped_low", func(t *testing.T) {
		c := parse(t, "-prompt", "x", "-max-workers", "0")
		assert.Equal(t, MinWorkers, c.MaxWorkers)
	})

	t.Run("autonomous_budget_clamped_high", func(t *testing.T) {
		c := parse(t, "-prompt", "x", "-autonomous-budget", "999")
		assert.Equal(t, MaxAutonomousBudget, c.AutonomousBudget)
	})

	t.Run("autonomous_budget_clamped_low", func(t *testing.T) {
		c := parse(t, "-prompt", "x", "-autonomous-budget", "0")
		assert.Equal(t, 1, c.AutonomousBudget)
	})

	t.Run("log_model_inherits", func(t *testing.T) {
		c := parse(t, "-prompt", "x", "-model", "main")
		assert.Equal(t, "main", c.Model)
		assert.Equal(t, "main", c.LogModel)
	})

	t.Run("log_model_explicit", func(t *testing.T) {
		c := parse(t, "-prompt", "x", "-model", "main", "-log-model", "small")
		assert.Equal(t, "main", c.Model)
		assert.Equal(t, "small", c.LogModel)
	})

	t.Run("log_max_context_inherits", func(t *testing.T) {
		c := parse(t, "-prompt", "x", "-max-context", "64000")
		assert.Equal(t, 64000, c.MaxContext)
		assert.Equal(t, 64000, c.LogMaxContext)
	})

	t.Run("log_max_context_explicit", func(t *testing.T) {
		c := parse(t, "-prompt", "x", "-max-context", "64000", "-log-max-context", "16000")
		assert.Equal(t, 64000, c.MaxContext)
		assert.Equal(t, 16000, c.LogMaxContext)
	})

	t.Run("prompt_inline_unchanged", func(t *testing.T) {
		c := parse(t, "-prompt", "find xss on /login")
		assert.Equal(t, "find xss on /login", c.Prompt)
	})

	t.Run("prompt_from_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "prompt.txt")
		body := "line one\nline two\n"
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		c := parse(t, "-prompt", path)
		assert.Equal(t, "line one\nline two", c.Prompt)
	})

	t.Run("prompt_empty_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "prompt.txt")
		require.NoError(t, os.WriteFile(path, []byte("   \n\t\n"), 0o600))
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		_, err := Parse(fs, []string{"-prompt", path})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})
}
