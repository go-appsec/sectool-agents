package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFileAtomic(t *testing.T) {
	t.Parallel()

	t.Run("writes_readable_content", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.md")
		require.NoError(t, WriteFileAtomic(path, []byte("hello"), 0o644))
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(raw))
	})

	t.Run("overwrites_existing_content", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.md")
		require.NoError(t, WriteFileAtomic(path, []byte("old"), 0o644))
		require.NoError(t, WriteFileAtomic(path, []byte("new"), 0o644))
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "new", string(raw))
	})

	t.Run("leaves_no_tmp_files", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "out.md")
		require.NoError(t, WriteFileAtomic(path, []byte("x"), 0o644))
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Len(t, entries, 1)
	})

	t.Run("missing_dir_errors", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "nope")
		assert.Error(t, WriteFileAtomic(filepath.Join(dir, "out.md"), []byte("x"), 0o644))
	})
}
