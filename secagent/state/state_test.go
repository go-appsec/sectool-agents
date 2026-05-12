package state

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	t.Run("missing_file", func(t *testing.T) {
		s, err := Load(filepath.Join(t.TempDir(), "nope.json"))
		require.NoError(t, err)
		assert.Equal(t, &State{}, s)
	})

	t.Run("corrupt_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "c.json")
		require.NoError(t, os.WriteFile(path, []byte("not json"), 0o644))
		s, err := Load(path)
		require.NoError(t, err)
		assert.Equal(t, &State{}, s)
	})

	t.Run("roundtrip", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "s.json")
		in := &State{SectoolVersionCheck: &SectoolVersionCheckEntry{
			LatestVersion: "v0.4.0",
			CheckedAt:     1700000000,
			Status:        "ok",
		}}
		require.NoError(t, Save(path, in))
		out, err := Load(path)
		require.NoError(t, err)
		assert.Equal(t, in, out)
	})
}

func TestSaveAtomic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")

	// concurrent writers should never leave a corrupt file behind
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = Save(path, &State{SectoolVersionCheck: &SectoolVersionCheckEntry{
				LatestVersion: "v0.4.0",
				CheckedAt:     int64(1700000000 + i),
				Status:        "ok",
			}})
		}(i)
	}
	wg.Wait()

	s, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, s.SectoolVersionCheck)
	assert.Equal(t, "ok", s.SectoolVersionCheck.Status)
}
