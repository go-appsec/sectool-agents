package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// withColors sets useColor for the test and restores it on cleanup.
func withColors(t *testing.T, on bool) {
	t.Helper()

	prev := useColor
	useColor = on
	t.Cleanup(func() { useColor = prev })
}

func TestStyleAppend(t *testing.T) {
	t.Run("disabled_writes_plain", func(t *testing.T) {
		withColors(t, false)
		var b strings.Builder
		StyleAppend(&b, Blue, "tag")
		assert.Equal(t, "tag", b.String())
	})

	t.Run("enabled_writes_escaped", func(t *testing.T) {
		withColors(t, true)
		var b strings.Builder
		StyleAppend(&b, Blue, "tag")
		assert.Equal(t, Blue+"tag"+Reset, b.String())
	})
}
