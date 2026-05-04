package cli

import (
	"os"
	"strings"
)

const (
	Reset    = "\033[0m"
	Bold     = "\033[1m"
	Dim      = "\033[2m"
	Black    = "\033[30m"
	Red      = "\033[31m"
	Green    = "\033[32m"
	Yellow   = "\033[33m"
	Blue     = "\033[34m"
	Magenta  = "\033[35m"
	Cyan     = "\033[36m"
	White    = "\033[37m"
	Gray     = "\033[38;5;245m"
	MedGreen = "\033[38;5;34m"
)

var useColor bool

// IsTerminal reports whether f is a character device.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// EnableColors opts the pretty logger into ANSI color output.
func EnableColors() {
	useColor = true
}

// StyleAppend writes s to sb, wrapping it in code/Reset when colors are enabled.
func StyleAppend(sb *strings.Builder, code, s string) {
	if useColor {
		sb.WriteString(code)
		sb.WriteString(s)
		sb.WriteString(Reset)
	} else {
		sb.WriteString(s)
	}
}
