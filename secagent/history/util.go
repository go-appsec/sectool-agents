package history

// Logger is a minimal structured-event sink.
type Logger interface {
	Log(tag, msg string, fields map[string]any)
}

// NopLogger discards every log event.
type NopLogger struct{}

func (NopLogger) Log(string, string, map[string]any) {}

func fallbackName(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func fallbackArgs(s string) string {
	if s == "" {
		return "{}"
	}
	return s
}
