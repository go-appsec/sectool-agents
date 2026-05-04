package orchestrator

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/secagent/cli"
)

// Tool-lifecycle event messages.
const (
	toolMsgDone    = "done"
	toolMsgSlow    = "slow"
	toolMsgTimeout = "timeout"
)

// Log-event tag values.
const (
	tagDecision = "decision"
	tagFinding  = "finding"
)

// Logger emits structured JSON to a log file plus pretty lines to stderr,
// optionally feeding events to an attached Narrator.
type Logger struct {
	mu       sync.Mutex
	file     io.WriteCloser
	mirror   io.Writer
	narrator *Narrator
}

// AttachNarrator sets the narrator that receives every Log call. Pass nil to detach.
func (l *Logger) AttachNarrator(n *Narrator) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.narrator = n
	l.mu.Unlock()
}

// NewLogger returns a Logger appending JSON records to path; stderr receives the human-readable mirror.
func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f, mirror: os.Stderr}, nil
}

// Close closes the underlying log file.
func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Log writes a JSON record to the log file, mirrors operator-relevant events to stderr,
// and records narrate-eligible events to the attached narrator.
func (l *Logger) Log(tag, msg string, fields map[string]any) {
	if l == nil {
		return
	}
	now := time.Now()
	l.mu.Lock()
	narrator := l.narrator
	if l.file != nil {
		if b := buildJSONLine(now, tag, msg, fields); b != nil {
			_, _ = l.file.Write(b)
		}
	}
	if l.mirror != nil && shouldMirror(tag, msg, fields) {
		_, _ = l.mirror.Write(buildPrettyLine(now, tag, msg, fields))
	}
	l.mu.Unlock()
	if narrator != nil && shouldNarrate(tag, msg) {
		narrator.Record(tag, msg, fields)
	}
}

// shouldNarrate reports whether (tag, msg) is signal-grade for the narrator.
func shouldNarrate(tag, msg string) bool {
	switch tag {
	case "controller", tagDecision, tagFinding, "plan", "verify", "worker":
		return true
	case "tool":
		return msg == "start" || msg == toolMsgDone || msg == toolMsgTimeout || msg == toolMsgSlow
	case "agent":
		return msg == "response" || msg == "response timeout" || msg == "response error"
	}
	return false
}

// shouldMirror reports whether (tag, msg) is noteworthy enough to mirror to stderr.
func shouldMirror(tag, msg string, fields map[string]any) bool {
	switch tag {
	case "server", "controller", tagDecision, tagFinding, "summary", "plan", "verify", "recon", "retire":
		return true
	case "narrate":
		// "empty" fires every tick when a reasoning model burns its whole
		// token budget inside an unclosed think block with no truncated-think
		// fallback either. Noisy on stderr; keep the JSON record for diagnostics.
		return !strings.HasSuffix(msg, ": empty")
	case "worker":
		// per-turn escalation lines anchor human reading; drain-error is signal
		return msg == "turn" || msg == "seeded" || strings.Contains(msg, "error")
	case "direct":
		return strings.Contains(msg, "error")
	case "tool":
		// tool lifecycle is chatty; only surface slow/timeout/error outcomes
		switch msg {
		case toolMsgTimeout, toolMsgSlow:
			return true
		case toolMsgDone:
			if b, ok := fields["error"].(bool); ok && b {
				return true
			}
		}
		return false
	case "agent":
		// request/response telemetry is file-only; malformed-args is signal
		return msg == "malformed-args"
	}
	return false
}

// Logf is a Log convenience that formats msg via fmt.Sprintf.
func (l *Logger) Logf(tag, format string, args ...any) {
	l.Log(tag, fmt.Sprintf(format, args...), nil)
}

func buildJSONLine(now time.Time, tag, msg string, fields map[string]any) []byte {
	record := map[string]any{
		"ts":    now.UTC().Format(time.RFC3339Nano),
		"tag":   tag,
		"level": "info",
		"msg":   msg,
	}
	for k, v := range fields {
		record[k] = v
	}
	b, err := json.Marshal(record)
	if err != nil {
		return nil
	}
	return append(b, '\n')
}

func buildPrettyLine(now time.Time, tag, msg string, fields map[string]any) []byte {
	var b strings.Builder
	cli.StyleAppend(&b, cli.Gray, now.Format("15:04:05.000"))
	b.WriteString(" [")
	cli.StyleAppend(&b, cli.Blue, tag)
	b.WriteString("] ")
	if tag == "narrate" {
		writeNarrateMsg(&b, msg)
	} else {
		b.WriteString(msg)
	}
	if len(fields) > 0 {
		keys := bulk.MapKeysSlice(fields)
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteByte(' ')
			cli.StyleAppend(&b, cli.Gray, k+"="+formatPrettyValue(fields[k]))
		}
	}
	b.WriteByte('\n')
	return []byte(b.String())
}

// writeNarrateMsg writes msg to b, coloring any single-token "speaker:" prefix.
func writeNarrateMsg(b *strings.Builder, msg string) {
	if colon := strings.IndexByte(msg, ':'); colon > 0 && !strings.ContainsAny(msg[:colon], " \t") {
		cli.StyleAppend(b, cli.MedGreen, msg[:colon+1])
		b.WriteString(msg[colon+1:])
		return
	}
	b.WriteString(msg)
}

func formatPrettyValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return quoteIfNeeded(t)
	case error:
		return quoteIfNeeded(t.Error())
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case time.Duration:
		return t.String()
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

func quoteIfNeeded(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " \t\"\\\n\r") {
		return strconv.Quote(s)
	}
	return s
}

// MalformedCounter counts malformed tool-args events per model.
type MalformedCounter struct {
	mu    sync.Mutex
	byKey map[string]int
	log   *Logger
}

// NewMalformedCounter returns a MalformedCounter wired to log.
func NewMalformedCounter(log *Logger) *MalformedCounter {
	return &MalformedCounter{byKey: map[string]int{}, log: log}
}

// Observe records and logs a malformed-args event for model/tool.
func (c *MalformedCounter) Observe(model, tool string, err error) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.byKey[model]++
	count := c.byKey[model]
	c.mu.Unlock()
	c.log.Log("agent", "malformed-args", map[string]any{
		"model": model, "tool": tool, "count": count, "err": err.Error(),
	})
}

// Flush emits one "malformed-summary" entry keyed by model. No-op if no events were recorded.
func (c *MalformedCounter) Flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if len(c.byKey) == 0 {
		c.mu.Unlock()
		return
	}
	snapshot := make(map[string]any, len(c.byKey))
	for k, v := range c.byKey {
		snapshot[k] = v
	}
	c.mu.Unlock()
	c.log.Log("controller", "malformed-summary", map[string]any{"by_model": snapshot})
}
