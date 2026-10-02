package agent

import (
	"context"
	"errors"
)

// Compactor compresses an agent's history when it nears the context limit.
type Compactor interface {
	MaybeCompact(ctx context.Context, h *History) error
	// SetOnSelfPruneApplied installs a post-apply hook fired with the IDs dropped by the
	// model-driven self-prune pass. Implementations that do not support self-prune may treat this as a no-op.
	SetOnSelfPruneApplied(func([]string))
}

// ErrRetireOnPressure signals that the compactor wants the agent to retire rather than compact.
var ErrRetireOnPressure = errors.New("retire on context pressure")

// ErrContextExhausted signals that compaction could not bring the history below the high
// watermark. Every later drain would fail identically; callers should surface a
// context-exhausted escalation so the agent is retired or recomposed instead of retried.
var ErrContextExhausted = errors.New("context exhausted")
