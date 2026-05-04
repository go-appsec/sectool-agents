package orchestrator

import (
	"context"
	"errors"
)

// PhaseRecover holds optional hooks for one-shot phase recovery.
type PhaseRecover struct {
	Compact     func()          // optional; runs between attempts
	OnExhausted func(err error) // optional; runs after final failure
}

// RunPhaseAttempt runs attempt with one-shot recovery via policy. Context errors propagate immediately;
// other errors trigger Compact then a retry, with OnExhausted called on second failure.
func RunPhaseAttempt[T any](ctx context.Context, attempt func(context.Context) (T, error),
	policy PhaseRecover, log *Logger, phase string) (T, error) {
	out, err := attempt(ctx)
	if err == nil {
		return out, nil
	}
	if isCtxErr(err) {
		return out, err
	}
	log.Log(phase, "recover", map[string]any{"attempt": 1, "err": err.Error()})
	if policy.Compact != nil {
		policy.Compact()
	}
	out, err = attempt(ctx)
	if err == nil {
		return out, nil
	}
	if isCtxErr(err) {
		return out, err
	}
	log.Log(phase, "retry exhausted", map[string]any{"err": err.Error()})
	if policy.OnExhausted != nil {
		policy.OnExhausted(err)
	}
	return out, err
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
