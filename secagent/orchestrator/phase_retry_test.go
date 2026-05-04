package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunPhaseAttempt(t *testing.T) {
	t.Parallel()

	t.Run("success_first_try", func(t *testing.T) {
		var calls int
		var compacted, exhausted bool
		out, err := RunPhaseAttempt(t.Context(),
			func(ctx context.Context) (int, error) { calls++; return 42, nil },
			PhaseRecover{
				Compact:     func() { compacted = true },
				OnExhausted: func(err error) { exhausted = true },
			}, nil, "test")
		require.NoError(t, err)
		assert.Equal(t, 42, out)
		assert.Equal(t, 1, calls)
		assert.False(t, compacted)
		assert.False(t, exhausted)
	})

	t.Run("recovery_succeeds", func(t *testing.T) {
		var calls int
		var compacted, exhausted bool
		out, err := RunPhaseAttempt(t.Context(),
			func(ctx context.Context) (int, error) {
				calls++
				if calls == 1 {
					return 0, errors.New("flake")
				}
				return 7, nil
			},
			PhaseRecover{
				Compact:     func() { compacted = true },
				OnExhausted: func(err error) { exhausted = true },
			}, nil, "test")
		require.NoError(t, err)
		assert.Equal(t, 7, out)
		assert.Equal(t, 2, calls)
		assert.True(t, compacted)
		assert.False(t, exhausted)
	})

	t.Run("exhausted_invokes_degrade", func(t *testing.T) {
		var calls int
		var gotErr error
		_, err := RunPhaseAttempt(t.Context(),
			func(ctx context.Context) (int, error) {
				calls++
				return 0, errors.New("persistent")
			},
			PhaseRecover{
				Compact:     func() {},
				OnExhausted: func(err error) { gotErr = err },
			}, nil, "test")
		require.Error(t, err)
		assert.Equal(t, 2, calls)
		assert.Equal(t, "persistent", gotErr.Error())
	})

	t.Run("ctx_error_propagates_no_retry", func(t *testing.T) {
		var calls int
		var compacted, exhausted bool
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // cancel before invocation so the first call returns ctx.Err()
		_, err := RunPhaseAttempt(ctx,
			func(ctx context.Context) (int, error) {
				calls++
				return 0, ctx.Err()
			},
			PhaseRecover{
				Compact:     func() { compacted = true },
				OnExhausted: func(err error) { exhausted = true },
			}, nil, "test")
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, calls)
		assert.False(t, compacted)
		assert.False(t, exhausted)
	})

	t.Run("nil_hooks_are_ok", func(t *testing.T) {
		var calls int
		_, err := RunPhaseAttempt(t.Context(),
			func(ctx context.Context) (int, error) {
				calls++
				return 0, errors.New("x")
			},
			PhaseRecover{},
			nil, "test")
		require.Error(t, err)
		assert.Equal(t, 2, calls)
	})
}
