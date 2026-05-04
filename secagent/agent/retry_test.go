package agent

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		err     error
		wantCat ErrCategory
		wantRA  time.Duration
	}{
		{name: "nil", wantCat: ErrOther},
		{name: "canceled", err: context.Canceled, wantCat: ErrDeadline},
		{name: "deadline_exceeded", err: context.DeadlineExceeded, wantCat: ErrDeadline},
		{name: "wrapped_canceled", err: fmt.Errorf("op: %w", context.Canceled), wantCat: ErrDeadline},
		{name: "context_overflow_local", err: errors.New("context size has been exceeded"), wantCat: ErrContextOverflow},
		{name: "context_overflow_openai", err: errors.New("context_length_exceeded"), wantCat: ErrContextOverflow},
		{name: "context_overflow_max_length", err: errors.New("this model's maximum context length is 8192 tokens"), wantCat: ErrContextOverflow},
		{name: "context_overflow_window", err: errors.New("request exceeds context window"), wantCat: ErrContextOverflow},
		{name: "context_overflow_case_insensitive", err: errors.New("CONTEXT_LENGTH_EXCEEDED"), wantCat: ErrContextOverflow},
		{name: "rate_limit_apierr", err: &openai.APIError{HTTPStatusCode: 429, Message: "rate limited"}, wantCat: ErrRateLimit},
		{name: "rate_limit_retry_seconds", err: &openai.APIError{HTTPStatusCode: 429, Message: "slow down; retry after 7 seconds"}, wantCat: ErrRateLimit, wantRA: 7 * time.Second},
		{name: "rate_limit_retry_ms", err: &openai.APIError{HTTPStatusCode: 429, Message: "retry-after: 250ms"}, wantCat: ErrRateLimit, wantRA: 250 * time.Millisecond},
		{name: "request_err_wrapped", err: &openai.RequestError{HTTPStatusCode: 503, Err: errors.New("upstream")}, wantCat: ErrTransientNet},
		{name: "wrapped_apierror", err: fmt.Errorf("call: %w", &openai.APIError{HTTPStatusCode: 429, Message: ""}), wantCat: ErrRateLimit},
		{name: "server_5xx", err: &openai.APIError{HTTPStatusCode: 503, Message: "upstream"}, wantCat: ErrTransientNet},
		{name: "server_500_exact", err: &openai.APIError{HTTPStatusCode: 500, Message: ""}, wantCat: ErrTransientNet},
		{name: "model_error_400", err: &openai.APIError{HTTPStatusCode: 400, Message: "bad request"}, wantCat: ErrModelError},
		{name: "auth_error_401", err: &openai.APIError{HTTPStatusCode: 401, Message: "unauthorized"}, wantCat: ErrModelError},
		{name: "connection_reset", err: errors.New("read tcp: connection reset by peer"), wantCat: ErrTransientNet},
		{name: "connection_refused", err: errors.New("dial tcp: connection refused"), wantCat: ErrTransientNet},
		{name: "eof", err: errors.New("unexpected EOF"), wantCat: ErrTransientNet},
		{name: "broken_pipe", err: errors.New("write: broken pipe"), wantCat: ErrTransientNet},
		{name: "net_timeout", err: &fakeNetErr{timeout: true}, wantCat: ErrTransientNet},
		{name: "unknown_error", err: errors.New("something surprising"), wantCat: ErrOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotCat, gotRA := Classify(tc.err)
			assert.Equal(t, tc.wantCat, gotCat)
			assert.Equal(t, tc.wantRA, gotRA)
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		msg  string
		want time.Duration
	}{
		{name: "seconds_word", msg: "retry after 5 seconds", want: 5 * time.Second},
		{name: "second_singular", msg: "retry-after 1 second", want: 1 * time.Second},
		{name: "bare_s", msg: "retry-after: 3s", want: 3 * time.Second},
		{name: "no_unit_seconds", msg: "retry-after 12", want: 12 * time.Second},
		{name: "ms_unit", msg: "retry-after: 250ms", want: 250 * time.Millisecond},
		{name: "millis_alias", msg: "retry-after 500 millis", want: 500 * time.Millisecond},
		{name: "milliseconds_alias", msg: "retry-after 750 milliseconds", want: 750 * time.Millisecond},
		{name: "decimal_seconds", msg: "retry-after 1.5 seconds", want: 1500 * time.Millisecond},
		{name: "no_match", msg: "no hint here", want: 0},
		{name: "zero_ignored", msg: "retry-after 0", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseRetryAfter(tc.msg))
		})
	}
}

func TestBackoffFor_RateLimitRetryAfter(t *testing.T) {
	t.Parallel()

	got := BackoffFor(ErrRateLimit, 0, 500*time.Millisecond, time.Second, rand.New(rand.NewSource(1)))
	assert.Equal(t, 500*time.Millisecond, got)
}

func TestBackoffFor_NonRetryable(t *testing.T) {
	t.Parallel()

	cats := []ErrCategory{ErrOther, ErrDeadline, ErrContextOverflow, ErrModelError}
	for _, cat := range cats {
		t.Run(fmt.Sprintf("category_%d", cat), func(t *testing.T) {
			got := BackoffFor(cat, 0, 0, time.Second, rand.New(rand.NewSource(1)))
			assert.Zero(t, got)
		})
	}
}

func TestBackoffFor_JitteredExponential(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		cat     ErrCategory
		attempt int
		base    time.Duration
		wantMin time.Duration
		wantMax time.Duration
	}{
		// attempt 2: base * 2^2 = 400ms before jitter; jitter +/-20% -> [320ms, 480ms)
		{name: "rate_limit_no_hint", cat: ErrRateLimit, attempt: 2, base: 100 * time.Millisecond,
			wantMin: 320 * time.Millisecond, wantMax: 480 * time.Millisecond},
		// attempt 0: base * 2^0 = 200ms before jitter -> [160ms, 240ms)
		{name: "transient_attempt_zero", cat: ErrTransientNet, base: 200 * time.Millisecond,
			wantMin: 160 * time.Millisecond, wantMax: 240 * time.Millisecond},
		// attempt 20: exponential capped at 30s, then jittered +/-20% -> [24s, 36s)
		{name: "transient_capped", cat: ErrTransientNet, attempt: 20, base: time.Second,
			wantMin: 24 * time.Second, wantMax: 36 * time.Second},
		// rate-limit cap is 60s; attempt 20 saturates and jitters -> [48s, 72s)
		{name: "rate_limit_capped", cat: ErrRateLimit, attempt: 20, base: time.Second,
			wantMin: 48 * time.Second, wantMax: 72 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BackoffFor(tc.cat, tc.attempt, 0, tc.base, rand.New(rand.NewSource(1)))
			assert.GreaterOrEqual(t, got, tc.wantMin)
			assert.Less(t, got, tc.wantMax)
		})
	}
}

// fakeNetErr implements net.Error so Classify exercises the timeout branch.
type fakeNetErr struct {
	timeout bool
}

func (e *fakeNetErr) Error() string   { return "fake net error" }
func (e *fakeNetErr) Timeout() bool   { return e.timeout }
func (e *fakeNetErr) Temporary() bool { return false }

var _ net.Error = (*fakeNetErr)(nil)
