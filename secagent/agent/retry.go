package agent

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sashabaranov/go-openai"
)

// ErrCategory classifies an error for retry policy.
type ErrCategory int

const (
	// ErrOther propagates without retry. Unknown / ambiguous errors.
	ErrOther ErrCategory = iota
	// ErrDeadline is ctx.Canceled or ctx.DeadlineExceeded. Never retry.
	ErrDeadline
	// ErrContextOverflow is the upstream model rejecting for context-length.
	// Handled by the in-flight hard-truncate fast-path, not by retry.
	ErrContextOverflow
	// ErrRateLimit is a 429. Honor Retry-After when present.
	ErrRateLimit
	// ErrTransientNet is 5xx, net timeout, or connection reset. Retry with exponential backoff + jitter.
	ErrTransientNet
	// ErrModelError is a non-overflow 4xx (bad request, auth, invalid params). Propagate; retrying won't fix it.
	ErrModelError
)

// Classify returns err's retry category and the hinted Retry-After duration (0 when none is available).
func Classify(err error) (ErrCategory, time.Duration) {
	if err == nil {
		return ErrOther, 0
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrDeadline, 0
	}
	// upstream context-overflow rejection
	emsg := strings.ToLower(err.Error())
	if strings.Contains(emsg, "context size has been exceeded") ||
		strings.Contains(emsg, "context_length_exceeded") ||
		strings.Contains(emsg, "maximum context length") ||
		strings.Contains(emsg, "context window") {
		return ErrContextOverflow, 0
	}

	// HTTP-shaped errors from go-openai
	var apiErr *openai.APIError
	if errors.As(err, &apiErr) {
		return classifyHTTPStatus(apiErr.HTTPStatusCode, apiErr.Message)
	}
	var reqErr *openai.RequestError
	if errors.As(err, &reqErr) {
		var body string
		if reqErr.Err != nil {
			body = reqErr.Err.Error()
		}
		return classifyHTTPStatus(reqErr.HTTPStatusCode, body)
	}

	// Network-shaped errors
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrTransientNet, 0
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "eof") ||
		strings.Contains(msg, "broken pipe") {
		return ErrTransientNet, 0
	}
	return ErrOther, 0
}

func classifyHTTPStatus(status int, message string) (ErrCategory, time.Duration) {
	switch {
	case status == 429:
		return ErrRateLimit, parseRetryAfter(message)
	case status >= 500:
		return ErrTransientNet, 0
	case status >= 400:
		return ErrModelError, 0
	}
	return ErrOther, 0
}

var retryAfterRe = regexp.MustCompile(`(?i)retry[- ]after[^0-9]{0,10}(\d+(?:\.\d+)?)\s*(s|sec|second|seconds|ms|millis|milliseconds)?`)

// parseRetryAfter scrapes a Retry-After hint from message. Handles integer
// or decimal seconds and the "ms" suffix. Returns 0 when nothing parses.
func parseRetryAfter(message string) time.Duration {
	m := retryAfterRe.FindStringSubmatch(message)
	if len(m) < 2 {
		return 0
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil || n <= 0 {
		return 0
	}
	unit := strings.ToLower(m[2])
	if unit == "ms" || unit == "millis" || unit == "milliseconds" {
		return time.Duration(n * float64(time.Millisecond))
	}
	return time.Duration(n * float64(time.Second))
}

// BackoffFor returns the wait time for retry category cat at the
// 0-indexed attempt. rng may be nil to use package-level randomness.
func BackoffFor(cat ErrCategory, attempt int, retryAfter, base time.Duration, rng *rand.Rand) time.Duration {
	switch cat {
	case ErrRateLimit:
		if retryAfter > 0 {
			return retryAfter
		}
		return jitter(expBackoff(base, attempt, 60*time.Second), rng)
	case ErrTransientNet:
		return jitter(expBackoff(base, attempt, 30*time.Second), rng)
	default:
		return 0
	}
}

func expBackoff(base time.Duration, attempt int, cap time.Duration) time.Duration {
	if base <= 0 {
		base = 2 * time.Second
	}
	d := time.Duration(float64(base) * math.Pow(2, float64(attempt)))
	if d > cap {
		return cap
	}
	return d
}

// jitter returns d with +/-20% jitter applied. rng may be nil.
func jitter(d time.Duration, rng *rand.Rand) time.Duration {
	if d <= 0 {
		return d
	}
	var r float64
	if rng != nil {
		r = rng.Float64()
	} else {
		r = rand.Float64() //nolint:gosec // jitter, not crypto
	}
	factor := 0.8 + 0.4*r // [0.8, 1.2)
	return time.Duration(float64(d) * factor)
}
