package agent

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"regexp"
	"slices"
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
	// zero-choice payload from the provider, retry like any other transient hiccup
	if errors.Is(err, ErrEmptyChoices) {
		return ErrTransientNet, 0
	}

	// HTTP status is decisive for HTTP-shaped errors; overflow markers are
	// only consulted inside classifyHTTPStatus so an unrelated 4xx message
	// mentioning context cannot trigger the destructive truncation fast-path
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

	// status-less upstream context-overflow rejection, tight markers only
	if isOverflowMessage(err.Error()) {
		return ErrContextOverflow, 0
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
		// only explicit overflow-shaped 4xx rejections count as overflow
		if isOverflowMessage(message) {
			return ErrContextOverflow, 0
		}
		return ErrModelError, 0
	}
	return ErrOther, 0
}

// overflowMarkers are the unambiguous provider phrases identifying a
// context-length rejection. Loose phrases like "context window" are
// intentionally excluded so unrelated error messages cannot trigger the
// destructive truncation fast-path.
var overflowMarkers = []string{
	"context_length_exceeded",
	"maximum context length",
	"context size has been exceeded",
}

// isOverflowMessage reports whether msg carries an explicit context-length rejection.
func isOverflowMessage(msg string) bool {
	msg = strings.ToLower(msg)
	return slices.ContainsFunc(overflowMarkers, func(marker string) bool {
		return strings.Contains(msg, marker)
	})
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
// 0-indexed attempt. retryAfter is the endpoint Retry-After hint (0 when
// absent). maxWait caps the result when positive. rng may be nil to use
// package-level randomness.
func BackoffFor(cat ErrCategory, attempt int, retryAfter, base, maxWait time.Duration, rng *rand.Rand) time.Duration {
	var d time.Duration
	switch cat {
	case ErrRateLimit:
		if retryAfter > 0 {
			d = retryAfter
		} else {
			d = jitter(expBackoff(base, attempt, 60*time.Second), rng)
		}
	case ErrTransientNet:
		d = jitter(expBackoff(base, attempt, 30*time.Second), rng)
	}
	return clampWait(d, maxWait)
}

// clampWait caps d at maxWait when maxWait is positive.
func clampWait(d, maxWait time.Duration) time.Duration {
	if maxWait > 0 && d > maxWait {
		return maxWait
	}
	return d
}

func expBackoff(base time.Duration, attempt int, cap time.Duration) time.Duration {
	if base <= 0 {
		base = 2 * time.Second
	}
	d := base
	for i := 0; i < attempt && d < cap; i++ {
		d *= 2
	}
	if d > cap || d <= 0 { // d <= 0 guards duration overflow
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
