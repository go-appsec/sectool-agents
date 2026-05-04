package util

import (
	"net"
	"net/http"
	"time"
)

// sharedHTTPTransport is reused across every secagent HTTP client so connection
// pooling works as a single pool and any future Transport tuning lands once.
var sharedHTTPTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   10,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// noFollowRedirects surfaces redirects to the caller without auto-following.
// Auto-following risks SSRF amplification, credential leakage to redirected
// hosts, and unintended cross-origin behavior.
func noFollowRedirects(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// HTTPClient is the package-shared HTTP client. Callers control deadlines via
// context.Context; no whole-request Timeout is set so streaming reads aren't
// killed mid-response. Redirects are surfaced rather than followed.
var HTTPClient = &http.Client{
	Transport:     sharedHTTPTransport,
	CheckRedirect: noFollowRedirects,
}

// NewHTTPClientWithTimeout returns a client with a per-request Timeout, sharing
// the package Transport and redirect policy. Use only when integrating with a
// third-party SDK that reads http.Client.Timeout (e.g. go-openai); other
// callers should pass a deadline-bearing context to HTTPClient instead.
func NewHTTPClientWithTimeout(d time.Duration) *http.Client {
	return &http.Client{
		Transport:     sharedHTTPTransport,
		CheckRedirect: noFollowRedirects,
		Timeout:       d,
	}
}
