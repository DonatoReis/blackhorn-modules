// Package httpclient provides a shared, configurable HTTP client for all modules.
// Using a single factory avoids each module creating its own client with
// inconsistent timeouts, user-agents or proxy settings.
package httpclient

import (
	"net/http"
	"time"
)

const (
	DefaultTimeout   = 15 * time.Second
	DefaultUserAgent = "Mozilla/5.0 (compatible; BLACKHORN/1.0; +https://github.com/DonatoReis/blackhorn)"
)

// Options configures the HTTP client.
type Options struct {
	Timeout   time.Duration
	UserAgent string
	// ProxyURL string  // reserved for future use
}

// New returns an *http.Client configured with the given options.
// Redirects are followed up to 10 times by default.
func New(opts Options) *http.Client {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = false
	transport.MaxIdleConnsPerHost = 10

	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: &userAgentTransport{inner: transport, ua: opts.UserAgent},
	}
	return client
}

// Default returns an *http.Client with default settings.
func Default() *http.Client {
	return New(Options{})
}

// userAgentTransport injects a User-Agent header on every request.
type userAgentTransport struct {
	inner http.RoundTripper
	ua    string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ua := t.ua
	if ua == "" {
		ua = DefaultUserAgent
	}
	clone := req.Clone(req.Context())
	clone.Header.Set("User-Agent", ua)
	return t.inner.RoundTrip(clone)
}
