// Package urlutil provides shared URL helpers used across multiple modules.
package urlutil

import (
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const MaxURLLength = 4096

// Normalize returns the URL with the fragment stripped and the path cleaned.
// It returns the original string unchanged if parsing fails.
func Normalize(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	return u.String()
}

// CanonicalHTTP validates and canonicalizes an absolute HTTP(S) URL.
// It rejects credentials, invalid ports, control characters and malformed
// hostnames so passive-source artifacts cannot become active scan targets.
func CanonicalHTTP(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxURLLength {
		return "", false
	}
	if strings.IndexFunc(raw, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0 {
		return "", false
	}

	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}

	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !validHost(host) {
		return "", false
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			port = ""
		}
	}

	u.Scheme = scheme
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.Fragment = ""
	u.RawFragment = ""

	return u.String(), true
}

// NormalizeDomain extracts and validates a hostname from a domain or URL.
func NormalizeDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !validHost(host) {
		return ""
	}
	return host
}

// InDomainScope reports whether raw belongs to domain or one of its subdomains.
func InDomainScope(raw, domain string) bool {
	canonical, ok := CanonicalHTTP(raw)
	if !ok {
		return false
	}
	domain = NormalizeDomain(domain)
	if domain == "" {
		return false
	}
	u, err := url.Parse(canonical)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func validHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// Deduplicate removes exact duplicate strings from a slice while preserving
// insertion order.
func Deduplicate(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}

// SortedParams returns the query-parameter keys of u in sorted order.
// Useful for building a canonical representation of a URL pattern.
func SortedParams(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// PatternKey returns a string that identifies the "shape" of a URL:
// scheme + host + path + sorted param names (values stripped).
// Two URLs with the same PatternKey differ only in parameter values.
func PatternKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""

	params := SortedParams(raw)
	if len(params) == 0 {
		u.RawQuery = ""
		return u.String()
	}

	// rebuild query with empty values
	q := make(url.Values, len(params))
	for _, k := range params {
		q.Set(k, "")
	}
	u.RawQuery = strings.TrimRight(q.Encode(), "=&")
	return u.String()
}
