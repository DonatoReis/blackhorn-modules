package urlutil

import "testing"

func TestCanonicalHTTP(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "canonical", raw: "HTTPS://Example.COM:443/a#fragment", want: "https://example.com/a", ok: true},
		{name: "ipv6", raw: "http://[2001:db8::1]:8080/a", want: "http://[2001:db8::1]:8080/a", ok: true},
		{name: "credentials", raw: "https://user:pass@example.com/a", ok: false},
		{name: "space", raw: "https://example.com/a b", ok: false},
		{name: "empty label", raw: "https://www..example.com/a", ok: false},
		{name: "bad label", raw: "https://-api.example.com/a", ok: false},
		{name: "bad port", raw: "https://example.com:70000/a", ok: false},
		{name: "unsupported scheme", raw: "javascript:alert(1)", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := CanonicalHTTP(tt.raw)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("CanonicalHTTP(%q) = (%q, %v), want (%q, %v)", tt.raw, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	if got := NormalizeDomain("https://API.Example.com/path?q=1"); got != "api.example.com" {
		t.Fatalf("NormalizeDomain returned %q", got)
	}
	if got := NormalizeDomain("www..example.com"); got != "" {
		t.Fatalf("expected invalid domain to be rejected, got %q", got)
	}
}

func TestInDomainScope(t *testing.T) {
	if !InDomainScope("https://api.example.com/v1", "example.com") {
		t.Fatal("expected subdomain URL to be in scope")
	}
	if InDomainScope("https://example.com.attacker.test/v1", "example.com") {
		t.Fatal("expected suffix-confusion URL to be out of scope")
	}
}
