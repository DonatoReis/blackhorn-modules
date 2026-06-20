// Package benchmarks provides performance benchmarks for blackhorn-modules.
//
// Run with:
//
//	go test -bench=. -benchmem -benchtime=5s ./benchmarks/
//
// Individual benchmarks:
//
//	go test -bench=BenchmarkURLDedup -benchmem ./benchmarks/
//	go test -bench=BenchmarkFingerprint -benchmem ./benchmarks/
//	go test -bench=BenchmarkTruffler -benchmem ./benchmarks/
package benchmarks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/bypass403"
	"github.com/DonatoReis/blackhorn-modules/modules/cacheprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/corsaudit"
	"github.com/DonatoReis/blackhorn-modules/modules/fingerprint"
	"github.com/DonatoReis/blackhorn-modules/modules/oauthprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/openredirect"
	"github.com/DonatoReis/blackhorn-modules/modules/truffler"
	"github.com/DonatoReis/blackhorn-modules/modules/urldedup"
	"github.com/DonatoReis/blackhorn-modules/modules/urlparse"
	"github.com/DonatoReis/blackhorn-modules/modules/vulnscan"
	"github.com/DonatoReis/blackhorn-modules/modules/xssreflect"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── urlparse ─────────────────────────────────────────────────────────────────

func BenchmarkURLParse_Single(b *testing.B) {
	m := urlparse.New()
	input := module.Input{URLs: []string{"https://api.example.com:8443/v2/users?page=1&limit=50#section"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

func BenchmarkURLParse_Bulk(b *testing.B) {
	m := urlparse.New()
	urls := make([]string, 100)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://sub%d.example.com/api/v1/resource/%d?id=%d&token=abc", i, i, i)
	}
	input := module.Input{URLs: urls}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

// ─── urldedup ─────────────────────────────────────────────────────────────────

func BenchmarkURLDedup_1000URLs(b *testing.B) {
	m := urldedup.New()
	urls := make([]string, 1000)
	for i := range urls {
		// Mix of dupes and unique.
		urls[i] = fmt.Sprintf("https://example.com/page?id=%d&sort=asc&token=abc%d", i%100, i%50)
	}
	input := module.Input{URLs: urls}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

// ─── fingerprint ──────────────────────────────────────────────────────────────

func BenchmarkFingerprint_Response(b *testing.B) {
	// Simulate a typical web server response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		w.Header().Set("X-Generator", "WordPress 6.4")
		w.Write([]byte(`<!DOCTYPE html><html><head>
<meta name="generator" content="WordPress 6.4">
<script src="/wp-includes/js/jquery/jquery.min.js"></script>
<link rel="stylesheet" href="/wp-content/themes/hello/style.css">
</head><body><div class="wp-block-group">Hello</div></body></html>`))
	}))
	defer srv.Close()

	m := fingerprint.New()
	input := module.Input{URLs: []string{srv.URL}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

// ─── truffler ─────────────────────────────────────────────────────────────────

func BenchmarkTruffler_RawContent_Small(b *testing.B) {
	m := truffler.New()
	content := `
# Config
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh
`
	input := module.Input{RawContent: content}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

func BenchmarkTruffler_RawContent_Large(b *testing.B) {
	m := truffler.New()
	// Simulate a large source file with occasional secrets.
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		sb.WriteString(fmt.Sprintf("// Line %d: some code here\n", i))
		if i%100 == 0 {
			sb.WriteString("const apiKey = \"AKIAIOSFODNN7EXAMPLE\"\n")
		}
	}
	input := module.Input{RawContent: sb.String()}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

// ─── corsaudit ────────────────────────────────────────────────────────────────

func BenchmarkCORSAudit(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := corsaudit.New()
	input := module.Input{Target: srv.URL}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

// ─── vulnscan ─────────────────────────────────────────────────────────────────

func BenchmarkVulnScan_BuiltinTemplates(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/config":
			w.WriteHeader(200)
			w.Write([]byte("[core]\nrepositoryformatversion = 0\n"))
		case "/.env":
			w.WriteHeader(200)
			w.Write([]byte("APP_KEY=base64:abc123\nDB_PASSWORD=secret\n"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	m := vulnscan.New()
	input := module.Input{Target: srv.URL}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

// ─── xssreflect ───────────────────────────────────────────────────────────────

func BenchmarkXSSReflect(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Write([]byte(fmt.Sprintf("<html><body><p>Search: %s</p></body></html>", q)))
	}))
	defer srv.Close()

	m := xssreflect.New()
	input := module.Input{URLs: []string{srv.URL + "?q=test"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

// ─── oauthprobe ───────────────────────────────────────────────────────────────

func BenchmarkOAuthProbe(b *testing.B) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "openid-configuration") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"issuer":"https://test.example.com",
				"authorization_endpoint":"https://test.example.com/authorize",
				"token_endpoint":"https://test.example.com/token",
				"response_types_supported":["code"],
				"code_challenge_methods_supported":["S256"]
			}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	m := oauthprobe.NewWithClient(srv.Client())
	input := module.Input{Target: srv.URL}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

// ─── cacheprobe ───────────────────────────────────────────────────────────────

func BenchmarkCacheProbe(b *testing.B) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "HIT")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(200)
		w.Write([]byte("cached content"))
	}))
	defer srv.Close()

	m := cacheprobe.NewWithClient(srv.Client())
	input := module.Input{Target: srv.URL}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}

// ─── bypass403 ───────────────────────────────────────────────────────────────

func BenchmarkBypass403_Probes(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		probes := bypass403.New() // just count probe generation cost
		_ = probes
	}
}

func BenchmarkBypass403_BuildProbes(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	// We can't call internal buildProbes from outside package,
	// but we benchmark the module creation (which is cheap).
	for i := 0; i < b.N; i++ {
		m := bypass403.New()
		_ = m
	}
}

// ─── openredirect ─────────────────────────────────────────────────────────────

func BenchmarkOpenRedirect_PayloadGeneration(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = openredirect.New()
	}
}

func BenchmarkOpenRedirect_Scan(b *testing.B) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		if strings.Contains(u, "canary") {
			http.Redirect(w, r, u, http.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := openredirect.NewWithClient(srv.Client())
	input := module.Input{Target: srv.URL + "?url=safe"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Run(context.Background(), input)
	}
}
