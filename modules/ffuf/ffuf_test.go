package ffuf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasType(findings []module.Finding, t string) bool {
	for _, f := range findings {
		if f.Type == t {
			return true
		}
	}
	return false
}

func hasURL(findings []module.Finding, suffix string) bool {
	for _, f := range findings {
		if strings.HasSuffix(f.URL, suffix) {
			return true
		}
	}
	return false
}

func hasWord(findings []module.Finding, word string) bool {
	for _, f := range findings {
		if f.Extra["word"] == word {
			return true
		}
	}
	return false
}

// routedSrv returns a test server that responds 200 to the listed paths
// and 404 to everything else.
func routedSrv(t *testing.T, paths ...string) *httptest.Server {
	t.Helper()
	set := make(map[string]bool)
	for _, p := range paths {
		set["/"+strings.TrimPrefix(p, "/")] = true
	}
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if set[r.URL.Path] {
			fmt.Fprintln(w, "found: "+r.URL.Path)
			return
		}
		http.NotFound(w, r)
	}))
}

// ─── basic ───────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if New().Name() != "ffuf" {
		t.Fatal("wrong name")
	}
}

func TestRun_NoTarget(t *testing.T) {
	_, err := New().Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// ─── directory fuzzing ────────────────────────────────────────────────────────

func TestDirFuzz_Hit(t *testing.T) {
	srv := routedSrv(t, "/admin", "/login")
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Mode = ModeDir
	m.Filter = Filter{FilterCodes: []int{404}}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "admin\nlogin\nnoexist"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "fuzzing_hit") {
		t.Fatal("expected fuzzing_hit findings")
	}
	if !hasWord(findings, "admin") {
		t.Fatal("expected word=admin in findings")
	}
	if !hasWord(findings, "login") {
		t.Fatal("expected word=login in findings")
	}
	if hasWord(findings, "noexist") {
		t.Fatal("noexist should not be in findings (404)")
	}
}

func TestDirFuzz_AllMiss(t *testing.T) {
	srv := routedSrv(t) // nothing returns 200
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Mode = ModeDir
	m.Filter = Filter{FilterCodes: []int{404}}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "admin\nlogin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestDirFuzz_Dedup(t *testing.T) {
	srv := routedSrv(t, "/admin")
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Mode = ModeDir
	m.Filter = Filter{FilterCodes: []int{404}}

	// Wordlist with repeated entry.
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "admin\nadmin\nadmin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range findings {
		if f.Extra["word"] == "admin" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 deduplicated admin finding, got %d", count)
	}
}

// ─── match / filter codes ─────────────────────────────────────────────────────

func TestMatchCodes_Option(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(200)
		case "/redir":
			w.WriteHeader(301)
		case "/forbidden":
			w.WriteHeader(403)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL,
		Options: map[string]string{
			"wordlist":     "ok\nredir\nforbidden\nnone",
			"match_codes":  "200,403",
			"filter_codes": "",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWord(findings, "ok") {
		t.Fatal("expected ok (200) with match_codes=200,403")
	}
	if !hasWord(findings, "forbidden") {
		t.Fatal("expected forbidden (403) with match_codes=200,403")
	}
	if hasWord(findings, "redir") {
		t.Fatal("redir (301) should be excluded with match_codes=200,403")
	}
	if hasWord(findings, "none") {
		t.Fatal("none (404) should be excluded with match_codes=200,403")
	}
}

func TestFilterCodes_Option(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exists":
			w.WriteHeader(200)
		case "/redirect":
			w.WriteHeader(301)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	// Only filter 404 (default behavior basically).
	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL,
		Options: map[string]string{
			"wordlist":     "exists\nredirect\nnothing",
			"filter_codes": "404",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWord(findings, "exists") {
		t.Fatal("expected exists (200) to pass filter")
	}
	if !hasWord(findings, "redirect") {
		t.Fatal("expected redirect (301) to pass filter when only 404 is filtered")
	}
	if hasWord(findings, "nothing") {
		t.Fatal("nothing (404) should be filtered")
	}
}

// ─── severity ────────────────────────────────────────────────────────────────

func TestSeverity_500IsHigh(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		fmt.Fprintln(w, "server error")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Filter = Filter{} // accept all
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "crash"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for 500")
	}
	for _, f := range findings {
		if f.Extra["word"] == "crash" && f.Severity != module.SeverityHigh {
			t.Errorf("expected High severity for 500 response, got %q", f.Severity)
		}
	}
}

func TestSeverity_200IsMedium(t *testing.T) {
	srv := routedSrv(t, "/test")
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Filter = Filter{FilterCodes: []int{404}}
	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Extra["word"] == "test" && f.Severity != module.SeverityMedium {
			t.Errorf("expected Medium severity for 200 response, got %q", f.Severity)
		}
	}
}

// ─── vhost fuzzing ────────────────────────────────────────────────────────────

func TestVhostFuzz_Hit(t *testing.T) {
	// Vhost mode sets req.Host to "word.basehost". The underlying TLS dial still
	// connects to 127.0.0.1 (from the URL), so the TLS handshake succeeds — only
	// the HTTP Host header changes. The server distinguishes by the first label.
	var mu sync.Mutex
	seenHosts := []string{}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenHosts = append(seenHosts, r.Host)
		mu.Unlock()
		// Return 404 for "blocked.*", 200 for everything else.
		prefix := r.Host
		if i := strings.Index(r.Host, "."); i >= 0 {
			prefix = r.Host[:i]
		}
		if prefix == "blocked" {
			w.WriteHeader(404)
			return
		}
		fmt.Fprintln(w, "vhost found")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Mode = ModeVhost
	m.Filter = Filter{FilterCodes: []int{404}}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "dev\nblocked"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// At least one probe must have gone through (soft-fail on TLS error is OK,
	// but if the server received requests, findings should reflect the 200 ones).
	mu.Lock()
	got := seenHosts
	mu.Unlock()
	if len(got) == 0 {
		// TLS rejected all connections — skip gracefully (CI/Mac TLS variance).
		t.Skip("TLS server rejected all vhost probes — skipping in this environment")
	}
	if !hasWord(findings, "dev") {
		t.Fatalf("expected dev vhost finding; seen hosts: %v", got)
	}
	if hasWord(findings, "blocked") {
		t.Fatal("blocked should return 404 and be filtered")
	}
}

// ─── query fuzzing ────────────────────────────────────────────────────────────

func TestQueryFuzz_Hit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			fmt.Fprintln(w, "param accepted")
			return
		}
		w.WriteHeader(400)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Mode = ModeQuery
	m.Filter = Filter{FilterCodes: []int{400, 404}}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "id\nuser\nfile"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "fuzzing_hit") {
		t.Fatal("expected fuzzing_hit from query mode")
	}
}

// ─── body fuzzing ─────────────────────────────────────────────────────────────

func TestBodyFuzz_Hit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Fprintln(w, "POST accepted")
			return
		}
		w.WriteHeader(405)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Mode = ModeBody
	m.Filter = Filter{FilterCodes: []int{405, 404}}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "admin\nroot"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "fuzzing_hit") {
		t.Fatal("expected fuzzing_hit from body mode")
	}
}

// ─── custom_fuzz ─────────────────────────────────────────────────────────────

func TestCustomFuzz_URLTemplate(t *testing.T) {
	srv := routedSrv(t, "/test.php")
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Filter = Filter{FilterCodes: []int{404}}

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL,
		Options: map[string]string{
			"wordlist":    "test\nother",
			"custom_fuzz": srv.URL + "/FUZZ.php",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWord(findings, "test") {
		t.Fatal("expected test.php hit with custom_fuzz template")
	}
}

// ─── redirect detection ───────────────────────────────────────────────────────

func TestRedirect_Captured(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "https://other.com/", http.StatusMovedPermanently)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Mode = ModeDir
	m.Filter = Filter{} // accept all codes including 301
	m.FollowRedirects = false

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "redir"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Extra["word"] == "redir" {
			if f.Extra["redirect"] == "" {
				t.Fatal("expected redirect location in Extra")
			}
			return
		}
	}
	t.Fatal("expected redir finding with redirect captured")
}

// ─── extra headers ────────────────────────────────────────────────────────────

func TestCustomHeaders_Sent(t *testing.T) {
	var gotToken string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Custom-Token")
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Mode = ModeDir
	m.Filter = Filter{FilterCodes: []int{404}}
	m.Headers = map[string]string{"X-Custom-Token": "secret123"}

	_, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "probe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != "secret123" {
		t.Fatalf("expected X-Custom-Token=secret123, got %q", gotToken)
	}
}

// ─── mode via Options ─────────────────────────────────────────────────────────

func TestModeOption_Overrides(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			fmt.Fprintln(w, "param accepted")
		} else {
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Mode = ModeDir // default — will be overridden
	m.Filter = Filter{FilterCodes: []int{400, 404}}

	findings, err := m.Run(context.Background(), module.Input{
		Target: srv.URL,
		Options: map[string]string{
			"mode":     "query",
			"wordlist": "id",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(findings, "fuzzing_hit") {
		t.Fatal("expected mode option to switch to query mode")
	}
}

// ─── filter helpers ───────────────────────────────────────────────────────────

func TestFilter_SizeRange(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/small":
			fmt.Fprint(w, "a")
		case "/large":
			fmt.Fprint(w, strings.Repeat("a", 1000))
		}
	}))
	defer srv.Close()

	m := NewWithClient(srv.Client())
	m.Mode = ModeDir
	m.Filter = Filter{MinSize: 100, MaxSize: 2000}

	findings, err := m.Run(context.Background(), module.Input{
		Target:  srv.URL,
		Options: map[string]string{"wordlist": "small\nlarge"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasWord(findings, "small") {
		t.Fatal("small response should be filtered by MinSize=100")
	}
	if !hasWord(findings, "large") {
		t.Fatal("large response should pass filter")
	}
}

// ─── built-in wordlists ───────────────────────────────────────────────────────

func TestBuiltinWordlist_Dir_NotEmpty(t *testing.T) {
	wl := builtinWordlist(ModeDir)
	if len(wl) < 50 {
		t.Fatalf("expected at least 50 built-in dir words, got %d", len(wl))
	}
}

func TestBuiltinWordlist_Vhost_NotEmpty(t *testing.T) {
	wl := builtinWordlist(ModeVhost)
	if len(wl) < 10 {
		t.Fatalf("expected at least 10 built-in vhost words, got %d", len(wl))
	}
}

func TestBuiltinWordlist_Params_NotEmpty(t *testing.T) {
	wl := builtinWordlist(ModeQuery)
	if len(wl) < 10 {
		t.Fatalf("expected at least 10 built-in param words, got %d", len(wl))
	}
}

// ─── helpers unit tests ───────────────────────────────────────────────────────

func TestCountWords(t *testing.T) {
	if n := countWords([]byte("hello world\nfoo")); n != 3 {
		t.Fatalf("expected 3 words, got %d", n)
	}
}

func TestCountLines(t *testing.T) {
	if n := countLines([]byte("a\nb\nc")); n != 3 {
		t.Fatalf("expected 3 lines, got %d", n)
	}
	if n := countLines(nil); n != 0 {
		t.Fatalf("expected 0 for empty, got %d", n)
	}
}

func TestParseCodes(t *testing.T) {
	codes := parseCodes("200, 301, 403")
	if len(codes) != 3 {
		t.Fatalf("expected 3 codes, got %d: %v", len(codes), codes)
	}
}

func TestParseWordlist(t *testing.T) {
	words := parseWordlist("admin\n# comment\nlogin\n\ntest\n")
	if len(words) != 3 {
		t.Fatalf("expected 3 words (comments+blanks stripped), got %d: %v", len(words), words)
	}
}

func TestDedupFindings(t *testing.T) {
	ff := []module.Finding{
		{Type: "fuzzing_hit", URL: "https://x.com/admin"},
		{Type: "fuzzing_hit", URL: "https://x.com/admin"},
		{Type: "fuzzing_hit", URL: "https://x.com/login"},
	}
	got := dedupFindings(ff)
	if len(got) != 2 {
		t.Fatalf("expected 2 after dedup, got %d", len(got))
	}
}

func TestHostFromURL(t *testing.T) {
	if h := hostFromURL("https://example.com:8080/path"); h != "example.com" {
		t.Fatalf("expected example.com, got %q", h)
	}
}

func TestBuildRequest_Dir(t *testing.T) {
	u, method, body := buildRequest("https://example.com", "admin", ModeDir, "", "")
	if u != "https://example.com/admin" {
		t.Fatalf("unexpected URL: %q", u)
	}
	if method != http.MethodGet {
		t.Fatalf("expected GET, got %q", method)
	}
	if body != "" {
		t.Fatal("expected no body for dir mode")
	}
}

func TestBuildRequest_Body(t *testing.T) {
	u, method, body := buildRequest("https://example.com/login", "admin", ModeBody, "user=FUZZ", "")
	if u != "https://example.com/login" {
		t.Fatalf("unexpected URL: %q", u)
	}
	if method != http.MethodPost {
		t.Fatalf("expected POST, got %q", method)
	}
	if !strings.Contains(body, "admin") {
		t.Fatalf("expected body to contain 'admin', got: %q", body)
	}
}
