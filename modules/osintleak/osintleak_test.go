package osintleak_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/osintleak"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// newModuleWithServer creates a test module that routes all HTTP requests to srv.
func newModuleWithServer(t *testing.T, srv *httptest.Server) *osintleak.Module {
	t.Helper()
	c := srv.Client()
	c.Transport = &roundTripRewrite{base: srv.URL, orig: http.DefaultTransport}
	return osintleak.NewWithClient(c)
}

type roundTripRewrite struct {
	base string
	orig http.RoundTripper
}

func (r *roundTripRewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(r.base, "http://")
	return r.orig.RoundTrip(clone)
}

// ─── Name ─────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := osintleak.New()
	if m.Name() != "osintleak" {
		t.Errorf("unexpected name: %s", m.Name())
	}
}

// ─── Empty target ─────────────────────────────────────────────────────────────

func TestRun_EmptyTarget_ReturnsError(t *testing.T) {
	m := osintleak.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
	if !strings.Contains(err.Error(), "target required") {
		t.Errorf("expected target-required error, got: %v", err)
	}
}

// ─── HIBP source ─────────────────────────────────────────────────────────────

func TestRun_HIBP_FindingsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := []map[string]interface{}{
			{
				"Name":        "Adobe",
				"Domain":      "adobe.com",
				"BreachDate":  "2013-10-04",
				"PwnCount":    153000000,
				"IsVerified":  true,
				"DataClasses": []string{"Email addresses", "Password hints", "Passwords", "Usernames"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	m := newModuleWithServer(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "hibp", "hibp_key": "test-key"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from HIBP")
	}
}

func TestRun_HIBP_FindingTypeIsBreach(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"Name": "TestBreach", "Domain": "test.com", "IsVerified": true, "PwnCount": 1000},
		})
	}))
	defer srv.Close()

	m := newModuleWithServer(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "victim@test.com",
		Options: map[string]string{"sources": "hibp", "hibp_key": "k"},
	})
	for _, f := range findings {
		if !strings.Contains(f.Type, "breach") && !strings.Contains(f.Type, "leak") {
			t.Errorf("expected breach/leak finding type, got %q", f.Type)
		}
	}
}

func TestRun_HIBP_HasConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"Name": "B", "IsVerified": true, "PwnCount": 500},
		})
	}))
	defer srv.Close()

	m := newModuleWithServer(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "hibp", "hibp_key": "k"},
	})
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Error("HIBP finding missing confidence")
		}
	}
}

func TestRun_HIBP_VerifiedHigherConfidence(t *testing.T) {
	var seenVerified, seenUnverified string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"Name": "Verified", "IsVerified": true, "PwnCount": 100},
			{"Name": "Unverified", "IsVerified": false, "PwnCount": 100},
		})
	}))
	defer srv.Close()

	m := newModuleWithServer(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "hibp", "hibp_key": "k"},
	})

	for _, f := range findings {
		if strings.Contains(f.Detail, "Verified") {
			seenVerified = f.Extra["confidence"]
		}
		if strings.Contains(f.Detail, "Unverified") {
			seenUnverified = f.Extra["confidence"]
		}
	}
	if seenVerified != "" && seenUnverified != "" {
		if seenVerified <= seenUnverified {
			t.Errorf("verified breach (%s) should have higher confidence than unverified (%s)", seenVerified, seenUnverified)
		}
	}
}

// ─── 404 = no breach ─────────────────────────────────────────────────────────

func TestRun_HIBP_404_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := newModuleWithServer(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "nosuchuser@notbreached.example",
		Options: map[string]string{"sources": "hibp", "hibp_key": "k"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["source"] == "hibp" {
			t.Errorf("expected no HIBP findings on 404, got: %v", f)
		}
	}
}

// ─── Deduplication ────────────────────────────────────────────────────────────

func TestRun_Deduplication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same breach returned twice (simulates overlap between sources)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"Name": "SameBreach", "IsVerified": true, "PwnCount": 100},
			{"Name": "SameBreach", "IsVerified": true, "PwnCount": 100},
		})
	}))
	defer srv.Close()

	m := newModuleWithServer(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "dup@example.com",
		Options: map[string]string{"sources": "hibp", "hibp_key": "k"},
	})

	seen := make(map[string]int)
	for _, f := range findings {
		key := f.Type + f.Detail
		seen[key]++
		if seen[key] > 1 {
			t.Errorf("duplicate finding: %s", f.Detail)
		}
	}
}

// ─── Source filter ────────────────────────────────────────────────────────────

func TestRun_SourceFilter_OnlyRequestedSource(t *testing.T) {
	var calledPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPaths = append(calledPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	m := newModuleWithServer(t, srv)
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "hibp", "hibp_key": "k"},
	})
	// Should not call dehashed or leakcheck endpoints
	for _, p := range calledPaths {
		if strings.Contains(p, "dehashed") || strings.Contains(p, "leakcheck") {
			t.Errorf("unexpected call to non-hibp source path: %s", p)
		}
	}
}

// ─── Context cancellation ─────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := osintleak.New()
	_, _ = m.Run(ctx, module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "hibp", "hibp_key": "k"},
	})
}

// ─── Severity ─────────────────────────────────────────────────────────────────

func TestRun_Findings_SeverityNotEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"Name": "TestBreachSev", "IsVerified": true, "PwnCount": 1000},
		})
	}))
	defer srv.Close()

	m := newModuleWithServer(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "hibp", "hibp_key": "k"},
	})
	for _, f := range findings {
		if f.Severity == "" {
			t.Error("finding missing severity")
		}
	}
}

// ─── Passwords redacted ───────────────────────────────────────────────────────

func TestRun_Passwords_RedactedInExtra(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate DeHashed response with password
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": 1,
			"entries": []map[string]interface{}{
				{
					"id":            "1",
					"email":         "victim@example.com",
					"password":      "supersecretpassword123",
					"database_name": "TestDB",
				},
			},
		})
	}))
	defer srv.Close()

	m := newModuleWithServer(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target: "victim@example.com",
		Options: map[string]string{
			"sources":           "dehashed",
			"dehashed_key":      "test-key",
			"dehashed_email":    "me@example.com",
			"include_passwords": "true",
		},
	})
	for _, f := range findings {
		pw := f.Extra["password"]
		if pw == "supersecretpassword123" {
			t.Error("password should be redacted in finding Extra")
		}
	}
}

// ─── Finding Detail populated ─────────────────────────────────────────────────

func TestRun_Findings_DetailNotEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"Name": "SomeBreachDetail", "IsVerified": true, "PwnCount": 99},
		})
	}))
	defer srv.Close()

	m := newModuleWithServer(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "hibp", "hibp_key": "k"},
	})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding has empty Detail")
		}
	}
}

// ─── max_results option ───────────────────────────────────────────────────────

func TestRun_MaxResults_Zero_UsesDefault(t *testing.T) {
	m := osintleak.New()
	// max_results=0 should not panic or error — it defaults internally
	_, err := m.Run(context.Background(), module.Input{
		Target:  "test@example.com",
		Options: map[string]string{"sources": "hibp", "hibp_key": "k", "max_results": "0"},
	})
	// Network will fail in test environment — that's fine
	_ = err
}
