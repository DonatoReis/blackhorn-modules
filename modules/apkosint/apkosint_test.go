package apkosint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/apkosint"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Transport that redirects Exodus API to test server ───────────────────────

type exodusTransport struct{ baseURL string }

func (t *exodusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := t.baseURL + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	req2, _ := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	for k, vs := range req.Header {
		for _, v := range vs {
			req2.Header.Add(k, v)
		}
	}
	return http.DefaultTransport.RoundTrip(req2)
}

func newModule(t *testing.T, srv *httptest.Server) *apkosint.Module {
	t.Helper()
	return apkosint.NewWithClient(&http.Client{Transport: &exodusTransport{baseURL: srv.URL}})
}

func findByType(findings []module.Finding, typ string) []module.Finding {
	var out []module.Finding
	for _, f := range findings {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

// ─── Fixtures ─────────────────────────────────────────────────────────────────

var exodusResult = map[string]any{
	"results": []map[string]any{
		{
			"name":         "WhatsApp",
			"creator":      "Meta Platforms",
			"handle":       "com.whatsapp",
			"version":      "2.24.1",
			"version_code": "240101",
			"downloads":    "5B+",
			"permissions": []string{
				"android.permission.CAMERA",
				"android.permission.RECORD_AUDIO",
				"android.permission.READ_CONTACTS",
				"android.permission.ACCESS_FINE_LOCATION",
				"android.permission.READ_SMS",
				"android.permission.READ_CALL_LOG",
			},
			"trackers": []map[string]any{
				{"id": 1, "name": "Facebook Analytics", "description": "Facebook crash analytics"},
				{"id": 2, "name": "Facebook Login", "description": "OAuth login"},
			},
			"score":   map[string]any{"score": 35.0},
			"updated": "2024-01-01",
		},
	},
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	if apkosint.New().Name() != "apkosint" {
		t.Error("expected name 'apkosint'")
	}
}

func TestEmptyTargetReturnsError(t *testing.T) {
	m := apkosint.New()
	_, err := m.Run(context.Background(), module.Input{Target: ""})
	if err == nil {
		t.Error("expected error for empty target")
	}
}

// TestPackageNameExtraction: various input formats.
func TestPackageNameExtraction(t *testing.T) {
	exodusBytes, _ := json.Marshal(map[string]any{"results": []any{}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(exodusBytes)
	}))
	defer srv.Close()

	targets := []struct {
		input string
		valid bool
	}{
		{"com.whatsapp", true},
		{"https://play.google.com/store/apps/details?id=com.whatsapp", true},
		{"com.example.myapp", true},
	}
	for _, tt := range targets {
		m := newModule(t, srv)
		_, err := m.Run(context.Background(), module.Input{
			Target:  tt.input,
			Options: map[string]string{"sources": "exodus"},
		})
		if tt.valid && err != nil {
			t.Errorf("Run(%q): unexpected error: %v", tt.input, err)
		}
	}
}

// TestInvalidTarget: plain string with no dots and no Play URL → error.
func TestInvalidTarget(t *testing.T) {
	m := apkosint.New()
	_, err := m.Run(context.Background(), module.Input{Target: "notapackage"})
	if err == nil {
		t.Error("expected error for target with no package name")
	}
}

// TestExodusAppInfoEmitted: valid Exodus response → apkosint_app_info finding.
func TestExodusAppInfoEmitted(t *testing.T) {
	exodusBytes, _ := json.Marshal(exodusResult)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(exodusBytes)
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "com.whatsapp",
		Options: map[string]string{"sources": "exodus"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	info := findByType(findings, "apkosint_app_info")
	if len(info) == 0 {
		t.Error("expected apkosint_app_info finding")
	}
	if info[0].Extra["name"] != "WhatsApp" {
		t.Errorf("unexpected app name: %q", info[0].Extra["name"])
	}
}

// TestTrackersFound: 2 trackers → 2 tracker findings.
func TestTrackersFound(t *testing.T) {
	exodusBytes, _ := json.Marshal(exodusResult)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(exodusBytes)
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "com.whatsapp",
		Options: map[string]string{"sources": "exodus"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	trackers := findByType(findings, "apkosint_tracker_found")
	if len(trackers) != 2 {
		t.Errorf("expected 2 tracker findings, got %d", len(trackers))
	}
}

// TestHighRiskPermissions: 6 high-risk permissions → 6 findings.
func TestHighRiskPermissions(t *testing.T) {
	exodusBytes, _ := json.Marshal(exodusResult)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(exodusBytes)
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "com.whatsapp",
		Options: map[string]string{"sources": "exodus"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	perms := findByType(findings, "apkosint_high_risk_permission")
	if len(perms) < 5 {
		t.Errorf("expected ≥5 high-risk permission findings, got %d", len(perms))
	}
	for _, f := range perms {
		if f.Severity != module.SeverityMedium {
			t.Errorf("high-risk permission should be Medium, got %v", f.Severity)
		}
	}
}

// TestExodusNotFound: 200 with empty results → not_found finding.
func TestExodusNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"results":[]}`))
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "com.unknown.app",
		Options: map[string]string{"sources": "exodus"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	notFound := findByType(findings, "apkosint_not_found")
	if len(notFound) == 0 {
		t.Error("expected apkosint_not_found for empty Exodus results")
	}
}

// TestExodusUnavailable: non-200 → apkosint_exodus_unavailable.
func TestExodusUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "com.example.app",
		Options: map[string]string{"sources": "exodus"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	unavail := findByType(findings, "apkosint_exodus_unavailable")
	if len(unavail) == 0 {
		t.Error("expected apkosint_exodus_unavailable for 503")
	}
}

// TestHighTrackerCount: 5 trackers → High severity.
func TestHighTrackerSeverityWith5Trackers(t *testing.T) {
	result := map[string]any{
		"results": []map[string]any{
			{
				"name": "SuspiciousApp", "creator": "BadCorp", "handle": "com.bad.app",
				"version": "1.0", "version_code": "1", "downloads": "1M+",
				"permissions": []string{},
				"trackers": []map[string]any{
					{"id": 1, "name": "T1", "description": "t1"},
					{"id": 2, "name": "T2", "description": "t2"},
					{"id": 3, "name": "T3", "description": "t3"},
					{"id": 4, "name": "T4", "description": "t4"},
					{"id": 5, "name": "T5", "description": "t5"},
				},
				"score":   map[string]any{"score": 20.0},
				"updated": "2024-01-01",
			},
		},
	}
	b, _ := json.Marshal(result)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(b)
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "com.bad.app",
		Options: map[string]string{"sources": "exodus"},
	})
	trackers := findByType(findings, "apkosint_tracker_found")
	for _, f := range trackers {
		if f.Severity != module.SeverityHigh {
			t.Errorf("5 trackers should produce High severity, got %v", f.Severity)
		}
	}
}

// TestConfidencePresent: all findings have confidence.
func TestConfidencePresent(t *testing.T) {
	exodusBytes, _ := json.Marshal(exodusResult)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(exodusBytes)
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "com.whatsapp",
		Options: map[string]string{"sources": "exodus"},
	})
	for _, f := range findings {
		if f.Extra == nil || f.Extra["confidence"] == "" {
			t.Errorf("finding %q missing confidence", f.Type)
		}
	}
}

// TestDeduplication: same finding type+URL should not appear twice.
func TestDeduplication(t *testing.T) {
	exodusBytes, _ := json.Marshal(exodusResult)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(exodusBytes)
	}))
	defer srv.Close()

	m := newModule(t, srv)
	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "com.whatsapp",
		Options: map[string]string{"sources": "exodus"},
	})
	seen := map[string]int{}
	for _, f := range findings {
		// Mesmo discriminador que dedup(): permission > tracker > cve > vazio.
		extra := ""
		if p := f.Extra["permission"]; p != "" {
			extra = p
		} else if tr := f.Extra["tracker"]; tr != "" {
			extra = tr
		} else if cve := f.Extra["cve"]; cve != "" {
			extra = cve
		}
		key := f.Type + "|" + f.URL + "|" + extra
		seen[key]++
		if seen[key] > 1 {
			t.Errorf("duplicate finding: %s", key)
		}
	}
}

// TestPlayStoreURLExtraction: Play Store URL → package name.
func TestPlayStoreURLExtraction(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(200)
		w.Write([]byte(`{"results":[]}`))
	}))
	defer srv.Close()

	m := newModule(t, srv)
	_, _ = m.Run(context.Background(), module.Input{
		Target:  "https://play.google.com/store/apps/details?id=com.example.app",
		Options: map[string]string{"sources": "exodus"},
	})
	if !strings.Contains(capturedPath, "com.example.app") {
		t.Errorf("expected Exodus to be called with package name in path, got %q", capturedPath)
	}
}
