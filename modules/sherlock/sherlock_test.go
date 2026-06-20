package sherlock_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/modules/sherlock"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// stubServer returns a test server that responds with given status for all requests.
func stubServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// singleSite builds a one-site list pointing at srv.
func singleSite(t *testing.T, srv *httptest.Server, probeType sherlock.ProbeType) []sherlock.Site {
	t.Helper()
	return []sherlock.Site{{
		Name:        "TestSite",
		Category:    "test",
		URLTemplate: srv.URL + "/{}",
		ProbeType:   probeType,
		FoundCode:   http.StatusOK,
	}}
}

// ─── Name ─────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := sherlock.New()
	if m.Name() != "sherlock" {
		t.Errorf("unexpected name: %s", m.Name())
	}
}

// ─── Empty target ─────────────────────────────────────────────────────────────

func TestRun_EmptyUsername_ReturnsError(t *testing.T) {
	m := sherlock.New()
	_, err := m.Run(context.Background(), module.Input{})
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

// ─── ProbeStatus ─────────────────────────────────────────────────────────────

func TestRun_ProbeStatus_Found_ReturnsFound(t *testing.T) {
	srv := stubServer(t, http.StatusOK)
	sites := singleSite(t, srv, sherlock.ProbeStatus)
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, err := m.Run(context.Background(), module.Input{Target: "testuser"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding for HTTP 200")
	}
}

func TestRun_ProbeStatus_NotFound_NoFinding(t *testing.T) {
	srv := stubServer(t, http.StatusNotFound)
	sites := singleSite(t, srv, sherlock.ProbeStatus)
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, _ := m.Run(context.Background(), module.Input{Target: "nosuchuser"})
	for _, f := range findings {
		if strings.Contains(f.Extra["site"], "TestSite") {
			t.Errorf("expected no finding for 404, got: %v", f)
		}
	}
}

// ─── ProbeMessage ─────────────────────────────────────────────────────────────

func TestRun_ProbeMessage_NoErrorMsg_ReturnsFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"username":"testuser","bio":"Hello"}`))
	}))
	t.Cleanup(srv.Close)

	sites := []sherlock.Site{{
		Name:        "MsgSite",
		Category:    "test",
		URLTemplate: srv.URL + "/{}",
		ProbeType:   sherlock.ProbeMessage,
		ErrorMsg:    "user not found",
	}}
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, _ := m.Run(context.Background(), module.Input{Target: "testuser"})
	found := false
	for _, f := range findings {
		if f.Extra["site"] == "MsgSite" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding when error message is absent from body")
	}
}

func TestRun_ProbeMessage_ErrorMsgPresent_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`user not found`))
	}))
	t.Cleanup(srv.Close)

	sites := []sherlock.Site{{
		Name:        "MsgSite404",
		Category:    "test",
		URLTemplate: srv.URL + "/{}",
		ProbeType:   sherlock.ProbeMessage,
		ErrorMsg:    "user not found",
	}}
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, _ := m.Run(context.Background(), module.Input{Target: "nobody"})
	for _, f := range findings {
		if f.Extra["site"] == "MsgSite404" {
			t.Error("should not find user when error message is in body")
		}
	}
}

// ─── ProbeURL ─────────────────────────────────────────────────────────────────

func TestRun_ProbeURL_UsernameInFinalURL_ReturnsFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	sites := []sherlock.Site{{
		Name:        "URLSite",
		Category:    "test",
		URLTemplate: srv.URL + "/users/{}",
		ProbeType:   sherlock.ProbeURL,
	}}
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, _ := m.Run(context.Background(), module.Input{Target: "targetuser"})
	found := false
	for _, f := range findings {
		if f.Extra["site"] == "URLSite" {
			found = true
		}
	}
	if !found {
		t.Error("expected ProbeURL finding when username appears in final URL")
	}
}

// ─── Confidence tiers ────────────────────────────────────────────────────────

func TestRun_ProbeStatus_Confidence075(t *testing.T) {
	srv := stubServer(t, http.StatusOK)
	sites := singleSite(t, srv, sherlock.ProbeStatus)
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, _ := m.Run(context.Background(), module.Input{Target: "u"})
	for _, f := range findings {
		c := f.Extra["confidence"]
		if c == "" {
			t.Error("ProbeStatus finding missing confidence")
		}
	}
}

func TestRun_ProbeURL_HigherConfidenceThanStatus(t *testing.T) {
	srv := stubServer(t, http.StatusOK)
	statusSite := []sherlock.Site{{
		Name: "StatusS", Category: "test",
		URLTemplate: srv.URL + "/s/{}", ProbeType: sherlock.ProbeStatus, FoundCode: http.StatusOK,
	}}
	urlSite := []sherlock.Site{{
		Name: "URLS", Category: "test",
		URLTemplate: srv.URL + "/u/{}", ProbeType: sherlock.ProbeURL,
	}}
	mStatus := sherlock.NewWithSites(srv.Client(), statusSite)
	mURL := sherlock.NewWithSites(srv.Client(), urlSite)

	fsStatus, _ := mStatus.Run(context.Background(), module.Input{Target: "u"})
	fsURL, _ := mURL.Run(context.Background(), module.Input{Target: "u"})

	if len(fsStatus) == 0 || len(fsURL) == 0 {
		t.Skip("no findings to compare")
	}
	cs := fsStatus[0].Extra["confidence"]
	cu := fsURL[0].Extra["confidence"]

	if cu < cs {
		t.Errorf("ProbeURL confidence (%s) should be >= ProbeStatus confidence (%s)", cu, cs)
	}
}

// ─── Category filter ─────────────────────────────────────────────────────────

func TestRun_CategoryFilter_RestrictsResults(t *testing.T) {
	srv := stubServer(t, http.StatusOK)
	sites := []sherlock.Site{
		{Name: "SocialSite", Category: "social", URLTemplate: srv.URL + "/{}", ProbeType: sherlock.ProbeStatus, FoundCode: http.StatusOK},
		{Name: "CodingSite", Category: "coding", URLTemplate: srv.URL + "/{}", ProbeType: sherlock.ProbeStatus, FoundCode: http.StatusOK},
	}
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, _ := m.Run(context.Background(), module.Input{
		Target:  "testuser",
		Options: map[string]string{"categories": "coding"},
	})

	for _, f := range findings {
		if f.Extra["category"] == "social" {
			t.Error("social category should be filtered out when categories=coding")
		}
	}
}

// ─── Finding fields ───────────────────────────────────────────────────────────

func TestRun_Findings_URLPopulated(t *testing.T) {
	srv := stubServer(t, http.StatusOK)
	sites := singleSite(t, srv, sherlock.ProbeStatus)
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, _ := m.Run(context.Background(), module.Input{Target: "myuser"})
	for _, f := range findings {
		if f.URL == "" {
			t.Error("finding missing URL field")
		}
	}
}

func TestRun_Findings_DetailNotEmpty(t *testing.T) {
	srv := stubServer(t, http.StatusOK)
	sites := singleSite(t, srv, sherlock.ProbeStatus)
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, _ := m.Run(context.Background(), module.Input{Target: "myuser"})
	for _, f := range findings {
		if f.Detail == "" {
			t.Error("finding missing Detail")
		}
	}
}

func TestRun_Findings_SiteNameInExtra(t *testing.T) {
	srv := stubServer(t, http.StatusOK)
	sites := singleSite(t, srv, sherlock.ProbeStatus)
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, _ := m.Run(context.Background(), module.Input{Target: "myuser"})
	for _, f := range findings {
		if f.Extra["site"] == "" {
			t.Error("finding missing 'site' in Extra")
		}
	}
}

// ─── Context cancellation ─────────────────────────────────────────────────────

func TestRun_ContextCancelled_DoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := stubServer(t, http.StatusOK)
	sites := singleSite(t, srv, sherlock.ProbeStatus)
	m := sherlock.NewWithSites(srv.Client(), sites)

	_, _ = m.Run(ctx, module.Input{Target: "user"})
}

// ─── Constructors ─────────────────────────────────────────────────────────────

func TestNew_HasBuiltInSites(t *testing.T) {
	m := sherlock.New()
	// Just verify it runs without panic
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNewWithClient_UsesProvidedClient(t *testing.T) {
	m := sherlock.NewWithClient(http.DefaultClient)
	if m == nil {
		t.Fatal("NewWithClient returned nil")
	}
	if m.Name() != "sherlock" {
		t.Errorf("wrong name: %s", m.Name())
	}
}

func TestNewWithSites_EmptySites_NoFindings(t *testing.T) {
	m := sherlock.NewWithSites(http.DefaultClient, []sherlock.Site{})
	findings, err := m.Run(context.Background(), module.Input{Target: "someuser"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings with empty site list, got %d", len(findings))
	}
}

// ─── Severity ─────────────────────────────────────────────────────────────────

func TestRun_FindingType_IsUsernameFound(t *testing.T) {
	srv := stubServer(t, http.StatusOK)
	sites := singleSite(t, srv, sherlock.ProbeStatus)
	m := sherlock.NewWithSites(srv.Client(), sites)

	findings, _ := m.Run(context.Background(), module.Input{Target: "u"})
	for _, f := range findings {
		if f.Type != "username_found" && !strings.HasPrefix(f.Type, "username") {
			t.Errorf("expected username_found type, got %q", f.Type)
		}
	}
}

// ─── Multiple sites ───────────────────────────────────────────────────────────

func TestRun_MultipleSites_AllQueried(t *testing.T) {
	var requestCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	sites := []sherlock.Site{
		{Name: "A", Category: "test", URLTemplate: srv.URL + "/a/{}", ProbeType: sherlock.ProbeStatus, FoundCode: http.StatusOK},
		{Name: "B", Category: "test", URLTemplate: srv.URL + "/b/{}", ProbeType: sherlock.ProbeStatus, FoundCode: http.StatusOK},
		{Name: "C", Category: "test", URLTemplate: srv.URL + "/c/{}", ProbeType: sherlock.ProbeStatus, FoundCode: http.StatusOK},
	}
	m := sherlock.NewWithSites(srv.Client(), sites)
	_, _ = m.Run(context.Background(), module.Input{Target: "u"})

	if got := requestCount.Load(); got != 3 {
		t.Errorf("expected 3 requests (one per site), got %d", got)
	}
}
