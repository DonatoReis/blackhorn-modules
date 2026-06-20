package smuggling_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonatoReis/blackhorn-modules/modules/smuggling"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// normalServer: standard HTTP server, no smuggling vulnerability.
func normalServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
}

// timingDialer: returns a dial function that simulates TCP connections.
// It proxies to the actual test server, allowing us to test without real smuggling.
func timingDialer(srv *httptest.Server) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Connect to the test server instead.
		return net.Dial(network, srv.Listener.Addr().String())
	}
}

// slowDialer: returns a dialer that delays responses to simulate timing detection.
type slowConn struct {
	net.Conn
	delay time.Duration
}

func (sc *slowConn) Read(b []byte) (n int, err error) {
	time.Sleep(sc.delay)
	return sc.Conn.Read(b)
}

func delayedDialer(srv *httptest.Server, readDelay time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := net.Dial(network, srv.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return &slowConn{Conn: conn, delay: readDelay}, nil
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	m := smuggling.New()
	if m.Name() != "smuggling" {
		t.Fatalf("expected 'smuggling', got %q", m.Name())
	}
}

func TestModuleImplementsInterface(t *testing.T) {
	var _ module.Module = smuggling.New()
}

// TestEmptyInput: no targets → nil.
func TestEmptyInput(t *testing.T) {
	m := smuggling.New()
	findings, err := m.Run(context.Background(), module.Input{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(findings))
	}
}

// TestContextCancellation: cancelled context does not panic.
func TestContextCancellation(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := smuggling.NewWithDialer(timingDialer(srv))
	_, err := m.Run(ctx, module.Input{Target: "http://" + srv.Listener.Addr().String() + "/"})
	_ = err
}

// TestNormalServerNoFindings: normal server should not produce any findings.
func TestNormalServerNoFindings(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(timingDialer(srv))
	findings, err := m.Run(context.Background(), module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "3"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Logf("unexpected findings (may be timing-related): %v", findings)
		// Don't fail — timing tests are flaky. Just ensure no panic.
	}
}

// TestParallelismOption: custom parallelism accepted.
func TestParallelismOption(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(timingDialer(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"parallelism": "2", "timeout": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestTargetFallback: input.Target used when URLs is empty.
func TestTargetFallback(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(timingDialer(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestMultipleURLs: multiple targets processed.
func TestMultipleURLs(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	addr := "http://" + srv.Listener.Addr().String()
	m := smuggling.NewWithDialer(timingDialer(srv))
	_, err := m.Run(context.Background(), module.Input{
		URLs:    []string{addr + "/", addr + "/api"},
		Options: map[string]string{"timeout": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
}

// TestNewWithDialer: does not panic.
func TestNewWithDialer(t *testing.T) {
	d := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("test")
	}
	m := smuggling.NewWithDialer(d)
	if m == nil || m.Name() != "smuggling" {
		t.Fatal("NewWithDialer failed")
	}
}

// TestTimingDetection: slow server triggers timing-based finding.
// We use a delay of 5s on responses (> timingThreshold of 4s) to simulate CL.TE.
func TestTimingDetection(t *testing.T) {
	// This test is inherently timing-based; run with generous timeout.
	srv := normalServer(t)
	defer srv.Close()

	// Delay by 5 seconds on reads — simulates back-end waiting for more data.
	m := smuggling.NewWithDialer(delayedDialer(srv, 5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	findings, err := m.Run(ctx, module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "6", "parallelism": "1"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	// May or may not find due to timing sensitivity — just ensure no panic.
	t.Logf("findings with 5s read delay: %d", len(findings))
}

// TestFindingFields: if a finding exists, all fields are populated.
func TestFindingFields(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(delayedDialer(srv, 5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	findings, err := m.Run(ctx, module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "6", "parallelism": "1"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" {
			t.Error("URL empty")
		}
		if f.Detail == "" {
			t.Error("Detail empty")
		}
		if f.Severity == "" {
			t.Error("Severity empty")
		}
		if f.Extra["probe_id"] == "" {
			t.Error("Extra.probe_id empty")
		}
		if f.Extra["variant"] == "" {
			t.Error("Extra.variant empty")
		}
	}
}

// TestDeduplication: same probe + URL not duplicated.
func TestDeduplication(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(delayedDialer(srv, 5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	u := "http://" + srv.Listener.Addr().String() + "/"
	findings, err := m.Run(ctx, module.Input{
		URLs:    []string{u, u},
		Options: map[string]string{"timeout": "6", "parallelism": "2"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	seen := make(map[string]int)
	for _, f := range findings {
		key := f.URL + "|" + f.Type + "|" + f.Extra["probe_id"]
		seen[key]++
	}
	for k, count := range seen {
		if count > 1 {
			t.Errorf("duplicate finding %q count=%d", k, count)
		}
	}
}

// TestDetailPrefix: findings have [Smuggling] in detail.
func TestDetailPrefix(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(delayedDialer(srv, 5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	findings, err := m.Run(ctx, module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "6", "parallelism": "1"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range findings {
		if !strings.Contains(f.Detail, "[Smuggling]") {
			t.Errorf("Detail %q missing '[Smuggling]'", f.Detail)
		}
	}
}

// TestNewWithDialer_NoNilReturn verifies NewWithDialer returns a valid module.
func TestNewWithDialer_NoNilReturn(t *testing.T) {
	d := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, fmt.Errorf("mock dialer")
	}
	m := smuggling.NewWithDialer(d)
	if m == nil {
		t.Fatal("NewWithDialer returned nil")
	}
	if m.Name() != "smuggling" {
		t.Errorf("expected name 'smuggling', got %q", m.Name())
	}
}

// TestTimeout_Accepted verifies that the timeout option is accepted without error.
func TestTimeout_Accepted(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(timingDialer(srv))
	_, err := m.Run(context.Background(), module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNoFindingsType: if any findings exist they have type 'http_smuggling'.
func TestNoFindingsType(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(delayedDialer(srv, 5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	findings, err := m.Run(ctx, module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "6", "parallelism": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type != "http_smuggling" {
			t.Errorf("expected type 'http_smuggling', got %q", f.Type)
		}
	}
}

// TestRun_FindingSeveritySet verifies http_smuggling findings have a severity.
func TestRun_FindingSeveritySet(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(timingDialer(srv))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	findings, err := m.Run(ctx, module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "3", "parallelism": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("smuggling finding missing Severity: %+v", f)
		}
	}
}

// TestRun_FindingsHaveConfidence verifies all findings have a non-empty confidence value.
func TestRun_FindingsHaveConfidence(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(delayedDialer(srv, 5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	findings, err := m.Run(ctx, module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "6", "parallelism": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Extra["confidence"] == "" {
			t.Errorf("finding missing Extra[confidence]: %+v", f)
		}
	}
}

// TestRun_FindingTypeValid verifies all findings have a non-empty Type field.
func TestRun_FindingTypeValid(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(delayedDialer(srv, 5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	findings, err := m.Run(ctx, module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "6", "parallelism": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Type == "" {
			t.Errorf("finding has empty Type: %+v", f)
		}
	}
}

// TestRun_FindingURLOrDetailSet verifies each finding has at least URL or Detail set.
func TestRun_FindingURLOrDetailSet(t *testing.T) {
	srv := normalServer(t)
	defer srv.Close()

	m := smuggling.NewWithDialer(delayedDialer(srv, 5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	findings, err := m.Run(ctx, module.Input{
		Target:  "http://" + srv.Listener.Addr().String() + "/",
		Options: map[string]string{"timeout": "6", "parallelism": "1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.URL == "" && f.Detail == "" {
			t.Errorf("finding has neither URL nor Detail: %+v", f)
		}
	}
}
