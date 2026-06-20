package registry_test

import (
	"context"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"github.com/DonatoReis/blackhorn-modules/pkg/registry"
)

// ─── stub module ─────────────────────────────────────────────────────────────

type stubModule struct{ name string }

func (s *stubModule) Name() string { return s.name }
func (s *stubModule) Run(_ context.Context, _ module.Input) ([]module.Finding, error) {
	return []module.Finding{{Type: "stub", Detail: "ok"}}, nil
}

func newStub(name string) func() module.Module {
	return func() module.Module { return &stubModule{name: name} }
}

// ─── isolated registry for tests (avoids polluting the global registry) ──────

func newTestRegistry() *registry.Registry {
	return registry.NewRegistry()
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestRegisterAndLookup(t *testing.T) {
	r := newTestRegistry()
	r.Register(&registry.Meta{
		Name:        "test-mod",
		Category:    registry.CategoryUtil,
		Description: "a test module",
		Factory:     newStub("test-mod"),
	})

	meta := r.Lookup("test-mod")
	if meta == nil {
		t.Fatal("expected meta, got nil")
	}
	if meta.Name != "test-mod" {
		t.Errorf("unexpected name: %q", meta.Name)
	}
}

func TestLookupMissing(t *testing.T) {
	r := newTestRegistry()
	if r.Lookup("nonexistent") != nil {
		t.Error("expected nil for unknown module")
	}
}

func TestDuplicatePanics(t *testing.T) {
	r := newTestRegistry()
	r.Register(&registry.Meta{Name: "dup", Category: registry.CategoryUtil, Factory: newStub("dup")})
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	r.Register(&registry.Meta{Name: "dup", Category: registry.CategoryUtil, Factory: newStub("dup")})
}

func TestAll(t *testing.T) {
	r := newTestRegistry()
	r.Register(&registry.Meta{Name: "b-mod", Category: registry.CategoryUtil, Factory: newStub("b-mod")})
	r.Register(&registry.Meta{Name: "a-mod", Category: registry.CategoryUtil, Factory: newStub("a-mod")})
	r.Register(&registry.Meta{Name: "c-mod", Category: registry.CategoryUtil, Factory: newStub("c-mod")})

	all := r.All()
	if len(all) != 3 {
		t.Fatalf("expected 3, got %d", len(all))
	}
	if all[0].Name != "a-mod" || all[1].Name != "b-mod" || all[2].Name != "c-mod" {
		t.Errorf("not sorted: %v", all)
	}
}

func TestByCategory(t *testing.T) {
	r := newTestRegistry()
	r.Register(&registry.Meta{Name: "recon-1", Category: registry.CategoryRecon, Factory: newStub("recon-1")})
	r.Register(&registry.Meta{Name: "recon-2", Category: registry.CategoryRecon, Factory: newStub("recon-2")})
	r.Register(&registry.Meta{Name: "vuln-1", Category: registry.CategoryWebVuln, Factory: newStub("vuln-1")})

	recon := r.ByCategory(registry.CategoryRecon)
	if len(recon) != 2 {
		t.Fatalf("expected 2 recon modules, got %d", len(recon))
	}
	vuln := r.ByCategory(registry.CategoryWebVuln)
	if len(vuln) != 1 {
		t.Fatalf("expected 1 vuln module, got %d", len(vuln))
	}
}

func TestWithGate(t *testing.T) {
	r := newTestRegistry()
	r.Register(&registry.Meta{
		Name:     "gated",
		Category: registry.CategoryOSINTBrasil,
		Gates:    []registry.Gate{registry.GateLGPD},
		Factory:  newStub("gated"),
	})
	r.Register(&registry.Meta{
		Name:     "free",
		Category: registry.CategoryOSINTBrasil,
		Factory:  newStub("free"),
	})

	gated := r.WithGate(registry.GateLGPD)
	if len(gated) != 1 || gated[0].Name != "gated" {
		t.Errorf("unexpected gated: %v", gated)
	}
}

func TestForInput(t *testing.T) {
	r := newTestRegistry()
	r.Register(&registry.Meta{
		Name:       "email-mod",
		Category:   registry.CategoryOSINTEmail,
		InputTypes: []string{"email", "domain"},
		Factory:    newStub("email-mod"),
	})
	r.Register(&registry.Meta{
		Name:       "phone-mod",
		Category:   registry.CategoryOSINTBrasil,
		InputTypes: []string{"phone"},
		Factory:    newStub("phone-mod"),
	})

	emailMods := r.ForInput("email")
	if len(emailMods) != 1 || emailMods[0].Name != "email-mod" {
		t.Errorf("unexpected email modules: %v", emailMods)
	}
	domainMods := r.ForInput("domain")
	if len(domainMods) != 1 || domainMods[0].Name != "email-mod" {
		t.Errorf("unexpected domain modules: %v", domainMods)
	}
	phoneMods := r.ForInput("phone")
	if len(phoneMods) != 1 || phoneMods[0].Name != "phone-mod" {
		t.Errorf("unexpected phone modules: %v", phoneMods)
	}
}

func TestNewAndRun(t *testing.T) {
	r := newTestRegistry()
	r.Register(&registry.Meta{
		Name:     "runnable",
		Factory:  newStub("runnable"),
		Category: registry.CategoryUtil,
	})

	mod, err := r.New("runnable")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if mod.Name() != "runnable" {
		t.Errorf("unexpected Name: %q", mod.Name())
	}

	findings, err := r.Run(context.Background(), "runnable", module.Input{Target: "test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 || findings[0].Type != "stub" {
		t.Errorf("unexpected findings: %v", findings)
	}
}

func TestNewUnknown(t *testing.T) {
	r := newTestRegistry()
	_, err := r.New("unknown")
	if err == nil {
		t.Error("expected error for unknown module")
	}
}

func TestNames(t *testing.T) {
	r := newTestRegistry()
	r.Register(&registry.Meta{Name: "z", Category: registry.CategoryUtil, Factory: newStub("z")})
	r.Register(&registry.Meta{Name: "a", Category: registry.CategoryUtil, Factory: newStub("a")})

	names := r.Names()
	if len(names) != 2 || names[0] != "a" || names[1] != "z" {
		t.Errorf("unexpected names: %v", names)
	}
}

func TestCount(t *testing.T) {
	r := newTestRegistry()
	if r.Count() != 0 {
		t.Errorf("expected 0, got %d", r.Count())
	}
	r.Register(&registry.Meta{Name: "x", Category: registry.CategoryUtil, Factory: newStub("x")})
	if r.Count() != 1 {
		t.Errorf("expected 1, got %d", r.Count())
	}
}

func TestNilFactoryPanics(t *testing.T) {
	r := newTestRegistry()
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic for nil factory")
		}
	}()
	r.Register(&registry.Meta{Name: "no-factory", Category: registry.CategoryUtil})
}

func TestEmptyNamePanics(t *testing.T) {
	r := newTestRegistry()
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic for empty name")
		}
	}()
	r.Register(&registry.Meta{Category: registry.CategoryUtil, Factory: newStub("")})
}
