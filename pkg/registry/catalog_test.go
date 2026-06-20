package registry_test

import (
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/registry"
)

// TestCatalogRegistered: verifica que o catalog.go registrou módulos no init.
func TestCatalogRegistered(t *testing.T) {
	// O init() do catalog.go popula o registry global.
	// Módulos são registrados quando o package é importado.
	count := registry.Count()
	if count < 100 {
		t.Errorf("expected at least 100 registered modules, got %d", count)
	}
	t.Logf("registry contains %d modules", count)
}

// TestCatalogAllSorted: All() deve retornar lista ordenada por nome.
func TestCatalogAllSorted(t *testing.T) {
	all := registry.All()
	for i := 1; i < len(all); i++ {
		if all[i].Name < all[i-1].Name {
			t.Errorf("All() not sorted: %q came after %q", all[i-1].Name, all[i].Name)
		}
	}
}

// TestCatalogNoDuplicates: nenhum nome duplicado.
func TestCatalogNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range registry.All() {
		if seen[m.Name] {
			t.Errorf("duplicate module name: %q", m.Name)
		}
		seen[m.Name] = true
	}
}

// TestCatalogAllHaveFactory: todo módulo tem Factory.
func TestCatalogAllHaveFactory(t *testing.T) {
	for _, m := range registry.All() {
		if m.Factory == nil {
			t.Errorf("module %q has nil Factory", m.Name)
		}
	}
}

// TestCatalogAllHaveDescription: todo módulo tem Description.
func TestCatalogAllHaveDescription(t *testing.T) {
	for _, m := range registry.All() {
		if m.Description == "" {
			t.Errorf("module %q has empty Description", m.Name)
		}
	}
}

// TestCatalogAllHaveCategory: todo módulo tem Category.
func TestCatalogAllHaveCategory(t *testing.T) {
	for _, m := range registry.All() {
		if m.Category == "" {
			t.Errorf("module %q has empty Category", m.Name)
		}
	}
}

// TestCatalogAllHaveInputTypes: todo módulo declara pelo menos um tipo de input.
func TestCatalogAllHaveInputTypes(t *testing.T) {
	for _, m := range registry.All() {
		if len(m.InputTypes) == 0 {
			t.Errorf("module %q has no InputTypes", m.Name)
		}
	}
}

// TestCatalogAllHaveOutputTypes: todo módulo declara pelo menos um tipo de output.
func TestCatalogAllHaveOutputTypes(t *testing.T) {
	for _, m := range registry.All() {
		if len(m.OutputTypes) == 0 {
			t.Errorf("module %q has no OutputTypes", m.Name)
		}
	}
}

// TestCatalogNewInstantiates: New() deve retornar uma instância não-nil.
func TestCatalogNewInstantiates(t *testing.T) {
	// spot-check some modules
	for _, name := range []string{"sherlock", "portscanner", "sqli", "secretscan", "swaggerfuzz", "emailspoof", "s3enum"} {
		mod, err := registry.New(name)
		if err != nil {
			t.Errorf("New(%q): %v", name, err)
			continue
		}
		if mod == nil {
			t.Errorf("New(%q): returned nil module", name)
			continue
		}
		if mod.Name() != name {
			t.Errorf("New(%q): module.Name() = %q", name, mod.Name())
		}
	}
}

func TestCatalogRuntimeBudgetsAreExposed(t *testing.T) {
	for _, name := range []string{"apiaudit", "cacheprobe", "cmdi", "cors2", "corsaudit", "s3enum", "wafscan"} {
		meta := registry.Lookup(name)
		if meta == nil {
			t.Fatalf("module %q not registered", name)
		}
		options := make(map[string]string, len(meta.Options))
		for _, option := range meta.Options {
			options[option.Key] = option.Default
		}
		if options["max_targets"] == "" {
			t.Errorf("module %q does not expose max_targets", name)
		}
		if options["max_runtime_seconds"] == "" {
			t.Errorf("module %q does not expose max_runtime_seconds", name)
		}
	}
}

func TestCatalogDomainScansExcludeInapplicableModules(t *testing.T) {
	for _, name := range []string{"brazilinfo", "govbr", "emailosint", "repochecker", "notify"} {
		meta := registry.Lookup(name)
		if meta == nil {
			t.Fatalf("module %q not registered", name)
		}
		for _, inputType := range meta.InputTypes {
			if inputType == "domain" {
				t.Errorf("module %q must not be selected automatically for domain scans", name)
			}
		}
	}
}

// TestCatalogByCategoryWebVuln: categoria web-vuln tem módulos esperados.
func TestCatalogByCategoryWebVuln(t *testing.T) {
	mods := registry.ByCategory(registry.CategoryWebVuln)
	if len(mods) < 10 {
		t.Errorf("expected ≥10 web-vuln modules, got %d", len(mods))
	}
}

// TestCatalogByCategoryOSINTBrasil: categoria osint-brasil tem módulos esperados.
func TestCatalogByCategoryOSINTBrasil(t *testing.T) {
	mods := registry.ByCategory(registry.CategoryOSINTBrasil)
	if len(mods) < 5 {
		t.Errorf("expected ≥5 osint-brasil modules, got %d", len(mods))
	}
}

// TestCatalogWithGateLGPD: módulos com gate LGPD incluem cpflookup, tribunais.
func TestCatalogWithGateLGPD(t *testing.T) {
	gated := registry.WithGate(registry.GateLGPD)
	names := map[string]bool{}
	for _, m := range gated {
		names[m.Name] = true
	}
	for _, expected := range []string{"cpflookup", "tribunais", "registroempresas"} {
		if !names[expected] {
			t.Errorf("expected %q to have LGPD gate", expected)
		}
	}
}

// TestCatalogWithGateAuthorized: credstuffing e wifite2 têm gate authorized.
func TestCatalogWithGateAuthorized(t *testing.T) {
	gated := registry.WithGate(registry.GateAuthorized)
	names := map[string]bool{}
	for _, m := range gated {
		names[m.Name] = true
	}
	for _, expected := range []string{"credstuffing", "wifite2"} {
		if !names[expected] {
			t.Errorf("expected %q to have authorized gate", expected)
		}
	}
}

// TestCatalogForInputDomain: módulos que aceitam "domain" incluem módulos básicos.
func TestCatalogForInputDomain(t *testing.T) {
	mods := registry.ForInput("domain")
	if len(mods) < 15 {
		t.Errorf("expected ≥15 modules accepting 'domain', got %d", len(mods))
	}
}

// TestCatalogForInputIP: módulos que aceitam "ip".
func TestCatalogForInputIP(t *testing.T) {
	mods := registry.ForInput("ip")
	if len(mods) < 5 {
		t.Errorf("expected ≥5 modules accepting 'ip', got %d", len(mods))
	}
}

// TestCatalogNames: Names() deve retornar lista com o mesmo count.
func TestCatalogNames(t *testing.T) {
	names := registry.Names()
	count := registry.Count()
	if len(names) != count {
		t.Errorf("Names() length %d != Count() %d", len(names), count)
	}
}
