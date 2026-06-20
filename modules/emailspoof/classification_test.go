package emailspoof

import (
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

func TestSpoofabilitySummaryDMARCNoneIsMedium(t *testing.T) {
	findings := []module.Finding{{Type: "dmarc_policy_none"}}
	summary := New().spoofabilitySummary("example.com", findings)
	if len(summary) != 1 {
		t.Fatalf("expected one summary, got %d", len(summary))
	}
	if summary[0].Severity != module.SeverityMedium {
		t.Fatalf("DMARC p=none alone must be Medium, got %s", summary[0].Severity)
	}
	if summary[0].Extra["verdict"] != "AT_RISK" {
		t.Fatalf("expected AT_RISK verdict, got %q", summary[0].Extra["verdict"])
	}
}
