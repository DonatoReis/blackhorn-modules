// export_test.go exposes internal helpers for use in _test packages.
// This file is only compiled when running tests.
package dnsrecon

import (
	"context"
	"testing"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

// AttemptAXFRForTesting calls the internal attemptAXFR function and converts
// the result to []module.Finding so tests can assert on finding types/severities
// without needing a live DNS infrastructure.
func AttemptAXFRForTesting(t *testing.T, domain, nsAddr string) []module.Finding {
	t.Helper()
	result := attemptAXFRAddr(context.Background(), domain, nsAddr)
	switch result.status {
	case axfrSuccess:
		return []module.Finding{{
			Type:     "dns_axfr_success",
			URL:      "dns://" + nsAddr,
			Severity: module.SeverityHigh,
			Extra: map[string]string{
				"confidence":   "0.98",
				"record_count": formatInt(result.recordCount),
			},
		}}
	default:
		return nil
	}
}

func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
