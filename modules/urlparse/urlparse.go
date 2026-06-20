// Package urlparse extracts and classifies components from URLs.
//
// Ported from tomnomnom/unfurl (MIT License).
// Original: https://github.com/tomnomnom/unfurl
// Adapted to the blackhorn-modules Module interface: structured []Finding
// output, context support, Go 1.26 patterns.
//
// All format directives from the original are preserved:
//
//	%s  scheme          %d  domain (full host)   %S  subdomain
//	%r  root domain     %t  TLD                  %P  port
//	%p  path            %e  path extension       %q  raw query
//	%f  fragment        %u  userinfo             %a  authority
//	%@  @ if userinfo   %:  : if port            %?  ? if query
//	%#  # if fragment   %%  literal %
package urlparse

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	parser "github.com/Cgboal/DomainParser"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

const moduleName = "urlparse"

// Mode names — mirrors the original CLI modes.
const (
	ModeKeys     = "keys"
	ModeValues   = "values"
	ModeKeyPairs = "keypairs"
	ModeDomains  = "domains"
	ModePaths    = "paths"
	ModeApexes   = "apexes"
	ModeJSON     = "json"
	ModeFormat   = "format"
)

// urlProc mirrors the type from the original.
type urlProc func(u *url.URL, fmtStr string) []string

var procFns = map[string]urlProc{
	"keys":     keys,
	"values":   values,
	"keypairs": keyPairs,
	"domains":  domains,
	"domain":   domains,
	"paths":    paths,
	"path":     paths,
	"apex":     apexes,
	"apexes":   apexes,
	"json":     jsonFormat,
	"format":   format,
}

// UrlStruct mirrors the original JSON output struct exactly.
type UrlStruct struct {
	Scheme        string     `json:"scheme"`
	Opaque        string     `json:"opaque"`
	User          string     `json:"user"`
	Host          string     `json:"host"`
	Path          string     `json:"path"`
	RawPath       string     `json:"raw_path"`
	RawQuery      string     `json:"raw_query"`
	Fragment      string     `json:"fragment"`
	Parameters    []KeyValue `json:"parameters"`
	URL           string     `json:"url"`
	Domain        string     `json:"domain"`
	Subdomain     string     `json:"subdomain"`
	Root          string     `json:"root"`
	TLD           string     `json:"tld"`
	Apex          string     `json:"apex"`
	Port          string     `json:"port"`
	PathExtension string     `json:"extension"`
}

// KeyValue is a single query parameter pair.
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

var domainExtractor parser.Parser
var portRe = regexp.MustCompile(`(?m):\d+$`)

func init() {
	domainExtractor = parser.NewDomainParser()
}

// Module implements module.Module for URL component extraction.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }

// Run parses every URL in input.URLs (or input.Target) and emits a Finding
// per extracted component according to the chosen mode.
//
// Supported options:
//   - "mode":   one of keys|values|keypairs|domains|paths|apexes|json|format
//     default: "json" (all components as a JSON object)
//   - "format": format string used when mode=format (e.g. "%s://%d%p")
//   - "unique": "true" to suppress duplicate values across all URLs
func (m *Module) Run(_ context.Context, input module.Input) ([]module.Finding, error) {
	urls := input.URLs
	if len(urls) == 0 && input.Target != "" {
		urls = []string{input.Target}
	}
	if len(urls) == 0 {
		return nil, errors.New("urlparse: no URLs provided")
	}

	mode := optStr(input.Options, "mode", ModeJSON)
	slog.Debug("urlparse: starting", "urls", len(urls), "mode", mode)
	fmtStr := optStr(input.Options, "format", "")
	unique := optBool(input.Options, "unique", false)

	procFn, ok := procFns[mode]
	if !ok {
		return nil, fmt.Errorf("urlparse: unknown mode %q", mode)
	}

	seen := make(map[string]bool)
	var findings []module.Finding

	for _, raw := range urls {
		u, err := parseURL(raw)
		if err != nil {
			continue // skip malformed — mirrors original verbose-off behaviour
		}

		for _, val := range procFn(u, fmtStr) {
			if val == "" {
				continue
			}
			if unique && seen[val] {
				continue
			}
			if unique {
				seen[val] = true
			}

			findings = append(findings, module.Finding{
				Type:     "url_component",
				URL:      raw,
				Detail:   fmt.Sprintf("mode=%s value=%s", mode, val),
				Severity: module.SeverityInfo,
				Extra:    map[string]string{"mode": mode, "value": val, "confidence": "0.99"},
			})
		}
	}
	return findings, nil
}

// --- processing functions (ported verbatim from tomnomnom/unfurl) ---

func keys(u *url.URL, _ string) []string {
	out := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		out = append(out, k)
	}
	return out
}

func values(u *url.URL, _ string) []string {
	var out []string
	for _, vals := range u.Query() {
		out = append(out, vals...)
	}
	return out
}

func keyPairs(u *url.URL, _ string) []string {
	var out []string
	for k, vals := range u.Query() {
		for _, v := range vals {
			out = append(out, fmt.Sprintf("%s=%s", k, v))
		}
	}
	return out
}

func domains(u *url.URL, _ string) []string { return format(u, "%d") }
func apexes(u *url.URL, _ string) []string  { return format(u, "%r.%t") }
func paths(u *url.URL, _ string) []string   { return format(u, "%p") }

func jsonFormat(u *url.URL, _ string) []string {
	parameters := make([]KeyValue, 0)
	for k, vals := range u.Query() {
		for _, v := range vals {
			parameters = append(parameters, KeyValue{Key: k, Value: v})
		}
	}

	s := UrlStruct{
		Scheme:        u.Scheme,
		Opaque:        u.Opaque,
		User:          u.User.String(),
		Host:          u.Host,
		Path:          u.Path,
		RawPath:       u.RawPath,
		RawQuery:      u.RawQuery,
		Fragment:      u.Fragment,
		Parameters:    parameters,
		URL:           u.String(),
		Domain:        firstOf(format(u, "%d")),
		Subdomain:     firstOf(format(u, "%S")),
		Root:          firstOf(format(u, "%r")),
		TLD:           firstOf(format(u, "%t")),
		Apex:          firstOf(format(u, "%r.%t")),
		Port:          firstOf(format(u, "%P")),
		PathExtension: firstOf(format(u, "%e")),
	}
	b, err := json.Marshal(s)
	if err != nil {
		return []string{""}
	}
	return []string{string(b)}
}

// format is ported verbatim from the original format() function.
func format(u *url.URL, f string) []string {
	out := &bytes.Buffer{}
	inFormat := false

	for _, r := range f {
		if r == '%' && !inFormat {
			inFormat = true
			continue
		}
		if !inFormat {
			out.WriteRune(r)
			continue
		}

		switch r {
		case '%':
			out.WriteRune('%')
		case 's':
			out.WriteString(u.Scheme)
		case 'u':
			if u.User != nil {
				out.WriteString(u.User.String())
			}
		case 'd':
			out.WriteString(u.Hostname())
		case 'P':
			out.WriteString(u.Port())
		case 'S':
			out.WriteString(extractFromDomain(u, "subdomain"))
		case 'r':
			out.WriteString(extractFromDomain(u, "root"))
		case 't':
			out.WriteString(extractFromDomain(u, "tld"))
		case 'p':
			out.WriteString(u.EscapedPath())
		case 'e':
			out.WriteString(fileExt(u.EscapedPath()))
		case 'q':
			out.WriteString(u.RawQuery)
		case 'f':
			out.WriteString(u.Fragment)
		case '@':
			if u.User != nil {
				out.WriteRune('@')
			}
		case ':':
			if u.Port() != "" {
				out.WriteRune(':')
			}
		case '?':
			if u.RawQuery != "" {
				out.WriteRune('?')
			}
		case '#':
			if u.Fragment != "" {
				out.WriteRune('#')
			}
		case 'a':
			out.WriteString(firstOf(format(u, "%u%@%d%:%P")))
		default:
			out.WriteRune('%')
			out.WriteRune(r)
		}
		inFormat = false
	}
	return []string{out.String()}
}

// --- helpers ---

// parseURL mirrors the original: prepend http:// if no scheme.
func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		return url.Parse("http://" + raw)
	}
	return u, nil
}

// extractFromDomain uses the DomainParser library (same as original).
func extractFromDomain(u *url.URL, selection string) string {
	domain := portRe.ReplaceAllString(u.Host, "")
	switch selection {
	case "subdomain":
		return domainExtractor.GetSubdomain(domain)
	case "root":
		return domainExtractor.GetDomain(domain)
	case "tld":
		return domainExtractor.GetTld(domain)
	default:
		return ""
	}
}

// fileExt extracts the file extension from a path — ported from original.
func fileExt(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) > 1 {
		segs := strings.Split(parts[len(parts)-1], ".")
		if len(segs) > 1 {
			return segs[len(segs)-1]
		}
		return ""
	}
	segs := strings.Split(p, ".")
	if len(segs) > 1 {
		return segs[len(segs)-1]
	}
	return ""
}

func firstOf(s []string) string {
	if len(s) == 1 {
		return s[0]
	}
	return ""
}

func optStr(opts map[string]string, key, def string) string {
	if opts == nil {
		return def
	}
	if v, ok := opts[key]; ok {
		return v
	}
	return def
}

func optBool(opts map[string]string, key string, def bool) bool {
	if opts == nil {
		return def
	}
	v, ok := opts[key]
	if !ok {
		return def
	}
	return strings.ToLower(v) != "false"
}
