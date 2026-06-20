package template

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// ─── Response context ─────────────────────────────────────────────────────────

// HTTPResponse carries all parts of an HTTP response that matchers can act on.
type HTTPResponse struct {
	StatusCode int
	Headers    http.Header
	Body       string
	Raw        string // headers + body concatenated
	URL        string
}

// DNSResponse holds a DNS query result for matcher evaluation.
type DNSResponse struct {
	Answer     []string
	Authority  []string
	Additional []string
	Question   string
	Raw        string
}

// NetworkResponse holds the result of a TCP/UDP probe.
type NetworkResponse struct {
	Data string
}

// ─── HTTP matcher evaluation ──────────────────────────────────────────────────

// EvaluateHTTPMatchers evaluates all matchers against an HTTP response.
// condition: "and" | "or" (default "or").
// Mirrors nuclei operators/matchers evaluation logic.
func EvaluateHTTPMatchers(matchers []Matcher, condition string, resp HTTPResponse) bool {
	if len(matchers) == 0 {
		return false
	}
	cond := normalizeCondition(condition)

	for _, m := range matchers {
		result := evalHTTPMatcher(m, resp)
		if m.Negative {
			result = !result
		}
		if cond == "and" && !result {
			return false
		}
		if cond == "or" && result {
			return true
		}
	}
	return cond == "and"
}

func evalHTTPMatcher(m Matcher, resp HTTPResponse) bool {
	part := httpPart(m.Part, resp)
	switch m.Type {
	case StatusMatcher:
		for _, code := range m.Status {
			if code == resp.StatusCode {
				return true
			}
		}
		return false
	case WordMatcher:
		return evalWords(m, part)
	case RegexMatcher:
		return evalRegex(m, part)
	case SizeMatcher:
		size := len(resp.Body)
		for _, s := range m.Size {
			if s == size {
				return true
			}
		}
		return false
	case BinaryMatcher:
		return evalBinary(m, part)
	case DSLMatcher:
		return evalDSL(m, resp)
	}
	return false
}

func httpPart(part MatcherPart, resp HTTPResponse) string {
	switch part {
	case PartHeader:
		return headersString(resp.Headers)
	case PartRaw, PartAll:
		return resp.Raw
	case PartStatusCode:
		return fmt.Sprintf("%d", resp.StatusCode)
	default: // PartBody or empty
		return resp.Body
	}
}

func headersString(h http.Header) string {
	var sb strings.Builder
	for k, vals := range h {
		for _, v := range vals {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// ─── DNS matcher evaluation ───────────────────────────────────────────────────

// EvaluateDNSMatchers evaluates matchers against a DNS response.
func EvaluateDNSMatchers(matchers []Matcher, condition string, resp DNSResponse) bool {
	if len(matchers) == 0 {
		return false
	}
	cond := normalizeCondition(condition)
	for _, m := range matchers {
		result := evalDNSMatcher(m, resp)
		if m.Negative {
			result = !result
		}
		if cond == "and" && !result {
			return false
		}
		if cond == "or" && result {
			return true
		}
	}
	return cond == "and"
}

func evalDNSMatcher(m Matcher, resp DNSResponse) bool {
	part := dnsPart(m.Part, resp)
	switch m.Type {
	case WordMatcher:
		return evalWords(m, part)
	case RegexMatcher:
		return evalRegex(m, part)
	}
	return false
}

func dnsPart(part MatcherPart, resp DNSResponse) string {
	switch part {
	case PartAuthority:
		return strings.Join(resp.Authority, "\n")
	case PartAdditional:
		return strings.Join(resp.Additional, "\n")
	case PartQuestion:
		return resp.Question
	case PartRaw, PartAll:
		return resp.Raw
	default: // PartAnswer or empty
		return strings.Join(resp.Answer, "\n")
	}
}

// ─── Network matcher evaluation ──────────────────────────────────────────────

// EvaluateNetworkMatchers evaluates matchers against a TCP/UDP response.
func EvaluateNetworkMatchers(matchers []Matcher, condition string, resp NetworkResponse) bool {
	if len(matchers) == 0 {
		return false
	}
	cond := normalizeCondition(condition)
	for _, m := range matchers {
		result := evalNetworkMatcher(m, resp)
		if m.Negative {
			result = !result
		}
		if cond == "and" && !result {
			return false
		}
		if cond == "or" && result {
			return true
		}
	}
	return cond == "and"
}

func evalNetworkMatcher(m Matcher, resp NetworkResponse) bool {
	switch m.Type {
	case WordMatcher:
		return evalWords(m, resp.Data)
	case RegexMatcher:
		return evalRegex(m, resp.Data)
	case BinaryMatcher:
		return evalBinary(m, resp.Data)
	}
	return false
}

// ─── Shared primitives ────────────────────────────────────────────────────────

// evalWords checks word/string matching — mirrors nuclei matchWordsMatcher().
func evalWords(m Matcher, target string) bool {
	cond := normalizeCondition(m.Condition)
	cmp := target
	if !m.CaseSensitive {
		cmp = strings.ToLower(target)
	}
	for _, word := range m.Words {
		w := word
		if !m.CaseSensitive {
			w = strings.ToLower(word)
		}
		match := strings.Contains(cmp, w)
		if cond == "and" && !match {
			return false
		}
		if cond == "or" && match {
			return true
		}
	}
	return cond == "and"
}

// evalRegex checks regex matching — mirrors nuclei matchRegexMatcher().
func evalRegex(m Matcher, target string) bool {
	cond := normalizeCondition(m.Condition)
	compiled := m.compiled
	if len(compiled) == 0 {
		for _, p := range m.Regex {
			re := mustCompileRegex(p)
			if re != nil {
				compiled = append(compiled, re)
			}
		}
	}
	for _, re := range compiled {
		match := re.MatchString(target)
		if cond == "and" && !match {
			return false
		}
		if cond == "or" && match {
			return true
		}
	}
	return cond == "and"
}

// evalBinary checks hex-encoded binary matching — mirrors nuclei matchBinaryMatcher().
func evalBinary(m Matcher, target string) bool {
	cond := normalizeCondition(m.Condition)
	for _, hexStr := range m.Binary {
		decoded, err := hex.DecodeString(hexStr)
		if err != nil {
			continue
		}
		match := strings.Contains(target, string(decoded))
		if cond == "and" && !match {
			return false
		}
		if cond == "or" && match {
			return true
		}
	}
	return cond == "and"
}

// evalDSL evaluates DSL expressions — implements a safe subset of nuclei's DSL.
// Supported: contains(body,"x"), status_code==N, len(body)>N
func evalDSL(m Matcher, resp HTTPResponse) bool {
	cond := normalizeCondition(m.Condition)
	for _, expr := range m.DSL {
		result := evalDSLExpr(expr, resp)
		if cond == "and" && !result {
			return false
		}
		if cond == "or" && result {
			return true
		}
	}
	return cond == "and"
}

func evalDSLExpr(expr string, resp HTTPResponse) bool {
	expr = strings.TrimSpace(expr)

	// contains(body, "needle") / contains(header, "needle")
	if strings.HasPrefix(expr, "contains(") {
		inner := strings.TrimPrefix(strings.TrimSuffix(expr, ")"), "contains(")
		parts := splitCSV(inner)
		if len(parts) == 2 {
			haystack := dslVar(strings.TrimSpace(parts[0]), resp)
			needle := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			return strings.Contains(haystack, needle)
		}
	}

	// status_code == N  /  status_code != N
	nosp := strings.ReplaceAll(expr, " ", "")
	if strings.HasPrefix(nosp, "status_code") {
		var code int
		if _, err := fmt.Sscanf(nosp, "status_code==%d", &code); err == nil {
			return resp.StatusCode == code
		}
		if _, err := fmt.Sscanf(nosp, "status_code!=%d", &code); err == nil {
			return resp.StatusCode != code
		}
	}

	// len(body) > N  /  len(body) >= N  /  etc.
	if strings.HasPrefix(expr, "len(") {
		inner := strings.TrimPrefix(expr, "len(")
		ps := strings.SplitN(inner, ")", 2)
		if len(ps) == 2 {
			val := dslVar(strings.TrimSpace(ps[0]), resp)
			return evalLenCmp(len(val), strings.TrimSpace(ps[1]))
		}
	}

	return false
}

func dslVar(name string, resp HTTPResponse) string {
	switch name {
	case "body":
		return resp.Body
	case "header", "headers":
		return headersString(resp.Headers)
	case "raw":
		return resp.Raw
	}
	return ""
}

func evalLenCmp(length int, op string) bool {
	var n int
	nosp := strings.ReplaceAll(op, " ", "")
	if _, err := fmt.Sscanf(nosp, ">=%d", &n); err == nil {
		return length >= n
	}
	if _, err := fmt.Sscanf(nosp, ">%d", &n); err == nil {
		return length > n
	}
	if _, err := fmt.Sscanf(nosp, "<=%d", &n); err == nil {
		return length <= n
	}
	if _, err := fmt.Sscanf(nosp, "<%d", &n); err == nil {
		return length < n
	}
	if _, err := fmt.Sscanf(nosp, "==%d", &n); err == nil {
		return length == n
	}
	return false
}

// splitCSV splits on comma not inside quotes.
func splitCSV(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\'' {
			depth++
		}
		if c == ',' && depth%2 == 0 {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// ─── Extractor evaluation ─────────────────────────────────────────────────────

// ExtractHTTP runs all extractors against an HTTP response.
// Returns map of extractor name → extracted values.
// Mirrors nuclei extractor evaluation.
func ExtractHTTP(extractors []Extractor, resp HTTPResponse) map[string][]string {
	out := map[string][]string{}
	for _, e := range extractors {
		vals := extractHTTPValues(e, resp)
		if len(vals) == 0 {
			continue
		}
		name := e.Name
		if name == "" {
			name = string(e.Type)
		}
		if !e.Internal {
			out[name] = append(out[name], vals...)
		}
	}
	return out
}

func extractHTTPValues(e Extractor, resp HTTPResponse) []string {
	part := httpPart(e.Part, resp)
	switch e.Type {
	case RegexExtractor:
		return extractRegexValues(e, part)
	case KVExtractor:
		return extractKVValues(e, resp.Headers)
	case JSONExtractor:
		return extractJSONValues(e, part)
	}
	return nil
}

func extractRegexValues(e Extractor, s string) []string {
	var out []string
	compiled := e.compiled
	if len(compiled) == 0 {
		for _, p := range e.Regex {
			re := mustCompileRegex(p)
			if re != nil {
				compiled = append(compiled, re)
			}
		}
	}
	group := e.Group
	for _, re := range compiled {
		for _, m := range re.FindAllStringSubmatch(s, -1) {
			if group < len(m) {
				out = append(out, m[group])
			} else if len(m) > 0 {
				out = append(out, m[0])
			}
		}
	}
	return out
}

func extractKVValues(e Extractor, h http.Header) []string {
	var out []string
	for _, key := range e.KVal {
		if vals, ok := h[http.CanonicalHeaderKey(key)]; ok {
			out = append(out, vals...)
		}
	}
	return out
}

func extractJSONValues(e Extractor, s string) []string {
	var out []string
	for _, path := range e.JSON {
		path = strings.TrimPrefix(path, ".")
		parts := strings.Split(path, ".")
		current := s
		found := true
		for _, part := range parts {
			re := mustCompileRegex(`"` + regexp.QuoteMeta(part) + `"\s*:\s*"([^"]*)"`)
			if re == nil {
				found = false
				break
			}
			m := re.FindStringSubmatch(current)
			if len(m) < 2 {
				found = false
				break
			}
			current = m[1]
		}
		if found && current != s {
			out = append(out, current)
		}
	}
	return out
}

// ─── Utilities ────────────────────────────────────────────────────────────────

func normalizeCondition(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	if c == "and" {
		return "and"
	}
	return "or"
}

func mustCompileRegex(pattern string) *regexp.Regexp {
	re, err := regexp.Compile(`(?i)` + pattern)
	if err != nil {
		re, err = regexp.Compile(pattern)
		if err != nil {
			return nil
		}
	}
	return re
}
