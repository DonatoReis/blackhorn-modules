# BLACKHORN Modules — Roadmap

Native Go module library that will replace all external binary dependencies
in the BLACKHORN security orchestrator. Each module implements the
`pkg/module.Module` interface and produces structured `[]Finding` output —
no CLI parsing, no side effects, fully testable.

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Complete — implementation + tests passing |
| 🚧 | In progress |
| 📋 | Planned — design decided |
| 💡 | Proposed — needs design |
| ❌ | Blocked or descoped |

---

## Phase 1 — Simple Natives

> Goal: prove the architecture with low-complexity modules.
> All are reimplementations of open-source tools, logic understood in full.

The phase tables below are historical implementation notes. The authoritative
runtime catalog is `pkg/registry/catalog.go`; module names and behavior in that
catalog take precedence over older milestone descriptions.

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `wayback` | tomnomnom/waybackurls | ✅ | CDX API, dedup, ctx cancellation |
| `urlparse` | tomnomnom/unfurl | ✅ | scheme/host/port/path/params/apex/subdomain |
| `urldedup` | s0md3v/uro | ✅ | Pattern-key dedup, param-order invariant |
| `corsaudit` | s0md3v/Corsy | ✅ | 6 test cases, credentials escalation to critical |
| `xssreflect` | tomnomnom/kxss | ✅ | Per-param canary injection, severity scoring |

---

## Phase 2 — Medium Complexity Natives

> Goal: cover parameter discovery, secret detection, and DNS resolution
> without any external binary.

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `paramdisc` | s0md3v/Arjun | ✅ | Binary-search param discovery; 9-factor anomaly detection; CDX seed |
| `paramspider` | devanshbatham/ParamSpider | ✅ | Direct MIT port; CDX fetch + FUZZ placeholder; extension filter |
| `secretscan` | gitleaks/gitleaks | ✅ | Regex + Shannon entropy engine; 35 high-signal rules from gitleaks.toml |
| `dnsprobe` | projectdiscovery/dnsx | ✅ | stdlib net.Resolver; A/AAAA/CNAME/MX/NS/TXT/PTR; custom resolver override |
| `tlsaudit` | drwetter/testssl.sh | ✅ | crypto/tls; protocol/cert/cipher/vuln/header checks; 5 vuln flags |
| `whois` | whois CLI | ✅ | RFC 3912 native TCP; referral chain; 31 TLD map; field extraction |

---

## Phase 3 — ProjectDiscovery Lib Integration

> Goal: eliminate the 6 biggest external binaries by importing their
> Go libs directly. No source copy needed — MIT license allows import.

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `subdiscovery` | subfinder (binary) | ✅ | 8 keyless sources (crtsh, hackertarget, waybackarchive, commoncrawl, rapiddns, urlscan, anubis, digitorus); dedup + scope validation |
| `webprobe` | httpx (binary) | ✅ | Result struct mirrors httpx runner/types.go; title extraction; tech detection from headers; redirect chain |
| `portscanner` | naabu (binary) | ✅ | NmapTop100/Top1000/Full port lists verbatim from naabu; TCP connect scan via net.DialContext; service + severity mapping |
| `vulnscan` | nuclei (binary) | ✅ | Matcher struct (status/word/regex/size) mirrors nuclei; 20 built-in HTTP templates; AND/OR conditions; tag/ID filtering |
| `crawler` | katana (binary) | ✅ | BFS crawler; Request/Response mirrors katana navigation; scope validation; deduplication; depth limit |
| `xssscan` | dalfox (binary) | ✅ | Canary injection + reflection detection; 12 XSS payloads escalation; per-param fan-out (dalfox migrated to Rust — reimplemented) |

---

## Phase 4 — Complex Natives

> Goal: build capabilities that have no clean lib equivalent and require
> a full native implementation.

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `fingerprint` | WhatWeb (binary) | ✅ | 60+ signatures from Wappalyzer community dataset (MIT); header/html/script/meta/url matching; version extraction; implies chain; category/confidence filter; 19 tests |
| `truffler` | trufflehog v3 (AGPL) | ✅ | Full reimpl (AGPL avoided); 45+ detectors for AWS/GCP/GitHub/Stripe/Slack/JWT/PEM/DB; Shannon entropy; line context; detector/tag filter; RawContent scan; 17 tests |
| `graphql` | manual / custom | ✅ | 12 checks (GQL-001–012): introspection, batching, alias/directive overload, depth DoS, GET introspection, debug leak, __type leak, subscription exposure, schema dump; endpoint auto-discovery; 14 tests |
| `sstiprobe` | custom | ✅ | 8 engines (Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, Pebble, Thymeleaf); polyglot error probe + math-expression confirmation; engine identification from error patterns; 13 tests |
| `jwtaudit` | custom | ✅ | 8 checks: none-alg (CVE-2015-9235), weak-secret brute-force, alg-confusion (RS256→HS256), expiry, sensitive-payload, kid-injection, jwk-injection, missing-claims; token extraction from headers/cookies/body/raw; 18 tests |

---

## Phase 5 — Template Engine

> Goal: replace Nuclei's binary + YAML templates with an internal engine
> that the BLACKHORN orchestrator controls directly.
> Package: `pkg/template` — import as a Go library, zero CLI dependency.

| Component | Status | Notes |
|-----------|--------|-------|
| Template schema (YAML compatible) | ✅ | `pkg/template/schema.go` — superset of Nuclei format; YAML/JSON tags identical to nuclei/pkg/templates/; Severity, TagSet, Matcher, Extractor, SignedBundle; 6 matcher types (status/word/regex/size/binary/dsl); 5 extractor types (regex/kval/json/xpath/dsl); HTTP/DNS/TCP/UDP/File request definitions |
| Template parser | ✅ | `pkg/template/parser.go` — ParseYAML/JSON/Bytes/File/Directory; MustCompile; StrictSignature mode; SkipValidation/SkipCompile options; YAML document stream support |
| HTTP matcher engine | ✅ | `pkg/template/matcher.go` — EvaluateHTTPMatchers/DNS/Network; AND/OR conditions; Negative matchers; header/body/raw/status_code parts; DSL subset (contains, status_code==, len(body)>); ExtractHTTP with regex/kval/json extractors |
| DNS/TCP/UDP matchers | ✅ | EvaluateDNSMatchers (answer/authority/additional/question parts); EvaluateNetworkMatchers (TCP+UDP, binary/word/regex); DNSResponse/NetworkResponse structs |
| Signed template bundles | ✅ | `pkg/template/registry.go` — GenerateKeyPair (ed25519); SignTemplate; SignedBundle.Verify; AddTrustedKey; strict mode verifies against trusted key set |
| Community template feed | ✅ | Registry.PullFeed — fetches YAML stream or JSON feed; tag/count filters; auto-sets source="community"; ParseDirectory bulk loader |

---

## Phase 6 — New Modules + Coverage Expansion

> Goal: expand module coverage with 5 new attack-surface modules, grow
> detection databases in existing modules, and add full infrastructure
> (CI, benchmarks, fuzz) to the repo.

### Existing module coverage expansion

| Module | Before | After |
|--------|--------|-------|
| `fingerprint` | 60+ signatures | 160+ signatures (web servers, JS frameworks, CMS, ecommerce, Java, Python, .NET, WAF, IAM, monitoring, CDN, containers) |
| `truffler` | 45+ detectors | 110+ detectors (Azure, GCP, AWS extra, CI/CD, Twilio, Mailchimp, DigitalOcean, Shopify, Terraform, K8s, crypto exchange, SaaS) |
| `vulnscan` | 20 templates | 60+ templates (Spring Boot actuator, Swagger/OpenAPI, K8s/Docker API, Prometheus, Grafana, security headers audit, CVE indicators, Jenkins, GitLab, Portainer) |

### New modules

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `oauthprobe` | oauth2c (MIT) | ✅ | 12 checks: OIDC discovery, implicit flow, PKCE, open redirect redirect_uri (CWE-601), HTTP token endpoint, JWKS exposure, weak alg (none/HS256), no client auth, wildcard scope, state CSRF, introspection without auth, open client registration; 14 tests |
| `cacheprobe` | param-miner (Apache-2.0) | ✅ | 8 checks: cache detection, X-Forwarded-Host injection, X-Host injection, X-Forwarded-Scheme downgrade, fat GET body (James Kettle technique), Cache-Control misconfiguration, Vary:Origin missing, X-Original-URL override; cache-buster technique; 14 tests |
| `smuggler` | smuggler.py (MIT) + http2smugl (MIT) | ✅ | 6 checks: CL.TE timing (raw TCP socket), TE.CL timing, TE.TE obfuscation (5 variants: xchunked/space/cow/tab/x-te), differential response, HTTP/2 downgrade surface (h2.te), Connection hop-by-hop; raw socket approach avoids Go http.Client normalization; 14 tests |
| `bypass403` | 403bypasser (MIT) + byp4xx (MIT) | ✅ | Path manipulation (10+ variants), URL encoding, case variation, extension injection, HTTP method overrides (X-HTTP-Method-Override, TRACE, OPTIONS), IP header bypass (8 headers × 3 IPs), Referer bypass, Googlebot UA, X-Original-URL/X-Rewrite-URL, X-Forwarded-Proto; 14 tests |
| `openredirect` | OpenRedireX (MIT) + Oralyzer (MIT) | ✅ | 50+ payloads (protocol variants, encoding, backslash tricks, credentials, subdomain, fragment, whitespace, IPv4 variants, file/data URIs, SSRF); FUZZ placeholder mode; per-parameter injection; body reflection detection; redirect chain follow (5 hops); 14 tests |

### Infrastructure

| Component | Status | Notes |
|-----------|--------|-------|
| CI workflow | ✅ | `.github/workflows/ci.yml` — build + lint + test matrix (Go version declared in go.mod) + race detector + benchmarks artifact + govulncheck security scan + interface compliance check |
| Benchmarks | ✅ | `benchmarks/benchmarks_test.go` — 15 benchmarks covering urlparse, urldedup, fingerprint, truffler, corsaudit, vulnscan, xssreflect, oauthprobe, cacheprobe, bypass403, openredir |
| Fuzz targets | ✅ | `fuzz/fuzz_test.go` — 7 fuzz targets: FuzzURLParse, FuzzURLDedup, FuzzTrufflerContent, FuzzFingerprintPattern, FuzzJWTAuditParse, FuzzOpenRedirPayload, FuzzTemplateParseYAML, FuzzTemplateParseBytes |

---

## Phase 7 — Native Replacements for orbit-core Modules

> Goal: replace remaining orbit-core modules that still depend on external binaries
> or Python. All implemented as native Go, zero external dependencies.
> Guided by source analysis of orbit-core internal/modules/*.go.

### New modules

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `pathprobe` | orbit-core `sensitive` (native HTTP) | ✅ | 120+ curated paths across 11 categories (api-docs, config, vcs, actuator, diagnostics, backup, log, manifest, ci-cd, cloud, cms); simhash soft-404 filter; auth-wall + anti-bot detection; wildcard-200 host detection; configurable per category; 22 tests |
| `soft404` | orbit-core `soft404` (native HTTP) | ✅ | Exported `Classify(body, headers, code)` API for reuse by other modules; FNV-1a simhash fingerprinting (Charikar); wildcard-200 prober with mutex-safe cache; auth-wall + anti-bot + low-content + content-ratio detection; 20 tests |
| `takeover` | orbit-core `takeover` (native HTTP) | ✅ | 70+ service signatures from can-i-take-over-xyz (MIT); DNS CNAME resolution via stdlib net.Resolver; soft-404 body detection for 10+ service-specific patterns (GitHub Pages, Heroku, AWS S3, Azure, Netlify, Fastly, etc.); confidence scoring; 18 tests |
| `verbtamper` | orbit-core `verbtamper` (native HTTP) | ✅ | GET baseline per endpoint; CRITICAL for DELETE/PUT/PATCH bypassing 401/403/405; HIGH for meaningful response diff; MEDIUM for OPTIONS exposing dangerous verbs; LOW for TRACE enabled; X-HTTP-Method-Override bypass check; API-path prioritisation; SHA-256 body diff; 20 tests |
| `dnsaudit` | orbit-core `dig` (binary) | ✅ | SPF: missing, +all permissive, multiple records, too many lookups, missing qualifier; DMARC: missing, p=none, no rua; DKIM: 19 common selectors, revoked key detection; Wildcard DNS; Dangling NS; Zone Transfer (AXFR via raw TCP); stdlib net.Resolver only; 18 tests |

---

## Phase 8 — Offensive Toolkit Expansion

> Goal: implement the next wave of high-value offensive modules based on the
> ProjectDiscovery toolchain (alterx, cdncheck, asnmap, interactsh/nuclei-templates)
> and Mozilla/OWASP security-header research. All native Go, zero external binaries.

### New modules

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `ssrfprobe` | nuclei-templates SSRF (MIT) + interactsh (Apache-2.0) | ✅ | In-band cloud IMDS payload injection (AWS/GCP/Azure/DO/Alibaba/OCI); header injection (13 headers); open-redirect SSRF; OOB callback support (interactsh-compatible); 20 tests |
| `headeraudit` | Mozilla Observatory (MPL-2.0) + OWASP Secure Headers | ✅ | 20 checks: HSTS (missing/short/preload), CSP (missing/unsafe-inline/unsafe-eval), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, server/X-Powered-By/ASP.NET version disclosure, CORS wildcard, CORS credentials+wildcard, cookie Secure/HttpOnly/SameSite; 29 tests |
| `cdncheck` | projectdiscovery/cdncheck (MIT) | ✅ | 3-signal detection: IP CIDR (60+ ranges: Cloudflare/Fastly/Akamai/AWS/GCP/Azure/Imperva/Sucuri/DO), CNAME chain (45+ suffixes), HTTP headers (25+ fingerprints); provider + kind (cdn/waf/cloud) + method in findings; 26 tests |
| `alterx` | projectdiscovery/alterx (MIT) | ✅ | 13 built-in permutation patterns via Go text/template; 500+ built-in words (11 categories); word enrichment from existing subdomains; ExtraWords/ExtraPatterns/OnlyPatterns configurable; MaxResults cap; configurable limit; dedup; 21 tests |
| `asnmap` | projectdiscovery/asnmap (MIT) | ✅ | Team Cymru DNS IP-to-ASN (public, no key); RIPE Stat API prefix lookup (public, free); supports ASN/IP/domain input; fallback finding on API failure; IPv4+IPv6; dedup; 19 tests |

---

## Phase 9 — Depth Expansion

> Goal: expand attack surface coverage with XXE injection, DNS bruteforce,
> JS URL extraction. All native Go, zero external dependencies.

### New modules

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `xxeprobe` | nuclei-templates XXE (MIT) | ✅ | 10 payloads: Linux/Windows file read, /proc/self/environ, AWS+GCP IMDS SSRF, error-based, SVG XXE; OOB payload support; in-band file marker + cloud metadata + XML parser error detection; 20 tests |
| `shuffledns` | projectdiscovery/shuffledns (MIT) | ✅ | 200+ built-in wordlist (15 tiers); concurrent DNS resolution via stdlib net.Resolver; wildcard detection (2 random probes → IP fingerprint); custom resolver support; ExtraWords/OnlyWords configurable; 20 tests |
| `urlfinder` | projectdiscovery/urlfinder (MIT) | ✅ | 9 extraction strategies: HTML href/src/action, fetch()/axios()/XHR, API base variables, quoted strings, template literals, sourceMappingURL, webpack chunks, require/import, absolute URLs; scope filtering; dedup; RawContent mode; 23 tests |
| `mapcidr` | projectdiscovery/mapcidr (MIT) | ✅ | 7 ops: expand (cap 65536), aggregate (greedy supernet merge), count (big.Int), filter-private/filter-public, split (sub-CIDR generation), contains; RFC-1918 + loopback + link-local + ULA private ranges; IPv4+IPv6; dedup; 29 tests |

---

## Phase 10 — Infrastructure + Notification + CT Discovery

> Goal: add CT log subdomain discovery, multi-channel notification dispatch,
> and complete remaining tool coverage from the reference list.

### New modules

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `tlsfinder` | sslmate/certspotter + crt.sh | ✅ | CT log subdomain discovery via crt.sh + Certspotter REST APIs; wildcard stripping; apex scope filter; dedup across sources; IncludeWildcard flag; multi-domain fan-out; configurable base URLs for testing; 25 tests |
| `notify` | projectdiscovery/notify (MIT) | ✅ | 6 providers: Slack (incoming webhook), Discord (webhook embed), Telegram (Bot API), MS Teams (MessageCard), generic webhook (JSON POST), custom (Go text/template body); findings_json dispatch via Options; multi-provider + multi-message fan-out; custom HTTP headers; soft failure per provider; 25 tests |
| `proxify` | projectdiscovery/proxify (MIT) | ✅ | In-process HTTP intercepting proxy; match/replace rules (URL/request-header/request-body/response-header/response-body targets); batch mode + live intercept mode; CONNECT tunnel support; regex backreference replace; finding emission per rule; 24 tests |
| `uncover` | projectdiscovery/uncover (MIT) | ✅ | 8 sources: Shodan InternetDB (keyless), Censys, FOFA, Hunter.how, ZoomEye, 360Quake, Netlas, PublicWWW; sensitive port detection; known vuln emission; multi-source fan-out; soft failure per source; dedup; 26 tests |
| `cloudlist` | projectdiscovery/cloudlist (MIT) | ✅ | 7 providers: AWS (IMDSv2 + S3), GCP (metadata server), Azure (IMDS), DigitalOcean, Cloudflare zones, Namecheap (XML API), Fastly; cloud_instance/cloud_storage/cloud_dns_zone/cloud_domain/cloud_cdn_service finding types; soft failure per provider; dedup; 20 tests |
| `interactsh` | projectdiscovery/interactsh (Apache-2.0) | ✅ | OOB interaction server for blind vuln detection; HTTP + DNS + SMTP + FTP + LDAP payload generation with correlation ID; self-hosted HTTP + DNS listeners; remote interact.sh-compatible server polling; interaction store (race-safe); oob_payload + oob_interaction finding types; severity by protocol (HTTP=High, DNS=Low); 23 tests |
| `vulnx` | shodan-labs/vulnx (MIT) + NVD public | ✅ | 40+ CVEs across 18 technology families (Apache, nginx, WordPress, Drupal, Joomla, Laravel, Spring, Log4j, Struts, Jenkins, GitLab, Docker, Kubernetes, OpenSSL, PHP, Redis, Elasticsearch, Confluence, Exchange); tech fingerprinting via headers + body; version constraint matching; MinCVSS filter; optional NVD API enrichment; ExtraVulns extension point; known_cve finding type; 22 tests |
| `recon` | OWASP Amass (Apache-2.0) + PD passive | ✅ | 6 passive OSINT sources: crt.sh CT log, Wayback Machine CDX, HackerTarget, RapidDNS, urlscan.io, stdlib DNS (A/AAAA/MX/NS/TXT); MaxSubdomains cap; multi-domain + RawContent input; subdomain/historical_url/scanned_url/dns_record finding types; RFC-1918 detection; dedup; soft failure per source; 22 tests |

---

## Phase 11 — URL Aggregation, Fuzzing, Extended Crawling & Advanced Probing

> Goal: feature-parity with the most-used ProjectDiscovery recon tools, extended with MurmurHash3 favicon fingerprinting, multi-source URL aggregation, and deep JS/form extraction.

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `gau` | lc/gau + bp0lr/gauplus (MIT) | ✅ | 4 sources: Wayback CDX (`fl=original`, single-column rows), Common Crawl (multi-index `collinfo.json` + NDJSON), AlienVault OTX (paginated, `HasNext`), URLScan.io; blacklist/whitelist by file extension; MaxURLs cap; multi-domain + RawContent input; dedup; soft failure per source; 28 tests |
| `ffuf` | ffuf/ffuf (MIT) | ✅ | 4 modes: `dir`/`query`/`vhost`/`body`; `Filter{Codes, FilterCodes, MinSize, MaxSize, MinWords, MaxWords}`; 80+ built-in dir paths, 40+ params, 40+ vhost prefixes; `custom_fuzz` URL template; `FUZZ` placeholder in post_body; redirect capture; extra headers; severity by status code; 28 tests |
| `katana` | projectdiscovery/katana (MIT) | ✅ | Extended crawler: BFS with depth control; form field extraction (input/textarea/select + method/action); JS endpoint extraction (fetch/axios/XHR/import/script-src/API-path via `q` char class); asset URL collection; robots.txt Disallow seeding; sitemap.xml urlset+sitemapindex seeding; scope=host/domain/all; eTLD+1 heuristic; errgroup fan-out; 28 tests |
| `httpxpro` | projectdiscovery/httpx (MIT) | ✅ | Favicon MurmurHash3-32 (Shodan/Censys compatible, base64-encoded icon bytes); CDN detection (13 header signatures); WAF detection (8 header signatures + server patterns); TLS metadata (version, cipher, issuer, expiry, SANs); security header grading (HSTS/CSP/X-Frame/X-Content-Type-Options); SHA256 body hash; technology stack detection (21 patterns); 32 tests |

### Expansions (Phase 11)

| Module | Change | Notes |
|--------|--------|-------|
| `fingerprint` | 141 → **263 signatures** (+122) | New categories: DevOps/CI (Jenkins, GitLab, Gitea, Gogs, Jira, Confluence, SonarQube, Nexus, Artifactory), Observability (Grafana, Prometheus, Kibana, Splunk, Zabbix, Nagios, PagerDuty), Security/WAF (Barracuda, NetScaler, Incapsula, Reblaze, Wordfence, Comodo), CDN/Hosting (Cloudflare Workers, GitHub Pages, Fly.io, DigitalOcean, BunnyCDN, KeyCDN, StackPath), Auth/Backend (Cognito, Firebase Auth, Supabase, PocketBase, Appwrite), Frontend (Tailwind, MUI, Chakra, Ant Design, Bulma, Foundation, Semantic UI, FontAwesome), JS Libraries (Lodash, Underscore.js, Moment.js, Chart.js, D3.js, Three.js, GSAP), Analytics/CRM (GTM, Adobe Analytics, Mixpanel, Amplitude, Segment, FullStory, Heap, Intercom, Zendesk, Drift, Crisp), OS (FreeBSD, Alpine, Amazon, Oracle), Frameworks (Struts, Grails, Ktor, Helidon, Javalin, CherryPy, Bottle, Falcon, Sanic, Lumen, Symfony, CodeIgniter, CakePHP, Yii, Zend, Slim, TYPO3, MODx, ExpressionEngine), Network gear (OpenWRT, pfSense, FortiGate, PAN-OS, Cisco ASA, Juniper, MikroTik), Infrastructure (Portainer, Rancher, ArgoCD, Vault, Consul, Nomad, MinIO, Nextcloud, Owncloud), Chat/Forum (Mattermost, Rocketchat, Discourse) |
| `truffler` | 89 → **123 detectors** (+34) | New categories: Cloud expanded (Azure Storage/Cosmos DB, GCP service account/API key, Firebase DB URL, Cloudflare API Token), DB connection strings (PostgreSQL, MySQL, MongoDB Atlas, Redis URL with password), Payment/Comms (PayPal, Square, SendGrid, Mailchimp, Twilio, Vonage, Postmark), VCS/Crypto (RSA/EC/PKCS8 private key headers, GitLab `glpat-`, npm `npm_`), Social/Productivity (Facebook App Secret, YouTube API Key, Notion `secret_`, Linear `lin_api_`), Infrastructure (HashiCorp Vault `s.`, Docker Hub `dckr_pat_`), PII (SSN `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`, IBAN), AI/ML (OpenAI `sk-`, Anthropic `sk-ant-api0+-`, Hugging Face `hf_`, Replicate `r8_`) |

---

## Phase 12 — Injection Techniques + UDP Surface + Real-Target Hardening

> Goal: implement SQL injection detection with three techniques (error-based,
> boolean-blind, time-blind), add UDP service discovery module, and apply
> fixes from real-target validation against tetraquimicametal.com.br.

### New modules

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `udpprobe` | nmap UDP scan + naabu UDP | ✅ | 21 built-in probes: DNS, NTP, SNMP v1/trap, SSDP, mDNS, NetBIOS-NS, TFTP, Memcached, IKE, QUIC, DHCP, LDAP, Syslog, WireGuard, L2TP, Kerberos, Echo, Chargen, RADIUS, RPC/portmapper; raw UDP via net.DialContext; protocol-specific payload + response validator; errgroup fan-out; port/service filter; 32 tests |
| `sqli` | sqlmap (GPL-2.0, reimpl) | ✅ | 3 techniques: error-based (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/DB2/generic — signatures from sqlmap/data/xml/errors.xml), boolean-based blind (true/false condition pairs, 20%+ body-length ratio threshold), time-based blind (SLEEP/pg_sleep/WAITFOR/DBMS_PIPE/{SLEEP} placeholder); GET parameter injection; per-param fan-out with errgroup.SetLimit; io.LimitReader on all reads; dedup by param+technique; dbms filter; techniques filter; NewWithClient testability; 29 tests |

---

## Phase 13 — Web Attack Coverage: Injection, Framing, Rate Limiting

> Goal: comprehensive web injection coverage (LFI, CMDi, NoSQLi), client-side
> attack vectors (Clickjacking, Host Header Injection), and rate limit bypass detection.

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `lfi` | PayloadsAllTheThings LFI (MIT) + nuclei-templates lfi/ (MIT) | ✅ | 4 traversal techniques (classical/URL-encoded/double-encoded/dot-encoded), 7 depths (1–12), null-byte, absolute Unix + Windows paths, PHP wrappers (filter/base64/input/data/expect), obfuscated patterns (....//); 7 file families (/etc/passwd/shadow/hosts/environ/access.log, win.ini, boot.ini); tag filter (unix/windows/absolute/wrapper/nullbyte/encoded/obfuscated); NewWithProbes; 30 tests |
| `cmdi` | commix (GPL-3.0, reimpl) + PayloadsAllTheThings CMDi (MIT) | ✅ | 2 techniques: results-based (canary via echo+operators: ; && || \| ` $() %0a \\n IFS brace) + time-based (sleep/ping-c/WAITFOR/PowerShell); Unix + Windows operators; per-session random canary (crypto/rand hex); os filter (unix/windows/generic); techniques filter R,T; NewWithProbes; 24 tests |
| `nosqli` | NoSQLMap (MIT) + PayloadsAllTheThings NoSQLi (MIT) | ✅ | 3 techniques: error-based (MongoDB/Redis/CouchDB/generic error signatures), boolean-based blind ($ne/$gt/$regex true/false response ratio), time-based ($where JS sleep); 3 vectors (query GET param / JSON POST body / header); db filter; techniques filter; NewWithClient; 22 tests |
| `hostinjection` | PortSwigger Host Header research + param-miner (Apache-2.0) | ✅ | 13 probes: Host/X-Forwarded-Host/X-Host/X-Forwarded-Server/X-HTTP-Host-Override/Forwarded RFC-7239/X-Original-URL; reflection detection (body+all headers); SSRF via Host→IMDS (169.254.169.254); cache-poisoning context (X-Cache/Age); password-reset context; attacker_host/attacker_ip configurable; dedup; NewWithProbes; 19 tests |
| `clickjacking` | OWASP Clickjacking Cheat Sheet + nuclei-templates (MIT) | ✅ | 5 checks: missing XFO+CSP (High), ALLOWALL deprecated (High), ALLOW-FROM deprecated (Medium), unknown XFO value (Medium), CSP frame-ancestors: * (High), XFO+CSP conflict (High); pure header analysis, no injection; HTTP 4xx skipped; multi-URL fan-out; 21 tests |
| `ratelimit` | OWASP API4:2023 + Burp rate-limit extension techniques | ✅ | 2 checks: missing (burst N rapid requests, no 429/503 → Medium) + bypass via IP header rotation (7 headers × 20 IP pool; 429 base confirmed first; bypass confirmed by non-429 response → High); burst_count/burst_delay/bypass_ips configurable; check filter; NewWithClient; 18 tests |

### Bug fixes (from real-target test)

| Module | Fix | Impact |
|--------|-----|--------|
| `tlsaudit` | TLS 1.3 ciphers (`TLS_AES_*`, `TLS_CHACHA20_*`) now correctly detected as PFS — RFC 8446 mandates ephemeral key exchange, but names don't contain "ECDHE" | Eliminated false-positive `no_forward_secrecy` for TLS 1.3 connections |
| `vulnx` | CVE-2021-23017 (nginx resolver 1-byte overwrite) added version range regex `< 1.20.2`; empty VersionRe was matching nginx 1.22.1 (patched) | Eliminated false-positive CVE finding on patched nginx versions |
| `vulnscan` | `exposed-minio-console` changed from `MatchersCondition: "or"` + status=200 to `"and"` requiring body containing `"minio/MinIO"` | Eliminated false-positive on React SPAs that return 200 for any path |

### Expansions (Phase 12)

| Module | Change | Notes |
|--------|--------|-------|
| `vulnscan` | 60 → **101 templates** (+41) | New sections: Spring Boot Actuator extended (health/beans/mappings/loggers), K8s/Container (metrics-server/dashboard/swarm/containerd), DB/Cache (redis-info/mongodb/elasticsearch), CI/CD (jenkins-script-console/circleci/sonarqube/nexus), CVEs (CVE-2022-1388/CVE-2021-26855/CVE-2021-41773/CVE-2023-23397/CVE-2022-47966/CVE-2023-34362/CVE-2023-44487), Cloud Storage (s3/azure-blob/gcs), CMS (wordpress-xmlrpc/debug/drupal/joomla), Observability (jaeger/zipkin/influxdb), Secrets (env-secrets/env-local/env-prod/laravel/symfony/git-config), API (openapi-json/yaml/graphql-voyager/api-docs), Services (adminer/vault-ui/consul/minio-console), Disclosure (server-info/nginx-status/apache-status/iis-short-name/trace-method), Webshell indicators; added `Body` field to Template struct for POST payloads |

---

## Phase 14 — Advanced Attack Surface: Bypass, Object Injection, API Security

> Goal: advanced CORS bypass techniques, insecure deserialization detection,
> IDOR enumeration, clickjacking protection auditing, rate limit bypass,
> and comprehensive OWASP API Security Top 10 checks.

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `cors2` | CORStest (MIT) + Corsy (MIT) + PortSwigger research | ✅ | 12 probes: random origin reflection (High/Critical), null origin (High/Critical), subdomain bypass (High/Critical), prefix/suffix bypass, HTTP downgrade, wildcard+credentials, no-scheme, backslash, localhost/loopback trust; detectReflection checks body+all headers; ACAC:true → Critical; NewWithProbes; 21 tests |
| `deserial` | ysoserial gadgets (Apache-2.0) + phpggc (MIT) | ✅ | 4 formats: Java (magic bytes 0xACED/rO0AB, error patterns), PHP (stdClass/phpggc-eval/array O:/a:/s:, unserialize errors), Python (pickle protocol 0+2 stop opcode), .NET (BinaryFormatter magic + JSON.NET TypeNameHandling); GET param + POST body vectors; format filter; errDetect(500 fallback); NewWithProbes; 18 tests |
| `idor` | OWASP API1:2023 / Broken Object Level Authorization | ✅ | Numeric ID extraction from path segments + query params; offset range ±1 to ±MaxOffset (default 5); High finding on 200 where baseline 403/404; Critical when PII detected (email/phone/SSN/password/token/secret/credit-card/ssn-field patterns); original_url preserved; dedup by id_type+tested_id; bearer auth option; NewWithClient; 17 tests |
| `clickjacking` | OWASP Clickjacking Cheat Sheet + nuclei-templates (MIT) | ✅ | 5 checks: missing XFO+CSP (High), ALLOWALL deprecated (High), ALLOW-FROM deprecated (Medium), unknown XFO value (Medium), CSP frame-ancestors: * (High), XFO+CSP conflict (High); 4xx responses skipped; multi-URL fan-out; 21 tests |
| `ratelimit` | OWASP API4:2023 + Burp rate-limit techniques | ✅ | burst-missing (N rapid, no 429/503 → Medium) + bypass (7 bypass headers × 20 IP pool; base-429 confirmed first → High); burst_count/burst_delay/bypass_ips/check filter; 18 tests |
| `hostinjection` | PortSwigger Host Header + param-miner (Apache-2.0) | ✅ | 13 probes across Host/X-Forwarded-Host/X-Host/X-Forwarded-Server/X-HTTP-Host-Override/Forwarded/X-Original-URL; SSRF→IMDS probe (Critical); password-reset+cache-poisoning context probes; attacker_host/attacker_ip options; 19 tests |
| `nosqli` | NoSQLMap (MIT) + PayloadsAllTheThings (MIT) | ✅ | 3 techniques (E/B/T) × MongoDB/Redis/CouchDB/generic; $ne/$gt/$regex boolean blind; $where JS sleep time-based; JSON POST body vector; db+techniques filter; 22 tests |
| `apiaudit` | OWASP API Security Top 10 2023 (CC-BY 4.0) | ✅ | 6 checks: API5 HTTP method bypass, API8 debug/swagger/actuator/metrics endpoints + missing security headers + sensitive field exposure, API9 old version accessibility, API2 unauthenticated JSON API access, API6 sensitive business flow endpoints; categories filter; NewWithClient; 20 tests |

---

## Phase 15 — WAF Detection & CRLF Injection

> Goal: WAF fingerprinting via header/cookie/body patterns (wafw00f-based database)
> plus CRLF injection scanning with multi-encoding variants, query param and header
> injection vectors, and Set-Cookie injection detection.

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `wafscan` | wafw00f (BSD-2, fingerprint DB) + bypass-firewalls-by-DNS-history | ✅ | 18 WAF signatures: Cloudflare, AWS WAF, ModSecurity, Imperva/Incapsula, Akamai, Barracuda, Sucuri, F5 BIG-IP ASM, Citrix NetScaler, Fortinet FortiWeb, WordFence, Azure Front Door, Fastly, Varnish, Reblaze, StackPath, DenyAll, Radware AppWall; 2-phase: header fingerprint (clean request) + attack probe (%27+OR, %3Cscript%3E, ..%2F traversal); generic block detection (200→403 diff); NewWithSignaturesAndClient testability; dedup; 22 tests |
| `crlf` | crlfuzz (MIT) + PortSwigger response-splitting research | ✅ | 11 CRLF encoding variants (plain/lf-only/cr-only/double-encode/double-lf/unicode/tab-space/null-inject + Unicode %E5%98%8A%E5%98%8D); 2 injection locations (query param values / request headers); Set-Cookie injection probes; InjectedHeader canary detection in response; LocationQuery/LocationHeader filter; headerTargets (Referer/User-Agent/X-Forwarded-For); NewWithProbesAndClient testability; dedup by url+probe_id; 21 tests |

### Test suite snapshot (Phase 15)

| Module | Tests | Cumulative |
|--------|-------|-----------|
| `wafscan` | 22 | 1329 |
| `crlf` | 21 | 1350 |

**Total: 1350 tests across 74 packages ✓**

---

## Phase 16 — Client-Side Injection & Redirect

> Goal: open redirect detection (12 bypass variants), Server-Side Template
> Injection (SSTI) across 12 engines with math-expression evaluation probes.

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `openredirect` | dalfox-openredirect (MIT) + PayloadsAllTheThings/Open-Redirect (MIT) | ✅ | 12 probes: absolute-https/http, double-slash, triple-slash, backslash, https-colon-noslash, attacker-as-param, tab-bypass, null-byte, at-sign-bypass, double-encode, whitespace-prefix; redirect param keyword detection (35 keywords: redirect/url/next/goto/dest/return/…); Location header + body attacker-domain detection; no-redirect client for direct Location inspection; attacker domain configurable; NewWithProbesAndClient testability; 19 tests |
| `ssti` | tplmap (MIT) + PayloadsAllTheThings SSTI (MIT) | ✅ | 24 probes across 12 engines: generic ({{7*7}} / ${7*7} / #{7*7} / <%=7*7%> / large-multiply / add), Jinja2 (class/string-multiply/config), Twig, Freemarker (math/assign), Smarty (math/phpinfo), Velocity (math/class), Mako (math/expression), ERB (math/expression), Liquid, Tornado, Nunjucks, Handlebars, Pebble; false-positive guard (Expected must not appear in Inject); engine filter; query param injection; dedup; NewWithProbesAndClient; 21 tests |

### Test suite snapshot (Phase 16)

| Module | Tests | Cumulative |
|--------|-------|-----------|
| `openredirect` | 19 | 1369 |
| `ssti` | 21 | 1390 |

**Total: 1390 tests across 76 packages ✓**

---

## Phase 17 — XSS, WebDAV

> Goal: reflected XSS detection with canary-based confirmation and context
> classification; WebDAV misconfiguration detection (OPTIONS/PROPFIND/PUT/MKCOL).

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `xss` | dalfox (MIT) + XSStrike (MIT) + PayloadsAllTheThings XSS (MIT) | ✅ | 19 probes: HTML context (script/img-onerror/svg-onload/body-onload/a-href-javascript/details-ontoggle/script-src/img-onerror-quotes), attribute context (dquote-break/squote-break/close-tag/event-handler), script context (js-break-squote/dquote/template-literal), bypass (case/entity-src/null-byte); unique canary per probe (BHXSS+12hex); classifyReflection: script-block / event-handler (not &lt;-prefixed) / verbatim payload; false-positive guard (payload-in-inject check); context filter; NewWithProbesAndClient; 19 tests |
| `webdav` | nuclei-templates/network/webdav (MIT) | ✅ | 5 checks: options-dav-header (DAV: response header → Medium), options-dangerous-methods (PUT/DELETE/PROPFIND/MKCOL in Allow → High), propfind-listing (207 Multi-Status → High), put-file-upload (201 Created on random file PUT → Critical, auto-cleanup DELETE), mkcol-directory (201 on MKCOL → High, auto-cleanup DELETE); check_id in Extra; dedup; 18 tests |

### Test suite snapshot (Phase 17)

| Module | Tests | Cumulative |
|--------|-------|-----------|
| `xss` | 19 | 1409 |
| `webdav` | 18 | 1427 |

**Total: 1427 tests across 78 packages ✓**

---

## Phase 18 — JWT Security, HTTP Smuggling

> Goal: JWT token security analysis (7 checks) and HTTP Request Smuggling
> timing-based detection (5 variants: CL.TE, TE.CL, TE.TE, CL=0).

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `jwt` | jwt_tool (MIT, ticarpi) + jwt-auditor (MIT) | ✅ | 7 checks: alg-none (Critical), weak-secret brute-force (24 common secrets, Critical), missing-algorithm (High), symmetric-algorithm info (HS256/384/512), expired/no-expiry/long-lived, kid-injection (path traversal/SQL/URL in kid), jku-header (attacker key set URL), jwk-embedded, sensitive-claims (email/password/ssn/credit_card/phone/address); token extraction from: Options/RawContent (eyJ substring scan)/Bearer header/Set-Cookie/body; dedup; NewWithClient; 20 tests |
| `smuggling` | smuggler (MIT, defparam) + PortSwigger research | ✅ | 5 probes: CL.TE basic (CL>TE body), TE.CL basic (TE then CL mismatch), TE.TE xchunked (dual Transfer-Encoding), TE.TE space (mangled header), CL=0 (body beyond CL); raw TCP via net.Dial (bypasses Go http.Client); timing-based detection (elapsed > 4s threshold); NewWithDialer testability; dedup; 10 tests |

### Test suite snapshot (Phase 18)

| Module | Tests | Cumulative |
|--------|-------|-----------|
| `jwt` | 20 | 1462 |
| `smuggling` | 10 | 1472 |

**Total: 1472 tests across 81 packages (expected) ✓**

---

## Phase 19 — OAuth 2.0 Security, Prototype Pollution

> Goal: OAuth 2.0 misconfiguration analysis (8 checks, pure URL analysis + OIDC
> discovery fetch) and Server-Side Prototype Pollution detection (9 probes:
> query bracket/dot/url-encoded + JSON __proto__/constructor patterns).

| Module | Replaces | Status | Notes |
|--------|----------|--------|-------|
| `oauth2` | oauthscan (various) + PortSwigger OAuth research | ✅ | 8 checks: implicit-flow (response_type=token), missing-state (CSRF), missing-pkce (no code_challenge), http-endpoint, broad-scope (*, all, admin, write...), token-in-url/fragment (access_token/id_token in query or fragment), open-redirect-uri (suspicious redirect_uri), discovery-endpoint (OIDC .well-known fetch → implicit supported + no PKCE); pure URL analysis, no active probing; NewWithClient; dedup; 19 tests |
| `prototype` | ppmap (MIT, kleiton0x00) + prototype-pollution-checker | ✅ | 9 probes: query (bracket __proto__[x], constructor[prototype][x], dot __proto__.x, constructor.prototype.x, url-encoded %5F%5F); JSON body (__proto__ direct, constructor.prototype, nested data.__proto__, merge); canary-based (BHJSPP+12hex); LocationQuery (GET + raw bracket append) + LocationJSON (POST application/json); dedup; filterProbes by location; NewWithProbesAndClient; 22 tests |

### Test suite snapshot (Phase 19)

| Module | Tests | Cumulative |
|--------|-------|-----------|
| `oauth2` | 19 | 1491 |
| `prototype` | 22 | 1513 |

**Total: 1513 tests across 83 packages ✓**

---

## Phase 20 — Cobertura Universal + Observabilidade + Performance

> Goal: todos os módulos com ≥17 testes; todos com slog observability;
> otimizações de performance nos módulos críticos (342× vs testssl.sh confirmado).

### Performance benchmarks

| Módulo | Original | BH | Speedup | Técnica |
|--------|---------|-----|---------|---------|
| `tlsaudit` | testssl.sh ~144s | ~420ms | **342×** | pipeline paralelo: protocolos+ciphers+headers simultâneos |
| `portscanner` | 25 threads, 3s timeout | 500 threads, 2-phase adaptive | **12×** | fast 150ms probe → retry timeout only at 3s |
| `dnsprobe` | sequential records | parallel errgroup + resolver racing | **7×** | todos resolvers simultâneos, primeiro responde vence |
| `gau` | blocking CC prefetch | background goroutine prefetch | **70×** | commoncrawl indexes prefetched antes do loop |
| `subdiscovery` | 30s timeout | 10s + HTTP/2 transport tuned | **3×** | MaxIdleConnsPerHost + ForceAttemptHTTP2 |

### Expansão de cobertura (todos ≥17 testes)

| Módulos expandidos | De | Para |
|--------------------|----|------|
| graphql, openredir, paramdisc, secretscan, smuggler, tlsaudit, urlparse, vulnscan, webprobe, portscan, subdiscovery | 13–14 | 17 |
| cacheprobe, wayback, bypass403, crawler, dnsprobe, smuggling, urldedup, whois, xssscan, sstiprobe | 13–16 | 17 |

### Observabilidade slog (100%)

`alterx`, `corsaudit`, `mapcidr`, `urldedup`, `urlparse`, `wayback` — slog adicionado.
**75/75 módulos com slog** (100%).

### Confidence scoring (dicas.md §4 + §7) — 100% cobertura

**75/75 módulos com `confidence` em Extra[]** — cobertura completa.

| Grupo | Módulos | Confidence típico | Razão |
|-------|---------|------------------|-------|
| Canary/marker definitivo | `xxeprobe`, `cmdi` (results), `sstiprobe`, `ssrfprobe`, `portscanner`, `interactsh` | 0.95–0.99 | Canary/token encontrado na resposta — definitivo |
| Payload confirmado | `lfi`, `ssti`, `xssscan` (confirmed), `openredirect`, `verbtamper` (TRACE/bypass) | 0.90–0.95 | Payload refletido/executado na resposta |
| Misconfiguration direta | `cors2`, `graphql`, `oauthprobe`, `jwtaudit`, `headeraudit`, `clickjacking`, `tlsaudit` | 0.90–0.99 | Misconfiguration confirmada em header/certificado |
| Signature match | `wafscan` (probe), `sqli`, `nosqli`, `vulnscan`, `smuggler`, `apiaudit`, `dnsprobe`, `tlsfinder` | 0.85–0.90 | Signature/fingerprint correspondeu |
| Comportamento diferencial | `bypass403`, `crlf`, `hostinjection`, `idor`, `ratelimit`, `verbtamper` (diff) | 0.75–0.90 | Comportamento diferente com/sem payload |
| Passivo/arquivo | `wayback`, `gau`, `paramspider`, `xss`, `xssreflect`, `alterx`, `urlfinder` | 0.70–0.80 | URL/param de fonte passiva — pode estar desatualizado |
| Entropy-based | `secretscan`, `truffler` | 0.75–0.98 | **Dinâmico**: razão entropy define confiança |
| Determinístico | `urldedup`, `urlparse`, `mapcidr` | 0.99 | Operação matemática/lógica — sempre correto |

### Test suite snapshot (Phase 20 — final)

| Métrica | Valor |
|---------|-------|
| Total de testes | **1544** |
| Pacotes | 75 |
| Menor cobertura | 17 testes |
| Go version | 1.26.4 |
| Módulos com slog | 75/75 (100%) |
| Módulos com confidence | **75/75 (100%)** |
| Falhas | **0** |

**Total: 1544 tests, 0 falhas, mínimo 17 por módulo, 75/75 módulos com confidence scoring ✓**

---

## Integration Milestone

> When all Phase 1–3 modules are complete, `orbit-core` can be updated to
> use `blackhorn-modules` as a Go dependency. Each external wrapper in
> `orbit-core/modules/external/` is replaced one-for-one by the native
> implementation. The executor interface stays unchanged.

```
go.mod (orbit-core):
  require github.com/DonatoReis/blackhorn-modules v0.x.x
```

Executor change per module:
```go
// Before (external binary):
m := external.NewSubfinder(binPath)

// After (native lib):
m := subdiscovery.New()
```

---

## Non-Goals

- **wpscan replacement** — WordPress vulnerability data is proprietary.
  Substitute: NVD CVE feed filtered by WordPress CPE, or WPScan REST API.
- **Browser automation** — out of scope; use a dedicated headless module if needed.
- **Network packet capture** — requires elevated privileges; not compatible
  with the BLACKHORN security model.

---

## Versioning

`blackhorn-modules` follows semver. Phase 1 ships as `v0.1.0`.
Breaking interface changes in `pkg/module` bump the minor version.
Individual module additions are patch releases.

The `pkg/module.Module` interface is considered stable after `v1.0.0`.
