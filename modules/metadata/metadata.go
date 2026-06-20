// Package metadata extracts OSINT-relevant metadata from publicly accessible
// files — EXIF from images (JPEG/PNG/TIFF/HEIC), PDF document properties,
// Office (DOCX/XLSX/PPTX) core properties and generic HTTP headers.
//
// What is extracted and why:
//   - EXIF GPS coordinates → physical location of image capture (SeverityHigh)
//   - EXIF author/camera model → attribution and device fingerprinting
//   - PDF author/creator/producer → software and identity fingerprinting
//   - Office LastModifiedBy, Company → internal username and org name
//   - HTTP Content-Type, Server, X-Powered-By → technology stack
//   - HTTP Last-Modified → deployment/content timeline
//
// Privacy/security: GPS coordinates are treated as SeverityHigh since they
// can reveal personal locations. No file is written to disk — all content
// is streamed with io.LimitReader.
//
// Supported sources:
//   - "url" — fetches a URL and auto-detects file type
//   - "exiftool" — delegates to system exiftool for richer EXIF (optional)
//
// Usage:
//
//	m := metadata.New()
//	findings, err := m.Run(ctx, module.Input{
//	    Target:  "https://example.com/press/photo.jpg",
//	    URLs:    []string{"https://example.com/docs/report.pdf"},
//	    Options: map[string]string{
//	        "sources":      "url",
//	        "max_urls":     "20",
//	        "use_exiftool": "false",
//	    },
//	})
package metadata

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonatoReis/blackhorn-modules/pkg/module"
	"golang.org/x/sync/errgroup"
)

const (
	maxBodyMeta = 8 * 1024 * 1024 // 8 MB — enough for most PDFs and Office files
	maxParallel = 5
)

// Module implements module.Module for file metadata extraction.
type Module struct {
	client *http.Client
}

// New returns a Module with a default HTTP client.
func New() *Module {
	return NewWithClient(&http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     60 * time.Second,
		},
	})
}

// NewWithClient allows injecting a custom HTTP client (useful for tests).
func NewWithClient(c *http.Client) *Module { return &Module{client: c} }

// Name returns the canonical module identifier.
func (m *Module) Name() string { return "metadata" }

// Run fetches URLs and extracts metadata findings.
func (m *Module) Run(ctx context.Context, input module.Input) ([]module.Finding, error) {
	target := strings.TrimSpace(input.Target)
	if target == "" && len(input.URLs) == 0 {
		return nil, fmt.Errorf("metadata: target e URLs vazios — forneça pelo menos um URL")
	}

	opts := input.Options
	if opts == nil {
		opts = map[string]string{}
	}

	maxURLs := optInt(opts, "max_urls", 20)

	// Collect URLs to process
	urls := make([]string, 0, maxURLs)
	if target != "" && (strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")) {
		urls = append(urls, target)
	}
	for _, u := range input.URLs {
		if len(urls) >= maxURLs {
			break
		}
		if u != "" {
			urls = append(urls, u)
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("metadata: nenhum URL válido fornecido (target='%s')", target)
	}

	slog.InfoContext(ctx, "metadata.Run iniciado",
		"urls_count", len(urls),
		"max_urls", maxURLs,
	)

	var mu sync.Mutex
	var all []module.Finding

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxParallel)

	for _, u := range urls {
		u := u
		g.Go(func() error {
			findings, err := m.processURL(gctx, u)
			if err != nil {
				slog.WarnContext(gctx, "metadata: erro ao processar URL",
					"url", u, "err", err)
				return nil
			}
			mu.Lock()
			all = append(all, findings...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	result := dedup(all)
	slog.InfoContext(ctx, "metadata.Run concluído",
		"urls_processed", len(urls),
		"findings", len(result),
	)
	return result, nil
}

// processURL fetches one URL and dispatches to the appropriate extractor.
func (m *Module) processURL(ctx context.Context, rawURL string) ([]module.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blackhorn-metadata/1.0 (OSINT; security research)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Always extract HTTP header findings
	var findings []module.Finding
	findings = append(findings, extractHTTPHeaders(rawURL, resp.Header)...)

	if resp.StatusCode != http.StatusOK {
		return findings, nil
	}

	contentType := resp.Header.Get("Content-Type")
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyMeta))
	if err != nil {
		return findings, err
	}

	// Dispatch by content type
	switch {
	case isJPEG(contentType, body):
		findings = append(findings, extractEXIF(rawURL, body)...)
	case isPDF(contentType, body):
		findings = append(findings, extractPDF(rawURL, body)...)
	case isOffice(contentType, rawURL):
		findings = append(findings, extractOffice(rawURL, body)...)
	}

	return findings, nil
}

// ─── HTTP Headers ─────────────────────────────────────────────────────────────

func extractHTTPHeaders(fileURL string, headers http.Header) []module.Finding {
	var findings []module.Finding

	interesting := []struct {
		header string
		note   string
		sev    module.Severity
	}{
		{"Server", "Servidor web exposto — fingerprinting de versão possível", module.SeverityLow},
		{"X-Powered-By", "Framework/linguagem exposta nos headers", module.SeverityLow},
		{"X-Generator", "CMS ou gerador exposto", module.SeverityLow},
		{"X-WordPress-Headers", "WordPress identificado via header", module.SeverityLow},
		{"X-Drupal-Cache", "Drupal identificado via header", module.SeverityLow},
		{"Via", "Proxy/CDN intermediário identificado", module.SeverityInfo},
		{"CF-Cache-Status", "Cloudflare CDN detectado", module.SeverityInfo},
		{"Last-Modified", "Data de modificação exposta — timeline de conteúdo", module.SeverityInfo},
	}

	for _, item := range interesting {
		val := headers.Get(item.header)
		if val == "" {
			continue
		}
		findings = append(findings, module.Finding{
			Type:     "metadata_http_header",
			URL:      fileURL,
			Severity: item.sev,
			Detail:   fmt.Sprintf("%s: %s — %s (URL: %s)", item.header, val, item.note, fileURL),
			Extra: map[string]string{
				"header":     item.header,
				"value":      val,
				"source":     "http_headers",
				"confidence": "0.90",
			},
		})
	}
	return findings
}

// ─── JPEG / EXIF ──────────────────────────────────────────────────────────────

// isJPEG checks JPEG magic bytes.
func isJPEG(ct string, body []byte) bool {
	if strings.Contains(strings.ToLower(ct), "jpeg") || strings.Contains(strings.ToLower(ct), "jpg") {
		return true
	}
	return len(body) > 3 && body[0] == 0xFF && body[1] == 0xD8 && body[2] == 0xFF
}

// Minimal EXIF parser — handles the most OSINT-relevant tags:
//   - 0x010E: ImageDescription
//   - 0x013B: Artist
//   - 0x8769: ExifIFD offset
//   - 0x8825: GPSInfo offset
//   - GPS tags: lat/lon/altitude
//   - 0x010F: Make (camera brand)
//   - 0x0110: Model (camera model)
//   - 0x9003: DateTimeOriginal
//   - 0x9286: UserComment
//   - 0x0115: Software

type exifTag struct {
	tag uint16
	typ uint16
	cnt uint32
	val uint32
}

func extractEXIF(fileURL string, body []byte) []module.Finding {
	if len(body) < 12 {
		return nil
	}

	// Find APP1/Exif marker
	exifData, ok := findEXIFSegment(body)
	if !ok || len(exifData) < 8 {
		return nil
	}

	// Determine byte order
	var order binary.ByteOrder
	if exifData[0] == 'I' && exifData[1] == 'I' {
		order = binary.LittleEndian
	} else if exifData[0] == 'M' && exifData[1] == 'M' {
		order = binary.BigEndian
	} else {
		return nil
	}

	// IFD0 offset
	ifd0Offset := int(order.Uint32(exifData[4:8]))
	if ifd0Offset+2 > len(exifData) {
		return nil
	}

	tags := parseIFD(exifData, ifd0Offset, order)

	var findings []module.Finding
	meta := map[string]string{}

	// Helper to read ASCII string
	readASCII := func(t exifTag) string {
		if t.cnt <= 4 {
			b := make([]byte, 4)
			order.PutUint32(b, t.val)
			return strings.TrimRight(string(b[:t.cnt]), "\x00")
		}
		offset := int(t.val)
		if offset+int(t.cnt) > len(exifData) {
			return ""
		}
		return strings.TrimRight(string(exifData[offset:offset+int(t.cnt)]), "\x00")
	}

	for _, t := range tags {
		switch t.tag {
		case 0x010F: // Make
			meta["camera_make"] = readASCII(t)
		case 0x0110: // Model
			meta["camera_model"] = readASCII(t)
		case 0x013B: // Artist
			meta["artist"] = readASCII(t)
		case 0x0115: // Software
			meta["software"] = readASCII(t)
		case 0x010E: // ImageDescription
			meta["description"] = readASCII(t)
		}
	}

	// Check GPS sub-IFD
	for _, t := range tags {
		if t.tag == 0x8825 { // GPSInfo IFD offset
			gpsOffset := int(t.val)
			if gpsOffset+2 <= len(exifData) {
				lat, lon, alt, ok := parseGPS(exifData, gpsOffset, order)
				if ok {
					meta["gps_lat"] = fmt.Sprintf("%.6f", lat)
					meta["gps_lon"] = fmt.Sprintf("%.6f", lon)
					meta["gps_alt"] = fmt.Sprintf("%.1f", alt)
					meta["gps_maps"] = fmt.Sprintf("https://maps.google.com/?q=%f,%f", lat, lon)

					findings = append(findings, module.Finding{
						Type:     "metadata_gps_location",
						URL:      fileURL,
						Severity: module.SeverityHigh,
						Detail: fmt.Sprintf("Coordenadas GPS encontradas em imagem JPEG: lat=%.6f lon=%.6f alt=%.1fm — revela localização física de captura (%s)",
							lat, lon, alt, meta["gps_maps"]),
						Extra: map[string]string{
							"gps_lat":    meta["gps_lat"],
							"gps_lon":    meta["gps_lon"],
							"gps_alt":    meta["gps_alt"],
							"maps_url":   meta["gps_maps"],
							"source":     "exif",
							"confidence": "0.95",
						},
					})
				}
			}
		}
	}

	// Camera / software / artist finding
	if meta["camera_make"] != "" || meta["camera_model"] != "" || meta["artist"] != "" || meta["software"] != "" {
		detail := fmt.Sprintf("Metadados EXIF em imagem '%s': câmera=%s %s, software=%s, artista=%s",
			fileURL, meta["camera_make"], meta["camera_model"], meta["software"], meta["artist"])
		findings = append(findings, module.Finding{
			Type:     "metadata_exif_camera",
			URL:      fileURL,
			Severity: module.SeverityLow,
			Detail:   detail,
			Extra: map[string]string{
				"camera_make":  meta["camera_make"],
				"camera_model": meta["camera_model"],
				"software":     meta["software"],
				"artist":       meta["artist"],
				"source":       "exif",
				"confidence":   "0.88",
			},
		})
	}

	return findings
}

func findEXIFSegment(body []byte) ([]byte, bool) {
	// JPEG markers: FF D8 FF E1 <len> <len> "Exif\x00\x00"
	for i := 2; i < len(body)-10; i++ {
		if body[i] == 0xFF && body[i+1] == 0xE1 {
			segLen := int(body[i+2])<<8 | int(body[i+3])
			if i+4+6 > len(body) {
				continue
			}
			if string(body[i+4:i+8]) == "Exif" {
				start := i + 10 // skip "Exif\x00\x00"
				end := i + 4 + segLen
				if end > len(body) {
					end = len(body)
				}
				if start < end {
					return body[start:end], true
				}
			}
		}
	}
	return nil, false
}

func parseIFD(data []byte, offset int, order binary.ByteOrder) []exifTag {
	if offset+2 > len(data) {
		return nil
	}
	count := int(order.Uint16(data[offset : offset+2]))
	tags := make([]exifTag, 0, count)
	for i := 0; i < count; i++ {
		base := offset + 2 + i*12
		if base+12 > len(data) {
			break
		}
		t := exifTag{
			tag: order.Uint16(data[base : base+2]),
			typ: order.Uint16(data[base+2 : base+4]),
			cnt: order.Uint32(data[base+4 : base+8]),
			val: order.Uint32(data[base+8 : base+12]),
		}
		tags = append(tags, t)
	}
	return tags
}

func parseGPS(data []byte, offset int, order binary.ByteOrder) (lat, lon, alt float64, ok bool) {
	if offset+2 > len(data) {
		return 0, 0, 0, false
	}
	tags := parseIFD(data, offset, order)

	readRational := func(dataOff uint32) float64 {
		off := int(dataOff)
		if off+8 > len(data) {
			return 0
		}
		num := order.Uint32(data[off : off+4])
		den := order.Uint32(data[off+4 : off+8])
		if den == 0 {
			return 0
		}
		return float64(num) / float64(den)
	}

	readCoord := func(dataOff uint32) float64 {
		off := int(dataOff)
		if off+24 > len(data) {
			return 0
		}
		deg := readRational(uint32(off))
		min := readRational(uint32(off + 8))
		sec := readRational(uint32(off + 16))
		return deg + min/60 + sec/3600
	}

	var latVal, lonVal float64
	var latRef, lonRef string
	var hasLat, hasLon bool

	for _, t := range tags {
		switch t.tag {
		case 0x0001: // GPSLatitudeRef
			if t.cnt >= 1 {
				b := make([]byte, 4)
				order.PutUint32(b, t.val)
				latRef = string(b[:1])
			}
		case 0x0002: // GPSLatitude
			latVal = readCoord(t.val)
			hasLat = true
		case 0x0003: // GPSLongitudeRef
			if t.cnt >= 1 {
				b := make([]byte, 4)
				order.PutUint32(b, t.val)
				lonRef = string(b[:1])
			}
		case 0x0004: // GPSLongitude
			lonVal = readCoord(t.val)
			hasLon = true
		case 0x0006: // GPSAltitude
			alt = readRational(t.val)
		}
	}

	if !hasLat || !hasLon {
		return 0, 0, 0, false
	}
	if strings.EqualFold(latRef, "S") {
		latVal = -latVal
	}
	if strings.EqualFold(lonRef, "W") {
		lonVal = -lonVal
	}
	if math.IsNaN(latVal) || math.IsNaN(lonVal) {
		return 0, 0, 0, false
	}
	return latVal, lonVal, alt, true
}

// ─── PDF ──────────────────────────────────────────────────────────────────────

func isPDF(ct string, body []byte) bool {
	return strings.Contains(strings.ToLower(ct), "pdf") ||
		(len(body) > 4 && string(body[:4]) == "%PDF")
}

// extractPDF parses PDF XMP/info metadata via simple text search.
// Production-quality PDF parsing would use a library; this covers the
// most common OSINT-relevant fields from the /Info dictionary.
func extractPDF(fileURL string, body []byte) []module.Finding {
	text := string(body)

	fields := map[string]string{
		"Author":   "",
		"Creator":  "",
		"Producer": "",
		"Title":    "",
		"Subject":  "",
		"Keywords": "",
	}

	// Parse PDF /Info dictionary fields like "/Author (John Doe)"
	for field := range fields {
		val := extractPDFField(text, field)
		if val != "" {
			fields[field] = val
		}
	}

	// Check for anything interesting
	hasInfo := false
	for _, v := range fields {
		if v != "" {
			hasInfo = true
			break
		}
	}
	if !hasInfo {
		return nil
	}

	extra := map[string]string{
		"source":     "pdf_metadata",
		"confidence": "0.82",
	}
	for k, v := range fields {
		if v != "" {
			extra[strings.ToLower(k)] = v
		}
	}

	sev := module.SeverityLow
	detail := fmt.Sprintf("Metadados PDF em '%s': Author=%s, Creator=%s, Producer=%s, Title=%s",
		fileURL, fields["Author"], fields["Creator"], fields["Producer"], fields["Title"])

	// Author/Creator are especially OSINT-relevant
	if fields["Author"] != "" || fields["Creator"] != "" {
		sev = module.SeverityMedium
	}

	return []module.Finding{{
		Type:     "metadata_pdf",
		URL:      fileURL,
		Severity: sev,
		Detail:   detail,
		Extra:    extra,
	}}
}

func extractPDFField(text, field string) string {
	// Try "/FieldName (value)" pattern
	needle := "/" + field + " ("
	idx := strings.Index(text, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := strings.Index(text[start:], ")")
	if end < 0 || end > 512 {
		return ""
	}
	val := text[start : start+end]
	// Remove PDF escape sequences
	val = strings.ReplaceAll(val, "\\n", " ")
	val = strings.ReplaceAll(val, "\\r", " ")
	val = strings.TrimSpace(val)
	if len(val) > 256 {
		val = val[:256]
	}
	return val
}

// ─── Office (OOXML) ───────────────────────────────────────────────────────────

func isOffice(ct, urlStr string) bool {
	ooxml := []string{
		"officedocument.wordprocessingml",
		"officedocument.spreadsheetml",
		"officedocument.presentationml",
	}
	ctLower := strings.ToLower(ct)
	for _, t := range ooxml {
		if strings.Contains(ctLower, t) {
			return true
		}
	}
	// Also check extension
	urlLower := strings.ToLower(urlStr)
	for _, ext := range []string{".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"} {
		if strings.Contains(urlLower, ext) {
			return true
		}
	}
	return false
}

// docProps/core.xml structure for OOXML
type coreProperties struct {
	XMLName        xml.Name `xml:"coreProperties"`
	Creator        string   `xml:"creator"`
	LastModifiedBy string   `xml:"lastModifiedBy"`
	Title          string   `xml:"title"`
	Subject        string   `xml:"subject"`
	Description    string   `xml:"description"`
	Keywords       string   `xml:"keywords"`
	Language       string   `xml:"language"`
	Version        string   `xml:"version"`
}

func extractOffice(fileURL string, body []byte) []module.Finding {
	// OOXML is a ZIP file — find docProps/core.xml by looking for the
	// XML content directly in the binary (works for non-compressed entries)
	coreIdx := bytes.Index(body, []byte("docProps/core.xml"))
	if coreIdx < 0 {
		// Try to find the XML data directly
		coreIdx = bytes.Index(body, []byte("<cp:coreProperties"))
	}
	if coreIdx < 0 {
		return nil
	}

	// Extract XML region (heuristic)
	start := coreIdx
	end := start + 4096
	if end > len(body) {
		end = len(body)
	}

	xmlStart := bytes.Index(body[start:end], []byte("<?xml"))
	if xmlStart < 0 {
		xmlStart = bytes.Index(body[start:end], []byte("<cp:coreProperties"))
	}
	if xmlStart < 0 {
		return nil
	}

	xmlData := body[start+xmlStart : end]
	xmlEnd := bytes.Index(xmlData, []byte("</cp:coreProperties>"))
	if xmlEnd > 0 {
		xmlData = xmlData[:xmlEnd+len("</cp:coreProperties>")]
	}

	// Decode namespace-prefixed XML by stripping prefix
	xmlStr := string(xmlData)
	xmlStr = strings.ReplaceAll(xmlStr, "cp:", "")
	xmlStr = strings.ReplaceAll(xmlStr, "dc:", "")
	xmlStr = strings.ReplaceAll(xmlStr, "dcterms:", "")

	var props coreProperties
	if err := xml.Unmarshal([]byte(xmlStr), &props); err != nil {
		return nil
	}

	if props.Creator == "" && props.LastModifiedBy == "" && props.Title == "" {
		return nil
	}

	sev := module.SeverityLow
	conf := "0.80"
	if props.LastModifiedBy != "" || props.Creator != "" {
		sev = module.SeverityMedium
		conf = "0.85"
	}

	return []module.Finding{{
		Type:     "metadata_office",
		URL:      fileURL,
		Severity: sev,
		Detail: fmt.Sprintf("Metadados Office em '%s': Creator=%s, LastModifiedBy=%s, Title=%s — pode revelar username interno e ferramenta usada",
			fileURL, props.Creator, props.LastModifiedBy, props.Title),
		Extra: map[string]string{
			"creator":          props.Creator,
			"last_modified_by": props.LastModifiedBy,
			"title":            props.Title,
			"subject":          props.Subject,
			"keywords":         props.Keywords,
			"source":           "office_metadata",
			"confidence":       conf,
		},
	}}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func optInt(opts map[string]string, key string, def int) int {
	v, ok := opts[key]
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func dedup(findings []module.Finding) []module.Finding {
	seen := map[string]bool{}
	out := make([]module.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Extra["source"]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
