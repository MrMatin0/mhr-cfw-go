package fronter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/denuitt1/mhr-cfw/internal/codec"
	"github.com/denuitt1/mhr-cfw/internal/config"
	"github.com/denuitt1/mhr-cfw/internal/constants"
	"github.com/denuitt1/mhr-cfw/internal/h2"
	"github.com/denuitt1/mhr-cfw/internal/logging"
)

var log = logging.Get("Fronter")

// HostStat tracks per-host request statistics.
type HostStat struct {
	Requests       int
	CacheHits      int
	Bytes          int
	TotalLatencyNs int64
	Errors         int
}

// DomainFronter relays HTTP requests via Google Apps Script domain-fronting.
type DomainFronter struct {
	connectHost string
	sniHosts    []string
	// FIX: sniIdx is now atomic to prevent race conditions in nextSNI().
	sniIdx   uint32
	httpHost string

	scriptIDs    []string
	sidBlacklist map[string]time.Time
	blacklistTTL time.Duration

	// FIX: perSite stats protected by statsMu to avoid map concurrent write.
	statsMu sync.Mutex
	perSite map[string]*HostStat

	authKey   string
	verifySSL bool
	relayTO   time.Duration
	tlsTO     time.Duration
	maxResp   int

	parallelRelay int

	h2 *h2.Transport

	poolMu sync.Mutex
	pool   []pooledConn

	batchMu      sync.Mutex
	batchPending []batchItem
	batchTimer   *time.Timer

	coalesceMu sync.Mutex
	coalesce   map[string][]chan []byte

	stopCh chan struct{}
}

type pooledConn struct {
	conn    net.Conn
	created time.Time
}

type batchItem struct {
	payload map[string]any
	respCh  chan []byte
}

func New(cfg config.Config) *DomainFronter {
	frontDomain := cfg.GetString("front_domain", "www.google.com")
	fronts := buildSNIPool(frontDomain, cfg.GetStringSlice("front_domains"))
	ids := cfg.GetScriptIDs()
	if len(ids) == 0 {
		ids = []string{cfg.GetString("script_id", "")}
	}

	parallel := cfg.GetInt("parallel_relay", 1)
	if parallel < 1 {
		parallel = 1
	}
	if parallel > len(ids) {
		parallel = len(ids)
	}

	f := &DomainFronter{
		connectHost:   cfg.GetString("google_ip", "216.239.38.120"),
		sniHosts:      fronts,
		httpHost:      "script.google.com",
		scriptIDs:     ids,
		sidBlacklist:  make(map[string]time.Time),
		blacklistTTL:  time.Duration(constants.ScriptBlacklistTTL * float64(time.Second)),
		perSite:       make(map[string]*HostStat),
		authKey:       cfg.GetString("auth_key", ""),
		verifySSL:     cfg.GetBool("verify_ssl", true),
		relayTO:       time.Duration(cfg.GetInt("relay_timeout", constants.RelayTimeout)) * time.Second,
		tlsTO:         time.Duration(cfg.GetInt("tls_connect_timeout", constants.TLSConnectTimeout)) * time.Second,
		maxResp:       cfg.GetInt("max_response_body_bytes", constants.MaxResponseBodyBytes),
		parallelRelay: parallel,
		coalesce:      make(map[string][]chan []byte),
		stopCh:        make(chan struct{}),
	}

	if len(fronts) > 1 {
		log.Infof("SNI rotation pool (%d): %s", len(fronts), strings.Join(fronts, ", "))
	}
	if parallel > 1 {
		log.Infof("Fan-out relay: %d parallel Apps Script instances per request", parallel)
	}
	log.Infof("Response codecs: %s", codec.SupportedEncodings())

	f.h2 = h2.New(f.connectHost, f.sniHosts, f.verifySSL)
	go f.statsLoop()
	return f
}

func buildSNIPool(frontDomain string, overrides []string) []string {
	if len(overrides) > 0 {
		seen := make(map[string]bool)
		out := make([]string, 0, len(overrides))
		for _, item := range overrides {
			host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(item), "."))
			if host != "" && !seen[host] {
				seen[host] = true
				out = append(out, host)
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	fd := strings.ToLower(strings.TrimSuffix(frontDomain, "."))
	if strings.HasSuffix(fd, ".google.com") || fd == "google.com" {
		pool := []string{fd}
		for _, h := range constants.FrontSNIPoolGoogle {
			if h != fd {
				pool = append(pool, h)
			}
		}
		return pool
	}
	if fd == "" {
		return []string{"www.google.com"}
	}
	return []string{fd}
}

func (f *DomainFronter) Close() error {
	close(f.stopCh)
	if f.h2 != nil {
		_ = f.h2.Close()
	}
	f.poolMu.Lock()
	for _, pc := range f.pool {
		_ = pc.conn.Close()
	}
	f.pool = nil
	f.poolMu.Unlock()
	return nil
}

func (f *DomainFronter) Relay(method, urlStr string, headers map[string]string, body []byte) []byte {
	payload := f.buildPayload(method, urlStr, headers, body)
	start := time.Now()
	isErr := false
	var raw []byte

	defer func() {
		f.recordSite(urlStr, len(raw), time.Since(start), isErr)
	}()

	if f.isStatefulRequest(method, urlStr, headers, body) {
		resp, err := f.relaySingle(payload)
		if err != nil {
			isErr = true
			return f.errorResponse(502, err.Error())
		}
		raw = resp
		return resp
	}

	key := f.coalesceKey(urlStr, headers)
	if strings.ToUpper(method) == "GET" && len(body) == 0 {
		if headers["range"] == "" {
			resp, ok := f.tryCoalesce(key, payload)
			if ok {
				raw = resp
				return resp
			}
		}
	}

	resp, err := f.batchSubmit(payload)
	if err != nil {
		isErr = true
		return f.errorResponse(502, err.Error())
	}
	raw = resp
	return resp
}

func (f *DomainFronter) tryCoalesce(key string, payload map[string]any) ([]byte, bool) {
	f.coalesceMu.Lock()
	if waiters, ok := f.coalesce[key]; ok {
		ch := make(chan []byte, 1)
		f.coalesce[key] = append(waiters, ch)
		f.coalesceMu.Unlock()
		return <-ch, true
	}
	f.coalesce[key] = []chan []byte{}
	f.coalesceMu.Unlock()

	resp, err := f.batchSubmit(payload)
	if err != nil {
		resp = f.errorResponse(502, err.Error())
	}

	f.coalesceMu.Lock()
	waiters := f.coalesce[key]
	delete(f.coalesce, key)
	f.coalesceMu.Unlock()

	for _, ch := range waiters {
		ch <- resp
	}
	return resp, true
}

func (f *DomainFronter) batchSubmit(payload map[string]any) ([]byte, error) {
	respCh := make(chan []byte, 1)
	item := batchItem{payload: payload, respCh: respCh}

	f.batchMu.Lock()
	f.batchPending = append(f.batchPending, item)

	if len(f.batchPending) >= constants.BatchMax {
		pending := f.batchPending
		f.batchPending = nil
		if f.batchTimer != nil {
			f.batchTimer.Stop()
			f.batchTimer = nil
		}
		f.batchMu.Unlock()
		go f.flushBatch(pending)
		return <-respCh, nil
	}

	if f.batchTimer == nil {
		// FIX: capture pending slice in closure to avoid flushing stale state
		// if the timer fires after the batch has already been manually flushed.
		f.batchTimer = time.AfterFunc(
			time.Duration(constants.BatchWindowMicro*float64(time.Second)),
			func() {
				f.batchMu.Lock()
				pending := f.batchPending
				f.batchPending = nil
				f.batchTimer = nil
				f.batchMu.Unlock()
				if len(pending) > 0 {
					f.flushBatch(pending)
				}
			},
		)
	}
	f.batchMu.Unlock()
	return <-respCh, nil
}

func (f *DomainFronter) flushBatch(batch []batchItem) {
	if len(batch) == 1 {
		resp, err := f.relaySingle(batch[0].payload)
		if err != nil {
			resp = f.errorResponse(502, err.Error())
		}
		batch[0].respCh <- resp
		return
	}

	results, err := f.relayBatch(batch)
	if err != nil {
		for _, item := range batch {
			item.respCh <- f.errorResponse(502, err.Error())
		}
		return
	}
	for i, item := range batch {
		item.respCh <- results[i]
	}
}

func (f *DomainFronter) relaySingle(payload map[string]any) ([]byte, error) {
	full := make(map[string]any, len(payload)+1)
	for k, v := range payload {
		full[k] = v
	}
	full["k"] = f.authKey

	jsonBody, err := json.Marshal(full)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	path := f.execPath(payload["u"])

	_, _, body, err := f.h2.Request(
		context.Background(), "POST", path, f.httpHost,
		map[string]string{"content-type": "application/json"},
		jsonBody, f.relayTO,
	)
	if err == nil {
		return f.parseRelayResponse(body), nil
	}

	resp, err := f.relayHTTP1(path, jsonBody)
	if err != nil {
		return nil, err
	}
	return f.parseRelayResponse(resp), nil
}

func (f *DomainFronter) relayBatch(batch []batchItem) ([][]byte, error) {
	payloads := make([]map[string]any, 0, len(batch))
	for _, item := range batch {
		payloads = append(payloads, item.payload)
	}
	full := map[string]any{
		"k": f.authKey,
		"q": payloads,
	}

	jsonBody, err := json.Marshal(full)
	if err != nil {
		return nil, fmt.Errorf("marshal batch: %w", err)
	}
	path := f.execPath(payloads[0]["u"])

	_, _, body, err := f.h2.Request(
		context.Background(), "POST", path, f.httpHost,
		map[string]string{"content-type": "application/json"},
		jsonBody, 30*time.Second,
	)
	if err == nil {
		return f.parseBatchBody(body, len(batch))
	}

	resp, err := f.relayHTTP1(path, jsonBody)
	if err != nil {
		return nil, err
	}
	return f.parseBatchBody(resp, len(batch))
}

func (f *DomainFronter) relayHTTP1(path string, body []byte) ([]byte, error) {
	conn, err := f.acquire()
	if err != nil {
		return nil, err
	}
	defer f.release(conn)

	req := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n",
		path, f.httpHost, len(body),
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(body); err != nil {
		return nil, err
	}

	status, headers, respBody, err := readHTTPResponse(conn, f.maxResp)
	if err != nil {
		return nil, err
	}

	if status >= 300 && status < 400 {
		loc := headers["location"]
		if loc != "" {
			parsed, _ := url.Parse(loc)
			rpath := parsed.Path
			if parsed.RawQuery != "" {
				rpath += "?" + parsed.RawQuery
			}
			return f.relayHTTP1(rpath, body)
		}
	}
	return respBody, nil
}

func readHTTPResponse(conn net.Conn, maxBody int) (int, map[string]string, []byte, error) {
	reader := bufio.NewReader(conn)

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, nil, nil, err
	}
	status := 0
	if m := regexp.MustCompile(`\d{3}`).FindString(statusLine); m != "" {
		status, _ = strconv.Atoi(m)
	}

	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return status, headers, nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			headers[strings.ToLower(strings.TrimSpace(line[:idx]))] = strings.TrimSpace(line[idx+1:])
		}
	}

	cl := 0
	if v := headers["content-length"]; v != "" {
		cl, _ = strconv.Atoi(v)
	}

	var body []byte
	if cl > 0 {
		if cl > maxBody {
			return status, headers, nil, errors.New("response exceeds cap")
		}
		body = make([]byte, cl)
		if _, err = io.ReadFull(reader, body); err != nil {
			return status, headers, nil, err
		}
	} else if headers["transfer-encoding"] == "chunked" {
		body, err = io.ReadAll(reader)
		if err != nil {
			return status, headers, nil, err
		}
	}

	if enc := headers["content-encoding"]; enc != "" {
		body = codec.Decode(body, enc)
	}
	return status, headers, body, nil
}

func (f *DomainFronter) acquire() (net.Conn, error) {
	f.poolMu.Lock()
	for len(f.pool) > 0 {
		pc := f.pool[len(f.pool)-1]
		f.pool = f.pool[:len(f.pool)-1]
		f.poolMu.Unlock()
		if time.Since(pc.created) < time.Duration(constants.ConnTTL*float64(time.Second)) {
			return pc.conn, nil
		}
		_ = pc.conn.Close()
		f.poolMu.Lock()
	}
	f.poolMu.Unlock()

	dialer := &net.Dialer{Timeout: f.tlsTO}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(f.connectHost, "443"))
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         f.nextSNI(),
		InsecureSkipVerify: !f.verifySSL, //nolint:gosec
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (f *DomainFronter) release(conn net.Conn) {
	f.poolMu.Lock()
	defer f.poolMu.Unlock()
	if len(f.pool) >= constants.PoolMax {
		_ = conn.Close()
		return
	}
	f.pool = append(f.pool, pooledConn{conn: conn, created: time.Now()})
}

// nextSNI returns the next SNI hostname in a round-robin fashion.
// FIX: uses atomic.AddUint32 to prevent race conditions (was plain sniIdx++).
func (f *DomainFronter) nextSNI() string {
	idx := atomic.AddUint32(&f.sniIdx, 1)
	return f.sniHosts[int(idx)%len(f.sniHosts)]
}

func (f *DomainFronter) execPath(urlOrHost any) string {
	sid := f.scriptIDForKey(hostKey(fmt.Sprint(urlOrHost)))
	return "/macros/s/" + sid + "/exec"
}

func hostKey(urlOrHost string) string {
	if urlOrHost == "" {
		return ""
	}
	if strings.Contains(urlOrHost, "://") {
		if parsed, err := url.Parse(urlOrHost); err == nil {
			return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		}
	}
	return strings.ToLower(strings.TrimSuffix(urlOrHost, "."))
}

func (f *DomainFronter) scriptIDForKey(key string) string {
	if len(f.scriptIDs) == 1 {
		return f.scriptIDs[0]
	}
	if key == "" {
		// Round-robin without a key is not thread-safe with plain increment;
		// use SHA-based approach on empty string as fallback.
		key = strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	h := sha1.Sum([]byte(key))
	return f.scriptIDs[int(h[0])%len(f.scriptIDs)]
}

func (f *DomainFronter) buildPayload(method, urlStr string, headers map[string]string, body []byte) map[string]any {
	p := map[string]any{
		"m": method,
		"u": urlStr,
		"r": false,
	}
	if len(headers) > 0 {
		filtered := make(map[string]string, len(headers))
		for k, v := range headers {
			if strings.ToLower(k) != "accept-encoding" {
				filtered[k] = v
			}
		}
		p["h"] = filtered
	}
	if len(body) > 0 {
		p["b"] = base64.StdEncoding.EncodeToString(body)
		if ct := headers["content-type"]; ct != "" {
			p["ct"] = ct
		}
	}
	return p
}

func (f *DomainFronter) parseRelayResponse(body []byte) []byte {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return f.errorResponse(502, "empty response from relay")
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		// Try to extract JSON from surrounding text.
		if m := regexp.MustCompile(`\{.*\}`).FindString(text); m != "" {
			if err2 := json.Unmarshal([]byte(m), &data); err2 != nil {
				return f.errorResponse(502, "bad JSON: "+truncate(text, 200))
			}
		} else {
			return f.errorResponse(502, "no JSON: "+truncate(text, 200))
		}
	}
	return f.parseRelayJSON(data)
}

func (f *DomainFronter) errorResponse(status int, message string) []byte {
	body := fmt.Sprintf("<html><body><h1>%d</h1><p>%s</p></body></html>", status, message)
	return []byte(fmt.Sprintf(
		"HTTP/1.1 %d Error\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s",
		status, len(body), body,
	))
}

func (f *DomainFronter) parseRelayJSON(data map[string]any) []byte {
	if e, ok := data["e"]; ok {
		return f.errorResponse(502, fmt.Sprintf("relay error: %v", e))
	}

	status := intVal(data["s"], 200)
	headers, _ := data["h"].(map[string]any)
	bodyStr, _ := data["b"].(string)

	body, _ := base64.StdEncoding.DecodeString(bodyStr)
	if len(body) > f.maxResp {
		return f.errorResponse(502, "relay response exceeds cap")
	}

	statusText := statusTextFor(status)

	skip := map[string]bool{
		"transfer-encoding": true,
		"connection":        true,
		"keep-alive":        true,
		"content-length":    true,
		"content-encoding":  true,
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", status, statusText))
	for k, v := range headers {
		if skip[strings.ToLower(k)] {
			continue
		}
		switch val := v.(type) {
		case []any:
			for _, item := range val {
				fmt.Fprintf(&buf, "%s: %v\r\n", k, item)
			}
		default:
			fmt.Fprintf(&buf, "%s: %v\r\n", k, val)
		}
	}
	fmt.Fprintf(&buf, "Content-Length: %d\r\n\r\n", len(body))
	buf.Write(body)
	return buf.Bytes()
}

func statusTextFor(code int) string {
	switch code {
	case 200:
		return "OK"
	case 206:
		return "Partial Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "Unknown"
	}
}

func (f *DomainFronter) parseBatchBody(body []byte, expected int) ([][]byte, error) {
	var data map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(body), &data); err != nil {
		return nil, fmt.Errorf("batch unmarshal: %w", err)
	}
	if e, ok := data["e"]; ok {
		return nil, fmt.Errorf("batch error: %v", e)
	}
	arr, ok := data["q"].([]any)
	if !ok || len(arr) != expected {
		return nil, fmt.Errorf("batch size mismatch: got %d, want %d", len(arr), expected)
	}

	results := make([][]byte, 0, len(arr))
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			results = append(results, f.errorResponse(502, "invalid batch item"))
			continue
		}
		results = append(results, f.parseRelayJSON(obj))
	}
	return results, nil
}

func (f *DomainFronter) isStatefulRequest(method, urlStr string, headers map[string]string, body []byte) bool {
	method = strings.ToUpper(method)
	if method != "GET" && method != "HEAD" {
		return true
	}
	if len(body) > 0 {
		return true
	}
	for _, name := range constants.StatefulHeaderNames {
		if headers[name] != "" {
			return true
		}
	}
	accept := strings.ToLower(headers["accept"])
	if strings.Contains(accept, "text/html") || strings.Contains(accept, "application/json") {
		return true
	}
	fetchMode := strings.ToLower(headers["sec-fetch-mode"])
	if fetchMode == "navigate" || fetchMode == "cors" {
		return true
	}
	return !isStaticAssetURL(urlStr)
}

func isStaticAssetURL(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for _, ext := range constants.StaticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func (f *DomainFronter) coalesceKey(urlStr string, headers map[string]string) string {
	var b strings.Builder
	b.WriteString(urlStr)
	for _, name := range []string{"accept", "accept-language", "user-agent", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"} {
		if v := headers[name]; v != "" {
			b.WriteByte('\n')
			b.WriteString(name)
			b.WriteByte('=')
			b.WriteString(v)
		}
	}
	return b.String()
}

// recordSite records per-host statistics. FIX: protected by statsMu.
func (f *DomainFronter) recordSite(urlStr string, byteCount int, latency time.Duration, errored bool) {
	host := hostKey(urlStr)
	if host == "" {
		return
	}
	f.statsMu.Lock()
	defer f.statsMu.Unlock()

	stat, ok := f.perSite[host]
	if !ok {
		stat = &HostStat{}
		f.perSite[host] = stat
	}
	stat.Requests++
	stat.Bytes += byteCount
	stat.TotalLatencyNs += latency.Nanoseconds()
	if errored {
		stat.Errors++
	}
}

func (f *DomainFronter) statsLoop() {
	ticker := time.NewTicker(time.Duration(constants.StatsLogInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-f.stopCh:
			return
		case <-ticker.C:
			f.logStats()
		}
	}
}

func (f *DomainFronter) logStats() {
	f.statsMu.Lock()
	if len(f.perSite) == 0 {
		f.statsMu.Unlock()
		return
	}
	type statEntry struct {
		host string
		stat HostStat
	}
	entries := make([]statEntry, 0, len(f.perSite))
	for host, stat := range f.perSite {
		entries = append(entries, statEntry{host: host, stat: *stat})
	}
	f.statsMu.Unlock()

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].stat.Bytes > entries[j].stat.Bytes
	})

	count := constants.StatsLogTopN
	if count > len(entries) {
		count = len(entries)
	}
	log.Debugf("-- per-host stats (top %d by bytes) --", count)
	for i := 0; i < count; i++ {
		e := entries[i]
		var avgLatency time.Duration
		if e.stat.Requests > 0 {
			avgLatency = time.Duration(e.stat.TotalLatencyNs / int64(e.stat.Requests))
		}
		log.Debugf("  %s: %d reqs, %.2fMB, %s avg, %d errs",
			e.host, e.stat.Requests, float64(e.stat.Bytes)/1024/1024, avgLatency, e.stat.Errors)
	}
}

// --- small helpers ---

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func intVal(v any, def int) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		if i, err := strconv.Atoi(t); err == nil {
			return i
		}
	}
	return def
}
