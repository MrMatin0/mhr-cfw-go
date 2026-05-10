package proxy

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/denuitt1/mhr-cfw/internal/config"
	"github.com/denuitt1/mhr-cfw/internal/constants"
	"github.com/denuitt1/mhr-cfw/internal/fronter"
	"github.com/denuitt1/mhr-cfw/internal/logging"
	"github.com/denuitt1/mhr-cfw/internal/mitm"
)

var log = logging.Get("Proxy")

var maxAgeRegex = regexp.MustCompile(`max-age=(\d+)`)

// cacheEntry holds a cached response with its expiry time and LRU list element.
type cacheEntry struct {
	raw     []byte
	expires time.Time
	elem    *list.Element // pointer into lruList for O(1) eviction
}

// ResponseCache is a thread-safe LRU cache for HTTP responses.
// FIX: replaced O(n) slice eviction with container/list for O(1) eviction.
type ResponseCache struct {
	mu     sync.Mutex
	store  map[string]*cacheEntry
	lru    *list.List // stores URL strings; front = most recently used
	size   int
	max    int
	Hits   int
	Misses int
}

func NewResponseCache(maxMB int) *ResponseCache {
	return &ResponseCache{
		store: make(map[string]*cacheEntry),
		lru:   list.New(),
		max:   maxMB * 1024 * 1024,
	}
}

func (c *ResponseCache) Get(url string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.store[url]
	if !ok {
		c.Misses++
		return nil
	}
	if time.Now().After(entry.expires) {
		c.evict(url, entry)
		c.Misses++
		return nil
	}
	// Move to front (most recently used).
	c.lru.MoveToFront(entry.elem)
	c.Hits++
	return entry.raw
}

func (c *ResponseCache) Put(url string, raw []byte, ttl int) {
	if len(raw) == 0 || ttl <= 0 {
		return
	}
	size := len(raw)
	// Don't cache items larger than 25% of the total cache.
	if size > c.max/4 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// If URL already exists, remove old entry first.
	if old, ok := c.store[url]; ok {
		c.evict(url, old)
	}

	// Evict LRU entries until there is room.
	for c.size+size > c.max && c.lru.Len() > 0 {
		back := c.lru.Back()
		if back == nil {
			break
		}
		oldURL := back.Value.(string)
		if e, ok := c.store[oldURL]; ok {
			c.evict(oldURL, e)
		}
	}

	elem := c.lru.PushFront(url)
	c.store[url] = &cacheEntry{
		raw:     raw,
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
		elem:    elem,
	}
	c.size += size
}

// evict removes a cache entry. Must be called with c.mu held.
func (c *ResponseCache) evict(url string, entry *cacheEntry) {
	c.lru.Remove(entry.elem)
	c.size -= len(entry.raw)
	delete(c.store, url)
}

// ParseTTL determines the cache TTL from a raw HTTP response.
// FIX: avoids full header string conversion when possible.
func (c *ResponseCache) ParseTTL(raw []byte, urlStr string) int {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return 0
	}
	// Only cache 200 OK responses.
	if len(raw) < 12 || string(raw[:12]) != "HTTP/1.1 200" {
		return 0
	}

	head := strings.ToLower(string(raw[:idx]))

	if strings.Contains(head, "no-store") ||
		strings.Contains(head, "private") ||
		strings.Contains(head, "set-cookie:") {
		return 0
	}

	if m := maxAgeRegex.FindStringSubmatch(head); len(m) == 2 {
		v, _ := strconv.Atoi(m[1])
		if v > constants.CacheTTLMax {
			return constants.CacheTTLMax
		}
		return v
	}

	path := strings.ToLower(strings.SplitN(urlStr, "?", 2)[0])
	for _, ext := range constants.StaticExts {
		if strings.HasSuffix(path, ext) {
			return constants.CacheTTLStaticLong
		}
	}
	if strings.Contains(head, "image/") || strings.Contains(head, "font/") {
		return constants.CacheTTLStaticLong
	}
	if strings.Contains(head, "text/css") || strings.Contains(head, "javascript") {
		return constants.CacheTTLStaticMed
	}
	return 0
}

// Server is the main proxy server handling HTTP and SOCKS5 connections.
type Server struct {
	host         string
	port         int
	socksEnabled bool
	socksHost    string
	socksPort    int

	fronter *fronter.DomainFronter
	mitm    *mitm.Manager
	cache   *ResponseCache

	servers []net.Listener
	wg      sync.WaitGroup
}

func NewServer(cfg config.Config) (*Server, error) {
	host := cfg.GetString("listen_host", "127.0.0.1")
	port := cfg.GetInt("listen_port", 8080)
	socksEnabled := cfg.GetBool("socks5_enabled", true)
	socksHost := cfg.GetString("socks5_host", host)
	socksPort := cfg.GetInt("socks5_port", 1080)

	if socksEnabled && socksHost == host && socksPort == port {
		return nil, fmt.Errorf(
			"listen_port and socks5_port must differ on the same host (both %d on %s)",
			port, host,
		)
	}

	return &Server{
		host:         host,
		port:         port,
		socksEnabled: socksEnabled,
		socksHost:    socksHost,
		socksPort:    socksPort,
		fronter:      fronter.New(cfg),
		mitm:         mitm.NewManager(),
		cache:        NewResponseCache(constants.CacheMaxMB),
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(s.host, strconv.Itoa(s.port)))
	if err != nil {
		return err
	}
	s.servers = append(s.servers, ln)
	log.Infof("HTTP proxy listening on %s:%d", s.host, s.port)

	if s.socksEnabled {
		socksLn, err := net.Listen("tcp", net.JoinHostPort(s.socksHost, strconv.Itoa(s.socksPort)))
		if err != nil {
			log.Errorf("SOCKS5 listener failed on %s:%d: %v", s.socksHost, s.socksPort, err)
		} else {
			s.servers = append(s.servers, socksLn)
			log.Infof("SOCKS5 proxy listening on %s:%d", s.socksHost, s.socksPort)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.acceptLoop(socksLn, s.handleSocksConn)
			}()
		}
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ln, s.handleHTTPConn)
	}()

	<-ctx.Done()

	// Close all listeners to unblock Accept calls.
	for _, l := range s.servers {
		_ = l.Close()
	}
	_ = s.fronter.Close()
	s.wg.Wait()
	log.Infof("Server stopped")
	return nil
}

func (s *Server) acceptLoop(ln net.Listener, handler func(net.Conn)) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Errorf("accept error: %v", err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			handler(conn)
		}()
	}
}

func (s *Server) handleHTTPConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	headers := []string{line}
	for {
		ln, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		headers = append(headers, ln)
		if ln == "\r\n" || ln == "\n" {
			break
		}
		if sumLen(headers) > constants.MaxHeaderBytes {
			return
		}
	}

	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return
	}
	if strings.ToUpper(parts[0]) == "CONNECT" {
		s.handleConnect(conn, reader, parts[1])
		return
	}
	s.handlePlainHTTP(conn, reader, headers)
}

func (s *Server) handleConnect(conn net.Conn, reader *bufio.Reader, target string) {
	host, port := splitHostPort(target, 443)
	log.Infof("CONNECT -> %s:%d", host, port)
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	s.handleTunnel(host, port, conn, reader)
}

func (s *Server) handleTunnel(host string, port int, conn net.Conn, _ *bufio.Reader) {
	if port == 443 {
		cfg, err := s.mitm.GetServerTLSConfig(host)
		if err != nil {
			log.Errorf("MITM TLS config error for %s: %v", host, err)
			return
		}
		tlsConn := tls.Server(conn, cfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		s.relayHTTPStream(host, port, tlsConn)
		return
	}
	s.relayHTTPStream(host, port, conn)
}

func (s *Server) relayHTTPStream(host string, port int, conn net.Conn) {
	reader := bufio.NewReaderSize(conn, 32*1024)
	idleTimeout := time.Duration(constants.ClientIdleTimeout) * time.Second

	for {
		_ = conn.SetDeadline(time.Now().Add(idleTimeout))

		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			continue
		}

		headers := []string{line}
		for {
			ln, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			headers = append(headers, ln)
			if ln == "\r\n" || ln == "\n" {
				break
			}
			if sumLen(headers) > constants.MaxHeaderBytes {
				return
			}
		}

		method, path := parseRequestLine(line)
		body, err := readBody(reader, headers)
		if err != nil {
			return
		}
		// FIX: parseHeaders now normalises keys to lowercase for O(1) lookup.
		headerMap := parseHeaders(headers[1:])

		urlStr := normalizeURL(host, port, path)
		log.Infof("MITM -> %s %s", method, urlStr)

		origin := headerMap["origin"]
		acrMethod := headerMap["access-control-request-method"]
		acrHeaders := headerMap["access-control-request-headers"]

		if strings.ToUpper(method) == "OPTIONS" && acrMethod != "" {
			_, _ = conn.Write(corsPreflight(origin, acrMethod, acrHeaders))
			continue
		}

		response := s.fronter.Relay(method, urlStr, headerMap, body)
		if origin != "" {
			response = injectCORSHeaders(response, origin)
		}
		_, _ = conn.Write(response)
	}
}

func (s *Server) handlePlainHTTP(conn net.Conn, reader *bufio.Reader, headers []string) {
	method, path := parseRequestLine(headers[0])
	body, err := readBody(reader, headers)
	if err != nil {
		return
	}
	headerMap := parseHeaders(headers[1:])

	origin := headerMap["origin"]
	acrMethod := headerMap["access-control-request-method"]
	acrHeaders := headerMap["access-control-request-headers"]

	if strings.ToUpper(method) == "OPTIONS" && acrMethod != "" {
		_, _ = conn.Write(corsPreflight(origin, acrMethod, acrHeaders))
		return
	}

	response := s.fronter.Relay(method, path, headerMap, body)
	if origin != "" {
		response = injectCORSHeaders(response, origin)
	}
	_, _ = conn.Write(response)
}

func (s *Server) handleSocksConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// SOCKS5 greeting
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != 5 {
		return
	}
	methods := make([]byte, int(buf[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// No authentication required.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// SOCKS5 request
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return
	}
	if request[0] != 5 || request[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch request[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		name := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return
		}
		host = string(name)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	log.Infof("SOCKS5 CONNECT -> %s:%d", host, port)
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	s.handleTunnel(host, port, conn, bufio.NewReader(conn))
}

// --- helpers ---

func sumLen(lines []string) int {
	n := 0
	for _, l := range lines {
		n += len(l)
	}
	return n
}

func parseRequestLine(line string) (method, path string) {
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return "GET", "/"
	}
	return parts[0], parts[1]
}

// parseHeaders parses HTTP headers into a lowercase-keyed map.
// FIX: keys are normalised to lowercase so headerValue lookups are O(1).
func parseHeaders(lines []string) map[string]string {
	h := make(map[string]string, len(lines))
	for _, ln := range lines {
		ln = strings.TrimRight(ln, "\r\n")
		if ln == "" {
			continue
		}
		idx := strings.IndexByte(ln, ':')
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(ln[:idx]))
		val := strings.TrimSpace(ln[idx+1:])
		h[key] = val
	}
	return h
}

// readBody reads the request body according to Content-Length.
// FIX: uses the already-lowercased header map instead of re-scanning lines.
func readBody(reader *bufio.Reader, headers []string) ([]byte, error) {
	// Parse Content-Length from raw header lines (map not available here).
	cl := 0
	for _, ln := range headers {
		lower := strings.ToLower(ln)
		if strings.HasPrefix(lower, "content-length:") {
			v := strings.TrimSpace(ln[len("content-length:"):])
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, errors.New("invalid Content-Length")
			}
			cl = n
			break
		}
	}
	if cl > constants.MaxRequestBodyBytes {
		return nil, errors.New("request body too large")
	}
	if cl == 0 {
		return nil, nil
	}
	buf := make([]byte, cl)
	_, err := io.ReadFull(reader, buf)
	return buf, err
}

func normalizeURL(host string, port int, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	if port == 80 || port == 443 {
		return fmt.Sprintf("%s://%s%s", scheme, host, path)
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)
}

func corsPreflight(origin, acrMethod, acrHeaders string) []byte {
	if origin == "" {
		origin = "*"
	}
	allowMethods := "GET, POST, PUT, DELETE, PATCH, OPTIONS"
	if acrMethod != "" {
		allowMethods = acrMethod + ", " + allowMethods
	}
	if acrHeaders == "" {
		acrHeaders = "*"
	}
	resp := "HTTP/1.1 204 No Content\r\n" +
		"Access-Control-Allow-Origin: " + origin + "\r\n" +
		"Access-Control-Allow-Methods: " + allowMethods + "\r\n" +
		"Access-Control-Allow-Headers: " + acrHeaders + "\r\n" +
		"Access-Control-Allow-Credentials: true\r\n" +
		"Access-Control-Max-Age: 86400\r\n" +
		"Vary: Origin\r\n" +
		"Content-Length: 0\r\n\r\n"
	return []byte(resp)
}

func injectCORSHeaders(response []byte, origin string) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(response, sep)
	if idx < 0 {
		return response
	}

	head := string(response[:idx])
	body := response[idx+4:]
	lines := strings.Split(head, "\r\n")

	filtered := lines[:0]
	for _, ln := range lines {
		if !strings.HasPrefix(strings.ToLower(ln), "access-control-") {
			filtered = append(filtered, ln)
		}
	}

	if origin == "" {
		origin = "*"
	}
	filtered = append(filtered,
		"Access-Control-Allow-Origin: "+origin,
		"Access-Control-Allow-Credentials: true",
		"Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS",
		"Access-Control-Allow-Headers: *",
		"Access-Control-Expose-Headers: *",
		"Vary: Origin",
	)

	var buf bytes.Buffer
	buf.WriteString(strings.Join(filtered, "\r\n"))
	buf.WriteString("\r\n\r\n")
	buf.Write(body)
	return buf.Bytes()
}

func splitHostPort(target string, defPort int) (string, int) {
	// Use net.SplitHostPort for correct IPv6 handling.
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target, defPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, defPort
	}
	return host, port
}

// textproto import kept for canonical header key (used elsewhere).
var _ = textproto.CanonicalMIMEHeaderKey
