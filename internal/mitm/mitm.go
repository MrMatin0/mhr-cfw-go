package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	projectRoot = func() string {
		wd, err := os.Getwd()
		if err != nil {
			exe, _ := os.Executable()
			return filepath.Dir(exe)
		}
		return wd
	}()
	CADir      = filepath.Join(projectRoot, "ca")
	CAKeyFile  = filepath.Join(CADir, "ca.key")
	CACertFile = filepath.Join(CADir, "ca.crt")
)

// Manager handles MITM certificate generation and caching.
type Manager struct {
	mu     sync.RWMutex
	caKey  *rsa.PrivateKey
	caCert *x509.Certificate
	// FIX: cache stores *tls.Certificate values; protected by mu.
	cache map[string]*tls.Certificate
}

func NewManager() *Manager {
	m := &Manager{
		cache: make(map[string]*tls.Certificate),
	}
	m.ensureCA()
	return m
}

// GetServerTLSConfig returns a TLS config for intercepting a given domain.
func (m *Manager) GetServerTLSConfig(domain string) (*tls.Config, error) {
	cert, err := m.getCertificate(domain)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	}, nil
}

// getCertificate returns a cached or newly-generated leaf certificate for domain.
// FIX: uses RWMutex with double-checked locking to avoid duplicate generation
// and unnecessary write-lock contention.
func (m *Manager) getCertificate(domain string) (*tls.Certificate, error) {
	// Fast path: read lock.
	m.mu.RLock()
	if cert, ok := m.cache[domain]; ok {
		m.mu.RUnlock()
		return cert, nil
	}
	m.mu.RUnlock()

	// Slow path: write lock with re-check (double-checked locking).
	m.mu.Lock()
	defer m.mu.Unlock()

	if cert, ok := m.cache[domain]; ok {
		return cert, nil
	}

	if m.caKey == nil || m.caCert == nil {
		m.ensureCALocked()
	}

	// Generate leaf key — 2048-bit for speed (CA is 4096, which is the trust anchor).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:   now.Add(-time.Minute), // small skew tolerance
		NotAfter:    now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{domain}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// Chain leaf + CA so clients can build the trust path.
	tlsCert, err := tls.X509KeyPair(append(certPEM, caPEM...), keyPEM)
	if err != nil {
		return nil, err
	}

	m.cache[domain] = &tlsCert
	return &tlsCert, nil
}

// ensureCA loads the existing CA or generates a new one.
// Must NOT be called with mu held.
func (m *Manager) ensureCA() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureCALocked()
}

// ensureCALocked is the same as ensureCA but expects mu to already be held.
func (m *Manager) ensureCALocked() {
	if fileExists(CAKeyFile) && fileExists(CACertFile) {
		keyPEM, _ := os.ReadFile(CAKeyFile)
		certPEM, _ := os.ReadFile(CACertFile)
		key, _ := parsePrivateKeyPEM(keyPEM)
		cert, _ := parseCertPEM(certPEM)
		if key != nil && cert != nil {
			m.caKey = key
			m.caCert = cert
			return
		}
	}

	_ = os.MkdirAll(CADir, 0o755)
	// FIX: use 4096-bit for the CA (trust anchor) for stronger security.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic("mitm: failed to generate CA key: " + err.Error())
	}

	now := time.Now().UTC()
	ca := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   "mhr-cfw",
			Organization: []string{"mhr-cfw"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, _ := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	m.caKey = key
	m.caCert = cert

	writePEM(CAKeyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	writePEM(CACertFile, "CERTIFICATE", der)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writePEM(path, typ string, der []byte) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	_ = pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
	if os.PathSeparator == '/' {
		_ = os.Chmod(path, 0o600)
	}
}

func parsePrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if k, ok := key.(*rsa.PrivateKey); ok {
			return k, nil
		}
	}
	return nil, nil
}

func parseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil
	}
	return x509.ParseCertificate(block.Bytes)
}

func randomSerial() *big.Int {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)
	return serial
}
