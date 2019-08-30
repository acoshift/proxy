package proxy

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"sync"
	"time"
)

type issuer struct {
	certsLock sync.RWMutex
	issueLock sync.Mutex
	certs     map[string]*tls.Certificate

	PrivateKey  *ecdsa.PrivateKey
	Certificate *x509.Certificate
}

func (s *issuer) Init() {
	s.certs = make(map[string]*tls.Certificate)
}

func (s *issuer) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.certsLock.RLock()
	cert := s.certs[info.ServerName]
	if cert != nil && time.Now().Before(cert.Leaf.NotAfter.AddDate(0, 0, -1)) {
		s.certsLock.RUnlock()
		return cert, nil
	}
	s.certsLock.RUnlock()

	cert, err := s.issueCert(info)
	if err != nil {
		return nil, err
	}

	s.certsLock.Lock()
	s.certs[info.ServerName] = cert
	s.certsLock.Unlock()
	return cert, nil
}

func (s *issuer) issueCert(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.issueLock.Lock()
	defer s.issueLock.Unlock()

	s.certsLock.RLock()
	if cert := s.certs[info.ServerName]; cert != nil {
		s.certsLock.RUnlock()
		return cert, nil
	}
	s.certsLock.RUnlock()

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	x509Cert := &x509.Certificate{
		Issuer:       s.Certificate.Subject,
		SerialNumber: serial,
		NotBefore:    now.AddDate(0, 0, -1).UTC(),
		NotAfter:     now.AddDate(1, 0, 0).UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{info.ServerName},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, x509Cert, s.Certificate, &s.PrivateKey.PublicKey, s.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  s.PrivateKey,
		Leaf:        s.Certificate,
	}
	return cert, nil
}
