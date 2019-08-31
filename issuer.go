package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"math/big"
	"sync"
	"time"
)

type issuer struct {
	certsLock sync.RWMutex
	issueLock sync.Mutex
	certs     map[string]*tls.Certificate

	Logger      *log.Logger
	PrivateKey  *ecdsa.PrivateKey
	Certificate *x509.Certificate
	Cache       CacheStorage
}

func (s *issuer) Init() {
	s.certs = make(map[string]*tls.Certificate)
}

func (s *issuer) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// memory
	s.certsLock.RLock()
	cert := s.certs[info.ServerName]
	if cert != nil && time.Now().Before(cert.Leaf.NotAfter.AddDate(0, 0, -1)) {
		s.certsLock.RUnlock()
		return cert, nil
	}
	s.certsLock.RUnlock()

	// disk
	fnKey := "certs/" + cacheStoreKey(info.ServerName)
	if fp := s.Cache.Open(fnKey); fp != nil {
		b, _ := ioutil.ReadAll(fp)
		fp.Close()
		cert, _ := x509.ParseCertificate(b)
		if cert != nil {
			cert := &tls.Certificate{
				Certificate: [][]byte{b},
				PrivateKey:  s.PrivateKey,
				Leaf:        s.Certificate,
			}
			s.certsLock.Lock()
			s.certs[info.ServerName] = cert
			s.certsLock.Unlock()
			s.Logger.Printf("%s; certificate loaded", info.ServerName)
			return cert, nil
		}
	}

	cert, err := s.issueCert(info)
	if err != nil {
		return nil, err
	}

	// save
	if fp := s.Cache.Create(fnKey); fp != nil {
		copyBuffer(fp, bytes.NewReader(cert.Certificate[0]), 0)
		fp.Close()
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
		s.Logger.Printf("%s; issue certificate error; %v", info.ServerName, err)
		return nil, err
	}

	s.Logger.Printf("%s; certificate issued", info.ServerName)
	return &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  s.PrivateKey,
		Leaf:        s.Certificate,
	}, nil
}
