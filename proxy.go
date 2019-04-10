package proxy

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

type Proxy struct {
	PrivateKey  *ecdsa.PrivateKey
	Certificate *x509.Certificate

	once      sync.Once
	certsLock sync.RWMutex
	issueLock sync.Mutex
	certs     map[string]*tls.Certificate
	server    *http.Server
	tr        *http.Transport
	httpsConn chan net.Conn
}

func (p *Proxy) init() {
	p.certs = make(map[string]*tls.Certificate)
	p.httpsConn = make(chan net.Conn)

	connPipe := &connPipe{p.httpsConn}
	p.server = &http.Server{
		Handler: http.HandlerFunc(p.proxyHTTPS),
		TLSConfig: &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				p.certsLock.RLock()
				if cert := p.certs[info.ServerName]; cert != nil {
					p.certsLock.RUnlock()
					return cert, nil
				}
				p.certsLock.RUnlock()

				cert, err := p.issueCert(info)
				if err != nil {
					return nil, err
				}

				p.certsLock.Lock()
				p.certs[info.ServerName] = cert
				p.certsLock.Unlock()
				return cert, nil
			},
		},
	}
	go p.server.ServeTLS(connPipe, "", "")

	p.tr = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		DisableCompression:    true,
		MaxIdleConns:          5000,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       5 * time.Minute,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func (p *Proxy) issueCert(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.issueLock.Lock()
	defer p.issueLock.Unlock()

	p.certsLock.RLock()
	if cert := p.certs[info.ServerName]; cert != nil {
		p.certsLock.RUnlock()
		return cert, nil
	}
	p.certsLock.RUnlock()

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	certBytes, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject: pkix.Name{
			CommonName: info.ServerName,
		},
		Issuer:       p.Certificate.Subject,
		SerialNumber: serial,
		NotBefore:    now.UTC(),
		NotAfter:     now.Add(3650 * 24 * time.Hour).UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{info.ServerName},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, p.Certificate, &p.PrivateKey.PublicKey, p.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  p.PrivateKey,
		Leaf:        p.Certificate,
	}
	return cert, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.once.Do(p.init)

	if r.Method == http.MethodConnect {
		p.tunnelHTTPS(w, r)
		return
	}

	p.proxyHTTP(w, r)
}

func (p *Proxy) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Connection", "keep-alive")
	r.URL.Host = r.Host

	resp, err := p.tr.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	buf := getBuffer()
	defer putBuffer(buf)
	io.CopyBuffer(w, resp.Body, buf)
}

func (p *Proxy) proxyHTTPS(w http.ResponseWriter, r *http.Request) {
	r.URL.Scheme = "https"
	p.proxyHTTP(w, r)
}

func (p *Proxy) tunnelHTTPS(w http.ResponseWriter, r *http.Request) {
	downstream, wr, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	wr.WriteString("HTTP/1.1 200 OK\n\n")
	wr.Flush()

	p.httpsConn <- downstream
}

func copyHeaders(dst http.Header, src http.Header) {
	for k, v := range src {
		dst[k] = v
	}
}

type connPipe struct {
	conn <-chan net.Conn
}

func (lis *connPipe) Accept() (net.Conn, error) {
	return <-lis.conn, nil
}

func (*connPipe) Close() error {
	return nil
}

func (*connPipe) Addr() net.Addr {
	return nil
}
