package proxy

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/acoshift/middleware"
)

type Proxy struct {
	PrivateKey  *ecdsa.PrivateKey
	Certificate *x509.Certificate
	CacheDir    string // empty string to disable cache

	once      sync.Once
	certsLock sync.RWMutex
	issueLock sync.Mutex
	certs     map[string]*tls.Certificate
	server    *http.Server
	tr        *http.Transport
	httpsConn chan net.Conn
	cache     cache
}

func (p *Proxy) init() {
	p.certs = make(map[string]*tls.Certificate)
	p.httpsConn = make(chan net.Conn)
	p.cache.dir = p.CacheDir

	p.tr = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       5 * time.Minute,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	mw := middleware.Chain(
		middleware.Compress(middleware.BrCompressor),
	)

	connPipe := &connPipe{p.httpsConn}
	p.server = &http.Server{
		ErrorLog:     log.New(ioutil.Discard, "", 0),
		Handler:      mw(http.HandlerFunc(p.proxyHTTPS)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  3 * time.Minute,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				p.certsLock.RLock()
				cert := p.certs[info.ServerName]
				if cert != nil && time.Now().Before(cert.Leaf.NotAfter.AddDate(0, 0, -1)) {
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
		NotBefore:    now.AddDate(0, 0, -1).UTC(),
		NotAfter:     now.AddDate(1, 0, 0).UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{info.ServerName},
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
	r.URL.Host = r.Host

	if r.Header.Get("Connection") == "Upgrade" {
		host, port, _ := net.SplitHostPort(r.Host)
		if port == "" {
			if r.URL.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		if host == "" {
			host = r.Host
		}

		var (
			upstream net.Conn
			err      error
		)
		if r.URL.Scheme == "https" {
			upstream, err = tls.Dial("tcp", host+":"+port, nil)
		} else {
			upstream, err = net.Dial("tcp", host+":"+port)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer upstream.Close()

		downstream, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer downstream.Close()

		r.Write(upstream)

		go copyBuffer(downstream, upstream)
		copyBuffer(upstream, downstream)
		return
	}

	if resp := p.cache.get(r); resp != nil {
		w.Header().Set("X-Proxy-Cache-Status", "HIT")
		resp.WriteTo(w)
		return
	}

	req := *r
	req.Header = make(http.Header)
	copyHeaders(req.Header, r.Header)

	req.Header.Set("Connection", "keep-alive")
	req.Header.Del("Accept-Encoding")

	resp, err := p.tr.RoundTrip(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if cit := p.cache.NewItem(resp); cit != nil {
		w.Header().Set("X-Proxy-Cache-Status", "MISS")
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, err = copyBuffer(io.MultiWriter(w, cit), resp.Body)
		cit.CloseWithError(err)
		return
	}

	w.Header().Set("X-Proxy-Cache-Status", "DISABLE")
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	copyBuffer(w, resp.Body)
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
