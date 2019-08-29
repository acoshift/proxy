package proxy

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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
	Logger         *log.Logger
	PrivateKey     *ecdsa.PrivateKey
	Certificate    *x509.Certificate
	TLSConfig      *tls.Config
	Cache          Cache
	BlacklistHosts []string
	TunnelHosts    []string

	initOnce       sync.Once
	certsLock      sync.RWMutex
	issueLock      sync.Mutex
	certs          map[string]*tls.Certificate
	server         *http.Server
	tr             *http.Transport
	httpsConn      chan net.Conn
	blacklistIndex index
	tunnelIndex    index
}

// Init proxy now instead of lazy init
func (p *Proxy) Init() {
	p.initOnce.Do(p.init)
}

func (p *Proxy) init() {
	p.certs = make(map[string]*tls.Certificate)
	p.httpsConn = make(chan net.Conn)
	p.blacklistIndex = loadIndex(p.BlacklistHosts)
	p.tunnelIndex = loadIndex(p.TunnelHosts)

	if p.TLSConfig == nil {
		p.TLSConfig = &tls.Config{}
	}
	if p.Cache == nil {
		p.Cache = noCache{}
	}
	if p.Logger == nil {
		p.Logger = log.New(ioutil.Discard, "", 0)
	}

	p.tr = &http.Transport{
		DialContext: (&RetryDialer{
			Dialer: net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			},
			MaxRetries: 2,
		}).DialContext,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       5 * time.Minute,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	connPipe := newConnPipe(p.httpsConn)

	p.TLSConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
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
	}

	mw := middleware.Chain(
		middleware.Compress(middleware.BrCompressor),
	)

	p.server = &http.Server{
		ErrorLog:     p.Logger,
		Handler:      mw(http.HandlerFunc(p.proxyHTTPS)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  3 * time.Minute,
		TLSConfig:    p.TLSConfig,
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
	x509Cert := &x509.Certificate{
		Issuer:       p.Certificate.Subject,
		SerialNumber: serial,
		NotBefore:    now.AddDate(0, 0, -1).UTC(),
		NotAfter:     now.AddDate(1, 0, 0).UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{info.ServerName},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, x509Cert, p.Certificate, &p.PrivateKey.PublicKey, p.PrivateKey)
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

func (p *Proxy) useTunnel(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = r.Host
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}

	if matchHost(p.tunnelIndex, host) {
		return true
	}

	return false
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.initOnce.Do(p.init)

	// blacklist
	if matchHost(p.blacklistIndex, r.Host) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

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
			p.Logger.Printf("upstream %s; dial error; %v", r.Host, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
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

		stream(downstream, upstream)
		return
	}

	if resp := p.Cache.Get(r); resp != nil {
		w.Header().Set("X-Proxy-Cache-Status", "HIT")
		resp.WriteTo(w)
		return
	}

	req := *r
	req.Header = make(http.Header)
	copyHeaders(req.Header, r.Header)

	req.Header.Set("Connection", "keep-alive")
	req.Header.Del("Accept-Encoding")

	if req.ContentLength == 0 {
		req.Body = nil
	}

	resp, err := p.tr.RoundTrip(&req)
	if err != nil {
		p.Logger.Printf("upstream %s; round trip error; %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	resp.Header.Del("Keep-Alive")

	if cit := p.Cache.NewItem(resp); cit != nil {
		w.Header().Set("X-Proxy-Cache-Status", "MISS")
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, err = copyBuffer(io.MultiWriter(w, cit), resp.Body, resp.ContentLength)
		cit.CloseWithError(err)
		return
	}

	w.Header().Set("X-Proxy-Cache-Status", "DISABLE")
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	copyBuffer(w, resp.Body, resp.ContentLength)
}

func (p *Proxy) proxyHTTPS(w http.ResponseWriter, r *http.Request) {
	r.URL.Scheme = "https"
	p.proxyHTTP(w, r)
}

func (p *Proxy) tunnelHTTPS(w http.ResponseWriter, r *http.Request) {
	// is request skipped, stream directly
	if p.useTunnel(r) {
		p.Logger.Printf("tunnel %s", r.Host)

		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			p.Logger.Printf("upstream %s; dial error; %v", r.Host, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstream.Close()

		downstream, wr, err := w.(http.Hijacker).Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer downstream.Close()

		wr.WriteString("HTTP/1.1 200 OK\r\n\r\n")
		wr.Flush()

		stream(upstream, downstream)
		return
	}

	p.Logger.Printf("proxies %s", r.Host)

	downstream, wr, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	wr.WriteString("HTTP/1.1 200 OK\r\n\r\n")
	wr.Flush()

	p.httpsConn <- downstream
}

func copyHeaders(dst http.Header, src http.Header) {
	for k, v := range src {
		dst[k] = v
	}
}

func stream(s1, s2 io.ReadWriter) error {
	errCh := make(chan error)
	go func() {
		_, err := copyBuffer(s1, s2, 0)
		errCh <- err
	}()
	go func() {
		_, err := copyBuffer(s2, s1, 0)
		errCh <- err
	}()
	return <-errCh
}
