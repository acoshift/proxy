package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/acoshift/middleware"
)

type Proxy struct {
	Logger           *log.Logger
	PrivateKey       *ecdsa.PrivateKey
	Certificate      *x509.Certificate
	TLSConfig        *tls.Config
	Transport        *http.Transport
	CacheStorage     CacheStorage
	BlacklistHosts   []string
	TunnelHosts      []string
	TunnelNotBrowser bool
	RedirectHTTPS    bool

	initOnce       sync.Once
	issuer         *issuer
	server         *http.Server
	httpsConn      chan net.Conn
	blacklistIndex index
	tunnelIndex    index
	cache          cacheBackend
}

// Init proxy now instead of lazy init
func (p *Proxy) Init() {
	p.initOnce.Do(p.init)
}

func (p *Proxy) init() {
	if p.Logger == nil {
		p.Logger = log.New(ioutil.Discard, "", 0)
	}

	if p.CacheStorage == nil {
		p.CacheStorage = noCache{}
	}
	p.cache.Store = p.CacheStorage

	p.issuer = &issuer{
		Logger:      p.Logger,
		PrivateKey:  p.PrivateKey,
		Certificate: p.Certificate,
		Cache:       p.CacheStorage,
	}
	p.issuer.Init()

	p.blacklistIndex = loadIndex(p.BlacklistHosts)
	p.tunnelIndex = loadIndex(p.TunnelHosts)

	if p.Transport == nil {
		p.Transport = &http.Transport{
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
	}

	if p.TLSConfig == nil {
		p.TLSConfig = &tls.Config{}
	}
	p.TLSConfig.GetCertificate = p.issuer.GetCertificate

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

	p.httpsConn = make(chan net.Conn)
	go p.server.ServeTLS(newConnPipe(p.httpsConn), "", "")
}

func (p *Proxy) useTunnel(r *http.Request) bool {
	if p.TunnelNotBrowser && !isBrowser(r) {
		return true
	}

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
		p.Logger.Printf("%s; blocked", r.Host)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		p.tunnelHTTPS(w, r)
		return
	}

	// p.RedirectHTTPS && (p.TunnelNotBrowser -> isBrowser(r))
	if p.RedirectHTTPS && (!p.TunnelNotBrowser || isBrowser(r)) {
		p.Logger.Printf("%s; redirect to https", r.Host)
		r.URL.Scheme = "https"
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
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
			p.Logger.Printf("%s; dial error; %v", r.Host, err)
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

	if resp := p.cache.Get(r); resp != nil {
		w.Header().Set("X-Proxy-Cache-Status", "HIT")
		copyResponse(resp, w)
		resp.Body.Close()
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

	resp, err := p.Transport.RoundTrip(&req)
	if err == context.Canceled {
		return
	}
	if err != nil {
		p.Logger.Printf("%s; round trip error; %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	resp.Header.Del("Keep-Alive")

	if cw := p.cache.NewWriter(resp); cw != nil {
		w.Header().Set("X-Proxy-Cache-Status", "MISS")
		cw.CloseWithError(copyResponse(resp, w, cw))
		return
	}

	w.Header().Set("X-Proxy-Cache-Status", "DISABLE")
	copyResponse(resp, w)
}

func (p *Proxy) proxyHTTPS(w http.ResponseWriter, r *http.Request) {
	r.URL.Scheme = "https"
	p.proxyHTTP(w, r)
}

func (p *Proxy) tunnelHTTPS(w http.ResponseWriter, r *http.Request) {
	if p.useTunnel(r) {
		p.Logger.Printf("%s; tunneled", r.Host)

		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			p.Logger.Printf("%s; dial error; %v", r.Host, err)
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

		wr.WriteString(proxyConnect)
		wr.Flush()

		stream(upstream, downstream)
		return
	}

	p.Logger.Printf("%s: proxied", r.Host)

	downstream, wr, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	wr.WriteString(proxyConnect)
	wr.Flush()

	p.httpsConn <- downstream
}
