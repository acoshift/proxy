package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/acoshift/proxy"
	"github.com/acoshift/proxy/cache"
)

var (
	port                  = flag.Int("port", 9000, "Port")
	proxyTunnel           = flag.String("proxy.tunnel", "", "Use tunnel mode for given hosts")
	proxyTunnelFile       = flag.String("proxy.tunnel.file", "", "Load tunnel from file")
	proxyTunnelNotBrowser = flag.Bool("proxy.tunnel.notbrowser", false, "Use tunnel for app that is not browser")
	proxyBlacklist        = flag.String("proxy.blacklist", "", "Blacklist hosts")
	proxyBlacklistFile    = flag.String("proxy.blacklist.file", "", "Load blacklist from file")
	proxyRedirectHTTPS    = flag.Bool("proxy.redirecthttps", false, "Redirect HTTP to HTTPS")
	caKey                 = flag.String("ca.key", "ca.key", "CA Private Key")
	caCert                = flag.String("ca.crt", "ca.crt", "CA Certificate")
	cachePath             = flag.String("cache.path", "", "Cache directory path")
	logEnable             = flag.Bool("log", false, "Enable log")
)

func main() {
	flag.Parse()

	privateKey, err := x509.ParseECPrivateKey(loadPem(*caKey))
	if err != nil {
		log.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(loadPem(*caCert))
	if err != nil {
		log.Fatal(err)
	}

	p := &proxy.Proxy{
		PrivateKey:  privateKey,
		Certificate: certificate,
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
		},
		BlacklistHosts:   append(loadList(*proxyBlacklistFile), splitList(*proxyBlacklist)...),
		TunnelHosts:      append(loadList(*proxyTunnelFile), splitList(*proxyTunnel)...),
		TunnelNotBrowser: *proxyTunnelNotBrowser,
		RedirectHTTPS:    *proxyRedirectHTTPS,
	}
	if *cachePath != "" {
		p.CacheStorage = &cache.DirStorage{Path: *cachePath}
	}
	if *logEnable {
		p.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	p.Init()

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), p))
}

func loadPem(filename string) []byte {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(b)
	return block.Bytes
}

func loadList(filename string) []string {
	bs, _ := ioutil.ReadFile(filename)

	var xs []string
	for _, x := range strings.Split(string(bs), "\n") {
		x = strings.TrimSpace(x)
		if x == "" || strings.HasPrefix(x, "#") {
			continue
		}
		xs = append(xs, x)
	}
	return xs
}

func splitList(list string) []string {
	var xs []string

	for _, x := range strings.Split(list, ",") {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		xs = append(xs, x)
	}
	return xs
}
