package main

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	cacheStorage          = flag.String("cache", "", "Cache storage backend. ex. memory, dir")
	cacheDirPath          = flag.String("cache.dir.path", "", "Cache directory path")
	logEnable             = flag.Bool("log", false, "Enable log")
	authUser              = flag.String("auth.user", "", "Auth username")
	authPass              = flag.String("auth.pass", "", "Auth password")
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
		},
		BlacklistHosts:   append(loadList(*proxyBlacklistFile), splitList(*proxyBlacklist)...),
		TunnelHosts:      append(loadList(*proxyTunnelFile), splitList(*proxyTunnel)...),
		TunnelNotBrowser: *proxyTunnelNotBrowser,
		RedirectHTTPS:    *proxyRedirectHTTPS,
	}
	if *authUser != "" && *authPass != "" {
		p.Auth = func(r *http.Request) bool {
			auth := r.Header.Get("Proxy-Authorization")
			if auth == "" {
				return false
			}
			user, pass, ok := parseBasicAuth(auth)
			if !ok {
				return false
			}
			okUser := subtle.ConstantTimeCompare([]byte(*authUser), []byte(user)) == 1
			okPass := subtle.ConstantTimeCompare([]byte(*authPass), []byte(pass)) == 1
			return okUser && okPass
		}
	}
	switch *cacheStorage {
	case "dir":
		p.CacheStorage = &cache.Dir{Path: *cacheDirPath}
	case "memory":
		p.CacheStorage = &cache.Memory{}
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

// copy from http.parseBasicAuth
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}
