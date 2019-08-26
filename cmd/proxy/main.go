package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/acoshift/middleware"

	"github.com/acoshift/proxy"
)

var (
	port      = flag.Int("port", 9000, "Port")
	noproxy   = flag.String("noproxy", "", "Disable HTTP(S) proxy for given domain/ip")
	caKey     = flag.String("ca.key", "ca.key", "CA Private Key")
	caCert    = flag.String("ca.crt", "ca.crt", "CA Certificate")
	cachePath = flag.String("cache.path", "", "Cache directory path")
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

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), &proxy.Proxy{
		Skipper:     noProxySkipper(),
		PrivateKey:  privateKey,
		Certificate: certificate,
		CacheDir:    *cachePath,
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
	}))
}

func loadPem(filename string) []byte {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(b)
	return block.Bytes
}

func noProxySkipper() middleware.Skipper {
	list := strings.Split(*noproxy, ",")

	// parse := func(x string) interface{} {
	// 	{
	// 		ip := net.ParseIP(x)
	// 		if ip != nil {
	// 			return ip
	// 		}
	// 	}
	//
	// 	{
	// 		_, cidr, _ := net.ParseCIDR(x)
	// 		if cidr != nil {
	// 			return cidr
	// 		}
	// 	}
	//
	// 	return x
	// }
	//
	// var parsedList []interface{}
	// for _, x := range list {
	// 	parsedList = append(parsedList, parse(x))
	// }

	return func(r *http.Request) bool {
		host, _, _ := net.SplitHostPort(r.Host)
		if host == "" {
			host = r.Host
		}
		for _, x := range list {
			if x == host {
				return true
			}
		}
		return false
	}
}
