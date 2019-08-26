package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/acoshift/proxy"
)

func main() {
	var port = os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	privateKey, err := x509.ParseECPrivateKey(loadPem("ca.key"))
	if err != nil {
		log.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(loadPem("ca.crt"))
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.ListenAndServe(":"+port, &proxy.Proxy{
		PrivateKey:  privateKey,
		Certificate: certificate,
		CacheDir:    os.Getenv("CACHE_DIR"),
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
