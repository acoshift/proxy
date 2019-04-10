package main

import (
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

	http.ListenAndServe(":"+port, &proxy.Proxy{
		PrivateKey:  privateKey,
		Certificate: certificate,
	})
}

func loadPem(filename string) []byte {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(b)
	return block.Bytes
}
