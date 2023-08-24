# Certificates Generator

[![test](https://github.com/shipengqi/crt/actions/workflows/test.yaml/badge.svg)](https://github.com/shipengqi/crt/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/shipengqi/crt/branch/main/graph/badge.svg?token=SMU4SI304O)](https://codecov.io/gh/shipengqi/crt)
[![Go Report Card](https://goreportcard.com/badge/github.com/shipengqi/crt)](https://goreportcard.com/report/github.com/shipengqi/crt)
[![release](https://img.shields.io/github/release/shipengqi/crt.svg)](https://github.com/shipengqi/crt/releases)
[![license](https://img.shields.io/github/license/shipengqi/crt)](https://github.com/shipengqi/crt/blob/main/LICENSE)

## Getting Started

```go
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net"
	"time"

	"github.com/shipengqi/crt"
	"github.com/shipengqi/crt/generator"
	"github.com/shipengqi/crt/key"
)

func main() {

	// create a certificate
	exCert := crt.New(
		crt.WithCN("example.com"),
		crt.WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
		crt.WithExtKeyUsages(x509.ExtKeyUsageServerAuth),
		crt.WithDNSNames("foo.example.com", "bar.example.com"),
		crt.WithIPs(net.ParseIP("16.187.0.1"), net.ParseIP("16.187.0.2")),
		crt.WithOrganizations("org1"),
		crt.WithValidity(time.Hour*24*365),
	)

	// create a server certificate
	serverCrt := crt.NewServerCert()

	// create a client certificate
	clientCrt := crt.NewClientCert()

	// create a CA certificate
	caCrt := crt.NewCACert()

	// ------------------------
	// create a Generator instance
	// by default, use RSA key generator
	g1 := generator.New()
	// create a Generator instance with specified key generator
	kgen := key.NewEcdsaKey(nil)
	g2 := generator.New(generator.WithKeyGenerator(kgen))
	
	// --------------------------------
	// generate CA certificate
	err := g1.CreateAndWrite(caCrt, "ca.crt", "ca.key")
	if err != nil {
		log.Fatalln(err)
	}
	
	// generate server certificate
	// set the CA first
	ca, cakey, err := g1.CreateWithOptions(caCrt, generator.CreateOptions{
		UseAsCA: true,
	})
	err = g1.Write(ca, cakey, "ca.crt", "ca.key")
	if err != nil {
		log.Fatalln(err)
	}
	err = g1.CreateAndWrite(serverCrt, "server.crt", "server.key")
	if err != nil {
		log.Fatalln(err)
	}
}

func parseCertBytes(data []byte) (*x509.Certificate, error) {
	if len(data) == 0 {
		return nil, nil
	}
	bl, _ := pem.Decode(data)
	if bl == nil {
		return nil, errors.New("no pem data is found")
	}
	cert, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}


func parseKeyBytes(pkey []byte) (crypto.PrivateKey, error) {
	var err error
	bl, _ := pem.Decode(pkey)
	keyBytes := bl.Bytes

	var pkcs1 *rsa.PrivateKey
	if pkcs1, err = x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return pkcs1, nil
	}
	var eck *ecdsa.PrivateKey
	if eck, err = x509.ParseECPrivateKey(keyBytes); err == nil {
		return eck, nil
	}
	
	var pkcs8 interface{}
	if pkcs8, err = x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		switch pkcs8k := pkcs8.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return pkcs8k, nil
		default:
			return nil, errors.New("unknown private key type in PKCS#8 wrapping")
		}
	}
	
	return nil, err
}
```

## Documentation

You can find the docs at [go docs](https://pkg.go.dev/github.com/shipengqi/crt).
