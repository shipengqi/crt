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
	"crypto/x509"
	"log"
	"net"
	"os"
	"time"

	"github.com/shipengqi/crt"
	"github.com/shipengqi/crt/generator"
	"github.com/shipengqi/crt/key"
)

func main() {

        // ---------------------------------
	// Create Certificate Examples
	
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

	// ---------------------------------
	// Create Generator Examples
	
	// create a Generator instance
	// by default, use RSA key generator
	g1 := generator.New()
	// create a Generator instance with specified key generator
	kgen := key.NewEcdsaKey(nil)
	g2 := generator.New(generator.WithKeyGenerator(kgen))

	// ---------------------------------
	// generate Certificate Examples
	
	// generate CA certificate
	cf, _ := os.Create("ca.crt")
	pf, _ := os.Create("ca.key")
	w := generator.NewFileWriter(cf, pf)
	err := g1.CreateAndWrite(w, caCrt)
	if err != nil {
		log.Fatalln(err)
	}
	
	// generate server certificate
	// set the CA for the generator
	_, _, err = g1.CreateWithOptions(caCrt, generator.CreateOptions{
		UseAsCA: true,
	})
	// generate server certificate files
	cf, _ = os.Create("server.crt")
	pf, _ = os.Create("server.key")
	w := generator.NewFileWriter(cf, pf)
	err = g1.CreateAndWrite(w, serverCrt)
	if err != nil {
		log.Fatalln(err)
	}
}
```

## Documentation

You can find the docs at [go docs](https://pkg.go.dev/github.com/shipengqi/crt).
