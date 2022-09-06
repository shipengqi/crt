package crt_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"testing"

	. "github.com/shipengqi/crt"
	"github.com/shipengqi/crt/generator"
	"github.com/stretchr/testify/assert"
)

func parseCertFile(fpath string) (*x509.Certificate, error) {
	bs, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	return parseCertBytes(bs)
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


func parseKeyBytes(key []byte) (crypto.PrivateKey, error) {
	var err error
	bl, _ := pem.Decode(key)
	keyBytes := bl.Bytes

	var pkcs1 *rsa.PrivateKey
	if pkcs1, err = x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return pkcs1, nil
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

	var eck *ecdsa.PrivateKey
	if eck, err = x509.ParseECPrivateKey(keyBytes); err == nil {
		return eck, nil
	}
	return nil, err
}

func cleanfiles(files []string) error {
	for _, v := range files {
		_ = os.Remove(v)
	}
	return nil
}

func createGenWithCA(t *testing.T) *generator.Generator {
	t.Helper()

	g := generator.New()
	cacert := New(WithCAType())
	ca, cakey, err := g.Create(cacert)
	assert.Nil(t, err)
	parsedca, err := parseCertBytes(ca)
	assert.Nil(t, err)
	parsedcakey, err := parseKeyBytes(cakey)
	assert.Nil(t, err)
	g.SetCA(parsedca, parsedcakey)

	return g
}
