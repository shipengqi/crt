package crt_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/shipengqi/crt/key"
	"github.com/stretchr/testify/assert"

	. "github.com/shipengqi/crt"
	"github.com/shipengqi/crt/generator"
)

var filelist []string

type mockwriter struct {}

func (w *mockwriter) Write(cert, priv []byte, certname, privname string) error {return nil}

func TestCertificateGenerator(t *testing.T) {
	t.Run("FileWriter", func(t *testing.T) {
		t.Run("Create CA certificate", func(t *testing.T) {
			caPath := "testdata/ca.crt"
			caKeyPath := "testdata/ca.key"

			t.Run("New(), should return nil", func(t *testing.T) {
				g := generator.New()
				filelist = append(filelist, caPath, caKeyPath)
				cert := New(WithCAType())
				err := g.CreateAndWrite(cert, caPath, caKeyPath)
				assert.Nil(t, err)

				parsedCert, err := parseCertFile(caPath)
				assert.Nil(t, err)
				assert.True(t, parsedCert.IsCA)
				assert.Empty(t, parsedCert.Issuer.CommonName)
				assert.Equal(t, parsedCert.NotBefore.Add(24*366*10*time.Hour), parsedCert.NotAfter)
				reset()
			})

			t.Run("NewCACert(), should return nil", func(t *testing.T) {
				g := generator.New()
				filelist = append(filelist, caPath, caKeyPath)
				cert := NewCACert()
				err := g.CreateAndWrite(cert, caPath, caKeyPath)
				assert.Nil(t, err)

				parsedCert, err := parseCertFile(caPath)
				assert.Nil(t, err)
				assert.True(t, parsedCert.IsCA)
				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Issuer.CommonName)
				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Subject.CommonName)
				assert.Equal(t, parsedCert.NotBefore.Add(24*366*10*time.Hour), parsedCert.NotAfter)
				reset()
			})
		})

		t.Run("Create Server certificate", func(t *testing.T) {
			serverCrtPath := "testdata/server.crt"
			serverKeyPath := "testdata/server.key"

			t.Run("New(), should return error: CA certificate or private key is not provided", func(t *testing.T) {
				filelist = append(filelist, serverCrtPath, serverKeyPath)
				g := generator.New()
				cert := New(
					WithServerType(),
					WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
					WithExtKeyUsages(x509.ExtKeyUsageServerAuth),
				)
				err := g.CreateAndWrite(cert, serverCrtPath, serverKeyPath)
				assert.Equal(t, "x509: CA certificate or private key is not provided",
					err.Error())
				reset()
			})
			t.Run("New(), should return nil", func(t *testing.T) {
				filelist = append(filelist, serverCrtPath, serverKeyPath)
				g := createGenWithCA(t)
				cert := New(
					WithServerType(),
					WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
					WithExtKeyUsages(x509.ExtKeyUsageServerAuth),
				)
				err := g.CreateAndWrite(cert, serverCrtPath, serverKeyPath)
				assert.Nil(t, err)

				parsedCert, err := parseCertFile(serverCrtPath)
				assert.Nil(t, err)
				assert.False(t, parsedCert.IsCA)
				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Issuer.CommonName)
				assert.Empty(t, parsedCert.Subject.CommonName)
				assert.Equal(t, parsedCert.NotBefore.Add(365*24*time.Hour), parsedCert.NotAfter)
				reset()
			})
			t.Run("NewServerCert(), should return nil", func(t *testing.T) {
				filelist = append(filelist, serverCrtPath, serverKeyPath)
				g := createGenWithCA(t)

				cert := NewServerCert()
				err := g.CreateAndWrite(cert, serverCrtPath, serverKeyPath)
				assert.Nil(t, err)

				parsedCert, err := parseCertFile(serverCrtPath)
				assert.Nil(t, err)
				assert.False(t, parsedCert.IsCA)
				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Issuer.CommonName)
				assert.NotEmpty(t, parsedCert.Subject.CommonName)
				assert.Equal(t, parsedCert.NotBefore.Add(365*24*time.Hour), parsedCert.NotAfter)
				reset()
			})
		})

		t.Run("Create Client certificate", func(t *testing.T) {
			clientCrtPath := "testdata/client.crt"
			clientKeyPath := "testdata/client.key"
			t.Run("New(), should return nil", func(t *testing.T) {
				filelist = append(filelist, clientCrtPath, clientKeyPath)
				g := createGenWithCA(t)

				cert := New(
					WithClientType(),
					WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
					WithExtKeyUsages(x509.ExtKeyUsageClientAuth),
				)
				err := g.CreateAndWrite(cert, clientCrtPath, clientKeyPath)
				assert.Nil(t, err)

				parsedCert, err := parseCertFile(clientCrtPath)
				assert.Nil(t, err)
				assert.False(t, parsedCert.IsCA)

				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Issuer.CommonName)
				assert.Empty(t, parsedCert.Subject.CommonName)
				assert.Equal(t, parsedCert.NotBefore.Add(365*24*time.Hour), parsedCert.NotAfter)
				reset()
			})

			t.Run("NewClientCert(), should return nil", func(t *testing.T) {
				filelist = append(filelist, clientCrtPath, clientKeyPath)
				g := createGenWithCA(t)

				cert := NewClientCert()
				err := g.CreateAndWrite(cert, clientCrtPath, clientKeyPath)
				assert.Nil(t, err)

				parsedCert, err := parseCertFile(clientCrtPath)
				assert.Nil(t, err)
				assert.False(t, parsedCert.IsCA)

				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Issuer.CommonName)
				assert.NotEmpty(t, parsedCert.Subject.CommonName)
				assert.Equal(t, parsedCert.NotBefore.Add(365*24*time.Hour), parsedCert.NotAfter)
				reset()
			})
		})
		t.Run("Create and Write with option", func(t *testing.T) {
			g := createGenWithCA(t)

			cert := NewClientCert()
			kyeg := key.NewEcdsaKey()
			crtRaw, keyRaw, err := g.CreateWithOptions(cert, generator.CreateOptions{G: kyeg})
			assert.Nil(t, err)

			parsedCert, err := parseCertBytes(crtRaw)
			assert.Nil(t, err)
			assert.False(t, parsedCert.IsCA)


			assert.Equal(t, "CRT GENERATOR CA", parsedCert.Issuer.CommonName)
			assert.NotEmpty(t, parsedCert.Subject.CommonName)
			assert.Equal(t, parsedCert.NotBefore.Add(365*24*time.Hour), parsedCert.NotAfter)
			parsedKey, err := parseKeyBytes(keyRaw)
			assert.Nil(t, err)
			_, ok := parsedKey.(*ecdsa.PrivateKey)
			assert.True(t, ok)

			err = g.WriteWithOptions(crtRaw, keyRaw, "", "", generator.WriteOptions{W: &mockwriter{}})
			assert.Nil(t, err)
		})

	})
}

func reset() {
	_ = cleanfiles(filelist)
	filelist = []string{}
}
