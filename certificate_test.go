package crt_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/shipengqi/crt/key"
	"github.com/stretchr/testify/assert"

	. "github.com/shipengqi/crt"
	"github.com/shipengqi/crt/generator"
)

var filelist []string

func TestCertificateGenerator(t *testing.T) {
	t.Run("FileWriter", func(t *testing.T) {
		t.Run("Create CA certificate", func(t *testing.T) {
			caPath := "testdata/ca.crt"
			caKeyPath := "testdata/ca.key"

			t.Run("New(), should return nil", func(t *testing.T) {
				g := generator.New()
				filelist = append(filelist, caPath, caKeyPath)
				cert := New(WithCAType())
				cf, err := os.Create(caPath)
				assert.NoError(t, err)
				pf, err := os.Create(caKeyPath)
				assert.NoError(t, err)
				w := generator.NewFileWriter(cf, pf)
				err = g.CreateAndWrite(w, cert)
				assert.NoError(t, err)

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
				w, err := generator.NewFileWriterFromPaths(caPath, caKeyPath)
				assert.NoError(t, err)
				err = g.CreateAndWrite(w, cert)
				assert.Nil(t, err)

				parsedCert, err := parseCertFile(caPath)
				assert.Nil(t, err)
				assert.True(t, parsedCert.IsCA)
				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Issuer.CommonName)
				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Subject.CommonName)
				assert.Equal(t, parsedCert.NotBefore.Add(24*366*10*time.Hour), parsedCert.NotAfter)
				reset()
			})
			t.Run("NewCACert(), UseAsCA true, AppendCA should be ignored", func(t *testing.T) {
				g := generator.New()
				filelist = append(filelist, caPath, caKeyPath)
				cert := NewCACert()
				w, err := generator.NewFileWriterFromPaths(caPath, caKeyPath)
				assert.NoError(t, err)
				certRaw, keyRaw, err := g.CreateWithOptions(cert, generator.CreateOptions{UseAsCA: true, AppendCA: true})
				err = w.Write(certRaw, keyRaw)
				defer func() { _ = w.Close() }()
				assert.NoError(t, err)

				parsedCerts, err := parseMultiCertFromFile(caPath)
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCerts))
				parsedCert := parsedCerts[0]
				assert.True(t, parsedCert.IsCA)
				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Issuer.CommonName)
				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Subject.CommonName)
				assert.Equal(t, parsedCert.NotBefore.Add(24*366*10*time.Hour), parsedCert.NotAfter)
				reset()
			})
			t.Run("NewCACert(), UseAsCA false, AppendCA should be ignored", func(t *testing.T) {
				g := generator.New()
				filelist = append(filelist, caPath, caKeyPath)
				cert := NewCACert()
				w, err := generator.NewFileWriterFromPaths(caPath, caKeyPath)
				assert.NoError(t, err)
				certRaw, keyRaw, err := g.CreateWithOptions(cert, generator.CreateOptions{UseAsCA: false, AppendCA: true})
				err = w.Write(certRaw, keyRaw)
				defer func() { _ = w.Close() }()
				assert.NoError(t, err)

				parsedCerts, err := parseMultiCertFromFile(caPath)
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCerts))
				parsedCert := parsedCerts[0]
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
				cf, err := os.Create(serverCrtPath)
				assert.NoError(t, err)
				pf, err := os.Create(serverKeyPath)
				assert.NoError(t, err)
				w := generator.NewFileWriter(cf, pf)
				err = g.CreateAndWrite(w, cert)

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
				cf, err := os.Create(serverCrtPath)
				assert.NoError(t, err)
				pf, err := os.Create(serverKeyPath)
				assert.NoError(t, err)
				w := generator.NewFileWriter(cf, pf)
				err = g.CreateAndWrite(w, cert)

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
				w, err := generator.NewFileWriterFromPaths(serverCrtPath, serverKeyPath)
				assert.NoError(t, err)
				err = g.CreateAndWrite(w, cert)

				assert.Nil(t, err)

				parsedCert, err := parseCertFile(serverCrtPath)
				assert.Nil(t, err)
				assert.False(t, parsedCert.IsCA)
				assert.Equal(t, "CRT GENERATOR CA", parsedCert.Issuer.CommonName)
				assert.NotEmpty(t, parsedCert.Subject.CommonName)
				assert.Equal(t, parsedCert.NotBefore.Add(365*24*time.Hour), parsedCert.NotAfter)
				reset()
			})

			t.Run("NewServerCert(), append CA", func(t *testing.T) {
				filelist = append(filelist, serverCrtPath, serverKeyPath)
				g := createGenWithCA(t)

				cert := NewServerCert()
				w, err := generator.NewFileWriterFromPaths(serverCrtPath, serverKeyPath)
				assert.NoError(t, err)
				certRaw, keyRaw, err := g.CreateWithOptions(cert, generator.CreateOptions{AppendCA: true})
				assert.NoError(t, err)
				err = w.Write(certRaw, keyRaw)
				defer func() { _ = w.Close() }()
				assert.NoError(t, err)

				parsedCerts, err := parseMultiCertFromFile(serverCrtPath)
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCerts))
				assert.False(t, parsedCerts[0].IsCA)
				assert.True(t, parsedCerts[1].IsCA)
				assert.Equal(t, "CRT GENERATOR CA", parsedCerts[0].Issuer.CommonName)
				assert.Equal(t, "CRT GENERATOR CA", parsedCerts[1].Subject.CommonName)
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
				cf, err := os.Create(clientCrtPath)
				assert.NoError(t, err)
				pf, err := os.Create(clientKeyPath)
				assert.NoError(t, err)
				w := generator.NewFileWriter(cf, pf)
				err = g.CreateAndWrite(w, cert)

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
				w, err := generator.NewFileWriterFromPaths(clientCrtPath, clientKeyPath)
				assert.NoError(t, err)
				err = g.CreateAndWrite(w, cert)
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
	})
}

func TestPrivateKeyWithPass(t *testing.T) {
	testPass := []byte("123456")
	t.Run("Create RSA private key with passphrase", func(t *testing.T) {
		g := createGenWithCA(t)
		keyg := key.NewRsaKey(0)
		cert := NewServerCert()
		_, keyRaw, err := g.CreateWithOptions(cert, generator.CreateOptions{G: keyg, KeyOpts: &key.MarshalOptions{
			Password: testPass,
		}})
		assert.Nil(t, err)
		encoded := decryptAndEncode(t, keyRaw, testPass, key.RsaBlockType)

		parsedKey, err := parseKeyBytes(encoded)
		assert.Nil(t, err)
		_, ok := parsedKey.(*rsa.PrivateKey)
		assert.True(t, ok)
	})

	t.Run("Create ECDSA private key with passphrase", func(t *testing.T) {
		g := createGenWithCA(t)
		keyg := key.NewEcdsaKey(nil)
		cert := NewServerCert()
		_, keyRaw, err := g.CreateWithOptions(cert, generator.CreateOptions{G: keyg, KeyOpts: &key.MarshalOptions{
			Password: testPass,
		}})
		assert.Nil(t, err)
		encoded := decryptAndEncode(t, keyRaw, testPass, key.EcdsaBlockType)

		parsedKey, err := parseKeyBytes(encoded)
		assert.Nil(t, err)
		_, ok := parsedKey.(*ecdsa.PrivateKey)
		assert.True(t, ok)
	})
}

func TestPKS8PrivateKey(t *testing.T) {
	testPass := []byte("123456")
	t.Run("Should ignore the passphrase when creating a PKCS#8 RSA private key", func(t *testing.T) {
		g := createGenWithUseAsCA(t)
		keyg := key.NewRsaKey(0)
		cert := NewServerCert()
		_, keyRaw, err := g.CreateWithOptions(cert, generator.CreateOptions{G: keyg, KeyOpts: &key.MarshalOptions{
			IsPKCS8:  true,
			Password: testPass,
		}})
		assert.Nil(t, err)

		parsedKey, err := parseKeyBytes(keyRaw)
		assert.Nil(t, err)
		_, ok := parsedKey.(*rsa.PrivateKey)
		assert.True(t, ok)
	})

	t.Run("Should ignore the passphrase when creating a PKCS#8 ECDSA private key", func(t *testing.T) {
		g := createGenWithUseAsCA(t)
		keyg := key.NewEcdsaKey(nil)
		cert := NewServerCert()
		_, keyRaw, err := g.CreateWithOptions(cert, generator.CreateOptions{G: keyg, KeyOpts: &key.MarshalOptions{
			IsPKCS8:  true,
			Password: testPass,
		}})
		assert.Nil(t, err)

		parsedKey, err := parseKeyBytes(keyRaw)
		assert.Nil(t, err)
		_, ok := parsedKey.(*ecdsa.PrivateKey)
		assert.True(t, ok)
	})
}

func decryptAndEncode(t *testing.T, b, pass []byte, blockType string) []byte {
	t.Helper()
	block, _ := pem.Decode(b)
	//nolint:staticcheck
	decrypted, _ := x509.DecryptPEMBlock(block, pass)
	encoded := key.EncodeWithBlockType(decrypted, blockType)
	return encoded
}

func TestIsServerCert(t *testing.T) {
	cert := NewServerCert()
	assert.True(t, cert.IsServerCert())

	cert = New(WithExtKeyUsages(x509.ExtKeyUsageServerAuth))
	assert.True(t, cert.IsServerCert())
}

func TestIsClientCert(t *testing.T) {
	cert := NewClientCert()
	assert.True(t, cert.IsClientCert())

	cert = New(WithExtKeyUsages(x509.ExtKeyUsageClientAuth))
	assert.True(t, cert.IsClientCert())
}

func reset() {
	_ = cleanfiles(filelist)
	filelist = []string{}
}
