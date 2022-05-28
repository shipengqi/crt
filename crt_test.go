package crt_test

import (
	"crypto/x509"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/shipengqi/crt"

	"github.com/shipengqi/crt/generator"
)

var _ = Describe("Certificates Generator", func() {
	Describe("FileWriter", func() {
		gg := generator.New()
		var filelist []string
		AfterEach(func() {
			for _, v := range filelist {
				_ = os.Remove(v)
			}
			filelist = []string{}
		})
		caPath := "testdata/ca.crt"
		caKeyPath := "testdata/ca.key"
		serverCrtPath := "testdata/server.crt"
		serverKeyPath := "testdata/server.key"
		clientCrtPath := "testdata/client.crt"
		clientKeyPath := "testdata/client.key"
		Context("Create CA certificate", func() {
			It("New(), should return nil", func() {
				filelist = append(filelist, caPath, caKeyPath)
				cert := New(WithCAType())
				err := gg.CreateAndWrite(cert, caPath, caKeyPath)
				Expect(err).To(BeNil())

				parsedCert, err := parseCertFile(caPath)
				Expect(err).To(BeNil())
				Expect(parsedCert.IsCA).To(BeTrue())
				Expect(parsedCert.Issuer.CommonName).To(BeEmpty())
				Expect(parsedCert.NotBefore.Add(24 * 366 * 10 * time.Hour)).To(Equal(parsedCert.NotAfter))
			})
			It("NewCACert(), should return nil", func() {
				filelist = append(filelist, caPath, caKeyPath)
				cert := NewCACert()
				err := gg.CreateAndWrite(cert, caPath, caKeyPath)
				Expect(err).To(BeNil())

				parsedCert, err := parseCertFile(caPath)
				Expect(err).To(BeNil())
				Expect(parsedCert.IsCA).To(BeTrue())
				Expect(parsedCert.Issuer.CommonName).To(Equal("CRT GENERATOR CA"))
				Expect(parsedCert.Subject.CommonName).To(Equal("CRT GENERATOR CA"))
				Expect(parsedCert.NotBefore.Add(24 * 366 * 10 * time.Hour)).To(Equal(parsedCert.NotAfter))
			})
		})
		Context("Create Server certificate", func() {
			It("New(), should return error: CA certificate or private key is not provided", func() {
				filelist = append(filelist, serverCrtPath, serverKeyPath)
				cert := New(
					WithServerType(),
					WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
					WithExtKeyUsages(x509.ExtKeyUsageServerAuth),
				)
				err := gg.CreateAndWrite(cert, serverCrtPath, serverKeyPath)
				Expect(err.Error()).To(Equal("x509: CA certificate or private key is not provided"))
			})
			It("New(), should return nil", func() {
				filelist = append(filelist, caPath, caKeyPath, serverCrtPath, serverKeyPath)
				cacrt := NewCACert()
				cablock, keyblock, err := gg.Create(cacrt)
				Expect(err).To(BeNil())
				ca, _ := parseCertBytes(cablock)
				key, _ := parseKeyBytes(keyblock)
				gg.SetCA(ca, key)
				cert := New(
					WithServerType(),
					WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
					WithExtKeyUsages(x509.ExtKeyUsageServerAuth),
				)
				err = gg.CreateAndWrite(cert, serverCrtPath, serverKeyPath)
				Expect(err).To(BeNil())

				parsedCert, err := parseCertFile(serverCrtPath)
				Expect(err).To(BeNil())
				Expect(parsedCert.IsCA).To(BeFalse())
				Expect(parsedCert.Issuer.CommonName).To(Equal("CRT GENERATOR CA"))
				Expect(parsedCert.Subject.CommonName).To(BeEmpty())
				Expect(parsedCert.NotBefore.Add(365 * 24 * time.Hour)).To(Equal(parsedCert.NotAfter))
			})
		})
		Context("Create Client certificate", func() {
			It("New(), should return nil", func() {
				filelist = append(filelist, caPath, caKeyPath, clientCrtPath, clientKeyPath)
				cacrt := NewCACert()
				cablock, keyblock, err := gg.Create(cacrt)
				Expect(err).To(BeNil())
				ca, _ := parseCertBytes(cablock)
				key, _ := parseKeyBytes(keyblock)
				gg.SetCA(ca, key)

				cert := New(
					WithClientType(),
					WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
					WithExtKeyUsages(x509.ExtKeyUsageClientAuth),
				)
				err = gg.CreateAndWrite(cert, clientCrtPath, clientKeyPath)
				Expect(err).To(BeNil())

				parsedCert, err := parseCertFile(clientCrtPath)
				Expect(err).To(BeNil())
				Expect(parsedCert.IsCA).To(BeFalse())
				Expect(parsedCert.Issuer.CommonName).To(Equal("CRT GENERATOR CA"))
				Expect(parsedCert.Subject.CommonName).To(BeEmpty())
				Expect(parsedCert.NotBefore.Add(365 * 24 * time.Hour)).To(Equal(parsedCert.NotAfter))
			})
		})
	})
})
