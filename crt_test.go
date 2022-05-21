package crt_test

import (
	"bytes"
	"crypto/x509"
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/shipengqi/crt"
	"github.com/shipengqi/crt/generator"
)

var _ = Describe("CRT CTL", func() {
	Describe("Generator", func() {
		Describe("FileWriter", Ordered, func() {
			gg := generator.New()
			caPath := "generator.file.ca.crt"
			caKeyPath := "generator.file.ca.key"
			serverCrtPath := "generator.file.server.crt"
			serverKeyPath := "generator.file.server.key"
			clientCrtPath := "generator.file.client.crt"
			clientKeyPath := "generator.file.client.key"
			Context("Create CA certificate", func() {
				It("New(), should return nil", func() {
					cert := New(WithCAType())
					err := gg.CreateAndWrite(cert, caPath, caKeyPath)
					Expect(err).To(BeNil())
				})
				It("NewCACert(), should return nil", func() {
					cert := NewCACert()
					err := gg.CreateAndWrite(cert, caPath, caKeyPath)
					Expect(err).To(BeNil())
				})
			})
			Context("Create Server certificate", func() {
				It("New(), should return error: certificate or private key is not provided", func() {
					cert := New(
						WithServerType(),
						WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
						WithExtKeyUsages(x509.ExtKeyUsageServerAuth),
					)
					err := gg.CreateAndWrite(cert, serverCrtPath, serverKeyPath)
					Expect(err.Error()).To(Equal("x509: certificate or private key is not provided"))
				})
				It("New(), should return nil", func() {
					ca, _ := ParseCertFile(caPath)
					key, _ := ParseKeyFile(caKeyPath)
					gg.SetCA(ca, key)
					cert := New(
						WithServerType(),
						WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
						WithExtKeyUsages(x509.ExtKeyUsageServerAuth),
					)
					err := gg.CreateAndWrite(cert, serverCrtPath, serverKeyPath)
					Expect(err).To(BeNil())
				})
			})
			Context("Create Client certificate", func() {
				It("New(), should return nil", func() {
					cert := New(
						WithClientType(),
						WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
						WithExtKeyUsages(x509.ExtKeyUsageClientAuth),
					)
					err := gg.CreateAndWrite(cert, clientCrtPath, clientKeyPath)
					Expect(err).To(BeNil())
				})
			})
			AfterAll(func() {
				_, _, _ = deleteLocalFile("./generator.file.*")
			})
		})
		Describe("SecretWriter", func() {})
	})
	Describe("Create", func() {})
	Describe("Check", func() {})
	Describe("Update", func() {})
	Describe("Apply", func() {})
})

func deleteLocalFile(path string) (string, string, error) {
	By("Running command: rm -rf " + path)
	cmd := exec.Command("rm", "-rf", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	By("\tSTDOUT: " + stdout.String())
	By("\tSTDERR: " + stderr.String())
	Expect(err).Should(BeNil())
	return stdout.String(), stderr.String(), err
}
