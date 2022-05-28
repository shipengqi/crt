package crt_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCrt(t *testing.T) {
	// config.DefaultReporterConfig.SlowSpecThreshold = 30
	RegisterFailHandler(Fail)
	RunSpecs(t, "CRT")
}
