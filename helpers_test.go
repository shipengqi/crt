package crt

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeDuplicateIPs(t *testing.T) {
	tests := []struct {
		title    string
		input    []net.IP
		expected []net.IP
	}{
		{"length should be 1", []net.IP{
			net.ParseIP("10.0.0.1"),
			net.ParseIP("10.0.0.1"),
			net.ParseIP(""),
			net.IP{},
		}, []net.IP{net.ParseIP("10.0.0.1")}},
		{"length should be 2", []net.IP{
			net.ParseIP("10.0.0.1"),
			net.ParseIP("10.0.0.2"),
			net.ParseIP("10.0.0.1"),
		}, []net.IP{
			net.ParseIP("10.0.0.1"),
			net.ParseIP("10.0.0.2"),
		}},
	}

	for _, v := range tests {
		t.Run(v.title, func(t *testing.T) {
			got := deduplicateips(v.input)
			assert.Equal(t, v.expected, got)
		})
	}
}

func TestDeDuplicateStr(t *testing.T) {
	tests := []struct {
		title    string
		input    []string
		expected []string
	}{
		{"length should be 1", []string{"111", "111", ""}, []string{"111"}},
		{"length should be 2", []string{"111s", "222", "111s"}, []string{"111s", "222"}},
	}

	for _, v := range tests {
		t.Run(v.title, func(t *testing.T) {
			got := deduplicatestr(v.input)
			assert.Equal(t, v.expected, got)
		})
	}
}
