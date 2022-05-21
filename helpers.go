package crt

import (
	"net"
)

func deduplicateips(ips []net.IP) []net.IP {
	encountered := map[string]bool{}
	ret := make([]net.IP, 0)
	for i := range ips {
		if len(ips[i].String()) == 0 {
			continue
		}
		if encountered[ips[i].String()] {
			continue
		}
		encountered[ips[i].String()] = true
		ret = append(ret, ips[i])
	}
	return ret
}

func deduplicatestr(s []string) []string {
	encountered := map[string]bool{}
	ret := make([]string, 0)
	for i := range s {
		if len(s[i]) == 0 {
			continue
		}
		if encountered[s[i]] {
			continue
		}
		encountered[s[i]] = true
		ret = append(ret, s[i])
	}
	return ret
}
