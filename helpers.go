package crt

import (
	"net"
)

func deduplicateips(ips []net.IP) []net.IP {
	encountered := map[string]struct{}{}
	ret := make([]net.IP, 0)
	for i := range ips {
		if ips[i] == nil {
			continue
		}
		if ips[i].String() == "<nil>" {
			continue
		}
		if _, contained := encountered[ips[i].String()]; contained {
			continue
		}
		encountered[ips[i].String()] = struct{}{}
		ret = append(ret, ips[i])
	}
	return ret
}

func deduplicatestr(s []string) []string {
	encountered := map[string]struct{}{}
	ret := make([]string, 0)
	for i := range s {
		if len(s[i]) == 0 {
			continue
		}
		if _, contained := encountered[s[i]]; contained {
			continue
		}
		encountered[s[i]] = struct{}{}
		ret = append(ret, s[i])
	}
	return ret
}
