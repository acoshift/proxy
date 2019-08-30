package proxy

import (
	"net"
	"net/http"
	"strings"
)

type index map[string]struct{}

func loadIndex(list []string) index {
	m := make(index)
	for _, x := range list {
		m[x] = struct{}{}
	}
	return m
}

func matchHost(index map[string]struct{}, host string) bool {
	h, _, _ := net.SplitHostPort(host)
	if h != "" {
		host = h
	}

	if _, ok := index[host]; ok {
		return true
	}

	for host != "" {
		i := strings.Index(host, ".")
		if i <= 0 {
			break
		}

		if _, ok := index["*"+host[i:]]; ok {
			return true
		}
		host = host[i+1:]
	}

	return false
}

func isBrowser(r *http.Request) bool {
	ua := r.UserAgent()
	if strings.HasPrefix(ua, "Mozilla") {
		return true
	}

	return false
}
