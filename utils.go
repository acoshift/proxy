package proxy

import (
	"io"
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

func copyHeaders(dst http.Header, src http.Header) {
	for k, v := range src {
		dst[k] = v
	}
}

func copyResponse(resp *http.Response, w ...http.ResponseWriter) error {
	for _, w := range w {
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
	}
	if len(w) == 1 {
		_, err := copyBuffer(w[0], resp.Body, resp.ContentLength)
		return err
	}

	ws := make([]io.Writer, 0, len(w))
	for _, w := range w {
		ws = append(ws, w)
	}
	_, err := copyBuffer(io.MultiWriter(ws...), resp.Body, resp.ContentLength)
	return err
}

func stream(s1, s2 io.ReadWriter) error {
	errCh := make(chan error, 1)
	go func() {
		_, err := copyBuffer(s1, s2, 0)
		errCh <- err
	}()
	go func() {
		_, err := copyBuffer(s2, s1, 0)
		errCh <- err
	}()
	return <-errCh
}

const proxyConnect = "HTTP/1.1 200 OK\r\n\r\n"
