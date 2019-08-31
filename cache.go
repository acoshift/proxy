package proxy

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

var proxyCacheHop = []string{
	"X-Proxy-Key",
	"X-Proxy-Created",
	"X-Proxy-Expires",
}

const (
	maxCacheItemSize = 32 * 1024 * 1024
	maxCacheDuration = 3 * 365 * 24 * time.Hour
)

type CacheStorage interface {
	Create(key string) CacheWriter
	Open(key string) io.ReadCloser
	Remove(key string)
}

type CacheWriter interface {
	io.WriteCloser
	Remove() error
}

type noCache struct{}

func (n noCache) Create(key string) CacheWriter {
	return nil
}

func (n noCache) Open(key string) io.ReadCloser {
	return nil
}

func (n noCache) Remove(key string) {
	return
}

type cacheBackend struct {
	Store CacheStorage
}

func (c *cacheBackend) Get(r *http.Request) *http.Response {
	key := cacheKey(r)
	sKey := cacheStoreKey(key)
	if sKey == "" {
		return nil
	}

	fp := c.Store.Open(sKey)
	if fp == nil {
		return nil
	}
	resp, err := http.ReadResponse(bufio.NewReader(fp), r)
	if err != nil {
		return nil
	}
	respBody := resp.Body
	resp.Body = struct {
		io.Reader
		io.Closer
	}{respBody, multiCloser{respBody, fp}}

	// hash collision
	if resp.Header.Get("X-Proxy-Key") != key {
		resp.Body.Close()
		return nil
	}

	// add age header
	created, _ := time.Parse(time.RFC3339, resp.Header.Get("X-Proxy-Created"))
	if !created.IsZero() {
		resp.Header.Set("X-Proxy-Cache-Age", strconv.FormatInt(int64(time.Since(created).Seconds()), 10))
	}

	// check expires
	if exp, _ := time.Parse(time.RFC3339, resp.Header.Get("X-Proxy-Expires")); time.Now().After(exp) {
		// TODO: check can use stale
		resp.Body.Close()
		return nil
	}

	for _, k := range proxyCacheHop {
		resp.Header.Del(k)
	}

	return resp
}

func (c *cacheBackend) NewWriter(resp *http.Response) *cacheResponseWriter {
	if !cacheables(resp) {
		return nil
	}

	d := cacheDuration(resp)
	if d <= 0 {
		return nil
	}

	key := cacheKey(resp.Request)
	sKey := cacheStoreKey(key)
	fp := c.Store.Create(sKey)
	if fp == nil {
		return nil
	}

	// proxy storage header
	now := time.Now()
	sh := make(http.Header)
	sh.Set("X-Proxy-Key", key)
	sh.Set("X-Proxy-Created", now.Format(time.RFC3339))
	sh.Set("X-Proxy-Expires", now.Add(d).Format(time.RFC3339))

	return &cacheResponseWriter{
		w:      fp,
		header: sh,
	}
}

func cacheKey(r *http.Request) string {
	return r.URL.String()
}

func cacheStoreKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func cacheables(resp *http.Response) bool {
	// request
	r := resp.Request
	if r.Method != http.MethodGet {
		return false
	}
	if r.Header.Get("Authorization") != "" {
		return false
	}

	// response
	if resp.StatusCode != http.StatusOK {
		return false
	}
	if resp.Header.Get("Set-Cookie") != "" {
		return false
	}
	if resp.ContentLength > maxCacheItemSize {
		return false
	}

	vary := extractHeaderValues(resp.Header["Vary"])

	// do not cache for low hit rate vary
	if _, ok := vary["*"]; ok {
		return false
	}
	if _, ok := vary["cookie"]; ok {
		return false
	}
	if _, ok := vary["user-agent"]; ok {
		return false
	}
	if _, ok := vary["referer"]; ok {
		return false
	}

	delete(vary, "accept-encoding")

	// do not support cache complex vary
	if len(vary) > 0 {
		return false
	}

	return true
}

func cacheDuration(resp *http.Response) time.Duration {
	cc := extractHeaderValues(resp.Header["Cache-Control"])
	if len(cc) == 0 {
		if alwaysCacheExt[path.Ext(resp.Request.URL.Path)] {
			return 6 * time.Hour
		}

		return 0
	}
	if _, ok := cc["immutable"]; ok {
		return maxCacheDuration
	}
	if _, ok := cc["private"]; ok {
		return 0
	}
	if _, ok := cc["no-cache"]; ok {
		return 0
	}
	if _, ok := cc["no-store"]; ok {
		return 0
	}

	maxAgeStr := cc["max-age"]
	if maxAgeStr == "" {
		return 0
	}
	maxAge, _ := strconv.ParseInt(maxAgeStr, 10, 64)
	if maxAge <= 0 {
		return 0
	}
	return time.Duration(maxAge) * time.Second
}

type cacheResponseWriter struct {
	w           CacheWriter
	wroteHeader bool
	header      http.Header
	writeError  bool
}

func (c *cacheResponseWriter) Header() http.Header {
	return c.header
}

func (c *cacheResponseWriter) WriteHeader(statusCode int) {
	if c.wroteHeader {
		panic("unreachable")
	}
	c.wroteHeader = true

	fmt.Fprintf(c.w, "HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	c.header.Write(c.w)
	fmt.Fprintf(c.w, "\r\n")
}

func (c *cacheResponseWriter) Write(p []byte) (n int, err error) {
	if !c.wroteHeader {
		panic("unreachable")
	}

	n = len(p)

	// can not write to storage, ex. storage full
	if c.writeError {
		return
	}

	_, err = c.w.Write(p)
	if err != nil {
		c.writeError = true
		err = nil
	}
	return
}

func (c *cacheResponseWriter) CloseWithError(err error) {
	c.w.Close()

	if err != nil || c.writeError {
		c.w.Remove()
	}
}

func extractHeaderValues(vs []string) map[string]string {
	xs := make(map[string]string)
	for _, v := range vs {
		for _, x := range strings.Split(v, ",") {
			x = strings.TrimSpace(x)
			ps := strings.SplitN(x, "=", 2)
			var p string
			if len(ps) == 2 {
				x, p = ps[0], ps[1]
			}
			x = strings.ToLower(x)
			xs[x] = p
		}
	}
	return xs
}

var alwaysCacheExt = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".svg":  true,
	".js":   true,
	".css":  true,
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	for _, x := range m {
		x.Close()
	}
	return nil
}
