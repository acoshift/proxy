package proxy

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
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

func (c *cacheBackend) Get(r *http.Request) *cacheResponseReader {
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

	it := &cacheResponseReader{
		fp:   fp,
		resp: resp,
	}

	// hash collision
	if it.resp.Header.Get("X-Proxy-Key") != key {
		it.Close()
		return nil
	}

	// add age header
	created, _ := time.Parse(time.RFC3339, it.resp.Header.Get("X-Proxy-Created"))
	if !created.IsZero() {
		it.resp.Header.Set("X-Proxy-Cache-Age", strconv.FormatInt(int64(time.Since(created).Seconds()), 10))
	}

	// check expires
	if exp, _ := time.Parse(time.RFC3339, it.resp.Header.Get("X-Proxy-Expires")); time.Now().After(exp) {
		// TODO: check can use stale
		it.Close()
		return nil
	}

	for _, k := range proxyCacheHop {
		it.resp.Header.Del(k)
	}

	return it
}

func (c *cacheBackend) NewWriter(resp *http.Response) *cacheResponseWriter {
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
	closeFp := true
	defer func() {
		if closeFp {
			fp.Close()
		}
	}()

	_, err := fmt.Fprint(fp, "HTTP/1.1 200 OK\r\n")
	if err != nil {
		return nil
	}
	err = resp.Header.Write(fp)
	if err != nil {
		return nil
	}

	// proxy storage header
	now := time.Now()

	sh := make(http.Header)
	sh.Set("X-Proxy-Key", key)
	sh.Set("X-Proxy-Created", now.Format(time.RFC3339))
	sh.Set("X-Proxy-Expires", now.Add(d).Format(time.RFC3339))
	err = sh.Write(fp)
	if err != nil {
		return nil
	}

	_, err = fmt.Fprintf(fp, "\r\n")
	if err != nil {
		return nil
	}

	closeFp = false
	return &cacheResponseWriter{CacheWriter: fp}
}

type DirCacheStorage struct {
	Path string
}

func (c *DirCacheStorage) filename(key string) string {
	return filepath.Join(c.Path, key)
}

func (c *DirCacheStorage) Create(key string) CacheWriter {
	fn := c.filename(key)
	fp, err := os.Create(fn)
	if err != nil {
		return nil
	}
	return &dirCacheWriter{
		fp: fp,
		fn: fn,
	}
}

func (c *DirCacheStorage) Open(key string) io.ReadCloser {
	if key == "" || c.Path == "" {
		return nil
	}

	fp, err := os.Open(c.filename(key))
	if err != nil {
		return nil
	}
	return fp
}

func (c *DirCacheStorage) Remove(key string) {
	os.Remove(c.filename(key))
}

type dirCacheWriter struct {
	fp *os.File
	fn string
}

func (w *dirCacheWriter) Write(p []byte) (n int, err error) {
	return w.fp.Write(p)
}

func (w *dirCacheWriter) Close() error {
	return w.fp.Close()
}

func (w *dirCacheWriter) Remove() error {
	return os.Remove(w.fn)
}

func cacheKey(r *http.Request) string {
	return r.URL.String()
}

func cacheStoreKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func cacheDuration(resp *http.Response) time.Duration {
	if resp.Request.Method != http.MethodGet {
		return 0
	}
	if resp.StatusCode != http.StatusOK {
		return 0
	}

	if resp.Header.Get("Set-Cookie") != "" {
		return 0
	}

	if resp.ContentLength > maxCacheItemSize {
		return 0
	}

	{
		// do not support cache complex vary
		x := extractHeaderValues(resp.Header["Vary"])
		delete(x, "accept-encoding")
		if len(x) > 0 {
			return 0
		}
	}

	{
		x := extractHeaderValues(resp.Header["Cache-Control"])
		if len(x) == 0 {
			if alwaysCacheExt[path.Ext(resp.Request.URL.Path)] {
				return 6 * time.Hour
			}

			return 0
		}
		if _, ok := x["immutable"]; ok {
			return maxCacheDuration
		}
		if _, ok := x["private"]; ok {
			return 0
		}
		if _, ok := x["no-cache"]; ok {
			return 0
		}
		if _, ok := x["no-store"]; ok {
			return 0
		}
		if p := x["max-age"]; p != "" {
			maxAge, _ := strconv.ParseInt(p, 10, 64)
			if maxAge <= 0 {
				return 0
			}
			return time.Duration(maxAge) * time.Second
		}
	}

	return 0
}

type cacheResponseWriter struct {
	CacheWriter
}

func (c *cacheResponseWriter) CloseWithError(err error) {
	c.Close()

	if err == nil {
		return
	}

	c.CacheWriter.Remove()
}

type cacheResponseReader struct {
	fp   io.ReadCloser
	resp *http.Response
}

func (c *cacheResponseReader) Close() error {
	c.resp.Body.Close()
	return c.fp.Close()
}

func (c *cacheResponseReader) WriteTo(w http.ResponseWriter) {
	defer c.Close()
	copyHeaders(w.Header(), c.resp.Header)
	w.WriteHeader(c.resp.StatusCode)
	copyBuffer(w, c.resp.Body, c.resp.ContentLength)
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
