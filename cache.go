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
	"X-Proxy-Expires",
}

const (
	maxCacheItemSize = 32 * 1024 * 1024
	maxCacheDuration = 3 * 365 * 24 * time.Hour
)

type CacheStorage interface {
	Create(key string) io.WriteCloser
	Open(key string) io.ReadCloser
	Remove(key string)
}

type noCache struct{}

func (n noCache) Create(key string) io.WriteCloser {
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

func (c *cacheBackend) Get(r *http.Request) *CacheReader {
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

	it := &CacheReader{
		fp:   fp,
		resp: resp,
	}
	if it.resp.Header.Get("X-Proxy-Key") != key {
		it.Close()
		return nil
	}
	if exp, _ := time.Parse(time.RFC3339, it.resp.Header.Get("X-Proxy-Expires")); time.Now().After(exp) {
		it.Close()
		return nil
	}

	for _, k := range proxyCacheHop {
		it.resp.Header.Del(k)
	}

	return it
}

func (c *cacheBackend) NewItem(resp *http.Response) *CacheWriter {
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

	// proxy storage
	_, err = fmt.Fprintf(fp, "X-Proxy-Key: %s\n", key)
	if err != nil {
		return nil
	}
	_, err = fmt.Fprintf(fp, "X-Proxy-Expires: %s\n", time.Now().Add(d).Format(time.RFC3339))
	if err != nil {
		return nil
	}

	_, err = fmt.Fprintf(fp, "\n")
	if err != nil {
		return nil
	}

	closeFp = false
	return &CacheWriter{
		fp:  fp,
		Key: key,
		fn:  sKey,
	}
}

type DirCacheStorage struct {
	Path string
}

func (c *DirCacheStorage) filename(key string) string {
	return filepath.Join(c.Path, key)
}

func (c *DirCacheStorage) Create(key string) io.WriteCloser {
	fp, err := os.Create(c.filename(key))
	if err != nil {
		return nil
	}
	return fp
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

type CacheWriter struct {
	fp  io.WriteCloser
	fn  string
	Key string
}

func (c *CacheWriter) Write(p []byte) (n int, err error) {
	return c.fp.Write(p)
}

func (c *CacheWriter) Close() error {
	return c.fp.Close()
}

func (c *CacheWriter) CloseWithError(err error) {
	c.Close()

	if err == nil {
		return
	}

	os.Remove(c.fn)
}

type CacheReader struct {
	fp   io.ReadCloser
	resp *http.Response
}

func (c *CacheReader) Close() error {
	c.resp.Body.Close()
	return c.fp.Close()
}

func (c *CacheReader) WriteTo(w http.ResponseWriter) {
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
			} else {
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
