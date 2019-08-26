package proxy

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
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

type cache struct {
	dir string
}

func (c *cache) get(r *http.Request) *cacheResponseWriter {
	if c.dir == "" {
		return nil
	}

	key := c.key(r)
	fn := c.fnKey(key)
	if fn == "" {
		return nil
	}

	it := c.load(r, fn)
	if it == nil {
		return nil
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

func (c *cache) key(r *http.Request) string {
	return r.URL.String()
}

func (c *cache) fnKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func (c *cache) NewItem(resp *http.Response) *cacheItem {
	if c.dir == "" {
		return nil
	}

	d := cacheables(resp)
	if d <= 0 {
		return nil
	}

	key := c.key(resp.Request)
	fn := filepath.Join(c.dir, c.fnKey(key))
	fp, err := os.Create(fn)
	if err != nil {
		return nil
	}

	_, err = fp.WriteString("HTTP/1.1 200 OK\n")
	if err != nil {
		return nil
	}
	err = resp.Header.Write(fp)
	if err != nil {
		return nil
	}

	// proxy storage
	_, err = fp.WriteString("X-Proxy-Key: " + key + "\n")
	if err != nil {
		return nil
	}
	_, err = fp.WriteString("X-Proxy-Expires: " + time.Now().Add(d).Format(time.RFC3339) + "\n")
	if err != nil {
		return nil
	}

	_, err = fp.WriteString("\n")
	if err != nil {
		return nil
	}
	return &cacheItem{
		fp:  fp,
		Key: key,
		fn:  fn,
	}
}

func (c *cache) load(r *http.Request, fn string) *cacheResponseWriter {
	if c.dir == "" {
		return nil
	}

	fp, err := os.Open(filepath.Join(c.dir, fn))
	if err != nil {
		return nil
	}

	resp, err := http.ReadResponse(bufio.NewReader(fp), r)
	if err != nil {
		return nil
	}
	return &cacheResponseWriter{
		fp:   fp,
		resp: resp,
	}
}

func cacheables(resp *http.Response) time.Duration {
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

type cacheItem struct {
	fp  *os.File
	fn  string
	Key string
}

func (c *cacheItem) Write(p []byte) (n int, err error) {
	return c.fp.Write(p)
}

func (c *cacheItem) Close() error {
	return c.fp.Close()
}

func (c *cacheItem) CloseWithError(err error) {
	c.Close()

	if err == nil {
		return
	}

	os.Remove(c.fn)
}

type cacheResponseWriter struct {
	fp   *os.File
	resp *http.Response
}

func (c *cacheResponseWriter) Close() error {
	c.resp.Body.Close()
	return c.fp.Close()
}

func (c *cacheResponseWriter) WriteTo(w http.ResponseWriter) {
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
