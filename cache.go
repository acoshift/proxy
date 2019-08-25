package proxy

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const maxCacheItemSize = 32 * 1024 * 1024

type cache struct {
	dir string
}

func (c *cache) get(r *http.Request) *cacheResponseWriter {
	if c.dir == "" {
		return nil
	}

	fn := c.fnKey(c.key(r))
	if fn == "" {
		return nil
	}

	it := c.load(r, fn)
	if it == nil {
		return nil
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
	if !cacheables(resp) {
		return nil
	}

	key := c.key(resp.Request)
	fn := c.fnKey(key)
	fp, err := os.Create(filepath.Join(c.dir, fn))
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

func cacheables(resp *http.Response) bool {
	if resp.Request.Method != http.MethodGet {
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}

	if resp.ContentLength > maxCacheItemSize {
		return false
	}

	{
		// do not support cache complex vary
		x := extractHeaderValues(resp.Header["Vary"])
		delete(x, "accept-encoding")
		if len(x) > 0 {
			return false
		}
	}

	if alwaysCacheExt[path.Ext(resp.Request.URL.Path)] {
		return true
	}

	{
		x := extractHeaderValues(resp.Header["Cache-Control"])
		if len(x) == 0 {
			return false
		}
		if x["immutable"] {
			return true
		}
		if x["private"] || x["no-cache"] || x["no-store"] {
			return false
		}
		// TODO: extract max-age
	}

	return true
}

type cacheItem struct {
	fp  *os.File
	fn  string
	Key string
}

func (c cacheItem) Write(p []byte) (n int, err error) {
	return c.fp.Write(p)
}

func (c cacheItem) Close() error {
	return c.fp.Close()
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
	copyBuffer(w, c.resp.Body)
}

func extractHeaderValues(vs []string) map[string]bool {
	xs := make(map[string]bool)
	for _, v := range vs {
		for _, x := range strings.Split(v, ",") {
			x = strings.TrimSpace(x)
			x = strings.ToLower(x)
			xs[x] = true
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
