package cache

import (
	"io"
	"os"
	"path/filepath"

	"github.com/acoshift/proxy"
)

type DirStorage struct {
	Path string
}

func (c *DirStorage) filename(key string) string {
	return filepath.Join(c.Path, key)
}

func (c *DirStorage) Create(key string) proxy.CacheWriter {
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

func (c *DirStorage) Open(key string) io.ReadCloser {
	if key == "" || c.Path == "" {
		return nil
	}

	fp, err := os.Open(c.filename(key))
	if err != nil {
		return nil
	}
	return fp
}

func (c *DirStorage) Remove(key string) {
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
