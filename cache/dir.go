package cache

import (
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/acoshift/proxy"
)

type DirStorage struct {
	Path string
}

func (s *DirStorage) filename(key string) string {
	return filepath.Join(s.Path, key)
}

func (s *DirStorage) Create(key string) proxy.CacheWriter {
	if key == "" {
		return nil
	}

	fn := s.filename(key)
	fp, err := os.Create(fn)
	if os.IsNotExist(err) {
		os.MkdirAll(filepath.Dir(fn), 0755)
		fp, err = os.Create(fn)
	}
	if err != nil {
		return nil
	}
	return &dirCacheWriter{
		fp: fp,
		fn: fn,
	}
}

func (s *DirStorage) Open(key string) io.ReadCloser {
	if key == "" {
		return nil
	}

	fp, err := os.Open(s.filename(key))
	if err != nil {
		return nil
	}
	return fp
}

func (s *DirStorage) Remove(key string) {
	os.Remove(s.filename(key))
}

func (s *DirStorage) Purge() {
	filepath.Walk(s.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		syscall.Unlink(path)
		return nil
	})
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
