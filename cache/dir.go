package cache

import (
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/acoshift/proxy"
)

// Dir stores cache in directory
type Dir struct {
	Path string
}

func (s *Dir) filename(key string) string {
	return filepath.Join(s.Path, key)
}

func (s *Dir) Create(key string) proxy.CacheWriter {
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
	return &fileWriter{
		fp: fp,
		fn: fn,
	}
}

func (s *Dir) Open(key string) io.ReadCloser {
	if key == "" {
		return nil
	}

	fp, err := os.Open(s.filename(key))
	if err != nil {
		return nil
	}
	return fp
}

func (s *Dir) Remove(key string) {
	os.Remove(s.filename(key))
}

func (s *Dir) Purge() {
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

type fileWriter struct {
	fp *os.File
	fn string
}

func (w *fileWriter) Write(p []byte) (n int, err error) {
	return w.fp.Write(p)
}

func (w *fileWriter) Close() error {
	return w.fp.Close()
}

func (w *fileWriter) Remove() error {
	return os.Remove(w.fn)
}
