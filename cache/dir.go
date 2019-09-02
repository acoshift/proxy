package cache

import (
	"io"
	"os"
	"path/filepath"
	"strings"
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

func (s *Dir) Range(f proxy.CacheRanger) {
	p := s.Path
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		fp, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer fp.Close()
		it := fileRangeItem{fp: fp}
		f(&it)
		fp.Close()
		if it.removed {
			os.Remove(path)
		}
		return nil
	})
}

func (s *Dir) Purge() {
	p := s.Path
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
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

type fileRangeItem struct {
	fp      *os.File
	removed bool
}

func (f *fileRangeItem) Read(p []byte) (n int, err error) {
	return f.fp.Read(p)
}

func (f *fileRangeItem) Remove() {
	f.removed = true
}
