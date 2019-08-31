package cache

import (
	"bytes"
	"io"
	"io/ioutil"
	"sync"

	"github.com/acoshift/proxy"
)

// Memory stores cache in memory
type Memory struct {
	s sync.Map
}

func (s *Memory) set(key string, value []byte) {
	s.s.Store(key, value)
}

func (s *Memory) Create(key string) proxy.CacheWriter {
	if key == "" {
		return nil
	}

	return &memWriter{key: key, set: s.set}
}

func (s *Memory) Open(key string) io.ReadCloser {
	bs, ok := s.s.Load(key)
	if !ok {
		return nil
	}
	return ioutil.NopCloser(bytes.NewReader(bs.([]byte)))
}

func (s *Memory) Remove(key string) {
	s.s.Delete(key)
}

type memWriter struct {
	key     string
	set     func(key string, value []byte)
	buf     bytes.Buffer
	removed bool
}

func (w *memWriter) Write(p []byte) (n int, err error) {
	return w.buf.Write(p)
}

func (w *memWriter) Close() error {
	if w.removed {
		return nil
	}

	w.set(w.key, w.buf.Bytes())
	return nil
}

func (w *memWriter) Remove() error {
	w.removed = true
	return nil
}
