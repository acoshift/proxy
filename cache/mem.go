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

func (s *Memory) Range(f proxy.CacheRanger) {
	s.s.Range(func(key, value interface{}) bool {
		it := memRangeItem{buf: bytes.NewReader(value.([]byte))}
		f(&it)
		if it.removed {
			s.s.Delete(key)
		}
		return true
	})
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

type memRangeItem struct {
	buf     *bytes.Reader
	removed bool
}

func (m *memRangeItem) Read(p []byte) (n int, err error) {
	return m.buf.Read(p)
}

func (m *memRangeItem) Remove() {
	m.removed = true
}
