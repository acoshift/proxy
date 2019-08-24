package proxy

import (
	"io"
	"sync"
)

const bufferSize = 32 * 1024

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, bufferSize)
	},
}

func getBuffer() []byte {
	return bufferPool.Get().([]byte)
}

func putBuffer(b []byte) {
	bufferPool.Put(b)
}

func copyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := getBuffer()
	defer putBuffer(buf)
	return io.CopyBuffer(dst, src, buf)
}
