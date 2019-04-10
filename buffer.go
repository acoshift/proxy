package proxy

import (
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
