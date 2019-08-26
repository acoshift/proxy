package proxy

import (
	"io"
	"sync"
)

func newBufferPool(size int64) *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			return make([]byte, size)
		},
	}
}

const (
	bufferSizeSmall  = 16 * 1024
	bufferSizeMedium = 32 * 1024
	bufferSizeLarge  = 128 * 1024
)

var (
	poolSmallBuffer  = newBufferPool(bufferSizeSmall)
	poolMediumBuffer = newBufferPool(bufferSizeMedium)
	poolLargeBuffer  = newBufferPool(bufferSizeLarge)
)

func getBufferPool(size int64) *sync.Pool {
	switch {
	case size <= 0:
		return poolMediumBuffer
	case size <= 4*1024:
		return poolSmallBuffer
	case size <= 32*1024:
		return poolMediumBuffer
	default:
		return poolLargeBuffer
	}
}

func copyBuffer(dst io.Writer, src io.Reader, size int64) (int64, error) {
	pool := getBufferPool(size)
	buf := pool.Get().([]byte)
	defer pool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}
