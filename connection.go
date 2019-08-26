package proxy

import (
	"context"
	"net"
)

type connPipe struct {
	conn <-chan net.Conn
}

func (lis *connPipe) Accept() (net.Conn, error) {
	return <-lis.conn, nil
}

func (*connPipe) Close() error {
	return nil
}

func (*connPipe) Addr() net.Addr {
	return nil
}

type RetryDialer struct {
	net.Dialer

	MaxRetries int
}

func (d *RetryDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)

	for i := 0; i <= d.MaxRetries; i++ {
		conn, err = d.Dialer.DialContext(ctx, network, address)
		if err == nil {
			break
		}
	}

	return conn, err
}
