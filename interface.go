package http_dialer

import (
	"context"
	"net"
)

// ContextDialer establishes connection to a target whose lifecycle is controlled by context
type ContextDialer interface {
	DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
}
