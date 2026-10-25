package proxy

import (
	"errors"
	"io"
	"net"
)

// Preserve TCP half-closes so a request can finish before its response arrives.
func finishWrite(conn net.Conn, err error) {
	if writer, ok := conn.(interface{ CloseWrite() error }); ok && (err == nil || errors.Is(err, io.EOF)) {
		writer.CloseWrite()
		return
	}
	conn.Close()
}
