package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ccakes/wgproxy/internal/config"
)

const testTimeout = 5 * time.Second

type dialFunc func(context.Context, string) (net.Conn, error)

func (f dialFunc) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return f(ctx, addr)
}

// deadlineConn advances a configured deadline without a two-minute test wait.
type deadlineConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

func (c *deadlineConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = deadline
	return c.Conn.SetDeadline(deadline)
}

func (c *deadlineConn) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.deadline.IsZero() {
		c.Conn.SetDeadline(time.Now().Add(-time.Second))
	}
}

func TestTCPStreamSurvivesDeadline(t *testing.T) {
	client, downstream := net.Pipe()
	upstream, backend := net.Pipe()
	defer client.Close()
	defer backend.Close()
	client.SetDeadline(time.Now().Add(testTimeout))

	local := &deadlineConn{Conn: downstream}
	remote := &deadlineConn{Conn: upstream}
	dial := dialFunc(func(context.Context, string) (net.Conn, error) { return remote, nil })
	p := NewTCPProxy(&config.ForwardRule{}, dial, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	defer p.cancel()
	p.wg.Add(1)
	go p.handleConn(local)
	go io.Copy(backend, backend)

	echo := func() {
		t.Helper()
		const message = "still streaming"
		if _, err := io.WriteString(client, message); err != nil {
			t.Fatalf("write after deadline: %v", err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatalf("read after deadline: %v", err)
		}
		if string(got) != message {
			t.Fatalf("echo = %q", got)
		}
	}

	echo()
	local.expire()
	remote.expire()
	echo()
}

func TestTCPHalfClose(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(testTimeout))
		request, _ := io.ReadAll(conn)
		conn.Write(append([]byte("reply: "), request...))
	}()

	dial := dialFunc(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Addr().String())
	})
	p := NewTCPProxy(&config.ForwardRule{LocalAddr: "127.0.0.1"}, dial,
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	client, err := net.DialTimeout("tcp", p.LocalAddr().String(), testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(testTimeout))
	io.WriteString(client, "request")
	client.(*net.TCPConn).CloseWrite()
	response, err := io.ReadAll(client)
	if err != nil || string(response) != "reply: request" {
		t.Fatalf("half-close response = %q, error = %v", response, err)
	}
}
