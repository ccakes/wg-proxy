// Package proxy provides TCP and UDP proxy implementations.
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ccakes/wgproxy/internal/config"
	"github.com/ccakes/wgproxy/internal/metrics"
	"github.com/ccakes/wgproxy/internal/tunnel"
)

const (
	// TCPTimeout is the connection timeout for TCP proxies.
	TCPTimeout = 2 * time.Minute
	// BufferSize is the buffer size for data copying.
	BufferSize = 32 * 1024
)

// TCPProxy handles TCP port forwarding.
type TCPProxy struct {
	rule     *config.ForwardRule
	manager  *tunnel.Manager
	logger   *slog.Logger
	metrics  *metrics.Collector
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewTCPProxy creates a new TCP proxy for the given rule.
func NewTCPProxy(rule *config.ForwardRule, manager *tunnel.Manager, logger *slog.Logger, m *metrics.Collector) *TCPProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPProxy{
		rule:    rule,
		manager: manager,
		logger:  logger.With("proxy", "tcp", "local", rule.LocalEndpoint(), "remote", rule.RemoteEndpoint()),
		metrics: m,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start starts the TCP proxy listener.
func (p *TCPProxy) Start() error {
	listener, err := net.Listen("tcp", p.rule.LocalEndpoint())
	if err != nil {
		return err
	}
	p.listener = listener

	p.logger.Info("started TCP proxy listener")

	p.wg.Add(1)
	go p.acceptLoop()

	return nil
}

// acceptLoop accepts incoming connections.
func (p *TCPProxy) acceptLoop() {
	defer p.wg.Done()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				p.logger.Error("accept failed", "error", err)
				continue
			}
		}

		p.wg.Add(1)
		go p.handleConn(conn)
	}
}

// handleConn handles a single TCP connection.
func (p *TCPProxy) handleConn(clientConn net.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	p.logger.Debug("new connection", "client", clientConn.RemoteAddr())

	// Record connection metric
	if p.metrics != nil {
		p.metrics.ConnectionsTotal.WithLabelValues("tcp", p.rule.LocalEndpoint(), p.rule.RemoteEndpoint()).Inc()
		p.metrics.ActiveConnections.WithLabelValues("tcp", p.rule.LocalEndpoint(), p.rule.RemoteEndpoint()).Inc()
		defer p.metrics.ActiveConnections.WithLabelValues("tcp", p.rule.LocalEndpoint(), p.rule.RemoteEndpoint()).Dec()
	}

	// Set deadline on client connection
	clientConn.SetDeadline(time.Now().Add(TCPTimeout))

	// Dial remote through tunnel
	ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
	remoteConn, err := p.manager.DialTCP(ctx, p.rule.RemoteEndpoint())
	cancel()
	if err != nil {
		p.logger.Error("failed to dial remote", "error", err)
		return
	}
	defer remoteConn.Close()

	// Set deadline on remote connection
	remoteConn.SetDeadline(time.Now().Add(TCPTimeout))

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Remote
	go func() {
		defer wg.Done()
		n, _ := p.copyWithMetrics(remoteConn, clientConn, "tx")
		p.logger.Debug("client->remote copy done", "bytes", n)
	}()

	// Remote -> Client
	go func() {
		defer wg.Done()
		n, _ := p.copyWithMetrics(clientConn, remoteConn, "rx")
		p.logger.Debug("remote->client copy done", "bytes", n)
	}()

	wg.Wait()
	p.logger.Debug("connection closed", "client", clientConn.RemoteAddr())
}

// copyWithMetrics copies data and records metrics.
func (p *TCPProxy) copyWithMetrics(dst, src net.Conn, direction string) (int64, error) {
	buf := make([]byte, BufferSize)
	var total int64

	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[:nr])
			if nw > 0 {
				total += int64(nw)
				if p.metrics != nil {
					p.metrics.BytesTransferred.WithLabelValues("tcp", p.rule.LocalEndpoint(), p.rule.RemoteEndpoint(), direction).Add(float64(nw))
				}
			}
			if writeErr != nil {
				return total, writeErr
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

// Stop stops the TCP proxy.
func (p *TCPProxy) Stop() error {
	p.cancel()

	if p.listener != nil {
		p.listener.Close()
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		p.logger.Warn("timeout waiting for TCP proxy connections to close")
	}

	p.logger.Info("TCP proxy stopped")
	return nil
}

// LocalAddr returns the local address the proxy is listening on.
func (p *TCPProxy) LocalAddr() net.Addr {
	if p.listener != nil {
		return p.listener.Addr()
	}
	return nil
}
