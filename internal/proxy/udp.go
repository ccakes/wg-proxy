package proxy

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ccakes/wgproxy/internal/config"
	"github.com/ccakes/wgproxy/internal/metrics"
	"github.com/ccakes/wgproxy/internal/tunnel"
)

const (
	// UDPIdleTimeout is the idle timeout for UDP sessions.
	UDPIdleTimeout = 2 * time.Minute
	// UDPBufferSize is the buffer size for UDP packets.
	UDPBufferSize = 65535
)

// UDPProxy handles UDP port forwarding.
type UDPProxy struct {
	rule     *config.ForwardRule
	manager  *tunnel.Manager
	logger   *slog.Logger
	metrics  *metrics.Collector
	listener *net.UDPConn
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// Session tracking
	sessions   map[string]*udpSession
	sessionsMu sync.Mutex
}

// udpSession tracks a UDP client session.
type udpSession struct {
	clientAddr *net.UDPAddr
	remoteConn net.Conn
	lastActive time.Time
	mu         sync.Mutex
}

// NewUDPProxy creates a new UDP proxy for the given rule.
func NewUDPProxy(rule *config.ForwardRule, manager *tunnel.Manager, logger *slog.Logger, m *metrics.Collector) *UDPProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &UDPProxy{
		rule:     rule,
		manager:  manager,
		logger:   logger.With("proxy", "udp", "local", rule.LocalEndpoint(), "remote", rule.RemoteEndpoint()),
		metrics:  m,
		ctx:      ctx,
		cancel:   cancel,
		sessions: make(map[string]*udpSession),
	}
}

// Start starts the UDP proxy listener.
func (p *UDPProxy) Start() error {
	addr, err := net.ResolveUDPAddr("udp", p.rule.LocalEndpoint())
	if err != nil {
		return err
	}

	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	p.listener = listener

	p.logger.Info("started UDP proxy listener")

	// Start packet handler
	p.wg.Add(1)
	go p.readLoop()

	// Start session cleanup
	p.wg.Add(1)
	go p.cleanupLoop()

	return nil
}

// readLoop reads incoming UDP packets and forwards them.
func (p *UDPProxy) readLoop() {
	defer p.wg.Done()

	buf := make([]byte, UDPBufferSize)

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		// Set read deadline to allow checking context
		p.listener.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, clientAddr, err := p.listener.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-p.ctx.Done():
				return
			default:
				p.logger.Error("read error", "error", err)
				continue
			}
		}

		// Get or create session
		session, err := p.getOrCreateSession(clientAddr)
		if err != nil {
			p.logger.Error("failed to create session", "client", clientAddr, "error", err)
			continue
		}

		// Forward packet to remote
		packet := make([]byte, n)
		copy(packet, buf[:n])

		p.wg.Add(1)
		go func(s *udpSession, data []byte) {
			defer p.wg.Done()
			p.forwardToRemote(s, data)
		}(session, packet)
	}
}

// getOrCreateSession gets an existing session or creates a new one.
func (p *UDPProxy) getOrCreateSession(clientAddr *net.UDPAddr) (*udpSession, error) {
	key := clientAddr.String()

	p.sessionsMu.Lock()
	session, exists := p.sessions[key]
	if exists {
		session.mu.Lock()
		session.lastActive = time.Now()
		session.mu.Unlock()
		p.sessionsMu.Unlock()
		return session, nil
	}
	p.sessionsMu.Unlock()

	// Create new session
	p.logger.Debug("creating new session", "client", clientAddr)

	// Record connection metric
	if p.metrics != nil {
		p.metrics.ConnectionsTotal.WithLabelValues("udp", p.rule.LocalEndpoint(), p.rule.RemoteEndpoint()).Inc()
		p.metrics.ActiveConnections.WithLabelValues("udp", p.rule.LocalEndpoint(), p.rule.RemoteEndpoint()).Inc()
	}

	// Dial remote through tunnel
	ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
	remoteConn, err := p.manager.DialUDP(ctx, p.rule.RemoteEndpoint())
	cancel()
	if err != nil {
		return nil, err
	}

	session = &udpSession{
		clientAddr: clientAddr,
		remoteConn: remoteConn,
		lastActive: time.Now(),
	}

	p.sessionsMu.Lock()
	// Double-check if another goroutine created the session
	if existing, exists := p.sessions[key]; exists {
		remoteConn.Close()
		p.sessionsMu.Unlock()
		return existing, nil
	}
	p.sessions[key] = session
	p.sessionsMu.Unlock()

	// Start response handler
	p.wg.Add(1)
	go p.handleResponses(session)

	return session, nil
}

// forwardToRemote forwards a packet to the remote endpoint.
func (p *UDPProxy) forwardToRemote(session *udpSession, data []byte) {
	session.mu.Lock()
	session.lastActive = time.Now()
	conn := session.remoteConn
	session.mu.Unlock()

	n, err := conn.Write(data)
	if err != nil {
		p.logger.Debug("write to remote failed", "error", err)
		return
	}

	if p.metrics != nil {
		p.metrics.BytesTransferred.WithLabelValues("udp", p.rule.LocalEndpoint(), p.rule.RemoteEndpoint(), "tx").Add(float64(n))
	}
}

// handleResponses handles responses from the remote endpoint.
func (p *UDPProxy) handleResponses(session *udpSession) {
	defer p.wg.Done()
	defer func() {
		// Clean up session
		p.sessionsMu.Lock()
		delete(p.sessions, session.clientAddr.String())
		p.sessionsMu.Unlock()

		session.remoteConn.Close()

		if p.metrics != nil {
			p.metrics.ActiveConnections.WithLabelValues("udp", p.rule.LocalEndpoint(), p.rule.RemoteEndpoint()).Dec()
		}

		p.logger.Debug("session closed", "client", session.clientAddr)
	}()

	buf := make([]byte, UDPBufferSize)

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		// Set read deadline for idle timeout
		session.remoteConn.SetReadDeadline(time.Now().Add(UDPIdleTimeout))

		n, err := session.remoteConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if session is still active
				session.mu.Lock()
				lastActive := session.lastActive
				session.mu.Unlock()

				if time.Since(lastActive) > UDPIdleTimeout {
					p.logger.Debug("session idle timeout", "client", session.clientAddr)
					return
				}
				continue
			}
			select {
			case <-p.ctx.Done():
				return
			default:
				p.logger.Debug("read from remote failed", "error", err)
				return
			}
		}

		// Update activity
		session.mu.Lock()
		session.lastActive = time.Now()
		session.mu.Unlock()

		// Forward response to client
		_, err = p.listener.WriteToUDP(buf[:n], session.clientAddr)
		if err != nil {
			p.logger.Debug("write to client failed", "error", err)
			continue
		}

		if p.metrics != nil {
			p.metrics.BytesTransferred.WithLabelValues("udp", p.rule.LocalEndpoint(), p.rule.RemoteEndpoint(), "rx").Add(float64(n))
		}
	}
}

// cleanupLoop periodically cleans up idle sessions.
func (p *UDPProxy) cleanupLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.cleanupIdleSessions()
		}
	}
}

// cleanupIdleSessions removes sessions that have been idle too long.
func (p *UDPProxy) cleanupIdleSessions() {
	p.sessionsMu.Lock()
	defer p.sessionsMu.Unlock()

	now := time.Now()
	for key, session := range p.sessions {
		session.mu.Lock()
		lastActive := session.lastActive
		session.mu.Unlock()

		if now.Sub(lastActive) > UDPIdleTimeout {
			p.logger.Debug("cleaning up idle session", "client", key)
			session.remoteConn.Close()
			delete(p.sessions, key)

			if p.metrics != nil {
				p.metrics.ActiveConnections.WithLabelValues("udp", p.rule.LocalEndpoint(), p.rule.RemoteEndpoint()).Dec()
			}
		}
	}
}

// Stop stops the UDP proxy.
func (p *UDPProxy) Stop() error {
	p.cancel()

	if p.listener != nil {
		p.listener.Close()
	}

	// Close all sessions
	p.sessionsMu.Lock()
	for _, session := range p.sessions {
		session.remoteConn.Close()
	}
	p.sessions = make(map[string]*udpSession)
	p.sessionsMu.Unlock()

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		p.logger.Warn("timeout waiting for UDP proxy to stop")
	}

	p.logger.Info("UDP proxy stopped")
	return nil
}

// LocalAddr returns the local address the proxy is listening on.
func (p *UDPProxy) LocalAddr() net.Addr {
	if p.listener != nil {
		return p.listener.LocalAddr()
	}
	return nil
}
