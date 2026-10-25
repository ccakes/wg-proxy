// Package tunnel manages the lifecycle of WireGuard tunnels with lazy creation and idle teardown.
package tunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ccakes/wgproxy/internal/config"
	"github.com/ccakes/wgproxy/internal/netstack"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgnetstack "golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	// IdleTimeout is the duration after which an idle tunnel is torn down.
	IdleTimeout = 2 * time.Minute
	// KeepaliveInterval is the WireGuard persistent keepalive interval.
	KeepaliveInterval = 25
)

// Manager manages the WireGuard tunnel lifecycle.
type Manager struct {
	profile *config.Profile
	logger  *slog.Logger

	mu           sync.Mutex
	tun          *wgnetstack.Net
	dev          *device.Device
	stack        *netstack.Stack
	activeConns  atomic.Int64
	lastActivity atomic.Int64

	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	tunnelUp   bool
	shutdownCh chan struct{}
}

// NewManager creates a new tunnel manager for the given profile.
func NewManager(profile *config.Profile, logger *slog.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		profile:    profile,
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
		shutdownCh: make(chan struct{}),
	}
	m.lastActivity.Store(time.Now().UnixNano())

	// Start idle checker
	m.wg.Add(1)
	go m.idleChecker()

	return m
}

// EnsureUp ensures the tunnel is up and ready for traffic.
// It creates the tunnel lazily on first call.
func (m *Manager) EnsureUp() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.tunnelUp {
		m.touchActivity()
		return nil
	}

	m.logger.Info("creating tunnel", "server", m.profile.Server)

	// Parse TUN IP
	tunIPPrefix, err := netip.ParsePrefix(m.profile.TunIP)
	if err != nil {
		return fmt.Errorf("invalid tun_ip: %w", err)
	}

	// Create the netstack TUN
	tun, net, err := wgnetstack.CreateNetTUN(
		[]netip.Addr{tunIPPrefix.Addr()},
		[]netip.Addr{}, // No DNS
		m.profile.MTU,
	)
	if err != nil {
		return fmt.Errorf("failed to create netstack TUN: %w", err)
	}

	// Create wireguard-go logger
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			m.logger.Debug(fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			m.logger.Error(fmt.Sprintf(format, args...))
		},
	}

	// Create WireGuard device
	dev := device.NewDevice(tun, conn.NewDefaultBind(), wgLogger)

	// Build and apply IPC config
	ipcConfig, err := m.buildIPCConfig()
	if err != nil {
		dev.Close()
		return fmt.Errorf("failed to build IPC config: %w", err)
	}

	if err := dev.IpcSet(ipcConfig); err != nil {
		dev.Close()
		return fmt.Errorf("failed to configure device: %w", err)
	}

	// Bring up the device
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("failed to bring up device: %w", err)
	}

	// Create our netstack wrapper
	stack := netstack.NewWithNet(net, tunIPPrefix.Addr(), m.logger)

	m.tun = net
	m.dev = dev
	m.stack = stack
	m.tunnelUp = true
	m.touchActivity()

	m.logger.Info("tunnel created successfully",
		"tun_ip", tunIPPrefix.Addr().String(),
		"server", m.profile.Server,
	)

	return nil
}

// buildIPCConfig creates the wireguard-go IPC configuration string.
func (m *Manager) buildIPCConfig() (string, error) {
	// Encode private key as hex
	privateKeyHex := fmt.Sprintf("%x", m.profile.ResolvedPrivateKey)
	peerPubKeyHex := fmt.Sprintf("%x", m.profile.ResolvedPeerPublicKey)

	// Resolve endpoint
	endpoint, err := m.resolveEndpoint(m.profile.Server)
	if err != nil {
		return "", fmt.Errorf("failed to resolve endpoint: %w", err)
	}

	// Build IPC config
	cfg := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
allowed_ip=%s
persistent_keepalive_interval=%d
`, privateKeyHex, peerPubKeyHex, endpoint, m.profile.CIDR, KeepaliveInterval)

	// Add PSK if provided
	if m.profile.PSK != "" {
		pskBytes, err := base64.StdEncoding.DecodeString(m.profile.PSK)
		if err != nil {
			return "", fmt.Errorf("invalid PSK: %w", err)
		}
		if len(pskBytes) != 32 {
			return "", fmt.Errorf("invalid PSK length: %d", len(pskBytes))
		}
		pskHex := fmt.Sprintf("%x", pskBytes)
		cfg = fmt.Sprintf(`private_key=%s
public_key=%s
preshared_key=%s
endpoint=%s
allowed_ip=%s
persistent_keepalive_interval=%d
`, privateKeyHex, peerPubKeyHex, pskHex, endpoint, m.profile.CIDR, KeepaliveInterval)
	}

	return cfg, nil
}

// resolveEndpoint resolves a host:port endpoint, performing DNS lookup if needed.
func (m *Manager) resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint format: %w", err)
	}

	// Check if it's already an IP
	if ip := net.ParseIP(host); ip != nil {
		return endpoint, nil
	}

	// Resolve DNS
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed: %w", err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses found for %s", host)
	}

	// Prefer IPv4
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
			return net.JoinHostPort(addr, port), nil
		}
	}

	// Fall back to first address
	return net.JoinHostPort(addrs[0], port), nil
}

// DialTCP creates a TCP connection through the tunnel.
func (m *Manager) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if err := m.EnsureUp(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	stack := m.stack
	m.mu.Unlock()

	if stack == nil {
		return nil, fmt.Errorf("tunnel not ready")
	}

	conn, err := stack.DialTCP(ctx, addr)
	if err != nil {
		return nil, err
	}

	m.IncrementConns()
	return &trackingConn{Conn: conn, manager: m}, nil
}

// DialUDP creates a UDP connection through the tunnel.
func (m *Manager) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	if err := m.EnsureUp(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	stack := m.stack
	m.mu.Unlock()

	if stack == nil {
		return nil, fmt.Errorf("tunnel not ready")
	}

	conn, err := stack.DialUDP(ctx, addr)
	if err != nil {
		return nil, err
	}

	m.IncrementConns()
	return &trackingConn{Conn: conn, manager: m}, nil
}

// IncrementConns increments the active connection count.
func (m *Manager) IncrementConns() {
	m.activeConns.Add(1)
	m.touchActivity()
}

// DecrementConns decrements the active connection count.
func (m *Manager) DecrementConns() {
	m.activeConns.Add(-1)
	m.touchActivity()
}

// touchActivity updates the last activity timestamp.
func (m *Manager) touchActivity() {
	m.lastActivity.Store(time.Now().UnixNano())
}

// TouchActivity is the exported version of touchActivity.
func (m *Manager) TouchActivity() {
	m.touchActivity()
}

// ActiveConns returns the current number of active connections.
func (m *Manager) ActiveConns() int64 {
	return m.activeConns.Load()
}

// idleChecker periodically checks for idle tunnels and tears them down.
func (m *Manager) idleChecker() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkIdle()
		}
	}
}

// checkIdle checks if the tunnel should be torn down due to inactivity.
func (m *Manager) checkIdle() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.tunnelUp {
		return
	}

	// Don't tear down if there are active connections
	if m.activeConns.Load() > 0 {
		return
	}

	lastActivity := time.Unix(0, m.lastActivity.Load())
	if time.Since(lastActivity) > IdleTimeout {
		m.logger.Info("tearing down idle tunnel", "idle_duration", time.Since(lastActivity))
		m.teardownLocked()
	}
}

// teardownLocked tears down the tunnel (must be called with lock held).
func (m *Manager) teardownLocked() {
	if m.stack != nil {
		m.stack.Close()
		m.stack = nil
	}

	if m.dev != nil {
		m.dev.Close()
		m.dev = nil
	}

	m.tun = nil
	m.tunnelUp = false

	m.logger.Info("tunnel torn down")
}

// Close shuts down the manager and all associated resources.
func (m *Manager) Close() error {
	m.logger.Info("shutting down tunnel manager")

	// Cancel context to stop goroutines
	m.cancel()

	// Tear down tunnel
	m.mu.Lock()
	if m.tunnelUp {
		m.teardownLocked()
	}
	m.mu.Unlock()

	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		m.logger.Warn("timeout waiting for tunnel manager goroutines")
	}

	close(m.shutdownCh)
	return nil
}

// IsUp returns whether the tunnel is currently up.
func (m *Manager) IsUp() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tunnelUp
}

// trackingConn wraps a connection to track when it's closed.
type trackingConn struct {
	net.Conn
	manager *Manager
	closed  bool
	mu      sync.Mutex
}

func (c *trackingConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	c.manager.DecrementConns()
	return c.Conn.Close()
}

// CloseWrite preserves half-closes through the connection tracker.
func (c *trackingConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return c.Close()
}

func (c *trackingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.manager.TouchActivity()
	}
	return n, err
}

func (c *trackingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.manager.TouchActivity()
	}
	return n, err
}
