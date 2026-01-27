// Package netstack provides a gVisor-based userspace IP stack integration
// using wireguard-go's netstack package.
package netstack

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Stack wraps wireguard-go's netstack with helpers for TCP/UDP connections.
type Stack struct {
	net     *netstack.Net
	tunIP   netip.Addr
	logger  *slog.Logger
	ctx     context.Context
	cancel  context.CancelFunc
	closed  bool
	closeMu sync.Mutex
}

// Config holds configuration for creating a netstack.
type Config struct {
	TunIP  string // e.g., "10.255.255.2/32"
	CIDR   string // e.g., "10.0.0.0/8"
	MTU    int
	Logger *slog.Logger
}

// New creates a new netstack. This is now a placeholder since
// wireguard-go/tun/netstack creates the TUN internally.
// Use NewWithNet instead after creating the WireGuard tunnel.
func New(cfg *Config) (*Stack, error) {
	// Parse TUN IP
	tunIPPrefix, err := netip.ParsePrefix(cfg.TunIP)
	if err != nil {
		return nil, fmt.Errorf("invalid tun_ip: %w", err)
	}
	tunIP := tunIPPrefix.Addr()

	ctx, cancel := context.WithCancel(context.Background())

	return &Stack{
		tunIP:  tunIP,
		logger: cfg.Logger,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// NewWithNet creates a Stack wrapping an existing netstack.Net.
func NewWithNet(n *netstack.Net, tunIP netip.Addr, logger *slog.Logger) *Stack {
	ctx, cancel := context.WithCancel(context.Background())
	return &Stack{
		net:    n,
		tunIP:  tunIP,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}
}

// SetNet sets the underlying netstack.Net (used for deferred initialization).
func (s *Stack) SetNet(n *netstack.Net) {
	s.net = n
}

// DialTCP creates a TCP connection to the given address through the tunnel.
func (s *Stack) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if s.net == nil {
		return nil, fmt.Errorf("netstack not initialized")
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	return s.net.DialContextTCP(ctx, tcpAddr)
}

// DialUDP creates a UDP connection to the given address through the tunnel.
func (s *Stack) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	if s.net == nil {
		return nil, fmt.Errorf("netstack not initialized")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	return s.net.DialUDP(nil, udpAddr)
}

// DialContextTCPAddrPort dials using netip.AddrPort.
func (s *Stack) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if s.net == nil {
		return nil, fmt.Errorf("netstack not initialized")
	}

	tcpAddr := net.TCPAddrFromAddrPort(addr)
	return s.net.DialContextTCP(ctx, tcpAddr)
}

// Close shuts down the netstack and all associated resources.
func (s *Stack) Close() error {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	s.closeMu.Unlock()

	// Cancel context
	s.cancel()

	return nil
}

// LocalAddr returns the local tunnel IP address.
func (s *Stack) LocalAddr() netip.Addr {
	return s.tunIP
}

// IsIPInCIDR checks if an IP address is within a CIDR range.
func IsIPInCIDR(ip, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return network.Contains(parsedIP)
}

// WaitWithTimeout waits for the context to be done or timeout.
func (s *Stack) WaitWithTimeout(timeout time.Duration) {
	select {
	case <-s.ctx.Done():
	case <-time.After(timeout):
	}
}
