// Package tun provides an in-memory TUN device implementation for wireguard-go.
package tun

import (
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	// DefaultMTU is the default MTU for the TUN device.
	DefaultMTU = 1280
	// QueueSize is the buffer size for packet channels.
	QueueSize = 256
)

// MemTun is a channel-based in-memory TUN device implementation.
// It implements the tun.Device interface for use with wireguard-go.
type MemTun struct {
	mtu       int
	inbound   chan []byte // packets from WG -> netstack
	outbound  chan []byte // packets from netstack -> WG
	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

// New creates a new in-memory TUN device with the specified MTU.
func New(mtu int) *MemTun {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	return &MemTun{
		mtu:      mtu,
		inbound:  make(chan []byte, QueueSize),
		outbound: make(chan []byte, QueueSize),
		events:   make(chan tun.Event, 4),
		closed:   make(chan struct{}),
	}
}

// Name returns the name of the TUN device.
func (t *MemTun) Name() (string, error) {
	return "memtun0", nil
}

// File returns nil as this is an in-memory device.
func (t *MemTun) File() *os.File {
	return nil
}

// Events returns the event channel.
func (t *MemTun) Events() <-chan tun.Event {
	return t.events
}

// MTU returns the MTU of the device.
func (t *MemTun) MTU() (int, error) {
	return t.mtu, nil
}

// BatchSize returns the preferred batch size for reads/writes.
func (t *MemTun) BatchSize() int {
	return 1
}

// Read reads packets from the outbound channel (netstack -> WG).
// This is called by wireguard-go to get packets to encrypt and send.
func (t *MemTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt := <-t.outbound:
		if len(pkt) > len(bufs[0])-offset {
			return 0, nil // drop oversized packet
		}
		copy(bufs[0][offset:], pkt)
		sizes[0] = len(pkt)
		return 1, nil
	}
}

// Write writes packets to the inbound channel (WG -> netstack).
// This is called by wireguard-go after decrypting received packets.
func (t *MemTun) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}

	for i, buf := range bufs {
		if len(buf) <= offset {
			continue
		}
		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])

		select {
		case t.inbound <- pkt:
		case <-t.closed:
			return i, os.ErrClosed
		default:
			// Drop packet if channel is full
		}
	}
	return len(bufs), nil
}

// Close closes the TUN device.
func (t *MemTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		// Signal that the device is down
		select {
		case t.events <- tun.EventDown:
		default:
		}
	})
	return nil
}

// Inbound returns the channel for reading packets destined for netstack.
// Use this to receive decrypted packets from WireGuard.
func (t *MemTun) Inbound() <-chan []byte {
	return t.inbound
}

// Outbound returns the channel for writing packets from netstack.
// Use this to send packets to WireGuard for encryption.
func (t *MemTun) Outbound() chan<- []byte {
	return t.outbound
}

// SendUp signals that the device is up.
func (t *MemTun) SendUp() {
	select {
	case t.events <- tun.EventUp:
	default:
	}
}

// IsClosed returns true if the TUN device has been closed.
func (t *MemTun) IsClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}
