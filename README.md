# wg-proxy

A user-space WireGuard client that exposes remote services on localhost via TCP/UDP port forwarding. No kernel TUN/TAP device or root privileges required.

## Overview

`wg-proxy` embeds WireGuard in-process and couples it with gVisor's user-space IP stack (netstack), allowing you to forward TCP and UDP traffic through a WireGuard tunnel without system-level network configuration or administrative privileges.

### ⚠️ Important: MTU Considerations

Due to TCP MSS (Maximum Segment Size) handling limitations in gVisor's netstack implementation, **a low MTU value is required** for reliable operation. The default MTU of **1280 bytes** is recommended and should not be increased significantly.

**Why this matters:**
- Small HTTP responses (redirects, API calls) will work fine
- Larger responses may fail silently if MTU is too high
- This is a known limitation with netstack-based WireGuard implementations (see [Tailscale #3878](https://github.com/tailscale/tailscale/issues/3878))

If you experience issues with larger responses, try reducing the MTU further (e.g., `mtu: 1200`).

## Features

- **No root required**: Runs entirely in user space
- **On-demand tunnels**: Creates WireGuard tunnel on first traffic, tears down after 2 minutes of inactivity
- **Multiple profiles**: Support for named configuration profiles
- **TCP & UDP forwarding**: Forward both TCP and UDP ports through the tunnel
- **Browser HTTPS**: Local CONNECT proxy and PAC file preserve service names and TLS
- **Flexible binding**: Bind to localhost or specific interfaces
- **Metrics**: Optional Prometheus metrics endpoint
- **Debug profiling**: Optional pprof endpoint for performance analysis
- **Lazy connection**: Tunnel only comes up when traffic flows

## Getting Started

### Prerequisites

- Go 1.25 or later (for building from source)
- Access to a WireGuard server with peer configuration
- Server's public key and endpoint

### Installation

#### Building from Source

```bash
# Clone the repository
git clone https://github.com/ccakes/wgproxy.git
cd wgproxy

# Build the binary
go build -o wg-proxy ./cmd/wg-proxy

# Optional: Install to system path
sudo cp wg-proxy /usr/local/bin/
```

### Quick Start

1. **Generate a WireGuard keypair:**

```bash
wg-proxy generate-key
```

Save the private key securely and provide the public key to your WireGuard server administrator.

2. **Generate a sample configuration:**

```bash
wg-proxy generate-config
```

This creates `config.yaml` in the current directory.

3. **Edit the configuration:**

```yaml
profiles:
  production:
    server: "192.0.2.10:51820"              # WireGuard server endpoint
    private_key: "$HOME/.wg-proxy/private.key"  # Path to your private key
    peer_public_key: "SERVER_PUBLIC_KEY_BASE64" # Server's public key
    cidr: "10.0.0.0/8"                      # Allowed IP range
    tun_ip: "10.255.255.2/32"               # Your tunnel IP
    mtu: 1280                               # Keep this low!
    tcp:
      - "8080:10.1.1.100:80"                # Forward local :8080 to remote 10.1.1.100:80
    udp:
      - "5353:10.1.1.1:53"                  # Forward local :5353 to remote 10.1.1.1:53
    log_level: info
    metrics: "127.0.0.1:9090"               # Optional metrics endpoint
```

4. **Store your private key:**

```bash
mkdir -p ~/.wg-proxy
echo "YOUR_PRIVATE_KEY_BASE64" > ~/.wg-proxy/private.key
chmod 600 ~/.wg-proxy/private.key
```

5. **Run the proxy:**

```bash
wg-proxy --profile production --config config.yaml
```

The tunnel will be created on-demand when you first access a forwarded port.

## Browser access through a private ingress

Add this to an existing WireGuard profile to reach HTTPS services by name
through a shared ingress. TCP/UDP forwards are optional; TLS terminates at the ingress.

```yaml
http_proxy:
  listen: "127.0.0.1:18080"
  target: "10.1.1.100:443"
  hosts: ["*.example.com"]
```

Start wg-proxy and set the automatic proxy URL to
`http://127.0.0.1:18080/proxy.pac`:

- **Safari / Chrome on macOS:** System Settings → Network → active connection
  → Details → Proxies → Automatic Proxy Configuration. Other apps may also use it.
- **Firefox:** Settings → Network Settings → Automatic proxy configuration URL.

Open `https://app.example.com`. Matching names use WireGuard; other sites
connect directly. Keep wg-proxy running while the PAC setting is enabled.

`listen` requires a loopback IP and fixed port. `target` requires an IPv4 address
on port 443, reachable through WireGuard and inside the profile's `cidr`.
That CIDR must also cover any retained TCP/UDP forwards. `hosts` accepts exact
names or `*.suffix` patterns; wildcards exclude the suffix itself.

Only TCP-based HTTPS is supported. The local proxy is unauthenticated;
host rules do not provide per-application authorization within the ingress.

## Running as a System Service

### systemd (Linux)

1. **Install the service file:**

```bash
mkdir -p ~/.config/systemd/user
cp extra/systemd/wg-proxy@.service ~/.config/systemd/user/
```

2. **Place your binary and configuration:**

```bash
mkdir -p ~/.local/bin ~/.config/wg-proxy
cp wg-proxy ~/.local/bin/
cp config.yaml ~/.config/wg-proxy/
```

3. **Enable and start the service:**

The service uses the `@` template syntax, where the profile name follows the `@`:

```bash
# Enable service for the "production" profile
systemctl --user enable wg-proxy@production
systemctl --user start wg-proxy@production

# Check status
systemctl --user status wg-proxy@production

# View logs
journalctl --user -u wg-proxy@production -f
```

4. **Multiple profiles:**

You can run multiple profiles simultaneously:

```bash
systemctl --user enable wg-proxy@staging
systemctl --user start wg-proxy@staging
```

### launchd (macOS)

1. **Install the plist file:**

```bash
cp extra/launchd/com.github.ccakes.wg-proxy.plist ~/Library/LaunchAgents/
```

2. **Edit the plist to match your setup:**

```bash
# Edit the plist to update:
# - Path to wg-proxy binary (if not in /usr/local/bin)
# - Profile name (default: "default")
# - Any other custom configuration
nano ~/Library/LaunchAgents/com.github.ccakes.wg-proxy.plist
```

3. **Place your configuration:**

```bash
mkdir -p ~/.config/wg-proxy
cp config.yaml ~/.config/wg-proxy/
```

4. **Load and start the service:**

```bash
# Load the service
launchctl load ~/Library/LaunchAgents/com.github.ccakes.wg-proxy.plist

# Start the service
launchctl start com.github.ccakes.wg-proxy

# Check if it's running
launchctl list | grep wg-proxy

# View logs
tail -f /tmp/wg-proxy.err.log
```

5. **Unload the service:**

```bash
launchctl unload ~/Library/LaunchAgents/com.github.ccakes.wg-proxy.plist
```

## Configuration Reference

### Profile Structure

```yaml
profiles:
  <profile-name>:
    server: "host:port"                  # Required: WireGuard server endpoint
    private_key: "path or base64"        # Default: $HOME/.wg-proxy/private.key
    peer_public_key: "base64"            # Required: Server's public key
    psk: "base64"                        # Optional: Pre-shared key
    cidr: "10.0.0.0/8"                   # Default: 10.0.0.0/8
    tun_ip: "10.255.255.2/32"            # Default: 10.255.255.2/32
    mtu: 1280                            # Default: 1280 (keep this low!)
    tcp: []                              # TCP forwarding rules
    udp: []                              # UDP forwarding rules
    log_level: "info"                    # debug|info|warn|error (default: info)
    metrics: "127.0.0.1:9090"            # Optional: metrics endpoint
    pprof: "127.0.0.1:6060"              # Optional: pprof endpoint
```

### Forwarding Rules

Rules can be specified in two formats:

1. **Short form** (binds to `127.0.0.1`):
   ```yaml
   tcp:
     - "8080:10.1.1.100:80"
   ```
   Maps `localhost:8080` → `10.1.1.100:80`

2. **Long form** (explicit bind address):
   ```yaml
   tcp:
     - "0.0.0.0:8443:10.1.2.10:443"
   ```
   Maps `0.0.0.0:8443` → `10.1.2.10:443` (accessible from network)

### Key Resolution

Keys can be provided as:
- **File path**: `$HOME/.wg-proxy/private.key` (file contents are read)
- **Base64 string**: `cF8qLjW8T...` (used directly)
- **Environment variable**: `WG_PRIVATE_KEY` or `WG_PUBLIC_KEY`

## Building

### Requirements

- Go 1.25 or later
- Standard build tools (make, git)

### Build Commands

```bash
# Build for current platform
go build -o wg-proxy ./cmd/wg-proxy

# Build with version information
go build -ldflags "-X main.version=$(git describe --tags)" -o wg-proxy ./cmd/wg-proxy

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o wg-proxy-linux-amd64 ./cmd/wg-proxy

# Cross-compile for macOS
GOOS=darwin GOARCH=arm64 go build -o wg-proxy-darwin-arm64 ./cmd/wg-proxy

# Build with optimizations
go build -ldflags "-s -w" -o wg-proxy ./cmd/wg-proxy
```

### Development

```bash
# Run tests
go test ./...

# Check concurrent connections and shutdown (Node.js also tests PAC execution)
go test -race ./...

# Run with race detector
go run -race ./cmd/wg-proxy --profile dev

# Build and install locally
go install ./cmd/wg-proxy
```

## Monitoring

### Metrics

When `metrics` is configured, a Prometheus-compatible endpoint is exposed:

```bash
curl http://127.0.0.1:9090/metrics
```

Available metrics:
- `wg_proxy_connections_total` - Total connections by protocol, port, and remote address
- `wg_proxy_active_connections` - Current active connections
- `wg_proxy_bytes_transferred_total` - Bytes transferred by direction (tx/rx)

### Health Check

```bash
curl http://127.0.0.1:9090/health
```

Returns:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-19T12:34:56Z"
}
```

### Debug Profiling

When `pprof` is configured:

```bash
# CPU profile
go tool pprof http://127.0.0.1:6060/debug/pprof/profile

# Heap profile
go tool pprof http://127.0.0.1:6060/debug/pprof/heap

# Goroutine profile
go tool pprof http://127.0.0.1:6060/debug/pprof/goroutine
```

## Architecture

`wg-proxy` consists of five major components:

1. **Connection Manager** - Orchestrates tunnel lifecycle with lazy creation and idle teardown
2. **WireGuard Device** - Embedded `wireguard-go` device
3. **Netstack (gVisor)** - User-space IP stack for routing
4. **Proxy Manager** - TCP/UDP listeners and traffic relay
5. **Metrics/Observability** - Optional monitoring endpoints

### Data Flow

```
Local Application
    ↓
TCP/UDP Listener (localhost)
    ↓
Tunnel Manager (lazy init)
    ↓
gVisor Netstack (IP stack)
    ↓
WireGuard Device (encryption)
    ↓
UDP Socket → WireGuard Server
    ↓
Remote Service
```

### Tunnel Lifecycle

- **Lazy creation**: Tunnel is created on first traffic
- **Keepalive**: 25-second persistent keepalive
- **Idle timeout**: Automatic teardown after 2 minutes of inactivity
- **On-demand**: Tunnel recreates automatically on next traffic

## Troubleshooting

### Large HTTP Responses Fail

**Symptom**: Small responses work, but large downloads or HTML pages fail.

**Solution**: This is the MSS/MTU issue. Lower your MTU:

```yaml
mtu: 1200  # Try even lower if needed
```

### Connection Timeouts

**Symptom**: Initial connection works but stalls after a few packets.

**Solution**: Check firewall rules and MTU settings on both client and server.

### DNS Issues

**Symptom**: Cannot resolve remote hostnames.

**Solution**: Forward DNS through the tunnel:

```yaml
udp:
  - "53:10.1.1.1:53"  # Forward DNS queries
```

### Tunnel Not Coming Up

**Symptom**: No traffic flows, tunnel never establishes.

**Checklist**:
1. Verify server endpoint is reachable: `nc -zvu server.example.com 51820`
2. Check keys are correct (peer public key matches server configuration)
3. Enable debug logging: `log_level: debug`
4. Verify allowed IPs on server include your traffic destinations

## Limitations

- **Single peer only**: Each profile connects to one WireGuard server
- **No dynamic reload**: Configuration changes require restart (SIGHUP accepted but not implemented)
- **IPv4 only**: IPv6 routing not supported
- **No NAT traversal**: Requires direct connectivity to WireGuard server
- **MSS limitation**: Low MTU required due to netstack TCP MSS handling

## Contributing

Contributions are welcome! Please:

1. Open an issue to discuss major changes
2. Follow existing code style
3. Add tests for new functionality
4. Update documentation as needed

## License

See [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on [wireguard-go](https://git.zx2c4.com/wireguard-go/)
- Uses [gVisor netstack](https://gvisor.dev/) for user-space networking
- Inspired by various WireGuard userspace implementations

## Related Projects

- [Tailscale](https://tailscale.com/) - Full mesh VPN using WireGuard (also uses netstack)
- [WireGuard](https://www.wireguard.com/) - The underlying protocol
- [wg-quick](https://git.zx2c4.com/wireguard-tools/) - Official WireGuard configuration utility

## See Also

- [SPEC.md](SPEC.md) - Detailed specification and architecture
- [Tailscale Issue #3878](https://github.com/tailscale/tailscale/issues/3878) - TCP MSS in netstack discussion
- [WireGuard MTU Fixes](https://keremerkan.net/posts/wireguard-mtu-fixes/) - General WireGuard MTU guidance
