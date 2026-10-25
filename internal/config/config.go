// Package config handles configuration loading, validation, and defaults for wg-proxy.
package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Default values per spec
const (
	DefaultCIDR     = "10.0.0.0/8"
	DefaultTunIP    = "10.255.255.2/32"
	DefaultMTU      = 1280
	DefaultLogLevel = "info"
)

// Config represents the top-level configuration file structure.
type Config struct {
	Profiles map[string]*Profile `yaml:"profiles"`
}

// Profile represents a single wg-proxy profile configuration.
type Profile struct {
	Server        string     `yaml:"server"`
	PrivateKey    string     `yaml:"private_key"`
	PeerPublicKey string     `yaml:"peer_public_key"`
	PSK           string     `yaml:"psk"`
	CIDR          string     `yaml:"cidr"`
	TunIP         string     `yaml:"tun_ip"`
	MTU           int        `yaml:"mtu"`
	TCP           []string   `yaml:"tcp"`
	UDP           []string   `yaml:"udp"`
	HTTPProxy     *HTTPProxy `yaml:"http_proxy"`
	LogLevel      string     `yaml:"log_level"`
	Metrics       string     `yaml:"metrics"`
	PProf         string     `yaml:"pprof"`

	// Resolved values (populated after Load)
	ResolvedPrivateKey    []byte
	ResolvedPeerPublicKey []byte
}

// ForwardRule represents a parsed forwarding rule.
type ForwardRule struct {
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
}

// String returns a string representation of the forward rule.
func (r ForwardRule) String() string {
	return fmt.Sprintf("%s:%d->%s:%d", r.LocalAddr, r.LocalPort, r.RemoteAddr, r.RemotePort)
}

// LocalEndpoint returns the local listen address.
func (r ForwardRule) LocalEndpoint() string {
	return net.JoinHostPort(r.LocalAddr, strconv.Itoa(r.LocalPort))
}

// RemoteEndpoint returns the remote target address.
func (r ForwardRule) RemoteEndpoint() string {
	return net.JoinHostPort(r.RemoteAddr, strconv.Itoa(r.RemotePort))
}

// Load reads and parses a configuration file, returning the Config.
func Load(path string) (*Config, error) {
	// Expand home directory
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		path = filepath.Join(home, path[1:])
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// GetProfile retrieves a profile by name and applies defaults.
func (c *Config) GetProfile(name string) (*Profile, error) {
	p, ok := c.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", name)
	}

	// Apply defaults
	if p.CIDR == "" {
		p.CIDR = DefaultCIDR
	}
	if p.TunIP == "" {
		p.TunIP = DefaultTunIP
	}
	if p.MTU == 0 {
		p.MTU = DefaultMTU
	}
	if p.LogLevel == "" {
		p.LogLevel = DefaultLogLevel
	}
	if p.PrivateKey == "" {
		home, _ := os.UserHomeDir()
		p.PrivateKey = filepath.Join(home, ".wg-proxy", "private.key")
	}

	// Validate required fields
	if err := p.Validate(); err != nil {
		return nil, err
	}

	// Resolve private key
	key, err := resolveKey(p.PrivateKey, "WG_PRIVATE_KEY")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve private key: %w", err)
	}
	p.ResolvedPrivateKey = key

	// Resolve peer public key
	peerKey, err := resolveKey(p.PeerPublicKey, "WG_PEER_PUBLIC_KEY")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve peer public key: %w", err)
	}
	p.ResolvedPeerPublicKey = peerKey

	return p, nil
}

// Validate checks that all required fields are present and valid.
func (p *Profile) Validate() error {
	if p.Server == "" {
		return fmt.Errorf("server is required")
	}
	if p.PeerPublicKey == "" {
		return fmt.Errorf("peer_public_key is required")
	}
	if len(p.TCP) == 0 && len(p.UDP) == 0 && p.HTTPProxy == nil {
		return fmt.Errorf("at least one tcp, udp, or http_proxy entry must exist")
	}

	// Validate forwarding rules
	for _, rule := range p.TCP {
		if _, err := ParseForwardRule(rule); err != nil {
			return fmt.Errorf("invalid TCP rule %q: %w", rule, err)
		}
	}
	for _, rule := range p.UDP {
		if _, err := ParseForwardRule(rule); err != nil {
			return fmt.Errorf("invalid UDP rule %q: %w", rule, err)
		}
	}

	// Validate CIDR
	_, network, err := net.ParseCIDR(p.CIDR)
	if err != nil {
		return fmt.Errorf("invalid cidr %q: %w", p.CIDR, err)
	}
	if p.HTTPProxy != nil {
		if err := p.HTTPProxy.validate(network); err != nil {
			return err
		}
	}

	// Validate TunIP
	if _, _, err := net.ParseCIDR(p.TunIP); err != nil {
		return fmt.Errorf("invalid tun_ip %q: %w", p.TunIP, err)
	}

	return nil
}

// ParseForwardRule parses a forwarding rule string.
// Formats:
//   - LocalPort:RemoteIP:RemotePort (binds to 127.0.0.1)
//   - LocalAddr:LocalPort:RemoteIP:RemotePort
func ParseForwardRule(rule string) (*ForwardRule, error) {
	parts := strings.Split(rule, ":")
	if len(parts) < 3 || len(parts) > 4 {
		return nil, fmt.Errorf("invalid format, expected LPORT:RIP:RPORT or LADDR:LPORT:RIP:RPORT")
	}

	var localAddr string
	var localPortStr, remoteAddr, remotePortStr string

	if len(parts) == 3 {
		// LocalPort:RemoteIP:RemotePort
		localAddr = "127.0.0.1"
		localPortStr = parts[0]
		remoteAddr = parts[1]
		remotePortStr = parts[2]
	} else {
		// LocalAddr:LocalPort:RemoteIP:RemotePort
		localAddr = parts[0]
		localPortStr = parts[1]
		remoteAddr = parts[2]
		remotePortStr = parts[3]
	}

	localPort, err := strconv.Atoi(localPortStr)
	if err != nil {
		return nil, fmt.Errorf("invalid local port: %w", err)
	}
	if localPort < 1 || localPort > 65535 {
		return nil, fmt.Errorf("local port out of range: %d", localPort)
	}

	remotePort, err := strconv.Atoi(remotePortStr)
	if err != nil {
		return nil, fmt.Errorf("invalid remote port: %w", err)
	}
	if remotePort < 1 || remotePort > 65535 {
		return nil, fmt.Errorf("remote port out of range: %d", remotePort)
	}

	// Validate remote address is a valid IP
	if net.ParseIP(remoteAddr) == nil {
		return nil, fmt.Errorf("invalid remote IP address: %s", remoteAddr)
	}

	return &ForwardRule{
		LocalAddr:  localAddr,
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		RemotePort: remotePort,
	}, nil
}

// GetTCPRules returns parsed TCP forwarding rules.
func (p *Profile) GetTCPRules() ([]*ForwardRule, error) {
	rules := make([]*ForwardRule, 0, len(p.TCP))
	for _, r := range p.TCP {
		rule, err := ParseForwardRule(r)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// GetUDPRules returns parsed UDP forwarding rules.
func (p *Profile) GetUDPRules() ([]*ForwardRule, error) {
	rules := make([]*ForwardRule, 0, len(p.UDP))
	for _, r := range p.UDP {
		rule, err := ParseForwardRule(r)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// GetTunIPAddr returns just the IP address portion of TunIP (without the mask).
func (p *Profile) GetTunIPAddr() net.IP {
	ip, _, _ := net.ParseCIDR(p.TunIP)
	return ip
}

// resolveKey attempts to resolve a key from:
// 1. Direct base64 string (32 bytes when decoded)
// 2. File path
// 3. Environment variable
func resolveKey(value, envVar string) ([]byte, error) {
	// Try environment variable first
	if envVal := os.Getenv(envVar); envVal != "" {
		value = envVal
	}

	// Expand home directory in path
	if strings.HasPrefix(value, "$HOME") {
		home, _ := os.UserHomeDir()
		value = strings.Replace(value, "$HOME", home, 1)
	}
	if strings.HasPrefix(value, "~") {
		home, _ := os.UserHomeDir()
		value = filepath.Join(home, value[1:])
	}

	// Try as base64 first (WireGuard keys are 32 bytes = 44 base64 chars with padding)
	if len(value) == 44 || len(value) == 43 {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}

	// Try as file path
	if data, err := os.ReadFile(value); err == nil {
		trimmed := strings.TrimSpace(string(data))
		decoded, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key from file: %w", err)
		}
		if len(decoded) != 32 {
			return nil, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(decoded))
		}
		return decoded, nil
	}

	return nil, fmt.Errorf("could not resolve key: not a valid base64 key or readable file")
}

// GenerateSampleConfig returns a sample configuration YAML.
func GenerateSampleConfig() string {
	return `# wg-proxy configuration file
profiles:
  example:
    # Required: WireGuard server endpoint
    server: "192.0.2.10:51820"
    
    # Path to private key file or base64-encoded key
    # Default: $HOME/.wg-proxy/private.key
    # Can also use WG_PRIVATE_KEY environment variable
    private_key: "$HOME/.wg-proxy/private.key"
    
    # Required: WireGuard peer's public key (base64)
    peer_public_key: "PEER_PUBLIC_KEY_HERE"
    
    # Optional: Pre-shared key
    # psk: "PSK_HERE"
    
    # IP range to route through the tunnel
    # Default: 10.0.0.0/8
    cidr: "10.0.0.0/8"
    
    # Local tunnel IP address
    # Default: 10.255.255.2/32
    tun_ip: "10.255.255.2/32"
    
    # MTU for the tunnel
    # Default: 1280
    mtu: 1280
    
    # TCP port forwarding rules
    # Format: LocalPort:RemoteIP:RemotePort or LocalAddr:LocalPort:RemoteIP:RemotePort
    tcp:
      - "8080:10.1.1.1:80"
      - "0.0.0.0:8443:10.1.1.1:443"
    
    # UDP port forwarding rules
    udp:
      - "5353:10.1.1.1:53"

    # Optional: browser HTTPS through one private ingress (no TCP/UDP rules needed)
    # PAC URL: http://127.0.0.1:18080/proxy.pac
    # http_proxy:
    #   listen: "127.0.0.1:18080"
    #   target: "10.1.1.1:443"
    #   hosts: ["*.example.com"]
    
    # Log level: debug, info, warn, error
    # Default: info
    log_level: "info"
    
    # Optional: Prometheus metrics endpoint
    # metrics: "127.0.0.1:9090"
    
    # Optional: pprof endpoint for profiling
    # pprof: "127.0.0.1:6060"
`
}
