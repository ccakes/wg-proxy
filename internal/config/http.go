package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const (
	HTTPSPort         = "443"
	maxHostnameLength = 253
	maxPort           = 65535
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// HTTPProxy maps approved HTTPS names to one ingress without changing TLS.
type HTTPProxy struct {
	Listen string   `yaml:"listen"`
	Target string   `yaml:"target"`
	Hosts  []string `yaml:"hosts"`
}

func (p *HTTPProxy) validate(network *net.IPNet) error {
	host, port, err := net.SplitHostPort(p.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("http_proxy.listen must use a loopback IP and port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > maxPort {
		return fmt.Errorf("invalid http_proxy.listen port")
	}

	host, port, err = net.SplitHostPort(p.Target)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || ip.To4() == nil || port != HTTPSPort {
		return fmt.Errorf("http_proxy.target must be an IPv4 address on port %s", HTTPSPort)
	}
	if !network.Contains(ip) {
		return fmt.Errorf("http_proxy.target is outside cidr")
	}

	if len(p.Hosts) == 0 {
		return fmt.Errorf("http_proxy.hosts must contain an exact name or wildcard suffix")
	}
	for _, pattern := range p.Hosts {
		name := strings.TrimPrefix(strings.ToLower(pattern), "*.")
		if !validHost(name) {
			return fmt.Errorf("invalid http_proxy host %q", pattern)
		}
	}
	return nil
}

func validHost(host string) bool {
	if len(host) > maxHostnameLength || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// AllowsHost checks label boundaries; *.example.com excludes example.com.
func (p *HTTPProxy) AllowsHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if !validHost(host) {
		return false
	}
	for _, pattern := range p.Hosts {
		pattern = strings.ToLower(pattern)
		if host == pattern {
			return true
		}
		if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) {
			return true
		}
	}
	return false
}
