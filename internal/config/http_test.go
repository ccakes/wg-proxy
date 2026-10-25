package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func browserProfile() *Profile {
	return &Profile{
		Server: "192.0.2.1:51820", PeerPublicKey: "test",
		CIDR: "10.1.1.100/32", TunIP: DefaultTunIP,
		HTTPProxy: &HTTPProxy{
			Listen: "127.0.0.1:18080", Target: "10.1.1.100:443",
			Hosts: []string{"*.example.com", "home.example.net"},
		},
	}
}

func TestBrowserProfile(t *testing.T) {
	const document = `profiles:
  home:
    server: 192.0.2.1:51820
    peer_public_key: test
    cidr: 10.1.1.100/32
    tun_ip: 10.255.255.2/32
    http_proxy:
      listen: 127.0.0.1:18080
      target: 10.1.1.100:443
      hosts: ["*.example.com"]
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(document), &cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Profiles["home"].Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBrowserConfigRejected(t *testing.T) {
	cases := map[string]func(*HTTPProxy){
		"public listener":  func(p *HTTPProxy) { p.Listen = "0.0.0.0:18080" },
		"named listener":   func(p *HTTPProxy) { p.Listen = "localhost:18080" },
		"missing port":     func(p *HTTPProxy) { p.Listen = "127.0.0.1" },
		"ephemeral port":   func(p *HTTPProxy) { p.Listen = "127.0.0.1:0" },
		"large port":       func(p *HTTPProxy) { p.Listen = "127.0.0.1:65536" },
		"named target":     func(p *HTTPProxy) { p.Target = "ingress.example.com:443" },
		"outside CIDR":     func(p *HTTPProxy) { p.Target = "10.1.1.101:443" },
		"wrong port":       func(p *HTTPProxy) { p.Target = "10.1.1.100:22" },
		"IPv6 target":      func(p *HTTPProxy) { p.Target = "[::1]:443" },
		"empty hosts":      func(p *HTTPProxy) { p.Hosts = nil },
		"all hosts":        func(p *HTTPProxy) { p.Hosts = []string{"*"} },
		"partial wildcard": func(p *HTTPProxy) { p.Hosts = []string{"*example.com"} },
		"bad label":        func(p *HTTPProxy) { p.Hosts = []string{"-example.com"} },
		"IP host":          func(p *HTTPProxy) { p.Hosts = []string{"127.0.0.1"} },
		"script injection": func(p *HTTPProxy) { p.Hosts = []string{`x";alert(1)`} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := browserProfile()
			change(p.HTTPProxy)
			if err := p.Validate(); err == nil {
				t.Fatal("accepted invalid HTTP proxy configuration")
			}
		})
	}
}

func TestAllowedHosts(t *testing.T) {
	p := browserProfile().HTTPProxy
	cases := map[string]bool{
		"app.example.com":             true,
		"APP.EXAMPLE.COM.":            true,
		"nested.app.example.com":      true,
		"home.example.net":            true,
		"example.com":                 false,
		"evilexample.com":             false,
		"app.example.com.example.org": false,
		"other.home.example.net":      false,
		"127.0.0.1":                   false,
		".example.com":                false,
		"bad..example.com":            false,
	}
	for host, want := range cases {
		if got := p.AllowsHost(host); got != want {
			t.Errorf("AllowsHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestLegacyProfile(t *testing.T) {
	p := browserProfile()
	p.HTTPProxy = nil
	p.TCP = []string{"8443:10.1.1.100:443"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}
