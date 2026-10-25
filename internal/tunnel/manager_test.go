package tunnel

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ccakes/wgproxy/internal/config"
)

func TestPeerUsesProfileCIDR(t *testing.T) {
	for _, psk := range []string{"", base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		m := &Manager{profile: &config.Profile{
			Server: "127.0.0.1:51820", CIDR: "10.1.1.100/32", PSK: psk,
		}}
		ipc, err := m.buildIPCConfig()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ipc, "allowed_ip=10.1.1.100/32\n") {
			t.Fatal("WireGuard peer does not enforce the configured CIDR")
		}
	}
}
