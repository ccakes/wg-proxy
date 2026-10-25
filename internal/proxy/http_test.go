package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ccakes/wgproxy/internal/config"
)

const (
	testTarget = "10.1.1.100:443"
	testHost   = "app.example.com"
)

func startHTTP(t *testing.T, dial tcpDialer) *HTTPProxy {
	t.Helper()
	p := NewHTTPProxy(&config.HTTPProxy{
		Listen: "127.0.0.1:0", Target: testTarget,
		Hosts: []string{"*.example.com", "home.example.net"},
	}, dial, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Stop(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func connect(t *testing.T, p *HTTPProxy, authority, payload string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", p.listener.Addr().String(), testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(testTimeout))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", authority, authority, payload)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return conn, reader, response.StatusCode
}

func TestCONNECTRestrictions(t *testing.T) {
	var calls atomic.Int32
	p := startHTTP(t, dialFunc(func(context.Context, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected dial")
	}))
	for _, target := range []string{
		"example.org:443", "example.com:443", "evilexample.com:443",
		"app.example.com.example.org:443", "10.1.1.100:443",
		"app.example.com:22", "app.example.com:0443", "app.example.com",
	} {
		t.Run(target, func(t *testing.T) {
			_, _, status := connect(t, p, target, "")
			if status != http.StatusForbidden {
				t.Fatalf("status = %d", status)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("rejected CONNECT reached the dialer")
	}
}

func TestCONNECTBufferedData(t *testing.T) {
	p := startHTTP(t, dialFunc(func(_ context.Context, target string) (net.Conn, error) {
		if target != testTarget {
			t.Errorf("dialed %q", target)
		}
		remote, backend := net.Pipe()
		go func() {
			defer backend.Close()
			io.Copy(backend, backend)
		}()
		return remote, nil
	}))
	const payload = "buffered bytes after CONNECT"
	conn, reader, status := connect(t, p, testHost+":"+config.HTTPSPort, payload)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != payload {
		t.Fatalf("buffered echo = %q, error = %v", got, err)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("shutdown left CONNECT open")
	}
}

func TestCONNECTPreservesTLS(t *testing.T) {
	// The backend observes the browser's hostname inside TLS, including redirects.
	var requests atomic.Int32
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != testHost || r.TLS.ServerName != testHost {
			t.Errorf("host = %q, SNI = %q", r.Host, r.TLS.ServerName)
		}
		if r.URL.Path == "/" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Secure: true})
			http.Redirect(w, r, "https://"+testHost+"/login", http.StatusFound)
			return
		}
		io.Copy(w, r.Body)
	}))
	certificate, roots := testCertificate(t)
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	backend.StartTLS()
	defer backend.Close()
	p := startHTTP(t, dialFunc(func(ctx context.Context, target string) (net.Conn, error) {
		if target != testTarget {
			t.Errorf("dialed %q", target)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
	}))
	proxyURL, _ := url.Parse("http://" + p.listener.Addr().String())
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: testTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Get("https://" + testHost + "/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "https://"+testHost+"/login" {
		t.Fatal("redirect changed")
	}
	if len(response.Cookies()) != 1 || !response.Cookies()[0].Secure {
		t.Fatal("secure cookie changed")
	}

	payload := bytes.Repeat([]byte("stream data\n"), 65536)
	response, err = client.Post("https://"+testHost+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(got, payload) || requests.Load() != 2 {
		t.Fatalf("stream failed: bytes = %d, error = %v", len(got), err)
	}
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{testHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func TestPACRouting(t *testing.T) {
	p := startHTTP(t, dialFunc(func(context.Context, string) (net.Conn, error) {
		t.Error("PAC request started the tunnel")
		return nil, errors.New("unexpected dial")
	}))
	client := &http.Client{Timeout: testTimeout}
	response, err := client.Get("http://" + p.listener.Addr().String() + pacPath)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != pacContentType {
		t.Fatal("PAC response is not usable")
	}
	if strings.Contains(string(body), "dnsResolve") || strings.Contains(string(body), "; DIRECT") {
		t.Fatal("PAC uses DNS or a direct fallback")
	}

	// Execute the actual PAC to catch suffix and JavaScript-generation mistakes.
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to execute PAC routing cases")
	}
	script := string(body) + `
var cases = {
  "app.example.com": true, "APP.EXAMPLE.COM.": true,
  "nested.app.example.com": true, "home.example.net": true,
  "example.com": false, "evilexample.com": false,
  "app.example.com.example.org": false, "example.org": false
};
for (var host in cases) {
  var result = FindProxyForURL("https://" + host + "/", host);
  var expected = cases[host] ? "PROXY " + process.argv[1] : "DIRECT";
  if (result !== expected) { throw new Error(host + ": " + result); }
}
`
	if output, err := exec.Command(node, "-e", script, p.listener.Addr().String()).CombinedOutput(); err != nil {
		t.Fatalf("PAC routing: %v\n%s", err, output)
	}
}

func TestCONNECTDialFailure(t *testing.T) {
	p := startHTTP(t, dialFunc(func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("offline")
	}))
	_, _, status := connect(t, p, testHost+":"+config.HTTPSPort, "")
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d", status)
	}
}

func TestPlainHTTPRejected(t *testing.T) {
	var calls atomic.Int32
	p := startHTTP(t, dialFunc(func(context.Context, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected dial")
	}))
	proxyURL, _ := url.Parse("http://" + p.listener.Addr().String())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: testTimeout}
	for _, destination := range []string{"http://" + testHost + "/", "http://" + testHost + pacPath} {
		response, err := client.Get(destination)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d", response.StatusCode)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("plain HTTP reached the tunnel")
	}
}

func TestStopCancelsDial(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	p := startHTTP(t, dialFunc(func(ctx context.Context, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}))
	conn, err := net.DialTimeout("tcp", p.listener.Addr().String(), testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", testHost, testHost)
	select {
	case <-started:
	case <-time.After(testTimeout):
		t.Fatal("dial did not start")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("shutdown did not cancel dial")
	}
}
