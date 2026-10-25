package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ccakes/wgproxy/internal/config"
)

const (
	pacPath         = "/proxy.pac"
	pacContentType  = "application/x-ns-proxy-autoconfig"
	headerTimeout   = 10 * time.Second
	httpIdleTimeout = time.Minute
	shutdownTimeout = 5 * time.Second
)

// HTTPProxy carries approved HTTPS connections through the tunnel dialer.
type HTTPProxy struct {
	config   *config.HTTPProxy
	dialer   tcpDialer
	logger   *slog.Logger
	listener net.Listener
	server   *http.Server
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	stopped  bool
	wg       sync.WaitGroup
}

func NewHTTPProxy(cfg *config.HTTPProxy, dialer tcpDialer, logger *slog.Logger) *HTTPProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &HTTPProxy{config: cfg, dialer: dialer, logger: logger, ctx: ctx, cancel: cancel}
}

func (p *HTTPProxy) Start() error {
	listener, err := net.Listen("tcp", p.config.Listen)
	if err != nil {
		return err
	}
	p.listener = listener
	p.server = &http.Server{
		Handler:           http.HandlerFunc(p.serve),
		ReadHeaderTimeout: headerTimeout,
		IdleTimeout:       httpIdleTimeout,
	}
	go func() {
		if err := p.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.logger.Error("HTTP proxy failed", "error", err)
		}
	}()
	return nil
}

func (p *HTTPProxy) serve(w http.ResponseWriter, r *http.Request) {
	// Stop prevents new handlers before waiting for hijacked connections.
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		http.Error(w, "proxy stopped", http.StatusServiceUnavailable)
		return
	}
	p.wg.Add(1)
	p.mu.Unlock()
	defer p.wg.Done()

	if r.Method == http.MethodGet && r.URL.Path == pacPath && !r.URL.IsAbs() && r.Host == p.listener.Addr().String() {
		w.Header().Set("Content-Type", pacContentType)
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, p.pac())
		return
	}
	if r.Method != http.MethodConnect {
		w.Header().Set("Allow", http.MethodConnect)
		http.Error(w, "only HTTPS CONNECT is supported", http.StatusMethodNotAllowed)
		return
	}

	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != config.HTTPSPort || !p.config.AllowsHost(host) {
		http.Error(w, "destination denied", http.StatusForbidden)
		return
	}

	// Never resolve or dial a client-supplied address: all names share one ingress.
	ctx, cancel := context.WithTimeout(p.ctx, dialTimeout)
	remote, err := p.dialer.DialTCP(ctx, p.config.Target)
	cancel()
	if err != nil {
		p.logger.Warn("CONNECT failed", "host", host, "error", err)
		http.Error(w, "tunnel unavailable", http.StatusBadGateway)
		return
	}
	defer remote.Close()

	client, buffered, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	// Hijacked connections outlive HTTP handlers; close them on proxy shutdown.
	stop := context.AfterFunc(p.ctx, func() {
		client.Close()
		remote.Close()
	})
	defer stop()
	client.SetDeadline(time.Time{})
	client.SetWriteDeadline(time.Now().Add(headerTimeout))
	fmt.Fprintf(buffered, "HTTP/1.1 %d %s\r\n\r\n", http.StatusOK, http.StatusText(http.StatusOK))
	if err := buffered.Flush(); err != nil {
		return
	}
	client.SetWriteDeadline(time.Time{})

	// Include bytes already buffered after CONNECT, such as an early TLS hello.
	done := make(chan struct{})
	go func() {
		_, err := io.Copy(remote, buffered.Reader)
		finishWrite(remote, err)
		close(done)
	}()
	_, err = io.Copy(client, remote)
	finishWrite(client, err)
	<-done
}

func (p *HTTPProxy) pac() string {
	hosts, _ := json.Marshal(p.config.Hosts)
	proxy, _ := json.Marshal("PROXY " + p.listener.Addr().String())
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
    var hosts = %s;
    host = host.toLowerCase().replace(/\.$/, "");
    for (var i = 0; i < hosts.length; i++) {
        var pattern = hosts[i].toLowerCase();
        var suffix = pattern.substring(1);
        if (host === pattern || (pattern.substring(0, 2) === "*." &&
            host.length > suffix.length && host.slice(-suffix.length) === suffix)) {
            return %s;
        }
    }
    return "DIRECT";
}
`, hosts, proxy)
}

func (p *HTTPProxy) Stop() error {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	p.cancel()
	if p.server != nil {
		p.server.Close()
	}

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(shutdownTimeout):
		return fmt.Errorf("HTTP proxy shutdown timed out")
	}
}
