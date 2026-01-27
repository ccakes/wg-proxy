// Package metrics provides Prometheus metrics collection for wg-proxy.
package metrics

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector holds all the Prometheus metrics for wg-proxy.
type Collector struct {
	ConnectionsTotal  *prometheus.CounterVec
	ActiveConnections *prometheus.GaugeVec
	BytesTransferred  *prometheus.CounterVec

	registry *prometheus.Registry
}

// NewCollector creates a new metrics collector.
func NewCollector() *Collector {
	c := &Collector{
		ConnectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "wg_proxy_connections_total",
				Help: "Total number of connections handled",
			},
			[]string{"protocol", "local_port", "remote_addr"},
		),
		ActiveConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "wg_proxy_active_connections",
				Help: "Number of currently active connections",
			},
			[]string{"protocol", "local_port", "remote_addr"},
		),
		BytesTransferred: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "wg_proxy_bytes_transferred_total",
				Help: "Total bytes transferred",
			},
			[]string{"protocol", "local_port", "remote_addr", "direction"},
		),
		registry: prometheus.NewRegistry(),
	}

	// Register all metrics
	c.registry.MustRegister(c.ConnectionsTotal)
	c.registry.MustRegister(c.ActiveConnections)
	c.registry.MustRegister(c.BytesTransferred)

	return c
}

// Handler returns an HTTP handler for the /metrics endpoint.
func (c *Collector) Handler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// Server manages the metrics HTTP server.
type Server struct {
	addr      string
	collector *Collector
	server    *http.Server
}

// NewServer creates a new metrics server.
func NewServer(addr string, collector *Collector) *Server {
	return &Server{
		addr:      addr,
		collector: collector,
	}
}

// Start starts the metrics HTTP server.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Metrics endpoint
	mux.Handle("/metrics", s.collector.Handler())

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go s.server.ListenAndServe()
	return nil
}

// Stop stops the metrics HTTP server.
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// Addr returns the address the server is listening on.
func (s *Server) Addr() string {
	return s.addr
}
