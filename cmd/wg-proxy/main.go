// wg-proxy is a userspace WireGuard client that exposes remote services on localhost.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ccakes/wgproxy/internal/config"
	"github.com/ccakes/wgproxy/internal/metrics"
	"github.com/ccakes/wgproxy/internal/proxy"
	"github.com/ccakes/wgproxy/internal/tunnel"

	"golang.org/x/crypto/curve25519"
)

const (
	defaultConfigPath = "$HOME/.config/wg-proxy/config.yaml"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "generate-key":
			generateKey()
			return
		case "generate-config":
			generateConfig()
			return
		case "help", "-h", "--help":
			printHelp()
			return
		}
	}

	// Main command flags
	var (
		configPath  string
		profileName string
	)

	flag.StringVar(&configPath, "config", defaultConfigPath, "path to configuration file")
	flag.StringVar(&profileName, "profile", "", "profile name to use (required)")
	flag.Parse()

	if profileName == "" {
		fmt.Fprintln(os.Stderr, "error: --profile is required")
		fmt.Fprintln(os.Stderr, "usage: wg-proxy --profile <name> [--config <path>]")
		os.Exit(1)
	}

	// Expand config path
	if configPath == defaultConfigPath {
		home, _ := os.UserHomeDir()
		configPath = home + "/.config/wg-proxy/config.yaml"
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	// Get profile
	profile, err := cfg.GetProfile(profileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Setup logger
	logLevel := slog.LevelInfo
	switch profile.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	logger.Info("starting wg-proxy",
		"profile", profileName,
		"server", profile.Server,
	)

	// Run the proxy
	if err := run(profile, logger); err != nil {
		logger.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run(profile *config.Profile, logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Start metrics server if configured
	var metricsCollector *metrics.Collector
	var metricsServer *metrics.Server
	if profile.Metrics != "" {
		metricsCollector = metrics.NewCollector()
		metricsServer = metrics.NewServer(profile.Metrics, metricsCollector)
		if err := metricsServer.Start(); err != nil {
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
		logger.Info("metrics server started", "addr", profile.Metrics)
		defer metricsServer.Stop()
	}

	// Start pprof server if configured
	if profile.PProf != "" {
		go func() {
			logger.Info("pprof server started", "addr", profile.PProf)
			if err := http.ListenAndServe(profile.PProf, nil); err != nil {
				logger.Error("pprof server error", "error", err)
			}
		}()
	}

	// Create tunnel manager
	tunnelManager := tunnel.NewManager(profile, logger)
	defer tunnelManager.Close()

	// Browser traffic keeps its HTTPS name while the tunnel dials the ingress.
	if profile.HTTPProxy != nil {
		p := proxy.NewHTTPProxy(profile.HTTPProxy, tunnelManager, logger)
		if err := p.Start(); err != nil {
			return fmt.Errorf("failed to start HTTP proxy: %w", err)
		}
		defer p.Stop()
		logger.Info("HTTP proxy started", "listen", profile.HTTPProxy.Listen,
			"pac", "http://"+profile.HTTPProxy.Listen+"/proxy.pac")
	}

	// Parse forwarding rules
	tcpRules, err := profile.GetTCPRules()
	if err != nil {
		return fmt.Errorf("failed to parse TCP rules: %w", err)
	}

	udpRules, err := profile.GetUDPRules()
	if err != nil {
		return fmt.Errorf("failed to parse UDP rules: %w", err)
	}

	// Start TCP proxies
	var tcpProxies []*proxy.TCPProxy
	for _, rule := range tcpRules {
		p := proxy.NewTCPProxy(rule, tunnelManager, logger, metricsCollector)
		if err := p.Start(); err != nil {
			return fmt.Errorf("failed to start TCP proxy %s: %w", rule.LocalEndpoint(), err)
		}
		tcpProxies = append(tcpProxies, p)
		logger.Info("TCP proxy started",
			"local", rule.LocalEndpoint(),
			"remote", rule.RemoteEndpoint(),
		)
	}

	// Start UDP proxies
	var udpProxies []*proxy.UDPProxy
	for _, rule := range udpRules {
		p := proxy.NewUDPProxy(rule, tunnelManager, logger, metricsCollector)
		if err := p.Start(); err != nil {
			return fmt.Errorf("failed to start UDP proxy %s: %w", rule.LocalEndpoint(), err)
		}
		udpProxies = append(udpProxies, p)
		logger.Info("UDP proxy started",
			"local", rule.LocalEndpoint(),
			"remote", rule.RemoteEndpoint(),
		)
	}

	logger.Info("wg-proxy ready", "tcp_proxies", len(tcpProxies), "udp_proxies", len(udpProxies))

	// Wait for shutdown signal
	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				logger.Info("received SIGHUP (reload not implemented)")
				continue
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("shutting down", "signal", sig)
				goto shutdown
			}
		case <-ctx.Done():
			goto shutdown
		}
	}

shutdown:
	// Stop proxies
	logger.Info("stopping proxies")

	for _, p := range tcpProxies {
		p.Stop()
	}
	for _, p := range udpProxies {
		p.Stop()
	}

	// Give everything time to clean up
	time.Sleep(100 * time.Millisecond)

	logger.Info("shutdown complete")
	return nil
}

func generateKey() {
	// Generate private key
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		fmt.Fprintf(os.Stderr, "error generating key: %v\n", err)
		os.Exit(1)
	}

	// Clamp private key for curve25519
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	fmt.Println("Private Key:", base64.StdEncoding.EncodeToString(privateKey[:]))
	fmt.Println("Public Key:", base64.StdEncoding.EncodeToString(publicKey[:]))
}

func generateConfig() {
	sample := config.GenerateSampleConfig()

	// Check if config.yaml already exists
	if _, err := os.Stat("config.yaml"); err == nil {
		fmt.Fprintln(os.Stderr, "error: config.yaml already exists")
		os.Exit(1)
	}

	if err := os.WriteFile("config.yaml", []byte(sample), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Generated config.yaml")
}

func printHelp() {
	fmt.Println(`wg-proxy - Userspace WireGuard port proxy

Usage:
  wg-proxy --profile <name> [--config <path>]
  wg-proxy generate-key
  wg-proxy generate-config

Commands:
  generate-key     Generate a new WireGuard private/public keypair
  generate-config  Write a sample config.yaml to the current directory

Options:
  --profile <name>  Profile name to use (required for main command)
  --config <path>   Path to configuration file
                    (default: $HOME/.config/wg-proxy/config.yaml)

Examples:
  # Start proxy with a profile
  wg-proxy --profile production --config ~/.wg-proxy/config.yaml

  # Generate a new keypair
  wg-proxy generate-key

  # Create a sample configuration file
  wg-proxy generate-config`)
}
