package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/transport"
	"github.com/mattn/go-isatty"
)

const transportNotice = "direct-tls keeps the relay certificate pin. Cloud TLS interception is unsupported; cloud transport is unavailable."

func setupTransport(mode, endpoint string, interactive bool, in io.Reader, out io.Writer) (string, error) {
	fmt.Fprintln(out, transportNotice)
	if mode == "" {
		if !interactive {
			return "", fmt.Errorf("select --transport direct-tls explicitly; cloud transport is unavailable")
		}
		fmt.Fprint(out, "Transport for this setup (type direct-tls, or cancel): ")
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("transport selection cancelled")
		}
		mode = strings.TrimSpace(line)
	}
	if mode != transport.DirectTLS {
		if _, err := transport.Resolve(mode, endpoint); err != nil {
			return "", err
		}
		return "", fmt.Errorf("setup cancelled; only direct-tls is supported for new setups")
	}
	_, err := transport.Resolve(mode, endpoint)
	return mode, err
}

// Discovery is not authentication. Only compare with independently supplied trust.
func verifiedRelayFingerprint(endpoint, expected string) (string, error) {
	pin, err := hex.DecodeString(expected)
	if err != nil || len(pin) != 32 {
		return "", fmt.Errorf("provide --fingerprint with the independently verified relay certificate SHA256; discovery alone cannot authenticate a relay")
	}
	fp, err := client.FetchRelayFingerprint(endpoint)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(fp, expected) {
		return "", fmt.Errorf("relay certificate mismatch; refusing setup or repin without changing trust")
	}
	return fp, nil
}

func reviewTransport(cfg *client.Config, interactive bool, in io.Reader, out io.Writer) error {
	mode, err := transport.Resolve(cfg.RelayTransport, cfg.RelayURL)
	if err != nil {
		return err
	}
	endpoint := cfg.DashboardURL
	if endpoint == "" {
		endpoint = client.DefaultDashboardURL
	}
	dashboardMode, err := transport.Resolve(cfg.DashboardTransport, endpoint)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Relay transport: %s (%s)\nDashboard transport: %s (%s)\n%s\n", mode, transport.EndpointLabel(cfg.RelayURL), dashboardMode, transport.EndpointLabel(endpoint), transportNotice)
	if !interactive || cfg.TransportReviewed {
		return nil
	}
	fmt.Fprint(out, "Keep the current transport settings for upgrades? (type keep, or cancel): ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "keep" {
		return fmt.Errorf("upgrade cancelled; transport settings unchanged")
	}
	return cfg.AcknowledgeTransport()
}

// Updating the executable remains possible even when identity manifests are bad.
func reviewUpgradeTransport() error {
	cfg, err := upgradeTransportConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Transport review unavailable; identity state unchanged.")
		return nil
	}
	return reviewTransport(cfg, isatty.IsTerminal(os.Stdin.Fd()), os.Stdin, os.Stderr)
}

func upgradeTransportConfig() (*client.Config, error) {
	ctx, err := client.LegacyContext().ActiveContext()
	if err != nil {
		return nil, err
	}
	return ctx.LoadTransportConfig()
}
