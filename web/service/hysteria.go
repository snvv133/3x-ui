// Package service contains the Hysteria2 inbound service.
//
// Hysteria2 is NOT an Xray protocol. It is managed as an external systemd unit
// (hysteria-server.service) reading /etc/hysteria/config.yaml. This service is
// responsible for serializing a Hysteria2 inbound's settings into that YAML
// file and restarting the unit.
package service

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

const (
	hysteriaConfigPath  = "/etc/hysteria/config.yaml"
	hysteriaCertDir     = "/etc/hysteria/cert"
	hysteriaServiceUnit = "hysteria-server.service"
)

// Hysteria2Settings is the JSON shape stored in Inbound.Settings for a
// hysteria2 inbound. Only fields the user can configure live here.
type Hysteria2Settings struct {
	Password               string `json:"password"`
	ObfsPassword           string `json:"obfsPassword,omitempty"`
	MasqueradeURL          string `json:"masqueradeUrl,omitempty"`
	UpMbps                 int    `json:"upMbps,omitempty"`
	DownMbps               int    `json:"downMbps,omitempty"`
	IgnoreClientBandwidth  bool   `json:"ignoreClientBandwidth,omitempty"`
	PortHoppingRange       string `json:"portHoppingRange,omitempty"` // e.g. "20000-50000"
	OutboundSocks5         string `json:"outboundSocks5,omitempty"`   // e.g. "127.0.0.1:1080"
	OutboundSocks5RouteAll bool   `json:"outboundSocks5RouteAll,omitempty"`
	// SubID, if non-empty, makes this inbound show up in /sub/{subId} responses.
	SubID string `json:"subId,omitempty"`
}

// ParseHysteria2Settings is the public helper used by the subscription service
// to read the same shape that HysteriaService writes.
func ParseHysteria2Settings(raw string) (*Hysteria2Settings, error) {
	return (&HysteriaService{}).parseSettings(raw)
}

// HysteriaService applies an Inbound of protocol hysteria2 to the system.
type HysteriaService struct{}

// Apply renders the inbound to /etc/hysteria/config.yaml and restarts the
// hysteria-server systemd unit. If the inbound is disabled, the service is
// stopped instead.
func (s *HysteriaService) Apply(inbound *model.Inbound) error {
	if inbound == nil || inbound.Protocol != model.Hysteria2 {
		return fmt.Errorf("hysteria.Apply: inbound is nil or not hysteria2")
	}
	if !inbound.Enable {
		return s.stop()
	}

	cfg, err := s.parseSettings(inbound.Settings)
	if err != nil {
		return fmt.Errorf("hysteria: parse settings: %w", err)
	}
	if cfg.Password == "" {
		return fmt.Errorf("hysteria: password is required")
	}
	if inbound.Port <= 0 || inbound.Port > 65535 {
		return fmt.Errorf("hysteria: invalid port %d", inbound.Port)
	}

	if err := s.ensureSelfSignedCert(); err != nil {
		return fmt.Errorf("hysteria: ensure cert: %w", err)
	}

	yaml := s.renderYAML(inbound.Port, cfg)
	if err := s.atomicWrite(hysteriaConfigPath, []byte(yaml)); err != nil {
		return fmt.Errorf("hysteria: write config: %w", err)
	}

	return s.restart()
}

// Stop disables/stops the hysteria-server unit.
func (s *HysteriaService) Stop() error { return s.stop() }

func (s *HysteriaService) parseSettings(raw string) (*Hysteria2Settings, error) {
	cfg := &Hysteria2Settings{}
	if strings.TrimSpace(raw) == "" {
		return cfg, nil
	}
	if err := json.Unmarshal([]byte(raw), cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (s *HysteriaService) renderYAML(port int, cfg *Hysteria2Settings) string {
	var b strings.Builder
	fmt.Fprintf(&b, "listen: :%d\n", port)

	fmt.Fprintf(&b, "\ntls:\n  cert: %s/fullchain.pem\n  key: %s/privkey.pem\n",
		hysteriaCertDir, hysteriaCertDir)

	fmt.Fprintf(&b, "\nauth:\n  type: password\n  password: %q\n", cfg.Password)

	masq := cfg.MasqueradeURL
	if masq == "" {
		masq = "https://www.bing.com"
	}
	fmt.Fprintf(&b, "\nmasquerade:\n  type: proxy\n  proxy:\n    url: %q\n    rewriteHost: true\n", masq)

	if cfg.UpMbps > 0 || cfg.DownMbps > 0 {
		up := cfg.UpMbps
		if up == 0 {
			up = 500
		}
		down := cfg.DownMbps
		if down == 0 {
			down = 500
		}
		fmt.Fprintf(&b, "\nbandwidth:\n  up: %d mbps\n  down: %d mbps\n", up, down)
	}

	fmt.Fprintf(&b, "\nignoreClientBandwidth: %t\n", cfg.IgnoreClientBandwidth)

	if cfg.ObfsPassword != "" {
		fmt.Fprintf(&b, "\nobfs:\n  type: salamander\n  salamander:\n    password: %q\n", cfg.ObfsPassword)
	}

	if cfg.OutboundSocks5 != "" {
		fmt.Fprintf(&b, "\noutbounds:\n  - name: socks_out\n    type: socks5\n    socks5:\n      addr: %q\n",
			cfg.OutboundSocks5)
		if cfg.OutboundSocks5RouteAll {
			fmt.Fprintf(&b, "\nacl:\n  inline:\n    - socks_out(all)\n")
		}
	}

	return b.String()
}

func (s *HysteriaService) ensureSelfSignedCert() error {
	cert := filepath.Join(hysteriaCertDir, "fullchain.pem")
	key := filepath.Join(hysteriaCertDir, "privkey.pem")
	if _, err := os.Stat(cert); err == nil {
		if _, err := os.Stat(key); err == nil {
			return nil
		}
	}
	if err := os.MkdirAll(hysteriaCertDir, 0o700); err != nil {
		return err
	}
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", key, "-out", cert, "-days", "3650", "-subj", "/CN=hysteria")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("openssl: %v: %s", err, string(out))
	}
	return nil
}

func (s *HysteriaService) atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	// World-readable: hysteria-server.service runs as a dedicated `hysteria`
	// user that needs to read this file. 0o600 would lock it to root and
	// the unit fails with "permission denied".
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *HysteriaService) restart() error {
	out, err := exec.Command("systemctl", "restart", hysteriaServiceUnit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart: %v: %s", err, string(out))
	}
	return nil
}

func (s *HysteriaService) stop() error {
	out, err := exec.Command("systemctl", "stop", hysteriaServiceUnit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop: %v: %s", err, string(out))
	}
	return nil
}
