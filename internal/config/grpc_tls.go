package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLSEnabled reports whether the gRPC port serves TLS.
func (g GRPCConfig) TLSEnabled() bool { return g.TLSCertFile != "" && g.TLSKeyFile != "" }

// TLSConfig builds the server TLS configuration: TLS 1.3 only and, when a
// client CA is configured, required and verified client certificates. It
// returns nil when TLS is not configured.
func (g GRPCConfig) TLSConfig() (*tls.Config, error) {
	if !g.TLSEnabled() {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(g.TLSCertFile, g.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("GRPC_TLS_CERT_FILE / GRPC_TLS_KEY_FILE: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if g.TLSClientCAFile != "" {
		pem, err := os.ReadFile(g.TLSClientCAFile) // #nosec G304 -- path chosen by the operator
		if err != nil {
			return nil, fmt.Errorf("GRPC_TLS_CLIENT_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("GRPC_TLS_CLIENT_CA_FILE: no PEM certificate found")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func (c *Config) validateGRPCTLS(add func(string, ...any)) {
	g := c.GRPC
	if (g.TLSCertFile == "") != (g.TLSKeyFile == "") {
		add("GRPC_TLS_CERT_FILE and GRPC_TLS_KEY_FILE must be set together")
		return
	}
	if g.TLSClientCAFile != "" && !g.TLSEnabled() {
		add("GRPC_TLS_CLIENT_CA_FILE requires GRPC_TLS_CERT_FILE and GRPC_TLS_KEY_FILE")
		return
	}
	if g.MTLSOnly && g.TLSClientCAFile == "" {
		add("GRPC_MTLS_ONLY=true requires GRPC_TLS_CLIENT_CA_FILE")
		return
	}
	if _, err := g.TLSConfig(); err != nil {
		add("%v", err)
	}
}
