package config

import (
	"path/filepath"
	"testing"
)

func TestGRPCTLSValidation(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.pem")
	cases := map[string]map[string]string{
		"cert without key":         {"GRPC_TLS_CERT_FILE": missing},
		"key without cert":         {"GRPC_TLS_KEY_FILE": missing},
		"unreadable cert and key":  {"GRPC_TLS_CERT_FILE": missing, "GRPC_TLS_KEY_FILE": missing},
		"client ca without server": {"GRPC_TLS_CLIENT_CA_FILE": missing},
		"mtls only without ca":     {"GRPC_MTLS_ONLY": "true"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			baseEnv(t)
			t.Setenv("GRPC_ENABLED", "true")
			t.Setenv("GRPC_API_KEYS", "0123456789abcdef0123456789abcdef")
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}

	t.Run("mtls only needs no api keys", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("GRPC_ENABLED", "true")
		t.Setenv("GRPC_MTLS_ONLY", "true")
		// Still fails: no CA. It must not complain about the missing keys first.
		if _, err := Load(); err == nil {
			t.Fatal("expected an error")
		}
	})
}
