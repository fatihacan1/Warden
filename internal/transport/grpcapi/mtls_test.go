package grpcapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/observability"
	wardenv1 "github.com/fatihacan1/warden/pkg/api/wardenv1"
)

type pki struct {
	caPEM  []byte
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &pki{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caCert: cert, caKey: key}
}

// issue returns a PEM certificate and key signed by the CA.
func (p *pki) issue(t *testing.T, cn string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

func write(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func startServer(t *testing.T, g config.GRPCConfig, keys []string) string {
	t.Helper()
	tlsCfg, err := g.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	s := New(nil, nil, Options{APIKeys: keys, TLS: tlsCfg, MTLSOnly: g.MTLSOnly}, slog.New(slog.NewTextHandler(io.Discard, nil)), observability.NewMetrics())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.ServeListener(ln) }()
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	return ln.Addr().String()
}

// call performs an RPC that only passes the interceptor when authenticated: a
// malformed id then fails validation (InvalidArgument) without a database.
func call(t *testing.T, addr string, tc *tls.Config, apiKey string) error {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if apiKey != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-api-key", apiKey)
	}
	_, err = wardenv1.NewAuthServiceClient(conn).GetUser(ctx, &wardenv1.GetUserRequest{UserId: "not-a-uuid"})
	return err
}

func clientTLS(t *testing.T, roots *x509.CertPool, signer *pki) *tls.Config {
	cfg := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	if signer != nil {
		c, k := signer.issue(t, "orders-service", x509.ExtKeyUsageClientAuth)
		cert, err := tls.X509KeyPair(c, k)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg
}

func TestMutualTLS(t *testing.T) {
	ca := newCA(t, "warden test ca")
	otherCA := newCA(t, "other ca")
	dir := t.TempDir()
	srvCert, srvKey := ca.issue(t, "localhost", x509.ExtKeyUsageServerAuth)
	addr := startServer(t, config.GRPCConfig{
		Enabled:         true,
		TLSCertFile:     write(t, dir, "server.pem", srvCert),
		TLSKeyFile:      write(t, dir, "server.key", srvKey),
		TLSClientCAFile: write(t, dir, "ca.pem", ca.caPEM),
		MTLSOnly:        true,
	}, nil)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.caPEM)

	if err := call(t, addr, clientTLS(t, roots, ca), ""); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("client with a certificate from the CA should be authenticated, got %v", err)
	}
	if err := call(t, addr, clientTLS(t, roots, nil), ""); err == nil || status.Code(err) == codes.InvalidArgument {
		t.Fatalf("client without a certificate must be refused, got %v", err)
	}
	if err := call(t, addr, clientTLS(t, roots, otherCA), ""); err == nil || status.Code(err) == codes.InvalidArgument {
		t.Fatalf("client with a certificate from another CA must be refused, got %v", err)
	}
	old := clientTLS(t, roots, ca)
	old.MinVersion, old.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if err := call(t, addr, old, ""); err == nil || status.Code(err) == codes.InvalidArgument {
		t.Fatalf("TLS 1.2 must be refused, got %v", err)
	}
}

func TestMutualTLSStillNeedsAPIKey(t *testing.T) {
	ca := newCA(t, "warden test ca")
	dir := t.TempDir()
	srvCert, srvKey := ca.issue(t, "localhost", x509.ExtKeyUsageServerAuth)
	const key = "0123456789abcdef0123456789abcdef"
	addr := startServer(t, config.GRPCConfig{
		TLSCertFile: write(t, dir, "server.pem", srvCert), TLSKeyFile: write(t, dir, "server.key", srvKey),
		TLSClientCAFile: write(t, dir, "ca.pem", ca.caPEM),
	}, []string{key})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.caPEM)
	cfg := clientTLS(t, roots, ca)

	if err := call(t, addr, cfg, ""); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("certificate without API key: %v", err)
	}
	if err := call(t, addr, cfg, key); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("certificate with API key: %v", err)
	}
}

func TestTLSConfigValidation(t *testing.T) {
	ca := newCA(t, "ca")
	dir := t.TempDir()
	cert, key := ca.issue(t, "localhost", x509.ExtKeyUsageServerAuth)
	good := config.GRPCConfig{TLSCertFile: write(t, dir, "c.pem", cert), TLSKeyFile: write(t, dir, "k.pem", key), TLSClientCAFile: write(t, dir, "ca.pem", ca.caPEM)}
	if cfg, err := good.TLSConfig(); err != nil || cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("good config: %v %+v", err, cfg)
	}
	bad := good
	bad.TLSClientCAFile = write(t, dir, "junk.pem", []byte("not pem"))
	if _, err := bad.TLSConfig(); err == nil {
		t.Fatal("junk CA accepted")
	}
	bad = good
	bad.TLSKeyFile = filepath.Join(dir, "missing.key")
	if _, err := bad.TLSConfig(); err == nil {
		t.Fatal("missing key accepted")
	}
}
