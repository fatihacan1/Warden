package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/store"
)

// KeyStore is the persistence needed by KeyManager.
type KeyStore interface {
	ListSigningKeys(ctx context.Context, since time.Time) ([]store.SigningKeyRow, error)
	RotateSigningKey(ctx context.Context, k store.SigningKeyRow) error
	DeleteRetiredKeys(ctx context.Context, before time.Time) error
	TryAdvisoryLock(ctx context.Context, key int64, fn func(context.Context) error) (bool, error)
}

type signingKey struct {
	kid       string
	private   *ecdsa.PrivateKey
	createdAt time.Time
}

type keyState struct {
	active *signingKey
	public map[string]*ecdsa.PublicKey
	jwks   []byte
}

// KeyManager keeps the signing keys in memory and in sync with the database.
// Every replica reloads periodically, so a rotation performed by one replica
// (or from the admin UI) propagates within the reload interval.
type KeyManager struct {
	store            KeyStore
	box              *secretbox.Box
	rotationInterval time.Duration
	// publishGrace keeps retired public keys in the JWKS so tokens signed just
	// before a rotation remain verifiable until they expire.
	publishGrace time.Duration
	log          *slog.Logger
	state        atomic.Pointer[keyState]
}

func NewKeyManager(st KeyStore, box *secretbox.Box, rotationInterval, accessTTL time.Duration, log *slog.Logger) *KeyManager {
	return &KeyManager{
		store:            st,
		box:              box,
		rotationInterval: rotationInterval,
		publishGrace:     accessTTL + 10*time.Minute,
		log:              log,
	}
}

// Init loads keys and creates the first key if none exists.
func (m *KeyManager) Init(ctx context.Context) error {
	if err := m.Reload(ctx); err != nil {
		return err
	}
	if m.active() != nil {
		return nil
	}
	if _, err := m.store.TryAdvisoryLock(ctx, store.LockKeyRotation, func(ctx context.Context) error {
		if err := m.Reload(ctx); err != nil || m.active() != nil {
			return err
		}
		m.log.Info("no signing key found, generating one")
		return m.rotateLocked(ctx)
	}); err != nil {
		return err
	}
	// Another replica may hold the lock while generating; wait for it briefly.
	for range 20 {
		if err := m.Reload(ctx); err != nil {
			return err
		}
		if m.active() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("token: no active signing key after initialization")
}

// Rotate generates a new active key. Old keys stay published for the grace
// period.
func (m *KeyManager) Rotate(ctx context.Context) error {
	ok, err := m.store.TryAdvisoryLock(ctx, store.LockKeyRotation, m.rotateLocked)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("token: another rotation is in progress")
	}
	return nil
}

func (m *KeyManager) rotateLocked(ctx context.Context) error {
	row, err := m.generate()
	if err != nil {
		return err
	}
	if err := m.store.RotateSigningKey(ctx, row); err != nil {
		return fmt.Errorf("token: store key: %w", err)
	}
	m.log.Info("signing key rotated", "kid", row.KID)
	return m.Reload(ctx)
}

// Reload refreshes the in-memory key state from the database.
func (m *KeyManager) Reload(ctx context.Context) error {
	rows, err := m.store.ListSigningKeys(ctx, time.Now().Add(-m.publishGrace))
	if err != nil {
		return fmt.Errorf("token: load keys: %w", err)
	}
	st := &keyState{public: make(map[string]*ecdsa.PublicKey, len(rows))}
	jwks := struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: []json.RawMessage{}}
	for _, r := range rows {
		der, err := m.box.Open(r.PrivateKey, "signing-key:"+r.KID)
		if err != nil {
			return fmt.Errorf("token: decrypt key %s (was ENCRYPTION_KEY changed?): %w", r.KID, err)
		}
		priv, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return fmt.Errorf("token: parse key %s: %w", r.KID, err)
		}
		st.public[r.KID] = &priv.PublicKey
		jwks.Keys = append(jwks.Keys, r.PublicJWK)
		if r.RetiredAt == nil {
			st.active = &signingKey{kid: r.KID, private: priv, createdAt: r.CreatedAt}
		}
	}
	st.jwks, err = json.Marshal(jwks)
	if err != nil {
		return err
	}
	m.state.Store(st)
	return nil
}

// Run reloads keys and performs scheduled rotation until ctx is cancelled.
func (m *KeyManager) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := m.Reload(ctx); err != nil {
			m.log.Error("signing key reload failed", "err", err)
			continue
		}
		if m.rotationInterval > 0 {
			if a := m.active(); a != nil && time.Since(a.createdAt) > m.rotationInterval {
				if _, err := m.store.TryAdvisoryLock(ctx, store.LockKeyRotation, func(ctx context.Context) error {
					if err := m.Reload(ctx); err != nil {
						return err
					}
					if a := m.active(); a != nil && time.Since(a.createdAt) <= m.rotationInterval {
						return nil // another replica already rotated
					}
					return m.rotateLocked(ctx)
				}); err != nil {
					m.log.Error("scheduled key rotation failed", "err", err)
				}
			}
		}
		if err := m.store.DeleteRetiredKeys(ctx, time.Now().Add(-m.publishGrace-24*time.Hour)); err != nil {
			m.log.Warn("delete retired keys failed", "err", err)
		}
	}
}

// JWKS returns the JSON Web Key Set document.
func (m *KeyManager) JWKS() []byte {
	if st := m.state.Load(); st != nil {
		return st.jwks
	}
	return []byte(`{"keys":[]}`)
}

// ActiveKID returns the id of the current signing key ("" if none).
func (m *KeyManager) ActiveKID() string {
	if a := m.active(); a != nil {
		return a.kid
	}
	return ""
}

// ActiveSince returns when the current signing key was created.
func (m *KeyManager) ActiveSince() time.Time {
	if a := m.active(); a != nil {
		return a.createdAt
	}
	return time.Time{}
}

func (m *KeyManager) active() *signingKey {
	if st := m.state.Load(); st != nil {
		return st.active
	}
	return nil
}

func (m *KeyManager) publicKey(kid string) *ecdsa.PublicKey {
	if st := m.state.Load(); st != nil {
		return st.public[kid]
	}
	return nil
}

func (m *KeyManager) generate() (store.SigningKeyRow, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return store.SigningKeyRow{}, err
	}
	jwk, kid, err := publicJWK(&priv.PublicKey)
	if err != nil {
		return store.SigningKeyRow{}, err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return store.SigningKeyRow{}, err
	}
	sealed, err := m.box.Seal(der, "signing-key:"+kid)
	if err != nil {
		return store.SigningKeyRow{}, err
	}
	return store.SigningKeyRow{KID: kid, Algorithm: "ES256", PrivateKey: sealed, PublicJWK: jwk}, nil
}

// publicJWK renders the key as a JWK and derives its kid from the RFC 7638
// thumbprint.
func publicJWK(pub *ecdsa.PublicKey) (json.RawMessage, string, error) {
	ecdh, err := pub.ECDH()
	if err != nil {
		return nil, "", err
	}
	raw := ecdh.Bytes() // 0x04 || X || Y
	b64 := base64.RawURLEncoding
	x, y := b64.EncodeToString(raw[1:33]), b64.EncodeToString(raw[33:65])
	thumb := sha256.Sum256(fmt.Appendf(nil, `{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y))
	kid := b64.EncodeToString(thumb[:])
	jwk, err := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "use": "sig", "alg": "ES256",
	})
	return jwk, kid, err
}
