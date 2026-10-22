// Package secretbox provides authenticated encryption for secrets stored at
// rest: signing keys, TOTP seeds, provider credentials, webhook secrets and
// queued emails.
//
// Every ciphertext is bound to an "associated data" label (for example
// "totp:<user-id>"), so a ciphertext copied into another row or column fails to
// decrypt instead of silently being accepted.
//
// A Box holds one current key, used for every new ciphertext, and any number
// of previous keys that are only used to decrypt. Ciphertexts record which key
// and algorithm sealed them, so keys can be rotated without downtime and old
// data re-encrypted later (warden reencrypt).
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Algorithm selects the AEAD used for new ciphertexts.
type Algorithm byte

const (
	// AES256GCM is the default: hardware accelerated on every modern CPU.
	AES256GCM Algorithm = 1
	// XChaCha20Poly1305 is constant time without AES instructions and has
	// 192-bit nonces, so random nonces never realistically collide.
	XChaCha20Poly1305 Algorithm = 2
)

// String returns the configuration name of the algorithm.
func (a Algorithm) String() string {
	switch a {
	case AES256GCM:
		return "aes-256-gcm"
	case XChaCha20Poly1305:
		return "xchacha20-poly1305"
	}
	return fmt.Sprintf("unknown(%d)", byte(a))
}

// ParseAlgorithm accepts the names used in ENCRYPTION_ALGORITHM.
func ParseAlgorithm(name string) (Algorithm, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "aes-256-gcm", "aes256gcm", "aes":
		return AES256GCM, nil
	case "xchacha20-poly1305", "xchacha20poly1305", "xchacha":
		return XChaCha20Poly1305, nil
	}
	return 0, fmt.Errorf("secretbox: unknown algorithm %q (use aes-256-gcm or xchacha20-poly1305)", name)
}

// Ciphertext layouts.
//
//	v1: 0x01 | nonce(12) | ciphertext+tag                     AES-256-GCM, no key id (legacy)
//	v2: 0x02 | alg(1) | key id(4) | nonce | ciphertext+tag     the header is authenticated too
const (
	versionLegacy byte = 1
	version       byte = 2
	keyIDLen           = 4
	headerLen          = 2 + keyIDLen
)

// ErrDecrypt is returned for tampered, truncated or mislabeled ciphertexts,
// and for ciphertexts sealed with a key this Box does not have.
var ErrDecrypt = errors.New("secretbox: decryption failed")

type key struct {
	id  [keyIDLen]byte
	raw []byte
	gcm cipher.AEAD
	xcp cipher.AEAD
}

func (k *key) aead(a Algorithm) cipher.AEAD {
	if a == XChaCha20Poly1305 {
		return k.xcp
	}
	return k.gcm
}

// Box encrypts and decrypts small payloads.
type Box struct {
	alg      Algorithm
	current  *key
	previous []*key
}

// New creates a Box with a single 32 byte AES-256-GCM key.
func New(k []byte) (*Box, error) { return NewKeyring(AES256GCM, k) }

// NewKeyring creates a Box that seals with current using alg and can still
// open data sealed with any of the previous keys.
func NewKeyring(alg Algorithm, current []byte, previous ...[]byte) (*Box, error) {
	if alg != AES256GCM && alg != XChaCha20Poly1305 {
		return nil, fmt.Errorf("secretbox: unsupported algorithm %d", alg)
	}
	cur, err := newKey(current)
	if err != nil {
		return nil, err
	}
	b := &Box{alg: alg, current: cur}
	for _, p := range previous {
		k, err := newKey(p)
		if err != nil {
			return nil, fmt.Errorf("secretbox: previous key: %w", err)
		}
		if k.id != cur.id {
			b.previous = append(b.previous, k)
		}
	}
	return b, nil
}

func newKey(raw []byte) (*key, error) {
	if len(raw) != 32 {
		return nil, errors.New("secretbox: key must be 32 bytes")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	xcp, err := chacha20poly1305.NewX(raw)
	if err != nil {
		return nil, err
	}
	k := &key{raw: append([]byte(nil), raw...), gcm: gcm, xcp: xcp}
	k.id = KeyID(raw)
	return k, nil
}

// KeyID is the public 4 byte identifier stored in each ciphertext. It is a
// hash prefix and reveals nothing useful about the key.
func KeyID(raw []byte) [keyIDLen]byte {
	sum := sha256.Sum256(append([]byte("warden-secretbox-key-id:"), raw...))
	var id [keyIDLen]byte
	copy(id[:], sum[:keyIDLen])
	return id
}

// Algorithm reports the algorithm used for new ciphertexts.
func (b *Box) Algorithm() Algorithm { return b.alg }

// Seal encrypts plaintext with the current key.
func (b *Box) Seal(plaintext []byte, label string) ([]byte, error) {
	aead := b.current.aead(b.alg)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, headerLen+len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, version, byte(b.alg))
	out = append(out, b.current.id[:]...)
	header := out[:headerLen:headerLen]
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, additional(header, label)), nil
}

// Open decrypts a ciphertext produced by Seal with the same label.
func (b *Box) Open(ciphertext []byte, label string) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, ErrDecrypt
	}
	switch ciphertext[0] {
	case versionLegacy:
		return b.openLegacy(ciphertext, label)
	case version:
	default:
		return nil, ErrDecrypt
	}
	if len(ciphertext) < headerLen {
		return nil, ErrDecrypt
	}
	alg := Algorithm(ciphertext[1])
	if alg != AES256GCM && alg != XChaCha20Poly1305 {
		return nil, ErrDecrypt
	}
	k := b.lookup(ciphertext[2:headerLen])
	if k == nil {
		return nil, ErrDecrypt
	}
	aead := k.aead(alg)
	ns := aead.NonceSize()
	if len(ciphertext) < headerLen+ns+aead.Overhead() {
		return nil, ErrDecrypt
	}
	nonce := ciphertext[headerLen : headerLen+ns]
	pt, err := aead.Open(nil, nonce, ciphertext[headerLen+ns:], additional(ciphertext[:headerLen], label))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// openLegacy reads the original format, which has no key id: every key is
// tried, current first.
func (b *Box) openLegacy(ciphertext []byte, label string) ([]byte, error) {
	for _, k := range b.keys() {
		ns := k.gcm.NonceSize()
		if len(ciphertext) < 1+ns+k.gcm.Overhead() {
			return nil, ErrDecrypt
		}
		if pt, err := k.gcm.Open(nil, ciphertext[1:1+ns], ciphertext[1+ns:], []byte(label)); err == nil {
			return pt, nil
		}
	}
	return nil, ErrDecrypt
}

// Current reports whether ciphertext is already sealed with the current key
// and algorithm, i.e. re-encrypting it would change nothing.
func (b *Box) Current(ciphertext []byte) bool {
	return len(ciphertext) >= headerLen && ciphertext[0] == version &&
		Algorithm(ciphertext[1]) == b.alg && string(ciphertext[2:headerLen]) == string(b.current.id[:])
}

// Reseal decrypts ciphertext with whichever key sealed it and encrypts it
// again with the current key. It is a no-op for current ciphertexts.
func (b *Box) Reseal(ciphertext []byte, label string) ([]byte, bool, error) {
	if b.Current(ciphertext) {
		return ciphertext, false, nil
	}
	pt, err := b.Open(ciphertext, label)
	if err != nil {
		return nil, false, err
	}
	out, err := b.Seal(pt, label)
	return out, err == nil, err
}

func (b *Box) keys() []*key { return append([]*key{b.current}, b.previous...) }

func (b *Box) lookup(id []byte) *key {
	for _, k := range b.keys() {
		if string(k.id[:]) == string(id) {
			return k
		}
	}
	return nil
}

func additional(header []byte, label string) []byte {
	ad := make([]byte, 0, len(header)+len(label))
	ad = append(ad, header...)
	return append(ad, label...)
}
