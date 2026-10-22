// Package secretbox provides authenticated encryption (AES-256-GCM) for
// secrets stored at rest: signing keys, TOTP seeds, provider credentials.
//
// Every ciphertext is bound to an "associated data" label (for example
// "totp:<user-id>"), so a ciphertext copied into another row or column fails to
// decrypt instead of silently being accepted.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const version byte = 1

// ErrDecrypt is returned for tampered, truncated or mislabeled ciphertexts.
var ErrDecrypt = errors.New("secretbox: decryption failed")

// Box encrypts and decrypts small payloads with a single 256-bit key.
type Box struct {
	aead cipher.AEAD
}

// New creates a Box from a 32 byte key.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("secretbox: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext. Output layout: version(1) | nonce(12) | ciphertext+tag.
func (b *Box) Seal(plaintext []byte, label string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+b.aead.Overhead())
	out = append(out, version)
	out = append(out, nonce...)
	return b.aead.Seal(out, nonce, plaintext, []byte(label)), nil
}

// Open decrypts a ciphertext produced by Seal with the same label.
func (b *Box) Open(ciphertext []byte, label string) ([]byte, error) {
	ns := b.aead.NonceSize()
	if len(ciphertext) < 1+ns+b.aead.Overhead() || ciphertext[0] != version {
		return nil, ErrDecrypt
	}
	nonce := ciphertext[1 : 1+ns]
	pt, err := b.aead.Open(nil, nonce, ciphertext[1+ns:], []byte(label))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
