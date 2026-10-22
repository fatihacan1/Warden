package secretbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
)

func newBox(t *testing.T) *Box {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	b, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	b := newBox(t)
	ct, err := b.Seal([]byte("hunter2"), "totp:1")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := b.Open(ct, "totp:1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("hunter2")) {
		t.Fatalf("got %q", pt)
	}
}

func TestNonceIsRandom(t *testing.T) {
	b := newBox(t)
	a, _ := b.Seal([]byte("same"), "l")
	c, _ := b.Seal([]byte("same"), "l")
	if bytes.Equal(a, c) {
		t.Fatal("two encryptions of the same plaintext must differ")
	}
}

func TestRejectsWrongLabel(t *testing.T) {
	b := newBox(t)
	ct, _ := b.Seal([]byte("secret"), "totp:user-a")
	if _, err := b.Open(ct, "totp:user-b"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

func TestRejectsTampering(t *testing.T) {
	b := newBox(t)
	ct, _ := b.Seal([]byte("secret"), "l")
	for i := range ct {
		mut := bytes.Clone(ct)
		mut[i] ^= 0x01
		if _, err := b.Open(mut, "l"); err == nil {
			t.Fatalf("tampering at byte %d was not detected", i)
		}
	}
	if _, err := b.Open(ct[:5], "l"); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
}

func TestRejectsOtherKey(t *testing.T) {
	ct, _ := newBox(t).Seal([]byte("secret"), "l")
	if _, err := newBox(t).Open(ct, "l"); err == nil {
		t.Fatal("ciphertext opened with a different key")
	}
}

func TestKeyLength(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("expected error for short key")
	}
}

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestXChaCha20RoundTrip(t *testing.T) {
	b, err := NewKeyring(XChaCha20Poly1305, randKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := b.Seal([]byte("secret"), "l")
	if Algorithm(ct[1]) != XChaCha20Poly1305 {
		t.Fatalf("sealed with %v", Algorithm(ct[1]))
	}
	pt, err := b.Open(ct, "l")
	if err != nil || string(pt) != "secret" {
		t.Fatalf("got %q, %v", pt, err)
	}
}

func TestRotationKeepsOldDataReadable(t *testing.T) {
	oldKey, newKey := randKey(t), randKey(t)
	old, _ := New(oldKey)
	ct, _ := old.Seal([]byte("secret"), "l")

	rotated, err := NewKeyring(XChaCha20Poly1305, newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := rotated.Open(ct, "l"); err != nil || string(pt) != "secret" {
		t.Fatalf("old ciphertext unreadable after rotation: %v", err)
	}
	if rotated.Current(ct) {
		t.Fatal("old ciphertext reported as current")
	}
	resealed, changed, err := rotated.Reseal(ct, "l")
	if err != nil || !changed || !rotated.Current(resealed) {
		t.Fatalf("reseal: changed=%v err=%v", changed, err)
	}
	// Once the old key is dropped, only resealed data stays readable.
	fresh, _ := NewKeyring(XChaCha20Poly1305, newKey)
	if _, err := fresh.Open(resealed, "l"); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Open(ct, "l"); !errors.Is(err, ErrDecrypt) {
		t.Fatal("dropped key still decrypts")
	}
	if _, changed, _ := fresh.Reseal(resealed, "l"); changed {
		t.Fatal("current ciphertext resealed")
	}
}

// Ciphertexts written before key ids existed must stay readable.
func TestLegacyFormat(t *testing.T) {
	k := randKey(t)
	block, _ := aes.NewCipher(k)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	legacy := append(append([]byte{1}, nonce...), gcm.Seal(nil, nonce, []byte("v1 secret"), []byte("l"))...)

	b, _ := NewKeyring(AES256GCM, randKey(t), k)
	pt, err := b.Open(legacy, "l")
	if err != nil || string(pt) != "v1 secret" {
		t.Fatalf("legacy ciphertext: %q %v", pt, err)
	}
	if _, err := b.Open(legacy, "other"); err == nil {
		t.Fatal("legacy ciphertext opened with the wrong label")
	}
}

func TestHeaderIsAuthenticated(t *testing.T) {
	k := randKey(t)
	b, _ := NewKeyring(AES256GCM, k)
	ct, _ := b.Seal([]byte("secret"), "l")
	mut := bytes.Clone(ct)
	mut[1] = byte(XChaCha20Poly1305)
	if _, err := b.Open(mut, "l"); err == nil {
		t.Fatal("algorithm byte change accepted")
	}
}

func TestParseAlgorithm(t *testing.T) {
	for name, want := range map[string]Algorithm{"": AES256GCM, "aes-256-gcm": AES256GCM, "XChaCha20-Poly1305": XChaCha20Poly1305} {
		if got, err := ParseAlgorithm(name); err != nil || got != want {
			t.Fatalf("%q: %v %v", name, got, err)
		}
	}
	if _, err := ParseAlgorithm("rot13"); err == nil {
		t.Fatal("unknown algorithm accepted")
	}
}
