package secretbox

import (
	"bytes"
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
