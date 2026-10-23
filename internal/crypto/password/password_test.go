package password

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Cheap parameters keep unit tests fast; production defaults are tested for
// format compatibility only.
var testParams = Params{Memory: 1024, Iterations: 1, Parallelism: 1}

func TestHashAndVerify(t *testing.T) {
	h := NewHasher(testParams, 2, time.Second, nil)
	ctx := context.Background()

	hash, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("unexpected format %q", hash)
	}
	ok, rehash, err := h.Verify(ctx, "correct horse battery staple", hash)
	if err != nil || !ok || rehash {
		t.Fatalf("verify: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	ok, _, err = h.Verify(ctx, "wrong", hash)
	if err != nil || ok {
		t.Fatalf("wrong password accepted: ok=%v err=%v", ok, err)
	}
}

func TestSaltIsUnique(t *testing.T) {
	h := NewHasher(testParams, 2, time.Second, nil)
	a, _ := h.Hash(context.Background(), "same")
	b, _ := h.Hash(context.Background(), "same")
	if a == b {
		t.Fatal("identical hashes for identical passwords: salt is not random")
	}
}

func TestNeedsRehashWhenParamsIncrease(t *testing.T) {
	weak := NewHasher(testParams, 1, time.Second, nil)
	hash, _ := weak.Hash(context.Background(), "pw-123456")
	strong := NewHasher(Params{Memory: 2048, Iterations: 2, Parallelism: 1}, 1, time.Second, nil)
	ok, rehash, err := strong.Verify(context.Background(), "pw-123456", hash)
	if err != nil || !ok || !rehash {
		t.Fatalf("ok=%v rehash=%v err=%v", ok, rehash, err)
	}
}

func TestRejectsMalformedAndHostileHashes(t *testing.T) {
	h := NewHasher(testParams, 1, time.Second, nil)
	cases := []string{
		"",
		"plaintext",
		"$argon2i$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // memory bomb
		"$argon2id$v=19$m=1024,t=1000,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",  // cpu bomb
		"$argon2id$v=19$m=1024,t=1,p=1$!!$aGFzaA",
	}
	for _, c := range cases {
		if _, _, err := h.Verify(context.Background(), "x", c); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("%q: expected ErrInvalidHash, got %v", c, err)
		}
	}
}

func TestConcurrencyIsBounded(t *testing.T) {
	h := NewHasher(Params{Memory: 8 * 1024, Iterations: 3, Parallelism: 1}, 1, 10*time.Millisecond, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	busy := 0
	for range 8 {
		wg.Go(func() {
			if _, err := h.Hash(context.Background(), "pw"); errors.Is(err, ErrBusy) {
				mu.Lock()
				busy++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if busy == 0 {
		t.Fatal("expected some requests to be shed with ErrBusy when the hasher is saturated")
	}
}

func TestContextCancellation(t *testing.T) {
	h := NewHasher(testParams, 1, time.Second, nil)
	h.slots <- struct{}{} // occupy the only slot
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "pw"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestDummyVerify(t *testing.T) {
	h := NewHasher(testParams, 1, time.Second, nil)
	if err := h.DummyVerify(context.Background(), "anything"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicy(t *testing.T) {
	p := Policy{MinLength: 8, MaxLength: 72}
	cases := []struct {
		pw, email string
		ok        bool
	}{
		{"short", "", false},
		{"password", "", false},
		{"aaaaaaaaaaaa", "", false},
		{"johnathan-2024!", "johnathan@example.com", false},
		{strings.Repeat("x", 73) + "y", "", false},
		{"correct horse battery", "a@b.co", true},
		{"çok-güçlü-şifre-ğ", "", true},
	}
	for _, c := range cases {
		got := p.Problem(c.pw, c.email) == ""
		if got != c.ok {
			t.Errorf("Problem(%q, %q) ok=%v want %v", c.pw, c.email, got, c.ok)
		}
	}
}

func TestBreachChecker(t *testing.T) {
	// SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) != len("/5BAA6") {
			t.Errorf("unexpected path %s (only a 5 char prefix may be sent)", r.URL.Path)
		}
		if r.Header.Get("Add-Padding") != "true" {
			t.Error("Add-Padding header missing")
		}
		fmt.Fprintln(w, "0018A45C4D1DEF81644B54AB7F969B88D65:1")
		fmt.Fprintln(w, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493")
	}))
	defer srv.Close()

	b := NewBreachChecker()
	b.baseURL = srv.URL + "/"
	breached, err := b.Breached(context.Background(), "password")
	if err != nil || !breached {
		t.Fatalf("breached=%v err=%v", breached, err)
	}
	breached, err = b.Breached(context.Background(), "a-much-better-passphrase")
	if err != nil || breached {
		t.Fatalf("breached=%v err=%v", breached, err)
	}
}

func BenchmarkHashDefaultParams(b *testing.B) {
	h := NewHasher(DefaultParams, 0, time.Minute, nil)
	for b.Loop() {
		if _, err := h.Hash(context.Background(), "benchmark-password"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestDefaultSlots(t *testing.T) {
	const mib = 1 << 20
	for _, c := range []struct {
		procs int
		limit int64
		want  int
	}{{12, math.MaxInt64, 12}, {12, 450 * mib, 11}, {4, 450 * mib, 4}, {8, 20 * mib, 1}} {
		if got := defaultSlots(19*1024, c.procs, c.limit); got != c.want {
			t.Errorf("defaultSlots(%d, %d) = %d, want %d", c.procs, c.limit, got, c.want)
		}
	}
}
