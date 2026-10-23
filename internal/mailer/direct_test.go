package mailer

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMX is a minimal SMTP server without STARTTLS.
type fakeMX struct {
	ln       net.Listener
	rejectTo string // RCPT answer, e.g. "550 no such user"
	mu       sync.Mutex
	conns    int
	got      []string // DATA bodies
}

func newFakeMX(t *testing.T, rejectTo string) *fakeMX {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeMX{ln: ln, rejectTo: rejectTo}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeMX) serve(c net.Conn) {
	defer c.Close()
	f.mu.Lock()
	f.conns++
	f.mu.Unlock()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250-fake")
			say("250 8BITMIME")
		case strings.HasPrefix(cmd, "MAIL"):
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT"):
			if f.rejectTo != "" {
				say(f.rejectTo)
			} else {
				say("250 ok")
			}
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.got = append(f.got, b.String())
			f.mu.Unlock()
			say("250 queued")
		case cmd == "RSET":
			say("250 ok")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (f *fakeMX) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

type fakeResolver struct {
	mx  map[string][]*net.MX
	err map[string]error
}

func (r fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if err, ok := r.err[name]; ok {
		return nil, err
	}
	return r.mx[name], nil
}

// direct returns a Direct whose hosts resolve to the given fake servers;
// every other host refuses the connection.
func direct(res Resolver, servers map[string]*fakeMX) *Direct {
	d := NewDirect("Warden <no-reply@auth.example.org>", "auth.example.org")
	d.Resolver = res
	d.AllowPrivate = true
	d.Timeout = 5 * time.Second
	d.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		s, ok := servers[host]
		if !ok {
			return nil, errors.New("connection refused")
		}
		return (&net.Dialer{}).DialContext(ctx, network, s.ln.Addr().String())
	}
	return d
}

var msg = Message{To: "ann@example.com", Subject: "Hi", Text: "hello", HTML: "<p>hello</p>"}

func TestDirectUsesLowestPreferenceFirstAndFallsBack(t *testing.T) {
	primary, backup := newFakeMX(t, ""), newFakeMX(t, "")
	res := fakeResolver{mx: map[string][]*net.MX{"example.com": {
		{Host: "backup.mx.test.", Pref: 20}, {Host: "primary.mx.test.", Pref: 10}, {Host: "dead.mx.test.", Pref: 5},
	}}}
	d := direct(res, map[string]*fakeMX{"primary.mx.test": primary, "backup.mx.test": backup})
	if err := d.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if primary.count() != 1 || backup.count() != 0 {
		t.Fatalf("expected the primary after skipping the dead one, got primary=%d backup=%d", primary.count(), backup.count())
	}
	if len(primary.got) != 1 || !strings.Contains(primary.got[0], "Subject: Hi") || !strings.Contains(primary.got[0], "no-reply@auth.example.org") {
		t.Fatalf("unexpected message: %q", primary.got)
	}
}

func TestDirectFallsBackToNextMXOnConnectionFailure(t *testing.T) {
	backup := newFakeMX(t, "")
	res := fakeResolver{mx: map[string][]*net.MX{"example.com": {{Host: "dead.mx.test.", Pref: 1}, {Host: "backup.mx.test.", Pref: 2}}}}
	d := direct(res, map[string]*fakeMX{"backup.mx.test": backup})
	if err := d.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if backup.count() != 1 {
		t.Fatal("backup not used")
	}
}

func TestDirectPermanentRejectionStopsAndIsPermanent(t *testing.T) {
	first, second := newFakeMX(t, "550 5.1.1 no such user"), newFakeMX(t, "")
	res := fakeResolver{mx: map[string][]*net.MX{"example.com": {{Host: "a.mx.test.", Pref: 1}, {Host: "b.mx.test.", Pref: 2}}}}
	d := direct(res, map[string]*fakeMX{"a.mx.test": first, "b.mx.test": second})
	err := d.Send(context.Background(), msg)
	var pe interface{ Permanent() bool }
	if err == nil || !errors.As(err, &pe) || !pe.Permanent() {
		t.Fatalf("want a permanent error, got %v", err)
	}
	if second.count() != 0 {
		t.Fatal("must not try another exchanger after a 5xx")
	}
}

func TestDirectTemporaryRejectionTriesNextMX(t *testing.T) {
	first, second := newFakeMX(t, "451 try later"), newFakeMX(t, "")
	res := fakeResolver{mx: map[string][]*net.MX{"example.com": {{Host: "a.mx.test.", Pref: 1}, {Host: "b.mx.test.", Pref: 2}}}}
	d := direct(res, map[string]*fakeMX{"a.mx.test": first, "b.mx.test": second})
	if err := d.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if second.count() != 1 {
		t.Fatal("second exchanger not used after a 4xx")
	}
}

func TestDirectNoMXFallsBackToDomainItself(t *testing.T) {
	self := newFakeMX(t, "")
	res := fakeResolver{err: map[string]error{"example.com": &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}}}
	d := direct(res, map[string]*fakeMX{"example.com": self})
	if err := d.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if self.count() != 1 {
		t.Fatal("implicit MX not used")
	}
}

func TestDirectNullMXIsPermanent(t *testing.T) {
	res := fakeResolver{mx: map[string][]*net.MX{"example.com": {{Host: ".", Pref: 0}}}}
	err := direct(res, nil).Send(context.Background(), msg)
	var pe interface{ Permanent() bool }
	if err == nil || !errors.As(err, &pe) {
		t.Fatalf("want permanent error, got %v", err)
	}
}

func TestDirectLookupFailureIsRetryable(t *testing.T) {
	res := fakeResolver{err: map[string]error{"example.com": &net.DNSError{Err: "server misbehaving", Name: "example.com", IsTemporary: true}}}
	err := direct(res, nil).Send(context.Background(), msg)
	var pe interface{ Permanent() bool }
	if err == nil || errors.As(err, &pe) {
		t.Fatalf("want a retryable error, got %v", err)
	}
}

func TestDirectRefusesPrivateAddresses(t *testing.T) {
	srv := newFakeMX(t, "")
	res := fakeResolver{mx: map[string][]*net.MX{"example.com": {{Host: "127.0.0.1", Pref: 1}}}}
	d := NewDirect("a@auth.example.org", "auth.example.org")
	d.Resolver = res
	d.Port = srv.ln.Addr().(*net.TCPAddr).Port
	d.Timeout = 3 * time.Second
	if err := d.Send(context.Background(), msg); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if srv.count() != 0 {
		t.Fatal("must not connect to a loopback exchanger")
	}
}

func TestDirectFromReplacesPlaceholderDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Warden <no-reply@localhost>":   "\"Warden\" <no-reply@auth.example.org>",
		"Warden <no-reply@example.com>": "\"Warden\" <no-reply@auth.example.org>",
		"Warden <no-reply@acme.dev>":    "\"Warden\" <no-reply@acme.dev>",
		"not an address":                "Warden <no-reply@auth.example.org>",
	} {
		if got := DirectFrom(in, "auth.example.org"); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2a00:1450::1": true, "64:ff9b::808:808": true,
		"10.0.0.1": false, "127.0.0.1": false, "100.64.1.1": false, "192.0.0.8": false,
		"198.18.0.1": false, "203.0.113.5": false, "240.0.0.1": false, "::1": false,
		"64:ff9b::a00:1": false, "2002:a00:1::1": false, "::ffff:10.0.0.1": false, "2001:db8::1": false,
	} {
		if got := publicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("publicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}
