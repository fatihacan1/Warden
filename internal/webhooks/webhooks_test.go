package webhooks

import (
	"net"
	"testing"
	"time"
)

// Test vector from the Standard Webhooks specification, so receivers can use
// any compliant library.
func TestSignMatchesStandardWebhooks(t *testing.T) {
	const (
		secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
		id     = "msg_p5jXN8AQM9LWM0D4loKWxJek"
		ts     = 1614265330
		body   = `{"test": 2432232314}`
		want   = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
	)
	got, err := Sign(secret, id, ts, []byte(body))
	if err != nil || got != want {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
	now := time.Unix(ts, 0).Add(time.Minute)
	if !Verify(secret, id, "1614265330", "v1,bogus "+want, []byte(body), 5*time.Minute, now) {
		t.Fatal("valid signature among several rejected")
	}
	if Verify(secret, id, "1614265330", want, []byte(body), 5*time.Minute, now.Add(time.Hour)) {
		t.Fatal("stale timestamp accepted")
	}
}

func TestPublicIP(t *testing.T) {
	for addr, public := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.1.1": false, "172.16.0.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "::1": false, "fd00::1": false, "fe80::1": false,
	} {
		if got := publicIP(net.ParseIP(addr)); got != public {
			t.Errorf("%s: public=%v", addr, got)
		}
	}
}
