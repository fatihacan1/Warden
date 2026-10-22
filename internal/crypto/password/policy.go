package password

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- SHA-1 is mandated by the HIBP k-anonymity API; never used for storage
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// Policy validates new passwords. It follows NIST SP 800-63B: a length
// requirement plus a blocklist, and no arbitrary composition rules.
type Policy struct {
	MinLength int
	MaxLength int
}

// Problem describes why a password was rejected, or "" when it is acceptable.
func (p Policy) Problem(pw, email string) string {
	n := utf8.RuneCountInString(pw)
	switch {
	case n < p.MinLength:
		return fmt.Sprintf("Password must be at least %d characters.", p.MinLength)
	case len(pw) > p.MaxLength:
		return fmt.Sprintf("Password must be at most %d bytes.", p.MaxLength)
	case !utf8.ValidString(pw):
		return "Password contains invalid characters."
	}
	lower := strings.ToLower(pw)
	if email != "" {
		local, _, _ := strings.Cut(strings.ToLower(email), "@")
		if lower == strings.ToLower(email) || (len(local) >= 4 && strings.Contains(lower, local)) {
			return "Password must not contain your email address."
		}
	}
	if _, bad := commonPasswords[lower]; bad {
		return "This password is too common."
	}
	if isSingleCharRepeat(pw) {
		return "Password must not be a single repeated character."
	}
	return ""
}

func isSingleCharRepeat(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	for _, c := range s {
		if c != r {
			return false
		}
	}
	return true
}

// A small built-in blocklist of the most common passwords. Enable
// PASSWORD_CHECK_BREACHED for the full Have I Been Pwned corpus.
var commonPasswords = func() map[string]struct{} {
	list := []string{
		"password", "password1", "password123", "12345678", "123456789", "1234567890",
		"qwertyuiop", "qwerty123", "iloveyou", "11111111", "00000000", "abc12345",
		"letmein1", "welcome1", "admin123", "sunshine", "princess", "football",
		"baseball", "starwars", "trustno1", "passw0rd", "p@ssw0rd", "changeme",
		"qwerty12", "1q2w3e4r", "1qaz2wsx", "zaq12wsx", "asdfghjkl", "superman",
		"dragon123", "monkey123", "master123", "whatever", "freedom1", "michael1",
	}
	m := make(map[string]struct{}, len(list))
	for _, p := range list {
		m[p] = struct{}{}
	}
	return m
}()

// BreachChecker queries the Have I Been Pwned range API using k-anonymity:
// only the first 5 hex chars of the SHA-1 hash ever leave the server.
type BreachChecker struct {
	client  *http.Client
	baseURL string
}

// NewBreachChecker returns a checker with a short timeout. It fails open.
func NewBreachChecker() *BreachChecker {
	return &BreachChecker{
		client:  &http.Client{Timeout: 2 * time.Second},
		baseURL: "https://api.pwnedpasswords.com/range/",
	}
}

// Breached reports whether pw appears in known breaches. On network errors it
// returns false and the error, so callers can log and continue (fail open).
func (b *BreachChecker) Breached(ctx context.Context, pw string) (bool, error) {
	sum := sha1.Sum([]byte(pw)) // #nosec G401 nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1 -- HIBP API requirement
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "warden-auth")
	resp, err := b.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hibp: unexpected status %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for sc.Scan() {
		line := sc.Text()
		hashSuffix, count, ok := strings.Cut(line, ":")
		if ok && hashSuffix == suffix && strings.TrimSpace(count) != "0" {
			return true, nil
		}
	}
	return false, sc.Err()
}
