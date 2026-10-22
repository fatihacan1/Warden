// Package randtoken generates and hashes opaque, high-entropy tokens
// (refresh tokens, email links, one-time codes).
//
// Opaque tokens carry 256 bits of entropy, so a fast hash (SHA-256) is the
// right way to store them: unlike passwords they cannot be brute forced, and
// lookups by hash stay O(1).
package randtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
)

// New returns a URL-safe random token with n bytes of entropy.
func New(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms (Go 1.24+ panics
		// internally instead); keep the guard for older runtimes.
		panic("randtoken: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash returns SHA-256(token).
func Hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// HashHex returns hex(SHA-256(token)), handy for Redis keys.
func HashHex(token string) string {
	return hex.EncodeToString(Hash(token))
}

const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no 0/o, 1/l/i

// RecoveryCode returns a human friendly code like "k7fp2-qx9mz".
func RecoveryCode() string {
	var sb strings.Builder
	max := big.NewInt(int64(len(recoveryAlphabet)))
	for i := range 10 {
		if i == 5 {
			sb.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("randtoken: " + err.Error())
		}
		sb.WriteByte(recoveryAlphabet[n.Int64()])
	}
	return sb.String()
}

// NormalizeRecoveryCode makes user input comparable to stored codes.
func NormalizeRecoveryCode(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	if len(s) == 10 && !strings.Contains(s, "-") {
		s = s[:5] + "-" + s[5:]
	}
	return s
}
