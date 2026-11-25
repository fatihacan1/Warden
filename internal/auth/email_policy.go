package auth

import (
	"context"
	_ "embed"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/settings"
)

// Email policy: which addresses may open an account.
//
//	any    every valid address (default)
//	known  large, well-known mailbox providers only. Companies and schools can
//	       be let in on top with their own switches. Throwaway providers never
//	       pass unless an operator lists them as allowed.
//
// Like the work email rule it applies to new accounts only, on password sign-up
// and on a first social login. Operators and the server API are not restricted.

//go:embed known_email_domains.txt
var knownEmailDomains string

// From github.com/disposable-email-domains/disposable-email-domains (CC0 1.0).
//
//go:embed disposable_domains.txt
var disposableDomains string

var (
	knownSet      = sync.OnceValue(func() map[string]struct{} { return domainSet(knownEmailDomains) })
	disposableSet = sync.OnceValue(func() map[string]struct{} { return domainSet(disposableDomains) })
)

const mxTimeout = 2 * time.Second

// replaced in tests
var lookupMX = net.DefaultResolver.LookupMX

func domainSet(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, d := range strings.Fields(raw) {
		out[d] = struct{}{}
	}
	return out
}

func anyRule(d string, rules []string) bool {
	for _, r := range rules {
		if matchesDomain(d, r) {
			return true
		}
	}
	return false
}

// isDisposable also catches subdomains: throwaway services hand them out.
func isDisposable(d string) bool {
	set := disposableSet()
	for d != "" {
		if _, ok := set[d]; ok {
			return true
		}
		_, rest, ok := strings.Cut(d, ".")
		if !ok {
			return false
		}
		d = rest
	}
	return false
}

// isSchool recognizes namespaces that registries reserve for education:
// .edu, .edu.tr, .ac.uk, .k12.tr, .k12.ca.us, .sch.uk.
func isSchool(d string) bool {
	l := strings.Split(d, ".")
	n := len(l)
	if n < 2 {
		return false
	}
	if l[n-1] == "edu" {
		return true
	}
	if n >= 3 && len(l[n-1]) == 2 {
		switch l[n-2] {
		case "edu", "ac", "k12", "sch":
			return true
		}
	}
	return n >= 4 && l[n-1] == "us" && len(l[n-2]) == 2 && l[n-3] == "k12"
}

// isCompany is a domain of one's own that can really receive mail: it has an MX
// record, and is neither a mailbox provider's nor a throwaway one. A temporary
// DNS failure does not turn people away; the other rules still hold.
func isCompany(ctx context.Context, d string) bool {
	if !strings.Contains(d, ".") || net.ParseIP(strings.Trim(d, "[]")) != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, mxTimeout)
	defer cancel()
	mx, err := lookupMX(ctx, d)
	if err != nil && len(mx) == 0 {
		var de *net.DNSError
		return errors.As(err, &de) && !de.IsNotFound && (de.IsTimeout || de.IsTemporary)
	}
	for _, m := range mx {
		if h := strings.Trim(strings.TrimSpace(m.Host), "."); h != "" { // "." is a null MX (RFC 7505): no mail
			return true
		}
	}
	return false
}

func acceptsEmail(ctx context.Context, email string, rt *settings.Runtime) bool {
	_, d, ok := strings.Cut(strings.ToLower(strings.TrimSpace(email)), "@")
	d = strings.TrimSuffix(d, ".")
	if !ok || d == "" || strings.ContainsAny(d, "@ \t") {
		return false
	}
	if anyRule(d, rt.EmailBlockedDomains) {
		return false
	}
	if anyRule(d, rt.EmailAllowedDomains) {
		return true
	}
	if isDisposable(d) {
		return false
	}
	if _, ok := knownSet()[d]; ok {
		return true
	}
	if isSchool(d) {
		return rt.EmailAllowSchools
	}
	return rt.EmailAllowCompanies && isCompany(ctx, d)
}

// checkNewEmail applies every rule about which addresses may open an account.
func (s *Service) checkNewEmail(ctx context.Context, email string) error {
	if err := s.checkWorkEmail(email); err != nil {
		return err
	}
	rt := s.Settings.Get()
	if rt.EmailPolicy == settings.EmailPolicyKnown && !acceptsEmail(ctx, email, rt) {
		s.metric("sign_up", "email_not_accepted")
		return domain.ErrEmailNotAccepted
	}
	return nil
}
