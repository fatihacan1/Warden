package auth

import (
	_ "embed"
	"strings"

	"github.com/fatihacan1/warden/internal/domain"
)

//go:embed work_email_domains.txt
var freeEmailDomains string

// matchesDomain matches a domain and its subdomains at a label boundary.
func matchesDomain(domain, rule string) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	return rule != "" && (domain == rule || strings.HasSuffix(domain, "."+rule))
}

func blockedWorkEmail(email string, extra, allowed []string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	_, domain, ok := strings.Cut(email, "@")
	domain = strings.TrimSpace(domain)
	if !ok || domain == "" {
		return true
	}
	for _, rule := range allowed {
		if matchesDomain(domain, rule) {
			return false
		}
	}
	for _, rule := range extra {
		if matchesDomain(domain, rule) {
			return true
		}
	}
	for _, rule := range strings.Fields(freeEmailDomains) {
		if matchesDomain(domain, rule) {
			return true
		}
	}
	return false
}

func (s *Service) checkWorkEmail(email string) error {
	rt := s.Settings.Get()
	if rt.RequireWorkEmail && blockedWorkEmail(email, rt.WorkEmailExtraBlocked, rt.WorkEmailAllowed) {
		return domain.ErrWorkEmailRequired
	}
	return nil
}
