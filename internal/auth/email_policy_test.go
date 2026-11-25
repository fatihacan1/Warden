package auth

import (
	"context"
	"net"
	"testing"

	"github.com/fatihacan1/warden/internal/settings"
)

func fakeMX(t *testing.T) {
	t.Helper()
	old := lookupMX
	t.Cleanup(func() { lookupMX = old })
	lookupMX = func(_ context.Context, d string) ([]*net.MX, error) {
		switch d {
		case "acme.com", "mail.acme.com", "shop.io":
			return []*net.MX{{Host: "mx." + d + ".", Pref: 10}}, nil
		case "nullmx.com":
			return []*net.MX{{Host: ".", Pref: 0}}, nil
		case "slowdns.com":
			return nil, &net.DNSError{Err: "timeout", Name: d, IsTimeout: true, IsTemporary: true}
		}
		return nil, &net.DNSError{Err: "no such host", Name: d, IsNotFound: true}
	}
}

func TestAcceptsEmail(t *testing.T) {
	fakeMX(t)
	type flags struct {
		company, school  bool
		allowed, blocked []string
	}
	cases := []struct {
		name, email string
		f           flags
		want        bool
	}{
		{"gmail", "a@gmail.com", flags{}, true},
		{"outlook turkey", "a@outlook.com.tr", flags{}, true},
		{"case and space", "  A@GMAIL.COM ", flags{}, true},
		{"trailing dot", "a@gmail.com.", flags{}, true},
		{"lookalike", "a@gmail.co", flags{}, false},
		{"prefix", "a@notgmail.com", flags{}, false},
		{"known as subdomain", "a@gmail.com.evil.com", flags{company: true}, false},
		{"subdomain of known", "a@x.gmail.com", flags{}, false},
		{"unknown extension", "a@mailbox.xyz", flags{}, false},
		{"company off", "a@acme.com", flags{}, false},
		{"company on", "a@acme.com", flags{company: true}, true},
		{"company without mail", "a@nomx.com", flags{company: true}, false},
		{"company that refuses mail", "a@nullmx.com", flags{company: true}, false},
		{"company, dns hiccup", "a@slowdns.com", flags{company: true}, true},
		{"ip literal", "a@[127.0.0.1]", flags{company: true}, false},
		{"no dot", "a@localhost", flags{company: true}, false},
		{"school off", "a@itu.edu.tr", flags{company: true}, false},
		{"school on", "a@itu.edu.tr", flags{school: true}, true},
		{"edu", "a@cs.mit.edu", flags{school: true}, true},
		{"ac.uk", "a@ox.ac.uk", flags{school: true}, true},
		{"k12 us", "a@lausd.k12.ca.us", flags{school: true}, true},
		{"school does not open companies", "a@acme.com", flags{school: true}, false},
		{"fake school", "a@edu.com", flags{school: true}, false},
		{"fake ac", "a@ac.shop.io", flags{school: true}, false},
		{"throwaway", "a@mailinator.com", flags{company: true, school: true}, false},
		{"throwaway subdomain", "a@x.y.mailinator.com", flags{company: true, school: true}, false},
		{"throwaway, allowed by operator", "a@mailinator.com", flags{allowed: []string{"mailinator.com"}}, true},
		{"extra allowed", "a@sub.partner.xyz", flags{allowed: []string{" Partner.XYZ "}}, true},
		{"blocked wins over known", "a@gmail.com", flags{blocked: []string{"gmail.com"}}, false},
		{"blocked wins over allowed", "a@x.com", flags{allowed: []string{"x.com"}, blocked: []string{"x.com"}}, false},
		{"empty", "", flags{company: true}, false},
		{"two ats", "a@b@gmail.com", flags{company: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &settings.Runtime{EmailPolicy: settings.EmailPolicyKnown, EmailAllowCompanies: tc.f.company, EmailAllowSchools: tc.f.school,
				EmailAllowedDomains: tc.f.allowed, EmailBlockedDomains: tc.f.blocked}
			if got := acceptsEmail(t.Context(), tc.email, rt); got != tc.want {
				t.Fatalf("%s: got %v", tc.email, got)
			}
		})
	}
}

func TestListsDoNotOverlap(t *testing.T) {
	if len(disposableSet()) < 5000 || len(knownSet()) < 100 {
		t.Fatal("lists are not embedded")
	}
	for d := range knownSet() {
		if isDisposable(d) {
			t.Error(d, "is on both lists")
		}
	}
}
