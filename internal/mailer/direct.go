package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"time"

	gomail "github.com/wneessen/go-mail"
)

// PermanentError marks a delivery failure that retrying cannot fix (for
// example a 5xx answer from the recipient's server). The outbox relay moves
// such messages to the dead letters right away.
type PermanentError struct{ Err error }

func (p *PermanentError) Error() string   { return p.Err.Error() }
func (p *PermanentError) Unwrap() error   { return p.Err }
func (p *PermanentError) Permanent() bool { return true }

// Resolver looks up mail exchangers. *net.Resolver implements it.
type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// Direct delivers each email straight to the recipient's mail server (MX) on
// port 25, the way a mail server does. No SMTP provider is needed, but most
// cloud networks block outbound port 25 and mail from an address without
// SPF/DKIM/reverse DNS is usually filtered as spam. Meant for tests.
//
// Delivery runs inside the outbox relay, never in a request.
type Direct struct {
	From     string
	Helo     string
	Resolver Resolver
	Port     int // 25
	// AllowPrivate lets Direct connect to loopback and private addresses.
	// Off in production use: a recipient domain whose MX points inside your
	// network could otherwise be used to reach internal mail servers.
	AllowPrivate bool
	// MaxMX bounds how many exchangers are tried per message.
	MaxMX   int
	Timeout time.Duration
	// DialContext replaces the network dialer (tests).
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewDirect builds a direct sender. from is the configured SMTP_FROM; when its
// domain is localhost (the default) the helo name is used instead.
func NewDirect(from, helo string) *Direct {
	return &Direct{From: DirectFrom(from, helo), Helo: helo, Resolver: net.DefaultResolver, Port: 25, MaxMX: 3, Timeout: 20 * time.Second}
}

// DirectFrom replaces a placeholder sender domain with the helo name.
func DirectFrom(from, helo string) string {
	a, err := mail.ParseAddress(from)
	if err != nil {
		return "Warden <no-reply@" + helo + ">"
	}
	domain := a.Address[strings.LastIndex(a.Address, "@")+1:]
	if domain == "" || domain == "localhost" || domain == "example.com" {
		a.Address = "no-reply@" + helo
	}
	return a.String()
}

func (d *Direct) Send(ctx context.Context, m Message) error {
	msg, err := d.build(m)
	if err != nil {
		return &PermanentError{err}
	}
	rcpt, _ := mail.ParseAddress(m.To) // build validated it
	domain := rcpt.Address[strings.LastIndex(rcpt.Address, "@")+1:]
	hosts, err := d.Hosts(ctx, domain)
	if err != nil {
		return err
	}
	var errs []error
	for _, h := range hosts {
		err := d.deliver(ctx, h, msg)
		if err == nil {
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", h, err))
		var pe *PermanentError
		if errors.As(err, &pe) {
			return &PermanentError{errors.Join(errs...)} // the server said no; another exchanger will not change that
		}
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("mailer: direct delivery to %s failed: %w", domain, errors.Join(errs...))
}

func (d *Direct) build(m Message) (*gomail.Msg, error) {
	msg := gomail.NewMsg()
	if err := msg.From(d.From); err != nil {
		return nil, fmt.Errorf("mailer: from: %w", err)
	}
	if err := msg.To(m.To); err != nil {
		return nil, fmt.Errorf("mailer: to: %w", err)
	}
	msg.Subject(m.Subject)
	msg.SetBodyString(gomail.TypeTextPlain, m.Text)
	msg.AddAlternativeString(gomail.TypeTextHTML, m.HTML)
	return msg, nil
}

// Hosts returns the mail exchangers of a domain in delivery order: lowest
// preference first. A domain without MX records is delivered to itself (RFC
// 5321 5.1); a null MX ("." ) means it accepts no mail.
func (d *Direct) Hosts(ctx context.Context, domain string) ([]string, error) {
	lctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()
	mxs, err := d.Resolver.LookupMX(lctx, domain)
	var dnsErr *net.DNSError
	switch {
	case err != nil && errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		mxs = nil // fall back to the domain itself below
	case err != nil && len(mxs) == 0:
		return nil, fmt.Errorf("mailer: MX lookup for %s: %w", domain, err)
	}
	sort.SliceStable(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })
	var hosts []string
	for _, mx := range mxs {
		h := strings.TrimSuffix(mx.Host, ".")
		if h == "" {
			if len(mxs) == 1 {
				return nil, &PermanentError{fmt.Errorf("mailer: %s does not accept email (null MX)", domain)}
			}
			continue
		}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		hosts = []string{domain}
	}
	if d.MaxMX > 0 && len(hosts) > d.MaxMX {
		hosts = hosts[:d.MaxMX]
	}
	return hosts, nil
}

func (d *Direct) client(host string) (*gomail.Client, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !d.AllowPrivate {
		dialer.Control = publicOnly
	}
	dial := dialer.DialContext
	if d.DialContext != nil {
		dial = d.DialContext
	}
	return gomail.NewClient(host,
		gomail.WithPort(d.Port),
		gomail.WithHELO(d.Helo),
		gomail.WithTLSPolicy(gomail.TLSOpportunistic),
		// Opportunistic TLS between mail servers (RFC 7435): encrypt when the
		// peer offers it, without trusting its certificate, as most MX hosts
		// present certificates that do not verify. A passive observer is
		// stopped; an active attacker could downgrade to plaintext anyway.
		gomail.WithTLSConfig(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}), // #nosec G402 -- opportunistic TLS, see above
		gomail.WithTimeout(d.Timeout),
		gomail.WithDialContextFunc(dial),
	)
}

func (d *Direct) deliver(ctx context.Context, host string, msg *gomail.Msg) error {
	c, err := d.client(host)
	if err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()
	err = c.DialAndSendWithContext(dctx, msg)
	if err == nil {
		return nil
	}
	var se *gomail.SendError
	if errors.As(err, &se) && !se.IsTemp() && se.ErrorCode() >= 500 {
		return &PermanentError{err}
	}
	return err
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicOnly is a net.Dialer control that refuses loopback, private,
// link-local and other non-public destinations.
func publicOnly(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("mailer: unexpected address %q", address)
	}
	ip := ap.Addr().Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip) {
		return fmt.Errorf("mailer: refusing to connect to non-public address %s", ip)
	}
	return nil
}
