package mailer

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Diagnose walks through what direct delivery to one address needs and prints
// each step: MX records, reachability of port 25, STARTTLS and the result of
// a real send. It reports whether the message was accepted.
func (d *Direct) Diagnose(ctx context.Context, to string, w io.Writer) bool {
	say := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		say("FAIL  %q is not a valid email address", to)
		return false
	}
	domain := rcpt.Address[strings.LastIndex(rcpt.Address, "@")+1:]
	say("From:  %s", d.From)
	say("HELO:  %s", d.Helo)
	hosts, err := d.Hosts(ctx, domain)
	if err != nil {
		say("FAIL  MX lookup for %s: %v", domain, err)
		return false
	}
	say("OK    %s accepts mail at: %s", domain, strings.Join(hosts, ", "))

	reachable := false
	for _, h := range hosts {
		addr := net.JoinHostPort(h, strconv.Itoa(d.Port))
		conn, err := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			say("FAIL  %s: cannot connect (%v)", addr, err)
			continue
		}
		reachable = true
		say("OK    %s: port %d is reachable", h, d.Port)
		d.probe(conn, h, say)
	}
	if !reachable {
		say("")
		say("Outbound port %d looks blocked. Many cloud providers block it by default (ask them to unblock it), or use SMTP_HOST with a relay, or MAIL_DELIVERY=inbox.", d.Port)
		return false
	}

	sctx, cancel := context.WithTimeout(ctx, 2*d.Timeout)
	defer cancel()
	msg := Message{To: rcpt.Address, Subject: "Warden test email", Text: "If you can read this, direct delivery from this server works.\n", HTML: "<p>If you can read this, direct delivery from this server works.</p>"}
	if err := d.Send(sctx, msg); err != nil {
		say("FAIL  send: %v", err)
		return false
	}
	say("OK    accepted by the recipient's mail server. Check the inbox and the spam folder.")
	say("Note: without SPF, DKIM and reverse DNS for this server, big providers often filter such mail as spam.")
	return true
}

// probe says whether a server offers STARTTLS. It consumes conn.
func (d *Direct) probe(conn net.Conn, host string, say func(string, ...any)) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		say("WARN  %s: no SMTP greeting (%v)", host, err)
		return
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(d.Helo); err != nil {
		say("WARN  %s: HELO rejected (%v)", host, err)
		return
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		say("OK    %s: STARTTLS offered", host)
	} else {
		say("WARN  %s: no STARTTLS, the message would travel unencrypted", host)
	}
	_ = c.Quit()
}
