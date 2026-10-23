package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/observability"
)

// mailTest sends one email with the configured delivery mode and explains
// what happens on the way: warden mail-test you@example.com
func mailTest(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: warden mail-test you@example.com")
		os.Exit(2)
	}
	cfg := load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	mode := cfg.MailDelivery()
	fmt.Println("Mail delivery:", mode)
	switch mode {
	case config.MailInbox:
		fmt.Println("Inbox mode keeps emails inside Warden and sends nothing. Sign up in your app, then open Inbox in the admin UI.")
	case config.MailLog:
		fmt.Println("Log mode writes emails to the log and sends nothing.")
	case config.MailDirect:
		d := mailer.NewDirect(cfg.SMTP.From, cfg.MailHeloName())
		if !d.Diagnose(ctx, args[0], os.Stdout) {
			os.Exit(1)
		}
	default:
		log := observability.NewLogger(cfg.LogLevel, cfg.LogFormat, cfg.ServiceName, cfg.Env)
		s := mailer.NewSender(cfg, nil, nil, log)
		fmt.Printf("Sending through %s:%d as %s ...\n", cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.From)
		err := s.Send(ctx, mailer.Message{To: args[0], Subject: "Warden test email",
			Text: "If you can read this, SMTP delivery from Warden works.\n", HTML: "<p>If you can read this, SMTP delivery from Warden works.</p>"})
		if err != nil {
			fmt.Fprintln(os.Stderr, "FAIL ", err)
			os.Exit(1)
		}
		fmt.Println("OK    accepted by the SMTP server. Check the inbox and the spam folder.")
	}
}
