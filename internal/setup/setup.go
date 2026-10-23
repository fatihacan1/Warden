// Package setup is the first-run wizard: a small local web page that asks for
// connections and secrets, tests them, validates the result with the same
// rules as `warden serve`, and writes .env.
//
// It is meant to run on the operator's machine before the service exists:
//
//	warden setup            (or: go run ./cmd/warden setup, make setup)
//
// It listens on 127.0.0.1 only, requires the one-time token printed in the
// terminal, checks Host and Origin headers against DNS rebinding and
// cross-site requests, and stops after the file is written.
package setup

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/transport/admin"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Options configure the wizard.
type Options struct {
	Addr    string // default 127.0.0.1:9095
	EnvFile string // default .env
	// AllowRemote permits a non-loopback listen address (for a container
	// with a published port). The token still protects it.
	AllowRemote bool
	Log         *slog.Logger
	// Ready is called with the URL to open once the server listens.
	Ready func(url string)
}

type server struct {
	opt      Options
	token    string
	page     *template.Template
	previous map[string]string
	order    []string

	mu      sync.Mutex
	pending string // .env text from the last successful review
	done    chan struct{}
	once    sync.Once
}

// Run serves the wizard until the file is saved or ctx is cancelled.
func Run(ctx context.Context, opt Options) error {
	if opt.Addr == "" {
		opt.Addr = "127.0.0.1:9095"
	}
	if opt.EnvFile == "" {
		opt.EnvFile = ".env"
	}
	host, _, err := net.SplitHostPort(opt.Addr)
	if err != nil {
		return fmt.Errorf("setup: --addr: %w", err)
	}
	if ip := net.ParseIP(host); !opt.AllowRemote && (ip == nil || !ip.IsLoopback()) && host != "localhost" {
		return errors.New("setup: refusing to listen on a non-loopback address; pass --allow-remote if you really mean it")
	}
	prev, order, err := config.ReadDotEnv(opt.EnvFile)
	if err != nil {
		return fmt.Errorf("setup: reading %s: %w", opt.EnvFile, err)
	}
	page, err := template.New("").Funcs(template.FuncMap{
		"value": func(vals map[string]string, k string) string { return vals[k] },
		"isset": func(vals map[string]string, k string) bool { return vals[k] != "" },
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return err
	}
	s := &server{opt: opt, token: randtoken.New(24), page: page, previous: prev, order: order, done: make(chan struct{})}

	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	srv := &http.Server{Handler: s.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second}
	go func() { // #nosec G118 -- shutdown must outlive the cancelled ctx
		select {
		case <-ctx.Done():
		case <-s.done:
			time.Sleep(time.Second) // let the confirmation page load
		}
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if opt.Ready != nil {
		addr := ln.Addr().String()
		if strings.HasPrefix(addr, "[::]") || strings.HasPrefix(addr, "0.0.0.0") {
			_, port, _ := net.SplitHostPort(addr)
			addr = "127.0.0.1:" + port
		}
		opt.Ready("http://" + addr + "/?token=" + s.token)
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/setup.js", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /static/admin.css", func(w http.ResponseWriter, r *http.Request) {
		b, _ := fs.ReadFile(admin.StaticFS(), "admin.css")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /static/mark.svg", func(w http.ResponseWriter, r *http.Request) {
		b, _ := fs.ReadFile(admin.StaticFS(), "mark.svg")
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /{$}", s.form)
	mux.HandleFunc("POST /check/{kind}", s.check)
	mux.HandleFunc("POST /generate/{kind}", s.generate)
	mux.HandleFunc("POST /review", s.review)
	mux.HandleFunc("POST /save", s.save)
	mux.HandleFunc("POST /download", s.download)
	return s.guard(mux)
}

const cookieName = "warden_setup"

// guard enforces the token, the Host header and same-origin posts.
func (s *server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin, not no-referrer: with no-referrer browsers send
		// "Origin: null" on form posts, which the origin check rejects.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")

		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if ip := net.ParseIP(host); !s.opt.AllowRemote && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			http.Error(w, "Unexpected Host header.", http.StatusMisdirectedRequest) // DNS rebinding
			return
		}
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if t := r.URL.Query().Get("token"); t != "" && r.Method == http.MethodGet {
			if subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) != 1 {
				http.Error(w, "Invalid setup token. Use the link printed in the terminal.", http.StatusForbidden)
				return
			}
			// Plain http on loopback: Secure would stop the cookie from being sent.
			// #nosec G124 -- loopback only, HttpOnly and SameSite=Strict
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.token)) != 1 {
			http.Error(w, "Open the link printed in the terminal (it contains a one-time token).", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					if s.opt.Log != nil {
						s.opt.Log.Warn("setup: cross-origin post rejected", "origin", o, "host", r.Host)
					}
					http.Error(w, "Cross-origin request rejected.", http.StatusForbidden)
					return
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		}
		next.ServeHTTP(w, r)
	})
}

type view struct {
	Sections []section
	Values   map[string]string
	Existing bool
	EnvFile  string
	Errors   []string
	Notes    []string
	Env      string
	Saved    string
	Backup   string
}

func (s *server) render(w http.ResponseWriter, name string, v view) {
	v.Sections, v.EnvFile, v.Existing = sections, s.absEnv(), len(s.previous) > 0
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.page.ExecuteTemplate(w, name, v); err != nil && s.opt.Log != nil {
		s.opt.Log.Error("setup render", "err", err)
	}
}

func (s *server) absEnv() string {
	if p, err := filepath.Abs(s.opt.EnvFile); err == nil {
		return p
	}
	return s.opt.EnvFile
}

// defaults prefill the form: the existing file wins, then field defaults,
// then freshly generated secrets.
func (s *server) defaults() map[string]string {
	vals := map[string]string{}
	for _, sec := range sections {
		for _, f := range sec.Fields {
			switch v, ok := s.previous[f.Key]; {
			case ok:
				vals[f.Key] = v
			case f.Generate != "":
				vals[f.Key] = generate(f.Generate)
			default:
				vals[f.Key] = f.Default
			}
		}
	}
	return vals
}

func (s *server) form(w http.ResponseWriter, r *http.Request) {
	s.render(w, "form", view{Values: s.defaults()})
}

func formValues(r *http.Request) map[string]string {
	_ = r.ParseForm()
	vals := map[string]string{}
	for _, sec := range sections {
		for _, f := range sec.Fields {
			v := strings.TrimSpace(r.PostForm.Get(f.Key))
			switch f.Kind {
			case "bool":
				v = map[bool]string{true: "true", false: "false"}[v == "on" || v == "true"]
			case "list":
				parts := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
				for i := range parts {
					parts[i] = strings.TrimSpace(parts[i])
				}
				v = strings.Join(slices.DeleteFunc(parts, func(p string) bool { return p == "" }), ",")
			case "select":
				if !slices.ContainsFunc(f.Options, func(o option) bool { return o.Value == v }) {
					v = f.Default
				}
			}
			vals[f.Key] = v
		}
	}
	return vals
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) check(w http.ResponseWriter, r *http.Request) {
	msg, err := check(r.Context(), r.PathValue("kind"), formValues(r))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

func (s *server) generate(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "key" && kind != "token" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"value": generate(kind)})
}

// complete adds derived values and handles key rotation.
func (s *server) complete(vals map[string]string) []string {
	var notes []string
	prod := vals["APP_ENV"] == "production"
	vals["HTTP_COOKIE_SECURE"] = fmt.Sprint(strings.HasPrefix(vals["HTTP_PUBLIC_URL"], "https://"))
	vals["LOG_FORMAT"] = map[bool]string{true: "json", false: "text"}[prod]
	vals["GRPC_REFLECTION"] = fmt.Sprint(!prod)

	prevKeys := strings.Split(s.previous["ENCRYPTION_PREVIOUS_KEYS"], ",")
	old := s.previous["ENCRYPTION_KEY"]
	if old != "" && old != vals["ENCRYPTION_KEY"] && !slices.Contains(prevKeys, old) {
		prevKeys = append([]string{old}, prevKeys...)
		notes = append(notes, "The encryption key changed. The old key is kept in ENCRYPTION_PREVIOUS_KEYS so existing data stays readable. After starting Warden, run `warden reencrypt`, then remove the old key.")
	}
	vals["ENCRYPTION_PREVIOUS_KEYS"] = strings.Join(slices.DeleteFunc(prevKeys, func(k string) bool { return strings.TrimSpace(k) == "" || k == vals["ENCRYPTION_KEY"] }), ",")
	if prev := s.previous["ENCRYPTION_ALGORITHM"]; prev != "" && prev != vals["ENCRYPTION_ALGORITHM"] {
		notes = append(notes, "The algorithm changed. New data uses "+vals["ENCRYPTION_ALGORITHM"]+"; existing data stays readable. `warden reencrypt` converts it.")
	}
	switch vals["MAIL_DELIVERY"] {
	case "inbox":
		notes = append(notes, "Emails are not sent: they appear in the admin UI under Inbox. Use this for testing only, your users receive nothing.")
	case "direct":
		notes = append(notes, "Emails are sent straight from this server. Outbound port 25 must be open and mail will likely land in spam. Run `warden mail-test you@example.com` to check.")
	}
	return notes
}

func (s *server) review(w http.ResponseWriter, r *http.Request) {
	vals := formValues(r)
	notes := s.complete(vals)
	env := map[string]string{}
	for k, v := range s.previous {
		env[k] = v
	}
	for k, v := range vals {
		env[k] = v
	}
	if _, err := config.LoadFrom(env); err != nil {
		var errs []string
		for _, line := range strings.Split(err.Error(), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				errs = append(errs, line)
			}
		}
		s.render(w, "form", view{Values: vals, Errors: errs})
		return
	}
	text := render(vals, s.previous, s.order)
	s.mu.Lock()
	s.pending = text
	s.mu.Unlock()
	s.render(w, "review", view{Values: vals, Env: text, Notes: notes})
}

func (s *server) take() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending
}

func (s *server) download(w http.ResponseWriter, r *http.Request) {
	text := s.take()
	if text == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename=".env"`)
	_, _ = w.Write([]byte(text))
}

func (s *server) save(w http.ResponseWriter, r *http.Request) {
	text := s.take()
	if text == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	path := s.absEnv()
	var backup string
	if _, err := os.Stat(path); err == nil {
		backup = path + ".bak-" + time.Now().Format("20060102-150405")
		if err := os.Rename(path, backup); err != nil {
			s.render(w, "review", view{Env: text, Errors: []string{"Could not back up the existing file: " + err.Error()}})
			return
		}
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		s.render(w, "review", view{Env: text, Errors: []string{"Could not write " + path + ": " + err.Error()}})
		return
	}
	s.render(w, "saved", view{Saved: path, Backup: backup})
	s.once.Do(func() { close(s.done) })
}
