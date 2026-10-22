package mailer

import (
	"context"
	"strings"
	"testing"

	"github.com/fatihacan1/warden/internal/store"
)

func TestRenderAllTemplates(t *testing.T) {
	r, err := NewRenderer(func() string { return "Acme" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]string{
		"Link":      "https://app.example.com/verify?token=abc&x=<script>",
		"ExpiresIn": "24 hours",
		"When":      "2026-10-22 10:00 UTC",
		"Action":    "enabled",
	}
	for _, info := range Templates {
		m, err := r.Render("user@example.com", info.Name, "", data)
		if err != nil {
			t.Fatalf("%s: %v", info.Name, err)
		}
		if !strings.HasPrefix(m.Subject, "Acme: ") || m.Text == "" || m.HTML == "" {
			t.Fatalf("%s: incomplete message %+v", info.Name, m)
		}
		if strings.Contains(m.HTML, "<script>") {
			t.Fatalf("%s: HTML output is not escaped", info.Name)
		}
		if !strings.Contains(m.HTML, "<!doctype html>") {
			t.Fatalf("%s: layout missing", info.Name)
		}
	}
}

func TestUnknownTemplate(t *testing.T) {
	r, _ := NewRenderer(func() string { return "Acme" }, nil)
	for _, name := range []string{"nope", LayoutName} {
		if _, err := r.Render("a@b.co", name, "", nil); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

type memStore struct {
	rows map[string]store.EmailTemplateRow
}

func (m *memStore) ListEmailTemplates(context.Context) ([]store.EmailTemplateRow, error) {
	var out []store.EmailTemplateRow
	for _, r := range m.rows {
		out = append(out, r)
	}
	return out, nil
}

func (m *memStore) SaveEmailTemplate(_ context.Context, r store.EmailTemplateRow) error {
	m.rows[r.Name+"/"+r.Locale] = r
	return nil
}

func (m *memStore) DeleteEmailTemplate(_ context.Context, name, locale string) error {
	delete(m.rows, name+"/"+locale)
	return nil
}

func TestLibraryOverridesAndValidation(t *testing.T) {
	ctx := context.Background()
	r, _ := NewRenderer(func() string { return "Acme" }, nil)
	lib := NewLibrary(&memStore{rows: map[string]store.EmailTemplateRow{}}, r, nil)

	custom := Source{
		Subject: "Welcome to {{.AppName}}!\r\nBcc: attacker@example.com",
		HTML:    `{{template "layout_start" .}}<p>Hi! <a href="{{.Data.Link}}">Verify</a></p>{{template "layout_end" .}}`,
		Text:    "Verify: {{.Data.Link}}",
	}
	if err := lib.Save(ctx, TemplateVerifyEmail, "en", custom); err != nil {
		t.Fatal(err)
	}
	m, err := r.Render("u@example.com", TemplateVerifyEmail, "en", map[string]string{"Link": "https://x.test/v?t=1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(m.Subject, "\r\n") || !strings.HasPrefix(m.Subject, "Welcome to Acme!") {
		t.Fatalf("subject not sanitized: %q", m.Subject)
	}
	if !strings.Contains(m.HTML, "Hi!") || m.Text != "Verify: https://x.test/v?t=1" {
		t.Fatalf("override not used: %+v", m)
	}

	for name, bad := range map[string]Source{
		"syntax":  {Subject: "x", HTML: "{{if}}", Text: "x"},
		"no text": {Subject: "x", HTML: "<p>x</p>", Text: " "},
		"subject": {Subject: "{{.Nope.Deeper}}", HTML: "<p>x</p>", Text: "x"},
	} {
		if err := lib.Save(ctx, TemplateResetPassword, "en", bad); err == nil {
			t.Fatalf("%s: invalid template accepted", name)
		}
	}
	if err := lib.Save(ctx, LayoutName, "en", Source{HTML: "<html>{{.AppName}}</html>"}); err == nil {
		t.Fatal("layout without layout_start/layout_end accepted")
	}

	if err := lib.Reset(ctx, TemplateVerifyEmail, "en"); err != nil {
		t.Fatal(err)
	}
	m, _ = r.Render("u@example.com", TemplateVerifyEmail, "en", map[string]string{"Link": "https://x.test"})
	if strings.Contains(m.HTML, "Hi!") {
		t.Fatal("reset did not restore the built-in template")
	}
}

func TestLocales(t *testing.T) {
	lang := "en"
	r, _ := NewRenderer(func() string { return "Acme" }, func() string { return lang })
	tr, err := r.Render("u@example.com", TemplateResetPassword, "tr-TR", map[string]string{"Link": "https://x.test", "ExpiresIn": "30 dakika"})
	if err != nil || !strings.Contains(tr.Subject, "Şifrenizi sıfırlayın") || !strings.Contains(tr.HTML, `lang="tr"`) {
		t.Fatalf("turkish: %q %v", tr.Subject, err)
	}
	en, _ := r.Render("u@example.com", TemplateResetPassword, "", map[string]string{"Link": "https://x.test"})
	if !strings.Contains(en.Subject, "Reset your password") {
		t.Fatalf("default english: %q", en.Subject)
	}
	lang = "tr" // instance default changes at runtime
	if m, _ := r.Render("u@example.com", TemplateResetPassword, "xx", map[string]string{"Link": "https://x.test"}); !strings.Contains(m.Subject, "Şifrenizi") {
		t.Fatalf("unsupported locale should use the instance default: %q", m.Subject)
	}
	m, _ := r.Render("u@example.com", TemplateMFAChanged, "tr", map[string]string{"Action": "disabled"})
	if !strings.Contains(m.Text, "kapatıldı") {
		t.Fatalf("translated action: %s", m.Text)
	}
}
