package mailer

import (
	"strings"
	"testing"
)

func TestRenderAllTemplates(t *testing.T) {
	r, err := NewRenderer(func() string { return "Acme" })
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]string{
		"Link":      "https://app.example.com/verify?token=abc&x=<script>",
		"ExpiresIn": "24 hours",
		"When":      "2026-10-22 10:00 UTC",
		"Action":    "enabled",
	}
	for name := range subjects {
		m, err := r.Render("user@example.com", name, data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.HasPrefix(m.Subject, "Acme: ") || m.Text == "" || m.HTML == "" {
			t.Fatalf("%s: incomplete message %+v", name, m)
		}
		if strings.Contains(m.HTML, "<script>") {
			t.Fatalf("%s: HTML output is not escaped", name)
		}
	}
}

func TestUnknownTemplate(t *testing.T) {
	r, _ := NewRenderer(func() string { return "Acme" })
	if _, err := r.Render("a@b.co", "nope", nil); err == nil {
		t.Fatal("expected error")
	}
}
