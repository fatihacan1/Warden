//go:build integration

package e2e

import (
	"bytes"
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fatihacan1/warden/internal/mailer"
)

var inboxLinkRe = regexp.MustCompile(`/admin/inbox/([0-9a-f-]{36})"`)

func TestInboxStoresEncryptedAndAdminReadsIt(t *testing.T) {
	ctx := context.Background()
	if _, err := A.Store.DeleteAllInbox(ctx); err != nil {
		t.Fatal(err)
	}
	a := adminLogin(t)
	inbox := mailer.NewInbox(A.Store, A.Box, 500)
	secretLink := "https://app.example.com/verify-email?token=SECRET-TOKEN-0123"
	to := "inbox-tester@example.com"
	err := inbox.Send(ctx, mailer.Message{To: to, Subject: "Verify your address", Text: "Open " + secretLink + " now.",
		HTML: `<p>Open <a href="` + secretLink + `">this</a></p><script>alert(1)</script>`})
	if err != nil {
		t.Fatal(err)
	}

	// Nothing readable at rest: recipient, subject and the one-time link are sealed.
	var meta, body []byte
	if err := A.Pool.QueryRow(ctx, `SELECT meta, body FROM inbox_messages LIMIT 1`).Scan(&meta, &body); err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{to, "Verify your address", "SECRET-TOKEN-0123", "verify-email"} {
		if bytes.Contains(meta, []byte(plain)) || bytes.Contains(body, []byte(plain)) {
			t.Fatalf("%q stored in plaintext", plain)
		}
	}

	// List shows recipient and subject.
	res, page := adminDo(t, "GET", "/admin/inbox", a.cookie, nil, nil)
	if res.StatusCode != 200 || !strings.Contains(page, to) || !strings.Contains(page, "Verify your address") {
		t.Fatalf("inbox list: %d", res.StatusCode)
	}
	m := inboxLinkRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no link to the message")
	}
	id := m[1]

	// Detail shows the link for copying, in a sandboxed frame.
	res, page = adminDo(t, "GET", "/admin/inbox/"+id, a.cookie, nil, nil)
	if res.StatusCode != 200 || !strings.Contains(page, `data-copy="`+secretLink+`"`) {
		t.Fatalf("detail: %d", res.StatusCode)
	}
	if !strings.Contains(page, `<iframe name="preview" class="preview-frame" title="Email" sandbox `) {
		t.Fatal("preview frame must carry the sandbox attribute")
	}

	// The frame content is served with a sandboxing CSP and cannot be framed elsewhere.
	res, html := adminDo(t, "GET", "/admin/inbox/"+id+"/preview", a.cookie, nil, nil)
	csp := res.Header.Get("Content-Security-Policy")
	if res.StatusCode != 200 || !strings.Contains(csp, "sandbox") || !strings.Contains(csp, "default-src 'none'") ||
		res.Header.Get("X-Frame-Options") != "SAMEORIGIN" || !strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatalf("preview: %d csp=%q xfo=%q", res.StatusCode, csp, res.Header.Get("X-Frame-Options"))
	}
	if strings.Contains(csp, "script-src") && !strings.Contains(csp, "default-src 'none'") {
		t.Fatal("scripts must stay blocked")
	}
	res, text := adminDo(t, "GET", "/admin/inbox/"+id+"/preview?view=text", a.cookie, nil, nil)
	if res.StatusCode != 200 || !strings.Contains(text, "SECRET-TOKEN-0123") {
		t.Fatalf("text view: %d", res.StatusCode)
	}

	// Garbage ids are not found.
	if res, _ := adminDo(t, "GET", "/admin/inbox/not-a-uuid", a.cookie, nil, nil); res.StatusCode != 404 {
		t.Fatalf("bad id: %d", res.StatusCode)
	}

	// Mutations need CSRF.
	if res, _ := adminDo(t, "POST", "/admin/inbox/"+id+"/delete", a.cookie, url.Values{}, map[string]string{"Origin": "http://admin.test"}); res.StatusCode == 303 && !strings.Contains(res.Header.Get("Location"), "ok=") {
		t.Fatal("delete without CSRF token must not succeed")
	}
	if n, _ := A.Store.CountInbox(ctx); n != 1 {
		t.Fatalf("message deleted without CSRF: %d", n)
	}

	res, _ = adminDo(t, "POST", "/admin/inbox/"+id+"/delete", a.cookie, url.Values{"_csrf": {a.csrf}}, map[string]string{"Origin": "http://admin.test"})
	if res.StatusCode != 303 {
		t.Fatalf("delete: %d", res.StatusCode)
	}
	if n, _ := A.Store.CountInbox(ctx); n != 0 {
		t.Fatalf("not deleted: %d", n)
	}
}

func TestInboxRequiresAdminSession(t *testing.T) {
	ctx := context.Background()
	inbox := mailer.NewInbox(A.Store, A.Box, 500)
	if err := inbox.Send(ctx, mailer.Message{To: "x@example.com", Subject: "s", Text: "t", HTML: "<p>t</p>"}); err != nil {
		t.Fatal(err)
	}
	rows, err := A.Store.ListInbox(ctx, 1, 0)
	if err != nil || len(rows) == 0 {
		t.Fatal("no row", err)
	}
	id := rows[0].ID.String()
	for _, p := range []string{"/admin/inbox", "/admin/inbox/" + id, "/admin/inbox/" + id + "/preview"} {
		for _, cookie := range []string{"", "forged-session"} {
			res, body := adminDo(t, "GET", p, cookie, nil, nil)
			if res.StatusCode != 303 && res.StatusCode != 302 {
				t.Errorf("%s with cookie %q: %d", p, cookie, res.StatusCode)
			}
			if strings.Contains(body, "x@example.com") {
				t.Errorf("%s leaked the message", p)
			}
		}
	}
	// A scoped access token is not an admin session either.
	res, _ := adminDo(t, "POST", "/admin/inbox/clear", "", url.Values{}, nil)
	if res.StatusCode != 303 && res.StatusCode != 302 {
		t.Errorf("clear without session: %d", res.StatusCode)
	}
}

func TestInboxRetention(t *testing.T) {
	ctx := context.Background()
	if _, err := A.Store.DeleteAllInbox(ctx); err != nil {
		t.Fatal(err)
	}
	inbox := mailer.NewInbox(A.Store, A.Box, 3)
	send := func(subject string) {
		t.Helper()
		if err := inbox.Send(ctx, mailer.Message{To: "r@example.com", Subject: subject, Text: "t", HTML: "<p>t</p>"}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		send("m")
	}
	if n, _ := A.Store.CountInbox(ctx); n != 3 {
		t.Fatalf("max not enforced on insert: %d", n)
	}
	// Age two of them past the retention period.
	if _, err := A.Pool.Exec(ctx, `UPDATE inbox_messages SET created_at = now() - interval '8 days' WHERE id IN (SELECT id FROM inbox_messages ORDER BY created_at LIMIT 2)`); err != nil {
		t.Fatal(err)
	}
	n, err := A.Store.PruneInbox(ctx, 500, time.Now().Add(-mailer.InboxRetention))
	if err != nil || n != 2 {
		t.Fatalf("prune removed %d, err %v", n, err)
	}
	if left, _ := A.Store.CountInbox(ctx); left != 1 {
		t.Fatalf("left: %d", left)
	}
	if n, err := A.Store.DeleteAllInbox(ctx); err != nil || n != 1 {
		t.Fatalf("delete all: %d %v", n, err)
	}
}

func TestInboxBannerAndNav(t *testing.T) {
	a := adminLogin(t)
	_, page := adminDo(t, "GET", "/admin/emails", a.cookie, nil, nil)
	if strings.Contains(page, "Test mail mode") {
		t.Fatal("banner shown outside inbox mode")
	}
	if !strings.Contains(page, `href="/admin/inbox"`) {
		t.Fatal("Inbox link missing from the navigation")
	}
	old := A.Config.Mail.Delivery
	A.Config.Mail.Delivery = "inbox"
	defer func() { A.Config.Mail.Delivery = old }()
	_, page = adminDo(t, "GET", "/admin", a.cookie, nil, nil)
	if !strings.Contains(page, "does not send emails") || !strings.Contains(page, "Mail delivery") {
		t.Fatal("persistent warning missing in inbox mode")
	}
	_, page = adminDo(t, "GET", "/admin/emails", a.cookie, nil, nil)
	if !strings.Contains(page, "Test mode: emails go to the Inbox") {
		t.Fatal("emails page does not show the mode")
	}
}
