//go:build integration

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fatihacan1/warden/internal/mcp"
)

func (a *adminClient) createToken(name, duration string, scopes map[string]string, ips string) string {
	a.t.Helper()
	form := url.Values{"_csrf": {a.csrf}, "name": {name}, "duration": {duration}, "allowed_ips": {ips}}
	for k, v := range scopes {
		form.Set("scope_"+k, v)
	}
	res, _ := adminDo(a.t, "POST", "/admin/access-tokens", a.cookie, form, nil)
	if hasFlashError(res) {
		a.t.Fatalf("create token %q failed", name)
	}
	loc := res.Header.Get("Location")
	_, page := adminDo(a.t, "GET", loc, a.cookie, nil, nil)
	i := strings.Index(page, "<code>wat_")
	if i < 0 {
		a.t.Fatal("token not revealed")
	}
	tok := page[i+len("<code>"):]
	return tok[:strings.Index(tok, "</code>")]
}

func apiDo(t *testing.T, method, path, token string, body any, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, "http://admin.test/api/v1"+path, rdr)
	req.Host = "admin.test"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := A.Admin.App().Test(req, fiberTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func apiCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func TestAccessTokensAndAdminAPI(t *testing.T) {
	a := adminLogin(t)
	tok := a.createToken("Claude: emails", "1h", map[string]string{"email_templates": "write", "users": "read"}, "")
	if !strings.HasPrefix(tok, "wat_") {
		t.Fatalf("token %q", tok)
	}
	_, page := adminDo(t, "GET", "/admin/access-tokens", a.cookie, nil, nil)
	if strings.Contains(page, tok) {
		t.Fatal("token value rendered on the list page")
	}

	if st, me := apiDo(t, "GET", "/token", tok, nil, nil); st != 200 || !strings.Contains(strings.Join(toStrings(me["scopes"]), ","), "email_templates:write") {
		t.Fatalf("whoami: %d %v", st, me)
	}
	if st, body := apiDo(t, "GET", "/users?per_page=5", tok, nil, nil); st != 200 || body["users"] == nil {
		t.Fatalf("list users: %d", st)
	}

	// Least privilege: no users:write, no settings at all.
	if st, body := apiDo(t, "POST", "/users", tok, map[string]any{"email": randEmail()}, nil); st != 403 || apiCode(body) != "insufficient_scope" {
		t.Fatalf("create user without users:write: %d %v", st, body)
	}
	if st, _ := apiDo(t, "GET", "/settings", tok, nil, nil); st != 403 {
		t.Fatalf("settings without permission: %d", st)
	}

	// Email templates: read, preview, change only the subject, reset.
	st, tpl := apiDo(t, "GET", "/email-templates/reset_password?lang=tr", tok, nil, nil)
	if st != 200 || tpl["locale"] != "tr" || !strings.Contains(tpl["subject"].(string), "Şifrenizi") {
		t.Fatalf("get template: %d %v", st, tpl)
	}
	if st, prev := apiDo(t, "POST", "/email-templates/reset_password/preview?lang=tr", tok, map[string]any{"subject": "Yeni konu {{.AppName}}"}, nil); st != 200 || !strings.HasPrefix(prev["subject"].(string), "Yeni konu ") {
		t.Fatalf("preview: %d %v", st, prev)
	}
	if st, saved := apiDo(t, "PUT", "/email-templates/reset_password?lang=tr", tok, map[string]any{"subject": "Şifre sıfırlama: {{.AppName}}"}, nil); st != 200 || saved["customized"] != true {
		t.Fatalf("save: %d %v", st, saved)
	}
	if s, _ := A.Renderer.Effective("reset_password", "tr"); s.Subject != "Şifre sıfırlama: {{.AppName}}" || !strings.Contains(s.HTML, "layout_start") {
		t.Fatalf("subject-only save changed the body or did not apply: %q", s.Subject)
	}
	if st, body := apiDo(t, "PUT", "/email-templates/reset_password?lang=tr", tok, map[string]any{"html": "{{if}}"}, nil); st != 422 {
		t.Fatalf("broken template accepted: %d %v", st, body)
	}
	if st, body := apiDo(t, "PUT", "/email-templates/reset_password?lang=tr", tok, map[string]any{"bogus": 1}, nil); st != 422 {
		t.Fatalf("unknown field accepted: %d %v", st, body)
	}
	apiDo(t, "DELETE", "/email-templates/reset_password?lang=tr", tok, nil, nil)
	audit, _ := A.Store.ListAudit(context.Background(), nil, 20)
	found := false
	for _, e := range audit {
		if e.Type == "api.email_template_saved" && e.Metadata["token_name"] == "Claude: emails" {
			found = true
		}
	}
	if !found {
		t.Fatal("API write not in the audit log with the token name")
	}

	// Browsers are refused, even with a valid token.
	if st, body := apiDo(t, "GET", "/token", tok, nil, map[string]string{"Origin": "https://evil.example.com"}); st != 403 || apiCode(body) != "browser_request" {
		t.Fatalf("browser request: %d", st)
	}
	if st, body := apiDo(t, "GET", "/token", "wat_bogus_bogus_bogus_bogus_bogus", nil, nil); st != 401 || apiCode(body) != "invalid_token" {
		t.Fatalf("bogus token: %d %v", st, body)
	}

	// Expiry and revocation take effect immediately.
	if _, err := A.Store.Pool().Exec(context.Background(), `UPDATE access_tokens SET expires_at = now() - interval '1 minute' WHERE name = 'Claude: emails'`); err != nil {
		t.Fatal(err)
	}
	if st, body := apiDo(t, "GET", "/token", tok, nil, nil); st != 401 || apiCode(body) != "token_expired" {
		t.Fatalf("expired token: %d %v", st, body)
	}
	tok2 := a.createToken("Ops", "1d", map[string]string{"settings": "write"}, "")
	if st, body := apiDo(t, "PATCH", "/settings", tok2, map[string]any{"admin_ip_allowlist": true, "admin_allowed_ips": []string{"203.0.113.1"}}, nil); st != 403 {
		t.Fatalf("token changed admin access: %d %v", st, body)
	}
	if st, body := apiDo(t, "PATCH", "/settings", tok2, map[string]any{"app_name": "Acme"}, nil); st != 200 || A.Settings.Get().AppName != "Acme" {
		t.Fatalf("patch settings: %d %v", st, body)
	}
	A.Settings.Reset(context.Background())
	var id string
	_ = A.Store.Pool().QueryRow(context.Background(), `SELECT id::text FROM access_tokens WHERE name = 'Ops'`).Scan(&id)
	adminDo(t, "POST", "/admin/access-tokens/"+id+"/revoke", a.cookie, url.Values{"_csrf": {a.csrf}}, nil)
	if st, body := apiDo(t, "GET", "/token", tok2, nil, nil); st != 401 || apiCode(body) != "token_revoked" {
		t.Fatalf("revoked token: %d %v", st, body)
	}

	// IP-bound tokens only work from their ranges.
	tok3 := a.createToken("Pinned", "1h", map[string]string{"stats": "read"}, "198.51.100.0/24")
	if st, body := apiDo(t, "GET", "/stats", tok3, nil, nil); st != 403 || apiCode(body) != "ip_not_allowed" {
		t.Fatalf("token used outside its range: %d %v", st, body)
	}

	// Invalid requests from the UI.
	res, _ := adminDo(t, "POST", "/admin/access-tokens", a.cookie, url.Values{"_csrf": {a.csrf}, "name": {"x"}, "duration": {"forever"}, "scope_stats": {"read"}}, nil)
	if !hasFlashError(res) {
		t.Fatal("token without expiry accepted")
	}
	res, _ = adminDo(t, "POST", "/admin/access-tokens", a.cookie, url.Values{"_csrf": {a.csrf}, "name": {"x"}, "duration": {"1h"}, "scope_audit": {"write"}}, nil)
	if !hasFlashError(res) {
		t.Fatal("write on a read-only resource accepted")
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// The MCP server lists only the tools a token allows and proxies calls to the
// admin API.
func TestMCPServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = A.Admin.App().Listener(ln) }()
	a := adminLogin(t)
	tok := a.createToken("MCP test", "1h", map[string]string{"email_templates": "read", "users": "read"}, "")

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = mcp.Serve(ctx, inR, outW, mcp.Config{AdminURL: "http://" + ln.Addr().String(), Token: tok, Version: "test"})
		outW.Close()
	}()
	out := bufio.NewScanner(outR)
	out.Buffer(make([]byte, 1<<20), 8<<20)
	send := func(id int, method string, params any) map[string]any {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		if _, err := inW.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
		done := make(chan bool, 1)
		var resp map[string]any
		go func() { done <- out.Scan() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: no answer", method)
		}
		_ = json.Unmarshal(out.Bytes(), &resp)
		return resp
	}

	init := send(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test"}})
	if r, _ := init["result"].(map[string]any); r["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize: %v", init)
	}
	inW.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"))

	list := send(2, "tools/list", map[string]any{})
	var names []string
	for _, x := range list["result"].(map[string]any)["tools"].([]any) {
		names = append(names, x.(map[string]any)["name"].(string))
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "get_email_template") || !strings.Contains(joined, "list_users") ||
		strings.Contains(joined, "update_email_template") || strings.Contains(joined, "create_user") || strings.Contains(joined, "get_settings") {
		t.Fatalf("tools not filtered by permissions: %s", joined)
	}

	call := send(3, "tools/call", map[string]any{"name": "get_email_template", "arguments": map[string]any{"name": "verify_email", "lang": "tr"}})
	res := call["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] == true || !strings.Contains(text, "E-posta adresinizi") {
		t.Fatalf("tool call: %v", call)
	}
	// A tool outside the token's permissions is refused locally.
	denied := send(4, "tools/call", map[string]any{"name": "update_email_template", "arguments": map[string]any{"name": "verify_email", "subject": "x"}})
	if denied["result"].(map[string]any)["isError"] != true {
		t.Fatal("tool outside the token's permissions ran")
	}
	inW.Close()
}
