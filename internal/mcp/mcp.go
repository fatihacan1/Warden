// Package mcp is a Model Context Protocol server (stdio transport) that
// exposes the Warden admin API as tools for AI agents such as Claude.
//
//	WARDEN_ADMIN_URL=http://localhost:9090 WARDEN_ACCESS_TOKEN=wat_... warden mcp
//
// It holds no privileges of its own: every tool call is an admin API request
// with the configured access token, so the token's permissions, expiry, IP
// ranges and rate limit apply, and every change lands in the audit log. Tools
// the token may not use are not offered at all.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ProtocolVersion is the newest MCP revision this server speaks.
const ProtocolVersion = "2025-06-18"

var supportedVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// Config configures the server.
type Config struct {
	AdminURL string
	Token    string
	Version  string
	Client   *http.Client
	Log      io.Writer // diagnostics (stderr); never stdout
}

type param struct {
	Name        string
	Type        string // string, integer, boolean, array, object
	Description string
	Required    bool
	In          string // "path", "query" or "body"
	Items       string // element type for arrays
}

type tool struct {
	Name        string
	Description string
	Scope       string // resource:level, "" = always
	Method      string
	Path        string
	Params      []param
	ReadOnly    bool
	Destructive bool
}

var (
	pUser    = param{Name: "user_id", Type: "string", Description: "User id (UUID).", Required: true, In: "path"}
	pTplName = param{Name: "name", Type: "string", Description: "Template name: layout, verify_email, reset_password, password_changed, mfa_changed, new_device, account_locked.", Required: true, In: "path"}
	pLang    = param{Name: "lang", Type: "string", Description: "Language code, e.g. en or tr. Defaults to the instance default.", In: "query"}
	pWebhook = param{Name: "webhook_id", Type: "string", Description: "Webhook id (UUID).", Required: true, In: "path"}
	pSubject = param{Name: "subject", Type: "string", Description: "Subject line (Go template; {{.AppName}} and {{.Data.X}} available).", In: "body"}
	pHTML    = param{Name: "html", Type: "string", Description: "HTML body (Go template). Wrap in {{template \"layout_start\" .}} ... {{template \"layout_end\" .}} to use the layout.", In: "body"}
	pText    = param{Name: "text", Type: "string", Description: "Plain text body (Go template).", In: "body"}
)

var tools = []tool{
	{Name: "whoami", Description: "Show this access token's name, permissions and expiry.", Method: "GET", Path: "/token", ReadOnly: true},
	{Name: "get_stats", Description: "User counts, active sessions and delivery queue health.", Scope: "stats:read", Method: "GET", Path: "/stats", ReadOnly: true},

	{Name: "list_users", Description: "List or search users (email, name or id), newest first.", Scope: "users:read", Method: "GET", Path: "/users", ReadOnly: true,
		Params: []param{{Name: "q", Type: "string", Description: "Search text.", In: "query"}, {Name: "page", Type: "integer", In: "query"}, {Name: "per_page", Type: "integer", Description: "1 to 200, default 50.", In: "query"}}},
	{Name: "get_user", Description: "A user with active sessions, linked accounts and recent security events.", Scope: "users:read", Method: "GET", Path: "/users/{user_id}", ReadOnly: true, Params: []param{pUser}},
	{Name: "create_user", Description: "Create a user. Works even when sign-ups are off. Without a password the user signs in socially or resets it.", Scope: "users:write", Method: "POST", Path: "/users",
		Params: []param{{Name: "email", Type: "string", Required: true, In: "body"}, {Name: "password", Type: "string", In: "body"}, {Name: "name", Type: "string", In: "body"},
			{Name: "roles", Type: "array", Items: "string", Description: "Lowercase role names.", In: "body"}, {Name: "email_verified", Type: "boolean", In: "body"}, {Name: "locale", Type: "string", Description: "Email language (en, tr).", In: "body"}}},
	{Name: "update_user", Description: "Change a user's name, roles (replaces the list), email language or disabled state. Disabling signs the user out everywhere.", Scope: "users:write", Method: "PATCH", Path: "/users/{user_id}",
		Params: []param{pUser, {Name: "name", Type: "string", In: "body"}, {Name: "roles", Type: "array", Items: "string", In: "body"}, {Name: "locale", Type: "string", In: "body"}, {Name: "disabled", Type: "boolean", In: "body"}}},
	{Name: "sign_out_user_everywhere", Description: "End every session of a user.", Scope: "users:write", Method: "DELETE", Path: "/users/{user_id}/sessions", Params: []param{pUser}, Destructive: true},

	{Name: "get_settings", Description: "Current feature toggles and policies.", Scope: "settings:read", Method: "GET", Path: "/settings", ReadOnly: true},
	{Name: "update_settings", Description: "Change settings. Pass only the fields to change, using the names returned by get_settings. Admin access settings cannot be changed here.", Scope: "settings:write", Method: "PATCH", Path: "/settings",
		Params: []param{{Name: "settings", Type: "object", Description: "Fields to change, e.g. {\"allow_signup\": false}.", Required: true, In: "body-root"}}},

	{Name: "list_email_templates", Description: "All email templates, their variables and which languages are customized.", Scope: "email_templates:read", Method: "GET", Path: "/email-templates", ReadOnly: true},
	{Name: "get_email_template", Description: "A template's subject, HTML and text in one language, with its variables and sample data.", Scope: "email_templates:read", Method: "GET", Path: "/email-templates/{name}", ReadOnly: true, Params: []param{pTplName, pLang}},
	{Name: "preview_email_template", Description: "Render a template with sample data without saving. Omitted fields use the current version.", Scope: "email_templates:read", Method: "POST", Path: "/email-templates/{name}/preview", ReadOnly: true,
		Params: []param{pTplName, pLang, pSubject, pHTML, pText}},
	{Name: "update_email_template", Description: "Save a template in one language. Omitted fields keep their current value. Invalid templates are rejected.", Scope: "email_templates:write", Method: "PUT", Path: "/email-templates/{name}",
		Params: []param{pTplName, pLang, pSubject, pHTML, pText}},
	{Name: "reset_email_template", Description: "Discard customizations of a template in one language and use the built-in version.", Scope: "email_templates:write", Method: "DELETE", Path: "/email-templates/{name}", Params: []param{pTplName, pLang}, Destructive: true},

	{Name: "list_webhooks", Description: "Webhook endpoints and the event types available.", Scope: "webhooks:read", Method: "GET", Path: "/webhooks", ReadOnly: true},
	{Name: "list_webhook_deliveries", Description: "Recent deliveries of one endpoint with status and errors.", Scope: "webhooks:read", Method: "GET", Path: "/webhooks/{webhook_id}/deliveries", ReadOnly: true, Params: []param{pWebhook}},
	{Name: "create_webhook", Description: "Add an endpoint. Returns its signing secret once.", Scope: "webhooks:write", Method: "POST", Path: "/webhooks",
		Params: []param{{Name: "url", Type: "string", Required: true, In: "body"}, {Name: "description", Type: "string", In: "body"}, {Name: "events", Type: "array", Items: "string", Description: "Event types; empty = all.", In: "body"}}},
	{Name: "update_webhook", Description: "Change an endpoint's URL, description, events or enabled state.", Scope: "webhooks:write", Method: "PATCH", Path: "/webhooks/{webhook_id}",
		Params: []param{pWebhook, {Name: "url", Type: "string", In: "body"}, {Name: "description", Type: "string", In: "body"}, {Name: "events", Type: "array", Items: "string", In: "body"}, {Name: "enabled", Type: "boolean", In: "body"}}},
	{Name: "delete_webhook", Description: "Delete an endpoint and its queued deliveries.", Scope: "webhooks:write", Method: "DELETE", Path: "/webhooks/{webhook_id}", Params: []param{pWebhook}, Destructive: true},
	{Name: "test_webhook", Description: "Queue a webhook.test event to an endpoint.", Scope: "webhooks:write", Method: "POST", Path: "/webhooks/{webhook_id}/test", Params: []param{pWebhook}},

	{Name: "list_api_keys", Description: "Publishable and secret keys (never their values).", Scope: "api_keys:read", Method: "GET", Path: "/api-keys", ReadOnly: true},
	{Name: "create_api_key", Description: "Create a publishable key (for an app) or a secret key (for a backend). Returns the value once.", Scope: "api_keys:write", Method: "POST", Path: "/api-keys",
		Params: []param{{Name: "kind", Type: "string", Description: "publishable or secret.", Required: true, In: "body"}, {Name: "name", Type: "string", Required: true, In: "body"}, {Name: "allowed_origins", Type: "array", Items: "string", Description: "Browser origins for a publishable key.", In: "body"}}},
	{Name: "revoke_api_key", Description: "Revoke a key immediately.", Scope: "api_keys:write", Method: "DELETE", Path: "/api-keys/{key_id}",
		Params: []param{{Name: "key_id", Type: "string", Required: true, In: "path"}}, Destructive: true},

	{Name: "list_providers", Description: "Sign-in providers, whether they are on, and their callback URLs.", Scope: "providers:read", Method: "GET", Path: "/providers", ReadOnly: true},
	{Name: "get_audit_log", Description: "Recent security and admin events, optionally for one user.", Scope: "audit:read", Method: "GET", Path: "/audit", ReadOnly: true,
		Params: []param{{Name: "user_id", Type: "string", In: "query"}, {Name: "limit", Type: "integer", Description: "1 to 500, default 50.", In: "query"}}},
}

func (t tool) schema() map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, p := range t.Params {
		if p.In == "body-root" {
			return map[string]any{"type": "object", "properties": map[string]any{p.Name: map[string]any{"type": "object", "description": p.Description}}, "required": []string{p.Name}}
		}
		s := map[string]any{"type": p.Type}
		if p.Description != "" {
			s["description"] = p.Description
		}
		if p.Type == "array" {
			s["items"] = map[string]any{"type": p.Items}
		}
		props[p.Name] = s
		if p.Required {
			required = append(required, p.Name)
		}
	}
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

func (t tool) allowed(scopes []string) bool {
	if t.Scope == "" || scopes == nil {
		return true
	}
	res, level, _ := strings.Cut(t.Scope, ":")
	for _, s := range scopes {
		if s == res+":write" || s == res+":"+level {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// JSON-RPC

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type server struct {
	cfg    Config
	mu     sync.Mutex
	out    *bufio.Writer
	scopes []string
}

// Serve runs until in is closed or ctx is cancelled.
func Serve(ctx context.Context, in io.Reader, out io.Writer, cfg Config) error {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	cfg.AdminURL = strings.TrimRight(cfg.AdminURL, "/")
	s := &server{cfg: cfg, out: bufio.NewWriter(out)}
	if u, err := url.Parse(cfg.AdminURL); err != nil || u.Host == "" {
		return fmt.Errorf("mcp: WARDEN_ADMIN_URL must be an absolute URL, like http://localhost:9090")
	} else if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		fmt.Fprintln(cfg.Log, "warden mcp: warning: the access token is sent over plain http to", u.Host, "- use an SSH tunnel, a VPN or https")
	}
	if !strings.HasPrefix(cfg.Token, "wat_") {
		return fmt.Errorf("mcp: WARDEN_ACCESS_TOKEN must be an access token (wat_...) from the admin UI")
	}
	s.loadScopes(ctx)

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 8<<20)
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.write(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		s.handle(ctx, req)
	}
	return sc.Err()
}

// loadScopes asks the API which permissions the token has, to list only the
// tools it can use. On failure every tool is listed and the API decides.
func (s *server) loadScopes(ctx context.Context) {
	status, body, err := s.call(ctx, "GET", "/token", nil)
	if err != nil || status != 200 {
		fmt.Fprintf(s.cfg.Log, "warden mcp: could not read token permissions (status %d, %v): %s\n", status, err, strings.TrimSpace(string(body)))
		return
	}
	var t struct {
		Scopes []string `json:"scopes"`
	}
	if json.Unmarshal(body, &t) == nil {
		s.scopes = t.Scopes
	}
}

func (s *server) write(r response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(r)
	_, err := s.out.Write(append(b, '\n'))
	if err == nil {
		err = s.out.Flush()
	}
	if err != nil {
		fmt.Fprintln(s.cfg.Log, "warden mcp: write failed:", err)
	}
}

func (s *server) handle(ctx context.Context, req request) {
	notification := len(req.ID) == 0
	reply := func(result any, err *rpcError) {
		if notification {
			return
		}
		s.write(response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: err})
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := ProtocolVersion
		for _, v := range supportedVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		reply(map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "warden", "title": "Warden admin", "version": s.cfg.Version},
			"instructions": "Tools manage a Warden authentication instance through its admin API, limited to this access token's permissions. " +
				"Prefer read tools first. Email templates are Go templates: keep {{template \"layout_start\" .}}/{{template \"layout_end\" .}} and the {{.Data.X}} variables listed by get_email_template; preview before saving. " +
				"Never invent user ids: look them up with list_users.",
		}, nil)
	case "notifications/initialized", "notifications/cancelled":
	case "ping":
		reply(map[string]any{}, nil)
	case "tools/list":
		list := []map[string]any{}
		for _, t := range tools {
			if !t.allowed(s.scopes) {
				continue
			}
			list = append(list, map[string]any{
				"name": t.Name, "description": t.Description, "inputSchema": t.schema(),
				"annotations": map[string]any{"readOnlyHint": t.ReadOnly, "destructiveHint": t.Destructive, "openWorldHint": false},
			})
		}
		reply(map[string]any{"tools": list}, nil)
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			reply(nil, &rpcError{Code: -32602, Message: "invalid params"})
			return
		}
		reply(s.callTool(ctx, p.Name, p.Arguments), nil)
	default:
		reply(nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method})
	}
}

func textResult(text string, isError bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isError}
}

func (s *server) callTool(ctx context.Context, name string, args map[string]any) map[string]any {
	var t *tool
	for i := range tools {
		if tools[i].Name == name {
			t = &tools[i]
		}
	}
	if t == nil || !t.allowed(s.scopes) {
		return textResult("Unknown tool or not allowed for this token: "+name, true)
	}
	path := t.Path
	query := url.Values{}
	body := map[string]any{}
	var rootBody any
	for _, p := range t.Params {
		v, ok := args[p.Name]
		if !ok || v == nil {
			if p.Required {
				return textResult("Missing required argument: "+p.Name, true)
			}
			continue
		}
		switch p.In {
		case "path":
			sv := fmt.Sprint(v)
			if sv == "" || strings.ContainsAny(sv, "/?#") || sv == "." || sv == ".." {
				return textResult("Invalid "+p.Name, true)
			}
			path = strings.ReplaceAll(path, "{"+p.Name+"}", url.PathEscape(sv))
		case "query":
			query.Set(p.Name, fmt.Sprint(v))
		case "body-root":
			rootBody = v
		default:
			body[p.Name] = v
		}
	}
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	var payload any
	switch {
	case rootBody != nil:
		payload = rootBody
	case len(body) > 0 || t.Method == "POST" || t.Method == "PUT" || t.Method == "PATCH":
		payload = body
	}
	status, resp, err := s.call(ctx, t.Method, path, payload)
	if err != nil {
		return textResult("Request failed: "+err.Error(), true)
	}
	text := string(resp)
	var pretty bytes.Buffer
	if json.Indent(&pretty, resp, "", "  ") == nil {
		text = pretty.String()
	}
	if status == http.StatusNoContent {
		text = "Done."
	}
	return textResult(text, status >= 400)
}

func (s *server) call(ctx context.Context, method, path string, payload any) (int, []byte, error) {
	var rdr io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.cfg.AdminURL+"/api/v1"+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("User-Agent", "warden-mcp/"+s.cfg.Version)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, err
}

// FromEnv reads the configuration from WARDEN_ADMIN_URL and
// WARDEN_ACCESS_TOKEN.
func FromEnv(version string) Config {
	u := os.Getenv("WARDEN_ADMIN_URL")
	if u == "" {
		u = "http://localhost:9090"
	}
	return Config{AdminURL: u, Token: os.Getenv("WARDEN_ACCESS_TOKEN"), Version: version, Log: os.Stderr}
}
