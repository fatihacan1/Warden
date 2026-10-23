package admin

import (
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/oauthclients"
)

// Service clients (OAuth 2.0 client credentials, service-to-service).

const clientsPath = "/admin/service-clients"

var clientTTLs = []struct {
	Key   string
	Label string
}{
	{"5", "5 min"}, {"15", "15 min"}, {"30", "30 min"}, {"60", "1 hour"},
}

func (s *Server) serviceClientsPage(c fiber.Ctx) error {
	list, err := s.Clients.List(c.Context())
	if err != nil {
		return err
	}
	return s.render(c, fiber.StatusOK, "serviceclients", "clients", "Service clients", map[string]any{
		"Clients": list, "Reveal": s.unstash(c), "Now": time.Now(), "PublicURL": s.Config.HTTP.PublicURL,
		"Graces": oauthclients.GraceOptions, "TTLs": clientTTLs, "DefaultAudience": strings.Join(s.Clients.DefaultAudience(), " "),
	})
}

func (s *Server) createServiceClient(c fiber.Ctx) error {
	minutes, err := strconv.Atoi(c.FormValue("ttl"))
	if err != nil {
		return backErr(c, clientsPath, domain.ErrValidation.WithMessage("Choose how long its tokens last."))
	}
	secret, cl, err := s.Clients.Create(c.Context(), oauthclients.Input{
		Name: c.FormValue("name"), Scopes: oauthclients.SplitList(c.FormValue("scopes")),
		Audiences: lines(c.FormValue("audiences")), TTL: time.Duration(minutes) * time.Minute,
	})
	if err != nil {
		return backErr(c, clientsPath, err)
	}
	s.audit(c, "admin.service_client_created", map[string]any{
		"client_id": cl.ClientID, "name": cl.Name, "scopes": cl.AllowedScopes, "audiences": cl.AllowedAudiences,
	})
	return s.reveal(c, clientsPath, map[string]string{"Value": secret, "Name": cl.Name, "ClientID": cl.ClientID})
}

func (s *Server) rotateServiceClient(c fiber.Ctx) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	var grace time.Duration
	note := "The old secret stopped working."
	for _, g := range oauthclients.GraceOptions {
		if g.Key == c.FormValue("grace") {
			grace = g.D
			if g.D > 0 {
				note = "The old secret keeps working for " + strings.TrimPrefix(strings.ToLower(g.Label), "keep the old secret for ") + ". Update your services before then."
			}
		}
	}
	cl, err := s.Clients.Get(c.Context(), id)
	if err != nil {
		return backErr(c, clientsPath, err)
	}
	secret, err := s.Clients.Rotate(c.Context(), id, grace)
	if err != nil {
		return backErr(c, clientsPath, err)
	}
	s.audit(c, "admin.service_client_rotated", map[string]any{"client_id": cl.ClientID, "grace_seconds": int(grace.Seconds())})
	return s.reveal(c, clientsPath, map[string]string{"Value": secret, "Name": cl.Name, "ClientID": cl.ClientID, "Rotated": "1", "GraceNote": note})
}

func (s *Server) revokeServiceClient(c fiber.Ctx) error {
	id, err := parseUserID(c)
	if err != nil {
		return err
	}
	cl, err := s.Clients.Get(c.Context(), id)
	if err != nil {
		return backErr(c, clientsPath, err)
	}
	if err := s.Clients.Revoke(c.Context(), id); err != nil {
		return backErr(c, clientsPath, err)
	}
	s.audit(c, "admin.service_client_revoked", map[string]any{"client_id": cl.ClientID})
	return back(c, clientsPath, "clientrevoked")
}
