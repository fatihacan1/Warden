package admin

import (
	"net"
	"slices"

	"github.com/gofiber/fiber/v3"
)

// The admin IP allowlist is a second layer. The first should be the network:
// keep ADMIN_ADDR off the internet and reach it over a VPN, an SSH tunnel or
// a private network, where a firewall decides who connects at all.
//
// It checks the address of the direct peer (the admin server trusts no proxy
// headers). Behind a reverse proxy every request has the proxy's address, so
// list that only if the proxy itself restricts access. ADMIN_IP_ALLOWLIST_DISABLED
// is the way back in after a lockout.

// ipAllowed reports whether ip matches one of the entries (IPs or CIDRs).
func ipAllowed(ip string, entries []string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, e := range entries {
		if _, n, err := net.ParseCIDR(e); err == nil {
			if n.Contains(addr) {
				return true
			}
		} else if other := net.ParseIP(e); other != nil && other.Equal(addr) {
			return true
		}
	}
	return false
}

func (s *Server) ipAllowlist(c fiber.Ctx) error {
	if s.Config.Admin.IPAllowlistDisabled {
		return c.Next()
	}
	rt := s.Settings.Get()
	if !rt.AdminIPAllowlist || ipAllowed(c.IP(), rt.AdminAllowedIPs) {
		return c.Next()
	}
	s.Log.Warn("admin request from an address outside the allowlist", "ip", c.IP(), "path", c.Path())
	c.Type("txt")
	return c.Status(fiber.StatusForbidden).SendString("This address (" + c.IP() + ") may not use the admin UI. " +
		"Ask an administrator to add it, or restart Warden with ADMIN_IP_ALLOWLIST_DISABLED=true to get back in.")
}

// withCurrentIP adds the admin's own address when the allowlist is turned on,
// so saving the setting can never lock out the person saving it.
func withCurrentIP(enabled bool, entries []string, ip string) ([]string, bool) {
	if !enabled || ip == "" || ipAllowed(ip, entries) {
		return entries, false
	}
	return append(slices.Clone(entries), ip), true
}
