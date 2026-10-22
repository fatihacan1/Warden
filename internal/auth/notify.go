package auth

import (
	"context"
	"crypto/sha256"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/i18n"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/store"
)

// Security notifications, modeled on what hosted auth providers send:
//
//   - New device sign-in: the first time an account signs in from a device
//     (browser or app + operating system) it has not used in the last 180
//     days. The very first device of an account never triggers it, so new
//     accounts and accounts that existed before the feature are not emailed.
//     At most 3 per account per hour, so an attack cannot flood the inbox.
//     The email has a link that ends that one session (behind a confirmation
//     page, because mail scanners open links).
//   - Account locked: once, when failed passwords reach the lockout threshold.
//   - Password changed and two-factor changed: always (see account.go, mfa.go).

const (
	deviceRetention        = 180 * 24 * time.Hour
	newDeviceMailsPerHour  = 3
	endSessionLinkLifetime = 7 * 24 * time.Hour
)

// locale is the email language of a user: their own choice, else the
// instance default.
func (s *Service) locale(u *domain.User) string {
	if l := i18n.Normalize(u.Locale); l != "" {
		return l
	}
	if l := i18n.Normalize(s.Settings.Get().DefaultLocale); l != "" {
		return l
	}
	return i18n.Default
}

// describeDevice turns a user agent into "Chrome on Windows" and a stable key
// that ignores versions, so browser updates are not new devices.
func describeDevice(ua string) (label, key string) {
	browser := ""
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/"):
		browser = "Opera"
	case strings.Contains(ua, "SamsungBrowser/"):
		browser = "Samsung Internet"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"), strings.Contains(ua, "CriOS/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/") && strings.Contains(ua, "Version/"):
		browser = "Safari"
	case strings.Contains(ua, "okhttp"), strings.Contains(ua, "Dalvik"):
		browser = "Android app"
	case strings.Contains(ua, "CFNetwork"):
		browser = "iOS app"
	case strings.HasPrefix(ua, "Dart/"):
		browser = "Flutter app"
	case ua != "":
		browser, _, _ = strings.Cut(ua, "/")
		if len(browser) > 40 {
			browser = browser[:40]
		}
	}
	os := ""
	switch {
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"), strings.Contains(ua, "iPod"), strings.Contains(ua, "CFNetwork"):
		os = "iOS"
	case strings.Contains(ua, "Android"), strings.Contains(ua, "okhttp"), strings.Contains(ua, "Dalvik"):
		os = "Android"
	case strings.Contains(ua, "CrOS"):
		os = "ChromeOS"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		os = "macOS"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}
	if browser == "" {
		return "", "unknown"
	}
	label = browser
	if os != "" && !strings.HasSuffix(browser, " app") {
		label += " on " + os
	}
	return label, strings.ToLower(browser + "|" + os)
}

func deviceFingerprint(userID uuid.UUID, key string) []byte {
	sum := sha256.Sum256([]byte("device:" + userID.String() + ":" + key))
	return sum[:]
}

// methodLabel describes how a session was authenticated, for emails.
func (s *Service) methodLabel(amr []string, locale string) string {
	label := ""
	for _, m := range amr {
		if p, ok := strings.CutPrefix(m, "oauth:"); ok {
			label = p
			if d := s.OAuth.Definition(p); d != nil {
				label = d.DisplayName
			}
		} else if m == domain.AMRPassword {
			label = i18n.T(locale, "password")
		}
	}
	for _, m := range amr {
		if m == domain.AMRMFA {
			label += " + " + i18n.T(locale, "two_factor")
			break
		}
	}
	return label
}

// recordDevice runs inside the sign-in transaction: it remembers the device
// and, the first time an existing account uses it, queues the notice.
func (s *Service) recordDevice(ctx context.Context, tx *store.Store, u *domain.User, sid uuid.UUID, amr []string, meta domain.RequestMeta) error {
	label, key := describeDevice(meta.UserAgent)
	known, err := tx.HasDevices(ctx, u.ID)
	if err != nil {
		return err
	}
	isNew, err := tx.SeenDevice(ctx, u.ID, deviceFingerprint(u.ID, key), label)
	if err != nil || !isNew || !known || !s.Settings.Get().NotifyNewDevice || u.Email == "" {
		return err
	}
	if !s.allowNotice(ctx, "newdev:"+u.ID.String(), newDeviceMailsPerHour, time.Hour) {
		s.Log.Warn("new device notices rate limited", "user_id", u.ID)
		return nil
	}
	loc := s.locale(u)
	if label == "" {
		label = i18n.T(loc, "unknown_device")
	}
	data := map[string]string{
		"Device": label, "IP": meta.IP, "Location": meta.Country, "Method": s.methodLabel(amr, loc),
		"When": i18n.Time(time.Now(), loc),
	}
	if link, err := s.endSessionLink(ctx, u.ID, sid); err == nil {
		data["SignOutLink"] = link
	} else {
		s.Log.Warn("could not create sign-out link", "err", err)
	}
	s.audit(ctx, u.ID, "user.new_device", meta, map[string]any{"device": label})
	return s.Events.Email(ctx, tx, u.Email, loc, mailer.TemplateNewDevice, data)
}

// allowNotice is a small per-account counter so notices cannot be used to
// flood someone's inbox. Fails open: a Redis outage only means more emails.
func (s *Service) allowNotice(ctx context.Context, key string, limit int64, window time.Duration) bool {
	k := "notice:" + key
	n, err := s.Redis.Incr(ctx, k).Result()
	if err != nil {
		return true
	}
	if n == 1 {
		s.Redis.Expire(ctx, k, window)
	}
	return n <= limit
}

type endSessionRecord struct {
	UserID    string `json:"u"`
	SessionID string `json:"s"`
}

// endSessionLink creates a single-use link that ends one session.
func (s *Service) endSessionLink(ctx context.Context, userID, sid uuid.UUID) (string, error) {
	tok := randtoken.New(32)
	if err := s.putJSON(ctx, "endsess:"+randtoken.HashHex(tok), endSessionRecord{UserID: userID.String(), SessionID: sid.String()}, endSessionLinkLifetime); err != nil {
		return "", err
	}
	return s.cfg.HTTP.PublicURL + "/v1/auth/sessions/end?token=" + tok, nil
}

// EndSessionFromEmail ends the session named by a link from a new device
// email. The link works once.
func (s *Service) EndSessionFromEmail(ctx context.Context, tok string, meta domain.RequestMeta) error {
	if tok == "" || len(tok) > 128 {
		return domain.ErrInvalidToken
	}
	var rec endSessionRecord
	if err := s.takeJSON(ctx, "endsess:"+randtoken.HashHex(tok), &rec); err != nil {
		return err
	}
	uid, err1 := uuid.Parse(rec.UserID)
	sid, err2 := uuid.Parse(rec.SessionID)
	if err1 != nil || err2 != nil {
		return domain.ErrInvalidToken
	}
	err := s.RevokeSession(ctx, uid, sid, domain.RevokeFromEmail, meta)
	if err != nil && domain.AsError(err) != nil && domain.AsError(err).Code == domain.ErrNotFound.Code {
		return nil // already signed out
	}
	return err
}

// noticeLocked emails the owner once when failed passwords lock the account.
func (s *Service) noticeLocked(ctx context.Context, u *domain.User, failures int, meta domain.RequestMeta) {
	if !s.Settings.Get().NotifyAccountLocked || u.Email == "" || failures != s.Settings.Get().LockoutThreshold {
		return
	}
	loc := s.locale(u)
	err := s.Store.InTx(ctx, func(tx *store.Store) error {
		return s.Events.Email(ctx, tx, u.Email, loc, mailer.TemplateAccountLocked, map[string]string{
			"Attempts": strconv.Itoa(failures), "Duration": i18n.Duration(s.cfg.Auth.LockoutWindow, loc), "IP": meta.IP,
			"When": i18n.Time(time.Now(), loc),
		})
	})
	if err != nil {
		s.Log.Warn("account locked notice failed", "err", err)
	}
}

// SetLocale changes a user's email language ("" = instance default).
func (s *Service) SetLocale(ctx context.Context, userID uuid.UUID, locale string) (*domain.User, error) {
	if locale != "" {
		if locale = i18n.Normalize(locale); locale == "" {
			return nil, domain.ErrValidation.WithFields(map[string]string{"locale": "Unsupported language."})
		}
	}
	err := s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.UpdateUserLocale(ctx, userID, locale); err != nil {
			return err
		}
		return s.Events.Event(ctx, tx, events.UserUpdated, userID, map[string]any{"fields": []string{"locale"}})
	})
	if err != nil {
		return nil, err
	}
	return s.Store.GetUserByID(ctx, userID)
}

// firstLocale returns the first supported locale, or "".
func firstLocale(candidates ...string) string {
	for _, c := range candidates {
		if l := i18n.Normalize(c); l != "" {
			return l
		}
	}
	return ""
}

// DescribeDevice returns a readable device name ("Chrome on Windows") for a
// user agent, or "" when unknown.
func DescribeDevice(ua string) string {
	label, _ := describeDevice(ua)
	return label
}
