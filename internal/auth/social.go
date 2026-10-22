package auth

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/oauth"
	"github.com/fatihacan1/warden/internal/store"
)

// AuthorizeInput starts a browser OAuth flow.
type AuthorizeInput struct {
	Provider      string
	RedirectURI   string
	State         string
	CodeChallenge string
	Method        string
}

// AuthorizeURL validates the request and returns the provider consent URL.
func (s *Service) AuthorizeURL(ctx context.Context, in AuthorizeInput) (string, error) {
	p, ok := s.OAuth.Get(in.Provider)
	if !ok {
		return "", domain.ErrProviderDisabled
	}
	if !oauth.RedirectAllowed(s.Settings.Get().AllowedRedirectURIs, in.RedirectURI) {
		return "", domain.ErrInvalidRedirect
	}
	if in.Method != "S256" || !oauth.ValidPKCEValue(in.CodeChallenge) || len(in.CodeChallenge) != 43 {
		return "", domain.ErrValidation.WithMessage("code_challenge (S256, base64url) is required.")
	}
	if len(in.State) > 512 {
		return "", domain.ErrValidation.WithMessage("state is too long.")
	}
	verifier := randtoken.New(32) // 43 chars, valid PKCE verifier
	nonce := randtoken.New(16)
	key, err := s.Flow.SaveState(ctx, oauth.State{
		Provider: in.Provider, RedirectURI: in.RedirectURI, ClientState: in.State,
		CodeChallenge: in.CodeChallenge, Nonce: nonce, Verifier: verifier,
	})
	if err != nil {
		return "", err
	}
	return p.AuthURL(key, nonce, verifier), nil
}

// CallbackResult tells the transport where to send the browser.
type CallbackResult struct {
	RedirectURL string
}

// HandleCallback completes the provider leg and redirects back to the app
// with a one-time login code (or an error code).
func (s *Service) HandleCallback(ctx context.Context, provider string, params url.Values, meta domain.RequestMeta) (*CallbackResult, error) {
	st, err := s.Flow.TakeState(ctx, params.Get("state"))
	if err != nil || st.Provider != provider {
		// Without a valid state there is no trusted redirect URI: show an error.
		return nil, domain.ErrInvalidToken.WithMessage("The sign-in request expired or is invalid. Please try again.")
	}
	fail := func(code string) *CallbackResult {
		return &CallbackResult{RedirectURL: oauth.AppendQuery(st.RedirectURI, map[string]string{"error": code, "state": st.ClientState})}
	}
	if e := params.Get("error"); e != "" {
		s.metric("oauth", "denied")
		if e != "access_denied" {
			e = "provider_error"
		}
		return fail(e), nil
	}
	p, ok := s.OAuth.Get(provider)
	if !ok {
		return fail("provider_not_enabled"), nil
	}
	code := params.Get("code")
	if code == "" || len(code) > 2048 {
		return fail("invalid_request"), nil
	}
	ident, err := p.Exchange(ctx, code, st.Verifier, st.Nonce, params)
	if err != nil {
		s.Log.Warn("oauth exchange failed", "provider", provider, "err", err)
		s.metric("oauth", "exchange_failed")
		return fail("server_error"), nil
	}
	u, _, err := s.resolveIdentity(ctx, ident, meta)
	if err != nil {
		var de *domain.Error
		if errors.As(err, &de) {
			return fail(de.Code), nil
		}
		return nil, err
	}
	loginCode, err := s.Flow.SaveCode(ctx, oauth.LoginCode{
		UserID: u.ID.String(), Provider: provider, RedirectURI: st.RedirectURI,
		CodeChallenge: st.CodeChallenge, AMR: []string{domain.AMROAuth(provider)},
	})
	if err != nil {
		return nil, err
	}
	s.metric("oauth", "callback_ok")
	return &CallbackResult{RedirectURL: oauth.AppendQuery(st.RedirectURI, map[string]string{"code": loginCode, "state": st.ClientState})}, nil
}

// ExchangeLoginCode redeems the code from HandleCallback (PKCE protected).
func (s *Service) ExchangeLoginCode(ctx context.Context, code, verifier, redirectURI string, meta domain.RequestMeta) (*Result, error) {
	lc, err := s.Flow.TakeCode(ctx, code)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	if lc.RedirectURI != redirectURI || !oauth.VerifyPKCE(verifier, lc.CodeChallenge) {
		s.metric("oauth", "pkce_failed")
		return nil, domain.ErrInvalidToken
	}
	uid, err := uuid.Parse(lc.UserID)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	u, err := s.Store.GetUserByID(ctx, uid)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	if u.Disabled() {
		return nil, domain.ErrAccountDisabled
	}
	res, err := s.startSession(ctx, u, lc.AMR, meta)
	if err == nil && !res.MFARequired {
		s.audit(ctx, u.ID, "user.sign_in", meta, map[string]any{"method": "oauth", "provider": lc.Provider})
	}
	return res, err
}

// SignInWithIDToken handles native mobile sign-in: the app obtained an ID
// token from the platform SDK (Sign in with Apple, Google Sign-In) and sends
// it with the raw nonce it used.
func (s *Service) SignInWithIDToken(ctx context.Context, provider, idToken, nonce string, name string, meta domain.RequestMeta) (*Result, error) {
	p, ok := s.OAuth.Get(provider)
	if !ok {
		return nil, domain.ErrProviderDisabled
	}
	nv, ok := p.(oauth.NativeVerifier)
	if !ok {
		return nil, domain.ErrProviderDisabled.WithMessage("This provider does not support native sign-in.")
	}
	if idToken == "" || len(idToken) > 8192 || len(nonce) < 16 || len(nonce) > 256 {
		return nil, domain.ErrValidation.WithMessage("id_token and nonce (min 16 chars) are required.")
	}
	ident, err := nv.VerifyIDToken(ctx, idToken, nonce)
	if err != nil {
		s.metric("oauth", "native_invalid")
		s.Log.Info("native id token rejected", "provider", provider, "err", err)
		return nil, domain.ErrInvalidToken
	}
	// Each nonce (and therefore each ID token) can be used once.
	fresh, err := s.Flow.UseNonce(ctx, provider, nonce, time.Hour)
	if err != nil {
		return nil, err
	}
	if !fresh {
		s.metric("oauth", "native_replay")
		return nil, domain.ErrInvalidToken
	}
	if ident.Name == "" {
		ident.Name = name // Apple only shares the name with the app, on first sign-in
	}
	u, isNew, err := s.resolveIdentity(ctx, ident, meta)
	if err != nil {
		return nil, err
	}
	res, err := s.startSession(ctx, u, []string{domain.AMROAuth(provider)}, meta)
	if err == nil && !res.MFARequired {
		s.audit(ctx, u.ID, "user.sign_in", meta, map[string]any{"method": "native", "provider": provider})
	}
	if res != nil {
		res.NewUser = isNew
	}
	return res, err
}

// resolveIdentity finds or creates the user for an external identity.
//
// Linking rules (account takeover protection):
//   - Known (provider, subject): that user.
//   - Email matches an existing user: link only when the provider asserts the
//     email is verified. If the existing account's email was never verified,
//     its password may have been set by someone squatting the address
//     ("pre-account takeover"), so that password and all sessions are wiped.
//   - Otherwise a new user is created.
func (s *Service) resolveIdentity(ctx context.Context, id *oauth.Identity, meta domain.RequestMeta) (*domain.User, bool, error) {
	if id.Subject == "" {
		return nil, false, domain.ErrOAuthFailed
	}
	var (
		user    *domain.User
		isNew   bool
		revoked []uuid.UUID
	)
	err := s.Store.InTx(ctx, func(tx *store.Store) error {
		existing, err := tx.GetIdentity(ctx, id.Provider, id.Subject)
		if err == nil {
			user, err = tx.GetUserByID(ctx, existing.UserID)
			if err != nil {
				return err
			}
			if user.Disabled() {
				return domain.ErrAccountDisabled
			}
			return tx.TouchIdentity(ctx, existing.ID, id.Email)
		}
		if !errors.Is(err, domain.ErrNotFound) {
			return err
		}

		email, emailOK := normalizeEmail(id.Email)
		if emailOK {
			user, err = tx.GetUserByEmail(ctx, email)
			if err != nil && !errors.Is(err, domain.ErrNotFound) {
				return err
			}
		}
		if user != nil {
			if !id.EmailVerified {
				return domain.ErrEmailTaken.WithMessage("An account with this email already exists. Sign in with your existing method.")
			}
			if user.Disabled() {
				return domain.ErrAccountDisabled
			}
			if !user.EmailVerified() {
				if user.HasPassword() {
					if err := tx.SetPasswordHash(ctx, user.ID, ""); err != nil {
						return err
					}
					user.PasswordHash = ""
				}
				if err := tx.MarkEmailVerified(ctx, user.ID, time.Now()); err != nil {
					return err
				}
				if revoked, err = s.revokeAll(ctx, tx, user.ID, uuid.Nil, domain.RevokeAccountLinked); err != nil {
					return err
				}
			}
			return s.link(ctx, tx, user.ID, id, email)
		}

		if !s.Settings.Get().AllowSignup {
			return domain.ErrSignupDisabled
		}
		user = &domain.User{ID: uuid.Must(uuid.NewV7()), Name: cleanName(id.Name), Roles: []string{}}
		if emailOK {
			user.Email = email
			if id.EmailVerified {
				now := time.Now()
				user.EmailVerifiedAt = &now
			}
		}
		if err := tx.CreateUser(ctx, user); err != nil {
			return err
		}
		isNew = true
		if err := s.Events.Event(ctx, tx, events.UserCreated, user.ID, map[string]any{"email": user.Email, "method": id.Provider}); err != nil {
			return err
		}
		if user.Email != "" && !user.EmailVerified() {
			if err := s.queueVerificationEmail(ctx, tx, user); err != nil {
				return err
			}
		}
		return s.link(ctx, tx, user.ID, id, email)
	})
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, false, domain.ErrConflict.WithMessage("This sign-in conflicts with an existing account link. Please retry or use your original sign-in method.")
		}
		return nil, false, err
	}
	s.markRevoked(ctx, revoked...)
	if isNew {
		s.metric("sign_up", "success")
		s.audit(ctx, user.ID, "user.sign_up", meta, map[string]any{"method": id.Provider})
	}
	// Re-read so callers see the committed state (verified flag, password).
	fresh, err := s.Store.GetUserByID(ctx, user.ID)
	if err != nil {
		return nil, false, err
	}
	return fresh, isNew, nil
}

func (s *Service) link(ctx context.Context, tx *store.Store, userID uuid.UUID, id *oauth.Identity, email string) error {
	ident := &domain.Identity{ID: uuid.Must(uuid.NewV7()), UserID: userID, Provider: id.Provider, Subject: id.Subject, Email: email}
	if err := tx.CreateIdentity(ctx, ident); err != nil {
		return err
	}
	return s.Events.Event(ctx, tx, events.IdentityLinked, userID, map[string]any{"provider": id.Provider})
}
