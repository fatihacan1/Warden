package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/fatihacan1/warden/internal/crypto/randtoken"
	"github.com/fatihacan1/warden/internal/domain"
	"github.com/fatihacan1/warden/internal/events"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/store"
)

const (
	mfaChallengeTTL   = 5 * time.Minute
	mfaMaxAttempts    = 5
	mfaSetupTTL       = 10 * time.Minute
	recoveryCodeCount = 10
	totpPeriod        = 30
)

var totpOpts = totp.ValidateOpts{Period: totpPeriod, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

type mfaChallenge struct {
	UserID string   `json:"u"`
	AMR    []string `json:"a"`
}

func (s *Service) createMFAChallenge(ctx context.Context, userID uuid.UUID, amr []string) (string, error) {
	tok := randtoken.New(32)
	if err := s.putJSON(ctx, "mfa:ch:"+randtoken.HashHex(tok), mfaChallenge{UserID: userID.String(), AMR: amr}, mfaChallengeTTL); err != nil {
		return "", err
	}
	return tok, nil
}

// VerifyMFA completes a sign-in that requires a second factor. code is a
// 6 digit TOTP code or a recovery code.
func (s *Service) VerifyMFA(ctx context.Context, mfaToken, code string, meta domain.RequestMeta) (*Result, error) {
	if mfaToken == "" || len(mfaToken) > 128 {
		return nil, domain.ErrInvalidToken
	}
	key := "mfa:ch:" + randtoken.HashHex(mfaToken)
	raw, err := s.Redis.Get(ctx, key).Bytes()
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	var ch mfaChallenge
	if err := json.Unmarshal(raw, &ch); err != nil {
		return nil, domain.ErrInvalidToken
	}
	uid, err := uuid.Parse(ch.UserID)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	lk := lockoutKey("mfa", ch.UserID)
	if retry := s.Lockout.Check(ctx, lk); retry > 0 {
		return nil, domain.ErrRateLimited.WithRetryAfter(retry)
	}
	// Per-challenge attempt budget.
	attempts, _ := s.Redis.Incr(ctx, key+":n").Result()
	s.Redis.Expire(ctx, key+":n", mfaChallengeTTL)
	if attempts > mfaMaxAttempts {
		s.Redis.Del(ctx, key)
		return nil, domain.ErrInvalidToken.WithMessage("Too many attempts. Please sign in again.")
	}

	u, err := s.Store.GetUserByID(ctx, uid)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	if u.Disabled() {
		return nil, domain.ErrAccountDisabled
	}
	method, err := s.checkSecondFactor(ctx, u, code)
	if err != nil {
		s.Lockout.Fail(ctx, lk)
		s.metric("mfa", "invalid")
		s.audit(ctx, uid, "user.mfa_failed", meta, nil)
		return nil, err
	}
	// Consume the challenge only after success; a concurrent request that
	// already consumed it loses.
	if n, err := s.Redis.Del(ctx, key).Result(); err != nil || n == 0 {
		return nil, domain.ErrInvalidToken
	}
	s.Lockout.Reset(ctx, lk)

	amr := append(append([]string{}, ch.AMR...), domain.AMRMFA, method)
	var pair *TokenPair
	if err := s.Store.InTx(ctx, func(tx *store.Store) error {
		pair, err = s.issueSession(ctx, tx, u, amr, meta)
		return err
	}); err != nil {
		return nil, err
	}
	s.metric("mfa", "success")
	s.audit(ctx, uid, "user.sign_in", meta, map[string]any{"method": "mfa", "factor": method})
	return &Result{User: u, Tokens: pair}, nil
}

// checkSecondFactor validates a TOTP or recovery code and returns the amr
// value for the factor used.
func (s *Service) checkSecondFactor(ctx context.Context, u *domain.User, code string) (string, error) {
	code = strings.TrimSpace(code)
	if !u.MFAEnabled() {
		return "", domain.ErrMFANotEnabled
	}
	if len(code) == 6 && isDigits(code) {
		secret, err := s.Box.Open(u.TOTPSecret, "totp:"+u.ID.String())
		if err != nil {
			return "", err
		}
		step, ok := matchTOTP(string(secret), code, time.Now())
		if !ok {
			return "", domain.ErrInvalidMFACode
		}
		// Single use: the step must be newer than the last accepted one.
		advanced, err := s.Store.AdvanceTOTPStep(ctx, u.ID, step)
		if err != nil {
			return "", err
		}
		if !advanced {
			return "", domain.ErrInvalidMFACode
		}
		return domain.AMROTP, nil
	}
	rc := randtoken.NormalizeRecoveryCode(code)
	if len(rc) != 11 {
		return "", domain.ErrInvalidMFACode
	}
	used, err := s.Store.UseRecoveryCode(ctx, u.ID, randtoken.Hash(rc))
	if err != nil {
		return "", err
	}
	if !used {
		return "", domain.ErrInvalidMFACode
	}
	return "recovery_code", nil
}

// matchTOTP accepts the current step and one step of clock drift either way,
// returning the matched step.
func matchTOTP(secret, code string, now time.Time) (int64, bool) {
	for _, skew := range []int64{0, -1, 1} {
		t := now.Add(time.Duration(skew*totpPeriod) * time.Second)
		expected, err := totp.GenerateCodeCustom(secret, t, totpOpts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return t.Unix() / totpPeriod, true
		}
	}
	return 0, false
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// TOTPSetup is returned when a user starts enrolling an authenticator app.
type TOTPSetup struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

// StartTOTPSetup creates a pending secret (valid 10 minutes).
func (s *Service) StartTOTPSetup(ctx context.Context, userID uuid.UUID) (*TOTPSetup, error) {
	u, err := s.Store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.MFAEnabled() {
		return nil, domain.ErrMFAAlreadyEnabled
	}
	account := u.Email
	if account == "" {
		account = u.ID.String()
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.Settings.Get().AppName, AccountName: account, Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return nil, err
	}
	sealed, err := s.Box.Seal([]byte(key.Secret()), "totp-setup:"+userID.String())
	if err != nil {
		return nil, err
	}
	if err := s.Redis.Set(ctx, "mfa:setup:"+userID.String(), sealed, mfaSetupTTL).Err(); err != nil {
		return nil, err
	}
	return &TOTPSetup{Secret: key.Secret(), OTPAuthURL: key.URL()}, nil
}

// EnableTOTP confirms enrollment with a code from the app and returns
// one-time recovery codes (shown to the user exactly once).
func (s *Service) EnableTOTP(ctx context.Context, userID uuid.UUID, code string, meta domain.RequestMeta) ([]string, error) {
	sealed, err := s.Redis.Get(ctx, "mfa:setup:"+userID.String()).Bytes()
	if err != nil {
		return nil, domain.ErrInvalidToken.WithMessage("No pending setup. Start two-factor setup again.")
	}
	secret, err := s.Box.Open(sealed, "totp-setup:"+userID.String())
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	step, ok := matchTOTP(string(secret), strings.TrimSpace(code), time.Now())
	if !ok {
		return nil, domain.ErrInvalidMFACode
	}
	stored, err := s.Box.Seal(secret, "totp:"+userID.String())
	if err != nil {
		return nil, err
	}
	codes := make([]string, recoveryCodeCount)
	hashes := make([][]byte, recoveryCodeCount)
	for i := range codes {
		codes[i] = randtoken.RecoveryCode()
		hashes[i] = randtoken.Hash(codes[i])
	}
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		u, err := tx.GetUserByIDForUpdate(ctx, userID)
		if err != nil {
			return err
		}
		if err := tx.EnableTOTP(ctx, userID, stored, step); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return domain.ErrMFAAlreadyEnabled
			}
			return err
		}
		if err := tx.ReplaceRecoveryCodes(ctx, userID, hashes); err != nil {
			return err
		}
		if err := s.Events.Event(ctx, tx, events.UserMFAEnabled, userID, nil); err != nil {
			return err
		}
		return s.Events.Email(ctx, tx, u.Email, mailer.TemplateMFAChanged, map[string]string{"Action": "enabled", "When": time.Now().UTC().Format(time.RFC1123)})
	})
	if err != nil {
		return nil, err
	}
	s.Redis.Del(ctx, "mfa:setup:"+userID.String())
	s.audit(ctx, userID, "user.mfa_enabled", meta, nil)
	return codes, nil
}

// DisableTOTP turns MFA off; it requires a valid second factor.
func (s *Service) DisableTOTP(ctx context.Context, userID uuid.UUID, code string, meta domain.RequestMeta) error {
	u, err := s.Store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	lk := lockoutKey("mfa", userID.String())
	if retry := s.Lockout.Check(ctx, lk); retry > 0 {
		return domain.ErrRateLimited.WithRetryAfter(retry)
	}
	if _, err := s.checkSecondFactor(ctx, u, code); err != nil {
		s.Lockout.Fail(ctx, lk)
		return err
	}
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.DisableTOTP(ctx, userID); err != nil {
			return err
		}
		if err := s.Events.Event(ctx, tx, events.UserMFADisabled, userID, nil); err != nil {
			return err
		}
		return s.Events.Email(ctx, tx, u.Email, mailer.TemplateMFAChanged, map[string]string{"Action": "disabled", "When": time.Now().UTC().Format(time.RFC1123)})
	})
	if err == nil {
		s.audit(ctx, userID, "user.mfa_disabled", meta, nil)
	}
	return err
}

// RegenerateRecoveryCodes replaces recovery codes; requires a TOTP code.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID uuid.UUID, code string, meta domain.RequestMeta) ([]string, error) {
	u, err := s.Store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if _, err := s.checkSecondFactor(ctx, u, code); err != nil {
		return nil, err
	}
	codes := make([]string, recoveryCodeCount)
	hashes := make([][]byte, recoveryCodeCount)
	for i := range codes {
		codes[i] = randtoken.RecoveryCode()
		hashes[i] = randtoken.Hash(codes[i])
	}
	if err := s.Store.InTx(ctx, func(tx *store.Store) error {
		return tx.ReplaceRecoveryCodes(ctx, userID, hashes)
	}); err != nil {
		return nil, err
	}
	s.audit(ctx, userID, "user.recovery_codes_regenerated", meta, nil)
	return codes, nil
}
