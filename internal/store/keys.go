package store

import (
	"context"
	"encoding/json"
	"time"
)

// SigningKeyRow is a persisted JWT signing key. PrivateKey is encrypted.
type SigningKeyRow struct {
	KID        string
	Algorithm  string
	PrivateKey []byte
	PublicJWK  json.RawMessage
	CreatedAt  time.Time
	RetiredAt  *time.Time
}

// ListSigningKeys returns the active key and keys retired after since
// (still needed to verify tokens issued before rotation).
func (s *Store) ListSigningKeys(ctx context.Context, since time.Time) ([]SigningKeyRow, error) {
	rows, err := s.db.Query(ctx, `
		SELECT kid, algorithm, private_key, public_jwk, created_at, retired_at
		FROM signing_keys WHERE retired_at IS NULL OR retired_at > $1
		ORDER BY created_at DESC`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SigningKeyRow
	for rows.Next() {
		var k SigningKeyRow
		if err := rows.Scan(&k.KID, &k.Algorithm, &k.PrivateKey, &k.PublicJWK, &k.CreatedAt, &k.RetiredAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RotateSigningKey retires the active key and inserts k as the new active key
// in one transaction.
func (s *Store) RotateSigningKey(ctx context.Context, k SigningKeyRow) error {
	return s.InTx(ctx, func(tx *Store) error {
		if _, err := tx.db.Exec(ctx, `UPDATE signing_keys SET retired_at = now() WHERE retired_at IS NULL`); err != nil {
			return err
		}
		_, err := tx.db.Exec(ctx, `
			INSERT INTO signing_keys (kid, algorithm, private_key, public_jwk) VALUES ($1, $2, $3, $4)`,
			k.KID, k.Algorithm, k.PrivateKey, k.PublicJWK)
		return mapErr(err)
	})
}

// DeleteRetiredKeys removes keys that can no longer verify any live token.
func (s *Store) DeleteRetiredKeys(ctx context.Context, before time.Time) error {
	_, err := s.db.Exec(ctx, `DELETE FROM signing_keys WHERE retired_at IS NOT NULL AND retired_at < $1`, before)
	return err
}
