package app

import (
	"context"
	"fmt"

	"github.com/fatihacan1/warden/internal/crypto/secretbox"
	"github.com/fatihacan1/warden/internal/store"
)

// ReencryptResult reports how many values of one column were rewritten.
type ReencryptResult struct {
	Column  string
	Changed int
}

// Reencrypt rewrites every encrypted value that is not yet sealed with the
// current ENCRYPTION_KEY and ENCRYPTION_ALGORITHM. Run it after rotating the
// key (old key moved to ENCRYPTION_PREVIOUS_KEYS) or changing the algorithm;
// once it reports nothing left, the previous keys can be removed.
//
// Each column is rewritten in its own transaction with its rows locked, so it
// is safe while Warden is running. It is idempotent.
func Reencrypt(ctx context.Context, st *store.Store, box *secretbox.Box) ([]ReencryptResult, error) {
	var out []ReencryptResult
	for _, col := range store.EncryptedColumns() {
		n, err := st.ResealColumn(ctx, col, box.Reseal)
		if err != nil {
			return out, fmt.Errorf("%s: %w (is the key that sealed it listed in ENCRYPTION_PREVIOUS_KEYS?)", col.Name, err)
		}
		out = append(out, ReencryptResult{Column: col.Name, Changed: n})
	}
	return out, nil
}
