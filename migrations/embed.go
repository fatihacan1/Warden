// Package migrations embeds the SQL schema migrations into the binary.
package migrations

import "embed"

// FS contains every *.sql migration, applied in lexical order by goose.
//
//go:embed *.sql
var FS embed.FS
