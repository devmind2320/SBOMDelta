// Package migrations embeds the SQL schema so that a built binary can bring an
// empty database up to date without shipping loose files alongside it.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
