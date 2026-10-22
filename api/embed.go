// Package api embeds the public API description so the binary can serve it.
package api

import _ "embed"

// OpenAPI is the OpenAPI 3.1 description of the public HTTP API.
//
//go:embed openapi.yaml
var OpenAPI []byte
