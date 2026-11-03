//go:build !dev

package gateway

import "net/http"

// DevEnabled reports whether this binary contains the dev stand-in. It is
// false in every image: the Dockerfile never builds with the "dev" tag.
const DevEnabled = false

func devIdentity(*http.Request) (Identity, bool) { return Identity{}, false }

// DevHandler is nil outside dev builds, so the router mounts nothing.
var DevHandler http.Handler
